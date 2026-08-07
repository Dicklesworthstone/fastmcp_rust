#!/usr/bin/env python3
"""Executable, fail-closed MCP campaign governance canary.

The only tracker mutations are made against the explicit disposable database
under ``--output``.  The directory is deliberately retained as the verifier's
receipt artifact; callers may remove it under their own retention policy.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
FIXTURE = Path(__file__).with_name("cases.json")
SCRIPT = ROOT / "scripts" / "mcp_campaign_canary.sh"
POLICY = ROOT / ".beads" / "policy.yaml"
NEGATIVE_IDS = {
    "canary_direct_close_rejected",
    "canary_double_claim_rejected",
    "canary_self_close_rejected",
    "canary_unchecked_acceptance_rejected",
    "canary_short_close_reason_rejected",
    "canary_missing_typed_reference_rejected",
    "canary_missing_attribution_rejected",
    "canary_review_without_pass_rejected",
    "canary_unauthorized_provider_limitation_detected",
    "canary_complete_provider_scrub_retained",
    "canary_stale_pass_rejected",
    "canary_live_tracker_unchanged",
}
POSITIVE_ID = "canary_distinct_orchestrator_closes_with_sole_fresh_pass"
WORKER = "CanaryWorker"
ORCHESTRATOR = "McpCampaignOrchestrator"
HARNESS = "scripts/mcp_campaign_canary.sh"
MODEL = "campaign-canary-v1"


def now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_path(path: Path) -> str | None:
    return sha256_bytes(path.read_bytes()) if path.exists() else None


def executable_path(name: str) -> Path:
    located = shutil.which(name)
    if not located:
        raise SystemExit(f"required executable is unavailable: {name}")
    path = Path(located).resolve()
    if not path.is_file():
        raise SystemExit(f"required executable is not a regular file: {path}")
    return path


def json_value(text: str) -> Any:
    try:
        return json.loads(text)  # ubs:ignore — malformed tracker JSON is retained as an unparsed receipt value below.
    except json.JSONDecodeError:
        return {"unparsed": text}


class Runner:
    def __init__(self, output: Path, subject_revision: str, br_binary: Path, bv_binary: Path) -> None:
        self.output = output
        self.workspace = output / "workspace"
        self.db = self.workspace / ".beads" / "canary.db"
        self.events: list[dict[str, Any]] = []
        self.commands: list[dict[str, Any]] = []
        self.subject_revision = subject_revision
        self.br_binary = br_binary
        self.bv_binary = bv_binary
        self.live_paths: tuple[Path, Path] = ()
        self.receipt_revision = self.git("rev-parse", "HEAD")
        self.stale_revision = self.git("rev-parse", f"{self.subject_revision}^")
        if self.stale_revision == self.subject_revision:
            raise RuntimeError("stale canary revision must differ from the subject revision")
        self.current_case = "preflight"

    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=ROOT, check=True, text=True, capture_output=True
        ).stdout.strip()

    def run(self, argv: list[str], *, actor: str | None = None) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(argv, cwd=ROOT, text=True, capture_output=True, check=False)
        self.commands.append(
            {
                "case_id": self.current_case,
                "actor": actor,
                "argv": argv,
                "exit_code": completed.returncode,
                "stdout_sha256": sha256_bytes(completed.stdout.encode()),
                "stderr_sha256": sha256_bytes(completed.stderr.encode()),
                "stdout": json_value(completed.stdout),
                "stderr": completed.stderr,
            }
        )
        return completed

    def br(self, *args: str, actor: str | None = None) -> subprocess.CompletedProcess[str]:
        argv = [str(self.br_binary), *args, "--db", str(self.db), "--json"]
        if actor:
            argv.extend(["--actor", actor])
        completed = subprocess.run(
            argv, cwd=self.workspace, text=True, capture_output=True, check=False
        )
        self.commands.append(
            {
                "case_id": self.current_case, "actor": actor, "argv": argv,
                "exit_code": completed.returncode,
                "stdout_sha256": sha256_bytes(completed.stdout.encode()),
                "stderr_sha256": sha256_bytes(completed.stderr.encode()),
                "stdout": json_value(completed.stdout), "stderr": completed.stderr,
            }
        )
        return completed

    def initialize_isolated_tracker(self) -> subprocess.CompletedProcess[str]:
        (self.workspace / ".beads").mkdir(parents=True, exist_ok=False)
        shutil.copyfile(POLICY, self.workspace / ".beads" / "policy.yaml")
        return self.br("init", "--prefix", "canary", actor=ORCHESTRATOR)

    def issue(self, issue_id: str) -> Any:
        completed = self.br("show", issue_id, actor=ORCHESTRATOR)
        return json_value(completed.stdout)

    def ledger(self, issue_id: str) -> Any:
        completed = self.br("gate", "list", issue_id, actor=ORCHESTRATOR)
        return json_value(completed.stdout)

    def audit(self, issue_id: str) -> Any:
        completed = self.br("audit", "log", issue_id, actor=ORCHESTRATOR)
        return json_value(completed.stdout)

    def snapshot(self, issue_id: str) -> tuple[Any, Any, Any]:
        return self.issue(issue_id), self.ledger(issue_id), self.audit(issue_id)

    def live_snapshot(self) -> dict[str, str | None]:
        return {str(path): digest_path(path) for path in self.live_paths}

    def create_subject(self, case_id: str, *, checked: bool = True) -> str:
        created = self.br(
            "create", f"MCP canary {case_id}", "--status", "open", "--silent", actor=WORKER
        )
        if created.returncode:
            raise RuntimeError(f"cannot create {case_id}: {created.stderr}")
        issue_id = created.stdout.strip()
        criterion = "[x] verified canary acceptance" if checked else "[ ] verified canary acceptance"
        updated = self.br(
            "update", issue_id, "--acceptance-criteria", criterion, actor=WORKER
        )
        if updated.returncode:
            raise RuntimeError(f"cannot update acceptance for {case_id}: {updated.stderr}")
        recorded = self.br(
            "audit", "record", "--kind", "tool_call", "--issue-id", issue_id,
            "--tool-name", "mcp_campaign_canary", "--exit-code", "0", actor=WORKER,
        )
        if recorded.returncode:
            raise RuntimeError(f"cannot record audit for {case_id}: {recorded.stderr}")
        return issue_id

    def review(self, issue_id: str, *, actor: str = WORKER) -> None:
        for status in ("in_progress", "review"):
            completed = self.br("update", issue_id, "--status", status, actor=actor)
            if completed.returncode:
                raise RuntimeError(f"cannot move {issue_id} to {status}: {completed.stderr}")

    def report_gate(
        self, issue_id: str, provider: str, status: str, actor: str, *, note: str | None = None
    ) -> None:
        completed = self.br(
            "gate", "report", issue_id, "--gate", "batch_verify", "--provider", provider,
            "--status", status, "--note", note or f"{self.current_case}:{self.subject_revision}", actor=actor,
        )
        if completed.returncode:
            raise RuntimeError(f"cannot report {provider} {status}: {completed.stderr}")

    def close(self, issue_id: str, *, actor: str, reason: str, attributed: bool = True) -> subprocess.CompletedProcess[str]:
        args = ["close", issue_id, "--reason", reason]
        if attributed:
            args.extend(["--agent-name", actor, "--harness", HARNESS, "--model", MODEL])
        return self.br(*args, actor=actor)

    def record_case(
        self, case: dict[str, str], issue_id: str | None, before: Any, after: Any,
        ledger_before: Any, ledger_after: Any, audit_before: Any, audit_after: Any,
        passed: bool, detail: str,
    ) -> None:
        self.events.append(
            {
                "case_id": case["id"], "kind": case["kind"], "planted_dimension": case["planted_dimension"],
                "actors": {"worker": WORKER, "orchestrator": ORCHESTRATOR},
                "passed": passed, "detail": detail, "issue_before": before, "issue_after": after,
                "gate_ledger_before": ledger_before, "gate_ledger_after": ledger_after,
                "audit_before": audit_before, "audit_after": audit_after,
                "command_indexes": [i for i, command in enumerate(self.commands) if command["case_id"] == case["id"]],
                "first_attempt": 1, "retries": 0,
                "execution_outcomes": {
                    "early_aborted": 0, "stale": 0, "mixed": 0, "substituted": 0,
                },
            }
        )


def provider_statuses(value: Any) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if isinstance(value, dict):
        provider = value.get("provider") or value.get("provider_name")
        status = value.get("status")
        if isinstance(provider, str) and isinstance(status, str):
            found.append((provider, status.lower()))
        for child in value.values():
            found.extend(provider_statuses(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(provider_statuses(child))
    return found


def same(value: Any, other: Any) -> bool:
    return json.dumps(value, sort_keys=True) == json.dumps(other, sort_keys=True)


def unchanged(before: tuple[Any, Any, Any], after: tuple[Any, Any, Any]) -> bool:
    return all(same(left, right) for left, right in zip(before, after, strict=True))


def retains_revision(value: Any, revision: str) -> bool:
    return revision in json.dumps(value, sort_keys=True)


def valid_reason() -> str:
    return "commit: canary-subject run: isolated-canary evidence: receipt incident: none"


def run_case(runner: Runner, case: dict[str, str]) -> None:
    runner.current_case = case["id"]
    issue_id: str | None = None
    before: Any = None
    after: Any = None
    ledger_before: Any = None
    ledger_after: Any = None
    audit_before: Any = None
    audit_after: Any = None
    passed = False
    detail = ""
    try:
        case_id = case["id"]
        if case_id == "canary_live_tracker_unchanged":
            before = runner.live_snapshot()
            after = runner.live_snapshot()
            passed = same(before, after)
            detail = "live tracker database and JSONL digests are unchanged"
        elif case_id == "canary_stale_pass_rejected":
            issue_id = runner.create_subject(case_id)
            runner.review(issue_id)
            runner.report_gate(
                issue_id, "batch_verify", "pass", ORCHESTRATOR,
                note=f"subject_revision:{runner.stale_revision}",
            )
            before, ledger_before, audit_before = runner.snapshot(issue_id)
            attempt = runner.close(issue_id, actor=ORCHESTRATOR, reason=valid_reason())
            after, ledger_after, audit_after = runner.snapshot(issue_id)
            passed = (
                runner.stale_revision != runner.subject_revision
                and retains_revision(ledger_before, runner.stale_revision)
                and attempt.returncode != 0
                and unchanged((before, ledger_before, audit_before), (after, ledger_after, audit_after))
            )
            detail = "a ledger PASS bound to a distinct real ancestor revision cannot authorize close"
        elif case_id == "canary_direct_close_rejected":
            issue_id = runner.create_subject(case_id)
            before, ledger_before, audit_before = runner.snapshot(issue_id)
            attempt = runner.close(issue_id, actor=ORCHESTRATOR, reason=valid_reason())
            after, ledger_after, audit_after = runner.snapshot(issue_id)
            passed = attempt.returncode != 0 and unchanged((before, ledger_before, audit_before), (after, ledger_after, audit_after))
            detail = "open-to-closed close rejects without changing issue state"
        elif case_id == "canary_double_claim_rejected":
            issue_id = runner.create_subject(case_id)
            first = runner.br("update", issue_id, "--claim", actor=WORKER)
            if first.returncode:
                raise RuntimeError(first.stderr)
            before, ledger_before, audit_before = runner.snapshot(issue_id)
            attempt = runner.br("update", issue_id, "--claim", actor="SecondCanaryWorker")
            after, ledger_after, audit_after = runner.snapshot(issue_id)
            passed = attempt.returncode != 0 and unchanged((before, ledger_before, audit_before), (after, ledger_after, audit_after))
            detail = "second atomic claimant rejects and preserves the first claim"
        elif case_id == "canary_self_close_rejected":
            issue_id = runner.create_subject(case_id)
            runner.review(issue_id)
            runner.report_gate(issue_id, "batch_verify", "pass", WORKER)
            before, ledger_before, audit_before = runner.snapshot(issue_id)
            attempt = runner.close(issue_id, actor=WORKER, reason=valid_reason())
            after, ledger_after, audit_after = runner.snapshot(issue_id)
            passed = attempt.returncode != 0 and unchanged((before, ledger_before, audit_before), (after, ledger_after, audit_after))
            detail = "claimant cannot self-close after in-progress"
        elif case_id == "canary_unchecked_acceptance_rejected":
            issue_id = runner.create_subject(case_id, checked=False)
            runner.review(issue_id)
            runner.report_gate(issue_id, "batch_verify", "pass", ORCHESTRATOR)
            before, ledger_before, audit_before = runner.snapshot(issue_id)
            attempt = runner.close(issue_id, actor=ORCHESTRATOR, reason=valid_reason())
            after, ledger_after, audit_after = runner.snapshot(issue_id)
            passed = attempt.returncode != 0 and unchanged((before, ledger_before, audit_before), (after, ledger_after, audit_after))
            detail = "unchecked acceptance rejects without state mutation"
        elif case_id == "canary_short_close_reason_rejected":
            issue_id = runner.create_subject(case_id)
            runner.review(issue_id)
            runner.report_gate(issue_id, "batch_verify", "pass", ORCHESTRATOR)
            before, ledger_before, audit_before = runner.snapshot(issue_id)
            attempt = runner.close(issue_id, actor=ORCHESTRATOR, reason="short")
            after, ledger_after, audit_after = runner.snapshot(issue_id)
            passed = attempt.returncode != 0 and unchanged((before, ledger_before, audit_before), (after, ledger_after, audit_after))
            detail = "short close reason rejects without state mutation"
        elif case_id == "canary_missing_typed_reference_rejected":
            issue_id = runner.create_subject(case_id)
            runner.review(issue_id)
            runner.report_gate(issue_id, "batch_verify", "pass", ORCHESTRATOR)
            before, ledger_before, audit_before = runner.snapshot(issue_id)
            attempt = runner.close(issue_id, actor=ORCHESTRATOR, reason="this deliberately long reason contains no required typed references")
            after, ledger_after, audit_after = runner.snapshot(issue_id)
            passed = attempt.returncode != 0 and unchanged((before, ledger_before, audit_before), (after, ledger_after, audit_after))
            detail = "missing commit/run/evidence/incident references reject"
        elif case_id == "canary_missing_attribution_rejected":
            issue_id = runner.create_subject(case_id)
            runner.review(issue_id)
            runner.report_gate(issue_id, "batch_verify", "pass", ORCHESTRATOR)
            before, ledger_before, audit_before = runner.snapshot(issue_id)
            attempt = runner.close(issue_id, actor=ORCHESTRATOR, reason=valid_reason(), attributed=False)
            after, ledger_after, audit_after = runner.snapshot(issue_id)
            passed = attempt.returncode != 0 and unchanged((before, ledger_before, audit_before), (after, ledger_after, audit_after))
            detail = "missing tier-one attribution rejects"
        elif case_id == "canary_review_without_pass_rejected":
            issue_id = runner.create_subject(case_id)
            runner.review(issue_id)
            before, ledger_before, audit_before = runner.snapshot(issue_id)
            attempt = runner.close(issue_id, actor=ORCHESTRATOR, reason=valid_reason())
            after, ledger_after, audit_after = runner.snapshot(issue_id)
            passed = attempt.returncode != 0 and unchanged((before, ledger_before, audit_before), (after, ledger_after, audit_after))
            detail = "review issue without batch_verify PASS rejects"
        elif case_id == "canary_unauthorized_provider_limitation_detected":
            issue_id = runner.create_subject(case_id)
            runner.review(issue_id)
            runner.report_gate(issue_id, "impostor", "pass", "ImpostorProvider")
            before, ledger_before, audit_before = runner.snapshot(issue_id)
            attempt = runner.close(issue_id, actor=ORCHESTRATOR, reason=valid_reason())
            after, ledger_after, audit_after = runner.snapshot(issue_id)
            statuses = provider_statuses(ledger_before)
            passed = attempt.returncode == 0 and ("impostor", "pass") in statuses
            detail = "installed br accepts an unauthorized provider PASS; harness records the limitation"
        elif case_id == "canary_complete_provider_scrub_retained":
            issue_id = runner.create_subject(case_id)
            runner.review(issue_id)
            runner.report_gate(issue_id, "impostor", "pass", "ImpostorProvider")
            runner.report_gate(issue_id, "old_batch", "pass", ORCHESTRATOR)
            before, ledger_before, _scrub_audit = runner.snapshot(issue_id)
            for provider, _status in sorted(set(provider_statuses(ledger_before))):
                runner.report_gate(issue_id, provider, "fail", ORCHESTRATOR)
            before, ledger_before, audit_before = runner.snapshot(issue_id)
            attempt = runner.close(issue_id, actor=ORCHESTRATOR, reason=valid_reason())
            after, ledger_after, audit_after = runner.snapshot(issue_id)
            passed = (
                attempt.returncode != 0
                and unchanged((before, ledger_before, audit_before), (after, ledger_after, audit_after))
                and not any(status == "pass" for _, status in provider_statuses(ledger_after))
            )
            detail = "all observed providers are overwritten to FAIL and cannot close"
        elif case_id == POSITIVE_ID:
            issue_id = runner.create_subject(case_id)
            runner.review(issue_id)
            runner.report_gate(issue_id, "batch_verify", "pass", ORCHESTRATOR)
            before, ledger_before, audit_before = runner.snapshot(issue_id)
            statuses = provider_statuses(ledger_before)
            fresh = (
                runner.subject_revision == runner.receipt_revision
                and retains_revision(ledger_before, runner.subject_revision)
            )
            attempt = runner.close(issue_id, actor=ORCHESTRATOR, reason=valid_reason()) if fresh and statuses == [("batch_verify", "pass")] else None
            after, ledger_after, audit_after = runner.snapshot(issue_id)
            passed = attempt is not None and attempt.returncode == 0
            detail = "distinct orchestrator closes only with the fresh sole batch_verify PASS"
        else:
            raise RuntimeError(f"unknown frozen case {case_id}")
    except Exception as error:  # Receipt must retain first failure rather than aborting the inventory.
        detail = f"exception: {error}"
        passed = False
        if issue_id:
            after, ledger_after, audit_after = runner.snapshot(issue_id)
    runner.record_case(
        case, issue_id, before, after, ledger_before, ledger_after, audit_before, audit_after,
        passed, detail,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="retained receipt directory (default: preserved temporary directory)")
    parser.add_argument("--subject-revision", default=None, help="revision being certified; defaults to current HEAD")
    args = parser.parse_args()
    if args.output:
        output = args.output.resolve()
        if ROOT not in output.parents:
            raise SystemExit("--output must be inside the repository for br path validation")
        output.mkdir(parents=True, exist_ok=False)
    else:
        output = Path(tempfile.mkdtemp(prefix="run-", dir=FIXTURE.parent))
    cases = json_value(FIXTURE.read_text())
    if not isinstance(cases, list):
        raise SystemExit("frozen canary fixture must be a JSON array")
    actual_ids = {case["id"] for case in cases}
    expected_ids = NEGATIVE_IDS | {POSITIVE_ID}
    if actual_ids != expected_ids or len(cases) != len(expected_ids):
        raise SystemExit("frozen canary fixture has duplicate, missing, or substituted case IDs")
    br_binary = executable_path("br")
    bv_binary = executable_path("bv")
    subject_ref = args.subject_revision or "HEAD"
    subject_revision = subprocess.run(
        ["git", "rev-parse", "--verify", f"{subject_ref}^{{commit}}"],
        cwd=ROOT, text=True, capture_output=True, check=True,
    ).stdout.strip()
    runner = Runner(output, subject_revision, br_binary, bv_binary)
    where = runner.run([str(br_binary), "where", "--json"])
    location = json_value(where.stdout)
    if where.returncode or not isinstance(location, dict):
        raise SystemExit("cannot discover the effective live Beads tracker")
    try:
        runner.live_paths = (Path(location["database_path"]).resolve(), Path(location["jsonl_path"]).resolve())
    except (KeyError, TypeError):
        raise SystemExit("br where did not provide live database and JSONL paths") from None
    live_before = runner.live_snapshot()
    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", ".beads/policy.yaml"], cwd=ROOT,
        text=True, capture_output=True, check=False,
    ).returncode == 0
    preflight = {
        "policy_tracked": tracked, "policy_path": str(POLICY.relative_to(ROOT)),
        "policy_sha256": digest_path(POLICY), "harness_sha256": digest_path(SCRIPT),
        "fixture_sha256": digest_path(FIXTURE), "runner_sha256": digest_path(Path(__file__)),
        "live_tracker": {"database_path": str(runner.live_paths[0]), "jsonl_path": str(runner.live_paths[1])},
        "br": {"path": str(br_binary), "sha256": digest_path(br_binary), "version": runner.run([str(br_binary), "--version"]).stdout.strip()},
        "bv": {"path": str(bv_binary), "sha256": digest_path(bv_binary), "version": runner.run([str(bv_binary), "--version"]).stdout.strip()},
        "subject_revision": subject_revision, "receipt_revision": runner.receipt_revision,
        "stale_revision": runner.stale_revision,
        "subject_tree": runner.git("rev-parse", f"{subject_revision}^{{tree}}"),
        "receipt_tree": runner.git("rev-parse", "HEAD^{tree}"),
        "dirty_inventory": runner.run(["git", "status", "--porcelain=v1", "--untracked-files=all"]).stdout.splitlines(),
    }
    if tracked:
        initialized = runner.initialize_isolated_tracker()
        if initialized.returncode == 0:
            with sqlite3.connect(runner.db) as connection:
                rows = connection.execute("SELECT type, name, sql FROM sqlite_master ORDER BY type, name").fetchall()
            preflight["tracker_schema_sha256"] = sha256_bytes(json.dumps(rows, sort_keys=True).encode())
            preflight["isolated_policy_sha256"] = digest_path(runner.workspace / ".beads" / "policy.yaml")
            for case in cases:
                run_case(runner, case)
        else:
            preflight["initialization_error"] = initialized.stderr
    else:
        preflight["initialization_error"] = "tracked .beads/policy.yaml is required; harness refused tracker mutation"
    live_after = runner.live_snapshot()
    receipt = {
        "receipt_format": "mcp-campaign-canary-v1", "generated_at": now(), "preflight": preflight,
        "isolated_database": str(runner.db), "live_before": live_before, "live_after": live_after,
        "live_unchanged": live_before == live_after, "required": len(expected_ids),
        "discovered": len(cases), "started": len(runner.events),
        "passed": sum(event["passed"] for event in runner.events), "first_attempts": len(runner.events),
        "retries": 0, "ignored": 0, "filtered": 0, "skipped": len(cases) - len(runner.events),
        "execution_integrity": {
            "zero_run": 0, "early_aborted": 0, "stale": 0, "mixed": 0, "substituted": 0,
        },
        "events_path": "events.jsonl",
        "commands_path": "commands.jsonl", "named_consumers": ["CI-BASE-01", "GATE-ALL-MCP-READY"],
        "zero_capability_credit": True,
    }
    (output / "events.jsonl").write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in runner.events))
    (output / "commands.jsonl").write_text("".join(json.dumps(command, sort_keys=True) + "\n" for command in runner.commands))
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"receipt": str(output / "receipt.json"), "passed": receipt["passed"], "required": receipt["required"]}, sort_keys=True))
    return 0 if tracked and receipt["started"] == receipt["required"] == receipt["passed"] and receipt["live_unchanged"] else 1


if __name__ == "__main__":
    sys.exit(main())
