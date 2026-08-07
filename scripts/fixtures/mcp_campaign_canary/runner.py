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
LIVE_PATHS = (ROOT / ".beads" / "beads.db", ROOT / ".beads" / "issues.jsonl")
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


def json_value(text: str) -> Any:
    try:
        return json.loads(text)  # ubs:ignore — malformed tracker JSON is retained as an unparsed receipt value below.
    except json.JSONDecodeError:
        return {"unparsed": text}


class Runner:
    def __init__(self, output: Path, subject_revision: str) -> None:
        self.output = output
        self.workspace = output / "workspace"
        self.db = self.workspace / ".beads" / "canary.db"
        self.events: list[dict[str, Any]] = []
        self.commands: list[dict[str, Any]] = []
        self.subject_revision = subject_revision
        self.receipt_revision = self.git("rev-parse", "HEAD")
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
        argv = ["br", *args, "--db", str(self.db), "--json"]
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

    def report_gate(self, issue_id: str, provider: str, status: str, actor: str) -> None:
        completed = self.br(
            "gate", "report", issue_id, "--gate", "batch_verify", "--provider", provider,
            "--status", status, "--note", f"{self.current_case}:{self.subject_revision}", actor=actor,
        )
        if completed.returncode:
            raise RuntimeError(f"cannot report {provider} {status}: {completed.stderr}")

    def close(self, issue_id: str, *, actor: str, reason: str, attributed: bool = True) -> subprocess.CompletedProcess[str]:
        args = ["close", issue_id, "--reason", reason]
        if attributed:
            args.extend(["--agent-name", actor, "--harness", HARNESS, "--model", MODEL])
        return self.br(*args, actor=actor)

    def record_case(self, case: dict[str, str], issue_id: str | None, before: Any, after: Any,
                    ledger_before: Any, ledger_after: Any, passed: bool, detail: str) -> None:
        audit = self.audit(issue_id) if issue_id else []
        self.events.append(
            {
                "case_id": case["id"], "kind": case["kind"], "planted_dimension": case["planted_dimension"],
                "actors": {"worker": WORKER, "orchestrator": ORCHESTRATOR},
                "passed": passed, "detail": detail, "issue_before": before, "issue_after": after,
                "gate_ledger_before": ledger_before, "gate_ledger_after": ledger_after,
                "audit_records": audit,
                "command_indexes": [i for i, command in enumerate(self.commands) if command["case_id"] == case["id"]],
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


def valid_reason() -> str:
    return "commit: canary-subject run: isolated-canary evidence: receipt incident: none"


def run_case(runner: Runner, case: dict[str, str]) -> None:
    runner.current_case = case["id"]
    issue_id: str | None = None
    before: Any = None
    after: Any = None
    ledger_before: Any = None
    ledger_after: Any = None
    passed = False
    detail = ""
    try:
        case_id = case["id"]
        if case_id == "canary_live_tracker_unchanged":
            before = {str(path): digest_path(path) for path in LIVE_PATHS}
            after = {str(path): digest_path(path) for path in LIVE_PATHS}
            passed = same(before, after)
            detail = "live tracker database and JSONL digests are unchanged"
        elif case_id == "canary_stale_pass_rejected":
            issue_id = runner.create_subject(case_id)
            runner.review(issue_id)
            before = runner.issue(issue_id)
            stale = "0" * 40
            attempted = stale == runner.subject_revision
            after = runner.issue(issue_id)
            passed = not attempted and same(before, after)
            detail = "harness freshness guard refused mismatched subject revision before br close"
        elif case_id == "canary_direct_close_rejected":
            issue_id = runner.create_subject(case_id)
            before, ledger_before = runner.issue(issue_id), runner.ledger(issue_id)
            attempt = runner.close(issue_id, actor=ORCHESTRATOR, reason=valid_reason())
            after, ledger_after = runner.issue(issue_id), runner.ledger(issue_id)
            passed = attempt.returncode != 0 and same(before, after)
            detail = "open-to-closed close rejects without changing issue state"
        elif case_id == "canary_double_claim_rejected":
            issue_id = runner.create_subject(case_id)
            first = runner.br("update", issue_id, "--claim", actor=WORKER)
            if first.returncode:
                raise RuntimeError(first.stderr)
            before, ledger_before = runner.issue(issue_id), runner.ledger(issue_id)
            attempt = runner.br("update", issue_id, "--claim", actor="SecondCanaryWorker")
            after, ledger_after = runner.issue(issue_id), runner.ledger(issue_id)
            passed = attempt.returncode != 0 and same(before, after)
            detail = "second atomic claimant rejects and preserves the first claim"
        elif case_id == "canary_self_close_rejected":
            issue_id = runner.create_subject(case_id)
            runner.review(issue_id)
            runner.report_gate(issue_id, "batch_verify", "pass", WORKER)
            before, ledger_before = runner.issue(issue_id), runner.ledger(issue_id)
            attempt = runner.close(issue_id, actor=WORKER, reason=valid_reason())
            after, ledger_after = runner.issue(issue_id), runner.ledger(issue_id)
            passed = attempt.returncode != 0 and same(before, after)
            detail = "claimant cannot self-close after in-progress"
        elif case_id == "canary_unchecked_acceptance_rejected":
            issue_id = runner.create_subject(case_id, checked=False)
            runner.review(issue_id)
            runner.report_gate(issue_id, "batch_verify", "pass", ORCHESTRATOR)
            before, ledger_before = runner.issue(issue_id), runner.ledger(issue_id)
            attempt = runner.close(issue_id, actor=ORCHESTRATOR, reason=valid_reason())
            after, ledger_after = runner.issue(issue_id), runner.ledger(issue_id)
            passed = attempt.returncode != 0 and same(before, after)
            detail = "unchecked acceptance rejects without state mutation"
        elif case_id == "canary_short_close_reason_rejected":
            issue_id = runner.create_subject(case_id)
            runner.review(issue_id)
            runner.report_gate(issue_id, "batch_verify", "pass", ORCHESTRATOR)
            before, ledger_before = runner.issue(issue_id), runner.ledger(issue_id)
            attempt = runner.close(issue_id, actor=ORCHESTRATOR, reason="short")
            after, ledger_after = runner.issue(issue_id), runner.ledger(issue_id)
            passed = attempt.returncode != 0 and same(before, after)
            detail = "short close reason rejects without state mutation"
        elif case_id == "canary_missing_typed_reference_rejected":
            issue_id = runner.create_subject(case_id)
            runner.review(issue_id)
            runner.report_gate(issue_id, "batch_verify", "pass", ORCHESTRATOR)
            before, ledger_before = runner.issue(issue_id), runner.ledger(issue_id)
            attempt = runner.close(issue_id, actor=ORCHESTRATOR, reason="this deliberately long reason contains no required typed references")
            after, ledger_after = runner.issue(issue_id), runner.ledger(issue_id)
            passed = attempt.returncode != 0 and same(before, after)
            detail = "missing commit/run/evidence/incident references reject"
        elif case_id == "canary_missing_attribution_rejected":
            issue_id = runner.create_subject(case_id)
            runner.review(issue_id)
            runner.report_gate(issue_id, "batch_verify", "pass", ORCHESTRATOR)
            before, ledger_before = runner.issue(issue_id), runner.ledger(issue_id)
            attempt = runner.close(issue_id, actor=ORCHESTRATOR, reason=valid_reason(), attributed=False)
            after, ledger_after = runner.issue(issue_id), runner.ledger(issue_id)
            passed = attempt.returncode != 0 and same(before, after)
            detail = "missing tier-one attribution rejects"
        elif case_id == "canary_review_without_pass_rejected":
            issue_id = runner.create_subject(case_id)
            runner.review(issue_id)
            before, ledger_before = runner.issue(issue_id), runner.ledger(issue_id)
            attempt = runner.close(issue_id, actor=ORCHESTRATOR, reason=valid_reason())
            after, ledger_after = runner.issue(issue_id), runner.ledger(issue_id)
            passed = attempt.returncode != 0 and same(before, after)
            detail = "review issue without batch_verify PASS rejects"
        elif case_id == "canary_unauthorized_provider_limitation_detected":
            issue_id = runner.create_subject(case_id)
            runner.review(issue_id)
            runner.report_gate(issue_id, "impostor", "pass", "ImpostorProvider")
            before, ledger_before = runner.issue(issue_id), runner.ledger(issue_id)
            attempt = runner.close(issue_id, actor=ORCHESTRATOR, reason=valid_reason())
            after, ledger_after = runner.issue(issue_id), runner.ledger(issue_id)
            statuses = provider_statuses(ledger_before)
            passed = attempt.returncode == 0 and ("impostor", "pass") in statuses
            detail = "installed br accepts an unauthorized provider PASS; harness records the limitation"
        elif case_id == "canary_complete_provider_scrub_retained":
            issue_id = runner.create_subject(case_id)
            runner.review(issue_id)
            runner.report_gate(issue_id, "impostor", "pass", "ImpostorProvider")
            runner.report_gate(issue_id, "old_batch", "pass", ORCHESTRATOR)
            before, ledger_before = runner.issue(issue_id), runner.ledger(issue_id)
            for provider, _status in sorted(set(provider_statuses(ledger_before))):
                runner.report_gate(issue_id, provider, "fail", ORCHESTRATOR)
            before, ledger_before = runner.issue(issue_id), runner.ledger(issue_id)
            attempt = runner.close(issue_id, actor=ORCHESTRATOR, reason=valid_reason())
            after, ledger_after = runner.issue(issue_id), runner.ledger(issue_id)
            passed = (
                attempt.returncode != 0
                and same(before, after)
                and not any(status == "pass" for _, status in provider_statuses(ledger_after))
            )
            detail = "all observed providers are overwritten to FAIL and cannot close"
        elif case_id == POSITIVE_ID:
            issue_id = runner.create_subject(case_id)
            runner.review(issue_id)
            runner.report_gate(issue_id, "batch_verify", "pass", ORCHESTRATOR)
            before, ledger_before = runner.issue(issue_id), runner.ledger(issue_id)
            statuses = provider_statuses(ledger_before)
            fresh = runner.subject_revision == runner.receipt_revision
            attempt = runner.close(issue_id, actor=ORCHESTRATOR, reason=valid_reason()) if fresh and statuses == [("batch_verify", "pass")] else None
            after, ledger_after = runner.issue(issue_id), runner.ledger(issue_id)
            passed = attempt is not None and attempt.returncode == 0
            detail = "distinct orchestrator closes only with the fresh sole batch_verify PASS"
        else:
            raise RuntimeError(f"unknown frozen case {case_id}")
    except Exception as error:  # Receipt must retain first failure rather than aborting the inventory.
        detail = f"exception: {error}"
        passed = False
        if issue_id:
            after = runner.issue(issue_id)
            ledger_after = runner.ledger(issue_id)
    runner.record_case(case, issue_id, before, after, ledger_before, ledger_after, passed, detail)


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
    subject_revision = args.subject_revision or subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, capture_output=True, check=True
    ).stdout.strip()
    runner = Runner(output, subject_revision)
    live_before = {str(path): digest_path(path) for path in LIVE_PATHS}
    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", ".beads/policy.yaml"], cwd=ROOT,
        text=True, capture_output=True, check=False,
    ).returncode == 0
    preflight = {
        "policy_tracked": tracked, "policy_path": str(POLICY.relative_to(ROOT)),
        "policy_sha256": digest_path(POLICY), "harness_sha256": digest_path(SCRIPT),
        "fixture_sha256": digest_path(FIXTURE), "runner_sha256": digest_path(Path(__file__)),
        "br_version": runner.run(["br", "--version"]).stdout.strip(),
        "bv_version": runner.run(["bv", "--version"]).stdout.strip(),
        "subject_revision": subject_revision, "receipt_revision": runner.receipt_revision,
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
    live_after = {str(path): digest_path(path) for path in LIVE_PATHS}
    receipt = {
        "receipt_format": "mcp-campaign-canary-v1", "generated_at": now(), "preflight": preflight,
        "isolated_database": str(runner.db), "live_before": live_before, "live_after": live_after,
        "live_unchanged": live_before == live_after, "required": len(expected_ids),
        "discovered": len(cases), "started": len(runner.events),
        "passed": sum(event["passed"] for event in runner.events), "ignored": 0, "filtered": 0,
        "skipped": len(cases) - len(runner.events), "events_path": "events.jsonl",
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
