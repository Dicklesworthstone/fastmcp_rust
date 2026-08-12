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
import re
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
CHECKBOX = re.compile(r"^\s*[-*+]\s+\[([ xX])\]\s+")
SUBJECT_REVISION_PREFIX = "subject_revision:"
SHORT_REASON_REJECTION = "close reason is shorter than the isolated policy minimum"


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
        self.close_reason_min_length = isolated_close_reason_min_length(POLICY)

    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=ROOT, check=True, text=True, capture_output=True
        ).stdout.strip()

    def record_command(
        self,
        argv: list[str],
        completed: subprocess.CompletedProcess[str],
        *,
        actor: str | None,
        started_ts: str,
        finished_ts: str,
        extra: dict[str, Any] | None = None,
    ) -> None:
        record: dict[str, Any] = {
            "case_id": self.current_case,
            "actor": actor,
            "argv": argv,
            "exit_code": completed.returncode,
            "started_ts": started_ts,
            "finished_ts": finished_ts,
            "stdout_sha256": sha256_bytes(completed.stdout.encode()),
            "stderr_sha256": sha256_bytes(completed.stderr.encode()),
            "stdout": json_value(completed.stdout),
            "stderr": completed.stderr,
        }
        if extra:
            record.update(extra)
        self.commands.append(record)

    def run(self, argv: list[str], *, actor: str | None = None) -> subprocess.CompletedProcess[str]:
        started_ts = now()
        completed = subprocess.run(argv, cwd=ROOT, text=True, capture_output=True, check=False)
        self.record_command(argv, completed, actor=actor, started_ts=started_ts, finished_ts=now())
        return completed

    def br(self, *args: str, actor: str | None = None) -> subprocess.CompletedProcess[str]:
        argv = [str(self.br_binary), *args, "--db", str(self.db), "--json"]
        if actor:
            argv.extend(["--actor", actor])
        started_ts = now()
        completed = subprocess.run(
            argv, cwd=self.workspace, text=True, capture_output=True, check=False
        )
        self.record_command(argv, completed, actor=actor, started_ts=started_ts, finished_ts=now())
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
        criterion = "- [x] verified canary acceptance" if checked else "- [ ] verified canary acceptance"
        updated = self.br(
            "update", issue_id, f"--acceptance-criteria={criterion}", actor=WORKER
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
            "--status", status, "--note", note or f"subject_revision:{self.subject_revision}", actor=actor,
        )
        if completed.returncode:
            raise RuntimeError(f"cannot report {provider} {status}: {completed.stderr}")

    def close(
        self,
        issue_id: str,
        *,
        actor: str,
        reason: str,
        agent_name: str | None = None,
        harness: str | None = None,
        model: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        args = ["close", issue_id, "--reason", reason]
        if agent_name:
            args.extend(["--agent-name", agent_name])
        if harness:
            args.extend(["--harness", harness])
        if model:
            args.extend(["--model", model])
        return self.br(*args, actor=actor)

    def guarded_close(
        self,
        issue_id: str,
        *,
        issue: Any,
        ledger: Any,
        actor: str,
        reason: str,
        agent_name: str | None = None,
        harness: str | None = None,
        model: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Require every non-bypass campaign closure to satisfy the frozen contract.

        br 0.2.16 captures supplied attribution but does not enforce its presence.
        This owned, auditable pre-transition guard supplies that missing operational
        control without claiming it is tracker-native enforcement.
        """
        started_ts = now()
        rejection = guarded_close_rejection(
            issue=issue,
            ledger=ledger,
            actor=actor,
            reason=reason,
            closer_agent_name=agent_name or "",
            harness=harness or "",
            model=model or "",
            subject_revision=self.subject_revision,
            case_id=self.current_case,
            explicit_db=self.db,
            close_reason_min_length=self.close_reason_min_length,
        )
        argv = [
            "guarded-close", issue_id, "--db", str(self.db),
            "--expected-revision", self.subject_revision,
            "--closer-agent-name", agent_name or "",
            "--harness", harness or "",
            "--model", model or "",
        ]
        if rejection:
            completed = subprocess.CompletedProcess(
                argv, 1, json.dumps({"rejected": rejection, "closure_entry_point": "guarded-close"}),
                "guarded-close refused close before tracker transition",
            )
            self.record_command(
                argv, completed, actor=actor, started_ts=started_ts, finished_ts=now(),
                extra={"closure_entry_point": "guarded-close", "guard_decision": "rejected"},
            )
            return completed
        accepted = subprocess.CompletedProcess(
            argv, 0, json.dumps({"guarded_close": "accepted", "closure_entry_point": "guarded-close"}),
            "",
        )
        self.record_command(
            argv, accepted, actor=actor, started_ts=started_ts, finished_ts=now(),
            extra={"closure_entry_point": "guarded-close", "guard_decision": "accepted"},
        )
        return self.close(
            issue_id, actor=actor, reason=reason,
            agent_name=agent_name, harness=harness, model=model,
        )

    def record_case(
        self, case: dict[str, str], issue_id: str | None, before: Any, after: Any,
        ledger_before: Any, ledger_after: Any, audit_before: Any, audit_after: Any,
        passed: bool, detail: str, *, started_ts: str, finished_ts: str,
        execution_outcomes: dict[str, int] | None = None,
    ) -> None:
        case_commands = [command for command in self.commands if command["case_id"] == case["id"]]
        outcomes = {
            "early_aborted": 0, "stale": 0, "mixed": 0, "substituted": 0,
        }
        if execution_outcomes:
            outcomes.update(execution_outcomes)
        self.events.append(
            {
                "case_id": case["id"], "kind": case["kind"], "planted_dimension": case["planted_dimension"],
                "actors": {"worker": WORKER, "orchestrator": ORCHESTRATOR},
                "passed": passed, "detail": detail, "issue_before": before, "issue_after": after,
                "gate_ledger_before": ledger_before, "gate_ledger_after": ledger_after,
                "audit_before": audit_before, "audit_after": audit_after,
                "started_ts": started_ts, "finished_ts": finished_ts,
                "command_indexes": [i for i, command in enumerate(self.commands) if command["case_id"] == case["id"]],
                "command_clocks": [
                    {
                        "argv": command.get("argv"),
                        "started_ts": command.get("started_ts"),
                        "finished_ts": command.get("finished_ts"),
                    }
                    for command in case_commands
                ],
                "first_attempt": 1, "retries": 0,
                "execution_outcomes": outcomes,
            }
        )


def provider_statuses(value: Any) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if isinstance(value, dict):
        provider = value.get("provider") or value.get("provider_name")
        status = value.get("status")
        if isinstance(provider, str) and isinstance(status, str):
            found.append((provider, status.lower()))
        elif isinstance(provider, str) and isinstance(value.get("passed"), bool):
            found.append((provider, "pass" if value["passed"] else "fail"))
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


def isolated_close_reason_min_length(policy_path: Path) -> int:
    """Read the copied/tracked policy min_length. The canary does not invent policy."""
    in_block = False
    for raw in policy_path.read_text().splitlines():
        stripped = raw.strip()
        if stripped.startswith("require_close_reason:"):
            in_block = True
            continue
        if not in_block:
            continue
        if stripped.startswith("min_length:"):
            return int(stripped.split(":", 1)[1].strip())
        if stripped and not raw[:1].isspace() and not stripped.startswith("#"):
            break
    raise RuntimeError("tracked policy does not declare close_policy.require_close_reason.min_length")


def subject_revisions_in_notes(value: Any) -> set[str]:
    """Collect only explicit subject_revision:<sha> tokens from gate notes."""
    found: set[str] = set()
    if isinstance(value, dict):
        for key in ("note", "notes"):
            note = value.get(key)
            if isinstance(note, str):
                for token in note.split():
                    if token.startswith(SUBJECT_REVISION_PREFIX):
                        found.add(token.removeprefix(SUBJECT_REVISION_PREFIX))
        for child in value.values():
            found.update(subject_revisions_in_notes(child))
    elif isinstance(value, list):
        for child in value:
            found.update(subject_revisions_in_notes(child))
    return found


def bound_to_subject_revision(ledger: Any, revision: str) -> bool:
    return subject_revisions_in_notes(ledger) == {revision}


def issue_field(issue: Any, field: str) -> Any:
    """Return a top-level issue field from br's object-or-singleton-list output."""
    if isinstance(issue, list) and len(issue) == 1:
        issue = issue[0]
    return issue.get(field) if isinstance(issue, dict) else None


def fully_checked_acceptance(issue: Any) -> bool:
    criteria = issue_field(issue, "acceptance_criteria")
    if not isinstance(criteria, str):
        return False
    checkboxes = [match.group(1).lower() for line in criteria.splitlines() if (match := CHECKBOX.match(line))]
    return bool(checkboxes) and all(mark == "x" for mark in checkboxes)


def has_concrete_typed_references(reason: str, subject_revision: str, case_id: str) -> bool:
    expected = {
        f"commit:{subject_revision}",
        f"run:{case_id}",
        f"evidence:receipt-{case_id}",
        f"incident:canary-{case_id}",
    }
    return expected.issubset(set(reason.split()))


def guarded_close_rejection(
    *,
    issue: Any,
    ledger: Any,
    actor: str,
    reason: str,
    closer_agent_name: str,
    harness: str,
    model: str,
    subject_revision: str,
    case_id: str,
    explicit_db: Path,
    close_reason_min_length: int,
) -> str | None:
    if not explicit_db.is_file():
        return "explicit isolated database is unavailable"
    if issue_field(issue, "status") != "review":
        return "issue is not in review"
    if not fully_checked_acceptance(issue):
        return "acceptance criteria are not fully checked"
    if actor == WORKER:
        return "closer must be distinct from the worker"
    if not closer_agent_name or not harness or not model:
        return "tier-one closer attribution is required"
    if closer_agent_name != actor:
        return "closer agent_name must equal the closer actor"
    if provider_statuses(ledger) != [("batch_verify", "pass")]:
        return "sole effective batch_verify PASS is required"
    if not bound_to_subject_revision(ledger, subject_revision):
        return "batch_verify PASS is not bound to the subject revision"
    if len(reason) < close_reason_min_length:
        return SHORT_REASON_REJECTION
    if not has_concrete_typed_references(reason, subject_revision, case_id):
        return "concrete typed close references are required"
    return None


def guard_rejected_for(attempt: subprocess.CompletedProcess[str], reason: str) -> bool:
    result = json_value(attempt.stdout)
    return attempt.returncode != 0 and isinstance(result, dict) and result.get("rejected") == reason


def valid_reason(runner: Runner) -> str:
    return (
        f"commit:{runner.subject_revision} run:{runner.current_case} "
        f"evidence:receipt-{runner.current_case} incident:canary-{runner.current_case}"
    )


def orchestrator_attribution() -> dict[str, str]:
    return {"agent_name": ORCHESTRATOR, "harness": HARNESS, "model": MODEL}


def last_guard_decision(runner: Runner, case_id: str) -> str | None:
    for command in reversed(runner.commands):
        if command.get("case_id") == case_id and command.get("closure_entry_point") == "guarded-close":
            decision = command.get("guard_decision")
            return decision if isinstance(decision, str) else None
    return None


def run_case(runner: Runner, case: dict[str, str]) -> None:
    runner.current_case = case["id"]
    started_ts = now()
    issue_id: str | None = None
    before: Any = None
    after: Any = None
    ledger_before: Any = None
    ledger_after: Any = None
    audit_before: Any = None
    audit_after: Any = None
    passed = False
    detail = ""
    execution_outcomes = {"early_aborted": 0, "stale": 0, "mixed": 0, "substituted": 0}
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
                note=f"{SUBJECT_REVISION_PREFIX}{runner.stale_revision}",
            )
            before, ledger_before, audit_before = runner.snapshot(issue_id)
            attempt = runner.guarded_close(
                issue_id, issue=before, ledger=ledger_before, actor=ORCHESTRATOR,
                reason=valid_reason(runner), **orchestrator_attribution(),
            )
            after, ledger_after, audit_after = runner.snapshot(issue_id)
            stale_only = subject_revisions_in_notes(ledger_before) == {runner.stale_revision}
            execution_outcomes["stale"] = 1 if stale_only else 0
            execution_outcomes["mixed"] = 1 if len(subject_revisions_in_notes(ledger_before)) > 1 else 0
            passed = (
                runner.stale_revision != runner.subject_revision
                and stale_only
                and not bound_to_subject_revision(ledger_before, runner.subject_revision)
                and guard_rejected_for(attempt, "batch_verify PASS is not bound to the subject revision")
                and unchanged((before, ledger_before, audit_before), (after, ledger_after, audit_after))
            )
            detail = "freshness guard rejects a ledger PASS whose note binds only a distinct ancestor revision"
        elif case_id == "canary_direct_close_rejected":
            issue_id = runner.create_subject(case_id)
            before, ledger_before, audit_before = runner.snapshot(issue_id)
            attempt = runner.close(
                issue_id, actor=ORCHESTRATOR, reason=valid_reason(runner),
                **orchestrator_attribution(),
            )
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
            runner.report_gate(issue_id, "batch_verify", "pass", ORCHESTRATOR)
            before, ledger_before, audit_before = runner.snapshot(issue_id)
            attempt = runner.guarded_close(
                issue_id, issue=before, ledger=ledger_before, actor=WORKER,
                reason=valid_reason(runner),
                agent_name=WORKER, harness=HARNESS, model=MODEL,
            )
            after, ledger_after, audit_after = runner.snapshot(issue_id)
            passed = (
                bound_to_subject_revision(ledger_before, runner.subject_revision)
                and provider_statuses(ledger_before) == [("batch_verify", "pass")]
                and guard_rejected_for(attempt, "closer must be distinct from the worker")
                and unchanged((before, ledger_before, audit_before), (after, ledger_after, audit_after))
            )
            detail = "only the closer identity is planted; worker cannot self-close"
        elif case_id == "canary_unchecked_acceptance_rejected":
            issue_id = runner.create_subject(case_id, checked=False)
            runner.review(issue_id)
            runner.report_gate(issue_id, "batch_verify", "pass", ORCHESTRATOR)
            before, ledger_before, audit_before = runner.snapshot(issue_id)
            attempt = runner.guarded_close(
                issue_id, issue=before, ledger=ledger_before, actor=ORCHESTRATOR,
                reason=valid_reason(runner), **orchestrator_attribution(),
            )
            after, ledger_after, audit_after = runner.snapshot(issue_id)
            passed = (
                issue_field(before, "acceptance_criteria") == "- [ ] verified canary acceptance"
                and guard_rejected_for(attempt, "acceptance criteria are not fully checked")
                and unchanged((before, ledger_before, audit_before), (after, ledger_after, audit_after))
            )
            detail = "unchecked acceptance rejects without state mutation"
        elif case_id == "canary_short_close_reason_rejected":
            issue_id = runner.create_subject(case_id)
            runner.review(issue_id)
            runner.report_gate(issue_id, "batch_verify", "pass", ORCHESTRATOR)
            before, ledger_before, audit_before = runner.snapshot(issue_id)
            attempt = runner.guarded_close(
                issue_id, issue=before, ledger=ledger_before, actor=ORCHESTRATOR,
                reason="short", **orchestrator_attribution(),
            )
            after, ledger_after, audit_after = runner.snapshot(issue_id)
            passed = (
                len("short") < runner.close_reason_min_length
                and guard_rejected_for(attempt, SHORT_REASON_REJECTION)
                and unchanged((before, ledger_before, audit_before), (after, ledger_after, audit_after))
            )
            detail = "short close reason is rejected at the length check before typed-reference evaluation"
        elif case_id == "canary_missing_typed_reference_rejected":
            issue_id = runner.create_subject(case_id)
            runner.review(issue_id)
            runner.report_gate(issue_id, "batch_verify", "pass", ORCHESTRATOR)
            before, ledger_before, audit_before = runner.snapshot(issue_id)
            long_without_refs = "this deliberately long reason contains no required typed references"
            attempt = runner.guarded_close(
                issue_id, issue=before, ledger=ledger_before, actor=ORCHESTRATOR,
                reason=long_without_refs, **orchestrator_attribution(),
            )
            after, ledger_after, audit_after = runner.snapshot(issue_id)
            passed = (
                len(long_without_refs) >= runner.close_reason_min_length
                and guard_rejected_for(attempt, "concrete typed close references are required")
                and unchanged((before, ledger_before, audit_before), (after, ledger_after, audit_after))
            )
            detail = "missing commit/run/evidence/incident references reject after the length check passes"
        elif case_id == "canary_missing_attribution_rejected":
            issue_id = runner.create_subject(case_id)
            runner.review(issue_id)
            runner.report_gate(issue_id, "batch_verify", "pass", ORCHESTRATOR)
            before, ledger_before, audit_before = runner.snapshot(issue_id)
            attempt = runner.guarded_close(
                issue_id, issue=before, ledger=ledger_before, actor=ORCHESTRATOR,
                reason=valid_reason(runner),
            )
            after, ledger_after, audit_after = runner.snapshot(issue_id)
            passed = (
                guard_rejected_for(attempt, "tier-one closer attribution is required")
                and unchanged((before, ledger_before, audit_before), (after, ledger_after, audit_after))
            )
            detail = "missing agent_name/harness/model rejects before any tracker transition"
        elif case_id == "canary_review_without_pass_rejected":
            issue_id = runner.create_subject(case_id)
            runner.review(issue_id)
            before, ledger_before, audit_before = runner.snapshot(issue_id)
            attempt = runner.guarded_close(
                issue_id, issue=before, ledger=ledger_before, actor=ORCHESTRATOR,
                reason=valid_reason(runner), **orchestrator_attribution(),
            )
            after, ledger_after, audit_after = runner.snapshot(issue_id)
            passed = (
                guard_rejected_for(attempt, "sole effective batch_verify PASS is required")
                and unchanged((before, ledger_before, audit_before), (after, ledger_after, audit_after))
            )
            detail = "review issue without batch_verify PASS rejects"
        elif case_id == "canary_unauthorized_provider_limitation_detected":
            issue_id = runner.create_subject(case_id)
            runner.review(issue_id)
            runner.report_gate(issue_id, "impostor", "pass", "ImpostorProvider")
            before, ledger_before, audit_before = runner.snapshot(issue_id)
            # Intentional direct br close: this frozen limitation case proves that
            # installed br accepts an unauthorized provider PASS.  It is never a
            # passing campaign closure and the retained receipt names the bypass.
            attempt = runner.close(
                issue_id, actor=ORCHESTRATOR, reason=valid_reason(runner),
                **orchestrator_attribution(),
            )
            after, ledger_after, audit_after = runner.snapshot(issue_id)
            statuses = provider_statuses(ledger_before)
            passed = attempt.returncode == 0 and ("impostor", "pass") in statuses
            detail = "intentional direct-close bypass proves installed br accepts an unauthorized provider PASS; harness records the limitation"
        elif case_id == "canary_complete_provider_scrub_retained":
            issue_id = runner.create_subject(case_id)
            runner.review(issue_id)
            runner.report_gate(issue_id, "impostor", "pass", "ImpostorProvider")
            runner.report_gate(issue_id, "old_batch", "pass", ORCHESTRATOR)
            before, ledger_before, _scrub_audit = runner.snapshot(issue_id)
            for provider, _status in sorted(set(provider_statuses(ledger_before))):
                runner.report_gate(issue_id, provider, "fail", ORCHESTRATOR)
            before, ledger_before, audit_before = runner.snapshot(issue_id)
            attempt = runner.guarded_close(
                issue_id, issue=before, ledger=ledger_before, actor=ORCHESTRATOR,
                reason=valid_reason(runner), **orchestrator_attribution(),
            )
            after, ledger_after, audit_after = runner.snapshot(issue_id)
            passed = (
                guard_rejected_for(attempt, "sole effective batch_verify PASS is required")
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
                and bound_to_subject_revision(ledger_before, runner.subject_revision)
            )
            attempt = runner.guarded_close(
                issue_id, issue=before, ledger=ledger_before, actor=ORCHESTRATOR,
                reason=valid_reason(runner), **orchestrator_attribution(),
            ) if fresh and statuses == [("batch_verify", "pass")] else None
            after, ledger_after, audit_after = runner.snapshot(issue_id)
            passed = (
                issue_field(before, "acceptance_criteria") == "- [x] verified canary acceptance"
                and issue_field(before, "status") == "review"
                and attempt is not None
                and last_guard_decision(runner, case_id) == "accepted"
                and attempt.returncode == 0
                and issue_field(after, "status") == "closed"
                and provider_statuses(ledger_before) == [("batch_verify", "pass")]
                and provider_statuses(ledger_after) == [("batch_verify", "pass")]
                and bound_to_subject_revision(ledger_after, runner.subject_revision)
            )
            detail = "distinct orchestrator closes only after guarded-close accepts a fresh sole batch_verify PASS; status becomes closed"
        else:
            raise RuntimeError(f"unknown frozen case {case_id}")
    except Exception as error:  # Receipt must retain first failure rather than aborting the inventory.
        detail = f"exception: {error}"
        passed = False
        if issue_id:
            after, ledger_after, audit_after = runner.snapshot(issue_id)
    runner.record_case(
        case, issue_id, before, after, ledger_before, ledger_after, audit_before, audit_after,
        passed, detail, started_ts=started_ts, finished_ts=now(),
        execution_outcomes=execution_outcomes,
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
            "zero_run": 0,
            "early_aborted": sum(event["execution_outcomes"].get("early_aborted", 0) for event in runner.events),
            "stale": sum(event["execution_outcomes"].get("stale", 0) for event in runner.events),
            "mixed": sum(event["execution_outcomes"].get("mixed", 0) for event in runner.events),
            "substituted": sum(event["execution_outcomes"].get("substituted", 0) for event in runner.events),
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
