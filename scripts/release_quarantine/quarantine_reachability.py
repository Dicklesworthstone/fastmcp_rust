#!/usr/bin/env python3
"""REL-QUAR-00 release-quarantine reachability checker (fail-closed, offline).

Bead: bd-mcp-rel-quar-00-p1f0 (fastmcp_rust).

Purpose
-------
Prove, statically and deterministically, that every event path of every
checked-in GitHub Actions workflow ends in ZERO external mutation and ZERO
secret access, and that no future edit can silently reintroduce a mutation
path without this checker failing closed.

Design stance
-------------
* Dependency-free restricted YAML recognizer: it accepts exactly the
  mapping/sequence/block-scalar subset used by the checked-in workflows and
  FAILS CLOSED on any construct it does not recognize. Structural drift in a
  quarantined workflow is itself a quarantine violation.
* Allowlist policy everywhere: known triggers, known pinned actions, known
  permission scopes, known environment variable names. Anything not
  explicitly allowed is a finding.
* The checked-in reachability matrix (reachability_matrix.toml) must cover
  the twelve mandated event sources and must agree with the triggers
  actually derived from the parsed workflows.
* Modes:
    default            analyze .github/workflows/*.yml against the matrix;
                       exit 0 iff every path is externally inert
    --self-test        apply in-memory quarantine-violation plants and
                       require every one to be detected (plus matrix
                       completeness negatives); exits 0 iff all caught
    --provider-audit   READ-ONLY GitHub API evidence collection (workflow
                       states, historical runs, secrets, environments);
                       emits a receipt; exit 0 iff provider verdict is SAFE
    --json             machine-readable output for the default mode
* This tool never performs a mutating API call and never prints secret
  values; it reports secret NAMES only.

Exit codes: 0 pass, 1 findings (default) / plant escaped (self-test),
2 provider verdict UNSAFE or provider evidence unavailable.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
MATRIX_PATH = Path(__file__).resolve().parent / "reachability_matrix.toml"

MANDATED_EVENT_SOURCES = [
    "tag_push",
    "branch_push",
    "pull_request",
    "manual_dispatch",
    "rerun",
    "reusable_invocation",
    "environment_approval",
    "fork_context",
    "token_present",
    "token_absent",
    "adversarial_ref_input",
    "historical_queued_run",
]

# Actions permitted in ANY checked-in workflow. Exact SHA pins only.
ALLOWED_ACTIONS = {
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "dtolnay/rust-toolchain@6c977a6ca4077a0ceb28ffbe03f59d46e9ac8772",
    "swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6",
    "taiki-e/install-action@6c6fd71fe4fb72c3697d269963d0e15df8adedad",
    "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
}

# Trigger keys permitted under `on:`. Everything else is a finding.
ALLOWED_TRIGGER_KEYS = {"push", "pull_request", "workflow_dispatch"}

# Under `push:` only these sub-keys are allowed (tags are FORBIDDEN).
PUSH_ALLOWED_SUBKEYS = {"branches"}
# Under `pull_request:` only these sub-keys are allowed.
PR_ALLOWED_SUBKEYS = {"branches"}

# Permission mappings allowed at workflow or job level. Only the minimum
# read scope survives quarantine.
ALLOWED_PERMISSIONS = {"contents": "read"}

# Top-level workflow env allowlist (exact names).
TOP_ENV_ALLOWLIST = {"CARGO_TERM_COLOR", "RUST_BACKTRACE"}

# Secret-bearing or credential-bearing env names are rejected outright.
FORBIDDEN_ENV_NAME_RE = re.compile(
    r"(token|secret|password|credential|apikey|api_key|key)", re.IGNORECASE
)

# Shell command patterns that constitute external mutation or credential
# access. Applied to every `run:` block.
FORBIDDEN_RUN_RES = [
    (re.compile(r"\bcargo\s+publish\b", re.IGNORECASE), "cargo publish"),
    (re.compile(r"\bcargo\s+login\b", re.IGNORECASE), "cargo login"),
    (re.compile(r"\bnpm\s+publish\b", re.IGNORECASE), "npm publish"),
    (re.compile(r"\bdocker\s+push\b", re.IGNORECASE), "docker push"),
    (re.compile(r"\boras\s+push\b", re.IGNORECASE), "oras push"),
    (re.compile(r"\bgh\s+\w", re.IGNORECASE), "gh CLI invocation"),
    (re.compile(r"\bgit\s+push\b", re.IGNORECASE), "git push"),
    (re.compile(r"\bgit\s+tag\b", re.IGNORECASE), "git tag"),
    (re.compile(r"\bhub\s+release\b", re.IGNORECASE), "hub release"),
    (re.compile(r"\bcurl\b", re.IGNORECASE), "curl"),
    (re.compile(r"\bwget\b", re.IGNORECASE), "wget"),
    (re.compile(r"\bhttpie\b|\bhttp\s+://", re.IGNORECASE), "http client"),
]

# Substrings that make a step/job `if:` condition quarantine-relevant.
FORBIDDEN_IF_SUBSTRINGS = [
    "refs/tags",
    "github.event.release",
    "secrets.",
    "inputs.",
    "vars.",
]

MAX_ARTIFACT_RETENTION_DAYS = 30


class RestrictedYamlError(Exception):
    """Raised on any construct outside the recognized workflow subset."""


# --------------------------------------------------------------------------
# Restricted YAML recognizer (mapping / sequence / block scalar / flow seq)
# --------------------------------------------------------------------------


def _strip_comment(line: str) -> str:
    out = []
    quote = None
    for idx, ch in enumerate(line):
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            out.append(ch)
            continue
        if ch == "#" and (idx == 0 or line[idx - 1] in " \t"):
            break
        out.append(ch)
    return "".join(out).rstrip()


def _split_flow_seq(body: str) -> list[str]:
    """Split '[a, b, c]' on top-level commas."""
    items: list[str] = []
    depth = 0
    cur: list[str] = []
    quote = None
    for ch in body:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            cur.append(ch)
            continue
        if ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        if ch == "," and depth == 0:
            items.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        items.append(tail)
    return items


def _scalar(text: str):
    text = text.strip()
    if text.startswith("[") and text.endswith("]"):
        return [_scalar(item) for item in _split_flow_seq(text[1:-1])]
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
        return text[1:-1]
    return text


def _parse_block(rows: list[tuple[int, str]], i: int, indent: int):
    """Parse a mapping or sequence block whose entries sit at `indent`.

    rows: list of (indent, content) with comments/blanks removed.
    Returns (value, next_index).
    """
    if i < len(rows) and rows[i][0] == indent and rows[i][1].startswith("- "):
        return _parse_sequence(rows, i, indent)
    return _parse_mapping(rows, i, indent)


def _parse_sequence(rows, i, indent):
    seq = []
    while i < len(rows) and rows[i][0] == indent and rows[i][1].startswith("- "):
        item_text = rows[i][1][2:].strip()
        item_indent = rows[i][0] + 2
        if _has_top_level_colon(item_text):
            # Sequence item that opens a mapping ("- name: x").
            key, _, rest = _split_key(item_text)
            virtual = [(item_indent, f"{key}: {rest}".strip())]
            j = i + 1
            while j < len(rows) and rows[j][0] >= item_indent and not (
                rows[j][0] == indent and rows[j][1].startswith("- ")
            ):
                virtual.append(rows[j])
                j += 1
            mapping, consumed = _parse_mapping(virtual, 0, item_indent)
            if consumed != len(virtual):
                raise RestrictedYamlError(f"unconsumed sequence-item rows near {virtual}")
            seq.append(mapping)
            i = j
        elif item_text:
            seq.append(_scalar(item_text))
            i += 1
        else:
            # Bare "-" then nested block below.
            j = i + 1
            if j < len(rows) and rows[j][0] > indent:
                value, j = _parse_block(rows, j, rows[j][0])
                seq.append(value)
            else:
                seq.append(None)
            i = j
    return seq, i


def _has_top_level_colon(text: str) -> bool:
    quote = None
    depth = 0
    for idx, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            continue
        if ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        elif ch == ":" and depth == 0:
            if idx + 1 == len(text) or text[idx + 1] in " \t":
                return True
    return False


def _split_key(text: str) -> tuple[str, str, str]:
    quote = None
    depth = 0
    for idx, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            continue
        if ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        elif ch == ":" and depth == 0:
            if idx + 1 == len(text) or text[idx + 1] in " \t":
                return text[:idx].strip(), text[idx : idx + 2].strip(), text[idx + 1 :].strip()
    raise RestrictedYamlError(f"expected 'key: value' pair, got: {text!r}")



def _parse_mapping(rows, i, indent):
    mapping: dict = {}
    while i < len(rows) and rows[i][0] == indent:
        content = rows[i][1]
        if content.startswith("- "):
            break
        key, sep, rest = _split_key(content)
        if sep == "":
            raise RestrictedYamlError(f"'{key}' lacks ': ' separator")
        if rest == "|" or rest == "|-" or rest == ">" or rest == ">-":
            # Block scalar: consume following deeper-indented lines verbatim.
            j = i + 1
            block_lines: list[str] = []
            while j < len(rows) and rows[j][0] > indent:
                block_lines.append(" " * rows[j][0] + rows[j][1])
                j += 1
            mapping[key] = "\n".join(block_lines)
            if block_lines:
                mapping[key] += "\n"
            i = j
        elif rest == "":
            j = i + 1
            if j < len(rows) and rows[j][0] > indent:
                value, j = _parse_block(rows, j, rows[j][0])
                mapping[key] = value
            elif j < len(rows) and rows[j][0] == indent and rows[j][1].startswith("- "):
                value, j = _parse_sequence(rows, j, indent)
                mapping[key] = value
            else:
                mapping[key] = None
            i = j
        else:
            mapping[key] = _scalar(rest)
            i += 1
    return mapping, i


def parse_workflow_text(text: str, origin: str):
    rows: list[tuple[int, str]] = []
    for raw in text.splitlines():
        stripped = _strip_comment(raw.replace("\t", "    "))
        if not stripped.strip():
            continue
        if stripped.strip() in ("---", "..."):
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        if stripped[indent:] == "-":
            rows.append((indent, "- "))
            continue
        rows.append((indent, stripped[indent:]))
    if not rows:
        raise RestrictedYamlError(f"{origin}: empty document")
    doc, consumed = _parse_block(rows, 0, rows[0][0])
    if consumed != len(rows):
        raise RestrictedYamlError(
            f"{origin}: unrecognized structure at row {consumed}: {rows[consumed]!r}"
        )
    if not isinstance(doc, dict):
        raise RestrictedYamlError(f"{origin}: top level must be a mapping")
    return doc


# --------------------------------------------------------------------------
# Policy analysis
# --------------------------------------------------------------------------


class Finding:
    def __init__(self, file: str, location: str, rule: str, detail: str):
        self.file = file
        self.location = location
        self.rule = rule
        self.detail = detail

    def as_row(self) -> dict:
        return {
            "file": self.file,
            "location": self.location,
            "rule": self.rule,
            "detail": self.detail,
        }

    def __str__(self) -> str:
        return f"[{self.rule}] {self.file}:{self.location}: {self.detail}"



def _check_triggers(doc, fname: str, findings: list[Finding]) -> set[str]:
    """Validate the `on:` block; return derived reachable event classes."""
    triggers = doc.get("on")
    reachable: set[str] = set()
    if triggers is None:
        findings.append(Finding(fname, "on", "TRIGGER_REQUIRED", "workflow declares no trigger"))
        return reachable
    if isinstance(triggers, str):
        triggers = [triggers]
    if isinstance(triggers, list):
        normalized: dict = {}
        for item in triggers:
            normalized[item] = None
        triggers = normalized
    if not isinstance(triggers, dict):
        raise RestrictedYamlError(f"{fname}: unsupported `on:` shape")

    for key, spec in triggers.items():
        if key not in ALLOWED_TRIGGER_KEYS:
            findings.append(
                Finding(fname, f"on.{key}", "TRIGGER_FORBIDDEN", f"trigger '{key}' is not allowed")
            )
            continue
        if key == "workflow_dispatch":
            reachable.add("manual_dispatch")
            if spec not in (None, {}, []):
                findings.append(
                    Finding(
                        fname,
                        "on.workflow_dispatch",
                        "DISPATCH_INPUTS_FORBIDDEN",
                        "manual dispatch must declare no inputs "
                        f"(found: {spec!r})",
                    )
                )
            else:
                reachable.add("adversarial_ref_input")
        elif key == "push":
            reachable.add("branch_push")
            if spec is None:
                findings.append(
                    Finding(
                        fname,
                        "on.push",
                        "PUSH_SPEC_REQUIRED",
                        "unqualified push trigger would also fire on tags",
                    )
                )
                continue
            if not isinstance(spec, dict):
                raise RestrictedYamlError(f"{fname}: unsupported push shape")
            for sub in spec:
                if sub not in PUSH_ALLOWED_SUBKEYS:
                    findings.append(
                        Finding(
                            fname,
                            f"on.push.{sub}",
                            "PUSH_TAG_TRIGGER_FORBIDDEN"
                            if sub == "tags"
                            else "PUSH_SUBKEY_FORBIDDEN",
                            f"push.{sub} is not allowed in quarantine",
                        )
                    )
        elif key == "pull_request":
            reachable.add("pull_request")
            reachable.add("fork_context")
            if spec is None:
                continue
            if not isinstance(spec, dict):
                raise RestrictedYamlError(f"{fname}: unsupported pull_request shape")
            for sub in spec:
                if sub not in PR_ALLOWED_SUBKEYS:
                    findings.append(
                        Finding(
                            fname,
                            f"on.pull_request.{sub}",
                            "PR_SUBKEY_FORBIDDEN",
                            f"pull_request.{sub} is not allowed",
                        )
                    )
    return reachable


def _check_permissions(perms, where: str, fname: str, findings: list[Finding]) -> None:
    if perms is None:
        findings.append(
            Finding(fname, f"{where}.permissions", "PERMISSIONS_REQUIRED", "permissions block missing")
        )
        return
    if isinstance(perms, str):
        findings.append(
            Finding(
                fname,
                f"{where}.permissions",
                "PERMISSIONS_NOT_MINIMAL",
                f"shorthand permission '{perms}' grants more than contents: read",
            )
        )
        return
    if not isinstance(perms, dict):
        raise RestrictedYamlError(f"{fname}: unsupported permissions shape at {where}")
    if not perms:
        findings.append(
            Finding(fname, f"{where}.permissions", "PERMISSIONS_REQUIRED", "permissions empty")
        )
        return
    for scope, level in perms.items():
        expected = ALLOWED_PERMISSIONS.get(scope)
        if expected is None:
            findings.append(
                Finding(
                    fname,
                    f"{where}.permissions.{scope}",
                    "PERMISSION_SCOPE_FORBIDDEN",
                    f"scope '{scope}' is not part of the read-only minimum",
                )
            )
        elif level != expected:
            findings.append(
                Finding(
                    fname,
                    f"{where}.permissions.{scope}",
                    "PERMISSION_LEVEL_FORBIDDEN",
                    f"{scope}: {level!r} exceeds the read-only minimum ({expected})",
                )
            )


def _scan_scalar_for_secrets(text: str, fname: str, location: str, findings: list[Finding]) -> None:
    if "${{ secrets." in text or "$${{ secrets." in text:
        findings.append(
            Finding(fname, location, "SECRET_REFERENCE_FORBIDDEN", f"secret expression in {location}")
        )
    if "to_token" in text and "github.token" in text.lower():
        findings.append(Finding(fname, location, "SECRET_REFERENCE_FORBIDDEN", "github token minting"))


def _check_steps(steps, job_name: str, fname: str, findings: list[Finding]) -> None:
    if not isinstance(steps, list):
        raise RestrictedYamlError(f"{fname}: steps of job {job_name} must be a sequence")
    for idx, step in enumerate(steps):
        loc = f"{job_name}.steps[{idx}]"
        if not isinstance(step, dict):
            raise RestrictedYamlError(f"{fname}: step {loc} must be a mapping")
        uses = step.get("uses")
        if uses is not None:
            if not isinstance(uses, str):
                raise RestrictedYamlError(f"{fname}: uses at {loc} must be a string")
            base, at, ref = uses.partition("@")
            if at == "" or not re.fullmatch(r"[0-9a-f]{40}", ref):
                findings.append(
                    Finding(
                        fname,
                        f"{loc}.uses",
                        "ACTION_NOT_SHA_PINNED",
                        f"'{uses}' is not pinned to a full 40-hex commit SHA",
                    )
                )
            elif uses not in ALLOWED_ACTIONS and base.lower() + "@" + ref not in {
                a.lower() for a in ALLOWED_ACTIONS
            }:
                findings.append(
                    Finding(
                        fname,
                        f"{loc}.uses",
                        "ACTION_NOT_ALLOWLISTED",
                        f"'{base}' is not an allowlisted action",
                    )
                )
            with_block = step.get("with")
            if isinstance(with_block, dict):
                for wkey, wval in with_block.items():
                    if isinstance(wval, str):
                        _scan_scalar_for_secrets(wval, fname, f"{loc}.with.{wkey}", findings)
                    if wkey == "persist-credentials" and wval not in (False, "false"):
                        findings.append(
                            Finding(
                                fname,
                                f"{loc}.with.persist-credentials",
                                "PERSIST_CREDENTIALS_FORBIDDEN",
                                "checkout must not persist credentials",
                            )
                        )
        run = step.get("run")
        if run is not None:
            if not isinstance(run, str):
                raise RestrictedYamlError(f"{fname}: run at {loc} must be a string")
            for regex, label in FORBIDDEN_RUN_RES:
                match = regex.search(run)
                if match:
                    findings.append(
                        Finding(
                            fname,
                            f"{loc}.run",
                            "MUTATING_COMMAND_FORBIDDEN",
                            f"{label} matched near {match.group(0)!r}",
                        )
                    )
            _scan_scalar_for_secrets(run, fname, f"{loc}.run", findings)
        cond = step.get("if")
        if isinstance(cond, str):
            for needle in FORBIDDEN_IF_SUBSTRINGS:
                if needle in cond:
                    findings.append(
                        Finding(
                            fname,
                            f"{loc}.if",
                            "CONDITION_QUARANTINE_RELEVANT",
                            f"condition references '{needle}'",
                        )
                    )
        env = step.get("env")
        if env is not None:
            _check_env(env, f"{loc}.env", fname, findings, top_level=False)
        if "environment" in step:
            findings.append(
                Finding(fname, f"{loc}.environment", "ENVIRONMENT_FORBIDDEN", "step environment declared")
            )
        if "continue-on-error" in step:
            # Masking failures could hide quarantine drift; disallow in
            # quarantine-relevant surfaces.
            findings.append(
                Finding(
                    fname,
                    f"{loc}.continue-on-error",
                    "CONTINUE_ON_ERROR_FORBIDDEN",
                    "failure masking is not allowed in quarantined workflows",
                )
            )


def _check_env(env, where: str, fname: str, findings: list[Finding], *, top_level: bool) -> None:
    if not isinstance(env, dict):
        raise RestrictedYamlError(f"{fname}: env at {where} must be a mapping")
    for name, value in env.items():
        if FORBIDDEN_ENV_NAME_RE.search(name):
            findings.append(
                Finding(
                    fname,
                    f"{where}.{name}",
                    "CREDENTIAL_ENV_NAME_FORBIDDEN",
                    f"env name '{name}' looks credential-bearing",
                )
            )
        if isinstance(value, str):
            _scan_scalar_for_secrets(value, fname, f"{where}.{name}", findings)
        if top_level and name not in TOP_ENV_ALLOWLIST:
            findings.append(
                Finding(
                    fname,
                    f"{where}.{name}",
                    "TOP_ENV_NOT_ALLOWLISTED",
                    f"top-level env '{name}' is not allowlisted",
                )
            )


def _check_artifact_uploads(doc, fname: str, findings: list[Finding]) -> None:
    """upload-artifact stays a private expiring diagnostic: bound retention."""
    jobs = doc.get("jobs") or {}
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps") or []
        for idx, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            uses = step.get("uses") or ""
            if not uses.lower().startswith("actions/upload-artifact@"):
                continue
            with_block = step.get("with") or {}
            retention = with_block.get("retention-days", 90)
            try:
                retention_int = int(retention)
            except (TypeError, ValueError):
                findings.append(
                    Finding(
                        fname,
                        f"{job_name}.steps[{idx}].retention-days",
                        "ARTIFACT_RETENTION_INVALID",
                        f"retention-days {retention!r} is not an integer",
                    )
                )
                continue
            if retention_int > MAX_ARTIFACT_RETENTION_DAYS:
                findings.append(
                    Finding(
                        fname,
                        f"{job_name}.steps[{idx}].retention-days",
                        "ARTIFACT_RETENTION_TOO_LONG",
                        f"retention {retention_int}d exceeds {MAX_ARTIFACT_RETENTION_DAYS}d diagnostic bound",
                    )
                )


def _derive_reachable_from_doc(doc, fname: str, findings: list[Finding]) -> set[str]:
    reachable = _check_triggers(doc, fname, findings)
    _check_permissions(doc.get("permissions"), "workflow", fname, findings)
    env = doc.get("env")
    if env is not None:
        _check_env(env, "workflow.env", fname, findings, top_level=True)
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        raise RestrictedYamlError(f"{fname}: jobs must be a non-empty mapping")
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            raise RestrictedYamlError(f"{fname}: job {job_name} must be a mapping")
        # A job without its own permissions block inherits the workflow-level
        # block, which was validated read-only above; only an explicit
        # per-job block must independently satisfy the allowlist.
        if "permissions" in job:
            _check_permissions(job["permissions"], f"job.{job_name}", fname, findings)
        if "environment" in job:
            findings.append(
                Finding(
                    fname,
                    f"job.{job_name}.environment",
                    "ENVIRONMENT_FORBIDDEN",
                    f"job '{job_name}' declares a GitHub environment",
                )
            )
        cond = job.get("if")
        if isinstance(cond, str):
            for needle in FORBIDDEN_IF_SUBSTRINGS:
                if needle in cond:
                    findings.append(
                        Finding(
                            fname,
                            f"job.{job_name}.if",
                            "CONDITION_QUARANTINE_RELEVANT",
                            f"job condition references '{needle}'",
                        )
                    )
        _check_steps(job.get("steps"), f"job.{job_name}", fname, findings)
    _check_artifact_uploads(doc, fname, findings)
    return reachable


def analyze_workflows() -> tuple[dict[str, dict], list[Finding], dict[str, set[str]]]:
    findings: list[Finding] = []
    docs: dict[str, dict] = {}
    reach: dict[str, set[str]] = {}
    if not WORKFLOW_DIR.is_dir():
        findings.append(
            Finding(str(WORKFLOW_DIR), "-", "WORKFLOW_DIR_MISSING", ".github/workflows not found")
        )
        return docs, findings, reach
    for path in sorted(WORKFLOW_DIR.glob("*.y*ml")):
        rel = path.relative_to(REPO_ROOT).as_posix()
        text = path.read_text(encoding="utf-8")
        try:
            doc = parse_workflow_text(text, rel)
        except RestrictedYamlError as err:
            findings.append(Finding(rel, "-", "UNRECOGNIZED_STRUCTURE", str(err)))
            continue
        docs[rel] = doc
        reach[rel] = _derive_reachable_from_doc(doc, rel, findings)
    return docs, findings, reach


# --------------------------------------------------------------------------
# Reachability matrix
# --------------------------------------------------------------------------


def load_matrix():
    with MATRIX_PATH.open("rb") as fh:
        data = tomllib.load(fh)
    return data


def check_matrix(matrix_data, reach: dict[str, set[str]], findings: list[Finding]):
    sources = {row["source"]: row for row in matrix_data.get("paths", [])}
    for required in MANDATED_EVENT_SOURCES:
        if required not in sources:
            findings.append(
                Finding(
                    MATRIX_PATH.name,
                    f"paths[{required}]",
                    "MATRIX_ROW_MISSING",
                    f"mandated event source '{required}' has no matrix row",
                )
            )
    for source, row in sorted(sources.items()):
        location = f"paths[{source}]"
        if row.get("terminal_state") != "externally_inert":
            findings.append(
                Finding(
                    MATRIX_PATH.name,
                    location,
                    "MATRIX_ROW_NOT_INERT",
                    f"terminal_state must be 'externally_inert', got {row.get('terminal_state')!r}",
                )
            )
        if not (row.get("rationale") or "").strip():
            findings.append(
                Finding(MATRIX_PATH.name, location, "MATRIX_RATIONALE_REQUIRED", "row lacks rationale")
            )
        declared = set(row.get("reachable_workflows", []))
        derived: set[str] = set()
        for wf, events in reach.items():
            overlap = events & _ROW_EVENT_MAP.get(source, set())
            if overlap:
                derived.add(wf)
        if declared != derived:
            findings.append(
                Finding(
                    MATRIX_PATH.name,
                    location,
                    "MATRIX_REACHABILITY_MISMATCH",
                    f"declared {sorted(declared)} != derived {sorted(derived)}",
                )
            )


# Maps matrix event sources to the derived event classes produced by
# _check_triggers so the matrix can be cross-checked against reality.
_ROW_EVENT_MAP = {
    "tag_push": set(),  # nothing may listen on tags; mismatch proves drift
    "branch_push": {"branch_push"},
    "pull_request": {"pull_request"},
    "manual_dispatch": {"manual_dispatch"},
    "rerun": {"branch_push", "pull_request", "manual_dispatch"},
    "reusable_invocation": set(),  # workflow_call must stay absent
    "environment_approval": set(),  # environments must stay absent
    "fork_context": {"fork_context"},
    "token_present": {"branch_push", "pull_request", "manual_dispatch"},
    "token_absent": {"branch_push", "pull_request", "manual_dispatch"},
    "adversarial_ref_input": {"adversarial_ref_input"},
    "historical_queued_run": {"branch_push", "pull_request", "manual_dispatch"},
}


# --------------------------------------------------------------------------
# Self-test plants
# --------------------------------------------------------------------------



def build_plants(docs: dict[str, dict]):
    """Each plant mutates one parsed workflow; the analyzer must flag it."""
    plants: list[tuple[str, callable]] = []

    def base_doc(fname):
        return copy.deepcopy(docs[fname])

    def plant(fn):
        plants.append((fn.__name__, fn))
        return fn

    release = ".github/workflows/release.yml"

    @plant
    def push_tags_trigger():
        d = base_doc(release)
        d["on"]["push"] = {"tags": ["v*"]}
        return d

    @plant
    def reusable_workflow_call_trigger():
        d = base_doc(release)
        d["on"]["workflow_call"] = None
        return d

    @plant
    def scheduled_trigger():
        d = base_doc(release)
        d["on"]["schedule"] = [{"cron": "0 3 * * *"}]
        return d

    @plant
    def top_level_contents_write():
        d = base_doc(release)
        d["permissions"] = {"contents": "write"}
        return d

    @plant
    def job_packages_write():
        d = base_doc(release)
        d["jobs"]["preflight"]["permissions"] = {"contents": "read", "packages": "write"}
        return d

    @plant
    def id_token_write():
        d = base_doc(release)
        d["jobs"]["preflight"]["permissions"] = {"contents": "read", "id-token": "write"}
        return d

    @plant
    def secret_expression_env():
        d = base_doc(release)
        d["jobs"]["preflight"]["steps"].append(
            {
                "name": "Publish",
                "run": "echo ok",
                "env": {"CARGO_REGISTRY_TOKEN": "${{ secrets.CARGO_REGISTRY_TOKEN }}"},
            }
        )
        return d

    @plant
    def cargo_publish_step():
        d = base_doc(release)
        d["jobs"]["preflight"]["steps"].append({"name": "Publish", "run": "cargo publish --locked"})
        return d

    @plant
    def gh_release_create_step():
        d = base_doc(release)
        d["jobs"]["build"]["steps"].append(
            {"name": "Release", "run": "gh release create v1.2.3 dist/*"}
        )
        return d

    @plant
    def git_push_tags_step():
        d = base_doc(release)
        d["jobs"]["build"]["steps"].append({"name": "Tag", "run": "git push origin v1.2.3"})
        return d

    @plant
    def unpinned_action():
        d = base_doc(release)
        d["jobs"]["build"]["steps"][0]["uses"] = "actions/checkout@v4"
        return d

    @plant
    def unknown_action_valid_sha():
        d = base_doc(release)
        sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        d["jobs"]["build"]["steps"][0]["uses"] = f"evil-org/exfiltrate@{sha}"
        return d

    @plant
    def dispatch_inputs_added():
        d = base_doc(release)
        d["on"]["workflow_dispatch"] = {"inputs": {"version": {"description": "v"}}}
        return d

    @plant
    def job_environment_declared():
        d = base_doc(release)
        d["jobs"]["preflight"]["environment"] = "production"
        return d

    @plant
    def conditional_tag_gated_job():
        d = base_doc(release)
        d["jobs"]["publish"] = {
            "name": "Publish gated",
            "runs-on": "ubuntu-latest",
            "if": "startsWith(github.ref, 'refs/tags/v')",
            "steps": [{"name": "noop", "run": "echo noop"}],
        }
        return d

    @plant
    def credential_named_env_top_level():
        d = base_doc(release)
        d["env"]["GITHUB_TOKEN"] = "implicit"
        return d

    @plant
    def curl_registry_upload():
        d = base_doc(release)
        d["jobs"]["build"]["steps"].append(
            {"name": "Upload", "run": "curl --data-binary @crate.crate https://crates.io/api/v1/new"}
        )
        return d

    @plant
    def checkout_persists_credentials():
        d = base_doc(release)
        d["jobs"]["build"]["steps"][0]["with"]["persist-credentials"] = True
        return d

    @plant
    def continue_on_error_masks_failure():
        d = base_doc(release)
        d["jobs"]["preflight"]["steps"][0]["continue-on-error"] = True
        return d

    return plants


def run_self_test(docs: dict[str, dict], reach: dict[str, set[str]]) -> int:
    escaped: list[str] = []
    for name, mutate in build_plants(docs):
        target_name = ".github/workflows/release.yml"
        mutated = mutate()
        findings: list[Finding] = []
        try:
            _derive_reachable_from_doc(mutated, target_name, findings)
        except RestrictedYamlError as err:
            # Unrecognized structure also counts as caught (fail closed).
            findings.append(Finding(target_name, "-", "UNRECOGNIZED_STRUCTURE", str(err)))
        if not findings:
            escaped.append(name)
    # Matrix negatives.
    matrix_negatives = 0
    matrix_negatives_escaped: list[str] = []
    for label, mangle in (
        ("missing_historical_queued_run", lambda m: m["paths"][:-1]),
        ("row_flipped_to_mutation", None),
    ):
        data = load_matrix()
        if label == "row_flipped_to_mutation":
            data["paths"][-1]["terminal_state"] = "mutation_allowed"
        else:
            data["paths"] = [
                row for row in data["paths"] if row["source"] != "historical_queued_run"
            ]
        findings: list[Finding] = []
        check_matrix(data, reach, findings)
        matrix_negatives += 1
        if not findings:
            matrix_negatives_escaped.append(label)

    total = len(build_plants(docs)) + matrix_negatives
    print(f"self-test: {total} plants, {len(escaped) + len(matrix_negatives_escaped)} escaped")
    for name in escaped:
        print(f"  ESCAPED PLANT: {name}")
    for name in matrix_negatives_escaped:
        print(f"  ESCAPED MATRIX NEGATIVE: {name}")
    return 1 if (escaped or matrix_negatives_escaped) else 0


# --------------------------------------------------------------------------
# Provider audit (READ-ONLY)
# --------------------------------------------------------------------------


def _gh_api(endpoint: str):
    result = subprocess.run(
        ["gh", "api", endpoint],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"gh api failed for {endpoint}: {result.stderr.strip()[:300]}")
    try:
        return json.loads(result.stdout)
    except ValueError as err:
        raise RuntimeError(f"gh api returned malformed JSON for {endpoint}: {err}") from err


def detect_repo() -> str:
    result = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "remote", "get-url", "origin"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    url = result.stdout.strip()
    match = re.search(r"github\.com[:/](.+?)(?:\.git)?$", url)
    if not match:
        raise RuntimeError(f"cannot infer repo from remote {url!r}")
    return match.group(1)


def provider_audit() -> tuple[dict, int]:
    receipt: dict = {"mode": "provider-audit", "read_only": True}
    blocking: list[str] = []
    try:
        repo = detect_repo()
        receipt["repo"] = repo
        workflows = _gh_api(f"repos/{repo}/actions/workflows")
        release_entries = [
            wf
            for wf in workflows.get("workflows", [])
            if wf.get("path") == ".github/workflows/release.yml"
        ]
        if not release_entries:
            blocking.append("release workflow identity not found on provider")
            receipt["release_workflow"] = None
        else:
            entry = release_entries[0]
            receipt["release_workflow"] = {
                "id": entry.get("id"),
                "name": entry.get("name"),
                "state": entry.get("state"),
            }
            if not str(entry.get("state", "")).startswith("disabled"):
                blocking.append(
                    f"historical release workflow id {entry.get('id')} state="
                    f"{entry.get('state')!r}; must be provider-disabled"
                )
            runs = _gh_api(
                f"repos/{repo}/actions/workflows/{entry['id']}/runs?per_page=100"
            )
            live = [
                {
                    "id": r.get("id"),
                    "status": r.get("status"),
                    "event": r.get("event"),
                    "created_at": r.get("created_at"),
                }
                for r in runs.get("workflow_runs", [])
                if r.get("status") not in ("completed",)
            ]
            receipt["historical_runs_total"] = runs.get("total_count")
            receipt["live_release_runs"] = live
            for run in live:
                blocking.append(
                    f"pre-quarantine release run {run['id']} still {run['status']!r}; "
                    "requires separately authorized provider-side review"
                )
        secrets = _gh_api(f"repos/{repo}/actions/secrets")
        names = [s.get("name") for s in secrets.get("secrets", [])]
        receipt["action_secret_names"] = names
        registry_tokens = [n for n in names if n and "CARGO_REGISTRY" in n.upper()]
        if registry_tokens:
            blocking.append(
                "ambient registry credential secret(s) present: "
                + ", ".join(registry_tokens)
                + "; rotation/removal requires separate human authorization"
            )
        try:
            envs = _gh_api(f"repos/{repo}/environments")
            receipt["environments"] = [e.get("name") for e in envs.get("environments", [])]
        except RuntimeError:
            receipt["environments"] = "<unavailable: fine-grained token lacks environments read>"
        receipt["blocking"] = blocking
        verdict = "SAFE" if not blocking else "UNSAFE"
        receipt["verdict"] = verdict
        return receipt, (0 if verdict == "SAFE" else 2)
    except (RuntimeError, KeyError, ValueError) as err:
        receipt["verdict"] = "EVIDENCE_UNAVAILABLE"
        receipt["error"] = str(err)
        receipt["blocking"] = ["provider evidence unavailable; fail-closed"]
        return receipt, 2


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true", help="run planted-mutation suite")
    parser.add_argument("--provider-audit", action="store_true", help="read-only provider facts")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    if args.provider_audit:
        receipt, code = provider_audit()
        print(json.dumps(receipt, indent=2, sort_keys=True))
        return code

    docs, findings, reach = analyze_workflows()

    if args.self_test:
        if findings:
            print("self-test precondition failed: baseline tree already violates quarantine")
            for finding in findings:
                print(f"  {finding}")
            return 1
        return run_self_test(docs, reach)

    try:
        matrix_data = load_matrix()
        check_matrix(matrix_data, reach, findings)
    except FileNotFoundError:
        findings.append(
            Finding(MATRIX_PATH.name, "-", "MATRIX_MISSING", "reachability_matrix.toml absent")
        )

    if findings:
        if args.json:
            print(
                json.dumps(
                    {"verdict": "QUARANTINE_VIOLATED", "findings": [f.as_row() for f in findings]},
                    indent=2,
                )
            )
        else:
            print(f"QUARANTINE VIOLATED: {len(findings)} finding(s)")
            for finding in findings:
                print(f"  {finding}")
        return 1

    payload = {
        "verdict": "EXTERNALLY_INERT",
        "workflows": sorted(docs),
        "derived_events": {k: sorted(v) for k, v in sorted(reach.items())},
        "matrix_sources_covered": len(MANDATED_EVENT_SOURCES),
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print("QUARANTINE INTACT: every checked-in workflow path is externally inert")
        for wf, events in sorted(reach.items()):
            print(f"  {wf}: events={sorted(events) or '{}'} -> zero mutation, zero secret access")
        print(f"  matrix: {len(MANDATED_EVENT_SOURCES)}/12 mandated event sources covered")
    return 0


if __name__ == "__main__":
    sys.exit(main())
