#!/usr/bin/env bash
# Repository qualification entrypoint: installed DSR owns every gate; RCH owns
# heavy execution. No gate reporting, Bead closure, or capability promotion.
# Consumer: batch verifier. Observed defects: empty DSR registrations returned
# success, aliases disagreed, and the previous runner bypassed RCH with SSH.
# Retire this adapter when installed DSR enforces the same inventory/source
# contract; keep the executable negative cases in its replacement.
set -euo pipefail
exec python3 - "$0" "$@" <<'PY'
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import tomllib

SCRIPT = Path(sys.argv[1]).resolve()
ROOT = SCRIPT.parent.parent
ALIASES = ("fastmcp", "fastmcp_rust")
LIB_KINDS = {"lib", "rlib", "proc-macro", "dylib", "cdylib", "staticlib"}

# THE LANE PARTITION (bd-green-rch-batch-unsatisfiable-qkr6e).
#
# A handful of test targets cannot be evaluated on an RCH worker no matter how
# healthy the fleet is, because `.rchignore` excludes `.git/` and a worker has
# no git repository at all. Every remote batch containing them is permanently
# red, so no batch can ever be centrally closed -- which is the arithmetic
# behind 167 closes in September, 1 in October and 0 in November against 1,018
# commits.
#
# THIS IS A SCOPE SPLIT OF THE INSTRUMENT, NOT A RELAXATION OF ANY ASSERTION
# (RH-1). Every row still runs, exactly once, with its full predicate, on a
# host where its inputs exist. Nothing is skipped, ignored or made
# conditional: `#[ignore]`-on-absence would be gate self-weakening and would
# also let PL-1 count an unexecuted row as executed, turning a visible
# structural failure into an invisible one.
#
# MEMBERSHIP IS MEASURED PER TARGET, by reading what each file actually does at
# RUNTIME rather than by counting how often it mentions a path. That
# distinction removed three targets the filing census had listed and added two
# it had missed:
#
#   NOT HERE, though the filing census listed them. Their only AGENTS.md
#   mentions are inside assertion MESSAGE strings or a module comment, and
#   their filesystem reads are all synced paths:
#     banned_dependency_fence      reads POLICY_PATH and LOCK_PATH only
#     provenance_user_agent_fence  sweeps SWEPT_TREES = ["evidence", "spec"]
#     limit_01_rows_do_not_drift   include_str! of two synced sources
#
#   NOT HERE, measured 2026-11-07: fnd_01_dependency_evidence. It validates a
#   RECORDED `.git` probe (it requires probe_result == "absent-not-found"),
#   never stats `.git` itself, and the eight repository-surface documents it
#   does read -- AGENTS.md, README.md, FEATURE_PARITY.md, CHANGELOG.md,
#   rust-toolchain.toml, crates/fastmcp/src/lib.rs and both workflow files --
#   are NONE of them in `.rchignore`, so a `--clean-overlay --no-overlay`
#   baseline carries all eight. If a remote run of it proves otherwise, add it
#   here WITH the observed failure, not on the strength of this reasoning.
LOCAL_LANE = {
    "fastmcp-rust::--test::fnd_01_a_evidence_binding":
        "shells out to git (std::process::Command::new(\"git\"), :397) and reads "
        "AGENTS.md from the repository root (:767); the file's own comment at :408 "
        "already records that this check cannot evaluate on a worker",
    "fastmcp-rust::--test::fnd_04_runtime_conformance":
        "reads .git/HEAD and .git/packed-refs directly (:2434). It DEGRADES rather "
        "than fails -- revision_and_tree() returns \"<unresolved>\" when .git is "
        "absent -- which is worse than a red: a remote green here would bind a "
        "receipt with no revision identity at all, defeating PL-5",
    "fastmcp-xtask::--test::fnd_02_a":
        "stats root/.git/index (:44)",
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def git(*args, root=ROOT):
    return subprocess.check_output(["git", "-C", str(root), *args]).decode().strip()


def workspace_source_paths(manifest):
    # readme_examples.rs compiles the root README through include_str!.
    paths = {"Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "README.md", "spec", ".cargo", "evidence"}
    members = manifest.get("workspace", {}).get("members", [])
    if not members:
        raise Rejected("workspace member inventory is empty")
    for member in members:
        path = Path(member)
        if path.is_absolute() or ".." in path.parts:
            raise Rejected(f"workspace member is outside the clean-revision source boundary: {member}")
        # Guard each member's top-level directory, including new source files
        # and siblings selected by member globs. A top-level glob needs the
        # whole repository boundary rather than a guessed subset of matches.
        first = path.parts[0] if path.parts else "."
        paths.add("." if any(char in first for char in "*?[") else first)
    return sorted(paths)


def admit_source_inputs(root, paths):
    changed = git("diff", "HEAD", "--name-only", "--", *paths, root=root)
    untracked = git("ls-files", "--others", "--exclude-standard", "--", *paths, root=root)
    if changed or untracked:
        raise Rejected("commit compilation inputs before qualification; clean RCH baseline would omit:\n"
                       + changed + "\n" + untracked)


def json_objects(text):
    # Product stderr can precede a libtest object without a newline. Decode
    # complete objects, advancing past each one so nested objects count once.
    decoder = json.JSONDecoder()
    position = 0
    while True:
        start = text.find("{", position)
        if start < 0:
            return
        try:
            value, end = decoder.raw_decode(text, start)
        except ValueError:
            position = start + 1
            continue
        position = end
        if isinstance(value, dict):
            yield value


class Rejected(Exception):
    pass


class Gates:
    def __init__(self, output, alias):
        self.output = output
        self.alias = alias
        self.dsr = shutil.which("dsr")
        if not self.dsr:
            raise Rejected("installed dsr is unavailable")
        self.runs = []
        self.sequence = 0

    def run(self, label, checks, targets=(), planted=None, env_overrides=None):
        """Run actual installed DSR, then validate its exact nonempty contract."""
        self.sequence += 1
        directory = self.output / f"{self.sequence:03d}-{label}"
        directory.mkdir()
        commands = [command for _, command in checks]
        required = {"checks": commands, "targets": list(targets)}
        write_json(directory / "required.json", required)
        required_digest = digest((directory / "required.json").read_bytes())
        registrations = {name: json.loads(json.dumps(required)) for name in ALIASES}
        if planted is not None:
            planted(registrations[self.alias])
        config = directory / "repos.yaml"
        # JSON is a YAML subset; this avoids shell/YAML interpolation of paths.
        write_json(config, {"tools": registrations})
        config_digest = digest(config.read_bytes())
        env = dict(os.environ, DSR_REPOS_FILE=str(config), LC_ALL="C")
        if env_overrides:
            env.update(env_overrides)
        with (directory / "dsr.json").open("w") as stdout, (directory / "dsr.log").open("w") as stderr:
            process = subprocess.run(
                [self.dsr, "-j", "quality", "--tool", self.alias, "--work-dir", str(ROOT)],
                env=env, stdout=stdout, stderr=stderr, check=False,
            )
        record = {"label": label, "directory": str(directory), "exit_code": process.returncode,
                  "required_sha256": required_digest, "configuration_sha256": config_digest,
                  "required_targets": list(targets), "commands": commands}
        self.runs.append(record)
        reasons = []
        if not commands:
            reasons.append("required checks are empty")
        if any(value != required for value in registrations.values()):
            reasons.append("alias registrations differ from the frozen required inventory")
        try:
            response = json.loads((directory / "dsr.json").read_text())
            details = response["details"]
            observed = details["checks"]
            if details.get("tool") != self.alias:
                reasons.append("DSR result names another alias")
            if [item["command"] for item in observed] != commands:
                reasons.append("DSR command inventory differs from required commands")
            if details.get("total") != len(commands) or details.get("passed") != len(commands):
                reasons.append("DSR did not execute and pass every required check")
            if details.get("failed") != 0 or details.get("skipped") or details.get("dry_run"):
                reasons.append("DSR failed, skipped, or only dry-ran checks")
            if response.get("status") != "success" or any(
                item.get("exit_code") != 0 or item.get("passed") is not True for item in observed
            ):
                reasons.append("DSR retained a failed check")
        except (ValueError, KeyError, TypeError) as error:
            reasons.append(f"invalid DSR result: {error}")
        if process.returncode:
            reasons.append(f"DSR exited {process.returncode}")
        if digest((directory / "required.json").read_bytes()) != required_digest:
            reasons.append("required inventory changed during execution")
        if digest(config.read_bytes()) != config_digest:
            reasons.append("DSR registration changed during execution")
        record["reasons"] = reasons
        write_json(directory / "contract.json", record)
        if reasons:
            raise Rejected(f"{label}: " + "; ".join(reasons))
        return directory


def redirected(argv, output, stderr=None):
    command = shlex.join([str(value) for value in argv])
    if stderr is None:
        return command + " > " + shlex.quote(str(output)) + " 2>&1"
    return command + " > " + shlex.quote(str(output)) + " 2> " + shlex.quote(str(stderr))


def self_test(gates):
    results = []
    checks = [("target-a", "printf '%s\\n' target-a"),
              ("target-b", 'printf "%s\\n" target-b; exit "${FASTMCP_DSR_CONTRACT_EXIT:-0}"')]
    targets = ["target-a", "target-b"]
    for alias in ALIASES:
        gates.alias = alias
        gates.run("dsr_alias_nonempty_positive-" + alias, checks, targets,
                  env_overrides={"FASTMCP_DSR_CONTRACT_EXIT": "0"})
    results.append("dsr_alias_nonempty_positive")
    for label, mutate, exit_code, expected_reason in (
        ("dsr_alias_empty_negative", lambda entry: entry.update(checks=[]), "0", "DSR command inventory"),
        ("dsr_failed_gate_negative", None, "7", "DSR retained a failed check"),
        ("dsr_required_target_omission_negative", lambda entry: (
            entry["checks"].pop(), entry["targets"].pop()
        ), "0", "DSR command inventory"),
    ):
        try:
            gates.run(label, checks, targets, planted=mutate,
                      env_overrides={"FASTMCP_DSR_CONTRACT_EXIT": exit_code})
        except Rejected as error:
            if expected_reason not in str(error):
                raise Rejected(f"negative failed for the wrong reason: {label}: {error}") from error
            results.append(label)
        else:
            raise Rejected(f"planted negative was accepted: {label}")
    write_json(gates.output / "contract-tests.json", {"passed": results, "proof_class": "installed-DSR configuration"})
    for name in results:
        print(f"PASS {name}")
    # These are parser controls, separate from the installed-DSR cases above.
    library = {"package": "probe", "name": "probe", "kind": ["lib"], "test": True,
               "required_features": [], "enabled_features": [], "eligible": True}
    if len(select_targets([library], ["probe"], False, [("--lib", None)])) != 1:
        raise Rejected("parser did not select the positive library target")
    for name, target in (
        ("required_example_omission_negative", dict(library, name="example", kind=["example"])),
        ("required_bench_omission_negative", dict(library, name="bench", kind=["bench"])),
        ("required_test_false_omission_negative", dict(library, name="binary", kind=["bin"], test=False)),
        ("required_custom_harness_omission_negative", dict(library, name="custom", kind=["test"], harness=False)),
    ):
        try:
            select_targets([library, target], ["probe"], False, [("--all-targets", None)])
        except Rejected as error:
            if "unsupported test target" not in str(error):
                raise
        else:
            raise Rejected(f"parser silently omitted a required target: {name}")
        if len(select_targets([library, target], ["probe"], False,
                              [("--all-targets", None)], compile_only=True)) != 2:
            raise Rejected("compile-only parser omitted a target from --all-targets")
        print(f"PASS {name}")
    listed = "alpha: test\nbeta: test\n"
    positive_events = [
        {"type": "test", "event": event, "name": name}
        for name in ("alpha", "beta") for event in ("started", "ok")
    ] + [{"type": "suite", "event": "ok", "passed": 2, "failed": 0,
          "ignored": 0, "filtered_out": 0}]
    positive_log = "\n".join(json.dumps(event) for event in positive_events)
    if observe_tests(listed, positive_log, [])["reasons"]:
        raise Rejected("libtest parser refused exact positive inventories")
    for name, omitted in (("required_started_missing_negative", 2),
                          ("required_passed_missing_negative", 3)):
        negative_log = "\n".join(json.dumps(event) for index, event in enumerate(positive_events)
                                 if index != omitted)
        if not observe_tests(listed, negative_log, [])["reasons"]:
            raise Rejected(f"libtest parser accepted an incomplete inventory: {name}")
        print(f"PASS {name}")
    try:
        parse_scope("-p probe --release")
    except Rejected as error:
        if "unsupported scope argument" not in str(error):
            raise
    else:
        raise Rejected("scope parser silently dropped an unsupported option")
    print("PASS unsupported_scope_negative")
    target = dict(library, name="integration", kind=["test"])
    positive = {"test": [{"name": "integration", "harness": True}]}
    negative = {"test": [{"name": "integration", "harness": False}]}
    if not uses_libtest(positive, target) or uses_libtest(negative, target):
        raise Rejected("manifest harness declaration was ignored")
    print("PASS custom_harness_manifest_negative")
    source_admission_self_test(gates.output)


def source_admission_self_test(output):
    # Real Git admission over isolated files; this is source-guard proof only.
    # All fixture repositories and diagnostics are retained, never cleaned up.
    fixture = output / "tooling-source-fixture"
    source = fixture / "tools" / "xtask" / "src" / "main.rs"
    source.parent.mkdir(parents=True)
    (fixture / "Cargo.toml").write_text('[workspace]\nmembers = ["tools/xtask"]\n')
    (fixture / "README.md").write_text("# Source admission fixture\n")
    (fixture / "tools" / "xtask" / "Cargo.toml").write_text(
        '[package]\nname = "qualification-source-probe"\nversion = "0.0.0"\n'
    )
    source.write_text("fn main() {}\n")
    commands = [
        ["git", "-C", str(fixture), "init", "--initial-branch", "main"],
        ["git", "-C", str(fixture), "add", "Cargo.toml", "README.md", "tools/xtask"],
        ["git", "-c", "core.hooksPath=/dev/null", "-c", "user.name=FastMCP source admission probe",
         "-c", "user.email=source-probe@example.invalid", "-C", str(fixture), "commit",
         "--no-gpg-sign", "-m", "Source admission fixture"],
    ]
    with (output / "tooling-source-fixture.log").open("w") as log:
        for command in commands:
            subprocess.run(command, stdout=log, stderr=log, check=True)
        untracked_fixture = output / "untracked-tooling-source-fixture"
        subprocess.run(["git", "clone", "--local", str(fixture), str(untracked_fixture)],
                       stdout=log, stderr=log, check=True)
        readme_fixture = output / "readme-source-fixture"
        subprocess.run(["git", "clone", "--local", str(fixture), str(readme_fixture)],
                       stdout=log, stderr=log, check=True)
    manifest = tomllib.loads(git("show", "HEAD:Cargo.toml", root=fixture))
    paths = workspace_source_paths(manifest)
    admit_source_inputs(fixture, paths)
    print("PASS clean_tooling_source_positive")
    admit_source_inputs(readme_fixture, paths)
    print("PASS clean_root_readme_positive")
    source.write_text("fn main() {}\n// changed tooling source\n")
    untracked = untracked_fixture / "tools" / "xtask" / "src" / "new.rs"
    untracked.write_text("// new tooling input\n")
    (readme_fixture / "README.md").write_text("# Source admission fixture\nChanged compiled README.\n")
    observed = {"guarded_paths": paths, "clean": "accepted", "negative_reasons": {}}
    for name, root, expected in (
        ("dirty_tooling_source_negative", fixture, "tools/xtask/src/main.rs"),
        ("untracked_tooling_source_negative", untracked_fixture, "tools/xtask/src/new.rs"),
        ("dirty_root_readme_negative", readme_fixture, "README.md"),
    ):
        try:
            admit_source_inputs(root, paths)
        except Rejected as error:
            if expected not in str(error):
                raise Rejected(f"source admission refused for the wrong reason: {error}") from error
            observed["negative_reasons"][name] = str(error)
        else:
            raise Rejected(f"source admission silently omitted a compiled input: {name}")
        print(f"PASS {name}")
    write_json(output / "tooling-source-admission.json", observed)


def parse_scope(text):
    tokens = shlex.split(text)
    packages, selectors, features = [], [], []
    workspace = False
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in ("-p", "--package", "--test", "--bin", "--features"):
            if index + 1 == len(tokens):
                raise Rejected(f"missing value after {token}")
            value = tokens[index + 1]
            index += 2
            if token in ("-p", "--package"):
                packages.append(value)
            elif token == "--features":
                features.extend([token, value])
            else:
                selectors.append((token, value))
        else:
            index += 1
            if token == "--workspace":
                workspace = True
            elif token in ("--all-features", "--no-default-features"):
                features.append(token)
            elif token in ("--lib", "--tests", "--bins", "--all-targets"):
                selectors.append((token, None))
            else:
                raise Rejected(f"unsupported scope argument {token!r}; select packages and lib/bin/test targets explicitly")
    if workspace == bool(packages):
        raise Rejected("scope must select either --workspace or one or more -p packages")
    if not selectors:
        selectors = [("--lib", None), ("--tests", None), ("--bins", None)]
    return packages, workspace, selectors, features


def uses_libtest(manifest, target):
    # Cargo metadata exposes `test` but not the manifest's `harness` flag.
    if LIB_KINDS.intersection(target["kind"]):
        return manifest.get("lib", {}).get("harness", True)
    for kind in ("bin", "test", "example", "bench"):
        if kind in target["kind"]:
            for entry in manifest.get(kind, []):
                if entry.get("name") == target["name"]:
                    return entry.get("harness", True)
                if "name" not in entry and entry.get("harness") is False:
                    # An inferred target name cannot justify assuming libtest.
                    # Require an explicit name before this runner credits it.
                    return False
    return True


def target_inventory(metadata):
    enabled = {node["id"]: set(node["features"]) for node in metadata["resolve"]["nodes"]}
    members = set(metadata["workspace_members"])
    inventory = []
    for package in metadata["packages"]:
        if package["source"] is None:
            try:
                Path(package["manifest_path"]).resolve().relative_to(ROOT)
            except ValueError as error:
                raise Rejected("external path dependency is outside the clean-revision source proof") from error
        if package["id"] not in members:
            continue
        manifest = tomllib.loads(Path(package["manifest_path"]).read_text())
        for target in package["targets"]:
            required = target.get("required-features", [])
            inventory.append({"package": package["name"], "name": target["name"], "kind": target["kind"],
                              "test": target["test"], "required_features": required,
                              "harness": uses_libtest(manifest, target),
                              "enabled_features": sorted(enabled[package["id"]]),
                              "eligible": set(required) <= enabled[package["id"]]})
    return inventory


def target_flag(kind):
    """The cargo selector for a metadata target kind, or None if unsupported.

    Extracted so the lane partition can compute the SAME target ids that
    select_targets produces. A second copy of this mapping would let the two
    disagree, and a lane key that silently matches nothing is precisely the
    permanently-red condition the split exists to remove.
    """
    if LIB_KINDS.intersection(kind):
        return "--lib"
    for name, flag in (("test", "--test"), ("bin", "--bin"),
                       ("example", "--example"), ("bench", "--bench")):
        if name in kind:
            return flag
    return None


def target_id(package, flag, name):
    return f"{package}::{flag}::{name}"


def inventory_ids(inventory):
    return {target_id(target["package"], flag, target["name"])
            for target in inventory
            if (flag := target_flag(target["kind"])) is not None}


def select_targets(inventory, packages, workspace, selectors, compile_only=False):
    names = {target["package"] for target in inventory}
    if set(packages) - names:
        raise Rejected(f"unknown packages: {sorted(set(packages) - names)}; facade package is fastmcp-rust")
    selected = []
    matched = set()
    for target in inventory:
        if not workspace and target["package"] not in packages:
            continue
        kind = target["kind"]
        flag = target_flag(kind)
        if flag is None:
            continue
        for index, (selector, name) in enumerate(selectors):
            matches = selector == "--all-targets" or selector == flag and (name is None or name == target["name"])
            matches |= selector == "--tests" and flag == "--test" or selector == "--bins" and flag == "--bin"
            if matches:
                matched.add(index)
                if not compile_only and (flag in ("--example", "--bench") or not target["test"]
                                         or not target.get("harness", True)):
                    raise Rejected(f"unsupported test target {target['package']}::{target['name']} "
                                   f"({kind}, test={target['test']}, harness={target.get('harness', True)}); "
                                   "select libtest --lib/--test/--bin targets explicitly")
                if not target["eligible"]:
                    if compile_only and name is None:
                        # Cargo skips feature-gated targets for broad compile
                        # selectors. The full inventory retains them as ineligible.
                        continue
                    raise Rejected(f"selected target {target['package']}::{target['name']} requires {target['required_features']}; enable its features")
                item = dict(target, flag=flag, id=target_id(target["package"], flag, target["name"]))
                if item not in selected:
                    selected.append(item)
    for index, (selector, name) in enumerate(selectors):
        if name is not None and index not in matched:
            raise Rejected(f"required target was not found: {selector} {name}")
    if not selected:
        raise Rejected("selected test target inventory is empty")
    return sorted(selected, key=lambda target: target["id"])


def observe_tests(list_log, run_log, filters):
    listed = re.findall(r"^(.+): test$", list_log, re.MULTILINE)
    required = [name for name in listed if not filters or any(value in name for value in filters)]
    events = list(json_objects(run_log))
    started = [event["name"] for event in events if event.get("type") == "test" and event.get("event") == "started"]
    passed = [event["name"] for event in events if event.get("type") == "test" and event.get("event") == "ok"]
    failed = [event.get("name") for event in events if event.get("type") == "test" and event.get("event") in ("failed", "ignored")]
    suites = [event for event in events if event.get("type") == "suite" and event.get("event") in ("ok", "failed")]
    expected = collections.Counter(required)
    reasons = []
    if not required or len(required) != len(set(required)):
        reasons.append("required test inventory is empty or contains duplicate IDs")
    if collections.Counter(started) != expected or collections.Counter(passed) != expected:
        reasons.append("required, started, and passed test inventories differ")
    if failed or len(suites) != 1 or any(
        suite.get("event") != "ok" or suite.get("failed") != 0 or suite.get("ignored") != 0
        or suite.get("passed") != len(required)
        or suite.get("filtered_out") != len(listed) - len(required) for suite in suites
    ):
        reasons.append("missing suite completion, failed/ignored test, or inconsistent suite totals")
    return {"discovered": sorted(listed), "required": sorted(required), "started": sorted(started),
            "passed": sorted(passed), "failed_or_ignored": failed, "suites": suites, "reasons": reasons}


def qualify(args, gates, receipt):
    packages, workspace, selectors, scope_features = parse_scope(args.scope)
    feature_args = scope_features + (["--features", args.features] if args.features else [])
    if args.all_features:
        feature_args.append("--all-features")
    if args.no_default_features:
        feature_args.append("--no-default-features")
    head = git("rev-parse", "HEAD")
    source_paths = workspace_source_paths(tomllib.loads(git("show", f"{head}:Cargo.toml")))
    admit_source_inputs(ROOT, source_paths)
    receipt["subject"] = {"head": head, "tree": git("rev-parse", "HEAD^{tree}"),
                          "dirty_inventory": git("status", "--porcelain", "--untracked-files=no"),
                          "lockfile_sha256": digest((ROOT / "Cargo.lock").read_bytes()),
                          "toolchain_sha256": digest((ROOT / "rust-toolchain.toml").read_bytes()),
                          "source_paths": source_paths,
                          "source_mode": "RCH clean-overlay --no-overlay"}
    pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    if args.toolchain and args.toolchain != pin:
        raise Rejected("--toolchain must equal rust-toolchain.toml")
    receipt["configuration"] = {"toolchain": pin, "profile": "dev" if args.check_only or args.clippy else "test",
                                "features": feature_args, "scope": args.scope, "target": args.target,
                                "filters": args.filter, "worker_requested": args.worker,
                                "test_threads": args.test_threads, "jobs": args.jobs,
                                "build_environment": {key: os.environ[key] for key in (
                                    "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER",
                                    "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_TARGET"
                                ) if key in os.environ}}
    # Metadata is read-only and does not compile. All three profiles are frozen;
    # successful execution of one never earns evidence for another.
    inventories = {}
    metadata = {}
    metadata_checks = []
    for name, flags in (("default", []), ("modern-only", ["--no-default-features"]),
                        ("all-features", ["--all-features"]), ("selected", feature_args)):
        path = gates.output / f"metadata-{name}.json"
        argv = ["cargo", f"+{pin}", "metadata", "--locked", "--format-version", "1", *flags]
        metadata_checks.append((name, redirected(argv, path, gates.output / f"metadata-{name}.log")))
        metadata[name] = path
    gates.run("cargo-metadata", metadata_checks)
    for name, path in metadata.items():
        inventories[name] = target_inventory(json.loads(path.read_text()))
    write_json(gates.output / "target-inventories.json", inventories)
    if git("rev-parse", "HEAD") != head:
        raise Rejected("compilation inputs moved while freezing metadata")
    admit_source_inputs(ROOT, source_paths)
    selected = select_targets(inventories["selected"], packages, workspace, selectors,
                              compile_only=args.check_only or args.clippy)
    receipt["required_targets"] = [target["id"] for target in selected]
    receipt["metadata_scope"] = (
        "Cargo metadata resolves workspace feature unification. Eligibility is a candidate inventory, "
        "not proof that a per-package execution enables a target. Every selected test target is "
        "compiled, discovered and run explicitly; a skipped/empty target cannot pass."
    )
    write_json(gates.output / "required-targets.json", selected)
    rch = shutil.which("rch")
    if not rch:
        raise Rejected("installed rch is unavailable")
    prefix = [rch, "--json", "exec", "--base", head, "--clean-overlay", "--no-overlay"]
    if args.worker:
        prefix += ["--worker", args.worker]
    prefix += ["--"]
    cargo_base = ["cargo", f"+{pin}"]
    common = ["--locked", "-j", str(args.jobs), *feature_args]
    if args.target:
        common += ["--target", args.target]

    def remote(label, argv, target_ids):
        stdout = gates.output / f"{label}.rch.json"
        stderr = gates.output / f"{label}.log"
        command = "RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary CARGO_TERM_COLOR=never " + redirected(prefix + argv, stdout, stderr)
        gates.run(label, [(label, command)], target_ids)
        envelopes = [item for item in json_objects(stdout.read_text()) if "outcome" in item]
        if len(envelopes) != 1 or any(item.get("location") != "remote" or item.get("outcome") != "completed"
                                     or item.get("remote_exit_code") != 0 for item in envelopes):
            raise Rejected(f"{label}: RCH did not confirm completed remote execution")
        receipt.setdefault("remote_runs", []).append(envelopes[0])
        return stderr.read_text(errors="replace")

    def local(label, argv, target_ids):
        """Run one declared policy/git target on THIS host.

        Same DSR gate, same argv, same toolchain pin, same features and the
        same libtest JSON observation as the remote lane. The only difference
        is the absence of the rch prefix, because the inputs these rows read
        -- a real `.git` -- exist only here. It deliberately does NOT set
        RCH_REQUIRE_REMOTE, and it is reachable only for an id listed in
        LOCAL_LANE, so it cannot become a general escape hatch from the
        build-first doctrine.
        """
        # stdout and stderr go to SEPARATE files, and the libtest stream is read
        # from stdout. The remote lane reads its output from stderr only because
        # RCH merges the worker's stdout into the local process's stderr; doing
        # the same here would interleave cargo's own progress lines into the
        # libtest `--format json` event stream and corrupt the parse. A single
        # merged file would be worse still: `> f 2> f` opens two descriptors on
        # one path in truncate mode and they overwrite each other.
        #
        # RCH_SHIM_LOCAL_IDE=1 is the cargo shim's OWN documented operator escape
        # hatch ("force this one build local"), and it is required rather than
        # optional here: `cargo` on this host is intercepted three ways --
        # ~/.rch/shims/cargo sits ahead of ~/.cargo/bin on PATH, the active
        # toolchain's bin/cargo is an "rch toolchain cargo wrapper" whose real
        # binary was renamed to cargo-rch-real, and Claude Code's PreToolUse hook
        # matches the literal word. Without this, a lane that calls itself local
        # would be offloaded to a worker that has no `.git`, and the receipt
        # would be false in the one way this split exists to prevent.
        #
        # The shim's exec_local path also caps CARGO_BUILD_JOBS at
        # RCH_LOCAL_MAX_JOBS (default 8), which is what keeps a local lane from
        # becoming the compilation storm RCH exists to avoid. RCH_REQUIRE_REMOTE
        # is deliberately NOT set: the shim refuses a caller-set bypass while it
        # is enabled.
        stdout = gates.output / f"{label}.out"
        stderr = gates.output / f"{label}.log"
        command = "RCH_SHIM_LOCAL_IDE=1 CARGO_TERM_COLOR=never " + redirected(argv, stdout, stderr)
        gates.run(label, [(label, command)], target_ids)
        # REFUSE A LANE THAT SILENTLY WENT REMOTE. Without this the receipt would
        # claim "lane": "local-policy" with this host's name even if the shim
        # escape hatch stopped working -- a shim rewrite, DSR dropping leading
        # env assignments, an operator setting force_local off -- and the rows
        # this lane exists for would have run somewhere with no `.git`, reporting
        # a green for inputs that were never read. That is the exact false
        # receipt the split exists to prevent, so it must fail loudly rather
        # than be assumed.
        #
        # The predicate is ONE-SIDED on purpose. A remote build reports paths
        # under the worker roots below; a local one never does. Their ABSENCE is
        # therefore not proof of locality -- a fully cached run prints no paths
        # at all -- but their PRESENCE is proof of the opposite, which is the
        # direction that can produce a false claim.
        observed = stdout.read_text(errors="replace") + stderr.read_text(errors="replace")
        offloaded = [marker for marker in ("/data/tmp/", "/data/projects/") if marker in observed]
        if offloaded:
            raise Rejected(
                f"{label}: the local lane was OFFLOADED -- worker path marker(s) "
                f"{offloaded} appear in its output. RCH_SHIM_LOCAL_IDE=1 did not take "
                f"effect, so this receipt would have claimed a local run that read no "
                f"local .git. Logs: {stdout} , {stderr}"
            )
        machine = os.uname()
        receipt.setdefault("local_runs", []).append({
            "label": label,
            "host": machine.nodename,
            "platform": f"{machine.sysname} {machine.release} {machine.machine}",
            "command": command,
            "stdout_log": str(stdout),
            "stderr_log": str(stderr),
            "lane": "local-policy",
            "locality_check": (
                "refused on worker path markers /data/tmp/ or /data/projects/ in the "
                "captured output; one-sided, so absence is not proof of locality"
            ),
        })
        return stdout.read_text(errors="replace")

    # A lane key that matches no real target is worse than no key at all: its
    # rows would stay on the remote lane, permanently red, while the receipt
    # claimed a partition that covered them. Validate against the FULL
    # inventory rather than the selected subset, so a narrowly scoped run does
    # not report a stale declaration it simply did not select.
    all_ids = inventory_ids(inventories["selected"])
    unknown_lane_keys = sorted(set(LOCAL_LANE) - all_ids)
    if unknown_lane_keys:
        raise Rejected("LOCAL_LANE names targets that do not exist in the inventory; "
                       f"the declaration is stale: {unknown_lane_keys}")
    receipt["lane_partition"] = {
        "rule": (
            "Every required target runs exactly once. A target listed in LOCAL_LANE runs on "
            "this host because its assertions read inputs RCH does not transfer (.rchignore "
            "excludes .git/, and a worker has no git repository); every other target runs on "
            "RCH exactly as before. No row is skipped, ignored or made conditional, so this "
            "is a scope split of the instrument and not a relaxation of any assertion."
        ),
        "local": LOCAL_LANE,
        "selected_local": sorted(set(LOCAL_LANE) & set(receipt["required_targets"])),
        "selected_remote": sorted(set(receipt["required_targets"]) - set(LOCAL_LANE)),
        "receipt_scope": (
            "Each lane binds its own host, toolchain, profile, features and executed test "
            "IDs. Neither lane's result is evidence for the other lane's rows, and "
            "required/executed set equality (PL-1) is checked per lane and then over the "
            "union."
        ),
    }

    if args.check_only or args.clippy:
        scope = ["--workspace"] if workspace else [value for name in packages for value in ("-p", name)]
        for flag, name in selectors:
            scope.append(flag)
            if name is not None:
                scope.append(name)
        command = "clippy" if args.clippy else "check"
        argv = cargo_base + [command, *common, *scope]
        if args.clippy:
            argv += ["--", "-D", "warnings"]
        remote(command, argv, receipt["required_targets"])
        receipt["mode"] = "compile-only; no tests executed"
        return
    receipt["mode"] = "selected test targets"
    receipt["doctests"] = "not selected; only explicitly inventoried libtest targets are covered"
    for index, target in enumerate(selected):
        flags = ["-p", target["package"], target["flag"]]
        if target["flag"] != "--lib":
            flags.append(target["name"])
        argv = cargo_base + ["test", *common, *flags]
        label = f"target-{index:03d}"
        # One runner per target, chosen by the declared partition. Compile,
        # discovery and execution all go to the SAME lane: compiling remotely
        # and running locally would bind a receipt to a binary this host never
        # produced.
        run = local if target["id"] in LOCAL_LANE else remote
        run(label + "-compile", argv + ["--no-run"], [target["id"]])
        listing = run(label + "-list", argv + ["--", "--list"], [target["id"]])
        execution = run(label + "-run", argv + ["--", "-Z", "unstable-options", "--format", "json",
                                                "--test-threads", str(args.test_threads), *args.filter], [target["id"]])
        observed = observe_tests(listing, execution, args.filter)
        observed["lane"] = "local-policy" if target["id"] in LOCAL_LANE else "rch-remote"
        observed["lane_reason"] = LOCAL_LANE.get(target["id"])
        receipt.setdefault("test_targets", {})[target["id"]] = observed
        write_json(gates.output / f"{label}-tests.json", observed)
        if observed["reasons"]:
            raise Rejected(f"{target['id']}: " + "; ".join(observed["reasons"]))
    if set(receipt.get("test_targets", {})) != set(receipt["required_targets"]):
        raise Rejected("required test target inventory differs from executed target inventory")
    discovered = [name for target in receipt["test_targets"].values() for name in target["discovered"]]
    unmatched = [value for value in args.filter if not any(value in name for name in discovered)]
    if unmatched:
        raise Rejected(f"requested filters matched no discovered test: {unmatched}")


def main():
    parser = argparse.ArgumentParser(prog="scripts/verify_batch.sh", description="Fail-closed installed DSR → RCH qualification. Logs are retained; no Beads are closed.")
    parser.add_argument("--scope", help="e.g. '-p fastmcp-rust --lib' or '--workspace --all-targets'")
    parser.add_argument("--features", default="")
    parser.add_argument("--all-features", action="store_true")
    parser.add_argument("--no-default-features", action="store_true")
    parser.add_argument("--filter", action="append", default=[])
    parser.add_argument("--alias", choices=ALIASES, default="fastmcp_rust")
    parser.add_argument("--worker", help="RCH worker ID; never an SSH hostname")
    parser.add_argument("--target", help="explicit Rust target triple")
    parser.add_argument("--toolchain", help="must match the repository pin")
    parser.add_argument("--test-threads", type=int, default=1)
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--clippy", action="store_true")
    parser.add_argument("--beads", default="")
    parser.add_argument("--out", help="parent directory for a fresh retained run directory")
    parser.add_argument("--self-test-dsr-contract", action="store_true")
    args = parser.parse_args(sys.argv[2:])
    if not args.self_test_dsr_contract and not args.scope:
        parser.error("--scope is required")
    if args.jobs < 1 or args.test_threads < 1:
        parser.error("--jobs and --test-threads must be positive")
    if args.filter and (args.check_only or args.clippy):
        parser.error("--filter is only valid for test execution")
    if args.out:
        Path(args.out).mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="fastmcp-verify-", dir=args.out)).resolve()
    receipt = {"verdict": "INVALID", "script_sha256": digest(SCRIPT.read_bytes()),
               "beads": [value for value in args.beads.split(",") if value],
               "note": "Evidence only; no gate verdict, closure, capability credit, or maturity promotion."}
    gates = None
    try:
        gates = Gates(output, args.alias)
        installed = Path(gates.dsr).resolve()
        receipt["installed_dsr"] = {"path": str(installed), "sha256": digest(installed.read_bytes())}
        quality_module = installed.parent / "src" / "quality_gates.sh"
        if quality_module.is_file():
            receipt["installed_dsr"]["quality_module_sha256"] = digest(quality_module.read_bytes())
        if args.self_test_dsr_contract:
            self_test(gates)
            receipt["mode"] = "installed-DSR configuration self-test; no Rust or MCP proof"
        else:
            qualify(args, gates, receipt)
        receipt["verdict"] = "GREEN"
    except (Rejected, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        receipt["reason"] = str(error)
        print(f"INVALID: {error}", file=sys.stderr)
    finally:
        receipt["dsr_runs"] = gates.runs if gates is not None else []
        if "subject" in receipt:
            receipt["subject"]["head_after"] = git("rev-parse", "HEAD")
            receipt["subject"]["source_claim"] = "the frozen committed revision, not subsequent working-tree edits"
        write_json(output / "receipt.json", receipt)
        print(f"artifacts: {output}", flush=True)
    return 0 if receipt["verdict"] == "GREEN" else 1


raise SystemExit(main())
PY
