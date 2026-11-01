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


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def git(*args):
    return subprocess.check_output(["git", "-C", str(ROOT), *args]).decode().strip()


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
        flag = "--lib" if LIB_KINDS.intersection(kind) else (
            "--test" if "test" in kind else "--bin" if "bin" in kind else
            "--example" if "example" in kind else "--bench" if "bench" in kind else None
        )
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
                item = dict(target, flag=flag, id=f"{target['package']}::{flag}::{target['name']}")
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
    source_paths = ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "crates", "spec", ".cargo", "evidence"]
    changed = git("diff", "HEAD", "--name-only", "--", *source_paths)
    untracked = git("ls-files", "--others", "--exclude-standard", "--", *source_paths)
    if changed or untracked:
        raise Rejected("commit compilation inputs before qualification; clean RCH baseline would omit:\n" + changed + "\n" + untracked)
    head = git("rev-parse", "HEAD")
    receipt["subject"] = {"head": head, "tree": git("rev-parse", "HEAD^{tree}"),
                          "dirty_inventory": git("status", "--porcelain", "--untracked-files=no"),
                          "lockfile_sha256": digest((ROOT / "Cargo.lock").read_bytes()),
                          "toolchain_sha256": digest((ROOT / "rust-toolchain.toml").read_bytes()),
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
    if (git("rev-parse", "HEAD") != head or git("diff", "HEAD", "--name-only", "--", *source_paths)
            or git("ls-files", "--others", "--exclude-standard", "--", *source_paths)):
        raise Rejected("compilation inputs moved while freezing metadata")
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
        remote(label + "-compile", argv + ["--no-run"], [target["id"]])
        listing = remote(label + "-list", argv + ["--", "--list"], [target["id"]])
        execution = remote(label + "-run", argv + ["--", "-Z", "unstable-options", "--format", "json",
                                                   "--test-threads", str(args.test_threads), *args.filter], [target["id"]])
        observed = observe_tests(listing, execution, args.filter)
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
