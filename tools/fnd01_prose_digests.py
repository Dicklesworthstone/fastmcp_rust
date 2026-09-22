#!/usr/bin/env python3
"""Reproduce FND-01 evidence digests from their DECLARED PROSE alone (bd-jpmay J1-J11).

Thesis under test: a third party can rebuild each declared digest in evidence/fnd-01 from the
construction the evidence itself declares, with no build. So this runner is stdlib-only python3:
it parses TOML with tomllib, links no workspace crate, reads no Rust source (the verifier -- the
producer -- is never opened; bca57 C6), and needs no cargo and no remote lane.

INPUTS ARE READ BY REVISION, NEVER FROM THE WORKING TREE. Every file is read with `git cat-file`
at --rev and its blob hash is printed, because the shared working tree moves under other lanes and
a figure bound to it is bound to nothing. The evidence file set is
`git ls-files ':(glob)evidence/fnd-01/**/*.toml'` evaluated at --rev (19 files). Without `:(glob)`
git's default pathspec does not recurse `**` and the same string returns 9.

J1 POPULATION. The base set is every whole-value 64-lowercase-hex string field (including string
elements of arrays) in the 19 files. Every base field is classified by a rule below, by READING the
table it sits in -- never by key name alone: CONSTRUCT (a J1 target: the evidence declares how its
preimage is built, under any key), or an exclusion category with its reason (FILE, MEMBER, EXT,
IMPLIED, UNDECLARED, OTHER). A base field no rule classifies, or a target that names no base field,
turns the run red: the screen is exhaustive by construction.

PRE-REGISTRATION (J3). Every target's reading -- each token the prose leaves open -- is written
below beside the builder that implements it, as a READING block naming the declared keys it
implements. Readings are committed before the targets they cover are first executed against the
real digests; the commit that introduced them is the pre-registration stamp. A reading is never
edited to turn a miss into a hit (RH-3): a structural VOID (preimage length != declared bytes, a
failed population control, or a crash in the builder) may be re-run ONCE with only the named defect
changed, and both runs are kept.

OUTCOMES (J4). MATCH needs the computed digest AND, wherever the table declares one, the computed
byte length to equal the declared values. MISMATCH is any other miss that is not VOID.
UNDERDETERMINED is recorded only with the specific open token or absent input named.
UNATTEMPTED rows carry their reason (J8). Digests confirmed only through another digest's preimage
are reported in a separate TRANSITIVE column and never added to the direct count.

SELF-TEST (J5). In the same invocation, on in-memory copies only, three one-byte-scale mutations per
attempted class; each must change the bytes it claims to change and turn the mutated target into
the pre-registered outcome, and the set of targets whose outcome changes must equal the mutated
target plus the dependents the mutation declares (a declared digest that is itself an input row of
another declared digest cannot be mutated without moving that other digest). An all-MATCH positive
without a passing negative is refused.

The runner is additive: it edits nothing under evidence/, no verifier, and no declared digest.
Exit status is non-zero if the population is not exhaustive, the totals do not reconcile with the
population (PL-1), or any J5 mutation fails.

Usage: python3 tools/fnd01_prose_digests.py [--rev <commit>]
"""

from __future__ import annotations

import argparse
import copy
import datetime
import gzip
import hashlib
import io
import json
import platform
import re
import struct
import subprocess
import sys
import tarfile
import tomllib
from dataclasses import dataclass, field
from typing import Callable

GLOB = ":(glob)evidence/fnd-01/**/*.toml"
ROOT = "evidence/fnd-01/"
DV = "evidence/fnd-01/dependency-verification.toml"
SV = "evidence/fnd-01/vectors/media/security-vectors.toml"
AUTH = "evidence/fnd-01/auth-standards.toml"
SDK = "evidence/fnd-01/sdk-matrix.toml"
SER = "evidence/fnd-01/serialization-uri-dependencies.toml"
TA = "evidence/fnd-01/tasks-apps.toml"
TC = "evidence/fnd-01/toolchain-asupersync.toml"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
BOUNDED_HEX64 = re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])")


class Underdetermined(Exception):
    """The declared prose leaves a token or an input open; the message names it."""


class Absent:
    """A selector that resolves to nothing (assertion_contract missing_tag)."""


ABSENT = Absent()


# --------------------------------------------------------------------------------------------
# Git access, bound to one revision
# --------------------------------------------------------------------------------------------


def git(*args: str) -> str:
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout


def git_bytes(*args: str) -> bytes:
    return subprocess.run(["git", *args], capture_output=True, check=True).stdout


class Repo:
    """Read-only view of one revision. Records the blob of every file it hands out (J10)."""

    def __init__(self, rev: str):
        self.rev = git("rev-parse", rev).strip()
        self.blobs_read: dict[str, str] = {}
        self._bytes: dict[str, bytes] = {}
        self._blob_at: dict[tuple, str] = {}

    def blob(self, path: str, rev: str | None = None) -> str:
        key = (rev or self.rev, path)
        if key not in self._blob_at:
            self._blob_at[key] = git("rev-parse", f"{key[0]}:{path}").strip()
        return self._blob_at[key]

    def read(self, path: str, rev: str | None = None) -> bytes:
        blob = self.blob(path, rev)
        label = path if rev is None else f"{path}@{rev[:12]}"
        self.blobs_read[label] = blob
        if blob not in self._bytes:
            self._bytes[blob] = git_bytes("cat-file", "blob", blob)
        return self._bytes[blob]

    def ls_files(self, prefix: str) -> list[str]:
        return git("ls-tree", "-r", "--name-only", self.rev, "--", prefix).split("\n")[:-1]

    def evidence_tomls(self) -> list[str]:
        # git ls-files evaluates the index, not a revision; so select the same :(glob) set from
        # the revision's tree listing and assert it against ls-files when they are the same tree.
        return sorted(p for p in self.ls_files(ROOT) if p.endswith(".toml"))

    def binding_revision(self, digest: str, path: str) -> str:
        """The first commit whose diff of `path` adds `digest` (pre-registered input revision)."""
        out = git("log", "--reverse", "--format=%H", f"-S{digest}", self.rev, "--", path).split()
        if not out:
            raise Underdetermined(f"no commit at or before --rev introduces {digest[:12]} in {path}")
        return out[0]


class World:
    """The inputs a builder may see: raw bytes by path, plus parsed documents (copy-on-write)."""

    def __init__(self, repo: Repo):
        self.repo = repo
        self.raw_override: dict[str, bytes] = {}
        self.parsed: dict[str, dict] = {}

    def raw(self, path: str) -> bytes:
        if path in self.raw_override:
            return self.raw_override[path]
        return self.repo.read(path)

    def text(self, path: str) -> str:
        return self.raw(path).decode("utf-8")

    def doc(self, path: str) -> dict:
        if path not in self.parsed:
            self.parsed[path] = tomllib.loads(self.text(path))
        return self.parsed[path]

    def clone(self) -> "World":
        other = World(self.repo)
        other.raw_override = dict(self.raw_override)
        other.parsed = dict(self.parsed)  # shared until mutable_doc copies one
        return other

    def mutable_doc(self, path: str) -> dict:
        self.parsed[path] = copy.deepcopy(self.doc(path))
        return self.parsed[path]

    def set_raw(self, path: str, data: bytes) -> None:
        self.raw_override[path] = data
        self.parsed.pop(path, None)


# --------------------------------------------------------------------------------------------
# Framing primitives. Every width below is the one the prose states; where a sentence says only
# "length-prefixed", the READING of that target names the width chosen and why.
# --------------------------------------------------------------------------------------------


def u8(value: int) -> bytes:
    return struct.pack(">B", value)


def u32(value: int) -> bytes:
    return struct.pack(">I", value)


def u64(value: int) -> bytes:
    return struct.pack(">Q", value)


def i64(value: int) -> bytes:
    return struct.pack(">q", value)


def lp32(text: str) -> bytes:
    """u32be byte length followed by the UTF-8 bytes."""
    if not isinstance(text, str):
        raise TypeError(f"expected a string, found {type(text).__name__}: {text!r}")
    raw = text.encode("utf-8")
    return u32(len(raw)) + raw


def boolean_byte(value: bool) -> bytes:
    if not isinstance(value, bool):
        raise TypeError(f"expected a boolean, found {type(value).__name__}")
    return b"\x01" if value else b"\x00"


def optional_lp32(row: dict, key: str) -> bytes:
    """One presence byte: 0x00 absent with nothing following, 0x01 then u32be length + UTF-8."""
    if key not in row:
        return b"\x00"
    return b"\x01" + lp32(row[key])


def lp32_list(values: list) -> bytes:
    """u32be count, then each element as u32be length + UTF-8, in the order given."""
    return u32(len(values)) + b"".join(lp32(value) for value in values)


def utf8(text: str) -> bytes:
    return text.encode("utf-8")


def fnd01_toml_value(value) -> bytes:
    """assertion_contract TOML value tags, recursive (FND01FIXv1 and FND01OBSv1 toml_domain).

    READING (assertion_contract boolean/toml_integer/toml_float/string/array/map/toml_datetime
    tags): bool is tagged before int because Python's bool is an int subtype; a map's members
    are sorted by raw UTF-8 key bytes with u32be key lengths; a string and an array use u64be
    length/count. OPEN TOKEN, NOT GUESSED: tag 0x09 needs `toml::value::Datetime::to_string`
    bytes, and tomllib cannot recover the source spelling of an offset (`Z` vs `+00:00`), so a
    datetime at any depth is UNDERDETERMINED rather than rendered by a guessed formatter.
    """
    if isinstance(value, bool):
        return b"\x02" + boolean_byte(value)
    if isinstance(value, int):
        return b"\x03" + i64(value)
    if isinstance(value, float):
        return b"\x04" + u64(struct.unpack(">Q", struct.pack(">d", value))[0])
    if isinstance(value, str):
        raw = utf8(value)
        return b"\x05" + u64(len(raw)) + raw
    if isinstance(value, list):
        return b"\x06" + u64(len(value)) + b"".join(fnd01_toml_value(item) for item in value)
    if isinstance(value, dict):
        members = sorted(value.items(), key=lambda item: utf8(item[0]))
        body = b"".join(u32(len(utf8(key))) + utf8(key) + fnd01_toml_value(item) for key, item in members)
        return b"\x07" + u64(len(value)) + body
    if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
        raise Underdetermined(
            "tag 0x09 needs toml::value::Datetime::to_string bytes; tomllib does not retain the "
            "source spelling of the value"
        )
    raise TypeError(f"no assertion_contract tag for {type(value).__name__}")


class JsonNumber(str):
    """A JSON number kept as its source lexeme (FND01OBSv1 json_number_tag)."""


def fnd01_json_value(value) -> bytes:
    """assertion_contract json_domain: null 0x01, bool 0x02, number 0x0a, string/array/map as TOML.

    READING (json_number_tag = "0x0a followed by u64be byte length and
    serde_json::Number::to_string UTF-8 bytes"): the number is rendered as its source lexeme.
    OPEN TOKEN: whether the producer's serde_json has arbitrary_precision (lexeme preserved) or
    not (canonical rendering). For a plain decimal integer lexeme both renderings coincide; any
    other number shape is UNDERDETERMINED rather than rendered by a guessed formatter.
    """
    if value is None:
        return b"\x01"
    if isinstance(value, bool):
        return b"\x02" + boolean_byte(value)
    if isinstance(value, JsonNumber):
        if not re.fullmatch(r"-?(0|[1-9][0-9]*)", value):
            raise Underdetermined(f"JSON number {value!r} renders differently with and without arbitrary_precision")
        raw = utf8(value)
        return b"\x0a" + u64(len(raw)) + raw
    if isinstance(value, str):
        raw = utf8(value)
        return b"\x05" + u64(len(raw)) + raw
    if isinstance(value, list):
        return b"\x06" + u64(len(value)) + b"".join(fnd01_json_value(item) for item in value)
    if isinstance(value, dict):
        members = sorted(value.items(), key=lambda item: utf8(item[0]))
        body = b"".join(u32(len(utf8(key))) + utf8(key) + fnd01_json_value(item) for key, item in members)
        return b"\x07" + u64(len(value)) + body
    raise TypeError(f"no json_domain tag for {type(value).__name__}")


def strict_json(data: bytes):
    def no_duplicates(pairs):
        keys = [key for key, _ in pairs]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate JSON member name")
        return dict(pairs)

    return json.loads(
        data.decode("utf-8"),
        object_pairs_hook=no_duplicates,
        parse_int=JsonNumber,
        parse_float=JsonNumber,
    )


# --------------------------------------------------------------------------------------------
# Targets
# --------------------------------------------------------------------------------------------


@dataclass
class Target:
    file: str
    location: str  # concrete location of the declared digest field, e.g. "case[3].sha256"
    klass: str  # A registry | B content | DOC document | TREE tree | OBS observation
    bytes_location: str | None  # concrete location of the declared preimage length, if any
    builder: Callable[["World"], bytes] | None
    reason: str = ""  # UNATTEMPTED reason, when builder is None
    reading: str = ""  # the pre-registered reading, printed with the row

    @property
    def key(self) -> tuple:
        return (self.file, self.location)


@dataclass
class Row:
    target: Target
    declared_bytes: int | None
    declared_digest: str
    computed_bytes: int | None = None
    computed_digest: str | None = None
    outcome: str = ""
    note: str = ""


LOCATION_PART = re.compile(r"([^.\[\]]+)|\[(\d+)\]")


def lookup(document, location: str):
    node = document
    for key, index in LOCATION_PART.findall(location):
        node = node[int(index)] if index else node[key]
    return node


def order_rows(rows: list, family_order: list) -> list:
    rank = {family: index for index, family in enumerate(family_order)}
    return sorted(rows, key=lambda row: (rank[row["family"]], row["source_index"]))


# ---- dependency-verification: canonical registries (Class A) --------------------------------


# READING dependency-verification mutation_contract.canonical_recipe_sha256
#   keys: canonical_recipe_encoding, canonical_recipe_order, canonical_recipe_fields,
#         canonical_recipe_string_encoding, canonical_recipe_source_index_encoding,
#         canonical_recipe_optional_string_encoding; rows [[negative_case]];
#         order from negative_inventory.family_order.
#   OPEN TOKEN: which fields are "optional". Read as argument and secondary_selector -- the two
#   fields the row rules (conditional_variant_rows) make sometimes forbidden; every other field
#   is a required string (source_index u32be).
def build_mutation_recipe(w: World) -> bytes:
    dv = w.doc(DV)
    rows = order_rows(dv["negative_case"], dv["negative_inventory"]["family_order"])
    fields = dv["mutation_contract"]["canonical_recipe_fields"]
    out = b"FND01MUTv2\x00" + u32(len(rows))
    for row in rows:
        for name in fields:
            if name == "source_index":
                out += u32(row[name])
            elif name in ("argument", "secondary_selector"):
                out += optional_lp32(row, name)
            else:
                out += lp32(row[name])
    return out


# READING dependency-verification negative_inventory.sha256
#   keys: canonical_record ("family || HTAB || id || LF after canonical_order sorting"),
#         canonical_order ("family_order, then ascending source_index"); rows [[negative_case]].
#   OPEN TOKEN: no header or count word is declared, so none is written; the registry is the
#   bare concatenation of records.
def build_negative_inventory(w: World) -> bytes:
    dv = w.doc(DV)
    rows = order_rows(dv["negative_case"], dv["negative_inventory"]["family_order"])
    return b"".join(utf8(row["family"] + "\t" + row["id"] + "\n") for row in rows)


# READING dependency-verification assertion_contract.canonical_sha256
#   keys: canonical_encoding, canonical_order (ascending raw UTF-8 id bytes), canonical_fields,
#         canonical_string_encoding, canonical_optional_string_encoding,
#         canonical_expected_trigger_count_encoding (u32be),
#         canonical_allowed_cotrigger_ids_encoding / canonical_suppressed_ids_encoding
#         (u32be count then canonical strings); digest_encoding; rows [[semantic_assertion]].
#   OPEN TOKEN: the two *_observation_sha256 fields are encoded as their 64-character lowercase
#   hex TEXT under canonical_string_encoding (digest_encoding says a digest IS 64 lowercase hex
#   characters), not as 32 raw bytes. secondary_selector is the optional string.
def build_assertion_registry(w: World) -> bytes:
    dv = w.doc(DV)
    rows = sorted(dv["semantic_assertion"], key=lambda row: utf8(row["id"]))
    fields = dv["assertion_contract"]["canonical_fields"]
    out = b"FND01ASTv2\x00" + u32(len(rows))
    for row in rows:
        for name in fields:
            if name == "secondary_selector":
                out += optional_lp32(row, name)
            elif name == "expected_trigger_count":
                out += u32(row[name])
            elif name in ("allowed_cotrigger_ids", "suppressed_ids"):
                out += lp32_list(row[name])
            else:
                out += lp32(row[name])
    return out


# READING dependency-verification closed_child_handoff_contract.registry_sha256
#   keys: registry_encoding, binding_order, binding_count, binding_exact_fields;
#         rows [[closed_child_binding]].
#   OPEN TOKEN: the count word is the declared binding_count (asserted equal to the row count);
#   rows are selected by path in binding_order. sha256 is "raw 32-byte". No byte length is
#   declared for this registry, so its MATCH is digest-only (J4 "wherever the table declares").
def build_closed_child_registry(w: World) -> bytes:
    dv = w.doc(DV)
    contract = dv["closed_child_handoff_contract"]
    by_path = {row["path"]: row for row in dv["closed_child_binding"]}
    if contract["binding_count"] != len(by_path):
        raise ValueError("population control: binding_count disagrees with the closed_child_binding row count")
    out = b"FND01CHILDv1\x00" + u32(contract["binding_count"])
    for path in contract["binding_order"]:
        row = by_path[path]
        out += lp32(row["path"]) + lp32(row["owner_scope"]) + u64(row["byte_length"])
        out += bytes.fromhex(row["sha256"])
    return out


# READING dependency-verification command_environment_profiles.native_tool_candidate_registry_sha256
#   keys: native_tool_candidate_registry_encoding, native_tool_candidate_row_fields,
#         native_tool_candidate_count; rows [[bootstrap_native_tool_candidate]].
#   OPEN TOKENS: "length-prefixed" states no width -> u32be, the only width the same sentence
#   uses; "each row" -> ascending ordinal (the ordinal is the row's declared position).
def build_native_tool_registry(w: World) -> bytes:
    rows = sorted(w.doc(DV)["bootstrap_native_tool_candidate"], key=lambda row: row["ordinal"])
    out = b"FND01BOOTSTRAPNATIVETOOLSv1\x00" + u32(20)
    for row in rows:
        out += u32(row["ordinal"]) + lp32(row["id"])
        out += lp32_list(row["candidate_paths"]) + lp32_list(row["version_argv"])
        out += lp32(row["version_stream"]) + lp32(row["version_parse"]) + lp32(row["identity_rule"])
    return out


def direct_dependency_row(row: dict) -> bytes:
    features = sorted(set(row["features"]), key=utf8)
    return (
        u32(row["ordinal"])
        + lp32(row["package"])
        + lp32(row["version"])
        + lp32(row["source"])
        + boolean_byte(row["default_features"])
        + lp32_list(features)
        + boolean_byte(row["verifier_dependency"])
    )


# READING dependency-verification bootstrap_manifest_contract.direct_dependency_registry_sha256
#   keys: direct_dependency_registry_encoding, direct_dependency_row_fields, direct_dependency_order,
#         direct_dependency_count; rows [[bootstrap_direct_dependency]].
#   OPEN TOKENS: boolean bytes are 0x00/0x01; features are applied "sorted unique" by raw bytes;
#   rows in ordinal order (the ordinal IS the direct_dependency_order position); union_alias is
#   not part of the row encoding (the encoding sentence does not list it).
def build_direct_registry(w: World) -> bytes:
    rows = sorted(w.doc(DV)["bootstrap_direct_dependency"], key=lambda row: row["ordinal"])
    return b"FND01BOOTSTRAPDIRECTv1\x00" + u32(45) + b"".join(direct_dependency_row(row) for row in rows)


# READING dependency-verification bootstrap_manifest_contract.union_only_registry_sha256
#   keys: union_only_registry_encoding ("the same full-row encoding for only
#   verifier_dependency=false rows while retaining each original 45-row ordinal and terminal
#   false byte").
def build_union_registry(w: World) -> bytes:
    rows = sorted(w.doc(DV)["bootstrap_direct_dependency"], key=lambda row: row["ordinal"])
    rows = [row for row in rows if not row["verifier_dependency"]]
    return b"FND01BOOTSTRAPUNIONv1\x00" + u32(38) + b"".join(direct_dependency_row(row) for row in rows)


def toml_string(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def union_dependency_line(row: dict) -> str:
    features = sorted(set(row["features"]), key=utf8)
    rendered = "[" + ", ".join(toml_string(feature) for feature in features) + "]"
    return (
        f"{row['union_alias']} = {{ package = {toml_string(row['package'])}, "
        f"version = {toml_string('=' + row['version'])}, "
        f"default-features = {'true' if row['default_features'] else 'false'}, "
        f"features = {rendered}, optional = true, registry = \"crates-io\" }}"
    )


# READING dependency-verification bootstrap_manifest_contract.canonical_document_sha256  (J7)
#   keys: format ("canonical duplicate-key-free TOML with LF line endings and one terminal LF"),
#         document_order, package_block, bin_block, dependencies_header,
#         verifier_dependency_lines, verifier_dependency_order, union_dependency_line_rule,
#         union_alias_formula, union_source_rule, workspace_block, canonical_document_bytes.
#   INPUT: the 38 union rows are the committed [[bootstrap_direct_dependency]] rows with
#   verifier_dependency=false, in ordinal (= direct_dependency_order) order, which is what
#   union_source_rule's final "apply direct_dependency_order" yields.
#   OPEN TOKENS, fixed before the attempt:
#     - every emitted line ends in LF; "one blank LF" is one empty line; "terminal LF" is the
#       last line's own LF, so the document ends in exactly one LF (format: "one terminal LF");
#     - verifier_dependency_lines are emitted verbatim, ordered by verifier_dependency_order
#       (each line's key is the text before " = ");
#     - a union line's alias is the row's declared union_alias; its inline-table keys appear in
#       the order union_dependency_line_rule lists them (package, version, default-features,
#       features, optional, registry); spacing and array style copy verifier_dependency_lines
#       ("{ key = value, ... }", '["a", "b"]'); an empty feature set renders "[]"; version is
#       "=<exact version>"; "registry crates-io" renders registry = "crates-io".
def build_bootstrap_document(w: World) -> bytes:
    contract = w.doc(DV)["bootstrap_manifest_contract"]
    verifier_by_name = {line.split(" = ", 1)[0]: line for line in contract["verifier_dependency_lines"]}
    rows = sorted(w.doc(DV)["bootstrap_direct_dependency"], key=lambda row: row["ordinal"])
    union_rows = [row for row in rows if not row["verifier_dependency"]]
    lines = list(contract["package_block"]) + [""] + list(contract["bin_block"]) + [""]
    lines.append(contract["dependencies_header"])
    lines += [verifier_by_name[name] for name in contract["verifier_dependency_order"]]
    lines += [union_dependency_line(row) for row in union_rows]
    lines += [""] + list(contract["workspace_block"])
    return utf8("\n".join(lines) + "\n")


# READING dependency-verification fixture_contract.canonical_sha256
#   keys: value_digest_encoding (FND01FIXv1 + NUL + one assertion-tagged value),
#         canonical_encoding (bare concatenation, no header/count), canonical_record
#         ("id || NUL || application || NUL || value_kind || NUL || lowercase
#         value_digest_sha256 || LF, sorted by raw UTF-8 id bytes"); rows [[mutation_fixture]].
#   The 51 per-value digests are reached only through this registry: TRANSITIVE, never direct.
def fixture_value_digest(row: dict) -> str:
    return hashlib.sha256(b"FND01FIXv1\x00" + fnd01_toml_value(row["value"])).hexdigest()


def build_fixture_registry(w: World) -> bytes:
    rows = sorted(w.doc(DV)["mutation_fixture"], key=lambda row: utf8(row["id"]))
    return b"".join(
        utf8("\x00".join([row["id"], row["application"], row["value_kind"], fixture_value_digest(row)])) + b"\n"
        for row in rows
    )


# READING dependency-verification receipt_contract.schema_registry_sha256
#   keys: schema_registry_encoding; rows [[receipt_schema]]. Fully specified; no open token.
def build_receipt_schema_registry(w: World) -> bytes:
    rows = sorted(w.doc(DV)["receipt_schema"], key=lambda row: utf8(row["receipt_id"]))
    out = b"FND01RECEIPTSCHEMAv1\x00" + u32(len(rows))
    for row in rows:
        out += lp32(row["kind"]) + lp32(row["receipt_id"]) + lp32(row["table_name"])
        out += lp32_list(row["exact_fields"])
        out += lp32(row["cardinality_rule"]) + lp32(row["semantic_rule"])
        out += optional_lp32(row, "typed_result_owner_rule")
    return out


# READING dependency-verification record_schema_contract.record_schema_registry_sha256
#   keys: record_schema_registry_encoding; rows [[record_schema]]. child_fields are stored as
#   the `field=>schema-id` strings the encoding names.
def build_record_schema_registry(w: World) -> bytes:
    rows = sorted(w.doc(DV)["record_schema"], key=lambda row: utf8(row["id"]))
    out = b"FND01RECSCHEMAv2\x00" + u32(len(rows))
    for row in rows:
        out += lp32(row["id"]) + lp32_list(row["selectors"]) + lp32_list(row["exact_fields"])
        out += lp32_list(row["child_fields"]) + lp32(row["rule"])
    return out


# READING dependency-verification record_schema_contract.record_variant_registry_sha256
#   keys: record_variant_registry_encoding; rows [[record_variant_schema]].
#   OPEN TOKEN: "length-prefixed" -> u32be, the width the same sentence states for id.
def build_record_variant_registry(w: World) -> bytes:
    rows = sorted(w.doc(DV)["record_variant_schema"], key=lambda row: utf8(row["id"]))
    out = b"FND01RECVARIANTv1\x00" + u32(len(rows))
    for row in rows:
        out += lp32(row["id"]) + lp32(row["parent_selector"])
        out += lp32(row["discriminator_field"]) + lp32(row["discriminator_value"])
        out += lp32_list(row["required_fields"]) + lp32_list(row["optional_fields"])
        out += lp32_list(row["child_fields"]) + lp32(row["rule"])
    return out


# READING dependency-verification policy_shape_contract.registry_sha256
#   keys: shape_row_encoding, shape_rows_a/b/c, shape_row_count, root_scalar_type_rows,
#         root_scalar_type_row_count, conditional_variant_rows, conditional_variant_row_count.
#   OPEN TOKEN: the three count words are the declared counts, each asserted equal to its rows.
def build_policy_shape_registry(w: World) -> bytes:
    contract = w.doc(DV)["policy_shape_contract"]
    shape = contract["shape_rows_a"] + contract["shape_rows_b"] + contract["shape_rows_c"]
    groups = [
        (contract["shape_row_count"], shape, "|"),
        (contract["root_scalar_type_row_count"], contract["root_scalar_type_rows"], "|"),
        (contract["conditional_variant_row_count"], contract["conditional_variant_rows"], "@"),
    ]
    out = b"FND01POLICYSHAPEv2\x00"
    for count, rows, separator in groups:
        if count != len(rows):
            raise ValueError(f"population control: declared count {count} disagrees with {len(rows)} rows")
        ordered = sorted(rows, key=lambda row: utf8(row.split(separator, 1)[0]))
        out += lp32_list(ordered)
    return out


# READING dependency-verification supply_bundle_contract.index_json_registry_sha256
#   keys: index_json_registry_encoding and the seven index_json_* arrays it names.
#   OPEN TOKEN: group ids are the literal words the encoding lists (top-level-allowed, ...,
#   versions); each group's rows keep their declared array order.
def build_index_json_registry(w: World) -> bytes:
    contract = w.doc(DV)["supply_bundle_contract"]
    groups = [
        ("top-level-allowed", contract["index_json_top_level_allowed_fields"]),
        ("top-level-required", contract["index_json_top_level_required_fields"]),
        ("top-level-types", contract["index_json_top_level_type_rows"]),
        ("dependency-allowed", contract["index_json_dependency_allowed_fields"]),
        ("dependency-required", contract["index_json_dependency_required_fields"]),
        ("dependency-types", contract["index_json_dependency_type_rows"]),
        ("versions", contract["index_json_version_rows"]),
    ]
    out = b"FND01CARGOINDEXJSONv1\x00" + u32(len(groups))
    for group_id, rows in groups:
        out += lp32(group_id) + lp32_list(rows)
    return out


# READING dependency-verification repository_surface_contract.agent_behavior_rule_registry_sha256
#   keys: agent_behavior_registry_encoding ("ASCII FND01AGENTRULEv1 followed by NUL and u32be row
#         count, then rows in agent_behavior_rule order as u32be id length/id bytes and u32be
#         required_exact_substring length/exact bytes"), agent_behavior_rule_count;
#         rows [[agent_behavior_rule]].
#   OPEN TOKEN: "agent_behavior_rule order" is the declared array order of [[agent_behavior_rule]]
#   (the table has no order key of its own). The count word is the row count, asserted equal to
#   agent_behavior_rule_count.
def build_agent_rule_registry(w: World) -> bytes:
    dv = w.doc(DV)
    rows = dv["agent_behavior_rule"]
    if len(rows) != dv["repository_surface_contract"]["agent_behavior_rule_count"]:
        raise ValueError("population control: agent_behavior_rule_count disagrees with the row count")
    out = b"FND01AGENTRULEv1\x00" + u32(len(rows))
    for row in rows:
        out += lp32(row["id"]) + lp32(row["required_exact_substring"])
    return out


# ---- dependency-verification: trees (Class TREE) ---------------------------------------------


def tree_record(path: str, length: int, digest: bytes) -> bytes:
    return lp32(path) + u64(length) + digest


# READING dependency-verification source_tree.sha256
#   keys: format FND01TREEv1, path_scope ("repository-relative POSIX ASCII path beginning
#         evidence/fnd-01/"), ordering ("ascending raw path bytes"), record_encoding
#         ("u32be(path_len) || path || u64be(file_len) || raw_sha256(file_bytes)"),
#         domain_prefix "none", excluded_exact_paths, excluded_exact_directory, file_count,
#         total_bytes.
#   INPUT: every file in the --rev tree under evidence/fnd-01/, minus the excluded exact paths
#   and the excluded directory, with its bytes at --rev. No header and no count word (domain_prefix
#   none). POPULATION CONTROL before hashing: the selected count and byte total must equal
#   file_count and total_bytes, otherwise the run is VOID (the reading did not select the set).
def build_source_tree(w: World) -> bytes:
    table = w.doc(DV)["source_tree"]
    excluded = set(table["excluded_exact_paths"])
    directory = table["excluded_exact_directory"].rstrip("/") + "/"
    paths = [
        path for path in w.repo.ls_files(ROOT)
        if path not in excluded and not path.startswith(directory)
    ]
    paths.sort(key=utf8)
    records, total = [], 0
    for path in paths:
        data = w.raw(path)
        total += len(data)
        records.append(tree_record(path, len(data), hashlib.sha256(data).digest()))
    if len(paths) != table["file_count"] or total != table["total_bytes"]:
        raise ValueError(
            f"population control: selected {len(paths)} files / {total} B, declared "
            f"{table['file_count']} / {table['total_bytes']}"
        )
    return b"".join(records)


# READING dependency-verification source_family[i].tree_sha256
#   keys: the source_family row (id, file_count, total_bytes, tree_sha256); record_schema
#         source-family-observation rule ("its tree digest is recomputed from the exact member
#         rows"); members are the [[source_input]] rows whose family equals the family id.
#   OPEN TOKEN, NOT STATED ANYWHERE: which tree encoding. Read as source_tree's FND01TREEv1
#   (the only tree format this file declares for evidence files): record_encoding over the member
#   rows in ascending raw path bytes, each record built from the row's declared path, byte_length
#   and raw 32-byte sha256; no header, no count word (domain_prefix none).
#   POPULATION CONTROL: member count and byte total equal the row's file_count and total_bytes.
def family_tree_builder(index: int) -> Callable[[World], bytes]:
    def build(w: World) -> bytes:
        dv = w.doc(DV)
        family = dv["source_family"][index]
        members = [row for row in dv["source_input"] if row["family"] == family["id"]]
        members.sort(key=lambda row: utf8(row["path"]))
        total = sum(row["byte_length"] for row in members)
        if len(members) != family["file_count"] or total != family["total_bytes"]:
            raise ValueError(
                f"population control: {len(members)} members / {total} B, declared "
                f"{family['file_count']} / {family['total_bytes']}"
            )
        return b"".join(
            tree_record(row["path"], row["byte_length"], bytes.fromhex(row["sha256"])) for row in members
        )

    return build


# READING dependency-verification archive_contract[i].member_tree_sha256
#   keys: archive_contract row (path, expected_root, member_count, regular_file_count,
#         expanded_bytes, allowed_entry_types); archive_parser_contract.member_tree_record_encoding
#         ("u32be(path_len) || path || u64be(file_len) || raw_sha256(member_bytes)"),
#         path_encoding "strict raw UTF-8"; archive_member_binding_rule ("path always
#         root-relative").
#   INPUT: the committed .crate at --rev, gzip then tar.
#   OPEN TOKENS: member path is root-relative (the expected_root/ prefix stripped, per the binding
#   rule); records in ascending raw UTF-8 path bytes (the ordering source_tree states; the record
#   encoding itself states none); no header or count word (none is declared).
#   POPULATION CONTROL: regular member count equals member_count and regular_file_count; member
#   byte total equals expanded_bytes.
def archive_tree_builder(index: int) -> Callable[[World], bytes]:
    def build(w: World) -> bytes:
        row = w.doc(DV)["archive_contract"][index]
        data = gzip.decompress(w.raw(row["path"]))
        prefix = row["expected_root"] + "/"
        members = []
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            for member in archive.getmembers():
                if not member.isreg():
                    raise ValueError(f"non-regular member {member.name!r}")
                if not member.name.startswith(prefix):
                    raise ValueError(f"member {member.name!r} outside {prefix}")
                body = archive.extractfile(member).read()
                members.append((member.name[len(prefix):], body))
        members.sort(key=lambda item: utf8(item[0]))
        total = sum(len(body) for _, body in members)
        if len(members) != row["member_count"] or len(members) != row["regular_file_count"] or total != row["expanded_bytes"]:
            raise ValueError(
                f"population control: {len(members)} members / {total} B, declared "
                f"{row['member_count']} / {row['expanded_bytes']}"
            )
        return b"".join(tree_record(path, len(body), hashlib.sha256(body).digest()) for path, body in members)

    return build


# ---- dependency-verification: content literals and file segments (Class B) -------------------


# READING dependency-verification agent_behavior_rule[i].sha256
#   keys: agent_behavior_rule ("each exact substring occurs once in final AGENTS.md with its
#   declared byte length and SHA-256"); row required_exact_substring, byte_length.
#   The preimage is the UTF-8 bytes of required_exact_substring as parsed from the TOML.
def agent_rule_builder(index: int) -> Callable[[World], bytes]:
    return lambda w: utf8(w.doc(DV)["agent_behavior_rule"][index]["required_exact_substring"])


BOUNDARY = re.compile(r"^first exact (?:bytes )?`(.*)`$", re.S)


def boundary_token(spec: str) -> bytes:
    match = BOUNDARY.match(spec)
    if not match:
        raise Underdetermined(f"boundary {spec!r} is not of the form first exact `...`")
    return utf8(match.group(1).replace("\\n", "\n"))


def unique_offset(haystack: bytes, needle: bytes, label: str) -> int:
    first = haystack.find(needle)
    if first < 0:
        raise Underdetermined(f"boundary {label} does not occur in the input")
    if haystack.find(needle, first + 1) >= 0:
        raise Underdetermined(f"boundary {label} occurs more than once; the rule requires a unique resolution")
    return first


# READING dependency-verification agent_frozen_segment[i].sha256
#   keys: agent_frozen_segment_rule ("resolve each exact byte boundary uniquely in final AGENTS.md
#         and hash the half-open segment without newline normalization; the three declared
#         pre-edit byte lengths and SHA-256 values must remain exact"); row start_boundary,
#         end_boundary, byte_length.
#   INPUT REVISION (pre-registered): AGENTS.md as it stood in the commit that first added this
#   segment's digest to dependency-verification.toml (git log -S, oldest first, reachable from
#   --rev). The rule binds pre-edit bytes, and the repository's AGENTS.md has been edited since,
#   so --rev's AGENTS.md is not the input this digest describes. The segment's bytes at --rev are
#   reported as a drift diagnostic only and never change the outcome.
#   OPEN TOKENS: "byte zero" is offset 0 and "EOF" is the file length; `first exact `X`` is the
#   offset of X with the two-character sequence \n read as LF; the segment starts AT its start
#   boundary (the boundary text is inside the segment) and ends BEFORE its end boundary
#   (half-open); a boundary text that occurs more than once is UNDERDETERMINED ("uniquely").
def segment_bytes(data: bytes, start_spec: str, end_spec: str) -> bytes:
    start = 0 if start_spec == "byte zero" else unique_offset(data, boundary_token(start_spec), start_spec)
    end = len(data) if end_spec == "EOF" else unique_offset(data, boundary_token(end_spec), end_spec)
    if end < start:
        raise Underdetermined(f"end boundary {end_spec!r} precedes start boundary {start_spec!r}")
    return data[start:end]


def agent_segment_builder(index: int) -> Callable[[World], bytes]:
    def build(w: World) -> bytes:
        row = w.doc(DV)["agent_frozen_segment"][index]
        revision = w.repo.binding_revision(row["sha256"], DV)
        return segment_bytes(w.repo.read("AGENTS.md", revision), row["start_boundary"], row["end_boundary"])

    return build


# READING dependency-verification repository_surface_contract.historical_changelog_suffix_sha256
#   keys: historical_changelog_boundary ("first exact bytes `## [v0.2.0] -- 2026-02-15 (GitHub
#         Release)\n`"), historical_changelog_rule ("locate historical_changelog_boundary exactly
#         once ... and require every byte from its first `#` through EOF to have the exact frozen
#         byte length and SHA-256"), historical_changelog_suffix_byte_length.
#   INPUT REVISION: CHANGELOG.md in the commit that first added this digest (same rule as the
#   AGENTS segments); --rev is a drift diagnostic only.
#   OPEN TOKEN: "exactly once" is enforced over the whole file (a second occurrence anywhere is
#   UNDERDETERMINED), and the suffix starts at the boundary's first byte, which is its first `#`.
def build_changelog_suffix(w: World) -> bytes:
    table = w.doc(DV)["repository_surface_contract"]
    revision = w.repo.binding_revision(table["historical_changelog_suffix_sha256"], DV)
    return segment_bytes(w.repo.read("CHANGELOG.md", revision), table["historical_changelog_boundary"], "EOF")


def drift_note(w: World, target: Target) -> str:
    """For the file-segment targets: the same reading applied to --rev, as a diagnostic."""
    dv = w.doc(DV)
    try:
        if target.location.startswith("agent_frozen_segment"):
            row = lookup(dv, target.location.rsplit(".", 1)[0])
            data = segment_bytes(w.repo.read("AGENTS.md"), row["start_boundary"], row["end_boundary"])
            declared = row["sha256"]
        else:
            table = dv["repository_surface_contract"]
            data = segment_bytes(w.repo.read("CHANGELOG.md"), table["historical_changelog_boundary"], "EOF")
            declared = table["historical_changelog_suffix_sha256"]
    except Underdetermined as gap:
        return f"drift diagnostic at --rev: {gap}"
    same = hashlib.sha256(data).hexdigest() == declared
    return f"drift diagnostic at --rev: {len(data)} B, {'unchanged' if same else 'DRIFTED'} since binding"


# ---- dependency-verification: FND01OBSv1 observations (Class OBS) ----------------------------


def resolve_pointer(document, pointer: str):
    """RFC 6901 over a parsed TOML/JSON tree, with mutation_contract identity components.

    READING (mutation_contract.selector_grammar): components are split on "/" and unescaped
    (~1 -> "/", ~0 -> "~"); on a table a component is a literal key; on an array a canonical
    decimal is an index and a component containing "=" is an identity component <key>=<literal>
    selecting the one element that is a table whose <key> is the string <literal>. A missing key,
    an out-of-range index, or zero identity matches is ABSENT (assertion_contract missing_tag);
    more than one identity match, or any other component on an array, is UNDERDETERMINED.
    """
    if pointer == "":
        return document
    if not pointer.startswith("/"):
        raise Underdetermined(f"selector {pointer!r} is not an RFC 6901 pointer")
    node = document
    for raw in pointer[1:].split("/"):
        component = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict):
            if component not in node:
                return ABSENT
            node = node[component]
        elif isinstance(node, list):
            if re.fullmatch(r"0|[1-9][0-9]*", component):
                index = int(component)
                if index >= len(node):
                    return ABSENT
                node = node[index]
            elif "=" in component:
                key, literal = component.split("=", 1)
                matches = [item for item in node if isinstance(item, dict) and item.get(key) == literal]
                if not matches:
                    return ABSENT
                if len(matches) > 1:
                    raise Underdetermined(f"identity component {component!r} matches {len(matches)} elements")
                node = matches[0]
            else:
                raise Underdetermined(f"component {component!r} on an array is neither an index nor an identity")
        else:
            return ABSENT
    return node


# READING dependency-verification semantic_assertion[i].baseline_observation_sha256
#   keys: assertion_contract observation_encoding FND01OBSv1, header ("ASCII FND01OBSv1 followed by
#         NUL"), toml_kind_byte 1 / json_kind_byte 2 / raw_kind_byte 3, path_encoding,
#         selector_tuple_encoding, value_sequence, toml_domain, json_domain, raw_domain, the tag
#         table (missing 0x00 ... json_number 0x0a), observation_identity; row source_path,
#         selector, secondary_selector, baseline_mode canonical_source_value, observation_mode.
#   OPEN TOKENS (the prose names each part but not the order they are joined in):
#     - part order is the order the keys are declared: header || kind byte || path_encoding(source
#       path) || selector_tuple_encoding || value_sequence;
#     - the kind byte is one raw byte (toml 0x01, json 0x02, raw 0x03), with no length or tag;
#     - baseline_mode canonical_source_value observes the unmutated committed source at --rev;
#     - the selector tuple is [selector] or, for a swap row, [selector, secondary_selector];
#     - a raw_source_bytes value is raw_bytes_tag 0x08 + u64be length + whole-file bytes, and its
#       selector ("remains an edit location") is still encoded in the tuple;
#     - toml values use fnd01_toml_value; json values use fnd01_json_value; an ABSENT selection
#       is the single missing_tag byte 0x00.
def observation_bytes(w: World, row: dict) -> bytes:
    mode = row["observation_mode"]
    kinds = {"canonical_selected_toml": 1, "canonical_selected_json": 2, "raw_source_bytes": 3}
    if mode not in kinds:
        raise Underdetermined(f"observation_mode {mode!r} has no declared kind byte")
    selectors = [row["selector"]] + ([row["secondary_selector"]] if "secondary_selector" in row else [])
    out = b"FND01OBSv1\x00" + u8(kinds[mode]) + lp32(row["source_path"])
    out += u32(len(selectors)) + b"".join(lp32(selector) for selector in selectors)
    if mode == "raw_source_bytes":
        if len(selectors) != 1:
            raise Underdetermined("raw_domain requires exactly one selector")
        data = w.raw(row["source_path"])
        return out + b"\x08" + u64(len(data)) + data
    if mode == "canonical_selected_toml":
        tree, encode = w.doc(row["source_path"]), fnd01_toml_value
    else:
        tree, encode = strict_json(w.raw(row["source_path"])), fnd01_json_value
    for selector in selectors:
        value = resolve_pointer(tree, selector)
        out += b"\x00" if value is ABSENT else encode(value)
    return out


def observation_builder(index: int) -> Callable[[World], bytes]:
    return lambda w: observation_bytes(w, w.doc(DV)["semantic_assertion"][index])


# ---- security vectors (Class B) ---------------------------------------------------------------


# READING security-vectors case.sha256 (Class B), per the case's own `encoding` key:
#   utf-8                              -> the UTF-8 bytes of the parsed payload string
#   hex                                -> bytes.fromhex(payload)
#   content-addressed-checked-in-binary-> the blob at payload_path, read at the same --rev
#   content-address-reference          -> the resolved bytes of the case whose id == payload_ref
#   Every case declares byte_length, so every MATCH is two-signal.
def security_vector_bytes(w: World, case: dict, depth: int = 0) -> bytes:
    encoding = case["encoding"]
    if encoding == "utf-8":
        return utf8(case["payload"])
    if encoding == "hex":
        return bytes.fromhex(case["payload"])
    if encoding == "content-addressed-checked-in-binary":
        return w.raw(case["payload_path"])
    if encoding == "content-address-reference":
        if depth > 4:
            raise Underdetermined("payload_ref chain does not terminate")
        referenced = [item for item in w.doc(SV)["case"] if item["id"] == case["payload_ref"]]
        if len(referenced) != 1:
            raise Underdetermined(f"payload_ref {case['payload_ref']!r} resolves to {len(referenced)} cases")
        return security_vector_bytes(w, referenced[0], depth + 1)
    raise Underdetermined(f"encoding {encoding!r} has no declared byte rule")


def security_vector_builder(index: int) -> Callable[[World], bytes]:
    return lambda w: security_vector_bytes(w, w.doc(SV)["case"][index])


# ---- auth-standards ---------------------------------------------------------------------------


# READING auth-standards phase_b_authority_table.full_input_digest
#   keys: full_input_canonicalization ("For source-order rows, encode each required dimension as
#         ASCII field-name, 0x00, the exact one-line TOML scalar right-hand-side token, 0x00;
#         terminate each row with 0x0A; SHA-256 the resulting bytes. Optional dimensions are
#         excluded"), required_dimensions, expected_row_count, compiler ("from every [[artifacts]]
#         record").
#   INPUT: the raw text of auth-standards.toml at --rev; rows are the [[artifacts]] blocks in
#   source order (a block runs from its header line to the next line that starts with "[").
#   OPEN TOKENS: dimensions are emitted in required_dimensions list order (the prose says "each
#   required dimension" and fixes no other order); the RHS token is the exact text after the
#   first " = " on the dimension's line up to, not including, its LF, with nothing stripped; a
#   dimension whose line is absent, repeated, or not one line is UNDERDETERMINED.
#   POPULATION CONTROL: the block count equals expected_row_count.
def build_auth_full_input(w: World) -> bytes:
    table = w.doc(AUTH)["phase_b_authority_table"]
    lines = w.text(AUTH).split("\n")
    blocks, current = [], None
    for line in lines:
        if line == "[[artifacts]]":
            current = []
            blocks.append(current)
        elif line.startswith("["):
            current = None
        elif current is not None:
            current.append(line)
    if len(blocks) != table["expected_row_count"]:
        raise ValueError(f"population control: {len(blocks)} [[artifacts]] blocks, declared {table['expected_row_count']}")
    out = b""
    for number, block in enumerate(blocks):
        tokens: dict[str, list] = {}
        for line in block:
            if " = " in line and not line.startswith((" ", "\t", "#")):
                key, rhs = line.split(" = ", 1)
                tokens.setdefault(key, []).append(rhs)
        for name in table["required_dimensions"]:
            found = tokens.get(name, [])
            if len(found) != 1:
                raise Underdetermined(f"artifact block {number} has {len(found)} one-line tokens for {name}")
            rhs = found[0]
            if rhs.startswith(('"""', "'''")) or rhs.startswith("[") and not rhs.endswith("]"):
                raise Underdetermined(f"artifact block {number} dimension {name} is not a one-line scalar token")
            out += name.encode("ascii") + b"\x00" + utf8(rhs) + b"\x00"
        out += b"\n"
    return out


# ---- toolchain-asupersync ---------------------------------------------------------------------


# READING toolchain-asupersync toolchain.rustup.release_metadata_sha256
#   keys: release_metadata_exact_utf8, release_metadata_content_length_bytes, note ("The
#   recorded exact 40-byte body and SHA-256 bind the observed 1.29.0 pointer").
#   The preimage is the UTF-8 bytes of release_metadata_exact_utf8 as parsed from the TOML.
def build_rustup_metadata(w: World) -> bytes:
    return utf8(w.doc(TC)["toolchain"]["rustup"]["release_metadata_exact_utf8"])


# ---- sdk-matrix -------------------------------------------------------------------------------


# READING sdk-matrix catalog.tier{1,2,3}_canonical_sha256 and peer_era_matrix.canonical_sha256
#   keys: catalog.canonicalization ("Reject duplicate IDs; require known ASCII-lowercase IDs; sort
#         bytewise; join with LF; retain one final LF; SHA-256 the resulting bytes"),
#         tier{n}_ids_canonical; peer_era_matrix.peer_ids_canonical.
#   OPEN TOKEN: peer_era_matrix states no rule of its own; its canonical_sha256 is read under the
#   catalog's canonicalization applied to peer_ids_canonical (cross-table reading). "known" IDs is
#   not checked against a list (no list of known IDs is declared besides the catalog entries).
def canonical_id_bytes(ids: list) -> bytes:
    if len(set(ids)) != len(ids):
        raise Underdetermined("duplicate ID in a canonical ID list")
    for item in ids:
        if not re.fullmatch(r"[a-z0-9._-]+", item):
            raise Underdetermined(f"ID {item!r} is not ASCII lowercase")
    return utf8("\n".join(sorted(ids, key=utf8)) + "\n")


def tier_builder(tier: int) -> Callable[[World], bytes]:
    return lambda w: canonical_id_bytes(w.doc(SDK)["catalog"][f"tier{tier}_ids_canonical"])


def build_peer_era_matrix(w: World) -> bytes:
    return canonical_id_bytes(w.doc(SDK)["peer_era_matrix"]["peer_ids_canonical"])


# READING sdk-matrix complete_input_binding.digest
#   keys: domain_separator_hex, manifest_record_tag_hex, lock_record_tag_hex, field_separator_hex,
#         manifest_path, lock_root, lock_relative_paths_bytewise, lock_file_count,
#         manifest_inclusion, self_excluded_manifest_fields, self_exclusion_contract,
#         preimage_algorithm, preimage_byte_length.
#   INPUT: sdk-matrix.toml raw bytes at --rev and the 13 listed files under lock_root at --rev.
#   Built exactly as preimage_algorithm states: domain separator; manifest record tag, ASCII
#   decimal included-manifest length, field separator, included manifest bytes; then per listed
#   file in list order: lock record tag, UTF-8 filename, field separator, ASCII decimal length,
#   field separator, raw bytes.
#   SELF-EXCLUSION: inside the sole [complete_input_binding] table, delete only the ASCII digits
#   after the exact bytes `preimage_byte_length = ` and the whole basic-string token (quotes
#   included) after the exact bytes `digest = `; every prefix and line ending is kept.
#   OPEN TOKEN: a table region runs from its header line to the next line starting with "[".
def build_complete_input(w: World) -> bytes:
    table = w.doc(SDK)["complete_input_binding"]
    manifest = w.raw(table["manifest_path"])
    lines = manifest.split(b"\n")
    headers = [index for index, line in enumerate(lines) if line == b"[complete_input_binding]"]
    if len(headers) != 1:
        raise Underdetermined(f"{len(headers)} [complete_input_binding] headers")
    kept, in_table, hits = [], False, {"length": 0, "digest": 0}
    for index, line in enumerate(lines):
        if line.startswith(b"["):
            in_table = index == headers[0]
        if in_table and re.fullmatch(rb"preimage_byte_length = [0-9]+", line):
            line, hits["length"] = b"preimage_byte_length = ", hits["length"] + 1
        elif in_table and re.fullmatch(rb'digest = "[^"\\]*"', line):
            line, hits["digest"] = b"digest = ", hits["digest"] + 1
        kept.append(line)
    if hits != {"length": 1, "digest": 1}:
        raise Underdetermined(f"self-excluded fields resolved {hits} times, not once each")
    included = b"\n".join(kept)
    separator = bytes.fromhex(table["field_separator_hex"])
    out = bytes.fromhex(table["domain_separator_hex"])
    out += bytes.fromhex(table["manifest_record_tag_hex"]) + str(len(included)).encode("ascii") + separator + included
    names = table["lock_relative_paths_bytewise"]
    if len(names) != table["lock_file_count"]:
        raise ValueError("population control: lock_file_count disagrees with the listed files")
    for name in names:
        data = w.raw(table["lock_root"] + "/" + name)
        out += bytes.fromhex(table["lock_record_tag_hex"]) + utf8(name) + separator
        out += str(len(data)).encode("ascii") + separator + data
    return out


# READING sdk-matrix peers[id=csharp].lock.native_generated_sha256
#   keys: vendoring_normalization ("One final LF was added to the native JSON for repository
#   text-file hygiene"), lock_path, native_generated_byte_length.
#   The preimage is the committed lock_path bytes at --rev with exactly its one final LF removed;
#   a file that does not end in LF is UNDERDETERMINED.
def build_csharp_native(w: World) -> bytes:
    lock = next(peer for peer in w.doc(SDK)["peers"] if peer["id"] == "csharp")["lock"]
    data = w.raw(lock["lock_path"])
    if not data.endswith(b"\n"):
        raise Underdetermined("the committed lock does not end in the LF the normalization says was added")
    return data[:-1]


# ---- serialization-uri-dependencies -----------------------------------------------------------


# READING serialization-uri consumer_probe.manifest_sha256 / source_sha256, dev_graph.sha256,
#   advisory_snapshot.audit_output_sha256, and the immutable_input rows that repeat them
#   keys: reproduction.materialization_recipe (`yq ... '.consumer_probe.manifest' | jq -j -r '.'`,
#         i.e. the raw string with no added newline), manifest_bytes, source_bytes;
#         dev_graph.canonical_output and bytes; advisory_snapshot.audit_output_json and
#         audit_output_bytes; immutable_input kind embedded-toml-bytes / embedded-rust-bytes /
#         embedded-json-bytes.
#   The preimage is the UTF-8 bytes of the parsed TOML string. An immutable_input row is joined to
#   its embedded string by kind (embedded-toml-bytes -> consumer_probe.manifest, embedded-rust-bytes
#   -> consumer_probe.source, embedded-json-bytes -> advisory_snapshot.audit_output_json).
EMBEDDED = {
    "embedded-toml-bytes": ("consumer_probe", "manifest"),
    "embedded-rust-bytes": ("consumer_probe", "source"),
    "embedded-json-bytes": ("advisory_snapshot", "audit_output_json"),
}


def ser_string_builder(table: str, key: str) -> Callable[[World], bytes]:
    return lambda w: utf8(lookup(w.doc(SER), f"{table}.{key}"))


def immutable_input_builder(index: int) -> Callable[[World], bytes]:
    def build(w: World) -> bytes:
        row = w.doc(SER)["phase_a_input_contract"]["immutable_input"][index]
        if row["kind"] not in EMBEDDED:
            raise Underdetermined(f"kind {row['kind']!r} names no embedded string")
        table, key = EMBEDDED[row["kind"]]
        return utf8(w.doc(SER)[table][key])

    return build


# READING serialization-uri consumer_probe.lock_package_projection_sha256
#   keys: reproduction.lock_projection ("yq -p=toml -o=json '.' Cargo.lock | jq -r '.package |
#         sort_by(.name,.version)[] | [.name,.version,(.checksum // \"path\")] | @tsv'"),
#         lock_package_projection_bytes, lock_package_projection_lines, lock_artifact_path.
#   INPUT: the committed consumer lock at --rev (lock_artifact_path).
#   OPEN TOKENS: jq sort_by over [name, version] compares strings by code point; jq -r ends every
#   output line with LF; @tsv escapes backslash, TAB, LF and CR (none is expected); a package
#   with no checksum renders the word path.
#   POPULATION CONTROL: the line count equals lock_package_projection_lines.
def build_lock_projection(w: World) -> bytes:
    probe = w.doc(SER)["consumer_probe"]
    lock = tomllib.loads(w.text(probe["lock_artifact_path"]))
    packages = sorted(lock["package"], key=lambda package: (package["name"], package["version"]))

    def tsv(text: str) -> str:
        return text.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r")

    lines = [
        "\t".join(tsv(field) for field in (package["name"], package["version"], package.get("checksum", "path")))
        for package in packages
    ]
    if len(lines) != probe["lock_package_projection_lines"]:
        raise ValueError(f"population control: {len(lines)} lines, declared {probe['lock_package_projection_lines']}")
    return utf8("".join(line + "\n" for line in lines))


# READING serialization-uri phase_a_input_contract.baseline_sha256
#   keys: format / domain_separator_text FND01SERIALIZATIONURIINPUTSv2, domain_separator_hex
#         (normative), domain_separator_rule, string_encoding, row_field_order, row_encoding ("For
#         each immutable_input in declaration order, append each row_field_order value as u32
#         big-endian UTF-8 byte length followed immediately by its UTF-8 bytes"), preimage
#         ("domain_separator_bytes followed by the encoded immutable_input rows only").
#   No open token: the source-contract row's literal "self-excluded" and the byte-absent rows'
#   literal "absent" are encoded as the strings they are.
def build_phase_a_baseline(w: World) -> bytes:
    contract = w.doc(SER)["phase_a_input_contract"]
    out = bytes.fromhex(contract["domain_separator_hex"])
    for row in contract["immutable_input"]:
        for name in contract["row_field_order"]:
            out += lp32(row[name])
    return out


# ---- tasks-apps -------------------------------------------------------------------------------


# READING tasks-apps executable_same_validator_contract.admitted_vendor_family_digest_sha256
#   keys: admitted_vendor_family_digest_algorithm ("SHA-256 over ASCII FND01TASKSAPPSVENDORv1 then
#         NUL, u32be entry count, then raw-UTF-8-path-sorted entries of u32be path length, path
#         bytes, u64be byte length, and raw 32-byte SHA-256; tasks-apps.toml and the separately
#         preserved blocked WHATWG candidate are intentionally excluded"),
#         admitted_vendor_input_count, admitted_vendor_input_total_bytes.
#   OPEN TOKENS: the admitted vendor inputs are the rows that carry a vendor_path: every
#   apps.artifact, tasks.artifact and tasks.conformance_artifact row (the WHATWG candidate carries
#   candidate_preserved_path instead and is excluded by name). Each entry uses the row's declared
#   vendor_path, byte_length and sha256 -- the identities the registry admits -- not a rehash of
#   the vendored file.
#   POPULATION CONTROL: entry count and byte total equal the declared count and total.
def build_vendor_family(w: World) -> bytes:
    doc = w.doc(TA)
    contract = doc["executable_same_validator_contract"]
    rows = doc["apps"]["artifact"] + doc["tasks"]["artifact"] + doc["tasks"]["conformance_artifact"]
    rows = sorted(rows, key=lambda row: utf8(row["vendor_path"]))
    total = sum(row["byte_length"] for row in rows)
    if len(rows) != contract["admitted_vendor_input_count"] or total != contract["admitted_vendor_input_total_bytes"]:
        raise ValueError(
            f"population control: {len(rows)} entries / {total} B, declared "
            f"{contract['admitted_vendor_input_count']} / {contract['admitted_vendor_input_total_bytes']}"
        )
    out = b"FND01TASKSAPPSVENDORv1\x00" + u32(len(rows))
    for row in rows:
        out += lp32(row["vendor_path"]) + u64(row["byte_length"]) + bytes.fromhex(row["sha256"])
    return out


# READING tasks-apps tasks.path_fixture[*] literal records (167)
#   keys: tasks.fixture_corpus_contract payload_encoding ("UTF-8 JSON without a trailing LF"),
#         payload_byte_length_rule, payload_hash_rule ("sha256 is the lowercase SHA-256 of the
#         exact UTF-8 bytes obtained from the TOML literal field; no JSON reserialization, member
#         reordering, whitespace normalization, or newline insertion"), context_literal_field_rule
#         (the substitution context uses substituted_response_literal/_byte_length/_sha256),
#         total_content_addressed_literal_record_count.
#   The preimage is the UTF-8 bytes of the parsed TOML literal string.
LITERAL_SLOTS = (
    ("raw_fixture", "literal"),
    ("composed_positive_fixture", "literal"),
    ("composed_negative_fixture", "literal"),
    ("correlation_negative_context", "substituted_response_literal"),
    ("acknowledgement_request_context", "literal"),
)


def fixture_literal_locations(doc: dict) -> list[tuple[str, str, str]]:
    """(digest location, bytes location, literal location) for every literal record."""
    found = []
    for index, row in enumerate(doc["tasks"]["path_fixture"]):
        base = f"tasks.path_fixture[{index}]"
        for slot, key in LITERAL_SLOTS:
            if slot in row:
                prefix = key.rsplit("literal", 1)[0]
                found.append((f"{base}.{slot}.{prefix}sha256", f"{base}.{slot}.{prefix}byte_length", f"{base}.{slot}.{key}"))
        for slot in ("composed_positive_member_fixtures", "composed_negative_member_fixtures"):
            for member in range(len(row.get(slot, []))):
                found.append((f"{base}.{slot}[{member}].sha256", f"{base}.{slot}[{member}].byte_length",
                              f"{base}.{slot}[{member}].literal"))
    return found


def literal_builder(file: str, literal_location: str) -> Callable[[World], bytes]:
    return lambda w: utf8(lookup(w.doc(file), literal_location))


# READING tasks-apps apps.standard_reuse[i].canonical_closure_sha256,
#   apps.sdk_1_29_0.standard_reuse_closure.canonical_global_sha256, and
#   apps.projection.standard_reuse_closure_sha256
#   keys: standard_reuse_closure canonical_root_payload ("UTF-8 and LF only:
#         fastmcp-sdk-schema-closure-v1\n, schema_source_sha256=<lowercase hex>\n, root=<sdk schema
#         export>\n, then node=<schema name>\n for every closure member in schema_name_order; the
#         final LF is required"), canonical_root_hash, schema_name_order ("ascending UTF-8 byte
#         order with duplicate names removed"), schema_closure_includes_root,
#         canonical_global_payload ("fastmcp-apps-sdk-1.29.0-standard-reuse-closures-v1\n,
#         schema_source_sha256=<lowercase hex>\n, then root=<sdk schema export><TAB>sha256=
#         <canonical root hash>\n in the literal standard_reuse_imports order"),
#         canonical_global_byte_length; rows apps.standard_reuse (sdk_schema_export,
#         schema_closure); apps.sdk_1_29_0.standard_reuse_imports; apps.projection
#         standard_reuse_inventory_ref (the projection's value is the same global digest).
#   OPEN TOKENS: the closure members are the row's declared schema_closure array (types.js is not
#   committed, so the graph extraction itself is not re-derived: this checks the ENCODING of the
#   declared closures, never whether they are the true closures); an import symbol maps to the
#   standard_reuse row whose symbol equals it; the global payload uses the COMPUTED root hashes.
#   DISCLOSED: RoseStream reproduced this encoding first (8dzq6 #5406). These readings were written
#   after that result was published, so they are not an independent first attempt.
def closure_payload(w: World, row: dict) -> bytes:
    closure = w.doc(TA)["apps"]["sdk_1_29_0"]["standard_reuse_closure"]
    names = sorted(set(row["schema_closure"]), key=utf8)
    text = "fastmcp-sdk-schema-closure-v1\n" + f"schema_source_sha256={closure['schema_source_sha256']}\n"
    text += f"root={row['sdk_schema_export']}\n" + "".join(f"node={name}\n" for name in names)
    return utf8(text)


def closure_builder(index: int) -> Callable[[World], bytes]:
    return lambda w: closure_payload(w, w.doc(TA)["apps"]["standard_reuse"][index])


def build_closure_global(w: World) -> bytes:
    apps = w.doc(TA)["apps"]
    closure = apps["sdk_1_29_0"]["standard_reuse_closure"]
    by_symbol = {row["symbol"]: row for row in apps["standard_reuse"]}
    text = "fastmcp-apps-sdk-1.29.0-standard-reuse-closures-v1\n" + f"schema_source_sha256={closure['schema_source_sha256']}\n"
    for symbol in apps["sdk_1_29_0"]["standard_reuse_imports"]:
        row = by_symbol[symbol]
        text += f"root={row['sdk_schema_export']}\tsha256={hashlib.sha256(closure_payload(w, row)).hexdigest()}\n"
    return utf8(text)


# --------------------------------------------------------------------------------------------
# Population: every J1 target, and every excluded base field with its category and reason
# --------------------------------------------------------------------------------------------


def unattempted(file: str, location: str, klass: str, reason: str) -> Target:
    return Target(file, location, klass, None, None, reason)


ABSENT_TOOL_OUTPUT = "input absent from committed bytes: {}"


def build_targets(w: World) -> list[Target]:
    dv, sv, ta, ser, sdk = w.doc(DV), w.doc(SV), w.doc(TA), w.doc(SER), w.doc(SDK)
    targets = [
        Target(DV, "mutation_contract.canonical_recipe_sha256", "A", "mutation_contract.canonical_recipe_bytes", build_mutation_recipe),
        Target(DV, "negative_inventory.sha256", "A", "negative_inventory.canonical_bytes", build_negative_inventory),
        Target(DV, "assertion_contract.canonical_sha256", "A", "assertion_contract.canonical_bytes", build_assertion_registry),
        Target(DV, "closed_child_handoff_contract.registry_sha256", "A", None, build_closed_child_registry),
        Target(DV, "command_environment_profiles.native_tool_candidate_registry_sha256", "A",
               "command_environment_profiles.native_tool_candidate_registry_bytes", build_native_tool_registry),
        Target(DV, "bootstrap_manifest_contract.direct_dependency_registry_sha256", "A",
               "bootstrap_manifest_contract.direct_dependency_registry_bytes", build_direct_registry),
        Target(DV, "bootstrap_manifest_contract.union_only_registry_sha256", "A",
               "bootstrap_manifest_contract.union_only_registry_bytes", build_union_registry),
        Target(DV, "bootstrap_manifest_contract.canonical_document_sha256", "DOC",
               "bootstrap_manifest_contract.canonical_document_bytes", build_bootstrap_document),
        Target(DV, "fixture_contract.canonical_sha256", "A", "fixture_contract.canonical_bytes", build_fixture_registry),
        Target(DV, "receipt_contract.schema_registry_sha256", "A", "receipt_contract.schema_registry_bytes",
               build_receipt_schema_registry),
        Target(DV, "record_schema_contract.record_schema_registry_sha256", "A",
               "record_schema_contract.record_schema_registry_bytes", build_record_schema_registry),
        Target(DV, "record_schema_contract.record_variant_registry_sha256", "A",
               "record_schema_contract.record_variant_registry_bytes", build_record_variant_registry),
        Target(DV, "policy_shape_contract.registry_sha256", "A", "policy_shape_contract.registry_bytes",
               build_policy_shape_registry),
        Target(DV, "supply_bundle_contract.index_json_registry_sha256", "A", "supply_bundle_contract.index_json_registry_bytes",
               build_index_json_registry),
        Target(DV, "repository_surface_contract.agent_behavior_rule_registry_sha256", "A", None, build_agent_rule_registry),
        unattempted(DV, "command_matrix_contract.gate_command_authority_sha256", "A",
                    "reading not yet written: the preimage needs the 206-command expansion of the 17 "
                    "command_templates through command_expansion_registry, with exact target/profile/"
                    "resolver/network-mode substitution; deferred to a later pre-registration commit"),
        Target(DV, "source_tree.sha256", "TREE", None, build_source_tree),
        unattempted(DV, "advisory_database_contract.source_tree_sha256", "TREE",
                    ABSENT_TOOL_OUTPUT.format("the RustSec advisory-db tree at commit 7c7ccac5 (1192 files, "
                                              "1283107 B) is not in the repository")),
        Target(DV, "repository_surface_contract.historical_changelog_suffix_sha256", "B",
               "repository_surface_contract.historical_changelog_suffix_byte_length", build_changelog_suffix),
    ]
    for index in range(len(dv["source_family"])):
        targets.append(Target(DV, f"source_family[{index}].tree_sha256", "TREE", None, family_tree_builder(index)))
    for index in range(len(dv["archive_contract"])):
        targets.append(Target(DV, f"archive_contract[{index}].member_tree_sha256", "TREE", None, archive_tree_builder(index)))
    for index in range(len(dv["agent_behavior_rule"])):
        targets.append(Target(DV, f"agent_behavior_rule[{index}].sha256", "B", f"agent_behavior_rule[{index}].byte_length",
                              agent_rule_builder(index)))
    for index in range(len(dv["agent_frozen_segment"])):
        targets.append(Target(DV, f"agent_frozen_segment[{index}].sha256", "B", f"agent_frozen_segment[{index}].byte_length",
                              agent_segment_builder(index)))
    for index in range(len(dv["semantic_assertion"])):
        targets.append(Target(DV, f"semantic_assertion[{index}].baseline_observation_sha256", "OBS", None,
                              observation_builder(index)))
        targets.append(unattempted(
            DV, f"semantic_assertion[{index}].violating_observation_sha256", "OBS",
            "reading not yet written: the violating observation first applies the case's mutation "
            "recipe (9 operations; per-operation semantics to be pre-registered in a later commit)"))
    for index in range(len(sv["case"])):
        targets.append(Target(SV, f"case[{index}].sha256", "B", f"case[{index}].byte_length", security_vector_builder(index)))
    targets.append(Target(AUTH, "phase_b_authority_table.full_input_digest", "A", None, build_auth_full_input))
    targets.append(Target(TC, "toolchain.rustup.release_metadata_sha256", "B",
                          "toolchain.rustup.release_metadata_content_length_bytes", build_rustup_metadata))
    targets.append(Target(SDK, "peer_era_matrix.canonical_sha256", "A", None, build_peer_era_matrix))
    for tier in (1, 2, 3):
        targets.append(Target(SDK, f"catalog.tier{tier}_canonical_sha256", "A", None, tier_builder(tier)))
    targets.append(Target(SDK, "complete_input_binding.digest", "A", "complete_input_binding.preimage_byte_length",
                          build_complete_input))
    peers = {peer["id"]: index for index, peer in enumerate(sdk["peers"])}
    targets.append(Target(SDK, f"peers[{peers['csharp']}].lock.native_generated_sha256", "B",
                          f"peers[{peers['csharp']}].lock.native_generated_byte_length", build_csharp_native))
    for peer, keys, tool in (
        ("typescript", ("expected_online_closure_sha256", "expected_offline_closure_sha256"),
         "`npm ls --all --json | jq -S .dependencies` over an npm-installed tree"),
        ("python", ("expected_online_closure_filename_sha256", "expected_offline_closure_filename_sha256",
                    "expected_online_closure_content_sha256", "expected_offline_closure_content_sha256"),
         "the downloaded wheel basenames and wheel hashes (the requirements lock names no wheel file)"),
        ("go", ("expected_online_closure_sha256", "expected_offline_closure_sha256"),
         "the go module listing produced by the reproduction_script over a downloaded module cache"),
    ):
        for key in keys:
            targets.append(unattempted(SDK, f"peers[{peers[peer]}].lock.{key}", "A", ABSENT_TOOL_OUTPUT.format(tool)))
    targets += [
        Target(SER, "advisory_snapshot.audit_output_sha256", "B", "advisory_snapshot.audit_output_bytes",
               ser_string_builder("advisory_snapshot", "audit_output_json")),
        Target(SER, "consumer_probe.manifest_sha256", "B", "consumer_probe.manifest_bytes",
               ser_string_builder("consumer_probe", "manifest")),
        Target(SER, "consumer_probe.source_sha256", "B", "consumer_probe.source_bytes",
               ser_string_builder("consumer_probe", "source")),
        Target(SER, "consumer_probe.dev_graph.sha256", "B", "consumer_probe.dev_graph.bytes",
               ser_string_builder("consumer_probe.dev_graph", "canonical_output")),
        Target(SER, "consumer_probe.lock_package_projection_sha256", "A", "consumer_probe.lock_package_projection_bytes",
               build_lock_projection),
        Target(SER, "phase_a_input_contract.baseline_sha256", "A", None, build_phase_a_baseline),
    ]
    for index, row in enumerate(ser["phase_a_input_contract"]["immutable_input"]):
        if row["kind"] in EMBEDDED:
            targets.append(Target(SER, f"phase_a_input_contract.immutable_input[{index}].content_sha256", "B", None,
                                  immutable_input_builder(index)))
    for index in range(len(ser["target_graph"])):
        for key in ("normal_build_sha256", "feature_sha256"):
            targets.append(unattempted(SER, f"target_graph[{index}].{key}", "A", ABSENT_TOOL_OUTPUT.format(
                "`cargo tree` output over the registry archives (gate consumer_target_graph_bytes_checked_in = "
                "false; reproduction.target_graph_prerequisites: not reproducible from the lock bytes alone)")))
    targets.append(Target(TA, "executable_same_validator_contract.admitted_vendor_family_digest_sha256", "A", None,
                          build_vendor_family))
    for digest_location, bytes_location, literal_location in fixture_literal_locations(ta):
        targets.append(Target(TA, digest_location, "B", bytes_location, literal_builder(TA, literal_location)))
    for index in range(len(ta["apps"]["standard_reuse"])):
        targets.append(Target(TA, f"apps.standard_reuse[{index}].canonical_closure_sha256", "A", None, closure_builder(index)))
    targets.append(Target(TA, "apps.sdk_1_29_0.standard_reuse_closure.canonical_global_sha256", "A",
                          "apps.sdk_1_29_0.standard_reuse_closure.canonical_global_byte_length", build_closure_global))
    targets.append(Target(TA, "apps.projection.standard_reuse_closure_sha256", "A", None, build_closure_global))
    return targets


# Exclusions: (file suffix, normalised-location regex, category, reason). Normalised locations
# replace every [n] with []. Each rule was written from READING the table, not from the key name.
EXCLUSIONS = [
    ("jose-ring.toml", r"ring\.cached_archive_sha256", "EXT", "crates.io archive (registry_archive_url) is not committed"),
    ("candidate-0.3.10.toml", r"archive\.(sha256|registry_checksum)", "EXT", "crates.io archive is not committed"),
    ("candidate-0.3.10.toml", r"source_files\[\]\.sha256", "EXT", "files inside the uncommitted crates.io archive"),
    ("rs256/rfc[0-9]+-[a-z0-9-]+\\.toml", r"(modulus|exponent|signing_input|signature|compact_jws)_sha256", "IMPLIED",
     "in-file b64u literal; its byte rule is implied only by key naming (no declared encoding; compact_jws construction unstated)"),
    ("core-conformance.toml", r"license_provenance\.[a-z0-9_]+\.sha256", "EXT", "remote LICENSE body; no vendored path"),
    ("core-conformance.toml", r"artifacts\[\]\.sha256", "FILE", "sha256 of the committed vendored_path file"),
    ("auth-standards.toml", r"artifacts\[\]\.sha256", "EXT", "storage = remote-pinned-identity-only; no body committed"),
    ("toolchain-asupersync.toml", r"toolchain\.(manifest_sha256|manifest_update_hash_value)", "EXT", "remote channel manifest"),
    ("toolchain-asupersync.toml", r"toolchain\.rustup\.installers\[\]\.(sha256|locally_observed_binary_sha256)", "EXT",
     "rustup-init binaries are not committed"),
    ("toolchain-asupersync.toml", r"asupersync\.(registry_checksum|archive_sha256)", "EXT", "crates.io archive is not committed"),
    ("media-dependencies.toml", r"plan_sha256", "FILE", "sha256 of the committed plan file as bound at record time"),
    ("media-dependencies.toml", r"toolchain\.target_authority_sha256", "FILE", "sha256 of a committed evidence file"),
    ("media-dependencies.toml", r"source_provenance_evidence\.[a-z0-9]+_index_sha256", "EXT", "sparse-index bodies are not committed"),
    ("media-dependencies.toml", r"owned_artifacts\.sha256\[\]", "FILE", "sha256 of committed owned artifact paths"),
    ("media-dependencies.toml", r"crate\[\]\.[a-z_]+_sha256", "EXT", "direct_root_archive_bytes_checked_in = false"),
    ("media-dependencies.toml", r"transitive_source_audit\[\]\.archive_sha256", "FILE", "sha256 of the committed .crate"),
    ("media-dependencies.toml", r"transitive_source_audit\[\]\.(cargo_toml|cargo_toml_orig|license|license_apache|license_mit)_sha256",
     "MEMBER", "sha256 of a member file inside a committed .crate (no construction prose)"),
    ("media-dependencies.toml", r"vectors\.(graph|security)_sha256", "FILE", "sha256 of a committed vector manifest"),
    ("media-dependencies.toml", r"graph_package_inventory\.reserved_artifact_audit_hashes\.[a-z0-9_]+", "EXT",
     "reserved transitive archives that are not among the three committed .crate files"),
    ("media-dependencies.toml", r"unsafe_ffi_panic_inventory\[\]\.source_hash", "EXT",
     "repeats archive checksums; no construction declared"),
    ("media-dependencies.toml", r"offline_fixtures\.[a-z_]+_sha256", "FILE", "sha256 of committed fixture files"),
    ("sdk-matrix.toml", r"catalog\.sha256", "FILE", "sha256 of the vendored catalog"),
    ("sdk-matrix.toml", r"catalog\.live_drift_observation\.sha256", "EXT", "live upstream bytes, not committed"),
    ("sdk-matrix.toml", r"peers\[\]\.era_capabilities\[\]\.sha256", "EXT", "remote SDK source files"),
    ("sdk-matrix.toml", r"peers\[\]\.validation_sources\[\]\.sha256", "EXT", "remote SDK source files (vendored = false)"),
    ("sdk-matrix.toml", r"peers\[\]\.registry_artifacts\[\]\.(sha256|raw_nupkg_sha256)", "EXT", "registry artifacts are not committed"),
    ("sdk-matrix.toml",
     r"peers\[\]\.lock\.(consumer_manifest|lock|consumer_project|project_assets_projection|consumer_module|consumer_sum|"
     r"consumer_resolved_module_lock|publisher_module|publisher_sum|publisher_context_projection)_sha256", "FILE",
     "sha256 of a committed sdk-locks file"),
    ("sdk-matrix.toml",
     r"peers\[\]\.lock\.(offline_lock_sha256_before|offline_lock_sha256_after|expected_online_resolved_module_lock_sha256|"
     r"expected_offline_resolved_module_lock_sha256)", "FILE", "repeats the sha256 of a committed sdk-locks file"),
    ("sdk-matrix.toml", r"peers\[\]\.lock\.canonical_json_sha256", "UNDECLARED", "no canonical-JSON rule is stated anywhere"),
    ("sdk-matrix.toml", r"peers\[\]\.lock\.resolver_sdk_archive_sha256", "EXT", "dotnet SDK archive is not committed"),
    ("sdk-matrix.toml", r"peers\[\]\.lock\.last_execution\.checked_in_[a-z_0-9]+", "FILE", "repeats a committed lock's sha256"),
    ("sdk-matrix.toml", r"peers\[\]\.lock\.last_execution\.(?!checked_in_)[a-z_0-9]+", "EXT",
     "historical execution output, not committed"),
    ("sdk-matrix.toml", r"peers\[\]\.lock\.last_revalidation\.reproduction_script_sha256", "IMPLIED",
     "the script text is in-file but no byte rule (terminal LF) is declared for this digest"),
    ("sdk-matrix.toml", r"vendored_artifacts\[\]\.sha256", "FILE", "sha256 of a committed sdk-locks file"),
    ("serialization-uri-dependencies.toml", r"advisory_snapshot\.reproduction_output_sha256", "EXT",
     "historical execution output (equal by value to audit_output_sha256)"),
    ("serialization-uri-dependencies.toml", r"advisory_snapshot\.consumer_lock_sha256", "FILE", "sha256 of the committed consumer lock"),
    ("serialization-uri-dependencies.toml", r"crate\[\]\.[a-z_]+_sha256", "EXT", "registry archives and publisher locks are not committed"),
    ("serialization-uri-dependencies.toml", r"consumer_probe\.lock_sha256", "FILE", "sha256 of the committed consumer lock"),
    ("serialization-uri-dependencies.toml", r"consumer_probe\.key_resolved_package\[\]\.checksum_sha256", "EXT", "registry archive checksums"),
    ("serialization-uri-dependencies.toml", r"phase_a_input_contract\.immutable_input\[\]\.content_sha256", "FILE",
     "checked-in-toml-bytes row: sha256 of the committed consumer lock"),
    ("state-capability-dependencies.toml", r"crate\[\]\.[a-z_]+_sha256", "EXT", "archives in a local ~/.cargo cache, not committed"),
    ("state-capability-dependencies.toml", r"probe\.[a-z_]+\.(manifest|source|lock)_sha256", "FILE", "sha256 of committed probe files"),
    ("state-capability-dependencies.toml", r"(build_script|source_finding|xc20p_tcb_path)\[\]\.sha256", "EXT",
     "files inside uncommitted archives"),
    ("state-capability-dependencies.toml", r"current_workspace_gap\.[a-z_]+_sha256", "FILE",
     "workspace manifests/lock as observed 2026-08-03 (historical file bytes)"),
    ("tasks-apps.toml", r"executable_same_validator_contract\.subtree_digest\.[a-z0-9_]+", "UNDECLARED",
     "only observation_domain FND01TASKSAPPSOBSv1 is named; no encoding is declared anywhere in the file"),
    ("tasks-apps.toml", r"executable_same_validator_contract\.planted_mutation\[\]\.replacement", "OTHER",
     "a planted-mutation replacement literal, not a digest claim"),
    ("tasks-apps.toml", r"(tasks\.artifact|tasks\.conformance_artifact|apps\.artifact)\[\]\.sha256", "FILE",
     "sha256 of the committed vendor_path file"),
    ("tasks-apps.toml", r"(tasks\.license_provenance|tasks\.conformance_license_provenance|apps\.license_provenance)\.sha256", "EXT",
     "remote LICENSE body"),
    ("tasks-apps.toml", r"(tasks|apps)\.sdk_1_29_0\.sha256", "EXT", "npm tarball is not committed"),
    ("tasks-apps.toml", r"apps\.product_composition_authority\[\]\.(sha256|tasks_sha256|mrtr_sha256)", "FILE",
     "repeats a vendored artifact's sha256 by artifact-id reference"),
    ("tasks-apps.toml", r"apps\.sdk_1_29_0\.standard_reuse_closure\.schema_source_sha256", "EXT", "types.js inside the uncommitted npm tarball"),
    ("tasks-apps.toml", r"apps\.projection\.sdk_schema_source_sha256", "EXT", "types.js inside the uncommitted npm tarball"),
    ("tasks-apps.toml", r"apps\.whatwg_html_validation\.candidate_sha256", "FILE", "sha256 of the committed candidate_preserved_path"),
    ("tasks-apps.toml", r"apps\.whatwg_html_validation\.candidate_license_sha256", "EXT", "remote LICENSE body"),
    ("dependency-verification.toml", r"closed_child_binding\[\]\.sha256", "FILE", "crate source files as bound at authoring time"),
    ("dependency-verification.toml", r"source_inventory_contract\.source_archive_absence_sha256", "OTHER",
     "all-zero absence sentinel, not a digest of any input"),
    ("dependency-verification.toml", r"package_relocated_source\[\]\.workspace_sha256", "FILE", "sha256 of a committed README"),
    ("dependency-verification.toml", r"sdk_peer_blueprint\[\]\.(online|offline)_closure_sha256", "EXT",
     "copies of historical execution outputs"),
    ("dependency-verification.toml", r"sdk_peer_blueprint\[\]\.checked_lock_sha256", "FILE", "repeats a committed lock's sha256"),
    ("dependency-verification.toml", r"bootstrap_rch_contract\.private_serving_daemon_sha256", "EXT", "rchd binary is not committed"),
    ("dependency-verification.toml", r"negative_family\[\]\.sha256", "UNDECLARED", "no encoding is declared anywhere in the file"),
    ("dependency-verification.toml", r"projection_dependency\[\]\.checksum_sha256", "EXT", "registry checksums"),
    ("dependency-verification.toml", r"source_input\[\]\.sha256", "FILE", "sha256 of a committed source_input path"),
    ("dependency-verification.toml", r"negative_case\[\]\.argument", "OTHER", "a mutation argument literal, not a digest claim"),
]


@dataclass
class BaseField:
    file: str
    location: str
    value: str

    @property
    def normalised(self) -> str:
        return re.sub(r"\[\d+\]", "[]", self.location)


def base_fields(w: World, files: list[str]) -> list[BaseField]:
    found = []

    def walk(file: str, node, location: str):
        if isinstance(node, dict):
            for key, value in node.items():
                walk(file, value, f"{location}.{key}" if location else key)
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(file, value, f"{location}[{index}]")
        elif isinstance(node, str) and HEX64.match(node):
            found.append(BaseField(file, location, node))

    for file in files:
        walk(file, w.doc(file), "")
    return found


def classify(fields: list[BaseField], targets: list[Target]) -> tuple[dict, list, list]:
    """Map every base field to its target or exclusion. Returns (by_key, exclusions, errors)."""
    by_target = {target.key: target for target in targets}
    by_key, exclusions, errors = {}, [], []
    for base in fields:
        key = (base.file, base.location)
        if key in by_target:
            by_key[key] = ("CONSTRUCT", by_target[key])
            continue
        rules = [rule for rule in EXCLUSIONS if re.search(rule[0] + "$", base.file) and re.fullmatch(rule[1], base.normalised)]
        if len(rules) != 1:
            errors.append(f"{base.file} {base.location}: matched {len(rules)} exclusion rules")
            continue
        exclusions.append((base, rules[0][2], rules[0][3]))
    field_keys = {(base.file, base.location) for base in fields}
    for target in targets:
        if target.key not in field_keys:
            errors.append(f"target {target.file} {target.location} names no 64-hex base field")
    return by_key, exclusions, errors


# --------------------------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------------------------


def evaluate(target: Target, w: World) -> Row:
    document = w.doc(target.file)
    declared_digest = lookup(document, target.location)
    declared_bytes = lookup(document, target.bytes_location) if target.bytes_location else None
    row = Row(target, declared_bytes, declared_digest)
    if target.builder is None:
        row.outcome, row.note = "UNATTEMPTED", target.reason
        return row
    try:
        preimage = target.builder(w)
    except Underdetermined as gap:
        row.outcome, row.note = "UNDERDETERMINED", str(gap)
        return row
    except (KeyError, IndexError, TypeError, ValueError, tarfile.TarError, OSError, subprocess.CalledProcessError) as defect:
        row.outcome, row.note = "VOID", f"{type(defect).__name__}: {defect}"
        return row
    row.computed_bytes = len(preimage)
    row.computed_digest = hashlib.sha256(preimage).hexdigest()
    if len(preimage) == 0 or (declared_bytes is not None and len(preimage) != declared_bytes):
        row.outcome = "VOID"
        row.note = "structural control: preimage length differs from the declared byte length"
        if row.computed_digest == declared_digest:
            row.outcome, row.note = "MISMATCH", "digest equal but declared length differs"
        return row
    row.outcome = "MATCH" if row.computed_digest == declared_digest else "MISMATCH"
    return row


def evaluate_all(w: World, targets: list[Target]) -> list[Row]:
    return [evaluate(target, w) for target in targets]


# --------------------------------------------------------------------------------------------
# J5 self-test: near-identical planted negatives on in-memory copies, same invocation
# --------------------------------------------------------------------------------------------


def replace_one_char(text: str, index: int = 0) -> str:
    """Change exactly one ASCII character, keeping the UTF-8 byte length unchanged."""
    original = text[index]
    if not original.isascii():
        raise ValueError("mutation site must be ASCII so the byte length is preserved")
    replacement = "0" if original != "0" else "1"
    return text[:index] + replacement + text[index + 1:]


def flip_digest(digest: str) -> str:
    return ("0" if digest[0] != "0" else "1") + digest[1:]


@dataclass
class Mutation:
    klass: str
    label: str
    target_key: tuple  # (file, location) of the target the mutation aims at
    length_preserving: bool
    apply: Callable[[World], tuple]  # mutates the world in place; returns (before, after)
    expected: str = "MISMATCH"  # pre-registered outcome of the aimed-at target
    dependents: tuple = ()  # other targets whose outcome must move too, each with its reason


def first_isolated_probe_assertion(w: World) -> int:
    """The first TOML assertion on a probe manifest whose selection is a string no other
    assertion on the same source can see (neither selector is a prefix of the other), reached
    by a plain path: an identity component (<key>=<literal>) is excluded, because mutating the
    identity key's own value would unresolve the selector instead of changing the value
    (run 1 of 040d9619 planted against /package/name=sha1_smol/name and failed that way)."""
    rows = w.doc(DV)["semantic_assertion"]

    def parts(selector: str) -> list:
        return selector.split("/")

    for index, row in enumerate(rows):
        if row["observation_mode"] != "canonical_selected_toml" or "/probes/" not in row["source_path"]:
            continue
        if "=" in row["selector"]:
            continue
        if not isinstance(resolve_pointer(w.doc(row["source_path"]), row["selector"]), str):
            continue
        mine = parts(row["selector"])
        clash = any(
            other is not row and other["source_path"] == row["source_path"]
            and (parts(other["selector"])[: len(mine)] == mine or mine[: len(parts(other["selector"]))] == parts(other["selector"]))
            for other in rows
        )
        if not clash:
            return index
    raise ValueError("no isolated probe assertion to plant against")


def mutations(w: World) -> list[Mutation]:
    registry = (DV, "assertion_contract.canonical_sha256")
    probe = first_isolated_probe_assertion(w)
    probe_row = w.doc(DV)["semantic_assertion"][probe]
    swap = next(index for index, row in enumerate(w.doc(DV)["semantic_assertion"]) if "secondary_selector" in row)
    families = w.doc(DV)["source_family"]
    family = next(index for index, row in enumerate(families) if row["file_count"] >= 2)
    family_id = families[family]["id"]
    sv_index = {case["id"]: index for index, case in enumerate(w.doc(SV)["case"])}

    def child_owner(w):
        row = w.mutable_doc(DV)["closed_child_binding"][0]
        before = row["owner_scope"]
        row["owner_scope"] = replace_one_char(before, len(before) - 1)
        return before, row["owner_scope"]

    def child_digest(w):
        table = w.mutable_doc(DV)["closed_child_handoff_contract"]
        before = table["registry_sha256"]
        table["registry_sha256"] = flip_digest(before)
        return before, table["registry_sha256"]

    def child_order(w):
        order = w.mutable_doc(DV)["closed_child_handoff_contract"]["binding_order"]
        before = list(order)
        order[0], order[1] = order[1], order[0]
        return before, list(order)

    def vector_literal(w):
        case = w.mutable_doc(SV)["case"][sv_index["html-minimal-document"]]
        before = case["payload"]
        index = before.index("x")
        case["payload"] = before[:index] + "y" + before[index + 1:]
        return before, case["payload"]

    def vector_digest(w):
        case = w.mutable_doc(SV)["case"][sv_index["png-valid-upstream"]]
        before = case["sha256"]
        case["sha256"] = flip_digest(before)
        return before, case["sha256"]

    def vector_recipe(w):
        case = w.mutable_doc(SV)["case"][sv_index["gif-magic-rejected"]]
        before = case["encoding"]
        case["encoding"] = "utf-8"
        return before, case["encoding"]

    def document_literal(w):
        block = w.mutable_doc(DV)["bootstrap_manifest_contract"]["package_block"]
        before = block[2]
        block[2] = before.replace("0.0.0", "0.0.1")
        return before, block[2]

    def document_digest(w):
        table = w.mutable_doc(DV)["bootstrap_manifest_contract"]
        before = table["canonical_document_sha256"]
        table["canonical_document_sha256"] = flip_digest(before)
        return before, table["canonical_document_sha256"]

    def document_order(w):
        order = w.mutable_doc(DV)["bootstrap_manifest_contract"]["verifier_dependency_order"]
        before = list(order)
        order[0], order[1] = order[1], order[0]
        return before, list(order)

    tree_input = "evidence/fnd-01/probes/asupersync/features-0.4.9.json"

    def tree_file_byte(w):
        before = w.raw(tree_input)
        position = before.index(b"a")
        w.set_raw(tree_input, before[:position] + b"b" + before[position + 1:])
        return before, w.raw(tree_input)

    def tree_digest(w):
        table = w.mutable_doc(DV)["source_tree"]
        before = table["sha256"]
        table["sha256"] = flip_digest(before)
        return before, table["sha256"]

    def tree_rows(w):
        members = [row for row in w.mutable_doc(DV)["source_input"] if row["family"] == family_id]
        before = [row["sha256"] for row in members[:2]]
        members[0]["sha256"], members[1]["sha256"] = members[1]["sha256"], members[0]["sha256"]
        return before, [row["sha256"] for row in members[:2]]

    def obs_value(w):
        source = w.mutable_doc(probe_row["source_path"])
        parent_pointer, leaf = probe_row["selector"].rsplit("/", 1)
        parent = resolve_pointer(source, parent_pointer)
        before = parent[leaf]
        parent[leaf] = replace_one_char(before, 0)
        return before, parent[leaf]

    def obs_digest(w):
        row = w.mutable_doc(DV)["semantic_assertion"][probe]
        before = row["baseline_observation_sha256"]
        row["baseline_observation_sha256"] = flip_digest(before)
        return before, row["baseline_observation_sha256"]

    def obs_order(w):
        row = w.mutable_doc(DV)["semantic_assertion"][swap]
        before = (row["selector"], row["secondary_selector"])
        row["selector"], row["secondary_selector"] = before[1], before[0]
        return before, (row["selector"], row["secondary_selector"])

    child = (DV, "closed_child_handoff_contract.registry_sha256")
    document = (DV, "bootstrap_manifest_contract.canonical_document_sha256")
    tree = (DV, "source_tree.sha256")
    obs = (DV, f"semantic_assertion[{probe}].baseline_observation_sha256")
    swapped = (DV, f"semantic_assertion[{swap}].baseline_observation_sha256")
    registry_reason = "the mutated field is a canonical_fields member of assertion_contract.canonical_sha256"
    return [
        Mutation("A", "(a) one byte of one input row: closed_child_binding[0].owner_scope", child, True, child_owner),
        Mutation("A", "(b) one byte of the declared digest", child, True, child_digest),
        Mutation("A", "(c) one reordering of binding_order", child, True, child_order),
        Mutation("B", "(a) one byte of one literal: html-minimal-document payload", (SV, f"case[{sv_index['html-minimal-document']}].sha256"),
                 True, vector_literal),
        Mutation("B", "(b) one byte of the declared digest: png-valid-upstream", (SV, f"case[{sv_index['png-valid-upstream']}].sha256"),
                 True, vector_digest),
        Mutation("B", "(c) one recipe change: gif-magic-rejected encoding hex -> utf-8 (length-changing, so VOID by J3)",
                 (SV, f"case[{sv_index['gif-magic-rejected']}].sha256"), False, vector_recipe, expected="VOID"),
        Mutation("DOC", "(a) one byte of one literal line: package_block version", document, True, document_literal),
        Mutation("DOC", "(b) one byte of the declared digest", document, True, document_digest),
        Mutation("DOC", "(c) one reordering of verifier_dependency_order", document, True, document_order),
        Mutation("TREE", f"(a) one byte of one input file: {tree_input}", tree, True, tree_file_byte),
        Mutation("TREE", "(b) one byte of the declared digest: source_tree.sha256", tree, True, tree_digest),
        Mutation("TREE", f"(c) one reordering: swap the sha256 of two member rows of source_family {family_id}",
                 (DV, f"source_family[{family}].tree_sha256"), True, tree_rows),
        Mutation("OBS", f"(a) one byte of one selected value: {probe_row['source_path']} {probe_row['selector']}", obs, True, obs_value),
        Mutation("OBS", f"(b) one byte of the declared digest: semantic_assertion[{probe}]", obs, True, obs_digest,
                 dependents=((registry, registry_reason),)),
        Mutation("OBS", f"(c) one reordering of the selector tuple of swap assertion semantic_assertion[{swap}]", swapped, True,
                 obs_order, dependents=((registry, registry_reason),)),
    ]


def self_test(w: World, targets: list[Target], baseline: list[Row]) -> list[str]:
    """Return failure messages; empty means every mutation behaved as pre-registered."""
    failures = []
    base = {row.target.key: row for row in baseline}
    planted = mutations(w)
    for mutation in planted:
        mine = []
        copied = w.clone()
        before, after = mutation.apply(copied)
        if before == after:
            mine.append("the mutation did not change its input")
        rows = {row.target.key: row for row in evaluate_all(copied, targets)}
        aimed, original = rows[mutation.target_key], base[mutation.target_key]
        if aimed.outcome != mutation.expected:
            mine.append(f"aimed-at target is {aimed.outcome}, pre-registered {mutation.expected}")
        if mutation.label.startswith("(b)"):
            if aimed.computed_digest != original.computed_digest:
                mine.append("a declared-digest mutation changed the computed bytes")
        elif aimed.computed_digest == original.computed_digest:
            mine.append("the computed digest did not change")
        if mutation.length_preserving and mutation.label[:3] in ("(a)", "(c)") and aimed.computed_bytes != original.computed_bytes:
            mine.append("meant to preserve the preimage length, but it changed")
        moved = {key for key, row in rows.items() if row.outcome != base[key].outcome}
        expected_moved = {mutation.target_key} | {key for key, _ in mutation.dependents}
        if moved != expected_moved:
            mine.append(f"outcomes moved on {sorted(moved - expected_moved)}; expected but unmoved {sorted(expected_moved - moved)}")
        failures += [f"{mutation.klass} {mutation.label}: {message}" for message in mine]
        dependents = "; dependents " + ", ".join(f"{key[1]} ({why})" for key, why in mutation.dependents) if mutation.dependents else ""
        print(f"selftest {mutation.klass:4s} {'ok' if not mine else 'FAILED':6s} {mutation.label} -> {aimed.outcome}"
              f" (bytes {original.computed_bytes}->{aimed.computed_bytes}){dependents}")
    attempted = {row.target.klass for row in baseline if row.outcome != "UNATTEMPTED"}
    for klass in sorted(attempted):
        mine = [m for m in planted if m.klass == klass]
        if len(mine) < 3:
            failures.append(f"class {klass} was attempted but has {len(mine)} J5 mutations, not 3")
        elif not any(m.length_preserving for m in mine):
            failures.append(f"class {klass} has no length-preserving mutation")
    return failures


# --------------------------------------------------------------------------------------------
# J2: set relations by digest value and by location
# --------------------------------------------------------------------------------------------


def bullet_one_population(w: World) -> tuple[set, int]:
    """FND-01 bullet [1]'s 934: bounded lowercase 64-hex substrings in the TOP-LEVEL TOMLs only."""
    distinct, occurrences = set(), 0
    for path in w.repo.evidence_tomls():
        if path.count("/") != 2:
            continue
        found = BOUNDED_HEX64.findall(w.text(path))
        occurrences += len(found)
        distinct |= set(found)
    return distinct, occurrences


def j2_report(w: World, rows: list[Row], fields: list[BaseField]) -> list[str]:
    lines = []
    population_values = {row.declared_digest for row in rows}
    direct_values = {row.declared_digest for row in rows if row.outcome == "MATCH"}
    base_values = {base.value for base in fields}
    b1, b1_occurrences = bullet_one_population(w)
    top_level = {row.declared_digest for row in rows if row.target.file.count("/") == 2}
    lines.append(f"J1 base set (whole-value 64-hex fields, 19 files): {len(fields)} locations, {len(base_values)} distinct values"
                 "  [the bar author's 1183]")
    lines.append(f"J1 population: {len(rows)} locations, {len(population_values)} distinct values; "
                 f"MATCH covers {len(direct_values)} distinct values")
    lines.append(f"bullet [1] 934: bounded 64-hex substrings of the 10 top-level TOMLs: {len(b1)} distinct / {b1_occurrences} occurrences")
    lines.append(f"  population values IN the 934: {len(population_values & b1)}; NOT in it: {len(population_values - b1)} "
                 f"(of which from subdirectory files: {len(population_values - b1 - top_level)})")
    lines.append(f"  MATCH values IN the 934: {len(direct_values & b1)}; NOT in it: {len(direct_values - b1)}")
    lines.append("  relation: OVERLAP (neither a subset of the other)" if population_values - b1 and b1 - population_values
                 else "  relation: SUBSET" if not population_values - b1 else "  relation: SUPERSET")
    lines.append("1054 (comment 5312): predicate never recorded and NOT reproduced here by bounded substrings (1099/779), quoted "
                 "whole values (980/724) or key = \"hex\" (971/724) over the six files 5312 names; NO relation is claimed against it")
    lines.append("bullet [1]'s 166/934 is NOT moved by this run: a value-level count is reported above, and moving the "
                 "bullet is the bullet owner's call")
    return lines


# --------------------------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--rev", default="HEAD")
    args = parser.parse_args()
    repo = Repo(args.rev)
    w = World(repo)
    files = repo.evidence_tomls()
    print(f"fnd01_prose_digests  rev {repo.rev}  python {platform.python_version()}  "
          f"evidence/fnd-01 tree {git('rev-parse', repo.rev + ':evidence/fnd-01').strip()}")
    print("no cargo, no compiled artifact, no remote lane; inputs read with git cat-file at --rev")
    if len(files) != 19:
        print(f"RED: {len(files)} evidence TOMLs at --rev, expected 19")
        return 1
    targets = build_targets(w)
    fields = base_fields(w, files)
    by_key, exclusions, errors = classify(fields, targets)
    for message in errors:
        print(f"RED population: {message}")
    rows = evaluate_all(w, targets)
    notes = {"agent_frozen_segment", "repository_surface_contract.historical_changelog_suffix_sha256"}
    print("\n== J1 targets (file | location | class | declared bytes/digest | computed bytes/digest | outcome | note) ==")
    for row in rows:
        t = row.target
        note = row.note
        if any(t.location.startswith(prefix) for prefix in notes) and row.outcome != "UNATTEMPTED":
            note = (note + "; " if note else "") + drift_note(w, t)
        print(f"{t.file.removeprefix(ROOT)} | {t.location} | {t.klass} | {row.declared_bytes}/{row.declared_digest[:16]} | "
              f"{row.computed_bytes}/{(row.computed_digest or '')[:16]} | {row.outcome} | {note}")
    print("\n== J1 exclusions: every other base field, by (file, shape, category) ==")
    grouped: dict = {}
    for base, category, reason in exclusions:
        grouped.setdefault((base.file.removeprefix(ROOT), base.normalised, category, reason), []).append(base)
    for (file, shape, category, reason), members in sorted(grouped.items()):
        print(f"{category:10s} {len(members):4d}  {file} | {shape} | {reason}")
    counts: dict = {}
    for _, category, _ in exclusions:
        counts[category] = counts.get(category, 0) + 1
    print("exclusion totals: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
    transitive = 0
    fixture = next(row for row in rows if row.target.location == "fixture_contract.canonical_sha256")
    if fixture.outcome == "MATCH":
        transitive = len(w.doc(DV)["mutation_fixture"])
    print(f"\n== J4 TRANSITIVE (never added to MATCH): {transitive} FND01FIXv1 per-value digests confirmed only through "
          "fixture_contract.canonical_sha256's preimage ==")
    print("\n== J2 ==")
    for line in j2_report(w, rows, fields):
        print(line)
    print("\n== J5 self-test (in-memory copies only; same invocation) ==")
    failures = self_test(w, targets, rows)
    for message in failures:
        print(f"RED selftest: {message}")
    tally = {name: sum(1 for row in rows if row.outcome == name) for name in ("MATCH", "MISMATCH", "UNDERDETERMINED", "VOID", "UNATTEMPTED")}
    total = sum(tally.values())
    by_class: dict = {}
    for row in rows:
        by_class.setdefault(row.target.klass, {}).setdefault(row.outcome, 0)
        by_class[row.target.klass][row.outcome] += 1
    print("\n== per class ==")
    for klass, outcome_counts in sorted(by_class.items()):
        print(f"{klass:4s} " + ", ".join(f"{k} {v}" for k, v in sorted(outcome_counts.items())))
    print("\n== inputs read (path -> blob) ==")
    for path, blob in sorted(repo.blobs_read.items()):
        print(f"{blob} {path}")
    reconciled = total == len(targets) and len(fields) == len(by_key) + len(exclusions)
    print(f"\nTOTALS  MATCH {tally['MATCH']} + MISMATCH {tally['MISMATCH']} + UNDERDETERMINED {tally['UNDERDETERMINED']} + "
          f"VOID {tally['VOID']} + UNATTEMPTED {tally['UNATTEMPTED']} = {total}  |  population {len(targets)}  |  "
          f"base {len(fields)} = targets {len(by_key)} + excluded {len(exclusions)}  |  TRANSITIVE {transitive}")
    exhaustive = tally["UNATTEMPTED"] == 0
    print(f"exhaustive: {'yes' if exhaustive else 'NO -- ' + str(tally['UNATTEMPTED']) + ' UNATTEMPTED (J8)'}")
    red = bool(errors) or not reconciled or bool(failures)
    print("RESULT: " + ("RED" if red else "GREEN (reconciled, exhaustive population screen, self-test passed)"))
    return 1 if red else 0


if __name__ == "__main__":
    sys.exit(main())
