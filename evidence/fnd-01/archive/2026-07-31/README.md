# FND-01 drift-remediation captures, 2026-07-31

Four snapshots of `crates/fastmcp/tests/fnd_01_dependency_evidence.rs`, taken
during a drift remediation of that file on 2026-07-31. Relocated here from
`crates/fastmcp/tests/` on 2026-09-17 under bd-on63m.

```
fnd_01_dependency_evidence.rs.drift-backup-20260731T111338Z      2,627,727 B
fnd_01_dependency_evidence.rs.drift-backup-20260731T111724Z      2,620,202 B
fnd_01_dependency_evidence.rs.drift-backup-20260731T111844Z      2,619,675 B
fnd_01_dependency_evidence.rs.coral-pre-acq-fix-20260731T113732Z 2,621,598 B
```

## Why these are kept rather than deleted

**Their content is not in the commit graph.** The live evidence file has 145
distinct historical blobs across 147 commits, and **none of these four matches any
of them.** They are snapshots of *uncommitted intermediate states* — the only
record of four moments that exist nowhere else.

That is the whole reason they survived a disposition review. The obvious argument
— "a backup inside a repository is already backed up" — is clean and, measured,
false here. Anyone proposing to delete them should first re-run that check and
authorise the deletion of *unique content*, not of duplicates. A permission
granted against a false description is not a permission.

They are also forensic captures of a drift remediation **of the very evidence file
whose drift FND-01 exists to detect**, which is the subsystem most likely to want
them later.

## Why they are not in `crates/`

They do not compile — the extension is `.rs.<suffix>`, so Cargo never sees them as
targets, and they cost nothing at build time. They were not free, though:

- **Grep pollution, measured twice on 2026-09-17.** A known-positive control for a
  single mapped FND-01 test ID returned **5 files where only 1 is a real target**,
  which nearly read as a PL-1 duplicate-ID defect; a separate scan returned 6 hits
  where 2 were real, which would have tripled a reported blast radius. Any
  ID-uniqueness or duplicate-detection sweep over `crates/` was reading 5-of-1.
- **`crates` is a `closed_scan_root`** in `dependency-verification.toml`, whose
  rule makes an unlisted regular file a failure. These were 4 of 168 unlisted
  files there. (Removing them does *not* make that check pass — it is red on the
  other 164 — but it is 4 fewer.)
- **A latent digest risk.** Today every `read_dir` walk in the verifier filters on
  `Path::extension() == "rs"`, and these files' extension is
  `drift-backup-20260731T111338Z`, so they are excluded. That protection depends
  on every future walk keeping an exact-extension test; a switch to
  `contains(".rs")` would silently start ingesting a six-week-old snapshot of an
  evidence file.

`evidence/` is not a `closed_scan_root` and nothing globs it, so the same problems
do not follow them here.

## Integrity

Relocated with `git mv` — a rename, not a delete: content, tracking and history
are all preserved. Verified byte-identical before and after by SHA-256:

```
c9bc31f5dbde3362…  coral-pre-acq-fix-20260731T113732Z
2df2fb117ddc6ca8…  drift-backup-20260731T111338Z
8d4cbebf64a1b263…  drift-backup-20260731T111724Z
12c63314d6352061…  drift-backup-20260731T111844Z
```
