//! Authoritative sources and their content bindings.
//!
//! A trace row is only worth something if it *detects* drift rather than
//! describing it. Every authoritative input this checker reads is bound by its
//! Git blob identity, and the binding is re-derived from the bytes on every
//! run. Editing a bound file without updating its binding turns the gate red.
//!
//! Blob identity, not commit SHA: `main` is rebased in this repository, so a
//! commit SHA stops resolving while the content it referred to is unchanged.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::diagnostics::{Code, Diagnostic, Report};
use super::digest::git_blob_hex;

/// Counts every side effect the checker could have had.
///
/// Validation is strictly read-only: it must never edit the plan, the Beads
/// database, Agent Mail reservations, the worktree, or Git state. There is no
/// write call site in this crate's check paths, so these counters are
/// structurally zero; they exist so the property is asserted rather than
/// assumed, and so a future write would have to announce itself here.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EffectLedger {
    pub plan_writes: u64,
    pub beads_writes: u64,
    pub reservation_writes: u64,
    pub worktree_writes: u64,
    pub git_index_writes: u64,
    pub process_spawns: u64,
    files_read: u64,
}

impl EffectLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that one file was read. Reads are not effects, but counting
    /// them keeps "the checker did nothing" distinguishable from "the checker
    /// never opened anything".
    pub fn record_read(&mut self) {
        self.files_read = self.files_read.saturating_add(1);
    }

    pub fn files_read(&self) -> u64 {
        self.files_read
    }

    /// The six write/effect counters acceptance requires to be zero.
    pub fn write_counters(&self) -> [u64; 6] {
        [
            self.plan_writes,
            self.beads_writes,
            self.reservation_writes,
            self.worktree_writes,
            self.git_index_writes,
            self.process_spawns,
        ]
    }

    pub fn is_read_only(&self) -> bool {
        self.write_counters().iter().all(|count| *count == 0)
    }
}

/// One authoritative input, bound by content.
#[derive(Debug, Clone, Deserialize)]
pub struct SourceBinding {
    /// Stable identifier a trace row cites.
    pub id: String,
    /// Repository-relative path.
    pub path: String,
    /// `git hash-object -t blob` identity of the exact bytes.
    pub blob_sha1: String,
    /// What this source is authoritative for.
    pub role: String,
}

/// The checked-in authoritative source registry.
#[derive(Debug, Clone, Deserialize)]
pub struct SourceRegistry {
    pub schema: String,
    #[serde(default, rename = "source")]
    pub sources: Vec<SourceBinding>,
}

/// The expected schema tag. A file that does not declare it is rejected rather
/// than parsed leniently.
pub const SOURCE_REGISTRY_SCHEMA: &str = "fnd-02-authoritative-sources-v1";

/// An authoritative source whose bytes have been read and verified.
#[derive(Debug, Clone)]
pub struct ResolvedSource {
    pub id: String,
    pub path: PathBuf,
    pub bytes: Vec<u8>,
    pub observed_blob_sha1: String,
}

impl ResolvedSource {
    /// The file's content as UTF-8, or `None` when it is not valid UTF-8.
    pub fn text(&self) -> Option<&str> {
        std::str::from_utf8(&self.bytes).ok()
    }
}

/// Every authoritative source, resolved and content-verified.
#[derive(Debug, Clone, Default)]
pub struct ResolvedSources {
    entries: Vec<ResolvedSource>,
}

impl ResolvedSources {
    pub fn get(&self, id: &str) -> Option<&ResolvedSource> {
        self.entries.iter().find(|entry| entry.id == id)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn ids(&self) -> Vec<&str> {
        self.entries.iter().map(|entry| entry.id.as_str()).collect()
    }
}

/// Parse the registry file. The schema tag must match exactly.
pub fn parse_registry(text: &str, subject: &str) -> Result<SourceRegistry, Diagnostic> {
    let registry: SourceRegistry = toml::from_str(text).map_err(|error| {
        Diagnostic::new(Code::SchemaInvalid, subject, "toml", error.to_string())
    })?;
    if registry.schema != SOURCE_REGISTRY_SCHEMA {
        return Err(Diagnostic::new(
            Code::SchemaInvalid,
            subject,
            "schema",
            format!(
                "expected {SOURCE_REGISTRY_SCHEMA}, observed {}",
                registry.schema
            ),
        ));
    }
    Ok(registry)
}

/// Read every bound source and verify its Git blob identity against the
/// recorded binding.
///
/// This is the mechanism that catches a binding going stale. It re-derives the
/// identity from the bytes on disk every run; it never trusts the recorded
/// value, and it never rewrites it.
pub fn resolve(
    root: &Path,
    registry: &SourceRegistry,
    ledger: &mut EffectLedger,
) -> (ResolvedSources, Report) {
    let mut report = Report::new();
    let mut entries = Vec::with_capacity(registry.sources.len());

    let mut seen = BTreeSet::new();
    for binding in &registry.sources {
        if !seen.insert(binding.id.as_str()) {
            report.push(Diagnostic::new(
                Code::SchemaInvalid,
                &binding.id,
                "id",
                "duplicate authoritative source id",
            ));
            continue;
        }

        let path = root.join(&binding.path);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) => {
                report.push(Diagnostic::new(
                    Code::SourceUnreadable,
                    &binding.id,
                    "path",
                    format!("{}: {error}", binding.path),
                ));
                continue;
            }
        };
        ledger.record_read();

        let observed = git_blob_hex(&bytes);
        if observed != binding.blob_sha1 {
            report.push(Diagnostic::new(
                Code::SourceBlobDrift,
                &binding.id,
                "blob_sha1",
                format!(
                    "{} recorded={} observed={}",
                    binding.path, binding.blob_sha1, observed
                ),
            ));
            continue;
        }

        entries.push(ResolvedSource {
            id: binding.id.clone(),
            path,
            bytes,
            observed_blob_sha1: observed,
        });
    }

    (ResolvedSources { entries }, report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_ledger_is_read_only() {
        let ledger = EffectLedger::new();
        assert!(ledger.is_read_only());
        assert_eq!(ledger.write_counters(), [0; 6]);
    }

    #[test]
    fn a_ledger_with_any_write_is_not_read_only() {
        // The predicate must be able to fail, or asserting it proves nothing.
        for index in 0..6 {
            let mut ledger = EffectLedger::new();
            match index {
                0 => ledger.plan_writes = 1,
                1 => ledger.beads_writes = 1,
                2 => ledger.reservation_writes = 1,
                3 => ledger.worktree_writes = 1,
                4 => ledger.git_index_writes = 1,
                _ => ledger.process_spawns = 1,
            }
            assert!(!ledger.is_read_only(), "counter {index} must be observed");
        }
    }

    #[test]
    fn registry_rejects_a_wrong_schema_tag() {
        let text = "schema = \"fnd-02-authoritative-sources-v0\"\n";
        let error = parse_registry(text, "s").expect_err("wrong schema must be rejected");
        assert_eq!(error.code, Code::SchemaInvalid);
        assert_eq!(error.field, "schema");
    }

    #[test]
    fn registry_accepts_the_exact_schema_tag() {
        let text = format!("schema = \"{SOURCE_REGISTRY_SCHEMA}\"\n");
        let registry = parse_registry(&text, "s").expect("exact schema must parse");
        assert!(registry.sources.is_empty());
    }
}
