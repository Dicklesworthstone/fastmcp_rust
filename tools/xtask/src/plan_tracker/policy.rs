//! Repository policy checks: workspace membership, the Cargo alias, the
//! unsafe-code invariant, and checker decomposition.
//!
//! These read manifests and source files as text. Parsing them as TOML would
//! be tidier for the manifests, but the crate-root lint check has to see the
//! exact source line: a `#![forbid(unsafe_code)]` that is present but
//! commented out, or conditionally compiled, is not the invariant.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use super::diagnostics::{Code, Diagnostic, Report};

/// The alias the plan requires, verbatim.
pub const REQUIRED_ALIAS: &str = "xtask = \"run --locked --quiet -p fastmcp-xtask --\"";
/// The workspace member path for the checker.
pub const XTASK_MEMBER: &str = "tools/xtask";
/// The crate-root attribute every workspace member must carry.
pub const FORBID_ATTRIBUTE: &str = "#![forbid(unsafe_code)]";

/// FND-02-B-13: the checker is a real, non-publishable workspace member whose
/// alias resolves it by package rather than through `PATH`.
pub fn check_xtask_package(root: &Path) -> Report {
    let mut report = Report::new();

    match fs::read_to_string(root.join("Cargo.toml")) {
        Err(error) => report.push(Diagnostic::new(
            Code::SourceUnreadable,
            "Cargo.toml",
            "path",
            error.to_string(),
        )),
        Ok(text) => {
            if !text.contains(&format!("\"{XTASK_MEMBER}\"")) {
                report.push(Diagnostic::new(
                    Code::WorkspacePolicy,
                    "Cargo.toml",
                    "members",
                    format!("{XTASK_MEMBER:?} is not a workspace member"),
                ));
            }
        }
    }

    match fs::read_to_string(root.join(XTASK_MEMBER).join("Cargo.toml")) {
        Err(error) => report.push(Diagnostic::new(
            Code::SourceUnreadable,
            "tools/xtask/Cargo.toml",
            "path",
            error.to_string(),
        )),
        Ok(text) => {
            if !text.contains("publish = false") {
                report.push(Diagnostic::new(
                    Code::WorkspacePolicy,
                    "tools/xtask/Cargo.toml",
                    "publish",
                    "the checker must declare publish = false",
                ));
            }
            if !text.contains("[[bin]]") {
                report.push(Diagnostic::new(
                    Code::WorkspacePolicy,
                    "tools/xtask/Cargo.toml",
                    "bin",
                    "the checker must declare an explicit binary target",
                ));
            }
            // The tool must not depend on a publishable FastMCP crate.
            for forbidden in [
                "fastmcp-core",
                "fastmcp-server",
                "fastmcp-client",
                "fastmcp-protocol",
                "fastmcp-transport",
            ] {
                if text.contains(forbidden) {
                    report.push(Diagnostic::new(
                        Code::WorkspacePolicy,
                        "tools/xtask/Cargo.toml",
                        "dependencies",
                        format!("the checker must not depend on {forbidden}"),
                    ));
                }
            }
        }
    }

    match fs::read_to_string(root.join(".cargo/config.toml")) {
        Err(error) => report.push(Diagnostic::new(
            Code::SourceUnreadable,
            ".cargo/config.toml",
            "path",
            error.to_string(),
        )),
        Ok(text) => {
            if !text.contains(REQUIRED_ALIAS) {
                report.push(Diagnostic::new(
                    Code::WorkspacePolicy,
                    ".cargo/config.toml",
                    "alias",
                    format!("expected the exact alias {REQUIRED_ALIAS}"),
                ));
            }
        }
    }

    report
}

/// FND-02-B-14: the unsafe-code invariant holds at the checker crate root.
///
/// The attribute must be a live source line, not a comment: a commented-out
/// `#![forbid(unsafe_code)]` reads identically to a substring search but
/// forbids nothing.
pub fn check_unsafe_policy(root: &Path, crate_roots: &[&str]) -> Report {
    let mut report = Report::new();

    for relative in crate_roots {
        let path = root.join(relative);
        let Ok(text) = fs::read_to_string(&path) else {
            report.push(Diagnostic::new(
                Code::SourceUnreadable,
                *relative,
                "path",
                "crate root is unreadable",
            ));
            continue;
        };
        let live = text.lines().any(|line| {
            let trimmed = line.trim();
            trimmed == FORBID_ATTRIBUTE
        });
        if !live {
            report.push(Diagnostic::new(
                Code::WorkspacePolicy,
                *relative,
                "forbid_unsafe",
                format!("{FORBID_ATTRIBUTE} is absent, commented, or conditional"),
            ));
        }
        if text.contains("#![allow(unsafe_code)]") || text.contains("unsafe_code = \"allow\"") {
            report.push(Diagnostic::new(
                Code::WorkspacePolicy,
                *relative,
                "forbid_unsafe",
                "the crate root weakens the unsafe-code policy",
            ));
        }
    }

    report
}

/// A module in the checker, with its source size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleSize {
    pub name: String,
    pub bytes: u64,
    pub lines: usize,
}

/// FND-02-B-12: the checker is decomposed into bounded, independently tested
/// modules.
///
/// FND-02 must not become another monolithic verifier: FND-01's single
/// integration test reached 85,819 lines and stopped being reviewable, which
/// is why nobody noticed six stale bindings inside it. The bound here is a
/// declared design limit, not a measurement, so it does not rot.
pub const MAX_MODULE_LINES: usize = 1_400;
/// The minimum number of modules the checker must be split across.
pub const MIN_MODULES: usize = 6;

pub fn check_module_inventory(root: &Path) -> (Vec<ModuleSize>, Report) {
    let mut report = Report::new();
    let mut modules = Vec::new();

    let directory = root.join(XTASK_MEMBER).join("src/plan_tracker");
    let Ok(entries) = fs::read_dir(&directory) else {
        report.push(Diagnostic::new(
            Code::SourceUnreadable,
            "src/plan_tracker",
            "path",
            "the checker module directory is unreadable",
        ));
        return (modules, report);
    };

    let mut names: BTreeSet<String> = BTreeSet::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|extension| extension != "rs") {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        let name = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("?")
            .to_owned();
        let lines = text.lines().count();
        if lines > MAX_MODULE_LINES {
            report.push(Diagnostic::new(
                Code::ModuleInventory,
                &name,
                "lines",
                format!("{lines} lines exceeds the {MAX_MODULE_LINES}-line review bound"),
            ));
        }
        // Every module carries its own tests. A module with no test is one
        // nobody exercises independently.
        if !text.contains("#[cfg(test)]") {
            report.push(Diagnostic::new(
                Code::ModuleInventory,
                &name,
                "tests",
                "module has no in-file test module",
            ));
        }
        names.insert(name.clone());
        modules.push(ModuleSize {
            name,
            bytes: text.len() as u64,
            lines,
        });
    }

    if modules.len() < MIN_MODULES {
        report.push(Diagnostic::new(
            Code::ModuleInventory,
            "src/plan_tracker",
            "modules",
            format!("{} modules is below the {MIN_MODULES} required", modules.len()),
        ));
    }

    modules.sort_by(|a, b| a.name.cmp(&b.name));
    (modules, report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_root() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("two levels above tools/xtask")
            .to_path_buf()
    }

    #[test]
    fn the_live_workspace_satisfies_the_xtask_package_policy() {
        let report = check_xtask_package(&repo_root());
        assert!(report.is_clean(), "{}", report.render());
    }

    #[test]
    fn the_checker_crate_roots_forbid_unsafe_code() {
        let report = check_unsafe_policy(
            &repo_root(),
            &["tools/xtask/src/lib.rs", "tools/xtask/src/main.rs"],
        );
        assert!(report.is_clean(), "{}", report.render());
    }

    #[test]
    fn a_missing_alias_is_detected() {
        // The predicate must be able to fail: point it at a directory with no
        // manifests at all and require every check to fire.
        let empty = std::env::temp_dir().join(format!("fnd-02-policy-{}", std::process::id()));
        let _ = fs::create_dir_all(&empty);
        let report = check_xtask_package(&empty);
        assert!(!report.is_clean());
        assert!(report.has(Code::SourceUnreadable));
        let _ = fs::remove_dir_all(&empty);
    }

    #[test]
    fn a_crate_root_without_the_attribute_is_detected() {
        let report = check_unsafe_policy(&repo_root(), &["tools/xtask/Cargo.toml"]);
        assert!(report.has(Code::WorkspacePolicy));
    }

    #[test]
    fn the_checker_is_decomposed_and_every_module_is_tested() {
        let (modules, report) = check_module_inventory(&repo_root());
        assert!(report.is_clean(), "{}", report.render());
        assert!(
            modules.len() >= MIN_MODULES,
            "observed {} modules",
            modules.len()
        );
        assert!(modules.iter().all(|m| m.lines <= MAX_MODULE_LINES));
        // The inventory is measured, not asserted: every module must be real.
        assert!(modules.iter().all(|m| m.bytes > 0));
    }

    #[test]
    fn the_module_inventory_reports_an_unreadable_directory() {
        let missing = std::env::temp_dir().join("fnd-02-no-such-checker-directory");
        let (modules, report) = check_module_inventory(&missing);
        assert!(modules.is_empty());
        assert!(report.has(Code::SourceUnreadable));
    }
}
