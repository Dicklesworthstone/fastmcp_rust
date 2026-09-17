//! `cargo xtask plan-tracker-check <mode>`.
//!
//! The alias in `.cargo/config.toml` resolves this binary by package, so the
//! command never depends on an ambient `cargo-xtask` executable or on PATH.
//!
//! Every mode is read-only. The binary never edits the plan, the tracker, a
//! reservation, the worktree, or Git state; the reservation snapshot is
//! supplied by the execution layer on a path or on stdin, because the checker
//! has no network and no mutation authority.

#![forbid(unsafe_code)]

use std::env;
use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use fastmcp_xtask::plan_tracker::{
    self, Mode,
    b_eval::{self, ReservationInputs},
    reservations,
};

fn usage() -> String {
    "usage: cargo xtask plan-tracker-check <all|snapshot|preclaim <issue-id>|preclose <issue-id>> \
     [--reservations-json <path|->]"
        .to_owned()
}

/// Read the reservation snapshot from a path, or from stdin for `-`.
///
/// One parser serves both routes, so a snapshot cannot mean one thing through
/// a file and another through a pipe.
fn read_snapshot(source: &str) -> Result<String, String> {
    if source == "-" {
        let mut buffer = String::new();
        std::io::stdin()
            .read_to_string(&mut buffer)
            .map_err(|error| format!("stdin: {error}"))?;
        return Ok(buffer);
    }
    std::fs::read_to_string(source).map_err(|error| format!("{source}: {error}"))
}

fn main() -> ExitCode {
    let argv: Vec<String> = env::args().collect();

    let Some(command) = argv.get(1) else {
        eprintln!("{}", usage());
        return ExitCode::FAILURE;
    };
    if command != "plan-tracker-check" {
        eprintln!("unknown command {command:?}\n{}", usage());
        return ExitCode::FAILURE;
    }

    let positional: Vec<&str> = argv[2..]
        .iter()
        .map(String::as_str)
        .take_while(|argument| !argument.starts_with("--"))
        .collect();
    let Some(mode) = positional
        .first()
        .and_then(|word| Mode::parse(word, positional.get(1).copied()))
    else {
        eprintln!("{}", usage());
        return ExitCode::FAILURE;
    };

    let snapshot_source = argv
        .iter()
        .position(|argument| argument == "--reservations-json")
        .and_then(|index| argv.get(index + 1))
        .cloned();

    let start = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let Some(root) = plan_tracker::find_root(&start) else {
        eprintln!(
            "could not locate {} above {}",
            plan_tracker::SOURCES_PATH,
            start.display()
        );
        return ExitCode::FAILURE;
    };

    let mut inputs = ReservationInputs {
        now: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs() as i64)
            .unwrap_or_default(),
        ..ReservationInputs::default()
    };
    if let Some(source) = &snapshot_source {
        let text = match read_snapshot(source) {
            Ok(text) => text,
            Err(message) => {
                eprintln!("{message}");
                return ExitCode::FAILURE;
            }
        };
        match reservations::parse_snapshot(&text, source) {
            Ok(snapshot) => inputs.snapshot = Some(snapshot),
            Err(diagnostic) => {
                eprintln!("{}", diagnostic.render());
                return ExitCode::FAILURE;
            }
        }
    }

    // The A evaluator: trace rows and authoritative sources.
    let a_run = match plan_tracker::run_all(&root) {
        Ok(run) => run,
        Err(diagnostic) => {
            eprintln!("{}", diagnostic.render());
            return ExitCode::FAILURE;
        }
    };

    // The B evaluator: plan corpus, fingerprints, policy, and projection.
    let b_run = match b_eval::run(&root, &inputs) {
        Ok(run) => run,
        Err(diagnostic) => {
            eprintln!("{}", diagnostic.render());
            return ExitCode::FAILURE;
        }
    };

    if mode == Mode::Snapshot {
        println!("{}", a_run.manifest.to_canonical_json());
        println!("{}", b_run.manifest.to_canonical_json());
        return ExitCode::SUCCESS;
    }

    println!("mode={}", mode.name());
    if let Some(issue) = mode.issue_id() {
        println!("issue={issue}");
    }
    for subcase in a_run
        .manifest
        .subcases
        .iter()
        .chain(b_run.manifest.subcases.iter())
    {
        println!(
            "{} {} {:?} diagnostics={}",
            subcase.id, subcase.name, subcase.outcome, subcase.diagnostic_count
        );
    }
    if !a_run.report.is_clean() {
        eprintln!("{}", a_run.report.render());
    }
    if !b_run.report.is_clean() {
        eprintln!("{}", b_run.report.render());
    }
    println!("a_manifest_sha256={}", a_run.manifest.digest());
    println!("b_manifest_sha256={}", b_run.manifest.digest());

    if a_run.passed() && b_run.passed() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
