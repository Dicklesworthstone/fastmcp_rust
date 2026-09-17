//! `cargo xtask plan-tracker-check <mode>`.
//!
//! The alias in `.cargo/config.toml` resolves this binary by package, so the
//! command never depends on an ambient `cargo-xtask` executable or on `PATH`.

#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use fastmcp_xtask::plan_tracker::{self, Mode};

fn usage() -> String {
    "usage: cargo xtask plan-tracker-check <all|snapshot>".to_owned()
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

    let Some(mode) = argv.get(2).map(String::as_str).and_then(Mode::parse) else {
        eprintln!("{}", usage());
        return ExitCode::FAILURE;
    };

    let start = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let Some(root) = plan_tracker::find_root(&start) else {
        eprintln!("could not locate {} above {}", plan_tracker::SOURCES_PATH, start.display());
        return ExitCode::FAILURE;
    };

    let run = match plan_tracker::run_all(&root) {
        Ok(run) => run,
        Err(diagnostic) => {
            eprintln!("{}", diagnostic.render());
            return ExitCode::FAILURE;
        }
    };

    match mode {
        Mode::Snapshot => println!("{}", run.manifest.to_canonical_json()),
        Mode::All => {
            for subcase in &run.manifest.subcases {
                println!(
                    "{} {} {:?} diagnostics={}",
                    subcase.id, subcase.name, subcase.outcome, subcase.diagnostic_count
                );
            }
            if !run.report.is_clean() {
                eprintln!("{}", run.report.render());
            }
            println!("manifest_sha256={}", run.manifest.digest());
        }
    }

    if run.passed() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
