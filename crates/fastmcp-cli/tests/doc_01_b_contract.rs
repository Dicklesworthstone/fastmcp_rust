//! Public-binary DOC-01-B contract checks.
//!
//! The oracle here is deliberately independent of the private production
//! validator: it observes only the shipped `fastmcp` binary's help streams.

use std::process::{Command, Output};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ModeExpectation {
    PlannedUnverifiedNotExecutable,
    Supported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PublicHelpOracle {
    modern_only: ModeExpectation,
}

const PROVISIONAL_PUBLIC_HELP_ORACLE: PublicHelpOracle = PublicHelpOracle {
    modern_only: ModeExpectation::PlannedUnverifiedNotExecutable,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublicHelpRefusal {
    MissingRequiredClause,
    UnexpectedAffirmativeClaim,
}

fn fastmcp_output(argument: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fastmcp"))
        .arg(argument)
        .output()
        .expect("spawn the shipped fastmcp binary")
}

fn normalized_stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone())
        .expect("public help must be UTF-8")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn evaluate_public_root_help(
    output: &Output,
    oracle: PublicHelpOracle,
) -> Result<(), PublicHelpRefusal> {
    if !output.status.success()
        || !output.stderr.is_empty()
        || output.stdout.len() > 32 * 1024
        || output.stdout.contains(&0x1b)
    {
        return Err(PublicHelpRefusal::MissingRequiredClause);
    }

    let stdout = normalized_stdout(output);
    let required_clauses = [
        "FastMCP CLI - Run, inspect, and install MCP servers.",
        "Protocol status: MCP 2026-07-28 support is under implementation and unverified.",
        "Public PROTOCOL_VERSION remains 2024-11-05;",
        "ModernOnly, Auto, and LegacyOnly are planned/unverified policy modes, not executable CLI profiles.",
        "MCP 2025-11-25 is unsupported: it has no alias, compatibility profile, route, or diagnostic selection.",
        "Help, inspect output, and examples are not conformance, runtime-readiness, maturity, or release evidence.",
        "Machine-readable diagnostics are separate from human-facing examples, redact secrets and peer-controlled terminal text, and preserve nonzero failures rather than fabricating an empty catalog or selection.",
    ];
    if required_clauses
        .iter()
        .any(|clause| !stdout.contains(clause))
    {
        return Err(PublicHelpRefusal::MissingRequiredClause);
    }

    let forbidden_claims = [
        "MCP 2026-07-28 is supported",
        "Auto is available",
        "LegacyOnly is production ready",
        "MCP 2025-11-25 has an alias",
        "aggregate MCP support",
        "MCP conformance",
        "release ready",
        "Bearer ",
        "token=",
    ];
    if forbidden_claims.iter().any(|claim| stdout.contains(claim)) {
        return Err(PublicHelpRefusal::UnexpectedAffirmativeClaim);
    }

    match oracle.modern_only {
        ModeExpectation::PlannedUnverifiedNotExecutable => {
            if stdout.contains("ModernOnly is supported") || stdout.contains("ModernOnly is runnable") {
                return Err(PublicHelpRefusal::UnexpectedAffirmativeClaim);
            }
        }
        ModeExpectation::Supported => {
            if !stdout.contains("ModernOnly is supported") {
                return Err(PublicHelpRefusal::MissingRequiredClause);
            }
        }
    }

    Ok(())
}

#[test]
fn doc_01_b_public_binary_positive() {
    let long_help = fastmcp_output("--help");
    let short_help = fastmcp_output("-h");
    assert_eq!(
        evaluate_public_root_help(&long_help, PROVISIONAL_PUBLIC_HELP_ORACLE),
        Ok(())
    );
    assert_eq!(
        evaluate_public_root_help(&short_help, PROVISIONAL_PUBLIC_HELP_ORACLE),
        Ok(())
    );
    assert_eq!(normalized_stdout(&long_help), normalized_stdout(&short_help));

    let subcommand_help = Command::new(env!("CARGO_BIN_EXE_fastmcp"))
        .args(["run", "--help"])
        .output()
        .expect("spawn the shipped fastmcp subcommand help");
    assert!(subcommand_help.status.success());
    assert!(subcommand_help.stderr.is_empty());
    let subcommand_stdout = normalized_stdout(&subcommand_help);
    assert!(subcommand_stdout.contains("Run an MCP server binary."));
    assert!(!subcommand_stdout.contains("Protocol status: MCP 2026-07-28"));
}

#[test]
fn doc_01_b_public_binary_planted_negative() {
    let long_help = fastmcp_output("--help");
    let short_help = fastmcp_output("-h");
    let long_help_before = long_help.stdout.clone();
    let short_help_before = short_help.stdout.clone();

    let mut planted_oracle = PROVISIONAL_PUBLIC_HELP_ORACLE;
    planted_oracle.modern_only = ModeExpectation::Supported;
    assert_eq!(
        evaluate_public_root_help(&long_help, planted_oracle),
        Err(PublicHelpRefusal::MissingRequiredClause)
    );
    assert_eq!(
        long_help.stdout, long_help_before,
        "one-field oracle mutation must not alter long-help output"
    );
    assert_eq!(
        short_help.stdout, short_help_before,
        "one-field oracle mutation must not alter short-help output"
    );
    assert_eq!(
        evaluate_public_root_help(&short_help, PROVISIONAL_PUBLIC_HELP_ORACLE),
        Ok(())
    );
}
