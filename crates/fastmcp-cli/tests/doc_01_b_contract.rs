//! Public-binary DOC-01-B contract checks.
//!
//! The oracle here is deliberately independent of the private production
//! validator: it observes only the shipped `fastmcp` binary's help streams.

use std::process::{Command, Output};

/// This oracle is deliberately authored in the public-binary target instead
/// of importing production validation code. It models each support assertion
/// independently, so a one-field mutation has a stable, specific refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PublicHelpOracle {
    protocol_2026_under_implementation: bool,
    public_protocol_version: &'static str,
    modern_only_executable: bool,
    auto_executable: bool,
    legacy_only_executable: bool,
    mcp_2025_unsupported: bool,
    aggregate_claims_are_evidence: bool,
}

const PROVISIONAL_PUBLIC_HELP_ORACLE: PublicHelpOracle = PublicHelpOracle {
    protocol_2026_under_implementation: true,
    public_protocol_version: "2024-11-05",
    modern_only_executable: true,
    auto_executable: cfg!(feature = "legacy-2024-11-05"),
    legacy_only_executable: cfg!(feature = "legacy-2024-11-05"),
    mcp_2025_unsupported: true,
    aggregate_claims_are_evidence: false,
};

#[cfg(feature = "legacy-2024-11-05")]
const PROVISIONAL_PUBLIC_STATUS_STANZA: &str = concat!(
    "Protocol status: MCP 2026-07-28 support is under implementation and unverified. ",
    "Public PROTOCOL_VERSION remains 2024-11-05; Auto, ModernOnly, and LegacyOnly are ",
    "executable CLI protocol-policy selections. Inspect configures the shipped client; run and ",
    "dev pass the selected policy to launched FastMCP ServerBuilder targets, while arbitrary ",
    "children may ignore it. This does not prove server support, aggregate conformance, or release readiness. MCP 2025-11-25 is ",
    "unsupported: it has no alias, compatibility profile, route, or diagnostic selection. ",
    "Help, inspect output, and examples are not conformance, runtime-readiness, maturity, ",
    "or release evidence. Machine-readable diagnostics are separate from human-facing ",
    "examples, redact secrets and peer-controlled terminal text, and preserve nonzero ",
    "failures rather than fabricating an empty catalog or selection."
);

#[cfg(not(feature = "legacy-2024-11-05"))]
const PROVISIONAL_PUBLIC_STATUS_STANZA: &str = concat!(
    "Protocol status: MCP 2026-07-28 support is under implementation and unverified. ",
    "This --no-default-features build executes ModernOnly only. Auto and LegacyOnly remain ",
    "parseable only to report that legacy-2024-11-05 is unavailable before contact. MCP ",
    "2025-11-25 is unsupported: it has no alias, compatibility profile, route, or diagnostic ",
    "selection. Help, inspect output, and examples are not conformance, runtime-readiness, ",
    "maturity, or release evidence. Machine-readable diagnostics are separate from human-facing ",
    "examples, redact secrets and peer-controlled terminal text, and preserve nonzero failures ",
    "rather than fabricating an empty catalog or selection."
);

/// Independently authored normalized frame for the public binary. It freezes
/// every non-whitespace byte; wrapping is the only renderer variance allowed.
#[cfg(not(feature = "tasks"))]
const PROVISIONAL_PUBLIC_ROOT_HELP_PREFIX: &str = concat!(
    "CLI tooling for FastMCP - run, inspect, and install MCP servers ",
    "Usage: fastmcp <COMMAND> ",
    "Commands: ",
    "run Run an MCP server binary ",
    "inspect Inspect an MCP server's capabilities ",
    "install Install server configuration into Claude Desktop or other clients ",
    "list List configured MCP servers ",
    "test Test MCP server connectivity ",
    "dev Run server in development mode with hot reloading ",
    "help Print this message or the help of the given subcommand(s) ",
    "Options: -h, --help Print help -V, --version Print version "
);

#[cfg(feature = "tasks")]
const PROVISIONAL_PUBLIC_ROOT_HELP_PREFIX: &str = concat!(
    "CLI tooling for FastMCP - run, inspect, and install MCP servers ",
    "Usage: fastmcp <COMMAND> ",
    "Commands: ",
    "run Run an MCP server binary ",
    "inspect Inspect an MCP server's capabilities ",
    "tasks Get, watch, update, or cancel an official MCP task ",
    "install Install server configuration into Claude Desktop or other clients ",
    "list List configured MCP servers ",
    "test Test MCP server connectivity ",
    "dev Run server in development mode with hot reloading ",
    "help Print this message or the help of the given subcommand(s) ",
    "Options: -h, --help Print help -V, --version Print version "
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublicHelpRefusal {
    InvalidOutputEnvelope,
    ProtocolStatusIsNotProvisional,
    UnexpectedPublicProtocolVersion,
    ModernOnlyIsNotExecutable,
    AutoAvailabilityMismatch,
    LegacyOnlyAvailabilityMismatch,
    Mcp2025IsNotUnsupported,
    AggregateClaimTreatedAsEvidence,
    MissingBaseFrame,
    MissingStatusStanza,
    AlteredStatusStanza,
    RootHelpFrameMismatch,
    UnsafeRootHelpContent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PublicHelpCandidate {
    oracle: PublicHelpOracle,
    stdout: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct AcceptedPublicHelp {
    candidate: Option<PublicHelpCandidate>,
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

fn validate_public_help_oracle(oracle: PublicHelpOracle) -> Result<(), PublicHelpRefusal> {
    if !oracle.protocol_2026_under_implementation {
        return Err(PublicHelpRefusal::ProtocolStatusIsNotProvisional);
    }
    if oracle.public_protocol_version != "2024-11-05" {
        return Err(PublicHelpRefusal::UnexpectedPublicProtocolVersion);
    }
    if !oracle.modern_only_executable {
        return Err(PublicHelpRefusal::ModernOnlyIsNotExecutable);
    }
    if oracle.auto_executable != cfg!(feature = "legacy-2024-11-05") {
        return Err(PublicHelpRefusal::AutoAvailabilityMismatch);
    }
    if oracle.legacy_only_executable != cfg!(feature = "legacy-2024-11-05") {
        return Err(PublicHelpRefusal::LegacyOnlyAvailabilityMismatch);
    }
    if !oracle.mcp_2025_unsupported {
        return Err(PublicHelpRefusal::Mcp2025IsNotUnsupported);
    }
    if oracle.aggregate_claims_are_evidence {
        return Err(PublicHelpRefusal::AggregateClaimTreatedAsEvidence);
    }

    Ok(())
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
        return Err(PublicHelpRefusal::InvalidOutputEnvelope);
    }
    validate_public_help_oracle(oracle)?;

    validate_public_root_help_bytes(&output.stdout)
}

fn validate_public_root_help_bytes(bytes: &[u8]) -> Result<(), PublicHelpRefusal> {
    let stdout = String::from_utf8_lossy(bytes)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let Some(status_start) = stdout.find("Protocol status:") else {
        return Err(PublicHelpRefusal::MissingStatusStanza);
    };
    let (root_help, status_stanza) = stdout.split_at(status_start);
    if !root_help.contains("CLI tooling for FastMCP - run, inspect, and install MCP servers") {
        return Err(PublicHelpRefusal::MissingBaseFrame);
    }
    if status_stanza != PROVISIONAL_PUBLIC_STATUS_STANZA {
        return Err(PublicHelpRefusal::AlteredStatusStanza);
    }

    if ["Bearer ", "token=", "\u{1b}"]
        .iter()
        .any(|term| root_help.contains(term))
    {
        return Err(PublicHelpRefusal::UnsafeRootHelpContent);
    }
    if root_help != PROVISIONAL_PUBLIC_ROOT_HELP_PREFIX {
        return Err(PublicHelpRefusal::RootHelpFrameMismatch);
    }

    Ok(())
}

fn raw_help_with_root_claim(bytes: &[u8], claim: &str) -> Vec<u8> {
    let marker = b"Protocol status:";
    let status_start = bytes
        .windows(marker.len())
        .position(|window| window == marker)
        .expect("public root help must contain its status stanza");
    let mut forged = Vec::with_capacity(bytes.len() + claim.len() + 1);
    forged.extend_from_slice(&bytes[..status_start]);
    forged.extend_from_slice(claim.as_bytes());
    forged.push(b' ');
    forged.extend_from_slice(&bytes[status_start..]);
    forged
}

fn raw_help_with_toggled_help_option_period(bytes: &[u8]) -> Vec<u8> {
    let normalized = String::from_utf8_lossy(bytes)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let expected = "-h, --help Print help -V, --version Print version";
    let toggled = "-h, --help Print help. -V, --version Print version";
    assert!(
        normalized.contains(expected),
        "approved root-help frame must contain the unpunctuated generated help option"
    );
    normalized.replacen(expected, toggled, 1).into_bytes()
}

fn raw_help_with_windows_executable_suffix(bytes: &[u8]) -> Vec<u8> {
    let normalized = String::from_utf8_lossy(bytes)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let expected = "Usage: fastmcp <COMMAND>";
    let toggled = "Usage: fastmcp.exe <COMMAND>";
    assert!(
        normalized.contains(expected),
        "approved root-help frame must contain the platform-neutral binary name"
    );
    normalized.replacen(expected, toggled, 1).into_bytes()
}

fn raw_help_with_toggled_tasks_command(bytes: &[u8]) -> Vec<u8> {
    let normalized = String::from_utf8_lossy(bytes)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let tasks_command = "tasks Get, watch, update, or cancel an official MCP task ";
    if cfg!(feature = "tasks") {
        assert!(normalized.contains(tasks_command));
        normalized.replacen(tasks_command, "", 1).into_bytes()
    } else {
        assert!(!normalized.contains(tasks_command));
        let following_command = "install Install server configuration";
        assert!(normalized.contains(following_command));
        normalized
            .replacen(
                following_command,
                &format!("{tasks_command}{following_command}"),
                1,
            )
            .into_bytes()
    }
}

fn admit_public_root_help(
    state: &mut AcceptedPublicHelp,
    candidate: PublicHelpCandidate,
) -> Result<(), PublicHelpRefusal> {
    validate_public_help_oracle(candidate.oracle)?;
    validate_public_root_help_bytes(&candidate.stdout)?;
    state.candidate = Some(candidate);
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
    assert_eq!(
        normalized_stdout(&long_help),
        normalized_stdout(&short_help)
    );
    assert_eq!(
        normalized_stdout(&long_help),
        format!("{PROVISIONAL_PUBLIC_ROOT_HELP_PREFIX}{PROVISIONAL_PUBLIC_STATUS_STANZA}")
    );
    #[cfg(not(feature = "tasks"))]
    {
        assert!(
            !normalized_stdout(&long_help)
                .contains("tasks Get, watch, update, or cancel an official MCP task ")
        );
        let task_id = format!(
            "doc-01-b-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("runtime-selected task ID clock")
                .as_nanos()
        );
        let tasks_output = Command::new(env!("CARGO_BIN_EXE_fastmcp"))
            .args(["tasks", "get", task_id.as_str()])
            .output()
            .expect("spawn the shipped Tasks-disabled binary");
        assert!(!tasks_output.status.success());
        assert!(tasks_output.stdout.is_empty());
        assert_eq!(
            tasks_output.stderr,
            b"FeatureUnavailable: Tasks commands require fastmcp-cli built with --features tasks\n"
        );
    }
    let mut long_state = AcceptedPublicHelp::default();
    assert_eq!(
        admit_public_root_help(
            &mut long_state,
            PublicHelpCandidate {
                oracle: PROVISIONAL_PUBLIC_HELP_ORACLE,
                stdout: long_help.stdout.clone(),
            },
        ),
        Ok(())
    );
    assert_eq!(
        long_state
            .candidate
            .as_ref()
            .expect("accepted public help must retain emitted bytes")
            .stdout
            .as_slice(),
        long_help.stdout.as_slice()
    );

    let subcommand_help = Command::new(env!("CARGO_BIN_EXE_fastmcp"))
        .args(["run", "--help"])
        .output()
        .expect("spawn the shipped fastmcp subcommand help");
    assert!(subcommand_help.status.success());
    assert_eq!(subcommand_help.stderr, b"");
    let subcommand_stdout = normalized_stdout(&subcommand_help);
    assert!(subcommand_stdout.contains("Run an MCP server binary."));
    assert!(!subcommand_stdout.contains("Protocol status: MCP 2026-07-28"));
}

#[test]
fn doc_01_b_public_binary_planted_negative() {
    let long_help = fastmcp_output("--help");
    assert_eq!(
        evaluate_public_root_help(&long_help, PROVISIONAL_PUBLIC_HELP_ORACLE),
        Ok(())
    );
    let baseline = PublicHelpCandidate {
        oracle: PROVISIONAL_PUBLIC_HELP_ORACLE,
        stdout: long_help.stdout.clone(),
    };
    let mut state = AcceptedPublicHelp::default();
    admit_public_root_help(&mut state, baseline.clone())
        .expect("baseline public help must satisfy the independent oracle");
    let accepted_before = state.clone();

    for (oracle, refusal) in [
        (
            PublicHelpOracle {
                auto_executable: !baseline.oracle.auto_executable,
                ..baseline.oracle
            },
            PublicHelpRefusal::AutoAvailabilityMismatch,
        ),
        (
            PublicHelpOracle {
                legacy_only_executable: !baseline.oracle.legacy_only_executable,
                ..baseline.oracle
            },
            PublicHelpRefusal::LegacyOnlyAvailabilityMismatch,
        ),
    ] {
        let availability_mutation = PublicHelpCandidate {
            oracle,
            stdout: baseline.stdout.clone(),
        };
        assert_eq!(
            admit_public_root_help(&mut state, availability_mutation),
            Err(refusal),
            "an opposite-profile availability assertion must be rejected"
        );
        assert_eq!(
            state, accepted_before,
            "a rejected availability mutation must preserve the accepted oracle and bytes"
        );
    }

    let tasks_command_mutation = PublicHelpCandidate {
        oracle: baseline.oracle,
        stdout: raw_help_with_toggled_tasks_command(&baseline.stdout),
    };
    assert_eq!(
        admit_public_root_help(&mut state, tasks_command_mutation),
        Err(PublicHelpRefusal::RootHelpFrameMismatch),
        "Tasks command presence must match the compiled feature profile"
    );
    assert_eq!(
        state, accepted_before,
        "a rejected Tasks command mutation must preserve the accepted oracle and bytes"
    );

    let planted_candidate = PublicHelpCandidate {
        oracle: baseline.oracle,
        stdout: raw_help_with_root_claim(&baseline.stdout, "FastMCP supports MCP 2026-07-28."),
    };
    assert_eq!(
        admit_public_root_help(&mut state, planted_candidate),
        Err(PublicHelpRefusal::RootHelpFrameMismatch),
        "the one-field raw-help mutation must be rejected"
    );
    assert_eq!(
        state, accepted_before,
        "a rejected one-field raw-help mutation must not alter accepted evaluator/output state"
    );

    let punctuation_mutation = PublicHelpCandidate {
        oracle: baseline.oracle,
        stdout: raw_help_with_toggled_help_option_period(&baseline.stdout),
    };
    assert_eq!(
        admit_public_root_help(&mut state, punctuation_mutation),
        Err(PublicHelpRefusal::RootHelpFrameMismatch),
        "a one-field terminal-punctuation mutation must be rejected"
    );
    assert_eq!(
        state, accepted_before,
        "a rejected punctuation mutation must not alter accepted evaluator/output state"
    );

    let windows_suffix_mutation = PublicHelpCandidate {
        oracle: baseline.oracle,
        stdout: raw_help_with_windows_executable_suffix(&baseline.stdout),
    };
    assert_eq!(
        admit_public_root_help(&mut state, windows_suffix_mutation),
        Err(PublicHelpRefusal::RootHelpFrameMismatch),
        "the one-field executable-suffix mutation must be rejected"
    );
    assert_eq!(
        state, accepted_before,
        "a rejected executable-suffix mutation must not alter accepted evaluator/output state"
    );
    let long_help_after_rejection = fastmcp_output("--help");
    assert_eq!(
        long_help_after_rejection.status, long_help.status,
        "a rejected oracle mutation must not alter the real binary's exit status"
    );
    assert_eq!(
        long_help_after_rejection.stderr.as_slice(),
        long_help.stderr.as_slice(),
        "a rejected oracle mutation must not alter the real binary's stderr"
    );
    assert_eq!(
        long_help_after_rejection.stdout.as_slice(),
        accepted_before
            .candidate
            .as_ref()
            .expect("baseline accepted state must retain public bytes")
            .stdout
            .as_slice(),
        "a rejected oracle mutation must not alter the real binary's consumer-visible output"
    );
}
