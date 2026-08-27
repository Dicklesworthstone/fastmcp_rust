//! FastMCP CLI - Command-line tooling for MCP servers.
//!
//! Commands:
//! - `run` - Run an MCP server
//! - `inspect` - Inspect a server's capabilities
//! - `install` - Install server config for Claude Desktop etc.
//! - `test` - Exercise a local server with per-request idle/absolute timeouts
//!
//! MCP 2026-07-28 support is under implementation and remains unverified. The
//! CLI builds with default features include the exact `2024-11-05` adapter;
//! `--no-default-features` is ModernOnly. Inspect output and examples are not
//! aggregate conformance or release evidence.
//!
//! # Role in the System
//!
//! `fastmcp-cli` is the **operator tooling layer** for FastMCP. It wraps the
//! client and transport crates to provide day-to-day workflows:
//! - Running local servers with stdio transport
//! - Inspecting tools/resources/prompts for debugging
//! - Installing client configs for Claude Desktop, Cursor, and Cline
//! - Diagnosing legacy custom task RPCs (not MCP 2026 task support)

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet};
use std::env;
#[cfg(test)]
use std::ffi::OsStr;
use std::fs::{File, Metadata, Permissions};
#[cfg(target_os = "linux")]
use std::io::Seek as _;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use asupersync::Cx;
use asupersync::runtime::reactor::create_reactor;
use asupersync::runtime::{Runtime, RuntimeBuilder};
use clap::{Parser, Subcommand};
use serde::de::DeserializeOwned;
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize, Serializer};

#[cfg(target_os = "linux")]
use fastmcp_client::linux_process_group_has_live_member;
use fastmcp_client::{
    CanonicalHttpUrl, Client, ClientBuilder, ClientProtocolPlan, ListPageLimits,
    claude_desktop_config_path,
};
use fastmcp_console::console::{is_credential_key, redact_free_text_credentials_with};
use fastmcp_core::McpResult;
use fastmcp_protocol::protocol_policy::{ProtocolEra, ProtocolPolicy, ProtocolVersion};

const MAX_TEST_IDLE_TIMEOUT_SECS: u64 = 5 * 60;
const MAX_TEST_ABSOLUTE_TIMEOUT_SECS: u64 = 15 * 60;
const CLIENT_CLEANUP_UNVERIFIED_DATA_KEY: &str = "fastmcpCleanupUnverified";
const CLIENT_CLEANUP_DURATION_MS_DATA_KEY: &str = "cleanupDurationMs";
const FASTMCP_PROTOCOL_POLICY_ENV: &str = "FASTMCP_PROTOCOL_POLICY";
const LEGACY_PROTOCOL_POLICY_FEATURE: &str = "legacy-2024-11-05";
const LEGACY_PROTOCOL_POLICY_ENABLED: bool = cfg!(feature = "legacy-2024-11-05");
#[cfg(feature = "legacy-2024-11-05")]
const CLI_PROTOCOL_STATUS_HELP: &str = concat!(
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
const CLI_PROTOCOL_STATUS_HELP: &str = concat!(
    "Protocol status: MCP 2026-07-28 support is under implementation and unverified. ",
    "This --no-default-features build executes ModernOnly only. Auto and LegacyOnly remain ",
    "parseable only to report that legacy-2024-11-05 is unavailable before contact. MCP ",
    "2025-11-25 is unsupported: it has no alias, compatibility profile, route, or diagnostic ",
    "selection. Help, inspect output, and examples are not conformance, runtime-readiness, ",
    "maturity, or release evidence. Machine-readable diagnostics are separate from human-facing ",
    "examples, redact secrets and peer-controlled terminal text, and preserve nonzero failures ",
    "rather than fabricating an empty catalog or selection."
);
/// Independently authored consumer contract for the normalized rendered
/// status stanza. This is intentionally not derived from `after_help`: a
/// change to producer text must fail admission until this contract is reviewed.
#[cfg(feature = "legacy-2024-11-05")]
const EXPECTED_CLI_PROTOCOL_STATUS_STANZA: &str = concat!(
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
const EXPECTED_CLI_PROTOCOL_STATUS_STANZA: &str = CLI_PROTOCOL_STATUS_HELP;
/// Independently authored normalized root-help frame. It freezes every
/// non-whitespace byte from the Clap construction below; normalization permits
/// line wrapping only, not punctuation or wording variance.
const EXPECTED_CLI_ROOT_HELP_PREFIX: &str = concat!(
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

/// Typed refusal emitted when the public Clap help pipeline cannot produce an
/// exactly provisional documentation contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CliDocumentationRefusal {
    ExpectedDisplayHelp,
    ProtocolStatusIsNotProvisional,
    UnexpectedPublicProtocolVersion,
    ModernOnlyAvailabilityMismatch,
    AutoAvailabilityMismatch,
    LegacyOnlyAvailabilityMismatch,
    Mcp2025IsNotUnsupported,
    AggregateClaimTreatedAsEvidence,
    MissingStatusStanza,
    StatusStanzaMismatch,
    RootHelpFrameMismatch,
    UnsafeRootHelpContent,
    NoAcceptedHelp,
    HelpEmissionFailed,
}

impl CliDocumentationRefusal {
    const fn diagnostic(self) -> &'static str {
        match self {
            Self::ExpectedDisplayHelp => "DOC-01 CLI help request must reach Clap DisplayHelp",
            Self::ProtocolStatusIsNotProvisional => {
                "DOC-01 CLI contract must keep MCP 2026-07-28 provisional"
            }
            Self::UnexpectedPublicProtocolVersion => {
                "DOC-01 CLI contract has an unexpected public protocol version"
            }
            Self::ModernOnlyAvailabilityMismatch => {
                "DOC-01 CLI contract has an invalid ModernOnly availability declaration"
            }
            Self::AutoAvailabilityMismatch => {
                "DOC-01 CLI contract has an invalid Auto availability declaration"
            }
            Self::LegacyOnlyAvailabilityMismatch => {
                "DOC-01 CLI contract has an invalid LegacyOnly availability declaration"
            }
            Self::Mcp2025IsNotUnsupported => {
                "DOC-01 CLI contract must keep MCP 2025-11-25 unsupported"
            }
            Self::AggregateClaimTreatedAsEvidence => {
                "DOC-01 CLI contract must not treat aggregate claims as evidence"
            }
            Self::MissingStatusStanza => {
                "DOC-01 CLI help is missing its provisional protocol-status stanza"
            }
            Self::StatusStanzaMismatch => {
                "DOC-01 CLI help has an altered provisional protocol-status stanza"
            }
            Self::RootHelpFrameMismatch => {
                "DOC-01 CLI help has an unexpected root documentation frame"
            }
            Self::UnsafeRootHelpContent => {
                "DOC-01 CLI help contains unsafe credential or terminal content"
            }
            Self::NoAcceptedHelp => "DOC-01 CLI cannot emit help before a public frame is accepted",
            Self::HelpEmissionFailed => "DOC-01 CLI help emission failed",
        }
    }
}

/// This independently authored semantic contract is validator input; it is
/// never derived from Clap help bytes. Each executable flag is explicit so a
/// one-field mutation receives a distinct typed refusal in shipped code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CliDocumentationContract {
    protocol_2026_under_implementation: bool,
    public_protocol_version: &'static str,
    modern_only_executable: bool,
    auto_executable: bool,
    legacy_only_executable: bool,
    mcp_2025_unsupported: bool,
    aggregate_claims_are_evidence: bool,
}

const CLI_DOCUMENTATION_CONTRACT: CliDocumentationContract = CliDocumentationContract {
    protocol_2026_under_implementation: true,
    public_protocol_version: "2024-11-05",
    modern_only_executable: true,
    auto_executable: LEGACY_PROTOCOL_POLICY_ENABLED,
    legacy_only_executable: LEGACY_PROTOCOL_POLICY_ENABLED,
    mcp_2025_unsupported: true,
    aggregate_claims_are_evidence: false,
};

#[derive(Clone, Debug, PartialEq, Eq)]
struct CliHelpCandidate {
    contract: CliDocumentationContract,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ConsumerVisibleCliHelp {
    accepted: Option<CliHelpCandidate>,
}

/// CLI tooling for FastMCP - run, inspect, and install MCP servers.
#[derive(Parser)]
#[command(name = "fastmcp")]
#[command(version, about, long_about = None)]
#[command(after_help = CLI_PROTOCOL_STATUS_HELP)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Collapse wrapping-only whitespace so the contract is independent of a
/// terminal's width while preserving every non-whitespace byte sequence.
fn normalize_cli_help_whitespace(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn validate_cli_documentation_contract(
    contract: CliDocumentationContract,
) -> Result<(), CliDocumentationRefusal> {
    if !contract.protocol_2026_under_implementation {
        return Err(CliDocumentationRefusal::ProtocolStatusIsNotProvisional);
    }
    if contract.public_protocol_version != "2024-11-05" {
        return Err(CliDocumentationRefusal::UnexpectedPublicProtocolVersion);
    }
    if !contract.modern_only_executable {
        return Err(CliDocumentationRefusal::ModernOnlyAvailabilityMismatch);
    }
    if contract.auto_executable != LEGACY_PROTOCOL_POLICY_ENABLED {
        return Err(CliDocumentationRefusal::AutoAvailabilityMismatch);
    }
    if contract.legacy_only_executable != LEGACY_PROTOCOL_POLICY_ENABLED {
        return Err(CliDocumentationRefusal::LegacyOnlyAvailabilityMismatch);
    }
    if !contract.mcp_2025_unsupported {
        return Err(CliDocumentationRefusal::Mcp2025IsNotUnsupported);
    }
    if contract.aggregate_claims_are_evidence {
        return Err(CliDocumentationRefusal::AggregateClaimTreatedAsEvidence);
    }

    Ok(())
}

/// Validate the rendered public help against the independent semantic contract.
/// Whitespace normalization makes wrapping width an output-only concern. The
/// complete status stanza must be the final normalized root-help section, so
/// appending or altering any support claim fails instead of slipping past a
/// substring blacklist.
fn validate_public_cli_help(candidate: &CliHelpCandidate) -> Result<(), CliDocumentationRefusal> {
    validate_cli_documentation_contract(candidate.contract)?;

    let rendered = normalize_cli_help_whitespace(&candidate.bytes);
    let Some(status_start) = rendered.find("Protocol status:") else {
        return Err(CliDocumentationRefusal::MissingStatusStanza);
    };
    let (root_help, status_stanza) = rendered.split_at(status_start);
    if status_stanza != EXPECTED_CLI_PROTOCOL_STATUS_STANZA {
        return Err(CliDocumentationRefusal::StatusStanzaMismatch);
    }

    if ["Bearer ", "token=", "\u{1b}"]
        .iter()
        .any(|term| root_help.contains(term))
    {
        return Err(CliDocumentationRefusal::UnsafeRootHelpContent);
    }
    if root_help != EXPECTED_CLI_ROOT_HELP_PREFIX {
        return Err(CliDocumentationRefusal::RootHelpFrameMismatch);
    }

    Ok(())
}

fn display_help_bytes(error: clap::Error) -> Result<Vec<u8>, CliDocumentationRefusal> {
    if error.kind() != clap::error::ErrorKind::DisplayHelp {
        return Err(CliDocumentationRefusal::ExpectedDisplayHelp);
    }
    Ok(error.to_string().into_bytes())
}

/// Invoke the same `--help` parse path a CLI consumer receives. Clap returns
/// the public help frame as `DisplayHelp` rather than parsing a command.
#[cfg(test)]
fn public_cli_help_candidate() -> Result<CliHelpCandidate, CliDocumentationRefusal> {
    match Cli::try_parse_from(["fastmcp", "--help"]) {
        Ok(_) => Err(CliDocumentationRefusal::ExpectedDisplayHelp),
        Err(error) => Ok(CliHelpCandidate {
            contract: CLI_DOCUMENTATION_CONTRACT,
            bytes: display_help_bytes(error)?,
        }),
    }
}

/// Commit a consumer-visible help frame only after its full public contract
/// validates. Rejected candidate bytes leave the previously accepted state
/// untouched.
fn admit_public_cli_help(
    state: &mut ConsumerVisibleCliHelp,
    candidate: CliHelpCandidate,
) -> Result<(), CliDocumentationRefusal> {
    validate_public_cli_help(&candidate)?;
    state.accepted = Some(candidate);
    Ok(())
}

fn admit_display_help(
    state: &mut ConsumerVisibleCliHelp,
    error: clap::Error,
) -> Result<(), CliDocumentationRefusal> {
    admit_public_cli_help(
        state,
        CliHelpCandidate {
            contract: CLI_DOCUMENTATION_CONTRACT,
            bytes: display_help_bytes(error)?,
        },
    )
}

/// Emit precisely the previously admitted public bytes. The caller never
/// re-renders help after admission, so the emitted frame is the validated one.
fn emit_admitted_cli_help_to<W: Write>(
    state: &ConsumerVisibleCliHelp,
    writer: &mut W,
) -> Result<(), CliDocumentationRefusal> {
    let accepted = state
        .accepted
        .as_ref()
        .ok_or(CliDocumentationRefusal::NoAcceptedHelp)?;
    writer
        .write_all(&accepted.bytes)
        .and_then(|()| writer.flush())
        .map_err(|_| CliDocumentationRefusal::HelpEmissionFailed)
}

fn emit_admitted_cli_help(state: &ConsumerVisibleCliHelp) -> Result<(), CliDocumentationRefusal> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    emit_admitted_cli_help_to(state, &mut stdout)
}

/// DOC-01 owns only the exact root help request. Every subcommand, nested, or
/// generated help path remains Clap's ordinary `DisplayHelp` behavior.
fn is_exact_root_help_request(args: &[std::ffi::OsString]) -> bool {
    matches!(
        args,
        [_, flag]
            if flag.as_os_str() == std::ffi::OsStr::new("--help")
                || flag.as_os_str() == std::ffi::OsStr::new("-h")
    )
}

#[cfg(test)]
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

#[cfg(test)]
fn raw_help_with_toggled_help_option_period(bytes: &[u8]) -> Vec<u8> {
    let normalized = normalize_cli_help_whitespace(bytes);
    let expected = "-h, --help Print help -V, --version Print version";
    let toggled = "-h, --help Print help. -V, --version Print version";
    assert!(
        normalized.contains(expected),
        "approved root-help frame must contain the unpunctuated generated help option"
    );
    normalized.replacen(expected, toggled, 1).into_bytes()
}

#[test]
fn doc_01_b_positive() {
    let independently_authored_contract = CliDocumentationContract {
        protocol_2026_under_implementation: true,
        public_protocol_version: "2024-11-05",
        modern_only_executable: true,
        auto_executable: LEGACY_PROTOCOL_POLICY_ENABLED,
        legacy_only_executable: LEGACY_PROTOCOL_POLICY_ENABLED,
        mcp_2025_unsupported: true,
        aggregate_claims_are_evidence: false,
    };
    assert_eq!(
        validate_cli_documentation_contract(independently_authored_contract),
        Ok(())
    );
    assert!(is_exact_root_help_request(
        &["fastmcp", "--help"]
            .iter()
            .map(std::ffi::OsString::from)
            .collect::<Vec<_>>()
    ));
    assert!(is_exact_root_help_request(
        &["fastmcp", "-h"]
            .iter()
            .map(std::ffi::OsString::from)
            .collect::<Vec<_>>()
    ));

    let public_help = public_cli_help_candidate().expect("--help must reach Clap DisplayHelp");
    assert_eq!(
        normalize_cli_help_whitespace(&public_help.bytes),
        format!("{EXPECTED_CLI_ROOT_HELP_PREFIX}{EXPECTED_CLI_PROTOCOL_STATUS_STANZA}")
    );
    let mut state = ConsumerVisibleCliHelp::default();

    assert_eq!(
        admit_public_cli_help(&mut state, public_help.clone()),
        Ok(())
    );
    assert_eq!(state.accepted, Some(public_help));

    let mut emitted = Vec::new();
    assert_eq!(emit_admitted_cli_help_to(&state, &mut emitted), Ok(()));
    assert_eq!(
        emitted.as_slice(),
        state
            .accepted
            .as_ref()
            .expect("admitted state must retain public bytes")
            .bytes
            .as_slice()
    );

    let short_help = match Cli::try_parse_from(["fastmcp", "-h"]) {
        Err(error) => CliHelpCandidate {
            contract: CLI_DOCUMENTATION_CONTRACT,
            bytes: display_help_bytes(error).expect("root -h must reach Clap DisplayHelp"),
        },
        Ok(_) => panic!("root -h must not parse a command"),
    };
    let mut short_state = ConsumerVisibleCliHelp::default();
    assert_eq!(admit_public_cli_help(&mut short_state, short_help), Ok(()));

    for args in [
        &["fastmcp", "run", "--help"][..],
        &["fastmcp", "help", "run"][..],
    ] {
        let error = match Cli::try_parse_from(args) {
            Err(error) => error,
            Ok(_) => panic!("subcommand and generated help must remain Clap DisplayHelp"),
        };
        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp);
        let argv = args
            .iter()
            .map(std::ffi::OsString::from)
            .collect::<Vec<_>>();
        assert!(!is_exact_root_help_request(&argv));
    }
}

#[test]
fn doc_01_b_planted_negative() {
    let mut state = ConsumerVisibleCliHelp::default();
    let baseline =
        public_cli_help_candidate().expect("baseline public help must reach Clap DisplayHelp");
    admit_public_cli_help(&mut state, baseline.clone())
        .expect("baseline public help must be admitted");
    let accepted_before = state.clone();

    let planted_candidate = CliHelpCandidate {
        contract: baseline.contract,
        bytes: raw_help_with_root_claim(&baseline.bytes, "FastMCP supports MCP 2026-07-28."),
    };
    assert_eq!(
        admit_public_cli_help(&mut state, planted_candidate),
        Err(CliDocumentationRefusal::RootHelpFrameMismatch),
        "the one-field raw-help mutation must be rejected"
    );
    assert_eq!(
        state, accepted_before,
        "a rejected one-field raw-help mutation must leave evaluator and consumer-visible state unchanged"
    );

    let punctuation_mutation = CliHelpCandidate {
        contract: baseline.contract,
        bytes: raw_help_with_toggled_help_option_period(&baseline.bytes),
    };
    assert_eq!(
        admit_public_cli_help(&mut state, punctuation_mutation),
        Err(CliDocumentationRefusal::RootHelpFrameMismatch),
        "a one-field terminal-punctuation mutation must be rejected"
    );
    assert_eq!(
        state, accepted_before,
        "a rejected punctuation mutation must leave evaluator and consumer-visible state unchanged"
    );
    let mut emitted_after_rejection = Vec::new();
    assert_eq!(
        emit_admitted_cli_help_to(&state, &mut emitted_after_rejection),
        Ok(())
    );
    assert_eq!(
        emitted_after_rejection.as_slice(),
        accepted_before
            .accepted
            .as_ref()
            .expect("baseline accepted state must retain public bytes")
            .bytes
            .as_slice()
    );
}

#[derive(Subcommand)]
enum Commands {
    /// Run an MCP server binary.
    ///
    /// Executes the specified server binary with stdio transport,
    /// passing any additional arguments after --.
    Run {
        /// Path to the server binary or command name.
        server: String,

        /// Arguments to pass to the server (after --).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,

        /// Working directory for the server.
        #[arg(long, short = 'C')]
        cwd: Option<PathBuf>,

        /// Environment variables (KEY=VALUE format).
        #[arg(long, short = 'e')]
        env: Vec<String>,

        /// Protocol-policy selection for the launched server.
        #[arg(long, value_enum, default_value_t = CliProtocolPolicy::default())]
        protocol_policy: CliProtocolPolicy,
    },

    /// Inspect an MCP server's capabilities.
    ///
    /// Connects to the server, lists its tools, resources, and prompts,
    /// then displays them in a formatted output.
    Inspect {
        /// Server command or path. Omit when using explicit HTTP endpoints.
        #[arg(conflicts_with_all = ["http_url", "legacy_sse_url", "legacy_message_url"])]
        server: Option<String>,

        /// Explicit modern Streamable HTTP MCP POST endpoint.
        #[arg(long, value_name = "URL")]
        http_url: Option<String>,

        /// Explicit MCP 2024-11-05 SSE GET endpoint (requires the legacy feature).
        #[arg(long, value_name = "URL")]
        legacy_sse_url: Option<String>,

        /// Explicit MCP 2024-11-05 message POST endpoint (requires the legacy feature).
        #[arg(long, value_name = "URL")]
        legacy_message_url: Option<String>,

        /// Arguments to pass to the server.
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            requires = "server"
        )]
        args: Vec<String>,

        /// Output format (text or FastMCP diagnostic JSON).
        #[arg(long, short = 'f', default_value = "text")]
        format: InspectFormat,

        /// Output file (default: stdout).
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,

        /// Protocol-policy selection for the client connection.
        #[arg(long, value_enum, default_value_t = CliProtocolPolicy::default())]
        protocol_policy: CliProtocolPolicy,
    },

    /// Install server configuration into Claude Desktop or other clients.
    ///
    /// Generates configuration snippets for various MCP clients.
    Install {
        /// Server name for configuration.
        name: String,

        /// Server command or path.
        server: String,

        /// Arguments to pass to the server.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,

        /// Working directory to store in the generated server configuration.
        #[arg(long, short = 'C')]
        cwd: Option<PathBuf>,

        /// Target client (claude, cursor, cline).
        #[arg(long, short = 't', default_value = "claude")]
        target: InstallTarget,

        /// Just print the config, don't modify any files.
        #[arg(long)]
        dry_run: bool,

        /// Protocol-policy selection for the installed FastMCP server.
        #[arg(long, value_enum, default_value_t = CliProtocolPolicy::default())]
        protocol_policy: CliProtocolPolicy,
    },

    /// List configured MCP servers.
    ///
    /// Scans configuration files for known MCP clients (Claude Desktop, Cursor, Cline)
    /// and lists all registered servers.
    List {
        /// Target client to list servers from (claude, cursor, cline).
        /// If not specified, lists from all detected clients.
        #[arg(long, short = 't')]
        target: Option<InstallTarget>,

        /// Path to a custom configuration file.
        #[arg(long, short = 'c')]
        config: Option<PathBuf>,

        /// Output format (table, json, yaml).
        #[arg(long, short = 'f', default_value = "table")]
        format: ListFormat,

        /// Show redacted argument shapes and environment variable names.
        #[arg(long, short = 'v')]
        verbose: bool,
    },

    /// Test MCP server connectivity.
    ///
    /// Spawns the server and tests initialization, capability listing, ping,
    /// and verified subprocess cleanup. This command is currently Unix-only:
    /// other platforms fail before spawning because no Job Object equivalent
    /// is implemented yet.
    Test {
        /// Server command or path.
        server: String,

        /// Arguments to pass to the server.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,

        /// Protocol-policy selection for both client negotiation and server launch.
        #[arg(long, value_enum, default_value_t = CliProtocolPolicy::default())]
        protocol_policy: CliProtocolPolicy,

        /// Per-request idle timeout in seconds (1-300).
        ///
        /// Starts when initialization or a later MCP request is committed.
        /// The current connectivity probes do not attach progress tokens, so
        /// peer traffic does not reset their idle timers. It does not bound
        /// the whole CLI or subprocess lifetime.
        #[arg(
            long,
            default_value_t = 30,
            value_parser = clap::value_parser!(u64).range(1..=MAX_TEST_IDLE_TIMEOUT_SECS)
        )]
        idle_timeout: u64,

        /// Non-resettable per-request absolute timeout in seconds (1-900).
        ///
        /// Starts when initialization or a later MCP request is committed. It
        /// does not bound the whole CLI or subprocess lifetime. On Unix child
        /// stdio, the request timers bound silent and partial-frame reads;
        /// blocking child-stdin writes cannot be preempted by these timers.
        #[arg(
            long,
            default_value_t = 120,
            value_parser = clap::value_parser!(u64).range(1..=MAX_TEST_ABSOLUTE_TIMEOUT_SECS)
        )]
        absolute_timeout: u64,

        /// Show detailed output.
        #[arg(long, short = 'v')]
        verbose: bool,

        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Run server in development mode with hot reloading.
    ///
    /// Watches source files and automatically rebuilds and restarts the server on changes.
    /// Server transport and network configuration remain the target's responsibility.
    Dev {
        /// Executable command/path or Cargo project directory.
        target: String,

        /// Directory to watch for changes (can specify multiple).
        #[arg(long = "reload-dir", default_value = "src")]
        reload_dirs: Vec<PathBuf>,

        /// File patterns to watch (glob syntax).
        #[arg(long = "reload-pattern", default_value = "**/*.rs")]
        reload_patterns: Vec<String>,

        /// Disable auto-reload (just run the server).
        #[arg(long)]
        no_reload: bool,

        /// Debounce time in milliseconds.
        #[arg(long, default_value = "100")]
        debounce: u64,

        /// Clear terminal on restart.
        #[arg(long)]
        clear: bool,

        /// Environment variables (KEY=VALUE format).
        #[arg(long, short = 'e')]
        env: Vec<String>,

        /// Protocol-policy selection for the launched server.
        #[arg(long, value_enum, default_value_t = CliProtocolPolicy::default())]
        protocol_policy: CliProtocolPolicy,

        /// Show detailed output.
        #[arg(long, short = 'v')]
        verbose: bool,
    },
}

impl Commands {
    const fn protocol_policy(&self) -> Option<CliProtocolPolicy> {
        match self {
            Self::Run {
                protocol_policy, ..
            }
            | Self::Inspect {
                protocol_policy, ..
            }
            | Self::Install {
                protocol_policy, ..
            }
            | Self::Test {
                protocol_policy, ..
            }
            | Self::Dev {
                protocol_policy, ..
            } => Some(*protocol_policy),
            Self::List { .. } => None,
        }
    }
}

/// Explicit protocol-policy input. The legacy spellings remain parseable in a
/// ModernOnly build so the CLI can issue an actionable pre-contact refusal.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum CliProtocolPolicy {
    /// Probe modern support and fall back only for an admitted legacy refusal.
    Auto,
    /// Require the current modern protocol path.
    ModernOnly,
    /// Require the exact 2024-11-05 legacy protocol path.
    LegacyOnly,
}

impl Default for CliProtocolPolicy {
    fn default() -> Self {
        if LEGACY_PROTOCOL_POLICY_ENABLED {
            Self::Auto
        } else {
            Self::ModernOnly
        }
    }
}

impl CliProtocolPolicy {
    const fn protocol_policy(self) -> ProtocolPolicy {
        match self {
            Self::Auto => ProtocolPolicy::Auto,
            Self::ModernOnly => ProtocolPolicy::ModernOnly,
            Self::LegacyOnly => ProtocolPolicy::LegacyOnly,
        }
    }

    const fn server_launch_value(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::ModernOnly => "modern-only",
            Self::LegacyOnly => "legacy-only",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CliProtocolPolicyRefusal {
    LegacyFeatureUnavailable { policy: CliProtocolPolicy },
}

impl CliProtocolPolicyRefusal {
    fn diagnostic(self) -> String {
        match self {
            Self::LegacyFeatureUnavailable { policy } => format!(
                "FeatureUnavailable: {} is compiled out; policy {} requires --features {}",
                LEGACY_PROTOCOL_POLICY_FEATURE,
                policy.server_launch_value(),
                LEGACY_PROTOCOL_POLICY_FEATURE,
            ),
        }
    }
}

fn validate_cli_protocol_policy(policy: CliProtocolPolicy) -> McpResult<()> {
    if LEGACY_PROTOCOL_POLICY_ENABLED || matches!(policy, CliProtocolPolicy::ModernOnly) {
        return Ok(());
    }

    let refusal = CliProtocolPolicyRefusal::LegacyFeatureUnavailable { policy };
    Err(fastmcp_core::McpError::invalid_params(refusal.diagnostic()))
}

/// The immutable policy selected by the CLI and the exact protocol revision
/// negotiated by an inspect connection. Both values are emitted together so
/// consumers never have to infer a legacy or modern result from a version
/// string alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InspectProtocolStatus {
    policy: CliProtocolPolicy,
    version: ProtocolVersion,
}

impl InspectProtocolStatus {
    fn new(policy: CliProtocolPolicy, version: &str) -> McpResult<Self> {
        validate_cli_protocol_policy(policy)?;
        let version = ProtocolVersion::parse(version).map_err(|_| {
            fastmcp_core::McpError::internal_error(
                "inspect received an unsupported negotiated protocol version",
            )
        })?;

        if !policy.protocol_policy().permits(version) {
            return Err(fastmcp_core::McpError::internal_error(format!(
                "inspect policy {} does not permit negotiated protocol version {}",
                policy.server_launch_value(),
                version.as_str()
            )));
        }

        Ok(Self { policy, version })
    }

    const fn era_name(self) -> &'static str {
        match self.version.era() {
            ProtocolEra::Modern2026 => "modern-2026",
            #[cfg(feature = "legacy-2024-11-05")]
            ProtocolEra::Legacy2024 => "legacy-2024",
            #[cfg(not(feature = "legacy-2024-11-05"))]
            _ => "legacy-compiled-out",
        }
    }
}

fn client_builder_for_protocol_policy(policy: CliProtocolPolicy) -> McpResult<ClientBuilder> {
    validate_cli_protocol_policy(policy)?;
    Ok(Client::builder().protocol_plan(ClientProtocolPlan::stdio(policy.protocol_policy())))
}

fn apply_protocol_policy_to_server_launch(command: &mut Command, policy: CliProtocolPolicy) {
    command.env(FASTMCP_PROTOCOL_POLICY_ENV, policy.server_launch_value());
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InspectFormat {
    Text,
    Json,
}

impl std::str::FromStr for InspectFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            _ => Err(format!("Unknown format: {s}. Expected: text, json")),
        }
    }
}

/// Output format for the list command.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
enum ListFormat {
    #[default]
    Table,
    Json,
    Yaml,
}

impl std::str::FromStr for ListFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "table" => Ok(Self::Table),
            "json" => Ok(Self::Json),
            "yaml" => Ok(Self::Yaml),
            _ => Err(format!("Unknown format: {s}. Expected: table, json, yaml")),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InstallTarget {
    Claude,
    Cursor,
    Cline,
}

impl std::str::FromStr for InstallTarget {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "claude" => Ok(Self::Claude),
            "cursor" => Ok(Self::Cursor),
            "cline" => Ok(Self::Cline),
            _ => Err(format!(
                "Unknown target: {s}. Expected: claude, cursor, cline"
            )),
        }
    }
}

fn main() -> ExitCode {
    let args = env::args_os().collect::<Vec<_>>();
    let is_exact_root_help = is_exact_root_help_request(&args);
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) if is_exact_root_help && error.kind() == clap::error::ErrorKind::DisplayHelp => {
            let mut admitted = ConsumerVisibleCliHelp::default();
            if let Err(refusal) = admit_display_help(&mut admitted, error)
                .and_then(|()| emit_admitted_cli_help(&admitted))
            {
                eprintln!(
                    "FastMCP CLI documentation contract error: {}",
                    refusal.diagnostic()
                );
                return ExitCode::FAILURE;
            }
            return ExitCode::SUCCESS;
        }
        Err(error) => error.exit(),
    };
    // FND-01: no eager crates.io update checks (CLI-NO-UREQ / CLI-NO-SEMVER).

    let runtime = match build_cli_runtime() {
        Ok(runtime) => runtime,
        Err(error) => {
            write_cli_error(&error);
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(async move {
        let cx = Cx::current().ok_or_else(|| {
            fastmcp_core::McpError::internal_error(
                "FastMCP CLI runtime did not install a cancellation context",
            )
        })?;
        Box::pin(run_cli(&cx, cli)).await
    });

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // `fastmcp run` and `fastmcp dev --no-reload` propagate the child
            // process exit code when the platform reports one.
            // We encode that in `McpError.data.exit_code` so the top-level can
            // return the right `ExitCode` without changing the command handler
            // signatures for the whole CLI.
            if let Some(code) = e
                .data
                .as_ref()
                .and_then(|data| data.get("exit_code"))
                .and_then(serde_json::Value::as_i64)
            {
                if let Ok(code) = u8::try_from(code) {
                    // Avoid duplicating the child's inherited stderr with a
                    // wrapper error line for representable non-zero exits.
                    return ExitCode::from(code);
                }
                write_cli_error(&e);
                return ExitCode::FAILURE;
            }

            write_cli_error(&e);
            ExitCode::FAILURE
        }
    }
}

fn build_cli_runtime() -> McpResult<Runtime> {
    let reactor = create_reactor().map_err(|error| {
        fastmcp_core::McpError::internal_error(format!(
            "Failed to create the FastMCP CLI I/O reactor: {error}"
        ))
    })?;
    RuntimeBuilder::current_thread()
        .with_reactor(reactor)
        .build()
        .map_err(|error| {
            fastmcp_core::McpError::internal_error(format!(
                "Failed to build the FastMCP CLI runtime: {error}"
            ))
        })
}

async fn run_cli(cx: &Cx, cli: Cli) -> McpResult<()> {
    let selected_protocol_policy = cli.command.protocol_policy();
    if let Some(protocol_policy) = selected_protocol_policy {
        validate_cli_protocol_policy(protocol_policy)?;
    }

    match cli.command {
        Commands::Run {
            server,
            args,
            cwd,
            env,
            protocol_policy,
        } => cmd_run(&server, &args, cwd.as_deref(), &env, protocol_policy),
        Commands::Inspect {
            server,
            http_url,
            legacy_sse_url,
            legacy_message_url,
            args,
            format,
            output,
            protocol_policy,
        } => match server.as_deref() {
            Some(server) => {
                cmd_inspect(
                    cx,
                    server,
                    &args,
                    format,
                    output.as_deref(),
                    protocol_policy,
                )
                .await
            }
            None if http_url.is_some()
                || legacy_sse_url.is_some()
                || legacy_message_url.is_some() =>
            {
                Box::pin(cmd_inspect_http(
                    cx,
                    http_url.as_deref(),
                    legacy_sse_url.as_deref(),
                    legacy_message_url.as_deref(),
                    format,
                    output.as_deref(),
                    protocol_policy,
                ))
                .await
            }
            None => Err(fastmcp_core::McpError::invalid_params(
                "inspect requires a server command or explicit HTTP endpoints",
            )),
        },
        Commands::Install {
            name,
            server,
            args,
            cwd,
            target,
            dry_run,
            protocol_policy,
        } => cmd_install(
            &name,
            &server,
            &args,
            cwd.as_deref(),
            target,
            dry_run,
            protocol_policy,
        ),
        Commands::List {
            target,
            config,
            format,
            verbose,
        } => cmd_list(target, config, format, verbose),
        Commands::Test {
            server,
            args,
            protocol_policy,
            idle_timeout,
            absolute_timeout,
            verbose,
            json,
        } => {
            cmd_test(
                cx,
                &server,
                &args,
                protocol_policy,
                idle_timeout,
                absolute_timeout,
                verbose,
                json,
            )
            .await
        }
        Commands::Dev {
            target,
            reload_dirs,
            reload_patterns,
            no_reload,
            debounce,
            clear,
            env,
            protocol_policy,
            verbose,
        } => cmd_dev(DevConfig {
            target,
            reload_dirs,
            reload_patterns,
            no_reload,
            debounce_ms: debounce,
            clear,
            env,
            protocol_policy,
            verbose,
        }),
    }
}

fn write_cli_error(error: &fastmcp_core::McpError) {
    let rendered = sanitize_peer_text(&error.to_string(), PEER_DETAIL_LIMIT);
    write_cli_stderr_line("Error", &rendered);
}

fn write_cli_warning(message: &str) {
    let rendered = sanitize_peer_text(message, PEER_DETAIL_LIMIT);
    write_cli_stderr_line("Warning", &rendered);
}

fn write_cli_stderr_line(label: &str, message: &str) {
    let stderr = io::stderr();
    let mut stderr = stderr.lock();
    let _ = writeln!(stderr, "{label}: {message}");
    let _ = stderr.flush();
}

fn parse_environment_assignments(entries: &[String]) -> McpResult<HashMap<String, String>> {
    entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let (key, value) = entry.split_once('=').ok_or_else(|| {
                fastmcp_core::McpError::invalid_params(format!(
                    "Invalid environment assignment at position {index}; expected KEY=VALUE"
                ))
            })?;
            if key.is_empty() {
                return Err(fastmcp_core::McpError::invalid_params(
                    "Environment variable name cannot be empty",
                ));
            }
            Ok((key.to_owned(), value.to_owned()))
        })
        .collect()
}

fn reject_reserved_protocol_policy_environment(
    env_vars: &HashMap<String, String>,
) -> McpResult<()> {
    if env_vars.contains_key(FASTMCP_PROTOCOL_POLICY_ENV) {
        return Err(fastmcp_core::McpError::invalid_params(format!(
            "{FASTMCP_PROTOCOL_POLICY_ENV} is controlled by --protocol-policy; remove it from --env"
        )));
    }

    Ok(())
}

fn dev_launch_environment(
    mut env_vars: HashMap<String, String>,
    protocol_policy: CliProtocolPolicy,
) -> McpResult<HashMap<String, String>> {
    validate_cli_protocol_policy(protocol_policy)?;
    reject_reserved_protocol_policy_environment(&env_vars)?;
    env_vars.insert(
        FASTMCP_PROTOCOL_POLICY_ENV.to_owned(),
        protocol_policy.server_launch_value().to_owned(),
    );
    Ok(env_vars)
}

fn child_exit_error(subject: &str, code: Option<i32>) -> fastmcp_core::McpError {
    if let Some(code) = code {
        fastmcp_core::McpError::with_data(
            fastmcp_core::McpErrorCode::InternalError,
            format!("{subject} exited with code {code}"),
            serde_json::json!({ "exit_code": code }),
        )
    } else {
        fastmcp_core::McpError::internal_error(format!("{subject} terminated by signal"))
    }
}

/// Run command: Execute an MCP server binary.
fn cmd_run(
    server: &str,
    args: &[String],
    cwd: Option<&std::path::Path>,
    env_vars: &[String],
    protocol_policy: CliProtocolPolicy,
) -> McpResult<()> {
    validate_cli_protocol_policy(protocol_policy)?;
    let env_vars = parse_environment_assignments(env_vars)?;
    reject_reserved_protocol_policy_environment(&env_vars)?;
    let mut cmd = Command::new(server);
    cmd.args(args)
        .envs(env_vars)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    apply_protocol_policy_to_server_launch(&mut cmd, protocol_policy);

    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }

    let mut child = cmd.spawn().map_err(|e| {
        fastmcp_core::McpError::internal_error(format!("Failed to start server: {e}"))
    })?;

    let status = child.wait().map_err(|e| {
        fastmcp_core::McpError::internal_error(format!("Failed to wait for server: {e}"))
    })?;

    if !status.success() {
        return Err(child_exit_error("Server", status.code()));
    }

    Ok(())
}

/// Server entry for list output.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServerEntry {
    name: String,
    source: String,
    command: String,
    #[serde(serialize_with = "serialize_redacted_arguments")]
    args: Vec<String>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_redacted_environment"
    )]
    env: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cwd: Option<String>,
    enabled: bool,
}

const REDACTED_ENV_VALUE: &str = "<redacted>";
const REDACTED_ARGUMENT_VALUE: &str = "<redacted>";
const REDACTED_LONG_OPTION: &str = "--<option>";
const REDACTED_SHORT_OPTION: &str = "-<option>";
const TERMINAL_TEXT_LIMIT: usize = 4 * 1024;
const TERMINAL_TRUNCATED: &str = "...[truncated]";
const PEER_FIELD_LIMIT: usize = 512;
const PEER_DETAIL_LIMIT: usize = 2 * 1024;
const CLI_OUTPUT_MAX_ITEMS: usize = 256;
const CLI_OUTPUT_MAX_BYTES: usize = 1024 * 1024;
const CONFIG_INPUT_MAX_BYTES: usize = 1024 * 1024;
const CONFIG_OUTPUT_MAX_BYTES: usize = 1024 * 1024;
#[cfg(target_os = "linux")]
const RETAINED_STAGE_MAX_FILES: usize = 32;
#[cfg(target_os = "linux")]
const RETAINED_STAGE_SCAN_MAX_ENTRIES: usize = 4_096;
// Compact item JSON can expand substantially under pretty-printing. Reserve
// three quarters of the aggregate output budget for indentation, field names,
// server metadata, and truncation envelopes.
const INSPECT_CATEGORY_MAX_BYTES: usize = CLI_OUTPUT_MAX_BYTES / 16;
const JSON_CREDENTIAL_KEY_PRECHECK_MAX_BYTES: usize = 1024;
const JSON_PREVIEW_MAX_DEPTH: usize = 16;
const JSON_PREVIEW_MAX_NODES: usize = 4 * 1024;
const JSON_PREVIEW_MAX_CONTAINER_ITEMS: usize = 256;
const JSON_PREVIEW_MAX_STRING_CHARS: usize = 2 * 1024;
const JSON_PREVIEW_MAX_STRING_CHARS_TOTAL: usize = 256 * 1024;

fn sanitize_display_key_with_metadata(value: &str) -> (String, OutputMutationMetadata) {
    let redacted = redact_free_text_credentials_with(value, "<redacted-key>");
    let mut sanitized = String::with_capacity(redacted.len().min(PEER_FIELD_LIMIT));
    let mut mutation = OutputMutationMetadata {
        redacted: redacted != value,
        ..OutputMutationMetadata::default()
    };
    for character in redacted.chars() {
        let (component, component_was_sanitized) =
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                (character.to_string(), false)
            } else if character.is_ascii() {
                (format!("\\x{:02X}", u32::from(character)), true)
            } else {
                (format!("\\u{{{:X}}}", u32::from(character)), true)
            };
        if sanitized.len().saturating_add(component.len()) > PEER_FIELD_LIMIT {
            append_truncation_marker(&mut sanitized, PEER_FIELD_LIMIT);
            mutation.truncated = true;
            break;
        }
        mutation.sanitized |= component_was_sanitized;
        sanitized.push_str(&component);
    }
    (sanitized, mutation)
}

/// Produces bounded, single-line ASCII for terminal-bound untrusted fields.
/// Structured CLI output uses the same representation and reports every
/// redaction, sanitation, and truncation through explicit root metadata.
fn sanitize_terminal_text(value: &str) -> String {
    sanitize_terminal_text_with_limit(value, TERMINAL_TEXT_LIMIT)
}

fn sanitize_terminal_text_with_limit(value: &str, limit: usize) -> String {
    sanitize_terminal_text_with_metadata(value, limit).0
}

fn sanitize_terminal_text_with_metadata(value: &str, limit: usize) -> (String, bool, bool) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    let limit = limit.min(TERMINAL_TEXT_LIMIT);
    if limit == 0 {
        return (String::new(), false, !value.is_empty());
    }

    let mut sanitized = String::with_capacity(value.len().min(limit));
    let mut escaped = false;
    for byte in value.bytes() {
        let (encoded_len, byte_needs_escape) = if byte.is_ascii_graphic() || byte == b' ' {
            (1, false)
        } else {
            (4, true)
        };
        if sanitized.len().saturating_add(encoded_len) > limit {
            append_truncation_marker(&mut sanitized, limit);
            return (sanitized, escaped, true);
        }
        escaped |= byte_needs_escape;
        if encoded_len == 1 {
            sanitized.push(char::from(byte));
        } else {
            sanitized.push('\\');
            sanitized.push('x');
            sanitized.push(char::from(HEX[usize::from(byte >> 4)]));
            sanitized.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    (sanitized, escaped, false)
}

fn append_truncation_marker(output: &mut String, limit: usize) {
    let marker_len = TERMINAL_TRUNCATED.len().min(limit);
    let retained_limit = limit.saturating_sub(marker_len).min(output.len());
    let mut retained = retained_limit;
    while !output.is_char_boundary(retained) {
        retained = retained.saturating_sub(1);
    }
    output.truncate(retained);
    output.push_str(&TERMINAL_TRUNCATED[..marker_len]);
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct OutputMutationMetadata {
    redacted: bool,
    sanitized: bool,
    truncated: bool,
}

impl OutputMutationMetadata {
    fn merge(&mut self, other: Self) {
        self.redacted |= other.redacted;
        self.sanitized |= other.sanitized;
        self.truncated |= other.truncated;
    }
}

fn sanitize_peer_text_with_metadata(value: &str, limit: usize) -> (String, OutputMutationMetadata) {
    let limit = limit.min(TERMINAL_TEXT_LIMIT);
    if limit == 0 {
        return (
            String::new(),
            OutputMutationMetadata {
                truncated: !value.is_empty(),
                ..OutputMutationMetadata::default()
            },
        );
    }

    // Bound redaction work independently of peer input size while retaining
    // look-ahead for a credential value close to the visible boundary.
    let scan_limit = limit.saturating_mul(4);
    let mut characters = value.chars();
    let bounded_input: String = characters.by_ref().take(scan_limit).collect();
    let source_was_truncated = characters.next().is_some();
    let redacted = redact_free_text_credentials_with(&bounded_input, REDACTED_ENV_VALUE);
    let was_redacted = redacted != bounded_input;
    let (mut rendered, terminal_sanitized, terminal_truncated) =
        sanitize_terminal_text_with_metadata(&redacted, limit);
    if source_was_truncated && !terminal_truncated {
        append_truncation_marker(&mut rendered, limit);
    }
    (
        rendered,
        OutputMutationMetadata {
            redacted: was_redacted,
            sanitized: terminal_sanitized,
            truncated: source_was_truncated || terminal_truncated,
        },
    )
}

fn sanitize_peer_text(value: &str, limit: usize) -> String {
    sanitize_peer_text_with_metadata(value, limit).0
}

#[derive(Debug)]
struct JsonPreviewBudget {
    nodes_remaining: usize,
    string_chars_remaining: usize,
    mutation: OutputMutationMetadata,
}

impl Default for JsonPreviewBudget {
    fn default() -> Self {
        Self {
            nodes_remaining: JSON_PREVIEW_MAX_NODES,
            string_chars_remaining: JSON_PREVIEW_MAX_STRING_CHARS_TOTAL,
            mutation: OutputMutationMetadata::default(),
        }
    }
}

fn json_key_is_sensitive(key: &str) -> bool {
    // Credential classification normalizes and tokenizes its input. Do not let
    // an attacker turn a display-only precheck into unbounded work. An
    // oversized key is unusual and cannot be classified safely within the
    // preview budget, so fail closed and redact its value.
    key.len() > JSON_CREDENTIAL_KEY_PRECHECK_MAX_BYTES || is_credential_key(key)
}

fn collision_safe_map_key(
    rendered: &serde_json::Map<String, serde_json::Value>,
    base: String,
) -> String {
    if !rendered.contains_key(&base) {
        return base;
    }

    // Check each generated suffix against entries already retained so even a
    // peer key containing the same suffix cannot replace another entry.
    let mut suffix = 2usize;
    loop {
        let candidate = format!("{base}~{suffix}");
        if !rendered.contains_key(&candidate) {
            return candidate;
        }
        suffix = suffix.saturating_add(1);
    }
}

#[cfg(test)]
fn bounded_json_preview(value: &serde_json::Value) -> serde_json::Value {
    bounded_json_preview_inner(value, 0, &mut JsonPreviewBudget::default())
}

fn bounded_json_preview_inner(
    value: &serde_json::Value,
    depth: usize,
    budget: &mut JsonPreviewBudget,
) -> serde_json::Value {
    if budget.nodes_remaining == 0 {
        budget.mutation.truncated = true;
        return serde_json::Value::String(TERMINAL_TRUNCATED.to_owned());
    }
    budget.nodes_remaining -= 1;
    if depth >= JSON_PREVIEW_MAX_DEPTH {
        budget.mutation.truncated = true;
        return serde_json::Value::String("...[depth limit]".to_owned());
    }

    match value {
        serde_json::Value::Null => serde_json::Value::Null,
        serde_json::Value::Bool(value) => serde_json::Value::Bool(*value),
        serde_json::Value::Number(value) => serde_json::Value::Number(value.clone()),
        serde_json::Value::String(value) => {
            let limit = JSON_PREVIEW_MAX_STRING_CHARS.min(budget.string_chars_remaining);
            let (rendered, mutation) = sanitize_peer_text_with_metadata(value, limit);
            budget.mutation.merge(mutation);
            budget.string_chars_remaining = budget
                .string_chars_remaining
                .saturating_sub(rendered.chars().count());
            serde_json::Value::String(rendered)
        }
        serde_json::Value::Array(values) => {
            let visible = values.len().min(JSON_PREVIEW_MAX_CONTAINER_ITEMS);
            let mut rendered = Vec::with_capacity(visible.saturating_add(1));
            for value in values.iter().take(visible) {
                if budget.nodes_remaining == 0 {
                    break;
                }
                rendered.push(bounded_json_preview_inner(value, depth + 1, budget));
            }
            let omitted = values.len().saturating_sub(rendered.len());
            if omitted > 0 {
                budget.mutation.truncated = true;
                rendered.push(serde_json::Value::String(format!(
                    "...[{omitted} items omitted]"
                )));
            }
            serde_json::Value::Array(rendered)
        }
        serde_json::Value::Object(values) => {
            let mut rendered = serde_json::Map::new();
            let visible = values.len().min(JSON_PREVIEW_MAX_CONTAINER_ITEMS);
            for (key, value) in values.iter().take(visible) {
                if budget.nodes_remaining == 0 {
                    break;
                }
                let sensitive = json_key_is_sensitive(key);
                let key_limit = PEER_FIELD_LIMIT.min(budget.string_chars_remaining);
                let (key, mutation) = sanitize_peer_text_with_metadata(key, key_limit);
                budget.mutation.merge(mutation);
                budget.string_chars_remaining = budget
                    .string_chars_remaining
                    .saturating_sub(key.chars().count());
                let unique_key = collision_safe_map_key(&rendered, key.clone());
                budget.mutation.sanitized |= unique_key != key;
                let value = if sensitive {
                    budget.mutation.redacted = true;
                    serde_json::Value::String(REDACTED_ENV_VALUE.to_owned())
                } else {
                    bounded_json_preview_inner(value, depth + 1, budget)
                };
                rendered.insert(unique_key, value);
            }
            let omitted = values.len().saturating_sub(rendered.len());
            if omitted > 0 {
                budget.mutation.truncated = true;
                let mut marker = "_fastmcp_omitted".to_owned();
                while rendered.contains_key(&marker) {
                    marker.push('_');
                }
                rendered.insert(marker, serde_json::json!(omitted));
            }
            serde_json::Value::Object(rendered)
        }
    }
}

fn output_too_large(context: &str, bytes: usize) -> fastmcp_core::McpError {
    fastmcp_core::McpError::internal_error(format!(
        "Refusing to write {context}: bounded output is {bytes} bytes (maximum {CLI_OUTPUT_MAX_BYTES})"
    ))
}

fn write_stdout_output(
    writer: &mut impl Write,
    output: &str,
    context: &str,
    append_newline: bool,
) -> McpResult<()> {
    let total_bytes = output.len().saturating_add(usize::from(append_newline));
    if total_bytes > CLI_OUTPUT_MAX_BYTES {
        return Err(output_too_large(context, total_bytes));
    }

    writer.write_all(output.as_bytes()).map_err(|error| {
        fastmcp_core::McpError::internal_error(format!(
            "Failed to write {context} to stdout (I/O kind: {:?})",
            error.kind()
        ))
    })?;
    if append_newline {
        writer.write_all(b"\n").map_err(|error| {
            fastmcp_core::McpError::internal_error(format!(
                "Failed to write {context} to stdout (I/O kind: {:?})",
                error.kind()
            ))
        })?;
    }
    writer.flush().map_err(|error| {
        fastmcp_core::McpError::internal_error(format!(
            "Failed to flush {context} to stdout (I/O kind: {:?})",
            error.kind()
        ))
    })
}

fn write_stdout(output: &str, context: &str, append_newline: bool) -> McpResult<()> {
    let stdout = io::stdout();
    write_stdout_output(&mut stdout.lock(), output, context, append_newline)
}

fn push_output_line(output: &mut String, line: &str) -> bool {
    let required = line.len().saturating_add(1);
    if output.len().saturating_add(required) <= CLI_OUTPUT_MAX_BYTES {
        output.push_str(line);
        output.push('\n');
        true
    } else {
        let content_limit = CLI_OUTPUT_MAX_BYTES.saturating_sub(1);
        if CLI_OUTPUT_MAX_BYTES > 0 {
            append_truncation_marker(output, content_limit);
            output.push('\n');
        }
        false
    }
}

fn sanitize_config_path(path: &Path) -> String {
    sanitize_peer_text(path.to_string_lossy().as_ref(), TERMINAL_TEXT_LIMIT)
}

fn invalid_config_document(path: &Path, source_name: &str, detail: &str) -> fastmcp_core::McpError {
    fastmcp_core::McpError::invalid_params(format!(
        "Invalid {} config at {}: {detail}",
        sanitize_terminal_text(source_name),
        sanitize_config_path(path)
    ))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileMetadataStamp {
    length: u64,
    readonly: bool,
    modified: Option<std::time::SystemTime>,
    created: Option<std::time::SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    owner: u32,
    #[cfg(unix)]
    group: u32,
    #[cfg(unix)]
    links: u64,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
    #[cfg(unix)]
    status_changed_seconds: i64,
    #[cfg(unix)]
    status_changed_nanoseconds: i64,
}

impl FileMetadataStamp {
    fn from_metadata(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt as _;

        Self {
            length: metadata.len(),
            readonly: metadata.permissions().readonly(),
            modified: metadata.modified().ok(),
            created: metadata.created().ok(),
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
            #[cfg(unix)]
            mode: metadata.mode(),
            #[cfg(unix)]
            owner: metadata.uid(),
            #[cfg(unix)]
            group: metadata.gid(),
            #[cfg(unix)]
            links: metadata.nlink(),
            #[cfg(unix)]
            modified_seconds: metadata.mtime(),
            #[cfg(unix)]
            modified_nanoseconds: metadata.mtime_nsec(),
            #[cfg(unix)]
            status_changed_seconds: metadata.ctime(),
            #[cfg(unix)]
            status_changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(target_os = "linux")]
struct StableStatStamp {
    device: u64,
    inode: u64,
    mode: u32,
    owner: u32,
    group: u32,
    links: u64,
    length: i64,
    modified_seconds: i64,
    modified_nanoseconds: u64,
    status_changed_seconds: i64,
    status_changed_nanoseconds: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(not(target_os = "linux"))]
struct StableStatStamp;

#[cfg(target_os = "linux")]
impl StableStatStamp {
    // rustix follows each Linux architecture's native stat field widths. The
    // explicit conversions keep this normalization portable even though some
    // of them are identities on x86_64.
    #[allow(clippy::unnecessary_fallible_conversions, clippy::useless_conversion)]
    fn from_stat(metadata: &rustix::fs::Stat) -> Self {
        Self {
            device: u64::from(metadata.st_dev),
            inode: u64::from(metadata.st_ino),
            mode: u32::from(metadata.st_mode),
            owner: u32::from(metadata.st_uid),
            group: u32::from(metadata.st_gid),
            links: u64::from(metadata.st_nlink),
            length: i64::from(metadata.st_size),
            modified_seconds: i64::from(metadata.st_mtime),
            modified_nanoseconds: u64::try_from(metadata.st_mtime_nsec).unwrap_or(u64::MAX),
            status_changed_seconds: i64::from(metadata.st_ctime),
            status_changed_nanoseconds: u64::try_from(metadata.st_ctime_nsec).unwrap_or(u64::MAX),
        }
    }

    fn from_metadata(metadata: &Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;

        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            owner: metadata.uid(),
            group: metadata.gid(),
            links: metadata.nlink(),
            length: i64::try_from(metadata.len()).unwrap_or(i64::MAX),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: u64::try_from(metadata.mtime_nsec()).unwrap_or(u64::MAX),
            status_changed_seconds: metadata.ctime(),
            status_changed_nanoseconds: u64::try_from(metadata.ctime_nsec()).unwrap_or(u64::MAX),
        }
    }
}

#[derive(Clone, Debug)]
struct ExistingFileSnapshot {
    bytes: Vec<u8>,
    #[cfg_attr(not(unix), allow(dead_code))]
    permissions: Permissions,
    metadata: FileMetadataStamp,
    replacement_metadata: ReplacementMetadataStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReplacementMetadataStatus {
    #[cfg(target_os = "linux")]
    NoVisibleUnsupportedMetadataDetected,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    ExtendedAttributesPresent,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    PlatformFileFlagsPresent,
    InspectionFailed(io::ErrorKind),
}

#[derive(Clone, Debug)]
enum DestinationSnapshot {
    Missing,
    Existing(ExistingFileSnapshot),
}

impl DestinationSnapshot {
    fn bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Missing => None,
            Self::Existing(snapshot) => Some(&snapshot.bytes),
        }
    }

    fn existing(&self) -> Option<&ExistingFileSnapshot> {
        match self {
            Self::Missing => None,
            Self::Existing(snapshot) => Some(snapshot),
        }
    }

    fn matches(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Missing, Self::Missing) => true,
            (Self::Existing(expected), Self::Existing(current)) => {
                expected.bytes == current.bytes
                    && expected.metadata == current.metadata
                    && expected.replacement_metadata == current.replacement_metadata
            }
            _ => false,
        }
    }
}

fn invalid_bounded_file(path: &Path, context: &str, detail: &str) -> fastmcp_core::McpError {
    fastmcp_core::McpError::invalid_params(format!(
        "Invalid {} at {}: {detail}",
        sanitize_terminal_text(context),
        sanitize_config_path(path)
    ))
}

fn bounded_file_io_error(
    path: &Path,
    context: &str,
    operation: &str,
    error: &io::Error,
) -> fastmcp_core::McpError {
    fastmcp_core::McpError::internal_error(format!(
        "Failed to {operation} {} at {} (I/O kind: {:?})",
        sanitize_terminal_text(context),
        sanitize_config_path(path),
        error.kind()
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn open_bounded_regular_file(path: &Path) -> io::Result<File> {
    use rustix::fs::{Mode, OFlags};

    rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(Into::into)
}

#[cfg(target_os = "windows")]
fn open_bounded_regular_file(path: &Path) -> io::Result<File> {
    File::open(path)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn open_bounded_regular_file(_path: &Path) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "bounded race-resistant config reads are unavailable on this platform",
    ))
}

fn validate_regular_metadata(
    path: &Path,
    context: &str,
    metadata: &Metadata,
    max_bytes: usize,
) -> McpResult<()> {
    if metadata.file_type().is_symlink() {
        return Err(invalid_bounded_file(
            path,
            context,
            "symbolic links are not accepted",
        ));
    }
    if !metadata.is_file() {
        return Err(invalid_bounded_file(
            path,
            context,
            "path must identify a regular file",
        ));
    }
    validate_bounded_file_size(path, context, metadata.len(), max_bytes)
}

fn inspect_replacement_metadata(file: &File) -> ReplacementMetadataStatus {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let mut empty = [0_u8; 0];
        match rustix::fs::flistxattr(file, &mut empty) {
            Ok(0) => {}
            Ok(_) => return ReplacementMetadataStatus::ExtendedAttributesPresent,
            Err(error) => {
                return ReplacementMetadataStatus::InspectionFailed(io::Error::from(error).kind());
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        match linux_platform_attributes_present(file) {
            Ok(true) => {
                return ReplacementMetadataStatus::PlatformFileFlagsPresent;
            }
            Ok(false) => {}
            Err(error) => {
                return ReplacementMetadataStatus::InspectionFailed(error.kind());
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        match rustix::fs::fstat(file) {
            Ok(status) if status.st_flags == 0 => {}
            Ok(_) => return ReplacementMetadataStatus::PlatformFileFlagsPresent,
            Err(error) => {
                return ReplacementMetadataStatus::InspectionFailed(io::Error::from(error).kind());
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        ReplacementMetadataStatus::NoVisibleUnsupportedMetadataDetected
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = file;
        ReplacementMetadataStatus::InspectionFailed(io::ErrorKind::Unsupported)
    }
}

#[cfg(target_os = "linux")]
fn linux_platform_attributes_present(file: &File) -> io::Result<bool> {
    use rustix::fs::{AtFlags, StatxAttributes, StatxFlags};

    let relevant = StatxAttributes::COMPRESSED
        | StatxAttributes::IMMUTABLE
        | StatxAttributes::APPEND
        | StatxAttributes::NODUMP
        | StatxAttributes::ENCRYPTED
        | StatxAttributes::VERITY
        | StatxAttributes::DAX;
    let status = rustix::fs::statx(file, "", AtFlags::EMPTY_PATH, StatxFlags::ALL)
        .map_err(io::Error::from)?;
    // `stx_attributes_mask` identifies the attribute bits supported by this
    // kernel/filesystem pair. Unsupported bits have no usable value; inspect
    // only the intersection and make no claim about flags outside statx's
    // visible contract.
    let supported_relevant = status.stx_attributes_mask & relevant;
    Ok(!(status.stx_attributes & supported_relevant).is_empty())
}

#[cfg(target_os = "linux")]
fn list_extended_attribute_names(file: &File) -> io::Result<Vec<u8>> {
    const MAX_ATTRIBUTE_NAME_BYTES: usize = 64 * 1024;

    let mut empty = [0_u8; 0];
    let required = rustix::fs::flistxattr(file, &mut empty).map_err(io::Error::from)?;
    if required > MAX_ATTRIBUTE_NAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "extended-attribute name list exceeds the verification limit",
        ));
    }
    if required == 0 {
        return Ok(Vec::new());
    }
    let mut names = vec![0_u8; required];
    let written = rustix::fs::flistxattr(file, &mut names).map_err(io::Error::from)?;
    if written > names.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "extended-attribute list changed during verification",
        ));
    }
    names.truncate(written);
    Ok(names)
}

#[cfg(target_os = "linux")]
fn extended_attribute_list_contains(names: &[u8], expected: &[u8]) -> bool {
    names.split(|byte| *byte == 0).any(|name| name == expected)
}

fn validate_snapshot_for_replacement(
    snapshot: &ExistingFileSnapshot,
    path: &Path,
    context: &str,
) -> McpResult<()> {
    #[cfg(unix)]
    {
        if snapshot.permissions.readonly() {
            return Err(invalid_bounded_file(
                path,
                context,
                "read-only files require an explicit operator decision and are not replaced implicitly",
            ));
        }
        if snapshot.metadata.links != 1 {
            return Err(invalid_bounded_file(
                path,
                context,
                "multiply linked files are safe to read but are not accepted for replacement",
            ));
        }
        if snapshot.metadata.mode & 0o7000 != 0 {
            return Err(invalid_bounded_file(
                path,
                context,
                "set-user-ID, set-group-ID, and sticky permission bits cannot be preserved safely during replacement",
            ));
        }
        if snapshot.metadata.mode & 0o022 != 0 {
            return Err(invalid_bounded_file(
                path,
                context,
                "group-writable or world-writable files cannot be staged safely for replacement",
            ));
        }
    }
    match snapshot.replacement_metadata {
        #[cfg(target_os = "linux")]
        ReplacementMetadataStatus::NoVisibleUnsupportedMetadataDetected => Ok(()),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        ReplacementMetadataStatus::ExtendedAttributesPresent => Err(invalid_bounded_file(
            path,
            context,
            "extended attributes or discoverable ACL metadata cannot yet be preserved exactly during replacement",
        )),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        ReplacementMetadataStatus::PlatformFileFlagsPresent => Err(invalid_bounded_file(
            path,
            context,
            "platform file flags cannot yet be preserved exactly during replacement",
        )),
        ReplacementMetadataStatus::InspectionFailed(error_kind) => {
            Err(fastmcp_core::McpError::internal_error(format!(
                "Failed to verify replacement metadata for {context} at {} (I/O kind: {error_kind:?})",
                sanitize_config_path(path)
            )))
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_xattr_visibility_warning(
    snapshot: &ExistingFileSnapshot,
    path: &Path,
    context: &str,
) -> Option<String> {
    if matches!(
        snapshot.replacement_metadata,
        ReplacementMetadataStatus::NoVisibleUnsupportedMetadataDetected
    ) {
        Some(format!(
            "Replacement of {context} at {} was assessed using Linux metadata visible to the current process; effective UID alone does not guarantee access to every capability- or namespace-restricted xattr, so this is not a claim that all hidden metadata can be preserved",
            sanitize_config_path(path)
        ))
    } else {
        None
    }
}

#[cfg(not(target_os = "linux"))]
fn linux_xattr_visibility_warning(
    _snapshot: &ExistingFileSnapshot,
    _path: &Path,
    _context: &str,
) -> Option<String> {
    None
}

fn validate_bounded_file_size(
    path: &Path,
    context: &str,
    bytes: u64,
    max_bytes: usize,
) -> McpResult<()> {
    let max_bytes_u64 = u64::try_from(max_bytes).unwrap_or(u64::MAX);
    if bytes > max_bytes_u64 {
        return Err(invalid_bounded_file(
            path,
            context,
            &format!("file is {bytes} bytes; maximum accepted size is {max_bytes} bytes"),
        ));
    }
    Ok(())
}

/// Reads a regular file through a bounded descriptor and captures the exact
/// bytes and metadata that downstream code acted on. Linux and macOS use
/// `O_NOFOLLOW` plus `O_NONBLOCK` to close the common symlink/FIFO race between
/// the path-kind check and `open`; Windows performs descriptor/path
/// revalidation, and other platforms fail closed until an equivalent bounded
/// open has been verified.
fn read_destination_snapshot(
    path: &Path,
    context: &str,
    max_bytes: usize,
) -> McpResult<DestinationSnapshot> {
    let before = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(DestinationSnapshot::Missing);
        }
        Err(error) => {
            return Err(bounded_file_io_error(path, context, "inspect", &error));
        }
    };
    validate_regular_metadata(path, context, &before, max_bytes)?;
    let before_stamp = FileMetadataStamp::from_metadata(&before);

    let mut file = open_bounded_regular_file(path)
        .map_err(|error| bounded_file_io_error(path, context, "open", &error))?;
    let opened = file
        .metadata()
        .map_err(|error| bounded_file_io_error(path, context, "inspect opened", &error))?;
    validate_regular_metadata(path, context, &opened, max_bytes)?;
    let opened_stamp = FileMetadataStamp::from_metadata(&opened);
    if opened_stamp != before_stamp {
        return Err(invalid_bounded_file(
            path,
            context,
            "file changed or was replaced while it was being opened",
        ));
    }

    let capacity = usize::try_from(opened.len()).map_or(max_bytes, |length| length.min(max_bytes));
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(
            u64::try_from(max_bytes)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut bytes)
        .map_err(|error| bounded_file_io_error(path, context, "read", &error))?;
    if bytes.len() > max_bytes {
        return Err(invalid_bounded_file(
            path,
            context,
            &format!("file exceeds the {max_bytes}-byte input limit"),
        ));
    }

    let opened_after_read = file
        .metadata()
        .map_err(|error| bounded_file_io_error(path, context, "reinspect opened", &error))?;
    validate_regular_metadata(path, context, &opened_after_read, max_bytes)?;
    let after_read_stamp = FileMetadataStamp::from_metadata(&opened_after_read);
    let after_path = std::fs::symlink_metadata(path)
        .map_err(|error| bounded_file_io_error(path, context, "reinspect path", &error))?;
    validate_regular_metadata(path, context, &after_path, max_bytes)?;
    let after_path_stamp = FileMetadataStamp::from_metadata(&after_path);
    if after_read_stamp != opened_stamp || after_path_stamp != opened_stamp {
        return Err(invalid_bounded_file(
            path,
            context,
            "file changed or was replaced while it was being read",
        ));
    }
    let replacement_metadata = inspect_replacement_metadata(&file);

    Ok(DestinationSnapshot::Existing(ExistingFileSnapshot {
        bytes,
        permissions: opened_after_read.permissions(),
        metadata: after_read_stamp,
        replacement_metadata,
    }))
}

#[cfg(target_os = "linux")]
fn read_destination_snapshot_at(
    parent: &SecuredParentDirectory,
    relative_name: &std::ffi::OsStr,
    diagnostic_path: &Path,
    context: &str,
    max_bytes: usize,
) -> McpResult<DestinationSnapshot> {
    use rustix::fs::{AtFlags, Mode, OFlags};

    let mut components = Path::new(relative_name).components();
    if !matches!(components.next(), Some(std::path::Component::Normal(_)))
        || components.next().is_some()
    {
        return Err(invalid_bounded_file(
            diagnostic_path,
            context,
            "descriptor-relative name must be exactly one normal path component",
        ));
    }

    let before = match rustix::fs::statat(&parent.handle, relative_name, AtFlags::SYMLINK_NOFOLLOW)
    {
        Ok(metadata) => metadata,
        Err(error) => {
            let error = io::Error::from(error);
            if error.kind() == io::ErrorKind::NotFound {
                return Ok(DestinationSnapshot::Missing);
            }
            return Err(bounded_file_io_error(
                diagnostic_path,
                context,
                "inspect through secured parent descriptor",
                &error,
            ));
        }
    };
    let before_type = rustix::fs::FileType::from_raw_mode(before.st_mode);
    if before_type.is_symlink() {
        return Err(invalid_bounded_file(
            diagnostic_path,
            context,
            "symbolic links are not accepted",
        ));
    }
    if !before_type.is_file() || before.st_size < 0 {
        return Err(invalid_bounded_file(
            diagnostic_path,
            context,
            "descriptor-relative name must identify a regular file",
        ));
    }
    let before_size = usize::try_from(before.st_size).unwrap_or(usize::MAX);
    if before_size > max_bytes {
        return Err(invalid_bounded_file(
            diagnostic_path,
            context,
            &format!("file is {before_size} bytes; maximum accepted size is {max_bytes} bytes"),
        ));
    }
    let before_stamp = StableStatStamp::from_stat(&before);

    let mut file = rustix::fs::openat(
        &parent.handle,
        relative_name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| {
        let error = io::Error::from(error);
        bounded_file_io_error(
            diagnostic_path,
            context,
            "open through secured parent descriptor",
            &error,
        )
    })?;
    let opened_raw = rustix::fs::fstat(&file).map_err(|error| {
        let error = io::Error::from(error);
        bounded_file_io_error(
            diagnostic_path,
            context,
            "inspect opened descriptor",
            &error,
        )
    })?;
    let opened_raw_stamp = StableStatStamp::from_stat(&opened_raw);
    let opened = file.metadata().map_err(|error| {
        bounded_file_io_error(
            diagnostic_path,
            context,
            "inspect opened descriptor metadata",
            &error,
        )
    })?;
    validate_regular_metadata(diagnostic_path, context, &opened, max_bytes)?;
    if opened_raw_stamp != before_stamp || StableStatStamp::from_metadata(&opened) != before_stamp {
        return Err(invalid_bounded_file(
            diagnostic_path,
            context,
            "file changed or was replaced while it was being opened through the secured parent descriptor",
        ));
    }

    let mut bytes = Vec::with_capacity(before_size);
    Read::by_ref(&mut file)
        .take(
            u64::try_from(max_bytes)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut bytes)
        .map_err(|error| {
            bounded_file_io_error(
                diagnostic_path,
                context,
                "read through secured parent descriptor",
                &error,
            )
        })?;
    if bytes.len() > max_bytes {
        return Err(invalid_bounded_file(
            diagnostic_path,
            context,
            &format!("file exceeds the {max_bytes}-byte input limit"),
        ));
    }
    let replacement_metadata = inspect_replacement_metadata(&file);

    // Bracket the final name observation with descriptor observations. A name
    // that disappears or changes after the initial stat is a race, not a
    // missing snapshot.
    let final_descriptor_before = rustix::fs::fstat(&file).map_err(|error| {
        let error = io::Error::from(error);
        bounded_file_io_error(
            diagnostic_path,
            context,
            "reinspect opened descriptor",
            &error,
        )
    })?;
    let final_named = rustix::fs::statat(&parent.handle, relative_name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| {
            let error = io::Error::from(error);
            bounded_file_io_error(
                diagnostic_path,
                context,
                "reinspect secured descriptor-relative name",
                &error,
            )
        })?;
    let final_metadata = file.metadata().map_err(|error| {
        bounded_file_io_error(
            diagnostic_path,
            context,
            "reinspect opened descriptor metadata",
            &error,
        )
    })?;
    validate_regular_metadata(diagnostic_path, context, &final_metadata, max_bytes)?;
    let final_descriptor_after = rustix::fs::fstat(&file).map_err(|error| {
        let error = io::Error::from(error);
        bounded_file_io_error(
            diagnostic_path,
            context,
            "finish reinspecting opened descriptor",
            &error,
        )
    })?;
    let final_descriptor_before = StableStatStamp::from_stat(&final_descriptor_before);
    let final_named = StableStatStamp::from_stat(&final_named);
    let final_metadata_stamp = StableStatStamp::from_metadata(&final_metadata);
    let final_descriptor_after = StableStatStamp::from_stat(&final_descriptor_after);
    if final_descriptor_before != before_stamp
        || final_named != before_stamp
        || final_metadata_stamp != before_stamp
        || final_descriptor_after != before_stamp
    {
        return Err(invalid_bounded_file(
            diagnostic_path,
            context,
            "file changed or was replaced while it was being read through the secured parent descriptor",
        ));
    }

    Ok(DestinationSnapshot::Existing(ExistingFileSnapshot {
        bytes,
        permissions: final_metadata.permissions(),
        metadata: FileMetadataStamp::from_metadata(&final_metadata),
        replacement_metadata,
    }))
}

#[cfg(not(target_os = "linux"))]
fn read_destination_snapshot_at(
    _parent: &SecuredParentDirectory,
    _relative_name: &std::ffi::OsStr,
    diagnostic_path: &Path,
    context: &str,
    _max_bytes: usize,
) -> McpResult<DestinationSnapshot> {
    Err(fastmcp_core::McpError::internal_error(format!(
        "Descriptor-relative snapshot reads are unavailable for {context} at {}",
        sanitize_config_path(diagnostic_path)
    )))
}

fn read_bounded_config(path: &Path, source_name: &str) -> McpResult<String> {
    let context = format!("{} config", sanitize_terminal_text(source_name));
    let snapshot = read_destination_snapshot(path, &context, CONFIG_INPUT_MAX_BYTES)?;
    let DestinationSnapshot::Existing(snapshot) = snapshot else {
        return Err(config_read_error(
            path,
            source_name,
            &io::Error::from(io::ErrorKind::NotFound),
        ));
    };
    String::from_utf8(snapshot.bytes)
        .map_err(|_| invalid_config_document(path, source_name, "file must contain valid UTF-8"))
}

fn json_parse_error(
    path: &Path,
    source_name: &str,
    error: &serde_json::Error,
) -> fastmcp_core::McpError {
    let category = match error.classify() {
        serde_json::error::Category::Io => "I/O",
        serde_json::error::Category::Syntax => "syntax",
        serde_json::error::Category::Data => "data",
        serde_json::error::Category::Eof => "end-of-file",
    };
    fastmcp_core::McpError::invalid_params(format!(
        "Failed to parse JSON {} config at {} (category: {category}, line: {}, column: {})",
        sanitize_terminal_text(source_name),
        sanitize_config_path(path),
        error.line(),
        error.column()
    ))
}

fn toml_parse_error(path: &Path, source_name: &str) -> fastmcp_core::McpError {
    fastmcp_core::McpError::invalid_params(format!(
        "Failed to parse TOML {} config at {} (category: syntax)",
        sanitize_terminal_text(source_name),
        sanitize_config_path(path)
    ))
}

fn config_read_error(path: &Path, source_name: &str, error: &io::Error) -> fastmcp_core::McpError {
    fastmcp_core::McpError::internal_error(format!(
        "Failed to read {} config at {} (I/O kind: {:?})",
        sanitize_terminal_text(source_name),
        sanitize_config_path(path),
        error.kind()
    ))
}

/// Preserves only whether an argument is a long option, short option, attached
/// option value, positional value, or end-of-options marker. Every label and
/// every attached/separate value is redacted because an arbitrary target can
/// use a dash-prefixed positional value or encode sensitive material in a
/// label.
fn redact_argument(argument: &str) -> String {
    if let Some(long_option) = argument.strip_prefix("--") {
        let has_attached_value = long_option.contains('=');
        return if has_attached_value {
            format!("{REDACTED_LONG_OPTION}={REDACTED_ARGUMENT_VALUE}")
        } else {
            REDACTED_LONG_OPTION.to_owned()
        };
    }

    let Some(short_option) = argument.strip_prefix('-') else {
        return REDACTED_ARGUMENT_VALUE.to_owned();
    };
    if short_option.is_empty() {
        return REDACTED_ARGUMENT_VALUE.to_owned();
    }

    // A short option can carry its value without `=` (`-usecret` or
    // `-HCookie:...`). Treat every byte after the first label character as an
    // attached value; clustered flags are intentionally represented
    // conservatively because their shape is ambiguous.
    let mut characters = short_option.chars();
    let _label_character = characters.next().expect("non-empty short option");
    if characters.as_str().is_empty() {
        REDACTED_SHORT_OPTION.to_owned()
    } else if characters.as_str().starts_with('=') {
        format!("{REDACTED_SHORT_OPTION}={REDACTED_ARGUMENT_VALUE}")
    } else {
        format!("{REDACTED_SHORT_OPTION}{REDACTED_ARGUMENT_VALUE}")
    }
}

fn redacted_arguments(arguments: &[String]) -> Vec<String> {
    let mut after_end_of_options = false;
    let mut redacted = arguments
        .iter()
        .take(CLI_OUTPUT_MAX_ITEMS)
        .map(|argument| {
            if after_end_of_options {
                return REDACTED_ARGUMENT_VALUE.to_owned();
            }
            if argument == "--" {
                after_end_of_options = true;
                return "--".to_owned();
            }
            redact_argument(argument)
        })
        .collect::<Vec<_>>();
    let omitted = arguments.len().saturating_sub(redacted.len());
    if omitted > 0 {
        redacted.push(format!("<{omitted} arguments omitted>"));
    }
    redacted
}

fn serialize_redacted_arguments<S>(arguments: &[String], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    redacted_arguments(arguments).serialize(serializer)
}

fn format_redacted_arguments(arguments: &[String]) -> String {
    if arguments.is_empty() {
        return "-".to_owned();
    }

    let mut rendered = String::new();
    let mut after_end_of_options = false;
    for argument in arguments {
        let redacted = if after_end_of_options {
            REDACTED_ARGUMENT_VALUE.to_owned()
        } else if argument == "--" {
            after_end_of_options = true;
            "--".to_owned()
        } else {
            redact_argument(argument)
        };
        if !push_bounded_terminal_component(&mut rendered, " ", &redacted) {
            break;
        }
    }
    rendered
}

fn push_bounded_terminal_component(
    rendered: &mut String,
    separator: &str,
    component: &str,
) -> bool {
    let separator = if rendered.is_empty() { "" } else { separator };
    let needed = separator.len().saturating_add(component.len());
    if rendered
        .len()
        .saturating_add(needed)
        .saturating_add(TERMINAL_TRUNCATED.len())
        <= TERMINAL_TEXT_LIMIT
    {
        rendered.push_str(separator);
        rendered.push_str(component);
        true
    } else {
        rendered.push_str(TERMINAL_TRUNCATED);
        false
    }
}

fn redacted_environment_entries_with_limit(
    environment: &HashMap<String, String>,
    limit: usize,
) -> (Vec<(String, String)>, OutputMutationMetadata) {
    // Retain the lexicographically smallest original keys with bounded
    // auxiliary memory, then sanitize. Capping before sorting would make the
    // result depend on HashMap iteration order; sanitizing before selection
    // would make distinct originals collapse unpredictably.
    let visible_key_limit = if environment.len() > limit {
        limit.saturating_sub(1)
    } else {
        environment.len()
    };
    let mut selected = BinaryHeap::with_capacity(visible_key_limit.saturating_add(1));
    for key in environment.keys() {
        if selected.len() < visible_key_limit {
            selected.push(key);
        } else if visible_key_limit > 0 && selected.peek().is_some_and(|largest| key < *largest) {
            let _ = selected.pop();
            selected.push(key);
        }
    }
    let mut keys = selected.into_vec();
    keys.sort_unstable();
    let omitted = environment.len().saturating_sub(keys.len());

    let mut mutation = OutputMutationMetadata {
        redacted: !keys.is_empty(),
        truncated: omitted > 0,
        ..OutputMutationMetadata::default()
    };
    let mut occupied = HashSet::with_capacity(keys.len().saturating_add(1));
    let mut entries = Vec::with_capacity(keys.len().saturating_add(usize::from(omitted > 0)));
    for key in keys {
        let (base, key_mutation) = sanitize_display_key_with_metadata(key);
        mutation.merge(key_mutation);
        let (key, collision_mutation) = collision_safe_display_key(&mut occupied, base);
        mutation.merge(collision_mutation);
        entries.push((key, REDACTED_ENV_VALUE.to_owned()));
    }
    if omitted > 0 && entries.len() < limit {
        let (marker, collision_mutation) =
            collision_safe_display_key(&mut occupied, "_fastmcp_omitted".to_owned());
        mutation.merge(collision_mutation);
        entries.push((marker, format!("<{omitted} entries omitted>")));
    }
    (entries, mutation)
}

fn redacted_environment_entries(environment: &HashMap<String, String>) -> Vec<(String, String)> {
    redacted_environment_entries_with_limit(environment, CLI_OUTPUT_MAX_ITEMS).0
}

fn collision_safe_display_key(
    occupied: &mut HashSet<String>,
    base: String,
) -> (String, OutputMutationMetadata) {
    if occupied.insert(base.clone()) {
        return (base, OutputMutationMetadata::default());
    }

    let mut mutation = OutputMutationMetadata {
        sanitized: true,
        ..OutputMutationMetadata::default()
    };
    let mut suffix = 2usize;
    loop {
        let suffix_text = format!("~{suffix}");
        let mut candidate = base.clone();
        if candidate.len().saturating_add(suffix_text.len()) > PEER_FIELD_LIMIT {
            candidate.truncate(PEER_FIELD_LIMIT.saturating_sub(suffix_text.len()));
            mutation.truncated = true;
        }
        candidate.push_str(&suffix_text);
        if occupied.insert(candidate.clone()) {
            return (candidate, mutation);
        }
        suffix = suffix.saturating_add(1);
    }
}

fn serialize_redacted_environment<S>(
    environment: &Option<HashMap<String, String>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let Some(environment) = environment else {
        return serializer.serialize_none();
    };

    let entries = redacted_environment_entries(environment);
    let mut map = serializer.serialize_map(Some(entries.len()))?;
    for (key, value) in entries {
        map.serialize_entry(&key, &value)?;
    }
    map.end()
}

fn format_redacted_environment(environment: Option<&HashMap<String, String>>) -> String {
    let Some(environment) = environment.filter(|environment| !environment.is_empty()) else {
        return "-".to_owned();
    };

    let mut rendered = String::new();
    for (key, value) in redacted_environment_entries(environment) {
        let component = format!("{}={value}", sanitize_terminal_text(&key));
        if !push_bounded_terminal_component(&mut rendered, ", ", &component) {
            break;
        }
    }
    rendered
}

/// List output for JSON/YAML serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BoundedServerEntry {
    name: String,
    source: String,
    command: String,
    args: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    env: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cwd: Option<String>,
    enabled: bool,
}

/// List output for JSON/YAML serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ListOutput {
    servers: Vec<BoundedServerEntry>,
    #[serde(flatten)]
    mutation: OutputMutationMetadata,
}

fn bounded_server_entries(servers: &[ServerEntry]) -> ListOutput {
    let mut mutation = OutputMutationMetadata {
        truncated: servers.len() > CLI_OUTPUT_MAX_ITEMS,
        ..OutputMutationMetadata::default()
    };
    let mut nested_items_remaining = CLI_OUTPUT_MAX_ITEMS;
    let mut bounded = Vec::with_capacity(servers.len().min(CLI_OUTPUT_MAX_ITEMS));
    for entry in servers.iter().take(CLI_OUTPUT_MAX_ITEMS) {
        let argument_limit = entry.args.len().min(nested_items_remaining);
        let mut after_end_of_options = false;
        let args = entry
            .args
            .iter()
            .take(argument_limit)
            .map(|argument| {
                if after_end_of_options {
                    REDACTED_ARGUMENT_VALUE.to_owned()
                } else if argument == "--" {
                    after_end_of_options = true;
                    "--".to_owned()
                } else {
                    redact_argument(argument)
                }
            })
            .collect::<Vec<_>>();
        nested_items_remaining = nested_items_remaining.saturating_sub(args.len());
        mutation.truncated |= entry.args.len() > args.len();
        mutation.redacted |= entry
            .args
            .iter()
            .take(args.len())
            .zip(&args)
            .any(|(original, rendered)| original != rendered);

        let env = entry.env.as_ref().map(|environment| {
            let environment_limit = environment.len().min(nested_items_remaining);
            let (rendered_entries, environment_mutation) =
                redacted_environment_entries_with_limit(environment, environment_limit);
            mutation.merge(environment_mutation);
            let bounded = rendered_entries.into_iter().collect::<BTreeMap<_, _>>();
            nested_items_remaining = nested_items_remaining.saturating_sub(bounded.len());
            bounded
        });

        let (name, name_mutation) = sanitize_peer_text_with_metadata(&entry.name, PEER_FIELD_LIMIT);
        mutation.merge(name_mutation);
        let (source, source_mutation) =
            sanitize_peer_text_with_metadata(&entry.source, PEER_FIELD_LIMIT);
        mutation.merge(source_mutation);
        let (command, command_mutation) =
            sanitize_peer_text_with_metadata(&entry.command, PEER_FIELD_LIMIT);
        mutation.merge(command_mutation);
        let cwd = entry.cwd.as_deref().map(|cwd| {
            let (cwd, cwd_mutation) = sanitize_peer_text_with_metadata(cwd, PEER_FIELD_LIMIT);
            mutation.merge(cwd_mutation);
            cwd
        });

        bounded.push(BoundedServerEntry {
            name,
            source,
            command,
            args,
            env,
            cwd,
            enabled: entry.enabled,
        });
    }
    ListOutput {
        servers: bounded,
        mutation,
    }
}

fn format_list_table(servers: &[ServerEntry], verbose: bool) -> String {
    let mut output = String::new();
    let header = if verbose {
        "Source | Server Name | Command | Working Directory | Status | Arguments | Environment"
    } else {
        "Source | Server Name | Command | Status"
    };
    let _ = push_output_line(&mut output, "Configured MCP Servers");
    let _ = push_output_line(&mut output, header);
    let _ = push_output_line(&mut output, &"-".repeat(header.len()));

    let mut rendered = 0usize;
    for entry in servers.iter().take(CLI_OUTPUT_MAX_ITEMS) {
        let status = if entry.enabled { "enabled" } else { "disabled" };
        let source = sanitize_peer_text(&entry.source, PEER_FIELD_LIMIT);
        let name = sanitize_peer_text(&entry.name, PEER_FIELD_LIMIT);
        let command = sanitize_peer_text(&entry.command, PEER_FIELD_LIMIT);
        let line = if verbose {
            let cwd = entry.cwd.as_deref().map_or_else(
                || "-".to_owned(),
                |cwd| sanitize_peer_text(cwd, PEER_FIELD_LIMIT),
            );
            let args = format_redacted_arguments(&entry.args);
            let environment = format_redacted_environment(entry.env.as_ref());
            format!("{source} | {name} | {command} | {cwd} | {status} | {args} | {environment}")
        } else {
            format!("{source} | {name} | {command} | {status}")
        };
        if !push_output_line(&mut output, &line) {
            break;
        }
        rendered += 1;
    }
    let omitted = servers.len().saturating_sub(rendered);
    if omitted > 0 {
        let _ = push_output_line(&mut output, &format!("...[{omitted} servers omitted]"));
    }
    output
}

/// List command: List configured MCP servers.
fn cmd_list(
    target: Option<InstallTarget>,
    config: Option<PathBuf>,
    format: ListFormat,
    verbose: bool,
) -> McpResult<()> {
    let mut servers: Vec<ServerEntry> = Vec::new();

    // If custom config path is provided, use only that
    if let Some(config_path) = config {
        load_servers_from_path(&config_path, "Custom", &mut servers)?;
    } else {
        // Load from standard targets
        let explicit_target = target.is_some();
        let targets = if let Some(t) = target {
            vec![t]
        } else {
            vec![
                InstallTarget::Claude,
                InstallTarget::Cursor,
                InstallTarget::Cline,
            ]
        };

        for t in targets {
            let (name, config_path_result) = match t {
                InstallTarget::Claude => ("Claude", get_claude_desktop_config_path()),
                InstallTarget::Cursor => ("Cursor", get_cursor_config_path()),
                InstallTarget::Cline => ("Cline", get_cline_config_path()),
            };

            let path = match config_path_result {
                Ok(path) => path,
                Err(error) if explicit_target => return Err(error),
                Err(_) => {
                    write_cli_warning(&format!(
                        "failed to resolve {} config path",
                        sanitize_terminal_text(name)
                    ));
                    continue;
                }
            };
            if path.exists() {
                let result = load_servers_from_client_config(&path, name, t, &mut servers);
                if explicit_target {
                    result?;
                } else if let Err(error) = result {
                    write_cli_warning(&format!(
                        "failed to load {} config at {}: {error}",
                        sanitize_terminal_text(name),
                        sanitize_config_path(&path)
                    ));
                }
            }
        }

        // Load from project-local configs
        load_project_local_servers(&mut servers);
    }

    // Output based on format
    match format {
        ListFormat::Table => {
            if servers.is_empty() {
                write_stdout("No configured servers found.", "list output", true)?;
                return Ok(());
            }
            let table = format_list_table(&servers, verbose);
            write_stdout(&table, "list output", false)?;
        }
        ListFormat::Json => {
            let output = bounded_server_entries(&servers);
            let json = serde_json::to_string_pretty(&output).map_err(|e| {
                fastmcp_core::McpError::internal_error(format!("JSON serialization error: {e}"))
            })?;
            write_stdout(&json, "list output", true)?;
        }
        ListFormat::Yaml => {
            let output = bounded_server_entries(&servers);
            let yaml = serde_yaml::to_string(&output).map_err(|e| {
                fastmcp_core::McpError::internal_error(format!("YAML serialization error: {e}"))
            })?;
            write_stdout(&yaml, "list output", false)?;
        }
    }

    Ok(())
}

fn invalid_server_entry(
    path: &std::path::Path,
    source_name: &str,
    name: &str,
    detail: &str,
) -> fastmcp_core::McpError {
    fastmcp_core::McpError::invalid_params(format!(
        "Invalid MCP server entry {:?} in {} config at {}: {detail}",
        sanitize_peer_text(name, PEER_FIELD_LIMIT),
        sanitize_peer_text(source_name, PEER_FIELD_LIMIT),
        sanitize_config_path(path)
    ))
}

fn is_supported_server_config_field(field: &str) -> bool {
    matches!(field, "command" | "args" | "env" | "cwd" | "disabled")
}

fn is_bounded_string_array(value: &serde_json::Value) -> bool {
    value.as_array().is_some_and(|items| {
        items.len() <= CLI_OUTPUT_MAX_ITEMS && items.iter().all(serde_json::Value::is_string)
    })
}

fn is_bounded_string_map(value: &serde_json::Value) -> bool {
    value.as_object().is_some_and(|entries| {
        entries.len() <= CLI_OUTPUT_MAX_ITEMS && entries.values().all(serde_json::Value::is_string)
    })
}

fn is_bounded_client_json(value: &serde_json::Value) -> bool {
    const MAX_DEPTH: usize = 8;

    fn visit(value: &serde_json::Value, depth: usize, remaining: &mut usize) -> bool {
        if depth > MAX_DEPTH || *remaining == 0 {
            return false;
        }
        *remaining -= 1;
        match value {
            serde_json::Value::Array(items) => {
                items.len() <= CLI_OUTPUT_MAX_ITEMS
                    && items.iter().all(|item| visit(item, depth + 1, remaining))
            }
            serde_json::Value::Object(entries) => {
                entries.len() <= CLI_OUTPUT_MAX_ITEMS
                    && entries
                        .values()
                        .all(|item| visit(item, depth + 1, remaining))
            }
            _ => true,
        }
    }

    let mut remaining = CLI_OUTPUT_MAX_ITEMS;
    visit(value, 0, &mut remaining)
}

fn is_valid_cline_timeout(value: &serde_json::Value) -> bool {
    value
        .as_f64()
        .is_some_and(|seconds| seconds.is_finite() && (1.0..=3600.0).contains(&seconds))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClientServerFieldClass {
    Local,
    Remote,
    Unsupported,
}

fn is_remote_transport_name(value: &str) -> bool {
    matches!(
        value,
        "http" | "streamable-http" | "streamableHttp" | "sse" | "ws"
    )
}

fn classify_cline_transport(value: &serde_json::Value) -> ClientServerFieldClass {
    let Some(transport) = value.as_object() else {
        return ClientServerFieldClass::Unsupported;
    };
    let Some(transport_type) = transport.get("type").and_then(serde_json::Value::as_str) else {
        return ClientServerFieldClass::Unsupported;
    };
    if is_remote_transport_name(transport_type) {
        return if transport
            .keys()
            .all(|field| matches!(field.as_str(), "type" | "url" | "headers"))
        {
            ClientServerFieldClass::Remote
        } else {
            ClientServerFieldClass::Unsupported
        };
    }
    if transport_type != "stdio"
        || transport
            .keys()
            .any(|field| !matches!(field.as_str(), "type" | "command" | "args" | "cwd" | "env"))
        || transport
            .get("command")
            .and_then(serde_json::Value::as_str)
            .is_none_or(|command| command.trim().is_empty())
        || transport
            .get("args")
            .is_some_and(|value| !is_bounded_string_array(value))
        || transport.get("cwd").is_some_and(|value| !value.is_string())
        || transport
            .get("env")
            .is_some_and(|value| !is_bounded_string_map(value))
    {
        return ClientServerFieldClass::Unsupported;
    }
    ClientServerFieldClass::Local
}

/// Classify every per-server field through the same target profile for both
/// listing and same-name installation updates. Unsupported keys are refused
/// instead of being preserved by install and then rejected by list.
fn classify_client_server_field(
    target: InstallTarget,
    field: &str,
    value: &serde_json::Value,
) -> ClientServerFieldClass {
    if is_supported_server_config_field(field) {
        return ClientServerFieldClass::Local;
    }
    if matches!(field, "url" | "headers" | "auth") {
        return ClientServerFieldClass::Remote;
    }
    if field == "type" {
        return match value.as_str() {
            Some("stdio") => ClientServerFieldClass::Local,
            Some(kind) if is_remote_transport_name(kind) => ClientServerFieldClass::Remote,
            _ => ClientServerFieldClass::Unsupported,
        };
    }
    if field == "transportType" {
        return match value.as_str() {
            Some("stdio") if target == InstallTarget::Cline => ClientServerFieldClass::Local,
            Some(kind) if is_remote_transport_name(kind) => ClientServerFieldClass::Remote,
            _ => ClientServerFieldClass::Unsupported,
        };
    }

    match (target, field) {
        (InstallTarget::Cursor, "envFile")
            if value.as_str().is_some_and(|path| !path.trim().is_empty()) =>
        {
            ClientServerFieldClass::Local
        }
        (InstallTarget::Cline, "transport") => classify_cline_transport(value),
        (InstallTarget::Cline, "autoApprove") if is_bounded_string_array(value) => {
            ClientServerFieldClass::Local
        }
        (InstallTarget::Cline, "timeout") if is_valid_cline_timeout(value) => {
            ClientServerFieldClass::Local
        }
        (InstallTarget::Cline, "remoteConfigured") if value.is_boolean() => {
            ClientServerFieldClass::Local
        }
        (InstallTarget::Cline, "oauth" | "metadata") if is_bounded_client_json(value) => {
            ClientServerFieldClass::Local
        }
        (InstallTarget::Claude | InstallTarget::Cursor, "oauth") => ClientServerFieldClass::Remote,
        _ => ClientServerFieldClass::Unsupported,
    }
}

fn normalize_cline_nested_stdio_entry(
    config: &serde_json::Value,
) -> Result<serde_json::Value, &'static str> {
    let outer = config.as_object().ok_or("schema validation failed")?;
    let allowed_outer = [
        "transport",
        "disabled",
        "autoApprove",
        "timeout",
        "remoteConfigured",
        "oauth",
        "metadata",
    ];
    if outer
        .keys()
        .any(|field| !allowed_outer.contains(&field.as_str()))
        || outer.iter().any(|(field, value)| {
            classify_client_server_field(InstallTarget::Cline, field, value)
                == ClientServerFieldClass::Unsupported
        })
    {
        return Err("schema validation failed");
    }

    let transport = outer
        .get("transport")
        .and_then(serde_json::Value::as_object)
        .ok_or("schema validation failed")?;
    let transport_type = transport
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or("schema validation failed")?;
    if is_remote_transport_name(transport_type) {
        return Err("remote MCP entries are not yet representable by fastmcp list");
    }
    if transport_type != "stdio" {
        return Err("schema validation failed");
    }

    let mut normalized = serde_json::Map::new();
    for field in ["command", "args", "cwd", "env"] {
        if let Some(value) = transport.get(field) {
            normalized.insert(field.to_owned(), value.clone());
        }
    }
    if let Some(disabled) = outer.get("disabled") {
        normalized.insert("disabled".to_owned(), disabled.clone());
    }
    Ok(serde_json::Value::Object(normalized))
}

fn parse_json_server_entry(
    path: &std::path::Path,
    source_name: &str,
    name: &str,
    config: &serde_json::Value,
    client_target: Option<InstallTarget>,
) -> McpResult<ServerEntry> {
    let normalized = if client_target == Some(InstallTarget::Cline)
        && config
            .as_object()
            .is_some_and(|fields| fields.contains_key("transport"))
    {
        Some(
            normalize_cline_nested_stdio_entry(config)
                .map_err(|detail| invalid_server_entry(path, source_name, name, detail))?,
        )
    } else {
        None
    };
    let config = normalized.as_ref().unwrap_or(config);

    if client_target.is_some_and(|target| {
        config.as_object().is_some_and(|fields| {
            fields.iter().any(|(field, value)| {
                classify_client_server_field(target, field, value) == ClientServerFieldClass::Remote
            })
        })
    }) {
        return Err(invalid_server_entry(
            path,
            source_name,
            name,
            "remote MCP entries are not yet representable by fastmcp list",
        ));
    }
    if config
        .as_object()
        .is_some_and(|fields| match client_target {
            Some(target) => fields.iter().any(|(field, value)| {
                classify_client_server_field(target, field, value)
                    == ClientServerFieldClass::Unsupported
            }),
            None => fields
                .keys()
                .any(|field| !is_supported_server_config_field(field)),
        })
    {
        return Err(invalid_server_entry(
            path,
            source_name,
            name,
            "schema validation failed",
        ));
    }
    let mcp_config = McpServerConfig::deserialize(config)
        .map_err(|_| invalid_server_entry(path, source_name, name, "schema validation failed"))?;
    validate_server_entry_counts(path, source_name, name, &mcp_config)?;

    Ok(ServerEntry {
        name: name.to_owned(),
        source: source_name.to_owned(),
        command: mcp_config.command,
        args: mcp_config.args,
        env: mcp_config.env,
        cwd: mcp_config.cwd,
        enabled: !mcp_config.disabled,
    })
}

fn parse_json_server_entries(
    path: &std::path::Path,
    source_name: &str,
    map: &serde_json::Map<String, serde_json::Value>,
    client_target: Option<InstallTarget>,
) -> McpResult<Vec<ServerEntry>> {
    if map.len() > CLI_OUTPUT_MAX_ITEMS {
        return Err(invalid_config_document(
            path,
            source_name,
            &format!(
                "MCP server registry contains {} entries; maximum accepted count is {CLI_OUTPUT_MAX_ITEMS}",
                map.len()
            ),
        ));
    }
    map.iter()
        .map(|(name, config)| {
            parse_json_server_entry(path, source_name, name, config, client_target)
        })
        .collect()
}

fn parse_toml_server_entry(
    path: &std::path::Path,
    source_name: &str,
    name: &str,
    config: &toml::Value,
) -> McpResult<ServerEntry> {
    if config.as_table().is_some_and(|fields| {
        fields
            .keys()
            .any(|field| !is_supported_server_config_field(field))
    }) {
        return Err(invalid_server_entry(
            path,
            source_name,
            name,
            "schema validation failed",
        ));
    }
    let mcp_config: McpServerConfig = config
        .clone()
        .try_into()
        .map_err(|_| invalid_server_entry(path, source_name, name, "schema validation failed"))?;
    validate_server_entry_counts(path, source_name, name, &mcp_config)?;

    Ok(ServerEntry {
        name: name.to_owned(),
        source: source_name.to_owned(),
        command: mcp_config.command,
        args: mcp_config.args,
        env: mcp_config.env,
        cwd: mcp_config.cwd,
        enabled: !mcp_config.disabled,
    })
}

fn validate_server_entry_counts(
    path: &Path,
    source_name: &str,
    name: &str,
    config: &McpServerConfig,
) -> McpResult<()> {
    if config.command.trim().is_empty() {
        return Err(invalid_server_entry(
            path,
            source_name,
            name,
            "schema validation failed",
        ));
    }
    if config.args.len() > CLI_OUTPUT_MAX_ITEMS {
        return Err(invalid_server_entry(
            path,
            source_name,
            name,
            &format!(
                "argument list contains {} entries; maximum accepted count is {CLI_OUTPUT_MAX_ITEMS}",
                config.args.len()
            ),
        ));
    }
    if config
        .env
        .as_ref()
        .is_some_and(|env| env.len() > CLI_OUTPUT_MAX_ITEMS)
    {
        return Err(invalid_server_entry(
            path,
            source_name,
            name,
            &format!("environment contains more than {CLI_OUTPUT_MAX_ITEMS} entries"),
        ));
    }
    Ok(())
}

/// Load servers from a client-specific config file.
fn load_servers_from_client_config(
    path: &Path,
    source_name: &str,
    target: InstallTarget,
    servers: &mut Vec<ServerEntry>,
) -> McpResult<()> {
    let content = read_bounded_config(path, source_name)?;

    let json: serde_json::Value = serde_json::from_str(&content)
        .map_err(|error| json_parse_error(path, source_name, &error))?;
    let root = json
        .as_object()
        .ok_or_else(|| invalid_config_document(path, source_name, "root must be a JSON object"))?;

    // Extract servers based on client type.
    let registry_name = "mcpServers";

    let registry = root.get(registry_name).ok_or_else(|| {
        invalid_config_document(path, source_name, "expected MCP server registry is missing")
    })?;
    let map = registry.as_object().ok_or_else(|| {
        invalid_config_document(
            path,
            source_name,
            "MCP server registry must be a JSON object",
        )
    })?;
    // Client-owned registries legitimately carry target-specific extension
    // fields. Validate a narrow typed allowlist so supported metadata survives
    // listing without turning every misspelled key into silently ignored data.
    let parsed = parse_json_server_entries(path, source_name, map, Some(target))?;
    servers.extend(parsed);

    Ok(())
}

/// Load servers from a custom config path.
fn load_servers_from_path(
    path: &Path,
    source_name: &str,
    servers: &mut Vec<ServerEntry>,
) -> McpResult<()> {
    let content = read_bounded_config(path, source_name)?;

    // Try to detect format by extension
    let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    match extension {
        "toml" => {
            // Parse as TOML
            let toml_value: toml::Value =
                toml::from_str(&content).map_err(|_| toml_parse_error(path, source_name))?;
            let root = toml_value.as_table().ok_or_else(|| {
                invalid_config_document(path, source_name, "root must be a TOML table")
            })?;

            // Look for [servers] or [mcpServers] table.
            let registry = root
                .get("servers")
                .map(|value| ("servers", value))
                .or_else(|| root.get("mcpServers").map(|value| ("mcpServers", value)));

            let (_registry_name, registry) = registry.ok_or_else(|| {
                invalid_config_document(
                    path,
                    source_name,
                    "expected MCP server registry is missing",
                )
            })?;
            let table = registry.as_table().ok_or_else(|| {
                invalid_config_document(
                    path,
                    source_name,
                    "MCP server registry must be a TOML table",
                )
            })?;
            if table.len() > CLI_OUTPUT_MAX_ITEMS {
                return Err(invalid_config_document(
                    path,
                    source_name,
                    &format!(
                        "MCP server registry contains {} entries; maximum accepted count is {CLI_OUTPUT_MAX_ITEMS}",
                        table.len()
                    ),
                ));
            }
            let parsed = table
                .iter()
                .map(|(name, config)| parse_toml_server_entry(path, source_name, name, config))
                .collect::<McpResult<Vec<_>>>()?;
            servers.extend(parsed);
        }
        _ => {
            // Default to JSON
            let json: serde_json::Value = serde_json::from_str(&content)
                .map_err(|error| json_parse_error(path, source_name, &error))?;
            let root = json.as_object().ok_or_else(|| {
                invalid_config_document(path, source_name, "root must be a JSON object")
            })?;

            let registry = root
                .get("servers")
                .map(|value| ("servers", value))
                .or_else(|| root.get("mcpServers").map(|value| ("mcpServers", value)));

            let (_registry_name, registry) = registry.ok_or_else(|| {
                invalid_config_document(
                    path,
                    source_name,
                    "expected MCP server registry is missing",
                )
            })?;
            let map = registry.as_object().ok_or_else(|| {
                invalid_config_document(
                    path,
                    source_name,
                    "MCP server registry must be a JSON object",
                )
            })?;
            let parsed = parse_json_server_entries(path, source_name, map, None)?;
            servers.extend(parsed);
        }
    }

    Ok(())
}

/// Load servers from project-local config files.
fn load_project_local_servers(servers: &mut Vec<ServerEntry>) {
    // Check for ./mcp.json
    let mcp_json = PathBuf::from("./mcp.json");
    if mcp_json.exists() {
        if let Err(e) = load_servers_from_path(&mcp_json, "Project (mcp.json)", servers) {
            write_cli_warning(&format!(
                "failed to load project config at {}: {e}",
                sanitize_config_path(&mcp_json)
            ));
        }
    }

    // Check for ./mcp.toml
    let mcp_toml = PathBuf::from("./mcp.toml");
    if mcp_toml.exists() {
        if let Err(e) = load_servers_from_path(&mcp_toml, "Project (mcp.toml)", servers) {
            write_cli_warning(&format!(
                "failed to load project config at {}: {e}",
                sanitize_config_path(&mcp_toml)
            ));
        }
    }
}

/// Allowlisted timeout source exposed by machine-readable test reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum TestTimeoutSource {
    Idle,
    Absolute,
}

impl TestTimeoutSource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Absolute => "absolute",
        }
    }
}

fn allowlisted_test_timeout_source(error: &fastmcp_core::McpError) -> Option<TestTimeoutSource> {
    if error.code != fastmcp_core::McpErrorCode::InternalError {
        return None;
    }
    let source = error
        .data
        .as_ref()
        .and_then(|data| data.get("timeoutSource"))
        .and_then(serde_json::Value::as_str)?;
    match (error.message.as_str(), source) {
        ("Request timed out at the idle deadline", "idle") => Some(TestTimeoutSource::Idle),
        ("Request timed out at the absolute deadline", "absolute") => {
            Some(TestTimeoutSource::Absolute)
        }
        _ => None,
    }
}

/// Test result for a single test.
#[derive(Debug, Clone, Serialize)]
struct TestResult {
    name: String,
    success: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    skipped: bool,
    duration_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timeout_source: Option<TestTimeoutSource>,
    #[serde(skip)]
    mutation: OutputMutationMetadata,
}

/// Full test report output.
#[derive(Debug, Clone, Serialize)]
struct TestReport {
    server: String,
    success: bool,
    tests: Vec<TestResult>,
    total_duration_ms: f64,
}

fn bounded_test_report_value(report: &TestReport) -> serde_json::Value {
    let mut mutation = OutputMutationMetadata {
        truncated: report.tests.len() > CLI_OUTPUT_MAX_ITEMS,
        ..OutputMutationMetadata::default()
    };
    let mut tests = Vec::with_capacity(report.tests.len().min(CLI_OUTPUT_MAX_ITEMS));
    for result in report.tests.iter().take(CLI_OUTPUT_MAX_ITEMS) {
        mutation.merge(result.mutation);
        let (name, name_mutation) =
            sanitize_peer_text_with_metadata(&result.name, PEER_FIELD_LIMIT);
        mutation.merge(name_mutation);
        let details = result.details.as_deref().map(|value| {
            let (value, value_mutation) =
                sanitize_peer_text_with_metadata(value, PEER_DETAIL_LIMIT);
            mutation.merge(value_mutation);
            value
        });
        let error = result.error.as_deref().map(|value| {
            let (value, value_mutation) =
                sanitize_peer_text_with_metadata(value, PEER_DETAIL_LIMIT);
            mutation.merge(value_mutation);
            value
        });
        let mut test = serde_json::Map::new();
        test.insert("name".to_owned(), serde_json::Value::String(name));
        test.insert(
            "success".to_owned(),
            serde_json::Value::Bool(result.success),
        );
        if result.skipped {
            test.insert("skipped".to_owned(), serde_json::Value::Bool(true));
        }
        test.insert(
            "duration_ms".to_owned(),
            serde_json::json!(result.duration_ms),
        );
        if let Some(details) = details {
            test.insert("details".to_owned(), serde_json::Value::String(details));
        }
        if let Some(error) = error {
            test.insert("error".to_owned(), serde_json::Value::String(error));
        }
        if let Some(timeout_source) = result.timeout_source {
            test.insert(
                "timeout_source".to_owned(),
                serde_json::Value::String(timeout_source.as_str().to_owned()),
            );
        }
        tests.push(serde_json::Value::Object(test));
    }
    let (server, server_mutation) =
        sanitize_peer_text_with_metadata(&report.server, PEER_FIELD_LIMIT);
    mutation.merge(server_mutation);
    serde_json::json!({
        "server": server,
        "success": report.success,
        "tests": tests,
        "total_duration_ms": report.total_duration_ms,
        "redacted": mutation.redacted,
        "sanitized": mutation.sanitized,
        "truncated": mutation.truncated,
    })
}

fn write_test_report(report: &TestReport, json_output: bool) -> McpResult<()> {
    if json_output {
        let json =
            serde_json::to_string_pretty(&bounded_test_report_value(report)).map_err(|e| {
                fastmcp_core::McpError::internal_error(format!("JSON serialization error: {e}"))
            })?;
        write_stdout(&json, "test output", true)
    } else {
        let summary = if report.success {
            "\nAll tests passed!"
        } else {
            "\nSome tests failed."
        };
        write_stdout(summary, "test output", true)
    }
}

fn failed_test_result(
    name: &str,
    duration: std::time::Duration,
    error: &fastmcp_core::McpError,
) -> TestResult {
    let prefix = format!("[{}] ", i32::from(error.code));
    let (message, mutation) = sanitize_peer_text_with_metadata(
        &error.message,
        PEER_DETAIL_LIMIT.saturating_sub(prefix.len()),
    );
    TestResult {
        name: name.to_owned(),
        success: false,
        skipped: false,
        duration_ms: duration.as_secs_f64() * 1000.0,
        details: None,
        error: Some(format!("{prefix}{message}")),
        timeout_source: allowlisted_test_timeout_source(error),
        mutation,
    }
}

fn split_client_cleanup_failure(
    error: &fastmcp_core::McpError,
) -> Option<(
    fastmcp_core::McpError,
    fastmcp_core::McpError,
    std::time::Duration,
)> {
    let data = error.data.as_ref()?.as_object()?;
    if data
        .get(CLIENT_CLEANUP_UNVERIFIED_DATA_KEY)
        .and_then(serde_json::Value::as_bool)
        != Some(true)
    {
        return None;
    }
    let operation = serde_json::from_value(data.get("operation")?.clone()).ok()?;
    let cleanup = serde_json::from_value(data.get("cleanup")?.clone()).ok()?;
    let duration_ms = data
        .get(CLIENT_CLEANUP_DURATION_MS_DATA_KEY)
        .and_then(serde_json::Value::as_f64)
        .filter(|duration| duration.is_finite() && *duration >= 0.0)
        .unwrap_or(0.0);
    Some((
        operation,
        cleanup,
        std::time::Duration::from_secs_f64(duration_ms / 1_000.0),
    ))
}

/// Couples a failed post-connect test-output operation to explicit cleanup.
///
/// Successful incremental output must not close the still-active test client.
/// Once output fails, however, the command cannot continue safely and must not
/// rely on `Client::drop` to stop the owned subprocess group. Preserve both
/// failures as structured data when cleanup cannot be verified.
fn finish_test_output<T, F>(output: McpResult<T>, cleanup: F) -> McpResult<T>
where
    F: FnOnce() -> McpResult<()>,
{
    match output {
        Ok(value) => Ok(value),
        Err(output_error) => {
            let cleanup_started = std::time::Instant::now();
            match cleanup() {
                Ok(()) => Err(output_error),
                Err(cleanup_error) => Err(fastmcp_core::McpError::with_data(
                    fastmcp_core::McpErrorCode::InternalError,
                    format!(
                        "Test output failed ({output_error}); client cleanup also failed ({cleanup_error})"
                    ),
                    serde_json::json!({
                        CLIENT_CLEANUP_UNVERIFIED_DATA_KEY: true,
                        "operation": output_error,
                        "cleanup": cleanup_error,
                        CLIENT_CLEANUP_DURATION_MS_DATA_KEY:
                            cleanup_started.elapsed().as_secs_f64() * 1_000.0,
                    }),
                )),
            }
        }
    }
}

/// Preserves a terminal connection failure when rendering its test report also
/// fails.
///
/// There is no live [`fastmcp_client::Client`] to clean up in this path: the
/// builder has already attempted cleanup and encoded any unverified outcome in
/// `terminal_error`. Keep that error as the primary result, including its
/// structured cleanup marker, while making the reporting failure observable.
fn combine_test_failure_with_output(
    mut terminal_error: fastmcp_core::McpError,
    output_error: fastmcp_core::McpError,
) -> fastmcp_core::McpError {
    terminal_error.message = format!(
        "{}; test-result reporting also failed ({output_error})",
        terminal_error.message
    );

    let output_error = serde_json::json!(output_error);
    match terminal_error.data.as_mut() {
        Some(serde_json::Value::Object(data)) => {
            data.insert("reporting".to_owned(), output_error);
        }
        Some(data) => {
            let cause_data = std::mem::take(data);
            *data = serde_json::json!({
                "causeData": cause_data,
                "reporting": output_error,
            });
        }
        None => {
            terminal_error.data = Some(serde_json::json!({
                "reporting": output_error,
            }));
        }
    }
    terminal_error
}

/// Test command: Test MCP server connectivity.
async fn cmd_test(
    cx: &Cx,
    server: &str,
    args: &[String],
    protocol_policy: CliProtocolPolicy,
    idle_timeout_secs: u64,
    absolute_timeout_secs: u64,
    verbose: bool,
    json_output: bool,
) -> McpResult<()> {
    use std::time::{Duration, Instant};

    let total_start = Instant::now();
    let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();

    if !json_output {
        write_stdout(
            &format!(
                "Testing server: {}",
                sanitize_peer_text(server, PEER_FIELD_LIMIT)
            ),
            "test output",
            true,
        )?;
    }

    // Connect to server. Start timing before the initialization handshake.
    let init_start = Instant::now();
    // This policy is snapshotted for initialization and each later request; it
    // is deliberately not an end-to-end deadline for this CLI process.
    let timeout_policy = fastmcp_client::RequestTimeoutPolicy::new(
        Duration::from_secs(idle_timeout_secs),
        Duration::from_secs(absolute_timeout_secs),
    )?;
    let client = client_builder_for_protocol_policy(protocol_policy)?
        .request_timeout_policy(timeout_policy)
        .env(
            FASTMCP_PROTOCOL_POLICY_ENV,
            protocol_policy.server_launch_value(),
        )
        .owned_process_group(true)
        .connect_stdio_with_cx(server, &args_refs, cx)
        .await;
    let mut client = match client {
        Ok(client) => client,
        Err(mut error) => {
            let split_cleanup = split_client_cleanup_failure(&error);
            let connection_duration = init_start.elapsed();
            let initialize_duration = split_cleanup
                .as_ref()
                .map_or(connection_duration, |(_, _, cleanup_duration)| {
                    connection_duration.saturating_sub(*cleanup_duration)
                });
            let init_result = failed_test_result(
                "initialize",
                initialize_duration,
                split_cleanup
                    .as_ref()
                    .map_or(&error, |(operation, _, _)| operation),
            );
            let cleanup_result = split_cleanup
                .as_ref()
                .map(|(_, cleanup, duration)| failed_test_result("cleanup", *duration, cleanup))
                .or_else(|| {
                    fastmcp_client::is_cleanup_unverified(&error)
                        .then(|| failed_test_result("cleanup", Duration::ZERO, &error))
                });
            if !json_output {
                if let Err(output_error) = print_test_result(&init_result, verbose) {
                    return Err(combine_test_failure_with_output(error, output_error));
                }
                if let Some(result) = &cleanup_result {
                    if let Err(output_error) = print_test_result(result, verbose) {
                        return Err(combine_test_failure_with_output(error, output_error));
                    }
                }
            }
            let mut tests = vec![init_result];
            tests.extend(cleanup_result);
            let report = TestReport {
                server: server.to_owned(),
                success: false,
                tests,
                total_duration_ms: total_start.elapsed().as_secs_f64() * 1000.0,
            };
            if let Err(output_error) = write_test_report(&report, json_output) {
                error = combine_test_failure_with_output(error, output_error);
            }
            return Err(error);
        }
    };

    let mut results: Vec<TestResult> = Vec::new();

    // Test 1: Initialize (already done by connect_stdio)
    let init_result = TestResult {
        name: "initialize".to_string(),
        success: true,
        skipped: false,
        duration_ms: init_start.elapsed().as_secs_f64() * 1000.0,
        details: Some(format!("protocol {}", client.protocol_version())),
        error: None,
        timeout_source: None,
        mutation: OutputMutationMetadata::default(),
    };
    if !json_output {
        finish_test_output(print_test_result(&init_result, verbose), || client.close())?;
    }
    results.push(init_result);

    let capabilities = client.server_capabilities().clone();

    let ping_result = run_test("ping", || {
        client.ping()?;
        Ok("server responded".to_owned())
    });
    if !json_output {
        finish_test_output(print_test_result(&ping_result, verbose), || client.close())?;
    }
    results.push(ping_result);

    // Only invoke capability-specific methods the server advertised.
    let tools_result = capabilities.tools.as_ref().map_or_else(
        || skipped_test("list_tools", "server did not advertise tools"),
        |_| {
            run_test("list_tools", || {
                let page = client.list_tools_page(
                    None,
                    ListPageLimits::new(CLI_OUTPUT_MAX_ITEMS, INSPECT_CATEGORY_MAX_BYTES),
                )?;
                let qualifier = if page.local_truncated || page.peer_has_more {
                    " in the bounded first page; more were omitted"
                } else {
                    ""
                };
                Ok(format!("{} tools{qualifier}", page.items.len()))
            })
        },
    );
    if !json_output {
        finish_test_output(print_test_result(&tools_result, verbose), || client.close())?;
    }
    results.push(tools_result);

    let resources_result = capabilities.resources.as_ref().map_or_else(
        || skipped_test("list_resources", "server did not advertise resources"),
        |_| {
            run_test("list_resources", || {
                let page = client.list_resources_page(
                    None,
                    ListPageLimits::new(CLI_OUTPUT_MAX_ITEMS, INSPECT_CATEGORY_MAX_BYTES),
                )?;
                let qualifier = if page.local_truncated || page.peer_has_more {
                    " in the bounded first page; more were omitted"
                } else {
                    ""
                };
                Ok(format!("{} resources{qualifier}", page.items.len()))
            })
        },
    );
    if !json_output {
        finish_test_output(print_test_result(&resources_result, verbose), || {
            client.close()
        })?;
    }
    results.push(resources_result);

    let prompts_result = capabilities.prompts.as_ref().map_or_else(
        || skipped_test("list_prompts", "server did not advertise prompts"),
        |_| {
            run_test("list_prompts", || {
                let page = client.list_prompts_page(
                    None,
                    ListPageLimits::new(CLI_OUTPUT_MAX_ITEMS, INSPECT_CATEGORY_MAX_BYTES),
                )?;
                let qualifier = if page.local_truncated || page.peer_has_more {
                    " in the bounded first page; more were omitted"
                } else {
                    ""
                };
                Ok(format!("{} prompts{qualifier}", page.items.len()))
            })
        },
    );
    if !json_output {
        finish_test_output(print_test_result(&prompts_result, verbose), || {
            client.close()
        })?;
    }
    results.push(prompts_result);

    // Explicit cleanup is part of the test result. A separate live Unix
    // process-group anchor pins group identity while the requested MCP peer
    // runs directly as its sibling; unsupported platforms fail during connect.
    let cleanup_start = Instant::now();
    let cleanup_result = match client.close() {
        Ok(()) => TestResult {
            name: "cleanup".to_owned(),
            success: true,
            skipped: false,
            duration_ms: cleanup_start.elapsed().as_secs_f64() * 1000.0,
            details: Some("owned subprocess group stopped".to_owned()),
            error: None,
            timeout_source: None,
            mutation: OutputMutationMetadata::default(),
        },
        Err(error) => failed_test_result("cleanup", cleanup_start.elapsed(), &error),
    };
    if !json_output {
        finish_test_output(print_test_result(&cleanup_result, verbose), || {
            client.close()
        })?;
    }
    results.push(cleanup_result);

    // Build report
    let all_passed = results.iter().all(|r| r.success);
    let total_duration_ms = total_start.elapsed().as_secs_f64() * 1000.0;

    let report = TestReport {
        server: server.to_string(),
        success: all_passed,
        tests: results,
        total_duration_ms,
    };

    finish_test_output(write_test_report(&report, json_output), || client.close())?;

    if all_passed {
        Ok(())
    } else {
        Err(fastmcp_core::McpError::internal_error("Some tests failed"))
    }
}

/// Run a single test and measure its duration.
fn run_test<F>(name: &str, test_fn: F) -> TestResult
where
    F: FnOnce() -> McpResult<String>,
{
    let start = std::time::Instant::now();
    match test_fn() {
        Ok(details) => {
            let (details, mutation) = sanitize_peer_text_with_metadata(&details, PEER_DETAIL_LIMIT);
            TestResult {
                name: name.to_string(),
                success: true,
                skipped: false,
                duration_ms: start.elapsed().as_secs_f64() * 1000.0,
                details: (!details.is_empty()).then_some(details),
                error: None,
                timeout_source: None,
                mutation,
            }
        }
        Err(error) => failed_test_result(name, start.elapsed(), &error),
    }
}

fn skipped_test(name: &str, reason: &str) -> TestResult {
    TestResult {
        name: name.to_owned(),
        success: true,
        skipped: true,
        duration_ms: 0.0,
        details: Some(reason.to_owned()),
        error: None,
        timeout_source: None,
        mutation: OutputMutationMetadata::default(),
    }
}

/// Print a single test result.
fn print_test_result(result: &TestResult, verbose: bool) -> McpResult<()> {
    let line = render_test_result(result, verbose);
    write_stdout(&line, "test output", true)
}

fn render_test_result(result: &TestResult, verbose: bool) -> String {
    let status = if result.skipped {
        "-"
    } else if result.success {
        "✓"
    } else {
        "✗"
    };
    let name = sanitize_peer_text(&result.name, PEER_FIELD_LIMIT);
    let duration = result.duration_ms;

    let mut line = if result.success {
        if let Some(details) = &result.details {
            if details.is_empty() {
                format!("  {status} {name}: {duration:.1}ms")
            } else {
                let details = sanitize_peer_text(details, PEER_DETAIL_LIMIT);
                format!("  {status} {name}: {duration:.1}ms ({details})")
            }
        } else {
            format!("  {status} {name}: {duration:.1}ms")
        }
    } else {
        let mut line = format!("  {status} {name}: {duration:.1}ms");
        if verbose {
            if let Some(error) = &result.error {
                line.push_str("\n      Error: ");
                line.push_str(&sanitize_peer_text(error, PEER_DETAIL_LIMIT));
            }
        }
        line
    };
    if line.len() > PEER_DETAIL_LIMIT.saturating_add(PEER_FIELD_LIMIT) {
        line = sanitize_terminal_text_with_limit(
            &line,
            PEER_DETAIL_LIMIT.saturating_add(PEER_FIELD_LIMIT),
        );
    }
    line
}

// ============================================================================
// Dev Command
// ============================================================================

/// Configuration for dev mode.
struct DevConfig {
    target: String,
    reload_dirs: Vec<PathBuf>,
    reload_patterns: Vec<String>,
    no_reload: bool,
    debounce_ms: u64,
    clear: bool,
    env: Vec<String>,
    protocol_policy: CliProtocolPolicy,
    verbose: bool,
}

fn poll_dev_signal(signal: &mut asupersync::signal::Signal) -> bool {
    use std::future::Future as _;

    let mut receive = std::pin::pin!(signal.recv());
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    matches!(
        receive.as_mut().poll(&mut context),
        std::task::Poll::Ready(Some(()))
    )
}

struct DevShutdownSignals {
    interrupt: asupersync::signal::Signal,
    terminate: asupersync::signal::Signal,
    hangup: asupersync::signal::Signal,
    quit: asupersync::signal::Signal,
    pipe: asupersync::signal::Signal,
}

fn dev_shutdown_requested(signals: &mut Option<DevShutdownSignals>) -> bool {
    signals.as_mut().is_some_and(|signals| {
        poll_dev_signal(&mut signals.interrupt)
            || poll_dev_signal(&mut signals.terminate)
            || poll_dev_signal(&mut signals.hangup)
            || poll_dev_signal(&mut signals.quit)
            || poll_dev_signal(&mut signals.pipe)
    })
}

const DEV_PROCESS_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(20);
const DEV_PROCESS_GRACE_PERIOD: std::time::Duration = std::time::Duration::from_secs(2);
const DEV_PROCESS_REAP_PERIOD: std::time::Duration = std::time::Duration::from_secs(2);
#[cfg(unix)]
const DEV_GROUP_CLEANUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(4);
#[cfg(target_os = "linux")]
const DEV_GROUP_INSPECTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);
#[cfg(all(unix, not(target_os = "linux")))]
const DEV_GROUP_STATUS_OUTPUT_MAX_BYTES: usize = 64 * 1024;
const DEV_BUILD_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(15);
const DEV_BUILD_CAPTURE_LIMIT: usize = 256 * 1024;
const DEV_BUILD_RENDER_LIMIT: usize = 32 * 1024;
const DEV_DIAGNOSTIC_MAX_SECRETS: usize = 128;
const DEV_DIAGNOSTIC_MAX_SECRET_BYTES: usize = 16 * 1024;
const DEV_DIAGNOSTIC_MAX_TOTAL_SECRET_BYTES: usize = 64 * 1024;
const DEV_DIAGNOSTIC_MATCH_BUDGET: usize = 8 * 1024 * 1024;

// The wrapper is the managed process-group leader. A signal-immune watchdog is
// created before the actual command and blocks on a private stdin control pipe
// retained only by the CLI owner. Owner death or dropping the child handle
// closes that pipe, so the watchdog TERM-then-KILLs the remaining group and
// itself. The same watchdog remains an in-group identity anchor through normal
// leader exit. After leader reap, Rust closes the control pipe and performs
// only bounded, read-only group observation; Drop never signals a remembered
// numeric PGID.
#[cfg(unix)]
const DEV_UNIX_GROUP_WRAPPER: &str = r#"
trap 'exit 143' HUP INT TERM
watchdog_ready=0
trap 'watchdog_ready=1' USR1
owned_group_leader=$$
# POSIX permits an asynchronous list to receive /dev/null as stdin when job
# control is disabled. Preserve the private control pipe on another descriptor
# before starting the watchdog, then explicitly restore it as that subshell's
# stdin. Close the duplicate everywhere before launching the managed command.
exec 3<&0
(
    trap '' HUP INT TERM
    kill -USR1 "$owned_group_leader" 2>/dev/null || exit 125
    # The CLI never writes control data. EOF proves that its only writer was
    # closed normally or by owner death. The managed command receives
    # /dev/null instead, so it cannot consume or retain the ownership channel.
    IFS= read -r _ || :
    # POSIX PID 0 targets this watchdog's current process group. The wrapper
    # created that group exclusively for the managed command, and the
    # watchdog ignores TERM so it can perform the forced-stop pass below.
    kill -TERM 0 2>/dev/null || :
    sleep 1
    kill -KILL 0 2>/dev/null || :
) <&3 3<&- >/dev/null 2>&1 &
owned_group_watchdog=$!
exec 3<&-
while [ "$watchdog_ready" -eq 0 ]; do
    kill -0 "$owned_group_watchdog" 2>/dev/null || exit 125
    sleep 0.01
done
trap - USR1
"$@" </dev/null &
owned_child=$!
wait "$owned_child"
exit $?
"#;

fn owned_dev_command(program: &str, arguments: &[String]) -> asupersync::process::Command {
    #[cfg(unix)]
    let mut command = {
        let mut command = asupersync::process::Command::new("/bin/sh");
        command
            .arg("-c")
            .arg(DEV_UNIX_GROUP_WRAPPER)
            .arg("fastmcp-dev-owned-process")
            .arg(program)
            .args(arguments)
            .process_group_mode(asupersync::process::ProcessGroupMode::NewProcessGroup)
            .signal_target(asupersync::process::ProcessSignalTarget::ProcessGroup);
        command
    };

    #[cfg(not(unix))]
    let mut command = {
        let mut command = asupersync::process::Command::new(program);
        command.args(arguments);
        command
    };

    #[cfg(unix)]
    {
        // The private pipe is the fail-safe custody mechanism. Unlike
        // asupersync's process-group kill-on-drop, closing it never signals a
        // recycled numeric PGID: the live in-group watchdog acts on PID 0.
        command
            .stdin(asupersync::process::Stdio::Pipe)
            .kill_on_drop(false);
    }
    #[cfg(not(unix))]
    command.kill_on_drop(true);
    command
}

#[cfg(unix)]
fn kernel_process_group_exists(process_group_id: i32) -> McpResult<bool> {
    let process_group_id = rustix::process::Pid::from_raw(process_group_id).ok_or_else(|| {
        fastmcp_core::McpError::internal_error(
            "Managed development process group has an invalid identifier",
        )
    })?;

    // This is POSIX `kill(-pgid, 0)`: despite the syscall name it transmits no
    // signal and only checks whether the numeric group currently has members.
    // A post-reap PGID reuse can therefore cause only a conservative false
    // positive; it can never signal the unrelated replacement group.
    match rustix::process::test_kill_process_group(process_group_id) {
        Ok(()) => Ok(true),
        // POSIX permits EPERM when the group exists but one or more members
        // are not signalable by this process. For signal 0 that is still
        // affirmative existence evidence; treating it as an observation
        // failure makes ordinary macOS watchdog cleanup fail spuriously.
        Err(rustix::io::Errno::PERM) => Ok(true),
        Err(rustix::io::Errno::SRCH) => Ok(false),
        Err(_) => Err(fastmcp_core::McpError::internal_error(
            "Managed-process-group observation failed",
        )),
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn non_linux_process_group_has_live_member(process_group_id: i32) -> McpResult<bool> {
    if process_group_id <= 0 {
        return Err(fastmcp_core::McpError::internal_error(
            "Managed development process group has an invalid identifier",
        ));
    }

    // BSD/macOS `kill(-pgid, 0)` reports zombie-only groups as present. Ask
    // the platform process table for the fixed-width state field so bounded
    // cleanup can distinguish dead members from runnable or sleeping work.
    // The absolute binary path and decimal PGID avoid shell or PATH custody.
    let output = Command::new("/bin/ps")
        .args(["-o", "state=", "-g", process_group_id.to_string().as_str()])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| {
            fastmcp_core::McpError::internal_error(
                "Managed-process-group liveness inspection failed",
            )
        })?;

    if output.stdout.len() > DEV_GROUP_STATUS_OUTPUT_MAX_BYTES {
        // Conservatively retain ownership when an unexpectedly large group
        // cannot be classified within the fixed observation bound.
        return Ok(true);
    }
    if !output.status.success() {
        return if !kernel_process_group_exists(process_group_id)? {
            Ok(false)
        } else {
            Err(fastmcp_core::McpError::internal_error(
                "Managed-process-group liveness inspection failed",
            ))
        };
    }

    Ok(output.stdout.split(|byte| *byte == b'\n').any(|line| {
        line.iter()
            .copied()
            .find(|byte| !byte.is_ascii_whitespace())
            .is_some_and(|state| state != b'Z')
    }))
}

fn wait_for_owned_dev_group_cleanup(child: &mut asupersync::process::Child) -> McpResult<()> {
    // Closing the only owner-side writer releases the signal-immune watchdog.
    // It targets its still-pinned current group, never a remembered numeric
    // identifier. Repeated calls are harmless once the handle is taken.
    drop(child.stdin());
    #[cfg(unix)]
    {
        let process_group_id = child.process_group_id().ok_or_else(|| {
            fastmcp_core::McpError::internal_error(
                "Owned development process has no managed process-group identifier",
            )
        })?;
        let deadline = std::time::Instant::now() + DEV_GROUP_CLEANUP_TIMEOUT;
        loop {
            if !kernel_process_group_exists(process_group_id)? {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                #[cfg(target_os = "linux")]
                {
                    // Linux `kill(-pgid, 0)` reports zombie-only groups as
                    // present. Prove the group has no live member twice before
                    // accepting that delayed orphan reaping is the only thing
                    // keeping the numeric group visible.
                    let inspection_deadline = std::time::Instant::now()
                        .checked_add(DEV_GROUP_INSPECTION_TIMEOUT)
                        .unwrap_or_else(std::time::Instant::now);
                    if !linux_process_group_has_live_member(process_group_id, inspection_deadline)?
                    {
                        std::thread::sleep(DEV_PROCESS_POLL_INTERVAL);
                        let second_inspection_deadline = std::time::Instant::now()
                            .checked_add(DEV_GROUP_INSPECTION_TIMEOUT)
                            .unwrap_or_else(std::time::Instant::now);
                        if !linux_process_group_has_live_member(
                            process_group_id,
                            second_inspection_deadline,
                        )? {
                            return Ok(());
                        }
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    if !non_linux_process_group_has_live_member(process_group_id)? {
                        std::thread::sleep(DEV_PROCESS_POLL_INTERVAL);
                        if !non_linux_process_group_has_live_member(process_group_id)? {
                            return Ok(());
                        }
                    }
                }
                return Err(fastmcp_core::McpError::internal_error(
                    "Managed development process group remained live after leader reap",
                ));
            }
            std::thread::sleep(DEV_PROCESS_POLL_INTERVAL);
        }
    }

    #[cfg(not(unix))]
    {
        let _ = child;
        Ok(())
    }
}

fn observe_child_after_failed_signal(
    child: &mut asupersync::process::Child,
    action: &str,
    signal_error: &dyn std::fmt::Display,
) -> McpResult<()> {
    let deadline = std::time::Instant::now() + DEV_PROCESS_REAP_PERIOD;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return wait_for_owned_dev_group_cleanup(child),
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(DEV_PROCESS_POLL_INTERVAL);
            }
            Ok(None) => {
                return Err(fastmcp_core::McpError::internal_error(format!(
                    "The owned development process remained live after {action} failed: {signal_error}"
                )));
            }
            Err(wait_error) => {
                return Err(fastmcp_core::McpError::internal_error(format!(
                    "Development-process ownership became uncertain after {action} failed: {wait_error}"
                )));
            }
        }
    }
}

fn stop_dev_server(child: &mut asupersync::process::Child) -> McpResult<()> {
    #[cfg(unix)]
    if let Err(signal_error) = child.signal(15) {
        return match child.try_wait() {
            Ok(Some(_)) => wait_for_owned_dev_group_cleanup(child),
            Ok(None) => observe_child_after_failed_signal(
                child,
                "the graceful-shutdown signal",
                &signal_error,
            ),
            // Do not issue another explicit numeric signal after ownership
            // became uncertain. The still-armed child guard performs the
            // final owned-child cleanup when this function returns.
            Err(wait_error) => Err(fastmcp_core::McpError::internal_error(format!(
                "Development-process ownership became uncertain after a shutdown error: {wait_error}"
            ))),
        };
    }

    #[cfg(not(unix))]
    if let Err(kill_error) = child.kill() {
        return observe_child_after_failed_signal(child, "the force-stop signal", &kill_error);
    }

    let graceful_deadline = std::time::Instant::now() + DEV_PROCESS_GRACE_PERIOD;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return wait_for_owned_dev_group_cleanup(child),
            Ok(None) if std::time::Instant::now() < graceful_deadline => {
                std::thread::sleep(DEV_PROCESS_POLL_INTERVAL);
            }
            Ok(None) => break,
            Err(error) => {
                return Err(fastmcp_core::McpError::internal_error(format!(
                    "Development-process ownership became uncertain while stopping: {error}"
                )));
            }
        }
    }

    if let Err(kill_error) = child.kill() {
        return observe_child_after_failed_signal(child, "the force-stop signal", &kill_error);
    }

    let reap_deadline = std::time::Instant::now() + DEV_PROCESS_REAP_PERIOD;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return wait_for_owned_dev_group_cleanup(child),
            Ok(None) if std::time::Instant::now() < reap_deadline => {
                std::thread::sleep(DEV_PROCESS_POLL_INTERVAL);
            }
            Ok(None) => {
                return Err(fastmcp_core::McpError::internal_error(
                    "Owned development process did not become reapable after forced shutdown",
                ));
            }
            Err(error) => {
                return Err(fastmcp_core::McpError::internal_error(format!(
                    "Development-process ownership became uncertain while reaping: {error}"
                )));
            }
        }
    }
}

#[derive(Default)]
struct BoundedDevCapture {
    bytes: Vec<u8>,
    truncated: bool,
    eof: bool,
}

fn poll_bounded_dev_capture<R>(
    reader: &mut Option<R>,
    capture: &mut BoundedDevCapture,
) -> io::Result<bool>
where
    R: asupersync::io::AsyncRead + Unpin,
{
    use asupersync::io::ReadBuf;
    use std::task::{Context, Poll, Waker};

    let mut made_progress = false;
    for _ in 0..16 {
        let Some(stream) = reader.as_mut() else {
            capture.eof = true;
            break;
        };
        let mut buffer = [0_u8; 8 * 1024];
        let mut read_buffer = ReadBuf::new(&mut buffer);
        let mut context = Context::from_waker(Waker::noop());
        match std::pin::Pin::new(stream).poll_read(&mut context, &mut read_buffer) {
            Poll::Pending => break,
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::WouldBlock => break,
            Poll::Ready(Err(error)) => return Err(error),
            Poll::Ready(Ok(())) => {
                let bytes = read_buffer.filled();
                if bytes.is_empty() {
                    capture.eof = true;
                    *reader = None;
                    break;
                }
                made_progress = true;
                let remaining = DEV_BUILD_CAPTURE_LIMIT.saturating_sub(capture.bytes.len());
                let retained = remaining.min(bytes.len());
                capture.bytes.extend_from_slice(&bytes[..retained]);
                capture.truncated |= retained < bytes.len();
            }
        }
    }
    Ok(made_progress)
}

fn push_dev_diagnostic_byte(rendered: &mut String, byte: u8) -> bool {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    if matches!(byte, b'\n' | b'\t') || byte.is_ascii_graphic() || byte == b' ' {
        if rendered.len() == DEV_BUILD_RENDER_LIMIT {
            return false;
        }
        rendered.push(char::from(byte));
        return true;
    }

    if rendered.len().saturating_add(4) > DEV_BUILD_RENDER_LIMIT {
        return false;
    }
    rendered.push('\\');
    rendered.push('x');
    rendered.push(char::from(HEX[usize::from(byte >> 4)]));
    rendered.push(char::from(HEX[usize::from(byte & 0x0f)]));
    true
}

fn push_dev_diagnostic_marker(rendered: &mut String) -> bool {
    if rendered.len().saturating_add(REDACTED_ENV_VALUE.len()) > DEV_BUILD_RENDER_LIMIT {
        return false;
    }
    rendered.push_str(REDACTED_ENV_VALUE);
    true
}

fn dev_diagnostic_output_contains_secret(
    rendered: &[u8],
    buckets: &[Vec<&[u8]>; 256],
    comparison_budget: &mut usize,
) -> bool {
    for index in 0..rendered.len() {
        let remaining = &rendered[index..];
        for secret in &buckets[usize::from(remaining[0])] {
            if remaining.len() < secret.len() {
                continue;
            }
            if secret.len() > *comparison_budget {
                // Failing closed is required here: returning partially
                // verified diagnostics would weaken the no-secret contract.
                return true;
            }
            *comparison_budget -= secret.len();
            if &remaining[..secret.len()] == *secret {
                return true;
            }
        }
    }
    false
}

fn redacted_dev_text_with_budget(
    bytes: &[u8],
    env_vars: &HashMap<String, String>,
    capture_truncated: bool,
    mut comparison_budget: usize,
) -> String {
    if bytes.len() > DEV_BUILD_CAPTURE_LIMIT {
        return String::new();
    }

    let mut secrets = Vec::new();
    let mut total_secret_bytes = 0_usize;
    for value in env_vars.values() {
        let secret = value.as_bytes();
        if secret.is_empty() {
            continue;
        }
        if secret.len() > DEV_DIAGNOSTIC_MAX_SECRET_BYTES
            || secrets.len() == DEV_DIAGNOSTIC_MAX_SECRETS
        {
            return String::new();
        }
        let Some(new_total) = total_secret_bytes.checked_add(secret.len()) else {
            return String::new();
        };
        if new_total > DEV_DIAGNOSTIC_MAX_TOTAL_SECRET_BYTES {
            return String::new();
        }
        total_secret_bytes = new_total;
        secrets.push(secret);
    }
    secrets.sort_unstable();
    secrets.dedup();

    let mut buckets: [Vec<&[u8]>; 256] = std::array::from_fn(|_| Vec::new());
    for &secret in &secrets {
        buckets[usize::from(secret[0])].push(secret);
    }
    for bucket in &mut buckets {
        bucket.sort_unstable_by(|left, right| {
            right.len().cmp(&left.len()).then_with(|| left.cmp(right))
        });
    }

    // Work directly on input bytes. Markers are emitted into a separate
    // buffer and are never recursively transformed, so a one-byte secret
    // cannot expand the placeholder. A retained final prefix is masked only
    // when the capture layer reports that it discarded bytes. The complete
    // rendered output is then verified because escaping, markers, and joining
    // surrounding fragments can synthesize a secret that was not contiguous
    // in the input.
    let mut rendered = String::with_capacity(bytes.len().min(DEV_BUILD_RENDER_LIMIT));
    let mut index = 0_usize;
    while index < bytes.len() {
        let remaining = &bytes[index..];
        let mut matched = None;
        for secret in &buckets[usize::from(remaining[0])] {
            let secret = *secret;
            let compared = remaining.len().min(secret.len());
            if compared > comparison_budget {
                return String::new();
            }
            comparison_budget -= compared;

            let exact = remaining.len() >= secret.len() && &remaining[..secret.len()] == secret;
            let truncated_prefix = capture_truncated
                && remaining.len() < secret.len()
                && remaining == &secret[..remaining.len()];
            if exact || truncated_prefix {
                matched = Some(if exact { secret.len() } else { remaining.len() });
                break;
            }
        }

        if let Some(matched_len) = matched {
            if !push_dev_diagnostic_marker(&mut rendered) {
                break;
            }
            index += matched_len;
        } else {
            if !push_dev_diagnostic_byte(&mut rendered, remaining[0]) {
                break;
            }
            index += 1;
        }
    }
    if dev_diagnostic_output_contains_secret(rendered.as_bytes(), &buckets, &mut comparison_budget)
    {
        String::new()
    } else {
        rendered
    }
}

fn redacted_dev_text(
    bytes: &[u8],
    env_vars: &HashMap<String, String>,
    capture_truncated: bool,
) -> String {
    redacted_dev_text_with_budget(
        bytes,
        env_vars,
        capture_truncated,
        DEV_DIAGNOSTIC_MATCH_BUDGET,
    )
}

enum DevBuildOutcome {
    Succeeded,
    Failed {
        stdout: BoundedDevCapture,
        stderr: BoundedDevCapture,
    },
    Shutdown,
}

fn run_dev_build(
    target_path: &Path,
    env_vars: &HashMap<String, String>,
    shutdown_signals: &mut Option<DevShutdownSignals>,
) -> McpResult<DevBuildOutcome> {
    let mut command = owned_dev_command("cargo", &["build".to_owned()]);
    command
        .current_dir(target_path)
        .envs(env_vars)
        .stdout(asupersync::process::Stdio::Pipe)
        .stderr(asupersync::process::Stdio::Pipe);
    let mut child = command.spawn().map_err(|error| {
        fastmcp_core::McpError::internal_error(format!(
            "Failed to start bounded development build: {}",
            redacted_dev_text(error.to_string().as_bytes(), env_vars, false)
        ))
    })?;
    let mut stdout = child.stdout();
    let mut stderr = child.stderr();
    let mut stdout_capture = BoundedDevCapture::default();
    let mut stderr_capture = BoundedDevCapture::default();
    let build_deadline = std::time::Instant::now() + DEV_BUILD_TIMEOUT;
    let mut exit_status = None;
    let mut post_exit_deadline = None;

    loop {
        let stdout_progress = match poll_bounded_dev_capture(&mut stdout, &mut stdout_capture) {
            Ok(progress) => progress,
            Err(error) => {
                let error = redacted_dev_text(error.to_string().as_bytes(), env_vars, false);
                if exit_status.is_none()
                    && let Err(cleanup_error) = stop_dev_server(&mut child)
                {
                    return Err(fastmcp_core::McpError::internal_error(format!(
                        "Failed to capture development-build stdout ({error}); bounded cleanup also failed: {cleanup_error}"
                    )));
                }
                return Err(fastmcp_core::McpError::internal_error(format!(
                    "Failed to capture development-build stdout: {error}"
                )));
            }
        };
        let stderr_progress = match poll_bounded_dev_capture(&mut stderr, &mut stderr_capture) {
            Ok(progress) => progress,
            Err(error) => {
                let error = redacted_dev_text(error.to_string().as_bytes(), env_vars, false);
                if exit_status.is_none()
                    && let Err(cleanup_error) = stop_dev_server(&mut child)
                {
                    return Err(fastmcp_core::McpError::internal_error(format!(
                        "Failed to capture development-build stderr ({error}); bounded cleanup also failed: {cleanup_error}"
                    )));
                }
                return Err(fastmcp_core::McpError::internal_error(format!(
                    "Failed to capture development-build stderr: {error}"
                )));
            }
        };

        if exit_status.is_some() && stdout_capture.eof && stderr_capture.eof {
            break;
        }
        if dev_shutdown_requested(shutdown_signals) {
            if exit_status.is_none() {
                stop_dev_server(&mut child)?;
            }
            return Ok(DevBuildOutcome::Shutdown);
        }

        if exit_status.is_none() {
            match child.try_wait() {
                Ok(Some(status)) => {
                    wait_for_owned_dev_group_cleanup(&mut child)?;
                    exit_status = Some(status);
                    post_exit_deadline = Some(std::time::Instant::now() + DEV_PROCESS_REAP_PERIOD);
                }
                Ok(None) => {}
                Err(error) => {
                    // Fail closed without another explicit numeric signal.
                    // The armed child guard performs final cleanup on drop.
                    return Err(fastmcp_core::McpError::internal_error(format!(
                        "Development-build process ownership became uncertain: {}",
                        redacted_dev_text(error.to_string().as_bytes(), env_vars, false)
                    )));
                }
            }
        }

        let now = std::time::Instant::now();
        if exit_status.is_none() && now >= build_deadline {
            stop_dev_server(&mut child)?;
            return Err(fastmcp_core::McpError::internal_error(format!(
                "Development build exceeded its {} second deadline",
                DEV_BUILD_TIMEOUT.as_secs()
            )));
        }
        if post_exit_deadline.is_some_and(|deadline| now >= deadline) {
            return Err(fastmcp_core::McpError::internal_error(
                "Development-build output pipes remained open after bounded process-group cleanup",
            ));
        }
        if !stdout_progress && !stderr_progress {
            std::thread::sleep(DEV_PROCESS_POLL_INTERVAL);
        }
    }

    let status = exit_status.ok_or_else(|| {
        fastmcp_core::McpError::internal_error(
            "Development-build output closed before a process status was observed",
        )
    })?;
    if status.success() {
        Ok(DevBuildOutcome::Succeeded)
    } else {
        Ok(DevBuildOutcome::Failed {
            stdout: stdout_capture,
            stderr: stderr_capture,
        })
    }
}

struct DevReloadWake {
    pending: std::sync::atomic::AtomicBool,
    last_change: std::sync::Mutex<Option<std::time::Instant>>,
    watcher_error: std::sync::Mutex<Option<String>>,
}

impl DevReloadWake {
    fn new() -> Self {
        Self {
            pending: std::sync::atomic::AtomicBool::new(false),
            last_change: std::sync::Mutex::new(None),
            watcher_error: std::sync::Mutex::new(None),
        }
    }
}

fn record_dev_watcher_error(
    wake: &DevReloadWake,
    sender: &std::sync::mpsc::SyncSender<()>,
    error: &notify::Error,
) {
    let mut watcher_error = wake
        .watcher_error
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if watcher_error.is_none() {
        *watcher_error = Some(sanitize_terminal_text(&error.to_string()));
    }
    drop(watcher_error);

    // Wake the main loop without relying on the reload-pending flag. A full
    // capacity-one queue already guarantees that the loop will wake and
    // inspect the terminal watcher error.
    let _ = sender.try_send(());
}

fn take_dev_watcher_error(wake: &DevReloadWake) -> Option<String> {
    wake.watcher_error
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
}

fn coalesce_dev_reload_wakeup(
    wake: &DevReloadWake,
    sender: &std::sync::mpsc::SyncSender<()>,
    now: std::time::Instant,
) {
    use std::sync::atomic::Ordering;

    let mut last_change = wake
        .last_change
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *last_change = Some(now);
    if wake
        .pending
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        // Capacity one plus a false->true send makes file-event storms consume
        // constant memory. A full queue already contains the required wakeup.
        let _ = sender.try_send(());
    }
}

fn take_due_dev_reload(wake: &DevReloadWake, debounce: std::time::Duration) -> bool {
    use std::sync::atomic::Ordering;

    let mut last_change = wake
        .last_change
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let due = last_change.is_some_and(|at| at.elapsed() >= debounce);
    if due
        && wake
            .pending
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    {
        *last_change = None;
        true
    } else {
        false
    }
}

fn write_dev_status(arguments: std::fmt::Arguments<'_>) -> McpResult<()> {
    write_stdout(&arguments.to_string(), "development status output", true)
}

fn return_dev_error_with_cleanup(
    child: &mut Option<asupersync::process::Child>,
    operation_error: fastmcp_core::McpError,
) -> McpResult<()> {
    if let Some(mut running_child) = child.take()
        && let Err(cleanup_error) = stop_dev_server(&mut running_child)
    {
        return Err(fastmcp_core::McpError::internal_error(format!(
            "{operation_error}; bounded server cleanup also failed: {cleanup_error}"
        )));
    }
    Err(operation_error)
}

fn write_dev_status_with_cleanup(
    child: &mut Option<asupersync::process::Child>,
    arguments: std::fmt::Arguments<'_>,
) -> McpResult<()> {
    let Err(output_error) = write_dev_status(arguments) else {
        return Ok(());
    };
    return_dev_error_with_cleanup(child, output_error)
}

/// Dev command: Run server in development mode with hot reloading.
fn cmd_dev(config: DevConfig) -> McpResult<()> {
    #[cfg(unix)]
    {
        cmd_dev_supported(config)
    }

    #[cfg(not(unix))]
    {
        let _ = config;
        Err(fastmcp_core::McpError::internal_error(
            "fastmcp dev is unsupported on non-Unix platforms until bounded pipe I/O and owned process-tree shutdown are available",
        ))
    }
}

#[cfg_attr(not(unix), allow(dead_code))]
fn cmd_dev_supported(config: DevConfig) -> McpResult<()> {
    use console::{Term, style};
    use notify::{Config as NotifyConfig, RecommendedWatcher, RecursiveMode, Watcher};
    use std::sync::mpsc;
    use std::time::Duration;

    let term = Term::stdout();

    let env_vars = dev_launch_environment(
        parse_environment_assignments(&config.env)?,
        config.protocol_policy,
    )?;

    let mut shutdown_signals = Some(DevShutdownSignals {
        interrupt: asupersync::signal::signal(asupersync::signal::SignalKind::interrupt())
            .map_err(|error| {
                fastmcp_core::McpError::internal_error(format!(
                    "Failed to register Ctrl+C handler: {error}"
                ))
            })?,
        terminate: asupersync::signal::signal(asupersync::signal::SignalKind::terminate())
            .map_err(|error| {
                fastmcp_core::McpError::internal_error(format!(
                    "Failed to register termination handler: {error}"
                ))
            })?,
        hangup: asupersync::signal::signal(asupersync::signal::SignalKind::hangup()).map_err(
            |error| {
                fastmcp_core::McpError::internal_error(format!(
                    "Failed to register hangup handler: {error}"
                ))
            },
        )?,
        quit: asupersync::signal::signal(asupersync::signal::SignalKind::quit()).map_err(
            |error| {
                fastmcp_core::McpError::internal_error(format!(
                    "Failed to register quit handler: {error}"
                ))
            },
        )?,
        pipe: asupersync::signal::signal(asupersync::signal::SignalKind::pipe()).map_err(
            |error| {
                fastmcp_core::McpError::internal_error(format!(
                    "Failed to register broken-pipe handler: {error}"
                ))
            },
        )?,
    });

    let patterns: Vec<glob::Pattern> = config
        .reload_patterns
        .iter()
        .map(|p| {
            glob::Pattern::new(p).map_err(|e| {
                fastmcp_core::McpError::internal_error(format!(
                    "Invalid reload pattern {}: {}",
                    sanitize_terminal_text(p),
                    sanitize_terminal_text(&e.to_string())
                ))
            })
        })
        .collect::<McpResult<Vec<_>>>()?;

    // Determine if this is a Cargo project
    let raw_target_path = PathBuf::from(&config.target);
    let is_cargo_project = raw_target_path.is_dir() && raw_target_path.join("Cargo.toml").is_file();
    let target_path = if is_cargo_project {
        raw_target_path.canonicalize().map_err(|error| {
            fastmcp_core::McpError::invalid_params(format!(
                "Failed to resolve Cargo project {}: {error}",
                sanitize_terminal_text(raw_target_path.to_string_lossy().as_ref())
            ))
        })?
    } else {
        raw_target_path
    };
    let watch_root = if is_cargo_project {
        target_path.clone()
    } else {
        std::env::current_dir()
            .and_then(|path| path.canonicalize())
            .map_err(|error| {
                fastmcp_core::McpError::internal_error(format!(
                    "Failed to determine development watch root: {error}"
                ))
            })?
    };
    let watch_paths = if config.no_reload {
        Vec::new()
    } else {
        let paths = config
            .reload_dirs
            .iter()
            .map(|dir| {
                let candidate = if dir.is_absolute() {
                    dir.clone()
                } else {
                    watch_root.join(dir)
                };
                let resolved = candidate.canonicalize().map_err(|error| {
                    fastmcp_core::McpError::invalid_params(format!(
                        "Failed to resolve reload directory {}: {error}",
                        sanitize_terminal_text(candidate.to_string_lossy().as_ref())
                    ))
                })?;
                if !resolved.is_dir() {
                    return Err(fastmcp_core::McpError::invalid_params(format!(
                        "Reload path is not a directory: {}",
                        sanitize_terminal_text(resolved.to_string_lossy().as_ref())
                    )));
                }
                Ok(resolved)
            })
            .collect::<McpResult<Vec<_>>>()?;
        if paths.is_empty() {
            return Err(fastmcp_core::McpError::invalid_params(
                "Development reload requires at least one existing watch directory",
            ));
        }
        paths
    };

    // Print startup message through a fallible path. Once a child is live,
    // every output failure is coupled to explicit bounded cleanup below.
    write_dev_status(format_args!(
        "{} {} Development mode",
        style("▶").green().bold(),
        style("fastmcp").cyan().bold()
    ))?;
    let displayed_target = sanitize_terminal_text(target_path.to_string_lossy().as_ref());
    write_dev_status(format_args!(
        "  Target: {}",
        style(&displayed_target).yellow()
    ))?;
    if !config.no_reload {
        let mut displayed_watch_paths = String::new();
        for path in &config.reload_dirs {
            let path = sanitize_terminal_text(path.to_string_lossy().as_ref());
            if !push_bounded_terminal_component(&mut displayed_watch_paths, ", ", &path) {
                break;
            }
        }
        write_dev_status(format_args!(
            "  Watching: {}",
            style(displayed_watch_paths).dim()
        ))?;
    }
    write_dev_status(format_args!(""))?;

    // A `None` result means a shutdown signal arrived during the bounded
    // build. A non-zero Cargo status remains recoverable in reload mode.
    let build_project =
        |verbose: bool, signals: &mut Option<DevShutdownSignals>| -> McpResult<Option<bool>> {
            if !is_cargo_project {
                return Ok(Some(true));
            }

            write_dev_status(format_args!("{} Building...", style("🔨").bold()))?;
            match run_dev_build(&target_path, &env_vars, signals)? {
                DevBuildOutcome::Succeeded => {
                    write_dev_status(format_args!(
                        "{} Build successful",
                        style("✓").green().bold()
                    ))?;
                    Ok(Some(true))
                }
                DevBuildOutcome::Failed { stdout, stderr } => {
                    write_dev_status(format_args!("{} Build failed", style("✗").red().bold()))?;
                    if verbose {
                        let mut remaining_lines = 40_usize;
                        for capture in [&stderr, &stdout] {
                            let rendered =
                                redacted_dev_text(&capture.bytes, &env_vars, capture.truncated);
                            for line in rendered.lines().take(remaining_lines) {
                                write_dev_status(format_args!("  {}", style(line).red()))?;
                                remaining_lines = remaining_lines.saturating_sub(1);
                            }
                            if capture.truncated {
                                write_dev_status(format_args!(
                                    "  {}",
                                    style("[diagnostics truncated]").dim()
                                ))?;
                            }
                            if remaining_lines == 0 {
                                break;
                            }
                        }
                    }
                    Ok(Some(false))
                }
                DevBuildOutcome::Shutdown => Ok(None),
            }
        };

    // Function to start the server
    let start_server =
        |env_vars: &HashMap<String, String>| -> McpResult<Option<asupersync::process::Child>> {
            let (cmd, args) = if is_cargo_project {
                ("cargo".to_string(), vec!["run".to_string()])
            } else {
                (config.target.clone(), vec![])
            };

            write_dev_status(format_args!("{} Starting server...", style("🚀").bold()))?;

            let mut command = owned_dev_command(&cmd, &args);
            command
                .envs(env_vars)
                .stdout(asupersync::process::Stdio::Inherit)
                .stderr(asupersync::process::Stdio::Inherit);
            if is_cargo_project {
                command.current_dir(&target_path);
            }

            match command.spawn() {
                Ok(child) => {
                    let pid = child
                        .id()
                        .map_or_else(|| "unavailable".to_owned(), |pid| pid.to_string());
                    let mut owned_child = Some(child);
                    write_dev_status_with_cleanup(
                        &mut owned_child,
                        format_args!(
                            "{} Server running (PID: {})",
                            style("✓").green().bold(),
                            pid
                        ),
                    )?;
                    Ok(owned_child)
                }
                Err(error) => {
                    let error = sanitize_terminal_text(&error.to_string());
                    write_dev_status(format_args!(
                        "{} Failed to start server: {}",
                        style("✗").red().bold(),
                        error
                    ))?;
                    Ok(None)
                }
            }
        };

    // No-reload mode needs no watcher, but still uses the same bounded build
    // and owned-process shutdown path.
    if config.no_reload {
        let Some(initial_build_succeeded) = build_project(config.verbose, &mut shutdown_signals)?
        else {
            return Ok(());
        };
        if !initial_build_succeeded {
            return Err(fastmcp_core::McpError::internal_error(
                "Initial development build failed",
            ));
        }
        if dev_shutdown_requested(&mut shutdown_signals) {
            return Ok(());
        }
        let mut child = start_server(&env_vars)?.ok_or_else(|| {
            fastmcp_core::McpError::internal_error("Failed to start development server")
        })?;
        loop {
            if dev_shutdown_requested(&mut shutdown_signals) {
                stop_dev_server(&mut child)?;
                return Ok(());
            }
            match child.try_wait() {
                Ok(Some(status)) if status.success() => {
                    wait_for_owned_dev_group_cleanup(&mut child)?;
                    return Ok(());
                }
                Ok(Some(status)) => {
                    wait_for_owned_dev_group_cleanup(&mut child)?;
                    return Err(child_exit_error("Development server", status.code()));
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(error) => {
                    // Ownership is uncertain, so do not issue another
                    // explicit signal. The armed child guard remains the
                    // final cleanup backstop.
                    return Err(fastmcp_core::McpError::internal_error(format!(
                        "Development-server process ownership became uncertain: {error}"
                    )));
                }
            }
        }
    }

    // Set up file watcher
    let (tx, rx) = mpsc::sync_channel(1);
    let reload_wake = std::sync::Arc::new(DevReloadWake::new());
    let callback_reload_wake = reload_wake.clone();
    let target_root = watch_root.clone();
    let ignored_build_dir = is_cargo_project.then(|| {
        let configured_target_dir = env_vars
            .get("CARGO_TARGET_DIR")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from));
        let path = configured_target_dir.map_or_else(
            || target_root.join("target"),
            |path| {
                if path.is_absolute() {
                    path
                } else {
                    target_root.join(path)
                }
            },
        );
        path.canonicalize().unwrap_or(path)
    });
    let patterns_for_cb = patterns.clone();

    let mut watcher = RecommendedWatcher::new(
        move |res: Result<notify::Event, notify::Error>| match res {
            Ok(event) => {
                // Check if any path matches our patterns
                let should_rebuild = event.paths.iter().any(|path| {
                    // Skip only this project's effective Cargo build directory;
                    // a source directory merely named `target` elsewhere is valid.
                    if ignored_build_dir
                        .as_ref()
                        .is_some_and(|build_dir| path.starts_with(build_dir))
                    {
                        return false;
                    }

                    // Match against user-specified reload patterns (relative to the target root).
                    // Normalize to forward slashes to match common glob patterns.
                    let rel = path.strip_prefix(&target_root).unwrap_or(path);
                    let rel_str = rel.to_string_lossy().replace('\\', "/");

                    if patterns_for_cb.is_empty() {
                        rel.extension()
                            .and_then(|ext| ext.to_str())
                            .is_some_and(|ext| {
                                ext.eq_ignore_ascii_case("rs") || ext.eq_ignore_ascii_case("toml")
                            })
                    } else {
                        patterns_for_cb.iter().any(|p| p.matches(&rel_str))
                    }
                });

                if should_rebuild {
                    coalesce_dev_reload_wakeup(
                        &callback_reload_wake,
                        &tx,
                        std::time::Instant::now(),
                    );
                }
            }
            Err(error) => {
                record_dev_watcher_error(&callback_reload_wake, &tx, &error);
            }
        },
        NotifyConfig::default().with_poll_interval(Duration::from_millis(100)),
    )
    .map_err(|e| {
        fastmcp_core::McpError::internal_error(format!(
            "Failed to create watcher: {}",
            sanitize_terminal_text(&e.to_string())
        ))
    })?;

    // Watch directories
    for watch_path in &watch_paths {
        watcher
            .watch(watch_path, RecursiveMode::Recursive)
            .map_err(|e| {
                fastmcp_core::McpError::internal_error(format!(
                    "Failed to watch {}: {}",
                    sanitize_terminal_text(watch_path.to_string_lossy().as_ref()),
                    sanitize_terminal_text(&e.to_string())
                ))
            })?;
    }

    // Register every watch before starting either the initial build child or
    // the server. Setup failures therefore happen before child ownership, and
    // changes during the initial build remain queued for a follow-up pass.
    let Some(initial_build_succeeded) = build_project(config.verbose, &mut shutdown_signals)?
    else {
        return Ok(());
    };
    if let Some(error) = take_dev_watcher_error(&reload_wake) {
        return Err(fastmcp_core::McpError::internal_error(format!(
            "Development file watcher failed: {error}"
        )));
    }
    if dev_shutdown_requested(&mut shutdown_signals) {
        return Ok(());
    }
    let mut child = if initial_build_succeeded {
        start_server(&env_vars)?
    } else {
        None
    };

    write_dev_status_with_cleanup(
        &mut child,
        format_args!(
            "\n{} Watching for changes... (Ctrl+C to stop)\n",
            style("👀").bold()
        ),
    )?;

    // Main loop
    let debounce_duration = Duration::from_millis(config.debounce_ms);

    loop {
        if dev_shutdown_requested(&mut shutdown_signals) {
            break;
        }
        // Check for file changes with timeout
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(()) => {}
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // No new events in this tick; fall through to debounce + child-exit checks.
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if let Some(mut running_child) = child.take() {
                    if let Err(cleanup_error) = stop_dev_server(&mut running_child) {
                        return Err(fastmcp_core::McpError::internal_error(format!(
                            "Development file-watcher channel disconnected; bounded server cleanup also failed: {cleanup_error}"
                        )));
                    }
                }
                return Err(fastmcp_core::McpError::internal_error(
                    "Development file-watcher channel disconnected",
                ));
            }
        }

        if let Some(error) = take_dev_watcher_error(&reload_wake) {
            if let Some(mut running_child) = child.take() {
                if let Err(cleanup_error) = stop_dev_server(&mut running_child) {
                    return Err(fastmcp_core::McpError::internal_error(format!(
                        "Development file watcher failed ({error}); bounded server cleanup also failed: {cleanup_error}"
                    )));
                }
            }
            return Err(fastmcp_core::McpError::internal_error(format!(
                "Development file watcher failed: {error}"
            )));
        }

        if dev_shutdown_requested(&mut shutdown_signals) {
            break;
        }

        if take_due_dev_reload(&reload_wake, debounce_duration) {
            if config.clear && term.clear_screen().is_err() {
                return return_dev_error_with_cleanup(
                    &mut child,
                    fastmcp_core::McpError::internal_error(
                        "Failed to clear the development-status terminal",
                    ),
                );
            }

            write_dev_status_with_cleanup(
                &mut child,
                format_args!("\n{} Change detected, rebuilding...", style("🔄").bold()),
            )?;

            if let Some(mut c) = child.take() {
                stop_dev_server(&mut c)?;
            }

            let Some(build_succeeded) = build_project(config.verbose, &mut shutdown_signals)?
            else {
                return Ok(());
            };
            if let Some(error) = take_dev_watcher_error(&reload_wake) {
                return Err(fastmcp_core::McpError::internal_error(format!(
                    "Development file watcher failed: {error}"
                )));
            }
            if build_succeeded {
                child = start_server(&env_vars)?;
            }

            write_dev_status_with_cleanup(
                &mut child,
                format_args!("\n{} Watching for changes...\n", style("👀").bold()),
            )?;
        }

        // Check if child has exited
        if let Some(ref mut c) = child {
            match c.try_wait() {
                Ok(Some(status)) => {
                    wait_for_owned_dev_group_cleanup(c)?;
                    if status.success() {
                        write_dev_status(format_args!(
                            "\n{} Server exited normally",
                            style("ℹ").blue().bold()
                        ))?;
                    } else {
                        write_dev_status(format_args!(
                            "\n{} Server exited with error ({})",
                            style("⚠").yellow().bold(),
                            status
                        ))?;
                    }
                    write_dev_status(format_args!(
                        "{} Waiting for changes...\n",
                        style("👀").bold()
                    ))?;
                    child = None;
                }
                Ok(None) => {
                    // Still running
                }
                Err(error) => {
                    // Do not repeatedly inspect uncertain process state. The
                    // armed child guard performs final cleanup on return.
                    return Err(fastmcp_core::McpError::internal_error(format!(
                        "Development-server process ownership became uncertain: {error}"
                    )));
                }
            }
        }
    }

    // Cleanup
    if let Some(mut c) = child {
        stop_dev_server(&mut c)?;
    }

    Ok(())
}

/// Inspect command: Connect to a server and display its capabilities.
async fn cmd_inspect(
    cx: &Cx,
    server: &str,
    args: &[String],
    format: InspectFormat,
    output: Option<&std::path::Path>,
    protocol_policy: CliProtocolPolicy,
) -> McpResult<()> {
    validate_cli_protocol_policy(protocol_policy)?;
    let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();

    // Connect to the server
    let mut client = client_builder_for_protocol_policy(protocol_policy)?
        .connect_stdio_with_cx(server, &args_refs, cx)
        .await?;
    let negotiated_protocol_version = client.protocol_version().to_owned();

    // Preserve the negotiated era's capability model. Modern discovery is an
    // open final model, so rendering it through the legacy capability struct
    // would silently discard advertised final members.
    let inspection = (|| {
        let server_info = client.server_info().clone();
        let capabilities = stdio_inspect_capabilities(&client)?;

        // Acquire one bounded page per category. MCP's list requests have no item
        // limit, so the transport may still receive one bounded protocol message,
        // but inspect never follows cursors into the client's much larger default
        // auto-pagination budget.
        let limits = ListPageLimits::new(CLI_OUTPUT_MAX_ITEMS, INSPECT_CATEGORY_MAX_BYTES);
        let mut acquisition_truncated = false;
        let tools = if capabilities.advertises("tools") {
            let page = client.list_tools_page(None, limits)?;
            acquisition_truncated |= page.local_truncated || page.peer_has_more;
            page.items
        } else {
            Vec::new()
        };

        let resources = if capabilities.advertises("resources") {
            let page = client.list_resources_page(None, limits)?;
            acquisition_truncated |= page.local_truncated || page.peer_has_more;
            page.items
        } else {
            Vec::new()
        };

        let resource_templates = if capabilities.advertises("resources") {
            let page = client.list_resource_templates_page(None, limits)?;
            acquisition_truncated |= page.local_truncated || page.peer_has_more;
            page.items
        } else {
            Vec::new()
        };

        let prompts = if capabilities.advertises("prompts") {
            let page = client.list_prompts_page(None, limits)?;
            acquisition_truncated |= page.local_truncated || page.peer_has_more;
            page.items
        } else {
            Vec::new()
        };

        Ok((
            server_info,
            capabilities,
            tools,
            resources,
            resource_templates,
            prompts,
            acquisition_truncated,
        ))
    })();
    let (
        server_info,
        capabilities,
        tools,
        resources,
        resource_templates,
        prompts,
        acquisition_truncated,
    ) = finish_inspect_acquisition(inspection, || client.close())?;
    let protocol_status =
        InspectProtocolStatus::new(protocol_policy, &negotiated_protocol_version)?;

    write_inspect_report(
        &server_info,
        &capabilities,
        &tools,
        &resources,
        &resource_templates,
        &prompts,
        acquisition_truncated,
        protocol_status,
        format,
        output,
    )
}

/// Ensures a live stdio inspect client is explicitly closed after either a
/// successful catalog acquisition or a rejected capability/list response.
///
/// `Client::drop` is only a best-effort backstop: a command must surface an
/// unverified cleanup rather than silently replacing a bounded lifecycle
/// outcome with destructor behavior.
fn finish_inspect_acquisition<T, F>(acquisition: McpResult<T>, cleanup: F) -> McpResult<T>
where
    F: FnOnce() -> McpResult<()>,
{
    let cleanup_started = std::time::Instant::now();
    match (acquisition, cleanup()) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(acquisition_error), Ok(())) => Err(acquisition_error),
        (Ok(_), Err(cleanup_error)) => Err(fastmcp_core::McpError::with_data(
            fastmcp_core::McpErrorCode::InternalError,
            format!("inspect client cleanup failed: {cleanup_error}"),
            serde_json::json!({
                CLIENT_CLEANUP_UNVERIFIED_DATA_KEY: true,
                "cleanup": cleanup_error,
                CLIENT_CLEANUP_DURATION_MS_DATA_KEY:
                    cleanup_started.elapsed().as_secs_f64() * 1_000.0,
            }),
        )),
        (Err(acquisition_error), Err(cleanup_error)) => Err(fastmcp_core::McpError::with_data(
            fastmcp_core::McpErrorCode::InternalError,
            format!("inspect client cleanup failed after an acquisition failure: {cleanup_error}"),
            serde_json::json!({
                CLIENT_CLEANUP_UNVERIFIED_DATA_KEY: true,
                "operation": acquisition_error,
                "cleanup": cleanup_error,
                CLIENT_CLEANUP_DURATION_MS_DATA_KEY:
                    cleanup_started.elapsed().as_secs_f64() * 1_000.0,
            }),
        )),
    }
}

/// Capability representation retained by inspect for the negotiated protocol
/// era. Only exact 2024-11-05 sessions use the legacy capability shape; final
/// discovery is retained as its complete protocol object.
#[derive(Clone, Debug)]
enum InspectCapabilities {
    Legacy(fastmcp_protocol::ServerCapabilities),
    /// Final discovery capabilities are an open object. Retain its complete
    /// object shape so the inspect renderer never recasts a modern peer into
    /// the closed legacy capability model.
    Final(serde_json::Map<String, serde_json::Value>),
}

impl InspectCapabilities {
    fn advertises(&self, member: &str) -> bool {
        match self {
            Self::Legacy(capabilities) => match member {
                "tools" => capabilities.tools.is_some(),
                "resources" => capabilities.resources.is_some(),
                "prompts" => capabilities.prompts.is_some(),
                "logging" => capabilities.logging.is_some(),
                _ => false,
            },
            Self::Final(capabilities) => capabilities.contains_key(member),
        }
    }

    fn final_from_discovery(
        capabilities: &fastmcp_protocol::ServerDiscoverCapabilities,
        source: &str,
    ) -> McpResult<Self> {
        let capabilities = serde_json::to_value(capabilities).map_err(|error| {
            fastmcp_core::McpError::internal_error(format!(
                "inspect could not serialize final {source} capabilities: {error}"
            ))
        })?;
        let serde_json::Value::Object(capabilities) = capabilities else {
            return Err(fastmcp_core::McpError::internal_error(format!(
                "inspect received non-object final {source} capabilities"
            )));
        };
        Ok(Self::Final(capabilities))
    }

    fn text_summary(&self) -> String {
        match self {
            Self::Legacy(capabilities) => format!(
                "Capabilities: tools={} resources={} prompts={} logging={}",
                capabilities.tools.is_some(),
                capabilities.resources.is_some(),
                capabilities.prompts.is_some(),
                capabilities.logging.is_some(),
            ),
            Self::Final(capabilities) => {
                let mut budget = JsonPreviewBudget::default();
                let preview = bounded_json_preview_inner(
                    &serde_json::Value::Object(capabilities.clone()),
                    0,
                    &mut budget,
                );
                let rendered = serde_json::to_string(&preview)
                    .unwrap_or_else(|_| "<unrenderable final capabilities>".to_owned());
                format!("Capabilities (final discovery): {rendered}")
            }
        }
    }

    fn json_value(&self, budget: &mut JsonPreviewBudget) -> serde_json::Value {
        match self {
            Self::Legacy(capabilities) => serde_json::json!({
                "tools": capabilities.tools.is_some(),
                "resources": capabilities.resources.is_some(),
                "prompts": capabilities.prompts.is_some(),
                "logging": capabilities.logging.is_some(),
            }),
            Self::Final(capabilities) => bounded_json_preview_inner(
                &serde_json::Value::Object(capabilities.clone()),
                0,
                budget,
            ),
        }
    }
}

/// Returns the capability model for the era actually selected by a completed
/// stdio negotiation. Final peers retain `server/discover`; legacy peers use
/// only the exact initialized 2024-11-05 model. A missing selected era is a
/// connection invariant failure, not an empty catalog.
fn stdio_inspect_capabilities(client: &Client) -> McpResult<InspectCapabilities> {
    match client.selected_protocol_era() {
        Some(ProtocolEra::Modern2026) => {
            let discovery = client.server_discovery().ok_or_else(|| {
                fastmcp_core::McpError::internal_error(
                    "modern stdio inspect completed without a server/discover result",
                )
            })?;
            InspectCapabilities::final_from_discovery(discovery.capabilities(), "server/discover")
        }
        #[cfg(feature = "legacy-2024-11-05")]
        Some(ProtocolEra::Legacy2024) => Ok(InspectCapabilities::Legacy(
            client.server_capabilities().clone(),
        )),
        #[cfg(not(feature = "legacy-2024-11-05"))]
        Some(_) => Err(fastmcp_core::McpError::invalid_params(format!(
            "FeatureUnavailable: {} is compiled out; legacy stdio inspection cannot run",
            LEGACY_PROTOCOL_POLICY_FEATURE,
        ))),
        None => Err(fastmcp_core::McpError::internal_error(
            "stdio inspect completed without a selected protocol era",
        )),
    }
}

/// Builds the immutable, explicit HTTP endpoint plan accepted by `inspect`.
///
/// Every supplied route is parsed independently and passed unchanged to the
/// client's negotiation authority. This command never derives a legacy route
/// from the modern URL, a discovery response, or an endpoint event.
fn http_inspect_protocol_plan(
    http_url: Option<&str>,
    legacy_sse_url: Option<&str>,
    legacy_message_url: Option<&str>,
    protocol_policy: CliProtocolPolicy,
) -> McpResult<ClientProtocolPlan> {
    validate_cli_protocol_policy(protocol_policy)?;
    #[cfg(not(feature = "legacy-2024-11-05"))]
    if legacy_sse_url.is_some() || legacy_message_url.is_some() {
        return Err(fastmcp_core::McpError::invalid_params(format!(
            "FeatureUnavailable: {} is compiled out; --legacy-sse-url and --legacy-message-url are unavailable",
            LEGACY_PROTOCOL_POLICY_FEATURE,
        )));
    }
    let modern_post = parse_http_inspect_endpoint(http_url, "--http-url")?;
    let legacy_sse = parse_http_inspect_endpoint(legacy_sse_url, "--legacy-sse-url")?;
    let legacy_message_post =
        parse_http_inspect_endpoint(legacy_message_url, "--legacy-message-url")?;
    ClientProtocolPlan::http(
        protocol_policy.protocol_policy(),
        modern_post,
        legacy_sse,
        legacy_message_post,
        "fastmcp-cli-inspect".to_owned(),
        "fastmcp-cli-inspect".to_owned(),
        "fastmcp-cli-inspect-http".to_owned(),
        1,
        1,
        1,
    )
    .map_err(|error| {
        fastmcp_core::McpError::invalid_params(format!("invalid HTTP endpoint bundle: {error}"))
    })
}

fn parse_http_inspect_endpoint(
    endpoint: Option<&str>,
    flag: &str,
) -> McpResult<Option<CanonicalHttpUrl>> {
    endpoint
        .map(|endpoint| {
            CanonicalHttpUrl::parse(endpoint).map_err(|error| {
                fastmcp_core::McpError::invalid_params(format!("invalid {flag}: {error}"))
            })
        })
        .transpose()
}

/// Inspects an explicit, policy-bound HTTP endpoint bundle through the
/// shipped dual-era client.
async fn cmd_inspect_http(
    cx: &Cx,
    http_url: Option<&str>,
    legacy_sse_url: Option<&str>,
    legacy_message_url: Option<&str>,
    format: InspectFormat,
    output: Option<&std::path::Path>,
    protocol_policy: CliProtocolPolicy,
) -> McpResult<()> {
    validate_cli_protocol_policy(protocol_policy)?;
    let protocol_plan = http_inspect_protocol_plan(
        http_url,
        legacy_sse_url,
        legacy_message_url,
        protocol_policy,
    )?;
    let mut client = Client::http_with_cx(protocol_plan, cx)
        .await
        .map_err(|error| {
            fastmcp_core::McpError::internal_error(format!(
                "inspect could not connect to the configured HTTP endpoint bundle: {error}"
            ))
        })?;

    let negotiated_version = client.connection().protocol_version().ok_or_else(|| {
        fastmcp_core::McpError::internal_error(
            "HTTP inspect completed without a negotiated protocol version",
        )
    })?;
    let protocol_status = InspectProtocolStatus::new(protocol_policy, negotiated_version)?;
    let server_info = client.server_info().clone();
    let capabilities = http_inspect_capabilities(&client)?;
    let (acquisition_truncated, tools, resources, resource_templates, prompts) =
        http_inspect_catalogs(cx, &mut client, &capabilities).await?;

    write_inspect_report(
        &server_info,
        &capabilities,
        &tools,
        &resources,
        &resource_templates,
        &prompts,
        acquisition_truncated,
        protocol_status,
        format,
        output,
    )
}

fn http_inspect_capabilities(
    client: &fastmcp_client::HttpClient,
) -> McpResult<InspectCapabilities> {
    match client.selected_protocol_era() {
        ProtocolEra::Modern2026 => {
            let discovery = client.server_discovery().ok_or_else(|| {
                fastmcp_core::McpError::internal_error(
                    "modern HTTP inspect completed without a server/discover result",
                )
            })?;
            InspectCapabilities::final_from_discovery(discovery.capabilities(), "server/discover")
        }
        #[cfg(feature = "legacy-2024-11-05")]
        ProtocolEra::Legacy2024 => client
            .legacy_server_capabilities()
            .cloned()
            .map(InspectCapabilities::Legacy)
            .ok_or_else(|| {
                fastmcp_core::McpError::internal_error(
                    "legacy HTTP inspect completed without initialize capabilities",
                )
            }),
        #[cfg(not(feature = "legacy-2024-11-05"))]
        _ => Err(fastmcp_core::McpError::invalid_params(format!(
            "FeatureUnavailable: {} is compiled out; legacy HTTP inspection cannot run",
            LEGACY_PROTOCOL_POLICY_FEATURE,
        ))),
    }
}

#[allow(clippy::type_complexity)]
async fn http_inspect_catalogs(
    cx: &Cx,
    client: &mut fastmcp_client::HttpClient,
    capabilities: &InspectCapabilities,
) -> McpResult<(
    bool,
    Vec<fastmcp_protocol::Tool>,
    Vec<fastmcp_protocol::Resource>,
    Vec<fastmcp_protocol::ResourceTemplate>,
    Vec<fastmcp_protocol::Prompt>,
)> {
    let mut acquisition_truncated = false;
    let tools = if capabilities.advertises("tools") {
        let (items, truncated) =
            http_inspect_tools_result(http_inspect_core_request(cx, client, "tools/list").await?)?;
        acquisition_truncated |= truncated;
        items
    } else {
        Vec::new()
    };
    let resources = if capabilities.advertises("resources") {
        let (items, truncated) = http_inspect_resources_result(
            http_inspect_core_request(cx, client, "resources/list").await?,
        )?;
        acquisition_truncated |= truncated;
        items
    } else {
        Vec::new()
    };
    let resource_templates = if capabilities.advertises("resources") {
        let (items, truncated) = http_inspect_resource_templates_result(
            http_inspect_core_request(cx, client, "resources/templates/list").await?,
        )?;
        acquisition_truncated |= truncated;
        items
    } else {
        Vec::new()
    };
    let prompts = if capabilities.advertises("prompts") {
        let (items, truncated) = http_inspect_prompts_result(
            http_inspect_core_request(cx, client, "prompts/list").await?,
        )?;
        acquisition_truncated |= truncated;
        items
    } else {
        Vec::new()
    };
    Ok((
        acquisition_truncated,
        tools,
        resources,
        resource_templates,
        prompts,
    ))
}

async fn http_inspect_core_request(
    cx: &Cx,
    client: &mut fastmcp_client::HttpClient,
    method: &'static str,
) -> McpResult<fastmcp_client::CoreResult> {
    client
        .request_final_core(cx, method, serde_json::json!({}))
        .await
        .map_err(|error| {
            fastmcp_core::McpError::internal_error(format!(
                "inspect HTTP {method} request failed: {error}"
            ))
        })
}

fn http_inspect_tools_result(
    result: fastmcp_client::CoreResult,
) -> McpResult<(Vec<fastmcp_protocol::Tool>, bool)> {
    match result {
        #[cfg(feature = "legacy-2024-11-05")]
        fastmcp_client::CoreResult::Legacy(fastmcp_client::LegacyCoreResult::ToolsList(result)) => {
            Ok((result.tools, result.next_cursor.is_some()))
        }
        fastmcp_client::CoreResult::Final(fastmcp_client::FinalCoreResult::ToolsList {
            result,
            ..
        }) => Ok((
            project_final_for_inspect(result.payload.tools, "tools/list")?,
            result.payload.next_cursor.is_some(),
        )),
        _ => Err(unexpected_http_inspect_result("tools/list")),
    }
}

fn http_inspect_resources_result(
    result: fastmcp_client::CoreResult,
) -> McpResult<(Vec<fastmcp_protocol::Resource>, bool)> {
    match result {
        #[cfg(feature = "legacy-2024-11-05")]
        fastmcp_client::CoreResult::Legacy(fastmcp_client::LegacyCoreResult::ResourcesList(
            result,
        )) => Ok((result.resources, result.next_cursor.is_some())),
        fastmcp_client::CoreResult::Final(fastmcp_client::FinalCoreResult::ResourcesList {
            result,
            ..
        }) => Ok((
            project_final_for_inspect(result.payload.resources, "resources/list")?,
            result.payload.next_cursor.is_some(),
        )),
        _ => Err(unexpected_http_inspect_result("resources/list")),
    }
}

fn http_inspect_resource_templates_result(
    result: fastmcp_client::CoreResult,
) -> McpResult<(Vec<fastmcp_protocol::ResourceTemplate>, bool)> {
    match result {
        #[cfg(feature = "legacy-2024-11-05")]
        fastmcp_client::CoreResult::Legacy(
            fastmcp_client::LegacyCoreResult::ResourceTemplatesList(result),
        ) => Ok((result.resource_templates, result.next_cursor.is_some())),
        fastmcp_client::CoreResult::Final(
            fastmcp_client::FinalCoreResult::ResourceTemplatesList { result, .. },
        ) => Ok((
            project_final_for_inspect(
                result.payload.resource_templates,
                "resources/templates/list",
            )?,
            result.payload.next_cursor.is_some(),
        )),
        _ => Err(unexpected_http_inspect_result("resources/templates/list")),
    }
}

fn http_inspect_prompts_result(
    result: fastmcp_client::CoreResult,
) -> McpResult<(Vec<fastmcp_protocol::Prompt>, bool)> {
    match result {
        #[cfg(feature = "legacy-2024-11-05")]
        fastmcp_client::CoreResult::Legacy(fastmcp_client::LegacyCoreResult::PromptsList(
            result,
        )) => Ok((result.prompts, result.next_cursor.is_some())),
        fastmcp_client::CoreResult::Final(fastmcp_client::FinalCoreResult::PromptsList {
            result,
            ..
        }) => Ok((
            project_final_for_inspect(result.payload.prompts, "prompts/list")?,
            result.payload.next_cursor.is_some(),
        )),
        _ => Err(unexpected_http_inspect_result("prompts/list")),
    }
}

fn unexpected_http_inspect_result(method: &str) -> fastmcp_core::McpError {
    fastmcp_core::McpError::internal_error(format!(
        "HTTP inspect received an unexpected selected-era result for {method}",
    ))
}

/// Projects typed final catalog items into the inspect catalog display model.
/// Final discovery capabilities never pass through this helper: inspect retains
/// and renders their complete final capability object separately.
fn project_final_for_inspect<T, U>(value: T, source: &str) -> McpResult<U>
where
    T: Serialize,
    U: DeserializeOwned,
{
    let value = serde_json::to_value(value).map_err(|error| {
        fastmcp_core::McpError::internal_error(format!(
            "inspect could not serialize typed final {source} data: {error}"
        ))
    })?;
    serde_json::from_value(value).map_err(|error| {
        fastmcp_core::McpError::internal_error(format!(
            "inspect could not render typed final {source} data: {error}"
        ))
    })
}

#[allow(clippy::too_many_arguments)]
fn write_inspect_report(
    server_info: &fastmcp_protocol::ServerInfo,
    capabilities: &InspectCapabilities,
    tools: &[fastmcp_protocol::Tool],
    resources: &[fastmcp_protocol::Resource],
    resource_templates: &[fastmcp_protocol::ResourceTemplate],
    prompts: &[fastmcp_protocol::Prompt],
    acquisition_truncated: bool,
    protocol_status: InspectProtocolStatus,
    format: InspectFormat,
    output: Option<&std::path::Path>,
) -> McpResult<()> {
    // Format output
    let output_text = match format {
        InspectFormat::Text => format_inspect_text_for_capabilities_with_truncation(
            server_info,
            capabilities,
            tools,
            resources,
            resource_templates,
            prompts,
            acquisition_truncated,
            protocol_status,
        ),
        InspectFormat::Json => format_inspect_json_for_capabilities_with_truncation(
            server_info,
            capabilities,
            tools,
            resources,
            resource_templates,
            prompts,
            acquisition_truncated,
            protocol_status,
        )?,
    };

    // Write output
    if let Some(path) = output {
        atomic_replace_file(
            path,
            output_text.as_bytes(),
            "inspect output",
            CLI_OUTPUT_MAX_BYTES,
        )?;
    } else {
        write_inspect_stdout(&output_text)?;
    }

    Ok(())
}

#[cfg(test)]
fn format_inspect_text(
    server_info: &fastmcp_protocol::ServerInfo,
    capabilities: &fastmcp_protocol::ServerCapabilities,
    tools: &[fastmcp_protocol::Tool],
    resources: &[fastmcp_protocol::Resource],
    resource_templates: &[fastmcp_protocol::ResourceTemplate],
    prompts: &[fastmcp_protocol::Prompt],
    protocol_status: InspectProtocolStatus,
) -> String {
    format_inspect_text_for_capabilities_with_truncation(
        server_info,
        &InspectCapabilities::Legacy(capabilities.clone()),
        tools,
        resources,
        resource_templates,
        prompts,
        false,
        protocol_status,
    )
}

fn format_inspect_text_for_capabilities_with_truncation(
    server_info: &fastmcp_protocol::ServerInfo,
    capabilities: &InspectCapabilities,
    tools: &[fastmcp_protocol::Tool],
    resources: &[fastmcp_protocol::Resource],
    resource_templates: &[fastmcp_protocol::ResourceTemplate],
    prompts: &[fastmcp_protocol::Prompt],
    acquisition_truncated: bool,
    protocol_status: InspectProtocolStatus,
) -> String {
    let mut out = String::new();

    let _ = push_output_line(
        &mut out,
        &format!(
            "Server: {} v{}",
            sanitize_peer_text(&server_info.name, PEER_FIELD_LIMIT),
            sanitize_peer_text(&server_info.version, PEER_FIELD_LIMIT)
        ),
    );
    let _ = push_output_line(
        &mut out,
        &format!(
            "Protocol: policy={} version={} era={}",
            protocol_status.policy.server_launch_value(),
            protocol_status.version.as_str(),
            protocol_status.era_name(),
        ),
    );
    let _ = push_output_line(&mut out, &capabilities.text_summary());
    let _ = push_output_line(&mut out, "");
    if acquisition_truncated {
        let _ = push_output_line(
            &mut out,
            "Data truncated: only the first bounded page of each category was acquired.",
        );
        let _ = push_output_line(&mut out, "");
    }

    if !tools.is_empty() {
        let _ = push_output_line(&mut out, &format!("Tools ({}):", tools.len()));
        let mut rendered = 0usize;
        for tool in tools.iter().take(CLI_OUTPUT_MAX_ITEMS) {
            let mut line = format!("  - {}", sanitize_peer_text(&tool.name, PEER_FIELD_LIMIT));
            if let Some(desc) = &tool.description {
                line.push_str(": ");
                line.push_str(&sanitize_peer_text(desc, PEER_DETAIL_LIMIT));
            }
            if !push_output_line(&mut out, &line) {
                return out;
            }
            rendered += 1;
        }
        let omitted = tools.len().saturating_sub(rendered);
        if omitted > 0 {
            let _ = push_output_line(&mut out, &format!("  ...[{omitted} tools omitted]"));
        }
        let _ = push_output_line(&mut out, "");
    }

    if !resources.is_empty() {
        let _ = push_output_line(&mut out, &format!("Resources ({}):", resources.len()));
        let mut rendered = 0usize;
        for resource in resources.iter().take(CLI_OUTPUT_MAX_ITEMS) {
            let mut line = format!(
                "  - {}",
                sanitize_peer_text(&resource.uri, PEER_FIELD_LIMIT)
            );
            if !resource.name.is_empty() {
                line.push_str(" (");
                line.push_str(&sanitize_peer_text(&resource.name, PEER_FIELD_LIMIT));
                line.push(')');
            }
            if !push_output_line(&mut out, &line) {
                return out;
            }
            rendered += 1;
        }
        let omitted = resources.len().saturating_sub(rendered);
        if omitted > 0 {
            let _ = push_output_line(&mut out, &format!("  ...[{omitted} resources omitted]"));
        }
        let _ = push_output_line(&mut out, "");
    }

    if !resource_templates.is_empty() {
        let _ = push_output_line(
            &mut out,
            &format!("Resource Templates ({}):", resource_templates.len()),
        );
        let mut rendered = 0usize;
        for template in resource_templates.iter().take(CLI_OUTPUT_MAX_ITEMS) {
            let mut line = format!(
                "  - {}",
                sanitize_peer_text(&template.uri_template, PEER_FIELD_LIMIT)
            );
            if !template.name.is_empty() {
                line.push_str(" (");
                line.push_str(&sanitize_peer_text(&template.name, PEER_FIELD_LIMIT));
                line.push(')');
            }
            if !push_output_line(&mut out, &line) {
                return out;
            }
            rendered += 1;
        }
        let omitted = resource_templates.len().saturating_sub(rendered);
        if omitted > 0 {
            let _ = push_output_line(
                &mut out,
                &format!("  ...[{omitted} resource templates omitted]"),
            );
        }
        let _ = push_output_line(&mut out, "");
    }

    if !prompts.is_empty() {
        let _ = push_output_line(&mut out, &format!("Prompts ({}):", prompts.len()));
        let mut rendered = 0usize;
        for prompt in prompts.iter().take(CLI_OUTPUT_MAX_ITEMS) {
            let mut line = format!("  - {}", sanitize_peer_text(&prompt.name, PEER_FIELD_LIMIT));
            if let Some(desc) = &prompt.description {
                line.push_str(": ");
                line.push_str(&sanitize_peer_text(desc, PEER_DETAIL_LIMIT));
            }
            if !push_output_line(&mut out, &line) {
                return out;
            }
            rendered += 1;
        }
        let omitted = prompts.len().saturating_sub(rendered);
        if omitted > 0 {
            let _ = push_output_line(&mut out, &format!("  ...[{omitted} prompts omitted]"));
        }
    }

    out
}

fn write_inspect_output(writer: &mut impl Write, output: &str) -> McpResult<()> {
    write_stdout_output(writer, output, "inspect output", false)
}

fn write_inspect_stdout(output: &str) -> McpResult<()> {
    let stdout = io::stdout();
    write_inspect_output(&mut stdout.lock(), output)
}

fn bounded_json_string(value: &str, budget: &mut JsonPreviewBudget) -> serde_json::Value {
    let limit = JSON_PREVIEW_MAX_STRING_CHARS.min(budget.string_chars_remaining);
    let (rendered, mutation) = sanitize_peer_text_with_metadata(value, limit);
    budget.mutation.merge(mutation);
    budget.string_chars_remaining = budget
        .string_chars_remaining
        .saturating_sub(rendered.chars().count());
    serde_json::Value::String(rendered)
}

fn insert_optional_json_string(
    output: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: Option<&str>,
    budget: &mut JsonPreviewBudget,
) {
    if let Some(value) = value {
        output.insert(key.to_owned(), bounded_json_string(value, budget));
    }
}

fn bounded_icon_value(
    icon: &fastmcp_protocol::Icon,
    budget: &mut JsonPreviewBudget,
) -> serde_json::Value {
    let mut output = serde_json::Map::new();
    insert_optional_json_string(&mut output, "src", icon.src.as_deref(), budget);
    insert_optional_json_string(&mut output, "mimeType", icon.mime_type.as_deref(), budget);
    insert_optional_json_string(&mut output, "sizes", icon.sizes.as_deref(), budget);
    serde_json::Value::Object(output)
}

fn bounded_tags_value(tags: &[String], budget: &mut JsonPreviewBudget) -> serde_json::Value {
    budget.mutation.truncated |= tags.len() > JSON_PREVIEW_MAX_CONTAINER_ITEMS;
    serde_json::Value::Array(
        tags.iter()
            .take(JSON_PREVIEW_MAX_CONTAINER_ITEMS)
            .map(|tag| bounded_json_string(tag, budget))
            .collect(),
    )
}

fn bounded_tool_value(
    tool: &fastmcp_protocol::Tool,
    budget: &mut JsonPreviewBudget,
) -> serde_json::Value {
    let mut output = serde_json::Map::new();
    output.insert("name".to_owned(), bounded_json_string(&tool.name, budget));
    insert_optional_json_string(
        &mut output,
        "description",
        tool.description.as_deref(),
        budget,
    );
    output.insert(
        "inputSchema".to_owned(),
        bounded_json_preview_inner(&tool.input_schema, 0, budget),
    );
    if let Some(schema) = &tool.output_schema {
        output.insert(
            "outputSchema".to_owned(),
            bounded_json_preview_inner(schema, 0, budget),
        );
    }
    if let Some(icon) = &tool.icon {
        output.insert("icon".to_owned(), bounded_icon_value(icon, budget));
    }
    insert_optional_json_string(&mut output, "version", tool.version.as_deref(), budget);
    if !tool.tags.is_empty() {
        output.insert("tags".to_owned(), bounded_tags_value(&tool.tags, budget));
    }
    if let Some(annotations) = &tool.annotations {
        let value = serde_json::to_value(annotations)
            .unwrap_or_else(|_| serde_json::Value::Object(serde_json::Map::new()));
        output.insert(
            "annotations".to_owned(),
            bounded_json_preview_inner(&value, 0, budget),
        );
    }
    serde_json::Value::Object(output)
}

fn bounded_resource_value(
    resource: &fastmcp_protocol::Resource,
    budget: &mut JsonPreviewBudget,
) -> serde_json::Value {
    let mut output = serde_json::Map::new();
    output.insert("uri".to_owned(), bounded_json_string(&resource.uri, budget));
    output.insert(
        "name".to_owned(),
        bounded_json_string(&resource.name, budget),
    );
    insert_optional_json_string(
        &mut output,
        "description",
        resource.description.as_deref(),
        budget,
    );
    insert_optional_json_string(
        &mut output,
        "mimeType",
        resource.mime_type.as_deref(),
        budget,
    );
    if let Some(icon) = &resource.icon {
        output.insert("icon".to_owned(), bounded_icon_value(icon, budget));
    }
    insert_optional_json_string(&mut output, "version", resource.version.as_deref(), budget);
    if !resource.tags.is_empty() {
        output.insert(
            "tags".to_owned(),
            bounded_tags_value(&resource.tags, budget),
        );
    }
    serde_json::Value::Object(output)
}

fn bounded_resource_template_value(
    template: &fastmcp_protocol::ResourceTemplate,
    budget: &mut JsonPreviewBudget,
) -> serde_json::Value {
    let mut output = serde_json::Map::new();
    output.insert(
        "uriTemplate".to_owned(),
        bounded_json_string(&template.uri_template, budget),
    );
    output.insert(
        "name".to_owned(),
        bounded_json_string(&template.name, budget),
    );
    insert_optional_json_string(
        &mut output,
        "description",
        template.description.as_deref(),
        budget,
    );
    insert_optional_json_string(
        &mut output,
        "mimeType",
        template.mime_type.as_deref(),
        budget,
    );
    if let Some(icon) = &template.icon {
        output.insert("icon".to_owned(), bounded_icon_value(icon, budget));
    }
    insert_optional_json_string(&mut output, "version", template.version.as_deref(), budget);
    if !template.tags.is_empty() {
        output.insert(
            "tags".to_owned(),
            bounded_tags_value(&template.tags, budget),
        );
    }
    serde_json::Value::Object(output)
}

fn bounded_prompt_value(
    prompt: &fastmcp_protocol::Prompt,
    budget: &mut JsonPreviewBudget,
) -> serde_json::Value {
    let mut output = serde_json::Map::new();
    output.insert("name".to_owned(), bounded_json_string(&prompt.name, budget));
    insert_optional_json_string(
        &mut output,
        "description",
        prompt.description.as_deref(),
        budget,
    );
    if !prompt.arguments.is_empty() {
        budget.mutation.truncated |= prompt.arguments.len() > JSON_PREVIEW_MAX_CONTAINER_ITEMS;
        let arguments = prompt
            .arguments
            .iter()
            .take(JSON_PREVIEW_MAX_CONTAINER_ITEMS)
            .map(|argument| {
                let mut output = serde_json::Map::new();
                output.insert(
                    "name".to_owned(),
                    bounded_json_string(&argument.name, budget),
                );
                insert_optional_json_string(
                    &mut output,
                    "description",
                    argument.description.as_deref(),
                    budget,
                );
                if argument.required {
                    output.insert("required".to_owned(), serde_json::Value::Bool(true));
                }
                serde_json::Value::Object(output)
            })
            .collect();
        output.insert("arguments".to_owned(), serde_json::Value::Array(arguments));
    }
    if let Some(icon) = &prompt.icon {
        output.insert("icon".to_owned(), bounded_icon_value(icon, budget));
    }
    insert_optional_json_string(&mut output, "version", prompt.version.as_deref(), budget);
    if !prompt.tags.is_empty() {
        output.insert("tags".to_owned(), bounded_tags_value(&prompt.tags, budget));
    }
    serde_json::Value::Object(output)
}

#[cfg(test)]
fn format_inspect_json(
    server_info: &fastmcp_protocol::ServerInfo,
    capabilities: &fastmcp_protocol::ServerCapabilities,
    tools: &[fastmcp_protocol::Tool],
    resources: &[fastmcp_protocol::Resource],
    resource_templates: &[fastmcp_protocol::ResourceTemplate],
    prompts: &[fastmcp_protocol::Prompt],
    protocol_status: InspectProtocolStatus,
) -> McpResult<String> {
    format_inspect_json_for_capabilities_with_truncation(
        server_info,
        &InspectCapabilities::Legacy(capabilities.clone()),
        tools,
        resources,
        resource_templates,
        prompts,
        false,
        protocol_status,
    )
}

fn format_inspect_json_for_capabilities_with_truncation(
    server_info: &fastmcp_protocol::ServerInfo,
    capabilities: &InspectCapabilities,
    tools: &[fastmcp_protocol::Tool],
    resources: &[fastmcp_protocol::Resource],
    resource_templates: &[fastmcp_protocol::ResourceTemplate],
    prompts: &[fastmcp_protocol::Prompt],
    acquisition_truncated: bool,
    protocol_status: InspectProtocolStatus,
) -> McpResult<String> {
    let mut budget = JsonPreviewBudget::default();
    let server_name = bounded_json_string(&server_info.name, &mut budget);
    let server_version = bounded_json_string(&server_info.version, &mut budget);
    let tool_values = tools
        .iter()
        .take(CLI_OUTPUT_MAX_ITEMS)
        .map(|tool| bounded_tool_value(tool, &mut budget))
        .collect::<Vec<_>>();
    let resource_values = resources
        .iter()
        .take(CLI_OUTPUT_MAX_ITEMS)
        .map(|resource| bounded_resource_value(resource, &mut budget))
        .collect::<Vec<_>>();
    let template_values = resource_templates
        .iter()
        .take(CLI_OUTPUT_MAX_ITEMS)
        .map(|template| bounded_resource_template_value(template, &mut budget))
        .collect::<Vec<_>>();
    let prompt_values = prompts
        .iter()
        .take(CLI_OUTPUT_MAX_ITEMS)
        .map(|prompt| bounded_prompt_value(prompt, &mut budget))
        .collect::<Vec<_>>();
    let capability_value = capabilities.json_value(&mut budget);
    let truncated = acquisition_truncated
        || tools.len() > tool_values.len()
        || resources.len() > resource_values.len()
        || resource_templates.len() > template_values.len()
        || prompts.len() > prompt_values.len()
        || budget.mutation.truncated;
    budget.mutation.truncated = truncated;
    let output = serde_json::json!({
        "server": {
            "name": server_name,
            "version": server_version,
        },
        "protocol": {
            "policy": protocol_status.policy.server_launch_value(),
            "version": protocol_status.version.as_str(),
            "era": protocol_status.era_name(),
        },
        "capabilities": capability_value,
        "tools": tool_values,
        "resources": resource_values,
        "resource_templates": template_values,
        "prompts": prompt_values,
        "redacted": budget.mutation.redacted,
        "sanitized": budget.mutation.sanitized,
        "truncated": budget.mutation.truncated,
    });

    serde_json::to_string_pretty(&output).map_err(|e| {
        fastmcp_core::McpError::internal_error(format!("JSON serialization error: {e}"))
    })
}

/// Install command: Generate configuration for MCP clients.
fn cmd_install(
    name: &str,
    server: &str,
    args: &[String],
    cwd: Option<&Path>,
    target: InstallTarget,
    dry_run: bool,
    protocol_policy: CliProtocolPolicy,
) -> McpResult<()> {
    validate_cli_protocol_policy(protocol_policy)?;
    let config = generate_server_config(name, server, args, cwd, protocol_policy)?;

    match target {
        InstallTarget::Claude => install_claude_desktop(&config, dry_run),
        InstallTarget::Cursor => install_cursor(&config, dry_run),
        InstallTarget::Cline => install_cline(&config, dry_run),
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
struct McpServerConfig {
    command: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    env: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cwd: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    disabled: bool,
}

fn server_configs_semantically_equal(left: &McpServerConfig, right: &McpServerConfig) -> bool {
    let left_environment = left
        .env
        .as_ref()
        .filter(|environment| !environment.is_empty());
    let right_environment = right
        .env
        .as_ref()
        .filter(|environment| !environment.is_empty());
    left.command == right.command
        && left.args == right.args
        && left_environment == right_environment
        && left.cwd == right.cwd
        && left.disabled == right.disabled
}

/// Client-owned environment entries are retained across install updates. The
/// generated policy always wins for its reserved key, so semantic no-op
/// detection treats an existing retained environment as part of the desired
/// installed state instead of rewriting the same entry on every invocation.
fn install_config_with_preserved_environment(
    existing: &McpServerConfig,
    desired: &McpServerConfig,
) -> McpServerConfig {
    let mut merged = desired.clone();
    let Some(existing_environment) = existing.env.as_ref() else {
        return merged;
    };
    let Some(desired_environment) = merged.env.as_mut() else {
        return merged;
    };

    for (key, value) in existing_environment {
        desired_environment
            .entry(key.clone())
            .or_insert_with(|| value.clone());
    }
    merged
}

fn serialize_server_config_object(
    config: &McpServerConfig,
) -> McpResult<serde_json::Map<String, serde_json::Value>> {
    serde_json::to_value(config)
        .map_err(|_| {
            fastmcp_core::McpError::internal_error("Failed to serialize installation config entry")
        })?
        .as_object()
        .cloned()
        .ok_or_else(|| {
            fastmcp_core::McpError::internal_error(
                "Serialized installation config entry was not a JSON object",
            )
        })
}

fn shape_install_server_entry(
    target: InstallTarget,
    mut server: serde_json::Map<String, serde_json::Value>,
) -> serde_json::Map<String, serde_json::Value> {
    match target {
        InstallTarget::Claude | InstallTarget::Cursor => {
            server.insert(
                "type".to_owned(),
                serde_json::Value::String("stdio".to_owned()),
            );
            server
        }
        InstallTarget::Cline => {
            let disabled = server.remove("disabled");
            server.insert(
                "type".to_owned(),
                serde_json::Value::String("stdio".to_owned()),
            );
            let mut outer = serde_json::Map::new();
            outer.insert("transport".to_owned(), serde_json::Value::Object(server));
            if let Some(disabled) = disabled {
                outer.insert("disabled".to_owned(), disabled);
            }
            outer
        }
    }
}

fn install_entry_has_remote_transport(entry: &serde_json::Map<String, serde_json::Value>) -> bool {
    entry.contains_key("url")
        || entry.contains_key("headers")
        || entry.contains_key("auth")
        || entry.contains_key("oauth")
        || entry
            .get("type")
            .is_some_and(|kind| kind.as_str() != Some("stdio"))
        || entry
            .get("transportType")
            .is_some_and(|kind| kind.as_str() != Some("stdio"))
}

fn has_valid_install_profile_fields(
    target: InstallTarget,
    entry: &serde_json::Map<String, serde_json::Value>,
) -> bool {
    entry.iter().all(|(field, value)| {
        classify_client_server_field(target, field, value) != ClientServerFieldClass::Unsupported
    })
}

fn effective_installed_server_config(
    target: InstallTarget,
    entry: &serde_json::Value,
) -> Option<McpServerConfig> {
    let fields = entry.as_object()?;
    // A FastMCP local install owns neither remote-sync membership nor OAuth
    // state from the previous transport. Their presence must force a real
    // rewrite so merge can clear them before a later semantic no-op.
    if target == InstallTarget::Cline
        && (fields.contains_key("remoteConfigured") || fields.contains_key("oauth"))
    {
        return None;
    }
    if target == InstallTarget::Cline && fields.contains_key("transport") {
        if fields.keys().any(|field| {
            matches!(
                field.as_str(),
                "type"
                    | "transportType"
                    | "command"
                    | "args"
                    | "env"
                    | "cwd"
                    | "url"
                    | "headers"
                    | "auth"
            )
        }) {
            return None;
        }
        let transport = fields.get("transport")?.as_object()?;
        if transport
            .keys()
            .any(|field| !matches!(field.as_str(), "type" | "command" | "args" | "cwd" | "env"))
            || install_entry_has_remote_transport(transport)
            || transport.get("type").and_then(serde_json::Value::as_str) != Some("stdio")
        {
            return None;
        }
        let mut normalized = serde_json::Map::new();
        for field in ["command", "args", "cwd", "env"] {
            if let Some(value) = transport.get(field) {
                normalized.insert(field.to_owned(), value.clone());
            }
        }
        if let Some(disabled) = fields.get("disabled") {
            normalized.insert("disabled".to_owned(), disabled.clone());
        }
        return McpServerConfig::deserialize(serde_json::Value::Object(normalized)).ok();
    }
    if install_entry_has_remote_transport(fields) {
        return None;
    }
    McpServerConfig::deserialize(entry.clone()).ok()
}

fn merge_install_server_entry(
    target: InstallTarget,
    existing: &mut serde_json::Map<String, serde_json::Value>,
    mut desired: serde_json::Map<String, serde_json::Value>,
) {
    merge_existing_install_environment(target, existing, &mut desired);

    for owned_key in [
        "transport",
        "type",
        "transportType",
        "command",
        "args",
        "env",
        "cwd",
        "disabled",
        "url",
        "headers",
        "auth",
        "oauth",
        "remoteConfigured",
    ] {
        existing.remove(owned_key);
    }
    if target != InstallTarget::Cursor {
        // `envFile` is Cursor-owned orthogonal metadata. It must survive a
        // Cursor stdio update but is not meaningful in the other registries.
        existing.remove("envFile");
    }
    existing.extend(desired);
}

/// Preserve client-owned environment entries while making the selected
/// FastMCP launch policy authoritative. Cline's current transport shape nests
/// its environment, while the flat legacy shape is accepted so an update can
/// migrate it without discarding environment entries.
fn merge_existing_install_environment(
    target: InstallTarget,
    existing: &serde_json::Map<String, serde_json::Value>,
    desired: &mut serde_json::Map<String, serde_json::Value>,
) {
    let existing_environment = if target == InstallTarget::Cline {
        existing
            .get("transport")
            .and_then(serde_json::Value::as_object)
            .and_then(|transport| transport.get("env"))
            .or_else(|| existing.get("env"))
    } else {
        existing.get("env")
    };
    let Some(existing_environment) = existing_environment.and_then(serde_json::Value::as_object)
    else {
        return;
    };

    let desired_environment = if target == InstallTarget::Cline {
        desired
            .get_mut("transport")
            .and_then(serde_json::Value::as_object_mut)
            .and_then(|transport| transport.get_mut("env"))
    } else {
        desired.get_mut("env")
    };
    let Some(desired_environment) = desired_environment.and_then(serde_json::Value::as_object_mut)
    else {
        return;
    };

    for (key, value) in existing_environment {
        desired_environment
            .entry(key.clone())
            .or_insert_with(|| value.clone());
    }
}

fn generate_server_config(
    name: &str,
    server: &str,
    args: &[String],
    cwd: Option<&Path>,
    protocol_policy: CliProtocolPolicy,
) -> McpResult<(String, McpServerConfig)> {
    validate_cli_protocol_policy(protocol_policy)?;
    if name.trim().is_empty() {
        return Err(fastmcp_core::McpError::invalid_params(
            "Install server name cannot be empty or whitespace",
        ));
    }
    if server.trim().is_empty() {
        return Err(fastmcp_core::McpError::invalid_params(
            "Install server command cannot be empty or whitespace",
        ));
    }
    if args.len() > CLI_OUTPUT_MAX_ITEMS {
        return Err(fastmcp_core::McpError::invalid_params(format!(
            "Install argument list contains {} entries; maximum accepted count is {CLI_OUTPUT_MAX_ITEMS}",
            args.len()
        )));
    }
    let cwd = cwd
        .map(|path| {
            path.to_str().map(str::to_owned).ok_or_else(|| {
                fastmcp_core::McpError::invalid_params(
                    "Install working directory must be valid UTF-8",
                )
            })
        })
        .transpose()?;
    Ok((
        name.to_string(),
        McpServerConfig {
            command: server.to_string(),
            args: args.to_vec(),
            env: Some(HashMap::from([(
                FASTMCP_PROTOCOL_POLICY_ENV.to_owned(),
                protocol_policy.server_launch_value().to_owned(),
            )])),
            cwd,
            disabled: false,
        },
    ))
}

fn redacted_install_config_snippet(
    registry_name: &str,
    config: &(String, McpServerConfig),
    target: InstallTarget,
) -> McpResult<String> {
    let mut server = serde_json::Map::new();
    server.insert(
        "command".to_owned(),
        serde_json::Value::String(sanitize_peer_text(&config.1.command, PEER_FIELD_LIMIT)),
    );
    server.insert(
        "args".to_owned(),
        serde_json::Value::Array({
            let mut arguments = redacted_arguments(&config.1.args)
                .into_iter()
                .take(CLI_OUTPUT_MAX_ITEMS)
                .map(serde_json::Value::String)
                .collect::<Vec<_>>();
            if config.1.args.len() > CLI_OUTPUT_MAX_ITEMS {
                arguments.push(serde_json::Value::String(format!(
                    "<{} arguments omitted>",
                    config.1.args.len() - CLI_OUTPUT_MAX_ITEMS
                )));
            }
            arguments
        }),
    );
    if let Some(environment) = &config.1.env {
        let redacted = redacted_environment_entries(environment)
            .into_iter()
            .map(|(key, value)| (key, serde_json::Value::String(value)))
            .collect();
        server.insert("env".to_owned(), serde_json::Value::Object(redacted));
    }
    if let Some(cwd) = &config.1.cwd {
        server.insert(
            "cwd".to_owned(),
            serde_json::Value::String(sanitize_peer_text(cwd, PEER_FIELD_LIMIT)),
        );
    }
    if config.1.disabled {
        server.insert("disabled".to_owned(), serde_json::Value::Bool(true));
    }

    let server = shape_install_server_entry(target, server);
    let mut servers = serde_json::Map::new();
    servers.insert(
        sanitize_peer_text(&config.0, PEER_FIELD_LIMIT),
        serde_json::Value::Object(server),
    );
    let mut root = serde_json::Map::new();
    root.insert(registry_name.to_owned(), serde_json::Value::Object(servers));

    serde_json::to_string_pretty(&serde_json::Value::Object(root)).map_err(|_| {
        fastmcp_core::McpError::internal_error("Failed to serialize redacted install preview")
    })
}

fn write_install_stdout(output: &str) -> McpResult<()> {
    write_stdout(output, "install output", true)
}

fn read_json_config_or_empty_at(
    parent: &SecuredParentDirectory,
    config_name: &std::ffi::OsStr,
    config_path: &Path,
) -> McpResult<(serde_json::Value, DestinationSnapshot)> {
    let snapshot = read_destination_snapshot_at(
        parent,
        config_name,
        config_path,
        "installation target config",
        CONFIG_INPUT_MAX_BYTES,
    )?;
    let value = match &snapshot {
        DestinationSnapshot::Missing => serde_json::json!({}),
        DestinationSnapshot::Existing(existing) => serde_json::from_slice(&existing.bytes)
            .map_err(|error| json_parse_error(config_path, "installation target", &error))?,
    };
    Ok((value, snapshot))
}

fn prepare_json_config(value: &serde_json::Value) -> McpResult<Vec<u8>> {
    let contents = serde_json::to_vec_pretty(value).map_err(|_| {
        fastmcp_core::McpError::internal_error("Failed to serialize installation config")
    })?;
    if contents.len() > CONFIG_OUTPUT_MAX_BYTES {
        return Err(fastmcp_core::McpError::invalid_params(format!(
            "Refusing to write installation config: output is {} bytes (maximum {CONFIG_OUTPUT_MAX_BYTES})",
            contents.len()
        )));
    }
    Ok(contents)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AtomicReplaceOutcome {
    Unchanged,
    Committed,
}

mod publication_durability {
    use super::{
        RetainedStage, SecuredParentDirectory, StableStatStamp, StagePublicationLocation,
        classify_stage_publication,
    };
    use std::ffi::OsStr;
    #[cfg(target_os = "linux")]
    use std::ffi::OsString;
    use std::io;

    /// Proof that the secured parent containing a published name was synced.
    ///
    /// The fields are private to this module so production callers cannot
    /// construct a proof without going through [`establish`]. The recorded
    /// identities also prevent a proof from one secured parent, name, or
    /// candidate from authorizing another. The directory stamp is a
    /// best-effort Linux ABA detector, not a kernel namespace lock or CAS.
    #[derive(Debug)]
    pub(super) struct DurablePublication {
        #[cfg(target_os = "linux")]
        device: u64,
        #[cfg(target_os = "linux")]
        inode: u64,
        #[cfg(target_os = "linux")]
        candidate_device: u64,
        #[cfg(target_os = "linux")]
        candidate_inode: u64,
        #[cfg(target_os = "linux")]
        destination_name: OsString,
        #[cfg(target_os = "linux")]
        parent_stamp: StableStatStamp,
        #[cfg(target_os = "linux")]
        private_candidate_stamp: StableStatStamp,
        _private: (),
    }

    pub(super) fn establish(
        parent: &SecuredParentDirectory,
        staged: &RetainedStage,
        destination_name: &OsStr,
    ) -> io::Result<DurablePublication> {
        establish_using(
            parent,
            staged,
            destination_name,
            SecuredParentDirectory::sync,
        )
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn establish_with_sync<F>(
        parent: &SecuredParentDirectory,
        staged: &RetainedStage,
        destination_name: &OsStr,
        sync_parent: F,
    ) -> io::Result<DurablePublication>
    where
        F: FnOnce(&SecuredParentDirectory) -> io::Result<()>,
    {
        establish_using(parent, staged, destination_name, sync_parent)
    }

    fn establish_using<F>(
        parent: &SecuredParentDirectory,
        staged: &RetainedStage,
        destination_name: &OsStr,
        sync_parent: F,
    ) -> io::Result<DurablePublication>
    where
        F: FnOnce(&SecuredParentDirectory) -> io::Result<()>,
    {
        let before_sync = published_binding_stamp(parent, staged, destination_name)?;
        sync_parent(parent)?;
        let after_sync = published_binding_stamp(parent, staged, destination_name)?;
        if before_sync != after_sync {
            return Err(io::Error::other(
                "secured parent metadata changed while publication durability was established",
            ));
        }
        Ok(proof_for(parent, staged, destination_name, after_sync))
    }

    fn published_binding_stamp(
        parent: &SecuredParentDirectory,
        staged: &RetainedStage,
        destination_name: &OsStr,
    ) -> io::Result<(StableStatStamp, StableStatStamp)> {
        if classify_stage_publication(parent, staged, destination_name)?
            != StagePublicationLocation::Published
        {
            return Err(io::Error::other(
                "candidate was not positively observed at the published name before parent sync",
            ));
        }
        #[cfg(target_os = "linux")]
        {
            let parent_metadata = parent.handle.metadata()?;
            let candidate_metadata = staged.as_file().metadata()?;
            Ok((
                StableStatStamp::from_metadata(&parent_metadata),
                StableStatStamp::from_metadata(&candidate_metadata),
            ))
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "parent mutation stamps are unavailable",
            ))
        }
    }

    fn proof_for(
        parent: &SecuredParentDirectory,
        staged: &RetainedStage,
        destination_name: &OsStr,
        binding_stamp: (StableStatStamp, StableStatStamp),
    ) -> DurablePublication {
        #[cfg(not(target_os = "linux"))]
        let _ = (parent, staged, destination_name, binding_stamp);
        DurablePublication {
            #[cfg(target_os = "linux")]
            device: parent.device,
            #[cfg(target_os = "linux")]
            inode: parent.inode,
            #[cfg(target_os = "linux")]
            candidate_device: staged.staging_device,
            #[cfg(target_os = "linux")]
            candidate_inode: staged.staging_inode,
            #[cfg(target_os = "linux")]
            destination_name: destination_name.to_os_string(),
            #[cfg(target_os = "linux")]
            parent_stamp: binding_stamp.0,
            #[cfg(target_os = "linux")]
            private_candidate_stamp: binding_stamp.1,
            _private: (),
        }
    }

    impl DurablePublication {
        #[cfg(target_os = "linux")]
        pub(super) fn authorizes(
            &self,
            parent: &SecuredParentDirectory,
            staged: &RetainedStage,
            destination_name: &OsStr,
            require_private_candidate: bool,
        ) -> io::Result<bool> {
            let current_candidate = staged.as_file().metadata()?;
            // Sample the directory last so the mutation stamp is the final
            // syscall-backed observation in this authorization check.
            let current_parent = parent.handle.metadata()?;
            use std::os::unix::fs::MetadataExt as _;

            Ok(self.device == parent.device
                && self.inode == parent.inode
                && self.candidate_device == staged.staging_device
                && self.candidate_inode == staged.staging_inode
                && self.destination_name == destination_name
                && current_candidate.dev() == self.candidate_device
                && current_candidate.ino() == self.candidate_inode
                && StableStatStamp::from_metadata(&current_parent) == self.parent_stamp
                && (!require_private_candidate
                    || StableStatStamp::from_metadata(&current_candidate)
                        == self.private_candidate_stamp))
        }
    }
}

use publication_durability::DurablePublication;

// The result is intentionally fallible at the cross-platform API boundary;
// only the verified Linux implementation compiles to an unconditional `Ok`.
#[cfg_attr(target_os = "linux", allow(clippy::unnecessary_wraps))]
fn ensure_atomic_replace_supported() -> McpResult<()> {
    #[cfg(target_os = "linux")]
    {
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(fastmcp_core::McpError::internal_error(
            "Atomic file publication is currently verified only on Linux; this platform is disabled because file identity, ACL/flag preservation, no-clobber rename, and directory durability have not all been proven",
        ))
    }
}

struct SecuredParentDirectory {
    #[cfg(target_os = "linux")]
    path: PathBuf,
    handle: File,
    #[cfg(target_os = "linux")]
    device: u64,
    #[cfg(target_os = "linux")]
    inode: u64,
    #[cfg(target_os = "linux")]
    ancestry: Vec<DirectoryIdentity>,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct DirectoryIdentity {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl SecuredParentDirectory {
    fn open(parent: &Path, destination: &Path, context: &str) -> McpResult<Self> {
        ensure_atomic_replace_supported()?;
        #[cfg(target_os = "linux")]
        {
            Self::open_linux(parent, destination, context)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (parent, destination, context);
            Err(fastmcp_core::McpError::internal_error(
                "Atomic parent-directory capabilities are unavailable on this platform",
            ))
        }
    }

    #[cfg(target_os = "linux")]
    fn open_linux(parent: &Path, destination: &Path, context: &str) -> McpResult<Self> {
        use rustix::fs::{Mode, OFlags};
        use std::os::unix::fs::MetadataExt as _;

        if parent
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(fastmcp_core::McpError::invalid_params(format!(
                "Refusing to write {context} at {}: parent-directory traversal components are not accepted for atomic publication",
                sanitize_config_path(destination)
            )));
        }
        let absolute_parent = if parent.is_absolute() {
            parent.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|error| {
                    fastmcp_core::McpError::internal_error(format!(
                        "Failed to resolve the current directory for {context} at {} (I/O kind: {:?})",
                        sanitize_config_path(destination),
                        error.kind()
                    ))
                })?
                .join(parent)
        };

        validate_directory_ancestry(&absolute_parent, destination, context, true)?;
        let missing = missing_parent_directories(&absolute_parent, destination, context)?;
        let (created_parent_handle, created) = if missing.is_empty() {
            (None, Vec::new())
        } else {
            let (handle, created) =
                create_missing_parent_directories_at(&missing, destination, context)?;
            (Some(handle), created)
        };
        if !created.is_empty() {
            write_cli_warning(&format!(
                "Created {} descriptor-anchored owner-only parent directories for {context} at {}; they are intentionally retained if a later step fails",
                created.len(),
                sanitize_config_path(destination)
            ));
        }
        let ancestry = validate_directory_ancestry(&absolute_parent, destination, context, false)?;
        let parent_identity = ancestry.last().ok_or_else(|| {
            fastmcp_core::McpError::internal_error(format!(
                "Failed to establish parent-directory ancestry for {context} at {}",
                sanitize_config_path(destination)
            ))
        })?;

        let handle = if let Some(handle) = created_parent_handle {
            handle
        } else {
            rustix::fs::open(
                &absolute_parent,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map(File::from)
            .map_err(|error| {
                let error = io::Error::from(error);
                fastmcp_core::McpError::internal_error(format!(
                    "Failed to open secured parent directory for {context} at {} (I/O kind: {:?})",
                    sanitize_config_path(destination),
                    error.kind()
                ))
            })?
        };

        let opened = handle.metadata().map_err(|error| {
            fastmcp_core::McpError::internal_error(format!(
                "Failed to inspect opened parent directory for {context} at {} (I/O kind: {:?})",
                sanitize_config_path(destination),
                error.kind()
            ))
        })?;
        if opened.dev() != parent_identity.device || opened.ino() != parent_identity.inode {
            return Err(fastmcp_core::McpError::invalid_params(format!(
                "Refusing to write {context} at {}: the parent directory changed while it was being opened",
                sanitize_config_path(destination)
            )));
        }
        rustix::fs::flock(
            &handle,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .map_err(|error| {
            fastmcp_core::McpError::internal_error(format!(
                "Failed to acquire the cooperative parent-directory transaction lock for {context} at {} (I/O kind: {:?})",
                sanitize_config_path(destination),
                io::Error::from(error).kind()
            ))
        })?;
        let secured = Self {
            path: absolute_parent,
            handle,
            device: opened.dev(),
            inode: opened.ino(),
            ancestry,
        };
        secured.revalidate(destination, context)?;
        Ok(secured)
    }

    fn revalidate(&self, destination: &Path, context: &str) -> McpResult<()> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt as _;

            let opened = self.handle.metadata().map_err(|error| {
                fastmcp_core::McpError::internal_error(format!(
                    "Failed to revalidate opened parent directory for {context} at {} (I/O kind: {:?})",
                    sanitize_config_path(destination),
                    error.kind()
                ))
            })?;
            let ancestry = validate_directory_ancestry(&self.path, destination, context, false)?;
            let parent_identity = ancestry.last();
            if parent_identity.is_none_or(|identity| {
                identity.device != self.device || identity.inode != self.inode
            }) || opened.dev() != self.device
                || opened.ino() != self.inode
                || ancestry != self.ancestry
            {
                return Err(fastmcp_core::McpError::invalid_params(format!(
                    "Refusing to write {context} at {}: the secured parent-directory identity changed",
                    sanitize_config_path(destination)
                )));
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (destination, context);
            Err(fastmcp_core::McpError::internal_error(
                "Atomic parent-directory revalidation is unavailable on this platform",
            ))
        }
    }

    fn sync(&self) -> io::Result<()> {
        self.handle.sync_all()
    }

    fn validate_staging_policy(&self, destination: &Path, context: &str) -> McpResult<()> {
        #[cfg(target_os = "linux")]
        {
            let attribute_names = list_extended_attribute_names(&self.handle).map_err(|error| {
                fastmcp_core::McpError::internal_error(format!(
                    "Failed to inspect parent-directory ACL metadata for {context} at {} (I/O kind: {:?})",
                    sanitize_config_path(destination),
                    error.kind()
                ))
            })?;
            if extended_attribute_list_contains(&attribute_names, b"system.posix_acl_default") {
                return Err(fastmcp_core::McpError::invalid_params(format!(
                    "Refusing to stage {context} at {}: the parent directory has a default POSIX ACL that may alter a newly created staging inode",
                    sanitize_config_path(destination)
                )));
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (destination, context);
            Err(fastmcp_core::McpError::internal_error(
                "Atomic staging-policy validation is unavailable on this platform",
            ))
        }
    }
}

fn establish_publication_durability(
    parent: &SecuredParentDirectory,
    staged: &RetainedStage,
    destination_name: &std::ffi::OsStr,
) -> io::Result<DurablePublication> {
    publication_durability::establish(parent, staged, destination_name)
}

#[cfg(target_os = "linux")]
fn validate_directory_ancestry(
    parent: &Path,
    destination: &Path,
    context: &str,
    allow_missing: bool,
) -> McpResult<Vec<DirectoryIdentity>> {
    use rustix::fs::{AtFlags, Mode, OFlags};
    use std::os::unix::fs::MetadataExt as _;

    if !parent.is_absolute() {
        return Err(fastmcp_core::McpError::internal_error(format!(
            "Failed to validate directory ancestry for {context} at {}: the parent path was not absolute",
            sanitize_config_path(destination)
        )));
    }
    let effective_user = rustix::process::geteuid().as_raw();
    let mut identities = Vec::new();
    let mut current_path = PathBuf::from("/");
    let mut current = rustix::fs::open(
        "/",
        OFlags::PATH | OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| {
        let error = io::Error::from(error);
        fastmcp_core::McpError::internal_error(format!(
            "Failed to open the filesystem root while validating directory ancestry for {context} at {} (I/O kind: {:?})",
            sanitize_config_path(destination),
            error.kind()
        ))
    })?;

    let validate_opened = |metadata: &Metadata| -> McpResult<()> {
        if !metadata.is_dir() {
            return Err(fastmcp_core::McpError::invalid_params(format!(
                "Refusing to write {context} at {}: every parent component must be a real directory",
                sanitize_config_path(destination)
            )));
        }
        let owner = metadata.uid();
        if owner != 0 && owner != effective_user {
            return Err(fastmcp_core::McpError::invalid_params(format!(
                "Refusing to write {context} at {}: a parent directory is controlled by an untrusted non-root user",
                sanitize_config_path(destination)
            )));
        }
        let mode = metadata.mode();
        if mode & 0o022 != 0 && mode & 0o1000 == 0 {
            return Err(fastmcp_core::McpError::invalid_params(format!(
                "Refusing to write {context} at {}: a parent directory is writable by another group or user without sticky-directory protection",
                sanitize_config_path(destination)
            )));
        }
        Ok(())
    };

    let root_metadata = current.metadata().map_err(|error| {
        fastmcp_core::McpError::internal_error(format!(
            "Failed to inspect the filesystem root while validating directory ancestry for {context} at {} (I/O kind: {:?})",
            sanitize_config_path(destination),
            error.kind()
        ))
    })?;
    validate_opened(&root_metadata)?;
    identities.push(DirectoryIdentity {
        path: current_path.clone(),
        device: root_metadata.dev(),
        inode: root_metadata.ino(),
    });

    for component in parent.components() {
        let std::path::Component::Normal(name) = component else {
            continue;
        };
        current_path.push(name);
        let child = match rustix::fs::openat(
            &current,
            name,
            OFlags::PATH | OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::NOFOLLOW,
            Mode::empty(),
        ) {
            Ok(child) => File::from(child),
            Err(error) => {
                let error = io::Error::from(error);
                if allow_missing && error.kind() == io::ErrorKind::NotFound {
                    break;
                }
                if error.kind() == io::ErrorKind::NotADirectory {
                    return Err(fastmcp_core::McpError::invalid_params(format!(
                        "Refusing to write {context} at {}: every parent component must be a real, non-symlink directory",
                        sanitize_config_path(destination)
                    )));
                }
                return Err(fastmcp_core::McpError::internal_error(format!(
                    "Failed to open a descriptor-relative parent component while validating {context} at {} (I/O kind: {:?})",
                    sanitize_config_path(destination),
                    error.kind()
                )));
            }
        };
        let metadata = child.metadata().map_err(|error| {
            fastmcp_core::McpError::internal_error(format!(
                "Failed to inspect a descriptor-relative parent component while validating {context} at {} (I/O kind: {:?})",
                sanitize_config_path(destination),
                error.kind()
            ))
        })?;
        validate_opened(&metadata)?;
        let named = rustix::fs::statat(&current, name, AtFlags::SYMLINK_NOFOLLOW).map_err(
            |error| {
                let error = io::Error::from(error);
                fastmcp_core::McpError::internal_error(format!(
                    "Failed to revalidate a descriptor-relative parent component for {context} at {} (I/O kind: {:?})",
                    sanitize_config_path(destination),
                    error.kind()
                ))
            },
        )?;
        if !rustix::fs::FileType::from_raw_mode(named.st_mode).is_dir()
            || named.st_dev != metadata.dev()
            || named.st_ino != metadata.ino()
        {
            return Err(fastmcp_core::McpError::invalid_params(format!(
                "Refusing to write {context} at {}: a parent component changed identity during descriptor traversal",
                sanitize_config_path(destination)
            )));
        }
        identities.push(DirectoryIdentity {
            path: current_path.clone(),
            device: metadata.dev(),
            inode: metadata.ino(),
        });
        current = child;
    }
    Ok(identities)
}

#[cfg(target_os = "linux")]
fn missing_parent_directories(
    parent: &Path,
    destination: &Path,
    context: &str,
) -> McpResult<Vec<PathBuf>> {
    let mut missing = Vec::new();
    let mut cursor = parent;
    loop {
        match std::fs::symlink_metadata(cursor) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(fastmcp_core::McpError::invalid_params(format!(
                        "Refusing to write {context} at {}: a required parent path is not a real directory",
                        sanitize_config_path(destination)
                    )));
                }
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.push(cursor.to_path_buf());
                cursor = cursor
                    .parent()
                    .filter(|path| !path.as_os_str().is_empty())
                    .unwrap_or_else(|| Path::new("."));
            }
            Err(error) => {
                return Err(fastmcp_core::McpError::internal_error(format!(
                    "Failed to inspect parent path for {context} at {} (I/O kind: {:?})",
                    sanitize_config_path(destination),
                    error.kind()
                )));
            }
        }
    }
    Ok(missing)
}

#[cfg(target_os = "linux")]
fn retained_parent_creation_error(
    destination: &Path,
    context: &str,
    created: &[PathBuf],
    detail: &str,
) -> fastmcp_core::McpError {
    if !created.is_empty() {
        write_cli_warning(&format!(
            "Created {} owner-only parent directories for {context} at {} before parent creation stopped; they were intentionally retained and their displayed paths are last-known diagnostics only",
            created.len(),
            sanitize_config_path(destination)
        ));
    }
    fastmcp_core::McpError::internal_error(format!(
        "Failed to create descriptor-anchored owner-only parent directories for {context} at {} after creating and retaining {} directories: {detail}",
        sanitize_config_path(destination),
        created.len()
    ))
}

#[cfg(target_os = "linux")]
fn create_missing_parent_directories_at(
    missing: &[PathBuf],
    destination: &Path,
    context: &str,
) -> McpResult<(File, Vec<PathBuf>)> {
    use rustix::fs::{AtFlags, Mode, OFlags};
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let highest_missing = missing.last().ok_or_else(|| {
        fastmcp_core::McpError::internal_error(
            "Missing-parent creation requires at least one missing component",
        )
    })?;
    let anchor_path = usable_parent(highest_missing);
    let anchor_metadata = std::fs::symlink_metadata(anchor_path).map_err(|error| {
        fastmcp_core::McpError::internal_error(format!(
            "Failed to inspect the existing parent anchor for {context} at {} (I/O kind: {:?})",
            sanitize_config_path(destination),
            error.kind()
        ))
    })?;
    if anchor_metadata.file_type().is_symlink() || !anchor_metadata.is_dir() {
        return Err(fastmcp_core::McpError::invalid_params(format!(
            "Refusing to write {context} at {}: the existing parent anchor is not a real directory",
            sanitize_config_path(destination)
        )));
    }
    let mut current = rustix::fs::open(
        anchor_path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| {
        let error = io::Error::from(error);
        fastmcp_core::McpError::internal_error(format!(
            "Failed to open the existing parent anchor for {context} at {} (I/O kind: {:?})",
            sanitize_config_path(destination),
            error.kind()
        ))
    })?;
    let anchor_opened = current.metadata().map_err(|error| {
        fastmcp_core::McpError::internal_error(format!(
            "Failed to inspect the opened parent anchor for {context} at {} (I/O kind: {:?})",
            sanitize_config_path(destination),
            error.kind()
        ))
    })?;
    if anchor_opened.dev() != anchor_metadata.dev() || anchor_opened.ino() != anchor_metadata.ino()
    {
        return Err(fastmcp_core::McpError::invalid_params(format!(
            "Refusing to write {context} at {}: the existing parent anchor changed while it was being opened",
            sanitize_config_path(destination)
        )));
    }

    let mut created = Vec::with_capacity(missing.len());
    for directory in missing.iter().rev() {
        let component = directory.file_name().ok_or_else(|| {
            retained_parent_creation_error(
                destination,
                context,
                &created,
                "a missing directory had no single relative component",
            )
        })?;
        let parent_attributes = list_extended_attribute_names(&current).map_err(|error| {
            retained_parent_creation_error(
                destination,
                context,
                &created,
                &format!(
                    "inspecting parent ACL metadata failed (I/O kind: {:?})",
                    error.kind()
                ),
            )
        })?;
        if extended_attribute_list_contains(&parent_attributes, b"system.posix_acl_default") {
            return Err(retained_parent_creation_error(
                destination,
                context,
                &created,
                "an existing parent has a default POSIX ACL that could alter newly created directory access",
            ));
        }

        let created_here = match rustix::fs::mkdirat(&current, component, Mode::RWXU) {
            Ok(()) => {
                created.push(directory.clone());
                true
            }
            Err(error) => {
                let error = io::Error::from(error);
                if error.kind() == io::ErrorKind::AlreadyExists {
                    false
                } else {
                    return Err(retained_parent_creation_error(
                        destination,
                        context,
                        &created,
                        &format!(
                            "descriptor-relative mkdir failed (I/O kind: {:?})",
                            error.kind()
                        ),
                    ));
                }
            }
        };
        let path_handle = rustix::fs::openat(
            &current,
            component,
            OFlags::PATH | OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| {
            let error = io::Error::from(error);
            retained_parent_creation_error(
                destination,
                context,
                &created,
                &format!(
                    "capturing the new directory inode failed (I/O kind: {:?})",
                    error.kind()
                ),
            )
        })?;
        let captured = path_handle.metadata().map_err(|error| {
            retained_parent_creation_error(
                destination,
                context,
                &created,
                &format!(
                    "inspecting the captured directory inode failed (I/O kind: {:?})",
                    error.kind()
                ),
            )
        })?;
        if !captured.is_dir() {
            return Err(retained_parent_creation_error(
                destination,
                context,
                &created,
                "a concurrently occupied parent component was not a directory",
            ));
        }
        let effective_user = rustix::process::geteuid().as_raw();
        if created_here {
            if captured.uid() != effective_user || captured.mode() & 0o077 != 0 {
                return Err(retained_parent_creation_error(
                    destination,
                    context,
                    &created,
                    "the newly captured directory was not owned by the effective user with no group/world access",
                ));
            }
            // `mkdirat` is subject to the process umask and may create mode
            // 000. Rustix 1.1.4 does not expose fchmodat2(AT_EMPTY_PATH), so
            // harden the held O_PATH inode through procfs's descriptor magic
            // link, then verify both the inode and its original name.
            let descriptor_path =
                PathBuf::from(format!("/proc/self/fd/{}", path_handle.as_raw_fd()));
            std::fs::set_permissions(&descriptor_path, Permissions::from_mode(0o700)).map_err(
                |error| {
                    retained_parent_creation_error(
                        destination,
                        context,
                        &created,
                        &format!(
                            "hardening the captured directory inode through procfs failed (I/O kind: {:?})",
                            error.kind()
                        ),
                    )
                },
            )?;
        } else {
            let owner = captured.uid();
            let mode = captured.mode();
            if (owner != 0 && owner != effective_user) || (mode & 0o022 != 0 && mode & 0o1000 == 0)
            {
                return Err(retained_parent_creation_error(
                    destination,
                    context,
                    &created,
                    "a concurrently created directory had an untrusted owner or unsafe writable permissions",
                ));
            }
        }

        let hardened = path_handle.metadata().map_err(|error| {
            retained_parent_creation_error(
                destination,
                context,
                &created,
                &format!(
                    "reinspecting the captured directory inode failed (I/O kind: {:?})",
                    error.kind()
                ),
            )
        })?;
        if created_here && (hardened.uid() != effective_user || hardened.mode() & 0o7777 != 0o700) {
            return Err(retained_parent_creation_error(
                destination,
                context,
                &created,
                "the captured directory inode did not retain exact owner-only permissions",
            ));
        }
        let child = rustix::fs::openat(
            &path_handle,
            ".",
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| {
            let error = io::Error::from(error);
            retained_parent_creation_error(
                destination,
                context,
                &created,
                &format!(
                    "opening the captured directory for traversal and durability failed (I/O kind: {:?})",
                    error.kind()
                ),
            )
        })?;
        let child_metadata = child.metadata().map_err(|error| {
            retained_parent_creation_error(
                destination,
                context,
                &created,
                &format!(
                    "inspecting the traversable directory descriptor failed (I/O kind: {:?})",
                    error.kind()
                ),
            )
        })?;
        if child_metadata.dev() != hardened.dev() || child_metadata.ino() != hardened.ino() {
            return Err(retained_parent_creation_error(
                destination,
                context,
                &created,
                "the traversable directory descriptor did not match the captured inode",
            ));
        }
        let named = rustix::fs::statat(&current, component, AtFlags::SYMLINK_NOFOLLOW).map_err(
            |error| {
                let error = io::Error::from(error);
                retained_parent_creation_error(
                    destination,
                    context,
                    &created,
                    &format!(
                        "revalidating the descriptor-relative directory name failed (I/O kind: {:?})",
                        error.kind()
                    ),
                )
            },
        )?;
        if named.st_dev != hardened.dev()
            || named.st_ino != hardened.ino()
            || !rustix::fs::FileType::from_raw_mode(named.st_mode).is_dir()
        {
            return Err(retained_parent_creation_error(
                destination,
                context,
                &created,
                "the descriptor-relative directory name changed identity after capture",
            ));
        }
        let child_attributes = list_extended_attribute_names(&child).map_err(|error| {
            retained_parent_creation_error(
                destination,
                context,
                &created,
                &format!(
                    "inspecting captured directory ACL metadata failed (I/O kind: {:?})",
                    error.kind()
                ),
            )
        })?;
        if extended_attribute_list_contains(&child_attributes, b"system.posix_acl_access")
            || extended_attribute_list_contains(&child_attributes, b"system.posix_acl_default")
        {
            return Err(retained_parent_creation_error(
                destination,
                context,
                &created,
                "the captured directory acquired POSIX ACL metadata that cannot be accepted safely",
            ));
        }
        // The component was absent during discovery. Even when another actor
        // wins mkdirat and we observe EEXIST, its directory entry may not yet
        // be durable. Sync both the captured inode and its containing
        // directory before descending into it.
        child.sync_all().map_err(|error| {
            retained_parent_creation_error(
                destination,
                context,
                &created,
                &format!(
                    "syncing the captured directory inode failed (I/O kind: {:?})",
                    error.kind()
                ),
            )
        })?;
        current.sync_all().map_err(|error| {
            retained_parent_creation_error(
                destination,
                context,
                &created,
                &format!(
                    "syncing the directory containing the captured entry failed (I/O kind: {:?})",
                    error.kind()
                ),
            )
        })?;
        current = child;
    }
    Ok((current, created))
}

fn atomic_replace_file(
    path: &Path,
    contents: &[u8],
    context: &str,
    max_bytes: usize,
) -> McpResult<AtomicReplaceOutcome> {
    if contents.len() > max_bytes {
        return Err(fastmcp_core::McpError::invalid_params(format!(
            "Refusing to write {context}: output is {} bytes (maximum {max_bytes})",
            contents.len()
        )));
    }
    validate_atomic_destination_name(path, context)?;
    ensure_atomic_replace_supported()?;
    let parent = usable_parent(path);
    let secured_parent = SecuredParentDirectory::open(parent, path, context)?;
    let destination_name = path.file_name().ok_or_else(|| {
        fastmcp_core::McpError::invalid_params(format!(
            "Cannot write {context} at {}: destination has no relative file name",
            sanitize_config_path(path)
        ))
    })?;
    let expected =
        read_destination_snapshot_at(&secured_parent, destination_name, path, context, max_bytes)?;
    if expected
        .bytes()
        .is_some_and(|existing| existing == contents)
    {
        secured_parent.revalidate(path, context)?;
        let final_identity = descriptor_relative_name_matches_snapshot(
            &secured_parent,
            destination_name,
            &expected,
        )
        .map_err(|error| {
            fastmcp_core::McpError::internal_error(format!(
                "Failed to complete descriptor-relative unchanged-file verification for {context} at {} (I/O kind: {:?})",
                sanitize_config_path(path),
                error.kind()
            ))
        })?;
        if !final_identity {
            return Err(fastmcp_core::McpError::invalid_params(format!(
                "Refusing to report {context} at {} unchanged: the destination changed while the no-op was verified",
                sanitize_config_path(path)
            )));
        }
        return Ok(AtomicReplaceOutcome::Unchanged);
    }
    let visibility_warning = if let Some(existing) = expected.existing() {
        validate_snapshot_for_replacement(existing, path, context)?;
        linux_xattr_visibility_warning(existing, path, context)
    } else {
        None
    };
    let result = atomic_replace_prepared_file_at(
        secured_parent,
        path,
        contents,
        context,
        max_bytes,
        &expected,
    );
    if let Some(warning) = visibility_warning {
        write_cli_warning(&warning);
    }
    result
}

fn atomic_replace_prepared_file_at(
    secured_parent: SecuredParentDirectory,
    path: &Path,
    contents: &[u8],
    context: &str,
    max_bytes: usize,
    expected: &DestinationSnapshot,
) -> McpResult<AtomicReplaceOutcome> {
    atomic_replace_prepared_file_at_with_durability(
        secured_parent,
        path,
        contents,
        context,
        max_bytes,
        expected,
        establish_publication_durability,
    )
}

fn atomic_replace_prepared_file_at_with_durability<F>(
    secured_parent: SecuredParentDirectory,
    path: &Path,
    contents: &[u8],
    context: &str,
    max_bytes: usize,
    expected: &DestinationSnapshot,
    establish_durability: F,
) -> McpResult<AtomicReplaceOutcome>
where
    F: FnOnce(
        &SecuredParentDirectory,
        &RetainedStage,
        &std::ffi::OsStr,
    ) -> io::Result<DurablePublication>,
{
    if contents.len() > max_bytes {
        return Err(fastmcp_core::McpError::invalid_params(format!(
            "Refusing to write {context}: output is {} bytes (maximum {max_bytes})",
            contents.len()
        )));
    }
    let destination_name = path.file_name().ok_or_else(|| {
        fastmcp_core::McpError::invalid_params(format!(
            "Cannot write {context} at {}: destination has no relative file name",
            sanitize_config_path(path)
        ))
    })?;
    if let Some(existing) = expected.existing() {
        validate_snapshot_for_replacement(existing, path, context)?;
    }
    secured_parent.validate_staging_policy(path, context)?;
    let mut staged = create_retained_same_directory_temp(
        &secured_parent,
        expected.existing(),
        path,
        context,
        "write",
    )?;
    stage_retained_contents(&secured_parent, &mut staged, contents, path, context)?;

    secured_parent.revalidate(path, context).map_err(|error| {
        retained_stage_error(
            path,
            context,
            staged.diagnostic_path(),
            &format!(
                "secured parent-path revalidation failed after staging: {}",
                error.message
            ),
        )
    })?;
    verify_staged_path_identity(&secured_parent, &staged, path, context)?;

    let current =
        read_destination_snapshot_at(&secured_parent, destination_name, path, context, max_bytes)
            .map_err(|error| {
            retained_stage_error(
                path,
                context,
                staged.diagnostic_path(),
                &format!("destination revalidation failed: {}", error.message),
            )
        })?;
    if !expected.matches(&current) {
        return Err(retained_stage_error(
            path,
            context,
            staged.diagnostic_path(),
            "destination changed or was replaced after it was read; refusing to overwrite it",
        ));
    }
    secured_parent.revalidate(path, context).map_err(|error| {
        retained_stage_error(
            path,
            context,
            staged.diagnostic_path(),
            &format!(
                "secured parent-path revalidation failed before publication preparation: {}",
                error.message
            ),
        )
    })?;
    verify_staged_path_identity(&secured_parent, &staged, path, context)?;

    // Missing destinations use a kernel-enforced no-clobber rename. Existing
    // destinations use optimistic snapshot revalidation plus a cooperative
    // directory lock; a non-cooperating writer can still race the final rename
    // window, so this path is intentionally not described as serializable.
    prepare_staged_for_publication(
        &secured_parent,
        &staged,
        contents,
        expected.existing(),
        path,
        context,
    )?;
    let current =
        read_destination_snapshot_at(&secured_parent, destination_name, path, context, max_bytes)
            .map_err(|error| {
            retained_stage_error(
                path,
                context,
                staged.diagnostic_path(),
                &format!("final destination revalidation failed: {}", error.message),
            )
        })?;
    if !expected.matches(&current) {
        return Err(retained_stage_error(
            path,
            context,
            staged.diagnostic_path(),
            "the destination changed during final staged-file verification; refusing to overwrite it",
        ));
    }
    // Keep path association as close as possible to the publication syscall.
    // A non-cooperating same-UID actor still has an unavoidable final
    // instruction-window race, which is why this is not a CAS claim.
    secured_parent.revalidate(path, context).map_err(|error| {
        retained_stage_error(
            path,
            context,
            staged.diagnostic_path(),
            &format!(
                "final secured parent-path revalidation failed before publication: {}",
                error.message
            ),
        )
    })?;
    let verified_stage_stamp = verify_staged_contents_and_metadata(
        &secured_parent,
        &staged,
        contents,
        expected.existing(),
        path,
        context,
    )?;
    verify_staged_path_identity(&secured_parent, &staged, path, context)?;
    match descriptor_relative_name_matches_snapshot(&secured_parent, destination_name, expected) {
        Ok(true) => {}
        Ok(false) => {
            return Err(retained_stage_error(
                path,
                context,
                staged.diagnostic_path(),
                "the destination metadata changed after final staged-content verification; refusing to overwrite it",
            ));
        }
        Err(error) => {
            return Err(retained_stage_error(
                path,
                context,
                staged.diagnostic_path(),
                &format!(
                    "the final descriptor-relative destination identity check failed (I/O kind: {:?})",
                    error.kind()
                ),
            ));
        }
    }
    match descriptor_relative_stage_matches_stamp(
        &secured_parent,
        staged.relative_name(),
        verified_stage_stamp,
    ) {
        Ok(true) => {}
        Ok(false) => {
            return Err(retained_stage_error(
                path,
                context,
                staged.diagnostic_path(),
                "the staged name, inode, or verified metadata changed during the final destination identity check; refusing to publish it",
            ));
        }
        Err(error) => {
            return Err(retained_stage_error(
                path,
                context,
                staged.diagnostic_path(),
                &format!(
                    "the final descriptor-relative staged-name check failed (I/O kind: {:?})",
                    error.kind()
                ),
            ));
        }
    }
    #[cfg(target_os = "linux")]
    let publication: io::Result<()> = match expected {
        DestinationSnapshot::Missing => rustix::fs::renameat_with(
            &secured_parent.handle,
            staged.relative_name(),
            &secured_parent.handle,
            destination_name,
            rustix::fs::RenameFlags::NOREPLACE,
        ),
        DestinationSnapshot::Existing(_) => rustix::fs::renameat(
            &secured_parent.handle,
            staged.relative_name(),
            &secured_parent.handle,
            destination_name,
        ),
    }
    .map_err(Into::into);
    #[cfg(not(target_os = "linux"))]
    let publication: io::Result<()> = Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic relative rename is unavailable",
    ));
    let publication_location =
        classify_stage_publication(&secured_parent, &staged, destination_name);
    match publication {
        Err(error) => {
            let kind = error.kind();
            match &publication_location {
                Ok(StagePublicationLocation::Staged) => {
                    let retained_verification = verify_staged_contents_and_metadata(
                        &secured_parent,
                        &staged,
                        contents,
                        expected.existing(),
                        path,
                        context,
                    );
                    let directory_sync = secured_parent.sync();
                    let mut detail = if matches!(expected, DestinationSnapshot::Missing)
                        && kind == io::ErrorKind::AlreadyExists
                    {
                        "the destination was created concurrently and the atomic no-clobber commit was refused; two descriptor-relative observations found the owner-only candidate at its staging name".to_owned()
                    } else {
                        format!(
                            "the atomic publication syscall failed (I/O kind: {kind:?}); two descriptor-relative observations found the owner-only candidate at its staging name"
                        )
                    };
                    detail.push_str(&retained_verification.map_or_else(
                        |verification_error| {
                            format!(
                                "; read-only retained-candidate verification failed: {}",
                                sanitize_peer_text(
                                    &verification_error.message,
                                    PEER_DETAIL_LIMIT
                                )
                            )
                        },
                        |_| {
                            "; the retained candidate was read-only verified with its expected contents, ownership, and private 0600 mode"
                                .to_owned()
                        },
                    ));
                    detail.push_str(&directory_sync.map_or_else(
                        |error| {
                            format!(
                                "; parent-directory sync failed (I/O kind: {:?}), so retained-name durability is uncertain",
                                error.kind()
                            )
                        },
                        |()| "; the held parent directory was synced".to_owned(),
                    ));
                    return Err(retained_stage_error(
                        path,
                        context,
                        staged.diagnostic_path(),
                        &detail,
                    ));
                }
                Ok(StagePublicationLocation::Published) => {
                    let private_verification = verify_private_published_file(
                        &staged,
                        contents,
                        expected.existing(),
                        path,
                        context,
                    );
                    let post_verification_publication =
                        classify_stage_publication(&secured_parent, &staged, destination_name);
                    let publication_detail =
                        reconcile_stage_state_after_observation(&post_verification_publication);
                    let durability = secured_parent.sync();
                    let location = secured_parent.revalidate(path, context);
                    drop(staged);
                    let durability_detail = durability.map_or_else(
                        |sync_error| {
                            format!("parent sync failed with I/O kind {:?}", sync_error.kind())
                        },
                        |()| "the held parent descriptor was synced".to_owned(),
                    );
                    let location_detail = location.map_or_else(
                        |revalidation_error| {
                            format!(
                                "parent-path revalidation failed: {}",
                                revalidation_error.message
                            )
                        },
                        |()| "the original parent path was revalidated".to_owned(),
                    );
                    let private_detail = private_verification.map_or_else(
                        |verification_error| {
                            format!(
                                "private committed-inode verification failed: {}",
                                sanitize_peer_text(
                                    &verification_error.message,
                                    PEER_DETAIL_LIMIT
                                )
                            )
                        },
                        |()| {
                            "the committed inode was verified at final ownership, exact expected contents, and private 0600 permissions".to_owned()
                        },
                    );
                    return Err(fastmcp_core::McpError::internal_error(format!(
                        "Atomic publication of {context} at {} reported an I/O failure ({kind:?}); the initial two descriptor-relative observations found the candidate committed, then {private_detail}, and {publication_detail}; broader final permissions were not applied after the failed syscall; {durability_detail}, and {location_detail}. Treat the current location as indeterminate unless the post-verification state is Published. Do not retry blindly",
                        sanitize_config_path(path)
                    )));
                }
                Ok(StagePublicationLocation::Indeterminate) | Err(_) => {
                    let state_error = publication_location.as_ref().err();
                    let durability = secured_parent.sync();
                    let location = secured_parent.revalidate(path, context);
                    let state_detail = state_error.map_or_else(
                        || "neither descriptor-relative name state uniquely identified the staged inode".to_owned(),
                        |identity_error| {
                            format!(
                                "descriptor-relative identity inspection failed with I/O kind {:?}",
                                identity_error.kind()
                            )
                        },
                    );
                    let durability_detail = durability.map_or_else(
                        |sync_error| {
                            format!("parent sync failed with I/O kind {:?}", sync_error.kind())
                        },
                        |()| "the held parent descriptor was synced".to_owned(),
                    );
                    let location_detail = location.map_or_else(
                        |revalidation_error| {
                            format!(
                                "parent-path revalidation failed: {}",
                                revalidation_error.message
                            )
                        },
                        |()| "the original parent path was revalidated".to_owned(),
                    );
                    return Err(fastmcp_core::McpError::internal_error(format!(
                        "Atomic publication of {context} at {} reported an I/O failure ({kind:?}) and commit state is indeterminate: {state_detail}; {durability_detail}, and {location_detail}. The candidate's last-known diagnostic path was {} but is not authoritative. Do not retry blindly",
                        sanitize_config_path(path),
                        sanitize_config_path(staged.diagnostic_path())
                    )));
                }
            }
        }
        Ok(()) => match &publication_location {
            Ok(StagePublicationLocation::Published) => {}
            Ok(StagePublicationLocation::Staged | StagePublicationLocation::Indeterminate)
            | Err(_) => {
                let state_error = publication_location.as_ref().err();
                let durability = secured_parent.sync();
                let location = secured_parent.revalidate(path, context);
                drop(staged);
                let state_detail = state_error.map_or_else(
                    || "descriptor-relative source/destination identity did not show exactly one published name".to_owned(),
                    |identity_error| {
                        format!(
                            "descriptor-relative identity inspection failed with I/O kind {:?}",
                            identity_error.kind()
                        )
                    },
                );
                let durability_detail = durability.map_or_else(
                    |sync_error| {
                        format!("parent sync failed with I/O kind {:?}", sync_error.kind())
                    },
                    |()| "the held parent descriptor was synced".to_owned(),
                );
                let location_detail = location.map_or_else(
                    |revalidation_error| {
                        format!(
                            "parent-path revalidation failed: {}",
                            revalidation_error.message
                        )
                    },
                    |()| "the original parent path was revalidated".to_owned(),
                );
                return Err(fastmcp_core::McpError::internal_error(format!(
                    "Atomic publication of {context} at {} returned success, but post-rename identity verification was indeterminate: {state_detail}; {durability_detail}, and {location_detail}. Treat the commit as potentially completed and do not retry blindly",
                    sanitize_config_path(path)
                )));
            }
        },
    }
    let durability_proof = match establish_durability(&secured_parent, &staged, destination_name) {
        Ok(proof) => proof,
        Err(error) => {
            let observation =
                classify_stage_publication(&secured_parent, &staged, destination_name);
            let state_detail = reconcile_stage_state_after_observation(&observation);
            let recovery_sync = secured_parent.sync();
            let location = secured_parent.revalidate(path, context);
            return Err(fastmcp_core::McpError::internal_error(format!(
                "Atomic publication of {context} at {} was observed committed, but publication durability could not be established before permission finalization (I/O kind: {:?}); FastMCP did not widen the inode beyond the private 0600 mode it established. State observation: {state_detail}; best-effort recovery parent sync result: {:?}; parent-path revalidation: {}. The normal durability proof is unavailable. Do not retry blindly",
                sanitize_config_path(path),
                error.kind(),
                recovery_sync.as_ref().map_err(io::Error::kind),
                location.map_or_else(
                    |revalidation_error| revalidation_error.message,
                    |()| "succeeded".to_owned()
                )
            )));
        }
    };
    if let Err(error) = secured_parent.revalidate(path, context) {
        let observation = classify_stage_publication(&secured_parent, &staged, destination_name);
        let state_detail = reconcile_stage_state_after_observation(&observation);
        return Err(fastmcp_core::McpError::internal_error(format!(
            "Atomic publication of {context} was made durable through the secured parent descriptor, but the original parent path could not be revalidated before permission finalization; FastMCP did not widen the inode beyond the private 0600 mode it established. State observation: {state_detail}. Do not retry blindly. Revalidation detail: {}",
            error.message
        )));
    }
    let before_permission_finalization =
        classify_stage_publication(&secured_parent, &staged, destination_name);
    if !matches!(
        &before_permission_finalization,
        Ok(StagePublicationLocation::Published)
    ) {
        let state_detail = reconcile_stage_state_after_observation(&before_permission_finalization);
        return Err(fastmcp_core::McpError::internal_error(format!(
            "Atomic publication of {context} at {} was made durable, but descriptor-relative identity was not still Published before permission finalization; FastMCP did not widen the inode beyond the private 0600 mode it established. State observation: {state_detail}. Do not retry blindly",
            sanitize_config_path(path)
        )));
    }
    if let Err(error) = finalize_published_file_metadata(
        &secured_parent,
        durability_proof,
        &staged,
        destination_name,
        contents,
        expected.existing(),
        path,
        context,
    ) {
        let observation = classify_stage_publication(&secured_parent, &staged, destination_name);
        let state_detail = reconcile_stage_state_after_observation(&observation);
        let directory_sync = secured_parent.sync();
        let location = secured_parent.revalidate(path, context);
        return Err(fastmcp_core::McpError::internal_error(format!(
            "{} Post-failure state observation: {state_detail}; parent-directory sync after the metadata-finalization attempt: {:?}; parent-path revalidation: {}",
            error.message,
            directory_sync.as_ref().map_err(io::Error::kind),
            location.map_or_else(
                |revalidation_error| revalidation_error.message,
                |()| "succeeded".to_owned()
            )
        )));
    }
    if let Err(error) = secured_parent.revalidate(path, context) {
        let observation = classify_stage_publication(&secured_parent, &staged, destination_name);
        let state_detail = reconcile_stage_state_after_observation(&observation);
        return Err(fastmcp_core::McpError::internal_error(format!(
            "Atomic publication of {context} was durably committed and inode-synced through held descriptors, but the original parent path could not be revalidated after metadata finalization. Final descriptor-relative state: {state_detail}. Do not retry blindly. Revalidation detail: {}",
            error.message
        )));
    }
    // This is the last destination-name observation before success. The
    // earlier parent fsync made the rename durable; chmod metadata was synced
    // through the file descriptor and needs no second directory fsync.
    let post_finalization = classify_stage_publication(&secured_parent, &staged, destination_name);
    if !matches!(&post_finalization, Ok(StagePublicationLocation::Published)) {
        let state_detail = reconcile_stage_state_after_observation(&post_finalization);
        return Err(fastmcp_core::McpError::internal_error(format!(
            "Atomic publication of {context} at {} was committed and metadata-finalized, but the final descriptor-relative destination identity was not Published; state observation: {state_detail}. Do not retry blindly",
            sanitize_config_path(path),
        )));
    }
    drop(staged);
    Ok(AtomicReplaceOutcome::Committed)
}

fn usable_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn validate_atomic_destination_name(path: &Path, context: &str) -> McpResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;

        let raw = path.as_os_str().as_bytes();
        let terminal = raw.rsplit(|byte| *byte == b'/').next().unwrap_or(raw);
        if raw.ends_with(b"/") || matches!(terminal, b"." | b"..") {
            return Err(fastmcp_core::McpError::invalid_params(format!(
                "Refusing to write {context} at {}: trailing separators and terminal . or .. components are not valid atomic file destinations",
                sanitize_config_path(path)
            )));
        }
    }
    let Some(name) = path.file_name() else {
        return Err(fastmcp_core::McpError::invalid_params(format!(
            "Cannot write {context}: destination has no file name"
        )));
    };
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;

        if name.as_bytes().starts_with(b".fastmcp-stage-") {
            return Err(fastmcp_core::McpError::invalid_params(format!(
                "Refusing to write {context} at {}: destination names beginning with the reserved .fastmcp-stage- prefix are not accepted",
                sanitize_config_path(path)
            )));
        }
    }
    #[cfg(not(unix))]
    let _ = name;
    Ok(())
}

struct RetainedStage {
    file: File,
    relative_name: std::ffi::OsString,
    diagnostic_path: PathBuf,
    #[cfg(target_os = "linux")]
    staging_owner: u32,
    #[cfg(target_os = "linux")]
    staging_group: u32,
    #[cfg(target_os = "linux")]
    staging_device: u64,
    #[cfg(target_os = "linux")]
    staging_inode: u64,
}

impl RetainedStage {
    fn as_file(&self) -> &File {
        &self.file
    }

    fn as_file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    fn relative_name(&self) -> &std::ffi::OsStr {
        &self.relative_name
    }

    fn diagnostic_path(&self) -> &Path {
        &self.diagnostic_path
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
enum StagePublicationLocation {
    Staged,
    Published,
    Indeterminate,
}

#[cfg(target_os = "linux")]
fn descriptor_name_matches_metadata(
    parent: &SecuredParentDirectory,
    opened: &Metadata,
    relative_name: &std::ffi::OsStr,
) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt as _;

    let named = match rustix::fs::statat(
        &parent.handle,
        relative_name,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Ok(named) => named,
        Err(error) => {
            let error = io::Error::from(error);
            if error.kind() == io::ErrorKind::NotFound {
                return Ok(false);
            }
            return Err(error);
        }
    };
    Ok(opened.is_file()
        && rustix::fs::FileType::from_raw_mode(named.st_mode).is_file()
        && opened.dev() == named.st_dev
        && opened.ino() == named.st_ino
        && opened.nlink() == 1
        && named.st_nlink == 1)
}

#[cfg(target_os = "linux")]
fn descriptor_relative_name_exists(
    parent: &SecuredParentDirectory,
    relative_name: &std::ffi::OsStr,
) -> io::Result<bool> {
    match rustix::fs::statat(
        &parent.handle,
        relative_name,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Ok(_) => Ok(true),
        Err(error) => {
            let error = io::Error::from(error);
            if error.kind() == io::ErrorKind::NotFound {
                Ok(false)
            } else {
                Err(error)
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn descriptor_relative_name_matches_snapshot(
    parent: &SecuredParentDirectory,
    relative_name: &std::ffi::OsStr,
    expected: &DestinationSnapshot,
) -> io::Result<bool> {
    let named = match rustix::fs::statat(
        &parent.handle,
        relative_name,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Ok(named) => Some(named),
        Err(error) => {
            let error = io::Error::from(error);
            if error.kind() == io::ErrorKind::NotFound {
                None
            } else {
                return Err(error);
            }
        }
    };
    match (expected, named) {
        (DestinationSnapshot::Missing, None) => Ok(true),
        (DestinationSnapshot::Missing, Some(_)) | (DestinationSnapshot::Existing(_), None) => {
            Ok(false)
        }
        (DestinationSnapshot::Existing(snapshot), Some(named)) => {
            let named = StableStatStamp::from_stat(&named);
            Ok(rustix::fs::FileType::from_raw_mode(named.mode).is_file()
                && named.device == snapshot.metadata.device
                && named.inode == snapshot.metadata.inode
                && named.mode == snapshot.metadata.mode
                && named.owner == snapshot.metadata.owner
                && named.group == snapshot.metadata.group
                && named.links == snapshot.metadata.links
                && named.length == i64::try_from(snapshot.metadata.length).unwrap_or(i64::MAX)
                && named.modified_seconds == snapshot.metadata.modified_seconds
                && named.modified_nanoseconds
                    == u64::try_from(snapshot.metadata.modified_nanoseconds).unwrap_or(u64::MAX)
                && named.status_changed_seconds == snapshot.metadata.status_changed_seconds
                && named.status_changed_nanoseconds
                    == u64::try_from(snapshot.metadata.status_changed_nanoseconds)
                        .unwrap_or(u64::MAX))
        }
    }
}

#[cfg(target_os = "linux")]
fn descriptor_relative_stage_matches_stamp(
    parent: &SecuredParentDirectory,
    relative_name: &std::ffi::OsStr,
    expected: StableStatStamp,
) -> io::Result<bool> {
    let named = rustix::fs::statat(
        &parent.handle,
        relative_name,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(io::Error::from)?;
    Ok(rustix::fs::FileType::from_raw_mode(named.st_mode).is_file()
        && StableStatStamp::from_stat(&named) == expected)
}

#[cfg(not(target_os = "linux"))]
fn descriptor_relative_stage_matches_stamp(
    _parent: &SecuredParentDirectory,
    _relative_name: &std::ffi::OsStr,
    _expected: StableStatStamp,
) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "descriptor-relative stage stamp checks are unavailable",
    ))
}

#[cfg(not(target_os = "linux"))]
fn descriptor_relative_name_matches_snapshot(
    _parent: &SecuredParentDirectory,
    _relative_name: &std::ffi::OsStr,
    _expected: &DestinationSnapshot,
) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "descriptor-relative snapshot identity checks are unavailable",
    ))
}

#[cfg(not(target_os = "linux"))]
fn descriptor_relative_name_exists(
    _parent: &SecuredParentDirectory,
    _relative_name: &std::ffi::OsStr,
) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "descriptor-relative existence checks are unavailable",
    ))
}

#[cfg(target_os = "linux")]
fn descriptor_name_matches_staged_file(
    parent: &SecuredParentDirectory,
    staged: &RetainedStage,
    relative_name: &std::ffi::OsStr,
) -> io::Result<bool> {
    let opened = staged.as_file().metadata()?;
    descriptor_name_matches_metadata(parent, &opened, relative_name)
}

#[cfg(not(target_os = "linux"))]
fn descriptor_name_matches_staged_file(
    _parent: &SecuredParentDirectory,
    _staged: &RetainedStage,
    _relative_name: &std::ffi::OsStr,
) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "descriptor-relative stage identity is unavailable",
    ))
}

fn classify_stage_publication(
    parent: &SecuredParentDirectory,
    staged: &RetainedStage,
    destination_name: &std::ffi::OsStr,
) -> io::Result<StagePublicationLocation> {
    #[cfg(target_os = "linux")]
    fn observe(
        parent: &SecuredParentDirectory,
        staged: &RetainedStage,
        destination_name: &std::ffi::OsStr,
    ) -> io::Result<(StagePublicationLocation, FileMetadataStamp)> {
        let before = staged.as_file().metadata()?;
        let source_matches =
            descriptor_name_matches_metadata(parent, &before, staged.relative_name())?;
        let destination_matches =
            descriptor_name_matches_metadata(parent, &before, destination_name)?;
        let after = staged.as_file().metadata()?;
        let before_stamp = FileMetadataStamp::from_metadata(&before);
        let after_stamp = FileMetadataStamp::from_metadata(&after);
        let location = if before_stamp != after_stamp {
            StagePublicationLocation::Indeterminate
        } else {
            match (source_matches, destination_matches) {
                (true, false) => StagePublicationLocation::Staged,
                (false, true) => StagePublicationLocation::Published,
                (true, true) | (false, false) => StagePublicationLocation::Indeterminate,
            }
        };
        Ok((location, after_stamp))
    }

    #[cfg(target_os = "linux")]
    {
        let first = observe(parent, staged, destination_name)?;
        let second = observe(parent, staged, destination_name)?;
        if first == second {
            Ok(first.0)
        } else {
            Ok(StagePublicationLocation::Indeterminate)
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (parent, staged, destination_name);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "descriptor-relative publication classification is unavailable",
        ))
    }
}

fn reconcile_stage_state_after_observation(
    observation: &io::Result<StagePublicationLocation>,
) -> String {
    match observation {
        Ok(StagePublicationLocation::Published) =>
            "descriptor-relative observation found the inode at the published destination; no inode metadata was mutated from that observation".to_owned(),
        Ok(StagePublicationLocation::Staged) =>
            "descriptor-relative observation found the inode at its staging name; no inode metadata was mutated from a potentially stale location observation".to_owned(),
        Ok(StagePublicationLocation::Indeterminate) =>
            "descriptor-relative observation was indeterminate, so no inode metadata was mutated from that observation".to_owned(),
        Err(error) => format!(
            "descriptor-relative observation failed with I/O kind {:?}, so no inode metadata was mutated from that observation",
            error.kind()
        ),
    }
}

#[cfg(target_os = "linux")]
fn is_fastmcp_stage_name(name: &[u8]) -> bool {
    const PREFIX: &[u8] = b".fastmcp-stage-";
    name.len() == PREFIX.len() + 64
        && name.starts_with(PREFIX)
        && name[PREFIX.len()..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn create_retained_same_directory_temp(
    parent: &SecuredParentDirectory,
    final_snapshot: Option<&ExistingFileSnapshot>,
    destination: &Path,
    context: &str,
    purpose: &str,
) -> McpResult<RetainedStage> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let mut retained = 0usize;
        let mut inspected = 0usize;
        let scan_handle = rustix::fs::openat(
            &parent.handle,
            ".",
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| {
            let error = io::Error::from(error);
            fastmcp_core::McpError::internal_error(format!(
                "Failed to duplicate the secured directory view for retained-stage inspection for {context} at {} (I/O kind: {:?})",
                sanitize_config_path(destination),
                error.kind()
            ))
        })?;
        let mut directory_buffer = Vec::<u8>::with_capacity(16 * 1_024);
        let mut entries =
            rustix::fs::RawDir::new(&scan_handle, directory_buffer.spare_capacity_mut());
        while let Some(entry) = entries.next() {
            let entry = entry.map_err(|error| {
                let error = io::Error::from(error);
                fastmcp_core::McpError::internal_error(format!(
                    "Failed to inspect a retained staging entry for {context} at {} through the secured directory descriptor (I/O kind: {:?})",
                    sanitize_config_path(destination),
                    error.kind()
                ))
            })?;
            inspected = inspected.saturating_add(1);
            if inspected > RETAINED_STAGE_SCAN_MAX_ENTRIES {
                return Err(fastmcp_core::McpError::internal_error(format!(
                    "Refusing to scan more than {RETAINED_STAGE_SCAN_MAX_ENTRIES} directory entries while checking retained stages for {context} at {}",
                    sanitize_config_path(destination)
                )));
            }
            let name = entry.file_name().to_bytes();
            if !is_fastmcp_stage_name(name) {
                continue;
            }
            let metadata = match rustix::fs::statat(
                &parent.handle,
                entry.file_name(),
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            ) {
                Ok(metadata) => metadata,
                Err(error) => {
                    let error = io::Error::from(error);
                    if error.kind() == io::ErrorKind::NotFound {
                        continue;
                    }
                    return Err(fastmcp_core::McpError::internal_error(format!(
                        "Failed to verify a retained staging entry for {context} at {} through the secured directory descriptor (I/O kind: {:?})",
                        sanitize_config_path(destination),
                        error.kind()
                    )));
                }
            };
            let mode = metadata.st_mode & 0o7777;
            let effective_user = rustix::process::geteuid().as_raw();
            let final_owner = final_snapshot.map(|snapshot| snapshot.metadata.owner);
            if !rustix::fs::FileType::from_raw_mode(metadata.st_mode).is_file()
                || (metadata.st_uid != effective_user && Some(metadata.st_uid) != final_owner)
                || metadata.st_nlink != 1
                || mode & 0o7022 != 0
            {
                continue;
            }
            retained = retained.saturating_add(1);
            if retained >= RETAINED_STAGE_MAX_FILES {
                return Err(fastmcp_core::McpError::internal_error(format!(
                    "Refusing to create another staging file for {context} at {}: at least {RETAINED_STAGE_MAX_FILES} plausible owner-controlled retained FastMCP stages require manual review",
                    sanitize_config_path(destination)
                )));
            }
        }
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for _ in 0..128 {
            let identifier = fastmcp_core::draw_security_identifier().map_err(|_| {
                fastmcp_core::McpError::internal_error(format!(
                    "Failed to obtain operating-system randomness for a retained {purpose} staging name for {context} at {}",
                    sanitize_config_path(destination)
                ))
            })?;
            let mut name = String::with_capacity(".fastmcp-stage-".len() + 64);
            name.push_str(".fastmcp-stage-");
            for byte in identifier.as_bytes() {
                name.push(char::from(HEX[usize::from(*byte >> 4)]));
                name.push(char::from(HEX[usize::from(*byte & 0x0f)]));
            }
            let relative_name = std::ffi::OsString::from(name);
            let opened = rustix::fs::openat(
                &parent.handle,
                &relative_name,
                rustix::fs::OFlags::RDWR
                    | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::EXCL
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NOFOLLOW,
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            );
            let file = match opened {
                Ok(file) => File::from(file),
                Err(error) => {
                    let error = io::Error::from(error);
                    if error.kind() == io::ErrorKind::AlreadyExists {
                        continue;
                    }
                    return Err(fastmcp_core::McpError::internal_error(format!(
                        "Failed to create descriptor-anchored same-directory {purpose} staging file for {context} at {} (I/O kind: {:?})",
                        sanitize_config_path(destination),
                        error.kind()
                    )));
                }
            };
            let mut staged = RetainedStage {
                diagnostic_path: parent.path.join(&relative_name),
                relative_name,
                file,
                staging_owner: rustix::process::geteuid().as_raw(),
                staging_group: rustix::process::getegid().as_raw(),
                staging_device: 0,
                staging_inode: 0,
            };
            if let Err(error) = staged
                .as_file()
                .set_permissions(Permissions::from_mode(0o600))
            {
                return Err(retained_stage_error(
                    destination,
                    context,
                    staged.diagnostic_path(),
                    &format!(
                        "setting exact owner-only staging permissions failed (I/O kind: {:?})",
                        error.kind()
                    ),
                ));
            }
            let metadata = staged.as_file().metadata().map_err(|error| {
                retained_stage_error(
                    destination,
                    context,
                    staged.diagnostic_path(),
                    &format!(
                        "verifying the newly created staging descriptor failed (I/O kind: {:?})",
                        error.kind()
                    ),
                )
            })?;
            if !metadata.is_file()
                || metadata.uid() != staged.staging_owner
                || metadata.mode() & 0o7777 != 0o600
                || metadata.nlink() != 1
            {
                return Err(retained_stage_error(
                    destination,
                    context,
                    staged.diagnostic_path(),
                    "the newly created staging inode did not have the required owner-only identity, permissions, and link count",
                ));
            }
            // A secure setgid parent legitimately supplies the new inode's
            // group. Capture that descriptor-observed group for retention and
            // new-file publication instead of assuming the process egid.
            staged.staging_group = metadata.gid();
            staged.staging_device = metadata.dev();
            staged.staging_inode = metadata.ino();
            verify_staged_path_identity(parent, &staged, destination, context)?;
            verify_staged_contents_and_metadata(parent, &staged, &[], None, destination, context)?;
            return Ok(staged);
        }
        Err(fastmcp_core::McpError::internal_error(format!(
            "Failed to allocate a collision-free retained {purpose} staging name for {context} at {} after 128 attempts",
            sanitize_config_path(destination)
        )))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (parent, final_snapshot, destination, context, purpose);
        Err(fastmcp_core::McpError::internal_error(
            "Descriptor-anchored retained staging is unavailable on this platform",
        ))
    }
}

fn verify_staged_path_identity(
    parent: &SecuredParentDirectory,
    staged: &RetainedStage,
    destination: &Path,
    context: &str,
) -> McpResult<()> {
    match descriptor_name_matches_staged_file(parent, staged, staged.relative_name()) {
        Ok(true) => Ok(()),
        Ok(false) => Err(retained_stage_error(
            destination,
            context,
            staged.diagnostic_path(),
            "the descriptor-relative staged name changed identity, stopped being a regular file, disappeared, or gained another hard link",
        )),
        Err(error) => Err(retained_stage_error(
            destination,
            context,
            staged.diagnostic_path(),
            &format!(
                "reinspecting the descriptor-relative staged name failed (I/O kind: {:?})",
                error.kind()
            ),
        )),
    }
}

fn retained_stage_error(
    destination: &Path,
    context: &str,
    staged_path: &Path,
    detail: &str,
) -> fastmcp_core::McpError {
    let relative_name = staged_path.file_name().map_or_else(
        || "<unknown>".to_owned(),
        |name| sanitize_peer_text(&name.to_string_lossy(), TERMINAL_TEXT_LIMIT),
    );
    fastmcp_core::McpError::internal_error(format!(
        "Failed to commit {context} at {}: {detail}. FastMCP intentionally did not unlink the descriptor-relative candidate named {relative_name}; the detail above describes its last observed completeness and reachability. Its last-known diagnostic path was {}, but that path association is not guaranteed. Do not retry blindly",
        sanitize_config_path(destination),
        sanitize_config_path(staged_path)
    ))
}

fn stage_retained_contents(
    parent: &SecuredParentDirectory,
    staged: &mut RetainedStage,
    contents: &[u8],
    destination: &Path,
    context: &str,
) -> McpResult<()> {
    verify_staged_path_identity(parent, staged, destination, context)?;
    if let Err(error) = staged.as_file_mut().write_all(contents) {
        return Err(retained_stage_error(
            destination,
            context,
            staged.diagnostic_path(),
            &format!("staging write failed (I/O kind: {:?})", error.kind()),
        ));
    }

    // Keep the unpublished secret-bearing inode at 0600. Replacement
    // ownership is established only during final pre-rename preparation, and
    // broader destination permissions are restored only after publication.
    #[cfg(target_os = "linux")]
    {
        let attribute_names = list_extended_attribute_names(staged.as_file()).map_err(|error| {
            retained_stage_error(
                destination,
                context,
                staged.diagnostic_path(),
                &format!(
                    "verifying staged ACL metadata failed (I/O kind: {:?})",
                    error.kind()
                ),
            )
        })?;
        if extended_attribute_list_contains(&attribute_names, b"system.posix_acl_access")
            || extended_attribute_list_contains(&attribute_names, b"system.posix_acl_default")
        {
            return Err(retained_stage_error(
                destination,
                context,
                staged.diagnostic_path(),
                "the staged inode inherited POSIX ACL metadata that cannot be published safely",
            ));
        }
        match linux_platform_attributes_present(staged.as_file()) {
            Ok(false) => {}
            Ok(true) => {
                return Err(retained_stage_error(
                    destination,
                    context,
                    staged.diagnostic_path(),
                    "the staged inode acquired unsupported filesystem attributes",
                ));
            }
            Err(error) => {
                return Err(retained_stage_error(
                    destination,
                    context,
                    staged.diagnostic_path(),
                    &format!(
                        "verifying staged filesystem attributes failed (I/O kind: {:?})",
                        error.kind()
                    ),
                ));
            }
        }
    }
    if let Err(error) = staged.as_file().sync_all() {
        return Err(retained_stage_error(
            destination,
            context,
            staged.diagnostic_path(),
            &format!("staging sync failed (I/O kind: {:?})", error.kind()),
        ));
    }
    verify_staged_contents_and_metadata(parent, staged, contents, None, destination, context)?;
    Ok(())
}

fn prepare_staged_for_publication(
    parent: &SecuredParentDirectory,
    staged: &RetainedStage,
    contents: &[u8],
    final_snapshot: Option<&ExistingFileSnapshot>,
    destination: &Path,
    context: &str,
) -> McpResult<()> {
    // First verify the private candidate under its original staging identity.
    // When replacing an existing file, establish the intended final owner and
    // group before rename while retaining exact 0600 permissions. This makes a
    // failed chown a pre-publication failure and ensures a crash can leave only
    // an owner-correct but overly restrictive candidate.
    verify_staged_contents_and_metadata(parent, staged, contents, None, destination, context)?;
    #[cfg(target_os = "linux")]
    if let Some(snapshot) = final_snapshot {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let current = staged.as_file().metadata().map_err(|error| {
            retained_stage_error(
                destination,
                context,
                staged.diagnostic_path(),
                &format!(
                    "inspecting staged ownership before publication failed (I/O kind: {:?})",
                    error.kind()
                ),
            )
        })?;
        if current.uid() != snapshot.metadata.owner || current.gid() != snapshot.metadata.group {
            verify_staged_path_identity(parent, staged, destination, context)?;
            rustix::fs::fchown(
                staged.as_file(),
                Some(rustix::fs::Uid::from_raw(snapshot.metadata.owner)),
                Some(rustix::fs::Gid::from_raw(snapshot.metadata.group)),
            )
            .map_err(|error| {
                retained_stage_error(
                    destination,
                    context,
                    staged.diagnostic_path(),
                    &format!(
                        "establishing final ownership before publication failed (I/O kind: {:?})",
                        io::Error::from(error).kind()
                    ),
                )
            })?;
        }
        // chown may clear permission bits on some systems. Reassert the exact
        // private mode after ownership transfer and make it durable before the
        // publication window.
        verify_staged_path_identity(parent, staged, destination, context)?;
        staged
            .as_file()
            .set_permissions(Permissions::from_mode(0o600))
            .map_err(|error| {
                retained_stage_error(
                    destination,
                    context,
                    staged.diagnostic_path(),
                    &format!(
                        "restoring private permissions after staged ownership transfer failed (I/O kind: {:?})",
                        error.kind()
                    ),
                )
            })?;
        staged.as_file().sync_all().map_err(|error| {
            retained_stage_error(
                destination,
                context,
                staged.diagnostic_path(),
                &format!(
                    "syncing final staged ownership before publication failed (I/O kind: {:?})",
                    error.kind()
                ),
            )
        })?;
    }
    verify_staged_contents_and_metadata(
        parent,
        staged,
        contents,
        final_snapshot,
        destination,
        context,
    )?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_private_published_file(
    staged: &RetainedStage,
    expected_contents: &[u8],
    final_snapshot: Option<&ExistingFileSnapshot>,
    destination: &Path,
    context: &str,
) -> McpResult<()> {
    use std::os::unix::fs::MetadataExt as _;

    let expected_owner =
        final_snapshot.map_or(staged.staging_owner, |snapshot| snapshot.metadata.owner);
    let expected_group =
        final_snapshot.map_or(staged.staging_group, |snapshot| snapshot.metadata.group);
    let private_before = staged.as_file().metadata().map_err(|error| {
        fastmcp_core::McpError::internal_error(format!(
            "Publication of {context} at {} was committed, but inspecting the private published candidate failed (I/O kind: {:?}). Do not retry blindly",
            sanitize_config_path(destination),
            error.kind()
        ))
    })?;
    if private_before.len() != u64::try_from(expected_contents.len()).unwrap_or(u64::MAX)
        || !private_before.is_file()
        || private_before.uid() != expected_owner
        || private_before.gid() != expected_group
        || private_before.mode() & 0o7777 != 0o600
        || private_before.nlink() != 1
    {
        return Err(fastmcp_core::McpError::internal_error(format!(
            "Publication of {context} at {} was committed, but the published inode did not retain its verified owner, group, private 0600 mode, type, length, and link count before permission finalization. Do not retry blindly",
            sanitize_config_path(destination)
        )));
    }
    let private_attribute_names =
        list_extended_attribute_names(staged.as_file()).map_err(|error| {
            fastmcp_core::McpError::internal_error(format!(
                "Publication of {context} at {} was committed, but inspecting private published extended attributes failed (I/O kind: {:?}). Do not retry blindly",
                sanitize_config_path(destination),
                error.kind()
            ))
        })?;
    let private_unsupported_attribute = private_attribute_names
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .any(|name| name != b"security.selinux");
    let private_platform_attributes =
        linux_platform_attributes_present(staged.as_file()).map_err(|error| {
            fastmcp_core::McpError::internal_error(format!(
                "Publication of {context} at {} was committed, but inspecting private published filesystem attributes failed (I/O kind: {:?}). Do not retry blindly",
                sanitize_config_path(destination),
                error.kind()
            ))
        })?;
    if private_unsupported_attribute || private_platform_attributes {
        return Err(fastmcp_core::McpError::internal_error(format!(
            "Publication of {context} at {} was committed, but the private published inode acquired unsupported security metadata or filesystem attributes before permission finalization. Do not retry blindly",
            sanitize_config_path(destination)
        )));
    }
    let mut private_reader = staged.as_file().try_clone().map_err(|error| {
        fastmcp_core::McpError::internal_error(format!(
            "Publication of {context} at {} was committed, but cloning the private published descriptor failed (I/O kind: {:?}). Do not retry blindly",
            sanitize_config_path(destination),
            error.kind()
        ))
    })?;
    private_reader.rewind().map_err(|error| {
        fastmcp_core::McpError::internal_error(format!(
            "Publication of {context} at {} was committed, but rewinding the private published descriptor failed (I/O kind: {:?}). Do not retry blindly",
            sanitize_config_path(destination),
            error.kind()
        ))
    })?;
    let mut private_contents = Vec::with_capacity(expected_contents.len());
    Read::by_ref(&mut private_reader)
        .take(
            u64::try_from(expected_contents.len())
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut private_contents)
        .map_err(|error| {
            fastmcp_core::McpError::internal_error(format!(
                "Publication of {context} at {} was committed, but reading the private published descriptor failed (I/O kind: {:?}). Do not retry blindly",
                sanitize_config_path(destination),
                error.kind()
            ))
        })?;
    let private_after = staged.as_file().metadata().map_err(|error| {
        fastmcp_core::McpError::internal_error(format!(
            "Publication of {context} at {} was committed, but reinspecting the private published descriptor failed (I/O kind: {:?}). Do not retry blindly",
            sanitize_config_path(destination),
            error.kind()
        ))
    })?;
    if private_contents != expected_contents
        || FileMetadataStamp::from_metadata(&private_before)
            != FileMetadataStamp::from_metadata(&private_after)
    {
        return Err(fastmcp_core::McpError::internal_error(format!(
            "Publication of {context} at {} was committed, but the private published contents or metadata changed before permission finalization. Do not retry blindly",
            sanitize_config_path(destination)
        )));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn verify_private_published_file(
    _staged: &RetainedStage,
    _expected_contents: &[u8],
    _final_snapshot: Option<&ExistingFileSnapshot>,
    destination: &Path,
    context: &str,
) -> McpResult<()> {
    Err(fastmcp_core::McpError::internal_error(format!(
        "Private published-file verification is unavailable for {context} at {}",
        sanitize_config_path(destination)
    )))
}

#[cfg(target_os = "linux")]
fn finalize_published_file_metadata(
    parent: &SecuredParentDirectory,
    durability_proof: DurablePublication,
    staged: &RetainedStage,
    destination_name: &std::ffi::OsStr,
    expected_contents: &[u8],
    final_snapshot: Option<&ExistingFileSnapshot>,
    destination: &Path,
    context: &str,
) -> McpResult<()> {
    finalize_published_file_metadata_with_hooks(
        parent,
        durability_proof,
        staged,
        destination_name,
        expected_contents,
        final_snapshot,
        destination,
        context,
        |_| Ok(()),
        |_| Ok(()),
    )
}

#[cfg(target_os = "linux")]
fn finalize_published_file_metadata_with_hooks<F, G>(
    parent: &SecuredParentDirectory,
    durability_proof: DurablePublication,
    staged: &RetainedStage,
    destination_name: &std::ffi::OsStr,
    expected_contents: &[u8],
    final_snapshot: Option<&ExistingFileSnapshot>,
    destination: &Path,
    context: &str,
    after_private_verification: F,
    after_permission_change: G,
) -> McpResult<()>
where
    F: FnOnce(&RetainedStage) -> McpResult<()>,
    G: FnOnce(&RetainedStage) -> McpResult<()>,
{
    use std::os::unix::fs::MetadataExt as _;

    let ensure_authorized = |phase: &str, require_private_candidate: bool| match durability_proof
        .authorizes(parent, staged, destination_name, require_private_candidate)
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(fastmcp_core::McpError::internal_error(format!(
            "Refusing to finalize publication of {context} at {} {phase}: the one-shot durability proof does not authorize the current secured parent stamp, destination name, and published candidate inode",
            sanitize_config_path(destination)
        ))),
        Err(error) => Err(fastmcp_core::McpError::internal_error(format!(
            "Refusing to finalize publication of {context} at {} {phase}: revalidating the one-shot durability proof failed (I/O kind: {:?})",
            sanitize_config_path(destination),
            error.kind()
        ))),
    };
    ensure_authorized("before private verification", true)?;
    verify_private_published_file(
        staged,
        expected_contents,
        final_snapshot,
        destination,
        context,
    )?;
    after_private_verification(staged)?;
    let publication_location = classify_stage_publication(parent, staged, destination_name)
        .map_err(|error| {
            fastmcp_core::McpError::internal_error(format!(
                "Publication of {context} at {} was privately verified, but descriptor-relative identity inspection immediately before permission finalization failed (I/O kind: {:?}); FastMCP did not widen its permissions. Do not retry blindly",
                sanitize_config_path(destination),
                error.kind()
            ))
        })?;
    if publication_location != StagePublicationLocation::Published {
        return Err(fastmcp_core::McpError::internal_error(format!(
            "Publication of {context} at {} was privately verified, but descriptor-relative identity was {publication_location:?} immediately before permission finalization; FastMCP did not widen its permissions. Do not retry blindly",
            sanitize_config_path(destination)
        )));
    }
    // Recheck the parent mutation stamp after the final test seam and the
    // final Published classification. This detects rename-away/rename-back
    // ABA changes when the filesystem exposes a changed directory stamp. A
    // non-cooperating actor can still race any userspace check, and coarse
    // timestamp filesystems can hide an ABA cycle; this is deliberately not a
    // kernel-enforced CAS claim.
    ensure_authorized("immediately before permission finalization", true)?;
    let expected_owner =
        final_snapshot.map_or(staged.staging_owner, |snapshot| snapshot.metadata.owner);
    let expected_group =
        final_snapshot.map_or(staged.staging_group, |snapshot| snapshot.metadata.group);

    if let Some(snapshot) = final_snapshot {
        // Ownership was already established and verified before rename. Only
        // widen permissions after publication is positively observed.
        staged
            .as_file()
            .set_permissions(snapshot.permissions.clone())
            .map_err(|error| {
                fastmcp_core::McpError::internal_error(format!(
                    "Publication of {context} at {} was committed, but restoring final permissions failed (I/O kind: {:?}); metadata finalization is incomplete. Do not retry blindly",
                    sanitize_config_path(destination),
                    error.kind()
                ))
            })?;
    }
    after_permission_change(staged)?;

    let before = staged.as_file().metadata().map_err(|error| {
        fastmcp_core::McpError::internal_error(format!(
            "Publication of {context} at {} was committed, but final metadata inspection failed (I/O kind: {:?}). Do not retry blindly",
            sanitize_config_path(destination),
            error.kind()
        ))
    })?;
    let expected_mode = final_snapshot.map_or(0o600, |snapshot| snapshot.metadata.mode & 0o7777);
    if before.len() != u64::try_from(expected_contents.len()).unwrap_or(u64::MAX)
        || !before.is_file()
        || before.uid() != expected_owner
        || before.gid() != expected_group
        || before.mode() & 0o7777 != expected_mode
        || before.nlink() != 1
    {
        return Err(fastmcp_core::McpError::internal_error(format!(
            "Publication of {context} at {} was committed, but its final length, ownership, permissions, type, or link count did not match the verified candidate. Do not retry blindly",
            sanitize_config_path(destination)
        )));
    }
    let attribute_names = list_extended_attribute_names(staged.as_file()).map_err(|error| {
        fastmcp_core::McpError::internal_error(format!(
            "Publication of {context} at {} was committed, but final extended-attribute inspection failed (I/O kind: {:?}). Do not retry blindly",
            sanitize_config_path(destination),
            error.kind()
        ))
    })?;
    let unsupported_attribute = attribute_names
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .any(|name| name != b"security.selinux");
    let platform_attributes_present =
        linux_platform_attributes_present(staged.as_file()).map_err(|error| {
            fastmcp_core::McpError::internal_error(format!(
                "Publication of {context} at {} was committed, but final filesystem-attribute inspection failed (I/O kind: {:?}). Do not retry blindly",
                sanitize_config_path(destination),
                error.kind()
            ))
        })?;
    if unsupported_attribute || platform_attributes_present {
        return Err(fastmcp_core::McpError::internal_error(format!(
            "Publication of {context} at {} was committed, but the published inode has unsupported security metadata or filesystem attributes. Do not retry blindly",
            sanitize_config_path(destination)
        )));
    }
    staged.as_file().sync_all().map_err(|error| {
        fastmcp_core::McpError::internal_error(format!(
            "Publication of {context} at {} was committed, but final inode sync failed (I/O kind: {:?}); durability is uncertain. Do not retry blindly",
            sanitize_config_path(destination),
            error.kind()
        ))
    })?;
    let mut reader = staged.as_file().try_clone().map_err(|error| {
        fastmcp_core::McpError::internal_error(format!(
            "Publication of {context} at {} was committed, but cloning the published descriptor for final content verification failed (I/O kind: {:?}). Do not retry blindly",
            sanitize_config_path(destination),
            error.kind()
        ))
    })?;
    reader.rewind().map_err(|error| {
        fastmcp_core::McpError::internal_error(format!(
            "Publication of {context} at {} was committed, but rewinding the published descriptor for final content verification failed (I/O kind: {:?}). Do not retry blindly",
            sanitize_config_path(destination),
            error.kind()
        ))
    })?;
    let mut actual = Vec::with_capacity(expected_contents.len());
    Read::by_ref(&mut reader)
        .take(
            u64::try_from(expected_contents.len())
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut actual)
        .map_err(|error| {
            fastmcp_core::McpError::internal_error(format!(
                "Publication of {context} at {} was committed, but reading the published descriptor for final content verification failed (I/O kind: {:?}). Do not retry blindly",
                sanitize_config_path(destination),
                error.kind()
            ))
        })?;
    if actual != expected_contents {
        return Err(fastmcp_core::McpError::internal_error(format!(
            "Publication of {context} at {} was committed, but its contents changed during metadata finalization. Do not retry blindly",
            sanitize_config_path(destination)
        )));
    }
    let after = staged.as_file().metadata().map_err(|error| {
        fastmcp_core::McpError::internal_error(format!(
            "Publication of {context} at {} was committed, but final metadata reinspection failed (I/O kind: {:?}). Do not retry blindly",
            sanitize_config_path(destination),
            error.kind()
        ))
    })?;
    if FileMetadataStamp::from_metadata(&before) != FileMetadataStamp::from_metadata(&after) {
        return Err(fastmcp_core::McpError::internal_error(format!(
            "Publication of {context} at {} was committed, but metadata changed during finalization. Do not retry blindly",
            sanitize_config_path(destination)
        )));
    }
    let final_location = classify_stage_publication(parent, staged, destination_name).map_err(
        |error| {
            fastmcp_core::McpError::internal_error(format!(
                "Publication of {context} at {} completed permission and inode metadata finalization, but final descriptor-relative identity inspection failed (I/O kind: {:?}). Final permissions may already be visible at an indeterminate name; do not retry blindly",
                sanitize_config_path(destination),
                error.kind()
            ))
        },
    )?;
    if final_location != StagePublicationLocation::Published {
        return Err(fastmcp_core::McpError::internal_error(format!(
            "Publication of {context} at {} completed permission and inode metadata finalization, but final descriptor-relative identity was {final_location:?}. Final permissions may already be visible at an indeterminate name; do not retry blindly",
            sanitize_config_path(destination)
        )));
    }
    match durability_proof.authorizes(parent, staged, destination_name, false) {
        Ok(true) => {}
        Ok(false) => {
            return Err(fastmcp_core::McpError::internal_error(format!(
                "Publication of {context} at {} completed permission and inode metadata finalization, but the one-shot durability proof no longer authorizes the current parent stamp, destination name, and candidate inode. Final permissions may already be visible at an indeterminate name; do not retry blindly",
                sanitize_config_path(destination)
            )));
        }
        Err(error) => {
            return Err(fastmcp_core::McpError::internal_error(format!(
                "Publication of {context} at {} completed permission and inode metadata finalization, but final revalidation of the one-shot durability proof failed (I/O kind: {:?}). Final permissions may already be visible at an indeterminate name; do not retry blindly",
                sanitize_config_path(destination),
                error.kind()
            )));
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn finalize_published_file_metadata(
    _parent: &SecuredParentDirectory,
    _durability_proof: DurablePublication,
    _staged: &RetainedStage,
    _destination_name: &std::ffi::OsStr,
    _expected_contents: &[u8],
    _final_snapshot: Option<&ExistingFileSnapshot>,
    destination: &Path,
    context: &str,
) -> McpResult<()> {
    Err(fastmcp_core::McpError::internal_error(format!(
        "Published-file metadata finalization is unavailable for {context} at {}",
        sanitize_config_path(destination)
    )))
}

#[cfg(target_os = "linux")]
fn verify_staged_contents_and_metadata(
    parent: &SecuredParentDirectory,
    staged: &RetainedStage,
    expected_contents: &[u8],
    final_snapshot: Option<&ExistingFileSnapshot>,
    destination: &Path,
    context: &str,
) -> McpResult<StableStatStamp> {
    use std::os::unix::fs::MetadataExt as _;

    verify_staged_path_identity(parent, staged, destination, context)?;
    let before = staged.as_file().metadata().map_err(|error| {
        retained_stage_error(
            destination,
            context,
            staged.diagnostic_path(),
            &format!(
                "inspecting staged metadata failed (I/O kind: {:?})",
                error.kind()
            ),
        )
    })?;
    let expected_mode = 0o600;
    let expected_owner =
        final_snapshot.map_or(staged.staging_owner, |snapshot| snapshot.metadata.owner);
    let expected_group =
        final_snapshot.map_or(staged.staging_group, |snapshot| snapshot.metadata.group);
    if before.len() != u64::try_from(expected_contents.len()).unwrap_or(u64::MAX)
        || before.mode() & 0o7777 != expected_mode
        || before.uid() != expected_owner
        || before.gid() != expected_group
        || before.nlink() != 1
    {
        return Err(retained_stage_error(
            destination,
            context,
            staged.diagnostic_path(),
            "staged length, ownership, permissions, or link count changed before publication",
        ));
    }

    let mut reader = staged.as_file().try_clone().map_err(|error| {
        retained_stage_error(
            destination,
            context,
            staged.diagnostic_path(),
            &format!(
                "cloning the staged descriptor for verification failed (I/O kind: {:?})",
                error.kind()
            ),
        )
    })?;
    reader.rewind().map_err(|error| {
        retained_stage_error(
            destination,
            context,
            staged.diagnostic_path(),
            &format!(
                "rewinding the staged descriptor for verification failed (I/O kind: {:?})",
                error.kind()
            ),
        )
    })?;
    let mut actual = Vec::with_capacity(expected_contents.len());
    Read::by_ref(&mut reader)
        .take(
            u64::try_from(expected_contents.len())
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut actual)
        .map_err(|error| {
            retained_stage_error(
                destination,
                context,
                staged.diagnostic_path(),
                &format!(
                    "reading the staged descriptor for verification failed (I/O kind: {:?})",
                    error.kind()
                ),
            )
        })?;
    if actual != expected_contents {
        return Err(retained_stage_error(
            destination,
            context,
            staged.diagnostic_path(),
            "staged contents changed before publication",
        ));
    }

    let attribute_names = list_extended_attribute_names(staged.as_file()).map_err(|error| {
        retained_stage_error(
            destination,
            context,
            staged.diagnostic_path(),
            &format!(
                "rechecking staged extended attributes failed (I/O kind: {:?})",
                error.kind()
            ),
        )
    })?;
    let unsupported_attribute = attribute_names
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .any(|name| name != b"security.selinux");
    if unsupported_attribute {
        return Err(retained_stage_error(
            destination,
            context,
            staged.diagnostic_path(),
            "the staged inode acquired an unsupported extended attribute",
        ));
    }
    match linux_platform_attributes_present(staged.as_file()) {
        Ok(false) => {}
        Ok(true) => {
            return Err(retained_stage_error(
                destination,
                context,
                staged.diagnostic_path(),
                "the staged inode acquired an unsupported filesystem attribute",
            ));
        }
        Err(error) => {
            return Err(retained_stage_error(
                destination,
                context,
                staged.diagnostic_path(),
                &format!(
                    "rechecking staged filesystem attributes failed (I/O kind: {:?})",
                    error.kind()
                ),
            ));
        }
    }

    let after = staged.as_file().metadata().map_err(|error| {
        retained_stage_error(
            destination,
            context,
            staged.diagnostic_path(),
            &format!(
                "reinspecting staged metadata failed (I/O kind: {:?})",
                error.kind()
            ),
        )
    })?;
    if FileMetadataStamp::from_metadata(&after) != FileMetadataStamp::from_metadata(&before) {
        return Err(retained_stage_error(
            destination,
            context,
            staged.diagnostic_path(),
            "staged metadata changed during final verification",
        ));
    }
    verify_staged_path_identity(parent, staged, destination, context)?;
    let final_metadata = staged.as_file().metadata().map_err(|error| {
        retained_stage_error(
            destination,
            context,
            staged.diagnostic_path(),
            &format!(
                "reinspecting staged metadata after the final name binding check failed (I/O kind: {:?})",
                error.kind()
            ),
        )
    })?;
    if FileMetadataStamp::from_metadata(&final_metadata) != FileMetadataStamp::from_metadata(&after)
    {
        return Err(retained_stage_error(
            destination,
            context,
            staged.diagnostic_path(),
            "staged metadata changed during the final name binding check",
        ));
    }
    Ok(StableStatStamp::from_metadata(&final_metadata))
}

#[cfg(not(target_os = "linux"))]
fn verify_staged_contents_and_metadata(
    _parent: &SecuredParentDirectory,
    _staged: &RetainedStage,
    _expected_contents: &[u8],
    _final_snapshot: Option<&ExistingFileSnapshot>,
    destination: &Path,
    context: &str,
) -> McpResult<StableStatStamp> {
    Err(fastmcp_core::McpError::internal_error(format!(
        "Staged-file verification is unavailable for {context} at {}",
        sanitize_config_path(destination)
    )))
}

fn backup_path_for(config_path: &Path) -> PathBuf {
    let mut backup_path = config_path.as_os_str().to_os_string();
    backup_path.push(".bak");
    PathBuf::from(backup_path)
}

fn backup_path_for_version(config_path: &Path, version: usize) -> PathBuf {
    let mut backup_path = backup_path_for(config_path).into_os_string();
    if version > 0 {
        backup_path.push(format!(".{version}"));
    }
    PathBuf::from(backup_path)
}

fn create_backup_if_exists(
    secured_parent: SecuredParentDirectory,
    config_name: &std::ffi::OsStr,
    config_path: &Path,
    original: &DestinationSnapshot,
) -> McpResult<(SecuredParentDirectory, Option<PathBuf>)> {
    create_backup_if_exists_with_hook(
        secured_parent,
        config_name,
        config_path,
        original,
        |_, _, _| Ok(()),
    )
}

fn create_backup_if_exists_with_hook<F>(
    secured_parent: SecuredParentDirectory,
    config_name: &std::ffi::OsStr,
    config_path: &Path,
    original: &DestinationSnapshot,
    mut before_publication: F,
) -> McpResult<(SecuredParentDirectory, Option<PathBuf>)>
where
    F: FnMut(usize, &Path, &RetainedStage) -> McpResult<()>,
{
    let DestinationSnapshot::Existing(original_file) = original else {
        return Ok((secured_parent, None));
    };
    validate_atomic_destination_name(config_path, "installation config backup")?;
    validate_snapshot_for_replacement(original_file, config_path, "installation config backup")?;
    let current = read_destination_snapshot_at(
        &secured_parent,
        config_name,
        config_path,
        "installation target config",
        CONFIG_INPUT_MAX_BYTES,
    )?;
    if !original.matches(&current) {
        return Err(fastmcp_core::McpError::invalid_params(format!(
            "Installation config at {} changed while the held backup transaction was preparing its descriptor-relative snapshot; no backup or config write was attempted",
            sanitize_config_path(config_path)
        )));
    }
    secured_parent.validate_staging_policy(config_path, "installation config backup")?;
    let mut staged = create_retained_same_directory_temp(
        &secured_parent,
        Some(original_file),
        config_path,
        "installation config backup",
        "backup",
    )?;
    stage_retained_contents(
        &secured_parent,
        &mut staged,
        &original_file.bytes,
        config_path,
        "installation config backup",
    )?;
    secured_parent
        .revalidate(config_path, "installation config backup")
        .map_err(|error| {
            retained_stage_error(
                config_path,
                "installation config backup",
                staged.diagnostic_path(),
                &format!(
                    "secured parent-path revalidation failed after staging: {}",
                    error.message
                ),
            )
        })?;
    verify_staged_path_identity(
        &secured_parent,
        &staged,
        config_path,
        "installation config backup",
    )?;
    // Prepare ownership and private mode exactly once. A no-clobber collision
    // can retry another backup name without trying to restore staging
    // ownership between attempts.
    prepare_staged_for_publication(
        &secured_parent,
        &staged,
        &original_file.bytes,
        Some(original_file),
        config_path,
        "installation config backup",
    )?;

    for version in 0..1_024 {
        let backup_path = backup_path_for_version(config_path, version);
        let backup_name = backup_path.file_name().ok_or_else(|| {
            retained_stage_error(
                config_path,
                "installation config backup",
                staged.diagnostic_path(),
                "the versioned backup path has no relative file name",
            )
        })?;
        match descriptor_relative_name_exists(&secured_parent, backup_name) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => {
                return Err(retained_stage_error(
                    config_path,
                    "installation config backup",
                    staged.diagnostic_path(),
                    &format!(
                        "inspecting the versioned backup name {} failed before publication (I/O kind: {:?}); the owner-only candidate has not entered the publication window",
                        sanitize_config_path(&backup_path),
                        error.kind()
                    ),
                ));
            }
        }
        let current = read_destination_snapshot_at(
            &secured_parent,
            config_name,
            config_path,
            "installation target config",
            CONFIG_INPUT_MAX_BYTES,
        )
        .map_err(|error| {
            retained_stage_error(
                config_path,
                "installation config backup",
                staged.diagnostic_path(),
                &format!(
                    "descriptor-relative installation-config revalidation failed before backup publication: {}",
                    error.message
                ),
            )
        })?;
        if !original.matches(&current) {
            return Err(retained_stage_error(
                config_path,
                "installation config backup",
                staged.diagnostic_path(),
                "the installation config changed during final backup verification; no backup was published and the config was not changed by FastMCP",
            ));
        }
        secured_parent
            .revalidate(config_path, "installation config backup")
            .map_err(|error| {
                retained_stage_error(
                    config_path,
                    "installation config backup",
                    staged.diagnostic_path(),
                    &format!(
                        "final secured parent-path revalidation failed before backup publication: {}",
                        error.message
                    ),
                )
            })?;
        let verified_stage_stamp = verify_staged_contents_and_metadata(
            &secured_parent,
            &staged,
            &original_file.bytes,
            Some(original_file),
            config_path,
            "installation config backup",
        )?;
        verify_staged_path_identity(
            &secured_parent,
            &staged,
            config_path,
            "installation config backup",
        )?;
        match descriptor_relative_name_matches_snapshot(&secured_parent, config_name, original) {
            Ok(true) => {}
            Ok(false) => {
                return Err(retained_stage_error(
                    config_path,
                    "installation config backup",
                    staged.diagnostic_path(),
                    "the installation config metadata changed after final backup-content verification; no backup was published and the config was not changed by FastMCP",
                ));
            }
            Err(error) => {
                return Err(retained_stage_error(
                    config_path,
                    "installation config backup",
                    staged.diagnostic_path(),
                    &format!(
                        "the final descriptor-relative installation-config identity check failed before backup publication (I/O kind: {:?})",
                        error.kind()
                    ),
                ));
            }
        }
        match descriptor_relative_stage_matches_stamp(
            &secured_parent,
            staged.relative_name(),
            verified_stage_stamp,
        ) {
            Ok(true) => {}
            Ok(false) => {
                return Err(retained_stage_error(
                    config_path,
                    "installation config backup",
                    staged.diagnostic_path(),
                    "the staged backup name, inode, or verified metadata changed during the final installation-config identity check; refusing to publish it",
                ));
            }
            Err(error) => {
                return Err(retained_stage_error(
                    config_path,
                    "installation config backup",
                    staged.diagnostic_path(),
                    &format!(
                        "the final descriptor-relative staged-backup check failed (I/O kind: {:?})",
                        error.kind()
                    ),
                ));
            }
        }
        before_publication(version, &backup_path, &staged).map_err(|error| {
            retained_stage_error(
                config_path,
                "installation config backup",
                staged.diagnostic_path(),
                &format!(
                    "the pre-publication backup hook failed: {}",
                    sanitize_peer_text(&error.message, PEER_DETAIL_LIMIT)
                ),
            )
        })?;
        #[cfg(target_os = "linux")]
        let publication: io::Result<()> = rustix::fs::renameat_with(
            &secured_parent.handle,
            staged.relative_name(),
            &secured_parent.handle,
            backup_name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(Into::into);
        #[cfg(not(target_os = "linux"))]
        let publication: io::Result<()> = Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "atomic backup publication is unavailable",
        ));
        let publication_location =
            classify_stage_publication(&secured_parent, &staged, backup_name);
        match publication {
            Ok(()) => {
                if !matches!(
                    &publication_location,
                    Ok(StagePublicationLocation::Published)
                ) {
                    let state_detail = publication_location.map_or_else(
                        |identity_error| {
                            format!(
                                "descriptor-relative identity inspection failed with I/O kind {:?}",
                                identity_error.kind()
                            )
                        },
                        |state| format!("descriptor-relative identity state was {state:?}"),
                    );
                    let durability = secured_parent.sync();
                    let location =
                        secured_parent.revalidate(config_path, "installation config backup");
                    drop(staged);
                    let durability_detail = durability.map_or_else(
                        |sync_error| {
                            format!("parent sync failed with I/O kind {:?}", sync_error.kind())
                        },
                        |()| "the held parent descriptor was synced".to_owned(),
                    );
                    let location_detail = location.map_or_else(
                        |revalidation_error| {
                            format!(
                                "parent-path revalidation failed: {}",
                                revalidation_error.message
                            )
                        },
                        |()| "the original parent path was revalidated".to_owned(),
                    );
                    return Err(fastmcp_core::McpError::internal_error(format!(
                        "Installation config backup publication to {} returned success, but post-rename identity verification was indeterminate: {state_detail}; {durability_detail}, and {location_detail}. FastMCP did not change the installation config. Treat the backup as potentially completed and do not retry blindly",
                        sanitize_config_path(&backup_path)
                    )));
                }
                let durability_proof = match establish_publication_durability(
                    &secured_parent,
                    &staged,
                    backup_name,
                ) {
                    Ok(proof) => proof,
                    Err(error) => {
                        let observation =
                            classify_stage_publication(&secured_parent, &staged, backup_name);
                        let state_detail = reconcile_stage_state_after_observation(&observation);
                        let recovery_sync = secured_parent.sync();
                        let location =
                            secured_parent.revalidate(config_path, "installation config backup");
                        return Err(fastmcp_core::McpError::internal_error(format!(
                            "Installation config backup at {} was observed committed, but publication durability could not be established before permission finalization (I/O kind: {:?}); FastMCP did not widen the backup inode beyond the private 0600 mode it established. State observation: {state_detail}; best-effort recovery parent sync result: {:?}; parent-path revalidation: {}. FastMCP did not change the installation config, and the normal backup durability proof is unavailable. Do not retry blindly",
                            sanitize_config_path(&backup_path),
                            error.kind(),
                            recovery_sync.as_ref().map_err(io::Error::kind),
                            location.map_or_else(
                                |revalidation_error| revalidation_error.message,
                                |()| "succeeded".to_owned()
                            )
                        )));
                    }
                };
                if let Err(error) =
                    secured_parent.revalidate(config_path, "installation config backup")
                {
                    let observation =
                        classify_stage_publication(&secured_parent, &staged, backup_name);
                    let state_detail = reconcile_stage_state_after_observation(&observation);
                    return Err(fastmcp_core::McpError::internal_error(format!(
                        "Installation config backup at {} was made durable through the secured parent descriptor, but the original parent path could not be revalidated before permission finalization; FastMCP did not widen the backup inode beyond the private 0600 mode it established. State observation: {state_detail}. FastMCP did not change the installation config. Do not retry blindly. Revalidation detail: {}",
                        sanitize_config_path(&backup_path),
                        error.message
                    )));
                }
                let before_permission_finalization =
                    classify_stage_publication(&secured_parent, &staged, backup_name);
                if !matches!(
                    &before_permission_finalization,
                    Ok(StagePublicationLocation::Published)
                ) {
                    let state_detail =
                        reconcile_stage_state_after_observation(&before_permission_finalization);
                    return Err(fastmcp_core::McpError::internal_error(format!(
                        "Installation config backup at {} was made durable, but descriptor-relative identity was not still Published before permission finalization; FastMCP did not widen the backup inode beyond the private 0600 mode it established. State observation: {state_detail}. FastMCP did not change the installation config. Do not retry blindly",
                        sanitize_config_path(&backup_path)
                    )));
                }
                if let Err(error) = finalize_published_file_metadata(
                    &secured_parent,
                    durability_proof,
                    &staged,
                    backup_name,
                    &original_file.bytes,
                    Some(original_file),
                    &backup_path,
                    "installation config backup",
                ) {
                    let observation =
                        classify_stage_publication(&secured_parent, &staged, backup_name);
                    let state_detail = reconcile_stage_state_after_observation(&observation);
                    let directory_sync = secured_parent.sync();
                    let location =
                        secured_parent.revalidate(config_path, "installation config backup");
                    return Err(fastmcp_core::McpError::internal_error(format!(
                        "{} Post-failure backup state observation: {state_detail}; parent-directory sync after the backup metadata-finalization attempt: {:?}; parent-path revalidation: {}",
                        error.message,
                        directory_sync.as_ref().map_err(io::Error::kind),
                        location.map_or_else(
                            |revalidation_error| revalidation_error.message,
                            |()| "succeeded".to_owned()
                        )
                    )));
                }
                if let Err(error) =
                    secured_parent.revalidate(config_path, "installation config backup")
                {
                    let observation =
                        classify_stage_publication(&secured_parent, &staged, backup_name);
                    let state_detail = reconcile_stage_state_after_observation(&observation);
                    return Err(fastmcp_core::McpError::internal_error(format!(
                        "Installation config backup at {} was durably committed and inode-synced through held descriptors, but the original parent path could not be revalidated after metadata finalization. Final descriptor-relative state: {state_detail}. FastMCP did not change the installation config. Do not retry blindly. Revalidation detail: {}",
                        sanitize_config_path(&backup_path),
                        error.message
                    )));
                }
                // Keep the final destination-name classification as the last
                // observation before reporting backup success.
                let post_finalization =
                    classify_stage_publication(&secured_parent, &staged, backup_name);
                if !matches!(&post_finalization, Ok(StagePublicationLocation::Published)) {
                    let state_detail = reconcile_stage_state_after_observation(&post_finalization);
                    return Err(fastmcp_core::McpError::internal_error(format!(
                        "Installation config backup at {} was committed and metadata-finalized, but its final descriptor-relative destination identity was not Published; state observation: {state_detail}. FastMCP did not change the installation config. Do not retry blindly",
                        sanitize_config_path(&backup_path),
                    )));
                }
                drop(staged);
                return Ok((secured_parent, Some(backup_path)));
            }
            Err(error) => {
                let kind = error.kind();
                match &publication_location {
                    Ok(StagePublicationLocation::Staged)
                        if kind == io::ErrorKind::AlreadyExists =>
                    {
                        if let Err(verification_error) = verify_staged_contents_and_metadata(
                            &secured_parent,
                            &staged,
                            &original_file.bytes,
                            Some(original_file),
                            config_path,
                            "installation config backup",
                        ) {
                            let observation =
                                classify_stage_publication(&secured_parent, &staged, backup_name);
                            let state_detail =
                                reconcile_stage_state_after_observation(&observation);
                            let directory_sync = secured_parent.sync();
                            let location = secured_parent
                                .revalidate(config_path, "installation config backup");
                            return Err(retained_stage_error(
                                config_path,
                                "installation config backup",
                                staged.diagnostic_path(),
                                &format!(
                                    "the no-clobber backup rename lost a race for {}, and read-only verification of the initially observed retained candidate failed: {}; fresh state: {state_detail}; held-parent sync result: {:?}; parent-path revalidation: {}; FastMCP did not change the installation config",
                                    sanitize_config_path(&backup_path),
                                    sanitize_peer_text(
                                        &verification_error.message,
                                        PEER_DETAIL_LIMIT
                                    ),
                                    directory_sync.as_ref().map_err(io::Error::kind),
                                    location.map_or_else(
                                        |revalidation_error| revalidation_error.message,
                                        |()| "succeeded".to_owned()
                                    )
                                ),
                            ));
                        }
                    }
                    Ok(StagePublicationLocation::Staged) => {
                        let retained_verification = verify_staged_contents_and_metadata(
                            &secured_parent,
                            &staged,
                            &original_file.bytes,
                            Some(original_file),
                            config_path,
                            "installation config backup",
                        );
                        let directory_sync = secured_parent.sync();
                        return Err(retained_stage_error(
                            config_path,
                            "installation config backup",
                            staged.diagnostic_path(),
                            &format!(
                                "atomic versioned-backup publication to {} failed (I/O kind: {kind:?}); two descriptor-relative observations found the owner-only candidate at its staging name; read-only retained-candidate verification: {}; parent-directory sync result: {:?}; FastMCP did not change the installation config",
                                sanitize_config_path(&backup_path),
                                retained_verification.map_or_else(
                                    |verification_error| format!(
                                        "failed: {}",
                                        sanitize_peer_text(
                                            &verification_error.message,
                                            PEER_DETAIL_LIMIT
                                        )
                                    ),
                                    |_| "succeeded".to_owned()
                                ),
                                directory_sync.as_ref().map_err(io::Error::kind)
                            ),
                        ));
                    }
                    Ok(StagePublicationLocation::Published) => {
                        let private_verification = verify_private_published_file(
                            &staged,
                            &original_file.bytes,
                            Some(original_file),
                            &backup_path,
                            "installation config backup",
                        );
                        let post_verification_publication =
                            classify_stage_publication(&secured_parent, &staged, backup_name);
                        let publication_detail =
                            reconcile_stage_state_after_observation(&post_verification_publication);
                        let durability = secured_parent.sync();
                        let location =
                            secured_parent.revalidate(config_path, "installation config backup");
                        drop(staged);
                        let durability_detail = durability.map_or_else(
                            |sync_error| {
                                format!("parent sync failed with I/O kind {:?}", sync_error.kind())
                            },
                            |()| "the held parent descriptor was synced".to_owned(),
                        );
                        let location_detail = location.map_or_else(
                            |revalidation_error| {
                                format!(
                                    "parent-path revalidation failed: {}",
                                    revalidation_error.message
                                )
                            },
                            |()| "the original parent path was revalidated".to_owned(),
                        );
                        let private_detail = private_verification.map_or_else(
                            |verification_error| {
                                format!(
                                    "private committed-backup verification failed: {}",
                                    sanitize_peer_text(
                                        &verification_error.message,
                                        PEER_DETAIL_LIMIT
                                    )
                                )
                            },
                            |()| {
                                "the committed backup inode was verified at final ownership, exact expected contents, and private 0600 permissions".to_owned()
                            },
                        );
                        return Err(fastmcp_core::McpError::internal_error(format!(
                            "Installation config backup publication to {} reported an I/O failure ({kind:?}); the initial two descriptor-relative observations found the backup inode at the destination, then {private_detail}, and {publication_detail}; broader final permissions were not applied after the failed syscall; {durability_detail}, and {location_detail}. FastMCP did not change the installation config. Treat the current backup location as indeterminate unless the post-verification state is Published. Do not retry blindly",
                            sanitize_config_path(&backup_path)
                        )));
                    }
                    Ok(StagePublicationLocation::Indeterminate) | Err(_) => {
                        let state_detail = publication_location.as_ref().map_or_else(
                            |identity_error| format!("descriptor-relative identity inspection failed with I/O kind {:?}", identity_error.kind()),
                            |state| format!("descriptor-relative identity state was {state:?}"),
                        );
                        let durability = secured_parent.sync();
                        let location =
                            secured_parent.revalidate(config_path, "installation config backup");
                        let durability_detail = durability.map_or_else(
                            |sync_error| {
                                format!("parent sync failed with I/O kind {:?}", sync_error.kind())
                            },
                            |()| "the held parent descriptor was synced".to_owned(),
                        );
                        let location_detail = location.map_or_else(
                            |revalidation_error| {
                                format!(
                                    "parent-path revalidation failed: {}",
                                    revalidation_error.message
                                )
                            },
                            |()| "the original parent path was revalidated".to_owned(),
                        );
                        return Err(fastmcp_core::McpError::internal_error(format!(
                            "Installation config backup publication to {} reported an I/O failure ({kind:?}) and commit state is indeterminate: {state_detail}; {durability_detail}, and {location_detail}. FastMCP did not change the installation config. The candidate's last-known diagnostic path was {} but is not authoritative. Do not retry blindly",
                            sanitize_config_path(&backup_path),
                            sanitize_config_path(staged.diagnostic_path())
                        )));
                    }
                }
            }
        }
    }

    let final_verification = verify_staged_contents_and_metadata(
        &secured_parent,
        &staged,
        &original_file.bytes,
        Some(original_file),
        config_path,
        "installation config backup",
    );
    let directory_sync = secured_parent.sync();
    let verification_detail = final_verification.map_or_else(
        |error| {
            format!(
                "failed: {}",
                sanitize_peer_text(&error.message, PEER_DETAIL_LIMIT)
            )
        },
        |_| "succeeded".to_owned(),
    );
    Err(retained_stage_error(
        config_path,
        "installation config backup",
        staged.diagnostic_path(),
        &format!(
            "all 1024 bounded versioned backup names already existed; FastMCP did not change the installation config, the candidate remains staged, final read-only staged-content verification {verification_detail}, and parent-directory sync result was {:?}",
            directory_sync.as_ref().map_err(io::Error::kind)
        ),
    ))
}

fn validate_install_registry_counts(
    config_path: &Path,
    registry_name: &str,
    registry: &serde_json::Map<String, serde_json::Value>,
    inserted_name: &str,
) -> McpResult<()> {
    if registry.len() > CLI_OUTPUT_MAX_ITEMS
        || (registry.len() == CLI_OUTPUT_MAX_ITEMS && !registry.contains_key(inserted_name))
    {
        return Err(fastmcp_core::McpError::invalid_params(format!(
            "Refusing to update {registry_name} at {}: registry would exceed {CLI_OUTPUT_MAX_ITEMS} entries",
            sanitize_config_path(config_path)
        )));
    }

    for entry in registry.values() {
        let Some(entry) = entry.as_object() else {
            continue;
        };
        let nested_transport = entry
            .get("transport")
            .and_then(serde_json::Value::as_object);
        for transport_fields in std::iter::once(entry).chain(nested_transport) {
            if transport_fields
                .get("args")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|args| args.len() > CLI_OUTPUT_MAX_ITEMS)
            {
                return Err(fastmcp_core::McpError::invalid_params(format!(
                    "Refusing to update {registry_name} at {}: an existing argument list exceeds {CLI_OUTPUT_MAX_ITEMS} entries",
                    sanitize_config_path(config_path)
                )));
            }
            if transport_fields
                .get("env")
                .and_then(serde_json::Value::as_object)
                .is_some_and(|environment| environment.len() > CLI_OUTPUT_MAX_ITEMS)
            {
                return Err(fastmcp_core::McpError::invalid_params(format!(
                    "Refusing to update {registry_name} at {}: an existing environment exceeds {CLI_OUTPUT_MAX_ITEMS} entries",
                    sanitize_config_path(config_path)
                )));
            }
        }
    }
    Ok(())
}

fn install_json_registry(
    config_path: &Path,
    registry_name: &str,
    config: &(String, McpServerConfig),
    target: InstallTarget,
) -> McpResult<()> {
    validate_atomic_destination_name(config_path, "installation target config")?;
    ensure_atomic_replace_supported()?;
    let parent = usable_parent(config_path);
    let secured_parent =
        SecuredParentDirectory::open(parent, config_path, "installation target config")?;
    let config_name = config_path.file_name().ok_or_else(|| {
        fastmcp_core::McpError::invalid_params(format!(
            "Cannot update installation config at {}: destination has no relative file name",
            sanitize_config_path(config_path)
        ))
    })?;
    let (mut document, original) =
        read_json_config_or_empty_at(&secured_parent, config_name, config_path)?;
    let root = document.as_object_mut().ok_or_else(|| {
        fastmcp_core::McpError::invalid_params(format!(
            "Config root at {} must be a JSON object",
            sanitize_config_path(config_path)
        ))
    })?;
    let registry = root
        .entry(registry_name.to_owned())
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .ok_or_else(|| {
            fastmcp_core::McpError::invalid_params(format!(
                "{registry_name} at {} must be a JSON object",
                sanitize_config_path(config_path)
            ))
        })?;
    let name = sanitize_peer_text(&config.0, PEER_FIELD_LIMIT);
    let config_path_display = sanitize_config_path(config_path);
    let entry_existed = registry.contains_key(&config.0);
    if registry
        .get(&config.0)
        .and_then(serde_json::Value::as_object)
        .is_some_and(|entry| !has_valid_install_profile_fields(target, entry))
    {
        return Err(fastmcp_core::McpError::invalid_params(format!(
            "Existing server entry '{name}' in {registry_name} at {config_path_display} contains unsupported or malformed per-server fields; refusing to preserve or discard them"
        )));
    }
    let semantic_noop = registry
        .get(&config.0)
        .and_then(|existing| effective_installed_server_config(target, existing))
        .is_some_and(|existing| {
            let desired = install_config_with_preserved_environment(&existing, &config.1);
            server_configs_semantically_equal(&existing, &desired)
        });
    if semantic_noop {
        let current = read_destination_snapshot_at(
            &secured_parent,
            config_name,
            config_path,
            "installation target config",
            CONFIG_INPUT_MAX_BYTES,
        )?;
        secured_parent.revalidate(config_path, "installation target config")?;
        let final_identity = descriptor_relative_name_matches_snapshot(
            &secured_parent,
            config_name,
            &original,
        )
        .map_err(|error| {
            fastmcp_core::McpError::internal_error(format!(
                "Failed to complete descriptor-relative no-op verification for installation config at {} (I/O kind: {:?})",
                sanitize_config_path(config_path),
                error.kind()
            ))
        })?;
        if !original.matches(&current) || !final_identity {
            return Err(fastmcp_core::McpError::invalid_params(format!(
                "Installation config at {config_path_display} changed or was replaced while the no-op update was being verified; no config write or backup was attempted"
            )));
        }
        drop(secured_parent);
        return write_install_stdout(&format!(
            "'{name}' is already configured in {config_path_display}; no changes or backup were needed"
        ));
    }
    validate_install_registry_counts(config_path, registry_name, registry, &config.0)?;
    let server = shape_install_server_entry(target, serialize_server_config_object(&config.1)?);
    if let Some(existing) = registry.get_mut(&config.0) {
        let existing = existing.as_object_mut().ok_or_else(|| {
            fastmcp_core::McpError::invalid_params(format!(
                "Existing server entry '{}' in {registry_name} at {config_path_display} must be a JSON object; refusing to replace it",
                sanitize_peer_text(&config.0, PEER_FIELD_LIMIT)
            ))
        })?;
        merge_install_server_entry(target, existing, server);
    } else {
        registry.insert(config.0.clone(), serde_json::Value::Object(server));
    }

    // Finish serialization and enforce the output cap before creating a
    // backup/staging inode or mutating the config file.
    let prepared = prepare_json_config(&document)?;
    let current = read_destination_snapshot_at(
        &secured_parent,
        config_name,
        config_path,
        "installation target config",
        CONFIG_INPUT_MAX_BYTES,
    )?;
    if !original.matches(&current) {
        return Err(fastmcp_core::McpError::invalid_params(format!(
            "Installation config at {} changed or was replaced while the update was being prepared; no config write or backup was attempted",
            sanitize_config_path(config_path)
        )));
    }

    if original
        .bytes()
        .is_some_and(|bytes| bytes == prepared.as_slice())
    {
        secured_parent.revalidate(config_path, "installation target config")?;
        let final_identity = descriptor_relative_name_matches_snapshot(
            &secured_parent,
            config_name,
            &original,
        )
        .map_err(|error| {
            fastmcp_core::McpError::internal_error(format!(
                "Failed to complete descriptor-relative unchanged-config verification at {} (I/O kind: {:?})",
                sanitize_config_path(config_path),
                error.kind()
            ))
        })?;
        if !final_identity {
            return Err(fastmcp_core::McpError::invalid_params(format!(
                "Installation config at {config_path_display} changed or was replaced while the unchanged update was being verified; no config write or backup was attempted"
            )));
        }
        drop(secured_parent);
        return write_install_stdout(&format!(
            "'{name}' is already configured in {config_path_display}; no changes or backup were needed"
        ));
    }

    if let Some(existing) = original.existing() {
        validate_snapshot_for_replacement(existing, config_path, "installation config")?;
    }
    let visibility_warning = original.existing().and_then(|existing| {
        linux_xattr_visibility_warning(existing, config_path, "installation config")
    });
    let backup_result =
        create_backup_if_exists(secured_parent, config_name, config_path, &original);
    let (secured_parent, backup_path) = match backup_result {
        Ok(backup) => backup,
        Err(error) => {
            if let Some(warning) = &visibility_warning {
                write_cli_warning(warning);
            }
            return Err(error);
        }
    };
    let update_result = atomic_replace_prepared_file_at(
        secured_parent,
        config_path,
        &prepared,
        "installation config",
        CONFIG_OUTPUT_MAX_BYTES,
        &original,
    )
    .map_err(|error| {
        if let Some(backup_path) = &backup_path {
            fastmcp_core::McpError::internal_error(format!(
                "A backup was already committed at {}, but the installation update at {} did not complete cleanly; inspect the config before retrying because commit state may be uncertain: {}",
                sanitize_config_path(backup_path),
                sanitize_config_path(config_path),
                error.message
            ))
        } else {
            error
        }
    });
    if let Some(warning) = &visibility_warning {
        write_cli_warning(warning);
    }
    update_result?;

    let action = if entry_existed { "Updated" } else { "Added" };
    let success = if let Some(backup_path) = backup_path {
        format!(
            "{action} '{name}' in {config_path_display} (backup: {})",
            sanitize_config_path(&backup_path)
        )
    } else {
        format!("{action} '{name}' in {config_path_display}")
    };
    write_install_stdout(&success).map_err(|error| {
        fastmcp_core::McpError::internal_error(format!(
            "Installation config at {config_path_display} was already committed, but reporting success failed: {} Do not retry blindly.",
            error.message
        ))
    })
}

fn install_claude_desktop(config: &(String, McpServerConfig), dry_run: bool) -> McpResult<()> {
    let config_path = get_claude_desktop_config_path()?;

    if dry_run {
        let snippet = redacted_install_config_snippet("mcpServers", config, InstallTarget::Claude)?;
        return write_install_stdout(&format!(
            "Dry-run: proposed update to {}:\n\n{snippet}",
            sanitize_config_path(&config_path)
        ));
    }
    install_json_registry(&config_path, "mcpServers", config, InstallTarget::Claude)
}

fn get_claude_desktop_config_path() -> McpResult<PathBuf> {
    claude_desktop_config_path().ok_or_else(|| {
        fastmcp_core::McpError::internal_error(
            "Claude Desktop configuration directory is unavailable",
        )
    })
}

fn install_cursor(config: &(String, McpServerConfig), dry_run: bool) -> McpResult<()> {
    // Cursor uses a similar format in .cursor/mcp.json
    let config_path = get_cursor_config_path()?;

    if dry_run {
        let snippet = redacted_install_config_snippet("mcpServers", config, InstallTarget::Cursor)?;
        return write_install_stdout(&format!(
            "Dry-run: proposed update to {}:\n\n{snippet}",
            sanitize_config_path(&config_path)
        ));
    }

    install_json_registry(&config_path, "mcpServers", config, InstallTarget::Cursor)
}

fn get_cursor_config_path() -> McpResult<PathBuf> {
    let home = env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .ok_or_else(|| {
            fastmcp_core::McpError::internal_error(
                "Neither HOME nor USERPROFILE environment variable set",
            )
        })?;
    Ok(PathBuf::from(home).join(".cursor").join("mcp.json"))
}

fn install_cline(config: &(String, McpServerConfig), dry_run: bool) -> McpResult<()> {
    let config_path = get_cline_config_path()?;

    if dry_run {
        let snippet = redacted_install_config_snippet("mcpServers", config, InstallTarget::Cline)?;
        return write_install_stdout(&format!(
            "Dry-run: proposed update to Cline settings at {}:\n\n{snippet}",
            sanitize_config_path(&config_path)
        ));
    }

    install_json_registry(&config_path, "mcpServers", config, InstallTarget::Cline)
}

fn nonempty_environment_value(value: Option<std::ffi::OsString>) -> Option<std::ffi::OsString> {
    let value = value?;
    if value.is_empty() {
        return None;
    }
    if let Some(value) = value.to_str() {
        let value = value.trim();
        return (!value.is_empty()).then(|| std::ffi::OsString::from(value));
    }
    Some(value)
}

#[allow(clippy::too_many_arguments)]
fn resolve_cline_config_path(
    settings_path: Option<std::ffi::OsString>,
    data_dir: Option<std::ffi::OsString>,
    cline_dir: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
    user_profile: Option<std::ffi::OsString>,
    home_drive: Option<std::ffi::OsString>,
    home_path: Option<std::ffi::OsString>,
) -> McpResult<PathBuf> {
    if let Some(path) = nonempty_environment_value(settings_path) {
        return Ok(PathBuf::from(path));
    }
    if let Some(path) = nonempty_environment_value(data_dir) {
        return Ok(PathBuf::from(path)
            .join("settings")
            .join("cline_mcp_settings.json"));
    }
    if let Some(path) = nonempty_environment_value(cline_dir) {
        return Ok(PathBuf::from(path)
            .join("data")
            .join("settings")
            .join("cline_mcp_settings.json"));
    }

    let home = nonempty_environment_value(home)
        .filter(|home| home.as_os_str() != std::ffi::OsStr::new("~"))
        .or_else(|| nonempty_environment_value(user_profile))
        .or_else(|| {
            let mut drive = nonempty_environment_value(home_drive)?;
            drive.push(nonempty_environment_value(home_path)?);
            Some(drive)
        })
        .ok_or_else(|| {
            fastmcp_core::McpError::internal_error(
                "Cline configuration directory is unavailable: HOME and platform home-directory fallbacks are unset",
            )
        })?;
    Ok(PathBuf::from(home)
        .join(".cline")
        .join("data")
        .join("settings")
        .join("cline_mcp_settings.json"))
}

fn get_cline_config_path() -> McpResult<PathBuf> {
    resolve_cline_config_path(
        env::var_os("CLINE_MCP_SETTINGS_PATH"),
        env::var_os("CLINE_DATA_DIR"),
        env::var_os("CLINE_DIR"),
        env::var_os("HOME"),
        env::var_os("USERPROFILE"),
        env::var_os("HOMEDRIVE"),
        env::var_os("HOMEPATH"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn cli_runtime_installs_context_only_during_runtime_entry() {
        assert!(
            Cx::current().is_none(),
            "the process must not have an ambient CLI context before runtime entry"
        );

        let runtime = build_cli_runtime().expect("the CLI runtime and reactor must initialize");
        let runtime_has_context = runtime.block_on(async { Cx::current().is_some() });

        assert!(runtime_has_context);
        assert!(
            Cx::current().is_none(),
            "the runtime-installed CLI context must not leak after runtime exit"
        );
    }

    #[test]
    fn production_cli_has_one_runtime_boundary_and_no_library_runtime_entry() {
        let source = include_str!("main.rs");
        let (production, _) = source
            .split_once("\n#[cfg(test)]\nmod tests {")
            .expect("the CLI unit-test boundary must remain present");

        assert_eq!(production.matches(".block_on(").count(), 1);
        assert!(!production.contains("fastmcp_core::runtime::block_on"));
    }

    fn make_test_server_info() -> fastmcp_protocol::ServerInfo {
        fastmcp_protocol::ServerInfo {
            name: "test-server".to_string(),
            version: "1.0.0".to_string(),
        }
    }

    fn make_test_capabilities(
        tools: bool,
        resources: bool,
        prompts: bool,
    ) -> fastmcp_protocol::ServerCapabilities {
        fastmcp_protocol::ServerCapabilities {
            tools: if tools {
                Some(fastmcp_protocol::ToolsCapability {
                    list_changed: false,
                })
            } else {
                None
            },
            resources: if resources {
                Some(fastmcp_protocol::ResourcesCapability {
                    subscribe: false,
                    list_changed: false,
                })
            } else {
                None
            },
            prompts: if prompts {
                Some(fastmcp_protocol::PromptsCapability {
                    list_changed: false,
                })
            } else {
                None
            },
            logging: None,
            completions: None,
            tasks: None,
        }
    }

    fn make_test_protocol_status() -> InspectProtocolStatus {
        InspectProtocolStatus::new(CliProtocolPolicy::default(), "2026-07-28")
            .expect("the default policy admits the modern exact version")
    }

    // ============================================================================
    // CLI Argument Parsing Tests
    // ============================================================================

    mod cli_parsing {
        use super::*;

        #[test]
        fn test_run_command_basic() {
            let cli = Cli::try_parse_from(["fastmcp", "run", "./my-server"]).unwrap();
            match cli.command {
                Commands::Run {
                    server,
                    args,
                    cwd,
                    env,
                    protocol_policy,
                } => {
                    assert_eq!(server, "./my-server");
                    assert_eq!(args, Vec::<String>::new());
                    assert!(cwd.is_none());
                    assert_eq!(env, Vec::<String>::new());
                    assert_eq!(protocol_policy, CliProtocolPolicy::default());
                }
                _ => unreachable!("Expected Run command"),
            }
        }

        #[test]
        fn test_run_command_with_args() {
            let cli = Cli::try_parse_from([
                "fastmcp",
                "run",
                "./my-server",
                "--",
                "--config",
                "config.json",
            ])
            .unwrap();
            match cli.command {
                Commands::Run { server, args, .. } => {
                    assert_eq!(server, "./my-server");
                    assert_eq!(args, vec!["--config", "config.json"]);
                }
                _ => unreachable!("Expected Run command"),
            }
        }

        #[test]
        fn test_run_command_with_cwd() {
            let cli = Cli::try_parse_from(["fastmcp", "run", "-C", "/tmp/workdir", "./my-server"])
                .unwrap();
            match cli.command {
                Commands::Run { cwd, .. } => {
                    assert_eq!(cwd, Some(PathBuf::from("/tmp/workdir")));
                }
                _ => unreachable!("Expected Run command"),
            }
        }

        #[test]
        fn test_run_command_with_env() {
            let cli = Cli::try_parse_from([
                "fastmcp", "run", "-e", "FOO=bar", "-e", "BAZ=qux", "./server",
            ])
            .unwrap();
            match cli.command {
                Commands::Run { env, .. } => {
                    assert_eq!(env, vec!["FOO=bar", "BAZ=qux"]);
                }
                _ => unreachable!("Expected Run command"),
            }
        }

        #[test]
        fn protocol_policy_defaults_match_the_compiled_profile() {
            let run = Cli::try_parse_from(["fastmcp", "run", "./server"])
                .expect("run policy defaults to auto");
            match run.command {
                Commands::Run {
                    protocol_policy, ..
                } => assert_eq!(protocol_policy, CliProtocolPolicy::default()),
                _ => unreachable!("Expected Run command"),
            }

            let inspect = Cli::try_parse_from(["fastmcp", "inspect", "./server"])
                .expect("inspect policy defaults to auto");
            match inspect.command {
                Commands::Inspect {
                    protocol_policy, ..
                } => assert_eq!(protocol_policy, CliProtocolPolicy::default()),
                _ => unreachable!("Expected Inspect command"),
            }
        }

        #[test]
        fn cli_manifest_forwards_the_server_profiles_now_defined_by_its_dependencies() {
            let manifest = include_str!("../Cargo.toml");
            let value = toml::from_str::<toml::Value>(manifest)
                .expect("the CLI manifest must remain valid TOML");
            let features = value
                .get("features")
                .and_then(toml::Value::as_table)
                .expect("the CLI manifest must declare its feature table");

            for (feature, expected) in [
                (
                    "builtin-auth-server",
                    [
                        "dep:fastmcp-server",
                        "fastmcp-server/builtin-auth-server",
                        "fastmcp-console/builtin-auth-server",
                    ]
                    .as_slice(),
                ),
                (
                    "jwt-resource-auth",
                    [
                        "dep:fastmcp-server",
                        "fastmcp-server/jwt-resource-auth",
                        "fastmcp-console/jwt-resource-auth",
                    ]
                    .as_slice(),
                ),
            ] {
                let actual = features
                    .get(feature)
                    .and_then(toml::Value::as_array)
                    .unwrap_or_else(|| panic!("CLI manifest must define {feature}"))
                    .iter()
                    .map(|value| value.as_str().expect("feature entries must be strings"))
                    .collect::<Vec<_>>();
                assert_eq!(
                    actual, expected,
                    "CLI {feature} equation must match plan section 25.10"
                );
            }
        }

        #[cfg(feature = "legacy-2024-11-05")]
        #[test]
        fn cli_legacy_feature_keeps_auto_as_the_public_default() {
            assert_eq!(CliProtocolPolicy::default(), CliProtocolPolicy::Auto);
            assert!(validate_cli_protocol_policy(CliProtocolPolicy::Auto).is_ok());
            assert!(validate_cli_protocol_policy(CliProtocolPolicy::LegacyOnly).is_ok());
        }

        #[cfg(not(feature = "legacy-2024-11-05"))]
        #[test]
        fn cli_without_legacy_is_modern_only_and_refuses_legacy_before_contact() {
            assert_eq!(CliProtocolPolicy::default(), CliProtocolPolicy::ModernOnly);
            assert_eq!(
                validate_cli_protocol_policy(CliProtocolPolicy::ModernOnly),
                Ok(())
            );

            for policy in [CliProtocolPolicy::Auto, CliProtocolPolicy::LegacyOnly] {
                let error = validate_cli_protocol_policy(policy).expect_err(
                    "a compiled-out policy must fail before any client or child launch",
                );
                assert_eq!(error.code, fastmcp_core::McpErrorCode::InvalidParams);
                assert!(error.message.contains("FeatureUnavailable"));
                assert!(error.message.contains(LEGACY_PROTOCOL_POLICY_FEATURE));
            }

            let parsed = Cli::try_parse_from([
                "fastmcp",
                "run",
                "--protocol-policy",
                "auto",
                "must-not-spawn",
            ])
            .expect("compiled-out policy names remain parseable for diagnostics");
            let policy = parsed
                .command
                .protocol_policy()
                .expect("run owns a protocol-policy selection");
            assert_eq!(policy, CliProtocolPolicy::Auto);
            assert!(validate_cli_protocol_policy(policy).is_err());

            let error = http_inspect_protocol_plan(
                Some("http://127.0.0.1:8123/mcp"),
                None,
                None,
                CliProtocolPolicy::Auto,
            )
            .expect_err("Auto must fail before the HTTP client can contact the endpoint");
            assert!(error.message.contains("FeatureUnavailable"));
        }

        #[cfg(feature = "legacy-2024-11-05")]
        #[test]
        fn protocol_policy_choices_route_to_shipped_builders() {
            for (argument, expected) in [
                ("auto", ProtocolPolicy::Auto),
                ("modern-only", ProtocolPolicy::ModernOnly),
                ("legacy-only", ProtocolPolicy::LegacyOnly),
            ] {
                let cli = Cli::try_parse_from([
                    "fastmcp",
                    "inspect",
                    "--protocol-policy",
                    argument,
                    "./server",
                ])
                .expect("exact protocol-policy choice parses");
                let Commands::Inspect {
                    protocol_policy, ..
                } = cli.command
                else {
                    unreachable!("Expected Inspect command");
                };
                assert_eq!(protocol_policy.protocol_policy(), expected);
                assert_eq!(
                    client_builder_for_protocol_policy(protocol_policy)
                        .expect("default CLI profile admits every configured policy")
                        .selected_protocol_plan()
                        .policy(),
                    expected
                );

                let mut command = Command::new("server");
                apply_protocol_policy_to_server_launch(&mut command, protocol_policy);
                let launch_policy = command
                    .get_envs()
                    .find(|(key, _)| *key == OsStr::new(FASTMCP_PROTOCOL_POLICY_ENV))
                    .and_then(|(_, value)| value.and_then(OsStr::to_str).map(str::to_owned));
                assert_eq!(launch_policy.as_deref(), Some(argument));
            }
        }

        #[cfg(feature = "legacy-2024-11-05")]
        #[test]
        fn inspect_protocol_status_renders_each_supported_selection_exactly() {
            let server_info = make_test_server_info();
            let capabilities = make_test_capabilities(false, false, false);

            for (policy, version, era) in [
                (CliProtocolPolicy::Auto, "2026-07-28", "modern-2026"),
                (CliProtocolPolicy::Auto, "2024-11-05", "legacy-2024"),
                (CliProtocolPolicy::ModernOnly, "2026-07-28", "modern-2026"),
                (CliProtocolPolicy::LegacyOnly, "2024-11-05", "legacy-2024"),
            ] {
                let status = InspectProtocolStatus::new(policy, version)
                    .expect("each policy must report its exact admitted protocol version");
                let text =
                    format_inspect_text(&server_info, &capabilities, &[], &[], &[], &[], status);
                assert!(text.contains(&format!(
                    "Protocol: policy={} version={version} era={era}",
                    policy.server_launch_value()
                )));

                let json =
                    format_inspect_json(&server_info, &capabilities, &[], &[], &[], &[], status)
                        .expect("inspect status serializes");
                let value: serde_json::Value =
                    serde_json::from_str(&json).expect("inspect status is JSON");
                assert_eq!(value["protocol"]["policy"], policy.server_launch_value());
                assert_eq!(value["protocol"]["version"], version);
                assert_eq!(value["protocol"]["era"], era);
            }
        }

        #[cfg(feature = "legacy-2024-11-05")]
        #[test]
        fn inspect_protocol_status_rejects_only_cross_policy_or_unsupported_versions() {
            for (policy, accepted_version, rejected_version) in [
                (CliProtocolPolicy::Auto, "2026-07-28", "2025-11-25"),
                (CliProtocolPolicy::ModernOnly, "2026-07-28", "2024-11-05"),
                (CliProtocolPolicy::LegacyOnly, "2024-11-05", "2026-07-28"),
            ] {
                let accepted = InspectProtocolStatus::new(policy, accepted_version)
                    .expect("the baseline policy/version pair is admitted");
                let accepted_before = accepted;

                let error = InspectProtocolStatus::new(policy, rejected_version)
                    .expect_err("changing only the negotiated protocol version must be rejected");

                assert_eq!(error.code, fastmcp_core::McpErrorCode::InternalError);
                assert_eq!(accepted, accepted_before);
            }
        }

        #[test]
        fn protocol_policy_launch_setting_overrides_conflicting_child_environment() {
            let mut command = Command::new("server");
            command.env(FASTMCP_PROTOCOL_POLICY_ENV, "legacy-only");
            apply_protocol_policy_to_server_launch(&mut command, CliProtocolPolicy::ModernOnly);

            let launch_policy = command
                .get_envs()
                .find(|(key, _)| *key == OsStr::new(FASTMCP_PROTOCOL_POLICY_ENV))
                .and_then(|(_, value)| value.and_then(OsStr::to_str).map(str::to_owned));

            assert_eq!(launch_policy.as_deref(), Some("modern-only"));
        }

        #[test]
        fn reserved_protocol_policy_environment_is_refused_before_server_spawn() {
            let env_vars = parse_environment_assignments(&[
                "FASTMCP_PROTOCOL_POLICY=mcp-2025-11-25".to_owned(),
            ])
            .expect("the generic parser preserves the assignment for command-specific validation");

            let error = reject_reserved_protocol_policy_environment(&env_vars)
                .expect_err("the reserved launch setting must be rejected before spawning");

            assert_eq!(error.code, fastmcp_core::McpErrorCode::InvalidParams);
            assert_eq!(
                error.message,
                "FASTMCP_PROTOCOL_POLICY is controlled by --protocol-policy; remove it from --env"
            );
        }

        #[test]
        fn protocol_policy_rejects_invalid_choice() {
            let result = Cli::try_parse_from([
                "fastmcp",
                "run",
                "--protocol-policy",
                "mcp-2025-11-25",
                "./server",
            ]);
            assert!(result.is_err());
        }

        #[test]
        fn test_inspect_command_basic() {
            let cli = Cli::try_parse_from(["fastmcp", "inspect", "./server"]).unwrap();
            match cli.command {
                Commands::Inspect {
                    server,
                    format,
                    output,
                    ..
                } => {
                    assert_eq!(server.as_deref(), Some("./server"));
                    assert_eq!(format, InspectFormat::Text);
                    assert!(output.is_none());
                }
                _ => unreachable!("Expected Inspect command"),
            }
        }

        #[test]
        fn test_inspect_command_json_format() {
            let cli =
                Cli::try_parse_from(["fastmcp", "inspect", "-f", "json", "./server"]).unwrap();
            match cli.command {
                Commands::Inspect { format, .. } => {
                    assert_eq!(format, InspectFormat::Json);
                }
                _ => unreachable!("Expected Inspect command"),
            }
        }

        #[test]
        fn test_inspect_command_http_url_target() {
            let cli = Cli::try_parse_from([
                "fastmcp",
                "inspect",
                "--http-url",
                "http://127.0.0.1:8123/mcp",
                "--protocol-policy",
                "modern-only",
            ])
            .expect("HTTP inspect target parses without a stdio command");
            match cli.command {
                Commands::Inspect {
                    server,
                    http_url,
                    args,
                    protocol_policy,
                    ..
                } => {
                    assert!(server.is_none());
                    assert_eq!(http_url.as_deref(), Some("http://127.0.0.1:8123/mcp"));
                    assert_eq!(args, Vec::<String>::new());
                    assert_eq!(protocol_policy, CliProtocolPolicy::ModernOnly);
                }
                _ => unreachable!("Expected Inspect command"),
            }
        }

        #[cfg(feature = "legacy-2024-11-05")]
        #[test]
        fn http_inspect_accepts_an_explicit_auto_endpoint_bundle() {
            let plan = http_inspect_protocol_plan(
                Some("http://127.0.0.1:8123/mcp"),
                Some("http://127.0.0.1:8123/sse"),
                Some("http://127.0.0.1:8123/messages"),
                CliProtocolPolicy::Auto,
            )
            .expect("an explicit Auto bundle must construct");
            assert_eq!(plan.modern_post_target(), Some("http://127.0.0.1:8123/mcp"));
            assert_eq!(plan.legacy_sse_target(), Some("http://127.0.0.1:8123/sse"));
            assert_eq!(
                plan.legacy_message_post_target(),
                Some("http://127.0.0.1:8123/messages")
            );
        }

        #[cfg(feature = "legacy-2024-11-05")]
        #[test]
        fn http_inspect_rejects_an_incomplete_auto_endpoint_bundle() {
            let error = http_inspect_protocol_plan(
                Some("http://127.0.0.1:8123/mcp"),
                Some("http://127.0.0.1:8123/sse"),
                None,
                CliProtocolPolicy::Auto,
            )
            .expect_err("Auto must not infer a missing legacy message route");
            assert_eq!(error.code, fastmcp_core::McpErrorCode::InvalidParams);
            assert!(
                error
                    .message
                    .contains("requires a configured legacy message POST target"),
                "the rejection must name the missing explicit endpoint"
            );
        }

        #[test]
        fn test_inspect_command_rejects_schema_misleading_mcp_alias() {
            let result = Cli::try_parse_from(["fastmcp", "inspect", "--format", "mcp", "./server"]);
            assert!(result.is_err());
        }

        #[test]
        fn test_inspect_command_with_output() {
            let cli = Cli::try_parse_from(["fastmcp", "inspect", "-o", "output.json", "./server"])
                .unwrap();
            match cli.command {
                Commands::Inspect { output, .. } => {
                    assert_eq!(output, Some(PathBuf::from("output.json")));
                }
                _ => unreachable!("Expected Inspect command"),
            }
        }

        #[test]
        fn test_install_command_basic() {
            let cli = Cli::try_parse_from(["fastmcp", "install", "my-server", "./server"]).unwrap();
            match cli.command {
                Commands::Install {
                    name,
                    server,
                    target,
                    dry_run,
                    protocol_policy,
                    ..
                } => {
                    assert_eq!(name, "my-server");
                    assert_eq!(server, "./server");
                    assert_eq!(target, InstallTarget::Claude);
                    assert!(!dry_run);
                    assert_eq!(protocol_policy, CliProtocolPolicy::default());
                }
                _ => unreachable!("Expected Install command"),
            }
        }

        #[test]
        fn test_install_command_with_protocol_policy() {
            let cli = Cli::try_parse_from([
                "fastmcp",
                "install",
                "--protocol-policy",
                "legacy-only",
                "my-server",
                "./server",
            ])
            .expect("install accepts an explicit protocol-policy selection");
            match cli.command {
                Commands::Install {
                    protocol_policy, ..
                } => assert_eq!(protocol_policy, CliProtocolPolicy::LegacyOnly),
                _ => unreachable!("Expected Install command"),
            }
        }

        #[test]
        fn test_install_command_with_target() {
            let cli = Cli::try_parse_from([
                "fastmcp",
                "install",
                "-t",
                "cursor",
                "my-server",
                "./server",
            ])
            .unwrap();
            match cli.command {
                Commands::Install { target, .. } => {
                    assert_eq!(target, InstallTarget::Cursor);
                }
                _ => unreachable!("Expected Install command"),
            }
        }

        #[test]
        fn test_install_command_dry_run() {
            let cli =
                Cli::try_parse_from(["fastmcp", "install", "--dry-run", "my-server", "./server"])
                    .unwrap();
            match cli.command {
                Commands::Install { dry_run, .. } => {
                    assert!(dry_run);
                }
                _ => unreachable!("Expected Install command"),
            }
        }

        #[test]
        fn test_install_command_with_working_directory() {
            let cli = Cli::try_parse_from([
                "fastmcp",
                "install",
                "-C",
                "/srv/my-server",
                "my-server",
                "./server",
            ])
            .unwrap();
            match cli.command {
                Commands::Install { cwd, .. } => {
                    assert_eq!(cwd, Some(PathBuf::from("/srv/my-server")));
                }
                _ => unreachable!("Expected Install command"),
            }
        }

        #[test]
        fn test_list_command_default() {
            let cli = Cli::try_parse_from(["fastmcp", "list"]).unwrap();
            match cli.command {
                Commands::List {
                    target,
                    config,
                    format,
                    verbose,
                } => {
                    assert!(target.is_none());
                    assert!(config.is_none());
                    assert_eq!(format, ListFormat::Table);
                    assert!(!verbose);
                }
                _ => unreachable!("Expected List command"),
            }
        }

        #[test]
        fn test_list_command_with_options() {
            let cli = Cli::try_parse_from(["fastmcp", "list", "-t", "cline", "-f", "json", "-v"])
                .unwrap();
            match cli.command {
                Commands::List {
                    target,
                    format,
                    verbose,
                    ..
                } => {
                    assert_eq!(target, Some(InstallTarget::Cline));
                    assert_eq!(format, ListFormat::Json);
                    assert!(verbose);
                }
                _ => unreachable!("Expected List command"),
            }
        }

        #[test]
        fn test_list_command_yaml_format() {
            let cli = Cli::try_parse_from(["fastmcp", "list", "--format", "yaml"]).unwrap();
            match cli.command {
                Commands::List { format, .. } => {
                    assert_eq!(format, ListFormat::Yaml);
                }
                _ => unreachable!("Expected List command"),
            }
        }

        #[test]
        fn test_test_command_default() {
            let cli = Cli::try_parse_from(["fastmcp", "test", "./server"]).unwrap();
            match cli.command {
                Commands::Test {
                    server,
                    protocol_policy,
                    idle_timeout,
                    absolute_timeout,
                    verbose,
                    json,
                    ..
                } => {
                    assert_eq!(server, "./server");
                    assert_eq!(protocol_policy, CliProtocolPolicy::default());
                    assert_eq!(idle_timeout, 30);
                    assert_eq!(absolute_timeout, 120);
                    assert!(!verbose);
                    assert!(!json);
                }
                _ => unreachable!("Expected Test command"),
            }
        }

        #[test]
        fn test_test_command_with_options() {
            let cli = Cli::try_parse_from([
                "fastmcp",
                "test",
                "--protocol-policy",
                "legacy-only",
                "--idle-timeout",
                "45",
                "--absolute-timeout",
                "180",
                "-v",
                "--json",
                "./server",
            ])
            .unwrap();
            match cli.command {
                Commands::Test {
                    protocol_policy,
                    idle_timeout,
                    absolute_timeout,
                    verbose,
                    json,
                    ..
                } => {
                    assert_eq!(protocol_policy, CliProtocolPolicy::LegacyOnly);
                    assert_eq!(idle_timeout, 45);
                    assert_eq!(absolute_timeout, 180);
                    assert!(verbose);
                    assert!(json);
                }
                _ => unreachable!("Expected Test command"),
            }
        }

        #[test]
        fn test_dev_command_default() {
            let cli = Cli::try_parse_from(["fastmcp", "dev", "."]).unwrap();
            match cli.command {
                Commands::Dev {
                    target,
                    no_reload,
                    debounce,
                    clear,
                    protocol_policy,
                    verbose,
                    ..
                } => {
                    assert_eq!(target, ".");
                    assert!(!no_reload);
                    assert_eq!(debounce, 100);
                    assert!(!clear);
                    assert_eq!(protocol_policy, CliProtocolPolicy::default());
                    assert!(!verbose);
                }
                _ => unreachable!("Expected Dev command"),
            }
        }

        #[test]
        fn test_dev_command_with_options() {
            let cli = Cli::try_parse_from([
                "fastmcp",
                "dev",
                "--no-reload",
                "--debounce",
                "250",
                "--clear",
                "-v",
                "--protocol-policy",
                "modern-only",
                ".",
            ])
            .unwrap();
            match cli.command {
                Commands::Dev {
                    no_reload,
                    debounce,
                    clear,
                    protocol_policy,
                    verbose,
                    ..
                } => {
                    assert!(no_reload);
                    assert_eq!(debounce, 250);
                    assert!(clear);
                    assert_eq!(protocol_policy, CliProtocolPolicy::ModernOnly);
                    assert!(verbose);
                }
                _ => unreachable!("Expected Dev command"),
            }
        }

        #[test]
        fn dev_launch_environment_selects_policy_and_refuses_reserved_override() {
            let selected = dev_launch_environment(
                HashMap::from([("OTHER".to_owned(), "value".to_owned())]),
                CliProtocolPolicy::ModernOnly,
            )
            .expect("an unrelated child environment entry is admitted");
            assert_eq!(
                selected
                    .get(FASTMCP_PROTOCOL_POLICY_ENV)
                    .map(String::as_str),
                Some("modern-only")
            );

            let error = dev_launch_environment(
                HashMap::from([(
                    FASTMCP_PROTOCOL_POLICY_ENV.to_owned(),
                    "mcp-2025-11-25".to_owned(),
                )]),
                CliProtocolPolicy::ModernOnly,
            )
            .expect_err("the reserved child setting must be refused before any dev child starts");
            assert_eq!(error.code, fastmcp_core::McpErrorCode::InvalidParams);
        }
    }

    // ============================================================================
    // Enum Parsing Tests
    // ============================================================================

    mod enum_parsing {
        use super::*;

        #[test]
        fn test_inspect_format_from_str() {
            assert_eq!(
                "text".parse::<InspectFormat>().unwrap(),
                InspectFormat::Text
            );
            assert_eq!(
                "TEXT".parse::<InspectFormat>().unwrap(),
                InspectFormat::Text
            );
            assert_eq!(
                "json".parse::<InspectFormat>().unwrap(),
                InspectFormat::Json
            );
            assert!("mcp".parse::<InspectFormat>().is_err());
        }

        #[test]
        fn test_inspect_format_invalid() {
            let result = "xml".parse::<InspectFormat>();
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("Unknown format"));
        }

        #[test]
        fn test_list_format_from_str() {
            assert_eq!("table".parse::<ListFormat>().unwrap(), ListFormat::Table);
            assert_eq!("TABLE".parse::<ListFormat>().unwrap(), ListFormat::Table);
            assert_eq!("json".parse::<ListFormat>().unwrap(), ListFormat::Json);
            assert_eq!("yaml".parse::<ListFormat>().unwrap(), ListFormat::Yaml);
        }

        #[test]
        fn test_list_format_invalid() {
            let result = "csv".parse::<ListFormat>();
            assert!(result.is_err());
        }

        #[test]
        fn test_list_format_default() {
            assert_eq!(ListFormat::default(), ListFormat::Table);
        }

        #[test]
        fn test_install_target_from_str() {
            assert_eq!(
                "claude".parse::<InstallTarget>().unwrap(),
                InstallTarget::Claude
            );
            assert_eq!(
                "CLAUDE".parse::<InstallTarget>().unwrap(),
                InstallTarget::Claude
            );
            assert_eq!(
                "cursor".parse::<InstallTarget>().unwrap(),
                InstallTarget::Cursor
            );
            assert_eq!(
                "cline".parse::<InstallTarget>().unwrap(),
                InstallTarget::Cline
            );
        }

        #[test]
        fn test_install_target_invalid() {
            let result = "vscode".parse::<InstallTarget>();
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("Unknown target"));
        }
    }

    // ============================================================================
    // Helper Function Tests
    // ============================================================================

    mod helper_functions {
        use super::*;

        #[test]
        fn test_generate_server_config() {
            let (name, config) = generate_server_config(
                "my-server",
                "/path/to/server",
                &["--config".to_string(), "config.json".to_string()],
                Some(Path::new("/srv/my-server")),
                CliProtocolPolicy::ModernOnly,
            )
            .expect("bounded config");

            assert_eq!(name, "my-server");
            assert_eq!(config.command, "/path/to/server");
            assert_eq!(config.args, vec!["--config", "config.json"]);
            assert_eq!(
                config
                    .env
                    .as_ref()
                    .and_then(|environment| environment.get(FASTMCP_PROTOCOL_POLICY_ENV))
                    .map(String::as_str),
                Some("modern-only")
            );
            assert_eq!(config.cwd.as_deref(), Some("/srv/my-server"));
        }

        #[test]
        fn generate_server_config_rejects_excessive_argument_counts() {
            let arguments = vec!["value".to_owned(); CLI_OUTPUT_MAX_ITEMS + 1];
            let error = generate_server_config(
                "server",
                "command",
                &arguments,
                None,
                CliProtocolPolicy::default(),
            )
            .err()
            .expect("oversized argument list must be rejected");

            assert!(error.message.contains("maximum accepted count"));
        }

        #[test]
        fn generate_server_config_rejects_blank_names_and_commands() {
            let blank_name =
                generate_server_config("  ", "server", &[], None, CliProtocolPolicy::default())
                    .err()
                    .expect("blank server name must be rejected");
            assert!(blank_name.message.contains("name"));

            let blank_command =
                generate_server_config("server", "\t", &[], None, CliProtocolPolicy::default())
                    .err()
                    .expect("blank server command must be rejected");
            assert!(blank_command.message.contains("command"));
        }

        #[cfg(feature = "legacy-2024-11-05")]
        #[test]
        fn install_policy_serializes_in_flat_client_configs() {
            for (policy, expected) in [
                (CliProtocolPolicy::Auto, "auto"),
                (CliProtocolPolicy::ModernOnly, "modern-only"),
                (CliProtocolPolicy::LegacyOnly, "legacy-only"),
            ] {
                let (_, config) = generate_server_config("server", "command", &[], None, policy)
                    .expect("install config accepts every explicit policy");

                for target in [InstallTarget::Claude, InstallTarget::Cursor] {
                    let entry = shape_install_server_entry(
                        target,
                        serialize_server_config_object(&config)
                            .expect("install config serializes to a JSON object"),
                    );
                    assert_eq!(entry["type"], "stdio");
                    assert_eq!(entry["env"][FASTMCP_PROTOCOL_POLICY_ENV], expected);
                }
            }
        }

        #[cfg(feature = "legacy-2024-11-05")]
        #[test]
        fn install_policy_serializes_in_cline_transport_config() {
            for (policy, expected) in [
                (CliProtocolPolicy::Auto, "auto"),
                (CliProtocolPolicy::ModernOnly, "modern-only"),
                (CliProtocolPolicy::LegacyOnly, "legacy-only"),
            ] {
                let (_, config) = generate_server_config("server", "command", &[], None, policy)
                    .expect("install config accepts every explicit policy");
                let entry = shape_install_server_entry(
                    InstallTarget::Cline,
                    serialize_server_config_object(&config)
                        .expect("install config serializes to a JSON object"),
                );

                assert_eq!(entry["transport"]["type"], "stdio");
                assert_eq!(
                    entry["transport"]["env"][FASTMCP_PROTOCOL_POLICY_ENV],
                    expected
                );
            }
        }

        #[test]
        fn install_merge_preserves_environment_in_flat_client_configs() {
            let (_, config) = generate_server_config(
                "server",
                "command",
                &[],
                None,
                CliProtocolPolicy::ModernOnly,
            )
            .expect("install config accepts the selected policy");

            for target in [InstallTarget::Claude, InstallTarget::Cursor] {
                let mut existing = serde_json::json!({
                    "type": "stdio",
                    "command": "previous-command",
                    "env": {
                        "EXISTING_SETTING": "preserve-exactly",
                        "FASTMCP_PROTOCOL_POLICY": "legacy-only",
                    },
                })
                .as_object()
                .expect("flat client fixture object")
                .clone();
                let desired = shape_install_server_entry(
                    target,
                    serialize_server_config_object(&config)
                        .expect("install config serializes to a JSON object"),
                );

                merge_install_server_entry(target, &mut existing, desired);

                assert_eq!(existing["type"], "stdio");
                assert_eq!(existing["env"]["EXISTING_SETTING"], "preserve-exactly");
                assert_eq!(existing["env"][FASTMCP_PROTOCOL_POLICY_ENV], "modern-only");
            }
        }

        #[cfg(feature = "legacy-2024-11-05")]
        #[test]
        fn install_merge_preserves_environment_in_cline_transport_shapes() {
            let (_, config) = generate_server_config(
                "server",
                "command",
                &[],
                None,
                CliProtocolPolicy::LegacyOnly,
            )
            .expect("install config accepts the selected policy");
            let desired = || {
                shape_install_server_entry(
                    InstallTarget::Cline,
                    serialize_server_config_object(&config)
                        .expect("install config serializes to a JSON object"),
                )
            };

            for mut existing in [
                serde_json::json!({
                    "transport": {
                        "type": "stdio",
                        "command": "previous-command",
                        "env": {
                            "EXISTING_SETTING": "preserve-exactly",
                            "FASTMCP_PROTOCOL_POLICY": "auto",
                        },
                    },
                    "metadata": ["preserve"],
                }),
                serde_json::json!({
                    "type": "stdio",
                    "command": "previous-command",
                    "env": {
                        "EXISTING_SETTING": "preserve-exactly",
                        "FASTMCP_PROTOCOL_POLICY": "modern-only",
                    },
                }),
            ] {
                let existing = existing.as_object_mut().expect("Cline fixture object");

                merge_install_server_entry(InstallTarget::Cline, existing, desired());

                assert_eq!(existing["transport"]["type"], "stdio");
                assert_eq!(
                    existing["transport"]["env"]["EXISTING_SETTING"],
                    "preserve-exactly"
                );
                assert_eq!(
                    existing["transport"]["env"][FASTMCP_PROTOCOL_POLICY_ENV],
                    "legacy-only"
                );
            }
        }

        #[test]
        fn install_semantic_noop_preserves_environment_but_requires_exact_policy() {
            let (_, desired) = generate_server_config(
                "server",
                "command",
                &[],
                None,
                CliProtocolPolicy::ModernOnly,
            )
            .expect("install config accepts the selected policy");
            let existing_with_selected_policy = McpServerConfig {
                command: "command".to_owned(),
                args: Vec::new(),
                env: Some(HashMap::from([
                    ("EXISTING_SETTING".to_owned(), "preserve-exactly".to_owned()),
                    (
                        FASTMCP_PROTOCOL_POLICY_ENV.to_owned(),
                        "modern-only".to_owned(),
                    ),
                ])),
                cwd: None,
                disabled: false,
            };
            let semantic_desired =
                install_config_with_preserved_environment(&existing_with_selected_policy, &desired);
            assert!(server_configs_semantically_equal(
                &existing_with_selected_policy,
                &semantic_desired
            ));

            let existing_with_stale_policy = McpServerConfig {
                env: Some(HashMap::from([
                    ("EXISTING_SETTING".to_owned(), "preserve-exactly".to_owned()),
                    (
                        FASTMCP_PROTOCOL_POLICY_ENV.to_owned(),
                        "legacy-only".to_owned(),
                    ),
                ])),
                ..existing_with_selected_policy
            };
            let semantic_desired =
                install_config_with_preserved_environment(&existing_with_stale_policy, &desired);
            assert_eq!(
                semantic_desired
                    .env
                    .as_ref()
                    .and_then(|environment| environment.get(FASTMCP_PROTOCOL_POLICY_ENV))
                    .map(String::as_str),
                Some("modern-only")
            );
            assert!(!server_configs_semantically_equal(
                &existing_with_stale_policy,
                &semantic_desired
            ));
        }

        #[test]
        fn config_registry_and_nested_counts_are_rejected_explicitly() {
            let registry = (0..=CLI_OUTPUT_MAX_ITEMS)
                .map(|index| {
                    (
                        format!("server-{index}"),
                        serde_json::json!({"command": "server"}),
                    )
                })
                .collect::<serde_json::Map<_, _>>();
            let registry_error =
                parse_json_server_entries(Path::new("config.json"), "test", &registry, None)
                    .expect_err("oversized registry must be rejected");
            assert!(registry_error.message.contains("registry contains"));

            let nested_arguments = serde_json::Map::from_iter([(
                "server".to_owned(),
                serde_json::json!({
                    "transport": {
                        "type": "stdio",
                        "command": "server",
                        "args": vec!["value"; CLI_OUTPUT_MAX_ITEMS + 1],
                    },
                }),
            )]);
            let arguments_error = validate_install_registry_counts(
                Path::new("config.json"),
                "mcpServers",
                &nested_arguments,
                "replacement",
            )
            .expect_err("oversized nested arguments must be rejected");
            assert!(arguments_error.message.contains("argument list exceeds"));

            let nested_environment = serde_json::Map::from_iter([(
                "server".to_owned(),
                serde_json::json!({
                    "transport": {
                        "type": "stdio",
                        "command": "server",
                        "env": (0..=CLI_OUTPUT_MAX_ITEMS)
                            .map(|index| (format!("KEY_{index}"), "value".to_owned()))
                            .collect::<HashMap<_, _>>(),
                    },
                }),
            )]);
            let environment_error = validate_install_registry_counts(
                Path::new("config.json"),
                "mcpServers",
                &nested_environment,
                "replacement",
            )
            .expect_err("oversized nested environment must be rejected");
            assert!(environment_error.message.contains("environment exceeds"));
        }

        #[test]
        fn install_profile_projection_rejects_conflicting_or_malformed_transport_state() {
            let invalid_cursor_type = serde_json::json!({
                "type": 7,
                "command": "server",
            });
            assert!(
                effective_installed_server_config(InstallTarget::Cursor, &invalid_cursor_type)
                    .is_none()
            );

            let blank_env_file = serde_json::json!({
                "type": "stdio",
                "command": "server",
                "envFile": "  ",
            });
            assert!(!has_valid_install_profile_fields(
                InstallTarget::Cursor,
                blank_env_file.as_object().expect("Cursor fixture object")
            ));

            let cline = serde_json::json!({
                "transport": {"type": "stdio", "command": "server", "args": []},
                "metadata": ["preserve", null],
            });
            assert!(has_valid_install_profile_fields(
                InstallTarget::Cline,
                cline.as_object().expect("Cline fixture object")
            ));
            assert_eq!(
                effective_installed_server_config(InstallTarget::Cline, &cline)
                    .expect("valid Cline transport")
                    .command,
                "server"
            );

            for transport_owned_state in [
                serde_json::json!({
                    "transport": {"type": "stdio", "command": "server"},
                    "remoteConfigured": false,
                }),
                serde_json::json!({
                    "transport": {"type": "stdio", "command": "server"},
                    "oauth": null,
                }),
            ] {
                assert!(has_valid_install_profile_fields(
                    InstallTarget::Cline,
                    transport_owned_state
                        .as_object()
                        .expect("Cline transport-owned fixture object")
                ));
                assert!(
                    effective_installed_server_config(InstallTarget::Cline, &transport_owned_state)
                        .is_none(),
                    "transport-owned state must force a cleanup rewrite"
                );
            }

            let unsupported = serde_json::json!({
                "command": "server",
                "clientExtension": {"keep": true},
            });
            for target in [
                InstallTarget::Claude,
                InstallTarget::Cursor,
                InstallTarget::Cline,
            ] {
                assert!(!has_valid_install_profile_fields(
                    target,
                    unsupported
                        .as_object()
                        .expect("unsupported extension fixture object")
                ));
            }

            for conflicting in [
                serde_json::json!({
                    "transport": {"type": "stdio", "command": "server"},
                    "command": "duplicate",
                }),
                serde_json::json!({
                    "transport": {"type": "stdio", "command": "server", "argz": []},
                }),
            ] {
                assert!(
                    effective_installed_server_config(InstallTarget::Cline, &conflicting).is_none()
                );
            }
        }

        #[test]
        fn list_entry_parsers_reject_unknown_fields_without_echoing_values() {
            const SECRET: &str = "UNKNOWN_ENTRY_FIELD_SECRET";
            const NAME_SECRET: &str = "UNKNOWN_ENTRY_NAME_SECRET";
            const SOURCE_SECRET: &str = "UNKNOWN_ENTRY_SOURCE_SECRET";
            let path = Path::new("config.json");
            let json = serde_json::json!({
                "command": "server",
                "credential_typo": [SECRET],
            });
            let json_error = parse_json_server_entry(
                path,
                &format!("token={SOURCE_SECRET}"),
                &format!("api_key={NAME_SECRET}"),
                &json,
                None,
            )
            .expect_err("unknown JSON entry fields must be rejected");
            assert!(json_error.message.contains("schema validation failed"));
            assert!(!json_error.message.contains(SECRET));
            assert!(!json_error.message.contains(NAME_SECRET));
            assert!(!json_error.message.contains(SOURCE_SECRET));
            for target in [
                InstallTarget::Claude,
                InstallTarget::Cursor,
                InstallTarget::Cline,
            ] {
                let client_error =
                    parse_json_server_entry(path, "client", "server", &json, Some(target))
                        .expect_err("client registries must reject unknown field names");
                assert!(client_error.message.contains("schema validation failed"));
                assert!(!client_error.message.contains(SECRET));
            }

            let toml_source = format!("command = \"server\"\ncredential_typo = [\"{SECRET}\"]\n");
            let toml = toml::from_str::<toml::Value>(&toml_source).expect("valid TOML fixture");
            let toml_error = parse_toml_server_entry(path, "test", "server", &toml)
                .expect_err("unknown TOML entry fields must be rejected");
            assert!(toml_error.message.contains("schema validation failed"));
            assert!(!toml_error.message.contains(SECRET));
        }

        #[test]
        fn list_entry_parsers_accept_only_typed_target_extensions() {
            let path = Path::new("config.json");
            let cases = [
                (
                    InstallTarget::Claude,
                    serde_json::json!({"command": "server"}),
                ),
                (
                    InstallTarget::Claude,
                    serde_json::json!({
                        "command": "server",
                        "type": "stdio",
                    }),
                ),
                (
                    InstallTarget::Cursor,
                    serde_json::json!({
                        "command": "server",
                        "type": "stdio",
                        "envFile": ".env.local",
                    }),
                ),
                (
                    InstallTarget::Cline,
                    serde_json::json!({
                        "command": "server",
                        "type": "stdio",
                        "transportType": "stdio",
                        "autoApprove": ["echo"],
                        "timeout": 1.5,
                        "remoteConfigured": false,
                        "metadata": {"owner": "test"},
                    }),
                ),
            ];

            for (target, value) in cases {
                let parsed =
                    parse_json_server_entry(path, "client", "server", &value, Some(target))
                        .expect("recognized typed client metadata must be accepted");
                assert_eq!(parsed.command, "server");
            }

            for (target, value) in [
                (
                    InstallTarget::Claude,
                    serde_json::json!({"command": "server", "type": "http"}),
                ),
                (
                    InstallTarget::Claude,
                    serde_json::json!({"command": "server", "url": "https://example.invalid/mcp"}),
                ),
                (
                    InstallTarget::Claude,
                    serde_json::json!({"command": "server", "tyep": "stdio"}),
                ),
                (
                    InstallTarget::Cursor,
                    serde_json::json!({"command": "server", "envFile": "  "}),
                ),
                (
                    InstallTarget::Cursor,
                    serde_json::json!({"command": "server", "headers": {"X-Test": "value"}}),
                ),
                (
                    InstallTarget::Cline,
                    serde_json::json!({"command": "server", "autoApprove": [7]}),
                ),
                (
                    InstallTarget::Cline,
                    serde_json::json!({"command": "server", "timeout": "sixty"}),
                ),
                (
                    InstallTarget::Cline,
                    serde_json::json!({"command": "server", "type": "sse"}),
                ),
                (
                    InstallTarget::Claude,
                    serde_json::json!({"command": "server", "envFile": ".env"}),
                ),
            ] {
                let error = parse_json_server_entry(path, "client", "server", &value, Some(target))
                    .expect_err("unsupported or malformed target fields must be rejected");
                assert!(
                    error.message.contains("schema validation failed")
                        || error.message.contains("not yet representable")
                );
            }
        }

        #[test]
        fn cline_nested_stdio_entries_are_projected_and_strictly_validated() {
            const SECRET: &str = "NESTED_CLINE_SECRET_MUST_NOT_LEAK";
            let path = Path::new("config.json");
            let entry = serde_json::json!({
                "transport": {
                    "type": "stdio",
                    "command": "server",
                    "args": ["--mode", "test"],
                    "cwd": "/srv/server",
                    "env": {"MODE": "test"},
                },
                "disabled": true,
                "autoApprove": ["echo"],
                "timeout": 60,
                "remoteConfigured": false,
                "oauth": ["preserved", null],
                "metadata": null,
            });
            let parsed = parse_json_server_entry(
                path,
                "Cline",
                "server",
                &entry,
                Some(InstallTarget::Cline),
            )
            .expect("valid current Cline stdio entry");
            assert_eq!(parsed.command, "server");
            assert_eq!(parsed.args, ["--mode", "test"]);
            assert_eq!(parsed.cwd.as_deref(), Some("/srv/server"));
            assert_eq!(
                parsed.env.as_ref().and_then(|env| env.get("MODE")),
                Some(&"test".to_owned())
            );
            assert!(!parsed.enabled);

            for malformed in [
                serde_json::json!({
                    "transport": {"type": "stdio", "command": "server"},
                    "command": "duplicate",
                }),
                serde_json::json!({
                    "transport": {"type": "stdio", "command": "server"},
                    "timeot": 60,
                }),
                serde_json::json!({
                    "transport": {"type": "stdio", "commnad": SECRET},
                }),
                serde_json::json!({
                    "transport": {"type": "stdio", "command": ""},
                }),
                serde_json::json!({
                    "transport": {"type": "sse", "url": SECRET},
                }),
                serde_json::json!({
                    "transport": {"type": "stdio", "command": "server", "args": [7]},
                }),
            ] {
                let error = parse_json_server_entry(
                    path,
                    "Cline",
                    "server",
                    &malformed,
                    Some(InstallTarget::Cline),
                )
                .expect_err("malformed nested Cline entries must be rejected");
                assert!(!error.message.contains(SECRET));
            }
        }

        #[test]
        fn cline_unknown_oauth_and_metadata_values_accept_bounded_json_shapes() {
            let path = Path::new("config.json");
            for field in ["oauth", "metadata"] {
                for value in [
                    serde_json::Value::Null,
                    serde_json::json!(true),
                    serde_json::json!(17),
                    serde_json::json!("opaque-state"),
                    serde_json::json!(["opaque", null, 3]),
                    serde_json::json!({"opaque": [true, null]}),
                ] {
                    let mut flat = serde_json::Map::from_iter([(
                        "command".to_owned(),
                        serde_json::json!("server"),
                    )]);
                    flat.insert(field.to_owned(), value.clone());
                    parse_json_server_entry(
                        path,
                        "Cline",
                        "flat-server",
                        &serde_json::Value::Object(flat),
                        Some(InstallTarget::Cline),
                    )
                    .expect("bounded flat Cline unknown value");

                    let mut nested = serde_json::Map::from_iter([(
                        "transport".to_owned(),
                        serde_json::json!({"type": "stdio", "command": "server"}),
                    )]);
                    nested.insert(field.to_owned(), value);
                    parse_json_server_entry(
                        path,
                        "Cline",
                        "nested-server",
                        &serde_json::Value::Object(nested),
                        Some(InstallTarget::Cline),
                    )
                    .expect("bounded nested Cline unknown value");
                }
            }
        }

        #[test]
        fn cline_extension_bounds_are_enforced() {
            let path = Path::new("config.json");
            for timeout in [
                serde_json::json!(1),
                serde_json::json!(1.5),
                serde_json::json!(3600),
            ] {
                let entry = serde_json::json!({"command": "server", "timeout": timeout});
                parse_json_server_entry(
                    path,
                    "Cline",
                    "server",
                    &entry,
                    Some(InstallTarget::Cline),
                )
                .expect("bounded timeout");
            }
            for timeout in [
                serde_json::json!(0),
                serde_json::json!(3600.1),
                serde_json::json!("60"),
            ] {
                let entry = serde_json::json!({"command": "server", "timeout": timeout});
                parse_json_server_entry(
                    path,
                    "Cline",
                    "server",
                    &entry,
                    Some(InstallTarget::Cline),
                )
                .expect_err("out-of-range timeout");
            }

            let oversized_approvals = serde_json::json!({
                "command": "server",
                "autoApprove": vec!["tool"; CLI_OUTPUT_MAX_ITEMS + 1],
            });
            parse_json_server_entry(
                path,
                "Cline",
                "server",
                &oversized_approvals,
                Some(InstallTarget::Cline),
            )
            .expect_err("oversized auto-approval list");

            let mut deep_metadata = serde_json::json!({"leaf": true});
            for _ in 0..9 {
                deep_metadata = serde_json::json!({"nested": deep_metadata});
            }
            for field in ["oauth", "metadata"] {
                for unbounded in [
                    deep_metadata.clone(),
                    serde_json::json!({
                        "nodes": vec![serde_json::Value::Null; CLI_OUTPUT_MAX_ITEMS],
                    }),
                ] {
                    let mut entry = serde_json::Map::from_iter([(
                        "command".to_owned(),
                        serde_json::json!("server"),
                    )]);
                    entry.insert(field.to_owned(), unbounded);
                    parse_json_server_entry(
                        path,
                        "Cline",
                        "server",
                        &serde_json::Value::Object(entry),
                        Some(InstallTarget::Cline),
                    )
                    .expect_err("unbounded Cline unknown value");
                }
            }
        }

        #[test]
        fn config_metadata_size_is_rejected_before_parsing() {
            assert!(
                validate_bounded_file_size(
                    Path::new("config.json"),
                    "test config",
                    1_048_576,
                    CONFIG_INPUT_MAX_BYTES,
                )
                .is_ok()
            );
            let error = validate_bounded_file_size(
                Path::new("config.json"),
                "test config",
                1_048_577,
                CONFIG_INPUT_MAX_BYTES,
            )
            .expect_err("oversized metadata must be rejected");
            assert!(error.message.contains("maximum accepted size"));
        }
    }

    // ============================================================================
    // Data Structure Tests
    // ============================================================================

    mod data_structures {
        use super::*;

        #[test]
        fn test_server_entry_serialization_redacts_environment_values() {
            const SECRET: &str = "unit-test-secret-must-not-be-rendered";
            let entry = ServerEntry {
                name: "test-server".to_string(),
                source: "Claude".to_string(),
                command: "/path/to/server".to_string(),
                args: vec!["--config".to_string(), "config.json".to_string()],
                env: Some(HashMap::from([
                    ("Z_TOKEN".to_string(), SECRET.to_string()),
                    ("A_KEY".to_string(), "another-secret".to_string()),
                ])),
                cwd: Some("/srv/test-server".to_owned()),
                enabled: true,
            };

            let json = serde_json::to_string(&entry).unwrap();
            assert!(json.contains("test-server"));
            assert!(json.contains("Claude"));
            assert!(!json.contains(SECRET));
            assert!(!json.contains("another-secret"));

            let json_value: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert_eq!(json_value["env"]["A_KEY"], REDACTED_ENV_VALUE);
            assert_eq!(json_value["env"]["Z_TOKEN"], REDACTED_ENV_VALUE);

            let yaml = serde_yaml::to_string(&entry).unwrap();
            assert!(!yaml.contains(SECRET));
            assert!(!yaml.contains("another-secret"));
            let yaml_value: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
            assert_eq!(
                yaml_value
                    .get("env")
                    .and_then(|env| env.get("A_KEY"))
                    .and_then(serde_yaml::Value::as_str),
                Some(REDACTED_ENV_VALUE)
            );
            assert_eq!(
                yaml_value
                    .get("env")
                    .and_then(|env| env.get("Z_TOKEN"))
                    .and_then(serde_yaml::Value::as_str),
                Some(REDACTED_ENV_VALUE)
            );
        }

        #[test]
        fn test_table_environment_format_preserves_sorted_keys_and_redacts_values() {
            let environment = HashMap::from([
                ("Z_TOKEN".to_owned(), "top-secret".to_owned()),
                ("A_KEY".to_owned(), "another-secret".to_owned()),
            ]);

            assert_eq!(
                format_redacted_environment(Some(&environment)),
                "A_KEY=<redacted>, Z_TOKEN=<redacted>"
            );
            assert_eq!(format_redacted_environment(None), "-");
            assert_eq!(format_redacted_environment(Some(&HashMap::new())), "-");
        }

        #[test]
        fn environment_keys_are_sorted_before_capping_and_collisions_are_retained() {
            let mut environment = (0..CLI_OUTPUT_MAX_ITEMS)
                .map(|index| (format!("B_KEY_{index:04}"), "secret".to_owned()))
                .collect::<HashMap<_, _>>();
            environment.insert("A_FIRST".to_owned(), "secret".to_owned());
            environment.insert("Z_LAST".to_owned(), "secret".to_owned());

            let entries = redacted_environment_entries(&environment);
            assert!(entries.iter().any(|(key, _)| key == "A_FIRST"));
            assert!(!entries.iter().any(|(key, _)| key == "Z_LAST"));
            assert!(
                entries
                    .iter()
                    .any(|(key, value)| key == "_fastmcp_omitted" && value.contains("omitted"))
            );

            let colliding = HashMap::from([
                ("\n".to_owned(), "first-secret".to_owned()),
                ("\\x0A".to_owned(), "second-secret".to_owned()),
            ]);
            let collision_entries = redacted_environment_entries(&colliding);
            let unique_keys = collision_entries
                .iter()
                .map(|(key, _)| key)
                .collect::<HashSet<_>>();
            assert_eq!(collision_entries.len(), 2);
            assert_eq!(unique_keys.len(), 2);
        }

        #[test]
        fn test_argument_redaction_preserves_safe_shape_without_exposing_credentials() {
            let arguments = vec![
                "--SAFE_LABEL_SECRET_CANARY".to_string(),
                "POSITIONAL_SECRET_CANARY".to_string(),
                "-u".to_string(),
                "SHORT_USER_SECRET_CANARY".to_string(),
                "-HCookie: SHORT_ATTACHED_HEADER_CANARY".to_string(),
                "-H".to_string(),
                "Cookie: SEPARATE_COOKIE_CANARY".to_string(),
                "--user=LONG_USER_SECRET_CANARY".to_string(),
                "--env=API_TOKEN=NESTED_ENV_SECRET_CANARY".to_string(),
                "--header=Authorization: Bearer HEADER_SECRET_CANARY".to_string(),
                "https://user:URL_SECRET_CANARY@example.test/path".to_string(),
                "--\u{1b}[31moption=CONTROL_LABEL_SECRET_CANARY".to_string(),
                "-\nvalue".to_string(),
                "--".to_string(),
                "--DASH_POSITIONAL_SECRET_CANARY".to_string(),
            ];

            let redacted = redacted_arguments(&arguments);
            assert_eq!(
                redacted,
                vec![
                    "--<option>",
                    "<redacted>",
                    "-<option>",
                    "<redacted>",
                    "-<option><redacted>",
                    "-<option>",
                    "<redacted>",
                    "--<option>=<redacted>",
                    "--<option>=<redacted>",
                    "--<option>=<redacted>",
                    "<redacted>",
                    "--<option>=<redacted>",
                    "-<option><redacted>",
                    "--",
                    "<redacted>",
                ]
            );
            let rendered = format_redacted_arguments(&arguments);
            for secret in [
                "SAFE_LABEL_SECRET_CANARY",
                "POSITIONAL_SECRET_CANARY",
                "SHORT_USER_SECRET_CANARY",
                "SHORT_ATTACHED_HEADER_CANARY",
                "SEPARATE_COOKIE_CANARY",
                "LONG_USER_SECRET_CANARY",
                "NESTED_ENV_SECRET_CANARY",
                "HEADER_SECRET_CANARY",
                "URL_SECRET_CANARY",
                "CONTROL_LABEL_SECRET_CANARY",
                "DASH_POSITIONAL_SECRET_CANARY",
            ] {
                assert!(!rendered.contains(secret));
            }
            assert!(!rendered.contains('\u{1b}'));
            assert!(!rendered.contains('\n'));
            assert!(rendered.starts_with("--<option> <redacted>"));

            let entry = ServerEntry {
                name: "test".to_string(),
                source: "Test".to_string(),
                command: "cmd".to_string(),
                args: arguments,
                env: None,
                cwd: None,
                enabled: true,
            };
            let json = serde_json::to_value(&entry).unwrap();
            assert_eq!(json["args"][3], REDACTED_ARGUMENT_VALUE);
            assert_eq!(json["args"][4], "-<option><redacted>");
        }

        #[test]
        fn verbose_table_redaction_is_bounded_for_large_argument_and_environment_sets() {
            let arguments =
                std::iter::repeat_n("--SECRET_LABEL=value".to_owned(), 2_000).collect::<Vec<_>>();
            let rendered_arguments = format_redacted_arguments(&arguments);
            assert!(rendered_arguments.len() <= TERMINAL_TEXT_LIMIT);
            assert!(rendered_arguments.ends_with(TERMINAL_TRUNCATED));
            assert!(!rendered_arguments.contains("SECRET_LABEL"));

            let environment = (0..2_000)
                .map(|index| {
                    (
                        format!("KEY_{index:04}_{}", "X".repeat(32)),
                        format!("SECRET_VALUE_{index}"),
                    )
                })
                .collect::<HashMap<_, _>>();
            let rendered_environment = format_redacted_environment(Some(&environment));
            assert!(rendered_environment.len() <= TERMINAL_TEXT_LIMIT);
            assert!(rendered_environment.ends_with(TERMINAL_TRUNCATED));
            assert!(!rendered_environment.contains("SECRET_VALUE"));
        }

        #[test]
        fn test_environment_key_redaction_escapes_terminal_controls_and_unicode() {
            let environment = HashMap::from([
                ("SAFE_KEY".to_owned(), "SAFE_VALUE_SECRET".to_owned()),
                (
                    "EVIL\u{1b}[31m\nKEY".to_owned(),
                    "CONTROL_VALUE_SECRET".to_owned(),
                ),
                ("BIDI\u{202e}KEY".to_owned(), "BIDI_VALUE_SECRET".to_owned()),
            ]);
            let rendered = format_redacted_environment(Some(&environment));

            assert!(rendered.contains("SAFE_KEY=<redacted>"));
            assert!(rendered.contains("EVIL\\x1B\\x5B31m\\x0AKEY=<redacted>"));
            assert!(rendered.contains("BIDI\\u{202E}KEY=<redacted>"));
            assert!(!rendered.contains('\u{1b}'));
            assert!(!rendered.contains('\u{202e}'));
            assert!(!rendered.contains('\n'));
            for secret in [
                "SAFE_VALUE_SECRET",
                "CONTROL_VALUE_SECRET",
                "BIDI_VALUE_SECRET",
            ] {
                assert!(!rendered.contains(secret));
            }

            let entry = ServerEntry {
                name: "test".to_owned(),
                source: "Test".to_owned(),
                command: "cmd".to_owned(),
                args: Vec::new(),
                env: Some(environment),
                cwd: None,
                enabled: true,
            };
            let json = serde_json::to_string(&entry).unwrap();
            assert!(!json.contains('\u{1b}'));
            assert!(!json.contains('\u{202e}'));
            assert!(!json.contains("CONTROL_VALUE_SECRET"));
        }

        #[test]
        fn terminal_text_is_single_line_ascii_and_bounded() {
            let mut candidate = "safe\u{202e}\n\u{1b}[31m".repeat(1_000);
            candidate.push_str("tail");

            let rendered = sanitize_terminal_text(&candidate);

            assert!(rendered.is_ascii());
            assert!(!rendered.contains('\n'));
            assert!(!rendered.contains('\u{1b}'));
            assert!(!rendered.contains('\u{202e}'));
            assert!(rendered.len() <= TERMINAL_TEXT_LIMIT);
            assert!(rendered.ends_with("...[truncated]"));
        }

        #[test]
        fn terminal_text_preserves_exact_fit_and_marks_only_real_overflow() {
            assert_eq!(sanitize_terminal_text_with_limit("a", 1), "a");
            assert_eq!(sanitize_terminal_text_with_limit("\n", 4), "\\x0A");
            assert_eq!(sanitize_terminal_text_with_limit("ab", 1), ".");
            assert_eq!(sanitize_terminal_text_with_limit("\nX", 4), "...[");
        }

        #[test]
        fn peer_text_reports_redaction_sanitization_and_truncation_exactly() {
            let (safe, safe_mutation) = sanitize_peer_text_with_metadata("safe", 4);
            assert_eq!(safe, "safe");
            assert_eq!(safe_mutation, OutputMutationMetadata::default());

            let (zero_budget, zero_budget_mutation) = sanitize_peer_text_with_metadata("safe", 0);
            assert_eq!(zero_budget, "");
            assert!(!zero_budget_mutation.redacted);
            assert!(!zero_budget_mutation.sanitized);
            assert!(zero_budget_mutation.truncated);

            let (escaped, escaped_mutation) = sanitize_peer_text_with_metadata("\n", 4);
            assert_eq!(escaped, "\\x0A");
            assert!(escaped_mutation.sanitized);
            assert!(!escaped_mutation.truncated);

            let (partial_marker, partial_mutation) = sanitize_peer_text_with_metadata("\nX", 4);
            assert_eq!(partial_marker, "...[");
            assert!(partial_mutation.sanitized);
            assert!(partial_mutation.truncated);

            let (literal_marker, literal_mutation) =
                sanitize_peer_text_with_metadata(TERMINAL_TRUNCATED, TERMINAL_TRUNCATED.len());
            assert_eq!(literal_marker, TERMINAL_TRUNCATED);
            assert!(!literal_mutation.truncated);

            let (redacted, redacted_mutation) =
                sanitize_peer_text_with_metadata("token=SECRET", PEER_FIELD_LIMIT);
            assert_eq!(redacted, "token=<redacted>");
            assert!(redacted_mutation.redacted);
        }

        #[test]
        fn output_line_makes_truncation_marker_visible_at_a_full_utf8_boundary() {
            let mut output = "é".repeat(CLI_OUTPUT_MAX_BYTES / 2);

            assert_eq!(output.len(), CLI_OUTPUT_MAX_BYTES);
            assert!(!push_output_line(&mut output, "overflow"));
            assert!(output.len() <= CLI_OUTPUT_MAX_BYTES);
            assert!(output.len() >= CLI_OUTPUT_MAX_BYTES - 1);
            assert!(output.ends_with("...[truncated]\n"));
            assert!(std::str::from_utf8(output.as_bytes()).is_ok());
        }

        #[test]
        fn output_line_accepts_an_exact_fit_without_a_marker() {
            let line = "x".repeat(CLI_OUTPUT_MAX_BYTES - 1);
            let mut output = String::new();

            assert!(push_output_line(&mut output, &line));
            assert_eq!(output.len(), CLI_OUTPUT_MAX_BYTES);
            assert!(!output.contains(TERMINAL_TRUNCATED));
        }

        #[test]
        fn peer_text_redacts_assignments_and_bearer_tokens_without_hiding_metadata() {
            let rendered = sanitize_peer_text(
                "tokenCount=7 authorization: Bearer PEER_SECRET\napi_key='SECOND_SECRET' [literal]",
                PEER_DETAIL_LIMIT,
            );

            assert!(rendered.contains("tokenCount=7"));
            assert!(rendered.contains("authorization: Bearer <redacted>"));
            assert!(rendered.contains("api_key='<redacted>'"));
            assert!(rendered.contains("[literal]"));
            assert!(!rendered.contains("PEER_SECRET"));
            assert!(!rendered.contains("SECOND_SECRET"));
        }

        #[test]
        fn peer_text_uses_shared_redactor_for_headers_namespaces_aws_and_userinfo() {
            let rendered = sanitize_peer_text(
                concat!(
                    "Authorization: Basic BASIC_SECRET WITH_SPACES\n",
                    "AuTh: Digest username=\"user\", response=\"DIGEST_SECRET\"\n",
                    "CoOkIe: session=COOKIE_SECRET; csrf=CSRF_SECRET\n",
                    "githubToken=CAMEL_SECRET credential=SINGULAR_SECRET ",
                    "passphrase='PHRASE SECRET' signature=SIGNATURE_SECRET\n",
                    "GET https://alice:USERINFO_SECRET@example.invalid/private?",
                    "X-Amz-Credential=AWS_CREDENTIAL_SECRET%2Fscope&",
                    "X-Amz-Signature=AWS_SIGNATURE_SECRET\n",
                    "authentication=enabled tokenCount=7 signatureAlgorithm=sha256 ",
                    "cookiePolicy=strict passwordless=true"
                ),
                TERMINAL_TEXT_LIMIT,
            );

            for secret in [
                "BASIC_SECRET",
                "WITH_SPACES",
                "DIGEST_SECRET",
                "COOKIE_SECRET",
                "CSRF_SECRET",
                "CAMEL_SECRET",
                "SINGULAR_SECRET",
                "PHRASE SECRET",
                "SIGNATURE_SECRET",
                "alice",
                "USERINFO_SECRET",
                "AWS_CREDENTIAL_SECRET",
                "AWS_SIGNATURE_SECRET",
            ] {
                assert!(!rendered.contains(secret), "leaked {secret}: {rendered}");
            }
            assert!(rendered.contains("Authorization: Basic <redacted>"));
            assert!(rendered.contains("AuTh: Digest <redacted>"));
            assert!(rendered.contains("CoOkIe: <redacted>"));
            assert!(rendered.contains("githubToken=<redacted>"));
            assert!(rendered.contains("credential=<redacted>"));
            assert!(rendered.contains("passphrase='<redacted>'"));
            assert!(rendered.contains("signature=<redacted>"));
            assert!(rendered.contains("https://<redacted>@example.invalid"));
            assert!(rendered.contains("X-Amz-Credential=<redacted>"));
            assert!(rendered.contains("X-Amz-Signature=<redacted>"));
            assert!(rendered.contains("authentication=enabled"));
            assert!(rendered.contains("tokenCount=7"));
            assert!(rendered.contains("signatureAlgorithm=sha256"));
            assert!(rendered.contains("cookiePolicy=strict"));
            assert!(rendered.contains("passwordless=true"));
        }

        #[test]
        fn structured_preview_redacts_hostile_mixed_case_keys_but_keeps_metadata() {
            let preview = bounded_json_preview(&serde_json::json!({
                "AuTh": "AUTH_SECRET",
                "CoOkIe": "COOKIE_SECRET",
                "AcCeSs_ToKeN": "TOKEN_SECRET",
                "sIgNaTuRe": "SIGNATURE_SECRET",
                "authentication": "enabled",
                "tokenCount": 7,
                "signatureAlgorithm": "sha256",
                "cookiePolicy": "strict",
                "passwordless": true,
            }));

            for key in ["AuTh", "CoOkIe", "AcCeSs_ToKeN", "sIgNaTuRe"] {
                assert!(is_credential_key(key), "missed credential key {key}");
                assert_eq!(preview[key], REDACTED_ENV_VALUE);
            }
            for key in [
                "authentication",
                "tokenCount",
                "signatureAlgorithm",
                "cookiePolicy",
                "passwordless",
            ] {
                assert!(!is_credential_key(key), "over-redacted metadata key {key}");
            }
            assert_eq!(preview["authentication"], "enabled");
            assert_eq!(preview["tokenCount"], 7);
            assert_eq!(preview["signatureAlgorithm"], "sha256");
            assert_eq!(preview["cookiePolicy"], "strict");
            assert_eq!(preview["passwordless"], true);
        }

        #[test]
        fn structured_preview_bounds_credential_precheck_and_preserves_key_collisions() {
            const SECRET: &str = "OVERSIZED-KEY-SECRET";
            let oversized_key = "metadata".repeat(JSON_CREDENTIAL_KEY_PRECHECK_MAX_BYTES);
            assert!(json_key_is_sensitive(&oversized_key));
            let mut source = serde_json::Map::new();
            source.insert(oversized_key, serde_json::json!(SECRET));
            source.insert("\n".to_owned(), serde_json::json!("first"));
            source.insert("\\x0A".to_owned(), serde_json::json!("second"));
            let preview = bounded_json_preview(&serde_json::Value::Object(source));
            let object = preview.as_object().expect("object preview");

            assert!(!serde_json::to_string(&preview).unwrap().contains(SECRET));
            assert_eq!(object.len(), 3);
            assert!(object.contains_key("\\x0A"));
            assert!(object.contains_key("\\x0A~2"));
        }

        #[test]
        fn structured_preview_reports_each_kind_of_output_mutation() {
            let mut budget = JsonPreviewBudget::default();
            budget.string_chars_remaining = 4;
            let partial = bounded_json_preview_inner(&serde_json::json!("\nX"), 0, &mut budget);
            assert_eq!(partial, "...[");
            assert!(budget.mutation.sanitized);
            assert!(budget.mutation.truncated);

            let mut literal_budget = JsonPreviewBudget::default();
            let literal = bounded_json_preview_inner(
                &serde_json::json!(TERMINAL_TRUNCATED),
                0,
                &mut literal_budget,
            );
            assert_eq!(literal, TERMINAL_TRUNCATED);
            assert!(!literal_budget.mutation.truncated);

            let mut redaction_budget = JsonPreviewBudget::default();
            let redacted = bounded_json_preview_inner(
                &serde_json::json!({"token": "STRUCTURED_SECRET"}),
                0,
                &mut redaction_budget,
            );
            assert_eq!(redacted["token"], REDACTED_ENV_VALUE);
            assert!(redaction_budget.mutation.redacted);

            let mut exact_budget = JsonPreviewBudget {
                nodes_remaining: 1,
                string_chars_remaining: 4,
                mutation: OutputMutationMetadata::default(),
            };
            let exact =
                bounded_json_preview_inner(&serde_json::json!("safe"), 0, &mut exact_budget);
            assert_eq!(exact, "safe");
            assert_eq!(exact_budget.nodes_remaining, 0);
            assert_eq!(exact_budget.string_chars_remaining, 0);
            assert_eq!(
                exact_budget.mutation,
                OutputMutationMetadata::default(),
                "exact budget exhaustion must not be reported as truncation"
            );
        }

        #[test]
        fn bounded_list_output_caps_items_and_never_copies_secret_values() {
            const SECRET: &str = "LIST_BOUND_SECRET_CANARY";
            let entries = std::iter::repeat_with(|| ServerEntry {
                name: "[server]\u{1b}[31m".to_owned(),
                source: "source".to_owned(),
                command: "token=LIST_BOUND_SECRET_CANARY".to_owned(),
                args: vec![SECRET.repeat(4)],
                env: Some(HashMap::from([("API_TOKEN".to_owned(), SECRET.repeat(4))])),
                cwd: Some(format!("token={SECRET}\nworking")),
                enabled: true,
            })
            .take(CLI_OUTPUT_MAX_ITEMS + 3)
            .collect::<Vec<_>>();

            let output = bounded_server_entries(&entries);
            let json = serde_json::to_string(&output).unwrap();

            assert_eq!(output.servers.len(), CLI_OUTPUT_MAX_ITEMS);
            assert!(output.mutation.redacted);
            assert!(output.mutation.sanitized);
            assert!(output.mutation.truncated);
            assert!(json.contains("[server]"));
            assert!(json.contains(REDACTED_ENV_VALUE));
            assert!(!json.contains(SECRET));
            assert!(!json.contains('\u{1b}'));
            assert!(json.len() <= CLI_OUTPUT_MAX_BYTES);
        }

        #[test]
        fn bounded_list_environment_keys_are_sanitized_exactly_once() {
            let output = bounded_server_entries(&[ServerEntry {
                name: "server".to_owned(),
                source: "test".to_owned(),
                command: "command".to_owned(),
                args: Vec::new(),
                env: Some(HashMap::from([("\n".to_owned(), "secret".to_owned())])),
                cwd: None,
                enabled: true,
            }]);
            let json = serde_json::to_string(&output).unwrap();

            assert!(output.mutation.redacted);
            assert!(output.mutation.sanitized);
            assert!(json.contains("\\\\x0A"));
            assert!(!json.contains("\\\\x5Cx0A"));
        }

        #[test]
        fn bounded_list_exact_fit_environment_key_is_not_truncated() {
            let exact_key = "K".repeat(PEER_FIELD_LIMIT);
            let output = bounded_server_entries(&[ServerEntry {
                name: "server".to_owned(),
                source: "test".to_owned(),
                command: "command".to_owned(),
                args: Vec::new(),
                env: Some(HashMap::from([(exact_key.clone(), "secret".to_owned())])),
                cwd: None,
                enabled: true,
            }]);

            let environment = output.servers[0].env.as_ref().unwrap();
            assert!(environment.contains_key(&exact_key));
            assert!(output.mutation.redacted);
            assert!(!output.mutation.sanitized);
            assert!(!output.mutation.truncated);
        }

        #[test]
        fn bounded_list_redacts_credentials_embedded_in_environment_keys() {
            const SECRET: &str = "ENVIRONMENT_KEY_SECRET_CANARY";
            let output = bounded_server_entries(&[ServerEntry {
                name: "server".to_owned(),
                source: "test".to_owned(),
                command: "command".to_owned(),
                args: Vec::new(),
                env: Some(HashMap::from([(
                    format!("token={SECRET}"),
                    "value-secret".to_owned(),
                )])),
                cwd: None,
                enabled: true,
            }]);
            let serialized = serde_json::to_string(&output).unwrap();

            assert!(!serialized.contains(SECRET));
            assert!(!serialized.contains("value-secret"));
            assert!(output.mutation.redacted);
            assert!(output.mutation.sanitized);
        }

        #[test]
        fn bounded_list_environment_serialization_is_deterministic() {
            let first_environment = HashMap::from([
                ("Z_KEY".to_owned(), "z-secret".to_owned()),
                ("A_KEY".to_owned(), "a-secret".to_owned()),
            ]);
            let mut second_environment = HashMap::new();
            second_environment.insert("A_KEY".to_owned(), "a-secret".to_owned());
            second_environment.insert("Z_KEY".to_owned(), "z-secret".to_owned());
            let make_entry = |environment| ServerEntry {
                name: "server".to_owned(),
                source: "test".to_owned(),
                command: "command".to_owned(),
                args: Vec::new(),
                env: Some(environment),
                cwd: None,
                enabled: true,
            };

            let first =
                serde_json::to_string(&bounded_server_entries(&[make_entry(first_environment)]))
                    .unwrap();
            let second =
                serde_json::to_string(&bounded_server_entries(&[make_entry(second_environment)]))
                    .unwrap();

            assert_eq!(first, second);
        }

        #[test]
        fn bounded_list_oversized_and_colliding_environment_keys_report_mutations() {
            let oversized_key = "K".repeat(PEER_FIELD_LIMIT + 1);
            let oversized = bounded_server_entries(&[ServerEntry {
                name: "server".to_owned(),
                source: "test".to_owned(),
                command: "command".to_owned(),
                args: Vec::new(),
                env: Some(HashMap::from([(oversized_key, "secret".to_owned())])),
                cwd: None,
                enabled: true,
            }]);
            let rendered_key = oversized.servers[0]
                .env
                .as_ref()
                .unwrap()
                .keys()
                .next()
                .unwrap();
            assert!(rendered_key.len() <= PEER_FIELD_LIMIT);
            assert!(!oversized.mutation.sanitized);
            assert!(oversized.mutation.truncated);

            let colliding = bounded_server_entries(&[ServerEntry {
                name: "server".to_owned(),
                source: "test".to_owned(),
                command: "command".to_owned(),
                args: Vec::new(),
                env: Some(HashMap::from([
                    ("token=FIRST_SECRET".to_owned(), "first".to_owned()),
                    ("token=SECOND_SECRET".to_owned(), "second".to_owned()),
                ])),
                cwd: None,
                enabled: true,
            }]);
            let environment = colliding.servers[0].env.as_ref().unwrap();
            let (redacted_key, _) = sanitize_display_key_with_metadata("token=FIRST_SECRET");
            assert_eq!(environment.len(), 2);
            assert!(environment.contains_key(&redacted_key));
            assert!(environment.contains_key(&format!("{redacted_key}~2")));
            assert!(colliding.mutation.redacted);
            assert!(colliding.mutation.sanitized);
            assert!(!colliding.mutation.truncated);
        }

        #[test]
        fn bounded_list_nested_item_budget_is_global_and_exact() {
            let output = bounded_server_entries(&[ServerEntry {
                name: "server".to_owned(),
                source: "test".to_owned(),
                command: "command".to_owned(),
                args: vec!["argument".to_owned(); CLI_OUTPUT_MAX_ITEMS - 1],
                env: Some(HashMap::from([
                    ("A".to_owned(), "first".to_owned()),
                    ("B".to_owned(), "second".to_owned()),
                ])),
                cwd: None,
                enabled: true,
            }]);

            let server = &output.servers[0];
            assert_eq!(
                server.args.len() + server.env.as_ref().unwrap().len(),
                CLI_OUTPUT_MAX_ITEMS
            );
            assert!(output.mutation.truncated);
        }

        #[test]
        fn bounded_empty_list_has_no_output_mutations() {
            let output = bounded_server_entries(&[]);

            assert!(output.servers.is_empty());
            assert_eq!(output.mutation, OutputMutationMetadata::default());
        }

        #[test]
        fn bounded_test_report_redacts_peer_errors_and_controls() {
            const SECRET: &str = "TEST_REPORT_SECRET_CANARY";
            let report = TestReport {
                server: "[server]".to_owned(),
                success: false,
                tests: vec![TestResult {
                    name: "ping\u{1b}[31m\u{202e}".to_owned(),
                    success: false,
                    skipped: false,
                    duration_ms: 1.0,
                    details: None,
                    error: Some(format!("Authorization: Bearer {SECRET}")),
                    timeout_source: None,
                    mutation: OutputMutationMetadata::default(),
                }],
                total_duration_ms: 1.0,
            };

            let json = serde_json::to_string(&bounded_test_report_value(&report)).unwrap();

            assert!(json.contains("[server]"));
            assert!(json.contains("<redacted>"));
            assert!(!json.contains(SECRET));
            assert!(!json.contains('\u{1b}'));
            assert!(!json.contains('\u{202e}'));
            let value: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert_eq!(value["redacted"], true);
            assert_eq!(value["sanitized"], true);
            assert_eq!(value["truncated"], false);
            let test = value["tests"][0].as_object().expect("test object");
            assert!(!test.contains_key("skipped"));
            assert!(!test.contains_key("details"));
        }

        #[test]
        fn bounded_test_report_omits_false_and_absent_optional_fields() {
            let report = TestReport {
                server: "server".to_owned(),
                success: true,
                tests: vec![TestResult {
                    name: "initialize".to_owned(),
                    success: true,
                    skipped: false,
                    duration_ms: 1.0,
                    details: None,
                    error: None,
                    timeout_source: None,
                    mutation: OutputMutationMetadata::default(),
                }],
                total_duration_ms: 1.0,
            };

            let value = bounded_test_report_value(&report);
            let test = value["tests"][0].as_object().expect("test object");
            assert!(!test.contains_key("skipped"));
            assert!(!test.contains_key("details"));
            assert!(!test.contains_key("error"));
            assert!(!test.contains_key("timeout_source"));
        }

        #[test]
        fn test_report_timeout_source_is_closed_and_drops_other_error_data() {
            const SECRET: &str = "TIMEOUT-DATA-SECRET-CANARY";
            let timeout = fastmcp_core::McpError::with_data(
                fastmcp_core::McpErrorCode::InternalError,
                "Request timed out at the idle deadline",
                serde_json::json!({"timeoutSource": "idle", "secret": SECRET}),
            );
            let result = failed_test_result("ping", std::time::Duration::ZERO, &timeout);
            assert_eq!(result.timeout_source, Some(TestTimeoutSource::Idle));
            let report = TestReport {
                server: "server".to_owned(),
                success: false,
                tests: vec![result],
                total_duration_ms: 0.0,
            };

            let value = bounded_test_report_value(&report);
            assert_eq!(value["tests"][0]["timeout_source"], "idle");
            assert!(!value.to_string().contains(SECRET));

            let spoofed = fastmcp_core::McpError::with_data(
                fastmcp_core::McpErrorCode::InternalError,
                "peer supplied unrelated failure",
                serde_json::json!({"timeoutSource": "idle"}),
            );
            assert_eq!(allowlisted_test_timeout_source(&spoofed), None);

            let wrong_code = fastmcp_core::McpError::with_data(
                fastmcp_core::McpErrorCode::InvalidParams,
                "Request timed out at the idle deadline",
                serde_json::json!({"timeoutSource": "idle"}),
            );
            assert_eq!(allowlisted_test_timeout_source(&wrong_code), None);

            let unknown_source = fastmcp_core::McpError::with_data(
                fastmcp_core::McpErrorCode::InternalError,
                "Request timed out at the idle deadline",
                serde_json::json!({"timeoutSource": "peer-defined"}),
            );
            assert_eq!(allowlisted_test_timeout_source(&unknown_source), None);
        }

        #[test]
        fn test_server_entry_without_env() {
            let entry = ServerEntry {
                name: "test".to_string(),
                source: "Test".to_string(),
                command: "cmd".to_string(),
                args: vec![],
                env: None,
                cwd: None,
                enabled: false,
            };

            let json = serde_json::to_string(&entry).unwrap();
            // env should be skipped when None due to skip_serializing_if
            assert!(!json.contains("env"));
        }

        #[test]
        fn test_list_output_serialization() {
            let output = ListOutput {
                servers: vec![
                    BoundedServerEntry {
                        name: "server1".to_string(),
                        source: "Claude".to_string(),
                        command: "cmd1".to_string(),
                        args: vec![],
                        env: None,
                        cwd: Some("/srv/server1".to_owned()),
                        enabled: true,
                    },
                    BoundedServerEntry {
                        name: "server2".to_string(),
                        source: "Cursor".to_string(),
                        command: "cmd2".to_string(),
                        args: vec!["arg1".to_string()],
                        env: None,
                        cwd: None,
                        enabled: false,
                    },
                ],
                mutation: OutputMutationMetadata::default(),
            };

            let json = serde_json::to_string_pretty(&output).unwrap();
            assert!(json.contains("server1"));
            assert!(json.contains("server2"));
            assert!(json.contains("Claude"));
            assert!(json.contains("Cursor"));
        }

        #[test]
        fn test_test_result_success() {
            let result = TestResult {
                name: "test_case".to_string(),
                success: true,
                skipped: false,
                duration_ms: 123.456,
                details: Some("passed".to_string()),
                error: None,
                timeout_source: None,
                mutation: OutputMutationMetadata::default(),
            };

            let json = serde_json::to_string(&result).unwrap();
            assert!(json.contains("test_case"));
            assert!(json.contains("true"));
            assert!(json.contains("123.456"));
            assert!(json.contains("passed"));
            // error should be skipped when None
            assert!(!json.contains("error"));
        }

        #[test]
        fn test_test_result_failure() {
            let result = TestResult {
                name: "failing_test".to_string(),
                success: false,
                skipped: false,
                duration_ms: 50.0,
                details: None,
                error: Some("Connection refused".to_string()),
                timeout_source: None,
                mutation: OutputMutationMetadata::default(),
            };

            let json = serde_json::to_string(&result).unwrap();
            assert!(json.contains("failing_test"));
            assert!(json.contains("false"));
            assert!(json.contains("Connection refused"));
        }

        #[test]
        fn verbose_failure_renderer_emits_error_once() {
            let result = TestResult {
                name: "failing_test".to_owned(),
                success: false,
                skipped: false,
                duration_ms: 50.0,
                details: None,
                error: Some("Connection refused".to_owned()),
                timeout_source: None,
                mutation: OutputMutationMetadata::default(),
            };

            let rendered = render_test_result(&result, true);
            assert_eq!(rendered.matches("Connection refused").count(), 1);
        }

        #[test]
        fn test_test_report_serialization() {
            let report = TestReport {
                server: "./my-server".to_string(),
                success: true,
                tests: vec![TestResult {
                    name: "init".to_string(),
                    success: true,
                    skipped: false,
                    duration_ms: 10.0,
                    details: None,
                    error: None,
                    timeout_source: None,
                    mutation: OutputMutationMetadata::default(),
                }],
                total_duration_ms: 100.0,
            };

            let json = serde_json::to_string_pretty(&report).unwrap();
            assert!(json.contains("my-server"));
            assert!(json.contains("init"));
            assert!(json.contains("total_duration_ms"));
        }

        #[test]
        fn test_mcp_server_config_serialization() {
            let config = McpServerConfig {
                command: "node".to_string(),
                args: vec!["server.js".to_string()],
                env: Some(HashMap::from([(
                    "NODE_ENV".to_string(),
                    "production".to_string(),
                )])),
                cwd: Some("/srv/node".to_owned()),
                disabled: false,
            };

            let json = serde_json::to_string(&config).unwrap();
            assert!(json.contains("node"));
            assert!(json.contains("server.js"));
            assert!(json.contains("NODE_ENV"));
        }

        #[test]
        fn test_mcp_server_config_deserialization() {
            let json = r#"{
                "command": "python",
                "args": ["-m", "my_server"],
                "env": {"PYTHONPATH": "/custom/path"},
                "cwd": "/srv/python"
            }"#;

            let config: McpServerConfig = serde_json::from_str(json).unwrap();
            assert_eq!(config.command, "python");
            assert_eq!(config.args, vec!["-m", "my_server"]);
            assert_eq!(config.cwd.as_deref(), Some("/srv/python"));
            assert_eq!(
                config.env.unwrap().get("PYTHONPATH"),
                Some(&"/custom/path".to_string())
            );
        }

        #[test]
        fn test_mcp_server_config_minimal() {
            let json = r#"{
                "command": "server"
            }"#;

            let config: McpServerConfig = serde_json::from_str(json).unwrap();
            assert_eq!(config.command, "server");
            assert_eq!(config.args, Vec::<String>::new());
            assert!(config.env.is_none());
            assert!(config.cwd.is_none());
            assert!(!config.disabled);
        }

        #[test]
        fn mcp_server_config_deserializer_is_only_a_semantic_projection() {
            let disabled: McpServerConfig = serde_json::from_str(
                r#"{"command":"server","args":[],"cwd":"/srv/server","disabled":true}"#,
            )
            .expect("disabled is part of the supported entry schema");
            assert!(disabled.disabled);
            assert_eq!(disabled.cwd.as_deref(), Some("/srv/server"));

            let extended = serde_json::from_str::<McpServerConfig>(
                r#"{"command":"server","clientExtension":{"mode":"custom"}}"#,
            )
            .expect("direct projection ignores fields that the target profile validates first");
            assert_eq!(extended.command, "server");
        }

        #[test]
        fn install_preview_redacts_arguments_and_environment_values() {
            let config = (
                "preview\u{1b}[31m".to_owned(),
                McpServerConfig {
                    command: "/bin/echo".to_owned(),
                    args: vec![
                        "POSITIONAL_PREVIEW_SECRET".to_owned(),
                        "--token=ATTACHED_PREVIEW_SECRET".to_owned(),
                        "-HAUTH_PREVIEW_SECRET".to_owned(),
                    ],
                    env: Some(HashMap::from([(
                        "API_TOKEN".to_owned(),
                        "ENV_PREVIEW_SECRET".to_owned(),
                    )])),
                    cwd: Some("token=CWD_PREVIEW_SECRET\n/srv/server".to_owned()),
                    disabled: false,
                },
            );

            let preview =
                redacted_install_config_snippet("mcpServers", &config, InstallTarget::Cursor)
                    .expect("serialize redacted preview");

            for secret in [
                "POSITIONAL_PREVIEW_SECRET",
                "ATTACHED_PREVIEW_SECRET",
                "AUTH_PREVIEW_SECRET",
                "ENV_PREVIEW_SECRET",
                "CWD_PREVIEW_SECRET",
            ] {
                assert!(!preview.contains(secret));
            }
            assert!(!preview.contains('\u{1b}'));
            let json: serde_json::Value = serde_json::from_str(&preview).unwrap();
            let (_, server) = json["mcpServers"]
                .as_object()
                .and_then(|servers| servers.iter().next())
                .expect("one preview server");
            assert_eq!(
                server["args"],
                serde_json::json!(["<redacted>", "--<option>=<redacted>", "-<option><redacted>"])
            );
            assert_eq!(server["env"]["API_TOKEN"], "<redacted>");
            assert_eq!(server["cwd"], "token=<redacted>\\x0A/srv/server");
            assert_eq!(server["type"], "stdio");
        }
    }

    // ============================================================================
    // Output Formatting Tests
    // ============================================================================

    mod output_formatting {
        use super::*;

        #[derive(Default)]
        struct FailingWriter {
            fail_write: bool,
            fail_flush: bool,
            bytes: Vec<u8>,
        }

        impl Write for FailingWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                if self.fail_write {
                    return Err(std::io::Error::other("injected write failure"));
                }
                self.bytes.extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                if self.fail_flush {
                    return Err(std::io::Error::other("injected flush failure"));
                }
                Ok(())
            }
        }

        struct BrokenPipeWriter;

        impl Write for BrokenPipeWriter {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        fn make_test_tool(name: &str, description: Option<&str>) -> fastmcp_protocol::Tool {
            fastmcp_protocol::Tool {
                name: name.to_string(),
                description: description.map(String::from),
                input_schema: serde_json::json!({}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }
        }

        fn make_test_resource(uri: &str, name: &str) -> fastmcp_protocol::Resource {
            fastmcp_protocol::Resource {
                uri: uri.to_string(),
                name: name.to_string(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            }
        }

        fn make_test_resource_template(
            uri_template: &str,
            name: &str,
        ) -> fastmcp_protocol::ResourceTemplate {
            fastmcp_protocol::ResourceTemplate {
                uri_template: uri_template.to_string(),
                name: name.to_string(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            }
        }

        fn make_test_prompt(name: &str, description: Option<&str>) -> fastmcp_protocol::Prompt {
            fastmcp_protocol::Prompt {
                name: name.to_string(),
                description: description.map(String::from),
                arguments: vec![],
                icon: None,
                version: None,
                tags: vec![],
            }
        }

        #[test]
        fn test_format_inspect_text_basic() {
            let server_info = make_test_server_info();
            let capabilities = make_test_capabilities(true, true, true);

            let output = format_inspect_text(
                &server_info,
                &capabilities,
                &[],
                &[],
                &[],
                &[],
                make_test_protocol_status(),
            );

            assert!(output.contains("test-server"));
            assert!(output.contains("v1.0.0"));
            assert!(output.contains("tools=true"));
            assert!(output.contains("resources=true"));
            assert!(output.contains("prompts=true"));
        }

        #[test]
        fn test_format_inspect_text_with_tools() {
            let server_info = make_test_server_info();
            let capabilities = make_test_capabilities(true, false, false);

            let tools = vec![make_test_tool("my_tool", Some("A test tool"))];

            let output = format_inspect_text(
                &server_info,
                &capabilities,
                &tools,
                &[],
                &[],
                &[],
                make_test_protocol_status(),
            );

            assert!(output.contains("Tools (1)"));
            assert!(output.contains("my_tool"));
            assert!(output.contains("A test tool"));
        }

        #[test]
        fn test_format_inspect_text_with_resources() {
            let server_info = make_test_server_info();
            let capabilities = make_test_capabilities(false, true, false);

            let resources = vec![make_test_resource("file:///test.txt", "test file")];

            let output = format_inspect_text(
                &server_info,
                &capabilities,
                &[],
                &resources,
                &[],
                &[],
                make_test_protocol_status(),
            );

            assert!(output.contains("Resources (1)"));
            assert!(output.contains("file:///test.txt"));
            assert!(output.contains("test file"));
        }

        #[test]
        fn test_format_inspect_text_with_prompts() {
            let server_info = make_test_server_info();
            let capabilities = make_test_capabilities(false, false, true);

            let prompts = vec![make_test_prompt("greeting", Some("A greeting prompt"))];

            let output = format_inspect_text(
                &server_info,
                &capabilities,
                &[],
                &[],
                &[],
                &prompts,
                make_test_protocol_status(),
            );

            assert!(output.contains("Prompts (1)"));
            assert!(output.contains("greeting"));
            assert!(output.contains("A greeting prompt"));
        }

        #[test]
        fn inspect_text_escapes_controls_redacts_credentials_and_preserves_brackets() {
            const SECRET: &str = "INSPECT_TEXT_SECRET_CANARY";
            let server_info = fastmcp_protocol::ServerInfo {
                name: "[literal]\u{1b}[31m\u{202e}".to_owned(),
                version: "token=INSPECT_TEXT_SECRET_CANARY".to_owned(),
            };
            let capabilities = make_test_capabilities(true, false, false);
            let tools = vec![make_test_tool(
                "[tool]\nname",
                Some("Authorization: Bearer INSPECT_TEXT_SECRET_CANARY"),
            )];

            let output = format_inspect_text(
                &server_info,
                &capabilities,
                &tools,
                &[],
                &[],
                &[],
                make_test_protocol_status(),
            );

            assert!(output.contains("[literal]"));
            assert!(output.contains("[tool]"));
            assert!(output.contains("<redacted>"));
            assert!(!output.contains(SECRET));
            assert!(!output.contains('\u{1b}'));
            assert!(!output.contains('\u{202e}'));
            assert!(!output.lines().any(|line| line == "name"));
            assert!(output.len() <= CLI_OUTPUT_MAX_BYTES);
        }

        #[test]
        fn test_format_inspect_json_basic() {
            let server_info = make_test_server_info();
            let capabilities = make_test_capabilities(true, true, false);

            let result = format_inspect_json(
                &server_info,
                &capabilities,
                &[],
                &[],
                &[],
                &[],
                make_test_protocol_status(),
            );

            assert!(result.is_ok());
            let json = result.unwrap();
            assert!(json.contains("\"name\": \"test-server\""));
            assert!(json.contains("\"version\": \"1.0.0\""));
            assert!(json.contains("\"tools\": true"));
            assert!(json.contains("\"resources\": true"));
            assert!(json.contains("\"prompts\": false"));
            let value: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert_eq!(value["redacted"], false);
            assert_eq!(value["sanitized"], false);
            assert_eq!(value["truncated"], false);
            assert_eq!(value["protocol"]["policy"], "auto");
            assert_eq!(value["protocol"]["version"], "2026-07-28");
            assert_eq!(value["protocol"]["era"], "modern-2026");
        }

        #[test]
        fn test_format_inspect_json_preserves_all_items() {
            let server_info = make_test_server_info();
            let capabilities = make_test_capabilities(true, true, true);

            let mut tool = make_test_tool("calculator", Some("Performs calculations"));
            tool.input_schema = serde_json::json!({
                "type": "object",
                "properties": {
                    "expression": { "type": "string" }
                }
            });
            let tools = vec![tool, make_test_tool("converter", None)];
            let resources = vec![
                make_test_resource("file:///one.txt", "one"),
                make_test_resource("file:///two.txt", "two"),
            ];
            let resource_templates = vec![
                make_test_resource_template("file:///{first}", "first"),
                make_test_resource_template("file:///{second}", "second"),
            ];
            let prompts = vec![
                make_test_prompt("greeting", None),
                make_test_prompt("farewell", None),
            ];

            let result = format_inspect_json(
                &server_info,
                &capabilities,
                &tools,
                &resources,
                &resource_templates,
                &prompts,
                make_test_protocol_status(),
            )
            .unwrap();
            let json: serde_json::Value = serde_json::from_str(&result).unwrap();

            assert_eq!(json["tools"].as_array().map(Vec::len), Some(tools.len()));
            assert_eq!(
                json["resources"].as_array().map(Vec::len),
                Some(resources.len())
            );
            assert_eq!(
                json["resource_templates"].as_array().map(Vec::len),
                Some(resource_templates.len())
            );
            assert_eq!(
                json["prompts"].as_array().map(Vec::len),
                Some(prompts.len())
            );
            assert_eq!(json["tools"][0]["name"], "calculator");
            assert_eq!(json["tools"][1]["name"], "converter");
        }

        #[test]
        fn inspect_json_redacts_credentials_and_bounds_depth_and_items() {
            const SECRET: &str = "INSPECT_JSON_SECRET_CANARY";
            let server_info = fastmcp_protocol::ServerInfo {
                name: "authorization=INSPECT_JSON_SECRET_CANARY".to_owned(),
                version: "1.0".to_owned(),
            };
            let capabilities = make_test_capabilities(true, false, false);
            let mut deep = serde_json::Value::String(SECRET.to_owned());
            for index in 0..(JSON_PREVIEW_MAX_DEPTH + 8) {
                let mut wrapper = serde_json::Map::new();
                wrapper.insert(format!("level_{index}"), deep);
                deep = serde_json::Value::Object(wrapper);
            }
            let mut tool = make_test_tool("[safe]", Some("api_key=INSPECT_JSON_SECRET_CANARY"));
            tool.input_schema = serde_json::json!({
                "password": SECRET,
                "line\nkey": "safe",
                "nested": deep,
            });
            let tools = std::iter::repeat_n(tool, CLI_OUTPUT_MAX_ITEMS + 5).collect::<Vec<_>>();

            let output = format_inspect_json(
                &server_info,
                &capabilities,
                &tools,
                &[],
                &[],
                &[],
                make_test_protocol_status(),
            )
            .unwrap();
            let json: serde_json::Value = serde_json::from_str(&output).unwrap();

            assert_eq!(
                json["tools"].as_array().map(Vec::len),
                Some(CLI_OUTPUT_MAX_ITEMS)
            );
            assert_eq!(json["truncated"].as_bool(), Some(true));
            assert_eq!(json["redacted"].as_bool(), Some(true));
            assert_eq!(json["sanitized"].as_bool(), Some(true));
            assert!(output.contains("<redacted>"));
            assert!(output.contains("[safe]"));
            assert!(output.contains("depth limit"));
            assert!(!output.contains(SECRET));
            assert!(!output.contains('\u{1b}'));
            assert!(output.len() <= CLI_OUTPUT_MAX_BYTES);
        }

        #[test]
        fn inspect_json_marks_nested_tag_and_prompt_argument_caps() {
            let server_info = make_test_server_info();
            let capabilities = make_test_capabilities(true, false, true);
            let mut tool = make_test_tool("tagged", None);
            tool.tags = vec!["tag".to_owned(); JSON_PREVIEW_MAX_CONTAINER_ITEMS + 1];
            let mut prompt = make_test_prompt("many-arguments", None);
            prompt.arguments = vec![
                fastmcp_protocol::PromptArgument {
                    name: "argument".to_owned(),
                    description: None,
                    required: false,
                };
                JSON_PREVIEW_MAX_CONTAINER_ITEMS + 1
            ];

            let output = format_inspect_json(
                &server_info,
                &capabilities,
                &[tool],
                &[],
                &[],
                &[prompt],
                make_test_protocol_status(),
            )
            .expect("inspect JSON");
            let value: serde_json::Value = serde_json::from_str(&output).unwrap();

            assert_eq!(value["truncated"], true);
            assert_eq!(
                value["tools"][0]["tags"].as_array().map(Vec::len),
                Some(JSON_PREVIEW_MAX_CONTAINER_ITEMS)
            );
            assert_eq!(
                value["prompts"][0]["arguments"].as_array().map(Vec::len),
                Some(JSON_PREVIEW_MAX_CONTAINER_ITEMS)
            );
        }

        #[test]
        fn inspect_renderers_surface_page_acquisition_truncation() {
            let server_info = make_test_server_info();
            let capabilities = make_test_capabilities(true, false, false);
            let capabilities = InspectCapabilities::Legacy(capabilities);
            let complete_text = format_inspect_text_for_capabilities_with_truncation(
                &server_info,
                &capabilities,
                &[],
                &[],
                &[],
                &[],
                false,
                make_test_protocol_status(),
            );
            let complete_json = format_inspect_json_for_capabilities_with_truncation(
                &server_info,
                &capabilities,
                &[],
                &[],
                &[],
                &[],
                false,
                make_test_protocol_status(),
            )
            .expect("inspect JSON");
            let truncated_text = format_inspect_text_for_capabilities_with_truncation(
                &server_info,
                &capabilities,
                &[],
                &[],
                &[],
                &[],
                true,
                make_test_protocol_status(),
            );
            let truncated_json = format_inspect_json_for_capabilities_with_truncation(
                &server_info,
                &capabilities,
                &[],
                &[],
                &[],
                &[],
                true,
                make_test_protocol_status(),
            )
            .expect("inspect JSON");

            assert!(!complete_text.contains("Data truncated"));
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&complete_json).unwrap()["truncated"],
                false
            );
            assert!(truncated_text.contains("Data truncated"));
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&truncated_json).unwrap()["truncated"],
                true
            );
        }

        #[test]
        fn test_write_inspect_output_propagates_write_failure() {
            let mut writer = FailingWriter {
                fail_write: true,
                ..FailingWriter::default()
            };

            let error = write_inspect_output(&mut writer, "inspect payload").unwrap_err();

            assert!(error.message.contains("Failed to write inspect output"));
            assert!(error.message.contains("I/O kind: Other"));
            assert!(!error.message.contains("injected write failure"));
        }

        #[test]
        fn test_write_inspect_output_propagates_flush_failure() {
            let mut writer = FailingWriter {
                fail_flush: true,
                ..FailingWriter::default()
            };

            let error = write_inspect_output(&mut writer, "inspect payload").unwrap_err();

            assert_eq!(writer.bytes.as_slice(), b"inspect payload");
            assert!(error.message.contains("Failed to flush inspect output"));
            assert!(error.message.contains("I/O kind: Other"));
            assert!(!error.message.contains("injected flush failure"));
        }

        #[test]
        fn shared_stdout_writer_reports_broken_pipe_without_panicking_or_echoing_data() {
            const SECRET: &str = "BROKEN_PIPE_SECRET_CANARY";
            let error = write_stdout_output(&mut BrokenPipeWriter, SECRET, "test output", true)
                .unwrap_err();

            assert!(
                error
                    .message
                    .contains("Failed to write test output to stdout")
            );
            assert!(error.message.contains("BrokenPipe"));
            assert!(!error.message.contains(SECRET));
        }

        #[test]
        fn reality_check_regression_test_output_guard_closes_after_output_failure() {
            let cleanup_calls = std::cell::Cell::new(0_u8);
            let value = finish_test_output(Ok(17_u8), || {
                cleanup_calls.set(cleanup_calls.get() + 1);
                Err(fastmcp_core::McpError::internal_error(
                    "cleanup must not run",
                ))
            })
            .expect("successful incremental output keeps the client live");
            assert_eq!(value, 17);
            assert_eq!(cleanup_calls.get(), 0);

            let output_error = fastmcp_core::McpError::internal_error("output sentinel");
            let error = finish_test_output::<(), _>(Err(output_error), || {
                cleanup_calls.set(cleanup_calls.get() + 1);
                Ok(())
            })
            .expect_err("failed output must be returned after verified cleanup");
            assert_eq!(error.message, "output sentinel");
            assert_eq!(cleanup_calls.get(), 1);
        }

        #[test]
        fn inspect_acquisition_closes_after_success_and_rejection() {
            let cleanup_calls = std::cell::Cell::new(0_u8);
            let value = finish_inspect_acquisition(Ok(17_u8), || {
                cleanup_calls.set(cleanup_calls.get() + 1);
                Ok(())
            })
            .expect("a successful acquisition with successful cleanup is retained");
            assert_eq!(value, 17);
            assert_eq!(cleanup_calls.get(), 1);

            let acquisition_error = fastmcp_core::McpError::invalid_params("list sentinel");
            let error = finish_inspect_acquisition::<(), _>(Err(acquisition_error.clone()), || {
                cleanup_calls.set(cleanup_calls.get() + 1);
                Ok(())
            })
            .expect_err("a rejected list response remains an inspect failure");
            assert_eq!(cleanup_calls.get(), 2);
            assert_eq!(error.code, acquisition_error.code);
            assert_eq!(error.message, acquisition_error.message);
        }

        #[test]
        fn inspect_acquisition_rh5_preserves_the_same_rejection_when_cleanup_is_unverified() {
            let cleanup_calls = std::cell::Cell::new(0_u8);
            let acquisition_error = fastmcp_core::McpError::invalid_params("list sentinel");
            let cleanup_error = fastmcp_core::McpError::internal_error("cleanup sentinel");

            // RH-5: changing only cleanup from a success to a failure must
            // retain the rejected acquisition and make lifecycle uncertainty
            // machine-visible instead of relying on Client::drop.
            let error = finish_inspect_acquisition::<(), _>(Err(acquisition_error.clone()), || {
                cleanup_calls.set(cleanup_calls.get() + 1);
                Err(cleanup_error.clone())
            })
            .expect_err("cleanup uncertainty must remain visible");

            assert_eq!(cleanup_calls.get(), 1);
            assert!(fastmcp_client::is_cleanup_unverified(&error));
            let data = error
                .data
                .as_ref()
                .and_then(serde_json::Value::as_object)
                .expect("unverified cleanup must retain structured inspect evidence");
            assert_eq!(data["operation"]["message"], "list sentinel");
            assert_eq!(data["cleanup"]["message"], "cleanup sentinel");
        }

        #[test]
        fn reality_check_regression_output_guard_preserves_output_and_cleanup_failures() {
            let error = finish_test_output::<(), _>(
                Err(fastmcp_core::McpError::internal_error(
                    "output failure sentinel",
                )),
                || {
                    Err(fastmcp_core::McpError::internal_error(
                        "cleanup failure sentinel",
                    ))
                },
            )
            .expect_err("unverified cleanup must remain visible");

            assert!(fastmcp_client::is_cleanup_unverified(&error));
            assert!(error.message.contains("output failure sentinel"));
            assert!(error.message.contains("cleanup failure sentinel"));
            let data = error
                .data
                .as_ref()
                .and_then(serde_json::Value::as_object)
                .expect("combined failure has structured data");
            assert!(data.get("operation").is_some());
            assert!(data.get("cleanup").is_some());
            assert!(
                data.get(CLIENT_CLEANUP_DURATION_MS_DATA_KEY)
                    .and_then(serde_json::Value::as_f64)
                    .is_some_and(|duration| duration >= 0.0)
            );
        }

        #[test]
        fn reality_check_regression_failed_connection_output_preserves_cleanup_evidence() {
            let terminal_error = fastmcp_core::McpError::with_data(
                fastmcp_core::McpErrorCode::InternalError,
                "initialization and cleanup failed",
                serde_json::json!({
                    CLIENT_CLEANUP_UNVERIFIED_DATA_KEY: true,
                    "operation": fastmcp_core::McpError::internal_error(
                        "initialization sentinel"
                    ),
                    "cleanup": fastmcp_core::McpError::internal_error("cleanup sentinel"),
                    CLIENT_CLEANUP_DURATION_MS_DATA_KEY: 17.0,
                }),
            );
            let combined = combine_test_failure_with_output(
                terminal_error,
                fastmcp_core::McpError::internal_error("reporting sentinel"),
            );

            assert!(fastmcp_client::is_cleanup_unverified(&combined));
            assert!(
                combined
                    .message
                    .contains("initialization and cleanup failed")
            );
            assert!(combined.message.contains("reporting sentinel"));
            let data = combined
                .data
                .as_ref()
                .and_then(serde_json::Value::as_object)
                .expect("combined failure retains structured data");
            assert!(data.get("operation").is_some());
            assert!(data.get("cleanup").is_some());
            assert!(data.get("reporting").is_some());
            assert_eq!(
                data.get(CLIENT_CLEANUP_DURATION_MS_DATA_KEY)
                    .and_then(serde_json::Value::as_f64),
                Some(17.0)
            );
        }

        #[test]
        fn shared_stdout_writer_rejects_oversized_aggregate_before_writing() {
            let mut writer = FailingWriter::default();
            let output = "x".repeat(CLI_OUTPUT_MAX_BYTES + 1);

            let error = write_stdout_output(&mut writer, &output, "test output", false)
                .expect_err("oversized output must be rejected");

            assert_eq!(writer.bytes, Vec::<u8>::new());
            assert!(error.message.contains("Refusing to write test output"));
        }
    }

    // ============================================================================
    // Config Path Tests
    // ============================================================================

    mod config_paths {
        use super::*;

        #[cfg(target_os = "linux")]
        fn retained_atomic_test_directory(label: &str) -> PathBuf {
            use std::os::unix::fs::PermissionsExt as _;

            const HEX: &[u8; 16] = b"0123456789abcdef";
            let temp_root = std::fs::canonicalize(std::env::temp_dir())
                .expect("resolve the test temporary directory without symlink components");
            for _ in 0..16 {
                let identifier = fastmcp_core::draw_security_identifier()
                    .expect("operating-system randomness for atomic test fixture");
                let mut suffix = String::with_capacity(64);
                for byte in identifier.as_bytes() {
                    suffix.push(char::from(HEX[usize::from(*byte >> 4)]));
                    suffix.push(char::from(HEX[usize::from(*byte & 0x0f)]));
                }
                let directory = temp_root.join(format!(
                    "fastmcp-cli-{label}-{}-{suffix}",
                    std::process::id()
                ));
                match std::fs::create_dir(&directory) {
                    Ok(()) => {
                        std::fs::set_permissions(&directory, Permissions::from_mode(0o700))
                            .expect("exact test-directory permissions");
                        return directory;
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("create retained atomic test directory: {error}"),
                }
            }
            panic!("could not allocate retained atomic test directory")
        }

        #[cfg(target_os = "linux")]
        fn atomic_template_snapshot(
            directory: &Path,
            contents: &[u8],
            mode: u32,
        ) -> ExistingFileSnapshot {
            use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

            let template = directory.join("template.json");
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .open(&template)
                .expect("create atomic template fixture");
            file.write_all(contents).expect("write template fixture");
            file.set_permissions(Permissions::from_mode(mode))
                .expect("set exact template mode");
            file.sync_all().expect("sync template fixture");
            let DestinationSnapshot::Existing(snapshot) = read_destination_snapshot(
                &template,
                "atomic template fixture",
                CONFIG_INPUT_MAX_BYTES,
            )
            .expect("read template fixture") else {
                panic!("template fixture unexpectedly missing");
            };
            snapshot
        }

        #[cfg(target_os = "linux")]
        fn assign_test_ownership(file: &File, owner: u32, group: u32) -> bool {
            match rustix::fs::fchown(
                file,
                Some(rustix::fs::Uid::from_raw(owner)),
                Some(rustix::fs::Gid::from_raw(group)),
            ) {
                Ok(()) => true,
                Err(error) => {
                    let error = io::Error::from(error);
                    if matches!(
                        error.kind(),
                        io::ErrorKind::InvalidInput | io::ErrorKind::PermissionDenied
                    ) {
                        false
                    } else {
                        panic!("assign test ownership: {error}");
                    }
                }
            }
        }

        #[cfg(target_os = "linux")]
        fn publish_test_stage(
            parent: &SecuredParentDirectory,
            staged: &RetainedStage,
            destination: &Path,
        ) -> DurablePublication {
            let destination_name = destination.file_name().expect("test destination name");
            rustix::fs::renameat_with(
                &parent.handle,
                staged.relative_name(),
                &parent.handle,
                destination_name,
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .expect("publish test stage");
            assert_eq!(
                classify_stage_publication(parent, staged, destination_name)
                    .expect("classify test publication"),
                StagePublicationLocation::Published
            );
            establish_publication_durability(parent, staged, destination_name)
                .expect("make test publication durable before permission finalization")
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn publication_establishes_ownership_before_rename_and_widens_mode_afterward() {
            use std::os::unix::fs::MetadataExt as _;

            let directory = retained_atomic_test_directory("publication-phases");
            let snapshot = atomic_template_snapshot(&directory, b"template", 0o640);
            let destination = directory.join("published.json");
            let parent = SecuredParentDirectory::open(
                &directory,
                &destination,
                "atomic publication phase test",
            )
            .expect("secure test parent");
            let expected = b"replacement contents";
            let mut staged = create_retained_same_directory_temp(
                &parent,
                Some(&snapshot),
                &destination,
                "atomic publication phase test",
                "test",
            )
            .expect("create test stage");
            stage_retained_contents(
                &parent,
                &mut staged,
                expected,
                &destination,
                "atomic publication phase test",
            )
            .expect("stage test contents");
            prepare_staged_for_publication(
                &parent,
                &staged,
                expected,
                Some(&snapshot),
                &destination,
                "atomic publication phase test",
            )
            .expect("prepare test stage");
            let prepared = staged.as_file().metadata().expect("prepared metadata");
            assert_eq!(prepared.uid(), snapshot.metadata.owner);
            assert_eq!(prepared.gid(), snapshot.metadata.group);
            assert_eq!(prepared.mode() & 0o7777, 0o600);

            let durability_proof = publish_test_stage(&parent, &staged, &destination);
            assert_eq!(
                staged
                    .as_file()
                    .metadata()
                    .expect("published metadata")
                    .mode()
                    & 0o7777,
                0o600
            );
            finalize_published_file_metadata(
                &parent,
                durability_proof,
                &staged,
                destination.file_name().expect("test destination name"),
                expected,
                Some(&snapshot),
                &destination,
                "atomic publication phase test",
            )
            .expect("finalize published test file");
            let finalized = staged.as_file().metadata().expect("final metadata");
            assert_eq!(finalized.uid(), snapshot.metadata.owner);
            assert_eq!(finalized.gid(), snapshot.metadata.group);
            assert_eq!(finalized.mode() & 0o7777, 0o640);
            assert_eq!(
                std::fs::read(&destination).expect("published bytes"),
                expected
            );
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn durability_proof_cannot_be_minted_before_publication() {
            use std::os::unix::fs::MetadataExt as _;

            let directory = retained_atomic_test_directory("premature-durability-proof");
            let destination = directory.join("must-remain-unpublished.json");
            let destination_name = destination.file_name().expect("test destination name");
            let parent = SecuredParentDirectory::open(
                &directory,
                &destination,
                "premature durability proof test",
            )
            .expect("secure premature-proof parent");
            let expected = b"private unpublished candidate";
            let mut staged = create_retained_same_directory_temp(
                &parent,
                None,
                &destination,
                "premature durability proof test",
                "test",
            )
            .expect("create premature-proof stage");
            stage_retained_contents(
                &parent,
                &mut staged,
                expected,
                &destination,
                "premature durability proof test",
            )
            .expect("write premature-proof stage");
            prepare_staged_for_publication(
                &parent,
                &staged,
                expected,
                None,
                &destination,
                "premature durability proof test",
            )
            .expect("prepare premature-proof stage");

            let error = establish_publication_durability(&parent, &staged, destination_name)
                .expect_err("a staged candidate must not yield a durability proof");
            assert_eq!(error.kind(), io::ErrorKind::Other);
            assert!(!destination.exists());
            assert_eq!(
                staged
                    .as_file()
                    .metadata()
                    .expect("private staged metadata")
                    .mode()
                    & 0o7777,
                0o600
            );
            assert!(
                descriptor_name_matches_staged_file(&parent, &staged, staged.relative_name())
                    .expect("staged identity after refused proof")
            );
            parent
                .sync()
                .expect("sync retained premature-proof fixture");
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn parent_sync_failure_after_real_rename_keeps_published_inode_private() {
            use std::os::unix::fs::MetadataExt as _;

            let directory = retained_atomic_test_directory("parent-sync-failure");
            let snapshot = atomic_template_snapshot(&directory, b"template", 0o640);
            let destination = directory.join("template.json");
            let parent = SecuredParentDirectory::open(
                &directory,
                &destination,
                "atomic parent sync failure test",
            )
            .expect("secure test parent");
            let expected = b"must-remain-private";
            let original = DestinationSnapshot::Existing(snapshot);
            let error = atomic_replace_prepared_file_at_with_durability(
                parent,
                &destination,
                expected,
                "atomic parent sync failure test",
                CONFIG_OUTPUT_MAX_BYTES,
                &original,
                |secured_parent, staged, destination_name| {
                    assert_eq!(
                        classify_stage_publication(secured_parent, staged, destination_name,)
                            .expect("classify publication at injected sync seam"),
                        StagePublicationLocation::Published
                    );
                    assert_eq!(
                        staged
                            .as_file()
                            .metadata()
                            .expect("private published metadata at sync seam")
                            .mode()
                            & 0o7777,
                        0o600
                    );
                    publication_durability::establish_with_sync(
                        secured_parent,
                        staged,
                        destination_name,
                        |_| Err(io::Error::other("injected parent sync failure")),
                    )
                },
            )
            .expect_err("injected parent sync failure must abort finalization");
            assert!(
                error
                    .message
                    .contains("durability could not be established")
            );
            assert_eq!(
                std::fs::read(&destination).expect("read privately published destination"),
                expected
            );
            assert_eq!(
                destination
                    .metadata()
                    .expect("private published metadata")
                    .mode()
                    & 0o7777,
                0o600
            );
            File::open(&directory)
                .expect("open retained fixture directory")
                .sync_all()
                .expect("retain the injected-failure test fixture durably");
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn durability_proof_rejects_parent_mutation_during_sync_seam() {
            use std::os::unix::fs::MetadataExt as _;

            let directory = retained_atomic_test_directory("parent-sync-mutation");
            let snapshot = atomic_template_snapshot(&directory, b"template", 0o640);
            let destination = directory.join("mutation-during-sync.json");
            let destination_name = destination.file_name().expect("test destination name");
            let parent =
                SecuredParentDirectory::open(&directory, &destination, "parent sync mutation test")
                    .expect("secure sync-mutation parent");
            let expected = b"must-stay-private-after-mutation";
            let mut staged = create_retained_same_directory_temp(
                &parent,
                Some(&snapshot),
                &destination,
                "parent sync mutation test",
                "test",
            )
            .expect("create sync-mutation stage");
            stage_retained_contents(
                &parent,
                &mut staged,
                expected,
                &destination,
                "parent sync mutation test",
            )
            .expect("stage sync-mutation contents");
            prepare_staged_for_publication(
                &parent,
                &staged,
                expected,
                Some(&snapshot),
                &destination,
                "parent sync mutation test",
            )
            .expect("prepare sync-mutation stage");
            rustix::fs::renameat_with(
                &parent.handle,
                staged.relative_name(),
                &parent.handle,
                destination_name,
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .expect("publish sync-mutation stage privately");

            let error = publication_durability::establish_with_sync(
                &parent,
                &staged,
                destination_name,
                |secured_parent| {
                    rustix::fs::mkdirat(
                        &secured_parent.handle,
                        ".fastmcp-retained-sync-mutation-marker",
                        rustix::fs::Mode::RWXU,
                    )
                    .map_err(io::Error::from)?;
                    secured_parent.sync()
                },
            )
            .expect_err("parent mutation across fsync must invalidate the proof");
            assert!(error.to_string().contains("metadata changed"));
            assert_eq!(
                staged
                    .as_file()
                    .metadata()
                    .expect("private sync-mutation candidate")
                    .mode()
                    & 0o7777,
                0o600
            );
            assert!(destination.exists());
            parent.sync().expect("sync retained sync-mutation fixtures");
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn final_stage_stamp_rejects_rebound_staging_name() {
            use std::os::unix::ffi::OsStringExt as _;

            let directory = retained_atomic_test_directory("stage-stamp-rebinding");
            let destination = directory.join("eventual-destination.json");
            let parent = SecuredParentDirectory::open(
                &directory,
                &destination,
                "stage stamp rebinding test",
            )
            .expect("secure stage-stamp parent");
            let expected = b"stable staged bytes";
            let mut staged = create_retained_same_directory_temp(
                &parent,
                None,
                &destination,
                "stage stamp rebinding test",
                "test",
            )
            .expect("create stage-stamp fixture");
            stage_retained_contents(
                &parent,
                &mut staged,
                expected,
                &destination,
                "stage stamp rebinding test",
            )
            .expect("write stage-stamp fixture");
            let stamp = verify_staged_contents_and_metadata(
                &parent,
                &staged,
                expected,
                None,
                &destination,
                "stage stamp rebinding test",
            )
            .expect("capture final stage stamp");
            let original_name = staged.relative_name().to_os_string();
            let mut detached_bytes = original_name.as_encoded_bytes().to_vec();
            detached_bytes.extend_from_slice(b".detached");
            let detached_name = std::ffi::OsString::from_vec(detached_bytes);
            rustix::fs::renameat_with(
                &parent.handle,
                &original_name,
                &parent.handle,
                &detached_name,
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .expect("retain original inode at detached test name");
            let mut replacement = File::from(
                rustix::fs::openat(
                    &parent.handle,
                    &original_name,
                    rustix::fs::OFlags::RDWR
                        | rustix::fs::OFlags::CREATE
                        | rustix::fs::OFlags::EXCL
                        | rustix::fs::OFlags::CLOEXEC
                        | rustix::fs::OFlags::NOFOLLOW,
                    rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                )
                .expect("bind replacement inode at original staging name"),
            );
            replacement
                .write_all(expected)
                .expect("write replacement inode");
            replacement.sync_all().expect("sync replacement inode");
            assert!(
                !descriptor_relative_stage_matches_stamp(&parent, &original_name, stamp)
                    .expect("compare rebound staging name against captured stamp")
            );
            parent.sync().expect("sync retained stamp fixtures");
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn ownership_failure_stops_before_publication() {
            use std::os::unix::fs::MetadataExt as _;

            if rustix::process::geteuid().as_raw() == 0 {
                return;
            }
            let directory = retained_atomic_test_directory("ownership-failure");
            let mut snapshot = atomic_template_snapshot(&directory, b"template", 0o640);
            snapshot.metadata.owner = 0;
            let destination = directory.join("must-not-publish.json");
            let parent = SecuredParentDirectory::open(
                &directory,
                &destination,
                "atomic ownership failure test",
            )
            .expect("secure test parent");
            let expected = b"private candidate";
            let mut staged = create_retained_same_directory_temp(
                &parent,
                Some(&snapshot),
                &destination,
                "atomic ownership failure test",
                "test",
            )
            .expect("create test stage");
            stage_retained_contents(
                &parent,
                &mut staged,
                expected,
                &destination,
                "atomic ownership failure test",
            )
            .expect("stage test contents");

            let error = prepare_staged_for_publication(
                &parent,
                &staged,
                expected,
                Some(&snapshot),
                &destination,
                "atomic ownership failure test",
            )
            .expect_err("unprivileged ownership transfer must fail");
            assert!(error.message.contains("before publication failed"));
            assert!(!destination.exists());
            assert!(
                descriptor_name_matches_staged_file(&parent, &staged, staged.relative_name())
                    .expect("retained stage identity")
            );
            let retained = staged.as_file().metadata().expect("retained metadata");
            assert_eq!(retained.uid(), staged.staging_owner);
            assert_eq!(retained.mode() & 0o7777, 0o600);
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn root_prepares_non_root_final_ownership_before_publication() {
            use std::os::unix::fs::MetadataExt as _;

            if rustix::process::geteuid().as_raw() != 0 {
                return;
            }
            const NON_ROOT_ID: u32 = 65_534;
            let directory = retained_atomic_test_directory("root-ownership-transfer");
            let _initial_snapshot = atomic_template_snapshot(&directory, b"template", 0o640);
            let template = File::open(directory.join("template.json")).expect("open template");
            if !assign_test_ownership(&template, NON_ROOT_ID, NON_ROOT_ID) {
                return;
            }
            let DestinationSnapshot::Existing(snapshot) = read_destination_snapshot(
                &directory.join("template.json"),
                "root ownership template",
                CONFIG_INPUT_MAX_BYTES,
            )
            .expect("read root ownership template") else {
                panic!("root ownership template unexpectedly missing");
            };
            let destination = directory.join("root-prepared.json");
            let parent = SecuredParentDirectory::open(
                &directory,
                &destination,
                "root ownership preparation test",
            )
            .expect("secure test parent");
            let expected = b"root-prepared candidate";
            let mut staged = create_retained_same_directory_temp(
                &parent,
                Some(&snapshot),
                &destination,
                "root ownership preparation test",
                "test",
            )
            .expect("create root-owned test stage");
            stage_retained_contents(
                &parent,
                &mut staged,
                expected,
                &destination,
                "root ownership preparation test",
            )
            .expect("stage root ownership contents");
            prepare_staged_for_publication(
                &parent,
                &staged,
                expected,
                Some(&snapshot),
                &destination,
                "root ownership preparation test",
            )
            .expect("prepare non-root final ownership");
            let prepared = staged.as_file().metadata().expect("prepared metadata");
            assert_eq!(prepared.uid(), NON_ROOT_ID);
            assert_eq!(prepared.gid(), NON_ROOT_ID);
            assert_eq!(prepared.mode() & 0o7777, 0o600);
            assert!(!destination.exists());
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn backup_transaction_reuses_private_stage_after_real_no_clobber_collision() {
            use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

            const NON_ROOT_ID: u32 = 65_534;
            const OCCUPIED_BYTES: &[u8] = b"preexisting-backup";
            let directory = retained_atomic_test_directory("backup-collision-ownership");
            let _initial_snapshot = atomic_template_snapshot(&directory, b"original", 0o640);
            let config_path = directory.join("template.json");
            let config_file = File::open(&config_path).expect("open config fixture");
            let cross_owner = rustix::process::geteuid().as_raw() == 0
                && assign_test_ownership(&config_file, NON_ROOT_ID, NON_ROOT_ID);
            config_file.sync_all().expect("sync config ownership");
            let original = read_destination_snapshot(
                &config_path,
                "backup collision config fixture",
                CONFIG_INPUT_MAX_BYTES,
            )
            .expect("read config fixture");
            let snapshot = original
                .existing()
                .expect("config fixture unexpectedly missing");
            if cross_owner {
                assert_eq!(snapshot.metadata.owner, NON_ROOT_ID);
                assert_eq!(snapshot.metadata.group, NON_ROOT_ID);
            }
            let parent = SecuredParentDirectory::open(
                &directory,
                &config_path,
                "backup collision ownership test",
            )
            .expect("secure backup test parent");
            let occupied_path = backup_path_for_version(&config_path, 0);
            let next_path = backup_path_for_version(&config_path, 1);
            let mut collision_created = false;
            let (parent, committed_backup) = create_backup_if_exists_with_hook(
                parent,
                config_path.file_name().expect("config name"),
                &config_path,
                &original,
                |version, attempted_path, staged| {
                    let staged_metadata = staged
                        .as_file()
                        .metadata()
                        .expect("inspect reusable backup stage");
                    assert_eq!(staged_metadata.mode() & 0o7777, 0o600);
                    assert_eq!(staged_metadata.uid(), snapshot.metadata.owner);
                    assert_eq!(staged_metadata.gid(), snapshot.metadata.group);
                    if version == 0 {
                        assert_eq!(attempted_path, occupied_path);
                        let mut occupied = std::fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .mode(0o600)
                            .open(attempted_path)
                            .expect("create colliding first backup name");
                        occupied
                            .write_all(OCCUPIED_BYTES)
                            .expect("write colliding backup fixture");
                        occupied.sync_all().expect("sync colliding backup fixture");
                        collision_created = true;
                    } else {
                        assert_eq!(version, 1);
                        assert!(collision_created);
                        assert_eq!(attempted_path, next_path);
                        let mut reader = staged.as_file().try_clone().expect("clone reused stage");
                        reader.rewind().expect("rewind reused stage");
                        let mut bytes = Vec::new();
                        reader
                            .read_to_end(&mut bytes)
                            .expect("read reused backup stage");
                        assert_eq!(bytes, snapshot.bytes);
                    }
                    Ok(())
                },
            )
            .expect("real backup transaction retries after no-clobber collision");
            assert_eq!(committed_backup.as_deref(), Some(next_path.as_path()));
            assert_eq!(
                std::fs::read(&occupied_path).expect("read occupied backup"),
                OCCUPIED_BYTES
            );
            assert_eq!(
                std::fs::read(&next_path).expect("read committed retry backup"),
                snapshot.bytes
            );
            assert_eq!(
                std::fs::read(&config_path).expect("read unchanged source config"),
                snapshot.bytes
            );
            let final_metadata = next_path.metadata().expect("final backup metadata");
            assert_eq!(final_metadata.uid(), snapshot.metadata.owner);
            assert_eq!(final_metadata.gid(), snapshot.metadata.group);
            assert_eq!(
                final_metadata.mode() & 0o7777,
                snapshot.metadata.mode & 0o7777
            );
            parent.sync().expect("sync retained backup fixture parent");
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn finalizer_rejects_same_length_content_corruption() {
            use std::os::unix::fs::MetadataExt as _;

            let directory = retained_atomic_test_directory("content-corruption");
            let snapshot = atomic_template_snapshot(&directory, b"template", 0o640);
            let destination = directory.join("corrupted.json");
            let parent =
                SecuredParentDirectory::open(&directory, &destination, "atomic corruption test")
                    .expect("secure test parent");
            let expected = b"expected-content";
            let mut staged = create_retained_same_directory_temp(
                &parent,
                Some(&snapshot),
                &destination,
                "atomic corruption test",
                "test",
            )
            .expect("create test stage");
            stage_retained_contents(
                &parent,
                &mut staged,
                expected,
                &destination,
                "atomic corruption test",
            )
            .expect("stage test contents");
            prepare_staged_for_publication(
                &parent,
                &staged,
                expected,
                Some(&snapshot),
                &destination,
                "atomic corruption test",
            )
            .expect("prepare test stage");
            let durability_proof = publish_test_stage(&parent, &staged, &destination);

            let error = finalize_published_file_metadata_with_hooks(
                &parent,
                durability_proof,
                &staged,
                destination.file_name().expect("test destination name"),
                expected,
                Some(&snapshot),
                &destination,
                "atomic corruption test",
                |_| Ok(()),
                |published| {
                    let mut corrupter = published.as_file().try_clone().expect("clone test stage");
                    corrupter.rewind().expect("rewind test stage");
                    corrupter.write_all(b"X").expect("corrupt one byte");
                    corrupter.sync_all().expect("sync corruption");
                    Ok(())
                },
            )
            .expect_err("same-length corruption must be detected");
            assert!(
                error
                    .message
                    .contains("contents changed during metadata finalization")
            );
            assert_eq!(
                staged
                    .as_file()
                    .metadata()
                    .expect("corrupt metadata")
                    .mode()
                    & 0o7777,
                0o640
            );
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn finalizer_refuses_to_widen_inode_moved_after_private_verification() {
            use std::os::unix::fs::MetadataExt as _;

            let directory = retained_atomic_test_directory("pre-chmod-move");
            let snapshot = atomic_template_snapshot(&directory, b"template", 0o640);
            let destination = directory.join("moved-before-chmod.json");
            let destination_name = destination.file_name().expect("test destination name");
            let parent = SecuredParentDirectory::open(
                &directory,
                &destination,
                "atomic pre-chmod move test",
            )
            .expect("secure test parent");
            let expected = b"private-before-chmod";
            let mut staged = create_retained_same_directory_temp(
                &parent,
                Some(&snapshot),
                &destination,
                "atomic pre-chmod move test",
                "test",
            )
            .expect("create test stage");
            stage_retained_contents(
                &parent,
                &mut staged,
                expected,
                &destination,
                "atomic pre-chmod move test",
            )
            .expect("stage test contents");
            prepare_staged_for_publication(
                &parent,
                &staged,
                expected,
                Some(&snapshot),
                &destination,
                "atomic pre-chmod move test",
            )
            .expect("prepare test stage");
            let durability_proof = publish_test_stage(&parent, &staged, &destination);

            let error = finalize_published_file_metadata_with_hooks(
                &parent,
                durability_proof,
                &staged,
                destination_name,
                expected,
                Some(&snapshot),
                &destination,
                "atomic pre-chmod move test",
                |published| {
                    rustix::fs::renameat(
                        &parent.handle,
                        destination_name,
                        &parent.handle,
                        published.relative_name(),
                    )
                    .expect("move published candidate back to its staging name");
                    Ok(())
                },
                |_| panic!("permission change hook must not run after the binding moved"),
            )
            .expect_err("a moved binding must stop permission widening");
            assert!(
                error
                    .message
                    .contains("identity was Staged immediately before permission finalization")
            );
            assert!(!destination.exists());
            assert!(
                descriptor_name_matches_staged_file(&parent, &staged, staged.relative_name())
                    .expect("retained stage identity")
            );
            assert_eq!(
                staged
                    .as_file()
                    .metadata()
                    .expect("retained metadata")
                    .mode()
                    & 0o7777,
                0o600
            );
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn finalizer_rejects_published_aba_after_parent_stamp_changes() {
            use std::os::unix::fs::MetadataExt as _;

            let directory = retained_atomic_test_directory("pre-chmod-aba");
            let snapshot = atomic_template_snapshot(&directory, b"template", 0o640);
            let destination = directory.join("aba-before-chmod.json");
            let destination_name = destination.file_name().expect("test destination name");
            let parent = SecuredParentDirectory::open(&directory, &destination, "atomic ABA test")
                .expect("secure ABA test parent");
            let expected = b"private-through-aba";
            let mut staged = create_retained_same_directory_temp(
                &parent,
                Some(&snapshot),
                &destination,
                "atomic ABA test",
                "test",
            )
            .expect("create ABA test stage");
            stage_retained_contents(
                &parent,
                &mut staged,
                expected,
                &destination,
                "atomic ABA test",
            )
            .expect("stage ABA test contents");
            prepare_staged_for_publication(
                &parent,
                &staged,
                expected,
                Some(&snapshot),
                &destination,
                "atomic ABA test",
            )
            .expect("prepare ABA test stage");
            let durability_proof = publish_test_stage(&parent, &staged, &destination);

            let error = finalize_published_file_metadata_with_hooks(
                &parent,
                durability_proof,
                &staged,
                destination_name,
                expected,
                Some(&snapshot),
                &destination,
                "atomic ABA test",
                |published| {
                    // Retain a directory marker so the parent stamp changes
                    // deterministically even on coarse-timestamp filesystems.
                    rustix::fs::mkdirat(
                        &parent.handle,
                        ".fastmcp-retained-aba-marker",
                        rustix::fs::Mode::RWXU,
                    )
                    .expect("create retained ABA marker directory");
                    rustix::fs::renameat(
                        &parent.handle,
                        destination_name,
                        &parent.handle,
                        published.relative_name(),
                    )
                    .expect("move published ABA candidate away");
                    rustix::fs::renameat(
                        &parent.handle,
                        published.relative_name(),
                        &parent.handle,
                        destination_name,
                    )
                    .expect("move published ABA candidate back");
                    Ok(())
                },
                |_| panic!("permission change hook must not run after parent-stamp ABA"),
            )
            .expect_err("a stale parent mutation stamp must stop permission widening");
            assert!(error.message.contains("one-shot durability proof"));
            assert!(destination.exists());
            assert_eq!(
                staged
                    .as_file()
                    .metadata()
                    .expect("ABA candidate metadata")
                    .mode()
                    & 0o7777,
                0o600
            );
            parent.sync().expect("sync retained ABA fixtures");
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn finalizer_reports_binding_loss_after_permissions_were_applied() {
            use std::os::unix::fs::MetadataExt as _;

            let directory = retained_atomic_test_directory("post-chmod-move");
            let snapshot = atomic_template_snapshot(&directory, b"template", 0o640);
            let destination = directory.join("moved-after-chmod.json");
            let destination_name = destination.file_name().expect("test destination name");
            let parent = SecuredParentDirectory::open(
                &directory,
                &destination,
                "atomic post-chmod move test",
            )
            .expect("secure post-chmod test parent");
            let expected = b"finalized-before-move";
            let mut staged = create_retained_same_directory_temp(
                &parent,
                Some(&snapshot),
                &destination,
                "atomic post-chmod move test",
                "test",
            )
            .expect("create post-chmod test stage");
            stage_retained_contents(
                &parent,
                &mut staged,
                expected,
                &destination,
                "atomic post-chmod move test",
            )
            .expect("stage post-chmod test contents");
            prepare_staged_for_publication(
                &parent,
                &staged,
                expected,
                Some(&snapshot),
                &destination,
                "atomic post-chmod move test",
            )
            .expect("prepare post-chmod test stage");
            let durability_proof = publish_test_stage(&parent, &staged, &destination);

            let error = finalize_published_file_metadata_with_hooks(
                &parent,
                durability_proof,
                &staged,
                destination_name,
                expected,
                Some(&snapshot),
                &destination,
                "atomic post-chmod move test",
                |_| Ok(()),
                |published| {
                    rustix::fs::mkdirat(
                        &parent.handle,
                        ".fastmcp-retained-post-chmod-marker",
                        rustix::fs::Mode::RWXU,
                    )
                    .expect("create retained post-chmod marker directory");
                    rustix::fs::renameat(
                        &parent.handle,
                        destination_name,
                        &parent.handle,
                        published.relative_name(),
                    )
                    .expect("move finalized inode back to retained staging name");
                    Ok(())
                },
            )
            .expect_err("post-chmod binding loss must fail final proof revalidation");
            assert!(
                error
                    .message
                    .contains("Final permissions may already be visible")
            );
            assert!(!destination.exists());
            assert!(
                descriptor_name_matches_staged_file(&parent, &staged, staged.relative_name())
                    .expect("post-chmod retained identity")
            );
            assert_eq!(
                staged
                    .as_file()
                    .metadata()
                    .expect("post-chmod retained metadata")
                    .mode()
                    & 0o7777,
                0o640
            );
            parent.sync().expect("sync retained post-chmod fixture");
        }

        #[test]
        fn test_get_claude_desktop_config_path_format() {
            // This test verifies the path format is correct
            // We can't test the actual path without mocking HOME
            let result = get_claude_desktop_config_path();
            if let Ok(path) = result {
                assert!(path.ends_with("claude_desktop_config.json"));
            }
            // If HOME is not set, result will be Err, which is also valid
        }

        #[test]
        fn test_get_cursor_config_path_format() {
            let result = get_cursor_config_path();
            if let Ok(path) = result {
                assert!(path.ends_with(Path::new(".cursor").join("mcp.json")));
            }
        }

        #[test]
        fn test_get_cline_config_path_format() {
            let path = resolve_cline_config_path(
                None,
                None,
                None,
                Some(std::ffi::OsString::from("/home/test")),
                None,
                None,
                None,
            )
            .expect("default Cline config path");
            assert_eq!(
                path,
                Path::new("/home/test/.cline/data/settings/cline_mcp_settings.json")
            );
        }

        #[test]
        fn cline_config_path_resolver_honors_precedence_and_empty_values() {
            use std::ffi::OsString;

            let resolved = resolve_cline_config_path(
                Some(OsString::from("  /direct/cline.json  ")),
                Some(OsString::from("/data-root")),
                Some(OsString::from("/cline-root")),
                Some(OsString::from("/home/user")),
                None,
                None,
                None,
            )
            .expect("direct settings override");
            assert_eq!(resolved, Path::new("/direct/cline.json"));

            let data_dir = resolve_cline_config_path(
                Some(OsString::from("  ")),
                Some(OsString::from("/data-root")),
                Some(OsString::from("/cline-root")),
                Some(OsString::from("/home/user")),
                None,
                None,
                None,
            )
            .expect("data-directory override");
            assert_eq!(
                data_dir,
                Path::new("/data-root/settings/cline_mcp_settings.json")
            );

            let cline_dir = resolve_cline_config_path(
                None,
                Some(OsString::new()),
                Some(OsString::from("/cline-root")),
                Some(OsString::from("/home/user")),
                None,
                None,
                None,
            )
            .expect("Cline-directory override");
            assert_eq!(
                cline_dir,
                Path::new("/cline-root/data/settings/cline_mcp_settings.json")
            );

            let home = resolve_cline_config_path(
                None,
                None,
                None,
                Some(OsString::from("~")),
                Some(OsString::from("/profile/user")),
                None,
                None,
            )
            .expect("user-profile fallback");
            assert_eq!(
                home,
                Path::new("/profile/user/.cline/data/settings/cline_mcp_settings.json")
            );

            let drive_home = resolve_cline_config_path(
                None,
                None,
                None,
                None,
                None,
                Some(OsString::from("C:")),
                Some(OsString::from("\\Users\\test")),
            )
            .expect("drive-and-home-path fallback");
            assert!(
                drive_home
                    .as_os_str()
                    .to_string_lossy()
                    .ends_with("C:\\Users\\test/.cline/data/settings/cline_mcp_settings.json")
            );

            assert!(resolve_cline_config_path(None, None, None, None, None, None, None).is_err());
        }

        #[cfg(unix)]
        #[test]
        fn backup_path_preserves_non_utf8_config_paths() {
            use std::ffi::OsString;
            use std::os::unix::ffi::{OsStrExt, OsStringExt};

            let config_path = PathBuf::from(OsString::from_vec(
                b"/tmp/fastmcp-config-\xff.json".to_vec(),
            ));
            let backup_path = backup_path_for(&config_path);
            let mut expected = config_path.as_os_str().as_bytes().to_vec();
            expected.extend_from_slice(b".bak");

            assert_eq!(backup_path.as_os_str().as_bytes(), expected);
        }

        #[test]
        fn backup_versions_never_reuse_the_primary_backup_name() {
            let path = Path::new("config.json");
            assert_eq!(
                backup_path_for_version(path, 0),
                Path::new("config.json.bak")
            );
            assert_eq!(
                backup_path_for_version(path, 1),
                Path::new("config.json.bak.1")
            );
            assert_eq!(
                backup_path_for_version(path, 17),
                Path::new("config.json.bak.17")
            );
        }

        #[test]
        fn atomic_output_rejects_oversized_content_before_touching_the_path() {
            let oversized = vec![b'x'; 17];
            let error = atomic_replace_file(
                Path::new("this-path-must-not-be-created"),
                &oversized,
                "test output",
                16,
            )
            .expect_err("oversized output must be rejected");

            assert!(error.message.contains("maximum 16"));
        }

        #[cfg(unix)]
        #[test]
        fn atomic_output_reserves_internal_staging_namespace() {
            let error = validate_atomic_destination_name(
                Path::new(".fastmcp-stage-operator-selected"),
                "test output",
            )
            .expect_err("operator destinations must not alias the staging namespace");

            assert!(error.message.contains("reserved .fastmcp-stage- prefix"));
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn atomic_output_rejects_trailing_separator_without_creating_normalized_target() {
            let directory = retained_atomic_test_directory("trailing-separator");
            let normalized_target = directory.join("must-not-be-created");
            let mut raw_target = normalized_target.as_os_str().to_os_string();
            raw_target.push("/");

            let error = atomic_replace_file(
                &PathBuf::from(raw_target),
                b"not written",
                "trailing separator test",
                CONFIG_OUTPUT_MAX_BYTES,
            )
            .expect_err("a raw trailing separator must be rejected");
            assert!(error.message.contains("trailing separators"));
            assert!(!normalized_target.exists());
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn atomic_output_rejects_terminal_dot_components_without_creating_parents() {
            let directory = retained_atomic_test_directory("terminal-dot-components");
            let dot_target = directory.join("dot-target");
            let mut raw_dot = dot_target.as_os_str().to_os_string();
            raw_dot.push("/.");
            let dot_error = atomic_replace_file(
                &PathBuf::from(raw_dot),
                b"not written",
                "terminal dot test",
                CONFIG_OUTPUT_MAX_BYTES,
            )
            .expect_err("a terminal dot component must be rejected");
            assert!(dot_error.message.contains("terminal . or .."));
            assert!(!dot_target.exists());

            let dotdot_parent = directory.join("dotdot-parent");
            let mut raw_dotdot = dotdot_parent.as_os_str().to_os_string();
            raw_dotdot.push("/..");
            let dotdot_error = atomic_replace_file(
                &PathBuf::from(raw_dotdot),
                b"not written",
                "terminal dotdot test",
                CONFIG_OUTPUT_MAX_BYTES,
            )
            .expect_err("a terminal dotdot component must be rejected");
            assert!(dotdot_error.message.contains("terminal . or .."));
            assert!(!dotdot_parent.exists());
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn atomic_output_rejects_intermediate_parent_traversal_before_creation() {
            let directory = retained_atomic_test_directory("intermediate-parent-traversal");
            let missing_component = directory.join("must-not-be-created");
            let target = missing_component.join("..").join("normalized-target.json");

            let error = atomic_replace_file(
                &target,
                b"not written",
                "intermediate traversal test",
                CONFIG_OUTPUT_MAX_BYTES,
            )
            .expect_err("intermediate parent traversal must be rejected");
            assert!(error.message.contains("traversal components"));
            assert!(!missing_component.exists());
            assert!(!directory.join("normalized-target.json").exists());
        }

        #[test]
        fn bounded_config_reader_rejects_a_directory_before_opening_it_as_input() {
            let error = read_bounded_config(Path::new("."), "test")
                .expect_err("directories are not config inputs");

            assert!(error.message.contains("regular file"));
        }

        #[test]
        fn prepared_install_output_is_capped_before_any_transaction_starts() {
            let value = serde_json::json!({
                "mcpServers": {
                    "oversized": {
                        "command": "x".repeat(CONFIG_OUTPUT_MAX_BYTES)
                    }
                }
            });
            let error = prepare_json_config(&value).expect_err("oversized output must fail");

            assert!(error.message.contains("maximum"));
        }
    }

    // ============================================================================
    // Error Case Tests
    // ============================================================================

    mod error_cases {
        use super::*;

        #[test]
        fn test_cli_missing_subcommand() {
            let result = Cli::try_parse_from(["fastmcp"]);
            assert!(result.is_err());
        }

        #[test]
        fn test_cli_invalid_subcommand() {
            let result = Cli::try_parse_from(["fastmcp", "invalid"]);
            assert!(result.is_err());
        }

        #[test]
        fn test_run_missing_server() {
            let result = Cli::try_parse_from(["fastmcp", "run"]);
            assert!(result.is_err());
        }

        #[test]
        fn test_inspect_invalid_format() {
            let result = Cli::try_parse_from(["fastmcp", "inspect", "-f", "invalid", "./server"]);
            assert!(result.is_err());
        }

        #[test]
        fn test_install_missing_name() {
            let result = Cli::try_parse_from(["fastmcp", "install", "./server"]);
            assert!(result.is_err());
        }

        #[test]
        fn test_dev_missing_target() {
            let result = Cli::try_parse_from(["fastmcp", "dev"]);
            assert!(result.is_err());
        }

        #[test]
        fn test_invalid_timeout_values() {
            for option in ["--idle-timeout", "--absolute-timeout"] {
                let result =
                    Cli::try_parse_from(["fastmcp", "test", option, "not-a-number", "./server"]);
                assert!(result.is_err(), "{option} must reject non-numeric input");
            }
        }

        #[test]
        fn test_idle_timeout_seconds_enforces_documented_boundaries() {
            for invalid in ["0", "301"] {
                let result =
                    Cli::try_parse_from(["fastmcp", "test", "--idle-timeout", invalid, "./server"]);
                assert!(result.is_err(), "idle timeout {invalid} must be rejected");
            }

            for (valid, expected) in [("1", 1), ("300", 300)] {
                let cli =
                    Cli::try_parse_from(["fastmcp", "test", "--idle-timeout", valid, "./server"])
                        .expect("idle timeout boundary must be accepted");
                let Commands::Test { idle_timeout, .. } = cli.command else {
                    panic!("expected test command");
                };
                assert_eq!(idle_timeout, expected);
            }
        }

        #[test]
        fn test_absolute_timeout_seconds_enforces_documented_boundaries() {
            for invalid in ["0", "901"] {
                let result = Cli::try_parse_from([
                    "fastmcp",
                    "test",
                    "--absolute-timeout",
                    invalid,
                    "./server",
                ]);
                assert!(
                    result.is_err(),
                    "absolute timeout {invalid} must be rejected"
                );
            }

            for (valid, expected) in [("1", 1), ("900", 900)] {
                let cli = Cli::try_parse_from([
                    "fastmcp",
                    "test",
                    "--absolute-timeout",
                    valid,
                    "./server",
                ])
                .expect("absolute timeout boundary must be accepted");
                let Commands::Test {
                    absolute_timeout, ..
                } = cli.command
                else {
                    panic!("expected test command");
                };
                assert_eq!(absolute_timeout, expected);
            }
        }

        #[test]
        fn test_removed_single_timeout_option_is_rejected() {
            let result = Cli::try_parse_from(["fastmcp", "test", "--timeout", "30", "./server"]);
            assert!(
                result.is_err(),
                "removed --timeout option must not be aliased"
            );
        }

        #[test]
        fn test_removed_dev_network_options_are_rejected() {
            for option in ["--host", "--port", "--transport"] {
                let result = Cli::try_parse_from(["fastmcp", "dev", option, "unused", "."]);
                assert!(result.is_err(), "removed option {option} must be rejected");
            }
        }
    }

    // ============================================================================
    // Integration-style Tests (without actual server)
    // ============================================================================

    mod integration {
        use super::*;

        #[test]
        fn parse_environment_assignments_is_strict_and_preserves_equals_in_values() {
            let parsed = parse_environment_assignments(&[
                "EMPTY=".to_owned(),
                "TOKEN=header.payload=signature".to_owned(),
            ])
            .unwrap();
            assert_eq!(parsed.get("EMPTY").map(String::as_str), Some(""));
            assert_eq!(
                parsed.get("TOKEN").map(String::as_str),
                Some("header.payload=signature")
            );

            assert!(parse_environment_assignments(&["MISSING_SEPARATOR".to_owned()]).is_err());
            assert!(parse_environment_assignments(&["=missing-name".to_owned()]).is_err());
        }

        #[test]
        fn malformed_environment_assignment_error_does_not_echo_the_candidate() {
            const SECRET: &str = "MALFORMED_ENV_SECRET_CANARY";
            let error = parse_environment_assignments(&[SECRET.to_owned()]).unwrap_err();

            assert_eq!(
                error.message,
                "Invalid environment assignment at position 0; expected KEY=VALUE"
            );
            assert!(!error.message.contains(SECRET));
        }

        #[test]
        fn dev_reload_wakeup_is_capacity_one_and_tracks_the_latest_change() {
            use std::sync::atomic::Ordering;
            use std::sync::mpsc::TryRecvError;
            use std::time::{Duration, Instant};

            let wake = DevReloadWake::new();
            let (sender, receiver) = std::sync::mpsc::sync_channel(1);
            coalesce_dev_reload_wakeup(&wake, &sender, Instant::now() - Duration::from_secs(120));
            // This event refreshes the quiet-period timestamp but does not
            // enqueue a second wake while the state is already pending.
            coalesce_dev_reload_wakeup(&wake, &sender, Instant::now());

            assert_eq!(receiver.try_recv(), Ok(()));
            assert_eq!(receiver.try_recv(), Err(TryRecvError::Empty));
            assert!(wake.pending.load(Ordering::Acquire));
            assert!(!take_due_dev_reload(&wake, Duration::from_secs(60)));

            *wake
                .last_change
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                Some(Instant::now() - Duration::from_secs(120));
            assert!(take_due_dev_reload(&wake, Duration::from_secs(60)));
            assert!(!wake.pending.load(Ordering::Acquire));

            coalesce_dev_reload_wakeup(&wake, &sender, Instant::now());
            assert_eq!(receiver.try_recv(), Ok(()));
        }

        #[test]
        fn dev_watcher_errors_are_bounded_preserved_and_wake_a_full_queue() {
            use std::sync::mpsc::TryRecvError;

            let wake = DevReloadWake::new();
            let (sender, receiver) = std::sync::mpsc::sync_channel(1);
            sender.send(()).unwrap();
            let raw_error = format!("watch\n\u{1b}[31m{}", "x".repeat(TERMINAL_TEXT_LIMIT * 2));
            record_dev_watcher_error(&wake, &sender, &notify::Error::generic(&raw_error));

            assert_eq!(receiver.try_recv(), Ok(()));
            assert_eq!(receiver.try_recv(), Err(TryRecvError::Empty));
            let error = take_dev_watcher_error(&wake).expect("watcher error should be retained");
            assert!(error.is_ascii());
            assert!(!error.contains('\n'));
            assert!(!error.contains('\u{1b}'));
            assert!(error.len() <= TERMINAL_TEXT_LIMIT);
            assert!(error.ends_with("...[truncated]"));
            assert!(take_dev_watcher_error(&wake).is_none());
        }

        #[test]
        fn bounded_dev_capture_discards_excess_without_stopping_the_drain() {
            use asupersync::io::{AsyncRead, ReadBuf};
            use std::pin::Pin;
            use std::task::{Context, Poll};

            struct FixedReader {
                remaining: usize,
            }

            impl AsyncRead for FixedReader {
                fn poll_read(
                    mut self: Pin<&mut Self>,
                    _context: &mut Context<'_>,
                    buffer: &mut ReadBuf<'_>,
                ) -> Poll<io::Result<()>> {
                    let count = self.remaining.min(buffer.remaining());
                    buffer.unfilled()[..count].fill(b'x');
                    buffer.advance(count);
                    self.remaining -= count;
                    Poll::Ready(Ok(()))
                }
            }

            let mut reader = Some(FixedReader {
                remaining: DEV_BUILD_CAPTURE_LIMIT + 32 * 1024,
            });
            let mut capture = BoundedDevCapture::default();
            while !capture.eof {
                poll_bounded_dev_capture(&mut reader, &mut capture).unwrap();
            }

            assert_eq!(capture.bytes.len(), DEV_BUILD_CAPTURE_LIMIT);
            assert!(capture.truncated);
            assert!(reader.is_none());
        }

        #[test]
        fn dev_diagnostics_are_secret_safe_control_safe_and_bounded() {
            const SECRET: &str = "DEV_DIAGNOSTIC_SECRET_CANARY";
            let environment = HashMap::from([("TOKEN".to_owned(), SECRET.to_owned())]);
            let mut diagnostics = b"\x1b[31m".to_vec();
            diagnostics.extend_from_slice(SECRET.as_bytes());
            diagnostics.extend(std::iter::repeat_n(b'x', DEV_BUILD_RENDER_LIMIT * 2));

            let rendered = redacted_dev_text(&diagnostics, &environment, false);
            assert!(rendered.len() <= DEV_BUILD_RENDER_LIMIT);
            assert!(!rendered.contains(SECRET));
            assert!(!rendered.contains('\u{1b}'));
            assert!(rendered.starts_with("\\x1B[31m<redacted>"));

            let partial =
                redacted_dev_text(&SECRET.as_bytes()[..SECRET.len() - 3], &environment, true);
            assert_eq!(partial, REDACTED_ENV_VALUE);
        }

        #[test]
        fn dev_diagnostics_mask_a_multibyte_secret_cut_inside_a_codepoint() {
            let secret = "PREFIX-é-secret";
            let environment = HashMap::from([("TOKEN".to_owned(), secret.to_owned())]);
            let split = secret.find('é').unwrap() + 1;

            let rendered = redacted_dev_text(&secret.as_bytes()[..split], &environment, true);

            assert_eq!(rendered, REDACTED_ENV_VALUE);
            assert!(!rendered.contains("PREFIX"));
        }

        #[test]
        fn dev_diagnostics_fail_closed_when_a_marker_would_echo_a_secret() {
            let environment = HashMap::from([
                ("ANGLE".to_owned(), "<".to_owned()),
                ("MARKER_WORD".to_owned(), "redacted".to_owned()),
                ("LETTER".to_owned(), "x".to_owned()),
            ]);

            assert_eq!(redacted_dev_text(b"<xxx", &environment, false), "");
        }

        #[test]
        fn dev_diagnostic_matching_suppresses_output_when_work_budget_is_exhausted() {
            let environment = HashMap::from([("TOKEN".to_owned(), "aaaaaaaa".to_owned())]);

            let rendered = redacted_dev_text_with_budget(b"aaaaaaab", &environment, false, 4);

            assert_eq!(rendered, "");
        }

        #[test]
        fn dev_diagnostics_fail_closed_on_synthesized_secret_text() {
            let escaped = HashMap::from([("TOKEN".to_owned(), "x1B".to_owned())]);
            assert_eq!(redacted_dev_text(b"\x1b", &escaped, false), "");

            let joined = HashMap::from([
                ("INNER".to_owned(), "X".to_owned()),
                ("SYNTHESIZED".to_owned(), "a<redacted>b".to_owned()),
            ]);
            assert_eq!(redacted_dev_text(b"aXb", &joined, false), "");
        }

        #[test]
        fn dev_diagnostics_escape_bidi_and_all_other_non_ascii_bytes() {
            let rendered = redacted_dev_text("safe\u{202e}txt".as_bytes(), &HashMap::new(), false);

            assert_eq!(rendered, "safe\\xE2\\x80\\xAEtxt");
            assert!(!rendered.contains('\u{202e}'));
        }

        #[cfg(unix)]
        #[test]
        fn owned_dev_child_drop_guard_cleans_a_still_live_group() {
            let mut command = owned_dev_command(
                "/bin/sh",
                &["-c".to_owned(), "trap '' HUP INT TERM; sleep 5".to_owned()],
            );
            command
                .stdin(asupersync::process::Stdio::Pipe)
                .stdout(asupersync::process::Stdio::Null)
                .stderr(asupersync::process::Stdio::Null);
            let child = command.spawn().expect("spawn guarded development child");
            let process_group_id = child
                .process_group_id()
                .expect("owned child must have a managed process group");
            assert!(
                kernel_process_group_exists(process_group_id)
                    .expect("observe live managed process group")
            );

            drop(child);

            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            loop {
                #[cfg(target_os = "linux")]
                let group_has_live_member =
                    linux_process_group_has_live_member(process_group_id, deadline)
                        .expect("inspect managed process-group cleanup");
                #[cfg(not(target_os = "linux"))]
                let group_has_live_member =
                    non_linux_process_group_has_live_member(process_group_id)
                        .expect("observe managed process-group cleanup");

                if !group_has_live_member {
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "armed child drop guard left the managed process group live"
                );
                std::thread::sleep(DEV_PROCESS_POLL_INTERVAL);
            }
        }

        #[cfg(unix)]
        #[test]
        fn reality_check_regression_dev_watchdog_preserves_private_stdin_pipe() {
            let mut command = owned_dev_command("/bin/sh", &["-c".to_owned(), "exit 0".to_owned()]);
            command
                .stdout(asupersync::process::Stdio::Null)
                .stderr(asupersync::process::Stdio::Null);
            let mut child = command
                .spawn()
                .expect("spawn development watchdog readiness fixture");
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);

            let status = loop {
                match child.try_wait() {
                    Ok(Some(status)) => break status,
                    Ok(None) if std::time::Instant::now() < deadline => {
                        std::thread::sleep(DEV_PROCESS_POLL_INTERVAL);
                    }
                    Ok(None) => {
                        drop(child);
                        panic!("development wrapper did not start and reap its managed command");
                    }
                    Err(error) => {
                        drop(child);
                        panic!("development wrapper readiness observation failed: {error}");
                    }
                }
            };

            assert!(
                status.success(),
                "the watchdog must not observe synthetic /dev/null EOF before owner cleanup"
            );
            wait_for_owned_dev_group_cleanup(&mut child)
                .expect("release and reap the successful development watchdog");
        }

        #[cfg(unix)]
        #[test]
        fn reality_check_regression_dev_error_cleanup_stops_owned_child() {
            let mut command = owned_dev_command(
                "/bin/sh",
                &["-c".to_owned(), "trap '' HUP INT TERM; sleep 5".to_owned()],
            );
            command
                .stdin(asupersync::process::Stdio::Pipe)
                .stdout(asupersync::process::Stdio::Null)
                .stderr(asupersync::process::Stdio::Null);
            let child = command.spawn().expect("spawn managed development child");
            let process_group_id = child
                .process_group_id()
                .expect("owned child must have a managed process group");
            let mut child = Some(child);

            let error = return_dev_error_with_cleanup(
                &mut child,
                fastmcp_core::McpError::internal_error("forced terminal operation failure"),
            )
            .expect_err("the original terminal error must be preserved");

            assert!(child.is_none(), "cleanup must consume the owned child");
            assert!(error.message.contains("forced terminal operation failure"));
            #[cfg(target_os = "linux")]
            assert!(
                !linux_process_group_has_live_member(
                    process_group_id,
                    std::time::Instant::now() + DEV_GROUP_INSPECTION_TIMEOUT,
                )
                .expect("inspect explicitly cleaned process group")
            );
            #[cfg(not(target_os = "linux"))]
            assert!(
                !non_linux_process_group_has_live_member(process_group_id)
                    .expect("observe explicitly cleaned process group")
            );
        }

        #[test]
        fn skipped_test_is_successful_but_explicitly_marked() {
            let result = skipped_test("list_tools", "not advertised");
            assert!(result.success);
            assert!(result.skipped);
            assert_eq!(result.details.as_deref(), Some("not advertised"));

            let json = serde_json::to_value(result).unwrap();
            assert_eq!(
                json.get("skipped").and_then(serde_json::Value::as_bool),
                Some(true)
            );
        }

        #[test]
        fn test_run_test_helper() {
            // Test the run_test helper function with a successful closure
            let result = run_test("test_success", || Ok("details".to_string()));

            assert!(result.success);
            assert_eq!(result.name, "test_success");
            assert_eq!(result.details, Some("details".to_string()));
            assert!(result.error.is_none());
            assert!(result.duration_ms >= 0.0);
        }

        #[test]
        fn test_run_test_helper_failure() {
            // Test the run_test helper function with a failing closure
            let result = run_test("test_failure", || {
                Err(fastmcp_core::McpError::internal_error("test error"))
            });

            assert!(!result.success);
            assert_eq!(result.name, "test_failure");
            assert!(result.details.is_none());
            assert!(result.error.is_some());
            assert!(result.error.unwrap().contains("test error"));
        }

        #[test]
        fn run_test_bounds_and_redacts_raw_error_text_at_capture_time() {
            const SECRET: &str = "RUN-TEST-SECRET";
            let result = run_test("failure", || {
                Err(fastmcp_core::McpError::internal_error(format!(
                    "Authorization: Bearer {SECRET}{}",
                    "x".repeat(PEER_DETAIL_LIMIT * 8)
                )))
            });
            let error = result.error.expect("captured error");

            assert!(error.len() <= PEER_DETAIL_LIMIT);
            assert!(error.contains(REDACTED_ENV_VALUE));
            assert!(!error.contains(SECRET));
        }

        #[test]
        fn test_run_test_helper_empty_details() {
            // Test that empty details are converted to None
            let result = run_test("test_empty", || Ok(String::new()));

            assert!(result.success);
            assert!(result.details.is_none());
        }
    }
}
