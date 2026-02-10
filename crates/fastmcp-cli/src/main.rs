//! FastMCP CLI - Command-line tooling for MCP servers.
//!
//! Commands:
//! - `run` - Run an MCP server
//! - `inspect` - Inspect a server's capabilities
//! - `install` - Install server config for Claude Desktop etc.
//! - `tasks` - Manage background tasks on MCP servers
//!
//! # Role in the System
//!
//! `fastmcp-cli` is the **operator tooling layer** for FastMCP. It wraps the
//! client and transport crates to provide day-to-day workflows:
//! - Running local servers with stdio transport
//! - Inspecting tools/resources/prompts for debugging
//! - Installing client configs for Claude Desktop, Cursor, and Cline
//! - Managing background tasks exposed by MCP servers

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::env;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

use fastmcp_client::Client;
use fastmcp_console::rich_rust::prelude::*;
use fastmcp_core::McpResult;
use fastmcp_protocol::TaskStatus;

#[derive(Debug, Deserialize)]
struct CratesIoCrateResponse {
    #[serde(rename = "crate")]
    krate: CratesIoCrateInfo,
}

#[derive(Debug, Deserialize)]
struct CratesIoCrateInfo {
    max_version: String,
}

fn should_check_for_updates() -> bool {
    // Default to enabled; allow opt-out for offline/CI environments.
    let val = env::var("FASTMCP_CHECK_FOR_UPDATES").ok();
    !matches!(val.as_deref(), Some("0" | "false" | "FALSE" | "no" | "NO"))
}

fn fetch_latest_crate_version(crate_name: &str) -> Option<String> {
    let url = format!("https://crates.io/api/v1/crates/{crate_name}");
    let config = ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_millis(500)))
        .timeout_global(Some(Duration::from_millis(800)))
        .build();
    let agent: ureq::Agent = config.into();

    let mut resp = agent.get(&url).call().ok()?;
    let body = resp.body_mut().read_to_string().ok()?;
    let parsed: CratesIoCrateResponse = serde_json::from_str(&body).ok()?;
    Some(parsed.krate.max_version)
}

fn maybe_print_update_notice() {
    if !should_check_for_updates() {
        return;
    }
    if env::var("CI").is_ok() {
        return;
    }

    // Check only the CLI crate. If the user is on `cargo install fastmcp-cli`,
    // this produces actionable guidance.
    let current = semver::Version::parse(env!("CARGO_PKG_VERSION")).ok();
    let latest = fetch_latest_crate_version("fastmcp-cli")
        .and_then(|v| semver::Version::parse(&v).ok().map(|sv| (v, sv)));

    let (Some(current), Some((latest_str, latest))) = (current, latest) else {
        return;
    };

    if latest > current {
        eprintln!(
            "Update available: fastmcp-cli {} -> {}. Run: cargo install fastmcp-cli",
            current, latest_str
        );
    }
}

/// FastMCP CLI - Run, inspect, and install MCP servers.
#[derive(Parser)]
#[command(name = "fastmcp")]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
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
    },

    /// Inspect an MCP server's capabilities.
    ///
    /// Connects to the server, lists its tools, resources, and prompts,
    /// then displays them in a formatted output.
    Inspect {
        /// Server command or path.
        server: String,

        /// Arguments to pass to the server.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,

        /// Output format (text, json, mcp).
        #[arg(long, short = 'f', default_value = "text")]
        format: InspectFormat,

        /// Output file (default: stdout).
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,
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

        /// Target client (claude, cursor, cline).
        #[arg(long, short = 't', default_value = "claude")]
        target: InstallTarget,

        /// Just print the config, don't modify any files.
        #[arg(long)]
        dry_run: bool,
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

        /// Show full configuration details including environment variables.
        #[arg(long, short = 'v')]
        verbose: bool,
    },

    /// Test MCP server connectivity.
    ///
    /// Spawns the server and tests initialization, capability listing, and ping functionality.
    Test {
        /// Server command or path.
        server: String,

        /// Arguments to pass to the server.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,

        /// Request timeout in seconds.
        #[arg(long, default_value = "30")]
        timeout: u64,

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
    Dev {
        /// Path to server module, binary, or Cargo target.
        target: String,

        /// Host to bind (for SSE/HTTP transport).
        #[arg(long, default_value = "localhost")]
        host: String,

        /// Port to bind (for SSE/HTTP transport).
        #[arg(long, default_value = "8000")]
        port: u16,

        /// Directory to watch for changes (can specify multiple).
        #[arg(long = "reload-dir", default_value = "src")]
        reload_dirs: Vec<PathBuf>,

        /// File patterns to watch (glob syntax).
        #[arg(long = "reload-pattern", default_value = "**/*.rs")]
        reload_patterns: Vec<String>,

        /// Disable auto-reload (just run the server).
        #[arg(long)]
        no_reload: bool,

        /// Transport type: stdio, sse, http.
        #[arg(long, default_value = "stdio")]
        transport: DevTransport,

        /// Debounce time in milliseconds.
        #[arg(long, default_value = "100")]
        debounce: u64,

        /// Clear terminal on restart.
        #[arg(long)]
        clear: bool,

        /// Environment variables (KEY=VALUE format).
        #[arg(long, short = 'e')]
        env: Vec<String>,

        /// Show detailed output.
        #[arg(long, short = 'v')]
        verbose: bool,
    },

    /// Manage background tasks on an MCP server.
    ///
    /// Query task status, retry failed tasks, cancel pending tasks, and view queue statistics.
    ///
    /// Example: fastmcp tasks list ./my-server -- --config config.json
    Tasks {
        /// Task subcommand.
        #[command(subcommand)]
        action: TasksAction,
    },
}

/// Subcommands for task management.
#[derive(Subcommand)]
enum TasksAction {
    /// List tasks with optional status filter.
    ///
    /// Example: fastmcp tasks list ./my-server -- --config config.json
    List {
        /// Server command or path.
        server: String,

        /// Arguments to pass to the server (after --).
        #[arg(last = true)]
        args: Vec<String>,

        /// Filter by status (pending, running, completed, failed, cancelled).
        #[arg(long, short = 's')]
        status: Option<TaskStatusFilter>,

        /// Maximum number of tasks to show.
        #[arg(long, short = 'n', default_value = "20")]
        limit: usize,

        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Show details of a specific task.
    ///
    /// Example: fastmcp tasks show ./my-server task-00000001
    Show {
        /// Server command or path.
        server: String,

        /// Task ID.
        task_id: String,

        /// Arguments to pass to the server (after --).
        #[arg(last = true)]
        args: Vec<String>,

        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Cancel a pending or running task.
    ///
    /// Example: fastmcp tasks cancel ./my-server task-00000001 -r "no longer needed"
    Cancel {
        /// Server command or path.
        server: String,

        /// Task ID to cancel.
        task_id: String,

        /// Arguments to pass to the server (after --).
        #[arg(last = true)]
        args: Vec<String>,

        /// Reason for cancellation.
        #[arg(long, short = 'r')]
        reason: Option<String>,
    },

    /// Show task queue statistics.
    ///
    /// Example: fastmcp tasks stats ./my-server
    Stats {
        /// Server command or path.
        server: String,

        /// Arguments to pass to the server (after --).
        #[arg(last = true)]
        args: Vec<String>,

        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
}

/// Task status filter for CLI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TaskStatusFilter {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl std::str::FromStr for TaskStatusFilter {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(Self::Pending),
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "cancelled" | "canceled" => Ok(Self::Cancelled),
            _ => Err(format!(
                "Unknown status: {s}. Expected: pending, running, completed, failed, cancelled"
            )),
        }
    }
}

impl From<TaskStatusFilter> for TaskStatus {
    fn from(filter: TaskStatusFilter) -> Self {
        match filter {
            TaskStatusFilter::Pending => TaskStatus::Pending,
            TaskStatusFilter::Running => TaskStatus::Running,
            TaskStatusFilter::Completed => TaskStatus::Completed,
            TaskStatusFilter::Failed => TaskStatus::Failed,
            TaskStatusFilter::Cancelled => TaskStatus::Cancelled,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InspectFormat {
    Text,
    Json,
    Mcp,
}

impl std::str::FromStr for InspectFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            "mcp" => Ok(Self::Mcp),
            _ => Err(format!("Unknown format: {s}. Expected: text, json, mcp")),
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

/// Transport type for dev mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
enum DevTransport {
    #[default]
    Stdio,
    Sse,
    Http,
}

impl std::str::FromStr for DevTransport {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "stdio" => Ok(Self::Stdio),
            "sse" => Ok(Self::Sse),
            "http" => Ok(Self::Http),
            _ => Err(format!(
                "Unknown transport: {s}. Expected: stdio, sse, http"
            )),
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
    let cli = Cli::parse();
    maybe_print_update_notice();

    let result = match cli.command {
        Commands::Run {
            server,
            args,
            cwd,
            env,
        } => cmd_run(&server, &args, cwd.as_deref(), &env),
        Commands::Inspect {
            server,
            args,
            format,
            output,
        } => cmd_inspect(&server, &args, format, output.as_deref()),
        Commands::Install {
            name,
            server,
            args,
            target,
            dry_run,
        } => cmd_install(&name, &server, &args, target, dry_run),
        Commands::List {
            target,
            config,
            format,
            verbose,
        } => cmd_list(target, config, format, verbose),
        Commands::Test {
            server,
            args,
            timeout,
            verbose,
            json,
        } => cmd_test(&server, &args, timeout, verbose, json),
        Commands::Dev {
            target,
            host,
            port,
            reload_dirs,
            reload_patterns,
            no_reload,
            transport,
            debounce,
            clear,
            env,
            verbose,
        } => cmd_dev(DevConfig {
            target,
            host,
            port,
            reload_dirs,
            reload_patterns,
            no_reload,
            transport,
            debounce_ms: debounce,
            clear,
            env,
            verbose,
        }),
        Commands::Tasks { action } => cmd_tasks(action),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // `fastmcp run` should propagate the child process exit code.
            // We encode that in `McpError.data.exit_code` so the top-level can
            // return the right `ExitCode` without changing the command handler
            // signatures for the whole CLI.
            if let Some(code) = e
                .data
                .as_ref()
                .and_then(|data| data.get("exit_code"))
                .and_then(serde_json::Value::as_i64)
            {
                // Avoid duplicating the child's stderr with our own error line on
                // normal non-zero exits.
                if !e.message.starts_with("Server exited with code") {
                    eprintln!("Error: {e}");
                }
                return u8::try_from(code)
                    .map(ExitCode::from)
                    .unwrap_or(ExitCode::FAILURE);
            }

            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Run command: Execute an MCP server binary.
fn cmd_run(
    server: &str,
    args: &[String],
    cwd: Option<&std::path::Path>,
    env_vars: &[String],
) -> McpResult<()> {
    let mut cmd = Command::new(server);
    cmd.args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }

    // Parse and set environment variables
    for env_var in env_vars {
        if let Some((key, value)) = env_var.split_once('=') {
            cmd.env(key, value);
        } else {
            eprintln!("Warning: Invalid env var format (expected KEY=VALUE): {env_var}");
        }
    }

    let mut child = cmd.spawn().map_err(|e| {
        fastmcp_core::McpError::internal_error(format!("Failed to start server: {e}"))
    })?;

    let status = child.wait().map_err(|e| {
        fastmcp_core::McpError::internal_error(format!("Failed to wait for server: {e}"))
    })?;

    if !status.success() {
        if let Some(code) = status.code() {
            return Err(fastmcp_core::McpError::with_data(
                fastmcp_core::McpErrorCode::InternalError,
                format!("Server exited with code {code}"),
                serde_json::json!({ "exit_code": code }),
            ));
        }
        return Err(fastmcp_core::McpError::internal_error(
            "Server terminated by signal",
        ));
    }

    Ok(())
}

/// Server entry for list output.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServerEntry {
    name: String,
    source: String,
    command: String,
    args: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    env: Option<HashMap<String, String>>,
    enabled: bool,
}

/// List output for JSON/YAML serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ListOutput {
    servers: Vec<ServerEntry>,
}

/// List command: List configured MCP servers.
fn cmd_list(
    target: Option<InstallTarget>,
    config: Option<PathBuf>,
    format: ListFormat,
    verbose: bool,
) -> McpResult<()> {
    use fastmcp_console::rich_rust::r#box::ROUNDED;
    use fastmcp_console::rich_rust::style::Style;

    let mut servers: Vec<ServerEntry> = Vec::new();

    // If custom config path is provided, use only that
    if let Some(config_path) = config {
        load_servers_from_path(&config_path, "Custom", &mut servers)?;
    } else {
        // Load from standard targets
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
            let (name, config_path) = match t {
                InstallTarget::Claude => ("Claude", get_claude_desktop_config_path()),
                InstallTarget::Cursor => ("Cursor", get_cursor_config_path()),
                InstallTarget::Cline => ("Cline", get_cline_config_path()),
            };

            if let Ok(path) = config_path {
                let path = PathBuf::from(path);
                if path.exists() {
                    if let Err(e) = load_servers_from_client_config(&path, name, t, &mut servers) {
                        eprintln!(
                            "Warning: failed to load {name} config at {}: {e}",
                            path.display()
                        );
                    }
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
                println!("No configured servers found.");
                return Ok(());
            }

            let mut table = Table::new()
                .title("Configured MCP Servers")
                .box_style(&ROUNDED)
                .show_header(true);

            table.add_column(
                Column::new("Source").style(Style::parse("bold cyan").unwrap_or_default()),
            );
            table.add_column(
                Column::new("Server Name").style(Style::parse("bold yellow").unwrap_or_default()),
            );
            table.add_column(Column::new("Command"));
            table.add_column(Column::new("Status"));

            if verbose {
                table.add_column(Column::new("Arguments"));
                table.add_column(Column::new("Environment"));
            }

            for entry in &servers {
                let status = if entry.enabled {
                    "✓ enabled"
                } else {
                    "✗ disabled"
                };

                if verbose {
                    let args = if entry.args.is_empty() {
                        "-".to_string()
                    } else {
                        entry.args.join(" ")
                    };

                    let env = if let Some(e) = &entry.env {
                        if e.is_empty() {
                            "-".to_string()
                        } else {
                            e.iter()
                                .map(|(k, v)| format!("{k}={v}"))
                                .collect::<Vec<_>>()
                                .join(", ")
                        }
                    } else {
                        "-".to_string()
                    };

                    table.add_row_cells([
                        entry.source.as_str(),
                        entry.name.as_str(),
                        entry.command.as_str(),
                        status,
                        args.as_str(),
                        env.as_str(),
                    ]);
                } else {
                    table.add_row_cells([
                        entry.source.as_str(),
                        entry.name.as_str(),
                        entry.command.as_str(),
                        status,
                    ]);
                }
            }

            fastmcp_console::console().render(&table);
        }
        ListFormat::Json => {
            let output = ListOutput { servers };
            let json = serde_json::to_string_pretty(&output).map_err(|e| {
                fastmcp_core::McpError::internal_error(format!("JSON serialization error: {e}"))
            })?;
            println!("{json}");
        }
        ListFormat::Yaml => {
            let output = ListOutput { servers };
            let yaml = serde_yaml::to_string(&output).map_err(|e| {
                fastmcp_core::McpError::internal_error(format!("YAML serialization error: {e}"))
            })?;
            println!("{yaml}");
        }
    }

    Ok(())
}

/// Load servers from a client-specific config file.
fn load_servers_from_client_config(
    path: &PathBuf,
    source_name: &str,
    target: InstallTarget,
    servers: &mut Vec<ServerEntry>,
) -> McpResult<()> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        fastmcp_core::McpError::internal_error(format!("Failed to read config: {e}"))
    })?;

    let json: serde_json::Value = serde_json::from_str(&content).map_err(|e| {
        fastmcp_core::McpError::internal_error(format!("Failed to parse config: {e}"))
    })?;

    // Extract servers based on client type
    let servers_map = match target {
        InstallTarget::Claude | InstallTarget::Cursor => {
            json.get("mcpServers").and_then(|v| v.as_object())
        }
        InstallTarget::Cline => json.get("cline.mcpServers").and_then(|v| v.as_object()),
    };

    if let Some(map) = servers_map {
        for (name, config) in map {
            if let Ok(mcp_config) = serde_json::from_value::<McpServerConfig>(config.clone()) {
                // Check if disabled (some configs have a "disabled" field)
                let enabled = !config
                    .get("disabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                servers.push(ServerEntry {
                    name: name.clone(),
                    source: source_name.to_string(),
                    command: mcp_config.command,
                    args: mcp_config.args,
                    env: mcp_config.env,
                    enabled,
                });
            }
        }
    }

    Ok(())
}

/// Load servers from a custom config path.
fn load_servers_from_path(
    path: &PathBuf,
    source_name: &str,
    servers: &mut Vec<ServerEntry>,
) -> McpResult<()> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        fastmcp_core::McpError::internal_error(format!("Failed to read config: {e}"))
    })?;

    // Try to detect format by extension
    let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    match extension {
        "toml" => {
            // Parse as TOML
            let toml_value: toml::Value = toml::from_str(&content).map_err(|e| {
                fastmcp_core::McpError::internal_error(format!("Failed to parse TOML: {e}"))
            })?;

            // Look for [servers] or [mcpServers] table
            let servers_table = toml_value
                .get("servers")
                .or_else(|| toml_value.get("mcpServers"))
                .and_then(|v| v.as_table());

            if let Some(table) = servers_table {
                for (name, config) in table {
                    let command = config
                        .get("command")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string();
                    let args = config
                        .get("args")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    let env = config.get("env").and_then(|v| v.as_table()).map(|t| {
                        t.iter()
                            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                            .collect()
                    });
                    let enabled = !config
                        .get("disabled")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);

                    servers.push(ServerEntry {
                        name: name.clone(),
                        source: source_name.to_string(),
                        command,
                        args,
                        env,
                        enabled,
                    });
                }
            }
        }
        _ => {
            // Default to JSON
            let json: serde_json::Value = serde_json::from_str(&content).map_err(|e| {
                fastmcp_core::McpError::internal_error(format!("Failed to parse JSON: {e}"))
            })?;

            let servers_map = json
                .get("servers")
                .or_else(|| json.get("mcpServers"))
                .and_then(|v| v.as_object());

            if let Some(map) = servers_map {
                for (name, config) in map {
                    if let Ok(mcp_config) =
                        serde_json::from_value::<McpServerConfig>(config.clone())
                    {
                        let enabled = !config
                            .get("disabled")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);

                        servers.push(ServerEntry {
                            name: name.clone(),
                            source: source_name.to_string(),
                            command: mcp_config.command,
                            args: mcp_config.args,
                            env: mcp_config.env,
                            enabled,
                        });
                    }
                }
            }
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
            eprintln!(
                "Warning: failed to load project config at {}: {e}",
                mcp_json.display()
            );
        }
    }

    // Check for ./mcp.toml
    let mcp_toml = PathBuf::from("./mcp.toml");
    if mcp_toml.exists() {
        if let Err(e) = load_servers_from_path(&mcp_toml, "Project (mcp.toml)", servers) {
            eprintln!(
                "Warning: failed to load project config at {}: {e}",
                mcp_toml.display()
            );
        }
    }
}

/// Test result for a single test.
#[derive(Debug, Clone, Serialize)]
struct TestResult {
    name: String,
    success: bool,
    duration_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Full test report output.
#[derive(Debug, Clone, Serialize)]
struct TestReport {
    server: String,
    success: bool,
    tests: Vec<TestResult>,
    total_duration_ms: f64,
}

/// Test command: Test MCP server connectivity.
fn cmd_test(
    server: &str,
    args: &[String],
    timeout_secs: u64,
    verbose: bool,
    json_output: bool,
) -> McpResult<()> {
    use std::time::Instant;

    let total_start = Instant::now();
    let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();

    if !json_output {
        println!("Testing server: {server}");
    }

    // Connect to server
    let mut client = fastmcp_client::ClientBuilder::new()
        .timeout_ms(timeout_secs * 1000)
        .connect_stdio(server, &args_refs)?;

    let mut results: Vec<TestResult> = Vec::new();

    // Test 1: Initialize (already done by connect_stdio)
    let init_start = Instant::now();
    let init_result = TestResult {
        name: "initialize".to_string(),
        success: true,
        duration_ms: init_start.elapsed().as_secs_f64() * 1000.0,
        details: Some(format!("protocol {}", client.protocol_version())),
        error: None,
    };
    if !json_output {
        print_test_result(&init_result, verbose);
    }
    results.push(init_result);

    // Test 2: List tools
    let tools_result = run_test("list_tools", || {
        let tools = client.list_tools()?;
        Ok(format!("{} tools", tools.len()))
    });
    if !json_output {
        print_test_result(&tools_result, verbose);
    }
    results.push(tools_result);

    // Test 3: List resources
    let resources_result = run_test("list_resources", || {
        let resources = client.list_resources()?;
        Ok(format!("{} resources", resources.len()))
    });
    if !json_output {
        print_test_result(&resources_result, verbose);
    }
    results.push(resources_result);

    // Test 4: List prompts
    let prompts_result = run_test("list_prompts", || {
        let prompts = client.list_prompts()?;
        Ok(format!("{} prompts", prompts.len()))
    });
    if !json_output {
        print_test_result(&prompts_result, verbose);
    }
    results.push(prompts_result);

    // Clean up
    client.close();

    // Build report
    let all_passed = results.iter().all(|r| r.success);
    let total_duration_ms = total_start.elapsed().as_secs_f64() * 1000.0;

    let report = TestReport {
        server: server.to_string(),
        success: all_passed,
        tests: results,
        total_duration_ms,
    };

    if json_output {
        let json = serde_json::to_string_pretty(&report).map_err(|e| {
            fastmcp_core::McpError::internal_error(format!("JSON serialization error: {e}"))
        })?;
        println!("{json}");
    } else {
        println!();
        if all_passed {
            println!("All tests passed!");
        } else {
            println!("Some tests failed.");
        }
    }

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
        Ok(details) => TestResult {
            name: name.to_string(),
            success: true,
            duration_ms: start.elapsed().as_secs_f64() * 1000.0,
            details: if details.is_empty() {
                None
            } else {
                Some(details)
            },
            error: None,
        },
        Err(e) => TestResult {
            name: name.to_string(),
            success: false,
            duration_ms: start.elapsed().as_secs_f64() * 1000.0,
            details: None,
            error: Some(e.to_string()),
        },
    }
}

/// Print a single test result.
fn print_test_result(result: &TestResult, verbose: bool) {
    let status = if result.success { "✓" } else { "✗" };
    let name = &result.name;
    let duration = result.duration_ms;

    if result.success {
        if let Some(details) = &result.details {
            if details.is_empty() {
                println!("  {status} {name}: {duration:.1}ms");
            } else {
                println!("  {status} {name}: {duration:.1}ms ({details})");
            }
        } else {
            println!("  {status} {name}: {duration:.1}ms");
        }
    } else {
        println!("  {status} {name}: {duration:.1}ms");
        if verbose {
            if let Some(error) = &result.error {
                println!("      Error: {error}");
            }
        }
    }
}

// ============================================================================
// Dev Command
// ============================================================================

/// Configuration for dev mode.
#[allow(dead_code)] // Fields will be used as more transport options are implemented
struct DevConfig {
    target: String,
    host: String,
    port: u16,
    reload_dirs: Vec<PathBuf>,
    reload_patterns: Vec<String>,
    no_reload: bool,
    transport: DevTransport,
    debounce_ms: u64,
    clear: bool,
    env: Vec<String>,
    verbose: bool,
}

/// Dev command: Run server in development mode with hot reloading.
fn cmd_dev(config: DevConfig) -> McpResult<()> {
    use console::{Term, style};
    use notify::{Config as NotifyConfig, RecommendedWatcher, RecursiveMode, Watcher};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    let term = Term::stdout();
    let flush_stdout = || {
        let _ = io::stdout().flush();
    };

    // Parse environment variables
    let env_vars: HashMap<String, String> = config
        .env
        .iter()
        .filter_map(|s| {
            let mut parts = s.splitn(2, '=');
            Some((parts.next()?.to_string(), parts.next()?.to_string()))
        })
        .collect();

    let patterns: Vec<glob::Pattern> = config
        .reload_patterns
        .iter()
        .map(|p| {
            glob::Pattern::new(p).map_err(|e| {
                fastmcp_core::McpError::internal_error(format!("Invalid reload pattern {p}: {e}"))
            })
        })
        .collect::<McpResult<Vec<_>>>()?;

    // Determine if this is a Cargo project
    let target_path = PathBuf::from(&config.target);
    let is_cargo_project = target_path.join("Cargo.toml").exists()
        || config.target == "."
        || config.target.starts_with("./");

    // Print startup message
    println!(
        "{} {} Development mode",
        style("▶").green().bold(),
        style("fastmcp").cyan().bold()
    );
    println!("  Target: {}", style(target_path.display()).yellow());
    if !config.no_reload {
        println!(
            "  Watching: {}",
            style(
                config
                    .reload_dirs
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
            .dim()
        );
    }
    println!();
    flush_stdout();

    // Build and start the server
    let rebuild_needed = std::sync::Arc::new(AtomicBool::new(false));
    let mut child: Option<std::process::Child> = None;

    // Function to build the project
    let build_project = |verbose: bool| -> bool {
        if is_cargo_project {
            println!("{} Building...", style("🔨").bold());
            flush_stdout();
            let output = Command::new("cargo")
                .arg("build")
                .current_dir(&target_path)
                .envs(&env_vars)
                .output();

            match output {
                Ok(output) => {
                    if output.status.success() {
                        println!("{} Build successful", style("✓").green().bold());
                        flush_stdout();
                        true
                    } else {
                        println!("{} Build failed", style("✗").red().bold());
                        if verbose {
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            for line in stderr.lines().take(20) {
                                println!("  {}", style(line).red());
                            }
                        }
                        flush_stdout();
                        false
                    }
                }
                Err(e) => {
                    println!("{} Build error: {}", style("✗").red().bold(), e);
                    flush_stdout();
                    false
                }
            }
        } else {
            // Binary, no build needed
            true
        }
    };

    // Function to start the server
    let start_server = |env_vars: &HashMap<String, String>| -> Option<std::process::Child> {
        let (cmd, args) = if is_cargo_project {
            ("cargo".to_string(), vec!["run".to_string()])
        } else {
            (config.target.clone(), vec![])
        };

        println!("{} Starting server...", style("🚀").bold());
        flush_stdout();

        let mut command = Command::new(&cmd);
        command
            .args(&args)
            .current_dir(&target_path)
            .envs(env_vars)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        match command.spawn() {
            Ok(child) => {
                println!(
                    "{} Server running (PID: {})",
                    style("✓").green().bold(),
                    child.id()
                );
                flush_stdout();
                Some(child)
            }
            Err(e) => {
                println!("{} Failed to start server: {}", style("✗").red().bold(), e);
                flush_stdout();
                None
            }
        }
    };

    // Initial build and start
    if build_project(config.verbose) {
        child = start_server(&env_vars);
    }

    // If no reload, just wait for the process
    if config.no_reload {
        if let Some(mut c) = child {
            let _ = c.wait();
        }
        return Ok(());
    }

    // Set up file watcher
    let (tx, rx) = mpsc::channel();
    let rebuild_flag = rebuild_needed.clone();
    let target_root = target_path.clone();
    let patterns_for_cb = patterns.clone();

    let mut watcher = RecommendedWatcher::new(
        move |res: Result<notify::Event, notify::Error>| {
            if let Ok(event) = res {
                // Check if any path matches our patterns
                let should_rebuild = event.paths.iter().any(|path| {
                    // Skip target directory (cargo build output).
                    if path.components().any(|c| c.as_os_str() == "target") {
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
                    rebuild_flag.store(true, Ordering::SeqCst);
                    let _ = tx.send(());
                }
            }
        },
        NotifyConfig::default().with_poll_interval(Duration::from_millis(100)),
    )
    .map_err(|e| {
        fastmcp_core::McpError::internal_error(format!("Failed to create watcher: {e}"))
    })?;

    // Watch directories
    for dir in &config.reload_dirs {
        let watch_path = target_path.join(dir);
        if watch_path.exists() {
            watcher
                .watch(&watch_path, RecursiveMode::Recursive)
                .map_err(|e| {
                    fastmcp_core::McpError::internal_error(format!(
                        "Failed to watch {}: {e}",
                        watch_path.display()
                    ))
                })?;
        }
    }

    println!(
        "\n{} Watching for changes... (Ctrl+C to stop)\n",
        style("👀").bold()
    );
    flush_stdout();

    // Main loop
    let mut last_change = Option::<Instant>::None;
    let debounce_duration = Duration::from_millis(config.debounce_ms);

    loop {
        // Check for file changes with timeout
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(()) => {
                // Proper debounce: rebuild after the stream of changes has been quiet for
                // `debounce_duration`. Without this, a single burst of edits can be missed.
                last_change = Some(Instant::now());
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // No new events in this tick; fall through to debounce + child-exit checks.
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break;
            }
        }

        if let Some(at) = last_change {
            if at.elapsed() >= debounce_duration && rebuild_needed.swap(false, Ordering::SeqCst) {
                last_change = None;

                if config.clear {
                    let _ = term.clear_screen();
                }

                println!("\n{} Change detected, rebuilding...", style("🔄").bold());
                flush_stdout();

                // Kill existing process
                if let Some(mut c) = child.take() {
                    let _ = c.kill();
                    let _ = c.wait();
                }

                // Rebuild and restart
                if build_project(config.verbose) {
                    child = start_server(&env_vars);
                }

                println!("\n{} Watching for changes...\n", style("👀").bold());
                flush_stdout();
            }
        }

        // Check if child has exited
        if let Some(ref mut c) = child {
            match c.try_wait() {
                Ok(Some(status)) => {
                    if status.success() {
                        println!("\n{} Server exited normally", style("ℹ").blue().bold());
                    } else {
                        println!(
                            "\n{} Server exited with error ({})",
                            style("⚠").yellow().bold(),
                            status
                        );
                    }
                    println!("{} Waiting for changes...\n", style("👀").bold());
                    flush_stdout();
                    child = None;
                }
                Ok(None) => {
                    // Still running
                }
                Err(e) => {
                    println!(
                        "\n{} Error checking process: {}",
                        style("✗").red().bold(),
                        e
                    );
                    flush_stdout();
                }
            }
        }
    }

    // Cleanup
    if let Some(mut c) = child {
        let _ = c.kill();
        let _ = c.wait();
    }

    Ok(())
}

/// Tasks command: Manage background tasks on an MCP server.
fn cmd_tasks(action: TasksAction) -> McpResult<()> {
    match action {
        TasksAction::List {
            server,
            args,
            status,
            limit,
            json,
        } => {
            let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();
            let mut client = Client::stdio(&server, &args_refs)?;
            let result = cmd_tasks_list(&mut client, status, limit, json);
            client.close();
            result
        }
        TasksAction::Show {
            server,
            task_id,
            args,
            json,
        } => {
            let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();
            let mut client = Client::stdio(&server, &args_refs)?;
            let result = cmd_tasks_show(&mut client, &task_id, json);
            client.close();
            result
        }
        TasksAction::Cancel {
            server,
            task_id,
            args,
            reason,
        } => {
            let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();
            let mut client = Client::stdio(&server, &args_refs)?;
            let result = cmd_tasks_cancel(&mut client, &task_id, reason.as_deref());
            client.close();
            result
        }
        TasksAction::Stats { server, args, json } => {
            let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();
            let mut client = Client::stdio(&server, &args_refs)?;
            let result = cmd_tasks_stats(&mut client, json);
            client.close();
            result
        }
    }
}

/// List tasks with optional status filter.
fn cmd_tasks_list(
    client: &mut Client,
    status: Option<TaskStatusFilter>,
    limit: usize,
    json_output: bool,
) -> McpResult<()> {
    use fastmcp_console::rich_rust::r#box::ROUNDED;
    use fastmcp_console::rich_rust::style::Style;

    let status_filter = status.map(TaskStatus::from);
    let result = client.list_tasks(status_filter, None, Some(limit as u32))?;
    let tasks = result.tasks;

    if json_output {
        let output = serde_json::to_string_pretty(&tasks).map_err(|e| {
            fastmcp_core::McpError::internal_error(format!("JSON serialization error: {e}"))
        })?;
        println!("{output}");
        return Ok(());
    }

    if tasks.is_empty() {
        println!("No tasks found.");
        return Ok(());
    }

    let mut table = Table::new()
        .title("Background Tasks")
        .box_style(&ROUNDED)
        .show_header(true);

    table.add_column(Column::new("ID").style(Style::parse("bold cyan").unwrap_or_default()));
    table.add_column(Column::new("Type").style(Style::parse("yellow").unwrap_or_default()));
    table.add_column(Column::new("Status").style(Style::parse("bold").unwrap_or_default()));
    table.add_column(Column::new("Progress"));
    table.add_column(Column::new("Created"));
    table.add_column(Column::new("Message"));

    for task in &tasks {
        let status_str = format_task_status(task.status);
        let progress = task
            .progress
            .map(|p| format!("{:.0}%", p * 100.0))
            .unwrap_or_else(|| "-".to_string());
        let created = format_timestamp(&task.created_at);
        let message = task.message.as_deref().unwrap_or("-");

        table.add_row_cells([
            task.id.to_string().as_str(),
            &task.task_type,
            &status_str,
            &progress,
            &created,
            message,
        ]);
    }

    fastmcp_console::console().render(&table);

    if result.next_cursor.is_some() {
        println!("\n(More tasks available, use --limit to see more)");
    }

    Ok(())
}

/// Show details of a specific task.
fn cmd_tasks_show(client: &mut Client, task_id: &str, json_output: bool) -> McpResult<()> {
    let result = client.get_task(task_id)?;

    if json_output {
        let output = serde_json::to_string_pretty(&result).map_err(|e| {
            fastmcp_core::McpError::internal_error(format!("JSON serialization error: {e}"))
        })?;
        println!("{output}");
        return Ok(());
    }

    let task = &result.task;
    println!("Task: {}", task.id);
    println!("Type: {}", task.task_type);
    println!("Status: {}", format_task_status(task.status));

    if let Some(progress) = task.progress {
        println!("Progress: {:.0}%", progress * 100.0);
    }

    if let Some(message) = &task.message {
        println!("Message: {message}");
    }

    println!("Created: {}", format_timestamp(&task.created_at));

    if let Some(started) = &task.started_at {
        println!("Started: {}", format_timestamp(started));
    }

    if let Some(completed) = &task.completed_at {
        println!("Completed: {}", format_timestamp(completed));
    }

    if let Some(error) = &task.error {
        println!("Error: {error}");
    }

    if let Some(task_result) = &result.result {
        println!("\nResult:");
        println!("  Success: {}", task_result.success);
        if let Some(data) = &task_result.data {
            if let Ok(pretty) = serde_json::to_string_pretty(data) {
                for line in pretty.lines() {
                    println!("  {line}");
                }
            }
        }
        if let Some(err) = &task_result.error {
            println!("  Error: {err}");
        }
    }

    Ok(())
}

/// Cancel a pending or running task.
fn cmd_tasks_cancel(client: &mut Client, task_id: &str, reason: Option<&str>) -> McpResult<()> {
    let task = if let Some(r) = reason {
        client.cancel_task_with_reason(task_id, Some(r))?
    } else {
        client.cancel_task(task_id)?
    };

    println!("Task {} cancelled.", task.id);
    println!("Status: {}", format_task_status(task.status));

    Ok(())
}

/// Show task queue statistics.
fn cmd_tasks_stats(client: &mut Client, json_output: bool) -> McpResult<()> {
    // Get all tasks to compute statistics
    let all_tasks = client.list_tasks_all(None)?;

    let mut pending = 0;
    let mut running = 0;
    let mut completed = 0;
    let mut failed = 0;
    let mut cancelled = 0;

    for task in &all_tasks {
        match task.status {
            TaskStatus::Pending => pending += 1,
            TaskStatus::Running => running += 1,
            TaskStatus::Completed => completed += 1,
            TaskStatus::Failed => failed += 1,
            TaskStatus::Cancelled => cancelled += 1,
        }
    }

    let total = all_tasks.len();
    let active = pending + running;

    if json_output {
        let stats = serde_json::json!({
            "total": total,
            "active": active,
            "pending": pending,
            "running": running,
            "completed": completed,
            "failed": failed,
            "cancelled": cancelled,
        });
        let output = serde_json::to_string_pretty(&stats).map_err(|e| {
            fastmcp_core::McpError::internal_error(format!("JSON serialization error: {e}"))
        })?;
        println!("{output}");
        return Ok(());
    }

    println!("Task Queue Statistics");
    println!("=====================");
    println!("Total:     {total}");
    println!("Active:    {active}");
    println!("  Pending:   {pending}");
    println!("  Running:   {running}");
    println!("Completed: {completed}");
    println!("Failed:    {failed}");
    println!("Cancelled: {cancelled}");

    Ok(())
}

/// Format a task status for display.
fn format_task_status(status: TaskStatus) -> String {
    match status {
        TaskStatus::Pending => "⏳ Pending".to_string(),
        TaskStatus::Running => "🔄 Running".to_string(),
        TaskStatus::Completed => "✅ Completed".to_string(),
        TaskStatus::Failed => "❌ Failed".to_string(),
        TaskStatus::Cancelled => "🚫 Cancelled".to_string(),
    }
}

/// Format a timestamp for display.
fn format_timestamp(ts: &str) -> String {
    // Try to parse RFC3339 and format nicely
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts) {
        dt.format("%Y-%m-%d %H:%M:%S").to_string()
    } else {
        ts.to_string()
    }
}

/// Inspect command: Connect to a server and display its capabilities.
fn cmd_inspect(
    server: &str,
    args: &[String],
    format: InspectFormat,
    output: Option<&std::path::Path>,
) -> McpResult<()> {
    let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();

    // Connect to the server
    let mut client = Client::stdio(server, &args_refs)?;

    // Gather server information
    let server_info = client.server_info().clone();
    let capabilities = client.server_capabilities().clone();

    // List all capabilities
    let tools = if capabilities.tools.is_some() {
        client.list_tools().unwrap_or_default()
    } else {
        Vec::new()
    };

    let resources = if capabilities.resources.is_some() {
        client.list_resources().unwrap_or_default()
    } else {
        Vec::new()
    };

    let resource_templates = if capabilities.resources.is_some() {
        client.list_resource_templates().unwrap_or_default()
    } else {
        Vec::new()
    };

    let prompts = if capabilities.prompts.is_some() {
        client.list_prompts().unwrap_or_default()
    } else {
        Vec::new()
    };

    // Close the client
    client.close();

    // Format output
    let output_text = match format {
        InspectFormat::Text => format_inspect_text(
            &server_info,
            &capabilities,
            &tools,
            &resources,
            &resource_templates,
            &prompts,
        ),
        InspectFormat::Json | InspectFormat::Mcp => format_inspect_json(
            &server_info,
            &capabilities,
            &tools,
            &resources,
            &resource_templates,
            &prompts,
        )?,
    };

    // Write output
    if let Some(path) = output {
        std::fs::write(path, &output_text).map_err(|e| {
            fastmcp_core::McpError::internal_error(format!("Failed to write output: {e}"))
        })?;
    } else {
        print!("{output_text}");
        io::stdout().flush().ok();
    }

    Ok(())
}

fn format_inspect_text(
    server_info: &fastmcp_protocol::ServerInfo,
    capabilities: &fastmcp_protocol::ServerCapabilities,
    tools: &[fastmcp_protocol::Tool],
    resources: &[fastmcp_protocol::Resource],
    resource_templates: &[fastmcp_protocol::ResourceTemplate],
    prompts: &[fastmcp_protocol::Prompt],
) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "Server: {} v{}\n",
        server_info.name, server_info.version
    ));
    out.push_str(&format!(
        "Capabilities: tools={} resources={} prompts={} logging={}\n\n",
        capabilities.tools.is_some(),
        capabilities.resources.is_some(),
        capabilities.prompts.is_some(),
        capabilities.logging.is_some(),
    ));

    if !tools.is_empty() {
        out.push_str(&format!("Tools ({}):\n", tools.len()));
        for tool in tools {
            out.push_str(&format!("  - {}", tool.name));
            if let Some(desc) = &tool.description {
                out.push_str(&format!(": {desc}"));
            }
            out.push('\n');
        }
        out.push('\n');
    }

    if !resources.is_empty() {
        out.push_str(&format!("Resources ({}):\n", resources.len()));
        for resource in resources {
            out.push_str(&format!("  - {}", resource.uri));
            if !resource.name.is_empty() {
                out.push_str(&format!(" ({})", resource.name));
            }
            out.push('\n');
        }
        out.push('\n');
    }

    if !resource_templates.is_empty() {
        out.push_str(&format!(
            "Resource Templates ({}):\n",
            resource_templates.len()
        ));
        for template in resource_templates {
            out.push_str(&format!("  - {}", template.uri_template));
            if !template.name.is_empty() {
                out.push_str(&format!(" ({})", template.name));
            }
            out.push('\n');
        }
        out.push('\n');
    }

    if !prompts.is_empty() {
        out.push_str(&format!("Prompts ({}):\n", prompts.len()));
        for prompt in prompts {
            out.push_str(&format!("  - {}", prompt.name));
            if let Some(desc) = &prompt.description {
                out.push_str(&format!(": {desc}"));
            }
            out.push('\n');
        }
    }

    out
}

#[derive(Serialize)]
struct InspectOutput {
    server: ServerInfoOutput,
    capabilities: CapabilitiesOutput,
    tools: Vec<serde_json::Value>,
    resources: Vec<serde_json::Value>,
    resource_templates: Vec<serde_json::Value>,
    prompts: Vec<serde_json::Value>,
}

#[derive(Serialize)]
struct ServerInfoOutput {
    name: String,
    version: String,
}

#[derive(Serialize)]
struct CapabilitiesOutput {
    tools: bool,
    resources: bool,
    prompts: bool,
    logging: bool,
}

fn format_inspect_json(
    server_info: &fastmcp_protocol::ServerInfo,
    capabilities: &fastmcp_protocol::ServerCapabilities,
    tools: &[fastmcp_protocol::Tool],
    resources: &[fastmcp_protocol::Resource],
    resource_templates: &[fastmcp_protocol::ResourceTemplate],
    prompts: &[fastmcp_protocol::Prompt],
) -> McpResult<String> {
    let output = InspectOutput {
        server: ServerInfoOutput {
            name: server_info.name.clone(),
            version: server_info.version.clone(),
        },
        capabilities: CapabilitiesOutput {
            tools: capabilities.tools.is_some(),
            resources: capabilities.resources.is_some(),
            prompts: capabilities.prompts.is_some(),
            logging: capabilities.logging.is_some(),
        },
        tools: tools
            .iter()
            .filter_map(|t| serde_json::to_value(t).ok())
            .collect(),
        resources: resources
            .iter()
            .filter_map(|r| serde_json::to_value(r).ok())
            .collect(),
        resource_templates: resource_templates
            .iter()
            .filter_map(|t| serde_json::to_value(t).ok())
            .collect(),
        prompts: prompts
            .iter()
            .filter_map(|p| serde_json::to_value(p).ok())
            .collect(),
    };

    serde_json::to_string_pretty(&output).map_err(|e| {
        fastmcp_core::McpError::internal_error(format!("JSON serialization error: {e}"))
    })
}

/// Install command: Generate configuration for MCP clients.
fn cmd_install(
    name: &str,
    server: &str,
    args: &[String],
    target: InstallTarget,
    dry_run: bool,
) -> McpResult<()> {
    let config = generate_server_config(name, server, args);

    match target {
        InstallTarget::Claude => install_claude_desktop(&config, dry_run),
        InstallTarget::Cursor => install_cursor(&config, dry_run),
        InstallTarget::Cline => install_cline(&config, dry_run),
    }
}

#[derive(Serialize, Deserialize)]
struct McpServerConfig {
    command: String,
    args: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    env: Option<HashMap<String, String>>,
}

fn generate_server_config(name: &str, server: &str, args: &[String]) -> (String, McpServerConfig) {
    (
        name.to_string(),
        McpServerConfig {
            command: server.to_string(),
            args: args.to_vec(),
            env: None,
        },
    )
}

fn read_json_config_or_empty(config_path: &str) -> McpResult<serde_json::Value> {
    if !std::path::Path::new(config_path).exists() {
        return Ok(serde_json::json!({}));
    }

    let content = std::fs::read_to_string(config_path).map_err(|e| {
        fastmcp_core::McpError::internal_error(format!(
            "Failed to read config at {config_path}: {e}"
        ))
    })?;
    serde_json::from_str(&content).map_err(|e| {
        fastmcp_core::McpError::internal_error(format!(
            "Failed to parse JSON config at {config_path}: {e}"
        ))
    })
}

fn write_json_config(config_path: &str, value: &serde_json::Value) -> McpResult<()> {
    let new_content = serde_json::to_string_pretty(value).map_err(|e| {
        fastmcp_core::McpError::internal_error(format!("JSON serialization error: {e}"))
    })?;

    if let Some(parent) = std::path::Path::new(config_path).parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            fastmcp_core::McpError::internal_error(format!(
                "Failed to create config directory for {config_path}: {e}"
            ))
        })?;
    }

    std::fs::write(config_path, new_content).map_err(|e| {
        fastmcp_core::McpError::internal_error(format!(
            "Failed to write config at {config_path}: {e}"
        ))
    })
}

fn create_backup_if_exists(config_path: &str) -> McpResult<Option<String>> {
    if !std::path::Path::new(config_path).exists() {
        return Ok(None);
    }

    let backup_path = format!("{config_path}.bak");
    std::fs::copy(config_path, &backup_path).map_err(|e| {
        fastmcp_core::McpError::internal_error(format!(
            "Failed to create backup {backup_path} from {config_path}: {e}"
        ))
    })?;
    Ok(Some(backup_path))
}

fn install_claude_desktop(config: &(String, McpServerConfig), dry_run: bool) -> McpResult<()> {
    let config_path = get_claude_desktop_config_path()?;

    let mut servers = HashMap::new();
    servers.insert(config.0.clone(), &config.1);

    let config_snippet = serde_json::json!({
        "mcpServers": servers
    });

    let snippet_str = serde_json::to_string_pretty(&config_snippet).map_err(|e| {
        fastmcp_core::McpError::internal_error(format!("JSON serialization error: {e}"))
    })?;

    if dry_run {
        println!("Dry-run: proposed update to {config_path}:\n\n{snippet_str}");
        return Ok(());
    }

    // Read existing config or create new one
    let mut existing_config = read_json_config_or_empty(&config_path)?;
    if !existing_config.is_object() {
        return Err(fastmcp_core::McpError::internal_error(format!(
            "Config root at {config_path} must be a JSON object"
        )));
    }

    let obj = existing_config.as_object_mut().unwrap();
    if !obj.contains_key("mcpServers") {
        obj.insert("mcpServers".to_string(), serde_json::json!({}));
    }

    let mcp_servers = obj.get_mut("mcpServers").unwrap();
    let servers_obj = mcp_servers.as_object_mut().ok_or_else(|| {
        fastmcp_core::McpError::internal_error(format!(
            "mcpServers at {config_path} must be a JSON object"
        ))
    })?;
    let server_val = serde_json::to_value(&config.1).map_err(|e| {
        fastmcp_core::McpError::internal_error(format!("JSON serialization error: {e}"))
    })?;
    servers_obj.insert(config.0.clone(), server_val);

    let backup_path = create_backup_if_exists(&config_path)?;
    write_json_config(&config_path, &existing_config)?;

    if let Some(backup_path) = backup_path {
        println!(
            "Added '{name}' to {config_path} (backup: {backup_path})",
            name = config.0
        );
    } else {
        println!("Added '{name}' to {config_path}", name = config.0);
    }
    Ok(())
}

fn get_claude_desktop_config_path() -> McpResult<String> {
    #[cfg(target_os = "macos")]
    {
        let home = env::var("HOME").map_err(|_| {
            fastmcp_core::McpError::internal_error("HOME environment variable not set")
        })?;
        Ok(format!(
            "{home}/Library/Application Support/Claude/claude_desktop_config.json"
        ))
    }

    #[cfg(target_os = "windows")]
    {
        let appdata = env::var("APPDATA").map_err(|_| {
            fastmcp_core::McpError::internal_error("APPDATA environment variable not set")
        })?;
        Ok(format!("{appdata}\\Claude\\claude_desktop_config.json"))
    }

    #[cfg(target_os = "linux")]
    {
        let home = env::var("HOME").map_err(|_| {
            fastmcp_core::McpError::internal_error("HOME environment variable not set")
        })?;
        Ok(format!("{home}/.config/Claude/claude_desktop_config.json"))
    }
}

fn install_cursor(config: &(String, McpServerConfig), dry_run: bool) -> McpResult<()> {
    // Cursor uses a similar format in .cursor/mcp.json
    let config_path = get_cursor_config_path()?;

    let mut servers = HashMap::new();
    servers.insert(config.0.clone(), &config.1);

    let config_json = serde_json::json!({
        "mcpServers": servers
    });

    let snippet_str = serde_json::to_string_pretty(&config_json).map_err(|e| {
        fastmcp_core::McpError::internal_error(format!("JSON serialization error: {e}"))
    })?;

    if dry_run {
        println!("Dry-run: proposed update to {config_path}:\n\n{snippet_str}");
        return Ok(());
    }

    // Similar merge logic as Claude Desktop
    let mut existing_config = read_json_config_or_empty(&config_path)?;
    if !existing_config.is_object() {
        return Err(fastmcp_core::McpError::internal_error(format!(
            "Config root at {config_path} must be a JSON object"
        )));
    }

    let obj = existing_config.as_object_mut().unwrap();
    if !obj.contains_key("mcpServers") {
        obj.insert("mcpServers".to_string(), serde_json::json!({}));
    }

    let mcp_servers = obj.get_mut("mcpServers").unwrap();
    let servers_obj = mcp_servers.as_object_mut().ok_or_else(|| {
        fastmcp_core::McpError::internal_error(format!(
            "mcpServers at {config_path} must be a JSON object"
        ))
    })?;
    let server_val = serde_json::to_value(&config.1).map_err(|e| {
        fastmcp_core::McpError::internal_error(format!("JSON serialization error: {e}"))
    })?;
    servers_obj.insert(config.0.clone(), server_val);

    let backup_path = create_backup_if_exists(&config_path)?;
    write_json_config(&config_path, &existing_config)?;

    if let Some(backup_path) = backup_path {
        println!(
            "Added '{name}' to {config_path} (backup: {backup_path})",
            name = config.0
        );
    } else {
        println!("Added '{name}' to {config_path}", name = config.0);
    }
    Ok(())
}

fn get_cursor_config_path() -> McpResult<String> {
    let home = env::var("HOME")
        .or_else(|_| env::var("USERPROFILE"))
        .map_err(|_| {
            fastmcp_core::McpError::internal_error(
                "Neither HOME nor USERPROFILE environment variable set",
            )
        })?;
    Ok(format!("{home}/.cursor/mcp.json"))
}

fn install_cline(config: &(String, McpServerConfig), dry_run: bool) -> McpResult<()> {
    // Cline uses VSCode settings
    let config_path = get_cline_config_path()?;

    let mut servers = HashMap::new();
    servers.insert(config.0.clone(), &config.1);

    let snippet_str = serde_json::to_string_pretty(&serde_json::json!({
        "cline.mcpServers": servers
    }))
    .map_err(|e| {
        fastmcp_core::McpError::internal_error(format!("JSON serialization error: {e}"))
    })?;

    if dry_run {
        println!("Dry-run: proposed update to VS Code settings at {config_path}:\n\n{snippet_str}");
        return Ok(());
    }

    // Merge into VS Code settings.json under `cline.mcpServers`.
    let mut existing_config = read_json_config_or_empty(&config_path)?;
    if !existing_config.is_object() {
        return Err(fastmcp_core::McpError::internal_error(format!(
            "VS Code settings at {config_path} must be a JSON object"
        )));
    }

    let obj = existing_config.as_object_mut().unwrap();
    if !obj.contains_key("cline.mcpServers") {
        obj.insert("cline.mcpServers".to_string(), serde_json::json!({}));
    }

    let mcp_servers = obj.get_mut("cline.mcpServers").unwrap();
    let servers_obj = mcp_servers.as_object_mut().ok_or_else(|| {
        fastmcp_core::McpError::internal_error(format!(
            "cline.mcpServers at {config_path} must be a JSON object"
        ))
    })?;

    let server_val = serde_json::to_value(&config.1).map_err(|e| {
        fastmcp_core::McpError::internal_error(format!("JSON serialization error: {e}"))
    })?;
    servers_obj.insert(config.0.clone(), server_val);

    let backup_path = create_backup_if_exists(&config_path)?;
    write_json_config(&config_path, &existing_config)?;

    if let Some(backup_path) = backup_path {
        println!(
            "Added '{name}' to {config_path} (backup: {backup_path})",
            name = config.0
        );
    } else {
        println!("Added '{name}' to {config_path}", name = config.0);
    }

    Ok(())
}

fn get_cline_config_path() -> McpResult<String> {
    #[cfg(target_os = "macos")]
    {
        let home = env::var("HOME").map_err(|_| {
            fastmcp_core::McpError::internal_error("HOME environment variable not set")
        })?;
        Ok(format!(
            "{home}/Library/Application Support/Code/User/settings.json"
        ))
    }

    #[cfg(target_os = "windows")]
    {
        let appdata = env::var("APPDATA").map_err(|_| {
            fastmcp_core::McpError::internal_error("APPDATA environment variable not set")
        })?;
        Ok(format!("{appdata}\\Code\\User\\settings.json"))
    }

    #[cfg(target_os = "linux")]
    {
        let home = env::var("HOME").map_err(|_| {
            fastmcp_core::McpError::internal_error("HOME environment variable not set")
        })?;
        Ok(format!("{home}/.config/Code/User/settings.json"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

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
                } => {
                    assert_eq!(server, "./my-server");
                    assert!(args.is_empty());
                    assert!(cwd.is_none());
                    assert!(env.is_empty());
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
        fn test_inspect_command_basic() {
            let cli = Cli::try_parse_from(["fastmcp", "inspect", "./server"]).unwrap();
            match cli.command {
                Commands::Inspect {
                    server,
                    format,
                    output,
                    ..
                } => {
                    assert_eq!(server, "./server");
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
        fn test_inspect_command_mcp_format() {
            let cli =
                Cli::try_parse_from(["fastmcp", "inspect", "--format", "mcp", "./server"]).unwrap();
            match cli.command {
                Commands::Inspect { format, .. } => {
                    assert_eq!(format, InspectFormat::Mcp);
                }
                _ => unreachable!("Expected Inspect command"),
            }
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
                    ..
                } => {
                    assert_eq!(name, "my-server");
                    assert_eq!(server, "./server");
                    assert_eq!(target, InstallTarget::Claude);
                    assert!(!dry_run);
                }
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
                    timeout,
                    verbose,
                    json,
                    ..
                } => {
                    assert_eq!(server, "./server");
                    assert_eq!(timeout, 30);
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
                "--timeout",
                "60",
                "-v",
                "--json",
                "./server",
            ])
            .unwrap();
            match cli.command {
                Commands::Test {
                    timeout,
                    verbose,
                    json,
                    ..
                } => {
                    assert_eq!(timeout, 60);
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
                    host,
                    port,
                    no_reload,
                    transport,
                    debounce,
                    clear,
                    verbose,
                    ..
                } => {
                    assert_eq!(target, ".");
                    assert_eq!(host, "localhost");
                    assert_eq!(port, 8000);
                    assert!(!no_reload);
                    assert_eq!(transport, DevTransport::Stdio);
                    assert_eq!(debounce, 100);
                    assert!(!clear);
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
                "--host",
                "0.0.0.0",
                "--port",
                "3000",
                "--transport",
                "sse",
                "--no-reload",
                "--clear",
                "-v",
                ".",
            ])
            .unwrap();
            match cli.command {
                Commands::Dev {
                    host,
                    port,
                    transport,
                    no_reload,
                    clear,
                    verbose,
                    ..
                } => {
                    assert_eq!(host, "0.0.0.0");
                    assert_eq!(port, 3000);
                    assert_eq!(transport, DevTransport::Sse);
                    assert!(no_reload);
                    assert!(clear);
                    assert!(verbose);
                }
                _ => unreachable!("Expected Dev command"),
            }
        }

        #[test]
        fn test_dev_command_http_transport() {
            let cli = Cli::try_parse_from(["fastmcp", "dev", "--transport", "http", "."]).unwrap();
            match cli.command {
                Commands::Dev { transport, .. } => {
                    assert_eq!(transport, DevTransport::Http);
                }
                _ => unreachable!("Expected Dev command"),
            }
        }

        #[test]
        fn test_tasks_list_command() {
            let cli = Cli::try_parse_from(["fastmcp", "tasks", "list", "./server"]).unwrap();
            match cli.command {
                Commands::Tasks {
                    action:
                        TasksAction::List {
                            server,
                            status,
                            limit,
                            json,
                            ..
                        },
                } => {
                    assert_eq!(server, "./server");
                    assert!(status.is_none());
                    assert_eq!(limit, 20);
                    assert!(!json);
                }
                _ => unreachable!("Expected Tasks List command"),
            }
        }

        #[test]
        fn test_tasks_list_with_status_filter() {
            let cli = Cli::try_parse_from([
                "fastmcp", "tasks", "list", "-s", "running", "-n", "50", "--json", "./server",
            ])
            .unwrap();
            match cli.command {
                Commands::Tasks {
                    action:
                        TasksAction::List {
                            status,
                            limit,
                            json,
                            ..
                        },
                } => {
                    assert_eq!(status, Some(TaskStatusFilter::Running));
                    assert_eq!(limit, 50);
                    assert!(json);
                }
                _ => unreachable!("Expected Tasks List command"),
            }
        }

        #[test]
        fn test_tasks_show_command() {
            let cli =
                Cli::try_parse_from(["fastmcp", "tasks", "show", "./server", "task-001"]).unwrap();
            match cli.command {
                Commands::Tasks {
                    action:
                        TasksAction::Show {
                            server,
                            task_id,
                            json,
                            ..
                        },
                } => {
                    assert_eq!(server, "./server");
                    assert_eq!(task_id, "task-001");
                    assert!(!json);
                }
                _ => unreachable!("Expected Tasks Show command"),
            }
        }

        #[test]
        fn test_tasks_cancel_command() {
            let cli = Cli::try_parse_from([
                "fastmcp",
                "tasks",
                "cancel",
                "-r",
                "no longer needed",
                "./server",
                "task-001",
            ])
            .unwrap();
            match cli.command {
                Commands::Tasks {
                    action:
                        TasksAction::Cancel {
                            server,
                            task_id,
                            reason,
                            ..
                        },
                } => {
                    assert_eq!(server, "./server");
                    assert_eq!(task_id, "task-001");
                    assert_eq!(reason, Some("no longer needed".to_string()));
                }
                _ => unreachable!("Expected Tasks Cancel command"),
            }
        }

        #[test]
        fn test_tasks_stats_command() {
            let cli =
                Cli::try_parse_from(["fastmcp", "tasks", "stats", "--json", "./server"]).unwrap();
            match cli.command {
                Commands::Tasks {
                    action: TasksAction::Stats { server, json, .. },
                } => {
                    assert_eq!(server, "./server");
                    assert!(json);
                }
                _ => unreachable!("Expected Tasks Stats command"),
            }
        }
    }

    // ============================================================================
    // Enum Parsing Tests
    // ============================================================================

    mod enum_parsing {
        use super::*;

        #[test]
        fn test_task_status_filter_from_str() {
            assert_eq!(
                "pending".parse::<TaskStatusFilter>().unwrap(),
                TaskStatusFilter::Pending
            );
            assert_eq!(
                "PENDING".parse::<TaskStatusFilter>().unwrap(),
                TaskStatusFilter::Pending
            );
            assert_eq!(
                "running".parse::<TaskStatusFilter>().unwrap(),
                TaskStatusFilter::Running
            );
            assert_eq!(
                "completed".parse::<TaskStatusFilter>().unwrap(),
                TaskStatusFilter::Completed
            );
            assert_eq!(
                "failed".parse::<TaskStatusFilter>().unwrap(),
                TaskStatusFilter::Failed
            );
            assert_eq!(
                "cancelled".parse::<TaskStatusFilter>().unwrap(),
                TaskStatusFilter::Cancelled
            );
            assert_eq!(
                "canceled".parse::<TaskStatusFilter>().unwrap(),
                TaskStatusFilter::Cancelled
            );
        }

        #[test]
        fn test_task_status_filter_invalid() {
            let result = "invalid".parse::<TaskStatusFilter>();
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("Unknown status"));
        }

        #[test]
        fn test_task_status_filter_to_task_status() {
            assert!(matches!(
                TaskStatus::from(TaskStatusFilter::Pending),
                TaskStatus::Pending
            ));
            assert!(matches!(
                TaskStatus::from(TaskStatusFilter::Running),
                TaskStatus::Running
            ));
            assert!(matches!(
                TaskStatus::from(TaskStatusFilter::Completed),
                TaskStatus::Completed
            ));
            assert!(matches!(
                TaskStatus::from(TaskStatusFilter::Failed),
                TaskStatus::Failed
            ));
            assert!(matches!(
                TaskStatus::from(TaskStatusFilter::Cancelled),
                TaskStatus::Cancelled
            ));
        }

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
            assert_eq!("mcp".parse::<InspectFormat>().unwrap(), InspectFormat::Mcp);
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
        fn test_dev_transport_from_str() {
            assert_eq!(
                "stdio".parse::<DevTransport>().unwrap(),
                DevTransport::Stdio
            );
            assert_eq!(
                "STDIO".parse::<DevTransport>().unwrap(),
                DevTransport::Stdio
            );
            assert_eq!("sse".parse::<DevTransport>().unwrap(), DevTransport::Sse);
            assert_eq!("http".parse::<DevTransport>().unwrap(), DevTransport::Http);
        }

        #[test]
        fn test_dev_transport_invalid() {
            let result = "websocket".parse::<DevTransport>();
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("Unknown transport"));
        }

        #[test]
        fn test_dev_transport_default() {
            assert_eq!(DevTransport::default(), DevTransport::Stdio);
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
        fn test_format_task_status_pending() {
            let result = format_task_status(TaskStatus::Pending);
            assert!(result.contains("Pending"));
        }

        #[test]
        fn test_format_task_status_running() {
            let result = format_task_status(TaskStatus::Running);
            assert!(result.contains("Running"));
        }

        #[test]
        fn test_format_task_status_completed() {
            let result = format_task_status(TaskStatus::Completed);
            assert!(result.contains("Completed"));
        }

        #[test]
        fn test_format_task_status_failed() {
            let result = format_task_status(TaskStatus::Failed);
            assert!(result.contains("Failed"));
        }

        #[test]
        fn test_format_task_status_cancelled() {
            let result = format_task_status(TaskStatus::Cancelled);
            assert!(result.contains("Cancelled"));
        }

        #[test]
        fn test_format_timestamp_rfc3339() {
            let result = format_timestamp("2024-01-15T10:30:00Z");
            assert_eq!(result, "2024-01-15 10:30:00");
        }

        #[test]
        fn test_format_timestamp_with_timezone() {
            let result = format_timestamp("2024-01-15T10:30:00+05:00");
            assert_eq!(result, "2024-01-15 10:30:00");
        }

        #[test]
        fn test_format_timestamp_invalid_passthrough() {
            let result = format_timestamp("not-a-timestamp");
            assert_eq!(result, "not-a-timestamp");
        }

        #[test]
        fn test_generate_server_config() {
            let (name, config) = generate_server_config(
                "my-server",
                "/path/to/server",
                &["--config".to_string(), "config.json".to_string()],
            );

            assert_eq!(name, "my-server");
            assert_eq!(config.command, "/path/to/server");
            assert_eq!(config.args, vec!["--config", "config.json"]);
            assert!(config.env.is_none());
        }
    }

    // ============================================================================
    // Data Structure Tests
    // ============================================================================

    mod data_structures {
        use super::*;

        #[test]
        fn test_server_entry_serialization() {
            let entry = ServerEntry {
                name: "test-server".to_string(),
                source: "Claude".to_string(),
                command: "/path/to/server".to_string(),
                args: vec!["--config".to_string(), "config.json".to_string()],
                env: Some(HashMap::from([("FOO".to_string(), "bar".to_string())])),
                enabled: true,
            };

            let json = serde_json::to_string(&entry).unwrap();
            assert!(json.contains("test-server"));
            assert!(json.contains("Claude"));
            assert!(json.contains("FOO"));
        }

        #[test]
        fn test_server_entry_without_env() {
            let entry = ServerEntry {
                name: "test".to_string(),
                source: "Test".to_string(),
                command: "cmd".to_string(),
                args: vec![],
                env: None,
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
                    ServerEntry {
                        name: "server1".to_string(),
                        source: "Claude".to_string(),
                        command: "cmd1".to_string(),
                        args: vec![],
                        env: None,
                        enabled: true,
                    },
                    ServerEntry {
                        name: "server2".to_string(),
                        source: "Cursor".to_string(),
                        command: "cmd2".to_string(),
                        args: vec!["arg1".to_string()],
                        env: None,
                        enabled: false,
                    },
                ],
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
                duration_ms: 123.456,
                details: Some("passed".to_string()),
                error: None,
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
                duration_ms: 50.0,
                details: None,
                error: Some("Connection refused".to_string()),
            };

            let json = serde_json::to_string(&result).unwrap();
            assert!(json.contains("failing_test"));
            assert!(json.contains("false"));
            assert!(json.contains("Connection refused"));
        }

        #[test]
        fn test_test_report_serialization() {
            let report = TestReport {
                server: "./my-server".to_string(),
                success: true,
                tests: vec![TestResult {
                    name: "init".to_string(),
                    success: true,
                    duration_ms: 10.0,
                    details: None,
                    error: None,
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
                "env": {"PYTHONPATH": "/custom/path"}
            }"#;

            let config: McpServerConfig = serde_json::from_str(json).unwrap();
            assert_eq!(config.command, "python");
            assert_eq!(config.args, vec!["-m", "my_server"]);
            assert_eq!(
                config.env.unwrap().get("PYTHONPATH"),
                Some(&"/custom/path".to_string())
            );
        }

        #[test]
        fn test_mcp_server_config_minimal() {
            let json = r#"{
                "command": "server",
                "args": []
            }"#;

            let config: McpServerConfig = serde_json::from_str(json).unwrap();
            assert_eq!(config.command, "server");
            assert!(config.args.is_empty());
            assert!(config.env.is_none());
        }
    }

    // ============================================================================
    // Output Formatting Tests
    // ============================================================================

    mod output_formatting {
        use super::*;

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
                tasks: None,
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

            let output = format_inspect_text(&server_info, &capabilities, &[], &[], &[], &[]);

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

            let output = format_inspect_text(&server_info, &capabilities, &tools, &[], &[], &[]);

            assert!(output.contains("Tools (1)"));
            assert!(output.contains("my_tool"));
            assert!(output.contains("A test tool"));
        }

        #[test]
        fn test_format_inspect_text_with_resources() {
            let server_info = make_test_server_info();
            let capabilities = make_test_capabilities(false, true, false);

            let resources = vec![make_test_resource("file:///test.txt", "test file")];

            let output =
                format_inspect_text(&server_info, &capabilities, &[], &resources, &[], &[]);

            assert!(output.contains("Resources (1)"));
            assert!(output.contains("file:///test.txt"));
            assert!(output.contains("test file"));
        }

        #[test]
        fn test_format_inspect_text_with_prompts() {
            let server_info = make_test_server_info();
            let capabilities = make_test_capabilities(false, false, true);

            let prompts = vec![make_test_prompt("greeting", Some("A greeting prompt"))];

            let output = format_inspect_text(&server_info, &capabilities, &[], &[], &[], &prompts);

            assert!(output.contains("Prompts (1)"));
            assert!(output.contains("greeting"));
            assert!(output.contains("A greeting prompt"));
        }

        #[test]
        fn test_format_inspect_json_basic() {
            let server_info = make_test_server_info();
            let capabilities = make_test_capabilities(true, true, false);

            let result = format_inspect_json(&server_info, &capabilities, &[], &[], &[], &[]);

            assert!(result.is_ok());
            let json = result.unwrap();
            assert!(json.contains("\"name\": \"test-server\""));
            assert!(json.contains("\"version\": \"1.0.0\""));
            assert!(json.contains("\"tools\": true"));
            assert!(json.contains("\"resources\": true"));
            assert!(json.contains("\"prompts\": false"));
        }

        #[test]
        fn test_format_inspect_json_with_tools() {
            let server_info = make_test_server_info();
            let capabilities = make_test_capabilities(true, false, false);

            let mut tool = make_test_tool("calculator", Some("Performs calculations"));
            tool.input_schema = serde_json::json!({
                "type": "object",
                "properties": {
                    "expression": { "type": "string" }
                }
            });
            let tools = vec![tool];

            let result = format_inspect_json(&server_info, &capabilities, &tools, &[], &[], &[]);

            assert!(result.is_ok());
            let json = result.unwrap();
            assert!(json.contains("calculator"));
            assert!(json.contains("Performs calculations"));
        }
    }

    // ============================================================================
    // Config Path Tests
    // ============================================================================

    mod config_paths {
        use super::*;

        #[test]
        fn test_get_claude_desktop_config_path_format() {
            // This test verifies the path format is correct
            // We can't test the actual path without mocking HOME
            let result = get_claude_desktop_config_path();
            if let Ok(path) = result {
                assert!(path.contains("claude_desktop_config.json"));
            }
            // If HOME is not set, result will be Err, which is also valid
        }

        #[test]
        fn test_get_cursor_config_path_format() {
            let result = get_cursor_config_path();
            if let Ok(path) = result {
                assert!(path.contains(".cursor"));
                assert!(path.contains("mcp.json"));
            }
        }

        #[test]
        fn test_get_cline_config_path_format() {
            let result = get_cline_config_path();
            if let Ok(path) = result {
                assert!(path.contains("settings.json"));
            }
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
        fn test_tasks_missing_subcommand() {
            let result = Cli::try_parse_from(["fastmcp", "tasks"]);
            assert!(result.is_err());
        }

        #[test]
        fn test_tasks_show_missing_task_id() {
            let result = Cli::try_parse_from(["fastmcp", "tasks", "show", "./server"]);
            assert!(result.is_err());
        }

        #[test]
        fn test_dev_missing_target() {
            let result = Cli::try_parse_from(["fastmcp", "dev"]);
            assert!(result.is_err());
        }

        #[test]
        fn test_invalid_timeout_value() {
            let result =
                Cli::try_parse_from(["fastmcp", "test", "--timeout", "not-a-number", "./server"]);
            assert!(result.is_err());
        }

        #[test]
        fn test_invalid_port_value() {
            let result = Cli::try_parse_from(["fastmcp", "dev", "--port", "not-a-number", "."]);
            assert!(result.is_err());
        }
    }

    // ============================================================================
    // Integration-style Tests (without actual server)
    // ============================================================================

    mod integration {
        use super::*;

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
        fn test_run_test_helper_empty_details() {
            // Test that empty details are converted to None
            let result = run_test("test_empty", || Ok(String::new()));

            assert!(result.success);
            assert!(result.details.is_none());
        }
    }
}
