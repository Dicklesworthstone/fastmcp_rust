//! FastMCP CLI - Command-line tooling for MCP servers.
//!
//! Commands:
//! - `run` - Run an MCP server
//! - `inspect` - Inspect a server's capabilities
//! - `install` - Install server config for Claude Desktop etc.
//! - `tasks` - Manage background tasks on MCP servers

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::env;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

use fastmcp_client::Client;
use fastmcp_console::rich_rust::prelude::*;
use fastmcp_core::McpResult;
use fastmcp_protocol::TaskStatus;

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
            _ => Err(format!("Unknown transport: {s}. Expected: stdio, sse, http")),
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
            return Err(fastmcp_core::McpError::internal_error(format!(
                "Server exited with code {code}"
            )));
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
                    let _ = load_servers_from_client_config(&path, name, t, &mut servers);
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
                let status = if entry.enabled { "✓ enabled" } else { "✗ disabled" };

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
            println!(
                "{}",
                serde_json::to_string_pretty(&output).unwrap_or_default()
            );
        }
        ListFormat::Yaml => {
            let output = ListOutput { servers };
            println!("{}", serde_yaml::to_string(&output).unwrap_or_default());
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
fn load_servers_from_path(path: &PathBuf, source_name: &str, servers: &mut Vec<ServerEntry>) -> McpResult<()> {
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
                    if let Ok(mcp_config) = serde_json::from_value::<McpServerConfig>(config.clone())
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
        let _ = load_servers_from_path(&mcp_json, "Project (mcp.json)", servers);
    }

    // Check for ./mcp.toml
    let mcp_toml = PathBuf::from("./mcp.toml");
    if mcp_toml.exists() {
        let _ = load_servers_from_path(&mcp_toml, "Project (mcp.toml)", servers);
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
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
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
    use console::{style, Term};
    use notify::{Config as NotifyConfig, RecommendedWatcher, RecursiveMode, Watcher};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    let term = Term::stdout();

    // Parse environment variables
    let env_vars: HashMap<String, String> = config
        .env
        .iter()
        .filter_map(|s| {
            let mut parts = s.splitn(2, '=');
            Some((parts.next()?.to_string(), parts.next()?.to_string()))
        })
        .collect();

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
    println!(
        "  Target: {}",
        style(target_path.display()).yellow()
    );
    if !config.no_reload {
        println!(
            "  Watching: {}",
            style(config.reload_dirs.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")).dim()
        );
    }
    println!();

    // Build and start the server
    let rebuild_needed = std::sync::Arc::new(AtomicBool::new(false));
    let mut child: Option<std::process::Child> = None;

    // Function to build the project
    let build_project = |verbose: bool| -> bool {
        if is_cargo_project {
            println!(
                "{} Building...",
                style("🔨").bold()
            );
            let output = Command::new("cargo")
                .arg("build")
                .current_dir(&target_path)
                .envs(&env_vars)
                .output();

            match output {
                Ok(output) => {
                    if output.status.success() {
                        println!(
                            "{} Build successful",
                            style("✓").green().bold()
                        );
                        true
                    } else {
                        println!(
                            "{} Build failed",
                            style("✗").red().bold()
                        );
                        if verbose {
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            for line in stderr.lines().take(20) {
                                println!("  {}", style(line).red());
                            }
                        }
                        false
                    }
                }
                Err(e) => {
                    println!(
                        "{} Build error: {}",
                        style("✗").red().bold(),
                        e
                    );
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

        println!(
            "{} Starting server...",
            style("🚀").bold()
        );

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
                Some(child)
            }
            Err(e) => {
                println!(
                    "{} Failed to start server: {}",
                    style("✗").red().bold(),
                    e
                );
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

    let mut watcher = RecommendedWatcher::new(
        move |res: Result<notify::Event, notify::Error>| {
            if let Ok(event) = res {
                // Check if any path matches our patterns
                let should_rebuild = event.paths.iter().any(|path| {
                    let path_str = path.to_string_lossy();
                    // Skip target directory
                    if path_str.contains("/target/") || path_str.contains("\\target\\") {
                        return false;
                    }
                    // Check if it's a Rust file
                    path_str.ends_with(".rs") || path_str.ends_with(".toml")
                });

                if should_rebuild {
                    rebuild_flag.store(true, Ordering::SeqCst);
                    let _ = tx.send(());
                }
            }
        },
        NotifyConfig::default().with_poll_interval(Duration::from_millis(100)),
    )
    .map_err(|e| fastmcp_core::McpError::internal_error(format!("Failed to create watcher: {e}")))?;

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

    // Main loop
    let mut last_rebuild = Instant::now();
    let debounce_duration = Duration::from_millis(config.debounce_ms);

    loop {
        // Check for file changes with timeout
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(()) => {
                // Debounce
                if last_rebuild.elapsed() < debounce_duration {
                    continue;
                }

                if rebuild_needed.swap(false, Ordering::SeqCst) {
                    if config.clear {
                        let _ = term.clear_screen();
                    }

                    println!(
                        "\n{} Change detected, rebuilding...",
                        style("🔄").bold()
                    );

                    // Kill existing process
                    if let Some(mut c) = child.take() {
                        let _ = c.kill();
                        let _ = c.wait();
                    }

                    // Rebuild and restart
                    if build_project(config.verbose) {
                        child = start_server(&env_vars);
                    }

                    last_rebuild = Instant::now();
                    println!(
                        "\n{} Watching for changes...\n",
                        style("👀").bold()
                    );
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Check if child has exited
                if let Some(ref mut c) = child {
                    match c.try_wait() {
                        Ok(Some(status)) => {
                            if status.success() {
                                println!(
                                    "\n{} Server exited normally",
                                    style("ℹ").blue().bold()
                                );
                            } else {
                                println!(
                                    "\n{} Server exited with error ({})",
                                    style("⚠").yellow().bold(),
                                    status
                                );
                            }
                            println!(
                                "{} Waiting for changes...\n",
                                style("👀").bold()
                            );
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
                        }
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break;
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
    let result = client.list_tasks(status_filter, None)?;
    let mut tasks = result.tasks;

    // Apply limit
    tasks.truncate(limit);

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
    let all_tasks = client.list_tasks(None, None)?;

    let mut pending = 0;
    let mut running = 0;
    let mut completed = 0;
    let mut failed = 0;
    let mut cancelled = 0;

    for task in &all_tasks.tasks {
        match task.status {
            TaskStatus::Pending => pending += 1,
            TaskStatus::Running => running += 1,
            TaskStatus::Completed => completed += 1,
            TaskStatus::Failed => failed += 1,
            TaskStatus::Cancelled => cancelled += 1,
        }
    }

    let total = all_tasks.tasks.len();
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
        println!("Would add to {config_path}:\n\n{snippet_str}");
        return Ok(());
    }

    // Read existing config or create new one
    let mut existing_config: serde_json::Value = if std::path::Path::new(&config_path).exists() {
        let content = std::fs::read_to_string(&config_path).map_err(|e| {
            fastmcp_core::McpError::internal_error(format!("Failed to read config: {e}"))
        })?;
        serde_json::from_str(&content).unwrap_or(serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    // Merge the server config
    if !existing_config.is_object() {
        existing_config = serde_json::json!({});
    }

    let obj = existing_config.as_object_mut().unwrap();
    if !obj.contains_key("mcpServers") {
        obj.insert("mcpServers".to_string(), serde_json::json!({}));
    }

    let mcp_servers = obj.get_mut("mcpServers").unwrap();
    if let Some(servers_obj) = mcp_servers.as_object_mut() {
        servers_obj.insert(
            config.0.clone(),
            serde_json::to_value(&config.1).unwrap_or(serde_json::json!({})),
        );
    }

    // Write back
    let new_content = serde_json::to_string_pretty(&existing_config).map_err(|e| {
        fastmcp_core::McpError::internal_error(format!("JSON serialization error: {e}"))
    })?;

    // Create parent directory if needed
    if let Some(parent) = std::path::Path::new(&config_path).parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            fastmcp_core::McpError::internal_error(format!(
                "Failed to create config directory: {e}"
            ))
        })?;
    }

    std::fs::write(&config_path, new_content).map_err(|e| {
        fastmcp_core::McpError::internal_error(format!("Failed to write config: {e}"))
    })?;

    println!("Added '{name}' to {config_path}", name = config.0);
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
        println!("Would add to {config_path}:\n\n{snippet_str}");
        return Ok(());
    }

    // Similar merge logic as Claude Desktop
    let mut existing_config: serde_json::Value = if std::path::Path::new(&config_path).exists() {
        let content = std::fs::read_to_string(&config_path).map_err(|e| {
            fastmcp_core::McpError::internal_error(format!("Failed to read config: {e}"))
        })?;
        serde_json::from_str(&content).unwrap_or(serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    if !existing_config.is_object() {
        existing_config = serde_json::json!({});
    }

    let obj = existing_config.as_object_mut().unwrap();
    if !obj.contains_key("mcpServers") {
        obj.insert("mcpServers".to_string(), serde_json::json!({}));
    }

    let mcp_servers = obj.get_mut("mcpServers").unwrap();
    if let Some(servers_obj) = mcp_servers.as_object_mut() {
        servers_obj.insert(
            config.0.clone(),
            serde_json::to_value(&config.1).unwrap_or(serde_json::json!({})),
        );
    }

    let new_content = serde_json::to_string_pretty(&existing_config).map_err(|e| {
        fastmcp_core::McpError::internal_error(format!("JSON serialization error: {e}"))
    })?;

    if let Some(parent) = std::path::Path::new(&config_path).parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            fastmcp_core::McpError::internal_error(format!(
                "Failed to create config directory: {e}"
            ))
        })?;
    }

    std::fs::write(&config_path, new_content).map_err(|e| {
        fastmcp_core::McpError::internal_error(format!("Failed to write config: {e}"))
    })?;

    println!("Added '{name}' to {config_path}", name = config.0);
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
        println!("Would add to VS Code settings.json:\n\n{snippet_str}");
        println!("\nSettings path: {config_path}");
        return Ok(());
    }

    // VSCode settings.json is more complex - just print instructions
    println!(
        "To add '{name}' to Cline, add the following to your VS Code settings.json:",
        name = config.0
    );
    println!("\n{snippet_str}");
    println!("\nSettings file: {config_path}");

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
