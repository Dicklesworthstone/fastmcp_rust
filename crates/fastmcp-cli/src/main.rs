//! FastMCP CLI - Command-line tooling for MCP servers.
//!
//! Commands:
//! - `run` - Run an MCP server
//! - `inspect` - Inspect a server's capabilities
//! - `install` - Install server config for Claude Desktop etc.

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
    },
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
