//! Server info tables

use rich_rust::prelude::*;
use fastmcp_protocol::{Tool, Resource, Prompt};
use crate::console::FastMcpConsole;

/// Display registered tools in a table
pub fn render_tools_table(tools: &[Tool], console: &FastMcpConsole) {
    if tools.is_empty() {
        return;
    }

    if !console.is_rich() {
        eprintln!("Registered tools:");
        for tool in tools {
            eprintln!("  - {}: {}", tool.name, tool.description.as_deref().unwrap_or("-"));
        }
        return;
    }

    let theme = console.theme();

    let mut table = Table::new()
        .title("Registered Tools")
        .title_style(theme.header_style.clone())
        .box_style(&rich_rust::r#box::ROUNDED)
        .border_style(theme.border_style.clone());
        
    table.add_column(Column::new("Name").style(theme.key_style.clone()));
    table.add_column(Column::new("Description"));

    for tool in tools {
        table.add_row_cells([
            &tool.name,
            tool.description.as_deref().unwrap_or("-"),
        ]);
    }

    console.render(&table);
}

/// Display registered resources in a table
pub fn render_resources_table(_resources: &[Resource], _console: &FastMcpConsole) {
    // Placeholder
}

/// Display registered prompts in a table
pub fn render_prompts_table(_prompts: &[Prompt], _console: &FastMcpConsole) {
    // Placeholder
}