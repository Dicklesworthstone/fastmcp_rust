use fastmcp_rust::{ToolHandler, tool};

#[tool(tasks)]
fn enabled_tasks_opt_in() -> fastmcp_rust::FinalToolOutcome {
    fastmcp_rust::FinalToolOutcome::Complete(fastmcp_rust::CompleteResult::new(
        fastmcp_rust::FinalCallToolResult {
            content: Vec::new(),
            is_error: false,
            structured_content: None,
        },
        fastmcp_rust::ResultMeta::empty(),
    ))
}

fn main() {
    assert!(EnabledTasksOptIn.declares_final_tasks());
}
