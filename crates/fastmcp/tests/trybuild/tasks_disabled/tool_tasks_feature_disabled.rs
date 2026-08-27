use fastmcp_rust::tool;

#[tool(tasks)]
fn bare_tasks_opt_in() -> fastmcp_rust::FinalToolOutcome {
    complete_outcome()
}

#[tool(tasks = true)]
fn assigned_tasks_opt_in() -> fastmcp_rust::FinalToolOutcome {
    complete_outcome()
}

#[tool(tasks())]
fn invoked_tasks_opt_in() -> fastmcp_rust::FinalToolOutcome {
    complete_outcome()
}

fn complete_outcome() -> fastmcp_rust::FinalToolOutcome {
    fastmcp_rust::FinalToolOutcome::Complete(fastmcp_rust::CompleteResult::new(
        fastmcp_rust::FinalCallToolResult {
            content: Vec::new(),
            is_error: false,
            structured_content: None,
        },
        fastmcp_rust::ResultMeta::empty(),
    ))
}

fn main() {}
