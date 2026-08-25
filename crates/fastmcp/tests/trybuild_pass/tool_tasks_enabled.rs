use fastmcp_rust::{ToolHandler, tool};

#[tool(tasks)]
fn enabled_tasks_opt_in() -> fastmcp_rust::FinalToolOutcome {
    unreachable!()
}

fn main() {
    assert!(EnabledTasksOptIn.declares_final_tasks());
}
