use fastmcp_rust::{FinalToolOutcome, ToolHandler, tool};

#[tool(tasks)]
fn enabled_tasks_opt_in() -> FinalToolOutcome {
    unreachable!()
}

fn main() {
    assert!(EnabledTasksOptIn.declares_final_tasks());
}
