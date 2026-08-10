use fastmcp_rust::tool;

#[tool(tasks)]
fn bare_tasks_opt_in() -> fastmcp_rust::FinalToolOutcome {
    unreachable!()
}

#[tool(tasks = true)]
fn assigned_tasks_opt_in() -> fastmcp_rust::FinalToolOutcome {
    unreachable!()
}

#[tool(tasks())]
fn invoked_tasks_opt_in() -> fastmcp_rust::FinalToolOutcome {
    unreachable!()
}

fn main() {}
