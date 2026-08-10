// The renamed-facade positive probe differs only in its canonical task result.

use fastmcp_rust::tool;

#[tool(tasks)]
fn renamed_facade_final_task_tool()
-> fastmcp_rust::CompleteResult<fastmcp_rust::FinalCallToolResult> {
    unreachable!()
}

fn main() {}
