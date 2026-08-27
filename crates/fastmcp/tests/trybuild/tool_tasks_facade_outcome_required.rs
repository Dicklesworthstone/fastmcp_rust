// The renamed-facade positive probe differs only in its canonical task result.

use fastmcp_rust::tool;

#[tool(tasks)]
fn renamed_facade_final_task_tool()
-> fastmcp_rust::CompleteResult<fastmcp_rust::FinalCallToolResult> {
    fastmcp_rust::CompleteResult::new(
        fastmcp_rust::FinalCallToolResult {
            content: Vec::new(),
            is_error: false,
            structured_content: None,
        },
        fastmcp_rust::ResultMeta::empty(),
    )
}

fn main() {}
