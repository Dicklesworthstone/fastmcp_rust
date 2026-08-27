// Final Tasks opt-in requires the final tool-outcome algebra, not only a
// complete final tool result.

use fastmcp_rust::tool;

#[tool(tasks)]
fn task_tool() -> fastmcp_rust::CompleteResult<fastmcp_rust::FinalCallToolResult> {
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
