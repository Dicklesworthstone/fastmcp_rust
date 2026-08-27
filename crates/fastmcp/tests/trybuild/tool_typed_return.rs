// A final tool result must carry the final tool payload, not a resource payload.

use fastmcp_rust::tool;

#[tool]
fn final_tool() -> fastmcp_rust::CompleteResult<fastmcp_rust::ReadResourceResult> {
    fastmcp_rust::CompleteResult::new(
        fastmcp_rust::ReadResourceResult {
            contents: Vec::new(),
            meta: None,
            additional: std::collections::BTreeMap::new(),
        },
        fastmcp_rust::ResultMeta::empty(),
    )
}

fn main() {}
