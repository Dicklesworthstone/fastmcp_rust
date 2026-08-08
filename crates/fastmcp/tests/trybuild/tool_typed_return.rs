// A final tool result must carry the final tool payload, not a resource payload.

use fastmcp_rust::tool;

#[tool]
fn final_tool() -> fastmcp_rust::CompleteResult<fastmcp_rust::ReadResourceResult> {
    unimplemented!()
}

fn main() {}
