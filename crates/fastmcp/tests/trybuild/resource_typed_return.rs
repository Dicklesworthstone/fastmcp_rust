// A resource final result must carry the resource payload, not a prompt payload.

use fastmcp_rust::resource;

#[resource(uri = "final://resource")]
fn final_resource() -> fastmcp_rust::CompleteResult<fastmcp_rust::GetPromptResult> {
    fastmcp_rust::CompleteResult::new(
        fastmcp_rust::GetPromptResult {
            description: None,
            messages: Vec::new(),
            meta: None,
            additional: std::collections::BTreeMap::new(),
        },
        fastmcp_rust::ResultMeta::empty(),
    )
}

fn main() {}
