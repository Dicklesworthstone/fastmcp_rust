// A prompt final result must carry the prompt payload, not a resource payload.

use fastmcp_rust::prompt;

#[prompt]
fn final_prompt() -> fastmcp_rust::CompleteResult<fastmcp_rust::ReadResourceResult> {
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
