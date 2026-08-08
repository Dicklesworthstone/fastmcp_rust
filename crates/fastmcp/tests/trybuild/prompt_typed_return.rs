// A prompt final result must carry the prompt payload, not a resource payload.

use fastmcp_rust::prompt;

#[prompt]
fn final_prompt() -> fastmcp_rust::CompleteResult<fastmcp_rust::ReadResourceResult> {
    unimplemented!()
}

fn main() {}
