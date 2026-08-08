// A resource final result must carry the resource payload, not a prompt payload.

use fastmcp_rust::resource;

#[resource(uri = "final://resource")]
fn final_resource() -> fastmcp_rust::CompleteResult<fastmcp_rust::GetPromptResult> {
    unimplemented!()
}

fn main() {}
