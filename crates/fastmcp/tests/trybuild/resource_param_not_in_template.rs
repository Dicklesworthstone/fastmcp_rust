// Tests that #[resource] with a parameter not in the URI template produces a compile error.

use fastmcp_rust::resource;

#[resource(uri = "file://{path}")]
fn my_resource(path: String, extra: String) -> String {
    format!("{path}/{extra}")
}

fn main() {}
