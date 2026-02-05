// Tests that #[resource] with parameters but no URI template produces a compile error.

use fastmcp_rust::{McpContext, resource};

#[resource(uri = "static://data")]
fn my_resource(name: String) -> String {
    format!("data for {name}")
}

fn main() {}
