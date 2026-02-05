// Tests that #[tool] with zero-duration timeout produces a compile error.

use fastmcp_rust::tool;

#[tool(timeout = "0s")]
fn my_tool() -> String {
    "ok".to_string()
}

fn main() {}
