// Tests that #[tool] with unknown attribute produces a compile error.

use fastmcp_rust::tool;

#[tool(invalid_attr = "foo")]
fn my_tool() -> String {
    "ok".to_string()
}

fn main() {}
