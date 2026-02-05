// Tests that #[resource] with invalid timeout produces a compile error.

use fastmcp_rust::resource;

#[resource(uri = "test://data", timeout = "xyz")]
fn my_resource() -> String {
    "data".to_string()
}

fn main() {}
