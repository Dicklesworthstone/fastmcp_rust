// Tests that #[resource] without uri attribute produces a compile error.

use fastmcp_rust::resource;

#[resource]
fn my_resource() -> String {
    "data".to_string()
}

fn main() {}
