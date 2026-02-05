// Tests that #[prompt] with invalid timeout produces a compile error.

use fastmcp_rust::prompt;
use fastmcp_rust::{PromptMessage};

#[prompt(timeout = "abc")]
fn my_prompt() -> Vec<PromptMessage> {
    vec![]
}

fn main() {}
