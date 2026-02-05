// Tests that #[prompt] with unknown attribute produces a compile error.

use fastmcp_rust::prompt;
use fastmcp_rust::{Content, PromptMessage, Role};

#[prompt(unknown = "value")]
fn my_prompt() -> Vec<PromptMessage> {
    vec![]
}

fn main() {}
