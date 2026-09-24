use asupersync::runtime::RuntimeBuilder;
use fastmcp_rust::{Cx, McpContext, McpResult, tool};

#[tool]
fn my_tool(ctx: &McpContext, input: String) -> McpResult<String> {
    ctx.checkpoint()?;
    Ok(input)
}

#[test]
fn test_my_tool() {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("create test runtime");
    runtime.block_on(async {
        let ctx = McpContext::new(Cx::current().expect("test context"), 1);
        let result = my_tool(&ctx, "input".to_string());
        assert_eq!(result.unwrap(), "input");
    });
}
