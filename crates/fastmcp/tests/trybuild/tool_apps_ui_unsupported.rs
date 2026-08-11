use fastmcp_derive::tool;

#[tool(ui(resource_uri = "ui://weather/dashboard"))]
fn unsupported_apps_ui_syntax() -> String {
    "weather".to_owned()
}

fn main() {}
