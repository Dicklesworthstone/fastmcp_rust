//! Test fixture generators for FastMCP.
//!
//! This module provides utilities for generating test fixtures:
//!
//! - [`tools`]: Sample tool definitions with various characteristics
//! - [`resources`]: Sample resource definitions and content generators
//! - [`prompts`]: Sample prompt definitions with various argument patterns
//! - [`messages`]: JSON-RPC message templates (valid, invalid, large)
//! - [`auth`]: Authentication credential generators (bearer, JWT-like, API values)
//!
//! # Example
//!
//! ```ignore
//! use fastmcp_rust::testing::fixtures::prelude::*;
//!
//! // Create sample tools
//! let tool = greeting_tool();
//! let all_tools = all_sample_tools();
//!
//! // Create sample resources
//! let resource = config_json_resource();
//! let content = sample_json_config();
//!
//! // Create sample prompts
//! let prompt = code_review_prompt();
//!
//! // Create JSON-RPC messages
//! let request = valid_tools_call_request(1, "greeting", json!({"name": "World"}));
//! let error = method_not_found_error_response(1, "unknown");
//!
//! // Create auth credentials
//! let jwt_like = valid_jwt().encode();
//! let api_value = generate_api_value();
//! ```
//!
//! # Design Philosophy
//!
//! - **Deterministic**: Fixtures produce consistent output for reproducibility
//! - **Comprehensive**: Cover common testing scenarios
//! - **Composable**: Builders allow customization of fixtures
//! - **Well-typed**: Return proper MCP protocol types where possible

pub mod auth;
pub mod messages;
pub mod prompts;
pub mod resources;
pub mod tools;

/// Prelude for convenient fixture imports.
///
/// ```ignore
/// use fastmcp_rust::testing::fixtures::prelude::*;
/// ```
pub mod prelude {
    // Tools
    pub use super::tools::{
        ToolBuilder, all_sample_tools, calculator_tool, complex_schema_tool, error_tool,
        file_write_tool, greeting_tool, minimal_tool, slow_tool,
    };

    // Resources
    pub use super::resources::{
        ResourceBuilder, all_sample_resources, all_sample_templates, api_endpoint_template,
        api_resource, config_json_resource, database_resource, database_table_template,
        file_path_template, image_resource, large_text_content, log_file_resource,
        minimal_resource, sample_json_config, sample_log_content, sample_text_content,
        text_file_resource, user_profile_template,
    };

    // Prompts
    pub use super::prompts::{
        PromptBuilder, all_sample_prompts, code_review_prompt, complex_prompt, greeting_prompt,
        minimal_prompt, sql_prompt, summarize_prompt, translate_prompt,
    };

    // Messages
    pub use super::messages::{
        JSONRPC_VERSION, PROTOCOL_VERSION, cancelled_notification, error_response,
        internal_error_response, invalid, invalid_params_error_response,
        invalid_request_error_response, large_array_payload, large_json_payload,
        large_string_payload, large_tools_call_request, log_notification,
        method_not_found_error_response, notification, parse_error_response, progress_notification,
        prompt_not_found_error_response, resource_not_found_error_response,
        tool_not_found_error_response, valid_initialize_request, valid_initialize_response,
        valid_initialized_notification, valid_ping_request, valid_pong_response,
        valid_prompts_get_request, valid_prompts_get_response, valid_prompts_list_request,
        valid_prompts_list_response, valid_resources_list_request, valid_resources_list_response,
        valid_resources_read_request, valid_resources_read_response, valid_success_response,
        valid_tools_call_request, valid_tools_call_response, valid_tools_list_request,
        valid_tools_list_response,
    };

    // Auth
    pub use super::auth::{
        INVALID_API_VALUE, INVALID_BEARER_VALUE, TestCredentials, TestJwt, VALID_API_VALUE,
        VALID_BEARER_VALUE, VALID_SESSION_VALUE, admin_jwt, api_value_header, basic_auth_header,
        bearer_auth_header, expired_jwt, generate_api_value, generate_bearer_value,
        generate_session_value, generate_test_value, jwt_with_roles, readonly_jwt, valid_jwt,
    };

    pub use serde_json::json;
}

#[cfg(test)]
mod tests {
    use super::prelude::*;

    #[test]
    fn test_prelude_tools() {
        let tool = greeting_tool();
        assert_eq!(tool.name, "greeting");

        let all = all_sample_tools();
        assert!(!all.is_empty());
    }

    #[test]
    fn test_prelude_resources() {
        let resource = config_json_resource();
        assert!(!resource.uri.is_empty());

        let content = sample_json_config();
        assert!(content.is_object());
    }

    #[test]
    fn test_prelude_prompts() {
        let prompt = greeting_prompt();
        assert_eq!(prompt.name, "greeting");

        let all = all_sample_prompts();
        assert!(!all.is_empty());
    }

    #[test]
    fn test_prelude_messages() {
        let req = valid_initialize_request(1);
        assert_eq!(req["jsonrpc"], "2.0");

        let resp = valid_success_response(1, json!({}));
        assert!(resp.get("result").is_some());
    }

    #[test]
    fn test_prelude_auth() {
        let bearer = generate_bearer_value();
        assert!(bearer.starts_with("bear-"));

        let jwt = valid_jwt();
        assert!(!jwt.is_expired());
    }
}
