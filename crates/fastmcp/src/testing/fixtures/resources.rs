//! Sample resource definitions for testing.
//!
//! Provides pre-built resource fixtures with various characteristics:
//! - Simple text resources
//! - JSON configuration resources
//! - Binary resources (images, etc.)
//! - Large resources for stress testing

use fastmcp_protocol::{Resource, ResourceTemplate};
use serde_json::json;

/// Creates a simple text file resource.
///
/// # Example
///
/// ```ignore
/// use fastmcp_rust::testing::fixtures::resources::text_file_resource;
///
/// let resource = text_file_resource();
/// assert!(resource.uri.starts_with("file://"));
/// ```
#[must_use]
pub fn text_file_resource() -> Resource {
    Resource {
        uri: "file:///test/sample.txt".to_string(),
        name: "sample.txt".to_string(),
        description: Some("A sample text file for testing".to_string()),
        mime_type: Some("text/plain".to_string()),
        icon: None,
        version: Some("1.0.0".to_string()),
        tags: vec!["text".to_string(), "sample".to_string()],
    }
}

/// Creates a JSON configuration resource.
///
/// # Example
///
/// ```ignore
/// use fastmcp_rust::testing::fixtures::resources::config_json_resource;
///
/// let resource = config_json_resource();
/// assert_eq!(resource.mime_type, Some("application/json".to_string()));
/// ```
#[must_use]
pub fn config_json_resource() -> Resource {
    Resource {
        uri: "file:///config/settings.json".to_string(),
        name: "settings.json".to_string(),
        description: Some("Application configuration in JSON format".to_string()),
        mime_type: Some("application/json".to_string()),
        icon: None,
        version: Some("2.1.0".to_string()),
        tags: vec!["config".to_string(), "json".to_string()],
    }
}

/// Creates a log file resource.
///
/// # Example
///
/// ```ignore
/// use fastmcp_rust::testing::fixtures::resources::log_file_resource;
///
/// let resource = log_file_resource();
/// assert!(resource.name.contains("log"));
/// ```
#[must_use]
pub fn log_file_resource() -> Resource {
    Resource {
        uri: "file:///var/log/app.log".to_string(),
        name: "app.log".to_string(),
        description: Some("Application log file".to_string()),
        mime_type: Some("text/plain".to_string()),
        icon: None,
        version: None,
        tags: vec!["log".to_string(), "monitoring".to_string()],
    }
}

/// Creates a database resource.
///
/// # Example
///
/// ```ignore
/// use fastmcp_rust::testing::fixtures::resources::database_resource;
///
/// let resource = database_resource();
/// assert!(resource.uri.starts_with("db://"));
/// ```
#[must_use]
pub fn database_resource() -> Resource {
    Resource {
        uri: "db://localhost/test_db/users".to_string(),
        name: "users table".to_string(),
        description: Some("User records from the database".to_string()),
        mime_type: Some("application/json".to_string()),
        icon: None,
        version: None,
        tags: vec!["database".to_string(), "users".to_string()],
    }
}

/// Creates an HTTP API resource.
///
/// # Example
///
/// ```ignore
/// use fastmcp_rust::testing::fixtures::resources::api_resource;
///
/// let resource = api_resource();
/// assert!(resource.uri.starts_with("https://"));
/// ```
#[must_use]
pub fn api_resource() -> Resource {
    Resource {
        uri: "https://api.example.com/v1/data".to_string(),
        name: "API Data".to_string(),
        description: Some("Data from external API".to_string()),
        mime_type: Some("application/json".to_string()),
        icon: None,
        version: Some("1.0.0".to_string()),
        tags: vec!["api".to_string(), "external".to_string()],
    }
}

/// Creates a minimal resource with no optional fields.
#[must_use]
pub fn minimal_resource() -> Resource {
    Resource {
        uri: "file:///minimal".to_string(),
        name: "minimal".to_string(),
        description: None,
        mime_type: None,
        icon: None,
        version: None,
        tags: vec![],
    }
}

/// Creates a binary image resource.
#[must_use]
pub fn image_resource() -> Resource {
    Resource {
        uri: "file:///images/logo.png".to_string(),
        name: "logo.png".to_string(),
        description: Some("Application logo image".to_string()),
        mime_type: Some("image/png".to_string()),
        icon: None,
        version: Some("1.0.0".to_string()),
        tags: vec!["image".to_string(), "binary".to_string()],
    }
}

/// Returns a collection of all sample resources.
#[must_use]
pub fn all_sample_resources() -> Vec<Resource> {
    vec![
        text_file_resource(),
        config_json_resource(),
        log_file_resource(),
        database_resource(),
        api_resource(),
        minimal_resource(),
        image_resource(),
    ]
}

// ============================================================================
// Resource Templates
// ============================================================================

/// Creates a file path template.
///
/// # Example
///
/// ```ignore
/// use fastmcp_rust::testing::fixtures::resources::file_path_template;
///
/// let template = file_path_template();
/// assert!(template.uri_template.contains("{path}"));
/// ```
#[must_use]
pub fn file_path_template() -> ResourceTemplate {
    ResourceTemplate {
        uri_template: "file:///{path}".to_string(),
        name: "File Path".to_string(),
        description: Some("Access any file by path".to_string()),
        mime_type: None,
        icon: None,
        version: Some("1.0.0".to_string()),
        tags: vec!["file".to_string(), "template".to_string()],
    }
}

/// Creates a database table template.
#[must_use]
pub fn database_table_template() -> ResourceTemplate {
    ResourceTemplate {
        uri_template: "db://{host}/{database}/{table}".to_string(),
        name: "Database Table".to_string(),
        description: Some("Access any database table".to_string()),
        mime_type: Some("application/json".to_string()),
        icon: None,
        version: Some("1.0.0".to_string()),
        tags: vec!["database".to_string(), "template".to_string()],
    }
}

/// Creates an API endpoint template.
#[must_use]
pub fn api_endpoint_template() -> ResourceTemplate {
    ResourceTemplate {
        uri_template: "https://api.example.com/{version}/{resource}".to_string(),
        name: "API Endpoint".to_string(),
        description: Some("Access versioned API endpoints".to_string()),
        mime_type: Some("application/json".to_string()),
        icon: None,
        version: Some("1.0.0".to_string()),
        tags: vec!["api".to_string(), "template".to_string()],
    }
}

/// Creates a user profile template.
#[must_use]
pub fn user_profile_template() -> ResourceTemplate {
    ResourceTemplate {
        uri_template: "user://{user_id}/profile".to_string(),
        name: "User Profile".to_string(),
        description: Some("Access user profile by ID".to_string()),
        mime_type: Some("application/json".to_string()),
        icon: None,
        version: None,
        tags: vec!["user".to_string(), "profile".to_string()],
    }
}

/// Returns all sample resource templates.
#[must_use]
pub fn all_sample_templates() -> Vec<ResourceTemplate> {
    vec![
        file_path_template(),
        database_table_template(),
        api_endpoint_template(),
        user_profile_template(),
    ]
}

// ============================================================================
// Resource Content Generators
// ============================================================================

/// Generates sample text content.
#[must_use]
pub fn sample_text_content() -> String {
    "Hello, World!\nThis is sample text content for testing.\nLine 3.\nLine 4.".to_string()
}

/// Generates sample JSON configuration content.
#[must_use]
pub fn sample_json_config() -> serde_json::Value {
    json!({
        "version": "1.0.0",
        "settings": {
            "debug": false,
            "log_level": "info",
            "max_connections": 100
        },
        "features": {
            "experimental": false,
            "beta": true
        },
        "database": {
            "host": "localhost",
            "port": 5432,
            "name": "test_db"
        }
    })
}

/// Generates sample log content.
#[must_use]
pub fn sample_log_content() -> String {
    [
        "[2024-01-15 10:30:00] INFO: Server started",
        "[2024-01-15 10:30:01] INFO: Listening on port 8080",
        "[2024-01-15 10:30:05] DEBUG: Connection accepted from 127.0.0.1",
        "[2024-01-15 10:30:06] INFO: Request processed in 15ms",
        "[2024-01-15 10:30:10] WARN: High memory usage detected",
        "[2024-01-15 10:30:15] ERROR: Connection timeout",
    ]
    .join("\n")
}

/// Generates large text content for stress testing.
///
/// # Arguments
///
/// * `size_kb` - Approximate size in kilobytes
#[must_use]
pub fn large_text_content(size_kb: usize) -> String {
    let line = "This is a line of text for stress testing. ".repeat(10);
    let lines_needed = (size_kb * 1024) / line.len() + 1;
    (0..lines_needed)
        .map(|i| format!("[Line {i:06}] {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Builder for customizing resource fixtures.
#[derive(Debug, Clone)]
pub struct ResourceBuilder {
    uri: String,
    name: String,
    description: Option<String>,
    mime_type: Option<String>,
    version: Option<String>,
    tags: Vec<String>,
}

impl ResourceBuilder {
    /// Creates a new resource builder.
    #[must_use]
    pub fn new(uri: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            name: name.into(),
            description: None,
            mime_type: None,
            version: None,
            tags: Vec::new(),
        }
    }

    /// Sets the description.
    #[must_use]
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Sets the MIME type.
    #[must_use]
    pub fn mime_type(mut self, mime: impl Into<String>) -> Self {
        self.mime_type = Some(mime.into());
        self
    }

    /// Sets the version.
    #[must_use]
    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Sets tags.
    #[must_use]
    pub fn tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    /// Builds the resource.
    #[must_use]
    pub fn build(self) -> Resource {
        Resource {
            uri: self.uri,
            name: self.name,
            description: self.description,
            mime_type: self.mime_type,
            icon: None,
            version: self.version,
            tags: self.tags,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_text_file_resource() {
        let resource = text_file_resource();
        assert!(resource.uri.starts_with("file://"));
        assert_eq!(resource.mime_type, Some("text/plain".to_string()));
    }

    #[test]
    fn test_config_json_resource() {
        let resource = config_json_resource();
        assert_eq!(resource.mime_type, Some("application/json".to_string()));
    }

    #[test]
    fn test_database_resource() {
        let resource = database_resource();
        assert!(resource.uri.starts_with("db://"));
    }

    #[test]
    fn test_api_resource() {
        let resource = api_resource();
        assert!(resource.uri.starts_with("https://"));
    }

    #[test]
    fn test_minimal_resource() {
        let resource = minimal_resource();
        assert!(resource.description.is_none());
        assert!(resource.mime_type.is_none());
        assert!(resource.tags.is_empty());
    }

    #[test]
    fn test_all_sample_resources() {
        let resources = all_sample_resources();
        assert!(resources.len() >= 5);

        // Verify uniqueness of URIs
        let uris: Vec<_> = resources.iter().map(|r| &r.uri).collect();
        let unique: std::collections::HashSet<_> = uris.iter().collect();
        assert_eq!(uris.len(), unique.len());
    }

    #[test]
    fn test_file_path_template() {
        let template = file_path_template();
        assert!(template.uri_template.contains("{path}"));
    }

    #[test]
    fn test_database_table_template() {
        let template = database_table_template();
        assert!(template.uri_template.contains("{host}"));
        assert!(template.uri_template.contains("{database}"));
        assert!(template.uri_template.contains("{table}"));
    }

    #[test]
    fn test_all_sample_templates() {
        let templates = all_sample_templates();
        assert!(templates.len() >= 3);
    }

    #[test]
    fn test_sample_text_content() {
        let content = sample_text_content();
        assert!(content.contains("Hello, World!"));
    }

    #[test]
    fn test_sample_json_config() {
        let config = sample_json_config();
        assert!(config.get("version").is_some());
        assert!(config.get("settings").is_some());
    }

    #[test]
    fn test_sample_log_content() {
        let log = sample_log_content();
        assert!(log.contains("INFO"));
        assert!(log.contains("ERROR"));
    }

    #[test]
    fn test_large_text_content() {
        let content = large_text_content(10);
        // Should be approximately 10KB
        assert!(content.len() >= 9 * 1024);
        assert!(content.len() <= 12 * 1024);
    }

    #[test]
    fn test_resource_builder() {
        let resource = ResourceBuilder::new("file:///test", "test")
            .description("A test resource")
            .mime_type("text/plain")
            .version("1.0.0")
            .tags(vec!["test".to_string()])
            .build();

        assert_eq!(resource.uri, "file:///test");
        assert_eq!(resource.name, "test");
        assert_eq!(resource.description, Some("A test resource".to_string()));
    }
}
