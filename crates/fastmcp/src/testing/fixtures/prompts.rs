//! Sample prompt definitions for testing.
//!
//! Provides pre-built prompt fixtures with various characteristics:
//! - Simple prompts with single arguments
//! - Complex prompts with multiple arguments
//! - Prompts with optional arguments

use fastmcp_protocol::{Prompt, PromptArgument};

/// Creates a simple greeting prompt.
///
/// Takes a `name` argument and returns a greeting.
///
/// # Example
///
/// ```ignore
/// use fastmcp_rust::testing::fixtures::prompts::greeting_prompt;
///
/// let prompt = greeting_prompt();
/// assert_eq!(prompt.name, "greeting");
/// ```
#[must_use]
pub fn greeting_prompt() -> Prompt {
    Prompt {
        name: "greeting".to_string(),
        description: Some("Generate a greeting for a person".to_string()),
        arguments: vec![PromptArgument {
            name: "name".to_string(),
            description: Some("The name of the person to greet".to_string()),
            required: true,
        }],
        icon: None,
        version: Some("1.0.0".to_string()),
        tags: vec!["greeting".to_string(), "simple".to_string()],
    }
}

/// Creates a code review prompt.
///
/// Takes code and language arguments.
#[must_use]
pub fn code_review_prompt() -> Prompt {
    Prompt {
        name: "code_review".to_string(),
        description: Some("Review code for quality, bugs, and improvements".to_string()),
        arguments: vec![
            PromptArgument {
                name: "code".to_string(),
                description: Some("The code to review".to_string()),
                required: true,
            },
            PromptArgument {
                name: "language".to_string(),
                description: Some(
                    "Programming language (e.g., rust, python, javascript)".to_string(),
                ),
                required: true,
            },
            PromptArgument {
                name: "focus".to_string(),
                description: Some(
                    "Specific areas to focus on (e.g., security, performance)".to_string(),
                ),
                required: false,
            },
        ],
        icon: None,
        version: Some("1.0.0".to_string()),
        tags: vec!["code".to_string(), "review".to_string()],
    }
}

/// Creates a summarization prompt.
#[must_use]
pub fn summarize_prompt() -> Prompt {
    Prompt {
        name: "summarize".to_string(),
        description: Some("Summarize text content".to_string()),
        arguments: vec![
            PromptArgument {
                name: "text".to_string(),
                description: Some("The text to summarize".to_string()),
                required: true,
            },
            PromptArgument {
                name: "max_length".to_string(),
                description: Some("Maximum length of the summary in words".to_string()),
                required: false,
            },
            PromptArgument {
                name: "style".to_string(),
                description: Some("Summary style: brief, detailed, or bullet-points".to_string()),
                required: false,
            },
        ],
        icon: None,
        version: Some("1.0.0".to_string()),
        tags: vec!["text".to_string(), "summarize".to_string()],
    }
}

/// Creates a translation prompt.
#[must_use]
pub fn translate_prompt() -> Prompt {
    Prompt {
        name: "translate".to_string(),
        description: Some("Translate text between languages".to_string()),
        arguments: vec![
            PromptArgument {
                name: "text".to_string(),
                description: Some("The text to translate".to_string()),
                required: true,
            },
            PromptArgument {
                name: "source_language".to_string(),
                description: Some("Source language (or 'auto' for detection)".to_string()),
                required: false,
            },
            PromptArgument {
                name: "target_language".to_string(),
                description: Some("Target language for translation".to_string()),
                required: true,
            },
        ],
        icon: None,
        version: Some("1.0.0".to_string()),
        tags: vec!["text".to_string(), "translation".to_string()],
    }
}

/// Creates a minimal prompt with no arguments.
#[must_use]
pub fn minimal_prompt() -> Prompt {
    Prompt {
        name: "minimal".to_string(),
        description: None,
        arguments: vec![],
        icon: None,
        version: None,
        tags: vec![],
    }
}

/// Creates a prompt with many optional arguments.
#[must_use]
pub fn complex_prompt() -> Prompt {
    Prompt {
        name: "complex_generation".to_string(),
        description: Some("Generate content with many customization options".to_string()),
        arguments: vec![
            PromptArgument {
                name: "topic".to_string(),
                description: Some("The main topic".to_string()),
                required: true,
            },
            PromptArgument {
                name: "tone".to_string(),
                description: Some("Writing tone: formal, casual, technical".to_string()),
                required: false,
            },
            PromptArgument {
                name: "audience".to_string(),
                description: Some("Target audience".to_string()),
                required: false,
            },
            PromptArgument {
                name: "length".to_string(),
                description: Some("Desired length: short, medium, long".to_string()),
                required: false,
            },
            PromptArgument {
                name: "format".to_string(),
                description: Some("Output format: prose, bullet-points, numbered-list".to_string()),
                required: false,
            },
            PromptArgument {
                name: "examples".to_string(),
                description: Some("Include examples: yes, no".to_string()),
                required: false,
            },
        ],
        icon: None,
        version: Some("2.0.0".to_string()),
        tags: vec!["generation".to_string(), "complex".to_string()],
    }
}

/// Creates a SQL generation prompt.
#[must_use]
pub fn sql_prompt() -> Prompt {
    Prompt {
        name: "sql_query".to_string(),
        description: Some("Generate SQL queries from natural language".to_string()),
        arguments: vec![
            PromptArgument {
                name: "description".to_string(),
                description: Some("Natural language description of the query".to_string()),
                required: true,
            },
            PromptArgument {
                name: "schema".to_string(),
                description: Some("Database schema definition".to_string()),
                required: true,
            },
            PromptArgument {
                name: "dialect".to_string(),
                description: Some("SQL dialect: postgresql, mysql, sqlite".to_string()),
                required: false,
            },
        ],
        icon: None,
        version: Some("1.0.0".to_string()),
        tags: vec!["sql".to_string(), "database".to_string()],
    }
}

/// Returns all sample prompts.
#[must_use]
pub fn all_sample_prompts() -> Vec<Prompt> {
    vec![
        greeting_prompt(),
        code_review_prompt(),
        summarize_prompt(),
        translate_prompt(),
        minimal_prompt(),
        complex_prompt(),
        sql_prompt(),
    ]
}

/// Builder for customizing prompt fixtures.
#[derive(Debug, Clone)]
pub struct PromptBuilder {
    name: String,
    description: Option<String>,
    arguments: Vec<PromptArgument>,
    version: Option<String>,
    tags: Vec<String>,
}

impl PromptBuilder {
    /// Creates a new prompt builder.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: None,
            arguments: Vec::new(),
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

    /// Adds a required argument.
    #[must_use]
    pub fn required_arg(mut self, name: impl Into<String>, desc: impl Into<String>) -> Self {
        self.arguments.push(PromptArgument {
            name: name.into(),
            description: Some(desc.into()),
            required: true,
        });
        self
    }

    /// Adds an optional argument.
    #[must_use]
    pub fn optional_arg(mut self, name: impl Into<String>, desc: impl Into<String>) -> Self {
        self.arguments.push(PromptArgument {
            name: name.into(),
            description: Some(desc.into()),
            required: false,
        });
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

    /// Builds the prompt.
    #[must_use]
    pub fn build(self) -> Prompt {
        Prompt {
            name: self.name,
            description: self.description,
            arguments: self.arguments,
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
    fn test_greeting_prompt() {
        let prompt = greeting_prompt();
        assert_eq!(prompt.name, "greeting");
        assert_eq!(prompt.arguments.len(), 1);
        assert!(prompt.arguments[0].required);
    }

    #[test]
    fn test_code_review_prompt() {
        let prompt = code_review_prompt();
        assert_eq!(prompt.name, "code_review");
        assert_eq!(prompt.arguments.len(), 3);

        let required_args: Vec<_> = prompt.arguments.iter().filter(|a| a.required).collect();
        assert_eq!(required_args.len(), 2);
    }

    #[test]
    fn test_minimal_prompt() {
        let prompt = minimal_prompt();
        assert_eq!(prompt.name, "minimal");
        assert!(prompt.arguments.is_empty());
        assert!(prompt.description.is_none());
    }

    #[test]
    fn test_complex_prompt() {
        let prompt = complex_prompt();
        assert!(prompt.arguments.len() >= 5);

        let optional_args: Vec<_> = prompt.arguments.iter().filter(|a| !a.required).collect();
        assert!(optional_args.len() >= 4);
    }

    #[test]
    fn test_all_sample_prompts() {
        let prompts = all_sample_prompts();
        assert!(prompts.len() >= 5);

        // Verify uniqueness of names
        let names: Vec<_> = prompts.iter().map(|p| &p.name).collect();
        let unique: std::collections::HashSet<_> = names.iter().collect();
        assert_eq!(names.len(), unique.len());
    }

    #[test]
    fn test_prompt_builder_basic() {
        let prompt = PromptBuilder::new("test_prompt")
            .description("A test prompt")
            .required_arg("input", "The input")
            .build();

        assert_eq!(prompt.name, "test_prompt");
        assert_eq!(prompt.description, Some("A test prompt".to_string()));
        assert_eq!(prompt.arguments.len(), 1);
    }

    #[test]
    fn test_prompt_builder_with_multiple_args() {
        let prompt = PromptBuilder::new("multi_arg")
            .required_arg("required1", "First required")
            .required_arg("required2", "Second required")
            .optional_arg("optional1", "First optional")
            .optional_arg("optional2", "Second optional")
            .build();

        assert_eq!(prompt.arguments.len(), 4);
        let required_count = prompt.arguments.iter().filter(|a| a.required).count();
        assert_eq!(required_count, 2);
    }

    #[test]
    fn test_prompt_builder_with_tags() {
        let prompt = PromptBuilder::new("tagged")
            .tags(vec!["tag1".to_string(), "tag2".to_string()])
            .build();

        assert_eq!(prompt.tags.len(), 2);
    }

    // =========================================================================
    // Additional coverage tests (bd-1u39)
    // =========================================================================

    #[test]
    fn summarize_prompt_fields() {
        let prompt = summarize_prompt();
        assert_eq!(prompt.name, "summarize");
        assert_eq!(prompt.arguments.len(), 3);
        assert!(prompt.arguments[0].required); // text
        assert!(!prompt.arguments[1].required); // max_length
        assert!(!prompt.arguments[2].required); // style
        assert!(prompt.tags.contains(&"summarize".to_string()));
    }

    #[test]
    fn translate_prompt_fields() {
        let prompt = translate_prompt();
        assert_eq!(prompt.name, "translate");
        assert_eq!(prompt.arguments.len(), 3);

        let required: Vec<_> = prompt
            .arguments
            .iter()
            .filter(|a| a.required)
            .map(|a| a.name.as_str())
            .collect();
        assert!(required.contains(&"text"));
        assert!(required.contains(&"target_language"));
        assert_eq!(required.len(), 2);
    }

    #[test]
    fn sql_prompt_fields() {
        let prompt = sql_prompt();
        assert_eq!(prompt.name, "sql_query");
        assert_eq!(prompt.arguments.len(), 3);
        assert!(prompt.tags.contains(&"sql".to_string()));
        assert!(prompt.tags.contains(&"database".to_string()));
    }

    #[test]
    fn prompt_builder_version_setter() {
        let prompt = PromptBuilder::new("versioned").version("5.0.0").build();
        assert_eq!(prompt.version, Some("5.0.0".to_string()));
    }

    #[test]
    fn prompt_builder_debug_and_clone() {
        let builder = PromptBuilder::new("dbg")
            .description("desc")
            .required_arg("x", "x desc");
        let debug = format!("{builder:?}");
        assert!(debug.contains("PromptBuilder"));
        assert!(debug.contains("dbg"));

        let cloned = builder.clone();
        let prompt = cloned.build();
        assert_eq!(prompt.name, "dbg");
        assert_eq!(prompt.arguments.len(), 1);
    }

    #[test]
    fn all_sample_prompts_exact_count() {
        assert_eq!(all_sample_prompts().len(), 7);
    }
}
