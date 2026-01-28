//! Built-in resource providers for common use cases.
//!
//! This module provides pre-built resource providers that can be registered
//! with a server to expose common data sources as MCP resources.
//!
//! # Available Providers
//!
//! - [`FilesystemProvider`]: Exposes files from a directory as resources
//!
//! # Example
//!
//! ```ignore
//! use fastmcp::prelude::*;
//! use fastmcp_server::providers::FilesystemProvider;
//!
//! let provider = FilesystemProvider::new("/data/docs")
//!     .with_prefix("docs")
//!     .with_patterns(&["**/*.md", "**/*.txt"])
//!     .with_recursive(true);
//!
//! // Get all resource handlers from the provider
//! for handler in provider.handlers() {
//!     server_builder = server_builder.resource(handler);
//! }
//! ```

#![forbid(unsafe_code)]

mod filesystem;

pub use filesystem::{FilesystemProvider, FilesystemProviderError};
