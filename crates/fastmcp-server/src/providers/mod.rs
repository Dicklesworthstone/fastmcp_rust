//! Built-in resource providers for common use cases.
//!
//! This module provides pre-built resource providers that can be registered
//! with a server to expose common data sources as MCP resources.
//!
//! # Available Providers
//!
//! - [`FilesystemProvider`]: Exposes a directory as MCP resources on Linux and
//!   macOS. Public `build` fails closed on other targets. Listing and reads
//!   use the caller-owned asupersync blocking pool when one is installed.
//! - With the `apps` feature, `McpAppsUiResource`: one immutable final-only
//!   `ui://` HTML document for a negotiated MCP Apps View.
//!
//! # Example
//!
//! ```ignore
//! use fastmcp_rust::prelude::*;
//! use fastmcp_rust::providers::{FilesystemProvider, FilesystemProviderError};
//!
//! let result = FilesystemProvider::new("/data/docs")
//!     .with_prefix("docs")
//!     .with_patterns(&["**/*.md", "**/*.txt"])
//!     .with_recursive(true)
//!     .build();
//! // On Linux/macOS this is `Ok(handler)`. Other targets remain FeatureUnavailable.
//! ```

#![forbid(unsafe_code)]

mod filesystem;
#[cfg(feature = "apps")]
mod mcp_apps;

pub use filesystem::{FilesystemProvider, FilesystemProviderError, FilesystemResourceHandler};
#[cfg(feature = "apps")]
pub use mcp_apps::{McpAppsUiResource, McpAppsUiResourceError};
