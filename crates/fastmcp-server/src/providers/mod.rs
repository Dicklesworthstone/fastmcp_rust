//! Built-in resource providers for common use cases.
//!
//! This module provides pre-built resource providers that can be registered
//! with a server to expose common data sources as MCP resources.
//!
//! # Available Providers
//!
//! - [`FilesystemProvider`]: Quarantined implementation for exposing files as
//!   resources. Its public `build` method currently fails closed on every
//!   target because the server does not yet provide a guaranteed non-inline,
//!   bounded, owned-and-drained blocking-I/O capability.
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
//! assert!(matches!(result, Err(FilesystemProviderError::FeatureUnavailable { .. })));
//! ```

#![forbid(unsafe_code)]

mod filesystem;

pub use filesystem::{FilesystemProvider, FilesystemProviderError, FilesystemResourceHandler};
