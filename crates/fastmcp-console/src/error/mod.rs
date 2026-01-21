//! Error handling utilities with automatic rich display.
//!
//! This module provides the [`ErrorBoundary`] type that wraps operations
//! and automatically displays errors beautifully on failure using the
//! configured console and theme.

mod boundary;

pub use boundary::ErrorBoundary;
