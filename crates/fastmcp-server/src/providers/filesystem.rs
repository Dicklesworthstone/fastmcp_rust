//! Filesystem resource provider.
//!
//! Exposes files from a directory as MCP resources with configurable
//! patterns, security controls, and MIME type detection.
//!
//! # Security
//!
//! The provider includes path traversal protection to prevent accessing
//! files outside the configured root directory.
//!
//! # Example
//!
//! ```ignore
//! use fastmcp_server::providers::FilesystemProvider;
//!
//! let provider = FilesystemProvider::new("/data/docs")
//!     .with_prefix("docs")
//!     .with_patterns(&["**/*.md", "**/*.txt"])
//!     .with_exclude(&["**/secret/**", "**/.*"])
//!     .with_recursive(true)
//!     .with_max_size(10 * 1024 * 1024); // 10MB limit
//! ```

use std::path::{Path, PathBuf};

use fastmcp_core::{McpContext, McpError, McpOutcome, McpResult, Outcome};
use fastmcp_protocol::{Resource, ResourceContent, ResourceTemplate};

use crate::handler::{BoxFuture, ResourceHandler, UriParams};

/// Default maximum file size (10 MB).
const DEFAULT_MAX_SIZE: usize = 10 * 1024 * 1024;

/// Errors that can occur when using the filesystem provider.
#[derive(Debug, Clone)]
pub enum FilesystemProviderError {
    /// The requested path would escape the root directory.
    PathTraversal { requested: String },
    /// The file exceeds the maximum allowed size.
    TooLarge { path: String, size: u64, max: usize },
    /// Symlink access was denied.
    SymlinkDenied { path: String },
    /// Symlink target escapes the root directory.
    SymlinkEscapesRoot { path: String },
    /// IO error occurred.
    Io { message: String },
    /// File not found.
    NotFound { path: String },
}

impl std::fmt::Display for FilesystemProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PathTraversal { requested } => {
                write!(f, "Path traversal attempt blocked: {requested}")
            }
            Self::TooLarge { path, size, max } => {
                write!(f, "File too large: {path} ({size} bytes, max {max} bytes)")
            }
            Self::SymlinkDenied { path } => {
                write!(f, "Symlink access denied: {path}")
            }
            Self::SymlinkEscapesRoot { path } => {
                write!(f, "Symlink target escapes root directory: {path}")
            }
            Self::Io { message } => write!(f, "IO error: {message}"),
            Self::NotFound { path } => write!(f, "File not found: {path}"),
        }
    }
}

impl std::error::Error for FilesystemProviderError {}

impl From<FilesystemProviderError> for McpError {
    fn from(err: FilesystemProviderError) -> Self {
        match err {
            FilesystemProviderError::PathTraversal { .. } => {
                // Security violation - path traversal attempt
                McpError::invalid_request(err.to_string())
            }
            FilesystemProviderError::TooLarge { .. } => McpError::invalid_request(err.to_string()),
            FilesystemProviderError::SymlinkDenied { .. }
            | FilesystemProviderError::SymlinkEscapesRoot { .. } => {
                // Security violation - symlink escape attempt
                McpError::invalid_request(err.to_string())
            }
            FilesystemProviderError::Io { .. } => McpError::internal_error(err.to_string()),
            FilesystemProviderError::NotFound { path } => McpError::resource_not_found(&path),
        }
    }
}

/// A resource provider that exposes filesystem directories.
///
/// Files under the configured root directory are exposed as MCP resources
/// with URIs like `file://{prefix}/{relative_path}`.
///
/// # Security
///
/// - Path traversal attempts (e.g., `../../../etc/passwd`) are blocked
/// - Symlinks can be optionally followed or blocked
/// - Maximum file size limits prevent memory exhaustion
/// - Hidden files (starting with `.`) can be excluded
///
/// # Example
///
/// ```ignore
/// use fastmcp_server::providers::FilesystemProvider;
///
/// let provider = FilesystemProvider::new("/app/data")
///     .with_prefix("data")
///     .with_patterns(&["*.json", "*.yaml"])
///     .with_recursive(true);
/// ```
#[derive(Debug, Clone)]
pub struct FilesystemProvider {
    /// Root directory for file access.
    root: PathBuf,
    /// URI prefix (e.g., "docs" -> "file://docs/...").
    prefix: Option<String>,
    /// Glob patterns to include (empty = all files).
    include_patterns: Vec<String>,
    /// Glob patterns to exclude.
    exclude_patterns: Vec<String>,
    /// Whether to traverse subdirectories.
    recursive: bool,
    /// Maximum file size in bytes.
    max_file_size: usize,
    /// Whether to follow symlinks.
    follow_symlinks: bool,
    /// Description for the resource template.
    description: Option<String>,
}

impl FilesystemProvider {
    /// Creates a new filesystem provider for the given root directory.
    ///
    /// # Arguments
    ///
    /// * `root` - The root directory to expose
    ///
    /// # Example
    ///
    /// ```ignore
    /// let provider = FilesystemProvider::new("/data/docs");
    /// ```
    #[must_use]
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            prefix: None,
            include_patterns: Vec::new(),
            exclude_patterns: vec![".*".to_string()], // Exclude hidden files by default
            recursive: false,
            max_file_size: DEFAULT_MAX_SIZE,
            follow_symlinks: false,
            description: None,
        }
    }

    /// Sets the URI prefix for resources.
    ///
    /// Files will have URIs like `file://{prefix}/{path}`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let provider = FilesystemProvider::new("/data")
    ///     .with_prefix("mydata");
    /// // Results in URIs like file://mydata/readme.md
    /// ```
    #[must_use]
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    /// Sets glob patterns to include.
    ///
    /// Only files matching at least one of these patterns will be exposed.
    /// Empty patterns means all files are included.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let provider = FilesystemProvider::new("/data")
    ///     .with_patterns(&["*.md", "*.txt", "**/*.json"]);
    /// ```
    #[must_use]
    pub fn with_patterns(mut self, patterns: &[&str]) -> Self {
        self.include_patterns = patterns.iter().map(|s| (*s).to_string()).collect();
        self
    }

    /// Sets glob patterns to exclude.
    ///
    /// Files matching any of these patterns will be excluded.
    /// By default, hidden files (starting with `.`) are excluded.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let provider = FilesystemProvider::new("/data")
    ///     .with_exclude(&["**/secret/**", "*.bak"]);
    /// ```
    #[must_use]
    pub fn with_exclude(mut self, patterns: &[&str]) -> Self {
        self.exclude_patterns = patterns.iter().map(|s| (*s).to_string()).collect();
        self
    }

    /// Enables or disables recursive directory traversal.
    ///
    /// When enabled, files in subdirectories are also exposed.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let provider = FilesystemProvider::new("/data")
    ///     .with_recursive(true);
    /// ```
    #[must_use]
    pub fn with_recursive(mut self, enabled: bool) -> Self {
        self.recursive = enabled;
        self
    }

    /// Sets the maximum file size in bytes.
    ///
    /// Files larger than this limit will return an error when read.
    /// Default is 10 MB.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let provider = FilesystemProvider::new("/data")
    ///     .with_max_size(5 * 1024 * 1024); // 5 MB
    /// ```
    #[must_use]
    pub fn with_max_size(mut self, bytes: usize) -> Self {
        self.max_file_size = bytes;
        self
    }

    /// Enables or disables following symlinks.
    ///
    /// When disabled (default), symlinks are not followed.
    /// When enabled, symlinks are followed but must still point within the root directory.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let provider = FilesystemProvider::new("/data")
    ///     .with_follow_symlinks(true);
    /// ```
    #[must_use]
    pub fn with_follow_symlinks(mut self, enabled: bool) -> Self {
        self.follow_symlinks = enabled;
        self
    }

    /// Sets the description for the resource template.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let provider = FilesystemProvider::new("/data")
    ///     .with_description("Documentation files");
    /// ```
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Builds a resource handler from this provider.
    ///
    /// The returned handler can be registered with a server.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let handler = FilesystemProvider::new("/data")
    ///     .with_prefix("docs")
    ///     .build();
    ///
    /// let server = Server::new("demo", "1.0")
    ///     .resource(handler);
    /// ```
    #[must_use]
    pub fn build(self) -> FilesystemResourceHandler {
        FilesystemResourceHandler::new(self)
    }

    /// Validates a path and returns the canonical path if valid.
    ///
    /// Returns an error if:
    /// - The path is absolute
    /// - The path escapes the root directory
    /// - The path is a symlink and symlinks are disabled
    fn validate_path(&self, requested: &str) -> Result<PathBuf, FilesystemProviderError> {
        let requested_path = Path::new(requested);

        // Reject absolute paths in request
        if requested_path.is_absolute() {
            return Err(FilesystemProviderError::PathTraversal {
                requested: requested.to_string(),
            });
        }

        // Build full path
        let full_path = self.root.join(requested_path);

        // Canonicalize to resolve ../ etc.
        // Note: canonicalize requires the path to exist
        let canonical = full_path.canonicalize().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                FilesystemProviderError::NotFound {
                    path: requested.to_string(),
                }
            } else {
                FilesystemProviderError::Io {
                    message: e.to_string(),
                }
            }
        })?;

        // Get canonical root for comparison
        let canonical_root = self
            .root
            .canonicalize()
            .map_err(|e| FilesystemProviderError::Io {
                message: format!("Cannot canonicalize root: {e}"),
            })?;

        // Verify still under root
        if !canonical.starts_with(&canonical_root) {
            return Err(FilesystemProviderError::PathTraversal {
                requested: requested.to_string(),
            });
        }

        // Check symlink
        if full_path.is_symlink() {
            self.check_symlink(&full_path, &canonical_root)?;
        }

        Ok(canonical)
    }

    /// Checks if a symlink is allowed.
    fn check_symlink(
        &self,
        path: &Path,
        canonical_root: &Path,
    ) -> Result<(), FilesystemProviderError> {
        if !self.follow_symlinks {
            return Err(FilesystemProviderError::SymlinkDenied {
                path: path.display().to_string(),
            });
        }

        // Verify symlink target is still under root
        let target = std::fs::read_link(path).map_err(|e| FilesystemProviderError::Io {
            message: e.to_string(),
        })?;

        let resolved = if target.is_absolute() {
            target
        } else {
            path.parent().unwrap_or(Path::new("")).join(&target)
        };

        let canonical_target =
            resolved
                .canonicalize()
                .map_err(|e| FilesystemProviderError::Io {
                    message: e.to_string(),
                })?;

        if !canonical_target.starts_with(canonical_root) {
            return Err(FilesystemProviderError::SymlinkEscapesRoot {
                path: path.display().to_string(),
            });
        }

        Ok(())
    }

    /// Checks if a filename matches the include/exclude patterns.
    fn matches_patterns(&self, relative_path: &str) -> bool {
        // Check exclude patterns first
        for pattern in &self.exclude_patterns {
            if glob_match(pattern, relative_path) {
                return false;
            }
        }

        // If no include patterns, include everything
        if self.include_patterns.is_empty() {
            return true;
        }

        // Check include patterns
        for pattern in &self.include_patterns {
            if glob_match(pattern, relative_path) {
                return true;
            }
        }

        false
    }

    /// Lists files in the directory that match patterns.
    fn list_files(&self) -> Result<Vec<FileEntry>, FilesystemProviderError> {
        let canonical_root = self
            .root
            .canonicalize()
            .map_err(|e| FilesystemProviderError::Io {
                message: format!("Cannot canonicalize root: {e}"),
            })?;

        let mut entries = Vec::new();
        self.walk_directory(&canonical_root, &canonical_root, &mut entries)?;
        Ok(entries)
    }

    /// Recursively walks a directory collecting file entries.
    fn walk_directory(
        &self,
        current: &Path,
        root: &Path,
        entries: &mut Vec<FileEntry>,
    ) -> Result<(), FilesystemProviderError> {
        let read_dir = std::fs::read_dir(current).map_err(|e| FilesystemProviderError::Io {
            message: e.to_string(),
        })?;

        for entry_result in read_dir {
            let entry = entry_result.map_err(|e| FilesystemProviderError::Io {
                message: e.to_string(),
            })?;

            let path = entry.path();
            let file_type = entry.file_type().map_err(|e| FilesystemProviderError::Io {
                message: e.to_string(),
            })?;

            // Handle symlinks
            if file_type.is_symlink() && !self.follow_symlinks {
                continue;
            }

            // Calculate relative path
            let relative = path
                .strip_prefix(root)
                .map_err(|e| FilesystemProviderError::Io {
                    message: e.to_string(),
                })?;
            let relative_str = relative.to_string_lossy().replace('\\', "/");

            if file_type.is_dir() || (file_type.is_symlink() && path.is_dir()) {
                if self.recursive {
                    self.walk_directory(&path, root, entries)?;
                }
            } else if file_type.is_file() || (file_type.is_symlink() && path.is_file()) {
                // Check patterns
                if self.matches_patterns(&relative_str) {
                    let metadata = std::fs::metadata(&path).ok();
                    entries.push(FileEntry {
                        path: path.clone(),
                        relative_path: relative_str,
                        size: metadata.as_ref().map(|m| m.len()),
                        mime_type: detect_mime_type(&path),
                    });
                }
            }
        }

        Ok(())
    }

    /// Returns the URI for a file.
    fn file_uri(&self, relative_path: &str) -> String {
        match &self.prefix {
            Some(prefix) => format!("file://{prefix}/{relative_path}"),
            None => format!("file://{relative_path}"),
        }
    }

    /// Returns the URI template for this provider.
    fn uri_template(&self) -> String {
        match &self.prefix {
            Some(prefix) => format!("file://{prefix}/{{path}}"),
            None => "file://{path}".to_string(),
        }
    }

    /// Extracts the relative path from a URI.
    fn path_from_uri(&self, uri: &str) -> Option<String> {
        let expected_prefix = match &self.prefix {
            Some(p) => format!("file://{p}/"),
            None => "file://".to_string(),
        };

        if uri.starts_with(&expected_prefix) {
            Some(uri[expected_prefix.len()..].to_string())
        } else {
            None
        }
    }

    /// Reads a file and returns its content.
    fn read_file(&self, relative_path: &str) -> Result<FileContent, FilesystemProviderError> {
        // Validate and get canonical path
        let path = self.validate_path(relative_path)?;

        // Check file size
        let metadata = std::fs::metadata(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                FilesystemProviderError::NotFound {
                    path: relative_path.to_string(),
                }
            } else {
                FilesystemProviderError::Io {
                    message: e.to_string(),
                }
            }
        })?;

        if metadata.len() > self.max_file_size as u64 {
            return Err(FilesystemProviderError::TooLarge {
                path: relative_path.to_string(),
                size: metadata.len(),
                max: self.max_file_size,
            });
        }

        // Detect MIME type
        let mime_type = detect_mime_type(&path);

        // Read content
        let content = if is_binary_mime_type(&mime_type) {
            let bytes = std::fs::read(&path).map_err(|e| FilesystemProviderError::Io {
                message: e.to_string(),
            })?;
            FileContent::Binary(bytes)
        } else {
            let text = std::fs::read_to_string(&path).map_err(|e| FilesystemProviderError::Io {
                message: e.to_string(),
            })?;
            FileContent::Text(text)
        };

        Ok(content)
    }
}

/// A file entry from directory listing.
#[derive(Debug)]
struct FileEntry {
    #[allow(dead_code)]
    path: PathBuf,
    relative_path: String,
    #[allow(dead_code)]
    size: Option<u64>,
    mime_type: String,
}

/// File content (text or binary).
enum FileContent {
    Text(String),
    Binary(Vec<u8>),
}

/// Resource handler implementation for the filesystem provider.
pub struct FilesystemResourceHandler {
    provider: FilesystemProvider,
    /// Cached file list for static resources.
    cached_resources: Vec<Resource>,
}

impl FilesystemResourceHandler {
    /// Creates a new handler from a provider.
    fn new(provider: FilesystemProvider) -> Self {
        // Pre-compute the list of resources
        let cached_resources = match provider.list_files() {
            Ok(entries) => entries
                .into_iter()
                .map(|entry| Resource {
                    uri: provider.file_uri(&entry.relative_path),
                    name: entry.relative_path.clone(),
                    description: None,
                    mime_type: Some(entry.mime_type),
                    icon: None,
                    version: None,
                    tags: vec![],
                })
                .collect(),
            Err(_) => Vec::new(),
        };

        Self {
            provider,
            cached_resources,
        }
    }
}

impl ResourceHandler for FilesystemResourceHandler {
    fn definition(&self) -> Resource {
        // Return a synthetic "root" resource for the provider
        Resource {
            uri: self.provider.uri_template(),
            name: self
                .provider
                .prefix
                .clone()
                .unwrap_or_else(|| "files".to_string()),
            description: self.provider.description.clone(),
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        }
    }

    fn template(&self) -> Option<ResourceTemplate> {
        Some(ResourceTemplate {
            uri_template: self.provider.uri_template(),
            name: self
                .provider
                .prefix
                .clone()
                .unwrap_or_else(|| "files".to_string()),
            description: self.provider.description.clone(),
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        })
    }

    fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        // For template resources, read() without params returns the file list
        let files = self.provider.list_files()?;

        let listing = files
            .iter()
            .map(|f| format!("{}: {}", f.relative_path, f.mime_type))
            .collect::<Vec<_>>()
            .join("\n");

        Ok(vec![ResourceContent {
            uri: self.provider.uri_template(),
            mime_type: Some("text/plain".to_string()),
            text: Some(listing),
            blob: None,
        }])
    }

    fn read_with_uri(
        &self,
        _ctx: &McpContext,
        uri: &str,
        params: &UriParams,
    ) -> McpResult<Vec<ResourceContent>> {
        // Extract path from URI or params
        let relative_path = if let Some(path) = params.get("path") {
            path.clone()
        } else if let Some(path) = self.provider.path_from_uri(uri) {
            path
        } else {
            return Err(McpError::invalid_params("Missing path parameter"));
        };

        let content = self.provider.read_file(&relative_path)?;

        let resource_content = match content {
            FileContent::Text(text) => ResourceContent {
                uri: uri.to_string(),
                mime_type: Some(detect_mime_type(Path::new(&relative_path))),
                text: Some(text),
                blob: None,
            },
            FileContent::Binary(bytes) => {
                let base64_str = base64_encode(&bytes);

                ResourceContent {
                    uri: uri.to_string(),
                    mime_type: Some(detect_mime_type(Path::new(&relative_path))),
                    text: None,
                    blob: Some(base64_str),
                }
            }
        };

        Ok(vec![resource_content])
    }

    fn read_async_with_uri<'a>(
        &'a self,
        ctx: &'a McpContext,
        uri: &'a str,
        params: &'a UriParams,
    ) -> BoxFuture<'a, McpOutcome<Vec<ResourceContent>>> {
        Box::pin(async move {
            match self.read_with_uri(ctx, uri, params) {
                Ok(v) => Outcome::Ok(v),
                Err(e) => Outcome::Err(e),
            }
        })
    }
}

impl std::fmt::Debug for FilesystemResourceHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FilesystemResourceHandler")
            .field("provider", &self.provider)
            .field("cached_resources", &self.cached_resources.len())
            .finish()
    }
}

/// Detects the MIME type for a file based on its extension.
fn detect_mime_type(path: &Path) -> String {
    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_lowercase);

    match extension.as_deref() {
        // Text formats
        Some("txt") => "text/plain",
        Some("md" | "markdown") => "text/markdown",
        Some("html" | "htm") => "text/html",
        Some("css") => "text/css",
        Some("csv") => "text/csv",
        Some("xml") => "application/xml",

        // Programming languages
        Some("rs") => "text/x-rust",
        Some("py") => "text/x-python",
        Some("js" | "mjs") => "text/javascript",
        Some("ts" | "mts") => "text/typescript",
        Some("json") => "application/json",
        Some("yaml" | "yml") => "application/yaml",
        Some("toml") => "application/toml",
        Some("sh" | "bash") => "text/x-shellscript",
        Some("c") => "text/x-c",
        Some("cpp" | "cc" | "cxx") => "text/x-c++",
        Some("h" | "hpp") => "text/x-c-header",
        Some("java") => "text/x-java",
        Some("go") => "text/x-go",
        Some("rb") => "text/x-ruby",
        Some("php") => "text/x-php",
        Some("swift") => "text/x-swift",
        Some("kt" | "kts") => "text/x-kotlin",
        Some("sql") => "text/x-sql",

        // Images
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("bmp") => "image/bmp",

        // Binary/Documents
        Some("pdf") => "application/pdf",
        Some("zip") => "application/zip",
        Some("gz" | "gzip") => "application/gzip",
        Some("tar") => "application/x-tar",
        Some("wasm") => "application/wasm",
        Some("exe") => "application/octet-stream",
        Some("dll") => "application/octet-stream",
        Some("so") => "application/octet-stream",
        Some("bin") => "application/octet-stream",

        // Default
        _ => "application/octet-stream",
    }
    .to_string()
}

/// Checks if a MIME type represents binary content.
fn is_binary_mime_type(mime_type: &str) -> bool {
    mime_type.starts_with("image/")
        || mime_type.starts_with("audio/")
        || mime_type.starts_with("video/")
        || mime_type == "application/octet-stream"
        || mime_type == "application/pdf"
        || mime_type == "application/zip"
        || mime_type == "application/gzip"
        || mime_type == "application/x-tar"
        || mime_type == "application/wasm"
}

/// Standard base64 alphabet.
const BASE64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encodes bytes to standard base64.
fn base64_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity((data.len() + 2) / 3 * 4);

    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

        let combined = (b0 << 16) | (b1 << 8) | b2;

        result.push(BASE64_CHARS[(combined >> 18) & 0x3F] as char);
        result.push(BASE64_CHARS[(combined >> 12) & 0x3F] as char);

        if chunk.len() > 1 {
            result.push(BASE64_CHARS[(combined >> 6) & 0x3F] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(BASE64_CHARS[combined & 0x3F] as char);
        } else {
            result.push('=');
        }
    }

    result
}

/// Simple glob pattern matching.
///
/// Supports:
/// - `*` - matches any sequence of characters (except `/`)
/// - `**` - matches any sequence of characters (including `/`)
/// - `?` - matches any single character
fn glob_match(pattern: &str, path: &str) -> bool {
    glob_match_recursive(pattern, path)
}

/// Recursive glob matching implementation.
fn glob_match_recursive(pattern: &str, path: &str) -> bool {
    let mut pattern_chars = pattern.chars().peekable();
    let mut path_chars = path.chars().peekable();

    while let Some(p) = pattern_chars.next() {
        match p {
            '*' => {
                // Check for **
                if pattern_chars.peek() == Some(&'*') {
                    pattern_chars.next(); // consume second *

                    // Skip optional / after **
                    if pattern_chars.peek() == Some(&'/') {
                        pattern_chars.next();
                    }

                    let remaining_pattern: String = pattern_chars.collect();

                    // ** matches zero or more path segments
                    // Try matching from current position and all subsequent positions
                    let remaining_path: String = path_chars.collect();

                    // Try matching with empty ** (zero segments)
                    if glob_match_recursive(&remaining_pattern, &remaining_path) {
                        return true;
                    }

                    // Try matching with ** consuming characters one at a time
                    for i in 0..=remaining_path.len() {
                        if glob_match_recursive(&remaining_pattern, &remaining_path[i..]) {
                            return true;
                        }
                    }
                    return false;
                }

                // Single * - match anything except /
                let remaining_pattern: String = pattern_chars.collect();
                let remaining_path: String = path_chars.collect();

                // Try matching with * consuming 0, 1, 2, ... characters (but not /)
                for i in 0..=remaining_path.len() {
                    // Check if the portion we're consuming contains /
                    if remaining_path[..i].contains('/') {
                        break;
                    }
                    if glob_match_recursive(&remaining_pattern, &remaining_path[i..]) {
                        return true;
                    }
                }
                return false;
            }
            '?' => {
                // Match any single character
                if path_chars.next().is_none() {
                    return false;
                }
            }
            c => {
                // Literal character
                if path_chars.next() != Some(c) {
                    return false;
                }
            }
        }
    }

    // Pattern exhausted - path should also be exhausted
    path_chars.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static TEST_DIR_SEQ: AtomicU64 = AtomicU64::new(1);

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(label: &str) -> Self {
            let mut path = std::env::temp_dir();
            let seq = TEST_DIR_SEQ.fetch_add(1, Ordering::SeqCst);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock before epoch")
                .as_nanos();
            path.push(format!(
                "fastmcp-fs-tests-{label}-{}-{seq}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("create temp test dir");
            Self { path }
        }

        fn join(&self, relative: &str) -> PathBuf {
            self.path.join(relative)
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn write_text(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent dir");
        }
        std::fs::write(path, content).expect("write text file");
    }

    fn write_bytes(path: &Path, bytes: &[u8]) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent dir");
        }
        std::fs::write(path, bytes).expect("write binary file");
    }

    #[test]
    fn test_glob_match_star() {
        assert!(glob_match("*.md", "readme.md"));
        assert!(glob_match("*.md", "CHANGELOG.md"));
        assert!(!glob_match("*.md", "readme.txt"));
        assert!(!glob_match("*.md", "dir/readme.md")); // * doesn't match /
    }

    #[test]
    fn test_glob_match_double_star() {
        assert!(glob_match("**/*.md", "readme.md"));
        assert!(glob_match("**/*.md", "docs/readme.md"));
        assert!(glob_match("**/*.md", "docs/api/readme.md"));
        assert!(!glob_match("**/*.md", "readme.txt"));
    }

    #[test]
    fn test_glob_match_question() {
        assert!(glob_match("file?.txt", "file1.txt"));
        assert!(glob_match("file?.txt", "fileA.txt"));
        assert!(!glob_match("file?.txt", "file12.txt"));
    }

    #[test]
    fn test_glob_match_hidden() {
        assert!(glob_match(".*", ".hidden"));
        assert!(glob_match(".*", ".gitignore"));
        assert!(!glob_match(".*", "visible"));
    }

    #[test]
    fn test_detect_mime_type() {
        assert_eq!(detect_mime_type(Path::new("file.md")), "text/markdown");
        assert_eq!(detect_mime_type(Path::new("file.json")), "application/json");
        assert_eq!(detect_mime_type(Path::new("file.rs")), "text/x-rust");
        assert_eq!(detect_mime_type(Path::new("file.png")), "image/png");
        assert_eq!(
            detect_mime_type(Path::new("file.unknown")),
            "application/octet-stream"
        );
    }

    #[test]
    fn test_is_binary_mime_type() {
        assert!(is_binary_mime_type("image/png"));
        assert!(is_binary_mime_type("application/pdf"));
        assert!(!is_binary_mime_type("text/plain"));
        assert!(!is_binary_mime_type("application/json"));
    }

    #[test]
    fn test_provider_list_files_respects_patterns_and_recursion() {
        let root = TestDir::new("list-recursive");
        write_text(&root.join("README.md"), "# readme");
        write_text(&root.join("notes.txt"), "notes");
        write_text(&root.join("nested/info.md"), "# nested");
        write_text(&root.join("nested/code.rs"), "fn main() {}");

        let provider = FilesystemProvider::new(root.path())
            .with_patterns(&["**/*.md", "**/*.txt"])
            .with_recursive(true);

        let files = provider.list_files().expect("list files");
        let mut relative_paths = files
            .iter()
            .map(|entry| entry.relative_path.as_str())
            .collect::<Vec<_>>();
        relative_paths.sort_unstable();

        assert_eq!(
            relative_paths,
            vec!["README.md", "nested/info.md", "notes.txt"]
        );
    }

    #[test]
    fn test_provider_list_files_non_recursive_skips_subdirectories() {
        let root = TestDir::new("list-flat");
        write_text(&root.join("root.md"), "root");
        write_text(&root.join("nested/child.md"), "child");

        let provider = FilesystemProvider::new(root.path())
            .with_patterns(&["**/*.md"])
            .with_recursive(false);

        let files = provider.list_files().expect("list files");
        let relative_paths = files
            .iter()
            .map(|entry| entry.relative_path.as_str())
            .collect::<Vec<_>>();
        assert_eq!(relative_paths, vec!["root.md"]);
    }

    #[test]
    fn test_validate_path_rejects_absolute_and_parent_escape() {
        let root = TestDir::new("validate-path");
        write_text(&root.join("safe.txt"), "safe");

        let outside_file = root
            .path()
            .parent()
            .expect("temp dir has parent")
            .join("outside-fastmcp-provider-test.txt");
        write_text(&outside_file, "outside");

        let provider = FilesystemProvider::new(root.path());

        let absolute = provider.validate_path("/tmp/absolute.txt");
        assert!(matches!(
            absolute,
            Err(FilesystemProviderError::PathTraversal { .. })
        ));

        let escape = provider.validate_path("../outside-fastmcp-provider-test.txt");
        assert!(matches!(
            escape,
            Err(FilesystemProviderError::PathTraversal { .. })
        ));

        let ok = provider.validate_path("safe.txt").expect("safe path");
        assert!(ok.ends_with("safe.txt"));
    }

    #[test]
    fn test_read_file_text_binary_and_size_limit() {
        let root = TestDir::new("read-file");
        write_text(&root.join("doc.txt"), "hello world");
        write_bytes(&root.join("blob.bin"), &[0x00, 0x7F, 0xAA, 0x55]);
        write_bytes(&root.join("large.bin"), &[0u8; 8]);

        let provider = FilesystemProvider::new(root.path()).with_max_size(32);

        let text = provider.read_file("doc.txt").expect("read text");
        assert!(matches!(text, FileContent::Text(ref t) if t == "hello world"));

        let binary = provider.read_file("blob.bin").expect("read binary");
        assert!(matches!(binary, FileContent::Binary(ref b) if b == &[0x00, 0x7F, 0xAA, 0x55]));

        let size_limited = FilesystemProvider::new(root.path()).with_max_size(4);
        let too_large = size_limited.read_file("large.bin");
        assert!(matches!(
            too_large,
            Err(FilesystemProviderError::TooLarge { path, size: 8, max: 4 })
                if path == "large.bin"
        ));
    }

    #[test]
    fn test_handler_read_listing_and_read_with_uri() {
        let root = TestDir::new("handler-read");
        write_text(&root.join("docs/readme.md"), "# docs");

        let handler = FilesystemProvider::new(root.path())
            .with_prefix("docs")
            .with_patterns(&["**/*.md"])
            .with_recursive(true)
            .with_description("Documentation")
            .build();

        let ctx = McpContext::new(asupersync::Cx::for_testing(), 1);

        let definition = handler.definition();
        assert_eq!(definition.uri, "file://docs/{path}");
        assert_eq!(definition.name, "docs");
        assert_eq!(definition.description.as_deref(), Some("Documentation"));

        let template = handler.template().expect("resource template");
        assert_eq!(template.uri_template, "file://docs/{path}");

        let listing = handler.read(&ctx).expect("read listing");
        let listing_text = listing[0].text.as_deref().expect("listing text");
        assert!(listing_text.contains("docs/readme.md: text/markdown"));

        let mut params = HashMap::new();
        params.insert("path".to_string(), "docs/readme.md".to_string());
        let content = handler
            .read_with_uri(&ctx, "file://docs/docs/readme.md", &params)
            .expect("read with params");
        assert_eq!(content[0].text.as_deref(), Some("# docs"));

        let empty_params = HashMap::new();
        let content_from_uri = handler
            .read_with_uri(&ctx, "file://docs/docs/readme.md", &empty_params)
            .expect("read using uri path");
        assert_eq!(content_from_uri[0].text.as_deref(), Some("# docs"));

        let invalid = handler.read_with_uri(&ctx, "file://wrong-prefix/readme.md", &empty_params);
        assert!(invalid.is_err());
    }

    #[test]
    fn test_handler_read_async_with_uri() {
        let root = TestDir::new("handler-async");
        write_text(&root.join("notes.md"), "async content");

        let handler = FilesystemProvider::new(root.path())
            .with_patterns(&["*.md"])
            .build();
        let ctx = McpContext::new(asupersync::Cx::for_testing(), 9);

        let mut params = HashMap::new();
        params.insert("path".to_string(), "notes.md".to_string());
        let outcome =
            fastmcp_core::block_on(handler.read_async_with_uri(&ctx, "file://notes.md", &params));
        match outcome {
            Outcome::Ok(content) => {
                assert_eq!(content.len(), 1);
                assert_eq!(content[0].text.as_deref(), Some("async content"));
            }
            other => panic!("unexpected async outcome: {other:?}"),
        }
    }

    #[test]
    fn test_base64_encode_padding_variants() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
    }

    #[cfg(unix)]
    #[test]
    fn test_symlink_validation_denied_and_escape() {
        use std::os::unix::fs::symlink;

        let root = TestDir::new("symlink-root");
        let outside = TestDir::new("symlink-outside");

        write_text(&root.join("inside.txt"), "inside");
        write_text(&outside.join("outside.txt"), "outside");

        let inside_link = root.join("inside-link.txt");
        let escape_link = root.join("escape-link.txt");
        symlink(root.join("inside.txt"), &inside_link).expect("create inside symlink");
        symlink(outside.join("outside.txt"), &escape_link).expect("create escape symlink");

        let deny_provider = FilesystemProvider::new(root.path()).with_follow_symlinks(false);
        let denied = deny_provider.validate_path("inside-link.txt");
        assert!(matches!(
            denied,
            Err(FilesystemProviderError::SymlinkDenied { .. })
        ));

        let allow_provider = FilesystemProvider::new(root.path()).with_follow_symlinks(true);
        let canonical_root = root.path().canonicalize().expect("canonical root");
        let escaped = allow_provider.check_symlink(&escape_link, &canonical_root);
        assert!(matches!(
            escaped,
            Err(FilesystemProviderError::SymlinkEscapesRoot { .. })
        ));
    }
}
