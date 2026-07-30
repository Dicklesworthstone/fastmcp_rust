//! Compile surface for the exact FND-01 Redis crate candidate.
//!
//! This probe never opens a connection. The unmodified crate's connector,
//! parser, credential representation, and peer-identity behavior do not meet
//! TASKR-01, so this artifact is dependency evidence rather than a persistence
//! support claim.

#![forbid(unsafe_code)]

use redis::{ConnectionAddr, Script, acl::AclInfo};

/// Exercise the `script` feature and its `sha1_smol` edge without I/O.
pub fn script_sha1(source: &str) -> String {
    Script::new(source).get_hash().to_owned()
}

/// Keep the `acl` feature's public result type in the compile surface.
pub fn acl_type_surface(info: &AclInfo) -> &AclInfo {
    info
}

/// Negative evidence: TCP remains a public, constructible address variant
/// even when every TLS/cluster/aio/runtime feature is disabled.
pub fn tcp_address_surface(host: String, port: u16) -> ConnectionAddr {
    ConnectionAddr::Tcp(host, port)
}

/// Negative evidence: on Unix the crate accepts an ambient socket path; this
/// is not the retained-capability, peer-verified connector TASKR-01 requires.
#[cfg(unix)]
pub fn ambient_unix_address_surface(path: std::path::PathBuf) -> ConnectionAddr {
    ConnectionAddr::Unix(path)
}
