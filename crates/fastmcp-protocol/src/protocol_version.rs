//! Final MCP protocol-version header validation.
//!
//! This module models the `2026-07-28` HTTP rule only: every request carries
//! an `MCP-Protocol-Version` header whose exact value matches the body's
//! `io.modelcontextprotocol/protocolVersion` value. Transport code owns HTTP
//! header parsing and supplies the already-decoded field value here.

/// The final protocol version implemented by this narrow modern surface.
pub const FINAL_PROTOCOL_VERSION: &str = "2026-07-28";

/// The HTTP header that mirrors the body's protocol-version metadata.
pub const MCP_PROTOCOL_VERSION_HEADER: &str = "MCP-Protocol-Version";

/// The final MCP JSON-RPC code for malformed, missing, or mismatched headers.
pub const HEADER_MISMATCH_ERROR_CODE: i32 = -32020;

/// The final MCP JSON-RPC code for a version the server does not support.
pub const UNSUPPORTED_PROTOCOL_VERSION_ERROR_CODE: i32 = -32022;

/// A validated final protocol version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalProtocolVersion;

impl FinalProtocolVersion {
    /// Returns the exact wire value for this final version.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        FINAL_PROTOCOL_VERSION
    }
}

/// Why final protocol-version validation rejected a request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolVersionError {
    /// The required header or body field was absent, empty, malformed, or differed.
    HeaderMismatch,
    /// Header and body agreed on a well-formed value that this final surface does not support.
    UnsupportedProtocolVersion { requested: String },
}

impl ProtocolVersionError {
    /// Returns the HTTP status required for either final version failure.
    #[must_use]
    pub const fn http_status(&self) -> u16 {
        400
    }

    /// Returns the final MCP JSON-RPC error code.
    #[must_use]
    pub const fn jsonrpc_error_code(&self) -> i32 {
        match self {
            Self::HeaderMismatch => HEADER_MISMATCH_ERROR_CODE,
            Self::UnsupportedProtocolVersion { .. } => UNSUPPORTED_PROTOCOL_VERSION_ERROR_CODE,
        }
    }
}

/// Validates the final HTTP header/body protocol-version mirror.
///
/// This deliberately performs no legacy fallback. A missing or empty header,
/// a missing or empty body value, and different values all use the final
/// header-mismatch classification. Matching non-final values are classified as
/// unsupported and retain the requested value for the caller's typed error
/// data.
pub fn validate_final_protocol_version(
    header_version: Option<&str>,
    body_version: Option<&str>,
) -> Result<FinalProtocolVersion, ProtocolVersionError> {
    let (Some(header_version), Some(body_version)) = (header_version, body_version) else {
        return Err(ProtocolVersionError::HeaderMismatch);
    };

    if header_version.is_empty() || body_version.is_empty() || header_version != body_version {
        return Err(ProtocolVersionError::HeaderMismatch);
    }

    if header_version != FINAL_PROTOCOL_VERSION {
        return Err(ProtocolVersionError::UnsupportedProtocolVersion {
            requested: header_version.to_owned(),
        });
    }

    Ok(FinalProtocolVersion)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prt_03_a_positive() {
        let header = Some(FINAL_PROTOCOL_VERSION);
        let body = Some(FINAL_PROTOCOL_VERSION);

        let version = validate_final_protocol_version(header, body)
            .expect("matching final header and body version must be admitted");

        assert_eq!(version.as_str(), FINAL_PROTOCOL_VERSION);
        assert_eq!(MCP_PROTOCOL_VERSION_HEADER, "MCP-Protocol-Version");
    }

    #[test]
    fn prt_03_a_planted_negative() {
        let header = Some("2025-11-25");
        let body = Some(FINAL_PROTOCOL_VERSION);

        let error = validate_final_protocol_version(header, body)
            .expect_err("changing only the header version must reject the request");

        assert_eq!(error, ProtocolVersionError::HeaderMismatch);
        assert_eq!(error.http_status(), 400);
        assert_eq!(error.jsonrpc_error_code(), HEADER_MISMATCH_ERROR_CODE);
        assert_eq!(body, Some(FINAL_PROTOCOL_VERSION));
    }

    #[test]
    fn matching_unsupported_version_reports_the_requested_value() {
        let error = validate_final_protocol_version(Some("2025-11-25"), Some("2025-11-25"))
            .expect_err("matching unsupported versions must not be accepted");

        assert_eq!(
            error,
            ProtocolVersionError::UnsupportedProtocolVersion {
                requested: "2025-11-25".to_owned(),
            }
        );
        assert_eq!(error.http_status(), 400);
        assert_eq!(
            error.jsonrpc_error_code(),
            UNSUPPORTED_PROTOCOL_VERSION_ERROR_CODE
        );
    }

    #[test]
    fn missing_or_empty_version_is_a_header_mismatch() {
        for (header, body) in [
            (None, Some(FINAL_PROTOCOL_VERSION)),
            (Some(FINAL_PROTOCOL_VERSION), None),
            (Some(""), Some(FINAL_PROTOCOL_VERSION)),
            (Some(FINAL_PROTOCOL_VERSION), Some("")),
        ] {
            assert_eq!(
                validate_final_protocol_version(header, body),
                Err(ProtocolVersionError::HeaderMismatch)
            );
        }
    }
}
