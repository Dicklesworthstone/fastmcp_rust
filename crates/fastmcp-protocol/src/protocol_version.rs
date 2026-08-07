//! Final MCP protocol-version header validation.
//!
//! This module models the `2026-07-28` HTTP rule only: every request carries
//! an `MCP-Protocol-Version` header whose exact value matches the body's
//! `io.modelcontextprotocol/protocolVersion` value. Transport code owns HTTP
//! header parsing and supplies the already-decoded field value here.

/// The final protocol version implemented by this narrow modern surface.
pub const FINAL_PROTOCOL_VERSION: &str = "2026-07-28";

/// The exact protocol versions admitted by this final-only surface.
pub const SUPPORTED_FINAL_PROTOCOL_VERSIONS: &[&str] = &[FINAL_PROTOCOL_VERSION];

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

/// The request metadata whose HTTP and JSON body values mirror each other.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestVersionMetadata<'a> {
    /// The already-decoded `MCP-Protocol-Version` HTTP header value.
    pub header_version: Option<&'a str>,
    /// The `io.modelcontextprotocol/protocolVersion` body metadata value.
    pub body_version: Option<&'a str>,
}

/// A request admitted through the final protocol-version boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalRequestAdmission {
    version: FinalProtocolVersion,
}

impl FinalRequestAdmission {
    /// Returns the version whose header/body mirror was admitted.
    #[must_use]
    pub const fn protocol_version(self) -> FinalProtocolVersion {
        self.version
    }
}

/// The exact header/body condition that failed final request admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderMismatchReason {
    /// The required protocol-version header was absent.
    MissingHeader,
    /// The required body protocol-version field was absent.
    MissingBodyVersion,
    /// The header value was empty.
    EmptyHeader,
    /// The body value was empty.
    EmptyBodyVersion,
    /// The supplied header and body values were different.
    HeaderBodyVersionMismatch,
}

/// Typed local detail for a final `HeaderMismatchError`.
///
/// The detail is for local routing and diagnostics only. Canonical peer-facing
/// header-mismatch emission has no required error-data shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeaderMismatchError {
    reason: HeaderMismatchReason,
}

impl HeaderMismatchError {
    /// Returns the local typed reason without constructing peer error data.
    #[must_use]
    pub const fn reason(self) -> HeaderMismatchReason {
        self.reason
    }

    /// Returns the final MCP JSON-RPC header-mismatch code.
    #[must_use]
    pub const fn jsonrpc_error_code(self) -> i32 {
        HEADER_MISMATCH_ERROR_CODE
    }

    /// Returns the final HTTP status for a header mismatch.
    #[must_use]
    pub const fn http_status(self) -> u16 {
        400
    }
}

/// Typed data for a final unsupported-protocol-version response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsupportedProtocolVersionError {
    requested: String,
}

impl UnsupportedProtocolVersionError {
    /// Returns the exact matching header/body value the server rejected.
    #[must_use]
    pub fn requested(&self) -> &str {
        &self.requested
    }

    /// Returns the exact final versions that this surface supports.
    #[must_use]
    pub const fn supported_versions(&self) -> &'static [&'static str] {
        SUPPORTED_FINAL_PROTOCOL_VERSIONS
    }

    /// Returns the final MCP JSON-RPC unsupported-version code.
    #[must_use]
    pub const fn jsonrpc_error_code(&self) -> i32 {
        UNSUPPORTED_PROTOCOL_VERSION_ERROR_CODE
    }

    /// Returns the final HTTP status for an unsupported version.
    #[must_use]
    pub const fn http_status(&self) -> u16 {
        400
    }
}

/// Typed failure from final request version admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequestAdmissionError {
    /// Required metadata was missing, empty, malformed, or failed the mirror check.
    HeaderMismatch(HeaderMismatchError),
    /// The mirror was valid but selected a version this surface does not support.
    UnsupportedProtocolVersion(UnsupportedProtocolVersionError),
}

impl RequestAdmissionError {
    /// Returns the HTTP status required by this final request-admission failure.
    #[must_use]
    pub const fn http_status(&self) -> u16 {
        match self {
            Self::HeaderMismatch(error) => error.http_status(),
            Self::UnsupportedProtocolVersion(error) => error.http_status(),
        }
    }

    /// Returns the final MCP JSON-RPC error code for this failure.
    #[must_use]
    pub const fn jsonrpc_error_code(&self) -> i32 {
        match self {
            Self::HeaderMismatch(error) => error.jsonrpc_error_code(),
            Self::UnsupportedProtocolVersion(error) => error.jsonrpc_error_code(),
        }
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
    admit_final_request(RequestVersionMetadata {
        header_version,
        body_version,
    })
    .map(|admission| admission.protocol_version())
    .map_err(|error| match error {
        RequestAdmissionError::HeaderMismatch(_) => ProtocolVersionError::HeaderMismatch,
        RequestAdmissionError::UnsupportedProtocolVersion(error) => {
            ProtocolVersionError::UnsupportedProtocolVersion {
                requested: error.requested,
            }
        }
    })
}

/// Admits final request metadata using the required error precedence.
///
/// Header/body validity is evaluated before version support. This prevents a
/// mismatched or malformed mirror from being misclassified as an unsupported
/// version and ensures callers never select policy from an untrusted header.
pub fn admit_final_request(
    metadata: RequestVersionMetadata<'_>,
) -> Result<FinalRequestAdmission, RequestAdmissionError> {
    let header_version = metadata.header_version.ok_or(RequestAdmissionError::HeaderMismatch(
        HeaderMismatchError {
            reason: HeaderMismatchReason::MissingHeader,
        },
    ))?;
    let body_version = metadata.body_version.ok_or(RequestAdmissionError::HeaderMismatch(
        HeaderMismatchError {
            reason: HeaderMismatchReason::MissingBodyVersion,
        },
    ))?;

    if header_version.is_empty() {
        return Err(RequestAdmissionError::HeaderMismatch(
            HeaderMismatchError {
                reason: HeaderMismatchReason::EmptyHeader,
            },
        ));
    }
    if body_version.is_empty() {
        return Err(RequestAdmissionError::HeaderMismatch(
            HeaderMismatchError {
                reason: HeaderMismatchReason::EmptyBodyVersion,
            },
        ));
    }
    if header_version != body_version {
        return Err(RequestAdmissionError::HeaderMismatch(
            HeaderMismatchError {
                reason: HeaderMismatchReason::HeaderBodyVersionMismatch,
            },
        ));
    }
    if header_version != FINAL_PROTOCOL_VERSION {
        return Err(RequestAdmissionError::UnsupportedProtocolVersion(
            UnsupportedProtocolVersionError {
                requested: header_version.to_owned(),
            },
        ));
    }

    Ok(FinalRequestAdmission {
        version: FinalProtocolVersion,
    })
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

    #[test]
    fn prt_03_b_positive() {
        let admission = admit_final_request(RequestVersionMetadata {
            header_version: Some(FINAL_PROTOCOL_VERSION),
            body_version: Some(FINAL_PROTOCOL_VERSION),
        })
        .expect("matching supported header and body versions must admit the request");

        assert_eq!(admission.protocol_version().as_str(), FINAL_PROTOCOL_VERSION);
        assert_eq!(SUPPORTED_FINAL_PROTOCOL_VERSIONS, [FINAL_PROTOCOL_VERSION]);
    }

    #[test]
    fn prt_03_b_planted_negative() {
        let body_version = Some(FINAL_PROTOCOL_VERSION);
        let changed_header_version = Some("2025-11-25");

        let error = admit_final_request(RequestVersionMetadata {
            header_version: changed_header_version,
            body_version,
        })
        .expect_err("changing only the header must retain header-mismatch precedence");

        assert_eq!(
            error,
            RequestAdmissionError::HeaderMismatch(HeaderMismatchError {
                reason: HeaderMismatchReason::HeaderBodyVersionMismatch,
            })
        );
        assert_eq!(error.jsonrpc_error_code(), HEADER_MISMATCH_ERROR_CODE);
        assert_eq!(error.http_status(), 400);
        assert_eq!(body_version, Some(FINAL_PROTOCOL_VERSION));
    }

    #[test]
    fn matching_unsupported_version_is_classified_after_the_mirror_check() {
        let error = admit_final_request(RequestVersionMetadata {
            header_version: Some("2025-11-25"),
            body_version: Some("2025-11-25"),
        })
        .expect_err("matching unsupported version must reject after mirror validation");

        let RequestAdmissionError::UnsupportedProtocolVersion(error) = error else {
            panic!("matching values must not use the header-mismatch error");
        };
        assert_eq!(error.requested(), "2025-11-25");
        assert_eq!(error.supported_versions(), [FINAL_PROTOCOL_VERSION]);
        assert_eq!(error.jsonrpc_error_code(), UNSUPPORTED_PROTOCOL_VERSION_ERROR_CODE);
        assert_eq!(error.http_status(), 400);
    }
}
