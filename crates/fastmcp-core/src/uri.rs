//! URI identity and canonical network-URL types.
//!
//! [`AbsoluteUri`] is the wire-identity type used for ordinary MCP URI
//! fields. It validates the RFC 3986 `URI` production (a required scheme,
//! followed by a hierarchical or opaque part, with optional query and
//! fragment components). It deliberately does not use the WHATWG URL parser:
//! every admitted byte and every absent/empty/nonempty component state is
//! preserved.
//!
//! [`CanonicalHttpUrl`] and [`CanonicalResourceId`] are separate security
//! domains. They use the exactly pinned `url` crate's WHATWG canonicalization
//! and never compare or convert implicitly to [`AbsoluteUri`].
//!
//! The lack of convenience conversions is intentional:
//!
//! ```compile_fail
//! use fastmcp_core::{AbsoluteUri, CanonicalHttpUrl};
//!
//! let wire = AbsoluteUri::parse("https://example.test/mcp").unwrap();
//! let _: CanonicalHttpUrl = wire.into();
//! ```
//!
//! ```compile_fail
//! use fastmcp_core::AbsoluteUri;
//!
//! let wire = AbsoluteUri::parse("custom:value").unwrap();
//! assert!(wire == "custom:value");
//! ```
//!
//! ```compile_fail
//! use fastmcp_core::{
//!     CanonicalHttpUrl, CanonicalResourceId, CanonicalResourceIdPolicy,
//! };
//!
//! let http = CanonicalHttpUrl::parse("https://example.test/mcp").unwrap();
//! let resource = CanonicalResourceId::parse_for_endpoint(
//!     "https://example.test/mcp",
//!     &http,
//!     CanonicalResourceIdPolicy::DEFAULT,
//! )
//! .unwrap();
//! assert!(http == resource);
//! ```
//!
//! Authority-bearing resource identifiers cannot be constructed without an
//! configured-endpoint binding:
//!
//! ```compile_fail
//! use fastmcp_core::CanonicalResourceId;
//!
//! let _ = CanonicalResourceId::parse("https://example.test/mcp");
//! ```
//!
//! ```compile_fail
//! use fastmcp_core::{CanonicalResourceId, CanonicalResourceIdPolicy};
//!
//! let _ = CanonicalResourceId::parse_with_policy(
//!     "https://example.test/mcp",
//!     CanonicalResourceIdPolicy::DEFAULT,
//! );
//! ```
//!
//! ```compile_fail
//! use fastmcp_core::{CanonicalResourceId, CanonicalResourceIdPolicy};
//!
//! let _ = CanonicalResourceId::parse_with_policy_and_max_bytes(
//!     "https://example.test/mcp",
//!     CanonicalResourceIdPolicy::DEFAULT,
//!     1024,
//! );
//! ```
//!
//! ```compile_fail
//! use fastmcp_core::AbsoluteUri;
//!
//! let _: AbsoluteUri = "custom:value".into();
//! ```
//!
//! ```compile_fail
//! use fastmcp_core::AbsoluteUri;
//!
//! let wire = AbsoluteUri::parse("custom:value").unwrap();
//! let _: String = wire.to_string();
//! ```

#![allow(clippy::module_name_repetitions)]

use std::cell::Cell;
use std::fmt;
use std::net::Ipv6Addr;

use url::{SyntaxViolation, Url};

/// Default encoded-byte limit for one ordinary MCP absolute URI.
pub const DEFAULT_ABSOLUTE_URI_MAX_BYTES: usize = 16 * 1024;

/// Hard encoded-byte ceiling for one ordinary MCP absolute URI.
pub const ABSOLUTE_URI_HARD_MAX_BYTES: usize = 64 * 1024;

/// Default input and canonical-output byte limit for a network URL.
pub const DEFAULT_CANONICAL_URL_MAX_BYTES: usize = DEFAULT_ABSOLUTE_URI_MAX_BYTES;

/// Hard input and canonical-output byte ceiling for a network URL.
pub const CANONICAL_URL_HARD_MAX_BYTES: usize = ABSOLUTE_URI_HARD_MAX_BYTES;

/// Maximum configured endpoints considered by one resource binding.
pub const MAX_CONFIGURED_RESOURCE_ENDPOINTS: usize = 64;

/// Maximum UTF-8 bytes in one stable configured-endpoint identity.
pub const MAX_CONFIGURED_RESOURCE_ENDPOINT_IDENTITY_BYTES: usize = 256;

/// An optional URI component with its wire-presence state intact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UriComponentState<'a> {
    /// The component delimiter was absent.
    Absent,
    /// The delimiter was present with no following component bytes.
    Empty,
    /// The delimiter was present with nonempty component bytes.
    NonEmpty(&'a str),
}

impl<'a> UriComponentState<'a> {
    fn from_optional(component: Option<&'a str>) -> Self {
        match component {
            None => Self::Absent,
            Some("") => Self::Empty,
            Some(value) => Self::NonEmpty(value),
        }
    }

    /// Returns whether the component delimiter was present.
    #[must_use]
    pub const fn is_present(self) -> bool {
        !matches!(self, Self::Absent)
    }

    /// Returns whether the component delimiter was present and empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        matches!(self, Self::Empty)
    }
}

/// A borrowed, parser-derived view of an [`AbsoluteUri`] scheme.
///
/// [`as_str`](Self::as_str) preserves the original spelling. Every semantic
/// scheme classification must instead use
/// [`is`](Self::is), which performs RFC 3986 ASCII-case-insensitive matching.
#[derive(Debug, Clone, Copy)]
pub struct AbsoluteUriScheme<'a> {
    original: &'a str,
}

impl<'a> AbsoluteUriScheme<'a> {
    /// Returns the scheme's exact original spelling.
    #[must_use]
    pub const fn as_str(self) -> &'a str {
        self.original
    }

    /// Classifies the scheme using RFC 3986 ASCII-case-insensitive matching.
    #[must_use]
    pub fn is(self, expected: &str) -> bool {
        self.original.eq_ignore_ascii_case(expected)
    }
}

/// RFC 3986 component in which an invalid character was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbsoluteUriComponent {
    /// The scheme before `:`.
    Scheme,
    /// The optional authority userinfo.
    Userinfo,
    /// The authority host.
    Host,
    /// The authority port.
    Port,
    /// The hierarchical or opaque path.
    Path,
    /// The query after `?`.
    Query,
    /// The fragment after `#`.
    Fragment,
}

impl AbsoluteUriComponent {
    const fn name(self) -> &'static str {
        match self {
            Self::Scheme => "scheme",
            Self::Userinfo => "userinfo",
            Self::Host => "host",
            Self::Port => "port",
            Self::Path => "path",
            Self::Query => "query",
            Self::Fragment => "fragment",
        }
    }
}

/// Structural authority failure while parsing an [`AbsoluteUri`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityErrorKind {
    /// More than one unescaped `@` delimiter was present.
    MultipleAtSigns,
    /// A bracketed IP literal did not have a closing bracket.
    MissingIpLiteralBracket,
    /// A bracketed value was neither RFC 3986 IPv6 nor IPvFuture syntax.
    InvalidIpLiteral,
    /// Bytes other than an optional `:` port followed the IP literal.
    InvalidIpLiteralSuffix,
    /// An unbracketed authority contained more than one `:` delimiter.
    UnbracketedColon,
}

impl AuthorityErrorKind {
    const fn description(self) -> &'static str {
        match self {
            Self::MultipleAtSigns => "multiple unescaped '@' delimiters",
            Self::MissingIpLiteralBracket => "missing closing IP-literal bracket",
            Self::InvalidIpLiteral => "invalid IPv6 or IPvFuture literal",
            Self::InvalidIpLiteralSuffix => "invalid bytes after IP literal",
            Self::UnbracketedColon => "multiple ':' delimiters in an unbracketed authority",
        }
    }
}

/// Error returned by bounded RFC 3986 [`AbsoluteUri`] admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbsoluteUriError {
    /// The requested caller limit exceeded the protocol hard ceiling.
    LimitExceedsHardCeiling {
        /// Requested limit.
        requested_max_bytes: usize,
        /// Protocol hard ceiling.
        hard_max_bytes: usize,
    },
    /// The encoded input exceeded the active limit.
    TooLong {
        /// Actual encoded bytes.
        input_bytes: usize,
        /// Active limit.
        max_bytes: usize,
    },
    /// The URI string was empty.
    Empty,
    /// No required scheme delimiter was present.
    MissingScheme,
    /// The scheme before `:` was empty.
    EmptyScheme,
    /// A raw non-ASCII byte was present. URI admission is not IRI admission.
    NonAscii {
        /// Zero-based byte index.
        index: usize,
    },
    /// A raw ASCII control or space was present.
    ControlOrSpace {
        /// Zero-based byte index.
        index: usize,
        /// Rejected byte.
        byte: u8,
    },
    /// A component contained a byte outside its RFC 3986 grammar.
    InvalidCharacter {
        /// Component containing the byte.
        component: AbsoluteUriComponent,
        /// Zero-based byte index in the complete URI.
        index: usize,
        /// Rejected byte.
        byte: u8,
    },
    /// `%` was not followed by exactly two ASCII hexadecimal digits.
    InvalidPercentEncoding {
        /// Zero-based byte index of `%`.
        index: usize,
    },
    /// The authority or bracketed IP-literal structure was malformed.
    InvalidAuthority {
        /// Zero-based byte index nearest the structural failure.
        index: usize,
        /// Failure class.
        kind: AuthorityErrorKind,
    },
}

impl fmt::Display for AbsoluteUriError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimitExceedsHardCeiling {
                requested_max_bytes,
                hard_max_bytes,
            } => write!(
                formatter,
                "absolute URI limit of {requested_max_bytes} bytes exceeds the \
                 {hard_max_bytes}-byte hard ceiling"
            ),
            Self::TooLong {
                input_bytes,
                max_bytes,
            } => write!(
                formatter,
                "absolute URI is {input_bytes} bytes, exceeding the {max_bytes}-byte limit"
            ),
            Self::Empty => formatter.write_str("absolute URI is empty"),
            Self::MissingScheme => formatter.write_str("absolute URI is missing a scheme"),
            Self::EmptyScheme => formatter.write_str("absolute URI has an empty scheme"),
            Self::NonAscii { index } => {
                write!(
                    formatter,
                    "absolute URI contains non-ASCII input at byte {index}"
                )
            }
            Self::ControlOrSpace { index, byte } => write!(
                formatter,
                "absolute URI contains control or space byte 0x{byte:02X} at byte {index}"
            ),
            Self::InvalidCharacter {
                component,
                index,
                byte,
            } => write!(
                formatter,
                "absolute URI {} contains invalid byte 0x{byte:02X} at byte {index}",
                component.name()
            ),
            Self::InvalidPercentEncoding { index } => write!(
                formatter,
                "absolute URI contains an invalid percent triplet at byte {index}"
            ),
            Self::InvalidAuthority { index, kind } => write!(
                formatter,
                "absolute URI authority is invalid at byte {index}: {}",
                kind.description()
            ),
        }
    }
}

impl std::error::Error for AbsoluteUriError {}

/// A bounded, byte-preserving RFC 3986 URI with a required scheme.
///
/// Equality and hashing use the complete original string. Scheme case,
/// percent-hex case, default-looking ports, dot segments, and empty component
/// delimiters are all identity-significant here.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AbsoluteUri {
    original: String,
    scheme_end: usize,
    query_delimiter: Option<usize>,
    fragment_delimiter: Option<usize>,
}

impl AbsoluteUri {
    /// Parses with [`DEFAULT_ABSOLUTE_URI_MAX_BYTES`].
    pub fn parse(input: &str) -> Result<Self, AbsoluteUriError> {
        Self::parse_with_max_bytes(input, DEFAULT_ABSOLUTE_URI_MAX_BYTES)
    }

    /// Parses with a caller-selected limit no greater than
    /// [`ABSOLUTE_URI_HARD_MAX_BYTES`].
    ///
    /// The length check occurs before syntax validation and before the
    /// admitted bytes are copied.
    pub fn parse_with_max_bytes(input: &str, max_bytes: usize) -> Result<Self, AbsoluteUriError> {
        if max_bytes > ABSOLUTE_URI_HARD_MAX_BYTES {
            return Err(AbsoluteUriError::LimitExceedsHardCeiling {
                requested_max_bytes: max_bytes,
                hard_max_bytes: ABSOLUTE_URI_HARD_MAX_BYTES,
            });
        }
        if input.len() > max_bytes {
            return Err(AbsoluteUriError::TooLong {
                input_bytes: input.len(),
                max_bytes,
            });
        }
        if input.is_empty() {
            return Err(AbsoluteUriError::Empty);
        }

        validate_ascii_wire_bytes(input)?;

        let scheme_end = input.find(':').ok_or(AbsoluteUriError::MissingScheme)?;
        validate_scheme(input, scheme_end)?;
        validate_percent_triplets(input, scheme_end + 1)?;

        let fragment_delimiter = input.find('#');
        let before_fragment_end = fragment_delimiter.unwrap_or(input.len());
        let query_delimiter = input[..before_fragment_end].find('?');
        let hier_end = query_delimiter.unwrap_or(before_fragment_end);

        validate_hier_part(input, scheme_end + 1, hier_end)?;
        if let Some(query) = query_delimiter {
            validate_query_or_fragment(
                input,
                query + 1,
                before_fragment_end,
                AbsoluteUriComponent::Query,
            )?;
        }
        if let Some(fragment) = fragment_delimiter {
            validate_query_or_fragment(
                input,
                fragment + 1,
                input.len(),
                AbsoluteUriComponent::Fragment,
            )?;
        }

        Ok(Self {
            original: input.to_owned(),
            scheme_end,
            query_delimiter,
            fragment_delimiter,
        })
    }

    /// Returns the complete, exact admitted wire spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.original
    }

    /// Returns the complete, exact admitted wire bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.original.as_bytes()
    }

    /// Returns the number of exact encoded wire bytes.
    #[must_use]
    pub fn encoded_bytes(&self) -> usize {
        self.original.len()
    }

    /// Returns the parser-derived scheme view.
    #[must_use]
    pub fn scheme(&self) -> AbsoluteUriScheme<'_> {
        AbsoluteUriScheme {
            original: &self.original[..self.scheme_end],
        }
    }

    /// Returns the hierarchical or opaque part between `:` and `?`/`#`.
    #[must_use]
    pub fn hier_part(&self) -> &str {
        let end = self
            .query_delimiter
            .or(self.fragment_delimiter)
            .unwrap_or(self.original.len());
        &self.original[self.scheme_end + 1..end]
    }

    /// Returns the exact query bytes, preserving absent versus present-empty.
    #[must_use]
    pub fn query(&self) -> Option<&str> {
        self.query_delimiter.map(|delimiter| {
            let end = self.fragment_delimiter.unwrap_or(self.original.len());
            &self.original[delimiter + 1..end]
        })
    }

    /// Returns a presence-aware view of the query component.
    #[must_use]
    pub fn query_state(&self) -> UriComponentState<'_> {
        UriComponentState::from_optional(self.query())
    }

    /// Returns the exact fragment bytes, preserving absent versus present-empty.
    #[must_use]
    pub fn fragment(&self) -> Option<&str> {
        self.fragment_delimiter
            .map(|delimiter| &self.original[delimiter + 1..])
    }

    /// Returns a presence-aware view of the fragment component.
    #[must_use]
    pub fn fragment_state(&self) -> UriComponentState<'_> {
        UriComponentState::from_optional(self.fragment())
    }
}

fn validate_ascii_wire_bytes(input: &str) -> Result<(), AbsoluteUriError> {
    for (index, byte) in input.bytes().enumerate() {
        if !byte.is_ascii() {
            return Err(AbsoluteUriError::NonAscii { index });
        }
        if byte <= b' ' || byte == 0x7f {
            return Err(AbsoluteUriError::ControlOrSpace { index, byte });
        }
    }
    Ok(())
}

fn validate_scheme(input: &str, scheme_end: usize) -> Result<(), AbsoluteUriError> {
    if scheme_end == 0 {
        return Err(AbsoluteUriError::EmptyScheme);
    }

    let scheme = &input.as_bytes()[..scheme_end];
    if !scheme[0].is_ascii_alphabetic() {
        return Err(AbsoluteUriError::InvalidCharacter {
            component: AbsoluteUriComponent::Scheme,
            index: 0,
            byte: scheme[0],
        });
    }

    for (index, byte) in scheme.iter().copied().enumerate().skip(1) {
        if !(byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')) {
            return Err(AbsoluteUriError::InvalidCharacter {
                component: AbsoluteUriComponent::Scheme,
                index,
                byte,
            });
        }
    }
    Ok(())
}

fn validate_percent_triplets(input: &str, start: usize) -> Result<(), AbsoluteUriError> {
    let bytes = input.as_bytes();
    let mut index = start;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len()
            || !bytes[index + 1].is_ascii_hexdigit()
            || !bytes[index + 2].is_ascii_hexdigit()
        {
            return Err(AbsoluteUriError::InvalidPercentEncoding { index });
        }
        index += 3;
    }
    Ok(())
}

fn validate_hier_part(
    input: &str,
    hier_start: usize,
    hier_end: usize,
) -> Result<(), AbsoluteUriError> {
    let hier = &input[hier_start..hier_end];
    if let Some(after_slashes) = hier.strip_prefix("//") {
        let authority_len = after_slashes.find('/').unwrap_or(after_slashes.len());
        let authority_start = hier_start + 2;
        validate_authority(&after_slashes[..authority_len], authority_start)?;
        let path_start = authority_start + authority_len;
        validate_path(input, path_start, hier_end)
    } else {
        validate_path(input, hier_start, hier_end)
    }
}

fn validate_authority(authority: &str, offset: usize) -> Result<(), AbsoluteUriError> {
    let (host_port, host_port_offset) = if let Some(at) = authority.find('@') {
        if let Some(second) = authority[at + 1..].find('@') {
            return Err(AbsoluteUriError::InvalidAuthority {
                index: offset + at + 1 + second,
                kind: AuthorityErrorKind::MultipleAtSigns,
            });
        }
        validate_component(
            &authority[..at],
            offset,
            AbsoluteUriComponent::Userinfo,
            is_userinfo_byte,
        )?;
        (&authority[at + 1..], offset + at + 1)
    } else {
        (authority, offset)
    };

    if let Some(ip_literal) = host_port.strip_prefix('[') {
        let close = ip_literal
            .find(']')
            .ok_or(AbsoluteUriError::InvalidAuthority {
                index: host_port_offset,
                kind: AuthorityErrorKind::MissingIpLiteralBracket,
            })?;
        let literal = &ip_literal[..close];
        if !is_valid_ip_literal(literal) {
            return Err(AbsoluteUriError::InvalidAuthority {
                index: host_port_offset + 1,
                kind: AuthorityErrorKind::InvalidIpLiteral,
            });
        }

        let suffix = &ip_literal[close + 1..];
        if suffix.is_empty() {
            return Ok(());
        }
        let Some(port) = suffix.strip_prefix(':') else {
            return Err(AbsoluteUriError::InvalidAuthority {
                index: host_port_offset + close + 2,
                kind: AuthorityErrorKind::InvalidIpLiteralSuffix,
            });
        };
        return validate_component(
            port,
            host_port_offset + close + 3,
            AbsoluteUriComponent::Port,
            |byte| byte.is_ascii_digit(),
        );
    }

    let (host, port) = match host_port.split_once(':') {
        Some((host, port)) => {
            if let Some(second) = port.find(':') {
                return Err(AbsoluteUriError::InvalidAuthority {
                    index: host_port_offset + host.len() + 1 + second,
                    kind: AuthorityErrorKind::UnbracketedColon,
                });
            }
            (host, Some(port))
        }
        None => (host_port, None),
    };

    validate_component(
        host,
        host_port_offset,
        AbsoluteUriComponent::Host,
        is_reg_name_byte,
    )?;
    if let Some(port) = port {
        validate_component(
            port,
            host_port_offset + host.len() + 1,
            AbsoluteUriComponent::Port,
            |byte| byte.is_ascii_digit(),
        )?;
    }
    Ok(())
}

fn is_valid_ip_literal(literal: &str) -> bool {
    literal.parse::<Ipv6Addr>().is_ok() || is_valid_ipv_future(literal)
}

fn is_valid_ipv_future(literal: &str) -> bool {
    let bytes = literal.as_bytes();
    if bytes.len() < 4 || !matches!(bytes[0], b'v' | b'V') {
        return false;
    }
    let Some(dot) = bytes[1..].iter().position(|byte| *byte == b'.') else {
        return false;
    };
    let dot = dot + 1;
    if dot == 1 || dot + 1 >= bytes.len() {
        return false;
    }
    bytes[1..dot].iter().all(u8::is_ascii_hexdigit)
        && bytes[dot + 1..]
            .iter()
            .copied()
            .all(|byte| is_unreserved(byte) || is_sub_delim(byte) || byte == b':')
}

fn validate_path(input: &str, start: usize, end: usize) -> Result<(), AbsoluteUriError> {
    validate_component(
        &input[start..end],
        start,
        AbsoluteUriComponent::Path,
        |byte| is_pchar(byte) || byte == b'/',
    )
}

fn validate_query_or_fragment(
    input: &str,
    start: usize,
    end: usize,
    component: AbsoluteUriComponent,
) -> Result<(), AbsoluteUriError> {
    validate_component(&input[start..end], start, component, |byte| {
        is_pchar(byte) || matches!(byte, b'/' | b'?')
    })
}

fn validate_component<F>(
    component: &str,
    offset: usize,
    kind: AbsoluteUriComponent,
    admitted: F,
) -> Result<(), AbsoluteUriError>
where
    F: Fn(u8) -> bool,
{
    for (relative, byte) in component.bytes().enumerate() {
        if !admitted(byte) {
            return Err(AbsoluteUriError::InvalidCharacter {
                component: kind,
                index: offset + relative,
                byte,
            });
        }
    }
    Ok(())
}

fn is_userinfo_byte(byte: u8) -> bool {
    is_unreserved(byte) || is_sub_delim(byte) || matches!(byte, b':' | b'%')
}

fn is_reg_name_byte(byte: u8) -> bool {
    is_unreserved(byte) || is_sub_delim(byte) || byte == b'%'
}

fn is_pchar(byte: u8) -> bool {
    is_unreserved(byte) || is_sub_delim(byte) || matches!(byte, b':' | b'@' | b'%')
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn is_sub_delim(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
    )
}

/// Named IDNA behavior of a canonical URL domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdnaPolicy {
    /// Use the IDNA processing performed by exactly pinned `url 2.5.8`.
    UrlCrateV2_5_8,
}

/// Named scheme/host case behavior of a canonical URL domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemeHostCasePolicy {
    /// Canonicalize scheme and DNS host case through `url 2.5.8`.
    UrlCrateV2_5_8,
}

/// Named default-port behavior of a canonical URL domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultPortPolicy {
    /// Elide the HTTP port 80 and HTTPS port 443 through `url 2.5.8`.
    ElideHttpAndHttpsDefaults,
}

/// Named dot-segment behavior of a canonical URL domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DotSegmentPolicy {
    /// Apply the WHATWG dot and percent-encoded-dot rules from `url 2.5.8`.
    UrlCrateV2_5_8,
}

/// Named percent-encoding behavior of a canonical URL domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PercentEncodingPolicy {
    /// Use `url 2.5.8` exactly: encode where its WHATWG parser requires,
    /// preserve already encoded non-dot path bytes and their hex case, and
    /// recognize percent-encoded dot segments according to that parser.
    UrlCrateV2_5_8,
}

/// Named trailing-slash policy of a canonical URL domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrailingSlashPolicy {
    /// Preserve `url 2.5.8` URL semantics, including `/` for a bare origin.
    UrlCrateV2_5_8,
    /// Require a non-root endpoint path without a trailing slash.
    NonRootWithoutTrailingSlash,
    /// Require a non-root endpoint path with a trailing slash.
    NonRootWithTrailingSlash,
    /// Require the root path `/`.
    RootEndpoint,
}

/// Named userinfo policy of a canonical URL domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserinfoPolicy {
    /// Preserve the canonical behavior of `url 2.5.8`.
    UrlCrateV2_5_8,
    /// Reject userinfo, including an input containing empty userinfo.
    Reject,
}

/// Named fragment policy of a canonical URL domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentPolicy {
    /// Preserve absent, empty, or nonempty canonical URL fragment state.
    Preserve,
    /// Reject every present fragment, including an empty fragment.
    Reject,
}

/// Named query policy of a canonical URL domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryPolicy {
    /// Preserve absent, empty, or nonempty canonical URL query state.
    Preserve,
    /// Reject every present query, including an empty query.
    Reject,
    /// Preserve a query after explicit deployment configuration declares it
    /// part of protected-resource identity.
    ResourceSignificant,
}

/// Named handling of non-fatal WHATWG parser syntax violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyntaxViolationPolicy {
    /// Follow the exact acceptance and canonicalization behavior of `url 2.5.8`.
    UrlCrateV2_5_8,
    /// Reject inputs for which `url 2.5.8` reports a non-fatal violation.
    Reject,
}

/// Reviewable description of a canonical URL domain's policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalUrlPolicy {
    /// IDNA behavior.
    pub idna: IdnaPolicy,
    /// Scheme and host case behavior.
    pub scheme_host_case: SchemeHostCasePolicy,
    /// Default-port behavior.
    pub default_port: DefaultPortPolicy,
    /// Dot-segment behavior.
    pub dot_segments: DotSegmentPolicy,
    /// Percent-encoding behavior.
    pub percent_encoding: PercentEncodingPolicy,
    /// Trailing-slash behavior.
    pub trailing_slash: TrailingSlashPolicy,
    /// Userinfo behavior.
    pub userinfo: UserinfoPolicy,
    /// Fragment behavior.
    pub fragment: FragmentPolicy,
    /// Query behavior.
    pub query: QueryPolicy,
    /// Non-fatal WHATWG syntax-violation behavior.
    pub syntax_violations: SyntaxViolationPolicy,
}

/// Exact policy applied by [`CanonicalHttpUrl`].
pub const CANONICAL_HTTP_URL_POLICY: CanonicalUrlPolicy = CanonicalUrlPolicy {
    idna: IdnaPolicy::UrlCrateV2_5_8,
    scheme_host_case: SchemeHostCasePolicy::UrlCrateV2_5_8,
    default_port: DefaultPortPolicy::ElideHttpAndHttpsDefaults,
    dot_segments: DotSegmentPolicy::UrlCrateV2_5_8,
    percent_encoding: PercentEncodingPolicy::UrlCrateV2_5_8,
    trailing_slash: TrailingSlashPolicy::UrlCrateV2_5_8,
    userinfo: UserinfoPolicy::UrlCrateV2_5_8,
    fragment: FragmentPolicy::Preserve,
    query: QueryPolicy::Preserve,
    syntax_violations: SyntaxViolationPolicy::UrlCrateV2_5_8,
};

/// Error returned by bounded [`CanonicalHttpUrl`] admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalHttpUrlError {
    /// The requested caller limit exceeded the hard ceiling.
    LimitExceedsHardCeiling {
        /// Requested limit.
        requested_max_bytes: usize,
        /// Hard ceiling.
        hard_max_bytes: usize,
    },
    /// The input exceeded the active limit before URL parsing.
    InputTooLong {
        /// Actual input bytes.
        input_bytes: usize,
        /// Active limit.
        max_bytes: usize,
    },
    /// A percent sign was not followed by two ASCII hexadecimal digits.
    InvalidPercentEncoding {
        /// Byte offset of the malformed percent sign in the caller input.
        byte_index: usize,
    },
    /// The `url` parser rejected the input.
    Parse(url::ParseError),
    /// The parsed URL's scheme was neither HTTP nor HTTPS.
    SchemeNotHttp,
    /// The parsed HTTP(S) URL did not have a host.
    MissingHost,
    /// WHATWG canonicalization expanded the serialization beyond the limit.
    CanonicalOutputTooLong {
        /// Canonical serialization bytes.
        canonical_bytes: usize,
        /// Active limit.
        max_bytes: usize,
    },
}

impl fmt::Display for CanonicalHttpUrlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimitExceedsHardCeiling {
                requested_max_bytes,
                hard_max_bytes,
            } => write!(
                formatter,
                "canonical-URL limit of {requested_max_bytes} bytes exceeds the \
                 {hard_max_bytes}-byte hard ceiling"
            ),
            Self::InputTooLong {
                input_bytes,
                max_bytes,
            } => write!(
                formatter,
                "canonical-URL input is {input_bytes} bytes, exceeding the \
                 {max_bytes}-byte limit"
            ),
            Self::InvalidPercentEncoding { byte_index } => write!(
                formatter,
                "canonical-URL input has malformed percent encoding at byte {byte_index}"
            ),
            Self::Parse(error) => write!(formatter, "URL parser rejected input: {error}"),
            Self::SchemeNotHttp => formatter.write_str("URL scheme is not HTTP or HTTPS"),
            Self::MissingHost => formatter.write_str("HTTP(S) URL is missing a host"),
            Self::CanonicalOutputTooLong {
                canonical_bytes,
                max_bytes,
            } => write!(
                formatter,
                "canonical URL is {canonical_bytes} bytes, exceeding the \
                 {max_bytes}-byte limit"
            ),
        }
    }
}

impl std::error::Error for CanonicalHttpUrlError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parse(error) => Some(error),
            _ => None,
        }
    }
}

/// A bounded HTTP or HTTPS URL canonicalized by exactly pinned `url 2.5.8`.
///
/// This lower-layer type deliberately follows that parser's complete accepted
/// behavior, including its reported non-fatal syntax violations. Security use
/// sites that require stricter admission must construct a purpose type such as
/// [`CanonicalResourceId`].
#[derive(Debug, Clone)]
pub struct CanonicalHttpUrl {
    url: Url,
    syntax_flags: UrlSyntaxFlags,
}

impl PartialEq for CanonicalHttpUrl {
    fn eq(&self, other: &Self) -> bool {
        self.url == other.url
    }
}

impl Eq for CanonicalHttpUrl {}

impl std::hash::Hash for CanonicalHttpUrl {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.url.hash(state);
    }
}

impl CanonicalHttpUrl {
    /// Parses with [`DEFAULT_CANONICAL_URL_MAX_BYTES`].
    pub fn parse(input: &str) -> Result<Self, CanonicalHttpUrlError> {
        Self::parse_with_max_bytes(input, DEFAULT_CANONICAL_URL_MAX_BYTES)
    }

    /// Parses with a caller-selected limit no greater than
    /// [`CANONICAL_URL_HARD_MAX_BYTES`].
    pub fn parse_with_max_bytes(
        input: &str,
        max_bytes: usize,
    ) -> Result<Self, CanonicalHttpUrlError> {
        parse_canonical_http_url(input, max_bytes).map(|parsed| parsed.url)
    }

    /// Returns the exact named policy applied by this type.
    #[must_use]
    pub const fn policy() -> CanonicalUrlPolicy {
        CANONICAL_HTTP_URL_POLICY
    }

    /// Returns the canonical URL serialization.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }

    /// Returns the canonical URL serialization as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.url.as_str().as_bytes()
    }

    /// Returns the canonical lowercase `http` or `https` scheme.
    #[must_use]
    pub fn scheme(&self) -> &str {
        self.url.scheme()
    }

    /// Returns the canonical ASCII host.
    #[must_use]
    pub fn host(&self) -> &str {
        self.url.host_str().unwrap_or_default()
    }

    /// Returns the explicit non-default port, if present.
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        self.url.port()
    }

    /// Returns the explicit port or the scheme's known default.
    #[must_use]
    pub fn effective_port(&self) -> u16 {
        let known_default = if self.url.scheme() == "http" { 80 } else { 443 };
        self.url.port().unwrap_or(known_default)
    }

    /// Returns the canonical percent-encoded path.
    #[must_use]
    pub fn path(&self) -> &str {
        self.url.path()
    }

    /// Returns the canonical query, preserving absent versus present-empty.
    #[must_use]
    pub fn query(&self) -> Option<&str> {
        self.url.query()
    }

    /// Returns the canonical fragment, preserving absent versus present-empty.
    #[must_use]
    pub fn fragment(&self) -> Option<&str> {
        self.url.fragment()
    }

    /// Returns whether canonical userinfo remains present.
    #[must_use]
    pub fn has_userinfo(&self) -> bool {
        self.url.authority().contains('@')
    }

    fn has_syntax_violation(&self) -> bool {
        self.syntax_flags.any
    }

    fn has_credential_syntax_violation(&self) -> bool {
        self.syntax_flags.credentials
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct UrlSyntaxFlags {
    any: bool,
    credentials: bool,
}

struct ParsedCanonicalHttpUrl {
    url: CanonicalHttpUrl,
    syntax_flags: UrlSyntaxFlags,
}

fn parse_canonical_http_url(
    input: &str,
    max_bytes: usize,
) -> Result<ParsedCanonicalHttpUrl, CanonicalHttpUrlError> {
    if max_bytes > CANONICAL_URL_HARD_MAX_BYTES {
        return Err(CanonicalHttpUrlError::LimitExceedsHardCeiling {
            requested_max_bytes: max_bytes,
            hard_max_bytes: CANONICAL_URL_HARD_MAX_BYTES,
        });
    }
    if input.len() > max_bytes {
        return Err(CanonicalHttpUrlError::InputTooLong {
            input_bytes: input.len(),
            max_bytes,
        });
    }
    validate_http_percent_triplets(input)?;
    if has_empty_http_authority(input) {
        return Err(CanonicalHttpUrlError::MissingHost);
    }

    let syntax_flags = Cell::new(UrlSyntaxFlags::default());
    let callback = |violation: SyntaxViolation| {
        let mut flags = syntax_flags.get();
        flags.any = true;
        if matches!(
            violation,
            SyntaxViolation::EmbeddedCredentials | SyntaxViolation::UnencodedAtSign
        ) {
            flags.credentials = true;
        }
        syntax_flags.set(flags);
    };
    let url = Url::options()
        .syntax_violation_callback(Some(&callback))
        .parse(input)
        .map_err(CanonicalHttpUrlError::Parse)?;

    if !matches!(url.scheme(), "http" | "https") {
        return Err(CanonicalHttpUrlError::SchemeNotHttp);
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(CanonicalHttpUrlError::MissingHost);
    }
    if url.as_str().len() > max_bytes {
        return Err(CanonicalHttpUrlError::CanonicalOutputTooLong {
            canonical_bytes: url.as_str().len(),
            max_bytes,
        });
    }

    Ok(ParsedCanonicalHttpUrl {
        url: CanonicalHttpUrl {
            url,
            syntax_flags: syntax_flags.get(),
        },
        syntax_flags: syntax_flags.get(),
    })
}

fn validate_http_percent_triplets(input: &str) -> Result<(), CanonicalHttpUrlError> {
    let bytes = input.as_bytes();
    for (byte_index, byte) in bytes.iter().enumerate() {
        if *byte == b'%'
            && (byte_index + 2 >= bytes.len()
                || !bytes[byte_index + 1].is_ascii_hexdigit()
                || !bytes[byte_index + 2].is_ascii_hexdigit())
        {
            return Err(CanonicalHttpUrlError::InvalidPercentEncoding { byte_index });
        }
    }
    Ok(())
}

fn has_empty_http_authority(input: &str) -> bool {
    let Some((scheme, after_scheme)) = input.split_once(':') else {
        return false;
    };
    if !(scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")) {
        return false;
    }
    let Some(authority) = after_scheme.strip_prefix("//") else {
        return false;
    };
    authority.is_empty()
        || authority.starts_with('/')
        || authority.starts_with('?')
        || authority.starts_with('#')
}

/// Endpoint-path shape accepted for a protected MCP resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceEndpointPathPolicy {
    /// Require a non-root path with no trailing slash. This is the safe default.
    NonRootWithoutTrailingSlash,
    /// Require a non-root path whose endpoint semantics include a trailing slash.
    NonRootWithTrailingSlash,
    /// Require exactly the root path `/`.
    RootEndpoint,
}

impl ResourceEndpointPathPolicy {
    const fn trailing_slash_policy(self) -> TrailingSlashPolicy {
        match self {
            Self::NonRootWithoutTrailingSlash => TrailingSlashPolicy::NonRootWithoutTrailingSlash,
            Self::NonRootWithTrailingSlash => TrailingSlashPolicy::NonRootWithTrailingSlash,
            Self::RootEndpoint => TrailingSlashPolicy::RootEndpoint,
        }
    }
}

/// Closed construction policy for [`CanonicalResourceId`].
///
/// The default requires the usual most-specific non-root MCP endpoint path,
/// has no trailing slash, and rejects all query components. Deployments whose
/// endpoint semantics differ must select a named constructor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalResourceIdPolicy {
    endpoint_path: ResourceEndpointPathPolicy,
    query: QueryPolicy,
}

/// A named configured MCP endpoint considered by resource binding.
///
/// The identity is retained by [`CanonicalResourceId`] after selection so a
/// caller can bind later authorization to the precise configured endpoint,
/// rather than to a URI string alone.
#[derive(Debug, Clone, Copy)]
pub struct ConfiguredResourceEndpoint<'a> {
    identity: &'a str,
    endpoint: &'a CanonicalHttpUrl,
    resource_policy: CanonicalResourceIdPolicy,
}

impl<'a> ConfiguredResourceEndpoint<'a> {
    /// Creates a configured endpoint with an explicit stable identity and
    /// complete named resource policy.
    #[must_use]
    pub const fn new(
        identity: &'a str,
        endpoint: &'a CanonicalHttpUrl,
        resource_policy: CanonicalResourceIdPolicy,
    ) -> Self {
        Self {
            identity,
            endpoint,
            resource_policy,
        }
    }

    /// Returns the configured endpoint identity.
    #[must_use]
    pub const fn identity(self) -> &'a str {
        self.identity
    }

    /// Returns the configured canonical endpoint URL.
    #[must_use]
    pub const fn endpoint(self) -> &'a CanonicalHttpUrl {
        self.endpoint
    }

    /// Returns the complete named resource policy for this endpoint.
    #[must_use]
    pub const fn resource_policy(self) -> CanonicalResourceIdPolicy {
        self.resource_policy
    }
}

impl CanonicalResourceIdPolicy {
    /// Safe default: non-root endpoint, no trailing slash, and no query.
    pub const DEFAULT: Self = Self {
        endpoint_path: ResourceEndpointPathPolicy::NonRootWithoutTrailingSlash,
        query: QueryPolicy::Reject,
    };

    /// Selects endpoint semantics that require a non-root trailing slash.
    #[must_use]
    pub const fn non_root_with_trailing_slash() -> Self {
        Self {
            endpoint_path: ResourceEndpointPathPolicy::NonRootWithTrailingSlash,
            query: QueryPolicy::Reject,
        }
    }

    /// Selects an MCP endpoint deployed exactly at the origin root.
    #[must_use]
    pub const fn root_endpoint() -> Self {
        Self {
            endpoint_path: ResourceEndpointPathPolicy::RootEndpoint,
            query: QueryPolicy::Reject,
        }
    }

    /// Explicitly declares a bounded canonical query resource-significant.
    #[must_use]
    pub const fn with_resource_significant_query(mut self) -> Self {
        self.query = QueryPolicy::ResourceSignificant;
        self
    }

    /// Returns the selected endpoint-path policy.
    #[must_use]
    pub const fn endpoint_path(self) -> ResourceEndpointPathPolicy {
        self.endpoint_path
    }

    /// Returns the selected query policy.
    #[must_use]
    pub const fn query(self) -> QueryPolicy {
        self.query
    }

    /// Returns the complete reviewable canonicalization policy.
    #[must_use]
    pub const fn canonicalization(self) -> CanonicalUrlPolicy {
        CanonicalUrlPolicy {
            idna: IdnaPolicy::UrlCrateV2_5_8,
            scheme_host_case: SchemeHostCasePolicy::UrlCrateV2_5_8,
            default_port: DefaultPortPolicy::ElideHttpAndHttpsDefaults,
            dot_segments: DotSegmentPolicy::UrlCrateV2_5_8,
            percent_encoding: PercentEncodingPolicy::UrlCrateV2_5_8,
            trailing_slash: self.endpoint_path.trailing_slash_policy(),
            userinfo: UserinfoPolicy::Reject,
            fragment: FragmentPolicy::Reject,
            query: self.query,
            syntax_violations: SyntaxViolationPolicy::Reject,
        }
    }
}

impl Default for CanonicalResourceIdPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Error returned by [`CanonicalResourceId`] construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalResourceIdError {
    /// HTTP URL parsing or bounded canonicalization failed.
    HttpUrl(CanonicalHttpUrlError),
    /// The input triggered a non-fatal WHATWG syntax violation. Resource
    /// identity rejects rather than repairs such ambiguous input.
    NonCanonicalSyntax,
    /// Userinfo was present, including syntactically empty userinfo.
    UserinfoNotAllowed,
    /// The canonical scheme was HTTP rather than required HTTPS.
    HttpsRequired,
    /// A fragment delimiter was present, including an empty fragment.
    FragmentNotAllowed,
    /// A query delimiter was present without explicit resource-significant
    /// query policy.
    QueryNotAllowed,
    /// The canonical path did not satisfy the selected endpoint-path policy.
    EndpointPathPolicyMismatch {
        /// Required path shape.
        required: ResourceEndpointPathPolicy,
    },
    /// No configured endpoint was supplied for binding.
    ConfiguredEndpointSetEmpty,
    /// A configured endpoint omitted its stable identity.
    ConfiguredEndpointIdentityEmpty,
    /// More than one configured endpoint used the same stable identity.
    ConfiguredEndpointIdentityDuplicate,
    /// The configured endpoint set exceeded its bounded admission limit.
    ConfiguredEndpointSetTooLarge {
        /// Supplied configured endpoint count.
        endpoint_count: usize,
        /// Maximum admitted configured endpoint count.
        max_endpoints: usize,
    },
    /// A configured endpoint identity exceeded its bounded admission limit.
    ConfiguredEndpointIdentityTooLong {
        /// Supplied identity UTF-8 byte count.
        identity_bytes: usize,
        /// Maximum admitted identity UTF-8 byte count.
        max_identity_bytes: usize,
    },
    /// A configured endpoint contains userinfo and cannot be a resource
    /// binding authority.
    ConfiguredEndpointUserinfoNotAllowed,
    /// A configured endpoint was accepted only after a non-fatal URL parser
    /// repair and therefore cannot satisfy the resource syntax policy.
    ConfiguredEndpointNonCanonicalSyntax,
    /// A configured endpoint does not satisfy its complete named policy.
    ConfiguredEndpointPolicyMismatch,
    /// No configured endpoint had the canonical scheme, host, and effective
    /// port of the protected resource.
    ConfiguredEndpointOriginMismatch,
    /// No origin-compatible configured endpoint matched the resource path and
    /// query under its complete named policy.
    NoMatchingConfiguredEndpoint,
    /// More than one matching configured endpoint had maximal specificity.
    AmbiguousConfiguredEndpoint,
}

impl fmt::Display for CanonicalResourceIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HttpUrl(error) => error.fmt(formatter),
            Self::NonCanonicalSyntax => {
                formatter.write_str("resource identifier contains non-canonical URL syntax")
            }
            Self::UserinfoNotAllowed => {
                formatter.write_str("resource identifier must not contain userinfo")
            }
            Self::HttpsRequired => formatter.write_str("resource identifier must use HTTPS"),
            Self::FragmentNotAllowed => {
                formatter.write_str("resource identifier must not contain a fragment")
            }
            Self::QueryNotAllowed => formatter.write_str(
                "resource identifier query requires explicit resource-significant policy",
            ),
            Self::EndpointPathPolicyMismatch { required } => write!(
                formatter,
                "resource identifier path does not satisfy endpoint policy {required:?}"
            ),
            Self::ConfiguredEndpointSetEmpty => {
                formatter.write_str("resource identifier requires a configured endpoint")
            }
            Self::ConfiguredEndpointIdentityEmpty => {
                formatter.write_str("configured MCP endpoint identity must not be empty")
            }
            Self::ConfiguredEndpointIdentityDuplicate => {
                formatter.write_str("configured MCP endpoint identities must be unique")
            }
            Self::ConfiguredEndpointSetTooLarge {
                endpoint_count,
                max_endpoints,
            } => write!(
                formatter,
                "configured MCP endpoint count of {endpoint_count} exceeds the \
                 {max_endpoints}-endpoint limit"
            ),
            Self::ConfiguredEndpointIdentityTooLong {
                identity_bytes,
                max_identity_bytes,
            } => write!(
                formatter,
                "configured MCP endpoint identity is {identity_bytes} bytes, exceeding the \
                 {max_identity_bytes}-byte limit"
            ),
            Self::ConfiguredEndpointUserinfoNotAllowed => {
                formatter.write_str("configured MCP endpoint must not contain userinfo")
            }
            Self::ConfiguredEndpointNonCanonicalSyntax => {
                formatter.write_str("configured MCP endpoint contains non-canonical URL syntax")
            }
            Self::ConfiguredEndpointPolicyMismatch => formatter
                .write_str("configured MCP endpoint does not satisfy its named resource policy"),
            Self::ConfiguredEndpointOriginMismatch => formatter
                .write_str("resource identifier origin does not match any configured MCP endpoint"),
            Self::NoMatchingConfiguredEndpoint => {
                formatter.write_str("resource identifier does not match a configured MCP endpoint")
            }
            Self::AmbiguousConfiguredEndpoint => formatter.write_str(
                "resource identifier matches multiple equally specific configured MCP endpoints",
            ),
        }
    }
}

impl std::error::Error for CanonicalResourceIdError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::HttpUrl(error) => Some(error),
            _ => None,
        }
    }
}

/// A canonical, HTTPS-only protected MCP resource identifier.
///
/// Userinfo and fragments are always rejected. Queries and endpoint trailing
/// slash/root semantics require explicit named policy. Equality and hashing
/// use the final canonical serialization plus the selected configured endpoint
/// identity and exist solely within this resource-identifier domain.
/// Construction is available only through endpoint-binding constructors.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonicalResourceId {
    url: CanonicalHttpUrl,
    configured_endpoint_identity: String,
}

impl CanonicalResourceId {
    // This unbound parser is deliberately private. Its result is returned only
    // after a public endpoint-binding constructor has checked path and query.
    fn parse_unbound_with_policy_and_max_bytes(
        input: &str,
        policy: CanonicalResourceIdPolicy,
        max_bytes: usize,
    ) -> Result<Self, CanonicalResourceIdError> {
        let parsed = parse_canonical_http_url(input, max_bytes)
            .map_err(CanonicalResourceIdError::HttpUrl)?;
        validate_resource_common(&parsed)?;
        validate_resource_policy(&parsed, policy)?;

        Ok(Self {
            url: parsed.url,
            configured_endpoint_identity: String::new(),
        })
    }

    /// Parses and binds a resource to exactly one maximal matching configured
    /// endpoint.
    ///
    /// Candidates must have the endpoint's canonical scheme, host, and
    /// effective port. Their query state/value must match exactly, and their
    /// path must be at or below the endpoint path on a path-segment boundary.
    /// The longest matching endpoint path wins; an equal-specificity tie is
    /// rejected rather than selected by configuration order.
    pub fn parse_for_configured_endpoints(
        input: &str,
        configured_endpoints: &[ConfiguredResourceEndpoint<'_>],
    ) -> Result<Self, CanonicalResourceIdError> {
        Self::parse_for_configured_endpoints_with_max_bytes(
            input,
            configured_endpoints,
            DEFAULT_CANONICAL_URL_MAX_BYTES,
        )
    }

    /// Bounded form of
    /// [`parse_for_configured_endpoints`](Self::parse_for_configured_endpoints).
    pub fn parse_for_configured_endpoints_with_max_bytes(
        input: &str,
        configured_endpoints: &[ConfiguredResourceEndpoint<'_>],
        max_bytes: usize,
    ) -> Result<Self, CanonicalResourceIdError> {
        if configured_endpoints.is_empty() {
            return Err(CanonicalResourceIdError::ConfiguredEndpointSetEmpty);
        }
        if configured_endpoints.len() > MAX_CONFIGURED_RESOURCE_ENDPOINTS {
            return Err(CanonicalResourceIdError::ConfiguredEndpointSetTooLarge {
                endpoint_count: configured_endpoints.len(),
                max_endpoints: MAX_CONFIGURED_RESOURCE_ENDPOINTS,
            });
        }
        validate_configured_endpoint_identities(configured_endpoints)?;

        let parsed = parse_canonical_http_url(input, max_bytes)
            .map_err(CanonicalResourceIdError::HttpUrl)?;
        validate_resource_common(&parsed)?;

        // Prefer the resource's own closed policy failure over a configured
        // endpoint policy mismatch when no origin-compatible policy could
        // admit this resource. This keeps rejected empty queries and endpoint
        // path shapes observable as input errors rather than configuration
        // errors from the convenience endpoint used by the caller.
        let mut origin_compatible = false;
        let mut policy_accepted = false;
        let mut resource_error = None;
        for configured in configured_endpoints {
            if !canonical_origins_match(&parsed.url, configured.endpoint) {
                continue;
            }
            origin_compatible = true;
            match validate_resource_policy(&parsed, configured.resource_policy) {
                Ok(()) => policy_accepted = true,
                Err(error) => {
                    resource_error.get_or_insert(error);
                }
            }
        }
        if origin_compatible && !policy_accepted {
            if let Some(error) = resource_error {
                return Err(error);
            }
        }
        validate_configured_endpoint_policies(configured_endpoints)?;
        let mut selected: Option<(usize, Self)> = None;
        let mut ambiguous_specificity = None;
        let mut origin_compatible = false;
        let mut any_policy_accepted = false;
        let mut resource_error = None;

        for configured in configured_endpoints {
            if !canonical_origins_match(&parsed.url, configured.endpoint) {
                continue;
            }
            origin_compatible = true;

            let mut resource = match Self::parse_unbound_with_policy_and_max_bytes(
                input,
                configured.resource_policy,
                max_bytes,
            ) {
                Ok(resource) => resource,
                Err(error) => {
                    resource_error.get_or_insert(error);
                    continue;
                }
            };
            any_policy_accepted = true;

            if resource.query() != configured.endpoint.query()
                || !endpoint_path_is_prefix_of_resource(configured.endpoint.path(), resource.path())
            {
                continue;
            }

            resource.configured_endpoint_identity = configured.identity.to_owned();
            let specificity = configured.endpoint.path().len();
            match &selected {
                None => {
                    selected = Some((specificity, resource));
                    ambiguous_specificity = None;
                }
                Some((selected_specificity, _)) if specificity > *selected_specificity => {
                    selected = Some((specificity, resource));
                    ambiguous_specificity = None;
                }
                Some((selected_specificity, _)) if specificity == *selected_specificity => {
                    ambiguous_specificity = Some(specificity);
                }
                Some(_) => {}
            }
        }

        if let Some((_, resource)) = selected {
            if ambiguous_specificity.is_some() {
                return Err(CanonicalResourceIdError::AmbiguousConfiguredEndpoint);
            }
            return Ok(resource);
        }
        if !origin_compatible {
            return Err(CanonicalResourceIdError::ConfiguredEndpointOriginMismatch);
        }
        if !any_policy_accepted {
            if let Some(error) = resource_error {
                return Err(error);
            }
        }
        Err(CanonicalResourceIdError::NoMatchingConfiguredEndpoint)
    }

    /// Parses and binds a resource against one configured endpoint.
    ///
    /// This is the single-endpoint convenience form of the bounded endpoint
    /// set selector. It applies the same canonical-origin and named-policy
    /// checks; it never treats an internal HTTP endpoint as interchangeable
    /// with a public HTTPS resource.
    pub fn parse_for_endpoint(
        input: &str,
        configured_endpoint: &CanonicalHttpUrl,
        policy: CanonicalResourceIdPolicy,
    ) -> Result<Self, CanonicalResourceIdError> {
        Self::parse_for_endpoint_with_max_bytes(
            input,
            configured_endpoint,
            policy,
            DEFAULT_CANONICAL_URL_MAX_BYTES,
        )
    }

    /// Bounded form of [`parse_for_endpoint`](Self::parse_for_endpoint).
    pub fn parse_for_endpoint_with_max_bytes(
        input: &str,
        configured_endpoint: &CanonicalHttpUrl,
        policy: CanonicalResourceIdPolicy,
        max_bytes: usize,
    ) -> Result<Self, CanonicalResourceIdError> {
        let configured = [ConfiguredResourceEndpoint::new(
            "single-configured-endpoint",
            configured_endpoint,
            policy,
        )];
        Self::parse_for_configured_endpoints_with_max_bytes(input, &configured, max_bytes)
    }

    /// Returns the selected complete named policy.
    #[must_use]
    pub const fn policy(resource_policy: CanonicalResourceIdPolicy) -> CanonicalUrlPolicy {
        resource_policy.canonicalization()
    }

    /// Returns the canonical HTTPS resource serialization.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }

    /// Returns the canonical HTTPS resource serialization as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.url.as_bytes()
    }

    /// Returns the canonical ASCII host.
    #[must_use]
    pub fn host(&self) -> &str {
        self.url.host()
    }

    /// Returns the explicit non-default port, if present.
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        self.url.port()
    }

    /// Returns the explicit port or HTTPS default 443.
    #[must_use]
    pub fn effective_port(&self) -> u16 {
        self.url.effective_port()
    }

    /// Returns the canonical percent-encoded protected endpoint path.
    #[must_use]
    pub fn path(&self) -> &str {
        self.url.path()
    }

    /// Returns the canonical resource-significant query when configured.
    #[must_use]
    pub fn query(&self) -> Option<&str> {
        self.url.query()
    }

    /// Returns the identity of the configured endpoint selected at binding.
    #[must_use]
    pub fn configured_endpoint_identity(&self) -> &str {
        &self.configured_endpoint_identity
    }
}

fn validate_resource_common(
    parsed: &ParsedCanonicalHttpUrl,
) -> Result<(), CanonicalResourceIdError> {
    if parsed.syntax_flags.credentials || parsed.url.has_userinfo() {
        return Err(CanonicalResourceIdError::UserinfoNotAllowed);
    }
    if parsed.syntax_flags.any {
        return Err(CanonicalResourceIdError::NonCanonicalSyntax);
    }
    if parsed.url.scheme() != "https" {
        return Err(CanonicalResourceIdError::HttpsRequired);
    }
    if parsed.url.fragment().is_some() {
        return Err(CanonicalResourceIdError::FragmentNotAllowed);
    }
    Ok(())
}

fn validate_resource_policy(
    parsed: &ParsedCanonicalHttpUrl,
    policy: CanonicalResourceIdPolicy,
) -> Result<(), CanonicalResourceIdError> {
    if policy.query == QueryPolicy::Reject && parsed.url.query().is_some() {
        return Err(CanonicalResourceIdError::QueryNotAllowed);
    }
    if !endpoint_path_matches(parsed.url.path(), policy.endpoint_path) {
        return Err(CanonicalResourceIdError::EndpointPathPolicyMismatch {
            required: policy.endpoint_path,
        });
    }
    Ok(())
}

fn canonical_origins_match(left: &CanonicalHttpUrl, right: &CanonicalHttpUrl) -> bool {
    left.scheme() == right.scheme()
        && left.host() == right.host()
        && left.effective_port() == right.effective_port()
}

fn validate_configured_endpoint_identities(
    configured_endpoints: &[ConfiguredResourceEndpoint<'_>],
) -> Result<(), CanonicalResourceIdError> {
    for (index, configured) in configured_endpoints.iter().enumerate() {
        if configured.identity.is_empty() {
            return Err(CanonicalResourceIdError::ConfiguredEndpointIdentityEmpty);
        }
        if configured.identity.len() > MAX_CONFIGURED_RESOURCE_ENDPOINT_IDENTITY_BYTES {
            return Err(
                CanonicalResourceIdError::ConfiguredEndpointIdentityTooLong {
                    identity_bytes: configured.identity.len(),
                    max_identity_bytes: MAX_CONFIGURED_RESOURCE_ENDPOINT_IDENTITY_BYTES,
                },
            );
        }
        if configured_endpoints[..index]
            .iter()
            .any(|earlier| earlier.identity == configured.identity)
        {
            return Err(CanonicalResourceIdError::ConfiguredEndpointIdentityDuplicate);
        }
    }
    Ok(())
}

fn validate_configured_endpoint_policies(
    configured_endpoints: &[ConfiguredResourceEndpoint<'_>],
) -> Result<(), CanonicalResourceIdError> {
    for configured in configured_endpoints {
        if configured.endpoint.has_userinfo()
            || configured.endpoint.has_credential_syntax_violation()
        {
            return Err(CanonicalResourceIdError::ConfiguredEndpointUserinfoNotAllowed);
        }
        if configured.endpoint.has_syntax_violation() {
            return Err(CanonicalResourceIdError::ConfiguredEndpointNonCanonicalSyntax);
        }
        if !configured_endpoint_matches_policy(configured) {
            return Err(CanonicalResourceIdError::ConfiguredEndpointPolicyMismatch);
        }
    }
    Ok(())
}

fn configured_endpoint_matches_policy(configured: &ConfiguredResourceEndpoint<'_>) -> bool {
    configured.endpoint.scheme() == "https"
        && configured.endpoint.fragment().is_none()
        && (configured.resource_policy.query != QueryPolicy::Reject
            || configured.endpoint.query().is_none())
        && endpoint_path_matches(
            configured.endpoint.path(),
            configured.resource_policy.endpoint_path,
        )
}

fn endpoint_path_is_prefix_of_resource(endpoint_path: &str, resource_path: &str) -> bool {
    let Some(suffix) = resource_path.strip_prefix(endpoint_path) else {
        return false;
    };
    (suffix.is_empty() || endpoint_path.ends_with('/') || suffix.starts_with('/'))
        && !contains_percent_encoded_path_separator(suffix)
}

fn contains_percent_encoded_path_separator(path_suffix: &str) -> bool {
    path_suffix.as_bytes().windows(3).any(|triplet| {
        triplet[0] == b'%'
            && ((triplet[1] == b'2' && matches!(triplet[2], b'f' | b'F'))
                || (triplet[1] == b'5' && matches!(triplet[2], b'c' | b'C')))
    })
}

fn endpoint_path_matches(path: &str, policy: ResourceEndpointPathPolicy) -> bool {
    match policy {
        ResourceEndpointPathPolicy::NonRootWithoutTrailingSlash => {
            path != "/" && !path.ends_with('/')
        }
        ResourceEndpointPathPolicy::NonRootWithTrailingSlash => path != "/" && path.ends_with('/'),
        ResourceEndpointPathPolicy::RootEndpoint => path == "/",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    fn parse_resource_for_matching_endpoint(
        input: &str,
        policy: CanonicalResourceIdPolicy,
    ) -> Result<CanonicalResourceId, CanonicalResourceIdError> {
        let endpoint = CanonicalHttpUrl::parse(input)
            .expect("resource test input must be accepted by the lower URL layer");
        CanonicalResourceId::parse_for_endpoint(input, &endpoint, policy)
    }

    fn parse_default_resource(
        input: &str,
    ) -> Result<CanonicalResourceId, CanonicalResourceIdError> {
        parse_resource_for_matching_endpoint(input, CanonicalResourceIdPolicy::DEFAULT)
    }

    #[test]
    fn uri_component_state_distinguishes_all_states() {
        assert_ne!(UriComponentState::Absent, UriComponentState::Empty);
        assert_ne!(UriComponentState::Empty, UriComponentState::NonEmpty(""));
        assert!(!UriComponentState::Absent.is_present());
        assert!(UriComponentState::Empty.is_present());
        assert!(UriComponentState::Empty.is_empty());
        assert!(!UriComponentState::NonEmpty("x").is_empty());
    }

    #[test]
    fn absolute_uri_scheme_identity_and_classification_are_separate() {
        let lower = AbsoluteUri::parse("https://example.test/x").unwrap();
        let upper = AbsoluteUri::parse("HTTPS://example.test/x").unwrap();
        let mixed = AbsoluteUri::parse("HtTpS://example.test/x").unwrap();

        assert_ne!(lower, upper);
        assert_ne!(upper, mixed);
        assert_eq!(upper.scheme().as_str(), "HTTPS");
        assert!(lower.scheme().is("HTTPS"));
        assert!(upper.scheme().is("https"));
        assert!(mixed.scheme().is("hTtPs"));
        assert!(!mixed.scheme().is("http"));
    }

    #[test]
    fn absolute_uri_never_normalizes_identity() {
        let spellings = [
            "HTTPS://EXAMPLE.test:443/a/./b/../c/%7e?",
            "https://example.test/a/c/~",
            "https://example.test:443/a/%2E/b/%7E?",
            "https://example.test/a/b/%7e?#",
        ];
        let values: Vec<_> = spellings
            .iter()
            .map(|input| AbsoluteUri::parse(input).unwrap())
            .collect();

        for (value, expected) in values.iter().zip(spellings) {
            assert_eq!(value.as_str(), expected);
        }
        assert_eq!(values.iter().collect::<HashSet<_>>().len(), spellings.len());
    }

    #[test]
    fn absolute_uri_length_boundaries_are_exact() {
        let at_default = format!("x:{}", "a".repeat(DEFAULT_ABSOLUTE_URI_MAX_BYTES - 2));
        assert_eq!(at_default.len(), DEFAULT_ABSOLUTE_URI_MAX_BYTES);
        assert!(AbsoluteUri::parse(&at_default).is_ok());

        let over_default = format!("{at_default}a");
        assert_eq!(
            AbsoluteUri::parse(&over_default),
            Err(AbsoluteUriError::TooLong {
                input_bytes: DEFAULT_ABSOLUTE_URI_MAX_BYTES + 1,
                max_bytes: DEFAULT_ABSOLUTE_URI_MAX_BYTES,
            })
        );
        assert!(
            AbsoluteUri::parse_with_max_bytes(&over_default, ABSOLUTE_URI_HARD_MAX_BYTES,).is_ok()
        );

        let at_hard = format!("x:{}", "a".repeat(ABSOLUTE_URI_HARD_MAX_BYTES - 2));
        assert!(AbsoluteUri::parse_with_max_bytes(&at_hard, ABSOLUTE_URI_HARD_MAX_BYTES,).is_ok());

        let over_hard = format!("{at_hard}a");
        assert_eq!(
            AbsoluteUri::parse_with_max_bytes(&over_hard, ABSOLUTE_URI_HARD_MAX_BYTES,),
            Err(AbsoluteUriError::TooLong {
                input_bytes: ABSOLUTE_URI_HARD_MAX_BYTES + 1,
                max_bytes: ABSOLUTE_URI_HARD_MAX_BYTES,
            })
        );
        assert_eq!(
            AbsoluteUri::parse_with_max_bytes("x:a", ABSOLUTE_URI_HARD_MAX_BYTES + 1,),
            Err(AbsoluteUriError::LimitExceedsHardCeiling {
                requested_max_bytes: ABSOLUTE_URI_HARD_MAX_BYTES + 1,
                hard_max_bytes: ABSOLUTE_URI_HARD_MAX_BYTES,
            })
        );
    }

    #[test]
    fn absolute_uri_rejects_raw_non_ascii_control_space_and_del() {
        let cases = [
            "scheme:café",
            "scheme:☃",
            "scheme:a b",
            "scheme:\ta",
            "scheme:\na",
            "scheme:\ra",
            "scheme:\u{0000}a",
            "scheme:\u{001f}a",
            "scheme:\u{007f}a",
            "scheme:a?x y",
            "scheme:a#x\ny",
        ];
        for input in cases {
            assert!(AbsoluteUri::parse(input).is_err(), "{input:?}");
        }
    }

    #[test]
    fn absolute_uri_authority_goldens_and_negatives() {
        let valid = [
            "x://",
            "x://host",
            "x://host:",
            "x://:123",
            "x://user:@host",
            "x://!$&'()*+,;=:pass@host",
            "x://999.999.999.999",
            "x://[::]",
            "x://[2001:db8:0:1::1]",
            "x://[vF.a:b!$&'()*+,;=]:999999",
        ];
        for input in valid {
            assert!(AbsoluteUri::parse(input).is_ok(), "{input}");
        }

        let invalid = [
            "x://user@other@host",
            "x://[",
            "x://[]",
            "x://[2001:::1]",
            "x://[v.example]",
            "x://[v1.]",
            "x://[v1.bad^]",
            "x://[::1]suffix",
            "x://[::1]:abc",
            "x://host:abc",
            "x://host:1:2",
            "x://ho[st",
            "x://ho]st",
            "x://user^@host",
        ];
        for input in invalid {
            assert!(AbsoluteUri::parse(input).is_err(), "{input}");
        }
    }

    #[test]
    fn absolute_uri_rejects_component_grammar_violations() {
        let cases = [
            r"scheme:a\b",
            "scheme:a[0]",
            "scheme:a|b",
            "scheme:a?query#fragment#again",
            "scheme:a?query^",
            "scheme:a#fragment[",
        ];
        for input in cases {
            assert!(AbsoluteUri::parse(input).is_err(), "{input}");
        }
    }

    #[test]
    fn absolute_uri_error_is_typed_and_does_not_echo_input() {
        let error = AbsoluteUri::parse("scheme:secret value").unwrap_err();
        let display = error.to_string();
        assert!(display.contains("byte"));
        assert!(!display.contains("secret"));
        let _: &dyn std::error::Error = &error;
    }

    #[test]
    fn canonical_http_policy_is_frozen_and_named() {
        assert_eq!(
            CanonicalHttpUrl::policy(),
            CanonicalUrlPolicy {
                idna: IdnaPolicy::UrlCrateV2_5_8,
                scheme_host_case: SchemeHostCasePolicy::UrlCrateV2_5_8,
                default_port: DefaultPortPolicy::ElideHttpAndHttpsDefaults,
                dot_segments: DotSegmentPolicy::UrlCrateV2_5_8,
                percent_encoding: PercentEncodingPolicy::UrlCrateV2_5_8,
                trailing_slash: TrailingSlashPolicy::UrlCrateV2_5_8,
                userinfo: UserinfoPolicy::UrlCrateV2_5_8,
                fragment: FragmentPolicy::Preserve,
                query: QueryPolicy::Preserve,
                syntax_violations: SyntaxViolationPolicy::UrlCrateV2_5_8,
            }
        );
    }

    #[test]
    fn canonical_http_default_ports_and_trailing_slashes_follow_url_crate() {
        let http = CanonicalHttpUrl::parse("HTTP://EXAMPLE.TEST:80").unwrap();
        let https = CanonicalHttpUrl::parse("HTTPS://EXAMPLE.TEST:443/").unwrap();
        let nondefault = CanonicalHttpUrl::parse("https://example.test:8443/mcp").unwrap();

        assert_eq!(http.as_str(), "http://example.test/");
        assert_eq!(https.as_str(), "https://example.test/");
        assert_eq!(nondefault.port(), Some(8443));
        assert_eq!(nondefault.effective_port(), 8443);
    }

    #[test]
    fn canonical_http_preserves_url_crate_percent_encoding_differentials() {
        let lower = CanonicalHttpUrl::parse("https://example.test/mcp/%7e").unwrap();
        let upper = CanonicalHttpUrl::parse("https://example.test/mcp/%7E").unwrap();
        let literal = CanonicalHttpUrl::parse("https://example.test/mcp/~").unwrap();
        let dot = CanonicalHttpUrl::parse("https://example.test/a/%2e/b").unwrap();
        let encoded_delimiters =
            CanonicalHttpUrl::parse("https://example.test/mcp/%2F%3F%23?key=%26#%3D").unwrap();

        assert_eq!(lower.as_str(), "https://example.test/mcp/%7e");
        assert_eq!(upper.as_str(), "https://example.test/mcp/%7E");
        assert_eq!(literal.as_str(), "https://example.test/mcp/~");
        assert_ne!(lower, upper);
        assert_ne!(upper, literal);
        assert_eq!(dot.as_str(), "https://example.test/a/b");
        assert_eq!(
            encoded_delimiters.as_str(),
            "https://example.test/mcp/%2F%3F%23?key=%26#%3D"
        );
    }

    #[test]
    fn canonical_http_rejects_malformed_percent_triplets_before_url_parsing() {
        let cases = [
            "https://example.test/mcp/%zz",
            "https://example.test/mcp/%2",
            "https://example.test/mcp/%",
            "https://example.test/mcp?key=%q0",
            "https://example.test/mcp#%0g",
        ];
        for input in cases {
            assert_eq!(
                CanonicalHttpUrl::parse(input),
                Err(CanonicalHttpUrlError::InvalidPercentEncoding {
                    byte_index: input.find('%').unwrap(),
                }),
                "{input}"
            );
        }
    }

    #[test]
    fn canonical_http_preserves_query_fragment_and_userinfo_policy() {
        let value = CanonicalHttpUrl::parse("https://user:pass@example.test/mcp?#").unwrap();
        assert!(value.has_userinfo());
        assert_eq!(value.query(), Some(""));
        assert_eq!(value.fragment(), Some(""));
        assert_eq!(value.as_str(), "https://user:pass@example.test/mcp?#");
    }

    #[test]
    fn canonical_http_checks_input_and_expanded_output_bounds() {
        assert_eq!(
            CanonicalHttpUrl::parse_with_max_bytes(
                "https://example.test/",
                CANONICAL_URL_HARD_MAX_BYTES + 1,
            ),
            Err(CanonicalHttpUrlError::LimitExceedsHardCeiling {
                requested_max_bytes: CANONICAL_URL_HARD_MAX_BYTES + 1,
                hard_max_bytes: CANONICAL_URL_HARD_MAX_BYTES,
            })
        );
        assert!(matches!(
            CanonicalHttpUrl::parse_with_max_bytes("https://example.test/path", 10,),
            Err(CanonicalHttpUrlError::InputTooLong { .. })
        ));

        let unicode_expansion = "https://example.test/☃";
        assert!(unicode_expansion.len() < 28);
        assert!(matches!(
            CanonicalHttpUrl::parse_with_max_bytes(unicode_expansion, 28),
            Err(CanonicalHttpUrlError::CanonicalOutputTooLong { .. })
        ));
    }

    #[test]
    fn canonical_resource_default_policy_is_https_no_query_nonroot_no_slash() {
        let policy = CanonicalResourceIdPolicy::DEFAULT;
        let named = policy.canonicalization();
        assert_eq!(named.userinfo, UserinfoPolicy::Reject);
        assert_eq!(named.fragment, FragmentPolicy::Reject);
        assert_eq!(named.query, QueryPolicy::Reject);
        assert_eq!(
            named.trailing_slash,
            TrailingSlashPolicy::NonRootWithoutTrailingSlash
        );
        assert_eq!(named.syntax_violations, SyntaxViolationPolicy::Reject);

        let value = parse_default_resource("HTTPS://BÜCHER.Example:443/a/../mcp").unwrap();
        assert_eq!(value.as_str(), "https://xn--bcher-kva.example/mcp");
        assert_eq!(value.host(), "xn--bcher-kva.example");
        assert_eq!(value.port(), None);
        assert_eq!(value.effective_port(), 443);
        assert_eq!(value.path(), "/mcp");
        assert_eq!(value.query(), None);
    }

    #[test]
    fn canonical_resource_rejects_userinfo_including_empty_forms() {
        let cases = [
            "https://user@example.test/mcp",
            "https://user:pass@example.test/mcp",
            "https://@example.test/mcp",
            "https://:@example.test/mcp",
        ];
        for input in cases {
            assert_eq!(
                parse_default_resource(input),
                Err(CanonicalResourceIdError::UserinfoNotAllowed),
                "{input}"
            );
        }
    }

    #[test]
    fn canonical_resource_rejects_present_query_and_fragment_by_default() {
        for input in ["https://example.test/mcp?", "https://example.test/mcp?x=1"] {
            assert_eq!(
                parse_default_resource(input),
                Err(CanonicalResourceIdError::QueryNotAllowed),
                "{input}"
            );
        }
        for input in [
            "https://example.test/mcp#",
            "https://example.test/mcp#fragment",
        ] {
            assert_eq!(
                parse_default_resource(input),
                Err(CanonicalResourceIdError::FragmentNotAllowed),
                "{input}"
            );
        }
    }

    #[test]
    fn canonical_resource_query_requires_named_resource_significance() {
        let policy = CanonicalResourceIdPolicy::DEFAULT.with_resource_significant_query();
        let absent =
            parse_resource_for_matching_endpoint("https://example.test/mcp", policy).unwrap();
        let empty =
            parse_resource_for_matching_endpoint("https://example.test/mcp?", policy).unwrap();
        let nonempty =
            parse_resource_for_matching_endpoint("https://example.test/mcp?tenant=one", policy)
                .unwrap();

        assert_eq!(absent.query(), None);
        assert_eq!(empty.query(), Some(""));
        assert_eq!(nonempty.query(), Some("tenant=one"));
        assert_ne!(absent, empty);
        assert_ne!(empty, nonempty);
    }

    #[test]
    fn canonical_resource_endpoint_path_policies_are_closed_and_explicit() {
        assert!(parse_default_resource("https://example.test/mcp").is_ok());
        assert!(matches!(
            parse_default_resource("https://example.test/"),
            Err(CanonicalResourceIdError::EndpointPathPolicyMismatch { .. })
        ));
        assert!(matches!(
            parse_default_resource("https://example.test/mcp/"),
            Err(CanonicalResourceIdError::EndpointPathPolicyMismatch { .. })
        ));

        let slash = CanonicalResourceIdPolicy::non_root_with_trailing_slash();
        assert!(parse_resource_for_matching_endpoint("https://example.test/mcp/", slash).is_ok());
        assert!(parse_resource_for_matching_endpoint("https://example.test/mcp", slash).is_err());

        let root = CanonicalResourceIdPolicy::root_endpoint();
        assert!(parse_resource_for_matching_endpoint("https://example.test/", root).is_ok());
        assert_eq!(
            parse_resource_for_matching_endpoint("https://example.test/mcp", root),
            Err(CanonicalResourceIdError::EndpointPathPolicyMismatch {
                required: ResourceEndpointPathPolicy::RootEndpoint,
            })
        );
    }

    #[test]
    fn configured_endpoint_selection_rejects_ties_foreign_origins_and_confusion() {
        let first = CanonicalHttpUrl::parse("https://api.example.test/tenant/mcp").unwrap();
        let second = CanonicalHttpUrl::parse("https://api.example.test/tenant/mcp").unwrap();
        let tied = [
            ConfiguredResourceEndpoint::new("first", &first, CanonicalResourceIdPolicy::DEFAULT),
            ConfiguredResourceEndpoint::new("second", &second, CanonicalResourceIdPolicy::DEFAULT),
        ];
        assert_eq!(
            CanonicalResourceId::parse_for_configured_endpoints(
                "https://api.example.test/tenant/mcp/tool",
                &tied,
            ),
            Err(CanonicalResourceIdError::AmbiguousConfiguredEndpoint)
        );

        let public = CanonicalHttpUrl::parse("https://api.example.test/mcp").unwrap();
        let endpoints = [ConfiguredResourceEndpoint::new(
            "public",
            &public,
            CanonicalResourceIdPolicy::DEFAULT,
        )];
        for resource in [
            "https://evil.example.test/mcp/tool",
            "https://127.0.0.1/mcp/tool",
            "https://[::1]/mcp/tool",
        ] {
            assert_eq!(
                CanonicalResourceId::parse_for_configured_endpoints(resource, &endpoints),
                Err(CanonicalResourceIdError::ConfiguredEndpointOriginMismatch),
                "{resource}"
            );
        }

        let userinfo = CanonicalHttpUrl::parse("https://user@api.example.test/mcp").unwrap();
        assert_eq!(
            CanonicalResourceId::parse_for_configured_endpoints(
                "https://api.example.test/mcp",
                &[ConfiguredResourceEndpoint::new(
                    "userinfo",
                    &userinfo,
                    CanonicalResourceIdPolicy::DEFAULT,
                )],
            ),
            Err(CanonicalResourceIdError::ConfiguredEndpointUserinfoNotAllowed)
        );
    }

    #[test]
    fn configured_endpoint_selection_rejects_repaired_provenance_and_bounds() {
        let endpoint = CanonicalHttpUrl::parse("https://api.example.test/mcp").unwrap();
        let repaired_endpoint = CanonicalHttpUrl::parse("https:api.example.test/mcp").unwrap();
        assert_eq!(
            CanonicalResourceId::parse_for_configured_endpoints(
                "https://api.example.test/mcp",
                &[ConfiguredResourceEndpoint::new(
                    "repaired",
                    &repaired_endpoint,
                    CanonicalResourceIdPolicy::DEFAULT,
                )],
            ),
            Err(CanonicalResourceIdError::ConfiguredEndpointNonCanonicalSyntax)
        );

        let foreign_endpoint = CanonicalHttpUrl::parse("https://foreign.example.test/mcp").unwrap();
        let last = ConfiguredResourceEndpoint::new(
            "sole-last-match",
            &endpoint,
            CanonicalResourceIdPolicy::DEFAULT,
        );
        let foreign_identities: Vec<_> = (0..MAX_CONFIGURED_RESOURCE_ENDPOINTS)
            .map(|index| format!("foreign-{index}"))
            .collect();
        let mut at_limit: Vec<_> = foreign_identities
            .iter()
            .map(|identity| {
                ConfiguredResourceEndpoint::new(
                    identity,
                    &foreign_endpoint,
                    CanonicalResourceIdPolicy::DEFAULT,
                )
            })
            .collect();
        *at_limit.last_mut().unwrap() = last;
        let selected = CanonicalResourceId::parse_for_configured_endpoints(
            "https://api.example.test/mcp",
            &at_limit,
        )
        .unwrap();
        assert_eq!(selected.configured_endpoint_identity(), "sole-last-match");

        let over_limit = vec![last; MAX_CONFIGURED_RESOURCE_ENDPOINTS + 1];
        assert_eq!(
            CanonicalResourceId::parse_for_configured_endpoints(
                "https://api.example.test/mcp/%zz",
                &over_limit,
            ),
            Err(CanonicalResourceIdError::ConfiguredEndpointSetTooLarge {
                endpoint_count: MAX_CONFIGURED_RESOURCE_ENDPOINTS + 1,
                max_endpoints: MAX_CONFIGURED_RESOURCE_ENDPOINTS,
            })
        );

        let identity_at_limit = "a".repeat(MAX_CONFIGURED_RESOURCE_ENDPOINT_IDENTITY_BYTES);
        let at_identity_limit = CanonicalResourceId::parse_for_configured_endpoints(
            "https://api.example.test/mcp",
            &[ConfiguredResourceEndpoint::new(
                &identity_at_limit,
                &endpoint,
                CanonicalResourceIdPolicy::DEFAULT,
            )],
        )
        .unwrap();
        assert_eq!(
            at_identity_limit.configured_endpoint_identity(),
            identity_at_limit
        );

        let identity_over_limit = "a".repeat(MAX_CONFIGURED_RESOURCE_ENDPOINT_IDENTITY_BYTES + 1);
        assert_eq!(
            CanonicalResourceId::parse_for_configured_endpoints(
                "https://api.example.test/mcp",
                &[ConfiguredResourceEndpoint::new(
                    &identity_over_limit,
                    &endpoint,
                    CanonicalResourceIdPolicy::DEFAULT,
                )],
            ),
            Err(
                CanonicalResourceIdError::ConfiguredEndpointIdentityTooLong {
                    identity_bytes: MAX_CONFIGURED_RESOURCE_ENDPOINT_IDENTITY_BYTES + 1,
                    max_identity_bytes: MAX_CONFIGURED_RESOURCE_ENDPOINT_IDENTITY_BYTES,
                }
            )
        );
    }

    #[test]
    fn configured_endpoint_selection_rejects_duplicate_identities_before_matching() {
        let shorter = CanonicalHttpUrl::parse("https://api.example.test/mcp").unwrap();
        let longer = CanonicalHttpUrl::parse("https://api.example.test/tenant/mcp").unwrap();
        assert_eq!(
            CanonicalResourceId::parse_for_configured_endpoints(
                "https://api.example.test/tenant/mcp/tool",
                &[
                    ConfiguredResourceEndpoint::new(
                        "shared-identity",
                        &shorter,
                        CanonicalResourceIdPolicy::DEFAULT,
                    ),
                    ConfiguredResourceEndpoint::new(
                        "shared-identity",
                        &longer,
                        CanonicalResourceIdPolicy::DEFAULT,
                    ),
                ],
            ),
            Err(CanonicalResourceIdError::ConfiguredEndpointIdentityDuplicate)
        );
        assert_eq!(
            CanonicalResourceId::parse_for_configured_endpoints(
                "https://api.example.test/tenant/mcp/%zz",
                &[
                    ConfiguredResourceEndpoint::new(
                        "shared-identity",
                        &shorter,
                        CanonicalResourceIdPolicy::DEFAULT,
                    ),
                    ConfiguredResourceEndpoint::new(
                        "shared-identity",
                        &longer,
                        CanonicalResourceIdPolicy::DEFAULT,
                    ),
                ],
            ),
            Err(CanonicalResourceIdError::ConfiguredEndpointIdentityDuplicate)
        );
    }

    #[test]
    fn configured_endpoint_selection_rejects_prefix_lookalikes_and_fragments() {
        let endpoint = CanonicalHttpUrl::parse("https://api.example.test/tenant/mcp").unwrap();
        let endpoints = [ConfiguredResourceEndpoint::new(
            "tenant",
            &endpoint,
            CanonicalResourceIdPolicy::DEFAULT,
        )];
        for input in [
            "https://api.example.test/tenant/mcp-evil",
            "https://api.example.test/tenant/mcp.evil",
            "https://api.example.test/tenant/mcp%2Ftool",
        ] {
            assert_eq!(
                CanonicalResourceId::parse_for_configured_endpoints(input, &endpoints),
                Err(CanonicalResourceIdError::NoMatchingConfiguredEndpoint),
                "{input}"
            );
        }

        let fragmented =
            CanonicalHttpUrl::parse("https://api.example.test/tenant/mcp#fragment").unwrap();
        assert_eq!(
            CanonicalResourceId::parse_for_configured_endpoints(
                "https://api.example.test/tenant/mcp/tool",
                &[ConfiguredResourceEndpoint::new(
                    "fragmented",
                    &fragmented,
                    CanonicalResourceIdPolicy::DEFAULT,
                )],
            ),
            Err(CanonicalResourceIdError::ConfiguredEndpointPolicyMismatch)
        );
    }

    #[test]
    fn configured_resource_significant_query_must_match_exactly() {
        let policy = CanonicalResourceIdPolicy::DEFAULT.with_resource_significant_query();
        let endpoint =
            CanonicalHttpUrl::parse("https://public.example.test/mcp?tenant=one").unwrap();
        assert!(
            CanonicalResourceId::parse_for_endpoint(
                "https://public.example.test/mcp?tenant=one",
                &endpoint,
                policy,
            )
            .is_ok()
        );
        assert_eq!(
            CanonicalResourceId::parse_for_endpoint(
                "https://public.example.test/mcp?tenant=two",
                &endpoint,
                policy,
            ),
            Err(CanonicalResourceIdError::NoMatchingConfiguredEndpoint)
        );
        assert_eq!(
            CanonicalResourceId::parse_for_endpoint(
                "https://public.example.test/mcp",
                &endpoint,
                policy,
            ),
            Err(CanonicalResourceIdError::NoMatchingConfiguredEndpoint)
        );

        let empty_endpoint = CanonicalHttpUrl::parse("https://public.example.test/mcp?").unwrap();
        assert!(
            CanonicalResourceId::parse_for_endpoint(
                "https://public.example.test/mcp?",
                &empty_endpoint,
                policy,
            )
            .is_ok()
        );
        assert_eq!(
            CanonicalResourceId::parse_for_endpoint(
                "https://public.example.test/mcp",
                &empty_endpoint,
                policy,
            ),
            Err(CanonicalResourceIdError::NoMatchingConfiguredEndpoint)
        );

        let absent_endpoint = CanonicalHttpUrl::parse("https://public.example.test/mcp").unwrap();
        assert_eq!(
            CanonicalResourceId::parse_for_endpoint(
                "https://public.example.test/mcp?",
                &absent_endpoint,
                policy,
            ),
            Err(CanonicalResourceIdError::NoMatchingConfiguredEndpoint)
        );
    }

    #[test]
    fn configured_endpoint_query_must_be_absent_under_default_policy() {
        let endpoint =
            CanonicalHttpUrl::parse("https://public.example.test/mcp?tenant=one").unwrap();
        assert_eq!(
            CanonicalResourceId::parse_for_endpoint(
                "https://public.example.test/mcp",
                &endpoint,
                CanonicalResourceIdPolicy::DEFAULT,
            ),
            Err(CanonicalResourceIdError::ConfiguredEndpointPolicyMismatch)
        );
        assert_eq!(
            CanonicalResourceId::parse_for_endpoint(
                "https://public.example.test/mcp?tenant=one",
                &endpoint,
                CanonicalResourceIdPolicy::DEFAULT,
            ),
            Err(CanonicalResourceIdError::QueryNotAllowed)
        );
    }

    #[test]
    fn canonical_resource_applies_url_dot_and_percent_policies() {
        let plain = parse_default_resource("https://example.test/mcp").unwrap();
        let dot = parse_default_resource("https://example.test/a/%2e%2e/mcp").unwrap();
        assert_eq!(plain, dot);

        let lower = parse_default_resource("https://example.test/mcp/%7e").unwrap();
        let upper = parse_default_resource("https://example.test/mcp/%7E").unwrap();
        assert_ne!(lower, upper);
        assert_eq!(lower.path(), "/mcp/%7e");
        assert_eq!(upper.path(), "/mcp/%7E");
    }

    #[test]
    fn canonical_resource_rejects_url_syntax_repair_differentials() {
        let cases = [
            " https://example.test/mcp",
            "https:example.test/mcp",
            r"https://example.test\mcp",
            "https://example.test/mcp with-space",
        ];
        for input in cases {
            assert_eq!(
                parse_default_resource(input),
                Err(CanonicalResourceIdError::NonCanonicalSyntax),
                "{input:?}"
            );
        }
    }

    #[test]
    fn canonical_resource_rejects_malformed_percent_encoded_delimiters_and_bounds() {
        let endpoint = CanonicalHttpUrl::parse("https://example.test/mcp").unwrap();
        for input in [
            "https://example.test/mcp/%zz",
            "https://example.test/mcp/%2",
            "https://example.test/mcp?x=%q0",
            "https://example.test/mcp#%0g",
        ] {
            assert_eq!(
                CanonicalResourceId::parse_for_endpoint(
                    input,
                    &endpoint,
                    CanonicalResourceIdPolicy::DEFAULT,
                ),
                Err(CanonicalResourceIdError::HttpUrl(
                    CanonicalHttpUrlError::InvalidPercentEncoding {
                        byte_index: input.find('%').unwrap(),
                    }
                )),
                "{input}"
            );
        }

        let endpoints = [ConfiguredResourceEndpoint::new(
            "bounded",
            &endpoint,
            CanonicalResourceIdPolicy::DEFAULT,
        )];
        assert_eq!(
            CanonicalResourceId::parse_for_configured_endpoints_with_max_bytes(
                "https://example.test/mcp",
                &endpoints,
                CANONICAL_URL_HARD_MAX_BYTES + 1,
            ),
            Err(CanonicalResourceIdError::HttpUrl(
                CanonicalHttpUrlError::LimitExceedsHardCeiling {
                    requested_max_bytes: CANONICAL_URL_HARD_MAX_BYTES + 1,
                    hard_max_bytes: CANONICAL_URL_HARD_MAX_BYTES,
                }
            ))
        );
        assert_eq!(
            CanonicalResourceId::parse_for_configured_endpoints_with_max_bytes(
                "https://example.test/mcp",
                &endpoints,
                10,
            ),
            Err(CanonicalResourceIdError::HttpUrl(
                CanonicalHttpUrlError::InputTooLong {
                    input_bytes: "https://example.test/mcp".len(),
                    max_bytes: 10,
                }
            ))
        );
        assert_eq!(
            CanonicalResourceId::parse_for_configured_endpoints("https://example.test/mcp", &[]),
            Err(CanonicalResourceIdError::ConfiguredEndpointSetEmpty)
        );
    }

    #[test]
    fn canonical_resource_same_domain_equality_and_hash_use_canonical_value() {
        let first = parse_default_resource("HTTPS://EXAMPLE.TEST:443/a/../mcp").unwrap();
        let second = parse_default_resource("https://example.test/mcp").unwrap();
        assert_eq!(first, second);

        let mut set = HashSet::new();
        set.insert(first.clone());
        set.insert(second.clone());
        assert_eq!(set.len(), 1);

        let mut map = HashMap::new();
        map.insert(first, "value");
        assert_eq!(map.get(&second), Some(&"value"));
    }

    #[test]
    fn canonical_errors_are_typed_standard_errors() {
        let http_error = CanonicalHttpUrl::parse("not a URL").unwrap_err();
        let resource_error = parse_default_resource("http://example.test/mcp").unwrap_err();
        let _: &dyn std::error::Error = &http_error;
        let _: &dyn std::error::Error = &resource_error;
        assert!(!http_error.to_string().is_empty());
        assert!(!resource_error.to_string().is_empty());
    }

    #[test]
    fn uri_domains_remain_distinct_at_runtime() {
        let wire = AbsoluteUri::parse("HTTPS://EXAMPLE.TEST:443/a/../mcp").unwrap();
        let http = CanonicalHttpUrl::parse("HTTPS://EXAMPLE.TEST:443/a/../mcp").unwrap();
        let resource = parse_default_resource("HTTPS://EXAMPLE.TEST:443/a/../mcp").unwrap();

        assert_eq!(wire.as_str(), "HTTPS://EXAMPLE.TEST:443/a/../mcp");
        assert_eq!(http.as_str(), "https://example.test/mcp");
        assert_eq!(resource.as_str(), "https://example.test/mcp");
        assert_ne!(wire.as_str(), http.as_str());
    }
}
