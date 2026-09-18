//! Ordered, same-issuer metadata retrieval with per-candidate reservations.
//!
//! A location is not an issuer election. The selected identifier, trust roots
//! and endpoint-origin grants are immutable for this whole sequence. No request
//! is retried, no redirect is followed, and no credential is sent on a GET.
//! OpenID well-known locations carry OAuth metadata, not OIDC identity claims.

use asupersync::{Cx, types::Time};
use serde::Deserialize;

use super::{
    OAuthDiscoveryError, TrustedOAuthIssuer, check_context, decode_metadata,
    fetch_metadata, https_url, issuer_metadata_urls, present, validate_optional_array,
};

/// Safe positional tags: diagnostics never retain issuer URLs or tenant paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssuerMetadataLocation {
    OAuthAuthorizationServer,
    OpenIdInserted,
    OpenIdAppended,
}

/// Bounded failure causes, independent of peer bodies and transport diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssuerMetadataCause {
    NotFound,
    HttpStatus(u16),
    InvalidRepresentation,
    InvalidMetadata,
    IssuerMismatch,
    EndpointNotTrusted,
    ResourceMismatch,
    UnsupportedFlow,
    UnsupportedScopes,
    SignedMetadataUnsupported,
    TransportFailed,
    CandidateDeadline,
    Cancelled,
    RuntimeUnavailable,
    InvalidPolicy,
}

/// The most important failure without discarding earlier candidate failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssuerMetadataFailureClass {
    Cancelled,
    OverallDeadline,
    TrustOrIntegrity,
    ProtocolOrHttp,
    Transport,
    NotFound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IssuerMetadataAttempt {
    location: IssuerMetadataLocation,
    cause: IssuerMetadataCause,
}
impl IssuerMetadataAttempt {
    pub fn location(&self) -> IssuerMetadataLocation { self.location }
    pub fn cause(&self) -> IssuerMetadataCause { self.cause }
}

/// At most three ordered attempted locations; cancellation may stop earlier.
/// No failed document, URL, body, token or parser exception is retained.
#[derive(Debug)]
pub struct IssuerMetadataFailure {
    attempts: Vec<IssuerMetadataAttempt>,
    interrupted: Option<IssuerMetadataFailureClass>,
}
impl IssuerMetadataFailure {
    pub fn attempts(&self) -> &[IssuerMetadataAttempt] { &self.attempts }

    pub fn classification(&self) -> IssuerMetadataFailureClass {
        if let Some(reason) = self.interrupted { return reason; }
        self.attempts.iter().map(|attempt| match attempt.cause {
            IssuerMetadataCause::Cancelled => (5, IssuerMetadataFailureClass::Cancelled),
            IssuerMetadataCause::IssuerMismatch | IssuerMetadataCause::EndpointNotTrusted
            | IssuerMetadataCause::ResourceMismatch | IssuerMetadataCause::UnsupportedFlow
            | IssuerMetadataCause::UnsupportedScopes | IssuerMetadataCause::SignedMetadataUnsupported
            | IssuerMetadataCause::InvalidPolicy => (4, IssuerMetadataFailureClass::TrustOrIntegrity),
            IssuerMetadataCause::HttpStatus(_) | IssuerMetadataCause::InvalidRepresentation
            | IssuerMetadataCause::InvalidMetadata => (3, IssuerMetadataFailureClass::ProtocolOrHttp),
            IssuerMetadataCause::TransportFailed | IssuerMetadataCause::CandidateDeadline
            | IssuerMetadataCause::RuntimeUnavailable => (2, IssuerMetadataFailureClass::Transport),
            IssuerMetadataCause::NotFound => (1, IssuerMetadataFailureClass::NotFound),
        }).max_by_key(|(rank, _)| *rank).map_or(IssuerMetadataFailureClass::NotFound, |(_, class)| class)
    }
}

fn cause(error: &OAuthDiscoveryError) -> IssuerMetadataCause {
    match error {
        OAuthDiscoveryError::MetadataNotFound => IssuerMetadataCause::NotFound,
        OAuthDiscoveryError::HttpStatus { status } => IssuerMetadataCause::HttpStatus(*status),
        OAuthDiscoveryError::InvalidRepresentation => IssuerMetadataCause::InvalidRepresentation,
        OAuthDiscoveryError::InvalidMetadata => IssuerMetadataCause::InvalidMetadata,
        OAuthDiscoveryError::IssuerMismatch => IssuerMetadataCause::IssuerMismatch,
        OAuthDiscoveryError::EndpointNotTrusted => IssuerMetadataCause::EndpointNotTrusted,
        OAuthDiscoveryError::ResourceMismatch => IssuerMetadataCause::ResourceMismatch,
        OAuthDiscoveryError::UnsupportedFlow => IssuerMetadataCause::UnsupportedFlow,
        OAuthDiscoveryError::UnsupportedScopes => IssuerMetadataCause::UnsupportedScopes,
        OAuthDiscoveryError::SignedMetadataUnsupported => IssuerMetadataCause::SignedMetadataUnsupported,
        OAuthDiscoveryError::TransportFailed => IssuerMetadataCause::TransportFailed,
        OAuthDiscoveryError::TimedOut => IssuerMetadataCause::CandidateDeadline,
        OAuthDiscoveryError::Cancelled => IssuerMetadataCause::Cancelled,
        OAuthDiscoveryError::RuntimeUnavailable => IssuerMetadataCause::RuntimeUnavailable,
        OAuthDiscoveryError::InvalidPolicy | OAuthDiscoveryError::NoTrustedIssuer
        | OAuthDiscoveryError::ResourceMetadataExhausted(_) | OAuthDiscoveryError::IssuerMetadataExhausted(_)
        | OAuthDiscoveryError::Login(_) => IssuerMetadataCause::InvalidPolicy,
    }
}

// Every consumer validates the selected issuer before interpreting its own
// fields. Do not deserialize via Value: escaped duplicate issuer keys must fail.
#[derive(Deserialize)]
struct Identity {
    issuer: String,
}
fn admit_identity(issuer: &TrustedOAuthIssuer, body: &[u8]) -> Result<(), OAuthDiscoveryError> {
    let identity: Identity = decode_metadata(body)?;
    // Same admission function as TrustedOAuthIssuer::new, then exact original
    // string equality. Canonical URL equivalence is NOT issuer identity.
    https_url(&identity.issuer)?;
    if identity.issuer != issuer.identifier { return Err(OAuthDiscoveryError::IssuerMismatch); }
    Ok(())
}

// Shape/endpoint profile shared by code and machine consumers. The caller still
// owns its chosen grant/authentication method; a supported but unusable method
// does not silently become another method. Native flow admission can be supplied
// to discover() instead to include all code-flow predicates in candidate election.
#[derive(Deserialize)]
struct EndpointDocument {
    token_endpoint: String,
    #[serde(default, deserialize_with = "present")]
    authorization_endpoint: Option<String>,
    #[serde(default, deserialize_with = "present")]
    response_types_supported: Option<Vec<String>>,
    #[serde(default, deserialize_with = "present")]
    grant_types_supported: Option<Vec<String>>,
    #[serde(default, deserialize_with = "present")]
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
    #[serde(default, deserialize_with = "present")]
    scopes_supported: Option<Vec<String>>,
    #[serde(default, deserialize_with = "present")]
    signed_metadata: Option<String>,
}
pub(super) fn admit_document(issuer: &TrustedOAuthIssuer, body: &[u8]) -> Result<Vec<u8>, OAuthDiscoveryError> {
    let document: EndpointDocument = decode_metadata(body)?;
    if document.signed_metadata.is_some() { return Err(OAuthDiscoveryError::SignedMetadataUnsupported); }
    issuer.endpoint(&document.token_endpoint)?;
    if let Some(endpoint) = document.authorization_endpoint { issuer.endpoint(&endpoint)?; }
    for values in [document.response_types_supported, document.grant_types_supported,
        document.token_endpoint_auth_methods_supported, document.scopes_supported] {
        validate_optional_array(values.as_deref())?;
    }
    // Preserve the exact admitted source for each consumer's strict decoder.
    Ok(body.to_vec())
}

// Reserve an equal finite share for every remaining candidate before starting.
// Half of the remaining outer budget stays available for registration or other
// post-discovery work. Every GET has its own independent metadata byte ceiling.
fn deadlines(now: Time, end: Time, count: usize) -> Result<Vec<Time>, OAuthDiscoveryError> {
    if !(2..=3).contains(&count) { return Err(OAuthDiscoveryError::InvalidPolicy); }
    let remaining = end.as_nanos().checked_sub(now.as_nanos()).ok_or(OAuthDiscoveryError::TimedOut)?;
    let share = remaining / 2 / count as u64;
    if share == 0 { return Err(OAuthDiscoveryError::TimedOut); }
    Ok((1..=count).map(|index| Time::from_nanos(now.as_nanos() + share * index as u64)).collect())
}

/// Common retrieval engine. A winning value has passed identity and the supplied
/// consumer admission function under the SAME candidate time allowance. Failed
/// values are discarded, never merged with another candidate. Only local,
/// synchronous protocol validators are supplied here, not user callbacks.
pub(super) async fn discover<T>(
    cx: &Cx,
    deadline: Time,
    issuer: &TrustedOAuthIssuer,
    admit: impl Fn(&[u8]) -> Result<T, OAuthDiscoveryError>,
) -> Result<T, OAuthDiscoveryError> {
    check_context(cx, deadline)?;
    let locations = issuer_metadata_urls(&issuer.url)?;
    let schedule = deadlines(cx.now(), deadline, locations.len())?;
    let tags = [IssuerMetadataLocation::OAuthAuthorizationServer,
        IssuerMetadataLocation::OpenIdInserted, IssuerMetadataLocation::OpenIdAppended];
    let mut failure = IssuerMetadataFailure { attempts: Vec::with_capacity(3), interrupted: None };
    for ((location, end), tag) in locations.into_iter().zip(schedule).zip(tags) {
        if cx.checkpoint().is_err() {
            failure.interrupted = Some(IssuerMetadataFailureClass::Cancelled);
            break;
        }
        if cx.now() >= deadline {
            failure.interrupted = Some(IssuerMetadataFailureClass::OverallDeadline);
            break;
        }
        let result = fetch_metadata(cx, end, &location, &issuer.roots).await
            .and_then(|body| body.ok_or(OAuthDiscoveryError::MetadataNotFound))
            .and_then(|body| { admit_identity(issuer, &body)?; admit(&body) });
        // Synchronous admission is bounded input but cannot be preempted. Do
        // not publish its result if that work overran the reserved deadline.
        let result = if cx.checkpoint().is_err() {
            Err(OAuthDiscoveryError::Cancelled)
        } else if cx.now() >= end {
            Err(OAuthDiscoveryError::TimedOut)
        } else { result };
        match result {
            Ok(value) => return Ok(value),
            Err(error) => failure.attempts.push(IssuerMetadataAttempt { location: tag, cause: cause(&error) }),
        }
    }
    if cx.checkpoint().is_err() {
        failure.interrupted = Some(IssuerMetadataFailureClass::Cancelled);
    } else if cx.now() >= deadline {
        failure.interrupted = Some(IssuerMetadataFailureClass::OverallDeadline);
    }
    Err(OAuthDiscoveryError::IssuerMetadataExhausted(failure))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn issuer() -> TrustedOAuthIssuer { TrustedOAuthIssuer::new("https://issuer.example/tenant/").unwrap() }

    #[test]
    fn identity_requires_valid_exact_issuer_not_canonical_equivalence() {
        let selected = issuer();
        assert!(admit_identity(&selected, br#"{"issuer":"https://issuer.example/tenant/"}"#).is_ok());
        for other in ["https://issuer.example/tenant", "https://ISSUER.example/tenant/", "https://issuer.example:443/tenant/"] {
            assert!(matches!(admit_identity(&selected, json!({"issuer":other}).to_string().as_bytes()), Err(OAuthDiscoveryError::IssuerMismatch)));
        }
        for invalid in ["not-an-issuer", "http://issuer.example/tenant/", "https://issuer.example/tenant/?q=1", "https://issuer.example/tenant/#x"] {
            assert!(matches!(admit_identity(&selected, json!({"issuer":invalid}).to_string().as_bytes()), Err(OAuthDiscoveryError::InvalidMetadata)));
        }
    }

    #[test]
    fn duplicate_escaped_identity_and_positional_json_cannot_win() {
        for body in [r#"{"issuer":"https://issuer.example/tenant/","iss\u0075er":"https://issuer.example/tenant/"}"#,
            r#"["https://issuer.example/tenant/"]"#, r#"{"issuer":null}"#, "{}"] {
            assert!(matches!(admit_identity(&issuer(), body.as_bytes()), Err(OAuthDiscoveryError::InvalidMetadata)));
        }
    }

    #[test]
    fn generic_endpoint_profile_admits_machine_metadata_without_browser_fields() {
        let body = br#"{"issuer":"https://issuer.example/tenant/","token_endpoint":"https://issuer.example/token","grant_types_supported":["client_credentials"],"x-exact":1.20e+4}"#;
        assert_eq!(admit_document(&issuer(), body).unwrap(), body);
        let other = br#"{"token_endpoint":"https://elsewhere.example/token"}"#;
        assert!(matches!(admit_document(&issuer(), other), Err(OAuthDiscoveryError::EndpointNotTrusted)));
        let trusted = issuer().with_endpoint_origin(super::super::https_url("https://elsewhere.example/").unwrap()).unwrap();
        assert_eq!(admit_document(&trusted, other).unwrap(), other);
    }

    #[test]
    fn endpoint_document_rejects_invalid_shapes_before_source_is_retained() {
        for body in [r#"{"token_endpoint":"http://issuer.example/token"}"#,
            r#"{"token_endpoint":"https://issuer.example/token","authorization_endpoint":null}"#,
            r#"{"token_endpoint":"https://issuer.example/token","grant_types_supported":["code","code"]}"#,
            r#"{"token_endpoint":"https://issuer.example/token","token_endpoint":"https://issuer.example/token"}"#] {
            assert!(matches!(admit_document(&issuer(), body.as_bytes()), Err(OAuthDiscoveryError::InvalidMetadata)));
        }
        assert!(matches!(admit_document(&issuer(), br#"{"token_endpoint":"https://issuer.example/token","signed_metadata":"unverified"}"#), Err(OAuthDiscoveryError::SignedMetadataUnsupported)));
    }

    #[test]
    fn schedule_reserves_later_attempts_and_post_discovery_time() {
        let now = Time::from_nanos(100);
        let end = Time::from_nanos(700);
        assert_eq!(deadlines(now, end, 3).unwrap(), [Time::from_nanos(200), Time::from_nanos(300), Time::from_nanos(400)]);
        assert_eq!(deadlines(now, end, 2).unwrap(), [Time::from_nanos(250), Time::from_nanos(400)]);
        for count in [0, 1, 4, usize::MAX] { assert!(deadlines(now, end, count).is_err()); }
        assert!(deadlines(now, Time::from_nanos(105), 3).is_err());
        assert!(deadlines(end, now, 3).is_err());
        assert_eq!(deadlines(Time::from_nanos(u64::MAX - 600), Time::from_nanos(u64::MAX), 3).unwrap()[2], Time::from_nanos(u64::MAX - 300));
    }

    #[test]
    fn diagnostics_preserve_order_and_never_erase_integrity_with_later_404() {
        let failure = IssuerMetadataFailure { attempts: vec![
            IssuerMetadataAttempt { location: IssuerMetadataLocation::OAuthAuthorizationServer, cause: IssuerMetadataCause::IssuerMismatch },
            IssuerMetadataAttempt { location: IssuerMetadataLocation::OpenIdInserted, cause: IssuerMetadataCause::HttpStatus(503) },
            IssuerMetadataAttempt { location: IssuerMetadataLocation::OpenIdAppended, cause: IssuerMetadataCause::NotFound },
        ], interrupted: None };
        assert_eq!(failure.classification(), IssuerMetadataFailureClass::TrustOrIntegrity);
        assert_eq!(failure.attempts()[0].cause(), IssuerMetadataCause::IssuerMismatch);
        assert_eq!(failure.attempts()[2].location(), IssuerMetadataLocation::OpenIdAppended);
        let error = OAuthDiscoveryError::IssuerMetadataExhausted(failure);
        assert!(!format!("{error:?} {error}").contains("https://"));
    }

    #[test]
    fn interruption_preserves_attempts_without_inventing_later_contacts() {
        for interrupted in [IssuerMetadataFailureClass::Cancelled, IssuerMetadataFailureClass::OverallDeadline] {
            let failure = IssuerMetadataFailure { attempts: vec![IssuerMetadataAttempt {
                location: IssuerMetadataLocation::OAuthAuthorizationServer, cause: IssuerMetadataCause::IssuerMismatch,
            }], interrupted: Some(interrupted) };
            assert_eq!(failure.classification(), interrupted);
            assert_eq!(failure.attempts().len(), 1);
        }
    }
}
