//! Bounded HTTP/JSON admission shared by all three enterprise token stages.

use asupersync::security::SecretString;
use fastmcp_protocol::{SecurityDocumentKind, admit_security_document};
use serde::{Deserialize, Deserializer};

use super::{
    EnterpriseCacheDiagnostics, EnterpriseOAuthDenial, EnterpriseOAuthErrorCode,
    EnterpriseResponseError as Error, EnterpriseTokenResponse, EnterpriseTokenResponseStage,
};
use crate::http_auth::discovery::challenge::admits_one_basic_challenge;
use crate::http_auth::token_response::cache_policy;

const MAX_HEADER_FIELDS: usize = 64;
const MAX_HEADER_BYTES: usize = 16 * 1024;

fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}
fn secret<'de, D: Deserializer<'de>>(d: D) -> Result<Option<SecretString>, D::Error> {
    String::deserialize(d).map(SecretString::from_string).map(Some)
}

#[derive(Default)]
struct Presence(bool);
impl<'de> Deserialize<'de> for Presence {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        serde::de::IgnoredAny::deserialize(d)?;
        Ok(Self(true))
    }
}

// Token strings enter zeroizing owners directly. Unknown values are skipped
// after shared duplicate/depth/number admission, never collected into a Value.
#[derive(Deserialize)]
pub(super) struct Body {
    #[serde(default, deserialize_with = "secret")]
    pub access_token: Option<SecretString>,
    #[serde(default, deserialize_with = "secret")]
    pub id_token: Option<SecretString>,
    #[serde(default)]
    refresh_token: Presence,
    #[serde(default, deserialize_with = "present")]
    pub token_type: Option<String>,
    #[serde(default, deserialize_with = "present")]
    pub issued_token_type: Option<String>,
    #[serde(default, deserialize_with = "present")]
    pub scope: Option<String>,
    #[serde(default, deserialize_with = "present")]
    pub resource: Option<String>,
    #[serde(default, deserialize_with = "present")]
    pub expires_in: Option<u64>,
    #[serde(default, deserialize_with = "present")]
    error: Option<String>,
    #[serde(default, deserialize_with = "present")]
    error_description: Option<String>,
    #[serde(default, deserialize_with = "present")]
    error_uri: Option<String>,
    #[serde(default, deserialize_with = "present")]
    max_age: Option<u64>,
    #[serde(default)]
    authorization_details: Presence,
    #[serde(default)]
    cnf: Presence,
    #[serde(default)]
    act: Presence,
    #[serde(default)]
    sub_id: Presence,
}

#[allow(clippy::large_enum_variant)]
pub(super) enum AdmittedBody {
    Success(Body),
    Denied(EnterpriseOAuthDenial),
    StepUp(Option<u64>),
}

pub(super) fn admit(
    response: &EnterpriseTokenResponse<'_>,
    stage: EnterpriseTokenResponseStage,
    used_basic: bool,
    maximum_authentication_age_seconds: u64,
) -> Result<(AdmittedBody, EnterpriseCacheDiagnostics), Error> {
    let diagnostics = headers(response.headers, stage)?;
    admit_security_document(SecurityDocumentKind::TokenResponse, response.body)
        .map_err(|_| Error::InvalidResponse)?;
    let body: Body = serde_json::from_slice(response.body).map_err(|_| Error::InvalidResponse)?;
    if body.refresh_token.0 || body.authorization_details.0 || body.cnf.0
        || body.act.0 || body.sub_id.0
    {
        return Err(Error::InvalidResponse);
    }
    if let Some(error) = body.error.as_deref() {
        if body.access_token.is_some() || body.id_token.is_some() || body.token_type.is_some()
            || body.issued_token_type.is_some() || body.scope.is_some()
            || body.resource.is_some() || body.expires_in.is_some()
            || !error_text(error, 256)
            || body.error_description.as_deref().is_some_and(|s| !error_text(s, 2048))
            || body.error_uri.as_deref().is_some_and(|s| !error_uri(s))
        {
            return Err(Error::InvalidResponse);
        }
        if error == "insufficient_user_authentication" {
            if stage != EnterpriseTokenResponseStage::IdJag || response.status != 400
                || body.max_age.is_some_and(|age| age > maximum_authentication_age_seconds)
            {
                return Err(Error::InvalidResponse);
            }
            return Ok((AdmittedBody::StepUp(body.max_age), diagnostics));
        }
        if body.max_age.is_some() {
            return Err(Error::InvalidResponse);
        }
        let basic_denial = response.status == 401 && error == "invalid_client"
            && used_basic && admits_one_basic_challenge(response.headers);
        if response.status != 400 && !basic_denial {
            return Err(Error::UnexpectedStatus);
        }
        let code = match error {
            "invalid_request" => EnterpriseOAuthErrorCode::InvalidRequest,
            "invalid_client" => EnterpriseOAuthErrorCode::InvalidClient,
            "invalid_grant" => EnterpriseOAuthErrorCode::InvalidGrant,
            "unauthorized_client" => EnterpriseOAuthErrorCode::UnauthorizedClient,
            "unsupported_grant_type" => EnterpriseOAuthErrorCode::UnsupportedGrantType,
            "invalid_scope" => EnterpriseOAuthErrorCode::InvalidScope,
            "invalid_target" => EnterpriseOAuthErrorCode::InvalidTarget,
            "access_denied" => EnterpriseOAuthErrorCode::AccessDenied,
            "interaction_required" => EnterpriseOAuthErrorCode::InteractionRequired,
            _ => EnterpriseOAuthErrorCode::Extension,
        };
        return Ok((AdmittedBody::Denied(EnterpriseOAuthDenial {
            code, status: response.status, basic_challenge: basic_denial,
        }), diagnostics));
    }
    if response.status != 200 {
        return Err(Error::UnexpectedStatus);
    }
    if body.access_token.is_none() || body.token_type.is_none()
        || body.error_description.is_some() || body.error_uri.is_some()
        || body.max_age.is_some() || body.expires_in == Some(0)
    {
        return Err(Error::InvalidResponse);
    }
    match stage {
        EnterpriseTokenResponseStage::OidcCode => {
            if body.id_token.is_none() || body.issued_token_type.is_some() || body.resource.is_some()
                || !body.token_type.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("Bearer"))
            {
                return Err(Error::InvalidResponse);
            }
        }
        EnterpriseTokenResponseStage::IdJag => {
            if body.id_token.is_some() || body.resource.is_some()
                || body.issued_token_type.as_deref() != Some("urn:ietf:params:oauth:token-type:id-jag")
                || !body.token_type.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("N_A"))
            {
                return Err(Error::InvalidResponse);
            }
        }
        EnterpriseTokenResponseStage::AccessToken => {
            if body.id_token.is_some() || body.issued_token_type.is_some() || body.resource.is_none()
                || !body.token_type.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("Bearer"))
            {
                return Err(Error::InvalidResponse);
            }
        }
    }
    Ok((AdmittedBody::Success(body), diagnostics))
}

fn error_text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum
        && value.bytes().all(|b| b == 0x20 || b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b))
}
fn error_uri(value: &str) -> bool {
    // Discarded RFC6749 diagnostic text; never resolved or opened.
    !value.is_empty() && value.len() <= 2048
        && value.bytes().all(|b| b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b))
}
fn token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.'
        | b'^' | b'_' | 0x60 | b'|' | b'~')
}
fn ows(value: &str) -> &str {
    value.trim_matches([' ', '\t'])
}

fn headers(
    fields: &[(String, String)],
    stage: EnterpriseTokenResponseStage,
) -> Result<EnterpriseCacheDiagnostics, Error> {
    if fields.len() > MAX_HEADER_FIELDS {
        return Err(Error::InvalidHeaders);
    }
    let mut bytes = 0usize;
    let mut content_type = None;
    let mut content_encoding = false;
    for (name, value) in fields {
        bytes = bytes.checked_add(name.len()).and_then(|n| n.checked_add(value.len()))
            .ok_or(Error::InvalidHeaders)?;
        if bytes > MAX_HEADER_BYTES || name.is_empty() || !name.bytes().all(token_byte)
            || value.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f)
            || name.eq_ignore_ascii_case("DPoP") || name.eq_ignore_ascii_case("DPoP-Nonce")
        {
            return Err(Error::InvalidHeaders);
        }
        if name.eq_ignore_ascii_case("content-type") {
            if !value.is_ascii() || content_type.replace(value.as_str()).is_some() {
                return Err(Error::InvalidHeaders);
            }
        } else if name.eq_ignore_ascii_case("content-encoding") {
            if content_encoding || !ows(value).eq_ignore_ascii_case("identity") {
                return Err(Error::InvalidHeaders);
            }
            content_encoding = true;
        }
    }
    let mut media = content_type.ok_or(Error::InvalidHeaders)?.split(';');
    if !media.next().is_some_and(|s| ows(s).eq_ignore_ascii_case("application/json")) {
        return Err(Error::InvalidHeaders);
    }
    if let Some(parameter) = media.next() {
        let (name, value) = ows(parameter).split_once('=').ok_or(Error::InvalidHeaders)?;
        if !ows(name).eq_ignore_ascii_case("charset")
            || !(ows(value).eq_ignore_ascii_case("utf-8") || ows(value).eq_ignore_ascii_case("\"utf-8\""))
            || media.next().is_some()
        {
            return Err(Error::InvalidHeaders);
        }
    }
    let cache = cache_policy(fields).map_err(|_| Error::InvalidCachePolicy)?;
    Ok(EnterpriseCacheDiagnostics {
        missing_no_store: cache.missing_no_store,
        missing_pragma_no_cache: stage != EnterpriseTokenResponseStage::OidcCode && cache.missing_pragma_no_cache,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head() -> Vec<(String, String)> {
        vec![
            ("Content-Type".into(), "application/json".into()),
            ("Cache-Control".into(), "no-store".into()),
            ("Pragma".into(), "no-cache".into()),
        ]
    }

    #[test]
    fn enterprise_token_stages_admit_only_their_own_positive_shape() {
        let headers = head();
        let examples = [
            (EnterpriseTokenResponseStage::OidcCode, r#"{"access_token":"temporary","token_type":"Bearer","id_token":"signed","scope":"openid"}"#),
            (EnterpriseTokenResponseStage::IdJag, r#"{"access_token":"signed","token_type":"n_A","issued_token_type":"urn:ietf:params:oauth:token-type:id-jag"}"#),
            (EnterpriseTokenResponseStage::AccessToken, r#"{"access_token":"final","token_type":"bEaReR","resource":"https://mcp.example/mcp","scope":"read"}"#),
        ];
        for (own, body) in examples {
            for stage in [EnterpriseTokenResponseStage::OidcCode, EnterpriseTokenResponseStage::IdJag, EnterpriseTokenResponseStage::AccessToken] {
                let result = admit(&EnterpriseTokenResponse {
                    status: 200, headers: &headers, body: body.as_bytes(),
                }, stage, false, 3600);
                assert_eq!(matches!(result, Ok((AdmittedBody::Success(_), _))), own == stage);
            }
        }
    }

    #[test]
    fn enterprise_token_stages_reject_duplicates_nulls_mixed_grants_and_delegation() {
        let headers = head();
        let base = r#"{"access_token":"signed","token_type":"N_A","issued_token_type":"urn:ietf:params:oauth:token-type:id-jag""#;
        for addition in [
            r#", "token_type":"N_A"}"#, r#", "refresh_token":null}"#,
            r#", "expires_in":null}"#, r#", "expires_in":0}"#,
            r#", "expires_in":1.5}"#, r#", "scope":null}"#,
            r#", "error":"invalid_grant"}"#, r#", "authorization_details":null}"#,
            r#", "cnf":{}}"#, r#", "act":null}"#, r#", "sub_id":"alias"}"#,
            r#", "extension":{"duplicate":1,"duplicate":2}}"#,
        ] {
            let body = format!("{base}{addition}");
            assert!(admit(&EnterpriseTokenResponse {
                status: 200, headers: &headers, body: body.as_bytes(),
            }, EnterpriseTokenResponseStage::IdJag, false, 3600).is_err(), "{addition}");
        }
        let positive = format!("{base}, \"extension\":{{\"inert\":true}}}}");
        assert!(admit(&EnterpriseTokenResponse {
            status: 200, headers: &headers, body: positive.as_bytes(),
        }, EnterpriseTokenResponseStage::IdJag, false, 3600).is_ok());
    }

    #[test]
    fn enterprise_step_up_is_a_bounded_400_only_nonautomatic_outcome() {
        let headers = head();
        for age in ["", ",\"max_age\":0", ",\"max_age\":3600"] {
            let body = format!(r#"{{"error":"insufficient_user_authentication","error_description":"Fresh login required","acr_values":"ignored"{age}}}"#);
            for status in [200, 201, 400, 401, 403, 429, 500] {
                let result = admit(&EnterpriseTokenResponse {
                    status, headers: &headers, body: body.as_bytes(),
                }, EnterpriseTokenResponseStage::IdJag, true, 3600);
                assert_eq!(matches!(result, Ok((AdmittedBody::StepUp(_), _))), status == 400);
            }
        }
        for age in ["null", "-1", "1.5", "\"1\"", "3601", "18446744073709551616"] {
            let body = format!(r#"{{"error":"insufficient_user_authentication","max_age":{age}}}"#);
            assert!(admit(&EnterpriseTokenResponse {
                status: 400, headers: &headers, body: body.as_bytes(),
            }, EnterpriseTokenResponseStage::IdJag, true, 3600).is_err());
        }
    }

    #[test]
    fn enterprise_basic_denial_needs_one_matching_challenge_and_selected_method() {
        let body = br#"{"error":"invalid_client"}"#;
        for (challenge, accepted) in [
            (r#"Basic realm="issuer""#, true),
            (r#"Bearer realm="other", Basic realm="issuer, with comma", charset="UTF-8""#, true),
            (r#"Bearer realm="issuer""#, false),
            (r#"Basic realm="one", Basic realm="two""#, false),
            ("Basic", false), ("Basic YWJjZA==", false),
            (r#"Basic realm="issuer", realm="issuer""#, false),
            (r#"Basic realm="issuer", charset="UTF-16""#, false),
        ] {
            let mut headers = head();
            headers.push(("WWW-Authenticate".into(), challenge.into()));
            for basic in [false, true] {
                let result = admit(&EnterpriseTokenResponse {
                    status: 401, headers: &headers, body,
                }, EnterpriseTokenResponseStage::OidcCode, basic, 3600);
                assert_eq!(matches!(result, Ok((AdmittedBody::Denied(_), _))), accepted && basic, "{challenge}");
            }
        }
        let headers = head();
        assert!(matches!(admit(&EnterpriseTokenResponse {
            status: 400, headers: &headers, body,
        }, EnterpriseTokenResponseStage::OidcCode, true, 3600), Ok((AdmittedBody::Denied(_), _))));
    }

    #[test]
    fn enterprise_cache_fields_combine_and_missing_directives_only_diagnose() {
        let mut fields = vec![("Content-Type".into(), "application/json; charset=\"UTF-8\"".into())];
        let missing = headers(&fields, EnterpriseTokenResponseStage::IdJag).unwrap();
        assert!(missing.missing_no_store && missing.missing_pragma_no_cache);
        let oidc_missing = headers(&fields, EnterpriseTokenResponseStage::OidcCode).unwrap();
        assert!(oidc_missing.missing_no_store && !oidc_missing.missing_pragma_no_cache);
        fields.extend([
            ("Cache-Control".into(), "private, extension=\"a,b\"".into()),
            ("Cache-Control".into(), "no-store, NO-STORE".into()),
            ("Pragma".into(), "no-cache".into()),
        ]);
        let admitted = headers(&fields, EnterpriseTokenResponseStage::IdJag).unwrap();
        assert!(!admitted.missing_no_store && !admitted.missing_pragma_no_cache);
        for directive in [
            "public", "max-age=0", "s-maxage=1", "no-store=false",
            "extension=other", "broken=\"unterminated",
        ] {
            let mut bad = fields.clone();
            bad.push(("Cache-Control".into(), directive.into()));
            assert!(headers(&bad, EnterpriseTokenResponseStage::IdJag).is_err(), "{directive}");
        }
        for bad_type in [
            "text/json", "application/json; charset=\"utf-8",
            "application/json; charset=utf-16", "application/json; charset=utf-8; charset=utf-8",
            "application/json\u{2003}",
        ] {
            assert!(headers(&[("Content-Type".into(), bad_type.into())],
                EnterpriseTokenResponseStage::IdJag).is_err());
        }
        for forbidden in ["DPoP", "dPoP", "DPoP-Nonce"] {
            let mut bad = fields.clone();
            bad.push((forbidden.into(), "proof-or-challenge".into()));
            assert_eq!(headers(&bad, EnterpriseTokenResponseStage::IdJag),
                Err(Error::InvalidHeaders));
        }
    }
}
