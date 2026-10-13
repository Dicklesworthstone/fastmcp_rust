//! RFC 9449 DPoP proof construction using locally held P-256 keys.
//!
//! Enabled by `jose`. Every call signs a new proof with a fresh 256-bit `jti`.
//! Token-endpoint proofs omit `ath`; resource proofs bind the exact access
//! token with SHA-256. The public JWK never contains private key material.
//! RFC 7638 thumbprints can also be used as the authorization request's
//! `dpop_jkt` parameter.
//!
//! This is a signing primitive, not server-side proof validation or OAuth
//! orchestration. Callers must authenticate HTTPS peers, keep authorization
//! server and resource server nonces separate, and generate a new proof for
//! every request attempt. A proof is not a substitute for TLS, and it does
//! not sign the request body. Redirects require a new admission decision.

use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use fastmcp_core::{AccessToken, CanonicalHttpUrl};
use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde_json::{Value, json};

/// Local bound on an opaque server-provided nonce.
pub const MAX_DPOP_NONCE_BYTES: usize = 1024;
/// Local bound on a request target, including its unsigned query.
pub const MAX_DPOP_TARGET_BYTES: usize = 8192;
/// Local bound on imported P-256 PKCS#8 key material.
pub const MAX_DPOP_PKCS8_BYTES: usize = 4096;

/// A redacted, stable DPoP construction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpopError {
    /// The operating system could not provide randomness.
    EntropyUnavailable,
    /// The key was oversized, malformed, or not a supported P-256 key.
    InvalidPrivateKey,
    /// DPoP, like bearer authorization, requires HTTPS even on loopback.
    CleartextTarget,
    /// The configured request target exceeded the local bound.
    TargetTooLong,
    /// The HTTP method was empty, oversized, or not an HTTP token.
    InvalidMethod,
    /// The access token violated the shared bounded token68 admission.
    InvalidAccessToken,
    /// A nonce violated RFC 9449's nonce syntax or the local byte bound.
    InvalidNonce,
    /// The clock was before the Unix epoch or outside the admitted range.
    InvalidTimestamp,
    /// JSON serialization or signing failed; no partial proof is returned.
    SigningFailed,
}

impl fmt::Display for DpopError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EntropyUnavailable => "DPoP randomness is unavailable",
            Self::InvalidPrivateKey => "invalid DPoP P-256 private key",
            Self::CleartextTarget => "DPoP requires an HTTPS target",
            Self::TargetTooLong => "DPoP target exceeds its byte bound",
            Self::InvalidMethod => "invalid DPoP HTTP method",
            Self::InvalidAccessToken => "invalid DPoP access token",
            Self::InvalidNonce => "invalid DPoP nonce",
            Self::InvalidTimestamp => "invalid DPoP issue time",
            Self::SigningFailed => "DPoP proof signing failed",
        })
    }
}

impl std::error::Error for DpopError {}

/// An admitted opaque nonce. Debug output deliberately omits its contents.
#[derive(Clone, PartialEq, Eq)]
pub struct DpopNonce(String);

impl DpopNonce {
    /// Admit exactly the supplied nonce without trimming or normalization.
    pub fn new(value: &str) -> Result<Self, DpopError> {
        // RFC 9449 section 8.1: 1*NQCHAR. Quotes, spaces, backslashes,
        // controls, DEL, and non-ASCII bytes are not NQCHAR.
        if value.is_empty()
            || value.len() > MAX_DPOP_NONCE_BYTES
            || !value
                .bytes()
                .all(|byte| matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
        {
            return Err(DpopError::InvalidNonce);
        }
        Ok(Self(value.to_owned()))
    }

    /// Return the exact admitted nonce for a proof claim.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DpopNonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DpopNonce(<redacted>)")
    }
}

/// One signed proof. Construct another proof rather than reusing this one.
///
/// This type intentionally implements neither `Clone` nor `Serialize`.
/// Extracting its wire value is an explicit operation.
pub struct DpopProof(String);

impl DpopProof {
    /// The compact JWT to put in the single `DPoP` request header.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the proof to build the request's `DPoP` header.
    #[must_use]
    pub fn into_header_value(self) -> String {
        self.0
    }
}

impl fmt::Debug for DpopProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DpopProof(<redacted>)")
    }
}

/// A locally held ES256 proof key. Clones share the same private key.
///
/// Key generation is explicit, not global. Preserve the key across token
/// refreshes: a refresh token bound to one key cannot be used with another.
/// Imported key custody and persistence remain the caller's responsibility.
#[derive(Clone)]
pub struct DpopKey {
    signer: Arc<EcdsaKeyPair>,
    public_jwk: Value,
    thumbprint: String,
}

impl fmt::Debug for DpopKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DpopKey")
            .field("algorithm", &"ES256")
            .field("private_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl DpopKey {
    /// Generate a new ephemeral key using operating-system randomness.
    pub fn generate() -> Result<Self, DpopError> {
        let random = SystemRandom::new();
        let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &random)
            .map_err(|_| DpopError::EntropyUnavailable)?;
        Self::from_pkcs8(document.as_ref())
    }

    /// Import a caller-protected P-256 PKCS#8 key without exporting it again.
    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self, DpopError> {
        if bytes.is_empty() || bytes.len() > MAX_DPOP_PKCS8_BYTES {
            return Err(DpopError::InvalidPrivateKey);
        }
        let signer = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            bytes,
            &SystemRandom::new(),
        )
        .map_err(|_| DpopError::InvalidPrivateKey)?;
        let public = signer.public_key().as_ref();
        if public.len() != 65 || public[0] != 4 {
            return Err(DpopError::InvalidPrivateKey);
        }
        let x = URL_SAFE_NO_PAD.encode(&public[1..33]);
        let y = URL_SAFE_NO_PAD.encode(&public[33..65]);
        // RFC 7638 hashes only required public members, lexicographically
        // sorted, with no whitespace. Do not depend on serde map features.
        let canonical = format!("{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}");
        let thumbprint = sha256_base64url(canonical.as_bytes());
        let public_jwk = json!({"crv": "P-256", "kty": "EC", "x": x, "y": y});
        Ok(Self {
            signer: Arc::new(signer),
            public_jwk,
            thumbprint,
        })
    }

    /// A public-only JWK suitable for the proof's protected JOSE header.
    #[must_use]
    pub fn public_jwk(&self) -> &Value {
        &self.public_jwk
    }

    /// RFC 7638 SHA-256 thumbprint, also usable as `dpop_jkt` or `cnf.jkt`.
    #[must_use]
    pub fn thumbprint(&self) -> &str {
        &self.thumbprint
    }

    /// Sign a fresh POST token-endpoint proof. It never contains `ath`.
    pub fn token_endpoint_proof(
        &self,
        target: &CanonicalHttpUrl,
        nonce: Option<&DpopNonce>,
    ) -> Result<DpopProof, DpopError> {
        self.proof_at("POST", target, None, nonce, unix_time()?)
    }

    /// Sign a fresh resource request, binding the exact access token.
    /// HTTP methods are case-sensitive and are never normalized.
    pub fn resource_proof(
        &self,
        method: &str,
        target: &CanonicalHttpUrl,
        access_token: &str,
        nonce: Option<&DpopNonce>,
    ) -> Result<DpopProof, DpopError> {
        self.proof_at(method, target, Some(access_token), nonce, unix_time()?)
    }

    fn proof_at(
        &self,
        method: &str,
        target: &CanonicalHttpUrl,
        access_token: Option<&str>,
        nonce: Option<&DpopNonce>,
        issued_at: u64,
    ) -> Result<DpopProof, DpopError> {
        if !target.as_str().starts_with("https://") {
            return Err(DpopError::CleartextTarget);
        }
        if target.as_str().len() > MAX_DPOP_TARGET_BYTES {
            return Err(DpopError::TargetTooLong);
        }
        if method.is_empty() || method.len() > 64 || !method.bytes().all(is_http_token_byte) {
            return Err(DpopError::InvalidMethod);
        }
        if issued_at > i64::MAX as u64 {
            return Err(DpopError::InvalidTimestamp);
        }
        if access_token.is_some_and(|token| !AccessToken::is_valid_token68(token)) {
            return Err(DpopError::InvalidAccessToken);
        }
        let random = SystemRandom::new();
        let mut identifier = [0_u8; 32];
        random
            .fill(&mut identifier)
            .map_err(|_| DpopError::EntropyUnavailable)?;
        // CanonicalHttpUrl admits the target first. Only the proof's htu
        // loses its query; credential/resource binding must keep the query.
        let htu = target
            .as_str()
            .split(['?', '#'])
            .next()
            .ok_or(DpopError::SigningFailed)?;
        let header = json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": self.public_jwk});
        let mut claims = json!({
            "jti": URL_SAFE_NO_PAD.encode(identifier),
            "htm": method,
            "htu": htu,
            "iat": issued_at,
        });
        if let Some(token) = access_token {
            claims["ath"] = Value::String(sha256_base64url(token.as_bytes()));
        }
        if let Some(nonce) = nonce {
            claims["nonce"] = Value::String(nonce.as_str().to_owned());
        }
        let header = serde_json::to_vec(&header).map_err(|_| DpopError::SigningFailed)?;
        let claims = serde_json::to_vec(&claims).map_err(|_| DpopError::SigningFailed)?;
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(claims)
        );
        // JOSE ES256 requires fixed-width r || s, not ASN.1 DER.
        let signature = self
            .signer
            .sign(&random, input.as_bytes())
            .map_err(|_| DpopError::SigningFailed)?;
        Ok(DpopProof(format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(signature.as_ref())
        )))
    }
}

fn unix_time() -> Result<u64, DpopError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| DpopError::InvalidTimestamp)
}

fn sha256_base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(digest(&SHA256, bytes).as_ref())
}

fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};

    fn url(value: &str) -> CanonicalHttpUrl {
        CanonicalHttpUrl::parse(value).unwrap()
    }

    fn decoded(proof: &DpopProof) -> (Value, Value, Vec<u8>, String) {
        let parts: Vec<_> = proof.as_str().split('.').collect();
        assert_eq!(parts.len(), 3);
        assert!(parts.iter().all(|part| !part.contains('=')));
        (
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap(),
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap(),
            URL_SAFE_NO_PAD.decode(parts[2]).unwrap(),
            format!("{}.{}", parts[0], parts[1]),
        )
    }

    #[test]
    fn dpop_signs_verifiable_fixed_width_es256_with_public_jwk_only() {
        let key = DpopKey::generate().unwrap();
        let target = url("https://mcp.example/api?tenant=one&cursor=two");
        let nonce = DpopNonce::new("server-nonce").unwrap();
        let proof = key
            .proof_at(
                "POST",
                &target,
                Some("mF_9.B5f-4.1JqM"),
                Some(&nonce),
                1700000000,
            )
            .unwrap();
        let (header, claims, signature, input) = decoded(&proof);
        assert_eq!(header["typ"], "dpop+jwt");
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["jwk"], *key.public_jwk());
        assert_eq!(header["jwk"].as_object().unwrap().len(), 4);
        assert!(header["jwk"].get("d").is_none());
        assert_eq!(claims["htm"], "POST");
        assert_eq!(claims["htu"], "https://mcp.example/api");
        assert_eq!(claims["iat"], 1700000000_u64);
        assert_eq!(claims["nonce"], "server-nonce");
        // Independently calculated SHA-256/base64url known-answer vector.
        assert_eq!(claims["ath"], "uOFIVFsTx4vHTaLxpydd1x5W3ezhKdfS97PswG95lNo");
        assert_eq!(signature.len(), 64);
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key.signer.public_key().as_ref())
            .verify(input.as_bytes(), &signature)
            .unwrap();
        let mut tampered = input.into_bytes();
        tampered[0] ^= 1;
        assert!(
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key.signer.public_key().as_ref())
                .verify(&tampered, &signature)
                .is_err()
        );
    }

    #[test]
    fn dpop_token_proofs_omit_ath_and_refresh_jti_even_in_the_same_second() {
        let key = DpopKey::generate().unwrap();
        let target = url("https://issuer.example/token");
        let first = key.proof_at("POST", &target, None, None, 7).unwrap();
        let second = key
            .clone()
            .proof_at("POST", &target, None, None, 7)
            .unwrap();
        let (_, first, _, _) = decoded(&first);
        let (_, second, _, _) = decoded(&second);
        assert!(first.get("ath").is_none());
        assert!(first.get("nonce").is_none());
        assert_ne!(first["jti"], second["jti"]);
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(first["jti"].as_str().unwrap())
                .unwrap()
                .len(),
            32
        );
        assert_eq!(key.thumbprint(), key.clone().thumbprint());
    }

    #[test]
    fn dpop_rfc7638_thumbprint_matches_independent_p256_vector() {
        // Test-only scalar 1, encoded by an independent PKCS#8 implementation.
        // Never use this publicly known private key outside this test.
        let bytes = URL_SAFE_NO_PAD
            .decode(concat!(
                "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGhRANCAARrF9Hy4SxCR_i85uVjpEDydwN9",
                "gS3rM6D0oTlF2JjClk_jQuL-Gn-bjufrSnwPnhYrzjNXazFezsu2QGg3v1H1"
            ))
            .unwrap();
        let key = DpopKey::from_pkcs8(&bytes).unwrap();
        assert_eq!(
            key.thumbprint(),
            "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"
        );
        assert_eq!(
            key.public_jwk()["x"],
            "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY"
        );
        assert_eq!(
            key.public_jwk()["y"],
            "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"
        );
    }

    #[test]
    fn dpop_rejects_cleartext_targets_including_loopback() {
        let key = DpopKey::generate().unwrap();
        for target in [
            "http://mcp.example/api",
            "http://localhost:8080/api",
            "http://127.0.0.1/api",
        ] {
            assert_eq!(
                key.token_endpoint_proof(&url(target), None).unwrap_err(),
                DpopError::CleartextTarget
            );
        }
    }

    #[test]
    fn dpop_rejects_invalid_methods_tokens_and_timestamps() {
        let key = DpopKey::generate().unwrap();
        let target = url("https://mcp.example/api");
        for method in ["", "POST GET", "POST\r\nInjected: yes", "méthod"] {
            assert_eq!(
                key.proof_at(method, &target, None, None, 7).unwrap_err(),
                DpopError::InvalidMethod
            );
        }
        for token in ["", "with space", "token\n", "é", "a=b"] {
            assert_eq!(
                key.resource_proof("POST", &target, token, None)
                    .unwrap_err(),
                DpopError::InvalidAccessToken
            );
        }
        assert_eq!(
            key.proof_at("POST", &target, None, None, u64::MAX)
                .unwrap_err(),
            DpopError::InvalidTimestamp
        );
        let proof = key.proof_at("custom", &target, None, None, 7).unwrap();
        assert_eq!(decoded(&proof).1["htm"], "custom");
    }

    #[test]
    fn dpop_nonce_admission_is_bounded_and_does_not_normalize() {
        for nonce in [
            "",
            "has space",
            "has\"quote",
            "has\\slash",
            "bad\r\n",
            "é",
            "\u{7f}",
        ] {
            assert_eq!(DpopNonce::new(nonce).unwrap_err(), DpopError::InvalidNonce);
        }
        assert!(DpopNonce::new(&"n".repeat(MAX_DPOP_NONCE_BYTES)).is_ok());
        assert!(DpopNonce::new(&"n".repeat(MAX_DPOP_NONCE_BYTES + 1)).is_err());
        let nonce = DpopNonce::new("opaque+/=_-![]").unwrap();
        assert_eq!(nonce.as_str(), "opaque+/=_-![]");
        assert!(!format!("{nonce:?}").contains(nonce.as_str()));
    }

    #[test]
    fn dpop_key_import_is_bounded_and_diagnostics_are_redacted() {
        assert_eq!(
            DpopKey::from_pkcs8(&[]).unwrap_err(),
            DpopError::InvalidPrivateKey
        );
        assert_eq!(
            DpopKey::from_pkcs8(&vec![0; MAX_DPOP_PKCS8_BYTES + 1]).unwrap_err(),
            DpopError::InvalidPrivateKey
        );
        let key = DpopKey::generate().unwrap();
        let proof = key
            .token_endpoint_proof(&url("https://issuer.example/token"), None)
            .unwrap();
        assert!(!format!("{key:?}").contains(key.public_jwk()["x"].as_str().unwrap()));
        assert!(!format!("{proof:?}").contains(proof.as_str()));
        assert!(format!("{proof:?}").contains("<redacted>"));
    }
}
