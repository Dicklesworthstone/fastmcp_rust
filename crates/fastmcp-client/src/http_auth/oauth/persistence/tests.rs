use super::*;
use super::super::tests as native;
use super::super::{bind_loopback, within};
use crate::http_auth::CanonicalHttpUrl;
use asupersync::io::AsyncWriteExt;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use fastmcp_core::partition::{DurableOwnerKey, PartitionDescriptor};
use crate::http_auth::secure_file::slot::coordinator::{
    CredentialAnchorError, CredentialAnchorSnapshot, CredentialAnchorState,
};

fn url(value: &str) -> CanonicalHttpUrl { CanonicalHttpUrl::parse(value).unwrap() }

fn encoded(configuration: &OAuthClientConfiguration, binding: OAuthGrantBinding) -> Vec<u8> {
    let scopes = vec!["tools:read".to_owned()];
    let encoding = OAuthGrantEncoding {
        binding, refresh_token: "refresh-only-secret", scopes: &scopes,
    };
    validate_refresh(encoding.refresh_token, encoding.scopes, configuration).unwrap();
    let mut bytes = Vec::new();
    encoding.write_to(&mut bytes).unwrap();
    assert_eq!(bytes.len(), encoding.encoded_len());
    bytes
}

#[test]
fn canonical_refresh_record_round_trips_without_an_access_token_or_expiry() {
    let configuration = native::config();
    let binding = grant_binding(configuration_digest(&configuration).unwrap(), &[3; 32], 1).unwrap();
    let bytes = encoded(&configuration, binding);
    let grant = decode_grant(&configuration, binding, &bytes).unwrap();
    assert_eq!(grant.refresh_token, "refresh-only-secret");
    assert_eq!(grant.scopes(), ["tools:read".to_owned()]);
    assert_eq!(grant.configuration, configuration);
    // This exact closed binary layout has only binding, refresh token and
    // scopes; no persisted Instant/access token can be reconstructed from it.
    assert_eq!(bytes.len(), 8 + 32 + 4 + "refresh-only-secret".len() + 1 + 2 + "tools:read".len());
}

#[test]
fn refresh_record_rejects_every_truncation_trailing_data_and_wrong_binding() {
    let configuration = native::config();
    let digest = configuration_digest(&configuration).unwrap();
    let binding = grant_binding(digest, &[3; 32], 1).unwrap();
    let bytes = encoded(&configuration, binding);
    for end in 0..bytes.len() {
        assert!(decode_grant(&configuration, binding, &bytes[..end]).is_err());
    }
    let mut changed = bytes.clone();
    changed.push(0);
    assert!(decode_grant(&configuration, binding, &changed).is_err());
    for changed_binding in [
        grant_binding(digest, &[4; 32], 1).unwrap(),
        grant_binding(digest, &[3; 32], 2).unwrap(),
    ] {
        assert!(decode_grant(&configuration, changed_binding, &bytes).is_err());
    }
    assert!(decode_grant(&configuration, binding, &bytes).is_ok());
    assert!(grant_binding(digest, &[3; 32], 0).is_err());
}

#[test]
fn refresh_record_bounds_lengths_and_rejects_scope_expansion() {
    let configuration = native::config();
    let binding = grant_binding(configuration_digest(&configuration).unwrap(), &[3; 32], 1).unwrap();
    let bytes = encoded(&configuration, binding);
    let mut changed = bytes.clone();
    changed[40..44].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(decode_grant(&configuration, binding, &changed).is_err());
    let mut changed = bytes.clone();
    changed[44] = 0;
    assert!(decode_grant(&configuration, binding, &changed).is_err());
    let mut changed = bytes.clone();
    changed[44 + "refresh-only-secret".len()] = 33;
    assert!(decode_grant(&configuration, binding, &changed).is_err());
    assert!(matches!(
        decode_grant(&configuration, binding, &vec![0; MAX_ENCODED_REFRESH_GRANT_BYTES + 1]),
        Err(OAuthRefreshStoreError::TooLarge)
    ));
    let scopes = vec!["admin".to_owned()];
    let encoding = OAuthGrantEncoding { binding, refresh_token: "refresh-only-secret", scopes: &scopes };
    let mut expanded = Vec::new();
    encoding.write_to(&mut expanded).unwrap();
    assert!(decode_grant(&configuration, binding, &expanded).is_err());
    assert!(decode_grant(&configuration, binding, &bytes).is_ok());
}

#[test]
fn refresh_configuration_binding_covers_endpoints_policy_registration_and_roots() {
    let configuration = native::config();
    let original = configuration_digest(&configuration).unwrap();
    assert_eq!(configuration_digest(&configuration.clone()).unwrap(), original);
    for dimension in 0..10 {
        let mut changed = configuration.clone();
        match dimension {
            0 => changed.issuer.push('/'),
            1 => changed.authorization_endpoint = url("https://issuer.example/other-authorize"),
            2 => changed.token_endpoint = url("https://issuer.example/other-token"),
            3 => changed.resource = url("https://mcp.example/other"),
            4 => changed.client_id.push_str("-other"),
            5 => changed.scopes.reverse(),
            6 => changed.authorization_timeout = Duration::from_secs(1),
            7 => changed.max_access_token_lifetime = Duration::from_secs(1),
            8 => changed.extra_root_certificates.push(native::test_root().as_der().to_vec()),
            _ => changed.revocation_endpoint = Some(url("https://issuer.example/revoke")),
        }
        assert_ne!(configuration_digest(&changed).unwrap(), original, "dimension {dimension}");
    }
}

#[test]
fn live_grant_transfer_is_single_use_and_keeps_original_access_expiry() {
    let configuration = native::config();
    let mut credentials = native::renewable_grant(&configuration);
    let access = credentials.access.authorization_for_target(&configuration.resource);
    let expiry = credentials.expires_at();
    let grant = credentials.take_refresh_grant().unwrap();
    assert_eq!(grant.refresh_token, "refresh-one");
    assert_eq!(grant.scopes(), configuration.scopes);
    assert!(!credentials.has_refresh_token());
    assert_eq!(credentials.take_refresh_grant().err(), Some(OAuthError::RefreshUnavailable));
    assert_eq!(credentials.access.authorization_for_target(&configuration.resource), access);
    assert_eq!(credentials.expires_at(), expiry);
}

// Fault-injection doubles ONLY. TestVault models a remote opaque-envelope
// service while TestAnchor models its independently retained CAS state. These
// are not encryption/anchor implementations or provider qualification evidence.
#[derive(Clone, Default)]
struct TestVault(Arc<Mutex<VaultState>>);
#[derive(Default)]
struct VaultState {
    next: u64,
    records: BTreeMap<Vec<u8>, (OAuthGrantBinding, Vec<u8>)>,
    seals: usize,
    opens: usize,
    refuse_seal: bool,
    oversized_seal: bool,
    corrupt_open: bool,
}
impl OAuthGrantProtector for TestVault {
    type Plaintext = Vec<u8>;
    fn seal(&mut self, cx: &Cx, binding: &OAuthGrantBinding, grant: &OAuthGrantEncoding<'_>)
        -> Result<Vec<u8>, OAuthGrantProtectionError>
    {
        cx.checkpoint().map_err(|_| OAuthGrantProtectionError::Cancelled)?;
        let mut state = self.0.lock().unwrap();
        state.seals += 1;
        if state.refuse_seal { return Err(OAuthGrantProtectionError::Unavailable); }
        if state.oversized_seal { return Ok(vec![7; MAX_PROTECTED_REFRESH_GRANT_BYTES + 1]); }
        let mut bytes = Vec::new();
        grant.write_to(&mut bytes)?;
        state.next += 1;
        let envelope = state.next.to_be_bytes().to_vec();
        state.records.insert(envelope.clone(), (*binding, bytes));
        Ok(envelope)
    }
    fn open(&mut self, cx: &Cx, binding: &OAuthGrantBinding, protected: &[u8])
        -> Result<Self::Plaintext, OAuthGrantProtectionError>
    {
        cx.checkpoint().map_err(|_| OAuthGrantProtectionError::Cancelled)?;
        let mut state = self.0.lock().unwrap();
        state.opens += 1;
        let (recorded, bytes) = state.records.get(protected)
            .ok_or(OAuthGrantProtectionError::InvalidEnvelope)?;
        if recorded != binding { return Err(OAuthGrantProtectionError::InvalidEnvelope); }
        let mut bytes = bytes.clone();
        if state.corrupt_open { bytes.push(0); }
        Ok(bytes)
    }
}

#[derive(Clone)]
struct TestAnchor(Arc<Mutex<AnchorState>>);
struct AnchorState {
    snapshot: CredentialAnchorSnapshot,
    lose_settlement_reply: bool,
}
impl CredentialCommitAnchor for TestAnchor {
    fn current(&mut self, cx: &Cx, binding: &CredentialAnchorBinding)
        -> Result<CredentialAnchorSnapshot, CredentialAnchorError>
    {
        cx.checkpoint().map_err(|_| CredentialAnchorError::Unavailable)?;
        let state = self.0.lock().unwrap();
        if state.snapshot.binding() != *binding { return Err(CredentialAnchorError::NotProvisioned); }
        Ok(state.snapshot)
    }
    fn compare_exchange(&mut self, cx: &Cx, expected: &CredentialAnchorSnapshot, next: CredentialAnchorState)
        -> Result<CredentialAnchorSnapshot, CredentialAnchorError>
    {
        cx.checkpoint().map_err(|_| CredentialAnchorError::Unavailable)?;
        let mut state = self.0.lock().unwrap();
        if state.snapshot != *expected { return Err(CredentialAnchorError::Conflict); }
        state.snapshot = CredentialAnchorSnapshot::new(
            expected.binding(), expected.sequence().checked_add(1).ok_or(CredentialAnchorError::Unavailable)?, next,
        );
        if state.lose_settlement_reply && matches!(next, CredentialAnchorState::Stable(_)) {
            return Err(CredentialAnchorError::Uncertain);
        }
        Ok(state.snapshot)
    }
}

fn partition(subject: &str) -> (CredentialStoreKey, PartitionAuthorization) {
    let descriptor = PartitionDescriptor::from_verified_facts(
        "test-provider", 1, "https://issuer.example", "https://mcp.example/mcp",
        "tenant", subject, "native-client", 1, 1, &[b"oauth-resource"],
    ).unwrap();
    let owner = DurableOwnerKey::derive(&descriptor, 1).unwrap();
    let authorization = PartitionAuthorization::current(&descriptor, &owner);
    let key = CredentialStoreKey::derive(&descriptor, "native-store", "oauth-refresh", "lineage-one").unwrap();
    (key, authorization)
}

struct Fixture {
    directory: PathBuf,
    key: CredentialStoreKey,
    authorization: PartitionAuthorization,
    anchor: TestAnchor,
    vault: TestVault,
}
impl Fixture {
    fn new() -> Self {
        let nonce = fastmcp_core::draw_security_identifier().unwrap();
        let directory = std::env::temp_dir().join(format!(
            "fastmcp-oauth-custody-{}-{}", std::process::id(), super::super::hex(nonce.as_bytes()),
        ));
        fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let (key, authorization) = partition("alice");
        let binding = CredentialAnchorBinding::for_store("native-oauth", &key, &authorization).unwrap();
        let anchor = TestAnchor(Arc::new(Mutex::new(AnchorState {
            snapshot: CredentialAnchorSnapshot::new(binding, 0, CredentialAnchorState::Stable(None)),
            lose_settlement_reply: false,
        })));
        Self { directory, key, authorization, anchor, vault: TestVault::default() }
    }
    fn open(&self, cx: &Cx, client: &OAuthClient)
        -> Result<OAuthRefreshStore<TestAnchor, TestVault>, OAuthRefreshStoreError>
    {
        let file = SecureAtomicFile::open(
            cx, File::open(&self.directory).unwrap(), "grant", MAX_PROTECTED_REFRESH_GRANT_BYTES + 256,
        ).unwrap();
        OAuthRefreshStore::open(cx, file, &self.key, &self.authorization, "native-oauth",
            self.anchor.clone(), self.vault.clone(), client).map(|(store, _)| store)
    }
    fn sequence(&self) -> u64 { self.anchor.0.lock().unwrap().snapshot.sequence() }
    fn bytes(&self) -> Vec<u8> { fs::read(self.directory.join("grant")).unwrap() }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // Remove only this fixture's two known files and its now-empty private
        // directory, never recursively traverse a caller-supplied path.
        let _ = fs::remove_file(self.directory.join("grant"));
        let _ = fs::remove_file(self.directory.join(".grant.lock"));
        let _ = fs::remove_dir(&self.directory);
    }
}

#[test]
fn anchored_refresh_custody_survives_file_reopen_and_consumes_exactly_once() {
    let cx = Cx::for_testing();
    let configuration = native::config();
    let client = OAuthClient::new(configuration.clone());
    let fixture = Fixture::new();
    let mut store = fixture.open(&cx, &client).unwrap();
    let mut credentials = native::renewable_grant(&configuration);
    let access = credentials.access.authorization_for_target(&configuration.resource);
    let expiry = credentials.expires_at();
    let revision = store.store_refresh(&cx, &fixture.authorization, None, &mut credentials).unwrap();
    assert_eq!(revision.generation(), 1);
    assert!(!credentials.has_refresh_token());
    assert_eq!(credentials.access.authorization_for_target(&configuration.resource), access);
    assert_eq!(credentials.expires_at(), expiry);
    for secret in [b"refresh-one".as_slice(), b"access-one".as_slice()] {
        assert!(!fixture.bytes().windows(secret.len()).any(|bytes| bytes == secret));
    }
    drop(store);
    let mut reopened = fixture.open(&cx, &client).unwrap();
    let grant = reopened.take_refresh(&cx, &fixture.authorization).unwrap().unwrap();
    assert_eq!(grant.refresh_token, "refresh-one");
    assert_eq!(grant.scopes(), configuration.scopes);
    assert_eq!(reopened.revision().unwrap().generation(), 2);
    assert!(reopened.take_refresh(&cx, &fixture.authorization).unwrap().is_none());
    drop(grant);
    drop(reopened);
    let mut reopened = fixture.open(&cx, &client).unwrap();
    assert!(reopened.take_refresh(&cx, &fixture.authorization).unwrap().is_none());
    assert_eq!(reopened.revision().unwrap().generation(), 2);
}

#[test]
fn refused_sealing_and_oversized_envelopes_preserve_live_refresh_ownership() {
    for oversized in [false, true] {
        let cx = Cx::for_testing();
        let configuration = native::config();
        let client = OAuthClient::new(configuration.clone());
        let fixture = Fixture::new();
        let mut store = fixture.open(&cx, &client).unwrap();
        let mut credentials = native::renewable_grant(&configuration);
        {
            let mut state = fixture.vault.0.lock().unwrap();
            state.refuse_seal = !oversized;
            state.oversized_seal = oversized;
        }
        assert!(store.store_refresh(&cx, &fixture.authorization, None, &mut credentials).is_err());
        assert!(credentials.has_refresh_token());
        assert_eq!(store.revision(), None);
        assert_eq!(fixture.sequence(), 0);
        assert!(!fixture.directory.join("grant").exists());
        {
            let mut state = fixture.vault.0.lock().unwrap();
            state.refuse_seal = false;
            state.oversized_seal = false;
        }
        store.store_refresh(&cx, &fixture.authorization, None, &mut credentials).unwrap();
        assert!(!credentials.has_refresh_token());
        assert!(store.take_refresh(&cx, &fixture.authorization).unwrap().is_some());
    }
}

#[test]
fn wrong_authorization_and_malformed_plaintext_cannot_consume_stored_grants() {
    let cx = Cx::for_testing();
    let configuration = native::config();
    let client = OAuthClient::new(configuration.clone());
    let fixture = Fixture::new();
    let mut store = fixture.open(&cx, &client).unwrap();
    let mut credentials = native::renewable_grant(&configuration);
    store.store_refresh(&cx, &fixture.authorization, None, &mut credentials).unwrap();
    let (_, intruder) = partition("mallory");
    let before = fixture.bytes();
    let sequence = fixture.sequence();
    assert!(store.take_refresh(&cx, &intruder).is_err());
    assert_eq!(fixture.vault.0.lock().unwrap().opens, 0);
    assert_eq!(fixture.sequence(), sequence);
    assert_eq!(fixture.bytes(), before);
    fixture.vault.0.lock().unwrap().corrupt_open = true;
    assert!(matches!(store.take_refresh(&cx, &fixture.authorization), Err(OAuthRefreshStoreError::InvalidGrant)));
    assert_eq!(fixture.sequence(), sequence);
    assert_eq!(fixture.bytes(), before);
    fixture.vault.0.lock().unwrap().corrupt_open = false;
    assert!(store.take_refresh(&cx, &fixture.authorization).unwrap().is_some());
}

#[test]
fn changed_client_binding_does_not_destroy_the_original_persisted_grant() {
    let cx = Cx::for_testing();
    let configuration = native::config();
    let client = OAuthClient::new(configuration.clone());
    let fixture = Fixture::new();
    let mut store = fixture.open(&cx, &client).unwrap();
    let mut credentials = native::renewable_grant(&configuration);
    store.store_refresh(&cx, &fixture.authorization, None, &mut credentials).unwrap();
    let before = fixture.bytes();
    let sequence = fixture.sequence();
    drop(store);
    let mut different = configuration.clone();
    different.client_id.push_str("-other");
    let mut mismatched = fixture.open(&cx, &OAuthClient::new(different)).unwrap();
    assert!(mismatched.take_refresh(&cx, &fixture.authorization).is_err());
    assert_eq!(fixture.bytes(), before);
    assert_eq!(fixture.sequence(), sequence);
    drop(mismatched);
    let mut original = fixture.open(&cx, &client).unwrap();
    assert!(original.take_refresh(&cx, &fixture.authorization).unwrap().is_some());
}

#[test]
fn lost_take_settlement_reply_and_rollback_never_redeliver_refresh_ownership() {
    let cx = Cx::for_testing();
    let configuration = native::config();
    let client = OAuthClient::new(configuration.clone());
    let fixture = Fixture::new();
    let mut store = fixture.open(&cx, &client).unwrap();
    let mut credentials = native::renewable_grant(&configuration);
    store.store_refresh(&cx, &fixture.authorization, None, &mut credentials).unwrap();
    let old_file = fixture.bytes();
    fixture.anchor.0.lock().unwrap().lose_settlement_reply = true;
    assert!(store.take_refresh(&cx, &fixture.authorization).is_err());
    assert!(store.requires_recovery());
    drop(store);
    fixture.anchor.0.lock().unwrap().lose_settlement_reply = false;
    let mut recovered = fixture.open(&cx, &client).unwrap();
    assert!(recovered.take_refresh(&cx, &fixture.authorization).unwrap().is_none());
    assert_eq!(recovered.revision().unwrap().generation(), 2);
    drop(recovered);
    // Change only the replaceable data file, not its independent anchor.
    fs::write(fixture.directory.join("grant"), old_file).unwrap();
    assert!(fixture.open(&cx, &client).is_err());
}

#[test]
fn stale_revision_and_cancelled_store_preserve_grants_and_provider_state() {
    let cx = Cx::for_testing();
    let configuration = native::config();
    let client = OAuthClient::new(configuration.clone());
    let fixture = Fixture::new();
    let mut store = fixture.open(&cx, &client).unwrap();
    let mut credentials = native::renewable_grant(&configuration);
    let stopped = Cx::for_testing();
    stopped.set_cancel_requested(true);
    assert_eq!(store.store_refresh(&stopped, &fixture.authorization, None, &mut credentials).err(),
        Some(OAuthRefreshStoreError::ContextStopped));
    assert_eq!(fixture.vault.0.lock().unwrap().seals, 0);
    assert_eq!(fixture.sequence(), 0);
    assert!(credentials.has_refresh_token());
    store.store_refresh(&cx, &fixture.authorization, None, &mut credentials).unwrap();
    let mut successor = native::renewable_grant(&configuration);
    assert_eq!(store.store_refresh(&cx, &fixture.authorization, None, &mut successor).err(),
        Some(OAuthRefreshStoreError::RevisionMismatch));
    assert!(successor.has_refresh_token());
    assert_eq!(fixture.vault.0.lock().unwrap().seals, 1);
    let revision = store.invalidate(&cx, &fixture.authorization).unwrap();
    let sequence = fixture.sequence();
    assert_eq!(store.invalidate(&cx, &fixture.authorization).unwrap(), revision);
    assert_eq!(fixture.sequence(), sequence);
    assert!(store.take_refresh(&cx, &fixture.authorization).unwrap().is_none());
    store.store_refresh(&cx, &fixture.authorization, Some(revision), &mut successor).unwrap();
    assert!(!successor.has_refresh_token());
}

#[test]
fn persisted_grant_reopen_renews_over_native_https_with_rotation_and_scope_narrowing() {
    for rotate in [false, true] {
        asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            let deadline = operation_deadline(&cx, Duration::from_secs(20)).unwrap();
            let listener = within(&cx, deadline, bind_loopback()).await.unwrap();
            let mut configuration = native::config().with_extra_root_certificate(native::test_root()).unwrap();
            configuration.token_endpoint = url(&format!("https://{}/token", listener.local_addr().unwrap()));
            let client = OAuthClient::new(configuration.clone());
            let fixture = Fixture::new();
            let mut credentials = native::renewable_grant(&configuration);
            // Execute file/provider work on an owned thread, not the polling
            // thread. Both reopens address the actual descriptor-relative file.
            let client_for_store = client.clone();
            let storage_cx = cx.clone();
            let (grant, fixture) = std::thread::spawn(move || {
                let mut store = fixture.open(&storage_cx, &client_for_store).unwrap();
                store.store_refresh(&storage_cx, &fixture.authorization, None, &mut credentials).unwrap();
                assert!(!credentials.has_refresh_token());
                drop(credentials);
                drop(store);
                let mut store = fixture.open(&storage_cx, &client_for_store).unwrap();
                let grant = store.take_refresh(&storage_cx, &fixture.authorization).unwrap().unwrap();
                assert!(store.take_refresh(&storage_cx, &fixture.authorization).unwrap().is_none());
                drop(store);
                (grant, fixture)
            }).join().unwrap();
            let acceptor = native::test_acceptor();
            let server = within(&cx, deadline, async {
                let (socket, _) = listener.accept().await.map_err(|_| OAuthError::TransportFailed)?;
                let mut tls = acceptor.accept(socket).await.map_err(|_| OAuthError::TransportFailed)?;
                let (head, form) = native::read_token_request(&mut tls).await?;
                assert!(head.starts_with("POST /token HTTP/1.1\r\n"));
                assert!(!head.to_ascii_lowercase().contains("authorization:"));
                assert_eq!(form["grant_type"], "refresh_token");
                assert_eq!(form["refresh_token"], "refresh-one");
                assert_eq!(form["client_id"], "native-client");
                assert_eq!(form["resource"], "https://mcp.example/mcp");
                let body = if rotate {
                    r#"{"access_token":"resumed-access","token_type":"Bearer","expires_in":120,"refresh_token":"rotated-refresh","scope":"tools:read"}"#
                } else {
                    r#"{"access_token":"resumed-access","token_type":"Bearer","expires_in":120,"scope":"tools:read"}"#
                };
                let reply = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                tls.write_all(reply.as_bytes()).await.map_err(|_| OAuthError::TransportFailed)?;
                tls.shutdown().await.map_err(|_| OAuthError::TransportFailed)?;
                Ok(())
            });
            let (server, result) =
                Box::pin(native::pair(server, client.refresh_grant(&cx, grant))).await;
            assert_eq!(server, Ok(()));
            let credentials = result.unwrap();
            assert_eq!(credentials.access.authorization_for_target(&configuration.resource), Some("Bearer resumed-access".to_owned()));
            assert_eq!(credentials.refresh_token.as_deref(), Some(if rotate { "rotated-refresh" } else { "refresh-one" }));
            assert_eq!(credentials.scopes(), ["tools:read".to_owned()]);
            assert!(credentials.expires_at() <= Instant::now() + Duration::from_secs(120));
            drop(fixture);
        });
    }
}

#[test]
fn resumed_grant_rejects_scope_expansion_and_never_retries_lost_or_redirected_exchange() {
    for mode in 0..3 {
        asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            let deadline = operation_deadline(&cx, Duration::from_secs(20)).unwrap();
            let listener = within(&cx, deadline, bind_loopback()).await.unwrap();
            let mut configuration = native::config().with_extra_root_certificate(native::test_root()).unwrap();
            configuration.token_endpoint = url(&format!("https://{}/token", listener.local_addr().unwrap()));
            let client = OAuthClient::new(configuration.clone());
            let mut credentials = admit_token_response(&configuration, &configuration.scopes,
                br#"{"access_token":"old-access","token_type":"Bearer","refresh_token":"refresh-one","scope":"tools:read"}"#,
                Instant::now()).unwrap();
            let grant = credentials.take_refresh_grant().unwrap();
            let acceptor = native::test_acceptor();
            let server = within(&cx, deadline, async {
                let (socket, _) = listener.accept().await.map_err(|_| OAuthError::TransportFailed)?;
                let mut tls = acceptor.accept(socket).await.map_err(|_| OAuthError::TransportFailed)?;
                let (_, form) = native::read_token_request(&mut tls).await?;
                assert_eq!(form["refresh_token"], "refresh-one");
                assert_eq!(form["scope"], "tools:read");
                if mode == 1 {
                    tls.write_all(b"HTTP/1.1 307 Temporary Redirect\r\nLocation: https://127.0.0.1:9/forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.map_err(|_| OAuthError::TransportFailed)?;
                } else if mode == 2 {
                    let body = r#"{"access_token":"bad-access","token_type":"Bearer","scope":"tools:write"}"#;
                    let reply = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                    tls.write_all(reply.as_bytes()).await.map_err(|_| OAuthError::TransportFailed)?;
                }
                if mode != 0 { tls.shutdown().await.map_err(|_| OAuthError::TransportFailed)?; }
                Ok(())
            });
            let (server, result) =
                Box::pin(native::pair(server, client.refresh_grant(&cx, grant))).await;
            assert_eq!(server, Ok(()));
            assert_eq!(result.err(), Some(match mode {
                0 => OAuthError::TransportFailed,
                1 => OAuthError::TokenEndpointRejected,
                _ => OAuthError::ScopeExpansion,
            }));
            assert_eq!(credentials.take_refresh_grant().err(), Some(OAuthError::RefreshUnavailable));
            let mut task = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(listener.poll_accept(&mut task).is_pending());
        });
    }
}
