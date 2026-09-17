//! AUTH-00 integration: join the A and B capability slices through public
//! entrypoints.
//!
//! # Why this target exists here, and why it could not live in either child
//!
//! AUTH-00 A ships its seam across two crates: the facts, descriptor and
//! partition types in `fastmcp-core`, and the borrowed request view, the
//! `IngressAuthenticator` trait and the opaque `AuthenticatedTransportIngress`
//! in `fastmcp-transport`. AUTH-00 B ships partition admission and lookup in
//! `fastmcp-core`.
//!
//! `fastmcp-core` has no dependency on `fastmcp-transport` — not in
//! `[dependencies]` and not in `[dev-dependencies]`, and it could not have one
//! without a package cycle. So a target under `crates/fastmcp-core/tests/`
//! cannot name the sealed ingress value at all, which is why B's own harness
//! constructs its descriptor from the core facts type directly. **The join of
//! A's sealed transport ingress to B's partition admission is therefore not
//! expressible inside either child.** This package depends on both, so it is
//! the first place the whole chain can be driven end to end.
//!
//! # What is actually joined
//!
//! ```text
//! AuthRequestView::new(..)                       A, transport
//!   -> authenticate_ingress(..)                  A, transport  (only producer)
//!   -> AuthenticatedTransportIngress             A, opaque
//!   -> .authentication()                         A, core facts
//!   -> SecurityPartitionDescriptor::from_verified_ingress(..)
//!   -> .to_partition_descriptor()                A -> B seam
//!   -> {Cache,Continuation,Subscription,CredentialStore,DurableOwner,
//!       Quota,ReplayReservation} keys            B
//!   -> PartitionAuthorization::current(..)       B
//!   -> PartitionAdmissionController::lookup(..)  B
//! ```
//!
//! Every call above is the shipped public entrypoint of its crate, reached the
//! way a downstream consumer reaches it. Nothing here is `cfg(test)` inside a
//! library, and there is no `use super` and no `pub(crate)` path: `cfg(test)`
//! behaviour cannot prove shipped behaviour (PL-3).
//!
//! # Why this file implements `IngressAuthenticator`
//!
//! For the same reason A's own harness does, and it is not a fixture standing
//! in for live proof. A ships a *seam*; AUTH-01 supplies concrete providers.
//! Driving the seam requires a provider on the other side of it. What is under
//! test is the join, and every production entrypoint in the chain above is the
//! shipped one.

use std::time::Duration;

use asupersync::Cx;
use asupersync::runtime::reactor::create_reactor;
use asupersync::runtime::{Runtime, RuntimeBuilder};

use fastmcp_core::crypto::{HMAC_SHA256_KEY_BYTES, HmacSha256Key};
use fastmcp_core::ingress::{
    AuthorizationRotationFacts, DEFAULT_MAXIMUM_STALENESS, MaximumStaleness, RevalidationDispatch,
    SealedProviderReference, SecurityPartitionDescriptor, VerifiedAudienceBinding,
    VerifiedIdentityFacts, VerifiedIngressAuthentication,
};
use fastmcp_core::partition::{
    CachePartitionKey, ContinuationPartitionKey, CredentialStoreKey, DurableOwnerKey,
    LookupOutcome, PartitionAdmissionController, PartitionAuthorization, PartitionDescriptor,
    PartitionSlot, QuotaPartitionKey, ReplayReservationKey, RevalidationLimits,
    SubscriptionPartitionKey,
};
use fastmcp_core::sha256_bounded;
use fastmcp_transport::ingress::{
    AuthRequestView, AuthenticatedTransportIngress, IngressAuthenticationError,
    IngressAuthenticator, VerifiedIngressOutcome, authenticate_ingress,
};

// ---------------------------------------------------------------------------
// Frozen subject
// ---------------------------------------------------------------------------

const PROVIDER: &str = "org.fastmcp.provider.auth00i";
const CONFIGURATION_GENERATION: u64 = 11;
const ISSUER: &str = "https://issuer.example/auth00i";
const CANONICAL_RESOURCE: &str = "https://resource.example/mcp";
const AUDIENCE_POLICY_ID: &str = "accepted-audience-policy/strict";
const AUDIENCE_POLICY_REVISION: u64 = 4;
const TENANT: &str = "tenant-alpha";
const FOREIGN_TENANT: &str = "tenant-beta";
const SUBJECT: &str = "subject-7f3a";
const CLIENT: &str = "client-console";
const AUTH_POLICY_REVISION: u64 = 19;
const TRUST_GENERATION: u64 = 3;
const CLAIMS: [(&str, &str); 2] = [("amr", "mfa"), ("scope", "mcp.read")];

/// The credential the caller presents. It must never reach any public value,
/// key, `Debug` rendering or lookup outcome anywhere below.
const PRESENTED_CREDENTIAL: &[u8] = b"secret-bearer-value-that-must-never-be-recorded";
const SCHEME: &str = "Bearer";
const TRANSPORT_PROVENANCE: &str = "tls1.3/h2/198.51.100.7";

const FINGERPRINT_KEY_ID: &str = "auth00i-key-2026-09";
const FINGERPRINT_GENERATION: u64 = 2;
const PROVIDER_REFERENCE_MATERIAL: &[u8] = b"opaque-provider-handle-not-a-bearer";
const TOKEN_INSTANCE_MATERIAL: &[u8] = b"opaque-token-instance-not-a-bearer";
const ROTATED_TOKEN_MATERIAL: &[u8] = b"opaque-token-instance-AFTER-ROTATION";
const GRANTS: [&str; 2] = ["mcp.read", "mcp.write"];
const OWNERSHIP_EPOCH: u64 = 2;
const QUOTA_EPOCH: u64 = 5;

fn fingerprint_key() -> HmacSha256Key {
    HmacSha256Key::from_bytes([7_u8; HMAC_SHA256_KEY_BYTES])
}

// ---------------------------------------------------------------------------
// A conforming provider on the other side of the seam
// ---------------------------------------------------------------------------

struct JoinAuthenticator {
    tenant: &'static str,
    token_material: &'static [u8],
}

impl IngressAuthenticator for JoinAuthenticator {
    fn authenticate(
        &self,
        _cx: &Cx,
        _request: &AuthRequestView<'_>,
        _deadline: Duration,
    ) -> Result<VerifiedIngressOutcome, IngressAuthenticationError> {
        let authentication =
            VerifiedIngressAuthentication::from_verified_provider_output(VerifiedIdentityFacts {
                provider: PROVIDER,
                configuration_generation: CONFIGURATION_GENERATION,
                issuer: ISSUER,
                canonical_resource: CANONICAL_RESOURCE,
                verified_audience_binding: VerifiedAudienceBinding::OAuth {
                    canonical_resource: CANONICAL_RESOURCE.to_owned(),
                    validated_audience: CANONICAL_RESOURCE.to_owned(),
                    audience_policy_id: AUDIENCE_POLICY_ID.to_owned(),
                    audience_policy_revision: AUDIENCE_POLICY_REVISION,
                    provider: PROVIDER.to_owned(),
                    configuration_generation: CONFIGURATION_GENERATION,
                },
                tenant: self.tenant,
                subject_or_principal: SUBJECT,
                authorized_party_or_client: CLIENT,
                verified_claims: &CLAIMS,
                auth_policy_revision: AUTH_POLICY_REVISION,
                trust_generation: TRUST_GENERATION,
            })
            .map_err(|_| IngressAuthenticationError::NotAuthenticated)?;

        let key = fingerprint_key();
        let provider_reference = SealedProviderReference::seal(
            FINGERPRINT_KEY_ID,
            FINGERPRINT_GENERATION,
            &key,
            PROVIDER_REFERENCE_MATERIAL,
        )
        .map_err(|_| IngressAuthenticationError::NotAuthenticated)?;
        let token_instance = SealedProviderReference::seal(
            FINGERPRINT_KEY_ID,
            FINGERPRINT_GENERATION,
            &key,
            self.token_material,
        )
        .map_err(|_| IngressAuthenticationError::NotAuthenticated)?;
        let staleness = MaximumStaleness::new(DEFAULT_MAXIMUM_STALENESS)
            .map_err(|_| IngressAuthenticationError::NotAuthenticated)?;

        Ok(VerifiedIngressOutcome {
            authentication,
            rotation: Some(AuthorizationRotationFacts::new(
                provider_reference,
                token_instance,
                &GRANTS,
                TRUST_GENERATION,
                Duration::from_secs(600),
                staleness,
                RevalidationDispatch::Dispatched,
            )),
        })
    }
}

fn application_runtime() -> Runtime {
    RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().expect("platform reactor is available"))
        .blocking_threads(0, 2)
        .build()
        .expect("application-owned runtime builds")
}

/// Drives one full ingress through the shipped A entrypoint.
fn run_ingress(
    tenant: &'static str,
    token_material: &'static [u8],
) -> Result<AuthenticatedTransportIngress, IngressAuthenticationError> {
    application_runtime().block_on(async move {
        let cx = Cx::current().expect("block_on installs a current Cx");
        let authenticator = JoinAuthenticator {
            tenant,
            token_material,
        };
        let request = AuthRequestView::new(
            PRESENTED_CREDENTIAL,
            SCHEME,
            TRANSPORT_PROVENANCE,
            CANONICAL_RESOURCE,
        )?;
        authenticate_ingress(&cx, Some(&authenticator), &request, Duration::from_secs(5))
    })
}

/// Crosses the A -> B seam: sealed ingress to partition descriptor.
fn descriptor_of(ingress: &AuthenticatedTransportIngress) -> PartitionDescriptor {
    SecurityPartitionDescriptor::from_verified_ingress(ingress.authentication())
        .to_partition_descriptor()
}

fn cache_key(descriptor: &PartitionDescriptor, token: &str) -> CachePartitionKey {
    CachePartitionKey::derive(
        descriptor,
        &GRANTS,
        token,
        "representation-json",
        "cache-domain-main",
    )
    .expect("cache partition derives")
}

fn owner_key(descriptor: &PartitionDescriptor) -> DurableOwnerKey {
    DurableOwnerKey::derive(descriptor, OWNERSHIP_EPOCH).expect("durable owner derives")
}

fn authorization(descriptor: &PartitionDescriptor) -> PartitionAuthorization {
    PartitionAuthorization::current(descriptor, &owner_key(descriptor))
}

fn controller() -> PartitionAdmissionController {
    PartitionAdmissionController::new(RevalidationLimits::default(), 8)
        .expect("controller admits a positive quota capacity")
}

// ---------------------------------------------------------------------------
// Ordered row manifest
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManifestRow {
    id: &'static str,
    parts: Vec<Vec<u8>>,
}

/// Binds the ordered integration rows to one canonical digest.
///
/// The rows are canonically length-prefixed so no two different row sets can
/// serialize to the same bytes by concatenation ambiguity.
fn auth_00_integration_manifest_digest(rows: &[ManifestRow]) -> [u8; 32] {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"auth_00_integration_manifest_digest-v1");
    for row in rows {
        encoded.extend_from_slice(&(row.id.len() as u64).to_be_bytes());
        encoded.extend_from_slice(row.id.as_bytes());
        encoded.extend_from_slice(&(row.parts.len() as u64).to_be_bytes());
        for part in &row.parts {
            encoded.extend_from_slice(&(part.len() as u64).to_be_bytes());
            encoded.extend_from_slice(part);
        }
    }
    *sha256_bounded(&encoded, 1024 * 1024)
        .expect("the bounded integration manifest is within its limit")
        .as_bytes()
}

/// The ordered join, in the exact order the acceptance names it.
///
/// Every row carries real bytes: the opaque partition keys expose
/// `as_bytes()` and the descriptor exposes `identity()`. Their `Debug` impls
/// are deliberately redacting — `CachePartitionKey { .. }` renders identically
/// for every instance — so a manifest or comparison built on `format!("{:?}")`
/// would be vacuous, not merely ugly.
fn manifest(ingress: &AuthenticatedTransportIngress) -> Vec<ManifestRow> {
    let descriptor = descriptor_of(ingress);
    let token = "token-instance-1";
    let row = |id: &'static str, parts: Vec<Vec<u8>>| ManifestRow { id, parts };

    vec![
        row(
            "AUTH-00-I.01",
            vec![
                ingress.scheme().as_bytes().to_vec(),
                ingress.transport_provenance().as_bytes().to_vec(),
            ],
        ),
        row(
            "AUTH-00-I.02",
            vec![
                ingress.authentication().provider().as_bytes().to_vec(),
                ingress.authentication().issuer().as_bytes().to_vec(),
                ingress.authentication().tenant().as_bytes().to_vec(),
            ],
        ),
        row(
            "AUTH-00-I.03",
            vec![
                descriptor.identity().to_vec(),
                descriptor.tenant().as_bytes().to_vec(),
                descriptor.subject().as_bytes().to_vec(),
            ],
        ),
        row(
            "AUTH-00-I.04",
            vec![cache_key(&descriptor, token).as_bytes().to_vec()],
        ),
        row(
            "AUTH-00-I.05",
            vec![
                ContinuationPartitionKey::derive(
                    &descriptor,
                    &GRANTS,
                    "tools/list:cursor",
                    "capability-fp-1",
                    "continuation-policy-strict",
                    "continuation-domain-main",
                )
                .expect("continuation partition derives")
                .as_bytes()
                .to_vec(),
            ],
        ),
        row(
            "AUTH-00-I.06",
            vec![
                SubscriptionPartitionKey::derive(
                    &descriptor,
                    &GRANTS,
                    token,
                    "topic-main",
                    "delivery-at-least-once",
                )
                .expect("subscription partition derives")
                .as_bytes()
                .to_vec(),
            ],
        ),
        row(
            "AUTH-00-I.07",
            vec![
                CredentialStoreKey::derive(
                    &descriptor,
                    "store-main",
                    "credential-class-refresh",
                    token,
                )
                .expect("credential store partition derives")
                .as_bytes()
                .to_vec(),
            ],
        ),
        row(
            "AUTH-00-I.08",
            vec![owner_key(&descriptor).as_bytes().to_vec()],
        ),
        row(
            "AUTH-00-I.09",
            vec![
                QuotaPartitionKey::derive(&descriptor, QUOTA_EPOCH)
                    .expect("quota partition derives")
                    .as_bytes()
                    .to_vec(),
            ],
        ),
        row(
            "AUTH-00-I.10",
            vec![
                ReplayReservationKey::derive(&descriptor, "alias-1", "assertion-replay")
                    .expect("replay reservation derives")
                    .as_bytes()
                    .to_vec(),
            ],
        ),
        row(
            "AUTH-00-I.11",
            vec![
                descriptor.provider().as_bytes().to_vec(),
                descriptor.trust_generation().to_be_bytes().to_vec(),
                descriptor.auth_policy_revision().to_be_bytes().to_vec(),
            ],
        ),
        row(
            "AUTH-00-I.12",
            vec![descriptor.canonical_resource().as_bytes().to_vec()],
        ),
    ]
}

/// Asserts the presented credential appears in no admitted byte anywhere.
///
/// This checks the raw manifest bytes and the redacting `Debug` renderings
/// together: a leak could surface as either.
fn assert_credential_redacted(ingress: &AuthenticatedTransportIngress, rows: &[ManifestRow]) {
    for row in rows {
        for part in &row.parts {
            assert!(
                !part
                    .windows(PRESENTED_CREDENTIAL.len())
                    .any(|window| window == PRESENTED_CREDENTIAL),
                "row {} carries the presented credential in its admitted bytes",
                row.id
            );
        }
    }
    let credential = String::from_utf8_lossy(PRESENTED_CREDENTIAL).into_owned();
    for surface in [
        format!("{ingress:?}"),
        format!("{:?}", ingress.authentication()),
    ] {
        assert!(
            !surface.contains(credential.as_str()),
            "a public rendering exposed the presented credential: {surface}"
        );
    }
}

// ---------------------------------------------------------------------------
// Frozen acceptance IDs
// ---------------------------------------------------------------------------

#[test]
fn auth_00_integration_positive() {
    let ingress = run_ingress(TENANT, TOKEN_INSTANCE_MATERIAL)
        .expect("a conforming provider yields the sealed ingress value");

    // Verified-principal ingress, and the opaque value carries the
    // framework-stamped provenance rather than a caller claim.
    assert_eq!(ingress.scheme(), SCHEME);
    assert_eq!(ingress.transport_provenance(), TRANSPORT_PROVENANCE);
    assert_eq!(ingress.authentication().tenant(), TENANT);

    let rows = manifest(&ingress);
    assert_eq!(rows.len(), 12, "the ordered join declares twelve rows");
    assert_credential_redacted(&ingress, &rows);

    // The A -> B seam, then purpose separation: distinct purposes over one
    // identity must not collapse onto one partition.
    let descriptor = descriptor_of(&ingress);
    let cache = *cache_key(&descriptor, "token-instance-1").as_bytes();
    let owner = *owner_key(&descriptor).as_bytes();
    let quota = *QuotaPartitionKey::derive(&descriptor, QUOTA_EPOCH)
        .expect("quota derives")
        .as_bytes();
    assert_ne!(
        cache, owner,
        "cache and durable-owner purposes stay separate"
    );
    assert_ne!(cache, quota, "cache and quota purposes stay separate");
    assert_ne!(
        owner, quota,
        "durable-owner and quota purposes stay separate"
    );

    // Verified authorization reads its own record through B's controller.
    let mut controller = controller();
    let auth = authorization(&descriptor);
    let slot = PartitionSlot::Cache(cache_key(&descriptor, "token-instance-1"));
    assert_eq!(controller.record_count(), 0);
    assert!(
        controller
            .store(&auth, &slot, b"joined-result".to_vec())
            .is_none()
    );
    assert_eq!(
        controller.lookup(&auth, &slot),
        LookupOutcome::Present(b"joined-result".to_vec()),
        "the verified owner reads the record its own identity partitioned"
    );

    // The digest is stable across independent derivations of the same join.
    assert_eq!(
        auth_00_integration_manifest_digest(&rows),
        auth_00_integration_manifest_digest(&manifest(&ingress)),
        "auth_00_integration_manifest_digest must be stable for one identity"
    );
}

#[test]
fn auth_00_integration_planted_negative() {
    // Baseline: the accepted join, with one stored record.
    let ingress = run_ingress(TENANT, TOKEN_INSTANCE_MATERIAL).expect("baseline ingress");
    let descriptor = descriptor_of(&ingress);
    let baseline_digest = auth_00_integration_manifest_digest(&manifest(&ingress));
    let baseline_identity = *descriptor.identity();

    let mut controller = controller();
    let auth = authorization(&descriptor);
    let slot = PartitionSlot::Cache(cache_key(&descriptor, "token-instance-1"));
    assert!(
        controller
            .store(&auth, &slot, b"joined-result".to_vec())
            .is_none()
    );
    let records_before = controller.record_count();

    // ONE VARIABLE: the verified tenant. Provider, issuer, resource, subject,
    // client, grants, epochs and the presented credential are all unchanged.
    let foreign = run_ingress(FOREIGN_TENANT, TOKEN_INSTANCE_MATERIAL)
        .expect("a foreign tenant still authenticates; isolation is not authentication");
    let foreign_descriptor = descriptor_of(&foreign);
    assert_ne!(
        *foreign_descriptor.identity(),
        baseline_identity,
        "a different verified tenant must not derive the owner's identity"
    );

    // Cross-tenant no-effect: the foreign principal reads nothing, and
    // observing that leaves the owner's state untouched.
    let foreign_auth = authorization(&foreign_descriptor);
    let foreign_slot = PartitionSlot::Cache(cache_key(&foreign_descriptor, "token-instance-1"));
    assert_eq!(
        controller.lookup(&foreign_auth, &foreign_slot),
        LookupOutcome::Absent,
        "a foreign tenant's lookup is absent, never the owner's bytes"
    );
    assert_eq!(
        controller.lookup(&foreign_auth, &slot),
        LookupOutcome::Absent,
        "nor can it read the owner's own slot"
    );
    assert_eq!(
        controller.record_count(),
        records_before,
        "a refused cross-tenant lookup creates and destroys no record"
    );
    assert_eq!(
        controller.lookup(&auth, &slot),
        LookupOutcome::Present(b"joined-result".to_vec()),
        "and the owner's record is byte-for-byte unchanged"
    );

    // The forbidden dimension moves the canonical digest, so one manifest
    // cannot certify two different identities as the same join.
    assert_ne!(
        auth_00_integration_manifest_digest(&manifest(&foreign)),
        baseline_digest,
        "changing only the verified tenant must move the integration digest"
    );

    // A second forbidden dimension: credential exposure on the refused join.
    assert_credential_redacted(&foreign, &manifest(&foreign));
}

#[test]
fn auth_00_i_positive() {
    // A's sealed value is the only thing that reaches B, and B's keys derive
    // from it rather than from loose strings.
    let ingress = run_ingress(TENANT, TOKEN_INSTANCE_MATERIAL).expect("sealed ingress");
    let descriptor = descriptor_of(&ingress);

    let mut controller = controller();
    let auth = authorization(&descriptor);
    let slot = PartitionSlot::Cache(cache_key(&descriptor, "token-instance-1"));
    assert!(controller.store(&auth, &slot, b"a-to-b".to_vec()).is_none());
    assert_eq!(
        controller.lookup(&auth, &slot),
        LookupOutcome::Present(b"a-to-b".to_vec())
    );

    // Ordinary token rotation preserves durable-owner identity while a
    // different token instance moves the cache partition: the
    // stable-versus-invalidating contract, compared on real digest bytes.
    let rotated = run_ingress(TENANT, ROTATED_TOKEN_MATERIAL).expect("rotated ingress");
    let rotated_descriptor = descriptor_of(&rotated);
    assert_eq!(
        *owner_key(&descriptor).as_bytes(),
        *owner_key(&rotated_descriptor).as_bytes(),
        "token rotation must not move durable-owner identity"
    );
    assert_ne!(
        *cache_key(&descriptor, "token-instance-1").as_bytes(),
        *cache_key(&descriptor, "token-instance-2").as_bytes(),
        "a different token instance must move the cache partition"
    );
}

#[test]
fn auth_00_i_planted_negative() {
    // Baseline accepted join.
    let ingress = run_ingress(TENANT, TOKEN_INSTANCE_MATERIAL).expect("baseline ingress");
    let descriptor = descriptor_of(&ingress);
    let mut controller = controller();
    let auth = authorization(&descriptor);
    let slot = PartitionSlot::Cache(cache_key(&descriptor, "token-instance-1"));
    assert!(controller.store(&auth, &slot, b"owned".to_vec()).is_none());
    let before = controller.record_count();

    // ONE VARIABLE: an authenticator that refuses. No sealed value is minted,
    // so nothing reaches B at all — A's output is the only admissible B input,
    // and its absence is total rather than partial.
    struct RefusingAuthenticator;
    impl IngressAuthenticator for RefusingAuthenticator {
        fn authenticate(
            &self,
            _cx: &Cx,
            _request: &AuthRequestView<'_>,
            _deadline: Duration,
        ) -> Result<VerifiedIngressOutcome, IngressAuthenticationError> {
            Err(IngressAuthenticationError::NotAuthenticated)
        }
    }

    let refused = application_runtime().block_on(async move {
        let cx = Cx::current().expect("block_on installs a current Cx");
        let request = AuthRequestView::new(
            PRESENTED_CREDENTIAL,
            SCHEME,
            TRANSPORT_PROVENANCE,
            CANONICAL_RESOURCE,
        )?;
        authenticate_ingress(
            &cx,
            Some(&RefusingAuthenticator),
            &request,
            Duration::from_secs(5),
        )
    });
    assert!(
        refused.is_err(),
        "a refusing provider mints no sealed ingress value"
    );

    // The refusal reached B in no way at all: state is byte-for-byte unchanged.
    assert_eq!(controller.record_count(), before);
    assert_eq!(
        controller.lookup(&auth, &slot),
        LookupOutcome::Present(b"owned".to_vec()),
        "the accepted record survives a refused ingress untouched"
    );
}
