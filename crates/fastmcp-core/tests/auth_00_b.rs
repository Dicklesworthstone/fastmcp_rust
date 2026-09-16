//! AUTH-00 B: partition admission, non-oracular lookup, cross-tenant isolation.
//!
//! This is an **external** consumer of the packaged `fastmcp-core` crate: it
//! reaches the AUTH-00 B surface the way a downstream crate does, via
//! `use fastmcp_core::partition::...`, never through `use super` or any
//! `pub(crate)` path, and nothing here is compiled under `cfg(test)` inside
//! the library. `cfg(test)` behaviour cannot prove shipped behaviour (PL-3).
//!
//! The positive drives an ordered row manifest over acceptance rows (2)-(7)
//! — cache partition, continuation partition, durable owner, subscription and
//! credential store, quota partition, and revalidation singleflight plus
//! replay reservation — and binds `auth_00_b_manifest_digest` over the
//! canonical ordered rows.
//!
//! The planted negative changes exactly one of tenant, issuer, resource,
//! subject, client, provider, required grant, policy/trust generation, replay
//! alias, or quota epoch, reaches the typed denial, and proves cross-tenant no
//! effect: the foreign result is absent and every record, counter, quota
//! reservation and revalidation flight is byte-for-byte unchanged.
//!
//! No-claim boundary: this leaf proves partition admission and non-oracular
//! lookup from a verified descriptor. It does not prove AUTH-00 A's ingress
//! construction, the AUTH-00 aggregate, or aggregate MCP capability.

#![forbid(unsafe_code)]

use fastmcp_core::partition::{
    ATTEMPT_RATE_WINDOW, CachePartitionKey, ContinuationPartitionKey, CredentialStoreKey,
    DEFAULT_ATTEMPTS_PER_MINUTE_PER_PARTITION, DEFAULT_ATTEMPTS_PER_MINUTE_PER_PROVIDER,
    DEFAULT_REVALIDATIONS_PER_DEPLOYMENT, DEFAULT_REVALIDATIONS_PER_PARTITION,
    DEFAULT_REVALIDATIONS_PER_PROVIDER, DurableOwnerKey, HARD_ATTEMPTS_PER_MINUTE_PER_PARTITION,
    HARD_ATTEMPTS_PER_MINUTE_PER_PROVIDER, HARD_REVALIDATIONS_PER_DEPLOYMENT,
    HARD_REVALIDATIONS_PER_PARTITION, HARD_REVALIDATIONS_PER_PROVIDER, LookupOutcome,
    PartitionAdmissionController, PartitionAdmissionError, PartitionAuthorization,
    PartitionDescriptor, PartitionSlot,
    QuotaPartitionKey, ReplayReservationKey, RevalidationFlightKey, RevalidationLimits,
    RevalidationLimitsError, SubscriptionPartitionKey,
};
use fastmcp_core::{SealedAdmissionKeyError, sha256_bounded};

// ---------------------------------------------------------------------------
// Baseline verified facts
// ---------------------------------------------------------------------------

const PROVIDER: &str = "org.fastmcp.provider";
const CONFIGURATION_GENERATION: u64 = 7;
const ISSUER: &str = "https://auth.example.test";
const RESOURCE: &str = "mcp://servers/main";
const TENANT: &str = "tenant-alpha";
const SUBJECT: &str = "subject-user-42";
const CLIENT: &str = "client-reg-1";
const TRUST_GENERATION: u64 = 3;
const AUDIENCE_POLICY_REVISION: u64 = 11;
const OWNERSHIP_EPOCH: u64 = 2;
const QUOTA_EPOCH: u64 = 5;

const TOKEN_INSTANCE: &str = "token-instance-aaaa";
const ROTATED_TOKEN_INSTANCE: &str = "token-instance-bbbb";
const GRANTS: [&str; 2] = ["mcp:tools:call", "mcp:resources:read"];
const CHURNED_GRANTS: [&str; 3] = ["mcp:tools:call", "mcp:resources:read", "mcp:prompts:get"];

/// The verified facts a descriptor is built from. Every planted negative
/// mutates exactly one of these and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VerifiedFacts {
    provider: &'static str,
    configuration_generation: u64,
    issuer: &'static str,
    resource: &'static str,
    tenant: &'static str,
    subject: &'static str,
    client: &'static str,
    trust_generation: u64,
    audience_policy_revision: u64,
}

const BASELINE: VerifiedFacts = VerifiedFacts {
    provider: PROVIDER,
    configuration_generation: CONFIGURATION_GENERATION,
    issuer: ISSUER,
    resource: RESOURCE,
    tenant: TENANT,
    subject: SUBJECT,
    client: CLIENT,
    trust_generation: TRUST_GENERATION,
    audience_policy_revision: AUDIENCE_POLICY_REVISION,
};

fn descriptor_from(facts: &VerifiedFacts) -> PartitionDescriptor {
    PartitionDescriptor::from_verified_facts(
        facts.provider,
        facts.configuration_generation,
        facts.issuer,
        facts.resource,
        facts.tenant,
        facts.subject,
        facts.client,
        facts.trust_generation,
        facts.audience_policy_revision,
    )
    .expect("verified facts must mint a partition descriptor")
}

fn baseline_descriptor() -> PartitionDescriptor {
    descriptor_from(&BASELINE)
}

fn cache_key(descriptor: &PartitionDescriptor, grants: &[&str], token: &str) -> CachePartitionKey {
    CachePartitionKey::derive(
        descriptor,
        grants,
        token,
        "representation-json",
        "cache-domain-main",
    )
    .expect("cache partition derives")
}

fn continuation_key(descriptor: &PartitionDescriptor, grants: &[&str]) -> ContinuationPartitionKey {
    ContinuationPartitionKey::derive(
        descriptor,
        grants,
        "tools/list:cursor",
        "capability-fp-1",
        "continuation-policy-strict",
        "continuation-domain-main",
    )
    .expect("continuation partition derives")
}

fn subscription_key(
    descriptor: &PartitionDescriptor,
    grants: &[&str],
    token: &str,
) -> SubscriptionPartitionKey {
    SubscriptionPartitionKey::derive(
        descriptor,
        grants,
        token,
        "topic-main",
        "delivery-at-least-once",
    )
    .expect("subscription partition derives")
}

fn credential_key(descriptor: &PartitionDescriptor, token: &str) -> CredentialStoreKey {
    CredentialStoreKey::derive(descriptor, "store-main", "credential-class-refresh", token)
        .expect("credential store partition derives")
}

fn owner_key(descriptor: &PartitionDescriptor) -> DurableOwnerKey {
    DurableOwnerKey::derive(descriptor, OWNERSHIP_EPOCH).expect("durable owner derives")
}

fn authorization(descriptor: &PartitionDescriptor) -> PartitionAuthorization {
    PartitionAuthorization::current(descriptor, &owner_key(descriptor))
}

fn quota_key(descriptor: &PartitionDescriptor) -> QuotaPartitionKey {
    QuotaPartitionKey::derive(descriptor, QUOTA_EPOCH).expect("quota partition derives")
}

fn controller() -> PartitionAdmissionController {
    PartitionAdmissionController::new(RevalidationLimits::default(), 8)
        .expect("controller admits a positive quota capacity")
}

/// Every observable controller counter, for unchanged-state proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ControllerState {
    records: usize,
    quota_in_use: usize,
    partition_flights: usize,
    provider_flights: usize,
    deployment_flights: usize,
    replay_reservations: usize,
    denials: usize,
}

fn observe(
    controller: &PartitionAdmissionController,
    descriptor: &PartitionDescriptor,
    quota: &QuotaPartitionKey,
) -> ControllerState {
    ControllerState {
        records: controller.record_count(),
        quota_in_use: controller.quota_in_use(quota),
        partition_flights: controller.partition_flights(descriptor),
        provider_flights: controller.provider_flights(descriptor),
        deployment_flights: controller.deployment_flights(),
        replay_reservations: controller.replay_reservation_count(),
        denials: controller.denial_count(),
    }
}

// ---------------------------------------------------------------------------
// Ordered row manifest
// ---------------------------------------------------------------------------

/// One canonical manifest row: an ordered acceptance row id and its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ManifestRow {
    id: &'static str,
    parts: Vec<Vec<u8>>,
}

impl ManifestRow {
    fn new(id: &'static str, parts: Vec<Vec<u8>>) -> Self {
        Self { id, parts }
    }
}

/// Length-prefixed canonical encoding over the ordered rows.
fn manifest_digest(rows: &[ManifestRow]) -> [u8; 32] {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"auth_00_b_manifest_digest-v1");
    for row in rows {
        let id = row.id.as_bytes();
        encoded.extend_from_slice(
            &u64::try_from(id.len())
                .expect("row id fits u64")
                .to_be_bytes(),
        );
        encoded.extend_from_slice(id);
        encoded.extend_from_slice(
            &u64::try_from(row.parts.len())
                .expect("row part count fits u64")
                .to_be_bytes(),
        );
        for part in &row.parts {
            encoded.extend_from_slice(
                &u64::try_from(part.len())
                    .expect("row part length fits u64")
                    .to_be_bytes(),
            );
            encoded.extend_from_slice(part);
        }
    }
    sha256_bounded(&encoded, 64 * 1024)
        .expect("canonical manifest stays inside the hash bound")
        .into_bytes()
}

/// Builds the ordered acceptance-row manifest for one descriptor, grant set
/// and token instance. Every planted negative rebuilds this with exactly one
/// input changed.
fn build_manifest(
    descriptor: &PartitionDescriptor,
    grants: &[&str],
    token: &str,
    quota_epoch: u64,
    replay_alias: &str,
) -> Vec<ManifestRow> {
    let cache = cache_key(descriptor, grants, token);
    let continuation = continuation_key(descriptor, grants);
    let owner = owner_key(descriptor);
    let subscription = subscription_key(descriptor, grants, token);
    let credential = credential_key(descriptor, token);
    let quota = QuotaPartitionKey::derive(descriptor, quota_epoch).expect("quota derives");
    let flight = RevalidationFlightKey::derive(descriptor, "revalidate-token")
        .expect("revalidation flight derives");
    let replay = ReplayReservationKey::derive(descriptor, replay_alias, "assertion-replay")
        .expect("replay reservation derives");

    vec![
        ManifestRow::new(
            "AUTH-00-B.02-cache-partition",
            vec![cache.as_bytes().to_vec()],
        ),
        ManifestRow::new(
            "AUTH-00-B.03-continuation-partition",
            vec![continuation.as_bytes().to_vec()],
        ),
        ManifestRow::new(
            "AUTH-00-B.04-durable-owner",
            vec![owner.as_bytes().to_vec()],
        ),
        ManifestRow::new(
            "AUTH-00-B.05-subscription-and-credential-store",
            vec![
                subscription.as_bytes().to_vec(),
                credential.as_bytes().to_vec(),
            ],
        ),
        ManifestRow::new(
            "AUTH-00-B.06-quota-partition",
            vec![quota.as_bytes().to_vec()],
        ),
        ManifestRow::new(
            "AUTH-00-B.07-revalidation-and-replay",
            vec![flight.as_bytes().to_vec(), replay.as_bytes().to_vec()],
        ),
    ]
}

fn baseline_manifest(descriptor: &PartitionDescriptor) -> Vec<ManifestRow> {
    build_manifest(descriptor, &GRANTS, TOKEN_INSTANCE, QUOTA_EPOCH, "alias-1")
}

// ---------------------------------------------------------------------------
// Positive
// ---------------------------------------------------------------------------

#[test]
fn auth_00_b_positive() {
    // -- Frozen numeric floors -------------------------------------------
    assert_eq!(DEFAULT_REVALIDATIONS_PER_PARTITION, 2);
    assert_eq!(HARD_REVALIDATIONS_PER_PARTITION, 16);
    assert_eq!(DEFAULT_REVALIDATIONS_PER_PROVIDER, 32);
    assert_eq!(HARD_REVALIDATIONS_PER_PROVIDER, 256);
    assert_eq!(DEFAULT_REVALIDATIONS_PER_DEPLOYMENT, 256);
    assert_eq!(HARD_REVALIDATIONS_PER_DEPLOYMENT, 4_096);
    assert_eq!(DEFAULT_ATTEMPTS_PER_MINUTE_PER_PARTITION, 120);
    assert_eq!(HARD_ATTEMPTS_PER_MINUTE_PER_PARTITION, 6_000);
    assert_eq!(DEFAULT_ATTEMPTS_PER_MINUTE_PER_PROVIDER, 10_000);
    assert_eq!(HARD_ATTEMPTS_PER_MINUTE_PER_PROVIDER, 100_000);
    assert_eq!(ATTEMPT_RATE_WINDOW.as_secs(), 60);

    let defaults = RevalidationLimits::default();
    assert_eq!(
        defaults.per_partition(),
        DEFAULT_REVALIDATIONS_PER_PARTITION
    );
    assert_eq!(defaults.per_provider(), DEFAULT_REVALIDATIONS_PER_PROVIDER);
    assert_eq!(
        defaults.per_deployment(),
        DEFAULT_REVALIDATIONS_PER_DEPLOYMENT
    );
    assert_eq!(
        defaults.partition_attempts_per_minute(),
        DEFAULT_ATTEMPTS_PER_MINUTE_PER_PARTITION
    );
    assert_eq!(
        defaults.provider_attempts_per_minute(),
        DEFAULT_ATTEMPTS_PER_MINUTE_PER_PROVIDER
    );

    // Each row is admissible at its hard ceiling and refused one above it.
    assert!(
        RevalidationLimits::new(
            HARD_REVALIDATIONS_PER_PARTITION,
            HARD_REVALIDATIONS_PER_PROVIDER,
            HARD_REVALIDATIONS_PER_DEPLOYMENT,
            HARD_ATTEMPTS_PER_MINUTE_PER_PARTITION,
            HARD_ATTEMPTS_PER_MINUTE_PER_PROVIDER,
        )
        .is_ok(),
        "every row must be admissible exactly at its hard ceiling"
    );
    for (index, refused) in [
        RevalidationLimits::new(
            HARD_REVALIDATIONS_PER_PARTITION + 1,
            DEFAULT_REVALIDATIONS_PER_PROVIDER,
            DEFAULT_REVALIDATIONS_PER_DEPLOYMENT,
            DEFAULT_ATTEMPTS_PER_MINUTE_PER_PARTITION,
            DEFAULT_ATTEMPTS_PER_MINUTE_PER_PROVIDER,
        ),
        RevalidationLimits::new(
            DEFAULT_REVALIDATIONS_PER_PARTITION,
            HARD_REVALIDATIONS_PER_PROVIDER + 1,
            DEFAULT_REVALIDATIONS_PER_DEPLOYMENT,
            DEFAULT_ATTEMPTS_PER_MINUTE_PER_PARTITION,
            DEFAULT_ATTEMPTS_PER_MINUTE_PER_PROVIDER,
        ),
        RevalidationLimits::new(
            DEFAULT_REVALIDATIONS_PER_PARTITION,
            DEFAULT_REVALIDATIONS_PER_PROVIDER,
            HARD_REVALIDATIONS_PER_DEPLOYMENT + 1,
            DEFAULT_ATTEMPTS_PER_MINUTE_PER_PARTITION,
            DEFAULT_ATTEMPTS_PER_MINUTE_PER_PROVIDER,
        ),
        RevalidationLimits::new(
            DEFAULT_REVALIDATIONS_PER_PARTITION,
            DEFAULT_REVALIDATIONS_PER_PROVIDER,
            DEFAULT_REVALIDATIONS_PER_DEPLOYMENT,
            HARD_ATTEMPTS_PER_MINUTE_PER_PARTITION + 1,
            DEFAULT_ATTEMPTS_PER_MINUTE_PER_PROVIDER,
        ),
        RevalidationLimits::new(
            DEFAULT_REVALIDATIONS_PER_PARTITION,
            DEFAULT_REVALIDATIONS_PER_PROVIDER,
            DEFAULT_REVALIDATIONS_PER_DEPLOYMENT,
            DEFAULT_ATTEMPTS_PER_MINUTE_PER_PARTITION,
            HARD_ATTEMPTS_PER_MINUTE_PER_PROVIDER + 1,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(
            refused,
            Err(RevalidationLimitsError::ExceedsHardCeiling),
            "limits row {index} one above its hard ceiling must be refused"
        );
    }

    let descriptor = baseline_descriptor();
    assert_eq!(descriptor.provider(), PROVIDER);
    assert_eq!(descriptor.issuer(), ISSUER);
    assert_eq!(descriptor.tenant(), TENANT);
    assert_eq!(descriptor.subject(), SUBJECT);
    assert_eq!(descriptor.client(), CLIENT);
    assert_eq!(descriptor.canonical_resource(), RESOURCE);
    assert_eq!(descriptor.trust_generation(), TRUST_GENERATION);
    assert_eq!(
        descriptor.audience_policy_revision(),
        AUDIENCE_POLICY_REVISION
    );
    // Identity fields are redacted from Debug.
    let rendered = format!("{descriptor:?}");
    for secret in [PROVIDER, ISSUER, TENANT, SUBJECT, CLIENT, RESOURCE] {
        assert!(
            !rendered.contains(secret),
            "Debug must not render the verified field {secret}"
        );
    }

    // -- Ordered row manifest, floor 6 rows -------------------------------
    let rows = baseline_manifest(&descriptor);
    assert_eq!(
        rows.len(),
        6,
        "the AUTH-00 B manifest floor is 6 ordered rows"
    );
    let ids: Vec<&str> = rows.iter().map(|row| row.id).collect();
    assert_eq!(
        ids,
        vec![
            "AUTH-00-B.02-cache-partition",
            "AUTH-00-B.03-continuation-partition",
            "AUTH-00-B.04-durable-owner",
            "AUTH-00-B.05-subscription-and-credential-store",
            "AUTH-00-B.06-quota-partition",
            "AUTH-00-B.07-revalidation-and-replay",
        ],
        "manifest rows must run in the frozen order"
    );

    // Derivation is deterministic: an independent rebuild is byte-identical.
    let digest = manifest_digest(&rows);
    assert_eq!(
        digest,
        manifest_digest(&baseline_manifest(&baseline_descriptor())),
        "auth_00_b_manifest_digest must be stable across independent derivations"
    );

    // -- Predicate: rotation and scope churn preserve owner and quota -----
    let rotated_cache = cache_key(&descriptor, &CHURNED_GRANTS, ROTATED_TOKEN_INSTANCE);
    let baseline_cache = cache_key(&descriptor, &GRANTS, TOKEN_INSTANCE);
    assert_ne!(
        baseline_cache, rotated_cache,
        "a token or grant change must move the cache partition"
    );
    assert_ne!(
        continuation_key(&descriptor, &GRANTS),
        continuation_key(&descriptor, &CHURNED_GRANTS),
        "a grant-snapshot change must move the continuation partition"
    );
    assert_ne!(
        subscription_key(&descriptor, &GRANTS, TOKEN_INSTANCE),
        subscription_key(&descriptor, &CHURNED_GRANTS, ROTATED_TOKEN_INSTANCE),
        "a token or grant change must move the subscription partition"
    );
    assert_ne!(
        credential_key(&descriptor, TOKEN_INSTANCE),
        credential_key(&descriptor, ROTATED_TOKEN_INSTANCE),
        "a token change must move the credential-store partition"
    );
    // Durable owner and quota are derived from stable principal facts only.
    assert_eq!(
        owner_key(&descriptor),
        owner_key(&descriptor),
        "durable owner derivation is deterministic"
    );
    assert_eq!(
        quota_key(&descriptor),
        quota_key(&descriptor),
        "quota derivation is deterministic"
    );

    // An audience-policy revision bump is result-affecting.
    let bumped_policy = descriptor_from(&VerifiedFacts {
        audience_policy_revision: AUDIENCE_POLICY_REVISION + 1,
        ..BASELINE
    });
    assert_ne!(
        baseline_cache,
        cache_key(&bumped_policy, &GRANTS, TOKEN_INSTANCE),
        "an audience-policy revision change must move the cache partition"
    );
    assert_eq!(
        owner_key(&descriptor),
        owner_key(&bumped_policy),
        "an audience-policy revision change must not move durable ownership"
    );

    // -- Predicate: quota-key equality does not authorize a lookup --------
    // Two principals differing only in issuer share a quota identity but are
    // distinct durable owners.
    let other_issuer = descriptor_from(&VerifiedFacts {
        issuer: "https://other-auth.example.test",
        ..BASELINE
    });
    assert_eq!(
        quota_key(&descriptor),
        quota_key(&other_issuer),
        "quota identity deliberately excludes the issuer"
    );
    assert_ne!(
        owner_key(&descriptor),
        owner_key(&other_issuer),
        "durable ownership must distinguish issuers"
    );

    // -- Admission and lookup ---------------------------------------------
    let controller = controller();
    let auth = authorization(&descriptor);
    let quota = quota_key(&descriptor);
    let slot = PartitionSlot::Cache(baseline_cache);

    assert_eq!(controller.record_count(), 0);
    assert!(
        controller
            .store(&auth, &slot, b"result-bytes".to_vec())
            .is_none()
    );
    assert_eq!(controller.record_count(), 1);
    assert_eq!(
        controller.lookup(&auth, &slot),
        LookupOutcome::Present(b"result-bytes".to_vec()),
        "the owning principal must read its own record"
    );

    // Ordinary token rotation and scope churn do not move the authorization,
    // because neither is a descriptor field.
    assert_eq!(
        auth,
        PartitionAuthorization::current(&descriptor, &owner_key(&descriptor)),
        "authorization derivation is deterministic"
    );
    // A trust-generation bump relocates every record the principal could
    // previously reach.
    let bumped_trust = descriptor_from(&VerifiedFacts {
        trust_generation: TRUST_GENERATION + 1,
        ..BASELINE
    });
    assert_eq!(
        owner_key(&bumped_trust),
        owner_key(&descriptor),
        "a trust-generation bump must not move durable ownership"
    );
    assert_eq!(
        controller.lookup(&authorization(&bumped_trust), &slot),
        LookupOutcome::Absent,
        "a trust-generation bump must relocate the reachable partition"
    );

    // The same partition key presented by a different durable owner — the
    // leaked-key case — is absent, and nothing changes.
    let before_foreign = observe(&controller, &descriptor, &quota);
    let foreign_auth = authorization(&other_issuer);
    assert_eq!(
        controller.lookup(&foreign_auth, &slot),
        LookupOutcome::Absent,
        "holding another principal's partition key must not authorize a lookup"
    );
    assert_eq!(
        observe(&controller, &descriptor, &quota),
        before_foreign,
        "a non-oracular miss must not move any counter, including denials"
    );

    // Quota is admission only, and shared quota identity does not leak reads.
    let mut reservation = controller
        .reserve_quota(&quota, 3)
        .expect("quota reserve must be admitted");
    assert_eq!(controller.quota_in_use(&quota), 3);
    assert_eq!(
        controller.quota_in_use(&quota_key(&other_issuer)),
        3,
        "the shared quota identity shares admission accounting"
    );
    assert_eq!(
        controller.lookup(&foreign_auth, &slot),
        LookupOutcome::Absent,
        "holding the same quota identity must not authorize a lookup"
    );
    assert_eq!(
        controller
            .reserve_quota(&quota, 6)
            .expect_err("over-capacity quota must refuse"),
        PartitionAdmissionError::QuotaExhausted {
            requested: 6,
            in_use: 3,
            limit: 8,
        }
    );
    reservation.release().expect("quota release succeeds");
    assert_eq!(controller.quota_in_use(&quota), 0);
    assert_eq!(
        reservation
            .release()
            .expect_err("a second release must refuse"),
        PartitionAdmissionError::QuotaAlreadySettled
    );

    // -- Revalidation singleflight and concurrency ------------------------
    let flight_key =
        RevalidationFlightKey::derive(&descriptor, "revalidate-token").expect("flight key derives");
    let mut first = controller
        .begin_revalidation(&descriptor, &flight_key)
        .expect("the first flight is admitted");
    assert_eq!(controller.partition_flights(&descriptor), 1);
    assert_eq!(controller.provider_flights(&descriptor), 1);
    assert_eq!(controller.deployment_flights(), 1);
    assert_eq!(
        controller
            .begin_revalidation(&descriptor, &flight_key)
            .expect_err("singleflight must collapse the duplicate"),
        PartitionAdmissionError::RevalidationAlreadyInFlight
    );
    assert_eq!(
        controller.partition_flights(&descriptor),
        1,
        "a collapsed duplicate must not open a second flight"
    );

    let second_key = RevalidationFlightKey::derive(&descriptor, "revalidate-audience")
        .expect("a second purpose derives a distinct flight key");
    let mut second = controller
        .begin_revalidation(&descriptor, &second_key)
        .expect("a distinct purpose is admitted up to the partition ceiling");
    assert_eq!(controller.partition_flights(&descriptor), 2);

    let third_key = RevalidationFlightKey::derive(&descriptor, "revalidate-grants")
        .expect("a third purpose derives a distinct flight key");
    assert_eq!(
        controller
            .begin_revalidation(&descriptor, &third_key)
            .expect_err("the per-partition ceiling must refuse the third flight"),
        PartitionAdmissionError::PartitionRevalidationLimitExceeded {
            in_flight: DEFAULT_REVALIDATIONS_PER_PARTITION,
            limit: DEFAULT_REVALIDATIONS_PER_PARTITION,
        }
    );

    first.finish().expect("closing the first flight succeeds");
    assert_eq!(controller.partition_flights(&descriptor), 1);
    second.finish().expect("closing the second flight succeeds");
    assert_eq!(controller.partition_flights(&descriptor), 0);
    assert_eq!(controller.deployment_flights(), 0);
    // Attempts are not refunded: three admitted attempts were genuinely made.
    assert_eq!(controller.partition_attempts(&descriptor), 2);

    // -- Replay reservation ------------------------------------------------
    let replay = ReplayReservationKey::derive(&descriptor, "alias-1", "assertion-replay")
        .expect("replay key derives");
    controller
        .reserve_replay(&descriptor, &replay)
        .expect("the first reservation is admitted");
    assert!(controller.replay_reserved(&replay));
    assert_eq!(
        controller
            .reserve_replay(&descriptor, &replay)
            .expect_err("a duplicate alias must refuse"),
        PartitionAdmissionError::ReplayAliasAlreadyReserved
    );
    assert_eq!(controller.replay_reservation_count(), 1);

    // -- Sealed-field refusals --------------------------------------------
    assert_eq!(
        PartitionDescriptor::from_verified_facts(
            "",
            CONFIGURATION_GENERATION,
            ISSUER,
            RESOURCE,
            TENANT,
            SUBJECT,
            CLIENT,
            TRUST_GENERATION,
            AUDIENCE_POLICY_REVISION,
        )
        .expect_err("an empty verified field must refuse"),
        SealedAdmissionKeyError::EmptyField
    );
}

// ---------------------------------------------------------------------------
// Planted negative
// ---------------------------------------------------------------------------

/// The single verified field a planted negative mutates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MutatedRow {
    Tenant,
    Issuer,
    Resource,
    Subject,
    Client,
    Provider,
    RequiredGrant,
    TrustGeneration,
    ReplayAlias,
    QuotaEpoch,
}

/// One one-variable planted negative.
#[derive(Debug, Clone, Copy)]
struct PlantedCase {
    id: &'static str,
    row: MutatedRow,
}

const PLANTED_CASES: [PlantedCase; 10] = [
    PlantedCase {
        id: "AUTH-00-B-NEG.01",
        row: MutatedRow::Tenant,
    },
    PlantedCase {
        id: "AUTH-00-B-NEG.02",
        row: MutatedRow::Issuer,
    },
    PlantedCase {
        id: "AUTH-00-B-NEG.03",
        row: MutatedRow::Resource,
    },
    PlantedCase {
        id: "AUTH-00-B-NEG.04",
        row: MutatedRow::Subject,
    },
    PlantedCase {
        id: "AUTH-00-B-NEG.05",
        row: MutatedRow::Client,
    },
    PlantedCase {
        id: "AUTH-00-B-NEG.06",
        row: MutatedRow::Provider,
    },
    PlantedCase {
        id: "AUTH-00-B-NEG.07",
        row: MutatedRow::RequiredGrant,
    },
    PlantedCase {
        id: "AUTH-00-B-NEG.08",
        row: MutatedRow::TrustGeneration,
    },
    PlantedCase {
        id: "AUTH-00-B-NEG.09",
        row: MutatedRow::ReplayAlias,
    },
    PlantedCase {
        id: "AUTH-00-B-NEG.10",
        row: MutatedRow::QuotaEpoch,
    },
];

/// Applies exactly one mutation, leaving every other input byte-identical.
fn mutate(row: MutatedRow) -> (VerifiedFacts, &'static [&'static str], u64, &'static str) {
    let mut facts = BASELINE;
    let mut grants: &'static [&'static str] = &GRANTS;
    let mut quota_epoch = QUOTA_EPOCH;
    let mut replay_alias = "alias-1";
    match row {
        MutatedRow::Tenant => facts.tenant = "tenant-beta",
        MutatedRow::Issuer => facts.issuer = "https://other-auth.example.test",
        MutatedRow::Resource => facts.resource = "mcp://servers/other",
        MutatedRow::Subject => facts.subject = "subject-user-43",
        MutatedRow::Client => facts.client = "client-reg-2",
        MutatedRow::Provider => facts.provider = "org.other.provider",
        MutatedRow::RequiredGrant => grants = &CHURNED_GRANTS,
        MutatedRow::TrustGeneration => facts.trust_generation = TRUST_GENERATION + 1,
        MutatedRow::ReplayAlias => replay_alias = "alias-2",
        MutatedRow::QuotaEpoch => quota_epoch = QUOTA_EPOCH + 1,
    }
    (facts, grants, quota_epoch, replay_alias)
}

#[test]
fn auth_00_b_planted_negative() {
    // Numeric floor: ten one-variable rows, one per named mutable field.
    assert_eq!(
        PLANTED_CASES.len(),
        10,
        "the acceptance names ten one-variable mutation rows"
    );

    let baseline = baseline_descriptor();
    let baseline_rows = baseline_manifest(&baseline);
    let baseline_digest = manifest_digest(&baseline_rows);
    let baseline_owner = owner_key(&baseline);
    let baseline_quota = quota_key(&baseline);
    let baseline_cache = cache_key(&baseline, &GRANTS, TOKEN_INSTANCE);
    let baseline_slot = PartitionSlot::Cache(baseline_cache);

    for case in &PLANTED_CASES {
        // A fresh controller per row, populated identically.
        let controller = controller();
        controller.store(&baseline_owner, &baseline_slot, b"result-bytes".to_vec());
        let mut held = controller
            .reserve_quota(&baseline_quota, 3)
            .expect("baseline quota reserve is admitted");
        let baseline_flight = RevalidationFlightKey::derive(&baseline, "revalidate-token")
            .expect("baseline flight key derives");
        let mut flight = controller
            .begin_revalidation(&baseline, &baseline_flight)
            .expect("baseline flight is admitted");
        let baseline_replay =
            ReplayReservationKey::derive(&baseline, "alias-1", "assertion-replay")
                .expect("baseline replay key derives");
        controller
            .reserve_replay(&baseline, &baseline_replay)
            .expect("baseline replay reservation is admitted");

        let before = observe(&controller, &baseline, &baseline_quota);
        assert_eq!(
            controller.lookup(&baseline_owner, &baseline_slot),
            LookupOutcome::Present(b"result-bytes".to_vec()),
            "{}: the baseline record must be present before the mutation",
            case.id
        );

        // -- apply exactly one mutation --------------------------------
        let (facts, grants, quota_epoch, replay_alias) = mutate(case.row);
        let mutated = descriptor_from(&facts);
        let mutated_rows =
            build_manifest(&mutated, grants, TOKEN_INSTANCE, quota_epoch, replay_alias);

        // The manifest digest is sensitive to every named row.
        assert_ne!(
            manifest_digest(&mutated_rows),
            baseline_digest,
            "{}: mutating {:?} must change auth_00_b_manifest_digest",
            case.id,
            case.row
        );
        assert_eq!(
            mutated_rows.len(),
            baseline_rows.len(),
            "{}: the mutation must not change the manifest shape",
            case.id
        );

        // -- the typed denial -------------------------------------------
        let mutated_owner = owner_key(&mutated);
        let mutated_cache = cache_key(&mutated, grants, TOKEN_INSTANCE);

        // Reading the victim's record with the mutated authorization is
        // absent, and so is reading the mutated partition. Both are
        // indistinguishable from a genuine miss: that is the non-oracular
        // property.
        assert_eq!(
            controller.lookup(&mutated_owner, &baseline_slot),
            LookupOutcome::Absent,
            "{}: mutating {:?} must not authorize the baseline record",
            case.id,
            case.row
        );
        assert_eq!(
            controller.lookup(&mutated_owner, &PartitionSlot::Cache(mutated_cache)),
            LookupOutcome::Absent,
            "{}: the mutated partition must hold nothing",
            case.id
        );

        // A duplicate replay alias reaches its typed denial.
        assert_eq!(
            controller
                .reserve_replay(&baseline, &baseline_replay)
                .expect_err("a duplicate baseline alias must refuse"),
            PartitionAdmissionError::ReplayAliasAlreadyReserved,
            "{}: duplicate replay alias denial",
            case.id
        );
        // A duplicate singleflight reaches its typed denial.
        assert_eq!(
            controller
                .begin_revalidation(&baseline, &baseline_flight)
                .expect_err("a duplicate baseline flight must refuse"),
            PartitionAdmissionError::RevalidationAlreadyInFlight,
            "{}: duplicate singleflight denial",
            case.id
        );

        // -- cross-tenant no effect --------------------------------------
        let after = observe(&controller, &baseline, &baseline_quota);
        assert_eq!(
            after.records, before.records,
            "{}: the victim's records must be unchanged",
            case.id
        );
        assert_eq!(
            after.quota_in_use, before.quota_in_use,
            "{}: the victim's quota reservations must be unchanged",
            case.id
        );
        assert_eq!(
            after.partition_flights, before.partition_flights,
            "{}: the victim's revalidation flight must be unchanged",
            case.id
        );
        assert_eq!(
            after.provider_flights, before.provider_flights,
            "{}: the victim's provider flight count must be unchanged",
            case.id
        );
        assert_eq!(
            after.deployment_flights, before.deployment_flights,
            "{}: the deployment flight count must be unchanged",
            case.id
        );
        assert_eq!(
            after.replay_reservations, before.replay_reservations,
            "{}: the victim's replay reservation must be unchanged",
            case.id
        );
        assert_eq!(
            controller.lookup(&baseline_owner, &baseline_slot),
            LookupOutcome::Present(b"result-bytes".to_vec()),
            "{}: the victim's record must still be readable by its owner",
            case.id
        );
        assert!(
            controller.replay_reserved(&baseline_replay),
            "{}: the victim's replay alias must still be reserved",
            case.id
        );

        held.release().expect("baseline quota releases once");
        flight.finish().expect("baseline flight closes once");
    }

    // Each mutation moves exactly the rows it should and no others.
    for case in &PLANTED_CASES {
        let (facts, grants, quota_epoch, replay_alias) = mutate(case.row);
        let mutated = descriptor_from(&facts);
        let mutated_quota =
            QuotaPartitionKey::derive(&mutated, quota_epoch).expect("mutated quota derives");
        let mutated_owner = owner_key(&mutated);
        let mutated_replay =
            ReplayReservationKey::derive(&mutated, replay_alias, "assertion-replay")
                .expect("mutated replay derives");

        match case.row {
            // Issuer is excluded from quota identity by design, so it moves
            // ownership without moving quota.
            MutatedRow::Issuer => {
                assert_eq!(
                    mutated_quota, baseline_quota,
                    "{}: quota excludes issuer",
                    case.id
                );
                assert_ne!(
                    mutated_owner, baseline_owner,
                    "{}: owner includes issuer",
                    case.id
                );
            }
            // Grants, trust generation and replay alias are not owner or
            // quota inputs: ownership and quota identity survive them.
            MutatedRow::RequiredGrant | MutatedRow::TrustGeneration | MutatedRow::ReplayAlias => {
                assert_eq!(
                    mutated_quota, baseline_quota,
                    "{}: quota identity must survive scope churn",
                    case.id
                );
                assert_eq!(
                    mutated_owner, baseline_owner,
                    "{}: durable ownership must survive scope churn",
                    case.id
                );
            }
            MutatedRow::QuotaEpoch => {
                assert_ne!(
                    mutated_quota, baseline_quota,
                    "{}: quota epoch is a quota input",
                    case.id
                );
                assert_eq!(
                    mutated_owner, baseline_owner,
                    "{}: quota epoch is not an owner input",
                    case.id
                );
            }
            // The stable principal facts move both.
            MutatedRow::Tenant
            | MutatedRow::Resource
            | MutatedRow::Subject
            | MutatedRow::Client
            | MutatedRow::Provider => {
                assert_ne!(
                    mutated_quota, baseline_quota,
                    "{}: quota must move",
                    case.id
                );
                assert_ne!(
                    mutated_owner, baseline_owner,
                    "{}: ownership must move",
                    case.id
                );
            }
        }

        if case.row == MutatedRow::ReplayAlias {
            assert_ne!(
                mutated_replay,
                ReplayReservationKey::derive(&baseline, "alias-1", "assertion-replay")
                    .expect("baseline replay derives"),
                "{}: a different alias must be a different reservation",
                case.id
            );
        }
    }
}
