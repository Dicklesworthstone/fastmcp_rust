//! LIMIT-01 implementation A frozen proofs, as an EXTERNAL consumer.
//!
//! bd-600a3. These four IDs previously existed only inside
//! `crates/fastmcp-core/src/lib.rs` under `#[cfg(test)]`, where they could
//! observe the crate from the inside. PL-3 makes that inadmissible for a
//! capability Bead: `cfg(test)` behaviour cannot prove shipped behaviour, and
//! an A/B frozen pair exists precisely to bind the PUBLIC surface.
//!
//! This target links `fastmcp-core` the way any dependent does, through
//! `use fastmcp_core::...` only. The in-crate copies are left untouched; a
//! duplicate ID inside a `mod tests` does not collide with a root-level one,
//! so both coexist and `--exact` still resolves each to one definition.
//!
//! NOTHING WAS RE-EXPORTED TO MAKE THIS COMPILE. Every symbol these tests
//! touch was already public at the crate root (`lib.rs:2229`), so the
//! `cfg(test)` placement was never forced by the API — which is the finding,
//! not just the fix.

mod limit_01_rows;

fn limit_01_a_bound_rows() -> [(fastmcp_core::ProtocolLimit, usize, usize); 6] {
    [
        (
            fastmcp_core::ProtocolLimit::JsonRpcBodyBytes,
            fastmcp_core::DEFAULT_JSON_RPC_MAX_BODY_BYTES,
            fastmcp_core::HARD_JSON_RPC_MAX_BODY_BYTES,
        ),
        (
            fastmcp_core::ProtocolLimit::MetadataEntries,
            fastmcp_core::DEFAULT_METADATA_MAX_ENTRIES as usize,
            fastmcp_core::HARD_METADATA_MAX_ENTRIES as usize,
        ),
        (
            fastmcp_core::ProtocolLimit::MetadataBytes,
            fastmcp_core::DEFAULT_METADATA_MAX_BYTES,
            fastmcp_core::HARD_METADATA_MAX_BYTES,
        ),
        (
            fastmcp_core::ProtocolLimit::UriBytes,
            fastmcp_core::DEFAULT_URI_MAX_BYTES,
            fastmcp_core::HARD_URI_MAX_BYTES,
        ),
        (
            fastmcp_core::ProtocolLimit::CancellationReasonBytes,
            fastmcp_core::DEFAULT_CANCELLATION_REASON_MAX_BYTES,
            fastmcp_core::HARD_CANCELLATION_REASON_MAX_BYTES,
        ),
        (
            fastmcp_core::ProtocolLimit::CursorBytes,
            fastmcp_core::DEFAULT_CURSOR_MAX_BYTES,
            fastmcp_core::HARD_CURSOR_MAX_BYTES,
        ),
    ]
}


/// LIMIT-01 A positive: six catalog rows, sealed partitions, and N-1/N charges.
#[test]
fn limit_01_a_positive() {
    let defaults = fastmcp_core::ProtocolLimits::try_new(
        fastmcp_core::DEFAULT_JSON_RPC_MAX_BODY_BYTES,
        fastmcp_core::DEFAULT_METADATA_MAX_ENTRIES,
        fastmcp_core::DEFAULT_METADATA_MAX_BYTES,
        fastmcp_core::DEFAULT_URI_MAX_BYTES,
        fastmcp_core::DEFAULT_CANCELLATION_REASON_MAX_BYTES,
        fastmcp_core::DEFAULT_CURSOR_MAX_BYTES,
    )
    .expect("documented defaults must admit");
    defaults.validate().expect("defaults remain valid");
    let snapshot = defaults.snapshot();
    assert_eq!(
        snapshot.generation(),
        fastmcp_core::PROTOCOL_LIMITS_INITIAL_GENERATION
    );
    for (limit, default, ceiling) in limit_01_a_bound_rows() {
        assert_eq!(
            snapshot.configured_units(limit).expect("countable row"),
            default
        );
        assert_eq!(
            fastmcp_core::ProtocolLimits::hard_ceiling(limit).expect("countable row"),
            ceiling
        );
        let at_ceiling = fastmcp_core::ProtocolLimits::builder()
            .json_rpc_max_body_bytes(if limit == fastmcp_core::ProtocolLimit::JsonRpcBodyBytes {
                ceiling
            } else {
                fastmcp_core::DEFAULT_JSON_RPC_MAX_BODY_BYTES
            })
            .metadata_max_entries(if limit == fastmcp_core::ProtocolLimit::MetadataEntries {
                u16::try_from(ceiling).expect("metadata entries fit u16")
            } else {
                fastmcp_core::DEFAULT_METADATA_MAX_ENTRIES
            })
            .metadata_max_bytes(if limit == fastmcp_core::ProtocolLimit::MetadataBytes {
                ceiling
            } else {
                fastmcp_core::DEFAULT_METADATA_MAX_BYTES
            })
            .uri_max_bytes(if limit == fastmcp_core::ProtocolLimit::UriBytes {
                ceiling
            } else {
                fastmcp_core::DEFAULT_URI_MAX_BYTES
            })
            .cancellation_reason_max_bytes(
                if limit == fastmcp_core::ProtocolLimit::CancellationReasonBytes {
                    ceiling
                } else {
                    fastmcp_core::DEFAULT_CANCELLATION_REASON_MAX_BYTES
                },
            )
            .cursor_max_bytes(if limit == fastmcp_core::ProtocolLimit::CursorBytes {
                ceiling
            } else {
                fastmcp_core::DEFAULT_CURSOR_MAX_BYTES
            })
            .build()
            .expect("hard ceiling must admit");
        assert_eq!(
            at_ceiling.configured_units(limit).expect("countable row"),
            ceiling
        );
        assert_eq!(
            snapshot
                .try_charge(limit, default - 1, 1)
                .expect("N-1 admits"),
            default
        );
        assert_eq!(
            snapshot.try_charge(limit, 0, default).expect("N admits"),
            default
        );
    }

    assert_eq!(
        fastmcp_core::ProtocolLimits::hard_ceiling(fastmcp_core::ProtocolLimit::LogicalExchangeWallClock),
        Err(fastmcp_core::ProtocolLimitsError::NotCountable {
            limit: fastmcp_core::ProtocolLimit::LogicalExchangeWallClock,
        })
    );
    assert_eq!(
        snapshot.configured_units(fastmcp_core::ProtocolLimit::LogicalExchangeWallClock),
        Err(fastmcp_core::ProtocolLimitsError::NotCountable {
            limit: fastmcp_core::ProtocolLimit::LogicalExchangeWallClock,
        })
    );

    let later = fastmcp_core::ProtocolLimits::try_new(
        fastmcp_core::HARD_JSON_RPC_MAX_BODY_BYTES,
        fastmcp_core::HARD_METADATA_MAX_ENTRIES,
        fastmcp_core::HARD_METADATA_MAX_BYTES,
        fastmcp_core::HARD_URI_MAX_BYTES,
        fastmcp_core::HARD_CANCELLATION_REASON_MAX_BYTES,
        fastmcp_core::HARD_CURSOR_MAX_BYTES,
    )
    .expect("hard ceilings must admit");
    assert_eq!(snapshot, defaults.snapshot());
    assert_ne!(later.snapshot(), snapshot);

    let pre_auth = fastmcp_core::AdmissionPartition::pre_auth(
        fastmcp_core::PreAuthSourceBucketKey::from_listener_and_source(
            "mcp.example.test",
            "tcp:203.0.113.8",
        )
        .expect("transport-observed source is admitted"),
    );
    assert!(pre_auth.is_pre_auth());
    assert!(!pre_auth.is_verified());
    let verified = fastmcp_core::AdmissionPartition::verified(
        fastmcp_core::QuotaPartitionKey::from_verified_security_facts(
            "static-token",
            1,
            "https://issuer.example.test",
            "https://mcp.example.test/mcp",
            "tenant-a",
            "subject-a",
        )
        .expect("verified security facts mint a partition key"),
    );
    assert!(verified.is_verified());
    let flow = fastmcp_core::AdmissionPartition::authorization_flow(
        fastmcp_core::AuthorizationFlowQuotaKey::from_configured_flow(
            "https://issuer.example.test",
            "https://mcp.example.test/mcp",
            "registered-client-1",
            "loopback",
            "oauth-authorization-code",
        )
        .expect("configured flow is admitted"),
    );
    assert!(!flow.is_verified());
    assert!(!flow.is_pre_auth());

    // -----------------------------------------------------------------------
    // Ordered acceptance rows and the three canonical LIMIT-01 A receipts.
    // -----------------------------------------------------------------------

    // AC-LIMIT-A-01-BOUNDS — numeric floor 6, digest LIMIT01-A-BOUNDS-v1 over
    // ordered row ID / default / ceiling / result fields.
    let bound_rows = limit_01_rows::run_bound_rows();
    assert_eq!(bound_rows.len(), 6, "AC-LIMIT-A-01 numeric floor is 6 rows");
    let bounds = limit_01_rows::bounds_receipt(&bound_rows);
    assert_eq!(bounds.len(), 1 + 6, "the bounds receipt carries a header and six ordered rows");
    assert_eq!(
        bounds[0],
        format!(
            "LIMIT01-A-BOUNDS-v1 rows=6 generation={}",
            fastmcp_core::PROTOCOL_LIMITS_INITIAL_GENERATION
        )
    );
    for (index, (id, limit, default, ceiling)) in
        limit_01_rows::bound_rows().into_iter().enumerate()
    {
        // Each row's declared refusal above its ceiling is the row's own bound,
        // so a diagnostic naming the wrong bound fails here.
        assert_eq!(
            bounds[1 + index],
            format!(
                "{id} configured={default} ceiling={ceiling} generation={} refused={:?}",
                fastmcp_core::PROTOCOL_LIMITS_INITIAL_GENERATION,
                fastmcp_core::ProtocolLimitsError::ExceedsHardCeiling { limit }
            ),
            "bounds receipt row {index} must be the frozen {id} tuple"
        );
    }

    // AC-LIMIT-A-02-PARTITIONS — numeric floor 5, digest LIMIT01-A-PARTITIONS-v1
    // over ordered discriminant / generation / result fields.
    let partition_rows = limit_01_rows::run_partition_rows();
    assert_eq!(
        partition_rows.len(),
        5,
        "AC-LIMIT-A-02 numeric floor is 5 rows"
    );
    let partitions = limit_01_rows::partitions_receipt(&partition_rows);
    assert_eq!(partitions.len(), 1 + 5);
    assert_eq!(partitions[0], "LIMIT01-A-PARTITIONS-v1 rows=5");
    for (index, (id, discriminant)) in [
        ("LIMIT-A-02.01", "PreAuth"),
        ("LIMIT-A-02.02", "Verified"),
        ("LIMIT-A-02.03", "AuthorizationFlow"),
        ("LIMIT-A-02.04", "refused"),
        ("LIMIT-A-02.05", "refused"),
    ]
    .into_iter()
    .enumerate()
    {
        let row = &partition_rows[index];
        assert_eq!(row.id, id, "partition row {index} is out of acceptance order");
        assert_eq!(row.discriminant, discriminant, "{id}: wrong discriminant");
        assert_eq!(
            row.generation,
            fastmcp_core::PROTOCOL_LIMITS_INITIAL_GENERATION,
            "{id}: the request snapshot generation must not move"
        );
        // Every row re-offers its own raw input to the sealed path. If any
        // constructor were unsealed so a request-supplied value could mint a
        // partition, this flips to false.
        assert!(
            row.non_authorizing,
            "{id}: a request-supplied identifier must never mint a partition key"
        );
        assert!(
            partitions[1 + index].starts_with(&format!("{id} discriminant={discriminant}")),
            "partitions receipt row {index} must be {id}"
        );
    }
    // No raw value manufactured a Verified partition: the only Verified row is
    // the one built from verified security facts.
    assert_eq!(
        partition_rows
            .iter()
            .filter(|row| row.discriminant == "Verified")
            .count(),
        1,
        "exactly one row may reach the verified domain, and only from verified facts"
    );
    for id in ["LIMIT-A-02.04", "LIMIT-A-02.05"] {
        let row = partition_rows
            .iter()
            .find(|row| row.id == id)
            .expect("refusal row present");
        assert_eq!(
            row.result,
            Err(fastmcp_core::SealedAdmissionKeyError::RequestSuppliedIdentifier),
            "{id}: the sealed refusal must be the typed request-supplied error"
        );
    }

    // AC-LIMIT-A-03-ARITHMETIC — numeric floor 4, digest LIMIT01-A-ARITHMETIC-v1
    // over ordered inputs / results / counters.
    let arithmetic_rows = limit_01_rows::run_arithmetic_rows();
    assert_eq!(
        arithmetic_rows.len(),
        4,
        "AC-LIMIT-A-03 numeric floor is 4 rows"
    );
    let row_limit = fastmcp_core::ProtocolLimit::MetadataEntries;
    let available = fastmcp_core::DEFAULT_METADATA_MAX_ENTRIES as usize;
    let expected_arithmetic = [
        (
            "LIMIT-A-03.01",
            available - 1,
            Ok(available - 1),
            available - 1,
        ),
        ("LIMIT-A-03.02", available, Ok(available), available),
        (
            "LIMIT-A-03.03",
            1,
            Err(fastmcp_core::ProtocolLimitsError::ChargeExceedsLimit {
                limit: row_limit,
                requested: available + 1,
                ceiling: available,
            }),
            // The refused N+1 leaves the retained counter exactly where the
            // admitted N left it: no wrap, no partial advance.
            available,
        ),
        (
            "LIMIT-A-03.04",
            1,
            Err(fastmcp_core::ProtocolLimitsError::ChargeOverflow { limit: row_limit }),
            available,
        ),
    ];
    for (index, (id, requested, result, retained)) in expected_arithmetic.into_iter().enumerate() {
        let row = &arithmetic_rows[index];
        assert_eq!(row.id, id, "arithmetic row {index} is out of acceptance order");
        assert_eq!(row.requested, requested, "{id}: wrong requested units");
        assert_eq!(row.available, available, "{id}: wrong available units");
        assert_eq!(row.result, result, "{id}: wrong public result");
        assert_eq!(row.retained, retained, "{id}: wrong retained counter");
    }
    let arithmetic = limit_01_rows::arithmetic_receipt(&arithmetic_rows);
    assert_eq!(arithmetic.len(), 1 + 4);
    assert_eq!(arithmetic[0], "LIMIT01-A-ARITHMETIC-v1 rows=4");
}


/// LIMIT-01 A planted negative: one-row N+1 and raw identifiers leave state unchanged.
#[test]
fn limit_01_a_planted_negative() {
    let limits = fastmcp_core::ProtocolLimits::try_new(
        fastmcp_core::DEFAULT_JSON_RPC_MAX_BODY_BYTES,
        fastmcp_core::DEFAULT_METADATA_MAX_ENTRIES,
        fastmcp_core::DEFAULT_METADATA_MAX_BYTES,
        fastmcp_core::DEFAULT_URI_MAX_BYTES,
        fastmcp_core::DEFAULT_CANCELLATION_REASON_MAX_BYTES,
        fastmcp_core::DEFAULT_CURSOR_MAX_BYTES,
    )
    .expect("documented defaults must admit");
    let snapshot_before = limits.snapshot();
    let mut admitted = 0_usize;
    let planted = fastmcp_core::ProtocolLimit::MetadataEntries;
    let ceiling = limits.configured_units(planted).expect("countable row");
    let refused = limits
        .try_charge(planted, ceiling, 1)
        .expect_err("N+1 must refuse");
    assert_eq!(
        refused,
        fastmcp_core::ProtocolLimitsError::ChargeExceedsLimit {
            limit: planted,
            requested: ceiling + 1,
            ceiling,
        }
    );
    let overflow = limits
        .try_charge(planted, usize::MAX, 1)
        .expect_err("overflow must refuse");
    assert_eq!(
        overflow,
        fastmcp_core::ProtocolLimitsError::ChargeOverflow { limit: planted }
    );
    assert_eq!(admitted, 0);
    admitted = limits
        .try_charge(planted, admitted, ceiling)
        .expect("exact N still admits after refused N+1");
    assert_eq!(admitted, ceiling);
    assert_eq!(limits.snapshot(), snapshot_before);
    assert_eq!(
        fastmcp_core::ProtocolLimits::builder()
            .metadata_max_entries(fastmcp_core::HARD_METADATA_MAX_ENTRIES + 1)
            .build()
            .expect_err("ceiling+1 must refuse configuration"),
        fastmcp_core::ProtocolLimitsError::ExceedsHardCeiling {
            limit: fastmcp_core::ProtocolLimit::MetadataEntries,
        }
    );
    assert_eq!(limits.snapshot(), snapshot_before);

    let partition_before = fastmcp_core::AdmissionPartition::pre_auth(
        fastmcp_core::PreAuthSourceBucketKey::from_listener_and_source(
            "mcp.example.test",
            "tcp:203.0.113.8",
        )
        .expect("transport-observed source is admitted"),
    );
    assert_eq!(
        fastmcp_core::QuotaPartitionKey::try_from_request_identifier("raw-request-id"),
        Err(fastmcp_core::SealedAdmissionKeyError::RequestSuppliedIdentifier)
    );
    assert_eq!(
        fastmcp_core::AdmissionPartition::try_from_request_identifier("raw-request-id"),
        Err(fastmcp_core::SealedAdmissionKeyError::RequestSuppliedIdentifier)
    );
    assert!(partition_before.is_pre_auth());
    assert!(!partition_before.is_verified());
    assert_eq!(limits.snapshot(), snapshot_before);

    // -----------------------------------------------------------------------
    // The canonical receipts are unchanged across the refused one-variable
    // mutation — and are proved sensitive first, so "unchanged" means something.
    // -----------------------------------------------------------------------

    let bounds_before = limit_01_rows::bounds_receipt(&limit_01_rows::run_bound_rows());
    let partitions_before =
        limit_01_rows::partitions_receipt(&limit_01_rows::run_partition_rows());
    let arithmetic_before =
        limit_01_rows::arithmetic_receipt(&limit_01_rows::run_arithmetic_rows());

    // SENSITIVITY: a receipt that cannot change cannot witness anything. Perturb
    // exactly one observed field in each row set and require the digest to move.
    // If these pass while the digest is a constant string, the equality checks
    // below would be worthless.
    let mut perturbed_bounds = limit_01_rows::run_bound_rows();
    perturbed_bounds[1].configured += 1;
    assert_ne!(
        limit_01_rows::bounds_receipt(&perturbed_bounds),
        bounds_before,
        "LIMIT01-A-BOUNDS-v1 must observe the configured field"
    );
    let mut perturbed_partitions = limit_01_rows::run_partition_rows();
    perturbed_partitions[0].non_authorizing = !perturbed_partitions[0].non_authorizing;
    assert_ne!(
        limit_01_rows::partitions_receipt(&perturbed_partitions),
        partitions_before,
        "LIMIT01-A-PARTITIONS-v1 must observe the non-authorizing-key status"
    );
    let mut perturbed_arithmetic = limit_01_rows::run_arithmetic_rows();
    perturbed_arithmetic[3].retained += 1;
    assert_ne!(
        limit_01_rows::arithmetic_receipt(&perturbed_arithmetic),
        arithmetic_before,
        "LIMIT01-A-ARITHMETIC-v1 must observe the retained counter"
    );

    // THE ONE VARIABLE: a single catalog row moves from its ceiling N to N+1.
    // Every other row keeps its documented value.
    let mutated = limit_01_rows::build_with_override(
        fastmcp_core::ProtocolLimit::CursorBytes,
        fastmcp_core::HARD_CURSOR_MAX_BYTES + 1,
    )
    .expect_err("one row at ceiling+1 must refuse the whole configuration");
    assert_eq!(
        mutated,
        fastmcp_core::ProtocolLimitsError::ExceedsHardCeiling {
            limit: fastmcp_core::ProtocolLimit::CursorBytes,
        }
    );
    // The same builder with that one row at exactly N still admits, so the
    // refusal above is attributable to the single changed variable and nothing
    // else in the configuration.
    limit_01_rows::build_with_override(
        fastmcp_core::ProtocolLimit::CursorBytes,
        fastmcp_core::HARD_CURSOR_MAX_BYTES,
    )
    .expect("the same configuration at exactly N must still admit");

    // No snapshot, counter, or admitted-work state moved.
    assert_eq!(
        limit_01_rows::bounds_receipt(&limit_01_rows::run_bound_rows()),
        bounds_before,
        "the refused row must leave LIMIT01-A-BOUNDS-v1 byte-identical"
    );
    assert_eq!(
        limit_01_rows::partitions_receipt(&limit_01_rows::run_partition_rows()),
        partitions_before,
        "the refused row must leave LIMIT01-A-PARTITIONS-v1 byte-identical"
    );
    assert_eq!(
        limit_01_rows::arithmetic_receipt(&limit_01_rows::run_arithmetic_rows()),
        arithmetic_before,
        "the refused row must leave LIMIT01-A-ARITHMETIC-v1 byte-identical"
    );
    assert_eq!(limits.snapshot(), snapshot_before);
}
