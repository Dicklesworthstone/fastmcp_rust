//! Explicit outbound trace admission at client request boundaries.

use fastmcp_core::limits::DEFAULT_METADATA_MAX_BYTES;
use fastmcp_core::{McpError, McpResult, OutboundTraceDecision, TraceEndpoint, TraceTransport};
use fastmcp_protocol::common_types::{MAX_METADATA_ENTRIES, MAX_METADATA_VALUE_BYTES};
use fastmcp_protocol::protocol_policy::ProtocolEra;
use serde_json::{Map, Value};

/// Validates local configuration before changing a live client's state.
/// Network clients bind to their actual immutable destination; an already
/// owned local/pre-upgraded transport has the peer identity asserted by its
/// host when it supplies the policy decision.
pub(crate) fn validate_destination(
    decision: Option<&OutboundTraceDecision>,
    transport: TraceTransport,
    era: Option<ProtocolEra>,
    network_target: Option<&str>,
) -> McpResult<()> {
    let Some(decision) = decision else {
        return Ok(());
    };
    if era != Some(ProtocolEra::Modern2026) {
        return Err(McpError::invalid_params(
            "Outbound trace propagation requires a negotiated MCP 2026-07-28 peer",
        ));
    }
    let destination = decision.destination();
    if destination.transport() != transport {
        return Err(McpError::invalid_params(
            "Outbound trace decision does not match this client's transport",
        ));
    }
    if let Some(target) = network_target {
        let actual = TraceEndpoint::network(
            transport,
            target,
            destination.tenant(),
            destination.security_domain(),
        )
        .map_err(|_| McpError::invalid_params("Outbound trace destination is invalid"))?;
        if &actual != destination {
            return Err(McpError::invalid_params(
                "Outbound trace decision does not match this client's destination",
            ));
        }
    } else if transport == TraceTransport::WebSocket && destination.network_origin().is_some() {
        return Err(McpError::invalid_params(
            "Pre-upgraded WebSocket trace propagation requires a host-assigned local peer identity",
        ));
    }
    Ok(())
}

/// Raw caller metadata never grants forwarding authority. Only the immutable
/// output of an explicitly evaluated policy may populate these wire fields.
pub(crate) fn apply_metadata(
    metadata: &mut Map<String, Value>,
    decision: Option<&OutboundTraceDecision>,
) {
    for name in ["traceparent", "tracestate", "baggage"] {
        metadata.remove(name);
    }
    if let Some(decision) = decision {
        let context = decision.context();
        for (name, value) in [
            ("traceparent", context.traceparent()),
            ("tracestate", context.tracestate()),
            ("baggage", context.baggage()),
        ] {
            if let Some(value) = value {
                metadata.insert(name.to_owned(), Value::String(value.to_owned()));
            }
        }
        // Optional telemetry must not push an otherwise valid application
        // request over the carrier's entry or encoded-byte ceilings. Drop the
        // whole projection so tracestate can never outlive its parent. The
        // bounded writer measures without allocating a second metadata body.
        let trace_value_exceeds_limit = ["traceparent", "tracestate", "baggage"]
            .iter()
            .filter_map(|name| metadata.get(*name))
            .any(|value| {
                serde_json::to_writer(&mut MetadataByteBudget(MAX_METADATA_VALUE_BYTES), value)
                    .is_err()
            });
        if metadata.len() > MAX_METADATA_ENTRIES
            || trace_value_exceeds_limit
            || serde_json::to_writer(
                &mut MetadataByteBudget(DEFAULT_METADATA_MAX_BYTES),
                &metadata,
            )
            .is_err()
        {
            for name in ["traceparent", "tracestate", "baggage"] {
                metadata.remove(name);
            }
        }
    }
}

struct MetadataByteBudget(usize);

impl std::io::Write for MetadataByteBudget {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.checked_sub(bytes.len()).ok_or_else(|| {
            std::io::Error::other("outbound trace exceeds metadata carrier capacity")
        })?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Notification and raw-request paths do not synthesize request-only metadata.
/// Invalid application envelope shapes remain the owning codec's concern.
pub(crate) fn apply_parameters(parameters: &mut Value, decision: Option<&OutboundTraceDecision>) {
    let Some(parameters) = parameters.as_object_mut() else {
        return;
    };
    let has_trace = decision.is_some_and(|decision| !decision.context().is_empty());
    if has_trace {
        parameters
            .entry("_meta")
            .or_insert_with(|| Value::Object(Map::new()));
    }
    if let Some(metadata) = parameters.get_mut("_meta").and_then(Value::as_object_mut) {
        apply_metadata(metadata, decision);
    }
}

#[cfg(test)]
pub(crate) const TEST_TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

#[cfg(test)]
pub(crate) fn test_decision(transport: TraceTransport, target: &str) -> OutboundTraceDecision {
    use fastmcp_core::{
        BaggageForwardingLimits, OutboundTracePolicy, TraceContext, TracePropagationRule,
    };

    let source = TraceEndpoint::network(
        TraceTransport::Http,
        "https://inbound.example/mcp",
        "tenant-a",
        "domain-a",
    )
    .unwrap();
    let destination = if transport == TraceTransport::Http {
        TraceEndpoint::network(transport, target, "tenant-a", "domain-a")
    } else {
        TraceEndpoint::local(transport, target, "tenant-a", "domain-a")
    }
    .unwrap();
    let context = TraceContext::try_from_fields(
        Some(TEST_TRACEPARENT),
        Some("vendor=kept,other=drop"),
        Some("region=us,authorization=never-forward,user=not-allowed"),
    )
    .unwrap();
    OutboundTracePolicy::new(19)
        .unwrap()
        .with_rule(
            TracePropagationRule::new(source.clone(), destination.clone())
                .with_traceparent()
                .with_tracestate_keys(["vendor"])
                .unwrap()
                .with_baggage_keys(
                    ["region", "authorization"],
                    BaggageForwardingLimits::default(),
                )
                .unwrap(),
        )
        .unwrap()
        .evaluate(&source, &destination, &context, "2026-07-28")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obs01_outbound_trace_exhausted_carriers_drop_only_optional_telemetry() {
        let decision = test_decision(TraceTransport::Memory, "bounded-peer");
        let mut count_limited = (0..MAX_METADATA_ENTRIES)
            .map(|index| (format!("example.test/key{index}"), Value::Null))
            .collect::<Map<_, _>>();
        let expected = count_limited.clone();
        apply_metadata(&mut count_limited, Some(&decision));
        assert_eq!(count_limited, expected);

        let mut byte_limited = (0..16)
            .map(|index| {
                (
                    format!("example.test/key{index}"),
                    Value::String("x".repeat(MAX_METADATA_VALUE_BYTES - 2)),
                )
            })
            .collect::<Map<_, _>>();
        let size = serde_json::to_vec(&byte_limited).unwrap().len();
        let trim = size - (DEFAULT_METADATA_MAX_BYTES - 1);
        let Value::String(value) = byte_limited.get_mut("example.test/key0").unwrap() else {
            unreachable!()
        };
        value.truncate(value.len() - trim);
        assert_eq!(
            serde_json::to_vec(&byte_limited).unwrap().len(),
            DEFAULT_METADATA_MAX_BYTES - 1
        );
        let expected = byte_limited.clone();
        apply_metadata(&mut byte_limited, Some(&decision));
        assert_eq!(byte_limited, expected);
    }

    #[test]
    fn obs01_outbound_trace_binding_refuses_legacy_foreign_origin_and_transport() {
        let decision = test_decision(TraceTransport::Http, "https://peer.example/mcp");
        assert!(
            validate_destination(
                Some(&decision),
                TraceTransport::Http,
                Some(ProtocolEra::Modern2026),
                Some("https://peer.example/another-path")
            )
            .is_ok()
        );
        assert!(
            validate_destination(
                Some(&decision),
                TraceTransport::Http,
                Some(ProtocolEra::Modern2026),
                Some("https://foreign.example/mcp")
            )
            .is_err()
        );
        assert!(
            validate_destination(
                Some(&decision),
                TraceTransport::Memory,
                Some(ProtocolEra::Modern2026),
                None
            )
            .is_err()
        );
        assert!(validate_destination(Some(&decision), TraceTransport::Http, None, None).is_err());
        #[cfg(feature = "legacy-2024-11-05")]
        assert!(
            validate_destination(
                Some(&decision),
                TraceTransport::Http,
                Some(ProtocolEra::Legacy2024),
                None
            )
            .is_err()
        );

        let network_peer = TraceEndpoint::network(
            TraceTransport::WebSocket,
            "wss://peer.example/mcp",
            "tenant-a",
            "domain-a",
        )
        .unwrap();
        let network_decision = fastmcp_core::OutboundTracePolicy::new(20)
            .unwrap()
            .with_rule(
                fastmcp_core::TracePropagationRule::new(
                    decision.source().clone(),
                    network_peer.clone(),
                )
                .with_traceparent(),
            )
            .unwrap()
            .evaluate(
                decision.source(),
                &network_peer,
                decision.context(),
                "2026-07-28",
            );
        assert!(
            validate_destination(
                Some(&network_decision),
                TraceTransport::WebSocket,
                Some(ProtocolEra::Modern2026),
                None
            )
            .is_err()
        );
        assert!(
            validate_destination(
                Some(&network_decision),
                TraceTransport::WebSocket,
                Some(ProtocolEra::Modern2026),
                Some("wss://peer.example/upgraded")
            )
            .is_ok()
        );
    }
}
