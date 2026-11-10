//! Explicit, caller-owned resource update production for a managed gateway.
//!
//! Selectors come from already-admitted resource handlers. The provider opens
//! one bounded authenticated `subscriptions/listen` POST, validates its first
//! acknowledgement, and exposes any accepted-filter narrowing before relay.
//! Resource URIs retain their exact spelling on both legs. Upstream correlation
//! IDs, metadata, extra fields, catalog events and terminal controls never pass
//! through the sink. The server's notification publisher applies its own
//! downstream filters, authorization, queue bounds and subscription IDs.
//!
//! This is explicit service-account event production, not a transparent
//! per-downstream subscription proxy. The application selects and registers
//! the resources, owns the pump future, and cancels it with its server region.
//! No task, runtime, retry, reconnect, replay or legacy subscribe hook is added.
//! After any interruption the host must explicitly open a new subscription
//! and reconcile resource snapshots; a new ACK cannot recover missed updates.
//!
//! ```ignore
//! let mut selectors = Vec::new();
//! for resource in provider.resources(cx).await? {
//!     selectors.push(resource.update_subscription());
//!     builder = builder.resource(resource);
//! }
//! let server = builder.build();
//! let publisher = server.subscription_publisher();
//! let updates = provider.open_resource_updates(
//!     cx, &cancellation, &selectors, ManagedSubscriptionLimits::default(),
//! ).await?;
//! // Inspect updates.accepted_resources() before starting the pump.
//! // Run the listener and this future in the application's owning region.
//! let pump = updates.relay(cx, |event| publisher.publish(event));
//! ```

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use asupersync::Cx;
use fastmcp_client::http_auth::managed::OAuthSessionError;
use fastmcp_client::http_auth::managed::subscriptions::{
    ManagedSubscription, ManagedSubscriptionError, ManagedSubscriptionEvent,
    ManagedSubscriptionLimits,
};
use fastmcp_core::{McpError, McpRequestCancellation, McpResult};
use fastmcp_protocol::common_types::AbsoluteUri;
use fastmcp_protocol::{
    FinalResourceUpdatedNotificationParams, MAX_RESOURCE_SUBSCRIPTION_BYTES,
    MAX_RESOURCE_SUBSCRIPTIONS, ServerNotification, SubscriptionFilter,
};
use serde_json::json;

use super::{ManagedOAuthProvider, ManagedOAuthResource, check_cx, core_request};

/// One exact resource selected through a handler from this provider family.
///
/// No public constructor accepts an arbitrary URI or upstream identity.
/// Provider clones retain the same origin; independently constructed providers
/// do not, even when their resource URIs happen to match.
#[derive(Clone)]
pub struct ManagedOAuthResourceSelector {
    origin: Arc<AtomicU64>,
    uri: AbsoluteUri,
}

impl ManagedOAuthResourceSelector {
    pub(super) fn new(origin: Arc<AtomicU64>, uri: AbsoluteUri) -> Self {
        Self { origin, uri }
    }

    /// Byte-preserved upstream and published resource identity.
    #[must_use]
    pub fn uri(&self) -> &AbsoluteUri {
        &self.uri
    }
}

impl ManagedOAuthResource {
    /// Selects updates for this exact catalog resource, without I/O.
    /// Construct before moving the handler into the server builder.
    #[must_use]
    pub fn update_subscription(&self) -> ManagedOAuthResourceSelector {
        ManagedOAuthResourceSelector::new(
            Arc::clone(&self.forwarder.next_id),
            self.definition.uri.clone(),
        )
    }
}

impl ManagedOAuthProvider {
    /// Opens one bounded core subscription and awaits its admitted first ACK.
    ///
    /// All selectors must belong to this provider or one of its clones. Empty,
    /// duplicate, oversized and foreign-provider selections fail before token
    /// renewal or network I/O. Templates must select concrete, reversibly
    /// matched resource URIs, never template strings or wildcard filters.
    ///
    /// The managed owner retains the original credential generation, expiry,
    /// revocation, request cancellation and whole-listen deadline. Renewal of a
    /// sibling operation cannot extend this stream. Dropping the returned owner
    /// or its relay future closes its response without affecting siblings.
    pub async fn open_resource_updates(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        resources: &[ManagedOAuthResourceSelector],
        limits: ManagedSubscriptionLimits,
    ) -> McpResult<ManagedOAuthResourceUpdates> {
        check_cx(cx)?;
        let requested = resource_filter(&self.forwarder.next_id, resources)?;
        let request = core_request(
            "subscriptions/listen",
            json!({"notifications": requested}),
            None,
        )?;
        let mut upstream = self
            .session
            .subscribe_core_with_cancellation(
                cx,
                cancellation,
                request,
                self.forwarder.allocate_id()?,
                limits,
            )
            .await
            .map_err(subscription_error)?;
        let Some(ManagedSubscriptionEvent::Acknowledged { accepted_filter }) =
            upstream.next_event(cx).await.map_err(subscription_error)?
        else {
            return Err(unexpected_event());
        };
        // Native admission has already proved this is a subset of the exact
        // requested core filter. Retain the accepted set, never the broader
        // request, as the final resource gate immediately before publication.
        let accepted_resources = accepted_filter.resource_subscriptions.unwrap_or_default();
        Ok(ManagedOAuthResourceUpdates {
            upstream,
            accepted_resources,
        })
    }
}

fn resource_filter(
    origin: &Arc<AtomicU64>,
    resources: &[ManagedOAuthResourceSelector],
) -> McpResult<SubscriptionFilter> {
    if resources.is_empty() || resources.len() > MAX_RESOURCE_SUBSCRIPTIONS {
        return Err(invalid_selection());
    }
    let mut seen = HashSet::new();
    let mut bytes = 0usize;
    for resource in resources {
        bytes = bytes
            .checked_add(resource.uri.as_str().len())
            .filter(|bytes| *bytes <= MAX_RESOURCE_SUBSCRIPTION_BYTES)
            .ok_or_else(invalid_selection)?;
        if !Arc::ptr_eq(origin, &resource.origin) || !seen.insert(resource.uri.as_str()) {
            return Err(invalid_selection());
        }
    }
    let filter = SubscriptionFilter {
        resource_subscriptions: Some(
            resources
                .iter()
                .map(|resource| resource.uri.as_str().to_owned())
                .collect(),
        ),
        ..Default::default()
    };
    filter
        .validate_resource_subscriptions()
        .map_err(|_| invalid_selection())?;
    Ok(filter)
}

/// Acknowledged, independently owned authenticated resource updates.
///
/// Retaining an unpolled owner does not create a worker. Credential and
/// cancellation guards are checked on every read before an event is delivered;
/// the socket is released on a failed read, explicit close, or drop.
pub struct ManagedOAuthResourceUpdates {
    upstream: ManagedSubscription,
    accepted_resources: Vec<String>,
}

/// Which valid upstream terminal ended a relay. Neither outcome promises that
/// another subscription can resume without an event gap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedOAuthResourceRelayEnd {
    Complete,
    Cancelled,
}

/// Counts are local observations, not upstream replay cursors or acknowledgements.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedOAuthResourceRelayOutcome {
    pub end: ManagedOAuthResourceRelayEnd,
    pub forwarded_updates: usize,
    pub downstream_deliveries: usize,
}

impl ManagedOAuthResourceUpdates {
    /// Exact accepted URI set. It can be narrower than the requested set,
    /// including empty; the relay never widens it or silently resubscribes.
    #[must_use]
    pub fn accepted_resources(&self) -> &[String] {
        &self.accepted_resources
    }

    /// Session-local credential generation bound to this stream, not a token.
    #[must_use]
    pub fn credential_generation(&self) -> u64 {
        self.upstream.credential_generation()
    }

    /// Releases this response immediately without closing the shared login.
    pub fn close(&mut self) {
        self.upstream.close();
    }

    /// Pumps updates through the host's synchronous, bounded publication sink.
    ///
    /// Use a server's `subscription_publisher().publish` for downstream
    /// authorization, filter checks, ID retagging and per-listener backpressure.
    /// This future owns the upstream response: dropping it or returning a sink
    /// error closes the stream. The host must cancel the owning context or the
    /// supplied request-cancellation token when shutting down its application.
    ///
    /// Missing/truncated EOF, expiry, revocation, local cancellation and budget
    /// exhaustion are errors. Only a validated upstream terminal yields an
    /// outcome. Upstream cancellation is reported separately from completion;
    /// neither terminal is broadcast onto unrelated downstream listens.
    pub async fn relay(
        mut self,
        cx: &Cx,
        mut publish: impl FnMut(ServerNotification) -> McpResult<usize>,
    ) -> McpResult<ManagedOAuthResourceRelayOutcome> {
        let mut forwarded_updates = 0usize;
        let mut downstream_deliveries = 0usize;
        loop {
            let event = self
                .upstream
                .next_event(cx)
                .await
                .map_err(subscription_error)?;
            let end = match event {
                Some(ManagedSubscriptionEvent::Notification(notification)) => {
                    let notification = resource_update(*notification, &self.accepted_resources)?;
                    let delivered = publish(notification)?;
                    forwarded_updates += 1;
                    downstream_deliveries = downstream_deliveries
                        .checked_add(delivered)
                        .ok_or_else(|| {
                            McpError::internal_error("Resource relay delivery count overflow")
                        })?;
                    continue;
                }
                Some(ManagedSubscriptionEvent::Terminal { .. }) => {
                    ManagedOAuthResourceRelayEnd::Complete
                }
                Some(ManagedSubscriptionEvent::Cancelled { .. }) => {
                    ManagedOAuthResourceRelayEnd::Cancelled
                }
                // A second ACK, Tasks event, or EOF without an observed terminal
                // cannot be interpreted as successful resource relay.
                _ => return Err(unexpected_event()),
            };
            return Ok(ManagedOAuthResourceRelayOutcome {
                end,
                forwarded_updates,
                downstream_deliveries,
            });
        }
    }
}

fn resource_update(
    notification: ServerNotification,
    accepted: &[String],
) -> McpResult<ServerNotification> {
    let ServerNotification::ResourceUpdated(params) = notification else {
        return Err(unexpected_event());
    };
    if !accepted.iter().any(|uri| uri == params.uri.as_str()) {
        return Err(unexpected_event());
    }
    Ok(ServerNotification::ResourceUpdated(
        FinalResourceUpdatedNotificationParams {
            uri: params.uri,
            meta: None,
            additional: BTreeMap::new(),
        },
    ))
}

fn invalid_selection() -> McpError {
    McpError::invalid_params("Invalid managed OAuth resource subscription selection")
}

fn unexpected_event() -> McpError {
    McpError::invalid_request(
        "Authenticated upstream resource subscription returned an unsupported event",
    )
}

fn subscription_error(error: ManagedSubscriptionError) -> McpError {
    if matches!(
        error,
        ManagedSubscriptionError::Session(OAuthSessionError::Cancelled)
    ) {
        McpError::request_cancelled()
    } else {
        // ManagedSubscriptionError deliberately redacts peer bodies, filter
        // identities, correlation IDs and authorization material.
        McpError::invalid_request(format!(
            "Authenticated upstream resource subscription failed: {error}"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_protocol::{FINAL_SUBSCRIPTION_ID_META_KEY, RequestId};
    use std::sync::Mutex;

    fn selector(origin: &Arc<AtomicU64>, uri: &str) -> ManagedOAuthResourceSelector {
        ManagedOAuthResourceSelector::new(Arc::clone(origin), AbsoluteUri::parse(uri).unwrap())
    }

    fn update(uri: &str) -> ServerNotification {
        ServerNotification::ResourceUpdated(FinalResourceUpdatedNotificationParams {
            uri: AbsoluteUri::parse(uri).unwrap(),
            meta: None,
            additional: BTreeMap::new(),
        })
    }

    #[test]
    fn resource_selection_is_bounded_exact_and_provider_owned() {
        let owner = Arc::new(AtomicU64::new(1));
        let resource = selector(&owner, "report://monthly/a%2Fb");
        let accepted = resource_filter(&owner, std::slice::from_ref(&resource)).unwrap();
        assert_eq!(
            accepted.resource_subscriptions,
            Some(vec!["report://monthly/a%2Fb".to_owned()])
        );
        assert!(
            resource_filter(
                &Arc::new(AtomicU64::new(1)),
                std::slice::from_ref(&resource)
            )
            .is_err()
        );
        assert!(resource_filter(&owner, &[]).is_err());
        assert!(resource_filter(&owner, &[resource.clone(), resource]).is_err());

        let maximum: Vec<_> = (0..MAX_RESOURCE_SUBSCRIPTIONS)
            .map(|index| selector(&owner, &format!("report://monthly/{index}")))
            .collect();
        assert!(resource_filter(&owner, &maximum).is_ok());
        let mut excessive = maximum;
        excessive.push(selector(&owner, "report://monthly/excess"));
        assert!(resource_filter(&owner, &excessive).is_err());
        let bytes: Vec<_> = (0..20)
            .map(|index| {
                selector(
                    &owner,
                    &format!("report://monthly/{index}/{}", "a".repeat(15_000)),
                )
            })
            .collect();
        assert!(resource_filter(&owner, &bytes).is_err());
        assert_eq!(owner.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[test]
    fn relay_strips_upstream_authority_and_rechecks_the_accepted_uri() {
        let accepted = vec!["report://monthly/a%2Fb".to_owned()];
        let mut incoming = update(&accepted[0]);
        if let ServerNotification::ResourceUpdated(params) = &mut incoming {
            params.meta = Some(
                serde_json::from_value(json!({
                    FINAL_SUBSCRIPTION_ID_META_KEY: "upstream-private-id",
                    "com.example/private": "upstream-private-metadata"
                }))
                .unwrap(),
            );
            params
                .additional
                .insert("private".to_owned(), json!("not forwarded"));
        }
        let ServerNotification::ResourceUpdated(forwarded) =
            resource_update(incoming, &accepted).unwrap()
        else {
            panic!("only a resource update may be forwarded");
        };
        assert_eq!(forwarded.uri.as_str(), accepted[0]);
        assert!(forwarded.meta.is_none());
        assert!(forwarded.additional.is_empty());
        assert!(resource_update(update("report://monthly/a/b"), &accepted).is_err());
        assert!(resource_update(update(&accepted[0]), &[]).is_err());
        assert!(resource_update(ServerNotification::ToolsListChanged(None), &accepted).is_err());
    }

    #[test]
    fn weak_publisher_filters_retags_and_cannot_outlive_the_server() {
        let server = crate::Server::new("resource-updates", "1").build();
        let publisher = server.subscription_publisher();
        let events = Arc::new(Mutex::new(Vec::new()));
        let delivered = Arc::clone(&events);
        let selected = server
            .open_subscription_listen(
                RequestId::String("downstream-id".to_owned()),
                SubscriptionFilter {
                    resource_subscriptions: Some(vec!["report://monthly/a".to_owned()]),
                    ..Default::default()
                },
                Arc::new(move |event| delivered.lock().unwrap().push(event)),
            )
            .unwrap();
        let unrelated = server
            .open_subscription_listen(
                RequestId::Number(2),
                SubscriptionFilter {
                    resource_subscriptions: Some(vec!["report://monthly/b".to_owned()]),
                    ..Default::default()
                },
                Arc::new(|event| {
                    assert_eq!(event.method, "notifications/subscriptions/acknowledged")
                }),
            )
            .unwrap();
        assert!(!publisher.is_closed());
        assert_eq!(publisher.publish(update("report://monthly/a")).unwrap(), 1);
        let observed = events.lock().unwrap();
        assert_eq!(observed.len(), 2);
        assert_eq!(
            observed[1].params.as_ref().unwrap()["_meta"][FINAL_SUBSCRIPTION_ID_META_KEY],
            "downstream-id"
        );
        drop(observed);
        drop(server);
        // Both registration handles still retain the registry. They must not
        // revive a producer whose server has been discarded.
        assert!(publisher.is_closed());
        assert!(publisher.publish(update("report://monthly/a")).is_err());
        drop((selected, unrelated));

        let server = crate::Server::new("terminated-updates", "1").build();
        let publisher = server.subscription_publisher();
        assert_eq!(server.terminate_subscription_streams(), 0);
        assert!(publisher.is_closed());
        assert!(publisher.publish(update("report://monthly/a")).is_err());
    }
}
