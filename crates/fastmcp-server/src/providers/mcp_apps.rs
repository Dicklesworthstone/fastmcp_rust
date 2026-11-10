//! Final-only `ui://` resources for negotiated MCP Apps Views.
//!
//! The provider deliberately registers through the exact-final resource path.
//! A `ui://` document is meaningful only to a negotiated modern Apps Host, so
//! it must never leak into MCP 2024-11-05 resource discovery or dispatch.

use std::collections::BTreeMap;
use std::fmt;

use fastmcp_core::{McpContext, McpError, McpResult};
use fastmcp_protocol::common_types::{AbsoluteUri, EmbeddedResourceContents};
use fastmcp_protocol::{
    CacheScope, CacheTtl, CompleteResult, FinalReadResourceResult, FinalResource,
    MCP_APPS_HTML_MIME_TYPE, McpAppsMetadataError, McpAppsResourceMetadata, Resource,
    ResourceContent, ResultMeta,
};

use crate::handler::DEFAULT_FINAL_RESOURCE_TTL_MS;
use crate::{FinalResourceReadCacheHintProvenance, ResourceHandler, UriParams};

/// An immutable HTML document advertised as one final-only `ui://` resource.
#[derive(Clone, Debug)]
pub struct McpAppsUiResource {
    uri: AbsoluteUri,
    name: String,
    description: Option<String>,
    html: String,
    apps_metadata: Option<McpAppsResourceMetadata>,
}

impl McpAppsUiResource {
    /// Creates an MCP Apps HTML document for an exact `ui://` resource URI.
    pub fn try_new(
        uri: AbsoluteUri,
        name: impl Into<String>,
        html: impl Into<String>,
    ) -> Result<Self, McpAppsUiResourceError> {
        if !uri.as_str().starts_with("ui://") {
            return Err(McpAppsUiResourceError::UriMustUseUiPrefix);
        }
        let name = name.into();
        if name.is_empty() {
            return Err(McpAppsUiResourceError::EmptyName);
        }
        Ok(Self {
            uri,
            name,
            description: None,
            html: html.into(),
            apps_metadata: None,
        })
    }

    /// Adds an optional catalog description without changing the document body.
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Adds typed final-only Apps rendering metadata for this View.
    ///
    /// The supplied CSP, sandbox permissions, and host view domain are
    /// validated before this resource can be registered. This metadata is
    /// never projected into exact MCP 2024-11-05 discovery or reads.
    pub fn with_apps_metadata(
        mut self,
        metadata: McpAppsResourceMetadata,
    ) -> Result<Self, McpAppsUiResourceError> {
        let metadata = validated_apps_metadata(metadata)?;
        metadata.to_open_metadata().map_err(|_| {
            McpAppsUiResourceError::InvalidMetadata(McpAppsMetadataError::InvalidResourceMetadata)
        })?;
        self.apps_metadata = Some(metadata);
        Ok(self)
    }

    /// Returns the exact final catalog entry published for this document.
    #[must_use]
    pub fn final_catalog_entry(&self) -> FinalResource {
        FinalResource {
            uri: self.uri.clone(),
            name: self.name.clone(),
            title: None,
            description: self.description.clone(),
            icons: None,
            mime_type: Some(MCP_APPS_HTML_MIME_TYPE.to_owned()),
            size: None,
            annotations: None,
            meta: self.apps_metadata.as_ref().map(|metadata| {
                metadata
                    .to_open_metadata()
                    .expect("validated MCP Apps resource metadata serializes")
            }),
        }
    }

    /// Returns the immutable Apps document URI.
    #[must_use]
    pub const fn uri(&self) -> &AbsoluteUri {
        &self.uri
    }
}

impl ResourceHandler for McpAppsUiResource {
    fn definition(&self) -> Resource {
        Resource {
            uri: self.uri.as_str().to_owned(),
            name: self.name.clone(),
            description: self.description.clone(),
            mime_type: Some(MCP_APPS_HTML_MIME_TYPE.to_owned()),
            icon: None,
            version: None,
            tags: Vec::new(),
        }
    }

    fn final_definition(&self) -> Option<FinalResource> {
        Some(self.final_catalog_entry())
    }

    fn read(&self, context: &McpContext) -> McpResult<Vec<ResourceContent>> {
        context.checkpoint()?;
        Ok(vec![ResourceContent {
            uri: self.uri.as_str().to_owned(),
            mime_type: Some(MCP_APPS_HTML_MIME_TYPE.to_owned()),
            text: Some(self.html.clone()),
            blob: None,
        }])
    }

    fn read_final(
        &self,
        context: &McpContext,
    ) -> McpResult<CompleteResult<FinalReadResourceResult>> {
        context.checkpoint()?;
        let meta = self
            .apps_metadata
            .as_ref()
            .map(McpAppsResourceMetadata::to_open_metadata)
            .transpose()
            .map_err(|_| {
                McpError::internal_error("MCP Apps resource metadata could not be encoded")
            })?;

        // A Host may load this URI without listing resources first. Keep the
        // validated presentation policy on the exact document it governs,
        // including the distinction between absent metadata and `ui: {}`.
        Ok(CompleteResult::new(
            FinalReadResourceResult {
                contents: vec![EmbeddedResourceContents::Text {
                    uri: self.uri.clone(),
                    text: self.html.clone(),
                    mime_type: Some(MCP_APPS_HTML_MIME_TYPE.to_owned()),
                    meta,
                    additional: BTreeMap::new(),
                }],
                ttl_ms: CacheTtl::milliseconds(DEFAULT_FINAL_RESOURCE_TTL_MS),
                cache_scope: CacheScope::Private,
            },
            ResultMeta::empty(),
        ))
    }

    fn read_final_with_uri(
        &self,
        context: &McpContext,
        _uri: &str,
        _params: &UriParams,
    ) -> McpResult<CompleteResult<FinalReadResourceResult>> {
        self.read_final(context)
    }

    fn final_resource_read_cache_hint_provenance(&self) -> FinalResourceReadCacheHintProvenance {
        // This provider adds document metadata, not an application cache
        // policy. Preserve the router policy used by its former bridge.
        FinalResourceReadCacheHintProvenance::RouterPolicy
    }
}

/// Invalid final-only Apps resource configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpAppsUiResourceError {
    /// The catalog URI is not an authority-form MCP Apps `ui://` URI.
    UriMustUseUiPrefix,
    /// A resource needs a stable non-empty catalog name.
    EmptyName,
    /// Typed Apps rendering metadata did not satisfy its closed validation rules.
    InvalidMetadata(McpAppsMetadataError),
}

impl fmt::Display for McpAppsUiResourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UriMustUseUiPrefix => {
                formatter.write_str("MCP Apps UI resource URI must start with ui://")
            }
            Self::EmptyName => formatter.write_str("MCP Apps UI resource name must not be empty"),
            Self::InvalidMetadata(error) => {
                write!(formatter, "MCP Apps UI resource metadata: {error}")
            }
        }
    }
}

impl std::error::Error for McpAppsUiResourceError {}

fn validated_apps_metadata(
    metadata: McpAppsResourceMetadata,
) -> Result<McpAppsResourceMetadata, McpAppsUiResourceError> {
    McpAppsResourceMetadata::try_new(
        metadata.csp,
        metadata.permissions,
        metadata.domain,
        metadata.prefers_border,
    )
    .map_err(McpAppsUiResourceError::InvalidMetadata)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use fastmcp_core::{Cx, McpContext, McpErrorCode, SessionState};
    use fastmcp_protocol::common_types::AbsoluteUri;
    use fastmcp_protocol::{
        JsonRpcRequest, McpAppsResourceCsp, McpAppsResourceMetadata, McpAppsResourcePermission,
        McpAppsResourcePermissions, ReadResourceParams,
    };
    use serde_json::{Value, json};

    use super::*;
    use crate::{
        DuplicateBehavior, InboundRequestContext, InboundRequestTransport, Router, Server,
    };

    fn apps_request_meta() -> Value {
        json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {
                "extensions": {
                    "io.modelcontextprotocol/ui": {
                        "mimeTypes": [MCP_APPS_HTML_MIME_TYPE]
                    }
                }
            }
        })
    }

    async fn dispatch_apps_request(
        server: &Server,
        cx: &Cx,
        method: &str,
        params: Value,
        id: u64,
    ) -> Value {
        let response = server
            .dispatch_stateless(
                &InboundRequestContext::new(cx.clone(), id, InboundRequestTransport::Memory),
                &JsonRpcRequest::new(method, Some(params), i64::try_from(id).unwrap()),
            )
            .await
            .expect("Apps request has a response");
        assert!(
            response.error.is_none(),
            "Apps dispatch: {:?}",
            response.error
        );
        response.result.expect("Apps request has a result")
    }

    #[test]
    fn ui_resource_publishes_the_exact_html_catalog_shape_and_body() {
        let resource = McpAppsUiResource::try_new(
            AbsoluteUri::parse("ui://weather/dashboard").expect("valid ui URI"),
            "weather-dashboard",
            "<main>weather</main>",
        )
        .expect("ui resource configuration is valid")
        .with_description("Current weather");

        let catalog = resource.final_catalog_entry();
        assert_eq!(catalog.uri.as_str(), "ui://weather/dashboard");
        assert_eq!(catalog.mime_type.as_deref(), Some(MCP_APPS_HTML_MIME_TYPE));

        let context = McpContext::new(Cx::for_testing(), 1);
        let contents = resource.read(&context).expect("fixed UI document reads");
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0].text.as_deref(), Some("<main>weather</main>"));
        assert_eq!(
            contents[0].mime_type.as_deref(),
            Some(MCP_APPS_HTML_MIME_TYPE)
        );
    }

    #[test]
    fn changing_only_the_ui_authority_delimiter_rejects_an_opaque_ui_uri() {
        assert!(matches!(
            McpAppsUiResource::try_new(
                AbsoluteUri::parse("ui:opaque").expect("valid opaque ui URI"),
                "weather-dashboard",
                "<main>weather</main>",
            ),
            Err(McpAppsUiResourceError::UriMustUseUiPrefix)
        ));
    }

    #[test]
    fn ui_resource_publishes_typed_apps_csp_permissions_and_domain_metadata() {
        let metadata = McpAppsResourceMetadata::try_new(
            Some(
                McpAppsResourceCsp::try_new(
                    Some(vec!["https://api.weather.example".to_owned()]),
                    None,
                    None,
                    None,
                )
                .expect("bounded CSP is valid"),
            ),
            Some(McpAppsResourcePermissions {
                geolocation: Some(McpAppsResourcePermission::default()),
                ..McpAppsResourcePermissions::default()
            }),
            Some("weather-view.host.example".to_owned()),
            Some(true),
        )
        .expect("typed Apps metadata is valid");
        let resource = McpAppsUiResource::try_new(
            AbsoluteUri::parse("ui://weather/dashboard").expect("valid ui URI"),
            "weather-dashboard",
            "<main>weather</main>",
        )
        .expect("ui resource configuration is valid")
        .with_apps_metadata(metadata)
        .expect("typed Apps metadata is accepted");

        let metadata = resource
            .final_catalog_entry()
            .mcp_apps_metadata()
            .expect("published metadata remains closed and typed")
            .expect("Apps resource publishes its presentation metadata");
        assert_eq!(
            metadata.domain.as_deref(),
            Some("weather-view.host.example")
        );
        assert_eq!(metadata.prefers_border, Some(true));
        assert!(
            metadata
                .permissions
                .as_ref()
                .and_then(|permissions| permissions.geolocation.as_ref())
                .is_some()
        );
        assert_eq!(
            metadata
                .csp
                .as_ref()
                .and_then(|csp| csp.connect_domains.as_deref()),
            Some(["https://api.weather.example".to_owned()].as_slice())
        );
    }

    #[test]
    fn public_apps_read_preserves_catalog_policy_without_a_prior_list() {
        let ((), report) = asupersync::lab::run_async_under_lab(0xa9_01, |cx| async move {
            let metadata = McpAppsResourceMetadata::try_new(
                Some(
                    McpAppsResourceCsp::try_new(
                        Some(vec!["https://api.weather.example".to_owned()]),
                        Some(vec!["https://cdn.weather.example".to_owned()]),
                        Some(vec!["https://maps.weather.example".to_owned()]),
                        Some(vec!["https://weather.example".to_owned()]),
                    )
                    .expect("bounded CSP is valid"),
                ),
                Some(McpAppsResourcePermissions {
                    camera: Some(McpAppsResourcePermission::default()),
                    microphone: Some(McpAppsResourcePermission::default()),
                    geolocation: Some(McpAppsResourcePermission::default()),
                    clipboard_write: Some(McpAppsResourcePermission::default()),
                }),
                Some("weather-view.host.example".to_owned()),
                Some(false),
            )
            .expect("typed Apps metadata is valid");
            let resource = McpAppsUiResource::try_new(
                AbsoluteUri::parse("ui://weather/dashboard").unwrap(),
                "weather-dashboard",
                "<!doctype html>\n<main data-units=\"°C\">weather &amp; maps</main>\n",
            )
            .unwrap()
            .with_apps_metadata(metadata)
            .unwrap();
            let server = Server::new("apps-resource-policy", "1.0")
                .mcp_apps()
                .unwrap()
                .mcp_apps_ui_resource(resource)
                .unwrap()
                .build();

            // A tool can link to this document before the Host lists resources.
            let read = dispatch_apps_request(
                &server,
                &cx,
                "resources/read",
                json!({"uri": "ui://weather/dashboard", "_meta": apps_request_meta()}),
                1,
            )
            .await;
            let expected_meta = json!({
                "ui": {
                    "csp": {
                        "connectDomains": ["https://api.weather.example"],
                        "resourceDomains": ["https://cdn.weather.example"],
                        "frameDomains": ["https://maps.weather.example"],
                        "baseUriDomains": ["https://weather.example"]
                    },
                    "permissions": {
                        "camera": {}, "microphone": {}, "geolocation": {}, "clipboardWrite": {}
                    },
                    "domain": "weather-view.host.example",
                    "prefersBorder": false
                }
            });
            assert_eq!(read["resultType"], "complete");
            assert_eq!(
                read["contents"],
                json!([{
                    "uri": "ui://weather/dashboard",
                    "mimeType": "text/html;profile=mcp-app",
                    "text": "<!doctype html>\n<main data-units=\"°C\">weather &amp; maps</main>\n",
                    "_meta": expected_meta
                }]),
                "one exact document must carry its own typed policy and unchanged HTML"
            );
            assert_eq!(read["ttlMs"], DEFAULT_FINAL_RESOURCE_TTL_MS);
            assert_eq!(read["cacheScope"], "private");

            let list = dispatch_apps_request(
                &server,
                &cx,
                "resources/list",
                json!({"_meta": apps_request_meta()}),
                2,
            )
            .await;
            assert_eq!(list["resources"].as_array().unwrap().len(), 1);
            assert_eq!(list["resources"][0]["_meta"], expected_meta);
            assert_eq!(read["contents"][0]["_meta"], list["resources"][0]["_meta"]);
        });
        assert!(report.lab_test_passed(), "Apps resource policy: {report:?}");
    }

    #[test]
    fn public_apps_read_distinguishes_absent_and_present_empty_metadata() {
        for present in [false, true] {
            let ((), report) =
                asupersync::lab::run_async_under_lab(0xa9_02, move |cx| async move {
                    let resource = McpAppsUiResource::try_new(
                        AbsoluteUri::parse("ui://weather/dashboard").unwrap(),
                        "weather-dashboard",
                        "<main>weather</main>",
                    )
                    .unwrap();
                    let resource = if present {
                        resource
                            .with_apps_metadata(McpAppsResourceMetadata::default())
                            .unwrap()
                    } else {
                        resource
                    };
                    let direct = resource
                        .read_final_with_uri(
                            &McpContext::new(cx.clone(), 1),
                            "ui://weather/dashboard",
                            &UriParams::new(),
                        )
                        .unwrap();
                    let server = Server::new("apps-resource-presence", "1.0")
                        .mcp_apps()
                        .unwrap()
                        .mcp_apps_ui_resource(resource)
                        .unwrap()
                        .build();
                    let read = dispatch_apps_request(
                        &server,
                        &cx,
                        "resources/read",
                        json!({"uri": "ui://weather/dashboard", "_meta": apps_request_meta()}),
                        2,
                    )
                    .await;
                    assert_eq!(read["contents"].as_array().unwrap().len(), 1);
                    assert_eq!(read["contents"][0]["text"], "<main>weather</main>");
                    assert_eq!(
                        read["contents"],
                        serde_json::to_value(direct.payload.contents).unwrap(),
                        "the URI-aware final hook preserves the same metadata presence"
                    );
                    if present {
                        assert_eq!(read["contents"][0]["_meta"], json!({"ui": {}}));
                    } else {
                        assert!(
                            read["contents"][0].get("_meta").is_none(),
                            "absence must not synthesize a UI policy or permission markers"
                        );
                    }
                });
            assert!(
                report.lab_test_passed(),
                "Apps metadata presence: {report:?}"
            );
        }
    }

    #[test]
    fn apps_read_metadata_preserves_configured_router_cache_policy() {
        let ((), report) = asupersync::lab::run_async_under_lab(0xa9_03, |cx| async move {
            let resource = McpAppsUiResource::try_new(
                AbsoluteUri::parse("ui://weather/dashboard").unwrap(),
                "weather-dashboard",
                "<main>weather</main>",
            )
            .unwrap()
            .with_apps_metadata(McpAppsResourceMetadata::new(Some(true)))
            .unwrap();
            let mut router = Server::new("apps-resource-cache", "1.0")
                .mcp_apps()
                .unwrap()
                .mcp_apps_ui_resource(resource)
                .unwrap()
                .build()
                .into_router();
            router.set_final_cache_hint_policy(
                CacheTtl::milliseconds(17),
                CacheTtl::milliseconds(23),
                CacheScope::Public,
            );
            let read = router
                .dispatch_stateless(
                    &McpContext::new(cx, 1),
                    &JsonRpcRequest::new(
                        "resources/read",
                        Some(json!({
                            "uri": "ui://weather/dashboard", "_meta": apps_request_meta()
                        })),
                        1_i64,
                    ),
                )
                .await
                .expect("Apps resource reads through configured router");
            assert_eq!(read["ttlMs"], 23);
            assert_eq!(read["cacheScope"], "public");
            assert_eq!(
                read["contents"][0]["_meta"],
                json!({"ui": {"prefersBorder": true}})
            );
        });
        assert!(
            report.lab_test_passed(),
            "Apps resource cache policy: {report:?}"
        );
    }

    #[test]
    fn changing_only_the_apps_domain_to_empty_rejects_metadata_without_catalog_mutation() {
        let accepted = McpAppsResourceMetadata::try_new(
            None,
            None,
            Some("weather-view.host.example".to_owned()),
            None,
        )
        .expect("non-empty domain is valid");
        let planted = McpAppsResourceMetadata {
            domain: Some(String::new()),
            ..accepted.clone()
        };
        let resource = McpAppsUiResource::try_new(
            AbsoluteUri::parse("ui://weather/dashboard").expect("valid ui URI"),
            "weather-dashboard",
            "<main>weather</main>",
        )
        .expect("ui resource configuration is valid");
        let catalog_before = resource.final_catalog_entry();

        assert_eq!(
            resource
                .clone()
                .with_apps_metadata(planted)
                .expect_err("only an empty domain makes the typed metadata invalid"),
            McpAppsUiResourceError::InvalidMetadata(McpAppsMetadataError::InvalidDomain)
        );
        assert_eq!(
            resource.final_catalog_entry().meta,
            catalog_before.meta,
            "rejected metadata cannot alter the published final catalog entry"
        );
        let read = resource
            .read_final(&McpContext::new(Cx::for_testing(), 1))
            .expect("original document remains readable");
        let wire = serde_json::to_value(read.payload.contents).unwrap();
        assert!(
            wire[0].get("_meta").is_none(),
            "rejected metadata cannot enter the matching resource content"
        );
    }

    struct CountingUiResource {
        inner: McpAppsUiResource,
        reads: Arc<AtomicUsize>,
    }

    impl ResourceHandler for CountingUiResource {
        fn definition(&self) -> Resource {
            self.inner.definition()
        }

        fn final_definition(&self) -> Option<FinalResource> {
            self.inner.final_definition()
        }

        fn read(&self, context: &McpContext) -> McpResult<Vec<ResourceContent>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.inner.read(context)
        }

        fn read_final(
            &self,
            context: &McpContext,
        ) -> McpResult<CompleteResult<FinalReadResourceResult>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.inner.read_final(context)
        }
    }

    #[test]
    fn final_only_ui_resource_has_exact_2024_zero_read_invocation() {
        let reads = Arc::new(AtomicUsize::new(0));
        let resource = CountingUiResource {
            inner: McpAppsUiResource::try_new(
                AbsoluteUri::parse("ui://weather/dashboard").expect("valid ui URI"),
                "weather-dashboard",
                "<main>weather</main>",
            )
            .expect("ui resource configuration is valid"),
            reads: Arc::clone(&reads),
        };
        let mut router = Router::new();
        router
            .add_mcp_apps_ui_resource_with_behavior(resource, DuplicateBehavior::Error)
            .expect("final-only UI resource registers");

        let state = SessionState::new();
        let context = McpContext::with_state(Cx::for_testing(), 2, state.clone());
        let error = fastmcp_core::block_on(router.handle_resources_read(
            &context,
            &ReadResourceParams {
                uri: "ui://weather/dashboard".to_owned(),
                meta: None,
            },
            state,
            None,
            None,
        ))
        .expect_err("final-only Apps documents are not exact-2024 resources");

        assert_eq!(error.code, McpErrorCode::ResourceNotFound);
        assert_eq!(
            reads.load(Ordering::SeqCst),
            0,
            "exact 2024 rejection must not invoke the Apps document reader"
        );
    }
}
