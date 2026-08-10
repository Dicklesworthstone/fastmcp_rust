//! Final-only `ui://` resources for negotiated MCP Apps Views.
//!
//! The provider deliberately registers through the exact-final resource path.
//! A `ui://` document is meaningful only to a negotiated modern Apps Host, so
//! it must never leak into MCP 2024-11-05 resource discovery or dispatch.

use std::fmt;

use fastmcp_core::{McpContext, McpResult};
use fastmcp_protocol::common_types::AbsoluteUri;
use fastmcp_protocol::{FinalResource, MCP_APPS_HTML_MIME_TYPE, Resource, ResourceContent};

use crate::ResourceHandler;

/// An immutable HTML document advertised as one final-only `ui://` resource.
#[derive(Clone, Debug)]
pub struct McpAppsUiResource {
    uri: AbsoluteUri,
    name: String,
    description: Option<String>,
    html: String,
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
        })
    }

    /// Adds an optional catalog description without changing the document body.
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
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
            meta: None,
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
}

/// Invalid final-only Apps resource configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpAppsUiResourceError {
    /// The catalog URI is not an authority-form MCP Apps `ui://` URI.
    UriMustUseUiPrefix,
    /// A resource needs a stable non-empty catalog name.
    EmptyName,
}

impl fmt::Display for McpAppsUiResourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UriMustUseUiPrefix => {
                formatter.write_str("MCP Apps UI resource URI must start with ui://")
            }
            Self::EmptyName => formatter.write_str("MCP Apps UI resource name must not be empty"),
        }
    }
}

impl std::error::Error for McpAppsUiResourceError {}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use fastmcp_core::{Cx, McpContext, McpErrorCode, SessionState};
    use fastmcp_protocol::ReadResourceParams;
    use fastmcp_protocol::common_types::AbsoluteUri;

    use super::*;
    use crate::{DuplicateBehavior, Router};

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
            .add_final_resource_with_behavior(resource, DuplicateBehavior::Error)
            .expect("final-only UI resource registers");

        let state = SessionState::new();
        let context = McpContext::with_state(Cx::for_testing(), 2, state.clone());
        let error = router
            .handle_resources_read(
                &context,
                &ReadResourceParams {
                    uri: "ui://weather/dashboard".to_owned(),
                    meta: None,
                },
                state,
                None,
                None,
            )
            .expect_err("final-only Apps documents are not exact-2024 resources");

        assert_eq!(error.code, McpErrorCode::ResourceNotFound);
        assert_eq!(
            reads.load(Ordering::SeqCst),
            0,
            "exact 2024 rejection must not invoke the Apps document reader"
        );
    }
}
