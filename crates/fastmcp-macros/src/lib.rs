//! Procedural macros for FastMCP.
//!
//! This crate provides attribute macros for defining MCP handlers:
//! - `#[tool]` - Define a tool handler
//! - `#[resource]` - Define a resource handler
//! - `#[prompt]` - Define a prompt handler
//!
//! MCP 2026-07-28 support is under implementation and remains unverified. The
//! public protocol constant is still `2024-11-05`, and macro source presence
//! is not aggregate conformance or release evidence. Async handler forms await
//! the caller-owned request future directly and do not create or re-enter a
//! runtime. Their synchronous trait entry points report explicit misuse.
//!
//! # Example
//!
//! ```ignore
//! use fastmcp_rust::prelude::*;
//!
//! /// Greets a user by name.
//! #[tool]
//! async fn greet(
//!     ctx: &McpContext,
//!     /// The name to greet
//!     name: String,
//! ) -> McpResult<String> {
//!     ctx.checkpoint()?;
//!     Ok(format!("Hello, {name}!"))
//! }
//!
//! /// A configuration file resource.
//! #[resource(uri = "config://app")]
//! fn app_config(ctx: &McpContext) -> McpResult<String> {
//!     ctx.checkpoint()?;
//!     std::fs::read_to_string("config.json")
//!         .map_err(|error| McpError::internal_error(error.to_string()))
//! }
//!
//! /// A code review prompt.
//! #[prompt]
//! async fn code_review(
//!     ctx: &McpContext,
//!     /// The code to review
//!     code: String,
//! ) -> McpResult<Vec<PromptMessage>> {
//!     ctx.checkpoint()?;
//!     Ok(vec![PromptMessage {
//!         role: Role::User,
//!         content: Content::Text { text: format!("Review this code:\n\n{code}") },
//!     }])
//! }
//! ```
//!
//! # Role in the System
//!
//! `fastmcp-derive` is the **ergonomics layer** of FastMCP. The attribute
//! macros expand handler functions into the trait implementations used by
//! `fastmcp-server`, and they also generate JSON Schema metadata consumed by
//! `fastmcp-protocol` during tool registration.
//!
//! Most users never need to depend on this crate directly; it is re-exported
//! by the `fastmcp-rust` façade for `use fastmcp_rust::prelude::*`.

#![forbid(unsafe_code)]

use std::collections::HashMap;

use proc_macro::TokenStream;
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{format_ident, quote};
use syn::spanned::Spanned as _;
use syn::{
    Attribute, FnArg, Ident, ItemFn, Lit, LitStr, Meta, Pat, Token, Type, parse::Parse,
    parse::ParseStream, parse_macro_input,
};

/// Crate paths used by handler macro expansions.
///
/// When the consumer depends on the `fastmcp-rust` facade, every generated
/// path goes through its private re-export namespace. Otherwise, direct
/// `fastmcp-derive` consumers retain the narrower subcrate arrangement used by
/// this workspace. Both routes honor Cargo dependency renames.
struct HandlerCratePaths {
    core: TokenStream2,
    protocol: TokenStream2,
    server: TokenStream2,
}

struct ToolCratePaths {
    handler: HandlerCratePaths,
    serde_json: TokenStream2,
}

fn found_crate_path(found: FoundCrate, package: &str) -> TokenStream2 {
    match found {
        FoundCrate::Itself if package == "fastmcp-rust" => quote!(::fastmcp_rust),
        FoundCrate::Itself => quote!(crate),
        FoundCrate::Name(name) => {
            let ident = Ident::new(&name.replace('-', "_"), Span::call_site());
            quote!(::#ident)
        }
    }
}

fn direct_crate_path(package: &str) -> syn::Result<TokenStream2> {
    crate_name(package)
        .map(|found| found_crate_path(found, package))
        .map_err(|error| {
            syn::Error::new(
                Span::call_site(),
                format!(
                    "FastMCP macro expansion requires either the `fastmcp-rust` facade or a direct `{package}` dependency: {error}"
                ),
            )
        })
}

fn handler_crate_paths() -> syn::Result<HandlerCratePaths> {
    if let Ok(found) = crate_name("fastmcp-rust") {
        let facade = found_crate_path(found, "fastmcp-rust");
        return Ok(HandlerCratePaths {
            core: quote!(#facade::__private::core),
            protocol: quote!(#facade::__private::protocol),
            server: quote!(#facade::__private::server),
        });
    }

    Ok(HandlerCratePaths {
        core: direct_crate_path("fastmcp-core")?,
        protocol: direct_crate_path("fastmcp-protocol")?,
        server: direct_crate_path("fastmcp-server")?,
    })
}

fn tool_crate_paths() -> syn::Result<ToolCratePaths> {
    Ok(ToolCratePaths {
        handler: handler_crate_paths()?,
        serde_json: serde_json_crate_path()?,
    })
}

fn serde_json_crate_path() -> syn::Result<TokenStream2> {
    if let Ok(found) = crate_name("fastmcp-rust") {
        let facade = found_crate_path(found, "fastmcp-rust");
        Ok(quote!(#facade::__private::serde_json))
    } else {
        direct_crate_path("serde_json")
    }
}

/// Extracts documentation from attributes.
fn extract_doc_comments(attrs: &[Attribute]) -> Option<String> {
    let docs: Vec<String> = attrs
        .iter()
        .filter_map(|attr| {
            if attr.path().is_ident("doc") {
                if let Meta::NameValue(nv) = &attr.meta {
                    if let syn::Expr::Lit(syn::ExprLit {
                        lit: Lit::Str(s), ..
                    }) = &nv.value
                    {
                        return Some(s.value().trim().to_string());
                    }
                }
            }
            None
        })
        .collect();

    if docs.is_empty() {
        None
    } else {
        Some(docs.join("\n"))
    }
}

/// Checks if a type is `&McpContext`.
fn is_mcp_context_ref(ty: &Type) -> bool {
    if let Type::Reference(type_ref) = ty {
        if let Type::Path(type_path) = type_ref.elem.as_ref() {
            return type_path
                .path
                .segments
                .last()
                .is_some_and(|s| s.ident == "McpContext");
        }
    }
    false
}

/// Checks whether a parameter is the macro's optional MRTR resume input.
///
/// A resumable handler runs once before the peer has supplied any embedded
/// input and again only after the router has validated a completed exchange.
/// `Option<&MrtrCompletedInputs>` expresses both states without exposing a
/// client-provided wire value to the user function.
fn is_mrtr_completed_inputs_option_ref(ty: &Type) -> bool {
    let Some(inner) = option_inner_type(ty) else {
        return false;
    };
    let Type::Reference(reference) = inner else {
        return false;
    };
    let Type::Path(type_path) = reference.elem.as_ref() else {
        return false;
    };
    type_path
        .path
        .segments
        .last()
        .is_some_and(|segment| segment.ident == "MrtrCompletedInputs")
}

/// Detects the completed-input type in a parameter even when it is not in
/// the required optional-reference form. This lets expansion reject the
/// near-identical non-optional form instead of treating it as an ordinary
/// tool, resource, or prompt argument.
fn contains_mrtr_completed_inputs(ty: &Type) -> bool {
    match ty {
        Type::Path(type_path) => type_path.path.segments.iter().any(|segment| {
            segment.ident == "MrtrCompletedInputs"
                || match &segment.arguments {
                    syn::PathArguments::AngleBracketed(arguments) => arguments
                        .args
                        .iter()
                        .filter_map(|argument| match argument {
                            syn::GenericArgument::Type(value) => Some(value),
                            _ => None,
                        })
                        .any(contains_mrtr_completed_inputs),
                    _ => false,
                }
        }),
        Type::Reference(reference) => contains_mrtr_completed_inputs(&reference.elem),
        Type::Group(group) => contains_mrtr_completed_inputs(&group.elem),
        Type::Paren(paren) => contains_mrtr_completed_inputs(&paren.elem),
        _ => false,
    }
}

fn invalid_mrtr_resume_parameter_error(ty: &Type) -> syn::Error {
    syn::Error::new_spanned(ty, "MRTR resume input must be Option<&MrtrCompletedInputs>")
}

/// Checks if a type is `Option<T>`.
fn is_option_type(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty {
        return type_path
            .path
            .segments
            .last()
            .is_some_and(|s| s.ident == "Option");
    }
    false
}

/// Returns the inner type if `ty` is `Option<T>`.
fn option_inner_type(ty: &Type) -> Option<&Type> {
    if let Type::Path(type_path) = ty {
        if let Some(segment) = type_path.path.segments.last() {
            if segment.ident == "Option" {
                if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                    if let Some(syn::GenericArgument::Type(inner_ty)) = args.args.first() {
                        return Some(inner_ty);
                    }
                }
            }
        }
    }
    None
}

/// Returns true if the type is `String`.
fn is_string_type(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty {
        return type_path
            .path
            .segments
            .last()
            .is_some_and(|s| s.ident == "String");
    }
    false
}

fn default_lit_expr_for_type(lit: &Lit, ty: &Type) -> syn::Result<TokenStream2> {
    if is_option_type(ty) {
        let inner = option_inner_type(ty).ok_or_else(|| {
            syn::Error::new(
                ty.span(),
                "Option<T> default requires a concrete inner type",
            )
        })?;
        let inner_expr = default_lit_expr_for_type(lit, inner)?;
        return Ok(quote! { Some(#inner_expr) });
    }

    if is_string_type(ty) {
        let Lit::Str(s) = lit else {
            return Err(syn::Error::new(
                lit.span(),
                "default for String must be a string literal",
            ));
        };
        return Ok(quote! { #s.to_string() });
    }

    Ok(quote! { #lit })
}

/// Parses a human-readable duration string and returns milliseconds.
///
/// Supports formats like "30s", "5m", "1h", "500ms", "1h30m".
fn parse_duration_to_millis(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty string".to_string());
    }

    let mut total_millis: u64 = 0;
    let mut current_num = String::new();
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c.is_ascii_digit() {
            current_num.push(c);
        } else if c.is_ascii_alphabetic() {
            if current_num.is_empty() {
                return Err(format!(
                    "unexpected unit character '{c}' without preceding number"
                ));
            }

            let num: u64 = current_num
                .parse()
                .map_err(|_| format!("invalid number: {current_num}"))?;

            // Check for multi-character units (ms)
            let unit = if c == 'm' && chars.peek() == Some(&'s') {
                chars.next(); // consume 's'
                "ms"
            } else {
                // Single character unit
                match c {
                    'h' => "h",
                    'm' => "m",
                    's' => "s",
                    _ => return Err(format!("unknown unit '{c}'")),
                }
            };

            let millis = match unit {
                "ms" => num,
                "s" => num
                    .checked_mul(1000)
                    .ok_or_else(|| format!("duration overflow for component: {num}s"))?,
                "m" => num
                    .checked_mul(60_000)
                    .ok_or_else(|| format!("duration overflow for component: {num}m"))?,
                "h" => num
                    .checked_mul(3_600_000)
                    .ok_or_else(|| format!("duration overflow for component: {num}h"))?,
                _ => unreachable!(),
            };

            total_millis = total_millis
                .checked_add(millis)
                .ok_or_else(|| "duration overflow".to_string())?;
            current_num.clear();
        } else if c.is_whitespace() {
            continue;
        } else {
            return Err(format!("unexpected character '{c}'"));
        }
    }

    if !current_num.is_empty() {
        return Err(format!(
            "number '{current_num}' missing unit (use s, m, h, or ms)"
        ));
    }

    if total_millis == 0 {
        return Err("duration must be greater than zero".to_string());
    }

    Ok(total_millis)
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod duration_parse_tests {
    use super::parse_duration_to_millis;

    #[test]
    fn parse_duration_compound_values() {
        assert_eq!(parse_duration_to_millis("1h30m"), Ok(5_400_000));
        assert_eq!(parse_duration_to_millis("500ms"), Ok(500));
    }

    #[test]
    fn parse_duration_component_overflow_returns_error() {
        let input = format!("{}s", u64::MAX);
        let err = parse_duration_to_millis(&input).expect_err("overflowing component must fail");
        assert!(err.contains("overflow"));
    }

    #[test]
    fn parse_duration_total_overflow_returns_error() {
        let input = format!("{}ms1ms", u64::MAX);
        let err = parse_duration_to_millis(&input).expect_err("overflowing total must fail");
        assert!(err.contains("overflow"));
    }

    // =========================================================================
    // Additional coverage tests (bd-1d2h)
    // =========================================================================

    #[test]
    fn parse_single_units() {
        assert_eq!(parse_duration_to_millis("30s"), Ok(30_000));
        assert_eq!(parse_duration_to_millis("5m"), Ok(300_000));
        assert_eq!(parse_duration_to_millis("2h"), Ok(7_200_000));
        assert_eq!(parse_duration_to_millis("100ms"), Ok(100));
    }

    #[test]
    fn parse_empty_and_whitespace() {
        assert!(parse_duration_to_millis("").is_err());
        assert!(parse_duration_to_millis("  ").is_err());
    }

    #[test]
    fn parse_missing_unit() {
        let err = parse_duration_to_millis("42").unwrap_err();
        assert!(err.contains("missing unit"));
    }

    #[test]
    fn parse_unit_without_number() {
        let err = parse_duration_to_millis("s").unwrap_err();
        assert!(err.contains("without preceding number"));
    }

    #[test]
    fn parse_unknown_unit() {
        let err = parse_duration_to_millis("10x").unwrap_err();
        assert!(err.contains("unknown unit"));
    }

    #[test]
    fn parse_unexpected_character() {
        let err = parse_duration_to_millis("10s$").unwrap_err();
        assert!(err.contains("unexpected character"));
    }

    #[test]
    fn parse_zero_duration() {
        let err = parse_duration_to_millis("0s").unwrap_err();
        assert!(err.contains("greater than zero"));
    }

    #[test]
    fn parse_whitespace_between_components() {
        assert_eq!(parse_duration_to_millis("1h 30m"), Ok(5_400_000));
    }

    #[test]
    fn parse_trimmed_input() {
        assert_eq!(parse_duration_to_millis("  10s  "), Ok(10_000));
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod helper_tests {
    use super::{extract_template_params, to_pascal_case};

    #[test]
    fn template_params_use_reversible_protocol_template() {
        let params = extract_template_params("mcp://resource{/collection}/manifest{?revision}")
            .expect("the protocol's reversible template subset parses");
        assert_eq!(params, vec!["collection", "revision"]);
    }

    #[test]
    fn template_params_flatten_every_variable_in_named_expression() {
        let params = extract_template_params("mcp://resource{?collection*,revision*}")
            .expect("the protocol's reversible multi-variable expression parses");
        assert_eq!(params, vec!["collection", "revision"]);
    }

    #[test]
    fn template_params_none() {
        let params =
            extract_template_params("static/path/no/params").expect("literal-only template parses");
        assert_eq!(params, [] as [String; 0]);
    }

    #[test]
    fn template_params_single() {
        let params =
            extract_template_params("config://{name}").expect("single parameter template parses");
        assert_eq!(params, vec!["name"]);
    }

    #[test]
    fn template_params_reject_one_lossy_prefix_via_protocol_template() {
        let accepted = "mcp://resource{/collection}/manifest{?revision}";
        let rejected = "mcp://resource{/collection:3}/manifest{?revision}";
        assert_eq!(
            extract_template_params(accepted).expect("unmodified template is reversible"),
            vec!["collection", "revision"]
        );
        let error = extract_template_params(rejected)
            .expect_err("changing only one variable to a lossy prefix is rejected");
        assert!(error.contains("URI template cannot be reverse matched"));
    }

    #[test]
    fn pascal_case_single_word() {
        assert_eq!(to_pascal_case("hello"), "Hello");
    }

    #[test]
    fn pascal_case_snake_case() {
        assert_eq!(to_pascal_case("my_tool_handler"), "MyToolHandler");
    }

    #[test]
    fn pascal_case_already_pascal() {
        assert_eq!(to_pascal_case("Hello"), "Hello");
    }

    #[test]
    fn pascal_case_empty() {
        assert_eq!(to_pascal_case(""), "");
    }

    #[test]
    fn pascal_case_leading_underscore() {
        // Leading underscore produces an empty first segment
        assert_eq!(to_pascal_case("_private"), "Private");
    }
}

/// Extracts reversible RFC 6570 variable names from a URI template string.
///
/// Resource macro admission intentionally shares the protocol parser and
/// reversible matcher compiler with Router registration. The macro needs Rust
/// argument names, not expression syntax, so it returns every variable from
/// each admitted reversible expression in source order.
fn extract_template_params(uri: &str) -> Result<Vec<String>, String> {
    let matcher = fastmcp_protocol::UriTemplate::parse(uri)
        .map_err(|error| format!("invalid RFC 6570 URI template: {error}"))?
        .compile_reversible()
        .map_err(|error| format!("URI template is not reversible: {error}"))?;

    Ok(matcher
        .template()
        .parts()
        .iter()
        .flat_map(|part| match part {
            fastmcp_protocol::UriTemplatePart::Literal(_) => Vec::new(),
            fastmcp_protocol::UriTemplatePart::Expression(expression) => expression
                .variables()
                .iter()
                .map(|variable| variable.name().to_owned())
                .collect(),
        })
        .collect())
}

/// Converts a snake_case identifier to PascalCase.
fn to_pascal_case(s: &str) -> String {
    s.split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

/// Represents different return type conversion strategies.
enum ReturnTypeKind {
    /// Returns a final CompleteResult<FinalCallToolResult> directly.
    FinalComplete,
    /// Returns Result<CompleteResult<FinalCallToolResult>, E>.
    ResultFinalComplete,
    /// Returns McpResult<CompleteResult<FinalCallToolResult>>.
    McpResultFinalComplete,
    /// Returns Vec<Content> directly
    VecContent,
    /// Returns String, wrap in Content::Text
    String,
    /// Returns Result<T, E> - need to unwrap and convert T
    ResultVecContent,
    /// Returns Result<String, E> - unwrap and wrap in Content::Text
    ResultString,
    /// Returns McpResult<Vec<Content>>
    McpResultVecContent,
    /// Returns McpResult<String>
    McpResultString,
    /// Unknown type - try to convert via Display or Debug
    Other,
    /// Unit type () - return empty content
    Unit,
}

/// Analyzes a function's return type and determines conversion strategy.
fn analyze_return_type(output: &syn::ReturnType) -> ReturnTypeKind {
    match final_complete_return_kind(output, "FinalCallToolResult") {
        Some(FinalCompleteReturnKind::Direct) => return ReturnTypeKind::FinalComplete,
        Some(FinalCompleteReturnKind::Result) => return ReturnTypeKind::ResultFinalComplete,
        Some(FinalCompleteReturnKind::McpResult) => {
            return ReturnTypeKind::McpResultFinalComplete;
        }
        None => {}
    }

    match output {
        syn::ReturnType::Default => ReturnTypeKind::Unit,
        syn::ReturnType::Type(_, ty) => analyze_type(ty),
    }
}

/// Analyzes a type and determines what kind of return it is.
fn analyze_type(ty: &Type) -> ReturnTypeKind {
    if let Type::Path(type_path) = ty {
        if let Some(segment) = type_path.path.segments.last() {
            let type_name = segment.ident.to_string();

            match type_name.as_str() {
                "String" => return ReturnTypeKind::String,
                "Vec" => {
                    // Check if it's Vec<Content>
                    if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                        if let Some(syn::GenericArgument::Type(Type::Path(inner_path))) =
                            args.args.first()
                        {
                            if inner_path
                                .path
                                .segments
                                .last()
                                .is_some_and(|s| s.ident == "Content")
                            {
                                return ReturnTypeKind::VecContent;
                            }
                        }
                    }
                }
                "Result" | "McpResult" => {
                    // Check the Ok type
                    if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                        if let Some(syn::GenericArgument::Type(inner_ty)) = args.args.first() {
                            let inner_kind = analyze_type(inner_ty);
                            return match inner_kind {
                                ReturnTypeKind::VecContent => {
                                    if type_name == "McpResult" {
                                        ReturnTypeKind::McpResultVecContent
                                    } else {
                                        ReturnTypeKind::ResultVecContent
                                    }
                                }
                                ReturnTypeKind::String => {
                                    if type_name == "McpResult" {
                                        ReturnTypeKind::McpResultString
                                    } else {
                                        ReturnTypeKind::ResultString
                                    }
                                }
                                _ => ReturnTypeKind::Other,
                            };
                        }
                    }
                }
                _ => {}
            }
        }
    }
    ReturnTypeKind::Other
}

/// Generates the exact final-to-legacy content projection available to the
/// current tool handler trait. Content annotations, metadata, resource links,
/// and the final tool-error bit cannot be represented by `Vec<Content>`, so
/// the conversion rejects them rather than silently weakening a final result.
fn generate_final_tool_payload_projection(value: TokenStream2) -> TokenStream2 {
    quote! {
        let final_result = #value;
        if final_result.is_error {
            Err(fastmcp_core::McpError::internal_error(
                "final tool result cannot be projected exactly through the legacy handler",
            ))
        } else {
            final_result
                .content
                .into_iter()
                .map(|content| {
                    let content_wire = serde_json::to_value(&content).map_err(|error| {
                        fastmcp_core::McpError::internal_error(format!(
                            "failed to inspect final tool content for exact legacy projection: {error}",
                        ))
                    })?;
                    let has_only_wire_fields = |value: &serde_json::Value, allowed: &[&str]| {
                        value
                            .as_object()
                            .is_some_and(|object| object.keys().all(|key| allowed.contains(&key.as_str())))
                    };
                    match content {
                        fastmcp_protocol::common_types::ContentBlock::Text {
                            text,
                            annotations: None,
                            meta: None,
                            ..
                        } if has_only_wire_fields(&content_wire, &["type", "text"]) => {
                            Ok(fastmcp_protocol::Content::Text { text })
                        }
                        fastmcp_protocol::common_types::ContentBlock::Image {
                            data,
                            mime_type,
                            annotations: None,
                            meta: None,
                            ..
                        } if has_only_wire_fields(&content_wire, &["type", "data", "mimeType"]) => {
                            Ok(fastmcp_protocol::Content::Image { data, mime_type })
                        }
                        fastmcp_protocol::common_types::ContentBlock::Audio {
                            data,
                            mime_type,
                            annotations: None,
                            meta: None,
                            ..
                        } if has_only_wire_fields(&content_wire, &["type", "data", "mimeType"]) => {
                            Ok(fastmcp_protocol::Content::Audio { data, mime_type })
                        }
                        fastmcp_protocol::common_types::ContentBlock::Resource {
                            resource,
                            annotations: None,
                            meta: None,
                            ..
                        } if has_only_wire_fields(&content_wire, &["type", "resource"]) => {
                            let resource_wire = serde_json::to_value(&resource).map_err(|error| {
                                fastmcp_core::McpError::internal_error(format!(
                                    "failed to inspect final embedded resource for exact legacy projection: {error}",
                                ))
                            })?;
                            let resource = match resource {
                                fastmcp_protocol::common_types::EmbeddedResourceContents::Text {
                                    uri,
                                    text,
                                    mime_type,
                                    ..
                                } if has_only_wire_fields(&resource_wire, &["uri", "text", "mimeType"]) => {
                                    Ok(fastmcp_protocol::ResourceContent {
                                        uri: uri.as_str().to_owned(),
                                        mime_type,
                                        text: Some(text),
                                        blob: None,
                                    })
                                }
                                fastmcp_protocol::common_types::EmbeddedResourceContents::Blob {
                                    uri,
                                    blob,
                                    mime_type,
                                    ..
                                } if has_only_wire_fields(&resource_wire, &["uri", "blob", "mimeType"]) => {
                                    Ok(fastmcp_protocol::ResourceContent {
                                        uri: uri.as_str().to_owned(),
                                        mime_type,
                                        text: None,
                                        blob: Some(blob),
                                    })
                                }
                                _ => Err(fastmcp_core::McpError::internal_error(
                                    "final embedded resource cannot be projected exactly through the legacy handler",
                                )),
                            }?;
                            Ok(fastmcp_protocol::Content::Resource { resource })
                        }
                        _ => Err(fastmcp_core::McpError::internal_error(
                            "final tool content cannot be projected exactly through the legacy handler",
                        )),
                    }
                })
                .collect()
        }
    }
}

/// Generates code to convert a function result to Vec<Content>.
fn generate_result_conversion(output: &syn::ReturnType) -> TokenStream2 {
    let kind = analyze_return_type(output);

    match kind {
        ReturnTypeKind::FinalComplete => {
            generate_final_tool_payload_projection(quote! { result.payload })
        }
        ReturnTypeKind::ResultFinalComplete => {
            let projection =
                generate_final_tool_payload_projection(quote! { result_value.payload });
            quote! {
                let result_value = result
                    .map_err(|error| fastmcp_core::McpError::internal_error(error.to_string()))?;
                #projection
            }
        }
        ReturnTypeKind::McpResultFinalComplete => {
            let projection =
                generate_final_tool_payload_projection(quote! { result_value.payload });
            quote! {
                let result_value = result?;
                #projection
            }
        }
        ReturnTypeKind::Unit => quote! {
            Ok(vec![])
        },
        ReturnTypeKind::VecContent => quote! {
            Ok(result)
        },
        ReturnTypeKind::String => quote! {
            Ok(vec![fastmcp_protocol::Content::Text { text: result }])
        },
        ReturnTypeKind::ResultVecContent => quote! {
            result.map_err(|e| fastmcp_core::McpError::internal_error(e.to_string()))
        },
        ReturnTypeKind::McpResultVecContent => quote! {
            result
        },
        ReturnTypeKind::ResultString => quote! {
            result
                .map(|s| vec![fastmcp_protocol::Content::Text { text: s }])
                .map_err(|e| fastmcp_core::McpError::internal_error(e.to_string()))
        },
        ReturnTypeKind::McpResultString => quote! {
            result.map(|s| vec![fastmcp_protocol::Content::Text { text: s }])
        },
        ReturnTypeKind::Other => quote! {
            // Convert via ToString or Debug as fallback
            let text = format!("{}", result);
            Ok(vec![fastmcp_protocol::Content::Text { text }])
        },
    }
}

/// Generates the JSON-text content used by the legacy handler surface for a
/// schema-bound result. The current handler trait returns `Vec<Content>`, so
/// the protocol/server layer is responsible for promoting this JSON value to a
/// structured tool result when that surface is available.
fn generate_schema_bound_content(value: TokenStream2) -> TokenStream2 {
    quote! {
        let result_value = serde_json::to_value(&(#value)).map_err(|error| {
            fastmcp_core::McpError::internal_error(format!(
                "failed to serialize schema-bound tool result: {error}",
            ))
        })?;
        Ok(vec![fastmcp_protocol::Content::Text {
            text: result_value.to_string(),
        }])
    }
}

/// Generates conversion for a tool that opts into a typed output schema.
///
/// This intentionally leaves the legacy conversion path untouched. Typed
/// schemas make the generated handler serialize the returned value as JSON,
/// which both checks the result's `Serialize` contract at compile time and
/// keeps the content representation aligned with its advertised schema.
fn generate_schema_bound_result_conversion(output: &syn::ReturnType) -> TokenStream2 {
    let wrapped_result = match output {
        syn::ReturnType::Type(_, output_type) => match output_type.as_ref() {
            Type::Path(type_path) => type_path
                .path
                .segments
                .last()
                .map(|segment| segment.ident == "Result" || segment.ident == "McpResult")
                .unwrap_or(false),
            _ => false,
        },
        _ => false,
    };

    if !wrapped_result {
        return generate_schema_bound_content(quote! { result });
    }

    let is_mcp_result = match output {
        syn::ReturnType::Type(_, output_type) => match output_type.as_ref() {
            Type::Path(type_path) => type_path
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "McpResult"),
            _ => false,
        },
        _ => false,
    };

    if is_mcp_result {
        let content = generate_schema_bound_content(quote! { result_value });
        quote! {
            let result_value = result?;
            #content
        }
    } else {
        let content = generate_schema_bound_content(quote! { result_value });
        quote! {
            let result_value = result
                .map_err(|error| fastmcp_core::McpError::internal_error(error.to_string()))?;
            #content
        }
    }
}

/// Chooses the conversion policy for a tool result.
fn generate_tool_result_conversion(
    output: &syn::ReturnType,
    typed_output_schema: bool,
) -> TokenStream2 {
    if final_complete_return_kind(output, "FinalCallToolResult").is_some() {
        generate_result_conversion(output)
    } else if final_tool_outcome_return_kind(output).is_some() {
        quote! {
            Err(fastmcp_core::McpError::internal_error(
                "final #[tool] handlers must be invoked through ToolHandler::call_final_outcome",
            ))
        }
    } else if typed_output_schema {
        generate_schema_bound_result_conversion(output)
    } else {
        generate_result_conversion(output)
    }
}

/// Generates the exact final result conversion for a tool that already
/// returns the public final complete-result algebra. The legacy execution path
/// remains responsible for its strict, lossless projection to `Vec<Content>`.
fn generate_final_tool_result_conversion(output: &syn::ReturnType) -> Option<TokenStream2> {
    match final_complete_return_kind(output, "FinalCallToolResult")? {
        FinalCompleteReturnKind::Direct => Some(quote! { Ok(result) }),
        FinalCompleteReturnKind::Result => Some(quote! {
            result.map_err(|error| fastmcp_core::McpError::internal_error(error.to_string()))
        }),
        FinalCompleteReturnKind::McpResult => Some(quote! { result }),
    }
}

/// Generates the direct final-outcome conversion for a tool returning the
/// complete, input-required, or task-creation algebra.
fn generate_final_tool_outcome_conversion(output: &syn::ReturnType) -> Option<TokenStream2> {
    match final_tool_outcome_return_kind(output)? {
        FinalCompleteReturnKind::Direct => Some(quote! { Ok(result) }),
        FinalCompleteReturnKind::Result
            if final_tool_outcome_result_preserves_mcp_error(output) =>
        {
            Some(quote! { result })
        }
        FinalCompleteReturnKind::Result => Some(quote! {
            result.map_err(|error| fastmcp_core::McpError::internal_error(error.to_string()))
        }),
        FinalCompleteReturnKind::McpResult => Some(quote! { result }),
    }
}

/// Validates the explicit final-Tasks opt-in before expansion.
///
/// A tool may only advertise task creation when its exact result algebra can
/// actually emit `FinalToolOutcome::CreateTask`. Keeping this opt-in separate
/// from ordinary final-result handlers prevents an accidental capability claim
/// from widening router admission.
fn validate_tool_tasks_return(output: &syn::ReturnType) -> syn::Result<()> {
    if final_tool_outcome_return_kind(output).is_some() {
        return Ok(());
    }

    Err(syn::Error::new_spanned(
        output,
        "#[tool(tasks)] requires a canonical FinalToolOutcome return type: fastmcp_rust::FinalToolOutcome, Result<fastmcp_rust::FinalToolOutcome, E>, or McpResult<fastmcp_rust::FinalToolOutcome>",
    ))
}

/// Emits the capability declaration only for the validated explicit opt-in.
fn generate_tool_tasks_declaration(tasks: bool) -> TokenStream2 {
    if tasks {
        quote! {
            fn declares_final_tasks(&self) -> bool {
                true
            }
        }
    } else {
        TokenStream2::new()
    }
}

/// Emits typed final MCP Apps UI metadata for a validated tool declaration.
#[cfg(feature = "apps")]
fn generate_tool_apps_metadata(ui: Option<&ToolAppsUi>) -> TokenStream2 {
    let Some(ui) = ui else {
        return TokenStream2::new();
    };

    let resource_uri = &ui.resource_uri;
    let visibility = match ui.visibility.as_deref() {
        Some(visibility) => {
            let entries = visibility.iter().map(|visibility| match visibility {
                ToolAppsToolVisibility::Model => {
                    quote!(fastmcp_protocol::McpAppsToolVisibility::Model)
                }
                ToolAppsToolVisibility::App => {
                    quote!(fastmcp_protocol::McpAppsToolVisibility::App)
                }
            });
            quote!(Some(vec![#(#entries),*]))
        }
        None => quote!(None),
    };

    quote! {
        fn final_metadata(&self) -> Option<&fastmcp_protocol::OpenMetadata> {
            static METADATA: std::sync::OnceLock<fastmcp_protocol::OpenMetadata> =
                std::sync::OnceLock::new();
            Some(METADATA.get_or_init(|| {
                let resource_uri = fastmcp_protocol::AbsoluteUri::parse(#resource_uri)
                    .expect("#[tool(ui(...))] validates its resource URI during macro expansion");
                fastmcp_protocol::McpAppsToolMetadata::try_new(Some(resource_uri), #visibility)
                    .expect("#[tool(ui(...))] validates its metadata during macro expansion")
                    .to_open_metadata()
                    .expect("validated MCP Apps metadata encodes as open metadata")
            }))
        }
    }
}

fn generate_tool_execution_methods(
    is_async: bool,
    expects_context: bool,
    fn_name: &Ident,
    param_names: &[&Ident],
    param_extractions: &[TokenStream2],
    result_conversion: &TokenStream2,
    final_result_conversion: Option<&TokenStream2>,
    final_outcome_conversion: Option<&TokenStream2>,
) -> TokenStream2 {
    let final_outcome_request_method = if final_outcome_conversion.is_some() {
        quote! {
            fn call_final_outcome_async_in_request<'a>(
                &'a self,
                ctx: &'a fastmcp_core::McpContext,
                request_cx: &'a fastmcp_core::Cx,
                arguments: serde_json::Value,
            ) -> fastmcp_server::BoxFuture<
                'a,
                fastmcp_core::McpOutcome<fastmcp_server::FinalToolOutcome>,
            > {
                Box::pin(async move {
                    if request_cx.checkpoint().is_err() {
                        return fastmcp_core::cancelled();
                    }

                    let outcome = self.call_final_outcome_async(ctx, arguments).await;
                    if request_cx.checkpoint().is_err() {
                        fastmcp_core::cancelled()
                    } else {
                        outcome
                    }
                })
            }
        }
    } else {
        quote! {
            fn call_final_outcome_async_in_request<'a>(
                &'a self,
                ctx: &'a fastmcp_core::McpContext,
                request_cx: &'a fastmcp_core::Cx,
                arguments: serde_json::Value,
            ) -> fastmcp_server::BoxFuture<
                'a,
                fastmcp_core::McpOutcome<fastmcp_server::FinalToolOutcome>,
            > {
                Box::pin(async move {
                    match self.call_final_async_in_request(ctx, request_cx, arguments).await {
                        fastmcp_core::Outcome::Ok(result) => {
                            fastmcp_core::Outcome::Ok(
                                fastmcp_server::FinalToolOutcome::Complete(result),
                            )
                        }
                        fastmcp_core::Outcome::Err(error) => fastmcp_core::Outcome::Err(error),
                        fastmcp_core::Outcome::Cancelled(reason) => {
                            fastmcp_core::Outcome::Cancelled(reason)
                        }
                        fastmcp_core::Outcome::Panicked(payload) => {
                            fastmcp_core::Outcome::Panicked(payload)
                        }
                    }
                })
            }
        }
    };
    let modern_request_methods = quote! {
        fn call_async_in_request<'a>(
            &'a self,
            ctx: &'a fastmcp_core::McpContext,
            _request_cx: &'a fastmcp_core::Cx,
            arguments: serde_json::Value,
        ) -> fastmcp_server::BoxFuture<
            'a,
            fastmcp_core::McpOutcome<Vec<fastmcp_protocol::Content>>,
        > {
            self.call_async(ctx, arguments)
        }

        fn call_final_async_in_request<'a>(
            &'a self,
            ctx: &'a fastmcp_core::McpContext,
            _request_cx: &'a fastmcp_core::Cx,
            arguments: serde_json::Value,
        ) -> fastmcp_server::BoxFuture<
            'a,
            fastmcp_core::McpOutcome<
                fastmcp_protocol::CompleteResult<fastmcp_protocol::FinalCallToolResult>,
            >,
        > {
            self.call_final_async(ctx, arguments)
        }

        #final_outcome_request_method
    };
    let sync_invocation = if expects_context {
        quote! { #fn_name(ctx, #(#param_names),*) }
    } else {
        quote! { #fn_name(#(#param_names),*) }
    };

    if !is_async {
        let legacy_method = if final_outcome_conversion.is_some() {
            quote! {
                fn call(
                    &self,
                    _ctx: &fastmcp_core::McpContext,
                    _arguments: serde_json::Value,
                ) -> fastmcp_core::McpResult<Vec<fastmcp_protocol::Content>> {
                    Err(fastmcp_core::McpError::internal_error(
                        "final #[tool] handlers must be invoked through ToolHandler::call_final_outcome",
                    ))
                }
            }
        } else {
            quote! {
                fn call(
                    &self,
                    ctx: &fastmcp_core::McpContext,
                    arguments: serde_json::Value,
                ) -> fastmcp_core::McpResult<Vec<fastmcp_protocol::Content>> {
                    let arguments = arguments.as_object()
                        .cloned()
                        .unwrap_or_default();

                    #(#param_extractions)*

                    let result = #sync_invocation;
                    #result_conversion
                }
            }
        };
        let final_method = final_result_conversion.map_or_else(TokenStream2::new, |conversion| {
            quote! {
                fn call_final(
                    &self,
                    ctx: &fastmcp_core::McpContext,
                    arguments: serde_json::Value,
                ) -> fastmcp_core::McpResult<
                    fastmcp_protocol::CompleteResult<fastmcp_protocol::FinalCallToolResult>,
                > {
                    let arguments = arguments.as_object()
                        .cloned()
                        .unwrap_or_default();

                    #(#param_extractions)*

                    let result = #sync_invocation;
                    #conversion
                }
            }
        });
        let final_outcome_method =
            final_outcome_conversion.map_or_else(TokenStream2::new, |conversion| {
                quote! {
                    fn call_final_outcome(
                        &self,
                        ctx: &fastmcp_core::McpContext,
                        arguments: serde_json::Value,
                    ) -> fastmcp_core::McpResult<fastmcp_server::FinalToolOutcome> {
                        let arguments = arguments.as_object()
                            .cloned()
                            .unwrap_or_default();

                        #(#param_extractions)*

                        let result = #sync_invocation;
                        #conversion
                    }
                }
            });
        return quote! {
            #legacy_method

            #final_method

            #final_outcome_method

            #modern_request_methods
        };
    }

    let async_invocation = if expects_context {
        quote! { #fn_name(ctx, #(#param_names),*).await }
    } else {
        quote! { #fn_name(#(#param_names),*).await }
    };

    let final_method = if let Some(conversion) = final_result_conversion {
        quote! {
            fn call_final_async<'a>(
                &'a self,
                ctx: &'a fastmcp_core::McpContext,
                arguments: serde_json::Value,
            ) -> fastmcp_server::BoxFuture<
                'a,
                fastmcp_core::McpOutcome<
                    fastmcp_protocol::CompleteResult<fastmcp_protocol::FinalCallToolResult>,
                >,
            > {
                Box::pin(async move {
                    let result: fastmcp_core::McpResult<
                        fastmcp_protocol::CompleteResult<fastmcp_protocol::FinalCallToolResult>,
                    > = async move {
                        let arguments = arguments.as_object()
                            .cloned()
                            .unwrap_or_default();

                        #(#param_extractions)*

                        let result = #async_invocation;
                        #conversion
                    }.await;

                    match result {
                        Ok(value) => fastmcp_core::Outcome::Ok(value),
                        Err(error) => fastmcp_core::Outcome::Err(error),
                    }
                })
            }
        }
    } else if final_outcome_conversion.is_none() {
        quote! {
            fn call_final_async<'a>(
                &'a self,
                ctx: &'a fastmcp_core::McpContext,
                arguments: serde_json::Value,
            ) -> fastmcp_server::BoxFuture<
                'a,
                fastmcp_core::McpOutcome<
                    fastmcp_protocol::CompleteResult<fastmcp_protocol::FinalCallToolResult>,
                >,
            > {
                Box::pin(async move {
                    match self.call_async(ctx, arguments).await {
                        fastmcp_core::Outcome::Ok(content) => {
                            match ::fastmcp_server::promote_legacy_tool_content(content) {
                                Ok(complete) => fastmcp_core::Outcome::Ok(complete),
                                Err(error) => fastmcp_core::Outcome::Err(error),
                            }
                        }
                        fastmcp_core::Outcome::Err(error) => fastmcp_core::Outcome::Err(error),
                        fastmcp_core::Outcome::Cancelled(cancelled) => {
                            fastmcp_core::Outcome::Cancelled(cancelled)
                        }
                        fastmcp_core::Outcome::Panicked(panic) => {
                            fastmcp_core::Outcome::Panicked(panic)
                        }
                    }
                })
            }
        }
    } else {
        TokenStream2::new()
    };

    let final_outcome_method =
        final_outcome_conversion.map_or_else(TokenStream2::new, |conversion| {
            quote! {
                fn call_final_outcome_async<'a>(
                    &'a self,
                    ctx: &'a fastmcp_core::McpContext,
                    arguments: serde_json::Value,
                ) -> fastmcp_server::BoxFuture<
                    'a,
                    fastmcp_core::McpOutcome<fastmcp_server::FinalToolOutcome>,
                > {
                    Box::pin(async move {
                        let result: fastmcp_core::McpResult<fastmcp_server::FinalToolOutcome> = async move {
                            let arguments = arguments.as_object()
                                .cloned()
                                .unwrap_or_default();

                            #(#param_extractions)*

                            let result = #async_invocation;
                            #conversion
                        }.await;

                        match result {
                            Ok(value) => fastmcp_core::Outcome::Ok(value),
                            Err(error) => fastmcp_core::Outcome::Err(error),
                        }
                    })
                }
            }
        });

    let legacy_async_method = if final_outcome_conversion.is_some() {
        quote! {
            fn call_async<'a>(
                &'a self,
                _ctx: &'a fastmcp_core::McpContext,
                _arguments: serde_json::Value,
            ) -> fastmcp_server::BoxFuture<
                'a,
                fastmcp_core::McpOutcome<Vec<fastmcp_protocol::Content>>,
            > {
                Box::pin(async {
                    fastmcp_core::Outcome::Err(fastmcp_core::McpError::internal_error(
                        "final #[tool] handlers must be invoked through ToolHandler::call_final_outcome_async",
                    ))
                })
            }
        }
    } else {
        quote! {
            fn call_async<'a>(
                &'a self,
                ctx: &'a fastmcp_core::McpContext,
                arguments: serde_json::Value,
            ) -> fastmcp_server::BoxFuture<
                'a,
                fastmcp_core::McpOutcome<Vec<fastmcp_protocol::Content>>,
            > {
                Box::pin(async move {
                    let result: fastmcp_core::McpResult<Vec<fastmcp_protocol::Content>> = async move {
                        let arguments = arguments.as_object()
                            .cloned()
                            .unwrap_or_default();

                        #(#param_extractions)*

                        let result = #async_invocation;
                        #result_conversion
                    }.await;

                    match result {
                        Ok(value) => fastmcp_core::Outcome::Ok(value),
                        Err(error) => fastmcp_core::Outcome::Err(error),
                    }
                })
            }
        }
    };

    quote! {
        fn call(
            &self,
            _ctx: &fastmcp_core::McpContext,
            _arguments: serde_json::Value,
        ) -> fastmcp_core::McpResult<Vec<fastmcp_protocol::Content>> {
            Err(fastmcp_core::McpError::internal_error(
                "async #[tool] handlers must be invoked through ToolHandler::call_async",
            ))
        }

        #legacy_async_method

        #final_method

        #final_outcome_method

        #modern_request_methods
    }
}

/// Emits the retry-only tool hook for a macro handler that opted into the
/// typed MRTR input parameter. Ordinary generated entry points keep passing
/// `None`; this hook is reached only after router admission supplied the
/// completed input map.
fn generate_tool_mrtr_resume_method(
    is_async: bool,
    expects_context: bool,
    fn_name: &Ident,
    param_names: &[&Ident],
    param_extractions: &[TokenStream2],
    resume_name: &Ident,
    resume_type: &Type,
    final_outcome_conversion: &TokenStream2,
) -> TokenStream2 {
    let sync_invocation = if expects_context {
        quote! { #fn_name(ctx, #(#param_names),*) }
    } else {
        quote! { #fn_name(#(#param_names),*) }
    };
    let async_invocation = if expects_context {
        quote! { #fn_name(ctx, #(#param_names),*).await }
    } else {
        quote! { #fn_name(#(#param_names),*).await }
    };
    let invocation = if is_async {
        quote! {
            let result: fastmcp_core::McpResult<fastmcp_server::FinalToolOutcome> = async move {
                let arguments = arguments.as_object().cloned().unwrap_or_default();
                #(#param_extractions)*
                let #resume_name: #resume_type = resume_inputs;
                let result = #async_invocation;
                #final_outcome_conversion
            }.await;
        }
    } else {
        quote! {
            let result: fastmcp_core::McpResult<fastmcp_server::FinalToolOutcome> = (|| {
                let arguments = arguments.as_object().cloned().unwrap_or_default();
                #(#param_extractions)*
                let #resume_name: #resume_type = resume_inputs;
                let result = #sync_invocation;
                #final_outcome_conversion
            })();
        }
    };

    quote! {
        fn declares_final_mrtr(&self) -> bool {
            true
        }

        fn call_final_outcome_async_resuming_in_request<'a>(
            &'a self,
            ctx: &'a fastmcp_core::McpContext,
            request_cx: &'a fastmcp_core::Cx,
            arguments: serde_json::Value,
            resume_inputs: Option<&'a fastmcp_server::bidirectional::MrtrCompletedInputs>,
        ) -> fastmcp_server::BoxFuture<'a, fastmcp_core::McpOutcome<fastmcp_server::FinalToolOutcome>> {
            Box::pin(async move {
                if request_cx.checkpoint().is_err() {
                    return fastmcp_core::cancelled();
                }
                #invocation
                if request_cx.checkpoint().is_err() {
                    fastmcp_core::cancelled()
                } else {
                    match result {
                        Ok(value) => fastmcp_core::Outcome::Ok(value),
                        Err(error) => fastmcp_core::Outcome::Err(error),
                    }
                }
            })
        }
    }
}

// ============================================================================
// Prompt Return Type Analysis
// ============================================================================

/// The explicit final complete-result forms which can be projected through a
/// legacy handler trait without discarding method payload content.
#[derive(Clone, Copy)]
enum FinalCompleteReturnKind {
    Direct,
    Result,
    McpResult,
}

fn return_type_value(output: &syn::ReturnType) -> Option<&Type> {
    match output {
        syn::ReturnType::Default => None,
        syn::ReturnType::Type(_, value) => Some(value),
    }
}

fn type_last_segment(ty: &Type) -> Option<&syn::PathSegment> {
    let Type::Path(type_path) = ty else {
        return None;
    };
    if type_path.qself.is_some() {
        return None;
    }
    type_path.path.segments.last()
}

fn type_has_last_ident(ty: &Type, expected: &str) -> bool {
    type_last_segment(ty).is_some_and(|segment| segment.ident == expected)
}

fn first_type_argument(ty: &Type) -> Option<&Type> {
    let segment = type_last_segment(ty)?;
    let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return None;
    };
    arguments.args.iter().find_map(|argument| match argument {
        syn::GenericArgument::Type(value) => Some(value),
        _ => None,
    })
}

fn is_complete_result_for(ty: &Type, payload: &str) -> bool {
    type_has_last_ident(ty, "CompleteResult")
        && first_type_argument(ty).is_some_and(|value| type_has_last_ident(value, payload))
}

fn final_complete_return_kind(
    output: &syn::ReturnType,
    payload: &str,
) -> Option<FinalCompleteReturnKind> {
    let value = return_type_value(output)?;
    if is_complete_result_for(value, payload) {
        return Some(FinalCompleteReturnKind::Direct);
    }

    let success = first_type_argument(value)?;
    if !is_complete_result_for(success, payload) {
        return None;
    }
    if type_has_last_ident(value, "McpResult") {
        Some(FinalCompleteReturnKind::McpResult)
    } else if type_has_last_ident(value, "Result") {
        Some(FinalCompleteReturnKind::Result)
    } else {
        None
    }
}

fn final_tool_outcome_return_kind(output: &syn::ReturnType) -> Option<FinalCompleteReturnKind> {
    let value = return_type_value(output)?;
    if is_canonical_final_tool_outcome(value) {
        return Some(FinalCompleteReturnKind::Direct);
    }

    let success = first_type_argument(value)?;
    if !is_canonical_final_tool_outcome(success) {
        return None;
    }
    if type_has_last_ident(value, "McpResult") {
        Some(FinalCompleteReturnKind::McpResult)
    } else if type_has_last_ident(value, "Result") {
        Some(FinalCompleteReturnKind::Result)
    } else {
        None
    }
}

/// Classifies the complete-or-input-required algebra used by final resources
/// and prompts. Unlike a bare `CompleteResult`, this return type preserves an
/// application request for more embedded input until the router mints the
/// retry state.
fn final_method_outcome_return_kind(
    output: &syn::ReturnType,
    final_payload: &str,
) -> Option<FinalCompleteReturnKind> {
    let value = return_type_value(output)?;
    let outcome_payload = |candidate: &Type| {
        let Type::Path(type_path) = candidate else {
            return false;
        };
        let Some(segment) = type_path.path.segments.last() else {
            return false;
        };
        if segment.ident != "FinalMethodOutcome" {
            return false;
        }
        first_type_argument(candidate)
            .is_some_and(|payload| type_has_last_ident(payload, final_payload))
    };

    if outcome_payload(value) {
        return Some(FinalCompleteReturnKind::Direct);
    }
    let success = first_type_argument(value)?;
    if !outcome_payload(success) {
        return None;
    }
    if type_has_last_ident(value, "McpResult") {
        Some(FinalCompleteReturnKind::McpResult)
    } else if type_has_last_ident(value, "Result") {
        Some(FinalCompleteReturnKind::Result)
    } else {
        None
    }
}

fn final_tool_outcome_result_preserves_mcp_error(output: &syn::ReturnType) -> bool {
    let Some(value) = return_type_value(output) else {
        return false;
    };
    let Type::Path(type_path) = value else {
        return false;
    };
    let Some(segment) = type_path.path.segments.last() else {
        return false;
    };
    if segment.ident != "Result" {
        return false;
    }
    let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return false;
    };
    arguments
        .args
        .iter()
        .filter_map(|argument| match argument {
            syn::GenericArgument::Type(value) => Some(value),
            _ => None,
        })
        .nth(1)
        .is_some_and(|error| type_has_last_ident(error, "McpError"))
}

fn final_tool_outcome_candidate(output: &syn::ReturnType) -> Option<&Type> {
    let value = return_type_value(output)?;
    if type_has_last_ident(value, "FinalToolOutcome") {
        return Some(value);
    }

    let success = first_type_argument(value)?;
    type_has_last_ident(success, "FinalToolOutcome").then_some(success)
}

fn is_canonical_final_tool_outcome(ty: &Type) -> bool {
    let Type::Path(type_path) = ty else {
        return false;
    };
    let segments = &type_path.path.segments;
    if segments.len() < 2
        || segments
            .last()
            .is_none_or(|segment| segment.ident != "FinalToolOutcome")
    {
        return false;
    }

    let Some(root) = segments.first().map(|segment| segment.ident.to_string()) else {
        return false;
    };
    if matches!(root.as_str(), "fastmcp_rust" | "fastmcp_server") {
        return true;
    }

    ["fastmcp-rust", "fastmcp-server"]
        .into_iter()
        .any(|package| matches!(crate_name(package), Ok(FoundCrate::Name(name)) if name == root))
}

fn type_contains_final_result_term(ty: &Type) -> bool {
    const FINAL_RESULT_TERMS: &[&str] = &[
        "CompleteResult",
        "InputRequiredResult",
        "CacheableResult",
        "PaginatedResult",
        "FinalCallToolResult",
        "FinalToolOutcome",
        "FinalMethodOutcome",
        "FinalReadResourceResult",
        "FinalGetPromptResult",
        "ReadResourceResult",
        "GetPromptResult",
    ];

    match ty {
        Type::Path(type_path) => type_path.path.segments.iter().any(|segment| {
            FINAL_RESULT_TERMS.iter().any(|term| segment.ident == *term)
                || match &segment.arguments {
                    syn::PathArguments::AngleBracketed(arguments) => arguments
                        .args
                        .iter()
                        .filter_map(|argument| match argument {
                            syn::GenericArgument::Type(value) => Some(value),
                            _ => None,
                        })
                        .any(type_contains_final_result_term),
                    _ => false,
                }
        }),
        Type::Array(array) => type_contains_final_result_term(&array.elem),
        Type::Group(group) => type_contains_final_result_term(&group.elem),
        Type::Paren(paren) => type_contains_final_result_term(&paren.elem),
        Type::Ptr(pointer) => type_contains_final_result_term(&pointer.elem),
        Type::Reference(reference) => type_contains_final_result_term(&reference.elem),
        Type::Slice(slice) => type_contains_final_result_term(&slice.elem),
        Type::Tuple(tuple) => tuple.elems.iter().any(type_contains_final_result_term),
        _ => false,
    }
}

fn validate_final_handler_return(
    output: &syn::ReturnType,
    handler: &str,
    payload: &str,
    final_payload: Option<&str>,
    legacy_output: &str,
) -> syn::Result<()> {
    let Some(value) = return_type_value(output) else {
        return Ok(());
    };
    if payload == "FinalCallToolResult"
        && let Some(candidate) = final_tool_outcome_candidate(output)
        && !is_canonical_final_tool_outcome(candidate)
    {
        return Err(syn::Error::new_spanned(
            candidate,
            "final #[tool] outcomes must use fastmcp_rust::FinalToolOutcome or fastmcp_server::FinalToolOutcome",
        ));
    }
    if final_complete_return_kind(output, payload).is_some()
        || (payload == "FinalCallToolResult" && final_tool_outcome_return_kind(output).is_some())
        || final_payload.is_some_and(|final_payload| {
            final_method_outcome_return_kind(output, final_payload).is_some()
        })
        || final_payload
            .is_some_and(|payload| final_complete_return_kind(output, payload).is_some())
        || !type_contains_final_result_term(value)
    {
        return Ok(());
    }

    let direct_forms = final_payload.map_or_else(
        || format!("CompleteResult<{payload}>"),
        |final_payload| format!("CompleteResult<{payload}> or CompleteResult<{final_payload}>"),
    );
    let wrapped_forms = final_payload.map_or_else(
        || format!("Result<CompleteResult<{payload}>, E>, or McpResult<CompleteResult<{payload}>>"),
        |final_payload| format!(
            "Result<CompleteResult<{payload}>, E>, Result<CompleteResult<{final_payload}>, E>, McpResult<CompleteResult<{payload}>>, or McpResult<CompleteResult<{final_payload}>>",
        ),
    );

    Err(syn::Error::new_spanned(
        output,
        format!(
            "ambiguous or cross-era final #[{handler}] return; use {direct_forms}, {wrapped_forms} so the legacy handler can project {legacy_output}",
        ),
    ))
}

/// Represents return type strategies for prompt handlers.
enum PromptReturnTypeKind {
    /// Returns a final CompleteResult<GetPromptResult> directly.
    FinalComplete,
    /// Returns Result<CompleteResult<GetPromptResult>, E>.
    ResultFinalComplete,
    /// Returns McpResult<CompleteResult<GetPromptResult>>.
    McpResultFinalComplete,
    /// Returns Vec<PromptMessage> directly
    VecPromptMessage,
    /// Returns Result<Vec<PromptMessage>, E>
    ResultVecPromptMessage,
    /// Returns McpResult<Vec<PromptMessage>>
    McpResultVecPromptMessage,
    /// Unknown type - will fail at compile time
    Other,
}

/// Analyzes a prompt function's return type.
fn analyze_prompt_return_type(output: &syn::ReturnType) -> PromptReturnTypeKind {
    match final_complete_return_kind(output, "GetPromptResult") {
        Some(FinalCompleteReturnKind::Direct) => return PromptReturnTypeKind::FinalComplete,
        Some(FinalCompleteReturnKind::Result) => {
            return PromptReturnTypeKind::ResultFinalComplete;
        }
        Some(FinalCompleteReturnKind::McpResult) => {
            return PromptReturnTypeKind::McpResultFinalComplete;
        }
        None => {}
    }
    match output {
        syn::ReturnType::Default => PromptReturnTypeKind::Other, // () not valid for prompts
        syn::ReturnType::Type(_, ty) => analyze_prompt_type(ty),
    }
}

/// Analyzes a type for prompt return type classification.
fn analyze_prompt_type(ty: &Type) -> PromptReturnTypeKind {
    if let Type::Path(type_path) = ty {
        if let Some(segment) = type_path.path.segments.last() {
            let type_name = segment.ident.to_string();

            match type_name.as_str() {
                "Vec" => {
                    // Check if it's Vec<PromptMessage>
                    if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                        if let Some(syn::GenericArgument::Type(Type::Path(inner_path))) =
                            args.args.first()
                        {
                            if inner_path
                                .path
                                .segments
                                .last()
                                .is_some_and(|s| s.ident == "PromptMessage")
                            {
                                return PromptReturnTypeKind::VecPromptMessage;
                            }
                        }
                    }
                }
                "Result" | "McpResult" => {
                    // Check the Ok type
                    if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                        if let Some(syn::GenericArgument::Type(inner_ty)) = args.args.first() {
                            let inner_kind = analyze_prompt_type(inner_ty);
                            return match inner_kind {
                                PromptReturnTypeKind::VecPromptMessage => {
                                    if type_name == "McpResult" {
                                        PromptReturnTypeKind::McpResultVecPromptMessage
                                    } else {
                                        PromptReturnTypeKind::ResultVecPromptMessage
                                    }
                                }
                                _ => PromptReturnTypeKind::Other,
                            };
                        }
                    }
                }
                _ => {}
            }
        }
    }
    PromptReturnTypeKind::Other
}

/// Generates code to convert a prompt function result to McpResult<Vec<PromptMessage>>.
fn generate_prompt_result_conversion(output: &syn::ReturnType) -> TokenStream2 {
    let kind = analyze_prompt_return_type(output);

    match kind {
        PromptReturnTypeKind::FinalComplete => quote! {
            Ok(result.payload.messages)
        },
        PromptReturnTypeKind::ResultFinalComplete => quote! {
            result
                .map(|complete| complete.payload.messages)
                .map_err(|error| fastmcp_core::McpError::internal_error(error.to_string()))
        },
        PromptReturnTypeKind::McpResultFinalComplete => quote! {
            Ok(result?.payload.messages)
        },
        PromptReturnTypeKind::VecPromptMessage => quote! {
            Ok(result)
        },
        PromptReturnTypeKind::ResultVecPromptMessage => quote! {
            result.map_err(|e| fastmcp_core::McpError::internal_error(e.to_string()))
        },
        PromptReturnTypeKind::McpResultVecPromptMessage => quote! {
            result
        },
        PromptReturnTypeKind::Other => quote! {
            // Fallback: assume the result is Vec<PromptMessage>
            Ok(result)
        },
    }
}

/// Generates the final prompt result conversion for handlers that already
/// return the final prompt result algebra.
fn generate_final_prompt_result_conversion(output: &syn::ReturnType) -> Option<TokenStream2> {
    match final_complete_return_kind(output, "FinalGetPromptResult")? {
        FinalCompleteReturnKind::Direct => Some(quote! { Ok(result) }),
        FinalCompleteReturnKind::Result => Some(quote! {
            result.map_err(|error| fastmcp_core::McpError::internal_error(error.to_string()))
        }),
        FinalCompleteReturnKind::McpResult => Some(quote! { result }),
    }
}

/// Converts a prompt's complete-or-input-required final algebra without a
/// legacy prompt-message projection.
fn generate_final_prompt_outcome_conversion(output: &syn::ReturnType) -> Option<TokenStream2> {
    match final_method_outcome_return_kind(output, "FinalGetPromptResult")? {
        FinalCompleteReturnKind::Direct => Some(quote! { Ok(result) }),
        FinalCompleteReturnKind::Result => Some(quote! {
            result.map_err(|error| fastmcp_core::McpError::internal_error(error.to_string()))
        }),
        FinalCompleteReturnKind::McpResult => Some(quote! { result }),
    }
}

fn generate_prompt_execution_methods(
    is_async: bool,
    expects_context: bool,
    fn_name: &Ident,
    param_names: &[Ident],
    param_extractions: &[TokenStream2],
    result_conversion: &TokenStream2,
    final_result_conversion: Option<&TokenStream2>,
    emit_async_final_outcome: bool,
) -> TokenStream2 {
    let modern_request_methods = quote! {
        fn get_async_in_request<'a>(
            &'a self,
            ctx: &'a fastmcp_core::McpContext,
            _request_cx: &'a fastmcp_core::Cx,
            arguments: std::collections::HashMap<String, String>,
        ) -> fastmcp_server::BoxFuture<
            'a,
            fastmcp_core::McpOutcome<Vec<fastmcp_protocol::PromptMessage>>,
        > {
            self.get_async(ctx, arguments)
        }

        fn get_final_async_in_request<'a>(
            &'a self,
            ctx: &'a fastmcp_core::McpContext,
            _request_cx: &'a fastmcp_core::Cx,
            arguments: std::collections::HashMap<String, String>,
        ) -> fastmcp_server::BoxFuture<
            'a,
            fastmcp_core::McpOutcome<
                fastmcp_protocol::CompleteResult<fastmcp_protocol::FinalGetPromptResult>,
            >,
        > {
            self.get_final_async(ctx, arguments)
        }
    };
    let sync_invocation = if expects_context {
        quote! { #fn_name(ctx, #(#param_names),*) }
    } else {
        quote! { #fn_name(#(#param_names),*) }
    };

    if !is_async {
        let final_method = final_result_conversion.map_or_else(TokenStream2::new, |conversion| {
            quote! {
                fn get_final(
                    &self,
                    ctx: &fastmcp_core::McpContext,
                    arguments: std::collections::HashMap<String, String>,
                ) -> fastmcp_core::McpResult<
                    fastmcp_protocol::CompleteResult<fastmcp_protocol::FinalGetPromptResult>,
                > {
                    #(#param_extractions)*
                    let result = #sync_invocation;
                    #conversion
                }
            }
        });
        let legacy_methods = if final_result_conversion.is_some() {
            quote! {
                fn get(
                    &self,
                    _ctx: &fastmcp_core::McpContext,
                    _arguments: std::collections::HashMap<String, String>,
                ) -> fastmcp_core::McpResult<Vec<fastmcp_protocol::PromptMessage>> {
                    #result_conversion
                }
            }
        } else {
            quote! {
                fn get(
                    &self,
                    ctx: &fastmcp_core::McpContext,
                    arguments: std::collections::HashMap<String, String>,
                ) -> fastmcp_core::McpResult<Vec<fastmcp_protocol::PromptMessage>> {
                    #(#param_extractions)*
                    let result = #sync_invocation;
                    #result_conversion
                }
            }
        };
        return quote! {
            #legacy_methods
            #final_method
            #modern_request_methods
        };
    }

    let async_invocation = if expects_context {
        quote! { #fn_name(ctx, #(#param_names),*).await }
    } else {
        quote! { #fn_name(#(#param_names),*).await }
    };

    let final_method = final_result_conversion.map_or_else(TokenStream2::new, |conversion| {
        quote! {
            fn get_final_async<'a>(
                &'a self,
                ctx: &'a fastmcp_core::McpContext,
                arguments: std::collections::HashMap<String, String>,
            ) -> fastmcp_server::BoxFuture<
                'a,
                fastmcp_core::McpOutcome<
                    fastmcp_protocol::CompleteResult<fastmcp_protocol::FinalGetPromptResult>,
                >,
            > {
                Box::pin(async move {
                    let result: fastmcp_core::McpResult<
                        fastmcp_protocol::CompleteResult<fastmcp_protocol::FinalGetPromptResult>,
                    > = async move {
                        #(#param_extractions)*
                        let result = #async_invocation;
                        #conversion
                    }.await;

                    match result {
                        Ok(value) => fastmcp_core::Outcome::Ok(value),
                        Err(error) => fastmcp_core::Outcome::Err(error),
                    }
                })
            }
        }
    });

    let legacy_methods = if final_result_conversion.is_some() {
        quote! {
            fn get(
                &self,
                _ctx: &fastmcp_core::McpContext,
                _arguments: std::collections::HashMap<String, String>,
            ) -> fastmcp_core::McpResult<Vec<fastmcp_protocol::PromptMessage>> {
                #result_conversion
            }
        }
    } else {
        quote! {
            fn get(
                &self,
                _ctx: &fastmcp_core::McpContext,
                _arguments: std::collections::HashMap<String, String>,
            ) -> fastmcp_core::McpResult<Vec<fastmcp_protocol::PromptMessage>> {
                Err(fastmcp_core::McpError::internal_error(
                    "async #[prompt] handlers must be invoked through PromptHandler::get_async",
                ))
            }

            fn get_async<'a>(
                &'a self,
                ctx: &'a fastmcp_core::McpContext,
                arguments: std::collections::HashMap<String, String>,
            ) -> fastmcp_server::BoxFuture<
                'a,
                fastmcp_core::McpOutcome<Vec<fastmcp_protocol::PromptMessage>>,
            > {
                Box::pin(async move {
                    let result: fastmcp_core::McpResult<
                        Vec<fastmcp_protocol::PromptMessage>,
                    > = async move {
                        #(#param_extractions)*
                        let result = #async_invocation;
                        #result_conversion
                    }.await;

                    match result {
                        Ok(value) => fastmcp_core::Outcome::Ok(value),
                        Err(error) => fastmcp_core::Outcome::Err(error),
                    }
                })
            }
        }
    };

    let async_outcome_hook = if emit_async_final_outcome {
        if final_result_conversion.is_some() {
            quote! {
                fn get_final_outcome_async_in_request<'a>(
                    &'a self,
                    ctx: &'a fastmcp_core::McpContext,
                    request_cx: &'a fastmcp_core::Cx,
                    arguments: std::collections::HashMap<String, String>,
                ) -> fastmcp_server::BoxFuture<
                    'a,
                    fastmcp_core::McpOutcome<
                        fastmcp_server::FinalMethodOutcome<fastmcp_protocol::FinalGetPromptResult>,
                    >,
                > {
                    Box::pin(async move {
                        match self.get_final_async_in_request(ctx, request_cx, arguments).await {
                            fastmcp_core::Outcome::Ok(complete) => {
                                fastmcp_core::Outcome::Ok(
                                    fastmcp_server::FinalMethodOutcome::Complete(complete),
                                )
                            }
                            fastmcp_core::Outcome::Err(error) => fastmcp_core::Outcome::Err(error),
                            fastmcp_core::Outcome::Cancelled(cancelled) => {
                                fastmcp_core::Outcome::Cancelled(cancelled)
                            }
                            fastmcp_core::Outcome::Panicked(panic) => {
                                fastmcp_core::Outcome::Panicked(panic)
                            }
                        }
                    })
                }
            }
        } else {
            quote! {
                fn get_final_outcome_async_in_request<'a>(
                    &'a self,
                    ctx: &'a fastmcp_core::McpContext,
                    request_cx: &'a fastmcp_core::Cx,
                    arguments: std::collections::HashMap<String, String>,
                ) -> fastmcp_server::BoxFuture<
                    'a,
                    fastmcp_core::McpOutcome<
                        fastmcp_server::FinalMethodOutcome<fastmcp_protocol::FinalGetPromptResult>,
                    >,
                > {
                    Box::pin(async move {
                        match self.get_async_in_request(ctx, request_cx, arguments).await {
                            fastmcp_core::Outcome::Ok(messages) => {
                                match ::fastmcp_server::promote_legacy_prompt_messages(messages) {
                                    Ok(complete) => fastmcp_core::Outcome::Ok(
                                        fastmcp_server::FinalMethodOutcome::Complete(complete),
                                    ),
                                    Err(error) => fastmcp_core::Outcome::Err(error),
                                }
                            }
                            fastmcp_core::Outcome::Err(error) => fastmcp_core::Outcome::Err(error),
                            fastmcp_core::Outcome::Cancelled(cancelled) => {
                                fastmcp_core::Outcome::Cancelled(cancelled)
                            }
                            fastmcp_core::Outcome::Panicked(panic) => {
                                fastmcp_core::Outcome::Panicked(panic)
                            }
                        }
                    })
                }
            }
        }
    } else {
        TokenStream2::new()
    };

    quote! {
        #legacy_methods
        #final_method
        #modern_request_methods
        #async_outcome_hook
    }
}

/// Emits the final complete-or-input-required prompt hooks for a resumable
/// macro handler. The accepted MRTR map is supplied only through the retry
/// hook after router validation.
fn generate_prompt_mrtr_outcome_methods(
    is_async: bool,
    expects_context: bool,
    fn_name: &Ident,
    param_names: &[Ident],
    param_extractions: &[TokenStream2],
    resume_name: &Ident,
    resume_type: &Type,
    conversion: &TokenStream2,
) -> TokenStream2 {
    let sync_invocation = if expects_context {
        quote! { #fn_name(ctx, #(#param_names),*) }
    } else {
        quote! { #fn_name(#(#param_names),*) }
    };
    let async_invocation = if expects_context {
        quote! { #fn_name(ctx, #(#param_names),*).await }
    } else {
        quote! { #fn_name(#(#param_names),*).await }
    };
    let initial_invocation = if is_async {
        quote! {
            let result: fastmcp_core::McpResult<fastmcp_server::FinalMethodOutcome<fastmcp_protocol::FinalGetPromptResult>> = async move {
                #(#param_extractions)*
                let #resume_name: #resume_type = None;
                let result = #async_invocation;
                #conversion
            }.await;
        }
    } else {
        quote! {
            let result: fastmcp_core::McpResult<fastmcp_server::FinalMethodOutcome<fastmcp_protocol::FinalGetPromptResult>> = (|| {
                #(#param_extractions)*
                let #resume_name: #resume_type = None;
                let result = #sync_invocation;
                #conversion
            })();
        }
    };
    let resumed_invocation = if is_async {
        quote! {
            let result: fastmcp_core::McpResult<fastmcp_server::FinalMethodOutcome<fastmcp_protocol::FinalGetPromptResult>> = async move {
                #(#param_extractions)*
                let #resume_name: #resume_type = resume_inputs;
                let result = #async_invocation;
                #conversion
            }.await;
        }
    } else {
        quote! {
            let result: fastmcp_core::McpResult<fastmcp_server::FinalMethodOutcome<fastmcp_protocol::FinalGetPromptResult>> = (|| {
                #(#param_extractions)*
                let #resume_name: #resume_type = resume_inputs;
                let result = #sync_invocation;
                #conversion
            })();
        }
    };
    let outcome = quote! {
        match result {
            Ok(value) => fastmcp_core::Outcome::Ok(value),
            Err(error) => fastmcp_core::Outcome::Err(error),
        }
    };

    quote! {
        fn declares_final_mrtr(&self) -> bool {
            true
        }

        fn get_final_outcome_async_in_request<'a>(
            &'a self,
            ctx: &'a fastmcp_core::McpContext,
            _request_cx: &'a fastmcp_core::Cx,
            arguments: std::collections::HashMap<String, String>,
        ) -> fastmcp_server::BoxFuture<'a, fastmcp_core::McpOutcome<fastmcp_server::FinalMethodOutcome<fastmcp_protocol::FinalGetPromptResult>>> {
            Box::pin(async move {
                let _ = ctx;
                let _ = &arguments;
                #initial_invocation
                #outcome
            })
        }

        fn get_final_outcome_async_resuming_in_request<'a>(
            &'a self,
            ctx: &'a fastmcp_core::McpContext,
            _request_cx: &'a fastmcp_core::Cx,
            arguments: std::collections::HashMap<String, String>,
            resume_inputs: Option<&'a fastmcp_server::bidirectional::MrtrCompletedInputs>,
        ) -> fastmcp_server::BoxFuture<'a, fastmcp_core::McpOutcome<fastmcp_server::FinalMethodOutcome<fastmcp_protocol::FinalGetPromptResult>>> {
            Box::pin(async move {
                let _ = ctx;
                let _ = &arguments;
                #resumed_invocation
                #outcome
            })
        }
    }
}

// ============================================================================
// Resource Return Type Analysis
// ============================================================================

/// Represents return type strategies for resource handlers.
enum ResourceReturnTypeKind {
    /// Returns a final CompleteResult<ReadResourceResult> directly.
    FinalComplete,
    /// Returns Result<CompleteResult<ReadResourceResult>, E>.
    ResultFinalComplete,
    /// Returns McpResult<CompleteResult<ReadResourceResult>>.
    McpResultFinalComplete,
    /// Returns String directly
    String,
    /// Returns Vec<ResourceContent> directly
    VecResourceContent,
    /// Returns Result<String, E>
    ResultString,
    /// Returns McpResult<String>
    McpResultString,
    /// Returns Result<Vec<ResourceContent>, E>
    ResultVecResourceContent,
    /// Returns McpResult<Vec<ResourceContent>>
    McpResultVecResourceContent,
    /// Unknown type - use ToString
    Other,
}

/// Analyzes a resource function's return type.
fn analyze_resource_return_type(output: &syn::ReturnType) -> ResourceReturnTypeKind {
    match final_complete_return_kind(output, "ReadResourceResult") {
        Some(FinalCompleteReturnKind::Direct) => return ResourceReturnTypeKind::FinalComplete,
        Some(FinalCompleteReturnKind::Result) => {
            return ResourceReturnTypeKind::ResultFinalComplete;
        }
        Some(FinalCompleteReturnKind::McpResult) => {
            return ResourceReturnTypeKind::McpResultFinalComplete;
        }
        None => {}
    }
    match output {
        syn::ReturnType::Default => ResourceReturnTypeKind::Other, // () not typical for resources
        syn::ReturnType::Type(_, ty) => analyze_resource_type(ty),
    }
}

/// Analyzes a type for resource return type classification.
fn analyze_resource_type(ty: &Type) -> ResourceReturnTypeKind {
    if let Type::Path(type_path) = ty {
        if let Some(segment) = type_path.path.segments.last() {
            let type_name = segment.ident.to_string();

            match type_name.as_str() {
                "String" => return ResourceReturnTypeKind::String,
                "Vec" => {
                    // Check if it's Vec<ResourceContent>
                    if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                        if let Some(syn::GenericArgument::Type(Type::Path(inner_path))) =
                            args.args.first()
                        {
                            if inner_path
                                .path
                                .segments
                                .last()
                                .is_some_and(|s| s.ident == "ResourceContent")
                            {
                                return ResourceReturnTypeKind::VecResourceContent;
                            }
                        }
                    }
                }
                "Result" | "McpResult" => {
                    // Check the Ok type
                    if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                        if let Some(syn::GenericArgument::Type(inner_ty)) = args.args.first() {
                            let inner_kind = analyze_resource_type(inner_ty);
                            return match inner_kind {
                                ResourceReturnTypeKind::String => {
                                    if type_name == "McpResult" {
                                        ResourceReturnTypeKind::McpResultString
                                    } else {
                                        ResourceReturnTypeKind::ResultString
                                    }
                                }
                                ResourceReturnTypeKind::VecResourceContent => {
                                    if type_name == "McpResult" {
                                        ResourceReturnTypeKind::McpResultVecResourceContent
                                    } else {
                                        ResourceReturnTypeKind::ResultVecResourceContent
                                    }
                                }
                                _ => ResourceReturnTypeKind::Other,
                            };
                        }
                    }
                }
                _ => {}
            }
        }
    }
    ResourceReturnTypeKind::Other
}

/// Generates code to convert a resource function result to McpResult<Vec<ResourceContent>>.
///
/// The generated code handles:
/// - `String` → wrap in ResourceContent
/// - `Result<String, E>` → unwrap result, then wrap in ResourceContent
/// - `McpResult<String>` → unwrap result, then wrap in ResourceContent
/// - Other types → use ToString trait
///
/// The generated code uses `uri` and `mime_type` variables that must be in scope.
fn generate_resource_result_conversion(output: &syn::ReturnType, mime_type: &str) -> TokenStream2 {
    let kind = analyze_resource_return_type(output);

    match kind {
        ResourceReturnTypeKind::FinalComplete => quote! {
            Ok(result.payload.contents)
        },
        ResourceReturnTypeKind::ResultFinalComplete => quote! {
            result
                .map(|complete| complete.payload.contents)
                .map_err(|error| fastmcp_core::McpError::internal_error(error.to_string()))
        },
        ResourceReturnTypeKind::McpResultFinalComplete => quote! {
            Ok(result?.payload.contents)
        },
        ResourceReturnTypeKind::String => quote! {
            let text = result;
            Ok(vec![fastmcp_protocol::ResourceContent {
                uri: uri.to_string(),
                mime_type: Some(#mime_type.to_string()),
                text: Some(text),
                blob: None,
            }])
        },
        ResourceReturnTypeKind::VecResourceContent => quote! {
            Ok(result)
        },
        ResourceReturnTypeKind::ResultString => quote! {
            let text = result.map_err(|e| fastmcp_core::McpError::internal_error(e.to_string()))?;
            Ok(vec![fastmcp_protocol::ResourceContent {
                uri: uri.to_string(),
                mime_type: Some(#mime_type.to_string()),
                text: Some(text),
                blob: None,
            }])
        },
        ResourceReturnTypeKind::McpResultString => quote! {
            let text = result?;
            Ok(vec![fastmcp_protocol::ResourceContent {
                uri: uri.to_string(),
                mime_type: Some(#mime_type.to_string()),
                text: Some(text),
                blob: None,
            }])
        },
        ResourceReturnTypeKind::ResultVecResourceContent => quote! {
            result.map_err(|e| fastmcp_core::McpError::internal_error(e.to_string()))
        },
        ResourceReturnTypeKind::McpResultVecResourceContent => quote! {
            result
        },
        ResourceReturnTypeKind::Other => quote! {
            // Fallback: use ToString trait
            let text = result.to_string();
            Ok(vec![fastmcp_protocol::ResourceContent {
                uri: uri.to_string(),
                mime_type: Some(#mime_type.to_string()),
                text: Some(text),
                blob: None,
            }])
        },
    }
}

/// Generates the final resource result conversion for handlers that already
/// return the final resource result algebra.
fn generate_final_resource_result_conversion(output: &syn::ReturnType) -> Option<TokenStream2> {
    match final_complete_return_kind(output, "FinalReadResourceResult")? {
        FinalCompleteReturnKind::Direct => Some(quote! { Ok(result) }),
        FinalCompleteReturnKind::Result => Some(quote! {
            result.map_err(|error| fastmcp_core::McpError::internal_error(error.to_string()))
        }),
        FinalCompleteReturnKind::McpResult => Some(quote! { result }),
    }
}

/// Marks a final `#[resource]` expansion as the author of its cache hints.
fn explicit_final_resource_cache_hint_methods() -> TokenStream2 {
    let server = handler_crate_paths()
        .map(|paths| paths.server)
        .unwrap_or_else(|_| quote!(::fastmcp_server));
    quote! {
        fn final_resource_read_cache_hint_provenance(
            &self,
        ) -> #server::FinalResourceReadCacheHintProvenance {
            #server::FinalResourceReadCacheHintProvenance::Explicit
        }
    }
}

/// Converts a resource's complete-or-input-required final algebra without
/// projecting it through the legacy resource result surface.
fn generate_final_resource_outcome_conversion(output: &syn::ReturnType) -> Option<TokenStream2> {
    match final_method_outcome_return_kind(output, "FinalReadResourceResult")? {
        FinalCompleteReturnKind::Direct => Some(quote! { Ok(result) }),
        FinalCompleteReturnKind::Result => Some(quote! {
            result.map_err(|error| fastmcp_core::McpError::internal_error(error.to_string()))
        }),
        FinalCompleteReturnKind::McpResult => Some(quote! { result }),
    }
}

/// Emits the canonical final resource-outcome hook for a non-resumable macro
/// handler. Resumable handlers need a second hook that receives admitted MRTR
/// inputs and are generated by `generate_resource_mrtr_outcome_methods`.
fn generate_resource_final_outcome_method(
    is_async: bool,
    fn_name: &Ident,
    call_args: &TokenStream2,
    param_extractions: &[TokenStream2],
    conversion: &TokenStream2,
) -> TokenStream2 {
    let invocation = if is_async {
        quote! {
            let result: fastmcp_core::McpResult<fastmcp_server::FinalMethodOutcome<fastmcp_protocol::FinalReadResourceResult>> = async move {
                #(#param_extractions)*
                let result = #fn_name(#call_args).await;
                #conversion
            }.await;
        }
    } else {
        quote! {
            let result: fastmcp_core::McpResult<fastmcp_server::FinalMethodOutcome<fastmcp_protocol::FinalReadResourceResult>> = (|| {
                #(#param_extractions)*
                let result = #fn_name(#call_args);
                #conversion
            })();
        }
    };

    quote! {
        fn read_final_outcome_async_with_uri_in_request<'a>(
            &'a self,
            ctx: &'a fastmcp_core::McpContext,
            _request_cx: &'a fastmcp_core::Cx,
            _uri: &'a str,
            uri_params: &'a std::collections::HashMap<String, String>,
        ) -> fastmcp_server::BoxFuture<'a, fastmcp_core::McpOutcome<fastmcp_server::FinalMethodOutcome<fastmcp_protocol::FinalReadResourceResult>>> {
            Box::pin(async move {
                let _ = ctx;
                let _ = uri_params;
                #invocation
                match result {
                    Ok(value) => fastmcp_core::Outcome::Ok(value),
                    Err(error) => fastmcp_core::Outcome::Err(error),
                }
            })
        }
    }
}

fn generate_final_legacy_rejection(handler: &str, final_hook: &str) -> TokenStream2 {
    let message = format!("final #[{handler}] handlers must be invoked through {final_hook}");
    quote! {
        Err(fastmcp_core::McpError::internal_error(#message))
    }
}

fn generate_resource_execution_methods(
    is_async: bool,
    fn_name: &Ident,
    call_args: &TokenStream2,
    uri: &str,
    param_extractions: &[TokenStream2],
    result_conversion: &TokenStream2,
    final_result_conversion: Option<&TokenStream2>,
    final_outcome_conversion: Option<&TokenStream2>,
    emit_async_final_outcome: bool,
) -> TokenStream2 {
    let default_async_outcome_hook = if emit_async_final_outcome {
        quote! {
            fn read_final_outcome_async_with_uri_in_request<'a>(
                &'a self,
                ctx: &'a fastmcp_core::McpContext,
                request_cx: &'a fastmcp_core::Cx,
                uri: &'a str,
                uri_params: &'a std::collections::HashMap<String, String>,
            ) -> fastmcp_server::BoxFuture<
                'a,
                fastmcp_core::McpOutcome<
                    fastmcp_server::FinalMethodOutcome<fastmcp_protocol::FinalReadResourceResult>,
                >,
            > {
                Box::pin(async move {
                    match self
                        .read_async_with_uri_in_request(ctx, request_cx, uri, uri_params)
                        .await
                    {
                        fastmcp_core::Outcome::Ok(contents) => {
                            match ::fastmcp_server::promote_legacy_resource_contents(contents) {
                                Ok(complete) => fastmcp_core::Outcome::Ok(
                                    fastmcp_server::FinalMethodOutcome::Complete(complete),
                                ),
                                Err(error) => fastmcp_core::Outcome::Err(error),
                            }
                        }
                        fastmcp_core::Outcome::Err(error) => fastmcp_core::Outcome::Err(error),
                        fastmcp_core::Outcome::Cancelled(cancelled) => {
                            fastmcp_core::Outcome::Cancelled(cancelled)
                        }
                        fastmcp_core::Outcome::Panicked(panic) => {
                            fastmcp_core::Outcome::Panicked(panic)
                        }
                    }
                })
            }
        }
    } else {
        TokenStream2::new()
    };
    let modern_request_methods = quote! {
        fn read_async_with_uri_in_request<'a>(
            &'a self,
            ctx: &'a fastmcp_core::McpContext,
            _request_cx: &'a fastmcp_core::Cx,
            uri: &'a str,
            uri_params: &'a std::collections::HashMap<String, String>,
        ) -> fastmcp_server::BoxFuture<
            'a,
            fastmcp_core::McpOutcome<Vec<fastmcp_protocol::ResourceContent>>,
        > {
            self.read_async_with_uri(ctx, uri, uri_params)
        }

        fn read_final_async_with_uri_in_request<'a>(
            &'a self,
            ctx: &'a fastmcp_core::McpContext,
            _request_cx: &'a fastmcp_core::Cx,
            uri: &'a str,
            uri_params: &'a std::collections::HashMap<String, String>,
        ) -> fastmcp_server::BoxFuture<
            'a,
            fastmcp_core::McpOutcome<
                fastmcp_protocol::CompleteResult<fastmcp_protocol::FinalReadResourceResult>,
            >,
        > {
            self.read_final_async_with_uri(ctx, uri, uri_params)
        }

        #default_async_outcome_hook
    };
    let final_outcome_method =
        final_outcome_conversion.map_or_else(TokenStream2::new, |conversion| {
            generate_resource_final_outcome_method(
                is_async,
                fn_name,
                call_args,
                param_extractions,
                conversion,
            )
        });
    let explicit_cache_hints =
        if final_result_conversion.is_some() || final_outcome_conversion.is_some() {
            explicit_final_resource_cache_hint_methods()
        } else {
            TokenStream2::new()
        };
    if !is_async {
        let final_method = final_result_conversion.map_or_else(TokenStream2::new, |conversion| {
            quote! {
                fn read_final(
                    &self,
                    ctx: &fastmcp_core::McpContext,
                ) -> fastmcp_core::McpResult<
                    fastmcp_protocol::CompleteResult<fastmcp_protocol::FinalReadResourceResult>,
                > {
                    let uri_params = std::collections::HashMap::new();
                    self.read_final_with_uri(ctx, #uri, &uri_params)
                }

                fn read_final_with_uri(
                    &self,
                    ctx: &fastmcp_core::McpContext,
                    uri: &str,
                    uri_params: &std::collections::HashMap<String, String>,
                ) -> fastmcp_core::McpResult<
                    fastmcp_protocol::CompleteResult<fastmcp_protocol::FinalReadResourceResult>,
                > {
                    #(#param_extractions)*
                    let result = #fn_name(#call_args);
                    #conversion
                }
            }
        });
        let legacy_methods = if final_result_conversion.is_some() {
            quote! {
                fn read(
                    &self,
                    _ctx: &fastmcp_core::McpContext,
                ) -> fastmcp_core::McpResult<Vec<fastmcp_protocol::ResourceContent>> {
                    #result_conversion
                }
            }
        } else {
            quote! {
                fn read(
                    &self,
                    ctx: &fastmcp_core::McpContext,
                ) -> fastmcp_core::McpResult<Vec<fastmcp_protocol::ResourceContent>> {
                    let uri_params = std::collections::HashMap::new();
                    self.read_with_uri(ctx, #uri, &uri_params)
                }

                fn read_with_uri(
                    &self,
                    ctx: &fastmcp_core::McpContext,
                    uri: &str,
                    uri_params: &std::collections::HashMap<String, String>,
                ) -> fastmcp_core::McpResult<Vec<fastmcp_protocol::ResourceContent>> {
                    #(#param_extractions)*
                    let result = #fn_name(#call_args);
                    #result_conversion
                }

                fn read_async_with_uri<'a>(
                    &'a self,
                    ctx: &'a fastmcp_core::McpContext,
                    uri: &'a str,
                    uri_params: &'a std::collections::HashMap<String, String>,
                ) -> fastmcp_server::BoxFuture<
                    'a,
                    fastmcp_core::McpOutcome<Vec<fastmcp_protocol::ResourceContent>>,
                > {
                    Box::pin(async move {
                        match self.read_with_uri(ctx, uri, uri_params) {
                            Ok(value) => fastmcp_core::Outcome::Ok(value),
                            Err(error) => fastmcp_core::Outcome::Err(error),
                        }
                    })
                }
            }
        };
        return quote! {
            #legacy_methods
            #explicit_cache_hints
            #final_method
            #final_outcome_method
            #modern_request_methods
        };
    }

    let final_method = final_result_conversion.map_or_else(TokenStream2::new, |conversion| {
        quote! {
            fn read_final_async_with_uri<'a>(
                &'a self,
                ctx: &'a fastmcp_core::McpContext,
                uri: &'a str,
                uri_params: &'a std::collections::HashMap<String, String>,
            ) -> fastmcp_server::BoxFuture<
                'a,
                fastmcp_core::McpOutcome<
                    fastmcp_protocol::CompleteResult<fastmcp_protocol::FinalReadResourceResult>,
                >,
            > {
                Box::pin(async move {
                    let result: fastmcp_core::McpResult<
                        fastmcp_protocol::CompleteResult<fastmcp_protocol::FinalReadResourceResult>,
                    > = async move {
                        #(#param_extractions)*
                        let result = #fn_name(#call_args).await;
                        #conversion
                    }.await;

                    match result {
                        Ok(value) => fastmcp_core::Outcome::Ok(value),
                        Err(error) => fastmcp_core::Outcome::Err(error),
                    }
                })
            }

            fn read_final_async<'a>(
                &'a self,
                ctx: &'a fastmcp_core::McpContext,
            ) -> fastmcp_server::BoxFuture<
                'a,
                fastmcp_core::McpOutcome<
                    fastmcp_protocol::CompleteResult<fastmcp_protocol::FinalReadResourceResult>,
                >,
            > {
                Box::pin(async move {
                    let uri_params = std::collections::HashMap::new();
                    self.read_final_async_with_uri(ctx, #uri, &uri_params).await
                })
            }
        }
    });

    let legacy_methods = if final_result_conversion.is_some() {
        quote! {
            fn read(
                &self,
                _ctx: &fastmcp_core::McpContext,
            ) -> fastmcp_core::McpResult<Vec<fastmcp_protocol::ResourceContent>> {
                #result_conversion
            }
        }
    } else {
        quote! {
            fn read(
                &self,
                _ctx: &fastmcp_core::McpContext,
            ) -> fastmcp_core::McpResult<Vec<fastmcp_protocol::ResourceContent>> {
                Err(fastmcp_core::McpError::internal_error(
                    "async #[resource] handlers must be invoked through ResourceHandler::read_async",
                ))
            }

            fn read_async_with_uri<'a>(
                &'a self,
                ctx: &'a fastmcp_core::McpContext,
                uri: &'a str,
                uri_params: &'a std::collections::HashMap<String, String>,
            ) -> fastmcp_server::BoxFuture<
                'a,
                fastmcp_core::McpOutcome<Vec<fastmcp_protocol::ResourceContent>>,
            > {
                Box::pin(async move {
                    let result: fastmcp_core::McpResult<
                        Vec<fastmcp_protocol::ResourceContent>,
                    > = async move {
                        #(#param_extractions)*
                        let result = #fn_name(#call_args).await;
                        #result_conversion
                    }.await;

                    match result {
                        Ok(value) => fastmcp_core::Outcome::Ok(value),
                        Err(error) => fastmcp_core::Outcome::Err(error),
                    }
                })
            }

            fn read_async<'a>(
                &'a self,
                ctx: &'a fastmcp_core::McpContext,
            ) -> fastmcp_server::BoxFuture<
                'a,
                fastmcp_core::McpOutcome<Vec<fastmcp_protocol::ResourceContent>>,
            > {
                Box::pin(async move {
                    let uri_params = std::collections::HashMap::new();
                    self.read_async_with_uri(ctx, #uri, &uri_params).await
                })
            }
        }
    };

    quote! {
        #legacy_methods
        #explicit_cache_hints
        #final_method
        #final_outcome_method
        #modern_request_methods
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod async_handler_expansion_tests {
    #[cfg(not(feature = "apps"))]
    use super::TOOL_APPS_UI_FEATURE_DIAGNOSTIC;
    #[cfg(feature = "apps")]
    use super::generate_tool_apps_metadata;
    use super::{
        ToolAttrs, found_crate_path, generate_final_prompt_result_conversion,
        generate_final_resource_outcome_conversion, generate_final_resource_result_conversion,
        generate_final_tool_outcome_conversion, generate_final_tool_payload_projection,
        generate_final_tool_result_conversion, generate_prompt_execution_methods,
        generate_resource_execution_methods, generate_tool_execution_methods,
        validate_final_handler_return,
    };
    #[cfg(feature = "tasks")]
    use super::{generate_tool_tasks_declaration, validate_tool_tasks_return};
    use proc_macro_crate::FoundCrate;
    use quote::{format_ident, quote};

    fn assert_direct_async_expansion(tokens: proc_macro2::TokenStream, async_method: &str) {
        let expansion = tokens.to_string();
        assert!(expansion.contains(async_method), "{expansion}");
        assert!(expansion.contains(". await"), "{expansion}");
        assert!(!expansion.contains("block_on"), "{expansion}");
        assert!(!expansion.contains("runtime ::"), "{expansion}");
    }

    #[test]
    fn async_tool_expansion_awaits_without_runtime_reentry() {
        let fn_name = format_ident!("example_tool");
        let param = format_ident!("value");
        let tokens = generate_tool_execution_methods(
            true,
            true,
            &fn_name,
            &[&param],
            &[quote! { let value: String = String::new(); }],
            &quote! { Ok(vec![]) },
            None,
            None,
        );

        assert_direct_async_expansion(tokens.clone(), "fn call_async");
        assert_direct_async_expansion(tokens, "fn call_final_async");
    }

    #[test]
    fn async_resource_expansion_awaits_without_runtime_reentry() {
        let fn_name = format_ident!("example_resource");
        let generated = generate_resource_execution_methods(
            true,
            &fn_name,
            &quote! { ctx },
            "example://resource",
            &[],
            &quote! { Ok(vec![]) },
            None,
            None,
            true,
        );

        assert_direct_async_expansion(generated.clone(), "fn read_async_with_uri");
        assert_direct_async_expansion(generated, "fn read_final_outcome_async_with_uri_in_request");
    }

    #[test]
    fn async_prompt_expansion_awaits_without_runtime_reentry() {
        let fn_name = format_ident!("example_prompt");
        let param = format_ident!("value");
        let tokens = generate_prompt_execution_methods(
            true,
            true,
            &fn_name,
            &[param],
            &[quote! { let value: String = String::new(); }],
            &quote! { Ok(vec![]) },
            None,
            true,
        );

        assert_direct_async_expansion(tokens, "fn get_async");
    }

    #[test]
    fn sync_tool_expansion_keeps_the_synchronous_entry_point() {
        let fn_name = format_ident!("sync_tool");
        let tokens = generate_tool_execution_methods(
            false,
            false,
            &fn_name,
            &[],
            &[],
            &quote! { Ok(vec![]) },
            None,
            None,
        )
        .to_string();

        assert!(tokens.contains("fn call"), "{tokens}");
        assert!(!tokens.contains("fn call_async <"), "{tokens}");
        assert!(!tokens.contains("fn call_final ("), "{tokens}");
        assert!(tokens.contains("fn call_async_in_request"), "{tokens}");
        assert!(
            tokens.contains("fn call_final_outcome_async_in_request"),
            "{tokens}"
        );
    }

    #[test]
    fn modern_request_contract_expands_for_tool_resource_and_prompt() {
        let tool_name = format_ident!("modern_tool");
        let tool_output: syn::ReturnType = syn::parse_quote!(
            -> fastmcp_protocol::CompleteResult<fastmcp_protocol::FinalCallToolResult>
        );
        let tool_conversion = generate_final_tool_result_conversion(&tool_output)
            .expect("final tool output selects the final hook");
        let tool = generate_tool_execution_methods(
            true,
            true,
            &tool_name,
            &[],
            &[],
            &quote! { Ok(vec![]) },
            Some(&tool_conversion),
            None,
        )
        .to_string();
        assert!(tool.contains("fn call_async_in_request"), "{tool}");
        assert!(tool.contains("fn call_final_async_in_request"), "{tool}");
        assert!(
            tool.contains("fn call_final_outcome_async_in_request"),
            "{tool}"
        );
        assert!(tool.contains("fastmcp_core :: Cx"), "{tool}");
        assert!(tool.contains("FinalToolOutcome :: Complete"), "{tool}");

        let resource_name = format_ident!("modern_resource");
        let resource_output: syn::ReturnType = syn::parse_quote!(
            -> fastmcp_protocol::CompleteResult<fastmcp_protocol::FinalReadResourceResult>
        );
        let resource_conversion = generate_final_resource_result_conversion(&resource_output)
            .expect("final resource output selects the final hook");
        let resource = generate_resource_execution_methods(
            true,
            &resource_name,
            &quote! { ctx },
            "modern://resource",
            &[],
            &quote! { Ok(vec![]) },
            Some(&resource_conversion),
            None,
            false,
        )
        .to_string();
        assert!(
            resource.contains("fn read_async_with_uri_in_request"),
            "{resource}"
        );
        assert!(
            resource.contains("fn read_final_async_with_uri_in_request"),
            "{resource}"
        );
        assert!(
            resource.contains("FinalResourceReadCacheHintProvenance :: Explicit"),
            "{resource}"
        );

        let prompt_name = format_ident!("modern_prompt");
        let prompt_output: syn::ReturnType = syn::parse_quote!(
            -> fastmcp_protocol::CompleteResult<fastmcp_protocol::FinalGetPromptResult>
        );
        let prompt_conversion = generate_final_prompt_result_conversion(&prompt_output)
            .expect("final prompt output selects the final hook");
        let prompt = generate_prompt_execution_methods(
            true,
            true,
            &prompt_name,
            &[],
            &[],
            &quote! { Ok(vec![]) },
            Some(&prompt_conversion),
            true,
        )
        .to_string();
        assert!(prompt.contains("fn get_async_in_request"), "{prompt}");
        assert!(prompt.contains("fn get_final_async_in_request"), "{prompt}");
        assert!(
            prompt.contains("fn get_final_outcome_async_in_request"),
            "{prompt}"
        );
    }

    #[test]
    fn async_final_resource_outcome_expands_the_router_outcome_hook() {
        let resource_name = format_ident!("async_final_resource_outcome");
        let resource_output: syn::ReturnType = syn::parse_quote!(
            -> fastmcp_server::FinalMethodOutcome<fastmcp_protocol::FinalReadResourceResult>
        );
        let outcome_conversion = generate_final_resource_outcome_conversion(&resource_output)
            .expect("final resource outcome selects the final outcome hook");
        let generated = generate_resource_execution_methods(
            true,
            &resource_name,
            &quote! { ctx, collection, revision },
            "mcp://resource{?collection*,revision*}",
            &[
                quote! { let collection: String = uri_params.get("collection").expect("collection").clone(); },
                quote! { let revision: String = uri_params.get("revision").expect("revision").clone(); },
            ],
            &quote! { Err(fastmcp_core::McpError::internal_error("legacy")) },
            None,
            Some(&outcome_conversion),
            false,
        );

        assert_direct_async_expansion(
            generated.clone(),
            "fn read_final_outcome_async_with_uri_in_request",
        );
        let tokens = generated.to_string();
        assert!(tokens.contains("FinalMethodOutcome"), "{tokens}");
        assert!(tokens.contains("collection"), "{tokens}");
        assert!(tokens.contains("revision"), "{tokens}");
    }

    #[test]
    fn modern_request_contract_rejects_one_dimension_cross_handler_signature() {
        let accepted: syn::ReturnType = syn::parse_quote!(
            -> fastmcp_protocol::CompleteResult<fastmcp_protocol::FinalGetPromptResult>
        );
        let rejected: syn::ReturnType = syn::parse_quote!(
            -> fastmcp_protocol::CompleteResult<fastmcp_protocol::FinalReadResourceResult>
        );

        assert!(
            validate_final_handler_return(
                &accepted,
                "prompt",
                "GetPromptResult",
                Some("FinalGetPromptResult"),
                "Vec<PromptMessage>",
            )
            .is_ok()
        );
        let error = validate_final_handler_return(
            &rejected,
            "prompt",
            "GetPromptResult",
            Some("FinalGetPromptResult"),
            "Vec<PromptMessage>",
        )
        .expect_err("changing only the final payload type must fail closed");

        assert!(error.to_string().contains("FinalGetPromptResult"));
        assert!(error.to_string().contains("legacy handler"));
    }

    #[test]
    fn final_tool_expansion_keeps_exact_final_result_hook() {
        let fn_name = format_ident!("final_tool");
        let output: syn::ReturnType = syn::parse_quote!(
            -> fastmcp_protocol::CompleteResult<fastmcp_protocol::FinalCallToolResult>
        );
        let conversion = generate_final_tool_result_conversion(&output)
            .expect("the complete final tool result selects the final hook");
        let tokens = generate_tool_execution_methods(
            false,
            false,
            &fn_name,
            &[],
            &[],
            &quote! { Ok(vec![]) },
            Some(&conversion),
            None,
        )
        .to_string();

        assert!(tokens.contains("fn call_final"), "{tokens}");
        assert!(tokens.contains("FinalCallToolResult"), "{tokens}");
        assert!(!tokens.contains("result . payload"), "{tokens}");
    }

    #[test]
    fn final_tool_outcome_return_forms_select_the_disjoint_hook() {
        let fn_name = format_ident!("final_tool_outcome");
        for output in [
            syn::parse_quote!(-> fastmcp_server::FinalToolOutcome),
            syn::parse_quote!(-> Result<fastmcp_server::FinalToolOutcome, std::io::Error>),
            syn::parse_quote!(-> fastmcp_core::McpResult<fastmcp_server::FinalToolOutcome>),
        ] {
            let conversion = generate_final_tool_outcome_conversion(&output)
                .expect("every supported final tool outcome return form selects the outcome hook");
            let tokens = generate_tool_execution_methods(
                false,
                false,
                &fn_name,
                &[],
                &[],
                &quote! { unreachable!() },
                None,
                Some(&conversion),
            )
            .to_string();

            assert!(tokens.contains("fn call_final_outcome"), "{tokens}");
            assert!(tokens.contains("FinalToolOutcome"), "{tokens}");
            // The path lives inside a string literal, which stringifies
            // verbatim rather than with token-stream spacing.
            assert!(
                tokens.contains("must be invoked through ToolHandler::call_final_outcome"),
                "{tokens}"
            );
            assert!(!tokens.contains("fn call_final ("), "{tokens}");
        }
    }

    #[cfg(feature = "tasks")]
    #[test]
    fn tool_tasks_opt_in_is_bound_to_canonical_final_tool_outcomes() {
        let attrs: ToolAttrs = syn::parse_str("tasks").expect("the bare tasks opt-in parses");
        assert!(attrs.tasks);

        for output in [
            syn::parse_quote!(-> fastmcp_rust::FinalToolOutcome),
            syn::parse_quote!(-> Result<fastmcp_rust::FinalToolOutcome, std::io::Error>),
            syn::parse_quote!(-> fastmcp_core::McpResult<fastmcp_rust::FinalToolOutcome>),
        ] {
            validate_tool_tasks_return(&output)
                .expect("each canonical final tool outcome return enables the tasks opt-in");
        }

        let incompatible: syn::ReturnType = syn::parse_quote!(
            -> fastmcp_rust::CompleteResult<fastmcp_rust::FinalCallToolResult>
        );
        let error = validate_tool_tasks_return(&incompatible)
            .expect_err("changing only the return algebra must reject the tasks opt-in");
        assert_eq!(
            error.to_string(),
            "#[tool(tasks)] requires a canonical FinalToolOutcome return type: fastmcp_rust::FinalToolOutcome, Result<fastmcp_rust::FinalToolOutcome, E>, or McpResult<fastmcp_rust::FinalToolOutcome>",
        );

        let declaration = generate_tool_tasks_declaration(true).to_string();
        assert!(
            declaration.contains("fn declares_final_tasks"),
            "{declaration}"
        );
        assert!(declaration.contains("true"), "{declaration}");
        assert!(generate_tool_tasks_declaration(false).is_empty());
    }

    #[cfg(not(feature = "tasks"))]
    #[test]
    fn tool_tasks_forms_require_the_feature_before_expansion() {
        const DIAGNOSTIC: &str = "#[tool(tasks)] requires the fastmcp-derive `tasks` feature; enable fastmcp-rust's `tasks` feature or fastmcp-derive's `tasks` feature";

        for attributes in ["tasks", "tasks = true", "tasks()"] {
            let error = syn::parse_str::<ToolAttrs>(attributes)
                .expect_err("every Tasks-specific spelling must be feature-gated");
            assert_eq!(error.to_string(), DIAGNOSTIC, "{attributes}");
        }
    }

    #[cfg(feature = "apps")]
    #[test]
    fn tool_apps_ui_syntax_parses_when_the_feature_is_enabled() {
        let attrs = syn::parse_str::<ToolAttrs>(
            "ui(resource_uri = \"ui://weather/dashboard\", visibility = [\"model\", \"app\"])",
        )
        .expect("the Apps UI declaration parses with the Apps feature enabled");
        assert_eq!(
            attrs
                .apps_ui
                .as_ref()
                .expect("the parsed Apps UI declaration is retained")
                .resource_uri,
            "ui://weather/dashboard"
        );
        let metadata = generate_tool_apps_metadata(attrs.apps_ui.as_ref()).to_string();
        assert!(metadata.contains("final_metadata"), "{metadata}");
        assert!(metadata.contains("McpAppsToolMetadata"), "{metadata}");
    }

    #[cfg(not(feature = "apps"))]
    #[test]
    fn tool_apps_ui_syntax_requires_the_feature_before_expansion() {
        let error = syn::parse_str::<ToolAttrs>(
            "ui(resource_uri = \"ui://weather/dashboard\", visibility = [\"model\", \"app\"])",
        )
        .expect_err("Apps UI syntax must remain unavailable without the feature");
        assert_eq!(error.to_string(), TOOL_APPS_UI_FEATURE_DIAGNOSTIC);
    }

    #[test]
    fn final_tool_outcome_rejects_ambiguous_lookalike_type() {
        let accepted: syn::ReturnType = syn::parse_quote!(
            -> fastmcp_rust::FinalToolOutcome
        );
        let ambiguous: syn::ReturnType = syn::parse_quote!(
            -> FinalToolOutcome
        );
        let consumer_local: syn::ReturnType = syn::parse_quote!(
            -> crate::FinalToolOutcome
        );

        assert!(
            validate_final_handler_return(
                &accepted,
                "tool",
                "FinalCallToolResult",
                None,
                "Vec<Content>",
            )
            .is_ok()
        );
        let error = validate_final_handler_return(
            &ambiguous,
            "tool",
            "FinalCallToolResult",
            None,
            "Vec<Content>",
        )
        .expect_err("bare same-named return type must fail before expansion");

        assert!(error.to_string().contains("fastmcp_rust::FinalToolOutcome"));
        let error = validate_final_handler_return(
            &consumer_local,
            "tool",
            "FinalCallToolResult",
            None,
            "Vec<Content>",
        )
        .expect_err("consumer-local same-named return type must fail before expansion");
        assert!(error.to_string().contains("fastmcp_rust::FinalToolOutcome"));
    }

    #[test]
    fn final_tool_hook_preserves_complete_result_metadata_and_open_fields() {
        let fn_name = format_ident!("final_tool");
        let output: syn::ReturnType = syn::parse_quote!(
            -> fastmcp_protocol::CompleteResult<fastmcp_protocol::FinalCallToolResult>
        );
        let final_conversion = generate_final_tool_result_conversion(&output)
            .expect("the complete final tool result selects the final hook");
        let legacy_conversion = generate_final_tool_payload_projection(quote! { result.payload });
        let tokens = generate_tool_execution_methods(
            false,
            false,
            &fn_name,
            &[],
            &[],
            &legacy_conversion,
            Some(&final_conversion),
            None,
        )
        .to_string();
        let (_, final_hook) = tokens
            .split_once("fn call_final")
            .expect("final tool expansion has a direct final hook");

        assert_eq!(final_conversion.to_string(), "Ok (result)");
        assert!(final_hook.contains("CompleteResult"), "{final_hook}");
        assert!(final_hook.contains("FinalCallToolResult"), "{final_hook}");
        assert!(final_hook.contains("Ok (result)"), "{final_hook}");
        // Guard against payload PROJECTION (`result . payload`), not the
        // `Outcome::Panicked(payload)` binding of the 4-valued bridge.
        assert!(!final_hook.contains(". payload"), "{final_hook}");
        assert!(!final_hook.contains("content . into_iter"), "{final_hook}");

        let async_tokens = generate_tool_execution_methods(
            true,
            false,
            &fn_name,
            &[],
            &[],
            &legacy_conversion,
            Some(&final_conversion),
            None,
        );
        assert_direct_async_expansion(async_tokens.clone(), "fn call_final_async");
        let async_expansion = async_tokens.to_string();
        let (_, final_async_hook) = async_expansion
            .split_once("fn call_final_async")
            .expect("async final tool expansion has a direct final hook");
        assert!(
            final_async_hook.contains("Ok (result)"),
            "{final_async_hook}"
        );
        // Same precision as the sync hook: forbid projection, not the
        // Outcome::Panicked binding.
        assert!(
            !final_async_hook.contains(". payload"),
            "{final_async_hook}"
        );
    }

    #[test]
    fn final_resource_and_prompt_hooks_preserve_final_result_algebras() {
        let resource_name = format_ident!("final_resource");
        let resource_param_extractions = [quote! {
            let segment: String = uri_params
                .get("segment")
                .expect("matched resource URI segment")
                .clone();
        }];
        let resource_output: syn::ReturnType = syn::parse_quote!(
            -> fastmcp_protocol::CompleteResult<fastmcp_protocol::FinalReadResourceResult>
        );
        let resource_conversion = generate_final_resource_result_conversion(&resource_output)
            .expect("the complete final resource result selects the final hook");
        let resource_tokens = generate_resource_execution_methods(
            false,
            &resource_name,
            &quote! { ctx, segment },
            "example://resource",
            &resource_param_extractions,
            &quote! { Err(fastmcp_core::McpError::internal_error("legacy")) },
            Some(&resource_conversion),
            None,
            false,
        )
        .to_string();
        let (resource_legacy_hook, resource_final_hook) = resource_tokens
            .split_once("fn read_final")
            .expect("final resource expansion has a direct final hook");

        assert_eq!(resource_conversion.to_string(), "Ok (result)");
        assert!(
            resource_legacy_hook.contains("legacy"),
            "{resource_legacy_hook}"
        );
        assert!(
            !resource_legacy_hook.contains("final_resource ("),
            "a legacy projection must reject before evaluating the final resource: {resource_legacy_hook}"
        );
        assert!(resource_final_hook.contains("FinalReadResourceResult"));
        assert!(resource_final_hook.contains("uri_params . get"));
        assert!(resource_final_hook.contains("segment"));
        assert!(
            resource_tokens.contains("FinalResourceReadCacheHintProvenance :: Explicit"),
            "{resource_tokens}"
        );
        assert!(resource_final_hook.contains("Ok (result)"));
        assert!(!resource_final_hook.contains("payload"));
        assert!(!resource_final_hook.contains("contents . into_iter"));

        let resource_async_tokens = generate_resource_execution_methods(
            true,
            &resource_name,
            &quote! { ctx, segment },
            "example://resource",
            &resource_param_extractions,
            &quote! { Err(fastmcp_core::McpError::internal_error("legacy")) },
            Some(&resource_conversion),
            None,
            false,
        );
        assert_direct_async_expansion(
            resource_async_tokens.clone(),
            "fn read_final_async_with_uri",
        );
        let resource_async_expansion = resource_async_tokens.to_string();
        let (resource_legacy_async_hook, resource_final_async_hook) = resource_async_expansion
            .split_once("fn read_final_async_with_uri")
            .expect("async final resource expansion has a direct final hook");
        assert!(
            !resource_legacy_async_hook.contains("final_resource ("),
            "a legacy projection must reject before awaiting the final resource: {resource_legacy_async_hook}"
        );
        assert!(resource_final_async_hook.contains("Ok (result)"));
        assert!(resource_final_async_hook.contains("uri_params . get"));
        assert!(resource_final_async_hook.contains("segment"));
        assert!(!resource_final_async_hook.contains("payload"));

        let prompt_name = format_ident!("final_prompt");
        let prompt_param = format_ident!("topic");
        let prompt_params = [prompt_param];
        let prompt_param_extractions = [quote! {
            let topic: String = arguments
                .get("topic")
                .expect("prompt argument")
                .clone();
        }];
        let prompt_output: syn::ReturnType = syn::parse_quote!(
            -> fastmcp_protocol::CompleteResult<fastmcp_protocol::FinalGetPromptResult>
        );
        let prompt_conversion = generate_final_prompt_result_conversion(&prompt_output)
            .expect("the complete final prompt result selects the final hook");
        let prompt_tokens = generate_prompt_execution_methods(
            false,
            false,
            &prompt_name,
            &prompt_params,
            &prompt_param_extractions,
            &quote! { Err(fastmcp_core::McpError::internal_error("legacy")) },
            Some(&prompt_conversion),
            false,
        )
        .to_string();
        let (prompt_legacy_hook, prompt_final_hook) = prompt_tokens
            .split_once("fn get_final")
            .expect("final prompt expansion has a direct final hook");

        assert_eq!(prompt_conversion.to_string(), "Ok (result)");
        assert!(
            prompt_legacy_hook.contains("legacy"),
            "{prompt_legacy_hook}"
        );
        assert!(
            !prompt_legacy_hook.contains("final_prompt ("),
            "a legacy projection must reject before evaluating the final prompt: {prompt_legacy_hook}"
        );
        assert!(prompt_final_hook.contains("FinalGetPromptResult"));
        assert!(prompt_final_hook.contains("arguments . get"));
        assert!(prompt_final_hook.contains("topic"));
        assert!(prompt_final_hook.contains("Ok (result)"));
        assert!(!prompt_final_hook.contains("payload"));
        assert!(!prompt_final_hook.contains("messages . into_iter"));

        let prompt_async_tokens = generate_prompt_execution_methods(
            true,
            false,
            &prompt_name,
            &prompt_params,
            &prompt_param_extractions,
            &quote! { Err(fastmcp_core::McpError::internal_error("legacy")) },
            Some(&prompt_conversion),
            true,
        );
        assert_direct_async_expansion(prompt_async_tokens.clone(), "fn get_final_async");
        let prompt_async_expansion = prompt_async_tokens.to_string();
        let (prompt_legacy_async_hook, prompt_final_async_hook) = prompt_async_expansion
            .split_once("fn get_final_async")
            .expect("async final prompt expansion has a direct final hook");
        assert!(
            !prompt_legacy_async_hook.contains("final_prompt ("),
            "a legacy projection must reject before awaiting the final prompt: {prompt_legacy_async_hook}"
        );
        assert!(prompt_final_async_hook.contains("Ok (result)"));
        assert!(prompt_final_async_hook.contains("arguments . get"));
        assert!(prompt_final_async_hook.contains("topic"));
        assert!(!prompt_final_async_hook.contains("payload"));
    }

    #[test]
    fn final_resource_and_prompt_signatures_reject_other_final_payload_with_one_type_change() {
        let accepted: syn::ReturnType = syn::parse_quote!(
            -> fastmcp_protocol::CompleteResult<fastmcp_protocol::FinalReadResourceResult>
        );
        let rejected: syn::ReturnType = syn::parse_quote!(
            -> fastmcp_protocol::CompleteResult<fastmcp_protocol::FinalGetPromptResult>
        );

        assert!(
            validate_final_handler_return(
                &accepted,
                "resource",
                "ReadResourceResult",
                Some("FinalReadResourceResult"),
                "Vec<ResourceContent>",
            )
            .is_ok()
        );
        let error = validate_final_handler_return(
            &rejected,
            "resource",
            "ReadResourceResult",
            Some("FinalReadResourceResult"),
            "Vec<ResourceContent>",
        )
        .expect_err("changing only the final payload type must fail closed");

        assert!(error.to_string().contains("FinalReadResourceResult"));
        assert!(error.to_string().contains("legacy handler"));

        assert!(
            validate_final_handler_return(
                &rejected,
                "prompt",
                "GetPromptResult",
                Some("FinalGetPromptResult"),
                "Vec<PromptMessage>",
            )
            .is_ok()
        );
        let error = validate_final_handler_return(
            &accepted,
            "prompt",
            "GetPromptResult",
            Some("FinalGetPromptResult"),
            "Vec<PromptMessage>",
        )
        .expect_err("changing only the final payload type must fail closed");

        assert!(error.to_string().contains("FinalGetPromptResult"));
        assert!(error.to_string().contains("legacy handler"));
    }

    #[test]
    fn final_tool_signature_rejects_legacy_payload_with_one_type_change() {
        let accepted: syn::ReturnType = syn::parse_quote!(
            -> fastmcp_protocol::CompleteResult<fastmcp_protocol::FinalCallToolResult>
        );
        let rejected: syn::ReturnType = syn::parse_quote!(
            -> fastmcp_protocol::CompleteResult<fastmcp_protocol::CallToolResult>
        );

        assert!(
            validate_final_handler_return(
                &accepted,
                "tool",
                "FinalCallToolResult",
                None,
                "Vec<Content>",
            )
            .is_ok()
        );
        let error = validate_final_handler_return(
            &rejected,
            "tool",
            "FinalCallToolResult",
            None,
            "Vec<Content>",
        )
        .expect_err("changing only result payload type must fail closed");

        assert!(error.to_string().contains("FinalCallToolResult"));
        assert!(error.to_string().contains("legacy handler"));
    }

    #[test]
    fn final_result_wrapper_forms_select_the_direct_modern_hooks() {
        let tool_result: syn::ReturnType = syn::parse_quote!(
            -> Result<
                fastmcp_protocol::CompleteResult<fastmcp_protocol::FinalCallToolResult>,
                std::io::Error,
            >
        );
        let tool_mcp_result: syn::ReturnType = syn::parse_quote!(
            -> fastmcp_core::McpResult<
                fastmcp_protocol::CompleteResult<fastmcp_protocol::FinalCallToolResult>,
            >
        );
        assert!(
            generate_final_tool_result_conversion(&tool_result)
                .expect("Result final tool return selects the direct hook")
                .to_string()
                .contains("map_err")
        );
        assert_eq!(
            generate_final_tool_result_conversion(&tool_mcp_result)
                .expect("McpResult final tool return selects the direct hook")
                .to_string(),
            "result"
        );

        let resource_result: syn::ReturnType = syn::parse_quote!(
            -> Result<
                fastmcp_protocol::CompleteResult<fastmcp_protocol::FinalReadResourceResult>,
                std::io::Error,
            >
        );
        let resource_mcp_result: syn::ReturnType = syn::parse_quote!(
            -> fastmcp_core::McpResult<
                fastmcp_protocol::CompleteResult<fastmcp_protocol::FinalReadResourceResult>,
            >
        );
        assert!(
            generate_final_resource_result_conversion(&resource_result)
                .expect("Result final resource return selects the direct hook")
                .to_string()
                .contains("map_err")
        );
        assert_eq!(
            generate_final_resource_result_conversion(&resource_mcp_result)
                .expect("McpResult final resource return selects the direct hook")
                .to_string(),
            "result"
        );

        let prompt_result: syn::ReturnType = syn::parse_quote!(
            -> Result<
                fastmcp_protocol::CompleteResult<fastmcp_protocol::FinalGetPromptResult>,
                std::io::Error,
            >
        );
        let prompt_mcp_result: syn::ReturnType = syn::parse_quote!(
            -> fastmcp_core::McpResult<
                fastmcp_protocol::CompleteResult<fastmcp_protocol::FinalGetPromptResult>,
            >
        );
        assert!(
            generate_final_prompt_result_conversion(&prompt_result)
                .expect("Result final prompt return selects the direct hook")
                .to_string()
                .contains("map_err")
        );
        assert_eq!(
            generate_final_prompt_result_conversion(&prompt_mcp_result)
                .expect("McpResult final prompt return selects the direct hook")
                .to_string(),
            "result"
        );
    }

    #[test]
    fn final_tool_projection_matches_open_content_without_erasing_wire_fields() {
        let tokens = generate_final_tool_payload_projection(quote! { result.payload }).to_string();

        assert!(tokens.matches("..").count() >= 6, "{tokens}");
        assert!(tokens.contains("has_only_wire_fields"), "{tokens}");
        assert!(
            tokens.contains("serde_json :: to_value (& content)"),
            "{tokens}"
        );
        assert!(tokens.contains("exact legacy projection"), "{tokens}");
    }

    #[test]
    fn macro_source_contains_no_private_runtime_bridge() {
        let forbidden = ["runtime", "::", "block_on"].concat();
        assert!(!include_str!("lib.rs").contains(&forbidden));
    }

    #[test]
    fn renamed_facade_dependency_becomes_an_absolute_rust_path() {
        let path = found_crate_path(FoundCrate::Name("my_fastmcp".to_string()), "fastmcp-rust");
        assert_eq!(path.to_string(), ":: my_fastmcp");
    }
}

/// Generates a JSON schema type for a Rust type.
fn type_to_json_schema(ty: &Type) -> TokenStream2 {
    let Type::Path(type_path) = ty else {
        return quote! { serde_json::json!({}) };
    };

    let segment = type_path.path.segments.last().unwrap();
    let type_name = segment.ident.to_string();

    match type_name.as_str() {
        "String" | "str" => quote! {
            serde_json::json!({ "type": "string" })
        },
        "i8" | "i16" | "i32" | "i64" | "i128" | "isize" | "u8" | "u16" | "u32" | "u64" | "u128"
        | "usize" => quote! {
            serde_json::json!({ "type": "integer" })
        },
        "f32" | "f64" => quote! {
            serde_json::json!({ "type": "number" })
        },
        "bool" => quote! {
            serde_json::json!({ "type": "boolean" })
        },
        "Option" => {
            // For Option<T>, emit T's schema widened to admit JSON null, so
            // callers may spell "omitted" as an explicit null (serde maps both
            // to None). Schemas without a "type" keyword (empty or custom
            // object schemas) are left untouched: an absent "type" already
            // admits null, and custom json_schema() output is not ours to
            // rewrite.
            if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                if let Some(syn::GenericArgument::Type(inner_ty)) = args.args.first() {
                    let inner_schema = type_to_json_schema(inner_ty);
                    return quote! {{
                        let mut schema = #inner_schema;
                        if let Some(obj) = schema.as_object_mut() {
                            let widened = match obj.get("type") {
                                Some(serde_json::Value::String(existing)) => {
                                    if existing == "null" {
                                        None
                                    } else {
                                        Some(serde_json::json!([existing.clone(), "null"]))
                                    }
                                }
                                Some(serde_json::Value::Array(types)) => {
                                    if types.iter().any(|t| t == "null") {
                                        None
                                    } else {
                                        let mut types = types.clone();
                                        types.push(serde_json::json!("null"));
                                        Some(serde_json::Value::Array(types))
                                    }
                                }
                                _ => None,
                            };
                            if let Some(widened) = widened {
                                obj.insert("type".to_string(), widened);
                            }
                        }
                        schema
                    }};
                }
            }
            quote! { serde_json::json!({}) }
        }
        "Vec" => {
            // For Vec<T>, create array schema
            if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                if let Some(syn::GenericArgument::Type(inner_ty)) = args.args.first() {
                    let inner_schema = type_to_json_schema(inner_ty);
                    return quote! {
                        serde_json::json!({
                            "type": "array",
                            "items": #inner_schema
                        })
                    };
                }
            }
            quote! { serde_json::json!({ "type": "array" }) }
        }
        "HashSet" | "BTreeSet" => {
            // For Set<T>, create array schema with uniqueItems
            if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                if let Some(syn::GenericArgument::Type(inner_ty)) = args.args.first() {
                    let inner_schema = type_to_json_schema(inner_ty);
                    return quote! {
                        serde_json::json!({
                            "type": "array",
                            "items": #inner_schema,
                            "uniqueItems": true
                        })
                    };
                }
            }
            quote! { serde_json::json!({ "type": "array", "uniqueItems": true }) }
        }
        "HashMap" | "BTreeMap" => {
            // For Map<K, V>, create object schema with additionalProperties
            if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                // Check if key is String-like (implied for JSON object keys)
                // We mainly care about the value type (second arg)
                if args.args.len() >= 2 {
                    if let Some(syn::GenericArgument::Type(value_ty)) = args.args.iter().nth(1) {
                        let value_schema = type_to_json_schema(value_ty);
                        return quote! {
                            serde_json::json!({
                                "type": "object",
                                "additionalProperties": #value_schema
                            })
                        };
                    }
                }
            }
            quote! { serde_json::json!({ "type": "object" }) }
        }
        "serde_json::Value" | "Value" => {
            // Any JSON value
            quote! { serde_json::json!({}) }
        }
        _ => {
            // For other types, assume they implement a json_schema() method
            // (e.g. via #[derive(JsonSchema)] or manual implementation)
            quote! { <#ty>::json_schema() }
        }
    }
}

/// Emits the final complete-or-input-required resource hooks for a resumable
/// macro handler. The normal hook supplies `None`; the retry hook supplies
/// only router-admitted completed inputs.
fn generate_resource_mrtr_outcome_methods(
    is_async: bool,
    fn_name: &Ident,
    call_args: &TokenStream2,
    param_extractions: &[TokenStream2],
    resume_name: &Ident,
    resume_type: &Type,
    conversion: &TokenStream2,
) -> TokenStream2 {
    let initial_invocation = if is_async {
        quote! {
            let result: fastmcp_core::McpResult<fastmcp_server::FinalMethodOutcome<fastmcp_protocol::FinalReadResourceResult>> = async move {
                #(#param_extractions)*
                let #resume_name: #resume_type = None;
                let result = #fn_name(#call_args).await;
                #conversion
            }.await;
        }
    } else {
        quote! {
            let result: fastmcp_core::McpResult<fastmcp_server::FinalMethodOutcome<fastmcp_protocol::FinalReadResourceResult>> = (|| {
                #(#param_extractions)*
                let #resume_name: #resume_type = None;
                let result = #fn_name(#call_args);
                #conversion
            })();
        }
    };
    let resumed_invocation = if is_async {
        quote! {
            let result: fastmcp_core::McpResult<fastmcp_server::FinalMethodOutcome<fastmcp_protocol::FinalReadResourceResult>> = async move {
                #(#param_extractions)*
                let #resume_name: #resume_type = resume_inputs;
                let result = #fn_name(#call_args).await;
                #conversion
            }.await;
        }
    } else {
        quote! {
            let result: fastmcp_core::McpResult<fastmcp_server::FinalMethodOutcome<fastmcp_protocol::FinalReadResourceResult>> = (|| {
                #(#param_extractions)*
                let #resume_name: #resume_type = resume_inputs;
                let result = #fn_name(#call_args);
                #conversion
            })();
        }
    };
    let outcome = quote! {
        match result {
            Ok(value) => fastmcp_core::Outcome::Ok(value),
            Err(error) => fastmcp_core::Outcome::Err(error),
        }
    };
    let explicit_cache_hints = explicit_final_resource_cache_hint_methods();

    quote! {
        fn declares_final_mrtr(&self) -> bool {
            true
        }

        #explicit_cache_hints

        fn read_final_outcome_async_with_uri_in_request<'a>(
            &'a self,
            ctx: &'a fastmcp_core::McpContext,
            _request_cx: &'a fastmcp_core::Cx,
            _uri: &'a str,
            uri_params: &'a std::collections::HashMap<String, String>,
        ) -> fastmcp_server::BoxFuture<'a, fastmcp_core::McpOutcome<fastmcp_server::FinalMethodOutcome<fastmcp_protocol::FinalReadResourceResult>>> {
            Box::pin(async move {
                let _ = ctx;
                let _ = uri_params;
                #initial_invocation
                #outcome
            })
        }

        fn read_final_outcome_async_with_uri_resuming_in_request<'a>(
            &'a self,
            ctx: &'a fastmcp_core::McpContext,
            _request_cx: &'a fastmcp_core::Cx,
            _uri: &'a str,
            uri_params: &'a std::collections::HashMap<String, String>,
            resume_inputs: Option<&'a fastmcp_server::bidirectional::MrtrCompletedInputs>,
        ) -> fastmcp_server::BoxFuture<'a, fastmcp_core::McpOutcome<fastmcp_server::FinalMethodOutcome<fastmcp_protocol::FinalReadResourceResult>>> {
            Box::pin(async move {
                let _ = ctx;
                let _ = uri_params;
                #resumed_invocation
                #outcome
            })
        }
    }
}

// ============================================================================
// Tool Macro
// ============================================================================

/// Parsed attributes for #[tool].
#[derive(Debug)]
struct ToolAttrs {
    name: Option<String>,
    description: Option<String>,
    timeout: Option<String>,
    /// Opts a canonical final tool-outcome handler into final Tasks creation.
    tasks: bool,
    /// Typed final MCP Apps UI metadata attached to this tool.
    #[cfg(feature = "apps")]
    apps_ui: Option<ToolAppsUi>,
    tags: Vec<String>,
    defaults: HashMap<String, Lit>,
    /// Output schema as a JSON literal or type name
    output_schema: Option<syn::Expr>,
    /// Tool version string (e.g., "1.0.0").
    version: Option<String>,
    /// Optional icon source URL or data URI.
    icon: Option<String>,
    /// Annotation flags: `read_only`, `idempotent`, `destructive`, `open_world_hint`.
    /// Each is a boolean hint: bare (`read_only`) means `true`, or set explicitly
    /// (`open_world_hint = false`).
    annotations_read_only: Option<bool>,
    annotations_idempotent: Option<bool>,
    annotations_destructive: Option<bool>,
    annotations_open_world_hint: Option<bool>,
}

/// The validated `ui(...)` declaration accepted by `#[tool]`.
#[cfg(feature = "apps")]
#[derive(Debug)]
struct ToolAppsUi {
    resource_uri: String,
    visibility: Option<Vec<ToolAppsToolVisibility>>,
}

/// One explicit MCP Apps tool audience accepted by the macro surface.
#[cfg(feature = "apps")]
#[derive(Debug)]
enum ToolAppsToolVisibility {
    Model,
    App,
}

#[cfg(not(feature = "apps"))]
const TOOL_APPS_UI_FEATURE_DIAGNOSTIC: &str = "#[tool(ui(...))] requires Apps support; enable fastmcp-rust's `apps` feature, or for direct subcrate use enable both fastmcp-derive's and fastmcp-protocol's `apps` features";

/// Parses and validates one Apps UI declaration only when the macro host has
/// the matching Apps-enabled protocol dependency.
#[cfg(feature = "apps")]
fn parse_tool_apps_ui_metadata(
    input: ParseStream<'_>,
    ui_span: Span,
    apps_ui: &mut Option<ToolAppsUi>,
) -> syn::Result<()> {
    if apps_ui.is_some() {
        return Err(syn::Error::new(
            ui_span,
            "duplicate ui metadata declaration",
        ));
    }

    let content;
    syn::parenthesized!(content in input);
    let mut resource_uri = None;
    let mut visibility = None;
    while !content.is_empty() {
        let field: Ident = content.parse()?;
        match field.to_string().as_str() {
            "resource_uri" => {
                if resource_uri.is_some() {
                    return Err(syn::Error::new(field.span(), "duplicate ui resource_uri"));
                }
                content.parse::<Token![=]>()?;
                let uri: LitStr = content.parse()?;
                resource_uri = Some(uri);
            }
            "visibility" => {
                if visibility.is_some() {
                    return Err(syn::Error::new(field.span(), "duplicate ui visibility"));
                }
                content.parse::<Token![=]>()?;
                let values: syn::ExprArray = content.parse()?;
                let mut audiences = Vec::new();
                for value in values.elems {
                    let syn::Expr::Lit(syn::ExprLit {
                        lit: Lit::Str(value),
                        ..
                    }) = value
                    else {
                        return Err(syn::Error::new_spanned(
                            value,
                            "ui visibility entries must be string literals",
                        ));
                    };
                    let audience = match value.value().as_str() {
                        "model" => ToolAppsToolVisibility::Model,
                        "app" => ToolAppsToolVisibility::App,
                        _ => {
                            return Err(syn::Error::new(
                                value.span(),
                                "ui visibility entries must be `model` or `app`",
                            ));
                        }
                    };
                    audiences.push(audience);
                }
                visibility = Some(audiences);
            }
            _ => {
                return Err(syn::Error::new(
                    field.span(),
                    "ui metadata expects resource_uri and optional visibility",
                ));
            }
        }
        if !content.is_empty() {
            content.parse::<Token![,]>()?;
        }
    }

    let resource_uri = resource_uri
        .ok_or_else(|| syn::Error::new(ui_span, "ui metadata requires resource_uri"))?;
    let parsed_uri = fastmcp_protocol::common_types::AbsoluteUri::parse(&resource_uri.value())
        .map_err(|error| {
            syn::Error::new(
                resource_uri.span(),
                format!("ui resource_uri must be an absolute URI: {error}"),
            )
        })?;
    let typed_visibility = visibility.as_ref().map(|values| {
        values
            .iter()
            .map(|value| match value {
                ToolAppsToolVisibility::Model => fastmcp_protocol::McpAppsToolVisibility::Model,
                ToolAppsToolVisibility::App => fastmcp_protocol::McpAppsToolVisibility::App,
            })
            .collect()
    });
    fastmcp_protocol::McpAppsToolMetadata::try_new(Some(parsed_uri), typed_visibility).map_err(
        |error| {
            syn::Error::new(
                resource_uri.span(),
                format!("invalid MCP Apps tool UI metadata: {error}"),
            )
        },
    )?;
    *apps_ui = Some(ToolAppsUi {
        resource_uri: resource_uri.value(),
        visibility,
    });
    Ok(())
}

impl Parse for ToolAttrs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut name = None;
        let mut description = None;
        let mut timeout = None;
        let mut tasks = false;
        #[cfg(feature = "apps")]
        let mut apps_ui = None;
        let mut tags = Vec::new();
        let mut defaults: HashMap<String, Lit> = HashMap::new();
        let mut output_schema = None;
        let mut version = None;
        let mut icon = None;
        let mut annotations_read_only = None;
        let mut annotations_idempotent = None;
        let mut annotations_destructive = None;
        let mut annotations_open_world_hint = None;

        while !input.is_empty() {
            let ident: Ident = input.parse()?;

            match ident.to_string().as_str() {
                "name" => {
                    input.parse::<Token![=]>()?;
                    let lit: LitStr = input.parse()?;
                    name = Some(lit.value());
                }
                "description" => {
                    input.parse::<Token![=]>()?;
                    let lit: LitStr = input.parse()?;
                    description = Some(lit.value());
                }
                "timeout" => {
                    input.parse::<Token![=]>()?;
                    let lit: LitStr = input.parse()?;
                    timeout = Some(lit.value());
                }
                "tasks" => {
                    if !cfg!(feature = "tasks") {
                        return Err(syn::Error::new(
                            ident.span(),
                            "#[tool(tasks)] requires the fastmcp-derive `tasks` feature; enable fastmcp-rust's `tasks` feature or fastmcp-derive's `tasks` feature",
                        ));
                    }
                    if input.peek(Token![=]) {
                        return Err(syn::Error::new(
                            ident.span(),
                            "tasks is a bare opt-in; write #[tool(tasks)]",
                        ));
                    }
                    if tasks {
                        return Err(syn::Error::new(ident.span(), "duplicate tasks opt-in"));
                    }
                    tasks = true;
                }
                "icon" => {
                    input.parse::<Token![=]>()?;
                    icon = Some(parse_icon_src(input)?);
                }
                "ui" => {
                    #[cfg(feature = "apps")]
                    parse_tool_apps_ui_metadata(input, ident.span(), &mut apps_ui)?;
                    #[cfg(not(feature = "apps"))]
                    return Err(syn::Error::new(
                        ident.span(),
                        TOOL_APPS_UI_FEATURE_DIAGNOSTIC,
                    ));
                }
                "version" => {
                    input.parse::<Token![=]>()?;
                    let lit: LitStr = input.parse()?;
                    version = Some(lit.value());
                }
                "tags" => {
                    input.parse::<Token![=]>()?;
                    let expr_array: syn::ExprArray = input.parse()?;
                    for expr in expr_array.elems {
                        match expr {
                            syn::Expr::Lit(syn::ExprLit {
                                lit: Lit::Str(tag), ..
                            }) => tags.push(tag.value()),
                            other => {
                                return Err(syn::Error::new_spanned(
                                    other,
                                    "tags entries must be string literals",
                                ));
                            }
                        }
                    }
                }
                "defaults" => {
                    let content;
                    syn::parenthesized!(content in input);
                    while !content.is_empty() {
                        let key: Ident = content.parse()?;
                        content.parse::<Token![=]>()?;
                        let lit: Lit = content.parse()?;
                        defaults.insert(key.to_string(), lit);
                        if !content.is_empty() {
                            content.parse::<Token![,]>()?;
                        }
                    }
                }
                "output_schema" => {
                    input.parse::<Token![=]>()?;
                    // Accept any expression (json!(...), type name, etc.)
                    let expr: syn::Expr = input.parse()?;
                    output_schema = Some(expr);
                }
                "annotations" => {
                    let content;
                    syn::parenthesized!(content in input);
                    while !content.is_empty() {
                        let ann_ident: Ident = content.parse()?;
                        match ann_ident.to_string().as_str() {
                            "read_only" => {
                                annotations_read_only = Some(parse_annotation_bool(&content)?);
                            }
                            "idempotent" => {
                                annotations_idempotent = Some(parse_annotation_bool(&content)?);
                            }
                            "destructive" => {
                                annotations_destructive = Some(parse_annotation_bool(&content)?);
                            }
                            "open_world_hint" => {
                                annotations_open_world_hint =
                                    Some(parse_annotation_bool(&content)?);
                            }
                            other => {
                                return Err(syn::Error::new(
                                    ann_ident.span(),
                                    format!(
                                        "unknown annotation: {other}; expected read_only, idempotent, destructive, or open_world_hint"
                                    ),
                                ));
                            }
                        }
                        if !content.is_empty() {
                            content.parse::<Token![,]>()?;
                        }
                    }
                }
                _ => {
                    return Err(syn::Error::new(ident.span(), "unknown attribute"));
                }
            }

            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }

        Ok(Self {
            name,
            description,
            timeout,
            tasks,
            #[cfg(feature = "apps")]
            apps_ui,
            tags,
            defaults,
            output_schema,
            version,
            icon,
            annotations_read_only,
            annotations_idempotent,
            annotations_destructive,
            annotations_open_world_hint,
        })
    }
}

/// Parses and admits one icon source URI for `#[tool]`, `#[resource]`, and
/// `#[prompt]`. The source must be a valid final `RawIcon` URI so the
/// generated handler can advertise both the legacy singular icon and the
/// modern icon set.
fn parse_icon_src(input: ParseStream<'_>) -> syn::Result<String> {
    let lit: LitStr = input.parse()?;
    let src = lit.value();
    fastmcp_protocol::common_types::RawIcon::try_new(&src)
        .map_err(|error| syn::Error::new(lit.span(), format!("invalid icon URI: {error}")))?;
    Ok(src)
}

fn generated_icon_field(icon: Option<&str>) -> TokenStream2 {
    icon.map_or_else(
        || quote! { None },
        |src| quote! { Some(fastmcp_protocol::Icon::new(#src)) },
    )
}

fn generated_icon_hooks(icon: Option<&str>) -> TokenStream2 {
    let Some(src) = icon else {
        return TokenStream2::new();
    };
    quote! {
        fn icon(&self) -> Option<&fastmcp_protocol::Icon> {
            static ICON: std::sync::OnceLock<fastmcp_protocol::Icon> = std::sync::OnceLock::new();
            Some(ICON.get_or_init(|| fastmcp_protocol::Icon::new(#src)))
        }

        fn final_icons(&self) -> Option<&[fastmcp_protocol::common_types::RawIcon]> {
            static ICONS: std::sync::OnceLock<Vec<fastmcp_protocol::common_types::RawIcon>> =
                std::sync::OnceLock::new();
            Some(
                ICONS
                    .get_or_init(|| {
                        vec![fastmcp_protocol::common_types::RawIcon::try_new(#src)
                            .expect("macro-validated icon source")]
                    })
                    .as_slice(),
            )
        }
    }
}

fn generated_resource_icon_hooks(icon: Option<&str>) -> TokenStream2 {
    let Some(src) = icon else {
        return TokenStream2::new();
    };
    let shared = generated_icon_hooks(Some(src));
    quote! {
        #shared

        fn final_template_icons(&self) -> Option<&[fastmcp_protocol::common_types::RawIcon]> {
            self.final_icons()
        }
    }
}

/// Parses a boolean annotation value: bare (`read_only`) yields `true`, an
/// explicit form (`open_world_hint = false`) yields the given literal.
fn parse_annotation_bool(input: ParseStream<'_>) -> syn::Result<bool> {
    if input.peek(Token![=]) {
        input.parse::<Token![=]>()?;
        Ok(input.parse::<syn::LitBool>()?.value)
    } else {
        Ok(true)
    }
}

/// The two supported sources for a tool output schema.
///
/// An inline expression retains the exact legacy behavior. A bare type path
/// becomes the typed form only when it matches the tool's success return type;
/// this lets legacy schema constants continue to work unchanged.
#[derive(Clone, Copy)]
enum OutputSchemaSource<'a> {
    Inline(&'a syn::Expr),
    Type(&'a syn::Path),
}

fn output_schema_source<'a>(
    schema_expr: &'a syn::Expr,
    output: &syn::ReturnType,
) -> OutputSchemaSource<'a> {
    match schema_expr {
        syn::Expr::Path(path)
            if path.qself.is_none() && typed_output_schema_matches_return(&path.path, output) =>
        {
            OutputSchemaSource::Type(&path.path)
        }
        _ => OutputSchemaSource::Inline(schema_expr),
    }
}

fn output_schema_value(source: OutputSchemaSource<'_>) -> TokenStream2 {
    match source {
        OutputSchemaSource::Inline(schema_expr) => quote! { #schema_expr },
        OutputSchemaSource::Type(schema_type) => quote! { <#schema_type>::json_schema() },
    }
}

/// Returns the success value type from a direct return or `Result`-style
/// return. This lets the typed output-schema form prove that the advertised
/// schema and the handler result name the same type.
fn tool_success_type(output: &syn::ReturnType) -> Option<&Type> {
    let syn::ReturnType::Type(_, output_type) = output else {
        return None;
    };
    let Type::Path(type_path) = output_type.as_ref() else {
        return Some(output_type.as_ref());
    };
    let Some(segment) = type_path.path.segments.last() else {
        return Some(output_type.as_ref());
    };

    if segment.ident != "Result" && segment.ident != "McpResult" {
        return Some(output_type.as_ref());
    }

    let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return None;
    };

    arguments.args.first().and_then(|argument| match argument {
        syn::GenericArgument::Type(success_type) => Some(success_type),
        _ => None,
    })
}

fn typed_output_schema_matches_return(schema_type: &syn::Path, output: &syn::ReturnType) -> bool {
    tool_success_type(output).is_some_and(|success_type| {
        quote! { #schema_type }.to_string() == quote! { #success_type }.to_string()
    })
}

/// Rejects the boolean-schema form before emitting a tool definition.
///
/// MCP tool `outputSchema` must be a JSON object. Arbitrary expressions still
/// preserve legacy ergonomics and are checked by the schema admission layer;
/// the macro can prove and reject only literal boolean schemas here.
fn validate_output_schema_expr(schema_expr: &syn::Expr) -> syn::Result<()> {
    let is_boolean_schema = match schema_expr {
        syn::Expr::Lit(syn::ExprLit {
            lit: Lit::Bool(_), ..
        }) => true,
        syn::Expr::Macro(expr_macro)
            if expr_macro
                .mac
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "json") =>
        {
            syn::parse2::<syn::LitBool>(expr_macro.mac.tokens.clone()).is_ok()
        }
        _ => false,
    };

    if is_boolean_schema {
        return Err(syn::Error::new_spanned(
            schema_expr,
            "output_schema must be a JSON object; boolean schemas are not supported",
        ));
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod mrtr_resume_expansion_tests {
    use super::{
        contains_mrtr_completed_inputs, generate_prompt_mrtr_outcome_methods,
        generate_resource_mrtr_outcome_methods, generate_tool_mrtr_resume_method,
        invalid_mrtr_resume_parameter_error, is_mrtr_completed_inputs_option_ref,
    };
    use quote::{format_ident, quote};

    #[test]
    fn resumable_mrtr_macros_deliver_completed_inputs_to_all_handler_kinds() {
        let resume = format_ident!("completed_inputs");
        let resume_type: syn::Type = syn::parse_quote!(Option<&MrtrCompletedInputs>);
        let handler = format_ident!("resumable");
        let extraction = quote! { let argument = "admitted"; };

        let tool = generate_tool_mrtr_resume_method(
            true,
            true,
            &handler,
            &[&resume],
            std::slice::from_ref(&extraction),
            &resume,
            &resume_type,
            &quote! { Ok(result) },
        )
        .to_string();
        assert!(
            tool.contains("call_final_outcome_async_resuming_in_request"),
            "{tool}"
        );
        assert!(
            tool.contains("completed_inputs : Option < & MrtrCompletedInputs > = resume_inputs"),
            "{tool}"
        );
        assert!(
            tool.contains("fn declares_final_mrtr (& self) -> bool { true }"),
            "{tool}"
        );

        let call_args = quote! { ctx, completed_inputs };
        let resource = generate_resource_mrtr_outcome_methods(
            false,
            &handler,
            &call_args,
            std::slice::from_ref(&extraction),
            &resume,
            &resume_type,
            &quote! { Ok(result) },
        )
        .to_string();
        assert!(
            resource.contains("read_final_outcome_async_with_uri_resuming_in_request"),
            "{resource}"
        );
        assert!(resource.contains("= resume_inputs"), "{resource}");
        assert!(
            resource.contains("completed_inputs : Option < & MrtrCompletedInputs > = None"),
            "{resource}"
        );
        assert!(
            resource.contains("fn declares_final_mrtr (& self) -> bool { true }"),
            "{resource}"
        );
        assert!(
            resource.contains("FinalResourceReadCacheHintProvenance :: Explicit"),
            "{resource}"
        );

        let prompt = generate_prompt_mrtr_outcome_methods(
            true,
            true,
            &handler,
            std::slice::from_ref(&resume),
            &[extraction],
            &resume,
            &resume_type,
            &quote! { Ok(result) },
        )
        .to_string();
        assert!(
            prompt.contains("get_final_outcome_async_resuming_in_request"),
            "{prompt}"
        );
        assert!(prompt.contains("= resume_inputs"), "{prompt}");
        assert!(
            prompt.contains("completed_inputs : Option < & MrtrCompletedInputs > = None"),
            "{prompt}"
        );
        assert!(
            prompt.contains("fn declares_final_mrtr (& self) -> bool { true }"),
            "{prompt}"
        );
    }

    #[test]
    fn resumable_mrtr_rejects_the_one_variable_non_optional_form() {
        let invalid: syn::Type = syn::parse_quote!(&MrtrCompletedInputs);
        assert!(contains_mrtr_completed_inputs(&invalid));
        assert!(!is_mrtr_completed_inputs_option_ref(&invalid));
        assert_eq!(
            invalid_mrtr_resume_parameter_error(&invalid).to_string(),
            "MRTR resume input must be Option<&MrtrCompletedInputs>",
        );
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod schema_bound_tool_expansion_tests {
    use super::{
        OutputSchemaSource, generate_tool_result_conversion, output_schema_source,
        output_schema_value, typed_output_schema_matches_return, validate_output_schema_expr,
    };

    #[test]
    fn sch_02_a_positive() {
        let inline_schema: syn::Expr = syn::parse_quote!(serde_json::json!({ "type": "object" }));
        validate_output_schema_expr(&inline_schema).expect("object schemas are accepted");

        let output_type: syn::Expr = syn::parse_quote!(FinalToolResult);
        let return_type: syn::ReturnType = syn::parse_quote!(-> McpResult<FinalToolResult>);
        let OutputSchemaSource::Type(_) = output_schema_source(&output_type, &return_type) else {
            panic!("a bare output type must generate its final schema");
        };
        let schema =
            output_schema_value(output_schema_source(&output_type, &return_type)).to_string();
        assert!(schema.contains("FinalToolResult"), "{schema}");
        assert!(schema.contains("json_schema"), "{schema}");

        let legacy_schema: syn::Expr = syn::parse_quote!(LEGACY_SCHEMA);
        let legacy_return: syn::ReturnType = syn::parse_quote!(-> String);
        assert!(matches!(
            output_schema_source(&legacy_schema, &legacy_return),
            OutputSchemaSource::Inline(_),
        ));

        let OutputSchemaSource::Type(schema_type) =
            output_schema_source(&output_type, &return_type)
        else {
            unreachable!("the schema source was checked above");
        };
        assert!(typed_output_schema_matches_return(
            schema_type,
            &return_type
        ));
        let conversion = generate_tool_result_conversion(&return_type, true).to_string();
        assert!(
            conversion.contains("serde_json :: to_value"),
            "{conversion}"
        );
        assert!(conversion.contains("result ?"), "{conversion}");
    }

    #[test]
    fn sch_02_a_planted_negative() {
        let inline_schema: syn::Expr = syn::parse_quote!(serde_json::json!(true));
        let error = validate_output_schema_expr(&inline_schema)
            .expect_err("the paired boolean schema must fail macro expansion");

        assert_eq!(
            error.to_string(),
            "output_schema must be a JSON object; boolean schemas are not supported",
        );
    }
}

/// Defines a tool handler.
///
/// The function signature should be:
/// ```ignore
/// async fn tool_name(ctx: &McpContext, args...) -> Result
/// ```
///
/// # Attributes
///
/// - `name` - Override the tool name (default: function name)
/// - `description` - Tool description (default: doc comment)
/// - `tags` - List of tool tags for filtering (`tags = ["api", "read"]`)
/// - `icon` - Icon source URL or data URI (`icon = "https://example.com/icon.png"`)
/// - `output_schema` - An inline JSON object (legacy form), or a bare return
///   type path with `json_schema()` (typed result form)
/// - `tasks` - With the `fastmcp-derive/tasks` feature enabled, opt a
///   canonical `FinalToolOutcome` return into final Tasks creation;
///   incompatible return types are rejected at compile time
///
/// # Parameter Defaults
///
/// Rust has no default function arguments. For feature parity with Python FastMCP,
/// `#[tool]` supports per-parameter defaults via `defaults(...)`:
///
/// ```ignore
/// #[tool(defaults(title = "World"))]
/// fn greet(name: String, title: String) -> String {
///     format!("Hello {title} {name}")
/// }
/// ```
///
/// If the argument is omitted in the JSON-RPC call, the default value is used.
#[proc_macro_attribute]
#[allow(clippy::too_many_lines)]
pub fn tool(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attrs = parse_macro_input!(attr as ToolAttrs);
    let input_fn = parse_macro_input!(item as ItemFn);
    let ToolCratePaths {
        handler:
            HandlerCratePaths {
                core,
                protocol,
                server,
            },
        serde_json,
    } = match tool_crate_paths() {
        Ok(paths) => paths,
        Err(error) => return error.to_compile_error().into(),
    };

    if attrs.tasks
        && let Err(error) = validate_tool_tasks_return(&input_fn.sig.output)
    {
        return syn::Error::new_spanned(&input_fn.sig.ident, error.to_string())
            .to_compile_error()
            .into();
    }

    if let Err(error) = validate_final_handler_return(
        &input_fn.sig.output,
        "tool",
        "FinalCallToolResult",
        None,
        "Vec<Content>",
    ) {
        return syn::Error::new_spanned(&input_fn.sig.ident, error.to_string())
            .to_compile_error()
            .into();
    }

    let typed_output_schema = if let Some(schema_expr) = attrs.output_schema.as_ref() {
        if let Err(error) = validate_output_schema_expr(schema_expr) {
            return error.to_compile_error().into();
        }

        match output_schema_source(schema_expr, &input_fn.sig.output) {
            OutputSchemaSource::Type(_) => true,
            OutputSchemaSource::Inline(_) => false,
        }
    } else {
        false
    };

    let fn_name = &input_fn.sig.ident;
    let fn_name_str = fn_name.to_string();

    // Generate handler struct name (PascalCase)
    let handler_name = format_ident!("{}", to_pascal_case(&fn_name_str));
    let impl_module = format_ident!("__fastmcp_tool_{}", fn_name);

    // Get tool name (from attr or function name)
    let tool_name = attrs.name.unwrap_or_else(|| fn_name_str.clone());

    // Get description (from attr or doc comments)
    let description = attrs
        .description
        .or_else(|| extract_doc_comments(&input_fn.attrs));
    let description_tokens = description.as_ref().map_or_else(
        || quote! { None },
        |desc| quote! { Some(#desc.to_string()) },
    );

    // Parse timeout attribute
    let timeout_tokens = if let Some(ref timeout_str) = attrs.timeout {
        match parse_duration_to_millis(timeout_str) {
            Ok(millis) => {
                quote! {
                    fn timeout(&self) -> Option<std::time::Duration> {
                        Some(std::time::Duration::from_millis(#millis))
                    }
                }
            }
            Err(e) => {
                return syn::Error::new_spanned(
                    &input_fn.sig.ident,
                    format!("invalid timeout: {e}"),
                )
                .to_compile_error()
                .into();
            }
        }
    } else {
        quote! {}
    };

    // Parse output_schema attribute
    let (output_schema_field, output_schema_method) =
        if let Some(ref schema_expr) = attrs.output_schema {
            let definition_schema =
                output_schema_value(output_schema_source(schema_expr, &input_fn.sig.output));
            let handler_schema =
                output_schema_value(output_schema_source(schema_expr, &input_fn.sig.output));
            (
                quote! { Some(#definition_schema) },
                quote! {
                    fn output_schema(&self) -> Option<serde_json::Value> {
                        Some(#handler_schema)
                    }
                },
            )
        } else {
            (quote! { None }, quote! {})
        };

    let tag_entries: Vec<TokenStream2> = attrs
        .tags
        .iter()
        .map(|tag| quote! { #tag.to_string() })
        .collect();

    // Generate version token
    let version_tokens = attrs
        .version
        .as_ref()
        .map_or_else(|| quote! { None }, |v| quote! { Some(#v.to_string()) });
    let icon_tokens = generated_icon_field(attrs.icon.as_deref());
    let icon_hooks = generated_icon_hooks(attrs.icon.as_deref());

    // Generate annotations token
    let has_annotations = attrs.annotations_read_only.is_some()
        || attrs.annotations_idempotent.is_some()
        || attrs.annotations_destructive.is_some()
        || attrs.annotations_open_world_hint.is_some();

    let annotations_tokens = if has_annotations {
        let ro = attrs
            .annotations_read_only
            .map_or_else(|| quote! { None }, |v| quote! { Some(#v) });
        let idem = attrs
            .annotations_idempotent
            .map_or_else(|| quote! { None }, |v| quote! { Some(#v) });
        let destr = attrs
            .annotations_destructive
            .map_or_else(|| quote! { None }, |v| quote! { Some(#v) });
        let owh = attrs
            .annotations_open_world_hint
            .map_or_else(|| quote! { None }, |v| quote! { Some(#v) });
        quote! {
            Some(fastmcp_protocol::ToolAnnotations {
                read_only: #ro,
                idempotent: #idem,
                destructive: #destr,
                open_world_hint: #owh,
            })
        }
    } else {
        quote! { None }
    };

    // Parse parameters (skip first if it's &McpContext)
    let mut params: Vec<(&Ident, &Type, Option<String>, Option<Lit>)> = Vec::new();
    let mut call_param_names: Vec<&Ident> = Vec::new();
    let mut mrtr_resume_param: Option<(&Ident, &Type)> = None;
    let mut required_params: Vec<String> = Vec::new();
    let mut expects_context = false;

    for (i, arg) in input_fn.sig.inputs.iter().enumerate() {
        if let FnArg::Typed(pat_type) = arg {
            // Skip the first parameter if it looks like a context
            if i == 0 && is_mcp_context_ref(pat_type.ty.as_ref()) {
                expects_context = true;
                continue;
            }

            if is_mrtr_completed_inputs_option_ref(pat_type.ty.as_ref()) {
                let Pat::Ident(pat_ident) = pat_type.pat.as_ref() else {
                    return syn::Error::new_spanned(
                        &pat_type.pat,
                        "MRTR resume input must use an identifier pattern",
                    )
                    .to_compile_error()
                    .into();
                };
                if mrtr_resume_param.is_some() {
                    return syn::Error::new_spanned(
                        &pat_type.ty,
                        "a handler may have only one MRTR resume input",
                    )
                    .to_compile_error()
                    .into();
                }
                let param_name = &pat_ident.ident;
                mrtr_resume_param = Some((param_name, pat_type.ty.as_ref()));
                call_param_names.push(param_name);
                continue;
            }
            if contains_mrtr_completed_inputs(pat_type.ty.as_ref()) {
                return invalid_mrtr_resume_parameter_error(pat_type.ty.as_ref())
                    .to_compile_error()
                    .into();
            }

            if let Pat::Ident(pat_ident) = pat_type.pat.as_ref() {
                let param_name = &pat_ident.ident;
                let param_type = pat_type.ty.as_ref();
                let param_doc = extract_doc_comments(&pat_type.attrs);
                let param_default = attrs.defaults.get(&param_name.to_string()).cloned();

                // Check if parameter is required (not Option<T> and no default)
                let is_optional = is_option_type(param_type);

                if !is_optional && param_default.is_none() {
                    required_params.push(param_name.to_string());
                }

                params.push((param_name, param_type, param_doc, param_default));
                call_param_names.push(param_name);
            }
        }
    }

    // Generate JSON schema for input
    let property_entries: Vec<TokenStream2> = params
        .iter()
        .map(|(name, ty, doc, default_expr)| {
            let name_str = name.to_string();
            let schema = type_to_json_schema(ty);

            let default_insert = default_expr.as_ref().map_or_else(
                || quote! {},
                |lit| {
                    quote! {
                        obj.insert("default".to_string(), serde_json::json!(#lit));
                    }
                },
            );

            match (doc.as_ref(), default_expr.as_ref()) {
                (None, None) => quote! {
                    (#name_str.to_string(), #schema)
                },
                (Some(desc), _) => quote! {
                    (#name_str.to_string(), {
                        let mut s = #schema;
                        if let Some(obj) = s.as_object_mut() {
                            obj.insert("description".to_string(), serde_json::json!(#desc));
                            #default_insert
                        }
                        s
                    })
                },
                (None, Some(_)) => quote! {
                    (#name_str.to_string(), {
                        let mut s = #schema;
                        if let Some(obj) = s.as_object_mut() {
                            #default_insert
                        }
                        s
                    })
                },
            }
        })
        .collect();

    // Generate parameter extraction code
    let mut param_extractions: Vec<TokenStream2> = Vec::new();
    for (name, ty, _, default_lit) in &params {
        let name_str = name.to_string();
        let is_optional = is_option_type(ty);

        if is_optional {
            if let Some(default_lit) = default_lit {
                let default_expr = match default_lit_expr_for_type(default_lit, ty) {
                    Ok(v) => v,
                    Err(e) => return e.to_compile_error().into(),
                };
                param_extractions.push(quote! {
                    let #name: #ty = match arguments.get(#name_str) {
                        // Explicit JSON null on an Option parameter is the
                        // wire spelling of "omitted": fall through to the
                        // default exactly as if the field were absent.
                        Some(value) if !value.is_null() => Some(
                            serde_json::from_value(value.clone()).map_err(|e| {
                                fastmcp_core::McpError::invalid_params(e.to_string())
                            })?,
                        ),
                        _ => #default_expr,
                    };
                });
            } else {
                param_extractions.push(quote! {
                    let #name: #ty = match arguments.get(#name_str) {
                        // Explicit JSON null on an Option parameter is the
                        // wire spelling of "omitted" (Python parity): both
                        // deserialize to None.
                        Some(value) if !value.is_null() => Some(
                            serde_json::from_value(value.clone()).map_err(|e| {
                                fastmcp_core::McpError::invalid_params(e.to_string())
                            })?,
                        ),
                        _ => None,
                    };
                });
            }
        } else if let Some(default_lit) = default_lit {
            let default_expr = match default_lit_expr_for_type(default_lit, ty) {
                Ok(v) => v,
                Err(e) => return e.to_compile_error().into(),
            };
            param_extractions.push(quote! {
                let #name: #ty = match arguments.get(#name_str) {
                    Some(v) => serde_json::from_value(v.clone())
                        .map_err(|e| fastmcp_core::McpError::invalid_params(e.to_string()))?,
                    None => #default_expr,
                };
            });
        } else {
            param_extractions.push(quote! {
                let #name: #ty = arguments.get(#name_str)
                    .ok_or_else(|| fastmcp_core::McpError::invalid_params(
                        format!("missing required parameter: {}", #name_str)
                    ))
                    .and_then(|v| serde_json::from_value(v.clone())
                        .map_err(|e| fastmcp_core::McpError::invalid_params(e.to_string())))?;
            });
        }
    }

    let mrtr_param_extractions = param_extractions.clone();
    if let Some((name, ty)) = mrtr_resume_param {
        param_extractions.push(quote! {
            let #name: #ty = None;
        });
    }

    // Generate parameter names for function call
    let param_names = call_param_names;

    // Check if function is async
    let is_async = input_fn.sig.asyncness.is_some();

    // Analyze return type to determine conversion strategy
    let return_type = &input_fn.sig.output;
    let result_conversion = generate_tool_result_conversion(return_type, typed_output_schema);
    let final_result_conversion = generate_final_tool_result_conversion(return_type);
    let final_outcome_conversion = generate_final_tool_outcome_conversion(return_type);
    if mrtr_resume_param.is_some() && final_outcome_conversion.is_none() {
        return syn::Error::new_spanned(
            &input_fn.sig.output,
            "MRTR resume input requires a canonical FinalToolOutcome return type",
        )
        .to_compile_error()
        .into();
    }
    let tasks_declaration = generate_tool_tasks_declaration(attrs.tasks);
    #[cfg(feature = "apps")]
    let apps_metadata = generate_tool_apps_metadata(attrs.apps_ui.as_ref());
    #[cfg(not(feature = "apps"))]
    let apps_metadata = TokenStream2::new();

    let execution_methods = generate_tool_execution_methods(
        is_async,
        expects_context,
        fn_name,
        &param_names,
        &param_extractions,
        &result_conversion,
        final_result_conversion.as_ref(),
        final_outcome_conversion.as_ref(),
    );
    let mrtr_resume_method = match (mrtr_resume_param, final_outcome_conversion.as_ref()) {
        (Some((name, ty)), Some(conversion)) => generate_tool_mrtr_resume_method(
            is_async,
            expects_context,
            fn_name,
            &param_names,
            &mrtr_param_extractions,
            name,
            ty,
            conversion,
        ),
        (None, _) => TokenStream2::new(),
        (Some(_), None) => unreachable!("MRTR return validation above rejects this form"),
    };

    // Generate the handler implementation
    let expanded = quote! {
        // Keep the original function
        #input_fn

        /// Handler for the #fn_name tool.
        #[derive(Clone)]
        pub struct #handler_name;

        #[doc(hidden)]
        mod #impl_module {
            use super::*;
            use #core as fastmcp_core;
            use #protocol as fastmcp_protocol;
            use #server as fastmcp_server;
            use #serde_json as serde_json;

            impl fastmcp_server::ToolHandler for #handler_name {
                fn definition(&self) -> fastmcp_protocol::Tool {
                    let properties: std::collections::HashMap<String, serde_json::Value> = vec![
                        #(#property_entries),*
                    ].into_iter().collect();

                    let required: Vec<String> = vec![#(#required_params.to_string()),*];

                    fastmcp_protocol::Tool {
                        name: #tool_name.to_string(),
                        description: #description_tokens,
                        input_schema: serde_json::json!({
                            "$schema": "https://json-schema.org/draft/2020-12/schema",
                            "type": "object",
                            "properties": properties,
                            "required": required,
                        }),
                        output_schema: #output_schema_field,
                        icon: #icon_tokens,
                        version: #version_tokens,
                        tags: vec![#(#tag_entries),*],
                        annotations: #annotations_tokens,
                    }
                }

                #timeout_tokens

                #icon_hooks

                #output_schema_method

                #apps_metadata

                #tasks_declaration

                #execution_methods

                #mrtr_resume_method
            }
        }
    };

    TokenStream::from(expanded)
}

// ============================================================================
// Resource Macro
// ============================================================================

/// Parsed attributes for #[resource].
struct ResourceAttrs {
    uri: Option<String>,
    name: Option<String>,
    description: Option<String>,
    mime_type: Option<String>,
    timeout: Option<String>,
    version: Option<String>,
    icon: Option<String>,
    tags: Vec<String>,
}

impl Parse for ResourceAttrs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut uri = None;
        let mut name = None;
        let mut description = None;
        let mut mime_type = None;
        let mut timeout = None;
        let mut version = None;
        let mut icon = None;
        let mut tags = Vec::new();

        while !input.is_empty() {
            let ident: Ident = input.parse()?;

            match ident.to_string().as_str() {
                "tags" => {
                    input.parse::<Token![=]>()?;
                    let expr_array: syn::ExprArray = input.parse()?;
                    for expr in expr_array.elems {
                        match expr {
                            syn::Expr::Lit(syn::ExprLit {
                                lit: Lit::Str(tag), ..
                            }) => tags.push(tag.value()),
                            other => {
                                return Err(syn::Error::new_spanned(
                                    other,
                                    "tags entries must be string literals",
                                ));
                            }
                        }
                    }
                }
                _ => {
                    input.parse::<Token![=]>()?;
                    match ident.to_string().as_str() {
                        "uri" => {
                            let lit: LitStr = input.parse()?;
                            uri = Some(lit.value());
                        }
                        "name" => {
                            let lit: LitStr = input.parse()?;
                            name = Some(lit.value());
                        }
                        "description" => {
                            let lit: LitStr = input.parse()?;
                            description = Some(lit.value());
                        }
                        "mime_type" => {
                            let lit: LitStr = input.parse()?;
                            mime_type = Some(lit.value());
                        }
                        "timeout" => {
                            let lit: LitStr = input.parse()?;
                            timeout = Some(lit.value());
                        }
                        "version" => {
                            let lit: LitStr = input.parse()?;
                            version = Some(lit.value());
                        }
                        "icon" => {
                            icon = Some(parse_icon_src(input)?);
                        }
                        _ => {
                            return Err(syn::Error::new(ident.span(), "unknown attribute"));
                        }
                    }
                }
            }

            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }

        Ok(Self {
            uri,
            name,
            description,
            mime_type,
            timeout,
            version,
            icon,
            tags,
        })
    }
}

/// Defines a resource handler.
///
/// # Attributes
///
/// - `uri` - The resource URI (required)
/// - `name` - Display name (default: function name)
/// - `description` - Resource description (default: doc comment)
/// - `mime_type` - MIME type (default: "text/plain")
/// - `icon` - Icon source URL or data URI (`icon = "https://example.com/icon.png"`)
#[proc_macro_attribute]
#[allow(clippy::too_many_lines)]
pub fn resource(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attrs = parse_macro_input!(attr as ResourceAttrs);
    let input_fn = parse_macro_input!(item as ItemFn);
    let HandlerCratePaths {
        core,
        protocol,
        server,
    } = match handler_crate_paths() {
        Ok(paths) => paths,
        Err(error) => return error.to_compile_error().into(),
    };

    if let Err(error) = validate_final_handler_return(
        &input_fn.sig.output,
        "resource",
        "ReadResourceResult",
        Some("FinalReadResourceResult"),
        "Vec<ResourceContent>",
    ) {
        return syn::Error::new_spanned(&input_fn.sig.ident, error.to_string())
            .to_compile_error()
            .into();
    }

    let fn_name = &input_fn.sig.ident;
    let fn_name_str = fn_name.to_string();

    // Generate handler struct name
    let handler_name = format_ident!("{}Resource", to_pascal_case(&fn_name_str));
    let impl_module = format_ident!("__fastmcp_resource_{}", fn_name);

    // Get resource URI (required)
    let Some(uri) = attrs.uri else {
        return syn::Error::new_spanned(&input_fn.sig.ident, "resource requires uri attribute")
            .to_compile_error()
            .into();
    };

    // Get name and description
    let resource_name = attrs.name.unwrap_or_else(|| fn_name_str.clone());
    let description = attrs
        .description
        .or_else(|| extract_doc_comments(&input_fn.attrs));
    let mime_type = attrs.mime_type.unwrap_or_else(|| "text/plain".to_string());

    let description_tokens = description.as_ref().map_or_else(
        || quote! { None },
        |desc| quote! { Some(#desc.to_string()) },
    );

    // Parse timeout attribute
    let timeout_tokens = if let Some(ref timeout_str) = attrs.timeout {
        match parse_duration_to_millis(timeout_str) {
            Ok(millis) => {
                quote! {
                    fn timeout(&self) -> Option<std::time::Duration> {
                        Some(std::time::Duration::from_millis(#millis))
                    }
                }
            }
            Err(e) => {
                return syn::Error::new_spanned(
                    &input_fn.sig.ident,
                    format!("invalid timeout: {e}"),
                )
                .to_compile_error()
                .into();
            }
        }
    } else {
        quote! {}
    };

    // Generate version token
    let version_tokens = attrs
        .version
        .as_ref()
        .map_or_else(|| quote! { None }, |v| quote! { Some(#v.to_string()) });
    let icon_tokens = generated_icon_field(attrs.icon.as_deref());
    let icon_hooks = generated_resource_icon_hooks(attrs.icon.as_deref());

    // Generate tags
    let tag_entries: Vec<TokenStream2> = attrs
        .tags
        .iter()
        .map(|tag| quote! { #tag.to_string() })
        .collect();

    let template_params = match extract_template_params(&uri) {
        Ok(params) => params,
        Err(error) => {
            return syn::Error::new_spanned(
                &input_fn.sig.ident,
                format!("invalid resource URI template: {error}"),
            )
            .to_compile_error()
            .into();
        }
    };

    // Parse parameters (skip first if it's &McpContext)
    let mut params: Vec<(&Ident, &Type)> = Vec::new();
    let mut call_param_names: Vec<&Ident> = Vec::new();
    let mut mrtr_resume_param: Option<(&Ident, &Type)> = None;
    let mut expects_context = false;

    for (i, arg) in input_fn.sig.inputs.iter().enumerate() {
        if let FnArg::Typed(pat_type) = arg {
            if i == 0 && is_mcp_context_ref(pat_type.ty.as_ref()) {
                expects_context = true;
                continue;
            }

            if is_mrtr_completed_inputs_option_ref(pat_type.ty.as_ref()) {
                let Pat::Ident(pat_ident) = pat_type.pat.as_ref() else {
                    return syn::Error::new_spanned(
                        &pat_type.pat,
                        "MRTR resume input must use an identifier pattern",
                    )
                    .to_compile_error()
                    .into();
                };
                if mrtr_resume_param.is_some() {
                    return syn::Error::new_spanned(
                        &pat_type.ty,
                        "a handler may have only one MRTR resume input",
                    )
                    .to_compile_error()
                    .into();
                }
                let param_name = &pat_ident.ident;
                mrtr_resume_param = Some((param_name, pat_type.ty.as_ref()));
                call_param_names.push(param_name);
                continue;
            }
            if contains_mrtr_completed_inputs(pat_type.ty.as_ref()) {
                return invalid_mrtr_resume_parameter_error(pat_type.ty.as_ref())
                    .to_compile_error()
                    .into();
            }

            if let Pat::Ident(pat_ident) = pat_type.pat.as_ref() {
                let param_name = &pat_ident.ident;
                let param_type = pat_type.ty.as_ref();
                params.push((param_name, param_type));
                call_param_names.push(param_name);
            }
        }
    }

    if template_params.is_empty() && !params.is_empty() {
        return syn::Error::new_spanned(
            &input_fn.sig.ident,
            "resource parameters require a URI template with matching {params}",
        )
        .to_compile_error()
        .into();
    }

    let missing_params: Vec<String> = params
        .iter()
        .map(|(name, _)| name.to_string())
        .filter(|name| !template_params.contains(name))
        .collect();

    if !missing_params.is_empty() {
        return syn::Error::new_spanned(
            &input_fn.sig.ident,
            format!(
                "resource parameters missing from uri template: {}",
                missing_params.join(", ")
            ),
        )
        .to_compile_error()
        .into();
    }

    let is_template = !template_params.is_empty();

    let mut param_extractions: Vec<TokenStream2> = params
        .iter()
        .map(|(name, ty)| {
            let name_str = name.to_string();
            if let Some(inner_ty) = option_inner_type(ty) {
                if is_string_type(inner_ty) {
                    quote! {
                        let #name: #ty = uri_params.get(#name_str).cloned();
                    }
                } else {
                    quote! {
                        let #name: #ty = match uri_params.get(#name_str) {
                            Some(value) => Some(value.parse().map_err(|_| {
                                fastmcp_core::McpError::invalid_params(
                                    format!("invalid uri parameter: {}", #name_str)
                                )
                            })?),
                            None => None,
                        };
                    }
                }
            } else if is_string_type(ty) {
                quote! {
                    let #name: #ty = uri_params
                        .get(#name_str)
                        .ok_or_else(|| fastmcp_core::McpError::invalid_params(
                            format!("missing uri parameter: {}", #name_str)
                        ))?
                        .clone();
                }
            } else {
                quote! {
                    let #name: #ty = uri_params
                        .get(#name_str)
                        .ok_or_else(|| fastmcp_core::McpError::invalid_params(
                            format!("missing uri parameter: {}", #name_str)
                        ))?
                        .parse()
                        .map_err(|_| fastmcp_core::McpError::invalid_params(
                            format!("invalid uri parameter: {}", #name_str)
                        ))?;
                }
            }
        })
        .collect();

    let mrtr_param_extractions = param_extractions.clone();
    if let Some((name, ty)) = mrtr_resume_param {
        param_extractions.push(quote! {
            let #name: #ty = None;
        });
    }

    let param_names = call_param_names;
    let call_args = if expects_context {
        quote! { ctx, #(#param_names),* }
    } else {
        quote! { #(#param_names),* }
    };

    let is_async = input_fn.sig.asyncness.is_some();

    let template_tokens = if is_template {
        quote! {
            Some(fastmcp_protocol::ResourceTemplate {
                uri_template: #uri.to_string(),
                name: #resource_name.to_string(),
                description: #description_tokens,
                mime_type: Some(#mime_type.to_string()),
                icon: #icon_tokens,
                version: #version_tokens,
                tags: vec![#(#tag_entries),*],
            })
        }
    } else {
        quote! { None }
    };

    // Generate result conversion based on return type (supports Result<String, E>)
    let return_type = &input_fn.sig.output;
    let final_result_conversion = generate_final_resource_result_conversion(return_type);
    let final_outcome_conversion = generate_final_resource_outcome_conversion(return_type);
    if mrtr_resume_param.is_some() && final_outcome_conversion.is_none() {
        return syn::Error::new_spanned(
            &input_fn.sig.output,
            "MRTR resume input requires FinalMethodOutcome<FinalReadResourceResult>",
        )
        .to_compile_error()
        .into();
    }
    let resource_result_conversion =
        if final_result_conversion.is_some() || final_outcome_conversion.is_some() {
            generate_final_legacy_rejection("resource", "ResourceHandler::read_final")
        } else {
            generate_resource_result_conversion(return_type, &mime_type)
        };
    let execution_methods = generate_resource_execution_methods(
        is_async,
        fn_name,
        &call_args,
        &uri,
        &param_extractions,
        &resource_result_conversion,
        final_result_conversion.as_ref(),
        mrtr_resume_param
            .is_none()
            .then_some(final_outcome_conversion.as_ref())
            .flatten(),
        is_async
            && mrtr_resume_param.is_none()
            && final_result_conversion.is_none()
            && final_outcome_conversion.is_none(),
    );
    let mrtr_outcome_methods = match (mrtr_resume_param, final_outcome_conversion.as_ref()) {
        (Some((name, ty)), Some(conversion)) => generate_resource_mrtr_outcome_methods(
            is_async,
            fn_name,
            &call_args,
            &mrtr_param_extractions,
            name,
            ty,
            conversion,
        ),
        (None, _) => TokenStream2::new(),
        (Some(_), None) => unreachable!("MRTR return validation above rejects this form"),
    };

    let expanded = quote! {
        // Keep the original function
        #input_fn

        /// Handler for the #fn_name resource.
        #[derive(Clone)]
        pub struct #handler_name;

        #[doc(hidden)]
        mod #impl_module {
            use super::*;
            use #core as fastmcp_core;
            use #protocol as fastmcp_protocol;
            use #server as fastmcp_server;

            impl fastmcp_server::ResourceHandler for #handler_name {
                fn definition(&self) -> fastmcp_protocol::Resource {
                    fastmcp_protocol::Resource {
                        uri: #uri.to_string(),
                        name: #resource_name.to_string(),
                        description: #description_tokens,
                        mime_type: Some(#mime_type.to_string()),
                        icon: #icon_tokens,
                        version: #version_tokens,
                        tags: vec![#(#tag_entries),*],
                    }
                }

                fn template(&self) -> Option<fastmcp_protocol::ResourceTemplate> {
                    #template_tokens
                }

                #timeout_tokens

                #icon_hooks

                #execution_methods

                #mrtr_outcome_methods
            }
        }
    };

    TokenStream::from(expanded)
}

// ============================================================================
// Prompt Macro
// ============================================================================

/// Parsed attributes for #[prompt].
struct PromptAttrs {
    name: Option<String>,
    description: Option<String>,
    timeout: Option<String>,
    defaults: HashMap<String, Lit>,
    version: Option<String>,
    icon: Option<String>,
    tags: Vec<String>,
}

impl Parse for PromptAttrs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut name = None;
        let mut description = None;
        let mut timeout = None;
        let mut defaults: HashMap<String, Lit> = HashMap::new();
        let mut version = None;
        let mut icon = None;
        let mut tags = Vec::new();

        while !input.is_empty() {
            let ident: Ident = input.parse()?;

            match ident.to_string().as_str() {
                "name" => {
                    input.parse::<Token![=]>()?;
                    let lit: LitStr = input.parse()?;
                    name = Some(lit.value());
                }
                "description" => {
                    input.parse::<Token![=]>()?;
                    let lit: LitStr = input.parse()?;
                    description = Some(lit.value());
                }
                "timeout" => {
                    input.parse::<Token![=]>()?;
                    let lit: LitStr = input.parse()?;
                    timeout = Some(lit.value());
                }
                "version" => {
                    input.parse::<Token![=]>()?;
                    let lit: LitStr = input.parse()?;
                    version = Some(lit.value());
                }
                "icon" => {
                    input.parse::<Token![=]>()?;
                    icon = Some(parse_icon_src(input)?);
                }
                "tags" => {
                    input.parse::<Token![=]>()?;
                    let expr_array: syn::ExprArray = input.parse()?;
                    for expr in expr_array.elems {
                        match expr {
                            syn::Expr::Lit(syn::ExprLit {
                                lit: Lit::Str(tag), ..
                            }) => tags.push(tag.value()),
                            other => {
                                return Err(syn::Error::new_spanned(
                                    other,
                                    "tags entries must be string literals",
                                ));
                            }
                        }
                    }
                }
                "defaults" => {
                    let content;
                    syn::parenthesized!(content in input);
                    while !content.is_empty() {
                        let key: Ident = content.parse()?;
                        content.parse::<Token![=]>()?;
                        let lit: Lit = content.parse()?;
                        defaults.insert(key.to_string(), lit);
                        if !content.is_empty() {
                            content.parse::<Token![,]>()?;
                        }
                    }
                }
                _ => {
                    return Err(syn::Error::new(ident.span(), "unknown attribute"));
                }
            }

            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }

        Ok(Self {
            name,
            description,
            timeout,
            defaults,
            version,
            icon,
            tags,
        })
    }
}

/// Defines a prompt handler.
///
/// # Attributes
///
/// - `name` - Override the prompt name (default: function name)
/// - `description` - Prompt description (default: doc comment)
/// - `icon` - Icon source URL or data URI (`icon = "https://example.com/icon.png"`)
///
/// # Argument Defaults
///
/// Prompt handlers take a `HashMap<String, String>` of arguments. For feature
/// parity with Python FastMCP, `#[prompt]` supports defaults via `defaults(...)`:
///
/// ```ignore
/// #[prompt(defaults(greeting = "Hi"))]
/// fn greet(name: String, greeting: String) -> Vec<PromptMessage> {
///     vec![PromptMessage::user(format!("{greeting} {name}"))]
/// }
/// ```
#[proc_macro_attribute]
#[allow(clippy::too_many_lines)]
pub fn prompt(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attrs = parse_macro_input!(attr as PromptAttrs);
    let input_fn = parse_macro_input!(item as ItemFn);
    let HandlerCratePaths {
        core,
        protocol,
        server,
    } = match handler_crate_paths() {
        Ok(paths) => paths,
        Err(error) => return error.to_compile_error().into(),
    };

    if let Err(error) = validate_final_handler_return(
        &input_fn.sig.output,
        "prompt",
        "GetPromptResult",
        Some("FinalGetPromptResult"),
        "Vec<PromptMessage>",
    ) {
        return syn::Error::new_spanned(&input_fn.sig.ident, error.to_string())
            .to_compile_error()
            .into();
    }

    let fn_name = &input_fn.sig.ident;
    let fn_name_str = fn_name.to_string();

    // Generate handler struct name
    let handler_name = format_ident!("{}Prompt", to_pascal_case(&fn_name_str));
    let impl_module = format_ident!("__fastmcp_prompt_{}", fn_name);

    // Get prompt name
    let prompt_name = attrs.name.unwrap_or_else(|| fn_name_str.clone());

    // Get description
    let description = attrs
        .description
        .or_else(|| extract_doc_comments(&input_fn.attrs));
    let description_tokens = description.as_ref().map_or_else(
        || quote! { None },
        |desc| quote! { Some(#desc.to_string()) },
    );

    // Parse timeout attribute
    let timeout_tokens = if let Some(ref timeout_str) = attrs.timeout {
        match parse_duration_to_millis(timeout_str) {
            Ok(millis) => {
                quote! {
                    fn timeout(&self) -> Option<std::time::Duration> {
                        Some(std::time::Duration::from_millis(#millis))
                    }
                }
            }
            Err(e) => {
                return syn::Error::new_spanned(
                    &input_fn.sig.ident,
                    format!("invalid timeout: {e}"),
                )
                .to_compile_error()
                .into();
            }
        }
    } else {
        quote! {}
    };

    // Parse parameters for prompt arguments (skip first if it's &McpContext)
    let mut prompt_args: Vec<TokenStream2> = Vec::new();
    let mut expects_context = false;
    let mut mrtr_resume_param: Option<(&Ident, &Type)> = None;

    for (i, arg) in input_fn.sig.inputs.iter().enumerate() {
        if let FnArg::Typed(pat_type) = arg {
            // Skip the context parameter
            if i == 0 && is_mcp_context_ref(pat_type.ty.as_ref()) {
                expects_context = true;
                continue;
            }

            if is_mrtr_completed_inputs_option_ref(pat_type.ty.as_ref()) {
                let Pat::Ident(pat_ident) = pat_type.pat.as_ref() else {
                    return syn::Error::new_spanned(
                        &pat_type.pat,
                        "MRTR resume input must use an identifier pattern",
                    )
                    .to_compile_error()
                    .into();
                };
                if mrtr_resume_param.is_some() {
                    return syn::Error::new_spanned(
                        &pat_type.ty,
                        "a handler may have only one MRTR resume input",
                    )
                    .to_compile_error()
                    .into();
                }
                mrtr_resume_param = Some((&pat_ident.ident, pat_type.ty.as_ref()));
                continue;
            }
            if contains_mrtr_completed_inputs(pat_type.ty.as_ref()) {
                return invalid_mrtr_resume_parameter_error(pat_type.ty.as_ref())
                    .to_compile_error()
                    .into();
            }

            if let Pat::Ident(pat_ident) = pat_type.pat.as_ref() {
                let param_name = pat_ident.ident.to_string();
                let param_doc = extract_doc_comments(&pat_type.attrs);
                let is_optional = is_option_type(pat_type.ty.as_ref());
                let has_default = attrs.defaults.contains_key(&param_name);
                let required = !(is_optional || has_default);

                let desc_tokens = param_doc
                    .as_ref()
                    .map_or_else(|| quote! { None }, |d| quote! { Some(#d.to_string()) });

                prompt_args.push(quote! {
                    fastmcp_protocol::PromptArgument {
                        name: #param_name.to_string(),
                        description: #desc_tokens,
                        required: #required,
                    }
                });
            }
        }
    }

    // Generate parameter extraction for the get method
    let mut param_extractions: Vec<TokenStream2> = Vec::new();
    let mut param_names: Vec<Ident> = Vec::new();

    for (i, arg) in input_fn.sig.inputs.iter().enumerate() {
        if let FnArg::Typed(pat_type) = arg {
            // Skip context
            if i == 0 && is_mcp_context_ref(pat_type.ty.as_ref()) {
                continue;
            }

            if is_mrtr_completed_inputs_option_ref(pat_type.ty.as_ref()) {
                let Pat::Ident(pat_ident) = pat_type.pat.as_ref() else {
                    unreachable!("the first prompt parameter pass validated the pattern")
                };
                param_names.push(pat_ident.ident.clone());
                continue;
            }

            if let Pat::Ident(pat_ident) = pat_type.pat.as_ref() {
                let param_name = &pat_ident.ident;
                let param_name_str = param_name.to_string();
                let param_ty = pat_type.ty.as_ref();
                let is_optional = is_option_type(param_ty);
                let default_lit = attrs.defaults.get(&param_name_str).cloned();

                param_names.push(param_name.clone());

                if is_optional {
                    if let Some(default_lit) = default_lit {
                        let default_expr = match default_lit_expr_for_type(&default_lit, param_ty) {
                            Ok(v) => v,
                            Err(e) => return e.to_compile_error().into(),
                        };
                        // Optional parameters with defaults: use default if missing
                        param_extractions.push(quote! {
                            let #param_name: #param_ty = match arguments.get(#param_name_str) {
                                Some(v) => Some(v.clone()),
                                None => #default_expr,
                            };
                        });
                    } else {
                        // Optional parameters: return None if not provided
                        param_extractions.push(quote! {
                            let #param_name: #param_ty = arguments.get(#param_name_str).cloned();
                        });
                    }
                } else {
                    if let Some(default_lit) = default_lit {
                        let default_expr = match default_lit_expr_for_type(&default_lit, param_ty) {
                            Ok(v) => v,
                            Err(e) => return e.to_compile_error().into(),
                        };
                        // Required-typed parameters with defaults: use default if missing.
                        param_extractions.push(quote! {
                            let #param_name: #param_ty = match arguments.get(#param_name_str) {
                                Some(v) => v.clone(),
                                None => #default_expr,
                            };
                        });
                    } else {
                        // Required parameters: return an error if missing
                        param_extractions.push(quote! {
                            let #param_name: #param_ty = arguments.get(#param_name_str)
                                .cloned()
                                .ok_or_else(|| fastmcp_core::McpError::invalid_params(
                                    format!("missing required argument: {}", #param_name_str)
                                ))?;
                        });
                    }
                }
            }
        }
    }

    let mrtr_param_extractions = param_extractions.clone();
    if let Some((name, ty)) = mrtr_resume_param {
        param_extractions.push(quote! {
            let #name: #ty = None;
        });
    }

    let is_async = input_fn.sig.asyncness.is_some();

    // Generate result conversion based on return type (supports Result<Vec<PromptMessage>, E>)
    let return_type = &input_fn.sig.output;
    let final_result_conversion = generate_final_prompt_result_conversion(return_type);
    let final_outcome_conversion = generate_final_prompt_outcome_conversion(return_type);
    if mrtr_resume_param.is_some() && final_outcome_conversion.is_none() {
        return syn::Error::new_spanned(
            &input_fn.sig.output,
            "MRTR resume input requires FinalMethodOutcome<FinalGetPromptResult>",
        )
        .to_compile_error()
        .into();
    }
    let prompt_result_conversion =
        if final_result_conversion.is_some() || final_outcome_conversion.is_some() {
            generate_final_legacy_rejection("prompt", "PromptHandler::get_final")
        } else {
            generate_prompt_result_conversion(return_type)
        };
    let execution_methods = generate_prompt_execution_methods(
        is_async,
        expects_context,
        fn_name,
        &param_names,
        &param_extractions,
        &prompt_result_conversion,
        final_result_conversion.as_ref(),
        is_async && mrtr_resume_param.is_none(),
    );
    let mrtr_outcome_methods = match (mrtr_resume_param, final_outcome_conversion.as_ref()) {
        (Some((name, ty)), Some(conversion)) => generate_prompt_mrtr_outcome_methods(
            is_async,
            expects_context,
            fn_name,
            &param_names,
            &mrtr_param_extractions,
            name,
            ty,
            conversion,
        ),
        (None, _) => TokenStream2::new(),
        (Some(_), None) => unreachable!("MRTR return validation above rejects this form"),
    };

    // Generate version token
    let version_tokens = attrs
        .version
        .as_ref()
        .map_or_else(|| quote! { None }, |v| quote! { Some(#v.to_string()) });
    let icon_tokens = generated_icon_field(attrs.icon.as_deref());
    let icon_hooks = generated_icon_hooks(attrs.icon.as_deref());

    // Generate tags
    let tag_entries: Vec<TokenStream2> = attrs
        .tags
        .iter()
        .map(|tag| quote! { #tag.to_string() })
        .collect();

    let expanded = quote! {
        // Keep the original function
        #input_fn

        /// Handler for the #fn_name prompt.
        #[derive(Clone)]
        pub struct #handler_name;

        #[doc(hidden)]
        mod #impl_module {
            use super::*;
            use #core as fastmcp_core;
            use #protocol as fastmcp_protocol;
            use #server as fastmcp_server;

            impl fastmcp_server::PromptHandler for #handler_name {
                fn definition(&self) -> fastmcp_protocol::Prompt {
                    fastmcp_protocol::Prompt {
                        name: #prompt_name.to_string(),
                        description: #description_tokens,
                        arguments: vec![#(#prompt_args),*],
                        icon: #icon_tokens,
                        version: #version_tokens,
                        tags: vec![#(#tag_entries),*],
                    }
                }

                #timeout_tokens

                #icon_hooks

                #execution_methods

                #mrtr_outcome_methods
            }
        }
    };

    TokenStream::from(expanded)
}

/// Derives JSON Schema for a type.
///
/// Used for generating input schemas for tools. Generates a `json_schema()` method
/// that returns the JSON Schema representation of the type.
///
/// # Example
///
/// ```ignore
/// use fastmcp_rust::JsonSchema;
///
/// #[derive(JsonSchema)]
/// struct MyToolInput {
///     /// The name of the person
///     name: String,
///     /// Optional age
///     age: Option<u32>,
///     /// List of tags
///     tags: Vec<String>,
/// }
///
/// // Generated schema:
/// // {
/// //   "type": "object",
/// //   "properties": {
/// //     "name": { "type": "string", "description": "The name of the person" },
/// //     "age": { "type": ["integer", "null"], "description": "Optional age" },
/// //     "tags": { "type": "array", "items": { "type": "string" }, "description": "List of tags" }
/// //   },
/// //   "required": ["name", "tags"]
/// // }
/// ```
///
/// # Supported Types
///
/// - `String`, `&str` → `"string"`
/// - `i8`..`i128`, `u8`..`u128`, `isize`, `usize` → `"integer"`
/// - `f32`, `f64` → `"number"`
/// - `bool` → `"boolean"`
/// - `Option<T>` → schema for T widened with `"null"` (e.g. `["integer", "null"]`), field not required; explicit JSON `null` is treated as omitted
/// - `Vec<T>` → `"array"` with items schema
/// - `HashMap<String, T>` → `"object"` with additionalProperties
/// - Other types → `"object"` (custom types should derive JsonSchema)
///
/// # Attributes
///
/// - `#[json_schema(rename = "...")]` - Rename the field in the schema
/// - `#[json_schema(skip)]` - Skip this field
/// - `#[json_schema(flatten)]` - Flatten nested object properties
#[proc_macro_derive(JsonSchema, attributes(json_schema))]
pub fn derive_json_schema(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as syn::DeriveInput);
    let serde_json = match serde_json_crate_path() {
        Ok(path) => path,
        Err(error) => return error.to_compile_error().into(),
    };

    let name = &input.ident;
    let impl_module = format_ident!("__fastmcp_json_schema_{}", name);
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    // Extract type-level doc comments for schema description
    let type_description = extract_doc_comments(&input.attrs);
    let type_desc_tokens = type_description
        .as_ref()
        .map_or_else(|| quote! { None::<&str> }, |desc| quote! { Some(#desc) });

    // Process fields based on data type
    let schema_impl = match &input.data {
        syn::Data::Struct(data_struct) => generate_struct_schema(data_struct, &type_desc_tokens),
        syn::Data::Enum(data_enum) => generate_enum_schema(data_enum, &type_desc_tokens),
        syn::Data::Union(_) => {
            return syn::Error::new_spanned(input, "JsonSchema cannot be derived for unions")
                .to_compile_error()
                .into();
        }
    };

    let expanded = quote! {
        #[doc(hidden)]
        #[allow(non_snake_case)]
        mod #impl_module {
            use super::*;
            use #serde_json as serde_json;

            impl #impl_generics #name #ty_generics #where_clause {
                /// Returns the JSON Schema for this type.
                pub fn json_schema() -> serde_json::Value {
                    #schema_impl
                }
            }
        }
    };

    TokenStream::from(expanded)
}

/// Generates JSON Schema for a struct.
fn generate_struct_schema(data: &syn::DataStruct, type_desc_tokens: &TokenStream2) -> TokenStream2 {
    match &data.fields {
        syn::Fields::Named(fields) => {
            let mut property_entries = Vec::new();
            let mut required_fields = Vec::new();

            for field in &fields.named {
                // Check for skip attribute
                if has_json_schema_attr(&field.attrs, "skip") {
                    continue;
                }

                let field_name = field.ident.as_ref().unwrap();

                // Check for rename attribute
                let schema_name =
                    get_json_schema_rename(&field.attrs).unwrap_or_else(|| field_name.to_string());

                // Get field doc comment
                let field_doc = extract_doc_comments(&field.attrs);

                // Generate schema for this field's type
                let field_type = &field.ty;
                let is_optional = is_option_type(field_type);

                // Generate the base schema
                let field_schema = type_to_json_schema(field_type);

                // Add description if available
                let property_value = if let Some(desc) = &field_doc {
                    quote! {
                        {
                            let mut schema = #field_schema;
                            if let Some(obj) = schema.as_object_mut() {
                                obj.insert("description".to_string(), serde_json::json!(#desc));
                            }
                            schema
                        }
                    }
                } else {
                    field_schema
                };

                property_entries.push(quote! {
                    (#schema_name.to_string(), #property_value)
                });

                // Add to required if not optional
                if !is_optional {
                    required_fields.push(schema_name);
                }
            }

            quote! {
                {
                    let properties: std::collections::HashMap<String, serde_json::Value> = vec![
                        #(#property_entries),*
                    ].into_iter().collect();

                    let required: Vec<String> = vec![#(#required_fields.to_string()),*];

                    let mut schema = serde_json::json!({
                        "type": "object",
                        "properties": properties,
                        "required": required,
                    });

                    // Add description if available
                    if let Some(desc) = #type_desc_tokens {
                        if let Some(obj) = schema.as_object_mut() {
                            obj.insert("description".to_string(), serde_json::json!(desc));
                        }
                    }

                    schema
                }
            }
        }
        syn::Fields::Unnamed(fields) => {
            // Tuple struct - generate as array
            if fields.unnamed.len() == 1 {
                // Newtype pattern - just use inner type's schema
                let inner_type = &fields.unnamed.first().unwrap().ty;
                let inner_schema = type_to_json_schema(inner_type);
                quote! { #inner_schema }
            } else {
                // Multiple fields - tuple represented as array with prefixItems
                let item_schemas: Vec<_> = fields
                    .unnamed
                    .iter()
                    .map(|f| type_to_json_schema(&f.ty))
                    .collect();
                let num_items = item_schemas.len();
                quote! {
                    {
                        let items: Vec<serde_json::Value> = vec![#(#item_schemas),*];
                        serde_json::json!({
                            "type": "array",
                            "prefixItems": items,
                            "minItems": #num_items,
                            "maxItems": #num_items,
                        })
                    }
                }
            }
        }
        syn::Fields::Unit => {
            // Unit struct - null type
            quote! { serde_json::json!({ "type": "null" }) }
        }
    }
}

/// Generates JSON Schema for an enum.
fn generate_enum_schema(data: &syn::DataEnum, type_desc_tokens: &TokenStream2) -> TokenStream2 {
    // Check if all variants are unit variants (string enum)
    let all_unit = data
        .variants
        .iter()
        .all(|v| matches!(v.fields, syn::Fields::Unit));

    if all_unit {
        // Simple string enum
        let variant_names: Vec<String> =
            data.variants.iter().map(|v| v.ident.to_string()).collect();

        quote! {
            {
                let mut schema = serde_json::json!({
                    "type": "string",
                    "enum": [#(#variant_names),*]
                });

                if let Some(desc) = #type_desc_tokens {
                    if let Some(obj) = schema.as_object_mut() {
                        obj.insert("description".to_string(), serde_json::json!(desc));
                    }
                }

                schema
            }
        }
    } else {
        // Tagged union - use oneOf
        let variant_schemas: Vec<TokenStream2> = data
            .variants
            .iter()
            .map(|variant| {
                let variant_name = variant.ident.to_string();
                match &variant.fields {
                    syn::Fields::Unit => {
                        quote! {
                            serde_json::json!({
                                "type": "object",
                                "properties": {
                                    #variant_name: { "type": "null" }
                                },
                                "required": [#variant_name]
                            })
                        }
                    }
                    syn::Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
                        let inner_type = &fields.unnamed.first().unwrap().ty;
                        let inner_schema = type_to_json_schema(inner_type);
                        quote! {
                            serde_json::json!({
                                "type": "object",
                                "properties": {
                                    #variant_name: #inner_schema
                                },
                                "required": [#variant_name]
                            })
                        }
                    }
                    _ => {
                        // Complex variant - just mark as object
                        quote! {
                            serde_json::json!({
                                "type": "object",
                                "properties": {
                                    #variant_name: { "type": "object" }
                                },
                                "required": [#variant_name]
                            })
                        }
                    }
                }
            })
            .collect();

        quote! {
            {
                let mut schema = serde_json::json!({
                    "oneOf": [#(#variant_schemas),*]
                });

                if let Some(desc) = #type_desc_tokens {
                    if let Some(obj) = schema.as_object_mut() {
                        obj.insert("description".to_string(), serde_json::json!(desc));
                    }
                }

                schema
            }
        }
    }
}

/// Checks if a field has a specific json_schema attribute.
fn has_json_schema_attr(attrs: &[Attribute], attr_name: &str) -> bool {
    for attr in attrs {
        if attr.path().is_ident("json_schema") {
            if let Meta::List(meta_list) = &attr.meta {
                if let Ok(nested) = meta_list.parse_args::<Ident>() {
                    if nested == attr_name {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Gets the rename value from json_schema attribute if present.
fn get_json_schema_rename(attrs: &[Attribute]) -> Option<String> {
    for attr in attrs {
        if attr.path().is_ident("json_schema") {
            if let Meta::List(meta_list) = &attr.meta {
                // Parse as ident = "value"
                let result: syn::Result<(Ident, LitStr)> =
                    meta_list.parse_args_with(|input: ParseStream| {
                        let ident: Ident = input.parse()?;
                        let _: Token![=] = input.parse()?;
                        let lit: LitStr = input.parse()?;
                        Ok((ident, lit))
                    });

                if let Ok((ident, lit)) = result {
                    if ident == "rename" {
                        return Some(lit.value());
                    }
                }
            }
        }
    }
    None
}
