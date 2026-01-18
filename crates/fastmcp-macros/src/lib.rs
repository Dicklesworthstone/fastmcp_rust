//! Procedural macros for FastMCP.
//!
//! This crate provides attribute macros for defining MCP handlers:
//! - `#[tool]` - Define a tool handler
//! - `#[resource]` - Define a resource handler
//! - `#[prompt]` - Define a prompt handler
//!
//! # Example
//!
//! ```ignore
//! use fastmcp::prelude::*;
//!
//! /// Greets a user by name.
//! #[tool]
//! async fn greet(
//!     ctx: &McpContext,
//!     /// The name to greet
//!     name: String,
//! ) -> String {
//!     format!("Hello, {name}!")
//! }
//!
//! /// A configuration file resource.
//! #[resource(uri = "config://app")]
//! async fn app_config(ctx: &McpContext) -> String {
//!     std::fs::read_to_string("config.json").unwrap()
//! }
//!
//! /// A code review prompt.
//! #[prompt]
//! async fn code_review(
//!     ctx: &McpContext,
//!     /// The code to review
//!     code: String,
//! ) -> Vec<PromptMessage> {
//!     vec![PromptMessage {
//!         role: Role::User,
//!         content: Content::Text { text: format!("Review this code:\n\n{code}") },
//!     }]
//! }
//! ```

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{
    Attribute, FnArg, Ident, ItemFn, Lit, LitStr, Meta, Pat, Token, Type, parse::Parse,
    parse::ParseStream, parse_macro_input,
};

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

/// Generates code to convert a function result to Vec<Content>.
fn generate_result_conversion(output: &syn::ReturnType) -> TokenStream2 {
    let kind = analyze_return_type(output);

    match kind {
        ReturnTypeKind::Unit => quote! {
            Ok(vec![])
        },
        ReturnTypeKind::VecContent => quote! {
            Ok(result)
        },
        ReturnTypeKind::String => quote! {
            Ok(vec![fastmcp_protocol::Content::Text { text: result }])
        },
        ReturnTypeKind::ResultVecContent | ReturnTypeKind::McpResultVecContent => quote! {
            result.map_err(|e| fastmcp_core::McpError::internal_error(e.to_string()))
        },
        ReturnTypeKind::ResultString | ReturnTypeKind::McpResultString => quote! {
            result
                .map(|s| vec![fastmcp_protocol::Content::Text { text: s }])
                .map_err(|e| fastmcp_core::McpError::internal_error(e.to_string()))
        },
        ReturnTypeKind::Other => quote! {
            // Convert via ToString or Debug as fallback
            let text = format!("{}", result);
            Ok(vec![fastmcp_protocol::Content::Text { text }])
        },
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
            // For Option<T>, get the inner type
            if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                if let Some(syn::GenericArgument::Type(inner_ty)) = args.args.first() {
                    return type_to_json_schema(inner_ty);
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
        _ => {
            // Default to object for complex types
            quote! { serde_json::json!({ "type": "object" }) }
        }
    }
}

// ============================================================================
// Tool Macro
// ============================================================================

/// Parsed attributes for #[tool].
struct ToolAttrs {
    name: Option<String>,
    description: Option<String>,
}

impl Parse for ToolAttrs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut name = None;
        let mut description = None;

        while !input.is_empty() {
            let ident: Ident = input.parse()?;
            input.parse::<Token![=]>()?;

            match ident.to_string().as_str() {
                "name" => {
                    let lit: LitStr = input.parse()?;
                    name = Some(lit.value());
                }
                "description" => {
                    let lit: LitStr = input.parse()?;
                    description = Some(lit.value());
                }
                _ => {
                    return Err(syn::Error::new(ident.span(), "unknown attribute"));
                }
            }

            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }

        Ok(Self { name, description })
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
#[proc_macro_attribute]
#[allow(clippy::too_many_lines)]
pub fn tool(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attrs = parse_macro_input!(attr as ToolAttrs);
    let input_fn = parse_macro_input!(item as ItemFn);

    let fn_name = &input_fn.sig.ident;
    let fn_name_str = fn_name.to_string();

    // Generate handler struct name (PascalCase)
    let handler_name = format_ident!("{}", to_pascal_case(&fn_name_str));

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

    // Parse parameters (skip first if it's &McpContext)
    let mut params: Vec<(&Ident, &Type, Option<String>)> = Vec::new();
    let mut required_params: Vec<String> = Vec::new();

    for (i, arg) in input_fn.sig.inputs.iter().enumerate() {
        if let FnArg::Typed(pat_type) = arg {
            // Skip the first parameter if it looks like a context
            if i == 0 && is_mcp_context_ref(pat_type.ty.as_ref()) {
                continue;
            }

            if let Pat::Ident(pat_ident) = pat_type.pat.as_ref() {
                let param_name = &pat_ident.ident;
                let param_type = pat_type.ty.as_ref();
                let param_doc = extract_doc_comments(&pat_type.attrs);

                // Check if parameter is required (not Option<T>)
                let is_optional = is_option_type(param_type);

                if !is_optional {
                    required_params.push(param_name.to_string());
                }

                params.push((param_name, param_type, param_doc));
            }
        }
    }

    // Generate JSON schema for input
    let property_entries: Vec<TokenStream2> = params
        .iter()
        .map(|(name, ty, doc)| {
            let name_str = name.to_string();
            let schema = type_to_json_schema(ty);
            if let Some(desc) = doc {
                quote! {
                    (#name_str.to_string(), {
                        let mut s = #schema;
                        if let Some(obj) = s.as_object_mut() {
                            obj.insert("description".to_string(), serde_json::json!(#desc));
                        }
                        s
                    })
                }
            } else {
                quote! {
                    (#name_str.to_string(), #schema)
                }
            }
        })
        .collect();

    // Generate parameter extraction code
    let param_extractions: Vec<TokenStream2> = params
        .iter()
        .map(|(name, ty, _)| {
            let name_str = name.to_string();
            let is_optional = is_option_type(ty);

            if is_optional {
                quote! {
                    let #name: #ty = arguments.get(#name_str)
                        .and_then(|v| serde_json::from_value(v.clone()).ok());
                }
            } else {
                quote! {
                    let #name: #ty = arguments.get(#name_str)
                        .ok_or_else(|| fastmcp_core::McpError::invalid_params(
                            format!("missing required parameter: {}", #name_str)
                        ))
                        .and_then(|v| serde_json::from_value(v.clone())
                            .map_err(|e| fastmcp_core::McpError::invalid_params(e.to_string())))?;
                }
            }
        })
        .collect();

    // Generate parameter names for function call
    let param_names: Vec<&Ident> = params.iter().map(|(name, _, _)| *name).collect();

    // Check if function is async
    let is_async = input_fn.sig.asyncness.is_some();

    // Analyze return type to determine conversion strategy
    let return_type = &input_fn.sig.output;
    let result_conversion = generate_result_conversion(return_type);

    // Generate the call expression (async functions are executed via block_on)
    let call_expr = if is_async {
        quote! {
            fastmcp_core::runtime::block_on(async move {
                #fn_name(ctx, #(#param_names),*).await
            })
        }
    } else {
        quote! {
            #fn_name(ctx, #(#param_names),*)
        }
    };

    // Generate the handler implementation
    let expanded = quote! {
        // Keep the original function
        #input_fn

        /// Handler for the #fn_name tool.
        #[derive(Clone)]
        pub struct #handler_name;

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
                        "type": "object",
                        "properties": properties,
                        "required": required,
                    }),
                }
            }

            fn call(
                &self,
                ctx: &fastmcp_core::McpContext,
                arguments: serde_json::Value,
            ) -> fastmcp_core::McpResult<Vec<fastmcp_protocol::Content>> {
                // Parse arguments as object
                let arguments = arguments.as_object()
                    .cloned()
                    .unwrap_or_default();

                // Extract parameters
                #(#param_extractions)*

                // Call the function
                let result = #call_expr;

                // Convert result to Vec<Content> based on return type
                #result_conversion
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
}

impl Parse for ResourceAttrs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut uri = None;
        let mut name = None;
        let mut description = None;
        let mut mime_type = None;

        while !input.is_empty() {
            let ident: Ident = input.parse()?;
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
                _ => {
                    return Err(syn::Error::new(ident.span(), "unknown attribute"));
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
#[proc_macro_attribute]
pub fn resource(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attrs = parse_macro_input!(attr as ResourceAttrs);
    let input_fn = parse_macro_input!(item as ItemFn);

    let fn_name = &input_fn.sig.ident;
    let fn_name_str = fn_name.to_string();

    // Generate handler struct name
    let handler_name = format_ident!("{}Resource", to_pascal_case(&fn_name_str));

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

    let is_async = input_fn.sig.asyncness.is_some();
    let call_expr = if is_async {
        quote! {
            fastmcp_core::runtime::block_on(async move {
                #fn_name(ctx).await
            })
        }
    } else {
        quote! {
            #fn_name(ctx)
        }
    };

    let expanded = quote! {
        // Keep the original function
        #input_fn

        /// Handler for the #fn_name resource.
        #[derive(Clone)]
        pub struct #handler_name;

        impl fastmcp_server::ResourceHandler for #handler_name {
            fn definition(&self) -> fastmcp_protocol::Resource {
                fastmcp_protocol::Resource {
                    uri: #uri.to_string(),
                    name: #resource_name.to_string(),
                    description: #description_tokens,
                    mime_type: Some(#mime_type.to_string()),
                }
            }

            fn read(
                &self,
                ctx: &fastmcp_core::McpContext,
            ) -> fastmcp_core::McpResult<Vec<fastmcp_protocol::ResourceContent>> {
                let result = #call_expr;
                // Convert result to text content
                // Supports: String, &str, types implementing ToString
                let text = result.to_string();
                Ok(vec![fastmcp_protocol::ResourceContent {
                    uri: #uri.to_string(),
                    mime_type: Some(#mime_type.to_string()),
                    text: Some(text),
                    blob: None,
                }])
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
}

impl Parse for PromptAttrs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut name = None;
        let mut description = None;

        while !input.is_empty() {
            let ident: Ident = input.parse()?;
            input.parse::<Token![=]>()?;

            match ident.to_string().as_str() {
                "name" => {
                    let lit: LitStr = input.parse()?;
                    name = Some(lit.value());
                }
                "description" => {
                    let lit: LitStr = input.parse()?;
                    description = Some(lit.value());
                }
                _ => {
                    return Err(syn::Error::new(ident.span(), "unknown attribute"));
                }
            }

            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }

        Ok(Self { name, description })
    }
}

/// Defines a prompt handler.
///
/// # Attributes
///
/// - `name` - Override the prompt name (default: function name)
/// - `description` - Prompt description (default: doc comment)
#[proc_macro_attribute]
pub fn prompt(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attrs = parse_macro_input!(attr as PromptAttrs);
    let input_fn = parse_macro_input!(item as ItemFn);

    let fn_name = &input_fn.sig.ident;
    let fn_name_str = fn_name.to_string();

    // Generate handler struct name
    let handler_name = format_ident!("{}Prompt", to_pascal_case(&fn_name_str));

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

    // Parse parameters for prompt arguments (skip first if it's &McpContext)
    let mut prompt_args: Vec<TokenStream2> = Vec::new();

    for (i, arg) in input_fn.sig.inputs.iter().enumerate() {
        if let FnArg::Typed(pat_type) = arg {
            // Skip the context parameter
            if i == 0 && is_mcp_context_ref(pat_type.ty.as_ref()) {
                continue;
            }

            if let Pat::Ident(pat_ident) = pat_type.pat.as_ref() {
                let param_name = pat_ident.ident.to_string();
                let param_doc = extract_doc_comments(&pat_type.attrs);
                let is_optional = is_option_type(pat_type.ty.as_ref());

                let desc_tokens = param_doc
                    .as_ref()
                    .map_or_else(|| quote! { None }, |d| quote! { Some(#d.to_string()) });

                prompt_args.push(quote! {
                    fastmcp_protocol::PromptArgument {
                        name: #param_name.to_string(),
                        description: #desc_tokens,
                        required: !#is_optional,
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

            if let Pat::Ident(pat_ident) = pat_type.pat.as_ref() {
                let param_name = &pat_ident.ident;
                let param_name_str = param_name.to_string();

                param_names.push(param_name.clone());
                param_extractions.push(quote! {
                    let #param_name = arguments.get(#param_name_str)
                        .cloned()
                        .unwrap_or_default();
                });
            }
        }
    }

    let is_async = input_fn.sig.asyncness.is_some();
    let call_expr = if is_async {
        quote! {
            fastmcp_core::runtime::block_on(async move {
                #fn_name(ctx, #(#param_names),*).await
            })
        }
    } else {
        quote! {
            #fn_name(ctx, #(#param_names),*)
        }
    };

    let expanded = quote! {
        // Keep the original function
        #input_fn

        /// Handler for the #fn_name prompt.
        #[derive(Clone)]
        pub struct #handler_name;

        impl fastmcp_server::PromptHandler for #handler_name {
            fn definition(&self) -> fastmcp_protocol::Prompt {
                fastmcp_protocol::Prompt {
                    name: #prompt_name.to_string(),
                    description: #description_tokens,
                    arguments: vec![#(#prompt_args),*],
                }
            }

            fn get(
                &self,
                ctx: &fastmcp_core::McpContext,
                arguments: std::collections::HashMap<String, String>,
            ) -> fastmcp_core::McpResult<Vec<fastmcp_protocol::PromptMessage>> {
                #(#param_extractions)*
                let result = #call_expr;
                Ok(result)
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
/// use fastmcp::JsonSchema;
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
/// //     "age": { "type": "integer", "description": "Optional age" },
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
/// - `Option<T>` → schema for T, field not required
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

    let name = &input.ident;
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
        impl #impl_generics #name #ty_generics #where_clause {
            /// Returns the JSON Schema for this type.
            pub fn json_schema() -> serde_json::Value {
                #schema_impl
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
