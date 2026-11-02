//! The extension attribute deliberately has no direct-component fallback.
//!
//! Manifest verification complements `proc_macro_crate`: that crate silently
//! chooses the last alias when the same package is declared more than once.
//! Extension authors must explicitly select a facade in that case so generated
//! adapters cannot bind to a different version's authority contract by accident.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use proc_macro_crate::FoundCrate;
use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};
use syn::ext::IdentExt as _;
use syn::parse::{Parse, ParseStream};
use syn::{FnArg, GenericArgument, Ident, ItemFn, LitStr, PathArguments, ReturnType, Token, Type};

const FACADE_PACKAGE: &str = "fastmcp-rust";

#[derive(Debug)]
struct ExtensionAttributes {
    method: LitStr,
    params_schema: LitStr,
    result_schema: LitStr,
    crate_override: Option<LitStr>,
}

impl Parse for ExtensionAttributes {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let mut method = None;
        let mut params_schema = None;
        let mut result_schema = None;
        let mut crate_override = None;

        while !input.is_empty() {
            let key = input.call(Ident::parse_any)?;
            let slot = match key.to_string().as_str() {
                "method" => &mut method,
                "params_schema" => &mut params_schema,
                "result_schema" => &mut result_schema,
                "crate" => &mut crate_override,
                _ => {
                    return Err(syn::Error::new_spanned(
                        key,
                        "unknown extension option; expected method, params_schema, result_schema, or crate",
                    ));
                }
            };
            if slot.is_some() {
                return Err(syn::Error::new_spanned(key, "duplicate extension option"));
            }
            input.parse::<Token![=]>()?;
            let value: LitStr = input.parse()?;
            if value.value().trim().is_empty() {
                return Err(syn::Error::new_spanned(
                    value,
                    "extension option must not be empty",
                ));
            }
            *slot = Some(value);
            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }

        let required = |value: Option<LitStr>, name: &str| {
            value.ok_or_else(|| {
                syn::Error::new(input.span(), format!("missing extension option `{name}`"))
            })
        };
        Ok(Self {
            method: required(method, "method")?,
            params_schema: required(params_schema, "params_schema")?,
            result_schema: required(result_schema, "result_schema")?,
            crate_override,
        })
    }
}

struct HandlerTypes<'a> {
    settings: &'a Type,
    request: &'a Type,
    response: &'a Type,
}

fn handler_types(function: &ItemFn) -> syn::Result<HandlerTypes<'_>> {
    let signature = &function.sig;
    if !signature.generics.params.is_empty() || signature.generics.where_clause.is_some() {
        return Err(syn::Error::new_spanned(
            &signature.generics,
            "extension handlers must use concrete request, response, and settings types",
        ));
    }
    if !matches!(signature.safety, syn::Safety::Default)
        || signature.abi.is_some()
        || signature.variadic.is_some()
        || signature.constness.is_some()
    {
        return Err(syn::Error::new_spanned(
            signature,
            "extension handlers must be ordinary safe Rust functions or async functions",
        ));
    }
    if signature.inputs.len() != 2 {
        return Err(syn::Error::new_spanned(
            &signature.inputs,
            "extension handlers require exactly a sealed context and an owned request",
        ));
    }
    let mut arguments = signature.inputs.iter();
    let Some(FnArg::Typed(context)) = arguments.next() else {
        return Err(syn::Error::new_spanned(
            &signature.inputs,
            "extension handlers cannot have a self receiver",
        ));
    };
    let Some(FnArg::Typed(request)) = arguments.next() else {
        return Err(syn::Error::new_spanned(
            &signature.inputs,
            "extension handlers cannot have a self receiver",
        ));
    };
    let invalid_context = || {
        syn::Error::new_spanned(
            &context.ty,
            "first extension parameter must be ExtensionContext<'_, Settings> by value",
        )
    };
    let Type::Path(context_path) = context.ty.as_ref() else {
        return Err(invalid_context());
    };
    let Some(context_type) = context_path.path.segments.last() else {
        return Err(invalid_context());
    };
    if context_path.qself.is_some() || context_type.ident != "ExtensionContext" {
        return Err(invalid_context());
    }
    let PathArguments::AngleBracketed(context_args) = &context_type.arguments else {
        return Err(invalid_context());
    };
    let mut context_args_iter = context_args.args.iter();
    let (Some(GenericArgument::Lifetime(lifetime)), Some(GenericArgument::Type(settings))) =
        (context_args_iter.next(), context_args_iter.next())
    else {
        return Err(invalid_context());
    };
    if lifetime.ident != "_" || context_args_iter.next().is_some() {
        return Err(invalid_context());
    }

    let invalid_response = || {
        syn::Error::new_spanned(
            &signature.output,
            "extension handlers must return McpResult<Response>",
        )
    };
    let ReturnType::Type(_, output) = &signature.output else {
        return Err(invalid_response());
    };
    let Type::Path(output_path) = output.as_ref() else {
        return Err(invalid_response());
    };
    let Some(result_type) = output_path.path.segments.last() else {
        return Err(invalid_response());
    };
    if output_path.qself.is_some() || result_type.ident != "McpResult" {
        return Err(invalid_response());
    }
    let PathArguments::AngleBracketed(result_args) = &result_type.arguments else {
        return Err(invalid_response());
    };
    let Some(GenericArgument::Type(response)) = result_args.args.first() else {
        return Err(invalid_response());
    };
    if result_args.args.len() != 1 {
        return Err(invalid_response());
    }
    for ty in [settings, request.ty.as_ref(), response] {
        if has_opaque_type(ty) {
            return Err(syn::Error::new_spanned(
                ty,
                "extension handler types cannot contain impl Trait or inferred types",
            ));
        }
    }
    Ok(HandlerTypes {
        settings,
        request: &request.ty,
        response,
    })
}

fn has_opaque_type(ty: &Type) -> bool {
    match ty {
        Type::ImplTrait(_) | Type::Infer(_) => true,
        Type::Path(path) => path
            .path
            .segments
            .iter()
            .any(|segment| match &segment.arguments {
                PathArguments::AngleBracketed(arguments) => arguments.args.iter().any(
                    |argument| matches!(argument, GenericArgument::Type(ty) if has_opaque_type(ty)),
                ),
                _ => false,
            }),
        Type::Reference(reference) => has_opaque_type(&reference.elem),
        Type::Array(array) => has_opaque_type(&array.elem),
        Type::Slice(slice) => has_opaque_type(&slice.elem),
        Type::Tuple(tuple) => tuple.elems.iter().any(has_opaque_type),
        Type::Paren(paren) => has_opaque_type(&paren.elem),
        Type::Group(group) => has_opaque_type(&group.elem),
        _ => false,
    }
}

/// Proven facade names in the consumer manifest. An alias that resolves to
/// different packages under different target tables is deliberately rejected:
/// `proc_macro_crate` does not evaluate target cfg predicates either.
#[derive(Debug)]
struct FacadeManifest {
    is_facade: bool,
    aliases: BTreeSet<String>,
}

fn dependency_tables<'a>(manifest: &'a toml::Table) -> Vec<&'a toml::Table> {
    let mut tables = Vec::new();
    let mut collect = |table: &'a toml::Table| {
        for name in ["dependencies", "dev-dependencies"] {
            if let Some(dependencies) = table.get(name).and_then(toml::Value::as_table) {
                tables.push(dependencies);
            }
        }
    };
    collect(manifest);
    if let Some(targets) = manifest.get("target").and_then(toml::Value::as_table) {
        for target in targets.values().filter_map(toml::Value::as_table) {
            collect(target);
        }
    }
    tables
}

fn package_name<'a>(alias: &'a str, value: &'a toml::Value) -> Result<&'a str, String> {
    match value {
        toml::Value::String(_) => Ok(alias),
        toml::Value::Table(table) => match table.get("package") {
            None => Ok(alias),
            Some(toml::Value::String(package)) => Ok(package),
            Some(_) => Err(format!(
                "dependency `{alias}` has an invalid package identity"
            )),
        },
        _ => Err(format!(
            "dependency `{alias}` is not a Cargo dependency declaration"
        )),
    }
}

fn facade_manifest(
    manifest: &toml::Table,
    workspace: Option<&toml::Table>,
) -> Result<FacadeManifest, String> {
    let workspace_dependencies = workspace
        .unwrap_or(manifest)
        .get("workspace")
        .and_then(toml::Value::as_table)
        .and_then(|workspace| workspace.get("dependencies"))
        .and_then(toml::Value::as_table);
    let mut packages_by_alias = BTreeMap::<String, BTreeSet<String>>::new();
    for dependencies in dependency_tables(manifest) {
        for (alias, value) in dependencies {
            let inherited = value.get("workspace").and_then(toml::Value::as_bool) == Some(true);
            let package = if inherited {
                let inherited_value = workspace_dependencies
                    .and_then(|dependencies| dependencies.get(alias))
                    .ok_or_else(|| {
                        format!("cannot resolve inherited dependency `{alias}` in workspace.dependencies")
                    })?;
                let inherited_package = package_name(alias, inherited_value)?;
                if let Some(local_package) = value.get("package").and_then(toml::Value::as_str)
                    && local_package != inherited_package
                {
                    return Err(format!(
                        "dependency `{alias}` overrides its inherited package identity"
                    ));
                }
                inherited_package
            } else {
                package_name(alias, value)?
            };
            packages_by_alias
                .entry(alias.replace('-', "_"))
                .or_default()
                .insert(package.to_owned());
        }
    }
    let mut aliases = BTreeSet::new();
    for (alias, packages) in packages_by_alias {
        if packages.contains(FACADE_PACKAGE) {
            if packages.len() != 1 {
                return Err(format!(
                    "facade alias `{alias}` identifies different packages across dependency tables"
                ));
            }
            aliases.insert(alias);
        }
    }
    let is_facade = manifest
        .get("package")
        .and_then(toml::Value::as_table)
        .and_then(|package| package.get("name"))
        .and_then(toml::Value::as_str)
        == Some(FACADE_PACKAGE);
    Ok(FacadeManifest { is_facade, aliases })
}

fn read_manifest(path: &std::path::Path) -> syn::Result<toml::Table> {
    let contents = std::fs::read_to_string(path).map_err(|error| {
        syn::Error::new(
            Span::call_site(),
            format!(
                "cannot read facade consumer manifest {}: {error}",
                path.display()
            ),
        )
    })?;
    toml::from_str(&contents).map_err(|error| {
        syn::Error::new(
            Span::call_site(),
            format!(
                "cannot parse facade consumer manifest {}: {error}",
                path.display()
            ),
        )
    })
}

fn load_facade_manifest() -> syn::Result<FacadeManifest> {
    let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR").ok_or_else(|| {
        syn::Error::new(
            Span::call_site(),
            "CARGO_MANIFEST_DIR is required to resolve the extension facade",
        )
    })?;
    let manifest_path = PathBuf::from(manifest_dir).join("Cargo.toml");
    let manifest = read_manifest(&manifest_path)?;
    let inherits_workspace = dependency_tables(&manifest).iter().any(|table| {
        table
            .values()
            .any(|value| value.get("workspace").and_then(toml::Value::as_bool) == Some(true))
    });
    let workspace = if inherits_workspace && !manifest.contains_key("workspace") {
        let cargo = std::env::var_os("CARGO").ok_or_else(|| {
            syn::Error::new(
                Span::call_site(),
                "CARGO is required to prove the inherited facade dependency",
            )
        })?;
        let output = std::process::Command::new(cargo)
            .args([
                "locate-project",
                "--workspace",
                "--message-format=plain",
                "--manifest-path",
            ])
            .arg(&manifest_path)
            .output()
            .map_err(|error| {
                syn::Error::new(
                    Span::call_site(),
                    format!("cannot locate facade consumer workspace: {error}"),
                )
            })?;
        if !output.status.success() {
            return Err(syn::Error::new(
                Span::call_site(),
                "cannot locate facade consumer workspace",
            ));
        }
        let path = String::from_utf8(output.stdout).map_err(|_| {
            syn::Error::new(
                Span::call_site(),
                "facade consumer workspace path is not UTF-8",
            )
        })?;
        if path.trim().is_empty() {
            return Err(syn::Error::new(
                Span::call_site(),
                "facade consumer workspace path is empty",
            ));
        }
        Some(read_manifest(std::path::Path::new(path.trim()))?)
    } else {
        None
    };
    facade_manifest(&manifest, workspace.as_ref())
        .map_err(|message| syn::Error::new(Span::call_site(), message))
}

fn facade_path(
    manifest: &FacadeManifest,
    crate_override: Option<&LitStr>,
    find_crate: impl FnOnce() -> Result<FoundCrate, String>,
) -> syn::Result<TokenStream> {
    if let Some(value) = crate_override {
        let path: syn::Path = value.parse().map_err(|_| {
            syn::Error::new_spanned(
                value,
                "extension crate override must name a facade dependency alias",
            )
        })?;
        if path.segments.len() != 1 || !matches!(path.segments[0].arguments, PathArguments::None) {
            return Err(syn::Error::new_spanned(
                value,
                "extension crate override must name a facade dependency alias, not an internal module or component path",
            ));
        }
        let ident = &path.segments[0].ident;
        let alias = ident.unraw().to_string();
        if alias == "crate" && manifest.is_facade && path.leading_colon.is_none() {
            // The package also contains examples and integration-test targets.
            // Their `crate` is not the facade library, so use its stable self name.
            return Ok(crate::found_crate_path(FoundCrate::Itself, FACADE_PACKAGE));
        }
        if !manifest.aliases.contains(&alias) {
            return Err(syn::Error::new_spanned(
                value,
                "extension crate override does not identify a declared fastmcp-rust facade dependency; component crates are not supported",
            ));
        }
        return Ok(quote!(::#ident));
    }
    if manifest.aliases.len() + usize::from(manifest.is_facade) == 0 {
        return Err(syn::Error::new(
            Span::call_site(),
            "#[extension] requires a fastmcp-rust facade dependency with extension-authoring; component crates are not a fallback",
        ));
    }
    if manifest.aliases.len() + usize::from(manifest.is_facade) != 1 {
        return Err(syn::Error::new(
            Span::call_site(),
            "ambiguous fastmcp-rust facade dependencies; select one with crate = \"facade_alias\"",
        ));
    }
    let found = find_crate().map_err(|message| syn::Error::new(Span::call_site(), message))?;
    match &found {
        FoundCrate::Itself if manifest.is_facade => {}
        FoundCrate::Name(name)
            if manifest.aliases.contains(name)
                || (manifest.is_facade && name == "fastmcp_rust") => {}
        _ => {
            return Err(syn::Error::new(
                Span::call_site(),
                "resolved facade name disagrees with the consumer's dependency declarations",
            ));
        }
    }
    Ok(crate::found_crate_path(found, FACADE_PACKAGE))
}

fn generate(
    attributes: &ExtensionAttributes,
    function: &ItemFn,
    types: &HandlerTypes<'_>,
    facade: &TokenStream,
) -> TokenStream {
    let name = &function.sig.ident;
    let adapter = format_ident!(
        "{}Extension",
        crate::to_pascal_case(&name.unraw().to_string())
    );
    let visibility = &function.vis;
    let HandlerTypes {
        settings,
        request,
        response,
    } = types;
    let method = &attributes.method;
    let params_schema = &attributes.params_schema;
    let result_schema = &attributes.result_schema;
    let hidden = quote!(#facade::__private::extensions);
    let invocation = if function.sig.asyncness.is_some() {
        quote!(#name(__fastmcp_context, __fastmcp_request).await)
    } else {
        quote!(#name(__fastmcp_context, __fastmcp_request))
    };
    let adapter_doc = format!("Sealed typed extension adapter for `{name}`.");
    quote! {
        #function

        #[doc = #adapter_doc]
        #[derive(Clone, Copy, Debug, Default)]
        #visibility struct #adapter;

        impl #hidden::ExtensionHandler<#request, #response, #settings> for #adapter {
            fn handle<'a>(
                &'a self,
                __fastmcp_context: #hidden::ExtensionContext<'a, #settings>,
                __fastmcp_request: #request,
            ) -> #hidden::BoxFuture<'a, #hidden::McpResult<#response>> {
                ::std::boxed::Box::pin(async move { #invocation })
            }
        }

        impl #adapter {
            /// Installs this typed handler into an unfrozen extension builder.
            #visibility fn register<__FastMcpClientSettings, __FastMcpServerSettings>(
                self,
                builder: #hidden::ExtensionBuilder<
                    __FastMcpClientSettings,
                    __FastMcpServerSettings,
                    #settings,
                >,
            ) -> #hidden::McpResult<#hidden::ExtensionBuilder<
                __FastMcpClientSettings,
                __FastMcpServerSettings,
                #settings,
            >> {
                builder.typed_request::<#request, #response, _>(
                    #method,
                    #params_schema,
                    #result_schema,
                    self,
                )
            }
        }
    }
}

pub(super) fn expand(attributes: TokenStream, function: TokenStream) -> syn::Result<TokenStream> {
    let attributes: ExtensionAttributes = syn::parse2(attributes)?;
    let function: ItemFn = syn::parse2(function)?;
    let types = handler_types(&function)?;
    let manifest = load_facade_manifest()?;
    let facade = facade_path(&manifest, attributes.crate_override.as_ref(), || {
        proc_macro_crate::crate_name(FACADE_PACKAGE).map_err(|error| error.to_string())
    })?;
    Ok(generate(&attributes, &function, &types, &facade))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attributes() -> ExtensionAttributes {
        syn::parse_quote!(
            method = "com.example/lookup",
            params_schema = "com.example/Request",
            result_schema = "com.example/Response",
        )
    }

    fn manifest(source: &str, workspace: Option<&str>) -> Result<FacadeManifest, String> {
        let source: toml::Table = toml::from_str(source).expect("valid test manifest");
        let workspace: Option<toml::Table> =
            workspace.map(|source| toml::from_str(source).expect("valid test workspace"));
        facade_manifest(&source, workspace.as_ref())
    }

    fn renamed_manifest() -> FacadeManifest {
        manifest(
            "[dependencies]\nrenamed = { package = 'fastmcp-rust', version = '0.13' }",
            None,
        )
        .expect("one facade")
    }

    fn expanded(function: ItemFn) -> String {
        let types = handler_types(&function).expect("valid typed handler");
        let generated = generate(&attributes(), &function, &types, &quote!(::renamed));
        syn::parse2::<syn::File>(generated.clone()).expect("generated Rust items parse");
        generated.to_string()
    }

    fn signature_error(function: ItemFn) -> String {
        handler_types(&function)
            .err()
            .expect("invalid handler")
            .to_string()
    }

    #[test]
    fn sync_handler_uses_only_sealed_facade_adapter() {
        let output = expanded(syn::parse_quote! {
            pub fn lookup(context: ExtensionContext<'_, Settings>, request: Request) -> McpResult<Response> {
                context.checkpoint()?;
                Ok(Response { value: request.value })
            }
        });
        assert!(output.contains("pub struct LookupExtension"), "{output}");
        assert!(
            output.contains(":: renamed :: __private :: extensions :: ExtensionHandler"),
            "{output}"
        );
        assert!(
            output.contains("builder . typed_request :: < Request , Response , _ >"),
            "{output}"
        );
        assert!(
            output.contains("lookup (__fastmcp_context , __fastmcp_request)"),
            "{output}"
        );
        for forbidden in [
            "fastmcp_core",
            "fastmcp_server",
            "fastmcp_protocol",
            "serde_json",
            "block_on",
            "asupersync",
            "runtime ::",
        ] {
            assert!(!output.contains(forbidden), "{forbidden}: {output}");
        }
    }

    #[test]
    fn async_handler_awaits_without_runtime_reentry() {
        let output = expanded(syn::parse_quote! {
            async fn lookup(context: ExtensionContext<'_, Settings>, request: Request) -> McpResult<Response> {
                perform(context, request).await
            }
        });
        assert!(
            output.contains("lookup (__fastmcp_context , __fastmcp_request) . await"),
            "{output}"
        );
        assert!(output.contains("Box :: pin (async move"), "{output}");
        assert!(!output.contains("block_on"), "{output}");
        assert!(!output.contains("runtime ::"), "{output}");
    }

    #[test]
    fn handler_visibility_and_original_function_are_retained() {
        let output = expanded(syn::parse_quote! {
            #[allow(unused_variables)]
            pub(crate) fn r#type(context: ExtensionContext<'_, Settings>, request: Request) -> McpResult<Response> {
                original_body(request)
            }
        });
        assert!(
            output.contains("pub (crate) struct TypeExtension"),
            "{output}"
        );
        assert!(output.contains("pub (crate) fn register"), "{output}");
        assert!(output.contains("original_body (request)"), "{output}");
        assert!(output.contains("allow (unused_variables)"), "{output}");
    }

    #[test]
    fn handler_rejects_invalid_context_or_arity() {
        for function in [
            syn::parse_quote!(
                fn run(ctx: &McpContext, request: Request) -> McpResult<Response> {}
            ),
            syn::parse_quote!(
                fn run(
                    ctx: &ExtensionContext<'_, Settings>,
                    request: Request,
                ) -> McpResult<Response> {
                }
            ),
            syn::parse_quote!(
                fn run(
                    ctx: ExtensionContext<'static, Settings>,
                    request: Request,
                ) -> McpResult<Response> {
                }
            ),
            syn::parse_quote!(
                fn run(ctx: ExtensionContext<Settings>, request: Request) -> McpResult<Response> {}
            ),
            syn::parse_quote!(
                fn run(
                    ctx: ExtensionContext<'_, Settings, Extra>,
                    request: Request,
                ) -> McpResult<Response> {
                }
            ),
        ] {
            assert!(signature_error(function).contains("ExtensionContext<'_, Settings>"));
        }
        assert!(
            signature_error(syn::parse_quote!(
                fn run(request: Request) -> McpResult<Response> {}
            ))
            .contains("exactly")
        );
    }

    #[test]
    fn handler_rejects_generic_unsafe_extern_and_receiver_signatures() {
        for function in [
            syn::parse_quote!(
                fn run<T>(ctx: ExtensionContext<'_, Settings>, request: T) -> McpResult<Response> {}
            ),
            syn::parse_quote!(
                fn run(ctx: ExtensionContext<'_, Settings>, request: Request) -> McpResult<Response>
                where
                    Request: Clone,
                {
                }
            ),
            syn::parse_quote!(
                unsafe fn run(
                    ctx: ExtensionContext<'_, Settings>,
                    request: Request,
                ) -> McpResult<Response> {
                }
            ),
            syn::parse_quote!(
                extern "C" fn run(
                    ctx: ExtensionContext<'_, Settings>,
                    request: Request,
                ) -> McpResult<Response> {
                }
            ),
            syn::parse_quote!(
                extern "C" fn run(ctx: ExtensionContext<'_, Settings>, ...) -> McpResult<Response> {
                }
            ),
            syn::parse_quote!(
                fn run(&self, request: Request) -> McpResult<Response> {}
            ),
            syn::parse_quote!(
                fn run(
                    ctx: ExtensionContext<'_, Settings>,
                    request: Vec<impl Clone>,
                ) -> McpResult<Response> {
                }
            ),
        ] {
            assert!(!signature_error(function).is_empty());
        }
    }

    #[test]
    fn handler_rejects_non_mcp_results() {
        for function in [
            syn::parse_quote!(
                fn run(ctx: ExtensionContext<'_, Settings>, request: Request) {}
            ),
            syn::parse_quote!(
                fn run(ctx: ExtensionContext<'_, Settings>, request: Request) -> Response {}
            ),
            syn::parse_quote!(
                fn run(
                    ctx: ExtensionContext<'_, Settings>,
                    request: Request,
                ) -> Result<Response, Error> {
                }
            ),
            syn::parse_quote!(
                fn run(
                    ctx: ExtensionContext<'_, Settings>,
                    request: Request,
                ) -> McpResult<Response, Error> {
                }
            ),
        ] {
            assert!(signature_error(function).contains("McpResult<Response>"));
        }
    }

    #[test]
    fn attribute_rejects_unknown_duplicate_or_missing_options() {
        for options in [
            quote!(
                method = "com.example/a",
                params_schema = "a",
                result_schema = "b",
                runtime = "ambient"
            ),
            quote!(
                method = "com.example/a",
                method = "com.example/b",
                params_schema = "a",
                result_schema = "b"
            ),
            quote!(method = "com.example/a", params_schema = "a"),
            quote!(method = "", params_schema = "a", result_schema = "b"),
            quote!(
                method = "com.example/a",
                params_schema = 1,
                result_schema = "b"
            ),
        ] {
            assert!(syn::parse2::<ExtensionAttributes>(options).is_err());
        }
        let with_override: ExtensionAttributes = syn::parse_quote!(
            method = "com.example/a",
            params_schema = "a",
            result_schema = "b",
            crate = "renamed"
        );
        assert_eq!(with_override.crate_override.unwrap().value(), "renamed");
    }

    #[test]
    fn override_rejects_component_and_malformed_paths() {
        let manifest = manifest("[dependencies]\nrenamed = { package = 'fastmcp-rust', version = '0.13' }\nfastmcp-server = '0.13'", None).unwrap();
        for value in [
            "fastmcp_server",
            "renamed::__private::server",
            "renamed<T>",
            "not a path!",
            "other",
            "crate",
        ] {
            let value = LitStr::new(value, Span::call_site());
            assert!(
                facade_path(&manifest, Some(&value), || panic!(
                    "override must not guess"
                ))
                .is_err()
            );
        }
        let value = LitStr::new("::renamed", Span::call_site());
        assert_eq!(
            facade_path(&manifest, Some(&value), || panic!("explicit alias"))
                .unwrap()
                .to_string(),
            ":: renamed"
        );
    }

    #[test]
    fn manifest_resolves_default_and_renamed_facades() {
        for (source, alias) in [
            ("[dependencies]\nfastmcp-rust = '0.13'", "fastmcp_rust"),
            (
                "[dependencies]\nrenamed = { package = 'fastmcp-rust', version = '0.13' }",
                "renamed",
            ),
        ] {
            let manifest = manifest(source, None).unwrap();
            assert_eq!(
                facade_path(&manifest, None, || Ok(FoundCrate::Name(alias.to_owned())))
                    .unwrap()
                    .to_string(),
                format!(":: {alias}")
            );
        }
        let itself = manifest("[package]\nname = 'fastmcp-rust'", None).unwrap();
        assert_eq!(
            facade_path(&itself, None, || Ok(FoundCrate::Itself))
                .unwrap()
                .to_string(),
            ":: fastmcp_rust"
        );
        let value = LitStr::new("crate", Span::call_site());
        assert_eq!(
            facade_path(&itself, Some(&value), || panic!("explicit own crate"))
                .unwrap()
                .to_string(),
            ":: fastmcp_rust"
        );
    }

    #[test]
    fn manifest_resolves_workspace_inherited_aliases() {
        let workspace = "[workspace.dependencies]\nrenamed = { package = 'fastmcp-rust', version = '0.13' }\nserde = '1'";
        let manifest = manifest(
            "[dependencies]\nrenamed = { workspace = true }\nserde.workspace = true",
            Some(workspace),
        )
        .unwrap();
        assert_eq!(manifest.aliases, BTreeSet::from(["renamed".to_owned()]));
        assert_eq!(
            facade_path(&manifest, None, || Ok(FoundCrate::Name(
                "renamed".to_owned()
            )))
            .unwrap()
            .to_string(),
            ":: renamed"
        );
    }

    #[test]
    fn manifest_includes_target_and_development_dependencies() {
        let manifest = manifest("[dev-dependencies]\nrenamed = { package = 'fastmcp-rust', version = '0.13' }\n[target.'cfg(unix)'.dependencies]\nrenamed = { package = 'fastmcp-rust', version = '0.13' }", None).unwrap();
        assert_eq!(manifest.aliases, BTreeSet::from(["renamed".to_owned()]));
        assert!(
            facade_path(&manifest, None, || Ok(FoundCrate::Name(
                "renamed".to_owned()
            )))
            .is_ok()
        );
    }

    #[test]
    fn manifest_requires_override_for_ambiguous_aliases() {
        let manifest = manifest("[dependencies]\none = { package = 'fastmcp-rust', version = '0.13' }\ntwo = { package = 'fastmcp-rust', version = '0.12' }", None).unwrap();
        let error = facade_path(&manifest, None, || {
            panic!("must reject before last-alias lookup")
        })
        .unwrap_err();
        assert!(error.to_string().contains("ambiguous"));
        let value = LitStr::new("one", Span::call_site());
        assert_eq!(
            facade_path(&manifest, Some(&value), || panic!("explicit alias"))
                .unwrap()
                .to_string(),
            ":: one"
        );
    }

    #[test]
    fn facade_resolution_does_not_fall_back_to_components() {
        let component_only = manifest("[dependencies]\nfastmcp-server = '0.13'\nfastmcp-core = '0.13'\nfastmcp-protocol = '0.13'", None).unwrap();
        assert!(
            facade_path(&component_only, None, || panic!(
                "must not resolve components"
            ))
            .unwrap_err()
            .to_string()
            .contains("facade dependency")
        );
        assert!(
            facade_path(&renamed_manifest(), None, || Err(
                "facade unavailable".to_owned()
            ))
            .is_err()
        );
        assert!(
            facade_path(&renamed_manifest(), None, || Ok(FoundCrate::Name(
                "fastmcp_server".to_owned()
            )))
            .is_err()
        );
    }

    #[test]
    fn manifest_rejects_inconsistent_or_unprovable_aliases() {
        assert!(
            manifest("[dependencies]\nrenamed.workspace = true", None)
                .unwrap_err()
                .contains("inherited dependency")
        );
        assert!(manifest("[dependencies]\nrenamed = { package = 'fastmcp-rust', workspace = true }", Some("[workspace.dependencies]\nrenamed = { package = 'fastmcp-server', version = '0.13' }")).unwrap_err().contains("inherited package"));
        assert!(manifest("[dependencies]\nrenamed = { package = 'fastmcp-rust', version = '0.13' }\n[target.'cfg(unix)'.dependencies]\nrenamed = { package = 'fastmcp-server', version = '0.13' }", None).unwrap_err().contains("different packages"));
    }
}
