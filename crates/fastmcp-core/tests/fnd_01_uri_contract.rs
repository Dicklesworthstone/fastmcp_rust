//! FND-01 public URI contract: exactly eight frozen acceptance IDs.
//!
//! These tests exercise only the exported API.  Each negative row starts from
//! an accepted baseline and changes exactly one named field; it then records
//! bounded input, configuration, and registry-state digests before asserting
//! the exact typed refusal.

use std::fmt::Debug;

use fastmcp_core::{
    sha256_bounded, AbsoluteUri, AbsoluteUriError, CanonicalHttpUrl,
    CanonicalHttpUrlError, CanonicalResourceId, CanonicalResourceIdError,
    CanonicalResourceIdPolicy, UriComponentState,
};
use fastmcp_core::uri::ConfiguredResourceEndpoint;

const TRACE_HASH_MAX_BYTES: usize = 4 * 1024;

fn digest_hex(value: &str) -> String {
    let digest = sha256_bounded(value.as_bytes(), TRACE_HASH_MAX_BYTES)
        .expect("URI contract trace values stay within their fixed bound");
    digest
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn trace_case(
    test_id: &str,
    case_id: &str,
    public_api: &str,
    baseline: &str,
    planted_field: &str,
    input_before: &str,
    input_after: &str,
    configuration_before: &str,
    configuration_after: &str,
    registry_before: &str,
    registry_after: &str,
    result: &str,
) {
    eprintln!(
        "fnd01_uri test_id={test_id} case_id={case_id} api={public_api} \\
         baseline_sha256={} planted_field={planted_field} result={result} \\
         input_pre_sha256={} input_post_sha256={} configuration_pre_sha256={} \\
         configuration_post_sha256={} registry_pre_sha256={} registry_post_sha256={}",
        digest_hex(baseline),
        digest_hex(input_before),
        digest_hex(input_after),
        digest_hex(configuration_before),
        digest_hex(configuration_after),
        digest_hex(registry_before),
        digest_hex(registry_after),
    );
}

fn assert_typed_refusal<T: Debug, E: Debug + PartialEq>(
    test_id: &str,
    case_id: &str,
    public_api: &str,
    baseline: &str,
    planted_field: &str,
    planted_input: &str,
    configuration: &str,
    registry: &str,
    expected: E,
    baseline_operation: impl FnOnce(&str) -> Result<T, E>,
    planted_operation: impl FnOnce(&str) -> Result<T, E>,
) {
    assert!(
        baseline_operation(baseline).is_ok(),
        "{test_id}:{case_id}: baseline must be accepted"
    );
    let input_before = planted_input.to_owned();
    let configuration_before = configuration.to_owned();
    let registry_before = registry.to_owned();
    let actual = planted_operation(&input_before).expect_err("planted input must be refused");
    assert_eq!(actual, expected, "{test_id}:{case_id}");
    assert_eq!(input_before, planted_input, "input changed during refusal");
    assert_eq!(configuration_before, configuration, "configuration changed during refusal");
    assert_eq!(registry_before, registry, "registry state changed during refusal");
    trace_case(
        test_id,
        case_id,
        public_api,
        baseline,
        planted_field,
        &input_before,
        planted_input,
        &configuration_before,
        configuration,
        &registry_before,
        registry,
        &format!("{actual:?}"),
    );
}

fn expected_state(component: Option<&str>) -> UriComponentState<'_> {
    match component {
        None => UriComponentState::Absent,
        Some("") => UriComponentState::Empty,
        Some(value) => UriComponentState::NonEmpty(value),
    }
}

fn parse_default_resource(input: &str) -> Result<CanonicalResourceId, CanonicalResourceIdError> {
    let endpoint = CanonicalHttpUrl::parse(input)
        .expect("resource test input must be accepted by the lower URL layer");
    CanonicalResourceId::parse_for_endpoint(input, &endpoint, CanonicalResourceIdPolicy::DEFAULT)
}

#[test]
fn absolute_uri_accepts_rfc3986_hierarchical_and_opaque_goldens() {
    let cases = [
        "https://user:pass@example.com:8443/a/b?x=y#z",
        "http://example.com",
        "urn:isbn:0451450523",
        "custom:opaque:data",
        "unknown+ext.1:value",
        "scheme:",
        "scheme:/",
        "scheme:///path",
        "scheme://",
        "scheme://@host:",
        "scheme://:80/path",
        "scheme://[2001:db8::1]/path",
        "scheme://[::ffff:192.0.2.128]/path",
        "scheme://[v1.fe80::a]/path",
        "scheme:%E2%98%83",
        "scheme:%FF%FE%00",
        "scheme:a!$&'()*+,;=:@/b",
        "scheme:a?x/?:@!$&'()*+,;=%FF#y/?:@!$&'()*+,;=%00",
    ];

    for (case_index, input) in cases.into_iter().enumerate() {
        let uri = AbsoluteUri::parse(input).expect("frozen RFC 3986 golden must parse");
        assert_eq!(uri.as_str(), input);
        assert_eq!(uri.as_bytes(), input.as_bytes());
        assert_eq!(uri.encoded_bytes(), input.len());
        trace_case(
            "absolute_uri_accepts_rfc3986_hierarchical_and_opaque_goldens",
            &format!("golden-{case_index}"),
            "AbsoluteUri::parse",
            input,
            "none",
            input,
            input,
            "required_scheme_rfc3986",
            "required_scheme_rfc3986",
            "no_configured_endpoint",
            "no_configured_endpoint",
            "Ok(AbsoluteUri)",
        );
    }
}

#[test]
fn absolute_uri_preserves_query_fragment_cartesian_product() {
    let queries = [None, Some(""), Some("query")];
    let fragments = [None, Some(""), Some("fragment")];

    for query in queries {
        for fragment in fragments {
            let mut input = String::from("scheme:path");
            if let Some(query) = query {
                input.push('?');
                input.push_str(query);
            }
            if let Some(fragment) = fragment {
                input.push('#');
                input.push_str(fragment);
            }

            let uri = AbsoluteUri::parse(&input).expect("component state golden must parse");
            assert_eq!(uri.as_str(), input);
            assert_eq!(uri.query(), query);
            assert_eq!(uri.fragment(), fragment);
            assert_eq!(uri.query_state(), expected_state(query));
            assert_eq!(uri.fragment_state(), expected_state(fragment));
            trace_case(
                "absolute_uri_preserves_query_fragment_cartesian_product",
                &format!("query-{query:?}-fragment-{fragment:?}"),
                "AbsoluteUri::parse",
                "scheme:path",
                "query_and_fragment_presence",
                &input,
                &input,
                "preserve_absent_empty_nonempty",
                "preserve_absent_empty_nonempty",
                "no_configured_endpoint",
                "no_configured_endpoint",
                "Ok(AbsoluteUri)",
            );
        }
    }
}

#[test]
fn canonical_http_uses_exact_url_crate_canonicalization() {
    let input = "HTTPS://BÜCHER.Example:443/a/./b/../c?x=1#frag";
    let value = CanonicalHttpUrl::parse(input).expect("frozen URL canonicalization golden");

    assert_eq!(value.as_str(), "https://xn--bcher-kva.example/a/c?x=1#frag");
    assert_eq!(value.scheme(), "https");
    assert_eq!(value.host(), "xn--bcher-kva.example");
    assert_eq!(value.port(), None);
    assert_eq!(value.effective_port(), 443);
    assert_eq!(value.path(), "/a/c");
    assert_eq!(value.query(), Some("x=1"));
    assert_eq!(value.fragment(), Some("frag"));
    trace_case(
        "canonical_http_uses_exact_url_crate_canonicalization",
        "idna-case-port-dot-segment",
        "CanonicalHttpUrl::parse",
        input,
        "url_crate_canonicalization",
        input,
        value.as_str(),
        "url=2.5.8,std",
        "url=2.5.8,std",
        "no_configured_endpoint",
        "no_configured_endpoint",
        "Ok(CanonicalHttpUrl)",
    );
}

#[test]
fn canonical_resource_can_bind_the_most_specific_configured_endpoint() {
    let tenant_base = CanonicalHttpUrl::parse("https://api.example.test/tenant").unwrap();
    let tenant = CanonicalHttpUrl::parse("https://api.example.test/tenant/mcp").unwrap();
    let endpoints = [
        ConfiguredResourceEndpoint::new(
            "tenant-base",
            &tenant_base,
            CanonicalResourceIdPolicy::DEFAULT,
        ),
        ConfiguredResourceEndpoint::new("tenant", &tenant, CanonicalResourceIdPolicy::DEFAULT),
    ];

    let input = "https://api.example.test/tenant/mcp/tool";
    let resource = CanonicalResourceId::parse_for_configured_endpoints(input, &endpoints)
        .expect("most-specific configured endpoint must bind");
    assert_eq!(resource.path(), "/tenant/mcp/tool");
    assert_eq!(resource.configured_endpoint_identity(), "tenant");

    let first_identity = CanonicalResourceId::parse_for_configured_endpoints(
        input,
        &[ConfiguredResourceEndpoint::new(
            "first-identity",
            &tenant,
            CanonicalResourceIdPolicy::DEFAULT,
        )],
    )
    .unwrap();
    let second_identity = CanonicalResourceId::parse_for_configured_endpoints(
        input,
        &[ConfiguredResourceEndpoint::new(
            "second-identity",
            &tenant,
            CanonicalResourceIdPolicy::DEFAULT,
        )],
    )
    .unwrap();
    assert_ne!(first_identity, second_identity);

    let ipv6 = CanonicalHttpUrl::parse("https://[2001:db8::1]/mcp").unwrap();
    let ipv6_resource = CanonicalResourceId::parse_for_configured_endpoints(
        "https://[2001:db8::1]/mcp/tool",
        &[ConfiguredResourceEndpoint::new(
            "ipv6",
            &ipv6,
            CanonicalResourceIdPolicy::DEFAULT,
        )],
    )
    .unwrap();
    assert_eq!(ipv6_resource.configured_endpoint_identity(), "ipv6");
    assert_typed_refusal(
        "canonical_resource_can_bind_the_most_specific_configured_endpoint",
        "encoded-path-separator",
        "CanonicalResourceId::parse_for_configured_endpoints",
        input,
        "candidate_path_percent_encoded_separator",
        "https://api.example.test/tenant/mcp%2Ftool",
        "CanonicalResourceIdPolicy::DEFAULT",
        "tenant-base,tenant",
        CanonicalResourceIdError::NoMatchingConfiguredEndpoint,
        |candidate| CanonicalResourceId::parse_for_configured_endpoints(candidate, &endpoints),
        |candidate| CanonicalResourceId::parse_for_configured_endpoints(candidate, &endpoints),
    );
    trace_case(
        "canonical_resource_can_bind_the_most_specific_configured_endpoint",
        "tenant-most-specific",
        "CanonicalResourceId::parse_for_configured_endpoints",
        input,
        "configured_endpoint_path_specificity",
        input,
        resource.as_str(),
        "CanonicalResourceIdPolicy::DEFAULT",
        "CanonicalResourceIdPolicy::DEFAULT",
        "tenant-base,tenant",
        "tenant-base,tenant",
        "Ok(CanonicalResourceId { identity: tenant })",
    );
}

#[test]
fn absolute_uri_rejects_missing_and_invalid_schemes() {
    let cases = [
        ("empty", "scheme:path", "", AbsoluteUriError::Empty),
        (
            "relative-path",
            "scheme:path",
            "relative/path",
            AbsoluteUriError::MissingScheme,
        ),
        (
            "slash-relative-path",
            "scheme:path",
            "/relative",
            AbsoluteUriError::MissingScheme,
        ),
        (
            "authority-relative-path",
            "scheme:path",
            "//authority/path",
            AbsoluteUriError::MissingScheme,
        ),
        (
            "empty-scheme",
            "scheme:path",
            ":path",
            AbsoluteUriError::EmptyScheme,
        ),
        (
            "numeric-leading-scheme",
            "scheme:path",
            "1scheme:path",
            AbsoluteUriError::InvalidCharacter {
                component: fastmcp_core::AbsoluteUriComponent::Scheme,
                index: 0,
                byte: b'1',
            },
        ),
        (
            "plus-leading-scheme",
            "scheme:path",
            "+scheme:path",
            AbsoluteUriError::InvalidCharacter {
                component: fastmcp_core::AbsoluteUriComponent::Scheme,
                index: 0,
                byte: b'+',
            },
        ),
        (
            "underscore-in-scheme",
            "scheme:path",
            "scheme_name:path",
            AbsoluteUriError::InvalidCharacter {
                component: fastmcp_core::AbsoluteUriComponent::Scheme,
                index: 6,
                byte: b'_',
            },
        ),
        (
            "slash-in-scheme",
            "scheme:path",
            "scheme/path:later",
            AbsoluteUriError::InvalidCharacter {
                component: fastmcp_core::AbsoluteUriComponent::Scheme,
                index: 6,
                byte: b'/',
            },
        ),
        (
            "query-leading-scheme",
            "scheme:path",
            "?query:later",
            AbsoluteUriError::InvalidCharacter {
                component: fastmcp_core::AbsoluteUriComponent::Scheme,
                index: 0,
                byte: b'?',
            },
        ),
    ];
    for (case_id, baseline, planted, expected) in cases {
        assert_typed_refusal(
            "absolute_uri_rejects_missing_and_invalid_schemes",
            case_id,
            "AbsoluteUri::parse",
            baseline,
            "scheme",
            planted,
            "required_scheme_rfc3986",
            "no_configured_endpoint",
            expected,
            AbsoluteUri::parse,
            AbsoluteUri::parse,
        );
    }
}

#[test]
fn absolute_uri_rejects_invalid_percent_triplets_everywhere() {
    let cases = [
        ("path-empty", "scheme:path", "scheme:%"),
        ("path-short", "scheme:path", "scheme:%0"),
        ("path-non-hex", "scheme:path", "scheme:%GG"),
        ("userinfo", "scheme://user@host/path", "scheme://user%@host/path"),
        ("host", "scheme://host/path", "scheme://host%2/path"),
        ("query", "scheme:path?x=1", "scheme:path?%"),
        ("query-short", "scheme:path?x=1", "scheme:path?x=%0"),
        ("fragment", "scheme:path#fragment", "scheme:path#%xz"),
    ];
    for (case_id, baseline, planted) in cases {
        assert_typed_refusal(
            "absolute_uri_rejects_invalid_percent_triplets_everywhere",
            case_id,
            "AbsoluteUri::parse",
            baseline,
            "percent_triplet",
            planted,
            "required_scheme_rfc3986",
            "no_configured_endpoint",
            AbsoluteUriError::InvalidPercentEncoding {
                index: planted.find('%').unwrap(),
            },
            AbsoluteUri::parse,
            AbsoluteUri::parse,
        );
    }
}

#[test]
fn canonical_http_rejects_non_http_relative_missing_host_and_bad_port() {
    let cases = [
        (
            "non-http-scheme",
            "https://example.test/mcp",
            "ftp://example.test/mcp",
            CanonicalHttpUrlError::SchemeNotHttp,
        ),
        (
            "opaque-non-http-scheme",
            "https://example.test/mcp",
            "urn:example:x",
            CanonicalHttpUrlError::SchemeNotHttp,
        ),
        (
            "relative-input",
            "https://example.test/mcp",
            "/relative",
            CanonicalHttpUrlError::Parse(url::ParseError::RelativeUrlWithoutBase),
        ),
        (
            "missing-host",
            "https://example.test/mcp",
            "https:///mcp",
            CanonicalHttpUrlError::MissingHost,
        ),
        (
            "empty-authority",
            "https://example.test/mcp",
            "https://",
            CanonicalHttpUrlError::MissingHost,
        ),
        (
            "bad-port",
            "https://example.test/mcp",
            "https://example.test:99999/mcp",
            CanonicalHttpUrlError::Parse(url::ParseError::InvalidPort),
        ),
    ];
    for (case_id, baseline, planted, expected) in cases {
        assert_typed_refusal(
            "canonical_http_rejects_non_http_relative_missing_host_and_bad_port",
            case_id,
            "CanonicalHttpUrl::parse",
            baseline,
            "http_url_form",
            planted,
            "http_or_https_required",
            "no_configured_endpoint",
            expected,
            CanonicalHttpUrl::parse,
            CanonicalHttpUrl::parse,
        );
    }
}

#[test]
fn canonical_resource_rejects_every_http_form_including_loopback() {
    let cases = [
        ("public-http", "https://example.test/mcp", "http://example.test/mcp"),
        ("localhost-http", "https://localhost/mcp", "http://localhost/mcp"),
        ("ipv4-loopback-http", "https://127.0.0.1/mcp", "http://127.0.0.1/mcp"),
        ("ipv6-loopback-http", "https://[::1]/mcp", "http://[::1]/mcp"),
    ];
    for (case_id, baseline, planted) in cases {
        assert_typed_refusal(
            "canonical_resource_rejects_every_http_form_including_loopback",
            case_id,
            "CanonicalResourceId::parse_for_endpoint",
            baseline,
            "scheme",
            planted,
            "CanonicalResourceIdPolicy::DEFAULT",
            "single-configured-endpoint",
            CanonicalResourceIdError::HttpsRequired,
            parse_default_resource,
            parse_default_resource,
        );
    }
}
