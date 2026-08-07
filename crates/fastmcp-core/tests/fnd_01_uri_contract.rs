//! FND-01 public URI contract: exactly eight frozen acceptance IDs.
//!
//! These tests exercise only the exported API.  Each negative row starts from
//! an accepted baseline and changes exactly one named field; it then records
//! bounded input, configuration, and registry-state digests before asserting
//! the exact typed refusal.

use std::fmt::Debug;

use fastmcp_core::uri::ConfiguredResourceEndpoint;
use fastmcp_core::{
    sha256_bounded, AbsoluteUri, AbsoluteUriError, CanonicalHttpUrl, CanonicalHttpUrlError,
    CanonicalResourceId, CanonicalResourceIdError, CanonicalResourceIdPolicy, UriComponentState,
};

const TRACE_HASH_MAX_BYTES: usize = 4 * 1024;

fn digest_hex(value: impl AsRef<[u8]>) -> String {
    let digest = sha256_bounded(value.as_ref(), TRACE_HASH_MAX_BYTES)
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
    baseline: impl AsRef<[u8]>,
    planted_field: &str,
    input_before: impl AsRef<[u8]>,
    input_after: impl AsRef<[u8]>,
    configuration_before: impl AsRef<[u8]>,
    configuration_after: impl AsRef<[u8]>,
    registry_before: impl AsRef<[u8]>,
    registry_after: impl AsRef<[u8]>,
    result: &str,
    canonical_output: Option<&str>,
) {
    eprintln!(
        concat!(
            "{\"event\":\"fnd01_uri\",\"test_id\":{},\"case_id\":{},",
            "\"public_api\":{},\"baseline_sha256\":{},\"planted_field\":{},",
            "\"result\":{},\"canonical_output\":{},\"input_pre_sha256\":{},",
            "\"input_post_sha256\":{},\"configuration_pre_sha256\":{},",
            "\"configuration_post_sha256\":{},\"registry_pre_sha256\":{},",
            "\"registry_post_sha256\":{}}}"
        ),
        json_string(test_id),
        json_string(case_id),
        json_string(public_api),
        json_string(&digest_hex(baseline)),
        json_string(planted_field),
        json_string(result),
        canonical_output.map_or_else(|| "null".to_owned(), json_string),
        json_string(&digest_hex(input_before)),
        json_string(&digest_hex(input_after)),
        json_string(&digest_hex(configuration_before)),
        json_string(&digest_hex(configuration_after)),
        json_string(&digest_hex(registry_before)),
        json_string(&digest_hex(registry_after)),
    );
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).expect("URI contract trace values serialize as JSON strings")
}

fn snapshot(value: &impl Debug) -> String {
    format!("{value:?}")
}

#[derive(Debug)]
struct NoConfiguration;

#[derive(Debug)]
struct NoEndpointRegistry;

fn assert_typed_refusal<T: Debug, E: Debug + PartialEq, C: Debug, R: Debug>(
    test_id: &str,
    case_id: &str,
    public_api: &str,
    baseline: &str,
    planted_field: &str,
    planted_input: &str,
    configuration: &C,
    registry: &R,
    expected: E,
    baseline_operation: impl FnOnce(&str) -> Result<T, E>,
    planted_operation: impl FnOnce(&str) -> Result<T, E>,
) {
    assert!(
        baseline_operation(baseline).is_ok(),
        "{test_id}:{case_id}: baseline must be accepted"
    );
    let input_before = planted_input.to_owned();
    let input_before_bytes = input_before.as_bytes().to_vec();
    let configuration_before = snapshot(configuration);
    let registry_before = snapshot(registry);
    let actual = planted_operation(&input_before).expect_err("planted input must be refused");
    let input_after = input_before.as_bytes().to_vec();
    let configuration_after = snapshot(configuration);
    let registry_after = snapshot(registry);
    assert_eq!(actual, expected, "{test_id}:{case_id}");
    assert_eq!(
        input_after, input_before_bytes,
        "input changed during refusal"
    );
    assert_eq!(
        configuration_after, configuration_before,
        "configuration changed during refusal"
    );
    assert_eq!(
        registry_after, registry_before,
        "registry state changed during refusal"
    );
    trace_case(
        test_id,
        case_id,
        public_api,
        baseline,
        planted_field,
        &input_before_bytes,
        &input_after,
        &configuration_before,
        &configuration_after,
        &registry_before,
        &registry_after,
        &format!("{actual:?}"),
        None,
    );
}

fn expected_state(component: Option<&str>) -> UriComponentState<'_> {
    match component {
        None => UriComponentState::Absent,
        Some("") => UriComponentState::Empty,
        Some(value) => UriComponentState::NonEmpty(value),
    }
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
            &snapshot(&NoConfiguration),
            &snapshot(&NoConfiguration),
            &snapshot(&NoEndpointRegistry),
            &snapshot(&NoEndpointRegistry),
            "Ok(AbsoluteUri)",
            Some(uri.as_str()),
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
                &snapshot(&NoConfiguration),
                &snapshot(&NoConfiguration),
                &snapshot(&NoEndpointRegistry),
                &snapshot(&NoEndpointRegistry),
                "Ok(AbsoluteUri)",
                Some(uri.as_str()),
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
        &snapshot(&NoConfiguration),
        &snapshot(&NoConfiguration),
        &snapshot(&NoEndpointRegistry),
        &snapshot(&NoEndpointRegistry),
        "Ok(CanonicalHttpUrl)",
        Some(value.as_str()),
    );
}

#[test]
fn canonical_resource_can_bind_the_most_specific_configured_endpoint() {
    let policy = CanonicalResourceIdPolicy::DEFAULT;
    let tenant_base = CanonicalHttpUrl::parse("https://api.example.test/tenant").unwrap();
    let tenant = CanonicalHttpUrl::parse("https://api.example.test/tenant/mcp").unwrap();
    let endpoints = [
        ConfiguredResourceEndpoint::new("tenant-base", &tenant_base, policy),
        ConfiguredResourceEndpoint::new("tenant", &tenant, policy),
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
            policy,
        )],
    )
    .unwrap();
    let second_identity = CanonicalResourceId::parse_for_configured_endpoints(
        input,
        &[ConfiguredResourceEndpoint::new(
            "second-identity",
            &tenant,
            policy,
        )],
    )
    .unwrap();
    assert_ne!(first_identity, second_identity);

    let ipv6 = CanonicalHttpUrl::parse("https://[2001:db8::1]/mcp").unwrap();
    let ipv6_resource = CanonicalResourceId::parse_for_configured_endpoints(
        "https://[2001:db8::1]/mcp/tool",
        &[ConfiguredResourceEndpoint::new("ipv6", &ipv6, policy)],
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
        &policy,
        &endpoints,
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
        &snapshot(&policy),
        &snapshot(&policy),
        &snapshot(&endpoints),
        &snapshot(&endpoints),
        "Ok(CanonicalResourceId { identity: tenant })",
        Some(resource.as_str()),
    );
}

#[test]
fn absolute_uri_rejects_missing_and_invalid_schemes() {
    let cases = [
        (
            "empty",
            "x:",
            "entire_absolute_uri",
            "",
            AbsoluteUriError::Empty,
        ),
        (
            "relative-path",
            "relative:path",
            "scheme_delimiter",
            "relative/path",
            AbsoluteUriError::MissingScheme,
        ),
        (
            "slash-relative-path",
            "x:/relative",
            "scheme_prefix",
            "/relative",
            AbsoluteUriError::MissingScheme,
        ),
        (
            "authority-relative-path",
            "x://authority/path",
            "scheme_prefix",
            "//authority/path",
            AbsoluteUriError::MissingScheme,
        ),
        (
            "empty-scheme",
            "x:path",
            "scheme_name",
            ":path",
            AbsoluteUriError::EmptyScheme,
        ),
        (
            "numeric-leading-scheme",
            "xscheme:path",
            "scheme_first_byte",
            "1scheme:path",
            AbsoluteUriError::InvalidCharacter {
                component: fastmcp_core::AbsoluteUriComponent::Scheme,
                index: 0,
                byte: b'1',
            },
        ),
        (
            "plus-leading-scheme",
            "xscheme:path",
            "scheme_first_byte",
            "+scheme:path",
            AbsoluteUriError::InvalidCharacter {
                component: fastmcp_core::AbsoluteUriComponent::Scheme,
                index: 0,
                byte: b'+',
            },
        ),
        (
            "underscore-in-scheme",
            "scheme-name:path",
            "scheme_byte_6",
            "scheme_name:path",
            AbsoluteUriError::InvalidCharacter {
                component: fastmcp_core::AbsoluteUriComponent::Scheme,
                index: 6,
                byte: b'_',
            },
        ),
        (
            "slash-in-scheme",
            "schemeXpath:later",
            "scheme_byte_6",
            "scheme/path:later",
            AbsoluteUriError::InvalidCharacter {
                component: fastmcp_core::AbsoluteUriComponent::Scheme,
                index: 6,
                byte: b'/',
            },
        ),
        (
            "query-leading-scheme",
            "xquery:later",
            "scheme_first_byte",
            "?query:later",
            AbsoluteUriError::InvalidCharacter {
                component: fastmcp_core::AbsoluteUriComponent::Scheme,
                index: 0,
                byte: b'?',
            },
        ),
    ];
    let configuration = NoConfiguration;
    let registry = NoEndpointRegistry;
    for (case_id, baseline, planted_field, planted, expected) in cases {
        assert_typed_refusal(
            "absolute_uri_rejects_missing_and_invalid_schemes",
            case_id,
            "AbsoluteUri::parse",
            baseline,
            planted_field,
            planted,
            &configuration,
            &registry,
            expected,
            AbsoluteUri::parse,
            AbsoluteUri::parse,
        );
    }
}

#[test]
fn absolute_uri_rejects_invalid_percent_triplets_everywhere() {
    let cases = [
        (
            "path-empty",
            "scheme:%00",
            "path_percent_triplet",
            "scheme:%",
        ),
        (
            "path-short",
            "scheme:%00",
            "path_percent_triplet",
            "scheme:%0",
        ),
        (
            "path-non-hex",
            "scheme:%00",
            "path_percent_triplet",
            "scheme:%GG",
        ),
        (
            "userinfo",
            "scheme://user%20@host/path",
            "userinfo_percent_triplet",
            "scheme://user%@host/path",
        ),
        (
            "host",
            "scheme://host%20/path",
            "host_percent_triplet",
            "scheme://host%2/path",
        ),
        (
            "query",
            "scheme:path?x=%00",
            "query_percent_triplet",
            "scheme:path?%",
        ),
        (
            "query-short",
            "scheme:path?x=%00",
            "query_percent_triplet",
            "scheme:path?x=%0",
        ),
        (
            "fragment",
            "scheme:path#%00",
            "fragment_percent_triplet",
            "scheme:path#%xz",
        ),
    ];
    let configuration = NoConfiguration;
    let registry = NoEndpointRegistry;
    for (case_id, baseline, planted_field, planted) in cases {
        assert_typed_refusal(
            "absolute_uri_rejects_invalid_percent_triplets_everywhere",
            case_id,
            "AbsoluteUri::parse",
            baseline,
            planted_field,
            planted,
            &configuration,
            &registry,
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
            "scheme",
            "ftp://example.test/mcp",
            CanonicalHttpUrlError::SchemeNotHttp,
        ),
        (
            "opaque-non-http-scheme",
            "https:example:x",
            "scheme",
            "urn:example:x",
            CanonicalHttpUrlError::SchemeNotHttp,
        ),
        (
            "relative-input",
            "https:/relative",
            "scheme_prefix",
            "/relative",
            CanonicalHttpUrlError::Parse(url::ParseError::RelativeUrlWithoutBase),
        ),
        (
            "missing-host",
            "https://host/mcp",
            "authority_host",
            "https:///mcp",
            CanonicalHttpUrlError::MissingHost,
        ),
        (
            "empty-authority",
            "https://host",
            "authority_host",
            "https://",
            CanonicalHttpUrlError::MissingHost,
        ),
        (
            "bad-port",
            "https://example.test:443/mcp",
            "authority_port",
            "https://example.test:99999/mcp",
            CanonicalHttpUrlError::Parse(url::ParseError::InvalidPort),
        ),
    ];
    let configuration = NoConfiguration;
    let registry = NoEndpointRegistry;
    for (case_id, baseline, planted_field, planted, expected) in cases {
        assert_typed_refusal(
            "canonical_http_rejects_non_http_relative_missing_host_and_bad_port",
            case_id,
            "CanonicalHttpUrl::parse",
            baseline,
            planted_field,
            planted,
            &configuration,
            &registry,
            expected,
            CanonicalHttpUrl::parse,
            CanonicalHttpUrl::parse,
        );
    }
}

#[test]
fn canonical_resource_rejects_every_http_form_including_loopback() {
    let cases = [
        (
            "public-http",
            "https://example.test/mcp",
            "http://example.test/mcp",
        ),
        (
            "localhost-http",
            "https://localhost/mcp",
            "http://localhost/mcp",
        ),
        (
            "ipv4-loopback-http",
            "https://127.0.0.1/mcp",
            "http://127.0.0.1/mcp",
        ),
        (
            "ipv6-loopback-http",
            "https://[::1]/mcp",
            "http://[::1]/mcp",
        ),
    ];
    for (case_id, baseline, planted) in cases {
        let endpoint = CanonicalHttpUrl::parse(baseline)
            .expect("each resource refusal baseline must provide an accepted HTTPS endpoint");
        let policy = CanonicalResourceIdPolicy::DEFAULT;
        let registry = [ConfiguredResourceEndpoint::new(
            "fixed-https-endpoint",
            &endpoint,
            policy,
        )];
        assert_typed_refusal(
            "canonical_resource_rejects_every_http_form_including_loopback",
            case_id,
            "CanonicalResourceId::parse_for_endpoint",
            baseline,
            "resource_scheme",
            planted,
            &(&endpoint, policy),
            &registry,
            CanonicalResourceIdError::HttpsRequired,
            |candidate| CanonicalResourceId::parse_for_endpoint(candidate, &endpoint, policy),
            |candidate| CanonicalResourceId::parse_for_endpoint(candidate, &endpoint, policy),
        );
    }
}
