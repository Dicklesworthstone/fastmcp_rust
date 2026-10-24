//! Real method-codec and shared-collector tests for DPoP catalog traversal.

use std::future::Future;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use fastmcp_core::CanonicalHttpUrl;
use fastmcp_protocol::dpop::DpopKey;
use fastmcp_protocol::{ClientCapabilities, FinalCoreResult, FinalRequestMeta};
use serde::Serialize;
use serde_json::json;

use super::*;
use crate::http_auth::dpop::DpopSession;
use crate::http_auth::dpop::native::{DpopHttpPolicy, DpopHttpResponse};

const TARGET: &str = "https://mcp.example/mcp";
const METHODS: [&str; 4] = [
    "tools/list", "resources/list", "resources/templates/list", "prompts/list",
];

fn request(method: &str, mut params: Value) -> CoreRequest {
    params["_meta"] = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
    CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&params)).unwrap()
}

fn traversal(method: &str, limits: CatalogLimits) -> Traversal {
    Traversal::new(
        request(method, json!({})), "catalog", ManagedCoreLimits::default(), limits, 8 * 1024 * 1024,
    ).unwrap()
}

fn source(method: &str, count: usize, cursor: Option<&str>, extras: &str) -> String {
    let (field, entry) = match method {
        "tools/list" => ("tools", json!({"name":"private-entry","inputSchema":{"type":"object"}})),
        "resources/list" => ("resources", json!({"name":"private-entry","uri":"note:///item"})),
        "resources/templates/list" => ("resourceTemplates", json!({"name":"private-entry","uriTemplate":"note:///{id}"})),
        "prompts/list" => ("prompts", json!({"name":"private-entry"})),
        _ => panic!("not a catalog fixture"),
    };
    let entries = serde_json::to_string(&vec![entry; count]).unwrap();
    let cursor = cursor.map_or_else(String::new, |cursor| {
        format!(",\"nextCursor\":{}", serde_json::to_string(cursor).unwrap())
    });
    format!(r#"{{"resultType":"complete","{field}":{entries},"ttlMs":0,"cacheScope":"private"{cursor}{extras}}}"#)
}

fn decoded(method: &str, source: &str) -> CoreResult {
    request(method, json!({})).decode_result(source).unwrap()
}

fn response(wire: &ModernHttpRequest, source: &str) -> DpopHttpResponse {
    let sent: Value = serde_json::from_slice(wire.body()).unwrap();
    DpopHttpResponse {
        status: 200,
        headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
        body: format!(r#"{{"jsonrpc":"2.0","id":{},"result":{source}}}"#, sent["id"]).into_bytes(),
    }
}

fn page(walk: &mut Traversal, source: &str) -> Result<bool, DpopCatalogError> {
    let (wire, mut decoder) = walk.next_request(TARGET)?;
    let result = decode_response(&mut decoder, response(&wire, source))?;
    walk.append(result)
}

fn assert_views<T: Serialize>(catalog: &ManagedCatalog<T>, originals: &[CoreResult]) {
    assert_eq!(catalog.page_count(), originals.len());
    for (index, original) in originals.iter().enumerate() {
        let mut rebuilt = original.clone();
        macro_rules! check {
            ($result:ident, $diagnostic:ident, $field:ident) => {{
                assert_eq!(
                    serde_json::to_vec(catalog.page_entries(index).unwrap()).unwrap(),
                    serde_json::to_vec(&$result.payload.$field).unwrap(),
                );
                assert_eq!(catalog.page_has_continuation(index), Some($result.payload.next_cursor.is_some()));
                assert_eq!(catalog.page_diagnostic(index), $diagnostic.as_ref());
                $result.meta = catalog.page_metadata(index).unwrap().clone();
                $result.extras = catalog.page_extras(index).unwrap().clone();
                let (ttl, scope) = catalog.page_cache_hints(index).unwrap();
                $result.payload.ttl_ms = ttl.clone();
                $result.payload.cache_scope = *scope;
            }};
        }
        match &mut rebuilt {
            CoreResult::Final(FinalCoreResult::ToolsList { result, diagnostic }) => check!(result, diagnostic, tools),
            CoreResult::Final(FinalCoreResult::ResourcesList { result, diagnostic }) => check!(result, diagnostic, resources),
            CoreResult::Final(FinalCoreResult::ResourceTemplatesList { result, diagnostic }) => check!(result, diagnostic, resource_templates),
            CoreResult::Final(FinalCoreResult::PromptsList { result, diagnostic }) => check!(result, diagnostic, prompts),
            _ => panic!("wrong result fixture"),
        }
        assert_eq!(rebuilt.encode().unwrap(), original.encode().unwrap());
    }
}

fn assert_collection(collection: CatalogCollection, originals: &[CoreResult]) {
    match collection {
        CatalogCollection::Tools(catalog) => assert_views(&catalog, originals),
        CatalogCollection::Resources(catalog) => assert_views(&catalog, originals),
        CatalogCollection::Templates(catalog) => assert_views(&catalog, originals),
        CatalogCollection::Prompts(catalog) => assert_views(&catalog, originals),
    }
}

#[test]
fn all_catalogs_preserve_parameters_fresh_ids_and_lossless_page_views() {
    for method in METHODS {
        let initial = request(method, json!({"includeTags":["selected"]}));
        let original_params = initial.encode_params().unwrap().unwrap();
        let mut walk = Traversal::new(
            initial, "run-17", ManagedCoreLimits::default(), CatalogLimits::default(), 8 * 1024 * 1024,
        ).unwrap();
        let sources = [
            source(method, 1, Some(""), ""),
            source(method, 0, Some(""), r#", "_meta":{}"#),
            source(method, 1, None, r#", "_meta":{"private":"metadata-canary","z":900719925474099312345,"a":1.20e+4},"x-open":{"z":900719925474099312345,"a":1.20e+4},"requestState":"inert""#),
        ];
        let originals: Vec<_> = sources.iter().map(|text| decoded(method, text)).collect();
        for (index, text) in sources.iter().enumerate() {
            let (wire, mut decoder) = walk.next_request(TARGET).unwrap();
            assert_eq!(wire.target(), TARGET);
            let sent: Value = serde_json::from_slice(wire.body()).unwrap();
            assert_eq!(sent["id"], format!("run-17.{index}"));
            assert_eq!(sent["method"], method);
            let mut params = sent["params"].clone();
            let cursor = params.as_object_mut().unwrap().remove("cursor");
            assert_eq!(cursor, (index != 0).then(|| json!("")));
            assert_eq!(params, original_params);
            let result = decode_response(&mut decoder, response(&wire, text)).unwrap();
            assert_eq!(walk.append(result).unwrap(), index == 2);
        }
        assert!(walk.next_request(TARGET).is_err());
        let collection = walk.finish().unwrap();
        let diagnostic = format!("{collection:?}");
        for secret in ["private-entry", "metadata-canary", "x-open", "inert"] {
            assert!(!diagnostic.contains(secret));
        }
        assert_collection(collection, &originals);
    }
}

#[test]
fn repeated_nonempty_unicode_and_whitespace_cursors_remain_opaque() {
    for cursor in ["opaque-雪%2F", " \t\"\\\n ", "same"] {
        let mut walk = traversal("tools/list", CatalogLimits::default());
        for _ in 0..3 {
            assert!(!page(&mut walk, &source("tools/list", 0, Some(cursor), "")).unwrap());
            assert_eq!(walk.params["cursor"], cursor);
        }
        assert!(page(&mut walk, &source("tools/list", 0, None, "")).unwrap());
        let CatalogCollection::Tools(catalog) = walk.finish().unwrap() else { panic!("wrong catalog"); };
        assert_eq!(catalog.page_count(), 4);
        assert!(catalog.entries().is_empty());
    }
}

#[test]
fn exact_cumulative_bytes_and_entries_are_shared_across_pages() {
    for method in METHODS {
        let first = source(method, 1, Some("next"), "");
        let last = source(method, 1, None, r#", "_meta":{"private":"metadata-canary"},"x-open":1.20e+4"#);
        let originals = [decoded(method, &first), decoded(method, &last)];
        let bytes = originals.iter().map(|page| page.encode().unwrap().len()).sum::<usize>();
        for refusal in [None, Some(CatalogError::ByteLimit), Some(CatalogError::EntryLimit)] {
            let limit = CatalogLimits::new(
                2,
                if refusal == Some(CatalogError::EntryLimit) { 1 } else { 2 },
                bytes - usize::from(refusal == Some(CatalogError::ByteLimit)),
            ).unwrap();
            let mut walk = traversal(method, limit);
            assert!(!page(&mut walk, &first).unwrap());
            let result = page(&mut walk, &last);
            match refusal {
                None => {
                    assert!(result.unwrap());
                    assert_collection(walk.finish().unwrap(), &originals);
                }
                Some(expected) => {
                    assert!(matches!(result, Err(DpopCatalogError::Catalog(actual)) if actual == expected));
                    assert!(walk.finish().is_err());
                }
            }
        }
    }
}

#[test]
fn page_and_cursor_exhaustion_do_not_return_a_truncated_catalog() {
    for method in METHODS {
        let mut walk = traversal(method, CatalogLimits::new(2, 4, 1024 * 1024).unwrap());
        assert!(!page(&mut walk, &source(method, 1, Some(""), "")).unwrap());
        assert!(matches!(
            page(&mut walk, &source(method, 1, Some(""), "")),
            Err(DpopCatalogError::Catalog(CatalogError::PageLimit)),
        ));
        assert_eq!(walk.sequence, 2);
        assert!(walk.finish().is_err());
        let mut walk = traversal(method, CatalogLimits::default());
        assert!(!page(&mut walk, &source(method, 1, Some("next"), "")).unwrap());
        assert!(matches!(
            page(&mut walk, &source(method, 0, Some(&"x".repeat(16 * 1024 + 1)), "")),
            Err(DpopCatalogError::Catalog(CatalogError::CursorLimit)),
        ));
        assert!(walk.finish().is_err());
    }
}

#[test]
fn shared_collector_cannot_finish_early_or_recover_from_a_refused_page() {
    let new = || CatalogCollector::new("tools/list", CatalogLimits::default()).unwrap();
    assert!(new().finish().is_err());
    let mut incomplete = new();
    incomplete.append(decoded("tools/list", &source("tools/list", 1, Some("next"), ""))).unwrap();
    assert!(incomplete.finish().is_err());
    for after_terminal in [false, true] {
        let mut collector = new();
        collector.append(decoded("tools/list", &source("tools/list", 1, if after_terminal { None } else { Some("next") }, ""))).unwrap();
        assert!(collector.append(decoded("resources/list", &source("resources/list", 0, None, ""))).is_err());
        assert!(collector.append(decoded("tools/list", &source("tools/list", 0, None, ""))).is_err());
        assert!(collector.finish().is_err());
    }
}

#[test]
fn non_catalog_initial_cursors_extensions_and_bad_prefixes_are_refused() {
    let start = |req, prefix: &str| Traversal::new(
        req, prefix, ManagedCoreLimits::default(), CatalogLimits::default(), 8 * 1024 * 1024,
    );
    assert!(matches!(start(request("tools/call", json!({"name":"never-run"})), "run"), Err(DpopCatalogError::InvalidRequest)));
    for method in METHODS {
        for cursor in ["", "foreign-credential-cursor"] {
            assert!(matches!(start(request(method, json!({"cursor":cursor})), "run"), Err(DpopCatalogError::InvalidRequest)));
        }
        for prefix in ["", "a/b", "a b", "雪", "\n", &"x".repeat(129)] {
            assert!(matches!(start(request(method, json!({})), prefix), Err(DpopCatalogError::InvalidIdPrefix)));
        }
        let mut params = request(method, json!({})).encode_params().unwrap().unwrap();
        params["_meta"][fastmcp_protocol::FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"] = json!({"io.modelcontextprotocol/tasks":{}});
        let offered = CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&params)).unwrap();
        assert!(matches!(start(offered, "run"), Err(DpopCatalogError::Core(DpopCoreError::Protocol(ManagedCoreError::UnsupportedRequest)))));
    }
}

#[test]
fn per_page_encoding_limits_and_response_correlation_are_not_bypassed() {
    let mut measure = traversal("tools/list", CatalogLimits::default());
    let (wire, _) = measure.next_request(TARGET).unwrap();
    let mut walk = Traversal::new(
        request("tools/list", json!({})), "catalog", ManagedCoreLimits::default(), CatalogLimits::default(), wire.body().len(),
    ).unwrap();
    assert!(!page(&mut walk, &source("tools/list", 0, Some("next"), "")).unwrap());
    assert!(matches!(walk.next_request(TARGET), Err(DpopCatalogError::Core(DpopCoreError::Protocol(ManagedCoreError::RequestTooLarge)))));
    assert_eq!(walk.sequence, 1);
    assert!(walk.finish().is_err());
    let mut walk = traversal("tools/list", CatalogLimits::default());
    assert!(!page(&mut walk, &source("tools/list", 0, Some("next"), "")).unwrap());
    let (wire, mut decoder) = walk.next_request(TARGET).unwrap();
    let mut wrong = response(&wire, &source("tools/list", 0, None, ""));
    let mut body: Value = serde_json::from_slice(&wrong.body).unwrap();
    body["id"] = json!("catalog.0");
    wrong.body = serde_json::to_vec(&body).unwrap();
    assert!(decode_response(&mut decoder, wrong).is_err());
    assert!(walk.finish().is_err());
}

#[test]
fn every_http_error_including_nonce_challenge_stays_terminal_for_the_page() {
    for status in [202, 204, 307, 400, 401, 429, 500] {
        let mut walk = traversal("tools/list", CatalogLimits::default());
        assert!(!page(&mut walk, &source("tools/list", 0, Some("next"), "")).unwrap());
        let (wire, mut decoder) = walk.next_request(TARGET).unwrap();
        let mut denied = response(&wire, &source("tools/list", 0, None, ""));
        denied.status = status;
        denied.headers.push(("DPoP-Nonce".to_owned(), "next-nonce".to_owned()));
        assert!(matches!(decode_response(&mut decoder, denied), Err(DpopCoreError::Protocol(ManagedCoreError::HttpStatus { status: actual })) if actual == status));
        assert_eq!(walk.sequence, 2);
        assert!(walk.finish().is_err());
    }
}

#[test]
fn cancelled_public_catalog_refuses_before_network_and_does_not_revoke_session() {
    let cx = Cx::for_testing();
    cx.set_cancel_requested(true);
    let endpoint = CanonicalHttpUrl::parse("https://issuer.example/token").unwrap();
    let session = DpopSession::new(
        DpopKey::generate().unwrap(), endpoint.clone(), CanonicalHttpUrl::parse(TARGET).unwrap(),
    ).unwrap();
    let credential = session.admit_token_response(
        &endpoint, 200, br#"{"access_token":"token","token_type":"DPoP","expires_in":60}"#,
        Instant::now(), Duration::from_secs(60),
    ).unwrap();
    let mut client = DpopHttpClient::new(session, DpopHttpPolicy::default()).unwrap();
    let owner = client.revocation_handle();
    let mut operation = Box::pin(client.collect_catalog(
        &cx, &credential, request("tools/list", json!({})), "run", ManagedCoreLimits::default(), CatalogLimits::default(),
    ));
    assert!(matches!(
        operation.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Err(DpopCatalogError::Core(DpopCoreError::Transport(DpopHttpError::Cancelled)))),
    ));
    drop(operation);
    assert!(!owner.is_revoked());
}
