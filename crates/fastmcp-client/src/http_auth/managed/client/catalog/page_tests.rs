//! Exercise the collector with the real method-owned result codec.

use super::*;
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::{
    ClientCapabilities, CoreRequest, ExactJsonMember, ExactJsonValue, FinalRequestMeta,
};
use serde_json::json;

const KINDS: [CatalogKind; 4] = [
    CatalogKind::Tools,
    CatalogKind::Resources,
    CatalogKind::Templates,
    CatalogKind::Prompts,
];
const HINTS: &str = r#""ttlMs":0,"cacheScope":"private""#;

fn page(kind: CatalogKind, count: usize, cursor: Option<&str>, fields: &str) -> CoreResult {
    let (method, field, entry) = match kind {
        CatalogKind::Tools => (
            "tools/list",
            "tools",
            json!({"name":"private-entry", "inputSchema":{"type":"object"}}),
        ),
        CatalogKind::Resources => (
            "resources/list",
            "resources",
            json!({"name":"private-entry", "uri":"note:///item"}),
        ),
        CatalogKind::Templates => (
            "resources/templates/list",
            "resourceTemplates",
            json!({"name":"private-entry", "uriTemplate":"note:///{id}"}),
        ),
        CatalogKind::Prompts => (
            "prompts/list",
            "prompts",
            json!({"name":"private-entry"}),
        ),
    };
    let entries = serde_json::to_string(&vec![entry; count]).unwrap();
    let cursor = cursor.map_or_else(String::new, |cursor| {
        format!(",\"nextCursor\":{}", serde_json::to_string(cursor).unwrap())
    });
    let source = format!(r#"{{"resultType":"complete","{field}":{entries},{fields}{cursor}}}"#);
    let metadata = FinalRequestMeta::new(ClientCapabilities::default());
    let request = CoreRequest::decode(
        ProtocolEra::Modern2026,
        method,
        Some(&json!({"_meta":metadata})),
    )
    .unwrap();
    request.decode_result(&source).unwrap()
}

fn assert_pages(entries: Entries, originals: &[CoreResult]) {
    match entries.finish() {
        Collected::Tools(catalog) => assert_views(&catalog, originals),
        Collected::Resources(catalog) => assert_views(&catalog, originals),
        Collected::Templates(catalog) => assert_views(&catalog, originals),
        Collected::Prompts(catalog) => assert_views(&catalog, originals),
    }
}

fn assert_views<T: Serialize>(catalog: &ManagedCatalog<T>, originals: &[CoreResult]) {
    assert_eq!(catalog.page_count(), originals.len());
    for (index, original) in originals.iter().enumerate() {
        let mut reconstructed = original.clone();
        macro_rules! check {
            ($result:ident, $diagnostic:ident, $field:ident) => {{
                assert_eq!(
                    serde_json::to_vec(catalog.page_entries(index).unwrap()).unwrap(),
                    serde_json::to_vec(&$result.payload.$field).unwrap()
                );
                assert_eq!(
                    catalog.page_has_continuation(index),
                    Some($result.payload.next_cursor.is_some())
                );
                assert_eq!(catalog.page_diagnostic(index), $diagnostic.as_ref());
                $result.meta = catalog.page_metadata(index).unwrap().clone();
                $result.extras = catalog.page_extras(index).unwrap().clone();
                let (ttl, scope) = catalog.page_cache_hints(index).unwrap();
                $result.payload.ttl_ms = ttl.clone();
                $result.payload.cache_scope = *scope;
            }};
        }
        match &mut reconstructed {
            CoreResult::Final(FinalCoreResult::ToolsList { result, diagnostic }) => {
                check!(result, diagnostic, tools);
            }
            CoreResult::Final(FinalCoreResult::ResourcesList { result, diagnostic }) => {
                check!(result, diagnostic, resources);
            }
            CoreResult::Final(FinalCoreResult::ResourceTemplatesList { result, diagnostic }) => {
                check!(result, diagnostic, resource_templates);
            }
            CoreResult::Final(FinalCoreResult::PromptsList { result, diagnostic }) => {
                check!(result, diagnostic, prompts);
            }
            _ => panic!("non-catalog comparison fixture"),
        }
        // Only the fixture retains the original cursor. The product exposes
        // its presence, never a raw token that could be reused after logout.
        // Re-encode the ACTUAL metadata/extras views to distinguish absent
        // metadata from {}, and to detect changed number lexemes or ordering.
        assert_eq!(reconstructed.encode().unwrap(), original.encode().unwrap());
    }
    for absent in [originals.len(), usize::MAX] {
        assert!(catalog.page_entries(absent).is_none());
        assert!(catalog.page_metadata(absent).is_none());
        assert!(catalog.page_extras(absent).is_none());
        assert!(catalog.page_cache_hints(absent).is_none());
        assert!(catalog.page_diagnostic(absent).is_none());
        assert!(catalog.page_has_continuation(absent).is_none());
    }
}

fn counts(entries: &Entries) -> (usize, usize) {
    match entries {
        Entries::Tools(catalog) => (catalog.entries().len(), catalog.page_count()),
        Entries::Resources(catalog) => (catalog.entries().len(), catalog.page_count()),
        Entries::Templates(catalog) => (catalog.entries().len(), catalog.page_count()),
        Entries::Prompts(catalog) => (catalog.entries().len(), catalog.page_count()),
    }
}

fn usage(meter: &Meter) -> (usize, usize, usize) {
    (meter.pages, meter.entries, meter.remaining_bytes)
}

#[test]
fn every_catalog_preserves_exact_page_views_and_empty_page_boundaries() {
    for kind in KINDS {
        let sources = [
            page(kind, 2, Some(""), HINTS),
            page(
                kind,
                0,
                Some(""),
                r#""ttlMs":15,"cacheScope":"public","_meta":{},"x-open":null"#,
            ),
            page(
                kind,
                1,
                None,
                r#""ttlMs":0,"cacheScope":"private","_meta":{"private":"metadata-canary","z":900719925474099312345,"a":1.20e+4,"nextCursor":"inert"},"x-open":{"z":900719925474099312345,"a":1.20e+4,"values":[null,true,"雪"]},"inputRequests":{"not-authority":true},"requestState":"inert-state""#,
            ),
        ];
        let expected: Vec<_> = sources.iter().map(|page| page.encode().unwrap()).collect();
        assert!(expected[2].contains("900719925474099312345"));
        assert!(expected[2].contains("1.20e+4"));
        let total = expected.iter().map(String::len).sum();
        let mut meter = Meter::new(CatalogLimits::new(3, 3, total).unwrap());
        let mut entries = Entries::new(kind);
        for (index, source) in sources.iter().cloned().enumerate() {
            let cursor = entries.append(source, &mut meter).unwrap();
            assert_eq!(cursor.as_deref(), if index == 2 { None } else { Some("") });
        }
        assert_eq!(counts(&entries), (3, 3));
        assert_eq!(meter.remaining_bytes, 0);
        assert_pages(entries, &sources);
    }
}

#[test]
fn complete_page_byte_limit_counts_metadata_and_extras_before_retention() {
    for kind in KINDS {
        let first = page(kind, 1, Some("next"), HINTS);
        let last = page(
            kind,
            1,
            None,
            r#""ttlMs":0,"cacheScope":"private","_meta":{"secret":"private-meta"},"x-extra":"private-extra""#,
        );
        let first_encoded = first.encode().unwrap();
        let total = first_encoded.len() + last.encode().unwrap().len();
        for exact in [false, true] {
            let limit = total - usize::from(!exact);
            let mut meter = Meter::new(CatalogLimits::new(2, 2, limit).unwrap());
            let mut entries = Entries::new(kind);
            entries.append(first.clone(), &mut meter).unwrap();
            let before = usage(&meter);
            let outcome = entries.append(last.clone(), &mut meter);
            if exact {
                assert_eq!(outcome, Ok(None));
                assert_eq!(counts(&entries), (2, 2));
                assert_eq!(meter.remaining_bytes, 0);
            } else {
                assert_eq!(outcome, Err(CatalogError::ByteLimit));
                assert_eq!(usage(&meter), before);
                assert_eq!(counts(&entries), (1, 1));
                assert_pages(entries, std::slice::from_ref(&first));
            }
        }
    }
}

#[test]
fn a_full_nonterminal_page_cannot_consume_the_entire_remaining_byte_budget() {
    for kind in KINDS {
        let first = page(kind, 0, Some(""), HINTS);
        let size = first.encode().unwrap().len();
        for spare_byte in [false, true] {
            let mut meter = Meter::new(
                CatalogLimits::new(2, 1, size + usize::from(spare_byte)).unwrap(),
            );
            let mut entries = Entries::new(kind);
            let before = usage(&meter);
            let outcome = entries.append(first.clone(), &mut meter);
            if spare_byte {
                assert_eq!(outcome, Ok(Some(String::new())));
                assert_eq!(counts(&entries), (0, 1));
                assert_eq!(meter.remaining_bytes, 1);
            } else {
                assert_eq!(outcome, Err(CatalogError::ByteLimit));
                assert_eq!(usage(&meter), before);
                assert_eq!(counts(&entries), (0, 0));
            }
        }
    }
}

#[test]
fn wrong_result_family_and_invalid_encoding_do_not_mutate_a_partial_catalog() {
    let first = page(CatalogKind::Tools, 1, Some("next"), HINTS);
    let mut entries = Entries::new(CatalogKind::Tools);
    let mut meter = Meter::new(CatalogLimits::default());
    entries.append(first.clone(), &mut meter).unwrap();
    let before = usage(&meter);
    let wrong_family = page(CatalogKind::Prompts, 1, None, HINTS);
    let mut invalid = page(CatalogKind::Tools, 1, None, HINTS);
    let CoreResult::Final(FinalCoreResult::ToolsList { result, .. }) = &mut invalid else {
        panic!("tools fixture decoded another result family");
    };
    // The generic constructor cannot know the selected composition. The
    // method-owned encoder must refuse this collision, not drop it silently.
    result.extras = UnknownResultMembers::try_new(
        vec![ExactJsonMember {
            name: "tools".to_owned(),
            value: ExactJsonValue::Bool(true),
        }],
        &[],
    )
    .unwrap();
    assert!(invalid.encode().is_err());
    for refused in [wrong_family, invalid] {
        assert_eq!(
            entries.append(refused, &mut meter),
            Err(CatalogError::UnexpectedResult)
        );
        assert_eq!(usage(&meter), before);
        assert_eq!(counts(&entries), (1, 1));
    }
    assert_pages(entries, &[first]);
}

#[test]
fn per_page_peer_diagnostics_are_not_combined_or_discarded() {
    let mut first = page(CatalogKind::Tools, 1, Some("next"), HINTS);
    let CoreResult::Final(FinalCoreResult::ToolsList { diagnostic, .. }) = &mut first else {
        panic!("tools fixture decoded another result family");
    };
    *diagnostic = Some(ResultPeerDiagnostic::ModernMissingResultType);
    let mut entries = Entries::new(CatalogKind::Tools);
    let mut meter = Meter::new(CatalogLimits::default());
    let pages = [first, page(CatalogKind::Tools, 0, None, HINTS)];
    for page in &pages {
        entries.append(page.clone(), &mut meter).unwrap();
    }
    assert_pages(entries, &pages);
}

#[test]
fn catalog_debug_redacts_retained_metadata_extras_entries_and_cursors() {
    let mut entries = Entries::new(CatalogKind::Prompts);
    let mut meter = Meter::new(CatalogLimits::default());
    entries
        .append(
            page(
                CatalogKind::Prompts,
                1,
                Some("private-cursor"),
                r#""ttlMs":0,"cacheScope":"private","_meta":{"private":"private-meta"},"x-extra":"private-extra""#,
            ),
            &mut meter,
        )
        .unwrap();
    entries
        .append(page(CatalogKind::Prompts, 0, None, HINTS), &mut meter)
        .unwrap();
    let Collected::Prompts(catalog) = entries.finish() else {
        panic!("prompts fixture collected another family");
    };
    assert_eq!(catalog.page_count(), 2);
    assert_eq!(catalog.entries()[0].name, "private-entry");
    let debug = format!("{catalog:?}");
    assert!(debug.contains("pages: 2"));
    assert!(!debug.contains("private-"));
    assert_eq!(
        catalog.page_metadata(0).unwrap().metadata().get("private"),
        Some(&ExactJsonValue::String("private-meta".to_owned()))
    );
    assert!(catalog.page_extras(0).unwrap().members().iter().any(|member| {
        member.name == "x-extra"
            && member.value == ExactJsonValue::String("private-extra".to_owned())
    }));
    assert_eq!(catalog.page_has_continuation(0), Some(true));
    assert_eq!(catalog.page_has_continuation(1), Some(false));
}
