//! bd-fnd04-b7-shipped-block-on-proxy-4rkp9, R5 and R6.
//!
//! R5 asks for one `#[test]` that asserts the shipped `block_on` call-site count
//! is zero across four files, and that the guard FAILS CLOSED when a named
//! source file is absent, renamed or unreadable, with that behaviour itself
//! asserted. R6 asks for a near-identical negative proving the guard can refuse,
//! run against an in-memory copy of a shipped file with exactly one call site
//! reintroduced, naming the file and line it objected to.
//!
//! The zero assertion (`fnd_04_b7_shipped_block_on_guard_four_files_are_zero`)
//! landed once R1/R2's removals did. Before then it was deliberately withheld:
//! a knowingly-red test would have broken the target for every lane.
//!
//! WHY A NEW FILE rather than an addition to an existing one. The only test in
//! this package that reads source text is `fnd_07_a.rs`, which belongs to
//! another bead and is cited by its receipts; adding a FND-04 guard there would
//! disturb a frozen surface and could void evidence this bead has no business
//! touching.
//!
//! WIDENED TO THE LIBRARY GRAPH. `guard_library_crate` applies the same scan to
//! every file each of `GUARDED_CRATES` ships, found by walking `mod` declarations
//! from `src/lib.rs`. It also refuses library-side runtime construction. The one
//! exemption is `fastmcp_core::block_on`'s own body. The workspace zero is
//! `fnd_04_b7_library_graph_has_no_block_on_or_runtime_construction`.
//!
//! The counting rules mirror `tools/shipped_block_on_census.py`, which is the
//! instrument R3/R4 were established with, except that cfg predicates are
//! evaluated for satisfiability: `not(feature = "x")` ships when the feature is
//! off. The census read 21 / 7 / 3 / 0 shipped sites for the four files before
//! the removals.
//!
//! The scanners live in `support/shipped_source.rs`, shared with FND-04 A's
//! public-signature evaluator. This file keeps the R5 predicate and its tests.

use std::path::Path;

#[path = "support/shipped_source.rs"]
mod shipped_source;

use shipped_source::{
    BRIDGE_DEFINITION, GUARDED_CRATES, Objection, disk, guard_library_crate, repository_root,
    runtime_construction_sites, shipped_block_on_sites, shipped_crate_files,
};

/// The four files R1 and R2 name, relative to the repository root.
const GUARDED_FILES: [&str; 4] = [
    "crates/fastmcp-server/src/proxy.rs",
    "crates/fastmcp-server/src/router.rs",
    "crates/fastmcp-server/src/lib.rs",
    "crates/fastmcp-server/src/legacy_2024.rs",
];

/// The guard. Refuses on an unreadable file BEFORE it can report a false clean.
fn guard_file(root: &Path, relative: &str) -> Result<(), Objection> {
    let path = root.join(relative);
    let source = std::fs::read_to_string(&path).map_err(|_| Objection::Unreadable {
        path: relative.to_owned(),
    })?;
    guard_source(relative, &source)
}

/// The same predicate over source TEXT, so R6's negative can run against an
/// in-memory copy without touching the tree.
fn guard_source(relative: &str, source: &str) -> Result<(), Objection> {
    let lines = shipped_block_on_sites(source);
    if lines.is_empty() {
        Ok(())
    } else {
        Err(Objection::ShippedCallSites {
            path: relative.to_owned(),
            lines,
        })
    }
}

/// A copy of `source` with `planted` appended as its own top-level item, and the
/// 1-based line the plant starts on.
fn plant_at_end(source: &str, planted: &str) -> (String, usize) {
    let mut out = source.to_owned();
    if !out.ends_with('\n') {
        out.push('\n');
    }
    let line = out.matches('\n').count() + 1;
    out.push_str(planted);
    out.push('\n');
    (out, line)
}

/// `disk`, except that `subject` reads as `replacement`.
fn substituting<'a>(
    subject: &'a Path,
    replacement: &'a str,
) -> impl Fn(&Path) -> Option<String> + 'a {
    move |path| {
        if path == subject {
            Some(replacement.to_owned())
        } else {
            disk(path)
        }
    }
}

/// R5, zero half: the four files R1 and R2 name hold no shipped `block_on` call.
#[test]
fn fnd_04_b7_shipped_block_on_guard_four_files_are_zero() {
    let root = repository_root();
    let objections: Vec<String> = GUARDED_FILES
        .iter()
        .filter_map(|relative| guard_file(&root, relative).err())
        .map(|objection| objection.to_string())
        .collect();
    assert!(objections.is_empty(), "{}", objections.join("\n"));
}

/// The workspace zero. No guarded library crate's shipped graph calls
/// `block_on` or builds a runtime, except `fastmcp_core::block_on`'s own body.
/// The same instrument refuses a single planted site
/// (`fnd_04_b7_library_graph_planted_negative`) and fails closed
/// (`fnd_04_b7_library_graph_fails_closed`), so this zero is not a blind one.
#[test]
fn fnd_04_b7_library_graph_has_no_block_on_or_runtime_construction() {
    let root = repository_root();
    let mut objections = Vec::new();
    let mut scanned = 0usize;
    for crate_dir in GUARDED_CRATES {
        match guard_library_crate(&root, crate_dir, &disk) {
            Ok(files) => scanned += files,
            Err(found) => objections.extend(found.iter().map(ToString::to_string)),
        }
    }
    assert!(
        objections.is_empty(),
        "shipped library code still bridges or builds a runtime:\n{}",
        objections.join("\n")
    );
    assert!(
        scanned > GUARDED_CRATES.len(),
        "the walk must reach past each crate root; scanned {scanned} files"
    );
}

/// R5, fail-closed half. A named file that is absent, renamed or unreadable must
/// make the guard REFUSE — not pass, not skip — and the refusal must name it.
#[test]
fn fnd_04_b7_shipped_block_on_guard_fails_closed_positive() {
    let root = repository_root();
    let missing = "crates/fastmcp-server/src/this_file_does_not_exist.rs";

    let objection = guard_file(&root, missing)
        .expect_err("a guard that cannot read its subject must refuse, never report success");

    assert_eq!(
        objection,
        Objection::Unreadable {
            path: missing.to_owned()
        },
        "the refusal must name the file it could not read"
    );
    assert!(
        objection.to_string().contains(missing),
        "the rendered objection must carry the path: {objection}"
    );

    // The four real files must all be READABLE, so the check above is testing
    // fail-closed behaviour rather than a typo in GUARDED_FILES. Without this the
    // test would still pass if every guarded path were wrong.
    for relative in GUARDED_FILES {
        assert!(
            root.join(relative).is_file(),
            "guarded path must exist, else the guard is aimed at nothing: {relative}"
        );
    }
}

/// R6. The same guard, against an in-memory copy of a shipped file with exactly
/// ONE call site reintroduced, must refuse and name the file and the line.
#[test]
fn fnd_04_b7_shipped_block_on_guard_planted_negative() {
    let relative = "crates/fastmcp-server/src/legacy_2024.rs";
    let root = repository_root();
    let pristine = std::fs::read_to_string(root.join(relative))
        .expect("the planted negative needs a readable subject");

    // legacy_2024.rs is the file the census reports at ZERO shipped call sites,
    // so it is the one subject where a clean baseline is available today and the
    // plant is the only variable. R1's removals have not landed, so the other
    // three still hold sites and could not distinguish a plant from a survivor.
    guard_source(relative, &pristine)
        .expect("baseline must be clean, or the plant below proves nothing");

    let mut planted = String::new();
    let mut planted_line = 0usize;
    for (index, line) in pristine.lines().enumerate() {
        planted.push_str(line);
        planted.push('\n');
        if planted_line == 0 && line.starts_with("use ") {
            planted.push_str("fn fnd04_b7_planted() { let _ = block_on(async {}); }\n");
            planted_line = index + 2;
        }
    }
    assert_ne!(planted_line, 0, "the plant must have been inserted");
    assert_eq!(
        planted.matches("block_on(").count(),
        pristine.matches("block_on(").count() + 1,
        "the plant changes exactly one dimension: one added call site"
    );

    let objection = guard_source(relative, &planted)
        .expect_err("one reintroduced shipped call site must be refused");

    assert_eq!(
        objection,
        Objection::ShippedCallSites {
            path: relative.to_owned(),
            lines: vec![planted_line],
        },
        "the refusal must name the file and the exact line it objected to"
    );
}

/// The guard must not count what is not a shipped call. Each case below is a way
/// a naive matcher reports a false positive, and `block_on` appears in all of
/// them.
#[test]
fn fnd_04_b7_shipped_block_on_guard_excludes_non_calls_positive() {
    let cases: [(&str, &str); 5] = [
        ("import", "use futures::executor::block_on;\n"),
        ("line comment", "// block_on(x) is not a call here\n"),
        ("doc comment", "/// See block_on(x) for details.\n"),
        ("string", "const S: &str = \"block_on(x)\";\n"),
        ("raw string", "const R: &str = r#\"block_on(x)\"#;\n"),
    ];
    for (label, source) in cases {
        assert_eq!(
            shipped_block_on_sites(source),
            Vec::<usize>::new(),
            "{label} must not count as a shipped call site"
        );
    }

    // cfg(test) exclusion, on a FUNCTION rather than a mod — the form a
    // mod-only stripper misses.
    let gated = "#[cfg(test)]\nfn t() { block_on(async {}); }\n";
    assert_eq!(
        shipped_block_on_sites(gated),
        Vec::<usize>::new(),
        "a call inside a cfg(test) item is not shipped"
    );

    // CONTROL: the identical body WITHOUT the attribute must be counted, so the
    // exclusion above is doing work rather than the matcher simply never firing.
    let shipped = "fn t() { block_on(async {}); }\n";
    assert_eq!(
        shipped_block_on_sites(shipped),
        vec![1],
        "the same call outside cfg(test) MUST be counted"
    );

    // cfg(not(test)) is the opposite of a test gate and stays shipped.
    let not_test = "#[cfg(not(test))]\nfn t() { block_on(async {}); }\n";
    assert_eq!(
        shipped_block_on_sites(not_test),
        vec![2],
        "cfg(not(test)) is shipped code"
    );
}

/// A cfg predicate that MENTIONS `test` is not thereby test-only. Each pair
/// differs only in whether the predicate can hold outside `cargo test`.
#[test]
fn fnd_04_b7_shipped_block_on_guard_evaluates_cfg_predicates() {
    let body = "fn t() { block_on(async {}); }\n";
    let cases: [(&str, Vec<usize>); 7] = [
        // Ships whenever the feature is on: lib.rs gates thousands of lines so.
        (
            "#[cfg(any(feature = \"legacy-2024-11-05\", test))]\n",
            vec![2],
        ),
        (
            "#[cfg(all(test, feature = \"legacy-2024-11-05\"))]\n",
            vec![],
        ),
        // A feature whose NAME contains "test" is not the `test` predicate.
        ("#[cfg(feature = \"test-internals\")]\n", vec![2]),
        ("#[cfg(test)]\n", vec![]),
        // not(feature) ships when the feature is off; not(test) always ships.
        ("#[cfg(not(feature = \"legacy-2024-11-05\"))]\n", vec![2]),
        ("#[cfg(all(unix, not(test)))]\n", vec![2]),
        ("#[cfg(all(unix, any(test, all(test, windows))))]\n", vec![]),
    ];
    for (attribute, expected) in cases {
        assert_eq!(
            shipped_block_on_sites(&format!("{attribute}{body}")),
            expected,
            "{attribute:?}"
        );
    }
}

/// A gated item WITHOUT a body ends at its semicolon. Before this rule the guard
/// ran on to the next `{` and excluded whatever shipped item came after.
#[test]
fn fnd_04_b7_shipped_block_on_guard_bodyless_item_does_not_swallow_the_next() {
    let declared = "#[cfg(test)]\nmod tests;\nfn shipped() { block_on(async {}); }\n";
    assert_eq!(
        shipped_block_on_sites(declared),
        vec![3],
        "a shipped fn after `#[cfg(test)] mod tests;` must still be counted"
    );
    let inline = "#[cfg(test)]\nmod tests { fn shipped() { block_on(async {}); } }\n";
    assert_eq!(
        shipped_block_on_sites(inline),
        Vec::<usize>::new(),
        "CONTROL: the same call inside the inline test module is excluded"
    );
    let stacked = "#[cfg(test)]\n#[allow(dead_code)]\nfn gated() { block_on(async {}); }\n";
    assert_eq!(
        shipped_block_on_sites(stacked),
        Vec::<usize>::new(),
        "further attributes between the cfg and its item do not detach the gate"
    );
}

/// Masking keeps every newline, including one a `\` line continuation escapes
/// inside a string, so reported lines match the source.
#[test]
fn fnd_04_b7_shipped_block_on_guard_keeps_lines_across_string_continuations() {
    // runtime.rs has 7 `\` continuations; dropping their newlines put a planted
    // call at line 795 instead of 802.
    let continued = "const S: &str = \"a \\\n    b\";\nfn t() { block_on(async {}); }\n";
    assert_eq!(
        shipped_block_on_sites(continued),
        vec![3],
        "the call's line is counted through the continued string"
    );
    let single = "const S: &str = \"a b\";\n\nfn t() { block_on(async {}); }\n";
    assert_eq!(
        shipped_block_on_sites(single),
        vec![3],
        "CONTROL: the same layout without a continuation"
    );
}

/// Char literals holding a quote or a brace must not desynchronise the scan.
#[test]
fn fnd_04_b7_shipped_block_on_guard_masks_char_literals() {
    let quote = "fn s() { let q = '\"'; block_on(async {}); }\n";
    assert_eq!(
        shipped_block_on_sites(quote),
        vec![1],
        "a '\"' char literal must not open a string that hides the call"
    );
    // Unmasked, the '{' leaves this item's braces unbalanced, so the region never
    // closes and the gated call is counted as shipped.
    let brace = "#[cfg(test)]\nfn t() { let b = '{'; block_on(async {}); }\n";
    assert_eq!(
        shipped_block_on_sites(brace),
        Vec::<usize>::new(),
        "a '{{' char literal must not break the cfg(test) item's brace match"
    );
    let lifetime = "fn s<'a>(x: &'a str) -> &'a str { block_on(async {}); x }\n";
    assert_eq!(
        shipped_block_on_sites(lifetime),
        vec![1],
        "lifetimes are code, not char literals"
    );
}

/// The crate walk is aimed at the shipped graph. It reaches files that only a
/// `mod` chain names, follows `#[path]`, and leaves test-only modules out. A
/// walker that scanned nothing would pass every zero assertion, so each crate
/// must yield files and specific deep ones are named.
#[test]
fn fnd_04_b7_library_graph_reaches_shipped_files_and_skips_test_modules() {
    let root = repository_root();
    let walked = |crate_dir: &str| -> Vec<String> {
        shipped_crate_files(&root, crate_dir, &disk)
            .unwrap_or_else(|objection| panic!("{crate_dir}: {objection}"))
            .into_iter()
            .map(|file| file.relative)
            .collect()
    };
    for crate_dir in GUARDED_CRATES {
        assert!(
            !walked(crate_dir).is_empty(),
            "{crate_dir} yields no shipped files"
        );
    }
    let core = walked("crates/fastmcp-core");
    assert!(
        core.iter()
            .any(|path| path == "crates/fastmcp-core/src/runtime/envelope.rs"),
        "reached only through `pub mod envelope;` in runtime.rs: {core:?}"
    );
    assert!(
        !core
            .iter()
            .any(|path| path == "crates/fastmcp-core/src/limit_01_rows.rs"),
        "declared `#[cfg(test)] mod limit_01_rows;`, so not shipped"
    );
    let console = walked("crates/fastmcp-console");
    assert!(
        console
            .iter()
            .any(|path| path == "crates/fastmcp-console/src/client/traffic.rs"),
        "`#[path = \"client/traffic.rs\"] pub mod traffic;` resolves: {console:?}"
    );
    let server = walked("crates/fastmcp-server");
    assert!(
        server
            .iter()
            .any(|path| path == "crates/fastmcp-server/src/proxy.rs")
    );
    assert!(
        !server
            .iter()
            .any(|path| path == "crates/fastmcp-server/src/tests.rs"),
        "declared `#[cfg(test)] mod tests;`, so not shipped"
    );
}

/// The crate guard refuses rather than reports clean when it cannot see its
/// subject: a missing crate root, or a shipped `mod name;` naming no file. The
/// same declaration under `#[cfg(test)]` needs no file, which is the control.
#[test]
fn fnd_04_b7_library_graph_fails_closed() {
    let root = repository_root();
    let missing = "crates/fastmcp-does-not-exist";
    assert_eq!(
        shipped_crate_files(&root, missing, &disk).err(),
        Some(Objection::Unreadable {
            path: format!("{missing}/src/lib.rs"),
        }),
    );

    let lib = root.join("crates/fastmcp-core/src/lib.rs");
    let pristine = disk(&lib).expect("fastmcp-core's lib.rs is readable");
    let (shipped, line) = plant_at_end(&pristine, "mod fnd04_b7_does_not_exist;");
    assert_eq!(
        shipped_crate_files(&root, "crates/fastmcp-core", &substituting(&lib, &shipped)).err(),
        Some(Objection::UnresolvedModule {
            path: "crates/fastmcp-core/src/lib.rs".to_owned(),
            line,
            name: "fnd04_b7_does_not_exist".to_owned(),
        }),
        "a shipped declaration without a file is refused, never skipped"
    );
    let (gated, _) = plant_at_end(&pristine, "#[cfg(test)]\nmod fnd04_b7_does_not_exist;");
    assert!(
        shipped_crate_files(&root, "crates/fastmcp-core", &substituting(&lib, &gated)).is_ok(),
        "CONTROL: the same declaration under cfg(test) is not part of the shipped graph"
    );
}

/// R6 for the crate guard. One call site, or one runtime construction, planted in
/// a file only the module tree reaches is refused by file and line. The same
/// plant in a test-only module is not shipped, so it is not refused.
#[test]
fn fnd_04_b7_library_graph_planted_negative() {
    let root = repository_root();
    let core = "crates/fastmcp-core";
    guard_library_crate(&root, core, &disk)
        .unwrap_or_else(|objections| panic!("baseline must be clean: {objections:?}"));

    let envelope = root.join("crates/fastmcp-core/src/runtime/envelope.rs");
    let pristine = disk(&envelope).expect("envelope.rs is readable");
    let relative = "crates/fastmcp-core/src/runtime/envelope.rs".to_owned();
    let (planted, line) = plant_at_end(
        &pristine,
        "fn fnd04_b7_planted() { let _ = block_on(async {}); }",
    );
    assert_eq!(
        guard_library_crate(&root, core, &substituting(&envelope, &planted)),
        Err(vec![Objection::ShippedCallSites {
            path: relative.clone(),
            lines: vec![line],
        }]),
    );
    let (planted, line) = plant_at_end(
        &pristine,
        "fn fnd04_b7_planted() { let _ = asupersync::runtime::RuntimeBuilder::current_thread(); }",
    );
    assert_eq!(
        guard_library_crate(&root, core, &substituting(&envelope, &planted)),
        Err(vec![Objection::RuntimeConstruction {
            path: relative,
            lines: vec![line],
        }]),
    );

    let limit = root.join("crates/fastmcp-core/src/limit_01_rows.rs");
    let (planted, _) = plant_at_end(
        &disk(&limit).expect("limit_01_rows.rs is readable"),
        "fn fnd04_b7_planted() { let _ = block_on(async {}); }",
    );
    assert!(
        guard_library_crate(&root, core, &substituting(&limit, &planted)).is_ok(),
        "CONTROL: the identical plant in a `#[cfg(test)] mod` file is not shipped"
    );
}

/// `fastmcp_core::block_on`'s own body is the one exemption, and it covers that
/// body only. The definition really does call and build (so the exemption is
/// doing work), and a second call elsewhere in the same file is refused.
#[test]
fn fnd_04_b7_library_graph_exempts_only_the_bridge_definition() {
    let root = repository_root();
    let runtime = root.join(BRIDGE_DEFINITION.0);
    let pristine = disk(&runtime).expect("the bridge's file is readable");
    assert!(
        !shipped_block_on_sites(&pristine).is_empty()
            && !runtime_construction_sites(&pristine).is_empty(),
        "CONTROL: the definition calls block_on and builds a runtime"
    );
    let (planted, line) = plant_at_end(
        &pristine,
        "fn fnd04_b7_planted() { let _ = block_on(async {}); }",
    );
    assert_eq!(
        guard_library_crate(
            &root,
            "crates/fastmcp-core",
            &substituting(&runtime, &planted)
        ),
        Err(vec![Objection::ShippedCallSites {
            path: BRIDGE_DEFINITION.0.to_owned(),
            lines: vec![line],
        }]),
    );
}
