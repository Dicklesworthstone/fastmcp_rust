//! Fence-aware canonical plan extraction.
//!
//! Packages are found with an explicit bounded state machine, not a heading
//! regex over raw lines: a `### PKG — Title` inside a fenced code block is
//! example text, and counting it as a package would silently admit a
//! requirement that no one owns.
//!
//! Every limit here is a *declared design limit* and is therefore a legitimate
//! frozen constant. The digests over this corpus are measurements of mutable
//! content and are deliberately not frozen anywhere -- they are computed on
//! every run.

use std::collections::BTreeSet;

use super::diagnostics::{Code, Diagnostic};

/// Hard parser limits, checked before allocation.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_plan_bytes: usize,
    pub max_packages: usize,
    pub max_edges: usize,
    pub max_id_bytes: usize,
    pub max_body_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_plan_bytes: 64 * 1024 * 1024,
            max_packages: 4_096,
            max_edges: 65_536,
            max_id_bytes: 64,
            max_body_bytes: 2 * 1024 * 1024,
        }
    }
}

/// The em dash that separates a package id from its title.
pub const EM_DASH: char = '\u{2014}';
/// The heading that opens the canonical region.
pub const REGION_START: &str = "### FND-01 \u{2014} ";
/// The heading that closes the canonical region.
pub const REGION_END: &str = "## 24. Dependency graph and critical path";
/// The exact zero-edge sentinel.
pub const NONE_BULLET: &str = "- None.";

/// One canonical package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    pub id: String,
    pub title: String,
    pub canonical_body: Vec<u8>,
    pub dependencies: Vec<String>,
}

/// The parsed canonical corpus and its dependency graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub packages: Vec<Package>,
    /// `(dependent, prerequisite)` pairs in physical plan order.
    pub edges: Vec<(String, String)>,
}

impl Plan {
    pub fn ids(&self) -> Vec<&str> {
        self.packages.iter().map(|p| p.id.as_str()).collect()
    }
}

/// True when `id` matches `[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*` within `max_bytes`.
///
/// Lowercase, underscore, leading digit or hyphen, doubled or trailing hyphen,
/// whitespace, control, and non-ASCII forms are all invalid.
pub fn is_package_id(id: &str, max_bytes: usize) -> bool {
    let bytes = id.as_bytes();
    if bytes.is_empty() || bytes.len() > max_bytes || !id.is_ascii() {
        return false;
    }
    if !bytes[0].is_ascii_uppercase() {
        return false;
    }
    let mut previous_hyphen = false;
    for (index, byte) in bytes.iter().enumerate().skip(1) {
        match byte {
            b'-' => {
                // No doubled hyphen and no trailing hyphen.
                if previous_hyphen || index + 1 == bytes.len() {
                    return false;
                }
                previous_hyphen = true;
            }
            b'A'..=b'Z' | b'0'..=b'9' => previous_hyphen = false,
            _ => return false,
        }
    }
    true
}

/// A CommonMark fence opener or closer at 0-3 spaces of indentation.
struct Fence {
    character: u8,
    run_length: usize,
}

/// Classify a line as a fence marker, if it is one.
fn fence_marker(line: &str) -> Option<(u8, usize, &str)> {
    let indent = line.len() - line.trim_start_matches(' ').len();
    if indent > 3 {
        return None;
    }
    let rest = &line[indent..];
    let character = match rest.as_bytes().first() {
        Some(b'`') => b'`',
        Some(b'~') => b'~',
        _ => return None,
    };
    let run_length = rest
        .bytes()
        .take_while(|byte| *byte == character)
        .count();
    if run_length < 3 {
        return None;
    }
    Some((character, run_length, &rest[run_length..]))
}

/// Line-by-line fence state, so callers can ask whether a line is structural.
///
/// Remembering the opening character and run length matters: a shorter or
/// mismatched closer does not close the block, and treating it as one would
/// let the rest of a code sample be read as plan structure.
pub struct FenceScanner {
    open: Option<Fence>,
}

impl Default for FenceScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl FenceScanner {
    pub fn new() -> Self {
        Self { open: None }
    }

    pub fn is_open(&self) -> bool {
        self.open.is_some()
    }

    /// Feed one line. Returns true when the line is *outside* a fence and is
    /// not itself a fence marker, i.e. when it may carry plan structure.
    pub fn accept(&mut self, line: &str) -> bool {
        let Some((character, run_length, info)) = fence_marker(line) else {
            return self.open.is_none();
        };

        match &self.open {
            None => {
                // A backtick opener's info string may not contain a backtick.
                if character == b'`' && info.contains('`') {
                    return true;
                }
                self.open = Some(Fence { character, run_length });
                false
            }
            Some(fence) => {
                if character == fence.character
                    && run_length >= fence.run_length
                    && info.trim().is_empty()
                {
                    self.open = None;
                }
                false
            }
        }
    }
}

/// Canonical package bytes: CRLF to LF, trailing space/tab stripped from every
/// line, outer blank lines removed, exactly one trailing LF.
pub fn canonicalize_body(body: &str) -> Vec<u8> {
    let normalized = body.replace("\r\n", "\n");
    let mut lines: Vec<&str> = normalized
        .split('\n')
        .map(|line| line.trim_end_matches([' ', '\t']))
        .collect();
    while lines.first().is_some_and(|line| line.is_empty()) {
        lines.remove(0);
    }
    while lines.last().is_some_and(|line| line.is_empty()) {
        lines.pop();
    }
    let mut out = lines.join("\n").into_bytes();
    out.push(b'\n');
    out
}

/// Admissibility of the raw plan bytes, before any structural parsing.
fn admit_bytes(bytes: &[u8], limits: &Limits) -> Result<String, Diagnostic> {
    if bytes.len() > limits.max_plan_bytes {
        return Err(Diagnostic::new(
            Code::PlanLimitExceeded,
            "plan",
            "max_plan_bytes",
            format!("{} bytes exceeds {}", bytes.len(), limits.max_plan_bytes),
        ));
    }
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err(Diagnostic::new(
            Code::PlanEncodingInvalid,
            "plan",
            "bom",
            "a UTF-8 byte order mark is not admissible",
        ));
    }
    if bytes.contains(&0) {
        return Err(Diagnostic::new(
            Code::PlanEncodingInvalid,
            "plan",
            "nul",
            "a NUL byte is not admissible",
        ));
    }
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'\r' && bytes.get(index + 1) != Some(&b'\n') {
            return Err(Diagnostic::new(
                Code::PlanEncodingInvalid,
                "plan",
                "bare_cr",
                format!("bare CR at byte {index}"),
            ));
        }
    }
    let text = String::from_utf8(bytes.to_vec()).map_err(|error| {
        Diagnostic::new(Code::PlanEncodingInvalid, "plan", "utf8", error.to_string())
    })?;

    // CRLF is admissible and is normalized here, before any structural scan.
    // Normalizing only inside `canonicalize_body` would be too late: the line
    // scan splits on LF, so a CRLF document would carry a trailing CR on every
    // line and no heading or `Dependencies:` line would ever match its exact
    // spelling. The documented guarantee is that a CRLF plan and its LF twin
    // produce byte-identical canonical streams, which requires normalizing
    // before extraction rather than after it.
    Ok(text.replace("\r\n", "\n"))
}

/// True for a CommonMark thematic break used as an interstitial separator.
fn is_separator(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.len() < 3 {
        return false;
    }
    let first = trimmed.as_bytes()[0];
    matches!(first, b'-' | b'*' | b'_') && trimmed.bytes().all(|byte| byte == first)
}

/// True for a level-one or level-two structural heading.
fn is_phase_heading(line: &str) -> bool {
    line.starts_with("# ") || line.starts_with("## ")
}

/// Parse a package heading, which must be exactly `### <ID> — <TITLE>`.
fn parse_heading(line: &str, limits: &Limits) -> Result<(String, String), Diagnostic> {
    let subject = line.chars().take(72).collect::<String>();

    let Some(rest) = line.strip_prefix("### ") else {
        return Err(Diagnostic::new(
            Code::PackageHeadingInvalid,
            subject,
            "prefix",
            "a package heading begins in column zero with `### `",
        ));
    };
    if line.contains('\t') || line.trim_end() != line {
        return Err(Diagnostic::new(
            Code::PackageHeadingInvalid,
            subject,
            "whitespace",
            "a package heading carries no tab and no trailing whitespace",
        ));
    }

    let separator = format!(" {EM_DASH} ");
    let Some((id, title)) = rest.split_once(&separator) else {
        return Err(Diagnostic::new(
            Code::PackageHeadingInvalid,
            subject,
            "em_dash",
            "expected one ASCII space on each side of U+2014",
        ));
    };

    if !is_package_id(id, limits.max_id_bytes) {
        return Err(Diagnostic::new(
            Code::PackageIdInvalid,
            subject,
            "id",
            format!("{id:?} is not a canonical package identifier"),
        ));
    }
    if title.is_empty() || title.len() > 512 || title.chars().any(char::is_control) {
        return Err(Diagnostic::new(
            Code::PackageHeadingInvalid,
            subject,
            "title",
            "a title is 1 to 512 bytes and carries no control character",
        ));
    }

    Ok((id.to_owned(), title.to_owned()))
}

/// Parse the canonical region of the plan.
pub fn parse(bytes: &[u8], limits: &Limits) -> Result<Plan, Diagnostic> {
    let text = admit_bytes(bytes, limits)?;

    // Pass one: classify every line's fence state across the whole document,
    // so the region boundaries themselves are recognized only outside fences.
    let lines: Vec<&str> = text.split('\n').collect();
    let mut scanner = FenceScanner::new();
    let structural: Vec<bool> = lines.iter().map(|line| scanner.accept(line)).collect();
    if scanner.is_open() {
        return Err(Diagnostic::new(
            Code::PlanFenceUnclosed,
            "plan",
            "fence",
            "a fenced block opened and never closed",
        ));
    }

    let start = lines
        .iter()
        .zip(&structural)
        .position(|(line, ok)| *ok && line.starts_with(REGION_START))
        .ok_or_else(|| {
            Diagnostic::new(
                Code::PlanRegionMissing,
                "plan",
                "region_start",
                format!("no outside-fence {REGION_START:?} heading"),
            )
        })?;
    let end = lines
        .iter()
        .zip(&structural)
        .enumerate()
        .position(|(index, (line, ok))| index > start && *ok && line.starts_with(REGION_END))
        .ok_or_else(|| {
            Diagnostic::new(
                Code::PlanRegionMissing,
                "plan",
                "region_end",
                format!("no outside-fence {REGION_END:?} heading after the region start"),
            )
        })?;

    // Pass two: package heading offsets within the region.
    let heading_offsets: Vec<usize> = (start..end)
        .filter(|index| structural[*index] && lines[*index].starts_with("### "))
        .collect();
    if heading_offsets.is_empty() {
        return Err(Diagnostic::new(
            Code::PlanRegionMissing,
            "plan",
            "packages",
            "the canonical region contains no package heading",
        ));
    }
    if heading_offsets.len() > limits.max_packages {
        return Err(Diagnostic::new(
            Code::PlanLimitExceeded,
            "plan",
            "max_packages",
            format!("{} exceeds {}", heading_offsets.len(), limits.max_packages),
        ));
    }

    let mut packages: Vec<Package> = Vec::with_capacity(heading_offsets.len());
    let mut edges: Vec<(String, String)> = Vec::new();
    let mut seen_ids: BTreeSet<String> = BTreeSet::new();

    for (position, heading_index) in heading_offsets.iter().copied().enumerate() {
        let stop = heading_offsets.get(position + 1).copied().unwrap_or(end);
        let (id, title) = parse_heading(lines[heading_index], limits)?;
        if !seen_ids.insert(id.clone()) {
            return Err(Diagnostic::new(
                Code::PackageDuplicate,
                &id,
                "id",
                "one package identifier is declared twice",
            ));
        }

        // Exactly one outside-fence `Dependencies:` heading, at the end.
        let dependency_indices: Vec<usize> = (heading_index..stop)
            .filter(|index| structural[*index] && lines[*index] == "Dependencies:")
            .collect();
        let [dependency_index] = dependency_indices[..] else {
            return Err(Diagnostic::new(
                Code::DependencySectionInvalid,
                &id,
                "dependency_heading",
                format!(
                    "expected exactly one outside-fence dependency heading, found {}",
                    dependency_indices.len()
                ),
            ));
        };
        if lines.get(dependency_index + 1).copied() != Some("") {
            return Err(Diagnostic::new(
                Code::DependencySectionInvalid,
                &id,
                "blank_line",
                "`Dependencies:` is followed by exactly one blank line",
            ));
        }

        let mut cursor = dependency_index + 2;
        let mut sentinel = false;
        let mut named: Vec<String> = Vec::new();
        while cursor < stop {
            let line = lines[cursor];
            if line == NONE_BULLET {
                sentinel = true;
                cursor += 1;
                continue;
            }
            let Some(rest) = line.strip_prefix("- ") else {
                break;
            };
            let Some(candidate) = rest.strip_suffix('.') else {
                return Err(Diagnostic::new(
                    Code::DependencyBulletInvalid,
                    &id,
                    "bullet",
                    format!("{line:?} does not end in exactly one period"),
                ));
            };
            if !is_package_id(candidate, limits.max_id_bytes) {
                return Err(Diagnostic::new(
                    Code::DependencyBulletInvalid,
                    &id,
                    "bullet",
                    format!("{candidate:?} is not a canonical package identifier"),
                ));
            }
            named.push(candidate.to_owned());
            cursor += 1;
        }

        if sentinel && !named.is_empty() {
            return Err(Diagnostic::new(
                Code::DependencyMixedSentinel,
                &id,
                "bullet",
                "`- None.` and named dependencies cannot both appear",
            ));
        }
        if !sentinel && named.is_empty() {
            return Err(Diagnostic::new(
                Code::DependencySectionInvalid,
                &id,
                "bullet",
                "a dependency section declares `- None.` or at least one identifier",
            ));
        }

        // Everything after the bullets is interstitial region syntax and is
        // excluded from the package body. Only blank lines, separators, and
        // level one or two headings are permitted, so a requirement cannot
        // fall silently outside the canonical corpus.
        for index in cursor..stop {
            let line = lines[index];
            if !structural[index] || line.is_empty() {
                continue;
            }
            if is_separator(line) || is_phase_heading(line) {
                continue;
            }
            return Err(Diagnostic::new(
                Code::InterstitialProse,
                &id,
                "interstitial",
                format!("{:?} is neither blank, a separator, nor a phase heading",
                    line.chars().take(64).collect::<String>()),
            ));
        }

        let body = lines[heading_index..cursor].join("\n");
        let canonical_body = canonicalize_body(&body);
        if canonical_body.len() > limits.max_body_bytes {
            return Err(Diagnostic::new(
                Code::PackageBodyTooLarge,
                &id,
                "max_body_bytes",
                format!("{} exceeds {}", canonical_body.len(), limits.max_body_bytes),
            ));
        }

        for prerequisite in &named {
            edges.push((id.clone(), prerequisite.clone()));
        }
        packages.push(Package {
            id,
            title,
            canonical_body,
            dependencies: named,
        });
    }

    if edges.len() > limits.max_edges {
        return Err(Diagnostic::new(
            Code::PlanLimitExceeded,
            "plan",
            "max_edges",
            format!("{} exceeds {}", edges.len(), limits.max_edges),
        ));
    }

    // Graph closure: no unresolved edge, no self edge, no duplicate edge.
    let mut unique: BTreeSet<(String, String)> = BTreeSet::new();
    for (dependent, prerequisite) in &edges {
        if !seen_ids.contains(prerequisite) {
            return Err(Diagnostic::new(
                Code::DependencyUnresolved,
                dependent,
                "dependency",
                format!("{prerequisite:?} is not a declared package"),
            ));
        }
        if dependent == prerequisite {
            return Err(Diagnostic::new(
                Code::DependencySelfEdge,
                dependent,
                "dependency",
                "a package cannot depend on itself",
            ));
        }
        if !unique.insert((dependent.clone(), prerequisite.clone())) {
            return Err(Diagnostic::new(
                Code::DependencyDuplicate,
                dependent,
                "dependency",
                format!("edge to {prerequisite:?} is declared twice"),
            ));
        }
    }

    Ok(Plan { packages, edges })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits::default()
    }

    // ------------------------------------------------------- package ids

    #[test]
    fn package_id_grammar_accepts_canonical_forms() {
        for id in ["A", "FND-01", "REL-QUAR-00", "GATE-ALL-MCP-READY", "A2", "AA"] {
            assert!(is_package_id(id, 64), "{id} must be valid");
        }
    }

    #[test]
    fn package_id_grammar_rejects_every_boundary_mutation() {
        for id in [
            "",            // empty
            "a",           // lowercase
            "1A",          // leading digit
            "-A",          // leading hyphen
            "A-",          // trailing hyphen
            "A--B",        // doubled hyphen
            "A_B",         // underscore
            "A B",         // whitespace
            "A\tB",        // control
            "Á",           // non-ASCII
            "A.",          // punctuation
        ] {
            assert!(!is_package_id(id, 64), "{id:?} must be rejected");
        }
        // 64 bytes is admissible, 65 is not.
        let id_64 = format!("A{}", "B".repeat(63));
        assert_eq!(id_64.len(), 64);
        assert!(is_package_id(&id_64, 64));
        assert!(!is_package_id(&format!("{id_64}C"), 64));
    }

    // ------------------------------------------------------------ fences

    #[test]
    fn a_heading_inside_a_fence_is_not_structural() {
        let mut scanner = FenceScanner::new();
        assert!(scanner.accept("ordinary text"));
        assert!(!scanner.accept("```"));
        assert!(!scanner.accept("### FAKE \u{2014} not a package"));
        assert!(!scanner.accept("```"));
        assert!(scanner.accept("### REAL \u{2014} a package"));
    }

    #[test]
    fn a_shorter_or_mismatched_closer_does_not_close_the_fence() {
        let mut scanner = FenceScanner::new();
        assert!(!scanner.accept("````"));
        assert!(!scanner.accept("```")); // shorter: not a closer
        assert!(scanner.is_open());
        assert!(!scanner.accept("~~~~")); // wrong character: not a closer
        assert!(scanner.is_open());
        assert!(!scanner.accept("````"));
        assert!(!scanner.is_open());
    }

    #[test]
    fn fence_indentation_zero_through_three_opens_and_four_does_not() {
        for indent in 0..=3 {
            let mut scanner = FenceScanner::new();
            scanner.accept(&format!("{}```", " ".repeat(indent)));
            assert!(scanner.is_open(), "indent {indent} must open a fence");
        }
        let mut scanner = FenceScanner::new();
        assert!(scanner.accept("    ```"));
        assert!(!scanner.is_open(), "indent 4 is an indented code line");
    }

    #[test]
    fn tilde_fences_are_recognized_and_do_not_cross_close_backticks() {
        let mut scanner = FenceScanner::new();
        scanner.accept("~~~");
        assert!(scanner.is_open());
        scanner.accept("```");
        assert!(scanner.is_open(), "a backtick run cannot close a tilde fence");
        scanner.accept("~~~");
        assert!(!scanner.is_open());
    }

    #[test]
    fn a_backtick_opener_with_a_backtick_info_string_is_not_a_fence() {
        let mut scanner = FenceScanner::new();
        assert!(scanner.accept("``` rust ` inline"));
        assert!(!scanner.is_open());
    }

    // -------------------------------------------------- canonical bytes

    #[test]
    fn canonicalization_normalizes_endings_padding_and_outer_blanks() {
        assert_eq!(canonicalize_body("a\r\nb"), b"a\nb\n");
        assert_eq!(canonicalize_body("a   \nb\t\t"), b"a\nb\n");
        assert_eq!(canonicalize_body("\n\n a \n\n\n"), b" a\n");
        assert_eq!(canonicalize_body("x"), b"x\n");
        // Exactly one trailing LF, never two.
        assert_eq!(canonicalize_body("x\n\n\n"), b"x\n");
    }

    #[test]
    fn canonicalization_is_idempotent() {
        let once = canonicalize_body("a  \r\n\n b \n\n");
        let twice = canonicalize_body(std::str::from_utf8(&once).unwrap());
        assert_eq!(once, twice);
    }

    #[test]
    fn interior_blank_lines_survive_canonicalization() {
        assert_eq!(canonicalize_body("a\n\nb"), b"a\n\nb\n");
    }

    // ----------------------------------------------------- admissibility

    fn minimal_plan(body: &str) -> String {
        format!("### FND-01 \u{2014} Freeze\n\n{body}\n\n## 24. Dependency graph and critical path\n")
    }

    #[test]
    fn a_bom_bare_cr_or_nul_is_rejected() {
        let good = minimal_plan("Dependencies:\n\n- None.");
        assert!(parse(good.as_bytes(), &limits()).is_ok());

        let mut bom = vec![0xef, 0xbb, 0xbf];
        bom.extend_from_slice(good.as_bytes());
        assert_eq!(
            parse(&bom, &limits()).unwrap_err().code,
            Code::PlanEncodingInvalid
        );

        // A bare CR is a CR *not* followed by LF. Injecting one before an
        // existing LF would make a CRLF, which is admissible -- the first
        // version of this test did exactly that and asserted the wrong thing,
        // so the CR goes mid-line where it cannot pair.
        let cr = good.replace("Freeze", "Free\rze");
        assert!(!cr.contains("\r\n"), "the mutation must not form a CRLF");
        let error = parse(cr.as_bytes(), &limits()).expect_err("a bare CR is rejected");
        assert_eq!(error.code, Code::PlanEncodingInvalid);
        assert_eq!(error.field, "bare_cr");

        let mut nul = good.clone().into_bytes();
        nul.push(0);
        assert_eq!(parse(&nul, &limits()).unwrap_err().field, "nul");
    }

    #[test]
    fn crlf_is_admissible_and_yields_the_same_corpus_as_lf() {
        // The documented normalization: a CRLF plan and its LF twin must
        // parse identically and produce byte-identical canonical bodies.
        let lf = TWO_PACKAGES;
        let crlf = lf.replace('\n', "\r\n");
        assert!(crlf.contains("\r\n"));

        let from_lf = parse(lf.as_bytes(), &limits()).expect("LF parses");
        let from_crlf = parse(crlf.as_bytes(), &limits()).expect("CRLF parses");

        assert_eq!(from_lf, from_crlf, "line endings must not change the corpus");
        assert_eq!(from_crlf.ids(), ["FND-01", "FND-02"]);
        for package in &from_crlf.packages {
            assert!(
                !package.canonical_body.contains(&b'\r'),
                "{} retained a CR",
                package.id
            );
        }
    }

    #[test]
    fn a_missing_dependency_heading_names_the_violated_property() {
        // `field` names what was violated, never the literal text of the
        // thing that was missing. An evaluator joining on a defect label
        // stops matching silently when a field carries section text instead.
        let text = TWO_PACKAGES.replace("Dependencies:\n\n- None.", "No dependency section.");
        let error = parse(text.as_bytes(), &limits()).expect_err("must be rejected");
        assert_eq!(error.code, Code::DependencySectionInvalid);
        assert_eq!(error.field, "dependency_heading");
    }

    #[test]
    fn an_over_limit_plan_is_rejected_before_parsing() {
        let small = Limits { max_plan_bytes: 8, ..Limits::default() };
        let error = parse(minimal_plan("Dependencies:\n\n- None.").as_bytes(), &small)
            .expect_err("must reject");
        assert_eq!(error.code, Code::PlanLimitExceeded);
    }

    #[test]
    fn an_unclosed_fence_is_rejected() {
        let text = format!("### FND-01 \u{2014} Freeze\n\n```\nunclosed\n");
        assert_eq!(
            parse(text.as_bytes(), &limits()).unwrap_err().code,
            Code::PlanFenceUnclosed
        );
    }

    #[test]
    fn a_missing_region_boundary_is_rejected() {
        assert_eq!(
            parse(b"# nothing here\n", &limits()).unwrap_err().code,
            Code::PlanRegionMissing
        );
    }

    // ------------------------------------------------------- structure

    const TWO_PACKAGES: &str = "\
### FND-01 \u{2014} Freeze authoritative inputs

Body of one.

Dependencies:

- None.

---

### FND-02 \u{2014} Build normative traceability

Body of two.

Dependencies:

- FND-01.

## 24. Dependency graph and critical path
";

    #[test]
    fn two_packages_parse_with_one_edge() {
        let plan = parse(TWO_PACKAGES.as_bytes(), &limits()).expect("parses");
        assert_eq!(plan.ids(), ["FND-01", "FND-02"]);
        assert_eq!(plan.edges, [("FND-02".to_owned(), "FND-01".to_owned())]);
        // The interstitial separator is excluded from both bodies.
        let first = String::from_utf8(plan.packages[0].canonical_body.clone()).unwrap();
        assert!(first.ends_with("- None.\n"));
        assert!(!first.contains("---"));
    }

    #[test]
    fn a_heading_inside_a_fence_does_not_become_a_package() {
        let text = TWO_PACKAGES.replace(
            "Body of one.",
            "```\n### FAKE \u{2014} example heading\nDependencies:\n\n- None.\n```",
        );
        let plan = parse(text.as_bytes(), &limits()).expect("parses");
        assert_eq!(plan.ids(), ["FND-01", "FND-02"], "fenced heading leaked in");
    }

    #[test]
    fn an_unresolved_self_or_duplicate_edge_is_rejected() {
        let unresolved = TWO_PACKAGES.replace("- FND-01.", "- FND-99.");
        assert_eq!(
            parse(unresolved.as_bytes(), &limits()).unwrap_err().code,
            Code::DependencyUnresolved
        );

        let self_edge = TWO_PACKAGES.replace("- FND-01.", "- FND-02.");
        assert_eq!(
            parse(self_edge.as_bytes(), &limits()).unwrap_err().code,
            Code::DependencySelfEdge
        );

        let duplicate = TWO_PACKAGES.replace("- FND-01.", "- FND-01.\n- FND-01.");
        assert_eq!(
            parse(duplicate.as_bytes(), &limits()).unwrap_err().code,
            Code::DependencyDuplicate
        );
    }

    #[test]
    fn mixing_the_none_sentinel_with_an_identifier_is_rejected() {
        let mixed = TWO_PACKAGES.replace("- FND-01.", "- None.\n- FND-01.");
        assert_eq!(
            parse(mixed.as_bytes(), &limits()).unwrap_err().code,
            Code::DependencyMixedSentinel
        );
    }

    #[test]
    fn bullet_spacing_indentation_and_terminator_are_exact() {
        for bad in ["-FND-01.", "  - FND-01.", "- FND-01", "- FND-01..", "- FND-01. "] {
            let text = TWO_PACKAGES.replace("- FND-01.", bad);
            let result = parse(text.as_bytes(), &limits());
            assert!(result.is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn a_missing_blank_line_after_the_dependency_heading_is_rejected() {
        let text = TWO_PACKAGES.replace("Dependencies:\n\n- FND-01.", "Dependencies:\n- FND-01.");
        assert_eq!(
            parse(text.as_bytes(), &limits()).unwrap_err().code,
            Code::DependencySectionInvalid
        );
    }

    #[test]
    fn interstitial_prose_is_rejected() {
        let text = TWO_PACKAGES.replace("---", "This sentence owns no package.");
        assert_eq!(
            parse(text.as_bytes(), &limits()).unwrap_err().code,
            Code::InterstitialProse
        );
    }

    #[test]
    fn an_interstitial_phase_heading_is_permitted() {
        let text = TWO_PACKAGES.replace("---", "## 14. Phase 2 \u{2014} Something");
        assert!(parse(text.as_bytes(), &limits()).is_ok());
    }

    #[test]
    fn a_duplicate_package_identifier_is_rejected() {
        let text = TWO_PACKAGES.replace("### FND-02 \u{2014} Build normative traceability", "### FND-01 \u{2014} Duplicate");
        assert_eq!(
            parse(text.as_bytes(), &limits()).unwrap_err().code,
            Code::PackageDuplicate
        );
    }

    #[test]
    fn heading_em_dash_spacing_is_exact() {
        for bad in [
            "### FND-02 - Hyphen not em dash",
            "### FND-02\u{2014}No spaces",
            "### FND-02  \u{2014}  Two spaces",
        ] {
            let text = TWO_PACKAGES.replace("### FND-02 \u{2014} Build normative traceability", bad);
            assert!(parse(text.as_bytes(), &limits()).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn an_over_limit_package_body_is_rejected() {
        let tight = Limits { max_body_bytes: 16, ..Limits::default() };
        assert_eq!(
            parse(TWO_PACKAGES.as_bytes(), &tight).unwrap_err().code,
            Code::PackageBodyTooLarge
        );
    }

    #[test]
    fn an_over_limit_package_count_is_rejected() {
        let tight = Limits { max_packages: 1, ..Limits::default() };
        assert_eq!(
            parse(TWO_PACKAGES.as_bytes(), &tight).unwrap_err().field,
            "max_packages"
        );
    }
}
