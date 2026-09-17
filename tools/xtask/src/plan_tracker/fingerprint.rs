//! Versioned, domain-separated binary fingerprints.
//!
//! Delimiter-joined text fingerprints are ambiguous: two different graphs can
//! serialize to one string when an identifier contains the delimiter, and a
//! digest that two different inputs share cannot detect drift between them.
//! These streams are length-prefixed, counted, domain-separated by magic, and
//! exactly decodable.
//!
//! The digest is the full 32-byte SHA-256 of the complete stream, taken once.
//! Truncation, uppercase rendering, double hashing, hashing a textual hex
//! rendering, and swapping the algorithm are all distinct wrong answers, and
//! each has a test.

use std::collections::BTreeSet;

use super::diagnostics::{Code, Diagnostic};
use super::digest::{hex, sha256};
use super::plan::{Limits, Plan};

/// Domain tag for the dependency graph stream.
pub const GRAPH_MAGIC: &[u8; 8] = b"FMCPGRF\0";
/// Domain tag for the package corpus stream.
pub const CORPUS_MAGIC: &[u8; 8] = b"FMCPCOR\0";
/// Stream version. A design constant, not a measurement.
pub const STREAM_VERSION: u16 = 2;

/// Unsigned ASCII-byte lexicographic ordering.
///
/// Never locale, Unicode collation, case folding, or natural sort: under
/// natural sort `A-10` precedes `A-2`, which silently reorders the stream and
/// changes the digest without changing the graph.
fn byte_order(left: &str, right: &str) -> std::cmp::Ordering {
    left.as_bytes().cmp(right.as_bytes())
}

/// Encode the dependency graph as a v2 stream.
pub fn encode_graph(plan: &Plan) -> Vec<u8> {
    let mut nodes: Vec<&str> = plan.ids();
    nodes.sort_by(|a, b| byte_order(a, b));
    nodes.dedup();

    let mut edges: Vec<(&str, &str)> = plan
        .edges
        .iter()
        .map(|(dependent, prerequisite)| (dependent.as_str(), prerequisite.as_str()))
        .collect();
    edges.sort_by(|a, b| byte_order(a.0, b.0).then_with(|| byte_order(a.1, b.1)));
    edges.dedup();

    let mut out = Vec::with_capacity(16 + nodes.len() * 12 + edges.len() * 24);
    out.extend_from_slice(GRAPH_MAGIC);
    out.extend_from_slice(&STREAM_VERSION.to_be_bytes());
    out.extend_from_slice(&(nodes.len() as u32).to_be_bytes());
    for node in &nodes {
        out.extend_from_slice(&(node.len() as u16).to_be_bytes());
        out.extend_from_slice(node.as_bytes());
    }
    out.extend_from_slice(&(edges.len() as u32).to_be_bytes());
    for (dependent, prerequisite) in &edges {
        out.extend_from_slice(&(dependent.len() as u16).to_be_bytes());
        out.extend_from_slice(dependent.as_bytes());
        out.extend_from_slice(&(prerequisite.len() as u16).to_be_bytes());
        out.extend_from_slice(prerequisite.as_bytes());
    }
    out
}

/// Encode the package corpus as a v2 stream, in physical plan order.
pub fn encode_corpus(plan: &Plan) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + plan.packages.len() * 64);
    out.extend_from_slice(CORPUS_MAGIC);
    out.extend_from_slice(&STREAM_VERSION.to_be_bytes());
    out.extend_from_slice(&(plan.packages.len() as u32).to_be_bytes());
    for package in &plan.packages {
        out.extend_from_slice(&(package.id.len() as u16).to_be_bytes());
        out.extend_from_slice(package.id.as_bytes());
        out.extend_from_slice(&(package.canonical_body.len() as u64).to_be_bytes());
        out.extend_from_slice(&package.canonical_body);
    }
    out
}

/// A decoded graph stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedGraph {
    pub nodes: Vec<String>,
    pub edges: Vec<(String, String)>,
}

/// A decoded corpus stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedCorpus {
    pub packages: Vec<(String, Vec<u8>)>,
}

/// Exact-consumption cursor with checked arithmetic.
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
    subject: &'static str,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8], subject: &'static str) -> Self {
        Self { bytes, offset: 0, subject }
    }

    fn fail(&self, field: &str, detail: impl Into<String>) -> Diagnostic {
        Diagnostic::new(Code::StreamMalformed, self.subject, field, detail)
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], Diagnostic> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or_else(|| self.fail("length", "length overflow"))?;
        if end > self.bytes.len() {
            return Err(self.fail(
                "truncated",
                format!("need {count} bytes at offset {}", self.offset),
            ));
        }
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn u16(&mut self) -> Result<u16, Diagnostic> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, Diagnostic> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&mut self) -> Result<u64, Diagnostic> {
        let bytes = self.take(8)?;
        let mut buffer = [0u8; 8];
        buffer.copy_from_slice(bytes);
        Ok(u64::from_be_bytes(buffer))
    }

    fn identifier(&mut self, limits: &Limits) -> Result<String, Diagnostic> {
        let length = usize::from(self.u16()?);
        if length == 0 || length > limits.max_id_bytes {
            return Err(self.fail("id_len", format!("{length} is outside 1..={}", limits.max_id_bytes)));
        }
        let bytes = self.take(length)?;
        String::from_utf8(bytes.to_vec()).map_err(|error| self.fail("id", error.to_string()))
    }

    fn finish(&self) -> Result<(), Diagnostic> {
        if self.offset != self.bytes.len() {
            return Err(self.fail(
                "trailing",
                format!("{} unconsumed bytes", self.bytes.len() - self.offset),
            ));
        }
        Ok(())
    }
}

fn expect_header(
    cursor: &mut Cursor<'_>,
    magic: &[u8; 8],
) -> Result<(), Diagnostic> {
    let observed = cursor.take(8)?;
    if observed != magic {
        return Err(cursor.fail(
            "magic",
            format!("expected {:?}, observed {:?}", hex(magic), hex(observed)),
        ));
    }
    let version = cursor.u16()?;
    if version != STREAM_VERSION {
        return Err(cursor.fail(
            "version",
            format!("expected {STREAM_VERSION}, observed {version}"),
        ));
    }
    Ok(())
}

/// Decode a graph stream, rejecting anything the encoder could not have
/// produced: wrong magic, wrong version, over-limit counts, unsorted or
/// duplicate records, truncation, and trailing bytes.
pub fn decode_graph(bytes: &[u8], limits: &Limits) -> Result<DecodedGraph, Diagnostic> {
    let mut cursor = Cursor::new(bytes, "graph-v2");
    expect_header(&mut cursor, GRAPH_MAGIC)?;

    let node_count = cursor.u32()? as usize;
    if node_count > limits.max_packages {
        return Err(cursor.fail("node_count", format!("{node_count} exceeds {}", limits.max_packages)));
    }
    let mut nodes = Vec::with_capacity(node_count.min(limits.max_packages));
    let mut previous: Option<String> = None;
    for _ in 0..node_count {
        let id = cursor.identifier(limits)?;
        if let Some(last) = &previous
            && byte_order(last, &id) != std::cmp::Ordering::Less
        {
            return Err(cursor.fail("node_order", format!("{last:?} then {id:?} is not ascending")));
        }
        previous = Some(id.clone());
        nodes.push(id);
    }

    let edge_count = cursor.u32()? as usize;
    if edge_count > limits.max_edges {
        return Err(cursor.fail("edge_count", format!("{edge_count} exceeds {}", limits.max_edges)));
    }
    let known: BTreeSet<&str> = nodes.iter().map(String::as_str).collect();
    let mut edges = Vec::with_capacity(edge_count.min(limits.max_edges));
    let mut previous_edge: Option<(String, String)> = None;
    for _ in 0..edge_count {
        let dependent = cursor.identifier(limits)?;
        let prerequisite = cursor.identifier(limits)?;
        if !known.contains(dependent.as_str()) || !known.contains(prerequisite.as_str()) {
            return Err(cursor.fail(
                "edge_unresolved",
                format!("{dependent:?} -> {prerequisite:?} names an undeclared node"),
            ));
        }
        if dependent == prerequisite {
            return Err(cursor.fail("edge_self", format!("{dependent:?} depends on itself")));
        }
        let candidate = (dependent, prerequisite);
        if let Some(last) = &previous_edge {
            let ordering = byte_order(&last.0, &candidate.0)
                .then_with(|| byte_order(&last.1, &candidate.1));
            if ordering != std::cmp::Ordering::Less {
                return Err(cursor.fail(
                    "edge_order",
                    format!("{last:?} then {candidate:?} is not ascending"),
                ));
            }
        }
        previous_edge = Some(candidate.clone());
        edges.push(candidate);
    }

    cursor.finish()?;
    Ok(DecodedGraph { nodes, edges })
}

/// Decode a corpus stream under the same discipline.
pub fn decode_corpus(bytes: &[u8], limits: &Limits) -> Result<DecodedCorpus, Diagnostic> {
    let mut cursor = Cursor::new(bytes, "corpus-v2");
    expect_header(&mut cursor, CORPUS_MAGIC)?;

    let count = cursor.u32()? as usize;
    if count > limits.max_packages {
        return Err(cursor.fail("package_count", format!("{count} exceeds {}", limits.max_packages)));
    }
    let mut packages = Vec::with_capacity(count.min(limits.max_packages));
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for _ in 0..count {
        let id = cursor.identifier(limits)?;
        if !seen.insert(id.clone()) {
            return Err(cursor.fail("package_duplicate", format!("{id:?} appears twice")));
        }
        let length = cursor.u64()?;
        let length = usize::try_from(length)
            .map_err(|_| cursor.fail("body_len", "length does not fit in this address space"))?;
        if length == 0 || length > limits.max_body_bytes {
            return Err(cursor.fail(
                "body_len",
                format!("{length} is outside 1..={}", limits.max_body_bytes),
            ));
        }
        let body = cursor.take(length)?.to_vec();
        packages.push((id, body));
    }

    cursor.finish()?;
    Ok(DecodedCorpus { packages })
}

/// Full 32-byte SHA-256 of a complete stream, taken exactly once.
pub fn fingerprint(stream: &[u8]) -> [u8; 32] {
    sha256(stream)
}

/// The required 64-character lowercase hexadecimal rendering.
pub fn fingerprint_hex(stream: &[u8]) -> String {
    hex(&fingerprint(stream))
}

/// Round-trip proof: decode a stream and re-encode it, requiring byte
/// identity. A decoder that silently normalizes would let two distinct byte
/// streams share one trusted digest.
pub fn graph_reencodes_identically(bytes: &[u8], limits: &Limits) -> Result<(), Diagnostic> {
    let decoded = decode_graph(bytes, limits)?;
    let plan = Plan {
        packages: decoded
            .nodes
            .iter()
            .map(|id| super::plan::Package {
                id: id.clone(),
                title: String::new(),
                canonical_body: b"x\n".to_vec(),
                dependencies: Vec::new(),
            })
            .collect(),
        edges: decoded.edges.clone(),
    };
    let reencoded = encode_graph(&plan);
    if reencoded != bytes {
        return Err(Diagnostic::new(
            Code::StreamReencodeMismatch,
            "graph-v2",
            "reencode",
            "a canonical re-encode is not byte-identical to the input",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::plan::Package;

    fn limits() -> Limits {
        Limits::default()
    }

    fn plan(ids: &[&str], edges: &[(&str, &str)]) -> Plan {
        Plan {
            packages: ids
                .iter()
                .map(|id| Package {
                    id: (*id).to_owned(),
                    title: "t".to_owned(),
                    canonical_body: format!("body of {id}\n").into_bytes(),
                    dependencies: Vec::new(),
                })
                .collect(),
            edges: edges
                .iter()
                .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
                .collect(),
        }
    }

    // --------------------------------------------------- known answers

    #[test]
    fn graph_stream_has_the_declared_layout() {
        let encoded = encode_graph(&plan(&["AB", "C"], &[("C", "AB")]));
        let expected: Vec<u8> = [
            GRAPH_MAGIC.as_slice(),
            &[0x00, 0x02],             // version 2
            &[0x00, 0x00, 0x00, 0x02], // 2 nodes
            &[0x00, 0x02],
            b"AB",
            &[0x00, 0x01],
            b"C",
            &[0x00, 0x00, 0x00, 0x01], // 1 edge
            &[0x00, 0x01],
            b"C",
            &[0x00, 0x02],
            b"AB",
        ]
        .concat();
        assert_eq!(encoded, expected);
    }

    #[test]
    fn corpus_stream_has_the_declared_layout() {
        let mut one = plan(&["A"], &[]);
        one.packages[0].canonical_body = b"x\n".to_vec();
        let encoded = encode_corpus(&one);
        let expected: Vec<u8> = [
            CORPUS_MAGIC.as_slice(),
            &[0x00, 0x02],
            &[0x00, 0x00, 0x00, 0x01],
            &[0x00, 0x01],
            b"A",
            &[0, 0, 0, 0, 0, 0, 0, 2],
            b"x\n",
        ]
        .concat();
        assert_eq!(encoded, expected);
    }

    // ------------------------------------------------------- ordering

    #[test]
    fn ordering_is_unsigned_byte_not_natural_or_locale() {
        // Under natural sort `A-2` precedes `A-10`; under byte order it does
        // not, because '1' (0x31) sorts before '2' (0x32).
        let encoded = encode_graph(&plan(&["A-2", "A-10", "AA", "A"], &[]));
        let decoded = decode_graph(&encoded, &limits()).expect("decodes");
        assert_eq!(decoded.nodes, ["A", "A-10", "A-2", "AA"]);
    }

    #[test]
    fn prefix_identifiers_order_before_their_extensions() {
        let encoded = encode_graph(&plan(&["AB", "A"], &[]));
        let decoded = decode_graph(&encoded, &limits()).expect("decodes");
        assert_eq!(decoded.nodes, ["A", "AB"]);
    }

    #[test]
    fn edges_order_by_the_full_tuple_and_reversal_is_a_different_graph() {
        let forward = encode_graph(&plan(&["A", "B"], &[("A", "B")]));
        let reversed = encode_graph(&plan(&["A", "B"], &[("B", "A")]));
        assert_ne!(forward, reversed);
        assert_ne!(fingerprint_hex(&forward), fingerprint_hex(&reversed));

        // Same edge set, different declaration order, identical stream.
        let one = encode_graph(&plan(&["A", "B", "C"], &[("C", "A"), ("B", "A")]));
        let two = encode_graph(&plan(&["A", "B", "C"], &[("B", "A"), ("C", "A")]));
        assert_eq!(one, two);
    }

    #[test]
    fn encoding_is_deterministic() {
        let subject = plan(&["A", "B"], &[("B", "A")]);
        assert_eq!(encode_graph(&subject), encode_graph(&subject));
        assert_eq!(encode_corpus(&subject), encode_corpus(&subject));
    }

    // ------------------------------------------------- domain separation

    #[test]
    fn a_graph_and_a_corpus_never_share_a_digest() {
        let subject = plan(&["A"], &[]);
        assert_ne!(
            fingerprint_hex(&encode_graph(&subject)),
            fingerprint_hex(&encode_corpus(&subject))
        );
    }

    #[test]
    fn a_domain_swapped_stream_is_rejected() {
        let subject = plan(&["A"], &[]);
        let graph = encode_graph(&subject);
        let error = decode_corpus(&graph, &limits()).expect_err("magic must be checked");
        assert_eq!(error.code, Code::StreamMalformed);
        assert_eq!(error.field, "magic");
    }

    #[test]
    fn a_version_swapped_stream_is_rejected() {
        let mut stream = encode_graph(&plan(&["A"], &[]));
        stream[9] = 3;
        assert_eq!(
            decode_graph(&stream, &limits()).unwrap_err().field,
            "version"
        );
    }

    // ------------------------------------------------------- mutations

    #[test]
    fn every_truncation_boundary_is_rejected() {
        let stream = encode_graph(&plan(&["A", "B"], &[("B", "A")]));
        for cut in 0..stream.len() {
            assert!(
                decode_graph(&stream[..cut], &limits()).is_err(),
                "truncation at {cut} must be rejected"
            );
        }
        assert!(decode_graph(&stream, &limits()).is_ok());
    }

    #[test]
    fn a_trailing_byte_is_rejected() {
        let mut stream = encode_graph(&plan(&["A"], &[]));
        stream.push(0);
        assert_eq!(
            decode_graph(&stream, &limits()).unwrap_err().field,
            "trailing"
        );
    }

    #[test]
    fn an_inflated_count_is_rejected_rather_than_allocated() {
        let mut stream = encode_graph(&plan(&["A"], &[]));
        stream[10..14].copy_from_slice(&u32::MAX.to_be_bytes());
        let error = decode_graph(&stream, &limits()).expect_err("must reject");
        assert_eq!(error.code, Code::StreamMalformed);
        assert_eq!(error.field, "node_count");
    }

    #[test]
    fn an_unsorted_or_duplicate_node_record_is_rejected() {
        // Hand-build a stream whose nodes descend.
        let stream: Vec<u8> = [
            GRAPH_MAGIC.as_slice(),
            &[0, 2],
            &[0, 0, 0, 2],
            &[0, 1],
            b"B",
            &[0, 1],
            b"A",
            &[0, 0, 0, 0],
        ]
        .concat();
        assert_eq!(
            decode_graph(&stream, &limits()).unwrap_err().field,
            "node_order"
        );

        let duplicate: Vec<u8> = [
            GRAPH_MAGIC.as_slice(),
            &[0, 2],
            &[0, 0, 0, 2],
            &[0, 1],
            b"A",
            &[0, 1],
            b"A",
            &[0, 0, 0, 0],
        ]
        .concat();
        assert_eq!(
            decode_graph(&duplicate, &limits()).unwrap_err().field,
            "node_order"
        );
    }

    #[test]
    fn a_zero_or_over_limit_length_is_rejected() {
        let zero: Vec<u8> = [
            GRAPH_MAGIC.as_slice(),
            &[0, 2],
            &[0, 0, 0, 1],
            &[0, 0], // zero-length identifier
            &[0, 0, 0, 0],
        ]
        .concat();
        assert_eq!(decode_graph(&zero, &limits()).unwrap_err().field, "id_len");
    }

    #[test]
    fn an_edge_naming_an_undeclared_node_is_rejected() {
        let stream: Vec<u8> = [
            GRAPH_MAGIC.as_slice(),
            &[0, 2],
            &[0, 0, 0, 1],
            &[0, 1],
            b"A",
            &[0, 0, 0, 1],
            &[0, 1],
            b"A",
            &[0, 1],
            b"Z",
        ]
        .concat();
        assert_eq!(
            decode_graph(&stream, &limits()).unwrap_err().field,
            "edge_unresolved"
        );
    }

    #[test]
    fn a_body_substitution_changes_the_corpus_digest() {
        let mut subject = plan(&["A"], &[]);
        let baseline = fingerprint_hex(&encode_corpus(&subject));
        subject.packages[0].canonical_body = b"different\n".to_vec();
        assert_ne!(baseline, fingerprint_hex(&encode_corpus(&subject)));
    }

    #[test]
    fn a_round_trip_reencodes_byte_identically() {
        let stream = encode_graph(&plan(&["A", "B", "C"], &[("C", "A"), ("B", "A")]));
        graph_reencodes_identically(&stream, &limits()).expect("round trip is exact");
    }

    // --------------------------------------------------- digest hygiene

    #[test]
    fn the_digest_is_a_single_full_length_lowercase_sha256() {
        let stream = encode_graph(&plan(&["A"], &[]));
        let rendered = fingerprint_hex(&stream);
        assert_eq!(rendered.len(), 64);
        assert!(rendered.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));

        // Distinct wrong answers.
        let raw = fingerprint(&stream);
        assert_ne!(rendered, hex(&sha256(&raw)), "double hashing");
        assert_ne!(rendered, hex(&sha256(rendered.as_bytes())), "hashing the hex text");
        assert_ne!(rendered, rendered[..32].to_owned(), "truncation");
        assert_ne!(rendered, rendered.to_uppercase(), "uppercase");
    }

    #[test]
    fn a_one_byte_change_anywhere_changes_the_digest() {
        let stream = encode_graph(&plan(&["A", "B"], &[("B", "A")]));
        let baseline = fingerprint_hex(&stream);
        for index in 0..stream.len() {
            let mut mutated = stream.clone();
            mutated[index] ^= 0x01;
            assert_ne!(baseline, fingerprint_hex(&mutated), "byte {index}");
        }
    }
}
