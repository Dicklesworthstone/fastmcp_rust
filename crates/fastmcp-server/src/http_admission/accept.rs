//! Bounded, quote-aware response negotiation for the modern POST boundary.
//!
//! RFC 9110 sections 12.4.2 and 12.5.1: determine each representation's quality
//! from its most specific matching range, THEN compare the representations.
//! In particular, an exact q=0 cannot be undone by a positive wildcard. JSON
//! wins equal qualities, retaining the existing default for ordinary clients.
//!
//! The response writer offers parameter-free application/json and
//! text/event-stream. A range requiring other media parameters does not match
//! either offer. Invalid syntax rejects negotiation rather than salvaging
//! preferences from a partially parsed field. Duplicate equally specific
//! ranges use the lower quality, independent of field or member order.

use super::{MAX_ACCEPT_MEMBERS, ModernPostRejection, ResponseRepresentation};

const MAX_ACCEPT_PARAMETERS: usize = 16;
const MAX_IGNORED_ACCEPT_EMPTY_ELEMENTS: usize = 16;

pub(super) fn negotiate_representation(
    headers: &[(String, String)],
) -> Result<ResponseRepresentation, ModernPostRejection> {
    let mut members = 0_usize;
    let mut empty_elements = 0_usize;
    let mut saw_accept = false;
    let mut json = Preference::default();
    let mut sse = Preference::default();

    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("accept") {
            continue;
        }
        saw_accept = true;
        for member in QuotedParts::new(value, b',') {
            let member = ows(member.map_err(|()| ModernPostRejection::NotAcceptable)?);
            if member.is_empty() {
                empty_elements += 1;
                if empty_elements > MAX_IGNORED_ACCEPT_EMPTY_ELEMENTS {
                    return Err(ModernPostRejection::NotAcceptable);
                }
                continue;
            }
            members += 1;
            if members > MAX_ACCEPT_MEMBERS {
                return Err(ModernPostRejection::NotAcceptable);
            }
            let range = MediaRange::parse(member)
                .map_err(|()| ModernPostRejection::NotAcceptable)?;
            if let Some(specificity) = range.specificity_for("application", "json") {
                json.consider(specificity, range.quality);
            }
            if let Some(specificity) = range.specificity_for("text", "event-stream") {
                sse.consider(specificity, range.quality);
            }
        }
    }

    if !saw_accept {
        return Ok(ResponseRepresentation::Json);
    }
    let (json, sse) = (json.quality(), sse.quality());
    if json > 0 && json >= sse {
        Ok(ResponseRepresentation::Json)
    } else if sse > 0 {
        Ok(ResponseRepresentation::RequestScopedSse)
    } else {
        Err(ModernPostRejection::NotAcceptable)
    }
}

#[derive(Default)]
struct Preference {
    matched: Option<(u8, u16)>,
}

impl Preference {
    fn consider(&mut self, specificity: u8, quality: u16) {
        self.matched = Some(match self.matched {
            Some((previous, weight)) if previous > specificity => (previous, weight),
            Some((previous, weight)) if previous == specificity => (previous, weight.min(quality)),
            _ => (specificity, quality),
        });
    }

    fn quality(&self) -> u16 {
        self.matched.map_or(0, |(_, quality)| quality)
    }
}

struct MediaRange<'a> {
    media_type: &'a str,
    subtype: &'a str,
    quality: u16,
    requires_parameters: bool,
}

impl<'a> MediaRange<'a> {
    fn parse(member: &'a str) -> Result<Self, ()> {
        let mut parts = QuotedParts::new(member, b';');
        let essence = ows(parts.next().ok_or(())??);
        let (media_type, subtype) = essence.split_once('/').ok_or(())?;
        if !is_token(media_type) || !is_token(subtype)
            || (media_type == "*" && subtype != "*") {
            return Err(());
        }
        let mut quality = None;
        let mut requires_parameters = false;
        for (index, parameter) in parts.enumerate() {
            if index >= MAX_ACCEPT_PARAMETERS {
                return Err(());
            }
            let parameter = ows(parameter?);
            // RFC 9110's parameters production permits empty parameter slots.
            if parameter.is_empty() {
                continue;
            }
            let (name, value) = parameter.split_once('=').ok_or(())?;
            if !is_token(name) || !is_parameter_value(value) {
                return Err(());
            }
            if name.eq_ignore_ascii_case("q") {
                if quality.is_some() {
                    return Err(());
                }
                quality = Some(parse_quality(value).ok_or(())?);
            } else {
                requires_parameters = true;
            }
        }
        Ok(Self {
            media_type,
            subtype,
            quality: quality.unwrap_or(1000),
            requires_parameters,
        })
    }

    fn specificity_for(&self, media_type: &str, subtype: &str) -> Option<u8> {
        if self.requires_parameters {
            return None;
        }
        if self.media_type == "*" && self.subtype == "*" {
            Some(0)
        } else if !self.media_type.eq_ignore_ascii_case(media_type) {
            None
        } else if self.subtype == "*" {
            Some(1)
        } else if self.subtype.eq_ignore_ascii_case(subtype) {
            Some(2)
        } else {
            None
        }
    }
}

/// Exact thousandths; floating-point parsing would accept non-HTTP forms and
/// can turn a tiny, invalid preference into an unintended positive weight.
fn parse_quality(value: &str) -> Option<u16> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if !matches!(whole, "0" | "1") || fraction.len() > 3
        || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if whole == "1" {
        return fraction.bytes().all(|byte| byte == b'0').then_some(1000);
    }
    let mut quality = 0_u16;
    for byte in fraction.bytes() {
        quality = quality * 10 + u16::from(byte - b'0');
    }
    for _ in fraction.len()..3 {
        quality *= 10;
    }
    Some(quality)
}

fn ows(value: &str) -> &str {
    value.trim_matches([' ', '\t'])
}

fn is_token(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte|
        byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

fn is_parameter_value(value: &str) -> bool {
    if is_token(value) {
        return true;
    }
    let Some(quoted) = value.strip_prefix('"').and_then(|value| value.strip_suffix('"')) else {
        return false;
    };
    let mut escaped = false;
    for byte in quoted.bytes() {
        if byte < b' ' && byte != b'\t' || byte == 0x7f {
            return false;
        }
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            return false;
        }
    }
    !escaped
}

/// Split a list or parameter sequence without letting a quoted comma or
/// semicolon manufacture another preference. Slices end only at ASCII bytes,
/// so UTF-8 boundaries remain valid. No allocation or unbounded retention.
struct QuotedParts<'a> {
    rest: Option<&'a str>,
    separator: u8,
}

impl<'a> QuotedParts<'a> {
    fn new(value: &'a str, separator: u8) -> Self {
        Self { rest: Some(value), separator }
    }
}

impl<'a> Iterator for QuotedParts<'a> {
    type Item = Result<&'a str, ()>;

    fn next(&mut self) -> Option<Self::Item> {
        let value = self.rest.take()?;
        let mut quoted = false;
        let mut escaped = false;
        for (index, byte) in value.bytes().enumerate() {
            if byte < b' ' && byte != b'\t' || byte == 0x7f {
                return Some(Err(()));
            }
            if escaped {
                escaped = false;
            } else if quoted && byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = !quoted;
            } else if !quoted && byte == self.separator {
                self.rest = Some(&value[index + 1..]);
                return Some(Ok(&value[..index]));
            }
        }
        Some(if quoted || escaped { Err(()) } else { Ok(value) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{HttpAdmissionLimits, HttpEndpointConfig, admit_modern_post};
    use fastmcp_protocol::FINAL_PROTOCOL_VERSION;
    use serde_json::json;

    fn negotiate(values: &[&str]) -> Result<ResponseRepresentation, ModernPostRejection> {
        let fields = values.iter().map(|value| ("Accept".to_owned(), (*value).to_owned())).collect::<Vec<_>>();
        negotiate_representation(&fields)
    }

    fn headers(values: &[&str]) -> Vec<(String, String)> {
        let mut fields = vec![
            ("Content-Type".to_owned(), "application/json".to_owned()),
            ("MCP-Protocol-Version".to_owned(), FINAL_PROTOCOL_VERSION.to_owned()),
            ("Mcp-Method".to_owned(), "server/discover".to_owned()),
        ];
        fields.extend(values.iter().map(|value| ("aCcEpT".to_owned(), (*value).to_owned())));
        fields
    }

    fn config() -> HttpEndpointConfig {
        HttpEndpointConfig::new("/mcp", HttpAdmissionLimits::new(32, 8192, 65536).unwrap()).unwrap()
    }

    fn body() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "jsonrpc":"2.0", "id":1, "method":"server/discover", "params":{
                "_meta":{
                    "io.modelcontextprotocol/protocolVersion":FINAL_PROTOCOL_VERSION,
                    "io.modelcontextprotocol/clientCapabilities":{}
                }
            }
        })).unwrap()
    }

    #[test]
    fn exact_exclusions_override_wildcards_in_either_order_or_field() {
        for fields in [
            vec!["application/json;q=0, */*;q=1"],
            vec!["*/*;q=1, application/json;q=0"],
            vec!["application/json;q=0", "*/*;q=1"],
            vec!["*/*;q=1", "application/json;q=0"],
            vec!["application/*;q=0, */*;q=1"],
        ] {
            assert_eq!(negotiate(&fields), Ok(ResponseRepresentation::RequestScopedSse));
        }
        assert_eq!(negotiate(&["*/*;q=1, application/json;q=0, text/event-stream;q=0"]),
            Err(ModernPostRejection::NotAcceptable));
        assert_eq!(negotiate(&["*/*;q=0, application/json;q=0.1"]), Ok(ResponseRepresentation::Json));
    }

    #[test]
    fn quality_selects_streaming_and_json_wins_only_ties() {
        assert_eq!(negotiate(&["application/json;q=0.1, text/event-stream;q=0.9"]),
            Ok(ResponseRepresentation::RequestScopedSse));
        assert_eq!(negotiate(&["text/*;q=0.7, */*;q=0.8, text/event-stream;q=0.9"]),
            Ok(ResponseRepresentation::RequestScopedSse));
        assert_eq!(negotiate(&["application/json;q=0.7, text/event-stream;q=0.7"]),
            Ok(ResponseRepresentation::Json));
        assert_eq!(negotiate(&[]), Ok(ResponseRepresentation::Json));
        assert_eq!(negotiate(&[""]), Err(ModernPostRejection::NotAcceptable));
    }

    #[test]
    fn duplicate_equal_specificity_cannot_resurrect_an_exclusion() {
        for fields in [vec!["application/json", "application/json;q=0"],
            vec!["application/json;q=0", "application/json"]] {
            assert_eq!(negotiate(&fields), Err(ModernPostRejection::NotAcceptable));
        }
        assert_eq!(negotiate(&["application/json, APPLICATION/JSON;q=0, text/event-stream"]),
            Ok(ResponseRepresentation::RequestScopedSse));
    }

    #[test]
    fn quality_grammar_is_exact_and_exhaustive_at_thousandth_precision() {
        for quality in 0_u16..1000 {
            assert_eq!(parse_quality(&format!("0.{quality:03}")), Some(quality));
        }
        for valid in ["1", "1.", "1.0", "1.00", "1.000"] {
            assert_eq!(parse_quality(valid), Some(1000));
        }
        for invalid in ["", ".5", "00", "01", "1.001", "0.0001", "1.0000", "-0.1",
            "+0.5", "NaN", "inf", "1e-1", "2", "0.5.0", " 0.5", "\"0.5\""] {
            assert_eq!(parse_quality(invalid), None, "{invalid:?}");
            assert_eq!(negotiate(&[&format!("application/json;q={invalid}"), "text/event-stream"]),
                Err(ModernPostRejection::NotAcceptable));
        }
        assert_eq!(negotiate(&["application/json;q=1;Q=0"]), Err(ModernPostRejection::NotAcceptable));
    }

    #[test]
    fn quoted_delimiters_do_not_inject_supported_media_ranges() {
        for value in [
            r#"application/json;profile="x, text/event-stream;q=1""#,
            r#"application/json;profile="x; q=1""#,
            r#"application/json;profile="x\", text/event-stream;q=1""#,
        ] {
            assert_eq!(negotiate(&[value]), Err(ModernPostRejection::NotAcceptable));
            assert_eq!(negotiate(&[value, "text/event-stream"]), Ok(ResponseRepresentation::RequestScopedSse));
        }
        assert_eq!(negotiate(&[r#"application/json;profile="unterminated, text/event-stream"#]),
            Err(ModernPostRejection::NotAcceptable));
        for value in ["*/json", "application /json", "/json", "application/json/extra",
            "application/json;q =1", "application/json\r\n", "application/json;profile=\""] {
            assert_eq!(negotiate(&[value]), Err(ModernPostRejection::NotAcceptable));
        }
    }

    #[test]
    fn member_parameter_and_empty_element_limits_are_aggregate_and_exact() {
        let at_limit = vec!["application/json"; MAX_ACCEPT_MEMBERS].join(",");
        assert_eq!(negotiate(&[&at_limit]), Ok(ResponseRepresentation::Json));
        assert_eq!(negotiate(&[&at_limit, "text/event-stream"]), Err(ModernPostRejection::NotAcceptable));
        let empties = format!("{}application/json", ",".repeat(MAX_IGNORED_ACCEPT_EMPTY_ELEMENTS));
        assert_eq!(negotiate(&[&empties]), Ok(ResponseRepresentation::Json));
        assert_eq!(negotiate(&[&empties, ""]), Err(ModernPostRejection::NotAcceptable));
        let parameters = format!("application/json{}", ";".repeat(MAX_ACCEPT_PARAMETERS));
        assert_eq!(negotiate(&[&parameters]), Ok(ResponseRepresentation::Json));
        assert_eq!(negotiate(&[&format!("{parameters};")]), Err(ModernPostRejection::NotAcceptable));
    }

    #[test]
    fn public_post_admission_uses_negotiated_weights_without_changing_body() {
        let config = config();
        let body = body();
        let original = body.clone();
        let fields = headers(&["application/json;q=0", "*/*;q=0.8"]);
        let admitted = admit_modern_post(&config, "POST", "/mcp", &fields, &body).unwrap();
        assert_eq!(admitted.representation(), ResponseRepresentation::RequestScopedSse);
        assert_eq!(admitted.request().method, "server/discover");
        assert_eq!(body, original);
        let rejected = headers(&["application/json;q=0", "text/event-stream;q=0", "*/*;q=1"]);
        assert_eq!(admit_modern_post(&config, "POST", "/mcp", &rejected, &body).map(|_| ()),
            Err(ModernPostRejection::NotAcceptable));
    }

    #[test]
    fn invalid_accept_rejects_before_json_decode() {
        let fields = headers(&["application/json;q=NaN"]);
        assert_eq!(admit_modern_post(&config(), "POST", "/mcp", &fields, b"not JSON").map(|_| ()),
            Err(ModernPostRejection::NotAcceptable));
    }
}
