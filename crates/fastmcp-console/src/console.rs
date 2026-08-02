//! Console wrapper for rich stderr output.
//!
//! `FastMcpConsole` is the core output surface for fastmcp-console. It wraps
//! a `rich_rust::Console` configured to write to stderr, and it automatically
//! falls back to plain text when running in agent contexts.
//!
//! # Quick Example
//!
//! ```rust,ignore
//! use fastmcp_console::console::FastMcpConsole;
//!
//! let console = FastMcpConsole::new();
//! console.rule(Some("FastMCP Console"));
//! console.print("Ready.");
//! ```

use crate::theme::FastMcpTheme;
use rich_rust::prelude::*;
use rich_rust::renderables::Renderable;
use std::io::{self, Write};
use std::sync::{Mutex, MutexGuard, OnceLock};

pub(crate) const DEFAULT_TERMINAL_FIELD_MAX_CHARS: usize = 512;
pub(crate) const DEFAULT_LOG_MESSAGE_MAX_CHARS: usize = 2_048;
pub(crate) const REDACTED_VALUE: &str = "[REDACTED]";
const TERMINAL_TEXT_HARD_MAX_CHARS: usize = 4_096;
const TERMINAL_TRUNCATION_MARKER: &str = "...";
const CREDENTIAL_KEY_SCAN_MAX_CHARS: usize = 256;

/// A bounded, redacted, single-line terminal-safe rendering of untrusted text.
///
/// Constructing this type escapes terminal controls, line separators, bidi
/// controls, and Unicode default-ignorable characters. It also redacts common
/// credential forms and applies a hard output bound. The original source text
/// is never retained.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct UntrustedDisplayText(String);

impl UntrustedDisplayText {
    /// Sanitize untrusted text using the standard terminal-field budget.
    #[must_use]
    pub fn new(text: &str) -> Self {
        Self::with_max_chars(text, DEFAULT_TERMINAL_FIELD_MAX_CHARS)
    }

    /// Sanitize untrusted text using a caller-supplied character budget.
    ///
    /// The budget is still capped by the crate's internal hard ceiling.
    #[must_use]
    pub fn with_max_chars(text: &str, max_chars: usize) -> Self {
        Self(bounded_redacted_terminal_text(text, max_chars))
    }

    /// Borrow the sanitized terminal-safe representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for UntrustedDisplayText {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Returns whether a structured field name conventionally carries a secret.
pub fn is_credential_key(key: &str) -> bool {
    // Public callers may receive peer-controlled object keys. Bound all
    // classifier allocations and fail closed when the complete key cannot be
    // inspected.
    if key
        .chars()
        .take(CREDENTIAL_KEY_SCAN_MAX_CHARS.saturating_add(1))
        .count()
        > CREDENTIAL_KEY_SCAN_MAX_CHARS
    {
        return true;
    }

    // Case-folding the complete alphanumeric spelling catches hostile mixed
    // casing such as `AuTh` and `PassWord`, where camel-case word splitting is
    // intentionally ambiguous. Keep this exact list narrow so ordinary
    // metadata such as `authentication` and `tokenizer` remains visible.
    let compact = compact_credential_key(key);
    let exact_compact = matches!(
        compact.as_str(),
        "authorization"
            | "auth"
            | "token"
            | "secret"
            | "credential"
            | "credentials"
            | "cookie"
            | "password"
            | "passphrase"
            | "signature"
            | "apikey"
            | "privatekey"
            | "codeverifier"
            | "setcookie"
            | "accesstoken"
            | "refreshtoken"
            | "clientsecret"
            | "idtoken"
            | "xamzcredential"
            | "xamzsignature"
            | "awsaccesskeyid"
            | "awssecretaccesskey"
    );

    let words = credential_key_words(key);
    let word_refs: Vec<&str> = words.iter().map(String::as_str).collect();
    let benign_metadata_suffix = word_refs.len() > 1
        && word_refs.last().is_some_and(|word| {
            matches!(
                *word,
                "algorithm" | "count" | "hint" | "length" | "name" | "policy" | "type" | "version"
            )
        });
    let exact_single = matches!(
        word_refs.as_slice(),
        ["authorization"]
            | ["auth"]
            | ["token"]
            | ["secret"]
            | ["credential"]
            | ["credentials"]
            | ["cookie"]
            | ["password"]
            | ["passphrase"]
            | ["signature"]
    );
    let sensitive_suffix = !benign_metadata_suffix
        && (word_refs.last().is_some_and(|word| {
            matches!(
                *word,
                "token"
                    | "secret"
                    | "credential"
                    | "credentials"
                    | "password"
                    | "passphrase"
                    | "authorization"
                    | "auth"
                    | "signature"
            )
        }) || word_refs.ends_with(&["api", "key"])
            || word_refs.ends_with(&["private", "key"])
            || word_refs.ends_with(&["code", "verifier"])
            || word_refs.ends_with(&["set", "cookie"]));
    let sensitive_prefix = word_refs.first().is_some_and(|word| {
        matches!(
            *word,
            "token"
                | "secret"
                | "credential"
                | "credentials"
                | "password"
                | "passphrase"
                | "authorization"
                | "auth"
                | "signature"
        )
    }) && word_refs.len() > 1
        && !benign_metadata_suffix;

    // Lowercase or deliberately irregularly-cased names may not expose a
    // camel-case boundary. Inspect the compact suffix as a fallback, while
    // retaining the metadata exclusions above and exact benign words below.
    let compact_sensitive_suffix = !benign_metadata_suffix
        && !matches!(
            compact.as_str(),
            "authentication" | "tokenizer" | "passwordless"
        )
        && [
            "accesstoken",
            "refreshtoken",
            "clientsecret",
            "idtoken",
            "apikey",
            "privatekey",
            "codeverifier",
            "setcookie",
            "passphrase",
            "password",
            "credentials",
            "credential",
            "signature",
            "secret",
            "token",
            "cookie",
            "auth",
            "authorization",
        ]
        .iter()
        .any(|suffix| compact.ends_with(suffix));

    exact_compact
        || exact_single
        || sensitive_suffix
        || sensitive_prefix
        || compact_sensitive_suffix
}

fn compact_credential_key(key: &str) -> String {
    key.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

fn credential_key_words(key: &str) -> Vec<String> {
    let characters: Vec<char> = key.chars().collect();
    let mut words = Vec::new();
    let mut current = String::new();

    for (index, character) in characters.iter().copied().enumerate() {
        if !character.is_ascii_alphanumeric() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            continue;
        }

        let previous = index.checked_sub(1).and_then(|index| characters.get(index));
        let next = characters.get(index + 1);
        let camel_boundary = !current.is_empty()
            && character.is_ascii_uppercase()
            && (previous.is_some_and(|previous| {
                previous.is_ascii_lowercase() || previous.is_ascii_digit()
            }) || (previous.is_some_and(char::is_ascii_uppercase)
                && next.is_some_and(char::is_ascii_lowercase)));
        if camel_boundary {
            words.push(std::mem::take(&mut current));
        }
        current.push(character.to_ascii_lowercase());
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

/// Redacts credential-like assignments in free text.
pub fn redact_free_text_credentials(text: &str) -> String {
    redact_free_text_credentials_with(text, REDACTED_VALUE)
}

/// Redacts credential-like assignments in free text using `replacement`.
///
/// This recognizes structured secret assignments, authorization and cookie
/// headers, standalone bearer tokens, and URI userinfo. The replacement is
/// copied verbatim and should therefore be a trusted application constant.
pub fn redact_free_text_credentials_with(text: &str, replacement: &str) -> String {
    if text.is_empty() {
        return String::new();
    }

    // Keep each pass linear and non-recursive. Assignment detection delegates
    // key classification to `is_credential_key`, so namespaced camelCase and
    // vendor-specific keys receive the same treatment as structured fields.
    let without_userinfo = redact_uri_userinfo(text, replacement);
    let without_assignments = redact_credential_assignments(&without_userinfo, replacement);
    redact_standalone_bearer(&without_assignments, replacement)
}

fn redact_uri_userinfo(text: &str, replacement: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = String::with_capacity(text.len());
    let mut emitted_through = 0usize;
    let mut search_from = 0usize;

    while let Some(relative_colon) = text[search_from..].find("://") {
        let authority_start = search_from + relative_colon + 3;
        let mut authority_end = authority_start;
        while authority_end < bytes.len()
            && !matches!(
                bytes[authority_end],
                b'/' | b'?' | b'#' | b'\r' | b'\n' | b' ' | b'\t'
            )
        {
            authority_end += 1;
        }

        let userinfo_end = bytes[authority_start..authority_end]
            .iter()
            .rposition(|byte| *byte == b'@')
            .map(|relative| authority_start + relative);
        if let Some(userinfo_end) = userinfo_end.filter(|end| *end > authority_start) {
            output.push_str(&text[emitted_through..authority_start]);
            output.push_str(replacement);
            emitted_through = userinfo_end;
        }

        search_from = authority_end.max(authority_start);
        if search_from >= bytes.len() {
            break;
        }
    }

    if emitted_through == 0 {
        return text.to_owned();
    }
    output.push_str(&text[emitted_through..]);
    output
}

fn redact_credential_assignments(text: &str, replacement: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = String::with_capacity(text.len());
    let mut emitted_through = 0usize;
    let mut cursor = 0usize;

    while cursor < bytes.len() {
        let separator = bytes[cursor];
        if !matches!(separator, b':' | b'=') {
            cursor += 1;
            continue;
        }

        let Some((key, quoted_key)) = key_before_separator(text, cursor) else {
            cursor += 1;
            continue;
        };
        if !is_credential_key(key) {
            cursor += 1;
            continue;
        }

        let mut value_start = cursor + 1;
        while value_start < bytes.len() && matches!(bytes[value_start], b' ' | b'\t') {
            value_start += 1;
        }
        if value_start >= bytes.len() || matches!(bytes[value_start], b'\r' | b'\n') {
            cursor += 1;
            continue;
        }

        let authorization = is_authorization_key(key);
        let cookie_header = is_cookie_key(key);
        let header_value = separator == b':' && !quoted_key;
        let Some((redaction_start, redaction_end)) = credential_value_range(
            text,
            value_start,
            authorization,
            header_value,
            header_value && cookie_header,
        ) else {
            cursor += 1;
            continue;
        };

        output.push_str(&text[emitted_through..redaction_start]);
        output.push_str(replacement);
        emitted_through = redaction_end;
        cursor = redaction_end.max(cursor + 1);
    }

    if emitted_through == 0 {
        return text.to_owned();
    }
    output.push_str(&text[emitted_through..]);
    output
}

fn key_before_separator(text: &str, separator: usize) -> Option<(&str, bool)> {
    let bytes = text.as_bytes();
    let mut key_end = separator;
    while key_end > 0 && matches!(bytes[key_end - 1], b' ' | b'\t') {
        key_end -= 1;
    }

    let quoted_key = key_end > 0 && matches!(bytes[key_end - 1], b'\'' | b'"');
    if quoted_key {
        key_end -= 1;
    }

    let mut key_start = key_end;
    while key_start > 0 && credential_key_byte(bytes[key_start - 1]) {
        key_start -= 1;
    }
    (key_start < key_end).then(|| (&text[key_start..key_end], quoted_key))
}

fn credential_key_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
}

fn is_authorization_key(key: &str) -> bool {
    let compact = compact_credential_key(key);
    let words = credential_key_words(key);
    is_credential_key(key)
        && (compact.ends_with("authorization")
            || compact.ends_with("auth")
            || words
                .iter()
                .any(|word| matches!(word.as_str(), "auth" | "authorization")))
}

fn is_cookie_key(key: &str) -> bool {
    let compact = compact_credential_key(key);
    let words = credential_key_words(key);
    let word_refs: Vec<&str> = words.iter().map(String::as_str).collect();
    is_credential_key(key)
        && (compact.ends_with("cookie")
            || matches!(word_refs.as_slice(), ["cookie"])
            || word_refs.ends_with(&["set", "cookie"]))
}

fn credential_value_range(
    text: &str,
    value_start: usize,
    authorization: bool,
    header_value: bool,
    cookie_header_value: bool,
) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    let quote = matches!(bytes[value_start], b'\'' | b'"').then_some(bytes[value_start]);
    let content_start = value_start + usize::from(quote.is_some());
    let content_end = if let Some(quote) = quote {
        closing_quote_or_line_end(bytes, content_start, quote)
    } else if authorization && header_value {
        line_end(bytes, content_start)
    } else if authorization {
        authorization_value_end(bytes, content_start)
    } else if cookie_header_value {
        line_end(bytes, content_start)
    } else {
        ordinary_value_end(bytes, content_start)
    };
    if content_start >= content_end {
        return None;
    }

    let redaction_start = if authorization {
        authorization_scheme_end(text, content_start, content_end).unwrap_or(content_start)
    } else {
        content_start
    };
    (redaction_start < content_end).then_some((redaction_start, content_end))
}

fn closing_quote_or_line_end(bytes: &[u8], start: usize, quote: u8) -> usize {
    let mut cursor = start;
    let mut escaped = false;
    while cursor < bytes.len() {
        let byte = bytes[cursor];
        if matches!(byte, b'\r' | b'\n') {
            return cursor;
        }
        if byte == quote && !escaped {
            return cursor;
        }
        if byte == b'\\' {
            escaped = !escaped;
        } else {
            escaped = false;
        }
        cursor += 1;
    }
    cursor
}

fn authorization_value_end(bytes: &[u8], start: usize) -> usize {
    let mut cursor = start;
    let mut quote = None;
    let mut escaped = false;
    while cursor < bytes.len() {
        let byte = bytes[cursor];
        if matches!(byte, b'\r' | b'\n') {
            break;
        }
        if let Some(active_quote) = quote {
            if byte == active_quote && !escaped {
                quote = None;
            }
            if byte == b'\\' {
                escaped = !escaped;
            } else {
                escaped = false;
            }
        } else if matches!(byte, b'\'' | b'"') {
            quote = Some(byte);
            escaped = false;
        } else if matches!(byte, b'&' | b'#') {
            break;
        }
        cursor += 1;
    }
    cursor
}

fn ordinary_value_end(bytes: &[u8], start: usize) -> usize {
    let mut cursor = start;
    while cursor < bytes.len() && !ordinary_value_delimiter(bytes[cursor]) {
        cursor += 1;
    }
    cursor
}

fn ordinary_value_delimiter(byte: u8) -> bool {
    matches!(
        byte,
        b' ' | b'\t' | b'\r' | b'\n' | b',' | b';' | b'&' | b'#' | b')' | b']' | b'}'
    )
}

fn line_end(bytes: &[u8], start: usize) -> usize {
    let mut cursor = start;
    while cursor < bytes.len() && !matches!(bytes[cursor], b'\r' | b'\n') {
        cursor += 1;
    }
    cursor
}

fn authorization_scheme_end(text: &str, start: usize, end: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut scheme_end = start;
    while scheme_end < end
        && (bytes[scheme_end].is_ascii_alphanumeric() || bytes[scheme_end] == b'-')
    {
        scheme_end += 1;
    }
    if scheme_end == start || scheme_end >= end || !matches!(bytes[scheme_end], b' ' | b'\t') {
        return None;
    }

    let scheme = &text[start..scheme_end];
    if !["basic", "bearer", "digest", "negotiate", "aws4-hmac-sha256"]
        .iter()
        .any(|candidate| scheme.eq_ignore_ascii_case(candidate))
    {
        return None;
    }

    while scheme_end < end && matches!(bytes[scheme_end], b' ' | b'\t') {
        scheme_end += 1;
    }
    Some(scheme_end)
}

fn redact_standalone_bearer(text: &str, replacement: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = String::with_capacity(text.len());
    let mut emitted_through = 0usize;
    let mut cursor = 0usize;

    while cursor + "bearer".len() <= bytes.len() {
        let word_end = cursor + "bearer".len();
        let has_word_boundaries = (cursor == 0
            || !matches!(bytes[cursor - 1], b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_'))
            && word_end < bytes.len()
            && matches!(bytes[word_end], b' ' | b'\t');
        if !has_word_boundaries || !bytes[cursor..word_end].eq_ignore_ascii_case(b"bearer") {
            cursor += 1;
            continue;
        }

        let mut value_start = word_end;
        while value_start < bytes.len() && matches!(bytes[value_start], b' ' | b'\t') {
            value_start += 1;
        }
        if value_start >= bytes.len() || matches!(bytes[value_start], b'\r' | b'\n') {
            cursor = word_end;
            continue;
        }
        let replacement_end = value_start.saturating_add(replacement.len());
        let starts_with_replacement = !replacement.is_empty()
            && text[value_start..].starts_with(replacement)
            && replacement_end <= bytes.len();
        if starts_with_replacement
            && (replacement_end == bytes.len() || ordinary_value_delimiter(bytes[replacement_end]))
        {
            cursor = replacement_end;
            continue;
        }

        let (redaction_start, redaction_end) = if starts_with_replacement {
            // An attacker-controlled token may deliberately begin with our
            // marker (for example, `Bearer <redacted>ACTUAL`). Treat only an
            // exact, delimiter-terminated marker as already redacted.
            (value_start, ordinary_value_end(bytes, replacement_end))
        } else if matches!(bytes[value_start], b'\'' | b'"') {
            let quote = bytes[value_start];
            let content_start = value_start + 1;
            (
                content_start,
                closing_quote_or_line_end(bytes, content_start, quote),
            )
        } else {
            (value_start, ordinary_value_end(bytes, value_start))
        };
        if redaction_start >= redaction_end {
            cursor = word_end;
            continue;
        }

        output.push_str(&text[emitted_through..redaction_start]);
        output.push_str(replacement);
        emitted_through = redaction_end;
        cursor = redaction_end;
    }

    if emitted_through == 0 {
        return text.to_owned();
    }
    output.push_str(&text[emitted_through..]);
    output
}

pub(crate) fn terminal_text_is_unsafe(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            // Frozen Unicode Default_Ignorable_Code_Point profile, plus the
            // Unicode line and paragraph separators. These formatting
            // characters can spoof identifiers or forge terminal layout even
            // when bidi controls and C0/C1 are escaped. Keep the reserved
            // supplementary ranges: newly assigned characters there remain
            // unsafe until this table is deliberately reviewed.
            '\u{00ad}'
                | '\u{034f}'
                | '\u{061c}'
                | '\u{115f}'..='\u{1160}'
                | '\u{17b4}'..='\u{17b5}'
                | '\u{180b}'..='\u{180f}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{3164}'
                | '\u{fe00}'..='\u{fe0f}'
                | '\u{feff}'
                | '\u{ffa0}'
                | '\u{fff0}'..='\u{fff8}'
                | '\u{1bca0}'..='\u{1bca3}'
                | '\u{1d173}'..='\u{1d17a}'
                | '\u{e0000}'..='\u{e0fff}'
        )
}

/// Produces bounded terminal-safe text escaped for insertion into rich markup.
///
/// When a trusted markup tag will be appended immediately after this value,
/// use [`bounded_rich_fragment`] so trailing backslashes cannot escape the
/// caller's opening bracket.
pub(crate) fn bounded_rich_text(text: &str, max_chars: usize) -> String {
    bounded_terminal_text_impl(text, max_chars, true)
}

/// Produces bounded terminal-safe text for interpolation before trusted markup.
///
/// Rich markup parses a backslash immediately before `[` as an escape. Doubling
/// the trailing markup-source run preserves the same number of visible
/// backslashes while ensuring a caller-appended trusted tag remains active.
pub(crate) fn bounded_rich_fragment(text: &str, max_chars: usize) -> String {
    protect_rich_fragment_right_boundary(bounded_rich_text(text, max_chars))
}

/// Redacts secrets and produces bounded, single-line terminal-safe text.
pub(crate) fn bounded_redacted_terminal_text(text: &str, max_chars: usize) -> String {
    bounded_redacted_text_impl(text, max_chars, false)
}

/// Redacts secrets and produces bounded text safe for rich markup insertion.
///
/// When a trusted markup tag will be appended immediately after this value,
/// use [`bounded_redacted_rich_fragment`].
pub(crate) fn bounded_redacted_rich_text(text: &str, max_chars: usize) -> String {
    bounded_redacted_text_impl(text, max_chars, true)
}

/// Redacts secrets and prepares a bounded value for interpolation before a
/// trusted rich-markup tag.
pub(crate) fn bounded_redacted_rich_fragment(text: &str, max_chars: usize) -> String {
    protect_rich_fragment_right_boundary(bounded_redacted_rich_text(text, max_chars))
}

fn protect_rich_fragment_right_boundary(mut fragment: String) -> String {
    let trailing_backslashes = fragment
        .as_bytes()
        .iter()
        .rev()
        .take_while(|byte| **byte == b'\\')
        .count();
    fragment.reserve(trailing_backslashes);
    fragment.extend(std::iter::repeat_n('\\', trailing_backslashes));
    fragment
}

fn bounded_redacted_text_impl(text: &str, max_chars: usize, escape_markup: bool) -> String {
    let max_chars = max_chars.min(TERMINAL_TEXT_HARD_MAX_CHARS);
    if max_chars == 0 {
        return String::new();
    }

    // Limit redaction work to a small multiple of the display budget while
    // retaining look-ahead for a secret value near the visible edge.
    let scan_limit = max_chars.saturating_mul(4);
    let mut characters = text.chars();
    let bounded_input: String = characters.by_ref().take(scan_limit).collect();
    let source_was_truncated = characters.next().is_some();
    let redacted = redact_free_text_credentials(&bounded_input);
    let rendered = bounded_terminal_text_impl(&redacted, max_chars, escape_markup);

    if !source_was_truncated || rendered.ends_with(TERMINAL_TRUNCATION_MARKER) {
        return rendered;
    }
    if max_chars <= TERMINAL_TRUNCATION_MARKER.len() {
        // For one-to-three-character budgets, preserve the visible prefix we
        // already produced. Replacing it with dots would make this helper's
        // semantics differ from `bounded_terminal_text_impl` merely because
        // the bounded regex scan detected additional source input.
        return if rendered.is_empty() {
            TERMINAL_TRUNCATION_MARKER.chars().take(max_chars).collect()
        } else {
            rendered
        };
    }

    let mut rendered = bounded_terminal_text_impl(
        &redacted,
        max_chars - TERMINAL_TRUNCATION_MARKER.len(),
        escape_markup,
    );
    if !rendered.ends_with(TERMINAL_TRUNCATION_MARKER) {
        rendered.push_str(TERMINAL_TRUNCATION_MARKER);
    }
    rendered
}

fn bounded_terminal_text_impl(text: &str, max_chars: usize, escape_markup: bool) -> String {
    let max_chars = max_chars.min(TERMINAL_TEXT_HARD_MAX_CHARS);
    if max_chars == 0 {
        return String::new();
    }

    let mut rendered = String::new();
    let mut rendered_chars = 0usize;
    let mut component_ends = Vec::new();
    let mut truncated = false;

    let mut characters = text.chars().peekable();
    'render: while let Some(character) = characters.next() {
        let component = if terminal_text_is_unsafe(character) {
            character.escape_default().collect::<String>()
        } else if escape_markup && character == '\\' {
            // Preserve ordinary backslashes verbatim. Immediately before `[`,
            // rich_rust interprets slash parity, so N source slashes must
            // become 2N+1 markup-source slashes to render N literal slashes
            // followed by a literal `[`. Cap look-ahead at the remaining
            // output budget so a huge slash run cannot force a full scan.
            let run_scan_limit = max_chars.saturating_sub(rendered_chars).saturating_add(1);
            let mut run_length = 1usize;
            while characters.peek() == Some(&'\\') {
                if run_length >= run_scan_limit {
                    truncated = true;
                    break 'render;
                }
                characters.next();
                run_length += 1;
            }

            if characters.peek() == Some(&'[') {
                characters.next();
                let mut escaped = "\\".repeat(run_length.saturating_mul(2).saturating_add(1));
                escaped.push('[');
                escaped
            } else {
                "\\".repeat(run_length)
            }
        } else if escape_markup && character == '[' {
            "\\[".to_owned()
        } else {
            character.to_string()
        };
        let component_chars = component.chars().count();
        if rendered_chars.saturating_add(component_chars) > max_chars {
            truncated = true;
            break;
        }
        rendered.push_str(&component);
        rendered_chars += component_chars;
        component_ends.push((rendered.len(), rendered_chars));
    }

    if !truncated {
        return rendered;
    }
    if max_chars <= TERMINAL_TRUNCATION_MARKER.len() {
        if !rendered.is_empty() {
            return rendered;
        }
        return TERMINAL_TRUNCATION_MARKER.chars().take(max_chars).collect();
    }

    let retained_chars = max_chars - TERMINAL_TRUNCATION_MARKER.len();
    while component_ends
        .last()
        .is_some_and(|(_, characters)| *characters > retained_chars)
    {
        component_ends.pop();
    }
    if let Some((byte_end, _)) = component_ends.last().copied() {
        rendered.truncate(byte_end);
    } else {
        rendered.clear();
    }
    rendered.push_str(TERMINAL_TRUNCATION_MARKER);
    rendered
}

/// FastMCP console for rich output to stderr.
///
/// This type centralizes rich-vs-plain output behavior and exposes
/// convenience methods for printing tables, panels, and styled text.
///
/// # Example
///
/// ```rust,ignore
/// use fastmcp_console::console::FastMcpConsole;
/// use rich_rust::prelude::Style;
///
/// let console = FastMcpConsole::new();
/// console.print_styled("Server started", Style::new().bold());
/// ```
pub struct FastMcpConsole {
    inner: Mutex<Console>,
    enabled: bool,
    theme: &'static FastMcpTheme,
}

impl FastMcpConsole {
    fn lock_inner(&self) -> MutexGuard<'_, Console> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Create with automatic detection
    #[must_use]
    pub fn new() -> Self {
        let enabled = crate::detection::should_enable_rich();
        Self::with_enabled(enabled)
    }

    /// Create with explicit enable/disable
    #[must_use]
    pub fn with_enabled(enabled: bool) -> Self {
        let inner = if enabled {
            Console::builder()
                .file(Box::new(io::stderr()))
                .force_terminal(true)
                .markup(true)
                .emoji(true)
                .highlight(false)
                .build()
        } else {
            Console::builder()
                .file(Box::new(io::stderr()))
                .no_color()
                .markup(false)
                .emoji(false)
                .highlight(false)
                .build()
        };

        Self {
            inner: Mutex::new(inner),
            enabled,
            theme: crate::theme::theme(),
        }
    }

    /// Create with custom writer (for testing)
    #[must_use]
    pub fn with_writer<W: Write + Send + 'static>(writer: W, enabled: bool) -> Self {
        let mut builder = Console::builder()
            .file(Box::new(writer))
            .markup(enabled)
            .emoji(enabled)
            .highlight(false);

        if !enabled {
            builder = builder.no_color();
        }

        let inner = if enabled {
            builder.force_terminal(true).build()
        } else {
            builder.build()
        };

        Self {
            inner: Mutex::new(inner),
            enabled,
            theme: crate::theme::theme(),
        }
    }

    // ─────────────────────────────────────────────────
    // State Queries
    // ─────────────────────────────────────────────────

    /// Check if rich output is enabled.
    pub fn is_rich(&self) -> bool {
        self.enabled
    }

    /// Get the theme used for standard styling.
    pub fn theme(&self) -> &FastMcpTheme {
        self.theme
    }

    /// Get the configured terminal width.
    pub fn width(&self) -> usize {
        self.lock_inner().width()
    }

    /// Get the configured terminal height.
    pub fn height(&self) -> usize {
        self.lock_inner().height()
    }

    // ─────────────────────────────────────────────────
    // Output Methods
    // ─────────────────────────────────────────────────

    /// Print trusted styled markup (auto-detects markup).
    ///
    /// This method does not sanitize terminal controls or secrets. Use
    /// [`Self::print_untrusted`] for any peer-, user-, or network-controlled
    /// value.
    pub fn print(&self, content: &str) {
        let console = self.lock_inner();
        if self.enabled {
            console.print(content);
        } else {
            console.print_plain(&strip_markup(content));
        }
    }

    /// Print trusted plain text (no markup processing ever).
    ///
    /// Disabling markup does not make terminal control sequences safe. Use
    /// [`Self::print_untrusted`] for untrusted values.
    pub fn print_plain(&self, text: &str) {
        // Use the dependency's markup-disabled path directly. Escaping and
        // then parsing is both unnecessary and unsafe for attacker-controlled
        // backslash runs immediately before `[`.
        self.lock_inner().print_plain(text);
    }

    /// Sanitize, redact, bound, and print an untrusted value as plain text.
    pub fn print_untrusted(&self, text: &str) {
        let safe = UntrustedDisplayText::new(text);
        self.lock_inner().print_plain(safe.as_str());
    }

    /// Print a renderable.
    pub fn render<R: Renderable>(&self, renderable: &R) {
        let console = self.lock_inner();
        if self.enabled {
            console.print_renderable(renderable);
        } else {
            // Plain fallback: caller should provide alternative or we log a placeholder
            console.print_plain("[Complex Output]");
        }
    }

    /// Print a renderable with a trusted plain-text fallback closure.
    ///
    /// Use [`Self::render_or_untrusted`] when the fallback is not trusted.
    pub fn render_or<F>(&self, render_op: F, plain_fallback: &str)
    where
        F: FnOnce(&Console),
    {
        let console = self.lock_inner();
        if self.enabled {
            render_op(&console);
        } else {
            console.print_plain(plain_fallback);
        }
    }

    /// Print a renderable with a sanitized untrusted plain-text fallback.
    pub fn render_or_untrusted<F>(&self, render_op: F, plain_fallback: &str)
    where
        F: FnOnce(&Console),
    {
        let console = self.lock_inner();
        if self.enabled {
            render_op(&console);
        } else {
            let safe = UntrustedDisplayText::new(plain_fallback);
            console.print_plain(safe.as_str());
        }
    }

    // ─────────────────────────────────────────────────
    // Convenience Methods
    // ─────────────────────────────────────────────────

    /// Print a horizontal rule with an optional trusted title.
    ///
    /// Use [`Self::rule_untrusted`] for an untrusted title.
    pub fn rule(&self, title: Option<&str>) {
        let console = self.lock_inner();
        if self.enabled {
            match title {
                Some(t) => console
                    .print_renderable(&Rule::with_title(t).style(self.theme.border_style.clone())),
                None => {
                    console.print_renderable(&Rule::new().style(self.theme.border_style.clone()))
                }
            }
        } else {
            let fallback =
                title.map_or_else(|| "---".to_string(), |title| format!("--- {title} ---"));
            console.print_plain(&fallback);
        }
    }

    /// Print a horizontal rule after sanitizing an untrusted title.
    pub fn rule_untrusted(&self, title: &str) {
        let safe = UntrustedDisplayText::new(title);
        self.rule(Some(safe.as_str()));
    }

    /// Print a blank line.
    pub fn newline(&self) {
        self.lock_inner().print_plain("");
    }

    /// Print trusted text with a specific style.
    ///
    /// Use [`Self::print_untrusted_styled`] for an untrusted value.
    pub fn print_styled(&self, text: &str, style: Style) {
        let console = self.lock_inner();
        if self.enabled {
            console.print_styled(text, style);
        } else {
            console.print_plain(text);
        }
    }

    /// Sanitize an untrusted value before printing it with a trusted style.
    pub fn print_untrusted_styled(&self, text: &str, style: Style) {
        let safe = UntrustedDisplayText::new(text);
        self.print_styled(safe.as_str(), style);
    }

    /// Print a table with a trusted plain fallback.
    ///
    /// Use [`Self::print_table_untrusted`] when the fallback is untrusted.
    pub fn print_table(&self, table: &Table, plain_fallback: &str) {
        let console = self.lock_inner();
        if self.enabled {
            console.print_renderable(table);
        } else {
            console.print_plain(plain_fallback);
        }
    }

    /// Print a table with a sanitized untrusted plain fallback.
    pub fn print_table_untrusted(&self, table: &Table, plain_fallback: &str) {
        let safe = UntrustedDisplayText::new(plain_fallback);
        self.print_table(table, safe.as_str());
    }

    /// Print a panel with a trusted plain fallback.
    ///
    /// Use [`Self::print_panel_untrusted`] when the fallback is untrusted.
    pub fn print_panel(&self, panel: &Panel, plain_fallback: &str) {
        let console = self.lock_inner();
        if self.enabled {
            console.print_renderable(panel);
        } else {
            console.print_plain(plain_fallback);
        }
    }

    /// Print a panel with a sanitized untrusted plain fallback.
    pub fn print_panel_untrusted(&self, panel: &Panel, plain_fallback: &str) {
        let safe = UntrustedDisplayText::new(plain_fallback);
        self.print_panel(panel, safe.as_str());
    }
}

impl Default for FastMcpConsole {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────
// Global Console Accessor
// ─────────────────────────────────────────────────────────

static CONSOLE: OnceLock<FastMcpConsole> = OnceLock::new();

/// Get the global FastMCP console instance.
///
/// # Example
///
/// ```rust,ignore
/// let console = fastmcp_console::console::console();
/// console.print("Hello from global console");
/// ```
#[must_use]
pub fn console() -> &'static FastMcpConsole {
    CONSOLE.get_or_init(FastMcpConsole::new)
}

/// Initialize the global console with specific settings.
///
/// Must be called before any output; returns error if already initialized.
///
/// # Example
///
/// ```rust,ignore
/// use fastmcp_console::console::init_console;
///
/// init_console(false).expect("console already initialized");
/// ```
pub fn init_console(enabled: bool) -> Result<(), &'static str> {
    CONSOLE
        .set(FastMcpConsole::with_enabled(enabled))
        .map_err(|_| "Console already initialized")
}

// ─────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────

/// Strip markup tags from text (for plain output).
///
/// Handles escaped brackets (`[[` -> `[`, `\\[` -> `[`, `\\]` -> `]`) and strips valid tags (`[...]`).
#[must_use]
pub fn strip_markup(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                // Rich uses backslash escaping for literal brackets. Preserve those for plain output.
                if let Some(next) = chars.peek().copied() {
                    if next == '[' || next == ']' || next == '\\' {
                        out.push(next);
                        chars.next();
                    } else {
                        out.push('\\');
                    }
                } else {
                    out.push('\\');
                }
            }
            '[' => {
                // Check for escaped bracket [[
                if let Some('[') = chars.peek() {
                    out.push('[');
                    chars.next(); // Consume the second [
                } else {
                    // It's a tag start, skip until ]
                    // Note: This is a simple skippper; it doesn't handle nested brackets
                    // or quoted strings inside tags, but covers standard style tags.
                    for c in chars.by_ref() {
                        if c == ']' {
                            break;
                        }
                    }
                }
            }
            _ => out.push(ch),
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Debug)]
    struct SharedWriter {
        buf: Arc<Mutex<Vec<u8>>>,
    }

    impl SharedWriter {
        fn new() -> (Self, Arc<Mutex<Vec<u8>>>) {
            let buf = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    buf: Arc::clone(&buf),
                },
                buf,
            )
        }
    }

    impl Write for SharedWriter {
        fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
            if let Ok(mut guard) = self.buf.lock() {
                guard.extend_from_slice(input);
            }
            Ok(input.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_strip_markup_simple() {
        assert_eq!(strip_markup("[bold]Hello[/]"), "Hello");
    }

    #[test]
    fn test_strip_markup_nested() {
        assert_eq!(strip_markup("[bold][red]Error[/][/]"), "Error");
    }

    #[test]
    fn test_strip_markup_multiple_tags() {
        assert_eq!(
            strip_markup("[green]✓[/] Success [dim](100ms)[/]"),
            "✓ Success (100ms)"
        );
    }

    #[test]
    fn test_strip_markup_no_tags() {
        assert_eq!(strip_markup("Plain text"), "Plain text");
    }

    #[test]
    fn test_strip_markup_empty() {
        assert_eq!(strip_markup(""), "");
    }

    #[test]
    fn test_strip_markup_only_tags() {
        assert_eq!(strip_markup("[bold][/]"), "");
    }

    #[test]
    fn test_strip_markup_preserves_unicode() {
        assert_eq!(strip_markup("[info]⚡ Fast[/]"), "⚡ Fast");
    }

    #[test]
    fn test_strip_markup_preserves_backslash_escaped_brackets() {
        assert_eq!(
            strip_markup(r"tools/list \[OK\] 12ms"),
            "tools/list [OK] 12ms"
        );
        assert_eq!(strip_markup(r"\[x\]"), "[x]");
        assert_eq!(strip_markup(r"\\[bold]x[/]"), r"\x");
    }

    #[test]
    fn test_strip_markup_double_bracket_escape() {
        assert_eq!(strip_markup("[[literal]]"), "[literal]]");
    }

    #[test]
    fn test_console_with_enabled_true() {
        let console = FastMcpConsole::with_enabled(true);
        assert!(console.is_rich());
    }

    #[test]
    fn test_console_with_enabled_false() {
        let console = FastMcpConsole::with_enabled(false);
        assert!(!console.is_rich());
    }

    #[test]
    fn test_console_theme_access() {
        let console = FastMcpConsole::with_enabled(false);
        let theme = console.theme();
        // Verify theme is accessible
        assert_eq!(theme.primary.triplet.map(|tr| tr.blue), Some(255));
    }

    #[test]
    fn test_console_dimensions_default() {
        let console = FastMcpConsole::with_enabled(false);
        // Non-TTY should return defaults
        assert!(console.width() > 0);
        assert!(console.height() > 0);
    }

    #[test]
    fn test_with_writer_print_and_print_plain_paths() {
        let (writer, captured) = SharedWriter::new();
        let console = FastMcpConsole::with_writer(writer, true);

        console.print("[bold]Hello[/]");
        console.print_plain("[literal]");

        let output = String::from_utf8(captured.lock().expect("writer lock poisoned").clone())
            .unwrap_or_default();
        assert!(output.contains("Hello"));
        assert!(output.contains("[literal]"));
        assert!(!output.contains("\\[literal]"));
    }

    #[test]
    fn bounded_rich_text_keeps_markup_escaped_after_backslash_runs() {
        let (writer, captured) = SharedWriter::new();
        let console = FastMcpConsole::with_writer(writer, true);

        let hostile_values = [
            r"\[bold]FORGED[/]",
            r"\\[bold]FORGED[/]",
            r"\\\[bold]FORGED[/]",
        ];
        for hostile in hostile_values {
            let safe = bounded_rich_text(hostile, 128);
            console.print(&format!("[cyan]{safe}[/]"));
        }
        let windows_path = r"C:\tmp\fastmcp\config.json";
        console.print(&format!(
            "[cyan]{}[/]",
            bounded_rich_text(windows_path, 128)
        ));

        let output = captured
            .lock()
            .expect("rich parity output lock poisoned")
            .clone();
        let plain = String::from_utf8(strip_ansi_escapes::strip(&output))
            .expect("rich parity output must be UTF-8");
        assert_eq!(
            plain.matches("[bold]FORGED[/]").count(),
            hostile_values.len(),
            "attacker markup became active: {plain:?}"
        );
        for expected in [
            hostile_values[0],
            hostile_values[1],
            hostile_values[2],
            windows_path,
        ] {
            assert!(
                plain.lines().any(|line| line == expected),
                "rich escaping changed benign text or slash count: expected {expected:?}, got {plain:?}"
            );
        }
    }

    #[test]
    fn bounded_rich_fragments_preserve_trailing_slashes_before_trusted_tags() {
        let (writer, captured) = SharedWriter::new();
        let console = FastMcpConsole::with_writer(writer, true);

        for trailing_slashes in 1..=3 {
            let source = format!("plain{}", "\\".repeat(trailing_slashes));
            let safe = bounded_rich_fragment(&source, 128);
            console.print(&format!("[cyan]{safe}[/]"));

            let redacted_source = format!("token=private {}", "\\".repeat(trailing_slashes));
            let safe = bounded_redacted_rich_fragment(&redacted_source, 128);
            console.print(&format!("[cyan]{safe}[/]"));
        }

        let output = captured
            .lock()
            .expect("rich fragment output lock poisoned")
            .clone();
        let plain = String::from_utf8(strip_ansi_escapes::strip(&output))
            .expect("rich fragment output must be UTF-8");
        let lines: Vec<&str> = plain.lines().collect();
        assert_eq!(lines.len(), 6, "unexpected rendered output: {plain:?}");
        for trailing_slashes in 1..=3 {
            assert_eq!(
                lines[(trailing_slashes - 1) * 2],
                format!("plain{}", "\\".repeat(trailing_slashes))
            );
            assert_eq!(
                lines[(trailing_slashes - 1) * 2 + 1],
                format!("token=[REDACTED] {}", "\\".repeat(trailing_slashes))
            );
        }

        assert_eq!(bounded_rich_text(r"standalone\", 128), r"standalone\");
    }

    #[test]
    fn print_plain_never_activates_markup_after_backslash_runs() {
        let (writer, captured) = SharedWriter::new();
        let console = FastMcpConsole::with_writer(writer, true);

        for hostile in [
            r"\[link=https://example.invalid]click[/link]",
            r"\\[link=https://example.invalid]click[/link]",
            r"\\\[link=https://example.invalid]click[/link]",
        ] {
            console.print_plain(hostile);
        }

        let output = captured
            .lock()
            .expect("plain markup output lock poisoned")
            .clone();
        assert!(
            !output
                .windows(b"\x1b]8;;".len())
                .any(|window| window == b"\x1b]8;;"),
            "plain output activated a terminal hyperlink: {output:?}"
        );
        let plain = String::from_utf8(strip_ansi_escapes::strip(&output))
            .expect("plain markup output must be UTF-8");
        for expected in [
            r"\[link=https://example.invalid]click[/link]",
            r"\\[link=https://example.invalid]click[/link]",
            r"\\\[link=https://example.invalid]click[/link]",
        ] {
            assert!(
                plain.lines().any(|line| line == expected),
                "output: {plain:?}"
            );
        }
    }

    fn hostile_untrusted_console_text() -> String {
        format!(
            "auth=secret-canary\r\nFORGED\u{1b}]52;c;clipboard-canary\u{7}\u{202e}\u{115f}{}TAIL_CANARY",
            "x".repeat(10_000)
        )
    }

    fn assert_untrusted_console_text_is_safe(output: &[u8]) {
        assert!(
            !output
                .windows(b"\x1b]52;".len())
                .any(|window| window == b"\x1b]52;"),
            "untrusted OSC 52 sequence reached the terminal: {output:?}"
        );
        let plain = String::from_utf8(strip_ansi_escapes::strip(output))
            .expect("sanitized console output must be UTF-8");
        assert!(plain.contains("auth=[REDACTED]"), "output: {plain:?}");
        assert!(plain.contains("\\r\\n"), "output: {plain:?}");
        assert!(plain.contains("\\u{1b}"), "output: {plain:?}");
        assert!(plain.contains("\\u{7}"), "output: {plain:?}");
        assert!(plain.contains("\\u{202e}"), "output: {plain:?}");
        assert!(plain.contains("\\u{115f}"), "output: {plain:?}");
        assert!(plain.contains("..."), "output: {plain:?}");
        assert!(!plain.contains("secret-canary"), "output: {plain:?}");
        assert!(!plain.contains("TAIL_CANARY"), "output: {plain:?}");
        assert!(!plain.lines().any(|line| line == "FORGED"));
    }

    #[test]
    fn untrusted_display_text_is_redacted_bounded_and_single_line() {
        let safe = UntrustedDisplayText::new(&hostile_untrusted_console_text());
        assert!(safe.as_str().chars().count() <= DEFAULT_TERMINAL_FIELD_MAX_CHARS);
        assert!(
            !safe
                .as_str()
                .chars()
                .any(|character| matches!(character, '\r' | '\n'))
        );
        assert!(!safe.as_str().chars().any(terminal_text_is_unsafe));
        assert!(safe.as_str().contains("auth=[REDACTED]"));
        assert!(safe.as_str().ends_with("..."));
    }

    #[test]
    fn public_untrusted_output_paths_are_safe_in_plain_mode() {
        let (writer, captured) = SharedWriter::new();
        let console = FastMcpConsole::with_writer(writer, false);
        let hostile = hostile_untrusted_console_text();
        let table = Table::new().with_column(Column::new("A"));
        let panel = Panel::from_text("trusted panel");

        console.print_untrusted(&hostile);
        console.print_untrusted_styled(&hostile, Style::new().bold());
        console.rule_untrusted(&hostile);
        console.render_or_untrusted(|_| panic!("plain fallback expected"), &hostile);
        console.print_table_untrusted(&table, &hostile);
        console.print_panel_untrusted(&panel, &hostile);

        let output = captured.lock().expect("plain output lock poisoned").clone();
        assert_untrusted_console_text_is_safe(&output);
        assert_eq!(
            String::from_utf8(output)
                .expect("plain output must be UTF-8")
                .matches("auth=[REDACTED]")
                .count(),
            6
        );
    }

    #[test]
    fn public_untrusted_output_paths_are_safe_in_rich_mode() {
        let (writer, captured) = SharedWriter::new();
        let console = FastMcpConsole::with_writer(writer, true);
        let hostile = hostile_untrusted_console_text();

        console.print_untrusted(&hostile);
        console.print_untrusted_styled(&hostile, Style::new().bold());
        console.rule_untrusted(&hostile);

        let output = captured.lock().expect("rich output lock poisoned").clone();
        assert_untrusted_console_text_is_safe(&output);
        let plain = String::from_utf8(strip_ansi_escapes::strip(&output))
            .expect("rich output must be UTF-8 after ANSI stripping");
        assert_eq!(plain.matches("auth=[REDACTED]").count(), 3);
    }

    #[test]
    fn credential_key_matching_handles_hostile_mixed_case() {
        for key in [
            "AuTh",
            "PassWord",
            "AcCeSs_ToKeN",
            "githubToken",
            "sessionToken",
            "dbPassword",
            "openaiApiKey",
            "credential",
            "passphrase",
            "X-Amz-Credential",
            "X-Amz-Signature",
            "aws_access_key_id",
        ] {
            assert!(is_credential_key(key), "missed credential key {key}");
        }
        for key in [
            "authentication",
            "tokenizer",
            "accessTokenCount",
            "tokenHint",
            "tokenLength",
            "tokenName",
            "tokenPolicy",
            "tokenType",
            "apiKeyName",
            "clientSecretHint",
            "codeVerifierLength",
            "cookiePolicy",
            "idTokenType",
            "passwordless",
            "refreshTokenCount",
            "secretHint",
            "credentialsCount",
            "signatureAlgorithm",
            "signatureVersion",
        ] {
            assert!(!is_credential_key(key), "over-redacted benign key {key}");
        }
        assert!(is_credential_key(
            &"x".repeat(CREDENTIAL_KEY_SCAN_MAX_CHARS + 1)
        ));
    }

    #[test]
    fn terminal_sanitizers_escape_zero_width_spoofing_markers() {
        let unsafe_characters = [
            '\u{115f}',
            '\u{1160}',
            '\u{17b4}',
            '\u{17b5}',
            '\u{180b}',
            '\u{180e}',
            '\u{200b}',
            '\u{200c}',
            '\u{200d}',
            '\u{2060}',
            '\u{3164}',
            '\u{fe0f}',
            '\u{feff}',
            '\u{ffa0}',
            '\u{fff0}',
            '\u{1bca0}',
            '\u{1d173}',
            '\u{e0001}',
            '\u{e0080}',
            '\u{e0100}',
            '\u{e01f0}',
            '\u{e0fff}',
        ];
        let hostile = format!(
            "a{}b",
            unsafe_characters.iter().copied().collect::<String>()
        );

        for rendered in [
            bounded_redacted_terminal_text(&hostile, 1_024),
            bounded_redacted_rich_text(&hostile, 1_024),
        ] {
            assert!(!rendered.chars().any(terminal_text_is_unsafe));
            for character in unsafe_characters {
                let escaped = character.escape_default().collect::<String>();
                assert!(rendered.contains(&escaped), "missing {escaped}: {rendered}");
            }
        }
    }

    #[test]
    fn free_text_redaction_consumes_complete_authorization_schemes() {
        let text = concat!(
            "Authorization: Basic Zm9v OmJhcg==\n",
            "AuTh: Digest username=\"Mufasa\", realm=\"private\", ",
            "uri=\"/private#fragment\", nonce=\"abc\", response=\"deadbeef\"\n",
            "CoOkIe: session=secret; csrf=also-secret\n",
            "auth=Bearer query-secret&mode=read\n",
            "auth=Digest username=\"u\", uri=\"/a&b\", response=\"digest-secret\"&mode=write\n",
            "next=visible"
        );
        let redacted = redact_free_text_credentials_with(text, "<redacted>");

        assert_eq!(
            redacted,
            concat!(
                "Authorization: Basic <redacted>\n",
                "AuTh: Digest <redacted>\n",
                "CoOkIe: <redacted>\n",
                "auth=Bearer <redacted>&mode=read\n",
                "auth=Digest <redacted>&mode=write\n",
                "next=visible"
            )
        );
        for secret in [
            "Zm9v",
            "OmJhcg",
            "Mufasa",
            "private",
            "fragment",
            "deadbeef",
            "query-secret",
            "digest-secret",
            "also-secret",
        ] {
            assert!(!redacted.contains(secret), "leaked {secret}: {redacted}");
        }

        assert_eq!(
            redact_free_text_credentials("token=wrapper-secret"),
            "token=[REDACTED]"
        );
    }

    #[test]
    fn standalone_bearer_marker_prefix_cannot_bypass_redaction() {
        assert_eq!(
            redact_free_text_credentials_with("Bearer <redacted>ACTUAL-SECRET", "<redacted>"),
            "Bearer <redacted>"
        );
        assert_eq!(
            redact_free_text_credentials("Bearer [REDACTED]ACTUAL-SECRET"),
            "Bearer [REDACTED]"
        );
        assert_eq!(
            redact_free_text_credentials("Bearer [REDACTED]"),
            "Bearer [REDACTED]"
        );
    }

    #[test]
    fn free_text_redaction_handles_namespaced_and_singular_keys() {
        let text = concat!(
            "githubToken=ghp_private sessionToken: session-private ",
            "dbPassword=\"correct horse battery staple\" ",
            "openaiApiKey='sk-private' credential=credential-private ",
            "passphrase: 'phrase private' ",
            "authentication=enabled tokenizer=cl100k passwordless=true"
        );
        let redacted = redact_free_text_credentials(text);

        for secret in [
            "ghp_private",
            "session-private",
            "correct horse battery staple",
            "sk-private",
            "credential-private",
            "phrase private",
        ] {
            assert!(!redacted.contains(secret), "leaked {secret}: {redacted}");
        }
        assert_eq!(redacted.matches(REDACTED_VALUE).count(), 6);
        assert!(redacted.contains("authentication=enabled"));
        assert!(redacted.contains("tokenizer=cl100k"));
        assert!(redacted.contains("passwordless=true"));
    }

    #[test]
    fn free_text_redaction_handles_uri_userinfo_and_aws_signed_queries() {
        let text = concat!(
            "GET https://alice:s3cr3t@example.com/private?",
            "X-Amz-Credential=AKIA_PRIVATE%2F20260802%2Fus-east-1&",
            "X-Amz-Signature=deadbeef&",
            "aws_access_key_id=AKIA_OTHER&mode=read"
        );
        let redacted = redact_free_text_credentials(text);

        assert_eq!(
            redacted,
            concat!(
                "GET https://[REDACTED]@example.com/private?",
                "X-Amz-Credential=[REDACTED]&",
                "X-Amz-Signature=[REDACTED]&",
                "aws_access_key_id=[REDACTED]&mode=read"
            )
        );
        for secret in ["alice", "s3cr3t", "AKIA_PRIVATE", "deadbeef", "AKIA_OTHER"] {
            assert!(!redacted.contains(secret), "leaked {secret}: {redacted}");
        }
    }

    #[test]
    fn free_text_redaction_is_unicode_safe_and_bounded_callers_can_truncate() {
        let text = format!(
            "prefix 🔑 githubToken={} suffix authentication=visible",
            "s".repeat(16_384)
        );
        let redacted = redact_free_text_credentials(&text);
        assert!(redacted.contains("🔑 githubToken=[REDACTED]"));
        assert!(redacted.contains("authentication=visible"));
        assert!(!redacted.contains(&"s".repeat(512)));

        let bounded = bounded_redacted_terminal_text(&text, 80);
        assert!(bounded.chars().count() <= 80);
    }

    #[test]
    fn test_render_and_convenience_methods_in_rich_mode() {
        let (writer, captured) = SharedWriter::new();
        let console = FastMcpConsole::with_writer(writer, true);

        let mut table = Table::new()
            .with_column(Column::new("A"))
            .with_column(Column::new("B"));
        table.add_row(Row::new(vec![Cell::new("1"), Cell::new("2")]));
        let panel = Panel::from_text("Panel body");

        console.rule(Some("Section"));
        console.rule(None);
        console.print_styled("Styled", Style::new().bold());
        console.print_table(&table, "table fallback");
        console.print_panel(&panel, "panel fallback");
        console.render(&Rule::new());

        let mut called = false;
        console.render_or(
            |c| {
                called = true;
                c.print("render_or rich");
            },
            "render_or fallback",
        );
        assert!(called);

        let output = String::from_utf8(captured.lock().expect("writer lock poisoned").clone())
            .unwrap_or_default();
        assert!(output.contains("Section"));
        assert!(output.contains("Styled"));
        assert!(output.contains("Panel body"));
        assert!(output.contains("render_or rich"));
    }

    // =========================================================================
    // Additional coverage tests (bd-m32k)
    // =========================================================================

    #[test]
    fn strip_markup_trailing_backslash() {
        // Backslash at end of string with no following char
        assert_eq!(strip_markup("path\\"), "path\\");
    }

    #[test]
    fn strip_markup_backslash_non_special() {
        // Backslash followed by a char that is NOT [ ] or \
        assert_eq!(strip_markup("line\\n break"), "line\\n break");
    }

    #[test]
    fn strip_markup_backslash_backslash_escape() {
        // Double backslash → single backslash
        assert_eq!(strip_markup("a\\\\b"), "a\\b");
    }

    #[test]
    fn strip_markup_unclosed_tag() {
        // Opening bracket with no closing bracket — consumes rest of string
        assert_eq!(strip_markup("hello [bold no close"), "hello ");
    }

    #[test]
    fn with_writer_plain_mode() {
        let (writer, captured) = SharedWriter::new();
        let console = FastMcpConsole::with_writer(writer, false);

        assert!(!console.is_rich());
        console.print_plain("[literal]");

        let output = String::from_utf8(captured.lock().unwrap().clone()).unwrap_or_default();
        assert_eq!(output, "[literal]\n");
    }

    #[test]
    fn console_default_impl() {
        // Default should not panic and should produce a valid console
        let console = FastMcpConsole::default();
        // Width/height should return sensible values
        assert!(console.width() > 0);
        assert!(console.height() > 0);
    }

    #[test]
    fn disabled_mode_routes_every_output_path_through_configured_writer() {
        let (writer, captured) = SharedWriter::new();
        let console = FastMcpConsole::with_writer(writer, false);
        let table = Table::new().with_column(Column::new("A"));
        let panel = Panel::from_text("panel");

        console.print("[bold]Hello[/]");
        console.print_plain("plain");
        console.render(&Rule::new());
        console.rule(Some("Title"));
        console.rule(None);
        console.newline();
        console.print_styled("styled", Style::new());
        console.print_table(&table, "table fallback");
        console.print_panel(&panel, "panel fallback");

        let mut called = false;
        console.render_or(
            |_| {
                called = true;
            },
            "fallback",
        );
        assert!(!called);

        let output = String::from_utf8(captured.lock().unwrap().clone()).unwrap_or_default();
        for expected in [
            "Hello",
            "plain",
            "[Complex Output]",
            "--- Title ---",
            "styled",
            "table fallback",
            "panel fallback",
            "fallback",
        ] {
            assert!(
                output.contains(expected),
                "missing {expected:?} from configured writer output: {output:?}"
            );
        }
        assert!(!output.contains("[bold]"));
    }
}
