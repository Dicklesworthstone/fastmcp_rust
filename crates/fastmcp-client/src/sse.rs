//! Bounded WHATWG event-stream parsing for the modern HTTP client.
//!
//! HTTP-03 requires the client's SSE dialect to be frozen to the WHATWG
//! event-stream processing algorithm, independent of input chunking, rather
//! than delegated to an implementation-dependent event-source library. This
//! module owns that dialect:
//!
//! - One streaming Encoding Standard `UTF-8 decode` pass in replacement mode
//!   across all chunks, stripping at most one leading UTF-8 BOM; strict
//!   UTF-8-or-fail decoding is never applied on this lane.
//! - CRLF, bare LF, and bare CR line terminators, invariant across chunk
//!   boundaries.
//! - Fields split at the first colon with at most one immediately following
//!   U+0020 removed; `data`, `data:`, and `data: ` behave exactly as the
//!   standard prescribes. One LF is appended per data field, multiple data
//!   lines join in order, and exactly the final appended LF is removed at
//!   dispatch.
//! - A blank line with no `data` field and comment lines beginning with `:`
//!   produce no MCP message. A blank line after one or more empty `data`
//!   fields dispatches an empty payload (which the MCP JSON decoder then
//!   rejects); the two cases are never conflated.
//! - `event`, `id`, `retry`, and unknown fields are parsed for bounded line
//!   framing but carry no MCP routing, retry, resumption, or cache
//!   semantics: no ID is retained, no reconnect delay changes, and no
//!   decoder is selected from `event`.
//! - At end of stream, an unterminated pending event is discarded per the
//!   event-stream algorithm; a blank line is never synthesized.
//! - Raw-octet and replacement-expanded decoded-text budgets are counted
//!   independently against the same line/event ceilings, and comment-only
//!   keepalive traffic is bounded. On any refusal the parser releases its
//!   buffered memory and refuses further input.
//!
//! This parser assembles event payloads only. JSON-RPC admission of each
//! dispatched payload (exactly one bounded object of an allowed direction)
//! belongs to the protocol layer above, which must feed SSE payloads
//! through its own admission and must never route direct JSON responses
//! through this replacement-mode lane.

use core::fmt;

/// The UTF-8 byte-order mark this lane strips at most once, at stream start.
const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

/// Explicit, caller-supplied bounds for one SSE response stream.
///
/// There is deliberately no `Default`: the frozen numeric ceilings belong to
/// the central bounds package and must be wired in explicitly by the
/// integration layer, never assumed ambiently by this parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SseLimits {
    line_bytes: usize,
    event_bytes: usize,
    keepalive_lines: usize,
}

impl SseLimits {
    /// Constructs bounds. Every ceiling must be nonzero; a zero bound would
    /// make the parser silently reject all input rather than fail closed at
    /// configuration time.
    #[must_use]
    pub const fn new(
        max_line_bytes: usize,
        max_event_bytes: usize,
        max_keepalive_lines: usize,
    ) -> Option<Self> {
        if max_line_bytes == 0 || max_event_bytes == 0 || max_keepalive_lines == 0 {
            return None;
        }
        Some(Self {
            line_bytes: max_line_bytes,
            event_bytes: max_event_bytes,
            keepalive_lines: max_keepalive_lines,
        })
    }

    /// Maximum bytes in one line, enforced independently on raw octets and
    /// on replacement-decoded text.
    #[must_use]
    pub const fn max_line_bytes(&self) -> usize {
        self.line_bytes
    }

    /// Maximum bytes in one assembled event, enforced independently on the
    /// raw octets of its `data` lines and on the decoded data buffer.
    #[must_use]
    pub const fn max_event_bytes(&self) -> usize {
        self.event_bytes
    }

    /// Maximum consecutive non-dispatching lines (comments, inert fields,
    /// blank no-data lines) between dispatched events.
    #[must_use]
    pub const fn max_keepalive_lines(&self) -> usize {
        self.keepalive_lines
    }
}

/// What the stream left behind when it ended.
///
/// The caller uses this to report missing-final-response/stream termination;
/// the parser itself never synthesizes a blank line or dispatches a partial
/// event at end of stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SseEndOfStream {
    /// A pending event had accumulated `data` that was discarded unsent.
    pub discarded_pending_event: bool,
    /// An unterminated final line was discarded undelivered.
    pub discarded_partial_line: bool,
}

/// Typed refusals raised by the bounded parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SseParseError {
    /// One line exceeded the raw-octet or decoded-text line ceiling.
    LineTooLong {
        /// The configured line ceiling in bytes.
        limit_bytes: usize,
    },
    /// One assembled event exceeded the raw-octet or decoded-text ceiling.
    EventTooLarge {
        /// The configured event ceiling in bytes.
        limit_bytes: usize,
    },
    /// Too many consecutive non-dispatching lines arrived between events.
    KeepaliveFlood {
        /// The configured consecutive non-dispatching line ceiling.
        limit_lines: usize,
    },
    /// The parser already refused earlier input and holds no state.
    Poisoned,
}

/// The result of incrementally handing one dispatched SSE payload to its
/// caller.
///
/// The parser keeps parsing and allocation bounded independently from the
/// integration's pending-event budget. A consumer refusal still poisons the
/// parser so the owning response stream can release both sides together.
#[derive(Debug)]
pub(crate) enum SsePushError<E> {
    /// The event-stream wire syntax or parser-local limits were refused.
    Parse(SseParseError),
    /// The caller refused one individual dispatched payload.
    Consumer(E),
}

impl fmt::Display for SseParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LineTooLong { limit_bytes } => {
                write!(formatter, "SSE line exceeds {limit_bytes} bytes")
            }
            Self::EventTooLarge { limit_bytes } => {
                write!(formatter, "SSE event exceeds {limit_bytes} bytes")
            }
            Self::KeepaliveFlood { limit_lines } => {
                write!(
                    formatter,
                    "SSE stream exceeds {limit_lines} consecutive non-dispatching lines"
                )
            }
            Self::Poisoned => formatter.write_str("SSE parser already refused earlier input"),
        }
    }
}

impl std::error::Error for SseParseError {}

/// A bounded, chunk-invariant WHATWG event-stream parser.
///
/// Feed response-body chunks through [`Self::push`] and terminate with
/// [`Self::finish`]. Dispatched payloads are the assembled `data` values in
/// stream order. After any refusal, buffered memory is released and every
/// further call reports [`SseParseError::Poisoned`].
#[derive(Debug)]
pub struct BoundedSseParser {
    limits: SseLimits,
    /// Raw octets of the current, still-unterminated line.
    raw_line: Vec<u8>,
    /// A CR terminator was just consumed; one immediately following LF is
    /// part of the same terminator.
    pending_cr: bool,
    /// No line has been decoded yet, so one leading BOM may still be
    /// stripped.
    bom_window_open: bool,
    /// The WHATWG data buffer: one appended LF per data field.
    data: String,
    /// Raw octets contributed by the current event's `data` lines.
    event_raw_bytes: usize,
    /// Consecutive non-dispatching lines since the last dispatch/data line.
    keepalive_lines: usize,
    poisoned: bool,
}

impl BoundedSseParser {
    /// Creates a parser holding no buffered input.
    #[must_use]
    pub fn new(limits: SseLimits) -> Self {
        Self {
            limits,
            raw_line: Vec::new(),
            pending_cr: false,
            bom_window_open: true,
            data: String::new(),
            event_raw_bytes: 0,
            keepalive_lines: 0,
            poisoned: false,
        }
    }

    /// Bytes currently buffered by the parser (pending line plus pending
    /// event data). Zero after a refusal and after every clean dispatch.
    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        self.raw_line.len() + self.data.len()
    }

    /// Consumes one response-body chunk and returns the payloads dispatched
    /// by it, in order.
    ///
    /// # Errors
    ///
    /// Returns the typed bound refusal. After an error the parser has
    /// released its buffers and every subsequent call returns
    /// [`SseParseError::Poisoned`]; the owning response stream must be
    /// closed.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<String>, SseParseError> {
        let mut dispatched = Vec::new();
        self.push_with(chunk, |payload| {
            dispatched.push(payload);
            Ok::<_, ()>(())
        })
        .map_err(|error| match error {
            SsePushError::Parse(error) => error,
            SsePushError::Consumer(()) => unreachable!("infallible SSE event collector refused"),
        })?;
        Ok(dispatched)
    }

    /// Consumes one response-body chunk, dispatching each completed payload
    /// immediately to `accept` instead of first materializing a chunk-wide
    /// collection.
    ///
    /// This lets an integration enforce its aggregate pending count and byte
    /// budgets before a chunk packed with individually valid SSE events can
    /// allocate every payload at once. On either parser or consumer refusal,
    /// parser buffers are released and further input is poisoned.
    pub(crate) fn push_with<E>(
        &mut self,
        chunk: &[u8],
        mut accept: impl FnMut(String) -> Result<(), E>,
    ) -> Result<(), SsePushError<E>> {
        if self.poisoned {
            return Err(SsePushError::Parse(SseParseError::Poisoned));
        }
        for &byte in chunk {
            if self.pending_cr {
                self.pending_cr = false;
                if byte == b'\n' {
                    continue;
                }
            }
            match byte {
                b'\r' => {
                    self.complete_line_with(&mut accept)?;
                    self.pending_cr = true;
                }
                b'\n' => self.complete_line_with(&mut accept)?,
                other => {
                    if self.raw_line.len() >= self.limits.line_bytes {
                        return Err(SsePushError::Parse(self.poison(
                            SseParseError::LineTooLong {
                                limit_bytes: self.limits.line_bytes,
                            },
                        )));
                    }
                    self.raw_line.push(other);
                }
            }
        }
        Ok(())
    }

    /// Terminates the stream, reporting what pending state was discarded.
    ///
    /// Per the event-stream algorithm, an incomplete final event or line is
    /// discarded, never dispatched, and no blank line is synthesized.
    ///
    /// # Errors
    ///
    /// Returns [`SseParseError::Poisoned`] when the stream already refused
    /// earlier input; the discard report would otherwise misstate state the
    /// parser has already released.
    pub fn finish(self) -> Result<SseEndOfStream, SseParseError> {
        if self.poisoned {
            return Err(SseParseError::Poisoned);
        }
        Ok(SseEndOfStream {
            discarded_pending_event: !self.data.is_empty(),
            discarded_partial_line: !self.raw_line.is_empty(),
        })
    }

    fn poison(&mut self, error: SseParseError) -> SseParseError {
        // Release, not merely clear: refused streams must not keep their
        // line/event reservations alive.
        self.raw_line = Vec::new();
        self.data = String::new();
        self.event_raw_bytes = 0;
        self.keepalive_lines = 0;
        self.poisoned = true;
        error
    }

    fn complete_line_with<E>(
        &mut self,
        accept: &mut impl FnMut(String) -> Result<(), E>,
    ) -> Result<(), SsePushError<E>> {
        let mut raw = core::mem::take(&mut self.raw_line);
        if self.bom_window_open {
            self.bom_window_open = false;
            if raw.starts_with(&UTF8_BOM) {
                raw.drain(..UTF8_BOM.len());
            }
        }
        let raw_len = raw.len();
        // Replacement-mode decode. Buffering the complete raw line first
        // makes this identical to a streaming replacement decoder for any
        // chunking: a multi-byte sequence can span chunks only inside one
        // line, and a sequence interrupted by a terminator is invalid in
        // both formulations.
        let line = String::from_utf8_lossy(&raw);
        if line.len() > self.limits.line_bytes {
            // Replacement expansion (U+FFFD is three bytes) counts against
            // the same ceiling as the raw octets, independently.
            return Err(SsePushError::Parse(self.poison(
                SseParseError::LineTooLong {
                    limit_bytes: self.limits.line_bytes,
                },
            )));
        }
        match self.process_line_with(&line, raw_len, accept) {
            Ok(()) => Ok(()),
            Err(SsePushError::Parse(error)) => Err(SsePushError::Parse(self.poison(error))),
            Err(SsePushError::Consumer(error)) => Err(SsePushError::Consumer(error)),
        }
    }

    fn process_line_with<E>(
        &mut self,
        line: &str,
        raw_len: usize,
        accept: &mut impl FnMut(String) -> Result<(), E>,
    ) -> Result<(), SsePushError<E>> {
        if line.is_empty() {
            // Dispatch step. The empty-buffer check precedes trailing-LF
            // removal, so one empty data field ("\n" in the buffer) really
            // dispatches an empty payload while a no-data event dispatches
            // nothing.
            if self.data.is_empty() {
                return self
                    .count_non_dispatching_line()
                    .map_err(SsePushError::Parse);
            }
            let mut payload = core::mem::take(&mut self.data);
            if payload.ends_with('\n') {
                payload.pop();
            }
            self.event_raw_bytes = 0;
            self.keepalive_lines = 0;
            return accept(payload).map_err(|error| {
                self.poison(SseParseError::Poisoned);
                SsePushError::Consumer(error)
            });
        }
        if line.starts_with(':') {
            return self
                .count_non_dispatching_line()
                .map_err(SsePushError::Parse);
        }
        let (field, value) = match line.split_once(':') {
            Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
            None => (line, ""),
        };
        if field == "data" {
            let decoded_after = self
                .data
                .len()
                .saturating_add(value.len())
                .saturating_add(1);
            let raw_after = self.event_raw_bytes.saturating_add(raw_len);
            if decoded_after > self.limits.event_bytes || raw_after > self.limits.event_bytes {
                return Err(SsePushError::Parse(self.poison(
                    SseParseError::EventTooLarge {
                        limit_bytes: self.limits.event_bytes,
                    },
                )));
            }
            self.data.push_str(value);
            self.data.push('\n');
            self.event_raw_bytes = raw_after;
            self.keepalive_lines = 0;
            return Ok(());
        }
        // `event`, `id`, `retry`, and unknown fields: bounded framing only.
        // Deliberately no retained ID, no `Last-Event-ID`, no reconnect
        // delay, no decoder selection — inert fields from standard producers
        // are accepted without reviving removed modern SSE state.
        self.count_non_dispatching_line()
            .map_err(SsePushError::Parse)
    }

    fn count_non_dispatching_line(&mut self) -> Result<(), SseParseError> {
        self.keepalive_lines = self.keepalive_lines.saturating_add(1);
        if self.keepalive_lines > self.limits.keepalive_lines {
            return Err(SseParseError::KeepaliveFlood {
                limit_lines: self.limits.keepalive_lines,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{BoundedSseParser, SseEndOfStream, SseLimits, SseParseError, SsePushError};

    fn generous_limits() -> SseLimits {
        SseLimits::new(4_096, 65_536, 64).expect("nonzero test limits")
    }

    fn parse_all(
        input: &[u8],
        limits: SseLimits,
    ) -> Result<(Vec<String>, SseEndOfStream), SseParseError> {
        let mut parser = BoundedSseParser::new(limits);
        let events = parser.push(input)?;
        let end = parser.finish()?;
        Ok((events, end))
    }

    /// Feeds `input` whole, byte-by-byte, and split at every boundary,
    /// asserting all runs observe identical dispatches and end state.
    fn assert_chunk_invariant(input: &[u8], limits: SseLimits) -> (Vec<String>, SseEndOfStream) {
        let reference = parse_all(input, limits).expect("reference parse succeeds");

        let mut byte_parser = BoundedSseParser::new(limits);
        let mut byte_events = Vec::new();
        for byte in input {
            byte_events.extend(
                byte_parser
                    .push(core::slice::from_ref(byte))
                    .expect("byte-by-byte parse succeeds"),
            );
        }
        let byte_end = byte_parser.finish().expect("byte-by-byte finish succeeds");
        assert_eq!(
            (&byte_events, byte_end),
            (&reference.0, reference.1),
            "byte-by-byte feed must match whole-buffer feed"
        );

        for split in 0..=input.len() {
            let mut parser = BoundedSseParser::new(limits);
            let mut events = parser
                .push(&input[..split])
                .expect("first split half parses");
            events.extend(
                parser
                    .push(&input[split..])
                    .expect("second split half parses"),
            );
            let end = parser.finish().expect("split finish succeeds");
            assert_eq!(
                (&events, end),
                (&reference.0, reference.1),
                "split at byte {split} must match whole-buffer feed"
            );
        }
        reference
    }

    #[test]
    fn dispatches_single_data_event() {
        let (events, end) = assert_chunk_invariant(b"data: hello\n\n", generous_limits());
        assert_eq!(events, ["hello"]);
        assert_eq!(
            end,
            SseEndOfStream {
                discarded_pending_event: false,
                discarded_partial_line: false
            }
        );
    }

    #[test]
    fn data_field_name_variants_match_the_standard() {
        // `data`, `data:`, and `data: ` all contribute one (possibly empty)
        // data line; only one leading space is removed.
        let (events, _) = assert_chunk_invariant(b"data\n\n", generous_limits());
        assert_eq!(events, [""]);
        let (events, _) = assert_chunk_invariant(b"data:\n\n", generous_limits());
        assert_eq!(events, [""]);
        let (events, _) = assert_chunk_invariant(b"data: \n\n", generous_limits());
        assert_eq!(events, [""]);
        let (events, _) = assert_chunk_invariant(b"data:  two spaces\n\n", generous_limits());
        assert_eq!(events, [" two spaces"]);
    }

    #[test]
    fn multiple_data_lines_join_with_inserted_newlines() {
        let (events, _) =
            assert_chunk_invariant(b"data: a\ndata: b\ndata: c\n\n", generous_limits());
        assert_eq!(events, ["a\nb\nc"]);
    }

    #[test]
    fn exactly_one_trailing_inserted_newline_is_removed() {
        // "a" then an empty data line assemble to "a\n\n"; dispatch removes
        // exactly the final appended LF, leaving the interior one.
        let (events, _) = assert_chunk_invariant(b"data: a\ndata:\n\n", generous_limits());
        assert_eq!(events, ["a\n"]);
    }

    #[test]
    fn blank_line_without_data_produces_no_event() {
        let (events, _) = assert_chunk_invariant(b"\n\n\n", generous_limits());
        assert_eq!(events, Vec::<String>::new());
    }

    #[test]
    fn empty_data_event_is_distinct_from_no_data_event() {
        // One empty data field dispatches an empty payload; a blank line
        // alone dispatches nothing. The empty payload later fails MCP JSON
        // admission — the two cases must never be conflated.
        let (events, _) = assert_chunk_invariant(b"\ndata:\n\n\n", generous_limits());
        assert_eq!(events, [""]);
    }

    #[test]
    fn comment_lines_produce_no_event() {
        let (events, _) =
            assert_chunk_invariant(b": keepalive\n: another\ndata: x\n\n", generous_limits());
        assert_eq!(events, ["x"]);
    }

    #[test]
    fn inert_fields_are_parsed_but_carry_no_state() {
        let input: &[u8] = b"event: custom\nid: 7\nretry: 50\nunknown: y\ndata: x\n\nid: 8\n\n";
        let (events, _) = assert_chunk_invariant(input, generous_limits());
        // The id-only block dispatches nothing: no data buffer, no retained
        // last-event-ID, no resumption state anywhere in the API.
        assert_eq!(events, ["x"]);
    }

    #[test]
    fn field_without_colon_is_a_name_with_empty_value() {
        // A bare "event" line is a field named `event` with empty value —
        // inert here — and a bare "data" line contributes an empty data line.
        let (events, _) = assert_chunk_invariant(b"event\ndata: x\n\n", generous_limits());
        assert_eq!(events, ["x"]);
    }

    #[test]
    fn crlf_bare_lf_and_bare_cr_terminate_lines_identically() {
        for input in [
            b"data: a\r\n\r\n".as_slice(),
            b"data: a\n\n".as_slice(),
            b"data: a\r\r".as_slice(),
            b"data: a\r\n\n".as_slice(),
            b"data: a\n\r\n".as_slice(),
        ] {
            let (events, _) = assert_chunk_invariant(input, generous_limits());
            assert_eq!(events, ["a"], "input {input:?}");
        }
    }

    #[test]
    fn leading_bom_is_stripped_exactly_once() {
        let mut input = vec![0xEF, 0xBB, 0xBF];
        input.extend_from_slice(b"data: x\n\n");
        let (events, _) = assert_chunk_invariant(&input, generous_limits());
        assert_eq!(events, ["x"]);
    }

    #[test]
    fn midstream_bom_is_ordinary_content() {
        // A BOM inside a data value survives as U+FEFF content.
        let mut input = b"data: ".to_vec();
        input.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
        input.extend_from_slice(b"x\n\n");
        let (events, _) = assert_chunk_invariant(&input, generous_limits());
        assert_eq!(events, ["\u{FEFF}x"]);

        // A BOM starting the second line makes that line's field name
        // "\u{FEFF}data" — an inert unknown field, not a data field.
        let mut input = b"data: a\n".to_vec();
        input.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
        input.extend_from_slice(b"data: b\n\n");
        let (events, _) = assert_chunk_invariant(&input, generous_limits());
        assert_eq!(events, ["a"]);
    }

    #[test]
    fn malformed_utf8_is_replaced_never_fatal() {
        let (events, _) = assert_chunk_invariant(b"data: \xFF\n\n", generous_limits());
        assert_eq!(events, ["\u{FFFD}"]);

        // A maximal invalid prefix followed by a valid continuation of the
        // line replaces exactly per the shared substitution policy.
        let (events, _) = assert_chunk_invariant(b"data: \xE2\x82ok\n\n", generous_limits());
        assert_eq!(events, ["\u{FFFD}ok"]);
    }

    #[test]
    fn multibyte_sequences_split_across_chunks_survive() {
        // The whole-buffer reference already parses "€"; the split loop in
        // the invariance helper proves every chunk boundary inside the
        // three-byte sequence decodes identically.
        let (events, _) = assert_chunk_invariant("data: €\n\n".as_bytes(), generous_limits());
        assert_eq!(events, ["€"]);
    }

    #[test]
    fn sequence_interrupted_by_terminator_is_replaced_within_its_line() {
        // An incomplete sequence at a line terminator cannot borrow bytes
        // from the next line.
        let (events, _) = assert_chunk_invariant(b"data: \xE2\x82\ndata: x\n\n", generous_limits());
        assert_eq!(events, ["\u{FFFD}\nx"]);
    }

    #[test]
    fn nul_bytes_pass_through_data_values() {
        let (events, _) = assert_chunk_invariant(b"data: a\x00b\n\n", generous_limits());
        assert_eq!(events, ["a\u{0000}b"]);
    }

    #[test]
    fn eof_discards_unterminated_pending_event() {
        let limits = generous_limits();
        let mut parser = BoundedSseParser::new(limits);
        let events = parser.push(b"data: never dispatched\n").expect("parses");
        assert_eq!(events, Vec::<String>::new());
        let end = parser.finish().expect("finish succeeds");
        assert!(end.discarded_pending_event);
        assert!(!end.discarded_partial_line);
    }

    #[test]
    fn eof_discards_unterminated_partial_line() {
        let limits = generous_limits();
        let mut parser = BoundedSseParser::new(limits);
        parser.push(b"data: x\n\ndata: partial").expect("parses");
        let end = parser.finish().expect("finish succeeds");
        assert!(!end.discarded_pending_event);
        assert!(end.discarded_partial_line);
    }

    #[test]
    fn raw_line_bound_is_exact() {
        let limits = SseLimits::new(8, 65_536, 64).expect("limits");
        // "data: xx" is exactly 8 raw bytes — admitted.
        let (events, _) = assert_chunk_invariant(b"data: xx\n\n", limits);
        assert_eq!(events, ["xx"]);

        // One more byte on the line refuses before buffering it.
        let mut parser = BoundedSseParser::new(limits);
        let error = parser.push(b"data: xxx\n\n").expect_err("line too long");
        assert_eq!(error, SseParseError::LineTooLong { limit_bytes: 8 });
        assert_eq!(parser.buffered_bytes(), 0, "refusal releases buffers");
        assert_eq!(
            parser.push(b"data: x\n\n"),
            Err(SseParseError::Poisoned),
            "a refused stream accepts nothing further"
        );
    }

    #[test]
    fn replacement_expansion_counts_against_the_decoded_line_bound() {
        // Nine raw bytes ("data: " plus three invalid octets) decode to
        // fifteen bytes because each invalid octet becomes a three-byte
        // U+FFFD. The raw feed fits a 12-byte ceiling; the decoded text
        // does not — the independent decoded budget must refuse.
        let limits = SseLimits::new(12, 65_536, 64).expect("limits");
        let mut parser = BoundedSseParser::new(limits);
        let error = parser
            .push(b"data: \xFF\xFF\xFF\n\n")
            .expect_err("decoded expansion exceeds the line ceiling");
        assert_eq!(error, SseParseError::LineTooLong { limit_bytes: 12 });
    }

    #[test]
    fn event_bound_is_exact_across_data_lines() {
        // Each "data: abcd" line contributes 10 raw bytes to the event and
        // 5 decoded bytes ("abcd" plus the appended LF). Three lines = 30
        // raw bytes: admitted at a 30-byte ceiling; a fourth line refuses.
        let limits = SseLimits::new(4_096, 30, 64).expect("limits");
        let (events, _) = assert_chunk_invariant(b"data: abcd\ndata: abcd\ndata: abcd\n\n", limits);
        assert_eq!(events, ["abcd\nabcd\nabcd"]);

        let mut parser = BoundedSseParser::new(limits);
        let error = parser
            .push(b"data: abcd\ndata: abcd\ndata: abcd\ndata: abcd\n\n")
            .expect_err("event too large");
        assert_eq!(error, SseParseError::EventTooLarge { limit_bytes: 30 });
        assert_eq!(parser.buffered_bytes(), 0, "refusal releases buffers");
    }

    #[test]
    fn keepalive_flood_is_bounded_and_reset_by_data() {
        let limits = SseLimits::new(4_096, 65_536, 3).expect("limits");
        // Three comments then data: admitted, and the data line resets the
        // consecutive count so the pattern can repeat indefinitely.
        let (events, _) = assert_chunk_invariant(
            b": a\n: b\n: c\ndata: x\n\n: a\n: b\n: c\ndata: y\n\n",
            limits,
        );
        assert_eq!(events, ["x", "y"]);

        // A fourth consecutive non-dispatching line refuses.
        let mut parser = BoundedSseParser::new(limits);
        let error = parser
            .push(b": a\n: b\n: c\n: d\n")
            .expect_err("comment flood");
        assert_eq!(error, SseParseError::KeepaliveFlood { limit_lines: 3 });
    }

    #[test]
    fn dispatch_resets_buffered_bytes() {
        let mut parser = BoundedSseParser::new(generous_limits());
        parser.push(b"data: hello").expect("parses");
        assert!(parser.buffered_bytes() > 0);
        let events = parser.push(b"\n\n").expect("dispatches");
        assert_eq!(events, ["hello"]);
        assert_eq!(parser.buffered_bytes(), 0);
    }

    #[test]
    fn chunk_packed_consumer_overflow_stops_before_materializing_the_tail() {
        // Vary only the number of otherwise identical, individually valid
        // events in one native chunk. The rejecting consumer observes exactly
        // the first overflowing event; later chunk entries are never
        // materialized into payload Strings.
        let accepted = 3_usize;
        let chunk = b"data: x\n\n".repeat(accepted + 2);
        let mut parser = BoundedSseParser::new(generous_limits());
        let mut observed = 0_usize;

        let error = parser
            .push_with(&chunk, |_| {
                observed += 1;
                if observed > accepted { Err(()) } else { Ok(()) }
            })
            .expect_err("the first event beyond the one-variable count limit refuses");

        assert!(matches!(error, SsePushError::Consumer(())));
        assert_eq!(observed, accepted + 1);
        assert_eq!(
            parser.buffered_bytes(),
            0,
            "refusal releases parser buffers"
        );
        assert_eq!(
            parser.push(b"data: later\n\n"),
            Err(SseParseError::Poisoned),
            "a consumer-refused chunk cannot materialize a later tail"
        );
    }

    #[test]
    fn zero_limits_are_rejected_at_construction() {
        assert!(SseLimits::new(0, 1, 1).is_none());
        assert!(SseLimits::new(1, 0, 1).is_none());
        assert!(SseLimits::new(1, 1, 0).is_none());
    }

    #[test]
    fn poisoned_finish_reports_poisoned_not_a_discard_summary() {
        let limits = SseLimits::new(8, 65_536, 64).expect("limits");
        let mut parser = BoundedSseParser::new(limits);
        parser
            .push(b"data: way too long for the line bound\n\n")
            .expect_err("line too long");
        assert_eq!(parser.finish(), Err(SseParseError::Poisoned));
    }

    #[test]
    fn interleaved_events_dispatch_in_stream_order() {
        let input: &[u8] =
            b"data: first\n\n: keepalive\nevent: progress\ndata: second\n\ndata: third\n\n";
        let (events, end) = assert_chunk_invariant(input, generous_limits());
        assert_eq!(events, ["first", "second", "third"]);
        assert!(!end.discarded_pending_event);
    }
}
