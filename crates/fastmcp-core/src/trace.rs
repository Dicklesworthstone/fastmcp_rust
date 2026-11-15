//! Bounded W3C trace metadata admission and independent-field recovery.
//!
//! The grammars follow [Trace Context, sections 3.2–3.3](https://www.w3.org/TR/2021/REC-trace-context-1-20211123/)
//! and [Baggage, section 3.3](https://www.w3.org/TR/2024/CR-baggage-20240530/).
//! The limits are the default OBS-01/LIMIT-01 admission profile. Valid values
//! retain their exact spelling; this module neither decodes baggage nor grants
//! authority to forward it. Outbound propagation needs its own trust policy.
//!
//! Incoming optional telemetry uses [`TraceContext::recover`]: malformed trace
//! metadata never becomes an application-protocol error. Local producers use
//! [`TraceContext::try_from_fields`] to reject malformed field combinations.

use std::fmt;

use serde_json::Value;

/// Maximum encoded bytes retained for a traceparent, including a future suffix.
pub const MAX_TRACEPARENT_BYTES: usize = 4 * 1024;
/// Maximum encoded bytes retained for the complete tracestate field.
pub const MAX_TRACESTATE_BYTES: usize = 512;
/// Maximum tracestate list members, including permitted empty members.
pub const MAX_TRACESTATE_MEMBERS: usize = 32;
/// Maximum encoded bytes retained for the complete baggage field.
pub const MAX_BAGGAGE_BYTES: usize = 8 * 1024;
/// Maximum baggage members, including repeated keys.
pub const MAX_BAGGAGE_MEMBERS: usize = 64;

/// Fixed diagnostics for locally constructed trace metadata. No peer data is
/// retained in an error, its display text, or its debug representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceContextError {
    /// A traceparent violates the known-field or version grammar.
    InvalidTraceparent,
    /// A tracestate violates its key/value grammar or repeats a key.
    InvalidTracestate,
    /// A baggage member or property violates the baggage grammar.
    InvalidBaggage,
    /// A tracestate has no valid companion traceparent.
    OrphanedTracestate,
    /// A traceparent exceeds the local encoded-byte bound.
    TraceparentLimitExceeded,
    /// A tracestate exceeds the local encoded-byte or member bound.
    TracestateLimitExceeded,
    /// Baggage exceeds the local encoded-byte or member bound.
    BaggageLimitExceeded,
}

impl fmt::Display for TraceContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidTraceparent => "invalid traceparent",
            Self::InvalidTracestate => "invalid tracestate",
            Self::InvalidBaggage => "invalid baggage",
            Self::OrphanedTracestate => "tracestate requires a valid traceparent",
            Self::TraceparentLimitExceeded => "traceparent exceeds its admission limit",
            Self::TracestateLimitExceeded => "tracestate exceeds its admission limit",
            Self::BaggageLimitExceeded => "baggage exceeds its admission limit",
        })
    }
}

impl std::error::Error for TraceContextError {}

/// A bounded report of fields removed during receiver recovery.
///
/// Counts describe discarded fields, never attacker-controlled member counts.
/// An invalid traceparent also removes a present tracestate, but baggage is
/// independent. No rejected value or peer-controlled diagnostic is retained.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TraceContextRecovery {
    rejected: u8,
}

impl TraceContextRecovery {
    const TRACEPARENT: u8 = 1;
    const TRACESTATE: u8 = 2;
    const BAGGAGE: u8 = 4;

    /// Whether a present traceparent was discarded.
    pub const fn traceparent_rejected(self) -> bool {
        self.rejected & Self::TRACEPARENT != 0
    }

    /// Whether a present tracestate was discarded, including orphaned state.
    pub const fn tracestate_rejected(self) -> bool {
        self.rejected & Self::TRACESTATE != 0
    }

    /// Whether a present baggage field was discarded in its entirety.
    pub const fn baggage_rejected(self) -> bool {
        self.rejected & Self::BAGGAGE != 0
    }

    /// Number of discarded fields, always between zero and three.
    pub const fn rejected_count(self) -> u8 {
        self.rejected.count_ones() as u8
    }

    /// Whether recovery discarded no fields.
    pub const fn is_empty(self) -> bool {
        self.rejected == 0
    }
}

/// Immutable, syntactically admitted W3C trace metadata.
///
/// Baggage may contain sensitive application data. Debug output therefore
/// reveals field presence only; values are available solely through explicit
/// accessors. Syntax admission is neither authentication nor forwarding consent.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct TraceContext {
    traceparent: Option<String>,
    tracestate: Option<String>,
    baggage: Option<String>,
}

impl fmt::Debug for TraceContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TraceContext")
            .field("has_traceparent", &self.traceparent.is_some())
            .field("has_tracestate", &self.tracestate.is_some())
            .field("has_baggage", &self.baggage.is_some())
            .finish()
    }
}

impl TraceContext {
    /// Admits locally supplied fields without normalizing their spelling.
    ///
    /// Tracestate requires a valid traceparent; baggage does not. All validation
    /// and local admission limits are checked before any field is copied.
    pub fn try_from_fields(
        traceparent: Option<&str>,
        tracestate: Option<&str>,
        baggage: Option<&str>,
    ) -> Result<Self, TraceContextError> {
        if let Some(value) = traceparent {
            validate_traceparent(value)?;
        }
        if let Some(value) = tracestate {
            if traceparent.is_none() {
                return Err(TraceContextError::OrphanedTracestate);
            }
            validate_tracestate(value)?;
        }
        if let Some(value) = baggage {
            validate_baggage(value)?;
        }
        Ok(Self {
            traceparent: traceparent.map(str::to_owned),
            tracestate: tracestate.map(str::to_owned),
            baggage: baggage.map(str::to_owned),
        })
    }

    /// Recovers optional peer metadata using the OBS-01 receiver policy.
    ///
    /// Invalid or non-string traceparent removes itself and its tracestate.
    /// Invalid/orphaned tracestate does not invalidate a valid traceparent.
    /// Baggage is independent and is discarded in full on any malformed member
    /// or local limit failure. The caller can use the bounded report to remove
    /// rejected fields from its effective metadata without changing the MCP
    /// request, notification, result, or error.
    pub fn recover(
        traceparent: Option<&Value>,
        tracestate: Option<&Value>,
        baggage: Option<&Value>,
    ) -> (Self, TraceContextRecovery) {
        let mut report = TraceContextRecovery::default();
        let traceparent = recover_field(
            traceparent,
            validate_traceparent,
            TraceContextRecovery::TRACEPARENT,
            &mut report,
        );
        let tracestate = if traceparent.is_some() {
            recover_field(
                tracestate,
                validate_tracestate,
                TraceContextRecovery::TRACESTATE,
                &mut report,
            )
        } else {
            // Do not inspect orphaned vendor state, even if its grammar is valid.
            if tracestate.is_some() {
                report.rejected |= TraceContextRecovery::TRACESTATE;
            }
            None
        };
        let baggage = recover_field(
            baggage,
            validate_baggage,
            TraceContextRecovery::BAGGAGE,
            &mut report,
        );
        (
            Self {
                traceparent: traceparent.map(str::to_owned),
                tracestate: tracestate.map(str::to_owned),
                baggage: baggage.map(str::to_owned),
            },
            report,
        )
    }

    /// Returns the exact admitted traceparent, including opaque future fields.
    pub fn traceparent(&self) -> Option<&str> {
        self.traceparent.as_deref()
    }

    /// Returns the exact admitted tracestate, including permitted whitespace.
    pub fn tracestate(&self) -> Option<&str> {
        self.tracestate.as_deref()
    }

    /// Returns admitted baggage without decoding, sorting, or merging keys.
    pub fn baggage(&self) -> Option<&str> {
        self.baggage.as_deref()
    }

    /// Whether none of the three fields is present.
    pub const fn is_empty(&self) -> bool {
        self.traceparent.is_none() && self.tracestate.is_none() && self.baggage.is_none()
    }
}

fn recover_field<'a>(
    value: Option<&'a Value>,
    validate: fn(&str) -> Result<(), TraceContextError>,
    rejected_bit: u8,
    report: &mut TraceContextRecovery,
) -> Option<&'a str> {
    let value = value?;
    match value.as_str() {
        Some(value) if validate(value).is_ok() => Some(value),
        _ => {
            report.rejected |= rejected_bit;
            None
        }
    }
}

fn validate_traceparent(value: &str) -> Result<(), TraceContextError> {
    if value.len() > MAX_TRACEPARENT_BYTES {
        return Err(TraceContextError::TraceparentLimitExceeded);
    }
    let bytes = value.as_bytes();
    if bytes.len() < 55
        || !bytes[..2].iter().copied().all(is_lower_hex)
        || &bytes[..2] == b"ff"
        || bytes[2] != b'-'
        || bytes[35] != b'-'
        || bytes[52] != b'-'
        || !bytes[3..35].iter().copied().all(is_lower_hex)
        || bytes[3..35].iter().all(|byte| *byte == b'0')
        || !bytes[36..52].iter().copied().all(is_lower_hex)
        || bytes[36..52].iter().all(|byte| *byte == b'0')
        || !bytes[53..55].iter().copied().all(is_lower_hex)
    {
        return Err(TraceContextError::InvalidTraceparent);
    }
    if &bytes[..2] == b"00" {
        if bytes.len() != 55 {
            return Err(TraceContextError::InvalidTraceparent);
        }
    } else if bytes.len() > 55 && bytes[55] != b'-' {
        return Err(TraceContextError::InvalidTraceparent);
    }
    // An unknown version's suffix is opaque: do not invent a field grammar or
    // require hexadecimal extensions. Keep only the US-ASCII HTTP field-value
    // boundary (visible characters, space, and horizontal tab). Other control
    // characters and non-ASCII text cannot be part of this representation.
    if !bytes
        .iter()
        .all(|byte| matches!(*byte, b'\t' | 0x20..=0x7e))
    {
        return Err(TraceContextError::InvalidTraceparent);
    }
    Ok(())
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

fn trim_ows(value: &str) -> &str {
    value.trim_matches([' ', '\t'])
}

fn validate_tracestate(value: &str) -> Result<(), TraceContextError> {
    if value.len() > MAX_TRACESTATE_BYTES {
        return Err(TraceContextError::TracestateLimitExceeded);
    }
    let mut keys = [""; MAX_TRACESTATE_MEMBERS];
    for (index, member) in value.split(',').enumerate() {
        if index >= MAX_TRACESTATE_MEMBERS {
            return Err(TraceContextError::TracestateLimitExceeded);
        }
        let member = trim_ows(member);
        if member.is_empty() {
            continue;
        }
        let (key, value) = member
            .split_once('=')
            .ok_or(TraceContextError::InvalidTracestate)?;
        if !valid_tracestate_key(key)
            || keys.contains(&key)
            || value.is_empty()
            || value.len() > 256
            || !value
                .bytes()
                .all(|byte| matches!(byte, 0x20..=0x2b | 0x2d..=0x3c | 0x3e..=0x7e))
        {
            return Err(TraceContextError::InvalidTracestate);
        }
        keys[index] = key;
    }
    Ok(())
}

fn valid_tracestate_key(value: &str) -> bool {
    let permitted = |byte: u8| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'_' | b'-' | b'*' | b'/')
    };
    if let Some((tenant, system)) = value.split_once('@') {
        !tenant.is_empty()
            && tenant.len() <= 241
            && (tenant.as_bytes()[0].is_ascii_lowercase() || tenant.as_bytes()[0].is_ascii_digit())
            && tenant.bytes().all(permitted)
            && !system.is_empty()
            && system.len() <= 14
            && system.as_bytes()[0].is_ascii_lowercase()
            && system.bytes().all(permitted)
    } else {
        !value.is_empty()
            && value.len() <= 256
            && value.as_bytes()[0].is_ascii_lowercase()
            && value.bytes().all(permitted)
    }
}

fn validate_baggage(value: &str) -> Result<(), TraceContextError> {
    if value.len() > MAX_BAGGAGE_BYTES {
        return Err(TraceContextError::BaggageLimitExceeded);
    }
    for (index, member) in value.split(',').enumerate() {
        if index >= MAX_BAGGAGE_MEMBERS {
            return Err(TraceContextError::BaggageLimitExceeded);
        }
        let mut parts = member.split(';');
        let (key, value) = parts
            .next()
            .and_then(|part| part.split_once('='))
            .ok_or(TraceContextError::InvalidBaggage)?;
        if !valid_baggage_key(trim_ows(key)) || !valid_baggage_value(trim_ows(value)) {
            return Err(TraceContextError::InvalidBaggage);
        }
        for property in parts {
            let property = trim_ows(property);
            let valid = match property.split_once('=') {
                Some((key, value)) => {
                    valid_baggage_key(trim_ows(key)) && valid_baggage_value(trim_ows(value))
                }
                None => valid_baggage_key(property),
            };
            if !valid {
                return Err(TraceContextError::InvalidBaggage);
            }
        }
    }
    Ok(())
}

fn valid_baggage_key(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn valid_baggage_value(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        if byte == b'%' {
            // The value grammar permits encoded octets, including invalid UTF-8
            // octets. We preserve them; a decoder must apply W3C replacement.
            if !bytes.get(index + 1).is_some_and(u8::is_ascii_hexdigit)
                || !bytes.get(index + 2).is_some_and(u8::is_ascii_hexdigit)
            {
                return false;
            }
            index += 3;
        } else {
            if !matches!(byte, 0x21 | 0x23..=0x2b | 0x2d..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e) {
                return false;
            }
            index += 1;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const PARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    #[test]
    fn obs_01_traceparent_known_fields_and_future_suffix_corpus() {
        for parent in [
            PARENT,
            "00-00000000000000000000000000000001-0000000000000001-00",
            "00-ffffffffffffffffffffffffffffffff-ffffffffffffffff-ff",
            "cc-12345678901234567890123456789012-1234567890123456-01",
            "cc-12345678901234567890123456789012-1234567890123456-09-opaque=Future.Value",
            "01-12345678901234567890123456789012-1234567890123456-01-",
            "fe-12345678901234567890123456789012-1234567890123456-ff-a--b;value with space",
            "01-12345678901234567890123456789012-1234567890123456-01-future\tfield",
        ] {
            let context = TraceContext::try_from_fields(Some(parent), None, None).unwrap();
            assert_eq!(context.traceparent(), Some(parent));
        }
    }

    #[test]
    fn obs_01_traceparent_rejects_one_invalid_known_dimension() {
        for parent in [
            "",
            "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "FF-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "0g-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "0-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "000-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            "00-4BF92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00F067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0A",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-future",
            "cc-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01.future",
            "cc-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-\r\nsecret",
            "cc-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-\0secret",
            "cc-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-\x7fsecret",
            "cc-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-é",
        ] {
            assert_eq!(
                TraceContext::try_from_fields(Some(parent), None, None),
                Err(TraceContextError::InvalidTraceparent)
            );
        }
    }

    #[test]
    fn obs_01_traceparent_byte_limit_is_exact() {
        let prefix = "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-";
        let parent = format!(
            "{prefix}{}",
            "x".repeat(MAX_TRACEPARENT_BYTES - prefix.len())
        );
        assert!(TraceContext::try_from_fields(Some(&parent), None, None).is_ok());
        assert_eq!(
            TraceContext::try_from_fields(Some(&(parent + "x")), None, None),
            Err(TraceContextError::TraceparentLimitExceeded)
        );
    }

    #[test]
    fn obs_01_tracestate_accepts_ows_empty_members_and_tenant_keys() {
        for state in [
            "",
            " \t ",
            ",",
            " \t,rojo=00f067aa0ba902b7, \t,congo=t61rcWkgMzE,",
            "\trojo=leading and interior spaces \t",
            "rojo= leading space",
            "123tenant@vendor=value",
            "a_1-*/=b",
            "a=!*+:/@[]\\?^`{|}~",
        ] {
            let context = TraceContext::try_from_fields(Some(PARENT), Some(state), None).unwrap();
            assert_eq!(context.tracestate(), Some(state));
        }
        assert!(
            TraceContext::try_from_fields(
                Some(PARENT),
                Some(&format!("{}=v", "a".repeat(256))),
                None
            )
            .is_ok()
        );
        assert!(
            TraceContext::try_from_fields(
                Some(PARENT),
                Some(&format!("{}@{}=v", "1".repeat(241), "a".repeat(14))),
                None
            )
            .is_ok()
        );
    }

    #[test]
    fn obs_01_tracestate_rejects_duplicates_and_invalid_member_grammar() {
        for state in [
            "a=1,a=2",
            "a=1, \ta=2",
            "a",
            "a=",
            "a= \t ",
            "a =b",
            "a\t=b",
            "a=b=c",
            "a=b\tc",
            "a=b\nc",
            "a=é",
            "=b",
            "A=b",
            "1=b",
            "_a=b",
            "a.b=c",
            "a@b@c=d",
            "a@1=b",
            "@b=c",
            "a@=b",
            "a=b,broken",
        ] {
            assert_eq!(
                TraceContext::try_from_fields(Some(PARENT), Some(state), None),
                Err(TraceContextError::InvalidTracestate)
            );
        }
        for state in [
            format!("{}=b", "a".repeat(257)),
            format!("{}@b=c", "a".repeat(242)),
            format!("a@{}=b", "a".repeat(15)),
            format!("a={}", "b".repeat(257)),
        ] {
            assert_eq!(
                TraceContext::try_from_fields(Some(PARENT), Some(&state), None),
                Err(TraceContextError::InvalidTracestate)
            );
        }
    }

    #[test]
    fn obs_01_tracestate_member_and_byte_limits_are_exact() {
        let members = (0..MAX_TRACESTATE_MEMBERS)
            .map(|index| format!("k{index}=v"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(TraceContext::try_from_fields(Some(PARENT), Some(&members), None).is_ok());
        assert_eq!(
            TraceContext::try_from_fields(Some(PARENT), Some(&(members + ",extra=v")), None),
            Err(TraceContextError::TracestateLimitExceeded)
        );
        let empty = ",".repeat(MAX_TRACESTATE_MEMBERS - 1);
        assert!(TraceContext::try_from_fields(Some(PARENT), Some(&empty), None).is_ok());
        assert_eq!(
            TraceContext::try_from_fields(Some(PARENT), Some(&(empty + ",")), None),
            Err(TraceContextError::TracestateLimitExceeded)
        );
        let state = format!("a={},b={}", "x".repeat(256), "y".repeat(251));
        assert_eq!(state.len(), MAX_TRACESTATE_BYTES);
        assert!(TraceContext::try_from_fields(Some(PARENT), Some(&state), None).is_ok());
        assert_eq!(
            TraceContext::try_from_fields(Some(PARENT), Some(&(state + "y")), None),
            Err(TraceContextError::TracestateLimitExceeded)
        );
    }

    #[test]
    fn obs_01_baggage_accepts_duplicates_properties_and_encoded_octets() {
        for baggage in [
            "key=value",
            "key=",
            "key=value,key=other",
            "key1=value1;property1;property2, key2 = value2, key3=value3; propertyKey=propertyValue",
            " \tKEY = value\t ; flag \t ; key = a=b== \t ",
            "key=;empty=;flag;flag;empty=next",
            "key=Am%C3%A9lie,percent=%25,binary=%ff,lower=%c3%a9",
            "!#$%&'*+-.^_`|~=!#$&'()*+-./0123456789:<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`{|}~",
        ] {
            let context = TraceContext::try_from_fields(None, None, Some(baggage)).unwrap();
            assert_eq!(context.baggage(), Some(baggage));
            assert!(context.traceparent().is_none());
        }
    }

    #[test]
    fn obs_01_baggage_rejects_one_malformed_member_or_property() {
        for baggage in [
            "",
            " \t ",
            "key",
            "=value",
            ",key=value",
            "key=value,",
            "key=value,,other=value",
            "key=has space",
            "key=has\ttab",
            "key=\"quoted\"",
            "key=back\\slash",
            "key=é",
            "key=\n",
            "key=%",
            "key=%0",
            "key=%xy",
            "key=%2g",
            "key=value;",
            "key=value;;flag",
            "key=value;=bad",
            "key=value;bad key",
            "key=value;prop=has space",
            "key=value;prop=%",
            "bad:key=value",
            "key=value,otherwise=good;bad=\"quoted\"",
        ] {
            assert_eq!(
                TraceContext::try_from_fields(None, None, Some(baggage)),
                Err(TraceContextError::InvalidBaggage)
            );
        }
    }

    #[test]
    fn obs_01_baggage_member_and_byte_limits_are_exact() {
        let members = vec!["key=value"; MAX_BAGGAGE_MEMBERS].join(",");
        assert!(TraceContext::try_from_fields(None, None, Some(&members)).is_ok());
        assert_eq!(
            TraceContext::try_from_fields(None, None, Some(&(members + ",key=value"))),
            Err(TraceContextError::BaggageLimitExceeded)
        );
        let baggage = format!("k={}", "x".repeat(MAX_BAGGAGE_BYTES - 2));
        assert!(TraceContext::try_from_fields(None, None, Some(&baggage)).is_ok());
        assert_eq!(
            TraceContext::try_from_fields(None, None, Some(&(baggage + "x"))),
            Err(TraceContextError::BaggageLimitExceeded)
        );
    }

    #[test]
    fn obs_01_recovery_retains_only_independently_valid_fields() {
        let parent = json!(PARENT);
        let state = json!("a=1");
        let baggage = json!("key=value;property");
        let invalid = json!("secret-invalid-field");
        let (context, report) = TraceContext::recover(Some(&invalid), Some(&state), Some(&baggage));
        assert_eq!(context.traceparent(), None);
        assert_eq!(context.tracestate(), None);
        assert_eq!(context.baggage(), baggage.as_str());
        assert!(report.traceparent_rejected());
        assert!(report.tracestate_rejected());
        assert!(!report.baggage_rejected());
        assert_eq!(report.rejected_count(), 2);

        let (context, report) =
            TraceContext::recover(Some(&parent), Some(&invalid), Some(&baggage));
        assert_eq!(context.traceparent(), Some(PARENT));
        assert_eq!(context.tracestate(), None);
        assert_eq!(context.baggage(), baggage.as_str());
        assert_eq!(report.rejected_count(), 1);
        assert!(report.tracestate_rejected());

        let (context, report) = TraceContext::recover(Some(&parent), Some(&state), Some(&invalid));
        assert_eq!(context.traceparent(), Some(PARENT));
        assert_eq!(context.tracestate(), state.as_str());
        assert_eq!(context.baggage(), None);
        assert_eq!(report.rejected_count(), 1);
        assert!(report.baggage_rejected());
    }

    #[test]
    fn obs_01_recovery_rejects_non_strings_without_retaining_them() {
        for invalid in [
            Value::Null,
            json!(true),
            json!(17),
            json!([]),
            json!({"secret": 1}),
        ] {
            let (context, report) =
                TraceContext::recover(Some(&invalid), Some(&invalid), Some(&invalid));
            assert!(context.is_empty());
            assert_eq!(report.rejected_count(), 3);
            assert!(report.traceparent_rejected());
            assert!(report.tracestate_rejected());
            assert!(report.baggage_rejected());
            assert!(!format!("{report:?}").contains("secret"));
        }
        let (context, report) = TraceContext::recover(None, None, None);
        assert_eq!(context, TraceContext::default());
        assert!(report.is_empty());
        let (context, report) = TraceContext::recover(None, Some(&json!("")), None);
        assert!(context.is_empty());
        assert!(report.tracestate_rejected());
        assert_eq!(report.rejected_count(), 1);
        assert_eq!(
            TraceContext::try_from_fields(None, Some(""), None),
            Err(TraceContextError::OrphanedTracestate)
        );
    }

    #[test]
    fn obs_01_recovery_discards_the_entire_baggage_field() {
        for invalid in [
            json!("valid=retained-only-if-all-valid,invalid"),
            json!(format!("k={}", "x".repeat(MAX_BAGGAGE_BYTES))),
            json!(vec!["k=v"; MAX_BAGGAGE_MEMBERS + 1].join(",")),
        ] {
            let (context, report) =
                TraceContext::recover(Some(&json!(PARENT)), None, Some(&invalid));
            assert_eq!(context.traceparent(), Some(PARENT));
            assert_eq!(context.baggage(), None);
            assert_eq!(report.rejected_count(), 1);
            assert!(report.baggage_rejected());
        }
    }

    #[test]
    fn obs_01_admitted_values_round_trip_and_debug_is_redacted() {
        let state = " \ta=private-vendor-value, ";
        let baggage = "sensitive=secret-value;sensitive-property";
        let context =
            TraceContext::try_from_fields(Some(PARENT), Some(state), Some(baggage)).unwrap();
        let (recovered, report) = TraceContext::recover(
            Some(&json!(context.traceparent().unwrap())),
            Some(&json!(context.tracestate().unwrap())),
            Some(&json!(context.baggage().unwrap())),
        );
        assert_eq!(recovered, context);
        assert!(report.is_empty());
        let debug = format!("{context:?}");
        assert!(!debug.contains(PARENT));
        assert!(!debug.contains("private-vendor-value"));
        assert!(!debug.contains("secret-value"));
        assert!(!debug.contains("sensitive-property"));
        assert!(debug.contains("has_traceparent: true"));
    }
}
