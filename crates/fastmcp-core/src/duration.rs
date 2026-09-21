//! Human-readable duration parsing.
//!
//! Supports parsing durations in formats like:
//! - "30s" → 30 seconds
//! - "5m" → 5 minutes
//! - "1h" → 1 hour
//! - "500ms" → 500 milliseconds
//! - "1h30m" → 1 hour 30 minutes

use std::time::Duration;

/// Error type for duration parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseDurationError {
    /// The invalid input string.
    pub input: String,
    /// Description of the error.
    pub message: String,
}

impl std::fmt::Display for ParseDurationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid duration '{}': {}", self.input, self.message)
    }
}

impl std::error::Error for ParseDurationError {}

/// Parses a human-readable duration string into a `Duration`.
///
/// # Supported Formats
///
/// - Milliseconds: "500ms", "100ms"
/// - Seconds: "30s", "5s"
/// - Minutes: "5m", "10m"
/// - Hours: "1h", "2h"
/// - Combined: "1h30m", "2m30s", "1h30m45s"
///
/// Whitespace may separate components or a number from its unit, but cannot
/// split the digits of a number: "1h 30 m" is valid, while "1 0s" is not.
///
/// # Examples
///
/// ```
/// use fastmcp_core::parse_duration;
/// use std::time::Duration;
///
/// assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
/// assert_eq!(parse_duration("5m").unwrap(), Duration::from_mins(5));
/// assert_eq!(parse_duration("1h").unwrap(), Duration::from_hours(1));
/// assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
/// assert_eq!(parse_duration("1h30m").unwrap(), Duration::from_mins(90));
/// ```
pub fn parse_duration(s: &str) -> Result<Duration, ParseDurationError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(ParseDurationError {
            input: s.to_string(),
            message: "empty string".to_string(),
        });
    }

    let mut total_millis: u64 = 0;
    let mut current_num = String::new();
    let mut number_has_separator = false;
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c.is_ascii_digit() {
            if number_has_separator {
                return Err(ParseDurationError {
                    input: s.to_string(),
                    message: "whitespace cannot split the digits of a duration number".to_string(),
                });
            }
            current_num.push(c);
        } else if c.is_ascii_alphabetic() {
            if current_num.is_empty() {
                return Err(ParseDurationError {
                    input: s.to_string(),
                    message: format!("unexpected unit character '{c}' without preceding number"),
                });
            }

            let num: u64 = current_num.parse().map_err(|_| ParseDurationError {
                input: s.to_string(),
                message: format!("invalid number: {current_num}"),
            })?;

            // Check for multi-character units (ms)
            let unit = if c == 'm' && chars.peek() == Some(&'s') {
                chars.next(); // consume 's'
                "ms"
            } else {
                // Single character unit
                match c {
                    'h' => "h",
                    'm' => "m",
                    's' => "s",
                    _ => {
                        return Err(ParseDurationError {
                            input: s.to_string(),
                            message: format!("unknown unit '{c}'"),
                        });
                    }
                }
            };

            let millis_per_unit = match unit {
                "ms" => 1,
                "s" => 1_000,
                "m" => 60_000,
                "h" => 3_600_000,
                _ => unreachable!(),
            };
            let millis = num
                .checked_mul(millis_per_unit)
                .ok_or_else(|| ParseDurationError {
                    input: s.to_string(),
                    message: format!("duration component overflows: {num}{unit}"),
                })?;

            total_millis = total_millis
                .checked_add(millis)
                .ok_or_else(|| ParseDurationError {
                    input: s.to_string(),
                    message: "combined duration overflows".to_string(),
                })?;
            current_num.clear();
            number_has_separator = false;
        } else if c.is_whitespace() {
            // Preserve legal component/number-unit spacing without joining
            // two distinct numeric tokens into a different duration.
            number_has_separator |= !current_num.is_empty();
        } else {
            return Err(ParseDurationError {
                input: s.to_string(),
                message: format!("unexpected character '{c}'"),
            });
        }
    }

    // Every component requires an explicit unit, including the last one.
    if !current_num.is_empty() {
        return Err(ParseDurationError {
            input: s.to_string(),
            message: format!("number '{current_num}' missing unit (use s, m, h, or ms)"),
        });
    }

    if total_millis == 0 {
        return Err(ParseDurationError {
            input: s.to_string(),
            message: "duration must be greater than zero".to_string(),
        });
    }

    Ok(Duration::from_millis(total_millis))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_seconds() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("1s").unwrap(), Duration::from_secs(1));
        assert_eq!(parse_duration("120s").unwrap(), Duration::from_secs(120));
    }

    #[test]
    fn test_parse_minutes() {
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration("1m").unwrap(), Duration::from_secs(60));
        assert_eq!(parse_duration("90m").unwrap(), Duration::from_mins(90));
    }

    #[test]
    fn test_parse_hours() {
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
        assert_eq!(parse_duration("24h").unwrap(), Duration::from_hours(24));
    }

    #[test]
    #[allow(clippy::duration_suboptimal_units)]
    fn test_parse_milliseconds() {
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(
            parse_duration("1000ms").unwrap(),
            Duration::from_millis(1000)
        );
        assert_eq!(parse_duration("1ms").unwrap(), Duration::from_millis(1));
    }

    #[test]
    fn test_parse_combined() {
        assert_eq!(parse_duration("1h30m").unwrap(), Duration::from_mins(90));
        assert_eq!(parse_duration("2m30s").unwrap(), Duration::from_secs(150));
        assert_eq!(
            parse_duration("1h30m45s").unwrap(),
            Duration::from_secs(5445)
        );
        assert_eq!(
            parse_duration("1m500ms").unwrap(),
            Duration::from_millis(60500)
        );
    }

    #[test]
    fn test_parse_with_whitespace() {
        assert_eq!(parse_duration("  30s  ").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("1h 30m").unwrap(), Duration::from_mins(90));
    }

    #[test]
    fn rejects_whitespace_inside_numeric_tokens() {
        for separator in [" ", "\t", "\n", "\r\n", "\u{00a0}", "\u{2003}"] {
            for (compact, split) in [
                ("10s", format!("1{separator}0s")),
                ("500ms", format!("5{separator}00ms")),
                ("1h30m", format!("1h 3{separator}0m")),
            ] {
                assert!(parse_duration(compact).is_ok(), "{compact:?}");
                let error = parse_duration(&split)
                    .expect_err("a separator must not concatenate numeric tokens");
                assert_eq!(error.input, split);
                assert_eq!(
                    error.message,
                    "whitespace cannot split the digits of a duration number"
                );
            }
        }
    }

    #[test]
    fn number_unit_spacing_does_not_poison_later_components() {
        for separator in [" ", "\t", "\n", "\u{00a0}", "\u{2003}"] {
            let input = format!("1{separator}h{separator}30{separator}m500{separator}ms");
            assert_eq!(
                parse_duration(&input).expect("spacing around complete numeric tokens is legal"),
                Duration::from_millis(5_400_500)
            );
        }
    }

    #[test]
    fn spaced_components_still_require_units_and_checked_arithmetic() {
        assert!(parse_duration("1h 30 ").is_err());
        assert!(parse_duration("1h 0 s").is_ok());
        assert!(parse_duration("0 s").is_err());
        assert_eq!(
            parse_duration("18446744073709551615 ms").unwrap(),
            Duration::from_millis(u64::MAX)
        );
        assert!(parse_duration("18446744073709551615 ms 1 ms").is_err());
        assert!(parse_duration("18446744073709551615 s").is_err());
    }

    #[test]
    fn rejects_component_and_combined_overflow() {
        let component = parse_duration("18446744073709551615s")
            .expect_err("seconds-to-milliseconds conversion must be checked");
        assert_eq!(
            component.message,
            "duration component overflows: 18446744073709551615s"
        );

        let combined = parse_duration("18446744073709551615ms1ms")
            .expect_err("adding duration components must be checked");
        assert_eq!(combined.message, "combined duration overflows");
    }

    #[test]
    fn test_parse_errors() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("30").is_err()); // Missing unit
        assert!(parse_duration("30x").is_err()); // Invalid unit
        assert!(parse_duration("0s").is_err()); // Zero duration
    }

    // =========================================================================
    // Additional coverage tests (bd-1p24)
    // =========================================================================

    #[test]
    fn error_display_format() {
        let err = parse_duration("").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("invalid duration"));
        assert!(msg.contains("empty string"));
    }

    #[test]
    fn error_is_std_error() {
        let err = parse_duration("bad").unwrap_err();
        // Ensure std::error::Error is implemented
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn error_debug_clone_eq() {
        let err = parse_duration("30").unwrap_err();
        let debug = format!("{err:?}");
        assert!(debug.contains("ParseDurationError"));

        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn error_unit_without_number() {
        let err = parse_duration("s").unwrap_err();
        assert!(err.message.contains("without preceding number"));
    }

    #[test]
    fn error_unknown_unit() {
        let err = parse_duration("30x").unwrap_err();
        assert!(err.message.contains("unknown unit"));
    }

    #[test]
    fn error_unexpected_character() {
        let err = parse_duration("30s$").unwrap_err();
        assert!(err.message.contains("unexpected character"));
    }

    #[test]
    fn error_missing_unit() {
        let err = parse_duration("42").unwrap_err();
        assert!(err.message.contains("missing unit"));
    }

    #[test]
    fn error_zero_duration() {
        let err = parse_duration("0s").unwrap_err();
        assert!(err.message.contains("greater than zero"));
    }

    #[test]
    fn whitespace_between_components() {
        assert_eq!(
            parse_duration("2h 30m 15s").unwrap(),
            Duration::from_secs(2 * 3600 + 30 * 60 + 15)
        );
    }

    // =========================================================================
    // Additional coverage tests (bd-2qlj)
    // =========================================================================

    #[test]
    fn maximum_milliseconds_is_exact_and_one_more_is_rejected() {
        assert_eq!(
            parse_duration(&format!("{}ms", u64::MAX)).unwrap(),
            Duration::from_millis(u64::MAX)
        );

        let err = parse_duration(&format!("{}ms 1ms", u64::MAX))
            .expect_err("duration parsing must not silently saturate overflow");
        assert_eq!(err.message, "combined duration overflows");
    }

    #[test]
    fn error_fields_accessible() {
        let err = parse_duration("42").unwrap_err();
        assert_eq!(err.input, "42");
        assert!(err.message.contains("missing unit"));
    }

    #[test]
    fn only_whitespace_input() {
        let err = parse_duration("   ").unwrap_err();
        assert!(err.message.contains("empty string"));
    }

    #[test]
    fn combined_with_ms() {
        assert_eq!(
            parse_duration("1h 30m 45s 500ms").unwrap(),
            Duration::from_millis(3_600_000 + 30 * 60_000 + 45_000 + 500)
        );
    }
}
