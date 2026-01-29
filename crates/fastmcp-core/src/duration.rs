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
/// # Examples
///
/// ```
/// use fastmcp_core::parse_duration;
/// use std::time::Duration;
///
/// assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
/// assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
/// assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
/// assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
/// assert_eq!(parse_duration("1h30m").unwrap(), Duration::from_secs(5400));
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
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c.is_ascii_digit() {
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

            let millis = match unit {
                "ms" => num,
                "s" => num * 1000,
                "m" => num * 60 * 1000,
                "h" => num * 60 * 60 * 1000,
                _ => unreachable!(),
            };

            total_millis = total_millis.saturating_add(millis);
            current_num.clear();
        } else if c.is_whitespace() {
            // Allow whitespace between components
            continue;
        } else {
            return Err(ParseDurationError {
                input: s.to_string(),
                message: format!("unexpected character '{c}'"),
            });
        }
    }

    // Handle trailing number without unit (treat as seconds for compatibility)
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
        assert_eq!(parse_duration("90m").unwrap(), Duration::from_secs(5400));
    }

    #[test]
    fn test_parse_hours() {
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
        assert_eq!(parse_duration("24h").unwrap(), Duration::from_secs(86400));
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
        assert_eq!(parse_duration("1h30m").unwrap(), Duration::from_secs(5400));
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
        assert_eq!(parse_duration("1h 30m").unwrap(), Duration::from_secs(5400));
    }

    #[test]
    fn test_parse_errors() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("30").is_err()); // Missing unit
        assert!(parse_duration("30x").is_err()); // Invalid unit
        assert!(parse_duration("0s").is_err()); // Zero duration
    }
}
