//! Bounded file intake shared by explicit and discovered configuration paths.

use std::io::Read;
use std::path::Path;

use super::{ConfigError, McpConfig, parse};

pub(super) fn load(path: &Path, max_bytes: usize) -> Result<McpConfig, ConfigError> {
    // One extra byte is necessary to distinguish a file exactly at the bound
    // from a truncated prefix of a larger file. Validate before opening it.
    let read_limit = checked_read_limit(max_bytes)?;
    let file = std::fs::File::open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            ConfigError::NotFound(path.display().to_string())
        } else {
            ConfigError::ReadError(error)
        }
    })?;
    let bytes = read_bounded(file, max_bytes, read_limit)?;
    let content = std::str::from_utf8(&bytes).map_err(|_| {
        ConfigError::ReadError(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Configuration file is not valid UTF-8",
        ))
    })?;
    parse::from_path_content(path, content)
}

fn checked_read_limit(max_bytes: usize) -> Result<u64, ConfigError> {
    if max_bytes == 0 {
        return Err(ConfigError::InvalidFileByteLimit);
    }
    u64::try_from(max_bytes)
        .ok()
        .and_then(|limit| limit.checked_add(1))
        .ok_or(ConfigError::InvalidFileByteLimit)
}

fn read_bounded(
    reader: impl Read,
    max_bytes: usize,
    read_limit: u64,
) -> Result<Vec<u8>, ConfigError> {
    let mut bytes = Vec::new();
    reader
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(ConfigError::ReadError)?;
    if bytes.len() > max_bytes {
        return Err(ConfigError::FileTooLarge {
            limit_bytes: max_bytes,
        });
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor};

    #[test]
    fn exact_byte_bound_is_accepted_and_one_more_byte_is_refused() {
        let limit = checked_read_limit(3).unwrap();
        assert_eq!(read_bounded(Cursor::new(b"abc"), 3, limit).unwrap(), b"abc");
        assert!(matches!(
            read_bounded(Cursor::new(b"abcd"), 3, limit),
            Err(ConfigError::FileTooLarge { limit_bytes: 3 })
        ));
    }

    #[test]
    fn growing_input_cannot_bypass_the_bound_with_stale_metadata() {
        let limit = checked_read_limit(64).unwrap();
        // repeat() has no EOF, just like a file concurrently extended by a
        // writer. The reader still terminates after the single-byte probe.
        assert!(matches!(
            read_bounded(io::repeat(b' '), 64, limit),
            Err(ConfigError::FileTooLarge { limit_bytes: 64 })
        ));
    }

    #[test]
    fn invalid_byte_limits_are_not_silently_saturated() {
        assert!(matches!(checked_read_limit(0), Err(ConfigError::InvalidFileByteLimit)));
        assert_eq!(checked_read_limit(1).unwrap(), 2);
        #[cfg(target_pointer_width = "64")]
        assert!(matches!(
            checked_read_limit(usize::MAX),
            Err(ConfigError::InvalidFileByteLimit)
        ));
    }
}
