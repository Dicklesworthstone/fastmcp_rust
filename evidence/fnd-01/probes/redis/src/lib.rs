//! Compile surface for the exact FND-01 Redis crate candidate.
//!
//! This probe never opens a connection. The unmodified crate's connector,
//! parser, credential representation, and peer-identity behavior do not meet
//! TASKR-01, so this artifact is dependency evidence rather than a persistence
//! support claim.

#![forbid(unsafe_code)]

use redis::{acl::AclInfo, ConnectionAddr, Script};

/// Exercise the `script` feature and its `sha1_smol` edge without I/O.
pub fn script_sha1(source: &str) -> String {
    Script::new(source).get_hash().to_owned()
}

/// Keep the `acl` feature's public result type in the compile surface.
pub fn acl_type_surface(info: &AclInfo) -> &AclInfo {
    info
}

/// Negative evidence: TCP remains a public, constructible address variant
/// even when every TLS/cluster/aio/runtime feature is disabled.
pub fn tcp_address_surface(host: String, port: u16) -> ConnectionAddr {
    ConnectionAddr::Tcp(host, port)
}

/// Negative evidence: on Unix the crate accepts an ambient socket path; this
/// is not the retained-capability, peer-verified connector TASKR-01 requires.
#[cfg(unix)]
pub fn ambient_unix_address_surface(path: std::path::PathBuf) -> ConnectionAddr {
    ConnectionAddr::Unix(path)
}

#[cfg(test)]
mod tests {
    use super::{script_sha1, tcp_address_surface};

    const STATE: &str = include_str!("../../../state-capability-dependencies.toml");
    const ENVELOPE_MANIFEST: &str = include_str!("../../envelope/Cargo.toml");
    const ENVELOPE_LOCK: &str = include_str!("../../envelope/Cargo.lock");
    const CAPABILITY_FS_MANIFEST: &str = include_str!("../../capability-fs/Cargo.toml");
    const CAPABILITY_FS_LOCK: &str = include_str!("../../capability-fs/Cargo.lock");
    const REDIS_MANIFEST: &str = include_str!("../Cargo.toml");
    const REDIS_LOCK: &str = include_str!("../Cargo.lock");
    const ENVELOPE_SOURCE: &str = include_str!("../../envelope/src/lib.rs");
    const CAPABILITY_FS_SOURCE: &str = include_str!("../../capability-fs/src/lib.rs");
    const REDIS_FEATURE_LINE: &str = "redis = { version = \"=1.4.1\", default-features = false, features = [\"acl\", \"script\"] }";
    const FROZEN_INPUTS_DIGEST: &str =
        "166511cfae5c5dd9073c6123c98fd83b8cadf2481c400b5150709129844866d1";
    fn validate_packages_absent(
        subject: &'static str,
        lock: &str,
        packages: &[&str],
    ) -> Result<(), StructuredEvidenceError> {
        let selected = parse_lock(subject, lock)?;
        for package in packages {
            if selected.iter().any(|selected| selected.name == *package) {
                return Err(StructuredEvidenceError::ForbiddenFeature {
                    subject,
                    feature: (*package).to_owned(),
                });
            }
        }
        Ok(())
    }

    const MAX_EVIDENCE_BYTES: usize = 131_072;
    const MAX_LOCK_BYTES: usize = 16_384;
    const MAX_ARRAY_ITEMS: usize = 128;
    const MAX_LOCK_PACKAGES: usize = 128;

    #[derive(Debug, Eq, PartialEq)]
    enum StructuredEvidenceError {
        InputTooLarge {
            subject: &'static str,
            maximum: usize,
        },
        MissingSection {
            subject: &'static str,
        },
        MissingField {
            subject: &'static str,
            field: &'static str,
        },
        MalformedField {
            subject: &'static str,
            field: &'static str,
        },
        UnexpectedValue {
            subject: &'static str,
            field: &'static str,
            expected: String,
            actual: String,
        },
        ForbiddenFeature {
            subject: &'static str,
            feature: String,
        },
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct DependencySelection {
        version: String,
        default_features: bool,
        features: Vec<String>,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct AcceptedContractState {
        envelope: DependencySelection,
        capability_fs_extension: DependencySelection,
        capability_fs_root: DependencySelection,
        redis: DependencySelection,
        graph_receipts_verified: bool,
        archive_bytes_available: bool,
        target_compilation_verified: bool,
        advisory_execution_verified: bool,
        redis_profile_supported: bool,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct Inputs {
        state: String,
        envelope_manifest: String,
        envelope_lock: String,
        envelope_source: String,
        capability_fs_manifest: String,
        capability_fs_lock: String,
        capability_fs_source: String,
        redis_manifest: String,
        redis_lock: String,
        expected_domain_digest: String,
    }

    impl Inputs {
        fn baseline() -> Self {
            Self {
                state: STATE.to_owned(),
                envelope_manifest: ENVELOPE_MANIFEST.to_owned(),
                envelope_lock: ENVELOPE_LOCK.to_owned(),
                envelope_source: ENVELOPE_SOURCE.to_owned(),
                capability_fs_manifest: CAPABILITY_FS_MANIFEST.to_owned(),
                capability_fs_lock: CAPABILITY_FS_LOCK.to_owned(),
                capability_fs_source: CAPABILITY_FS_SOURCE.to_owned(),
                redis_manifest: REDIS_MANIFEST.to_owned(),
                redis_lock: REDIS_LOCK.to_owned(),
                expected_domain_digest: FROZEN_INPUTS_DIGEST.to_owned(),
            }
        }

        fn rebind_expected_domain_digest(&mut self) -> Result<(), StructuredEvidenceError> {
            self.expected_domain_digest = inputs_digest(self)?;
            Ok(())
        }
    }

    impl StructuredEvidenceError {
        fn stable_diagnostic(&self) -> String {
            match self {
                Self::InputTooLarge { subject, maximum } => {
                    format!("E_INPUT_TOO_LARGE:{subject}:{maximum}")
                }
                Self::MissingSection { subject } => format!("E_MISSING_SECTION:{subject}"),
                Self::MissingField { subject, field } => {
                    format!("E_MISSING_FIELD:{subject}:{field}")
                }
                Self::MalformedField { subject, field } => {
                    format!("E_MALFORMED_FIELD:{subject}:{field}")
                }
                Self::UnexpectedValue {
                    subject,
                    field,
                    expected,
                    actual,
                } => format!("E_UNEXPECTED_VALUE:{subject}:{field}:{expected}:{actual}"),
                Self::ForbiddenFeature { subject, feature } => {
                    format!("E_FORBIDDEN_FEATURE:{subject}:{feature}")
                }
            }
        }
    }

    fn state_without_redis_self_source_record(
        state: &str,
    ) -> Result<String, StructuredEvidenceError> {
        let start =
            state
                .find("[probe.redis]\n")
                .ok_or(StructuredEvidenceError::MissingSection {
                    subject: "[probe.redis]",
                })?;
        let after_header = start + "[probe.redis]\n".len();
        let end = state[after_header..]
            .find("\n[")
            .map_or(state.len(), |offset| after_header + offset + 1);
        let probe = &state[after_header..end];
        let source_bytes = format!(
            "source_bytes = {}",
            usize_field("[probe.redis]", probe, "source_bytes")?
        );
        let source_hash = format!(
            "source_sha256 = \"{}\"",
            quoted_field("[probe.redis]", probe, "source_sha256")?
        );
        let normalized = probe
            .replacen(&source_bytes, "source_bytes = <self-excluded>", 1)
            .replacen(&source_hash, "source_sha256 = <self-excluded>", 1);
        Ok(format!(
            "{}{}{}",
            &state[..after_header],
            normalized,
            &state[end..]
        ))
    }

    fn inputs_digest(inputs: &Inputs) -> Result<String, StructuredEvidenceError> {
        let mut canonical = b"fastmcp-fnd01-inputs-v1\0".to_vec();
        let normalized_state = state_without_redis_self_source_record(&inputs.state)?;
        for (name, value) in [
            ("state", normalized_state.as_str()),
            ("envelope_manifest", inputs.envelope_manifest.as_str()),
            ("envelope_lock", inputs.envelope_lock.as_str()),
            ("envelope_source", inputs.envelope_source.as_str()),
            (
                "capability_fs_manifest",
                inputs.capability_fs_manifest.as_str(),
            ),
            ("capability_fs_lock", inputs.capability_fs_lock.as_str()),
            ("capability_fs_source", inputs.capability_fs_source.as_str()),
            ("redis_manifest", inputs.redis_manifest.as_str()),
            ("redis_lock", inputs.redis_lock.as_str()),
        ] {
            canonical.extend_from_slice(name.as_bytes());
            canonical.push(0);
            canonical.extend_from_slice(value.len().to_string().as_bytes());
            canonical.push(0);
            canonical.extend_from_slice(value.as_bytes());
            canonical.push(0);
        }
        Ok(sha256_hex(&canonical))
    }

    fn changed_input_count(left: &Inputs, right: &Inputs) -> usize {
        [
            left.state != right.state,
            left.envelope_manifest != right.envelope_manifest,
            left.envelope_lock != right.envelope_lock,
            left.envelope_source != right.envelope_source,
            left.capability_fs_manifest != right.capability_fs_manifest,
            left.capability_fs_lock != right.capability_fs_lock,
            left.capability_fs_source != right.capability_fs_source,
            left.redis_manifest != right.redis_manifest,
            left.redis_lock != right.redis_lock,
        ]
        .into_iter()
        .filter(|changed| *changed)
        .count()
    }

    fn semantic_input_change_count(left: &Inputs, right: &Inputs) -> usize {
        [
            left.envelope_manifest != right.envelope_manifest,
            left.envelope_lock != right.envelope_lock,
            left.envelope_source != right.envelope_source,
            left.capability_fs_manifest != right.capability_fs_manifest,
            left.capability_fs_lock != right.capability_fs_lock,
            left.capability_fs_source != right.capability_fs_source,
            left.redis_manifest != right.redis_manifest,
            left.redis_lock != right.redis_lock,
        ]
        .into_iter()
        .filter(|changed| *changed)
        .count()
    }

    fn rebind_redis_manifest_mirror(
        state: &str,
        redis_manifest: &str,
    ) -> Result<String, StructuredEvidenceError> {
        let start =
            state
                .find("[probe.redis]\n")
                .ok_or(StructuredEvidenceError::MissingSection {
                    subject: "[probe.redis]",
                })?;
        let after_header = start + "[probe.redis]\n".len();
        let end = state[after_header..]
            .find("\n[")
            .map_or(state.len(), |offset| after_header + offset + 1);
        let probe = &state[after_header..end];
        let old_bytes = format!(
            "manifest_bytes = {}",
            usize_field("[probe.redis]", probe, "manifest_bytes")?
        );
        let old_hash = format!(
            "manifest_sha256 = \"{}\"",
            quoted_field("[probe.redis]", probe, "manifest_sha256")?
        );
        let new_bytes = format!("manifest_bytes = {}", redis_manifest.len());
        let new_hash = format!(
            "manifest_sha256 = \"{}\"",
            sha256_hex(redis_manifest.as_bytes())
        );
        let rebind_field = |input: &str,
                            current: &str,
                            derived: &str,
                            field: &'static str|
         -> Result<String, StructuredEvidenceError> {
            if input.lines().filter(|line| *line == current).count() != 1 {
                return Err(StructuredEvidenceError::UnexpectedValue {
                    subject: "[probe.redis]",
                    field,
                    expected: "one exact field replacement".to_owned(),
                    actual: current.to_owned(),
                });
            }
            let rebound = if current == derived {
                input.to_owned()
            } else {
                input.replacen(current, derived, 1)
            };
            if rebound.lines().filter(|line| *line == derived).count() != 1
                || (current != derived && rebound.lines().any(|line| line == current))
            {
                return Err(StructuredEvidenceError::UnexpectedValue {
                    subject: "[probe.redis]",
                    field,
                    expected: "one exact field replacement".to_owned(),
                    actual: current.to_owned(),
                });
            }
            Ok(rebound)
        };
        let rebound_probe = rebind_field(
            probe,
            &old_bytes,
            &new_bytes,
            "manifest_bytes mirror",
        )?;
        let rebound_probe = rebind_field(
            &rebound_probe,
            &old_hash,
            &new_hash,
            "manifest_sha256 mirror",
        )?;
        Ok(format!(
            "{}{}{}",
            &state[..after_header],
            rebound_probe,
            &state[end..]
        ))
    }

    fn state_without_redis_manifest_mirror(state: &str) -> Result<String, StructuredEvidenceError> {
        let start =
            state
                .find("[probe.redis]\n")
                .ok_or(StructuredEvidenceError::MissingSection {
                    subject: "[probe.redis]",
                })?;
        let after_header = start + "[probe.redis]\n".len();
        let end = state[after_header..]
            .find("\n[")
            .map_or(state.len(), |offset| after_header + offset + 1);
        let probe = &state[after_header..end];
        let bytes = format!(
            "manifest_bytes = {}",
            usize_field("[probe.redis]", probe, "manifest_bytes")?
        );
        let hash = format!(
            "manifest_sha256 = \"{}\"",
            quoted_field("[probe.redis]", probe, "manifest_sha256")?
        );
        let normalized = probe
            .replacen(&bytes, "manifest_bytes = <derived>", 1)
            .replacen(&hash, "manifest_sha256 = <derived>", 1);
        Ok(format!(
            "{}{}{}",
            &state[..after_header],
            normalized,
            &state[end..]
        ))
    }

    #[derive(Debug)]
    struct LockPackage {
        name: String,
        version: String,
        source: Option<String>,
        checksum: Option<String>,
        dependencies: Vec<String>,
    }

    fn bounded<'a>(
        subject: &'static str,
        text: &'a str,
        maximum: usize,
    ) -> Result<&'a str, StructuredEvidenceError> {
        if text.len() > maximum {
            return Err(StructuredEvidenceError::InputTooLarge { subject, maximum });
        }
        Ok(text)
    }

    fn section<'a>(
        text: &'a str,
        header: &'static str,
    ) -> Result<&'a str, StructuredEvidenceError> {
        bounded("evidence", text, MAX_EVIDENCE_BYTES)?;
        let expected = header
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .ok_or(StructuredEvidenceError::MalformedField {
                subject: header,
                field: "TOML table header",
            })?;
        let mut found = false;
        let mut start = 0;
        let mut offset = 0;
        for line in text.split_inclusive('\n') {
            let trimmed = line.trim();
            let table_name = trimmed
                .strip_prefix('[')
                .and_then(|value| value.strip_suffix(']'))
                .map(str::trim);
            if found && table_name.is_some() {
                if table_name == Some(expected) {
                    return Err(StructuredEvidenceError::UnexpectedValue {
                        subject: header,
                        field: "duplicate TOML table header",
                        expected: "one table".to_owned(),
                        actual: header.to_owned(),
                    });
                }
                return Ok(&text[start..offset]);
            }
            if table_name == Some(expected) {
                found = true;
                start = offset + line.len();
            }
            offset += line.len();
        }
        if found {
            Ok(&text[start..])
        } else {
            Err(StructuredEvidenceError::MissingSection { subject: header })
        }
    }

    fn structural_fields<'a>(
        subject: &'static str,
        text: &'a str,
    ) -> Result<Vec<(&'a str, &'a str)>, StructuredEvidenceError> {
        let bytes = text.as_bytes();
        let mut cursor = 0;
        let mut fields = Vec::new();
        while cursor < bytes.len() {
            while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            if cursor == bytes.len() {
                break;
            }
            if bytes[cursor] == b'#' {
                while cursor < bytes.len() && bytes[cursor] != b'\n' {
                    cursor += 1;
                }
                continue;
            }
            let key_start = cursor;
            while cursor < bytes.len()
                && (bytes[cursor].is_ascii_alphanumeric() || matches!(bytes[cursor], b'_' | b'-'))
            {
                cursor += 1;
            }
            if cursor == key_start {
                return Err(StructuredEvidenceError::MalformedField {
                    subject,
                    field: "bare TOML key",
                });
            }
            let key = &text[key_start..cursor];
            while cursor < bytes.len() && matches!(bytes[cursor], b' ' | b'\t') {
                cursor += 1;
            }
            if cursor == bytes.len() || bytes[cursor] != b'=' {
                return Err(StructuredEvidenceError::MalformedField {
                    subject,
                    field: "TOML key/value delimiter",
                });
            }
            cursor += 1;
            while cursor < bytes.len() && matches!(bytes[cursor], b' ' | b'\t') {
                cursor += 1;
            }
            let value_start = cursor;
            let mut quoted = false;
            let mut escaped = false;
            let mut nesting = 0_u8;
            while cursor < bytes.len() {
                match bytes[cursor] {
                    b'\\' if quoted => escaped = !escaped,
                    b'"' if !escaped => quoted = !quoted,
                    b'[' | b'{' if !quoted => nesting = nesting.saturating_add(1),
                    b']' | b'}' if !quoted => {
                        nesting = nesting.checked_sub(1).ok_or(
                            StructuredEvidenceError::MalformedField {
                                subject,
                                field: "TOML value nesting",
                            },
                        )?;
                    }
                    b'#' if !quoted && nesting == 0 => break,
                    b'\n' if !quoted && nesting == 0 => break,
                    _ => escaped = false,
                }
                cursor += 1;
            }
            if quoted || nesting != 0 || value_start == cursor {
                return Err(StructuredEvidenceError::MalformedField {
                    subject,
                    field: "TOML value",
                });
            }
            let value = text[value_start..cursor].trim_end_matches([' ', '\t']);
            if fields.iter().any(|(existing, _)| *existing == key) {
                return Err(StructuredEvidenceError::UnexpectedValue {
                    subject,
                    field: "duplicate TOML key",
                    expected: "unique keys".to_owned(),
                    actual: key.to_owned(),
                });
            }
            fields.push((key, value));
            while cursor < bytes.len() && bytes[cursor] != b'\n' {
                cursor += 1;
            }
        }
        Ok(fields)
    }

    fn field_value<'a>(
        subject: &'static str,
        text: &'a str,
        field: &'static str,
    ) -> Result<&'a str, StructuredEvidenceError> {
        structural_fields(subject, text)?
            .into_iter()
            .find_map(|(key, value)| (key == field).then_some(value))
            .ok_or(StructuredEvidenceError::MissingField { subject, field })
    }

    fn optional_field_value<'a>(
        subject: &'static str,
        text: &'a str,
        field: &'static str,
    ) -> Result<Option<&'a str>, StructuredEvidenceError> {
        Ok(structural_fields(subject, text)?
            .into_iter()
            .find_map(|(key, value)| (key == field).then_some(value)))
    }

    fn quoted_field(
        subject: &'static str,
        text: &str,
        field: &'static str,
    ) -> Result<String, StructuredEvidenceError> {
        let value = field_value(subject, text, field)?;
        value
            .strip_prefix('\"')
            .and_then(|value| value.strip_suffix('\"'))
            .map(str::to_owned)
            .ok_or(StructuredEvidenceError::MalformedField { subject, field })
    }

    fn boolean_field(
        subject: &'static str,
        text: &str,
        field: &'static str,
    ) -> Result<bool, StructuredEvidenceError> {
        match field_value(subject, text, field)? {
            "true" => Ok(true),
            "false" => Ok(false),
            value => Err(StructuredEvidenceError::UnexpectedValue {
                subject,
                field,
                expected: "true or false".to_owned(),
                actual: value.to_owned(),
            }),
        }
    }

    fn usize_field(
        subject: &'static str,
        text: &str,
        field: &'static str,
    ) -> Result<usize, StructuredEvidenceError> {
        field_value(subject, text, field)?
            .parse()
            .map_err(|_| StructuredEvidenceError::MalformedField { subject, field })
    }

    fn string_array(
        subject: &'static str,
        text: &str,
        field: &'static str,
    ) -> Result<Vec<String>, StructuredEvidenceError> {
        let encoded = field_value(subject, text, field)?;
        let normalized = encoded
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .map(str::trim_end)
            .and_then(|content| content.strip_suffix(','))
            .filter(|content| !content.trim().is_empty())
            .map(|content| format!("[{content}]"));
        parse_string_array_value(subject, field, normalized.as_deref().unwrap_or(encoded))
    }

    fn parse_string_array_value(
        subject: &'static str,
        field: &'static str,
        encoded: &str,
    ) -> Result<Vec<String>, StructuredEvidenceError> {
        let content = encoded
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .ok_or(StructuredEvidenceError::MalformedField { subject, field })?;
        if content.trim().is_empty() {
            return Ok(Vec::new());
        }
        let mut raw_values = Vec::new();
        let mut start = 0;
        let mut nesting = 0_u8;
        let mut quoted = false;
        for (offset, character) in content.char_indices() {
            match character {
                '\"' => quoted = !quoted,
                '[' | '{' if !quoted => nesting = nesting.saturating_add(1),
                ']' | '}' if !quoted => nesting = nesting.saturating_sub(1),
                ',' if !quoted && nesting == 0 => {
                    let value = content[start..offset].trim();
                    if value.is_empty() {
                        return Err(StructuredEvidenceError::MalformedField { subject, field });
                    }
                    raw_values.push(value);
                    start = offset + character.len_utf8();
                }
                _ => {}
            }
        }
        if quoted || nesting != 0 {
            return Err(StructuredEvidenceError::MalformedField { subject, field });
        }
        let value = content[start..].trim();
        if value.is_empty() {
            return Err(StructuredEvidenceError::MalformedField { subject, field });
        }
        raw_values.push(value);
        let values = raw_values
            .into_iter()
            .map(|value| {
                value
                    .strip_prefix('\"')
                    .and_then(|value| value.strip_suffix('\"'))
                    .map(str::to_owned)
                    .ok_or(StructuredEvidenceError::MalformedField { subject, field })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if values.len() > MAX_ARRAY_ITEMS {
            return Err(StructuredEvidenceError::InputTooLarge {
                subject,
                maximum: MAX_ARRAY_ITEMS,
            });
        }
        Ok(values)
    }

    fn expect_string(
        subject: &'static str,
        text: &str,
        field: &'static str,
        expected: &str,
    ) -> Result<(), StructuredEvidenceError> {
        let actual = quoted_field(subject, text, field)?;
        if actual == expected {
            Ok(())
        } else {
            Err(StructuredEvidenceError::UnexpectedValue {
                subject,
                field,
                expected: expected.to_owned(),
                actual,
            })
        }
    }

    fn expect_false(
        subject: &'static str,
        text: &str,
        field: &'static str,
    ) -> Result<(), StructuredEvidenceError> {
        if !boolean_field(subject, text, field)? {
            Ok(())
        } else {
            Err(StructuredEvidenceError::UnexpectedValue {
                subject,
                field,
                expected: "false".to_owned(),
                actual: "true".to_owned(),
            })
        }
    }

    fn expect_array(
        subject: &'static str,
        text: &str,
        field: &'static str,
        expected: &[&str],
    ) -> Result<(), StructuredEvidenceError> {
        let actual = string_array(subject, text, field)?;
        let expected = expected
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();
        if actual == expected {
            Ok(())
        } else {
            Err(StructuredEvidenceError::UnexpectedValue {
                subject,
                field,
                expected: format!("{expected:?}"),
                actual: format!("{actual:?}"),
            })
        }
    }

    fn array_table_record<'a>(record: &'a str) -> &'a str {
        record
            .find("\n[")
            .map_or(record, |next_header| &record[..next_header])
    }

    fn crate_section<'a>(
        evidence: &'a str,
        candidate: &'static str,
    ) -> Result<&'a str, StructuredEvidenceError> {
        bounded("evidence", evidence, MAX_EVIDENCE_BYTES)?;
        for item in evidence.split("[[crate]]").skip(1).take(8) {
            let item = array_table_record(item);
            if quoted_field("crate", item, "name").ok().as_deref() == Some(candidate) {
                return Ok(item);
            }
        }
        Err(StructuredEvidenceError::MissingSection { subject: candidate })
    }

    fn inline_table_fields<'a>(
        subject: &'static str,
        name: &'static str,
        body: &'a str,
    ) -> Result<Vec<(&'a str, &'a str)>, StructuredEvidenceError> {
        let mut fields = Vec::new();
        let mut start = 0;
        let mut nesting = 0_u8;
        let mut quoted = false;
        for (offset, character) in body.char_indices() {
            match character {
                '\"' => quoted = !quoted,
                '[' | '{' if !quoted => nesting = nesting.saturating_add(1),
                ']' | '}' if !quoted => nesting = nesting.saturating_sub(1),
                ',' if !quoted && nesting == 0 => {
                    let field = body[start..offset].trim();
                    let (key, value) =
                        field
                            .split_once('=')
                            .ok_or(StructuredEvidenceError::MalformedField {
                                subject,
                                field: name,
                            })?;
                    let key = key.trim();
                    if key.is_empty()
                        || !key
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
                        || fields.iter().any(|(existing, _)| *existing == key)
                    {
                        return Err(StructuredEvidenceError::MalformedField {
                            subject,
                            field: name,
                        });
                    }
                    fields.push((key, value.trim()));
                    start = offset + character.len_utf8();
                }
                _ => {}
            }
        }
        if quoted || nesting != 0 {
            return Err(StructuredEvidenceError::MalformedField {
                subject,
                field: name,
            });
        }
        let field = body[start..].trim();
        let (key, value) =
            field
                .split_once('=')
                .ok_or(StructuredEvidenceError::MalformedField {
                    subject,
                    field: name,
                })?;
        let key = key.trim();
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            || fields.iter().any(|(existing, _)| *existing == key)
        {
            return Err(StructuredEvidenceError::MalformedField {
                subject,
                field: name,
            });
        }
        fields.push((key, value.trim()));
        Ok(fields)
    }

    fn parse_dependency_selection(
        subject: &'static str,
        manifest: &str,
        name: &'static str,
    ) -> Result<DependencySelection, StructuredEvidenceError> {
        bounded(subject, manifest, 4_096)?;
        let dependencies = section(manifest, "[dependencies]")?;
        let value = field_value(subject, dependencies, name)?;
        let body = value
            .strip_prefix('{')
            .and_then(|body| body.strip_suffix('}'))
            .ok_or(StructuredEvidenceError::MalformedField {
                subject,
                field: name,
            })?;
        let attributes = inline_table_fields(subject, name, body)?;
        let mut version = None;
        let mut default_features = None;
        let mut features = None;
        for (key, value) in attributes {
            match key {
                "version" => {
                    version = value
                        .strip_prefix('\"')
                        .and_then(|value| value.strip_suffix('\"'))
                        .map(str::to_owned)
                }
                "default-features" => match value {
                    "false" => default_features = Some(false),
                    "true" => default_features = Some(true),
                    _ => {
                        return Err(StructuredEvidenceError::MalformedField {
                            subject,
                            field: name,
                        });
                    }
                },
                "features" => features = Some(parse_string_array_value(subject, name, value)?),
                _ => {
                    return Err(StructuredEvidenceError::MalformedField {
                        subject,
                        field: name,
                    });
                }
            }
        }
        Ok(DependencySelection {
            version: version.ok_or(StructuredEvidenceError::MissingField {
                subject,
                field: "version",
            })?,
            default_features: default_features.ok_or(StructuredEvidenceError::MissingField {
                subject,
                field: "default-features",
            })?,
            features: features.unwrap_or_default(),
        })
    }

    fn validate_selection(
        subject: &'static str,
        actual: &DependencySelection,
        version: &str,
        features: &[&str],
    ) -> Result<(), StructuredEvidenceError> {
        let expected = DependencySelection {
            version: version.to_owned(),
            default_features: false,
            features: features
                .iter()
                .map(|feature| (*feature).to_owned())
                .collect(),
        };
        if actual == &expected {
            Ok(())
        } else {
            Err(StructuredEvidenceError::UnexpectedValue {
                subject,
                field: "dependency selection",
                expected: format!("{expected:?}"),
                actual: format!("{actual:?}"),
            })
        }
    }

    fn validate_redis_selection(
        manifest: &str,
    ) -> Result<DependencySelection, StructuredEvidenceError> {
        let selection = parse_dependency_selection("redis manifest", manifest, "redis")?;
        for feature in &selection.features {
            if !["acl", "script"].contains(&feature.as_str()) {
                return Err(StructuredEvidenceError::ForbiddenFeature {
                    subject: "redis requested_features",
                    feature: feature.clone(),
                });
            }
        }
        validate_selection("redis manifest", &selection, "=1.4.1", &["acl", "script"])?;
        Ok(selection)
    }

    fn parse_lock(
        subject: &'static str,
        lock: &str,
    ) -> Result<Vec<LockPackage>, StructuredEvidenceError> {
        bounded(subject, lock, MAX_LOCK_BYTES)?;
        let mut packages = Vec::new();
        for item in lock.split("[[package]]").skip(1) {
            let item = array_table_record(item);
            let name = quoted_field(subject, item, "name")?;
            let version = quoted_field(subject, item, "version")?;
            let source = optional_field_value(subject, item, "source")?
                .and_then(|value| {
                    value
                        .strip_prefix('\"')
                        .and_then(|value| value.strip_suffix('\"'))
                })
                .map(str::to_owned);
            let checksum = optional_field_value(subject, item, "checksum")?
                .and_then(|value| {
                    value
                        .strip_prefix('\"')
                        .and_then(|value| value.strip_suffix('\"'))
                })
                .map(str::to_owned);
            let dependencies = if optional_field_value(subject, item, "dependencies")?.is_some() {
                string_array(subject, item, "dependencies")?
            } else {
                Vec::new()
            };
            packages.push(LockPackage {
                name,
                version,
                source,
                checksum,
                dependencies,
            });
        }
        if packages.len() > MAX_LOCK_PACKAGES {
            return Err(StructuredEvidenceError::InputTooLarge {
                subject,
                maximum: MAX_LOCK_PACKAGES,
            });
        }
        Ok(packages)
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        const INITIAL: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        const ROUND: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let mut message = bytes.to_vec();
        let bit_length = (message.len() as u64).wrapping_mul(8);
        message.push(0x80);
        while message.len() % 64 != 56 {
            message.push(0);
        }
        message.extend_from_slice(&bit_length.to_be_bytes());
        let mut state = INITIAL;
        for chunk in message.chunks_exact(64) {
            let mut words = [0_u32; 64];
            for (index, word) in words[..16].iter_mut().enumerate() {
                let offset = index * 4;
                *word = (u32::from(chunk[offset]) << 24)
                    | (u32::from(chunk[offset + 1]) << 16)
                    | (u32::from(chunk[offset + 2]) << 8)
                    | u32::from(chunk[offset + 3]);
            }
            for index in 16..64 {
                let small0 = words[index - 15].rotate_right(7)
                    ^ words[index - 15].rotate_right(18)
                    ^ (words[index - 15] >> 3);
                let small1 = words[index - 2].rotate_right(17)
                    ^ words[index - 2].rotate_right(19)
                    ^ (words[index - 2] >> 10);
                words[index] = words[index - 16]
                    .wrapping_add(small0)
                    .wrapping_add(words[index - 7])
                    .wrapping_add(small1);
            }
            let mut working = state;
            for (index, constant) in ROUND.iter().enumerate() {
                let big1 = working[4].rotate_right(6)
                    ^ working[4].rotate_right(11)
                    ^ working[4].rotate_right(25);
                let choose = (working[4] & working[5]) ^ (!working[4] & working[6]);
                let temporary1 = working[7]
                    .wrapping_add(big1)
                    .wrapping_add(choose)
                    .wrapping_add(*constant)
                    .wrapping_add(words[index]);
                let big0 = working[0].rotate_right(2)
                    ^ working[0].rotate_right(13)
                    ^ working[0].rotate_right(22);
                let majority = (working[0] & working[1])
                    ^ (working[0] & working[2])
                    ^ (working[1] & working[2]);
                let temporary2 = big0.wrapping_add(majority);
                working = [
                    temporary1.wrapping_add(temporary2),
                    working[0],
                    working[1],
                    working[2],
                    working[3].wrapping_add(temporary1),
                    working[4],
                    working[5],
                    working[6],
                ];
            }
            for (target, value) in state.iter_mut().zip(working) {
                *target = target.wrapping_add(value);
            }
        }
        state.iter().map(|word| format!("{word:08x}")).collect()
    }

    fn validate_lock(
        subject: &'static str,
        lock: &str,
        expected_bytes: usize,
        expected_hash: &str,
        expected_count: usize,
        direct_name: &'static str,
        direct_version: &str,
        direct_checksum: &str,
    ) -> Result<(), StructuredEvidenceError> {
        if lock.len() != expected_bytes || sha256_hex(lock.as_bytes()) != expected_hash {
            return Err(StructuredEvidenceError::UnexpectedValue {
                subject,
                field: "lock byte/hash binding",
                expected: format!("{expected_bytes}:{expected_hash}"),
                actual: format!("{}:{}", lock.len(), sha256_hex(lock.as_bytes())),
            });
        }
        let packages = parse_lock(subject, lock)?;
        if packages.len() != expected_count {
            return Err(StructuredEvidenceError::UnexpectedValue {
                subject,
                field: "package_count",
                expected: expected_count.to_string(),
                actual: packages.len().to_string(),
            });
        }
        let direct = packages
            .iter()
            .find(|package| package.name == direct_name && package.version == direct_version)
            .ok_or(StructuredEvidenceError::MissingSection {
                subject: direct_name,
            })?;
        if direct.checksum.as_deref() != Some(direct_checksum) {
            return Err(StructuredEvidenceError::UnexpectedValue {
                subject,
                field: "direct checksum",
                expected: direct_checksum.to_owned(),
                actual: format!("{:?}", direct.checksum),
            });
        }
        for package in &packages {
            if package
                .source
                .as_deref()
                .is_some_and(|source| source.starts_with("registry+"))
            {
                let checksum =
                    package
                        .checksum
                        .as_deref()
                        .ok_or(StructuredEvidenceError::MissingField {
                            subject,
                            field: "registry checksum",
                        })?;
                if checksum.len() != 64
                    || !checksum
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                {
                    return Err(StructuredEvidenceError::MalformedField {
                        subject,
                        field: "registry checksum",
                    });
                }
            }
            for dependency in &package.dependencies {
                let mut words = dependency.split_whitespace();
                let dependency_name =
                    words
                        .next()
                        .ok_or(StructuredEvidenceError::MalformedField {
                            subject,
                            field: "dependency edge",
                        })?;
                let dependency_version = words.next();
                if words.next().is_some()
                    || !packages.iter().any(|candidate| {
                        candidate.name == dependency_name
                            && dependency_version.is_none_or(|version| candidate.version == version)
                    })
                {
                    return Err(StructuredEvidenceError::MalformedField {
                        subject,
                        field: "dependency edge",
                    });
                }
            }
        }
        Ok(())
    }

    fn validate_recorded_bytes(
        evidence: &str,
        header: &'static str,
        field_prefix: &'static str,
        actual: &str,
    ) -> Result<(), StructuredEvidenceError> {
        let probe = section(evidence, header)?;
        let bytes_field = match field_prefix {
            "manifest" => "manifest_bytes",
            "lock" => "lock_bytes",
            "source" => "source_bytes",
            _ => unreachable!("fixed validator field prefix"),
        };
        let hash_field = match field_prefix {
            "manifest" => "manifest_sha256",
            "lock" => "lock_sha256",
            "source" => "source_sha256",
            _ => unreachable!("fixed validator field prefix"),
        };
        let expected_bytes = usize_field(header, probe, bytes_field)?;
        let expected_hash = quoted_field(header, probe, hash_field)?;
        let actual_hash = sha256_hex(actual.as_bytes());
        if actual.len() == expected_bytes && actual_hash == expected_hash {
            Ok(())
        } else {
            Err(StructuredEvidenceError::UnexpectedValue {
                subject: header,
                field: "recorded byte/hash binding",
                expected: format!("{bytes_field}={expected_bytes};{hash_field}={expected_hash}"),
                actual: format!("{bytes_field}={};{hash_field}={actual_hash}", actual.len()),
            })
        }
    }

    fn manifest_table<'a>(
        subject: &'static str,
        manifest: &'a str,
        header: &'static str,
    ) -> Result<&'a str, StructuredEvidenceError> {
        section(manifest, header).map_err(|_| StructuredEvidenceError::MissingSection { subject })
    }

    fn validate_exact_table_keys(
        subject: &'static str,
        table: &str,
        expected_keys: &[&str],
    ) -> Result<(), StructuredEvidenceError> {
        let mut actual_keys = structural_fields(subject, table)?
            .into_iter()
            .map(|(key, _)| key.to_owned())
            .collect::<Vec<_>>();
        actual_keys.sort();
        actual_keys.dedup();
        let mut expected_keys = expected_keys
            .iter()
            .map(|key| (*key).to_owned())
            .collect::<Vec<_>>();
        expected_keys.sort();
        if actual_keys == expected_keys {
            Ok(())
        } else {
            Err(StructuredEvidenceError::UnexpectedValue {
                subject,
                field: "exact table key set",
                expected: format!("{expected_keys:?}"),
                actual: format!("{actual_keys:?}"),
            })
        }
    }

    fn validate_manifest_contract(
        subject: &'static str,
        manifest: &str,
        package_name: &'static str,
        dependency_keys: &[&str],
    ) -> Result<(), StructuredEvidenceError> {
        bounded(subject, manifest, 4096)?;
        let package = manifest_table(subject, manifest, "[package]")?;
        validate_exact_table_keys(subject, package, &["name", "version", "edition", "publish"])?;
        expect_string(subject, package, "name", package_name)?;
        expect_string(subject, package, "version", "0.0.0")?;
        expect_string(subject, package, "edition", "2024")?;
        if boolean_field(subject, package, "publish")? {
            return Err(StructuredEvidenceError::UnexpectedValue {
                subject,
                field: "publish",
                expected: "false".to_owned(),
                actual: "true".to_owned(),
            });
        }
        let dependencies = manifest_table(subject, manifest, "[dependencies]")?;
        let mut actual_keys = structural_fields(subject, dependencies)?
            .into_iter()
            .map(|(key, _)| key.to_owned())
            .collect::<Vec<_>>();
        actual_keys.sort();
        let mut expected_keys = dependency_keys
            .iter()
            .map(|key| (*key).to_owned())
            .collect::<Vec<_>>();
        expected_keys.sort();
        if actual_keys != expected_keys {
            return Err(StructuredEvidenceError::UnexpectedValue {
                subject,
                field: "dependency key set",
                expected: format!("{expected_keys:?}"),
                actual: format!("{actual_keys:?}"),
            });
        }
        let lib = manifest_table(subject, manifest, "[lib]")?;
        validate_exact_table_keys(subject, lib, &["path"])?;
        expect_string(subject, lib, "path", "src/lib.rs")?;
        let workspace = manifest_table(subject, manifest, "[workspace]")?;
        validate_exact_table_keys(subject, workspace, &["resolver"])?;
        expect_string(subject, workspace, "resolver", "3")?;
        Ok(())
    }

    fn validate_candidate_evidence(
        evidence: &str,
        subject: &'static str,
        name: &'static str,
        version: &'static str,
        requested: &[&str],
        allowed: &[&str],
        prohibited: &[&str],
        checksum: &'static str,
        license: &'static str,
        rust_version: &'static str,
    ) -> Result<(), StructuredEvidenceError> {
        let crate_evidence = crate_section(evidence, name)?;
        expect_string(subject, crate_evidence, "name", name)?;
        expect_string(subject, crate_evidence, "version", version)?;
        expect_string(
            subject,
            crate_evidence,
            "requirement",
            &format!("={version}"),
        )?;
        expect_false(subject, crate_evidence, "default_features")?;
        expect_array(subject, crate_evidence, "requested_features", requested)?;
        expect_array(subject, crate_evidence, "allowed_features", allowed)?;
        expect_array(subject, crate_evidence, "prohibited_features", prohibited)?;
        expect_string(subject, crate_evidence, "checksum_sha256", checksum)?;
        expect_string(subject, crate_evidence, "license", license)?;
        expect_string(subject, crate_evidence, "rust_version", rust_version)?;
        expect_false(subject, crate_evidence, "yanked")?;
        Ok(())
    }

    fn validate_probe_evidence(
        evidence: &str,
        header: &'static str,
        expected_count: usize,
        expected_direct_projection: &'static str,
        expected_active_features: &[&str],
        forbidden_packages: &[&str],
    ) -> Result<(), StructuredEvidenceError> {
        let probe = section(evidence, header)?;
        let recorded_count = usize_field(header, probe, "package_count")?;
        if recorded_count != expected_count {
            return Err(StructuredEvidenceError::UnexpectedValue {
                subject: header,
                field: "package_count",
                expected: expected_count.to_string(),
                actual: recorded_count.to_string(),
            });
        }
        expect_array(
            header,
            probe,
            "active_features_expected",
            expected_active_features,
        )?;
        expect_array(
            header,
            probe,
            "prohibited_packages_absent_from_lock",
            forbidden_packages,
        )?;
        let package_projection = string_array(header, probe, "package_projection")?;
        if !package_projection
            .iter()
            .any(|row| row == expected_direct_projection)
        {
            return Err(StructuredEvidenceError::MissingField {
                subject: header,
                field: "direct package projection",
            });
        }
        let license_msrv_projection = string_array(header, probe, "license_msrv_projection")?;
        if license_msrv_projection.is_empty()
            || license_msrv_projection
                .iter()
                .any(|row| row.split(" | ").count() != 3)
        {
            return Err(StructuredEvidenceError::MalformedField {
                subject: header,
                field: "license_msrv_projection",
            });
        }
        Ok(())
    }

    fn validate_projection_bindings(
        evidence: &str,
        header: &'static str,
        lock_subject: &'static str,
        lock: &str,
        frozen_license_msrv_rows_hash: &'static str,
    ) -> Result<(), StructuredEvidenceError> {
        let probe = section(evidence, header)?;
        let packages = parse_lock(lock_subject, lock)?;
        let package_rows = string_array(header, probe, "package_projection")?;
        let license_rows = string_array(header, probe, "license_msrv_projection")?;
        let license_rows_hash = sha256_hex(format!("{}\n", license_rows.join("\n")).as_bytes());
        if license_rows_hash != frozen_license_msrv_rows_hash {
            return Err(StructuredEvidenceError::UnexpectedValue {
                subject: header,
                field: "license_msrv_projection immutable value digest",
                expected: frozen_license_msrv_rows_hash.to_owned(),
                actual: license_rows_hash,
            });
        }
        let mut projected_packages = Vec::new();
        for row in &package_rows {
            let mut words = row.split_whitespace();
            let name = words
                .next()
                .ok_or(StructuredEvidenceError::MalformedField {
                    subject: header,
                    field: "package_projection",
                })?;
            let version = words
                .next()
                .ok_or(StructuredEvidenceError::MalformedField {
                    subject: header,
                    field: "package_projection",
                })?;
            let checksum = words.next();
            if words.next().is_some()
                || !packages.iter().any(|package| {
                    package.name == name
                        && package.version == version
                        && match (package.source.as_deref(), checksum) {
                            (None, Some("path")) => true,
                            (Some(source), Some(expected)) if source.starts_with("registry+") => {
                                package.checksum.as_deref() == Some(expected)
                            }
                            _ => false,
                        }
                })
            {
                return Err(StructuredEvidenceError::UnexpectedValue {
                    subject: header,
                    field: "package_projection",
                    expected: "exact package/version/source/checksum tuple bound to lock package"
                        .to_owned(),
                    actual: row.clone(),
                });
            }
            projected_packages.push(format!("{name} {version}"));
        }
        let mut lock_packages = packages
            .iter()
            .map(|package| format!("{} {}", package.name, package.version))
            .collect::<Vec<_>>();
        lock_packages.sort();
        projected_packages.sort();
        if projected_packages != lock_packages {
            return Err(StructuredEvidenceError::UnexpectedValue {
                subject: header,
                field: "package_projection bijection",
                expected: format!("{lock_packages:?}"),
                actual: format!("{projected_packages:?}"),
            });
        }
        let mut projected_registry_tuples = packages
            .iter()
            .filter(|package| {
                package
                    .source
                    .as_deref()
                    .is_some_and(|source| source.starts_with("registry+"))
            })
            .map(|package| {
                format!(
                    "{} {} {} {}",
                    package.name,
                    package.version,
                    package.source.as_deref().unwrap_or_default(),
                    package.checksum.as_deref().unwrap_or_default()
                )
            })
            .collect::<Vec<_>>();
        projected_registry_tuples.sort();
        let mut license_tuples = Vec::new();
        for row in &license_rows {
            let (identity, details) =
                row.split_once(" | ")
                    .ok_or(StructuredEvidenceError::MalformedField {
                        subject: header,
                        field: "license_msrv_projection",
                    })?;
            let mut detail_fields = details.split(" | ");
            let license = detail_fields.next();
            let msrv = detail_fields.next();
            if license.is_none() || msrv.is_none() || detail_fields.next().is_some() {
                return Err(StructuredEvidenceError::MalformedField {
                    subject: header,
                    field: "license_msrv_projection",
                });
            }
            let mut words = identity.split_whitespace();
            let name = words
                .next()
                .ok_or(StructuredEvidenceError::MalformedField {
                    subject: header,
                    field: "license_msrv_projection",
                })?;
            let version = words
                .next()
                .ok_or(StructuredEvidenceError::MalformedField {
                    subject: header,
                    field: "license_msrv_projection",
                })?;
            if words.next().is_some() {
                return Err(StructuredEvidenceError::MalformedField {
                    subject: header,
                    field: "license_msrv_projection",
                });
            }
            let package = packages
                .iter()
                .find(|package| {
                    package.name == name
                        && package.version == version
                        && package
                            .source
                            .as_deref()
                            .is_some_and(|source| source.starts_with("registry+"))
                })
                .ok_or(StructuredEvidenceError::UnexpectedValue {
                    subject: header,
                    field: "license_msrv_projection",
                    expected: "registry package key with source/checksum".to_owned(),
                    actual: row.clone(),
                })?;
            let checksum =
                package
                    .checksum
                    .as_deref()
                    .ok_or(StructuredEvidenceError::MissingField {
                        subject: header,
                        field: "license_msrv_projection checksum",
                    })?;
            license_tuples.push(format!(
                "{name} {version} {} {checksum} | {} | {}",
                package.source.as_deref().unwrap_or_default(),
                license.unwrap_or_default(),
                msrv.unwrap_or_default()
            ));
        }
        license_tuples.sort();
        let license_package_tuples = license_tuples
            .iter()
            .map(|tuple| {
                tuple
                    .split_once(" | ")
                    .map_or_else(|| tuple.clone(), |(left, _)| left.to_owned())
            })
            .collect::<Vec<_>>();
        if license_package_tuples != projected_registry_tuples {
            return Err(StructuredEvidenceError::UnexpectedValue {
                subject: header,
                field: "license_msrv_projection full tuple bijection",
                expected: format!("{projected_registry_tuples:?}"),
                actual: format!("{license_package_tuples:?}"),
            });
        }
        Ok(())
    }

    fn target_union(
        evidence: &str,
        candidate: &'static str,
    ) -> Result<Vec<String>, StructuredEvidenceError> {
        bounded("evidence", evidence, MAX_EVIDENCE_BYTES)?;
        let mut targets = Vec::new();
        let mut matched = 0;
        for projection in evidence.split("[[target_projection]]").skip(1).take(16) {
            let projection = array_table_record(projection);
            if quoted_field("target projection", projection, "candidate")
                .ok()
                .as_deref()
                == Some(candidate)
            {
                expect_false("target projection", projection, "compile_verified")?;
                targets.extend(string_array("target projection", projection, "targets")?);
                matched += 1;
            }
        }
        if matched == 0 {
            return Err(StructuredEvidenceError::MissingSection { subject: candidate });
        }
        targets.sort();
        targets.dedup();
        Ok(targets)
    }

    fn expect_targets(
        evidence: &str,
        candidate: &'static str,
        expected: &[&str],
    ) -> Result<(), StructuredEvidenceError> {
        let actual = target_union(evidence, candidate)?;
        let mut expected = expected
            .iter()
            .map(|target| (*target).to_owned())
            .collect::<Vec<_>>();
        expected.sort();
        if actual == expected {
            Ok(())
        } else {
            Err(StructuredEvidenceError::UnexpectedValue {
                subject: candidate,
                field: "target union",
                expected: format!("{expected:?}"),
                actual: format!("{actual:?}"),
            })
        }
    }

    fn validate_target_rows(evidence: &str) -> Result<(), StructuredEvidenceError> {
        let rows = evidence
            .split("[[target_projection]]")
            .skip(1)
            .take(9)
            .map(array_table_record)
            .collect::<Vec<_>>();
        let expected: [(&str, &[&str], &str); 8] = [
            (
                "envelope",
                &["x86_64-unknown-linux-gnu", "x86_64-apple-darwin"],
                "cpufeatures is reachable through the x86-only chacha20 and poly1305 edges, but its libc edges are a lock-only false cross-product because they require aarch64/loongarch64. Ordinary x86 runtime dispatch reaches AVX512 when chacha20_avx512 is set; forced AVX512 additionally requires chacha20_backend=avx512 plus compile-time avx512f and avx512vl. AVX2/SSE2, poly1305 AVX2/autodetect, and cmov x86 assembly are also reachable; exact native cfg/codegen verification remains pending.",
            ),
            (
                "envelope",
                &["aarch64-unknown-linux-gnu", "aarch64-apple-darwin"],
                "chacha20 AArch64/NEON and cmov AArch64 assembly are statically reachable. cpufeatures and libc are not reachable because both parent cpufeatures edges are x86-only; exact native cfg/codegen and constant-time verification remains pending.",
            ),
            (
                "envelope",
                &["x86_64-pc-windows-msvc"],
                "cpufeatures, chacha20 AVX2/SSE2 and ordinary-runtime AVX512 dispatch (when chacha20_avx512 is set) form the static target surface; forced AVX512 additionally requires chacha20_backend=avx512 plus avx512f and avx512vl. Poly1305 AVX2/autodetect and cmov x86 assembly are also reachable. libc is lock-only and unreachable because cpufeatures has no x86/Windows libc edge; exact native cfg/codegen and symbol inventory remains pending.",
            ),
            (
                "capability-fs",
                &["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"],
                "rustix, rustix-linux-procfs, libc, linux-raw-sys, and target-rustc feature probes are reachable.",
            ),
            (
                "capability-fs",
                &["x86_64-apple-darwin", "aarch64-apple-darwin"],
                "rustix/libc and target-rustc feature probes are reachable; rustix-linux-procfs is Linux-only.",
            ),
            (
                "capability-fs",
                &["x86_64-pc-windows-msvc"],
                "windows-sys/winx plus windows_by_handle/windows_file_type_ext feature probes are reachable; ReFS identity and reparse behavior remain unqualified.",
            ),
            (
                "redis",
                &[
                    "x86_64-unknown-linux-gnu",
                    "aarch64-unknown-linux-gnu",
                    "x86_64-apple-darwin",
                    "aarch64-apple-darwin",
                ],
                "socket2/libc and the unconditional TCP plus ambient Unix connector surfaces are reachable.",
            ),
            (
                "redis",
                &["x86_64-pc-windows-msvc"],
                "socket2/windows-sys and unconditional TCP surface are reachable; Unix variant is unavailable. TASKR-01 Redis support remains unavailable on Windows.",
            ),
        ];
        if rows.len() != expected.len() {
            return Err(StructuredEvidenceError::UnexpectedValue {
                subject: "target_projection",
                field: "row cardinality",
                expected: expected.len().to_string(),
                actual: rows.len().to_string(),
            });
        }
        for (row, (candidate, targets, static_delta)) in rows.into_iter().zip(expected) {
            expect_string("target_projection", row, "candidate", candidate)?;
            expect_array("target_projection", row, "targets", targets)?;
            expect_string("target_projection", row, "static_delta", static_delta)?;
            expect_false("target_projection", row, "compile_verified")?;
        }
        Ok(())
    }

    fn validate_state_table_inventory(evidence: &str) -> Result<(), StructuredEvidenceError> {
        bounded("state table inventory", evidence, MAX_EVIDENCE_BYTES)?;
        let mut regular = std::collections::BTreeMap::<String, usize>::new();
        let mut arrays = std::collections::BTreeMap::<String, usize>::new();
        for line in evidence.lines() {
            let header = line.trim_start();
            if !header.starts_with('[') {
                continue;
            }
            let (name, trailing, target) = if let Some(rest) = header.strip_prefix("[[") {
                let (name, trailing) =
                    rest.split_once("]]")
                        .ok_or(StructuredEvidenceError::MalformedField {
                            subject: "state table inventory",
                            field: "TOML array-table header",
                        })?;
                (name.trim(), trailing.trim_start(), &mut arrays)
            } else {
                let (name, trailing) = header
                    .strip_prefix('[')
                    .and_then(|rest| rest.split_once(']'))
                    .ok_or(StructuredEvidenceError::MalformedField {
                        subject: "state table inventory",
                        field: "TOML table header",
                    })?;
                (name.trim(), trailing.trim_start(), &mut regular)
            };
            if !trailing.is_empty() && !trailing.starts_with('#') {
                return Err(StructuredEvidenceError::MalformedField {
                    subject: "state table inventory",
                    field: "TOML table-header trailing content",
                });
            }
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
            {
                return Err(StructuredEvidenceError::MalformedField {
                    subject: "state table inventory",
                    field: "TOML table header",
                });
            }
            *target.entry(name.to_owned()).or_default() += 1;
        }
        let expected_regular = [
            "advisory_snapshot",
            "bounds.capability_fs",
            "bounds.envelope",
            "bounds.redis",
            "current_revalidation",
            "current_workspace_gap",
            "gate",
            "handoff",
            "policy",
            "probe.capability_fs",
            "probe.envelope",
            "probe.redis",
            "rematerialized_hard_gate",
            "reproduction",
            "toolchain",
            "xc20p_tcb_assertion",
            "xc20p_tcb_gate",
        ];
        let expected_regular = expected_regular
            .into_iter()
            .map(|name| (name.to_owned(), 1_usize))
            .collect::<std::collections::BTreeMap<_, _>>();
        let expected_arrays = [
            ("build_script", 6_usize),
            ("crate", 4),
            ("negative_evidence", 39),
            ("source_finding", 20),
            ("target_projection", 8),
            ("xc20p_tcb_path", 14),
        ]
        .into_iter()
        .map(|(name, count)| (name.to_owned(), count))
        .collect::<std::collections::BTreeMap<_, _>>();
        if regular != expected_regular || arrays != expected_arrays {
            return Err(StructuredEvidenceError::UnexpectedValue {
                subject: "state table inventory",
                field: "known unique table headers and records",
                expected: format!("regular={expected_regular:?}; arrays={expected_arrays:?}"),
                actual: format!("regular={regular:?}; arrays={arrays:?}"),
            });
        }
        Ok(())
    }

    fn validate_crate_records(evidence: &str) -> Result<(), StructuredEvidenceError> {
        let mut names = Vec::new();
        for record in evidence.split("[[crate]]").skip(1) {
            let record = array_table_record(record);
            names.push(quoted_field("crate record", record, "name")?);
        }
        names.sort();
        let expected = ["cap-fs-ext", "cap-std", "chacha20poly1305", "redis"]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if names != expected {
            return Err(StructuredEvidenceError::UnexpectedValue {
                subject: "crate record",
                field: "exact unique candidate records",
                expected: format!("{expected:?}"),
                actual: format!("{names:?}"),
            });
        }
        Ok(())
    }

    fn validate_frozen_contract(
        inputs: &Inputs,
    ) -> Result<AcceptedContractState, StructuredEvidenceError> {
        #[allow(non_snake_case)]
        let state = inputs.state.as_str();
        #[allow(non_snake_case)]
        let envelope_manifest = inputs.envelope_manifest.as_str();
        #[allow(non_snake_case)]
        let envelope_lock = inputs.envelope_lock.as_str();
        #[allow(non_snake_case)]
        let capability_fs_manifest = inputs.capability_fs_manifest.as_str();
        #[allow(non_snake_case)]
        let capability_fs_lock = inputs.capability_fs_lock.as_str();
        #[allow(non_snake_case)]
        let redis_manifest = inputs.redis_manifest.as_str();
        #[allow(non_snake_case)]
        let redis_lock = inputs.redis_lock.as_str();
        bounded("envelope lock", envelope_lock, MAX_LOCK_BYTES)?;
        bounded("capability-fs lock", capability_fs_lock, MAX_LOCK_BYTES)?;
        bounded("redis lock", redis_lock, MAX_LOCK_BYTES)?;
        validate_state_table_inventory(state)?;
        validate_crate_records(state)?;
        validate_recorded_bytes(state, "[probe.envelope]", "manifest", envelope_manifest)?;
        validate_recorded_bytes(state, "[probe.envelope]", "lock", envelope_lock)?;
        validate_recorded_bytes(
            state,
            "[probe.envelope]",
            "source",
            inputs.envelope_source.as_str(),
        )?;
        validate_recorded_bytes(
            state,
            "[probe.capability_fs]",
            "manifest",
            capability_fs_manifest,
        )?;
        validate_recorded_bytes(state, "[probe.capability_fs]", "lock", capability_fs_lock)?;
        validate_recorded_bytes(
            state,
            "[probe.capability_fs]",
            "source",
            inputs.capability_fs_source.as_str(),
        )?;
        validate_recorded_bytes(state, "[probe.redis]", "manifest", redis_manifest)?;
        validate_recorded_bytes(state, "[probe.redis]", "lock", redis_lock)?;
        validate_manifest_contract(
            "envelope manifest",
            envelope_manifest,
            "fastmcp-fnd01-envelope-probe",
            &["chacha20poly1305"],
        )?;
        validate_manifest_contract(
            "capability-fs manifest",
            capability_fs_manifest,
            "fastmcp-fnd01-capability-fs-probe",
            &["cap-fs-ext", "cap-std"],
        )?;
        validate_manifest_contract(
            "redis manifest",
            redis_manifest,
            "fastmcp-fnd01-redis-probe",
            &["redis"],
        )?;

        let hard_gate = section(state, "[rematerialized_hard_gate]")?;
        expect_string(
            "rematerialized hard gate",
            hard_gate,
            "owner",
            "bd-mcp-2026-07-28-support-ahet.1.13",
        )?;
        expect_array(
            "rematerialized hard gate",
            hard_gate,
            "test_ids",
            &[
                "tests::fnd_01_state_capability_dependencies_positive",
                "tests::fnd_01_state_capability_dependencies_planted_negative",
            ],
        )?;
        expect_array(
            "rematerialized hard gate",
            hard_gate,
            "coverage",
            &[
                "envelope: exact manifest selection; frozen candidate checksum/license/MSRV/features; lock count/direct checksum/registry checksum shape; RNG absence; frozen target union",
                "capability-filesystem: exact cap-fs-ext and cap-std selections; frozen checksums/licenses/MSRVs/features; lock count/direct checksum/registry checksum shape; Tokio/smol/aio absence; frozen target union",
                "redis: exact acl+script selection; all frozen prohibited Redis features including cluster/aio/Tokio/smol/TLS/connection-manager; frozen checksum/license/MSRV; lock count/direct checksum/registry checksum shape; prohibited package absence; advisory/target/persistence boundaries",
            ],
        )?;
        expect_array(
            "rematerialized hard gate",
            hard_gate,
            "unverified_required_facts",
            &[
                "archive bytes are unavailable at the recorded local cache paths, so current archive rehash and full transitive license/MSRV provenance remain unverified",
                "canonical normal/build/feature/dev graph receipts, target compilation, and advisory execution remain false pending the serialized owners",
                "constant-time target qualification, filesystem semantics, bounded Redis connector/parser, peer identity, and Redis profile support remain false",
            ],
        )?;

        let envelope =
            parse_dependency_selection("envelope manifest", envelope_manifest, "chacha20poly1305")?;
        let capability_fs_extension = parse_dependency_selection(
            "capability-fs manifest",
            capability_fs_manifest,
            "cap-fs-ext",
        )?;
        let capability_fs_root = parse_dependency_selection(
            "capability-fs manifest",
            capability_fs_manifest,
            "cap-std",
        )?;
        let redis = validate_redis_selection(redis_manifest)?;
        validate_selection(
            "envelope manifest",
            &envelope,
            "=0.11.0",
            &["alloc", "zeroize"],
        )?;
        validate_selection(
            "capability-fs manifest",
            &capability_fs_extension,
            "=4.0.2",
            &["std"],
        )?;
        validate_selection("capability-fs manifest", &capability_fs_root, "=4.0.2", &[])?;

        validate_candidate_evidence(
            state,
            "envelope evidence",
            "chacha20poly1305",
            "0.11.0",
            &["alloc", "zeroize"],
            &["alloc", "zeroize"],
            &[
                "default",
                "arrayvec",
                "bytes",
                "getrandom",
                "rand_core",
                "reduced-round",
            ],
            "9b89e1c441e926b9c82a8d023f6e1b7ae0adcfaa7d621814e4d60789bac751cb",
            "Apache-2.0 OR MIT",
            "1.85",
        )?;
        validate_candidate_evidence(
            state,
            "capability-fs root evidence",
            "cap-std",
            "4.0.2",
            &[],
            &["default"],
            &["arf_strings", "fs_utf8"],
            "7281235d6e96d3544ca18bba9049be92f4190f8d923e3caef1b5f66cfa752608",
            "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT",
            "",
        )?;
        validate_candidate_evidence(
            state,
            "capability-fs extension evidence",
            "cap-fs-ext",
            "4.0.2",
            &["std"],
            &["std"],
            &["default", "arf_strings", "fs_utf8"],
            "d78e5a3368ae89b7cb68186411452b4b9fac8b41be9c19bf3f47c2d2c8e36e6b",
            "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT",
            "",
        )?;
        validate_candidate_evidence(
            state,
            "redis evidence",
            "redis",
            "1.4.1",
            &["acl", "script"],
            &["acl", "script"],
            &[
                "default",
                "ahash",
                "aio",
                "bb8",
                "bigdecimal",
                "bloom",
                "bytes",
                "cache-aio",
                "cluster",
                "cluster-async",
                "connection-manager",
                "entra-id",
                "geospatial",
                "hashbrown",
                "json",
                "num-bigint",
                "r2d2",
                "rust_decimal",
                "sentinel",
                "smol-comp",
                "smol-native-tls-comp",
                "smol-rustls-comp",
                "streams",
                "tls-native-tls",
                "tls-rustls",
                "tls-rustls-insecure",
                "tls-rustls-webpki-roots",
                "token-based-authentication",
                "tokio-comp",
                "tokio-native-tls-comp",
                "tokio-rustls-comp",
                "uuid",
                "vector-sets",
            ],
            "b0b9503711b03773e43b31668c7b5bd279ee7cd9b7d18cff7c23a42cc1d08e5a",
            "BSD-3-Clause",
            "1.88",
        )?;

        validate_probe_evidence(
            state,
            "[probe.envelope]",
            18,
            "chacha20poly1305 0.11.0 9b89e1c441e926b9c82a8d023f6e1b7ae0adcfaa7d621814e4d60789bac751cb",
            &[
                "chacha20poly1305/alloc",
                "chacha20poly1305/zeroize",
                "aead/alloc",
                "chacha20/xchacha",
                "chacha20/zeroize",
                "cipher/stream-wrapper",
            ],
            &["getrandom", "rand", "rand_core"],
        )?;
        validate_probe_evidence(
            state,
            "[probe.capability_fs]",
            41,
            "cap-fs-ext 4.0.2 d78e5a3368ae89b7cb68186411452b4b9fac8b41be9c19bf3f47c2d2c8e36e6b",
            &[
                "cap-fs-ext/std",
                "cap-std/default (empty feature, activated by cap-fs-ext's optional dependency edge)",
                "rustix/default,fs,process,termios,time",
            ],
            &["arf-strings", "camino", "tokio", "async-std", "smol"],
        )?;
        validate_probe_evidence(
            state,
            "[probe.redis]",
            50,
            "redis 1.4.1 b0b9503711b03773e43b31668c7b5bd279ee7cd9b7d18cff7c23a42cc1d08e5a",
            &[
                "redis/acl",
                "redis/script",
                "combine/std",
                "socket2/all",
                "url/default,std",
                "idna/alloc,compiled_data,std",
                "xxhash-rust/xxh3",
            ],
            &[
                "ahash",
                "arc-swap",
                "async-io",
                "async-lock",
                "async-native-tls",
                "backon",
                "bb8",
                "crc16",
                "futures-channel",
                "futures-rustls",
                "futures-util",
                "native-tls",
                "num-bigint",
                "rand",
                "rustls",
                "smol",
                "smol-timeout",
                "tokio",
                "tokio-native-tls",
                "tokio-rustls",
                "tokio-util",
            ],
        )?;

        validate_lock(
            "envelope lock",
            envelope_lock,
            4046,
            "f60c46fe85004ade47468d2b93441ab87551cd6a1cc6a9481eb75b199614c1e5",
            18,
            "chacha20poly1305",
            "0.11.0",
            "9b89e1c441e926b9c82a8d023f6e1b7ae0adcfaa7d621814e4d60789bac751cb",
        )?;
        validate_lock(
            "capability-fs lock",
            capability_fs_lock,
            9614,
            "a1962ecdf71a74787a4481cac2a8788581bb9dcb7fd2e459f81e5c3aabcbfe4c",
            41,
            "cap-fs-ext",
            "4.0.2",
            "d78e5a3368ae89b7cb68186411452b4b9fac8b41be9c19bf3f47c2d2c8e36e6b",
        )?;
        validate_lock(
            "capability-fs lock",
            capability_fs_lock,
            9614,
            "a1962ecdf71a74787a4481cac2a8788581bb9dcb7fd2e459f81e5c3aabcbfe4c",
            41,
            "cap-std",
            "4.0.2",
            "7281235d6e96d3544ca18bba9049be92f4190f8d923e3caef1b5f66cfa752608",
        )?;
        validate_lock(
            "redis lock",
            redis_lock,
            11713,
            "d2deaeced0e36efbd0232a3f4d1bf198de102a719d86d59eea7ed59b193ab029",
            50,
            "redis",
            "1.4.1",
            "b0b9503711b03773e43b31668c7b5bd279ee7cd9b7d18cff7c23a42cc1d08e5a",
        )?;
        validate_projection_bindings(
            state,
            "[probe.envelope]",
            "envelope lock",
            envelope_lock,
            "fdc2097796d6f17f16c077b7b0c306bd8ca0c2b8d0449ec98fa936684788ae1f",
        )?;
        validate_projection_bindings(
            state,
            "[probe.capability_fs]",
            "capability-fs lock",
            capability_fs_lock,
            "b6c9207a08283979144bcaf2f170b58daca1b31bbff355419a2d5186abfcd9f6",
        )?;
        validate_projection_bindings(
            state,
            "[probe.redis]",
            "redis lock",
            redis_lock,
            "20b4e7f176301d12cd682638bd9b1b3f10d4d89dc2ca1546acfb82cafdca5946",
        )?;
        let redis_packages = parse_lock("redis lock", redis_lock)?;
        if !redis_packages.iter().any(|package| {
            package.name == "sha1_smol"
                && package.version == "1.0.1"
                && package.checksum.as_deref()
                    == Some("bbfa15b3dddfee50a0fff136974b3e1bde555604ba463834a7eb7deb6417705d")
        }) {
            return Err(StructuredEvidenceError::MissingSection {
                subject: "sha1_smol 1.0.1",
            });
        }

        validate_packages_absent(
            "envelope prohibited_packages_absent_from_lock",
            envelope_lock,
            &["getrandom", "rand", "rand_core"],
        )?;
        validate_packages_absent(
            "capability-fs prohibited_packages_absent_from_lock",
            capability_fs_lock,
            &["arf-strings", "camino", "tokio", "smol", "async-std"],
        )?;
        validate_packages_absent(
            "redis prohibited_packages_absent_from_lock",
            redis_lock,
            &[
                "tokio",
                "smol",
                "async-std",
                "native-tls",
                "rustls",
                "connection-manager",
                "tokio-native-tls",
                "tokio-rustls",
                "futures-rustls",
                "async-native-tls",
            ],
        )?;

        let advisory = section(state, "[advisory_snapshot]")?;
        validate_exact_table_keys(
            "advisory snapshot",
            advisory,
            &[
                "repository",
                "local_path",
                "commit",
                "commit_time_utc",
                "worktree_clean",
                "advisory_count_from_frozen_fnd01_evidence",
                "audit_executed_for_these_locks",
                "audit_result",
                "ignore_list",
                "known_relevant_records",
                "known_relevant_record_hashes",
                "redis_direct_text_match",
            ],
        )?;
        expect_false(
            "advisory snapshot",
            advisory,
            "audit_executed_for_these_locks",
        )?;
        expect_string(
            "advisory snapshot",
            advisory,
            "repository",
            "https://github.com/RustSec/advisory-db",
        )?;
        expect_string(
            "advisory snapshot",
            advisory,
            "local_path",
            "/Users/jemanuel/.cargo/advisory-db",
        )?;
        expect_string(
            "advisory snapshot",
            advisory,
            "commit",
            "7c7ccac53056b87f69ac677f15ea2d9a98a6f8e2",
        )?;
        expect_string(
            "advisory snapshot",
            advisory,
            "commit_time_utc",
            "2026-07-29T15:17:10Z",
        )?;
        if !boolean_field("advisory snapshot", advisory, "worktree_clean")? {
            return Err(StructuredEvidenceError::UnexpectedValue {
                subject: "advisory snapshot",
                field: "worktree_clean",
                expected: "true".to_owned(),
                actual: "false".to_owned(),
            });
        }
        expect_string(
            "advisory snapshot",
            advisory,
            "audit_result",
            "pending bd-mcp-2026-07-28-support-ahet.1.1 RCH execution; .1.13 owns only the local hard-gate test source; .1.15 independently attests receipts; no clean claim",
        )?;
        if usize_field(
            "advisory snapshot",
            advisory,
            "advisory_count_from_frozen_fnd01_evidence",
        )? != 1173
        {
            return Err(StructuredEvidenceError::UnexpectedValue {
                subject: "advisory snapshot",
                field: "advisory_count_from_frozen_fnd01_evidence",
                expected: "1173".to_owned(),
                actual: usize_field(
                    "advisory snapshot",
                    advisory,
                    "advisory_count_from_frozen_fnd01_evidence",
                )?
                .to_string(),
            });
        }
        expect_array("advisory snapshot", advisory, "ignore_list", &[])?;
        expect_array(
            "advisory snapshot",
            advisory,
            "known_relevant_records",
            &[
                "RUSTSEC-2019-0029 chacha20 counter overflow; patched >=0.2.3; selected 0.10.1",
                "RUSTSEC-2024-0445 cap-primitives Windows superscript device-name sandbox bypass; patched >=3.4.1; selected 4.0.2",
                "RUSTSEC-2026-0003 cmov ARM32 non-constant-time code generation; patched >=0.4.4; selected 0.5.4; supported targets exclude ARM32",
            ],
        )?;
        expect_array(
            "advisory snapshot",
            advisory,
            "known_relevant_record_hashes",
            &[
                "RUSTSEC-2019-0029 f02361318232aa3202c954fd9cde3e2a688b0842f137d16ee22d042fac691c4c",
                "RUSTSEC-2024-0445 4e514b50d277c08caae1d01003aa26c6c0c2122cb796b07319cb4c92d598fcf3",
                "RUSTSEC-2026-0003 a78d8ba6c0ac1de3da9f0b94a771dcb24e0c8f02c8536b89e9f3268e082579d7",
            ],
        )?;
        expect_string(
            "advisory snapshot",
            advisory,
            "redis_direct_text_match",
            "none observed in the pinned local database; this is not a full-lock audit result",
        )?;
        expect_array(
            "policy",
            section(state, "[policy]")?,
            "prohibited_active_packages",
            &[
                "tokio",
                "smol",
                "async-std",
                "rand",
                "rand_core",
                "getrandom",
                "native-tls",
                "rustls",
                "hyper",
                "reqwest",
            ],
        )?;
        let policy = section(state, "[policy]")?;
        let global_prohibitions = string_array("policy", policy, "prohibited_active_packages")?;
        let global_prohibitions = global_prohibitions
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        validate_packages_absent(
            "policy prohibited_active_packages envelope",
            envelope_lock,
            &global_prohibitions,
        )?;
        validate_packages_absent(
            "policy prohibited_active_packages capability-fs",
            capability_fs_lock,
            &global_prohibitions,
        )?;
        validate_packages_absent(
            "policy prohibited_active_packages redis",
            redis_lock,
            &global_prohibitions,
        )?;
        for (candidate, targets) in [
            (
                "envelope",
                [
                    "x86_64-unknown-linux-gnu",
                    "aarch64-unknown-linux-gnu",
                    "x86_64-apple-darwin",
                    "aarch64-apple-darwin",
                    "x86_64-pc-windows-msvc",
                ],
            ),
            (
                "capability-fs",
                [
                    "x86_64-unknown-linux-gnu",
                    "aarch64-unknown-linux-gnu",
                    "x86_64-apple-darwin",
                    "aarch64-apple-darwin",
                    "x86_64-pc-windows-msvc",
                ],
            ),
            (
                "redis",
                [
                    "x86_64-unknown-linux-gnu",
                    "aarch64-unknown-linux-gnu",
                    "x86_64-apple-darwin",
                    "aarch64-apple-darwin",
                    "x86_64-pc-windows-msvc",
                ],
            ),
        ] {
            expect_targets(state, candidate, &targets)?;
        }
        validate_target_rows(state)?;
        expect_array(
            "policy",
            section(state, "[policy]")?,
            "supported_targets",
            &[
                "x86_64-unknown-linux-gnu",
                "aarch64-unknown-linux-gnu",
                "x86_64-apple-darwin",
                "aarch64-apple-darwin",
                "x86_64-pc-windows-msvc",
            ],
        )?;

        let gate = section(state, "[gate]")?;
        validate_exact_table_keys(
            "gate",
            gate,
            &[
                "direct_archive_checksums_verified",
                "direct_index_records_verified",
                "direct_license_files_verified",
                "direct_vcs_info_verified",
                "upstream_tags_verified",
                "isolated_lock_toml_parsed",
                "isolated_lock_archives_present",
                "isolated_lock_archive_checksums_verified",
                "cargo_lock_regeneration_verified",
                "canonical_normal_build_graphs_captured",
                "canonical_feature_graphs_captured",
                "canonical_dev_graphs_captured",
                "target_compilation_verified",
                "full_transitive_license_files_verified",
                "full_cfg_reachable_unsafe_ffi_panic_inventory_verified",
                "advisory_locks_audited",
                "constant_time_targets_verified",
                "xc20p_application_bounds_verified",
                "capability_filesystem_semantics_supported",
                "bounded_redis_connector",
                "bounded_redis_parser",
                "redis_peer_identity_proven",
                "redis_profile_supported",
                "workspace_manifests_integrated",
                "workspace_lock_integrated",
                "rch_compile_verified",
                "claim",
            ],
        )?;
        for field in [
            "direct_archive_checksums_verified",
            "direct_index_records_verified",
            "direct_license_files_verified",
            "direct_vcs_info_verified",
            "isolated_lock_toml_parsed",
            "isolated_lock_archives_present",
            "isolated_lock_archive_checksums_verified",
        ] {
            if !boolean_field("gate", gate, field)? {
                return Err(StructuredEvidenceError::UnexpectedValue {
                    subject: "gate",
                    field,
                    expected: "true".to_owned(),
                    actual: "false".to_owned(),
                });
            }
        }
        for field in [
            "cargo_lock_regeneration_verified",
            "canonical_normal_build_graphs_captured",
            "canonical_feature_graphs_captured",
            "canonical_dev_graphs_captured",
            "target_compilation_verified",
            "full_transitive_license_files_verified",
            "full_cfg_reachable_unsafe_ffi_panic_inventory_verified",
            "advisory_locks_audited",
            "constant_time_targets_verified",
            "xc20p_application_bounds_verified",
            "capability_filesystem_semantics_supported",
            "bounded_redis_connector",
            "bounded_redis_parser",
            "redis_peer_identity_proven",
            "redis_profile_supported",
            "workspace_manifests_integrated",
            "workspace_lock_integrated",
            "rch_compile_verified",
            "upstream_tags_verified",
        ] {
            expect_false("gate", gate, field)?;
        }
        expect_string(
            "gate",
            gate,
            "claim",
            "Direct immutable provenance and offline isolated lock/archive projections are frozen. All execution, target, semantic-support, bounded-Redis, and workspace integration gates remain fail-closed.",
        )?;
        let revalidation = section(state, "[current_revalidation]")?;
        expect_false(
            "current revalidation",
            revalidation,
            "archive_cache_paths_available_now",
        )?;
        let redis_bounds = section(state, "[bounds.redis]")?;
        validate_exact_table_keys(
            "redis bounds",
            redis_bounds,
            &[
                "recursion_depth_constant",
                "line_bytes_bound",
                "bulk_bytes_bound",
                "collection_count_bound",
                "aggregate_frame_bytes_bound",
                "scratch_bytes_bound",
                "resolver_address_count_bound",
                "connect_setup_retry_bound",
                "blocking_boundary",
            ],
        )?;
        if usize_field("redis bounds", redis_bounds, "recursion_depth_constant")? != 100 {
            return Err(StructuredEvidenceError::UnexpectedValue {
                subject: "redis bounds",
                field: "recursion_depth_constant",
                expected: "100".to_owned(),
                actual: usize_field("redis bounds", redis_bounds, "recursion_depth_constant")?
                    .to_string(),
            });
        }
        for field in [
            "line_bytes_bound",
            "bulk_bytes_bound",
            "collection_count_bound",
            "aggregate_frame_bytes_bound",
            "scratch_bytes_bound",
            "resolver_address_count_bound",
            "connect_setup_retry_bound",
        ] {
            expect_string("redis bounds", redis_bounds, field, "absent")?;
        }
        expect_string(
            "redis bounds",
            redis_bounds,
            "blocking_boundary",
            "synchronous crate; unmodified connector/parser cannot cross the TASKR-01 support gate",
        )?;
        let envelope_bounds = section(state, "[bounds.envelope]")?;
        validate_exact_table_keys(
            "envelope bounds",
            envelope_bounds,
            &[
                "key_bytes",
                "nonce_bytes",
                "tag_bytes",
                "block_bytes",
                "maximum_blocks_rejection_threshold",
                "largest_dependency_buffer_accepted_bytes",
                "application_limit",
                "associated_data_limit",
                "audit_report_verified",
                "constant_time_targets_verified",
            ],
        )?;
        for (field, expected) in [
            ("key_bytes", 32),
            ("nonce_bytes", 24),
            ("tag_bytes", 16),
            ("block_bytes", 64),
            ("maximum_blocks_rejection_threshold", 4_294_967_295),
            ("largest_dependency_buffer_accepted_bytes", 274_877_906_879),
        ] {
            if usize_field("envelope bounds", envelope_bounds, field)? != expected {
                return Err(StructuredEvidenceError::UnexpectedValue {
                    subject: "envelope bounds",
                    field,
                    expected: expected.to_string(),
                    actual: usize_field("envelope bounds", envelope_bounds, field)?.to_string(),
                });
            }
        }
        expect_string(
            "envelope bounds",
            envelope_bounds,
            "application_limit",
            "not supplied by this artifact; FND-08/LIMITS must impose a much smaller bound before allocation or crypto",
        )?;
        expect_string(
            "envelope bounds",
            envelope_bounds,
            "associated_data_limit",
            "u64 conversion only at dependency layer; FND-08 bound pending",
        )?;
        expect_false("envelope bounds", envelope_bounds, "audit_report_verified")?;
        expect_false(
            "envelope bounds",
            envelope_bounds,
            "constant_time_targets_verified",
        )?;
        let capability_bounds = section(state, "[bounds.capability_fs]")?;
        validate_exact_table_keys(
            "capability-fs bounds",
            capability_bounds,
            &[
                "path_component_bound",
                "symlink_scope",
                "blocking_boundary",
                "windows_identity",
            ],
        )?;
        expect_string(
            "capability-fs bounds",
            capability_bounds,
            "path_component_bound",
            "not supplied by these dependencies; FND-07 must admit and bound one normal relative component at a time",
        )?;
        expect_string(
            "capability-fs bounds",
            capability_bounds,
            "symlink_scope",
            "no-follow only controls final component",
        )?;
        expect_string(
            "capability-fs bounds",
            capability_bounds,
            "blocking_boundary",
            "all filesystem operations are synchronous and must run only through FND-04's guaranteed non-inline bounded blocking facility",
        )?;
        expect_string(
            "capability-fs bounds",
            capability_bounds,
            "windows_identity",
            "u64 projection is insufficient to claim ReFS identity correctness",
        )?;

        Ok(AcceptedContractState {
            envelope,
            capability_fs_extension,
            capability_fs_root,
            redis,
            graph_receipts_verified: false,
            archive_bytes_available: false,
            target_compilation_verified: false,
            advisory_execution_verified: false,
            redis_profile_supported: false,
        })
    }

    fn validate_full(inputs: &Inputs) -> Result<AcceptedContractState, StructuredEvidenceError> {
        let actual = inputs_digest(inputs)?;
        if actual != inputs.expected_domain_digest {
            return Err(StructuredEvidenceError::UnexpectedValue {
                subject: "Inputs",
                field: "supplied domain-separated Inputs digest",
                expected: inputs.expected_domain_digest.clone(),
                actual,
            });
        }
        validate_frozen_contract(inputs)
    }

    fn assert_fresh_baseline(accepted: &AcceptedContractState) {
        let baseline = Inputs::baseline();
        assert_eq!(
            inputs_digest(&baseline).expect("baseline digest must exclude only self source record"),
            FROZEN_INPUTS_DIGEST
        );
        assert_eq!(
            validate_full(&baseline).expect("baseline must remain valid"),
            accepted.clone()
        );
    }

    #[test]
    fn fnd_01_state_capability_dependencies_positive() {
        let baseline = Inputs::baseline();
        assert_eq!(
            inputs_digest(&baseline).expect("baseline digest must be available"),
            FROZEN_INPUTS_DIGEST
        );
        let accepted = validate_full(&baseline).expect("frozen candidate contract must validate");

        assert_eq!(accepted.redis.features, ["acl", "script"]);
        assert!(!accepted.graph_receipts_verified);
        assert!(!accepted.archive_bytes_available);
        assert!(!accepted.target_compilation_verified);
        assert!(!accepted.advisory_execution_verified);
        assert!(!accepted.redis_profile_supported);
        assert_eq!(
            script_sha1("return 1"),
            "e0e1f9fabfc9d4800c877a703b823ac0578ff8db"
        );
        assert!(matches!(
            tcp_address_surface("localhost".to_owned(), 6379),
            redis::ConnectionAddr::Tcp(host, 6379) if host == "localhost"
        ));
    }

    #[test]
    fn fnd_01_state_capability_dependencies_planted_negative() {
        let baseline = Inputs::baseline();
        let baseline_digest = inputs_digest(&baseline).expect("baseline digest must be available");
        assert_eq!(baseline_digest, FROZEN_INPUTS_DIGEST);
        let accepted_before = validate_full(&baseline).expect("baseline state must validate");
        let mut planted = Inputs::baseline();
        planted.redis_manifest = planted.redis_manifest.replace(
            REDIS_FEATURE_LINE,
            "redis={version=\"=1.4.1\",default-features=false,features=[\"acl\",\"script\",\"tokio-comp\"]}",
        );
        assert_eq!(baseline.redis_manifest.len(), planted.redis_manifest.len());
        planted.state = rebind_redis_manifest_mirror(&planted.state, &planted.redis_manifest)
            .expect("the virtual mirror must be derived from the planted manifest");
        planted
            .rebind_expected_domain_digest()
            .expect("planted expected digest must be derived from the virtual inputs");

        assert_eq!(semantic_input_change_count(&baseline, &planted), 1);
        assert_eq!(changed_input_count(&baseline, &planted), 2);
        assert_eq!(
            state_without_redis_manifest_mirror(&baseline.state)
                .expect("baseline mirror fields must exist"),
            state_without_redis_manifest_mirror(&planted.state)
                .expect("planted mirror fields must exist")
        );
        assert_eq!(
            planted.state,
            rebind_redis_manifest_mirror(&baseline.state, &planted.redis_manifest)
                .expect("only the target mirror may be rebound")
        );
        assert_ne!(
            baseline_digest,
            inputs_digest(&planted).expect("planted digest must be available")
        );
        let error = validate_full(&planted).expect_err("tokio-comp must be rejected");
        assert_eq!(
            error,
            StructuredEvidenceError::ForbiddenFeature {
                subject: "redis requested_features",
                feature: "tokio-comp".to_owned(),
            }
        );
        assert_eq!(
            error.stable_diagnostic(),
            "E_FORBIDDEN_FEATURE:redis requested_features:tokio-comp"
        );
        assert_fresh_baseline(&accepted_before);

        let mut double_terminal_comma = Inputs::baseline();
        let test_ids_tail = concat!(
            "  \"tests::fnd_01_state_capability_dependencies_planted_negative\",\n",
            "]",
        );
        let double_comma_tail = concat!(
            "  \"tests::fnd_01_state_capability_dependencies_planted_negative\",,\n",
            "]",
        );
        double_terminal_comma.state = double_terminal_comma.state.replacen(
            test_ids_tail,
            double_comma_tail,
            1,
        );
        double_terminal_comma
            .rebind_expected_domain_digest()
            .expect("double-comma expected digest must be derived");
        assert_eq!(changed_input_count(&baseline, &double_terminal_comma), 1);
        assert_eq!(semantic_input_change_count(&baseline, &double_terminal_comma), 0);
        assert_eq!(
            validate_full(&double_terminal_comma),
            Err(StructuredEvidenceError::MalformedField {
                subject: "rematerialized hard gate",
                field: "test_ids",
            })
        );
        assert_fresh_baseline(&accepted_before);

        for (label, replacement, expected) in [
            (
                "extra tokio dependency",
                format!("{REDIS_FEATURE_LINE}\ntokio={{version=\"1\"}}"),
                StructuredEvidenceError::UnexpectedValue {
                    subject: "redis manifest",
                    field: "dependency key set",
                    expected: "[\"redis\"]".to_owned(),
                    actual: "[\"redis\", \"tokio\"]".to_owned(),
                },
            ),
            (
                "duplicate dependency key",
                format!("{REDIS_FEATURE_LINE}\nredis={{version=\"=1.4.1\",default-features=false,features=[\"acl\",\"script\"]}}"),
                StructuredEvidenceError::UnexpectedValue {
                    subject: "redis manifest",
                    field: "duplicate TOML key",
                    expected: "unique keys".to_owned(),
                    actual: "redis".to_owned(),
                },
            ),
            (
                "quoted dependency key",
                REDIS_FEATURE_LINE.replacen("redis", "\"redis\"", 1),
                StructuredEvidenceError::MalformedField {
                    subject: "redis manifest",
                    field: "bare TOML key",
                },
            ),
            (
                "dotted dependency key",
                REDIS_FEATURE_LINE.replacen("redis", "redis.alias", 1),
                StructuredEvidenceError::MalformedField {
                    subject: "redis manifest",
                    field: "TOML key/value delimiter",
                },
            ),
            (
                "alias dependency key",
                REDIS_FEATURE_LINE.replacen(
                    "redis =",
                    "alias =",
                    1,
                ).replace(
                    "version = \"=1.4.1\"",
                    "package = \"redis\", version = \"=1.4.1\"",
                ),
                StructuredEvidenceError::UnexpectedValue {
                    subject: "redis manifest",
                    field: "dependency key set",
                    expected: "[\"redis\"]".to_owned(),
                    actual: "[\"alias\"]".to_owned(),
                },
            ),
        ] {
            let mut malformed = Inputs::baseline();
            malformed.redis_manifest = malformed
                .redis_manifest
                .replace(REDIS_FEATURE_LINE, &replacement);
            malformed.state = rebind_redis_manifest_mirror(&malformed.state, &malformed.redis_manifest)
                .unwrap_or_else(|error| panic!("{label}: mirror rebind failed: {error:?}"));
            malformed
                .rebind_expected_domain_digest()
                .unwrap_or_else(|error| panic!("{label}: expected digest rebind failed: {error:?}"));
            assert_eq!(
                validate_full(&malformed),
                Err(expected),
                "{label} must be rejected by the structural parser"
            );
            assert_eq!(semantic_input_change_count(&baseline, &malformed), 1);
            assert_eq!(
                state_without_redis_manifest_mirror(&baseline.state)
                    .expect("baseline mirror fields must exist"),
                state_without_redis_manifest_mirror(&malformed.state)
                    .expect("malformed mirror fields must exist")
            );
            assert_fresh_baseline(&accepted_before);
        }

        for replacement in [
            "redis={version=\"=1.4.1\",default-features=false,features=[\"acl\",,\"script\"]}",
            "redis={version=\"=1.4.1\",default-features=false,features=[\"acl\",\"script\",]}",
        ] {
            let mut malformed_array = Inputs::baseline();
            malformed_array.redis_manifest = malformed_array
                .redis_manifest
                .replace(REDIS_FEATURE_LINE, replacement);
            malformed_array.state = rebind_redis_manifest_mirror(
                &malformed_array.state,
                &malformed_array.redis_manifest,
            )
            .expect("array plant mirror must be derived");
            malformed_array
                .rebind_expected_domain_digest()
                .expect("array expected digest must be derived");
            assert_eq!(
                validate_full(&malformed_array),
                Err(StructuredEvidenceError::MalformedField {
                    subject: "redis manifest",
                    field: "redis",
                })
            );
            assert_eq!(semantic_input_change_count(&baseline, &malformed_array), 1);
            assert_fresh_baseline(&accepted_before);
        }

        let mut malformed_inline = Inputs::baseline();
        malformed_inline.redis_manifest = malformed_inline.redis_manifest.replace(
            REDIS_FEATURE_LINE,
            "redis={version=\"=1.4.1\",default-features=false,features=[\"acl\",\"script\"]",
        );
        malformed_inline.state =
            rebind_redis_manifest_mirror(&malformed_inline.state, &malformed_inline.redis_manifest)
                .expect("inline-table plant mirror must be derived");
        malformed_inline
            .rebind_expected_domain_digest()
            .expect("inline expected digest must be derived");
        assert_eq!(
            validate_full(&malformed_inline),
            Err(StructuredEvidenceError::MalformedField {
                subject: "redis manifest",
                field: "TOML value",
            })
        );
        assert_fresh_baseline(&accepted_before);

        let mut reordered = Inputs::baseline();
        reordered.redis_manifest = reordered.redis_manifest.replace(
            REDIS_FEATURE_LINE,
            "redis={features=[\"acl\",\"script\"],default-features=false,version=\"=1.4.1\"} # whitespace/order comment",
        );
        reordered.state = rebind_redis_manifest_mirror(&reordered.state, &reordered.redis_manifest)
            .expect("reordered mirror must be derived");
        reordered
            .rebind_expected_domain_digest()
            .expect("reordered expected digest must be derived");
        assert_eq!(
            validate_full(&reordered).expect("comment/spacing/order must not bypass or reject"),
            accepted_before
        );
        assert_fresh_baseline(&accepted_before);

        let mut mirror_only = Inputs::baseline();
        mirror_only.state = rebind_redis_manifest_mirror(
            &mirror_only.state,
            "redis={version=\"=1.4.1\",default-features=false,features=[\"acl\",\"script\",\"tokio-comp\"]}",
        )
        .expect("mirror-only plant must derive its altered mirror");
        mirror_only
            .rebind_expected_domain_digest()
            .expect("mirror-only expected digest must be derived");
        assert!(matches!(
            validate_full(&mirror_only),
            Err(StructuredEvidenceError::UnexpectedValue {
                subject: "[probe.redis]",
                field: "recorded byte/hash binding",
                ..
            })
        ));
        assert_eq!(semantic_input_change_count(&baseline, &mirror_only), 0);
        assert_fresh_baseline(&accepted_before);

        let mut whitespace_header = Inputs::baseline();
        whitespace_header.state = format!(
            "{}\n  [untrusted] # whitespace must not bypass the supplied digest\nvalue = 1\n",
            whitespace_header.state
        );
        assert!(matches!(
            validate_full(&whitespace_header),
            Err(StructuredEvidenceError::UnexpectedValue {
                subject: "Inputs",
                field: "supplied domain-separated Inputs digest",
                expected,
                ..
            }) if expected == FROZEN_INPUTS_DIGEST
        ));
        assert_fresh_baseline(&accepted_before);

        for (label, state) in [
            (
                "unknown trailing table",
                format!("{}\n[untrusted]\nvalue = 1\n", baseline.state),
            ),
            (
                "commented unknown trailing table",
                format!(
                    "{}\n[untrusted] # must not be ignored\nvalue = 1\n",
                    baseline.state
                ),
            ),
            (
                "duplicate trailing table",
                format!("{}\n[gate]\nclaim = \"duplicate\"\n", baseline.state),
            ),
            (
                "duplicate crate record",
                format!("{}\n[[crate]]\nname = \"redis\"\n", baseline.state),
            ),
            (
                "unknown gate field",
                baseline.state.replacen(
                    "rch_compile_verified = false\nclaim =",
                    "rch_compile_verified = false\nuntrusted = false\nclaim =",
                    1,
                ),
            ),
        ] {
            let mut malformed_state = Inputs::baseline();
            malformed_state.state = state;
            malformed_state
                .rebind_expected_domain_digest()
                .expect("state plant expected digest must be derived");
            let error = validate_full(&malformed_state)
                .expect_err("every state-header/record plant must fail closed");
            assert!(
                matches!(
                    error,
                    StructuredEvidenceError::UnexpectedValue {
                        subject: "state table inventory" | "gate",
                        ..
                    }
                ),
                "{label}: {error:?}"
            );
            assert_fresh_baseline(&accepted_before);
        }

        for (label, lock, expected_actual) in [
            (
                "alternate registry source",
                baseline.redis_lock.replacen(
                    "registry+https://github.com/rust-lang/crates.io-index",
                    "registry+https://example.invalid/index",
                    1,
                ),
                "lock_bytes=11698;lock_sha256=d3ea89518d958ec1c96f24051a89aeec5226f6f2bd6a536d0db718a78785e865",
            ),
            (
                "alternate registry checksum",
                baseline.redis_lock.replacen(
                    "checksum = \"03918c3dbd7701a85c6b9887732e2921175f26c350b4563841d0958c21d57e6d\"",
                    "checksum = \"0000000000000000000000000000000000000000000000000000000000000000\"",
                    1,
                ),
                "lock_bytes=11713;lock_sha256=02e4ec378a3deb718fc40a8a137187d9b8cbde5c3f0bb5a54f69f6bedc98d4ef",
            ),
        ] {
            let mut alternate_lock = Inputs::baseline();
            alternate_lock.redis_lock = lock;
            alternate_lock
                .rebind_expected_domain_digest()
                .expect("lock plant expected digest must be derived");
            assert_eq!(changed_input_count(&baseline, &alternate_lock), 1, "{label}");
            assert_eq!(
                semantic_input_change_count(&baseline, &alternate_lock),
                1,
                "{label}"
            );
            assert_eq!(alternate_lock.state, baseline.state, "{label}");
            let error = validate_full(&alternate_lock)
                .expect_err("one-field Redis lock plant must fail closed");
            let expected_binding = "lock_bytes=11713;lock_sha256=d2deaeced0e36efbd0232a3f4d1bf198de102a719d86d59eea7ed59b193ab029";
            assert_eq!(
                error,
                StructuredEvidenceError::UnexpectedValue {
                    subject: "[probe.redis]",
                    field: "recorded byte/hash binding",
                    expected: expected_binding.to_owned(),
                    actual: expected_actual.to_owned(),
                },
                "{label}"
            );
            assert_eq!(
                error.stable_diagnostic(),
                format!(
                    "E_UNEXPECTED_VALUE:[probe.redis]:recorded byte/hash binding:{expected_binding}:{expected_actual}"
                ),
                "{label}"
            );
            assert_fresh_baseline(&accepted_before);
        }
    }
}
