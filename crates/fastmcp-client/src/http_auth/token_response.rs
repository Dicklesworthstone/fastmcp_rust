//! Shared, bounded cache-policy admission for sensitive OAuth responses.
//!
//! Missing protective directives are diagnostic: they never grant permission
//! to cache a response. Explicit cacheable policy and ambiguous or malformed
//! directives are rejected before a caller can install returned credentials.

use std::collections::BTreeMap;

const MAX_HEADER_FIELDS: usize = 64;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_DIRECTIVES: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TokenCacheDiagnostics {
    pub(crate) missing_no_store: bool,
    pub(crate) missing_pragma_no_cache: bool,
}

/// Deliberately contains no peer-controlled header names or values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct InvalidTokenCachePolicy;

pub(crate) fn cache_policy(
    fields: &[(String, String)],
) -> Result<TokenCacheDiagnostics, InvalidTokenCachePolicy> {
    if fields.len() > MAX_HEADER_FIELDS {
        return Err(InvalidTokenCachePolicy);
    }
    let mut bytes = 0usize;
    let mut cache = String::new();
    let mut pragma = String::new();
    for (name, value) in fields {
        bytes = bytes
            .checked_add(name.len())
            .and_then(|n| n.checked_add(value.len()))
            .ok_or(InvalidTokenCachePolicy)?;
        if bytes > MAX_HEADER_BYTES {
            return Err(InvalidTokenCachePolicy);
        }
        let combined = if name.eq_ignore_ascii_case("cache-control") {
            &mut cache
        } else if name.eq_ignore_ascii_case("pragma") {
            &mut pragma
        } else {
            continue;
        };
        if !combined.is_empty() {
            combined.push(',');
        }
        combined.push_str(value);
    }
    let cache = directives(&cache)?;
    let pragma = directives(&pragma)?;
    for prohibited in [
        "public",
        "max-age",
        "s-maxage",
        "immutable",
        "stale-while-revalidate",
        "stale-if-error",
    ] {
        if cache.contains_key(prohibited) {
            return Err(InvalidTokenCachePolicy);
        }
    }
    for (name, values) in [
        ("no-store", &cache),
        ("no-cache", &cache),
        ("no-cache", &pragma),
    ] {
        if values.get(name).is_some_and(Option::is_some) {
            return Err(InvalidTokenCachePolicy);
        }
    }
    Ok(TokenCacheDiagnostics {
        missing_no_store: !cache.contains_key("no-store"),
        missing_pragma_no_cache: !pragma.contains_key("no-cache"),
    })
}

fn token_byte(byte: u8) -> bool {
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
                | 0x60
                | b'|'
                | b'~'
        )
}

// Combine field lines first, preserve quoted commas and reject conflicting
// duplicate directives. Admission never grants permission to cache a response.
fn directives(source: &str) -> Result<BTreeMap<String, Option<String>>, InvalidTokenCachePolicy> {
    let bytes = source.as_bytes();
    let mut at = 0;
    let mut count = 0;
    let mut result = BTreeMap::new();
    while at < bytes.len() {
        while bytes
            .get(at)
            .is_some_and(|b| matches!(b, b' ' | b'\t' | b','))
        {
            at += 1;
        }
        if at == bytes.len() {
            break;
        }
        count += 1;
        if count > MAX_DIRECTIVES {
            return Err(InvalidTokenCachePolicy);
        }
        let start = at;
        while bytes.get(at).is_some_and(|b| token_byte(*b)) {
            at += 1;
        }
        if at == start {
            return Err(InvalidTokenCachePolicy);
        }
        let name = source[start..at].to_ascii_lowercase();
        while bytes.get(at).is_some_and(|b| matches!(b, b' ' | b'\t')) {
            at += 1;
        }
        let value = if bytes.get(at) == Some(&b'=') {
            at += 1;
            while bytes.get(at).is_some_and(|b| matches!(b, b' ' | b'\t')) {
                at += 1;
            }
            let mut value = String::new();
            if bytes.get(at) == Some(&b'"') {
                at += 1;
                loop {
                    let byte = *bytes.get(at).ok_or(InvalidTokenCachePolicy)?;
                    at += 1;
                    match byte {
                        b'"' => break,
                        b'\\' => {
                            let escaped = *bytes.get(at).ok_or(InvalidTokenCachePolicy)?;
                            if !(0x20..=0x7e).contains(&escaped) && escaped != b'\t' {
                                return Err(InvalidTokenCachePolicy);
                            }
                            at += 1;
                            value.push(char::from(escaped));
                        }
                        b'\t' | 0x20..=0x21 | 0x23..=0x5b | 0x5d..=0x7e => {
                            value.push(char::from(byte));
                        }
                        _ => return Err(InvalidTokenCachePolicy),
                    }
                }
            } else {
                let start = at;
                while bytes.get(at).is_some_and(|b| token_byte(*b)) {
                    at += 1;
                }
                if at == start {
                    return Err(InvalidTokenCachePolicy);
                }
                value.push_str(&source[start..at]);
            }
            Some(value)
        } else {
            None
        };
        while bytes.get(at).is_some_and(|b| matches!(b, b' ' | b'\t')) {
            at += 1;
        }
        if at < bytes.len() && bytes[at] != b',' {
            return Err(InvalidTokenCachePolicy);
        }
        if let Some(previous) = result.get(&name) {
            if previous != &value {
                return Err(InvalidTokenCachePolicy);
            }
        } else {
            result.insert(name, value);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(name: &str, value: &str) -> (String, String) {
        (name.to_owned(), value.to_owned())
    }

    #[test]
    fn missing_protective_directives_are_diagnostic_and_safe_repetitions_combine() {
        assert_eq!(
            cache_policy(&[field("Content-Type", "application/json")]),
            Ok(TokenCacheDiagnostics {
                missing_no_store: true,
                missing_pragma_no_cache: true,
            })
        );
        let fields = [
            field("Cache-Control", "private, extension=\"a,b\""),
            field("cAcHe-CoNtRoL", "no-store, NO-STORE, extension=\"a,b\""),
            field("Pragma", "no-cache"),
            field("PRAGMA", "NO-CACHE"),
        ];
        assert_eq!(
            cache_policy(&fields),
            Ok(TokenCacheDiagnostics {
                missing_no_store: false,
                missing_pragma_no_cache: false,
            })
        );
        assert!(
            cache_policy(&[
                field("Cache-Control", "extension=\"a\\,b\""),
                field("Cache-Control", "extension=\"a,b\""),
            ])
            .is_ok()
        );
    }

    #[test]
    fn explicit_cacheable_policy_is_rejected_even_with_no_store() {
        for directive in [
            "public",
            "PUBLIC=true",
            "max-age=0",
            "s-maxage=1",
            "immutable",
            "stale-while-revalidate=60",
            "stale-if-error=60",
        ] {
            for protective in ["", "no-store, no-cache"] {
                assert_eq!(
                    cache_policy(&[
                        field("Cache-Control", protective),
                        field("cache-control", directive),
                        field("Pragma", "no-cache"),
                    ]),
                    Err(InvalidTokenCachePolicy),
                    "{directive}"
                );
            }
        }
    }

    #[test]
    fn malformed_or_conflicting_directives_cannot_hide_in_repeated_fields() {
        for directive in [
            "extension=other",
            "extension",
            "no-store=false",
            "no-cache=\"field\"",
            "=no-store",
            "broken=",
            "broken=\"unterminated",
            "broken=\"trailing\\",
            "broken=\"line\nbreak\"",
            "broken=value extra",
            "broken=\"value\"extra",
            "é",
        ] {
            assert_eq!(
                cache_policy(&[
                    field("Cache-Control", "no-store, extension=\"a,b\""),
                    field("CACHE-CONTROL", directive),
                ]),
                Err(InvalidTokenCachePolicy),
                "{directive}"
            );
        }
        for directive in ["no-cache=false", "extension=a, EXTENSION=b", "broken=\""] {
            assert_eq!(
                cache_policy(&[
                    field("Cache-Control", "no-store"),
                    field("Pragma", "no-cache"),
                    field("pragma", directive),
                ]),
                Err(InvalidTokenCachePolicy),
                "{directive}"
            );
        }
    }

    #[test]
    fn fields_bytes_and_combined_directives_have_fixed_admission_bounds() {
        let mut fields = vec![field("X-Extension", "ignored"); MAX_HEADER_FIELDS];
        assert!(cache_policy(&fields).is_ok());
        fields.push(field("Cache-Control", "no-store"));
        assert_eq!(cache_policy(&fields), Err(InvalidTokenCachePolicy));

        let padding = "x".repeat(MAX_HEADER_BYTES - "X-Padding".len());
        assert!(cache_policy(&[field("X-Padding", &padding)]).is_ok());
        assert_eq!(
            cache_policy(&[field("X-Padding", &format!("{padding}x"))]),
            Err(InvalidTokenCachePolicy)
        );

        for (name, directive) in [("Cache-Control", "no-store"), ("Pragma", "no-cache")] {
            let accepted = vec![directive; MAX_DIRECTIVES].join(",");
            assert!(cache_policy(&[field(name, &accepted)]).is_ok());
            assert_eq!(
                cache_policy(&[field(name, &accepted), field(name, directive)]),
                Err(InvalidTokenCachePolicy)
            );
        }
    }
}
