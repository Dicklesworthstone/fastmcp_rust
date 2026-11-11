//! Fixed XC20P FMCPBOX and typed FMCPENV v1 codecs.
//!
//! Only provider implementations construct headers. Consumer APIs never accept
//! a key, nonce or algorithm selector. Parsing validates the complete bounded
//! frame before an envelope can be used for provider routing.

use zeroize::Zeroizing;

use super::{ExpectedEnvelopeContext, MAX_AAD, MAX_ENVELOPE, PersistentEnvelopeError};

const BOX_MAGIC: &[u8; 8] = b"FMCPBOX\0";
const AAD_MAGIC: &[u8; 8] = b"FMCPENV\0";
const ALGORITHM: &[u8; 5] = b"XC20P";
const TAG_BYTES: usize = 16;
const NONCE_BYTES: usize = 24;

/// Validated provider-selected XC20P header. Construction is an adapter codec
/// facility; it cannot select crypto fields in a PersistentBlobStore operation.
pub struct PersistentEnvelopeHeader {
    key_id: String,
    generation: u64,
    nonce: [u8; NONCE_BYTES],
    sealed_bytes: usize,
}
impl PersistentEnvelopeHeader {
    pub fn xc20p(key_id: String, generation: u64, nonce: [u8; NONCE_BYTES])
        -> Result<Self, PersistentEnvelopeError>
    {
        if !key_identifier(&key_id) || generation == 0 {
            return Err(PersistentEnvelopeError::InvalidEnvelope);
        }
        Ok(Self { key_id, generation, nonce, sealed_bytes: 0 })
    }
    pub fn key_id(&self) -> &str { &self.key_id }
    pub const fn generation(&self) -> u64 { self.generation }
    pub const fn nonce(&self) -> &[u8; NONCE_BYTES] { &self.nonce }
    pub const fn algorithm_id(&self) -> &'static str { "XC20P" }
    /// Parsed ciphertext-plus-tag length; a newly constructed header has zero
    /// until it is encoded into a canonical envelope.
    pub const fn sealed_bytes(&self) -> usize { self.sealed_bytes }

    /// Encodes bounded ciphertext followed by its full 16-byte Poly1305 tag.
    /// This checks framing, not cryptographic authenticity or nonce uniqueness.
    pub fn encode(&self, ciphertext_and_tag: &[u8])
        -> Result<CanonicalEnvelope, PersistentEnvelopeError>
    {
        if ciphertext_and_tag.len() < TAG_BYTES {
            return Err(PersistentEnvelopeError::InvalidEnvelope);
        }
        let header_bytes = 55_usize.checked_add(self.key_id.len())
            .ok_or(PersistentEnvelopeError::TooLarge)?;
        let total = header_bytes.checked_add(ciphertext_and_tag.len())
            .ok_or(PersistentEnvelopeError::TooLarge)?;
        if total > MAX_ENVELOPE { return Err(PersistentEnvelopeError::TooLarge); }
        let sealed_length = u32::try_from(ciphertext_and_tag.len())
            .map_err(|_| PersistentEnvelopeError::TooLarge)?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.try_reserve_exact(total).map_err(|_| PersistentEnvelopeError::CapacityExceeded)?;
        bytes.extend_from_slice(BOX_MAGIC);
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.push(ALGORITHM.len() as u8);
        bytes.extend_from_slice(ALGORITHM);
        bytes.extend_from_slice(&(self.key_id.len() as u16).to_be_bytes());
        bytes.extend_from_slice(self.key_id.as_bytes());
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.push(NONCE_BYTES as u8);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&sealed_length.to_be_bytes());
        bytes.extend_from_slice(ciphertext_and_tag);
        debug_assert_eq!(bytes.len(), total);
        CanonicalEnvelope::from_bytes(bytes)
    }
}

/// Exclusive bounded raw envelope owner. No Clone/Debug/Serialize; untrusted
/// bytes are canonical-parsed before admission and never become request URLs.
pub struct CanonicalEnvelope {
    bytes: Zeroizing<Vec<u8>>,
    sealed_offset: usize,
}
impl CanonicalEnvelope {
    pub fn from_bytes(bytes: Zeroizing<Vec<u8>>) -> Result<Self, PersistentEnvelopeError> {
        if bytes.capacity() > MAX_ENVELOPE { return Err(PersistentEnvelopeError::TooLarge); }
        let (_, sealed_offset) = parse(&bytes)?;
        Ok(Self { bytes, sealed_offset })
    }
    pub fn as_bytes(&self) -> &[u8] { &self.bytes }
    pub fn allocated_bytes(&self) -> usize { self.bytes.capacity() }
    pub fn ciphertext_and_tag(&self) -> &[u8] { &self.bytes[self.sealed_offset..] }
    pub fn header(&self) -> Result<PersistentEnvelopeHeader, PersistentEnvelopeError> {
        parse(&self.bytes).map(|(header, _)| header)
    }
}

pub(super) fn key_identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

fn parse(bytes: &[u8]) -> Result<(PersistentEnvelopeHeader, usize), PersistentEnvelopeError> {
    let invalid = || PersistentEnvelopeError::InvalidEnvelope;
    if bytes.len() > MAX_ENVELOPE || bytes.len() < 72
        || bytes.get(..8) != Some(BOX_MAGIC.as_slice())
        || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
        || bytes.get(10) != Some(&5)
        || bytes.get(11..16) != Some(ALGORITHM.as_slice())
    { return Err(invalid()); }
    let key_bytes = u16::from_be_bytes(bytes.get(16..18).ok_or_else(invalid)?
        .try_into().map_err(|_| invalid())?) as usize;
    if !(1..=128).contains(&key_bytes) { return Err(invalid()); }
    let key_end = 18_usize.checked_add(key_bytes).ok_or_else(invalid)?;
    let key_id = std::str::from_utf8(bytes.get(18..key_end).ok_or_else(invalid)?)
        .map_err(|_| invalid())?;
    if !key_identifier(key_id) { return Err(invalid()); }
    let generation_end = key_end.checked_add(8).ok_or_else(invalid)?;
    let generation = u64::from_be_bytes(bytes.get(key_end..generation_end).ok_or_else(invalid)?
        .try_into().map_err(|_| invalid())?);
    if generation == 0 || bytes.get(generation_end) != Some(&24) { return Err(invalid()); }
    let nonce_start = generation_end + 1;
    let nonce_end = nonce_start + NONCE_BYTES;
    let nonce = bytes.get(nonce_start..nonce_end).ok_or_else(invalid)?
        .try_into().map_err(|_| invalid())?;
    let sealed_offset = nonce_end + 4;
    let sealed_bytes = u32::from_be_bytes(bytes.get(nonce_end..sealed_offset).ok_or_else(invalid)?
        .try_into().map_err(|_| invalid())?) as usize;
    if sealed_bytes < TAG_BYTES
        || sealed_offset.checked_add(sealed_bytes) != Some(bytes.len())
    { return Err(invalid()); }
    Ok((PersistentEnvelopeHeader {
        key_id: key_id.to_owned(), generation, nonce, sealed_bytes,
    }, sealed_offset))
}

/// Compile-time v1 registry. Process lifetime tags 32/33 are deliberately not
/// admitted here. Persistent binding tags 64/65 are required. Every value is
/// generated from closed typed framework facts, so no unknown/missing/custom
/// tag can enter this encoder.
pub(super) fn aad(context: &ExpectedEnvelopeContext<'_>, header: &PersistentEnvelopeHeader)
    -> Result<Vec<u8>, PersistentEnvelopeError>
{
    let generation = header.generation.to_be_bytes();
    let record_generation = context.index.generation.to_be_bytes();
    let purpose = 1_u64.to_be_bytes(); // ProtectedBlob
    let binding_digest = context.binding.digest();
    let epoch = context.binding.epoch().to_be_bytes();
    let storage_generation = context.blob_generation.to_be_bytes();
    let fields: [(u16, u8, &[u8]); 17] = [
        (1, 2, ALGORITHM),
        (2, 2, header.key_id.as_bytes()),
        (3, 3, &generation),
        (4, 1, &header.nonce),
        (5, 1, &[2]), // Persistent lifetime
        (6, 1, &context.deployment_uuid),
        (7, 1, &context.index.namespace),
        (8, 1, &context.index.record_id),
        (9, 3, &record_generation),
        (10, 3, &purpose),
        (11, 2, b"payload"),
        (12, 1, &context.store_set_digest),
        (13, 1, &context.blob_artifact_digest),
        (14, 1, &context.blob_configuration_fingerprint),
        (15, 3, &storage_generation),
        (64, 1, &binding_digest),
        (65, 4, &epoch),
    ];
    let mut total = 12_usize;
    for (_, _, value) in fields {
        total = total.checked_add(7).and_then(|n| n.checked_add(value.len()))
            .ok_or(PersistentEnvelopeError::TooLarge)?;
    }
    if context.aad_limit > MAX_AAD || total > context.aad_limit {
        return Err(PersistentEnvelopeError::TooLarge);
    }
    let mut out = Vec::new();
    // Reserve the complete encoded size before allocation or field copying.
    out.try_reserve_exact(total).map_err(|_| PersistentEnvelopeError::CapacityExceeded)?;
    out.extend_from_slice(AAD_MAGIC);
    out.extend_from_slice(&1_u16.to_be_bytes());
    out.extend_from_slice(&(fields.len() as u16).to_be_bytes());
    for (tag, kind, value) in fields {
        out.extend_from_slice(&tag.to_be_bytes());
        out.push(kind);
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value);
    }
    debug_assert_eq!(out.len(), total);
    Ok(out)
}


#[cfg(test)]
mod tests {
    use super::*;

    fn known_envelope() -> Vec<u8> {
        let hex = concat!(
            "464d4350424f5800000105584332305000016b",
            "000000000000000718",
            "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
            "00000010",
            "11111111111111111111111111111111"
        );
        hex.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let text = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(text, 16).unwrap()
            })
            .collect()
    }

    #[test]
    fn fmcpbox_exact_external_vector_and_round_trip() {
        let header = PersistentEnvelopeHeader::xc20p("k".into(), 7, [0xa5; 24]).unwrap();
        let encoded = header.encode(&[0x11; 16]).unwrap();
        assert_eq!(encoded.as_bytes(), known_envelope());
        let parsed = encoded.header().unwrap();
        assert_eq!(parsed.algorithm_id(), "XC20P");
        assert_eq!(parsed.key_id(), "k");
        assert_eq!(parsed.generation(), 7);
        assert_eq!(parsed.nonce(), &[0xa5; 24]);
        assert_eq!(parsed.sealed_bytes(), 16);
        assert_eq!(encoded.ciphertext_and_tag(), &[0x11; 16]);
    }

    #[test]
    fn every_truncation_and_any_trailing_byte_is_rejected() {
        let canonical = known_envelope();
        for end in 0..canonical.len() {
            assert!(CanonicalEnvelope::from_bytes(Zeroizing::new(canonical[..end].to_vec())).is_err());
        }
        let mut trailing = canonical;
        trailing.push(0);
        assert!(CanonicalEnvelope::from_bytes(Zeroizing::new(trailing)).is_err());
    }

    #[test]
    fn rejects_unknown_suite_version_and_noncanonical_widths() {
        let canonical = known_envelope();
        for (offset, value) in [
            (0, b'X'), (9, 2), (10, 4), (11, b'Y'),
            (16, 1), (17, 0), (18, b'/'), (26, 0), (27, 23),
            (52, 1), (55, 15),
        ] {
            let mut mutated = canonical.clone();
            mutated[offset] = value;
            assert!(CanonicalEnvelope::from_bytes(Zeroizing::new(mutated)).is_err(),
                "bad frame at {offset} must fail");
        }
    }

    #[test]
    fn key_identifiers_have_one_finite_ascii_grammar() {
        for rejected in ["", "a b", "a/b", "https://host", "a\n", "é", "a=1", "a%2fb"] {
            assert!(PersistentEnvelopeHeader::xc20p(rejected.into(), 1, [0; 24]).is_err());
        }
        assert!(PersistentEnvelopeHeader::xc20p("k".repeat(129), 1, [0; 24]).is_err());
        assert!(PersistentEnvelopeHeader::xc20p("k".into(), 0, [0; 24]).is_err());
        assert!(PersistentEnvelopeHeader::xc20p("Key_9.v2:old-generation".into(), 1, [0; 24]).is_ok());
        assert!(PersistentEnvelopeHeader::xc20p("k".repeat(128), u64::MAX, [0xff; 24]).is_ok());
    }

    #[test]
    fn ciphertext_always_has_a_complete_tag() {
        let header = PersistentEnvelopeHeader::xc20p("key".into(), 1, [0; 24]).unwrap();
        for length in 0..16 {
            assert!(header.encode(&vec![0; length]).is_err());
        }
        for length in [16, 17, 255, 4096] {
            let envelope = header.encode(&vec![0xa5; length]).unwrap();
            assert_eq!(envelope.ciphertext_and_tag().len(), length);
            assert_eq!(envelope.header().unwrap().sealed_bytes(), length);
        }
    }

    #[test]
    fn maximum_key_header_has_exact_checked_overhead() {
        let header = PersistentEnvelopeHeader::xc20p("k".repeat(128), 1, [0; 24]).unwrap();
        let envelope = header.encode(&[0; 16]).unwrap();
        assert_eq!(envelope.as_bytes().len(), 199);
        assert!(envelope.allocated_bytes() >= envelope.as_bytes().len());
    }
}
