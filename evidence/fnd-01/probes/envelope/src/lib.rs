//! Compile surface for the exact FND-01 XChaCha20-Poly1305 candidate.
//!
//! This probe intentionally owns no entropy source and defines no FastMCP
//! envelope format. FND-08 owns key generation, nonce allocation, application
//! bounds, epoch handling, zeroization, and wire-format semantics.

#![forbid(unsafe_code)]

use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    Key, XChaCha20Poly1305, XNonce,
};

pub const KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 24;
pub const TAG_BYTES: usize = 16;

/// Exercise only the explicitly selected allocation/in-place AEAD surface.
///
/// The caller supplies key and nonce bytes. That is deliberate negative
/// evidence that this dependency edge does not select `getrandom` or
/// `rand_core`; it is not the eventual public FastMCP API.
pub fn seal_in_place(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    associated_data: &[u8],
    plaintext: &mut Vec<u8>,
) -> Result<(), chacha20poly1305::Error> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher.encrypt_in_place(XNonce::from_slice(nonce), associated_data, plaintext)
}

/// Exercise authentication failure and decryption through the same selected
/// surface without claiming any application-level length policy.
pub fn open_in_place(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    associated_data: &[u8],
    ciphertext_and_tag: &mut Vec<u8>,
) -> Result<(), chacha20poly1305::Error> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher.decrypt_in_place(
        XNonce::from_slice(nonce),
        associated_data,
        ciphertext_and_tag,
    )
}

#[cfg(test)]
mod tests {
    use super::{open_in_place, seal_in_place, KEY_BYTES, NONCE_BYTES, TAG_BYTES};

    #[test]
    fn caller_supplied_key_and_nonce_round_trip() {
        let key = [0x11; KEY_BYTES];
        let nonce = [0x22; NONCE_BYTES];
        let associated_data = b"fnd-01 envelope probe";
        let mut payload = b"caller-supplied entropy only".to_vec();

        seal_in_place(&key, &nonce, associated_data, &mut payload).unwrap();
        assert_eq!(
            payload.len(),
            b"caller-supplied entropy only".len() + TAG_BYTES
        );
        open_in_place(&key, &nonce, associated_data, &mut payload).unwrap();

        assert_eq!(payload, b"caller-supplied entropy only");
    }

    #[test]
    fn altered_ciphertext_is_rejected() {
        let key = [0x33; KEY_BYTES];
        let nonce = [0x44; NONCE_BYTES];
        let mut payload = b"authenticated probe payload".to_vec();

        seal_in_place(&key, &nonce, b"aad", &mut payload).unwrap();
        payload[0] ^= 0x01;

        assert!(open_in_place(&key, &nonce, b"aad", &mut payload).is_err());
    }
}
