//! Self-contained digests for FND-02 evidence binding.
//!
//! Two algorithms are needed and neither may come from a dependency edge:
//! the tool must add zero packages to `Cargo.lock` so that adding it cannot
//! perturb FND-01's dependency evidence.
//!
//! * SHA-256 renders canonical manifest digests.
//! * SHA-1 reproduces `git hash-object -t blob`, which is how FND-02 binds an
//!   authoritative source file. Commit SHAs rot under rebase; blob hashes do
//!   not, because they address content rather than history.
//!
//! Both are cross-checked against published known-answer vectors in the unit
//! tests below, so a transcription error cannot silently produce a stable but
//! wrong fingerprint.

/// Lowercase hexadecimal rendering. No `0x`, whitespace, or newline.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    out
}

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Full 32-byte SHA-256 of `input`, computed exactly once.
///
/// Truncation, uppercase rendering, double hashing, and hashing a textual hex
/// rendering are all distinct wrong answers; callers get the raw digest and
/// render it through [`hex`].
// The working variables are named a..h exactly as FIPS 180-4 names them.
// `many_single_char_names` is a READABILITY lint and cannot conceal a
// correctness defect; renaming these away from the standard's own
// identifiers would satisfy the linter by degrading the one property
// that matters here -- that a human can check this against the
// specification by reading it side by side. Narrow on purpose: this
// allow covers one function, not the module.
#[allow(clippy::many_single_char_names)]
pub fn sha256(input: &[u8]) -> [u8; 32] {
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let mut padded = Vec::with_capacity(input.len() + 72);
    padded.extend_from_slice(input);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    let bit_len = (input.len() as u64).wrapping_mul(8);
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 64];
    // `padded` is a whole number of 64-byte blocks by construction: the loop
    // above pads to `len % 64 == 56` and then appends exactly 8 length bytes.
    // `as_chunks` therefore yields an empty remainder, asserted below rather
    // than assumed.
    let (blocks, remainder) = padded.as_chunks::<64>();
    debug_assert!(remainder.is_empty(), "padding must produce whole 64-byte blocks");
    for chunk in blocks {
        for (index, word) in w.iter_mut().enumerate().take(16) {
            let base = index * 4;
            *word = u32::from_be_bytes([chunk[base], chunk[base + 1], chunk[base + 2], chunk[base + 3]]);
        }
        for index in 16..64 {
            let s0 = w[index - 15].rotate_right(7) ^ w[index - 15].rotate_right(18) ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17) ^ w[index - 2].rotate_right(19) ^ (w[index - 2] >> 10);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[index])
                .wrapping_add(w[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }

    let mut out = [0u8; 32];
    for (index, word) in state.iter().enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Full 20-byte SHA-1. Used only to reproduce Git's blob object identity.
// The working variables are named a..h exactly as FIPS 180-4 names them.
// `many_single_char_names` is a READABILITY lint and cannot conceal a
// correctness defect; renaming these away from the standard's own
// identifiers would satisfy the linter by degrading the one property
// that matters here -- that a human can check this against the
// specification by reading it side by side. Narrow on purpose: this
// allow covers one function, not the module.
#[allow(clippy::many_single_char_names)]
pub fn sha1(input: &[u8]) -> [u8; 20] {
    let mut state: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

    let mut padded = Vec::with_capacity(input.len() + 72);
    padded.extend_from_slice(input);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    let bit_len = (input.len() as u64).wrapping_mul(8);
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 80];
    // `padded` is a whole number of 64-byte blocks by construction: the loop
    // above pads to `len % 64 == 56` and then appends exactly 8 length bytes.
    // `as_chunks` therefore yields an empty remainder, asserted below rather
    // than assumed.
    let (blocks, remainder) = padded.as_chunks::<64>();
    debug_assert!(remainder.is_empty(), "padding must produce whole 64-byte blocks");
    for chunk in blocks {
        for (index, word) in w.iter_mut().enumerate().take(16) {
            let base = index * 4;
            *word = u32::from_be_bytes([chunk[base], chunk[base + 1], chunk[base + 2], chunk[base + 3]]);
        }
        for index in 16..80 {
            w[index] = (w[index - 3] ^ w[index - 8] ^ w[index - 14] ^ w[index - 16]).rotate_left(1);
        }

        let [mut a, mut b, mut c, mut d, mut e] = state;
        for (index, word) in w.iter().enumerate() {
            let (f, k) = match index {
                0..=19 => ((b & c) | ((!b) & d), 0x5a827999u32),
                20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                _ => (b ^ c ^ d, 0xca62c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        for (slot, value) in state.iter_mut().zip([a, b, c, d, e]) {
            *slot = slot.wrapping_add(value);
        }
    }

    let mut out = [0u8; 20];
    for (index, word) in state.iter().enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Git blob object identity for `content`: `SHA-1("blob " || len || NUL || content)`.
///
/// This is exactly what `git hash-object -t blob` prints, which makes the
/// binding verifiable from the shell without this tool.
pub fn git_blob_sha1(content: &[u8]) -> [u8; 20] {
    let mut preimage = Vec::with_capacity(content.len() + 24);
    preimage.extend_from_slice(b"blob ");
    preimage.extend_from_slice(content.len().to_string().as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(content);
    sha1(&preimage)
}

/// Lowercase hexadecimal Git blob identity.
pub fn git_blob_hex(content: &[u8]) -> String {
    hex(&git_blob_sha1(content))
}

/// Lowercase hexadecimal SHA-256.
pub fn sha256_hex(input: &[u8]) -> String {
    hex(&sha256(input))
}

#[cfg(test)]
mod tests {
    use super::*;

    // FIPS 180-4 known-answer vectors. If the transcription above were wrong,
    // every digest this tool produces would still be internally consistent and
    // therefore useless as evidence; these pin it to the published algorithm.
    #[test]
    fn sha256_matches_published_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        // Multi-block input crossing the length-padding boundary.
        assert_eq!(
            sha256_hex(&vec![b'a'; 1_000_000]),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn sha1_matches_published_vectors() {
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(hex(&sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            hex(&sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }

    #[test]
    fn git_blob_identity_matches_git_hash_object() {
        // `printf '' | git hash-object -t blob --stdin`
        assert_eq!(git_blob_hex(b""), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391");
        // `printf 'hello\n' | git hash-object -t blob --stdin`
        assert_eq!(
            git_blob_hex(b"hello\n"),
            "ce013625030ba8dba906f756967f9e9ca394464a"
        );
        // `printf 'what is up, doc?' | git hash-object -t blob --stdin`
        assert_eq!(
            git_blob_hex(b"what is up, doc?"),
            "bd9dbf5aae1a3862dd1526723246b20206e5fc37"
        );
    }

    #[test]
    fn hex_rendering_is_lowercase_and_bare() {
        let rendered = sha256_hex(b"abc");
        assert_eq!(rendered.len(), 64);
        assert!(rendered.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        assert!(!rendered.contains("0x") && !rendered.contains(char::is_whitespace));
    }

    // A digest that cannot distinguish two different inputs is not evidence.
    #[test]
    fn distinct_inputs_produce_distinct_digests() {
        assert_ne!(sha256_hex(b"FND-02"), sha256_hex(b"FND-03"));
        assert_ne!(git_blob_hex(b"a"), git_blob_hex(b"b"));
        // Domain separation: the blob prefix means blob(x) != sha1(x).
        assert_ne!(git_blob_hex(b"abc"), hex(&sha1(b"abc")));
    }
}
