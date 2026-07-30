//! Synchronous verification and trust bootstrapping for FND-01 evidence.
//!
//! The ordinary Cargo-built verifier remains read-only.  A separately selected
//! `fnd01_bootstrap` configuration contains only `std` code and establishes the
//! immutable inputs required before dependency-backed verification may run.

#![forbid(unsafe_code)]
#![allow(clippy::too_many_lines)]
#![allow(unexpected_cfgs)]

#[allow(dead_code)]
mod trust_std {
    use std::ffi::{OsStr, OsString};
    use std::fmt;
    use std::fs::{self, File, Metadata};
    use std::io::{self, Read};
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    use std::os::unix::fs::MetadataExt;
    use std::path::{Component, Path, PathBuf};

    pub const AUTHORING_MARKER_ENV: &str = "FASTMCP_FND01_AUTHORING_CLOSURE";
    pub const INTEGRATION_SEAL_ENV: &str = "FASTMCP_FND01_INTEGRATION_SEAL";
    pub const MAX_POLICY_BYTES: u64 = 8 * 1024 * 1024;
    pub const MAX_VERIFIER_BYTES: u64 = 2 * 1024 * 1024;
    pub const MAX_HARNESS_BYTES: u64 = 256 * 1024;
    pub const MAX_RECEIPT_BYTES: u64 = 64 * 1024 * 1024;
    pub const MAX_SUPPLY_BUNDLE_BYTES: u64 = 1024 * 1024 * 1024;
    pub const MAX_OUTER_TRANSPORT_RECORD_BYTES: u64 = 128 * 1024 * 1024;
    const MAX_CHECKED_SET_MEMBERS: usize = 8;
    const MAX_AUTHORING_MARKER_TEXT_BYTES: usize = 512;
    const MAX_INTEGRATION_SEAL_TEXT_BYTES: usize = 1024;
    const MAX_ABSOLUTE_PATH_BYTES: usize = 4096;
    const MAX_ABSOLUTE_PATH_COMPONENT_BYTES: usize = 255;
    const MAX_ABSOLUTE_PATH_DEPTH: usize = 64;
    const MAX_RELATIVE_PATH_BYTES: usize = 240;
    const MAX_RELATIVE_PATH_COMPONENT_BYTES: usize = 100;
    const MAX_RELATIVE_PATH_DEPTH: usize = 8;

    pub const AUTHORING_PATHS: [&str; 3] = [
        "evidence/fnd-01/dependency-verification.toml",
        "crates/fastmcp/tests/fnd_01_dependency_evidence.rs",
        "crates/fastmcp/examples/fnd_01_evidence_harness.rs",
    ];
    const AUTHORING_LIMITS: [u64; 3] =
        [MAX_POLICY_BYTES, MAX_VERIFIER_BYTES, MAX_HARNESS_BYTES];
    pub const INTEGRATION_SEAL_PATHS: [&str; 5] = [
        "Cargo.lock",
        "evidence/fnd-01/integration/source-snapshot.toml",
        "evidence/fnd-01/integration/supply-bundle.bin",
        "evidence/fnd-01/integration/workspace-receipt.toml",
        "evidence/fnd-01/integration/integration-index.toml",
    ];
    const INTEGRATION_SEAL_LIMITS: [u64; 5] = [
        MAX_RECEIPT_BYTES,
        MAX_RECEIPT_BYTES,
        MAX_SUPPLY_BUNDLE_BYTES,
        MAX_RECEIPT_BYTES,
        MAX_RECEIPT_BYTES,
    ];

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct TrustError {
        code: &'static str,
        detail: String,
    }

    impl TrustError {
        pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
            Self {
                code,
                detail: detail.into(),
            }
        }

        pub fn code(&self) -> &'static str {
            self.code
        }

        pub fn detail(&self) -> &str {
            &self.detail
        }
    }

    impl fmt::Display for TrustError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "{}|{}", self.code, self.detail)
        }
    }

    impl std::error::Error for TrustError {}

    pub type TrustResult<T> = Result<T, TrustError>;

    fn io_error(code: &'static str, subject: &str, error: &io::Error) -> TrustError {
        TrustError::new(code, format!("{subject}: {error}"))
    }

    pub fn parse_canonical_nonzero_u64(
        value: &str,
        maximum: u64,
        subject: &str,
    ) -> TrustResult<u64> {
        let bytes = value.as_bytes();
        if bytes.is_empty()
            || bytes[0] == b'0'
            || !bytes.iter().all(u8::is_ascii_digit)
        {
            return Err(TrustError::new(
                "E_CANONICAL_INTEGER",
                format!("{subject}: {value:?}"),
            ));
        }
        let parsed = bytes.iter().try_fold(0u64, |current, byte| {
            current
                .checked_mul(10)
                .and_then(|next| next.checked_add(u64::from(*byte - b'0')))
        });
        let parsed = parsed.ok_or_else(|| {
            TrustError::new("E_INTEGER_OVERFLOW", format!("{subject}: {value:?}"))
        })?;
        if parsed == 0 || parsed > maximum {
            return Err(TrustError::new(
                "E_INTEGER_BOUND",
                format!("{subject}: {parsed} > {maximum}"),
            ));
        }
        Ok(parsed)
    }

    fn lower_hex_nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        }
    }

    pub fn decode_lower_hex<const N: usize>(
        value: &str,
        subject: &str,
    ) -> TrustResult<[u8; N]> {
        let expected_length = N.checked_mul(2).ok_or_else(|| {
            TrustError::new("E_HEX_BOUND", format!("{subject}: length overflow"))
        })?;
        if value.len() != expected_length {
            return Err(TrustError::new(
                "E_HEX_LENGTH",
                format!("{subject}: {} != {expected_length}", value.len()),
            ));
        }
        let mut decoded = [0u8; N];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let high = lower_hex_nibble(pair[0]).ok_or_else(|| {
                TrustError::new("E_HEX_FORMAT", format!("{subject}: lowercase hex required"))
            })?;
            let low = lower_hex_nibble(pair[1]).ok_or_else(|| {
                TrustError::new("E_HEX_FORMAT", format!("{subject}: lowercase hex required"))
            })?;
            decoded[index] = (high << 4) | low;
        }
        Ok(decoded)
    }

    pub fn encode_lower_hex(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
        for byte in bytes {
            encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
            encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
        }
        encoded
    }

    const SHA256_INITIAL_STATE: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    const SHA256_ROUND_CONSTANTS: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];

    #[derive(Debug, Clone)]
    pub struct StreamingSha256 {
        state: [u32; 8],
        buffer: [u8; 64],
        buffer_length: usize,
        total_length: u64,
    }

    impl Default for StreamingSha256 {
        fn default() -> Self {
            Self {
                state: SHA256_INITIAL_STATE,
                buffer: [0; 64],
                buffer_length: 0,
                total_length: 0,
            }
        }
    }

    impl StreamingSha256 {
        pub fn new() -> Self {
            Self::default()
        }

        fn compress(&mut self, block: &[u8; 64]) {
            let mut schedule = [0u32; 64];
            for (index, word) in block.chunks_exact(4).take(16).enumerate() {
                schedule[index] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
            }
            for index in 16..64 {
                let previous_15 = schedule[index - 15];
                let previous_2 = schedule[index - 2];
                let small_sigma_0 = previous_15.rotate_right(7)
                    ^ previous_15.rotate_right(18)
                    ^ (previous_15 >> 3);
                let small_sigma_1 = previous_2.rotate_right(17)
                    ^ previous_2.rotate_right(19)
                    ^ (previous_2 >> 10);
                schedule[index] = schedule[index - 16]
                    .wrapping_add(small_sigma_0)
                    .wrapping_add(schedule[index - 7])
                    .wrapping_add(small_sigma_1);
            }

            let mut a = self.state[0];
            let mut b = self.state[1];
            let mut c = self.state[2];
            let mut d = self.state[3];
            let mut e = self.state[4];
            let mut f = self.state[5];
            let mut g = self.state[6];
            let mut h = self.state[7];

            for index in 0..64 {
                let big_sigma_1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let choice = (e & f) ^ ((!e) & g);
                let temporary_1 = h
                    .wrapping_add(big_sigma_1)
                    .wrapping_add(choice)
                    .wrapping_add(SHA256_ROUND_CONSTANTS[index])
                    .wrapping_add(schedule[index]);
                let big_sigma_0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let majority = (a & b) ^ (a & c) ^ (b & c);
                let temporary_2 = big_sigma_0.wrapping_add(majority);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temporary_1);
                d = c;
                c = b;
                b = a;
                a = temporary_1.wrapping_add(temporary_2);
            }

            self.state[0] = self.state[0].wrapping_add(a);
            self.state[1] = self.state[1].wrapping_add(b);
            self.state[2] = self.state[2].wrapping_add(c);
            self.state[3] = self.state[3].wrapping_add(d);
            self.state[4] = self.state[4].wrapping_add(e);
            self.state[5] = self.state[5].wrapping_add(f);
            self.state[6] = self.state[6].wrapping_add(g);
            self.state[7] = self.state[7].wrapping_add(h);
        }

        pub fn update(&mut self, mut bytes: &[u8]) -> TrustResult<()> {
            let additional = u64::try_from(bytes.len()).map_err(|_| {
                TrustError::new("E_SHA256_LENGTH", "input length does not fit u64")
            })?;
            let total_length = self.total_length.checked_add(additional).ok_or_else(|| {
                TrustError::new("E_SHA256_LENGTH", "input length overflow")
            })?;
            if total_length > u64::MAX / 8 {
                return Err(TrustError::new(
                    "E_SHA256_LENGTH",
                    "SHA-256 bit length overflow",
                ));
            }
            self.total_length = total_length;

            if self.buffer_length != 0 {
                let needed = 64 - self.buffer_length;
                let copied = needed.min(bytes.len());
                self.buffer[self.buffer_length..self.buffer_length + copied]
                    .copy_from_slice(&bytes[..copied]);
                self.buffer_length += copied;
                bytes = &bytes[copied..];
                if self.buffer_length == 64 {
                    let block = self.buffer;
                    self.compress(&block);
                    self.buffer_length = 0;
                }
            }

            while bytes.len() >= 64 {
                let block = <&[u8; 64]>::try_from(&bytes[..64]).map_err(|_| {
                    TrustError::new("E_SHA256_INTERNAL", "full block conversion")
                })?;
                self.compress(block);
                bytes = &bytes[64..];
            }
            if !bytes.is_empty() {
                self.buffer[..bytes.len()].copy_from_slice(bytes);
                self.buffer_length = bytes.len();
            }
            Ok(())
        }

        pub fn finalize(mut self) -> TrustResult<[u8; 32]> {
            let bit_length = self.total_length.checked_mul(8).ok_or_else(|| {
                TrustError::new("E_SHA256_LENGTH", "SHA-256 bit length overflow")
            })?;
            self.buffer[self.buffer_length] = 0x80;
            self.buffer_length += 1;
            if self.buffer_length > 56 {
                self.buffer[self.buffer_length..].fill(0);
                let block = self.buffer;
                self.compress(&block);
                self.buffer = [0; 64];
                self.buffer_length = 0;
            }
            self.buffer[self.buffer_length..56].fill(0);
            self.buffer[56..64].copy_from_slice(&bit_length.to_be_bytes());
            let block = self.buffer;
            self.compress(&block);

            let mut digest = [0u8; 32];
            for (destination, word) in digest.chunks_exact_mut(4).zip(self.state) {
                destination.copy_from_slice(&word.to_be_bytes());
            }
            Ok(digest)
        }
    }

    pub fn sha256(bytes: &[u8]) -> TrustResult<[u8; 32]> {
        let mut hasher = StreamingSha256::new();
        hasher.update(bytes)?;
        hasher.finalize()
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FileBinding {
        pub byte_length: u64,
        pub sha256: [u8; 32],
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct AuthoringMarker {
        pub policy: FileBinding,
        pub verifier: FileBinding,
        pub harness: FileBinding,
        pub closure_sha256: [u8; 32],
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct IntegrationSeal {
        pub run_id: [u8; 16],
        pub records: [FileBinding; 5],
        pub outer_transport: FileBinding,
        pub authoring_closure_sha256: [u8; 32],
        pub seal_sha256: [u8; 32],
    }

    fn split_exact<'a, const N: usize>(
        value: &'a str,
        subject: &str,
    ) -> TrustResult<[&'a str; N]> {
        let mut parts = [""; N];
        let mut iterator = value.split(':');
        for part in &mut parts {
            *part = iterator.next().ok_or_else(|| {
                TrustError::new("E_MARKER_GRAMMAR", format!("{subject}: missing field"))
            })?;
        }
        if iterator.next().is_some() {
            return Err(TrustError::new(
                "E_MARKER_GRAMMAR",
                format!("{subject}: trailing field"),
            ));
        }
        Ok(parts)
    }

    fn reserve_preimage(preimage: &mut Vec<u8>, additional: usize) -> TrustResult<()> {
        preimage.try_reserve_exact(additional).map_err(|_| {
            TrustError::new(
                "E_PREIMAGE_ALLOCATION",
                format!("cannot reserve {additional} preimage bytes"),
            )
        })
    }

    fn append_bound_record(
        preimage: &mut Vec<u8>,
        path: &str,
        binding: FileBinding,
    ) -> TrustResult<()> {
        let path_length = u32::try_from(path.len()).map_err(|_| {
            TrustError::new(
                "E_PREIMAGE_BOUND",
                format!("binding path exceeds u32 encoding: {path:?}"),
            )
        })?;
        let encoded_length = 4usize
            .checked_add(path.len())
            .and_then(|length| length.checked_add(8 + 32))
            .ok_or_else(|| {
                TrustError::new("E_PREIMAGE_BOUND", "binding record length overflow")
            })?;
        reserve_preimage(preimage, encoded_length)?;
        preimage.extend_from_slice(&path_length.to_be_bytes());
        preimage.extend_from_slice(path.as_bytes());
        preimage.extend_from_slice(&binding.byte_length.to_be_bytes());
        preimage.extend_from_slice(&binding.sha256);
        Ok(())
    }

    pub fn authoring_closure_preimage(marker: &AuthoringMarker) -> TrustResult<Vec<u8>> {
        let mut preimage = Vec::new();
        reserve_preimage(&mut preimage, b"FND01AUTHORv2\0".len() + 4)?;
        preimage.extend_from_slice(b"FND01AUTHORv2\0");
        preimage.extend_from_slice(&3u32.to_be_bytes());
        append_bound_record(&mut preimage, AUTHORING_PATHS[0], marker.policy)?;
        append_bound_record(&mut preimage, AUTHORING_PATHS[1], marker.verifier)?;
        append_bound_record(&mut preimage, AUTHORING_PATHS[2], marker.harness)?;
        Ok(preimage)
    }

    pub fn parse_authoring_marker(value: &str) -> TrustResult<AuthoringMarker> {
        if value.len() > MAX_AUTHORING_MARKER_TEXT_BYTES {
            return Err(TrustError::new(
                "E_AUTHORING_MARKER",
                "marker exceeds bounded grammar size",
            ));
        }
        let fields = split_exact::<8>(value, AUTHORING_MARKER_ENV)?;
        if fields[0] != "FND01AUTHORv2" {
            return Err(TrustError::new(
                "E_AUTHORING_MARKER",
                "wrong marker prefix",
            ));
        }
        let marker = AuthoringMarker {
            policy: FileBinding {
                byte_length: parse_canonical_nonzero_u64(
                    fields[1],
                    MAX_POLICY_BYTES,
                    "policy length",
                )?,
                sha256: decode_lower_hex(fields[2], "policy SHA-256")?,
            },
            verifier: FileBinding {
                byte_length: parse_canonical_nonzero_u64(
                    fields[3],
                    MAX_VERIFIER_BYTES,
                    "verifier length",
                )?,
                sha256: decode_lower_hex(fields[4], "verifier SHA-256")?,
            },
            harness: FileBinding {
                byte_length: parse_canonical_nonzero_u64(
                    fields[5],
                    MAX_HARNESS_BYTES,
                    "harness length",
                )?,
                sha256: decode_lower_hex(fields[6], "harness SHA-256")?,
            },
            closure_sha256: decode_lower_hex(fields[7], "authoring closure SHA-256")?,
        };
        let actual = sha256(&authoring_closure_preimage(&marker)?)?;
        if actual != marker.closure_sha256 {
            return Err(TrustError::new(
                "E_AUTHORING_CLOSURE",
                "authoring closure digest mismatch",
            ));
        }
        Ok(marker)
    }

    pub fn integration_seal_preimage(seal: &IntegrationSeal) -> TrustResult<Vec<u8>> {
        let mut preimage = Vec::new();
        reserve_preimage(
            &mut preimage,
            b"FND01INTEGRATIONv1\0".len() + seal.run_id.len(),
        )?;
        preimage.extend_from_slice(b"FND01INTEGRATIONv1\0");
        preimage.extend_from_slice(&seal.run_id);
        for (path, binding) in INTEGRATION_SEAL_PATHS.iter().zip(seal.records) {
            append_bound_record(&mut preimage, path, binding)?;
        }
        reserve_preimage(&mut preimage, 8 + 32 + 32)?;
        preimage.extend_from_slice(&seal.outer_transport.byte_length.to_be_bytes());
        preimage.extend_from_slice(&seal.outer_transport.sha256);
        preimage.extend_from_slice(&seal.authoring_closure_sha256);
        Ok(preimage)
    }

    pub fn parse_integration_seal(
        value: &str,
        expected_authoring_closure: &[u8; 32],
    ) -> TrustResult<IntegrationSeal> {
        if value.len() > MAX_INTEGRATION_SEAL_TEXT_BYTES {
            return Err(TrustError::new(
                "E_INTEGRATION_SEAL",
                "seal exceeds bounded grammar size",
            ));
        }
        let fields = split_exact::<16>(value, INTEGRATION_SEAL_ENV)?;
        if fields[0] != "FND01INTEGRATIONv1" {
            return Err(TrustError::new(
                "E_INTEGRATION_SEAL",
                "wrong seal prefix",
            ));
        }
        let run_id = decode_lower_hex::<16>(fields[1], "integration run ID")?;
        if run_id.iter().all(|byte| *byte == 0) {
            return Err(TrustError::new(
                "E_INTEGRATION_RUN_ID",
                "all-zero run ID is forbidden",
            ));
        }
        let mut records = [FileBinding {
            byte_length: 0,
            sha256: [0; 32],
        }; 5];
        for (index, record) in records.iter_mut().enumerate() {
            *record = FileBinding {
                byte_length: parse_canonical_nonzero_u64(
                    fields[2 + index * 2],
                    INTEGRATION_SEAL_LIMITS[index],
                    INTEGRATION_SEAL_PATHS[index],
                )?,
                sha256: decode_lower_hex(
                    fields[3 + index * 2],
                    INTEGRATION_SEAL_PATHS[index],
                )?,
            };
        }
        let seal = IntegrationSeal {
            run_id,
            records,
            outer_transport: FileBinding {
                byte_length: parse_canonical_nonzero_u64(
                    fields[12],
                    MAX_OUTER_TRANSPORT_RECORD_BYTES,
                    "outer transport record length",
                )?,
                sha256: decode_lower_hex(fields[13], "outer transport record SHA-256")?,
            },
            authoring_closure_sha256: decode_lower_hex(
                fields[14],
                "seal authoring closure",
            )?,
            seal_sha256: decode_lower_hex(fields[15], "integration seal SHA-256")?,
        };
        if seal.authoring_closure_sha256 != *expected_authoring_closure {
            return Err(TrustError::new(
                "E_INTEGRATION_AUTHORING_CLOSURE",
                "seal and authoring marker disagree",
            ));
        }
        let actual = sha256(&integration_seal_preimage(&seal)?)?;
        if actual != seal.seal_sha256 {
            return Err(TrustError::new(
                "E_INTEGRATION_SEAL",
                "integration seal digest mismatch",
            ));
        }
        Ok(seal)
    }

    pub fn read_unique_environment(name: &str) -> TrustResult<String> {
        let mut found = None::<OsString>;
        for (key, value) in std::env::vars_os() {
            if key == OsStr::new(name) {
                if found.replace(value).is_some() {
                    return Err(TrustError::new(
                        "E_ENV_DUPLICATE",
                        format!("{name}: duplicate environment entry"),
                    ));
                }
            }
        }
        let value = found.ok_or_else(|| {
            TrustError::new("E_ENV_MISSING", format!("{name}: required external value"))
        })?;
        value.into_string().map_err(|_| {
            TrustError::new("E_ENV_ENCODING", format!("{name}: UTF-8 required"))
        })
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct LinuxFileIdentity {
        pub device: u64,
        pub inode: u64,
        pub link_count: u64,
        pub file_type: u32,
        pub mode: u32,
        pub byte_length: u64,
        pub modification_seconds: i64,
        pub modification_nanoseconds: i64,
        pub change_seconds: i64,
        pub change_nanoseconds: i64,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct CheckedSnapshot {
        pub logical_path: String,
        pub byte_length: u64,
        pub sha256: [u8; 32],
        pub identity: LinuxFileIdentity,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SnapshotStage {
        PreOpen,
        PostOpenPreRead,
        PostReadPreFinalMetadata,
    }

    pub trait SnapshotHook {
        fn at(&mut self, stage: SnapshotStage, path: &Path) -> TrustResult<()>;
    }

    impl<F> SnapshotHook for F
    where
        F: FnMut(SnapshotStage, &Path) -> TrustResult<()>,
    {
        fn at(&mut self, stage: SnapshotStage, path: &Path) -> TrustResult<()> {
            self(stage, path)
        }
    }

    struct NoopSnapshotHook;

    impl SnapshotHook for NoopSnapshotHook {
        fn at(&mut self, _stage: SnapshotStage, _path: &Path) -> TrustResult<()> {
            Ok(())
        }
    }

    fn require_qualified_platform() -> TrustResult<()> {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            Ok(())
        }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            Err(TrustError::new(
                "E_UNQUALIFIED_PLATFORM",
                "retained evidence requires Linux x86_64",
            ))
        }
    }

    fn linux_identity(metadata: &Metadata, _subject: &str) -> TrustResult<LinuxFileIdentity> {
        require_qualified_platform()?;
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            Ok(LinuxFileIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
                link_count: metadata.nlink(),
                file_type: metadata.mode() & 0o170_000,
                mode: metadata.mode(),
                byte_length: metadata.len(),
                modification_seconds: metadata.mtime(),
                modification_nanoseconds: metadata.mtime_nsec(),
                change_seconds: metadata.ctime(),
                change_nanoseconds: metadata.ctime_nsec(),
            })
        }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            let _ = metadata;
            Err(TrustError::new("E_UNQUALIFIED_PLATFORM", _subject))
        }
    }

    fn validate_absolute_lexical_path(value: &str, subject: &str) -> TrustResult<PathBuf> {
        if value.len() > MAX_ABSOLUTE_PATH_BYTES
            || !value.starts_with('/')
            || value == "/"
            || value.ends_with('/')
            || value.contains("//")
            || value.contains('\\')
            || value.as_bytes().iter().any(|byte| byte.is_ascii_control())
        {
            return Err(TrustError::new(
                "E_ROOT_PATH",
                format!("{subject}: invalid absolute lexical path"),
            ));
        }
        let mut depth = 0usize;
        for component in value.split('/').skip(1) {
            depth = depth.checked_add(1).ok_or_else(|| {
                TrustError::new("E_ROOT_PATH", format!("{subject}: depth overflow"))
            })?;
            if component.is_empty()
                || component == "."
                || component == ".."
                || component.len() > MAX_ABSOLUTE_PATH_COMPONENT_BYTES
            {
                return Err(TrustError::new(
                    "E_ROOT_PATH",
                    format!("{subject}: invalid component"),
                ));
            }
        }
        if depth == 0 || depth > MAX_ABSOLUTE_PATH_DEPTH {
            return Err(TrustError::new(
                "E_ROOT_PATH",
                format!("{subject}: depth {depth}"),
            ));
        }
        let path = PathBuf::from(value);
        if path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
        {
            return Err(TrustError::new(
                "E_ROOT_PATH",
                format!("{subject}: non-lexical component"),
            ));
        }
        Ok(path)
    }

    fn validate_existing_directory_root(root: &Path, subject: &str) -> TrustResult<()> {
        require_qualified_platform()?;
        if !root.is_absolute() {
            return Err(TrustError::new(
                "E_ROOT_PATH",
                format!("{subject}: absolute path required"),
            ));
        }
        let mut current = PathBuf::from("/");
        for component in root.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(part) => {
                    current.push(part);
                    let metadata = fs::symlink_metadata(&current)
                        .map_err(|error| io_error("E_ROOT_METADATA", subject, &error))?;
                    if metadata.file_type().is_symlink() || !metadata.is_dir() {
                        return Err(TrustError::new(
                            "E_ROOT_TYPE",
                            format!("{subject}: {}", current.display()),
                        ));
                    }
                }
                _ => {
                    return Err(TrustError::new(
                        "E_ROOT_PATH",
                        format!("{subject}: non-lexical component"),
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_relative_path(relative: &str, subject: &str) -> TrustResult<()> {
        if relative.is_empty()
            || relative.len() > MAX_RELATIVE_PATH_BYTES
            || relative.starts_with('/')
            || relative.ends_with('/')
            || relative.contains("//")
            || relative.contains('\\')
            || relative.contains(':')
            || relative
                .as_bytes()
                .iter()
                .any(|byte| byte.is_ascii_control())
        {
            return Err(TrustError::new(
                "E_PATH_GRAMMAR",
                format!("{subject}: {relative:?}"),
            ));
        }
        let mut depth = 0usize;
        for component in relative.split('/') {
            depth = depth.checked_add(1).ok_or_else(|| {
                TrustError::new("E_PATH_GRAMMAR", format!("{subject}: depth overflow"))
            })?;
            if component.is_empty()
                || component == "."
                || component == ".."
                || component.len() > MAX_RELATIVE_PATH_COMPONENT_BYTES
            {
                return Err(TrustError::new(
                    "E_PATH_GRAMMAR",
                    format!("{subject}: invalid component"),
                ));
            }
        }
        if depth > MAX_RELATIVE_PATH_DEPTH {
            return Err(TrustError::new(
                "E_PATH_GRAMMAR",
                format!("{subject}: depth {depth}"),
            ));
        }
        Ok(())
    }

    fn precheck_leaf(
        root: &Path,
        relative: &str,
        subject: &str,
    ) -> TrustResult<(PathBuf, Metadata, LinuxFileIdentity)> {
        validate_existing_directory_root(root, "repository root")?;
        validate_relative_path(relative, subject)?;
        let mut current = root.to_path_buf();
        let component_count = relative.split('/').count();
        for (index, component) in relative.split('/').enumerate() {
            current.push(component);
            let metadata = fs::symlink_metadata(&current)
                .map_err(|error| io_error("E_PATH_METADATA", subject, &error))?;
            if metadata.file_type().is_symlink() {
                return Err(TrustError::new(
                    "E_PATH_SYMLINK",
                    format!("{subject}: {relative}"),
                ));
            }
            if index + 1 == component_count {
                if !metadata.is_file() {
                    return Err(TrustError::new(
                        "E_FILE_TYPE",
                        format!("{subject}: regular file required"),
                    ));
                }
                let identity = linux_identity(&metadata, subject)?;
                if identity.link_count != 1 {
                    return Err(TrustError::new(
                        "E_FILE_HARDLINK",
                        format!("{subject}: nlink={}", identity.link_count),
                    ));
                }
                return Ok((current, metadata, identity));
            }
            if !metadata.is_dir() {
                return Err(TrustError::new(
                    "E_PATH_COMPONENT",
                    format!("{subject}: intermediate directory required"),
                ));
            }
        }
        Err(TrustError::new(
            "E_PATH_GRAMMAR",
            format!("{subject}: missing leaf"),
        ))
    }

    fn checked_stream_with_hook<H, F>(
        root: &Path,
        relative: &str,
        maximum_bytes: u64,
        expected: Option<FileBinding>,
        hook: &mut H,
        mut observe: F,
    ) -> TrustResult<CheckedSnapshot>
    where
        H: SnapshotHook,
        F: FnMut(&[u8]) -> TrustResult<()>,
    {
        let subject = relative;
        let (path, pre_metadata, pre_identity) = precheck_leaf(root, relative, subject)?;
        if pre_metadata.len() > maximum_bytes {
            return Err(TrustError::new(
                "E_FILE_BOUND",
                format!("{subject}: {} > {maximum_bytes}", pre_metadata.len()),
            ));
        }
        if expected.is_some_and(|binding| binding.byte_length != pre_metadata.len()) {
            return Err(TrustError::new(
                "E_FILE_LENGTH",
                format!("{subject}: marker length mismatch"),
            ));
        }

        hook.at(SnapshotStage::PreOpen, &path)?;
        let mut file =
            File::open(&path).map_err(|error| io_error("E_FILE_OPEN", subject, &error))?;
        let opened_metadata = file
            .metadata()
            .map_err(|error| io_error("E_FILE_METADATA", subject, &error))?;
        let opened_identity = linux_identity(&opened_metadata, subject)?;
        if opened_identity != pre_identity {
            return Err(TrustError::new(
                "E_FILE_RACE",
                format!("{subject}: pre-open identity changed"),
            ));
        }

        hook.at(SnapshotStage::PostOpenPreRead, &path)?;
        let mut hasher = StreamingSha256::new();
        let mut byte_length = 0u64;
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|error| io_error("E_FILE_READ", subject, &error))?;
            if read == 0 {
                break;
            }
            byte_length = byte_length
                .checked_add(u64::try_from(read).map_err(|_| {
                    TrustError::new("E_FILE_LENGTH", format!("{subject}: read length overflow"))
                })?)
                .ok_or_else(|| {
                    TrustError::new("E_FILE_LENGTH", format!("{subject}: length overflow"))
                })?;
            if byte_length > maximum_bytes {
                return Err(TrustError::new(
                    "E_FILE_BOUND",
                    format!("{subject}: stream exceeded {maximum_bytes}"),
                ));
            }
            hasher.update(&buffer[..read])?;
            observe(&buffer[..read])?;
        }
        if byte_length != pre_identity.byte_length {
            return Err(TrustError::new(
                "E_FILE_RACE",
                format!("{subject}: length changed during read"),
            ));
        }
        let digest = hasher.finalize()?;

        let after_handle_metadata = file
            .metadata()
            .map_err(|error| io_error("E_FILE_METADATA", subject, &error))?;
        let after_handle_identity = linux_identity(&after_handle_metadata, subject)?;
        if after_handle_identity != pre_identity {
            return Err(TrustError::new(
                "E_FILE_RACE",
                format!("{subject}: opened handle identity changed"),
            ));
        }
        hook.at(SnapshotStage::PostReadPreFinalMetadata, &path)?;
        let (post_path, _post_metadata, post_identity) = precheck_leaf(root, relative, subject)?;
        if post_path != path || post_identity != pre_identity {
            return Err(TrustError::new(
                "E_FILE_RACE",
                format!("{subject}: post-read path identity changed"),
            ));
        }
        if let Some(binding) = expected {
            if digest != binding.sha256 {
                return Err(TrustError::new(
                    "E_FILE_DIGEST",
                    format!("{subject}: marker digest mismatch"),
                ));
            }
        }
        Ok(CheckedSnapshot {
            logical_path: relative.to_owned(),
            byte_length,
            sha256: digest,
            identity: pre_identity,
        })
    }

    pub fn checked_snapshot(
        root: &Path,
        relative: &str,
        maximum_bytes: u64,
        expected: Option<FileBinding>,
    ) -> TrustResult<CheckedSnapshot> {
        let mut hook = NoopSnapshotHook;
        checked_stream_with_hook(
            root,
            relative,
            maximum_bytes,
            expected,
            &mut hook,
            |_| Ok(()),
        )
    }

    pub fn checked_snapshot_with_hook<H>(
        root: &Path,
        relative: &str,
        maximum_bytes: u64,
        expected: Option<FileBinding>,
        hook: &mut H,
    ) -> TrustResult<CheckedSnapshot>
    where
        H: SnapshotHook,
    {
        checked_stream_with_hook(
            root,
            relative,
            maximum_bytes,
            expected,
            hook,
            |_| Ok(()),
        )
    }

    pub fn checked_read(
        root: &Path,
        relative: &str,
        maximum_bytes: u64,
        expected: Option<FileBinding>,
    ) -> TrustResult<(CheckedSnapshot, Vec<u8>)> {
        let mut bytes = Vec::new();
        let mut hook = NoopSnapshotHook;
        let snapshot = checked_stream_with_hook(
            root,
            relative,
            maximum_bytes,
            expected,
            &mut hook,
            |chunk| {
                bytes.try_reserve(chunk.len()).map_err(|_| {
                    TrustError::new("E_FILE_ALLOCATION", format!("{relative}: allocation failed"))
                })?;
                bytes.extend_from_slice(chunk);
                Ok(())
            },
        )?;
        Ok((snapshot, bytes))
    }

    fn validate_checked_snapshot_set_configuration<const N: usize>(
        canonical_paths: &[&str; N],
        maximum_bytes: &[u64; N],
    ) -> TrustResult<()> {
        if N == 0 || N > MAX_CHECKED_SET_MEMBERS {
            return Err(TrustError::new(
                "E_SET_BOUND",
                format!("checked snapshot set has {N} members"),
            ));
        }
        for (index, (path, maximum)) in canonical_paths
            .iter()
            .zip(maximum_bytes.iter())
            .enumerate()
        {
            validate_relative_path(path, "checked snapshot set path")?;
            if *maximum == 0 {
                return Err(TrustError::new(
                    "E_SET_CONFIGURATION",
                    format!("{path}: zero byte bound"),
                ));
            }
            if canonical_paths[..index].contains(path) {
                return Err(TrustError::new(
                    "E_SET_CONFIGURATION",
                    format!("{path}: duplicate canonical member"),
                ));
            }
        }
        Ok(())
    }

    /// Reopen every member only after the complete first pass has been retained.
    ///
    /// Per-file bookends close races during one stream. This second pass closes
    /// the gap in which an earlier member can drift while a later member is read.
    pub fn revalidate_checked_snapshot_set<const N: usize>(
        root: &Path,
        canonical_paths: &[&str; N],
        maximum_bytes: &[u64; N],
        retained: &[CheckedSnapshot; N],
    ) -> TrustResult<()> {
        validate_checked_snapshot_set_configuration(canonical_paths, maximum_bytes)?;
        for ((canonical_path, maximum), retained_member) in canonical_paths
            .iter()
            .zip(maximum_bytes.iter())
            .zip(retained.iter())
        {
            if retained_member.logical_path != *canonical_path {
                return Err(TrustError::new(
                    "E_SET_RACE",
                    format!(
                        "{canonical_path}: retained logical path changed to {:?}",
                        retained_member.logical_path
                    ),
                ));
            }
            let expected = FileBinding {
                byte_length: retained_member.byte_length,
                sha256: retained_member.sha256,
            };
            let current = checked_snapshot(root, canonical_path, *maximum, Some(expected))
                .map_err(|error| {
                    TrustError::new(
                        "E_SET_RACE",
                        format!("{canonical_path}: second-pass revalidation failed: {error}"),
                    )
                })?;
            if &current != retained_member {
                return Err(TrustError::new(
                    "E_SET_RACE",
                    format!(
                        "{canonical_path}: identity, metadata, length, or digest changed \
                         between set passes"
                    ),
                ));
            }
        }
        Ok(())
    }

    pub fn checked_snapshot_set_with_hook<const N: usize, H>(
        root: &Path,
        canonical_paths: &[&str; N],
        maximum_bytes: &[u64; N],
        expected: &[FileBinding; N],
        hook: &mut H,
    ) -> TrustResult<[CheckedSnapshot; N]>
    where
        H: SnapshotHook,
    {
        validate_checked_snapshot_set_configuration(canonical_paths, maximum_bytes)?;
        let mut retained = Vec::new();
        retained.try_reserve_exact(N).map_err(|_| {
            TrustError::new(
                "E_SET_ALLOCATION",
                format!("unable to reserve {N} checked snapshots"),
            )
        })?;
        for ((canonical_path, maximum), binding) in canonical_paths
            .iter()
            .zip(maximum_bytes.iter())
            .zip(expected.iter())
        {
            retained.push(checked_snapshot_with_hook(
                root,
                canonical_path,
                *maximum,
                Some(*binding),
                hook,
            )?);
        }
        let retained: [CheckedSnapshot; N] = retained.try_into().map_err(|values| {
            TrustError::new(
                "E_SET_INTERNAL",
                format!("retained {} checked snapshots, expected {N}", values.len()),
            )
        })?;
        revalidate_checked_snapshot_set(root, canonical_paths, maximum_bytes, &retained)?;
        Ok(retained)
    }

    fn checked_snapshot_set<const N: usize>(
        root: &Path,
        canonical_paths: &[&str; N],
        maximum_bytes: &[u64; N],
        expected: &[FileBinding; N],
    ) -> TrustResult<[CheckedSnapshot; N]> {
        let mut hook = NoopSnapshotHook;
        checked_snapshot_set_with_hook(
            root,
            canonical_paths,
            maximum_bytes,
            expected,
            &mut hook,
        )
    }

    pub fn verify_authoring_files(
        repository_root: &Path,
        marker: &AuthoringMarker,
    ) -> TrustResult<[CheckedSnapshot; 3]> {
        checked_snapshot_set(
            repository_root,
            &AUTHORING_PATHS,
            &AUTHORING_LIMITS,
            &[marker.policy, marker.verifier, marker.harness],
        )
    }

    pub fn revalidate_authoring_files(
        repository_root: &Path,
        retained: &[CheckedSnapshot; 3],
    ) -> TrustResult<()> {
        revalidate_checked_snapshot_set(
            repository_root,
            &AUTHORING_PATHS,
            &AUTHORING_LIMITS,
            retained,
        )
    }

    pub fn verify_integration_seal_files(
        repository_root: &Path,
        seal: &IntegrationSeal,
    ) -> TrustResult<[CheckedSnapshot; 5]> {
        checked_snapshot_set(
            repository_root,
            &INTEGRATION_SEAL_PATHS,
            &INTEGRATION_SEAL_LIMITS,
            &seal.records,
        )
    }

    pub fn revalidate_integration_seal_files(
        repository_root: &Path,
        retained: &[CheckedSnapshot; 5],
    ) -> TrustResult<()> {
        revalidate_checked_snapshot_set(
            repository_root,
            &INTEGRATION_SEAL_PATHS,
            &INTEGRATION_SEAL_LIMITS,
            retained,
        )
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum BootstrapMode {
        Produce,
        Attest,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct BootstrapArguments {
        pub mode: BootstrapMode,
        pub repository_root: PathBuf,
        pub run_root: PathBuf,
    }

    pub fn parse_bootstrap_arguments<I>(arguments: I) -> TrustResult<BootstrapArguments>
    where
        I: IntoIterator<Item = OsString>,
    {
        let mut iterator = arguments.into_iter();
        let _program = iterator.next().ok_or_else(|| {
            TrustError::new("E_BOOTSTRAP_ARGUMENTS", "missing argv[0]")
        })?;
        let mode = iterator
            .next()
            .and_then(|value| value.into_string().ok())
            .ok_or_else(|| {
                TrustError::new("E_BOOTSTRAP_ARGUMENTS", "missing UTF-8 mode")
            })?;
        let repository_flag = iterator
            .next()
            .and_then(|value| value.into_string().ok())
            .ok_or_else(|| {
                TrustError::new("E_BOOTSTRAP_ARGUMENTS", "missing repository-root flag")
            })?;
        let repository_value = iterator
            .next()
            .and_then(|value| value.into_string().ok())
            .ok_or_else(|| {
                TrustError::new("E_BOOTSTRAP_ARGUMENTS", "missing repository root")
            })?;
        let run_flag = iterator
            .next()
            .and_then(|value| value.into_string().ok())
            .ok_or_else(|| TrustError::new("E_BOOTSTRAP_ARGUMENTS", "missing run-root flag"))?;
        let run_value = iterator
            .next()
            .and_then(|value| value.into_string().ok())
            .ok_or_else(|| TrustError::new("E_BOOTSTRAP_ARGUMENTS", "missing run root"))?;
        if iterator.next().is_some()
            || repository_flag != "--repository-root"
            || run_flag != "--run-root"
        {
            return Err(TrustError::new(
                "E_BOOTSTRAP_ARGUMENTS",
                "expected <produce|attest> --repository-root <abs> --run-root <abs>",
            ));
        }
        let mode = match mode.as_str() {
            "produce" => BootstrapMode::Produce,
            "attest" => BootstrapMode::Attest,
            _ => {
                return Err(TrustError::new(
                    "E_BOOTSTRAP_ARGUMENTS",
                    format!("unknown mode {mode:?}"),
                ));
            }
        };
        let repository_root =
            validate_absolute_lexical_path(&repository_value, "repository root")?;
        let run_root = validate_absolute_lexical_path(&run_value, "run root")?;
        validate_existing_directory_root(&repository_root, "repository root")?;
        let scratch_root = repository_root.join(".fnd01-run");
        if run_root == scratch_root || !run_root.starts_with(&scratch_root) {
            return Err(TrustError::new(
                "E_BOOTSTRAP_RUN_ROOT",
                "run root must be a strict descendant of <repository>/.fnd01-run",
            ));
        }
        Ok(BootstrapArguments {
            mode,
            repository_root,
            run_root,
        })
    }
}

#[cfg(fnd01_bootstrap)]
mod bootstrap {
    use super::trust_std::{
        BootstrapMode, TrustError, TrustResult, parse_authoring_marker,
        parse_bootstrap_arguments, parse_integration_seal, read_unique_environment,
        revalidate_authoring_files, revalidate_integration_seal_files,
        verify_authoring_files, verify_integration_seal_files, AUTHORING_MARKER_ENV,
        INTEGRATION_SEAL_ENV,
    };
    use std::ffi::OsString;

    fn run<I>(arguments: I) -> TrustResult<()>
    where
        I: IntoIterator<Item = OsString>,
    {
        let arguments = parse_bootstrap_arguments(arguments)?;
        let authoring_value = read_unique_environment(AUTHORING_MARKER_ENV)?;
        let authoring_marker = parse_authoring_marker(&authoring_value)?;
        let authoring_snapshots =
            verify_authoring_files(&arguments.repository_root, &authoring_marker)?;
        let integration_snapshots = if arguments.mode == BootstrapMode::Attest {
            let seal_value = read_unique_environment(INTEGRATION_SEAL_ENV)?;
            let seal =
                parse_integration_seal(&seal_value, &authoring_marker.closure_sha256)?;
            Some(verify_integration_seal_files(
                &arguments.repository_root,
                &seal,
            )?)
        } else {
            None
        };
        // The attest-only first pass occurs after the authoring set's local
        // bookend, so repeat the retained-set checks immediately before the
        // Phase-B role dispatch.
        revalidate_authoring_files(&arguments.repository_root, &authoring_snapshots)?;
        if let Some(retained) = &integration_snapshots {
            revalidate_integration_seal_files(&arguments.repository_root, retained)?;
        }
        let role = match arguments.mode {
            BootstrapMode::Produce => "produce",
            BootstrapMode::Attest => "attest",
        };
        Err(TrustError::new(
            "E_BOOTSTRAP_PHASE_A",
            format!(
                "{role}: external byte bindings validated; run-root component/no-link/freshness \
                 checks and supply/control execution remain deferred and fail closed"
            ),
        ))
    }

    pub fn harness_main<I>(arguments: I) -> i32
    where
        I: IntoIterator<Item = OsString>,
    {
        match run(arguments) {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("FND01_BOOTSTRAP|{error}");
                3
            }
        }
    }
}

#[cfg(not(fnd01_bootstrap))]
mod ordinary {

use flate2::bufread::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::de::{DeserializeOwned, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;

const POLICY_SCHEMA_VERSION: u32 = 2;
const RECEIPT_SCHEMA_VERSION: u32 = 2;
const FROZEN_POLICY_BYTES: usize = 697_168;
const FROZEN_POLICY_SHA256: &str =
    "c293a9890367ed2cff548c8165cede2285e5ffd5c5481519c85fdc536167ba56";
const EXPECTED_SOURCE_FILES: usize = 66;
const EXPECTED_NEGATIVES: usize = 188;
const MUTATION_RECIPE_CANONICAL_BYTES: usize = 42_564;
const MUTATION_RECIPE_CANONICAL_SHA256: &str =
    "609f0ce94ad6403a3324f1afd705f641573469a833fd3271e84b0647e86f2f5a";
const ASSERTION_CANONICAL_BYTES: usize = 77_379;
const ASSERTION_CANONICAL_SHA256: &str =
    "29f2e159ce5f0febd11d59f3819a0feeb80e57337da940c081cc2be92a88bc24";
const EXPECTED_RECEIPTS: usize = 13;
const EXPECTED_RECEIPT_TOMLS: usize = 10;
const EXPECTED_RECEIPT_BINARIES: usize = 3;
const EXPECTED_DIRECT_PARENT_EDGES: usize = 42;
const PARENT_PURPOSE_REGISTRY_BYTES: usize = 4_622;
const PARENT_PURPOSE_REGISTRY_SHA256: &str =
    "8eb41a8a3cc80c5c79916eda615bd3b0ee0bc2e0d3e9aebd41eaeda582e7cbdc";
const POLICY_SHAPE_SCHEMA_ID: &str = "fastmcp-fnd01-policy-shape";
const POLICY_SHAPE_SCHEMA_VERSION: u32 = 2;
const POLICY_SHAPE_ROW_COUNT: usize = 100;
const POLICY_ROOT_SCALAR_TYPE_ROW_COUNT: usize = 19;
const POLICY_CONDITIONAL_VARIANT_ROW_COUNT: usize = 4;
const POLICY_SHAPE_REGISTRY_BYTES: usize = 37_655;
const POLICY_SHAPE_REGISTRY_SHA256: &str =
    "dccbf908117aed9dd1b609d29b60a7d7e1fedd6f57c4bc31e7bda63377a46534";
const MAX_POLICY_SHAPE_REGISTRY_BYTES: usize = 1_048_576;
const POLICY_TYPE_REGISTRY_ROW_COUNT: usize = 1_584;
const POLICY_TYPE_REGISTRY_BYTES: usize = 84_795;
const POLICY_TYPE_REGISTRY_SHA256: &str =
    "fe8e9ae5dce7a6dc7578dd9b3f289427f70f314a8c94b24734831b97c5589e6d";
const RECORD_SCHEMA_REGISTRY_COUNT: usize = 94;
const RECORD_SCHEMA_SELECTOR_COUNT: usize = 164;
const RECORD_SCHEMA_REGISTRY_BYTES: usize = 41_685;
const RECORD_SCHEMA_REGISTRY_SHA256: &str =
    "570f17c77893f51e4d16bc8639055ce62f973eeb2713a9bb32a8acce80eafcdb";
const RECORD_VARIANT_REGISTRY_COUNT: usize = 2;
const RECORD_VARIANT_REGISTRY_BYTES: usize = 818;
const RECORD_VARIANT_REGISTRY_SHA256: &str =
    "b3a981e6778fec16a22b359843a6cde39b88e4d01a66abd396ca15d6c611d2f9";
const RECEIPT_SCHEMA_REGISTRY_COUNT: usize = 10;
const RECEIPT_SCHEMA_REGISTRY_BYTES: usize = 12_477;
const RECEIPT_SCHEMA_REGISTRY_SHA256: &str =
    "4c1d496195f1f6147f34908f789e64490e110fbcb43a99437b6ee54c89c1a9c1";
const DIRECT_FIELD_TYPE_COUNT: usize = 1_015;
const DIRECT_FIELD_TYPE_REGISTRY_BYTES: usize = 67_433;
const DIRECT_FIELD_TYPE_REGISTRY_SHA256: &str =
    "89e05dd9cd5d3327ef7249d1051fb8a9f7465a803561f464a3b6e046bdab485f";
const EXPECTED_PROJECTIONS: usize = 13;
const EXPECTED_TARGETS: usize = 5;
const EXPECTED_PACKAGES: usize = 9;
const EXPECTED_SDKS: usize = 4;
const HARD_MAX_POLICY_BYTES: u64 = 8 * 1024 * 1024;
const PACKAGE_VERSION: &str = "0.3.2";
const SOURCE_TREE_SHA256: &str =
    "e9bb690856a404e4b3b10a9b86e1bec8f1dfc7005a4c42ee9d346f41216e368b";
const NEGATIVE_INVENTORY_SHA256: &str =
    "294b4285f5fd3f0c36a3cb7dd8fccfb967dde29405805f3e1609858c75c973d5";
const INTEGRATION_PRODUCER: &str = "bd-mcp-2026-07-28-support-ahet.1.1";
const POLICY_OWNER: &str = "bd-mcp-2026-07-28-support-ahet.1.14";
const FINAL_ATTESTER: &str = "bd-mcp-2026-07-28-support-ahet.1.15";

const RECORD_SCHEMA_TYPE_MASKS: &[(&str, &str)] = &[
    ("authoring-file-binding", "sus"),
    ("output-binding", "sssus"),
    ("file-binding", "sus"),
    ("parent-binding", "sssuss"),
    ("workspace-file-binding", "susuuuuuuuu"),
    ("run-directory-binding", "suuuu"),
    ("directory-tree-binding", "ssuuuuuus"),
    ("execution-bin-binding", "suuuuus"),
    ("producer-outer-record-file-binding", "susss"),
    ("attester-outer-record-file-binding", "susss"),
    ("source-input-observation", "ssssssbbbssus"),
    ("source-family-observation", "ssuus"),
    ("archive-observation", "sssauuusus"),
    ("source-quarantine-observation", "ssssSSSBSUbbb"),
    ("closed-child-binding", "ssus"),
    ("worker-observation", "ssssssuussssuuu"),
    ("gate-worker-observation", "ssssssuuss"),
    ("controller-rch-binding", "susssbbb"),
    ("controller-invocation-plan", "raaessuS"),
    ("bootstrap-control-plan", "saesss"),
    ("tool-observation", "ssuss"),
    ("environment-assignment", "ss"),
    ("environment-profile-observation", "suqs"),
    (
        "target-tool-profile-observation",
        "ssssssssssssasssrrr",
    ),
    ("external-input-root-observation", "ssuuuuuus"),
    ("publication-quarantine-observation", "sssuss"),
    ("process-ancestry-observation", "uuususs"),
    ("supply-package", "ssssssaa"),
    ("supply-acquisition-anchor", "ssssus"),
    ("postcommand-lock-binding", "sssusuus"),
    ("command-stream-frame", "ssuuusuus"),
    ("cargo-compiler-artifact", "ssssaassabbas"),
    ("cargo-build-finished", "sbu"),
    ("target-snapshot", "suus"),
    (
        "bootstrap-control-build",
        "srrrrrraesiuusuususrrrrs",
    ),
    ("bootstrap-exec-entry", "sruuraesssbss"),
    ("command-result", "sssuaessssssssiuusuusssss"),
    ("compile-cell", "sssuuuss"),
    ("projection-result", "sssbsssus"),
    ("target-graph-node", "sssssaa"),
    ("target-graph-edge", "ssssSab"),
    ("target-graph", "sssuquqss"),
    ("resolver-delta-item", "ssSS"),
    ("resolver-delta", "suququqss"),
    ("dependency-policy-result", "sssssssss"),
    ("archive-inventory", "suqsss"),
    ("source-inventory", "suqsss"),
    ("license-inventory", "suqsss"),
    ("advisory-inventory", "suqsss"),
    ("unsafe-ffi-panic-inventory", "suqsss"),
    ("build-tool-inventory", "suqsss"),
    ("rng-delta-inventory", "suqsss"),
    ("symbol-inventory", "sruasuqsss"),
    ("archive-inventory-row", "sssusus"),
    ("source-inventory-row", "ssssuss"),
    ("license-inventory-row", "ssuss"),
    ("advisory-inventory-row", "ssbss"),
    ("unsafe-ffi-panic-inventory-row", "ssssuuss"),
    ("build-tool-inventory-row", "sssssss"),
    ("rng-delta-inventory-row", "susssss"),
    ("symbol-inventory-row", "ssusssussssssssss"),
    ("rs256-vector-result", "sssbSs"),
    ("rs256-provider-invariance-result", "ssbSs"),
    ("rs256-openssl-positive-result", "ssbsss"),
    ("rs256-kat", "uququqbbbbss"),
    ("sdk-peer-result", "sssssusssb"),
    ("sdk-matrix", "uqsss"),
    ("workspace-snapshot-summary", "suus"),
    ("workspace-manifest-result", "ssussssssuus"),
    (
        "integration-dependency-rule-result",
        "sssssbssababs",
    ),
    ("integration-source-rule-result", "ssssusus"),
    ("integration-feature-rule-result", "ssssss"),
    ("repository-surface-rule-result", "sssssusus"),
    ("workspace-graph-result", "sssuusus"),
    ("workspace-gate-result", "sssssiss"),
    ("mutation-finding", "sssss"),
    ("mutation-result", "ssussbbuqsaaaaaussss"),
    ("package-result", "ssssussusususbs"),
    ("package-archive-member", "sussss"),
    ("package-list-row", "sssuusss"),
    ("package-source-row", "sssssuussssusS"),
    ("package-listing", "ssusuqsuqss"),
    ("package-source-listing", "ssuqs"),
    ("consumer-extraction", "ssussusss"),
    ("consumer-command-result", "saesssissss"),
    ("consumer-package-result", "sssbbssb"),
    ("integration-edge", "sss"),
    ("integration-rank", "su"),
    ("pending-gate", "ss"),
    ("gate-input-recheck", "srrb"),
    ("gate-fallback-residue", "ssssUSb"),
    ("final-gate-input", "susrrraserrsss"),
    ("final-gate-result", "sussriiususuquqss"),
    ("raw-stream-blob", "usx"),
    ("optional-file-binding", "bSUS"),
    (
        "control-ledger",
        "sussussuqrrssaesirrusrrrraers",
    ),
    ("acquisition-spool-command", "suaesirrsss"),
    ("acquisition-spool", "sussuqrs"),
];

const RECORD_VARIANT_TYPE_MASKS: &[(&str, &str)] = &[
    ("supply-entry-crate-archive", "ssusssssb"),
    (
        "supply-entry-derived-local-index-file",
        "ssussuas",
    ),
];

const RECEIPT_BODY_TYPE_MASKS: &[(&str, &str)] = &[
    ("source-snapshot", "uusququququququqs"),
    ("producer-environment", "rrrruququququqrrrrrrruquqss"),
    ("supply-receipt", "ruqrrusuquququuuusvuqsssssbs"),
    ("command-results", "ruquqrrusuquqsuuuquuauqssss"),
    ("dependency-receipt", "uquququqrrrrrrrrrrs"),
    ("workspace-receipt", "ruququququququqs"),
    ("mutation-receipt", "usususuuuuuuuuuqs"),
    ("package-receipt", "ruqsuquqssssbs"),
    ("consumer-receipt", "rruququqsss"),
    ("integration-index", "uququqss"),
];

const RECEIPT_COMMON_TYPE_MASK: &str = "susssussssrrruussbuq";
const FINAL_ATTESTATION_TYPE_MASK: &str = "sussssssrrrrrrrrruquuassssbssbuq";

const COUNT_ARRAY_LINK_COUNT: usize = 73;
const COUNT_ARRAY_LINK_REGISTRY_BYTES: usize = 5_477;
const COUNT_ARRAY_LINK_REGISTRY_SHA256: &str =
    "b210cee0772271ca37e1179afb682846aa0a466d6c56923b1ad0a53bcd8c4c6e";
const COUNT_ARRAY_LINKS: &[(&str, &str, &str)] = &[
    (
        "schema/environment-profile-observation",
        "assignment_count",
        "assignment",
    ),
    ("schema/target-graph", "node_count", "node"),
    ("schema/target-graph", "edge_count", "edge"),
    ("schema/resolver-delta", "added_count", "added"),
    ("schema/resolver-delta", "removed_count", "removed"),
    ("schema/resolver-delta", "changed_count", "changed"),
    ("schema/archive-inventory", "row_count", "row"),
    ("schema/source-inventory", "row_count", "row"),
    ("schema/license-inventory", "row_count", "row"),
    ("schema/advisory-inventory", "row_count", "row"),
    ("schema/unsafe-ffi-panic-inventory", "row_count", "row"),
    ("schema/build-tool-inventory", "row_count", "row"),
    ("schema/rng-delta-inventory", "row_count", "row"),
    (
        "schema/symbol-inventory",
        "response_artifact_count",
        "response_artifact_path",
    ),
    ("schema/symbol-inventory", "row_count", "row"),
    ("schema/rs256-kat", "vector_count", "vector"),
    (
        "schema/rs256-kat",
        "provider_invariance_count",
        "provider_invariance",
    ),
    (
        "schema/rs256-kat",
        "openssl_positive_count",
        "openssl_positive",
    ),
    ("schema/sdk-matrix", "result_count", "result"),
    (
        "schema/mutation-result",
        "raw_finding_count",
        "raw_finding",
    ),
    (
        "schema/package-listing",
        "raw_row_count",
        "raw_row",
    ),
    (
        "schema/package-listing",
        "source_row_count",
        "source_row",
    ),
    (
        "schema/package-source-listing",
        "member_count",
        "member",
    ),
    (
        "schema/final-gate-result",
        "input_recheck_count",
        "input_recheck",
    ),
    (
        "schema/final-gate-result",
        "fallback_residue_count",
        "fallback_residue",
    ),
    (
        "schema/control-ledger",
        "scratch_binding_count",
        "scratch_binding",
    ),
    (
        "schema/acquisition-spool",
        "command_count",
        "command",
    ),
    (
        "variant/supply-entry-derived-local-index-file",
        "selected_row_count",
        "selected_version",
    ),
    (
        "receipt/source_snapshot/source_snapshot",
        "workspace_file_count",
        "workspace_binding",
    ),
    (
        "receipt/source_snapshot/source_snapshot",
        "source_input_count",
        "source_input",
    ),
    (
        "receipt/source_snapshot/source_snapshot",
        "source_family_count",
        "source_family",
    ),
    (
        "receipt/source_snapshot/source_snapshot",
        "archive_count",
        "archive",
    ),
    (
        "receipt/source_snapshot/source_snapshot",
        "quarantine_count",
        "quarantine",
    ),
    (
        "receipt/source_snapshot/source_snapshot",
        "closed_child_count",
        "closed_child",
    ),
    (
        "receipt/source_snapshot/source_snapshot",
        "authoring_count",
        "authoring",
    ),
    (
        "receipt/producer_environment/producer_environment",
        "tool_count",
        "tool",
    ),
    (
        "receipt/producer_environment/producer_environment",
        "environment_profile_count",
        "environment_profile",
    ),
    (
        "receipt/producer_environment/producer_environment",
        "proxy_count",
        "proxy",
    ),
    (
        "receipt/producer_environment/producer_environment",
        "target_tool_profile_count",
        "target_tool_profile",
    ),
    (
        "receipt/producer_environment/producer_environment",
        "external_input_root_count",
        "external_input_root",
    ),
    (
        "receipt/producer_environment/producer_environment",
        "quarantine_count",
        "quarantine",
    ),
    (
        "receipt/producer_environment/producer_environment",
        "process_ancestry_count",
        "process_ancestry",
    ),
    (
        "receipt/supply_receipt/supply_receipt",
        "bundle_parent_count",
        "bundle_parent",
    ),
    (
        "receipt/supply_receipt/supply_receipt",
        "bootstrap_package_count",
        "bootstrap_package",
    ),
    (
        "receipt/supply_receipt/supply_receipt",
        "downstream_union_package_count",
        "downstream_union_package",
    ),
    (
        "receipt/supply_receipt/supply_receipt",
        "control_only_package_count",
        "control_only_package",
    ),
    (
        "receipt/supply_receipt/supply_receipt",
        "entry_count",
        "entry",
    ),
    (
        "receipt/supply_receipt/supply_receipt",
        "acquisition_anchor_count",
        "acquisition_anchor",
    ),
    (
        "receipt/command_results/command_results",
        "streams_parent_count",
        "streams_parent",
    ),
    (
        "receipt/command_results/command_results",
        "control_frame_count",
        "control_frame",
    ),
    (
        "receipt/command_results/command_results",
        "command_count",
        "command",
    ),
    (
        "receipt/command_results/command_results",
        "compile_cell_count",
        "compile_cell",
    ),
    (
        "receipt/command_results/command_results",
        "postcommand_lock_count",
        "postcommand_lock",
    ),
    (
        "receipt/dependency_receipt/dependency_receipt",
        "projection_count",
        "projection",
    ),
    (
        "receipt/dependency_receipt/dependency_receipt",
        "target_graph_count",
        "target_graph",
    ),
    (
        "receipt/dependency_receipt/dependency_receipt",
        "resolver_delta_count",
        "resolver_delta",
    ),
    (
        "receipt/dependency_receipt/dependency_receipt",
        "dependency_policy_count",
        "dependency_policy",
    ),
    (
        "receipt/workspace_receipt/workspace_receipt",
        "manifest_count",
        "manifest",
    ),
    (
        "receipt/workspace_receipt/workspace_receipt",
        "integration_dependency_rule_count",
        "integration_dependency_rule",
    ),
    (
        "receipt/workspace_receipt/workspace_receipt",
        "integration_source_rule_count",
        "integration_source_rule",
    ),
    (
        "receipt/workspace_receipt/workspace_receipt",
        "integration_feature_rule_count",
        "integration_feature_rule",
    ),
    (
        "receipt/workspace_receipt/workspace_receipt",
        "repository_surface_rule_count",
        "repository_surface_rule",
    ),
    (
        "receipt/workspace_receipt/workspace_receipt",
        "workspace_graph_count",
        "workspace_graph",
    ),
    (
        "receipt/workspace_receipt/workspace_receipt",
        "workspace_gate_count",
        "workspace_gate",
    ),
    (
        "receipt/mutation_receipt/mutation_receipt",
        "result_count",
        "result",
    ),
    (
        "receipt/package_receipt/package_receipt",
        "artifacts_parent_count",
        "artifacts_parent",
    ),
    (
        "receipt/command_results/command_results",
        "package_list_count",
        "package_list",
    ),
    (
        "receipt/package_receipt/package_receipt",
        "package_count",
        "package",
    ),
    (
        "receipt/package_receipt/package_receipt",
        "source_listing_count",
        "source_listing",
    ),
    (
        "receipt/consumer_receipt/consumer_receipt",
        "extraction_count",
        "extraction",
    ),
    (
        "receipt/consumer_receipt/consumer_receipt",
        "consumer_command_count",
        "consumer_command",
    ),
    (
        "receipt/consumer_receipt/consumer_receipt",
        "package_count",
        "package",
    ),
    (
        "receipt/integration_index/integration_index",
        "member_count",
        "member",
    ),
    (
        "receipt/integration_index/integration_index",
        "edge_count",
        "edge",
    ),
    (
        "receipt/integration_index/integration_index",
        "rank_count",
        "rank",
    ),
    ("receipt/common", "parent_count", "parent"),
    ("final-attestation", "output_count", "output"),
    ("final-attestation", "pending_count", "pending"),
];

const COMMAND_TEMPLATE_IDS: [&str; 17] = [
    "bootstrap.resolve",
    "bootstrap.fetch",
    "tool.identity",
    "projection.resolve.r3",
    "projection.resolve.r2",
    "projection.graph.r3",
    "projection.compile.r3.ring-free",
    "projection.compile.r3.ring-bearing",
    "projection.symbol-build",
    "projection.symbol-scan",
    "workspace.graph.default",
    "workspace.graph.all",
    "workspace.gate",
    "kat.openssl",
    "package.list",
    "package",
    "consumer",
];
const COMMAND_TEMPLATE_EXPANSION_COUNTS: [usize; 17] =
    [1, 1, 6, 13, 13, 65, 45, 20, 8, 1, 5, 5, 6, 2, 9, 2, 4];
const COMMAND_TEMPLATE_GROUPS: [&str; 17] = [
    "bootstrap",
    "bootstrap",
    "tool-identity",
    "resolver-root-metadata",
    "resolver-root-metadata",
    "target-filtered-metadata",
    "projection-check",
    "projection-check",
    "host-symbol-build",
    "host-llvm-nm",
    "workspace-graph",
    "workspace-graph",
    "workspace-gate",
    "openssl-kat",
    "package-ab",
    "package-ab",
    "packaged-consumer",
];
const COMMAND_FAMILY_IDS: [&str; 12] = [
    "bootstrap",
    "tool-identity",
    "resolver-root-metadata",
    "target-filtered-metadata",
    "projection-check",
    "host-symbol-build",
    "host-llvm-nm",
    "workspace-graph",
    "workspace-gate",
    "openssl-kat",
    "package-ab",
    "packaged-consumer",
];
const COMMAND_FAMILY_COUNTS: [usize; 12] = [2, 6, 26, 65, 65, 8, 1, 10, 6, 2, 11, 4];

const OUTPUT_IDS: &[&str] = &[
    "source-snapshot",
    "producer-environment",
    "supply-bundle",
    "supply-receipt",
    "command-streams",
    "command-results",
    "dependency-receipt",
    "workspace-receipt",
    "mutation-receipt",
    "package-artifacts",
    "package-receipt",
    "consumer-receipt",
    "integration-index",
];

const OUTPUT_PATHS: &[&str] = &[
    "evidence/fnd-01/integration/source-snapshot.toml",
    "evidence/fnd-01/integration/producer-environment.toml",
    "evidence/fnd-01/integration/supply-bundle.bin",
    "evidence/fnd-01/integration/supply-receipt.toml",
    "evidence/fnd-01/integration/command-streams.bin.gz",
    "evidence/fnd-01/integration/command-results.toml",
    "evidence/fnd-01/integration/dependency-receipt.toml",
    "evidence/fnd-01/integration/workspace-receipt.toml",
    "evidence/fnd-01/integration/mutation-receipt.toml",
    "evidence/fnd-01/integration/package-artifacts.bin",
    "evidence/fnd-01/integration/package-receipt.toml",
    "evidence/fnd-01/integration/consumer-receipt.toml",
    "evidence/fnd-01/integration/integration-index.toml",
];

const OUTPUT_KINDS: &[&str] = &[
    "source_snapshot",
    "producer_environment",
    "supply_bundle",
    "supply_receipt",
    "command_streams",
    "command_results",
    "dependency_receipt",
    "workspace_receipt",
    "mutation_receipt",
    "package_artifacts",
    "package_receipt",
    "consumer_receipt",
    "integration_index",
];

const BINARY_OUTPUT_IDS: &[&str] = &[
    "supply-bundle",
    "command-streams",
    "package-artifacts",
];

const TOML_OUTPUT_IDS: &[&str] = &[
    "source-snapshot",
    "producer-environment",
    "supply-receipt",
    "command-results",
    "dependency-receipt",
    "workspace-receipt",
    "mutation-receipt",
    "package-receipt",
    "consumer-receipt",
    "integration-index",
];

const PROJECTIONS: &[&str] = &[
    "workspace-baseline",
    "core-foundation",
    "asupersync-0.3.9",
    "asupersync-0.3.10-rejected",
    "serialization-uri",
    "jose-ring-direct",
    "tls-plus-jose-unified",
    "media-html5ever",
    "media-image",
    "media-resvg",
    "state-envelope",
    "state-capability-fs",
    "state-redis",
];

const TARGETS: &[&str] = &[
    "aarch64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "x86_64-unknown-linux-gnu",
];

const SDK_IDS: &[&str] = &["typescript", "python", "csharp", "go"];

const PACKAGE_IDS: &[&str] = &[
    "fastmcp-rust",
    "fastmcp-core",
    "fastmcp-protocol",
    "fastmcp-transport",
    "fastmcp-server",
    "fastmcp-client",
    "fastmcp-derive",
    "fastmcp-console",
    "fastmcp-cli",
];

const SOURCE_FAMILIES: &[(&str, &str, usize, u64, &str)] = &[
    (
        "core",
        "bd-mcp-2026-07-28-support-ahet.1.2",
        7,
        367_030,
        "8dcb85833bcbba14c45a9643de0ef892a9cf1c16f32b9f96a2bba6fa29aa7021",
    ),
    (
        "tasks_apps",
        "bd-mcp-2026-07-28-support-ahet.1.3",
        14,
        1_374_873,
        "a48f8da9b1ebe4468230f1bdbc8a5e7ea2d1fb501b022b031d5b9f8a43d9cb49",
    ),
    (
        "auth",
        "bd-mcp-2026-07-28-support-ahet.1.4",
        1,
        47_484,
        "666855be022cb35f34409050eb91622eb867d586ab4503207b436996c7647c2b",
    ),
    (
        "sdk",
        "bd-mcp-2026-07-28-support-ahet.1.5",
        14,
        89_103,
        "7871c0ee9a815abe7b2b39355de0046b75b455e59e8448c019ac59543d5f8c25",
    ),
    (
        "toolchain",
        "bd-mcp-2026-07-28-support-ahet.1.6",
        4,
        59_659,
        "6a6068bbd609193d8a53284226a0ca821d5203aaf36c21457a938946d06edf1a",
    ),
    (
        "serialization",
        "bd-mcp-2026-07-28-support-ahet.1.7",
        2,
        57_001,
        "b3bf50f442b52c6775ca8001e4fb4e86acad8556558e7afe82d3c9dacf065d0d",
    ),
    (
        "jose",
        "bd-mcp-2026-07-28-support-ahet.1.11",
        4,
        11_364,
        "ab70b0dd9d675825b9dda72a737fe296ee1de72116ea09e7490183972be85bbd",
    ),
    (
        "media",
        "bd-mcp-2026-07-28-support-ahet.1.12",
        10,
        559_330,
        "8f8f0cd6503eaa6a31971f0e6ec93f9798b8799769dd6f895c6efff9d830cb15",
    ),
    (
        "state",
        "bd-mcp-2026-07-28-support-ahet.1.13",
        10,
        106_043,
        "3df9af76991b048e402e15b807026e34df686896972bcf7ef44f8f256193e298",
    ),
];

const SOURCE_ARCHIVES: &[(&str, &str, &str, usize, u64, &str)] = &[
    (
        "tiny-skia-0.12.0",
        "evidence/fnd-01/vectors/media/tiny-skia-0.12.0.crate",
        "tiny-skia-0.12.0",
        200,
        799_605,
        "907f0c0dfa6247d760c32bb4fe565148e703266d44a2a456e3984f11656bca8f",
    ),
    (
        "tiny-skia-path-0.12.0",
        "evidence/fnd-01/vectors/media/tiny-skia-path-0.12.0.crate",
        "tiny-skia-path-0.12.0",
        19,
        221_110,
        "a95b4911a601e00010d312c2a4827b6d362b7cddb53005f031787e010793091d",
    ),
    (
        "usvg-0.47.0",
        "evidence/fnd-01/vectors/media/usvg-0.47.0.crate",
        "usvg-0.47.0",
        39,
        655_886,
        "3818c9dfe3466a924f5413fff61b229782cd95d25a9088562733f55fcf2b195a",
    ),
];

const NEGATIVE_FAMILIES: &[(&str, &str, &str, usize, &str)] = &[
    (
        "sdk.catalog",
        "evidence/fnd-01/sdk-matrix.toml",
        "catalog_negative_cases",
        6,
        "8ab04cce3b0914db027bbf5ce66177f53fae938913d86c7eb603bf373fd855ae",
    ),
    (
        "sdk.peer",
        "evidence/fnd-01/sdk-matrix.toml",
        "peer_negative_cases",
        6,
        "0c35e75a468882916c71a8fe002cbee69b664d6ea767e4fbac8fd0d2cb8f53cd",
    ),
    (
        "auth",
        "evidence/fnd-01/auth-standards.toml",
        "substitution_negatives",
        61,
        "726c87d92a4ea27a1dd0081eee2bc677c54fc4ea69ce53970be4ed108974b8e4",
    ),
    (
        "tasks_apps",
        "evidence/fnd-01/tasks-apps.toml",
        "drift_negative",
        42,
        "98cde81a23c988ad56f34eed844304e4cd63452ab1f99a3e692f1297f2fd64a0",
    ),
    (
        "media",
        "evidence/fnd-01/media-dependencies.toml",
        "substitution_negative",
        34,
        "aee60f347471635c306d6906f9f1e5df1a5a9336adcea1a945f39731d732fa8a",
    ),
    (
        "state",
        "evidence/fnd-01/state-capability-dependencies.toml",
        "negative_evidence",
        39,
        "2298cf6720809148d968333e76def2a65decdac9da52de06d7f0bd0bc2f54c96",
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Severity {
    Pending,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Diagnostic {
    severity: Severity,
    code: String,
    subject: String,
    logical_path: String,
}

impl Diagnostic {
    fn error(code: impl Into<String>, subject: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            code: code.into(),
            subject: subject.into(),
            logical_path: String::new(),
        }
    }

    fn pending(gate: impl Into<String>) -> Self {
        let gate = gate.into();
        Self {
            severity: Severity::Pending,
            code: gate.clone(),
            subject: gate,
            logical_path: String::new(),
        }
    }

    fn at(mut self, logical_path: impl Into<String>) -> Self {
        self.logical_path = logical_path.into();
        self
    }

    fn stable(&self) -> String {
        format!(
            "FND01|{:?}|{}|{}|{}",
            self.severity, self.code, self.subject, self.logical_path
        )
    }
}

type VResult<T> = Result<T, Diagnostic>;

#[derive(Debug, Default)]
struct Report {
    diagnostics: Vec<Diagnostic>,
}

impl Report {
    fn push(&mut self, diagnostic: Diagnostic) {
        self.diagnostics.push(diagnostic);
    }

    fn extend(&mut self, diagnostics: impl IntoIterator<Item = Diagnostic>) {
        self.diagnostics.extend(diagnostics);
    }

    fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == Severity::Error)
    }

    fn sorted_stable(&self) -> Vec<String> {
        let mut diagnostics = self.diagnostics.clone();
        diagnostics.sort();
        diagnostics
            .iter()
            .map(Diagnostic::stable)
            .collect::<Vec<_>>()
    }
}

#[derive(Debug, Deserialize)]
struct Policy {
    format: String,
    schema_version: u32,
    policy_id: String,
    protocol_version: String,
    recorded_on: String,
    hash_algorithm: String,
    authoring_bead: String,
    integration_producer_bead: String,
    final_attester_bead: String,
    source_input_count: usize,
    source_input_total_bytes: u64,
    negative_case_count: usize,
    derived_output_count: usize,
    derived_toml_count: usize,
    derived_binary_count: usize,
    derived_direct_parent_edge_count: usize,
    deny_unknown_policy_fields: bool,
    deny_unknown_receipt_fields: bool,
    aggregate_support_claimed: bool,
    paths: PolicyPaths,
    bounds: Bounds,
    source_tree: SourceTreeContract,
    source_input_contract: SourceInputContract,
    parse_inventory: ParseInventory,
    negative_inventory: NegativeInventoryContract,
    mutation_contract: MutationContract,
    fixture_contract: FixtureContract,
    assertion_contract: AssertionContract,
    observation_typing: ObservationTyping,
    archive_parser_contract: ArchiveParserContract,
    output_namespace: OutputNamespaceContract,
    receipt_contract: ReceiptContract,
    parent_contract: ParentContract,
    final_attestation_contract: FinalAttestationContract,
    pending_contract: PendingContract,
    nonpromotion_contract: NonpromotionContract,
    source_family: Vec<SourceFamilyContract>,
    negative_family: Vec<NegativeSourceContract>,
    archive_contract: Vec<ArchiveContract>,
    quarantine: Vec<QuarantineContract>,
    projection: Vec<ProjectionContract>,
    record_schema: Vec<RecordSchemaContract>,
    record_variant_schema: Vec<RecordVariantSchemaContract>,
    receipt_schema: Vec<ReceiptSchemaContract>,
    command_template: Vec<CommandTemplateContract>,
    environment_profile: Vec<EnvironmentProfileContract>,
    target_tool_profile: Vec<TargetToolProfileContract>,
    source_input: Vec<SourceFileContract>,
    semantic_assertion: Vec<SemanticAssertion>,
    negative_case: Vec<NegativeCase>,
    mutation_fixture: Vec<MutationFixture>,
    derived_output: Vec<DerivedOutputContract>,
    #[serde(flatten)]
    _validated_unmodeled: BTreeMap<String, toml::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyPaths {
    repository_root_resolution: String,
    repository_root_parent_count: usize,
    current_dir_allowed: bool,
    environment_path_search_allowed: bool,
    ancestor_manifest_discovery_allowed: bool,
    source_root: String,
    policy_path: String,
    verifier_test_path: String,
    bootstrap_harness_path: String,
    integration_root: String,
    final_attestation_path: String,
    run_scratch_root: String,
    integration_is_flat: bool,
    follow_symlinks: bool,
    allow_absolute_paths: bool,
    allow_backslashes: bool,
    allow_empty_components: bool,
    allow_dot_components: bool,
    allow_dot_dot_components: bool,
    allow_drive_prefixes: bool,
    allow_nul: bool,
    reject_hardlinks: bool,
    reject_special_files: bool,
    reject_ascii_case_collisions: bool,
    reject_extra_files: bool,
    reject_extra_directories: bool,
    typed_path_scope_rule: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bounds {
    max_path_bytes: usize,
    max_path_component_bytes: usize,
    max_path_depth: usize,
    max_id_bytes: usize,
    max_selector_bytes: usize,
    max_selector_depth: usize,
    max_source_file_bytes: u64,
    max_policy_bytes: u64,
    max_verifier_test_bytes: u64,
    max_bootstrap_harness_bytes: u64,
    max_receipt_toml_bytes: u64,
    max_supply_bundle_bytes: u64,
    max_command_stream_bundle_bytes: u64,
    max_command_stream_expanded_bytes: u64,
    max_package_artifact_bytes: u64,
    max_final_attestation_bytes: u64,
    max_integration_total_bytes: u64,
    max_outer_transport_record_bytes: u64,
    max_outer_transport_argv_items: usize,
    max_outer_transport_assignments: usize,
    max_outer_transport_argument_bytes: usize,
    max_outer_transport_key_bytes: usize,
    max_outer_transport_value_bytes: usize,
    max_outer_transport_stdout_bytes: u64,
    max_outer_transport_stderr_bytes: u64,
    max_outer_transport_final_argv_items: usize,
    max_outer_transport_cfg_entries: usize,
    max_outer_transport_cfg_bytes: u64,
    max_final_gate_stdout_bytes: u64,
    max_final_gate_stderr_bytes: u64,
    max_final_gate_input_bytes: u64,
    max_final_gate_result_bytes: u64,
    max_gate_executable_bytes: u64,
    max_control_ledger_bytes: u64,
    max_acquisition_spool_bytes: u64,
    max_raw_stdout_bytes: u64,
    max_raw_stderr_bytes: u64,
    max_argv_items: usize,
    max_argument_bytes: usize,
    max_environment_items: usize,
    max_environment_key_bytes: usize,
    max_environment_value_bytes: usize,
    max_parent_count: usize,
    max_archive_compressed_bytes: u64,
    max_archive_expanded_bytes: u64,
    max_archive_member_count: usize,
    max_archive_member_bytes: u64,
    max_tree_entry_count: usize,
    max_run_scratch_total_bytes: u64,
    max_execution_footprint_total_bytes: u64,
    max_fallback_target_total_bytes: u64,
    max_transport_target_total_bytes: u64,
    max_controller_scratch_total_bytes: u64,
    max_control_plane_total_bytes: u64,
    max_package_source_total_bytes: u64,
    max_quarantine_total_bytes: u64,
    max_return_tree_total_bytes: u64,
    max_publication_staging_total_bytes: u64,
    max_bootstrap_scratch_total_bytes: u64,
    max_materialization_total_bytes: u64,
    max_projection_tree_total_bytes: u64,
    max_package_tree_total_bytes: u64,
    max_consumer_tree_total_bytes: u64,
    max_external_input_entry_count: usize,
    max_external_input_member_bytes: u64,
    max_external_input_total_bytes: u64,
    max_record_depth: usize,
    max_record_field_count: usize,
    max_record_array_items: usize,
    max_record_string_bytes: usize,
    max_record_blob_bytes: u64,
    max_record_total_bytes: u64,
    max_record_registry_bytes: u64,
    max_receipt_schema_registry_bytes: u64,
    max_policy_shape_registry_bytes: u64,
    exact_source_input_count: usize,
    exact_negative_case_count: usize,
    exact_derived_output_count: usize,
    exact_derived_toml_count: usize,
    exact_derived_binary_count: usize,
    exact_direct_parent_edge_count: usize,
    exact_projection_count: usize,
    exact_target_count: usize,
    exact_projection_target_count: usize,
}

#[derive(Debug, Clone, Copy)]
struct ArchiveBounds {
    max_archive_compressed_bytes: u64,
    max_archive_expanded_bytes: u64,
    max_archive_member_count: usize,
    max_archive_member_bytes: u64,
}

impl Bounds {
    fn archive_bounds(&self) -> ArchiveBounds {
        ArchiveBounds {
            max_archive_compressed_bytes: self.max_archive_compressed_bytes,
            max_archive_expanded_bytes: self.max_archive_expanded_bytes,
            max_archive_member_count: self.max_archive_member_count,
            max_archive_member_bytes: self.max_archive_member_bytes,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceTreeContract {
    format: String,
    path_scope: String,
    ordering: String,
    record_encoding: String,
    domain_prefix: String,
    file_count: usize,
    total_bytes: u64,
    sha256: String,
    excluded_exact_paths: Vec<String>,
    excluded_exact_directory: String,
    wildcard_exclusions_allowed: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceInputContract {
    all_rows_bytes_available: bool,
    all_rows_rehash_mode: String,
    all_rows_claim_ceiling: String,
    all_rows_required: bool,
    all_rows_source_tree_members: bool,
    checked_in_archives_remain_local_exact_bytes: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ParseInventory {
    toml: usize,
    json: usize,
    utf8_text: usize,
    opaque_binary: usize,
    gzip_tar: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NegativeInventoryContract {
    family_order: Vec<String>,
    row_order_authoritative: bool,
    canonical_order: String,
    source_indices_must_be_contiguous_per_family: bool,
    canonical_record: String,
    count: usize,
    canonical_bytes: usize,
    sha256: String,
    ids_globally_unique: bool,
    one_recipe_per_id: bool,
    anonymous_corpora_excluded: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationContract {
    allowed_operations: Vec<String>,
    allowed_integrity_modes: Vec<String>,
    default_integrity_mode: String,
    all_cases_must_rebind_virtual_hashes: bool,
    selector_grammar: String,
    require_target_path_exists: bool,
    require_target_selector_resolves: bool,
    require_non_noop_mutation: bool,
    remove_argument_forbidden_except_remove_exact_fixture: bool,
    duplicate_argument_forbidden: bool,
    swap_argument_forbidden: bool,
    swap_secondary_selector_required: bool,
    insert_argument_required: bool,
    replace_argument_required: bool,
    toggle_bool_argument_required: bool,
    increment_argument_required: bool,
    append_feature_argument_required: bool,
    rename_key_argument_required: bool,
    replace_bytes_argument_required: bool,
    replace_bytes_argument_grammar: String,
    non_swap_secondary_selector_forbidden: bool,
    stable_diagnostic_format: String,
    require_exact_one_primary_diagnostic: bool,
    additional_diagnostic_rule: String,
    require_literal_family_id_rule_and_path: bool,
    forbid_negative_row_self_mutation: bool,
    negative_case_rows_deny_unknown_fields: bool,
    negative_case_exact_fields: Vec<String>,
    assertion_registry_is_only_oracle_authority: bool,
    forbid_result_field_mutation: bool,
    forbid_verified_field_mutation: bool,
    semantic_drift_meta_test_required: bool,
    semantic_drift_meta_test_rebinds_file_and_tree_hashes: bool,
    mutation_execution_isolation: String,
    quarantine_meta_test_exception: String,
    structured_toml_mutation_allowed: bool,
    structured_json_mutation_allowed: bool,
    structured_json_duplicate_keys_rejected: bool,
    structured_json_reserved_number_member_name_rule: String,
    structured_json_depth_and_member_bounds_required: bool,
    structured_json_numbers_must_be_losslessly_classified: bool,
    canonical_recipe_encoding: String,
    canonical_recipe_order: String,
    canonical_recipe_fields: Vec<String>,
    canonical_recipe_string_encoding: String,
    canonical_recipe_source_index_encoding: String,
    canonical_recipe_optional_string_encoding: String,
    canonical_recipe_count: usize,
    canonical_recipe_bytes: usize,
    canonical_recipe_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureContract {
    reference_prefix: String,
    exact_fixture_count: usize,
    max_fixture_id_bytes: usize,
    max_fixture_value_bytes: usize,
    max_fixture_value_depth: usize,
    max_fixture_value_members: usize,
    allowed_applications: Vec<String>,
    allowed_value_kinds: Vec<String>,
    ids_must_be_unique: bool,
    all_references_must_resolve: bool,
    all_fixtures_must_be_referenced: bool,
    application_must_match_operation: bool,
    replace_operation_applications: Vec<String>,
    remove_operation_applications: Vec<String>,
    insert_operation_applications: Vec<String>,
    swap_operation_applications: Vec<String>,
    duplicate_operation_applications: Vec<String>,
    toggle_bool_operation_applications: Vec<String>,
    increment_operation_applications: Vec<String>,
    append_feature_operation_applications: Vec<String>,
    rename_key_operation_applications: Vec<String>,
    replace_bytes_operation_applications: Vec<String>,
    value_kind_must_match_value: bool,
    payload_must_be_nonempty: bool,
    payload_must_differ_from_canonical_target: bool,
    target_type_compatibility_required: bool,
    literal_fixture_reference_is_forbidden: bool,
    toml_and_json_target_compatibility_required: bool,
    remove_exact_value_must_equal_selected_value: bool,
    table_member_value_requires_exact_keys: Vec<String>,
    table_member_relative_selector_grammar: String,
    insert_table_member_relative_selector_component_count: usize,
    table_member_key_collision_allowed_for_insert: bool,
    insert_table_member_requires_absent_target: bool,
    replace_table_member_key_must_exist: bool,
    replace_table_member_requires_exact_single_resolution: bool,
    replace_table_member_identity_is_required_for_table_arrays: bool,
    fixture_rows_deny_unknown_fields: bool,
    value_digest_encoding: String,
    canonical_record: String,
    canonical_encoding: String,
    canonical_count: usize,
    canonical_bytes: usize,
    canonical_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssertionContract {
    exact_assertion_count: usize,
    baseline_preflight_required: bool,
    post_mutation_full_scan_required: bool,
    observation_encoding: String,
    header: String,
    toml_kind_byte: u8,
    json_kind_byte: u8,
    raw_kind_byte: u8,
    path_encoding: String,
    selector_tuple_encoding: String,
    value_sequence: String,
    toml_domain: String,
    json_domain: String,
    raw_domain: String,
    missing_tag: String,
    json_null_tag: String,
    boolean_tag: String,
    toml_integer_tag: String,
    toml_float_tag: String,
    string_tag: String,
    array_tag: String,
    map_tag: String,
    raw_bytes_tag: String,
    toml_datetime_tag: String,
    json_number_tag: String,
    hash_algorithm: String,
    digest_encoding: String,
    allowed_observation_modes: Vec<String>,
    allowed_violation_modes: Vec<String>,
    swap_assertion_secondary_selector_required: bool,
    swap_assertion_secondary_selector_must_equal_recipe: bool,
    non_swap_assertion_secondary_selector_forbidden: bool,
    single_selector_count: usize,
    swap_selector_count: usize,
    pointer_overlap: String,
    baseline_preservation_scope: String,
    observation_identity: String,
    overlapping_non_target_rule: String,
    default_expected_trigger_count: usize,
    default_allowed_cotrigger_ids: Vec<String>,
    default_suppressed_ids: Vec<String>,
    finding_precedence: String,
    reference_rule: String,
    trigger_count_rule: String,
    diagnostic_authority_rule: String,
    reject_all_length_or_count_conversion_overflow: bool,
    enforce_bounds_before_encoding: bool,
    assertion_rows_deny_unknown_fields: bool,
    canonical_encoding: String,
    canonical_order: String,
    canonical_fields: Vec<String>,
    canonical_string_encoding: String,
    canonical_optional_string_encoding: String,
    canonical_expected_trigger_count_encoding: String,
    canonical_allowed_cotrigger_ids_encoding: String,
    canonical_suppressed_ids_encoding: String,
    canonical_count: usize,
    canonical_bytes: usize,
    canonical_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationTyping {
    allowed_kinds: Vec<String>,
    allowed_rehash_modes: Vec<String>,
    remote_may_claim_local_bytes: bool,
    local_cache_may_claim_checked_in_bytes: bool,
    receipt_text_substitutes_for_bytes: bool,
    missing_required_local_bytes_is_pass: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveParserContract {
    gzip_member_count: usize,
    gzip_trailing_bytes_allowed: bool,
    tar_terminal_zero_block_count: usize,
    tar_trailing_bytes_after_terminal_blocks_allowed: bool,
    allowed_tar_typeflags: Vec<String>,
    path_encoding: String,
    reject_invalid_utf8: bool,
    reject_absolute_path: bool,
    reject_backslash: bool,
    reject_drive_prefix: bool,
    reject_unc_prefix: bool,
    reject_colon: bool,
    reject_empty_component: bool,
    reject_dot_component: bool,
    reject_dot_dot_component: bool,
    reject_percent_encoded_separator: bool,
    reject_duplicate_path: bool,
    reject_ascii_case_collision: bool,
    require_exact_root_name_version: bool,
    check_header_checksum: bool,
    check_all_integer_conversions: bool,
    check_all_offset_and_size_additions: bool,
    filesystem_canonicalize_allowed: bool,
    filesystem_follow_allowed: bool,
    member_tree_record_encoding: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutputNamespaceContract {
    root: String,
    flat: bool,
    output_count: usize,
    toml_count: usize,
    binary_count: usize,
    direct_parent_edge_count: usize,
    integration_index_member_count: usize,
    integration_index_may_hash_itself: bool,
    final_attestation_in_namespace: bool,
    output_ids: Vec<String>,
    output_paths: Vec<String>,
    output_kinds: Vec<String>,
    id_path_kind_arrays_are_zipped: bool,
    order_rule: String,
    binary_ids: Vec<String>,
    toml_ids: Vec<String>,
    projections: Vec<String>,
    publication_rule: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptContract {
    format_literal: String,
    schema_version_literal: u32,
    toml_receipt_count: usize,
    binary_output_count: usize,
    schema_dispatch: String,
    schema_registry_encoding: String,
    schema_registry_count: usize,
    schema_registry_bytes: usize,
    schema_registry_sha256: String,
    schema_registry_bound_rule: String,
    schema_registry_verifier_authority_rule: String,
    common_required_fields: Vec<String>,
    common_field_rule: String,
    exact_field_union_rule: String,
    binary_rule: String,
    candidate_rule: String,
    digest_rule: String,
    support_claim_must_be_false: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ParentContract {
    edge_count: usize,
    parent_binding_exact_fields: Vec<String>,
    parent_order: String,
    edge_semantics: String,
    no_implicit_edges_rule: String,
    binary_parent_rule: String,
    binary_sidecar_rule: String,
    package_edge_construction_rule: String,
    rank_rule: String,
    member_rank_counts_1_through_11: Vec<usize>,
    member_rank_count_sum: usize,
    integration_index_rank: u32,
    all_output_rank_counts_1_through_12: Vec<usize>,
    all_output_rank_count_sum: usize,
    non_index_max_parent_count: usize,
    index_parent_count: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalAttestationContract {
    format: String,
    schema_version: u32,
    attestation_id_literal: String,
    path: String,
    role: String,
    exact_fields: Vec<String>,
    output_rule: String,
    entry_rule: String,
    rerun_rule: String,
    return_rule: String,
    self_exclusion_rule: String,
    verdict_rule: String,
    claim_ceiling: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingContract {
    verdicts: Vec<String>,
    gate_prefix: String,
    authoring_allowed_pending: Vec<String>,
    post_authoring_allowed_pending: Vec<String>,
    post_publication_allowed_pending: Vec<String>,
    post_seal_allowed_pending: Vec<String>,
    post_attestation_allowed_pending: Vec<String>,
    final_allowed_pending: Vec<String>,
    missing_frozen_source_is_pending: bool,
    missing_required_current_phase_output_is_pending: bool,
    present_invalid_output_is_pending: bool,
    extra_output_is_pending: bool,
    failed_or_skipped_command_is_pending: bool,
    rule: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NonpromotionContract {
    aggregate_support_claimed: bool,
    all_receipt_support_claims_false: bool,
    resolver_domain: Vec<String>,
    canonical_resolver: String,
    resolver2_is_comparison_only: bool,
    resolver2_to_3_delta_required: bool,
    candidate_dispositions: Vec<String>,
    candidate_evidence_rule: String,
    fixed_candidates: Vec<String>,
    jose_scope: String,
    sdk_scope: String,
    excluded_work: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceFileContract {
    id: String,
    family: String,
    owner_bead: String,
    path: String,
    byte_length: u64,
    sha256: String,
    parse_kind: FileFamily,
    observation_kind: ObservationKind,
    bytes_available: bool,
    rehash_mode: String,
    claim_ceiling: String,
    required: bool,
    source_tree_member: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
enum FileFamily {
    Toml,
    Json,
    Utf8Text,
    OpaqueBinary,
    GzipTar,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ObservationKind {
    LocalFile,
    CheckedInArchive,
    CheckedInArchiveMember,
    InlineBytes,
    RemoteContentAddress,
    LocalCacheObservation,
    DerivedReceipt,
    FinalAttestation,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceFamilyContract {
    id: String,
    owner_bead: String,
    file_count: usize,
    total_bytes: u64,
    tree_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NegativeSourceContract {
    id: String,
    source_path: String,
    source_array: String,
    count: usize,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveContract {
    id: String,
    path: String,
    expected_root: String,
    member_count: usize,
    regular_file_count: usize,
    expanded_bytes: u64,
    member_tree_sha256: String,
    allowed_entry_types: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QuarantineContract {
    id: String,
    source_path: String,
    source_selector: String,
    expected_source_basename: Option<String>,
    expected_vector_id: Option<String>,
    expected_role: Option<String>,
    expected_accepted_vector: Option<bool>,
    expected_duplicate_of: Option<String>,
    expected_negative_mutation_count: Option<usize>,
    execution_allowed: bool,
    mutation_allowed: bool,
    promotion_allowed: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectionContract {
    id: String,
    disposition: String,
    evidence_verdict: String,
    support_claim: bool,
    dependency_count: usize,
    probe_sentinel: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DerivedOutputContract {
    id: String,
    path: String,
    kind: String,
    generation_rank: u32,
    producer_bead: String,
    pending_gate: String,
    required_parent_ids: Vec<String>,
    parent_purposes: Vec<String>,
    min_bytes: u64,
    max_bytes: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordSchemaContract {
    id: String,
    selectors: Vec<String>,
    exact_fields: Vec<String>,
    child_fields: Vec<String>,
    rule: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordVariantSchemaContract {
    id: String,
    parent_selector: String,
    discriminator_field: String,
    discriminator_value: String,
    required_fields: Vec<String>,
    optional_fields: Vec<String>,
    child_fields: Vec<String>,
    rule: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptSchemaContract {
    kind: String,
    receipt_id: String,
    table_name: String,
    exact_fields: Vec<String>,
    cardinality_rule: String,
    semantic_rule: String,
    typed_result_owner_rule: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandTemplateContract {
    template_id: String,
    group: String,
    expansion_count: usize,
    id_formula: String,
    coordinate_domain: String,
    executor: String,
    argv_source: String,
    argv_template: Vec<String>,
    environment_profile: String,
    working_directory: String,
    target_scope: String,
    execution_mode: String,
    profile: String,
    resolver: String,
    network_mode: String,
    exit_expectation: String,
    stdout_limit: u64,
    stderr_limit: u64,
    typed_parser: String,
    claim_ceiling: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentProfileContract {
    id: String,
    required: Vec<Vec<String>>,
    optional: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetToolProfileContract {
    target: String,
    cc_tool_id: String,
    ar_tool_id: String,
    linker_tool_id: String,
    cc_env_key: String,
    ar_env_key: String,
    cflags_env_key: String,
    linker_env_key: String,
    rustflags_env_key: String,
    cflags_exact: String,
    rustflags_exact: String,
    linker_flavor: String,
    linker_args_exact: Vec<String>,
    input_root_id: String,
    sdk_binding: String,
    rustlib_binding: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticAssertion {
    id: String,
    family: String,
    source_path: String,
    selector: String,
    secondary_selector: Option<String>,
    rule: String,
    logical_path: String,
    baseline_mode: String,
    observation_mode: AssertionObservationMode,
    baseline_observation_sha256: String,
    violation_mode: AssertionViolationMode,
    violating_observation_sha256: String,
    expected_trigger_count: usize,
    allowed_cotrigger_ids: Vec<String>,
    suppressed_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum AssertionObservationMode {
    CanonicalSelectedToml,
    CanonicalSelectedJson,
    RawSourceBytes,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum AssertionViolationMode {
    ExactObservationSha256,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct NegativeCase {
    family: String,
    id: String,
    source_index: usize,
    target_path: String,
    target_selector: String,
    operation: MutationKind,
    argument: Option<String>,
    secondary_selector: Option<String>,
    integrity_mode: String,
    validator: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationFixture {
    id: String,
    application: FixtureApplication,
    value_kind: FixtureValueKind,
    value: toml::Value,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum FixtureApplication {
    ReplaceValue,
    RemoveExactValue,
    InsertArrayElement,
    InsertTableMember,
    ReplaceTableMember,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum FixtureValueKind {
    String,
    StringArray,
    Table,
    TableArray,
    TableMember,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum MutationKind {
    Remove,
    Insert,
    Replace,
    Swap,
    Duplicate,
    ToggleBool,
    Increment,
    AppendFeature,
    RenameKey,
    ReplaceBytes,
}

#[derive(Debug, Clone)]
struct LoadedFile {
    contract: SourceFileContract,
    bytes: Vec<u8>,
    digest: [u8; 32],
}

/// The checked, immutable 66-file mutation baseline.
///
/// Mutation execution receives only shared access to this value.  A case can
/// therefore alter neither another case nor the checked source bytes.
#[derive(Debug)]
struct Corpus66<'a> {
    files: &'a [LoadedFile],
    by_path: BTreeMap<String, usize>,
    toml_documents: BTreeMap<String, toml::Value>,
    json_documents: BTreeMap<String, StrictJson>,
}

/// The sole per-case virtual substitution.  It owns one replacement byte
/// vector and, when applicable, its strictly parsed structured view.
#[derive(Debug)]
struct Overlay<'a> {
    target_path: &'a str,
    bytes: Vec<u8>,
    toml_document: Option<toml::Value>,
    json_document: Option<StrictJson>,
    file_binding: VirtualBinding,
    family_binding: VirtualBinding,
    tree_binding: VirtualBinding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VirtualBinding {
    byte_length: u64,
    sha256: [u8; 32],
}

#[derive(Debug, Clone)]
struct NegativeSpec {
    family: &'static str,
    id: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NegativeDiagnostic {
    family: String,
    id: String,
    rule: String,
    logical_path: String,
}

impl NegativeDiagnostic {
    fn stable(&self) -> String {
        format!(
            "FND01_NEG|{}|{}|{}|{}",
            self.family, self.id, self.rule, self.logical_path
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MutationFinding {
    assertion_id: String,
    rule: String,
    logical_path: String,
    diagnostic: String,
    observation_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FindingResolution {
    emitted: Vec<MutationFinding>,
    suppressed: Vec<MutationFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReceiptParentBinding {
    id: String,
    path: String,
    kind: String,
    byte_length: u64,
    sha256: String,
    purpose: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReceiptOutputBinding {
    id: String,
    path: String,
    kind: String,
    byte_length: u64,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IntegrationEdge {
    child_id: String,
    parent_id: String,
    purpose: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IntegrationRank {
    id: String,
    generation_rank: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StreamRegionBinding {
    offset: u64,
    byte_length: u64,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommandStreamBinding {
    id: String,
    stdout: StreamRegionBinding,
    stderr: StreamRegionBinding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LockStreamBinding {
    id: String,
    region: StreamRegionBinding,
    package_set_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedCommandResult {
    id: String,
    actual_worker_id: String,
    argv: Vec<String>,
    environment: Vec<(String, String)>,
    working_directory: String,
    target_scope: String,
    stdout: StreamRegionBinding,
    stderr: StreamRegionBinding,
    typed_result_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExternalRootObservation {
    path: String,
    tree_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProducerEnvironmentSummary {
    worker_id: String,
    repository_root: String,
    tools: BTreeMap<String, String>,
    proxies: Vec<(String, String)>,
    target_tool_paths: BTreeMap<String, (String, String, String)>,
    external_roots: BTreeMap<String, ExternalRootObservation>,
    run_root: String,
    acquisition_cargo_home: String,
    offline_cargo_home: String,
    acquisition_target_root: String,
    execution_bin: String,
    local_registry: String,
    return_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedPostcommandLock {
    id: String,
    producer_command_id: String,
    region: StreamRegionBinding,
    package_set_sha256: String,
}

#[derive(Debug)]
struct ParsedReceipt {
    receipt_id: String,
    run_id: String,
    parents: Vec<ReceiptParentBinding>,
    sidecar_output: Option<ReceiptOutputBinding>,
    sidecar_parents: Vec<ReceiptParentBinding>,
    actual_worker_id: Option<String>,
    producer_environment: Option<ProducerEnvironmentSummary>,
    control_frame: Option<CommandStreamBinding>,
    bootstrap_control: Option<CommandStreamBinding>,
    command_ids: Vec<String>,
    command_results: Vec<ParsedCommandResult>,
    postcommand_locks: Vec<ParsedPostcommandLock>,
    postcommand_package_set_sha256: Option<String>,
    integration_members: Vec<ReceiptOutputBinding>,
    integration_edges: Vec<IntegrationEdge>,
    integration_ranks: Vec<IntegrationRank>,
}

fn stream_region_from_record(
    table: &toml::map::Map<String, toml::Value>,
    prefix: &str,
    subject: &str,
) -> VResult<StreamRegionBinding> {
    let offset_field = format!("{prefix}_offset");
    let length_field = format!("{prefix}_byte_length");
    let sha256_field = format!("{prefix}_sha256");
    let region = StreamRegionBinding {
        offset: record_u64(table, &offset_field, subject)?,
        byte_length: record_u64(table, &length_field, subject)?,
        sha256: record_string(table, &sha256_field, subject)?.to_owned(),
    };
    if region
        .offset
        .checked_add(region.byte_length)
        .is_none()
    {
        return Err(Diagnostic::error("E_COMMAND_STREAM_BINDING", subject).at(prefix));
    }
    validate_sha256(&region.sha256, subject)?;
    Ok(region)
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
enum StrictJson {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrictJsonVisitor;

        impl<'de> Visitor<'de> for StrictJsonVisitor {
            type Value = StrictJson;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON value without duplicate object members")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictJson::Bool(value))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
                Ok(StrictJson::Number(value.into()))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
                Ok(StrictJson::Number(value.into()))
            }

            fn visit_i128<E>(self, value: i128) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                serde_json::Number::from_i128(value)
                    .map(StrictJson::Number)
                    .ok_or_else(|| E::custom("JSON integer is outside the configured number domain"))
            }

            fn visit_u128<E>(self, value: u128) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                serde_json::Number::from_u128(value)
                    .map(StrictJson::Number)
                    .ok_or_else(|| E::custom("JSON integer is outside the configured number domain"))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                serde_json::Number::from_f64(value)
                    .map(StrictJson::Number)
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                Ok(StrictJson::String(value.to_owned()))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(StrictJson::String(value))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(StrictJson::Null)
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(StrictJson::Null)
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element()? {
                    values.push(value);
                }
                Ok(StrictJson::Array(values))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = BTreeMap::new();
                let Some(first_key) = map.next_key::<String>()? else {
                    return Ok(StrictJson::Object(values));
                };
                if first_key == "$serde_json::private::Number" {
                    let raw = map.next_value::<String>()?;
                    if map.next_key::<String>()?.is_some() {
                        return Err(A::Error::custom(
                            "arbitrary-precision JSON number carried extra members",
                        ));
                    }
                    let number = serde_json::from_str::<serde_json::Number>(&raw)
                        .map_err(A::Error::custom)?;
                    return Ok(StrictJson::Number(number));
                }
                let first_value = map.next_value::<StrictJson>()?;
                values.insert(first_key, first_value);
                while let Some((key, value)) = map.next_entry::<String, StrictJson>()? {
                    if values.insert(key.clone(), value).is_some() {
                        return Err(A::Error::custom(format!(
                            "duplicate JSON object member {key:?}"
                        )));
                    }
                }
                Ok(StrictJson::Object(values))
            }
        }

        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("facade crate must be two levels below the repository root")
        .to_path_buf()
}

fn validate_repository_root_layout(root: &Path) -> VResult<()> {
    let manifest_directory = Path::new(env!("CARGO_MANIFEST_DIR"));
    if !manifest_directory.is_absolute()
        || manifest_directory.file_name().and_then(|name| name.to_str()) != Some("fastmcp")
        || manifest_directory
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            != Some("crates")
        || root.join("crates/fastmcp") != manifest_directory
    {
        return Err(Diagnostic::error(
            "E_REPOSITORY_ROOT",
            "compile-time CARGO_MANIFEST_DIR",
        ));
    }
    Ok(())
}

fn parse_toml_strict<T: DeserializeOwned>(bytes: &[u8], subject: &str) -> VResult<T> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        Diagnostic::error("E_UTF8", subject).at("complete TOML document must be UTF-8")
    })?;
    toml::from_str(text)
        .map_err(|_| Diagnostic::error("E_TOML_SCHEMA", subject).at("strict typed parse"))
}

fn validate_ascii_posix_path(path: &str, subject: &str) -> VResult<()> {
    if path.is_empty()
        || path.len() > 240
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\\')
        || !path.is_ascii()
        || path.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(Diagnostic::error("E_PATH_INVALID", subject).at(path));
    }
    let mut depth = 0usize;
    for component in path.split('/') {
        depth = depth
            .checked_add(1)
            .ok_or_else(|| Diagnostic::error("E_PATH_INVALID", subject).at(path))?;
        if component.is_empty()
            || component.len() > 100
            || component == "."
            || component == ".."
            || component.contains(':')
        {
            return Err(Diagnostic::error("E_PATH_INVALID", subject).at(path));
        }
    }
    if depth > 8 {
        return Err(Diagnostic::error("E_PATH_INVALID", subject).at(path));
    }
    Ok(())
}

fn resolve_safe(root: &Path, relative: &str, subject: &str) -> VResult<PathBuf> {
    validate_ascii_posix_path(relative, subject)?;
    let root_metadata = fs::symlink_metadata(root)
        .map_err(|_| Diagnostic::error("E_REPOSITORY_ROOT", subject).at("metadata"))?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(Diagnostic::error("E_REPOSITORY_ROOT", subject)
            .at("regular directory boundary required"));
    }
    let mut current = root.to_path_buf();
    for component in relative.split('/') {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(Diagnostic::error("E_PATH_SYMLINK", subject).at(relative));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(Diagnostic::error("E_PATH_METADATA", subject).at(relative));
            }
        }
    }
    Ok(current)
}

fn read_bounded(path: &Path, limit: u64, subject: &str) -> VResult<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| Diagnostic::error("E_FILE_MISSING", subject).at("metadata"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Diagnostic::error("E_FILE_TYPE", subject).at("regular file required"));
    }
    #[cfg(unix)]
    if metadata.nlink() != 1 {
        return Err(Diagnostic::error("E_FILE_HARDLINK", subject)
            .at(format!("link_count={}", metadata.nlink())));
    }
    #[cfg(windows)]
    if metadata.number_of_links() != 1 {
        return Err(Diagnostic::error("E_FILE_HARDLINK", subject)
            .at(format!("link_count={}", metadata.number_of_links())));
    }
    if metadata.len() > limit {
        return Err(Diagnostic::error("E_FILE_BOUND", subject).at(metadata.len().to_string()));
    }
    let file =
        File::open(path).map_err(|_| Diagnostic::error("E_FILE_READ", subject).at("open"))?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| Diagnostic::error("E_FILE_READ", subject).at("bounded read"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(Diagnostic::error("E_FILE_BOUND", subject).at("stream exceeded bound"));
    }
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != metadata.len() {
        return Err(Diagnostic::error("E_FILE_RACE", subject).at("length changed while reading"));
    }
    Ok(bytes)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn validate_sha256(value: &str, subject: &str) -> VResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Diagnostic::error("E_SHA256_FORMAT", subject).at(value));
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyShapeBootstrap {
    schema_id: String,
    schema_version: u32,
    root_scalar_names: Vec<String>,
    root_scalar_type_row_count: usize,
    root_scalar_type_rows: Vec<String>,
    root_table_names: Vec<String>,
    root_array_table_names: Vec<String>,
    shape_row_count: usize,
    shape_row_encoding: String,
    shape_rows_a: Vec<String>,
    shape_rows_b: Vec<String>,
    shape_rows_c: Vec<String>,
    fixture_inline_value_rule: String,
    nested_collection_rule: String,
    conditional_variant_row_count: usize,
    conditional_variant_rows: Vec<String>,
    child_structure_rule: String,
    direct_value_type_rule: String,
    registry_bytes: usize,
    registry_sha256: String,
    verifier_authority_rule: String,
    validation_order: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyShapeKind {
    Root,
    Table,
    ArrayTableRow,
    TypedInlineException,
}

#[derive(Debug, Clone)]
struct PolicyShapeRule {
    kind: PolicyShapeKind,
    required: BTreeSet<String>,
    optional: BTreeSet<String>,
}

fn append_registry_count(
    output: &mut Vec<u8>,
    count: usize,
    subject: &str,
) -> VResult<()> {
    let count = u32::try_from(count)
        .map_err(|_| Diagnostic::error("E_POLICY_SHAPE_BOUND", subject).at("count"))?;
    output.extend_from_slice(&count.to_be_bytes());
    Ok(())
}

fn append_registry_row(output: &mut Vec<u8>, row: &str, subject: &str) -> VResult<()> {
    let length = u32::try_from(row.len())
        .map_err(|_| Diagnostic::error("E_POLICY_SHAPE_BOUND", subject).at("row length"))?;
    let next_length = output
        .len()
        .checked_add(4)
        .and_then(|length| length.checked_add(row.len()))
        .ok_or_else(|| Diagnostic::error("E_POLICY_SHAPE_BOUND", subject).at("registry length"))?;
    if next_length > MAX_POLICY_SHAPE_REGISTRY_BYTES {
        return Err(
            Diagnostic::error("E_POLICY_SHAPE_BOUND", subject).at("registry byte cap")
        );
    }
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(row.as_bytes());
    Ok(())
}

fn registry_sort_key<'a>(row: &'a str, delimiter: char, subject: &str) -> VResult<&'a str> {
    let key = row
        .split_once(delimiter)
        .map(|(key, _)| key)
        .ok_or_else(|| Diagnostic::error("E_POLICY_SHAPE_ROW", subject).at(row))?;
    if key.is_empty() {
        return Err(Diagnostic::error("E_POLICY_SHAPE_ROW", subject).at("empty sort key"));
    }
    Ok(key)
}

fn sort_registry_rows(
    rows: &mut [String],
    delimiter: char,
    subject: &str,
) -> VResult<()> {
    for row in rows.iter() {
        registry_sort_key(row, delimiter, subject)?;
    }
    rows.sort_by(|left, right| {
        let left_key = left.split_once(delimiter).map_or("", |(key, _)| key);
        let right_key = right.split_once(delimiter).map_or("", |(key, _)| key);
        left_key.as_bytes().cmp(right_key.as_bytes())
    });
    if rows.windows(2).any(|pair| {
        let left = pair[0].split_once(delimiter).map_or("", |(key, _)| key);
        let right = pair[1].split_once(delimiter).map_or("", |(key, _)| key);
        left == right
    }) {
        return Err(Diagnostic::error(
            "E_POLICY_SHAPE_DUPLICATE",
            subject,
        ));
    }
    Ok(())
}

fn encode_policy_shape_registry(shape: &PolicyShapeBootstrap) -> VResult<Vec<u8>> {
    let mut shape_rows = shape
        .shape_rows_a
        .iter()
        .chain(&shape.shape_rows_b)
        .chain(&shape.shape_rows_c)
        .cloned()
        .collect::<Vec<_>>();
    let mut scalar_rows = shape.root_scalar_type_rows.clone();
    let mut variant_rows = shape.conditional_variant_rows.clone();
    if shape_rows.len() != POLICY_SHAPE_ROW_COUNT
        || scalar_rows.len() != POLICY_ROOT_SCALAR_TYPE_ROW_COUNT
        || variant_rows.len() != POLICY_CONDITIONAL_VARIANT_ROW_COUNT
    {
        return Err(Diagnostic::error(
            "E_POLICY_SHAPE_COUNT",
            "policy shape registry",
        ));
    }
    sort_registry_rows(&mut shape_rows, '|', "policy shape rows")?;
    sort_registry_rows(&mut scalar_rows, '|', "policy scalar type rows")?;
    sort_registry_rows(&mut variant_rows, '@', "policy conditional variant rows")?;

    let mut encoded = Vec::with_capacity(POLICY_SHAPE_REGISTRY_BYTES);
    encoded.extend_from_slice(b"FND01POLICYSHAPEv2\0");
    append_registry_count(&mut encoded, shape_rows.len(), "policy shape rows")?;
    for row in &shape_rows {
        append_registry_row(&mut encoded, row, "policy shape rows")?;
    }
    append_registry_count(&mut encoded, scalar_rows.len(), "policy scalar type rows")?;
    for row in &scalar_rows {
        append_registry_row(&mut encoded, row, "policy scalar type rows")?;
    }
    append_registry_count(
        &mut encoded,
        variant_rows.len(),
        "policy conditional variant rows",
    )?;
    for row in &variant_rows {
        append_registry_row(&mut encoded, row, "policy conditional variant rows")?;
    }
    Ok(encoded)
}

fn parse_shape_fields(
    encoded: &str,
    allow_empty: bool,
    subject: &str,
) -> VResult<BTreeSet<String>> {
    if encoded.is_empty() {
        return allow_empty
            .then(BTreeSet::new)
            .ok_or_else(|| Diagnostic::error("E_POLICY_SHAPE_ROW", subject).at("empty fields"));
    }
    let mut fields = BTreeSet::new();
    for field in encoded.split(',') {
        if field.is_empty()
            || field.contains('|')
            || !fields.insert(field.to_owned())
        {
            return Err(Diagnostic::error("E_POLICY_SHAPE_ROW", subject).at(field));
        }
    }
    Ok(fields)
}

fn parse_policy_shape_rules(
    shape: &PolicyShapeBootstrap,
) -> VResult<BTreeMap<String, PolicyShapeRule>> {
    let mut rules = BTreeMap::new();
    for row in shape
        .shape_rows_a
        .iter()
        .chain(&shape.shape_rows_b)
        .chain(&shape.shape_rows_c)
    {
        let columns = row.split('|').collect::<Vec<_>>();
        if columns.len() != 4 {
            return Err(Diagnostic::error("E_POLICY_SHAPE_ROW", "shape row").at(row));
        }
        let path = columns[0];
        let kind = match columns[1] {
            "root" => PolicyShapeKind::Root,
            "table" => PolicyShapeKind::Table,
            "array-table-row" => PolicyShapeKind::ArrayTableRow,
            "typed-inline-exception" => PolicyShapeKind::TypedInlineException,
            _ => {
                return Err(
                    Diagnostic::error("E_POLICY_SHAPE_ROW", path).at("unknown node kind")
                );
            }
        };
        let required = parse_shape_fields(
            columns[2],
            kind == PolicyShapeKind::TypedInlineException,
            path,
        )?;
        let optional = parse_shape_fields(columns[3], true, path)?;
        if !required.is_disjoint(&optional) {
            return Err(
                Diagnostic::error("E_POLICY_SHAPE_ROW", path).at("required/optional overlap")
            );
        }
        if rules
            .insert(
                path.to_owned(),
                PolicyShapeRule {
                    kind,
                    required,
                    optional,
                },
            )
            .is_some()
        {
            return Err(Diagnostic::error("E_POLICY_SHAPE_DUPLICATE", path));
        }
    }
    if rules.len() != POLICY_SHAPE_ROW_COUNT {
        return Err(Diagnostic::error(
            "E_POLICY_SHAPE_COUNT",
            "parsed policy shape rows",
        ));
    }
    Ok(rules)
}

fn validate_table_against_shape(
    table: &toml::map::Map<String, toml::Value>,
    rule: &PolicyShapeRule,
    subject: &str,
) -> VResult<()> {
    let actual = table.keys().cloned().collect::<BTreeSet<_>>();
    if !rule.required.is_subset(&actual)
        || actual
            .iter()
            .any(|field| !rule.required.contains(field) && !rule.optional.contains(field))
    {
        return Err(Diagnostic::error("E_POLICY_SHAPE_FIELDS", subject).at(format!(
            "required={:?};optional={:?};actual={actual:?}",
            rule.required, rule.optional
        )));
    }
    Ok(())
}

fn table_string<'a>(
    table: &'a toml::map::Map<String, toml::Value>,
    field: &str,
    subject: &str,
) -> VResult<&'a str> {
    table
        .get(field)
        .and_then(toml::Value::as_str)
        .ok_or_else(|| Diagnostic::error("E_POLICY_SHAPE_TYPE", subject).at(field))
}

fn validate_policy_shape_variants(
    root: &toml::map::Map<String, toml::Value>,
) -> VResult<()> {
    let negative_rows = root
        .get("negative_case")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| Diagnostic::error("E_POLICY_SHAPE_TYPE", "negative_case"))?;
    let mut operation_by_id = BTreeMap::new();
    let mut secondary_by_id = BTreeMap::new();
    for value in negative_rows {
        let row = value
            .as_table()
            .ok_or_else(|| Diagnostic::error("E_POLICY_SHAPE_TYPE", "negative_case[]"))?;
        let id = table_string(row, "id", "negative_case[]")?;
        let operation = table_string(row, "operation", id)?;
        let has_argument = row.contains_key("argument");
        let has_secondary = row.contains_key("secondary_selector");
        let valid = match operation {
            "swap" => !has_argument && has_secondary,
            "remove" => !has_secondary,
            "duplicate" => !has_argument && !has_secondary,
            _ => has_argument && !has_secondary,
        };
        if !valid
            || operation_by_id
                .insert(id.to_owned(), operation.to_owned())
                .is_some()
        {
            return Err(Diagnostic::error("E_POLICY_SHAPE_VARIANT", id));
        }
        secondary_by_id.insert(
            id.to_owned(),
            row.get("secondary_selector")
                .and_then(toml::Value::as_str)
                .map(str::to_owned),
        );
    }

    let quarantine_rows = root
        .get("quarantine")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| Diagnostic::error("E_POLICY_SHAPE_TYPE", "quarantine"))?;
    let quarantine_variant_fields = [
        "expected_source_basename",
        "expected_vector_id",
        "expected_role",
        "expected_accepted_vector",
        "expected_duplicate_of",
        "expected_negative_mutation_count",
    ];
    for value in quarantine_rows {
        let row = value
            .as_table()
            .ok_or_else(|| Diagnostic::error("E_POLICY_SHAPE_TYPE", "quarantine[]"))?;
        let id = table_string(row, "id", "quarantine[]")?;
        let is_jose = id == "jose-rfc8017-sha256-duplicate";
        if quarantine_variant_fields
            .iter()
            .any(|field| row.contains_key(*field) != is_jose)
        {
            return Err(Diagnostic::error("E_POLICY_SHAPE_VARIANT", id));
        }
    }

    let receipt_rows = root
        .get("receipt_schema")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| Diagnostic::error("E_POLICY_SHAPE_TYPE", "receipt_schema"))?;
    for value in receipt_rows {
        let row = value
            .as_table()
            .ok_or_else(|| Diagnostic::error("E_POLICY_SHAPE_TYPE", "receipt_schema[]"))?;
        let kind = table_string(row, "kind", "receipt_schema[]")?;
        if row.contains_key("typed_result_owner_rule") != (kind == "command_results") {
            return Err(Diagnostic::error("E_POLICY_SHAPE_VARIANT", kind));
        }
    }

    let assertion_rows = root
        .get("semantic_assertion")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| Diagnostic::error("E_POLICY_SHAPE_TYPE", "semantic_assertion"))?;
    for value in assertion_rows {
        let row = value
            .as_table()
            .ok_or_else(|| Diagnostic::error("E_POLICY_SHAPE_TYPE", "semantic_assertion[]"))?;
        let id = table_string(row, "id", "semantic_assertion[]")?;
        let operation = operation_by_id
            .get(id)
            .ok_or_else(|| Diagnostic::error("E_POLICY_SHAPE_VARIANT", id))?;
        let assertion_secondary = row
            .get("secondary_selector")
            .and_then(toml::Value::as_str);
        let recipe_secondary = secondary_by_id.get(id).and_then(Option::as_deref);
        if (operation == "swap" && assertion_secondary != recipe_secondary)
            || (operation != "swap" && assertion_secondary.is_some())
        {
            return Err(Diagnostic::error("E_POLICY_SHAPE_VARIANT", id));
        }
    }
    Ok(())
}

fn validate_raw_fixture_value(
    value: &toml::Value,
    depth: usize,
    nodes: &mut usize,
    total_bytes: &mut usize,
    subject: &str,
) -> VResult<()> {
    if depth > 8 {
        return Err(Diagnostic::error("E_FIXTURE_BOUND", subject).at("raw depth"));
    }
    *nodes = nodes
        .checked_add(1)
        .ok_or_else(|| Diagnostic::error("E_FIXTURE_BOUND", subject).at("raw node overflow"))?;
    if *nodes > 64 {
        return Err(Diagnostic::error("E_FIXTURE_BOUND", subject).at("raw nodes"));
    }
    let add_bytes = |total: &mut usize, additional: usize| -> VResult<()> {
        *total = total.checked_add(additional).ok_or_else(|| {
            Diagnostic::error("E_FIXTURE_BOUND", subject).at("raw byte overflow")
        })?;
        if *total > 16_384 {
            return Err(Diagnostic::error("E_FIXTURE_BOUND", subject).at("raw bytes"));
        }
        Ok(())
    };
    match value {
        toml::Value::String(value) => add_bytes(total_bytes, value.len())?,
        toml::Value::Integer(_) | toml::Value::Float(_) => add_bytes(total_bytes, 8)?,
        toml::Value::Boolean(_) => add_bytes(total_bytes, 1)?,
        toml::Value::Datetime(value) => add_bytes(total_bytes, value.to_string().len())?,
        toml::Value::Array(values) => {
            for value in values {
                validate_raw_fixture_value(value, depth + 1, nodes, total_bytes, subject)?;
            }
        }
        toml::Value::Table(table) => {
            for (key, value) in table {
                if key.is_empty()
                    || key.len() > 128
                    || !key.is_ascii()
                    || key.bytes().any(|byte| byte.is_ascii_control())
                {
                    return Err(
                        Diagnostic::error("E_FIXTURE_SCHEMA", subject).at("raw table key")
                    );
                }
                add_bytes(total_bytes, key.len())?;
                validate_raw_fixture_value(value, depth + 1, nodes, total_bytes, subject)?;
            }
        }
    }
    Ok(())
}

fn validate_raw_fixture_values(root: &toml::map::Map<String, toml::Value>) -> VResult<()> {
    let fixtures = root
        .get("mutation_fixture")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| Diagnostic::error("E_POLICY_SHAPE_TYPE", "mutation_fixture"))?;
    for row in fixtures {
        let table = row
            .as_table()
            .ok_or_else(|| Diagnostic::error("E_POLICY_SHAPE_TYPE", "mutation_fixture[]"))?;
        let id = table_string(table, "id", "mutation_fixture[]")?;
        let value = table
            .get("value")
            .ok_or_else(|| Diagnostic::error("E_POLICY_SHAPE_FIELDS", id).at("value"))?;
        let mut nodes = 0usize;
        let mut total_bytes = 0usize;
        validate_raw_fixture_value(value, 0, &mut nodes, &mut total_bytes, id)?;
    }
    Ok(())
}

fn policy_value_signature(value: &toml::Value) -> String {
    match value {
        toml::Value::String(_) => "string".to_owned(),
        toml::Value::Integer(value) if *value >= 0 => "nonnegative-integer".to_owned(),
        toml::Value::Integer(_) => "negative-integer".to_owned(),
        toml::Value::Float(_) => "float".to_owned(),
        toml::Value::Boolean(_) => "bool".to_owned(),
        toml::Value::Datetime(_) => "datetime".to_owned(),
        toml::Value::Table(_) => "table".to_owned(),
        toml::Value::Array(values) => {
            if values.is_empty() {
                return "array<empty>".to_owned();
            }
            let element_types = values
                .iter()
                .map(policy_value_signature)
                .collect::<BTreeSet<_>>();
            if element_types.len() == 1 {
                format!(
                    "array<{}>",
                    element_types
                        .first()
                        .expect("one array element type must exist")
                )
            } else {
                format!(
                    "array<mixed:{}>",
                    element_types.into_iter().collect::<Vec<_>>().join(",")
                )
            }
        }
    }
}

fn merge_policy_field_signatures(values: &[&toml::Value]) -> String {
    if values.is_empty() {
        return "absent".to_owned();
    }
    let mut signatures = values
        .iter()
        .map(|value| policy_value_signature(value))
        .collect::<BTreeSet<_>>();
    if signatures.len() > 1 {
        let nonempty_arrays = signatures
            .iter()
            .filter(|signature| signature.as_str() != "array<empty>")
            .cloned()
            .collect::<BTreeSet<_>>();
        if signatures.contains("array<empty>") && nonempty_arrays.len() == 1 {
            return nonempty_arrays
                .first()
                .expect("one nonempty array signature must exist")
                .clone();
        }
    }
    if signatures.len() == 1 {
        return signatures
            .pop_first()
            .expect("one policy field signature must exist");
    }
    format!(
        "inconsistent:{}",
        signatures.into_iter().collect::<Vec<_>>().join(",")
    )
}

fn encode_policy_type_registry(
    root: &toml::map::Map<String, toml::Value>,
    rules: &BTreeMap<String, PolicyShapeRule>,
) -> VResult<Vec<u8>> {
    let mut rows = Vec::new();
    for (path, rule) in rules {
        if rule.kind == PolicyShapeKind::TypedInlineException {
            continue;
        }
        let fields = rule
            .required
            .iter()
            .chain(&rule.optional)
            .collect::<BTreeSet<_>>();
        match rule.kind {
            PolicyShapeKind::Root => {
                for field in fields {
                    let value = root.get(field).ok_or_else(|| {
                        Diagnostic::error("E_POLICY_SHAPE_FIELDS", path).at(field)
                    })?;
                    rows.push(format!("{path}|{field}|{}", policy_value_signature(value)));
                }
            }
            PolicyShapeKind::Table => {
                let table = root
                    .get(path)
                    .and_then(toml::Value::as_table)
                    .ok_or_else(|| Diagnostic::error("E_POLICY_SHAPE_TYPE", path))?;
                for field in fields {
                    let signature = table
                        .get(field)
                        .map_or_else(|| "absent".to_owned(), policy_value_signature);
                    rows.push(format!("{path}|{field}|{signature}"));
                }
            }
            PolicyShapeKind::ArrayTableRow => {
                let root_name = path.strip_suffix("[]").ok_or_else(|| {
                    Diagnostic::error("E_POLICY_SHAPE_ROW", path).at("array path suffix")
                })?;
                let values = root
                    .get(root_name)
                    .and_then(toml::Value::as_array)
                    .ok_or_else(|| Diagnostic::error("E_POLICY_SHAPE_TYPE", path))?;
                for field in fields {
                    let field_values = values
                        .iter()
                        .filter_map(|value| value.as_table().and_then(|table| table.get(field)))
                        .collect::<Vec<_>>();
                    let signature = if path == "mutation_fixture[]" && field == "value" {
                        "fixture-dynamic".to_owned()
                    } else {
                        merge_policy_field_signatures(&field_values)
                    };
                    rows.push(format!("{path}|{field}|{signature}"));
                }
            }
            PolicyShapeKind::TypedInlineException => unreachable!(),
        }
    }
    rows.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    if rows.len() != POLICY_TYPE_REGISTRY_ROW_COUNT {
        return Err(Diagnostic::error(
            "E_POLICY_TYPE_COUNT",
            "policy type registry",
        )
        .at(rows.len().to_string()));
    }
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"FND01POLICYTYPEv1\0");
    append_registry_count(&mut encoded, rows.len(), "policy type registry")?;
    for row in &rows {
        append_registry_row(&mut encoded, row, "policy type registry")?;
    }
    Ok(encoded)
}

fn validate_policy_type_registry(encoded: &[u8]) -> VResult<()> {
    if encoded.len() != POLICY_TYPE_REGISTRY_BYTES
        || encoded.len() > MAX_POLICY_SHAPE_REGISTRY_BYTES
        || lower_hex(&sha256(encoded)) != POLICY_TYPE_REGISTRY_SHA256
    {
        return Err(Diagnostic::error(
            "E_POLICY_TYPE_REGISTRY",
            "compiled direct policy value types",
        ));
    }
    Ok(())
}

fn append_registry_strings(
    output: &mut Vec<u8>,
    values: &[String],
    subject: &str,
) -> VResult<()> {
    append_registry_count(output, values.len(), subject)?;
    for value in values {
        append_registry_row(output, value, subject)?;
    }
    Ok(())
}

fn encode_record_schema_registry(rows: &[RecordSchemaContract]) -> VResult<Vec<u8>> {
    if rows.len() != RECORD_SCHEMA_REGISTRY_COUNT {
        return Err(Diagnostic::error(
            "E_RECORD_SCHEMA_COUNT",
            "record schema registry",
        ));
    }
    let mut rows = rows.iter().collect::<Vec<_>>();
    rows.sort_by(|left, right| left.id.as_bytes().cmp(right.id.as_bytes()));
    if rows.windows(2).any(|pair| pair[0].id == pair[1].id) {
        return Err(Diagnostic::error(
            "E_RECORD_SCHEMA_DUPLICATE",
            "record schema ID",
        ));
    }
    let mut encoded = Vec::with_capacity(RECORD_SCHEMA_REGISTRY_BYTES);
    encoded.extend_from_slice(b"FND01RECSCHEMAv2\0");
    append_registry_count(&mut encoded, rows.len(), "record schema registry")?;
    for row in rows {
        append_registry_row(&mut encoded, &row.id, "record schema ID")?;
        append_registry_strings(&mut encoded, &row.selectors, "record schema selectors")?;
        append_registry_strings(
            &mut encoded,
            &row.exact_fields,
            "record schema exact fields",
        )?;
        append_registry_strings(
            &mut encoded,
            &row.child_fields,
            "record schema child fields",
        )?;
        append_registry_row(&mut encoded, &row.rule, "record schema rule")?;
    }
    Ok(encoded)
}

fn encode_record_variant_registry(rows: &[RecordVariantSchemaContract]) -> VResult<Vec<u8>> {
    if rows.len() != RECORD_VARIANT_REGISTRY_COUNT {
        return Err(Diagnostic::error(
            "E_RECORD_VARIANT_COUNT",
            "record variant registry",
        ));
    }
    let mut rows = rows.iter().collect::<Vec<_>>();
    rows.sort_by(|left, right| left.id.as_bytes().cmp(right.id.as_bytes()));
    if rows.windows(2).any(|pair| pair[0].id == pair[1].id) {
        return Err(Diagnostic::error(
            "E_RECORD_VARIANT_DUPLICATE",
            "record variant ID",
        ));
    }
    let mut encoded = Vec::with_capacity(RECORD_VARIANT_REGISTRY_BYTES);
    encoded.extend_from_slice(b"FND01RECVARIANTv1\0");
    append_registry_count(&mut encoded, rows.len(), "record variant registry")?;
    for row in rows {
        for (value, subject) in [
            (&row.id, "record variant ID"),
            (&row.parent_selector, "record variant parent selector"),
            (&row.discriminator_field, "record variant discriminator field"),
            (&row.discriminator_value, "record variant discriminator value"),
        ] {
            append_registry_row(&mut encoded, value, subject)?;
        }
        append_registry_strings(
            &mut encoded,
            &row.required_fields,
            "record variant required fields",
        )?;
        append_registry_strings(
            &mut encoded,
            &row.optional_fields,
            "record variant optional fields",
        )?;
        append_registry_strings(
            &mut encoded,
            &row.child_fields,
            "record variant child fields",
        )?;
        append_registry_row(&mut encoded, &row.rule, "record variant rule")?;
    }
    Ok(encoded)
}

fn encode_receipt_schema_registry(rows: &[ReceiptSchemaContract]) -> VResult<Vec<u8>> {
    if rows.len() != RECEIPT_SCHEMA_REGISTRY_COUNT {
        return Err(Diagnostic::error(
            "E_RECEIPT_SCHEMA_COUNT",
            "receipt schema registry",
        ));
    }
    let mut rows = rows.iter().collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        left.receipt_id
            .as_bytes()
            .cmp(right.receipt_id.as_bytes())
    });
    if rows
        .windows(2)
        .any(|pair| pair[0].receipt_id == pair[1].receipt_id)
    {
        return Err(Diagnostic::error(
            "E_RECEIPT_SCHEMA_DUPLICATE",
            "receipt schema ID",
        ));
    }
    let mut encoded = Vec::with_capacity(RECEIPT_SCHEMA_REGISTRY_BYTES);
    encoded.extend_from_slice(b"FND01RECEIPTSCHEMAv1\0");
    append_registry_count(&mut encoded, rows.len(), "receipt schema registry")?;
    for row in rows {
        for (value, subject) in [
            (&row.kind, "receipt schema kind"),
            (&row.receipt_id, "receipt schema ID"),
            (&row.table_name, "receipt schema table"),
        ] {
            append_registry_row(&mut encoded, value, subject)?;
        }
        append_registry_strings(
            &mut encoded,
            &row.exact_fields,
            "receipt schema exact fields",
        )?;
        append_registry_row(
            &mut encoded,
            &row.cardinality_rule,
            "receipt schema cardinality rule",
        )?;
        append_registry_row(
            &mut encoded,
            &row.semantic_rule,
            "receipt schema semantic rule",
        )?;
        match &row.typed_result_owner_rule {
            None => encoded.push(0),
            Some(rule) => {
                encoded.push(1);
                append_registry_row(
                    &mut encoded,
                    rule,
                    "receipt schema typed-result owner rule",
                )?;
            }
        }
        if encoded.len() > MAX_POLICY_SHAPE_REGISTRY_BYTES {
            return Err(Diagnostic::error(
                "E_RECEIPT_SCHEMA_BOUND",
                "receipt schema registry",
            ));
        }
    }
    Ok(encoded)
}

fn validate_record_selector(selector: &str) -> VResult<()> {
    if selector.is_empty()
        || selector.len() > 512
        || !selector.is_ascii()
        || selector.starts_with('/')
        || selector.ends_with('/')
        || selector.bytes().any(|byte| byte.is_ascii_control())
        || selector
            .bytes()
            .any(|byte| matches!(byte, b'*' | b'?' | b'{' | b'}' | b'\\' | b'|' | b'@'))
    {
        return Err(Diagnostic::error("E_RECORD_SELECTOR", selector));
    }
    let mut depth = 0usize;
    for component in selector.split('/') {
        depth = depth
            .checked_add(1)
            .ok_or_else(|| Diagnostic::error("E_RECORD_SELECTOR", selector))?;
        let component = component.strip_suffix("[]").unwrap_or(component);
        if component.is_empty()
            || component.contains('[')
            || component.contains(']')
            || !component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(Diagnostic::error("E_RECORD_SELECTOR", selector));
        }
    }
    if depth > 32 {
        return Err(Diagnostic::error("E_RECORD_SELECTOR", selector).at("depth"));
    }
    Ok(())
}

fn validate_record_schema_acyclic(
    node: &str,
    graph: &BTreeMap<&str, BTreeSet<&str>>,
    temporary: &mut BTreeSet<String>,
    permanent: &mut BTreeSet<String>,
) -> VResult<()> {
    if permanent.contains(node) {
        return Ok(());
    }
    if !temporary.insert(node.to_owned()) {
        return Err(Diagnostic::error("E_RECORD_SCHEMA_CYCLE", node));
    }
    if let Some(children) = graph.get(node) {
        for child in children {
            validate_record_schema_acyclic(child, graph, temporary, permanent)?;
        }
    }
    temporary.remove(node);
    permanent.insert(node.to_owned());
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectFieldType {
    String,
    Unsigned,
    Signed,
    Boolean,
    RawBytes,
    StringArray,
    EnvironmentPairs,
    Record,
    RecordArray,
    VariantArray,
    OptionalString,
    OptionalUnsigned,
    OptionalBoolean,
}

impl DirectFieldType {
    fn from_code(code: u8, subject: &str) -> VResult<Self> {
        match code {
            b's' => Ok(Self::String),
            b'u' => Ok(Self::Unsigned),
            b'i' => Ok(Self::Signed),
            b'b' => Ok(Self::Boolean),
            b'x' => Ok(Self::RawBytes),
            b'a' => Ok(Self::StringArray),
            b'e' => Ok(Self::EnvironmentPairs),
            b'r' => Ok(Self::Record),
            b'q' => Ok(Self::RecordArray),
            b'v' => Ok(Self::VariantArray),
            b'S' => Ok(Self::OptionalString),
            b'U' => Ok(Self::OptionalUnsigned),
            b'B' => Ok(Self::OptionalBoolean),
            _ => Err(Diagnostic::error("E_RECORD_TYPE_REGISTRY", subject)
                .at(format!("unknown type code {code:#04x}"))),
        }
    }

    fn code(self) -> &'static str {
        match self {
            Self::String => "s",
            Self::Unsigned => "u",
            Self::Signed => "i",
            Self::Boolean => "b",
            Self::RawBytes => "x",
            Self::StringArray => "a",
            Self::EnvironmentPairs => "e",
            Self::Record => "r",
            Self::RecordArray => "q",
            Self::VariantArray => "v",
            Self::OptionalString => "S",
            Self::OptionalUnsigned => "U",
            Self::OptionalBoolean => "B",
        }
    }

    fn child_mapping_suffix(self) -> Option<&'static str> {
        match self {
            Self::Record => Some(""),
            Self::RecordArray => Some("[]"),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectFieldTypeSpec {
    root: String,
    ordinal: usize,
    field: String,
    code: &'static str,
    target: String,
}

fn encode_record_string(output: &mut Vec<u8>, value: &str, subject: &str) -> VResult<()> {
    output.push(0x01);
    append_registry_row(output, value, subject)
}

fn encode_record_array_header(
    output: &mut Vec<u8>,
    tag: u8,
    count: usize,
    subject: &str,
) -> VResult<()> {
    output.push(tag);
    append_registry_count(output, count, subject)
}

fn record_schema_for_id<'a>(
    policy: &'a Policy,
    schema_id: &str,
    subject: &str,
) -> VResult<&'a RecordSchemaContract> {
    let mut matching = policy
        .record_schema
        .iter()
        .filter(|schema| schema.id == schema_id);
    let schema = matching
        .next()
        .ok_or_else(|| Diagnostic::error("E_RECORD_SCHEMA", subject).at(schema_id))?;
    if matching.next().is_some() {
        return Err(Diagnostic::error("E_RECORD_SCHEMA", subject)
            .at(format!("duplicate schema {schema_id}")));
    }
    Ok(schema)
}

fn encode_schema_record(
    output: &mut Vec<u8>,
    table: &toml::map::Map<String, toml::Value>,
    schema_id: &str,
    policy: &Policy,
    subject: &str,
) -> VResult<()> {
    let schema = record_schema_for_id(policy, schema_id, subject)?;
    let mask = compiled_type_mask(RECORD_SCHEMA_TYPE_MASKS, schema_id, subject)?;
    if mask.len() != schema.exact_fields.len() {
        return Err(Diagnostic::error("E_RECORD_TYPE_REGISTRY", subject).at(schema_id));
    }
    output.push(0x06);
    append_registry_row(output, schema_id, subject)?;
    for (field, code) in schema.exact_fields.iter().zip(mask.bytes()) {
        let direct_type = DirectFieldType::from_code(code, subject)?;
        let target = child_type_target(
            &schema.child_fields,
            field,
            direct_type,
            schema_id,
        )?;
        let value = table
            .get(field)
            .ok_or_else(|| Diagnostic::error("E_RECORD_FIELD", subject).at(field))?;
        encode_direct_record_value(
            output,
            value,
            direct_type,
            &target,
            policy,
            subject,
        )?;
    }
    Ok(())
}

fn encode_direct_record_value(
    output: &mut Vec<u8>,
    value: &toml::Value,
    direct_type: DirectFieldType,
    target: &str,
    policy: &Policy,
    subject: &str,
) -> VResult<()> {
    match direct_type {
        DirectFieldType::String => {
            let value = value
                .as_str()
                .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", subject))?;
            encode_record_string(output, value, subject)
        }
        DirectFieldType::Unsigned => {
            let value = value
                .as_integer()
                .filter(|value| *value >= 0)
                .and_then(|value| u64::try_from(value).ok())
                .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", subject))?;
            output.push(0x02);
            output.extend_from_slice(&value.to_be_bytes());
            Ok(())
        }
        DirectFieldType::Signed => {
            let value = value
                .as_integer()
                .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", subject))?;
            output.push(0x0a);
            output.extend_from_slice(&value.to_be_bytes());
            Ok(())
        }
        DirectFieldType::Boolean => {
            let value = value
                .as_bool()
                .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", subject))?;
            output.push(0x03);
            output.push(u8::from(value));
            Ok(())
        }
        DirectFieldType::StringArray => {
            let values = value
                .as_array()
                .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", subject))?;
            encode_record_array_header(output, 0x05, values.len(), subject)?;
            for value in values {
                encode_record_string(
                    output,
                    value
                        .as_str()
                        .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", subject))?,
                    subject,
                )?;
            }
            Ok(())
        }
        DirectFieldType::EnvironmentPairs => {
            let values = value
                .as_array()
                .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", subject))?;
            encode_record_array_header(output, 0x05, values.len(), subject)?;
            for pair in values {
                let pair = pair
                    .as_array()
                    .filter(|pair| pair.len() == 2)
                    .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", subject))?;
                encode_record_array_header(output, 0x05, 2, subject)?;
                for item in pair {
                    encode_record_string(
                        output,
                        item.as_str()
                            .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", subject))?,
                        subject,
                    )?;
                }
            }
            Ok(())
        }
        DirectFieldType::Record => encode_schema_record(
            output,
            value
                .as_table()
                .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", subject))?,
            target,
            policy,
            subject,
        ),
        DirectFieldType::RecordArray => {
            let values = value
                .as_array()
                .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", subject))?;
            encode_record_array_header(output, 0x07, values.len(), subject)?;
            for value in values {
                encode_schema_record(
                    output,
                    value
                        .as_table()
                        .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", subject))?,
                    target,
                    policy,
                    subject,
                )?;
            }
            Ok(())
        }
        DirectFieldType::OptionalString
        | DirectFieldType::OptionalUnsigned
        | DirectFieldType::OptionalBoolean => {
            let values = value
                .as_array()
                .filter(|values| values.len() <= 1)
                .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", subject))?;
            output.push(0x08);
            output.push(u8::from(!values.is_empty()));
            if let Some(value) = values.first() {
                let inner = match direct_type {
                    DirectFieldType::OptionalString => DirectFieldType::String,
                    DirectFieldType::OptionalUnsigned => DirectFieldType::Unsigned,
                    DirectFieldType::OptionalBoolean => DirectFieldType::Boolean,
                    _ => unreachable!(),
                };
                encode_direct_record_value(output, value, inner, "", policy, subject)?;
            }
            Ok(())
        }
        DirectFieldType::RawBytes | DirectFieldType::VariantArray => Err(
            Diagnostic::error("E_RECORD_CANONICAL", subject)
                .at(format!("unsupported direct type {}", direct_type.code())),
        ),
    }
}

fn record_set_sha256(
    values: &[toml::Value],
    schema_id: &str,
    policy: &Policy,
    subject: &str,
) -> VResult<String> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"FND01RECv2\0");
    append_registry_count(&mut encoded, values.len(), subject)?;
    for value in values {
        let table = value
            .as_table()
            .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", subject))?;
        let mut record = Vec::new();
        encode_schema_record(&mut record, table, schema_id, policy, subject)?;
        append_registry_count(&mut encoded, record.len(), subject)?;
        encoded.extend_from_slice(&record);
    }
    Ok(lower_hex(&sha256(&encoded)))
}

fn compiled_type_mask(
    masks: &[(&'static str, &'static str)],
    id: &str,
    subject: &str,
) -> VResult<&'static str> {
    let mut matching = masks
        .iter()
        .filter(|(candidate, _)| *candidate == id)
        .map(|(_, mask)| *mask);
    let mask = matching
        .next()
        .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE_REGISTRY", subject).at(id))?;
    if matching.next().is_some() {
        return Err(Diagnostic::error("E_RECORD_TYPE_REGISTRY", subject)
            .at(format!("duplicate mask for {id}")));
    }
    Ok(mask)
}

fn child_type_target(
    child_fields: &[String],
    field: &str,
    direct_type: DirectFieldType,
    subject: &str,
) -> VResult<String> {
    let mappings = parse_child_schema_mappings(child_fields, subject)?;
    let matching = mappings
        .iter()
        .filter(|(candidate, _)| candidate.strip_suffix("[]").unwrap_or(candidate) == field)
        .map(|(mapped, target)| (*mapped, *target))
        .collect::<Vec<_>>();
    match direct_type.child_mapping_suffix() {
        Some(suffix) => {
            let expected = format!("{field}{suffix}");
            if matching.len() != 1 || matching[0].0 != expected {
                return Err(Diagnostic::error("E_RECORD_TYPE_REGISTRY", subject)
                    .at(format!("{field}: child mapping/type mismatch")));
            }
            Ok(matching[0].1.to_owned())
        }
        None if matching.is_empty() => Ok(String::new()),
        None => Err(Diagnostic::error("E_RECORD_TYPE_REGISTRY", subject)
            .at(format!("{field}: scalar has child mapping"))),
    }
}

fn root_field_type_target(
    policy: &Policy,
    root: &str,
    field: &str,
    direct_type: DirectFieldType,
) -> VResult<String> {
    let table_selector = format!("{root}/{field}");
    let array_selector = format!("{root}/{field}[]");
    let record_table_targets = policy
        .record_schema
        .iter()
        .filter(|row| row.selectors.iter().any(|value| value == &table_selector))
        .map(|row| row.id.as_str())
        .collect::<Vec<_>>();
    let record_array_targets = policy
        .record_schema
        .iter()
        .filter(|row| row.selectors.iter().any(|value| value == &array_selector))
        .map(|row| row.id.as_str())
        .collect::<Vec<_>>();
    let variant_table_targets = policy
        .record_variant_schema
        .iter()
        .filter(|row| row.parent_selector == table_selector)
        .map(|row| row.id.as_str())
        .collect::<Vec<_>>();
    let mut variant_array_targets = policy
        .record_variant_schema
        .iter()
        .filter(|row| row.parent_selector == array_selector)
        .map(|row| row.id.as_str())
        .collect::<Vec<_>>();
    match direct_type {
        DirectFieldType::Record
            if record_table_targets.len() == 1
                && record_array_targets.is_empty()
                && variant_table_targets.is_empty()
                && variant_array_targets.is_empty() =>
        {
            Ok(record_table_targets[0].to_owned())
        }
        DirectFieldType::RecordArray
            if record_table_targets.is_empty()
                && record_array_targets.len() == 1
                && variant_table_targets.is_empty()
                && variant_array_targets.is_empty() =>
        {
            Ok(record_array_targets[0].to_owned())
        }
        DirectFieldType::VariantArray
            if record_table_targets.is_empty()
                && record_array_targets.is_empty()
                && variant_table_targets.is_empty()
                && !variant_array_targets.is_empty() =>
        {
            variant_array_targets.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
            variant_array_targets.dedup();
            Ok(variant_array_targets.join(","))
        }
        DirectFieldType::Record
        | DirectFieldType::RecordArray
        | DirectFieldType::VariantArray => Err(Diagnostic::error(
            "E_RECORD_TYPE_REGISTRY",
            root,
        )
        .at(format!("{field}: selector/type mismatch"))),
        _ if record_table_targets.is_empty()
            && record_array_targets.is_empty()
            && variant_table_targets.is_empty()
            && variant_array_targets.is_empty() =>
        {
            Ok(String::new())
        }
        _ => Err(Diagnostic::error("E_RECORD_TYPE_REGISTRY", root)
            .at(format!("{field}: scalar has record selector"))),
    }
}

fn append_direct_type_specs(
    output: &mut Vec<DirectFieldTypeSpec>,
    root: &str,
    fields: &[String],
    mask: &str,
    mut target_for: impl FnMut(&str, DirectFieldType) -> VResult<String>,
) -> VResult<()> {
    if mask.len() != fields.len() || !mask.is_ascii() {
        return Err(Diagnostic::error("E_RECORD_TYPE_REGISTRY", root)
            .at(format!("{} fields != {} mask bytes", fields.len(), mask.len())));
    }
    for (ordinal, (field, code)) in fields.iter().zip(mask.bytes()).enumerate() {
        let direct_type = DirectFieldType::from_code(code, root)?;
        output.push(DirectFieldTypeSpec {
            root: root.to_owned(),
            ordinal,
            field: field.clone(),
            code: direct_type.code(),
            target: target_for(field, direct_type)?,
        });
    }
    Ok(())
}

fn build_direct_field_type_specs(policy: &Policy) -> VResult<Vec<DirectFieldTypeSpec>> {
    let mut specs = Vec::with_capacity(DIRECT_FIELD_TYPE_COUNT);
    for row in &policy.record_schema {
        let mask = compiled_type_mask(
            RECORD_SCHEMA_TYPE_MASKS,
            &row.id,
            "record schema type masks",
        )?;
        let root = format!("schema/{}", row.id);
        append_direct_type_specs(&mut specs, &root, &row.exact_fields, mask, |field, kind| {
            child_type_target(&row.child_fields, field, kind, &row.id)
        })?;
    }
    if policy.record_schema.len() != RECORD_SCHEMA_TYPE_MASKS.len() {
        return Err(Diagnostic::error(
            "E_RECORD_TYPE_REGISTRY",
            "record schema type masks",
        ));
    }

    for row in &policy.record_variant_schema {
        let mask = compiled_type_mask(
            RECORD_VARIANT_TYPE_MASKS,
            &row.id,
            "record variant type masks",
        )?;
        let fields = row
            .required_fields
            .iter()
            .chain(&row.optional_fields)
            .cloned()
            .collect::<Vec<_>>();
        let root = format!("variant/{}", row.id);
        append_direct_type_specs(&mut specs, &root, &fields, mask, |field, kind| {
            child_type_target(&row.child_fields, field, kind, &row.id)
        })?;
    }
    if policy.record_variant_schema.len() != RECORD_VARIANT_TYPE_MASKS.len() {
        return Err(Diagnostic::error(
            "E_RECORD_TYPE_REGISTRY",
            "record variant type masks",
        ));
    }

    for row in &policy.receipt_schema {
        let mask = compiled_type_mask(
            RECEIPT_BODY_TYPE_MASKS,
            &row.receipt_id,
            "receipt body type masks",
        )?;
        let root = format!("receipt/{}/{}", row.kind, row.table_name);
        append_direct_type_specs(&mut specs, &root, &row.exact_fields, mask, |field, kind| {
            root_field_type_target(policy, &root, field, kind)
        })?;
    }
    if policy.receipt_schema.len() != RECEIPT_BODY_TYPE_MASKS.len() {
        return Err(Diagnostic::error(
            "E_RECORD_TYPE_REGISTRY",
            "receipt body type masks",
        ));
    }

    append_direct_type_specs(
        &mut specs,
        "receipt/common",
        &policy.receipt_contract.common_required_fields,
        RECEIPT_COMMON_TYPE_MASK,
        |field, kind| match (field, kind) {
            ("policy" | "verifier" | "harness", DirectFieldType::Record) => {
                Ok("authoring-file-binding".to_owned())
            }
            ("parent", DirectFieldType::RecordArray) => Ok("parent-binding".to_owned()),
            (_, DirectFieldType::Record | DirectFieldType::RecordArray | DirectFieldType::VariantArray) => {
                Err(Diagnostic::error("E_RECORD_TYPE_REGISTRY", "receipt/common").at(field))
            }
            _ => Ok(String::new()),
        },
    )?;

    append_direct_type_specs(
        &mut specs,
        "final-attestation",
        &policy.final_attestation_contract.exact_fields,
        FINAL_ATTESTATION_TYPE_MASK,
        |field, kind| root_field_type_target(policy, "final-attestation", field, kind),
    )?;

    if specs.len() != DIRECT_FIELD_TYPE_COUNT {
        return Err(Diagnostic::error(
            "E_RECORD_TYPE_COUNT",
            "direct field type registry",
        )
        .at(specs.len().to_string()));
    }
    specs.sort_by(|left, right| {
        left.root
            .as_bytes()
            .cmp(right.root.as_bytes())
            .then_with(|| left.ordinal.cmp(&right.ordinal))
    });
    if specs.windows(2).any(|pair| {
        (pair[0].root == pair[1].root && pair[0].ordinal == pair[1].ordinal)
            || (pair[0].root == pair[1].root && pair[0].field == pair[1].field)
    }) {
        return Err(Diagnostic::error(
            "E_RECORD_TYPE_REGISTRY",
            "duplicate direct field type entry",
        ));
    }
    Ok(specs)
}

fn encode_direct_field_type_registry(policy: &Policy) -> VResult<Vec<u8>> {
    let specs = build_direct_field_type_specs(policy)?;
    let mut encoded = Vec::with_capacity(DIRECT_FIELD_TYPE_REGISTRY_BYTES);
    encoded.extend_from_slice(b"FND01RECTYPEv1\0");
    append_registry_count(&mut encoded, specs.len(), "direct field type registry")?;
    for spec in &specs {
        append_registry_row(&mut encoded, &spec.root, "direct field type root")?;
        append_registry_count(
            &mut encoded,
            spec.ordinal,
            "direct field type field ordinal",
        )?;
        append_registry_row(&mut encoded, &spec.field, "direct field type field")?;
        append_registry_row(&mut encoded, spec.code, "direct field type code")?;
        append_registry_row(&mut encoded, &spec.target, "direct field type target")?;
    }
    Ok(encoded)
}

fn encode_count_array_link_registry(policy: &Policy) -> VResult<Vec<u8>> {
    if COUNT_ARRAY_LINKS.len() != COUNT_ARRAY_LINK_COUNT {
        return Err(Diagnostic::error(
            "E_RECORD_COUNT_LINK_REGISTRY",
            "compiled count/array links",
        ));
    }
    let type_specs = build_direct_field_type_specs(policy)?;
    let type_by_field = type_specs
        .iter()
        .map(|spec| ((spec.root.as_str(), spec.field.as_str()), spec.code))
        .collect::<BTreeMap<_, _>>();
    let mut links = COUNT_ARRAY_LINKS.to_vec();
    links.sort_by(|left, right| {
        left.0
            .as_bytes()
            .cmp(right.0.as_bytes())
            .then_with(|| left.1.as_bytes().cmp(right.1.as_bytes()))
            .then_with(|| left.2.as_bytes().cmp(right.2.as_bytes()))
    });
    if links.windows(2).any(|pair| {
        pair[0] == pair[1] || (pair[0].0 == pair[1].0 && pair[0].1 == pair[1].1)
    }) {
        return Err(Diagnostic::error(
            "E_RECORD_COUNT_LINK_REGISTRY",
            "duplicate count/array link",
        ));
    }
    for (root, count_field, array_field) in &links {
        if type_by_field.get(&(*root, *count_field)).copied() != Some("u")
            || !type_by_field
                .get(&(*root, *array_field))
                .copied()
                .is_some_and(|code| matches!(code, "a" | "q" | "v"))
        {
            return Err(Diagnostic::error("E_RECORD_COUNT_LINK_REGISTRY", root)
                .at(format!("{count_field}->{array_field}")));
        }
    }

    let mut encoded = Vec::with_capacity(COUNT_ARRAY_LINK_REGISTRY_BYTES);
    encoded.extend_from_slice(b"FND01COUNTLINKv1\0");
    append_registry_count(&mut encoded, links.len(), "count/array link registry")?;
    for (root, count_field, array_field) in links {
        append_registry_row(&mut encoded, root, "count/array link root")?;
        append_registry_row(&mut encoded, count_field, "count/array link count field")?;
        append_registry_row(&mut encoded, array_field, "count/array link array field")?;
    }
    Ok(encoded)
}

fn validate_schema_registries(policy: &Policy) -> VResult<()> {
    let record = encode_record_schema_registry(&policy.record_schema)?;
    if record.len() != RECORD_SCHEMA_REGISTRY_BYTES
        || lower_hex(&sha256(&record)) != RECORD_SCHEMA_REGISTRY_SHA256
    {
        return Err(Diagnostic::error(
            "E_RECORD_SCHEMA_REGISTRY",
            "record schema registry",
        ));
    }
    let variants = encode_record_variant_registry(&policy.record_variant_schema)?;
    if variants.len() != RECORD_VARIANT_REGISTRY_BYTES
        || lower_hex(&sha256(&variants)) != RECORD_VARIANT_REGISTRY_SHA256
    {
        return Err(Diagnostic::error(
            "E_RECORD_VARIANT_REGISTRY",
            "record variant registry",
        ));
    }
    let record_bound = usize::try_from(policy.bounds.max_record_registry_bytes)
        .map_err(|_| Diagnostic::error("E_RECORD_SCHEMA_BOUND", "record registries"))?;
    if record.len() > record_bound
        || variants.len() > record_bound
        || record
            .len()
            .checked_add(variants.len())
            .is_none_or(|length| length > record_bound)
    {
        return Err(Diagnostic::error(
            "E_RECORD_SCHEMA_BOUND",
            "record registries",
        ));
    }
    let record_contract = policy_unmodeled_table(policy, "record_schema_contract")?;
    if record_string(record_contract, "schema_id", "record_schema_contract")?
        != "fastmcp-fnd01-record-schema"
        || record_u32(
            record_contract,
            "schema_version",
            "record_schema_contract",
        )? != 2
        || record_usize(
            record_contract,
            "record_schema_registry_count",
            "record_schema_contract",
        )? != RECORD_SCHEMA_REGISTRY_COUNT
        || record_usize(
            record_contract,
            "record_schema_registry_bytes",
            "record_schema_contract",
        )? != RECORD_SCHEMA_REGISTRY_BYTES
        || record_string(
            record_contract,
            "record_schema_registry_sha256",
            "record_schema_contract",
        )? != RECORD_SCHEMA_REGISTRY_SHA256
        || record_usize(
            record_contract,
            "record_variant_registry_count",
            "record_schema_contract",
        )? != RECORD_VARIANT_REGISTRY_COUNT
        || record_usize(
            record_contract,
            "record_variant_registry_bytes",
            "record_schema_contract",
        )? != RECORD_VARIANT_REGISTRY_BYTES
        || record_string(
            record_contract,
            "record_variant_registry_sha256",
            "record_schema_contract",
        )? != RECORD_VARIANT_REGISTRY_SHA256
    {
        return Err(Diagnostic::error(
            "E_RECORD_SCHEMA_REGISTRY",
            "record_schema_contract",
        ));
    }
    let receipts = encode_receipt_schema_registry(&policy.receipt_schema)?;
    if receipts.len() != RECEIPT_SCHEMA_REGISTRY_BYTES
        || lower_hex(&sha256(&receipts)) != RECEIPT_SCHEMA_REGISTRY_SHA256
        || policy.receipt_contract.schema_registry_count != RECEIPT_SCHEMA_REGISTRY_COUNT
        || policy.receipt_contract.schema_registry_bytes != RECEIPT_SCHEMA_REGISTRY_BYTES
        || policy.receipt_contract.schema_registry_sha256 != RECEIPT_SCHEMA_REGISTRY_SHA256
    {
        return Err(Diagnostic::error(
            "E_RECEIPT_SCHEMA_REGISTRY",
            "receipt schema registry",
        ));
    }
    if u64::try_from(receipts.len()).unwrap_or(u64::MAX)
        > policy.bounds.max_receipt_schema_registry_bytes
    {
        return Err(Diagnostic::error(
            "E_RECEIPT_SCHEMA_BOUND",
            "receipt schema registry",
        ));
    }

    let record_ids = policy
        .record_schema
        .iter()
        .map(|row| row.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut selectors = BTreeSet::new();
    let mut selector_count = 0usize;
    let mut schema_graph = BTreeMap::<&str, BTreeSet<&str>>::new();
    for row in &policy.record_schema {
        selector_count = selector_count
            .checked_add(row.selectors.len())
            .ok_or_else(|| Diagnostic::error("E_RECORD_SELECTOR", &row.id))?;
        if row.id.is_empty()
            || row.rule.is_empty()
            || row.exact_fields.is_empty()
            || row
                .selectors
                .iter()
                .any(|selector| !selectors.insert(selector.as_str()))
            || row.exact_fields.iter().collect::<BTreeSet<_>>().len()
                != row.exact_fields.len()
        {
            return Err(Diagnostic::error("E_RECORD_SCHEMA_GRAPH", &row.id));
        }
        for selector in &row.selectors {
            validate_record_selector(selector)?;
        }
        let mut child_fields = BTreeSet::new();
        for child in &row.child_fields {
            let (field, child_id) = child.split_once("=>").ok_or_else(|| {
                Diagnostic::error("E_RECORD_SCHEMA_GRAPH", &row.id).at(child)
            })?;
            let direct_field = field.strip_suffix("[]").unwrap_or(field);
            if !row.exact_fields.iter().any(|exact| exact == direct_field)
                || !child_fields.insert(field)
                || !record_ids.contains(child_id)
            {
                return Err(Diagnostic::error("E_RECORD_SCHEMA_GRAPH", &row.id).at(child));
            }
            let target = policy
                .record_schema
                .iter()
                .find(|candidate| candidate.id == child_id)
                .ok_or_else(|| Diagnostic::error("E_RECORD_SCHEMA_GRAPH", &row.id).at(child))?;
            for selector in &row.selectors {
                let expected_child_selector = format!("{selector}/{field}");
                if !target
                    .selectors
                    .iter()
                    .any(|candidate| candidate == &expected_child_selector)
                {
                    return Err(Diagnostic::error("E_RECORD_SCHEMA_GRAPH", &row.id)
                        .at(expected_child_selector));
                }
            }
            schema_graph
                .entry(row.id.as_str())
                .or_default()
                .insert(child_id);
        }
    }
    if selector_count != RECORD_SCHEMA_SELECTOR_COUNT {
        return Err(Diagnostic::error(
            "E_RECORD_SELECTOR_COUNT",
            "record schema registry",
        )
        .at(selector_count.to_string()));
    }
    let recursive_roots =
        policy_string_array(policy, "record_schema_contract", "recursive_root_selectors")?;
    for selector in &selectors {
        let selector = *selector;
        if !selector.starts_with("receipt/common/")
            && !recursive_roots.iter().any(|root| {
                selector == root.as_str()
                    || selector
                        .strip_prefix(root.as_str())
                        .is_some_and(|suffix| suffix.starts_with('/'))
            })
        {
            return Err(Diagnostic::error("E_RECORD_SELECTOR_ROOT", selector));
        }
    }
    let no_optional_ids = policy_string_array(
        policy,
        "record_schema_contract",
        "record_schema_no_optional_field_ids",
    )?;
    if record_usize(
        record_contract,
        "record_schema_no_optional_field_count",
        "record_schema_contract",
    )? != RECORD_SCHEMA_REGISTRY_COUNT
        || no_optional_ids.iter().map(String::as_str).collect::<BTreeSet<_>>() != record_ids
    {
        return Err(Diagnostic::error(
            "E_RECORD_SCHEMA_PRESENCE",
            "record_schema_contract",
        ));
    }
    let mut temporary = BTreeSet::new();
    let mut permanent = BTreeSet::new();
    for id in &record_ids {
        validate_record_schema_acyclic(
            id,
            &schema_graph,
            &mut temporary,
            &mut permanent,
        )?;
    }
    let mut variant_dispatches = BTreeSet::new();
    for row in &policy.record_variant_schema {
        let required_fields = row.required_fields.iter().collect::<BTreeSet<_>>();
        let optional_fields = row.optional_fields.iter().collect::<BTreeSet<_>>();
        if row.id.is_empty()
            || row.parent_selector.is_empty()
            || row.discriminator_field.is_empty()
            || row.discriminator_value.is_empty()
            || row.rule.is_empty()
            || required_fields.len() != row.required_fields.len()
            || optional_fields.len() != row.optional_fields.len()
            || !variant_dispatches.insert((
                row.parent_selector.as_str(),
                row.discriminator_field.as_str(),
                row.discriminator_value.as_str(),
            ))
            || !row
                .required_fields
                .iter()
                .any(|field| field == &row.discriminator_field)
            || !required_fields.is_disjoint(&optional_fields)
        {
            return Err(Diagnostic::error("E_RECORD_VARIANT_GRAPH", &row.id));
        }
        for child in &row.child_fields {
            let (field, child_id) = child.split_once("=>").ok_or_else(|| {
                Diagnostic::error("E_RECORD_VARIANT_GRAPH", &row.id).at(child)
            })?;
            let direct_field = field.strip_suffix("[]").unwrap_or(field);
            if !row
                .required_fields
                .iter()
                .any(|candidate| candidate == direct_field)
                && !row
                    .optional_fields
                    .iter()
                    .any(|candidate| candidate == direct_field)
            {
                return Err(Diagnostic::error("E_RECORD_VARIANT_GRAPH", &row.id).at(child));
            }
            if !record_ids.contains(child_id) {
                return Err(Diagnostic::error("E_RECORD_VARIANT_GRAPH", &row.id).at(child));
            }
        }
    }

    let receipt_ids = policy
        .receipt_schema
        .iter()
        .map(|row| row.receipt_id.as_str())
        .collect::<Vec<_>>();
    let receipt_kinds = policy
        .receipt_schema
        .iter()
        .map(|row| row.kind.as_str())
        .collect::<Vec<_>>();
    let receipt_tables = policy
        .receipt_schema
        .iter()
        .map(|row| row.table_name.as_str())
        .collect::<Vec<_>>();
    let expected_receipt_ids = TOML_OUTPUT_IDS.iter().copied().collect::<BTreeSet<_>>();
    let expected_receipt_kinds = OUTPUT_IDS
        .iter()
        .zip(OUTPUT_KINDS)
        .filter(|(id, _)| TOML_OUTPUT_IDS.contains(id))
        .map(|(_, kind)| *kind)
        .collect::<BTreeSet<_>>();
    if receipt_ids.iter().copied().collect::<BTreeSet<_>>() != expected_receipt_ids
        || receipt_ids.iter().collect::<BTreeSet<_>>().len() != receipt_ids.len()
        || receipt_kinds.iter().copied().collect::<BTreeSet<_>>() != expected_receipt_kinds
        || receipt_kinds.iter().collect::<BTreeSet<_>>().len() != receipt_kinds.len()
        || receipt_tables.iter().collect::<BTreeSet<_>>().len() != receipt_tables.len()
    {
        return Err(Diagnostic::error(
            "E_RECEIPT_SCHEMA_DISPATCH",
            "receipt schema registry",
        ));
    }

    let direct_types = encode_direct_field_type_registry(policy)?;
    if direct_types.len() != DIRECT_FIELD_TYPE_REGISTRY_BYTES
        || direct_types.len() > record_bound
        || lower_hex(&sha256(&direct_types)) != DIRECT_FIELD_TYPE_REGISTRY_SHA256
    {
        return Err(Diagnostic::error(
            "E_RECORD_TYPE_REGISTRY",
            "compiled direct field type registry",
        ));
    }
    let count_links = encode_count_array_link_registry(policy)?;
    if count_links.len() != COUNT_ARRAY_LINK_REGISTRY_BYTES
        || count_links.len() > record_bound
        || lower_hex(&sha256(&count_links)) != COUNT_ARRAY_LINK_REGISTRY_SHA256
    {
        return Err(Diagnostic::error(
            "E_RECORD_COUNT_LINK_REGISTRY",
            "compiled count/array link registry",
        ));
    }
    Ok(())
}

fn validate_raw_policy_shape(raw: &toml::Value) -> VResult<()> {
    let root = raw
        .as_table()
        .ok_or_else(|| Diagnostic::error("E_POLICY_SHAPE_TYPE", "policy root"))?;
    let shape_value = root
        .get("policy_shape_contract")
        .ok_or_else(|| Diagnostic::error("E_POLICY_SHAPE_FIELDS", "policy root"))?;
    let shape = shape_value
        .clone()
        .try_into::<PolicyShapeBootstrap>()
        .map_err(|_| {
            Diagnostic::error("E_POLICY_SHAPE_BOOTSTRAP", "policy_shape_contract")
        })?;
    if shape.schema_id != POLICY_SHAPE_SCHEMA_ID
        || shape.schema_version != POLICY_SHAPE_SCHEMA_VERSION
        || shape.shape_row_count != POLICY_SHAPE_ROW_COUNT
        || shape.root_scalar_type_row_count != POLICY_ROOT_SCALAR_TYPE_ROW_COUNT
        || shape.conditional_variant_row_count != POLICY_CONDITIONAL_VARIANT_ROW_COUNT
        || shape.registry_bytes != POLICY_SHAPE_REGISTRY_BYTES
        || shape.registry_sha256 != POLICY_SHAPE_REGISTRY_SHA256
        || shape.registry_bytes > MAX_POLICY_SHAPE_REGISTRY_BYTES
        || shape.shape_row_encoding.is_empty()
        || shape.fixture_inline_value_rule.is_empty()
        || shape.nested_collection_rule.is_empty()
        || shape.child_structure_rule.is_empty()
        || shape.direct_value_type_rule.is_empty()
        || shape.verifier_authority_rule.is_empty()
        || shape.validation_order.is_empty()
    {
        return Err(Diagnostic::error(
            "E_POLICY_SHAPE_IDENTITY",
            "policy_shape_contract",
        ));
    }
    validate_sha256(&shape.registry_sha256, "policy shape registry SHA-256")?;
    let encoded = encode_policy_shape_registry(&shape)?;
    if encoded.len() != POLICY_SHAPE_REGISTRY_BYTES
        || lower_hex(&sha256(&encoded)) != POLICY_SHAPE_REGISTRY_SHA256
    {
        return Err(Diagnostic::error(
            "E_POLICY_SHAPE_REGISTRY",
            "policy_shape_contract",
        ));
    }
    let rules = parse_policy_shape_rules(&shape)?;
    let root_shape_row = shape
        .shape_rows_a
        .iter()
        .chain(&shape.shape_rows_b)
        .chain(&shape.shape_rows_c)
        .find(|row| row.starts_with("$|"))
        .ok_or_else(|| Diagnostic::error("E_POLICY_SHAPE_ROW", "policy root"))?;
    let root_columns = root_shape_row.split('|').collect::<Vec<_>>();
    let root_field_order = root_columns
        .get(2)
        .ok_or_else(|| Diagnostic::error("E_POLICY_SHAPE_ROW", "policy root"))?
        .split(',')
        .collect::<Vec<_>>();
    let declared_root_order = shape
        .root_scalar_names
        .iter()
        .chain(&shape.root_table_names)
        .chain(&shape.root_array_table_names)
        .map(String::as_str)
        .collect::<Vec<_>>();
    if root_field_order != declared_root_order {
        return Err(Diagnostic::error(
            "E_POLICY_SHAPE_ROOT_CLASS",
            "root field order",
        ));
    }
    let root_rule = rules
        .get("$")
        .filter(|rule| rule.kind == PolicyShapeKind::Root)
        .ok_or_else(|| Diagnostic::error("E_POLICY_SHAPE_ROW", "policy root"))?;
    validate_table_against_shape(root, root_rule, "policy root")?;

    let mut scalar_types = BTreeMap::new();
    for row in &shape.root_scalar_type_rows {
        let (field, kind) = row.split_once('|').ok_or_else(|| {
            Diagnostic::error("E_POLICY_SHAPE_ROW", "root scalar type").at(row)
        })?;
        if !matches!(kind, "string" | "bool" | "nonnegative-integer")
            || scalar_types.insert(field, kind).is_some()
        {
            return Err(Diagnostic::error("E_POLICY_SHAPE_ROW", "root scalar type").at(row));
        }
    }
    let scalar_names = shape
        .root_scalar_names
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if scalar_names.len() != POLICY_ROOT_SCALAR_TYPE_ROW_COUNT
        || scalar_names != scalar_types.keys().copied().collect()
    {
        return Err(Diagnostic::error(
            "E_POLICY_SHAPE_ROOT_CLASS",
            "root scalar names",
        ));
    }
    for (field, kind) in scalar_types {
        let value = root
            .get(field)
            .ok_or_else(|| Diagnostic::error("E_POLICY_SHAPE_FIELDS", "policy root").at(field))?;
        let valid = match kind {
            "string" => value.is_str(),
            "bool" => value.is_bool(),
            "nonnegative-integer" => value.as_integer().is_some_and(|value| value >= 0),
            _ => false,
        };
        if !valid {
            return Err(Diagnostic::error("E_POLICY_SHAPE_TYPE", "policy root").at(field));
        }
    }

    let table_names = shape
        .root_table_names
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let array_names = shape
        .root_array_table_names
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if table_names.len() != shape.root_table_names.len()
        || array_names.len() != shape.root_array_table_names.len()
        || !table_names.is_disjoint(&array_names)
    {
        return Err(Diagnostic::error(
            "E_POLICY_SHAPE_ROOT_CLASS",
            "root table classes",
        ));
    }
    for name in table_names {
        let rule = rules
            .get(name)
            .filter(|rule| rule.kind == PolicyShapeKind::Table)
            .ok_or_else(|| Diagnostic::error("E_POLICY_SHAPE_ROW", name))?;
        let table = root
            .get(name)
            .and_then(toml::Value::as_table)
            .ok_or_else(|| Diagnostic::error("E_POLICY_SHAPE_TYPE", name))?;
        validate_table_against_shape(table, rule, name)?;
    }
    for name in array_names {
        let path = format!("{name}[]");
        let rule = rules
            .get(&path)
            .filter(|rule| rule.kind == PolicyShapeKind::ArrayTableRow)
            .ok_or_else(|| Diagnostic::error("E_POLICY_SHAPE_ROW", &path))?;
        let values = root
            .get(name)
            .and_then(toml::Value::as_array)
            .filter(|values| !values.is_empty())
            .ok_or_else(|| Diagnostic::error("E_POLICY_SHAPE_TYPE", &path))?;
        for (index, value) in values.iter().enumerate() {
            let table = value
                .as_table()
                .ok_or_else(|| Diagnostic::error("E_POLICY_SHAPE_TYPE", &path))?;
            validate_table_against_shape(table, rule, &format!("{path}[{index}]"))?;
        }
    }
    if rules
        .get("mutation_fixture[].value")
        .is_none_or(|rule| rule.kind != PolicyShapeKind::TypedInlineException)
    {
        return Err(Diagnostic::error(
            "E_POLICY_SHAPE_ROW",
            "mutation_fixture[].value",
        ));
    }
    validate_policy_shape_variants(root)?;
    validate_raw_fixture_values(root)?;
    let type_registry = encode_policy_type_registry(root, &rules)?;
    validate_policy_type_registry(&type_registry)?;
    Ok(())
}

fn read_policy(root: &Path) -> VResult<(Policy, Vec<u8>)> {
    let relative = "evidence/fnd-01/dependency-verification.toml";
    let path = resolve_safe(root, relative, "dependency-verification policy")?;
    let bytes = read_bounded(&path, HARD_MAX_POLICY_BYTES, relative)?;
    if bytes.len() != FROZEN_POLICY_BYTES
        || lower_hex(&sha256(&bytes)) != FROZEN_POLICY_SHA256
    {
        return Err(Diagnostic::error("E_POLICY_FROZEN_BINDING", relative));
    }
    let raw: toml::Value = parse_toml_strict(&bytes, relative)?;
    validate_raw_policy_shape(&raw)?;
    let policy = raw.try_into::<Policy>().map_err(|_| {
        Diagnostic::error("E_TOML_SCHEMA", relative)
            .at("V2 typed extraction after raw policy-shape validation")
    })?;
    Ok((policy, bytes))
}

fn string_sequence_is(actual: &[String], expected: &[&str]) -> bool {
    actual
        .iter()
        .map(String::as_str)
        .eq(expected.iter().copied())
}

fn validate_policy_shape(policy: &Policy) -> VResult<()> {
    if policy.format != "fastmcp-fnd-01-dependency-verification-v2"
        || policy.schema_version != POLICY_SCHEMA_VERSION
        || policy.policy_id != "FND-01/dependency-verification"
        || policy.protocol_version != "2026-07-28"
        || policy.recorded_on != "2026-07-30"
        || policy.hash_algorithm != "sha256"
        || policy.authoring_bead != POLICY_OWNER
        || policy.integration_producer_bead != INTEGRATION_PRODUCER
        || policy.final_attester_bead != FINAL_ATTESTER
        || policy.source_input_count != EXPECTED_SOURCE_FILES
        || policy.source_input_total_bytes != 2_671_887
        || policy.negative_case_count != EXPECTED_NEGATIVES
        || policy.derived_output_count != EXPECTED_RECEIPTS
        || policy.derived_toml_count != EXPECTED_RECEIPT_TOMLS
        || policy.derived_binary_count != EXPECTED_RECEIPT_BINARIES
        || policy.derived_direct_parent_edge_count != EXPECTED_DIRECT_PARENT_EDGES
        || !policy.deny_unknown_policy_fields
        || !policy.deny_unknown_receipt_fields
        || policy.aggregate_support_claimed
    {
        return Err(Diagnostic::error("E_POLICY_IDENTITY", &policy.policy_id)
            .at("format/version/identity/cardinality"));
    }
    if policy.paths.repository_root_resolution
        != "ordinary read-only verifier mode uses compile-time CARGO_MANIFEST_DIR for crates/fastmcp followed by exactly two parent() operations; environment or ancestor discovery is forbidden"
        || policy.paths.repository_root_parent_count != 2
        || policy.paths.current_dir_allowed
        || policy.paths.environment_path_search_allowed
        || policy.paths.ancestor_manifest_discovery_allowed
        || policy.paths.source_root != "evidence/fnd-01"
        || policy.paths.policy_path != "evidence/fnd-01/dependency-verification.toml"
        || policy.paths.verifier_test_path
            != "crates/fastmcp/tests/fnd_01_dependency_evidence.rs"
        || policy.paths.bootstrap_harness_path
            != "crates/fastmcp/examples/fnd_01_evidence_harness.rs"
        || policy.paths.integration_root != "evidence/fnd-01/integration"
        || policy.paths.final_attestation_path != "evidence/fnd-01/final-attestation.toml"
        || policy.paths.run_scratch_root != ".fnd01-run"
        || !policy.paths.integration_is_flat
        || policy.paths.follow_symlinks
        || policy.paths.allow_absolute_paths
        || policy.paths.allow_backslashes
        || policy.paths.allow_empty_components
        || policy.paths.allow_dot_components
        || policy.paths.allow_dot_dot_components
        || policy.paths.allow_drive_prefixes
        || policy.paths.allow_nul
        || !policy.paths.reject_hardlinks
        || !policy.paths.reject_special_files
        || !policy.paths.reject_ascii_case_collisions
        || !policy.paths.reject_extra_files
        || !policy.paths.reject_extra_directories
        || policy.paths.typed_path_scope_rule.is_empty()
    {
        return Err(Diagnostic::error("E_POLICY_PATHS", &policy.policy_id));
    }
    for path in [
        &policy.paths.source_root,
        &policy.paths.policy_path,
        &policy.paths.verifier_test_path,
        &policy.paths.bootstrap_harness_path,
        &policy.paths.integration_root,
        &policy.paths.final_attestation_path,
        &policy.paths.run_scratch_root,
    ] {
        validate_ascii_posix_path(path, "policy path")?;
    }
    let bounds = &policy.bounds;
    if bounds.max_path_bytes != 240
        || bounds.max_path_component_bytes != 100
        || bounds.max_path_depth != 8
        || bounds.max_id_bytes != 128
        || bounds.max_selector_bytes != 512
        || bounds.max_selector_depth != 16
        || bounds.max_source_file_bytes != 1_048_576
        || bounds.max_policy_bytes != HARD_MAX_POLICY_BYTES
        || bounds.max_verifier_test_bytes != 2_097_152
        || bounds.max_bootstrap_harness_bytes != 262_144
        || bounds.max_receipt_toml_bytes != 67_108_864
        || bounds.max_supply_bundle_bytes != 1_073_741_824
        || bounds.max_command_stream_bundle_bytes != 536_870_912
        || bounds.max_command_stream_expanded_bytes != 1_073_741_824
        || bounds.max_package_artifact_bytes != 268_435_456
        || bounds.max_final_attestation_bytes != 16_777_216
        || bounds.max_integration_total_bytes != 4_294_967_296
        || bounds.max_outer_transport_record_bytes != 134_217_728
        || bounds.max_outer_transport_argv_items != 64
        || bounds.max_outer_transport_assignments != 16
        || bounds.max_outer_transport_argument_bytes != 4_096
        || bounds.max_outer_transport_key_bytes != 128
        || bounds.max_outer_transport_value_bytes != 4_096
        || bounds.max_outer_transport_stdout_bytes != 33_554_432
        || bounds.max_outer_transport_stderr_bytes != 33_554_432
        || bounds.max_outer_transport_final_argv_items != 16
        || bounds.max_outer_transport_cfg_entries != 512
        || bounds.max_outer_transport_cfg_bytes != 1_048_576
        || bounds.max_final_gate_stdout_bytes != 1_048_576
        || bounds.max_final_gate_stderr_bytes != 1_048_576
        || bounds.max_final_gate_input_bytes != 1_048_576
        || bounds.max_final_gate_result_bytes != 4_194_304
        || bounds.max_gate_executable_bytes != 268_435_456
        || bounds.max_control_ledger_bytes != 67_108_864
        || bounds.max_acquisition_spool_bytes != 134_217_728
        || bounds.max_raw_stdout_bytes != 67_108_864
        || bounds.max_raw_stderr_bytes != 67_108_864
        || bounds.max_argv_items != 64
        || bounds.max_argument_bytes != 4_096
        || bounds.max_environment_items != 64
        || bounds.max_environment_key_bytes != 128
        || bounds.max_environment_value_bytes != 4_096
        || bounds.max_parent_count != EXPECTED_RECEIPTS - 1
        || bounds.max_archive_compressed_bytes != 8_388_608
        || bounds.max_archive_expanded_bytes != 67_108_864
        || bounds.max_archive_member_count != 4_096
        || bounds.max_archive_member_bytes != 16_777_216
        || bounds.max_tree_entry_count != 1_000_000
        || bounds.max_run_scratch_total_bytes != 68_719_476_736
        || bounds.max_execution_footprint_total_bytes != 73_014_444_032
        || bounds.max_fallback_target_total_bytes != 8_589_934_592
        || bounds.max_transport_target_total_bytes != 4_563_402_752
        || bounds.max_controller_scratch_total_bytes != 1_073_741_824
        || bounds.max_control_plane_total_bytes != 268_435_456
        || bounds.max_package_source_total_bytes != 4_294_967_296
        || bounds.max_quarantine_total_bytes != 8_589_934_592
        || bounds.max_return_tree_total_bytes != 4_294_967_296
        || bounds.max_publication_staging_total_bytes != 4_294_967_296
        || bounds.max_bootstrap_scratch_total_bytes != 4_294_967_296
        || bounds.max_materialization_total_bytes != 4_294_967_296
        || bounds.max_projection_tree_total_bytes != 4_294_967_296
        || bounds.max_package_tree_total_bytes != 4_294_967_296
        || bounds.max_consumer_tree_total_bytes != 4_294_967_296
        || bounds.max_external_input_entry_count != 1_000_000
        || bounds.max_external_input_member_bytes != 2_147_483_648
        || bounds.max_external_input_total_bytes != 68_719_476_736
        || bounds.max_record_depth != 32
        || bounds.max_record_field_count != 256
        || bounds.max_record_array_items != 1_000_000
        || bounds.max_record_string_bytes != 1_048_576
        || bounds.max_record_blob_bytes != 1_073_741_824
        || bounds.max_record_total_bytes != 1_073_741_824
        || bounds.max_record_registry_bytes != 1_048_576
        || bounds.max_receipt_schema_registry_bytes != 1_048_576
        || bounds.max_policy_shape_registry_bytes != 1_048_576
        || bounds.exact_source_input_count != EXPECTED_SOURCE_FILES
        || bounds.exact_negative_case_count != EXPECTED_NEGATIVES
        || bounds.exact_derived_output_count != EXPECTED_RECEIPTS
        || bounds.exact_derived_toml_count != EXPECTED_RECEIPT_TOMLS
        || bounds.exact_derived_binary_count != EXPECTED_RECEIPT_BINARIES
        || bounds.exact_direct_parent_edge_count != EXPECTED_DIRECT_PARENT_EDGES
        || bounds.exact_projection_count != EXPECTED_PROJECTIONS
        || bounds.exact_target_count != EXPECTED_TARGETS
        || bounds.exact_projection_target_count != EXPECTED_PROJECTIONS * EXPECTED_TARGETS
    {
        return Err(Diagnostic::error("E_POLICY_BOUNDS", &policy.policy_id));
    }
    if policy.source_tree.format != "FND01TREEv1"
        || policy.source_tree.path_scope
            != "repository-relative POSIX ASCII path beginning evidence/fnd-01/"
        || policy.source_tree.ordering != "ascending raw path bytes"
        || policy.source_tree.record_encoding
            != "u32be(path_len) || path || u64be(file_len) || raw_sha256(file_bytes)"
        || policy.source_tree.domain_prefix != "none"
        || policy.source_tree.file_count != EXPECTED_SOURCE_FILES
        || policy.source_tree.total_bytes != policy.source_input_total_bytes
        || policy.source_tree.sha256 != SOURCE_TREE_SHA256
        || !string_sequence_is(
            &policy.source_tree.excluded_exact_paths,
            &[
                "evidence/fnd-01/dependency-verification.toml",
                "crates/fastmcp/tests/fnd_01_dependency_evidence.rs",
                "crates/fastmcp/examples/fnd_01_evidence_harness.rs",
                "evidence/fnd-01/final-attestation.toml",
            ],
        )
        || policy.source_tree.excluded_exact_directory != "evidence/fnd-01/integration"
        || policy.source_tree.wildcard_exclusions_allowed
    {
        return Err(Diagnostic::error("E_SOURCE_TREE_CONTRACT", &policy.policy_id));
    }
    validate_sha256(&policy.source_tree.sha256, "source tree SHA-256")?;
    if !policy.source_input_contract.all_rows_bytes_available
        || policy.source_input_contract.all_rows_rehash_mode != "exact_local"
        || policy.source_input_contract.all_rows_claim_ceiling != "local-byte-proof"
        || !policy.source_input_contract.all_rows_required
        || !policy.source_input_contract.all_rows_source_tree_members
        || !policy
            .source_input_contract
            .checked_in_archives_remain_local_exact_bytes
        || policy.parse_inventory.toml != 22
        || policy.parse_inventory.json != 14
        || policy.parse_inventory.utf8_text != 23
        || policy.parse_inventory.opaque_binary != 4
        || policy.parse_inventory.gzip_tar != 3
    {
        return Err(Diagnostic::error("E_SOURCE_INPUT_CONTRACT", &policy.policy_id));
    }
    if !string_sequence_is(
        &policy.negative_inventory.family_order,
        &["sdk.catalog", "sdk.peer", "auth", "tasks_apps", "media", "state"],
    ) || policy.negative_inventory.row_order_authoritative
        || policy.negative_inventory.canonical_order
            != "family_order, then ascending source_index"
        || !policy
            .negative_inventory
            .source_indices_must_be_contiguous_per_family
        || policy.negative_inventory.canonical_record
            != "family || HTAB || id || LF after canonical_order sorting"
        || policy.negative_inventory.count != EXPECTED_NEGATIVES
        || policy.negative_inventory.canonical_bytes != 6_912
        || policy.negative_inventory.sha256 != NEGATIVE_INVENTORY_SHA256
        || !policy.negative_inventory.ids_globally_unique
        || !policy.negative_inventory.one_recipe_per_id
        || !policy.negative_inventory.anonymous_corpora_excluded
    {
        return Err(Diagnostic::error("E_NEGATIVE_CONTRACT", &policy.policy_id));
    }
    validate_sha256(
        &policy.negative_inventory.sha256,
        "negative inventory SHA-256",
    )?;
    if !string_sequence_is(
        &policy.mutation_contract.allowed_operations,
        &[
            "remove",
            "insert",
            "replace",
            "swap",
            "duplicate",
            "toggle_bool",
            "increment",
            "append_feature",
            "rename_key",
            "replace_bytes",
        ],
    ) || !string_sequence_is(
        &policy.mutation_contract.allowed_integrity_modes,
        &["rebind_virtual_hashes"],
    ) || policy.mutation_contract.default_integrity_mode != "rebind_virtual_hashes"
        || !policy
            .mutation_contract
            .all_cases_must_rebind_virtual_hashes
        || policy.mutation_contract.selector_grammar
            != "RFC 6901 JSON Pointer; raw bytes use /bytes/<decimal-offset-or-end>. Canonical decimal array indices are permitted for ordinary array selection. Identity components /<array>/<identity-key>=<literal>/<field> are required only where fixture_contract.replace_table_member_identity_is_required_for_table_arrays applies (including its relative_selector traversal) or another row-specific contract explicitly requires a stable table-array identity; the grammar does not silently impose identity selectors on every TOML array"
        || !policy.mutation_contract.require_target_path_exists
        || !policy.mutation_contract.require_target_selector_resolves
        || !policy.mutation_contract.require_non_noop_mutation
        || !policy
            .mutation_contract
            .remove_argument_forbidden_except_remove_exact_fixture
        || !policy.mutation_contract.duplicate_argument_forbidden
        || !policy.mutation_contract.swap_argument_forbidden
        || !policy.mutation_contract.swap_secondary_selector_required
        || !policy.mutation_contract.insert_argument_required
        || !policy.mutation_contract.replace_argument_required
        || !policy.mutation_contract.toggle_bool_argument_required
        || !policy.mutation_contract.increment_argument_required
        || !policy.mutation_contract.append_feature_argument_required
        || !policy.mutation_contract.rename_key_argument_required
        || !policy.mutation_contract.replace_bytes_argument_required
        || policy.mutation_contract.replace_bytes_argument_grammar
            != "exactly append-hex:<nonempty-even-lowerhex>, xor:<two-lowerhex>, truncate:<canonical-positive-decimal>, or insert-cr-before-lf; insert-cr-before-lf requires target_selector /bytes/<canonical-decimal>, selected byte exact LF, and inserts one CR immediately before that LF without changing any other byte"
        || !policy
            .mutation_contract
            .non_swap_secondary_selector_forbidden
        || policy.mutation_contract.stable_diagnostic_format
            != "FND01_NEG|<family>|<id>|<rule>|<logical-path>"
        || !policy
            .mutation_contract
            .require_exact_one_primary_diagnostic
        || policy.mutation_contract.additional_diagnostic_rule
            != "zero or more actually observed allowed cotrigger diagnostics may follow the one required primary in assertion_contract finding_precedence order; suppressed findings are recorded without an emitted diagnostic and unexpected findings fail"
        || !policy
            .mutation_contract
            .require_literal_family_id_rule_and_path
        || !policy
            .mutation_contract
            .forbid_negative_row_self_mutation
        || !policy
            .mutation_contract
            .negative_case_rows_deny_unknown_fields
        || !string_sequence_is(
            &policy.mutation_contract.negative_case_exact_fields,
            &[
                "family",
                "id",
                "source_index",
                "target_path",
                "target_selector",
                "operation",
                "argument",
                "secondary_selector",
                "integrity_mode",
                "validator",
            ],
        )
        || !policy
            .mutation_contract
            .assertion_registry_is_only_oracle_authority
        || !policy.mutation_contract.forbid_result_field_mutation
        || !policy.mutation_contract.forbid_verified_field_mutation
        || !policy
            .mutation_contract
            .semantic_drift_meta_test_required
        || !policy
            .mutation_contract
            .semantic_drift_meta_test_rebinds_file_and_tree_hashes
        || policy.mutation_contract.mutation_execution_isolation
            != "load the exact 66 source_input byte map read-only; for each negative_case create a fresh bounded in-memory copy of only target_path bytes, apply exactly that recipe, rebind only the virtual file/source-family/source-tree hashes required by integrity_mode, run the complete validator against the one virtual byte substitution, record the result, and discard it before the next case; no source, workspace, retained, scratch, or integration file is written, and mutations never accumulate"
        || policy.mutation_contract.quarantine_meta_test_exception
            != "the sole recipe whose selector enters a quarantined source array is tasks_apps/quarantine-drift; it removes one table only from the fresh in-memory tasks-apps.toml clone to prove the exact quarantine set validator fires, never parses or executes the quarantined table as a payload, and therefore does not contradict quarantine mutation_allowed=false"
        || !policy.mutation_contract.structured_toml_mutation_allowed
        || !policy.mutation_contract.structured_json_mutation_allowed
        || !policy
            .mutation_contract
            .structured_json_duplicate_keys_rejected
        || policy
            .mutation_contract
            .structured_json_reserved_number_member_name_rule
            != "before serde_json::Value deserialization or any arbitrary_precision Number classification, token-aware strict-JSON preflight decodes every object member name and forbids the exact decoded name `$serde_json::private::Number` at every object depth, including objects nested through arrays; any literal, Unicode-escaped, or mixed spelling that decodes to that name fails E_JSON_SCHEMA, and the reserved object can never be silently reclassified as a JSON number"
        || !policy
            .mutation_contract
            .structured_json_depth_and_member_bounds_required
        || !policy
            .mutation_contract
            .structured_json_numbers_must_be_losslessly_classified
        || policy.mutation_contract.canonical_recipe_encoding
            != "ASCII FND01MUTv2 followed by NUL, then u32be row count, then canonical rows"
        || policy.mutation_contract.canonical_recipe_order
            != "negative_inventory family_order, then ascending source_index"
        || !string_sequence_is(
            &policy.mutation_contract.canonical_recipe_fields,
            &[
                "family",
                "id",
                "source_index",
                "target_path",
                "target_selector",
                "operation",
                "argument",
                "secondary_selector",
                "integrity_mode",
                "validator",
            ],
        )
        || policy.mutation_contract.canonical_recipe_string_encoding
            != "u32be byte length followed by UTF-8 bytes"
        || policy.mutation_contract.canonical_recipe_source_index_encoding != "u32be"
        || policy.mutation_contract.canonical_recipe_optional_string_encoding
            != "one presence byte: 0x00 means absent with no following bytes; 0x01 means present followed by canonical_recipe_string_encoding; every other presence byte is invalid"
        || policy.mutation_contract.canonical_recipe_count != EXPECTED_NEGATIVES
        || policy.mutation_contract.canonical_recipe_bytes
            != MUTATION_RECIPE_CANONICAL_BYTES
        || policy.mutation_contract.canonical_recipe_sha256
            != MUTATION_RECIPE_CANONICAL_SHA256
    {
        return Err(Diagnostic::error("E_MUTATION_CONTRACT", &policy.policy_id));
    }
    let fixtures = &policy.fixture_contract;
    if fixtures.reference_prefix != "fixture:"
        || fixtures.exact_fixture_count != 51
        || fixtures.max_fixture_id_bytes != 128
        || fixtures.max_fixture_value_bytes != 16_384
        || fixtures.max_fixture_value_depth != 8
        || fixtures.max_fixture_value_members != 64
        || !string_sequence_is(
            &fixtures.allowed_applications,
            &[
                "replace_value",
                "remove_exact_value",
                "insert_array_element",
                "insert_table_member",
                "replace_table_member",
            ],
        )
        || !string_sequence_is(
            &fixtures.allowed_value_kinds,
            &[
                "string",
                "string_array",
                "table",
                "table_array",
                "table_member",
            ],
        )
        || !fixtures.ids_must_be_unique
        || !fixtures.all_references_must_resolve
        || !fixtures.all_fixtures_must_be_referenced
        || !fixtures.application_must_match_operation
        || !string_sequence_is(
            &fixtures.replace_operation_applications,
            &["replace_value", "replace_table_member"],
        )
        || !string_sequence_is(
            &fixtures.remove_operation_applications,
            &["remove_exact_value"],
        )
        || !string_sequence_is(
            &fixtures.insert_operation_applications,
            &["insert_array_element", "insert_table_member"],
        )
        || !fixtures.swap_operation_applications.is_empty()
        || !fixtures.duplicate_operation_applications.is_empty()
        || !fixtures.toggle_bool_operation_applications.is_empty()
        || !fixtures.increment_operation_applications.is_empty()
        || !fixtures.append_feature_operation_applications.is_empty()
        || !fixtures.rename_key_operation_applications.is_empty()
        || !fixtures.replace_bytes_operation_applications.is_empty()
        || !fixtures.value_kind_must_match_value
        || !fixtures.payload_must_be_nonempty
        || !fixtures.payload_must_differ_from_canonical_target
        || !fixtures.target_type_compatibility_required
        || !fixtures.literal_fixture_reference_is_forbidden
        || !fixtures.toml_and_json_target_compatibility_required
        || !fixtures.remove_exact_value_must_equal_selected_value
        || !string_sequence_is(
            &fixtures.table_member_value_requires_exact_keys,
            &["relative_selector", "value"],
        )
        || fixtures.table_member_relative_selector_grammar
            != "nonempty RFC 6901 pointer appended component-wise to the negative case target_selector"
        || fixtures.insert_table_member_relative_selector_component_count != 1
        || fixtures.table_member_key_collision_allowed_for_insert
        || !fixtures.insert_table_member_requires_absent_target
        || !fixtures.replace_table_member_key_must_exist
        || !fixtures.replace_table_member_requires_exact_single_resolution
        || !fixtures
            .replace_table_member_identity_is_required_for_table_arrays
        || !fixtures.fixture_rows_deny_unknown_fields
        || fixtures.value_digest_encoding
            != "sha256 over ASCII FND01FIXv1 followed by NUL and exactly one recursively encoded fixture value using assertion_contract TOML value tags {0x02,0x03,0x04,0x05,0x06,0x07,0x09}"
        || fixtures.canonical_record
            != "id || NUL || application || NUL || value_kind || NUL || lowercase value_digest_sha256 || LF, sorted by raw UTF-8 id bytes"
        || fixtures.canonical_encoding
            != "the canonical registry byte string is exactly the concatenation of canonical_record rows in the declared raw-id order, with no header, count word, blank row, alternate separator, or bytes after the final row LF; canonical_count and canonical_bytes are externally checked before SHA-256"
        || fixtures.canonical_count != 51
        || fixtures.canonical_bytes != 6_552
        || fixtures.canonical_sha256
            != "3abebcd4232aff29d4612427cf7a3bfb4a2398f088eab6d8cf2662917828dae7"
    {
        return Err(Diagnostic::error("E_FIXTURE_CONTRACT", &policy.policy_id));
    }
    let assertions = &policy.assertion_contract;
    if assertions.exact_assertion_count != EXPECTED_NEGATIVES
        || !assertions.baseline_preflight_required
        || !assertions.post_mutation_full_scan_required
        || assertions.observation_encoding != "FND01OBSv1"
        || assertions.header != "ASCII FND01OBSv1 followed by NUL"
        || assertions.toml_kind_byte != 1
        || assertions.json_kind_byte != 2
        || assertions.raw_kind_byte != 3
        || assertions.path_encoding
            != "u32be byte length followed by repository-relative UTF-8 path bytes"
        || assertions.selector_tuple_encoding
            != "u32be selector count followed by each selector as u32be byte length and declared RFC 6901 UTF-8 bytes, preserving tuple order"
        || assertions.value_sequence
            != "one encoded value per declared selector, in selector tuple order"
        || assertions.toml_domain != "kind 0x01; recursively typed selected TOML value"
        || assertions.json_domain
            != "kind 0x02; recursively typed selected JSON value after strict duplicate-key and bounds validation"
        || assertions.raw_domain
            != "kind 0x03; selector_count exactly one; selector remains an edit location and encoded value is the exact whole source file"
        || assertions.missing_tag != "0x00"
        || assertions.json_null_tag != "0x01"
        || assertions.boolean_tag != "0x02 followed by one byte 0 or 1"
        || assertions.toml_integer_tag != "0x03 followed by i64be"
        || assertions.toml_float_tag != "0x04 followed by f64::to_bits as u64be"
        || assertions.string_tag
            != "0x05 followed by u64be byte length and UTF-8 bytes"
        || assertions.array_tag
            != "0x06 followed by u64be element count and recursively encoded elements in order"
        || assertions.map_tag
            != "0x07 followed by u64be member count and members sorted by raw UTF-8 key bytes; each member is u32be key length, key bytes, then recursively encoded value"
        || assertions.raw_bytes_tag
            != "0x08 followed by u64be length and exact whole-file bytes"
        || assertions.toml_datetime_tag
            != "0x09 followed by u64be byte length and toml::value::Datetime::to_string UTF-8 bytes"
        || assertions.json_number_tag
            != "0x0a followed by u64be byte length and serde_json::Number::to_string UTF-8 bytes; every JSON number uses this tag"
        || assertions.hash_algorithm != "sha256"
        || assertions.digest_encoding != "64 lowercase hexadecimal characters"
        || !string_sequence_is(
            &assertions.allowed_observation_modes,
            &[
                "canonical_selected_toml",
                "canonical_selected_json",
                "raw_source_bytes",
            ],
        )
        || !string_sequence_is(
            &assertions.allowed_violation_modes,
            &["exact_observation_sha256"],
        )
        || !assertions.swap_assertion_secondary_selector_required
        || !assertions.swap_assertion_secondary_selector_must_equal_recipe
        || !assertions.non_swap_assertion_secondary_selector_forbidden
        || assertions.single_selector_count != 1
        || assertions.swap_selector_count != 2
        || assertions.pointer_overlap
            != "same source path and either decoded selector component tuple is a prefix of the other; raw_source_bytes overlaps every assertion on the same source"
        || assertions.baseline_preservation_scope != "only pointer-disjoint assertions"
        || assertions.observation_identity
            != "source_path, observation_mode, and ordered selector tuple; selector tuple is [selector] for non-swap and [selector, secondary_selector] for swap"
        || assertions.overlapping_non_target_rule
            != "an assertion triggers only by matching its own violating_observation_sha256; an observation may match another assertion's violation digest only when source_path, observation_mode, selector, and secondary_selector are identical; different observation identities must never match"
        || assertions.default_expected_trigger_count != 1
        || !assertions.default_allowed_cotrigger_ids.is_empty()
        || !assertions.default_suppressed_ids.is_empty()
        || assertions.finding_precedence
            != "the actual assertion-ID set is globally unique; the case.validator primary assertion is required exactly once and is classified first, actually observed allowed_cotrigger_ids are emitted next in their declared order, actually observed suppressed_ids are recorded but not emitted next in their declared order, and any remaining, duplicate, unknown, self-referential, overlapping, or multiply classified ID is terminal Fail"
        || assertions.reference_rule
            != "every allowed_cotrigger_ids and suppressed_ids entry resolves to a different assertion ID; each array is duplicate-free and in canonical assertion declaration order; neither array contains the primary ID and the arrays are disjoint; declarations are optional allowlists and do not require the referenced assertion to fire"
        || assertions.trigger_count_rule
            != "expected_trigger_count counts emitted non-suppressed findings: exactly one required primary plus every actually observed allowed cotrigger; observed suppressed findings never increment trigger_count; each declared allowed or suppressed ID may occur at most once"
        || assertions.diagnostic_authority_rule
            != "every emitted diagnostic is rendered solely from the matched semantic_assertion fields and uses semantic_assertion.logical_path; negative_case.target_selector and removed recipe expected fields are never diagnostic authority"
        || !assertions.reject_all_length_or_count_conversion_overflow
        || !assertions.enforce_bounds_before_encoding
        || !assertions.assertion_rows_deny_unknown_fields
        || assertions.canonical_encoding
            != "ASCII FND01ASTv2 followed by NUL, then u32be row count, then canonical rows"
        || assertions.canonical_order != "ascending raw UTF-8 id bytes"
        || !string_sequence_is(
            &assertions.canonical_fields,
            &[
                "id",
                "family",
                "source_path",
                "selector",
                "secondary_selector",
                "rule",
                "logical_path",
                "baseline_mode",
                "observation_mode",
                "baseline_observation_sha256",
                "violation_mode",
                "violating_observation_sha256",
                "expected_trigger_count",
                "allowed_cotrigger_ids",
                "suppressed_ids",
            ],
        )
        || assertions.canonical_string_encoding
            != "u32be byte length followed by UTF-8 bytes"
        || assertions.canonical_optional_string_encoding
            != "one presence byte: 0x00 means absent with no following bytes; 0x01 means present followed by canonical_string_encoding; every other presence byte is invalid"
        || assertions.canonical_expected_trigger_count_encoding != "u32be"
        || assertions.canonical_allowed_cotrigger_ids_encoding
            != "u32be count followed by each canonical string in declared order"
        || assertions.canonical_suppressed_ids_encoding
            != "u32be count followed by each canonical string in declared order"
        || assertions.canonical_count != EXPECTED_NEGATIVES
        || assertions.canonical_bytes != ASSERTION_CANONICAL_BYTES
        || assertions.canonical_sha256 != ASSERTION_CANONICAL_SHA256
    {
        return Err(Diagnostic::error("E_ASSERTION_CONTRACT", &policy.policy_id));
    }
    if !string_sequence_is(
        &policy.observation_typing.allowed_kinds,
        &[
            "local_file",
            "checked_in_archive",
            "checked_in_archive_member",
            "inline_bytes",
            "remote_content_address",
            "local_cache_observation",
            "derived_receipt",
            "final_attestation",
        ],
    ) || !string_sequence_is(
        &policy.observation_typing.allowed_rehash_modes,
        &["exact_local", "archive_member", "embedded", "unavailable"],
    ) || policy.observation_typing.remote_may_claim_local_bytes
        || policy
            .observation_typing
            .local_cache_may_claim_checked_in_bytes
        || policy.observation_typing.receipt_text_substitutes_for_bytes
        || policy
            .observation_typing
            .missing_required_local_bytes_is_pass
    {
        return Err(Diagnostic::error("E_OBSERVATION_CONTRACT", &policy.policy_id));
    }
    let archive = &policy.archive_parser_contract;
    if archive.gzip_member_count != 1
        || archive.gzip_trailing_bytes_allowed
        || archive.tar_terminal_zero_block_count != 2
        || archive.tar_trailing_bytes_after_terminal_blocks_allowed
        || !string_sequence_is(&archive.allowed_tar_typeflags, &["NUL", "0"])
        || archive.path_encoding != "strict raw UTF-8"
        || !archive.reject_invalid_utf8
        || !archive.reject_absolute_path
        || !archive.reject_backslash
        || !archive.reject_drive_prefix
        || !archive.reject_unc_prefix
        || !archive.reject_colon
        || !archive.reject_empty_component
        || !archive.reject_dot_component
        || !archive.reject_dot_dot_component
        || !archive.reject_percent_encoded_separator
        || !archive.reject_duplicate_path
        || !archive.reject_ascii_case_collision
        || !archive.require_exact_root_name_version
        || !archive.check_header_checksum
        || !archive.check_all_integer_conversions
        || !archive.check_all_offset_and_size_additions
        || archive.filesystem_canonicalize_allowed
        || archive.filesystem_follow_allowed
        || archive.member_tree_record_encoding
            != "u32be(path_len) || path || u64be(file_len) || raw_sha256(member_bytes)"
    {
        return Err(Diagnostic::error("E_ARCHIVE_CONTRACT", &policy.policy_id));
    }
    validate_schema_registries(policy)?;
    validate_receipt_matrix(policy)?;
    let receipt = &policy.receipt_contract;
    if receipt.format_literal != "fastmcp-fnd-01-integration-receipt-v2"
        || receipt.schema_version_literal != RECEIPT_SCHEMA_VERSION
        || receipt.toml_receipt_count != EXPECTED_RECEIPT_TOMLS
        || receipt.binary_output_count != EXPECTED_RECEIPT_BINARIES
        || receipt.schema_dispatch
            != "exact kind to exactly one receipt_schema row; no default, flatten, alias, compatibility version, unknown table, or historical model"
        || receipt.schema_registry_encoding.is_empty()
        || receipt.schema_registry_count != EXPECTED_RECEIPT_TOMLS
        || receipt.schema_registry_bytes == 0
        || u64::try_from(receipt.schema_registry_bytes).unwrap_or(u64::MAX)
            > policy.bounds.max_receipt_schema_registry_bytes
        || receipt.schema_registry_sha256.len() != 64
        || receipt.schema_registry_bound_rule.is_empty()
        || receipt.schema_registry_verifier_authority_rule.is_empty()
        || !string_sequence_is(
            &receipt.common_required_fields,
            &[
                "format",
                "schema_version",
                "receipt_id",
                "kind",
                "path",
                "generation_rank",
                "producer_bead",
                "producer_role",
                "run_id",
                "authoring_closure_sha256",
                "policy",
                "verifier",
                "harness",
                "source_tree_file_count",
                "source_tree_total_bytes",
                "source_tree_sha256",
                "evidence_verdict",
                "support_claim",
                "parent_count",
                "parent",
            ],
        )
        || receipt.common_field_rule
            != "format/schema equal literals; receipt_id/kind/producer/rank/path equal derived_output; run_id equals run_identity_contract; the three authoring bindings and closure equal the external authoring marker; source-tree fields equal source_tree; evidence_verdict is exact Pass; support_claim is false; parent is an exact ordered bijection to direct parents with purpose"
        || receipt.exact_field_union_rule
            != "for every receipt_schema, the receipt top-level keys are exactly common_required_fields union one table named table_name; inside that table keys are exactly receipt_schema.exact_fields; neither list excludes, overrides, flattens, aliases, or makes optional the other"
        || receipt.binary_rule
            != "the three binary outputs have no TOML envelope or self-asserted header fields beyond their binary contracts; their child receipts and integration-index independently bind raw length/hash and parse the complete container"
        || receipt.candidate_rule
            != "candidate disposition is carried only by typed projection results and never substitutes for evidence_verdict: a rejected or unsupported candidate still requires Pass evidence for every applicable command, graph, policy, and mutation observation"
        || receipt.digest_rule
            != "every record-set digest uses ASCII FND01RECv2 followed by NUL, u32be record count, then for each canonical record u32be encoded-record length and the recursively tagged exact record bytes; receipt schema names the record type and no raw TOML reserialization is hashed"
        || !receipt.support_claim_must_be_false
    {
        return Err(Diagnostic::error("E_RECEIPT_CONTRACT", &policy.policy_id));
    }
    validate_sha256(
        &receipt.schema_registry_sha256,
        "receipt schema registry SHA-256",
    )?;
    let parent = &policy.parent_contract;
    if parent.edge_count != EXPECTED_DIRECT_PARENT_EDGES
        || !string_sequence_is(
            &parent.parent_binding_exact_fields,
            &["id", "path", "kind", "byte_length", "sha256", "purpose"],
        )
        || parent.parent_order != "ascending raw UTF-8 parent id bytes"
        || parent.edge_semantics
            != "each derived_output.required_parent_ids row is an exact semantic direct-input set: the child parser consumes or validates the named parent bytes for the row's declared parent_purposes and records a checked length/hash binding; the graph is neither a transitive closure nor a mathematical transitive reduction"
        || parent.no_implicit_edges_rule
            != "generation rank, command order, common authoring/source fields, integration-index membership, and a transitive ancestor do not create an edge; every one of the 42 edges must appear once in its child receipt with the exact per-parent purpose, while an unlisted, duplicated, reordered, omitted, or closure-expanded parent fails"
        || parent.binary_parent_rule
            != "binary parents are parsed under their named container contract in addition to raw length/hash binding; a receipt digest or prose assertion cannot substitute for binary bytes"
        || parent.binary_sidecar_rule
            != "because binary outputs have no TOML common envelope, supply-receipt carries supply-bundle's own output binding plus exact two parent bindings/purposes, command-results carries command-streams' output binding plus exact three parent bindings/purposes, and package-receipt carries package-artifacts' output binding plus exact three parent bindings/purposes; integration-index independently repeats all eight binary-child edges"
        || parent.package_edge_construction_rule
            != "package-artifacts is constructed only from the nine exact package.a/package.b scratch archive objects and the typed command/dependency/workspace parent records; it does not open source-snapshot or a source tree. package-receipt compares Cargo.toml.orig only to the canonical manifest byte binding carried inside workspace-receipt.manifest, so its existing workspace-receipt parent is the direct source of that digest and no hidden source-snapshot read adds an edge"
        || parent.rank_rule
            != "ranks constrain publication dependency order only and do not schedule commands; commands remain serialized under bootstrap_rch_contract"
        || parent.member_rank_counts_1_through_11.as_slice()
            != [1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1]
        || parent.member_rank_count_sum != EXPECTED_RECEIPTS - 1
        || parent.integration_index_rank != 12
        || parent.all_output_rank_counts_1_through_12.as_slice()
            != [1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1]
        || parent.all_output_rank_count_sum != EXPECTED_RECEIPTS
        || parent.non_index_max_parent_count != 4
        || parent.index_parent_count != EXPECTED_RECEIPTS - 1
    {
        return Err(Diagnostic::error("E_PARENT_CONTRACT", &policy.policy_id));
    }
    let final_attestation = &policy.final_attestation_contract;
    if final_attestation.format != "fastmcp-fnd-01-final-attestation-v2"
        || final_attestation.schema_version != RECEIPT_SCHEMA_VERSION
        || final_attestation.attestation_id_literal != "FND-01/final-attestation"
        || final_attestation.path != policy.paths.final_attestation_path
        || final_attestation.role != "independent-attester"
        || !string_sequence_is(
            &final_attestation.exact_fields,
            &[
                "format",
                "schema_version",
                "attestation_id",
                "attester_bead",
                "attester_role",
                "run_id",
                "authoring_closure_sha256",
                "integration_seal_sha256",
                "producer_outer_transport",
                "policy",
                "verifier",
                "harness",
                "workspace_snapshot",
                "integration_index",
                "returned_gate_executable",
                "attester_bootstrap_control_build",
                "attester_bootstrap_exec_entry",
                "output_count",
                "output",
                "producer_command_count",
                "attester_command_count",
                "attester_excluded_command_ids",
                "attester_command_set_sha256",
                "producer_streams_sha256",
                "producer_lock_set_sha256",
                "attester_lock_set_sha256",
                "locks_byte_equal",
                "rerun_semantic_set_sha256",
                "verdict",
                "support_claim",
                "pending_count",
                "pending",
            ],
        )
        || [
            &final_attestation.entry_rule,
            &final_attestation.output_rule,
            &final_attestation.rerun_rule,
            &final_attestation.return_rule,
            &final_attestation.self_exclusion_rule,
            &final_attestation.verdict_rule,
            &final_attestation.claim_ceiling,
        ]
        .iter()
        .any(|rule| rule.is_empty())
    {
        return Err(Diagnostic::error(
            "E_ATTESTATION_CONTRACT",
            &policy.policy_id,
        ));
    }
    let pending = &policy.pending_contract;
    if !string_sequence_is(&pending.verdicts, &["Pass", "Pending", "Fail"])
        || pending.gate_prefix != "E_PENDING_GATE:FND01:"
        || !string_sequence_is(
            &pending.authoring_allowed_pending,
            &[
                "E_PENDING_GATE:FND01:AUTHORING_CLOSURE",
                "E_PENDING_GATE:FND01:INTEGRATION_OUTPUTS",
                "E_PENDING_GATE:FND01:INTEGRATION_SEAL",
                "E_PENDING_GATE:FND01:FINAL_ATTESTATION",
                "E_PENDING_GATE:FND01:FINAL_GATE_SEAL",
            ],
        )
        || !string_sequence_is(
            &pending.post_authoring_allowed_pending,
            &[
                "E_PENDING_GATE:FND01:INTEGRATION_OUTPUTS",
                "E_PENDING_GATE:FND01:INTEGRATION_SEAL",
                "E_PENDING_GATE:FND01:FINAL_ATTESTATION",
                "E_PENDING_GATE:FND01:FINAL_GATE_SEAL",
            ],
        )
        || !string_sequence_is(
            &pending.post_publication_allowed_pending,
            &[
                "E_PENDING_GATE:FND01:INTEGRATION_SEAL",
                "E_PENDING_GATE:FND01:FINAL_ATTESTATION",
                "E_PENDING_GATE:FND01:FINAL_GATE_SEAL",
            ],
        )
        || !string_sequence_is(
            &pending.post_seal_allowed_pending,
            &[
                "E_PENDING_GATE:FND01:FINAL_ATTESTATION",
                "E_PENDING_GATE:FND01:FINAL_GATE_SEAL",
            ],
        )
        || !string_sequence_is(
            &pending.post_attestation_allowed_pending,
            &["E_PENDING_GATE:FND01:FINAL_GATE_SEAL"],
        )
        || !pending.final_allowed_pending.is_empty()
        || pending.missing_frozen_source_is_pending
        || pending.missing_required_current_phase_output_is_pending
        || pending.present_invalid_output_is_pending
        || pending.extra_output_is_pending
        || pending.failed_or_skipped_command_is_pending
        || pending.rule
            != "Pending describes only a not-yet-entered later role boundary explicitly listed for the current phase; once a phase begins, its missing/invalid/extra output, marker, command, or receipt is Fail and cannot be relabeled Pending"
    {
        return Err(Diagnostic::error("E_PENDING_CONTRACT", &policy.policy_id));
    }
    let nonpromotion = &policy.nonpromotion_contract;
    if nonpromotion.aggregate_support_claimed
        || !nonpromotion.all_receipt_support_claims_false
        || !string_sequence_is(
            &nonpromotion.resolver_domain,
            &["2", "3", "not-applicable"],
        )
        || nonpromotion.canonical_resolver != "3"
        || !nonpromotion.resolver2_is_comparison_only
        || !nonpromotion.resolver2_to_3_delta_required
        || !string_sequence_is(
            &nonpromotion.candidate_dispositions,
            &[
                "baseline-observation",
                "selected-isolated-candidate",
                "rejected-candidate",
                "unsupported-candidate",
                "quarantined",
            ],
        )
        || nonpromotion.candidate_evidence_rule
            != "every projection_result evidence_verdict is Pass independently of candidate_disposition; rejected, unsupported, and quarantined are candidate policy classifications, never evidence failures and never permission to omit an applicable command"
        || !string_sequence_is(
            &nonpromotion.fixed_candidates,
            &[
                "asupersync-0.3.10-rejected=rejected-candidate",
                "media-html5ever=unsupported-candidate",
                "media-image=unsupported-candidate",
                "media-resvg=unsupported-candidate",
                "state-redis=unsupported-candidate",
            ],
        )
        || nonpromotion.jose_scope
            != "bounded public RS256 verification on x86_64-unknown-linux-gnu only"
        || nonpromotion.sdk_scope != "frozen local interoperability-peer metadata only"
        || !string_sequence_is(
            &nonpromotion.excluded_work,
            &[
                "Section 25.10 release-profile feature cells",
                "Section 25.10 pairwise feature matrix",
                "Tasks macros",
                "Apps runtime",
                "Redis Tasks runtime",
                "safe media rendering runtime",
            ],
        )
    {
        return Err(Diagnostic::error("E_NONPROMOTION_CONTRACT", &policy.policy_id));
    }
    let projection_dispositions = [
        "baseline-observation",
        "baseline-observation",
        "selected-isolated-candidate",
        "rejected-candidate",
        "selected-isolated-candidate",
        "selected-isolated-candidate",
        "selected-isolated-candidate",
        "unsupported-candidate",
        "unsupported-candidate",
        "unsupported-candidate",
        "selected-isolated-candidate",
        "selected-isolated-candidate",
        "unsupported-candidate",
    ];
    let projection_dependency_counts = [1, 1, 1, 1, 5, 1, 2, 1, 1, 1, 1, 2, 1];
    if policy.projection.len() != EXPECTED_PROJECTIONS {
        return Err(Diagnostic::error("E_PROJECTION_COUNT", "projection"));
    }
    for (((projection, expected_id), expected_disposition), expected_dependency_count) in policy
        .projection
        .iter()
        .zip(PROJECTIONS.iter().copied())
        .zip(projection_dispositions)
        .zip(projection_dependency_counts)
    {
        if projection.id != expected_id
            || projection.disposition != expected_disposition
            || projection.evidence_verdict != "Pass"
            || projection.support_claim
            || projection.dependency_count != expected_dependency_count
            || projection.probe_sentinel != format!("FND01_PROBE|{expected_id}|OK")
        {
            return Err(Diagnostic::error("E_PROJECTION_CONTRACT", &projection.id));
        }
    }
    Ok(())
}

fn collect_tree_files(
    root: &Path,
    relative: &str,
    excluded_exact_paths: &BTreeSet<String>,
    excluded_exact_directory: &str,
    expected_files: &BTreeSet<String>,
    output: &mut BTreeSet<String>,
    maximum_files: usize,
) -> VResult<()> {
    validate_ascii_posix_path(relative, "inventory root")?;
    let directory = resolve_safe(root, relative, "inventory root")?;
    let metadata = fs::symlink_metadata(&directory)
        .map_err(|_| Diagnostic::error("E_FILE_MISSING", relative))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Diagnostic::error("E_FILE_TYPE", relative).at("directory required"));
    }
    let entries = fs::read_dir(&directory)
        .map_err(|_| Diagnostic::error("E_FILE_READ", relative).at("read_dir"))?;
    for entry in entries {
        let entry = entry.map_err(|_| Diagnostic::error("E_FILE_READ", relative))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| Diagnostic::error("E_PATH_INVALID", relative).at("non-UTF-8 name"))?;
        let child = format!("{relative}/{name}");
        validate_ascii_posix_path(&child, "inventory member")?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|_| Diagnostic::error("E_PATH_METADATA", &child))?;
        if metadata.file_type().is_symlink() {
            return Err(Diagnostic::error("E_PATH_SYMLINK", &child));
        }
        if excluded_exact_paths.contains(&child) {
            continue;
        }
        if child == excluded_exact_directory {
            if !metadata.is_dir() {
                return Err(Diagnostic::error("E_SOURCE_EXCLUSION_TYPE", &child)
                    .at("excluded boundary must be a directory"));
            }
            continue;
        }
        if metadata.is_dir() {
            let prefix = format!("{child}/");
            if !expected_files
                .iter()
                .any(|expected| expected.starts_with(&prefix))
            {
                return Err(Diagnostic::error("E_SOURCE_EXTRA_DIRECTORY", &child));
            }
            collect_tree_files(
                root,
                &child,
                excluded_exact_paths,
                excluded_exact_directory,
                expected_files,
                output,
                maximum_files,
            )?;
        } else if metadata.is_file() {
            #[cfg(unix)]
            if metadata.nlink() != 1 {
                return Err(Diagnostic::error("E_FILE_HARDLINK", &child)
                    .at(format!("link_count={}", metadata.nlink())));
            }
            #[cfg(windows)]
            if metadata.number_of_links() != 1 {
                return Err(Diagnostic::error("E_FILE_HARDLINK", &child)
                    .at(format!("link_count={}", metadata.number_of_links())));
            }
            if !output.insert(child.clone()) {
                return Err(Diagnostic::error("E_INVENTORY_DUPLICATE", &child));
            }
            if output.len() > maximum_files {
                return Err(Diagnostic::error("E_INVENTORY_BOUND", relative));
            }
        } else {
            return Err(Diagnostic::error("E_FILE_TYPE", &child));
        }
    }
    Ok(())
}

fn validate_case_unique(values: impl IntoIterator<Item = String>, subject: &str) -> VResult<()> {
    let mut exact = BTreeSet::new();
    let mut folded = BTreeMap::<String, String>::new();
    for value in values {
        if !exact.insert(value.clone()) {
            return Err(Diagnostic::error("E_INVENTORY_DUPLICATE", subject).at(value));
        }
        let lower = value.to_ascii_lowercase();
        if let Some(previous) = folded.insert(lower, value.clone()) {
            return Err(Diagnostic::error("E_CASE_COLLISION", subject)
                .at(format!("{previous}|{value}")));
        }
    }
    Ok(())
}

fn validate_json_bounds(
    value: &StrictJson,
    depth: usize,
    nodes: &mut usize,
    subject: &str,
) -> VResult<()> {
    if depth > 128 {
        return Err(Diagnostic::error("E_JSON_BOUND", subject).at("depth"));
    }
    *nodes = nodes
        .checked_add(1)
        .ok_or_else(|| Diagnostic::error("E_JSON_BOUND", subject).at("node overflow"))?;
    if *nodes > 1_048_576 {
        return Err(Diagnostic::error("E_JSON_BOUND", subject).at("nodes"));
    }
    match value {
        StrictJson::String(string) => {
            if string.len() > 1_048_576 {
                return Err(Diagnostic::error("E_JSON_BOUND", subject).at("string"));
            }
        }
        StrictJson::Array(values) => {
            for value in values {
                validate_json_bounds(value, depth + 1, nodes, subject)?;
            }
        }
        StrictJson::Object(values) => {
            for (key, value) in values {
                if key.len() > 1_048_576 {
                    return Err(Diagnostic::error("E_JSON_BOUND", subject).at("member name"));
                }
                validate_json_bounds(value, depth + 1, nodes, subject)?;
            }
        }
        StrictJson::Null | StrictJson::Bool(_) | StrictJson::Number(_) => {}
    }
    Ok(())
}

const SERDE_JSON_PRIVATE_NUMBER_KEY: &str = "$serde_json::private::Number";

struct JsonObjectKeyScanner<'a> {
    bytes: &'a [u8],
    offset: usize,
    subject: &'a str,
}

impl<'a> JsonObjectKeyScanner<'a> {
    fn new(bytes: &'a [u8], subject: &'a str) -> Self {
        Self {
            bytes,
            offset: 0,
            subject,
        }
    }

    fn error(&self, detail: &str) -> Diagnostic {
        Diagnostic::error("E_JSON_SCHEMA", self.subject).at(detail)
    }

    fn skip_json_whitespace(&mut self) {
        while matches!(
            self.bytes.get(self.offset),
            Some(b' ' | b'\t' | b'\n' | b'\r')
        ) {
            self.offset += 1;
        }
    }

    fn consume(&mut self, expected: u8) -> VResult<()> {
        if self.bytes.get(self.offset) != Some(&expected) {
            return Err(self.error("invalid JSON structure during reserved-key preflight"));
        }
        self.offset += 1;
        Ok(())
    }

    fn scan_string_token(&mut self) -> VResult<&'a [u8]> {
        let start = self.offset;
        self.consume(b'"')?;
        loop {
            let Some(byte) = self.bytes.get(self.offset).copied() else {
                return Err(self.error("unterminated JSON string"));
            };
            match byte {
                b'"' => {
                    self.offset += 1;
                    return Ok(&self.bytes[start..self.offset]);
                }
                b'\\' => {
                    self.offset += 1;
                    let Some(escape) = self.bytes.get(self.offset).copied() else {
                        return Err(self.error("unterminated JSON escape"));
                    };
                    self.offset += 1;
                    if escape == b'u' {
                        let end = self
                            .offset
                            .checked_add(4)
                            .ok_or_else(|| self.error("JSON escape length overflow"))?;
                        let digits = self
                            .bytes
                            .get(self.offset..end)
                            .ok_or_else(|| self.error("truncated JSON Unicode escape"))?;
                        if !digits.iter().all(u8::is_ascii_hexdigit) {
                            return Err(self.error("invalid JSON Unicode escape"));
                        }
                        self.offset = end;
                    }
                }
                0x00..=0x1f => {
                    return Err(self.error("unescaped control byte in JSON string"));
                }
                _ => {
                    self.offset += 1;
                }
            }
        }
    }

    fn consume_literal(&mut self, literal: &[u8]) -> VResult<()> {
        let end = self
            .offset
            .checked_add(literal.len())
            .ok_or_else(|| self.error("JSON literal length overflow"))?;
        if self.bytes.get(self.offset..end) != Some(literal) {
            return Err(self.error("invalid JSON literal"));
        }
        self.offset = end;
        Ok(())
    }

    fn scan_number_candidate(&mut self) {
        while let Some(byte) = self.bytes.get(self.offset) {
            if matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | b',' | b']' | b'}') {
                break;
            }
            self.offset += 1;
        }
    }

    fn scan_value(&mut self, depth: usize) -> VResult<()> {
        if depth > 128 {
            return Err(self.error("JSON depth exceeds reserved-key preflight bound"));
        }
        self.skip_json_whitespace();
        match self.bytes.get(self.offset).copied() {
            Some(b'{') => self.scan_object(depth),
            Some(b'[') => self.scan_array(depth),
            Some(b'"') => self.scan_string_token().map(|_| ()),
            Some(b't') => self.consume_literal(b"true"),
            Some(b'f') => self.consume_literal(b"false"),
            Some(b'n') => self.consume_literal(b"null"),
            Some(b'-' | b'0'..=b'9') => {
                self.scan_number_candidate();
                Ok(())
            }
            _ => Err(self.error("invalid JSON value during reserved-key preflight")),
        }
    }

    fn scan_object(&mut self, depth: usize) -> VResult<()> {
        self.consume(b'{')?;
        self.skip_json_whitespace();
        if self.bytes.get(self.offset) == Some(&b'}') {
            self.offset += 1;
            return Ok(());
        }
        loop {
            let key_token = self.scan_string_token()?;
            let key = serde_json::from_slice::<String>(key_token)
                .map_err(|_| self.error("invalid JSON object member name"))?;
            if key == SERDE_JSON_PRIVATE_NUMBER_KEY {
                return Err(self.error(
                    "reserved serde_json arbitrary-precision number carrier member",
                ));
            }
            self.skip_json_whitespace();
            self.consume(b':')?;
            let child_depth = depth
                .checked_add(1)
                .ok_or_else(|| self.error("JSON depth overflow"))?;
            self.scan_value(child_depth)?;
            self.skip_json_whitespace();
            match self.bytes.get(self.offset) {
                Some(b',') => {
                    self.offset += 1;
                    self.skip_json_whitespace();
                }
                Some(b'}') => {
                    self.offset += 1;
                    return Ok(());
                }
                _ => {
                    return Err(
                        self.error("invalid JSON object delimiter during reserved-key preflight")
                    );
                }
            }
        }
    }

    fn scan_array(&mut self, depth: usize) -> VResult<()> {
        self.consume(b'[')?;
        self.skip_json_whitespace();
        if self.bytes.get(self.offset) == Some(&b']') {
            self.offset += 1;
            return Ok(());
        }
        loop {
            let child_depth = depth
                .checked_add(1)
                .ok_or_else(|| self.error("JSON depth overflow"))?;
            self.scan_value(child_depth)?;
            self.skip_json_whitespace();
            match self.bytes.get(self.offset) {
                Some(b',') => {
                    self.offset += 1;
                    self.skip_json_whitespace();
                }
                Some(b']') => {
                    self.offset += 1;
                    return Ok(());
                }
                _ => {
                    return Err(
                        self.error("invalid JSON array delimiter during reserved-key preflight")
                    );
                }
            }
        }
    }

    fn reject_reserved_object_keys(mut self) -> VResult<()> {
        self.scan_value(0)?;
        Ok(())
    }
}

fn parse_strict_json(bytes: &[u8], subject: &str) -> VResult<StrictJson> {
    JsonObjectKeyScanner::new(bytes, subject).reject_reserved_object_keys()?;
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictJson::deserialize(&mut deserializer)
        .map_err(|_| Diagnostic::error("E_JSON_SCHEMA", subject))?;
    deserializer
        .end()
        .map_err(|_| Diagnostic::error("E_JSON_TRAILING", subject))?;
    let mut nodes = 0;
    validate_json_bounds(&value, 0, &mut nodes, subject)?;
    Ok(value)
}

fn validate_json(bytes: &[u8], subject: &str) -> VResult<()> {
    parse_strict_json(bytes, subject).map(|_| ())
}

fn c_string_field(field: &[u8], subject: &str) -> VResult<String> {
    let end = field.iter().position(|byte| *byte == 0).unwrap_or(field.len());
    if field[end..].iter().any(|byte| *byte != 0) {
        return Err(Diagnostic::error("E_TAR_HEADER", subject).at("embedded NUL suffix"));
    }
    let bytes = &field[..end];
    String::from_utf8(bytes.to_vec())
        .map_err(|_| Diagnostic::error("E_TAR_PATH", subject).at("non-UTF-8"))
}

fn validate_archive_path(path: &str, subject: &str) -> VResult<()> {
    let lower = path.to_ascii_lowercase();
    if path.is_empty()
        || path.len() > 240
        || path.starts_with('/')
        || path.starts_with("//")
        || path.ends_with('/')
        || path.contains('\\')
        || path.contains(':')
        || path.chars().any(char::is_control)
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(Diagnostic::error("E_TAR_PATH", subject).at(path));
    }
    let mut depth = 0usize;
    for component in path.split('/') {
        depth = depth
            .checked_add(1)
            .ok_or_else(|| Diagnostic::error("E_TAR_PATH", subject).at(path))?;
        if component.is_empty()
            || component.len() > 100
            || component == "."
            || component == ".."
        {
            return Err(Diagnostic::error("E_TAR_PATH", subject).at(path));
        }
    }
    if depth > 8 {
        return Err(Diagnostic::error("E_TAR_PATH", subject).at(path));
    }
    Ok(())
}

fn parse_tar_octal(field: &[u8], subject: &str) -> VResult<u64> {
    if field.first().is_some_and(|byte| byte & 0x80 != 0) {
        return Err(Diagnostic::error("E_TAR_HEADER", subject).at("base-256 number"));
    }
    let text = std::str::from_utf8(field)
        .map_err(|_| Diagnostic::error("E_TAR_HEADER", subject).at("numeric UTF-8"))?
        .trim_matches(|character| character == '\0' || character == ' ');
    if text.is_empty() {
        return Ok(0);
    }
    if !text.bytes().all(|byte| (b'0'..=b'7').contains(&byte)) {
        return Err(Diagnostic::error("E_TAR_HEADER", subject).at("non-octal number"));
    }
    u64::from_str_radix(text, 8)
        .map_err(|_| Diagnostic::error("E_TAR_HEADER", subject).at("octal overflow"))
}

fn validate_tar_checksum(header: &[u8], subject: &str) -> VResult<()> {
    let expected = parse_tar_octal(&header[148..156], subject)?;
    let actual = header
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                u64::from(b' ')
            } else {
                u64::from(*byte)
            }
        })
        .sum::<u64>();
    if actual != expected {
        return Err(Diagnostic::error("E_TAR_CHECKSUM", subject));
    }
    Ok(())
}

#[derive(Debug)]
struct ArchiveSummary {
    member_count: usize,
    regular_file_count: usize,
    expanded_bytes: u64,
    member_tree_sha256: [u8; 32],
    root: String,
}

fn validate_gzip_tar(
    bytes: &[u8],
    bounds: &ArchiveBounds,
    subject: &str,
    expected_root: Option<&str>,
) -> VResult<ArchiveSummary> {
    let compressed_length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if compressed_length > bounds.max_archive_compressed_bytes {
        return Err(Diagnostic::error("E_ARCHIVE_BOUND", subject).at("compressed bytes"));
    }
    if bytes.len() < 18 || !bytes.starts_with(&[0x1f, 0x8b, 0x08]) {
        return Err(Diagnostic::error("E_GZIP_HEADER", subject));
    }
    if bytes[3] & 0xe0 != 0 {
        return Err(Diagnostic::error("E_GZIP_HEADER", subject).at("reserved flags"));
    }
    let mut decoder = GzDecoder::new(bytes);
    let mut expanded = Vec::new();
    decoder
        .by_ref()
        .take(bounds.max_archive_expanded_bytes.saturating_add(1))
        .read_to_end(&mut expanded)
        .map_err(|_| Diagnostic::error("E_GZIP_STREAM", subject))?;
    if u64::try_from(expanded.len()).unwrap_or(u64::MAX)
        > bounds.max_archive_expanded_bytes
    {
        return Err(Diagnostic::error("E_ARCHIVE_BOUND", subject).at("expanded bytes"));
    }
    let remaining = decoder.into_inner();
    if !remaining.is_empty() {
        return Err(Diagnostic::error("E_GZIP_TRAILING", subject)
            .at(format!("trailing_bytes={}", remaining.len())));
    }

    let mut offset = 0usize;
    let mut records = Vec::<(String, u64, [u8; 32])>::new();
    let mut total_member_bytes = 0u64;
    let mut saw_exact_terminal = false;
    while offset < expanded.len() {
        let header_end = offset
            .checked_add(512)
            .ok_or_else(|| Diagnostic::error("E_TAR_BOUND", subject))?;
        if header_end > expanded.len() {
            return Err(Diagnostic::error("E_TAR_TRUNCATED", subject).at("header"));
        }
        let header = &expanded[offset..header_end];
        offset = header_end;
        if header.iter().all(|byte| *byte == 0) {
            let second_end = offset
                .checked_add(512)
                .ok_or_else(|| Diagnostic::error("E_TAR_BOUND", subject))?;
            if second_end > expanded.len() {
                return Err(Diagnostic::error("E_TAR_TERMINATOR", subject)
                    .at("lone terminal zero block"));
            }
            if expanded[offset..second_end].iter().any(|byte| *byte != 0) {
                return Err(Diagnostic::error("E_TAR_TERMINATOR", subject)
                    .at("second terminal block is not zero"));
            }
            offset = second_end;
            if offset != expanded.len() {
                return Err(Diagnostic::error("E_TAR_TRAILING", subject)
                    .at((expanded.len() - offset).to_string()));
            }
            saw_exact_terminal = true;
            break;
        }
        validate_tar_checksum(header, subject)?;
        for field in [
            &header[100..108],
            &header[108..116],
            &header[116..124],
            &header[136..148],
            &header[329..337],
            &header[337..345],
        ] {
            parse_tar_octal(field, subject)?;
        }
        if records.len() >= bounds.max_archive_member_count {
            return Err(Diagnostic::error("E_ARCHIVE_BOUND", subject).at("entries"));
        }
        let name = c_string_field(&header[0..100], subject)?;
        let prefix = c_string_field(&header[345..500], subject)?;
        if !c_string_field(&header[157..257], subject)?.is_empty() {
            return Err(Diagnostic::error("E_TAR_HEADER", subject)
                .at("regular entry linkname must be empty"));
        }
        let path = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        validate_archive_path(&path, subject)?;
        let size = parse_tar_octal(&header[124..136], subject)?;
        if size > bounds.max_archive_member_bytes {
            return Err(Diagnostic::error("E_ARCHIVE_BOUND", subject).at(&path));
        }
        let kind = header[156];
        if !matches!(kind, 0 | b'0') {
            return Err(Diagnostic::error("E_TAR_ENTRY_TYPE", subject)
                .at(format!("type byte {kind}")));
        }
        let content_length = usize::try_from(size)
            .map_err(|_| Diagnostic::error("E_TAR_BOUND", subject).at(&path))?;
        let content_end = offset
            .checked_add(content_length)
            .ok_or_else(|| Diagnostic::error("E_TAR_BOUND", subject).at(&path))?;
        if content_end > expanded.len() {
            return Err(Diagnostic::error("E_TAR_TRUNCATED", subject).at(&path));
        }
        let digest = sha256(&expanded[offset..content_end]);
        total_member_bytes = total_member_bytes
            .checked_add(size)
            .ok_or_else(|| Diagnostic::error("E_ARCHIVE_BOUND", subject).at("member byte sum"))?;
        if total_member_bytes > bounds.max_archive_expanded_bytes {
            return Err(Diagnostic::error("E_ARCHIVE_BOUND", subject).at("member byte sum"));
        }
        records.push((path, size, digest));
        let padded = size
            .checked_add(511)
            .and_then(|value| value.checked_div(512))
            .and_then(|blocks| blocks.checked_mul(512))
            .ok_or_else(|| Diagnostic::error("E_TAR_BOUND", subject))?;
        let padded = usize::try_from(padded)
            .map_err(|_| Diagnostic::error("E_TAR_BOUND", subject))?;
        let padded_end = offset
            .checked_add(padded)
            .ok_or_else(|| Diagnostic::error("E_TAR_BOUND", subject))?;
        if padded_end > expanded.len() {
            return Err(Diagnostic::error("E_TAR_TRUNCATED", subject).at("payload padding"));
        }
        if expanded[content_end..padded_end]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(Diagnostic::error("E_TAR_PADDING", subject));
        }
        offset = padded_end;
    }
    if offset != expanded.len() || records.is_empty() || !saw_exact_terminal {
        return Err(Diagnostic::error("E_TAR_TERMINATOR", subject));
    }
    validate_case_unique(
        records.iter().map(|(path, _, _)| path.clone()),
        subject,
    )?;
    let mut roots = records
        .iter()
        .filter_map(|(path, _, _)| path.split('/').next())
        .collect::<BTreeSet<_>>();
    if roots.len() != 1 {
        return Err(Diagnostic::error("E_TAR_ROOT", subject));
    }
    let root = roots
        .pop_first()
        .ok_or_else(|| Diagnostic::error("E_TAR_ROOT", subject))?
        .to_owned();
    if let Some(expected) = expected_root {
        if expected != root {
            return Err(Diagnostic::error("E_TAR_ROOT", subject)
                .at(format!("expected={expected};actual={root}")));
        }
    }
    let required_prefix = format!("{root}/");
    if records
        .iter()
        .any(|(path, _, _)| !path.starts_with(&required_prefix))
    {
        return Err(Diagnostic::error("E_TAR_ROOT", subject)
            .at("every member must be inside the exact root"));
    }
    records.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    let mut member_tree = Sha256::new();
    for (path, size, digest) in &records {
        let path_length = u32::try_from(path.len())
            .map_err(|_| Diagnostic::error("E_TAR_BOUND", subject).at(path))?;
        member_tree.update(path_length.to_be_bytes());
        member_tree.update(path.as_bytes());
        member_tree.update(size.to_be_bytes());
        member_tree.update(digest);
    }
    Ok(ArchiveSummary {
        member_count: records.len(),
        regular_file_count: records.len(),
        expanded_bytes: total_member_bytes,
        member_tree_sha256: member_tree.finalize().into(),
        root,
    })
}

fn validate_family(file: &LoadedFile, policy: &Policy) -> VResult<()> {
    let subject = file.contract.path.as_str();
    match file.contract.parse_kind {
        FileFamily::Toml => {
            if u64::try_from(file.bytes.len()).unwrap_or(u64::MAX)
                > policy.bounds.max_source_file_bytes
            {
                return Err(Diagnostic::error("E_TOML_BOUND", subject));
            }
            let text = std::str::from_utf8(&file.bytes)
                .map_err(|_| Diagnostic::error("E_UTF8", subject))?;
            text.parse::<toml::Table>()
                .map_err(|_| Diagnostic::error("E_TOML_SYNTAX", subject))?;
            Ok(())
        }
        FileFamily::Json => validate_json(&file.bytes, subject),
        FileFamily::Utf8Text => {
            let text = std::str::from_utf8(&file.bytes)
                .map_err(|_| Diagnostic::error("E_UTF8", subject))?;
            if text.contains('\0') {
                return Err(Diagnostic::error("E_UTF8_NUL", subject));
            }
            Ok(())
        }
        FileFamily::OpaqueBinary => Ok(()),
        FileFamily::GzipTar => {
            let contract = policy
                .archive_contract
                .iter()
                .find(|contract| contract.path == file.contract.path)
                .ok_or_else(|| Diagnostic::error("E_ARCHIVE_CONTRACT", subject))?;
            if !string_sequence_is(&contract.allowed_entry_types, &["regular"]) {
                return Err(Diagnostic::error("E_ARCHIVE_CONTRACT", subject)
                    .at("entry types"));
            }
            let summary = validate_gzip_tar(
                &file.bytes,
                &policy.bounds.archive_bounds(),
                subject,
                Some(&contract.expected_root),
            )?;
            validate_sha256(&contract.member_tree_sha256, subject)?;
            if summary.member_count != contract.member_count
                || summary.regular_file_count != contract.regular_file_count
                || summary.expanded_bytes != contract.expanded_bytes
                || lower_hex(&summary.member_tree_sha256) != contract.member_tree_sha256
                || summary.root != contract.expected_root
            {
                return Err(Diagnostic::error("E_ARCHIVE_INVENTORY", subject).at(format!(
                    "members={};regular={};bytes={};tree={}",
                    summary.member_count,
                    summary.regular_file_count,
                    summary.expanded_bytes,
                    lower_hex(&summary.member_tree_sha256)
                )));
            }
            Ok(())
        }
    }
}

fn load_sources(root: &Path, policy: &Policy) -> VResult<Vec<LoadedFile>> {
    if policy.source_input.len() != EXPECTED_SOURCE_FILES {
        return Err(Diagnostic::error("E_SOURCE_COUNT", "source_input")
            .at(policy.source_input.len().to_string()));
    }
    validate_case_unique(
        policy
            .source_input
            .iter()
            .map(|contract| contract.path.clone()),
        "source paths",
    )?;
    validate_case_unique(
        policy
            .source_input
            .iter()
            .map(|contract| contract.id.clone()),
        "source IDs",
    )?;
    for (index, contract) in policy.source_input.iter().enumerate() {
        let expected_id = format!("s{:02}", index + 1);
        if contract.id != expected_id {
            return Err(Diagnostic::error("E_SOURCE_ID", &contract.id).at(expected_id));
        }
    }
    let expected = policy
        .source_input
        .iter()
        .map(|contract| contract.path.clone())
        .collect::<BTreeSet<_>>();
    let excluded = policy
        .source_tree
        .excluded_exact_paths
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    validate_case_unique(excluded.iter().cloned(), "source tree exclusions")?;
    let mut actual = BTreeSet::new();
    collect_tree_files(
        root,
        &policy.paths.source_root,
        &excluded,
        &policy.source_tree.excluded_exact_directory,
        &expected,
        &mut actual,
        policy.bounds.exact_source_input_count,
    )?;
    if actual != expected {
        let missing = expected.difference(&actual).cloned().collect::<Vec<_>>();
        let extra = actual.difference(&expected).cloned().collect::<Vec<_>>();
        return Err(Diagnostic::error("E_SOURCE_EXACT_SET", "source inventory")
            .at(format!("missing={missing:?};extra={extra:?}")));
    }
    let mut total = 0u64;
    let family_contracts = policy
        .source_family
        .iter()
        .map(|family| (family.id.as_str(), family))
        .collect::<BTreeMap<_, _>>();
    if family_contracts.len() != SOURCE_FAMILIES.len()
        || policy.source_family.len() != SOURCE_FAMILIES.len()
    {
        return Err(Diagnostic::error("E_SOURCE_FAMILY_COUNT", "source_family")
            .at(family_contracts.len().to_string()));
    }
    for (actual, expected) in policy.source_family.iter().zip(SOURCE_FAMILIES) {
        if actual.id != expected.0
            || actual.owner_bead != expected.1
            || actual.file_count != expected.2
            || actual.total_bytes != expected.3
            || actual.tree_sha256 != expected.4
        {
            return Err(Diagnostic::error("E_SOURCE_FAMILY_CONTRACT", &actual.id));
        }
    }
    let archive_paths = policy
        .archive_contract
        .iter()
        .map(|contract| contract.path.clone())
        .collect::<Vec<_>>();
    if archive_paths.len() != SOURCE_ARCHIVES.len()
        || policy.archive_contract.len() != SOURCE_ARCHIVES.len()
    {
        return Err(Diagnostic::error("E_ARCHIVE_CONTRACT", "archive_contract")
            .at(archive_paths.len().to_string()));
    }
    validate_case_unique(archive_paths, "archive contracts")?;
    for (actual, expected) in policy.archive_contract.iter().zip(SOURCE_ARCHIVES) {
        if actual.id != expected.0
            || actual.path != expected.1
            || actual.expected_root != expected.2
            || actual.member_count != expected.3
            || actual.regular_file_count != expected.3
            || actual.expanded_bytes != expected.4
            || actual.member_tree_sha256 != expected.5
            || !string_sequence_is(&actual.allowed_entry_types, &["regular"])
        {
            return Err(Diagnostic::error("E_ARCHIVE_CONTRACT", &actual.id));
        }
    }

    let mut loaded = Vec::with_capacity(policy.source_input.len());
    for contract in &policy.source_input {
        validate_ascii_posix_path(&contract.path, "source path")?;
        validate_sha256(&contract.sha256, &contract.path)?;
        let family = family_contracts
            .get(contract.family.as_str())
            .ok_or_else(|| Diagnostic::error("E_SOURCE_FAMILY", &contract.path))?;
        if contract.owner_bead != family.owner_bead
            || !contract.required
            || !contract.source_tree_member
            || !contract.bytes_available
            || contract.rehash_mode != "exact_local"
            || contract.claim_ceiling != "local-byte-proof"
        {
            return Err(Diagnostic::error("E_SOURCE_CONTRACT", &contract.path));
        }
        match contract.observation_kind {
            ObservationKind::CheckedInArchive => {
                if contract.parse_kind != FileFamily::GzipTar {
                    return Err(Diagnostic::error("E_OBSERVATION_CONTRACT", &contract.path));
                }
            }
            ObservationKind::LocalFile => {
                if contract.parse_kind == FileFamily::GzipTar {
                    return Err(Diagnostic::error("E_OBSERVATION_CONTRACT", &contract.path));
                }
            }
            ObservationKind::CheckedInArchiveMember
            | ObservationKind::InlineBytes
            | ObservationKind::RemoteContentAddress
            | ObservationKind::LocalCacheObservation
            | ObservationKind::DerivedReceipt
            | ObservationKind::FinalAttestation => {
                return Err(Diagnostic::error("E_OBSERVATION_CONTRACT", &contract.path));
            }
        }
        let path = resolve_safe(root, &contract.path, &contract.path)?;
        let bytes = read_bounded(&path, policy.bounds.max_source_file_bytes, &contract.path)?;
        let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        total = total
            .checked_add(length)
            .ok_or_else(|| Diagnostic::error("E_SOURCE_TOTAL_BOUND", "source inventory"))?;
        if total > policy.source_input_total_bytes {
            return Err(Diagnostic::error("E_SOURCE_TOTAL_BOUND", "source inventory"));
        }
        if length != contract.byte_length {
            return Err(Diagnostic::error("E_LENGTH_MISMATCH", &contract.path)
                .at(format!("expected={};actual={length}", contract.byte_length)));
        }
        let digest = sha256(&bytes);
        if lower_hex(&digest) != contract.sha256 {
            return Err(Diagnostic::error("E_SHA256_MISMATCH", &contract.path));
        }
        let file = LoadedFile {
            contract: contract.clone(),
            bytes,
            digest,
        };
        validate_family(&file, policy)?;
        loaded.push(file);
    }
    if total != policy.source_input_total_bytes {
        return Err(Diagnostic::error("E_SOURCE_TOTAL", "source inventory")
            .at(format!("expected={};actual={total}", policy.source_input_total_bytes)));
    }
    let mut parse_counts = BTreeMap::<FileFamily, usize>::new();
    for file in &loaded {
        *parse_counts.entry(file.contract.parse_kind).or_default() += 1;
    }
    let expected_parse_counts = BTreeMap::from([
        (FileFamily::Toml, policy.parse_inventory.toml),
        (FileFamily::Json, policy.parse_inventory.json),
        (FileFamily::Utf8Text, policy.parse_inventory.utf8_text),
        (FileFamily::OpaqueBinary, policy.parse_inventory.opaque_binary),
        (FileFamily::GzipTar, policy.parse_inventory.gzip_tar),
    ]);
    if parse_counts != expected_parse_counts {
        return Err(Diagnostic::error("E_PARSE_INVENTORY", "source inputs"));
    }
    for family in &policy.source_family {
        validate_sha256(&family.tree_sha256, &family.id)?;
        let family_files = loaded
            .iter()
            .filter(|file| file.contract.family == family.id)
            .collect::<Vec<_>>();
        let (digest, bytes) = source_tree_digest_refs(&family_files)?;
        if family_files.len() != family.file_count
            || bytes != family.total_bytes
            || lower_hex(&digest) != family.tree_sha256
        {
            return Err(Diagnostic::error("E_SOURCE_FAMILY_TREE", &family.id).at(format!(
                "files={};bytes={bytes};sha256={}",
                family_files.len(),
                lower_hex(&digest)
            )));
        }
    }
    Ok(loaded)
}

fn source_tree_digest_refs(files: &[&LoadedFile]) -> VResult<([u8; 32], u64)> {
    let mut ordered = files.to_vec();
    ordered.sort_by(|left, right| left.contract.path.cmp(&right.contract.path));
    let mut hasher = Sha256::new();
    let mut bytes = 0u64;
    for file in ordered {
        let path = file.contract.path.as_bytes();
        let path_length = u32::try_from(path.len())
            .map_err(|_| Diagnostic::error("E_TREE_BOUND", &file.contract.path))?;
        hasher.update(path_length.to_be_bytes());
        hasher.update(path);
        hasher.update(file.contract.byte_length.to_be_bytes());
        hasher.update(file.digest);
        bytes = bytes
            .checked_add(file.contract.byte_length)
            .ok_or_else(|| Diagnostic::error("E_TREE_BOUND", "source tree bytes"))?;
    }
    Ok((hasher.finalize().into(), bytes))
}

fn validate_source_tree(files: &[LoadedFile], policy: &Policy) -> VResult<[u8; 32]> {
    let references = files.iter().collect::<Vec<_>>();
    let (digest, bytes) = source_tree_digest_refs(&references)?;
    if files.len() != policy.source_tree.file_count
        || bytes != policy.source_tree.total_bytes
        || lower_hex(&digest) != policy.source_tree.sha256
    {
        return Err(Diagnostic::error("E_TREE_DIGEST_MISMATCH", "FND-01 source tree")
            .at(format!("bytes={bytes};sha256={}", lower_hex(&digest))));
    }
    Ok(digest)
}

fn extract_array_table_ids(bytes: &[u8], table: &str, subject: &str) -> VResult<Vec<String>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Diagnostic::error("E_UTF8", subject))?;
    let document = text
        .parse::<toml::Value>()
        .map_err(|_| Diagnostic::error("E_TOML_SYNTAX", subject))?;
    let rows = document
        .as_table()
        .and_then(|root| root.get(table))
        .and_then(toml::Value::as_array)
        .ok_or_else(|| Diagnostic::error("E_NEGATIVE_ROW", subject).at(table))?;
    let mut ids = Vec::with_capacity(rows.len());
    for (index, row) in rows.iter().enumerate() {
        let id = row
            .as_table()
            .and_then(|fields| fields.get("id"))
            .and_then(toml::Value::as_str)
            .ok_or_else(|| {
                Diagnostic::error("E_NEGATIVE_ROW", subject)
                    .at(format!("{table}/{index}/id"))
            })?;
        if id.is_empty() || id.len() > 128 || !id.is_ascii() {
            return Err(Diagnostic::error("E_NEGATIVE_ID", subject).at(id));
        }
        ids.push(id.to_owned());
    }
    Ok(ids)
}

fn source_lookup<'a>(files: &'a [LoadedFile], path: &str) -> VResult<&'a LoadedFile> {
    files
        .iter()
        .find(|file| file.contract.path == path)
        .ok_or_else(|| Diagnostic::error("E_SOURCE_EXACT_SET", path))
}

fn negative_specs() -> Vec<NegativeSpec> {
    let mut specs = Vec::with_capacity(EXPECTED_NEGATIVES);
    add_task_negative_specs(&mut specs);
    add_auth_negative_specs(&mut specs);
    add_sdk_negative_specs(&mut specs);
    add_media_negative_specs(&mut specs);
    add_state_negative_specs(&mut specs);
    specs
}

fn add_specs(
    output: &mut Vec<NegativeSpec>,
    family: &'static str,
    ids: &'static [&'static str],
) {
    output.extend(ids.iter().copied().map(|id| NegativeSpec {
        family,
        id,
    }));
}

fn add_task_negative_specs(output: &mut Vec<NegativeSpec>) {
    const IDS: &[&str] = &[
        "artifact-missing",
        "artifact-swapped",
        "artifact-truncated",
        "artifact-provenance-drift",
        "floating-source",
        "verbatim-upstream-string-misclassified-as-provenance",
        "duplicate-artifact-identity",
        "sdk-resolution-drift",
        "tasks-import-inventory-drift",
        "apps-direct-import-drift",
        "apps-standard-reuse-drift",
        "apps-union-parity-drift",
        "apps-inherited-control-drift",
        "direction-or-role-drift",
        "artifact-authority-promotion",
        "quarantine-drift",
        "composition-profile-drift",
        "tasks-raw-schema-promotion",
        "apps-raw-schema-promotion",
        "apps-lossy-projection",
        "tasks-conformance-source-drift",
        "tasks-conformance-ttl-authority-promotion",
        "tasks-status-branch-expansion-drift",
        "tasks-path-fixture-corpus-drift",
        "apps-whatwg-html-validation-drift",
        "apps-client-settings-policy-drift",
        "apps-server-settings-policy-drift",
        "apps-negotiation-policy-drift",
        "apps-lifecycle-transition-drift",
        "apps-tool-call-lifecycle-drift",
        "apps-host-cursor-substitution-drift",
        "apps-content-block-path-inventory-drift",
        "apps-json-value-domain-drift",
        "apps-early-request-precedence-drift",
        "apps-early-notification-sink-drift",
        "apps-cause-outcome-drift",
        "apps-request-id-domain-drift",
        "apps-error-profile-drift",
        "apps-projection-normalization-drift",
        "apps-projection-omission-disposition-drift",
        "apps-typed-exclusion-drift",
        "cross-domain-envelope-forwarding",
    ];
    add_specs(output, "tasks_apps", IDS);
}

fn add_auth_negative_specs(output: &mut Vec<NegativeSpec>) {
    const IDS: &[&str] = &[
        "missing-required-artifact",
        "extra-artifact-alias",
        "changed-retrieval-url",
        "changed-byte-length",
        "wrong-sha256-or-content-address-mismatch",
        "changed-revision-commit-or-path",
        "changed-retrieval-date",
        "changed-artifact-format",
        "truncated-body",
        "normalized-body",
        "floating-latest",
        "browser-rendered-or-github-blob",
        "redirected-effective-url",
        "content-encoding-or-transfer-framing",
        "openid-document-swap",
        "openid-revision-swap",
        "oauth-13-14-clause-swap",
        "single-floating-oauth",
        "core-cimd-revision-swap",
        "enterprise-inherits-core-cimd",
        "enterprise-identity-delegate-omission",
        "oidc-metadata-as-id-jag-algorithm-authority",
        "oidc-enterprise-authority-broadening",
        "dynamic-registration-operation-from-metadata-semantics",
        "id-jag-example-omission",
        "generic-oauth-scope-omission-in-enterprise-stage-two",
        "oidc-invalid-client-conflict-collapse",
        "scenario-file-level-classification",
        "scenario-inventory-drift",
        "duplicate-enterprise-condition-inventory",
        "empty-scope-omission-as-forced-rejection",
        "cache-header-diagnostic-as-forced-rejection",
        "raw-provider-input-reclassified",
        "scenario-es256-only-attribution",
        "scenario-oracle-defect-as-client-rejection",
        "raw-expected-rejection-as-upstream-pass",
        "adjusted-fixture-as-upstream-pass",
        "basic-inherits-jwt-blocker",
        "mock-as-production-positive",
        "rendered-auth-identifier-as-wire-authority",
        "client-secret-in-body",
        "dual-client-authentication",
        "auth-profile-stability-conflation",
        "first-stage-resource-unproven-omission",
        "signed-scope-on-empty-request",
        "signed-scope-missing-on-nonempty-request",
        "zero-scope-grant-on-nonempty-request",
        "top-level-scope-omitted-after-narrowing",
        "top-level-scope-differs-from-signed-grant",
        "stage-two-scope-on-empty-grant",
        "stage-two-scope-not-subset-of-idp-grant",
        "stage-two-resource-omitted-after-implicit-first-stage-mapping",
        "enterprise-registration-role-reuse",
        "enterprise-dynamic-registration-substitute",
        "unpinned-enterprise-cimd-01",
        "oidc-enterprise-vs-cimd-family-confusion",
        "oidc-invalid-client-401-wrong-method",
        "oidc-invalid-client-401-wrong-error",
        "oidc-invalid-client-malformed-challenge",
        "oidc-invalid-client-unadmitted-error-body",
        "oidc-invalid-client-emitter-inheritance",
    ];
    add_specs(output, "auth", IDS);
}

fn add_sdk_negative_specs(output: &mut Vec<NegativeSpec>) {
    const IDS: &[&str] = &[
        "missing-tier1-typescript",
        "extra-lower-tier-java",
        "duplicate-go",
        "catalog-byte-drift",
        "catalog-tier-drift",
        "floating-catalog-substitution",
        "floating-version",
        "source-commit-drift",
        "registry-byte-drift",
        "swapped-ecosystem-artifact",
        "lock-byte-drift",
        "closure-drift",
    ];
    output.extend(IDS.iter().copied().enumerate().map(|(index, id)| NegativeSpec {
        family: if index < 6 { "sdk.catalog" } else { "sdk.peer" },
        id,
    }));
}

fn add_media_negative_specs(output: &mut Vec<NegativeSpec>) {
    const IDS: &[&str] = &[
        "root-version-drift",
        "archive-checksum-or-length-drift",
        "source-ref-drift",
        "invent-html5ever-tag",
        "license-or-msrv-drift",
        "html-feature-enabled",
        "image-codec-removed",
        "image-extra-codec-or-rayon",
        "resvg-feature-enabled",
        "graph-kind-or-target-omitted",
        "compatible-projection-promoted",
        "build-unsafe-ffi-panic-finding-omitted",
        "missing-archive-audit-promoted",
        "advisory-scan-inferred",
        "mime-magic-mismatch-admitted",
        "animated-or-multiframe-admitted",
        "apng-static-policy-admitted",
        "jpeg-alias-positive-coverage-removed",
        "limit-or-overflow-bypass",
        "metadata-or-color-authority",
        "svg-script-event-animation",
        "svg-image-or-foreign-object",
        "svg-external-resource",
        "svg-css-animation-import-font-vectors-omitted",
        "svg-text-silent-drop",
        "html-parser-equals-conformance",
        "timeout-without-kill-or-bound",
        "runtime-handoff-promoted",
        "source-index-entry-unbound",
        "transitive-renderer-audit-omitted",
        "compiled-image-encoder-surface-admitted",
        "raster-body-offline-binding-omitted",
        "mime-unknown-or-svg-mismatch-admitted",
        "svg-case-namespace-evasion-admitted",
    ];
    add_specs(output, "media", IDS);
}

fn add_state_negative_specs(output: &mut Vec<NegativeSpec>) {
    const FEATURE_IDS: &[&str] = &[
        "NEG-REDIS-FEATURE-AHASH",
        "NEG-REDIS-FEATURE-BIGDECIMAL",
        "NEG-REDIS-FEATURE-BLOOM",
        "NEG-REDIS-FEATURE-BYTES",
        "NEG-REDIS-FEATURE-HASHBROWN",
        "NEG-REDIS-FEATURE-RUST_DECIMAL",
        "NEG-REDIS-FEATURE-UUID",
        "NEG-REDIS-FEATURE-DEFAULT",
        "NEG-REDIS-FEATURE-AIO",
        "NEG-REDIS-FEATURE-BB8",
        "NEG-REDIS-FEATURE-CACHE-AIO",
        "NEG-REDIS-FEATURE-CLUSTER",
        "NEG-REDIS-FEATURE-CLUSTER-ASYNC",
        "NEG-REDIS-FEATURE-CONNECTION-MANAGER",
        "NEG-REDIS-FEATURE-ENTRA-ID",
        "NEG-REDIS-FEATURE-GEOSPATIAL",
        "NEG-REDIS-FEATURE-JSON",
        "NEG-REDIS-FEATURE-NUM-BIGINT",
        "NEG-REDIS-FEATURE-R2D2",
        "NEG-REDIS-FEATURE-SENTINEL",
        "NEG-REDIS-FEATURE-SMOL-COMP",
        "NEG-REDIS-FEATURE-SMOL-NATIVE-TLS-COMP",
        "NEG-REDIS-FEATURE-SMOL-RUSTLS-COMP",
        "NEG-REDIS-FEATURE-STREAMS",
        "NEG-REDIS-FEATURE-TLS-NATIVE-TLS",
        "NEG-REDIS-FEATURE-TLS-RUSTLS",
        "NEG-REDIS-FEATURE-TLS-RUSTLS-INSECURE",
        "NEG-REDIS-FEATURE-TLS-RUSTLS-WEBPKI-ROOTS",
        "NEG-REDIS-FEATURE-TOKEN-BASED-AUTHENTICATION",
        "NEG-REDIS-FEATURE-TOKIO-COMP",
        "NEG-REDIS-FEATURE-TOKIO-NATIVE-TLS-COMP",
        "NEG-REDIS-FEATURE-TOKIO-RUSTLS-COMP",
        "NEG-REDIS-FEATURE-VECTOR-SETS",
    ];
    output.extend([
        NegativeSpec {
            family: "state",
            id: "NEG-ENVELOPE-RNG",
        },
        NegativeSpec {
            family: "state",
            id: "NEG-ENVELOPE-ALGORITHMS",
        },
        NegativeSpec {
            family: "state",
            id: "NEG-CAP-OPTIONALS",
        },
        NegativeSpec {
            family: "state",
            id: "NEG-REDIS-FEATURES",
        },
    ]);
    add_specs(output, "state", FEATURE_IDS);
    output.extend([
        NegativeSpec {
            family: "state",
            id: "NEG-REDIS-SMOL-NAME",
        },
        NegativeSpec {
            family: "state",
            id: "NEG-REDIS-SUPPORT",
        },
    ]);
}

fn validate_negative_inventory(files: &[LoadedFile], policy: &Policy) -> VResult<Vec<NegativeSpec>> {
    let specs = negative_specs();
    if specs.len() != EXPECTED_NEGATIVES {
        return Err(Diagnostic::error("E_STATIC_NEGATIVE_COUNT", "verifier registry")
            .at(specs.len().to_string()));
    }
    validate_case_unique(
        specs
            .iter()
            .map(|spec| format!("{}/{}", spec.family, spec.id)),
        "static negative registry",
    )?;
    validate_case_unique(
        specs.iter().map(|spec| spec.id.to_owned()),
        "static globally unique negative IDs",
    )?;
    if policy.negative_family.len() != NEGATIVE_FAMILIES.len() {
        return Err(Diagnostic::error("E_NEGATIVE_FAMILY_COUNT", "negative_family")
            .at(policy.negative_family.len().to_string()));
    }

    let mut observed_by_family = BTreeMap::<String, Vec<String>>::new();
    let mut observed_keys = Vec::with_capacity(EXPECTED_NEGATIVES);
    let mut observed_ids = Vec::with_capacity(EXPECTED_NEGATIVES);
    for (source, expected_contract) in
        policy.negative_family.iter().zip(NEGATIVE_FAMILIES)
    {
        if source.id != expected_contract.0
            || source.source_path != expected_contract.1
            || source.source_array != expected_contract.2
            || source.count != expected_contract.3
            || source.sha256 != expected_contract.4
        {
            return Err(Diagnostic::error("E_NEGATIVE_FAMILY_CONTRACT", &source.id));
        }
        validate_ascii_posix_path(&source.source_path, "negative source path")?;
        validate_sha256(&source.sha256, &source.id)?;
        let file = source_lookup(files, &source.source_path)?;
        let ids = extract_array_table_ids(
            &file.bytes,
            &source.source_array,
            &source.source_path,
        )?;
        if ids.len() != source.count {
            return Err(Diagnostic::error("E_NEGATIVE_SOURCE_COUNT", &source.id)
                .at(format!("expected={};actual={}", source.count, ids.len())));
        }
        validate_case_unique(ids.clone(), &source.id)?;
        for id in &ids {
            observed_keys.push(format!("{}/{}", source.id, id));
            observed_ids.push(id.clone());
        }
        if observed_by_family.insert(source.id.clone(), ids).is_some() {
            return Err(Diagnostic::error("E_NEGATIVE_DUPLICATE", &source.id));
        }
    }
    if observed_keys.len() != EXPECTED_NEGATIVES {
        return Err(Diagnostic::error("E_NEGATIVE_COUNT", "child-declared negatives")
            .at(observed_keys.len().to_string()));
    }
    validate_case_unique(observed_keys.clone(), "observed negative registry")?;
    validate_case_unique(observed_ids, "observed globally unique negative IDs")?;
    let expected = specs
        .iter()
        .map(|spec| format!("{}/{}", spec.family, spec.id))
        .collect::<BTreeSet<_>>();
    let observed = observed_keys.into_iter().collect::<BTreeSet<_>>();
    if observed != expected || expected.len() != EXPECTED_NEGATIVES {
        return Err(Diagnostic::error("E_NEGATIVE_EXACT_SET", "negative registry"));
    }
    if policy.negative_case.len() != EXPECTED_NEGATIVES {
        return Err(Diagnostic::error("E_MUTATION_COUNT", "negative_case")
            .at(policy.negative_case.len().to_string()));
    }
    let policy_case_keys = policy
        .negative_case
        .iter()
        .map(|case| format!("{}/{}", case.family, case.id))
        .collect::<Vec<_>>();
    validate_case_unique(policy_case_keys.clone(), "policy negative cases")?;
    let policy_case_set = policy_case_keys.into_iter().collect::<BTreeSet<_>>();
    if policy_case_set != expected {
        return Err(Diagnostic::error("E_MUTATION_EXACT_SET", "policy negative cases"));
    }
    let static_specs = specs
        .iter()
        .map(|spec| ((spec.family, spec.id), spec))
        .collect::<BTreeMap<_, _>>();
    for case in &policy.negative_case {
        if case.id.is_empty()
            || case.id.len() > policy.bounds.max_id_bytes
            || !case.id.is_ascii()
            || case.family.is_empty()
            || case.family.len() > policy.bounds.max_id_bytes
            || !case.family.is_ascii()
            || case.validator.is_empty()
            || case.validator.len() > policy.bounds.max_selector_bytes
            || !case.validator.is_ascii()
            || case.target_selector.len() > policy.bounds.max_selector_bytes
            || !case.target_selector.is_ascii()
            || case.argument.as_ref().is_some_and(|argument| {
                argument.is_empty()
                    || argument.len() > policy.bounds.max_argument_bytes
                    || !argument.is_ascii()
            })
            || case.secondary_selector.as_ref().is_some_and(|selector| {
                selector.is_empty()
                    || selector.len() > policy.bounds.max_selector_bytes
                    || !selector.is_ascii()
            })
        {
            return Err(Diagnostic::error("E_NEGATIVE_ID", &case.id));
        }
        parse_pointer(&case.target_selector, &case.id)?;
        if let Some(secondary) = &case.secondary_selector {
            parse_pointer(secondary, &case.id)?;
        }
        validate_ascii_posix_path(&case.target_path, &case.id)?;
        let family_ids = observed_by_family
            .get(&case.family)
            .ok_or_else(|| Diagnostic::error("E_MUTATION_FAMILY", &case.id))?;
        if !family_ids.iter().any(|id| id == &case.id) {
            return Err(Diagnostic::error("E_MUTATION_SOURCE_INDEX", &case.id)
                .at(case.source_index.to_string()));
        }
        source_lookup(files, &case.target_path)
            .map_err(|_| Diagnostic::error("E_MUTATION_TARGET", &case.id)
                .at(&case.target_path))?;
        static_specs
            .get(&(case.family.as_str(), case.id.as_str()))
            .ok_or_else(|| Diagnostic::error("E_MUTATION_EXACT_SET", &case.id))?;
        let expected_validator = format!("{}.{}", case.family, case.id);
        if case.integrity_mode != "rebind_virtual_hashes"
            || case.validator != expected_validator
        {
            return Err(Diagnostic::error("E_MUTATION_DIAGNOSTIC_CONTRACT", &case.id));
        }
    }
    let mut canonical = Vec::with_capacity(policy.negative_inventory.canonical_bytes);
    for family in &policy.negative_inventory.family_order {
        let source = policy
            .negative_family
            .iter()
            .find(|source| source.id == *family)
            .ok_or_else(|| Diagnostic::error("E_NEGATIVE_FAMILY_CONTRACT", family))?;
        let mut cases = policy
            .negative_case
            .iter()
            .filter(|case| case.family == *family)
            .collect::<Vec<_>>();
        cases.sort_by_key(|case| case.source_index);
        if cases.len() != source.count
            || cases
                .iter()
                .enumerate()
                .any(|(index, case)| case.source_index != index)
        {
            return Err(Diagnostic::error("E_MUTATION_SOURCE_INDEX", family));
        }
        let observed = observed_by_family
            .get(family)
            .ok_or_else(|| Diagnostic::error("E_MUTATION_FAMILY", family))?
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let ordered = cases.iter().map(|case| case.id.as_str()).collect::<Vec<_>>();
        if ordered.iter().copied().collect::<BTreeSet<_>>() != observed {
            return Err(Diagnostic::error("E_MUTATION_SOURCE_INDEX", family)
                .at("source-index bijection"));
        }
        let mut family_canonical = Vec::new();
        for id in ordered {
            family_canonical.extend_from_slice(family.as_bytes());
            family_canonical.push(b'\t');
            family_canonical.extend_from_slice(id.as_bytes());
            family_canonical.push(b'\n');
        }
        if lower_hex(&sha256(&family_canonical)) != source.sha256 {
            return Err(Diagnostic::error("E_NEGATIVE_FAMILY_HASH", family)
                .at(lower_hex(&sha256(&family_canonical))));
        }
        canonical.extend_from_slice(&family_canonical);
    }
    if canonical.len() != policy.negative_inventory.canonical_bytes
        || lower_hex(&sha256(&canonical)) != policy.negative_inventory.sha256
    {
        return Err(Diagnostic::error("E_NEGATIVE_INVENTORY_HASH", "negative registry")
            .at(format!(
                "bytes={};sha256={}",
                canonical.len(),
                lower_hex(&sha256(&canonical))
            )));
    }
    validate_recipe_canonical_registry(policy)?;
    Ok(specs)
}

fn mutation_kind_name(kind: MutationKind) -> &'static str {
    match kind {
        MutationKind::Remove => "remove",
        MutationKind::Insert => "insert",
        MutationKind::Replace => "replace",
        MutationKind::Swap => "swap",
        MutationKind::Duplicate => "duplicate",
        MutationKind::ToggleBool => "toggle_bool",
        MutationKind::Increment => "increment",
        MutationKind::AppendFeature => "append_feature",
        MutationKind::RenameKey => "rename_key",
        MutationKind::ReplaceBytes => "replace_bytes",
    }
}

fn canonical_u32(output: &mut Vec<u8>, value: usize, subject: &str) -> VResult<()> {
    let value = u32::try_from(value)
        .map_err(|_| Diagnostic::error("E_MUTATION_CANONICAL", subject).at("u32 overflow"))?;
    output.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn canonical_string(output: &mut Vec<u8>, value: &str, subject: &str) -> VResult<()> {
    canonical_u32(output, value.len(), subject)?;
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn canonical_optional_string(
    output: &mut Vec<u8>,
    value: Option<&str>,
    subject: &str,
) -> VResult<()> {
    match value {
        None => output.push(0x00),
        Some(value) => {
            output.push(0x01);
            canonical_string(output, value, subject)?;
        }
    }
    Ok(())
}

fn validate_recipe_canonical_registry(policy: &Policy) -> VResult<()> {
    let family_order = policy
        .negative_inventory
        .family_order
        .iter()
        .enumerate()
        .map(|(index, family)| (family.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    let mut recipes = policy.negative_case.iter().collect::<Vec<_>>();
    recipes.sort_by(|left, right| {
        let left_family = family_order.get(left.family.as_str()).copied();
        let right_family = family_order.get(right.family.as_str()).copied();
        (left_family, left.source_index).cmp(&(right_family, right.source_index))
    });
    if recipes.iter().any(|recipe| !family_order.contains_key(recipe.family.as_str())) {
        return Err(Diagnostic::error(
            "E_MUTATION_CANONICAL",
            "negative_case",
        )
        .at("unknown family"));
    }
    let mut canonical = Vec::with_capacity(policy.mutation_contract.canonical_recipe_bytes);
    canonical.extend_from_slice(b"FND01MUTv2\0");
    canonical_u32(&mut canonical, recipes.len(), "negative_case")?;
    for recipe in recipes {
        canonical_string(&mut canonical, &recipe.family, &recipe.id)?;
        canonical_string(&mut canonical, &recipe.id, &recipe.id)?;
        canonical_u32(&mut canonical, recipe.source_index, &recipe.id)?;
        canonical_string(&mut canonical, &recipe.target_path, &recipe.id)?;
        canonical_string(&mut canonical, &recipe.target_selector, &recipe.id)?;
        canonical_string(
            &mut canonical,
            mutation_kind_name(recipe.operation),
            &recipe.id,
        )?;
        canonical_optional_string(
            &mut canonical,
            recipe.argument.as_deref(),
            &recipe.id,
        )?;
        canonical_optional_string(
            &mut canonical,
            recipe.secondary_selector.as_deref(),
            &recipe.id,
        )?;
        canonical_string(&mut canonical, &recipe.integrity_mode, &recipe.id)?;
        canonical_string(&mut canonical, &recipe.validator, &recipe.id)?;
    }
    let digest = lower_hex(&sha256(&canonical));
    if canonical.len() != MUTATION_RECIPE_CANONICAL_BYTES
        || digest != MUTATION_RECIPE_CANONICAL_SHA256
        || canonical.len() != policy.mutation_contract.canonical_recipe_bytes
        || digest != policy.mutation_contract.canonical_recipe_sha256
    {
        return Err(Diagnostic::error(
            "E_MUTATION_CANONICAL",
            "negative_case",
        )
        .at(format!("bytes={};sha256={digest}", canonical.len())));
    }
    Ok(())
}

fn parse_pointer(pointer: &str, subject: &str) -> VResult<Vec<String>> {
    if !pointer.starts_with('/')
        || pointer == "/"
        || pointer.len() > 512
        || !pointer.is_ascii()
        || pointer.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer));
    }
    let components = pointer[1..]
        .split('/')
        .map(|component| {
            if component.is_empty() {
                return Err(Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer));
            }
            let mut decoded = String::new();
            let mut chars = component.chars();
            while let Some(character) = chars.next() {
                if character == '~' {
                    match chars.next() {
                        Some('0') => decoded.push('~'),
                        Some('1') => decoded.push('/'),
                        _ => {
                            return Err(
                                Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer)
                            );
                        }
                    }
                } else {
                    decoded.push(character);
                }
            }
            Ok(decoded)
        })
        .collect::<VResult<Vec<_>>>()?;
    if components.len() > 16 {
        return Err(Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer));
    }
    Ok(components)
}

fn array_selector_index(
    array: &[toml::Value],
    component: &str,
    subject: &str,
    pointer: &str,
) -> VResult<usize> {
    if let Ok(index) = component.parse::<usize>() {
        if component == index.to_string() && index < array.len() {
            return Ok(index);
        }
        return Err(Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer));
    }
    let (key, expected) = component
        .split_once('=')
        .ok_or_else(|| Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer))?;
    if key.is_empty() || expected.is_empty() {
        return Err(Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer));
    }
    let matches = array
        .iter()
        .enumerate()
        .filter_map(|(index, value)| {
            value
                .as_table()
                .and_then(|table| table.get(key))
                .and_then(toml::Value::as_str)
                .filter(|actual| *actual == expected)
                .map(|_| index)
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(Diagnostic::error("E_SEMANTIC_POINTER", subject)
            .at(format!("{pointer}:matches={}", matches.len())));
    }
    Ok(matches[0])
}

fn pointer_get<'a>(
    value: &'a toml::Value,
    pointer: &str,
    subject: &str,
) -> VResult<&'a toml::Value> {
    let components = parse_pointer(pointer, subject)?;
    let mut current = value;
    for component in components {
        current = match current {
            toml::Value::Table(table) => table
                .get(&component)
                .ok_or_else(|| Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer))?,
            toml::Value::Array(array) => {
                let index = array_selector_index(array, &component, subject, pointer)?;
                array
                    .get(index)
                    .ok_or_else(|| Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer))?
            }
            _ => {
                return Err(Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer));
            }
        };
    }
    Ok(current)
}

fn pointer_parent_mut<'a>(
    value: &'a mut toml::Value,
    pointer: &str,
    subject: &str,
) -> VResult<(&'a mut toml::Value, String)> {
    let mut components = parse_pointer(pointer, subject)?;
    let final_component = components
        .pop()
        .ok_or_else(|| Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer))?;
    let mut current = value;
    for component in components {
        current = match current {
            toml::Value::Table(table) => table
                .get_mut(&component)
                .ok_or_else(|| Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer))?,
            toml::Value::Array(array) => {
                let index = array_selector_index(array, &component, subject, pointer)?;
                array
                    .get_mut(index)
                    .ok_or_else(|| Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer))?
            }
            _ => {
                return Err(Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer));
            }
        };
    }
    Ok((current, final_component))
}

fn set_pointer(
    document: &mut toml::Value,
    pointer: &str,
    replacement: toml::Value,
    subject: &str,
) -> VResult<()> {
    let (parent, component) = pointer_parent_mut(document, pointer, subject)?;
    match parent {
        toml::Value::Table(table) => {
            let slot = table
                .get_mut(&component)
                .ok_or_else(|| Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer))?;
            *slot = replacement;
        }
        toml::Value::Array(array) => {
            let index = array_selector_index(array, &component, subject, pointer)?;
            let slot = array
                .get_mut(index)
                .ok_or_else(|| Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer))?;
            *slot = replacement;
        }
        _ => return Err(Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer)),
    }
    Ok(())
}

fn remove_pointer(
    document: &mut toml::Value,
    pointer: &str,
    subject: &str,
) -> VResult<()> {
    let (parent, component) = pointer_parent_mut(document, pointer, subject)?;
    match parent {
        toml::Value::Table(table) => {
            table
                .remove(&component)
                .ok_or_else(|| Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer))?;
        }
        toml::Value::Array(array) => {
            let index = array_selector_index(array, &component, subject, pointer)?;
            if index >= array.len() {
                return Err(Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer));
            }
            array.remove(index);
        }
        _ => return Err(Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer)),
    }
    Ok(())
}

fn pointer_get_mut<'a>(
    value: &'a mut toml::Value,
    pointer: &str,
    subject: &str,
) -> VResult<&'a mut toml::Value> {
    let components = parse_pointer(pointer, subject)?;
    let mut current = value;
    for component in components {
        current = match current {
            toml::Value::Table(table) => table
                .get_mut(&component)
                .ok_or_else(|| Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer))?,
            toml::Value::Array(array) => {
                let index = array_selector_index(array, &component, subject, pointer)?;
                array
                    .get_mut(index)
                    .ok_or_else(|| Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer))?
            }
            _ => {
                return Err(Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer));
            }
        };
    }
    Ok(current)
}

fn json_array_selector_index(
    array: &[StrictJson],
    component: &str,
    subject: &str,
    pointer: &str,
) -> VResult<usize> {
    if let Ok(index) = component.parse::<usize>() {
        if component == index.to_string() && index < array.len() {
            return Ok(index);
        }
        return Err(Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer));
    }
    let (key, expected) = component
        .split_once('=')
        .ok_or_else(|| Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer))?;
    let matches = array
        .iter()
        .enumerate()
        .filter_map(|(index, value)| match value {
            StrictJson::Object(object) => object
                .get(key)
                .and_then(|value| match value {
                    StrictJson::String(text) if text == expected => Some(index),
                    _ => None,
                }),
            _ => None,
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(Diagnostic::error("E_SEMANTIC_POINTER", subject)
            .at(format!("{pointer}:matches={}", matches.len())));
    }
    Ok(matches[0])
}

fn json_pointer_get<'a>(
    value: &'a StrictJson,
    pointer: &str,
    subject: &str,
) -> VResult<&'a StrictJson> {
    let components = parse_pointer(pointer, subject)?;
    let mut current = value;
    for component in components {
        current = match current {
            StrictJson::Object(object) => object
                .get(&component)
                .ok_or_else(|| Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer))?,
            StrictJson::Array(array) => {
                let index = json_array_selector_index(array, &component, subject, pointer)?;
                array
                    .get(index)
                    .ok_or_else(|| Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer))?
            }
            _ => {
                return Err(Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer));
            }
        };
    }
    Ok(current)
}

fn json_pointer_parent_mut<'a>(
    value: &'a mut StrictJson,
    pointer: &str,
    subject: &str,
) -> VResult<(&'a mut StrictJson, String)> {
    let mut components = parse_pointer(pointer, subject)?;
    let final_component = components
        .pop()
        .ok_or_else(|| Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer))?;
    let mut current = value;
    for component in components {
        current = match current {
            StrictJson::Object(object) => object
                .get_mut(&component)
                .ok_or_else(|| Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer))?,
            StrictJson::Array(array) => {
                let index = json_array_selector_index(array, &component, subject, pointer)?;
                array
                    .get_mut(index)
                    .ok_or_else(|| Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer))?
            }
            _ => {
                return Err(Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer));
            }
        };
    }
    Ok((current, final_component))
}

fn json_pointer_get_mut<'a>(
    value: &'a mut StrictJson,
    pointer: &str,
    subject: &str,
) -> VResult<&'a mut StrictJson> {
    let components = parse_pointer(pointer, subject)?;
    let mut current = value;
    for component in components {
        current = match current {
            StrictJson::Object(object) => object
                .get_mut(&component)
                .ok_or_else(|| Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer))?,
            StrictJson::Array(array) => {
                let index = json_array_selector_index(array, &component, subject, pointer)?;
                array
                    .get_mut(index)
                    .ok_or_else(|| Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer))?
            }
            _ => {
                return Err(Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer));
            }
        };
    }
    Ok(current)
}

fn json_set_pointer(
    document: &mut StrictJson,
    pointer: &str,
    replacement: StrictJson,
    subject: &str,
) -> VResult<()> {
    let (parent, component) = json_pointer_parent_mut(document, pointer, subject)?;
    match parent {
        StrictJson::Object(object) => {
            let slot = object
                .get_mut(&component)
                .ok_or_else(|| Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer))?;
            *slot = replacement;
        }
        StrictJson::Array(array) => {
            let index = json_array_selector_index(array, &component, subject, pointer)?;
            *array
                .get_mut(index)
                .ok_or_else(|| Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer))? =
                replacement;
        }
        _ => return Err(Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer)),
    }
    Ok(())
}

fn json_remove_pointer(
    document: &mut StrictJson,
    pointer: &str,
    subject: &str,
) -> VResult<()> {
    let (parent, component) = json_pointer_parent_mut(document, pointer, subject)?;
    match parent {
        StrictJson::Object(object) => {
            object
                .remove(&component)
                .ok_or_else(|| Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer))?;
        }
        StrictJson::Array(array) => {
            let index = json_array_selector_index(array, &component, subject, pointer)?;
            array.remove(index);
        }
        _ => return Err(Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer)),
    }
    Ok(())
}

fn fixture_json_value(value: &toml::Value, subject: &str) -> VResult<StrictJson> {
    match value {
        toml::Value::String(text) => Ok(StrictJson::String(text.clone())),
        toml::Value::Integer(number) => Ok(StrictJson::Number((*number).into())),
        toml::Value::Float(number) => serde_json::Number::from_f64(*number)
            .map(StrictJson::Number)
            .ok_or_else(|| Diagnostic::error("E_FIXTURE_SCHEMA", subject).at("non-finite float")),
        toml::Value::Boolean(value) => Ok(StrictJson::Bool(*value)),
        toml::Value::Datetime(_) => {
            Err(Diagnostic::error("E_FIXTURE_SCHEMA", subject).at("datetime is not JSON"))
        }
        toml::Value::Array(values) => values
            .iter()
            .map(|value| fixture_json_value(value, subject))
            .collect::<VResult<Vec<_>>>()
            .map(StrictJson::Array),
        toml::Value::Table(table) => table
            .iter()
            .map(|(key, value)| {
                fixture_json_value(value, subject).map(|value| (key.clone(), value))
            })
            .collect::<VResult<BTreeMap<_, _>>>()
            .map(StrictJson::Object),
    }
}

struct ObservationEncoder {
    bytes: Vec<u8>,
    limit: usize,
    subject: String,
}

impl ObservationEncoder {
    fn new(limit: u64, subject: &str) -> VResult<Self> {
        let limit = usize::try_from(limit)
            .map_err(|_| Diagnostic::error("E_OBSERVATION_BOUND", subject).at("limit"))?;
        Ok(Self {
            bytes: Vec::new(),
            limit,
            subject: subject.to_owned(),
        })
    }

    fn extend(&mut self, value: &[u8]) -> VResult<()> {
        let new_length = self
            .bytes
            .len()
            .checked_add(value.len())
            .ok_or_else(|| {
                Diagnostic::error("E_OBSERVATION_BOUND", &self.subject).at("length overflow")
            })?;
        if new_length > self.limit {
            return Err(Diagnostic::error("E_OBSERVATION_BOUND", &self.subject)
                .at(new_length.to_string()));
        }
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn byte(&mut self, value: u8) -> VResult<()> {
        self.extend(&[value])
    }

    fn u32(&mut self, value: usize) -> VResult<()> {
        let value = u32::try_from(value)
            .map_err(|_| Diagnostic::error("E_OBSERVATION_BOUND", &self.subject).at("u32"))?;
        self.extend(&value.to_be_bytes())
    }

    fn u64(&mut self, value: usize) -> VResult<()> {
        let value = u64::try_from(value)
            .map_err(|_| Diagnostic::error("E_OBSERVATION_BOUND", &self.subject).at("u64"))?;
        self.extend(&value.to_be_bytes())
    }

    fn sized_u32(&mut self, value: &[u8]) -> VResult<()> {
        self.u32(value.len())?;
        self.extend(value)
    }

    fn sized_u64(&mut self, value: &[u8]) -> VResult<()> {
        self.u64(value.len())?;
        self.extend(value)
    }
}

fn encode_toml_observation(
    value: Option<&toml::Value>,
    output: &mut ObservationEncoder,
) -> VResult<()> {
    let Some(value) = value else {
        return output.byte(0x00);
    };
    match value {
        toml::Value::Boolean(value) => {
            output.byte(0x02)?;
            output.byte(u8::from(*value))
        }
        toml::Value::Integer(value) => {
            output.byte(0x03)?;
            output.extend(&value.to_be_bytes())
        }
        toml::Value::Float(value) => {
            output.byte(0x04)?;
            output.extend(&value.to_bits().to_be_bytes())
        }
        toml::Value::String(value) => {
            output.byte(0x05)?;
            output.sized_u64(value.as_bytes())
        }
        toml::Value::Array(values) => {
            output.byte(0x06)?;
            output.u64(values.len())?;
            for value in values {
                encode_toml_observation(Some(value), output)?;
            }
            Ok(())
        }
        toml::Value::Table(table) => {
            output.byte(0x07)?;
            output.u64(table.len())?;
            let mut entries = table.iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
            for (key, value) in entries {
                output.sized_u32(key.as_bytes())?;
                encode_toml_observation(Some(value), output)?;
            }
            Ok(())
        }
        toml::Value::Datetime(value) => {
            output.byte(0x09)?;
            output.sized_u64(value.to_string().as_bytes())
        }
    }
}

fn encode_json_observation(
    value: Option<&StrictJson>,
    output: &mut ObservationEncoder,
) -> VResult<()> {
    let Some(value) = value else {
        return output.byte(0x00);
    };
    match value {
        StrictJson::Null => output.byte(0x01),
        StrictJson::Bool(value) => {
            output.byte(0x02)?;
            output.byte(u8::from(*value))
        }
        StrictJson::String(value) => {
            output.byte(0x05)?;
            output.sized_u64(value.as_bytes())
        }
        StrictJson::Array(values) => {
            output.byte(0x06)?;
            output.u64(values.len())?;
            for value in values {
                encode_json_observation(Some(value), output)?;
            }
            Ok(())
        }
        StrictJson::Object(values) => {
            output.byte(0x07)?;
            output.u64(values.len())?;
            for (key, value) in values {
                output.sized_u32(key.as_bytes())?;
                encode_json_observation(Some(value), output)?;
            }
            Ok(())
        }
        StrictJson::Number(value) => {
            output.byte(0x0a)?;
            output.sized_u64(value.to_string().as_bytes())
        }
    }
}

fn toml_pointer_observation<'a>(
    value: &'a toml::Value,
    pointer: &str,
    subject: &str,
) -> VResult<Option<&'a toml::Value>> {
    let components = parse_pointer(pointer, subject)?;
    let mut current = value;
    for component in components {
        current = match current {
            toml::Value::Table(table) => {
                let Some(value) = table.get(&component) else {
                    return Ok(None);
                };
                value
            }
            toml::Value::Array(array) => {
                if let Ok(index) = component.parse::<usize>() {
                    let Some(value) = array.get(index) else {
                        return Ok(None);
                    };
                    value
                } else {
                    let (key, expected) = component.split_once('=').ok_or_else(|| {
                        Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer)
                    })?;
                    let mut matches = array.iter().filter(|value| {
                        value
                            .as_table()
                            .and_then(|table| table.get(key))
                            .and_then(toml::Value::as_str)
                            == Some(expected)
                    });
                    let Some(value) = matches.next() else {
                        return Ok(None);
                    };
                    if matches.next().is_some() {
                        return Err(Diagnostic::error("E_SEMANTIC_POINTER", subject)
                            .at("ambiguous named array selector"));
                    }
                    value
                }
            }
            _ => return Ok(None),
        };
    }
    Ok(Some(current))
}

fn json_pointer_observation<'a>(
    value: &'a StrictJson,
    pointer: &str,
    subject: &str,
) -> VResult<Option<&'a StrictJson>> {
    let components = parse_pointer(pointer, subject)?;
    let mut current = value;
    for component in components {
        current = match current {
            StrictJson::Object(object) => {
                let Some(value) = object.get(&component) else {
                    return Ok(None);
                };
                value
            }
            StrictJson::Array(array) => {
                if let Ok(index) = component.parse::<usize>() {
                    let Some(value) = array.get(index) else {
                        return Ok(None);
                    };
                    value
                } else {
                    let (key, expected) = component.split_once('=').ok_or_else(|| {
                        Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer)
                    })?;
                    let mut matches = array.iter().filter(|value| match value {
                        StrictJson::Object(object) => {
                            matches!(object.get(key), Some(StrictJson::String(text)) if text == expected)
                        }
                        _ => false,
                    });
                    let Some(value) = matches.next() else {
                        return Ok(None);
                    };
                    if matches.next().is_some() {
                        return Err(Diagnostic::error("E_SEMANTIC_POINTER", subject)
                            .at("ambiguous named array selector"));
                    }
                    value
                }
            }
            _ => return Ok(None),
        };
    }
    Ok(Some(current))
}

enum ObservationDocument<'a> {
    Toml(&'a toml::Value),
    Json(&'a StrictJson),
    Raw(&'a [u8]),
}

fn observation_digest(
    assertion: &SemanticAssertion,
    document: ObservationDocument<'_>,
    policy: &Policy,
) -> VResult<[u8; 32]> {
    validate_ascii_posix_path(&assertion.source_path, &assertion.id)?;
    let selectors = std::iter::once(assertion.selector.as_str())
        .chain(assertion.secondary_selector.as_deref())
        .collect::<Vec<_>>();
    for selector in &selectors {
        parse_pointer(selector, &assertion.id)?;
    }
    if assertion.observation_mode == AssertionObservationMode::RawSourceBytes
        && selectors.len() != 1
    {
        return Err(Diagnostic::error("E_OBSERVATION_DOMAIN", &assertion.id)
            .at("raw observation requires exactly one selector"));
    }
    let mut output =
        ObservationEncoder::new(policy.bounds.max_receipt_toml_bytes, &assertion.id)?;
    output.extend(b"FND01OBSv1\0")?;
    let kind = match (&assertion.observation_mode, &document) {
        (AssertionObservationMode::CanonicalSelectedToml, ObservationDocument::Toml(_)) => 0x01,
        (AssertionObservationMode::CanonicalSelectedJson, ObservationDocument::Json(_)) => 0x02,
        (AssertionObservationMode::RawSourceBytes, ObservationDocument::Raw(_)) => 0x03,
        _ => {
            return Err(Diagnostic::error("E_OBSERVATION_DOMAIN", &assertion.id));
        }
    };
    output.byte(kind)?;
    output.sized_u32(assertion.source_path.as_bytes())?;
    output.u32(selectors.len())?;
    for selector in &selectors {
        output.sized_u32(selector.as_bytes())?;
    }
    match document {
        ObservationDocument::Toml(document) => {
            for selector in &selectors {
                let selected = toml_pointer_observation(document, selector, &assertion.id)?;
                encode_toml_observation(selected, &mut output)?;
            }
        }
        ObservationDocument::Json(document) => {
            for selector in &selectors {
                let selected = json_pointer_observation(document, selector, &assertion.id)?;
                encode_json_observation(selected, &mut output)?;
            }
        }
        ObservationDocument::Raw(bytes) => {
            let components = parse_pointer(&assertion.selector, &assertion.id)?;
            if components.len() != 2
                || components[0] != "bytes"
                || (components[1] != "end" && components[1].parse::<usize>().is_err())
            {
                return Err(Diagnostic::error("E_OBSERVATION_DOMAIN", &assertion.id)
                    .at("raw selector"));
            }
            output.byte(0x08)?;
            output.sized_u64(bytes)?;
        }
    }
    Ok(sha256(&output.bytes))
}

fn pointer_component_prefix(left: &[String], right: &[String]) -> bool {
    left.len() <= right.len() && left.iter().zip(right).all(|(left, right)| left == right)
}

fn pointer_overlaps_literal(pointer: &[String], literal: &[&str]) -> bool {
    (pointer.len() <= literal.len()
        && pointer
            .iter()
            .zip(literal)
            .all(|(component, expected)| component.as_str() == *expected))
        || (literal.len() <= pointer.len()
            && literal
                .iter()
                .zip(pointer)
                .all(|(expected, component)| *expected == component.as_str()))
}

fn task_app_quarantine_overlap(
    target_path: &str,
    pointer: &[String],
) -> (bool, bool) {
    if target_path != "evidence/fnd-01/tasks-apps.toml" {
        return (false, false);
    }
    (
        pointer_overlaps_literal(pointer, &["tasks", "quarantine"]),
        pointer_overlaps_literal(pointer, &["apps", "quarantine"]),
    )
}

fn pointer_enters_named_root(pointer: &[String], root: &str) -> bool {
    pointer.first().is_some_and(|component| component == root)
}

fn assertion_overlaps_mutation(
    assertion: &SemanticAssertion,
    case: &NegativeCase,
) -> VResult<bool> {
    if assertion.source_path != case.target_path {
        return Ok(false);
    }
    if assertion.observation_mode == AssertionObservationMode::RawSourceBytes
        || case.operation == MutationKind::ReplaceBytes
    {
        return Ok(true);
    }
    let assertion_selectors = std::iter::once(assertion.selector.as_str())
        .chain(assertion.secondary_selector.as_deref())
        .map(|selector| parse_pointer(selector, &assertion.id))
        .collect::<VResult<Vec<_>>>()?;
    let mutation_selectors = std::iter::once(case.target_selector.as_str())
        .chain(case.secondary_selector.as_deref())
        .map(|selector| parse_pointer(selector, &case.id))
        .collect::<VResult<Vec<_>>>()?;
    for assertion_components in &assertion_selectors {
        for mutation_components in &mutation_selectors {
            if pointer_component_prefix(assertion_components, mutation_components)
                || pointer_component_prefix(mutation_components, assertion_components)
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn validate_fixture_structure(
    value: &toml::Value,
    depth: usize,
    nodes: &mut usize,
    policy: &Policy,
    subject: &str,
) -> VResult<()> {
    if depth > policy.fixture_contract.max_fixture_value_depth {
        return Err(Diagnostic::error("E_FIXTURE_BOUND", subject).at("depth"));
    }
    *nodes = nodes
        .checked_add(1)
        .ok_or_else(|| Diagnostic::error("E_FIXTURE_BOUND", subject).at("node overflow"))?;
    if *nodes > policy.fixture_contract.max_fixture_value_members {
        return Err(Diagnostic::error("E_FIXTURE_BOUND", subject).at("nodes"));
    }
    match value {
        toml::Value::String(text) => {
            if text.len() > policy.fixture_contract.max_fixture_value_bytes {
                return Err(Diagnostic::error("E_FIXTURE_BOUND", subject).at("string"));
            }
        }
        toml::Value::Array(values) => {
            for value in values {
                validate_fixture_structure(value, depth + 1, nodes, policy, subject)?;
            }
        }
        toml::Value::Table(table) => {
            for (key, value) in table {
                if key.is_empty()
                    || key.len() > policy.bounds.max_id_bytes
                    || !key.is_ascii()
                    || key.bytes().any(|byte| byte.is_ascii_control())
                {
                    return Err(Diagnostic::error("E_FIXTURE_SCHEMA", subject).at("table key"));
                }
                validate_fixture_structure(value, depth + 1, nodes, policy, subject)?;
            }
        }
        toml::Value::Integer(_)
        | toml::Value::Float(_)
        | toml::Value::Boolean(_)
        | toml::Value::Datetime(_) => {}
    }
    Ok(())
}

fn fixture_payload_is_nonempty(value: &toml::Value) -> bool {
    match value {
        toml::Value::String(value) => !value.is_empty(),
        toml::Value::Array(value) => !value.is_empty(),
        toml::Value::Table(value) => !value.is_empty(),
        toml::Value::Integer(_)
        | toml::Value::Float(_)
        | toml::Value::Boolean(_)
        | toml::Value::Datetime(_) => true,
    }
}

fn fixture_value_kind_matches(fixture: &MutationFixture, policy: &Policy) -> bool {
    match fixture.value_kind {
        FixtureValueKind::String => fixture
            .value
            .as_str()
            .is_some_and(|value| !value.is_empty()),
        FixtureValueKind::StringArray => fixture.value.as_array().is_some_and(|values| {
            !values.is_empty()
                && values
                    .iter()
                    .all(|value| value.as_str().is_some_and(|text| !text.is_empty()))
        }),
        FixtureValueKind::Table => fixture
            .value
            .as_table()
            .is_some_and(|table| !table.is_empty()),
        FixtureValueKind::TableArray => fixture.value.as_array().is_some_and(|values| {
            !values.is_empty()
                && values
                    .iter()
                    .all(|value| value.as_table().is_some_and(|table| !table.is_empty()))
        }),
        FixtureValueKind::TableMember => fixture
            .value
            .as_table()
            .is_some_and(|table| {
                table.len() == 2
                    && table
                        .keys()
                        .map(String::as_str)
                        .eq(["relative_selector", "value"])
                    && table
                        .get("relative_selector")
                        .and_then(toml::Value::as_str)
                        .is_some_and(|selector| {
                            !selector.is_empty()
                                && selector.len() <= policy.bounds.max_selector_bytes
                                && selector.is_ascii()
                                && selector.starts_with('/')
                                && !selector.bytes().any(|byte| byte.is_ascii_control())
                        })
                    && table
                        .get("value")
                        .is_some_and(fixture_payload_is_nonempty)
            }),
    }
}

fn fixture_application_matches_operation(
    application: FixtureApplication,
    operation: MutationKind,
) -> bool {
    matches!(
        (application, operation),
        (
            FixtureApplication::ReplaceValue | FixtureApplication::ReplaceTableMember,
            MutationKind::Replace
        ) | (
            FixtureApplication::RemoveExactValue,
            MutationKind::Remove
        ) | (
            FixtureApplication::InsertArrayElement | FixtureApplication::InsertTableMember,
            MutationKind::Insert
        )
    )
}

fn fixture_application_name(application: FixtureApplication) -> &'static str {
    match application {
        FixtureApplication::ReplaceValue => "replace_value",
        FixtureApplication::RemoveExactValue => "remove_exact_value",
        FixtureApplication::InsertArrayElement => "insert_array_element",
        FixtureApplication::InsertTableMember => "insert_table_member",
        FixtureApplication::ReplaceTableMember => "replace_table_member",
    }
}

fn fixture_value_kind_name(value_kind: FixtureValueKind) -> &'static str {
    match value_kind {
        FixtureValueKind::String => "string",
        FixtureValueKind::StringArray => "string_array",
        FixtureValueKind::Table => "table",
        FixtureValueKind::TableArray => "table_array",
        FixtureValueKind::TableMember => "table_member",
    }
}

fn validate_mutation_fixtures<'a>(
    policy: &'a Policy,
) -> VResult<BTreeMap<&'a str, &'a MutationFixture>> {
    if policy.mutation_fixture.len() != policy.fixture_contract.exact_fixture_count {
        return Err(Diagnostic::error("E_FIXTURE_COUNT", "mutation_fixture")
            .at(policy.mutation_fixture.len().to_string()));
    }
    validate_case_unique(
        policy
            .mutation_fixture
            .iter()
            .map(|fixture| fixture.id.clone()),
        "mutation fixture IDs",
    )?;
    let fixtures = policy
        .mutation_fixture
        .iter()
        .map(|fixture| (fixture.id.as_str(), fixture))
        .collect::<BTreeMap<_, _>>();
    if fixtures.len() != policy.fixture_contract.exact_fixture_count {
        return Err(Diagnostic::error("E_FIXTURE_COUNT", "mutation_fixture"));
    }
    for fixture in &policy.mutation_fixture {
        if fixture.id.is_empty()
            || fixture.id.len() > policy.fixture_contract.max_fixture_id_bytes
            || !fixture.id.is_ascii()
            || fixture.id.bytes().any(|byte| byte.is_ascii_control())
            || fixture.id.starts_with(&policy.fixture_contract.reference_prefix)
            || !fixture_value_kind_matches(fixture, policy)
        {
            return Err(Diagnostic::error("E_FIXTURE_SCHEMA", &fixture.id));
        }
        let mut wrapper = toml::Table::new();
        wrapper.insert("value".to_owned(), fixture.value.clone());
        let encoded = toml::to_string(&wrapper)
            .map_err(|_| Diagnostic::error("E_FIXTURE_SCHEMA", &fixture.id).at("serialize"))?;
        if encoded.is_empty()
            || encoded.len() > policy.fixture_contract.max_fixture_value_bytes
        {
            return Err(Diagnostic::error("E_FIXTURE_BOUND", &fixture.id)
                .at(encoded.len().to_string()));
        }
        let mut nodes = 0;
        validate_fixture_structure(&fixture.value, 0, &mut nodes, policy, &fixture.id)?;
        if fixture.value_kind == FixtureValueKind::TableMember {
            let (relative_selector, _) = fixture_table_member(fixture, &fixture.id)?;
            parse_pointer(relative_selector, &fixture.id)?;
        }
    }
    let mut ordered_fixtures = policy.mutation_fixture.iter().collect::<Vec<_>>();
    ordered_fixtures.sort_by(|left, right| left.id.as_bytes().cmp(right.id.as_bytes()));
    let mut canonical = Vec::new();
    for fixture in ordered_fixtures {
        let fixture_bound = u64::try_from(policy.fixture_contract.max_fixture_value_bytes)
            .map_err(|_| Diagnostic::error("E_FIXTURE_BOUND", &fixture.id))?;
        let mut encoded = ObservationEncoder::new(fixture_bound, &fixture.id)?;
        encoded.extend(b"FND01FIXv1\0")?;
        encode_toml_observation(Some(&fixture.value), &mut encoded)?;
        let value_digest = lower_hex(&sha256(&encoded.bytes));
        for field in [
            fixture.id.as_str(),
            fixture_application_name(fixture.application),
            fixture_value_kind_name(fixture.value_kind),
            value_digest.as_str(),
        ] {
            canonical.extend_from_slice(field.as_bytes());
            canonical.push(0);
        }
        canonical.pop();
        canonical.push(b'\n');
    }
    if canonical.len() != policy.fixture_contract.canonical_bytes
        || lower_hex(&sha256(&canonical)) != policy.fixture_contract.canonical_sha256
    {
        return Err(Diagnostic::error("E_FIXTURE_CANONICAL", "mutation_fixture")
            .at(format!(
                "bytes={};sha256={}",
                canonical.len(),
                lower_hex(&sha256(&canonical))
            )));
    }

    let prefix = policy.fixture_contract.reference_prefix.as_str();
    let mut references = Vec::new();
    for case in &policy.negative_case {
        if let Some(argument) = case.argument.as_deref() {
            if let Some(id) = argument.strip_prefix(prefix) {
                if id.is_empty()
                    || argument[prefix.len()..].contains(':')
                    || !fixture_application_matches_operation(
                        fixtures
                            .get(id)
                            .ok_or_else(|| {
                                Diagnostic::error("E_FIXTURE_MISSING", &case.id).at(id)
                            })?
                            .application,
                        case.operation,
                    )
                {
                    return Err(Diagnostic::error("E_FIXTURE_APPLICATION", &case.id).at(id));
                }
                references.push(id.to_owned());
            } else if argument.contains(prefix) {
                return Err(Diagnostic::error("E_FIXTURE_LITERAL", &case.id));
            }
        }
    }
    validate_case_unique(references.clone(), "mutation fixture references")?;
    let referenced = references.into_iter().collect::<BTreeSet<_>>();
    let declared = fixtures
        .keys()
        .map(|id| (*id).to_owned())
        .collect::<BTreeSet<_>>();
    if referenced != declared {
        return Err(Diagnostic::error("E_FIXTURE_EXACT_SET", "mutation_fixture")
            .at(format!(
                "missing={:?};unused={:?}",
                referenced.difference(&declared).collect::<Vec<_>>(),
                declared.difference(&referenced).collect::<Vec<_>>()
            )));
    }
    Ok(fixtures)
}

fn mutation_argument<'a>(case: &'a NegativeCase) -> VResult<&'a str> {
    case.argument
        .as_deref()
        .filter(|argument| !argument.is_empty())
        .ok_or_else(|| Diagnostic::error("E_MUTATION_SCHEMA", &case.id).at("argument"))
}

fn validate_mutation_field_relevance(
    case: &NegativeCase,
    fixture: Option<&MutationFixture>,
) -> VResult<()> {
    let valid = match case.operation {
        MutationKind::Remove => {
            case.secondary_selector.is_none()
                && match fixture {
                    Some(fixture) => {
                        case.argument.is_some()
                            && fixture.application == FixtureApplication::RemoveExactValue
                    }
                    None => case.argument.is_none(),
                }
        }
        MutationKind::Duplicate => {
            case.argument.is_none() && case.secondary_selector.is_none()
        }
        MutationKind::Swap => {
            case.argument.is_none() && case.secondary_selector.is_some()
        }
        MutationKind::Insert
        | MutationKind::Replace
        | MutationKind::ToggleBool
        | MutationKind::Increment
        | MutationKind::AppendFeature
        | MutationKind::RenameKey
        | MutationKind::ReplaceBytes => {
            case.argument.as_deref().is_some_and(|argument| !argument.is_empty())
                && case.secondary_selector.is_none()
        }
    };
    if !valid {
        return Err(Diagnostic::error("E_MUTATION_FIELD_RELEVANCE", &case.id));
    }
    Ok(())
}

fn mutation_key(case: &NegativeCase) -> String {
    format!("fnd01_{}", &lower_hex(&sha256(case.id.as_bytes()))[..12])
}

fn replacement_value(existing: &toml::Value, argument: &str) -> toml::Value {
    match existing {
        toml::Value::Boolean(_) => argument
            .parse::<bool>()
            .map(toml::Value::Boolean)
            .unwrap_or_else(|_| toml::Value::String(argument.to_owned())),
        toml::Value::Integer(_) => argument
            .parse::<i64>()
            .map(toml::Value::Integer)
            .unwrap_or_else(|_| toml::Value::String(argument.to_owned())),
        toml::Value::Float(_) => argument
            .parse::<f64>()
            .map(toml::Value::Float)
            .unwrap_or_else(|_| toml::Value::String(argument.to_owned())),
        _ => toml::Value::String(argument.to_owned()),
    }
}

fn apply_insert(document: &mut toml::Value, case: &NegativeCase) -> VResult<()> {
    let argument = mutation_argument(case)?;
    let key = mutation_key(case);
    let target = pointer_get_mut(document, &case.target_selector, &case.id)?;
    match target {
        toml::Value::Table(table) => {
            if let Ok(fields) = argument.parse::<toml::Table>() {
                if fields.is_empty() || fields.keys().any(|field| table.contains_key(field)) {
                    return Err(Diagnostic::error("E_MUTATION_SCHEMA", &case.id)
                        .at("insert table collision"));
                }
                table.extend(fields);
            } else if table
                .insert(key, toml::Value::String(argument.to_owned()))
                .is_some()
            {
                return Err(Diagnostic::error("E_MUTATION_SCHEMA", &case.id)
                    .at("insert key collision"));
            }
        }
        toml::Value::Array(array) => {
            array.push(toml::Value::String(argument.to_owned()));
        }
        toml::Value::String(string) => {
            string.push('|');
            string.push_str(argument);
        }
        other => {
            let original = other.clone();
            *other = toml::Value::Array(vec![
                original,
                toml::Value::String(argument.to_owned()),
            ]);
        }
    }
    Ok(())
}

fn values_have_compatible_shape(left: &toml::Value, right: &toml::Value) -> bool {
    match (left, right) {
        (toml::Value::String(_), toml::Value::String(_))
        | (toml::Value::Integer(_), toml::Value::Integer(_))
        | (toml::Value::Float(_), toml::Value::Float(_))
        | (toml::Value::Boolean(_), toml::Value::Boolean(_))
        | (toml::Value::Datetime(_), toml::Value::Datetime(_))
        | (toml::Value::Table(_), toml::Value::Table(_)) => true,
        (toml::Value::Array(left), toml::Value::Array(right)) => {
            left.is_empty()
                || right.is_empty()
                || left
                    .iter()
                    .all(|left_value| {
                        right
                            .iter()
                            .all(|right_value| values_have_compatible_shape(left_value, right_value))
                    })
        }
        _ => false,
    }
}

fn fixture_table_member<'a>(
    fixture: &'a MutationFixture,
    subject: &str,
) -> VResult<(&'a str, &'a toml::Value)> {
    let table = fixture
        .value
        .as_table()
        .ok_or_else(|| Diagnostic::error("E_FIXTURE_SCHEMA", subject).at("table member"))?;
    if table.len() != 2
        || !table
            .keys()
            .map(String::as_str)
            .eq(["relative_selector", "value"])
    {
        return Err(Diagnostic::error("E_FIXTURE_SCHEMA", subject)
            .at("table_member requires exact relative_selector/value fields"));
    }
    let relative_selector = table
        .get("relative_selector")
        .and_then(toml::Value::as_str)
        .filter(|selector| {
            !selector.is_empty()
                && selector.len() <= 512
                && selector.is_ascii()
                && selector.starts_with('/')
                && !selector.bytes().any(|byte| byte.is_ascii_control())
        })
        .ok_or_else(|| {
            Diagnostic::error("E_FIXTURE_SCHEMA", subject).at("table member relative selector")
        })?;
    if selector_targets_forbidden_field(relative_selector, subject)? {
        return Err(Diagnostic::error("E_MUTATION_FORBIDDEN_TARGET", subject)
            .at(relative_selector));
    }
    let value = table
        .get("value")
        .ok_or_else(|| Diagnostic::error("E_FIXTURE_SCHEMA", subject).at("table member value"))?;
    if !fixture_payload_is_nonempty(value) {
        return Err(Diagnostic::error("E_FIXTURE_SCHEMA", subject)
            .at("empty table member value"));
    }
    Ok((relative_selector, value))
}

fn relative_pointer_parent_mut<'a>(
    root: &'a mut toml::Value,
    components: &[String],
    subject: &str,
) -> VResult<(&'a mut toml::Value, String)> {
    let (last, parents) = components
        .split_last()
        .ok_or_else(|| Diagnostic::error("E_FIXTURE_SCHEMA", subject).at("empty relative pointer"))?;
    let mut current = root;
    for component in parents {
        current = match current {
            toml::Value::Table(table) => table.get_mut(component).ok_or_else(|| {
                Diagnostic::error("E_FIXTURE_CANONICAL_VALUE", subject).at(component)
            })?,
            toml::Value::Array(array) => {
                let index =
                    array_selector_index(array, component, subject, "fixture relative selector")?;
                array.get_mut(index).ok_or_else(|| {
                    Diagnostic::error("E_FIXTURE_CANONICAL_VALUE", subject).at(component)
                })?
            }
            _ => {
                return Err(Diagnostic::error("E_FIXTURE_TARGET_TYPE", subject)
                    .at("relative pointer traversal"));
            }
        };
    }
    Ok((current, last.clone()))
}

fn require_toml_table_array_identity(
    document: &toml::Value,
    pointer: &str,
    subject: &str,
) -> VResult<()> {
    let components = parse_pointer(pointer, subject)?;
    let mut current = document;
    for component in components {
        current = match current {
            toml::Value::Table(table) => table
                .get(&component)
                .ok_or_else(|| Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer))?,
            toml::Value::Array(array) => {
                let index = array_selector_index(array, &component, subject, pointer)?;
                let selected = array
                    .get(index)
                    .ok_or_else(|| Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer))?;
                if component.parse::<usize>().is_ok() && selected.as_table().is_some() {
                    return Err(Diagnostic::error(
                        "E_FIXTURE_IDENTITY_REQUIRED",
                        subject,
                    )
                    .at(pointer));
                }
                selected
            }
            _ => {
                return Err(Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer));
            }
        };
    }
    Ok(())
}

fn require_json_table_array_identity(
    document: &StrictJson,
    pointer: &str,
    subject: &str,
) -> VResult<()> {
    let components = parse_pointer(pointer, subject)?;
    let mut current = document;
    for component in components {
        current = match current {
            StrictJson::Object(object) => object
                .get(&component)
                .ok_or_else(|| Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer))?,
            StrictJson::Array(array) => {
                let index = json_array_selector_index(array, &component, subject, pointer)?;
                let selected = array
                    .get(index)
                    .ok_or_else(|| Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer))?;
                if component.parse::<usize>().is_ok()
                    && matches!(selected, StrictJson::Object(_))
                {
                    return Err(Diagnostic::error(
                        "E_FIXTURE_IDENTITY_REQUIRED",
                        subject,
                    )
                    .at(pointer));
                }
                selected
            }
            _ => {
                return Err(Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer));
            }
        };
    }
    Ok(())
}

fn apply_toml_fixture(
    document: &mut toml::Value,
    case: &NegativeCase,
    fixture: &MutationFixture,
) -> VResult<()> {
    match fixture.application {
        FixtureApplication::ReplaceValue => {
            let current = pointer_get(document, &case.target_selector, &case.id)?;
            if current == &fixture.value {
                return Err(Diagnostic::error("E_MUTATION_NOOP", &case.id));
            }
            if !values_have_compatible_shape(current, &fixture.value) {
                return Err(Diagnostic::error("E_FIXTURE_TARGET_TYPE", &case.id));
            }
            set_pointer(
                document,
                &case.target_selector,
                fixture.value.clone(),
                &case.id,
            )
        }
        FixtureApplication::RemoveExactValue => {
            let current = pointer_get(document, &case.target_selector, &case.id)?;
            if current != &fixture.value {
                return Err(Diagnostic::error("E_FIXTURE_CANONICAL_VALUE", &case.id));
            }
            remove_pointer(document, &case.target_selector, &case.id)
        }
        FixtureApplication::InsertArrayElement => {
            let target = pointer_get_mut(document, &case.target_selector, &case.id)?;
            let array = target.as_array_mut().ok_or_else(|| {
                Diagnostic::error("E_FIXTURE_TARGET_TYPE", &case.id).at("array required")
            })?;
            if array.iter().any(|value| value == &fixture.value) {
                return Err(Diagnostic::error("E_FIXTURE_COLLISION", &case.id));
            }
            if array
                .iter()
                .any(|value| !values_have_compatible_shape(value, &fixture.value))
            {
                return Err(Diagnostic::error("E_FIXTURE_TARGET_TYPE", &case.id)
                    .at("array element shape"));
            }
            array.push(fixture.value.clone());
            Ok(())
        }
        FixtureApplication::InsertTableMember => {
            let (relative_selector, value) = fixture_table_member(fixture, &case.id)?;
            let components = parse_pointer(relative_selector, &case.id)?;
            if components.len() != 1 {
                return Err(Diagnostic::error("E_FIXTURE_SCHEMA", &case.id)
                    .at("insert relative selector must contain one component"));
            }
            let key = &components[0];
            let target = pointer_get_mut(document, &case.target_selector, &case.id)?;
            let table = target.as_table_mut().ok_or_else(|| {
                Diagnostic::error("E_FIXTURE_TARGET_TYPE", &case.id).at("table required")
            })?;
            if table.contains_key(key) {
                return Err(Diagnostic::error("E_FIXTURE_COLLISION", &case.id).at(key));
            }
            table.insert(key.to_owned(), value.clone());
            Ok(())
        }
        FixtureApplication::ReplaceTableMember => {
            let (relative_selector, value) = fixture_table_member(fixture, &case.id)?;
            let components = parse_pointer(relative_selector, &case.id)?;
            require_toml_table_array_identity(
                document,
                &case.target_selector,
                &case.id,
            )?;
            let immutable_target =
                pointer_get(document, &case.target_selector, &case.id)?;
            require_toml_table_array_identity(
                immutable_target,
                relative_selector,
                &case.id,
            )?;
            let target = pointer_get_mut(document, &case.target_selector, &case.id)?;
            let (parent, key) = relative_pointer_parent_mut(target, &components, &case.id)?;
            let table = parent.as_table_mut().ok_or_else(|| {
                Diagnostic::error("E_FIXTURE_TARGET_TYPE", &case.id).at("table required")
            })?;
            let current = table
                .get(&key)
                .ok_or_else(|| {
                    Diagnostic::error("E_FIXTURE_CANONICAL_VALUE", &case.id).at(&key)
                })?;
            if current == value {
                return Err(Diagnostic::error("E_MUTATION_NOOP", &case.id));
            }
            if !values_have_compatible_shape(current, value) {
                return Err(Diagnostic::error("E_FIXTURE_TARGET_TYPE", &case.id).at(&key));
            }
            table.insert(key, value.clone());
            Ok(())
        }
    }
}

fn json_values_have_compatible_shape(left: &StrictJson, right: &StrictJson) -> bool {
    match (left, right) {
        (StrictJson::Null, StrictJson::Null)
        | (StrictJson::Bool(_), StrictJson::Bool(_))
        | (StrictJson::Number(_), StrictJson::Number(_))
        | (StrictJson::String(_), StrictJson::String(_))
        | (StrictJson::Object(_), StrictJson::Object(_)) => true,
        (StrictJson::Array(left), StrictJson::Array(right)) => {
            left.is_empty()
                || right.is_empty()
                || left.iter().all(|left_value| {
                    right.iter().all(|right_value| {
                        json_values_have_compatible_shape(left_value, right_value)
                    })
                })
        }
        _ => false,
    }
}

fn json_relative_pointer_parent_mut<'a>(
    root: &'a mut StrictJson,
    components: &[String],
    subject: &str,
) -> VResult<(&'a mut StrictJson, String)> {
    let (last, parents) = components
        .split_last()
        .ok_or_else(|| Diagnostic::error("E_FIXTURE_SCHEMA", subject).at("empty relative pointer"))?;
    let mut current = root;
    for component in parents {
        current = match current {
            StrictJson::Object(object) => object.get_mut(component).ok_or_else(|| {
                Diagnostic::error("E_FIXTURE_CANONICAL_VALUE", subject).at(component)
            })?,
            StrictJson::Array(array) => {
                let index = json_array_selector_index(
                    array,
                    component,
                    subject,
                    "fixture relative selector",
                )?;
                array.get_mut(index).ok_or_else(|| {
                    Diagnostic::error("E_FIXTURE_CANONICAL_VALUE", subject).at(component)
                })?
            }
            _ => {
                return Err(Diagnostic::error("E_FIXTURE_TARGET_TYPE", subject)
                    .at("relative pointer traversal"));
            }
        };
    }
    Ok((current, last.clone()))
}

fn apply_json_fixture(
    document: &mut StrictJson,
    case: &NegativeCase,
    fixture: &MutationFixture,
) -> VResult<()> {
    let fixture_value = fixture_json_value(&fixture.value, &fixture.id)?;
    match fixture.application {
        FixtureApplication::ReplaceValue => {
            let current = json_pointer_get(document, &case.target_selector, &case.id)?;
            if current == &fixture_value {
                return Err(Diagnostic::error("E_MUTATION_NOOP", &case.id));
            }
            if !json_values_have_compatible_shape(current, &fixture_value) {
                return Err(Diagnostic::error("E_FIXTURE_TARGET_TYPE", &case.id));
            }
            json_set_pointer(
                document,
                &case.target_selector,
                fixture_value,
                &case.id,
            )
        }
        FixtureApplication::RemoveExactValue => {
            let current = json_pointer_get(document, &case.target_selector, &case.id)?;
            if current != &fixture_value {
                return Err(Diagnostic::error("E_FIXTURE_CANONICAL_VALUE", &case.id));
            }
            json_remove_pointer(document, &case.target_selector, &case.id)
        }
        FixtureApplication::InsertArrayElement => {
            let target = json_pointer_get_mut(document, &case.target_selector, &case.id)?;
            let StrictJson::Array(array) = target else {
                return Err(Diagnostic::error("E_FIXTURE_TARGET_TYPE", &case.id)
                    .at("array required"));
            };
            if array.iter().any(|value| value == &fixture_value) {
                return Err(Diagnostic::error("E_FIXTURE_COLLISION", &case.id));
            }
            if array
                .iter()
                .any(|value| !json_values_have_compatible_shape(value, &fixture_value))
            {
                return Err(Diagnostic::error("E_FIXTURE_TARGET_TYPE", &case.id)
                    .at("array element shape"));
            }
            array.push(fixture_value);
            Ok(())
        }
        FixtureApplication::InsertTableMember => {
            let (relative_selector, value) = fixture_table_member(fixture, &case.id)?;
            let components = parse_pointer(relative_selector, &case.id)?;
            if components.len() != 1 {
                return Err(Diagnostic::error("E_FIXTURE_SCHEMA", &case.id)
                    .at("insert relative selector must contain one component"));
            }
            let key = &components[0];
            let target = json_pointer_get_mut(document, &case.target_selector, &case.id)?;
            let StrictJson::Object(object) = target else {
                return Err(Diagnostic::error("E_FIXTURE_TARGET_TYPE", &case.id)
                    .at("object required"));
            };
            if object.contains_key(key) {
                return Err(Diagnostic::error("E_FIXTURE_COLLISION", &case.id).at(key));
            }
            object.insert(key.clone(), fixture_json_value(value, &fixture.id)?);
            Ok(())
        }
        FixtureApplication::ReplaceTableMember => {
            let (relative_selector, value) = fixture_table_member(fixture, &case.id)?;
            let components = parse_pointer(relative_selector, &case.id)?;
            require_json_table_array_identity(
                document,
                &case.target_selector,
                &case.id,
            )?;
            let immutable_target =
                json_pointer_get(document, &case.target_selector, &case.id)?;
            require_json_table_array_identity(
                immutable_target,
                relative_selector,
                &case.id,
            )?;
            let target = json_pointer_get_mut(document, &case.target_selector, &case.id)?;
            let (parent, key) =
                json_relative_pointer_parent_mut(target, &components, &case.id)?;
            let StrictJson::Object(object) = parent else {
                return Err(Diagnostic::error("E_FIXTURE_TARGET_TYPE", &case.id)
                    .at("object required"));
            };
            let fixture_value = fixture_json_value(value, &fixture.id)?;
            let current = object.get(&key).ok_or_else(|| {
                Diagnostic::error("E_FIXTURE_CANONICAL_VALUE", &case.id).at(&key)
            })?;
            if current == &fixture_value {
                return Err(Diagnostic::error("E_MUTATION_NOOP", &case.id));
            }
            if !json_values_have_compatible_shape(current, &fixture_value) {
                return Err(Diagnostic::error("E_FIXTURE_TARGET_TYPE", &case.id).at(&key));
            }
            object.insert(key, fixture_value);
            Ok(())
        }
    }
}

fn apply_duplicate(document: &mut toml::Value, case: &NegativeCase) -> VResult<()> {
    let value = pointer_get(document, &case.target_selector, &case.id)?.clone();
    let (parent, component) =
        pointer_parent_mut(document, &case.target_selector, &case.id)?;
    if let toml::Value::Array(array) = parent {
        let index = array_selector_index(array, &component, &case.id, &case.target_selector)?;
        array.insert(
            index
                .checked_add(1)
                .ok_or_else(|| Diagnostic::error("E_MUTATION_SCHEMA", &case.id))?,
            value,
        );
        return Ok(());
    }
    let target = pointer_get_mut(document, &case.target_selector, &case.id)?;
    match target {
        toml::Value::Array(array) => {
            let duplicate = array
                .first()
                .cloned()
                .ok_or_else(|| Diagnostic::error("E_MUTATION_SCHEMA", &case.id).at("empty array"))?;
            array.push(duplicate);
        }
        toml::Value::Table(table) => {
            let duplicate = table
                .values()
                .next()
                .cloned()
                .ok_or_else(|| Diagnostic::error("E_MUTATION_SCHEMA", &case.id).at("empty table"))?;
            let key = mutation_key(case);
            if table.contains_key(&key) {
                return Err(Diagnostic::error("E_MUTATION_SCHEMA", &case.id)
                    .at("duplicate key collision"));
            }
            table.insert(key, duplicate);
        }
        other => {
            let duplicate = other.clone();
            *other = toml::Value::Array(vec![duplicate.clone(), duplicate]);
        }
    }
    Ok(())
}

fn apply_swap(document: &mut toml::Value, case: &NegativeCase) -> VResult<()> {
    let secondary = case
        .secondary_selector
        .as_deref()
        .ok_or_else(|| {
            Diagnostic::error("E_MUTATION_SCHEMA", &case.id)
                .at("swap requires secondary_selector")
        })?;
    let first_components = parse_pointer(&case.target_selector, &case.id)?;
    let second_components = parse_pointer(secondary, &case.id)?;
    if case.target_selector == secondary
        || pointer_component_prefix(&first_components, &second_components)
        || pointer_component_prefix(&second_components, &first_components)
    {
        return Err(Diagnostic::error("E_MUTATION_SCHEMA", &case.id)
            .at("swap selectors must be distinct and pointer-disjoint"));
    }
    let first = pointer_get(document, &case.target_selector, &case.id)?.clone();
    let second = pointer_get(document, secondary, &case.id)?.clone();
    if first == second {
        return Err(Diagnostic::error("E_MUTATION_NOOP", &case.id)
            .at("swap selected equal values"));
    }
    set_pointer(document, secondary, first, &case.id)?;
    set_pointer(document, &case.target_selector, second, &case.id)
}

fn apply_rename_key(document: &mut toml::Value, case: &NegativeCase) -> VResult<()> {
    let argument = mutation_argument(case)?;
    let (parent, component) =
        pointer_parent_mut(document, &case.target_selector, &case.id)?;
    let toml::Value::Table(table) = parent else {
        return Err(Diagnostic::error("E_MUTATION_SCHEMA", &case.id)
            .at("rename_key requires a table member"));
    };
    if argument == component {
        return Err(Diagnostic::error("E_MUTATION_NOOP", &case.id)
            .at("rename key equals selected key"));
    }
    if table.contains_key(argument) {
        return Err(Diagnostic::error("E_MUTATION_SCHEMA", &case.id)
            .at("rename key collision"));
    }
    let value = table
        .remove(&component)
        .ok_or_else(|| Diagnostic::error("E_SEMANTIC_POINTER", &case.id))?;
    table.insert(argument.to_owned(), value);
    Ok(())
}

fn apply_toml_mutation(
    document: &mut toml::Value,
    case: &NegativeCase,
    fixture: Option<&MutationFixture>,
) -> VResult<()> {
    if let Some(fixture) = fixture {
        return apply_toml_fixture(document, case, fixture);
    }
    match case.operation {
        MutationKind::Remove => remove_pointer(document, &case.target_selector, &case.id),
        MutationKind::Insert => apply_insert(document, case),
        MutationKind::Replace => {
            let argument = mutation_argument(case)?;
            let current = pointer_get(document, &case.target_selector, &case.id)?;
            let replacement = replacement_value(current, argument);
            if current == &replacement {
                return Err(Diagnostic::error("E_MUTATION_NOOP", &case.id)
                    .at("replacement equals selected value"));
            }
            set_pointer(
                document,
                &case.target_selector,
                replacement,
                &case.id,
            )
        }
        MutationKind::Swap => apply_swap(document, case),
        MutationKind::Duplicate => apply_duplicate(document, case),
        MutationKind::ToggleBool => {
            let value = pointer_get(document, &case.target_selector, &case.id)?
                .as_bool()
                .ok_or_else(|| Diagnostic::error("E_MUTATION_SCHEMA", &case.id)
                    .at("toggle_bool target"))?;
            let direction = mutation_argument(case)?;
            if (value && direction != "true-to-false")
                || (!value && direction != "false-to-true")
            {
                return Err(Diagnostic::error("E_MUTATION_SCHEMA", &case.id)
                    .at("toggle_bool direction"));
            }
            set_pointer(
                document,
                &case.target_selector,
                toml::Value::Boolean(!value),
                &case.id,
            )
        }
        MutationKind::Increment => {
            let argument = mutation_argument(case)?;
            let delta = argument
                .parse::<i64>()
                .map_err(|_| Diagnostic::error("E_MUTATION_SCHEMA", &case.id).at("increment"))?;
            if delta == 0 || argument != delta.to_string() {
                return Err(Diagnostic::error("E_MUTATION_SCHEMA", &case.id)
                    .at("nonzero canonical increment"));
            }
            let value = pointer_get(document, &case.target_selector, &case.id)?
                .as_integer()
                .ok_or_else(|| Diagnostic::error("E_MUTATION_SCHEMA", &case.id)
                    .at("increment target"))?;
            let incremented = value
                .checked_add(delta)
                .ok_or_else(|| Diagnostic::error("E_MUTATION_SCHEMA", &case.id)
                    .at("integer overflow"))?;
            set_pointer(
                document,
                &case.target_selector,
                toml::Value::Integer(incremented),
                &case.id,
            )
        }
        MutationKind::AppendFeature => {
            let feature = mutation_argument(case)?.to_owned();
            let target = pointer_get_mut(document, &case.target_selector, &case.id)?;
            let array = target
                .as_array_mut()
                .ok_or_else(|| Diagnostic::error("E_MUTATION_SCHEMA", &case.id)
                    .at("append_feature target"))?;
            if array
                .iter()
                .any(|value| value.as_str() == Some(feature.as_str()))
            {
                return Err(Diagnostic::error("E_MUTATION_NOOP", &case.id));
            }
            array.push(toml::Value::String(feature));
            Ok(())
        }
        MutationKind::RenameKey => apply_rename_key(document, case),
        MutationKind::ReplaceBytes => Err(Diagnostic::error("E_MUTATION_SCHEMA", &case.id)
            .at("replace_bytes dispatched as TOML")),
    }
}

fn decode_lower_hex(value: &str, subject: &str) -> VResult<Vec<u8>> {
    if value.len() % 2 != 0
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Diagnostic::error("E_HEX", subject));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair)
                .map_err(|_| Diagnostic::error("E_HEX", subject))?;
            u8::from_str_radix(text, 16)
                .map_err(|_| Diagnostic::error("E_HEX", subject))
        })
        .collect()
}

fn apply_byte_mutation(bytes: &mut Vec<u8>, case: &NegativeCase) -> VResult<()> {
    let components = parse_pointer(&case.target_selector, &case.id)?;
    if components.len() != 2 || components[0] != "bytes" {
        return Err(Diagnostic::error("E_MUTATION_SCHEMA", &case.id).at("byte selector"));
    }
    let argument = mutation_argument(case)?;
    if let Some(hex) = argument.strip_prefix("append-hex:") {
        if components[1] != "end" || hex.is_empty() {
            return Err(Diagnostic::error("E_MUTATION_SCHEMA", &case.id).at("append offset"));
        }
        bytes.extend_from_slice(&decode_lower_hex(hex, &case.id)?);
    } else if let Some(count) = argument.strip_prefix("truncate:") {
        if components[1] != "end"
            || count.is_empty()
            || count == "0"
            || (count.starts_with('0') && count.len() > 1)
            || !count.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(Diagnostic::error("E_MUTATION_SCHEMA", &case.id).at("truncate offset"));
        }
        let count = count
            .parse::<usize>()
            .map_err(|_| Diagnostic::error("E_MUTATION_SCHEMA", &case.id).at("truncate count"))?;
        let new_length = bytes
            .len()
            .checked_sub(count)
            .ok_or_else(|| Diagnostic::error("E_MUTATION_SCHEMA", &case.id).at("truncate bound"))?;
        bytes.truncate(new_length);
    } else if let Some(hex) = argument.strip_prefix("xor:") {
        if hex.len() != 2 {
            return Err(Diagnostic::error("E_MUTATION_SCHEMA", &case.id).at("xor mask"));
        }
        let offset = components[1]
            .parse::<usize>()
            .map_err(|_| Diagnostic::error("E_MUTATION_SCHEMA", &case.id).at("xor offset"))?;
        if components[1] != offset.to_string() {
            return Err(Diagnostic::error("E_MUTATION_SCHEMA", &case.id)
                .at("non-canonical xor offset"));
        }
        let mask = decode_lower_hex(hex, &case.id)?;
        let end = offset
            .checked_add(mask.len())
            .ok_or_else(|| Diagnostic::error("E_MUTATION_SCHEMA", &case.id).at("xor bound"))?;
        if mask.is_empty() || end > bytes.len() {
            return Err(Diagnostic::error("E_MUTATION_SCHEMA", &case.id).at("xor bound"));
        }
        for (byte, mask_byte) in bytes[offset..end].iter_mut().zip(mask) {
            *byte ^= mask_byte;
        }
    } else if argument == "insert-cr-before-lf" {
        let offset = components[1]
            .parse::<usize>()
            .map_err(|_| Diagnostic::error("E_MUTATION_SCHEMA", &case.id).at("CRLF offset"))?;
        if components[1] != offset.to_string()
            || bytes.get(offset).copied() != Some(b'\n')
        {
            return Err(Diagnostic::error("E_MUTATION_SCHEMA", &case.id).at("CRLF target"));
        }
        bytes.insert(offset, b'\r');
    } else {
        return Err(Diagnostic::error("E_MUTATION_SCHEMA", &case.id)
            .at("replace_bytes argument"));
    }
    Ok(())
}

fn selector_targets_forbidden_field(selector: &str, subject: &str) -> VResult<bool> {
    let forbidden = [
        "expected",
        "expected_rule",
        "expected_diagnostic",
        "result",
        "verified",
        "mutation",
        "mutation_test_status",
    ];
    Ok(parse_pointer(selector, subject)?.iter().any(|component| {
        let name = component
            .split_once('=')
            .map_or(component.as_str(), |(key, _)| key)
            .to_ascii_lowercase();
        forbidden.iter().any(|field| name == *field)
    }))
}

fn virtual_source_subset_digest(
    files: &[LoadedFile],
    target_path: &str,
    replacement: &[u8],
    family: Option<&str>,
) -> VResult<[u8; 32]> {
    let mut ordered = files
        .iter()
        .filter(|file| family.is_none_or(|family| file.contract.family == family))
        .collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.contract.path.cmp(&right.contract.path));
    let mut hasher = Sha256::new();
    let mut target_seen = false;
    for file in ordered {
        let path = file.contract.path.as_bytes();
        let path_length = u32::try_from(path.len())
            .map_err(|_| Diagnostic::error("E_TREE_BOUND", &file.contract.path))?;
        let (length, digest) = if file.contract.path == target_path {
            target_seen = true;
            (
                u64::try_from(replacement.len())
                    .map_err(|_| Diagnostic::error("E_TREE_BOUND", target_path))?,
                sha256(replacement),
            )
        } else {
            (file.contract.byte_length, file.digest)
        };
        hasher.update(path_length.to_be_bytes());
        hasher.update(path);
        hasher.update(length.to_be_bytes());
        hasher.update(digest);
    }
    if !target_seen {
        return Err(Diagnostic::error("E_MUTATION_TARGET", target_path)
            .at(family.unwrap_or("source tree")));
    }
    Ok(hasher.finalize().into())
}

impl<'a> Corpus66<'a> {
    fn checked(
        files: &'a [LoadedFile],
        policy: &Policy,
    ) -> VResult<Self> {
        if files.len() != EXPECTED_SOURCE_FILES
            || policy.source_tree.file_count != EXPECTED_SOURCE_FILES
        {
            return Err(Diagnostic::error("E_CORPUS66_COUNT", "immutable mutation corpus")
                .at(files.len().to_string()));
        }
        let mut by_path = BTreeMap::new();
        for (index, file) in files.iter().enumerate() {
            let byte_length = u64::try_from(file.bytes.len())
                .map_err(|_| Diagnostic::error("E_CORPUS66_BOUND", &file.contract.path))?;
            if byte_length != file.contract.byte_length
                || sha256(&file.bytes) != file.digest
                || lower_hex(&file.digest) != file.contract.sha256
            {
                return Err(Diagnostic::error("E_CORPUS66_BINDING", &file.contract.path));
            }
            if by_path.insert(file.contract.path.clone(), index).is_some() {
                return Err(Diagnostic::error("E_CORPUS66_DUPLICATE", &file.contract.path));
            }
        }
        let references = files.iter().collect::<Vec<_>>();
        let (tree, _) = source_tree_digest_refs(&references)?;
        if lower_hex(&tree) != policy.source_tree.sha256 {
            return Err(Diagnostic::error("E_CORPUS66_TREE", "immutable mutation corpus")
                .at(lower_hex(&tree)));
        }
        for family in &policy.source_family {
            let family_files = files
                .iter()
                .filter(|file| file.contract.family == family.id)
                .collect::<Vec<_>>();
            let (digest, byte_length) = source_tree_digest_refs(&family_files)?;
            if family_files.len() != family.file_count
                || byte_length != family.total_bytes
                || lower_hex(&digest) != family.tree_sha256
            {
                return Err(Diagnostic::error("E_CORPUS66_FAMILY", &family.id));
            }
        }

        let mut toml_documents = BTreeMap::new();
        let mut json_documents = BTreeMap::new();
        for assertion in &policy.semantic_assertion {
            let index = by_path
                .get(assertion.source_path.as_str())
                .copied()
                .ok_or_else(|| {
                    Diagnostic::error("E_CORPUS66_PATH", &assertion.id)
                        .at(&assertion.source_path)
                })?;
            let file = &files[index];
            match assertion.observation_mode {
                AssertionObservationMode::CanonicalSelectedToml => {
                    if file.contract.parse_kind != FileFamily::Toml {
                        return Err(Diagnostic::error("E_OBSERVATION_DOMAIN", &assertion.id));
                    }
                    if !toml_documents.contains_key(assertion.source_path.as_str()) {
                        let text = std::str::from_utf8(&file.bytes)
                            .map_err(|_| Diagnostic::error("E_UTF8", &assertion.source_path))?;
                        let document = text.parse::<toml::Value>().map_err(|_| {
                            Diagnostic::error("E_TOML_SYNTAX", &assertion.source_path)
                        })?;
                        toml_documents.insert(assertion.source_path.clone(), document);
                    }
                }
                AssertionObservationMode::CanonicalSelectedJson => {
                    if file.contract.parse_kind != FileFamily::Json {
                        return Err(Diagnostic::error("E_OBSERVATION_DOMAIN", &assertion.id));
                    }
                    if !json_documents.contains_key(assertion.source_path.as_str()) {
                        json_documents.insert(
                            assertion.source_path.clone(),
                            parse_strict_json(&file.bytes, &assertion.source_path)?,
                        );
                    }
                }
                AssertionObservationMode::RawSourceBytes => {}
            }
        }
        Ok(Self {
            files,
            by_path,
            toml_documents,
            json_documents,
        })
    }

    fn file(&self, path: &str) -> VResult<&LoadedFile> {
        self.by_path
            .get(path)
            .and_then(|index| self.files.get(*index))
            .ok_or_else(|| Diagnostic::error("E_CORPUS66_PATH", path))
    }

    fn toml(&self, path: &str, subject: &str) -> VResult<&toml::Value> {
        self.toml_documents
            .get(path)
            .ok_or_else(|| Diagnostic::error("E_OBSERVATION_DOMAIN", subject).at(path))
    }

    fn json(&self, path: &str, subject: &str) -> VResult<&StrictJson> {
        self.json_documents
            .get(path)
            .ok_or_else(|| Diagnostic::error("E_OBSERVATION_DOMAIN", subject).at(path))
    }
}

impl<'a> Overlay<'a> {
    fn checked(
        corpus: &Corpus66<'_>,
        case: &'a NegativeCase,
        fixture: Option<&MutationFixture>,
        policy: &Policy,
    ) -> VResult<Self> {
        let source = corpus.file(&case.target_path)?;
        let mut toml_document = None;
        let mut json_document = None;
        let bytes = if case.operation == MutationKind::ReplaceBytes {
            let mut bytes = source.bytes.clone();
            apply_byte_mutation(&mut bytes, case)?;
            match source.contract.parse_kind {
                FileFamily::Toml => {
                    let text = std::str::from_utf8(&bytes)
                        .map_err(|_| Diagnostic::error("E_UTF8", &case.id))?;
                    toml_document = Some(text.parse::<toml::Value>().map_err(|_| {
                        Diagnostic::error("E_TOML_SYNTAX", &case.id)
                    })?);
                }
                FileFamily::Json => {
                    json_document = Some(parse_strict_json(&bytes, &case.id)?);
                }
                FileFamily::Utf8Text
                | FileFamily::OpaqueBinary
                | FileFamily::GzipTar => {}
            }
            bytes
        } else {
            match source.contract.parse_kind {
                FileFamily::Toml => {
                    let mut document = corpus.toml(&case.target_path, &case.id)?.clone();
                    pointer_get(&document, &case.target_selector, &case.id)?;
                    apply_toml_mutation(&mut document, case, fixture)?;
                    let bytes = toml::to_string(&document)
                        .map_err(|_| Diagnostic::error("E_MUTATION_SERIALIZE", &case.id))?
                        .into_bytes();
                    let text = std::str::from_utf8(&bytes)
                        .map_err(|_| Diagnostic::error("E_UTF8", &case.id))?;
                    toml_document = Some(text.parse::<toml::Value>().map_err(|_| {
                        Diagnostic::error("E_TOML_SYNTAX", &case.id)
                    })?);
                    bytes
                }
                FileFamily::Json => {
                    let mut document = corpus.json(&case.target_path, &case.id)?.clone();
                    json_pointer_get(&document, &case.target_selector, &case.id)?;
                    let fixture = fixture.ok_or_else(|| {
                        Diagnostic::error("E_MUTATION_SCHEMA", &case.id)
                            .at("structured JSON mutation requires typed fixture")
                    })?;
                    apply_json_fixture(&mut document, case, fixture)?;
                    let mut nodes = 0;
                    validate_json_bounds(&document, 0, &mut nodes, &case.id)?;
                    let bytes = serde_json::to_vec(&document)
                        .map_err(|_| Diagnostic::error("E_MUTATION_SERIALIZE", &case.id))?;
                    json_document = Some(parse_strict_json(&bytes, &case.id)?);
                    bytes
                }
                FileFamily::Utf8Text
                | FileFamily::OpaqueBinary
                | FileFamily::GzipTar => {
                    return Err(Diagnostic::error("E_MUTATION_SOURCE_TYPE", &case.id)
                        .at("structured TOML or JSON source required"));
                }
            }
        };
        if sha256(&bytes) == source.digest {
            return Err(Diagnostic::error("E_MUTATION_NOOP", &case.id));
        }
        let byte_length = u64::try_from(bytes.len())
            .map_err(|_| Diagnostic::error("E_MUTATION_BOUND", &case.id))?;
        if byte_length > policy.bounds.max_source_file_bytes {
            return Err(Diagnostic::error("E_MUTATION_BOUND", &case.id));
        }
        let file_digest = sha256(&bytes);
        let family_digest = virtual_source_subset_digest(
            corpus.files,
            &case.target_path,
            &bytes,
            Some(&source.contract.family),
        )?;
        let family_contract = policy
            .source_family
            .iter()
            .find(|family| family.id == source.contract.family)
            .ok_or_else(|| Diagnostic::error("E_SOURCE_FAMILY", &source.contract.family))?;
        if lower_hex(&family_digest) == family_contract.tree_sha256 {
            return Err(Diagnostic::error("E_MUTATION_NOOP", &case.id)
                .at("virtual source-family tree"));
        }
        let family_byte_length = family_contract
            .total_bytes
            .checked_sub(source.contract.byte_length)
            .and_then(|length| length.checked_add(byte_length))
            .ok_or_else(|| {
                Diagnostic::error("E_MUTATION_BOUND", &case.id)
                    .at("virtual source-family length")
            })?;
        let tree_digest =
            virtual_source_subset_digest(corpus.files, &case.target_path, &bytes, None)?;
        if lower_hex(&tree_digest) == policy.source_tree.sha256 {
            return Err(Diagnostic::error("E_MUTATION_NOOP", &case.id)
                .at("virtual source tree"));
        }
        let tree_byte_length = policy
            .source_tree
            .total_bytes
            .checked_sub(source.contract.byte_length)
            .and_then(|length| length.checked_add(byte_length))
            .ok_or_else(|| {
                Diagnostic::error("E_MUTATION_BOUND", &case.id)
                    .at("virtual source-tree length")
            })?;
        Ok(Self {
            target_path: case.target_path.as_str(),
            bytes,
            toml_document,
            json_document,
            file_binding: VirtualBinding {
                byte_length,
                sha256: file_digest,
            },
            family_binding: VirtualBinding {
                byte_length: family_byte_length,
                sha256: family_digest,
            },
            tree_binding: VirtualBinding {
                byte_length: tree_byte_length,
                sha256: tree_digest,
            },
        })
    }
}

fn assertion_observation_mode_name(mode: AssertionObservationMode) -> &'static str {
    match mode {
        AssertionObservationMode::CanonicalSelectedToml => "canonical_selected_toml",
        AssertionObservationMode::CanonicalSelectedJson => "canonical_selected_json",
        AssertionObservationMode::RawSourceBytes => "raw_source_bytes",
    }
}

fn assertion_violation_mode_name(mode: AssertionViolationMode) -> &'static str {
    match mode {
        AssertionViolationMode::ExactObservationSha256 => "exact_observation_sha256",
    }
}

fn same_observation_identity(
    left: &SemanticAssertion,
    right: &SemanticAssertion,
) -> bool {
    left.source_path == right.source_path
        && left.observation_mode == right.observation_mode
        && left.selector == right.selector
        && left.secondary_selector == right.secondary_selector
}

fn strings_are_strictly_raw_sorted(values: &[String]) -> bool {
    values
        .windows(2)
        .all(|pair| pair[0].as_bytes() < pair[1].as_bytes())
}

fn assertion_negative_id<'a>(assertion: &'a SemanticAssertion) -> VResult<&'a str> {
    let prefix = format!("{}.", assertion.family);
    assertion
        .id
        .strip_prefix(&prefix)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| Diagnostic::error("E_ASSERTION_IDENTITY", &assertion.id))
}

fn finding_from_assertion(
    assertion: &SemanticAssertion,
    observation_sha256: String,
) -> VResult<MutationFinding> {
    let negative_id = assertion_negative_id(assertion)?;
    let diagnostic = NegativeDiagnostic {
        family: assertion.family.clone(),
        id: negative_id.to_owned(),
        rule: assertion.rule.clone(),
        logical_path: assertion.logical_path.clone(),
    }
    .stable();
    Ok(MutationFinding {
        assertion_id: assertion.id.clone(),
        rule: assertion.rule.clone(),
        logical_path: assertion.logical_path.clone(),
        diagnostic,
        observation_sha256,
    })
}

fn validate_finding_authority(
    finding: &MutationFinding,
    assertions: &BTreeMap<&str, &SemanticAssertion>,
) -> VResult<()> {
    validate_sha256(&finding.observation_sha256, &finding.assertion_id)?;
    let owner = assertions
        .get(finding.assertion_id.as_str())
        .copied()
        .ok_or_else(|| {
            Diagnostic::error("E_ASSERTION_REFERENCE_UNKNOWN", &finding.assertion_id)
        })?;
    let expected = finding_from_assertion(
        owner,
        owner.violating_observation_sha256.clone(),
    )?;
    if finding != &expected {
        return Err(Diagnostic::error(
            "E_MUTATION_DIAGNOSTIC",
            &finding.assertion_id,
        )
        .at(&finding.diagnostic));
    }
    Ok(())
}

fn assertion_document<'view>(
    corpus: &'view Corpus66<'_>,
    overlay: Option<&'view Overlay<'_>>,
    assertion: &SemanticAssertion,
) -> VResult<ObservationDocument<'view>> {
    let overlaid = overlay
        .filter(|overlay| overlay.target_path == assertion.source_path);
    match assertion.observation_mode {
        AssertionObservationMode::CanonicalSelectedToml => {
            let document = if let Some(overlay) = overlaid {
                overlay.toml_document.as_ref().ok_or_else(|| {
                    Diagnostic::error("E_MUTATION_SOURCE_TYPE", &assertion.id)
                        .at("strict TOML overlay")
                })?
            } else {
                corpus.toml(&assertion.source_path, &assertion.id)?
            };
            Ok(ObservationDocument::Toml(document))
        }
        AssertionObservationMode::CanonicalSelectedJson => {
            let document = if let Some(overlay) = overlaid {
                overlay.json_document.as_ref().ok_or_else(|| {
                    Diagnostic::error("E_MUTATION_SOURCE_TYPE", &assertion.id)
                        .at("strict JSON overlay")
                })?
            } else {
                corpus.json(&assertion.source_path, &assertion.id)?
            };
            Ok(ObservationDocument::Json(document))
        }
        AssertionObservationMode::RawSourceBytes => {
            let bytes = if let Some(overlay) = overlaid {
                overlay.bytes.as_slice()
            } else {
                corpus.file(&assertion.source_path)?.bytes.as_slice()
            };
            Ok(ObservationDocument::Raw(bytes))
        }
    }
}

fn scan_assertion_registry(
    corpus: &Corpus66<'_>,
    overlay: Option<&Overlay<'_>>,
    case: Option<&NegativeCase>,
    policy: &Policy,
    assertions: &BTreeMap<&str, &SemanticAssertion>,
    violation_owners: &BTreeMap<String, Vec<&SemanticAssertion>>,
) -> VResult<Vec<MutationFinding>> {
    let mut findings = Vec::new();
    let mut finding_ids = BTreeSet::new();
    for assertion in &policy.semantic_assertion {
        let actual = observation_digest(
            assertion,
            assertion_document(corpus, overlay, assertion)?,
            policy,
        )?;
        let actual_hex = lower_hex(&actual);
        if overlay.is_none() {
            if actual_hex != assertion.baseline_observation_sha256 {
                return Err(Diagnostic::error("E_ASSERTION_BASELINE", &assertion.id)
                    .at(actual_hex));
            }
        } else if let Some(case) = case {
            if !assertion_overlaps_mutation(assertion, case)?
                && actual_hex != assertion.baseline_observation_sha256
            {
                return Err(Diagnostic::error("E_ASSERTION_BASELINE_DRIFT", &assertion.id)
                    .at(&case.id));
            }
        } else {
            return Err(Diagnostic::error(
                "E_ASSERTION_SCAN_MODE",
                "overlay scan requires its negative case",
            ));
        }
        if let Some(owners) = violation_owners.get(&actual_hex) {
            for owner in owners {
                if owner.id != assertion.id
                    && !same_observation_identity(assertion, owner)
                {
                    return Err(Diagnostic::error("E_ASSERTION_CROSS_TRIGGER", &assertion.id)
                        .at(&owner.id));
                }
            }
        }
        if actual_hex == assertion.violating_observation_sha256 {
            if !assertions.contains_key(assertion.id.as_str())
                || !finding_ids.insert(assertion.id.as_str())
            {
                return Err(Diagnostic::error("E_ASSERTION_DUPLICATE_FINDING", &assertion.id));
            }
            findings.push(finding_from_assertion(assertion, actual_hex)?);
        }
    }
    Ok(findings)
}

fn resolve_findings(
    primary: &SemanticAssertion,
    findings: Vec<MutationFinding>,
) -> VResult<FindingResolution> {
    let mut actual = BTreeMap::new();
    for finding in findings {
        let id = finding.assertion_id.clone();
        if actual.insert(id.clone(), finding).is_some() {
            return Err(Diagnostic::error("E_ASSERTION_DUPLICATE_FINDING", id));
        }
    }
    let primary_finding = actual
        .remove(&primary.id)
        .ok_or_else(|| Diagnostic::error("E_ASSERTION_PRIMARY_MISSING", &primary.id))?;
    let mut emitted = vec![primary_finding];
    for id in &primary.allowed_cotrigger_ids {
        if let Some(finding) = actual.remove(id) {
            emitted.push(finding);
        }
    }
    let mut suppressed = Vec::new();
    for id in &primary.suppressed_ids {
        if let Some(finding) = actual.remove(id) {
            suppressed.push(finding);
        }
    }
    if !actual.is_empty() {
        return Err(Diagnostic::error("E_ASSERTION_UNEXPECTED_FINDING", &primary.id)
            .at(format!("{:?}", actual.keys().collect::<Vec<_>>())));
    }
    if emitted.len() != primary.expected_trigger_count {
        return Err(Diagnostic::error("E_ASSERTION_TRIGGER_COUNT", &primary.id)
            .at(format!(
                "expected={};actual={}",
                primary.expected_trigger_count,
                emitted.len()
            )));
    }
    Ok(FindingResolution {
        emitted,
        suppressed,
    })
}

fn validate_assertion_references(
    assertions: &BTreeMap<&str, &SemanticAssertion>,
) -> VResult<()> {
    for assertion in assertions.values() {
        let maximum_expected_trigger_count = assertion
            .allowed_cotrigger_ids
            .len()
            .checked_add(1)
            .ok_or_else(|| {
                Diagnostic::error("E_ASSERTION_REFERENCE_BOUND", &assertion.id)
                    .at("allowed cotrigger count overflow")
            })?;
        if !strings_are_strictly_raw_sorted(&assertion.allowed_cotrigger_ids)
            || !strings_are_strictly_raw_sorted(&assertion.suppressed_ids)
            || assertion.expected_trigger_count == 0
            || assertion.expected_trigger_count > maximum_expected_trigger_count
        {
            return Err(Diagnostic::error("E_ASSERTION_REFERENCE_ORDER", &assertion.id));
        }
        let allowed = assertion
            .allowed_cotrigger_ids
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let suppressed = assertion
            .suppressed_ids
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if allowed.contains(assertion.id.as_str())
            || suppressed.contains(assertion.id.as_str())
            || !allowed.is_disjoint(&suppressed)
        {
            return Err(Diagnostic::error("E_ASSERTION_REFERENCE_OVERLAP", &assertion.id));
        }
        for reference in allowed.iter().chain(&suppressed) {
            if !assertions.contains_key(*reference) {
                return Err(Diagnostic::error("E_ASSERTION_REFERENCE_UNKNOWN", &assertion.id)
                    .at(*reference));
            }
        }
    }
    Ok(())
}

fn validate_quarantine_mutation_boundary(
    case: &NegativeCase,
    fixture: Option<&MutationFixture>,
    policy: &Policy,
) -> VResult<()> {
    let target = parse_pointer(&case.target_selector, &case.id)?;
    let (targets_tasks_quarantine, targets_apps_quarantine) =
        task_app_quarantine_overlap(&case.target_path, &target);
    let (secondary_targets_tasks_quarantine, secondary_targets_apps_quarantine) =
        match case.secondary_selector.as_deref() {
            Some(selector) => {
                let secondary = parse_pointer(selector, &case.id)?;
                task_app_quarantine_overlap(&case.target_path, &secondary)
            }
            None => (false, false),
        };
    let targets_jose_quarantine = policy.quarantine.iter().any(|row| {
        row.source_selector == "/" && row.source_path == case.target_path
    });
    if targets_apps_quarantine
        || secondary_targets_tasks_quarantine
        || secondary_targets_apps_quarantine
        || targets_jose_quarantine
    {
        return Err(Diagnostic::error("E_QUARANTINE_MUTATION", &case.id)
            .at(&case.target_selector));
    }
    if targets_tasks_quarantine {
        let expected_selector = "/tasks/quarantine/id=tasks-raw-result-composition";
        let exact_row = policy.quarantine.iter().any(|row| {
            row.id == "tasks-raw-result-composition"
                && row.source_path == case.target_path
                && row.source_selector == expected_selector
                && !row.execution_allowed
                && !row.mutation_allowed
                && !row.promotion_allowed
        });
        if case.family != "tasks_apps"
            || case.id != "quarantine-drift"
            || case.target_selector != expected_selector
            || case.operation != MutationKind::Remove
            || case.argument.is_some()
            || case.secondary_selector.is_some()
            || fixture.is_some()
            || !exact_row
        {
            return Err(Diagnostic::error("E_QUARANTINE_MUTATION", &case.id)
                .at(&case.target_selector));
        }
    } else if case.family == "tasks_apps" && case.id == "quarantine-drift" {
        return Err(Diagnostic::error("E_QUARANTINE_MUTATION", &case.id)
            .at("named structural removal required"));
    }
    Ok(())
}

fn validate_assertion_canonical_registry(policy: &Policy) -> VResult<()> {
    let mut assertions = policy.semantic_assertion.iter().collect::<Vec<_>>();
    assertions.sort_by(|left, right| left.id.as_bytes().cmp(right.id.as_bytes()));
    let mut canonical = Vec::with_capacity(policy.assertion_contract.canonical_bytes);
    canonical.extend_from_slice(b"FND01ASTv2\0");
    canonical_u32(&mut canonical, assertions.len(), "semantic_assertion")?;
    for assertion in assertions {
        for field in [
            assertion.id.as_str(),
            assertion.family.as_str(),
            assertion.source_path.as_str(),
            assertion.selector.as_str(),
        ] {
            canonical_string(&mut canonical, field, &assertion.id)?;
        }
        canonical_optional_string(
            &mut canonical,
            assertion.secondary_selector.as_deref(),
            &assertion.id,
        )?;
        for field in [
            assertion.rule.as_str(),
            assertion.logical_path.as_str(),
            assertion.baseline_mode.as_str(),
            assertion_observation_mode_name(assertion.observation_mode),
            assertion.baseline_observation_sha256.as_str(),
            assertion_violation_mode_name(assertion.violation_mode),
            assertion.violating_observation_sha256.as_str(),
        ] {
            canonical_string(&mut canonical, field, &assertion.id)?;
        }
        canonical_u32(
            &mut canonical,
            assertion.expected_trigger_count,
            &assertion.id,
        )?;
        canonical_u32(
            &mut canonical,
            assertion.allowed_cotrigger_ids.len(),
            &assertion.id,
        )?;
        for cotrigger in &assertion.allowed_cotrigger_ids {
            canonical_string(&mut canonical, cotrigger, &assertion.id)?;
        }
        canonical_u32(
            &mut canonical,
            assertion.suppressed_ids.len(),
            &assertion.id,
        )?;
        for suppressed in &assertion.suppressed_ids {
            canonical_string(&mut canonical, suppressed, &assertion.id)?;
        }
    }
    let digest = lower_hex(&sha256(&canonical));
    if canonical.len() != ASSERTION_CANONICAL_BYTES
        || digest != ASSERTION_CANONICAL_SHA256
        || canonical.len() != policy.assertion_contract.canonical_bytes
        || digest != policy.assertion_contract.canonical_sha256
    {
        return Err(Diagnostic::error(
            "E_ASSERTION_CANONICAL",
            "semantic_assertion",
        )
        .at(format!("bytes={};sha256={digest}", canonical.len())));
    }
    Ok(())
}

fn validate_mutation_dispatch(files: &[LoadedFile], policy: &Policy) -> VResult<()> {
    if policy.semantic_assertion.len() != EXPECTED_NEGATIVES
        || policy.negative_case.len() != EXPECTED_NEGATIVES
    {
        return Err(Diagnostic::error("E_SEMANTIC_ASSERTION_COUNT", "semantic_assertion")
            .at(format!(
                "assertions={};cases={}",
                policy.semantic_assertion.len(),
                policy.negative_case.len()
            )));
    }
    validate_case_unique(
        policy
            .semantic_assertion
            .iter()
            .map(|assertion| assertion.id.clone()),
        "semantic assertions",
    )?;
    validate_case_unique(
        policy
            .negative_case
            .iter()
            .map(|case| case.validator.clone()),
        "negative validators",
    )?;
    validate_case_unique(
        policy
            .negative_case
            .iter()
            .map(|case| format!("{}/{}", case.family, case.id)),
        "negative case identities",
    )?;

    let assertions = policy
        .semantic_assertion
        .iter()
        .map(|assertion| (assertion.id.as_str(), assertion))
        .collect::<BTreeMap<_, _>>();
    if assertions.len() != EXPECTED_NEGATIVES {
        return Err(Diagnostic::error(
            "E_SEMANTIC_ASSERTION_COUNT",
            "semantic assertion map",
        )
        .at(assertions.len().to_string()));
    }
    validate_assertion_references(&assertions)?;

    let cases_by_validator = policy
        .negative_case
        .iter()
        .map(|case| (case.validator.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    if cases_by_validator.len() != EXPECTED_NEGATIVES {
        return Err(Diagnostic::error("E_MUTATION_COUNT", "negative validator map")
            .at(cases_by_validator.len().to_string()));
    }

    let specs = negative_specs();
    if specs.len() != EXPECTED_NEGATIVES {
        return Err(Diagnostic::error("E_STATIC_NEGATIVE_COUNT", "verifier registry")
            .at(specs.len().to_string()));
    }
    let expected_case_keys = specs
        .iter()
        .map(|spec| format!("{}/{}", spec.family, spec.id))
        .collect::<BTreeSet<_>>();
    let actual_case_keys = policy
        .negative_case
        .iter()
        .map(|case| format!("{}/{}", case.family, case.id))
        .collect::<BTreeSet<_>>();
    let expected_assertion_ids = specs
        .iter()
        .map(|spec| format!("{}.{}", spec.family, spec.id))
        .collect::<BTreeSet<_>>();
    let actual_assertion_ids = assertions
        .keys()
        .map(|id| (*id).to_owned())
        .collect::<BTreeSet<_>>();
    let actual_validator_ids = cases_by_validator
        .keys()
        .map(|id| (*id).to_owned())
        .collect::<BTreeSet<_>>();
    if expected_case_keys.len() != EXPECTED_NEGATIVES
        || expected_assertion_ids.len() != EXPECTED_NEGATIVES
        || actual_case_keys != expected_case_keys
        || actual_assertion_ids != expected_assertion_ids
        || actual_validator_ids != expected_assertion_ids
    {
        return Err(Diagnostic::error(
            "E_MUTATION_EXACT_SET",
            "recipe/assertion/negative registry bijection",
        ));
    }

    let family_order = policy
        .negative_inventory
        .family_order
        .iter()
        .enumerate()
        .map(|(index, family)| (family.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    if family_order.len() != policy.negative_inventory.family_order.len() {
        return Err(Diagnostic::error(
            "E_MUTATION_FAMILY",
            "duplicate negative family order",
        ));
    }
    let family_counts = policy
        .negative_family
        .iter()
        .map(|family| (family.id.as_str(), family.count))
        .collect::<BTreeMap<_, _>>();
    if family_counts.len() != policy.negative_family.len()
        || family_counts.keys().copied().collect::<BTreeSet<_>>()
            != family_order.keys().copied().collect::<BTreeSet<_>>()
    {
        return Err(Diagnostic::error(
            "E_MUTATION_FAMILY",
            "negative family registry",
        ));
    }
    let mut seen_source_indices = BTreeSet::new();
    for case in &policy.negative_case {
        let count = family_counts
            .get(case.family.as_str())
            .copied()
            .ok_or_else(|| Diagnostic::error("E_MUTATION_FAMILY", &case.id))?;
        if case.source_index >= count
            || !seen_source_indices.insert((case.family.clone(), case.source_index))
        {
            return Err(Diagnostic::error("E_MUTATION_SOURCE_INDEX", &case.id)
                .at(case.source_index.to_string()));
        }
    }
    for (family, count) in &family_counts {
        for source_index in 0..*count {
            if !seen_source_indices.contains(&((*family).to_owned(), source_index)) {
                return Err(Diagnostic::error("E_MUTATION_SOURCE_INDEX", *family)
                    .at(source_index.to_string()));
            }
        }
    }
    if seen_source_indices.len() != EXPECTED_NEGATIVES {
        return Err(Diagnostic::error(
            "E_MUTATION_SOURCE_INDEX",
            "canonical negative source indices",
        )
        .at(seen_source_indices.len().to_string()));
    }

    for assertion in &policy.semantic_assertion {
        let case = cases_by_validator
            .get(assertion.id.as_str())
            .copied()
            .ok_or_else(|| Diagnostic::error("E_MUTATION_ASSERTION", &assertion.id))?;
        validate_sha256(
            &assertion.baseline_observation_sha256,
            &assertion.id,
        )?;
        validate_sha256(
            &assertion.violating_observation_sha256,
            &assertion.id,
        )?;
        validate_ascii_posix_path(&assertion.source_path, &assertion.id)?;
        let negative_id = assertion_negative_id(assertion)?;
        if assertion.id.is_empty()
            || assertion.id.len() > policy.bounds.max_selector_bytes
            || !assertion.id.is_ascii()
            || assertion
                .id
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b'|')
            || assertion.family.is_empty()
            || assertion.family.len() > policy.bounds.max_id_bytes
            || !assertion.family.is_ascii()
            || assertion
                .family
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b'|')
            || assertion.rule.is_empty()
            || assertion.rule.len() > policy.bounds.max_selector_bytes
            || !assertion.rule.is_ascii()
            || assertion
                .rule
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b'|')
            || assertion.logical_path.is_empty()
            || assertion.logical_path.len() > policy.bounds.max_selector_bytes
            || !assertion.logical_path.is_ascii()
            || assertion.logical_path.contains('|')
            || assertion.selector.len() > policy.bounds.max_selector_bytes
            || !assertion.selector.is_ascii()
            || assertion.secondary_selector.as_ref().is_some_and(|selector| {
                selector.is_empty()
                    || selector.len() > policy.bounds.max_selector_bytes
                    || !selector.is_ascii()
            })
            || assertion.family != case.family
            || negative_id != case.id
            || case.validator != assertion.id
            || case.validator != format!("{}.{}", case.family, case.id)
            || assertion.source_path != case.target_path
            || assertion.baseline_mode != "canonical_source_value"
            || assertion.violation_mode
                != AssertionViolationMode::ExactObservationSha256
            || assertion.baseline_observation_sha256
                == assertion.violating_observation_sha256
            || (case.operation == MutationKind::ReplaceBytes
                && (assertion.selector != case.target_selector
                    || assertion.observation_mode
                        != AssertionObservationMode::RawSourceBytes))
            || (case.operation == MutationKind::Swap
                && (assertion.selector != case.target_selector
                    || assertion.secondary_selector != case.secondary_selector))
            || (case.operation != MutationKind::Swap
                && assertion.secondary_selector.is_some())
            || !assertion_overlaps_mutation(assertion, case)?
        {
            return Err(Diagnostic::error("E_MUTATION_ASSERTION", &case.id));
        }
        parse_pointer(&assertion.selector, &assertion.id)?;
        parse_pointer(&assertion.logical_path, &assertion.id)?;
        if selector_targets_forbidden_field(&assertion.selector, &case.id)?
            || selector_targets_forbidden_field(&assertion.logical_path, &case.id)?
        {
            return Err(Diagnostic::error("E_MUTATION_FORBIDDEN_TARGET", &case.id));
        }
        if let Some(secondary) = &assertion.secondary_selector {
            parse_pointer(secondary, &assertion.id)?;
            if selector_targets_forbidden_field(secondary, &case.id)? {
                return Err(Diagnostic::error("E_MUTATION_FORBIDDEN_TARGET", &case.id));
            }
        }
        let source = source_lookup(files, &assertion.source_path)?;
        let expected_observation_mode = if case.operation == MutationKind::ReplaceBytes {
            AssertionObservationMode::RawSourceBytes
        } else {
            match source.contract.parse_kind {
                FileFamily::Toml => AssertionObservationMode::CanonicalSelectedToml,
                FileFamily::Json => AssertionObservationMode::CanonicalSelectedJson,
                FileFamily::Utf8Text
                | FileFamily::OpaqueBinary
                | FileFamily::GzipTar => {
                    return Err(Diagnostic::error(
                        "E_MUTATION_SOURCE_TYPE",
                        &assertion.id,
                    )
                    .at("structured mutation requires TOML or JSON"));
                }
            }
        };
        if assertion.observation_mode != expected_observation_mode {
            return Err(Diagnostic::error(
                "E_OBSERVATION_DOMAIN",
                &assertion.id,
            )
            .at("observation mode does not match source and operation"));
        }
    }
    validate_assertion_canonical_registry(policy)?;

    let corpus = Corpus66::checked(files, policy)?;
    for assertion in &policy.semantic_assertion {
        match assertion.observation_mode {
            AssertionObservationMode::CanonicalSelectedToml => {
                let document = corpus.toml(&assertion.source_path, &assertion.id)?;
                pointer_get(document, &assertion.selector, &assertion.id)?;
                if let Some(secondary) = &assertion.secondary_selector {
                    pointer_get(document, secondary, &assertion.id)?;
                }
            }
            AssertionObservationMode::CanonicalSelectedJson => {
                let document = corpus.json(&assertion.source_path, &assertion.id)?;
                json_pointer_get(document, &assertion.selector, &assertion.id)?;
                if let Some(secondary) = &assertion.secondary_selector {
                    json_pointer_get(document, secondary, &assertion.id)?;
                }
            }
            AssertionObservationMode::RawSourceBytes => {
                let source = corpus.file(&assertion.source_path)?;
                let components = parse_pointer(&assertion.selector, &assertion.id)?;
                let valid_offset = components.get(1).is_some_and(|component| {
                    component == "end"
                        || component.parse::<usize>().ok().is_some_and(|offset| {
                            component == &offset.to_string() && offset < source.bytes.len()
                        })
                });
                if components.len() != 2 || components[0] != "bytes" || !valid_offset {
                    return Err(Diagnostic::error("E_OBSERVATION_DOMAIN", &assertion.id)
                        .at("raw edit selector"));
                }
            }
        }
    }

    let mut violation_owners = BTreeMap::<String, Vec<&SemanticAssertion>>::new();
    for assertion in &policy.semantic_assertion {
        violation_owners
            .entry(assertion.violating_observation_sha256.clone())
            .or_default()
            .push(assertion);
    }
    for owners in violation_owners.values() {
        let Some(first) = owners.first() else {
            return Err(Diagnostic::error(
                "E_ASSERTION_VIOLATION_COLLISION",
                "empty violation owner set",
            ));
        };
        for owner in owners.iter().skip(1) {
            if !same_observation_identity(first, owner) {
                return Err(Diagnostic::error(
                    "E_ASSERTION_VIOLATION_COLLISION",
                    &owner.id,
                )
                .at(&first.id));
            }
        }
    }

    let baseline_findings = scan_assertion_registry(
        &corpus,
        None,
        None,
        policy,
        &assertions,
        &violation_owners,
    )?;
    if !baseline_findings.is_empty() {
        return Err(Diagnostic::error(
            "E_ASSERTION_BASELINE_FINDING",
            "immutable Corpus66 baseline",
        )
        .at(format!(
            "{:?}",
            baseline_findings
                .iter()
                .map(|finding| finding.assertion_id.as_str())
                .collect::<Vec<_>>()
        )));
    }

    let negative_arrays = policy
        .negative_family
        .iter()
        .map(|family| {
            (
                family.id.as_str(),
                (family.source_path.as_str(), family.source_array.as_str()),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let fixtures = validate_mutation_fixtures(policy)?;

    let mut canonical_cases = policy.negative_case.iter().collect::<Vec<_>>();
    canonical_cases.sort_by(|left, right| {
        let left_family = family_order
            .get(left.family.as_str())
            .copied()
            .unwrap_or(usize::MAX);
        let right_family = family_order
            .get(right.family.as_str())
            .copied()
            .unwrap_or(usize::MAX);
        (left_family, left.source_index).cmp(&(right_family, right.source_index))
    });

    let mut execution_count = 0usize;
    for case in canonical_cases {
        let assertion = assertions
            .get(case.validator.as_str())
            .copied()
            .ok_or_else(|| Diagnostic::error("E_MUTATION_ASSERTION", &case.id))?;
        let fixture = match case.argument.as_deref().and_then(|argument| {
            argument.strip_prefix(&policy.fixture_contract.reference_prefix)
        }) {
            Some(id) => Some(
                fixtures
                    .get(id)
                    .copied()
                    .ok_or_else(|| Diagnostic::error("E_FIXTURE_MISSING", &case.id).at(id))?,
            ),
            None => None,
        };
        validate_mutation_field_relevance(case, fixture)?;
        if selector_targets_forbidden_field(&case.target_selector, &case.id)? {
            return Err(Diagnostic::error("E_MUTATION_FORBIDDEN_TARGET", &case.id));
        }
        let target_components = parse_pointer(&case.target_selector, &case.id)?;
        let secondary_components = if let Some(secondary) = &case.secondary_selector {
            if selector_targets_forbidden_field(secondary, &case.id)? {
                return Err(Diagnostic::error("E_MUTATION_FORBIDDEN_TARGET", &case.id));
            }
            Some(parse_pointer(secondary, &case.id)?)
        } else {
            None
        };
        let targets_own_negative_array = |components: &[String]| {
            negative_arrays
                .get(case.family.as_str())
                .is_some_and(|(path, array)| {
                    *path == case.target_path
                        && pointer_enters_named_root(components, array)
                })
        };
        if targets_own_negative_array(&target_components)
            || secondary_components
                .as_deref()
                .is_some_and(targets_own_negative_array)
        {
            return Err(Diagnostic::error("E_MUTATION_SELF_TARGET", &case.id));
        }
        validate_quarantine_mutation_boundary(case, fixture, policy)?;

        let source = corpus.file(&case.target_path)?;
        let overlay = Overlay::checked(&corpus, case, fixture, policy)?;
        let expected_file_digest = sha256(&overlay.bytes);
        let expected_family_digest = virtual_source_subset_digest(
            corpus.files,
            &case.target_path,
            &overlay.bytes,
            Some(&source.contract.family),
        )?;
        let expected_tree_digest =
            virtual_source_subset_digest(corpus.files, &case.target_path, &overlay.bytes, None)?;
        let baseline_family = policy
            .source_family
            .iter()
            .find(|family| family.id == source.contract.family)
            .ok_or_else(|| Diagnostic::error("E_SOURCE_FAMILY", &source.contract.family))?;
        let expected_file_length = u64::try_from(overlay.bytes.len())
            .map_err(|_| Diagnostic::error("E_MUTATION_BOUND", &case.id))?;
        let expected_family_length = baseline_family
            .total_bytes
            .checked_sub(source.contract.byte_length)
            .and_then(|length| length.checked_add(expected_file_length))
            .ok_or_else(|| {
                Diagnostic::error("E_MUTATION_BOUND", &case.id)
                    .at("virtual source-family length")
            })?;
        let expected_tree_length = policy
            .source_tree
            .total_bytes
            .checked_sub(source.contract.byte_length)
            .and_then(|length| length.checked_add(expected_file_length))
            .ok_or_else(|| {
                Diagnostic::error("E_MUTATION_BOUND", &case.id)
                    .at("virtual source-tree length")
            })?;
        if overlay.target_path != case.target_path
            || overlay.file_binding
                != (VirtualBinding {
                    byte_length: expected_file_length,
                    sha256: expected_file_digest,
                })
            || overlay.family_binding
                != (VirtualBinding {
                    byte_length: expected_family_length,
                    sha256: expected_family_digest,
                })
            || overlay.tree_binding
                != (VirtualBinding {
                    byte_length: expected_tree_length,
                    sha256: expected_tree_digest,
                })
            || overlay.file_binding.sha256 == source.digest
            || lower_hex(&overlay.family_binding.sha256) == baseline_family.tree_sha256
            || lower_hex(&overlay.tree_binding.sha256) == policy.source_tree.sha256
        {
            return Err(Diagnostic::error("E_MUTATION_BINDING", &case.id));
        }

        let findings = scan_assertion_registry(
            &corpus,
            Some(&overlay),
            Some(case),
            policy,
            &assertions,
            &violation_owners,
        )?;
        let resolution = resolve_findings(assertion, findings)?;
        let primary = resolution
            .emitted
            .first()
            .ok_or_else(|| Diagnostic::error("E_ASSERTION_PRIMARY_MISSING", &assertion.id))?;
        if primary.assertion_id != assertion.id {
            return Err(Diagnostic::error("E_ASSERTION_PRIMARY_ORDER", &assertion.id)
                .at(&primary.assertion_id));
        }
        for finding in resolution
            .emitted
            .iter()
            .chain(&resolution.suppressed)
        {
            validate_finding_authority(finding, &assertions)?;
        }
        let expected_primary = finding_from_assertion(
            assertion,
            assertion.violating_observation_sha256.clone(),
        )?;
        if *primary != expected_primary {
            return Err(Diagnostic::error("E_MUTATION_DIAGNOSTIC", &case.id)
                .at(&primary.diagnostic));
        }

        execution_count = execution_count
            .checked_add(1)
            .ok_or_else(|| Diagnostic::error("E_MUTATION_COUNT", "execution overflow"))?;
    }

    if execution_count != EXPECTED_NEGATIVES {
        return Err(Diagnostic::error("E_MUTATION_COUNT", "executed isolated mutations")
            .at(format!(
                "expected={EXPECTED_NEGATIVES};actual={execution_count}"
            )));
    }
    let final_baseline_findings = scan_assertion_registry(
        &corpus,
        None,
        None,
        policy,
        &assertions,
        &violation_owners,
    )?;
    if !final_baseline_findings.is_empty() {
        return Err(Diagnostic::error(
            "E_ASSERTION_BASELINE_FINDING",
            "post-mutation immutable Corpus66 baseline",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExpectedDerivedOutput {
    path: String,
    kind: String,
    generation_rank: u32,
    required_parent_ids: Vec<String>,
}

fn sort_raw_utf8(values: &mut [String]) {
    values.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
}

fn expected_derived_outputs() -> VResult<BTreeMap<String, ExpectedDerivedOutput>> {
    fn insert(
        outputs: &mut BTreeMap<String, ExpectedDerivedOutput>,
        id: &str,
        path: &str,
        kind: &str,
        generation_rank: u32,
        required_parent_ids: &[&str],
    ) -> VResult<()> {
        let mut required_parent_ids = required_parent_ids
            .iter()
            .map(|parent| (*parent).to_owned())
            .collect::<Vec<_>>();
        sort_raw_utf8(&mut required_parent_ids);
        let output = ExpectedDerivedOutput {
            path: path.to_owned(),
            kind: kind.to_owned(),
            generation_rank,
            required_parent_ids,
        };
        if outputs.insert(id.to_owned(), output).is_some() {
            return Err(Diagnostic::error("E_STATIC_MATRIX", "duplicate output ID").at(id));
        }
        Ok(())
    }

    let mut outputs = BTreeMap::new();
    for (id, path, kind, rank, parents) in [
        (
            "source-snapshot",
            "evidence/fnd-01/integration/source-snapshot.toml",
            "source_snapshot",
            1,
            &[][..],
        ),
        (
            "producer-environment",
            "evidence/fnd-01/integration/producer-environment.toml",
            "producer_environment",
            2,
            &["source-snapshot"][..],
        ),
        (
            "supply-bundle",
            "evidence/fnd-01/integration/supply-bundle.bin",
            "supply_bundle",
            3,
            &["producer-environment", "source-snapshot"][..],
        ),
        (
            "supply-receipt",
            "evidence/fnd-01/integration/supply-receipt.toml",
            "supply_receipt",
            4,
            &[
                "producer-environment",
                "source-snapshot",
                "supply-bundle",
            ][..],
        ),
        (
            "command-streams",
            "evidence/fnd-01/integration/command-streams.bin.gz",
            "command_streams",
            5,
            &[
                "producer-environment",
                "source-snapshot",
                "supply-receipt",
            ][..],
        ),
        (
            "command-results",
            "evidence/fnd-01/integration/command-results.toml",
            "command_results",
            6,
            &[
                "command-streams",
                "producer-environment",
                "supply-receipt",
            ][..],
        ),
        (
            "dependency-receipt",
            "evidence/fnd-01/integration/dependency-receipt.toml",
            "dependency_receipt",
            7,
            &["command-results", "source-snapshot", "supply-receipt"][..],
        ),
        (
            "workspace-receipt",
            "evidence/fnd-01/integration/workspace-receipt.toml",
            "workspace_receipt",
            8,
            &[
                "command-results",
                "dependency-receipt",
                "source-snapshot",
            ][..],
        ),
        (
            "mutation-receipt",
            "evidence/fnd-01/integration/mutation-receipt.toml",
            "mutation_receipt",
            3,
            &["producer-environment", "source-snapshot"][..],
        ),
        (
            "package-artifacts",
            "evidence/fnd-01/integration/package-artifacts.bin",
            "package_artifacts",
            9,
            &[
                "command-results",
                "dependency-receipt",
                "workspace-receipt",
            ][..],
        ),
        (
            "package-receipt",
            "evidence/fnd-01/integration/package-receipt.toml",
            "package_receipt",
            10,
            &[
                "command-results",
                "package-artifacts",
                "workspace-receipt",
            ][..],
        ),
        (
            "consumer-receipt",
            "evidence/fnd-01/integration/consumer-receipt.toml",
            "consumer_receipt",
            11,
            &[
                "command-results",
                "dependency-receipt",
                "package-artifacts",
                "package-receipt",
            ][..],
        ),
        (
            "integration-index",
            "evidence/fnd-01/integration/integration-index.toml",
            "integration_index",
            12,
            &[
                "command-results",
                "command-streams",
                "consumer-receipt",
                "dependency-receipt",
                "mutation-receipt",
                "package-artifacts",
                "package-receipt",
                "producer-environment",
                "source-snapshot",
                "supply-bundle",
                "supply-receipt",
                "workspace-receipt",
            ][..],
        ),
    ] {
        insert(&mut outputs, id, path, kind, rank, parents)?;
    }
    if outputs.len() != EXPECTED_RECEIPTS {
        return Err(Diagnostic::error("E_STATIC_MATRIX", "derived output count")
            .at(outputs.len().to_string()));
    }
    Ok(outputs)
}

fn expected_receipt_paths() -> VResult<BTreeSet<String>> {
    OUTPUT_PATHS
        .iter()
        .map(|path| {
            path.strip_prefix("evidence/fnd-01/integration/")
                .map(str::to_owned)
                .ok_or_else(|| {
                    Diagnostic::error("E_STATIC_MATRIX", "compiled output path").at(*path)
                })
        })
        .collect()
}

fn strings_strictly_sorted(values: &[String]) -> bool {
    values
        .windows(2)
        .all(|pair| pair[0].as_bytes() < pair[1].as_bytes())
}

fn encode_parent_purpose_registry(outputs: &[DerivedOutputContract]) -> VResult<Vec<u8>> {
    let mut edges = Vec::new();
    for output in outputs {
        if output.required_parent_ids.len() != output.parent_purposes.len() {
            return Err(Diagnostic::error(
                "E_PARENT_PURPOSE_ORACLE",
                &output.id,
            )
            .at("parent/purpose cardinality"));
        }
        for (parent, purpose) in output
            .required_parent_ids
            .iter()
            .zip(&output.parent_purposes)
        {
            if output.id.is_empty() || parent.is_empty() || purpose.is_empty() {
                return Err(Diagnostic::error(
                    "E_PARENT_PURPOSE_ORACLE",
                    &output.id,
                )
                .at(parent));
            }
            edges.push((&output.id, parent, purpose));
        }
    }
    edges.sort_by(|left, right| {
        left.0
            .as_bytes()
            .cmp(right.0.as_bytes())
            .then_with(|| left.1.as_bytes().cmp(right.1.as_bytes()))
            .then_with(|| left.2.as_bytes().cmp(right.2.as_bytes()))
    });
    if edges.len() != EXPECTED_DIRECT_PARENT_EDGES
        || edges.windows(2).any(|pair| pair[0] == pair[1])
    {
        return Err(Diagnostic::error(
            "E_PARENT_PURPOSE_ORACLE",
            "derived output edges",
        ));
    }
    let mut encoded = Vec::with_capacity(PARENT_PURPOSE_REGISTRY_BYTES);
    encoded.extend_from_slice(b"FND01PARENTv1\0");
    append_registry_count(&mut encoded, edges.len(), "parent purpose registry")?;
    for (child, parent, purpose) in edges {
        append_registry_row(&mut encoded, child, "parent purpose child")?;
        append_registry_row(&mut encoded, parent, "parent purpose parent")?;
        append_registry_row(&mut encoded, purpose, "parent purpose text")?;
    }
    Ok(encoded)
}

fn validate_receipt_matrix(policy: &Policy) -> VResult<BTreeSet<String>> {
    if PROJECTIONS.len() != EXPECTED_PROJECTIONS
        || TARGETS.len() != EXPECTED_TARGETS
        || SDK_IDS.len() != EXPECTED_SDKS
        || PACKAGE_IDS.len() != EXPECTED_PACKAGES
        || OUTPUT_IDS.len() != EXPECTED_RECEIPTS
        || OUTPUT_PATHS.len() != EXPECTED_RECEIPTS
        || OUTPUT_KINDS.len() != EXPECTED_RECEIPTS
        || TOML_OUTPUT_IDS.len() != EXPECTED_RECEIPT_TOMLS
        || BINARY_OUTPUT_IDS.len() != EXPECTED_RECEIPT_BINARIES
    {
        return Err(Diagnostic::error("E_STATIC_MATRIX", "verifier constants"));
    }
    let namespace = &policy.output_namespace;
    if namespace.root != "evidence/fnd-01/integration"
        || !namespace.flat
        || namespace.output_count != EXPECTED_RECEIPTS
        || namespace.toml_count != EXPECTED_RECEIPT_TOMLS
        || namespace.binary_count != EXPECTED_RECEIPT_BINARIES
        || namespace.direct_parent_edge_count != EXPECTED_DIRECT_PARENT_EDGES
        || namespace.integration_index_member_count != EXPECTED_RECEIPTS - 1
        || namespace.integration_index_may_hash_itself
        || namespace.final_attestation_in_namespace
        || !string_sequence_is(&namespace.output_ids, OUTPUT_IDS)
        || !string_sequence_is(&namespace.output_paths, OUTPUT_PATHS)
        || !string_sequence_is(&namespace.output_kinds, OUTPUT_KINDS)
        || !namespace.id_path_kind_arrays_are_zipped
        || namespace.order_rule
            != "all three arrays are the exact canonical output order; derived_output is an exact ordered bijection to them; every path is a direct child of root, every basename is unique under exact and ASCII-case-folded comparison, and no unlisted file or directory is admitted"
        || !string_sequence_is(&namespace.binary_ids, BINARY_OUTPUT_IDS)
        || !string_sequence_is(&namespace.toml_ids, TOML_OUTPUT_IDS)
        || !string_sequence_is(&namespace.projections, PROJECTIONS)
        || namespace.publication_rule
            != "all 13 outputs are generated in one fresh run-specific return tree, validated as an exact set, and published once without overwriting any destination; integration-index binds the other 12 and excludes itself; final-attestation is external and self-excluded"
    {
        return Err(Diagnostic::error("E_MATRIX_IDENTITY", "output namespace"));
    }
    let paths = expected_receipt_paths()?;
    if paths.len() != EXPECTED_RECEIPTS {
        return Err(Diagnostic::error("E_STATIC_MATRIX", "receipt path count")
            .at(paths.len().to_string()));
    }
    if policy.derived_output.len() != EXPECTED_RECEIPTS {
        return Err(Diagnostic::error("E_DERIVED_OUTPUT_COUNT", "derived_output")
            .at(policy.derived_output.len().to_string()));
    }
    let parent_purpose_registry = encode_parent_purpose_registry(&policy.derived_output)?;
    if parent_purpose_registry.len() != PARENT_PURPOSE_REGISTRY_BYTES
        || lower_hex(&sha256(&parent_purpose_registry)) != PARENT_PURPOSE_REGISTRY_SHA256
    {
        return Err(Diagnostic::error(
            "E_PARENT_PURPOSE_ORACLE",
            "derived output edges",
        ));
    }
    if !policy
        .derived_output
        .iter()
        .zip(OUTPUT_IDS.iter().zip(OUTPUT_PATHS).zip(OUTPUT_KINDS))
        .all(|(output, ((id, path), kind))| {
            output.id == *id && output.path == *path && output.kind == *kind
        })
    {
        return Err(Diagnostic::error(
            "E_DERIVED_OUTPUT_ORDER",
            "derived_output",
        ));
    }
    let declared_ids = policy
        .derived_output
        .iter()
        .map(|output| output.id.clone())
        .collect::<Vec<_>>();
    validate_case_unique(declared_ids, "derived output IDs")?;
    let declared = policy
        .derived_output
        .iter()
        .map(|output| {
            output
                .path
                .strip_prefix("evidence/fnd-01/integration/")
                .unwrap_or(&output.path)
                .to_owned()
        })
        .collect::<BTreeSet<_>>();
    let output_by_id = policy
        .derived_output
        .iter()
        .map(|output| (output.id.as_str(), output))
        .collect::<BTreeMap<_, _>>();
    if output_by_id.len() != EXPECTED_RECEIPTS {
        return Err(Diagnostic::error("E_DERIVED_OUTPUT_DUPLICATE", "derived_output"));
    }
    let expected_by_id = expected_derived_outputs()?;
    let declared_id_set = output_by_id.keys().copied().collect::<BTreeSet<_>>();
    let expected_id_set = expected_by_id
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if declared_id_set != expected_id_set {
        return Err(Diagnostic::error(
            "E_DERIVED_OUTPUT_EXACT_SET",
            "derived_output",
        ));
    }
    let mut pending_gates = Vec::with_capacity(EXPECTED_RECEIPTS);
    for output in &policy.derived_output {
        let oracle = expected_by_id
            .get(&output.id)
            .ok_or_else(|| Diagnostic::error("E_DERIVED_OUTPUT_EXACT_SET", &output.id))?;
        validate_ascii_posix_path(&output.path, &output.id)?;
        let relative = output
            .path
            .strip_prefix("evidence/fnd-01/integration/")
            .ok_or_else(|| Diagnostic::error("E_DERIVED_OUTPUT_PATH", &output.id))?;
        if relative.contains('/') {
            return Err(Diagnostic::error("E_DERIVED_OUTPUT_PATH", &output.id)
                .at("output namespace must be flat"));
        }
        let expected_gate = format!("E_PENDING_GATE:FND01:OUTPUT:{}", output.id);
        let expected_max = match output.id.as_str() {
            "supply-bundle" => policy.bounds.max_supply_bundle_bytes,
            "command-streams" => policy.bounds.max_command_stream_bundle_bytes,
            "package-artifacts" => policy.bounds.max_package_artifact_bytes,
            _ => policy.bounds.max_receipt_toml_bytes,
        };
        let receipt_schema_match_count = policy
            .receipt_schema
            .iter()
            .filter(|schema| schema.receipt_id == output.id && schema.kind == output.kind)
            .count();
        let schema_dispatch_is_exact = if TOML_OUTPUT_IDS.contains(&output.id.as_str()) {
            receipt_schema_match_count == 1
        } else {
            BINARY_OUTPUT_IDS.contains(&output.id.as_str()) && receipt_schema_match_count == 0
        };
        let parent_limit = if output.id == "integration-index" {
            policy.parent_contract.index_parent_count
        } else {
            policy.parent_contract.non_index_max_parent_count
        };
        if output.path != oracle.path
            || output.kind != oracle.kind
            || !schema_dispatch_is_exact
            || output.generation_rank != oracle.generation_rank
            || output.producer_bead != INTEGRATION_PRODUCER
            || output.pending_gate != expected_gate
            || output.required_parent_ids != oracle.required_parent_ids
            || output.parent_purposes.len() != output.required_parent_ids.len()
            || output
                .parent_purposes
                .iter()
                .any(|purpose| purpose.is_empty())
            || output.min_bytes != 1
            || output.max_bytes != expected_max
            || output.required_parent_ids.len() > parent_limit
            || output.required_parent_ids.len() > policy.bounds.max_parent_count
            || !strings_strictly_sorted(&output.required_parent_ids)
        {
            return Err(Diagnostic::error("E_DERIVED_OUTPUT_CONTRACT", &output.id));
        }
        validate_case_unique(
            output.required_parent_ids.clone(),
            &format!("{} parents", output.id),
        )?;
        for parent_id in &output.required_parent_ids {
            let parent = output_by_id
                .get(parent_id.as_str())
                .ok_or_else(|| Diagnostic::error("E_DERIVED_PARENT", &output.id).at(parent_id))?;
            if parent.id == output.id || parent.generation_rank >= output.generation_rank {
                return Err(Diagnostic::error("E_DERIVED_PARENT_RANK", &output.id)
                    .at(parent_id));
            }
        }
        pending_gates.push(output.pending_gate.clone());
    }
    if declared != paths {
        return Err(Diagnostic::error("E_RECEIPT_EXACT_SET", "policy output paths"));
    }
    validate_case_unique(pending_gates, "derived output pending gates")?;
    let mut rank_counts = BTreeMap::<u32, usize>::new();
    let mut parent_edge_count = 0usize;
    for output in &policy.derived_output {
        *rank_counts.entry(output.generation_rank).or_default() += 1;
        parent_edge_count = parent_edge_count
            .checked_add(output.required_parent_ids.len())
            .ok_or_else(|| {
                Diagnostic::error("E_DERIVED_PARENT_COUNT", "derived_output")
            })?;
    }
    let expected_rank_counts = policy
        .parent_contract
        .all_output_rank_counts_1_through_12
        .iter()
        .enumerate()
        .map(|(index, count)| {
            u32::try_from(index + 1)
                .map(|rank| (rank, *count))
                .map_err(|_| {
                    Diagnostic::error("E_DERIVED_DAG_CARDINALITY", "rank conversion")
                })
        })
        .collect::<VResult<BTreeMap<_, _>>>()?;
    if rank_counts != expected_rank_counts
        || parent_edge_count != policy.parent_contract.edge_count
    {
        return Err(Diagnostic::error("E_DERIVED_DAG_CARDINALITY", "derived_output")
            .at(format!("ranks={rank_counts:?};edges={parent_edge_count}")));
    }
    let integration = output_by_id
        .get("integration-index")
        .ok_or_else(|| Diagnostic::error("E_DERIVED_OUTPUT_CONTRACT", "integration-index"))?;
    let all_other_ids = policy
        .derived_output
        .iter()
        .filter(|output| output.id != "integration-index")
        .map(|output| output.id.clone())
        .collect::<BTreeSet<_>>();
    let integration_parents = integration
        .required_parent_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if integration_parents != all_other_ids
        || integration.required_parent_ids.len() != EXPECTED_RECEIPTS - 1
    {
        return Err(Diagnostic::error(
            "E_DERIVED_INTEGRATION_PARENTS",
            "integration-index",
        ));
    }
    validate_case_unique(paths.iter().cloned(), "receipt matrix")?;
    Ok(paths)
}

fn exact_table_fields(
    table: &toml::map::Map<String, toml::Value>,
    expected: impl IntoIterator<Item = impl AsRef<str>>,
    subject: &str,
) -> VResult<()> {
    let expected = expected
        .into_iter()
        .map(|field| field.as_ref().to_owned())
        .collect::<BTreeSet<_>>();
    let actual = table.keys().cloned().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(Diagnostic::error("E_RECORD_FIELDS", subject)
            .at(format!("expected={expected:?};actual={actual:?}")));
    }
    Ok(())
}

fn record_string<'a>(
    table: &'a toml::map::Map<String, toml::Value>,
    field: &str,
    subject: &str,
) -> VResult<&'a str> {
    table
        .get(field)
        .and_then(toml::Value::as_str)
        .filter(|value| !value.as_bytes().contains(&0))
        .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", subject).at(field))
}

fn record_bool(
    table: &toml::map::Map<String, toml::Value>,
    field: &str,
    subject: &str,
) -> VResult<bool> {
    table
        .get(field)
        .and_then(toml::Value::as_bool)
        .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", subject).at(field))
}

fn record_u64(
    table: &toml::map::Map<String, toml::Value>,
    field: &str,
    subject: &str,
) -> VResult<u64> {
    table
        .get(field)
        .and_then(toml::Value::as_integer)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", subject).at(field))
}

fn record_i64(
    table: &toml::map::Map<String, toml::Value>,
    field: &str,
    subject: &str,
) -> VResult<i64> {
    table
        .get(field)
        .and_then(toml::Value::as_integer)
        .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", subject).at(field))
}

fn record_usize(
    table: &toml::map::Map<String, toml::Value>,
    field: &str,
    subject: &str,
) -> VResult<usize> {
    usize::try_from(record_u64(table, field, subject)?)
        .map_err(|_| Diagnostic::error("E_RECORD_TYPE", subject).at(field))
}

fn record_u32(
    table: &toml::map::Map<String, toml::Value>,
    field: &str,
    subject: &str,
) -> VResult<u32> {
    u32::try_from(record_u64(table, field, subject)?)
        .map_err(|_| Diagnostic::error("E_RECORD_TYPE", subject).at(field))
}

fn record_table<'a>(
    table: &'a toml::map::Map<String, toml::Value>,
    field: &str,
    subject: &str,
) -> VResult<&'a toml::map::Map<String, toml::Value>> {
    table
        .get(field)
        .and_then(toml::Value::as_table)
        .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", subject).at(field))
}

fn record_array<'a>(
    table: &'a toml::map::Map<String, toml::Value>,
    field: &str,
    subject: &str,
) -> VResult<&'a [toml::Value]> {
    table
        .get(field)
        .and_then(toml::Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", subject).at(field))
}

fn record_string_array(
    table: &toml::map::Map<String, toml::Value>,
    field: &str,
    subject: &str,
) -> VResult<Vec<String>> {
    record_array(table, field, subject)?
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|text| !text.as_bytes().contains(&0))
                .map(ToOwned::to_owned)
                .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", subject).at(field))
        })
        .collect()
}

fn record_environment_pairs(
    table: &toml::map::Map<String, toml::Value>,
    field: &str,
    subject: &str,
) -> VResult<Vec<(String, String)>> {
    record_array(table, field, subject)?
        .iter()
        .map(|value| {
            let pair = value
                .as_array()
                .filter(|pair| pair.len() == 2)
                .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", subject).at(field))?;
            let key = pair[0]
                .as_str()
                .filter(|key| !key.is_empty() && !key.as_bytes().contains(&0))
                .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", subject).at(field))?;
            let value = pair[1]
                .as_str()
                .filter(|value| !value.as_bytes().contains(&0))
                .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", subject).at(field))?;
            Ok((key.to_owned(), value.to_owned()))
        })
        .collect()
}

fn validate_record_value_bounds(
    value: &toml::Value,
    bounds: &Bounds,
    depth: usize,
    subject: &str,
) -> VResult<()> {
    if depth > bounds.max_record_depth {
        return Err(Diagnostic::error("E_RECORD_BOUND", subject).at("depth"));
    }
    match value {
        toml::Value::String(value) => {
            if value.len() > bounds.max_record_string_bytes || value.as_bytes().contains(&0) {
                return Err(Diagnostic::error("E_RECORD_BOUND", subject).at("string"));
            }
        }
        toml::Value::Integer(_) | toml::Value::Boolean(_) => {}
        toml::Value::Float(_) | toml::Value::Datetime(_) => {
            return Err(Diagnostic::error("E_RECORD_TYPE", subject)
                .at("float and datetime values are forbidden"));
        }
        toml::Value::Array(values) => {
            if values.len() > bounds.max_record_array_items {
                return Err(Diagnostic::error("E_RECORD_BOUND", subject).at("array"));
            }
            for value in values {
                validate_record_value_bounds(value, bounds, depth + 1, subject)?;
            }
        }
        toml::Value::Table(table) => {
            if table.len() > bounds.max_record_field_count {
                return Err(Diagnostic::error("E_RECORD_BOUND", subject).at("field count"));
            }
            for (field, value) in table {
                if field.is_empty()
                    || field.len() > bounds.max_record_string_bytes
                    || field.as_bytes().contains(&0)
                {
                    return Err(Diagnostic::error("E_RECORD_BOUND", subject).at(field));
                }
                validate_record_value_bounds(value, bounds, depth + 1, subject)?;
            }
        }
    }
    Ok(())
}

fn validate_direct_field_value(
    value: &toml::Value,
    direct_type: DirectFieldType,
    subject: &str,
    field: &str,
) -> VResult<()> {
    let type_error = || Diagnostic::error("E_RECORD_TYPE", subject).at(field);
    match direct_type {
        DirectFieldType::String => {
            if value
                .as_str()
                .is_none_or(|text| text.as_bytes().contains(&0))
            {
                return Err(type_error());
            }
        }
        DirectFieldType::Unsigned => {
            if value
                .as_integer()
                .and_then(|integer| u64::try_from(integer).ok())
                .is_none()
            {
                return Err(type_error());
            }
        }
        DirectFieldType::Signed => {
            if value.as_integer().is_none() {
                return Err(type_error());
            }
        }
        DirectFieldType::Boolean => {
            if value.as_bool().is_none() {
                return Err(type_error());
            }
        }
        DirectFieldType::RawBytes => {
            return Err(Diagnostic::error("E_RECORD_RAW_TOML", subject).at(field));
        }
        DirectFieldType::StringArray => {
            let values = value.as_array().ok_or_else(type_error)?;
            if values.iter().any(|value| {
                value
                    .as_str()
                    .is_none_or(|text| text.as_bytes().contains(&0))
            }) {
                return Err(type_error());
            }
        }
        DirectFieldType::EnvironmentPairs => {
            let values = value.as_array().ok_or_else(type_error)?;
            let mut keys = BTreeSet::new();
            for value in values {
                let pair = value.as_array().ok_or_else(type_error)?;
                if pair.len() != 2 {
                    return Err(type_error());
                }
                let key = pair[0].as_str().ok_or_else(type_error)?;
                let assigned = pair[1].as_str().ok_or_else(type_error)?;
                if key.is_empty()
                    || key.as_bytes().contains(&0)
                    || assigned.as_bytes().contains(&0)
                    || !keys.insert(key)
                {
                    return Err(type_error());
                }
            }
        }
        DirectFieldType::Record => {
            if value.as_table().is_none() {
                return Err(type_error());
            }
        }
        DirectFieldType::RecordArray | DirectFieldType::VariantArray => {
            let values = value.as_array().ok_or_else(type_error)?;
            if values.iter().any(|value| value.as_table().is_none()) {
                return Err(type_error());
            }
        }
        DirectFieldType::OptionalString
        | DirectFieldType::OptionalUnsigned
        | DirectFieldType::OptionalBoolean => {
            let values = value.as_array().ok_or_else(type_error)?;
            if values.len() > 1 {
                return Err(Diagnostic::error("E_RECORD_PRESENCE", subject).at(field));
            }
            if let Some(value) = values.first() {
                let contained = match direct_type {
                    DirectFieldType::OptionalString => DirectFieldType::String,
                    DirectFieldType::OptionalUnsigned => DirectFieldType::Unsigned,
                    DirectFieldType::OptionalBoolean => DirectFieldType::Boolean,
                    _ => unreachable!(),
                };
                validate_direct_field_value(value, contained, subject, field)?;
            }
        }
    }
    Ok(())
}

fn validate_direct_fields(
    table: &toml::map::Map<String, toml::Value>,
    fields: &[String],
    structurally_optional_fields: &[String],
    mask: &str,
    subject: &str,
) -> VResult<()> {
    if mask.len() != fields.len() || !mask.is_ascii() {
        return Err(Diagnostic::error("E_RECORD_TYPE_REGISTRY", subject)
            .at("field/type mask length"));
    }
    for (field, code) in fields.iter().zip(mask.bytes()) {
        let Some(value) = table.get(field) else {
            if structurally_optional_fields
                .iter()
                .any(|candidate| candidate == field)
            {
                continue;
            }
            return Err(Diagnostic::error("E_RECORD_FIELDS", subject).at(field));
        };
        validate_direct_field_value(
            value,
            DirectFieldType::from_code(code, subject)?,
            subject,
            field,
        )?;
    }
    Ok(())
}

fn validate_count_array_links(
    table: &toml::map::Map<String, toml::Value>,
    type_root: &str,
    subject: &str,
) -> VResult<()> {
    for (_, count_field, array_field) in COUNT_ARRAY_LINKS
        .iter()
        .filter(|(candidate, _, _)| *candidate == type_root)
    {
        let count = record_u64(table, count_field, subject)?;
        let length = record_array(table, array_field, subject)?.len();
        let length = u64::try_from(length)
            .map_err(|_| Diagnostic::error("E_RECORD_COUNT_LINK", subject).at(*array_field))?;
        if count != length {
            return Err(Diagnostic::error("E_RECORD_COUNT_LINK", subject)
                .at(format!("{count_field}={count};{array_field}.len={length}")));
        }
    }
    Ok(())
}

fn record_schema_by_id<'a>(
    policy: &'a Policy,
    id: &str,
    subject: &str,
) -> VResult<&'a RecordSchemaContract> {
    let mut matching = policy.record_schema.iter().filter(|row| row.id == id);
    let row = matching
        .next()
        .ok_or_else(|| Diagnostic::error("E_RECORD_SCHEMA_DISPATCH", subject).at(id))?;
    if matching.next().is_some() {
        return Err(Diagnostic::error("E_RECORD_SCHEMA_DISPATCH", subject).at(id));
    }
    Ok(row)
}

fn record_variant_by_selector<'a>(
    policy: &'a Policy,
    selector: &str,
    table: &toml::map::Map<String, toml::Value>,
) -> VResult<&'a RecordVariantSchemaContract> {
    let mut matching = policy
        .record_variant_schema
        .iter()
        .filter(|row| row.parent_selector == selector)
        .filter(|row| {
            table
                .get(&row.discriminator_field)
                .and_then(toml::Value::as_str)
                == Some(row.discriminator_value.as_str())
        });
    let row = matching
        .next()
        .ok_or_else(|| Diagnostic::error("E_RECORD_VARIANT_DISPATCH", selector))?;
    if matching.next().is_some() {
        return Err(Diagnostic::error("E_RECORD_VARIANT_DISPATCH", selector)
            .at("overlapping variants"));
    }
    Ok(row)
}

fn parse_child_schema_mappings<'a>(
    mappings: &'a [String],
    subject: &str,
) -> VResult<BTreeMap<&'a str, &'a str>> {
    let mut parsed = BTreeMap::new();
    let mut direct_fields = BTreeSet::new();
    for mapping in mappings {
        let (field, schema_id) = mapping
            .split_once("=>")
            .ok_or_else(|| Diagnostic::error("E_RECORD_SCHEMA_GRAPH", subject).at(mapping))?;
        let direct_field = field.strip_suffix("[]").unwrap_or(field);
        if field.is_empty()
            || schema_id.is_empty()
            || !direct_fields.insert(direct_field)
            || parsed.insert(field, schema_id).is_some()
        {
            return Err(Diagnostic::error("E_RECORD_SCHEMA_GRAPH", subject).at(mapping));
        }
    }
    Ok(parsed)
}

fn validate_mapped_children(
    table: &toml::map::Map<String, toml::Value>,
    child_mappings: &BTreeMap<&str, &str>,
    selector: &str,
    policy: &Policy,
    depth: usize,
) -> VResult<()> {
    for (mapped_field, schema_id) in child_mappings {
        let (field, is_array) = mapped_field
            .strip_suffix("[]")
            .map_or((*mapped_field, false), |field| (field, true));
        let value = table
            .get(field)
            .ok_or_else(|| Diagnostic::error("E_RECORD_FIELDS", selector).at(field))?;
        let child_selector = format!("{selector}/{mapped_field}");
        let child_schema = record_schema_by_id(policy, schema_id, &child_selector)?;
        if !child_schema
            .selectors
            .iter()
            .any(|value| value == &child_selector)
        {
            return Err(
                Diagnostic::error("E_RECORD_SCHEMA_DISPATCH", &child_selector).at(*schema_id)
            );
        }
        if is_array {
            let values = value
                .as_array()
                .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", selector).at(*mapped_field))?;
            for child in values {
                let child = child.as_table().ok_or_else(|| {
                    Diagnostic::error("E_RECORD_TYPE", selector).at(*mapped_field)
                })?;
                validate_nested_record(
                    child,
                    child_schema,
                    &child_selector,
                    policy,
                    depth + 1,
                )?;
            }
        } else {
            let child = value
                .as_table()
                .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", selector).at(field))?;
            validate_nested_record(
                child,
                child_schema,
                &child_selector,
                policy,
                depth + 1,
            )?;
        }
    }
    for (field, value) in table {
        if child_mappings.contains_key(field.as_str())
            || child_mappings.contains_key(format!("{field}[]").as_str())
        {
            continue;
        }
        if value.as_table().is_some()
            || value
                .as_array()
                .is_some_and(|values| values.iter().any(|value| value.as_table().is_some()))
        {
            return Err(Diagnostic::error("E_RECORD_SCHEMA_DISPATCH", selector).at(field));
        }
    }
    Ok(())
}

fn validate_nested_record(
    table: &toml::map::Map<String, toml::Value>,
    schema: &RecordSchemaContract,
    selector: &str,
    policy: &Policy,
    depth: usize,
) -> VResult<()> {
    if depth > policy.bounds.max_record_depth {
        return Err(Diagnostic::error("E_RECORD_BOUND", selector).at("schema depth"));
    }
    exact_table_fields(table, &schema.exact_fields, selector)?;
    let type_mask = compiled_type_mask(
        RECORD_SCHEMA_TYPE_MASKS,
        &schema.id,
        "record schema type masks",
    )?;
    validate_direct_fields(table, &schema.exact_fields, &[], type_mask, selector)?;
    validate_count_array_links(table, &format!("schema/{}", schema.id), selector)?;
    let child_mappings = parse_child_schema_mappings(&schema.child_fields, selector)?;
    validate_mapped_children(table, &child_mappings, selector, policy, depth)
}

fn validate_variant_record(
    table: &toml::map::Map<String, toml::Value>,
    variant: &RecordVariantSchemaContract,
    selector: &str,
    policy: &Policy,
    depth: usize,
) -> VResult<()> {
    let expected = variant
        .required_fields
        .iter()
        .chain(&variant.optional_fields)
        .collect::<Vec<_>>();
    let actual = table.keys().collect::<BTreeSet<_>>();
    let required = variant.required_fields.iter().collect::<BTreeSet<_>>();
    let allowed = expected.into_iter().collect::<BTreeSet<_>>();
    if !required.is_subset(&actual) || !actual.is_subset(&allowed) {
        return Err(Diagnostic::error("E_RECORD_FIELDS", selector));
    }
    if record_string(table, &variant.discriminator_field, selector)?
        != variant.discriminator_value
    {
        return Err(Diagnostic::error("E_RECORD_VARIANT_DISPATCH", selector));
    }
    let type_mask = compiled_type_mask(
        RECORD_VARIANT_TYPE_MASKS,
        &variant.id,
        "record variant type masks",
    )?;
    let fields = variant
        .required_fields
        .iter()
        .chain(&variant.optional_fields)
        .cloned()
        .collect::<Vec<_>>();
    validate_direct_fields(
        table,
        &fields,
        &variant.optional_fields,
        type_mask,
        selector,
    )?;
    validate_count_array_links(table, &format!("variant/{}", variant.id), selector)?;
    let child_mappings = parse_child_schema_mappings(&variant.child_fields, selector)?;
    validate_mapped_children(table, &child_mappings, selector, policy, depth)
}

fn validate_dispatched_record(
    table: &toml::map::Map<String, toml::Value>,
    selector: &str,
    policy: &Policy,
    depth: usize,
) -> VResult<()> {
    let schemas = policy
        .record_schema
        .iter()
        .filter(|row| row.selectors.iter().any(|candidate| candidate == selector))
        .collect::<Vec<_>>();
    let variants = policy
        .record_variant_schema
        .iter()
        .filter(|row| row.parent_selector == selector)
        .collect::<Vec<_>>();
    match (schemas.as_slice(), variants.is_empty()) {
        ([schema], true) => validate_nested_record(table, schema, selector, policy, depth),
        ([], false) => {
            let variant = record_variant_by_selector(policy, selector, table)?;
            validate_variant_record(table, variant, selector, policy, depth)
        }
        _ => Err(Diagnostic::error("E_RECORD_SCHEMA_DISPATCH", selector)
            .at("missing or overlapping root dispatch")),
    }
}

fn validate_record_root_children(
    table: &toml::map::Map<String, toml::Value>,
    selector_prefix: &str,
    policy: &Policy,
) -> VResult<()> {
    for (field, value) in table {
        let table_selector = format!("{selector_prefix}/{field}");
        let array_selector = format!("{selector_prefix}/{field}[]");
        let table_record_dispatches = policy
            .record_schema
            .iter()
            .filter(|row| row.selectors.iter().any(|selector| selector == &table_selector))
            .count();
        let table_variant_dispatches = policy
            .record_variant_schema
            .iter()
            .filter(|row| row.parent_selector == table_selector)
            .count();
        let array_record_dispatches = policy
            .record_schema
            .iter()
            .filter(|row| row.selectors.iter().any(|selector| selector == &array_selector))
            .count();
        let array_variant_dispatches = policy
            .record_variant_schema
            .iter()
            .filter(|row| row.parent_selector == array_selector)
            .count();
        if table_record_dispatches > 1
            || array_record_dispatches > 1
            || (table_record_dispatches != 0 && table_variant_dispatches != 0)
            || (array_record_dispatches != 0 && array_variant_dispatches != 0)
        {
            return Err(Diagnostic::error("E_RECORD_SCHEMA_DISPATCH", selector_prefix).at(field));
        }
        let table_dispatches =
            usize::from(table_record_dispatches == 1 || table_variant_dispatches != 0);
        let array_dispatches =
            usize::from(array_record_dispatches == 1 || array_variant_dispatches != 0);
        if table_dispatches + array_dispatches > 1 {
            return Err(Diagnostic::error("E_RECORD_SCHEMA_DISPATCH", selector_prefix).at(field));
        }
        match value {
            toml::Value::Table(child) => {
                if table_dispatches != 1 {
                    return Err(
                        Diagnostic::error("E_RECORD_SCHEMA_DISPATCH", selector_prefix).at(field)
                    );
                }
                validate_dispatched_record(child, &table_selector, policy, 1)?;
            }
            toml::Value::Array(values) if array_dispatches == 1 => {
                for child in values {
                    let child = child.as_table().ok_or_else(|| {
                        Diagnostic::error("E_RECORD_TYPE", selector_prefix)
                            .at(format!("{field}[]"))
                    })?;
                    validate_dispatched_record(child, &array_selector, policy, 1)?;
                }
            }
            toml::Value::Array(values) => {
                if values.iter().any(|value| value.as_table().is_some()) {
                    return Err(Diagnostic::error("E_RECORD_TYPE", selector_prefix)
                        .at(format!("{field}[]")));
                }
                if table_dispatches != 0 {
                    return Err(
                        Diagnostic::error("E_RECORD_TYPE", selector_prefix).at(field)
                    );
                }
            }
            _ => {
                if table_dispatches != 0 || array_dispatches != 0 {
                    return Err(
                        Diagnostic::error("E_RECORD_TYPE", selector_prefix).at(field)
                    );
                }
            }
        }
    }
    Ok(())
}

fn receipt_schema_for<'a>(
    policy: &'a Policy,
    receipt_id: &str,
    kind: &str,
) -> VResult<&'a ReceiptSchemaContract> {
    let mut matching = policy
        .receipt_schema
        .iter()
        .filter(|row| row.receipt_id == receipt_id && row.kind == kind);
    let row = matching
        .next()
        .ok_or_else(|| Diagnostic::error("E_RECEIPT_SCHEMA_DISPATCH", receipt_id).at(kind))?;
    if matching.next().is_some() {
        return Err(
            Diagnostic::error("E_RECEIPT_SCHEMA_DISPATCH", receipt_id).at("overlap")
        );
    }
    Ok(row)
}

fn validate_receipt_record_shape<'a, 'p>(
    raw: &'a toml::Value,
    policy: &'p Policy,
    subject: &str,
) -> VResult<(
    &'a toml::map::Map<String, toml::Value>,
    &'a toml::map::Map<String, toml::Value>,
    &'p ReceiptSchemaContract,
)> {
    validate_record_value_bounds(raw, &policy.bounds, 0, subject)?;
    let root = raw
        .as_table()
        .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", subject).at("root"))?;
    let receipt_id = record_string(root, "receipt_id", subject)?;
    let kind = record_string(root, "kind", subject)?;
    let schema = receipt_schema_for(policy, receipt_id, kind)?;
    let mut root_fields = policy.receipt_contract.common_required_fields.clone();
    root_fields.push(schema.table_name.clone());
    exact_table_fields(root, &root_fields, subject)?;
    validate_direct_fields(
        root,
        &policy.receipt_contract.common_required_fields,
        &[],
        RECEIPT_COMMON_TYPE_MASK,
        subject,
    )?;
    validate_count_array_links(root, "receipt/common", subject)?;

    for field in ["policy", "verifier", "harness"] {
        let child = record_table(root, field, subject)?;
        validate_dispatched_record(
            child,
            &format!("receipt/common/{field}"),
            policy,
            1,
        )?;
    }
    let parents = record_array(root, "parent", subject)?;
    if parents.iter().any(|value| value.as_table().is_none()) {
        return Err(Diagnostic::error("E_RECORD_TYPE", subject).at("parent[]"));
    }
    for parent in parents.iter().filter_map(toml::Value::as_table) {
        validate_dispatched_record(parent, "receipt/common/parent[]", policy, 1)?;
    }

    let body = record_table(root, &schema.table_name, subject)?;
    exact_table_fields(body, &schema.exact_fields, subject)?;
    let body_type_mask = compiled_type_mask(
        RECEIPT_BODY_TYPE_MASKS,
        receipt_id,
        "receipt body type masks",
    )?;
    validate_direct_fields(body, &schema.exact_fields, &[], body_type_mask, subject)?;
    validate_count_array_links(
        body,
        &format!("receipt/{kind}/{}", schema.table_name),
        subject,
    )?;
    validate_record_root_children(
        body,
        &format!("receipt/{kind}/{}", schema.table_name),
        policy,
    )?;
    Ok((root, body, schema))
}

fn parse_parent_bindings(
    values: &[toml::Value],
    subject: &str,
) -> VResult<Vec<ReceiptParentBinding>> {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let logical = format!("{subject}/parent[{index}]");
            let table = value
                .as_table()
                .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", &logical))?;
            let sha256 = record_string(table, "sha256", &logical)?.to_owned();
            validate_sha256(&sha256, &logical)?;
            Ok(ReceiptParentBinding {
                id: record_string(table, "id", &logical)?.to_owned(),
                path: record_string(table, "path", &logical)?.to_owned(),
                kind: record_string(table, "kind", &logical)?.to_owned(),
                byte_length: record_u64(table, "byte_length", &logical)?,
                sha256,
                purpose: record_string(table, "purpose", &logical)?.to_owned(),
            })
        })
        .collect()
}

fn parse_output_bindings(
    values: &[toml::Value],
    subject: &str,
) -> VResult<Vec<ReceiptOutputBinding>> {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let logical = format!("{subject}/output[{index}]");
            let table = value
                .as_table()
                .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", &logical))?;
            let sha256 = record_string(table, "sha256", &logical)?.to_owned();
            validate_sha256(&sha256, &logical)?;
            Ok(ReceiptOutputBinding {
                id: record_string(table, "id", &logical)?.to_owned(),
                path: record_string(table, "path", &logical)?.to_owned(),
                kind: record_string(table, "kind", &logical)?.to_owned(),
                byte_length: record_u64(table, "byte_length", &logical)?,
                sha256,
            })
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActualFileBinding {
    path: String,
    byte_length: u64,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActualAuthoringBindings {
    policy: ActualFileBinding,
    verifier: ActualFileBinding,
    harness: ActualFileBinding,
    closure_sha256: String,
}

fn actual_file_binding(path: &str, bytes: &[u8]) -> VResult<ActualFileBinding> {
    Ok(ActualFileBinding {
        path: path.to_owned(),
        byte_length: u64::try_from(bytes.len())
            .map_err(|_| Diagnostic::error("E_RECORD_BOUND", path).at("byte length"))?,
        sha256: lower_hex(&sha256(bytes)),
    })
}

fn load_actual_authoring_bindings(
    root: &Path,
    policy: &Policy,
    policy_bytes: &[u8],
) -> VResult<ActualAuthoringBindings> {
    let verifier_bytes = read_bounded(
        &resolve_safe(root, &policy.paths.verifier_test_path, "verifier source")?,
        policy.bounds.max_verifier_test_bytes,
        &policy.paths.verifier_test_path,
    )?;
    let harness_bytes = read_bounded(
        &resolve_safe(
            root,
            &policy.paths.bootstrap_harness_path,
            "bootstrap harness",
        )?,
        policy.bounds.max_bootstrap_harness_bytes,
        &policy.paths.bootstrap_harness_path,
    )?;
    let policy_binding = actual_file_binding(&policy.paths.policy_path, policy_bytes)?;
    let verifier_binding =
        actual_file_binding(&policy.paths.verifier_test_path, &verifier_bytes)?;
    let harness_binding =
        actual_file_binding(&policy.paths.bootstrap_harness_path, &harness_bytes)?;
    let marker = super::trust_std::AuthoringMarker {
        policy: super::trust_std::FileBinding {
            byte_length: policy_binding.byte_length,
            sha256: sha256(policy_bytes),
        },
        verifier: super::trust_std::FileBinding {
            byte_length: verifier_binding.byte_length,
            sha256: sha256(&verifier_bytes),
        },
        harness: super::trust_std::FileBinding {
            byte_length: harness_binding.byte_length,
            sha256: sha256(&harness_bytes),
        },
        closure_sha256: [0; 32],
    };
    let preimage = super::trust_std::authoring_closure_preimage(&marker)
        .map_err(|error| Diagnostic::error("E_AUTHORING_CLOSURE", error.to_string()))?;
    let closure_sha256 = lower_hex(&sha256(&preimage));
    Ok(ActualAuthoringBindings {
        policy: policy_binding,
        verifier: verifier_binding,
        harness: harness_binding,
        closure_sha256,
    })
}

fn validate_actual_file_binding(
    table: &toml::map::Map<String, toml::Value>,
    expected: &ActualFileBinding,
    subject: &str,
) -> VResult<()> {
    if record_string(table, "path", subject)? != expected.path
        || record_u64(table, "byte_length", subject)? != expected.byte_length
        || record_string(table, "sha256", subject)? != expected.sha256
    {
        return Err(Diagnostic::error("E_FILE_BINDING", subject));
    }
    Ok(())
}

fn validate_run_id(value: &str, subject: &str) -> VResult<[u8; 16]> {
    let decoded = super::trust_std::decode_lower_hex::<16>(value, subject)
        .map_err(|error| Diagnostic::error("E_RUN_ID", subject).at(error.to_string()))?;
    if decoded.iter().all(|byte| *byte == 0) {
        return Err(Diagnostic::error("E_RUN_ID", subject).at("all-zero"));
    }
    Ok(decoded)
}

fn parse_single_output_binding(
    table: &toml::map::Map<String, toml::Value>,
    subject: &str,
) -> VResult<ReceiptOutputBinding> {
    let mut parsed = parse_output_bindings(
        &[toml::Value::Table(table.clone())],
        subject,
    )?;
    parsed
        .pop()
        .ok_or_else(|| Diagnostic::error("E_OUTPUT_BINDING", subject))
}

fn parse_integration_edges(
    values: &[toml::Value],
    subject: &str,
) -> VResult<Vec<IntegrationEdge>> {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let logical = format!("{subject}/edge[{index}]");
            let table = value
                .as_table()
                .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", &logical))?;
            Ok(IntegrationEdge {
                child_id: record_string(table, "child_id", &logical)?.to_owned(),
                parent_id: record_string(table, "parent_id", &logical)?.to_owned(),
                purpose: record_string(table, "purpose", &logical)?.to_owned(),
            })
        })
        .collect()
}

fn parse_integration_ranks(
    values: &[toml::Value],
    subject: &str,
) -> VResult<Vec<IntegrationRank>> {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let logical = format!("{subject}/rank[{index}]");
            let table = value
                .as_table()
                .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", &logical))?;
            Ok(IntegrationRank {
                id: record_string(table, "id", &logical)?.to_owned(),
                generation_rank: record_u32(table, "generation_rank", &logical)?,
            })
        })
        .collect()
}

fn validate_runtime_absolute_path(
    path: &str,
    bounds: &Bounds,
    allow_root: bool,
    subject: &str,
) -> VResult<()> {
    if path.is_empty()
        || path.len() > bounds.max_path_bytes
        || !path.starts_with('/')
        || (!allow_root && path == "/")
        || (path.len() > 1 && path.ends_with('/'))
        || path.contains("//")
        || path.contains('\\')
        || path.as_bytes().iter().any(|byte| byte.is_ascii_control())
    {
        return Err(Diagnostic::error("E_RUNTIME_PATH", subject).at(path));
    }
    let mut depth = 0usize;
    for component in path.split('/').skip(1) {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.len() > bounds.max_path_component_bytes
        {
            return Err(Diagnostic::error("E_RUNTIME_PATH", subject).at(path));
        }
        depth = depth
            .checked_add(1)
            .ok_or_else(|| Diagnostic::error("E_RUNTIME_PATH", subject))?;
    }
    if depth > bounds.max_path_depth {
        return Err(Diagnostic::error("E_RUNTIME_PATH", subject).at(path));
    }
    Ok(())
}

fn observed_directory_path(
    table: &toml::map::Map<String, toml::Value>,
    bounds: &Bounds,
    subject: &str,
) -> VResult<String> {
    let path = record_string(table, "path", subject)?.to_owned();
    validate_runtime_absolute_path(&path, bounds, false, subject)?;
    let mode = record_u64(table, "mode", subject)?;
    if record_u64(table, "device", subject)? == 0
        || record_u64(table, "inode", subject)? == 0
        || record_u64(table, "nlink", subject)? == 0
        || mode & 0o170_000 != 0o040_000
    {
        return Err(Diagnostic::error("E_RUNTIME_DIRECTORY", subject));
    }
    Ok(path)
}

fn observed_file_path(
    table: &toml::map::Map<String, toml::Value>,
    bounds: &Bounds,
    subject: &str,
) -> VResult<String> {
    let path = record_string(table, "path", subject)?.to_owned();
    validate_runtime_absolute_path(&path, bounds, false, subject)?;
    if record_u64(table, "byte_length", subject)? == 0 {
        return Err(Diagnostic::error("E_RUNTIME_FILE", subject));
    }
    validate_sha256(record_string(table, "sha256", subject)?, subject)?;
    Ok(path)
}

fn parse_environment_assignment_records(
    values: &[toml::Value],
    subject: &str,
) -> VResult<Vec<(String, String)>> {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let logical = format!("{subject}/assignment[{index}]");
            let table = value
                .as_table()
                .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", &logical))?;
            Ok((
                record_string(table, "key", &logical)?.to_owned(),
                record_string(table, "value", &logical)?.to_owned(),
            ))
        })
        .collect()
}

fn parse_producer_environment_summary(
    body: &toml::map::Map<String, toml::Value>,
    policy: &Policy,
    run_id: &str,
    subject: &str,
) -> VResult<ProducerEnvironmentSummary> {
    let worker = record_table(body, "actual_worker", subject)?;
    let worker_id = record_string(worker, "worker_id", subject)?.to_owned();
    let repository_root = record_string(worker, "remote_repository_root", subject)?.to_owned();
    validate_runtime_absolute_path(&repository_root, &policy.bounds, false, subject)?;
    if worker_id.is_empty()
        || record_string(worker, "os", subject)? != "Linux"
        || record_string(worker, "arch", subject)? != "x86_64"
        || record_u64(worker, "process_id", subject)? == 0
        || record_u64(worker, "parent_process_id", subject)? == 0
    {
        return Err(Diagnostic::error("E_COMMAND_WORKER", subject));
    }
    validate_sha256(
        record_string(worker, "machine_id_sha256", subject)?,
        subject,
    )?;

    let expected_tool_ids =
        policy_string_array(policy, "command_environment_profiles", "tool_inventory_ids")?;
    let tool_rows = record_array(body, "tool", subject)?;
    if record_usize(body, "tool_count", subject)? != tool_rows.len()
        || tool_rows.len() != expected_tool_ids.len()
    {
        return Err(Diagnostic::error("E_COMMAND_TOOL", subject));
    }
    let mut tools = BTreeMap::new();
    for (index, value) in tool_rows.iter().enumerate() {
        let logical = format!("{subject}/tool[{index}]");
        let table = value
            .as_table()
            .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", &logical))?;
        let id = record_string(table, "id", &logical)?;
        if id != expected_tool_ids[index] || record_string(table, "version", &logical)?.is_empty() {
            return Err(Diagnostic::error("E_COMMAND_TOOL", &logical));
        }
        let path = observed_file_path(table, &policy.bounds, &logical)?;
        if tools.insert(id.to_owned(), path).is_some() {
            return Err(Diagnostic::error("E_COMMAND_TOOL", &logical).at("duplicate"));
        }
    }

    let profile_rows = record_array(body, "environment_profile", subject)?;
    if record_usize(body, "environment_profile_count", subject)? != profile_rows.len()
        || profile_rows.len() != policy.environment_profile.len()
    {
        return Err(Diagnostic::error("E_COMMAND_ENVIRONMENT", subject));
    }
    for (index, (value, expected)) in profile_rows
        .iter()
        .zip(&policy.environment_profile)
        .enumerate()
    {
        let logical = format!("{subject}/environment_profile[{index}]");
        let table = value
            .as_table()
            .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", &logical))?;
        let assignments = record_array(table, "assignment", &logical)?;
        let parsed = parse_environment_assignment_records(assignments, &logical)?;
        let expected_pairs = expected
            .required
            .iter()
            .map(|pair| (pair[0].clone(), pair[1].clone()))
            .collect::<Vec<_>>();
        if record_string(table, "id", &logical)? != expected.id
            || record_usize(table, "assignment_count", &logical)? != assignments.len()
            || parsed != expected_pairs
            || record_string(table, "set_sha256", &logical)?
                != record_set_sha256(assignments, "environment-assignment", policy, &logical)?
        {
            return Err(Diagnostic::error("E_COMMAND_ENVIRONMENT", &logical));
        }
    }

    let proxy_rows = record_array(body, "proxy", subject)?;
    if record_usize(body, "proxy_count", subject)? != proxy_rows.len()
        || proxy_rows.len() > 4
    {
        return Err(Diagnostic::error("E_COMMAND_PROXY", subject));
    }
    let proxies = parse_environment_assignment_records(proxy_rows, subject)?;
    let proxy_order = ["ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"];
    let mut last_proxy_index = None;
    for (key, value) in &proxies {
        let index = proxy_order
            .iter()
            .position(|candidate| candidate == key)
            .ok_or_else(|| Diagnostic::error("E_COMMAND_PROXY", subject).at(key))?;
        if value.is_empty()
            || value.len() > policy.bounds.max_environment_value_bytes
            || last_proxy_index.is_some_and(|prior| index <= prior)
        {
            return Err(Diagnostic::error("E_COMMAND_PROXY", subject).at(key));
        }
        last_proxy_index = Some(index);
    }

    let target_rows = record_array(body, "target_tool_profile", subject)?;
    if record_usize(body, "target_tool_profile_count", subject)? != target_rows.len()
        || target_rows.len() != policy.target_tool_profile.len()
    {
        return Err(Diagnostic::error("E_COMMAND_TARGET_TOOL", subject));
    }
    let mut target_tool_paths = BTreeMap::new();
    for (index, (value, expected)) in target_rows
        .iter()
        .zip(&policy.target_tool_profile)
        .enumerate()
    {
        let logical = format!("{subject}/target_tool_profile[{index}]");
        let table = value
            .as_table()
            .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", &logical))?;
        for (field, expected_value) in [
            ("target", expected.target.as_str()),
            ("cc_tool_id", expected.cc_tool_id.as_str()),
            ("ar_tool_id", expected.ar_tool_id.as_str()),
            ("linker_tool_id", expected.linker_tool_id.as_str()),
            ("cc_env_key", expected.cc_env_key.as_str()),
            ("ar_env_key", expected.ar_env_key.as_str()),
            ("cflags_env_key", expected.cflags_env_key.as_str()),
            ("linker_env_key", expected.linker_env_key.as_str()),
            ("rustflags_env_key", expected.rustflags_env_key.as_str()),
            ("cflags_exact", expected.cflags_exact.as_str()),
            ("rustflags_exact", expected.rustflags_exact.as_str()),
            ("linker_flavor", expected.linker_flavor.as_str()),
            ("input_root_id", expected.input_root_id.as_str()),
            ("sdk_binding", expected.sdk_binding.as_str()),
            ("rustlib_binding", expected.rustlib_binding.as_str()),
        ] {
            if record_string(table, field, &logical)? != expected_value {
                return Err(Diagnostic::error("E_COMMAND_TARGET_TOOL", &logical).at(field));
            }
        }
        if expected.sdk_binding != expected.input_root_id
            || record_string_array(table, "linker_args_exact", &logical)?
                != expected.linker_args_exact
        {
            return Err(Diagnostic::error("E_COMMAND_TARGET_TOOL", &logical));
        }
        let cc = observed_file_path(
            record_table(table, "cc", &logical)?,
            &policy.bounds,
            &logical,
        )?;
        let ar = observed_file_path(
            record_table(table, "ar", &logical)?,
            &policy.bounds,
            &logical,
        )?;
        let linker = observed_file_path(
            record_table(table, "linker", &logical)?,
            &policy.bounds,
            &logical,
        )?;
        if tools.get(&expected.cc_tool_id) != Some(&cc)
            || tools.get(&expected.ar_tool_id) != Some(&ar)
            || tools.get(&expected.linker_tool_id) != Some(&linker)
            || target_tool_paths
                .insert(expected.target.clone(), (cc, ar, linker))
                .is_some()
        {
            return Err(Diagnostic::error("E_COMMAND_TARGET_TOOL", &logical));
        }
    }

    let expected_root_ids =
        policy_string_array(policy, "external_input_root_contract", "root_ids")?;
    let external_rows = record_array(body, "external_input_root", subject)?;
    if record_usize(body, "external_input_root_count", subject)? != external_rows.len()
        || external_rows.len() != expected_root_ids.len()
    {
        return Err(Diagnostic::error("E_EXTERNAL_ROOT", subject));
    }
    let mut external_roots = BTreeMap::new();
    for (index, value) in external_rows.iter().enumerate() {
        let logical = format!("{subject}/external_input_root[{index}]");
        let table = value
            .as_table()
            .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", &logical))?;
        let id = record_string(table, "id", &logical)?;
        let path = record_string(table, "path", &logical)?.to_owned();
        let tree_sha256 = record_string(table, "tree_sha256", &logical)?.to_owned();
        if id != expected_root_ids[index]
            || record_u64(table, "device", &logical)? == 0
            || record_u64(table, "inode", &logical)? == 0
            || record_u64(table, "nlink", &logical)? == 0
            || record_u64(table, "entry_count", &logical)? == 0
            || record_u64(table, "total_regular_file_bytes", &logical)? == 0
        {
            return Err(Diagnostic::error("E_EXTERNAL_ROOT", &logical));
        }
        validate_runtime_absolute_path(&path, &policy.bounds, true, &logical)?;
        validate_sha256(&tree_sha256, &logical)?;
        if external_roots
            .insert(id.to_owned(), ExternalRootObservation { path, tree_sha256 })
            .is_some()
        {
            return Err(Diagnostic::error("E_EXTERNAL_ROOT", &logical).at("duplicate"));
        }
    }
    for profile in &policy.target_tool_profile {
        if !external_roots.contains_key(&profile.input_root_id) {
            return Err(Diagnostic::error("E_EXTERNAL_ROOT", &profile.target)
                .at(&profile.input_root_id));
        }
    }

    let run_root = observed_directory_path(
        record_table(body, "run_root", subject)?,
        &policy.bounds,
        subject,
    )?;
    let acquisition_cargo_home = observed_directory_path(
        record_table(body, "acquisition_cargo_home", subject)?,
        &policy.bounds,
        subject,
    )?;
    let offline_cargo_home = observed_directory_path(
        record_table(body, "offline_cargo_home", subject)?,
        &policy.bounds,
        subject,
    )?;
    let acquisition_target_root = observed_directory_path(
        record_table(body, "acquisition_target_root", subject)?,
        &policy.bounds,
        subject,
    )?;
    let execution_bin_table = record_table(body, "execution_bin", subject)?;
    let execution_bin =
        observed_directory_path(execution_bin_table, &policy.bounds, subject)?;
    if record_usize(execution_bin_table, "entry_count", subject)? != tools.len() {
        return Err(Diagnostic::error("E_EXECUTION_BIN", subject));
    }
    validate_sha256(
        record_string(execution_bin_table, "entry_set_sha256", subject)?,
        subject,
    )?;
    let local_registry_table = record_table(body, "local_registry", subject)?;
    let local_registry =
        observed_directory_path(local_registry_table, &policy.bounds, subject)?;
    if record_string(local_registry_table, "id", subject)? != "sealed-local-registry"
        || record_u64(local_registry_table, "entry_count", subject)? == 0
        || record_u64(local_registry_table, "total_regular_file_bytes", subject)? == 0
    {
        return Err(Diagnostic::error("E_LOCAL_REGISTRY", subject));
    }
    validate_sha256(
        record_string(local_registry_table, "tree_sha256", subject)?,
        subject,
    )?;
    let return_root = observed_directory_path(
        record_table(body, "return_root", subject)?,
        &policy.bounds,
        subject,
    )?;

    let role_run_root = format!("{repository_root}/.fnd01-run/integration-producer/{run_id}");
    if run_root != role_run_root
        || acquisition_cargo_home != format!("{role_run_root}/cargo-home/acquisition")
        || offline_cargo_home != format!("{role_run_root}/cargo-home/offline")
        || acquisition_target_root != format!("{role_run_root}/targets/acquisition")
        || execution_bin != format!("{role_run_root}/execution-bin")
        || local_registry != format!("{role_run_root}/local-registry")
        || return_root != format!("{repository_root}/target/debug/fnd-01/{run_id}/return")
        || acquisition_cargo_home == offline_cargo_home
    {
        return Err(Diagnostic::error("E_GENERATED_PATH", subject));
    }

    Ok(ProducerEnvironmentSummary {
        worker_id,
        repository_root,
        tools,
        proxies,
        target_tool_paths,
        external_roots,
        run_root,
        acquisition_cargo_home,
        offline_cargo_home,
        acquisition_target_root,
        execution_bin,
        local_registry,
        return_root,
    })
}

fn parse_receipt_v2(
    bytes: &[u8],
    subject: &str,
    output: &DerivedOutputContract,
    policy: &Policy,
    authoring: &ActualAuthoringBindings,
) -> VResult<ParsedReceipt> {
    let raw: toml::Value = parse_toml_strict(bytes, subject)?;
    let (root, body, schema) = validate_receipt_record_shape(&raw, policy, subject)?;
    if record_string(root, "format", subject)? != policy.receipt_contract.format_literal
        || record_u32(root, "schema_version", subject)?
            != policy.receipt_contract.schema_version_literal
        || record_string(root, "receipt_id", subject)? != output.id
        || record_string(root, "kind", subject)? != output.kind
        || record_string(root, "path", subject)? != output.path
        || record_u32(root, "generation_rank", subject)? != output.generation_rank
        || record_string(root, "producer_bead", subject)? != output.producer_bead
        || record_string(root, "producer_role", subject)? != "integration-producer"
        || record_string(root, "evidence_verdict", subject)? != "Pass"
        || record_bool(root, "support_claim", subject)?
        || record_usize(root, "source_tree_file_count", subject)?
            != policy.source_tree.file_count
        || record_u64(root, "source_tree_total_bytes", subject)?
            != policy.source_tree.total_bytes
        || record_string(root, "source_tree_sha256", subject)? != policy.source_tree.sha256
    {
        return Err(Diagnostic::error("E_RECEIPT_COMMON", subject));
    }
    let run_id = record_string(root, "run_id", subject)?.to_owned();
    validate_run_id(&run_id, subject)?;
    let authoring_closure_sha256 =
        record_string(root, "authoring_closure_sha256", subject)?.to_owned();
    validate_sha256(&authoring_closure_sha256, subject)?;
    if authoring_closure_sha256 != authoring.closure_sha256 {
        return Err(Diagnostic::error("E_AUTHORING_CLOSURE", subject));
    }
    validate_actual_file_binding(
        record_table(root, "policy", subject)?,
        &authoring.policy,
        subject,
    )?;
    validate_actual_file_binding(
        record_table(root, "verifier", subject)?,
        &authoring.verifier,
        subject,
    )?;
    validate_actual_file_binding(
        record_table(root, "harness", subject)?,
        &authoring.harness,
        subject,
    )?;
    let parents = parse_parent_bindings(record_array(root, "parent", subject)?, subject)?;
    if record_usize(root, "parent_count", subject)? != parents.len() {
        return Err(Diagnostic::error("E_RECEIPT_PARENT_COUNT", subject));
    }

    let (sidecar_output, sidecar_parents) = match schema.kind.as_str() {
        "supply_receipt" => (
            Some(parse_single_output_binding(
                record_table(body, "bundle", subject)?,
                subject,
            )?),
            parse_parent_bindings(record_array(body, "bundle_parent", subject)?, subject)?,
        ),
        "command_results" => (
            Some(parse_single_output_binding(
                record_table(body, "streams", subject)?,
                subject,
            )?),
            parse_parent_bindings(record_array(body, "streams_parent", subject)?, subject)?,
        ),
        "package_receipt" => (
            Some(parse_single_output_binding(
                record_table(body, "artifacts", subject)?,
                subject,
            )?),
            parse_parent_bindings(record_array(body, "artifacts_parent", subject)?, subject)?,
        ),
        _ => (None, Vec::new()),
    };
    if let Some(binding) = &sidecar_output {
        let count_field = match binding.id.as_str() {
            "supply-bundle" => "bundle_parent_count",
            "command-streams" => "streams_parent_count",
            "package-artifacts" => "artifacts_parent_count",
            _ => {
                return Err(Diagnostic::error("E_BINARY_SIDECAR", subject).at(&binding.id));
            }
        };
        if record_usize(body, count_field, subject)? != sidecar_parents.len() {
            return Err(Diagnostic::error("E_BINARY_SIDECAR", subject).at(count_field));
        }
    }

    let producer_environment = if schema.kind == "producer_environment" {
        Some(parse_producer_environment_summary(
            body, policy, &run_id, subject,
        )?)
    } else {
        None
    };
    let actual_worker_id = producer_environment
        .as_ref()
        .map(|environment| environment.worker_id.clone());

    let (
        control_frame,
        bootstrap_control,
        command_ids,
        command_results,
        postcommand_locks,
        postcommand_package_set_sha256,
    ) = if schema.kind == "command_results" {
        let control_frames = record_array(body, "control_frame", subject)?;
        let control_table = control_frames
            .first()
            .and_then(toml::Value::as_table)
            .ok_or_else(|| Diagnostic::error("E_COMMAND_CONTROL_FRAME", subject))?;
        if record_usize(body, "control_frame_count", subject)? != 1
            || control_frames.len() != 1
            || record_string(control_table, "kind", subject)? != "control"
            || record_string(control_table, "id", subject)? != "bootstrap-control.build"
            || record_u64(control_table, "ordinal", subject)? != 0
        {
            return Err(Diagnostic::error("E_COMMAND_CONTROL_FRAME", subject));
        }
        let control_frame = CommandStreamBinding {
            id: "bootstrap-control.build".to_owned(),
            stdout: stream_region_from_record(control_table, "stdout", subject)?,
            stderr: stream_region_from_record(control_table, "stderr", subject)?,
        };
        let bootstrap_table = record_table(body, "bootstrap_control_build", subject)?;
        if record_string(bootstrap_table, "id", subject)? != "bootstrap-control.build"
            || record_i64(bootstrap_table, "exit_code", subject)? != 0
            || record_string(bootstrap_table, "evidence_verdict", subject)? != "Pass"
        {
            return Err(Diagnostic::error("E_COMMAND_CONTROL_BUILD", subject));
        }
        let bootstrap_control = CommandStreamBinding {
            id: "bootstrap-control.build".to_owned(),
            stdout: stream_region_from_record(bootstrap_table, "stdout", subject)?,
            stderr: stream_region_from_record(bootstrap_table, "stderr", subject)?,
        };
        if bootstrap_control != control_frame {
            return Err(Diagnostic::error("E_COMMAND_CONTROL_JOIN", subject));
        }
        let command_rows = record_array(body, "command", subject)?;
        let expected_ids = expected_command_ids(policy)?;
        if record_usize(body, "command_count", subject)? != command_rows.len()
            || command_rows.len() != expected_ids.len()
        {
            return Err(Diagnostic::error("E_COMMAND_COUNT", subject));
        }
        let mut command_ids = Vec::with_capacity(command_rows.len());
        let mut command_results = Vec::with_capacity(command_rows.len());
        for (index, value) in command_rows.iter().enumerate() {
            let logical = format!("{subject}/command[{index}]");
            let table = value
                .as_table()
                .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", &logical))?;
            let parsed =
                validate_command_result_row(table, index, &expected_ids[index], policy, &logical)?;
            command_ids.push(parsed.id.clone());
            command_results.push(parsed);
        }
        validate_case_unique(command_ids.iter().cloned(), "command result IDs")?;
        let command_matrix = policy_unmodeled_table(policy, "command_matrix_contract")?;
        let expected_template_count =
            record_usize(command_matrix, "exact_template_count", "command_matrix_contract")?;
        let expected_cargo_count =
            record_usize(command_matrix, "exact_cargo_command_count", "command_matrix_contract")?;
        let expected_non_cargo_count = record_usize(
            command_matrix,
            "exact_non_cargo_command_count",
            "command_matrix_contract",
        )?;
        let expected_attester_count = record_usize(
            command_matrix,
            "exact_attester_command_count",
            "command_matrix_contract",
        )?;
        let expected_excluded = policy_string_array(
            policy,
            "command_matrix_contract",
            "attester_excluded_command_ids",
        )?;
        let compile_cells = record_array(body, "compile_cell", subject)?;
        if record_usize(body, "template_count", subject)? != expected_template_count
            || record_usize(body, "cargo_command_count", subject)? != expected_cargo_count
            || record_usize(body, "non_cargo_command_count", subject)?
                != expected_non_cargo_count
            || record_usize(body, "producer_pass_count", subject)? != command_rows.len()
            || record_usize(body, "attester_expected_command_count", subject)?
                != expected_attester_count
            || record_string_array(body, "attester_excluded_command_ids", subject)?
                != expected_excluded
            || record_usize(body, "compile_cell_count", subject)? != compile_cells.len()
            || compile_cells.len() != 65
        {
            return Err(Diagnostic::error("E_COMMAND_AGGREGATE_COUNT", subject));
        }
        validate_compile_cells(compile_cells, &command_results, policy, subject)?;
        let expected_template_set = command_template_set_sha256(policy)?;
        let expected_command_set =
            record_set_sha256(command_rows, "command-result", policy, subject)?;
        let expected_compile_cell_set =
            record_set_sha256(compile_cells, "compile-cell", policy, subject)?;
        if record_string(body, "template_set_sha256", subject)? != expected_template_set
            || record_string(body, "command_set_sha256", subject)? != expected_command_set
            || record_string(body, "compile_cell_set_sha256", subject)?
                != expected_compile_cell_set
        {
            return Err(Diagnostic::error("E_COMMAND_AGGREGATE_DIGEST", subject));
        }
        validate_sha256(
            record_string(body, "postcommand_package_set_sha256", subject)?,
            subject,
        )?;
        let lock_rows = record_array(body, "postcommand_lock", subject)?;
        if record_usize(body, "postcommand_lock_count", subject)? != lock_rows.len() {
            return Err(Diagnostic::error("E_COMMAND_LOCK_COUNT", subject));
        }
        let expected_lock_ids =
            policy_string_array(policy, "lockfile_producer_contract", "lock_ids")?;
        let expected_producer_ids =
            policy_string_array(policy, "lockfile_producer_contract", "producer_command_ids")?;
        if lock_rows.len() != expected_lock_ids.len()
            || lock_rows.len() != expected_producer_ids.len()
        {
            return Err(Diagnostic::error("E_COMMAND_LOCK_COUNT", subject));
        }
        let mut locks = Vec::with_capacity(lock_rows.len());
        for (index, value) in lock_rows.iter().enumerate() {
            let logical = format!("{subject}/postcommand_lock[{index}]");
            let table = value
                .as_table()
                .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", &logical))?;
            let id = record_string(table, "id", &logical)?;
            let producer_command_id =
                record_string(table, "producer_command_id", &logical)?;
            let path = record_string(table, "path", &logical)?;
            validate_ascii_posix_path(path, &logical)?;
            let byte_length = record_u64(table, "byte_length", &logical)?;
            let stream_byte_length =
                record_u64(table, "stream_byte_length", &logical)?;
            let sha256 = record_string(table, "sha256", &logical)?.to_owned();
            let package_set_sha256 =
                record_string(table, "package_set_sha256", &logical)?.to_owned();
            let stream_offset = record_u64(table, "stream_offset", &logical)?;
            validate_sha256(&sha256, &logical)?;
            validate_sha256(&package_set_sha256, &logical)?;
            if id != expected_lock_ids[index]
                || producer_command_id != expected_producer_ids[index]
                || byte_length == 0
                || byte_length != stream_byte_length
                || byte_length > policy.bounds.max_record_blob_bytes
                || stream_offset.checked_add(stream_byte_length).is_none()
            {
                return Err(Diagnostic::error("E_COMMAND_LOCK_BINDING", &logical));
            }
            locks.push(ParsedPostcommandLock {
                id: id.to_owned(),
                producer_command_id: producer_command_id.to_owned(),
                region: StreamRegionBinding {
                    offset: stream_offset,
                    byte_length: stream_byte_length,
                    sha256,
                },
                package_set_sha256,
            });
        }
        validate_case_unique(
            locks.iter().map(|lock| lock.id.clone()),
            "postcommand lock IDs",
        )?;
        let expected_lock_set =
            record_set_sha256(lock_rows, "postcommand-lock-binding", policy, subject)?;
        if record_string(body, "postcommand_lock_set_sha256", subject)?
            != expected_lock_set
        {
            return Err(Diagnostic::error("E_COMMAND_LOCK_SET_DIGEST", subject));
        }
        (
            Some(control_frame),
            Some(bootstrap_control),
            command_ids,
            command_results,
            locks,
            Some(record_string(body, "postcommand_package_set_sha256", subject)?.to_owned()),
        )
    } else {
        (None, None, Vec::new(), Vec::new(), Vec::new(), None)
    };

    let (integration_members, integration_edges, integration_ranks) =
        if schema.kind == "integration_index" {
            let members =
                parse_output_bindings(record_array(body, "member", subject)?, subject)?;
            let edges = parse_integration_edges(record_array(body, "edge", subject)?, subject)?;
            let ranks = parse_integration_ranks(record_array(body, "rank", subject)?, subject)?;
            if record_usize(body, "member_count", subject)? != members.len()
                || record_usize(body, "edge_count", subject)? != edges.len()
                || record_usize(body, "rank_count", subject)? != ranks.len()
            {
                return Err(Diagnostic::error("E_INTEGRATION_INDEX_COUNT", subject));
            }
            validate_sha256(
                record_string(body, "output_set_sha256", subject)?,
                subject,
            )?;
            validate_sha256(record_string(body, "edge_set_sha256", subject)?, subject)?;
            (members, edges, ranks)
        } else {
            (Vec::new(), Vec::new(), Vec::new())
        };

    Ok(ParsedReceipt {
        receipt_id: output.id.clone(),
        run_id,
        parents,
        sidecar_output,
        sidecar_parents,
        actual_worker_id,
        producer_environment,
        control_frame,
        bootstrap_control,
        command_ids,
        command_results,
        postcommand_locks,
        postcommand_package_set_sha256,
        integration_members,
        integration_edges,
        integration_ranks,
    })
}

#[derive(Debug)]
struct BinaryCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
    subject: &'a str,
}

impl<'a> BinaryCursor<'a> {
    fn new(bytes: &'a [u8], subject: &'a str) -> Self {
        Self {
            bytes,
            offset: 0,
            subject,
        }
    }

    fn read_exact(&mut self, length: usize) -> VResult<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| Diagnostic::error("E_BINARY_BOUND", self.subject))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| Diagnostic::error("E_BINARY_TRUNCATED", self.subject))?;
        self.offset = end;
        Ok(value)
    }

    fn read_u8(&mut self) -> VResult<u8> {
        self.read_exact(1)
            .map(|bytes| bytes[0])
    }

    fn read_u32(&mut self) -> VResult<u32> {
        let bytes: [u8; 4] = self
            .read_exact(4)?
            .try_into()
            .map_err(|_| Diagnostic::error("E_BINARY_TRUNCATED", self.subject))?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn read_u64(&mut self) -> VResult<u64> {
        let bytes: [u8; 8] = self
            .read_exact(8)?
            .try_into()
            .map_err(|_| Diagnostic::error("E_BINARY_TRUNCATED", self.subject))?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn position(&self) -> usize {
        self.offset
    }

    fn read_len(&mut self, maximum: usize) -> VResult<usize> {
        let length = usize::try_from(self.read_u32()?)
            .map_err(|_| Diagnostic::error("E_BINARY_BOUND", self.subject))?;
        if length > maximum {
            return Err(Diagnostic::error("E_BINARY_BOUND", self.subject)
                .at(length.to_string()));
        }
        Ok(length)
    }

    fn read_string(&mut self, maximum: usize) -> VResult<String> {
        let length = self.read_len(maximum)?;
        let bytes = self.read_exact(length)?;
        let value = std::str::from_utf8(bytes)
            .map_err(|_| Diagnostic::error("E_BINARY_UTF8", self.subject))?;
        if value.is_empty() || value.as_bytes().contains(&0) {
            return Err(Diagnostic::error("E_BINARY_UTF8", self.subject));
        }
        Ok(value.to_owned())
    }

    fn finish(self) -> VResult<()> {
        if self.offset != self.bytes.len() {
            return Err(Diagnostic::error("E_BINARY_TRAILING", self.subject)
                .at((self.bytes.len() - self.offset).to_string()));
        }
        Ok(())
    }
}

fn checked_payload_length(length: u64, maximum: u64, subject: &str) -> VResult<usize> {
    if length == 0 || length > maximum {
        return Err(Diagnostic::error("E_BINARY_BOUND", subject).at(length.to_string()));
    }
    usize::try_from(length)
        .map_err(|_| Diagnostic::error("E_BINARY_BOUND", subject).at(length.to_string()))
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RegistryPackageTriple {
    name: String,
    version: String,
    checksum: String,
}

fn crates_io_index_path(package_name: &str, subject: &str) -> VResult<String> {
    if package_name.is_empty()
        || package_name.len() > 64
        || !package_name.is_ascii()
        || package_name != package_name.to_ascii_lowercase()
        || !package_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(Diagnostic::error("E_SUPPLY_INDEX_PATH", subject).at(package_name));
    }
    let path = match package_name.len() {
        1 => format!("1/{package_name}"),
        2 => format!("2/{package_name}"),
        3 => format!("3/{}/{package_name}", &package_name[..1]),
        _ => format!(
            "{}/{}/{package_name}",
            &package_name[..2],
            &package_name[2..4]
        ),
    };
    Ok(format!("index/{path}"))
}

fn strict_json_object<'a>(
    value: &'a StrictJson,
    subject: &str,
) -> VResult<&'a BTreeMap<String, StrictJson>> {
    match value {
        StrictJson::Object(object) => Ok(object),
        _ => Err(Diagnostic::error("E_SUPPLY_INDEX_JSON", subject).at("object")),
    }
}

fn strict_json_string<'a>(
    object: &'a BTreeMap<String, StrictJson>,
    field: &str,
    subject: &str,
) -> VResult<&'a str> {
    match object.get(field) {
        Some(StrictJson::String(value)) if !value.is_empty() => Ok(value),
        _ => Err(Diagnostic::error("E_SUPPLY_INDEX_JSON", subject).at(field)),
    }
}

fn strict_json_bool(
    object: &BTreeMap<String, StrictJson>,
    field: &str,
    subject: &str,
) -> VResult<bool> {
    match object.get(field) {
        Some(StrictJson::Bool(value)) => Ok(*value),
        _ => Err(Diagnostic::error("E_SUPPLY_INDEX_JSON", subject).at(field)),
    }
}

fn registry_packages_from_lock(
    lock: &toml::Value,
    subject: &str,
) -> VResult<BTreeSet<RegistryPackageTriple>> {
    let root = lock
        .as_table()
        .ok_or_else(|| Diagnostic::error("E_SUPPLY_LOCK_SCHEMA", subject))?;
    let packages = root
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| Diagnostic::error("E_SUPPLY_LOCK_SCHEMA", subject).at("package"))?;
    let mut triples = BTreeSet::new();
    for (index, package) in packages.iter().enumerate() {
        let logical = format!("{subject}/package[{index}]");
        let package = package
            .as_table()
            .ok_or_else(|| Diagnostic::error("E_SUPPLY_LOCK_SCHEMA", &logical))?;
        let source = package.get("source");
        let checksum = package.get("checksum");
        if source.is_none() && checksum.is_none() {
            continue;
        }
        let source = source
            .and_then(toml::Value::as_str)
            .ok_or_else(|| Diagnostic::error("E_SUPPLY_LOCK_SCHEMA", &logical).at("source"))?;
        if source != "registry+https://github.com/rust-lang/crates.io-index" {
            return Err(Diagnostic::error("E_SUPPLY_LOCK_SOURCE", &logical).at(source));
        }
        let checksum = checksum
            .and_then(toml::Value::as_str)
            .ok_or_else(|| Diagnostic::error("E_SUPPLY_LOCK_SCHEMA", &logical).at("checksum"))?;
        validate_sha256(checksum, &logical)?;
        let name = package
            .get("name")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| Diagnostic::error("E_SUPPLY_LOCK_SCHEMA", &logical).at("name"))?;
        crates_io_index_path(name, &logical)?;
        let version = package
            .get("version")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| Diagnostic::error("E_SUPPLY_LOCK_SCHEMA", &logical).at("version"))?;
        if version.is_empty()
            || !version.is_ascii()
            || version.bytes().any(|byte| {
                !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
            })
        {
            return Err(Diagnostic::error("E_SUPPLY_LOCK_SCHEMA", &logical).at("version"));
        }
        if !triples.insert(RegistryPackageTriple {
            name: name.to_owned(),
            version: version.to_owned(),
            checksum: checksum.to_owned(),
        }) {
            return Err(Diagnostic::error("E_SUPPLY_LOCK_DUPLICATE", &logical));
        }
    }
    if triples.is_empty() {
        return Err(Diagnostic::error("E_SUPPLY_LOCK_SCHEMA", subject)
            .at("empty crates.io closure"));
    }
    Ok(triples)
}

fn registry_package_set_sha256(
    packages: &BTreeSet<RegistryPackageTriple>,
    subject: &str,
) -> VResult<String> {
    let mut checksum_by_identity = BTreeMap::<(&str, &str), &str>::new();
    for package in packages {
        let identity = (package.name.as_str(), package.version.as_str());
        if checksum_by_identity
            .insert(identity, package.checksum.as_str())
            .is_some_and(|prior| prior != package.checksum.as_str())
        {
            return Err(Diagnostic::error("E_SUPPLY_LOCK_CHECKSUM_CONFLICT", subject)
                .at(format!("{} {}", package.name, package.version)));
        }
    }
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"FND01LOCKPACKAGESETv1\0");
    append_registry_count(&mut encoded, packages.len(), subject)?;
    for package in packages {
        append_registry_row(&mut encoded, &package.name, subject)?;
        append_registry_row(&mut encoded, &package.version, subject)?;
        append_registry_row(&mut encoded, &package.checksum, subject)?;
    }
    Ok(lower_hex(&sha256(&encoded)))
}

fn lock_packages_and_set_sha256(
    lock: &toml::Value,
    subject: &str,
) -> VResult<(BTreeSet<RegistryPackageTriple>, String)> {
    let packages = registry_packages_from_lock(lock, subject)?;
    let package_set_sha256 = registry_package_set_sha256(&packages, subject)?;
    Ok((packages, package_set_sha256))
}

fn validate_supply_bundle(
    bytes: &[u8],
    policy: &Policy,
    subject: &str,
) -> VResult<()> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > policy.bounds.max_supply_bundle_bytes {
        return Err(Diagnostic::error("E_BINARY_BOUND", subject));
    }
    let mut cursor = BinaryCursor::new(bytes, subject);
    if cursor.read_exact(b"FND01SUPPLYv2\0".len())? != b"FND01SUPPLYv2\0" {
        return Err(Diagnostic::error("E_SUPPLY_HEADER", subject));
    }
    let lock_length = checked_payload_length(
        cursor.read_u64()?,
        policy.bounds.max_record_blob_bytes,
        subject,
    )?;
    let lock_sha256 = cursor.read_exact(32)?;
    let lock_bytes = cursor.read_exact(lock_length)?;
    if sha256(lock_bytes).as_slice() != lock_sha256 {
        return Err(Diagnostic::error("E_SUPPLY_LOCK_HASH", subject));
    }
    let bootstrap_lock: toml::Value =
        parse_toml_strict(lock_bytes, "supply bootstrap Cargo.lock")?;
    let lock_packages =
        registry_packages_from_lock(&bootstrap_lock, "supply bootstrap Cargo.lock")?;

    let entry_count = usize::try_from(cursor.read_u32()?)
        .map_err(|_| Diagnostic::error("E_SUPPLY_COUNT", subject))?;
    if entry_count == 0 || entry_count > policy.bounds.max_record_array_items {
        return Err(Diagnostic::error("E_SUPPLY_COUNT", subject));
    }
    let declared_payload_bytes = cursor.read_u64()?;
    let declared_inner_sha256 = cursor.read_exact(32)?.to_owned();
    let mut inner = Sha256::new();
    inner.update(b"FND01SUPPLY-ENTRIESv1\0");
    inner.update(
        u32::try_from(entry_count)
            .map_err(|_| Diagnostic::error("E_SUPPLY_COUNT", subject))?
            .to_be_bytes(),
    );
    let mut total_payload_bytes = 0u64;
    let mut prior_key = None::<(u8, Vec<u8>)>;
    let mut paths = Vec::with_capacity(entry_count);
    let mut crate_packages = BTreeSet::new();
    let mut index_packages = BTreeSet::new();
    let mut index_file_names = BTreeSet::new();
    for _ in 0..entry_count {
        let kind = cursor.read_u8()?;
        if !matches!(kind, 0x01 | 0x02) {
            return Err(Diagnostic::error("E_SUPPLY_KIND", subject).at(kind.to_string()));
        }
        let path = cursor.read_string(policy.bounds.max_path_bytes)?;
        validate_ascii_posix_path(&path, subject)?;
        let key = (kind, path.as_bytes().to_vec());
        if prior_key.as_ref().is_some_and(|prior| prior >= &key) {
            return Err(Diagnostic::error("E_SUPPLY_ORDER", subject).at(&path));
        }
        prior_key = Some(key);
        paths.push(path.clone());
        let payload_length_u64 = cursor.read_u64()?;
        let payload_length = checked_payload_length(
            payload_length_u64,
            policy.bounds.max_record_blob_bytes,
            subject,
        )?;
        let payload_sha256 = cursor.read_exact(32)?;
        let payload = cursor.read_exact(payload_length)?;
        if sha256(payload).as_slice() != payload_sha256 {
            return Err(Diagnostic::error("E_SUPPLY_ENTRY_HASH", subject).at(&path));
        }
        total_payload_bytes = total_payload_bytes
            .checked_add(payload_length_u64)
            .ok_or_else(|| Diagnostic::error("E_SUPPLY_BOUND", subject))?;
        inner.update([kind]);
        inner.update(
            u32::try_from(path.len())
                .map_err(|_| Diagnostic::error("E_SUPPLY_BOUND", subject))?
                .to_be_bytes(),
        );
        inner.update(path.as_bytes());
        inner.update(payload_length_u64.to_be_bytes());
        inner.update(payload_sha256);
        inner.update(payload);
        if kind == 0x01 {
            let basename = path.strip_suffix(".crate").ok_or_else(|| {
                Diagnostic::error("E_SUPPLY_CRATE_PATH", subject).at(&path)
            })?;
            if path.contains('/') || basename.is_empty() {
                return Err(Diagnostic::error("E_SUPPLY_CRATE_PATH", subject).at(&path));
            }
            validate_gzip_tar(
                payload,
                &policy.bounds.archive_bounds(),
                &path,
                Some(basename),
            )?;
            let checksum = lower_hex(&sha256(payload));
            let matching = lock_packages
                .iter()
                .filter(|package| {
                    package.checksum == checksum
                        && path == format!("{}-{}.crate", package.name, package.version)
                })
                .cloned()
                .collect::<Vec<_>>();
            if matching.len() != 1 || !crate_packages.insert(matching[0].clone()) {
                return Err(Diagnostic::error("E_SUPPLY_CRATE_BINDING", subject).at(&path));
            }
        } else {
            if !path.starts_with("index/") || !payload.ends_with(b"\n") {
                return Err(Diagnostic::error("E_SUPPLY_INDEX_PATH", subject).at(&path));
            }
            let mut file_package_name = None::<String>;
            let mut file_versions = BTreeSet::new();
            let mut row_count = 0usize;
            for line in payload.strip_suffix(b"\n").unwrap_or_default().split(|byte| *byte == b'\n') {
                if line.is_empty() {
                    return Err(Diagnostic::error("E_SUPPLY_INDEX_JSON", subject).at(&path));
                }
                let json = parse_strict_json(line, &path)?;
                let object = strict_json_object(&json, &path)?;
                let name = strict_json_string(object, "name", &path)?;
                let version = strict_json_string(object, "vers", &path)?;
                let checksum = strict_json_string(object, "cksum", &path)?;
                validate_sha256(checksum, &path)?;
                if strict_json_bool(object, "yanked", &path)?
                    || crates_io_index_path(name, &path)? != path
                    || !file_package_name
                        .as_ref()
                        .is_none_or(|prior| prior == name)
                    || !file_versions.insert(version.to_owned())
                {
                    return Err(Diagnostic::error("E_SUPPLY_INDEX_BINDING", subject).at(&path));
                }
                file_package_name.get_or_insert_with(|| name.to_owned());
                let triple = RegistryPackageTriple {
                    name: name.to_owned(),
                    version: version.to_owned(),
                    checksum: checksum.to_owned(),
                };
                if !lock_packages.contains(&triple) || !index_packages.insert(triple) {
                    return Err(Diagnostic::error("E_SUPPLY_INDEX_BINDING", subject).at(&path));
                }
                row_count = row_count
                    .checked_add(1)
                    .ok_or_else(|| Diagnostic::error("E_SUPPLY_COUNT", subject))?;
            }
            let package_name = file_package_name
                .ok_or_else(|| Diagnostic::error("E_SUPPLY_INDEX_JSON", subject).at(&path))?;
            if row_count == 0 || !index_file_names.insert(package_name) {
                return Err(Diagnostic::error("E_SUPPLY_INDEX_BINDING", subject).at(&path));
            }
        }
    }
    cursor.finish()?;
    validate_case_unique(paths, "supply bundle paths")?;
    if total_payload_bytes != declared_payload_bytes
        || inner.finalize().as_slice() != declared_inner_sha256
    {
        return Err(Diagnostic::error("E_SUPPLY_INNER_BINDING", subject));
    }
    if crate_packages != lock_packages || index_packages != lock_packages {
        return Err(Diagnostic::error(
            "E_SUPPLY_CLOSURE_BIJECTION",
            subject,
        ));
    }
    Ok(())
}

fn validate_package_artifacts(
    bytes: &[u8],
    policy: &Policy,
    subject: &str,
) -> VResult<[u8; 16]> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > policy.bounds.max_package_artifact_bytes {
        return Err(Diagnostic::error("E_BINARY_BOUND", subject));
    }
    let mut cursor = BinaryCursor::new(bytes, subject);
    if cursor.read_exact(b"FND01PACKAGEv1\0".len())? != b"FND01PACKAGEv1\0" {
        return Err(Diagnostic::error("E_PACKAGE_HEADER", subject));
    }
    let run_id: [u8; 16] = cursor
        .read_exact(16)?
        .try_into()
        .map_err(|_| Diagnostic::error("E_PACKAGE_HEADER", subject))?;
    if run_id.iter().all(|byte| *byte == 0) {
        return Err(Diagnostic::error("E_RUN_ID", subject));
    }
    let member_count = usize::try_from(cursor.read_u32()?)
        .map_err(|_| Diagnostic::error("E_PACKAGE_COUNT", subject))?;
    if member_count != EXPECTED_PACKAGES {
        return Err(Diagnostic::error("E_PACKAGE_COUNT", subject));
    }
    let declared_payload_bytes = cursor.read_u64()?;
    let mut actual_payload_bytes = 0u64;
    for index in 0..member_count {
        let entry_id = cursor.read_string(policy.bounds.max_id_bytes)?;
        let package_id = cursor.read_string(policy.bounds.max_id_bytes)?;
        let basename = cursor.read_string(policy.bounds.max_path_component_bytes)?;
        let expected_package = PACKAGE_IDS[index];
        if entry_id != format!("package.{expected_package}")
            || package_id != expected_package
            || basename != format!("{expected_package}-{PACKAGE_VERSION}.crate")
        {
            return Err(Diagnostic::error("E_PACKAGE_MEMBER", subject).at(entry_id));
        }
        let payload_length_u64 = cursor.read_u64()?;
        let payload_length = checked_payload_length(
            payload_length_u64,
            policy.bounds.max_archive_compressed_bytes,
            subject,
        )?;
        let payload_sha256 = cursor.read_exact(32)?;
        let payload = cursor.read_exact(payload_length)?;
        if sha256(payload).as_slice() != payload_sha256 {
            return Err(Diagnostic::error("E_PACKAGE_HASH", subject).at(&package_id));
        }
        actual_payload_bytes = actual_payload_bytes
            .checked_add(payload_length_u64)
            .ok_or_else(|| Diagnostic::error("E_PACKAGE_BOUND", subject))?;
        validate_gzip_tar(
            payload,
            &policy.bounds.archive_bounds(),
            &basename,
            Some(&format!("{expected_package}-{PACKAGE_VERSION}")),
        )?;
    }
    cursor.finish()?;
    if actual_payload_bytes != declared_payload_bytes {
        return Err(Diagnostic::error("E_PACKAGE_PAYLOAD_TOTAL", subject));
    }
    Ok(run_id)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommandStreamSummary {
    run_id: [u8; 16],
    control: CommandStreamBinding,
    command_ids: Vec<String>,
    command_bindings: Vec<CommandStreamBinding>,
    lock_bindings: Vec<LockStreamBinding>,
    package_union_sha256: String,
}

fn policy_unmodeled_table<'a>(
    policy: &'a Policy,
    name: &str,
) -> VResult<&'a toml::map::Map<String, toml::Value>> {
    policy
        ._validated_unmodeled
        .get(name)
        .and_then(toml::Value::as_table)
        .ok_or_else(|| Diagnostic::error("E_POLICY_TYPED_EXTRACTION", name))
}

fn policy_string_array(
    policy: &Policy,
    table_name: &str,
    field: &str,
) -> VResult<Vec<String>> {
    record_array(
        policy_unmodeled_table(policy, table_name)?,
        field,
        table_name,
    )?
    .iter()
    .map(|value| {
        value
            .as_str()
            .map(ToOwned::to_owned)
            .ok_or_else(|| Diagnostic::error("E_POLICY_TYPED_EXTRACTION", table_name).at(field))
    })
        .collect()
}

fn policy_string_matrix(
    policy: &Policy,
    table_name: &str,
    field: &str,
) -> VResult<Vec<Vec<String>>> {
    record_array(
        policy_unmodeled_table(policy, table_name)?,
        field,
        table_name,
    )?
    .iter()
    .map(|row| {
        row.as_array()
            .ok_or_else(|| Diagnostic::error("E_POLICY_TYPED_EXTRACTION", table_name).at(field))?
            .iter()
            .map(|value| {
                value.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                    Diagnostic::error("E_POLICY_TYPED_EXTRACTION", table_name).at(field)
                })
            })
            .collect()
    })
    .collect()
}

fn command_template_set_sha256(policy: &Policy) -> VResult<String> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"FND01COMMANDTEMPLATEv1\0");
    append_registry_count(
        &mut encoded,
        policy.command_template.len(),
        "command template set",
    )?;
    for template in &policy.command_template {
        for value in [&template.template_id, &template.group] {
            append_registry_row(&mut encoded, value, "command template set")?;
        }
        encoded.extend_from_slice(
            &u64::try_from(template.expansion_count)
                .map_err(|_| Diagnostic::error("E_COMMAND_TEMPLATE", &template.template_id))?
                .to_be_bytes(),
        );
        for value in [
            &template.id_formula,
            &template.coordinate_domain,
            &template.executor,
            &template.argv_source,
        ] {
            append_registry_row(&mut encoded, value, "command template set")?;
        }
        append_registry_count(
            &mut encoded,
            template.argv_template.len(),
            "command template argv",
        )?;
        for argument in &template.argv_template {
            append_registry_row(&mut encoded, argument, "command template argv")?;
        }
        for value in [
            &template.environment_profile,
            &template.working_directory,
            &template.target_scope,
            &template.execution_mode,
            &template.profile,
            &template.resolver,
            &template.network_mode,
            &template.exit_expectation,
        ] {
            append_registry_row(&mut encoded, value, "command template set")?;
        }
        encoded.extend_from_slice(&template.stdout_limit.to_be_bytes());
        encoded.extend_from_slice(&template.stderr_limit.to_be_bytes());
        for value in [&template.typed_parser, &template.claim_ceiling] {
            append_registry_row(&mut encoded, value, "command template set")?;
        }
    }
    Ok(lower_hex(&sha256(&encoded)))
}

fn validate_command_environment_profiles(policy: &Policy) -> VResult<()> {
    let expected_ids =
        policy_string_array(policy, "command_environment_profiles", "profile_ids")?;
    if policy.environment_profile.len() != expected_ids.len()
        || policy
            .environment_profile
            .iter()
            .map(|profile| profile.id.as_str())
            .ne(expected_ids.iter().map(String::as_str))
    {
        return Err(Diagnostic::error(
            "E_COMMAND_ENVIRONMENT",
            "environment profile registry",
        ));
    }
    for profile in &policy.environment_profile {
        let mut keys = BTreeSet::new();
        if profile.required.is_empty() {
            return Err(Diagnostic::error("E_COMMAND_ENVIRONMENT", &profile.id)
                .at("empty required profile"));
        }
        for pair in &profile.required {
            if pair.len() != 2
                || pair[0].is_empty()
                || pair[0].len() > policy.bounds.max_environment_key_bytes
                || pair[1].len() > policy.bounds.max_environment_value_bytes
                || pair[0].as_bytes().contains(&0)
                || pair[1].as_bytes().contains(&0)
                || !keys.insert(pair[0].as_str())
            {
                return Err(Diagnostic::error("E_COMMAND_ENVIRONMENT", &profile.id)
                    .at("invalid required assignment"));
            }
        }
        for key in &profile.optional {
            if key.is_empty()
                || key.len() > policy.bounds.max_environment_key_bytes
                || key.as_bytes().contains(&0)
                || !keys.insert(key)
            {
                return Err(Diagnostic::error("E_COMMAND_ENVIRONMENT", &profile.id)
                    .at("invalid optional key"));
            }
        }
        if keys.len() > policy.bounds.max_environment_items {
            return Err(Diagnostic::error("E_COMMAND_ENVIRONMENT", &profile.id)
                .at("profile item bound"));
        }
    }
    Ok(())
}

fn validate_target_tool_profiles(policy: &Policy) -> VResult<()> {
    let targets = policy_string_array(policy, "command_matrix_contract", "target_order")?;
    let rust_targets = policy_string_array(policy, "rust_target_contract", "exact_targets")?;
    if policy.target_tool_profile.len() != targets.len()
        || targets != rust_targets
        || policy
            .target_tool_profile
            .iter()
            .map(|profile| profile.target.as_str())
            .ne(targets.iter().map(String::as_str))
    {
        return Err(Diagnostic::error(
            "E_COMMAND_ENVIRONMENT",
            "target tool profile registry",
        ));
    }
    for profile in &policy.target_tool_profile {
        let required_text = [
            &profile.cc_tool_id,
            &profile.ar_tool_id,
            &profile.linker_tool_id,
            &profile.cc_env_key,
            &profile.ar_env_key,
            &profile.cflags_env_key,
            &profile.linker_env_key,
            &profile.rustflags_env_key,
            &profile.cflags_exact,
            &profile.rustflags_exact,
            &profile.linker_flavor,
            &profile.input_root_id,
            &profile.sdk_binding,
            &profile.rustlib_binding,
        ];
        if required_text
            .iter()
            .any(|value| value.is_empty() || value.as_bytes().contains(&0))
            || !profile.linker_args_exact.is_empty()
        {
            return Err(Diagnostic::error("E_COMMAND_ENVIRONMENT", &profile.target)
                .at("target tool profile"));
        }
    }
    Ok(())
}

fn validate_command_template_registry(policy: &Policy) -> VResult<()> {
    let command_matrix = policy_unmodeled_table(policy, "command_matrix_contract")?;
    let template_contract = policy_unmodeled_table(policy, "command_template_contract")?;
    let environment_contract =
        policy_unmodeled_table(policy, "command_environment_profiles")?;
    let expected_template_fields = [
        "template_id",
        "group",
        "expansion_count",
        "id_formula",
        "coordinate_domain",
        "executor",
        "argv_source",
        "argv_template",
        "environment_profile",
        "working_directory",
        "target_scope",
        "execution_mode",
        "profile",
        "resolver",
        "network_mode",
        "exit_expectation",
        "stdout_limit",
        "stderr_limit",
        "typed_parser",
        "claim_ceiling",
    ];
    let expected_argv_sources = [
        "literal",
        "literal",
        "command_expansion_registry.tool_argv",
        "literal",
        "literal",
        "literal",
        "literal",
        "literal",
        "literal",
        "literal",
        "command_expansion_registry.workspace_default_graph_argv",
        "literal",
        "command_expansion_registry.workspace_gate_argv",
        "literal",
        "literal",
        "command_expansion_registry.package_argv",
        "command_expansion_registry.consumer_argv",
    ];
    if policy.command_template.len() != COMMAND_TEMPLATE_IDS.len()
        || record_usize(template_contract, "row_count", "command_template_contract")?
            != COMMAND_TEMPLATE_IDS.len()
        || policy_string_array(
            policy,
            "command_template_contract",
            "row_exact_fields",
        )?
        .iter()
        .map(String::as_str)
        .ne(expected_template_fields)
        || record_usize(
            environment_contract,
            "profile_count",
            "command_environment_profiles",
        )? != policy.environment_profile.len()
        || record_usize(command_matrix, "exact_template_count", "command_matrix_contract")?
            != COMMAND_TEMPLATE_IDS.len()
        || COMMAND_TEMPLATE_EXPANSION_COUNTS.iter().sum::<usize>()
            != record_usize(
                command_matrix,
                "exact_command_count",
                "command_matrix_contract",
            )?
    {
        return Err(Diagnostic::error(
            "E_COMMAND_TEMPLATE",
            "command template registry",
        ));
    }
    let family_order =
        policy_string_array(policy, "command_matrix_contract", "family_order")?;
    let family_values = policy
        ._validated_unmodeled
        .get("command_family")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| Diagnostic::error("E_COMMAND_FAMILY", "command_family"))?;
    if family_order
        .iter()
        .map(String::as_str)
        .ne(COMMAND_FAMILY_IDS)
        || family_values.len() != COMMAND_FAMILY_IDS.len()
        || record_usize(
            command_matrix,
            "exact_command_group_count",
            "command_matrix_contract",
        )? != COMMAND_FAMILY_IDS.len()
        || record_usize(
            command_matrix,
            "exact_cargo_command_count",
            "command_matrix_contract",
        )? != 198
        || record_usize(
            command_matrix,
            "exact_non_cargo_command_count",
            "command_matrix_contract",
        )? != 8
    {
        return Err(Diagnostic::error(
            "E_COMMAND_FAMILY",
            "command family registry",
        ));
    }
    let mut expansion_by_group = BTreeMap::<&str, usize>::new();
    for template in &policy.command_template {
        let count = expansion_by_group
            .entry(template.group.as_str())
            .or_default();
        *count = count
            .checked_add(template.expansion_count)
            .ok_or_else(|| Diagnostic::error("E_COMMAND_FAMILY", &template.group))?;
    }
    for (index, value) in family_values.iter().enumerate() {
        let logical = format!("command_family[{index}]");
        let table = value
            .as_table()
            .ok_or_else(|| Diagnostic::error("E_COMMAND_FAMILY", &logical))?;
        let id = record_string(table, "id", &logical)?;
        if id != COMMAND_FAMILY_IDS[index]
            || record_usize(table, "command_count", &logical)?
                != COMMAND_FAMILY_COUNTS[index]
            || expansion_by_group.get(id).copied() != Some(COMMAND_FAMILY_COUNTS[index])
            || record_string(table, "scope", &logical)?.is_empty()
        {
            return Err(Diagnostic::error("E_COMMAND_FAMILY", &logical));
        }
    }
    for (index, template) in policy.command_template.iter().enumerate() {
        let literal_argv = expected_argv_sources[index] == "literal";
        if template.template_id != COMMAND_TEMPLATE_IDS[index]
            || template.group != COMMAND_TEMPLATE_GROUPS[index]
            || template.expansion_count != COMMAND_TEMPLATE_EXPANSION_COUNTS[index]
            || template.argv_source != expected_argv_sources[index]
            || template.argv_template.is_empty() == literal_argv
            || template.executor != "same-outer-job-child"
            || template.exit_expectation != "zero"
            || template.id_formula.is_empty()
            || template.coordinate_domain.is_empty()
            || template.environment_profile.is_empty()
            || template.working_directory.is_empty()
            || template.target_scope.is_empty()
            || template.execution_mode.is_empty()
            || template.profile.is_empty()
            || template.resolver.is_empty()
            || template.network_mode.is_empty()
            || template.typed_parser.is_empty()
            || template.claim_ceiling.is_empty()
            || template.stdout_limit == 0
            || template.stdout_limit > policy.bounds.max_raw_stdout_bytes
            || template.stderr_limit == 0
            || template.stderr_limit > policy.bounds.max_raw_stderr_bytes
            || template.argv_template.len() > policy.bounds.max_argv_items
            || template.argv_template.iter().any(|argument| {
                argument.is_empty()
                    || argument.len() > policy.bounds.max_argument_bytes
                    || argument.as_bytes().contains(&0)
            })
        {
            return Err(Diagnostic::error("E_COMMAND_TEMPLATE", &template.template_id));
        }
    }
    validate_command_environment_profiles(policy)?;
    validate_target_tool_profiles(policy)?;

    for (field, expected) in [
        ("tool_argv", 6usize),
        ("workspace_default_graph_argv", 5),
        ("workspace_gate_argv", 6),
        ("package_argv", 2),
        ("consumer_argv", 4),
    ] {
        let matrix = policy_string_matrix(policy, "command_expansion_registry", field)?;
        if matrix.len() != expected
            || matrix.iter().any(|argv| {
                argv.is_empty()
                    || argv.len() > policy.bounds.max_argv_items
                    || argv.iter().any(|argument| {
                        argument.is_empty()
                            || argument.len() > policy.bounds.max_argument_bytes
                            || argument.as_bytes().contains(&0)
                    })
            })
        {
            return Err(
                Diagnostic::error("E_COMMAND_TEMPLATE", "command_expansion_registry").at(field)
            );
        }
    }
    for field in [
        "workspace_gate_environment_profiles",
        "workspace_gate_profiles",
        "workspace_gate_resolvers",
        "workspace_gate_network_modes",
    ] {
        if policy_string_array(policy, "command_expansion_registry", field)?.len() != 6 {
            return Err(
                Diagnostic::error("E_COMMAND_TEMPLATE", "command_expansion_registry").at(field)
            );
        }
    }
    for field in ["consumer_profiles", "consumer_typed_parsers"] {
        if policy_string_array(policy, "command_expansion_registry", field)?.len() != 4 {
            return Err(
                Diagnostic::error("E_COMMAND_TEMPLATE", "command_expansion_registry").at(field)
            );
        }
    }
    let mut cargo_count = 0usize;
    let mut non_cargo_count = 0usize;
    for template in &policy.command_template {
        for local_ordinal in 0..template.expansion_count {
            let argv = expected_argv_template(policy, template, local_ordinal)?;
            let count = if argv.first().map(String::as_str) == Some("{tool.cargo.path}") {
                &mut cargo_count
            } else {
                &mut non_cargo_count
            };
            *count = count
                .checked_add(1)
                .ok_or_else(|| Diagnostic::error("E_COMMAND_COUNT", &template.template_id))?;
        }
    }
    if cargo_count
        != record_usize(
            command_matrix,
            "exact_cargo_command_count",
            "command_matrix_contract",
        )?
        || non_cargo_count
            != record_usize(
                command_matrix,
                "exact_non_cargo_command_count",
                "command_matrix_contract",
            )?
    {
        return Err(Diagnostic::error(
            "E_COMMAND_COUNT",
            "Cargo/non-Cargo expansion partition",
        ));
    }
    Ok(())
}

fn expected_command_ids(policy: &Policy) -> VResult<Vec<String>> {
    validate_command_template_registry(policy)?;
    let command_matrix = policy_unmodeled_table(policy, "command_matrix_contract")?;
    let expansion = policy_unmodeled_table(policy, "command_expansion_registry")?;
    let projections = &policy.output_namespace.projections;
    let targets = policy_string_array(policy, "command_matrix_contract", "target_order")?;
    let ring_free =
        policy_string_array(policy, "command_matrix_contract", "ring_free_projection_ids")?;
    let ring_bearing =
        policy_string_array(policy, "command_matrix_contract", "ring_bearing_projection_ids")?;
    let tools =
        policy_string_array(policy, "command_expansion_registry", "tool_ids")?;
    let symbol_projections =
        policy_string_array(policy, "command_expansion_registry", "symbol_projection_ids")?;
    let workspace_gates =
        policy_string_array(policy, "command_expansion_registry", "workspace_gate_ids")?;
    let openssl_vectors =
        policy_string_array(policy, "command_expansion_registry", "openssl_vector_ids")?;
    let package_list_packages =
        policy_string_array(policy, "source_inventory_contract", "package_list_command_order")?;
    let package_runs =
        policy_string_array(policy, "command_expansion_registry", "package_run_labels")?;
    let consumer_commands =
        policy_string_array(policy, "command_expansion_registry", "consumer_command_ids")?;

    if record_usize(command_matrix, "exact_template_count", "command_matrix_contract")? != 17
        || projections.len() != 13
        || targets.len() != 5
        || ring_free.len() != 9
        || ring_bearing.len() != 4
        || tools.len() != 6
        || symbol_projections.len() != 8
        || workspace_gates.len() != 6
        || openssl_vectors.len() != 2
        || package_list_packages.len() != 9
        || package_runs.len() != 2
        || consumer_commands.len() != 4
        || ring_free
            .iter()
            .chain(&ring_bearing)
            .collect::<BTreeSet<_>>()
            != projections.iter().collect::<BTreeSet<_>>()
    {
        return Err(Diagnostic::error(
            "E_COMMAND_MATRIX",
            "compiled command coordinate domains",
        ));
    }

    let expected_count =
        record_usize(command_matrix, "exact_command_count", "command_matrix_contract")?;
    let mut ids = Vec::with_capacity(expected_count);
    ids.extend(["bootstrap.resolve".to_owned(), "bootstrap.fetch".to_owned()]);
    ids.extend(tools.iter().map(|id| format!("tool.{id}")));
    ids.extend(
        projections
            .iter()
            .map(|id| format!("projection.resolve.r3.{id}")),
    );
    ids.extend(
        projections
            .iter()
            .map(|id| format!("projection.resolve.r2.{id}")),
    );
    for projection in projections {
        ids.extend(
            targets
                .iter()
                .map(|target| format!("projection.graph.r3.{projection}.{target}")),
        );
    }
    for projection in &ring_free {
        ids.extend(
            targets
                .iter()
                .map(|target| format!("projection.compile.r3.{projection}.{target}")),
        );
    }
    for projection in &ring_bearing {
        ids.extend(
            targets
                .iter()
                .map(|target| format!("projection.compile.r3.{projection}.{target}")),
        );
    }
    ids.extend(
        symbol_projections
            .iter()
            .map(|id| format!("projection.symbol-build.{id}")),
    );
    ids.push("projection.symbol-scan".to_owned());
    ids.extend(
        targets
            .iter()
            .map(|target| format!("workspace.graph.default.{target}")),
    );
    ids.extend(
        targets
            .iter()
            .map(|target| format!("workspace.graph.all.{target}")),
    );
    ids.extend(
        workspace_gates
            .iter()
            .map(|id| format!("workspace.{id}")),
    );
    ids.extend(
        openssl_vectors
            .iter()
            .map(|id| format!("kat.openssl.{id}")),
    );
    ids.extend(
        package_list_packages
            .iter()
            .map(|id| format!("package.list.{id}")),
    );
    ids.extend(package_runs.iter().map(|id| format!("package.{id}")));
    ids.extend(
        consumer_commands
            .iter()
            .map(|id| format!("consumer.{id}")),
    );
    if ids.len() != expected_count {
        return Err(Diagnostic::error("E_COMMAND_COUNT", "command matrix")
            .at(ids.len().to_string()));
    }
    validate_case_unique(ids.iter().cloned(), "compiled command IDs")?;
    if expansion.is_empty() {
        return Err(Diagnostic::error(
            "E_COMMAND_MATRIX",
            "command_expansion_registry",
        ));
    }
    Ok(ids)
}

fn command_template_for_ordinal(
    policy: &Policy,
    ordinal: usize,
) -> VResult<(&CommandTemplateContract, usize)> {
    let mut start = 0usize;
    for template in &policy.command_template {
        let end = start
            .checked_add(template.expansion_count)
            .ok_or_else(|| Diagnostic::error("E_COMMAND_TEMPLATE", &template.template_id))?;
        if ordinal < end {
            return Ok((template, ordinal - start));
        }
        start = end;
    }
    Err(Diagnostic::error("E_COMMAND_ORDER", "command result ordinal")
        .at(ordinal.to_string()))
}

fn expected_argv_template(
    policy: &Policy,
    template: &CommandTemplateContract,
    local_ordinal: usize,
) -> VResult<Vec<String>> {
    if template.argv_source == "literal" {
        return Ok(template.argv_template.clone());
    }
    let field = match template.argv_source.as_str() {
        "command_expansion_registry.tool_argv" => "tool_argv",
        "command_expansion_registry.workspace_default_graph_argv" => {
            "workspace_default_graph_argv"
        }
        "command_expansion_registry.workspace_gate_argv" => "workspace_gate_argv",
        "command_expansion_registry.package_argv" => "package_argv",
        "command_expansion_registry.consumer_argv" => "consumer_argv",
        _ => {
            return Err(Diagnostic::error("E_COMMAND_TEMPLATE", &template.template_id)
                .at(&template.argv_source));
        }
    };
    policy_string_matrix(policy, "command_expansion_registry", field)?
        .get(local_ordinal)
        .cloned()
        .ok_or_else(|| {
            Diagnostic::error("E_COMMAND_EXPANSION", &template.template_id)
                .at(local_ordinal.to_string())
        })
}

fn expected_command_target(
    policy: &Policy,
    template: &CommandTemplateContract,
    local_ordinal: usize,
) -> VResult<Option<String>> {
    let target_index = match template.template_id.as_str() {
        "projection.graph.r3"
        | "projection.compile.r3.ring-free"
        | "projection.compile.r3.ring-bearing" => {
            Some(local_ordinal % EXPECTED_TARGETS)
        }
        "workspace.graph.default" | "workspace.graph.all" => Some(local_ordinal),
        _ => None,
    };
    target_index
        .map(|index| {
            policy_string_array(policy, "command_matrix_contract", "target_order")?
                .get(index)
                .cloned()
                .ok_or_else(|| {
                    Diagnostic::error("E_COMMAND_EXPANSION", &template.template_id)
                        .at(index.to_string())
                })
        })
        .transpose()
}

fn template_value_matches(actual: &str, template: &str, target: Option<&str>) -> bool {
    if actual.is_empty()
        || actual.as_bytes().contains(&0)
        || actual.contains('{')
        || actual.contains('}')
    {
        return false;
    }
    let Some(open) = template.find('{') else {
        return actual == template;
    };
    let Some(relative_close) = template[open + 1..].find('}') else {
        return false;
    };
    let close = open + 1 + relative_close;
    if template[close + 1..].contains('{') || template[..open].contains('}') {
        return false;
    }
    let placeholder = &template[open + 1..close];
    if placeholder.is_empty() {
        return false;
    }
    if placeholder == "target" {
        return target.is_some_and(|target| {
            actual
                == format!(
                    "{}{target}{}",
                    &template[..open],
                    &template[close + 1..]
                )
        });
    }
    let prefix = &template[..open];
    let suffix = &template[close + 1..];
    actual.starts_with(prefix)
        && actual.ends_with(suffix)
        && actual
            .len()
            .checked_sub(prefix.len())
            .and_then(|length| length.checked_sub(suffix.len()))
            .is_some_and(|dynamic_length| dynamic_length != 0)
}

fn target_tool_profile_for<'a>(
    policy: &'a Policy,
    target: &str,
    subject: &str,
) -> VResult<&'a TargetToolProfileContract> {
    let mut matching = policy
        .target_tool_profile
        .iter()
        .filter(|profile| profile.target == target);
    let profile = matching
        .next()
        .ok_or_else(|| Diagnostic::error("E_COMMAND_ENVIRONMENT", subject).at(target))?;
    if matching.next().is_some() {
        return Err(Diagnostic::error("E_COMMAND_ENVIRONMENT", subject)
            .at(format!("duplicate target profile {target}")));
    }
    Ok(profile)
}

fn target_environment_key(
    template: &str,
    profile: Option<&TargetToolProfileContract>,
) -> VResult<String> {
    let Some(profile) = profile else {
        if template.contains('{') || template.contains('}') {
            return Err(Diagnostic::error("E_COMMAND_ENVIRONMENT", template));
        }
        return Ok(template.to_owned());
    };
    let resolved = match template {
        "{target-tool-profile.ar-env-key}" => &profile.ar_env_key,
        "{target-tool-profile.cc-env-key}" => &profile.cc_env_key,
        "{target-tool-profile.cflags-env-key}" => &profile.cflags_env_key,
        "{target-tool-profile.linker-env-key}" => &profile.linker_env_key,
        "{target-tool-profile.rustflags-env-key}" => &profile.rustflags_env_key,
        _ if !template.contains('{') && !template.contains('}') => template,
        _ => {
            return Err(Diagnostic::error("E_COMMAND_ENVIRONMENT", &profile.target)
                .at(template));
        }
    };
    Ok(resolved.to_owned())
}

fn target_environment_value_template(
    template: &str,
    profile: Option<&TargetToolProfileContract>,
) -> String {
    match (template, profile) {
        ("{target-tool-profile.cflags-exact}", Some(profile)) => {
            profile.cflags_exact.clone()
        }
        ("{target-tool-profile.rustflags-exact}", Some(profile)) => {
            profile.rustflags_exact.clone()
        }
        _ => template.to_owned(),
    }
}

fn expected_environment_profile_id(
    policy: &Policy,
    template: &CommandTemplateContract,
    local_ordinal: usize,
) -> VResult<String> {
    if template.environment_profile
        == "command_expansion_registry.workspace_gate_environment_profiles"
    {
        return policy_string_array(
            policy,
            "command_expansion_registry",
            "workspace_gate_environment_profiles",
        )?
        .get(local_ordinal)
        .cloned()
        .ok_or_else(|| Diagnostic::error("E_COMMAND_ENVIRONMENT", &template.template_id));
    }
    Ok(template.environment_profile.clone())
}

fn validate_command_environment(
    actual: &[(String, String)],
    profile_id: &str,
    target: Option<&str>,
    policy: &Policy,
    subject: &str,
) -> VResult<()> {
    let mut matching = policy
        .environment_profile
        .iter()
        .filter(|profile| profile.id == profile_id);
    let profile = matching
        .next()
        .ok_or_else(|| Diagnostic::error("E_COMMAND_ENVIRONMENT", subject).at(profile_id))?;
    if matching.next().is_some() {
        return Err(Diagnostic::error("E_COMMAND_ENVIRONMENT", subject)
            .at(format!("duplicate profile {profile_id}")));
    }
    let target_profile = target
        .map(|target| target_tool_profile_for(policy, target, subject))
        .transpose()?;
    if actual.len() < profile.required.len()
        || actual.len() > profile.required.len() + profile.optional.len()
        || actual.len() > policy.bounds.max_environment_items
        || actual.iter().any(|(key, value)| {
            key.is_empty()
                || key.len() > policy.bounds.max_environment_key_bytes
                || value.len() > policy.bounds.max_environment_value_bytes
                || key.as_bytes().contains(&0)
                || value.as_bytes().contains(&0)
        })
    {
        return Err(Diagnostic::error("E_COMMAND_ENVIRONMENT", subject)
            .at("assignment cardinality"));
    }
    for ((actual_key, actual_value), expected) in
        actual.iter().zip(&profile.required)
    {
        let expected_key = target_environment_key(&expected[0], target_profile)?;
        let expected_value =
            target_environment_value_template(&expected[1], target_profile);
        if actual_key != &expected_key
            || !template_value_matches(actual_value, &expected_value, target)
        {
            return Err(Diagnostic::error("E_COMMAND_ENVIRONMENT", subject)
                .at(actual_key));
        }
    }
    let mut optional_index = 0usize;
    for (actual_key, _) in &actual[profile.required.len()..] {
        let Some(relative) = profile.optional[optional_index..]
            .iter()
            .position(|candidate| candidate == actual_key)
        else {
            return Err(Diagnostic::error("E_COMMAND_ENVIRONMENT", subject)
                .at(actual_key));
        };
        optional_index = optional_index
            .checked_add(relative + 1)
            .ok_or_else(|| Diagnostic::error("E_COMMAND_ENVIRONMENT", subject))?;
    }
    Ok(())
}

fn expected_command_profile(
    policy: &Policy,
    template: &CommandTemplateContract,
    local_ordinal: usize,
) -> VResult<String> {
    if template.profile == "command_expansion_registry.workspace_gate_profiles" {
        return policy_string_array(
            policy,
            "command_expansion_registry",
            "workspace_gate_profiles",
        )?
        .get(local_ordinal)
        .cloned()
        .ok_or_else(|| Diagnostic::error("E_COMMAND_SEMANTIC", &template.template_id));
    }
    if template.profile == "command_expansion_registry.consumer_profiles" {
        return policy_string_array(
            policy,
            "command_expansion_registry",
            "consumer_profiles",
        )?
        .get(local_ordinal)
        .cloned()
        .ok_or_else(|| Diagnostic::error("E_COMMAND_SEMANTIC", &template.template_id));
    }
    Ok(template.profile.clone())
}

fn expected_command_typed_parser(
    policy: &Policy,
    template: &CommandTemplateContract,
    local_ordinal: usize,
) -> VResult<String> {
    if template.typed_parser == "command_expansion_registry.consumer_typed_parsers" {
        return policy_string_array(
            policy,
            "command_expansion_registry",
            "consumer_typed_parsers",
        )?
        .get(local_ordinal)
        .cloned()
        .ok_or_else(|| Diagnostic::error("E_COMMAND_SEMANTIC", &template.template_id));
    }
    Ok(template.typed_parser.clone())
}

fn expected_command_network_mode(
    policy: &Policy,
    template: &CommandTemplateContract,
    local_ordinal: usize,
) -> VResult<String> {
    if template.network_mode
        == "command_expansion_registry.workspace_gate_network_modes"
    {
        return policy_string_array(
            policy,
            "command_expansion_registry",
            "workspace_gate_network_modes",
        )?
        .get(local_ordinal)
        .cloned()
        .ok_or_else(|| Diagnostic::error("E_COMMAND_SEMANTIC", &template.template_id));
    }
    Ok(template.network_mode.clone())
}

fn expected_command_resolver(
    policy: &Policy,
    template: &CommandTemplateContract,
    local_ordinal: usize,
) -> VResult<String> {
    if template.resolver == "command_expansion_registry.workspace_gate_resolvers" {
        return policy_string_array(
            policy,
            "command_expansion_registry",
            "workspace_gate_resolvers",
        )?
        .get(local_ordinal)
        .cloned()
        .ok_or_else(|| Diagnostic::error("E_COMMAND_SEMANTIC", &template.template_id));
    }
    Ok(template.resolver.clone())
}

fn validate_command_result_row(
    table: &toml::map::Map<String, toml::Value>,
    ordinal: usize,
    expected_id: &str,
    policy: &Policy,
    subject: &str,
) -> VResult<ParsedCommandResult> {
    let (template, local_ordinal) = command_template_for_ordinal(policy, ordinal)?;
    let target = expected_command_target(policy, template, local_ordinal)?;
    let argv_template = expected_argv_template(policy, template, local_ordinal)?;
    let argv = record_string_array(table, "argv", subject)?;
    if argv.len() != argv_template.len()
        || argv.len() > policy.bounds.max_argv_items
        || argv.iter().any(|argument| {
            argument.len() > policy.bounds.max_argument_bytes
                || argument.as_bytes().contains(&0)
        })
        || argv
            .iter()
            .zip(&argv_template)
            .any(|(actual, expected)| {
                !template_value_matches(actual, expected, target.as_deref())
            })
    {
        return Err(Diagnostic::error("E_COMMAND_ARGV", subject));
    }
    let environment = record_environment_pairs(table, "environment", subject)?;
    let environment_profile =
        expected_environment_profile_id(policy, template, local_ordinal)?;
    validate_command_environment(
        &environment,
        &environment_profile,
        target.as_deref(),
        policy,
        subject,
    )?;
    let expected_profile = expected_command_profile(policy, template, local_ordinal)?;
    let expected_resolver = expected_command_resolver(policy, template, local_ordinal)?;
    let expected_network =
        expected_command_network_mode(policy, template, local_ordinal)?;
    let expected_typed_parser =
        expected_command_typed_parser(policy, template, local_ordinal)?;
    let expected_ordinal = u64::try_from(ordinal)
        .map_err(|_| Diagnostic::error("E_COMMAND_ORDER", subject))?;
    if record_string(table, "id", subject)? != expected_id
        || record_string(table, "template_id", subject)? != template.template_id
        || record_string(table, "family", subject)? != template.group
        || record_u64(table, "ordinal", subject)? != expected_ordinal
        || record_string(table, "executor", subject)? != template.executor
        || !template_value_matches(
            record_string(table, "working_directory", subject)?,
            &template.working_directory,
            target.as_deref(),
        )
        || !template_value_matches(
            record_string(table, "target_scope", subject)?,
            &template.target_scope,
            target.as_deref(),
        )
        || record_string(table, "execution_mode", subject)? != template.execution_mode
        || record_string(table, "profile", subject)? != expected_profile
        || record_string(table, "resolver", subject)? != expected_resolver
        || record_string(table, "network_mode", subject)? != expected_network
        || record_string(table, "typed_result_kind", subject)? != expected_typed_parser
        || record_string(table, "evidence_verdict", subject)? != "Pass"
        || record_string(table, "claim_ceiling", subject)? != template.claim_ceiling
        || record_i64(table, "exit_code", subject)? != 0
    {
        return Err(Diagnostic::error("E_COMMAND_SEMANTIC", subject));
    }
    let actual_worker_id = record_string(table, "actual_worker_id", subject)?.to_owned();
    if actual_worker_id.is_empty() {
        return Err(Diagnostic::error("E_COMMAND_WORKER", subject));
    }
    let stdout = stream_region_from_record(table, "stdout", subject)?;
    let stderr = stream_region_from_record(table, "stderr", subject)?;
    if stdout.byte_length > template.stdout_limit
        || stderr.byte_length > template.stderr_limit
    {
        return Err(Diagnostic::error("E_COMMAND_STREAM_BINDING", subject));
    }
    let typed_result_sha256 =
        record_string(table, "typed_result_sha256", subject)?.to_owned();
    validate_sha256(&typed_result_sha256, subject)?;
    Ok(ParsedCommandResult {
        id: expected_id.to_owned(),
        actual_worker_id,
        argv,
        environment,
        working_directory: record_string(table, "working_directory", subject)?.to_owned(),
        target_scope: record_string(table, "target_scope", subject)?.to_owned(),
        stdout,
        stderr,
        typed_result_sha256,
    })
}

fn validate_compile_cells(
    values: &[toml::Value],
    command_results: &[ParsedCommandResult],
    policy: &Policy,
    subject: &str,
) -> VResult<()> {
    let ring_free =
        policy_string_array(policy, "command_matrix_contract", "ring_free_projection_ids")?;
    let ring_bearing =
        policy_string_array(policy, "command_matrix_contract", "ring_bearing_projection_ids")?;
    let targets = policy_string_array(policy, "command_matrix_contract", "target_order")?;
    let expected = ring_free
        .iter()
        .chain(&ring_bearing)
        .flat_map(|projection| {
            targets.iter().map(move |target| {
                (
                    projection.as_str(),
                    target.as_str(),
                    format!("projection.compile.r3.{projection}.{target}"),
                )
            })
        })
        .collect::<Vec<_>>();
    if values.len() != expected.len() {
        return Err(Diagnostic::error("E_COMPILE_CELL_COUNT", subject));
    }
    let command_by_id = command_results
        .iter()
        .map(|command| (command.id.as_str(), command))
        .collect::<BTreeMap<_, _>>();
    for (index, (value, (projection, target, command_id))) in
        values.iter().zip(expected).enumerate()
    {
        let logical = format!("{subject}/compile_cell[{index}]");
        let table = value
            .as_table()
            .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", &logical))?;
        let result_sha256 = record_string(table, "result_sha256", &logical)?;
        validate_sha256(result_sha256, &logical)?;
        let command = command_by_id
            .get(command_id.as_str())
            .ok_or_else(|| Diagnostic::error("E_COMPILE_CELL_COMMAND", &logical))?;
        if record_string(table, "projection_id", &logical)? != projection
            || record_string(table, "target", &logical)? != target
            || record_string(table, "command_id", &logical)? != command_id
            || record_u64(table, "crate_count", &logical)? == 0
            || record_u64(table, "artifact_count", &logical)? == 0
            || record_string(table, "evidence_verdict", &logical)? != "Pass"
            || result_sha256 != command.typed_result_sha256
        {
            return Err(Diagnostic::error("E_COMPILE_CELL", &logical));
        }
        let _diagnostic_count = record_u64(table, "diagnostic_count", &logical)?;
    }
    Ok(())
}

fn decompress_command_stream(
    bytes: &[u8],
    policy: &Policy,
    subject: &str,
) -> VResult<Vec<u8>> {
    let compressed_length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if compressed_length == 0
        || compressed_length > policy.bounds.max_command_stream_bundle_bytes
        || bytes.len() < 18
        || bytes[..3] != [0x1f, 0x8b, 0x08]
        || bytes[3] != 0
        || bytes[4..8] != [0, 0, 0, 0]
        || bytes[8] != 0
        || bytes[9] != 255
    {
        return Err(Diagnostic::error("E_STREAM_GZIP_HEADER", subject));
    }
    let mut decoder = GzDecoder::new(bytes);
    let mut expanded = Vec::new();
    decoder
        .by_ref()
        .take(
            policy
                .bounds
                .max_command_stream_expanded_bytes
                .saturating_add(1),
        )
        .read_to_end(&mut expanded)
        .map_err(|_| Diagnostic::error("E_STREAM_GZIP", subject))?;
    if u64::try_from(expanded.len()).unwrap_or(u64::MAX)
        > policy.bounds.max_command_stream_expanded_bytes
    {
        return Err(Diagnostic::error("E_STREAM_GZIP_BOUND", subject));
    }
    if !decoder.into_inner().is_empty() {
        return Err(Diagnostic::error("E_STREAM_GZIP_TRAILING", subject));
    }
    let trailer_isize = u32::from_le_bytes(
        bytes[bytes.len() - 4..]
            .try_into()
            .map_err(|_| Diagnostic::error("E_STREAM_GZIP", subject))?,
    );
    if u64::from(trailer_isize)
        != (u64::try_from(expanded.len()).unwrap_or(u64::MAX) & u64::from(u32::MAX))
    {
        return Err(Diagnostic::error("E_STREAM_GZIP_ISIZE", subject));
    }
    Ok(expanded)
}

fn read_stream_blob_binding(
    cursor: &mut BinaryCursor<'_>,
    maximum: u64,
    subject: &str,
) -> VResult<StreamRegionBinding> {
    let length = cursor.read_u64()?;
    if length > maximum {
        return Err(Diagnostic::error("E_STREAM_BLOB_BOUND", subject).at(length.to_string()));
    }
    let offset = u64::try_from(cursor.position())
        .map_err(|_| Diagnostic::error("E_STREAM_BLOB_BOUND", subject))?;
    let length_usize = usize::try_from(length)
        .map_err(|_| Diagnostic::error("E_STREAM_BLOB_BOUND", subject))?;
    let bytes = cursor.read_exact(length_usize)?;
    Ok(StreamRegionBinding {
        offset,
        byte_length: length,
        sha256: lower_hex(&sha256(bytes)),
    })
}

fn validate_command_streams(
    bytes: &[u8],
    policy: &Policy,
    subject: &str,
) -> VResult<CommandStreamSummary> {
    let expanded = decompress_command_stream(bytes, policy, subject)?;
    let mut cursor = BinaryCursor::new(&expanded, subject);
    if cursor.read_exact(b"FND01STREAMv2\0".len())? != b"FND01STREAMv2\0" {
        return Err(Diagnostic::error("E_STREAM_HEADER", subject));
    }
    let run_id: [u8; 16] = cursor
        .read_exact(16)?
        .try_into()
        .map_err(|_| Diagnostic::error("E_STREAM_HEADER", subject))?;
    if run_id.iter().all(|byte| *byte == 0) {
        return Err(Diagnostic::error("E_RUN_ID", subject));
    }
    let control_count = usize::try_from(cursor.read_u32()?)
        .map_err(|_| Diagnostic::error("E_STREAM_COUNT", subject))?;
    let command_count = usize::try_from(cursor.read_u32()?)
        .map_err(|_| Diagnostic::error("E_STREAM_COUNT", subject))?;
    let lock_count = usize::try_from(cursor.read_u32()?)
        .map_err(|_| Diagnostic::error("E_STREAM_COUNT", subject))?;
    if control_count != 1 || command_count != 206 || lock_count != 28 {
        return Err(Diagnostic::error("E_STREAM_COUNT", subject));
    }
    let control_id = cursor.read_string(policy.bounds.max_id_bytes)?;
    if control_id != "bootstrap-control.build" {
        return Err(Diagnostic::error("E_STREAM_CONTROL_ID", subject));
    }
    let control_stdout = read_stream_blob_binding(
        &mut cursor,
        policy.bounds.max_raw_stdout_bytes,
        subject,
    )?;
    let control_stderr = read_stream_blob_binding(
        &mut cursor,
        policy.bounds.max_raw_stderr_bytes,
        subject,
    )?;
    let control = CommandStreamBinding {
        id: control_id,
        stdout: control_stdout,
        stderr: control_stderr,
    };

    let mut command_ids = Vec::with_capacity(command_count);
    let mut command_bindings = Vec::with_capacity(command_count);
    for _ in 0..command_count {
        let id = cursor.read_string(policy.bounds.max_id_bytes)?;
        let stdout = read_stream_blob_binding(
            &mut cursor,
            policy.bounds.max_raw_stdout_bytes,
            subject,
        )?;
        let stderr = read_stream_blob_binding(
            &mut cursor,
            policy.bounds.max_raw_stderr_bytes,
            subject,
        )?;
        command_ids.push(id.clone());
        command_bindings.push(CommandStreamBinding {
            id,
            stdout,
            stderr,
        });
    }
    validate_case_unique(command_ids.iter().cloned(), "command stream IDs")?;
    if command_ids != expected_command_ids(policy)? {
        return Err(Diagnostic::error("E_STREAM_COMMAND_ORDER", subject));
    }

    let expected_lock_ids =
        policy_string_array(policy, "lockfile_producer_contract", "lock_ids")?;
    if expected_lock_ids.len() != lock_count {
        return Err(Diagnostic::error("E_STREAM_LOCK_COUNT", subject));
    }
    let mut lock_bindings = Vec::with_capacity(lock_count);
    let mut union_packages = BTreeSet::new();
    for expected_id in &expected_lock_ids {
        let id = cursor.read_string(policy.bounds.max_id_bytes)?;
        if &id != expected_id {
            return Err(Diagnostic::error("E_STREAM_LOCK_ORDER", subject).at(id));
        }
        let length = checked_payload_length(
            cursor.read_u64()?,
            policy.bounds.max_record_blob_bytes,
            subject,
        )?;
        let expected_sha256 = cursor.read_exact(32)?;
        let offset = u64::try_from(cursor.position())
            .map_err(|_| Diagnostic::error("E_STREAM_LOCK_BOUND", subject))?;
        let lock_bytes = cursor.read_exact(length)?;
        let actual_digest = sha256(lock_bytes);
        if actual_digest.as_slice() != expected_sha256 {
            return Err(Diagnostic::error("E_STREAM_LOCK_HASH", subject).at(&id));
        }
        let actual_sha256 = lower_hex(&actual_digest);
        let lock: toml::Value = parse_toml_strict(lock_bytes, &id)?;
        let (packages, package_set_sha256) = lock_packages_and_set_sha256(&lock, &id)?;
        union_packages.extend(packages);
        lock_bindings.push(LockStreamBinding {
            id,
            region: StreamRegionBinding {
                offset,
                byte_length: u64::try_from(length)
                    .map_err(|_| Diagnostic::error("E_STREAM_LOCK_BOUND", subject))?,
                sha256: actual_sha256,
            },
            package_set_sha256,
        });
    }
    cursor.finish()?;
    let package_union_sha256 = registry_package_set_sha256(&union_packages, subject)?;
    Ok(CommandStreamSummary {
        run_id,
        control,
        command_ids,
        command_bindings,
        lock_bindings,
        package_union_sha256,
    })
}

fn output_binding_from_bytes(
    output: &DerivedOutputContract,
    bytes: &[u8],
) -> VResult<ReceiptOutputBinding> {
    Ok(ReceiptOutputBinding {
        id: output.id.clone(),
        path: output.path.clone(),
        kind: output.kind.clone(),
        byte_length: u64::try_from(bytes.len())
            .map_err(|_| Diagnostic::error("E_OUTPUT_BINDING", &output.id))?,
        sha256: lower_hex(&sha256(bytes)),
    })
}

fn validate_parent_bindings_for_output(
    child: &DerivedOutputContract,
    parents: &[ReceiptParentBinding],
    output_by_id: &BTreeMap<&str, &DerivedOutputContract>,
    binding_by_id: &BTreeMap<&str, ReceiptOutputBinding>,
) -> VResult<()> {
    if parents.len() != child.required_parent_ids.len()
        || parents.len() != child.parent_purposes.len()
    {
        return Err(Diagnostic::error("E_RECEIPT_PARENT_COUNT", &child.id));
    }
    for ((actual, parent_id), purpose) in parents
        .iter()
        .zip(&child.required_parent_ids)
        .zip(&child.parent_purposes)
    {
        let parent = output_by_id
            .get(parent_id.as_str())
            .ok_or_else(|| Diagnostic::error("E_RECEIPT_PARENT", &child.id).at(parent_id))?;
        let binding = binding_by_id
            .get(parent_id.as_str())
            .ok_or_else(|| Diagnostic::error("E_RECEIPT_PARENT", &child.id).at(parent_id))?;
        if actual.id != parent.id
            || actual.path != parent.path
            || actual.kind != parent.kind
            || actual.byte_length != binding.byte_length
            || actual.sha256 != binding.sha256
            || actual.purpose != *purpose
        {
            return Err(
                Diagnostic::error("E_RECEIPT_PARENT_BINDING", &child.id).at(parent_id)
            );
        }
    }
    Ok(())
}

fn expected_integration_edges(policy: &Policy) -> Vec<IntegrationEdge> {
    policy
        .derived_output
        .iter()
        .flat_map(|output| {
            output
                .required_parent_ids
                .iter()
                .zip(&output.parent_purposes)
                .map(|(parent_id, purpose)| IntegrationEdge {
                    child_id: output.id.clone(),
                    parent_id: parent_id.clone(),
                    purpose: purpose.clone(),
                })
        })
        .collect()
}

fn validate_integration_index(
    index: &ParsedReceipt,
    policy: &Policy,
    binding_by_id: &BTreeMap<&str, ReceiptOutputBinding>,
) -> VResult<()> {
    let expected_members = policy
        .derived_output
        .iter()
        .filter(|output| output.id != "integration-index")
        .map(|output| {
            binding_by_id
                .get(output.id.as_str())
                .cloned()
                .ok_or_else(|| {
                    Diagnostic::error("E_INTEGRATION_INDEX_MEMBER", &output.id)
                })
        })
        .collect::<VResult<Vec<_>>>()?;
    let expected_edges = expected_integration_edges(policy);
    let expected_ranks = policy
        .derived_output
        .iter()
        .filter(|output| output.id != "integration-index")
        .map(|output| IntegrationRank {
            id: output.id.clone(),
            generation_rank: output.generation_rank,
        })
        .collect::<Vec<_>>();
    if index.integration_members != expected_members
        || index.integration_edges != expected_edges
        || index.integration_ranks != expected_ranks
    {
        return Err(Diagnostic::error(
            "E_INTEGRATION_INDEX_EXACT",
            "integration-index",
        ));
    }
    Ok(())
}

fn validate_final_attestation(
    root: &Path,
    policy: &Policy,
    authoring: &ActualAuthoringBindings,
    binding_by_id: &BTreeMap<&str, ReceiptOutputBinding>,
    run_id: &[u8; 16],
) -> VResult<()> {
    let subject = &policy.paths.final_attestation_path;
    let bytes = read_bounded(
        &resolve_safe(root, subject, "final attestation")?,
        policy.bounds.max_final_attestation_bytes,
        subject,
    )?;
    let raw: toml::Value = parse_toml_strict(&bytes, subject)?;
    validate_record_value_bounds(&raw, &policy.bounds, 0, subject)?;
    let table = raw
        .as_table()
        .ok_or_else(|| Diagnostic::error("E_RECORD_TYPE", subject).at("root"))?;
    exact_table_fields(
        table,
        &policy.final_attestation_contract.exact_fields,
        subject,
    )?;
    validate_direct_fields(
        table,
        &policy.final_attestation_contract.exact_fields,
        &[],
        FINAL_ATTESTATION_TYPE_MASK,
        subject,
    )?;
    validate_count_array_links(table, "final-attestation", subject)?;
    validate_record_root_children(table, "final-attestation", policy)?;
    if record_string(table, "format", subject)? != policy.final_attestation_contract.format
        || record_u32(table, "schema_version", subject)?
            != policy.final_attestation_contract.schema_version
        || record_string(table, "attestation_id", subject)?
            != policy.final_attestation_contract.attestation_id_literal
        || record_string(table, "attester_bead", subject)? != FINAL_ATTESTER
        || record_string(table, "attester_role", subject)?
            != policy.final_attestation_contract.role
        || record_string(table, "authoring_closure_sha256", subject)?
            != authoring.closure_sha256
        || record_string(table, "verdict", subject)? != "Pass"
        || record_bool(table, "support_claim", subject)?
    {
        return Err(Diagnostic::error("E_FINAL_ATTESTATION", subject));
    }
    let attestation_run_id = record_string(table, "run_id", subject)?;
    if &validate_run_id(attestation_run_id, subject)? != run_id {
        return Err(Diagnostic::error("E_RUN_ID_MISMATCH", subject));
    }
    validate_sha256(
        record_string(table, "integration_seal_sha256", subject)?,
        subject,
    )?;
    validate_actual_file_binding(
        record_table(table, "policy", subject)?,
        &authoring.policy,
        subject,
    )?;
    validate_actual_file_binding(
        record_table(table, "verifier", subject)?,
        &authoring.verifier,
        subject,
    )?;
    validate_actual_file_binding(
        record_table(table, "harness", subject)?,
        &authoring.harness,
        subject,
    )?;
    let index_binding = parse_single_output_binding(
        record_table(table, "integration_index", subject)?,
        subject,
    )?;
    if binding_by_id.get("integration-index") != Some(&index_binding) {
        return Err(Diagnostic::error("E_FINAL_INDEX_BINDING", subject));
    }
    let outputs = parse_output_bindings(record_array(table, "output", subject)?, subject)?;
    let expected_outputs = policy
        .derived_output
        .iter()
        .map(|output| {
            binding_by_id
                .get(output.id.as_str())
                .cloned()
                .ok_or_else(|| Diagnostic::error("E_FINAL_OUTPUT", &output.id))
        })
        .collect::<VResult<Vec<_>>>()?;
    if record_usize(table, "output_count", subject)? != EXPECTED_RECEIPTS
        || outputs != expected_outputs
    {
        return Err(Diagnostic::error("E_FINAL_OUTPUT", subject));
    }
    let command_matrix = policy_unmodeled_table(policy, "command_matrix_contract")?;
    if record_usize(table, "producer_command_count", subject)?
        != record_usize(command_matrix, "exact_command_count", "command_matrix_contract")?
        || record_usize(table, "attester_command_count", subject)?
            != record_usize(
                command_matrix,
                "exact_attester_command_count",
                "command_matrix_contract",
            )?
    {
        return Err(Diagnostic::error("E_FINAL_COMMAND_COUNT", subject));
    }
    let excluded = record_array(table, "attester_excluded_command_ids", subject)?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| {
                    Diagnostic::error("E_FINAL_COMMAND_EXCLUSION", subject)
                })
        })
        .collect::<VResult<Vec<_>>>()?;
    if excluded
        != policy_string_array(
            policy,
            "command_matrix_contract",
            "attester_excluded_command_ids",
        )?
    {
        return Err(Diagnostic::error("E_FINAL_COMMAND_EXCLUSION", subject));
    }
    if record_usize(table, "pending_count", subject)? != 0
        || !record_array(table, "pending", subject)?.is_empty()
    {
        return Err(Diagnostic::error("E_FINAL_PENDING", subject));
    }
    for field in [
        "attester_command_set_sha256",
        "producer_streams_sha256",
        "producer_lock_set_sha256",
        "attester_lock_set_sha256",
        "rerun_semantic_set_sha256",
    ] {
        validate_sha256(record_string(table, field, subject)?, subject)?;
    }
    if !record_bool(table, "locks_byte_equal", subject)? {
        return Err(Diagnostic::error("E_FINAL_LOCK_EQUALITY", subject));
    }
    Ok(())
}

fn verify_outputs(
    root: &Path,
    policy: &Policy,
    policy_bytes: &[u8],
    _source_tree: [u8; 32],
    report: &mut Report,
) -> VResult<()> {
    let expected_relative = validate_receipt_matrix(policy)?;
    let integration = resolve_safe(root, &policy.paths.integration_root, "integration root")?;
    let final_attestation = resolve_safe(
        root,
        &policy.paths.final_attestation_path,
        "final attestation",
    )?;
    if !integration.exists() {
        if final_attestation.exists() {
            return Err(Diagnostic::error(
                "E_FINAL_ATTESTATION_PREMATURE",
                &policy.paths.final_attestation_path,
            ));
        }
        report.extend(
            policy
                .pending_contract
                .post_authoring_allowed_pending
                .iter()
                .cloned()
                .map(Diagnostic::pending),
        );
        return Ok(());
    }
    let metadata = fs::symlink_metadata(&integration)
        .map_err(|_| Diagnostic::error("E_RECEIPT_DIRECTORY", "integration"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Diagnostic::error("E_RECEIPT_DIRECTORY", "integration"));
    }

    let mut actual_relative = BTreeSet::new();
    for entry in fs::read_dir(&integration)
        .map_err(|_| Diagnostic::error("E_RECEIPT_DIRECTORY", "integration"))?
    {
        let entry = entry.map_err(|_| Diagnostic::error("E_RECEIPT_DIRECTORY", "integration"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| Diagnostic::error("E_PATH_INVALID", "integration output"))?;
        validate_ascii_posix_path(&name, "integration output")?;
        if name.contains('/') {
            return Err(Diagnostic::error("E_RECEIPT_FLAT", &name));
        }
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|_| Diagnostic::error("E_PATH_METADATA", &name))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(Diagnostic::error("E_RECEIPT_FLAT", &name));
        }
        if !actual_relative.insert(name.clone()) {
            return Err(Diagnostic::error("E_RECEIPT_DUPLICATE", &name));
        }
    }
    if actual_relative != expected_relative {
        let missing = expected_relative
            .difference(&actual_relative)
            .cloned()
            .collect::<Vec<_>>();
        let extra = actual_relative
            .difference(&expected_relative)
            .cloned()
            .collect::<Vec<_>>();
        return Err(Diagnostic::error("E_RECEIPT_EXACT_SET", "integration")
            .at(format!("missing={missing:?};extra={extra:?}")));
    }

    let authoring = load_actual_authoring_bindings(root, policy, policy_bytes)?;
    let output_by_id = policy
        .derived_output
        .iter()
        .map(|output| (output.id.as_str(), output))
        .collect::<BTreeMap<_, _>>();
    let mut bytes_by_id = BTreeMap::<&str, Vec<u8>>::new();
    let mut binding_by_id = BTreeMap::<&str, ReceiptOutputBinding>::new();
    let mut total_bytes = 0u64;
    for output in &policy.derived_output {
        let path = resolve_safe(root, &output.path, &output.id)?;
        let bytes = read_bounded(&path, output.max_bytes, &output.path)?;
        let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if length < output.min_bytes {
            return Err(Diagnostic::error("E_OUTPUT_BOUND", &output.id));
        }
        total_bytes = total_bytes
            .checked_add(length)
            .ok_or_else(|| Diagnostic::error("E_OUTPUT_BOUND", "integration total"))?;
        binding_by_id.insert(output.id.as_str(), output_binding_from_bytes(output, &bytes)?);
        bytes_by_id.insert(output.id.as_str(), bytes);
    }
    if total_bytes > policy.bounds.max_integration_total_bytes {
        return Err(Diagnostic::error("E_OUTPUT_BOUND", "integration total"));
    }

    let mut parsed_by_id = BTreeMap::<&str, ParsedReceipt>::new();
    for output in &policy.derived_output {
        if TOML_OUTPUT_IDS.contains(&output.id.as_str()) {
            let bytes = bytes_by_id
                .get(output.id.as_str())
                .ok_or_else(|| Diagnostic::error("E_OUTPUT_MISSING", &output.id))?;
            parsed_by_id.insert(
                output.id.as_str(),
                parse_receipt_v2(bytes, &output.path, output, policy, &authoring)?,
            );
        }
    }
    validate_supply_bundle(
        bytes_by_id
            .get("supply-bundle")
            .ok_or_else(|| Diagnostic::error("E_OUTPUT_MISSING", "supply-bundle"))?,
        policy,
        "supply-bundle",
    )?;
    let stream_summary = validate_command_streams(
        bytes_by_id
            .get("command-streams")
            .ok_or_else(|| Diagnostic::error("E_OUTPUT_MISSING", "command-streams"))?,
        policy,
        "command-streams",
    )?;
    let package_run_id = validate_package_artifacts(
        bytes_by_id
            .get("package-artifacts")
            .ok_or_else(|| Diagnostic::error("E_OUTPUT_MISSING", "package-artifacts"))?,
        policy,
        "package-artifacts",
    )?;

    let mut run_id = None::<[u8; 16]>;
    for receipt in parsed_by_id.values() {
        let decoded = validate_run_id(&receipt.run_id, &receipt.receipt_id)?;
        if run_id.replace(decoded).is_some_and(|prior| prior != decoded) {
            return Err(Diagnostic::error("E_RUN_ID_MISMATCH", &receipt.receipt_id));
        }
        let output = output_by_id
            .get(receipt.receipt_id.as_str())
            .ok_or_else(|| Diagnostic::error("E_OUTPUT_MISSING", &receipt.receipt_id))?;
        validate_parent_bindings_for_output(
            output,
            &receipt.parents,
            &output_by_id,
            &binding_by_id,
        )?;
    }
    let run_id = run_id.ok_or_else(|| Diagnostic::error("E_RUN_ID", "receipt set"))?;
    if stream_summary.run_id != run_id || package_run_id != run_id {
        return Err(Diagnostic::error("E_RUN_ID_MISMATCH", "binary outputs"));
    }

    for (binary_id, sidecar_id) in [
        ("supply-bundle", "supply-receipt"),
        ("command-streams", "command-results"),
        ("package-artifacts", "package-receipt"),
    ] {
        let sidecar = parsed_by_id
            .get(sidecar_id)
            .ok_or_else(|| Diagnostic::error("E_BINARY_SIDECAR", sidecar_id))?;
        let binding = binding_by_id
            .get(binary_id)
            .ok_or_else(|| Diagnostic::error("E_BINARY_SIDECAR", binary_id))?;
        if sidecar.sidecar_output.as_ref() != Some(binding) {
            return Err(Diagnostic::error("E_BINARY_SIDECAR", sidecar_id).at(binary_id));
        }
        validate_parent_bindings_for_output(
            output_by_id
                .get(binary_id)
                .ok_or_else(|| Diagnostic::error("E_BINARY_SIDECAR", binary_id))?,
            &sidecar.sidecar_parents,
            &output_by_id,
            &binding_by_id,
        )?;
    }
    let command_results = parsed_by_id
        .get("command-results")
        .ok_or_else(|| Diagnostic::error("E_COMMAND_RESULTS", "command-results"))?;
    if command_results.command_ids != stream_summary.command_ids
        || command_results.control_frame.as_ref() != Some(&stream_summary.control)
        || command_results.bootstrap_control.as_ref() != Some(&stream_summary.control)
        || command_results.command_results.len() != stream_summary.command_bindings.len()
        || command_results
            .command_results
            .iter()
            .zip(&stream_summary.command_bindings)
            .any(|(result, stream)| {
                result.id != stream.id
                    || result.stdout != stream.stdout
                    || result.stderr != stream.stderr
            })
        || command_results.postcommand_locks.len() != stream_summary.lock_bindings.len()
        || command_results
            .postcommand_locks
            .iter()
            .zip(&stream_summary.lock_bindings)
            .any(|(result, stream)| {
                result.id != stream.id
                    || result.region != stream.region
                    || result.package_set_sha256 != stream.package_set_sha256
            })
        || command_results.postcommand_package_set_sha256.as_deref()
            != Some(stream_summary.package_union_sha256.as_str())
    {
        return Err(Diagnostic::error(
            "E_COMMAND_STREAM_JOIN",
            "command-results",
        ));
    }
    let mut worker_ids = command_results
        .command_results
        .iter()
        .map(|result| result.actual_worker_id.as_str());
    let actual_worker_id = worker_ids
        .next()
        .ok_or_else(|| Diagnostic::error("E_COMMAND_WORKER", "command-results"))?;
    let producer_worker_id = parsed_by_id
        .get("producer-environment")
        .and_then(|receipt| receipt.actual_worker_id.as_deref())
        .ok_or_else(|| Diagnostic::error("E_COMMAND_WORKER", "producer-environment"))?;
    if actual_worker_id != producer_worker_id
        || worker_ids.any(|worker_id| worker_id != producer_worker_id)
    {
        return Err(Diagnostic::error(
            "E_COMMAND_WORKER",
            "command-results",
        )
        .at("commands do not share one actual worker"));
    }
    validate_integration_index(
        parsed_by_id
            .get("integration-index")
            .ok_or_else(|| Diagnostic::error("E_INTEGRATION_INDEX", "integration-index"))?,
        policy,
        &binding_by_id,
    )?;

    if final_attestation.exists() {
        validate_final_attestation(
            root,
            policy,
            &authoring,
            &binding_by_id,
            &run_id,
        )?;
        report.extend(
            policy
                .pending_contract
                .post_attestation_allowed_pending
                .iter()
                .cloned()
                .map(Diagnostic::pending),
        );
    } else {
        report.extend(
            policy
                .pending_contract
                .post_publication_allowed_pending
                .iter()
                .cloned()
                .map(Diagnostic::pending),
        );
    }
    Ok(())
}

fn parse_source_toml(files: &[LoadedFile], path: &str) -> VResult<toml::Value> {
    let source = source_lookup(files, path)?;
    if source.contract.parse_kind != FileFamily::Toml {
        return Err(Diagnostic::error("E_SOURCE_PARSE_KIND", path).at("TOML required"));
    }
    let text = std::str::from_utf8(&source.bytes)
        .map_err(|_| Diagnostic::error("E_UTF8", path))?;
    text.parse::<toml::Value>()
        .map_err(|_| Diagnostic::error("E_TOML_SYNTAX", path))
}

fn string_array(value: &toml::Value, pointer: &str, subject: &str) -> VResult<Vec<String>> {
    pointer_get(value, pointer, subject)?
        .as_array()
        .ok_or_else(|| Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| Diagnostic::error("E_TOML_SCHEMA", subject).at(pointer))
        })
        .collect()
}

fn array_table_ids(value: &toml::Value, pointer: &str, subject: &str) -> VResult<Vec<String>> {
    pointer_get(value, pointer, subject)?
        .as_array()
        .ok_or_else(|| Diagnostic::error("E_SEMANTIC_POINTER", subject).at(pointer))?
        .iter()
        .map(|row| {
            row.as_table()
                .and_then(|table| table.get("id"))
                .and_then(toml::Value::as_str)
                .map(ToOwned::to_owned)
                .ok_or_else(|| Diagnostic::error("E_TOML_SCHEMA", subject).at(pointer))
        })
        .collect()
}

fn validate_supplemental_contracts(files: &[LoadedFile], policy: &Policy) -> VResult<()> {
    let core = parse_source_toml(files, "evidence/fnd-01/core-conformance.toml")?;
    let core_negatives = string_array(
        &core,
        "/required_negative_cases",
        "core-required-negative-cases",
    )?;
    if core_negatives.len() != 20 {
        return Err(Diagnostic::error(
            "E_SUPPLEMENTAL_CORE",
            "required_negative_cases",
        ));
    }
    validate_case_unique(core_negatives, "core required negative cases")?;

    let jose = parse_source_toml(files, "evidence/fnd-01/jose-ring.toml")?;
    let accepted_files = string_array(&jose, "/vectors/vector_files", "jose vectors")?;
    let rejected_files =
        string_array(&jose, "/vectors/rejected_artifact_files", "jose vectors")?;
    if !string_sequence_is(
        &accepted_files,
        &["rfc7515-a2.toml", "rfc7520-rs256.toml"],
    ) || !string_sequence_is(&rejected_files, &["rfc8017-sha256.toml"])
        || pointer_get(&jose, "/vectors/count", "jose vectors")?.as_integer() != Some(2)
        || pointer_get(&jose, "/vectors/private_keys_checked_in", "jose vectors")?
            .as_bool()
            != Some(false)
        || pointer_get(&jose, "/stable_jwt_oidc_support", "jose vectors")?.as_bool()
            != Some(false)
    {
        return Err(Diagnostic::error("E_QUARANTINE_JOSE", "vector roots"));
    }
    let mut accepted_mutations = 0usize;
    let mut accepted_documents = BTreeMap::new();
    for file in &accepted_files {
        let path = format!("evidence/fnd-01/vectors/rs256/{file}");
        let document = parse_source_toml(files, &path)?;
        if pointer_get(&document, "/verification_expectation", file)?.as_str()
            != Some("accept")
        {
            return Err(Diagnostic::error("E_QUARANTINE_JOSE", file));
        }
        let mutations = string_array(&document, "/negative_mutations", file)?;
        let cross = string_array(&document, "/cross_implementation", file)?;
        if mutations.len() != 5 || cross.len() != 2 {
            return Err(Diagnostic::error("E_QUARANTINE_JOSE", file)
                .at("accepted execution contract"));
        }
        accepted_mutations = accepted_mutations
            .checked_add(mutations.len())
            .ok_or_else(|| Diagnostic::error("E_SUPPLEMENTAL_BOUND", file))?;
        accepted_documents.insert(file.clone(), document);
    }
    if accepted_mutations != 10 {
        return Err(Diagnostic::error(
            "E_SUPPLEMENTAL_JOSE",
            "accepted vector mutations",
        ));
    }
    let rejected_path = "evidence/fnd-01/vectors/rs256/rfc8017-sha256.toml";
    let rejected = parse_source_toml(files, rejected_path)?;
    if pointer_get(&rejected, "/accepted_vector", rejected_path)?.as_bool() != Some(false)
        || pointer_get(&rejected, "/duplicate_of", rejected_path)?.as_str()
            != Some("rfc7515-a2.toml")
        || pointer_get(&rejected, "/artifact_role", rejected_path)?.as_str()
            != Some("quarantined-rejected-duplicate")
        || pointer_get(&rejected, "/verification_expectation", rejected_path)?.as_str()
            != Some("not-executed-quarantined")
        || !string_array(&rejected, "/negative_mutations", rejected_path)?.is_empty()
        || !string_array(&rejected, "/cross_implementation", rejected_path)?.is_empty()
    {
        return Err(Diagnostic::error("E_QUARANTINE_JOSE", rejected_path));
    }
    let accepted_duplicate = accepted_documents
        .get("rfc7515-a2.toml")
        .ok_or_else(|| Diagnostic::error("E_QUARANTINE_JOSE", "accepted duplicate root"))?;
    for field in [
        "algorithm",
        "modulus_bits",
        "exponent",
        "modulus_b64u",
        "modulus_bytes",
        "modulus_sha256",
        "exponent_bytes",
        "exponent_sha256",
        "protected_header_b64u",
        "payload_b64u",
        "signing_input",
        "signing_input_bytes",
        "signing_input_sha256",
        "signature_b64u",
        "signature_bytes",
        "signature_sha256",
        "compact_jws_bytes",
        "compact_jws_sha256",
    ] {
        let pointer = format!("/{field}");
        if pointer_get(&rejected, &pointer, rejected_path)?
            != pointer_get(accepted_duplicate, &pointer, "rfc7515-a2.toml")?
        {
            return Err(Diagnostic::error("E_QUARANTINE_JOSE_DUPLICATE", field));
        }
    }

    let tasks = parse_source_toml(files, "evidence/fnd-01/tasks-apps.toml")?;
    let task_quarantine =
        array_table_ids(&tasks, "/tasks/quarantine", "tasks quarantine")?;
    let app_quarantine = array_table_ids(&tasks, "/apps/quarantine", "apps quarantine")?;
    let expected_task_quarantine = [
        "tasks-raw-result-composition",
        "tasks-request-meta-closure",
        "tasks-mrtr-old-envelopes",
        "tasks-completed-and-failed-payloads",
        "tasks-open-notification",
        "tasks-duration-sign",
        "tasks-subscription-fragments",
        "tasks-progress-and-logging",
    ];
    let expected_app_quarantine = [
        "apps-client-mime-types-required",
        "apps-styles-generator",
        "apps-container-dimensions",
        "apps-old-tool-and-request-id",
        "apps-old-sdk-sampling",
        "apps-tasks-and-mrtr-results",
        "apps-envelope-separation",
        "apps-resource-uri-meta",
        "apps-forward-open-reserved-members",
        "apps-generated-schema-authority",
    ];
    if !string_sequence_is(&task_quarantine, &expected_task_quarantine)
        || !string_sequence_is(&app_quarantine, &expected_app_quarantine)
    {
        return Err(Diagnostic::error("E_QUARANTINE_TASKS_APPS", "source IDs"));
    }
    let mut expected_quarantine = vec!["jose-rfc8017-sha256-duplicate".to_owned()];
    expected_quarantine.extend(task_quarantine);
    expected_quarantine.extend(app_quarantine);
    let policy_quarantine = policy
        .quarantine
        .iter()
        .map(|row| row.id.clone())
        .collect::<Vec<_>>();
    if policy_quarantine != expected_quarantine || policy.quarantine.len() != 19 {
        return Err(Diagnostic::error("E_QUARANTINE_EXACT_SET", "policy quarantine"));
    }
    validate_case_unique(policy_quarantine, "policy quarantine")?;
    for (index, row) in policy.quarantine.iter().enumerate() {
        let jose_row = index == 0;
        let expected_source = if jose_row {
            rejected_path
        } else {
            "evidence/fnd-01/tasks-apps.toml"
        };
        let expected_selector = if jose_row {
            "/".to_owned()
        } else if index <= expected_task_quarantine.len() {
            format!("/tasks/quarantine/id={}", row.id)
        } else {
            format!("/apps/quarantine/id={}", row.id)
        };
        if row.source_path != expected_source
            || row.source_selector != expected_selector
            || row.execution_allowed
            || row.mutation_allowed
            || row.promotion_allowed
            || row.expected_role.as_deref()
                != jose_row.then_some("quarantined-rejected-duplicate")
            || row.expected_source_basename.as_deref()
                != jose_row.then_some("rfc8017-sha256.toml")
            || row.expected_vector_id.as_deref()
                != jose_row.then_some("rfc7515-appendix-a2-rs256-quarantined-duplicate")
            || row.expected_accepted_vector != jose_row.then_some(false)
            || row.expected_duplicate_of.as_deref()
                != jose_row.then_some("rfc7515-a2.toml")
            || row.expected_negative_mutation_count != jose_row.then_some(0)
        {
            return Err(Diagnostic::error("E_QUARANTINE_CONTRACT", &row.id));
        }
    }

    let task_paths = pointer_get(&tasks, "/tasks/path_fixture", "tasks path fixture")?
        .as_array()
        .ok_or_else(|| Diagnostic::error("E_TOML_SCHEMA", "tasks path fixture"))?;
    if task_paths.len() != 48
        || pointer_get(
            &tasks,
            "/verification_contract/tasks_composition_path_count",
            "tasks contract",
        )?
        .as_integer()
            != Some(48)
        || pointer_get(
            &tasks,
            "/verification_contract/tasks_named_fixture_corpus_count",
            "tasks contract",
        )?
        .as_integer()
            != Some(144)
        || pointer_get(
            &tasks,
            "/verification_contract/tasks_total_content_addressed_literal_record_count",
            "tasks contract",
        )?
        .as_integer()
            != Some(167)
        || pointer_get(
            &tasks,
            "/verification_contract/apps_projection_omission_count",
            "apps contract",
        )?
        .as_integer()
            != Some(3)
        || pointer_get(&tasks, "/apps/cause_outcome", "apps cause outcomes")?
            .as_array()
            .map(Vec::len)
            != Some(12)
    {
        return Err(Diagnostic::error(
            "E_SUPPLEMENTAL_TASKS_APPS",
            "structural counts",
        ));
    }

    let media = parse_source_toml(
        files,
        "evidence/fnd-01/vectors/media/security-vectors.toml",
    )?;
    let media_cases = pointer_get(&media, "/case", "media security cases")?
        .as_array()
        .ok_or_else(|| Diagnostic::error("E_TOML_SCHEMA", "media security cases"))?;
    let media_rejections = media_cases
        .iter()
        .filter(|case| {
            case.as_table()
                .and_then(|table| table.get("expected"))
                .and_then(toml::Value::as_str)
                .is_some_and(|expected| expected.starts_with("reject_"))
        })
        .count();
    if media_cases.len() != 48
        || media_rejections != 36
        || pointer_get(&media, "/case_count", "media security cases")?.as_integer()
            != Some(48)
        || pointer_get(
            &media,
            "/runtime_results_claimed",
            "media security cases",
        )?
        .as_bool()
            != Some(false)
        || pointer_get(
            &media,
            "/runtime_boundary/required_renderer_entry_count_for_every_rejection",
            "media security cases",
        )?
        .as_integer()
            != Some(0)
    {
        return Err(Diagnostic::error(
            "E_QUARANTINE_MEDIA",
            "security vector contract",
        ));
    }

    let auth = parse_source_toml(files, "evidence/fnd-01/auth-standards.toml")?;
    if pointer_get(
        &auth,
        "/closure_boundary/aggregate_auth_support_claimed",
        "auth nonpromotion",
    )?
    .as_bool()
        != Some(false)
        || pointer_get(
            &auth,
            "/closure_boundary/aggregate_fnd_01_support_claimed",
            "auth nonpromotion",
        )?
        .as_bool()
            != Some(false)
    {
        return Err(Diagnostic::error("E_QUARANTINE_AUTH", "support claims"));
    }
    let serialization = parse_source_toml(
        files,
        "evidence/fnd-01/serialization-uri-dependencies.toml",
    )?;
    if pointer_get(&serialization, "/toolchain/resolver", "serialization resolver")?.as_str()
        != Some("2")
        || pointer_get(
            &serialization,
            "/gate/workspace_manifests_integrated",
            "serialization resolver",
        )?
        .as_bool()
            != Some(false)
    {
        return Err(Diagnostic::error(
            "E_RESOLVER_CANDIDATE",
            "serialization-uri",
        ));
    }
    let media_graph = parse_source_toml(
        files,
        "evidence/fnd-01/vectors/media/graph-snapshot.toml",
    )?;
    if pointer_get(&media_graph, "/resolver", "media resolver")?.as_str() != Some("2")
        || pointer_get(
            &media_graph,
            "/canonical_fastmcp_resolution",
            "media resolver",
        )?
        .as_bool()
            != Some(false)
    {
        return Err(Diagnostic::error("E_RESOLVER_CANDIDATE", "media graph"));
    }
    let candidate = parse_source_toml(
        files,
        "evidence/fnd-01/probes/asupersync/candidate-0.3.10.toml",
    )?;
    if pointer_get(&candidate, "/verdict", "asupersync candidate")?.as_str()
        != Some("rejected_as_release_pin")
        || pointer_get(
            &candidate,
            "/disposition/prerequisites_unresolved",
            "asupersync candidate",
        )?
        .as_integer()
            != Some(3)
    {
        return Err(Diagnostic::error(
            "E_REJECTED_CANDIDATE_PROMOTION",
            "asupersync 0.3.10",
        ));
    }
    Ok(())
}

fn run_verifier() -> VResult<Report> {
    let root = repository_root();
    validate_repository_root_layout(&root)?;
    let (policy, policy_bytes) = read_policy(&root)?;
    validate_policy_shape(&policy)?;
    let marker = resolve_safe(&root, "Cargo.toml", "repository marker")?;
    if !marker.is_file() {
        return Err(Diagnostic::error("E_REPOSITORY_ROOT", "Cargo.toml"));
    }
    let files = load_sources(&root, &policy)?;
    let source_tree = validate_source_tree(&files, &policy)?;
    validate_negative_inventory(&files, &policy)?;
    validate_mutation_dispatch(&files, &policy)?;
    validate_supplemental_contracts(&files, &policy)?;
    let mut report = Report::default();
    verify_outputs(
        &root,
        &policy,
        &policy_bytes,
        source_tree,
        &mut report,
    )?;
    Ok(report)
}

fn archive_test_bounds() -> ArchiveBounds {
    ArchiveBounds {
        max_archive_compressed_bytes: 8_388_608,
        max_archive_expanded_bytes: 67_108_864,
        max_archive_member_count: 4_096,
        max_archive_member_bytes: 16_777_216,
    }
}

fn write_test_octal(field: &mut [u8], value: u64) {
    field.fill(b'0');
    let digits = format!("{value:o}");
    let start = field.len() - digits.len() - 1;
    field[start..start + digits.len()].copy_from_slice(digits.as_bytes());
    let final_index = field.len() - 1;
    field[final_index] = 0;
}

fn test_tar_header(path: &str, payload_length: usize, typeflag: u8) -> [u8; 512] {
    let mut header = [0u8; 512];
    header[..path.len()].copy_from_slice(path.as_bytes());
    write_test_octal(&mut header[100..108], 0o644);
    write_test_octal(&mut header[108..116], 0);
    write_test_octal(&mut header[116..124], 0);
    write_test_octal(
        &mut header[124..136],
        u64::try_from(payload_length).expect("test payload length fits u64"),
    );
    write_test_octal(&mut header[136..148], 0);
    header[148..156].fill(b' ');
    header[156] = typeflag;
    let checksum = header.iter().map(|byte| u64::from(*byte)).sum::<u64>();
    write_test_octal(&mut header[148..156], checksum);
    header
}

fn test_tar(members: &[(&str, &[u8], u8)]) -> Vec<u8> {
    let mut tar = Vec::new();
    for (path, payload, typeflag) in members {
        tar.extend_from_slice(&test_tar_header(path, payload.len(), *typeflag));
        tar.extend_from_slice(payload);
        let padding = (512 - payload.len() % 512) % 512;
        tar.resize(tar.len() + padding, 0);
    }
    tar.resize(tar.len() + 1_024, 0);
    tar
}

fn test_gzip(tar: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(tar)
        .expect("in-memory gzip test write must succeed");
    encoder
        .finish()
        .expect("in-memory gzip test finish must succeed")
}

fn assert_archive_error(
    gzip: &[u8],
    expected_root: &str,
    expected_code: &str,
) {
    let error = validate_gzip_tar(
        gzip,
        &archive_test_bounds(),
        "in-memory archive",
        Some(expected_root),
    )
    .expect_err("malformed archive must fail closed");
    assert_eq!(error.code, expected_code);
}

#[test]
fn fnd_01_dependency_evidence_is_strict_offline_and_fail_closed() {
    match run_verifier() {
        Ok(report) => {
            assert!(
                !report.has_errors(),
                "FND-01 verifier errors:\n{}",
                report.sorted_stable().join("\n")
            );
            for diagnostic in &report.diagnostics {
                assert_eq!(
                    diagnostic.severity,
                    Severity::Pending,
                    "only explicit pending gates are admissible before final attestation"
                );
                assert!(
                    diagnostic.code.starts_with("E_PENDING_GATE:FND01:"),
                    "pending diagnostics must carry the exact phase gate: {}",
                    diagnostic.code
                );
            }
            validate_case_unique(
                report
                    .diagnostics
                    .iter()
                    .map(|diagnostic| diagnostic.code.clone()),
                "pending gates",
            )
            .unwrap_or_else(|diagnostic| panic!("{}", diagnostic.stable()));
        }
        Err(diagnostic) => {
            panic!("FND-01 verifier failed: {}", diagnostic.stable());
        }
    }
}

#[test]
fn fnd_01_static_oracles_have_exact_cardinality_and_no_case_collisions() {
    let specs = negative_specs();
    assert_eq!(specs.len(), EXPECTED_NEGATIVES);
    validate_case_unique(
        specs
            .iter()
            .map(|spec| format!("{}/{}", spec.family, spec.id)),
        "static negative registry",
    )
    .unwrap_or_else(|diagnostic| panic!("{}", diagnostic.stable()));

    let outputs = expected_receipt_paths()
        .unwrap_or_else(|diagnostic| panic!("{}", diagnostic.stable()));
    assert_eq!(outputs.len(), EXPECTED_RECEIPTS);
    assert_eq!(TOML_OUTPUT_IDS.len(), EXPECTED_RECEIPT_TOMLS);
    assert_eq!(BINARY_OUTPUT_IDS.len(), EXPECTED_RECEIPT_BINARIES);
    validate_case_unique(outputs, "static receipt matrix")
        .unwrap_or_else(|diagnostic| panic!("{}", diagnostic.stable()));

    let matrix = expected_derived_outputs()
        .unwrap_or_else(|diagnostic| panic!("{}", diagnostic.stable()));
    assert_eq!(matrix.len(), EXPECTED_RECEIPTS);
    assert_eq!(
        matrix
            .values()
            .map(|output| output.required_parent_ids.len())
            .sum::<usize>(),
        EXPECTED_DIRECT_PARENT_EDGES
    );
    let matrix_paths = matrix
        .values()
        .map(|output| {
            output
                .path
                .strip_prefix("evidence/fnd-01/integration/")
                .expect("static oracle path has integration prefix")
                .to_owned()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        matrix_paths,
        expected_receipt_paths()
            .unwrap_or_else(|diagnostic| panic!("{}", diagnostic.stable()))
    );
}

#[test]
fn fnd_01_strict_json_preserves_arbitrary_precision_and_rejects_duplicates() {
    for number_text in [
        "18446744073709551616",
        "-9223372036854775809",
        "340282366920938463463374607431768211455",
        "-170141183460469231731687303715884105728",
        "1234567890123456789012345678901234567890",
    ] {
        let parsed = parse_strict_json(
            number_text.as_bytes(),
            "arbitrary-precision integer self-test",
        )
        .unwrap_or_else(|diagnostic| panic!("{}", diagnostic.stable()));
        let StrictJson::Number(number) = parsed else {
            panic!("large JSON integer was not classified as a number");
        };
        assert_eq!(
            number.to_string(),
            number_text,
            "serde_json arbitrary_precision must preserve every tested integer"
        );
    }

    let negative_zero = parse_strict_json(b"-0", "negative-zero self-test")
        .unwrap_or_else(|diagnostic| panic!("{}", diagnostic.stable()));
    let StrictJson::Number(negative_zero) = negative_zero else {
        panic!("negative zero was not classified as a number");
    };
    assert_eq!(
        negative_zero.to_string(),
        "0",
        "FND01OBS uses serde_json::Number::to_string canonical form, not the source lexeme"
    );

    let duplicate = parse_strict_json(br#"{"same":1,"same":2}"#, "duplicate-key self-test")
        .expect_err("duplicate JSON object members must fail closed");
    assert_eq!(duplicate.code, "E_JSON_SCHEMA");

    for reserved_object in [
        br#"{"$serde_json::private::Number":"123"}"#.as_slice(),
        br#"{"nested":{"$serde_json::private::\u004eumber":"123"}}"#.as_slice(),
    ] {
        let reserved = parse_strict_json(reserved_object, "reserved-key self-test")
            .expect_err("decoded private number carrier member must fail closed");
        assert_eq!(reserved.code, "E_JSON_SCHEMA");
    }
    parse_strict_json(
        br#"{"ordinary":"$serde_json::private::Number"}"#,
        "reserved-name string-value self-test",
    )
    .expect("reserved carrier text is forbidden only as a decoded object member name");
}

#[test]
fn fnd_01_archive_parser_rejects_boundary_and_namespace_ambiguity() {
    let valid_tar = test_tar(&[("demo-1.0.0/src/lib.rs", b"x", 0)]);
    let valid_gzip = test_gzip(&valid_tar);
    let summary = validate_gzip_tar(
        &valid_gzip,
        &archive_test_bounds(),
        "in-memory archive",
        Some("demo-1.0.0"),
    )
    .expect("frozen in-memory archive must be valid");
    assert_eq!(summary.member_count, 1);
    assert_eq!(summary.regular_file_count, 1);
    assert_eq!(summary.expanded_bytes, 1);

    let missing_terminal = test_gzip(&valid_tar[..valid_tar.len() - 1_024]);
    assert_archive_error(
        &missing_terminal,
        "demo-1.0.0",
        "E_TAR_TERMINATOR",
    );

    let single_terminal = test_gzip(&valid_tar[..valid_tar.len() - 512]);
    assert_archive_error(
        &single_terminal,
        "demo-1.0.0",
        "E_TAR_TERMINATOR",
    );

    let mut third_terminal = valid_tar.clone();
    third_terminal.resize(third_terminal.len() + 512, 0);
    assert_archive_error(
        &test_gzip(&third_terminal),
        "demo-1.0.0",
        "E_TAR_TRAILING",
    );

    let mut appended_bytes = valid_gzip.clone();
    appended_bytes.push(0);
    assert_archive_error(
        &appended_bytes,
        "demo-1.0.0",
        "E_GZIP_TRAILING",
    );

    let mut concatenated = valid_gzip.clone();
    concatenated.extend_from_slice(&valid_gzip);
    assert_archive_error(
        &concatenated,
        "demo-1.0.0",
        "E_GZIP_TRAILING",
    );

    assert_archive_error(
        &valid_gzip,
        "other-1.0.0",
        "E_TAR_ROOT",
    );
    let bare_root = test_gzip(&test_tar(&[("demo-1.0.0", b"x", 0)]));
    assert_archive_error(
        &bare_root,
        "demo-1.0.0",
        "E_TAR_ROOT",
    );

    let special = test_gzip(&test_tar(&[("demo-1.0.0/link", b"", b'5')]));
    assert_archive_error(
        &special,
        "demo-1.0.0",
        "E_TAR_ENTRY_TYPE",
    );

    let duplicate = test_gzip(&test_tar(&[
        ("demo-1.0.0/a", b"a", 0),
        ("demo-1.0.0/a", b"b", 0),
    ]));
    assert_archive_error(
        &duplicate,
        "demo-1.0.0",
        "E_INVENTORY_DUPLICATE",
    );

    let case_collision = test_gzip(&test_tar(&[
        ("demo-1.0.0/A", b"a", 0),
        ("demo-1.0.0/a", b"b", 0),
    ]));
    assert_archive_error(
        &case_collision,
        "demo-1.0.0",
        "E_CASE_COLLISION",
    );

    let mut bad_padding_tar = valid_tar.clone();
    bad_padding_tar[513] = 1;
    assert_archive_error(
        &test_gzip(&bad_padding_tar),
        "demo-1.0.0",
        "E_TAR_PADDING",
    );
}

#[test]
fn fnd_01_final_attestation_is_not_a_receipt_or_source_tree_member() {
    let root = repository_root();
    let (policy, _) =
        read_policy(&root).unwrap_or_else(|diagnostic| panic!("{}", diagnostic.stable()));
    let outputs = validate_receipt_matrix(&policy)
        .unwrap_or_else(|diagnostic| panic!("{}", diagnostic.stable()));
    assert!(!outputs.contains("final-attestation.toml"));
    assert!(
        !policy
            .source_input
            .iter()
            .any(|source| source.path == policy.paths.final_attestation_path)
    );
    assert!(
        policy
            .final_attestation_contract
            .self_exclusion_rule
            .contains("excluded")
    );
}

#[test]
fn fnd_01_binary_cursor_rejects_truncation_bounds_utf8_and_trailing_bytes() {
    let mut truncated = BinaryCursor::new(&[0, 1, 2], "truncated");
    assert_eq!(
        truncated
            .read_u64()
            .expect_err("short u64 must fail")
            .code,
        "E_BINARY_TRUNCATED"
    );

    let mut oversized = BinaryCursor::new(&[0, 0, 0, 4, b'a', b'b', b'c', b'd'], "oversized");
    assert_eq!(
        oversized
            .read_string(3)
            .expect_err("declared string above the field bound must fail")
            .code,
        "E_BINARY_BOUND"
    );

    let mut invalid_utf8 = BinaryCursor::new(&[0, 0, 0, 2, 0xff, 0xfe], "invalid UTF-8");
    assert_eq!(
        invalid_utf8
            .read_string(8)
            .expect_err("invalid UTF-8 must fail")
            .code,
        "E_BINARY_UTF8"
    );

    let mut nul = BinaryCursor::new(&[0, 0, 0, 1, 0], "NUL string");
    assert_eq!(
        nul.read_string(8)
            .expect_err("NUL-bearing string must fail")
            .code,
        "E_BINARY_UTF8"
    );

    assert_eq!(
        BinaryCursor::new(b"\0", "trailing")
            .finish()
            .expect_err("unread suffix must fail")
            .code,
        "E_BINARY_TRAILING"
    );
}

#[test]
fn fnd_01_command_id_expansion_is_exact_and_canonical() {
    let root = repository_root();
    let (policy, _) =
        read_policy(&root).unwrap_or_else(|diagnostic| panic!("{}", diagnostic.stable()));
    let ids = expected_command_ids(&policy)
        .unwrap_or_else(|diagnostic| panic!("{}", diagnostic.stable()));
    assert_eq!(ids.len(), 206);
    assert_eq!(ids.first().map(String::as_str), Some("bootstrap.resolve"));
    assert_eq!(ids.get(1).map(String::as_str), Some("bootstrap.fetch"));
    assert_eq!(
        ids.get(191).map(String::as_str),
        Some("package.list.fastmcp-cli")
    );
    assert_eq!(
        ids.get(206),
        None,
        "the command matrix must remain the exact 206-row expansion"
    );
    assert_eq!(
        ids.last().map(String::as_str),
        Some("consumer.test.all")
    );
    assert_eq!(
        ids.iter().collect::<BTreeSet<_>>().len(),
        ids.len(),
        "the expanded command matrix must not contain duplicate IDs"
    );
}

#[test]
fn fnd_01_crates_io_index_path_grammar_is_exact() {
    for (name, expected) in [
        ("a", "index/1/a"),
        ("ab", "index/2/ab"),
        ("abc", "index/3/a/abc"),
        ("serde", "index/se/rd/serde"),
        ("serde_json", "index/se/rd/serde_json"),
    ] {
        assert_eq!(
            crates_io_index_path(name, "test").expect("valid crates.io package name"),
            expected
        );
    }
    for name in ["", "A", "bad/name", "bad.name", "nul\0name"] {
        assert_eq!(
            crates_io_index_path(name, "test")
                .expect_err("invalid crates.io package name must fail")
                .code,
            "E_SUPPLY_INDEX_PATH"
        );
    }
}

#[test]
fn fnd_01_direct_field_types_reject_inference_and_invalid_option_arrays() {
    let subject = "synthetic direct field";
    validate_direct_field_value(
        &toml::Value::String("value".to_owned()),
        DirectFieldType::String,
        subject,
        "field",
    )
    .expect("a string must satisfy the compiled string type");
    assert_eq!(
        validate_direct_field_value(
            &toml::Value::Integer(1),
            DirectFieldType::String,
            subject,
            "field",
        )
        .expect_err("the current value must not redefine a compiled string type")
        .code,
        "E_RECORD_TYPE"
    );
    assert_eq!(
        validate_direct_field_value(
            &toml::Value::Integer(-1),
            DirectFieldType::Unsigned,
            subject,
            "field",
        )
        .expect_err("negative integers must not satisfy an unsigned type")
        .code,
        "E_RECORD_TYPE"
    );

    for valid in [
        toml::Value::Array(Vec::new()),
        toml::Value::Array(vec![toml::Value::String("present".to_owned())]),
    ] {
        validate_direct_field_value(
            &valid,
            DirectFieldType::OptionalString,
            subject,
            "field",
        )
        .expect("an explicit option is exactly [] or [typed-value]");
    }
    assert_eq!(
        validate_direct_field_value(
            &toml::Value::Array(vec![
                toml::Value::String("first".to_owned()),
                toml::Value::String("second".to_owned()),
            ]),
            DirectFieldType::OptionalString,
            subject,
            "field",
        )
        .expect_err("an explicit option must reject a second element")
        .code,
        "E_RECORD_PRESENCE"
    );
    assert_eq!(
        validate_direct_field_value(
            &toml::Value::String(String::new()),
            DirectFieldType::OptionalString,
            subject,
            "field",
        )
        .expect_err("an optional field must not use a scalar sentinel")
        .code,
        "E_RECORD_TYPE"
    );
}

#[test]
fn fnd_01_environment_pair_and_count_link_types_are_exact() {
    let environment = toml::Value::Array(vec![
        toml::Value::Array(vec![
            toml::Value::String("LANG".to_owned()),
            toml::Value::String("C".to_owned()),
        ]),
        toml::Value::Array(vec![
            toml::Value::String("TZ".to_owned()),
            toml::Value::String("UTC".to_owned()),
        ]),
    ]);
    validate_direct_field_value(
        &environment,
        DirectFieldType::EnvironmentPairs,
        "synthetic environment",
        "environment",
    )
    .expect("ordered unique key/value pairs must pass");
    let duplicate = toml::Value::Array(vec![
        toml::Value::Array(vec![
            toml::Value::String("LANG".to_owned()),
            toml::Value::String("C".to_owned()),
        ]),
        toml::Value::Array(vec![
            toml::Value::String("LANG".to_owned()),
            toml::Value::String("en_US.UTF-8".to_owned()),
        ]),
    ]);
    assert_eq!(
        validate_direct_field_value(
            &duplicate,
            DirectFieldType::EnvironmentPairs,
            "synthetic environment",
            "environment",
        )
        .expect_err("duplicate environment keys must fail")
        .code,
        "E_RECORD_TYPE"
    );

    let mut row = toml::Table::new();
    row.insert("selected_row_count".to_owned(), toml::Value::Integer(1));
    row.insert(
        "selected_version".to_owned(),
        toml::Value::Array(vec![toml::Value::String("1.0.0".to_owned())]),
    );
    validate_count_array_links(
        &row,
        "variant/supply-entry-derived-local-index-file",
        "synthetic count link",
    )
    .expect("the compiled count must equal its array length");
    row.insert("selected_row_count".to_owned(), toml::Value::Integer(2));
    assert_eq!(
        validate_count_array_links(
            &row,
            "variant/supply-entry-derived-local-index-file",
            "synthetic count link",
        )
        .expect_err("a mismatched compiled count/array link must fail")
        .code,
        "E_RECORD_COUNT_LINK"
    );
}

#[test]
fn fnd_01_supply_entry_dispatch_accepts_one_variant_family() {
    let root = repository_root();
    let (policy, _) =
        read_policy(&root).unwrap_or_else(|diagnostic| panic!("{}", diagnostic.stable()));
    let mut entry = toml::Table::new();
    for (field, value) in [
        ("kind", toml::Value::String("crate-archive".to_owned())),
        (
            "relative_path",
            toml::Value::String("crates/demo-1.0.0.crate".to_owned()),
        ),
        ("byte_length", toml::Value::Integer(1)),
        ("sha256", toml::Value::String("00".repeat(32))),
        ("package_id", toml::Value::String("demo 1.0.0".to_owned())),
        ("version", toml::Value::String("1.0.0".to_owned())),
        ("checksum_sha256", toml::Value::String("11".repeat(32))),
        (
            "selected_index_line_sha256",
            toml::Value::String("22".repeat(32)),
        ),
        ("yanked", toml::Value::Boolean(false)),
    ] {
        entry.insert(field.to_owned(), value);
    }
    let mut body = toml::Table::new();
    body.insert(
        "entry".to_owned(),
        toml::Value::Array(vec![toml::Value::Table(entry)]),
    );
    validate_record_root_children(
        &body,
        "receipt/supply_receipt/supply_receipt",
        &policy,
    )
    .expect("two declared variants form one valid tagged-union dispatch family");
}

#[test]
fn fnd_01_std_sha256_matches_frozen_vectors() {
    let vectors: &[(&[u8], &str)] = &[
        (
            b"",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            b"abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
    ];
    for (input, expected) in vectors {
        let digest = super::trust_std::sha256(input)
            .unwrap_or_else(|error| panic!("std SHA-256 failed: {error}"));
        assert_eq!(super::trust_std::encode_lower_hex(&digest), *expected);
    }

    let mut hasher = super::trust_std::StreamingSha256::new();
    let block = [b'a'; 1_000];
    for _ in 0..1_000 {
        hasher
            .update(&block)
            .unwrap_or_else(|error| panic!("std SHA-256 update failed: {error}"));
    }
    let digest = hasher
        .finalize()
        .unwrap_or_else(|error| panic!("std SHA-256 finalize failed: {error}"));
    assert_eq!(
        super::trust_std::encode_lower_hex(&digest),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}

#[test]
fn fnd_01_std_sha256_streaming_cross_checks_sha2() {
    let bytes = (0..4_097usize)
        .map(|index| u8::try_from((index * 131 + 17) % 251).expect("value fits u8"))
        .collect::<Vec<_>>();
    let expected: [u8; 32] = Sha256::digest(&bytes).into();
    for chunk_length in [1usize, 7, 55, 56, 63, 64, 65, 257, 1_024] {
        let mut hasher = super::trust_std::StreamingSha256::new();
        for chunk in bytes.chunks(chunk_length) {
            hasher
                .update(chunk)
                .unwrap_or_else(|error| panic!("std SHA-256 update failed: {error}"));
        }
        let actual = hasher
            .finalize()
            .unwrap_or_else(|error| panic!("std SHA-256 finalize failed: {error}"));
        assert_eq!(actual, expected, "chunk length {chunk_length}");
    }
}

#[test]
fn fnd_01_external_marker_and_seal_parsers_are_strict() {
    use super::trust_std::{
        AuthoringMarker, FileBinding, IntegrationSeal, authoring_closure_preimage,
        encode_lower_hex, integration_seal_preimage, parse_authoring_marker,
        parse_integration_seal, MAX_OUTER_TRANSPORT_RECORD_BYTES,
    };

    let mut marker = AuthoringMarker {
        policy: FileBinding {
            byte_length: 11,
            sha256: super::trust_std::sha256(b"policy")
                .expect("frozen policy test hash"),
        },
        verifier: FileBinding {
            byte_length: 12,
            sha256: super::trust_std::sha256(b"verifier")
                .expect("frozen verifier test hash"),
        },
        harness: FileBinding {
            byte_length: 13,
            sha256: super::trust_std::sha256(b"harness")
                .expect("frozen harness test hash"),
        },
        closure_sha256: [0; 32],
    };
    let marker_preimage =
        authoring_closure_preimage(&marker).expect("encode frozen authoring closure");
    marker.closure_sha256 =
        super::trust_std::sha256(&marker_preimage).expect("frozen authoring closure");
    let marker_text = format!(
        "FND01AUTHORv2:{}:{}:{}:{}:{}:{}:{}",
        marker.policy.byte_length,
        encode_lower_hex(&marker.policy.sha256),
        marker.verifier.byte_length,
        encode_lower_hex(&marker.verifier.sha256),
        marker.harness.byte_length,
        encode_lower_hex(&marker.harness.sha256),
        encode_lower_hex(&marker.closure_sha256),
    );
    assert_eq!(
        parse_authoring_marker(&marker_text).expect("canonical marker"),
        marker
    );
    assert!(parse_authoring_marker(&format!("{marker_text} ")).is_err());
    assert!(parse_authoring_marker(&marker_text.replacen(":11:", ":011:", 1)).is_err());
    assert!(parse_authoring_marker(&"x".repeat(513)).is_err());

    let mut seal = IntegrationSeal {
        run_id: [0x17; 16],
        records: [
            FileBinding {
                byte_length: 1,
                sha256: super::trust_std::sha256(b"a").expect("record hash"),
            },
            FileBinding {
                byte_length: 2,
                sha256: super::trust_std::sha256(b"bb").expect("record hash"),
            },
            FileBinding {
                byte_length: 3,
                sha256: super::trust_std::sha256(b"ccc").expect("record hash"),
            },
            FileBinding {
                byte_length: 4,
                sha256: super::trust_std::sha256(b"dddd").expect("record hash"),
            },
            FileBinding {
                byte_length: 5,
                sha256: super::trust_std::sha256(b"eeeee").expect("record hash"),
            },
        ],
        outer_transport: FileBinding {
            byte_length: 5,
            sha256: super::trust_std::sha256(b"outer").expect("outer transport hash"),
        },
        authoring_closure_sha256: marker.closure_sha256,
        seal_sha256: [0; 32],
    };
    let seal_preimage =
        integration_seal_preimage(&seal).expect("encode frozen integration seal");
    seal.seal_sha256 =
        super::trust_std::sha256(&seal_preimage).expect("frozen integration seal");
    let encode_seal = |value: &IntegrationSeal| {
        let mut text = format!(
            "FND01INTEGRATIONv1:{}",
            encode_lower_hex(&value.run_id)
        );
        for record in &value.records {
            text.push(':');
            text.push_str(&record.byte_length.to_string());
            text.push(':');
            text.push_str(&encode_lower_hex(&record.sha256));
        }
        text.push(':');
        text.push_str(&value.outer_transport.byte_length.to_string());
        text.push(':');
        text.push_str(&encode_lower_hex(&value.outer_transport.sha256));
        text.push(':');
        text.push_str(&encode_lower_hex(&value.authoring_closure_sha256));
        text.push(':');
        text.push_str(&encode_lower_hex(&value.seal_sha256));
        text
    };
    let mut legacy_fourteen_field_text = format!(
        "FND01INTEGRATIONv1:{}",
        encode_lower_hex(&seal.run_id)
    );
    for record in &seal.records {
        legacy_fourteen_field_text.push(':');
        legacy_fourteen_field_text.push_str(&record.byte_length.to_string());
        legacy_fourteen_field_text.push(':');
        legacy_fourteen_field_text.push_str(&encode_lower_hex(&record.sha256));
    }
    legacy_fourteen_field_text.push(':');
    legacy_fourteen_field_text.push_str(&encode_lower_hex(&seal.authoring_closure_sha256));
    legacy_fourteen_field_text.push(':');
    legacy_fourteen_field_text.push_str(&encode_lower_hex(&seal.seal_sha256));
    let seal_text = encode_seal(&seal);
    assert_eq!(
        parse_integration_seal(&seal_text, &marker.closure_sha256)
            .expect("canonical integration seal"),
        seal
    );
    assert!(
        parse_integration_seal(&legacy_fourteen_field_text, &marker.closure_sha256).is_err()
    );
    assert!(parse_integration_seal(&format!("{seal_text}:"), &marker.closure_sha256).is_err());
    assert!(parse_integration_seal(&seal_text, &[0x55; 32]).is_err());
    assert!(parse_integration_seal(&"x".repeat(1_025), &marker.closure_sha256).is_err());

    let mut boundary_seal = seal.clone();
    boundary_seal.outer_transport.byte_length = MAX_OUTER_TRANSPORT_RECORD_BYTES;
    boundary_seal.seal_sha256 = super::trust_std::sha256(
        &integration_seal_preimage(&boundary_seal).expect("encode boundary integration seal"),
    )
    .expect("hash boundary integration seal");
    let boundary_text = encode_seal(&boundary_seal);
    assert_eq!(
        parse_integration_seal(&boundary_text, &marker.closure_sha256)
            .expect("outer transport boundary is admitted"),
        boundary_seal
    );

    let mut oversized_seal = boundary_seal;
    oversized_seal.outer_transport.byte_length = MAX_OUTER_TRANSPORT_RECORD_BYTES + 1;
    oversized_seal.seal_sha256 = super::trust_std::sha256(
        &integration_seal_preimage(&oversized_seal).expect("encode oversized integration seal"),
    )
    .expect("hash oversized integration seal");
    let oversized_error = parse_integration_seal(
        &encode_seal(&oversized_seal),
        &marker.closure_sha256,
    );
    assert_eq!(
        oversized_error
            .expect_err("outer transport above the boundary must be rejected")
            .code(),
        "E_INTEGER_BOUND"
    );
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn fnd_01_checked_snapshot_hooks_detect_replacement_relinking_and_in_place_drift() {
    use super::trust_std::{
        FileBinding, SnapshotStage, TrustError, checked_snapshot_with_hook,
    };
    use std::fs::OpenOptions;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    #[derive(Debug, Clone, Copy)]
    enum Mutation {
        Replace,
        Relink,
        InPlace,
    }

    fn fresh_root(sequence: u64) -> PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "fastmcp-fnd01-snapshot-{}-{timestamp}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("fresh snapshot test root");
        root
    }

    for stage in [
        SnapshotStage::PreOpen,
        SnapshotStage::PostOpenPreRead,
        SnapshotStage::PostReadPreFinalMetadata,
    ] {
        for mutation in [Mutation::Replace, Mutation::Relink, Mutation::InPlace] {
            let sequence = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let root = fresh_root(sequence);
            let leaf = root.join("sample.bin");
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&leaf)
                .expect("fresh snapshot test leaf");
            file.write_all(b"original").expect("write snapshot test leaf");
            file.sync_all().expect("sync snapshot test leaf");
            drop(file);
            let expected = FileBinding {
                byte_length: 8,
                sha256: super::trust_std::sha256(b"original")
                    .expect("snapshot test digest"),
            };
            let expected = match mutation {
                Mutation::InPlace => None,
                Mutation::Replace | Mutation::Relink => Some(expected),
            };
            let mutation_root = root.clone();
            let attempted = Arc::new(AtomicBool::new(false));
            let mutation_completed = Arc::new(AtomicBool::new(false));
            let hook_attempted = Arc::clone(&attempted);
            let hook_completed = Arc::clone(&mutation_completed);
            let mut hook = move |observed: SnapshotStage,
                                 path: &Path|
                  -> Result<(), TrustError> {
                if observed != stage || hook_attempted.swap(true, Ordering::SeqCst) {
                    return Ok(());
                }
                match mutation {
                    Mutation::Replace => {
                        fs::rename(path, mutation_root.join("sample.original")).map_err(
                            |error| TrustError::new("E_TEST_RENAME", error.to_string()),
                        )?;
                        let mut replacement = OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(path)
                            .map_err(|error| {
                                TrustError::new("E_TEST_REPLACEMENT", error.to_string())
                            })?;
                        replacement.write_all(b"replaced").map_err(|error| {
                            TrustError::new("E_TEST_REPLACEMENT", error.to_string())
                        })?;
                        replacement.sync_all().map_err(|error| {
                            TrustError::new("E_TEST_REPLACEMENT", error.to_string())
                        })?;
                    }
                    Mutation::Relink => {
                        fs::hard_link(path, mutation_root.join("sample.alias")).map_err(
                            |error| TrustError::new("E_TEST_HARDLINK", error.to_string()),
                        )?;
                    }
                    Mutation::InPlace => {
                        let mut permissions = fs::metadata(path)
                            .map_err(|error| {
                                TrustError::new("E_TEST_IN_PLACE", error.to_string())
                            })?
                            .permissions();
                        let changed_mode = permissions.mode() ^ 0o100;
                        permissions.set_mode(changed_mode);
                        fs::set_permissions(path, permissions).map_err(|error| {
                            TrustError::new("E_TEST_IN_PLACE", error.to_string())
                        })?;
                        let mut changed_file = OpenOptions::new()
                            .write(true)
                            .truncate(true)
                            .open(path)
                            .map_err(|error| {
                                TrustError::new("E_TEST_IN_PLACE", error.to_string())
                            })?;
                        changed_file.write_all(b"mutated!").map_err(|error| {
                            TrustError::new("E_TEST_IN_PLACE", error.to_string())
                        })?;
                        changed_file.sync_all().map_err(|error| {
                            TrustError::new("E_TEST_IN_PLACE", error.to_string())
                        })?;
                    }
                }
                hook_completed.store(true, Ordering::SeqCst);
                Ok(())
            };
            let result =
                checked_snapshot_with_hook(&root, "sample.bin", 64, expected, &mut hook);
            assert!(
                attempted.load(Ordering::SeqCst),
                "hook stage was not reached"
            );
            assert!(
                mutation_completed.load(Ordering::SeqCst),
                "injected mutation failed before the verifier observed it"
            );
            let error = result.expect_err("injected mutation must be rejected");
            let expected_code = match (stage, mutation) {
                (SnapshotStage::PostReadPreFinalMetadata, Mutation::Relink) => {
                    "E_FILE_HARDLINK"
                }
                _ => "E_FILE_RACE",
            };
            assert_eq!(
                error.code(),
                expected_code,
                "unexpected error for stage={stage:?}, mutation={mutation:?}: {error}",
            );
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[derive(Debug, Clone, Copy)]
enum SetWideSnapshotDrift {
    SameLengthContent,
    Length,
    Metadata,
    Identity,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn exercise_set_wide_snapshot_drift(drift: SetWideSnapshotDrift) {
    use super::trust_std::{
        FileBinding, SnapshotStage, TrustError, checked_snapshot_set_with_hook,
    };
    use std::fs::OpenOptions;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    let sequence = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "fastmcp-fnd01-set-snapshot-{}-{timestamp}-{sequence}",
        std::process::id()
    ));
    fs::create_dir(&root).expect("fresh set-wide snapshot test root");

    let canonical_paths = ["member-0.bin", "member-1.bin", "member-2.bin"];
    let maximum_bytes = [64u64; 3];
    let payloads: [&[u8]; 3] = [b"member-zero", b"member-one", b"member-two"];
    for (relative, payload) in canonical_paths.iter().zip(payloads.iter()) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join(relative))
            .expect("fresh set-wide snapshot member");
        file.write_all(payload)
            .expect("write set-wide snapshot member");
        file.sync_all().expect("sync set-wide snapshot member");
    }
    let expected = payloads.map(|payload| FileBinding {
        byte_length: u64::try_from(payload.len()).expect("test payload length fits u64"),
        sha256: super::trust_std::sha256(payload).expect("set-wide snapshot member digest"),
    });

    let earlier_path = root.join(canonical_paths[0]);
    let later_path = root.join(canonical_paths[2]);
    let preserved_path = root.join("member-0.retained");
    let mutation_observed = std::cell::Cell::new(false);
    let mut hook = |stage: SnapshotStage, sampled_path: &Path| -> Result<(), TrustError> {
        if stage != SnapshotStage::PostOpenPreRead
            || sampled_path != later_path.as_path()
            || mutation_observed.replace(true)
        {
            return Ok(());
        }
        match drift {
            SetWideSnapshotDrift::SameLengthContent => {
                let mut file = OpenOptions::new()
                    .write(true)
                    .open(&earlier_path)
                    .map_err(|error| {
                        TrustError::new("E_TEST_SET_CONTENT", error.to_string())
                    })?;
                file.write_all(b"MEMBER-ZERO").map_err(|error| {
                    TrustError::new("E_TEST_SET_CONTENT", error.to_string())
                })?;
                file.sync_all().map_err(|error| {
                    TrustError::new("E_TEST_SET_CONTENT", error.to_string())
                })?;
            }
            SetWideSnapshotDrift::Length => {
                let mut file = OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .open(&earlier_path)
                    .map_err(|error| {
                        TrustError::new("E_TEST_SET_LENGTH", error.to_string())
                    })?;
                file.write_all(b"short").map_err(|error| {
                    TrustError::new("E_TEST_SET_LENGTH", error.to_string())
                })?;
                file.sync_all().map_err(|error| {
                    TrustError::new("E_TEST_SET_LENGTH", error.to_string())
                })?;
            }
            SetWideSnapshotDrift::Metadata => {
                let mut permissions = fs::metadata(&earlier_path)
                    .map_err(|error| {
                        TrustError::new("E_TEST_SET_METADATA", error.to_string())
                    })?
                    .permissions();
                permissions.set_mode(permissions.mode() ^ 0o100);
                fs::set_permissions(&earlier_path, permissions).map_err(|error| {
                    TrustError::new("E_TEST_SET_METADATA", error.to_string())
                })?;
            }
            SetWideSnapshotDrift::Identity => {
                fs::rename(&earlier_path, &preserved_path).map_err(|error| {
                    TrustError::new("E_TEST_SET_IDENTITY", error.to_string())
                })?;
                let mut replacement = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&earlier_path)
                    .map_err(|error| {
                        TrustError::new("E_TEST_SET_IDENTITY", error.to_string())
                    })?;
                replacement.write_all(payloads[0]).map_err(|error| {
                    TrustError::new("E_TEST_SET_IDENTITY", error.to_string())
                })?;
                replacement.sync_all().map_err(|error| {
                    TrustError::new("E_TEST_SET_IDENTITY", error.to_string())
                })?;
            }
        }
        Ok(())
    };

    let result = checked_snapshot_set_with_hook(
        &root,
        &canonical_paths,
        &maximum_bytes,
        &expected,
        &mut hook,
    );
    assert!(
        mutation_observed.get(),
        "the earlier member was not changed while the later member was sampled"
    );
    let error = result.expect_err("set-wide second pass must reject earlier-member drift");
    assert_eq!(
        error.code(),
        "E_SET_RACE",
        "unexpected error for drift={drift:?}: {error}"
    );
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn fnd_01_set_wide_bookend_accepts_a_stable_bounded_set_and_rejects_oversizing() {
    use super::trust_std::{
        FileBinding, SnapshotStage, TrustError, checked_snapshot_set_with_hook,
    };
    use std::fs::OpenOptions;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    let sequence = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "fastmcp-fnd01-stable-set-snapshot-{}-{timestamp}-{sequence}",
        std::process::id()
    ));
    fs::create_dir(&root).expect("fresh stable set-wide snapshot test root");
    let canonical_paths = ["stable-0.bin", "stable-1.bin"];
    let maximum_bytes = [64u64; 2];
    let payloads: [&[u8]; 2] = [b"stable-zero", b"stable-one"];
    for (relative, payload) in canonical_paths.iter().zip(payloads.iter()) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join(relative))
            .expect("fresh stable set-wide snapshot member");
        file.write_all(payload)
            .expect("write stable set-wide snapshot member");
        file.sync_all()
            .expect("sync stable set-wide snapshot member");
    }
    let expected = payloads.map(|payload| FileBinding {
        byte_length: u64::try_from(payload.len()).expect("test payload length fits u64"),
        sha256: super::trust_std::sha256(payload).expect("stable set member digest"),
    });
    let mut noop = |_stage: SnapshotStage, _path: &Path| -> Result<(), TrustError> { Ok(()) };
    let retained = checked_snapshot_set_with_hook(
        &root,
        &canonical_paths,
        &maximum_bytes,
        &expected,
        &mut noop,
    )
    .expect("an unchanged canonical set must survive both passes");
    assert_eq!(retained[0].logical_path, canonical_paths[0]);
    assert_eq!(retained[1].logical_path, canonical_paths[1]);

    let oversized_paths = ["oversized.bin"; 9];
    let oversized_limits = [64u64; 9];
    let oversized_bindings = [expected[0]; 9];
    let oversized_error = checked_snapshot_set_with_hook(
        &root,
        &oversized_paths,
        &oversized_limits,
        &oversized_bindings,
        &mut noop,
    )
    .expect_err("sets above the fixed eight-member bound must fail closed");
    assert_eq!(oversized_error.code(), "E_SET_BOUND");
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn fnd_01_set_wide_bookend_detects_earlier_member_content_and_length_drift() {
    for drift in [
        SetWideSnapshotDrift::SameLengthContent,
        SetWideSnapshotDrift::Length,
    ] {
        exercise_set_wide_snapshot_drift(drift);
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn fnd_01_set_wide_bookend_detects_earlier_member_metadata_and_identity_drift() {
    for drift in [
        SetWideSnapshotDrift::Metadata,
        SetWideSnapshotDrift::Identity,
    ] {
        exercise_set_wide_snapshot_drift(drift);
    }
}

#[cfg(test)]
fn synthetic_assertion(
    id: &str,
    expected_trigger_count: usize,
    allowed_cotrigger_ids: Vec<String>,
    suppressed_ids: Vec<String>,
) -> SemanticAssertion {
    SemanticAssertion {
        id: id.to_owned(),
        family: "synthetic".to_owned(),
        source_path: "evidence/fnd-01/synthetic.toml".to_owned(),
        selector: "/value".to_owned(),
        secondary_selector: None,
        rule: format!("RULE_{id}"),
        logical_path: "/value".to_owned(),
        baseline_mode: "canonical_source_value".to_owned(),
        observation_mode: AssertionObservationMode::CanonicalSelectedToml,
        baseline_observation_sha256: "00".repeat(32),
        violation_mode: AssertionViolationMode::ExactObservationSha256,
        violating_observation_sha256: "11".repeat(32),
        expected_trigger_count,
        allowed_cotrigger_ids,
        suppressed_ids,
    }
}

#[cfg(test)]
fn synthetic_byte_case(selector: &str, argument: &str) -> NegativeCase {
    NegativeCase {
        family: "synthetic".to_owned(),
        id: "byte-case".to_owned(),
        source_index: 0,
        target_path: "evidence/fnd-01/synthetic.bin".to_owned(),
        target_selector: selector.to_owned(),
        operation: MutationKind::ReplaceBytes,
        argument: Some(argument.to_owned()),
        secondary_selector: None,
        integrity_mode: "rebind_virtual_hashes".to_owned(),
        validator: "synthetic.byte-case".to_owned(),
    }
}

#[cfg(test)]
fn synthetic_table_member_fixture(relative_selector: &str) -> MutationFixture {
    let mut value = toml::Table::new();
    value.insert(
        "relative_selector".to_owned(),
        toml::Value::String(relative_selector.to_owned()),
    );
    value.insert(
        "value".to_owned(),
        toml::Value::String("changed".to_owned()),
    );
    MutationFixture {
        id: "synthetic/table-member".to_owned(),
        application: FixtureApplication::ReplaceTableMember,
        value_kind: FixtureValueKind::TableMember,
        value: toml::Value::Table(value),
    }
}

#[cfg(test)]
fn synthetic_structured_case(id: &str, selector: &str, operation: MutationKind) -> NegativeCase {
    NegativeCase {
        family: "synthetic".to_owned(),
        id: id.to_owned(),
        source_index: 0,
        target_path: "evidence/fnd-01/synthetic.toml".to_owned(),
        target_selector: selector.to_owned(),
        operation,
        argument: Some("fixture:synthetic/table-member".to_owned()),
        secondary_selector: None,
        integrity_mode: "rebind_virtual_hashes".to_owned(),
        validator: format!("synthetic.{id}"),
    }
}

#[test]
fn fixture_table_member_requires_identity_for_table_arrays() {
    let toml_document = r#"
[[ambiguities]]
id = "first"
decision = "one"

[[ambiguities]]
id = "second"
decision = "two"
"#
    .parse::<toml::Value>()
    .expect("synthetic TOML table array");
    let error = require_toml_table_array_identity(
        &toml_document,
        "/ambiguities/1",
        "synthetic.toml",
    )
    .expect_err("numeric TOML table-array traversal must fail");
    assert_eq!(error.code, "E_FIXTURE_IDENTITY_REQUIRED");
    require_toml_table_array_identity(
        &toml_document,
        "/ambiguities/id=second",
        "synthetic.toml",
    )
    .expect("named TOML table-array traversal must pass");

    let json_document = parse_strict_json(
        br#"{"ambiguities":[{"id":"first","decision":"one"},{"id":"second","decision":"two"}]}"#,
        "synthetic.json",
    )
    .expect("synthetic JSON object array");
    let error = require_json_table_array_identity(
        &json_document,
        "/ambiguities/1",
        "synthetic.json",
    )
    .expect_err("numeric JSON object-array traversal must fail");
    assert_eq!(error.code, "E_FIXTURE_IDENTITY_REQUIRED");
    require_json_table_array_identity(
        &json_document,
        "/ambiguities/id=second",
        "synthetic.json",
    )
    .expect("named JSON object-array traversal must pass");
}

#[test]
fn fixture_table_member_rejects_numeric_relative_table_array_traversal() {
    let fixture = synthetic_table_member_fixture("/items/1/decision");
    let case = synthetic_structured_case(
        "relative-table-array",
        "/root",
        MutationKind::Replace,
    );
    let mut toml_document = r#"
[root]
name = "container"

[[root.items]]
id = "first"
decision = "one"

[[root.items]]
id = "second"
decision = "two"
"#
    .parse::<toml::Value>()
    .expect("synthetic nested TOML table array");
    let error = apply_toml_fixture(&mut toml_document, &case, &fixture)
        .expect_err("numeric relative TOML table-array traversal must fail");
    assert_eq!(error.code, "E_FIXTURE_IDENTITY_REQUIRED");

    let mut json_document = parse_strict_json(
        br#"{"root":{"name":"container","items":[{"id":"first","decision":"one"},{"id":"second","decision":"two"}]}}"#,
        "synthetic.json",
    )
    .expect("synthetic nested JSON object array");
    let error = apply_json_fixture(&mut json_document, &case, &fixture)
        .expect_err("numeric relative JSON object-array traversal must fail");
    assert_eq!(error.code, "E_FIXTURE_IDENTITY_REQUIRED");
}

#[test]
fn fixture_table_member_rejects_forbidden_and_empty_relative_payloads() {
    let mut document = r#"
[root]
result = "original"
"#
    .parse::<toml::Value>()
    .expect("synthetic forbidden-field document");
    for (application, operation) in [
        (FixtureApplication::InsertTableMember, MutationKind::Insert),
        (FixtureApplication::ReplaceTableMember, MutationKind::Replace),
    ] {
        let mut fixture = synthetic_table_member_fixture("/result");
        fixture.application = application;
        let case = synthetic_structured_case("forbidden-relative", "/root", operation);
        let error = apply_toml_fixture(&mut document, &case, &fixture)
            .expect_err("fixture relative oracle field must fail");
        assert_eq!(error.code, "E_MUTATION_FORBIDDEN_TARGET");
    }

    for empty_value in [
        toml::Value::String(String::new()),
        toml::Value::Array(Vec::new()),
        toml::Value::Table(toml::Table::new()),
    ] {
        let mut fixture = synthetic_table_member_fixture("/value");
        fixture
            .value
            .as_table_mut()
            .expect("table-member fixture wrapper")
            .insert("value".to_owned(), empty_value);
        let error = fixture_table_member(&fixture, &fixture.id)
            .expect_err("empty nested table-member value must fail");
        assert_eq!(error.code, "E_FIXTURE_SCHEMA");
    }
}

#[test]
fn quarantine_boundary_detects_ancestor_and_descendant_selectors() {
    for selector in [
        "/tasks",
        "/tasks/quarantine",
        "/tasks/quarantine/id=tasks-raw-result-composition",
    ] {
        let components = parse_pointer(selector, "synthetic quarantine")
            .expect("valid synthetic quarantine selector");
        assert!(pointer_overlaps_literal(
            &components,
            &["tasks", "quarantine"],
        ));
        let (tasks, apps) =
            task_app_quarantine_overlap("evidence/fnd-01/tasks-apps.toml", &components);
        assert!(tasks);
        assert!(!apps);
    }
    let unrelated = parse_pointer("/tasks/active", "synthetic quarantine")
        .expect("valid unrelated selector");
    assert!(!pointer_overlaps_literal(
        &unrelated,
        &["tasks", "quarantine"],
    ));
    let secondary = parse_pointer(
        "/apps/quarantine/id=apps-unreviewed-loss",
        "synthetic quarantine",
    )
    .expect("valid synthetic swap secondary");
    let (tasks, apps) =
        task_app_quarantine_overlap("evidence/fnd-01/tasks-apps.toml", &secondary);
    assert!(!tasks);
    assert!(apps);

    let self_target = parse_pointer("/negative/0", "synthetic self target")
        .expect("valid synthetic negative-array selector");
    assert!(pointer_enters_named_root(&self_target, "negative"));
    assert!(!pointer_enters_named_root(&self_target, "positive"));
}

#[test]
fn mutation_rename_key_is_noop_and_collision_safe() {
    let baseline = r#"
[root]
old = "value"
occupied = "other"
"#
    .parse::<toml::Value>()
    .expect("synthetic rename document");

    let mut same_key = baseline.clone();
    let mut case = synthetic_structured_case("rename-key", "/root/old", MutationKind::RenameKey);
    case.argument = Some("old".to_owned());
    let error = apply_rename_key(&mut same_key, &case)
        .expect_err("renaming a key to itself must fail");
    assert_eq!(error.code, "E_MUTATION_NOOP");
    assert_eq!(same_key, baseline);

    let mut collision = baseline.clone();
    case.argument = Some("occupied".to_owned());
    let error = apply_rename_key(&mut collision, &case)
        .expect_err("renaming over an existing key must fail");
    assert_eq!(error.code, "E_MUTATION_SCHEMA");
    assert_eq!(collision, baseline);

    let mut renamed = baseline;
    case.argument = Some("renamed".to_owned());
    apply_rename_key(&mut renamed, &case).expect("fresh key rename must pass");
    assert!(pointer_get(&renamed, "/root/old", &case.id).is_err());
    assert_eq!(
        pointer_get(&renamed, "/root/renamed", &case.id)
            .expect("renamed key")
            .as_str(),
        Some("value"),
    );
}

#[test]
fn mutation_duplicate_rejects_synthetic_table_key_collision() {
    let case = synthetic_structured_case("duplicate-table", "/root", MutationKind::Duplicate);
    let mut document = r#"
[root]
original = "value"
"#
    .parse::<toml::Value>()
    .expect("synthetic duplicate document");
    let collision_key = mutation_key(&case);
    document
        .get_mut("root")
        .and_then(toml::Value::as_table_mut)
        .expect("synthetic duplicate target table")
        .insert(
            collision_key,
            toml::Value::String("preexisting".to_owned()),
        );
    let baseline = document.clone();
    let error = apply_duplicate(&mut document, &case)
        .expect_err("duplicate must not overwrite its synthetic table key");
    assert_eq!(error.code, "E_MUTATION_SCHEMA");
    assert_eq!(document, baseline);
}

#[test]
fn mutation_byte_grammar_accepts_exact_crlf_insertion() {
    let mut bytes = b"left\nright".to_vec();
    apply_byte_mutation(
        &mut bytes,
        &synthetic_byte_case("/bytes/4", "insert-cr-before-lf"),
    )
    .expect("exact LF offset must admit one CR insertion");
    assert_eq!(bytes, b"left\r\nright");
}

#[test]
fn mutation_byte_grammar_rejects_noncanonical_or_empty_arguments() {
    for (selector, argument) in [
        ("/bytes/end", "append-hex:"),
        ("/bytes/0", "xor:0001"),
        ("/bytes/end", "truncate:0"),
        ("/bytes/end", "truncate:01"),
        ("/bytes/04", "insert-cr-before-lf"),
    ] {
        let mut bytes = b"left\nright".to_vec();
        let error = apply_byte_mutation(
            &mut bytes,
            &synthetic_byte_case(selector, argument),
        )
        .expect_err("malformed byte mutation argument must fail");
        assert_eq!(error.code, "E_MUTATION_SCHEMA");
    }
}

#[test]
fn mutation_finding_precedence_emits_cotrigger_and_records_suppression() {
    let allowed = synthetic_assertion("synthetic.allowed", 1, Vec::new(), Vec::new());
    let suppressed = synthetic_assertion("synthetic.suppressed", 1, Vec::new(), Vec::new());
    let primary = synthetic_assertion(
        "synthetic.primary",
        2,
        vec![allowed.id.clone()],
        vec![suppressed.id.clone()],
    );
    let resolution = resolve_findings(
        &primary,
        vec![
            finding_from_assertion(&suppressed, "33".repeat(32))
                .expect("synthetic suppressed finding"),
            finding_from_assertion(&allowed, "22".repeat(32))
                .expect("synthetic allowed finding"),
            finding_from_assertion(&primary, "11".repeat(32))
                .expect("synthetic primary finding"),
        ],
    )
    .expect("declared cotrigger and suppression must resolve");
    assert_eq!(
        resolution
            .emitted
            .iter()
            .map(|finding| finding.assertion_id.as_str())
            .collect::<Vec<_>>(),
        ["synthetic.primary", "synthetic.allowed"],
    );
    assert_eq!(
        resolution
            .suppressed
            .iter()
            .map(|finding| finding.assertion_id.as_str())
            .collect::<Vec<_>>(),
        ["synthetic.suppressed"],
    );
}

#[test]
fn mutation_finding_authority_rejects_corrupted_observation_hash() {
    let assertion = synthetic_assertion("synthetic.primary", 1, Vec::new(), Vec::new());
    let assertions = BTreeMap::from([(assertion.id.as_str(), &assertion)]);
    let finding =
        finding_from_assertion(&assertion, "22".repeat(32)).expect("synthetic finding");
    let error = validate_finding_authority(&finding, &assertions)
        .expect_err("finding hash must be owned by its assertion");
    assert_eq!(error.code, "E_MUTATION_DIAGNOSTIC");
}

#[test]
fn mutation_finding_precedence_rejects_unexpected_and_bad_references() {
    let allowed = synthetic_assertion("synthetic.allowed", 1, Vec::new(), Vec::new());
    let suppressed = synthetic_assertion("synthetic.suppressed", 1, Vec::new(), Vec::new());
    let primary = synthetic_assertion(
        "synthetic.primary",
        2,
        vec![allowed.id.clone()],
        vec![suppressed.id.clone()],
    );
    let unexpected = synthetic_assertion("synthetic.unexpected", 1, Vec::new(), Vec::new());
    let error = resolve_findings(
        &primary,
        vec![
            finding_from_assertion(&primary, "11".repeat(32))
                .expect("synthetic primary finding"),
            finding_from_assertion(&unexpected, "44".repeat(32))
                .expect("synthetic unexpected finding"),
        ],
    )
    .expect_err("undeclared finding must fail");
    assert_eq!(error.code, "E_ASSERTION_UNEXPECTED_FINDING");

    let self_referencing = synthetic_assertion(
        "synthetic.invalid",
        1,
        vec!["synthetic.invalid".to_owned()],
        Vec::new(),
    );
    let assertions = BTreeMap::from([
        (allowed.id.as_str(), &allowed),
        (self_referencing.id.as_str(), &self_referencing),
        (primary.id.as_str(), &primary),
        (suppressed.id.as_str(), &suppressed),
    ]);
    let error = validate_assertion_references(&assertions)
        .expect_err("self assertion reference must fail");
    assert_eq!(error.code, "E_ASSERTION_REFERENCE_OVERLAP");

    let unknown = synthetic_assertion(
        "synthetic.invalid",
        1,
        vec!["synthetic.unknown".to_owned()],
        Vec::new(),
    );
    let assertions = BTreeMap::from([
        (allowed.id.as_str(), &allowed),
        (unknown.id.as_str(), &unknown),
        (primary.id.as_str(), &primary),
        (suppressed.id.as_str(), &suppressed),
    ]);
    let error = validate_assertion_references(&assertions)
        .expect_err("unknown assertion reference must fail");
    assert_eq!(error.code, "E_ASSERTION_REFERENCE_UNKNOWN");

    let multiply_classified = synthetic_assertion(
        "synthetic.invalid",
        1,
        vec![allowed.id.clone()],
        vec![allowed.id.clone()],
    );
    let assertions = BTreeMap::from([
        (allowed.id.as_str(), &allowed),
        (multiply_classified.id.as_str(), &multiply_classified),
        (primary.id.as_str(), &primary),
        (suppressed.id.as_str(), &suppressed),
    ]);
    let error = validate_assertion_references(&assertions)
        .expect_err("allowed/suppressed overlap must fail");
    assert_eq!(error.code, "E_ASSERTION_REFERENCE_OVERLAP");

    let out_of_order = synthetic_assertion(
        "synthetic.invalid",
        1,
        vec![suppressed.id.clone(), allowed.id.clone()],
        Vec::new(),
    );
    let assertions = BTreeMap::from([
        (allowed.id.as_str(), &allowed),
        (out_of_order.id.as_str(), &out_of_order),
        (primary.id.as_str(), &primary),
        (suppressed.id.as_str(), &suppressed),
    ]);
    let error = validate_assertion_references(&assertions)
        .expect_err("noncanonical reference order must fail");
    assert_eq!(error.code, "E_ASSERTION_REFERENCE_ORDER");

    let duplicate = synthetic_assertion(
        "synthetic.invalid",
        1,
        vec![allowed.id.clone(), allowed.id.clone()],
        Vec::new(),
    );
    let assertions = BTreeMap::from([
        (allowed.id.as_str(), &allowed),
        (duplicate.id.as_str(), &duplicate),
        (primary.id.as_str(), &primary),
        (suppressed.id.as_str(), &suppressed),
    ]);
    let error = validate_assertion_references(&assertions)
        .expect_err("duplicate reference must fail");
    assert_eq!(error.code, "E_ASSERTION_REFERENCE_ORDER");
}

pub fn harness_main<I>(arguments: I) -> i32
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    let mut arguments = arguments.into_iter();
    if arguments.next().is_none() || arguments.next().is_some() {
        eprintln!("FND01_VERIFY|E_ARGUMENTS|ordinary verifier accepts no arguments");
        return 2;
    }
    match run_verifier() {
        Ok(report) => {
            let failed = report.has_errors();
            for diagnostic in report.sorted_stable() {
                eprintln!("{diagnostic}");
            }
            if failed {
                1
            } else {
                0
            }
        }
        Err(diagnostic) => {
            eprintln!("{}", diagnostic.stable());
            1
        }
    }
}
} // mod ordinary

#[cfg(fnd01_bootstrap)]
pub use bootstrap::harness_main;
#[cfg(not(fnd01_bootstrap))]
pub use ordinary::harness_main;

#[cfg(all(fnd01_bootstrap, not(test)))]
fn main() {
    std::process::exit(harness_main(std::env::args_os()));
}
