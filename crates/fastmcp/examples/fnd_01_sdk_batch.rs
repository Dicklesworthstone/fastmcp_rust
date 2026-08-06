//! Public runner for the frozen FND-01 cross-SDK execution batch.
//!
//! The runner executes only an opaque, verifier-prepared plan. The verifier
//! independently reopens its observations and is the sole component that can
//! admit the trusted production proof class.

#![forbid(unsafe_code)]

#[allow(dead_code, unused_imports)]
#[path = "../tests/fnd_01_dependency_evidence.rs"]
mod evidence;

#[cfg(not(fnd01_bootstrap))]
mod sdk_producer {
    use super::evidence;
    use asupersync::Cx;
    use asupersync::io::{AsyncReadExt, AsyncWriteExt};
    use asupersync::process::{
        Child, ChildStderr, ChildStdin, ChildStdout, Command, ProcessGroupMode,
        ProcessSignalTarget, Stdio,
    };
    use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
    use asupersync::time;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeSet;
    use std::ffi::OsStr;
    use std::fs;
    use std::future::Future;
    use std::io::Read;
    use std::path::{Path, PathBuf};
    use std::task::Poll;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    type Result<T> = std::result::Result<T, String>;

    const CHILD_STREAM_LIMIT: usize = 1_048_576;
    const CHILD_STREAM_READ_LIMIT: u64 = 1_048_577;
    const CHILD_FAILURE_TAIL_LIMIT: usize = 4_096;
    const CHILD_HEARTBEAT: Duration = Duration::from_millis(100);
    const CHILD_FAILURE_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
    const CHILD_CLEANUP_TIMEOUT: Duration = Duration::from_secs(30);

    struct Capture {
        exit_code: i64,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        started_at_epoch_seconds: u64,
        finished_at_epoch_seconds: u64,
        monotonic_started_ns: u64,
        monotonic_finished_ns: u64,
    }

    struct Tools {
        environment: Vec<(String, String)>,
        interpreter: evidence::SdkExecutableBinding,
        primary: evidence::SdkExecutableBinding,
        additional: Vec<evidence::SdkExecutableBinding>,
        identities: Vec<ToolFileIdentity>,
    }

    #[derive(Debug, Eq, PartialEq)]
    struct ToolFileIdentity {
        id: String,
        path: String,
        #[cfg(unix)]
        device: u64,
        #[cfg(unix)]
        inode: u64,
    }

    struct Outputs {
        paths: Vec<String>,
        digests: Vec<String>,
    }

    fn err(code: &str, subject: &str) -> String {
        format!("{code}: {subject}")
    }

    fn hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
        for &byte in bytes {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        encoded
    }

    fn sha256(bytes: &[u8]) -> String {
        hex(&Sha256::digest(bytes))
    }

    fn stream_tail(bytes: &[u8]) -> &[u8] {
        &bytes[bytes.len().saturating_sub(CHILD_FAILURE_TAIL_LIMIT)..]
    }

    fn failure_stream_detail(stdout: &[u8], stderr: &[u8]) -> String {
        format!(
            "stdout_captured_len={};stdout_captured_sha256={};stdout_captured_tail_hex={};stderr_captured_len={};stderr_captured_sha256={};stderr_captured_tail_hex={}",
            stdout.len(),
            sha256(stdout),
            hex(stream_tail(stdout)),
            stderr.len(),
            sha256(stderr),
            hex(stream_tail(stderr)),
        )
    }

    fn failure_with_streams(failure: String, stdout: &[u8], stderr: &[u8]) -> String {
        format!("{failure}; {}", failure_stream_detail(stdout, stderr))
    }

    fn retain_capture<T>(result: Result<T>, capture: &Capture) -> Result<T> {
        result.map_err(|failure| {
            failure_with_streams(failure, &capture.stdout, &capture.stderr)
        })
    }

    fn retain_capture_and_probe<T>(
        result: Result<T>,
        capture: &Capture,
        probe: &evidence::SdkNetworkProbeBinding,
    ) -> Result<T> {
        result.map_err(|failure| {
            format!(
                "{failure}; reproduction_{}; network_probe_{}",
                failure_stream_detail(&capture.stdout, &capture.stderr),
                failure_stream_detail(&probe.stdout.raw, &probe.stderr.raw),
            )
        })
    }

    fn merge_capture_validation(
        execution: Result<Capture>,
        validation: Result<()>,
    ) -> Result<Capture> {
        match (execution, validation) {
            (Ok(capture), Ok(())) => Ok(capture),
            (Ok(capture), Err(failure)) => Err(failure_with_streams(
                failure,
                &capture.stdout,
                &capture.stderr,
            )),
            (Err(failure), Ok(())) => Err(failure),
            (Err(failure), Err(validation_failure)) => {
                Err(format!("{failure}; {validation_failure}"))
            }
        }
    }

    fn merge_probe_validation(
        probe: Result<evidence::SdkNetworkProbeBinding>,
        validation: Result<()>,
    ) -> Result<evidence::SdkNetworkProbeBinding> {
        match (probe, validation) {
            (Ok(probe), Ok(())) => Ok(probe),
            (Ok(probe), Err(failure)) => Err(failure_with_streams(
                failure,
                &probe.stdout.raw,
                &probe.stderr.raw,
            )),
            (Err(failure), Ok(())) => Err(failure),
            (Err(failure), Err(validation_failure)) => {
                Err(format!("{failure}; {validation_failure}"))
            }
        }
    }

    fn read_bounded(path: &Path, limit: u64, subject: &str) -> Result<Vec<u8>> {
        let mut file = fs::File::open(path).map_err(|_| err("E_SDK_FILE", subject))?;
        let mut bytes = Vec::new();
        file.by_ref()
            .take(limit.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| err("E_SDK_FILE", subject))?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
            return Err(err("E_SDK_FILE_BOUND", subject));
        }
        Ok(bytes)
    }

    fn canonical_utf8(path: &Path, subject: &str) -> Result<String> {
        let canonical = fs::canonicalize(path).map_err(|_| err("E_SDK_PATH", subject))?;
        let value = canonical
            .to_str()
            .ok_or_else(|| err("E_SDK_PATH", subject))?;
        if !value.starts_with('/')
            || value == "/"
            || value.ends_with('/')
            || value.contains("//")
            || value.contains("/./")
            || value.contains("/../")
            || value.as_bytes().iter().any(|byte| byte.is_ascii_control())
        {
            return Err(err("E_SDK_PATH", subject));
        }
        Ok(value.to_owned())
    }

    fn executable(
        id: &str,
        path: &Path,
        version: &str,
        subject: &str,
    ) -> Result<evidence::SdkExecutableBinding> {
        if id.is_empty() || version.is_empty() {
            return Err(err("E_SDK_TOOL", subject));
        }
        let path = canonical_utf8(path, subject)?;
        let bytes = read_bounded(Path::new(&path), 268_435_456, subject)?;
        Ok(evidence::SdkExecutableBinding {
            id: id.to_owned(),
            path,
            byte_length: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            sha256: sha256(&bytes),
            version: version.to_owned(),
        })
    }

    fn exact_executable(
        id: &str,
        path: &Path,
        version: &str,
        subject: &str,
    ) -> Result<evidence::SdkExecutableBinding> {
        let lexical = path
            .to_str()
            .ok_or_else(|| err("E_SDK_TOOL_IDENTITY", subject))?;
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| err("E_SDK_TOOL_IDENTITY", subject))?;
        if metadata.file_type().is_symlink()
            || !is_executable_file(&metadata)
            || canonical_utf8(path, subject)? != lexical
        {
            return Err(err("E_SDK_TOOL_IDENTITY", subject));
        }
        executable(id, path, version, subject)
    }

    fn transcript(raw: Vec<u8>, subject: &str) -> Result<evidence::SdkTranscriptBinding> {
        if raw.len() > 1_048_576 || raw.contains(&0) || std::str::from_utf8(&raw).is_err() {
            return Err(err("E_SDK_CHILD_STREAM", subject));
        }
        Ok(evidence::SdkTranscriptBinding {
            byte_length: u64::try_from(raw.len()).unwrap_or(u64::MAX),
            sha256: sha256(&raw),
            raw,
        })
    }

    fn required_environment(name: &str, subject: &str) -> Result<String> {
        let value = std::env::var(name).map_err(|_| err("E_SDK_RUNNER_CONFIGURATION", name))?;
        if value.is_empty()
            || value.len() > 4096
            || value.as_bytes().contains(&0)
            || value.chars().any(char::is_control)
        {
            return Err(err("E_SDK_RUNNER_CONFIGURATION", subject));
        }
        Ok(value)
    }

    fn configured_tool(
        name: &str,
        id: &str,
        version: &str,
    ) -> Result<evidence::SdkExecutableBinding> {
        let path = required_environment(name, "SDK configured tool")?;
        if !Path::new(&path).is_absolute() {
            return Err(err("E_SDK_RUNNER_CONFIGURATION", name));
        }
        executable(id, Path::new(&path), version, name)
    }

    fn system_tool(id: &str) -> Result<evidence::SdkExecutableBinding> {
        let path = match id {
            "awk" => "/usr/bin/awk",
            "basename" => "/usr/bin/basename",
            "cmp" => "/usr/bin/cmp",
            "curl" => "/usr/bin/curl",
            "env" => "/usr/bin/env",
            "find" => "/usr/bin/find",
            "install" => "/usr/bin/install",
            "mktemp" => "/usr/bin/mktemp",
            "perl" => "/usr/bin/perl",
            "sandbox-exec" => "/usr/bin/sandbox-exec",
            "sed" => "/usr/bin/sed",
            "shasum" => "/usr/bin/shasum",
            "sort" => "/usr/bin/sort",
            _ => return Err(err("E_SDK_RUNNER_CONFIGURATION", id)),
        };
        executable(id, Path::new(path), "system", id)
    }

    fn configured_directory(name: &str, subject: &str) -> Result<String> {
        let configured = required_environment(name, subject)?;
        if configured.ends_with('/')
            || configured.ends_with("/.")
            || configured.ends_with("/..")
        {
            return Err(err("E_SDK_RUNNER_CONFIGURATION", subject));
        }
        let path = Path::new(&configured);
        if !path.is_absolute() {
            return Err(err("E_SDK_RUNNER_CONFIGURATION", name));
        }
        let configured_metadata = fs::symlink_metadata(path)
            .map_err(|_| err("E_SDK_RUNNER_CONFIGURATION", subject))?;
        if configured_metadata.file_type().is_symlink() {
            return Err(err("E_SDK_RUNNER_CONFIGURATION", subject));
        }
        let canonical = canonical_utf8(path, subject)?;
        let metadata = fs::symlink_metadata(&canonical)
            .map_err(|_| err("E_SDK_RUNNER_CONFIGURATION", subject))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(err("E_SDK_RUNNER_CONFIGURATION", subject));
        }
        Ok(canonical)
    }

    fn directory_has_no_write_bits(metadata: &fs::Metadata) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode() & 0o222 == 0
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            false
        }
    }

    fn same_directory_identity(before: &fs::Metadata, after: &fs::Metadata) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            before.dev() == after.dev() && before.ino() == after.ino()
        }
        #[cfg(not(unix))]
        {
            let _ = (before, after);
            false
        }
    }

    fn configured_home() -> Result<String> {
        let configured = required_environment("FND01_SDK_HOME", "home")?;
        let canonical = configured_directory("FND01_SDK_HOME", "home")?;
        if configured != canonical {
            return Err(err("E_SDK_RUNNER_CONFIGURATION", "home"));
        }
        let before = fs::symlink_metadata(&canonical)
            .map_err(|_| err("E_SDK_RUNNER_CONFIGURATION", "home"))?;
        if !before.is_dir()
            || before.file_type().is_symlink()
            || !directory_has_no_write_bits(&before)
        {
            return Err(err("E_SDK_RUNNER_CONFIGURATION", "home"));
        }
        if fs::read_dir(&canonical)
            .map_err(|_| err("E_SDK_RUNNER_CONFIGURATION", "home"))?
            .next()
            .is_some()
        {
            return Err(err("E_SDK_RUNNER_CONFIGURATION", "home"));
        }
        let after = fs::symlink_metadata(&canonical)
            .map_err(|_| err("E_SDK_RUNNER_CONFIGURATION", "home"))?;
        if !after.is_dir()
            || after.file_type().is_symlink()
            || !directory_has_no_write_bits(&after)
            || !same_directory_identity(&before, &after)
        {
            return Err(err("E_SDK_RUNNER_CONFIGURATION", "home"));
        }
        Ok(canonical)
    }

    fn validate_observed_home(environment: &[(String, String)], subject: &str) -> Result<()> {
        let configured = configured_home()?;
        let observed = environment
            .iter()
            .find(|(name, _)| name == "HOME")
            .map(|(_, value)| value)
            .ok_or_else(|| err("E_SDK_CHILD_CONTRACT", subject))?;
        if observed != &configured {
            return Err(err("E_SDK_CHILD_CONTRACT", subject));
        }
        Ok(())
    }

    fn append_post_home_failure(
        environment: &[(String, String)],
        subject: &str,
        failure: String,
    ) -> String {
        match validate_observed_home(environment, subject) {
            Ok(()) => failure,
            Err(home_failure) => format!("{failure}; {home_failure}"),
        }
    }

    fn configured_parent(name: &str) -> Result<PathBuf> {
        let configured = required_environment(name, name)?;
        let path = Path::new(&configured);
        if !path.is_absolute() {
            return Err(err("E_SDK_RUNNER_CONFIGURATION", name));
        }
        let parent = path
            .parent()
            .ok_or_else(|| err("E_SDK_RUNNER_CONFIGURATION", name))?;
        Ok(PathBuf::from(canonical_utf8(parent, name)?))
    }

    fn push_unique_path(paths: &mut Vec<PathBuf>, path: PathBuf) {
        if !paths.contains(&path) {
            paths.push(path);
        }
    }

    fn is_executable_file(metadata: &fs::Metadata) -> bool {
        if !metadata.is_file() {
            return false;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode() & 0o111 != 0
        }
        #[cfg(not(unix))]
        {
            true
        }
    }

    fn resolve_path_program(paths: &[PathBuf], program: &str) -> Result<String> {
        if program.is_empty()
            || program.contains('/')
            || program.as_bytes().iter().any(|byte| byte.is_ascii_control())
        {
            return Err(err("E_SDK_RUNNER_CONFIGURATION", "PATH program"));
        }
        for directory in paths {
            let candidate = directory.join(program);
            if fs::metadata(&candidate).is_ok_and(|metadata| is_executable_file(&metadata)) {
                return canonical_utf8(&candidate, program);
            }
        }
        Err(err("E_SDK_RUNNER_CONFIGURATION", program))
    }

    fn path_program(tool_id: &str) -> Result<Option<&'static str>> {
        let program = match tool_id {
            "node" => Some("node"),
            "npm" => Some("npm"),
            "python" => Some("python3"),
            "jq" => Some("jq"),
            "awk" => Some("awk"),
            "basename" => Some("basename"),
            "cmp" => Some("cmp"),
            "env" => Some("env"),
            "find" => Some("find"),
            "install" => Some("install"),
            "mktemp" => Some("mktemp"),
            "perl" => Some("perl"),
            "shasum" => Some("shasum"),
            "sandbox-exec" => Some("sandbox-exec"),
            "sed" => Some("sed"),
            "sort" => Some("sort"),
            "curl" => Some("curl"),
            "dotnet" | "go" => None,
            _ => return Err(err("E_SDK_RUNNER_CONFIGURATION", tool_id)),
        };
        Ok(program)
    }

    fn validate_path_tool_bindings(
        paths: &[PathBuf],
        primary: &evidence::SdkExecutableBinding,
        additional: &[evidence::SdkExecutableBinding],
    ) -> Result<()> {
        for tool in std::iter::once(primary).chain(additional) {
            let Some(program) = path_program(&tool.id)? else {
                continue;
            };
            if resolve_path_program(paths, program)? != tool.path {
                return Err(err("E_SDK_RUNNER_CONFIGURATION", &tool.id));
            }
        }
        Ok(())
    }

    fn tool_file_identity(
        binding: &evidence::SdkExecutableBinding,
        subject: &str,
    ) -> Result<ToolFileIdentity> {
        let metadata = fs::symlink_metadata(&binding.path)
            .map_err(|_| err("E_SDK_TOOL_IDENTITY", subject))?;
        if metadata.file_type().is_symlink()
            || !is_executable_file(&metadata)
            || metadata.len() != binding.byte_length
        {
            return Err(err("E_SDK_TOOL_IDENTITY", subject));
        }
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        Ok(ToolFileIdentity {
            id: binding.id.clone(),
            path: binding.path.clone(),
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
        })
    }

    fn validate_tool_surface(tools: &Tools, subject: &str) -> Result<()> {
        let mut identities = tools.identities.iter();
        for binding in std::iter::once(&tools.interpreter)
            .chain(std::iter::once(&tools.primary))
            .chain(&tools.additional)
        {
            let expected_identity = identities
                .next()
                .ok_or_else(|| err("E_SDK_TOOL_IDENTITY", subject))?;
            let observed_binding = executable(
                &binding.id,
                Path::new(&binding.path),
                &binding.version,
                subject,
            )
            .map_err(|_| err("E_SDK_TOOL_IDENTITY", &binding.id))?;
            let observed_identity = tool_file_identity(&observed_binding, subject)?;
            if &observed_binding != binding || &observed_identity != expected_identity {
                return Err(err("E_SDK_TOOL_IDENTITY", &binding.id));
            }
        }
        if identities.next().is_some() {
            return Err(err("E_SDK_TOOL_IDENTITY", subject));
        }

        let mut path_values = tools
            .environment
            .iter()
            .filter(|(name, _)| name == "PATH")
            .map(|(_, value)| value);
        let path = path_values
            .next()
            .ok_or_else(|| err("E_SDK_TOOL_IDENTITY", "PATH"))?;
        if path_values.next().is_some() {
            return Err(err("E_SDK_TOOL_IDENTITY", "PATH"));
        }
        let path_directories = std::env::split_paths(OsStr::new(path)).collect::<Vec<_>>();
        if path_directories.is_empty()
            || path_directories
                .iter()
                .any(|directory| !directory.is_absolute())
        {
            return Err(err("E_SDK_TOOL_IDENTITY", "PATH"));
        }
        validate_path_tool_bindings(&path_directories, &tools.primary, &tools.additional)
            .map_err(|_| err("E_SDK_TOOL_IDENTITY", "PATH"))
    }

    fn tool_identity_digest(tools: &Tools, subject: &str) -> Result<String> {
        let bindings = std::iter::once(&tools.interpreter)
            .chain(std::iter::once(&tools.primary))
            .chain(&tools.additional);
        if tools.identities.len() != 2usize.saturating_add(tools.additional.len()) {
            return Err(err("E_SDK_TOOL_IDENTITY", subject));
        }
        let mut values = Vec::with_capacity(
            1usize.saturating_add(tools.identities.len().saturating_mul(8)),
        );
        values.push(tools.identities.len().to_string());
        for (binding, expected_identity) in bindings.zip(&tools.identities) {
            let observed_binding = executable(
                &binding.id,
                Path::new(&binding.path),
                &binding.version,
                subject,
            )
            .map_err(|_| err("E_SDK_TOOL_IDENTITY", &binding.id))?;
            let identity = tool_file_identity(&observed_binding, subject)?;
            if &observed_binding != binding || &identity != expected_identity {
                return Err(err("E_SDK_TOOL_IDENTITY", &binding.id));
            }
            values.extend([
                observed_binding.id,
                observed_binding.path,
                observed_binding.byte_length.to_string(),
                observed_binding.sha256,
                observed_binding.version,
            ]);
            #[cfg(unix)]
            values.extend([
                "unix-device-inode".to_owned(),
                identity.device.to_string(),
                identity.inode.to_string(),
            ]);
            #[cfg(not(unix))]
            values.push("identity-unavailable".to_owned());
        }
        Ok(evidence::sdk_sequence_sha256(
            b"FND01SDKTOOLIDENTITYv1\0",
            &values,
        ))
    }

    fn validate_tool_identity_temporal_binding(
        before: &str,
        after: &str,
        subject: &str,
    ) -> Result<()> {
        if before == after
            && before.bytes().any(|byte| byte != b'0')
            && after.bytes().any(|byte| byte != b'0')
        {
            Ok(())
        } else {
            Err(err("E_SDK_TOOL_IDENTITY", subject))
        }
    }

    fn validate_executable_binding(
        binding: &evidence::SdkExecutableBinding,
        subject: &str,
    ) -> Result<()> {
        let observed = executable(
            &binding.id,
            Path::new(&binding.path),
            &binding.version,
            subject,
        )
        .map_err(|_| err("E_SDK_TOOL_IDENTITY", subject))?;
        if &observed != binding {
            return Err(err("E_SDK_TOOL_IDENTITY", &binding.id));
        }
        Ok(())
    }

    fn epoch_seconds(subject: &str) -> Result<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_secs())
            .map_err(|_| err("E_SDK_CLOCK", subject))
    }

    async fn exchange_child_streams(
        cx: &Cx,
        mut stdin: ChildStdin,
        stdout: ChildStdout,
        stderr: ChildStderr,
        stdin_bytes: &[u8],
        subject: &str,
        stdout_capture: &mut Vec<u8>,
        stderr_capture: &mut Vec<u8>,
    ) -> Result<()> {
        let mut stdin_future = Box::pin(async move {
            stdin.write_all(stdin_bytes).await?;
            stdin.shutdown().await
        });
        let mut stdout_future = Box::pin(async move {
            let mut bounded = stdout.take(CHILD_STREAM_READ_LIMIT);
            bounded.read_to_end(stdout_capture).await
        });
        let mut stderr_future = Box::pin(async move {
            let mut bounded = stderr.take(CHILD_STREAM_READ_LIMIT);
            bounded.read_to_end(stderr_capture).await
        });
        let mut stdin_done = false;
        let mut stdout_done = None;
        let mut stderr_done = None;
        let mut heartbeat = Box::pin(time::sleep(cx.now(), CHILD_HEARTBEAT));
        let mut first_failure = None;
        let mut failure_drain = None;

        std::future::poll_fn(|task| {
            {
                let mut latch_failure = |failure: String| {
                    if first_failure.is_none() {
                        first_failure = Some(failure);
                        failure_drain = Some(Box::pin(time::sleep(
                            cx.now(),
                            CHILD_FAILURE_DRAIN_TIMEOUT,
                        )));
                    }
                };

                if cx.checkpoint().is_err() {
                    stdin_done = true;
                    latch_failure(err("E_SDK_CHILD_CANCELLED", subject));
                }

                if !stdin_done {
                    match stdin_future.as_mut().poll(task) {
                        Poll::Ready(Ok(())) => stdin_done = true,
                        Poll::Ready(Err(_)) => {
                            stdin_done = true;
                            latch_failure(err("E_SDK_CHILD_STREAM", "stdin write"));
                        }
                        Poll::Pending => {}
                    }
                }
                if stdout_done.is_none() {
                    match stdout_future.as_mut().poll(task) {
                        Poll::Ready(Ok(length)) => {
                            stdout_done = Some(length);
                            if length > CHILD_STREAM_LIMIT {
                                latch_failure(err(
                                    "E_SDK_CHILD_STREAM",
                                    "stdout bound exceeded",
                                ));
                            }
                        }
                        Poll::Ready(Err(_)) => {
                            stdout_done = Some(0);
                            latch_failure(err("E_SDK_CHILD_STREAM", "stdout"));
                        }
                        Poll::Pending => {}
                    }
                }
                if stderr_done.is_none() {
                    match stderr_future.as_mut().poll(task) {
                        Poll::Ready(Ok(length)) => {
                            stderr_done = Some(length);
                            if length > CHILD_STREAM_LIMIT {
                                latch_failure(err(
                                    "E_SDK_CHILD_STREAM",
                                    "stderr bound exceeded",
                                ));
                            }
                        }
                        Poll::Ready(Err(_)) => {
                            stderr_done = Some(0);
                            latch_failure(err("E_SDK_CHILD_STREAM", "stderr"));
                        }
                        Poll::Pending => {}
                    }
                }
                if first_failure.is_some() {
                    stdin_done = true;
                }
            }

            if stdout_done.is_some() && stderr_done.is_some() && stdin_done {
                return Poll::Ready(match first_failure.take() {
                    Some(failure) => Err(failure),
                    None => Ok(()),
                });
            }
            if let Some(deadline) = failure_drain.as_mut()
                && deadline.as_mut().poll(task).is_ready()
            {
                return Poll::Ready(Err(first_failure
                    .take()
                    .unwrap_or_else(|| err("E_SDK_CHILD_STREAM", subject))));
            }

            if heartbeat.as_mut().poll(task).is_ready() {
                heartbeat
                    .as_mut()
                    .get_mut()
                    .reset_after(cx.now(), CHILD_HEARTBEAT);
                task.waker().wake_by_ref();
            }
            Poll::Pending
        })
        .await
    }

    async fn cleanup_child(cx: &Cx, child: &mut Child, subject: &str) -> Result<()> {
        if child.id().is_none() {
            return Ok(());
        }
        let _ = child.kill();
        let cleanup_origin = cx.now();
        let _ = time::timeout(cleanup_origin, CHILD_CLEANUP_TIMEOUT, child.wait_async(cx)).await;
        if child.id().is_none() {
            Ok(())
        } else {
            Err(err("E_SDK_CHILD_REAP", subject))
        }
    }

    async fn fail_after_cleanup(
        cx: &Cx,
        child: &mut Child,
        subject: &str,
        failure: String,
    ) -> String {
        match cleanup_child(cx, child, subject).await {
            Ok(()) => failure,
            Err(cleanup) => format!("{failure}; {cleanup}"),
        }
    }

    async fn execute_bounded(
        cx: &Cx,
        argv: &[String],
        environment: &[(String, String)],
        root: &Path,
        stdin_bytes: &[u8],
        timeout: Duration,
        batch_clock: Instant,
        subject: &str,
    ) -> Result<Capture> {
        if argv.is_empty()
            || !Path::new(&argv[0]).is_absolute()
            || argv.len() > 32
            || timeout.is_zero()
            || environment.len() > 64
            || environment.windows(2).any(|window| window[0].0 >= window[1].0)
        {
            return Err(err("E_SDK_CHILD_CONTRACT", subject));
        }
        validate_observed_home(environment, subject)?;
        cx.checkpoint()
            .map_err(|_| err("E_SDK_CHILD_CANCELLED", subject))?;
        let timeout_origin = cx.now();
        let started_at_epoch_seconds = epoch_seconds(subject)?;
        let monotonic_started_ns =
            u64::try_from(batch_clock.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let mut command = Command::new(&argv[0]);
        command
            .args(&argv[1..])
            .env_clear()
            .envs(
                environment
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_str())),
            )
            .current_dir(root)
            .stdin(Stdio::Pipe)
            .stdout(Stdio::Pipe)
            .stderr(Stdio::Pipe)
            .kill_on_drop(true)
            .process_group_mode(ProcessGroupMode::NewProcessGroup)
            .signal_target(ProcessSignalTarget::ProcessGroup);
        let mut child = command
            .spawn()
            .map_err(|_| err("E_SDK_CHILD_SPAWN", subject))?;
        let pipes = (child.stdin(), child.stdout(), child.stderr());
        let (stdin, stdout, stderr) = match pipes {
            (Some(stdin), Some(stdout), Some(stderr)) => (stdin, stdout, stderr),
            _ => {
                let failure = err("E_SDK_CHILD_SPAWN", "stdio");
                let failure = fail_after_cleanup(cx, &mut child, subject, failure).await;
                return Err(append_post_home_failure(environment, subject, failure));
            }
        };
        let mut stdout_capture = Vec::new();
        let mut stderr_capture = Vec::new();
        let outcome = {
            let communication = async {
                // Keep the child handle unreaped while draining. A descendant may
                // inherit a pipe, and the managed group must remain signalable if
                // that pipe outlives the direct child.
                exchange_child_streams(
                    cx,
                    stdin,
                    stdout,
                    stderr,
                    stdin_bytes,
                    subject,
                    &mut stdout_capture,
                    &mut stderr_capture,
                )
                .await?;
                let status = child
                    .wait_async(cx)
                    .await
                    .map_err(|_| err("E_SDK_CHILD_WAIT", subject))?;
                Ok::<_, String>(status)
            };
            time::timeout(timeout_origin, timeout, communication).await
        };
        let status = match outcome {
            Ok(Ok(value)) => value,
            Ok(Err(failure)) => {
                let failure = failure_with_streams(failure, &stdout_capture, &stderr_capture);
                let failure = fail_after_cleanup(cx, &mut child, subject, failure).await;
                return Err(append_post_home_failure(environment, subject, failure));
            }
            Err(_) => {
                // Dropping the timed future above closes all pipe handles before
                // the configured process group is killed and the leader reaped.
                let failure = failure_with_streams(
                    err("E_SDK_CHILD_DEADLINE", subject),
                    &stdout_capture,
                    &stderr_capture,
                );
                let failure = fail_after_cleanup(cx, &mut child, subject, failure).await;
                return Err(append_post_home_failure(environment, subject, failure));
            }
        };
        let exit_code = match status.code() {
            Some(code) => i64::from(code),
            None => {
                let failure = failure_with_streams(
                    err("E_SDK_CHILD_WAIT", "signal"),
                    &stdout_capture,
                    &stderr_capture,
                );
                return Err(append_post_home_failure(environment, subject, failure));
            }
        };
        let finished_at_epoch_seconds = match epoch_seconds(subject) {
            Ok(value) => value,
            Err(failure) => {
                let failure = failure_with_streams(
                    failure,
                    &stdout_capture,
                    &stderr_capture,
                );
                return Err(append_post_home_failure(environment, subject, failure));
            }
        };
        validate_observed_home(environment, subject).map_err(|failure| {
            failure_with_streams(failure, &stdout_capture, &stderr_capture)
        })?;
        Ok(Capture {
            exit_code,
            stdout: stdout_capture,
            stderr: stderr_capture,
            started_at_epoch_seconds,
            finished_at_epoch_seconds,
            monotonic_started_ns,
            monotonic_finished_ns: u64::try_from(batch_clock.elapsed().as_nanos())
                .unwrap_or(u64::MAX),
        })
    }

    fn tool_surface(sdk_id: &str) -> Result<Tools> {
        if !cfg!(all(target_os = "macos", target_arch = "aarch64")) {
            return Err(err(
                "E_SDK_RUNNER_PLATFORM",
                "requires aarch64 macOS sandbox-exec evidence host",
            ));
        }
        let interpreter = exact_executable("zsh", Path::new("/bin/zsh"), "system", "zsh")?;
        let (primary, mut additional, configured_path_order, sdk_environment): (
            _,
            _,
            &[&str],
            Vec<(String, String)>,
        ) = match sdk_id {
            "typescript" => (
                configured_tool("FND01_SDK_NPM", "npm", "11.14.0")?,
                vec![
                    system_tool("awk")?,
                    system_tool("cmp")?,
                    system_tool("curl")?,
                    system_tool("env")?,
                    system_tool("install")?,
                    configured_tool("FND01_SDK_JQ", "jq", "byte-bound")?,
                    system_tool("mktemp")?,
                    configured_tool("FND01_SDK_NODE", "node", "v24.12.0")?,
                    system_tool("perl")?,
                    system_tool("sandbox-exec")?,
                    system_tool("shasum")?,
                ],
                &["FND01_SDK_NPM", "FND01_SDK_NODE", "FND01_SDK_JQ"],
                vec![
                    ("NPM_CONFIG_GLOBALCONFIG".to_owned(), "/dev/null".to_owned()),
                    ("NPM_CONFIG_USERCONFIG".to_owned(), "/dev/null".to_owned()),
                ],
            ),
            "python" => (
                configured_tool("FND01_SDK_PYTHON3", "python", "Python 3.14.4")?,
                vec![
                    system_tool("awk")?,
                    system_tool("basename")?,
                    system_tool("cmp")?,
                    system_tool("curl")?,
                    system_tool("find")?,
                    system_tool("install")?,
                    system_tool("mktemp")?,
                    system_tool("perl")?,
                    system_tool("sandbox-exec")?,
                    system_tool("sed")?,
                    system_tool("shasum")?,
                    system_tool("sort")?,
                ],
                &["FND01_SDK_PYTHON3"],
                vec![
                    ("PIP_CONFIG_FILE".to_owned(), "/dev/null".to_owned()),
                    ("PYTHONNOUSERSITE".to_owned(), "1".to_owned()),
                ],
            ),
            "csharp" => {
                let dotnet_root = configured_directory("DOTNET_SDK", "dotnet root")?;
                let dotnet_archive = canonical_utf8(
                    Path::new(&required_environment("DOTNET_ARCHIVE", "dotnet archive")?),
                    "dotnet archive",
                )?;
                (
                    exact_executable(
                        "dotnet",
                        &Path::new(&dotnet_root).join("dotnet"),
                        "10.0.100",
                        "dotnet",
                    )?,
                    vec![
                        system_tool("awk")?,
                        system_tool("cmp")?,
                        system_tool("curl")?,
                        system_tool("env")?,
                        system_tool("install")?,
                        configured_tool("FND01_SDK_JQ", "jq", "byte-bound")?,
                        system_tool("mktemp")?,
                        system_tool("perl")?,
                        system_tool("sandbox-exec")?,
                        system_tool("shasum")?,
                    ],
                    &["FND01_SDK_JQ"],
                    vec![
                        ("DOTNET_ARCHIVE".to_owned(), dotnet_archive),
                        ("DOTNET_ROOT".to_owned(), dotnet_root.clone()),
                        ("DOTNET_SDK".to_owned(), dotnet_root),
                    ],
                )
            }
            "go" => {
                let go_root = configured_directory("GO_1_25", "go root")?;
                (
                    exact_executable(
                        "go",
                        &Path::new(&go_root).join("bin/go"),
                        "go version go1.25.0 darwin/arm64",
                        "go",
                    )?,
                    vec![
                        system_tool("awk")?,
                        system_tool("cmp")?,
                        system_tool("curl")?,
                        system_tool("env")?,
                        system_tool("install")?,
                        configured_tool("FND01_SDK_JQ", "jq", "byte-bound")?,
                        system_tool("mktemp")?,
                        system_tool("perl")?,
                        system_tool("sandbox-exec")?,
                        system_tool("shasum")?,
                        system_tool("sort")?,
                    ],
                    &["FND01_SDK_JQ"],
                    vec![
                        ("GOENV".to_owned(), "off".to_owned()),
                        ("GOROOT".to_owned(), go_root.clone()),
                        ("GO_1_25".to_owned(), go_root),
                    ],
                )
            }
            _ => return Err(err("E_SDK_RUNNER_CONFIGURATION", sdk_id)),
        };
        additional.sort_unstable_by(|left, right| left.id.cmp(&right.id));
        if additional.windows(2).any(|window| window[0].id == window[1].id) {
            return Err(err("E_SDK_RUNNER_CONFIGURATION", "duplicate tool"));
        }
        let mut path_directories = Vec::new();
        for name in configured_path_order {
            push_unique_path(&mut path_directories, configured_parent(name)?);
        }
        for directory in [PathBuf::from("/usr/bin"), PathBuf::from("/bin")] {
            push_unique_path(&mut path_directories, directory);
        }
        validate_path_tool_bindings(&path_directories, &primary, &additional)?;
        let path = std::env::join_paths(&path_directories)
            .map_err(|_| err("E_SDK_RUNNER_CONFIGURATION", "PATH"))?
            .into_string()
            .map_err(|_| err("E_SDK_RUNNER_CONFIGURATION", "PATH"))?;
        let home = configured_home()?;
        let mut environment = vec![
            ("HOME".to_owned(), home),
            ("LANG".to_owned(), "C".to_owned()),
            ("LC_ALL".to_owned(), "C".to_owned()),
            ("NO_COLOR".to_owned(), "1".to_owned()),
            ("PATH".to_owned(), path),
            ("TMPDIR".to_owned(), "/tmp".to_owned()),
        ];
        environment.extend(sdk_environment);
        environment.sort_unstable();
        let identities = std::iter::once(&interpreter)
            .chain(std::iter::once(&primary))
            .chain(&additional)
            .map(|binding| tool_file_identity(binding, &binding.id))
            .collect::<Result<Vec<_>>>()?;
        Ok(Tools {
            environment,
            interpreter,
            primary,
            additional,
            identities,
        })
    }

    fn tmp_prefixes(sdk_id: &str) -> Result<&'static [&'static str]> {
        match sdk_id {
            "typescript" => Ok(&[
                "fastmcp-fnd01-ts-proof-cache.",
                "fastmcp-fnd01-ts-proof-online.",
                "fastmcp-fnd01-ts-proof-offline.",
            ]),
            "python" => Ok(&[
                "fastmcp-fnd01-python-proof-stage.",
                "fastmcp-fnd01-python-proof-online.",
                "fastmcp-fnd01-python-proof-offline.",
            ]),
            "csharp" => Ok(&[
                "fastmcp-fnd01-csharp-proof-cache.",
                "fastmcp-fnd01-csharp-proof-online.",
                "fastmcp-fnd01-csharp-proof-offline.",
                "fastmcp-fnd01-csharp-proof-empty.",
                "fastmcp-fnd01-csharp-proof-home.",
            ]),
            "go" => Ok(&[
                "fastmcp-fnd01-go-proof-mod-cache.",
                "fastmcp-fnd01-go-proof-build-cache.",
                "fastmcp-fnd01-go-proof-online.",
                "fastmcp-fnd01-go-proof-offline.",
            ]),
            _ => Err(err("E_SDK_RUNTIME_PATH", sdk_id)),
        }
    }

    fn tmp_snapshot(sdk_id: &str) -> Result<BTreeSet<String>> {
        let prefixes = tmp_prefixes(sdk_id)?;
        let mut paths = BTreeSet::new();
        for entry in fs::read_dir("/tmp").map_err(|_| err("E_SDK_RUNTIME_PATH", sdk_id))? {
            let entry = entry.map_err(|_| err("E_SDK_RUNTIME_PATH", sdk_id))?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| err("E_SDK_RUNTIME_PATH", "UTF-8"))?;
            if prefixes.iter().any(|prefix| name.starts_with(prefix)) {
                let metadata = fs::symlink_metadata(entry.path())
                    .map_err(|_| err("E_SDK_RUNTIME_PATH", sdk_id))?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(err("E_SDK_RUNTIME_PATH", &name));
                }
                paths.insert(canonical_utf8(&entry.path(), sdk_id)?);
            }
        }
        Ok(paths)
    }

    fn runtime_paths(
        sdk_id: &str,
        before: &BTreeSet<String>,
        after: &BTreeSet<String>,
    ) -> Result<Vec<String>> {
        let paths = after.difference(before).cloned().collect::<Vec<_>>();
        let prefixes = tmp_prefixes(sdk_id)?;
        if paths.len() != prefixes.len()
            || prefixes.iter().any(|prefix| {
                paths.iter().filter(|path| {
                    Path::new(path)
                        .file_name()
                        .and_then(OsStr::to_str)
                        .is_some_and(|name| name.starts_with(prefix))
                }).count() != 1
            })
        {
            return Err(err("E_SDK_RUNTIME_PATH", "exact created set"));
        }
        Ok(paths)
    }

    fn runtime_directory<'a>(paths: &'a [String], marker: &str) -> Result<&'a Path> {
        let matches = paths
            .iter()
            .filter(|path| {
                Path::new(path)
                    .file_name()
                    .and_then(OsStr::to_str)
                    .is_some_and(|name| name.contains(marker))
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(err("E_SDK_RUNTIME_PATH", marker));
        }
        Ok(Path::new(matches[0]))
    }

    fn observed_outputs(sdk_id: &str, paths: &[String]) -> Result<Outputs> {
        let online = runtime_directory(paths, "-online.")?;
        let offline = runtime_directory(paths, "-offline.")?;
        let raw_paths = match sdk_id {
            "typescript" => vec![
                online.join("closure.json"),
                offline.join("closure.json"),
                online.join("closure.json"),
                offline.join("closure.json"),
                offline.join("package-lock.json"),
            ],
            "python" => {
                let stage = runtime_directory(paths, "-stage.")?;
                vec![
                    online.join("closure.sha256"),
                    offline.join("closure.sha256"),
                    online.join("closure-filenames.txt"),
                    offline.join("closure-filenames.txt"),
                    stage.join("requirements.lock"),
                ]
            }
            "csharp" => vec![
                online.join("project-assets-closure.json"),
                offline.join("project-assets-closure.json"),
                online.join("generated-lock.canonical.json"),
                online.join("expected-lock.canonical.json"),
                offline.join("packages.lock.json"),
            ],
            "go" => vec![
                online.join("modules.sorted.txt"),
                offline.join("modules.sorted.txt"),
                online.join("modules.lock.json"),
                offline.join("modules.lock.json"),
                offline.join("go.sum"),
            ],
            _ => return Err(err("E_SDK_EXECUTION_FACTS", sdk_id)),
        };
        let mut output_paths = Vec::with_capacity(raw_paths.len());
        let mut digests = Vec::with_capacity(raw_paths.len());
        for path in raw_paths {
            let canonical = canonical_utf8(&path, sdk_id)?;
            digests.push(sha256(&read_bounded(Path::new(&canonical), 16_777_216, sdk_id)?));
            output_paths.push(canonical);
        }
        Ok(Outputs {
            paths: output_paths,
            digests,
        })
    }

    async fn network_probe(
        cx: &Cx,
        sdk_id: &str,
        environment: &[(String, String)],
        root: &Path,
        batch_clock: Instant,
        launcher: &evidence::SdkExecutableBinding,
        target_tool: &evidence::SdkExecutableBinding,
    ) -> Result<evidence::SdkNetworkProbeBinding> {
        validate_executable_binding(launcher, "network launcher")?;
        validate_executable_binding(target_tool, "network target")?;
        let url = match sdk_id {
            "typescript" => "https://registry.npmjs.org/",
            "python" => "https://pypi.org/",
            "csharp" => "https://api.nuget.org/v3/index.json",
            "go" => "https://proxy.golang.org/",
            _ => return Err(err("E_SDK_NETWORK_PROBE", sdk_id)),
        };
        let argv = vec![
            launcher.path.clone(),
            "-p".to_owned(),
            "(version 1) (allow default) (deny network*)".to_owned(),
            target_tool.path.clone(),
            "--silent".to_owned(),
            "--show-error".to_owned(),
            "--max-time".to_owned(),
            "2".to_owned(),
            url.to_owned(),
        ];
        let execution = execute_bounded(
            cx,
            &argv,
            environment,
            root,
            &[],
            Duration::from_secs(10),
            batch_clock,
            "network denial probe",
        )
        .await;
        let post_validation = validate_executable_binding(launcher, "network launcher")
            .and_then(|()| validate_executable_binding(target_tool, "network target"));
        let capture = merge_capture_validation(execution, post_validation)?;
        let cwd = retain_capture(canonical_utf8(root, sdk_id), &capture)?;
        let elapsed_ns = retain_capture(
            capture
                .monotonic_finished_ns
                .checked_sub(capture.monotonic_started_ns)
                .ok_or_else(|| err("E_SDK_CLOCK", sdk_id)),
            &capture,
        )?;
        let stream_detail = failure_stream_detail(&capture.stdout, &capture.stderr);
        let stdout = transcript(capture.stdout, sdk_id)
            .map_err(|failure| format!("{failure}; {stream_detail}"))?;
        let stderr = transcript(capture.stderr, sdk_id)
            .map_err(|failure| format!("{failure}; {stream_detail}"))?;
        Ok(evidence::SdkNetworkProbeBinding {
            argv,
            cwd,
            environment_sha256: evidence::sdk_environment_sha256(environment),
            launcher: launcher.clone(),
            target_tool: target_tool.clone(),
            stdout,
            stderr,
            exit_code: capture.exit_code,
            started_at_epoch_seconds: capture.started_at_epoch_seconds,
            finished_at_epoch_seconds: capture.finished_at_epoch_seconds,
            monotonic_started_ns: capture.monotonic_started_ns,
            monotonic_finished_ns: capture.monotonic_finished_ns,
            elapsed_ns,
        })
    }

    async fn build_observation(
        cx: &Cx,
        peer: &evidence::ValidatedSdkStaticPeer,
        root: &Path,
        batch_clock: Instant,
    ) -> Result<evidence::SdkExecutionObservation> {
        let sdk_id = peer.sdk_id.as_str();
        let script = peer.reproduction_script.as_slice();
        if sha256(script) != peer.reproduction_script_sha256
            || script.contains(&0)
            || script.contains(&b'\r')
            || !script.ends_with(b"\n")
        {
            return Err(err("E_SDK_EXECUTION_SCRIPT", sdk_id));
        }
        let tools = tool_surface(sdk_id)?;
        validate_tool_surface(&tools, sdk_id)?;
        let tool_identity_before_sha256 = tool_identity_digest(&tools, sdk_id)?;
        let before = tmp_snapshot(sdk_id)?;
        let argv = vec![
            tools.interpreter.path.clone(),
            "-f".to_owned(),
            "-s".to_owned(),
        ];
        let execution = execute_bounded(
            cx,
            &argv,
            &tools.environment,
            root,
            script,
            Duration::from_secs(7_200),
            batch_clock,
            sdk_id,
        )
        .await;
        let capture = merge_capture_validation(execution, validate_tool_surface(&tools, sdk_id))?;
        let after = retain_capture(tmp_snapshot(sdk_id), &capture)?;
        let runtime_paths = retain_capture(runtime_paths(sdk_id, &before, &after), &capture)?;
        let outputs = retain_capture(observed_outputs(sdk_id, &runtime_paths), &capture)?;
        let (expected_primary, expected_secondary) = peer.expected_output_digests();
        let expected_digests = [
            expected_primary,
            expected_primary,
            expected_secondary,
            expected_secondary,
            peer.checked_lock_sha256.as_str(),
        ];
        if capture.exit_code != 0
            || outputs.digests.len() != expected_digests.len()
            || outputs
                .digests
                .iter()
                .map(String::as_str)
                .ne(expected_digests)
        {
            return Err(failure_with_streams(
                format!("E_SDK_EXECUTION_ATTEMPT: {sdk_id}: exit={}", capture.exit_code),
                &capture.stdout,
                &capture.stderr,
            ));
        }
        let launcher = retain_capture(
            tools
                .additional
                .iter()
                .find(|tool| tool.id == "sandbox-exec")
                .ok_or_else(|| err("E_SDK_NETWORK_PROBE", sdk_id)),
            &capture,
        )?;
        let target_tool = retain_capture(
            tools
                .additional
                .iter()
                .find(|tool| tool.id == "curl")
                .ok_or_else(|| err("E_SDK_NETWORK_PROBE", sdk_id)),
            &capture,
        )?;
        let probe = network_probe(
            cx,
            sdk_id,
            &tools.environment,
            root,
            batch_clock,
            launcher,
            target_tool,
        )
        .await;
        let network_probe = retain_capture(
            merge_probe_validation(probe, validate_tool_surface(&tools, sdk_id)),
            &capture,
        )?;
        retain_capture_and_probe(
            validate_tool_surface(&tools, sdk_id),
            &capture,
            &network_probe,
        )?;
        let tool_identity_after_sha256 = retain_capture_and_probe(
            tool_identity_digest(&tools, sdk_id),
            &capture,
            &network_probe,
        )?;
        retain_capture_and_probe(
            validate_tool_identity_temporal_binding(
                &tool_identity_before_sha256,
                &tool_identity_after_sha256,
                sdk_id,
            ),
            &capture,
            &network_probe,
        )?;
        let elapsed_ns = retain_capture_and_probe(
            capture
                .monotonic_finished_ns
                .checked_sub(capture.monotonic_started_ns)
                .ok_or_else(|| err("E_SDK_CLOCK", sdk_id)),
            &capture,
            &network_probe,
        )?;
        let cwd = retain_capture_and_probe(
            canonical_utf8(root, sdk_id),
            &capture,
            &network_probe,
        )?;
        let stream_detail = format!(
            "reproduction_{}; network_probe_{}",
            failure_stream_detail(&capture.stdout, &capture.stderr),
            failure_stream_detail(&network_probe.stdout.raw, &network_probe.stderr.raw),
        );
        let stdout = transcript(capture.stdout, sdk_id)
            .map_err(|failure| format!("{failure}; {stream_detail}"))?;
        let stderr = transcript(capture.stderr, sdk_id)
            .map_err(|failure| format!("{failure}; {stream_detail}"))?;
        let mut process = evidence::SdkExecutionProcessBinding {
            command_id: format!("{sdk_id}-sdk-reproduction"),
            argv_sha256: evidence::sdk_sequence_sha256(b"FND01SDKARGVv3\0", &argv),
            argv,
            cwd,
            environment_sha256: evidence::sdk_environment_sha256(&tools.environment),
            environment: tools.environment,
            interpreter: tools.interpreter,
            primary_tool: tools.primary,
            additional_tools: tools.additional,
            tool_identity_before_sha256,
            tool_identity_after_sha256,
            reproduction_script_byte_length: u64::try_from(script.len()).unwrap_or(u64::MAX),
            reproduction_script_sha256: peer.reproduction_script_sha256.clone(),
            composite_script_observer_sha256: String::new(),
            stdout,
            stderr,
            exit_code: capture.exit_code,
            started_at_epoch_seconds: capture.started_at_epoch_seconds,
            finished_at_epoch_seconds: capture.finished_at_epoch_seconds,
            monotonic_started_ns: capture.monotonic_started_ns,
            monotonic_finished_ns: capture.monotonic_finished_ns,
            elapsed_ns,
            runtime_paths,
            complete_input_sha256: String::new(),
        };
        process.composite_script_observer_sha256 = evidence::sdk_composite_binding(
            &process.reproduction_script_sha256,
            &process.environment,
            &process.interpreter,
            &process.primary_tool,
            &process.additional_tools,
        );
        process.complete_input_sha256 = evidence::sdk_process_sha256(&process);
        Ok(evidence::SdkExecutionObservation {
            sdk_id: sdk_id.to_owned(),
            source_selector: peer.source_selector.clone(),
            source_commit: peer.source_commit.clone(),
            checked_lock_sha256: peer.checked_lock_sha256.clone(),
            artifact_count: peer.artifact_count,
            artifact_set_sha256: peer.artifact_set_sha256.clone(),
            online_closure_sha256: outputs.digests[0].clone(),
            offline_closure_sha256: outputs.digests[1].clone(),
            output_paths: outputs.paths,
            process,
            network_probe,
            first_attempt: true,
        })
    }

    async fn execute_async(
        cx: &Cx,
        plan: &evidence::SdkBatchPlan,
    ) -> Result<evidence::SdkBatchReceiptBody> {
        let batch_clock = Instant::now();
        let batch_started_at_epoch_seconds = epoch_seconds("SDK batch")?;
        let mut observations = Vec::with_capacity(plan.peers().len());
        for peer in plan.peers() {
            observations.push(build_observation(cx, peer, plan.root(), batch_clock).await?);
        }
        let count = observations.len();
        Ok(evidence::SdkBatchReceiptBody {
            batch_started_at_epoch_seconds,
            batch_finished_at_epoch_seconds: epoch_seconds("SDK batch")?,
            batch_monotonic_started_ns: 0,
            batch_monotonic_finished_ns: u64::try_from(batch_clock.elapsed().as_nanos())
                .unwrap_or(u64::MAX),
            required: count,
            discovered: count,
            started: count,
            passed: count,
            first_attempt_passed: count,
            retries: 0,
            skipped: 0,
            stale: 0,
            mixed: 0,
            observations,
        })
    }

    pub(super) fn execute(plan: &evidence::SdkBatchPlan) -> Result<evidence::SdkBatchReceiptBody> {
        let reactor = create_reactor().map_err(|_| err("E_SDK_RUNTIME", "reactor"))?;
        let runtime = RuntimeBuilder::current_thread()
            .with_reactor(reactor)
            .build()
            .map_err(|_| err("E_SDK_RUNTIME", "runtime"))?;
        runtime.block_on(async {
            let cx = Cx::current().ok_or_else(|| err("E_SDK_RUNTIME", "context"))?;
            execute_async(&cx, plan).await
        })
    }
}

#[cfg(not(fnd01_bootstrap))]
fn run_sdk_batch() -> i32 {
    let plan = match evidence::sdk_prepare_batch() {
        Ok(plan) => plan,
        Err(failure) => {
            print!("{failure}");
            return 1;
        }
    };
    let body = match sdk_producer::execute(&plan) {
        Ok(body) => body,
        Err(detail) => {
            print!("{}", evidence::sdk_batch_failure_json(&detail));
            return 1;
        }
    };
    match evidence::sdk_admit_batch(plan, body) {
        Ok(receipt) => {
            print!("{receipt}");
            0
        }
        Err(failure) => {
            print!("{failure}");
            1
        }
    }
}

#[cfg(not(fnd01_bootstrap))]
fn run_sdk_batch_planted_negative() -> i32 {
    let plan = match evidence::sdk_prepare_batch() {
        Ok(plan) => plan,
        Err(failure) => {
            print!("{failure}");
            return 1;
        }
    };
    let pristine = match sdk_producer::execute(&plan) {
        Ok(body) => body,
        Err(detail) => {
            print!("{}", evidence::sdk_batch_failure_json(&detail));
            return 1;
        }
    };
    let pristine_snapshot = pristine.clone();
    let batch_counts = (
        pristine.required,
        pristine.discovered,
        pristine.started,
        pristine.passed,
        pristine.first_attempt_passed,
        pristine.retries,
        pristine.skipped,
        pristine.stale,
        pristine.mixed,
    );
    let mut candidate = pristine.clone();
    let typescript_index = {
        let mut indices = candidate
            .observations
            .iter()
            .enumerate()
            .filter_map(|(index, observation)| {
                (observation.sdk_id == "typescript").then_some(index)
            });
        match (indices.next(), indices.next()) {
            (Some(index), None) => index,
            _ => {
                print!(
                    "{}",
                    evidence::sdk_batch_failure_json(
                        "E_SDK_EXECUTION_FACTS: TypeScript observation",
                    )
                );
                return 1;
            }
        }
    };
    let pristine_digest = candidate.observations[typescript_index]
        .offline_closure_sha256
        .clone();
    let planted_digest = if pristine_digest == "01".repeat(32) {
        "02".repeat(32)
    } else {
        "01".repeat(32)
    };
    candidate.observations[typescript_index].offline_closure_sha256 = planted_digest.clone();
    let mut restored_candidate = candidate.clone();
    restored_candidate.observations[typescript_index].offline_closure_sha256 =
        pristine_digest.clone();
    let exact_single_delta = candidate != pristine && restored_candidate == pristine;
    let candidate_snapshot = candidate.clone();
    let failure = match evidence::sdk_admit_batch(plan, candidate.clone()) {
        Ok(_) => {
            print!(
                "{}",
                evidence::sdk_batch_failure_json(
                    "E_SDK_EXECUTION_FACTS: planted TypeScript digest was admitted",
                )
            );
            return 1;
        }
        Err(failure) => failure,
    };
    let expected_detail = "FND01|Error|E_SDK_EXECUTION_FACTS|trusted SDK batch receipt|typescript";
    let exact_failure = serde_json::from_str::<serde_json::Value>(&failure).is_ok_and(|value| {
        value
            == serde_json::json!({
                "format": "fastmcp-fnd01-sdk-no-credit-v1",
                "proof_class": "producer_rejected",
                "capability_credit": false,
                "support_claim": false,
                "code": "sdk_batch_admission_failed",
                "detail": expected_detail,
            })
    });
    if !exact_single_delta
        || !exact_failure
        || candidate != candidate_snapshot
        || pristine != pristine_snapshot
    {
        print!(
            "{}",
            evidence::sdk_batch_failure_json(
                "E_SDK_EXECUTION_FACTS: planted-negative oracle mismatch",
            )
        );
        return 1;
    }
    let fresh_plan = match evidence::sdk_prepare_batch() {
        Ok(plan) => plan,
        Err(failure) => {
            print!("{failure}");
            return 1;
        }
    };
    if let Err(failure) = evidence::sdk_admit_batch(fresh_plan, pristine) {
        print!("{failure}");
        return 1;
    }
    let mut output = serde_json::json!({
        "format": "fastmcp-fnd01-sdk-planted-negative-v1",
        "producer": "sdk-batch-run-planted-negative-json",
        "proof_class": "planted_negative",
        "changed_field": "typescript.offline_closure_sha256",
        "from_sha256": pristine_digest,
        "to_sha256": planted_digest,
        "expected_diagnostic": "E_SDK_EXECUTION_FACTS",
        "expected_stable_diagnostic": expected_detail,
        "candidate_rejected": true,
        "receipt_binding_recomputed": true,
        "pristine_body_unchanged": true,
        "pristine_reaccepted": true,
        "required": batch_counts.0,
        "discovered": batch_counts.1,
        "started": batch_counts.2,
        "passed": batch_counts.3,
        "first_attempt_passed": batch_counts.4,
        "retries": batch_counts.5,
        "skipped": batch_counts.6,
        "stale": batch_counts.7,
        "mixed": batch_counts.8,
        "capability_credit": false,
        "support_claim": false,
    })
    .to_string();
    output.push('\n');
    print!("{output}");
    0
}

fn main() {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    #[cfg(not(fnd01_bootstrap))]
    let code = match arguments.get(1).and_then(|value| value.to_str()) {
        Some("sdk-batch-run-json") if arguments.len() == 2 => run_sdk_batch(),
        Some("sdk-batch-run-planted-negative-json") if arguments.len() == 2 => {
            run_sdk_batch_planted_negative()
        }
        _ => {
            print!(
                "{}",
                evidence::sdk_batch_failure_json(
                    "E_SDK_RUNNER_MODE: expected one frozen SDK batch mode",
                )
            );
            2
        }
    };
    #[cfg(fnd01_bootstrap)]
    let code = {
        let _ = arguments;
        2
    };
    std::process::exit(code);
}
