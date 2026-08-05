//! Remote coordinator for the frozen FND-01 evidence gate.
//!
//! The SDK batch backend executes only an opaque, verifier-prepared plan. The
//! verifier independently reopens its observations and is the sole component
//! that can assign the trusted production proof class.

#![forbid(unsafe_code)]

#[allow(dead_code, unused_imports)]
#[path = "../tests/fnd_01_dependency_evidence.rs"]
mod evidence;

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
    const CHILD_HEARTBEAT: Duration = Duration::from_millis(100);

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

    fn configured_tool(name: &str, id: &str, version: &str) -> Result<evidence::SdkExecutableBinding> {
        let path = required_environment(name, "SDK configured tool")?;
        if !Path::new(&path).is_absolute() {
            return Err(err("E_SDK_RUNNER_CONFIGURATION", name));
        }
        executable(id, Path::new(&path), version, name)
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
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut stdin_future = Box::pin(async move {
            stdin.write_all(stdin_bytes).await?;
            stdin.shutdown().await
        });
        let mut stdout_future = Box::pin(async move {
            let mut output = Vec::new();
            let mut bounded = stdout.take(CHILD_STREAM_READ_LIMIT);
            bounded.read_to_end(&mut output).await?;
            Ok::<_, std::io::Error>(output)
        });
        let mut stderr_future = Box::pin(async move {
            let mut output = Vec::new();
            let mut bounded = stderr.take(CHILD_STREAM_READ_LIMIT);
            bounded.read_to_end(&mut output).await?;
            Ok::<_, std::io::Error>(output)
        });
        let mut stdin_done = false;
        let mut stdout_done = None;
        let mut stderr_done = None;
        let mut heartbeat = Box::pin(time::sleep(cx.now(), CHILD_HEARTBEAT));

        std::future::poll_fn(|task| {
            if cx.checkpoint().is_err() {
                return Poll::Ready(Err(err("E_SDK_CHILD_CANCELLED", subject)));
            }

            if !stdin_done {
                match stdin_future.as_mut().poll(task) {
                    Poll::Ready(Ok(())) => stdin_done = true,
                    Poll::Ready(Err(_)) => {
                        return Poll::Ready(Err(err("E_SDK_CHILD_STREAM", "stdin write")));
                    }
                    Poll::Pending => {}
                }
            }
            if stdout_done.is_none() {
                match stdout_future.as_mut().poll(task) {
                    Poll::Ready(Ok(output)) => stdout_done = Some(output),
                    Poll::Ready(Err(_)) => {
                        return Poll::Ready(Err(err("E_SDK_CHILD_STREAM", "stdout")));
                    }
                    Poll::Pending => {}
                }
            }
            if stderr_done.is_none() {
                match stderr_future.as_mut().poll(task) {
                    Poll::Ready(Ok(output)) => stderr_done = Some(output),
                    Poll::Ready(Err(_)) => {
                        return Poll::Ready(Err(err("E_SDK_CHILD_STREAM", "stderr")));
                    }
                    Poll::Pending => {}
                }
            }

            if stdout_done
                .as_ref()
                .is_some_and(|output| output.len() > CHILD_STREAM_LIMIT)
                || stderr_done
                    .as_ref()
                    .is_some_and(|output| output.len() > CHILD_STREAM_LIMIT)
            {
                return Poll::Ready(Err(err("E_SDK_CHILD_STREAM", "bound exceeded")));
            }
            if stdin_done && stdout_done.is_some() && stderr_done.is_some() {
                return Poll::Ready(Ok((
                    stdout_done.take().unwrap_or_default(),
                    stderr_done.take().unwrap_or_default(),
                )));
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

    async fn cleanup_child(child: &mut Child, cx: &Cx, subject: &str) -> Result<()> {
        if child.id().is_none() {
            return Ok(());
        }
        let _ = child.kill();
        let _wait_result = child.wait_async(cx).await;
        if child.id().is_none() {
            Ok(())
        } else {
            Err(err("E_SDK_CHILD_REAP", subject))
        }
    }

    async fn fail_after_cleanup(
        child: &mut Child,
        cx: &Cx,
        subject: &str,
        failure: String,
    ) -> String {
        match cleanup_child(child, cx, subject).await {
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
                return Err(fail_after_cleanup(&mut child, cx, subject, failure).await);
            }
        };
        let outcome = {
            let communication = async {
                // Keep the child handle unreaped while draining. A descendant may
                // inherit a pipe, and the managed group must remain signalable if
                // that pipe outlives the direct child.
                let (stdout, stderr) =
                    exchange_child_streams(cx, stdin, stdout, stderr, stdin_bytes, subject).await?;
                let status = child
                    .wait_async(cx)
                    .await
                    .map_err(|_| err("E_SDK_CHILD_WAIT", subject))?;
                Ok::<_, String>((status, stdout, stderr))
            };
            time::timeout(timeout_origin, timeout, communication).await
        };
        let (status, stdout, stderr) = match outcome {
            Ok(Ok(value)) => value,
            Ok(Err(failure)) => {
                return Err(fail_after_cleanup(&mut child, cx, subject, failure).await);
            }
            Err(_) => {
                // Dropping the timed future above closes all pipe handles before
                // the configured process group is killed and the leader reaped.
                let failure = err("E_SDK_CHILD_DEADLINE", subject);
                return Err(fail_after_cleanup(&mut child, cx, subject, failure).await);
            }
        };
        let exit_code = status
            .code()
            .map(i64::from)
            .ok_or_else(|| err("E_SDK_CHILD_WAIT", "signal"))?;
        Ok(Capture {
            exit_code,
            stdout,
            stderr,
            started_at_epoch_seconds,
            finished_at_epoch_seconds: epoch_seconds(subject)?,
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
        let interpreter = executable("zsh", Path::new("/bin/zsh"), "system", "zsh")?;
        let node = configured_tool("FND01_SDK_NODE", "node", "v24.12.0")?;
        let npm = configured_tool("FND01_SDK_NPM", "npm", "11.14.0")?;
        let python = configured_tool("FND01_SDK_PYTHON3", "python", "Python 3.14.4")?;
        let jq = configured_tool("FND01_SDK_JQ", "jq", "byte-bound")?;
        let shasum = executable("shasum", Path::new("/usr/bin/shasum"), "system", "shasum")?;
        let sandbox = executable(
            "sandbox-exec",
            Path::new("/usr/bin/sandbox-exec"),
            "system",
            "sandbox-exec",
        )?;
        let curl = executable("curl", Path::new("/usr/bin/curl"), "system", "curl")?;
        let dotnet_root = required_environment("DOTNET_SDK", "dotnet root")?;
        let dotnet = executable(
            "dotnet",
            &Path::new(&dotnet_root).join("dotnet"),
            "10.0.100",
            "dotnet",
        )?;
        let go_root = required_environment("GO_1_25", "go root")?;
        let go = executable(
            "go",
            &Path::new(&go_root).join("bin/go"),
            "go version go1.25.0 darwin/arm64",
            "go",
        )?;
        let dotnet_directory = Path::new(&dotnet.path)
            .parent()
            .ok_or_else(|| err("E_SDK_RUNNER_CONFIGURATION", "dotnet path"))?
            .to_path_buf();
        let go_directory = Path::new(&go.path)
            .parent()
            .ok_or_else(|| err("E_SDK_RUNNER_CONFIGURATION", "go path"))?
            .to_path_buf();
        let (primary, mut additional) = match sdk_id {
            "typescript" => (npm, vec![node]),
            "python" => (python, Vec::new()),
            "csharp" => (dotnet, Vec::new()),
            "go" => (go, Vec::new()),
            _ => return Err(err("E_SDK_RUNNER_CONFIGURATION", sdk_id)),
        };
        additional.extend([jq, shasum, sandbox, curl]);
        additional.sort_unstable_by(|left, right| left.id.cmp(&right.id));
        if additional.windows(2).any(|window| window[0].id == window[1].id) {
            return Err(err("E_SDK_RUNNER_CONFIGURATION", "duplicate tool"));
        }
        let mut path_directories = additional
            .iter()
            .chain(std::iter::once(&primary))
            .filter_map(|tool| Path::new(&tool.path).parent())
            .map(Path::to_path_buf)
            .collect::<Vec<_>>();
        path_directories.extend([dotnet_directory, go_directory]);
        for name in [
            "FND01_SDK_NODE",
            "FND01_SDK_NPM",
            "FND01_SDK_PYTHON3",
            "FND01_SDK_JQ",
        ] {
            let configured = required_environment(name, name)?;
            let parent = Path::new(&configured)
                .parent()
                .ok_or_else(|| err("E_SDK_RUNNER_CONFIGURATION", name))?;
            path_directories.push(PathBuf::from(canonical_utf8(parent, name)?));
        }
        path_directories.extend([PathBuf::from("/usr/bin"), PathBuf::from("/bin")]);
        path_directories.sort();
        path_directories.dedup();
        let path = path_directories
            .iter()
            .map(|path| path.to_string_lossy())
            .collect::<Vec<_>>()
            .join(":");
        let home = canonical_utf8(
            Path::new(&required_environment("FND01_SDK_HOME", "home")?),
            "home",
        )?;
        let dotnet_archive = canonical_utf8(
            Path::new(&required_environment("DOTNET_ARCHIVE", "dotnet archive")?),
            "dotnet archive",
        )?;
        let mut environment = vec![
            ("DOTNET_ARCHIVE".to_owned(), dotnet_archive),
            ("DOTNET_SDK".to_owned(), dotnet_root),
            ("GO_1_25".to_owned(), go_root),
            ("HOME".to_owned(), home),
            ("LANG".to_owned(), "C".to_owned()),
            ("LC_ALL".to_owned(), "C".to_owned()),
            ("NO_COLOR".to_owned(), "1".to_owned()),
            ("PATH".to_owned(), path),
            ("TMPDIR".to_owned(), "/tmp".to_owned()),
        ];
        environment.sort_unstable();
        Ok(Tools {
            environment,
            interpreter,
            primary,
            additional,
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
        curl: &evidence::SdkExecutableBinding,
    ) -> Result<evidence::SdkNetworkProbeBinding> {
        let url = match sdk_id {
            "typescript" => "https://registry.npmjs.org/",
            "python" => "https://pypi.org/",
            "csharp" => "https://api.nuget.org/v3/index.json",
            "go" => "https://proxy.golang.org/",
            _ => return Err(err("E_SDK_NETWORK_PROBE", sdk_id)),
        };
        let argv = vec![
            "/usr/bin/sandbox-exec".to_owned(),
            "-p".to_owned(),
            "(version 1) (allow default) (deny network*)".to_owned(),
            "/usr/bin/curl".to_owned(),
            "--silent".to_owned(),
            "--show-error".to_owned(),
            "--max-time".to_owned(),
            "2".to_owned(),
            url.to_owned(),
        ];
        let capture = execute_bounded(
            cx,
            &argv,
            environment,
            root,
            &[],
            Duration::from_secs(10),
            batch_clock,
            "network denial probe",
        )
        .await?;
        Ok(evidence::SdkNetworkProbeBinding {
            argv,
            executable: curl.clone(),
            exit_code: capture.exit_code,
            stdout: transcript(capture.stdout, sdk_id)?,
            stderr: transcript(capture.stderr, sdk_id)?,
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
        let before = tmp_snapshot(sdk_id)?;
        let argv = vec!["/bin/zsh".to_owned(), "-f".to_owned(), "-s".to_owned()];
        let capture = execute_bounded(
            cx,
            &argv,
            &tools.environment,
            root,
            script,
            Duration::from_secs(7_200),
            batch_clock,
            sdk_id,
        )
        .await?;
        let runtime_paths = runtime_paths(sdk_id, &before, &tmp_snapshot(sdk_id)?)?;
        let outputs = observed_outputs(sdk_id, &runtime_paths)?;
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
            return Err(format!(
                "E_SDK_EXECUTION_ATTEMPT: {sdk_id}: exit={};stdout_hex={};stderr_hex={}",
                capture.exit_code,
                hex(&capture.stdout),
                hex(&capture.stderr),
            ));
        }
        let curl = tools
            .additional
            .iter()
            .find(|tool| tool.id == "curl")
            .ok_or_else(|| err("E_SDK_NETWORK_PROBE", sdk_id))?;
        let network_probe =
            network_probe(cx, sdk_id, &tools.environment, root, batch_clock, curl).await?;
        let elapsed_ns = capture
            .monotonic_finished_ns
            .checked_sub(capture.monotonic_started_ns)
            .ok_or_else(|| err("E_SDK_CLOCK", sdk_id))?;
        let mut process = evidence::SdkExecutionProcessBinding {
            command_id: format!("{sdk_id}-sdk-reproduction"),
            argv_sha256: evidence::sdk_sequence_sha256(b"FND01SDKARGVv3\0", &argv),
            argv,
            cwd: canonical_utf8(root, sdk_id)?,
            environment_sha256: evidence::sdk_environment_sha256(&tools.environment),
            environment: tools.environment,
            interpreter: tools.interpreter,
            primary_tool: tools.primary,
            additional_tools: tools.additional,
            reproduction_script_byte_length: u64::try_from(script.len()).unwrap_or(u64::MAX),
            reproduction_script_sha256: peer.reproduction_script_sha256.clone(),
            composite_script_observer_sha256: String::new(),
            stdout: transcript(capture.stdout, sdk_id)?,
            stderr: transcript(capture.stderr, sdk_id)?,
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

fn main() {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    let code = if arguments.len() == 2
        && arguments.get(1).and_then(|value| value.to_str()) == Some("sdk-batch-run-json")
    {
        run_sdk_batch()
    } else {
        evidence::harness_main(arguments)
    };
    std::process::exit(code);
}
