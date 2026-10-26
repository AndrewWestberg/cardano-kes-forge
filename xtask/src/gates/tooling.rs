use crate::evidence::{self, Frozen, Gate, Result};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub struct Output {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
    pub duration_ms: u64,
}

const MAX_CAPTURE: usize = 16 * 1024 * 1024;

pub(crate) fn component(label: &str) -> String {
    format!("{:x}", Sha256::digest(label.as_bytes()))
}

pub struct RuntimeDirectory {
    pub path: PathBuf,
}

impl Drop for RuntimeDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn process_session(path: &Path) -> Result<(u32, u32)> {
    let stat = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
    let fields: Vec<_> = stat
        .get(stat.rfind(')').ok_or("invalid process status")? + 1..)
        .ok_or("invalid process status")?
        .split_whitespace()
        .collect();
    let parent = fields
        .get(1)
        .ok_or("missing parent PID")?
        .parse()
        .map_err(|_| "invalid parent PID")?;
    let session = fields
        .get(3)
        .ok_or("missing process session")?
        .parse()
        .map_err(|_| "invalid process session")?;
    Ok((parent, session))
}

/// Descendants may have independent process groups, but must remain in the
/// session whose live leader was spawned by the declared outer controller.
pub fn controller_pid() -> Result<Option<u32>> {
    let Some(controller) = std::env::var_os("KESFORGE_GATE_CONTROLLER") else {
        return Ok(None);
    };
    let controller: u32 = controller
        .to_str()
        .ok_or("non-UTF-8 gate controller")?
        .parse()
        .map_err(|_| "invalid gate controller PID")?;
    let (_, session) = process_session(Path::new("/proc/self/stat"))?;
    let (parent, leader_session) =
        process_session(&PathBuf::from(format!("/proc/{session}/stat")))?;
    if controller == 0 || session == 0 || parent != controller || leader_session != session {
        return Err("gate controller marker does not match owned session-leader parent".into());
    }
    Ok(Some(controller))
}

/// Own only a newly created directory. In controlled execution the outer CLI
/// retains ownership of the base and cleans it even if this process is killed.
pub fn runtime_directory(frozen: &Frozen, gate: &Gate) -> Result<RuntimeDirectory> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    for name in [&frozen.candidate, &gate.id] {
        if name.is_empty()
            || Path::new(name).components().count() != 1
            || !matches!(
                Path::new(name).components().next(),
                Some(std::path::Component::Normal(_))
            )
        {
            return Err("invalid gate runtime identity".into());
        }
    }
    let root = std::fs::canonicalize(&frozen.workspace).map_err(|error| error.to_string())?;
    let base = root
        .join("target/gate-runtime")
        .join(&frozen.candidate)
        .join(&gate.id);
    let path = if controller_pid()?.is_some() {
        let supplied = std::env::var_os("KESFORGE_GATE_RUNTIME")
            .ok_or("controller omitted runtime directory")?;
        let supplied = PathBuf::from(supplied);
        if !supplied.is_absolute()
            || supplied != base
            || std::fs::canonicalize(&supplied).map_err(|error| error.to_string())? != base
        {
            return Err("controller runtime is not the exact candidate/gate directory".into());
        }
        let metadata = std::fs::symlink_metadata(&base).map_err(|error| error.to_string())?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o777 != 0o700 {
            return Err("controller runtime directory is not private mode0700".into());
        }
        base.join("runner")
    } else {
        if std::env::var_os("KESFORGE_GATE_RUNTIME").is_some() {
            return Err("runtime marker without verified controller".into());
        }
        let parent = base.parent().ok_or("runtime has no parent")?;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|error| error.to_string())?;
        if std::fs::canonicalize(parent).map_err(|error| error.to_string())? != parent {
            return Err("runtime parent is redirected through a symlink".into());
        }
        base
    };
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .map_err(|error| format!("cannot exclusively create runtime: {error}"))?;
    Ok(RuntimeDirectory { path })
}

fn capture(mut pipe: impl Read) -> std::io::Result<(Vec<u8>, bool)> {
    let mut bytes = Vec::new();
    let mut overflow = false;
    let mut buffer = [0_u8; 16384];
    loop {
        let count = pipe.read(&mut buffer)?;
        if count == 0 {
            return Ok((bytes, overflow));
        }
        let keep = count.min(MAX_CAPTURE.saturating_sub(bytes.len()));
        bytes.extend_from_slice(&buffer[..keep]);
        overflow |= keep != count;
    }
}

fn kill_group(id: u32) -> Result<()> {
    let status = Command::new("/bin/kill")
        .args(["-KILL", "--", &format!("-{id}")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("cannot terminate process group: {error}"))?;
    if !status.success() {
        let alive = Command::new("/bin/kill")
            .args(["-0", "--", &format!("-{id}")])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|error| error.to_string())?;
        if alive.success() {
            return Err("tool process group could not be terminated".into());
        }
    }
    Ok(())
}

/// Bound captures and cleanup. Tool process groups remain inside the inherited
/// session; the outer controller additionally owns session-wide cancellation.
/// No tool may create a new session.
pub fn run(command: &mut Command, budget_ms: u64) -> Result<Output> {
    if budget_ms == 0 {
        return Err("zero subprocess budget".into());
    }
    let started = Instant::now();
    if let Some(controller) = controller_pid()? {
        command.env("KESFORGE_GATE_CONTROLLER", controller.to_string());
        for key in [
            "KESFORGE_GATE_RUNTIME",
            "KESFORGE_CANDIDATE_ROOT",
            "KESFORGE_GATE",
        ] {
            let explicitly_set = command
                .get_envs()
                .any(|(name, value)| name == key && value.is_some());
            if !explicitly_set && let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot start {:?}: {error}", command.get_program()))?;
    let stdout = child.stdout.take().ok_or("missing stdout pipe")?;
    let stderr = child.stderr.take().ok_or("missing stderr pipe")?;
    let (out_sender, out) = std::sync::mpsc::sync_channel(1);
    let (err_sender, err) = std::sync::mpsc::sync_channel(1);
    let _out_reader = thread::spawn(move || {
        let _ = out_sender.send(capture(stdout));
    });
    let _err_reader = thread::spawn(move || {
        let _ = err_sender.send(capture(stderr));
    });
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                kill_group(child.id())?;
                let _ = child.wait();
                return Err(format!("cannot wait for tool: {error}"));
            }
        }
        if started.elapsed() >= Duration::from_millis(budget_ms) {
            timed_out = true;
            kill_group(child.id())?;
            break child.wait().map_err(|error| error.to_string())?;
        }
        thread::sleep(Duration::from_millis(10));
    };
    // Reap descendants in this tool group; outer cleanup covers all groups
    // still present in the controller's session if this wrapper is killed.
    kill_group(child.id())?;
    let cleanup = Instant::now();
    let grace = Duration::from_secs(1);
    let (stdout, out_overflow) = out
        .recv_timeout(grace)
        .map_err(|_| "stdout pipe did not close after process-group termination")?
        .map_err(|error| error.to_string())?;
    let (stderr, err_overflow) = err
        .recv_timeout(grace.saturating_sub(cleanup.elapsed()))
        .map_err(|_| "stderr pipe did not close after process-group termination")?
        .map_err(|error| error.to_string())?;
    if out_overflow || err_overflow {
        return Err(
            "tool output exceeded bounded capture; incomplete diagnostics cannot pass".into(),
        );
    }
    let elapsed = started.elapsed();
    timed_out |= elapsed >= Duration::from_millis(budget_ms);
    Ok(Output {
        code: status.code(),
        stdout,
        stderr,
        timed_out,
        duration_ms: elapsed
            .as_nanos()
            .div_ceil(1_000_000)
            .try_into()
            .map_err(|_| "duration overflow")?,
    })
}

pub(crate) fn reading(output: &Output) -> Value {
    let mut diagnostics = Vec::new();
    let mut artifacts = Vec::new();
    for line in output
        .stdout
        .split(|byte| *byte == b'\n')
        .chain(output.stderr.split(|byte| *byte == b'\n'))
    {
        let Ok(value) = serde_json::from_slice::<Value>(line) else {
            continue;
        };
        match value["reason"].as_str() {
            Some("compiler-message") => diagnostics.push(public_diagnostic(&value["message"])),
            Some("compiler-artifact") => artifacts.push(json!({"package_id":value["package_id"], "target":value["target"], "filenames":value["filenames"], "fresh":value["fresh"]})),
            _ => { if value.get("$message_type").is_some() { diagnostics.push(public_diagnostic(&value)); } }
        }
    }
    json!({"exit":output.code, "timed_out":output.timed_out, "duration_ms":output.duration_ms,
        "stdout_bytes":output.stdout.len(), "stderr_bytes":output.stderr.len(),
        "stdout_sha256":format!("{:x}",Sha256::digest(&output.stdout)),
        "stderr_sha256":format!("{:x}",Sha256::digest(&output.stderr)), "diagnostics":diagnostics, "artifacts":artifacts})
}

fn public_diagnostic(value: &Value) -> Value {
    let spans: Vec<Value> = value["spans"].as_array().into_iter().flatten().map(|span| json!({
        "file_name":span["file_name"], "line_start":span["line_start"], "line_end":span["line_end"],
        "column_start":span["column_start"], "column_end":span["column_end"], "is_primary":span["is_primary"]
    })).collect();
    let children: Vec<Value> = value["children"]
        .as_array()
        .into_iter()
        .flatten()
        .map(public_diagnostic)
        .collect();
    json!({"code":value["code"], "level":value["level"], "message":value["message"], "spans":spans, "children":children})
}

pub(crate) fn success(output: &Output) -> bool {
    output.code == Some(0) && !output.timed_out
}

pub(crate) fn diagnostic_count(output: &Output, code: &str) -> usize {
    output
        .stdout
        .split(|byte| *byte == b'\n')
        .chain(output.stderr.split(|byte| *byte == b'\n'))
        .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
        .filter(|value| {
            value["message"]["code"]["code"]
                .as_str()
                .or(value["code"]["code"].as_str())
                == Some(code)
        })
        .count()
}

pub(crate) fn pinned_tool(
    toolchain: &str,
    name: &str,
    budget_ms: u64,
) -> Result<std::path::PathBuf> {
    if !matches!(toolchain, "1.99.1" | "nightly-2026-10-22") {
        return Err(format!("unapproved toolchain {toolchain}"));
    }
    let output = run(
        Command::new("rustup").args(["which", "--toolchain", toolchain, name]),
        budget_ms,
    )?;
    if !success(&output) {
        return Err(format!("missing pinned {name} for {toolchain}"));
    }
    let path = std::path::PathBuf::from(
        std::str::from_utf8(&output.stdout)
            .map_err(|error| error.to_string())?
            .trim(),
    );
    evidence::file_hash(&path)?;
    Ok(path)
}

pub(crate) fn validate_tools(toolchain: &str, budget_ms: u64) -> Result<Value> {
    let mut values = serde_json::Map::new();
    for name in ["rustc", "cargo", "clippy-driver", "rustfmt"] {
        let path = pinned_tool(toolchain, name, budget_ms)?;
        let output = run(Command::new(&path).arg("--version"), budget_ms)?;
        let version = std::str::from_utf8(&output.stdout)
            .map_err(|error| error.to_string())?
            .trim();
        let valid = if toolchain == "1.99.1" {
            match name {
                "clippy-driver" => version == "clippy 0.1.99 (58cf8f9c35 2026-10-13)",
                "rustc" => version.starts_with("rustc 1.99.1 "),
                "cargo" => version.starts_with("cargo 1.99.1 "),
                "rustfmt" => version.contains("stable"),
                _ => false,
            }
        } else {
            version.contains("nightly") || name == "clippy-driver" && version.contains("2026-10-")
        };
        if !success(&output) || !valid {
            return Err(format!("wrong pinned {name} identity: {version}"));
        }
        values.insert(
            name.into(),
            json!({"path":path,"version":version,"sha256":evidence::file_hash(&path)?}),
        );
    }
    Ok(Value::Object(values))
}

pub(crate) fn config(root: &Path) -> Result<String> {
    let path = root.join("clippy.toml");
    let text = std::fs::read_to_string(&path).map_err(|error| error.to_string())?;
    if text.trim() != "cognitive-complexity-threshold = 25" {
        return Err("missing or overridden cognitive complexity threshold".into());
    }
    for key in [
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTDOCFLAGS",
        "CLIPPY_ARGS",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
    ] {
        if std::env::var_os(key).is_some_and(|value| !value.is_empty()) {
            return Err(format!("unapproved lint/compiler override: {key}"));
        }
    }
    evidence::file_hash(&path)
}

/// Reject suppression even when it was accidentally included in an approved build.
pub(crate) fn lint_flags(flags: &[String]) -> Result<()> {
    if flags.iter().any(|flag| {
        flag.contains("cap-lints") || flag.starts_with("-A") || flag.starts_with("--allow")
    }) {
        return Err("frozen compiler flags suppress diagnostics or cap lint enforcement".into());
    }
    Ok(())
}
