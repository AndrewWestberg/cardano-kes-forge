//! Development-only management lifecycle campaign.
//!
//! This runner proves the core state transitions and restart reconciliation. It
//! deliberately does not claim device, node, or physical power-cut coverage.
use crate::evidence::{self, Result};
use serde::Serialize;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

const SCENARIOS: [&str; 5] = [
    "credential-replace-revoke-staged-discard",
    "management-transport-credential-restart",
    "deletion-erased-slot-boot-recovery",
    "deletion-reenrollment-interrupted-recovery",
    "device-retirement-interrupted-recovery",
];

#[derive(Debug, Serialize)]
pub struct SoftwareManagementResult {
    pub manifest: PathBuf,
    pub scenarios: Vec<String>,
    pub duration_ms: u64,
    pub log_sha256: String,
}

#[derive(Serialize)]
struct Manifest<'a> {
    version: u8,
    campaign: &'static str,
    verdict: &'static str,
    execution_scope: &'static str,
    device_transport_status: &'static str,
    physical_power_cut_status: &'static str,
    scenarios: &'a [String],
    command: &'a [String],
    duration_ms: u64,
    log: &'static str,
    log_sha256: &'a str,
}

pub fn run_software(evidence_dir: &Path) -> Result<SoftwareManagementResult> {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("xtask workspace root unavailable")?;
    fs::create_dir_all(evidence_dir).map_err(|error| error.to_string())?;
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let arguments = [
        "test",
        "--locked",
        "-p",
        "kes-core",
        "--features",
        "protected-runtime",
        "--test",
        "management_lifecycle",
        "--",
        "--test-threads=1",
    ];
    let started = Instant::now();
    let output = Command::new(&cargo)
        .args(arguments)
        .current_dir(workspace)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("management software campaign failed to start: {error}"))?;
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let log_path = evidence_dir.join("management-software.log");
    write_new_log(&log_path, &output.stdout, &output.stderr)?;
    let log_sha256 = evidence::file_hash(&log_path)?;
    if !output.status.success() {
        return Err(format!(
            "management software campaign failed; log {log_sha256}"
        ));
    }

    let scenarios = SCENARIOS
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    let command = std::iter::once(cargo.to_string_lossy().into_owned())
        .chain(arguments.iter().map(|value| (*value).to_owned()))
        .collect::<Vec<_>>();
    let manifest_path = evidence_dir.join("management-software.json");
    evidence::write_new_json(
        &manifest_path,
        &Manifest {
            version: 1,
            campaign: "management-lifecycle-software",
            verdict: "software-pass",
            execution_scope: "kes-core authenticated state and journal codec restart",
            device_transport_status: "unavailable-not-attempted",
            physical_power_cut_status: "unavailable-not-attempted",
            scenarios: &scenarios,
            command: &command,
            duration_ms,
            log: "management-software.log",
            log_sha256: &log_sha256,
        },
    )?;
    Ok(SoftwareManagementResult {
        manifest: manifest_path,
        scenarios,
        duration_ms,
        log_sha256,
    })
}

fn write_new_log(path: &Path, stdout: &[u8], stderr: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(path)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
    file.write_all(stdout)
        .and_then(|()| file.write_all(b"\n--- stderr ---\n"))
        .and_then(|()| file.write_all(stderr))
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    let parent = path.parent().ok_or("management log has no parent")?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("cannot sync {}: {error}", parent.display()))
}
