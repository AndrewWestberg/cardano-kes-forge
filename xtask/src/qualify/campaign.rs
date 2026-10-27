//! Shared execution and evidence envelope for qualification campaigns.
//!
//! Runners name the real executables/tests they exercise and every scenario the
//! campaign covers. A command that cannot run, exits nonzero, or produces no
//! named scenario is never a pass. Hardware/network work that this host cannot
//! perform is listed explicitly as unavailable; it is not inferred from a
//! successful software run.
use crate::evidence::{self, Result};
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

#[derive(Serialize)]
pub struct CommandReading {
    pub name: String,
    pub program: String,
    pub args: Vec<String>,
    pub exit_code: Option<i32>,
    pub success: bool,
    pub duration_ms: u64,
    pub log: String,
    pub log_sha256: String,
}

#[derive(Serialize)]
pub struct CampaignReport {
    pub version: u8,
    pub campaign: &'static str,
    pub verdict: &'static str,
    pub candidate: Option<String>,
    pub scenarios: Vec<String>,
    pub commands: Vec<CommandReading>,
    pub unavailable: Vec<String>,
    pub completed: bool,
    pub evidence: PathBuf,
}

pub struct Run<'a> {
    pub name: &'a str,
    pub program: &'a str,
    pub args: &'a [&'a str],
    pub scenarios: &'a [&'a str],
    pub cwd: Option<&'a Path>,
}

pub fn workspace() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "workspace root unavailable".to_owned())
}

/// Execute every reading, retain its public transcript, and publish one report.
/// `unavailable` must describe required measurements this environment cannot
/// make; their presence makes the campaign incomplete even when software passes.
pub fn run(
    evidence_dir: &Path,
    campaign: &'static str,
    runs: &[Run<'_>],
    unavailable: Vec<String>,
) -> Result<CampaignReport> {
    if runs.is_empty() {
        return Err(format!("{campaign} has no executable readings"));
    }
    std::fs::create_dir_all(evidence_dir).map_err(|error| error.to_string())?;
    let candidate = std::env::var_os("KESFORGE_CANDIDATE_ROOT")
        .map(|path| evidence::load_current(Path::new(&path)))
        .transpose()?
        .map(|frozen| frozen.candidate);
    let workspace = workspace()?;
    let mut commands = Vec::with_capacity(runs.len());
    let mut scenarios = Vec::new();
    let mut clean = true;
    for run in runs {
        if run.scenarios.is_empty() {
            return Err(format!("{} names no scenarios", run.name));
        }
        for scenario in run.scenarios {
            if scenario.is_empty() || !scenarios.iter().all(|prior: &String| prior != scenario) {
                return Err(format!("empty or duplicate scenario in {}", run.name));
            }
        }
        let started = Instant::now();
        let output = Command::new(run.program)
            .args(run.args)
            .current_dir(run.cwd.unwrap_or(&workspace))
            .stdin(Stdio::null())
            .output()
            .map_err(|error| format!("{} failed to start: {error}", run.name))?;
        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let log_name = format!("{campaign}-{}.log", run.name);
        let log_path = evidence_dir.join(&log_name);
        write_log(&log_path, &output.stdout, &output.stderr)?;
        let log_sha256 = evidence::file_hash(&log_path)?;
        clean &= output.status.success();
        commands.push(CommandReading {
            name: run.name.to_owned(),
            program: run.program.to_owned(),
            args: run.args.iter().map(|value| (*value).to_owned()).collect(),
            exit_code: output.status.code(),
            success: output.status.success(),
            duration_ms,
            log: log_name,
            log_sha256,
        });
        scenarios.extend(run.scenarios.iter().map(|value| (*value).to_owned()));
    }
    let complete = clean && unavailable.is_empty();
    let report = CampaignReport {
        version: 1,
        campaign,
        verdict: match (clean, unavailable.is_empty()) {
            (true, true) => "pass",
            (true, false) => "software-pass-measurement-unavailable",
            (false, _) => "fail",
        },
        candidate,
        scenarios,
        commands,
        unavailable,
        completed: complete,
        evidence: evidence_dir.to_path_buf(),
    };
    let path = evidence_dir.join(format!("{campaign}.json"));
    evidence::write_new_json(&path, &report)?;
    if !clean {
        return Err(format!(
            "{campaign} failed; public report {}",
            path.display()
        ));
    }
    Ok(report)
}

fn write_log(path: &Path, stdout: &[u8], stderr: &[u8]) -> Result<()> {
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
    let parent = path.parent().ok_or("campaign log has no parent")?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("cannot sync {}: {error}", parent.display()))
}
