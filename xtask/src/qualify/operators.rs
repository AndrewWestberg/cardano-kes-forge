//! Representative-operator trials (G11/SC-001/SC-006).
//!
//! Human timing and comprehension cannot be produced by a test process. This
//! runner validates the public operator fixture and records the exact trial
//! inventory as unavailable until five representative operators perform the
//! documented workflows. It never substitutes a developer demonstration.
use super::node;
use crate::evidence::{self, Result};
use crate::fixture::ScenarioManifest;
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Serialize)]
pub struct Report {
    pub version: u8,
    pub campaign: &'static str,
    pub verdict: &'static str,
    pub candidate: Option<String>,
    pub operators_required: u8,
    pub scenarios: Vec<&'static str>,
    pub unavailable: Vec<&'static str>,
    pub completed: bool,
    pub evidence: PathBuf,
}

const SCENARIOS: &[&str] = &[
    "five-representative-operators-no-developer-assistance",
    "certificate-ready-vk-within-fifteen-minutes",
    "retrievable-backup-within-fifteen-minutes",
    "identify-active-backup-validity-within-one-minute",
    "single-operator-immediate-rotation-within-ten-minutes",
    "single-operator-scheduled-rotation-within-ten-minutes",
];

pub fn run(fixture: &Path, evidence_dir: &Path) -> Result<Report> {
    let _: ScenarioManifest = node::validate(fixture)?;
    std::fs::create_dir_all(evidence_dir).map_err(|error| error.to_string())?;
    let candidate = std::env::var_os("KESFORGE_CANDIDATE_ROOT")
        .map(|path| evidence::load_current(Path::new(&path)))
        .transpose()?
        .map(|frozen| frozen.candidate);
    let report = Report {
        version: 1,
        campaign: "operators",
        verdict: "measurement-unavailable",
        candidate,
        operators_required: 5,
        scenarios: SCENARIOS.to_vec(),
        unavailable: vec![
            "at least four of five representative operators without developer assistance",
            "certificate-ready verification key and retrievable backup within fifteen minutes",
            "active generation, backup and validity/staleness identified within one minute",
            "single-operator immediate and scheduled rotation within ten minutes",
        ],
        completed: false,
        evidence: evidence_dir.to_path_buf(),
    };
    evidence::write_new_json(&evidence_dir.join("operators.json"), &report)?;
    Ok(report)
}
