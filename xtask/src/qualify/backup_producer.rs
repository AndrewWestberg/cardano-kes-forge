//! Same-certificate backup producer rehearsal.
//!
//! A recovered conventional key may serve one disjoint interval after the
//! original producer stops. Producing accepted blocks from that backup requires
//! a running node and a certificate-bound connection; this module validates the
//! public scenario and reports the missing live readings instead of simulating
//! block acceptance.
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
    pub scenarios: Vec<&'static str>,
    pub unavailable: Vec<&'static str>,
    pub completed: bool,
    pub evidence: PathBuf,
}

const SCENARIOS: &[&str] = &[
    "device-produced-generation-and-certificate",
    "original-device-interval-blocks",
    "backup-interval-same-certificate-blocks",
    "producer-stop-before-backup-start",
    "absent-backup-key-and-password-limits",
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
        campaign: "backup-producer",
        verdict: "measurement-unavailable",
        candidate,
        scenarios: SCENARIOS.to_vec(),
        unavailable: vec![
            "accepted blocks from the original device interval",
            "accepted blocks from the recovered conventional key in a separate interval",
            "proof that the original producer stopped before backup service",
        ],
        completed: false,
        evidence: evidence_dir.to_path_buf(),
    };
    evidence::write_new_json(&evidence_dir.join("backup-producer.json"), &report)?;
    Ok(report)
}
