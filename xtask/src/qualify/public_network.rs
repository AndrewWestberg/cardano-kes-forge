//! Preview/preprod public-network trials (G11/SC-008).
//!
//! Each network must span at least two complete KES periods with at least ten
//! independently observed accepted blocks, separate device/backup intervals and
//! one disconnect/reconnect. No live network fixture is present here, so the
//! runner validates the public scenario and reports unavailable. Accelerated
//! private-network time is never substituted.
use super::node;
use crate::evidence::{self, Result};
use crate::fixture::ScenarioManifest;
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Serialize)]
pub struct Report {
    pub version: u8,
    pub campaign: &'static str,
    pub network: String,
    pub verdict: &'static str,
    pub candidate: Option<String>,
    pub scenarios: Vec<&'static str>,
    pub unavailable: Vec<&'static str>,
    pub completed: bool,
    pub evidence: PathBuf,
}

const SCENARIOS: &[&str] = &[
    "at-least-ten-independently-observed-accepted-blocks",
    "at-least-two-complete-actual-kes-periods",
    "separate-device-and-backup-intervals",
    "one-rotation",
    "disconnect-and-reconnect",
];

pub fn run(network: &str, fixture: &Path, evidence_dir: &Path) -> Result<Report> {
    if !matches!(network, "preview" | "preprod") {
        return Err("public network must be preview or preprod".into());
    }
    let _: ScenarioManifest = node::validate(fixture)?;
    std::fs::create_dir_all(evidence_dir).map_err(|error| error.to_string())?;
    let candidate = std::env::var_os("KESFORGE_CANDIDATE_ROOT")
        .map(|path| evidence::load_current(Path::new(&path)))
        .transpose()?
        .map(|frozen| frozen.candidate);
    let report = Report {
        version: 1,
        campaign: "public-network",
        network: network.to_owned(),
        verdict: "measurement-unavailable",
        candidate,
        scenarios: SCENARIOS.to_vec(),
        unavailable: vec![
            "actual public-network opportunities and elapsed time",
            "independently observed accepted block hashes",
            "two complete actual KES periods without accelerated substitution",
            "mainnet operator approval remains a separate decision",
        ],
        completed: false,
        evidence: evidence_dir.to_path_buf(),
    };
    evidence::write_new_json(
        &evidence_dir.join(format!("public-network-{network}.json")),
        &report,
    )?;
    Ok(report)
}
