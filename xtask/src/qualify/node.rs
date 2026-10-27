//! Mixed-node signing, outage and backup-producer campaign (US2/T066).
//!
//! The public fixture is validated before any measurement. Live blocks, outage
//! isolation and recovered-key backup blocks require a running mixed node, a
//! paired Pico and a controlled network; those readings are explicitly
//! unavailable here. The software targets exercise source selection, per-entry
//! authorization, typed failures and reconnect reconciliation only.
use super::campaign::{self, CampaignReport, Run};
use crate::evidence::Result;
use crate::fixture::ScenarioManifest;
use std::fs;
use std::path::Path;

const SCENARIOS: &[&str] = &[
    "mixed-file-and-device-source-selection",
    "per-entry-authorization-and-contention",
    "independent-signature-validation",
    "typed-source-failure-isolation",
    "unattended-reconnect-reconciliation",
];

const UNAVAILABLE: &[&str] = &[
    "one mixed-node PID with at least ten independently accepted blocks per pool",
    "outage opportunities for every file pool with zero induced misses",
    "one accepted device block after reconnect without a PID change",
    "same-certificate recovered-key accepted blocks with the Pico disconnected",
    "native cardano-node and consensus KesForge test components",
];

pub fn run(fixture: &Path, evidence_dir: &Path) -> Result<CampaignReport> {
    validate(fixture)?;
    let runs = [
        Run {
            name: "signing-routing",
            program: "cargo",
            args: &[
                "test",
                "--locked",
                "-p",
                "cardano-kes-forge",
                "--test",
                "signing_routing",
            ],
            scenarios: &SCENARIOS[..2],
            cwd: None,
        },
        Run {
            name: "daemon-signing",
            program: "cargo",
            args: &[
                "test",
                "--locked",
                "-p",
                "cardano-kes-forge",
                "--test",
                "daemon_signing",
            ],
            scenarios: &SCENARIOS[2..4],
            cwd: None,
        },
        Run {
            name: "reconnect-recovery",
            program: "cargo",
            args: &[
                "test",
                "--locked",
                "-p",
                "cardano-kes-forge",
                "--test",
                "reconnect_recovery",
            ],
            scenarios: &SCENARIOS[4..],
            cwd: None,
        },
    ];
    campaign::run(
        evidence_dir,
        "node-software",
        &runs,
        UNAVAILABLE
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
    )
}

/// Parse and bound the public scenario before any campaign consumes it.
pub fn validate(path: &Path) -> Result<ScenarioManifest> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.len() > 1_048_576 {
        return Err("scenario fixture must be a bounded regular file".into());
    }
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    let manifest: ScenarioManifest = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid scenario fixture: {error}"))?;
    if manifest.version != 1
        || !manifest.disposable
        || manifest.pools.len() != kes_core::MAX_POOLS
        || manifest.peers[0].name == manifest.peers[1].name
    {
        return Err("scenario fixture is not a complete disposable 32-pool declaration".into());
    }
    Ok(manifest)
}
