//! Single-operator immediate/scheduled rotation campaign (SC-006).
//!
//! The software readings exercise activation/schedule transitions and public
//! status/observation behavior. The ten-minute wall-clock criterion, sequence of
//! device/daemon/node restarts and zero unaffected-pool misses require the live
//! fixture and are reported as unavailable.
use super::campaign::{self, CampaignReport, Run};
use crate::evidence::Result;
use std::path::Path;

const SCENARIOS: &[&str] = &[
    "activation-intent-and-certificate-binding",
    "scheduled-activation",
    "replacement-generation-activation",
    "public-status-and-latency-fields",
];

const UNAVAILABLE: &[&str] = &[
    "certificate-ready action within ten minutes by one operator",
    "no additional authority beyond the pool certificate",
    "schedule followed by device, daemon and node restart without human action",
    "zero signer-related misses for unaffected pools",
    "backup forward-security and non-overlapping producer understanding",
];

pub fn run(evidence_dir: &Path) -> Result<CampaignReport> {
    let runs = [
        Run {
            name: "rotation",
            program: "cargo",
            args: &["test", "--locked", "-p", "kes-core", "--test", "rotation"],
            scenarios: &SCENARIOS[..3],
            cwd: None,
        },
        Run {
            name: "operator-status",
            program: "cargo",
            args: &[
                "test",
                "--locked",
                "-p",
                "cardano-kes-forge",
                "--test",
                "operator_status",
            ],
            scenarios: &SCENARIOS[3..],
            cwd: None,
        },
    ];
    campaign::run(
        evidence_dir,
        "rotation-software",
        &runs,
        UNAVAILABLE
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
    )
}
