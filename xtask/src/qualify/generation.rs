//! US1 clean-install generation and publication campaign.
//!
//! Software readings exercise the real operator CLI and daemon admission paths
//! through their behavioral test targets. A live device/enrollment ceremony,
//! two-pool service generation, byte comparison with the unmodified CLI and the
//! original-deadline load reading require the physical qualification fixture and
//! are reported as unavailable rather than inferred from these tests.
use super::campaign::{self, CampaignReport, Run};
use crate::evidence::Result;
use std::path::Path;

const SCENARIOS: &[&str] = &[
    "device-generation-surface",
    "lost-generation-response-reconciliation",
    "partial-output-repair",
    "artifact-pool-and-recipient-binding",
    "host-alias-and-plaintext-rejection",
    "pending-json-result",
    "daemon-peer-authorization-and-deadline",
];

const UNAVAILABLE: &[&str] = &[
    "attended clean-install bootstrap through the provisioning workstation",
    "two-pool live device generation through the real daemon and socket",
    "conventional unmodified CLI 11.4 generation comparison",
    "original service-admission and dispatch timing",
    "staged-capacity and entropy failure on fitted hardware",
    "authorized A2 disposable development smoke",
];

pub fn run(evidence_dir: &Path) -> Result<CampaignReport> {
    let runs = [
        Run {
            name: "generation-contract",
            program: "cargo",
            args: &[
                "test",
                "--locked",
                "-p",
                "cardano-kes-forge",
                "--test",
                "generation_contract",
            ],
            scenarios: &SCENARIOS[..6],
            cwd: None,
        },
        Run {
            name: "daemon-service",
            program: "cargo",
            args: &[
                "test",
                "--locked",
                "-p",
                "cardano-kes-forge",
                "--test",
                "daemon_service",
            ],
            scenarios: &SCENARIOS[6..],
            cwd: None,
        },
    ];
    campaign::run(
        evidence_dir,
        "generation-software",
        &runs,
        UNAVAILABLE
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
    )
}
