//! Release security and provisioning campaign (G9/T101/T109).
//!
//! Host-verifiable mode, authority-separation, custody and provisioning-binding
//! behavior is exercised. Physical silicon identification, secure-boot/OTP
//! readback, debug closure, negative access matrix, update rollback and
//! independent review require A4-or-later release hardware and are unavailable.
use super::campaign::{self, CampaignReport, Run};
use super::node;
use crate::evidence::Result;
use crate::fixture::ScenarioManifest;
use std::path::Path;

const SCENARIOS: &[&str] = &[
    "authority-and-machine-schema-separation",
    "private-custody-file-and-parent-permissions",
    "daemon-uid-connection-authorizations",
    "online-evidence-modes-and-no-release-downgrade",
    "provisioning-manifest-exact-bindings",
    "enrollment-precedes-daemon-configuration",
    "unlocked-a2-is-development-only",
];

const UNAVAILABLE: &[&str] = &[
    "A4-or-later silicon/ROM identification and trusted readback",
    "secure-boot key-slot validity and unsigned/development image refusal",
    "debug closure, alternate boot and OTP lock negative matrix",
    "SAU/MPU, ACCESSCTRL, DMA/XIP/QMI nonsecure access negatives",
    "TRNG health, glitch detector, BOD and RCP fail-stop checks",
    "signed update, rollback exhaustion and interrupted finalization",
    "independent review of adapted KES/HPKE/session transcripts",
];

pub fn run(fixture: &Path, evidence_dir: &Path) -> Result<CampaignReport> {
    let _: ScenarioManifest = node::validate(fixture)?;
    let runs = [
        Run {
            name: "security-modes",
            program: "cargo",
            args: &[
                "test",
                "--locked",
                "-p",
                "cardano-kes-forge",
                "--test",
                "security_modes",
            ],
            scenarios: &SCENARIOS[..6],
            cwd: None,
        },
        Run {
            name: "security-mode-qualification",
            program: "cargo",
            args: &[
                "test",
                "--locked",
                "-p",
                "cardano-kes-forge",
                "--test",
                "security_mode_qualification",
            ],
            scenarios: &SCENARIOS[6..],
            cwd: None,
        },
    ];
    campaign::run(
        evidence_dir,
        "security-software",
        &runs,
        UNAVAILABLE
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
    )
}
