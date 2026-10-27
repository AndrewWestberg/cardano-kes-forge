//! SC-012 telemetry and freshness campaign (US4/T088).
//!
//! Host observation/latency behavior is exercised through the public status and
//! observation tests. Native tracer/metric output, a live mixed node, connected
//! but stale clients and the unmodified offline CLI require the qualification
//! fixture and are reported as unavailable.
use super::campaign::{self, CampaignReport, Run};
use crate::evidence::Result;
use std::path::Path;

const SCENARIOS: &[&str] = &[
    "observation-unavailable-fresh-stale-and-invalidated",
    "matching-context-and-revision-readiness",
    "confirmed-evolution-never-regresses",
    "retired-generation-cannot-return",
    "latency-original-duration-and-freshness",
    "certificate-bounds-and-expired-readiness",
];

const UNAVAILABLE: &[&str] = &[
    "native tracer and metric output against one mixed node",
    "connected-but-stale and context-reset status through actual clients",
    "repeated STATUS not refreshing diagnostics",
    "offline unmodified CLI 11.4 kes-period-info comparison",
    "zero wrong-pool, wrong-generation or secret outputs over the full matrix",
];

pub fn run(evidence_dir: &Path) -> Result<CampaignReport> {
    let runs = [Run {
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
        scenarios: SCENARIOS,
        cwd: None,
    }];
    campaign::run(
        evidence_dir,
        "telemetry-software",
        &runs,
        UNAVAILABLE
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
    )
}
