//! Replacement-device and backup rehearsal campaign (US5/T099).
//!
//! Recovery/offline-producer behavior is exercised on the host. Accepted blocks
//! from a recovered key with the original Pico disconnected, and fresh-device
//! provisioning plus a newly issued certificate, require live hardware and a
//! running node and are therefore unavailable.
use super::campaign::{self, CampaignReport, Run};
use crate::evidence::Result;
use std::fs;
use std::path::Path;

const SCENARIOS: &[&str] = &[
    "same-certificate-disjoint-producer-intervals",
    "replacement-requires-fresh-trust-and-generation",
    "revoked-original-credential-cannot-reconnect",
    "missing-recipient-or-authentic-artifact-refused",
];

const UNAVAILABLE: &[&str] = &[
    "accepted conventional backup blocks with the original Pico disconnected",
    "fresh-device provisioning and newly issued certificate in service",
    "proof that no key import or rollback path exists on release hardware",
    "absent backup, recipient key and password recovery limits on live hardware",
];

pub fn run(evidence_dir: &Path) -> Result<CampaignReport> {
    let mut unavailable: Vec<String> = UNAVAILABLE
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
    if !swap_isolated() {
        unavailable.push(
            "no-swap disposable lab: run under a fresh cgroup-v2 unit with MemorySwapMax=0".into(),
        );
    }
    let runs = [Run {
        name: "device-replacement",
        program: "cargo",
        args: &[
            "test",
            "--locked",
            "-p",
            "cardano-kes-forge",
            "--test",
            "device_replacement",
            "--",
            "--test-threads=1",
        ],
        scenarios: SCENARIOS,
        cwd: None,
    }];
    campaign::run(evidence_dir, "replacement-software", &runs, unavailable)
}

fn swap_isolated() -> bool {
    let Ok(membership) = fs::read_to_string("/proc/self/cgroup") else {
        return false;
    };
    let Some(relative) = membership.lines().find_map(|line| line.strip_prefix("0::")) else {
        return false;
    };
    let root = Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/'));
    ["memory.swap.max", "memory.swap.current"]
        .iter()
        .all(|name| {
            fs::read_to_string(root.join(name))
                .map(|value| value.trim() == "0")
                .unwrap_or(false)
        })
}
