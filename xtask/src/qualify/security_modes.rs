//! Reversible A2 development security-mode qualification.
//!
//! This runner never invokes picotool, writes OTP, or claims release security.
//! The operator flashes the disposable image through BOOTSEL before requesting
//! the hardware lane. Complete release security remains an A4-only campaign.

use crate::evidence;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};

const HARDWARE_TEST: &str = "authenticated_a2_info_open_status_fail_closed_and_reopen";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseDisposition {
    Pass,
    NotRun,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CaseEvidence {
    pub id: &'static str,
    pub disposition: CaseDisposition,
    pub command: &'static str,
    pub output_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SecurityModesReport {
    pub version: u8,
    pub campaign: &'static str,
    pub verdict: &'static str,
    pub silicon_revision: &'static str,
    pub otp_mutated: bool,
    pub release_qualified: bool,
    pub cases: Vec<CaseEvidence>,
    pub deferred_to_a4: Vec<&'static str>,
}

pub fn run(evidence_dir: &Path, hardware: bool) -> evidence::Result<SecurityModesReport> {
    if std::env::var_os("KESFORGE_CANDIDATE_ROOT").is_some() {
        return Err(
            "A2 security-mode qualification is development evidence, not frozen release evidence"
                .to_owned(),
        );
    }
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("xtask manifest has no workspace parent")?
        .to_path_buf();
    let mut cases = Vec::with_capacity(3);
    cases.push(run_test(
        &workspace,
        "policy",
        "cargo test --test security_mode_qualification",
        &["test", "--test", "security_mode_qualification"],
    )?);
    cases.push(run_test(
        &workspace,
        "authenticated-software",
        "cargo test --test development_bootstrap",
        &["test", "--test", "development_bootstrap"],
    )?);
    if hardware {
        cases.push(run_test(
            &workspace,
            "authenticated-a2",
            "cargo test --test a2_development_hardware -- --ignored --exact authenticated_a2_info_open_status_fail_closed_and_reopen",
            &[
                "test",
                "--test",
                "a2_development_hardware",
                "--",
                "--ignored",
                "--exact",
                HARDWARE_TEST,
            ],
        )?);
    } else {
        cases.push(CaseEvidence {
            id: "authenticated-a2",
            disposition: CaseDisposition::NotRun,
            command: "cargo test --test a2_development_hardware -- --ignored --exact authenticated_a2_info_open_status_fail_closed_and_reopen",
            output_sha256: None,
        });
    }
    let report = SecurityModesReport {
        version: 1,
        campaign: "security-modes-a2-development",
        verdict: if hardware {
            "development-pass"
        } else {
            "software-pass-hardware-not-run"
        },
        silicon_revision: "A2",
        otp_mutated: false,
        release_qualified: false,
        cases,
        deferred_to_a4: vec![
            "secure boot",
            "debug and secure-debug lock",
            "DMA isolation",
            "OTP provisioning and lock readback",
            "signed update, downgrade, rollback, and interrupted update",
            "release-ready transition and post-lockdown service",
        ],
    };
    std::fs::create_dir_all(evidence_dir)
        .map_err(|error| format!("create security-mode evidence directory: {error}"))?;
    evidence::write_new_json(&evidence_dir.join("security-modes.json"), &report)?;
    Ok(report)
}

fn run_test(
    workspace: &Path,
    id: &'static str,
    command: &'static str,
    arguments: &[&str],
) -> evidence::Result<CaseEvidence> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .args(arguments)
        .current_dir(workspace)
        .output()
        .map_err(|error| format!("execute {id} qualification case: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{id} qualification case failed: {}",
            bounded_stderr(&output)
        ));
    }
    let mut hash = Sha256::new();
    hash.update(&output.stdout);
    hash.update(&output.stderr);
    Ok(CaseEvidence {
        id,
        disposition: CaseDisposition::Pass,
        command,
        output_sha256: Some(format!("{:x}", hash.finalize())),
    })
}

fn bounded_stderr(output: &Output) -> String {
    let bytes = if output.stderr.len() > 4096 {
        &output.stderr[output.stderr.len() - 4096..]
    } else {
        &output.stderr
    };
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_schema_never_claims_a2_release_qualification() {
        let report = SecurityModesReport {
            version: 1,
            campaign: "security-modes-a2-development",
            verdict: "development-pass",
            silicon_revision: "A2",
            otp_mutated: false,
            release_qualified: false,
            cases: Vec::new(),
            deferred_to_a4: vec!["secure boot"],
        };
        let encoded = serde_json::to_value(report).unwrap();
        assert_eq!(encoded["release_qualified"], false);
        assert_eq!(encoded["otp_mutated"], false);
        assert_eq!(encoded["silicon_revision"], "A2");
    }
}
