//! Shared sensitivity controls: clean readings plus bounded public counterexamples.
use super::behavior::{self, Producer, Runtime, Summary};
use super::tooling;
use crate::evidence::{Frozen, Result};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;

pub(crate) const CROSS_POOL_AUTHORIZATION: &str = "seeded-cross-pool-authorization";
pub(crate) const STALE_PERIOD: &str = "seeded-stale-period";
pub(crate) const CORRUPTED_SIGNATURE: &str = "seeded-corrupted-signature";
pub(crate) const LOST_ACKNOWLEDGED_COMMIT: &str = "seeded-drop-acknowledged-commit";
pub(crate) const ARTIFACT_AUTHENTICATION_OR_PUBLICATION: &str =
    "seeded-artifact-authentication-or-publication";
pub(crate) const AUTHORIZATION_OR_PUBLICATION: &str = "seeded-authorization-or-publication";
pub(crate) const SKIPPED_ERASE: &str = "seeded-skip-old-bank-erase";
pub(crate) const PARSER_AUTHENTICATION_BYPASS: &str = "seeded-semantic-authentication-bypass";
pub(crate) const UNEXECUTED_COVERAGE_PATH: &str = "seeded-unexecuted-coverage-path";
pub(crate) const CONTROLLED_TIMING_REGRESSION: &str = "seeded-controlled-timing-regression";

pub(crate) const FOUNDATIONAL_MODES: [&str; 8] = [
    CROSS_POOL_AUTHORIZATION,
    STALE_PERIOD,
    CORRUPTED_SIGNATURE,
    LOST_ACKNOWLEDGED_COMMIT,
    SKIPPED_ERASE,
    PARSER_AUTHENTICATION_BYPASS,
    UNEXECUTED_COVERAGE_PATH,
    CONTROLLED_TIMING_REGRESSION,
];

fn public_counterexample<'a>(summary: &'a Summary, mode: &str) -> Result<&'a Map<String, Value>> {
    let counterexample = summary.measurements["counterexample"]
        .as_object()
        .ok_or_else(|| format!("inactive detector: {mode} emitted no public counterexample"))?;
    if counterexample.len() != 4
        || counterexample.get("mode").and_then(Value::as_str) != Some(mode)
        || counterexample.get("disclosure").and_then(Value::as_str) != Some("public")
        || counterexample
            .get("path")
            .and_then(Value::as_str)
            .is_none_or(|value| value.is_empty() || value.len() > 128)
        || counterexample
            .get("observation")
            .and_then(Value::as_str)
            .is_none_or(|value| value.is_empty() || value.len() > 256)
    {
        return Err(format!("invalid public counterexample for {mode}"));
    }
    let encoded = serde_json::to_vec(counterexample)
        .map_err(|_| "cannot encode public counterexample".to_owned())?;
    if encoded.len() > 1024 {
        return Err(format!("oversized public counterexample for {mode}"));
    }
    Ok(counterexample)
}

pub(crate) fn detected(mode: &str, summary: &Summary, output: &tooling::Output) -> Result<Value> {
    if !FOUNDATIONAL_MODES.contains(&mode)
        && mode != ARTIFACT_AUTHENTICATION_OR_PUBLICATION
        && mode != AUTHORIZATION_OR_PUBLICATION
    {
        return Err(format!("unregistered sensitivity mode: {mode}"));
    }
    if !matches!(output.code, Some(code) if code > 0)
        || behavior::positive(&summary.measurements, "violations")? == 0
    {
        return Err(format!("inactive detector: {mode}"));
    }
    let counterexample = public_counterexample(summary, mode)?;
    Ok(json!({
        "exit": output.code,
        "violations": behavior::positive(&summary.measurements, "violations")?,
        "output_sha256": behavior::digest(&output.stdout),
        "counterexample": counterexample,
    }))
}

pub(crate) fn calibration(
    frozen: &Frozen,
    runtime: &Runtime,
    target: &Producer,
    modes: &[&str],
) -> Result<Value> {
    let unique: BTreeSet<_> = modes.iter().copied().collect();
    if modes.is_empty() || unique.len() != modes.len() {
        return Err("sensitivity calibration requires unique nonempty modes".into());
    }
    let (clean, output) = behavior::producer(frozen, runtime, target, "clean")?;
    behavior::succeeded(&output)?;
    if behavior::uint(&clean.measurements, "violations")? != 0 {
        return Err("calibration clean candidate has violations".into());
    }
    let clean = json!({
        "cases": clean.cases,
        "exit": output.code,
        "output_sha256": behavior::digest(&output.stdout),
    });
    let mut probes = BTreeMap::new();
    for mode in modes {
        let (seeded, output) = behavior::producer(frozen, runtime, target, mode)?;
        probes.insert(*mode, detected(mode, &seeded, &output)?);
    }
    Ok(json!({"clean":clean,"clean_cases":clean["cases"],"probes":probes}))
}

/// Exercise the actual recovery/publication implementation with one omitted
/// device-signature result check, exclusively in a hash-checked disposable source copy.
/// The source match locates the mutation; only executable behavior earns credit.
pub(crate) fn artifact_output_calibration(
    frozen: &Frozen,
    runtime: &Runtime,
    build_id: &str,
) -> Result<Value> {
    let config = behavior::build(frozen, build_id)?;
    if config.package != "cardano-kes-forge"
        || config
            .target
            .as_deref()
            .is_some_and(|t| t.starts_with("thumb"))
    {
        return Err(
            "artifact/output calibration requires an approved native cardano-kes-forge build"
                .into(),
        );
    }
    let target: Producer = serde_json::from_value(json!({
        "build": build_id,
        "target": "recovery_files",
    }))
    .map_err(|_| "cannot configure recovery behavioral producer")?;
    let (clean, clean_output) = behavior::producer(frozen, runtime, &target, "clean")?;
    behavior::succeeded(&clean_output)?;
    if behavior::uint(&clean.measurements, "violations")? != 0 {
        return Err("clean artifact/output recovery has violations".into());
    }

    let root = runtime.path.join("artifact-output-source");
    behavior::copy_candidate(frozen, &root)?;
    let source_path = root.join("src/backup/recover.rs");
    let source = fs::read_to_string(&source_path)
        .map_err(|_| "unavailable: artifact authentication implementation missing")?;
    let check = "    verify_signature(map, expected.identity_public_key)?;";
    if source.matches(check).count() != 1 {
        return Err(
            "unavailable: artifact signature omission no longer has a unique insertion point"
                .into(),
        );
    }
    let mutated = source.replacen(
        check,
        "    let _ = verify_signature(map, expected.identity_public_key);",
        1,
    );
    fs::write(&source_path, &mutated)
        .map_err(|_| "cannot seed disposable artifact authentication omission")?;
    // This clone changes only the execution root, never the stored frozen
    // identity or original workspace. The changed source is explicitly reported.
    let mut seeded = frozen.clone();
    seeded.workspace = root;
    let (summary, output) = behavior::producer(
        &seeded,
        runtime,
        &target,
        ARTIFACT_AUTHENTICATION_OR_PUBLICATION,
    )?;
    let detection = detected(ARTIFACT_AUTHENTICATION_OR_PUBLICATION, &summary, &output)?;
    Ok(json!({
        "clean": {
            "cases": clean.cases,
            "exit": clean_output.code,
            "output_sha256": behavior::digest(&clean_output.stdout),
        },
        "probe": detection,
        "seed": {
            "source": "src/backup/recover.rs",
            "defect": "ignored-device-signature-verification-result",
            "original_sha256": behavior::digest(source.as_bytes()),
            "mutated_sha256": behavior::digest(mutated.as_bytes()),
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foundational_inventory_is_exact_and_unique() {
        assert_eq!(FOUNDATIONAL_MODES.len(), 8);
        assert_eq!(
            FOUNDATIONAL_MODES
                .into_iter()
                .collect::<BTreeSet<_>>()
                .len(),
            FOUNDATIONAL_MODES.len()
        );
    }

    fn output(code: i32) -> tooling::Output {
        tooling::Output {
            code: Some(code),
            stdout: b"public output".to_vec(),
            stderr: Vec::new(),
            timed_out: false,
            duration_ms: 1,
        }
    }

    fn summary(counterexample: Value) -> Summary {
        Summary {
            version: 1,
            cases: 1,
            scenarios: BTreeMap::from([("public".into(), 1)]),
            measurements: json!({"violations":1,"counterexample":counterexample}),
        }
    }

    #[test]
    fn detector_requires_a_bounded_public_counterexample() {
        let valid = summary(json!({
            "mode": CROSS_POOL_AUTHORIZATION,
            "path": "kes-core.lifecycle.stage",
            "observation": "foreign pool authorization accepted",
            "disclosure": "public"
        }));
        assert!(detected(CROSS_POOL_AUTHORIZATION, &valid, &output(101)).is_ok());
        let missing = summary(json!({
            "mode": CROSS_POOL_AUTHORIZATION,
            "path": "kes-core.lifecycle.stage",
            "disclosure": "public"
        }));
        assert!(detected(CROSS_POOL_AUTHORIZATION, &missing, &output(101)).is_err());
        assert!(detected(CROSS_POOL_AUTHORIZATION, &valid, &output(0)).is_err());
    }
}
