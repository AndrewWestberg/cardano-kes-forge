//! Exhaustive software fault campaigns are real readings, but never physical G8 acceptance.
use super::behavior::{self, Producer, Runtime};
use crate::acceptance::{Report, Verdict};
use crate::evidence::{Frozen, Gate, Result};
use serde::Deserialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    producer: Producer,
    cut_points: Vec<String>,
}

pub fn run(frozen: &Frozen, gate: &Gate, _out_dir: &Path) -> Result<Report> {
    let plan: Plan = behavior::plan(frozen, gate)?;
    let expected: BTreeSet<_> = plan.cut_points.iter().collect();
    if expected.is_empty() || expected.len() != plan.cut_points.len() {
        return Err(
            "unavailable: exhaustive nonempty software transaction cut inventory required".into(),
        );
    }
    let runtime = Runtime::new(frozen, gate)?;
    let sensitivity = behavior::calibration(
        frozen,
        &runtime,
        &plan.producer,
        &[
            "seeded-drop-acknowledged-commit",
            "seeded-skip-old-bank-erase",
        ],
    )?;
    let (summary, output) =
        behavior::producer(frozen, &runtime, &plan.producer, "software-fault-campaign")?;
    behavior::succeeded(&output)?;
    behavior::exact_scopes(gate, summary.scenarios.keys().cloned())?;
    let m = &summary.measurements;
    let cut_points = m["software_cut_points"]
        .as_object()
        .ok_or("unavailable: missing actual software cut-point readings")?;
    if cut_points.keys().collect::<BTreeSet<_>>() != expected
        || cut_points
            .values()
            .any(|v| v.as_u64().is_none_or(|n| n == 0))
    {
        return Err("incomplete exhaustive software fault campaign".into());
    }
    let actual = cut_points.values().try_fold(0u64, |total, count| {
        total
            .checked_add(count.as_u64().ok_or("invalid cut-point count")?)
            .ok_or("cut-point count overflow")
    })?;
    if actual != summary.cases {
        return Err("software fault case totals disagree".into());
    }
    let pool_local_quarantines = behavior::uint(m, "pool_local_quarantines")?;
    let quarantined = cut_points["quarantined"]
        .as_u64()
        .ok_or("invalid quarantined cut-point count")?;
    if pool_local_quarantines != quarantined || pool_local_quarantines == 0 {
        return Err(
            "software fault campaign did not prove pool-local quarantine accounting".into(),
        );
    }
    let device_wide_corruptions = behavior::uint(m, "device_wide_corruptions")?;
    if device_wide_corruptions != 0 {
        return Err("software fault campaign escalated pool-local damage device-wide".into());
    }
    behavior::yes(m, "disposable_fixture_authorized")?;
    if m["network"].as_str() != Some("controlled") {
        return Err("destructive software faults require controlled disposable fixtures, never production/mainnet".into());
    }
    for name in [
        "ack_regressions",
        "lost_retained_artifacts",
        "cross_pool_mutations",
        "partial_plaintext_publications",
        "recovery_failures",
    ] {
        if behavior::uint(m, name)? != 0 {
            return Err(format!("software fault invariant violated: {name}"));
        }
    }
    let mut result = super::report(
        frozen,
        gate,
        summary.cases,
        summary.scenarios,
        BTreeMap::from([
            ("all_software_cut_points".into(), json!(true)),
            ("software_cut_points".into(), json!(cut_points)),
            ("ack_regressions".into(), json!(0)),
            ("lost_retained_artifacts".into(), json!(0)),
            ("cross_pool_mutations".into(), json!(0)),
            ("partial_plaintext_publications".into(), json!(0)),
            ("recovery_failures".into(), json!(0)),
            (
                "pool_local_quarantines".into(),
                json!(pool_local_quarantines),
            ),
            (
                "device_wide_corruptions".into(),
                json!(device_wide_corruptions),
            ),
            ("sensitivity".into(), sensitivity),
            ("physical_status".into(), json!("unavailable")),
            (
                "reason".into(),
                json!(
                    "software cut points measured only; T022/T047/T066 qualified physical runner, hardware, occupancy/cut schedule and calibration remain required"
                ),
            ),
        ]),
    );
    result.verdict = Verdict::Unavailable;
    result.completed = false;
    Ok(result)
}
