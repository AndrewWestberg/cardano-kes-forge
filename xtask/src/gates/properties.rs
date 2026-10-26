//! Lifecycle properties require target-generated accepted-case accounting, never PROPTEST_CASES alone.
use super::{
    behavior::{self, Producer, Runtime},
    sensitivity,
};
use crate::acceptance::Report;
use crate::evidence::{Frozen, Gate, Result};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    producer: Producer,
    transitions: Vec<String>,
}

pub fn run(frozen: &Frozen, gate: &Gate, out_dir: &Path) -> Result<Report> {
    let plan: Plan = behavior::plan(frozen, gate)?;
    let transitions: BTreeSet<_> = plan.transitions.iter().collect();
    if transitions.is_empty() || transitions.len() != plan.transitions.len() {
        return Err(
            "unavailable: complete nonempty lifecycle transition inventory required".into(),
        );
    }
    let runtime = Runtime::new(frozen, gate)?;
    let (clean, output) = behavior::producer(frozen, &runtime, &plan.producer, "clean")?;
    behavior::succeeded(&output)?;
    behavior::exact_scopes(gate, clean.scenarios.keys().cloned())?;
    let m = &clean.measurements;
    if !frozen
        .identity
        .source_inventory
        .dependencies
        .iter()
        .any(|(id, dependency)| {
            id.ends_with("#proptest@1.11.0")
                && frozen
                    .identity
                    .source_inventory
                    .compiled_inputs
                    .keys()
                    .any(|path| path.starts_with(&dependency.root))
        })
    {
        return Err("unavailable: source inventory must bind actually compiled proptest 1.11.0 dependency sources".into());
    }
    if m["proptest_version"].as_str() != Some("1.11.0") {
        return Err("unavailable: lifecycle target must use proptest 1.11.0".into());
    }
    let accepted = behavior::positive(m, "accepted_sequences")?;
    let minimum = behavior::positive(m, "minimum_sequence_length")?;
    let maximum = behavior::positive(m, "maximum_sequence_length")?;
    if accepted != clean.cases
        || accepted < 10000
        || minimum > maximum
        || maximum > 256
        || behavior::uint(m, "pool_count")? != 32
        || behavior::uint(m, "violations")? != 0
    {
        return Err("lifecycle accepted workload or invariants failed".into());
    }
    let counts = m["transitions"]
        .as_object()
        .ok_or("missing actual transition counts")?;
    if counts.keys().collect::<BTreeSet<_>>() != transitions
        || counts.values().any(|v| v.as_u64().is_none_or(|n| n == 0))
    {
        return Err("lifecycle transition coverage incomplete".into());
    }
    let rejected = behavior::uint(m, "rejected_sequences")?;
    let shrinks = behavior::uint(m, "shrink_iterations")?;
    let mut sensitivity_readings = BTreeMap::new();
    for mode in [
        sensitivity::CROSS_POOL_AUTHORIZATION,
        sensitivity::STALE_PERIOD,
    ] {
        let (defect, output) = behavior::producer(frozen, &runtime, &plan.producer, mode)?;
        sensitivity_readings.insert(mode, sensitivity::detected(mode, &defect, &output)?);
    }
    let measurements: BTreeMap<String, Value> = BTreeMap::from([
        ("minimum_sequence_length".into(), json!(minimum)),
        ("maximum_sequence_length".into(), json!(maximum)),
        ("pool_count".into(), json!(32)),
        ("violations".into(), json!(0)),
        ("accepted_sequences".into(), json!(accepted)),
        ("rejected_sequences".into(), json!(rejected)),
        ("shrink_iterations".into(), json!(shrinks)),
        ("all_transitions_exercised".into(), json!(true)),
        ("transitions".into(), json!(counts)),
        ("proptest_version".into(), json!("1.11.0")),
        ("sensitivity".into(), json!(sensitivity_readings)),
    ]);
    behavior::finish(
        frozen,
        gate,
        out_dir,
        accepted,
        clean.scenarios,
        measurements,
    )
}
