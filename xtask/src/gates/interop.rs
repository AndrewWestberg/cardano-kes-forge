//! Independent native-oracle interoperability gate.
use super::behavior::{
    Producer, Runtime, exact_scopes, finish, plan, producer, producer_build, succeeded, uint, yes,
};
use crate::acceptance::Report;
use crate::evidence::{Frozen, Gate, Result};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    build: String,
    target: Producer,
}

pub fn run(frozen: &Frozen, gate: &Gate, out_dir: &Path) -> Result<Report> {
    let configuration: Plan = plan(frozen, gate)?;
    producer_build(&configuration.target, &configuration.build)?;
    let build = super::behavior::build(frozen, &configuration.build)?;
    if !build
        .features
        .iter()
        .any(|feature| feature == "native-oracles")
    {
        return Err("unavailable: interoperability build lacks native-oracles".into());
    }
    exact_scopes(gate, ["native-crypto".to_owned()].into_iter())?;
    let runtime = Runtime::new(frozen, gate)?;
    let sensitivity = super::behavior::calibration(
        frozen,
        &runtime,
        &configuration.target,
        &[super::sensitivity::CORRUPTED_SIGNATURE],
    )?;
    let (summary, output) = producer(frozen, &runtime, &configuration.target, "clean")?;
    succeeded(&output)?;
    if summary.scenarios.len() != 1
        || summary.scenarios.get("native-crypto") != Some(&summary.cases)
        || uint(&summary.measurements, "violations")? != 0
    {
        return Err("native interoperability producer scope or result is invalid".into());
    }
    yes(&summary.measurements, "unmodified_cli_11_4")?;
    let object = summary
        .measurements
        .as_object()
        .ok_or("native interoperability measurements are not an object")?;
    let mut measurements: BTreeMap<String, Value> = object
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    measurements.insert("sensitivity".into(), sensitivity);
    measurements.insert("sensitivity_passed".into(), json!(true));
    finish(
        frozen,
        gate,
        out_dir,
        summary.cases,
        summary.scenarios,
        measurements,
    )
}
