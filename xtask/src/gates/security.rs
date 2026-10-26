//! Foundation authorization, isolation, and session security gate.
use super::behavior::{Producer, Runtime, exact_scopes, finish, plan, producer, succeeded, uint};
use crate::acceptance::Report;
use crate::evidence::{Frozen, Gate, Result};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    targets: BTreeMap<String, Producer>,
}

fn sensitivity_mode(scenario: &str) -> Result<&'static str> {
    match scenario {
        "core-state" => Ok(super::sensitivity::CROSS_POOL_AUTHORIZATION),
        "native-crypto" => Ok(super::sensitivity::CORRUPTED_SIGNATURE),
        "frame" | "artifact" | "certificate" | "snapshot" | "session" => {
            Ok(super::sensitivity::PARSER_AUTHENTICATION_BYPASS)
        }
        _ => Err(format!(
            "unregistered foundation security scenario: {scenario}"
        )),
    }
}

pub fn run(frozen: &Frozen, gate: &Gate, out_dir: &Path) -> Result<Report> {
    if frozen.definition.increment != "foundation" {
        return Err(
            "unavailable: later security increments require the physical release-security runner"
                .into(),
        );
    }
    let configuration: Plan = plan(frozen, gate)?;
    exact_scopes(gate, configuration.targets.keys().cloned())?;
    let runtime = Runtime::new(frozen, gate)?;
    let mut scenarios = BTreeMap::new();
    let mut cases = 0u64;
    let mut sensitivity = BTreeMap::new();
    for (scenario, target) in configuration.targets {
        let mode = sensitivity_mode(&scenario)?;
        sensitivity.insert(
            scenario.clone(),
            super::behavior::calibration(frozen, &runtime, &target, &[mode])?,
        );
        let (summary, output) = producer(frozen, &runtime, &target, "clean")?;
        succeeded(&output)?;
        if summary.scenarios.len() != 1
            || summary.scenarios.get(&scenario) != Some(&summary.cases)
            || uint(&summary.measurements, "violations")? != 0
        {
            return Err("foundation security producer scope or result is invalid".into());
        }
        cases = cases
            .checked_add(summary.cases)
            .ok_or("security case count overflow")?;
        scenarios.insert(scenario, summary.cases);
    }
    let measurements = BTreeMap::<String, Value>::from([
        ("unauthorized_results".into(), json!(0)),
        ("all_required_security_cases".into(), json!(true)),
        ("sensitivity_passed".into(), json!(true)),
        ("sensitivity".into(), json!(sensitivity)),
        ("release_readiness".into(), json!(false)),
    ]);
    finish(frozen, gate, out_dir, cases, scenarios, measurements)
}
