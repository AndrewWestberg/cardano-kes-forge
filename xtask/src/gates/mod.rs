pub mod behavior;
pub mod build;
pub mod cognitive_complexity;
pub mod coverage;
pub mod faults;
pub mod fuzz;
pub mod interop;
pub mod mutation;
pub mod performance;
pub mod properties;
pub mod security;
pub mod sensitivity;
pub mod tooling;

use crate::acceptance::{Report, Verdict};
use crate::evidence::{Frozen, Gate, Result};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

type GateRunner = fn(&Frozen, &Gate, &Path) -> Result<Report>;

pub fn run(name: &str, frozen: &Frozen, gate: &Gate, out_dir: &Path) -> Result<Report> {
    let (id, runner): (&str, GateRunner) = match name {
        "build" => ("G1", build::run),
        "behavior" => ("G2", behavior::run),
        "properties" => ("G3", properties::run),
        "mutation" => ("G4", mutation::run),
        "coverage" => ("G5", coverage::run),
        "fuzz" => ("G6", fuzz::run),
        "faults" => ("G8", faults::run),
        "interop" => ("G7", interop::run),
        "security" => ("G9", security::run),
        "cognitive-complexity" => ("G12", cognitive_complexity::run),
        "performance" => ("P0", performance::run),
        "node" | "operators" | "public-network" | "load" => {
            return Ok(unavailable(
                frozen,
                gate,
                "real physical or interoperability runner is not implemented",
            ));
        }
        _ => {
            return Ok(unavailable(
                frozen,
                gate,
                &format!("unknown gate runner: {name}"),
            ));
        }
    };
    if gate.id != id {
        return Ok(unavailable(
            frozen,
            gate,
            &format!("runner {name} cannot measure {}", gate.id),
        ));
    }
    match runner(frozen, gate, out_dir) {
        Ok(value) => Ok(value),
        Err(reason) => Ok(unavailable(frozen, gate, &reason)),
    }
}

pub(crate) fn report(
    frozen: &Frozen,
    gate: &Gate,
    cases: u64,
    scenarios: BTreeMap<String, u64>,
    measurements: BTreeMap<String, Value>,
) -> Report {
    Report {
        version: 1,
        candidate: frozen.candidate.clone(),
        gate: gate.id.clone(),
        identity: frozen.identity.clone(),
        features: frozen.definition.features.clone(),
        scenarios,
        cases,
        verdict: Verdict::Pass,
        completed: true,
        hardware: None,
        measurements,
    }
}

pub(crate) fn unavailable(frozen: &Frozen, gate: &Gate, reason: &str) -> Report {
    let mut value = report(
        frozen,
        gate,
        0,
        BTreeMap::new(),
        BTreeMap::from([("reason".into(), Value::String(reason.into()))]),
    );
    value.verdict = Verdict::Unavailable;
    value.completed = false;
    value
}
