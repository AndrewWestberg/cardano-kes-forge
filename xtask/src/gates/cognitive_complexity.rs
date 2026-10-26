use super::{tooling, unavailable};
use crate::acceptance::{Report, Verdict};
use crate::evidence::{Frozen, Gate, Result};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

pub(crate) fn remaining(start: Instant, budget: u64) -> Result<u64> {
    let elapsed = u64::try_from(start.elapsed().as_millis()).map_err(|_| "duration overflow")?;
    budget
        .checked_sub(elapsed)
        .filter(|value| *value > 0)
        .ok_or_else(|| "gate execution budget exhausted".into())
}

fn probe_source(branches: usize, attribute: &str) -> String {
    let mut text = format!(
        "{attribute}\npub fn probe(flags: &[bool; {branches}]) -> u32 {{\nlet mut count = 0;\n"
    );
    for index in 0..branches {
        text.push_str(&format!("if flags[{index}] {{ count += 1; }}\n"));
    }
    text.push_str("count\n}\n");
    text
}

pub(crate) fn sensitivity(
    root: &Path,
    runtime: &Path,
    start: Instant,
    budget: u64,
) -> Result<(bool, Value)> {
    let driver = tooling::pinned_tool("1.99.1", "clippy-driver", remaining(start, budget)?)?;
    let mut readings = serde_json::Map::new();
    let mut passed = true;
    for (name, branches, attribute, clean) in [
        // Pinned Clippy starts at one and adds one for each independent if.
        ("boundary", 24, "", true),
        ("above", 25, "", false),
        ("allow", 25, "#[allow(clippy::cognitive_complexity)]", false),
        (
            "expect",
            25,
            "#[expect(clippy::cognitive_complexity)]",
            false,
        ),
    ] {
        let directory = runtime.join(name);
        fs::create_dir(&directory).map_err(|error| error.to_string())?;
        let source = directory.join("probe.rs");
        fs::write(&source, probe_source(branches, attribute)).map_err(|error| error.to_string())?;
        let output = tooling::run(
            Command::new(&driver)
                .arg(&source)
                .args([
                    "--crate-type=lib",
                    "--edition=2024",
                    "--emit=metadata",
                    "--error-format=json",
                    "-D",
                    "warnings",
                    "-F",
                    "clippy::cognitive_complexity",
                ])
                .arg("--out-dir")
                .arg(&directory)
                .env("CLIPPY_CONF_DIR", root),
            remaining(start, budget)?,
        )?;
        let diagnostics = tooling::diagnostic_count(&output, "clippy::cognitive_complexity");
        let suppressed_rejected = tooling::diagnostic_count(&output, "E0453") > 0
            || String::from_utf8_lossy(&output.stderr)
                .contains("incompatible with previous forbid");
        let detected = if clean {
            tooling::success(&output) && diagnostics == 0
        } else if attribute.is_empty() {
            !tooling::success(&output) && !output.timed_out && diagnostics > 0
        } else {
            !tooling::success(&output) && !output.timed_out && suppressed_rejected
        };
        passed &= detected;
        readings.insert(name.into(), json!({"expected_complexity":branches + 1,"source_sha256":crate::evidence::file_hash(&source)?,"detected":detected,"reading":tooling::reading(&output)}));
    }
    Ok((passed, Value::Object(readings)))
}

pub fn run(frozen: &Frozen, gate: &Gate, out_dir: &Path) -> Result<Report> {
    let start = Instant::now();
    let mut result = unavailable(frozen, gate, "G12 prerequisites not measured");
    if let Err(reason) = measure(frozen, gate, out_dir, start, &mut result) {
        result.measurements.insert("reason".into(), json!(reason));
    }
    Ok(result)
}

fn measure(
    frozen: &Frozen,
    gate: &Gate,
    _out_dir: &Path,
    start: Instant,
    result: &mut Report,
) -> Result<()> {
    if frozen.definition.source_builds.is_empty() {
        return Err(
            "G12 requires a nonempty frozen source-build inventory, including setup controls"
                .into(),
        );
    }
    let config_hash = tooling::config(&frozen.workspace)?;
    let runtime_guard = tooling::runtime_directory(frozen, gate)?;
    let runtime = &runtime_guard.path;
    result.measurements.extend([
        ("threshold".into(), json!(25)),
        ("clippy_config_sha256".into(), json!(config_hash)),
        ("builds".into(), Value::Object(serde_json::Map::new())),
        ("tools".into(), Value::Object(serde_json::Map::new())),
    ]);
    let mut cases = 0;
    let mut clean = true;
    for build in &frozen.definition.source_builds {
        tooling::lint_flags(&build.rustflags)?;
        let tool_reading =
            tooling::validate_tools(&build.toolchain, remaining(start, gate.budget_ms)?)?;
        result
            .measurements
            .get_mut("tools")
            .and_then(Value::as_object_mut)
            .ok_or("internal tool reading object missing")?
            .insert(build.toolchain.clone(), tool_reading);
        let mut command = crate::source_inventory::cargo_command(
            build,
            &frozen.workspace,
            "clippy",
            &runtime.join(tooling::component(&build.id)),
            None,
        )?;
        command
            .arg("--message-format=json")
            .args(["--", "-D", "warnings", "-F", "clippy::cognitive_complexity"])
            .env("CLIPPY_CONF_DIR", &frozen.workspace);
        let output = tooling::run(&mut command, remaining(start, gate.budget_ms)?)?;
        clean &= tooling::success(&output);
        cases += 1;
        result.cases = cases;
        result
            .measurements
            .get_mut("builds")
            .and_then(Value::as_object_mut)
            .ok_or("internal complexity reading object missing")?
            .insert(build.id.clone(), tooling::reading(&output));
    }
    let (sensitive, probes) = sensitivity(&frozen.workspace, runtime, start, gate.budget_ms)?;
    result.measurements.extend([
        ("sensitivity".into(), probes),
        ("sensitivity_passed".into(), json!(sensitive)),
        (
            "maximum_complexity".into(),
            if clean { json!(25) } else { Value::Null },
        ),
        ("complexity_is_upper_bound".into(), json!(clean)),
        (
            "maximum_complexity_kind".into(),
            json!(if clean {
                "proved-upper-bound"
            } else {
                "unavailable"
            }),
        ),
        ("physical_firmware_acceptance".into(), json!(false)),
    ]);
    let expected: std::collections::BTreeSet<_> = frozen
        .definition
        .source_builds
        .iter()
        .map(|build| build.id.as_str())
        .collect();
    let scenarios: BTreeMap<_, _> = gate
        .scenarios
        .iter()
        .filter(|name| expected.contains(name.as_str()))
        .map(|name| (name.clone(), 1))
        .collect();
    let scope_complete = scenarios.len() == gate.scenarios.len() && !scenarios.is_empty();
    result.scenarios = scenarios;
    result.verdict = Verdict::Pass;
    result.completed = true;
    result.measurements.remove("reason");
    if !clean || !sensitive || !scope_complete || cases < gate.minimum_cases {
        result.verdict = Verdict::Fail;
        result.completed = false;
    }
    Ok(())
}
