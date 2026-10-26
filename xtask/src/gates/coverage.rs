//! Instrumented LLVM line readings, per approved crate/configuration and bound changed-line baselines.
use super::behavior::{self, Producer, Runtime};
use crate::acceptance::Report;
use crate::evidence::{self, Frozen, Gate, Result};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CratePlan {
    builds: Vec<String>,
    files: Vec<PathBuf>,
    changed_lines: BTreeMap<PathBuf, Vec<u64>>,
    changed_branches: Vec<String>,
    producers: BTreeMap<String, Producer>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    crates: BTreeMap<String, CratePlan>,
}
struct Reading {
    percent: f64,
    lines: u64,
    covered: u64,
    changed: f64,
}

fn parse(path: &Path, files: &[PathBuf], changed: &BTreeMap<PathBuf, Vec<u64>>) -> Result<Reading> {
    let value: Value = evidence::read_json(path)?;
    if value["type"].as_str() != Some("llvm.coverage.json.export")
        || value["cargo_llvm_cov"]["version"].as_str() != Some("0.9.1")
    {
        return Err("missing or incompatible cargo-llvm-cov export identity".into());
    }
    let exports = value["data"]
        .as_array()
        .ok_or("missing LLVM coverage data")?;
    let expected: BTreeSet<_> = files.iter().collect();
    if expected.is_empty() || expected.len() != files.len() {
        return Err("empty or duplicate approved coverage files".into());
    }
    let mut seen = BTreeSet::new();
    let mut lines = 0u64;
    let mut covered = 0u64;
    let mut changed_total = 0u64;
    let mut changed_covered = 0u64;
    for export in exports {
        for file in export["files"]
            .as_array()
            .ok_or("missing LLVM file readings")?
        {
            let filename = PathBuf::from(
                file["filename"]
                    .as_str()
                    .ok_or("missing LLVM source filename")?,
            );
            if !expected.contains(&filename) {
                continue;
            }
            if !seen.insert(filename.clone()) {
                return Err("duplicate LLVM source file reading".into());
            }
            let summary = &file["summary"]["lines"];
            let count = behavior::uint(summary, "count")?;
            let hit = behavior::uint(summary, "covered")?;
            if hit > count {
                return Err("invalid LLVM line counts".into());
            }
            lines += count;
            covered += hit;
            if let Some(changes) = changed.get(&filename) {
                let segments = file["segments"]
                    .as_array()
                    .ok_or("LLVM changed-line segments absent")?;
                let mut segment_rows = Vec::new();
                for segment in segments {
                    let row = segment.as_array().ok_or("malformed LLVM segment")?;
                    if row.len() != 6 {
                        return Err("malformed LLVM segment width".into());
                    }
                    segment_rows.push((
                        row[0].as_u64().ok_or("invalid segment line")?,
                        row[1].as_u64().ok_or("invalid segment column")?,
                        row[2].as_u64().ok_or("invalid segment count")?,
                        row[3].as_bool().ok_or("invalid segment has-count")?,
                        row[5].as_bool().ok_or("invalid segment gap")?,
                    ));
                }
                for line in changes {
                    if *line == 0 {
                        return Err("changed-line inventory contains zero line".into());
                    }
                    let mut executable = false;
                    let mut executed = false;
                    for (index, (start, _, count, has_count, gap)) in
                        segment_rows.iter().enumerate()
                    {
                        let end = segment_rows.get(index + 1).map(|r| (r.0, r.1));
                        let overlaps = *start <= *line
                            && end
                                .is_some_and(|(end, col)| end > *line || (end == *line && col > 1));
                        if overlaps && *has_count && !*gap {
                            executable = true;
                            executed |= *count > 0;
                        }
                    }
                    if !executable {
                        return Err(
                            "approved changed executable line absent from LLVM coverage".into()
                        );
                    }
                    changed_total += 1;
                    changed_covered += u64::from(executed);
                }
            }
        }
    }
    if seen != expected.into_iter().cloned().collect()
        || lines == 0
        || changed.keys().any(|p| !seen.contains(p))
    {
        return Err("coverage is empty or omits approved crate source".into());
    }
    let changed = if changed_total == 0 {
        100.0
    } else {
        100.0 * changed_covered as f64 / changed_total as f64
    };
    Ok(Reading {
        percent: 100.0 * covered as f64 / lines as f64,
        lines,
        covered,
        changed,
    })
}
fn collect(
    frozen: &Frozen,
    runtime: &Runtime,
    config: &crate::source_inventory::SourceBuild,
    workspace: &Path,
    output: &Path,
) -> Result<()> {
    if config
        .target
        .as_deref()
        .is_some_and(|t| t.starts_with("thumb"))
    {
        return Err(
            "unavailable: host LLVM coverage cannot measure physical firmware execution".into(),
        );
    }
    let mut command = behavior::plugin_command(frozen, runtime, config, workspace, "llvm-cov")?;
    command
        .args(["--json", "--output-path"])
        .arg(output)
        .env("PROPTEST_DISABLE_FAILURE_PERSISTENCE", "1")
        .env("KES_GATE_MODE", "coverage")
        .env("KES_GATE_RUNTIME", &runtime.path);
    behavior::succeeded(&runtime.execute(&mut command)?)
}
fn infrastructure(frozen: &Frozen, runtime: &Runtime) -> Result<(Reading, Value)> {
    let root = behavior::fixture(runtime)?;
    let config = behavior::fixture_build(frozen, &root)?;
    let files = vec![root.join("src/lib.rs")];
    let clean_path = runtime.path.join("coverage-control-clean.json");
    collect(frozen, runtime, &config, &root, &clean_path)?;
    let clean = parse(&clean_path, &files, &BTreeMap::new())?;
    if clean.percent < 90.0 {
        return Err("clean public infrastructure coverage control failed".into());
    }
    let mut source = fs::read_to_string(&files[0]).map_err(|_| "cannot read disposable control")?;
    source.push_str("\npub fn unexecuted_relevant_path(value:u64)->u64 {\n let a=value.wrapping_add(1);\n let b=a.wrapping_mul(3);\n let c=b.wrapping_add(5);\n let d=c.wrapping_mul(7);\n let e=d.wrapping_add(11);\n let f=e.wrapping_mul(13);\n let g=f.wrapping_add(17);\n let h=g.wrapping_mul(19);\n h.wrapping_add(23)\n}\n");
    fs::write(&files[0], source).map_err(|_| "cannot seed public uncovered-path control")?;
    let defect_path = runtime.path.join("coverage-control-defect.json");
    collect(frozen, runtime, &config, &root, &defect_path)?;
    let defect = parse(&defect_path, &files, &BTreeMap::new())?;
    if defect.percent >= 90.0 || defect.lines <= defect.covered {
        return Err("inactive coverage detector: unexecuted public path was not exposed".into());
    }
    let sensitivity = json!({
        "mode": super::sensitivity::UNEXECUTED_COVERAGE_PATH,
        "clean": {
            "line_percent": clean.percent,
            "covered_lines": clean.covered,
            "lines": clean.lines
        },
        "defect": {
            "line_percent": defect.percent,
            "uncovered_lines": defect.lines-defect.covered,
            "detected": true
        },
        "counterexample": {
            "mode": super::sensitivity::UNEXECUTED_COVERAGE_PATH,
            "path": "public-control.unexecuted_relevant_path",
            "observation": "a seeded eleven-line public path was absent from LLVM execution counts",
            "disclosure": "public"
        }
    });
    Ok((clean, sensitivity))
}
pub fn run(frozen: &Frozen, gate: &Gate, out_dir: &Path) -> Result<Report> {
    let runtime = Runtime::new(frozen, gate)?;
    behavior::pin_plugin(frozen, &runtime, "llvm-cov", "0.9.1")?;
    let (control, sensitivity) = infrastructure(frozen, &runtime)?;
    let mut crates = BTreeMap::new();
    let mut cases = 0u64;
    if frozen.definition.increment == "setup" {
        behavior::exact_scopes(gate, ["coverage".to_owned()].into_iter())?;
        if frozen.definition.coverage_baselines.get("coverage") != Some(&None) {
            return Err("setup public control requires approved initial coverage baseline".into());
        }
        cases = control.lines;
        crates.insert("coverage".to_owned(),json!({"line_coverage_percent":control.percent,"changed_line_coverage_percent":control.percent,"changed_branches_complete":true,"baseline_sha256":null,"lines":control.lines,"covered_lines":control.covered,"scope":"public-infrastructure-only"}));
    } else {
        let plan: Plan = behavior::plan(frozen, gate)?;
        behavior::exact_scopes(gate, plan.crates.keys().cloned())?;
        for (name, configuration) in plan.crates {
            if configuration.builds.is_empty() {
                return Err("unavailable: approved coverage build matrix absent".into());
            }
            let actual_builds: BTreeSet<_> =
                configuration.builds.iter().map(String::as_str).collect();
            let expected_builds: BTreeSet<_> = frozen
                .definition
                .source_builds
                .iter()
                .filter(|b| {
                    b.package == name && b.target.as_deref().is_none_or(|t| !t.starts_with("thumb"))
                })
                .map(|b| b.id.as_str())
                .collect();
            if actual_builds.len() != configuration.builds.len() || actual_builds != expected_builds
            {
                return Err(
                    "coverage omits or duplicates an approved native feature/target configuration"
                        .into(),
                );
            }
            if configuration
                .changed_lines
                .values()
                .any(|lines| lines.iter().collect::<BTreeSet<_>>().len() != lines.len())
            {
                return Err("duplicate changed executable line".into());
            }
            let files: Vec<_> = configuration
                .files
                .iter()
                .map(|p| evidence::resolve_input(&frozen.workspace, p))
                .collect::<Result<_>>()?;
            let first = behavior::build(frozen, &configuration.builds[0])?;
            let manifest = evidence::resolve_input(&frozen.workspace, &first.manifest_path)?;
            let source_root = manifest
                .parent()
                .ok_or("invalid crate manifest location")?
                .join("src");
            let compiled_sources: BTreeSet<_> = frozen
                .identity
                .source_inventory
                .compiled_inputs
                .keys()
                .filter(|path| {
                    path.starts_with(&source_root)
                        && path.extension().is_some_and(|extension| extension == "rs")
                })
                .collect();
            let approved_sources: BTreeSet<_> = files.iter().collect();
            if compiled_sources.is_empty() || !compiled_sources.is_subset(&approved_sources) {
                return Err(
                    "coverage file inventory omits compiled crate implementation sources".into(),
                );
            }
            let changed: BTreeMap<_, _> = configuration
                .changed_lines
                .iter()
                .map(|(p, lines)| {
                    Ok((
                        evidence::resolve_input(&frozen.workspace, p)?,
                        lines.clone(),
                    ))
                })
                .collect::<Result<_>>()?;
            let expected_branches: BTreeSet<_> = configuration.changed_branches.iter().collect();
            if expected_branches.len() != configuration.changed_branches.len() {
                return Err("duplicate changed-branch inventory".into());
            }
            if configuration
                .producers
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                != actual_builds
            {
                return Err("coverage requires one changed-branch producer per approved build configuration".into());
            }
            let mut percent = 100.0f64;
            let mut changed_percent = 100.0f64;
            let mut configurations = BTreeMap::new();
            for id in &configuration.builds {
                let config = behavior::build(frozen, id)?;
                if config.package != name {
                    return Err("coverage build belongs to another crate".into());
                }
                let producer = configuration
                    .producers
                    .get(id)
                    .ok_or("missing coverage configuration producer")?;
                behavior::producer_build(producer, id)?;
                let (public, producer_output) =
                    behavior::producer(frozen, &runtime, producer, "coverage")?;
                behavior::succeeded(&producer_output)?;
                if public.measurements["build"].as_str() != Some(id) {
                    return Err(
                        "coverage branch producer did not identify its actual build configuration"
                            .into(),
                    );
                }
                let branches = public.measurements["changed_branches"].as_object().ok_or(
                    "unavailable: actual per-configuration changed-branch readings absent",
                )?;
                if branches.keys().collect::<BTreeSet<_>>() != expected_branches
                    || branches.values().any(|v| v.as_u64().is_none_or(|n| n == 0))
                {
                    return Err("changed security/lifecycle branches not completely exercised in this configuration".into());
                }
                let output = runtime
                    .path
                    .join(format!("coverage-{}.json", super::tooling::component(id)));
                collect(frozen, &runtime, config, &frozen.workspace, &output)?;
                let reading = parse(&output, &files, &changed)?;
                if reading.percent < 90.0 {
                    return Err(format!(
                        "crate/configuration line coverage below 90%: {name}/{id}"
                    ));
                }
                percent = percent.min(reading.percent);
                changed_percent = changed_percent.min(reading.changed);
                cases += reading.lines;
                // Scenario accounting comes from the same actual instrumented line readings.
                configurations.insert(id,json!({"lines":reading.lines,"covered":reading.covered,"line_percent":reading.percent,"changed_line_percent":reading.changed,"changed_branches":branches,"branch_cases":public.cases,"export_sha256":evidence::file_hash(&output)?}));
            }
            let baseline = frozen
                .definition
                .coverage_baselines
                .get(&name)
                .ok_or("missing approved coverage baseline policy")?;
            let baseline_hash = baseline
                .as_ref()
                .map(|input| {
                    frozen
                        .identity
                        .inputs
                        .get(input)
                        .cloned()
                        .ok_or("missing frozen coverage baseline identity")
                })
                .transpose()?;
            let measured_lines = configurations.values().try_fold(0u64, |total, reading| {
                total
                    .checked_add(behavior::positive(reading, "lines")?)
                    .ok_or_else(|| "coverage count overflow".to_owned())
            })?;
            crates.insert(name,json!({"line_coverage_percent":percent,"changed_line_coverage_percent":changed_percent,"changed_branches_complete":true,"baseline_sha256":baseline_hash,"configurations":configurations,"lines":measured_lines}));
        }
    }
    let scenarios = crates
        .iter()
        .map(|(name, reading)| Ok((name.clone(), behavior::positive(reading, "lines")?)))
        .collect::<Result<_>>()?;
    behavior::finish(
        frozen,
        gate,
        out_dir,
        cases,
        scenarios,
        BTreeMap::from([
            ("crates".into(), json!(crates)),
            ("sensitivity".into(), sensitivity),
            ("tool_version".into(), json!("cargo-llvm-cov 0.9.1")),
        ]),
    )
}
