//! cargo-mutants 27.0.0 outcomes are counted per approved module; timeouts never count as kills.
use super::behavior::{self, Producer, Runtime};
use crate::acceptance::Report;
use crate::evidence::{self, Frozen, Gate, Result};
use crate::source_inventory::SourceBuild;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Module {
    files: Vec<PathBuf>,
    critical: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Campaign {
    build: String,
    modules: BTreeMap<String, Module>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    campaigns: Vec<Campaign>,
    calibration: Producer,
}

fn command(
    frozen: &Frozen,
    runtime: &Runtime,
    config: &SourceBuild,
    source_root: &Path,
    output: &Path,
    modules: &BTreeMap<String, Module>,
) -> Result<Command> {
    if config
        .target
        .as_deref()
        .is_some_and(|t| t.starts_with("thumb"))
    {
        return Err("unavailable: mutation requires a native executable test configuration".into());
    }
    let base = crate::source_inventory::cargo_command(
        config,
        source_root,
        "test",
        &runtime.path.join("mutant-target"),
        None,
    )?;
    let mut command = Command::new(behavior::plugin_path(frozen, "mutants")?);
    command.env_clear();
    for (key, value) in base.get_envs() {
        if let Some(value) = value {
            command.env(key, value);
        }
    }
    command
        .current_dir(source_root)
        .args([
            "mutants",
            "--no-config",
            "--baseline",
            "run",
            "--timeout",
            "120",
            "--build-timeout",
            "120",
            "--jobs",
            "1",
            "--gitignore=false",
        ])
        .arg("--manifest-path")
        .arg(evidence::resolve(source_root, &config.manifest_path)?)
        .args(["--package", &config.package])
        .arg("--output")
        .arg(output)
        .env("TMPDIR", &runtime.path)
        .env("PROPTEST_DISABLE_FAILURE_PERSISTENCE", "1");
    if !config.default_features {
        command.arg("--no-default-features");
    }
    if !config.features.is_empty() {
        command.arg("--features").arg(config.features.join(","));
    }
    // Pass the shared builder's exact flags to Cargo, excluding absolute clean-tree paths.
    let mut args = base.get_args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--manifest-path" || arg == "--target-dir" || arg == "--features" {
            args.next();
            continue;
        }
        if arg == "--no-default-features" {
            continue;
        }
        command.arg(format!(
            "--cargo-arg={}",
            arg.to_str().ok_or("non-UTF8 Cargo argument")?
        ));
    }
    for module in modules.values() {
        if module.files.is_empty() {
            return Err("empty mutation module file inventory".into());
        }
        for file in &module.files {
            if file.is_absolute()
                || file
                    .components()
                    .any(|c| !matches!(c, std::path::Component::Normal(_)))
            {
                return Err(
                    "mutation module files must be literal workspace-relative paths".into(),
                );
            }
            let source = fs::read_to_string(source_root.join(file))
                .map_err(|_| "unavailable: approved mutation source missing")?;
            if source.contains("mutants::skip") {
                return Err("mutation suppression in approved module".into());
            }
            command.arg("--file").arg(file);
        }
    }
    Ok(command)
}

fn reading(
    path: &Path,
    modules: &BTreeMap<String, Module>,
) -> Result<(BTreeMap<String, Value>, u64)> {
    let value: Value = evidence::read_json(path)?;
    if value["cargo_mutants_version"].as_str() != Some("27.0.0") || !value["end_time"].is_string() {
        return Err("inconclusive: incomplete or wrong-version mutation campaign".into());
    }
    let outcomes = value["outcomes"]
        .as_array()
        .ok_or("missing mutation outcomes")?;
    let mut counts: BTreeMap<String, [u64; 3]> = modules
        .keys()
        .map(|name| (name.clone(), [0, 0, 0]))
        .collect();
    let mut ids = BTreeSet::new();
    let mut baseline = 0;
    let mut totals = [0u64; 3];
    let mut records: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for outcome in outcomes {
        if outcome["scenario"].as_str() == Some("Baseline") {
            if outcome["summary"].as_str() != Some("Success") {
                return Err("mutation baseline did not pass".into());
            }
            baseline += 1;
            continue;
        }
        let mutant = outcome["scenario"]
            .get("Mutant")
            .ok_or("unknown mutation scenario")?;
        let file = mutant["file"]
            .as_str()
            .ok_or("missing mutant source path")?;
        let owners: Vec<_> = modules
            .iter()
            .filter(|(_, module)| module.files.iter().any(|p| p == Path::new(file)))
            .map(|(name, _)| name)
            .collect();
        if owners.len() != 1 {
            return Err("mutant source omitted from or duplicated in module inventory".into());
        }
        let id = behavior::digest(
            &serde_json::to_vec(mutant).map_err(|_| "cannot hash mutant identity")?,
        );
        if !ids.insert(id.clone()) {
            return Err("duplicated mutant outcome".into());
        }
        let kind =
            match outcome["summary"].as_str() {
                Some("CaughtMutant") => 0,
                Some("MissedMutant") => 1,
                Some("Unviable") => 2,
                Some("Timeout") => return Err(
                    "inconclusive: mutant timeout requires review, not automatic detection credit"
                        .into(),
                ),
                _ => return Err("inconclusive: unknown or incomplete mutant result".into()),
            };
        counts.get_mut(owners[0]).ok_or("unknown mutation module")?[kind] += 1;
        totals[kind] += 1;
        records.entry(owners[0].clone()).or_default().push(json!({"id_sha256":id,"source":file,"span":mutant["span"],"operator":mutant["genre"],"outcome":outcome["summary"]}));
    }
    if baseline != 1
        || behavior::uint(&value, "total_mutants")? != ids.len() as u64
        || behavior::uint(&value, "caught")? != totals[0]
        || behavior::uint(&value, "missed")? != totals[1]
        || behavior::uint(&value, "unviable")? != totals[2]
        || behavior::uint(&value, "timeout")? != 0
        || behavior::uint(&value, "success")? != 0
    {
        return Err("mutation summary and individual results disagree".into());
    }
    let mut result = BTreeMap::new();
    let mut eligible_total = 0;
    for (name, [caught, missed, invalid]) in counts {
        let eligible = caught + missed;
        let critical_survivors = if modules[&name].critical { missed } else { 0 };
        if eligible == 0
            || u128::from(caught) * 100 < u128::from(eligible) * 90
            || critical_survivors != 0
        {
            return Err(format!(
                "empty, insensitive or critically surviving mutation module {name}"
            ));
        }
        eligible_total += eligible;
        result.insert(name.clone(),json!({"eligible_mutants":eligible,"detected_mutants":caught,"critical_survivors":critical_survivors,"compile_invalid_mutants":invalid,"surviving_mutants":missed,"outcomes":records.remove(&name).unwrap_or_default()}));
    }
    Ok((result, eligible_total))
}

pub fn run(frozen: &Frozen, gate: &Gate, out_dir: &Path) -> Result<Report> {
    let runtime = Runtime::new(frozen, gate)?;
    behavior::pin_plugin(frozen, &runtime, "mutants", "27.0.0")?;
    let root = behavior::fixture(&runtime)?;
    let config = behavior::fixture_build(frozen, &root)?;
    let controls = BTreeMap::from([(
        "infrastructure".into(),
        Module {
            files: vec![PathBuf::from("src/lib.rs")],
            critical: true,
        },
    )]);
    let output_dir = runtime.path.join("control-out");
    fs::create_dir(&output_dir).map_err(|_| "cannot isolate mutation control output")?;
    let control = runtime.execute(&mut command(
        frozen,
        &runtime,
        &config,
        &root,
        &output_dir,
        &controls,
    )?)?;
    behavior::succeeded(&control)?;
    let (control_reading, control_cases) =
        reading(&output_dir.join("mutants.out/outcomes.json"), &controls)?;
    let mut modules = BTreeMap::new();
    let mut cases = 0;
    let calibration;
    if frozen.definition.increment == "setup" {
        behavior::exact_scopes(gate, ["mutation".to_owned()].into_iter())?;
        modules.insert("mutation".into(), control_reading["infrastructure"].clone());
        cases = control_cases;
        calibration = json!({"scope":"public-infrastructure-only","modules":control_reading});
    } else {
        let plan: Plan = behavior::plan(frozen, gate)?;
        let scopes: BTreeSet<_> = plan
            .campaigns
            .iter()
            .flat_map(|c| c.modules.keys().cloned())
            .collect();
        behavior::exact_scopes(gate, scopes.into_iter())?;
        let campaign_ids: BTreeSet<_> = plan.campaigns.iter().map(|c| c.build.as_str()).collect();
        if campaign_ids.len() != plan.campaigns.len() {
            return Err("duplicate mutation build configuration".into());
        }
        for campaign in &plan.campaigns {
            let config = behavior::build(frozen, &campaign.build)?;
            let expected: BTreeSet<_> = frozen
                .definition
                .source_builds
                .iter()
                .filter(|b| {
                    b.package == config.package
                        && b.target.as_deref().is_none_or(|t| !t.starts_with("thumb"))
                })
                .map(|b| b.id.as_str())
                .collect();
            let actual: BTreeSet<_> = plan
                .campaigns
                .iter()
                .filter(|other| {
                    behavior::build(frozen, &other.build).is_ok_and(|b| b.package == config.package)
                })
                .map(|c| c.build.as_str())
                .collect();
            if actual != expected {
                return Err(
                    "mutation omits an approved native feature/target configuration".into(),
                );
            }
            if plan.campaigns.iter().any(|other| {
                behavior::build(frozen, &other.build).is_ok_and(|b| b.package == config.package)
                    && other.modules != campaign.modules
            }) {
                return Err(
                    "mutation module inventory differs across approved configurations of one crate"
                        .into(),
                );
            }
        }
        let mut modes = vec![super::sensitivity::STALE_PERIOD];
        if frozen.definition.increment != "foundation" {
            modes.push(super::sensitivity::ARTIFACT_AUTHENTICATION_OR_PUBLICATION);
        }
        calibration = behavior::calibration(frozen, &runtime, &plan.calibration, modes.as_slice())?;
        let source_root = runtime.path.join("mutation-source");
        behavior::copy_candidate(frozen, &source_root)?;
        for (index, campaign) in plan.campaigns.into_iter().enumerate() {
            let config = behavior::build(frozen, &campaign.build)?;
            let output_dir = runtime.path.join(format!("campaign-{index}"));
            fs::create_dir(&output_dir).map_err(|_| "cannot isolate mutation output")?;
            let output = runtime.execute(&mut command(
                frozen,
                &runtime,
                config,
                &source_root,
                &output_dir,
                &campaign.modules,
            )?)?;
            // Exit 2 means surviving mutants; their per-module results still require inspection.
            if !matches!(output.code, Some(0 | 2)) {
                return Err("mutation tool failed or incomplete".into());
            }
            let (readings, count) = reading(
                &output_dir.join("mutants.out/outcomes.json"),
                &campaign.modules,
            )?;
            cases += count;
            for (name, reading) in readings {
                let aggregate = modules.entry(name).or_insert_with(|| json!({"eligible_mutants":0,"detected_mutants":0,"critical_survivors":0,"compile_invalid_mutants":0,"configurations":{}}));
                for field in [
                    "eligible_mutants",
                    "detected_mutants",
                    "critical_survivors",
                    "compile_invalid_mutants",
                ] {
                    aggregate[field] = json!(
                        behavior::uint(aggregate, field)?
                            .checked_add(behavior::uint(&reading, field)?)
                            .ok_or("mutation count overflow")?
                    );
                }
                aggregate["configurations"][&campaign.build] = reading;
            }
        }
    }
    let scenarios = modules
        .iter()
        .map(|(name, value)| Ok((name.clone(), behavior::positive(value, "eligible_mutants")?)))
        .collect::<Result<_>>()?;
    behavior::finish(
        frozen,
        gate,
        out_dir,
        cases,
        scenarios,
        BTreeMap::from([
            ("modules".into(), json!(modules)),
            ("sensitivity".into(), calibration),
            ("tool_version".into(), json!("cargo-mutants 27.0.0")),
        ]),
    )
}
