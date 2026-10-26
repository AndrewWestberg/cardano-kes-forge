//! cargo-fuzz 0.13.1 campaigns run only copied, frozen semantic targets and corpora.
use super::behavior::{self, Producer, Runtime};
use crate::acceptance::Report;
use crate::evidence::{self, Frozen, Gate, Result};
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    configurations: BTreeMap<String, Producer>,
    corpus: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    targets: BTreeMap<String, Target>,
    cxx_input: String,
    cxx_version: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Semantic {
    version: u8,
    semantic_checks: u64,
    violations: u64,
}

/// A corpus is either a registered frozen input or a complete frozen source subtree.
fn frozen_corpus(frozen: &Frozen, path: &Path) -> Result<(PathBuf, String)> {
    let source = evidence::resolve_input(&frozen.workspace, path)?;
    for (name, registered) in &frozen.definition.inputs {
        if evidence::resolve_input(&frozen.workspace, registered)? == source {
            let expected = frozen
                .identity
                .inputs
                .get(name)
                .ok_or("corpus input has no frozen identity")?;
            if evidence::input_hash(&source)? != *expected {
                return Err("frozen named corpus input changed".into());
            }
            return Ok((source, expected.clone()));
        }
    }
    let relative = source
        .strip_prefix(&frozen.workspace)
        .map_err(|_| "unavailable: external corpus must be an approved frozen named input")?;
    let mut expected = BTreeMap::new();
    for (name, hash) in &frozen.identity.source_files {
        if let Ok(entry) = Path::new(name).strip_prefix(relative) {
            let entry = entry.to_str().ok_or("invalid frozen corpus source path")?;
            if !entry.is_empty() {
                expected.insert(entry.to_owned(), hash.clone());
            }
        }
    }
    if expected.is_empty() {
        return Err(
            "unavailable: corpus is absent from frozen source inventory and named inputs".into(),
        );
    }
    let expected_hash = evidence::json_hash(&expected)?;
    if evidence::input_hash(&source)? != expected_hash {
        return Err("frozen corpus source subtree changed".into());
    }
    Ok((source, expected_hash))
}
fn corpus(source: &Path, destination: &Path) -> Result<(u64, String)> {
    fs::create_dir(destination).map_err(|_| "cannot isolate fuzz corpus")?;
    let mut hashes = BTreeMap::new();
    for entry in fs::read_dir(source).map_err(|_| "unavailable: real seed corpus is absent")? {
        let entry = entry.map_err(|_| "cannot enumerate corpus")?;
        let metadata =
            fs::symlink_metadata(entry.path()).map_err(|_| "cannot inspect corpus entry")?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 8192 {
            return Err(
                "seed corpus entries must be nonempty regular files of at most 8192 bytes".into(),
            );
        }
        let hash = evidence::file_hash(&entry.path())?;
        // Runtime names are hashes, never private original input names.
        fs::copy(entry.path(), destination.join(&hash))
            .map_err(|_| "cannot copy immutable seed corpus")?;
        if evidence::file_hash(&destination.join(&hash))? != hash {
            return Err("corpus changed while copying immutable seed input".into());
        }
        hashes.insert(hash, metadata.len());
    }
    if hashes.is_empty() {
        return Err("unavailable: empty semantic fuzz corpus".into());
    }
    Ok((hashes.len() as u64, evidence::json_hash(&hashes)?))
}
fn stats(bytes: &[u8]) -> Result<(u64, u64, u64)> {
    let text = std::str::from_utf8(bytes).map_err(|_| "invalid libFuzzer statistics encoding")?;
    let mut done = None;
    let mut executions = None;
    let mut coverage = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Done ") {
            let words: Vec<_> = rest.split_whitespace().collect();
            if words.len() != 5 || words[1] != "runs" || words[2] != "in" || words[4] != "second(s)"
            {
                return Err("malformed libFuzzer completion record".into());
            }
            if done.is_some() {
                return Err("duplicate libFuzzer completion record".into());
            }
            done = Some((
                words[0]
                    .parse::<u64>()
                    .map_err(|_| "invalid fuzz run count")?,
                words[3]
                    .parse::<u64>()
                    .map_err(|_| "invalid fuzz elapsed seconds")?,
            ));
        }
        if let Some(rest) = line.strip_prefix("stat::number_of_executed_units:") {
            if executions.is_some() {
                return Err("duplicate libFuzzer execution statistic".into());
            }
            executions = Some(
                rest.trim()
                    .parse::<u64>()
                    .map_err(|_| "invalid libFuzzer execution statistic")?,
            );
        }
        if line.starts_with('#') && line.split_whitespace().any(|word| word == "DONE") {
            let words: Vec<_> = line.split_whitespace().collect();
            let index = words
                .iter()
                .position(|word| *word == "cov:")
                .ok_or("missing final fuzz coverage statistic")?;
            coverage = Some(
                words
                    .get(index + 1)
                    .ok_or("missing fuzz edge count")?
                    .parse::<u64>()
                    .map_err(|_| "invalid fuzz edge count")?,
            );
        }
    }
    let (runs, seconds) =
        done.ok_or("inconclusive: libFuzzer did not complete its actual campaign")?;
    let executions = executions.ok_or("missing actual libFuzzer execution statistic")?;
    if runs == 0 || executions != runs {
        return Err("empty or inconsistent libFuzzer execution counts".into());
    }
    Ok((
        runs,
        seconds,
        coverage
            .filter(|n| *n > 0)
            .ok_or("empty libFuzzer coverage")?,
    ))
}
pub fn run(frozen: &Frozen, gate: &Gate, out_dir: &Path) -> Result<Report> {
    let plan: Plan = behavior::plan(frozen, gate)?;
    behavior::exact_scopes(gate, plan.targets.keys().cloned())?;
    let required = evidence::required_fuzz_targets(&frozen.definition.increment);
    if required.is_empty() {
        return Err(
            "unavailable: setup has no implemented semantic application fuzz targets".into(),
        );
    }
    if required
        .iter()
        .any(|name| !plan.targets.contains_key(*name))
        || plan.targets.len() != required.len()
    {
        return Err("incomplete approved semantic fuzz target inventory".into());
    }
    let runtime = Runtime::new(frozen, gate)?;
    behavior::pin_plugin(frozen, &runtime, "fuzz", "0.13.1")?;
    let compiler_path =
        frozen.definition.inputs.get(&plan.cxx_input).ok_or(
            "unavailable: libFuzzer requires a frozen named C++ compiler executable input",
        )?;
    let compiler = evidence::resolve_input(&frozen.workspace, compiler_path)?;
    let compiler_hash = frozen
        .identity
        .inputs
        .get(&plan.cxx_input)
        .ok_or("C++ compiler has no frozen identity")?;
    if evidence::file_hash(&compiler)? != *compiler_hash {
        return Err("libFuzzer C++ compiler changed".into());
    }
    behavior::pin(
        &runtime,
        compiler.to_str().ok_or("invalid C++ compiler path")?,
        &["--version"],
        &plan.cxx_version,
    )?;
    if !frozen
        .identity
        .source_inventory
        .dependencies
        .keys()
        .any(|id| id.contains("#libfuzzer-sys@"))
    {
        return Err(
            "unavailable: frozen libfuzzer-sys dependency sources and compiler identity required"
                .into(),
        );
    }
    let seconds = if frozen.definition.increment == "final" {
        86400u64
    } else {
        3600
    };
    let workspace = runtime.path.join("candidate");
    behavior::copy_candidate(frozen, &workspace)?;
    let mut targets = BTreeMap::new();
    let mut scenarios = BTreeMap::new();
    let mut cases = 0u64;
    for (name, target) in plan.targets {
        if target.configurations.is_empty() {
            return Err("unavailable: fuzz target build/calibration matrix absent".into());
        }
        let mut configurations = BTreeMap::new();
        let mut target_executions = 0u64;
        let mut minimum_seconds = u64::MAX;
        let mut seed_reading = None;
        for (id, calibrator) in &target.configurations {
            let config = behavior::build(frozen, id)?;
            if config.toolchain != "nightly-2026-10-22" || config.profile != "release" {
                return Err(
                    "unavailable: fuzz build requires approved nightly-2026-10-22 release profile"
                        .into(),
                );
            }
            let expected: std::collections::BTreeSet<_> = frozen
                .definition
                .source_builds
                .iter()
                .filter(|b| b.package == config.package && b.toolchain == "nightly-2026-10-22")
                .map(|b| b.id.as_str())
                .collect();
            if target
                .configurations
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>()
                != expected
            {
                return Err("fuzz target omits an approved feature/target configuration".into());
            }
            if config.rustflags.iter().any(|flag| {
                flag.chars().any(char::is_whitespace)
                    || flag.contains("sanitizer")
                    || flag.contains("debug-assertions")
                    || flag.contains("cfg")
            }) {
                return Err(
                    "fuzz Rust flags cannot override instrumentation or semantic assertions".into(),
                );
            }
            behavior::sensitivity_producer(frozen, calibrator, &name)?;
            let calibration = behavior::calibration(
                frozen,
                &runtime,
                calibrator,
                &["seeded-semantic-authentication-bypass"],
            )?;
            let (corpus_source, corpus_binding) = frozen_corpus(frozen, &target.corpus)?;
            let component = super::tooling::component(id);
            let corpus_destination = runtime.path.join(format!("corpus-{name}-{component}"));
            let (corpus_inputs, seed_hash) = corpus(&corpus_source, &corpus_destination)?;
            if evidence::input_hash(&corpus_source)? != corpus_binding {
                return Err("frozen corpus changed during runtime copy".into());
            }
            seed_reading = Some((corpus_inputs, seed_hash.clone(), corpus_binding));
            let manifest = evidence::resolve(&workspace, &config.manifest_path)?;
            let fuzz_dir = manifest.parent().ok_or("invalid fuzz manifest parent")?;
            if !fuzz_dir
                .join("fuzz_targets")
                .join(format!("{name}.rs"))
                .is_file()
            {
                return Err(format!(
                    "unavailable: real semantic fuzz target {name} absent"
                ));
            }
            let lock = fuzz_dir.join("Cargo.lock");
            let lock_hash = evidence::file_hash(&lock)
                .map_err(|_| "unavailable: frozen fuzz Cargo.lock required")?;
            let base = crate::source_inventory::cargo_command(
                config,
                &frozen.workspace,
                "test",
                &runtime.path.join("fuzz-target"),
                None,
            )?;
            let mut command = Command::new(behavior::plugin_path(frozen, "fuzz")?);
            command.env_clear();
            for (key, value) in base.get_envs() {
                if let Some(value) = value {
                    command.env(key, value);
                }
            }
            // cargo-fuzz constructs sanitizer Rust flags itself; encoded flags would override them.
            command
                .env_remove("CARGO_ENCODED_RUSTFLAGS")
                .env("RUSTFLAGS", config.rustflags.join(" "))
                .env("CARGO_NET_OFFLINE", "true")
                .env("KES_GATE_MODE", "fuzz")
                .env("KES_GATE_RUNTIME", &runtime.path)
                .env("KESFORGE_SOURCE_MANIFEST", &manifest)
                .env("CXX", &compiler)
                .current_dir(&workspace)
                .args(["fuzz", "run", &name])
                .arg(&corpus_destination)
                .arg("--fuzz-dir")
                .arg(fuzz_dir)
                .args(["--sanitizer", "address", "--target-dir"])
                .arg(runtime.path.join(format!("fuzz-target-{name}-{component}")));
            if !config.default_features {
                command.arg("--no-default-features");
            }
            if !config.features.is_empty() {
                command.arg("--features").arg(config.features.join(","));
            }
            if let Some(triple) = &config.target {
                command.args(["--target", triple]);
            }
            command
                .arg("--")
                .arg(format!("-max_total_time={seconds}"))
                .args(["-max_len=8192", "-print_final_stats=1", "-timeout=120"]);
            let output = runtime.execute(&mut command)?;
            behavior::succeeded(&output)?;
            if evidence::file_hash(&lock)? != lock_hash {
                return Err("fuzz tool changed frozen dependency lock".into());
            }
            let (executions, elapsed, edges) = stats(&output.stderr)?;
            if elapsed < seconds || output.duration_ms / 1000 < seconds {
                return Err(
                    "inconclusive: semantic fuzz campaign shorter than required wall duration"
                        .into(),
                );
            }
            let stdout = std::str::from_utf8(&output.stdout)
                .map_err(|_| "invalid fuzz semantic summary encoding")?;
            let records: Vec<_> = stdout
                .lines()
                .filter_map(|line| line.strip_prefix("KES_FUZZ_SUMMARY "))
                .collect();
            if records.len() != 1 {
                return Err(
                    "unavailable: target must emit exactly one final real KES_FUZZ_SUMMARY record"
                        .into(),
                );
            }
            let semantic: Semantic =
                serde_json::from_str(records[0]).map_err(|_| "invalid fuzz semantic summary")?;
            if semantic.version != 1 || semantic.semantic_checks == 0 || semantic.violations != 0 {
                return Err("missing semantic oracle execution or semantic fuzz finding".into());
            }
            cases = cases
                .checked_add(executions)
                .ok_or("fuzz execution count overflow")?;
            target_executions = target_executions
                .checked_add(executions)
                .ok_or("fuzz execution count overflow")?;
            minimum_seconds = minimum_seconds.min(elapsed);
            configurations.insert(id,json!({"seconds":elapsed,"executions":executions,"semantic_checks":semantic.semantic_checks,"coverage_edges":edges,"calibration":calibration}));
        }
        let (corpus_inputs, seed_hash, corpus_binding) =
            seed_reading.ok_or("unavailable: fuzz target has no measured configuration")?;
        scenarios.insert(name.clone(), target_executions);
        targets.insert(name,json!({"seconds":minimum_seconds,"executions":target_executions,"corpus_inputs":corpus_inputs,"seed_corpus_sha256":seed_hash,"frozen_corpus_sha256":corpus_binding,"sanitizers":true,"semantic_oracle":true,"findings":0,"configurations":configurations,"tool":"cargo-fuzz 0.13.1","toolchain":"nightly-2026-10-22","libfuzzer_cxx_sha256":compiler_hash,"libfuzzer_cxx_version":plan.cxx_version}));
    }
    behavior::finish(
        frozen,
        gate,
        out_dir,
        cases,
        scenarios,
        BTreeMap::from([("targets".into(), json!(targets))]),
    )
}
