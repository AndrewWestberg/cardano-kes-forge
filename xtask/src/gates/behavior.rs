//! Real libtest execution and shared public-summary producer protocol.
use super::{report, tooling};
use crate::acceptance::Report;
use crate::evidence::{self, Frozen, Gate, Result};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

pub(crate) struct Runtime {
    directory: tooling::RuntimeDirectory,
    started: Instant,
    budget: u64,
}
impl Runtime {
    pub fn new(frozen: &Frozen, gate: &Gate) -> Result<Self> {
        let directory = tooling::runtime_directory(frozen, gate)?;
        Ok(Self {
            directory,
            started: Instant::now(),
            budget: gate.budget_ms,
        })
    }
    pub fn execute(&self, command: &mut Command) -> Result<tooling::Output> {
        let elapsed = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let remaining = self
            .budget
            .checked_sub(elapsed)
            .filter(|n| *n > 0)
            .ok_or("inconclusive: gate budget exhausted")?;
        let output = tooling::run(command, remaining)?;
        if output.timed_out {
            return Err("inconclusive: gate subprocess timed out".into());
        }
        Ok(output)
    }
}
impl std::ops::Deref for Runtime {
    type Target = tooling::RuntimeDirectory;
    fn deref(&self) -> &Self::Target {
        &self.directory
    }
}

pub(crate) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub(crate) fn succeeded(output: &tooling::Output) -> Result<()> {
    if output.code != Some(0) {
        return Err(format!(
            "gate subprocess failed (exit {:?}, stdout sha256 {}, stderr sha256 {})",
            output.code,
            digest(&output.stdout),
            digest(&output.stderr)
        ));
    }
    Ok(())
}
pub(crate) fn plan<T: DeserializeOwned>(frozen: &Frozen, gate: &Gate) -> Result<T> {
    let name = format!("{}-plan", gate.id);
    let path = frozen.definition.inputs.get(&name).ok_or_else(|| format!("unavailable: required frozen input {name} is absent; no application target or calibration inferred"))?;
    evidence::read_json(&evidence::resolve_input(&frozen.workspace, path)?)
}
pub(crate) fn build<'a>(
    frozen: &'a Frozen,
    id: &str,
) -> Result<&'a crate::source_inventory::SourceBuild> {
    frozen
        .definition
        .source_builds
        .iter()
        .find(|b| b.id == id)
        .ok_or_else(|| format!("unavailable: approved source build {id} is absent"))
}
pub(crate) fn pin(runtime: &Runtime, program: &str, args: &[&str], expected: &str) -> Result<()> {
    let output = runtime.execute(
        Command::new(program)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .args(args),
    )?;
    succeeded(&output)?;
    let actual = std::str::from_utf8(&output.stdout)
        .map_err(|_| "invalid tool version encoding")?
        .trim();
    if actual != expected {
        return Err(format!("unavailable: required tool version {expected}"));
    }
    Ok(())
}

/// Reuse the frozen Cargo/RUSTC environment and build flags for a pinned Cargo plugin.
pub(crate) fn plugin_command(
    frozen: &Frozen,
    runtime: &Runtime,
    config: &crate::source_inventory::SourceBuild,
    workspace: &Path,
    plugin: &str,
) -> Result<Command> {
    let base = crate::source_inventory::cargo_command(
        config,
        workspace,
        "test",
        &runtime.path.join(tooling::component(&config.id)),
        None,
    )?;
    let executable = plugin_path(frozen, plugin)?;
    let mut command = Command::new(executable);
    command.env_clear();
    if let Some(cwd) = base.get_current_dir() {
        command.current_dir(cwd);
    }
    for (key, value) in base.get_envs() {
        if let Some(value) = value {
            command.env(key, value);
        } else {
            command.env_remove(key);
        }
    }
    let mut replaced = false;
    let mut args = base.get_args();
    while let Some(arg) = args.next() {
        if plugin == "llvm-cov" && arg == "--target-dir" {
            command.env(
                "CARGO_TARGET_DIR",
                args.next().ok_or("missing shared target directory")?,
            );
            continue;
        }
        if !replaced && arg == "test" {
            command.arg(plugin);
            replaced = true;
        } else {
            command.arg(arg);
        }
    }
    if !replaced {
        return Err("shared Cargo builder did not supply test action".into());
    }
    Ok(command)
}

pub(crate) fn plugin_path(frozen: &Frozen, plugin: &str) -> Result<PathBuf> {
    let name = format!("cargo-{plugin}");
    let mut matches = frozen.identity.tools.values().filter(|tool| {
        tool.resolved_path
            .file_name()
            .is_some_and(|n| n == name.as_str())
    });
    let tool = matches
        .next()
        .ok_or_else(|| format!("unavailable: {name} must be a frozen tool identity"))?;
    if matches.next().is_some() || evidence::file_hash(&tool.resolved_path)? != tool.sha256 {
        return Err("ambiguous or changed frozen Cargo plugin".into());
    }
    Ok(tool.resolved_path.clone())
}
pub(crate) fn pin_plugin(
    frozen: &Frozen,
    runtime: &Runtime,
    plugin: &str,
    version: &str,
) -> Result<()> {
    let path = plugin_path(frozen, plugin)?;
    let tool = frozen
        .identity
        .tools
        .values()
        .find(|tool| tool.resolved_path == path)
        .ok_or("missing frozen plugin registration")?;
    if tool.version_args.is_empty() {
        return Err("unavailable: pinned plugin has no registered version arguments".into());
    }
    let args: Vec<_> = tool.version_args.iter().map(String::as_str).collect();
    pin(
        runtime,
        path.to_str().ok_or("non-UTF8 pinned plugin path")?,
        &args,
        &format!("cargo-{plugin} {version}"),
    )
}
pub(crate) fn fixture_build(
    frozen: &Frozen,
    _root: &Path,
) -> Result<crate::source_inventory::SourceBuild> {
    let mut config = frozen
        .definition
        .source_builds
        .iter()
        .find(|b| b.toolchain == "1.99.1" && b.target.is_none())
        .ok_or("unavailable: pinned host build required for disposable infrastructure control")?
        .clone();
    config.id = "public-control".into();
    config.manifest_path = PathBuf::from("Cargo.toml");
    config.package = "gate-public-control".into();
    config.features.clear();
    config.default_features = true;
    config.profile = "dev".into();
    config.all_targets = false;
    config.rustflags.clear();
    Ok(config)
}

pub(crate) fn calibration(
    frozen: &Frozen,
    runtime: &Runtime,
    target: &Producer,
    modes: &[&str],
) -> Result<Value> {
    super::sensitivity::calibration(frozen, runtime, target, modes)
}
pub(crate) fn finish(
    frozen: &Frozen,
    gate: &Gate,
    _out: &Path,
    cases: u64,
    scenarios: BTreeMap<String, u64>,
    measurements: BTreeMap<String, Value>,
) -> Result<Report> {
    let result = report(frozen, gate, cases, scenarios, measurements);
    crate::acceptance::validate_report(frozen, gate, &result)?;
    Ok(result)
}
pub(crate) fn uint(value: &Value, name: &str) -> Result<u64> {
    value
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing unsigned public count {name}"))
}
pub(crate) fn positive(value: &Value, name: &str) -> Result<u64> {
    let count = uint(value, name)?;
    if count == 0 {
        return Err(format!("empty public count {name}"));
    }
    Ok(count)
}
pub(crate) fn yes(value: &Value, name: &str) -> Result<()> {
    if value.get(name).and_then(Value::as_bool) != Some(true) {
        return Err(format!("missing or false invariant {name}"));
    }
    Ok(())
}
pub(crate) fn exact_scopes(gate: &Gate, actual: impl Iterator<Item = String>) -> Result<()> {
    let mut expected = gate.scenarios.clone();
    expected.sort();
    let mut actual: Vec<_> = actual.collect();
    actual.sort();
    if expected.is_empty() || actual != expected {
        return Err("missing, duplicated or unexpected approved scenario scope".into());
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(untagged)]
pub(crate) enum Producer {
    Rust(RustProducer),
    Native(NativeProducer),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RustProducer {
    build: String,
    target: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeProducer {
    input: String,
    args: Vec<String>,
    env: BTreeMap<String, String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Summary {
    pub version: u8,
    pub cases: u64,
    pub scenarios: BTreeMap<String, u64>,
    pub measurements: Value,
}

pub(crate) fn sensitivity_producer(
    frozen: &Frozen,
    producer: &Producer,
    target_name: &str,
) -> Result<()> {
    let (expected_package, expected_test) = match target_name {
        "frame" => ("kes-protocol", "codec"),
        "certificate" => ("kes-core", "certificate_interop"),
        "snapshot" => ("kes-core", "journal_faults"),
        "session" => ("kes-core", "session"),
        _ => {
            return Err(format!(
                "unregistered semantic sensitivity target: {target_name}"
            ));
        }
    };
    let Producer::Rust(target) = producer else {
        return Err("semantic sensitivity requires a real Rust integration-test producer".into());
    };
    let config = build(frozen, &target.build)?;
    if config.package != expected_package
        || target.target != expected_test
        || config
            .target
            .as_deref()
            .is_some_and(|triple| triple.starts_with("thumb"))
    {
        return Err(format!(
            "semantic sensitivity producer for {target_name} must execute {expected_package}/{expected_test}"
        ));
    }
    Ok(())
}

pub(crate) fn producer_build(target: &Producer, id: &str) -> Result<()> {
    if let Producer::Rust(target) = target
        && target.build != id
    {
        return Err("producer does not execute the approved build configuration".into());
    }
    Ok(())
}

pub(crate) fn producer(
    frozen: &Frozen,
    runtime: &Runtime,
    target: &Producer,
    mode: &str,
) -> Result<(Summary, tooling::Output)> {
    let mut command = match target {
        Producer::Rust(target) => {
            if target.target.is_empty()
                || !target
                    .target
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
            {
                return Err("invalid producer test target".into());
            }
            let config = build(frozen, &target.build)?;
            if config
                .target
                .as_deref()
                .is_some_and(|t| t.starts_with("thumb"))
            {
                return Err("unavailable: host producer cannot execute firmware target".into());
            }
            let mut command = crate::source_inventory::cargo_command(
                config,
                &frozen.workspace,
                "test",
                &runtime.path.join(tooling::component(&target.build)),
                Some(&target.target),
            )?;
            command
                .args(["--", "--nocapture", "--test-threads=1"])
                .env("PROPTEST_CASES", "10000")
                .env("PROPTEST_RNG_SEED", "827694857102938475")
                .env("PROPTEST_DISABLE_FAILURE_PERSISTENCE", "1")
                .env("KES_GATE_BUILD", &target.build);
            command
        }
        Producer::Native(target) => {
            let input = frozen.definition.inputs.get(&target.input).ok_or(
                "unavailable: native producer must name an approved frozen executable input",
            )?;
            let binary = evidence::resolve_input(&frozen.workspace, input)?;
            let expected = frozen
                .identity
                .inputs
                .get(&target.input)
                .ok_or("native executable has no frozen identity")?;
            if evidence::file_hash(&binary)? != *expected {
                return Err("native producer executable changed".into());
            }
            if target.env.keys().any(|key| key.starts_with("KES_GATE_")) {
                return Err(
                    "native public environment cannot override gate control variables".into(),
                );
            }
            let mut command = Command::new(binary);
            command
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .envs(&target.env)
                .args(&target.args)
                .current_dir(&runtime.path);
            command
        }
    };
    command
        .env("KES_GATE_MODE", mode)
        .env("KES_GATE_RUNTIME", &runtime.path);
    let output = runtime.execute(&mut command)?;
    let stdout =
        std::str::from_utf8(&output.stdout).map_err(|_| "invalid producer output encoding")?;
    let prefix = "KES_GATE_SUMMARY ";
    let mut records = stdout
        .lines()
        .filter_map(|line| line.find(prefix).map(|index| &line[index + prefix.len()..]));
    let record = records
        .next()
        .ok_or("unavailable: target emitted no public KES_GATE_SUMMARY record")?;
    if records.next().is_some() {
        return Err("ambiguous duplicate producer summaries".into());
    }
    let summary: Summary =
        serde_json::from_str(record).map_err(|_| "invalid public producer summary")?;
    if summary.version != 1
        || summary.cases == 0
        || summary.scenarios.is_empty()
        || summary.scenarios.values().any(|n| *n == 0)
    {
        return Err("empty or unsupported public producer summary".into());
    }
    Ok((summary, output))
}

pub(crate) fn copy_candidate(frozen: &Frozen, destination: &Path) -> Result<()> {
    fs::create_dir(destination).map_err(|_| "cannot create disposable source workspace")?;
    for (relative, hash) in &frozen.identity.source_files {
        let source = frozen.workspace.join(relative);
        if evidence::file_hash(&source)? != *hash {
            return Err("frozen source changed before disposable source copy".into());
        }
        let target = destination.join(relative);
        fs::create_dir_all(target.parent().ok_or("invalid frozen source path")?)
            .map_err(|_| "cannot create disposable source parent")?;
        fs::copy(source, &target).map_err(|_| "cannot copy frozen source")?;
        if evidence::file_hash(&target)? != *hash {
            return Err("disposable source copy does not match the frozen identity".into());
        }
    }
    Ok(())
}

/// Public infrastructure control. It proves libtest assertion sensitivity, not application authorization.
pub(crate) fn fixture(runtime: &Runtime) -> Result<PathBuf> {
    let root = runtime.path.join("public-control");
    fs::create_dir(&root).map_err(|_| "cannot create disposable public control")?;
    fs::create_dir(root.join("src")).map_err(|_| "cannot create control source")?;
    fs::write(root.join("Cargo.toml"), "[package]\nname=\"gate-public-control\"\nversion=\"0.0.0\"\nedition=\"2024\"\n[workspace]\n").map_err(|_| "cannot write control manifest")?;
    fs::write(
        root.join("Cargo.lock"),
        "version = 4\n[[package]]\nname = \"gate-public-control\"\nversion = \"0.0.0\"\n",
    )
    .map_err(|_| "cannot write public control lock")?;
    fs::write(root.join("src/lib.rs"), "pub fn authorized(owner:u8,caller:u8)->bool { owner == caller }\n#[cfg(test)] mod tests { #[test] fn isolation(){ assert!(super::authorized(1,1)); assert!(!super::authorized(1,2)); } }\n").map_err(|_| "cannot write public control")?;
    Ok(root)
}
pub(crate) fn libtest_counts(bytes: &[u8]) -> Result<u64> {
    let text = std::str::from_utf8(bytes).map_err(|_| "invalid libtest output encoding")?;
    let mut passed = 0u64;
    let mut summaries = 0;
    for line in text
        .lines()
        .filter(|line| line.starts_with("test result: "))
    {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 17
            || fields[2] != "ok."
            || fields[4] != "passed;"
            || fields[6] != "failed;"
            || fields[8] != "ignored;"
            || fields[10] != "measured;"
            || fields[12] != "filtered"
            || fields[13] != "out;"
        {
            return Err("failed or malformed libtest summary".into());
        }
        for index in [5, 7, 9, 11] {
            if fields[index] != "0" {
                return Err("failed, ignored, measured or filtered libtest cases are not a complete reading".into());
            }
        }
        passed = passed
            .checked_add(
                fields[3]
                    .parse::<u64>()
                    .map_err(|_| "invalid libtest pass count")?,
            )
            .ok_or("case count overflow")?;
        summaries += 1;
    }
    if summaries == 0 || passed == 0 {
        return Err("unavailable: no nonempty libtest workload executed".into());
    }
    Ok(passed)
}

fn libtest_names(bytes: &[u8]) -> Result<Vec<String>> {
    let text = std::str::from_utf8(bytes).map_err(|_| "invalid libtest output")?;
    let mut names = std::collections::BTreeSet::new();
    for line in text.lines() {
        if let Some(rest) = line
            .strip_prefix("test ")
            .and_then(|line| line.strip_suffix(" ... ok"))
            && (rest.is_empty() || !names.insert(rest.to_owned()))
        {
            return Err("duplicate or empty executed test identity".into());
        }
    }
    if names.len() as u64 != libtest_counts(bytes)? {
        return Err("named executed test results disagree with libtest counts".into());
    }
    Ok(names.into_iter().collect())
}
fn infrastructure_sensitivity(frozen: &Frozen, runtime: &Runtime) -> Result<Value> {
    let root = fixture(runtime)?;
    let binary = root.join("probe");
    let config = fixture_build(frozen, &root)?;
    let base = crate::source_inventory::cargo_command(
        &config,
        &root,
        "test",
        &runtime.path.join("control-target"),
        None,
    )?;
    let rustc = base
        .get_envs()
        .find_map(|(key, value)| if key == "RUSTC" { value } else { None })
        .ok_or("shared builder omitted pinned RUSTC")?;
    let mut compile = Command::new(rustc);
    compile.env_clear();
    for (key, value) in base.get_envs() {
        if let Some(value) = value {
            compile.env(key, value);
        }
    }
    compile
        .args(["--test", "--edition=2024"])
        .arg(root.join("src/lib.rs"))
        .arg("-o")
        .arg(&binary);
    succeeded(&runtime.execute(&mut compile)?)?;
    let clean = runtime.execute(Command::new(&binary).env_clear())?;
    succeeded(&clean)?;
    let cases = libtest_counts(&clean.stdout)?;
    fs::write(root.join("src/lib.rs"), "pub fn authorized(owner:u8,caller:u8)->bool { owner != caller }\n#[test] fn isolation(){ assert!(authorized(1,1)); assert!(!authorized(1,2)); }\n").map_err(|_| "cannot seed public control defect")?;
    succeeded(&runtime.execute(&mut compile)?)?;
    let defect = runtime.execute(Command::new(&binary).env_clear())?;
    let text = std::str::from_utf8(&defect.stdout).map_err(|_| "invalid control output")?;
    if defect.code != Some(101)
        || !text
            .lines()
            .any(|s| s.starts_with("test result: FAILED.") && s.contains("1 failed;"))
    {
        return Err(
            "inactive behavior detector: seeded public assertion defect was not detected".into(),
        );
    }
    Ok(
        json!({"scope":"public-infrastructure-only","clean_cases":cases,"clean_exit":clean.code,"defect_exit":defect.code,"defect_stdout_sha256":digest(&defect.stdout)}),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    targets: BTreeMap<String, Producer>,
}
fn sensitivity_mode(scenario: &str) -> Result<&'static str> {
    match scenario {
        "core-state" => Ok(super::sensitivity::CROSS_POOL_AUTHORIZATION),
        "software-journal" => Ok(super::sensitivity::LOST_ACKNOWLEDGED_COMMIT),
        "native-crypto" => Ok(super::sensitivity::CORRUPTED_SIGNATURE),
        "frame" | "artifact" | "certificate" | "snapshot" | "session" => {
            Ok(super::sensitivity::PARSER_AUTHENTICATION_BYPASS)
        }
        _ => Err(format!(
            "unregistered behavior sensitivity scenario: {scenario}"
        )),
    }
}

pub fn run(frozen: &Frozen, gate: &Gate, out_dir: &Path) -> Result<Report> {
    let runtime = Runtime::new(frozen, gate)?;
    let sensitivity = infrastructure_sensitivity(frozen, &runtime)?;
    let mut scenarios = BTreeMap::new();
    let mut cases = 0u64;
    let mut application_sensitivity = BTreeMap::new();
    let mut executed_tests = Vec::new();
    if frozen.definition.increment == "setup" {
        exact_scopes(gate, ["acceptance".to_owned()].into_iter())?;
        let config = frozen
            .definition
            .source_builds
            .iter()
            .find(|b| b.package == "xtask" && b.target.is_none())
            .ok_or("unavailable: approved xtask source-build configuration missing")?;
        let mut command = crate::source_inventory::cargo_command(
            config,
            &frozen.workspace,
            "test",
            &runtime.path.join("acceptance"),
            Some("acceptance"),
        )?;
        command.args(["--", "--test-threads=1"]);
        let output = runtime.execute(&mut command)?;
        succeeded(&output)?;
        cases = libtest_counts(&output.stdout)?;
        executed_tests = libtest_names(&output.stdout)?;
        scenarios.insert("acceptance".to_owned(), cases);
    } else {
        let configuration: Plan = plan(frozen, gate)?;
        exact_scopes(gate, configuration.targets.keys().cloned())?;
        for (scenario, target) in configuration.targets {
            let mode = sensitivity_mode(&scenario)?;
            application_sensitivity.insert(
                scenario.clone(),
                calibration(frozen, &runtime, &target, &[mode])?,
            );
            let (clean, output) = producer(frozen, &runtime, &target, "clean")?;
            succeeded(&output)?;
            if clean.scenarios.len() != 1 || clean.scenarios.get(&scenario) != Some(&clean.cases) {
                return Err("behavior producer scenario identity/count disagrees with approved invocation plan".into());
            }
            if uint(&clean.measurements, "violations")? != 0 {
                return Err("application behavior producer reported violations".into());
            }
            scenarios.insert(scenario, clean.cases);
            cases = cases
                .checked_add(clean.cases)
                .ok_or("case count overflow")?;
        }
    }
    finish(
        frozen,
        gate,
        out_dir,
        cases,
        scenarios,
        BTreeMap::from([
            ("sensitivity_passed".into(), json!(true)),
            ("sensitivity".into(), sensitivity),
            ("executed_tests".into(), json!(executed_tests)),
            (
                "application_sensitivity".into(),
                json!(application_sensitivity),
            ),
        ]),
    )
}
