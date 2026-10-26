//! Reproducible Criterion execution, raw-sample retention, delay sensitivity, and
//! conservative three-run baseline comparison for P0.
use super::{report, tooling};
use crate::acceptance::{Report, Verdict};
use crate::evidence::{self, Frozen, Gate, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const SAMPLE_COUNT: usize = 100;
const WARMUP_SECONDS: u64 = 5;
const MEASUREMENT_SECONDS: u64 = 10;
const WORKLOAD_CASES: usize = 76;
const COMPARISON_RUNS: usize = 3;
const REGRESSION_LIMIT: f64 = 1.05;
const VARIANCE_LIMIT: f64 = 0.05;
const CONTROLLED_DELAY_US: u64 = 1000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    version: u8,
    build: String,
    benchmark: String,
    cpu: u16,
    governor: String,
    maximum_load_per_cpu: f64,
    require_kernel_isolation: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Estimate {
    point: f64,
    lower: f64,
    upper: f64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Case {
    estimate_ns: Estimate,
    iterations: Vec<f64>,
    elapsed_ns: Vec<f64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Environment {
    cpu: u16,
    governor: String,
    kernel_isolated: bool,
    boost: String,
    model: String,
    load_per_cpu: f64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Run {
    environment: Environment,
    metadata: Value,
    cases: BTreeMap<String, Case>,
    command: Value,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Samples {
    version: u8,
    criterion_version: String,
    candidate: String,
    sample_count: usize,
    warmup_seconds: u64,
    measurement_seconds: u64,
    runs: Vec<Run>,
}

struct RunContext<'a> {
    frozen: &'a Frozen,
    gate: &'a Gate,
    runtime: &'a Path,
    config: &'a crate::source_inventory::SourceBuild,
    plan: &'a Plan,
    taskset: &'a Path,
    out_dir: &'a Path,
}

pub fn run(frozen: &Frozen, gate: &Gate, out_dir: &Path) -> Result<Report> {
    if gate.id != "P0" {
        return Err("performance runner requires P0".into());
    }
    let plan: Plan = super::behavior::plan(frozen, gate)?;
    validate_plan(frozen, gate, &plan)?;
    let config = super::behavior::build(frozen, &plan.build)?;
    if config.package != "kes-core" || config.target.is_some() {
        return Err("P0 requires the approved host kes-core build".into());
    }
    let performance = frozen
        .definition
        .performance
        .as_ref()
        .ok_or("missing approved performance plan")?;
    let run_count = if performance.establish {
        1
    } else {
        COMPARISON_RUNS
    };
    let minimum_measurement_ms =
        run_count as u64 * WORKLOAD_CASES as u64 * (WARMUP_SECONDS + MEASUREMENT_SECONDS) * 1000;
    if gate.budget_ms < minimum_measurement_ms {
        return Err(format!(
            "inconclusive: approved P0 budget {}ms cannot contain the required minimum {}ms for {run_count} independent run(s)",
            gate.budget_ms, minimum_measurement_ms
        ));
    }
    let taskset = pinned_tool(frozen, "taskset")?;
    let runtime = tooling::runtime_directory(frozen, gate)?;
    let sensitivity = sensitivity(frozen, gate, &runtime.path, config, &plan, &taskset)?;
    prepare_output(out_dir)?;
    let context = RunContext {
        frozen,
        gate,
        runtime: &runtime.path,
        config,
        plan: &plan,
        taskset: &taskset,
        out_dir,
    };
    let mut runs = Vec::with_capacity(run_count);
    for index in 0..run_count {
        runs.push(execute_run(&context, index)?);
    }
    let samples = Samples {
        version: 1,
        criterion_version: "0.8.2".into(),
        candidate: frozen.candidate.clone(),
        sample_count: SAMPLE_COUNT,
        warmup_seconds: WARMUP_SECONDS,
        measurement_seconds: MEASUREMENT_SECONDS,
        runs,
    };
    let samples_path = out_dir.join(if performance.establish {
        "baseline.json"
    } else {
        "samples.json"
    });
    evidence::write_new_json(&samples_path, &samples)?;
    let (verdict, variance, lower, upper, baseline_hash) = if performance.establish {
        (Verdict::Pass, 0.0, 1.0, 1.0, Value::Null)
    } else {
        let input = performance
            .baseline_input
            .as_ref()
            .ok_or("comparison requires an approved baseline input")?;
        let baseline_path = evidence::resolve_input(
            &frozen.workspace,
            frozen
                .definition
                .inputs
                .get(input)
                .ok_or("approved baseline input is absent")?,
        )?;
        let baseline: Samples = evidence::read_json(&baseline_path)?;
        validate_baseline(&baseline)?;
        let comparison = compare(&baseline, &samples)?;
        (
            comparison.verdict,
            comparison.environment_variance,
            comparison.lower,
            comparison.upper,
            Value::String(
                frozen
                    .identity
                    .inputs
                    .get(input)
                    .ok_or("frozen baseline identity is absent")?
                    .clone(),
            ),
        )
    };
    let cases = samples.runs.first().map_or(0, |run| run.cases.len() as u64);
    let mut result = report(
        frozen,
        gate,
        cases,
        BTreeMap::from([("crypto-benchmarks".into(), cases)]),
        BTreeMap::from([
            ("samples".into(), json!(SAMPLE_COUNT)),
            ("warmup_seconds".into(), json!(WARMUP_SECONDS)),
            ("measurement_seconds".into(), json!(MEASUREMENT_SECONDS)),
            ("establishes_baseline".into(), json!(performance.establish)),
            ("independent_runs".into(), json!(run_count)),
            ("ratio_ci95_lower".into(), json!(lower)),
            ("ratio_ci95_upper".into(), json!(upper)),
            ("environment_variance".into(), json!(variance)),
            ("baseline_sha256".into(), baseline_hash),
            ("controlled_delay_sensitivity".into(), sensitivity),
            (
                "samples_artifact".into(),
                json!(samples_path.file_name().and_then(|name| name.to_str())),
            ),
            (
                "peak_buffers".into(),
                samples.runs[0]
                    .metadata
                    .get("peak_buffers")
                    .cloned()
                    .ok_or("benchmark omitted peak-buffer metadata")?,
            ),
            (
                "core_allocations_per_operation".into(),
                samples.runs[0]
                    .metadata
                    .get("core_allocations_per_operation")
                    .cloned()
                    .ok_or("benchmark omitted allocation metadata")?,
            ),
        ]),
    );
    result.verdict = verdict;
    result.completed = true;
    Ok(result)
}

fn validate_plan(frozen: &Frozen, gate: &Gate, plan: &Plan) -> Result<()> {
    if plan.version != 1
        || plan.benchmark != "kes"
        || plan.governor.is_empty()
        || !plan.require_kernel_isolation
        || !plan.maximum_load_per_cpu.is_finite()
        || !(0.0..=0.1).contains(&plan.maximum_load_per_cpu)
    {
        return Err("invalid P0 execution plan".into());
    }
    super::behavior::exact_scopes(gate, ["crypto-benchmarks".to_owned()].into_iter())?;
    if !frozen.definition.features.contains(&plan.build) {
        return Err("P0 build is outside the frozen feature inventory".into());
    }
    Ok(())
}

fn pinned_tool(frozen: &Frozen, name: &str) -> Result<PathBuf> {
    let mut tools = frozen.identity.tools.values().filter(|tool| {
        tool.resolved_path
            .file_name()
            .is_some_and(|file| file == name)
    });
    let tool = tools
        .next()
        .ok_or_else(|| format!("unavailable: pinned {name} is required"))?;
    if tools.next().is_some() || evidence::file_hash(&tool.resolved_path)? != tool.sha256 {
        return Err(format!("ambiguous or changed pinned {name}"));
    }
    Ok(tool.resolved_path.clone())
}

fn environment(plan: &Plan) -> Result<Environment> {
    let cpu_root = PathBuf::from(format!("/sys/devices/system/cpu/cpu{}", plan.cpu));
    if !cpu_root
        .join("online")
        .read_to_string()
        .unwrap_or_else(|_| "1".into())
        .trim()
        .eq("1")
    {
        return Err("configured benchmark CPU is offline".into());
    }
    let governor = fs::read_to_string(cpu_root.join("cpufreq/scaling_governor"))
        .map_err(|_| "unavailable: CPU governor cannot be read")?
        .trim()
        .to_owned();
    if governor != plan.governor {
        return Err(format!(
            "inconclusive: required governor {}, found {governor}",
            plan.governor
        ));
    }
    let isolated_text = fs::read_to_string("/sys/devices/system/cpu/isolated")
        .map_err(|_| "unavailable: kernel isolated-CPU set cannot be read")?;
    let kernel_isolated = cpu_set_contains(&isolated_text, plan.cpu)?;
    if !kernel_isolated {
        return Err("inconclusive: configured benchmark CPU is not kernel-isolated".into());
    }
    let cpu_count = std::thread::available_parallelism()
        .map_err(|error| error.to_string())?
        .get() as f64;
    let load = fs::read_to_string("/proc/loadavg")
        .map_err(|error| error.to_string())?
        .split_whitespace()
        .next()
        .ok_or("missing one-minute host load")?
        .parse::<f64>()
        .map_err(|_| "invalid one-minute host load")?;
    let load_per_cpu = load / cpu_count;
    if load_per_cpu > plan.maximum_load_per_cpu {
        return Err(format!(
            "inconclusive: host load per CPU {load_per_cpu:.6} exceeds {}",
            plan.maximum_load_per_cpu
        ));
    }
    let cpuinfo = fs::read_to_string("/proc/cpuinfo").map_err(|error| error.to_string())?;
    let model = cpuinfo
        .lines()
        .find_map(|line| line.strip_prefix("model name\t: "))
        .ok_or("CPU model is unavailable")?
        .to_owned();
    let boost = [
        "/sys/devices/system/cpu/cpufreq/boost",
        "/sys/devices/system/cpu/amd_pstate/cpb_boost",
    ]
    .into_iter()
    .find_map(|path| fs::read_to_string(path).ok())
    .map_or_else(|| "unavailable".into(), |value| value.trim().to_owned());
    Ok(Environment {
        cpu: plan.cpu,
        governor,
        kernel_isolated,
        boost,
        model,
        load_per_cpu,
    })
}

fn same_fixed_environment(left: &Environment, right: &Environment) -> bool {
    left.cpu == right.cpu
        && left.governor == right.governor
        && left.kernel_isolated == right.kernel_isolated
        && left.boost == right.boost
        && left.model == right.model
}

trait ReadText {
    fn read_to_string(&self) -> std::io::Result<String>;
}
impl ReadText for PathBuf {
    fn read_to_string(&self) -> std::io::Result<String> {
        fs::read_to_string(self)
    }
}

fn cpu_set_contains(text: &str, cpu: u16) -> Result<bool> {
    for segment in text.trim().split(',').filter(|part| !part.is_empty()) {
        let mut bounds = segment.split('-');
        let first = bounds
            .next()
            .ok_or("invalid isolated-CPU set")?
            .parse::<u16>()
            .map_err(|_| "invalid isolated-CPU set")?;
        let last = bounds.next().map_or(Ok(first), |value| {
            value.parse::<u16>().map_err(|_| "invalid isolated-CPU set")
        })?;
        if bounds.next().is_some() || first > last {
            return Err("invalid isolated-CPU set".into());
        }
        if (first..=last).contains(&cpu) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn prepare_output(out_dir: &Path) -> Result<()> {
    if out_dir.exists() {
        return Err("P0 output directory must be fresh".into());
    }
    fs::create_dir_all(out_dir).map_err(|error| error.to_string())
}

fn cargo_bench(
    frozen: &Frozen,
    config: &crate::source_inventory::SourceBuild,
    plan: &Plan,
    taskset: &Path,
    target_dir: &Path,
) -> Result<Command> {
    let cargo = crate::source_inventory::cargo_command(
        config,
        &frozen.workspace,
        "bench",
        target_dir,
        Some(&plan.benchmark),
    )?;
    let mut command = Command::new(taskset);
    command
        .env_clear()
        .arg("--cpu-list")
        .arg(plan.cpu.to_string())
        .arg("--")
        .arg(cargo.get_program())
        .args(cargo.get_args());
    if let Some(directory) = cargo.get_current_dir() {
        command.current_dir(directory);
    }
    for (name, value) in cargo.get_envs() {
        if let Some(value) = value {
            command.env(name, value);
        }
    }
    Ok(command)
}

fn execute(command: &mut Command, gate: &Gate) -> Result<tooling::Output> {
    let output = tooling::run(command, gate.budget_ms)?;
    if output.timed_out {
        return Err("inconclusive: Criterion subprocess timed out".into());
    }
    super::behavior::succeeded(&output)?;
    Ok(output)
}

fn sensitivity(
    frozen: &Frozen,
    gate: &Gate,
    runtime: &Path,
    config: &crate::source_inventory::SourceBuild,
    plan: &Plan,
    taskset: &Path,
) -> Result<Value> {
    let before = environment(plan)?;
    let target = runtime.join("sensitivity");
    let mut clean = cargo_bench(frozen, config, plan, taskset, &target)?;
    clean.args([
        "--",
        "--quick",
        "--noplot",
        "--save-baseline",
        "p0-sensitivity-clean",
        "sensitivity/controlled_delay",
    ]);
    let clean_output = execute(&mut clean, gate)?;
    let mut delayed = cargo_bench(frozen, config, plan, taskset, &target)?;
    delayed
        .env(
            "KES_BENCH_CONTROLLED_DELAY_US",
            CONTROLLED_DELAY_US.to_string(),
        )
        .args([
            "--",
            "--quick",
            "--noplot",
            "--baseline",
            "p0-sensitivity-clean",
            "sensitivity/controlled_delay",
        ]);
    let delayed_output = execute(&mut delayed, gate)?;
    let after = environment(plan)?;
    if !same_fixed_environment(&before, &after) {
        return Err("inconclusive: benchmark environment changed during sensitivity".into());
    }
    let path = target.join("criterion/sensitivity_controlled_delay/change/estimates.json");
    let estimates: Value = evidence::read_json(&path)?;
    let lower = finite(&estimates["mean"]["confidence_interval"]["lower_bound"])?;
    let upper = finite(&estimates["mean"]["confidence_interval"]["upper_bound"])?;
    if lower <= REGRESSION_LIMIT - 1.0 {
        return Err("controlled delay did not produce a wholly detected regression".into());
    }
    Ok(json!({
        "mode": super::sensitivity::CONTROLLED_TIMING_REGRESSION,
        "detected": true,
        "clean": {
            "command": tooling::reading(&clean_output)
        },
        "defect": {
            "delay_us": CONTROLLED_DELAY_US,
            "change_ci95_lower": lower,
            "change_ci95_upper": upper,
            "detected": true,
            "command": tooling::reading(&delayed_output)
        },
        "counterexample": {
            "mode": super::sensitivity::CONTROLLED_TIMING_REGRESSION,
            "path": "criterion.sensitivity/controlled_delay",
            "observation": "the delayed sample's entire 95% change interval exceeded the 5% regression limit",
            "disclosure": "public"
        }
    }))
}

fn execute_run(context: &RunContext<'_>, index: usize) -> Result<Run> {
    let before = environment(context.plan)?;
    let target = context.runtime.join(format!("run-{index}"));
    let mut command = cargo_bench(
        context.frozen,
        context.config,
        context.plan,
        context.taskset,
        &target,
    )?;
    command.args([
        "--",
        "--noplot",
        "^(generation|evolution|sign|verify|codec|journal)/",
    ]);
    let output = execute(&mut command, context.gate)?;
    let after = environment(context.plan)?;
    if !same_fixed_environment(&before, &after) {
        return Err("inconclusive: benchmark environment changed during a run".into());
    }
    let metadata = metadata(&output)?;
    let cases = criterion_cases(&target.join("criterion"))?;
    validate_cases(&cases)?;
    let raw = context.out_dir.join(format!("criterion-run-{index}"));
    copy_tree(&target.join("criterion"), &raw)?;
    Ok(Run {
        environment: after,
        metadata,
        cases,
        command: tooling::reading(&output),
    })
}

fn metadata(output: &tooling::Output) -> Result<Value> {
    let mut found = Vec::new();
    for bytes in [&output.stdout, &output.stderr] {
        let text = std::str::from_utf8(bytes).map_err(|_| "benchmark output is not UTF-8")?;
        found.extend(
            text.lines()
                .filter_map(|line| line.strip_prefix("KES_BENCH_METADATA "))
                .map(serde_json::from_str::<Value>),
        );
    }
    if found.len() != 1 {
        return Err("benchmark must emit exactly one metadata record".into());
    }
    let value = found
        .pop()
        .unwrap()
        .map_err(|_| "invalid benchmark metadata")?;
    let evolution = value["evolution_boundaries"].as_u64();
    let allocations = value["core_allocations_per_operation"].as_u64();
    if value["version"] != 1 || evolution != Some(63) || allocations != Some(0) {
        return Err("benchmark metadata does not describe the required workload".into());
    }
    let peak = json!({
        "journal_workspace_bytes": value["journal_workspace_bytes"],
        "object_workspace_bytes": value["object_workspace_bytes"],
        "secret_cache_bytes": value["secret_cache_bytes"],
        "public_tree_bytes": value["public_tree_bytes"],
        "signing_state_bytes": value["signing_state_bytes"],
        "signature_bytes": value["signature_bytes"],
        "maximum_message_bytes": value["maximum_message_bytes"]
    });
    Ok(json!({
        "version": 1,
        "core_allocations_per_operation": 0,
        "evolution_boundaries": 63,
        "peak_buffers": peak
    }))
}

fn criterion_cases(root: &Path) -> Result<BTreeMap<String, Case>> {
    let mut benchmarks = Vec::new();
    collect_named(root, "benchmark.json", &mut benchmarks)?;
    let mut cases = BTreeMap::new();
    for benchmark in benchmarks {
        if benchmark
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            != Some("new")
        {
            continue;
        }
        let identity: Value = evidence::read_json(&benchmark)?;
        let id = identity["full_id"]
            .as_str()
            .ok_or("Criterion benchmark has no full_id")?;
        if id == "sensitivity/controlled_delay" {
            continue;
        }
        let directory = benchmark
            .parent()
            .ok_or("invalid Criterion benchmark path")?;
        let sample: Value = evidence::read_json(&directory.join("sample.json"))?;
        let estimates: Value = evidence::read_json(&directory.join("estimates.json"))?;
        let iterations = numbers(&sample["iters"])?;
        let elapsed_ns = numbers(&sample["times"])?;
        if iterations.len() != SAMPLE_COUNT
            || elapsed_ns.len() != SAMPLE_COUNT
            || iterations.len() != elapsed_ns.len()
            || iterations.iter().any(|value| *value <= 0.0)
            || elapsed_ns.iter().any(|value| *value <= 0.0)
        {
            return Err(format!("Criterion case {id} has incomplete raw samples"));
        }
        let estimate = estimates.get("slope").unwrap_or(&estimates["mean"]);
        let value = Case {
            estimate_ns: Estimate {
                point: finite(&estimate["point_estimate"])?,
                lower: finite(&estimate["confidence_interval"]["lower_bound"])?,
                upper: finite(&estimate["confidence_interval"]["upper_bound"])?,
            },
            iterations,
            elapsed_ns,
        };
        if value.estimate_ns.lower <= 0.0
            || value.estimate_ns.point < value.estimate_ns.lower
            || value.estimate_ns.upper < value.estimate_ns.point
            || cases.insert(id.to_owned(), value).is_some()
        {
            return Err(format!("invalid or duplicate Criterion case {id}"));
        }
    }
    Ok(cases)
}

fn validate_cases(cases: &BTreeMap<String, Case>) -> Result<()> {
    let expected_fixed = [
        "generation/sum6_64_leaves",
        "sign/bytes/0",
        "sign/bytes/256",
        "sign/bytes/4096",
        "verify/bytes/0",
        "verify/bytes/256",
        "verify/bytes/4096",
        "codec/cbor_encode_4096",
        "codec/cbor_decode_4096",
        "journal/snapshot_encode_staged",
        "journal/snapshot_decode_staged",
        "journal/initialize_authenticated",
        "journal/recover_authenticated",
    ];
    if cases.len() != WORKLOAD_CASES || expected_fixed.iter().any(|name| !cases.contains_key(*name))
    {
        return Err("P0 benchmark workload set is incomplete".into());
    }
    for period in 0..63 {
        let name = format!("evolution/boundary/{period:02}_to_{:02}", period + 1);
        if !cases.contains_key(&name) {
            return Err(format!("missing evolution boundary {name}"));
        }
    }
    Ok(())
}

fn collect_named(directory: &Path, name: &str, output: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(directory).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let kind = entry.file_type().map_err(|error| error.to_string())?;
        if kind.is_symlink() {
            return Err("Criterion output contains a symlink".into());
        }
        if kind.is_dir() {
            collect_named(&entry.path(), name, output)?;
        } else if kind.is_file() && entry.file_name() == name {
            output.push(entry.path());
        }
    }
    Ok(())
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir(destination).map_err(|error| error.to_string())?;
    for entry in fs::read_dir(source).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let kind = entry.file_type().map_err(|error| error.to_string())?;
        let target = destination.join(entry.file_name());
        if kind.is_symlink() {
            return Err("Criterion output contains a symlink".into());
        }
        if kind.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else if kind.is_file() {
            fs::copy(entry.path(), target).map_err(|error| error.to_string())?;
        } else {
            return Err("Criterion output contains a special file".into());
        }
    }
    Ok(())
}

fn numbers(value: &Value) -> Result<Vec<f64>> {
    value
        .as_array()
        .ok_or("expected numeric sample array")?
        .iter()
        .map(finite)
        .collect()
}

fn finite(value: &Value) -> Result<f64> {
    value
        .as_f64()
        .filter(|number| number.is_finite())
        .ok_or_else(|| "missing finite Criterion reading".into())
}

fn validate_baseline(baseline: &Samples) -> Result<()> {
    if baseline.version != 1
        || baseline.criterion_version != "0.8.2"
        || baseline.sample_count != SAMPLE_COUNT
        || baseline.warmup_seconds != WARMUP_SECONDS
        || baseline.measurement_seconds != MEASUREMENT_SECONDS
        || baseline.runs.is_empty()
    {
        return Err("approved P0 baseline has incompatible settings".into());
    }
    for run in &baseline.runs {
        validate_cases(&run.cases)?;
    }
    Ok(())
}

struct Comparison {
    verdict: Verdict,
    environment_variance: f64,
    lower: f64,
    upper: f64,
}

fn compare(baseline: &Samples, candidate: &Samples) -> Result<Comparison> {
    if candidate.runs.len() != COMPARISON_RUNS {
        return Err("P0 comparison requires three independent runs".into());
    }
    let baseline_environment = &baseline.runs[0].environment;
    if baseline
        .runs
        .iter()
        .chain(&candidate.runs)
        .any(|run| !same_fixed_environment(baseline_environment, &run.environment))
    {
        return Err("inconclusive: baseline and candidate environments differ".into());
    }
    let baseline_cases = &baseline.runs[0].cases;
    let mut maximum_variance = 0.0_f64;
    let mut minimum_lower = f64::INFINITY;
    let mut maximum_upper = 0.0_f64;
    let mut regression = false;
    let mut straddled = false;
    for name in baseline_cases.keys() {
        let baseline_lower = baseline
            .runs
            .iter()
            .map(|run| run.cases[name].estimate_ns.lower)
            .fold(f64::INFINITY, f64::min);
        let baseline_upper = baseline
            .runs
            .iter()
            .map(|run| run.cases[name].estimate_ns.upper)
            .fold(0.0_f64, f64::max);
        let points: Vec<_> = candidate
            .runs
            .iter()
            .map(|run| {
                run.cases
                    .get(name)
                    .ok_or_else(|| format!("candidate omitted P0 case {name}"))
            })
            .collect::<Result<_>>()?;
        let mean = points
            .iter()
            .map(|case| case.estimate_ns.point)
            .sum::<f64>()
            / points.len() as f64;
        let spread = (points
            .iter()
            .map(|case| case.estimate_ns.point)
            .fold(0.0_f64, f64::max)
            - points
                .iter()
                .map(|case| case.estimate_ns.point)
                .fold(f64::INFINITY, f64::min))
            / mean;
        maximum_variance = maximum_variance.max(spread);
        for case in points {
            let lower = case.estimate_ns.lower / baseline_upper;
            let upper = case.estimate_ns.upper / baseline_lower;
            minimum_lower = minimum_lower.min(lower);
            maximum_upper = maximum_upper.max(upper);
            regression |= lower > REGRESSION_LIMIT;
            straddled |= lower <= REGRESSION_LIMIT && upper > REGRESSION_LIMIT;
        }
    }
    let verdict = if maximum_variance > VARIANCE_LIMIT {
        Verdict::Inconclusive
    } else if regression {
        Verdict::Fail
    } else if straddled {
        Verdict::Inconclusive
    } else if maximum_upper <= REGRESSION_LIMIT {
        Verdict::Pass
    } else {
        Verdict::Inconclusive
    };
    Ok(Comparison {
        verdict,
        environment_variance: maximum_variance,
        lower: minimum_lower,
        upper: maximum_upper,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    fn temporary_directory() -> PathBuf {
        std::env::temp_dir().join(format!(
            "kes-forge-p0-parser-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ))
    }

    use super::*;

    fn case(point: f64, lower: f64, upper: f64) -> Case {
        Case {
            estimate_ns: Estimate {
                point,
                lower,
                upper,
            },
            iterations: vec![1.0; SAMPLE_COUNT],
            elapsed_ns: vec![point; SAMPLE_COUNT],
        }
    }

    fn samples(points: [(f64, f64, f64); 3]) -> Samples {
        let runs = points
            .into_iter()
            .map(|(point, lower, upper)| Run {
                environment: Environment {
                    cpu: 1,
                    governor: "performance".into(),
                    kernel_isolated: true,
                    boost: "0".into(),
                    model: "test".into(),
                    load_per_cpu: 0.0,
                },
                metadata: json!({}),
                cases: BTreeMap::from([("case".into(), case(point, lower, upper))]),
                command: json!({}),
            })
            .collect();
        Samples {
            version: 1,
            criterion_version: "0.8.2".into(),
            candidate: "test".into(),
            sample_count: SAMPLE_COUNT,
            warmup_seconds: WARMUP_SECONDS,
            measurement_seconds: MEASUREMENT_SECONDS,
            runs,
        }
    }

    #[test]
    fn cpu_set_parser_handles_ranges_and_refuses_malformed_input() {
        assert!(cpu_set_contains("1-3,8,10-12\n", 2).unwrap());
        assert!(!cpu_set_contains("1-3,8,10-12\n", 9).unwrap());
        assert!(cpu_set_contains("3-1", 2).is_err());
        assert!(cpu_set_contains("1-2-3", 2).is_err());
    }

    #[test]
    fn criterion_parser_retains_every_iteration_and_elapsed_sample() {
        let root = temporary_directory();
        let directory = root.join("case/new");
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("benchmark.json"),
            serde_json::to_vec(&json!({"full_id":"case"})).unwrap(),
        )
        .unwrap();
        fs::write(
            directory.join("sample.json"),
            serde_json::to_vec(&json!({
                "sampling_mode":"Linear",
                "iters":vec![1.0; SAMPLE_COUNT],
                "times":vec![2.0; SAMPLE_COUNT]
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            directory.join("estimates.json"),
            serde_json::to_vec(&json!({
                "slope":{
                    "point_estimate":2.0,
                    "confidence_interval":{"lower_bound":1.9,"upper_bound":2.1}
                }
            }))
            .unwrap(),
        )
        .unwrap();
        let cases = criterion_cases(&root).unwrap();
        assert_eq!(cases["case"].iterations.len(), SAMPLE_COUNT);
        assert_eq!(cases["case"].elapsed_ns.len(), SAMPLE_COUNT);
        assert_eq!(cases["case"].estimate_ns.point, 2.0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn comparison_passes_only_when_every_interval_and_run_is_below_limit() {
        let baseline = samples([(100.0, 99.0, 101.0); 3]);
        let candidate = samples([(101.0, 100.0, 102.0); 3]);
        let result = compare(&baseline, &candidate).unwrap();
        assert_eq!(result.verdict, Verdict::Pass);
        assert!(result.upper <= REGRESSION_LIMIT);

        let mut changed_environment = samples([(101.0, 100.0, 102.0); 3]);
        changed_environment.runs[0].environment.cpu = 2;
        assert!(compare(&baseline, &changed_environment).is_err());
    }

    #[test]
    fn comparison_distinguishes_regression_straddle_and_environment_noise() {
        let baseline = samples([(100.0, 99.5, 100.5); 3]);
        let regression = samples([(110.0, 108.0, 112.0); 3]);
        assert_eq!(
            compare(&baseline, &regression).unwrap().verdict,
            Verdict::Fail
        );

        let mut mixed_baseline = samples([(100.0, 99.5, 100.5); 3]);
        let mut mixed_candidate = samples([(110.0, 108.0, 112.0); 3]);
        for run in &mut mixed_baseline.runs {
            run.cases
                .insert("straddle".into(), case(100.0, 99.5, 100.5));
        }
        for run in &mut mixed_candidate.runs {
            run.cases
                .insert("straddle".into(), case(105.0, 103.0, 107.0));
        }
        assert_eq!(
            compare(&mixed_baseline, &mixed_candidate).unwrap().verdict,
            Verdict::Fail
        );

        let straddle = samples([(105.0, 103.0, 107.0); 3]);
        assert_eq!(
            compare(&baseline, &straddle).unwrap().verdict,
            Verdict::Inconclusive
        );

        let noisy = samples([
            (100.0, 99.0, 101.0),
            (106.0, 105.0, 107.0),
            (100.0, 99.0, 101.0),
        ]);
        assert_eq!(
            compare(&baseline, &noisy).unwrap().verdict,
            Verdict::Inconclusive
        );
    }
}
