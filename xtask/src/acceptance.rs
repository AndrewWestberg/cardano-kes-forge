use crate::evidence::{self, Frozen, Gate, Identity, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Pass,
    Fail,
    Inconclusive,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Hardware {
    pub silicon_revision: String,
    pub security_mode: String,
    pub qualified: bool,
    pub stock_clock: bool,
    pub firmware_sha256: String,
    pub flash_part: String,
    pub flash_capacity_bytes: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub version: u8,
    pub candidate: String,
    pub gate: String,
    pub identity: Identity,
    pub features: Vec<String>,
    pub scenarios: BTreeMap<String, u64>,
    pub cases: u64,
    pub verdict: Verdict,
    pub completed: bool,
    pub hardware: Option<Hardware>,
    pub measurements: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u8,
    pub candidate: String,
    pub gate: String,
    pub identity: Identity,
    pub environment: BTreeMap<String, String>,
    pub started_ms: u64,
    pub finished_ms: u64,
    pub duration_ms: u64,
    pub timed_out: bool,
    pub process_exit: Option<i32>,
    pub report_sha256: Option<String>,
    pub verdict: Verdict,
}

fn number(report: &Report, name: &str) -> Result<u64> {
    report
        .measurements
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{} missing unsigned measurement {name}", report.gate))
}

fn flag(report: &Report, name: &str) -> Result<()> {
    if report.measurements.get(name).and_then(Value::as_bool) != Some(true) {
        return Err(format!("{} missing/failed invariant {name}", report.gate));
    }
    Ok(())
}

fn fraction(report: &Report, name: &str) -> Result<f64> {
    report
        .measurements
        .get(name)
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite())
        .ok_or_else(|| format!("{} missing finite measurement {name}", report.gate))
}

fn measured_units<'a>(
    gate: &Gate,
    report: &'a Report,
    name: &str,
) -> Result<&'a serde_json::Map<String, Value>> {
    let units = report
        .measurements
        .get(name)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("missing {name} readings"))?;
    let expected: BTreeSet<_> = gate.scenarios.iter().map(String::as_str).collect();
    let actual: BTreeSet<_> = units.keys().map(String::as_str).collect();
    if expected != actual {
        return Err(format!("missing or unexpected {name} scope"));
    }
    Ok(units)
}

fn check_mutation(gate: &Gate, report: &Report) -> Result<()> {
    for (module, reading) in measured_units(gate, report, "modules")? {
        let eligible = reading["eligible_mutants"]
            .as_u64()
            .ok_or("missing eligible mutants")?;
        let detected = reading["detected_mutants"]
            .as_u64()
            .ok_or("missing detected mutants")?;
        if eligible == 0
            || detected > eligible
            || u128::from(detected) * 100 < u128::from(eligible) * 90
            || reading["critical_survivors"].as_u64() != Some(0)
        {
            return Err(format!(
                "empty, insensitive or critically surviving mutation module: {module}"
            ));
        }
    }
    Ok(())
}

fn check_coverage(frozen: &Frozen, gate: &Gate, report: &Report) -> Result<()> {
    for (name, reading) in measured_units(gate, report, "crates")? {
        let line = reading["line_coverage_percent"]
            .as_f64()
            .ok_or("missing crate line coverage")?;
        let changed = reading["changed_line_coverage_percent"]
            .as_f64()
            .ok_or("missing changed-line coverage")?;
        if !(90.0..=100.0).contains(&line)
            || !(0.0..=100.0).contains(&changed)
            || reading["changed_branches_complete"].as_bool() != Some(true)
        {
            return Err(format!("coverage or changed-branch gap in crate {name}"));
        }
        let baseline_hash = reading
            .get("baseline_sha256")
            .ok_or("missing explicit coverage baseline binding")?;
        if let Some(input) = &frozen.definition.coverage_baselines[name] {
            if baseline_hash.as_str() != Some(frozen.identity.inputs[input].as_str()) {
                return Err("changed-line baseline identity mismatch".to_owned());
            }
            let baseline: Value = evidence::read_json(&evidence::resolve_input(
                &frozen.workspace,
                &frozen.definition.inputs[input],
            )?)?;
            let prior = baseline["changed_line_coverage_percent"]
                .as_f64()
                .ok_or("invalid coverage baseline")?;
            if baseline["crate"].as_str() != Some(name)
                || !(0.0..=100.0).contains(&prior)
                || changed < prior
            {
                return Err(format!(
                    "changed-line coverage regressed or baseline belongs to another crate: {name}"
                ));
            }
        } else if !baseline_hash.is_null() {
            return Err("unexpected baseline for approved initial coverage measurement".to_owned());
        }
    }
    Ok(())
}

fn check_fuzz(gate: &Gate, report: &Report, final_candidate: bool) -> Result<()> {
    let targets = measured_units(gate, report, "targets")?;
    let required_seconds = if final_candidate { 86400 } else { 3600 };
    for (target, reading) in targets {
        if reading["seconds"]
            .as_u64()
            .is_none_or(|value| value < required_seconds)
            || reading["executions"]
                .as_u64()
                .is_none_or(|value| value == 0)
            || reading["corpus_inputs"]
                .as_u64()
                .is_none_or(|value| value == 0)
            || reading["sanitizers"].as_bool() != Some(true)
            || reading["semantic_oracle"].as_bool() != Some(true)
            || reading["findings"].as_u64() != Some(0)
        {
            return Err(format!("incomplete or failing fuzz reading: {target}"));
        }
    }
    Ok(())
}

fn check_performance(frozen: &Frozen, report: &Report, final_candidate: bool) -> Result<()> {
    if report.gate == "P0" {
        let sensitivity = report
            .measurements
            .get("controlled_delay_sensitivity")
            .and_then(Value::as_object)
            .ok_or("missing controlled-delay sensitivity reading")?;
        let peak = report
            .measurements
            .get("peak_buffers")
            .and_then(Value::as_object)
            .ok_or("missing peak-buffer reading")?;
        if report.cases != 76
            || sensitivity.get("detected").and_then(Value::as_bool) != Some(true)
            || report
                .measurements
                .get("core_allocations_per_operation")
                .and_then(Value::as_u64)
                != Some(0)
            || [
                ("journal_workspace_bytes", 8192),
                ("object_workspace_bytes", 6144),
                ("secret_cache_bytes", 64),
                ("public_tree_bytes", 4064),
                ("signing_state_bytes", 608),
                ("signature_bytes", 448),
                ("maximum_message_bytes", 4096),
            ]
            .iter()
            .any(|(name, expected)| peak.get(*name).and_then(Value::as_u64) != Some(*expected))
        {
            return Err(
                "incomplete benchmark case, allocation, buffer, or sensitivity reading".into(),
            );
        }
        if number(report, "samples")? < 100
            || number(report, "warmup_seconds")? < 5
            || number(report, "measurement_seconds")? < 10
        {
            return Err("incomplete benchmark workload".to_owned());
        }
        let plan = frozen
            .definition
            .performance
            .as_ref()
            .ok_or("missing approved performance plan")?;
        if report
            .measurements
            .get("establishes_baseline")
            .and_then(Value::as_bool)
            != Some(plan.establish)
            || !(0.0..=0.05).contains(&fraction(report, "environment_variance")?)
        {
            return Err(
                "report changed approved baseline plan or environment is inconclusive".to_owned(),
            );
        }
        let establishing = plan.establish;
        let independent_runs = number(report, "independent_runs")?;
        let ratio_lower = fraction(report, "ratio_ci95_lower")?;
        if (establishing
            && (independent_runs != 1
                || ratio_lower != 1.0
                || fraction(report, "ratio_ci95_upper")? != 1.0
                || !report
                    .measurements
                    .get("baseline_sha256")
                    .is_some_and(Value::is_null)))
            || (!establishing && (independent_runs != 3 || ratio_lower <= 0.0))
        {
            return Err(
                "benchmark run count, baseline marker, or confidence interval is invalid".into(),
            );
        }
        if !plan.establish {
            let input = plan
                .baseline_input
                .as_ref()
                .ok_or("missing approved comparison baseline")?;
            if report
                .measurements
                .get("baseline_sha256")
                .and_then(Value::as_str)
                != Some(frozen.identity.inputs[input].as_str())
                || number(report, "independent_runs")? < 3
                || fraction(report, "ratio_ci95_upper")? > 1.05
                || fraction(report, "ratio_ci95_upper")? <= 0.0
            {
                return Err(
                    "benchmark baseline mismatch, regression or inconclusive comparison".to_owned(),
                );
            }
        }
    } else {
        if number(report, "warm_requests")? == 0
            || number(report, "rounds")? == 0
            || fraction(report, "warm_within_100ms_fraction")? < 0.99
            || fraction(report, "warm_within_100ms_fraction")? > 1.0
            || number(report, "worst_admitted_ms")? > 500
            || number(report, "worst_overload_ms")? > 500
            || number(report, "worst_status_ms")? > 2000
            || number(report, "maximum_message_bytes")? != 4096
            || number(report, "pool_count")? != 32
            || number(report, "invalid_signatures")? != 0
            || number(report, "kes_ram_bytes")? > 262144
            || number(report, "free_sram_bytes")? < 32768
        {
            return Err("physical load/capacity invariant failed".to_owned());
        }
        flag(report, "original_admission_deadlines")?;
        flag(report, "sensitivity_passed")?;
        if final_candidate
            && (number(report, "warm_requests")? < 10000 || number(report, "rounds")? < 10000)
        {
            return Err("incomplete final load campaign".to_owned());
        }
    }
    Ok(())
}

fn check_measurements(frozen: &Frozen, gate: &Gate, report: &Report) -> Result<()> {
    let final_candidate = frozen.definition.increment == "final";
    match report.gate.as_str() {
        "G1" | "G2" => flag(report, "sensitivity_passed"),
        "G3" => {
            if report.cases < 10000
                || number(report, "minimum_sequence_length")? < 1
                || number(report, "maximum_sequence_length")? > 256
                || number(report, "pool_count")? != 32
                || number(report, "violations")? != 0
            {
                return Err("invalid lifecycle property workload/result".to_owned());
            }
            flag(report, "all_transitions_exercised")
        }
        "G4" => check_mutation(gate, report),
        "G5" => check_coverage(frozen, gate, report),
        "G6" => check_fuzz(gate, report, final_candidate),
        "G7" => {
            if number(report, "periods")? != 64
                || number(report, "independent_oracles")? < 2
                || number(report, "mismatches")? != 0
            {
                return Err(
                    "incomplete or disagreeing independent interoperability reading".to_owned(),
                );
            }
            flag(report, "unmodified_cli_11_4")
        }
        "G8" => {
            if number(report, "physical_cuts")? == 0
                || number(report, "corruption_trials")? == 0
                || number(report, "ack_regressions")? != 0
                || number(report, "lost_retained_artifacts")? != 0
                || number(report, "cross_pool_mutations")? != 0
                || number(report, "obsolete_secret_retained")? != 0
                || number(report, "invalid_signatures")? != 0
                || number(report, "successful_recoveries")? == 0
            {
                return Err("empty or failed physical fault campaign".to_owned());
            }
            if final_candidate && number(report, "physical_cuts")? < 1000 {
                return Err("incomplete final power-cut campaign".to_owned());
            }
            flag(report, "all_software_cut_points")?;
            flag(report, "sensitivity_passed")
        }
        "G9" => {
            if number(report, "unauthorized_results")? != 0 {
                return Err("security boundary violation".to_owned());
            }
            flag(report, "all_required_security_cases")
        }
        "G10" => {
            if number(report, "accepted_blocks_per_pool_minimum")? < 10
                || number(report, "outage_induced_file_misses")? != 0
            {
                return Err("mixed node integration requirement failed".to_owned());
            }
            flag(report, "mixed_single_pid")?;
            flag(report, "reconnected_same_pid")?;
            if matches!(
                frozen.definition.increment.as_str(),
                "US4" | "US5" | "final"
            ) {
                if number(report, "opportunities")? < 100
                    || number(report, "period_transitions")? < 2
                {
                    return Err("incomplete node transition campaign".to_owned());
                }
                flag(report, "rotation_and_telemetry")?;
            }
            Ok(())
        }
        "G11" => {
            if number(report, "operators")? < 5
                || number(report, "successful_operators")? < 4
                || number(report, "preview_periods")? < 2
                || number(report, "preprod_periods")? < 2
                || number(report, "preview_blocks")? < 10
                || number(report, "preprod_blocks")? < 10
            {
                return Err("operator/public-network campaign incomplete".to_owned());
            }
            flag(report, "independent_security_review")
        }
        "G12" => {
            if number(report, "threshold")? != 25 || number(report, "maximum_complexity")? > 25 {
                return Err("complexity threshold altered or exceeded".to_owned());
            }
            flag(report, "sensitivity_passed")
        }
        "P0" | "P1" => check_performance(frozen, report, final_candidate),
        _ => Err("unknown gate reading".to_owned()),
    }
}

pub fn validate_report(frozen: &Frozen, gate: &Gate, report: &Report) -> Result<()> {
    if report.version != 1
        || report.candidate != frozen.candidate
        || report.identity != frozen.identity
        || report.gate != gate.id
        || report.verdict != Verdict::Pass
        || !report.completed
        || report.cases < gate.minimum_cases
    {
        return Err(format!(
            "{} missing, empty, stale, failed or incomplete reading",
            gate.id
        ));
    }
    let expected_features: BTreeSet<_> = frozen.definition.features.iter().collect();
    let actual_features: BTreeSet<_> = report.features.iter().collect();
    if expected_features != actual_features || actual_features.len() != report.features.len() {
        return Err("feature inventory omitted, duplicated or changed".to_owned());
    }
    let expected_scenarios: BTreeSet<_> = gate.scenarios.iter().collect();
    let actual_scenarios: BTreeSet<_> = report.scenarios.keys().collect();
    if expected_scenarios != actual_scenarios || report.scenarios.values().any(|count| *count == 0)
    {
        return Err("scenario/count inventory incomplete or changed".to_owned());
    }
    if gate.hardware_required {
        let hardware = report
            .hardware
            .as_ref()
            .ok_or("required hardware reading missing")?;
        if !crate::qualify::feasibility::qualified_revision(&hardware.silicon_revision)
            || !hardware.qualified
            || !hardware.stock_clock
            || hardware.flash_capacity_bytes != 4194304
            || hardware.flash_part.is_empty()
            || hardware.firmware_sha256.len() != 64
            || !hardware
                .firmware_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("unqualified silicon/flash/clock/firmware; exploratory A2 cannot satisfy acceptance".to_owned());
        }
        let expected_mode = if frozen.definition.increment == "foundation" {
            "development"
        } else {
            "release-ready"
        };
        if hardware.security_mode != expected_mode {
            return Err("wrong hardware security mode".to_owned());
        }
        let artifact = if expected_mode == "development" {
            "firmware-development"
        } else {
            "firmware-release"
        };
        if frozen.identity.artifacts.get(artifact) != Some(&hardware.firmware_sha256) {
            return Err("hardware reading does not match the frozen firmware bytes".to_owned());
        }
    }
    check_measurements(frozen, gate, report)
}

fn verified_report(
    directory: &Path,
    frozen: &Frozen,
    gate: &Gate,
    manifest: &Manifest,
) -> Result<Report> {
    let path = directory.join(&gate.id).join("report.json");
    let bytes = evidence::json_bytes(&path)?;
    let digest = format!("{:x}", Sha256::digest(&bytes));
    if manifest.report_sha256.as_ref() != Some(&digest) {
        return Err("report content hash changed".to_owned());
    }
    let report: Report = crate::strict_json::from_slice(&bytes)
        .map_err(|error| format!("invalid gate report: {error}"))?;
    validate_report(frozen, gate, &report)?;
    Ok(report)
}

fn validate_manifest(frozen: &Frozen, gate: &Gate, manifest: &Manifest) -> Result<()> {
    if manifest.version != 1
        || manifest.candidate != frozen.candidate
        || manifest.identity != frozen.identity
        || manifest.gate != gate.id
        || manifest.verdict != Verdict::Pass
        || manifest.process_exit != Some(0)
        || manifest.timed_out
        || manifest.duration_ms > gate.budget_ms
        || manifest.started_ms < frozen.frozen_ms
        || manifest.finished_ms < manifest.started_ms
    {
        return Err(format!(
            "{} invalid, stale, unsuccessful or timed-out execution manifest",
            gate.id
        ));
    }
    if ["os", "architecture", "kernel", "cpu", "memory", "governor"]
        .iter()
        .any(|name| manifest.environment.get(*name).is_none_or(String::is_empty))
    {
        return Err("execution environment inventory is incomplete".to_owned());
    }
    Ok(())
}

pub fn accept(directory: &Path) -> Result<Value> {
    let frozen = evidence::load_current(directory)?;
    let mut readings = BTreeMap::new();
    for gate in &frozen.definition.gates {
        let manifest: Manifest =
            evidence::read_json(&directory.join(&gate.id).join("manifest.json"))?;
        validate_manifest(&frozen, gate, &manifest)?;
        verified_report(directory, &frozen, gate, &manifest)?;
        readings.insert(gate.id.clone(), manifest.report_sha256);
    }
    evidence::load_current(directory)?;
    let result = json!({"version":1,"candidate":frozen.candidate,"increment":frozen.definition.increment,
        "verdict":"pass","readings":readings,"identity":frozen.identity});
    evidence::write_new_json(&directory.join("acceptance/manifest.json"), &result)?;
    Ok(result)
}

/// Run one gate in a dedicated, single-threaded CLI controller process.
pub fn run_gate(directory: &Path, gate_id: &str) -> Result<Value> {
    let directory = fs::canonicalize(directory)
        .map_err(|error| format!("cannot resolve candidate directory: {error}"))?;
    let frozen = evidence::load_current(&directory)?;
    let gate = frozen
        .definition
        .gates
        .iter()
        .find(|gate| gate.id == gate_id)
        .ok_or("gate is not approved for this candidate")?;
    let gate_directory = directory.join(&gate.id);
    fs::create_dir(&gate_directory)
        .map_err(|error| format!("refusing to replace gate output: {error}"))?;
    let runtime = parent_runtime(&frozen, gate)?;
    crate::gates::tooling::controller_pid()?;
    enable_controller()?;
    let environment = evidence::environment();
    let started_ms = evidence::now_ms()?;
    let started = Instant::now();
    let mut command = Command::new(evidence::SESSION_SUPERVISOR);
    command.arg("--").arg(&gate.program);
    let mut child = command
        .args(&gate.args)
        .current_dir(&frozen.workspace)
        .env("KESFORGE_CANDIDATE_ROOT", &directory)
        .env("KESFORGE_GATE", &gate.id)
        .env("KESFORGE_GATE_RUNTIME", &runtime.path)
        .env("KESFORGE_GATE_CONTROLLER", std::process::id().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("gate executable unavailable: {error}"))?;
    let (status, timed_out) = loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            break (status, false);
        }
        if started.elapsed() >= Duration::from_millis(gate.budget_ms) {
            terminate_gate(&mut child)?;
            break (child.wait().map_err(|error| error.to_string())?, true);
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    terminate_gate(&mut child)?;
    let report_path = gate_directory.join("report.json");
    let report: Result<Report> = evidence::read_json(&report_path);
    let validation = report
        .as_ref()
        .map_err(Clone::clone)
        .and_then(|report| validate_report(&frozen, gate, report));
    let report_sha256 = evidence::file_hash(&report_path).ok();
    let elapsed = started.elapsed();
    let timed_out = timed_out || elapsed >= Duration::from_millis(gate.budget_ms);
    let duration_ms = elapsed
        .as_nanos()
        .div_ceil(1_000_000)
        .try_into()
        .map_err(|_| "gate duration overflow")?;
    let verdict = execution_verdict(timed_out, status.success(), &report, &validation);
    let manifest = Manifest {
        version: 1,
        candidate: frozen.candidate.clone(),
        gate: gate.id.clone(),
        identity: frozen.identity.clone(),
        environment,
        started_ms,
        finished_ms: evidence::now_ms()?,
        duration_ms,
        timed_out,
        process_exit: status.code(),
        report_sha256,
        verdict,
    };
    drop(runtime);
    evidence::write_new_json(&gate_directory.join("manifest.json"), &manifest)?;
    evidence::load_current(&directory)?;
    if verdict != Verdict::Pass {
        return Err(format!(
            "{} gate produced {verdict:?}; {}",
            gate.id,
            validation
                .err()
                .unwrap_or_else(|| "execution did not complete successfully".to_owned())
        ));
    }
    Ok(json!({"candidate":frozen.candidate,"gate":gate.id,"verdict":"pass"}))
}

fn execution_verdict(
    timed_out: bool,
    succeeded: bool,
    report: &Result<Report>,
    validation: &Result<()>,
) -> Verdict {
    if timed_out {
        return Verdict::Inconclusive;
    }
    let Ok(report) = report else {
        return Verdict::Unavailable;
    };
    if report.verdict != Verdict::Pass {
        return report.verdict;
    }
    if !succeeded || validation.is_err() {
        Verdict::Fail
    } else {
        Verdict::Pass
    }
}

fn parent_runtime(frozen: &Frozen, gate: &Gate) -> Result<crate::gates::tooling::RuntimeDirectory> {
    use std::os::unix::fs::DirBuilderExt;
    let path = frozen
        .workspace
        .join("target/gate-runtime")
        .join(&frozen.candidate)
        .join(&gate.id);
    let parent = path.parent().ok_or("runtime parent missing")?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)
        .map_err(|error| error.to_string())?;
    if fs::canonicalize(parent).map_err(|error| error.to_string())? != parent {
        return Err("gate runtime parent is redirected through a symlink".to_owned());
    }
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .map_err(|error| format!("refusing to replace gate runtime: {error}"))?;
    Ok(crate::gates::tooling::RuntimeDirectory { path })
}

fn controller_children() -> Result<String> {
    fs::read_to_string(format!("/proc/self/task/{}/children", std::process::id()))
        .map_err(|error| format!("cannot inspect controller children: {error}"))
}

fn enable_controller() -> Result<()> {
    let mut threads = fs::read_dir("/proc/self/task").map_err(|error| error.to_string())?;
    let first = threads
        .next()
        .transpose()
        .map_err(|error| error.to_string())?;
    let second = threads
        .next()
        .transpose()
        .map_err(|error| error.to_string())?;
    if first.is_none() || second.is_some() || !controller_children()?.trim().is_empty() {
        return Err(
            "gate execution requires a dedicated single-threaded controller process".into(),
        );
    }
    // Rustix represents PR_SET_CHILD_SUBREAPER's nonzero enable flag as a PID.
    rustix::process::set_child_subreaper(Some(rustix::process::getpid()))
        .map_err(|error| format!("cannot enable gate child adoption: {error}"))?;
    if rustix::process::child_subreaper()
        .map_err(|error| error.to_string())?
        .is_none()
    {
        return Err("kernel did not enable gate child adoption".into());
    }
    Ok(())
}

fn terminate_gate(child: &mut Child) -> Result<ExitStatus> {
    if child
        .try_wait()
        .map_err(|error| error.to_string())?
        .is_none()
    {
        child
            .kill()
            .map_err(|error| format!("cannot stop gate session leader: {error}"))?;
    }
    let status = child.wait().map_err(|error| error.to_string())?;
    let cleanup = Instant::now();
    loop {
        reap_children()?;
        let children = controller_children()?;
        if children.trim().is_empty() {
            return Ok(status);
        }
        for child in children.split_whitespace() {
            let pid = child
                .parse::<i32>()
                .ok()
                .and_then(rustix::process::Pid::from_raw)
                .ok_or("invalid adopted gate child PID")?;
            match rustix::process::kill_process(pid, rustix::process::Signal::KILL) {
                Ok(()) | Err(rustix::io::Errno::SRCH) => {}
                Err(error) => return Err(format!("cannot stop adopted gate child: {error}")),
            }
        }
        if cleanup.elapsed() >= Duration::from_secs(2) {
            return Err("gate descendants remain alive after bounded cleanup".to_owned());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn reap_children() -> Result<()> {
    loop {
        match rustix::process::wait(rustix::process::WaitOptions::NOHANG) {
            Ok(Some(_)) | Err(rustix::io::Errno::INTR) => {}
            Ok(None) | Err(rustix::io::Errno::CHILD) => return Ok(()),
            Err(error) => return Err(format!("cannot reap adopted gate child: {error}")),
        }
    }
}
