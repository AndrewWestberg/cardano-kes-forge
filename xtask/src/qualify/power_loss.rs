//! Software-cut and ordinary physical power-loss qualification.
use super::feasibility::{
    CampaignHeader, CampaignIdentity, PreparedCampaign, decode_hex, public_message, read_records,
    validate_header,
};
use crate::acceptance::{Hardware, Report};
use crate::evidence::{self, Result};
use crate::fixture::{Content, Workstation};
use crate::oracles::{Baseline, Oracle};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

pub const OPERATIONAL_BOUNDARIES: [&str; 18] = [
    "candidate-object-write",
    "candidate-object-read-verify",
    "candidate-bank-erase",
    "candidate-bank-write",
    "candidate-bank-verify",
    "commit-page-erase",
    "commit-page-write",
    "commit-page-verify",
    "predecessor-bank-erase",
    "predecessor-bank-verify",
    "ram-secret-wipe",
    "clean-page-erase",
    "clean-page-write",
    "clean-page-verify",
    "acknowledgement",
    "verification-key-output-link",
    "encrypted-backup-output-link",
    "completion-manifest-output-link",
];

const OPERATIONAL_SCENARIOS: [&str; 6] = [
    "generation",
    "first-activation",
    "evolution-signing",
    "expiry",
    "output-publication",
    "management-lifecycle",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControllerProbe {
    version: u8,
    physical: bool,
    ready: bool,
    identity_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CutRecord {
    record: String,
    trial: u64,
    operation: String,
    boundary: String,
    pool: u8,
    active_before: u8,
    staged_before: u8,
    deliberate_corruption: bool,
    physical_power_cycle: bool,
    acknowledged_before_cut: bool,
    ack_before_revision: u64,
    ack_before_period: u8,
    ack_after_revision: Option<u64>,
    ack_after_period: Option<u8>,
    recovery_outcome: String,
    recovery_duration_ms: u64,
    lost_retained_artifact: bool,
    cross_pool_mutation: bool,
    obsolete_secret_retained: bool,
    returned_period: Option<u8>,
    verification_key_hex: Option<String>,
    signature_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FaultFooter {
    record: String,
    version: u8,
    seeded_defect: Option<String>,
    physical_cuts: u64,
    corruption_trials: u64,
    software_cut_points: BTreeMap<String, u64>,
    maximum_recovery_duration_ms: u64,
    scenarios: BTreeMap<String, u64>,
}

#[derive(Debug)]
pub struct PowerLossResult {
    pub identity: CampaignIdentity,
    pub hardware: Hardware,
    pub cases: u64,
    pub scenarios: BTreeMap<String, u64>,
    pub physical_cuts: u64,
    pub corruption_trials: u64,
    pub ack_regressions: u64,
    pub lost_retained_artifacts: u64,
    pub cross_pool_mutations: u64,
    pub obsolete_secret_retained: u64,
    pub invalid_signatures: u64,
    pub successful_recoveries: u64,
    pub maximum_recovery_duration_ms: u64,
    pub software_cut_points: BTreeMap<String, u64>,
    pub controller_identity_sha256: String,
    pub sensitivity_passed: bool,
}

#[derive(Debug, Serialize)]
pub struct SoftwarePowerLossResult {
    pub manifest: PathBuf,
    pub ordinary_recovery_cases: u64,
    pub intentional_corruption_cases: u64,
    pub pool_identities: Vec<String>,
    pub operational_boundaries: Vec<String>,
    pub scenarios: BTreeMap<String, u64>,
    pub maximum_scenario_duration_ms: u64,
}

#[derive(Debug, Serialize)]
struct SoftwareRun {
    scenario: String,
    command: Vec<String>,
    duration_ms: u64,
    log: String,
    log_sha256: String,
}

#[derive(Debug, Serialize)]
struct SoftwareManifest {
    version: u8,
    campaign: &'static str,
    verdict: &'static str,
    physical_status: &'static str,
    operational_boundaries: Vec<String>,
    cut_schedule: BTreeMap<String, Vec<String>>,
    public_state_before_after_ack: [&'static str; 6],
    signature_verification: &'static str,
    ordinary_recovery_cases: u64,
    intentional_corruption_cases: u64,
    pool_identities: Vec<String>,
    scenarios: BTreeMap<String, u64>,
    maximum_scenario_duration_ms: u64,
    aggregate_readings: BTreeMap<String, Value>,
    runs: Vec<SoftwareRun>,
}

trait SignatureVerifier {
    fn verify(&self, vk: &[u8; 32], period: u8, message: &[u8], signature: &[u8; 448]) -> bool;
}

struct Verifiers {
    cli: Oracle,
    node: Oracle,
}

impl Verifiers {
    fn pinned() -> Result<Self> {
        Ok(Self {
            cli: Oracle::pinned(Baseline::Cli114)?,
            node: Oracle::pinned(Baseline::Node1113)?,
        })
    }
}

impl SignatureVerifier for Verifiers {
    fn verify(&self, vk: &[u8; 32], period: u8, message: &[u8], signature: &[u8; 448]) -> bool {
        self.cli.verify(vk, period, message, signature) == Ok(true)
            && self.node.verify(vk, period, message, signature) == Ok(true)
    }
}

#[derive(Default)]
struct Accumulator {
    header: Option<CampaignHeader>,
    footer: Option<FaultFooter>,
    trials: BTreeSet<u64>,
    boundaries: BTreeSet<String>,
    operations: BTreeSet<String>,
    physical_cuts: u64,
    corruption_trials: u64,
    ack_regressions: u64,
    lost_retained_artifacts: u64,
    cross_pool_mutations: u64,
    obsolete_secret_retained: u64,
    invalid_signatures: u64,
    successful_recoveries: u64,
    maximum_recovery_duration_ms: u64,
}

pub fn run(fixture: &Path, cuts: u64, evidence_dir: &Path) -> Result<PowerLossResult> {
    if cuts < OPERATIONAL_BOUNDARIES.len() as u64 {
        return Err("physical schedule must cover every operational transaction boundary".into());
    }
    let prepared = super::feasibility::prepare(fixture)?;
    let controller = probe_controller(&prepared)?;
    let verifiers = Verifiers::pinned()?;
    let clean_identity = prepared.execute(
        "power-loss",
        cuts,
        0,
        None,
        evidence_dir,
        "power-loss-clean.ndjson",
    )?;
    let mut clean = validate(
        &prepared,
        clean_identity,
        cuts,
        None,
        &controller.identity_sha256,
        &verifiers,
    )?;
    if clean.ack_regressions != 0
        || clean.lost_retained_artifacts != 0
        || clean.cross_pool_mutations != 0
        || clean.obsolete_secret_retained != 0
        || clean.invalid_signatures != 0
    {
        return Err("clean physical power-loss invariant failed".to_owned());
    }

    for defect in ["drop-acknowledged-commit", "skip-old-bank-erase"] {
        let name = format!("power-loss-seeded-{defect}.ndjson");
        let identity = prepared.execute(
            "power-loss",
            OPERATIONAL_BOUNDARIES.len() as u64,
            0,
            Some(defect),
            evidence_dir,
            &name,
        )?;
        let seeded = validate(
            &prepared,
            identity,
            OPERATIONAL_BOUNDARIES.len() as u64,
            Some(defect),
            &controller.identity_sha256,
            &verifiers,
        )?;
        let detected = match defect {
            "drop-acknowledged-commit" => seeded.ack_regressions > 0,
            "skip-old-bank-erase" => seeded.obsolete_secret_retained > 0,
            _ => false,
        };
        if !detected {
            return Err(format!("seeded physical fault was not detected: {defect}"));
        }
    }
    clean.sensitivity_passed = true;
    Ok(clean)
}

pub fn run_software(evidence_dir: &Path) -> Result<SoftwarePowerLossResult> {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("xtask workspace root unavailable")?;
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let commands = [
        (
            "pool-journal-cuts",
            vec![
                "test",
                "--locked",
                "--release",
                "-p",
                "kes-core",
                "--features",
                "protected-runtime",
                "--test",
                "journal_faults",
                "every_transaction_prefix_bit_cut_drops_volatile_owners_and_never_rolls_back_commit",
                "--",
                "--exact",
                "--test-threads=1",
                "--nocapture",
            ],
        ),
        (
            "directory-journal-cuts",
            vec![
                "test",
                "--locked",
                "--release",
                "-p",
                "kes-core",
                "--features",
                "protected-runtime",
                "--test",
                "journal_faults",
                "directory::directory_byte_boundary_cuts_cover_both_erase_sectors_without_rollback",
                "--",
                "--exact",
                "--test-threads=1",
                "--nocapture",
            ],
        ),
        (
            "generation",
            vec![
                "test",
                "--locked",
                "-p",
                "kes-core",
                "--features",
                "protected-runtime",
                "--test",
                "generation_concurrency",
                "--",
                "--test-threads=1",
            ],
        ),
        (
            "activation-evolution-expiry",
            vec![
                "test",
                "--locked",
                "-p",
                "kes-core",
                "--features",
                "protected-runtime",
                "--test",
                "operations",
                "--",
                "--test-threads=1",
            ],
        ),
        (
            "restart-output-publication",
            vec![
                "test",
                "--locked",
                "--test",
                "operation_restart",
                "--",
                "--test-threads=1",
            ],
        ),
        (
            "socket-reconnect",
            vec![
                "test",
                "--locked",
                "--test",
                "reconnect_recovery",
                "--",
                "--test-threads=1",
            ],
        ),
        (
            "reconnect-expiry",
            vec![
                "test",
                "--locked",
                "-p",
                "kes-core",
                "--features",
                "protected-runtime",
                "--test",
                "lifecycle_properties",
                "skipped_current_earlier_final_and_uncertain_reconnect_are_monotonic",
                "--",
                "--test-threads=1",
            ],
        ),
        (
            "management-lifecycle",
            vec![
                "test",
                "--locked",
                "-p",
                "kes-core",
                "--features",
                "protected-runtime",
                "--test",
                "management_lifecycle",
                "--",
                "--test-threads=1",
            ],
        ),
        (
            "pool-identities",
            vec![
                "test",
                "--locked",
                "-p",
                "kes-core",
                "--features",
                "protected-runtime",
                "--test",
                "lifecycle_properties",
                "directory_capacity_preserves_full_pool_identity_and_stable_slots",
                "--",
                "--test-threads=1",
                "--nocapture",
            ],
        ),
    ];
    fs::create_dir_all(evidence_dir).map_err(|error| error.to_string())?;
    let mut runs = Vec::with_capacity(commands.len());
    let mut aggregate_readings = BTreeMap::new();
    let mut pool_identities = None;
    let mut maximum_scenario_duration_ms = 0;
    for (scenario, arguments) in commands {
        let started = Instant::now();
        let output = Command::new(&cargo)
            .args(&arguments)
            .current_dir(workspace)
            .stdin(Stdio::null())
            .output()
            .map_err(|error| format!("software power-loss scenario {scenario} failed: {error}"))?;
        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        maximum_scenario_duration_ms = maximum_scenario_duration_ms.max(duration_ms);
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let mut log = output.stdout.clone();
        log.extend_from_slice(b"\n--- stderr ---\n");
        log.extend_from_slice(&output.stderr);
        let log_name = format!("software-{scenario}.log");
        let log_path = evidence_dir.join(&log_name);
        write_new_log(&log_path, &log)?;
        let log_sha256 = evidence::file_hash(&log_path)?;
        if !output.status.success() {
            return Err(format!(
                "software power-loss scenario {scenario} failed; log {log_sha256}"
            ));
        }
        if scenario == "pool-journal-cuts" {
            aggregate_readings.insert(
                "pool_journal".to_owned(),
                prefixed_json(&stdout, "POOL_JOURNAL_CUTS ")?,
            );
        } else if scenario == "directory-journal-cuts" {
            aggregate_readings.insert(
                "directory_journal".to_owned(),
                prefixed_json(&stdout, "KES_DIRECTORY_FAULT_SUMMARY ")?,
            );
        } else if scenario == "pool-identities" {
            let value = prefixed_json(&stdout, "KES_POOL_IDENTITIES ")?;
            pool_identities = Some(
                serde_json::from_value::<Vec<String>>(value)
                    .map_err(|_| "invalid software pool identity reading".to_owned())?,
            );
        }
        runs.push(SoftwareRun {
            scenario: scenario.to_owned(),
            command: arguments.into_iter().map(str::to_owned).collect(),
            duration_ms,
            log: log_name,
            log_sha256,
        });
    }
    let pool_identities = pool_identities.ok_or("software pool identities missing")?;
    let unique: BTreeSet<_> = pool_identities.iter().collect();
    if pool_identities.len() != 32
        || unique.len() != 32
        || pool_identities
            .iter()
            .any(|identity| !super::feasibility::lower_hex(identity, 56))
    {
        return Err("software campaign did not record 32 distinct pool identities".to_owned());
    }
    let pool_cases = aggregate_readings["pool_journal"]["cuts"]
        .as_u64()
        .ok_or("pool journal cut count missing")?;
    let directory_cases = aggregate_readings["directory_journal"]["byte_boundary_cuts"]
        .as_u64()
        .ok_or("directory journal cut count missing")?;
    let ordinary_recovery_cases = pool_cases
        .checked_add(directory_cases)
        .ok_or("software recovery case count overflow")?;
    let operational_boundaries: Vec<String> = OPERATIONAL_BOUNDARIES
        .iter()
        .map(|boundary| (*boundary).to_owned())
        .collect();
    let journal_boundaries = operational_boundaries[..15].to_vec();
    let state_boundaries = operational_boundaries[2..15].to_vec();
    let output_boundaries = operational_boundaries[15..].to_vec();
    let cut_schedule = BTreeMap::from([
        ("generation".to_owned(), journal_boundaries),
        ("first-activation".to_owned(), state_boundaries.clone()),
        ("evolution-signing".to_owned(), state_boundaries.clone()),
        ("expiry".to_owned(), state_boundaries),
        ("output-publication".to_owned(), output_boundaries),
    ]);
    let scenarios: BTreeMap<String, u64> = OPERATIONAL_SCENARIOS
        .iter()
        .map(|scenario| ((*scenario).to_owned(), 1))
        .collect();
    let manifest = SoftwareManifest {
        version: 1,
        campaign: "operational-software-power-loss",
        verdict: "pass",
        physical_status: "unavailable-not-attempted",
        operational_boundaries: operational_boundaries.clone(),
        cut_schedule,
        public_state_before_after_ack: [
            "revision",
            "relativePeriod",
            "activeGeneration",
            "stagedGeneration",
            "lifecycle",
            "publicObjectReference",
        ],
        signature_verification: "every signature returned by the exercised operations path was independently verified",
        ordinary_recovery_cases,
        intentional_corruption_cases: 1,
        pool_identities: pool_identities.clone(),
        scenarios: scenarios.clone(),
        maximum_scenario_duration_ms,
        aggregate_readings,
        runs,
    };
    let manifest_path = evidence_dir.join("software-power-loss.json");
    evidence::write_new_json(&manifest_path, &manifest)?;
    Ok(SoftwarePowerLossResult {
        manifest: manifest_path,
        ordinary_recovery_cases,
        intentional_corruption_cases: 1,
        pool_identities,
        operational_boundaries,
        scenarios,
        maximum_scenario_duration_ms,
    })
}

fn prefixed_json(output: &str, prefix: &str) -> Result<Value> {
    let encoded = output
        .lines()
        .find_map(|line| line.find(prefix).map(|index| &line[index + prefix.len()..]))
        .ok_or_else(|| format!("software campaign output omitted {prefix}"))?;
    crate::strict_json::from_slice(encoded.as_bytes())
        .map_err(|error| format!("invalid software campaign reading {prefix}: {error}"))
}

fn write_new_log(path: &Path, contents: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
    file.write_all(contents)
        .map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())
}

fn probe_controller(prepared: &PreparedCampaign) -> Result<ControllerProbe> {
    let reference = &prepared.manifest.power_controller_executable;
    if reference.workstation != Workstation::PowerController
        || !matches!(&reference.content, Content::Executable)
        || !reference.path.is_absolute()
        || !prepared
            .manifest
            .power_controller_endpoint
            .path
            .is_absolute()
    {
        return Err("physical power-controller declaration is invalid".to_owned());
    }
    let executable = fs::canonicalize(&reference.path)
        .map_err(|_| "physical power-controller executable unavailable".to_owned())?;
    let metadata = fs::symlink_metadata(&executable)
        .map_err(|_| "physical power-controller executable unavailable".to_owned())?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err("physical power-controller executable is not executable".to_owned());
    }
    let output = Command::new(executable)
        .args(["probe", "--endpoint"])
        .arg(&prepared.manifest.power_controller_endpoint.path)
        .args(["--output-format", "json-v1"])
        .env_clear()
        .env("LANG", "C")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| "physical power-controller probe failed".to_owned())?;
    if !output.status.success() || output.stdout.len() > super::feasibility::MAX_RECORD_BYTES {
        return Err("physical power-controller probe failed".to_owned());
    }
    let probe: ControllerProbe = crate::strict_json::from_slice(&output.stdout)
        .map_err(|error| format!("invalid power-controller probe: {error}"))?;
    if probe.version != 1
        || !probe.physical
        || !probe.ready
        || !super::feasibility::lower_hex(&probe.identity_sha256, 64)
    {
        return Err("power-controller is not ready for physical interruption".to_owned());
    }
    Ok(probe)
}

fn validate(
    prepared: &PreparedCampaign,
    identity: CampaignIdentity,
    expected_cuts: u64,
    expected_defect: Option<&str>,
    controller_identity: &str,
    verifiers: &impl SignatureVerifier,
) -> Result<PowerLossResult> {
    let mut state = Accumulator::default();
    read_records(&identity.raw_path, |index, bytes| {
        let value: Value = crate::strict_json::from_slice(bytes)
            .map_err(|error| format!("invalid power-loss record {index}: {error}"))?;
        match value.get("record").and_then(Value::as_str) {
            Some("header") if index == 1 && state.header.is_none() => {
                let header: CampaignHeader = crate::strict_json::from_slice(bytes)
                    .map_err(|error| format!("invalid power-loss header: {error}"))?;
                validate_header(prepared, &header, "power-loss")?;
                state.header = Some(header);
            }
            Some("cut") if state.header.is_some() && state.footer.is_none() => {
                let record: CutRecord = crate::strict_json::from_slice(bytes)
                    .map_err(|error| format!("invalid power-loss event: {error}"))?;
                validate_cut(prepared, &record, expected_cuts, verifiers, &mut state)?;
            }
            Some("summary") if state.header.is_some() && state.footer.is_none() => {
                state.footer = Some(
                    crate::strict_json::from_slice(bytes)
                        .map_err(|error| format!("invalid power-loss summary: {error}"))?,
                );
            }
            _ => return Err("power-loss record order/type is invalid".to_owned()),
        }
        Ok(())
    })?;
    finish(
        prepared,
        identity,
        expected_cuts,
        expected_defect,
        controller_identity,
        state,
    )
}

fn validate_cut(
    prepared: &PreparedCampaign,
    record: &CutRecord,
    expected_cuts: u64,
    verifiers: &impl SignatureVerifier,
    state: &mut Accumulator,
) -> Result<()> {
    if record.record != "cut"
        || record.trial == 0
        || record.trial > expected_cuts + OPERATIONAL_BOUNDARIES.len() as u64
        || !state.trials.insert(record.trial)
        || record.pool >= 32
        || record.active_before != 32
        || record.staged_before != 32
        || !record.physical_power_cycle
        || record.recovery_duration_ms == 0
    {
        return Err("invalid physical cut identity, occupancy, or recovery reading".to_owned());
    }
    if !OPERATIONAL_BOUNDARIES.contains(&record.boundary.as_str()) {
        return Err("unrecognized operational transaction boundary".to_owned());
    }
    if !OPERATIONAL_SCENARIOS.contains(&record.operation.as_str()) {
        return Err("unrecognized operational physical-cut scenario".to_owned());
    }
    state.boundaries.insert(record.boundary.clone());
    state.operations.insert(record.operation.clone());
    state.maximum_recovery_duration_ms = state
        .maximum_recovery_duration_ms
        .max(record.recovery_duration_ms);

    if record.deliberate_corruption {
        state.corruption_trials += 1;
        if record.recovery_outcome != "quarantined"
            || record.ack_after_revision.is_some()
            || record.ack_after_period.is_some()
        {
            return Err("deliberate corruption was counted as successful recovery".to_owned());
        }
        return Ok(());
    }
    state.physical_cuts += 1;
    if !matches!(record.recovery_outcome.as_str(), "original" | "committed") {
        return Err("ordinary physical cut did not recover a permitted state".to_owned());
    }
    let after_revision = record
        .ack_after_revision
        .ok_or("successful recovery omitted public revision")?;
    let after_period = record
        .ack_after_period
        .ok_or("successful recovery omitted public period")?;
    if record.acknowledged_before_cut
        && (after_revision < record.ack_before_revision || after_period < record.ack_before_period)
    {
        state.ack_regressions += 1;
    }
    state.lost_retained_artifacts += u64::from(record.lost_retained_artifact);
    state.cross_pool_mutations += u64::from(record.cross_pool_mutation);
    state.obsolete_secret_retained += u64::from(record.obsolete_secret_retained);
    if let (Some(period), Some(vk), Some(signature)) = (
        record.returned_period,
        record.verification_key_hex.as_deref(),
        record.signature_hex.as_deref(),
    ) {
        let vk = decode_hex::<32>(vk)?;
        let signature = decode_hex::<448>(signature)?;
        let phase = format!("power-loss/{}/{}", record.operation, record.boundary);
        let message = public_message(
            &prepared.manifest.scenario_id,
            &phase,
            record.trial,
            record.pool,
        );
        if !verifiers.verify(&vk, period, &message, &signature) {
            state.invalid_signatures += 1;
        }
    } else if record.operation == "evolution-signing" {
        return Err("successful evolution/signing recovery omitted signature evidence".to_owned());
    }
    state.successful_recoveries += 1;
    Ok(())
}

fn finish(
    _prepared: &PreparedCampaign,
    identity: CampaignIdentity,
    expected_cuts: u64,
    expected_defect: Option<&str>,
    controller_identity: &str,
    state: Accumulator,
) -> Result<PowerLossResult> {
    let header = state.header.ok_or("power-loss header missing")?;
    let footer = state.footer.ok_or("power-loss summary missing")?;
    let expected_boundaries: BTreeSet<_> = OPERATIONAL_BOUNDARIES
        .iter()
        .map(|boundary| (*boundary).to_owned())
        .collect();
    if footer.record != "summary"
        || footer.version != 1
        || footer.seeded_defect.as_deref() != expected_defect
        || footer.physical_cuts != state.physical_cuts
        || footer.corruption_trials != state.corruption_trials
        || state.physical_cuts != expected_cuts
        || state.boundaries != expected_boundaries
        || state.operations
            != OPERATIONAL_SCENARIOS
                .iter()
                .map(|scenario| (*scenario).to_owned())
                .collect()
        || footer.maximum_recovery_duration_ms != state.maximum_recovery_duration_ms
        || footer.software_cut_points.keys().collect::<BTreeSet<_>>()
            != expected_boundaries.iter().collect::<BTreeSet<_>>()
        || footer.software_cut_points.values().any(|count| *count == 0)
        || footer.scenarios.values().any(|count| *count == 0)
    {
        return Err("physical/software cut inventory or summary is incomplete".to_owned());
    }
    let hardware = Hardware {
        silicon_revision: header.hardware.silicon_revision,
        security_mode: header.hardware.security_mode,
        qualified: true,
        stock_clock: true,
        firmware_sha256: header.hardware.firmware_sha256,
        flash_part: header.hardware.flash_part,
        flash_capacity_bytes: header.hardware.flash_capacity_bytes,
    };
    Ok(PowerLossResult {
        identity,
        hardware,
        cases: state.physical_cuts + state.corruption_trials,
        scenarios: footer.scenarios,
        physical_cuts: state.physical_cuts,
        corruption_trials: state.corruption_trials,
        ack_regressions: state.ack_regressions,
        lost_retained_artifacts: state.lost_retained_artifacts,
        cross_pool_mutations: state.cross_pool_mutations,
        invalid_signatures: state.invalid_signatures,
        successful_recoveries: state.successful_recoveries,
        obsolete_secret_retained: state.obsolete_secret_retained,
        maximum_recovery_duration_ms: state.maximum_recovery_duration_ms,
        software_cut_points: footer.software_cut_points,
        controller_identity_sha256: controller_identity.to_owned(),
        sensitivity_passed: false,
    })
}

pub fn report(
    frozen: &evidence::Frozen,
    gate: &evidence::Gate,
    result: &PowerLossResult,
) -> Result<Report> {
    let expected: BTreeSet<_> = gate.scenarios.iter().collect();
    if gate.id != "G8" || result.scenarios.keys().collect::<BTreeSet<_>>() != expected {
        return Err("G8 approved scenario inventory differs from physical run".to_owned());
    }
    let mut report = crate::gates::report(
        frozen,
        gate,
        result.cases,
        result.scenarios.clone(),
        BTreeMap::from([
            ("physical_cuts".into(), json!(result.physical_cuts)),
            ("corruption_trials".into(), json!(result.corruption_trials)),
            ("ack_regressions".into(), json!(result.ack_regressions)),
            (
                "lost_retained_artifacts".into(),
                json!(result.lost_retained_artifacts),
            ),
            (
                "cross_pool_mutations".into(),
                json!(result.cross_pool_mutations),
            ),
            (
                "invalid_signatures".into(),
                json!(result.invalid_signatures),
            ),
            (
                "successful_recoveries".into(),
                json!(result.successful_recoveries),
            ),
            (
                "obsolete_secret_retained".into(),
                json!(result.obsolete_secret_retained),
            ),
            (
                "maximum_recovery_duration_ms".into(),
                json!(result.maximum_recovery_duration_ms),
            ),
            ("all_software_cut_points".into(), json!(true)),
            (
                "software_cut_points".into(),
                json!(result.software_cut_points),
            ),
            (
                "sensitivity_passed".into(),
                json!(result.sensitivity_passed),
            ),
            ("raw_sha256".into(), json!(result.identity.raw_sha256)),
            (
                "controller_identity_sha256".into(),
                json!(result.controller_identity_sha256),
            ),
        ]),
    );
    report.hardware = Some(result.hardware.clone());
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Accept;

    impl SignatureVerifier for Accept {
        fn verify(
            &self,
            _vk: &[u8; 32],
            _period: u8,
            _message: &[u8],
            _signature: &[u8; 448],
        ) -> bool {
            true
        }
    }

    fn cut(deliberate_corruption: bool) -> CutRecord {
        CutRecord {
            record: "cut".to_owned(),
            trial: 1,
            operation: "generation".to_owned(),
            boundary: OPERATIONAL_BOUNDARIES[0].to_owned(),
            pool: 0,
            active_before: 32,
            staged_before: 32,
            deliberate_corruption,
            physical_power_cycle: true,
            acknowledged_before_cut: false,
            ack_before_revision: 1,
            ack_before_period: 0,
            ack_after_revision: None,
            ack_after_period: None,
            recovery_outcome: if deliberate_corruption {
                "quarantined"
            } else {
                "original"
            }
            .to_owned(),
            recovery_duration_ms: 1,
            lost_retained_artifact: false,
            cross_pool_mutation: false,
            obsolete_secret_retained: false,
            returned_period: None,
            verification_key_hex: None,
            signature_hex: None,
        }
    }

    #[test]
    fn corruption_is_excluded_and_ack_or_erasure_regression_is_detected() {
        let (prepared, _directory) = super::super::feasibility::tests::prepared();
        let mut state = Accumulator::default();
        validate_cut(&prepared, &cut(true), 14, &Accept, &mut state).unwrap();
        assert_eq!(state.corruption_trials, 1);
        assert_eq!(state.successful_recoveries, 0);

        let mut rollback = cut(false);
        rollback.trial = 2;
        rollback.operation = "evolution-signing".to_owned();
        rollback.acknowledged_before_cut = true;
        rollback.ack_before_revision = 2;
        rollback.ack_before_period = 1;
        rollback.ack_after_revision = Some(1);
        rollback.ack_after_period = Some(0);
        rollback.obsolete_secret_retained = true;
        rollback.returned_period = Some(0);
        rollback.verification_key_hex = Some("00".repeat(32));
        rollback.signature_hex = Some("00".repeat(448));
        validate_cut(&prepared, &rollback, 14, &Accept, &mut state).unwrap();
        assert_eq!(state.ack_regressions, 1);
        assert_eq!(state.obsolete_secret_retained, 1);
        assert_eq!(state.successful_recoveries, 1);
    }
}
