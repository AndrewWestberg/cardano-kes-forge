//! Host-only load controls; never a physical P1 reading.
use crate::evidence::{self, Result};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

const PHASES: [(&str, u64); 4] = [
    ("aligned_evolution", 32),
    ("midpoint_31_to_32", 32),
    ("activation", 32),
    ("background_generation", 64),
];

pub struct SoftwareResult {
    pub manifest: PathBuf,
    pub cases: u64,
    pub deadline_misses: u64,
}

#[derive(Default)]
struct Phase {
    requests: BTreeSet<(u64, u64)>,
    deadline_misses: u64,
    max_queue_wait_ns: u64,
    max_dispatch_to_verified_ns: u64,
    max_admission_to_verified_ns: u64,
    last_verified_ns: Option<u64>,
    generation_leaf_steps: u64,
}

pub fn run(evidence_dir: &Path) -> Result<SoftwareResult> {
    if std::env::var_os("KESFORGE_CANDIDATE_ROOT").is_some() {
        return Err("host software load controls cannot satisfy physical P1 acceptance".into());
    }
    crate::oracles::protect_memory()?;
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("xtask workspace root unavailable")?;
    fs::create_dir_all(evidence_dir).map_err(|error| error.to_string())?;
    let log_path = evidence_dir.join("software-load.log");
    let mut log = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&log_path)
        .map_err(|error| format!("cannot create software load log: {error}"))?;
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let arguments = [
        "test",
        "--locked",
        "--release",
        "-p",
        "kes-core",
        "--features",
        "native-oracles",
        "--test",
        "foundation_load",
        "--",
        "--test-threads=1",
        "--nocapture",
    ];
    let started = Instant::now();
    let output = Command::new(&cargo)
        .args(arguments)
        .current_dir(workspace)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("software load control failed to start: {error}"))?;
    log.write_all(&output.stdout)
        .and_then(|()| log.write_all(b"\n--- stderr ---\n"))
        .and_then(|()| log.write_all(&output.stderr))
        .and_then(|()| log.sync_all())
        .map_err(|error| format!("cannot write software load log: {error}"))?;
    let duration_ms = started.elapsed().as_millis();
    let log_sha256 = evidence::file_hash(&log_path)?;
    if !output.status.success() {
        return Err(format!("software load control failed; log {log_sha256}"));
    }
    let (summary, phases) = validate_output(&output.stdout)?;
    let cases = phases
        .values()
        .map(|phase| phase.requests.len() as u64)
        .sum();
    let deadline_misses = phases.values().map(|phase| phase.deadline_misses).sum();
    let manifest = evidence_dir.join("software-load.json");
    evidence::write_new_json(
        &manifest,
        &json!({
            "version": 1,
            "campaign": "foundation-load-software",
            "verdict": "software-pass",
            "physical_status": "unavailable-not-attempted",
            "a4_p1_acceptance": false,
            "cases": cases,
            "deadline_misses": deadline_misses,
            "duration_ms": duration_ms,
            "command": std::iter::once(cargo.to_string_lossy().into_owned())
                .chain(arguments.iter().map(|arg| (*arg).to_owned())).collect::<Vec<_>>(),
            "log": "software-load.log",
            "log_sha256": log_sha256,
            "measurements": summary,
        }),
    )?;
    Ok(SoftwareResult {
        manifest,
        cases,
        deadline_misses,
    })
}

fn validate_output(output: &[u8]) -> Result<(Value, BTreeMap<String, Phase>)> {
    let output = std::str::from_utf8(output).map_err(|_| "non-UTF-8 software load output")?;
    let mut summary = None;
    let mut phases = BTreeMap::<String, Phase>::new();
    for line in output.lines() {
        if let Some((_, encoded)) = line.split_once("KES_FOUNDATION_LOAD_REQUEST ") {
            let value = reading(encoded)?;
            record_request(&value, &mut phases)?;
        } else if let Some((_, encoded)) = line.split_once("KES_FOUNDATION_LOAD_SUMMARY ") {
            if summary.is_some() {
                return Err("duplicate software load summary".into());
            }
            summary = Some(reading(encoded)?);
        }
    }
    let summary = summary.ok_or("software load control omitted its measured summary")?;
    if number(&summary, "schema_version")? != 1
        || summary["scope"] != "host/software-only"
        || summary["a4_p1_acceptance"] != false
        || number(&summary, "pool_count")? != 32
        || number(&summary, "queue_capacity")? != 32
        || number(&summary, "max_message_bytes")? != 4096
        || number(&summary, "max_in_flight")? != 1
        || number(&summary, "background_leaf_steps")? != 64
        || number(&summary, "background_staged_vacancies_at_start")? != 1
        || number(&summary, "background_staged_generations_at_start")? != 31
        || number(&summary, "background_generations_staged")? != 1
        || number(&summary, "journal_recoveries")? != 32
        || !summary["physical_ram_high_water_bytes"].is_null()
        || summary["native_verifiers"]
            .as_array()
            .is_none_or(|values| values.len() != 2)
    {
        return Err("software load scope or measured inventory is incomplete".into());
    }
    let measured = summary["phases"]
        .as_array()
        .ok_or("software load phases missing")?;
    if measured.len() != PHASES.len() || phases.len() != PHASES.len() {
        return Err("software load phase inventory differs from required workload".into());
    }
    for (name, count) in PHASES {
        let phase = phases.get(name).ok_or("software load phase absent")?;
        let mut rows = measured.iter().filter(|row| row["name"] == name);
        let row = rows.next().ok_or("software load phase summary missing")?;
        if rows.next().is_some() || phase.requests.len() as u64 != count {
            return Err("software load request inventory is incomplete or duplicated".into());
        }
        let per_pool = if name == "background_generation" {
            2
        } else {
            1
        };
        if (0..32)
            .any(|pool| phase.requests.iter().filter(|(id, _)| *id == pool).count() != per_pool)
        {
            return Err("software load omitted a registered pool from its workload".into());
        }
        let expected_leaves = if name == "background_generation" {
            64
        } else {
            0
        };
        if phase.generation_leaf_steps != expected_leaves {
            return Err("software load did not interleave the required generation leaves".into());
        }
        for (key, expected) in [
            ("requests", count),
            ("verified_completions", count),
            ("native_verifications", count * 2),
            ("generation_leaf_steps", expected_leaves),
            ("deadline_misses", phase.deadline_misses),
            ("timely_usable_completions", count - phase.deadline_misses),
            ("max_queue_wait_ns", phase.max_queue_wait_ns),
            (
                "max_dispatch_to_verified_ns",
                phase.max_dispatch_to_verified_ns,
            ),
            (
                "max_admission_to_verified_ns",
                phase.max_admission_to_verified_ns,
            ),
        ] {
            if number(row, key)? != expected {
                return Err(format!(
                    "software load phase {name} disagrees with measured {key}"
                ));
            }
        }
    }
    Ok((summary, phases))
}

fn reading(encoded: &str) -> Result<Value> {
    if encoded.len() > super::super::feasibility::MAX_RECORD_BYTES {
        return Err("software load reading exceeds bounded record size".into());
    }
    crate::strict_json::from_slice(encoded.as_bytes())
        .map_err(|error| format!("invalid software load reading: {error}"))
}

fn record_request(value: &Value, phases: &mut BTreeMap<String, Phase>) -> Result<()> {
    let name = value["phase"]
        .as_str()
        .ok_or("software load request omitted phase")?;
    if number(value, "schema_version")? != 1 || !PHASES.iter().any(|(phase, _)| *phase == name) {
        return Err("software load request has unsupported schema or phase".into());
    }
    let request = &value["request"];
    let pool = number(request, "pool_index")?;
    let admitted = number(request, "admitted_ns")?;
    let dispatched = number(request, "dispatched_ns")?;
    let verified = number(request, "verified_completion_ns")?;
    let deadline = number(request, "original_deadline_ns")?;
    if pool >= 32
        || number(request, "message_bytes")? != 4096
        || admitted > dispatched
        || dispatched > verified
        || admitted.checked_add(500_000_000) != Some(deadline)
        || request["deadline_missed"].as_bool() != Some(verified > deadline)
        || request["timely_usable_completion"].as_bool() != Some(verified <= deadline)
        || number(request, "queue_wait_ns")? != dispatched - admitted
        || number(request, "dispatch_to_verified_ns")? != verified - dispatched
        || number(request, "admission_to_verified_ns")? != verified - admitted
    {
        return Err(
            "software load request changed its admission deadline or timing context".into(),
        );
    }
    let phase = phases.entry(name.to_owned()).or_default();
    if phase
        .last_verified_ns
        .is_some_and(|previous| previous > dispatched)
    {
        return Err("software load dispatched overlapping operations".into());
    }
    if let Some(leaf) = request
        .get("generation_leaf")
        .filter(|leaf| !leaf.is_null())
    {
        let started = number(leaf, "started_ns")?;
        let finished = number(leaf, "finished_ns")?;
        if name != "background_generation"
            || started < admitted
            || finished < started
            || finished > dispatched
        {
            return Err("software load generation leaf escaped its dispatch interval".into());
        }
        phase.generation_leaf_steps += 1;
    }
    if !phase
        .requests
        .insert((pool, number(request, "absolute_period")?))
    {
        return Err("duplicate software load pool/period request".into());
    }
    phase.deadline_misses += u64::from(verified > deadline);
    phase.max_queue_wait_ns = phase.max_queue_wait_ns.max(dispatched - admitted);
    phase.max_dispatch_to_verified_ns =
        phase.max_dispatch_to_verified_ns.max(verified - dispatched);
    phase.max_admission_to_verified_ns =
        phase.max_admission_to_verified_ns.max(verified - admitted);
    phase.last_verified_ns = Some(verified);
    Ok(())
}

fn number(value: &Value, field: &str) -> Result<u64> {
    value[field]
        .as_u64()
        .ok_or_else(|| format!("software load reading omitted unsigned {field}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(pool: u64, admitted: u64, dispatched: u64, verified: u64) -> Value {
        json!({
            "schema_version": 1,
            "phase": "aligned_evolution",
            "request": {
                "pool_index": pool, "absolute_period": 101, "message_bytes": 4096,
                "admitted_ns": admitted, "dispatched_ns": dispatched,
                "verified_completion_ns": verified,
                "original_deadline_ns": admitted + 500_000_000,
                "deadline_missed": verified > admitted + 500_000_000,
                "timely_usable_completion": verified <= admitted + 500_000_000,
                "queue_wait_ns": dispatched - admitted,
                "dispatch_to_verified_ns": verified - dispatched,
                "admission_to_verified_ns": verified - admitted,
                "generation_leaf": null,
            }
        })
    }

    #[test]
    fn original_deadlines_separate_late_verification_from_usable_completion() {
        let late = request(0, 1, 400_000_001, 500_000_002);
        let mut phases = BTreeMap::new();
        record_request(&late, &mut phases).unwrap();
        assert_eq!(phases["aligned_evolution"].deadline_misses, 1);
        let mut renewed = late.clone();
        renewed["request"]["original_deadline_ns"] = json!(900_000_001u64);
        assert!(record_request(&renewed, &mut BTreeMap::new()).is_err());
        let mut claimed_timely = late;
        claimed_timely["request"]["timely_usable_completion"] = json!(true);
        assert!(record_request(&claimed_timely, &mut BTreeMap::new()).is_err());
    }

    #[test]
    fn duplicate_pool_attempts_and_overlapping_dispatch_are_rejected() {
        let first = request(0, 1, 2, 4);
        let mut phases = BTreeMap::new();
        record_request(&first, &mut phases).unwrap();
        assert!(record_request(&first, &mut phases).is_err());
        assert!(record_request(&request(1, 1, 3, 5), &mut phases).is_err());
        record_request(&request(1, 1, 4, 5), &mut phases).unwrap();
        assert_eq!(phases["aligned_evolution"].requests.len(), 2);
    }
}
