//! Physical admission-to-independent-verification load qualification.
use super::feasibility::{
    CampaignHeader, CampaignIdentity, PreparedCampaign, decode_hex, public_message, read_records,
    validate_header,
};
use crate::acceptance::{Hardware, Report};
use crate::evidence::{self, Result};
use crate::oracles::{Baseline, Oracle};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const MAX_QUEUE_ENTRIES: u64 = 97;
const SIGN_DEADLINE_US: u64 = 500_000;
const STATUS_DEADLINE_US: u64 = 2_000_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LoadRecord {
    record: String,
    round: u64,
    phase: String,
    kind: String,
    pool: Option<u8>,
    request_id: String,
    body_bytes: u64,
    admitted_us: u64,
    dispatched_us: u64,
    completed_us: u64,
    absolute_deadline_us: u64,
    transmitted_budget_ms: u64,
    period: Option<u8>,
    verification_key_hex: Option<String>,
    signature_hex: Option<String>,
    physical_erases: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LoadFooter {
    record: String,
    version: u8,
    controlled_delay_ms: u64,
    warm_requests: u64,
    rounds: u64,
    peak_host_queue_entries: u64,
    peak_device_dispatches: u64,
    erase_latency_max_us: u64,
    flash_erase_cycles_consumed: u64,
    scenarios: BTreeMap<String, u64>,
}

#[derive(Debug)]
pub struct LoadResult {
    pub identity: CampaignIdentity,
    pub hardware: Hardware,
    pub cases: u64,
    pub scenarios: BTreeMap<String, u64>,
    pub warm_requests: u64,
    pub rounds: u64,
    pub warm_within_100ms_fraction: f64,
    pub worst_admitted_ms: u64,
    pub worst_overload_ms: u64,
    pub worst_status_ms: u64,
    pub invalid_signatures: u64,
    pub kes_ram_bytes: u64,
    pub free_sram_bytes: u64,
    pub erase_latency_max_us: u64,
    pub flash_erase_cycles_consumed: u64,
    pub timing_threshold_passed: bool,
}

trait SignatureVerifier {
    fn verify(&self, vk: &[u8; 32], period: u8, message: &[u8], signature: &[u8; 448]) -> bool;
}

struct IndependentVerifiers {
    cli: Oracle,
    node: Oracle,
}

impl IndependentVerifiers {
    fn pinned() -> Result<Self> {
        Ok(Self {
            cli: Oracle::pinned(Baseline::Cli114)?,
            node: Oracle::pinned(Baseline::Node1113)?,
        })
    }
}

impl SignatureVerifier for IndependentVerifiers {
    fn verify(&self, vk: &[u8; 32], period: u8, message: &[u8], signature: &[u8; 448]) -> bool {
        self.cli.verify(vk, period, message, signature) == Ok(true)
            && self.node.verify(vk, period, message, signature) == Ok(true)
    }
}

#[derive(Default)]
struct Accumulator {
    header: Option<CampaignHeader>,
    footer: Option<LoadFooter>,
    warm_requests: u64,
    warm_within_100ms: u64,
    rounds: BTreeMap<u64, RoundInventory>,
    scenarios_seen: BTreeSet<String>,
    cases: u64,
    invalid_signatures: u64,
    worst_admitted_us: u64,
    worst_overload_us: u64,
    worst_status_us: u64,
    physical_erases: u64,
    previous_completion_us: Option<u64>,
}

#[derive(Default)]
struct RoundInventory {
    phase: Option<String>,
    signs: BTreeSet<u8>,
    lifecycle: BTreeSet<u8>,
    status: BTreeSet<u8>,
    management: u8,
}

pub fn run(fixture: &Path, rounds: u64, evidence_dir: &Path) -> Result<LoadResult> {
    if rounds < 3 {
        return Err("Foundation load campaign requires at least three rounds".to_owned());
    }
    let prepared = super::feasibility::prepare(fixture)?;
    let verifiers = IndependentVerifiers::pinned()?;
    let clean_identity =
        prepared.execute("load", rounds, 0, None, evidence_dir, "load-clean.ndjson")?;
    let clean = validate(&prepared, clean_identity, rounds, 0, &verifiers)?;
    if !clean.timing_threshold_passed {
        return Err("physical load exceeded an unchanged timing threshold".to_owned());
    }

    let delayed_identity = prepared.execute(
        "load",
        3,
        600,
        None,
        evidence_dir,
        "load-controlled-delay.ndjson",
    )?;
    let delayed = validate(&prepared, delayed_identity, 3, 600, &verifiers)?;
    if delayed.timing_threshold_passed || delayed.worst_admitted_ms <= 500 {
        return Err("controlled load delay was not detected".to_owned());
    }
    Ok(clean)
}

fn validate(
    prepared: &PreparedCampaign,
    identity: CampaignIdentity,
    expected_rounds: u64,
    expected_delay_ms: u64,
    verifier: &impl SignatureVerifier,
) -> Result<LoadResult> {
    let mut state = Accumulator::default();
    read_records(&identity.raw_path, |index, bytes| {
        let value: Value = crate::strict_json::from_slice(bytes)
            .map_err(|error| format!("invalid load record {index}: {error}"))?;
        match value.get("record").and_then(Value::as_str) {
            Some("header") if index == 1 && state.header.is_none() => {
                let header: CampaignHeader = crate::strict_json::from_slice(bytes)
                    .map_err(|error| format!("invalid load header: {error}"))?;
                validate_header(prepared, &header, "load")?;
                state.header = Some(header);
            }
            Some("load") if state.header.is_some() && state.footer.is_none() => {
                let record: LoadRecord = crate::strict_json::from_slice(bytes)
                    .map_err(|error| format!("invalid load event: {error}"))?;
                validate_record(prepared, &record, expected_rounds, verifier, &mut state)?;
            }
            Some("summary") if state.header.is_some() && state.footer.is_none() => {
                state.footer = Some(
                    crate::strict_json::from_slice(bytes)
                        .map_err(|error| format!("invalid load summary: {error}"))?,
                );
            }
            _ => return Err("load record order/type is invalid".to_owned()),
        }
        Ok(())
    })?;
    finish(
        prepared,
        identity,
        expected_rounds,
        expected_delay_ms,
        state,
    )
}

fn validate_record(
    prepared: &PreparedCampaign,
    record: &LoadRecord,
    expected_rounds: u64,
    verifier: &impl SignatureVerifier,
    state: &mut Accumulator,
) -> Result<()> {
    if record.record != "load"
        || record.request_id.is_empty()
        || record.admitted_us > record.dispatched_us
        || record.dispatched_us > record.completed_us
        || record.completed_us > record.absolute_deadline_us.saturating_add(600_000)
    {
        return Err("invalid admission/dispatch/completion chronology".to_owned());
    }
    if state
        .previous_completion_us
        .is_some_and(|previous| record.dispatched_us < previous)
    {
        return Err("more than one request was device-dispatched at once".to_owned());
    }
    state.previous_completion_us = Some(record.completed_us);
    let elapsed = record.completed_us - record.admitted_us;
    let remaining_ms = (record.absolute_deadline_us - record.dispatched_us) / 1000;
    if record.transmitted_budget_ms != remaining_ms {
        return Err("dispatch reset or changed the original absolute deadline".to_owned());
    }
    match record.kind.as_str() {
        "sign" => {
            if record.body_bytes != 4096 || elapsed > SIGN_DEADLINE_US + 600_000 {
                return Err("invalid maximum-message signing record".to_owned());
            }
            verify_signature(prepared, record, verifier, state)?;
            if record.phase == "warm" {
                if record.round != 0 || record.pool != Some(0) || record.physical_erases != 0 {
                    return Err("invalid warm single-pool workload".to_owned());
                }
                state.warm_requests += 1;
                state.warm_within_100ms += u64::from(elapsed <= 100_000);
            } else {
                let pool = record
                    .pool
                    .filter(|pool| *pool < 32)
                    .ok_or("invalid sign pool")?;
                let inventory = round(prepared, record, expected_rounds, state)?;
                if !inventory.signs.insert(pool) {
                    return Err("duplicate sign request in synchronized round".to_owned());
                }
                state.physical_erases += record.physical_erases;
                state.worst_admitted_us = state.worst_admitted_us.max(elapsed);
            }
        }
        "lifecycle" => {
            let pool = record
                .pool
                .filter(|pool| *pool < 32)
                .ok_or("invalid lifecycle pool")?;
            let inventory = round(prepared, record, expected_rounds, state)?;
            if record.body_bytes > 8192 || !inventory.lifecycle.insert(pool) {
                return Err("invalid or duplicate lifecycle request".to_owned());
            }
            state.worst_overload_us = state.worst_overload_us.max(elapsed);
        }
        "status" => {
            let pool = record
                .pool
                .filter(|pool| *pool < 32)
                .ok_or("invalid status pool")?;
            let inventory = round(prepared, record, expected_rounds, state)?;
            if record.body_bytes > 8192 || !inventory.status.insert(pool) {
                return Err("invalid or duplicate status request".to_owned());
            }
            state.worst_status_us = state.worst_status_us.max(elapsed);
        }
        "management" => {
            let inventory = round(prepared, record, expected_rounds, state)?;
            if record.pool.is_some() || record.body_bytes > 8192 || inventory.management != 0 {
                return Err("invalid or duplicate management request".to_owned());
            }
            inventory.management = 1;
            state.worst_status_us = state.worst_status_us.max(elapsed);
        }
        _ => return Err("unknown load request kind".to_owned()),
    }
    let budget = if record.kind == "sign" || record.kind == "lifecycle" {
        SIGN_DEADLINE_US
    } else {
        STATUS_DEADLINE_US
    };
    if record.absolute_deadline_us - record.admitted_us != budget {
        return Err("request did not retain its original operation deadline".to_owned());
    }
    state.cases += 1;
    Ok(())
}

fn round<'a>(
    prepared: &PreparedCampaign,
    record: &LoadRecord,
    expected_rounds: u64,
    state: &'a mut Accumulator,
) -> Result<&'a mut RoundInventory> {
    if record.round == 0 || record.round > expected_rounds {
        return Err("load round is outside the approved count".to_owned());
    }
    let expected_phase = match (record.round - 1) % 3 {
        0 => "aligned-evolution",
        1 => "midpoint-evolution",
        _ => "activation",
    };
    if record.phase != expected_phase {
        return Err("load scenario phase does not match the fixed schedule".to_owned());
    }
    state.scenarios_seen.insert(expected_phase.to_owned());
    let inventory = state.rounds.entry(record.round).or_default();
    if inventory
        .phase
        .get_or_insert_with(|| expected_phase.to_owned())
        != expected_phase
    {
        return Err("one synchronized round mixed scenario phases".to_owned());
    }
    if prepared.manifest.pools.len() != 32 {
        return Err("fixture pool inventory changed".to_owned());
    }
    Ok(inventory)
}

fn verify_signature(
    prepared: &PreparedCampaign,
    record: &LoadRecord,
    verifier: &impl SignatureVerifier,
    state: &mut Accumulator,
) -> Result<()> {
    let period = record.period.ok_or("sign record omitted period")?;
    let vk = decode_hex::<32>(
        record
            .verification_key_hex
            .as_deref()
            .ok_or("sign record omitted verification key")?,
    )?;
    let signature = decode_hex::<448>(
        record
            .signature_hex
            .as_deref()
            .ok_or("sign record omitted signature")?,
    )?;
    let pool = record.pool.ok_or("sign record omitted pool")?;
    let message = public_message(
        &prepared.manifest.scenario_id,
        &record.phase,
        record.round,
        pool,
    );
    if !verifier.verify(&vk, period, &message, &signature) {
        state.invalid_signatures += 1;
        return Err("independent native oracle rejected returned signature".to_owned());
    }
    Ok(())
}

fn finish(
    prepared: &PreparedCampaign,
    identity: CampaignIdentity,
    expected_rounds: u64,
    expected_delay_ms: u64,
    state: Accumulator,
) -> Result<LoadResult> {
    let header = state.header.ok_or("load header missing")?;
    let footer = state.footer.ok_or("load summary missing")?;
    if footer.record != "summary"
        || footer.version != 1
        || footer.controlled_delay_ms != expected_delay_ms
        || footer.rounds != expected_rounds
        || state.warm_requests == 0
        || footer.warm_requests != state.warm_requests
        || footer.peak_host_queue_entries != MAX_QUEUE_ENTRIES
        || footer.peak_device_dispatches != 1
        || footer.erase_latency_max_us == 0
        || footer.flash_erase_cycles_consumed == 0
        || state.rounds.len() as u64 != expected_rounds
        || state.rounds.values().any(|round| {
            round.signs.len() != 32
                || round.lifecycle.len() != 32
                || round.status.len() != 32
                || round.management != 1
        })
        || state.scenarios_seen
            != BTreeSet::from([
                "activation".to_owned(),
                "aligned-evolution".to_owned(),
                "midpoint-evolution".to_owned(),
            ])
        || state.physical_erases == 0
        || footer.scenarios.keys().collect::<BTreeSet<_>>()
            != state.scenarios_seen.iter().collect::<BTreeSet<_>>()
        || footer.scenarios.values().any(|count| *count == 0)
    {
        return Err("load inventory, queue, erase, or scenario summary is incomplete".to_owned());
    }
    let warm_fraction = state.warm_within_100ms as f64 / state.warm_requests as f64;
    let timing_threshold_passed = warm_fraction >= 0.99
        && state.worst_admitted_us <= SIGN_DEADLINE_US
        && state.worst_overload_us <= SIGN_DEADLINE_US
        && state.worst_status_us <= STATUS_DEADLINE_US;
    let hardware = Hardware {
        silicon_revision: header.hardware.silicon_revision.clone(),
        security_mode: header.hardware.security_mode.clone(),
        qualified: true,
        stock_clock: true,
        firmware_sha256: header.hardware.firmware_sha256.clone(),
        flash_part: header.hardware.flash_part.clone(),
        flash_capacity_bytes: header.hardware.flash_capacity_bytes,
    };
    if identity.inspection.hardware != header.hardware
        || prepared.executable_sha256 != identity.harness_sha256
    {
        return Err("hardware or harness identity changed during campaign".to_owned());
    }
    Ok(LoadResult {
        identity,
        hardware,
        cases: state.cases,
        scenarios: footer.scenarios,
        warm_requests: state.warm_requests,
        rounds: expected_rounds,
        warm_within_100ms_fraction: warm_fraction,
        worst_admitted_ms: state.worst_admitted_us.div_ceil(1000),
        worst_overload_ms: state.worst_overload_us.div_ceil(1000),
        worst_status_ms: state.worst_status_us.div_ceil(1000),
        invalid_signatures: state.invalid_signatures,
        kes_ram_bytes: header.memory.kes_ram_bytes,
        free_sram_bytes: header.memory.complete_firmware_free_sram_bytes,
        erase_latency_max_us: footer.erase_latency_max_us,
        flash_erase_cycles_consumed: footer.flash_erase_cycles_consumed,
        timing_threshold_passed,
    })
}

pub fn report(
    frozen: &evidence::Frozen,
    gate: &evidence::Gate,
    result: &LoadResult,
) -> Result<Report> {
    let expected: BTreeSet<_> = gate.scenarios.iter().collect();
    if gate.id != "P1" || result.scenarios.keys().collect::<BTreeSet<_>>() != expected {
        return Err("P1 approved scenario inventory differs from physical run".to_owned());
    }
    let mut report = crate::gates::report(
        frozen,
        gate,
        result.cases,
        result.scenarios.clone(),
        BTreeMap::from([
            ("warm_requests".into(), json!(result.warm_requests)),
            ("rounds".into(), json!(result.rounds)),
            (
                "warm_within_100ms_fraction".into(),
                json!(result.warm_within_100ms_fraction),
            ),
            ("worst_admitted_ms".into(), json!(result.worst_admitted_ms)),
            ("worst_overload_ms".into(), json!(result.worst_overload_ms)),
            ("worst_status_ms".into(), json!(result.worst_status_ms)),
            ("maximum_message_bytes".into(), json!(4096)),
            ("pool_count".into(), json!(32)),
            (
                "invalid_signatures".into(),
                json!(result.invalid_signatures),
            ),
            ("kes_ram_bytes".into(), json!(result.kes_ram_bytes)),
            ("free_sram_bytes".into(), json!(result.free_sram_bytes)),
            ("original_admission_deadlines".into(), json!(true)),
            ("sensitivity_passed".into(), json!(true)),
            ("raw_sha256".into(), json!(result.identity.raw_sha256)),
            (
                "harness_sha256".into(),
                json!(result.identity.harness_sha256),
            ),
            (
                "erase_latency_max_us".into(),
                json!(result.erase_latency_max_us),
            ),
            (
                "flash_erase_cycles_consumed".into(),
                json!(result.flash_erase_cycles_consumed),
            ),
        ]),
    );
    report.hardware = Some(result.hardware.clone());
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Verdict(bool);

    impl SignatureVerifier for Verdict {
        fn verify(
            &self,
            _vk: &[u8; 32],
            _period: u8,
            _message: &[u8],
            _signature: &[u8; 448],
        ) -> bool {
            self.0
        }
    }

    fn warm() -> LoadRecord {
        LoadRecord {
            record: "load".to_owned(),
            round: 0,
            phase: "warm".to_owned(),
            kind: "sign".to_owned(),
            pool: Some(0),
            request_id: "warm-1".to_owned(),
            body_bytes: 4096,
            admitted_us: 1_000,
            dispatched_us: 2_000,
            completed_us: 3_000,
            absolute_deadline_us: 501_000,
            transmitted_budget_ms: 499,
            period: Some(0),
            verification_key_hex: Some("00".repeat(32)),
            signature_hex: Some("00".repeat(448)),
            physical_erases: 0,
        }
    }

    #[test]
    fn original_deadline_single_dispatch_and_independent_verification_are_enforced() {
        let (prepared, _directory) = super::super::feasibility::tests::prepared();
        let mut state = Accumulator::default();
        assert_eq!(
            validate_record(&prepared, &warm(), 3, &Verdict(true), &mut state),
            Ok(())
        );

        let mut reset = warm();
        reset.transmitted_budget_ms = 500;
        assert!(
            validate_record(
                &prepared,
                &reset,
                3,
                &Verdict(true),
                &mut Accumulator::default()
            )
            .is_err()
        );

        let mut overlapping = warm();
        overlapping.request_id = "warm-2".to_owned();
        overlapping.dispatched_us = 2_500;
        assert!(validate_record(&prepared, &overlapping, 3, &Verdict(true), &mut state).is_err());

        let mut rejected = Accumulator::default();
        assert!(validate_record(&prepared, &warm(), 3, &Verdict(false), &mut rejected).is_err());
        assert_eq!(rejected.invalid_signatures, 1);
    }
}
