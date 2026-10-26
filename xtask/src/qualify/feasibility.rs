//! Shared preflight and process boundary for physical qualification campaigns.
//!
//! The executable named by the public scenario owns USB access and generates
//! disposable secrets inside its protected runtime. This process supplies no
//! secret bytes and accepts only public, bounded NDJSON readings.
use crate::evidence::{self, Result};
use crate::fixture::{Content, ScenarioManifest, Workstation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const STOCK_CLOCK_HZ: u64 = 150_000_000;
pub const FITTED_FLASH_BYTES: u64 = 4_194_304;
pub const MAX_RECORD_BYTES: usize = 16 * 1024;
pub const FOUNDATION_BOUNDARIES: [&str; 14] = [
    "candidate-object-write",
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
];

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HardwareReading {
    pub silicon: String,
    pub silicon_revision: String,
    pub stock_clock_hz: u64,
    pub security_mode: String,
    pub flash_part: String,
    pub flash_capacity_bytes: u64,
    pub flash_minimum_erase_cycles: u64,
    pub firmware_sha256: String,
    pub firmware_link_bytes: u64,
    pub device_identity_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Inspection {
    pub version: u8,
    pub scenario_id: String,
    pub hardware: HardwareReading,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MemoryReading {
    pub active_cache_bytes: u64,
    pub device_frame_storage_bytes: u64,
    pub session_records_bytes: u64,
    pub hot_pool_metadata_bytes: u64,
    pub dispatch_metadata_bytes: u64,
    pub shared_crypto_workspace_bytes: u64,
    pub journal_workspace_bytes: u64,
    pub combined_stack_high_water_bytes: u64,
    pub unallocated_kes_margin_bytes: u64,
    pub kes_ram_bytes: u64,
    pub complete_firmware_free_sram_bytes: u64,
    pub background_generation_peak_observed: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CampaignHeader {
    pub record: String,
    pub version: u8,
    pub mode: String,
    pub scenario_id: String,
    pub harness_sha256: String,
    pub hardware: HardwareReading,
    pub memory: MemoryReading,
    pub active_generations: u8,
    pub staged_generations: u8,
    pub maximum_message_bytes: u64,
    pub host_queue_payload_capacity_bytes: u64,
    pub device_dispatch_capacity: u8,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignIdentity {
    pub raw_path: PathBuf,
    pub raw_sha256: String,
    pub harness_sha256: String,
    pub inspection: Inspection,
}

pub struct PreparedCampaign {
    pub manifest_path: PathBuf,
    pub manifest: ScenarioManifest,
    pub executable: PathBuf,
    pub executable_sha256: String,
    pub inspection: Inspection,
}

pub fn prepare(fixture: &Path) -> Result<PreparedCampaign> {
    let manifest_path = fs::canonicalize(fixture)
        .map_err(|error| format!("cannot resolve public scenario manifest: {error}"))?;
    let manifest: ScenarioManifest = evidence::read_json(&manifest_path)?;
    validate_manifest(&manifest)?;
    let executable = resolve_executable(&manifest)?;
    let executable_sha256 = evidence::file_hash(&executable)?;
    let output = Command::new(&executable)
        .args(["inspect", "--fixture"])
        .arg(&manifest_path)
        .args(["--output-format", "json-v1"])
        .env_clear()
        .env("LANG", "C")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| "qualification inspection executable unavailable".to_owned())?;
    if !output.status.success() || output.stdout.len() > MAX_RECORD_BYTES {
        return Err("qualification hardware inspection failed".to_owned());
    }
    let inspection: Inspection = crate::strict_json::from_slice(&output.stdout)
        .map_err(|error| format!("invalid qualification inspection: {error}"))?;
    validate_inspection(&manifest, &inspection)?;
    Ok(PreparedCampaign {
        manifest_path,
        manifest,
        executable,
        executable_sha256,
        inspection,
    })
}

impl PreparedCampaign {
    pub fn execute(
        &self,
        mode: &str,
        count: u64,
        controlled_delay_ms: u64,
        seeded_defect: Option<&str>,
        evidence_dir: &Path,
        output_name: &str,
    ) -> Result<CampaignIdentity> {
        let count_name = match mode {
            "load" => "rounds",
            "power-loss" => "cuts",
            _ => return Err("qualification campaign mode/count is invalid".to_owned()),
        };
        if count == 0 {
            return Err("qualification campaign mode/count is invalid".to_owned());
        }
        fs::create_dir_all(evidence_dir).map_err(|error| error.to_string())?;
        let raw_path = evidence_dir.join(output_name);
        if fs::symlink_metadata(&raw_path).is_ok() {
            return Err("refusing to replace campaign output".to_owned());
        }
        let partial_path = evidence_dir.join(format!(
            ".{output_name}.partial-{}-{}",
            std::process::id(),
            evidence::now_ms()?
        ));
        let raw = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&partial_path)
            .map_err(|error| format!("cannot create campaign output: {error}"))?;
        let mut command = Command::new(&self.executable);
        command
            .arg("run")
            .args(["--mode", mode, "--fixture"])
            .arg(&self.manifest_path)
            .arg(format!("--{count_name}"))
            .arg(count.to_string())
            .args(["--controlled-delay-ms", &controlled_delay_ms.to_string()])
            .args(["--output-format", "ndjson-v1"])
            .env_clear()
            .env("LANG", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::from(raw))
            .stderr(Stdio::null());
        if let Some(defect) = seeded_defect {
            command.args(["--seeded-defect", defect]);
        }
        let status = match command.status() {
            Ok(status) => status,
            Err(_) => {
                let _ = fs::remove_file(&partial_path);
                return Err("qualification campaign executable unavailable".to_owned());
            }
        };
        if !status.success() {
            let _ = fs::remove_file(&partial_path);
            return Err("qualification campaign process failed".to_owned());
        }
        File::open(&partial_path)
            .and_then(|file| file.sync_all())
            .map_err(|error| error.to_string())?;
        fs::rename(&partial_path, &raw_path).map_err(|error| error.to_string())?;
        File::open(evidence_dir)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| error.to_string())?;
        let raw_sha256 = evidence::file_hash(&raw_path)?;
        Ok(CampaignIdentity {
            raw_path,
            raw_sha256,
            harness_sha256: self.executable_sha256.clone(),
            inspection: self.inspection.clone(),
        })
    }
}

pub fn read_records(path: &Path, mut visit: impl FnMut(u64, &[u8]) -> Result<()>) -> Result<u64> {
    let input = File::open(path).map_err(|error| error.to_string())?;
    let mut reader = BufReader::new(input);
    let mut line = Vec::new();
    let mut records = 0u64;
    loop {
        line.clear();
        let read = reader
            .read_until(b'\n', &mut line)
            .map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        records = records
            .checked_add(1)
            .ok_or("qualification record count overflow")?;
        if line.len() > MAX_RECORD_BYTES || !line.ends_with(b"\n") {
            return Err("oversized or unterminated qualification record".to_owned());
        }
        line.pop();
        if line.is_empty() {
            return Err("empty qualification record".to_owned());
        }
        visit(records, &line)?;
    }
    if records < 3 {
        return Err("qualification output is empty or incomplete".to_owned());
    }
    Ok(records)
}

pub fn validate_header(
    prepared: &PreparedCampaign,
    header: &CampaignHeader,
    mode: &str,
) -> Result<()> {
    if header.record != "header"
        || header.version != 1
        || header.mode != mode
        || header.scenario_id != prepared.manifest.scenario_id
        || header.harness_sha256 != prepared.executable_sha256
        || header.hardware != prepared.inspection.hardware
        || header.active_generations != 32
        || header.staged_generations != 32
        || header.maximum_message_bytes != 4096
        || header.host_queue_payload_capacity_bytes != 794_624
        || header.device_dispatch_capacity != 1
    {
        return Err("qualification header changed required hardware/capacity inventory".to_owned());
    }
    validate_memory(&header.memory)
}

pub fn validate_memory(memory: &MemoryReading) -> Result<()> {
    let components = [
        (memory.active_cache_bytes, 151_552),
        (memory.device_frame_storage_bytes, 24_576),
        (memory.session_records_bytes, 8_448),
        (memory.hot_pool_metadata_bytes, 8_192),
        (memory.dispatch_metadata_bytes, 4_096),
        (memory.shared_crypto_workspace_bytes, 32_768),
        (memory.journal_workspace_bytes, 8_192),
        (memory.combined_stack_high_water_bytes, 16_384),
        (memory.unallocated_kes_margin_bytes, 7_936),
    ];
    if components.iter().any(|(actual, ceiling)| actual > ceiling)
        || components
            .iter()
            .try_fold(0u64, |sum, (value, _)| sum.checked_add(*value))
            != Some(memory.kes_ram_bytes)
        || memory.kes_ram_bytes > 262_144
        || memory.complete_firmware_free_sram_bytes < 32_768
        || !memory.background_generation_peak_observed
    {
        return Err("research R4 RAM/stack/free-SRAM ceiling failed".to_owned());
    }
    Ok(())
}

fn validate_manifest(manifest: &ScenarioManifest) -> Result<()> {
    if manifest.version != 1
        || !manifest.disposable
        || manifest.pools.len() != 32
        || manifest.devices.silicon != "RP2350"
        || manifest.devices.minimum_qualification_revision != "A4"
        || u64::from(manifest.devices.stock_clock_hz) != STOCK_CLOCK_HZ
        || u64::from(manifest.devices.fitted_flash_bytes) != FITTED_FLASH_BYTES
        || manifest.runtime.directory_mode != 0o700
        || manifest.runtime.private_file_mode != 0o600
        || !manifest.runtime.disable_core_dumps
        || !manifest.runtime.protect_transient_secret_memory
        || !manifest.runtime.populate_only_through_supported_workflows
    {
        return Err("scenario is not an approved disposable 32-pool qualification fixture".into());
    }
    Ok(())
}

fn resolve_executable(manifest: &ScenarioManifest) -> Result<PathBuf> {
    let reference = &manifest.qualification_executable;
    if reference.workstation != Workstation::Primary
        || !matches!(&reference.content, Content::Executable)
        || !reference.path.is_absolute()
    {
        return Err("qualification executable reference is invalid".to_owned());
    }
    let executable = fs::canonicalize(&reference.path)
        .map_err(|_| "qualification executable is unavailable".to_owned())?;
    let metadata = fs::symlink_metadata(&executable)
        .map_err(|_| "qualification executable is unavailable".to_owned())?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err("qualification executable is not a regular executable".to_owned());
    }
    Ok(executable)
}

fn validate_inspection(manifest: &ScenarioManifest, inspection: &Inspection) -> Result<()> {
    let hardware = &inspection.hardware;
    if inspection.version != 1
        || inspection.scenario_id != manifest.scenario_id
        || hardware.silicon != "RP2350"
        || !qualified_revision(&hardware.silicon_revision)
        || hardware.stock_clock_hz != STOCK_CLOCK_HZ
        || hardware.security_mode != "development"
        || hardware.flash_capacity_bytes != FITTED_FLASH_BYTES
        || hardware.flash_part.is_empty()
        || hardware.flash_minimum_erase_cycles < 100_000
        || hardware.firmware_link_bytes == 0
        || hardware.firmware_link_bytes > 1_048_576
        || !lower_hex(&hardware.firmware_sha256, 64)
        || !lower_hex(&hardware.device_identity_sha256, 64)
    {
        return Err(
            "unavailable: Foundation physical qualification requires stock-clock RP2350 A4-or-later with fitted 4-MiB flash; A2 is ineligible"
                .to_owned(),
        );
    }
    Ok(())
}

pub(crate) fn qualified_revision(value: &str) -> bool {
    value
        .strip_prefix('A')
        .filter(|number| !number.starts_with('0'))
        .and_then(|number| number.parse::<u16>().ok())
        .is_some_and(|revision| revision >= 4)
}

pub fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N]> {
    if !lower_hex(value, N * 2) {
        return Err("invalid fixed lowercase hexadecimal field".to_owned());
    }
    let mut result = [0u8; N];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        result[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(result)
}

fn nibble(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err("invalid lowercase hexadecimal field".to_owned()),
    }
}

pub fn public_message(scenario_id: &str, phase: &str, round: u64, pool: u8) -> [u8; 4096] {
    let mut output = [0u8; 4096];
    for (block, chunk) in output.as_chunks_mut::<32>().0.iter_mut().enumerate() {
        let mut hash = Sha256::new();
        hash.update(b"cardano-kes-forge/foundation-load-message/v1");
        hash.update(scenario_id.as_bytes());
        hash.update(phase.as_bytes());
        hash.update(round.to_be_bytes());
        hash.update([pool]);
        hash.update((block as u32).to_be_bytes());
        chunk.copy_from_slice(&hash.finalize());
    }
    output
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    pub(crate) struct TestDirectory(pub(crate) PathBuf);

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    pub(crate) fn prepared() -> (PreparedCampaign, TestDirectory) {
        let root = std::env::temp_dir().join(format!(
            "kes-qualification-unit-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let fixture = crate::fixture::create("controlled", 32, &root.join("fixture")).unwrap();
        let manifest: ScenarioManifest = evidence::read_json(&fixture).unwrap();
        let executable = fs::canonicalize("/bin/true").unwrap();
        let executable_sha256 = evidence::file_hash(&executable).unwrap();
        let hardware = HardwareReading {
            silicon: "RP2350".to_owned(),
            silicon_revision: "A4".to_owned(),
            stock_clock_hz: STOCK_CLOCK_HZ,
            security_mode: "development".to_owned(),
            flash_part: "Winbond W25Q32RV".to_owned(),
            flash_capacity_bytes: FITTED_FLASH_BYTES,
            flash_minimum_erase_cycles: 100_000,
            firmware_sha256: "0".repeat(64),
            firmware_link_bytes: 65_536,
            device_identity_sha256: "1".repeat(64),
        };
        (
            PreparedCampaign {
                manifest_path: fixture,
                inspection: Inspection {
                    version: 1,
                    scenario_id: manifest.scenario_id.clone(),
                    hardware,
                },
                manifest,
                executable,
                executable_sha256,
            },
            TestDirectory(root),
        )
    }

    pub(crate) fn memory() -> MemoryReading {
        MemoryReading {
            active_cache_bytes: 151_552,
            device_frame_storage_bytes: 24_576,
            session_records_bytes: 8_448,
            hot_pool_metadata_bytes: 8_192,
            dispatch_metadata_bytes: 4_096,
            shared_crypto_workspace_bytes: 32_768,
            journal_workspace_bytes: 8_192,
            combined_stack_high_water_bytes: 16_384,
            unallocated_kes_margin_bytes: 7_936,
            kes_ram_bytes: 262_144,
            complete_firmware_free_sram_bytes: 32_768,
            background_generation_peak_observed: true,
        }
    }

    #[test]
    fn a2_and_each_memory_ceiling_are_hard_failures() {
        let (prepared, _directory) = prepared();
        assert_eq!(
            validate_inspection(&prepared.manifest, &prepared.inspection),
            Ok(())
        );
        let mut a2 = prepared.inspection.clone();
        a2.hardware.silicon_revision = "A2".to_owned();
        assert!(validate_inspection(&prepared.manifest, &a2).is_err());
        let mut a5 = prepared.inspection.clone();
        a5.hardware.silicon_revision = "A5".to_owned();
        assert_eq!(validate_inspection(&prepared.manifest, &a5), Ok(()));

        let mut measured = memory();
        assert_eq!(validate_memory(&measured), Ok(()));
        measured.combined_stack_high_water_bytes += 1;
        measured.kes_ram_bytes += 1;
        assert!(validate_memory(&measured).is_err());
    }

    #[test]
    fn public_messages_and_fixed_hex_are_canonical() {
        let first = public_message("scenario", "aligned-evolution", 1, 0);
        assert_eq!(first, public_message("scenario", "aligned-evolution", 1, 0));
        assert_ne!(first, public_message("scenario", "aligned-evolution", 1, 1));
        assert_eq!(decode_hex::<2>("00ff").unwrap(), [0, 255]);
        assert!(decode_hex::<2>("00FF").is_err());
        assert!(decode_hex::<2>("00").is_err());
    }
}
