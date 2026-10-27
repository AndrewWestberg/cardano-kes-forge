//! Attended, read-only provisioning preparation. No hardware mutation is implemented here.
use super::{Manifest, Step};
use crate::host::{
    bootstrap::{self, AuthorityRole},
    config, management,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{IsTerminal, Read, Seek, SeekFrom, Write},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use zeroize::{Zeroize, Zeroizing};

const TOOL_DIGEST: &str = "eefcbd48c2c0fa825a8e2ea3e44239644194d79abff8eb082bc3914971e745e5";
const SYMBOL_DIGEST: &str = "1838713d5f94316c4c61558cb82d3346831235dc41f9b0f02151e6eda3f22fc2";
const MAX_DOCUMENT: usize = 65536;

#[derive(Debug)]
pub enum Error {
    Invalid,
    Filesystem,
    Trust,
    Hardware,
    InspectionIncomplete,
    Approval,
    PrivateKey,
    BackendUnavailable,
    Protection,
    ToolUnavailable,
    OutputLimit,
    Profile,
    DeviceUnavailable,
    DeviceChanged,
    MalformedInspection,
}
impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid => "INVALID_PROVISIONING_INPUT",
            Self::Filesystem => "PROVISIONING_FILESYSTEM",
            Self::Trust => "PROVISIONING_TRUST_MISMATCH",
            Self::Hardware => "UNSUPPORTED_HARDWARE",
            Self::InspectionIncomplete => "INCOMPLETE_TRUSTED_INSPECTION",
            Self::Approval => "ATTENDED_APPROVAL_REQUIRED",
            Self::PrivateKey => "INVALID_REVIEWER_PRIVATE_KEY",
            Self::BackendUnavailable => "PROVISIONING_APPLY_BACKEND_UNAVAILABLE",
            Self::Protection => "PROVISIONING_MEMORY_PROTECTION_UNAVAILABLE",
            Self::ToolUnavailable => "PROVISIONING_TOOL_UNAVAILABLE",
            Self::OutputLimit => "PROVISIONING_TOOL_OUTPUT_LIMIT",
            Self::Profile => "PROVISIONING_PROFILE_REQUIRED",
            Self::DeviceUnavailable => "PROVISIONING_DEVICE_UNAVAILABLE",
            Self::DeviceChanged => "PROVISIONING_DEVICE_CHANGED",
            Self::MalformedInspection => "PROVISIONING_INSPECTION_INTEGRITY",
        }
    }
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Invalid => 2,
            Self::Trust | Self::Approval | Self::PrivateKey | Self::Profile | Self::Hardware => 3,
            Self::DeviceChanged => 4,
            Self::InspectionIncomplete
            | Self::BackendUnavailable
            | Self::Protection
            | Self::ToolUnavailable
            | Self::DeviceUnavailable => 5,
            Self::OutputLimit | Self::MalformedInspection => 6,
            Self::Filesystem => 7,
        }
    }

    pub fn diagnostic(&self) -> &'static str {
        match self {
            Self::Invalid => {
                "Expected closed v1 provisioning JSON and the exact documented command flags."
            }
            Self::Filesystem => {
                "A checked input file or exclusive durable output publication is unavailable; inspect file ownership, ancestry, permissions and output collisions."
            }
            Self::Trust => {
                "Requires KES_FORGE_PROVISIONING_TRUST pointing to independently authenticated v1 public tool/symbol/manual/policy/recipe/reviewer artifacts with matching SHA-256 pins."
            }
            Self::Hardware => {
                "Requires selected RP2350 hardware whose measured public identity matches the reviewed manifest."
            }
            Self::InspectionIncomplete => {
                "Cannot sign: picotool 2.3.1 does not measure the physical flash part; authenticated physical identity/protection readback, device-internal root generation, trust enrollment and qualified negative-check evidence remain unavailable."
            }
            Self::Approval => {
                "Requires an attended controlling /dev/tty and exact ceremony approval."
            }
            Self::PrivateKey => {
                "Requires a checked provisioning-reviewer Ed25519 PKCS#8 private-key file matching the authenticated reviewer public key."
            }
            Self::BackendUnavailable => {
                "Apply requires trusted firmware device-internal TRNG root generation, trust enrollment, authenticated public identity/protection readback, and qualified signed/unsigned/wrong-key boot, rollback, debug, alternate-boot and nonsecure/DMA denial checks. No write attempted; no completed record issued."
            }
            Self::Protection => {
                "Requires locked raw-output memory, a non-dumpable workstation process and disabled core dumps before invoking picotool."
            }
            Self::ToolUnavailable => {
                "The authenticated pinned picotool inode could not be executed or its output could not be read; requires Linux /proc/self/fd execution and installed vendor runtime dependencies."
            }
            Self::OutputLimit => {
                "Pinned picotool exceeded the 65536-byte stdout bound; child terminated and reaped, raw diagnostics discarded."
            }
            Self::Profile => {
                "Requires the provisioning-only workstation installation profile, excluding primary, development, management and recovery features."
            }
            Self::DeviceUnavailable => {
                "Requires one unambiguous USB selector identifying a currently accessible provisioning device."
            }
            Self::DeviceChanged => {
                "Selected USB bus/address changed during inspection; discard the observation and inspect the intended device again."
            }
            Self::MalformedInspection => {
                "Pinned vendor stdout was malformed, duplicated a public field or exceeded the public field bounds; no inspection published."
            }
        }
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Artifact {
    pub file: PathBuf,
    pub digest: String,
    pub source: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Trust {
    version: u32,
    tool: Artifact,
    symbols: Artifact,
    manuals: Vec<Artifact>,
    policy: Artifact,
    recipe: Artifact,
    reviewer_public_key: Artifact,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Policy {
    version: u32,
    silicon_revisions: Vec<String>,
    rom_revisions: Vec<String>,
    flash_part: String,
    flash_capacity_bytes: u64,
    firmware_digest: String,
    partition_manifest_digest: String,
    boot_key_fingerprint: String,
    security_version: u64,
    required_negative_checks: Vec<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Recipe {
    version: u32,
    symbols_digest: String,
    interruption_policy: String,
    steps: Vec<RecipeStep>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecipeStep {
    index: u32,
    action: String,
    target: String,
    before: String,
    after: String,
    irreversible: bool,
    #[serde(deserialize_with = "bootstrap::required_nullable")]
    vendor_symbol: Option<String>,
    #[serde(deserialize_with = "bootstrap::required_nullable")]
    mask: Option<u32>,
    #[serde(deserialize_with = "bootstrap::required_nullable")]
    encoded_value: Option<u32>,
    readback: String,
    method: String,
}
impl RecipeStep {
    fn matches(&self, other: &Step) -> bool {
        self.index == other.index
            && self.action == other.action
            && self.target == other.target
            && self.before == other.before
            && self.after == other.after
            && self.irreversible == other.irreversible
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Inspection {
    version: u32,
    usb_device: String,
    bus: u8,
    address: u8,
    tool_version: String,
    tool_digest: String,
    symbol_digest: String,
    manual_digests: Vec<String>,
    manual_sources: Vec<String>,
    policy_source: String,
    recipe_source: String,
    policy_digest: String,
    recipe_digest: String,
    #[serde(deserialize_with = "bootstrap::required_nullable")]
    silicon_revision: Option<String>,
    #[serde(deserialize_with = "bootstrap::required_nullable")]
    rom_revision: Option<String>,
    #[serde(deserialize_with = "bootstrap::required_nullable")]
    flash_part: Option<String>,
    #[serde(deserialize_with = "bootstrap::required_nullable")]
    flash_capacity_bytes: Option<u64>,
    public_fields: BTreeMap<String, String>,
    readiness_failures: Vec<String>,
}
fn public(path: &Path) -> Result<Vec<u8>, Error> {
    let b = management::read_public_bounded(path, MAX_DOCUMENT).map_err(|_| Error::Filesystem)?;
    if b.len() > MAX_DOCUMENT {
        return Err(Error::Invalid);
    }
    Ok(b)
}
fn resolve(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        base.join(path)
    }
}
fn verify_artifact(base: &Path, artifact: &Artifact) -> Result<std::fs::File, Error> {
    if config::decode_hex::<32>(&artifact.digest).is_none() {
        return Err(Error::Invalid);
    }
    if !printable(&artifact.source, 2048) {
        return Err(Error::Invalid);
    }
    let path = resolve(base, &artifact.file);
    management::validate_ancestry(&path, false).map_err(|_| Error::Trust)?;
    let mut file = management::checked_file(&path, false).map_err(|_| Error::Trust)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 8192];
    loop {
        let n = file.read(&mut buffer).map_err(|_| Error::Filesystem)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    if management::hex(&hash.finalize()) != artifact.digest {
        return Err(Error::Trust);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| Error::Filesystem)?;
    Ok(file)
}
fn trust() -> Result<(Trust, PathBuf), Error> {
    // This file is an independently authenticated workstation installation input,
    // never a manifest-selected trust root or a USB-supplied document.
    let path = PathBuf::from(std::env::var_os("KES_FORGE_PROVISIONING_TRUST").ok_or(Error::Trust)?);
    let trust: Trust = serde_json::from_slice(&public(&path)?).map_err(|_| Error::Invalid)?;
    if trust.version != 1
        || trust.tool.digest != TOOL_DIGEST
        || trust.symbols.digest != SYMBOL_DIGEST
        || trust.manuals.len() < 2
        || trust.manuals.len() > 8
    {
        return Err(Error::Trust);
    }
    let base = path.parent().ok_or(Error::Invalid)?.to_owned();
    for a in [
        &trust.tool,
        &trust.symbols,
        &trust.policy,
        &trust.recipe,
        &trust.reviewer_public_key,
    ]
    .into_iter()
    .chain(&trust.manuals)
    {
        verify_artifact(&base, a)?;
    }
    Ok((trust, base))
}
fn read_artifact(base: &Path, artifact: &Artifact, limit: usize) -> Result<Vec<u8>, Error> {
    let file = verify_artifact(base, artifact)?;
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Filesystem)?;
    if bytes.len() > limit {
        return Err(Error::Invalid);
    }
    Ok(bytes)
}

struct ProtectedOutput {
    // Drop wipes while the allocation is still locked, then unlocks before free.
    _guard: crate::backup::publication::SystemMemoryGuard,
    bytes: Zeroizing<Vec<u8>>,
    len: usize,
}
impl Drop for ProtectedOutput {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}
impl std::ops::Deref for ProtectedOutput {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
fn read_bounded(reader: &mut impl Read, buffer: &mut [u8]) -> Result<usize, Error> {
    let mut len = 0;
    loop {
        let count = match reader.read(&mut buffer[len..]) {
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Error::ToolUnavailable),
        };
        if count == 0 {
            return Ok(len);
        }
        len += count;
        if len == buffer.len() {
            return Err(Error::OutputLimit);
        }
    }
}
fn command(tool: &std::fs::File, arguments: &[String]) -> Result<ProtectedOutput, Error> {
    use crate::backup::publication::{MemoryProtector, SystemMemory};
    rustix::process::setrlimit(
        rustix::process::Resource::Core,
        rustix::process::Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(|_| Error::Protection)?;
    // Allocate exactly once, protect before the first raw byte, never grow.
    let mut bytes = Zeroizing::new(vec![0; MAX_DOCUMENT + 1]);
    let guard = SystemMemory
        .protect(&mut bytes)
        .map_err(|_| Error::Protection)?;
    let mut output = ProtectedOutput {
        _guard: guard,
        bytes,
        len: 0,
    };
    // Linux resolves this descriptor at exec before CLOEXEC closes it: the
    // executable is the SAME opened inode that was hashed, not a reopened path.
    // Arguments are fixed read-only vendor operations; no shell or passthrough.
    let mut child = Command::new(format!("/proc/self/fd/{}", tool.as_raw_fd()))
        .args(arguments)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        // Never capture potentially private vendor diagnostics, even on failure.
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| Error::ToolUnavailable)?;
    let result = match child.stdout.take() {
        Some(mut stdout) => read_bounded(&mut stdout, &mut output.bytes),
        None => Err(Error::ToolUnavailable),
    };
    match result {
        Ok(len) => output.len = len,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    }
    let status = match child.wait() {
        Ok(status) => status,
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::ToolUnavailable);
        }
    };
    if !status.success() {
        return Err(Error::ToolUnavailable);
    }
    Ok(output)
}
fn collect(selector: &str, trust: &Trust, base: &Path) -> Result<Inspection, Error> {
    let tool = verify_artifact(base, &trust.tool)?;
    {
        let version = command(&tool, &["version".into()])?;
        let version = std::str::from_utf8(&version).map_err(|_| Error::MalformedInspection)?;
        if !version.starts_with("picotool v2.3.1 ") && version.trim() != "picotool v2.3.1" {
            return Err(Error::Trust);
        }
    }
    let (bus, address) = crate::host::usb::resolve_provisioning_selector(selector)
        .map_err(|_| Error::DeviceUnavailable)?;
    // Upstream 2.3.1 exposes revision/ROM gitrev only with --debug. It also
    // includes boot_random. Raw output is zeroized and never logged/published;
    // only the explicit public allowlist below survives parsing.
    let output = command(
        &tool,
        &[
            "info".into(),
            "-d".into(),
            "--debug".into(),
            "--bus".into(),
            bus.to_string(),
            "--address".into(),
            address.to_string(),
        ],
    )?;
    let fields = parse_public_fields(&output)?;
    drop(output);
    if fields.get("type").is_none_or(|v| !v.starts_with("RP2350")) {
        return Err(Error::Hardware);
    }
    let silicon = fields.get("revision").cloned();
    let rom = fields.get("rom gitrev").cloned();
    let capacity = fields
        .get("flash size")
        .and_then(|v| v.strip_suffix('K'))
        .and_then(|v| v.parse::<u64>().ok())
        .and_then(|n| n.checked_mul(1024));
    let mut failures = vec!["Physical flash part is not reported by picotool 2.3.1; authenticated board/flash identification backend is required".into(),
        "Complete OTP locks, boot trust, rollback and access-control readback is not available from picotool info".into(),
        "Qualified negative-check and fresh device-generated root evidence are not available".into()];
    if silicon.as_deref().is_none_or(|s| !supported(s)) {
        failures.push("Release requires reviewed A4-or-later silicon".into());
    }
    if rom.is_none() {
        failures.push("ROM revision was not reported".into());
    }
    if capacity != Some(4_194_304) {
        failures.push("Selected Pico 2 requires exactly 4194304 bytes flash".into());
    }
    if fields.get("secure boot").map(String::as_str) != Some("1") {
        failures.push("Secure boot is not enabled".into());
    }
    for k in ["debug enable", "secure debug enable"] {
        if fields.get(k).map(String::as_str) != Some("0") {
            failures.push(format!("{k} is not closed"));
        }
    }
    // Enumeration after the query detects topology changes rather than silently
    // signing evidence for a newly enumerated matching device.
    if crate::host::usb::resolve_provisioning_selector(selector)
        .map_err(|_| Error::DeviceUnavailable)?
        != (bus, address)
    {
        return Err(Error::DeviceChanged);
    }
    Ok(Inspection {
        version: 1,
        usb_device: selector.into(),
        bus,
        address,
        tool_version: "2.3.1".into(),
        tool_digest: trust.tool.digest.clone(),
        symbol_digest: trust.symbols.digest.clone(),
        manual_digests: trust.manuals.iter().map(|a| a.digest.clone()).collect(),
        manual_sources: trust.manuals.iter().map(|a| a.source.clone()).collect(),
        policy_source: trust.policy.source.clone(),
        recipe_source: trust.recipe.source.clone(),
        policy_digest: trust.policy.digest.clone(),
        recipe_digest: trust.recipe.digest.clone(),
        silicon_revision: silicon,
        rom_revision: rom,
        flash_part: None,
        flash_capacity_bytes: capacity,
        public_fields: fields,
        readiness_failures: failures,
    })
}
fn supported(s: &str) -> bool {
    s.strip_prefix('A')
        .and_then(|v| v.parse::<u32>().ok())
        .is_some_and(|v| v >= 4)
}
fn parse_public_fields(bytes: &[u8]) -> Result<BTreeMap<String, String>, Error> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::MalformedInspection)?;
    let allowed = [
        "type",
        "revision",
        "package",
        "chipid",
        "flash devinfo",
        "current cpu",
        "available cpus",
        "default cpu",
        "secure boot",
        "debug enable",
        "secure debug enable",
        "rom gitrev",
        "flash size",
    ];
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        if let Some((key, value)) = line.trim().split_once(':') {
            let value = value.trim();
            if allowed.contains(&key)
                && (value.is_empty()
                    || value.len() > 128
                    || !value.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
                    || fields.insert(key.to_owned(), value.to_owned()).is_some())
            {
                return Err(Error::MalformedInspection);
            }
        }
    }
    Ok(fields)
}
fn publish(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    if std::fs::symlink_metadata(path).is_ok() {
        return Err(Error::Filesystem);
    }
    management::publish(path, bytes).map_err(|_| Error::Filesystem)
}
pub fn inspect(selector: &str, output: &Path) -> Result<(), Error> {
    let (trust, base) = trust()?;
    let inspection = collect(selector, &trust, &base)?;
    publish(
        output,
        &serde_json::to_vec_pretty(&inspection).map_err(|_| Error::Invalid)?,
    )
}

fn validate_plan(
    manifest: &Manifest,
    base: &Path,
    trust: &Trust,
    trust_base: &Path,
) -> Result<Recipe, Error> {
    super::validate_references(manifest, base).map_err(|_| Error::Trust)?;
    if manifest.ceremony_id == manifest.device_id
        || manifest.policy_digest != trust.policy.digest
        || manifest.recipe_digest != trust.recipe.digest
        || manifest.reviewer_public_key_digest != trust.reviewer_public_key.digest
    {
        return Err(Error::Trust);
    }
    let reviewer = bootstrap::authority_public(
        &public(&resolve(base, &manifest.reviewer_public_key_file))?,
        AuthorityRole::ProvisioningReviewer,
    )
    .map_err(|_| Error::Trust)?;
    let management_key = bootstrap::authority_public(
        &public(&resolve(base, &manifest.management_public_key_file))?,
        AuthorityRole::Management,
    )
    .map_err(|_| Error::Trust)?;
    if reviewer.public_key == management_key.public_key {
        return Err(Error::Trust);
    }
    let policy: Policy =
        serde_json::from_slice(&read_artifact(trust_base, &trust.policy, MAX_DOCUMENT)?)
            .map_err(|_| Error::Invalid)?;
    let recipe: Recipe =
        serde_json::from_slice(&read_artifact(trust_base, &trust.recipe, MAX_DOCUMENT)?)
            .map_err(|_| Error::Invalid)?;
    if policy.version != 1
        || recipe.version != 1
        || recipe.symbols_digest != trust.symbols.digest
        || recipe.interruption_policy != "stop-unprovisioned-no-record"
        || policy.silicon_revisions.is_empty()
        || policy.silicon_revisions.len() > 32
        || policy.rom_revisions.is_empty()
        || policy.rom_revisions.len() > 32
        || !policy
            .silicon_revisions
            .contains(&manifest.silicon_revision)
        || !policy.rom_revisions.contains(&manifest.rom_revision)
        || policy.flash_part != manifest.flash_part
        || policy.flash_capacity_bytes != manifest.flash_capacity_bytes
        || policy.firmware_digest != manifest.firmware_digest
        || policy.partition_manifest_digest != manifest.partition_manifest_digest
        || policy.boot_key_fingerprint != manifest.boot_key_fingerprint
        || policy.security_version != manifest.security_version
        || recipe.steps.len() != manifest.steps.len()
        || policy.required_negative_checks.is_empty()
        || policy.required_negative_checks.len() > 64
    {
        return Err(Error::Trust);
    }
    let symbols: Vec<serde_json::Value> =
        serde_json::from_slice(&read_artifact(trust_base, &trust.symbols, 1_048_576)?)
            .map_err(|_| Error::Invalid)?;
    let mut seen = BTreeSet::new();
    let mut roots = 0;
    let mut images = 0;
    let mut trust_steps = 0;
    let mut verifies = 0;
    let mut negatives = BTreeSet::new();
    for (step, approved) in manifest.steps.iter().zip(&recipe.steps) {
        if !approved.matches(step)
            || !seen.insert((&step.action, &step.target))
            || !printable(&approved.readback, 256)
        {
            return Err(Error::Trust);
        }
        match step.action.as_str() {
            "otp-program" | "otp-lock" => {
                if approved.method != "vendor-symbolic-otp-v1" || !step.irreversible {
                    return Err(Error::Trust);
                }
                let symbol = approved.vendor_symbol.as_ref().ok_or(Error::Invalid)?;
                if symbol != &step.target {
                    return Err(Error::Trust);
                }
                // OTP access/encryption key material is not a public recipe
                // literal. It must be generated and retained inside the device.
                if !public_otp_symbol(symbol) {
                    return Err(Error::Trust);
                }
                let definition = symbols
                    .iter()
                    .find(|s| s.get("name").and_then(|v| v.as_str()) == Some(symbol.as_str()))
                    .ok_or(Error::Trust)?;
                let mask = approved.mask.ok_or(Error::Invalid)?;
                let encoded = approved.encoded_value.ok_or(Error::Invalid)?;
                let vendor_mask = definition
                    .get("mask")
                    .and_then(|v| v.as_u64())
                    .ok_or(Error::Trust)?;
                validate_otp_encoding(mask, encoded, vendor_mask)?;
            }
            "generate-device-roots" => {
                roots += 1;
                if approved.method != "secure-device-trng-root-generation-v1"
                    || step.before != "absent"
                    || step.after != "fresh-device-generated"
                    || !step.irreversible
                {
                    return Err(Error::Trust);
                }
            }
            "install-image" => {
                images += 1;
                if approved.method != "authenticated-release-image-v1" || !step.irreversible {
                    return Err(Error::Trust);
                }
            }
            "enroll-trust" => {
                trust_steps += 1;
                if approved.method != "secure-device-enroll-trust-v1" || !step.irreversible {
                    return Err(Error::Trust);
                }
            }
            "verify-protection" => {
                verifies += 1;
                if approved.method != "trusted-public-readback-v1" {
                    return Err(Error::Trust);
                }
            }
            "negative-check" => {
                if approved.method != "qualified-fixture-negative-check-v1" {
                    return Err(Error::Trust);
                }
                negatives.insert(step.target.clone());
            }
            _ => return Err(Error::Invalid),
        }
        if !matches!(step.action.as_str(), "otp-program" | "otp-lock")
            && (approved.vendor_symbol.is_some()
                || approved.mask.is_some()
                || approved.encoded_value.is_some())
        {
            return Err(Error::Invalid);
        }
    }
    if roots != 1
        || images != 1
        || trust_steps == 0
        || verifies == 0
        || policy
            .required_negative_checks
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != policy.required_negative_checks.len()
        || negatives != policy.required_negative_checks.into_iter().collect()
    {
        return Err(Error::Trust);
    }
    Ok(recipe)
}
fn printable(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
}

pub fn prepare(manifest_path: &Path, key_path: &Path, output: &Path) -> Result<(), Error> {
    let bytes = public(manifest_path)?;
    let manifest = super::parse_manifest(&bytes).map_err(|_| Error::Invalid)?;
    if manifest.signature.is_some() {
        return Err(Error::Invalid);
    }
    let base = manifest_path.parent().ok_or(Error::Invalid)?;
    let (trust, trust_base) = trust()?;
    let recipe = validate_plan(&manifest, base, &trust, &trust_base)?;
    let previous: Inspection =
        serde_json::from_slice(&public(&resolve(base, &manifest.inspection_file))?)
            .map_err(|_| Error::Invalid)?;
    let current = collect(&manifest.usb_device, &trust, &trust_base)?;
    if previous != current {
        return Err(Error::Trust);
    }
    if current.silicon_revision.as_deref() != Some(manifest.silicon_revision.as_str())
        || current.rom_revision.as_deref() != Some(manifest.rom_revision.as_str())
        || current.flash_capacity_bytes != Some(manifest.flash_capacity_bytes)
    {
        return Err(Error::Hardware);
    }
    let mut terminal = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| Error::Approval)?;
    if !terminal.is_terminal() {
        return Err(Error::Approval);
    }
    writeln!(terminal,"PROVISIONING REVIEW — no device writes during prepare\nExact unsigned manifest:\n{}\nExact expanded recipe:\n{}\nCurrent public inspection:\n{}",std::str::from_utf8(&bytes).map_err(|_|Error::Invalid)?,std::str::from_utf8(&public(&resolve(base,&manifest.recipe_file))?).map_err(|_|Error::Invalid)?,serde_json::to_string_pretty(&current).map_err(|_|Error::Invalid)?).map_err(|_|Error::Filesystem)?;
    for step in &recipe.steps {
        writeln!(
            terminal,
            "{} {} {}: {} -> {}; irreversible={}; method={}; readback={}; mask={:?}; encoding={:?}",
            step.index,
            step.action,
            step.target,
            step.before,
            step.after,
            step.irreversible,
            step.method,
            step.readback,
            step.mask,
            step.encoded_value
        )
        .map_err(|_| Error::Filesystem)?;
    }
    // Never sign an inspection whose immutable part identity was merely supplied
    // by the host manifest. picotool currently cannot measure that identity.
    if current.flash_part.as_deref() != Some(manifest.flash_part.as_str())
        || !current.readiness_failures.is_empty()
    {
        writeln!(terminal,"REFUSED: physical flash-part identification requires a trusted public device inspection backend; no manifest signed.").map_err(|_|Error::Filesystem)?;
        return Err(Error::InspectionIncomplete);
    }
    let expected = format!("APPROVE {} {}", manifest.ceremony_id, manifest.device_id);
    writeln!(
        terminal,
        "To approve the entire plan, type exactly: {expected}"
    )
    .map_err(|_| Error::Filesystem)?;
    terminal.flush().map_err(|_| Error::Filesystem)?;
    let mut answer = Vec::new();
    let mut byte = [0];
    while terminal.read(&mut byte).map_err(|_| Error::Approval)? == 1 {
        if byte[0] == b'\n' {
            break;
        }
        if answer.len() == 128 {
            return Err(Error::Approval);
        }
        answer.push(byte[0]);
    }
    if answer != expected.as_bytes() {
        return Err(Error::Approval);
    }
    // Recheck public dependencies after human review to reject substitutions.
    validate_plan(&manifest, base, &trust, &trust_base)?;
    let signed = sign_draft(
        &bytes,
        key_path,
        &read_artifact(&trust_base, &trust.reviewer_public_key, MAX_DOCUMENT)?,
    )?;
    publish(output, &signed)
}

fn sign_draft(draft: &[u8], path: &Path, reviewer_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    use crate::backup::publication::{MemoryProtector, SystemMemory};
    use ed25519_dalek::{Signer, SigningKey};
    rustix::process::setrlimit(
        rustix::process::Resource::Core,
        rustix::process::Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(|_| Error::PrivateKey)?;
    management::validate_ancestry(path, true).map_err(|_| Error::PrivateKey)?;
    let mut file = management::checked_file(path, true).map_err(|_| Error::PrivateKey)?;
    let mut bytes = Zeroizing::new(vec![0; 16385]);
    let _guard = SystemMemory
        .protect(&mut bytes)
        .map_err(|_| Error::PrivateKey)?;
    let mut n = 0;
    loop {
        let count = file.read(&mut bytes[n..]).map_err(|_| Error::PrivateKey)?;
        if count == 0 {
            break;
        }
        n += count;
        if n == bytes.len() {
            return Err(Error::PrivateKey);
        }
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Key<'a> {
        version: u32,
        algorithm: &'a str,
        role: &'a str,
        public_key: &'a str,
        private_key: &'a str,
    }
    let key: Key<'_> = serde_json::from_slice(&bytes[..n]).map_err(|_| Error::PrivateKey)?;
    if key.version != 1
        || key.algorithm != "Ed25519"
        || key.role != "provisioning-reviewer"
        || key.private_key.len() != 64
    {
        return Err(Error::PrivateKey);
    }
    let mut der = Zeroizing::new([0; 48]);
    let _der_guard = SystemMemory
        .protect(&mut der[..])
        .map_err(|_| Error::PrivateKey)?;
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (input, output) in key
        .private_key
        .as_bytes()
        .as_chunks::<4>()
        .0
        .iter()
        .zip(der.as_chunks_mut::<3>().0.iter_mut())
    {
        let mut word = 0u32;
        for byte in input {
            word = (word << 6)
                | alphabet
                    .iter()
                    .position(|v| v == byte)
                    .ok_or(Error::PrivateKey)? as u32;
        }
        output.copy_from_slice(&word.to_be_bytes()[1..]);
    }
    if der[..16]
        != [
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ]
    {
        return Err(Error::PrivateKey);
    }
    let mut seed = Zeroizing::new([0; 32]);
    let _seed_guard = SystemMemory
        .protect(&mut seed[..])
        .map_err(|_| Error::PrivateKey)?;
    seed.copy_from_slice(&der[16..]);
    let signing = config::LockedSigningKey::new(SigningKey::from_bytes(&seed))
        .map_err(|_| Error::PrivateKey)?;
    let reviewer = bootstrap::authority_public(reviewer_bytes, AuthorityRole::ProvisioningReviewer)
        .map_err(|_| Error::Trust)?;
    if reviewer.public_key != signing.verifying_key().to_bytes()
        || config::decode_spki(key.public_key) != Some(reviewer.public_key)
    {
        return Err(Error::Trust);
    }
    let signature = signing
        .sign(&super::manifest_signature_message(draft).map_err(|_| Error::Invalid)?)
        .to_bytes();
    let mut value: serde_json::Value = serde_json::from_slice(draft).map_err(|_| Error::Invalid)?;
    value["signature"] = serde_json::Value::String(config::encode_base64(&signature));
    let bytes = serde_json::to_vec_pretty(&value).map_err(|_| Error::Invalid)?;
    if bytes.len() > MAX_DOCUMENT {
        return Err(Error::Invalid);
    }
    Ok(bytes)
}

// The pinned vendor table supplies existence and masks; private key rows never
// become public recipe literals. Validity flags and BOOTKEY hashes are public.
fn public_otp_symbol(symbol: &str) -> bool {
    !symbol.starts_with("OTP_DATA_KEY") || symbol.ends_with("_VALID")
}
fn validate_otp_encoding(mask: u32, encoded: u32, vendor_mask: u64) -> Result<(), Error> {
    if vendor_mask > u64::from(u32::MAX)
        || mask == 0
        || u64::from(mask) & !vendor_mask != 0
        || encoded & !mask != 0
    {
        return Err(Error::Trust);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn drops_random_and_private_fields() {
        let fields=parse_public_fields(b"Device Information\n type: RP2350\n revision: A4\n boot_random: SECRET\n root: SECRET\n rom gitrev: abcdef12\n flash size: 4096K\n").unwrap();
        assert_eq!(fields.len(), 4);
        assert!(!fields.values().any(|v| v.contains("SECRET")));
    }
    #[test]
    fn duplicate_public_fields_fail_closed() {
        assert!(parse_public_fields(b"revision: A4\nrevision: A2\n").is_err());
    }
    #[test]
    fn public_parser_rejects_invalid_and_overlong_values() {
        assert!(parse_public_fields(b"revision: A4\x1b[0m\n").is_err());
        assert!(parse_public_fields(b"revision: \xff\n").is_err());
        assert!(parse_public_fields(b"revision: \n").is_err());
        let input = format!("revision: {}\n", "A".repeat(129));
        assert!(parse_public_fields(input.as_bytes()).is_err());
    }

    #[test]
    fn bounded_collection_accepts_limit_and_stops_at_first_excess_byte() {
        let mut buffer = vec![0; MAX_DOCUMENT + 1];
        let mut exact = std::io::Cursor::new(vec![b'A'; MAX_DOCUMENT]);
        assert_eq!(read_bounded(&mut exact, &mut buffer).unwrap(), MAX_DOCUMENT);
        let mut excess = std::io::Cursor::new(vec![b'A'; MAX_DOCUMENT + 4096]);
        assert!(matches!(
            read_bounded(&mut excess, &mut buffer),
            Err(Error::OutputLimit)
        ));
        assert_eq!(excess.position(), (MAX_DOCUMENT + 1) as u64);
    }

    #[test]
    fn bounded_collection_refuses_read_errors() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("private diagnostic must not escape"))
            }
        }
        assert!(matches!(
            read_bounded(&mut Broken, &mut [0; 8]),
            Err(Error::ToolUnavailable)
        ));
    }

    #[test]
    fn public_otp_recipe_rejects_private_keys_and_reserved_bits() {
        assert!(!public_otp_symbol("OTP_DATA_KEY1_0"));
        assert!(!public_otp_symbol("OTP_DATA_KEY6_7"));
        assert!(public_otp_symbol("OTP_DATA_KEY1_VALID"));
        assert!(public_otp_symbol("OTP_DATA_BOOTKEY0_0"));
        assert!(validate_otp_encoding(0, 0, 127).is_err());
        assert!(validate_otp_encoding(128, 128, 127).is_err());
        assert!(validate_otp_encoding(1, 2, 127).is_err());
        assert!(validate_otp_encoding(1, 1, u64::MAX).is_err());
        assert!(validate_otp_encoding(3, 2, 127).is_ok());
    }
}
