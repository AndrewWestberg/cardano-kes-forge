use super::bootstrap::{self, AuthorityRole, MachineScope};
use super::config::{self, DeviceIdentity, decode_base64, decode_hex};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidSchema,
    UnsupportedHardware,
    MissingPrerequisite,
    DigestMismatch,
    AuthorityMismatch,
    Unsigned,
    Authentication,
    BindingMismatch,
    FailedCheck,
    IrreversibleConsentRequired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Step {
    pub index: u32,
    pub action: String,
    pub target: String,
    pub before: String,
    pub after: String,
    pub irreversible: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Manifest {
    pub version: u64,
    pub ceremony_id: String,
    pub device_id: String,
    pub usb_device: String,
    pub inspection_file: PathBuf,
    pub inspection_digest: String,
    pub silicon_revision: String,
    pub rom_revision: String,
    pub flash_part: String,
    pub flash_capacity_bytes: u64,
    pub policy_file: PathBuf,
    pub policy_digest: String,
    pub recipe_file: PathBuf,
    pub recipe_digest: String,
    pub firmware_file: PathBuf,
    pub firmware_digest: String,
    pub partition_manifest_file: PathBuf,
    pub partition_manifest_digest: String,
    pub boot_key_fingerprint: String,
    pub security_version: u64,
    pub management_public_key_file: PathBuf,
    pub management_public_key_digest: String,
    pub management_transport_public_key_file: PathBuf,
    pub management_transport_public_key_digest: String,
    pub reviewer_public_key_file: PathBuf,
    pub reviewer_public_key_digest: String,
    pub steps: Vec<Step>,
    pub signature: Option<String>,
}

pub fn parse_manifest(bytes: &[u8]) -> Result<Manifest, Error> {
    if bytes.len() > 65_536 {
        return Err(Error::InvalidSchema);
    }
    let manifest: Manifest = serde_json::from_slice(bytes).map_err(|_| Error::InvalidSchema)?;
    if manifest.version != 1
        || decode_hex::<16>(&manifest.ceremony_id).is_none()
        || decode_hex::<16>(&manifest.device_id).is_none()
        || manifest.usb_device.is_empty()
        || manifest.usb_device.len() > 256
        || !printable(&manifest.usb_device)
        || manifest.flash_capacity_bytes != 4_194_304
        || manifest.steps.is_empty()
        || manifest.steps.len() > 256
        || manifest.security_version == 0
    {
        return Err(Error::InvalidSchema);
    }
    if manifest
        .signature
        .as_deref()
        .is_some_and(|signature| decode_base64(signature).is_none_or(|decoded| decoded.len() != 64))
    {
        return Err(Error::InvalidSchema);
    }
    if !supported_silicon(&manifest.silicon_revision) {
        return Err(Error::UnsupportedHardware);
    }
    for text in [&manifest.rom_revision, &manifest.flash_part] {
        if text.is_empty() || text.len() > 128 || !printable(text) {
            return Err(Error::InvalidSchema);
        }
    }
    for digest in [
        &manifest.inspection_digest,
        &manifest.policy_digest,
        &manifest.recipe_digest,
        &manifest.firmware_digest,
        &manifest.partition_manifest_digest,
        &manifest.boot_key_fingerprint,
        &manifest.management_public_key_digest,
        &manifest.management_transport_public_key_digest,
        &manifest.reviewer_public_key_digest,
    ] {
        if decode_hex::<32>(digest).is_none() {
            return Err(Error::InvalidSchema);
        }
    }
    for (index, step) in manifest.steps.iter().enumerate() {
        if step.index != index as u32
            || !matches!(
                step.action.as_str(),
                "install-image"
                    | "generate-device-roots"
                    | "enroll-trust"
                    | "otp-program"
                    | "otp-lock"
                    | "verify-protection"
                    | "negative-check"
            )
            || step.target.is_empty()
            || step.target.len() > 128
            || !printable(&step.target)
            || step.before.is_empty()
            || step.before.len() > 256
            || !printable(&step.before)
            || step.after.is_empty()
            || step.after.len() > 256
            || !printable(&step.after)
            || matches!(step.action.as_str(), "otp-program" | "otp-lock") && !step.irreversible
        {
            return Err(Error::InvalidSchema);
        }
    }
    Ok(manifest)
}

pub fn validate_references(manifest: &Manifest, base: &Path) -> Result<(), Error> {
    for (path, expected) in [
        (&manifest.inspection_file, &manifest.inspection_digest),
        (&manifest.policy_file, &manifest.policy_digest),
        (&manifest.recipe_file, &manifest.recipe_digest),
        (&manifest.firmware_file, &manifest.firmware_digest),
        (
            &manifest.partition_manifest_file,
            &manifest.partition_manifest_digest,
        ),
        (
            &manifest.management_public_key_file,
            &manifest.management_public_key_digest,
        ),
        (
            &manifest.management_transport_public_key_file,
            &manifest.management_transport_public_key_digest,
        ),
        (
            &manifest.reviewer_public_key_file,
            &manifest.reviewer_public_key_digest,
        ),
    ] {
        let bytes = std::fs::read(resolve(base, path)).map_err(|_| Error::MissingPrerequisite)?;
        let expected = decode_hex::<32>(expected).ok_or(Error::InvalidSchema)?;
        let actual: [u8; 32] = Sha256::digest(&bytes).into();
        if actual != expected {
            return Err(Error::DigestMismatch);
        }
    }
    let management = std::fs::read(resolve(base, &manifest.management_public_key_file))
        .map_err(|_| Error::MissingPrerequisite)?;
    bootstrap::authority_public(&management, AuthorityRole::Management)
        .map_err(|_| Error::AuthorityMismatch)?;
    let transport = std::fs::read(resolve(
        base,
        &manifest.management_transport_public_key_file,
    ))
    .map_err(|_| Error::MissingPrerequisite)?;
    let transport = bootstrap::machine_public(&transport, MachineScope::Management)
        .map_err(|_| Error::AuthorityMismatch)?;
    if transport.device != decode_hex(&manifest.device_id).ok_or(Error::InvalidSchema)?
        || transport.epoch != 0
    {
        return Err(Error::AuthorityMismatch);
    }
    let reviewer = std::fs::read(resolve(base, &manifest.reviewer_public_key_file))
        .map_err(|_| Error::MissingPrerequisite)?;
    bootstrap::authority_public(&reviewer, AuthorityRole::ProvisioningReviewer)
        .map_err(|_| Error::AuthorityMismatch)?;
    Ok(())
}

pub fn authorize_apply(manifest: &Manifest, irreversible_consent: bool) -> Result<(), Error> {
    if manifest.signature.is_none() {
        return Err(Error::Unsigned);
    }
    if manifest.steps.iter().any(|step| step.irreversible) && !irreversible_consent {
        return Err(Error::IrreversibleConsentRequired);
    }
    Ok(())
}

fn resolve(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn printable(text: &str) -> bool {
    text.bytes()
        .all(|byte| byte.is_ascii_graphic() || byte == b' ')
}

fn supported_silicon(revision: &str) -> bool {
    revision
        .strip_prefix('A')
        .and_then(|number| number.parse::<u16>().ok())
        .is_some_and(|number| number >= 4)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResultEntry {
    pub index: u32,
    pub observed: String,
    pub passed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Record {
    pub version: u64,
    pub ceremony_id: String,
    pub manifest_digest: String,
    pub device_id: String,
    pub identity_public_key: String,
    pub hpke_public_key: String,
    pub management_public_key: String,
    pub management_transport_public_key: String,
    pub credential_epoch: u64,
    pub silicon_revision: String,
    pub rom_revision: String,
    pub flash_part: String,
    pub flash_capacity_bytes: u64,
    pub boot_key_fingerprint: String,
    pub policy_digest: String,
    pub firmware_digest: String,
    pub security_version: u64,
    pub tool_version: String,
    pub tool_digest: String,
    pub results: Vec<ResultEntry>,
    pub completed_at: String,
    pub reviewer_public_key: String,
    pub signature: String,
}

/// Verifies the immutable ceremony chain used before a release-required host
/// accepts online device evidence. The reviewer key is a separately pinned
/// authority file; a key merely named by the record is never trusted.
pub fn verify_release_readiness(
    identity: &DeviceIdentity,
    manifest_bytes: &[u8],
    record_bytes: &[u8],
    trusted_reviewer_bytes: &[u8],
) -> Result<Record, Error> {
    if manifest_bytes.len() > 65_536 || record_bytes.len() > 65_536 {
        return Err(Error::InvalidSchema);
    }
    let manifest = parse_manifest(manifest_bytes)?;
    let record: Record = serde_json::from_slice(record_bytes).map_err(|_| Error::InvalidSchema)?;
    let reviewer =
        bootstrap::authority_public(trusted_reviewer_bytes, AuthorityRole::ProvisioningReviewer)
            .map_err(|_| Error::AuthorityMismatch)?;
    verify_json_signature(
        manifest_bytes,
        "signature",
        b"cardano-kes-forge/provision-manifest/v1",
        &reviewer.public_key,
    )?;
    verify_json_signature(
        record_bytes,
        "signature",
        b"cardano-kes-forge/provision-record/v1",
        &reviewer.public_key,
    )?;

    let manifest_digest: [u8; 32] = Sha256::digest(manifest_bytes).into();
    let record_reviewer =
        config::decode_spki(&record.reviewer_public_key).ok_or(Error::InvalidSchema)?;
    let identity_key =
        config::decode_spki(&record.identity_public_key).ok_or(Error::InvalidSchema)?;
    let management_key =
        config::decode_spki(&record.management_public_key).ok_or(Error::InvalidSchema)?;
    let transport_key =
        config::decode_spki(&record.management_transport_public_key).ok_or(Error::InvalidSchema)?;
    if record.version != 1
        || record.tool_version != "2.3.1"
        || record.credential_epoch != 0
        || decode_hex::<32>(&record.tool_digest).is_none()
        || !utc_rfc3339(&record.completed_at)
        || record.results.len() != manifest.steps.len()
    {
        return Err(Error::InvalidSchema);
    }
    if record.results.iter().enumerate().any(|(index, result)| {
        result.index != index as u32
            || result.observed.is_empty()
            || result.observed.len() > 256
            || !printable(&result.observed)
    }) {
        return Err(Error::InvalidSchema);
    }
    if record.results.iter().any(|result| !result.passed) {
        return Err(Error::FailedCheck);
    }
    if decode_hex::<32>(&record.manifest_digest) != Some(manifest_digest)
        || record.ceremony_id != manifest.ceremony_id
        || record.device_id != manifest.device_id
        || record.silicon_revision != manifest.silicon_revision
        || record.rom_revision != manifest.rom_revision
        || record.flash_part != manifest.flash_part
        || record.flash_capacity_bytes != manifest.flash_capacity_bytes
        || record.boot_key_fingerprint != manifest.boot_key_fingerprint
        || record.policy_digest != manifest.policy_digest
        || record.firmware_digest != manifest.firmware_digest
        || record.security_version != manifest.security_version
        || record_reviewer != reviewer.public_key
    {
        return Err(Error::BindingMismatch);
    }
    if decode_hex::<16>(&record.device_id) != Some(identity.device_id)
        || identity_key != identity.identity_public_key
        || decode_hex::<32>(&record.hpke_public_key) != Some(identity.hpke_public_key)
        || management_key != identity.management_public_key
        || transport_key != identity.management_transport_public_key
        || record.credential_epoch != identity.credential_epoch
        || decode_hex::<32>(&record.boot_key_fingerprint) != Some(identity.boot_key_fingerprint)
        || decode_hex::<32>(&record.policy_digest) != Some(identity.hardware_policy_digest)
        || decode_hex::<32>(&record.firmware_digest) != Some(identity.firmware_digest)
        || record.security_version != identity.security_version
    {
        return Err(Error::BindingMismatch);
    }
    Ok(record)
}

fn verify_json_signature(
    bytes: &[u8],
    signature_field: &str,
    domain: &[u8],
    public_key: &[u8; 32],
) -> Result<(), Error> {
    let (message, signature) = json_signature_message(bytes, signature_field, domain)?;
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| Error::Authentication)?;
    key.verify(&message, &Signature::from_bytes(&signature))
        .map_err(|_| Error::Authentication)
}

pub fn manifest_signature_message(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    json_signature_message(
        bytes,
        "signature",
        b"cardano-kes-forge/provision-manifest/v1",
    )
    .map(|(message, _)| message)
}

pub fn record_signature_message(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    json_signature_message(bytes, "signature", b"cardano-kes-forge/provision-record/v1")
        .map(|(message, _)| message)
}

fn json_signature_message(
    bytes: &[u8],
    signature_field: &str,
    domain: &[u8],
) -> Result<(Vec<u8>, [u8; 64]), Error> {
    let mut value: Value = serde_json::from_slice(bytes).map_err(|_| Error::InvalidSchema)?;
    let object = value.as_object_mut().ok_or(Error::InvalidSchema)?;
    let signature = object
        .remove(signature_field)
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or(Error::Unsigned)?;
    let signature = decode_base64(&signature).ok_or(Error::InvalidSchema)?;
    let signature: [u8; 64] = signature.try_into().map_err(|_| Error::InvalidSchema)?;
    let mut message = Vec::with_capacity(domain.len() + bytes.len());
    message.extend_from_slice(domain);
    encode_deterministic_json(&value, &mut message)?;
    Ok((message, signature))
}

fn encode_deterministic_json(value: &Value, output: &mut Vec<u8>) -> Result<(), Error> {
    match value {
        Value::Null => output.push(0xf6),
        Value::Bool(false) => output.push(0xf4),
        Value::Bool(true) => output.push(0xf5),
        Value::Number(number) => {
            let value = number.as_u64().ok_or(Error::InvalidSchema)?;
            cbor_head(0, value, output);
        }
        Value::String(text) => {
            cbor_head(3, text.len() as u64, output);
            output.extend_from_slice(text.as_bytes());
        }
        Value::Array(values) => {
            cbor_head(4, values.len() as u64, output);
            for value in values {
                encode_deterministic_json(value, output)?;
            }
        }
        Value::Object(values) => encode_map(values, output)?,
    }
    Ok(())
}

fn encode_map(values: &Map<String, Value>, output: &mut Vec<u8>) -> Result<(), Error> {
    let mut entries: Vec<_> = values.iter().collect();
    entries.sort_unstable_by(|(left, _), (right, _)| {
        left.len()
            .cmp(&right.len())
            .then_with(|| left.as_bytes().cmp(right.as_bytes()))
    });
    cbor_head(5, entries.len() as u64, output);
    for (key, value) in entries {
        cbor_head(3, key.len() as u64, output);
        output.extend_from_slice(key.as_bytes());
        encode_deterministic_json(value, output)?;
    }
    Ok(())
}

fn cbor_head(major: u8, value: u64, output: &mut Vec<u8>) {
    let prefix = major << 5;
    match value {
        0..=23 => output.push(prefix | value as u8),
        24..=0xff => output.extend_from_slice(&[prefix | 24, value as u8]),
        0x100..=0xffff => {
            output.push(prefix | 25);
            output.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push(prefix | 26);
            output.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            output.push(prefix | 27);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn utc_rfc3339(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || *bytes.last().unwrap_or(&0) != b'Z'
    {
        return false;
    }
    bytes[..4]
        .iter()
        .chain(&bytes[5..7])
        .chain(&bytes[8..10])
        .chain(&bytes[11..13])
        .chain(&bytes[14..16])
        .chain(&bytes[17..19])
        .all(u8::is_ascii_digit)
        && bytes[19..bytes.len() - 1]
            .iter()
            .enumerate()
            .all(|(index, byte)| index == 0 && *byte == b'.' || index > 0 && byte.is_ascii_digit())
}
