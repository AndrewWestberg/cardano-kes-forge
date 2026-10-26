use ed25519_dalek::SigningKey;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::ops::Deref;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

const MAX_CONFIG_BYTES: u64 = 65_536;

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    Invalid,
    Security,
    Unreadable,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkBinding {
    pub network_magic: u64,
    pub shelley_genesis_digest: String,
    pub slots_per_kes_period: u64,
    pub max_kes_evolutions: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MachineCredentialFile {
    version: u64,
    algorithm: String,
    scope: String,
    device_id: String,
    pool_id: Option<String>,
    incarnation_id: Option<String>,
    credential_epoch: u64,
    public_key: String,
    private_key: String,
}

pub struct MachineCredential {
    pub epoch: u64,
    pub public_key: [u8; 32],
    pub signing_key: LockedSigningKey,
}

pub struct LockedSigningKey {
    key: Box<SigningKey>,
}

impl LockedSigningKey {
    pub fn new(key: SigningKey) -> Result<Self, Error> {
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
            .map_err(|_| Error::Security)?;
        let mut key = Box::new(key);
        // SAFETY: the boxed allocation remains at this address until Drop and
        // covers exactly the live SigningKey object.
        unsafe {
            rustix::mm::mlock(
                (&raw mut *key).cast::<c_void>(),
                std::mem::size_of::<SigningKey>(),
            )
            .map_err(|_| Error::Security)?;
        }
        Ok(Self { key })
    }
}

impl Deref for LockedSigningKey {
    type Target = SigningKey;
    fn deref(&self) -> &Self::Target {
        &self.key
    }
}

impl Drop for LockedSigningKey {
    fn drop(&mut self) {
        let old = std::mem::replace(self.key.as_mut(), SigningKey::from_bytes(&[0; 32]));
        drop(old);
        // SAFETY: this is the same still-live boxed allocation locked in new.
        unsafe {
            let _ = rustix::mm::munlock(
                (&raw mut *self.key).cast::<c_void>(),
                std::mem::size_of::<SigningKey>(),
            );
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeviceIdentityFile {
    version: u64,
    device_id: String,
    identity_public_key: String,
    hpke_public_key: String,
    management_public_key: String,
    management_transport_public_key: String,
    credential_epoch: u64,
    boot_key_fingerprint: String,
    hardware_policy_digest: String,
    firmware_digest: String,
    security_version: u64,
    provisioning_record_file: PathBuf,
    provisioning_manifest_file: PathBuf,
    reviewer_public_key_file: PathBuf,
}

pub struct DeviceIdentity {
    pub device_id: [u8; 16],
    pub identity_public_key: [u8; 32],
    pub hpke_public_key: [u8; 32],
    pub management_public_key: [u8; 32],
    pub management_transport_public_key: [u8; 32],
    pub credential_epoch: u64,
    pub boot_key_fingerprint: [u8; 32],
    pub hardware_policy_digest: [u8; 32],
    pub firmware_digest: [u8; 32],
    pub security_version: u64,
    pub provisioning_record_file: PathBuf,
    pub provisioning_manifest_file: PathBuf,
    pub reviewer_public_key_file: PathBuf,
}

impl DeviceIdentity {
    pub fn load(path: &Path) -> Result<Self, Error> {
        let bytes = read_public(path)?;
        let file: DeviceIdentityFile =
            serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
        if file.version != 1 {
            return Err(Error::Invalid);
        }
        let base = containing_directory(path);
        let provisioning_record_file = resolve(base, file.provisioning_record_file);
        let provisioning_manifest_file = resolve(base, file.provisioning_manifest_file);
        let reviewer_public_key_file = resolve(base, file.reviewer_public_key_file);
        for referenced in [
            &provisioning_record_file,
            &provisioning_manifest_file,
            &reviewer_public_key_file,
        ] {
            let _ = read_public(referenced)?;
        }
        Ok(Self {
            device_id: decode_hex(&file.device_id).ok_or(Error::Invalid)?,
            identity_public_key: decode_spki(&file.identity_public_key).ok_or(Error::Invalid)?,
            hpke_public_key: decode_hex(&file.hpke_public_key).ok_or(Error::Invalid)?,
            management_public_key: decode_spki(&file.management_public_key)
                .ok_or(Error::Invalid)?,
            management_transport_public_key: decode_spki(&file.management_transport_public_key)
                .ok_or(Error::Invalid)?,
            credential_epoch: file.credential_epoch,
            boot_key_fingerprint: decode_hex(&file.boot_key_fingerprint).ok_or(Error::Invalid)?,
            hardware_policy_digest: decode_hex(&file.hardware_policy_digest)
                .ok_or(Error::Invalid)?,
            firmware_digest: decode_hex(&file.firmware_digest).ok_or(Error::Invalid)?,
            security_version: file.security_version,
            provisioning_record_file,
            provisioning_manifest_file,
            reviewer_public_key_file,
        })
    }

    pub fn verify_release_readiness(&self) -> Result<(), Error> {
        let manifest = read_public(&self.provisioning_manifest_file)?;
        let record = read_public(&self.provisioning_record_file)?;
        let reviewer = read_public(&self.reviewer_public_key_file)?;
        let parsed = super::provisioning::parse_manifest(&manifest).map_err(|_| Error::Security)?;
        super::provisioning::validate_references(
            &parsed,
            containing_directory(&self.provisioning_manifest_file),
        )
        .map_err(|_| Error::Security)?;
        super::provisioning::verify_release_readiness(self, &manifest, &record, &reviewer)
            .map(|_| ())
            .map_err(|_| Error::Security)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeviceConfigFile {
    version: u64,
    socket_path: PathBuf,
    device_id: String,
    device_identity_file: PathBuf,
    connection_name: String,
    credential_file: PathBuf,
    credential_epoch: u64,
    security_policy: String,
}

pub struct DeviceConfig {
    pub socket_path: PathBuf,
    pub device_id: [u8; 16],
    pub device_identity_file: PathBuf,
    pub connection_name: String,
    pub credential_file: PathBuf,
    pub credential: MachineCredential,
    pub identity: DeviceIdentity,
    pub security_policy: String,
}

impl DeviceConfig {
    pub fn load(path: &Path) -> Result<Self, Error> {
        let bytes = read_public(path)?;
        let file: DeviceConfigFile = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
        if file.version != 1
            || !valid_connection(&file.connection_name)
            || !valid_policy(&file.security_policy)
        {
            return Err(Error::Invalid);
        }
        let base = containing_directory(path);
        let device_identity_file = resolve(base, file.device_identity_file);
        let credential_file = resolve(base, file.credential_file);
        let identity = DeviceIdentity::load(&device_identity_file)?;
        if file.security_policy == "release-required" {
            identity.verify_release_readiness()?;
        }
        let device_id = decode_hex(&file.device_id).ok_or(Error::Invalid)?;
        let credential = load_credential(&credential_file, "management", device_id, None, None)?;
        if identity.device_id != device_id
            || credential.epoch != file.credential_epoch
            || identity.credential_epoch != file.credential_epoch
            || credential.public_key != identity.management_transport_public_key
        {
            return Err(Error::Security);
        }
        Ok(Self {
            socket_path: resolve(base, file.socket_path),
            device_id,
            device_identity_file,
            connection_name: file.connection_name,
            credential_file,
            credential,
            identity,
            security_policy: file.security_policy,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PoolConnectionFile {
    version: u64,
    socket_path: PathBuf,
    device_id: String,
    device_identity_file: PathBuf,
    pool_id: String,
    incarnation_id: String,
    network_binding: NetworkBinding,
    connection_name: String,
    credential_file: PathBuf,
    security_policy: String,
}

pub struct PoolConnection {
    pub socket_path: PathBuf,
    pub device_id: [u8; 16],
    pub pool_id: [u8; 28],
    pub incarnation_id: [u8; 16],
    pub identity_public_key: [u8; 32],
    pub network_binding: NetworkBinding,
    pub connection_name: String,
    pub device_identity_file: PathBuf,
    pub credential_file: PathBuf,
    pub credential: MachineCredential,
    pub security_policy: String,
}

impl PoolConnection {
    pub fn load(path: &Path) -> Result<Self, Error> {
        let bytes = read_public(path)?;
        let file: PoolConnectionFile =
            serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
        if file.version != 1
            || !valid_connection(&file.connection_name)
            || !valid_policy(&file.security_policy)
        {
            return Err(Error::Invalid);
        }
        validate_network(&file.network_binding)?;
        let base = containing_directory(path);
        let credential_file = resolve(base, file.credential_file);
        let device_identity_file = resolve(base, file.device_identity_file);
        let socket_path = resolve(base, file.socket_path);
        let identity = DeviceIdentity::load(&device_identity_file)?;
        let device_id = decode_hex(&file.device_id).ok_or(Error::Invalid)?;
        let pool_id = decode_hex(&file.pool_id).ok_or(Error::Invalid)?;
        let incarnation_id = decode_hex(&file.incarnation_id).ok_or(Error::Invalid)?;
        let credential = load_credential(
            &credential_file,
            "pool",
            device_id,
            Some(pool_id),
            Some(incarnation_id),
        )?;
        if identity.device_id != device_id {
            return Err(Error::Security);
        }
        Ok(Self {
            socket_path,
            device_id,
            pool_id,
            incarnation_id,
            network_binding: file.network_binding,
            identity_public_key: identity.identity_public_key,
            connection_name: file.connection_name,
            device_identity_file,
            credential_file,
            credential,
            security_policy: file.security_policy,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DaemonConfigFile {
    version: u64,
    socket_path: PathBuf,
    usb_device: String,
    device_config_file: PathBuf,
    pool_connection_files: Vec<PathBuf>,
    allowed_peer_uids: Vec<AllowedPeer>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AllowedPeer {
    pub uid: u32,
    pub connections: Vec<String>,
}

pub struct DaemonConfig {
    pub socket_path: PathBuf,
    pub usb_device: String,
    pub device_config_file: PathBuf,
    pub pool_connection_files: Vec<PathBuf>,
    pub device: DeviceConfig,
    pub pools: Vec<PoolConnection>,
    pub allowed_peer_uids: Vec<AllowedPeer>,
}

impl DaemonConfig {
    pub fn load(path: &Path) -> Result<Self, Error> {
        let bytes = read_public(path)?;
        let file: DaemonConfigFile = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
        if file.version != 1
            || file.socket_path.as_os_str().is_empty()
            || file.device_config_file.as_os_str().is_empty()
            || file.usb_device.is_empty()
            || file.usb_device.len() > 256
            || !file.usb_device.bytes().all(|byte| byte.is_ascii_graphic())
            || file.pool_connection_files.len() > 32
            || !(1..=64).contains(&file.allowed_peer_uids.len())
        {
            return Err(Error::Invalid);
        }
        let base = containing_directory(path);
        let socket_path = resolve(base, file.socket_path);
        let device_config_file = resolve(base, file.device_config_file);
        let device = DeviceConfig::load(&device_config_file)?;
        if device.socket_path != socket_path {
            return Err(Error::Security);
        }
        let mut pool_connection_files = Vec::with_capacity(file.pool_connection_files.len());
        let mut referenced_files = BTreeSet::new();
        let mut pools = Vec::with_capacity(file.pool_connection_files.len());
        let mut names = BTreeSet::from([device.connection_name.clone()]);
        let mut pool_ids = BTreeSet::new();
        let mut credentials = BTreeSet::from([normalized(&device.credential_file)?]);
        let identity_path = normalized(&device.device_identity_file)?;
        for relative in file.pool_connection_files {
            if relative.as_os_str().is_empty() {
                return Err(Error::Invalid);
            }
            let connection_file = resolve(base, relative);
            if !referenced_files.insert(normalized(&connection_file)?) {
                return Err(Error::Security);
            }
            let pool = PoolConnection::load(&connection_file)?;
            if pool.socket_path != socket_path
                || pool.device_id != device.device_id
                || normalized(&pool.device_identity_file)? != identity_path
                || pool.security_policy != device.security_policy
                || !names.insert(pool.connection_name.clone())
                || !pool_ids.insert(pool.pool_id)
                || !credentials.insert(normalized(&pool.credential_file)?)
            {
                return Err(Error::Security);
            }
            pool_connection_files.push(connection_file);
            pools.push(pool);
        }
        let mut uids = BTreeMap::new();
        for peer in &file.allowed_peer_uids {
            if !(1..=33).contains(&peer.connections.len()) || uids.insert(peer.uid, ()).is_some() {
                return Err(Error::Invalid);
            }
            let mut peer_names = BTreeSet::new();
            for connection in &peer.connections {
                if !valid_connection(connection)
                    || !names.contains(connection)
                    || !peer_names.insert(connection)
                {
                    return Err(Error::Security);
                }
            }
        }
        Ok(Self {
            socket_path,
            usb_device: file.usb_device,
            device_config_file,
            pool_connection_files,
            device,
            pools,
            allowed_peer_uids: file.allowed_peer_uids,
        })
    }
}

fn load_credential(
    path: &Path,
    expected_scope: &str,
    device_id: [u8; 16],
    pool_id: Option<[u8; 28]>,
    incarnation_id: Option<[u8; 16]>,
) -> Result<MachineCredential, Error> {
    let bytes = read_private(path)?;
    let mut file: MachineCredentialFile =
        serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
    if file.version != 1 || file.algorithm != "Ed25519" || file.scope != expected_scope {
        return Err(Error::Invalid);
    }
    let supplied_device = decode_hex(&file.device_id).ok_or(Error::Invalid)?;
    let supplied_pool = match file.pool_id.as_deref() {
        Some(value) => Some(decode_hex(value).ok_or(Error::Invalid)?),
        None => None,
    };
    let supplied_incarnation = match file.incarnation_id.as_deref() {
        Some(value) => Some(decode_hex(value).ok_or(Error::Invalid)?),
        None => None,
    };
    if supplied_device != device_id
        || supplied_pool != pool_id
        || supplied_incarnation != incarnation_id
    {
        return Err(Error::Security);
    }
    let public_key = decode_spki(&file.public_key).ok_or(Error::Invalid)?;
    let seed = Zeroizing::new(decode_pkcs8(&file.private_key).ok_or(Error::Invalid)?);
    file.private_key.zeroize();
    let signing_key = SigningKey::from_bytes(&seed);
    if signing_key.verifying_key().to_bytes() != public_key {
        return Err(Error::Security);
    }
    Ok(MachineCredential {
        epoch: file.credential_epoch,
        public_key,
        signing_key: LockedSigningKey::new(signing_key)?,
    })
}

fn validate_network(network: &NetworkBinding) -> Result<(), Error> {
    if network.network_magic > u64::from(u32::MAX)
        || network.slots_per_kes_period == 0
        || !(1..=64).contains(&network.max_kes_evolutions)
        || decode_hex::<32>(&network.shelley_genesis_digest).is_none()
    {
        return Err(Error::Invalid);
    }
    Ok(())
}

fn valid_policy(policy: &str) -> bool {
    matches!(policy, "isolated-development" | "release-required")
}

fn valid_connection(connection: &str) -> bool {
    !connection.is_empty()
        && connection.len() <= 64
        && connection
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn containing_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

fn resolve(base: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}

fn normalized(path: &Path) -> Result<PathBuf, Error> {
    std::fs::canonicalize(path).map_err(|_| Error::Unreadable)
}

fn read_public(path: &Path) -> Result<Vec<u8>, Error> {
    read_checked(path, false)
}

fn read_private(path: &Path) -> Result<Zeroizing<Vec<u8>>, Error> {
    read_checked(path, true).map(Zeroizing::new)
}

fn read_checked(path: &Path, private: bool) -> Result<Vec<u8>, Error> {
    validate_path_ancestry(path, private)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|_| Error::Unreadable)?;
    let metadata = file.metadata().map_err(|_| Error::Unreadable)?;
    let uid = rustix::process::getuid().as_raw();
    let trusted_owner = metadata.uid() == uid || (!private && metadata.uid() == 0);
    let safe_mode = if private {
        metadata.mode() & 0o777 == 0o600
    } else {
        metadata.mode() & 0o022 == 0
    };
    if !metadata.file_type().is_file() || !trusted_owner || !safe_mode {
        return Err(Error::Security);
    }
    read_bounded(file)
}

fn read_bounded(file: File) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Unreadable)?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(Error::Invalid);
    }
    Ok(bytes)
}

fn validate_path_ancestry(path: &Path, private: bool) -> Result<(), Error> {
    let uid = rustix::process::getuid().as_raw();
    let mut current = containing_directory(path);
    let mut immediate = true;
    loop {
        let metadata = std::fs::symlink_metadata(current).map_err(|_| Error::Unreadable)?;
        if !metadata.file_type().is_dir() {
            return Err(Error::Security);
        }
        if immediate && private {
            if metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
                return Err(Error::Security);
            }
        } else {
            let trusted_owner = metadata.uid() == uid || metadata.uid() == 0;
            let sticky_root = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
            if !trusted_owner || (metadata.mode() & 0o022 != 0 && !sticky_root) {
                return Err(Error::Security);
            }
        }
        let Some(parent) = current.parent() else {
            break;
        };
        if parent == current {
            break;
        }
        current = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        immediate = false;
    }
    Ok(())
}

pub(crate) fn decode_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2 {
        return None;
    }
    let mut output = [0; N];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(output)
}

pub(crate) fn decode_spki(text: &str) -> Option<[u8; 32]> {
    const PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let der = decode_base64(text)?;
    if der.len() != 44 || der[..12] != PREFIX {
        return None;
    }
    der[12..].try_into().ok()
}

pub(crate) fn decode_pkcs8(text: &str) -> Option<[u8; 32]> {
    const PREFIX: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    let der = decode_base64(text)?;
    if der.len() != 48 || der[..16] != PREFIX {
        return None;
    }
    der[16..].try_into().ok()
}

pub(crate) fn decode_base64(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() || !text.len().is_multiple_of(4) {
        return None;
    }
    let mut output = Vec::with_capacity(text.len() / 4 * 3);
    for (index, chunk) in text.as_bytes().chunks_exact(4).enumerate() {
        let last = index + 1 == text.len() / 4;
        let a = base64_value(chunk[0])?;
        let b = base64_value(chunk[1])?;
        let c = if chunk[2] == b'=' {
            if !last || chunk[3] != b'=' {
                return None;
            }
            0
        } else {
            base64_value(chunk[2])?
        };
        let d = if chunk[3] == b'=' {
            if !last {
                return None;
            }
            0
        } else {
            base64_value(chunk[3])?
        };
        let value =
            (u32::from(a) << 18) | (u32::from(b) << 12) | (u32::from(c) << 6) | u32::from(d);
        output.push((value >> 16) as u8);
        if chunk[2] != b'=' {
            output.push((value >> 8) as u8);
        }
        if chunk[3] != b'=' {
            output.push(value as u8);
        }
    }
    if encode_base64(&output) == text {
        Some(output)
    } else {
        None
    }
}

fn base64_value(value: u8) -> Option<u8> {
    match value {
        b'A'..=b'Z' => Some(value - b'A'),
        b'a'..=b'z' => Some(value - b'a' + 26),
        b'0'..=b'9' => Some(value - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

pub(crate) fn encode_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        output.push(ALPHABET[usize::from(a >> 2)] as char);
        output.push(ALPHABET[usize::from((a & 3) << 4 | b >> 4)] as char);
        output.push(if chunk.len() > 1 {
            ALPHABET[usize::from((b & 15) << 2 | c >> 6)] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            ALPHABET[usize::from(c & 63)] as char
        } else {
            '='
        });
    }
    output
}

fn nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}
