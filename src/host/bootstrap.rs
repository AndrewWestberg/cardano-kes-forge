use super::config::{decode_hex, decode_pkcs8, decode_spki};
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// A nullable field in a closed schema must be present, even when null.
pub(crate) fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(deserializer)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidSchema,
    WrongRole,
    WrongScope,
    WrongIdentity,
    UnsafePath,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityRole {
    Management,
    ProvisioningReviewer,
}

impl AuthorityRole {
    fn name(self) -> &'static str {
        match self {
            Self::Management => "management",
            Self::ProvisioningReviewer => "provisioning-reviewer",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityPublic {
    pub role: AuthorityRole,
    pub public_key: [u8; 32],
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AuthorityPrivate {
    pub public: AuthorityPublic,
    pub seed: [u8; 32],
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuthorityPublicFile {
    version: u64,
    algorithm: String,
    role: String,
    public_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuthorityPrivateFile {
    version: u64,
    algorithm: String,
    role: String,
    public_key: String,
    private_key: String,
}

pub fn authority_public(bytes: &[u8], expected: AuthorityRole) -> Result<AuthorityPublic, Error> {
    let file: AuthorityPublicFile =
        serde_json::from_slice(bytes).map_err(|_| Error::InvalidSchema)?;
    if file.version != 1 || file.algorithm != "Ed25519" {
        return Err(Error::InvalidSchema);
    }
    if file.role != expected.name() {
        return Err(Error::WrongRole);
    }
    Ok(AuthorityPublic {
        role: expected,
        public_key: decode_spki(&file.public_key).ok_or(Error::InvalidSchema)?,
    })
}

pub fn authority_private(bytes: &[u8], expected: AuthorityRole) -> Result<AuthorityPrivate, Error> {
    let file: AuthorityPrivateFile =
        serde_json::from_slice(bytes).map_err(|_| Error::InvalidSchema)?;
    if file.version != 1 || file.algorithm != "Ed25519" {
        return Err(Error::InvalidSchema);
    }
    if file.role != expected.name() {
        return Err(Error::WrongRole);
    }
    let public_key = decode_spki(&file.public_key).ok_or(Error::InvalidSchema)?;
    let seed = decode_pkcs8(&file.private_key).ok_or(Error::InvalidSchema)?;
    if SigningKey::from_bytes(&seed).verifying_key().to_bytes() != public_key {
        return Err(Error::WrongIdentity);
    }
    Ok(AuthorityPrivate {
        public: AuthorityPublic {
            role: expected,
            public_key,
        },
        seed,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MachineScope {
    Pool,
    Management,
}

impl MachineScope {
    fn name(self) -> &'static str {
        match self {
            Self::Pool => "pool",
            Self::Management => "management",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MachinePublic {
    pub scope: MachineScope,
    pub device: [u8; 16],
    pub pool: Option<[u8; 28]>,
    pub incarnation: Option<[u8; 16]>,
    pub epoch: u64,
    pub public_key: [u8; 32],
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MachinePublicFile {
    version: u64,
    algorithm: String,
    scope: String,
    device_id: String,
    #[serde(deserialize_with = "required_nullable")]
    pool_id: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    incarnation_id: Option<String>,
    credential_epoch: u64,
    public_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MachinePrivateFile {
    version: u64,
    algorithm: String,
    scope: String,
    device_id: String,
    #[serde(deserialize_with = "required_nullable")]
    pool_id: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    incarnation_id: Option<String>,
    credential_epoch: u64,
    public_key: String,
    private_key: String,
}

struct MachineFields<'a> {
    version: u64,
    algorithm: &'a str,
    scope: &'a str,
    device_id: &'a str,
    pool_id: Option<&'a str>,
    incarnation_id: Option<&'a str>,
    credential_epoch: u64,
    public_key: &'a str,
}

fn machine_fields(
    fields: MachineFields<'_>,
    expected: MachineScope,
) -> Result<MachinePublic, Error> {
    if fields.version != 1 || fields.algorithm != "Ed25519" {
        return Err(Error::InvalidSchema);
    }
    if fields.scope != expected.name() {
        return Err(Error::WrongScope);
    }
    let (pool, incarnation) = match expected {
        MachineScope::Pool => (
            Some(
                decode_hex(fields.pool_id.ok_or(Error::InvalidSchema)?)
                    .ok_or(Error::InvalidSchema)?,
            ),
            Some(
                decode_hex(fields.incarnation_id.ok_or(Error::InvalidSchema)?)
                    .ok_or(Error::InvalidSchema)?,
            ),
        ),
        MachineScope::Management if fields.pool_id.is_none() && fields.incarnation_id.is_none() => {
            (None, None)
        }
        MachineScope::Management => return Err(Error::WrongScope),
    };
    Ok(MachinePublic {
        scope: expected,
        device: decode_hex(fields.device_id).ok_or(Error::InvalidSchema)?,
        pool,
        incarnation,
        epoch: fields.credential_epoch,
        public_key: decode_spki(fields.public_key).ok_or(Error::InvalidSchema)?,
    })
}

pub fn machine_public(bytes: &[u8], expected: MachineScope) -> Result<MachinePublic, Error> {
    let file: MachinePublicFile =
        serde_json::from_slice(bytes).map_err(|_| Error::InvalidSchema)?;
    machine_fields(
        MachineFields {
            version: file.version,
            algorithm: &file.algorithm,
            scope: &file.scope,
            device_id: &file.device_id,
            pool_id: file.pool_id.as_deref(),
            incarnation_id: file.incarnation_id.as_deref(),
            credential_epoch: file.credential_epoch,
            public_key: &file.public_key,
        },
        expected,
    )
}

pub fn machine_private(bytes: &[u8], expected: MachineScope) -> Result<MachinePublic, Error> {
    let file: MachinePrivateFile =
        serde_json::from_slice(bytes).map_err(|_| Error::InvalidSchema)?;
    let public = machine_fields(
        MachineFields {
            version: file.version,
            algorithm: &file.algorithm,
            scope: &file.scope,
            device_id: &file.device_id,
            pool_id: file.pool_id.as_deref(),
            incarnation_id: file.incarnation_id.as_deref(),
            credential_epoch: file.credential_epoch,
            public_key: &file.public_key,
        },
        expected,
    )?;
    let seed = decode_pkcs8(&file.private_key).ok_or(Error::InvalidSchema)?;
    if SigningKey::from_bytes(&seed).verifying_key().to_bytes() != public.public_key {
        return Err(Error::WrongIdentity);
    }
    Ok(public)
}

#[derive(Debug, Eq, PartialEq)]
pub struct DaemonConfig {
    pub socket_path: PathBuf,
    pub usb_device: String,
    pub device_config_file: PathBuf,
    pub pool_connection_files: Vec<PathBuf>,
    pub allowed_peer_uids: Vec<AllowedPeer>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct AllowedPeer {
    pub uid: u32,
    pub connections: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DaemonConfigFile {
    version: u64,
    socket_path: PathBuf,
    usb_device: String,
    device_config_file: PathBuf,
    pool_connection_files: Vec<PathBuf>,
    allowed_peer_uids: Vec<AllowedPeerFile>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AllowedPeerFile {
    uid: u32,
    connections: Vec<String>,
}

pub fn daemon_config(bytes: &[u8]) -> Result<DaemonConfig, Error> {
    let file: DaemonConfigFile = serde_json::from_slice(bytes).map_err(|_| Error::InvalidSchema)?;
    if file.version != 1
        || file.socket_path.as_os_str().is_empty()
        || file.device_config_file.as_os_str().is_empty()
        || file.usb_device.is_empty()
        || file.usb_device.len() > 256
        || !file.usb_device.bytes().all(|byte| byte.is_ascii_graphic())
        || file.pool_connection_files.len() > 32
        || file
            .pool_connection_files
            .iter()
            .any(|path| path.as_os_str().is_empty())
        || !(1..=64).contains(&file.allowed_peer_uids.len())
    {
        return Err(Error::InvalidSchema);
    }
    let mut uids = BTreeSet::new();
    let mut peers = Vec::with_capacity(file.allowed_peer_uids.len());
    for peer in file.allowed_peer_uids {
        if !uids.insert(peer.uid) || !(1..=33).contains(&peer.connections.len()) {
            return Err(Error::InvalidSchema);
        }
        let mut names = BTreeSet::new();
        if peer.connections.iter().any(|name| {
            name.is_empty()
                || name.len() > 64
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
                || !names.insert(name.as_str())
        }) {
            return Err(Error::InvalidSchema);
        }
        peers.push(AllowedPeer {
            uid: peer.uid,
            connections: peer.connections,
        });
    }
    Ok(DaemonConfig {
        socket_path: file.socket_path,
        usb_device: file.usb_device,
        device_config_file: file.device_config_file,
        pool_connection_files: file.pool_connection_files,
        allowed_peer_uids: peers,
    })
}

pub fn validate_private_path(path: &Path) -> Result<(), Error> {
    let file = std::fs::symlink_metadata(path).map_err(|_| Error::UnsafePath)?;
    let parent = path.parent().ok_or(Error::UnsafePath)?;
    let directory = std::fs::symlink_metadata(parent).map_err(|_| Error::UnsafePath)?;
    let uid = rustix::process::getuid().as_raw();
    if !file.file_type().is_file()
        || file.uid() != uid
        || file.mode() & 0o777 != 0o600
        || !directory.file_type().is_dir()
        || directory.uid() != uid
        || directory.mode() & 0o077 != 0
    {
        return Err(Error::UnsafePath);
    }
    Ok(())
}
