use super::bootstrap::{AuthorityRole, MachineScope};
use super::config::encode_base64;
use crate::backup::publication::{self, MemoryProtector};
use crate::backup::recipient::{Entropy, OsEntropy};
use ed25519_dalek::SigningKey;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use zeroize::Zeroizing;

const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidIdentity,
    Entropy,
    ExistingOutput,
    UnsafePublicDirectory,
    PublicIo,
    SecretPublication(publication::Error),
}

#[derive(Clone, Copy)]
pub struct MachineIdentity {
    pub scope: MachineScope,
    pub device: [u8; 16],
    pub pool: Option<[u8; 28]>,
    pub incarnation: Option<[u8; 16]>,
    pub credential_epoch: u64,
}

pub fn create_authority(
    role: AuthorityRole,
    public_path: &Path,
    private_path: &Path,
) -> Result<(), Error> {
    let role = match role {
        AuthorityRole::Management => "management",
        AuthorityRole::ProvisioningReviewer => "provisioning-reviewer",
    };
    create_keypair(
        public_path,
        private_path,
        |public| {
            format!(
                "{{\"version\":1,\"algorithm\":\"Ed25519\",\"role\":\"{role}\",\"publicKey\":\"{public}\"}}"
            )
            .into_bytes()
        },
        |public, private| {
            format!(
                "{{\"version\":1,\"algorithm\":\"Ed25519\",\"role\":\"{role}\",\"publicKey\":\"{public}\",\"privateKey\":\"{private}\"}}"
            )
            .into_bytes()
        },
    )
}

pub fn create_machine(
    identity: MachineIdentity,
    public_path: &Path,
    private_path: &Path,
) -> Result<(), Error> {
    let (scope, pool, incarnation) = match (identity.scope, identity.pool, identity.incarnation) {
        (MachineScope::Pool, Some(pool), Some(incarnation)) => (
            "pool",
            format!("\"{}\"", hex(&pool)),
            format!("\"{}\"", hex(&incarnation)),
        ),
        (MachineScope::Management, None, None) => {
            ("management", "null".to_owned(), "null".to_owned())
        }
        _ => return Err(Error::InvalidIdentity),
    };
    let device = hex(&identity.device);
    create_keypair(
        public_path,
        private_path,
        |public| {
            format!(
                "{{\"version\":1,\"algorithm\":\"Ed25519\",\"scope\":\"{scope}\",\"deviceId\":\"{device}\",\"poolId\":{pool},\"incarnationId\":{incarnation},\"credentialEpoch\":{},\"publicKey\":\"{public}\"}}",
                identity.credential_epoch
            )
            .into_bytes()
        },
        |public, private| {
            format!(
                "{{\"version\":1,\"algorithm\":\"Ed25519\",\"scope\":\"{scope}\",\"deviceId\":\"{device}\",\"poolId\":{pool},\"incarnationId\":{incarnation},\"credentialEpoch\":{},\"publicKey\":\"{public}\",\"privateKey\":\"{private}\"}}",
                identity.credential_epoch
            )
            .into_bytes()
        },
    )
}

fn create_keypair(
    public_path: &Path,
    private_path: &Path,
    public_json: impl FnOnce(&str) -> Vec<u8>,
    private_json: impl FnOnce(&str, &str) -> Vec<u8>,
) -> Result<(), Error> {
    preflight_output(public_path)?;
    preflight_output(private_path)?;
    let mut seed = Zeroizing::new([0; 32]);
    let memory = publication::SystemMemory;
    let _seed_guard = memory
        .protect(&mut seed[..])
        .map_err(Error::SecretPublication)?;
    OsEntropy::new()
        .and_then(|mut entropy| entropy.fill(&mut seed[..]))
        .map_err(|_| Error::Entropy)?;
    let signing = SigningKey::from_bytes(&seed);
    let public_raw = signing.verifying_key().to_bytes();
    let mut spki = [0; 44];
    spki[..SPKI_PREFIX.len()].copy_from_slice(&SPKI_PREFIX);
    spki[SPKI_PREFIX.len()..].copy_from_slice(&public_raw);
    let public_key = encode_base64(&spki);

    let mut pkcs8 = Zeroizing::new([0; 48]);
    pkcs8[..PKCS8_PREFIX.len()].copy_from_slice(&PKCS8_PREFIX);
    pkcs8[PKCS8_PREFIX.len()..].copy_from_slice(&seed[..]);
    let private_key = Zeroizing::new(encode_base64(&pkcs8[..]));
    let mut private = Zeroizing::new(private_json(&public_key, &private_key));
    let public = public_json(&public_key);
    publication::publish_secret(private_path, &mut private[..])
        .map_err(Error::SecretPublication)?;
    publish_public(public_path, &public)
}

fn preflight_output(path: &Path) -> Result<(), Error> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(Error::ExistingOutput),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(Error::PublicIo),
    }
}

fn publish_public(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let metadata = std::fs::symlink_metadata(parent).map_err(|_| Error::UnsafePublicDirectory)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(Error::UnsafePublicDirectory);
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                Error::ExistingOutput
            } else {
                Error::PublicIo
            }
        })?;
    file.write_all(bytes).map_err(|_| Error::PublicIo)?;
    file.sync_all().map_err(|_| Error::PublicIo)?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| Error::PublicIo)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 15) as usize] as char);
    }
    output
}
