use crate::host::artifact::{self, ExpectedArtifact};
use crate::host::client::{BackupResult, GenerationResult};
use crate::host::config::PoolConnection;
use rustix::fs::{AtFlags, Mode, OFlags};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    InvalidResult,
    ExistingOutput,
    UnsafePath,
    UnsupportedFilesystem,
    Io,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationOutput {
    VerificationKey,
    EncryptedSigningKey,
}

pub trait PublicationFault {
    fn after_link(&self, output: GenerationOutput) -> Result<(), Error>;
}

pub struct NoFault;

impl PublicationFault for NoFault {
    fn after_link(&self, _: GenerationOutput) -> Result<(), Error> {
        Ok(())
    }
}

pub struct GenerationFiles<'a> {
    pub verification_key: &'a Path,
    pub encrypted_signing_key: &'a Path,
    pub manifest: &'a Path,
}

pub fn publish_generation(
    connection: &PoolConnection,
    request: [u8; 16],
    result: &GenerationResult,
    backup: &BackupResult,
    verification_key_file: &Path,
    encrypted_signing_key_file: &Path,
    generation_file: &Path,
) -> Result<(), Error> {
    publish_generation_with(
        connection,
        request,
        result,
        backup,
        GenerationFiles {
            verification_key: verification_key_file,
            encrypted_signing_key: encrypted_signing_key_file,
            manifest: generation_file,
        },
        &NoFault,
    )
}

pub fn publish_generation_with<F: PublicationFault>(
    connection: &PoolConnection,
    request: [u8; 16],
    result: &GenerationResult,
    backup: &BackupResult,
    files: GenerationFiles<'_>,
    fault: &F,
) -> Result<(), Error> {
    if result.creation_request != request
        || backup.generation != result.generation
        || backup.artifact_digest != result.artifact_digest
    {
        return Err(Error::InvalidResult);
    }
    artifact::validate(
        &backup.backup,
        ExpectedArtifact {
            connection,
            generation: result.generation,
            verification_key: Some(result.verification_key),
            generation_number: Some(result.generation_number),
            artifact_digest: result.artifact_digest,
        },
    )
    .map_err(|_| Error::InvalidResult)?;
    let verification_key = serde_json::to_vec_pretty(&json!({
        "type": "KesVerificationKey_ed25519_kes_2^6",
        "description": "KES Verification Key",
        "cborHex": format!("5820{}", hex(&result.verification_key)),
    }))
    .map_err(|_| Error::InvalidResult)?;
    let verification_digest: [u8; 32] = Sha256::digest(&verification_key).into();
    let encrypted_digest: [u8; 32] = Sha256::digest(&backup.backup).into();
    let generation = serde_json::to_vec_pretty(&json!({
        "version": 1,
        "operation": "GENERATE",
        "requestId": hex(&request),
        "deviceId": hex(&connection.device_id),
        "poolId": hex(&connection.pool_id),
        "incarnationId": hex(&connection.incarnation_id),
        "generationId": hex(&result.generation),
        "generationNumber": result.generation_number,
        "verificationKey": hex(&result.verification_key),
        "artifactDigest": hex(&result.artifact_digest),
        "revision": result.revision,
        "outputs": {
            "verificationKeySha256": hex(&verification_digest),
            "encryptedSigningKeySha256": hex(&encrypted_digest),
            "encryptedSigningKeyDescription": "Device-generated KES state encrypted to the enrolled recovery recipient; not a plaintext signing key",
        },
        "result": "complete",
    }))
    .map_err(|_| Error::InvalidResult)?;

    // Preflight every destination before creating any missing output. An
    // unrelated existing path therefore cannot produce a misleading partial
    // result during this invocation.
    preflight(files.verification_key, &verification_key)?;
    preflight(files.encrypted_signing_key, &backup.backup)?;
    preflight(files.manifest, &generation)?;

    publish_exact(files.verification_key, &verification_key)?;
    fault.after_link(GenerationOutput::VerificationKey)?;
    publish_exact(files.encrypted_signing_key, &backup.backup)?;
    fault.after_link(GenerationOutput::EncryptedSigningKey)?;
    // The completion manifest is intentionally linked last. Its presence means
    // both content-addressed outputs were already durable.
    publish_exact(files.manifest, &generation)
}

pub fn publish_backup(
    connection: &PoolConnection,
    expected_generation: [u8; 16],
    backup: &BackupResult,
    output: &Path,
) -> Result<(), Error> {
    if backup.generation != expected_generation {
        return Err(Error::InvalidResult);
    }
    artifact::validate(
        &backup.backup,
        ExpectedArtifact {
            connection,
            generation: expected_generation,
            verification_key: None,
            generation_number: None,
            artifact_digest: backup.artifact_digest,
        },
    )
    .map_err(|_| Error::InvalidResult)?;
    preflight(output, &backup.backup)?;
    publish_exact(output, &backup.backup)
}

/// Durably publish the public operational certificate used for native hot
/// context switching. Exact retries are accepted; conflicting bytes for the
/// same generation are rejected.
pub fn publish_rotation_certificate(path: &Path, certificate: &[u8]) -> Result<(), Error> {
    preflight(path, certificate)?;
    publish_exact(path, certificate)
}

fn preflight(path: &Path, expected: &[u8]) -> Result<(), Error> {
    match OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
    {
        Ok(file) => validate_existing(file, expected),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            validate_parent(path).map(|_| ())
        }
        Err(_) => Err(Error::UnsafePath),
    }
}

fn validate_existing(mut file: File, expected: &[u8]) -> Result<(), Error> {
    let metadata = file.metadata().map_err(|_| Error::Io)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.len() != expected.len() as u64
    {
        return Err(Error::ExistingOutput);
    }
    let mut actual = Vec::with_capacity(expected.len());
    file.read_to_end(&mut actual).map_err(|_| Error::Io)?;
    if actual != expected {
        return Err(Error::ExistingOutput);
    }
    Ok(())
}

fn publish_exact(path: &Path, expected: &[u8]) -> Result<(), Error> {
    if preflight(path, expected).is_ok() && path.exists() {
        return Ok(());
    }
    let (parent, name) = validate_parent(path)?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags((OFlags::DIRECTORY | OFlags::NOFOLLOW).bits() as i32)
        .open(parent)
        .map_err(|_| Error::UnsafePath)?;
    let descriptor = rustix::fs::openat(
        &directory,
        ".",
        OFlags::WRONLY | OFlags::CLOEXEC | OFlags::TMPFILE,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| Error::UnsupportedFilesystem)?;
    let mut anonymous = File::from(descriptor);
    anonymous.write_all(expected).map_err(|_| Error::Io)?;
    anonymous.sync_all().map_err(|_| Error::Io)?;
    match rustix::fs::linkat(&anonymous, "", &directory, name, AtFlags::EMPTY_PATH) {
        Ok(()) => directory.sync_all().map_err(|_| Error::Io),
        Err(error) if error == rustix::io::Errno::EXIST => {
            // A concurrent exact retry is acceptable; a different inode is not.
            preflight(path, expected)
        }
        Err(_) => Err(Error::Io),
    }
}

fn validate_parent(path: &Path) -> Result<(&Path, &OsStr), Error> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path.file_name().ok_or(Error::UnsafePath)?;
    let metadata = fs::symlink_metadata(parent).map_err(|_| Error::UnsafePath)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(Error::UnsafePath);
    }
    Ok((parent, name))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 15)] as char);
    }
    output
}
