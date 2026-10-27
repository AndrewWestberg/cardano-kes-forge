use crate::backup::{publication::Error as PublicationError, recipient, recover};
use crate::host::client::{self, Error as ClientError};
use crate::host::config::{Error as ConfigError, PublicPoolConnection};
use crate::host::publication;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

struct RecoveryArguments {
    artifact: PathBuf,
    recipient_key: PathBuf,
    device_identity: PathBuf,
    expected_device: [u8; 16],
    expected_pool: [u8; 28],
    expected_generation: [u8; 16],
    verification_key: PathBuf,
    output: PathBuf,
}

pub fn run_primary(arguments: Vec<OsString>) -> ExitCode {
    match arguments.first().and_then(|argument| argument.to_str()) {
        Some("fetch") => run_fetch(arguments),
        _ => usage_primary(),
    }
}

pub fn run_recovery(arguments: Vec<OsString>) -> ExitCode {
    match arguments.first().and_then(|argument| argument.to_str()) {
        Some("recover") => run_recover(arguments),
        _ => usage_recovery(),
    }
}

fn run_recover(arguments: Vec<OsString>) -> ExitCode {
    let arguments = match parse_recovery(arguments) {
        Ok(arguments) => arguments,
        Err(()) => return usage_recovery(),
    };
    let passphrase = match recipient::prompt_existing_passphrase() {
        Ok(passphrase) => passphrase,
        Err(recipient::Error::MemoryProtection) => {
            eprintln!("recovery requires a fresh no-swap, non-dumpable process");
            return ExitCode::from(5);
        }
        Err(_) => {
            eprintln!("recipient passphrase input unavailable or invalid");
            return ExitCode::from(2);
        }
    };
    match recover::recover_files(
        recover::RecoveryFiles {
            artifact: &arguments.artifact,
            recipient_key: &arguments.recipient_key,
            device_identity: &arguments.device_identity,
            expected_device: arguments.expected_device,
            expected_pool: arguments.expected_pool,
            expected_generation: arguments.expected_generation,
            verification_key: &arguments.verification_key,
            output: &arguments.output,
        },
        &passphrase,
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => recovery_error(error),
    }
}

fn run_fetch(arguments: Vec<OsString>) -> ExitCode {
    let (connection_path, generation, output) = match parse(arguments) {
        Ok(arguments) => arguments,
        Err(()) => return usage_primary(),
    };
    match std::fs::symlink_metadata(&output) {
        Ok(metadata) => {
            let valid = metadata.file_type().is_file()
                && std::fs::read(&output)
                    .is_ok_and(|bytes| kes_protocol::backup::BackupArtifact::parse(&bytes).is_ok());
            if !valid {
                eprintln!("backup output path contains unrelated content");
                return ExitCode::from(7);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return ExitCode::from(7),
    }
    let connection = match PublicPoolConnection::load(&connection_path) {
        Ok(connection) => connection,
        Err(ConfigError::Security) => {
            eprintln!("connection authentication binding mismatch");
            return ExitCode::from(3);
        }
        Err(ConfigError::Invalid | ConfigError::Unreadable) => {
            eprintln!("invalid connection configuration");
            return ExitCode::from(2);
        }
    };
    let mut request_hasher = Sha256::new();
    request_hasher.update(b"cardano-kes-forge/get-backup/v1");
    request_hasher.update(generation);
    let request_digest = request_hasher.finalize();
    let mut request = [0; 16];
    request.copy_from_slice(&request_digest[..16]);
    let backup = match client::get_backup(&connection, request, generation) {
        Ok(backup) => backup,
        Err(error) => return client_error(error),
    };
    if publication::publish_backup(&connection, generation, &backup, &output).is_err() {
        eprintln!("backup failed validation or durable publication");
        return ExitCode::from(7);
    }
    ExitCode::SUCCESS
}

fn client_error(error: ClientError) -> ExitCode {
    let code = match error {
        ClientError::Security => 3,
        ClientError::Conflict
        | ClientError::InProgress
        | ClientError::Unknown
        | ClientError::NotCommitted
        | ClientError::ResultReclaimed => 4,
        ClientError::Unavailable | ClientError::Uncertain => 5,
        ClientError::Integrity | ClientError::Damaged => 6,
    };
    eprintln!("backup service failed with code {code}");
    ExitCode::from(code)
}

fn parse(arguments: Vec<OsString>) -> Result<(PathBuf, [u8; 16], PathBuf), ()> {
    let mut arguments = arguments.into_iter();
    if arguments.next().as_deref() != Some("fetch".as_ref()) {
        return Err(());
    }
    let mut connection = None;
    let mut generation = None;
    let mut output = None;
    while let Some(flag) = arguments.next() {
        let value = arguments.next().ok_or(())?;
        match flag.to_str().ok_or(())? {
            "--connection" if connection.is_none() => connection = Some(PathBuf::from(value)),
            "--generation" if generation.is_none() => {
                generation = Some(decode_hex(value.to_str().ok_or(())?).ok_or(())?)
            }
            "--out-file" if output.is_none() => output = Some(PathBuf::from(value)),
            _ => return Err(()),
        }
    }
    Ok((
        connection.ok_or(())?,
        generation.ok_or(())?,
        output.ok_or(())?,
    ))
}

fn parse_recovery(arguments: Vec<OsString>) -> Result<RecoveryArguments, ()> {
    let mut arguments = arguments.into_iter();
    if arguments.next().as_deref() != Some("recover".as_ref()) {
        return Err(());
    }
    let mut artifact = None;
    let mut recipient_key = None;
    let mut device_identity = None;
    let mut expected_device = None;
    let mut expected_pool = None;
    let mut expected_generation = None;
    let mut verification_key = None;
    let mut output = None;
    while let Some(flag) = arguments.next() {
        let value = arguments.next().ok_or(())?;
        match flag.to_str().ok_or(())? {
            "--artifact" if artifact.is_none() => artifact = Some(PathBuf::from(value)),
            "--recipient-key" if recipient_key.is_none() => {
                recipient_key = Some(PathBuf::from(value))
            }
            "--device-identity-file" if device_identity.is_none() => {
                device_identity = Some(PathBuf::from(value))
            }
            "--expect-device" if expected_device.is_none() => {
                expected_device = Some(decode_hex(value.to_str().ok_or(())?).ok_or(())?)
            }
            "--expect-pool" if expected_pool.is_none() => {
                expected_pool = Some(decode_hex(value.to_str().ok_or(())?).ok_or(())?)
            }
            "--expect-generation" if expected_generation.is_none() => {
                expected_generation = Some(decode_hex(value.to_str().ok_or(())?).ok_or(())?)
            }
            "--verification-key-file" if verification_key.is_none() => {
                verification_key = Some(PathBuf::from(value))
            }
            "--out-file" if output.is_none() => output = Some(PathBuf::from(value)),
            _ => return Err(()),
        }
    }
    Ok(RecoveryArguments {
        artifact: artifact.ok_or(())?,
        recipient_key: recipient_key.ok_or(())?,
        device_identity: device_identity.ok_or(())?,
        expected_device: expected_device.ok_or(())?,
        expected_pool: expected_pool.ok_or(())?,
        expected_generation: expected_generation.ok_or(())?,
        verification_key: verification_key.ok_or(())?,
        output: output.ok_or(())?,
    })
}

fn recovery_error(error: recover::Error) -> ExitCode {
    if error == recover::Error::Publication(PublicationError::DurabilityUncertain) {
        eprintln!(
            "backup recovery durability is uncertain after linking; the complete output may exist and retries will not overwrite it"
        );
        return ExitCode::from(7);
    }
    let code = match error {
        recover::Error::WrongBinding
        | recover::Error::InvalidSignature
        | recover::Error::WrongRecipient
        | recover::Error::WrongPassword => 3,
        recover::Error::MemoryProtection => 5,
        recover::Error::InvalidArtifact
        | recover::Error::Decryption
        | recover::Error::InvalidState => 6,
        recover::Error::InvalidInput => 2,
        recover::Error::Publication(
            PublicationError::ExistingOutput
            | PublicationError::UnsafeDirectory
            | PublicationError::UnsupportedFilesystem
            | PublicationError::Interrupted
            | PublicationError::Io
            | PublicationError::UnsafeInput,
        ) => 7,
        recover::Error::Publication(PublicationError::DurabilityUncertain) => unreachable!(),
        recover::Error::Publication(PublicationError::MemoryProtection) => 5,
    };
    eprintln!("backup recovery failed with code {code}");
    ExitCode::from(code)
}

fn decode_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 {
        return None;
    }
    let mut output = [0; N];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        output[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(output)
}

fn nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn usage_primary() -> ExitCode {
    eprintln!("Usage: kes-forge backup fetch --connection FILE --generation HEX32 --out-file FILE");
    ExitCode::from(2)
}

fn usage_recovery() -> ExitCode {
    eprintln!(
        "Usage: kes-forge backup recover --artifact FILE --recipient-key FILE --device-identity-file FILE --expect-device HEX32 --expect-pool HEX56 --expect-generation HEX32 --verification-key-file FILE --out-file FILE"
    );
    ExitCode::from(2)
}
