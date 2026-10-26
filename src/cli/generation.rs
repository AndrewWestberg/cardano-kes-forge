use crate::host::client::{self, Error as ClientError};
use crate::host::config::{Error as ConfigError, PoolConnection};
use crate::host::operations::{Error as OperationError, Identity, OperationRecord, State};
use crate::host::publication;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

struct Arguments {
    connection: PathBuf,
    request_id: [u8; 16],
    generation_number: u64,
    verification_key_file: PathBuf,
    encrypted_signing_key_file: PathBuf,
    generation_file: PathBuf,
}

pub fn run(arguments: Vec<OsString>) -> ExitCode {
    let arguments = match parse(arguments) {
        Ok(arguments) => arguments,
        Err(()) => return usage(),
    };
    let operation_file = operation_record_file(&arguments.generation_file);
    if !distinct_outputs(&arguments, &operation_file) || !admissible_existing_outputs(&arguments) {
        eprintln!("generation output path contains unrelated content");
        return ExitCode::from(7);
    }
    let connection = match PoolConnection::load(&arguments.connection) {
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
    let identity = Identity {
        device: connection.device_id,
        pool: Some(connection.pool_id),
        incarnation: Some(connection.incarnation_id),
        request: arguments.request_id,
        generation_number: Some(arguments.generation_number),
    };
    let payload = generation_payload(arguments.generation_number);
    let mut operation =
        match OperationRecord::begin(&operation_file, "GENERATE", identity, &payload) {
            Ok(operation) => operation,
            Err(error) => return operation_error(error),
        };
    if matches!(
        operation.state(),
        State::NotCommitted | State::ResultReclaimed
    ) {
        return client_error(if operation.state() == State::NotCommitted {
            ClientError::NotCommitted
        } else {
            ClientError::ResultReclaimed
        });
    }
    let result = if operation.was_resumed() {
        client::generation_status(
            &connection,
            arguments.request_id,
            arguments.generation_number,
        )
    } else {
        client::generate(
            &connection,
            arguments.request_id,
            arguments.generation_number,
        )
    };
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            record_failure(&mut operation, &error);
            return client_error(error);
        }
    };
    if operation.record_committed(Some(result.generation)).is_err() {
        eprintln!("generation operation record could not be committed");
        return ExitCode::from(7);
    }
    let mut backup_request = arguments.request_id;
    backup_request[15] ^= 1;
    let backup = match client::get_backup(&connection, backup_request, result.generation) {
        Ok(backup) => backup,
        Err(error) => return client_error(error),
    };
    if publication::publish_generation(
        &connection,
        arguments.request_id,
        &result,
        &backup,
        &arguments.verification_key_file,
        &arguments.encrypted_signing_key_file,
        &arguments.generation_file,
    )
    .is_err()
    {
        eprintln!("generation result failed validation or durable publication");
        return ExitCode::from(7);
    }
    ExitCode::SUCCESS
}

fn operation_record_file(generation_file: &Path) -> PathBuf {
    let mut path = generation_file.to_path_buf();
    path.set_extension("operation.json");
    path
}

fn distinct_outputs(arguments: &Arguments, operation_file: &Path) -> bool {
    let paths = [
        arguments.verification_key_file.as_os_str(),
        arguments.encrypted_signing_key_file.as_os_str(),
        arguments.generation_file.as_os_str(),
        operation_file.as_os_str(),
    ];
    paths
        .iter()
        .enumerate()
        .all(|(index, path)| paths[..index].iter().all(|prior| prior != path))
}

fn generation_payload(generation_number: u64) -> Vec<u8> {
    const EXPECTED_REVISION: &[u8] = b"expected_revision";
    const NEXT_GENERATION: &[u8] = b"next_generation_number";
    let mut payload = Vec::with_capacity(1 + 1 + 17 + 1 + 1 + 22 + 9);
    payload.extend_from_slice(&[0xa2, 0x71]);
    payload.extend_from_slice(EXPECTED_REVISION);
    payload.push(0);
    payload.push(0x76);
    payload.extend_from_slice(NEXT_GENERATION);
    push_cbor_uint(&mut payload, generation_number);
    payload
}

fn push_cbor_uint(output: &mut Vec<u8>, value: u64) {
    match value {
        0..=23 => output.push(value as u8),
        24..=0xff => output.extend_from_slice(&[0x18, value as u8]),
        0x100..=0xffff => {
            output.push(0x19);
            output.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push(0x1a);
            output.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            output.push(0x1b);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn record_failure(operation: &mut OperationRecord, error: &ClientError) {
    let result = match error {
        ClientError::InProgress => operation.record_in_progress(),
        ClientError::NotCommitted => operation.record_not_committed(),
        ClientError::ResultReclaimed => operation.record_result_reclaimed(),
        ClientError::Unknown
        | ClientError::Unavailable
        | ClientError::Uncertain
        | ClientError::Conflict
        | ClientError::Security
        | ClientError::Integrity
        | ClientError::Damaged => operation.record_unknown(),
    };
    if result.is_err() {
        eprintln!("generation operation record state could not be updated");
    }
}

fn operation_error(error: OperationError) -> ExitCode {
    let code = match error {
        OperationError::Conflict | OperationError::Rollback => 4,
        OperationError::Io(_) | OperationError::Invalid => 7,
    };
    eprintln!("generation operation record failed with code {code}");
    ExitCode::from(code)
}

fn admissible_existing_outputs(arguments: &Arguments) -> bool {
    valid_or_missing(&arguments.verification_key_file, |bytes| {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
            return false;
        };
        value.get("type").and_then(|value| value.as_str())
            == Some("KesVerificationKey_ed25519_kes_2^6")
            && value
                .get("cborHex")
                .and_then(|value| value.as_str())
                .is_some_and(|value| value.len() == 68 && value.starts_with("5820"))
    }) && valid_or_missing(&arguments.encrypted_signing_key_file, |bytes| {
        kes_protocol::backup::BackupArtifact::parse(bytes).is_ok()
    }) && valid_or_missing(&arguments.generation_file, |bytes| {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
            return false;
        };
        let request_id = hex(&arguments.request_id);
        value.get("requestId").and_then(|value| value.as_str()) == Some(request_id.as_str())
            && value
                .get("generationNumber")
                .and_then(|value| value.as_u64())
                == Some(arguments.generation_number)
    })
}

fn valid_or_missing(path: &Path, validate: impl FnOnce(&[u8]) -> bool) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            std::fs::read(path).is_ok_and(|bytes| validate(&bytes))
        }
        Ok(_) => false,
        Err(error) => error.kind() == std::io::ErrorKind::NotFound,
    }
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
    eprintln!("generation service failed with code {code}");
    ExitCode::from(code)
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

fn parse(arguments: Vec<OsString>) -> Result<Arguments, ()> {
    let mut connection = None;
    let mut request_id = None;
    let mut generation_number = None;
    let mut verification_key_file = None;
    let mut encrypted_signing_key_file = None;
    let mut generation_file = None;
    let mut index = 0;
    while index < arguments.len() {
        let flag = &arguments[index];
        index += 1;
        let value = arguments.get(index).ok_or(())?;
        index += 1;
        match flag.to_str().ok_or(())? {
            "--connection" if connection.is_none() => connection = Some(PathBuf::from(value)),
            "--request-id" if request_id.is_none() => {
                request_id = Some(decode_hex(value.to_str().ok_or(())?).ok_or(())?)
            }
            "--generation-number" if generation_number.is_none() => {
                generation_number = Some(value.to_str().ok_or(())?.parse().map_err(|_| ())?)
            }
            "--verification-key-file" if verification_key_file.is_none() => {
                verification_key_file = Some(PathBuf::from(value))
            }
            "--encrypted-signing-key-file" if encrypted_signing_key_file.is_none() => {
                encrypted_signing_key_file = Some(PathBuf::from(value))
            }
            "--generation-file" if generation_file.is_none() => {
                generation_file = Some(PathBuf::from(value))
            }
            _ => return Err(()),
        }
    }
    Ok(Arguments {
        connection: connection.ok_or(())?,
        request_id: request_id.ok_or(())?,
        generation_number: generation_number.ok_or(())?,
        verification_key_file: verification_key_file.ok_or(())?,
        encrypted_signing_key_file: encrypted_signing_key_file.ok_or(())?,
        generation_file: generation_file.ok_or(())?,
    })
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

fn usage() -> ExitCode {
    eprintln!(
        "Usage: kes-forge key-gen-KES --connection FILE --request-id HEX32 --generation-number UINT --verification-key-file FILE --encrypted-signing-key-file FILE --generation-file FILE"
    );
    ExitCode::from(2)
}
