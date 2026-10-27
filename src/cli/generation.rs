use crate::host::client::{self, Error as ClientError};
use crate::host::config::{Error as ConfigError, PublicPoolConnection};
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
    let json = arguments.iter().any(|argument| argument == "--json");
    let mut context = serde_json::json!({
        "version": 1, "operation": "GENERATE", "requestId": null,
        "deviceId": null, "poolId": null, "generationId": null, "revision": null,
    });
    match execute(arguments, &mut context) {
        Ok(result) => {
            context["result"] = result;
            if json {
                println!("{context}");
            } else {
                println!("generation completed");
            }
            ExitCode::SUCCESS
        }
        Err((exit, code)) => {
            if json {
                context["code"] = serde_json::json!(code);
                context["scope"] = serde_json::json!("pool");
                eprintln!("{context}");
            } else {
                eprintln!("generation failed: {code}");
            }
            ExitCode::from(exit)
        }
    }
}

fn execute(
    arguments: Vec<OsString>,
    context: &mut serde_json::Value,
) -> Result<serde_json::Value, (u8, &'static str)> {
    let arguments = parse(arguments).map_err(|()| (2, "INVALID_ARGUMENTS"))?;
    context["requestId"] = serde_json::json!(hex(&arguments.request_id));
    let operation_file = operation_record_file(&arguments.generation_file);
    if !distinct_outputs(&arguments, &operation_file) || !admissible_existing_outputs(&arguments) {
        return Err((7, "OUTPUT_CONFLICT"));
    }
    let connection =
        PublicPoolConnection::load(&arguments.connection).map_err(|error| match error {
            ConfigError::Security => (3, "AUTHENTICATION_FAILED"),
            ConfigError::Invalid | ConfigError::Unreadable => (2, "INVALID_CONFIGURATION"),
        })?;
    context["deviceId"] = serde_json::json!(hex(&connection.device_id));
    context["poolId"] = serde_json::json!(hex(&connection.pool_id));
    let identity = Identity {
        device: connection.device_id,
        pool: Some(connection.pool_id),
        incarnation: Some(connection.incarnation_id),
        request: arguments.request_id,
        generation_number: Some(arguments.generation_number),
    };
    let (payload, expected_revision) = match OperationRecord::load(&operation_file) {
        Ok(record) => {
            if record.identity() != identity {
                return Err(operation_error(OperationError::Conflict));
            }
            let payload = record
                .canonical_payload()
                .ok_or_else(|| operation_error(OperationError::Invalid))?;
            let revision = generation_payload_revision(payload, arguments.generation_number)
                .ok_or_else(|| operation_error(OperationError::Conflict))?;
            (payload.to_vec(), revision)
        }
        Err(OperationError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut status_request = arguments.request_id;
            status_request[15] ^= 1;
            let revision = client::pool_status(&connection, status_request)
                .map_err(client_error)?
                .revision;
            (
                generation_payload(arguments.generation_number, revision),
                revision,
            )
        }
        Err(error) => return Err(operation_error(error)),
    };
    let mut operation = OperationRecord::begin(&operation_file, "GENERATE", identity, &payload)
        .map_err(operation_error)?;
    if matches!(
        operation.state(),
        State::NotCommitted | State::ResultReclaimed
    ) {
        return Err(client_error(if operation.state() == State::NotCommitted {
            ClientError::NotCommitted
        } else {
            ClientError::ResultReclaimed
        }));
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
            expected_revision,
        )
    };
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            record_failure(&mut operation, &error).map_err(operation_error)?;
            return Err(client_error(error));
        }
    };
    operation
        .record_committed(Some(result.generation))
        .map_err(operation_error)?;
    context["generationId"] = serde_json::json!(hex(&result.generation));
    context["revision"] = serde_json::json!(result.revision);
    let mut backup_request = arguments.request_id;
    backup_request[15] ^= 1;
    let backup =
        client::get_backup(&connection, backup_request, result.generation).map_err(client_error)?;
    publication::publish_generation(
        &connection,
        arguments.request_id,
        &result,
        &backup,
        &arguments.verification_key_file,
        &arguments.encrypted_signing_key_file,
        &arguments.generation_file,
    )
    .map_err(|error| match error {
        publication::Error::InvalidResult => (6, "INTEGRITY_FAILURE"),
        _ => (7, "PUBLICATION_FAILED"),
    })?;
    Ok(serde_json::json!({
        "generationNumber": result.generation_number,
        "verificationKey": hex(&result.verification_key),
        "artifactDigest": hex(&result.artifact_digest),
    }))
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

fn generation_payload(generation_number: u64, expected_revision: u64) -> Vec<u8> {
    const EXPECTED_REVISION: &[u8] = b"expected_revision";
    const NEXT_GENERATION: &[u8] = b"next_generation_number";
    let mut payload = Vec::with_capacity(1 + 1 + 17 + 1 + 1 + 22 + 9);
    payload.extend_from_slice(&[0xa2, 0x71]);
    payload.extend_from_slice(EXPECTED_REVISION);
    push_cbor_uint(&mut payload, expected_revision);
    payload.push(0x76);
    payload.extend_from_slice(NEXT_GENERATION);
    push_cbor_uint(&mut payload, generation_number);
    payload
}

fn generation_payload_revision(payload: &[u8], generation_number: u64) -> Option<u64> {
    let map = kes_core::cbor::Value::parse(payload).ok()?.map().ok()?;
    if map.len() != 2
        || map.required("next_generation_number").ok()?.uint().ok()? != generation_number
    {
        return None;
    }
    map.required("expected_revision").ok()?.uint().ok()
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

fn record_failure(
    operation: &mut OperationRecord,
    error: &ClientError,
) -> Result<(), OperationError> {
    match error {
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
    }
}

fn operation_error(error: OperationError) -> (u8, &'static str) {
    match error {
        OperationError::Conflict | OperationError::Rollback => (4, "OPERATION_CONFLICT"),
        OperationError::Io(_) | OperationError::Invalid => (7, "OPERATION_RECORD_FAILED"),
    }
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

fn client_error(error: ClientError) -> (u8, &'static str) {
    match error {
        ClientError::Security => (3, "AUTHENTICATION_FAILED"),
        ClientError::Conflict => (4, "CONFLICT"),
        ClientError::InProgress => (4, "IN_PROGRESS"),
        ClientError::Unknown => (4, "UNKNOWN"),
        ClientError::NotCommitted => (4, "NOT_COMMITTED"),
        ClientError::ResultReclaimed => (4, "RESULT_RECLAIMED"),
        ClientError::Unavailable => (5, "DEVICE_UNAVAILABLE"),
        ClientError::Uncertain => (5, "OUTCOME_UNKNOWN"),
        ClientError::Integrity => (6, "INTEGRITY_FAILURE"),
        ClientError::Damaged => (6, "STATE_DAMAGED"),
    }
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
    let mut json_seen = false;
    let mut index = 0;
    while index < arguments.len() {
        let flag = &arguments[index];
        index += 1;
        if flag == "--json" {
            if json_seen {
                return Err(());
            }
            json_seen = true;
            continue;
        }
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
