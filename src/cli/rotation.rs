use crate::host::client::{self, Descriptor, Error as ClientError, PoolStatus};
use crate::host::config::{Error as ConfigError, PoolConnection};
use crate::host::operations::{Error as OperationError, Identity, OperationRecord, State};
use kes_core::cbor::{Encoder, Value};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const MAX_CERTIFICATE_FILE_BYTES: u64 = 16_384;

#[derive(Clone, Copy)]
enum Command {
    Certify,
    Activate,
    Schedule,
}
impl Command {
    const fn operation(self) -> &'static str {
        match self {
            Self::Certify => "CERTIFY",
            Self::Activate => "ACTIVATE",
            Self::Schedule => "SCHEDULE",
        }
    }
}

struct Arguments {
    command: Command,
    connection: PathBuf,
    generation: [u8; 16],
    certificate_file: Option<PathBuf>,
    period: Option<u64>,
    json: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CertificateEnvelope {
    #[serde(rename = "type")]
    kind: String,
    #[serde(rename = "description")]
    _description: String,
    #[serde(rename = "cborHex")]
    cbor_hex: String,
}

pub fn run(command: &str, arguments: Vec<OsString>) -> ExitCode {
    let command = match command {
        "certify" => Command::Certify,
        "activate" => Command::Activate,
        "schedule" => Command::Schedule,
        _ => return ExitCode::from(2),
    };
    let arguments = match parse(command, arguments) {
        Ok(arguments) => arguments,
        Err(()) => return usage(command),
    };
    match execute(&arguments) {
        Ok(outcome) => {
            print_result(&arguments, &outcome);
            ExitCode::SUCCESS
        }
        Err(error) => {
            let code = error.exit_code();
            eprintln!("rotation operation failed: {}", error.message());
            ExitCode::from(code)
        }
    }
}

#[derive(Debug)]
enum Error {
    Usage,
    Security,
    Conflict,
    Unavailable,
    Integrity,
    Filesystem,
}
impl Error {
    const fn exit_code(&self) -> u8 {
        match self {
            Self::Usage => 2,
            Self::Security => 3,
            Self::Conflict => 4,
            Self::Unavailable => 5,
            Self::Integrity => 6,
            Self::Filesystem => 7,
        }
    }
    const fn message(&self) -> &'static str {
        match self {
            Self::Usage => "invalid configuration or arguments",
            Self::Security => "authentication or security policy failure",
            Self::Conflict => "rotation context conflict",
            Self::Unavailable => "device service unavailable or deadline expired",
            Self::Integrity => "invalid certificate or service response",
            Self::Filesystem => "operation record could not be persisted",
        }
    }
}

struct Outcome {
    descriptor: Descriptor,
    device: [u8; 16],
    pool: [u8; 28],
    request: [u8; 16],
}

fn execute(arguments: &Arguments) -> Result<Outcome, Error> {
    let connection = PoolConnection::load(&arguments.connection).map_err(config_error)?;
    let record_path = operation_record_path(
        &arguments.connection,
        arguments.command,
        arguments.generation,
    );
    let existing = match std::fs::symlink_metadata(&record_path) {
        Ok(_) => Some(OperationRecord::load(&record_path).map_err(operation_error)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(Error::Filesystem),
    };
    let request = match existing.as_ref() {
        Some(record) => record.identity().request,
        None => random_request_id()?,
    };
    let mut status_request = request;
    status_request[15] ^= 0x80;
    let status = client::pool_status(&connection, status_request).map_err(client_error)?;
    if let Some(descriptor) = completed_descriptor(arguments, &status, existing.as_ref())? {
        if matches!(arguments.command, Command::Certify) {
            let certificate =
                read_certificate(arguments.certificate_file.as_deref().ok_or(Error::Usage)?)?;
            publish_certificate(&connection, arguments.generation, &certificate)?;
        }
        if let Some(mut record) = existing {
            if record.state() != State::Committed {
                record.record_committed(None).map_err(operation_error)?;
            }
        }
        return Ok(Outcome {
            descriptor: descriptor.clone(),
            device: connection.device_id,
            pool: connection.pool_id,
            request,
        });
    }

    let expected_revision = match existing.as_ref() {
        Some(record) => expected_revision(record.canonical_payload().ok_or(Error::Integrity)?)?,
        None => status.revision,
    };
    let prepared = prepare(arguments, &connection, &status, expected_revision)?;
    let identity = Identity {
        device: connection.device_id,
        pool: Some(connection.pool_id),
        incarnation: Some(connection.incarnation_id),
        request,
        generation_number: None,
    };
    let mut record = OperationRecord::begin(
        &record_path,
        arguments.command.operation(),
        identity,
        &prepared.canonical_payload,
    )
    .map_err(operation_error)?;
    let descriptor = match arguments.command {
        Command::Certify => client::certify(
            &connection,
            request,
            arguments.generation,
            prepared.certificate.as_deref().ok_or(Error::Integrity)?,
            expected_revision,
        ),
        Command::Activate => client::activate(
            &connection,
            request,
            arguments.generation,
            prepared.certificate_digest.ok_or(Error::Integrity)?,
            arguments.period.ok_or(Error::Usage)?,
            prepared.expected_active_generation,
            expected_revision,
        ),
        Command::Schedule => client::schedule(
            &connection,
            request,
            arguments.generation,
            prepared.certificate_digest.ok_or(Error::Integrity)?,
            arguments.period.ok_or(Error::Usage)?,
            prepared.expected_active_generation.ok_or(Error::Conflict)?,
            expected_revision,
        ),
    }
    .map_err(|error| {
        let _ = record_client_outcome(&mut record, &error);
        client_error(error)
    })?;
    validate_result(arguments.command, arguments.generation, &descriptor)?;
    if let Some(certificate) = prepared.certificate.as_deref() {
        publish_certificate(&connection, arguments.generation, certificate)?;
    }
    record.record_committed(None).map_err(operation_error)?;
    Ok(Outcome {
        descriptor,
        device: connection.device_id,
        pool: connection.pool_id,
        request,
    })
}

fn record_client_outcome(
    record: &mut OperationRecord,
    error: &ClientError,
) -> Result<(), OperationError> {
    match error {
        ClientError::InProgress => record.record_in_progress(),
        ClientError::ResultReclaimed => record.record_result_reclaimed(),
        ClientError::Conflict
        | ClientError::Security
        | ClientError::Integrity
        | ClientError::Damaged
        | ClientError::NotCommitted => record.record_not_committed(),
        ClientError::Unavailable | ClientError::Uncertain | ClientError::Unknown => {
            record.record_unknown()
        }
    }
}

fn publish_certificate(
    connection: &PoolConnection,
    generation: [u8; 16],
    certificate: &[u8],
) -> Result<(), Error> {
    let path = crate::host::rotation::certificate_path(
        &connection.socket_path,
        &connection.connection_name,
        generation,
    );
    crate::host::publication::publish_rotation_certificate(&path, certificate)
        .map_err(|_| Error::Filesystem)
}

struct Prepared {
    canonical_payload: Vec<u8>,
    certificate: Option<Vec<u8>>,
    certificate_digest: Option<[u8; 32]>,
    expected_active_generation: Option<[u8; 16]>,
}

fn prepare(
    arguments: &Arguments,
    connection: &PoolConnection,
    status: &PoolStatus,
    expected_revision: u64,
) -> Result<Prepared, Error> {
    let staged = status
        .staged
        .as_ref()
        .filter(|descriptor| descriptor.generation == arguments.generation)
        .ok_or(Error::Conflict)?;
    match arguments.command {
        Command::Certify => {
            if staged.lifecycle != "staged" && staged.lifecycle != "certified-staged" {
                return Err(Error::Conflict);
            }
            let certificate =
                read_certificate(arguments.certificate_file.as_deref().ok_or(Error::Usage)?)?;
            let canonical_payload = certify_payload(
                connection,
                arguments.generation,
                &certificate,
                expected_revision,
            )?;
            Ok(Prepared {
                canonical_payload,
                certificate_digest: Some(Sha256::digest(&certificate).into()),
                certificate: Some(certificate),
                expected_active_generation: status.active.as_ref().map(|value| value.generation),
            })
        }
        Command::Activate | Command::Schedule => {
            if staged.lifecycle != "certified-staged" {
                return Err(Error::Conflict);
            }
            let certificate_digest = staged.certificate_digest.ok_or(Error::Conflict)?;
            let expected_active_generation = status.active.as_ref().map(|value| value.generation);
            if matches!(arguments.command, Command::Schedule)
                && expected_active_generation.is_none()
            {
                return Err(Error::Conflict);
            }
            let period = arguments.period.ok_or(Error::Usage)?;
            let canonical_payload = activation_payload(
                arguments.command,
                arguments.generation,
                certificate_digest,
                period,
                expected_active_generation,
                expected_revision,
            )?;
            Ok(Prepared {
                canonical_payload,
                certificate: None,
                certificate_digest: Some(certificate_digest),
                expected_active_generation,
            })
        }
    }
}

fn completed_descriptor<'a>(
    arguments: &Arguments,
    status: &'a PoolStatus,
    record: Option<&OperationRecord>,
) -> Result<Option<&'a Descriptor>, Error> {
    let expected_certificate_digest = if matches!(arguments.command, Command::Certify) {
        Some(<[u8; 32]>::from(Sha256::digest(read_certificate(
            arguments.certificate_file.as_deref().ok_or(Error::Usage)?,
        )?)))
    } else {
        None
    };
    let matching = |descriptor: &&Descriptor| {
        descriptor.generation == arguments.generation
            && descriptor.certificate_digest == expected_certificate_digest
    };
    let result = match arguments.command {
        Command::Certify => status
            .staged
            .as_ref()
            .filter(|descriptor| descriptor.lifecycle == "certified-staged")
            .filter(matching)
            .or_else(|| status.active.as_ref().filter(matching)),
        Command::Activate => status.active.as_ref().filter(|descriptor| {
            descriptor.generation == arguments.generation && descriptor.lifecycle == "active"
        }),
        Command::Schedule if record.is_some_and(|value| value.state() == State::Committed) => {
            status
                .staged
                .as_ref()
                .or(status.active.as_ref())
                .filter(|descriptor| descriptor.generation == arguments.generation)
        }
        Command::Schedule => None,
    };
    Ok(result)
}

fn certify_payload(
    connection: &PoolConnection,
    generation: [u8; 16],
    certificate: &[u8],
    expected_revision: u64,
) -> Result<Vec<u8>, Error> {
    let certificate = Value::parse(certificate).map_err(|_| Error::Integrity)?;
    encode_payload(|encoder| {
        encoder.map(4)?;
        encoder.text("network")?;
        encode_network(encoder, connection)?;
        encoder.text("generation")?;
        encoder.bytes(&generation)?;
        encoder.text("certificate")?;
        encoder.value(certificate)?;
        encoder.text("expected_revision")?;
        encoder.uint(expected_revision)
    })
}

fn activation_payload(
    command: Command,
    generation: [u8; 16],
    certificate_digest: [u8; 32],
    period: u64,
    expected_active_generation: Option<[u8; 16]>,
    expected_revision: u64,
) -> Result<Vec<u8>, Error> {
    encode_payload(|encoder| {
        encoder.map(5)?;
        encoder.text("generation")?;
        encoder.bytes(&generation)?;
        encoder.text("expected_revision")?;
        encoder.uint(expected_revision)?;
        encoder.text("certificate_digest")?;
        encoder.bytes(&certificate_digest)?;
        encoder.text(match command {
            Command::Activate => "current_absolute_period",
            Command::Schedule => "activation_absolute_period",
            Command::Certify => return Err(kes_core::cbor::Error::InvalidType),
        })?;
        encoder.uint(period)?;
        encoder.text("expected_active_generation")?;
        match expected_active_generation {
            Some(value) => encoder.bytes(&value),
            None => encoder.null(),
        }
    })
}

fn encode_payload(
    encode: impl FnOnce(&mut Encoder<'_>) -> Result<(), kes_core::cbor::Error>,
) -> Result<Vec<u8>, Error> {
    let mut bytes = [0; kes_protocol::MAX_FRAME_BYTES];
    let mut encoder = Encoder::new(&mut bytes);
    encode(&mut encoder).map_err(|_| Error::Integrity)?;
    Ok(encoder
        .finish()
        .map_err(|_| Error::Integrity)?
        .encoded()
        .to_vec())
}

fn encode_network(
    encoder: &mut Encoder<'_>,
    connection: &PoolConnection,
) -> Result<(), kes_core::cbor::Error> {
    let digest = decode_hex::<32>(&connection.network_binding.shelley_genesis_digest)
        .expect("validated connection digest");
    encoder.map(4)?;
    encoder.text("network_magic")?;
    encoder.uint(connection.network_binding.network_magic)?;
    encoder.text("max_kes_evolutions")?;
    encoder.uint(connection.network_binding.max_kes_evolutions)?;
    encoder.text("slots_per_kes_period")?;
    encoder.uint(connection.network_binding.slots_per_kes_period)?;
    encoder.text("shelley_genesis_digest")?;
    encoder.bytes(&digest)
}

fn expected_revision(payload: &[u8]) -> Result<u64, Error> {
    Value::parse(payload)
        .and_then(|value| value.map())
        .and_then(|map| map.required("expected_revision"))
        .and_then(|value| value.uint())
        .map_err(|_| Error::Integrity)
}

fn read_certificate(path: &Path) -> Result<Vec<u8>, Error> {
    let file = File::open(path).map_err(|_| Error::Filesystem)?;
    let mut bytes = Vec::new();
    file.take(MAX_CERTIFICATE_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Filesystem)?;
    if bytes.len() as u64 > MAX_CERTIFICATE_FILE_BYTES {
        return Err(Error::Usage);
    }
    let envelope: CertificateEnvelope =
        serde_json::from_slice(&bytes).map_err(|_| Error::Integrity)?;
    if envelope.kind != "NodeOperationalCertificate" {
        return Err(Error::Integrity);
    }
    decode_hex_vec(&envelope.cbor_hex).ok_or(Error::Integrity)
}

fn validate_result(
    command: Command,
    generation: [u8; 16],
    result: &Descriptor,
) -> Result<(), Error> {
    let expected_lifecycle = match command {
        Command::Certify | Command::Schedule => "certified-staged",
        Command::Activate => "active",
    };
    if result.generation != generation || result.lifecycle != expected_lifecycle {
        Err(Error::Integrity)
    } else {
        Ok(())
    }
}

fn operation_record_path(connection: &Path, command: Command, generation: [u8; 16]) -> PathBuf {
    let mut path = connection.to_path_buf();
    let name = connection
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("connection");
    path.set_file_name(format!(
        ".{name}.{}-{}.operation.json",
        command.operation().to_ascii_lowercase(),
        hex(&generation)
    ));
    path
}

fn random_request_id() -> Result<[u8; 16], Error> {
    let mut request = [0; 16];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut request))
        .map_err(|_| Error::Unavailable)?;
    Ok(request)
}

fn print_result(arguments: &Arguments, outcome: &Outcome) {
    let descriptor = &outcome.descriptor;
    if arguments.json {
        println!(
            "{}",
            serde_json::json!({
                "version": 1,
                "operation": arguments.command.operation(),
                "requestId": hex(&outcome.request),
                "deviceId": hex(&outcome.device),
                "poolId": hex(&outcome.pool),
                "generationId": hex(&descriptor.generation),
                "revision": descriptor.revision,
                "result": descriptor.lifecycle,
            })
        );
    } else {
        println!(
            "{} generation {} at revision {}",
            descriptor.lifecycle,
            hex(&descriptor.generation),
            descriptor.revision
        );
    }
}

fn parse(command: Command, arguments: Vec<OsString>) -> Result<Arguments, ()> {
    let mut connection = None;
    let mut generation = None;
    let mut certificate_file = None;
    let mut period = None;
    let mut json = false;
    let mut index = 0;
    while index < arguments.len() {
        let flag = arguments[index].to_str().ok_or(())?;
        index += 1;
        if flag == "--json" && !json {
            json = true;
            continue;
        }
        let value = arguments.get(index).ok_or(())?;
        index += 1;
        match flag {
            "--connection" if connection.is_none() => connection = Some(PathBuf::from(value)),
            "--generation" if generation.is_none() => {
                generation = Some(decode_hex(value.to_str().ok_or(())?).ok_or(())?)
            }
            "--operational-certificate-file"
                if matches!(command, Command::Certify) && certificate_file.is_none() =>
            {
                certificate_file = Some(PathBuf::from(value))
            }
            "--current-period" if matches!(command, Command::Activate) && period.is_none() => {
                period = Some(value.to_str().ok_or(())?.parse().map_err(|_| ())?)
            }
            "--activation-period" if matches!(command, Command::Schedule) && period.is_none() => {
                period = Some(value.to_str().ok_or(())?.parse().map_err(|_| ())?)
            }
            _ => return Err(()),
        }
    }
    if matches!(command, Command::Certify) != certificate_file.is_some()
        || !matches!(command, Command::Certify) != period.is_some()
    {
        return Err(());
    }
    Ok(Arguments {
        command,
        connection: connection.ok_or(())?,
        generation: generation.ok_or(())?,
        certificate_file,
        period,
        json,
    })
}

fn usage(command: Command) -> ExitCode {
    let tail = match command {
        Command::Certify => "--operational-certificate-file FILE",
        Command::Activate => "--current-period UINT",
        Command::Schedule => "--activation-period UINT",
    };
    eprintln!(
        "Usage: kes-forge {} --connection FILE --generation HEX32 {tail} [--json]",
        command.operation().to_ascii_lowercase()
    );
    ExitCode::from(2)
}

fn config_error(error: ConfigError) -> Error {
    match error {
        ConfigError::Security => Error::Security,
        ConfigError::Invalid | ConfigError::Unreadable => Error::Usage,
    }
}
fn operation_error(error: OperationError) -> Error {
    match error {
        OperationError::Conflict | OperationError::Rollback => Error::Conflict,
        OperationError::Invalid | OperationError::Io(_) => Error::Filesystem,
    }
}
fn client_error(error: ClientError) -> Error {
    match error {
        ClientError::Security => Error::Security,
        ClientError::Conflict
        | ClientError::InProgress
        | ClientError::Unknown
        | ClientError::NotCommitted
        | ClientError::ResultReclaimed => Error::Conflict,
        ClientError::Unavailable | ClientError::Uncertain => Error::Unavailable,
        ClientError::Integrity | ClientError::Damaged => Error::Integrity,
    }
}

fn decode_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 {
        return None;
    }
    let mut output = [0; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(output)
}
fn decode_hex_vec(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Some((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}
fn nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}
fn hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 15)] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn command_parser_requires_exact_operation_flags() {
        let generation = "01010101010101010101010101010101";
        assert!(
            parse(
                Command::Certify,
                arguments(&[
                    "--connection",
                    "pool.json",
                    "--generation",
                    generation,
                    "--operational-certificate-file",
                    "node.cert",
                ]),
            )
            .is_ok()
        );
        assert!(
            parse(
                Command::Activate,
                arguments(&[
                    "--connection",
                    "pool.json",
                    "--generation",
                    generation,
                    "--activation-period",
                    "42",
                ]),
            )
            .is_err()
        );
        assert!(
            parse(
                Command::Schedule,
                arguments(&[
                    "--connection",
                    "pool.json",
                    "--generation",
                    generation,
                    "--activation-period",
                    "not-a-period",
                ]),
            )
            .is_err()
        );
    }

    #[test]
    fn certificate_envelope_rejects_duplicate_and_unknown_fields() {
        let path = std::env::temp_dir().join(format!(
            "kes-forge-rotation-certificate-{}.json",
            std::process::id()
        ));
        let duplicate = br#"{"type":"NodeOperationalCertificate","type":"NodeOperationalCertificate","description":"test","cborHex":"80"}"#;
        fs::write(&path, duplicate).unwrap();
        assert!(matches!(read_certificate(&path), Err(Error::Integrity)));
        let unknown = br#"{"type":"NodeOperationalCertificate","description":"test","cborHex":"80","unexpected":true}"#;
        fs::write(&path, unknown).unwrap();
        assert!(matches!(read_certificate(&path), Err(Error::Integrity)));
        fs::remove_file(path).unwrap();
    }
}
