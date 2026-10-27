use cardano_kes_forge::host::client::{DeviceWire, Error as ClientError};
use cardano_kes_forge::host::config::{DeviceConfig, DeviceIdentity, PoolConnection};
use cardano_kes_forge::host::daemon::{AuthenticatedTransport, Config, Daemon};
use ed25519_dalek::{Signer, SigningKey};
use kes_core::cbor::Encoder;
use kes_protocol::{Envelope, EnvelopeKind, Operation};
use sha2::{Digest, Sha256};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const DEVICE: &str = "10101010101010101010101010101010";
const POOL: &str = "20202020202020202020202020202020202020202020202020202020";
const OTHER_POOL: &str = "21212121212121212121212121212121212121212121212121212121";
const INCARNATION: &str = "30303030303030303030303030303030";
const REQUEST: &str = "40404040404040404040404040404040";
const DIGEST: &str = "5050505050505050505050505050505050505050505050505050505050505050";
const GENERATION: &str = "60606060606060606060606060606060";

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    connection: PathBuf,
    socket: PathBuf,
}

impl Fixture {
    fn new(credential_pool: &str) -> Self {
        let nonce = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "kes-forge-generation-contract-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();

        let identity = root.join("device.identity.json");
        let credential = root.join("pool.credential.json");
        let connection = root.join("pool.connection.json");
        let socket = root.join("missing.sock");
        let provisioning_record = root.join("provisioning.record.json");
        let provisioning_manifest = root.join("provisioning.manifest.json");
        let reviewer = root.join("reviewer.public.json");

        let mut spki_der = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        spki_der.extend(
            SigningKey::from_bytes(&[0x61; 32])
                .verifying_key()
                .to_bytes(),
        );
        let spki = base64(&spki_der);
        let mut pkcs8_der = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        pkcs8_der.extend([0x61; 32]);
        let pkcs8 = base64(&pkcs8_der);

        write(
            &identity,
            &format!(
                "{{\"version\":1,\"deviceId\":\"{DEVICE}\",\"identityPublicKey\":\"{spki}\",\"hpkePublicKey\":\"{DIGEST}\",\"managementPublicKey\":\"{spki}\",\"managementTransportPublicKey\":\"{spki}\",\"credentialEpoch\":0,\"bootKeyFingerprint\":\"{DIGEST}\",\"hardwarePolicyDigest\":\"{DIGEST}\",\"firmwareDigest\":\"{DIGEST}\",\"securityVersion\":0,\"provisioningRecordFile\":\"{}\",\"provisioningManifestFile\":\"{}\",\"reviewerPublicKeyFile\":\"{}\"}}",
                provisioning_record.display(),
                provisioning_manifest.display(),
                reviewer.display()
            ),
            0o644,
        );
        write(&provisioning_record, "{}", 0o644);
        write(&provisioning_manifest, "{}", 0o644);
        write(&reviewer, "{}", 0o644);
        write(
            &credential,
            &format!(
                "{{\"version\":1,\"algorithm\":\"Ed25519\",\"scope\":\"pool\",\"deviceId\":\"{DEVICE}\",\"poolId\":\"{credential_pool}\",\"incarnationId\":\"{INCARNATION}\",\"credentialEpoch\":0,\"publicKey\":\"{spki}\",\"privateKey\":\"{pkcs8}\"}}"
            ),
            0o600,
        );
        write(
            &connection,
            &format!(
                "{{\"version\":1,\"socketPath\":\"{}\",\"deviceId\":\"{DEVICE}\",\"deviceIdentityFile\":\"{}\",\"poolId\":\"{POOL}\",\"incarnationId\":\"{INCARNATION}\",\"networkBinding\":{{\"networkMagic\":42,\"shelleyGenesisDigest\":\"{DIGEST}\",\"slotsPerKesPeriod\":64,\"maxKesEvolutions\":64}},\"connectionName\":\"pool-0\",\"credentialFile\":\"{}\",\"securityPolicy\":\"isolated-development\"}}",
                socket.display(),
                identity.display(),
                credential.display()
            ),
            0o644,
        );
        Self {
            root,
            connection,
            socket,
        }
    }

    fn outputs(&self) -> [PathBuf; 3] {
        [
            self.root.join("kes.vkey"),
            self.root.join("kes.kes-backup"),
            self.root.join("generation.json"),
        ]
    }

    fn generation_args(&self) -> Vec<OsString> {
        let [verification, backup, generation] = self.outputs();
        [
            OsString::from("key-gen-KES"),
            OsString::from("--connection"),
            self.connection.clone().into_os_string(),
            OsString::from("--request-id"),
            OsString::from(REQUEST),
            OsString::from("--generation-number"),
            OsString::from("1"),
            OsString::from("--verification-key-file"),
            verification.into_os_string(),
            OsString::from("--encrypted-signing-key-file"),
            backup.into_os_string(),
            OsString::from("--generation-file"),
            generation.into_os_string(),
        ]
        .into()
    }

    fn fetch_args(&self, output: &Path) -> Vec<OsString> {
        [
            OsString::from("backup"),
            OsString::from("fetch"),
            OsString::from("--connection"),
            self.connection.clone().into_os_string(),
            OsString::from("--generation"),
            OsString::from(GENERATION),
            OsString::from("--out-file"),
            output.as_os_str().to_owned(),
        ]
        .into()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

fn write(path: &Path, contents: &str, mode: u32) {
    fs::write(path, contents).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn run(args: impl IntoIterator<Item = impl AsRef<OsStr>>) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kes-forge"))
        .args(args)
        .output()
        .unwrap()
}

fn base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        output.push(TABLE[((value >> 18) & 63) as usize] as char);
        output.push(TABLE[((value >> 12) & 63) as usize] as char);
        output.push(if chunk.len() > 1 {
            TABLE[((value >> 6) & 63) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            TABLE[(value & 63) as usize] as char
        } else {
            '='
        });
    }
    output
}

fn bytes<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), N * 2);
    let mut output = [0; N];
    for (index, pair) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        output[index] = (hex_digit(pair[0]) << 4) | hex_digit(pair[1]);
    }
    output
}

fn hex_digit(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("test constant is not lowercase hexadecimal"),
    }
}

fn artifact_map(pool: &[u8; 28], recipient_id: &[u8; 32], signature: Option<&[u8; 64]>) -> Vec<u8> {
    let mut storage = [0; kes_protocol::MAX_BACKUP_BYTES];
    let mut encoder = Encoder::new(&mut storage);
    encoder
        .map(if signature.is_some() { 16 } else { 15 })
        .unwrap();
    encoder.text("kdf").unwrap();
    encoder.uint(1).unwrap();
    encoder.text("kem").unwrap();
    encoder.uint(32).unwrap();
    encoder.text("aead").unwrap();
    encoder.uint(3).unwrap();
    encoder.text("pool").unwrap();
    encoder.bytes(pool).unwrap();
    encoder.text("device").unwrap();
    encoder.bytes(&bytes::<16>(DEVICE)).unwrap();
    encoder.text("period").unwrap();
    encoder.uint(0).unwrap();
    encoder.text("version").unwrap();
    encoder.uint(1).unwrap();
    encoder.text("ciphertext").unwrap();
    encoder.bytes(&[0x71; 624]).unwrap();
    encoder.text("generation").unwrap();
    encoder.bytes(&bytes::<16>(GENERATION)).unwrap();
    encoder.text("incarnation").unwrap();
    encoder.bytes(&bytes::<16>(INCARNATION)).unwrap();
    encoder.text("recipient_id").unwrap();
    encoder.bytes(recipient_id).unwrap();
    encoder.text("encapsulation").unwrap();
    encoder.bytes(&[0x73; 32]).unwrap();
    if let Some(signature) = signature {
        encoder.text("device_signature").unwrap();
        encoder.bytes(signature).unwrap();
    }
    encoder.text("verification_key").unwrap();
    encoder.bytes(&[0x74; 32]).unwrap();
    encoder.text("generation_number").unwrap();
    encoder.uint(1).unwrap();
    encoder.text("recipient_public_key").unwrap();
    encoder.bytes(&[0x75; 32]).unwrap();
    encoder.finish().unwrap().encoded().to_vec()
}

fn signed_artifact(pool: [u8; 28]) -> Vec<u8> {
    let recipient_id: [u8; 32] = Sha256::digest([0x75; 32]).into();
    signed_artifact_with_recipient(pool, recipient_id)
}

fn signed_artifact_with_recipient(pool: [u8; 28], recipient_id: [u8; 32]) -> Vec<u8> {
    let unsigned = artifact_map(&pool, &recipient_id, None);
    let mut message = Vec::with_capacity(48 + unsigned.len());
    message.extend_from_slice(b"cardano-kes-forge/backup-signature/v1");
    message.extend_from_slice(b"KESBKP01");
    message.extend_from_slice(&unsigned);
    let signature = SigningKey::from_bytes(&[0x61; 32])
        .sign(&message)
        .to_bytes();
    [
        b"KESBKP01".as_slice(),
        artifact_map(&pool, &recipient_id, Some(&signature)).as_slice(),
    ]
    .concat()
}

fn response(
    operation: Operation,
    request: [u8; 16],
    payload: impl FnOnce(&mut Encoder<'_>),
) -> Vec<u8> {
    response_status(operation, request, "OK", payload)
}

fn response_status(
    operation: Operation,
    request: [u8; 16],
    status: &str,
    payload: impl FnOnce(&mut Encoder<'_>),
) -> Vec<u8> {
    let mut storage = [0; kes_protocol::MAX_FRAME_BYTES];
    let mut encoder = Encoder::new(&mut storage);
    encoder.map(6).unwrap();
    encoder.text("op").unwrap();
    encoder.text(operation.as_str()).unwrap();
    encoder.text("status").unwrap();
    encoder.text(status).unwrap();
    encoder.text("payload").unwrap();
    payload(&mut encoder);
    encoder.text("request").unwrap();
    encoder.bytes(&request).unwrap();
    encoder.text("version").unwrap();
    encoder.uint(1).unwrap();
    encoder.text("connection").unwrap();
    encoder.text("pool-0").unwrap();
    encoder.finish().unwrap().encoded().to_vec()
}

fn generation_response(operation: Operation, request: [u8; 16], digest: [u8; 32]) -> Vec<u8> {
    response(operation, request, |encoder| {
        encoder.map(13).unwrap();
        encoder.text("health").unwrap();
        encoder.text("healthy").unwrap();
        encoder.text("revision").unwrap();
        encoder.uint(1).unwrap();
        encoder.text("lifecycle").unwrap();
        encoder.text("staged").unwrap();
        encoder.text("generation").unwrap();
        encoder.bytes(&bytes::<16>(GENERATION)).unwrap();
        encoder.text("artifact_digest").unwrap();
        encoder.bytes(&digest).unwrap();
        encoder.text("relative_period").unwrap();
        encoder.uint(0).unwrap();
        encoder.text("backup_available").unwrap();
        encoder.boolean(true).unwrap();
        encoder.text("creation_request").unwrap();
        encoder.bytes(&request).unwrap();
        encoder.text("verification_key").unwrap();
        encoder.bytes(&[0x74; 32]).unwrap();
        encoder.text("certificate_start").unwrap();
        encoder.null().unwrap();
        encoder.text("generation_number").unwrap();
        encoder.uint(1).unwrap();
        encoder.text("certificate_digest").unwrap();
        encoder.null().unwrap();
        encoder.text("certificate_counter").unwrap();
        encoder.null().unwrap();
    })
}

fn backup_response(request: [u8; 16], artifact: &[u8], digest: [u8; 32]) -> Vec<u8> {
    response(Operation::GetBackup, request, |encoder| {
        encoder.map(3).unwrap();
        encoder.text("backup").unwrap();
        encoder.bytes(artifact).unwrap();
        encoder.text("generation").unwrap();
        encoder.bytes(&bytes::<16>(GENERATION)).unwrap();
        encoder.text("artifact_digest").unwrap();
        encoder.bytes(&digest).unwrap();
    })
}

fn read_request(stream: &mut std::os::unix::net::UnixStream) -> (Operation, [u8; 16]) {
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix).unwrap();
    let length = u32::from_be_bytes(prefix) as usize;
    assert!(length <= kes_protocol::MAX_FRAME_BYTES);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).unwrap();
    let request = Envelope::parse(&body, EnvelopeKind::LocalRequest).unwrap();
    let mut target = request.map().required("target").unwrap().array().unwrap();
    assert_eq!(target.next().unwrap().bytes().unwrap(), bytes::<16>(DEVICE));
    assert_eq!(target.next().unwrap().bytes().unwrap(), bytes::<28>(POOL));
    assert_eq!(
        target.next().unwrap().bytes().unwrap(),
        bytes::<16>(INCARNATION)
    );
    assert!(target.next().is_none());
    (request.operation, *request.request().unwrap().as_bytes())
}

fn send_response(mut stream: std::os::unix::net::UnixStream, body: &[u8]) {
    stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(body).unwrap();
}

fn send_initial_status(listener: &UnixListener) {
    let (mut stream, _) = listener.accept().unwrap();
    let (operation, request) = read_request(&mut stream);
    assert_eq!(operation, Operation::Status);
    let status = response(Operation::Status, request, |e| {
        e.map(9).unwrap();
        e.text("active").unwrap();
        e.null().unwrap();
        e.text("health").unwrap();
        e.text("healthy").unwrap();
        e.text("staged").unwrap();
        e.null().unwrap();
        e.text("revoked").unwrap();
        e.boolean(false).unwrap();
        e.text("revision").unwrap();
        e.uint(0).unwrap();
        e.text("directory").unwrap();
        e.array(0).unwrap();
        e.text("security_mode").unwrap();
        e.text("development").unwrap();
        e.text("blocking_reason").unwrap();
        e.text("fixture").unwrap();
        e.text("credential_epoch").unwrap();
        e.uint(0).unwrap();
    });
    send_response(stream, &status);
}

fn spawn_generation_service(
    fixture: &Fixture,
    artifact_pool: [u8; 28],
) -> (Vec<u8>, thread::JoinHandle<()>) {
    spawn_generation_artifact_service(fixture, signed_artifact(artifact_pool))
}

fn spawn_generation_artifact_service(
    fixture: &Fixture,
    artifact: Vec<u8>,
) -> (Vec<u8>, thread::JoinHandle<()>) {
    let listener = UnixListener::bind(&fixture.socket).unwrap();
    let service_artifact = artifact.clone();
    let handle = thread::spawn(move || {
        send_initial_status(&listener);
        let (mut generate, _) = listener.accept().unwrap();
        let (operation, request) = read_request(&mut generate);
        assert_eq!(operation, Operation::Generate);
        let digest: [u8; 32] = Sha256::digest(&service_artifact).into();
        send_response(
            generate,
            &generation_response(Operation::Generate, request, digest),
        );

        let (mut fetch, _) = listener.accept().unwrap();
        let (operation, request) = read_request(&mut fetch);
        assert_eq!(operation, Operation::GetBackup);
        send_response(fetch, &backup_response(request, &service_artifact, digest));
    });
    (artifact, handle)
}

fn spawn_fetch_service(fixture: &Fixture, artifact: Vec<u8>) -> thread::JoinHandle<()> {
    let listener = UnixListener::bind(&fixture.socket).unwrap();
    thread::spawn(move || {
        let (mut fetch, _) = listener.accept().unwrap();
        let (operation, request) = read_request(&mut fetch);
        assert_eq!(operation, Operation::GetBackup);
        let digest: [u8; 32] = Sha256::digest(&artifact).into();
        send_response(fetch, &backup_response(request, &artifact, digest));
    })
}

fn spawn_status_service(fixture: &Fixture, artifact: Vec<u8>) -> thread::JoinHandle<()> {
    let listener = UnixListener::bind(&fixture.socket).unwrap();
    thread::spawn(move || {
        let (mut status, _) = listener.accept().unwrap();
        let (operation, request) = read_request(&mut status);
        assert_eq!(operation, Operation::OpStatus);
        let digest: [u8; 32] = Sha256::digest(&artifact).into();
        send_response(
            status,
            &generation_response(Operation::OpStatus, request, digest),
        );

        let (mut fetch, _) = listener.accept().unwrap();
        let (operation, request) = read_request(&mut fetch);
        assert_eq!(operation, Operation::GetBackup);
        send_response(fetch, &backup_response(request, &artifact, digest));
    })
}

fn spawn_reconciliation_service(fixture: &Fixture) -> (Vec<u8>, thread::JoinHandle<()>) {
    let listener = UnixListener::bind(&fixture.socket).unwrap();
    let artifact = signed_artifact(bytes(POOL));
    let service_artifact = artifact.clone();
    let handle = thread::spawn(move || {
        send_initial_status(&listener);
        let (mut generate, _) = listener.accept().unwrap();
        let (operation, _) = read_request(&mut generate);
        assert_eq!(operation, Operation::Generate);
        drop(generate);

        let (mut status, _) = listener.accept().unwrap();
        let (operation, request) = read_request(&mut status);
        assert_eq!(operation, Operation::OpStatus);
        let digest: [u8; 32] = Sha256::digest(&service_artifact).into();
        send_response(
            status,
            &generation_response(Operation::OpStatus, request, digest),
        );

        let (mut fetch, _) = listener.accept().unwrap();
        let (operation, request) = read_request(&mut fetch);
        assert_eq!(operation, Operation::GetBackup);
        send_response(fetch, &backup_response(request, &service_artifact, digest));
    });
    (artifact, handle)
}

#[test]
fn exact_device_generation_surface_reaches_the_configured_service() {
    let fixture = Fixture::new(POOL);
    let output = run(fixture.generation_args());
    assert_eq!(output.status.code(), Some(5));
    assert!(fixture.outputs().iter().all(|path| !path.exists()));
}

#[test]
fn lost_generation_response_reconciles_by_durable_request_identity() {
    let fixture = Fixture::new(POOL);
    let (artifact, service) = spawn_reconciliation_service(&fixture);
    assert_eq!(run(fixture.generation_args()).status.code(), Some(0));
    service.join().unwrap();
    fs::remove_file(&fixture.socket).unwrap();
    let [verification, backup, generation] = fixture.outputs();
    assert!(verification.exists());
    assert_eq!(fs::read(backup).unwrap(), artifact);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(generation).unwrap()).unwrap();
    assert_eq!(manifest["requestId"], REQUEST);
    assert_eq!(manifest["generationId"], GENERATION);
}

#[test]
fn generation_publishes_decoded_identity_and_repairs_exact_partial_outputs() {
    let fixture = Fixture::new(POOL);
    fs::remove_file(fixture.root.join("pool.credential.json")).unwrap();
    let (artifact, service) = spawn_generation_service(&fixture, bytes(POOL));
    assert_eq!(run(fixture.generation_args()).status.code(), Some(0));
    service.join().unwrap();
    fs::remove_file(&fixture.socket).unwrap();

    let [verification, backup, generation] = fixture.outputs();
    let verification_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&verification).unwrap()).unwrap();
    assert_eq!(
        verification_json["type"],
        "KesVerificationKey_ed25519_kes_2^6"
    );
    assert_eq!(
        verification_json["cborHex"],
        format!("5820{}", "74".repeat(32))
    );
    assert_eq!(fs::read(&backup).unwrap(), artifact);
    let generation_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&generation).unwrap()).unwrap();
    assert_eq!(generation_json["requestId"], REQUEST);
    assert_eq!(generation_json["deviceId"], DEVICE);
    assert_eq!(generation_json["poolId"], POOL);
    assert_eq!(generation_json["generationId"], GENERATION);
    assert_eq!(generation_json["generationNumber"], 1);
    let verification_digest = format!("{:x}", Sha256::digest(fs::read(&verification).unwrap()));
    let backup_digest = format!("{:x}", Sha256::digest(fs::read(&backup).unwrap()));
    assert_eq!(
        generation_json["outputs"]["verificationKeySha256"],
        verification_digest
    );
    assert_eq!(
        generation_json["outputs"]["encryptedSigningKeySha256"],
        backup_digest
    );
    assert_eq!(
        generation_json["outputs"]["encryptedSigningKeyDescription"],
        "Device-generated KES state encrypted to the enrolled recovery recipient; not a plaintext signing key"
    );
    let operation_file = generation.with_extension("operation.json");
    let operation_json: serde_json::Value =
        serde_json::from_slice(&fs::read(operation_file).unwrap()).unwrap();
    assert_eq!(operation_json["state"], "COMMITTED");
    assert_eq!(operation_json["requestId"], REQUEST);

    let expected_verification = fs::read(&verification).unwrap();
    fs::remove_file(&backup).unwrap();
    fs::remove_file(&generation).unwrap();
    let retry_service = spawn_status_service(&fixture, artifact.clone());
    assert_eq!(run(fixture.generation_args()).status.code(), Some(0));
    retry_service.join().unwrap();
    fs::remove_file(&fixture.socket).unwrap();
    assert_eq!(fs::read(&verification).unwrap(), expected_verification);
    assert_eq!(fs::read(&backup).unwrap(), artifact);

    let fetched = fixture.root.join("fetched.kes-backup");
    let fetch_service = spawn_fetch_service(&fixture, artifact.clone());
    assert_eq!(run(fixture.fetch_args(&fetched)).status.code(), Some(0));
    fetch_service.join().unwrap();
    fs::remove_file(&fixture.socket).unwrap();
    assert_eq!(fs::read(fetched).unwrap(), artifact);
}

#[test]
fn unrelated_existing_output_is_rejected_before_any_missing_output_is_created() {
    let fixture = Fixture::new(POOL);
    let [verification, backup, generation] = fixture.outputs();
    write(&backup, "unrelated-existing-output", 0o600);
    assert_eq!(run(fixture.generation_args()).status.code(), Some(7));
    assert!(!verification.exists());
    assert!(!generation.exists());
    assert_eq!(fs::read(backup).unwrap(), b"unrelated-existing-output");
}

#[test]
fn signed_artifact_with_wrong_pool_is_rejected_before_publication() {
    let fixture = Fixture::new(POOL);
    let (_, service) = spawn_generation_service(&fixture, bytes(OTHER_POOL));
    assert_eq!(run(fixture.generation_args()).status.code(), Some(6));
    service.join().unwrap();
    fs::remove_file(&fixture.socket).unwrap();
    assert!(fixture.outputs().iter().all(|path| !path.exists()));
}

#[test]
fn signed_artifact_with_wrong_recipient_identity_is_rejected_before_publication() {
    let fixture = Fixture::new(POOL);
    let artifact = signed_artifact_with_recipient(bytes(POOL), [0x76; 32]);
    let (_, service) = spawn_generation_artifact_service(&fixture, artifact);
    assert_eq!(run(fixture.generation_args()).status.code(), Some(6));
    service.join().unwrap();
    fs::remove_file(&fixture.socket).unwrap();
    assert!(fixture.outputs().iter().all(|path| !path.exists()));
}

#[test]
fn exact_backup_fetch_surface_reaches_the_configured_service() {
    let fixture = Fixture::new(POOL);
    let backup = fixture.root.join("fetched.kes-backup");
    assert_eq!(run(fixture.fetch_args(&backup)).status.code(), Some(5));
    assert!(!backup.exists());

    write(&backup, "unrelated-existing-output", 0o600);
    assert_eq!(run(fixture.fetch_args(&backup)).status.code(), Some(7));
    assert_eq!(fs::read(&backup).unwrap(), b"unrelated-existing-output");
}

#[test]
fn host_generation_aliases_and_plaintext_output_are_rejected_as_usage() {
    let fixture = Fixture::new(POOL);
    let exact = fixture.generation_args();
    for forbidden in [
        vec![OsString::from("node"), OsString::from("key-gen-KES")],
        vec![OsString::from("babbage"), OsString::from("key-gen-KES")],
        vec![OsString::from("key-gen-kes")],
        {
            let mut args = exact.clone();
            args.extend([
                OsString::from("--signing-key-file"),
                fixture.root.join("kes.skey").into_os_string(),
            ]);
            args
        },
        {
            let mut args = exact.clone();
            args.push(OsString::from("--software-fallback"));
            args
        },
    ] {
        assert_eq!(run(forbidden).status.code(), Some(2));
    }
    assert_eq!(
        run(vec![OsString::from("backup"), OsString::from("recover")])
            .status
            .code(),
        Some(2)
    );
}

#[test]
fn pool_binding_mismatch_is_an_authentication_error_before_dispatch() {
    struct RefuseDevice(Arc<AtomicUsize>);
    impl DeviceWire for RefuseDevice {
        fn exchange(
            &mut self,
            _request: &[u8],
            _response: &mut [u8; kes_protocol::MAX_FRAME_BYTES],
            _timeout: Duration,
        ) -> Result<usize, ClientError> {
            self.0.fetch_add(1, Ordering::AcqRel);
            Err(ClientError::Unavailable)
        }
    }
    let fixture = Fixture::new(POOL);
    let pool = PoolConnection::load(&fixture.connection).unwrap();
    let credential = PoolConnection::load(&fixture.connection)
        .unwrap()
        .credential;
    let management = DeviceConfig {
        socket_path: fixture.socket.clone(),
        device_id: bytes(DEVICE),
        device_identity_file: fixture.root.join("device.identity.json"),
        connection_name: "management".to_owned(),
        credential_file: fixture.root.join("pool.credential.json"),
        credential,
        identity: DeviceIdentity::load(&fixture.root.join("device.identity.json")).unwrap(),
        security_policy: "isolated-development".to_owned(),
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let transport =
        AuthenticatedTransport::new(RefuseDevice(Arc::clone(&calls)), management, vec![pool])
            .unwrap();
    let daemon = Daemon::new(
        Config {
            management_connection: "management".to_owned(),
            pool_connections: vec!["pool-0".to_owned()],
            allowed_peer_uids: vec![(
                rustix::process::getuid().as_raw(),
                vec!["pool-0".to_owned()],
            )],
        },
        transport,
    )
    .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let socket = fixture.socket.clone();
    let server = thread::spawn(move || daemon.serve_until(&socket, &thread_stop).unwrap());
    let deadline = Instant::now() + Duration::from_secs(2);
    while !fixture.socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not bind");
        thread::sleep(Duration::from_millis(5));
    }
    fs::remove_file(fixture.root.join("pool.credential.json")).unwrap();
    let original: serde_json::Value =
        serde_json::from_slice(&fs::read(&fixture.connection).unwrap()).unwrap();
    for (field, wrong) in [
        ("poolId", OTHER_POOL),
        ("deviceId", "11111111111111111111111111111111"),
        ("incarnationId", "31313131313131313131313131313131"),
    ] {
        let mut config = original.clone();
        config[field] = wrong.into();
        write(
            &fixture.connection,
            &serde_json::to_string(&config).unwrap(),
            0o644,
        );
        let mut args = fixture.generation_args();
        *args.last_mut().unwrap() = fixture.root.join(format!("{field}.json")).into_os_string();
        assert_eq!(run(args).status.code(), Some(3));
        assert_eq!(calls.load(Ordering::Acquire), 0);
        assert!(fixture.outputs().iter().all(|path| !path.exists()));
    }
    // These valid socket requests exercise device and scope refusal against
    // the daemon's actual configured pins, not public-file consistency checks.
    for (device, pool, incarnation, status) in [
        (
            [0x11; 16],
            Some(bytes::<28>(POOL)),
            Some(bytes::<16>(INCARNATION)),
            kes_protocol::Status::WrongDevice,
        ),
        (
            bytes::<16>(DEVICE),
            None,
            None,
            kes_protocol::Status::WrongPool,
        ),
    ] {
        let mut storage = [0; kes_protocol::MAX_FRAME_BYTES];
        let mut encoder = Encoder::new(&mut storage);
        encoder.map(7).unwrap();
        encoder.text("op").unwrap();
        encoder.text("STATUS").unwrap();
        encoder.text("target").unwrap();
        encoder.array(3).unwrap();
        encoder.bytes(&device).unwrap();
        match pool {
            Some(id) => encoder.bytes(&id).unwrap(),
            None => encoder.null().unwrap(),
        }
        match incarnation {
            Some(id) => encoder.bytes(&id).unwrap(),
            None => encoder.null().unwrap(),
        }
        encoder.text("payload").unwrap();
        encoder.map(0).unwrap();
        encoder.text("request").unwrap();
        encoder.bytes(&bytes::<16>(REQUEST)).unwrap();
        encoder.text("version").unwrap();
        encoder.uint(1).unwrap();
        encoder.text("budget_ms").unwrap();
        encoder.uint(2000).unwrap();
        encoder.text("connection").unwrap();
        encoder.text("pool-0").unwrap();
        let encoded = encoder.finish().unwrap().encoded();
        let mut stream = std::os::unix::net::UnixStream::connect(&fixture.socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .write_all(&(encoded.len() as u32).to_be_bytes())
            .unwrap();
        stream.write_all(encoded).unwrap();
        let mut prefix = [0; 4];
        stream.read_exact(&mut prefix).unwrap();
        let length = u32::from_be_bytes(prefix) as usize;
        assert!(length <= storage.len());
        stream.read_exact(&mut storage[..length]).unwrap();
        assert_eq!(
            Envelope::parse(&storage[..length], EnvelopeKind::LocalResponse)
                .unwrap()
                .status,
            Some(status)
        );
        assert_eq!(calls.load(Ordering::Acquire), 0);
    }
    // A matching target reaches the real transport even though no private file
    // remains available to the CLI; the deliberately refusing wire stays failed.
    write(
        &fixture.connection,
        &serde_json::to_string(&original).unwrap(),
        0o644,
    );
    assert_eq!(run(fixture.generation_args()).status.code(), Some(5));
    assert!(calls.load(Ordering::Acquire) > 0);
    stop.store(true, Ordering::Release);
    server.join().unwrap();
}

#[test]
fn every_preexisting_generation_output_is_preserved_without_dispatch() {
    for collision in 0..3 {
        let fixture = Fixture::new(POOL);
        let outputs = fixture.outputs();
        write(&outputs[collision], "unrelated-existing-output", 0o600);
        let output = run(fixture.generation_args());
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(
            fs::read(&outputs[collision]).unwrap(),
            b"unrelated-existing-output"
        );
        for (index, path) in outputs.iter().enumerate() {
            if index != collision {
                assert!(!path.exists());
            }
        }
    }
}

#[test]
fn generation_json_reports_pending_without_publishing_outputs() {
    let fixture = Fixture::new(POOL);
    let listener = UnixListener::bind(&fixture.socket).unwrap();
    let service = thread::spawn(move || {
        send_initial_status(&listener);
        let (mut stream, _) = listener.accept().unwrap();
        let (operation, request) = read_request(&mut stream);
        assert_eq!(operation, Operation::Generate);
        let reply = response_status(operation, request, "IN_PROGRESS", |encoder| {
            encoder.map(2).unwrap();
            encoder.text("request").unwrap();
            encoder.bytes(&request).unwrap();
            encoder.text("generation_number").unwrap();
            encoder.uint(1).unwrap();
        });
        send_response(stream, &reply);
        let (mut stream, _) = listener.accept().unwrap();
        let (operation, request) = read_request(&mut stream);
        assert_eq!(operation, Operation::OpStatus);
        let reply = response_status(operation, request, "IN_PROGRESS", |encoder| {
            encoder.map(2).unwrap();
            encoder.text("request").unwrap();
            encoder.bytes(&request).unwrap();
            encoder.text("generation_number").unwrap();
            encoder.uint(1).unwrap();
        });
        send_response(stream, &reply);
    });
    let mut args = fixture.generation_args();
    args.push("--json".into());
    let output = run(args);
    service.join().unwrap();
    assert_eq!(output.status.code(), Some(4));
    let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["code"], "IN_PROGRESS");
    assert_eq!(error["requestId"], REQUEST);
    assert_eq!(error["deviceId"], DEVICE);
    assert_eq!(error["poolId"], POOL);
    assert!(output.stdout.is_empty());
    assert!(fixture.outputs().iter().all(|path| !path.exists()));
}

#[test]
fn generation_json_success_binds_committed_public_result() {
    let fixture = Fixture::new(POOL);
    let (_, service) = spawn_generation_service(&fixture, bytes::<28>(POOL));
    let mut args = fixture.generation_args();
    args.push("--json".into());
    let output = run(args);
    service.join().unwrap();
    assert!(output.status.success());
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["operation"], "GENERATE");
    assert_eq!(result["requestId"], REQUEST);
    assert_eq!(result["deviceId"], DEVICE);
    assert_eq!(result["poolId"], POOL);
    assert_eq!(result["generationId"], GENERATION);
    assert_eq!(result["revision"], 1);
    assert!(fixture.outputs().iter().all(|path| path.exists()));
}
