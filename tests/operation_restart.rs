use cardano_kes_forge::host::{
    client::{BackupResult, GenerationResult},
    config::PublicPoolConnection,
    operations::{Error as OperationError, OperationRecord, State},
    publication::{self, GenerationOutput, PublicationFault},
};
use ed25519_dalek::{Signer, SigningKey};
use kes_core::cbor::Encoder;
use kes_protocol::{Envelope, EnvelopeKind, Operation, Status};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;

const DEVICE: [u8; 16] = [0x10; 16];
const POOL: [u8; 28] = [0x20; 28];
const INCARNATION: [u8; 16] = [0x30; 16];
const REQUEST: [u8; 16] = [0x40; 16];
const DIGEST: [u8; 32] = [0x50; 32];
const GENERATION: [u8; 16] = [0x60; 16];
const CONNECTION: &str = "pool-0";

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    connection: PathBuf,
    socket: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "kes-operation-restart-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let identity = root.join("device.identity.json");
        let credential = root.join("pool.credential.json");
        let connection = root.join("pool.connection.json");
        let socket = root.join("daemon.sock");
        let provisioning_record = root.join("provisioning.record.json");
        let provisioning_manifest = root.join("provisioning.manifest.json");
        let reviewer = root.join("reviewer.public.json");

        let signing = SigningKey::from_bytes(&[0x61; 32]);
        let mut spki_der = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        spki_der.extend(signing.verifying_key().to_bytes());
        let spki = base64(&spki_der);
        write_mode(
            &identity,
            &format!(
                "{{\"version\":1,\"deviceId\":\"{}\",\"identityPublicKey\":\"{spki}\",\"hpkePublicKey\":\"{}\",\"managementPublicKey\":\"{spki}\",\"managementTransportPublicKey\":\"{spki}\",\"credentialEpoch\":0,\"bootKeyFingerprint\":\"{}\",\"hardwarePolicyDigest\":\"{}\",\"firmwareDigest\":\"{}\",\"securityVersion\":0,\"provisioningRecordFile\":\"{}\",\"provisioningManifestFile\":\"{}\",\"reviewerPublicKeyFile\":\"{}\"}}",
                hex(&DEVICE),
                hex(&DIGEST),
                hex(&DIGEST),
                hex(&DIGEST),
                hex(&DIGEST),
                provisioning_record.display(),
                provisioning_manifest.display(),
                reviewer.display()
            ),
            0o644,
        );
        write_mode(&provisioning_record, "{}", 0o644);
        write_mode(&provisioning_manifest, "{}", 0o644);
        write_mode(&reviewer, "{}", 0o644);
        // Operator processes have no daemon transport credential on disk.
        assert!(!credential.exists());
        write_mode(
            &connection,
            &format!(
                "{{\"version\":1,\"socketPath\":\"{}\",\"deviceId\":\"{}\",\"deviceIdentityFile\":\"{}\",\"poolId\":\"{}\",\"incarnationId\":\"{}\",\"networkBinding\":{{\"networkMagic\":42,\"shelleyGenesisDigest\":\"{}\",\"slotsPerKesPeriod\":64,\"maxKesEvolutions\":64}},\"connectionName\":\"{CONNECTION}\",\"credentialFile\":\"{}\",\"securityPolicy\":\"isolated-development\"}}",
                socket.display(),
                hex(&DEVICE),
                identity.display(),
                hex(&POOL),
                hex(&INCARNATION),
                hex(&DIGEST),
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

    fn outputs(&self, prefix: &str) -> [PathBuf; 3] {
        [
            self.root.join(format!("{prefix}.vkey")),
            self.root.join(format!("{prefix}.kes-backup")),
            self.root.join(format!("{prefix}.generation.json")),
        ]
    }

    fn generation_args(&self, generation_number: u64, prefix: &str) -> Vec<String> {
        let [verification, backup, generation] = self.outputs(prefix);
        vec![
            "key-gen-KES".into(),
            "--connection".into(),
            self.connection.display().to_string(),
            "--request-id".into(),
            hex(&REQUEST),
            "--generation-number".into(),
            generation_number.to_string(),
            "--verification-key-file".into(),
            verification.display().to_string(),
            "--encrypted-signing-key-file".into(),
            backup.display().to_string(),
            "--generation-file".into(),
            generation.display().to_string(),
        ]
    }

    fn operation(&self, prefix: &str) -> PathBuf {
        self.root
            .join(format!("{prefix}.generation.operation.json"))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn write_mode(path: &Path, contents: &str, mode: u32) {
    fs::write(path, contents).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn spawn_client(args: &[String]) -> Child {
    Command::new(env!("CARGO_BIN_EXE_kes-forge"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

fn run_client(args: &[String]) -> std::process::ExitStatus {
    Command::new(env!("CARGO_BIN_EXE_kes-forge"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
}

fn read_request(stream: &mut UnixStream) -> (Operation, [u8; 16]) {
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix).unwrap();
    let mut body = vec![0; u32::from_be_bytes(prefix) as usize];
    stream.read_exact(&mut body).unwrap();
    let request = Envelope::parse(&body, EnvelopeKind::LocalRequest).unwrap();
    (request.operation, *request.request().unwrap().as_bytes())
}

fn send_response(mut stream: UnixStream, body: &[u8]) {
    stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(body).unwrap();
}

fn response(
    operation: Operation,
    request: [u8; 16],
    status: Status,
    payload: impl FnOnce(&mut Encoder<'_>),
) -> Vec<u8> {
    let mut storage = [0; kes_protocol::MAX_FRAME_BYTES];
    let mut encoder = Encoder::new(&mut storage);
    encoder.map(6).unwrap();
    encoder.text("op").unwrap();
    encoder.text(operation.as_str()).unwrap();
    encoder.text("status").unwrap();
    encoder.text(status.as_str()).unwrap();
    encoder.text("payload").unwrap();
    payload(&mut encoder);
    encoder.text("request").unwrap();
    encoder.bytes(&request).unwrap();
    encoder.text("version").unwrap();
    encoder.uint(1).unwrap();
    encoder.text("connection").unwrap();
    encoder.text(CONNECTION).unwrap();
    encoder.finish().unwrap().encoded().to_vec()
}

fn generation_response(operation: Operation, request: [u8; 16], digest: [u8; 32]) -> Vec<u8> {
    response(operation, request, Status::Ok, |encoder| {
        encoder.map(13).unwrap();
        encoder.text("health").unwrap();
        encoder.text("healthy").unwrap();
        encoder.text("revision").unwrap();
        encoder.uint(1).unwrap();
        encoder.text("lifecycle").unwrap();
        encoder.text("staged").unwrap();
        encoder.text("generation").unwrap();
        encoder.bytes(&GENERATION).unwrap();
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
    response(Operation::GetBackup, request, Status::Ok, |encoder| {
        encoder.map(3).unwrap();
        encoder.text("backup").unwrap();
        encoder.bytes(artifact).unwrap();
        encoder.text("generation").unwrap();
        encoder.bytes(&GENERATION).unwrap();
        encoder.text("artifact_digest").unwrap();
        encoder.bytes(&digest).unwrap();
    })
}

fn status_response(request: [u8; 16]) -> Vec<u8> {
    response(Operation::Status, request, Status::Ok, |encoder| {
        encoder.map(9).unwrap();
        encoder.text("active").unwrap();
        encoder.null().unwrap();
        encoder.text("health").unwrap();
        encoder.text("healthy").unwrap();
        encoder.text("staged").unwrap();
        encoder.null().unwrap();
        encoder.text("revoked").unwrap();
        encoder.boolean(false).unwrap();
        encoder.text("revision").unwrap();
        encoder.uint(1).unwrap();
        encoder.text("directory").unwrap();
        encoder.array(0).unwrap();
        encoder.text("security_mode").unwrap();
        encoder.text("development").unwrap();
        encoder.text("blocking_reason").unwrap();
        encoder.text("fixture").unwrap();
        encoder.text("credential_epoch").unwrap();
        encoder.uint(0).unwrap();
    })
}

fn serve_initial_status(listener: &UnixListener) {
    let (mut stream, _) = listener.accept().unwrap();
    let (operation, request) = read_request(&mut stream);
    assert_eq!(operation, Operation::Status);
    send_response(stream, &status_response(request));
}

fn reclaimed_response(request: [u8; 16]) -> Vec<u8> {
    response(
        Operation::OpStatus,
        request,
        Status::ResultReclaimed,
        |encoder| {
            encoder.map(2).unwrap();
            encoder.text("request").unwrap();
            encoder.bytes(&REQUEST).unwrap();
            encoder.text("generation_number").unwrap();
            encoder.uint(1).unwrap();
        },
    )
}

fn artifact_map(signature: Option<&[u8; 64]>) -> Vec<u8> {
    let recipient_id: [u8; 32] = Sha256::digest([0x75; 32]).into();
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
    encoder.bytes(&POOL).unwrap();
    encoder.text("device").unwrap();
    encoder.bytes(&DEVICE).unwrap();
    encoder.text("period").unwrap();
    encoder.uint(0).unwrap();
    encoder.text("version").unwrap();
    encoder.uint(1).unwrap();
    encoder.text("ciphertext").unwrap();
    encoder.bytes(&[0x71; 624]).unwrap();
    encoder.text("generation").unwrap();
    encoder.bytes(&GENERATION).unwrap();
    encoder.text("incarnation").unwrap();
    encoder.bytes(&INCARNATION).unwrap();
    encoder.text("recipient_id").unwrap();
    encoder.bytes(&recipient_id).unwrap();
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

fn signed_artifact() -> Vec<u8> {
    let unsigned = artifact_map(None);
    let mut message = Vec::with_capacity(48 + unsigned.len());
    message.extend_from_slice(b"cardano-kes-forge/backup-signature/v1");
    message.extend_from_slice(b"KESBKP01");
    message.extend_from_slice(&unsigned);
    let signature = SigningKey::from_bytes(&[0x61; 32])
        .sign(&message)
        .to_bytes();
    [
        b"KESBKP01".as_slice(),
        artifact_map(Some(&signature)).as_slice(),
    ]
    .concat()
}

#[test]
fn killed_after_dispatch_reconciles_without_replay_and_rejects_changed_payload() {
    let fixture = Fixture::new();
    let artifact = signed_artifact();
    let digest: [u8; 32] = Sha256::digest(&artifact).into();
    let listener = UnixListener::bind(&fixture.socket).unwrap();
    let (dispatched_tx, dispatched_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let server_artifact = artifact.clone();
    let server = thread::spawn(move || {
        serve_initial_status(&listener);
        let (mut generate, _) = listener.accept().unwrap();
        assert_eq!(read_request(&mut generate), (Operation::Generate, REQUEST));
        dispatched_tx.send(()).unwrap();
        resume_rx.recv().unwrap();
        drop(generate);

        let (mut status, _) = listener.accept().unwrap();
        assert_eq!(read_request(&mut status), (Operation::OpStatus, REQUEST));
        send_response(
            status,
            &generation_response(Operation::OpStatus, REQUEST, digest),
        );
        let (mut fetch, _) = listener.accept().unwrap();
        let (operation, request) = read_request(&mut fetch);
        assert_eq!(operation, Operation::GetBackup);
        send_response(fetch, &backup_response(request, &server_artifact, digest));
    });

    let args = fixture.generation_args(1, "dispatch");
    let mut first = spawn_client(&args);
    dispatched_rx.recv().unwrap();
    first.kill().unwrap();
    assert!(!first.wait().unwrap().success());

    let changed = fixture.generation_args(2, "dispatch");
    assert_eq!(run_client(&changed).code(), Some(4));
    let pending = OperationRecord::load(&fixture.operation("dispatch")).unwrap();
    assert!(matches!(
        OperationRecord::begin(
            &fixture.operation("dispatch"),
            "GENERATE",
            pending.identity(),
            b"changed-canonical-payload",
        ),
        Err(OperationError::Conflict)
    ));
    resume_tx.send(()).unwrap();
    assert!(run_client(&args).success());
    server.join().unwrap();

    let operation = OperationRecord::load(&fixture.operation("dispatch")).unwrap();
    assert_eq!(operation.state(), State::Committed);
    assert_eq!(operation.identity().request, REQUEST);
    assert_eq!(operation.committed_generation(), Some(GENERATION));
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.outputs("dispatch")[2].clone()).unwrap()).unwrap();
    assert_eq!(manifest["requestId"], hex(&REQUEST));
    assert_eq!(manifest["generationId"], hex(&GENERATION));
}

#[test]
fn killed_after_device_commit_reconciles_status_and_completes_publication() {
    let fixture = Fixture::new();
    let artifact = signed_artifact();
    let digest: [u8; 32] = Sha256::digest(&artifact).into();
    let listener = UnixListener::bind(&fixture.socket).unwrap();
    let (committed_tx, committed_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let server_artifact = artifact.clone();
    let server = thread::spawn(move || {
        serve_initial_status(&listener);
        let (mut generate, _) = listener.accept().unwrap();
        assert_eq!(read_request(&mut generate), (Operation::Generate, REQUEST));
        send_response(
            generate,
            &generation_response(Operation::Generate, REQUEST, digest),
        );
        let (mut fetch, _) = listener.accept().unwrap();
        assert_eq!(read_request(&mut fetch).0, Operation::GetBackup);
        committed_tx.send(()).unwrap();
        resume_rx.recv().unwrap();
        drop(fetch);

        let (mut status, _) = listener.accept().unwrap();
        assert_eq!(read_request(&mut status), (Operation::OpStatus, REQUEST));
        send_response(
            status,
            &generation_response(Operation::OpStatus, REQUEST, digest),
        );
        let (mut retry_fetch, _) = listener.accept().unwrap();
        let (operation, request) = read_request(&mut retry_fetch);
        assert_eq!(operation, Operation::GetBackup);
        send_response(
            retry_fetch,
            &backup_response(request, &server_artifact, digest),
        );
    });

    let args = fixture.generation_args(1, "commit");
    let mut first = spawn_client(&args);
    committed_rx.recv().unwrap();
    let durable = OperationRecord::load(&fixture.operation("commit")).unwrap();
    assert_eq!(durable.state(), State::Committed);
    assert_eq!(durable.committed_generation(), Some(GENERATION));
    first.kill().unwrap();
    assert!(!first.wait().unwrap().success());
    assert!(fixture.outputs("commit").iter().all(|path| !path.exists()));

    resume_tx.send(()).unwrap();
    assert!(run_client(&args).success());
    server.join().unwrap();
    assert!(fixture.outputs("commit").iter().all(|path| path.exists()));
}

#[test]
fn authoritative_result_reclaimed_is_terminal_across_client_restarts() {
    let fixture = Fixture::new();
    let listener = UnixListener::bind(&fixture.socket).unwrap();
    let (dispatched_tx, dispatched_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        serve_initial_status(&listener);
        let (mut generate, _) = listener.accept().unwrap();
        assert_eq!(read_request(&mut generate), (Operation::Generate, REQUEST));
        dispatched_tx.send(()).unwrap();
        resume_rx.recv().unwrap();
        drop(generate);
        let (mut status, _) = listener.accept().unwrap();
        assert_eq!(read_request(&mut status), (Operation::OpStatus, REQUEST));
        send_response(status, &reclaimed_response(REQUEST));
    });

    let args = fixture.generation_args(1, "reclaimed");
    let mut first = spawn_client(&args);
    dispatched_rx.recv().unwrap();
    first.kill().unwrap();
    first.wait().unwrap();
    resume_tx.send(()).unwrap();
    assert_eq!(run_client(&args).code(), Some(4));
    server.join().unwrap();
    let record = OperationRecord::load(&fixture.operation("reclaimed")).unwrap();
    assert_eq!(record.state(), State::ResultReclaimed);
    assert_eq!(run_client(&args).code(), Some(4));
}

struct AbortAfter(GenerationOutput);

impl PublicationFault for AbortAfter {
    fn after_link(&self, output: GenerationOutput) -> Result<(), publication::Error> {
        if output == self.0 {
            std::process::abort();
        }
        Ok(())
    }
}

fn publish_fixture(root: &Path, boundary: Option<GenerationOutput>, prefix: &str) {
    let connection = PublicPoolConnection::load(&root.join("pool.connection.json")).unwrap();
    let artifact = signed_artifact();
    let digest: [u8; 32] = Sha256::digest(&artifact).into();
    let result = GenerationResult {
        generation: GENERATION,
        generation_number: 1,
        creation_request: REQUEST,
        verification_key: [0x74; 32],
        artifact_digest: digest,
        revision: 1,
    };
    let backup = BackupResult {
        generation: GENERATION,
        backup: artifact,
        artifact_digest: digest,
    };
    let prefix = match boundary {
        Some(GenerationOutput::VerificationKey) => "link-vkey",
        Some(GenerationOutput::EncryptedSigningKey) => "link-backup",
        None => prefix,
    };
    let verification = root.join(format!("{prefix}.vkey"));
    let encrypted = root.join(format!("{prefix}.kes-backup"));
    let manifest = root.join(format!("{prefix}.generation.json"));
    match boundary {
        Some(output) => {
            let _ = publication::publish_generation_with(
                &connection,
                REQUEST,
                &result,
                &backup,
                publication::GenerationFiles {
                    verification_key: &verification,
                    encrypted_signing_key: &encrypted,
                    manifest: &manifest,
                },
                &AbortAfter(output),
            );
        }
        None => publication::publish_generation(
            &connection,
            REQUEST,
            &result,
            &backup,
            &verification,
            &encrypted,
            &manifest,
        )
        .unwrap(),
    }
}

#[test]
fn publication_crash_child() {
    let Ok(root) = std::env::var("KES_RESTART_CHILD_ROOT") else {
        return;
    };
    let output = match std::env::var("KES_RESTART_BOUNDARY").unwrap().as_str() {
        "vkey" => GenerationOutput::VerificationKey,
        "backup" => GenerationOutput::EncryptedSigningKey,
        unexpected => panic!("unexpected boundary {unexpected}"),
    };
    publish_fixture(Path::new(&root), Some(output), "");
    panic!("publication fault did not terminate child");
}

#[test]
fn process_restart_between_each_output_link_finishes_matching_manifest() {
    let fixture = Fixture::new();
    for (boundary, prefix, linked) in [
        ("vkey", "link-vkey", 1usize),
        ("backup", "link-backup", 2usize),
    ] {
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "publication_crash_child", "--nocapture"])
            .env("KES_RESTART_CHILD_ROOT", &fixture.root)
            .env("KES_RESTART_BOUNDARY", boundary)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(!status.success());
        let outputs = fixture.outputs(prefix);
        assert!(outputs[..linked].iter().all(|path| path.exists()));
        assert!(outputs[linked..].iter().all(|path| !path.exists()));

        publish_fixture(&fixture.root, None, prefix);
        assert!(outputs.iter().all(|path| path.exists()));
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&outputs[2]).unwrap()).unwrap();
        assert_eq!(manifest["result"], "complete");
        assert_eq!(manifest["requestId"], hex(&REQUEST));
        assert_eq!(manifest["generationId"], hex(&GENERATION));
        assert_eq!(
            manifest["outputs"]["verificationKeySha256"],
            format!("{:x}", Sha256::digest(fs::read(&outputs[0]).unwrap()))
        );
        assert_eq!(
            manifest["outputs"]["encryptedSigningKeySha256"],
            format!("{:x}", Sha256::digest(fs::read(&outputs[1]).unwrap()))
        );
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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

#[test]
fn status_cli_uses_public_connection_and_reports_absent_node_data_as_null() {
    use cardano_kes_forge::host::{
        client::operator_status,
        observation::NetworkContext,
        signing::{Binding, Router},
    };
    let fixture = Fixture::new();
    let listener = UnixListener::bind(&fixture.socket).unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut prefix = [0; 4];
        stream.read_exact(&mut prefix).unwrap();
        let mut request = vec![0; u32::from_be_bytes(prefix) as usize];
        stream.read_exact(&mut request).unwrap();
        let envelope = Envelope::parse(&request, EnvelopeKind::LocalRequest).unwrap();
        assert_eq!(envelope.operation, Operation::Status);
        assert!(
            envelope
                .payload()
                .required("host_diagnostics")
                .unwrap()
                .boolean()
                .unwrap()
        );
        let request = *envelope.request().unwrap().as_bytes();
        let response = response(Operation::Status, request, Status::Ok, |e| {
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
            e.text("no active generation").unwrap();
            e.text("credential_epoch").unwrap();
            e.uint(0).unwrap();
        });
        let router = Router::new([(
            CONNECTION.to_owned(),
            Binding {
                device: DEVICE,
                pool: POOL,
                incarnation: INCARNATION,
                network: NetworkContext {
                    network_magic: 42,
                    shelley_genesis_digest: DIGEST,
                    slots_per_kes_period: 64,
                    max_kes_evolutions: 64,
                },
            },
        )])
        .unwrap();
        let mut bytes = [0; kes_protocol::MAX_FRAME_BYTES];
        let length = operator_status::attach(
            &response,
            &mut bytes,
            &DEVICE,
            Some((&POOL, &INCARNATION)),
            &router,
            CONNECTION,
        )
        .unwrap();
        send_response(stream, &bytes[..length]);
    });
    let output = Command::new(env!("CARGO_BIN_EXE_kes-forge"))
        .arg("status")
        .arg("--connection")
        .arg(&fixture.connection)
        .arg("--json")
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["result"]["observation"]["state"], "unavailable");
    assert!(value["result"]["observation"]["confirmedAgeMs"].is_null());
    assert!(value["result"]["ready"].is_null());
    assert!(value["result"]["remainingValidityPeriods"].is_null());
    assert!(
        !value["result"]["releaseEvidenceVerified"]
            .as_bool()
            .unwrap()
    );
    for entry in value["result"]["latency"].as_object().unwrap().values() {
        assert_eq!(entry["state"], "unavailable");
        assert!(entry["sample"].is_null());
    }
}
