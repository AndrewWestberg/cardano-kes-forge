use cardano_kes_forge::host::{
    client::{self, Error as ClientError},
    config::{NetworkBinding, PublicPoolConnection},
    observation::{NetworkContext, State as ObservationState},
    operations::{Identity, OperationRecord, State},
    signing::{Binding, Router, Session},
};
use kes_core::cbor::Encoder;
use kes_protocol::{Envelope, EnvelopeKind, Operation, Status};
use std::{
    fs,
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixListener},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::Duration,
};

const REQUEST: [u8; 16] = [0x41; 16];
const GENERATION: [u8; 16] = [0x52; 16];
const GENERATION_NUMBER: u64 = 7;
const CONNECTION: &str = "pool-a";

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "kes-reconnect-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        Self { root }
    }

    fn socket(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Clone, Copy)]
enum Reply {
    Drop,
    Generation { request: [u8; 16], revision: u64 },
    RecoveryStatus(Status),
    Malformed,
}

fn connection(socket_path: PathBuf, name: &str) -> PublicPoolConnection {
    PublicPoolConnection {
        socket_path,
        device_id: [1; 16],
        pool_id: [2; 28],
        incarnation_id: [3; 16],
        identity_public_key: [4; 32],
        network_binding: NetworkBinding {
            network_magic: 42,
            shelley_genesis_digest: "11".repeat(32),
            slots_per_kes_period: 129_600,
            max_kes_evolutions: 64,
        },
        connection_name: name.to_owned(),
        device_identity_file: PathBuf::from("unused-identity.json"),
        credential_file: PathBuf::from("unused-credential.json"),
        security_policy: "isolated-development".to_owned(),
    }
}

fn serve(socket: &Path, connection: &'static str, replies: Vec<Reply>) -> thread::JoinHandle<()> {
    let listener = UnixListener::bind(socket).unwrap();
    thread::spawn(move || {
        for reply in replies {
            let (mut stream, _) = listener.accept().unwrap();
            let mut prefix = [0; 4];
            stream.read_exact(&mut prefix).unwrap();
            let mut request_bytes = vec![0; u32::from_be_bytes(prefix) as usize];
            stream.read_exact(&mut request_bytes).unwrap();
            let request = Envelope::parse(&request_bytes, EnvelopeKind::LocalRequest).unwrap();
            let request_id = *request.request().unwrap().as_bytes();
            match reply {
                Reply::Drop => {
                    assert_eq!(request_id, REQUEST);
                    assert_eq!(request.operation, Operation::Generate);
                    assert_eq!(
                        request
                            .payload()
                            .required("expected_revision")
                            .unwrap()
                            .uint()
                            .unwrap(),
                        5
                    );
                }
                Reply::Malformed => {
                    assert_eq!(request.operation, Operation::OpStatus);
                    stream.write_all(&3u32.to_be_bytes()).unwrap();
                    stream.write_all(&[0xff; 3]).unwrap();
                }
                Reply::Generation {
                    request: response_request,
                    revision,
                } => {
                    assert_eq!(request_id, REQUEST);
                    assert_eq!(request.operation, Operation::OpStatus);
                    let encoded = generation_response(connection, response_request, revision);
                    stream
                        .write_all(&(encoded.len() as u32).to_be_bytes())
                        .unwrap();
                    stream.write_all(&encoded).unwrap();
                }
                Reply::RecoveryStatus(status) => {
                    assert_eq!(request_id, REQUEST);
                    assert_eq!(request.operation, Operation::OpStatus);
                    let encoded = recovery_response(connection, request_id, status);
                    stream
                        .write_all(&(encoded.len() as u32).to_be_bytes())
                        .unwrap();
                    stream.write_all(&encoded).unwrap();
                }
            }
        }
    })
}

fn generation_response(connection: &str, request: [u8; 16], revision: u64) -> Vec<u8> {
    local_response(connection, request, Status::Ok, |encoder| {
        encoder.map(13)?;
        encoder.text("health")?;
        encoder.text("healthy")?;
        encoder.text("revision")?;
        encoder.uint(revision)?;
        encoder.text("lifecycle")?;
        encoder.text("staged")?;
        encoder.text("generation")?;
        encoder.bytes(&GENERATION)?;
        encoder.text("artifact_digest")?;
        encoder.bytes(&[0x74; 32])?;
        encoder.text("relative_period")?;
        encoder.uint(0)?;
        encoder.text("backup_available")?;
        encoder.boolean(true)?;
        encoder.text("creation_request")?;
        encoder.bytes(&REQUEST)?;
        encoder.text("verification_key")?;
        encoder.bytes(&[0x63; 32])?;
        encoder.text("certificate_start")?;
        encoder.null()?;
        encoder.text("generation_number")?;
        encoder.uint(GENERATION_NUMBER)?;
        encoder.text("certificate_digest")?;
        encoder.null()?;
        encoder.text("certificate_counter")?;
        encoder.null()
    })
}

fn recovery_response(connection: &str, request: [u8; 16], status: Status) -> Vec<u8> {
    local_response(connection, request, status, |encoder| {
        encoder.map(2)?;
        encoder.text("request")?;
        encoder.bytes(&REQUEST)?;
        encoder.text("generation_number")?;
        encoder.uint(GENERATION_NUMBER)
    })
}

fn local_response(
    connection: &str,
    request: [u8; 16],
    status: Status,
    payload: impl FnOnce(&mut Encoder<'_>) -> Result<(), kes_core::cbor::Error>,
) -> Vec<u8> {
    let mut bytes = [0; kes_protocol::MAX_FRAME_BYTES];
    let mut encoder = Encoder::new(&mut bytes);
    encoder.map(6).unwrap();
    encoder.text("op").unwrap();
    encoder.text(Operation::OpStatus.as_str()).unwrap();
    encoder.text("status").unwrap();
    encoder.text(status.as_str()).unwrap();
    encoder.text("payload").unwrap();
    payload(&mut encoder).unwrap();
    encoder.text("request").unwrap();
    encoder.bytes(&request).unwrap();
    encoder.text("version").unwrap();
    encoder.uint(1).unwrap();
    encoder.text("connection").unwrap();
    encoder.text(connection).unwrap();
    encoder.finish().unwrap().encoded().to_vec()
}

#[test]
fn lost_generate_ack_reconciles_authoritative_status_without_replaying_mutation() {
    let fixture = Fixture::new();
    let socket = fixture.socket("daemon.sock");
    let server = serve(
        &socket,
        CONNECTION,
        vec![
            Reply::Drop,
            Reply::Generation {
                request: REQUEST,
                revision: 19,
            },
        ],
    );
    let result = client::generate(
        &connection(socket, CONNECTION),
        REQUEST,
        GENERATION_NUMBER,
        5,
    )
    .unwrap();
    assert_eq!(result.generation, GENERATION);
    assert_eq!(result.creation_request, REQUEST);
    assert_eq!(result.generation_number, GENERATION_NUMBER);
    assert_eq!(result.revision, 19);
    server.join().unwrap();
}

#[test]
fn late_pre_reboot_reply_is_rejected_and_pool_local_corruption_is_isolated() {
    let fixture = Fixture::new();
    let stale_socket = fixture.socket("stale.sock");
    let stale = serve(
        &stale_socket,
        CONNECTION,
        vec![Reply::Generation {
            request: [0x99; 16],
            revision: 4,
        }],
    );
    assert!(matches!(
        client::generation_status(
            &connection(stale_socket, CONNECTION),
            REQUEST,
            GENERATION_NUMBER
        ),
        Err(ClientError::Security)
    ));
    stale.join().unwrap();

    let damaged_socket = fixture.socket("damaged.sock");
    let damaged = serve(&damaged_socket, CONNECTION, vec![Reply::Malformed]);
    assert!(matches!(
        client::generation_status(
            &connection(damaged_socket, CONNECTION),
            REQUEST,
            GENERATION_NUMBER
        ),
        Err(ClientError::Integrity)
    ));
    damaged.join().unwrap();

    let healthy_socket = fixture.socket("healthy.sock");
    let healthy = serve(
        &healthy_socket,
        CONNECTION,
        vec![Reply::Generation {
            request: REQUEST,
            revision: 11,
        }],
    );
    assert_eq!(
        client::generation_status(
            &connection(healthy_socket, CONNECTION),
            REQUEST,
            GENERATION_NUMBER
        )
        .unwrap()
        .revision,
        11
    );
    healthy.join().unwrap();
}

#[test]
fn stale_host_manifest_records_authoritative_reclaimed_result() {
    let fixture = Fixture::new();
    let record_path = fixture.root.join("generate.operation.json");
    let identity = Identity {
        device: [1; 16],
        pool: Some([2; 28]),
        incarnation: Some([3; 16]),
        request: REQUEST,
        generation_number: Some(GENERATION_NUMBER),
    };
    let mut record =
        OperationRecord::begin(&record_path, "GENERATE", identity, b"canonical").unwrap();
    record.record_in_progress().unwrap();
    record.record_unknown().unwrap();
    drop(record);

    let socket = fixture.socket("reclaimed.sock");
    let server = serve(
        &socket,
        CONNECTION,
        vec![Reply::RecoveryStatus(Status::ResultReclaimed)],
    );
    assert!(matches!(
        client::generation_status(&connection(socket, CONNECTION), REQUEST, GENERATION_NUMBER),
        Err(ClientError::ResultReclaimed)
    ));
    server.join().unwrap();

    let mut restarted = OperationRecord::load(&record_path).unwrap();
    assert!(restarted.requires_status_reconciliation());
    restarted.record_result_reclaimed().unwrap();
    drop(restarted);
    let final_record = OperationRecord::load(&record_path).unwrap();
    assert_eq!(final_record.state(), State::ResultReclaimed);
    assert!(!final_record.requires_status_reconciliation());
}

#[test]
fn recovery_statuses_remain_distinct_across_reconnects() {
    for (index, (status, expected)) in [
        (Status::InProgress, "in-progress"),
        (Status::Unknown, "unknown"),
        (Status::NotCommitted, "not-committed"),
        (Status::ResultReclaimed, "result-reclaimed"),
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new();
        let socket = fixture.socket(&format!("status-{index}.sock"));
        let server = serve(&socket, CONNECTION, vec![Reply::RecoveryStatus(status)]);
        let actual =
            client::generation_status(&connection(socket, CONNECTION), REQUEST, GENERATION_NUMBER);
        assert!(match expected {
            "in-progress" => matches!(actual, Err(ClientError::InProgress)),
            "unknown" => matches!(actual, Err(ClientError::Unknown)),
            "not-committed" => matches!(actual, Err(ClientError::NotCommitted)),
            "result-reclaimed" => matches!(actual, Err(ClientError::ResultReclaimed)),
            _ => unreachable!(),
        });
        server.join().unwrap();
    }
}

#[test]
fn reboot_reconciles_unequal_pool_periods_and_committed_expiry_independently() {
    let network = NetworkContext {
        network_magic: 42,
        shelley_genesis_digest: [0x11; 32],
        slots_per_kes_period: 129_600,
        max_kes_evolutions: 64,
    };
    let mut router = Router::new([
        (
            "pool-a".to_owned(),
            Binding {
                device: [1; 16],
                pool: [2; 28],
                incarnation: [3; 16],
                network: network.clone(),
            },
        ),
        (
            "pool-b".to_owned(),
            Binding {
                device: [1; 16],
                pool: [4; 28],
                incarnation: [5; 16],
                network,
            },
        ),
    ])
    .unwrap();
    let first_session = Session {
        boot_nonce: [6; 32],
        session: [7; 16],
    };
    for (connection, request, generation, revision, relative) in [
        ("pool-a", [0xa1; 16], [0x21; 16], 3, 5),
        ("pool-b", [0xb1; 16], [0x31; 16], 7, 17),
    ] {
        router
            .complete(
                connection,
                &status_request(connection, request),
                &status_response(
                    connection, request, generation, revision, relative, "active",
                ),
                first_session,
                Duration::from_millis(1),
            )
            .unwrap();
    }
    assert_eq!(
        router
            .observation("pool-a", router.monotonic_ms())
            .unwrap()
            .historical
            .unwrap()
            .relative_period,
        5
    );
    assert_eq!(
        router
            .observation("pool-b", router.monotonic_ms())
            .unwrap()
            .historical
            .unwrap()
            .relative_period,
        17
    );

    let rebooted_session = Session {
        boot_nonce: [8; 32],
        session: [9; 16],
    };
    router
        .complete(
            "pool-a",
            &status_request("pool-a", [0xa2; 16]),
            &status_response("pool-a", [0xa2; 16], [0x21; 16], 4, 6, "active"),
            rebooted_session,
            Duration::from_millis(1),
        )
        .unwrap();
    router
        .complete(
            "pool-b",
            &status_request("pool-b", [0xb2; 16]),
            &status_response("pool-b", [0xb2; 16], [0x31; 16], 8, 63, "expired"),
            rebooted_session,
            Duration::from_millis(1),
        )
        .unwrap();

    let pool_a = router.observation("pool-a", router.monotonic_ms()).unwrap();
    assert_eq!(pool_a.state, ObservationState::Unavailable);
    assert_eq!(pool_a.historical.unwrap().relative_period, 6);
    assert_eq!(pool_a.historical.unwrap().revision, 4);
    let pool_b = router.observation("pool-b", router.monotonic_ms()).unwrap();
    assert_eq!(pool_b.state, ObservationState::Unavailable);
    assert_eq!(pool_b.historical.unwrap().relative_period, 63);
    assert_eq!(pool_b.historical.unwrap().revision, 8);
}

fn status_request(connection: &str, request: [u8; 16]) -> Vec<u8> {
    let mut storage = [0; kes_protocol::MAX_FRAME_BYTES];
    let mut encoder = Encoder::new(&mut storage);
    encoder.map(6).unwrap();
    encoder.text("op").unwrap();
    encoder.text("STATUS").unwrap();
    encoder.text("payload").unwrap();
    encoder.map(0).unwrap();
    encoder.text("request").unwrap();
    encoder.bytes(&request).unwrap();
    encoder.text("version").unwrap();
    encoder.uint(1).unwrap();
    encoder.text("budget_ms").unwrap();
    encoder.uint(500).unwrap();
    encoder.text("connection").unwrap();
    encoder.text(connection).unwrap();
    encoder.finish().unwrap().encoded().to_vec()
}

fn status_response(
    connection: &str,
    request: [u8; 16],
    generation: [u8; 16],
    revision: u64,
    relative_period: u64,
    lifecycle: &str,
) -> Vec<u8> {
    let mut storage = [0; kes_protocol::MAX_FRAME_BYTES];
    let mut encoder = Encoder::new(&mut storage);
    encoder.map(6).unwrap();
    encoder.text("op").unwrap();
    encoder.text("STATUS").unwrap();
    encoder.text("status").unwrap();
    encoder.text("OK").unwrap();
    encoder.text("payload").unwrap();
    encoder.map(9).unwrap();
    encoder.text("active").unwrap();
    descriptor(
        &mut encoder,
        generation,
        revision,
        relative_period,
        lifecycle,
    );
    encoder.text("health").unwrap();
    encoder.text("healthy").unwrap();
    encoder.text("staged").unwrap();
    encoder.null().unwrap();
    encoder.text("revoked").unwrap();
    encoder.boolean(false).unwrap();
    encoder.text("revision").unwrap();
    encoder.uint(revision).unwrap();
    encoder.text("directory").unwrap();
    encoder.array(0).unwrap();
    encoder.text("security_mode").unwrap();
    encoder.text("development").unwrap();
    encoder.text("blocking_reason").unwrap();
    encoder.text("").unwrap();
    encoder.text("credential_epoch").unwrap();
    encoder.uint(0).unwrap();
    encoder.text("request").unwrap();
    encoder.bytes(&request).unwrap();
    encoder.text("version").unwrap();
    encoder.uint(1).unwrap();
    encoder.text("connection").unwrap();
    encoder.text(connection).unwrap();
    encoder.finish().unwrap().encoded().to_vec()
}

fn descriptor(
    encoder: &mut Encoder<'_>,
    generation: [u8; 16],
    revision: u64,
    relative_period: u64,
    lifecycle: &str,
) {
    encoder.map(13).unwrap();
    encoder.text("health").unwrap();
    encoder.text("healthy").unwrap();
    encoder.text("revision").unwrap();
    encoder.uint(revision).unwrap();
    encoder.text("lifecycle").unwrap();
    encoder.text(lifecycle).unwrap();
    encoder.text("generation").unwrap();
    encoder.bytes(&generation).unwrap();
    encoder.text("artifact_digest").unwrap();
    encoder.bytes(&[0x71; 32]).unwrap();
    encoder.text("relative_period").unwrap();
    encoder.uint(relative_period).unwrap();
    encoder.text("backup_available").unwrap();
    encoder.boolean(true).unwrap();
    encoder.text("creation_request").unwrap();
    encoder.bytes(&[0x72; 16]).unwrap();
    encoder.text("verification_key").unwrap();
    encoder.bytes(&[0x73; 32]).unwrap();
    encoder.text("certificate_start").unwrap();
    encoder.uint(100).unwrap();
    encoder.text("generation_number").unwrap();
    encoder.uint(1).unwrap();
    encoder.text("certificate_digest").unwrap();
    encoder.bytes(&[0x74; 32]).unwrap();
    encoder.text("certificate_counter").unwrap();
    encoder.uint(1).unwrap();
}
