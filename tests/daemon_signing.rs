use cardano_kes_forge::host::daemon::{Config, Daemon, DeviceTransport, TransportError};
use cardano_kes_forge::host::socket::Frame;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use kes_core::cbor::Encoder;
use kes_protocol::{Envelope, EnvelopeKind, Operation, Status};
use std::collections::VecDeque;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

static NEXT: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
enum Action {
    Reply,
    Block,
    Unavailable,
    Late,
}

#[derive(Default)]
struct Gate {
    state: Mutex<(bool, bool)>,
    changed: Condvar,
}

impl Gate {
    fn enter_and_wait(&self) {
        let mut state = self.state.lock().unwrap();
        state.0 = true;
        self.changed.notify_all();
        while !state.1 {
            state = self.changed.wait(state).unwrap();
        }
    }

    fn wait_until_entered(&self) {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut state = self.state.lock().unwrap();
        while !state.0 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "transport did not enter blocking exchange"
            );
            let (next, timeout) = self.changed.wait_timeout(state, remaining).unwrap();
            assert!(
                !timeout.timed_out(),
                "transport did not enter blocking exchange"
            );
            state = next;
        }
    }

    fn release(&self) {
        let mut state = self.state.lock().unwrap();
        state.1 = true;
        self.changed.notify_all();
    }
}

struct TestTransport {
    actions: Arc<Mutex<VecDeque<Action>>>,
    calls: Arc<AtomicUsize>,
    order: Arc<Mutex<Vec<String>>>,
    gate: Arc<Gate>,
}

impl DeviceTransport for TestTransport {
    fn exchange(&mut self, frame: &mut Frame, _remaining: Duration) -> Result<(), TransportError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        let request = Envelope::parse(frame.as_slice(), EnvelopeKind::LocalRequest).unwrap();
        let connection = request
            .map()
            .required("connection")
            .unwrap()
            .text()
            .unwrap()
            .to_owned();
        self.order.lock().unwrap().push(connection.clone());
        match self
            .actions
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Action::Reply)
        {
            Action::Unavailable => return Err(TransportError::Unavailable),
            Action::Late => thread::sleep(Duration::from_millis(40)),
            Action::Block => self.gate.enter_and_wait(),
            Action::Reply => {}
        }
        let response = response(
            &connection,
            request.operation,
            *request.request().unwrap().as_bytes(),
            Status::Busy,
        );
        frame.replace(&response).unwrap();
        Ok(())
    }
}

struct Fixture {
    root: PathBuf,
    socket: PathBuf,
    stop: Arc<AtomicBool>,
    server: Option<thread::JoinHandle<()>>,
    calls: Arc<AtomicUsize>,
    order: Arc<Mutex<Vec<String>>>,
    gate: Arc<Gate>,
}

impl Fixture {
    fn start(allowed_uid: u32, actions: impl IntoIterator<Item = Action>) -> Self {
        let root = std::env::temp_dir().join(format!(
            "kes-forged-signing-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o750)).unwrap();
        let socket = root.join("kes-forged.sock");
        let stop = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicUsize::new(0));
        let order = Arc::new(Mutex::new(Vec::new()));
        let gate = Arc::new(Gate::default());
        let daemon = Daemon::new(
            Config {
                management_connection: "management".to_owned(),
                pool_connections: vec!["pool-0".to_owned(), "pool-1".to_owned()],
                allowed_peer_uids: vec![(
                    allowed_uid,
                    vec!["pool-0".to_owned(), "pool-1".to_owned()],
                )],
            },
            TestTransport {
                actions: Arc::new(Mutex::new(actions.into_iter().collect())),
                calls: Arc::clone(&calls),
                order: Arc::clone(&order),
                gate: Arc::clone(&gate),
            },
        )
        .unwrap();
        let thread_socket = socket.clone();
        let thread_stop = Arc::clone(&stop);
        let server = thread::spawn(move || {
            daemon.serve_until(&thread_socket, &thread_stop).unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        while !socket.exists() {
            assert!(Instant::now() < deadline, "daemon did not bind its socket");
            thread::sleep(Duration::from_millis(5));
        }
        Self {
            root,
            socket,
            stop,
            server: Some(server),
            calls,
            order,
            gate,
        }
    }

    fn exchange(
        &self,
        connection: &str,
        operation: Operation,
        budget_ms: u32,
        request_id: u8,
    ) -> Status {
        exchange(&self.socket, connection, operation, budget_ms, request_id)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.gate.release();
        self.stop.store(true, Ordering::Release);
        self.server.take().unwrap().join().unwrap();
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn actual_peer_credentials_reject_wrong_uid_pool_and_operation_scope() {
    let own_uid = rustix::process::getuid().as_raw();
    let wrong_uid = Fixture::start(own_uid.wrapping_add(1), [Action::Reply]);
    assert_eq!(
        wrong_uid.exchange("pool-0", Operation::Sign, 1_000, 1),
        Status::AuthFailed
    );
    assert_eq!(wrong_uid.calls.load(Ordering::Acquire), 0);

    let fixture = Fixture::start(own_uid, [Action::Reply]);
    assert_eq!(
        fixture.exchange("unknown-pool", Operation::Sign, 1_000, 2),
        Status::AuthFailed
    );
    assert_eq!(
        fixture.exchange("pool-0", Operation::UpdateBegin, 1_000, 3),
        Status::AuthFailed
    );
    assert_eq!(fixture.calls.load(Ordering::Acquire), 0);
}

#[test]
fn separate_processes_use_distinct_socket_connections() {
    let fixture = Fixture::start(
        rustix::process::getuid().as_raw(),
        [Action::Reply, Action::Reply, Action::Reply, Action::Reply],
    );
    for request_id in 10..14 {
        let mut child = subprocess(&fixture.socket, "pool-0", request_id, Status::Busy);
        assert!(child.wait().unwrap().success());
    }
    assert_eq!(fixture.calls.load(Ordering::Acquire), 4);
}

#[test]
fn flooding_pool_is_bounded_and_cannot_starve_another_pool() {
    let fixture = Arc::new(Fixture::start(
        rustix::process::getuid().as_raw(),
        [Action::Block, Action::Reply, Action::Reply],
    ));
    let first = exchange_thread(Arc::clone(&fixture), "pool-0", 20);
    fixture.gate.wait_until_entered();
    let queued_same_pool = exchange_thread(Arc::clone(&fixture), "pool-0", 21);
    let other_pool = exchange_thread(Arc::clone(&fixture), "pool-1", 22);
    thread::sleep(Duration::from_millis(20));
    assert_eq!(
        fixture.exchange("pool-0", Operation::Sign, 1_000, 23),
        Status::Busy
    );

    let secret_file = fixture.root.join("independent-file-backed.key");
    fs::write(&secret_file, [7_u8; 32]).unwrap();
    let key: [u8; 32] = fs::read(&secret_file).unwrap().try_into().unwrap();
    let signing_key = SigningKey::from_bytes(&key);
    let signature = signing_key.sign(b"independent file-backed opportunity");
    assert!(
        VerifyingKey::from(&signing_key)
            .verify_strict(b"independent file-backed opportunity", &signature)
            .is_ok()
    );

    fixture.gate.release();
    assert_eq!(first.join().unwrap(), Status::Busy);
    assert_eq!(queued_same_pool.join().unwrap(), Status::Busy);
    assert_eq!(other_pool.join().unwrap(), Status::Busy);
    assert_eq!(
        fixture.order.lock().unwrap().as_slice(),
        ["pool-0", "pool-1", "pool-0"]
    );
}

#[test]
fn unavailable_transport_reconnects_without_reusing_a_late_result() {
    let unavailable = Fixture::start(
        rustix::process::getuid().as_raw(),
        [Action::Unavailable, Action::Reply],
    );
    assert_eq!(
        unavailable.exchange("pool-0", Operation::Sign, 1_000, 30),
        Status::DeviceUnavailable
    );
    assert_eq!(
        unavailable.exchange("pool-0", Operation::Sign, 1_000, 31),
        Status::Busy
    );

    let late = Fixture::start(rustix::process::getuid().as_raw(), [Action::Late]);
    assert_eq!(
        late.exchange("pool-0", Operation::Sign, 5, 32),
        Status::DeadlineExceeded
    );
    assert_eq!(late.calls.load(Ordering::Acquire), 1);
}

fn exchange_thread(
    fixture: Arc<Fixture>,
    connection: &'static str,
    request_id: u8,
) -> thread::JoinHandle<Status> {
    thread::spawn(move || fixture.exchange(connection, Operation::Sign, 1_000, request_id))
}

fn subprocess(socket: &Path, connection: &str, request_id: u8, status: Status) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "daemon_signing_subprocess_client",
            "--ignored",
            "--nocapture",
        ])
        .env("KES_TEST_SOCKET", socket)
        .env("KES_TEST_CONNECTION", connection)
        .env("KES_TEST_REQUEST", request_id.to_string())
        .env("KES_TEST_STATUS", status.as_str())
        .spawn()
        .unwrap()
}

#[test]
#[ignore = "subprocess helper"]
fn daemon_signing_subprocess_client() {
    let socket = PathBuf::from(std::env::var_os("KES_TEST_SOCKET").unwrap());
    let connection = std::env::var("KES_TEST_CONNECTION").unwrap();
    let request_id = std::env::var("KES_TEST_REQUEST")
        .unwrap()
        .parse::<u8>()
        .unwrap();
    let expected = Status::parse(&std::env::var("KES_TEST_STATUS").unwrap()).unwrap();
    assert_eq!(
        exchange(&socket, &connection, Operation::Sign, 1_000, request_id),
        expected
    );
}

fn exchange(
    socket: &Path,
    connection: &str,
    operation: Operation,
    budget_ms: u32,
    request_id: u8,
) -> Status {
    let request = request(connection, operation, budget_ms, request_id);
    let mut stream = UnixStream::connect(socket).unwrap();
    stream
        .write_all(&(request.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(&request).unwrap();
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix).unwrap();
    let mut response = vec![0; u32::from_be_bytes(prefix) as usize];
    stream.read_exact(&mut response).unwrap();
    Envelope::parse(&response, EnvelopeKind::LocalResponse)
        .unwrap()
        .status
        .unwrap()
}

fn request(connection: &str, operation: Operation, budget_ms: u32, request: u8) -> Vec<u8> {
    let mut storage = [0; kes_protocol::MAX_FRAME_BYTES];
    let mut encoder = Encoder::new(&mut storage);
    encoder.map(6).unwrap();
    encoder.text("op").unwrap();
    encoder.text(operation.as_str()).unwrap();
    encoder.text("payload").unwrap();
    encode_request_payload(&mut encoder, operation);
    encoder.text("request").unwrap();
    encoder.bytes(&[request; 16]).unwrap();
    encoder.text("version").unwrap();
    encoder.uint(1).unwrap();
    encoder.text("budget_ms").unwrap();
    encoder.uint(u64::from(budget_ms)).unwrap();
    encoder.text("connection").unwrap();
    encoder.text(connection).unwrap();
    encoder.finish().unwrap().encoded().to_vec()
}

fn encode_request_payload(encoder: &mut Encoder<'_>, operation: Operation) {
    match operation {
        Operation::Sign => {
            encoder.map(5).unwrap();
            encoder.text("message").unwrap();
            encoder.bytes(b"native header bytes").unwrap();
            encoder.text("network").unwrap();
            encoder.map(4).unwrap();
            encoder.text("network_magic").unwrap();
            encoder.uint(42).unwrap();
            encoder.text("max_kes_evolutions").unwrap();
            encoder.uint(64).unwrap();
            encoder.text("slots_per_kes_period").unwrap();
            encoder.uint(64).unwrap();
            encoder.text("shelley_genesis_digest").unwrap();
            encoder.bytes(&[4; 32]).unwrap();
            encoder.text("generation").unwrap();
            encoder.bytes(&[5; 16]).unwrap();
            encoder.text("absolute_period").unwrap();
            encoder.uint(7).unwrap();
            encoder.text("certificate_digest").unwrap();
            encoder.bytes(&[6; 32]).unwrap();
        }
        Operation::UpdateBegin => {
            encoder.map(2).unwrap();
            encoder.text("manifest_digest").unwrap();
            encoder.bytes(&[7; 32]).unwrap();
            encoder.text("expected_revision").unwrap();
            encoder.uint(1).unwrap();
        }
        _ => {
            encoder.map(0).unwrap();
        }
    }
}

fn response(connection: &str, operation: Operation, request: [u8; 16], status: Status) -> Vec<u8> {
    let mut storage = [0; kes_protocol::MAX_FRAME_BYTES];
    let mut encoder = Encoder::new(&mut storage);
    encoder.map(6).unwrap();
    encoder.text("op").unwrap();
    encoder.text(operation.as_str()).unwrap();
    encoder.text("status").unwrap();
    encoder.text(status.as_str()).unwrap();
    encoder.text("payload").unwrap();
    encoder.map(2).unwrap();
    encoder.text("scope").unwrap();
    encoder.text("pool").unwrap();
    encoder.text("diagnostic").unwrap();
    encoder.text("test transport").unwrap();
    encoder.text("request").unwrap();
    encoder.bytes(&request).unwrap();
    encoder.text("version").unwrap();
    encoder.uint(1).unwrap();
    encoder.text("connection").unwrap();
    encoder.text(connection).unwrap();
    encoder.finish().unwrap().encoded().to_vec()
}
