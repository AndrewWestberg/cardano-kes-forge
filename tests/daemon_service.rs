use cardano_kes_forge::host::daemon::{Config, Daemon, DeviceTransport, TransportError};
use cardano_kes_forge::host::socket::Frame;
use kes_core::cbor::Encoder;
use kes_protocol::{Envelope, EnvelopeKind, Operation, Status};
use std::collections::VecDeque;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

static NEXT: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
enum Action {
    Reply,
    Late,
    Uncertain,
}

struct TestTransport {
    actions: Arc<Mutex<VecDeque<Action>>>,
    calls: Arc<AtomicUsize>,
}

impl DeviceTransport for TestTransport {
    fn exchange(&mut self, frame: &mut Frame, _remaining: Duration) -> Result<(), TransportError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        let action = self
            .actions
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Action::Reply);
        if matches!(action, Action::Uncertain) {
            return Err(TransportError::Uncertain);
        }
        if matches!(action, Action::Late) {
            thread::sleep(Duration::from_millis(30));
        }
        let request = Envelope::parse(frame.as_slice(), EnvelopeKind::LocalRequest).unwrap();
        let connection = request
            .map()
            .required("connection")
            .unwrap()
            .text()
            .unwrap();
        let body = response(
            connection,
            request.operation,
            *request.request().unwrap().as_bytes(),
            Status::Busy,
        );
        frame.replace(&body).unwrap();
        Ok(())
    }
}

struct Fixture {
    root: PathBuf,
    socket: PathBuf,
    stop: Arc<AtomicBool>,
    server: Option<thread::JoinHandle<()>>,
    calls: Arc<AtomicUsize>,
}

impl Fixture {
    fn start(allowed_uid: u32, actions: impl IntoIterator<Item = Action>) -> Self {
        let root = std::env::temp_dir().join(format!(
            "kes-forged-service-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o750)).unwrap();
        let socket = root.join("kes-forged.sock");
        let stop = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicUsize::new(0));
        let daemon = Daemon::new(
            Config {
                management_connection: "management".to_owned(),
                pool_connections: vec!["pool-0".to_owned()],
                allowed_peer_uids: vec![(allowed_uid, vec!["pool-0".to_owned()])],
            },
            TestTransport {
                actions: Arc::new(Mutex::new(actions.into_iter().collect())),
                calls: Arc::clone(&calls),
            },
        )
        .unwrap();
        let thread_socket = socket.clone();
        let thread_stop = Arc::clone(&stop);
        let server =
            thread::spawn(move || daemon.serve_until(&thread_socket, &thread_stop).unwrap());
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
        }
    }

    fn exchange(&self, budget_ms: u32, request_id: u8) -> Envelope<'static> {
        let request = request("pool-0", budget_ms, request_id);
        let mut stream = UnixStream::connect(&self.socket).unwrap();
        stream
            .write_all(&(request.len() as u32).to_be_bytes())
            .unwrap();
        stream.write_all(&request).unwrap();
        let mut prefix = [0; 4];
        stream.read_exact(&mut prefix).unwrap();
        let mut response = vec![0; u32::from_be_bytes(prefix) as usize];
        stream.read_exact(&mut response).unwrap();
        let leaked = Box::leak(response.into_boxed_slice());
        Envelope::parse(leaked, EnvelopeKind::LocalResponse).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.server.take().unwrap().join().unwrap();
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn peer_credentials_gate_exact_connection_before_dispatch() {
    let own_uid = rustix::process::getuid().as_raw();
    let authorized = Fixture::start(own_uid, [Action::Reply]);
    let metadata = fs::metadata(&authorized.socket).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o660);
    assert_eq!(authorized.exchange(1_000, 1).status, Some(Status::Busy));
    assert_eq!(authorized.calls.load(Ordering::Acquire), 1);

    let unauthorized = Fixture::start(own_uid.wrapping_add(1), [Action::Reply]);
    assert_eq!(
        unauthorized.exchange(1_000, 2).status,
        Some(Status::AuthFailed)
    );
    assert_eq!(unauthorized.calls.load(Ordering::Acquire), 0);
}

#[test]
fn late_results_are_discarded_against_the_original_budget() {
    let fixture = Fixture::start(rustix::process::getuid().as_raw(), [Action::Late]);
    assert_eq!(
        fixture.exchange(5, 3).status,
        Some(Status::DeadlineExceeded)
    );
    assert_eq!(fixture.calls.load(Ordering::Acquire), 1);
}

#[test]
fn uncertain_dispatch_poison_prevents_workspace_reuse() {
    let fixture = Fixture::start(
        rustix::process::getuid().as_raw(),
        [Action::Uncertain, Action::Reply],
    );
    assert_eq!(
        fixture.exchange(1_000, 4).status,
        Some(Status::DeviceUnavailable)
    );
    assert_eq!(
        fixture.exchange(1_000, 5).status,
        Some(Status::DeviceUnavailable)
    );
    assert_eq!(fixture.calls.load(Ordering::Acquire), 1);
}

fn request(connection: &str, budget_ms: u32, request: u8) -> Vec<u8> {
    let mut storage = [0; kes_protocol::MAX_FRAME_BYTES];
    let mut encoder = Encoder::new(&mut storage);
    encoder.map(6).unwrap();
    encoder.text("op").unwrap();
    encoder.text(Operation::Status.as_str()).unwrap();
    encoder.text("payload").unwrap();
    encoder.map(0).unwrap();
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
