use crate::host::client::{AuthenticatedClient, DeviceWire, Error as ClientError};
use crate::host::config::{DaemonConfig as StaticConfig, DeviceConfig, PoolConnection};
use crate::host::{
    observation, signing,
    socket::{self, Frame, MAX_PEERS, ProtectedListener},
};
use kes_core::cbor::Encoder;
use kes_protocol::{Envelope, EnvelopeKind, MAX_FRAME_BYTES, Operation, Status};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

const MAX_POOL_ROUTES: usize = 32;
const POOL_LANES: usize = 3;
const MANAGEMENT_CELL: usize = MAX_POOL_ROUTES * POOL_LANES;
const FRAME_CELLS: usize = MANAGEMENT_CELL + 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportError {
    /// The request definitely did not enter the secure device workspace.
    Unavailable,
    /// An authenticated response failed independent host validation. The
    /// affected pool session is discarded, but unrelated routes remain usable.
    InvalidResponse,
    /// Dispatch may have entered or completed the secure workspace. The handle
    /// must not be reused because request completion is no longer knowable.
    Uncertain,
}

/// Exclusive device owner used by the daemon's single dispatcher thread.
///
/// Implementations replace `frame` with the authenticated, validated local
/// response. A timeout after any device write must return `Uncertain`.
pub trait DeviceTransport: Send + 'static {
    fn exchange(&mut self, frame: &mut Frame, remaining: Duration) -> Result<(), TransportError>;
}

#[derive(Debug)]
pub enum ConfigError {
    TooManyPools,
    DuplicateConnection,
    InvalidConnection,
    InvalidSigningContext,
    UnknownAuthorization,
}

pub struct Config {
    pub management_connection: String,
    pub pool_connections: Vec<String>,
    pub allowed_peer_uids: Vec<(u32, Vec<String>)>,
}

pub struct AuthenticatedTransport<W> {
    wire: W,
    management: DeviceConfig,
    pools: Vec<PoolConnection>,
    pool_routes: BTreeMap<String, usize>,
    management_session: Option<AuthenticatedClient>,
    pool_sessions: Vec<Option<AuthenticatedClient>>,
    signing: signing::Router,
}

impl<W: DeviceWire + Send + 'static> AuthenticatedTransport<W> {
    pub fn new(
        wire: W,
        management: DeviceConfig,
        pools: Vec<PoolConnection>,
    ) -> Result<Self, ConfigError> {
        let pool_routes = pools
            .iter()
            .enumerate()
            .map(|(index, pool)| (pool.connection_name.clone(), index))
            .collect();
        let pool_sessions = (0..pools.len()).map(|_| None).collect();
        let signing = signing::Router::new(
            pools
                .iter()
                .map(|pool| Ok((pool.connection_name.clone(), signing_binding(pool)?)))
                .collect::<Result<Vec<_>, ConfigError>>()?,
        )
        .map_err(|_| ConfigError::InvalidSigningContext)?;
        Ok(Self {
            wire,
            management,
            pools,
            pool_routes,
            management_session: None,
            pool_sessions,
            signing,
        })
    }
}

impl<W: DeviceWire + Send + 'static> DeviceTransport for AuthenticatedTransport<W> {
    fn exchange(&mut self, frame: &mut Frame, remaining: Duration) -> Result<(), TransportError> {
        let started = Instant::now();
        let request = Envelope::parse(frame.as_slice(), EnvelopeKind::LocalRequest)
            .map_err(|_| TransportError::Unavailable)?;
        let connection = request
            .map()
            .required("connection")
            .and_then(|value| value.text())
            .map_err(|_| TransportError::Unavailable)?
            .to_owned();
        let mut response = [0; MAX_FRAME_BYTES];
        let result = if connection == self.management.connection_name {
            if self.management_session.is_none() {
                self.management_session = Some(
                    AuthenticatedClient::open_management(&mut self.wire, &self.management)
                        .map_err(transport_error)?,
                );
            }
            let remaining = remaining
                .checked_sub(started.elapsed())
                .ok_or(TransportError::Unavailable)?;
            let result = self
                .management_session
                .as_mut()
                .expect("management session was established")
                .exchange_local(&mut self.wire, frame.as_slice(), &mut response, remaining);
            if result.is_err() {
                self.management_session = None;
            }
            result.map_err(transport_error)?
        } else {
            let index = *self
                .pool_routes
                .get(&connection)
                .ok_or(TransportError::Unavailable)?;
            if self.pool_sessions[index].is_none() {
                self.pool_sessions[index] = Some(
                    AuthenticatedClient::open_pool(&mut self.wire, &self.pools[index])
                        .map_err(transport_error)?,
                );
            }
            let remaining = remaining
                .checked_sub(started.elapsed())
                .ok_or(TransportError::Unavailable)?;
            let client = self.pool_sessions[index]
                .as_mut()
                .expect("pool session was established");
            let session = signing::Session {
                boot_nonce: client.boot_nonce(),
                session: client.session_id(),
            };
            let result =
                client.exchange_local(&mut self.wire, frame.as_slice(), &mut response, remaining);
            let result = match result {
                Ok(length) => length,
                Err(error) => {
                    self.pool_sessions[index] = None;
                    self.signing.disconnect(&connection);
                    return Err(transport_error(error));
                }
            };
            if self
                .signing
                .complete(
                    &connection,
                    frame.as_slice(),
                    &response[..result],
                    session,
                    started.elapsed(),
                )
                .is_err()
            {
                client.invalidate();
                self.pool_sessions[index] = None;
                self.signing.disconnect(&connection);
                return Err(TransportError::InvalidResponse);
            }
            result
        };
        frame
            .replace(&response[..result])
            .map_err(|_| TransportError::Unavailable)
    }
}

fn transport_error(error: ClientError) -> TransportError {
    match error {
        ClientError::Uncertain => TransportError::Uncertain,
        ClientError::Security | ClientError::Integrity | ClientError::Damaged => {
            TransportError::InvalidResponse
        }
        ClientError::Unavailable
        | ClientError::Conflict
        | ClientError::InProgress
        | ClientError::Unknown
        | ClientError::NotCommitted
        | ClientError::ResultReclaimed => TransportError::Unavailable,
    }
}

pub struct Daemon {
    inner: Arc<Inner>,
}

struct Inner {
    scheduler: Arc<Scheduler>,
    authorization: BTreeMap<u32, BTreeSet<String>>,
    routes: BTreeMap<String, usize>,
    management_connection: String,
    peers: AtomicUsize,
}

struct Scheduler {
    state: Mutex<SchedulerState>,
    ready: Condvar,
}

struct SchedulerState {
    cells: Vec<Option<Job>>,
    cursor: usize,
    poisoned: bool,
}

struct Job {
    frame: Frame,
    metadata: Metadata,
    deadline: Instant,
    reply: mpsc::SyncSender<Frame>,
}

#[derive(Clone)]
struct Metadata {
    connection: String,
    request: [u8; 16],
    operation: Operation,
    scope: Scope,
}

#[derive(Clone, Copy)]
enum Scope {
    Pool,
    Device,
}

#[derive(Clone, Copy)]
enum Lane {
    Signing,
    Lifecycle,
    Status,
    Management,
}

impl Daemon {
    pub fn from_static_config<W: DeviceWire + Send + 'static>(
        config: StaticConfig,
        wire: W,
    ) -> Result<(Self, PathBuf), ConfigError> {
        let socket_path = config.socket_path.clone();
        let service = Config {
            management_connection: config.device.connection_name.clone(),
            pool_connections: config
                .pools
                .iter()
                .map(|pool| pool.connection_name.clone())
                .collect(),
            allowed_peer_uids: config
                .allowed_peer_uids
                .iter()
                .map(|peer| (peer.uid, peer.connections.clone()))
                .collect(),
        };
        let transport = AuthenticatedTransport::new(wire, config.device, config.pools)?;
        Ok((Self::new(service, transport)?, socket_path))
    }

    pub fn new(config: Config, transport: impl DeviceTransport) -> Result<Self, ConfigError> {
        if config.pool_connections.len() > MAX_POOL_ROUTES {
            return Err(ConfigError::TooManyPools);
        }
        validate_connection(&config.management_connection)?;
        let mut routes = BTreeMap::new();
        for (index, connection) in config.pool_connections.iter().enumerate() {
            validate_connection(connection)?;
            if connection == &config.management_connection
                || routes.insert(connection.clone(), index).is_some()
            {
                return Err(ConfigError::DuplicateConnection);
            }
        }
        let mut authorization = BTreeMap::new();
        for (uid, names) in config.allowed_peer_uids {
            if authorization.contains_key(&uid) {
                return Err(ConfigError::DuplicateConnection);
            }
            let mut allowed = BTreeSet::new();
            for name in names {
                validate_connection(&name)?;
                if name != config.management_connection && !routes.contains_key(&name) {
                    return Err(ConfigError::UnknownAuthorization);
                }
                if !allowed.insert(name) {
                    return Err(ConfigError::DuplicateConnection);
                }
            }
            authorization.insert(uid, allowed);
        }
        let scheduler = Arc::new(Scheduler {
            state: Mutex::new(SchedulerState {
                cells: (0..FRAME_CELLS).map(|_| None).collect(),
                cursor: 0,
                poisoned: false,
            }),
            ready: Condvar::new(),
        });
        start_dispatcher(Arc::clone(&scheduler), transport);
        Ok(Self {
            inner: Arc::new(Inner {
                scheduler,
                authorization,
                routes,
                management_connection: config.management_connection,
                peers: AtomicUsize::new(0),
            }),
        })
    }

    pub fn serve(&self, socket_path: &Path) -> io::Result<()> {
        self.serve_until(socket_path, &AtomicBool::new(false))
    }

    pub fn serve_until(&self, socket_path: &Path, stop: &AtomicBool) -> io::Result<()> {
        let listener = ProtectedListener::bind(socket_path)?;
        while !stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, uid)) => {
                    if !reserve_peer(&self.inner.peers) {
                        drop(stream);
                        continue;
                    }
                    let inner = Arc::clone(&self.inner);
                    thread::spawn(move || {
                        let _permit = PeerPermit(&inner.peers);
                        let _ = serve_peer(&inner, uid, stream);
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

fn reserve_peer(peers: &AtomicUsize) -> bool {
    peers
        .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            (current < MAX_PEERS).then_some(current + 1)
        })
        .is_ok()
}

struct PeerPermit<'a>(&'a AtomicUsize);
impl Drop for PeerPermit<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn serve_peer(
    inner: &Inner,
    uid: u32,
    mut stream: std::os::unix::net::UnixStream,
) -> io::Result<()> {
    let frame = socket::read_frame(&mut stream)?;
    let (mut metadata, budget) = parse_metadata(frame.as_slice())?;
    metadata.scope = if metadata.connection == inner.management_connection {
        Scope::Device
    } else {
        Scope::Pool
    };
    let authorized = inner
        .authorization
        .get(&uid)
        .is_some_and(|connections| connections.contains(&metadata.connection));
    if !authorized || !route_matches(inner, &metadata) {
        let mut response = frame;
        encode_error(
            &mut response,
            &metadata,
            Status::AuthFailed,
            "connection is not authorized",
        )?;
        return socket::write_frame(&mut stream, &response);
    }
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(u64::from(budget)))
        .unwrap_or_else(Instant::now);
    let (sender, receiver) = mpsc::sync_channel(1);
    let cell = cell_for(inner, &metadata)?;
    let job = Job {
        frame,
        metadata: metadata.clone(),
        deadline,
        reply: sender,
    };
    match inner.scheduler.admit(cell, job) {
        Ok(()) => {}
        Err(AdmissionError::Busy(mut rejected)) => {
            encode_error(
                &mut rejected.frame,
                &metadata,
                Status::Busy,
                "request lane is occupied",
            )?;
            return socket::write_frame(&mut stream, &rejected.frame);
        }
        Err(AdmissionError::Poisoned(mut rejected)) => {
            encode_error(
                &mut rejected.frame,
                &metadata,
                Status::DeviceUnavailable,
                "device completion is uncertain",
            )?;
            return socket::write_frame(&mut stream, &rejected.frame);
        }
    }
    let response = receiver.recv().map_err(|_| {
        io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "device dispatcher stopped",
        )
    })?;
    socket::write_frame(&mut stream, &response)
}

fn parse_metadata(bytes: &[u8]) -> io::Result<(Metadata, u32)> {
    let envelope = Envelope::parse(bytes, EnvelopeKind::LocalRequest).map_err(invalid_frame)?;
    let map = envelope.map();
    let connection = map
        .required("connection")
        .and_then(|value| value.text())
        .map_err(cbor_io)?
        .to_owned();
    let request = *envelope.request().map_err(invalid_frame)?.as_bytes();
    let budget = u32::try_from(
        map.required("budget_ms")
            .and_then(|value| value.uint())
            .map_err(cbor_io)?,
    )
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid request budget"))?;
    let scope = if management_operation(envelope.operation) {
        Scope::Device
    } else {
        Scope::Pool
    };
    Ok((
        Metadata {
            connection,
            request,
            operation: envelope.operation,
            scope,
        },
        budget,
    ))
}

fn route_matches(inner: &Inner, metadata: &Metadata) -> bool {
    match metadata.scope {
        Scope::Device => {
            metadata.connection == inner.management_connection
                && management_connection_operation(metadata.operation)
        }
        Scope::Pool => {
            inner.routes.contains_key(&metadata.connection)
                && !management_operation(metadata.operation)
        }
    }
}

fn cell_for(inner: &Inner, metadata: &Metadata) -> io::Result<usize> {
    let lane = classify(metadata.operation);
    if matches!(metadata.scope, Scope::Device) || matches!(lane, Lane::Management) {
        return Ok(MANAGEMENT_CELL);
    }
    let route = *inner.routes.get(&metadata.connection).ok_or_else(|| {
        io::Error::new(io::ErrorKind::PermissionDenied, "unknown pool connection")
    })?;
    let offset = match lane {
        Lane::Signing => 0,
        Lane::Lifecycle => 1,
        Lane::Status => 2,
        Lane::Management => unreachable!(),
    };
    Ok(route * POOL_LANES + offset)
}

fn classify(operation: Operation) -> Lane {
    match operation {
        Operation::Sign => Lane::Signing,
        Operation::Status | Operation::OpStatus => Lane::Status,
        Operation::Manage
        | Operation::UpdateBegin
        | Operation::UpdateChunk
        | Operation::UpdateFinalize => Lane::Management,
        Operation::Generate
        | Operation::GetBackup
        | Operation::Certify
        | Operation::Activate
        | Operation::Schedule
        | Operation::Evolve
        | Operation::ObservePeriod => Lane::Lifecycle,
        Operation::Info | Operation::Open | Operation::DevInspect => Lane::Management,
    }
}

fn management_operation(operation: Operation) -> bool {
    matches!(
        operation,
        Operation::Manage
            | Operation::UpdateBegin
            | Operation::UpdateChunk
            | Operation::UpdateFinalize
    )
}

fn management_connection_operation(operation: Operation) -> bool {
    matches!(operation, Operation::Status | Operation::OpStatus) || management_operation(operation)
}

enum AdmissionError {
    Busy(Job),
    Poisoned(Job),
}

impl Scheduler {
    fn admit(&self, cell: usize, job: Job) -> Result<(), AdmissionError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.poisoned {
            return Err(AdmissionError::Poisoned(job));
        }
        if state.cells[cell].is_some() {
            return Err(AdmissionError::Busy(job));
        }
        state.cells[cell] = Some(job);
        self.ready.notify_one();
        Ok(())
    }

    fn next(&self) -> Job {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            for distance in 0..=MAX_POOL_ROUTES {
                let route = (state.cursor + distance) % (MAX_POOL_ROUTES + 1);
                if route == MAX_POOL_ROUTES {
                    if let Some(job) = state.cells[MANAGEMENT_CELL].take() {
                        state.cursor = 0;
                        return job;
                    }
                    continue;
                }
                for lane in 0..POOL_LANES {
                    let index = route * POOL_LANES + lane;
                    if let Some(job) = state.cells[index].take() {
                        state.cursor = route + 1;
                        return job;
                    }
                }
            }
            state = self
                .ready
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }

    fn poison(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.poisoned = true;
        for slot in &mut state.cells {
            let Some(mut job) = slot.take() else {
                continue;
            };
            let metadata = job.metadata.clone();
            let _ = encode_error(
                &mut job.frame,
                &metadata,
                Status::DeviceUnavailable,
                "device completion is uncertain",
            );
            let _ = job.reply.send(job.frame);
        }
    }
}

fn start_dispatcher(scheduler: Arc<Scheduler>, mut transport: impl DeviceTransport) {
    thread::Builder::new()
        .name("kes-forged-usb".to_owned())
        .spawn(move || {
            loop {
                let mut job = scheduler.next();
                let now = Instant::now();
                if now >= job.deadline {
                    let metadata = job.metadata.clone();
                    let _ = encode_error(
                        &mut job.frame,
                        &metadata,
                        Status::DeadlineExceeded,
                        "request expired before dispatch",
                    );
                    let _ = job.reply.send(job.frame);
                    continue;
                }
                let remaining = job.deadline.saturating_duration_since(now);
                match transport.exchange(&mut job.frame, remaining) {
                    Ok(()) if Instant::now() >= job.deadline => {
                        let metadata = job.metadata.clone();
                        let _ = encode_error(
                            &mut job.frame,
                            &metadata,
                            Status::DeadlineExceeded,
                            "device response arrived after the original deadline",
                        );
                    }
                    Ok(()) if !response_matches(&job) => {
                        let metadata = job.metadata.clone();
                        let _ = encode_error(
                            &mut job.frame,
                            &metadata,
                            Status::DeviceUnavailable,
                            "device response failed local binding validation",
                        );
                    }
                    Ok(()) => {}
                    Err(TransportError::Unavailable) => {
                        let metadata = job.metadata.clone();
                        let _ = encode_error(
                            &mut job.frame,
                            &metadata,
                            Status::DeviceUnavailable,
                            "device is unavailable",
                        );
                    }
                    Err(TransportError::InvalidResponse) => {
                        let metadata = job.metadata.clone();
                        let _ = encode_error(
                            &mut job.frame,
                            &metadata,
                            Status::DeviceUnavailable,
                            "device response failed independent validation",
                        );
                    }
                    Err(TransportError::Uncertain) => {
                        let metadata = job.metadata.clone();
                        let _ = encode_error(
                            &mut job.frame,
                            &metadata,
                            Status::DeviceUnavailable,
                            "device completion is uncertain",
                        );
                        let _ = job.reply.send(job.frame);
                        scheduler.poison();
                        continue;
                    }
                }
                let _ = job.reply.send(job.frame);
            }
        })
        .expect("failed to start the bounded USB dispatcher");
}

fn response_matches(job: &Job) -> bool {
    let Ok(response) = Envelope::parse(job.frame.as_slice(), EnvelopeKind::LocalResponse) else {
        return false;
    };
    let Ok(connection) = response
        .map()
        .required("connection")
        .and_then(|value| value.text())
    else {
        return false;
    };
    response.operation == job.metadata.operation
        && connection == job.metadata.connection
        && response
            .request()
            .is_ok_and(|request| request.as_bytes() == &job.metadata.request)
}

fn encode_error(
    frame: &mut Frame,
    metadata: &Metadata,
    status: Status,
    diagnostic: &str,
) -> io::Result<()> {
    let mut storage = [0; MAX_FRAME_BYTES];
    let mut encoder = Encoder::new(&mut storage);
    encoder.map(6).map_err(cbor_io)?;
    encoder.text("op").map_err(cbor_io)?;
    encoder.text(metadata.operation.as_str()).map_err(cbor_io)?;
    encoder.text("status").map_err(cbor_io)?;
    encoder.text(status.as_str()).map_err(cbor_io)?;
    encoder.text("payload").map_err(cbor_io)?;
    encoder.map(2).map_err(cbor_io)?;
    encoder.text("scope").map_err(cbor_io)?;
    encoder
        .text(match metadata.scope {
            Scope::Pool => "pool",
            Scope::Device => "device",
        })
        .map_err(cbor_io)?;
    encoder.text("diagnostic").map_err(cbor_io)?;
    encoder.text(diagnostic).map_err(cbor_io)?;
    encoder.text("request").map_err(cbor_io)?;
    encoder.bytes(&metadata.request).map_err(cbor_io)?;
    encoder.text("version").map_err(cbor_io)?;
    encoder.uint(1).map_err(cbor_io)?;
    encoder.text("connection").map_err(cbor_io)?;
    encoder.text(&metadata.connection).map_err(cbor_io)?;
    let encoded = encoder.finish().map_err(cbor_io)?.encoded();
    frame.replace(encoded)
}

fn signing_binding(pool: &PoolConnection) -> Result<signing::Binding, ConfigError> {
    Ok(signing::Binding {
        device: pool.device_id,
        pool: pool.pool_id,
        incarnation: pool.incarnation_id,
        network: observation::NetworkContext {
            network_magic: u32::try_from(pool.network_binding.network_magic)
                .map_err(|_| ConfigError::InvalidSigningContext)?,
            shelley_genesis_digest: decode_hex(&pool.network_binding.shelley_genesis_digest)
                .ok_or(ConfigError::InvalidSigningContext)?,
            slots_per_kes_period: pool.network_binding.slots_per_kes_period,
            max_kes_evolutions: pool.network_binding.max_kes_evolutions,
        },
    })
}

fn decode_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2 {
        return None;
    }
    let mut output = [0; N];
    for (index, pair) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
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

fn validate_connection(connection: &str) -> Result<(), ConfigError> {
    if connection.is_empty()
        || connection.len() > 64
        || !connection
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Err(ConfigError::InvalidConnection)
    } else {
        Ok(())
    }
}

fn invalid_frame(error: kes_protocol::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn cbor_io(error: kes_core::cbor::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
