//! Authenticated development transport for disposable hardware testing.
//!
//! INFO/OPEN/STATUS are available without storage. `with_enrollment` additionally
//! borrows durable storage for signed ENROLL; no path provisions OTP or claims
//! release readiness. Legacy STATUS reports no persistent pool inspection;
//! `handle_persistent_status` authenticates a caller-recovered live directory
//! summary without fabricating absent or unrecoverable pool state.

use kes_core::{
    MAX_POOLS,
    cbor::Encoder,
    session::{
        DeviceHpkeKey, DeviceIdentityKey, INFO_TRANSCRIPT_BYTES, OpenContext, OpenRequest, Scope,
        SessionError, SessionTable, accept_open,
    },
    types::{CredentialEpoch, DeviceId, GenerationId, IncarnationId, PoolId, RequestId},
};
use kes_protocol::{
    Envelope, EnvelopeKind, ErrorScope, MAX_BACKUP_BYTES, MAX_CERTIFICATE_BYTES, MAX_FRAME_BYTES,
    MAX_MESSAGE_BYTES, MAX_SESSIONS, Operation, Status,
};
use rand_chacha::{ChaCha20Rng, rand_core::TryCryptoRng};

use crate::{
    scheduler::{RequestLease, Scheduler},
    usb::{CommandError, HandlerResult, SecureRequestHandler},
};

#[path = "development/device_management.rs"]
pub mod device_management;
#[path = "development/device_retirement.rs"]
pub mod device_retirement;
#[path = "development/enrollment.rs"]
mod enrollment;
#[path = "development/pool_deletion.rs"]
pub mod pool_deletion;
#[path = "development/pool_management.rs"]
pub mod pool_management;
pub use enrollment::EnrollmentHandler;
#[cfg(all(
    any(feature = "development", feature = "a2-development"),
    not(feature = "release")
))]
#[path = "development/inspection.rs"]
pub mod inspection;
#[path = "development/operation_status.rs"]
mod operation_status;
pub use operation_status::ManagementOperationStatus;
#[path = "development/pool_activation.rs"]
pub mod pool_activation;
#[path = "development/pool_observe.rs"]
pub mod pool_observe;
#[path = "development/pool_retrieval.rs"]
mod pool_retrieval;
pub use pool_retrieval::PoolContextResponse;
#[path = "development/pool_sessions.rs"]
pub mod pool_sessions;
#[path = "development/pool_signing.rs"]
pub mod pool_signing;
use pool_sessions::{PoolAuthority, PoolOpenCounter, PoolSessions};

const DEVELOPMENT_REVISION: u64 = 0;
const DEVELOPMENT_EPOCH: CredentialEpoch = CredentialEpoch::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DevelopmentEvidence {
    pub firmware_digest: [u8; 32],
    pub hardware_policy_digest: [u8; 32],
    pub security_version: u64,
    pub capability_evidence: &'static [u8],
}

/// Truthfully recovered, healthy live pool state for management STATUS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagementPoolStatus {
    pub pool: PoolId,
    pub incarnation: IncarnationId,
    pub revision: u64,
    pub credential_epoch: u64,
    pub management_sequence: u64,
    pub deleted: bool,
    pub revoked: bool,
    pub active: Option<GenerationId>,
    pub staged: Option<GenerationId>,
}

/// Directory authority and recovered live pools; callers must fail closed if
/// recovery cannot supply every field, including any retained tombstones.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagementStatus {
    pub revision: u64,
    pub credential_epoch: CredentialEpoch,
    pub revoked: bool,
    pub management_sequence: u64,
    pub retired: bool,
    pub pools: [Option<ManagementPoolStatus>; MAX_POOLS],
}

pub struct DevelopmentHandler<R: TryCryptoRng = ChaCha20Rng> {
    device: DeviceId,
    identity: DeviceIdentityKey,
    hpke: DeviceHpkeKey,
    boot_nonce: [u8; 32],
    machine_verification_key: [u8; 32],
    rng: R,
    evidence: DevelopmentEvidence,
    completion_clock: Option<fn() -> u64>,
    open_counter: u64,
    response_sequence: u64,
    sessions: SessionTable,
    pool_sessions: PoolSessions,
    info_scratch: [u8; INFO_TRANSCRIPT_BYTES],
}

impl<R: TryCryptoRng> DevelopmentHandler<R> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        device: DeviceId,
        identity: DeviceIdentityKey,
        hpke: DeviceHpkeKey,
        boot_nonce: [u8; 32],
        machine_verification_key: [u8; 32],
        rng: R,
        evidence: DevelopmentEvidence,
    ) -> Self {
        Self {
            device,
            identity,
            hpke,
            boot_nonce,
            machine_verification_key,
            rng,
            evidence,
            completion_clock: None,
            open_counter: 0,
            response_sequence: 0,
            sessions: SessionTable::new(),
            pool_sessions: PoolSessions::new(device, boot_nonce),
            info_scratch: [0; INFO_TRANSCRIPT_BYTES],
        }
    }

    pub fn with_completion_clock(mut self, clock: fn() -> u64) -> Self {
        self.completion_clock = Some(clock);
        self
    }

    /// Run recovery with the same health-checked entropy source used for OPEN.
    pub fn with_entropy<T>(&mut self, f: impl FnOnce(&mut R) -> T) -> T {
        f(&mut self.rng)
    }
    /// Retire a pool session after a durably committed credential change.
    pub fn invalidate_pool_session(&mut self, slot: kes_core::types::HardwareSlot) {
        self.pool_sessions.invalidate_slot(slot, &mut self.sessions);
    }
    /// Retire all pool sessions without disturbing the management ACK session.
    pub fn invalidate_all_pool_sessions(&mut self) {
        self.pool_sessions.disconnect(&mut self.sessions);
    }

    /// Discard management authority when a credential write has an uncertain result.
    pub fn invalidate_management_session(&mut self) {
        self.sessions.invalidate_scope(Scope::Management);
        self.response_sequence = 0;
    }

    /// Complete an attested backup with the existing identity key and entropy.
    pub fn with_identity_and_entropy<T>(
        &mut self,
        f: impl FnOnce(&DeviceIdentityKey, &mut R) -> T,
    ) -> T {
        f(&self.identity, &mut self.rng)
    }

    /// Produce signed INFO from freshly recovered directory authorities.
    pub fn handle_persistent_info(
        &mut self,
        request: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
        lease: RequestLease,
        authorities: &[Option<PoolAuthority>; MAX_POOLS],
    ) -> Result<HandlerResult, CommandError> {
        if request.operation != Operation::Info {
            return Err(invalid_frame());
        }
        let mut counters = [None; MAX_POOLS];
        for (index, authority) in authorities.iter().enumerate() {
            if let Some(authority) = authority {
                counters[index] = Some(
                    self.pool_sessions
                        .info_counter(*authority, &mut self.sessions),
                );
            } else {
                self.pool_sessions.invalidate_slot(
                    kes_core::types::HardwareSlot::new(index).expect("bounded slot"),
                    &mut self.sessions,
                );
            }
        }
        let response_length = self.info_with_counters(request, response, &counters)?;
        Ok(HandlerResult {
            response_length,
            completed_at_ms: self
                .completion_clock
                .map_or(lease.admitted_at_ms(), |clock| clock()),
        })
    }

    /// Authenticate an OPEN against a freshly recovered pool credential.
    pub fn handle_pool_open(
        &mut self,
        request: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
        lease: RequestLease,
        authority: PoolAuthority,
    ) -> Result<HandlerResult, CommandError> {
        let open = parse_open_request(request)?;
        let pending = self
            .pool_sessions
            .prepare_open(
                authority,
                &open,
                &self.hpke,
                &mut self.rng,
                &mut self.sessions,
            )
            .map_err(session_error)?;
        let context = pending.context();
        let fields = pending.response_fields();
        let length = encode_open_response(
            response,
            context,
            fields.session_id,
            fields.challenge_acknowledgement,
            [0; 32],
        )?;
        let unsigned = Envelope::parse(&response[..length], EnvelopeKind::OpenResponse)
            .map_err(|_| unavailable())?;
        let accepted = pending.commit(unsigned.map()).map_err(session_error)?;
        let response_length = encode_open_response(
            response,
            context,
            accepted.session_id,
            accepted.challenge_acknowledgement,
            accepted.mac,
        )?;
        Ok(HandlerResult {
            response_length,
            completed_at_ms: self
                .completion_clock
                .map_or(lease.admitted_at_ms(), |clock| clock()),
        })
    }

    /// Authenticate and report a fully recovered persistent management view.
    pub fn handle_persistent_status(
        &mut self,
        request: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
        lease: RequestLease,
        status: &ManagementStatus,
    ) -> Result<HandlerResult, CommandError> {
        if request.operation != Operation::Status {
            return Err(CommandError {
                scope: ErrorScope::Device,
                status: Status::UnsupportedOperation,
            });
        }
        let response_length = self.status_with_summary(
            request,
            response,
            status.credential_epoch,
            status.revoked,
            Some(status),
        )?;
        Ok(HandlerResult {
            response_length,
            completed_at_ms: self
                .completion_clock
                .map_or(lease.admitted_at_ms(), |clock| clock()),
        })
    }

    /// Borrow scoped flash and independently owned workspaces for one dispatch.
    /// The caller must explicitly provision the directory beforehand; neither
    /// this adapter nor ordinary boot initializes blank or damaged storage.
    pub fn with_enrollment<'a, 'key, 'work, F: kes_core::journal::Flash>(
        &'a mut self,
        storage: &'a kes_core::enrollment::EnrollmentStorage<'key>,
        flash: &'a mut F,
        work: &'a mut kes_core::journal::Workspaces<'work>,
    ) -> EnrollmentHandler<'a, 'key, 'work, R, F> {
        EnrollmentHandler::new(self, storage, flash, work)
    }

    /// Invalidate per-connection secrets without resetting the per-boot OPEN
    /// counter; a bus reset must not make an earlier OPEN transcript reusable.
    pub fn disconnect(&mut self) {
        self.sessions.invalidate_all();
        self.response_sequence = 0;
    }

    fn info(
        &mut self,
        request: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
    ) -> Result<usize, CommandError> {
        self.info_with_counters(request, response, &[])
    }

    fn info_with_counters(
        &mut self,
        request: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
        pool_counters: &[Option<PoolOpenCounter>],
    ) -> Result<usize, CommandError> {
        let request_id = request_id(request)?;
        let challenge = array::<32>(request.payload(), "challenge")?;
        let unsigned_length = encode_info_response(
            response,
            self.device,
            request_id,
            challenge,
            self.identity.verification_key(),
            self.hpke.public_key(),
            self.boot_nonce,
            self.open_counter,
            pool_counters,
            self.evidence,
            [0; 64],
        )?;
        let unsigned = Envelope::parse(&response[..unsigned_length], EnvelopeKind::InfoResponse)
            .map_err(|_| unavailable())?;
        let signature = self
            .identity
            .sign_info(
                unsigned.map(),
                self.device,
                request_id,
                &challenge,
                &mut self.info_scratch,
            )
            .map_err(session_error)?;
        encode_info_response(
            response,
            self.device,
            request_id,
            challenge,
            self.identity.verification_key(),
            self.hpke.public_key(),
            self.boot_nonce,
            self.open_counter,
            pool_counters,
            self.evidence,
            signature,
        )
    }

    fn open(
        &mut self,
        envelope: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
    ) -> Result<usize, CommandError> {
        self.open_with_credential(
            envelope,
            response,
            DEVELOPMENT_EPOCH,
            self.machine_verification_key,
        )
    }

    fn open_with_credential(
        &mut self,
        envelope: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
        epoch: CredentialEpoch,
        public_key: [u8; 32],
    ) -> Result<usize, CommandError> {
        let request = parse_open_request(envelope)?;
        if request.context.scope != Scope::Management {
            return Err(CommandError {
                scope: ErrorScope::Pool,
                status: Status::WrongPool,
            });
        }
        let expected = OpenContext::new(
            self.device,
            self.boot_nonce,
            Scope::Management,
            epoch,
            self.open_counter,
            request.context.request,
        );
        let accepted = accept_open(expected, &request, &self.hpke, &public_key, &mut self.rng)
            .map_err(session_error)?;
        let fields = accepted.response_fields();
        let unsigned_length = encode_open_response(
            response,
            expected,
            fields.session_id,
            fields.challenge_acknowledgement,
            [0; 32],
        )?;
        let authenticated = {
            let unsigned =
                Envelope::parse(&response[..unsigned_length], EnvelopeKind::OpenResponse)
                    .map_err(|_| unavailable())?;
            accepted
                .commit(&mut self.open_counter, &mut self.sessions, unsigned.map())
                .map_err(session_error)?
        };
        self.response_sequence = 0;
        encode_open_response(
            response,
            expected,
            authenticated.session_id,
            authenticated.challenge_acknowledgement,
            authenticated.mac,
        )
    }

    fn status(
        &mut self,
        envelope: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
    ) -> Result<usize, CommandError> {
        self.status_with_credential(envelope, response, DEVELOPMENT_EPOCH, false)
    }

    fn status_with_credential(
        &mut self,
        envelope: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
        epoch: CredentialEpoch,
        revoked: bool,
    ) -> Result<usize, CommandError> {
        self.status_with_summary(envelope, response, epoch, revoked, None)
    }

    fn status_with_summary(
        &mut self,
        envelope: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
        epoch: CredentialEpoch,
        revoked: bool,
        status: Option<&ManagementStatus>,
    ) -> Result<usize, CommandError> {
        let request_session = array::<16>(envelope.map(), "session")?;
        let session = self
            .sessions
            .get_mut(Scope::Management)
            .filter(|session| session.session_id() == &request_session)
            .ok_or(CommandError {
                scope: ErrorScope::Device,
                status: Status::AuthFailed,
            })?;
        let authenticated = session
            .authenticate_request(envelope.map(), epoch, revoked)
            .map_err(session_error)?;
        let unsigned_length = encode_status_response(
            response,
            self.device,
            request_session,
            self.response_sequence,
            authenticated.sequence,
            authenticated.request,
            [0; 32],
            status,
        )?;
        let mac = {
            let unsigned =
                Envelope::parse(&response[..unsigned_length], EnvelopeKind::DeviceResponse)
                    .map_err(|_| unavailable())?;
            session
                .response_mac(unsigned.map(), authenticated)
                .map_err(session_error)?
        };
        let length = encode_status_response(
            response,
            self.device,
            request_session,
            self.response_sequence,
            authenticated.sequence,
            authenticated.request,
            mac,
            status,
        )?;
        self.response_sequence = self.response_sequence.checked_add(1).ok_or(CommandError {
            scope: ErrorScope::Device,
            status: Status::Replay,
        })?;
        Ok(length)
    }
}

impl<R: TryCryptoRng> SecureRequestHandler for DevelopmentHandler<R> {
    fn handle(
        &mut self,
        request: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
        lease: RequestLease,
        _scheduler: &mut Scheduler,
    ) -> Result<HandlerResult, CommandError> {
        let response_length = match request.operation {
            Operation::Info => self.info(request, response)?,
            Operation::Open => self.open(request, response)?,
            Operation::Status => self.status(request, response)?,
            _ => {
                return Err(CommandError {
                    scope: ErrorScope::Device,
                    status: Status::UnsupportedOperation,
                });
            }
        };
        let completed_at_ms = self
            .completion_clock
            .map_or(lease.admitted_at_ms(), |clock| clock());
        Ok(HandlerResult {
            response_length,
            completed_at_ms,
        })
    }
}

fn parse_open_request(envelope: Envelope<'_>) -> Result<OpenRequest, CommandError> {
    let map = envelope.map();
    let pool = map.required("pool").map_err(|_| invalid_frame())?;
    let incarnation = map.required("incarnation").map_err(|_| invalid_frame())?;
    let scope = match (pool.is_null(), incarnation.is_null()) {
        (true, true) => Scope::Management,
        (false, false) => Scope::Pool {
            pool: PoolId::try_from(pool.bytes().map_err(|_| invalid_frame())?)
                .map_err(|_| invalid_frame())?,
            incarnation: IncarnationId::try_from(incarnation.bytes().map_err(|_| invalid_frame())?)
                .map_err(|_| invalid_frame())?,
        },
        _ => return Err(invalid_frame()),
    };
    let payload = envelope.payload();
    let context = OpenContext::new(
        DeviceId::try_from(bytes(map, "device")?).map_err(|_| invalid_frame())?,
        array(payload, "boot_nonce")?,
        scope,
        CredentialEpoch::new(uint(payload, "credential_epoch")?),
        uint(payload, "open_counter")?,
        request_id(envelope)?,
    );
    Ok(OpenRequest {
        context,
        encapsulation: array(payload, "encapsulation")?,
        ciphertext: array(payload, "ciphertext")?,
        signature: array(payload, "signature")?,
    })
}

fn request_id(envelope: Envelope<'_>) -> Result<RequestId, CommandError> {
    RequestId::try_from(bytes(envelope.map(), "request")?).map_err(|_| invalid_frame())
}

fn bytes<'a>(map: kes_core::cbor::Map<'a>, key: &str) -> Result<&'a [u8], CommandError> {
    map.required(key)
        .and_then(|value| value.bytes())
        .map_err(|_| invalid_frame())
}

fn array<const N: usize>(map: kes_core::cbor::Map<'_>, key: &str) -> Result<[u8; N], CommandError> {
    bytes(map, key)?.try_into().map_err(|_| invalid_frame())
}

fn uint(map: kes_core::cbor::Map<'_>, key: &str) -> Result<u64, CommandError> {
    map.required(key)
        .and_then(|value| value.uint())
        .map_err(|_| invalid_frame())
}

#[allow(clippy::too_many_arguments)]
fn encode_info_response(
    output: &mut [u8],
    device: DeviceId,
    request: RequestId,
    challenge: [u8; 32],
    identity_public_key: [u8; 32],
    hpke_public_key: [u8; 32],
    boot_nonce: [u8; 32],
    open_counter: u64,
    pool_counters: &[Option<PoolOpenCounter>],
    evidence: DevelopmentEvidence,
    signature: [u8; 64],
) -> Result<usize, CommandError> {
    let mut encoder = Encoder::new(output);
    encoder.map(7).map_err(|_| unavailable())?;
    encoder.text("op").map_err(|_| unavailable())?;
    encoder.text("INFO").map_err(|_| unavailable())?;
    encoder.text("device").map_err(|_| unavailable())?;
    encoder
        .bytes(device.as_bytes())
        .map_err(|_| unavailable())?;
    encoder.text("status").map_err(|_| unavailable())?;
    encoder.text("OK").map_err(|_| unavailable())?;
    encoder.text("payload").map_err(|_| unavailable())?;
    encoder.map(11).map_err(|_| unavailable())?;
    encoder.text("limits").map_err(|_| unavailable())?;
    encoder.map(6).map_err(|_| unavailable())?;
    encoder.text("pools").map_err(|_| unavailable())?;
    encoder.uint(MAX_POOLS as u64).map_err(|_| unavailable())?;
    encoder.text("sessions").map_err(|_| unavailable())?;
    encoder
        .uint(MAX_SESSIONS as u64)
        .map_err(|_| unavailable())?;
    encoder.text("frame_bytes").map_err(|_| unavailable())?;
    encoder
        .uint(MAX_FRAME_BYTES as u64)
        .map_err(|_| unavailable())?;
    encoder.text("backup_bytes").map_err(|_| unavailable())?;
    encoder
        .uint(MAX_BACKUP_BYTES as u64)
        .map_err(|_| unavailable())?;
    encoder.text("message_bytes").map_err(|_| unavailable())?;
    encoder
        .uint(MAX_MESSAGE_BYTES as u64)
        .map_err(|_| unavailable())?;
    encoder
        .text("certificate_bytes")
        .map_err(|_| unavailable())?;
    encoder
        .uint(MAX_CERTIFICATE_BYTES as u64)
        .map_err(|_| unavailable())?;
    encoder.text("challenge").map_err(|_| unavailable())?;
    encoder.bytes(&challenge).map_err(|_| unavailable())?;
    encoder.text("boot_nonce").map_err(|_| unavailable())?;
    encoder.bytes(&boot_nonce).map_err(|_| unavailable())?;
    encoder.text("open_counters").map_err(|_| unavailable())?;
    encoder
        .array(1 + pool_counters.iter().flatten().count())
        .map_err(|_| unavailable())?;
    encoder.map(3).map_err(|_| unavailable())?;
    encoder.text("pool").map_err(|_| unavailable())?;
    encoder.null().map_err(|_| unavailable())?;
    encoder.text("incarnation").map_err(|_| unavailable())?;
    encoder.null().map_err(|_| unavailable())?;
    encoder.text("open_counter").map_err(|_| unavailable())?;
    encoder.uint(open_counter).map_err(|_| unavailable())?;
    for counter in pool_counters.iter().flatten() {
        counter.encode(&mut encoder).map_err(|_| unavailable())?;
    }
    encoder.text("security_mode").map_err(|_| unavailable())?;
    encoder.text("development").map_err(|_| unavailable())?;
    encoder.text("firmware_digest").map_err(|_| unavailable())?;
    encoder
        .bytes(&evidence.firmware_digest)
        .map_err(|_| unavailable())?;
    encoder.text("hpke_public_key").map_err(|_| unavailable())?;
    encoder.bytes(&hpke_public_key).map_err(|_| unavailable())?;
    encoder
        .text("security_version")
        .map_err(|_| unavailable())?;
    encoder
        .uint(evidence.security_version)
        .map_err(|_| unavailable())?;
    encoder
        .text("capability_evidence")
        .map_err(|_| unavailable())?;
    encoder
        .bytes(evidence.capability_evidence)
        .map_err(|_| unavailable())?;
    encoder
        .text("identity_public_key")
        .map_err(|_| unavailable())?;
    encoder
        .bytes(&identity_public_key)
        .map_err(|_| unavailable())?;
    encoder
        .text("hardware_policy_digest")
        .map_err(|_| unavailable())?;
    encoder
        .bytes(&evidence.hardware_policy_digest)
        .map_err(|_| unavailable())?;
    encoder.text("request").map_err(|_| unavailable())?;
    encoder
        .bytes(request.as_bytes())
        .map_err(|_| unavailable())?;
    encoder.text("version").map_err(|_| unavailable())?;
    encoder.uint(1).map_err(|_| unavailable())?;
    encoder.text("signature").map_err(|_| unavailable())?;
    encoder.bytes(&signature).map_err(|_| unavailable())?;
    finish(encoder)
}

fn encode_open_response(
    output: &mut [u8],
    context: OpenContext,
    session: [u8; 16],
    challenge_acknowledgement: [u8; 32],
    mac: [u8; 32],
) -> Result<usize, CommandError> {
    let mut encoder = Encoder::new(output);
    encoder.map(9).map_err(|_| unavailable())?;
    encoder.text("op").map_err(|_| unavailable())?;
    encoder.text("OPEN").map_err(|_| unavailable())?;
    encoder.text("mac").map_err(|_| unavailable())?;
    encoder.bytes(&mac).map_err(|_| unavailable())?;
    encoder.text("pool").map_err(|_| unavailable())?;
    match context.scope {
        Scope::Management => encoder.null(),
        Scope::Pool { pool, .. } => encoder.bytes(pool.as_bytes()),
    }
    .map_err(|_| unavailable())?;
    encoder.text("device").map_err(|_| unavailable())?;
    encoder
        .bytes(context.device.as_bytes())
        .map_err(|_| unavailable())?;
    encoder.text("status").map_err(|_| unavailable())?;
    encoder.text("OK").map_err(|_| unavailable())?;
    encoder.text("payload").map_err(|_| unavailable())?;
    encoder.map(2).map_err(|_| unavailable())?;
    encoder.text("session").map_err(|_| unavailable())?;
    encoder.bytes(&session).map_err(|_| unavailable())?;
    encoder
        .text("challenge_acknowledgement")
        .map_err(|_| unavailable())?;
    encoder
        .bytes(&challenge_acknowledgement)
        .map_err(|_| unavailable())?;
    encoder.text("request").map_err(|_| unavailable())?;
    encoder
        .bytes(context.request.as_bytes())
        .map_err(|_| unavailable())?;
    encoder.text("version").map_err(|_| unavailable())?;
    encoder.uint(1).map_err(|_| unavailable())?;
    encoder.text("incarnation").map_err(|_| unavailable())?;
    match context.scope {
        Scope::Management => encoder.null(),
        Scope::Pool { incarnation, .. } => encoder.bytes(incarnation.as_bytes()),
    }
    .map_err(|_| unavailable())?;
    finish(encoder)
}

#[allow(clippy::too_many_arguments)]
fn encode_status_response(
    output: &mut [u8],
    device: DeviceId,
    session: [u8; 16],
    sequence: u64,
    request_sequence: u64,
    request: RequestId,
    mac: [u8; 32],
    status: Option<&ManagementStatus>,
) -> Result<usize, CommandError> {
    let mut encoder = Encoder::new(output);
    encoder.map(12).map_err(|_| unavailable())?;
    encoder.text("op").map_err(|_| unavailable())?;
    encoder.text("STATUS").map_err(|_| unavailable())?;
    encoder.text("mac").map_err(|_| unavailable())?;
    encoder.bytes(&mac).map_err(|_| unavailable())?;
    encoder.text("seq").map_err(|_| unavailable())?;
    encoder.uint(sequence).map_err(|_| unavailable())?;
    encoder.text("pool").map_err(|_| unavailable())?;
    encoder.null().map_err(|_| unavailable())?;
    encoder.text("device").map_err(|_| unavailable())?;
    encoder
        .bytes(device.as_bytes())
        .map_err(|_| unavailable())?;
    encoder.text("status").map_err(|_| unavailable())?;
    encoder.text("OK").map_err(|_| unavailable())?;
    encoder.text("payload").map_err(|_| unavailable())?;
    encoder.map(10).map_err(|_| unavailable())?;
    encoder.text("active").map_err(|_| unavailable())?;
    encoder.null().map_err(|_| unavailable())?;
    encoder.text("health").map_err(|_| unavailable())?;
    encoder.text("healthy").map_err(|_| unavailable())?;
    encoder.text("staged").map_err(|_| unavailable())?;
    encoder.null().map_err(|_| unavailable())?;
    encoder.text("revoked").map_err(|_| unavailable())?;
    encoder
        .boolean(status.is_some_and(|status| status.revoked))
        .map_err(|_| unavailable())?;
    encoder.text("revision").map_err(|_| unavailable())?;
    encoder
        .uint(status.map_or(DEVELOPMENT_REVISION, |status| status.revision))
        .map_err(|_| unavailable())?;
    encoder.text("directory").map_err(|_| unavailable())?;
    encoder
        .array(status.map_or(0, |status| status.pools.iter().flatten().count()))
        .map_err(|_| unavailable())?;
    if let Some(status) = status {
        for pool in status.pools.iter().flatten() {
            encode_management_pool(&mut encoder, pool)?;
        }
    }
    encoder.text("security_mode").map_err(|_| unavailable())?;
    encoder.text("development").map_err(|_| unavailable())?;
    encoder.text("blocking_reason").map_err(|_| unavailable())?;
    encoder
        .text(if status.is_some_and(|status| status.retired) {
            "device retired: all pool authorization and device-held keys removed"
        } else if status.is_some() {
            "development firmware: release security unavailable"
        } else {
            "development firmware: persistent pool state is unavailable"
        })
        .map_err(|_| unavailable())?;
    encoder
        .text("credential_epoch")
        .map_err(|_| unavailable())?;
    encoder
        .uint(
            status
                .map_or(DEVELOPMENT_EPOCH, |status| status.credential_epoch)
                .get(),
        )
        .map_err(|_| unavailable())?;
    encoder
        .text("management_sequence")
        .map_err(|_| unavailable())?;
    encoder
        .uint(status.map_or(0, |status| status.management_sequence))
        .map_err(|_| unavailable())?;
    encoder.text("request").map_err(|_| unavailable())?;
    encoder
        .bytes(request.as_bytes())
        .map_err(|_| unavailable())?;
    encoder.text("session").map_err(|_| unavailable())?;
    encoder.bytes(&session).map_err(|_| unavailable())?;
    encoder.text("version").map_err(|_| unavailable())?;
    encoder.uint(1).map_err(|_| unavailable())?;
    encoder.text("incarnation").map_err(|_| unavailable())?;
    encoder.null().map_err(|_| unavailable())?;
    encoder.text("request_seq").map_err(|_| unavailable())?;
    encoder.uint(request_sequence).map_err(|_| unavailable())?;
    finish(encoder)
}

fn encode_management_pool(
    encoder: &mut Encoder<'_>,
    pool: &ManagementPoolStatus,
) -> Result<(), CommandError> {
    let encode = |encoder: &mut Encoder<'_>| -> Result<(), kes_core::cbor::Error> {
        encoder.map(10)?;
        encoder.text("pool")?;
        encoder.bytes(pool.pool.as_bytes())?;
        encoder.text("active")?;
        match pool.active {
            Some(generation) => encoder.bytes(generation.as_bytes())?,
            None => encoder.null()?,
        }
        encoder.text("health")?;
        encoder.text("healthy")?;
        encoder.text("staged")?;
        match pool.staged {
            Some(generation) => encoder.bytes(generation.as_bytes())?,
            None => encoder.null()?,
        }
        encoder.text("deleted")?;
        encoder.boolean(pool.deleted)?;
        encoder.text("revoked")?;
        encoder.boolean(pool.revoked)?;
        encoder.text("revision")?;
        encoder.uint(pool.revision)?;
        encoder.text("incarnation")?;
        encoder.bytes(pool.incarnation.as_bytes())?;
        encoder.text("credential_epoch")?;
        encoder.uint(pool.credential_epoch)?;
        encoder.text("management_sequence")?;
        encoder.uint(pool.management_sequence)?;
        Ok(())
    };
    encode(encoder).map_err(|_| unavailable())
}

fn finish(encoder: Encoder<'_>) -> Result<usize, CommandError> {
    encoder
        .finish()
        .map(|encoded| encoded.encoded().len())
        .map_err(|_| unavailable())
}

fn session_error(error: SessionError) -> CommandError {
    let status = match error {
        SessionError::Sequence | SessionError::CounterOverflow => Status::Replay,
        SessionError::Capacity => Status::Capacity,
        SessionError::Entropy => Status::EntropyFailure,
        SessionError::Cbor(_) | SessionError::InvalidStructure | SessionError::BufferTooSmall => {
            Status::InvalidFrame
        }
        SessionError::WrongDevice => Status::WrongDevice,
        SessionError::WrongScope => Status::WrongPool,
        SessionError::WrongSession
        | SessionError::ChallengeMismatch
        | SessionError::CredentialChanged
        | SessionError::Revoked
        | SessionError::Authentication
        | SessionError::Hpke => Status::AuthFailed,
    };
    CommandError {
        scope: ErrorScope::Device,
        status,
    }
}

const fn invalid_frame() -> CommandError {
    CommandError {
        scope: ErrorScope::Device,
        status: Status::InvalidFrame,
    }
}

const fn unavailable() -> CommandError {
    CommandError {
        scope: ErrorScope::Device,
        status: Status::DeviceUnavailable,
    }
}
