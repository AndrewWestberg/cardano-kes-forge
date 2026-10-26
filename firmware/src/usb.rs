//! Single-flight USB framing and secure dispatch.
//!
//! The host owns service queues. This module owns exactly one non-secure body
//! buffer; `Gateway` owns the one secure request and one secure response buffer.

use kes_core::{
    activation::OperationError, certificate::CertificateError, crypto::CryptoError,
    journal::JournalError, state::StateError,
};
use kes_protocol::{
    Envelope, EnvelopeKind, Error as ProtocolError, ErrorScope, MAX_FRAME_BYTES, ReceiverState,
    STATUS_BUDGET_MS, Status,
};
use zeroize::Zeroize;

use crate::{
    scheduler::{RequestLease, Scheduler, SchedulerError},
    security::gateway::{Gateway, GatewayError},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveStatus {
    Pending,
    Ready,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiveProgress {
    pub consumed: usize,
    pub status: ReceiveStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandError {
    pub scope: ErrorScope,
    pub status: Status,
}

impl CommandError {
    pub const fn from_operation(scope: ErrorScope, error: OperationError) -> Self {
        let status = match error {
            OperationError::State(error) => state_status(error),
            OperationError::Journal(error) => journal_status(error),
            OperationError::Invalidated | OperationError::SelfVerification => Status::StateDamaged,
        };
        Self { scope, status }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsbCause {
    Protocol(ProtocolError),
    Gateway(GatewayError),
    Scheduler(SchedulerError),
    Command(CommandError),
    InvalidResponse,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UsbError {
    pub scope: ErrorScope,
    pub status: Status,
    pub cause: UsbCause,
}

impl UsbError {
    const fn protocol(error: ProtocolError) -> Self {
        Self {
            scope: ErrorScope::Device,
            status: error.status(),
            cause: UsbCause::Protocol(error),
        }
    }

    const fn gateway(error: GatewayError) -> Self {
        let status = match error {
            GatewayError::Busy => Status::Busy,
            GatewayError::Empty | GatewayError::Oversize | GatewayError::LengthMismatch => {
                Status::InvalidFrame
            }
            GatewayError::ResponseTooLarge
            | GatewayError::OutputTooSmall
            | GatewayError::KeyDerivation => Status::DeviceUnavailable,
        };
        Self {
            scope: ErrorScope::Device,
            status,
            cause: UsbCause::Gateway(error),
        }
    }

    const fn scheduler(error: SchedulerError, scope: ErrorScope) -> Self {
        let status = match error {
            SchedulerError::Busy | SchedulerError::GenerationBusy => Status::Busy,
            SchedulerError::Expired => Status::DeadlineExceeded,
            SchedulerError::ClockRegressed
            | SchedulerError::DeadlineOverflow
            | SchedulerError::InvalidLease
            | SchedulerError::TokenExhausted
            | SchedulerError::WrongOperation
            | SchedulerError::InvalidLeafCount => Status::DeviceUnavailable,
        };
        Self {
            scope,
            status,
            cause: UsbCause::Scheduler(error),
        }
    }

    const fn command(error: CommandError) -> Self {
        Self {
            scope: error.scope,
            status: error.status,
            cause: UsbCause::Command(error),
        }
    }

    const fn invalid_response(scope: ErrorScope) -> Self {
        Self {
            scope,
            status: Status::DeviceUnavailable,
            cause: UsbCause::InvalidResponse,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandlerResult {
    pub response_length: usize,
    pub completed_at_ms: u64,
}

/// Authenticates and executes one parsed request using the exact secure bytes.
///
/// Implementations must verify INFO/OPEN/session authority before mutation and
/// must return a real encoded response or a typed scoped error. The scheduler
/// reference permits GENERATE to register its single cooperative job; it owns
/// no request body and is not a device-side service queue.
pub trait SecureRequestHandler {
    fn handle(
        &mut self,
        request: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
        lease: RequestLease,
        scheduler: &mut Scheduler,
    ) -> Result<HandlerResult, CommandError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponseFrame {
    pub prefix: [u8; 4],
    pub body_length: usize,
}

pub struct UsbDispatcher {
    receive: [u8; MAX_FRAME_BYTES],
    receiver: ReceiverState,
    gateway: Gateway,
    scheduler: Scheduler,
}

impl UsbDispatcher {
    pub const fn new() -> Self {
        Self {
            receive: [0; MAX_FRAME_BYTES],
            receiver: ReceiverState::new(),
            gateway: Gateway::new(),
            scheduler: Scheduler::new(),
        }
    }

    pub fn receive(&mut self, input: &[u8], now_ms: u64) -> Result<ReceiveProgress, UsbError> {
        if self.receiver.complete(&self.receive).is_some() {
            return Err(UsbError::scheduler(
                SchedulerError::Busy,
                ErrorScope::Device,
            ));
        }
        let consumed = match self.receiver.push(&mut self.receive, input, now_ms) {
            Ok(consumed) => consumed,
            Err(error) => {
                self.discard_request();
                return Err(UsbError::protocol(error));
            }
        };
        let status = if self.receiver.complete(&self.receive).is_some() {
            ReceiveStatus::Ready
        } else {
            ReceiveStatus::Pending
        };
        Ok(ReceiveProgress { consumed, status })
    }

    pub fn check_receive_timeout(&mut self, now_ms: u64) -> Result<(), UsbError> {
        match self.receiver.check_timeout(now_ms) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.discard_request();
                Err(UsbError::protocol(error))
            }
        }
    }

    pub fn discard_request(&mut self) {
        self.receive.zeroize();
        self.receiver.reset();
    }

    /// Executes the complete frame and copies only its response body back to
    /// non-secure memory. The caller writes `prefix` then that exact body.
    pub fn dispatch(
        &mut self,
        now_ms: u64,
        output: &mut [u8],
        handler: &mut impl SecureRequestHandler,
    ) -> Result<ResponseFrame, UsbError> {
        let body = self
            .receiver
            .complete(&self.receive)
            .ok_or_else(|| UsbError::protocol(ProtocolError::Incomplete))?;
        let admitted = self.gateway.admit(body, body.len());
        self.receive.zeroize();
        self.receiver.reset();
        let mut transaction = admitted.map_err(UsbError::gateway)?;
        let scheduler = &mut self.scheduler;

        let (handled, lease, scope, response_kind) = {
            let (request_bytes, response) = transaction.buffers();
            let envelope =
                Envelope::parse_device_ingress(request_bytes).map_err(UsbError::protocol)?;
            let scope = request_scope(envelope);
            let budget_ms = request_budget(envelope).map_err(UsbError::protocol)?;
            let lease = scheduler
                .admit(envelope.operation, budget_ms, now_ms)
                .map_err(|error| UsbError::scheduler(error, scope))?;
            let handled = match handler.handle(envelope, response, lease, scheduler) {
                Ok(handled) => handled,
                Err(error) => {
                    scheduler
                        .abort(lease)
                        .map_err(|cause| UsbError::scheduler(cause, scope))?;
                    return Err(UsbError::command(error));
                }
            };
            (handled, lease, scope, response_kind(envelope.kind))
        };

        let valid_response = transaction
            .response()
            .get(..handled.response_length)
            .is_some_and(|response| Envelope::parse(response, response_kind).is_ok());
        if !valid_response {
            scheduler
                .abort(lease)
                .map_err(|error| UsbError::scheduler(error, scope))?;
            return Err(UsbError::invalid_response(scope));
        }
        scheduler
            .finish(lease, handled.completed_at_ms)
            .map_err(|error| UsbError::scheduler(error, scope))?;
        let body_length = transaction
            .complete(handled.response_length, output)
            .map_err(UsbError::gateway)?;
        let prefix = u32::try_from(body_length)
            .map_err(|_| UsbError::invalid_response(scope))?
            .to_be_bytes();
        Ok(ResponseFrame {
            prefix,
            body_length,
        })
    }

    pub fn scheduler(&self) -> &Scheduler {
        &self.scheduler
    }

    pub fn scheduler_mut(&mut self) -> &mut Scheduler {
        &mut self.scheduler
    }
}

impl Default for UsbDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

fn request_scope(envelope: Envelope<'_>) -> ErrorScope {
    if envelope
        .map()
        .get("pool")
        .ok()
        .flatten()
        .is_some_and(|pool| !pool.is_null())
    {
        ErrorScope::Pool
    } else {
        ErrorScope::Device
    }
}

fn request_budget(envelope: Envelope<'_>) -> Result<u32, ProtocolError> {
    if matches!(
        envelope.kind,
        EnvelopeKind::InfoRequest | EnvelopeKind::OpenRequest
    ) {
        return Ok(STATUS_BUDGET_MS);
    }
    u32::try_from(envelope.map().required("budget_ms")?.uint()?)
        .map_err(|_| ProtocolError::InvalidValue)
}

const fn state_status(error: StateError) -> Status {
    match error {
        StateError::Capacity | StateError::DirectoryFull => Status::Capacity,
        StateError::Unauthorized | StateError::PolicyChanged => Status::AuthFailed,
        StateError::WrongPool | StateError::WrongIncarnation => Status::WrongPool,
        StateError::WrongDevice => Status::WrongDevice,
        StateError::InvalidRecipient => Status::RecipientInvalid,
        StateError::GenerationConflict | StateError::StaleGeneration => Status::StaleGeneration,
        StateError::StagedConflict | StateError::CertificateConflict => Status::StagedConflict,
        StateError::RevisionConflict => Status::RevisionConflict,
        StateError::SecurityNotReady | StateError::DevelopmentOptInRequired => {
            Status::SecurityNotReady
        }
        StateError::Retired | StateError::Unavailable => Status::DeviceUnavailable,
        StateError::Certificate(error) => certificate_status(error),
        StateError::Crypto(error) => crypto_status(error),
        StateError::DuplicatePool
        | StateError::IncarnationConflict
        | StateError::InvalidPoolId
        | StateError::InvalidObject
        | StateError::UnsupportedVersion
        | StateError::TooLarge
        | StateError::CounterOverflow
        | StateError::Damaged
        | StateError::InvalidLifecycle
        | StateError::InvalidSecret => Status::StateDamaged,
    }
}

const fn certificate_status(error: CertificateError) -> Status {
    match error {
        CertificateError::WrongNetwork => Status::WrongNetwork,
        CertificateError::NotYetValid => Status::NotYetValid,
        CertificateError::Expired => Status::Expired,
        CertificateError::CounterNotIncreasing => Status::StaleGeneration,
        CertificateError::Cbor(_)
        | CertificateError::InvalidLength
        | CertificateError::InvalidStructure
        | CertificateError::InvalidColdKey
        | CertificateError::InvalidSignature
        | CertificateError::WrongColdKey
        | CertificateError::WrongPool
        | CertificateError::WrongKesKey
        | CertificateError::LifetimeMismatch
        | CertificateError::LifetimeOverflow => Status::CertificateInvalid,
    }
}

const fn crypto_status(error: CryptoError) -> Status {
    match error {
        CryptoError::StalePeriod => Status::StalePeriod,
        CryptoError::LifetimeExceeded => Status::Expired,
        CryptoError::InvalidLength { .. } | CryptoError::MessageTooLong => Status::InvalidFrame,
        CryptoError::UnsupportedAlgorithmVersion
        | CryptoError::InvalidPeriod
        | CryptoError::PeriodMismatch
        | CryptoError::ErasedKey
        | CryptoError::MalformedState
        | CryptoError::InvalidSignature
        | CryptoError::InvalidPublicTree
        | CryptoError::TreeMismatch
        | CryptoError::OutputInUse
        | CryptoError::GenerationIncomplete
        | CryptoError::GenerationComplete => Status::StateDamaged,
    }
}

const fn journal_status(error: JournalError) -> Status {
    match error {
        JournalError::State(error) => state_status(error),
        JournalError::EntropyFailure => Status::EntropyFailure,
        JournalError::Flash => Status::DeviceUnavailable,
        JournalError::NotCommitted => Status::NotCommitted,
        JournalError::RevisionConflict => Status::RevisionConflict,
        JournalError::Codec(_)
        | JournalError::InvalidContext
        | JournalError::SizeLimit
        | JournalError::Uninitialized
        | JournalError::AlreadyInitialized
        | JournalError::Damaged
        | JournalError::CounterOverflow
        | JournalError::ObjectMissing
        | JournalError::ObjectInvalid => Status::StateDamaged,
    }
}

const fn response_kind(request: EnvelopeKind) -> EnvelopeKind {
    match request {
        EnvelopeKind::InfoRequest => EnvelopeKind::InfoResponse,
        EnvelopeKind::OpenRequest => EnvelopeKind::OpenResponse,
        EnvelopeKind::DeviceRequest => EnvelopeKind::DeviceResponse,
        EnvelopeKind::InfoResponse
        | EnvelopeKind::OpenResponse
        | EnvelopeKind::DeviceResponse
        | EnvelopeKind::LocalRequest
        | EnvelopeKind::LocalResponse => EnvelopeKind::DeviceResponse,
    }
}

const _: () = assert!(MAX_FRAME_BYTES == 8192);
const _: () = assert!(
    core::mem::size_of::<UsbDispatcher>()
        <= 3 * MAX_FRAME_BYTES + crate::scheduler::DISPATCH_METADATA_LIMIT
);
