//! Authenticated retrieval from freshly recovered pool state and immutable public objects.
//! No journal absence is treated as proof of non-commitment; reconciliation uses
//! only the recovered generation checkpoint and retained generation descriptors.

use super::*;
use kes_core::{
    activation::OperationContext,
    generation::{self, GenerationCoordinator, OperationStatus, PublicObjectStore},
    signing::SigningResult,
    state::{KESGeneration, Lifecycle, MAX_PUBLIC_OBJECT_BYTES, PoolRegistration},
    types::GenerationNumber,
};

/// Actual committed context returned by a pool evolution or signature.
pub enum PoolContextResponse<'a> {
    Evolved(OperationContext),
    Signed(&'a SigningResult),
    Expired(OperationContext),
}

impl<R: TryCryptoRng> DevelopmentHandler<R> {
    /// Authenticate a freshly recovered pool before any durable mutation.
    pub fn authenticate_pool_operation<'a>(
        &mut self,
        request: Envelope<'a>,
        authority: PoolAuthority,
        pool: &PoolRegistration,
    ) -> Result<kes_core::session::AuthenticatedRequest<'a>, CommandError> {
        let allowed = matches!(
            request.operation,
            Operation::Generate
                | Operation::Certify
                | Operation::Activate
                | Operation::Schedule
                | Operation::Evolve
                | Operation::Sign
                | Operation::ObservePeriod
        );
        #[cfg(all(
            any(feature = "development", feature = "a2-development"),
            not(feature = "release")
        ))]
        let allowed = allowed || request.operation == Operation::DevInspect;
        if !allowed {
            return Err(pool_error(Status::UnsupportedOperation));
        }
        require_pool(authority, pool)?;
        self.pool_sessions
            .authenticate_request(authority, request.map(), &mut self.sessions)
            .map_err(session_error)
    }

    /// Sign a response only for an already authenticated generation admission.
    #[allow(clippy::too_many_arguments)]
    pub fn respond_pool_generation(
        &mut self,
        request: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
        lease: RequestLease,
        authority: PoolAuthority,
        authenticated: kes_core::session::AuthenticatedRequest<'_>,
        pool: &PoolRegistration,
        outcome: OperationStatus,
    ) -> Result<HandlerResult, CommandError> {
        require_pool(authority, pool)?;
        self.finish_pool_retrieval(
            request,
            response,
            lease,
            authority,
            authenticated,
            RetrievalPayload::Operation { outcome, pool },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn respond_pool_descriptor(
        &mut self,
        request: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
        lease: RequestLease,
        authority: PoolAuthority,
        authenticated: kes_core::session::AuthenticatedRequest<'_>,
        pool: &PoolRegistration,
        generation: GenerationId,
    ) -> Result<HandlerResult, CommandError> {
        require_pool(authority, pool)?;
        let generation = [pool.current(), pool.staged()]
            .into_iter()
            .flatten()
            .find(|item| item.id() == generation)
            .ok_or(pool_error(Status::StaleGeneration))?;
        self.finish_pool_retrieval(
            request,
            response,
            lease,
            authority,
            authenticated,
            RetrievalPayload::Descriptor { pool, generation },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn respond_pool_context(
        &mut self,
        request: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
        lease: RequestLease,
        authority: PoolAuthority,
        authenticated: kes_core::session::AuthenticatedRequest<'_>,
        pool: &PoolRegistration,
        context: PoolContextResponse<'_>,
    ) -> Result<HandlerResult, CommandError> {
        require_pool(authority, pool)?;
        self.finish_pool_retrieval(
            request,
            response,
            lease,
            authority,
            authenticated,
            RetrievalPayload::Context(context),
        )
    }

    /// Encode current secret state only for the explicitly enabled development mode.
    #[cfg(all(
        any(feature = "development", feature = "a2-development"),
        not(feature = "release")
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn respond_pool_inspection(
        &mut self,
        request: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
        lease: RequestLease,
        authority: PoolAuthority,
        authenticated: kes_core::session::AuthenticatedRequest<'_>,
        inspection: &super::inspection::DevelopmentInspection<'_>,
    ) -> Result<HandlerResult, CommandError> {
        self.finish_pool_retrieval(
            request,
            response,
            lease,
            authority,
            authenticated,
            RetrievalPayload::Inspection(inspection),
        )
    }

    /// Return a bounded authenticated failure only after request MAC verification.
    #[allow(clippy::too_many_arguments)]
    pub fn respond_pool_error(
        &mut self,
        request: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
        lease: RequestLease,
        authority: PoolAuthority,
        authenticated: kes_core::session::AuthenticatedRequest<'_>,
        error: CommandError,
    ) -> Result<HandlerResult, CommandError> {
        if error.scope != ErrorScope::Pool
            || matches!(
                error.status,
                Status::Ok
                    | Status::InProgress
                    | Status::NotCommitted
                    | Status::Unknown
                    | Status::ResultReclaimed
            )
            || (error.status == Status::Expired
                && matches!(
                    request.operation,
                    Operation::Sign | Operation::Evolve | Operation::ObservePeriod
                ))
        {
            return Err(error);
        }
        self.finish_pool_retrieval(
            request,
            response,
            lease,
            authority,
            authenticated,
            RetrievalPayload::Failure(error.status),
        )
    }

    /// Pool STATUS exposes only this authenticated pool's recovered state.
    pub fn handle_pool_status(
        &mut self,
        request: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
        lease: RequestLease,
        authority: PoolAuthority,
        pool: &PoolRegistration,
    ) -> Result<HandlerResult, CommandError> {
        if request.operation != Operation::Status {
            return Err(pool_error(Status::UnsupportedOperation));
        }
        require_pool(authority, pool)?;
        let authenticated = self
            .pool_sessions
            .authenticate_request(authority, request.map(), &mut self.sessions)
            .map_err(session_error)?;
        if let Some(value) = request
            .payload()
            .get("generation")
            .map_err(|_| invalid_frame())?
        {
            let generation = GenerationId::try_from(value.bytes().map_err(|_| invalid_frame())?)
                .map_err(|_| invalid_frame())?;
            if ![pool.current(), pool.staged()]
                .into_iter()
                .flatten()
                .any(|item| item.id() == generation)
            {
                return self.respond_pool_error(
                    request,
                    response,
                    lease,
                    authority,
                    authenticated,
                    pool_error(Status::StaleGeneration),
                );
            }
        }
        self.finish_pool_retrieval(
            request,
            response,
            lease,
            authority,
            authenticated,
            RetrievalPayload::Status(pool),
        )
    }

    /// `pool` and `authority` must be freshly recovered from the same live slot.
    /// An interrupted checkpoint stays IN_PROGRESS until durable cleanup records
    /// NOT_COMMITTED; this read-only handler never performs or assumes cleanup.
    pub fn handle_pool_operation_status(
        &mut self,
        request: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
        lease: RequestLease,
        authority: PoolAuthority,
        pool: &PoolRegistration,
    ) -> Result<HandlerResult, CommandError> {
        if request.operation != Operation::OpStatus {
            return Err(pool_error(Status::UnsupportedOperation));
        }
        require_pool(authority, pool)?;
        let authenticated = self
            .pool_sessions
            .authenticate_request(authority, request.map(), &mut self.sessions)
            .map_err(session_error)?;
        let target = RequestId::from_bytes(array(request.payload(), "request")?);
        let number = request
            .payload()
            .get("generation_number")
            .map_err(|_| invalid_frame())?
            .map(|value| value.uint().map(GenerationNumber::new))
            .transpose()
            .map_err(|_| invalid_frame())?;
        let coordinator = pool
            .generation_checkpoint()
            .map(GenerationCoordinator::from_checkpoint)
            .unwrap_or_default();
        let outcome = coordinator.status(pool, target, number);
        let payload = RetrievalPayload::Operation { outcome, pool };
        self.finish_pool_retrieval(request, response, lease, authority, authenticated, payload)
    }

    /// The store must be the slot-scoped FlashPublicObjects adapter constructed
    /// from this same recovered pool. `object` is public scratch, not a key copy.
    #[allow(clippy::too_many_arguments)]
    pub fn handle_pool_get_backup<S: PublicObjectStore>(
        &mut self,
        request: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
        lease: RequestLease,
        authority: PoolAuthority,
        pool: &PoolRegistration,
        store: &mut S,
        object: &mut [u8; MAX_PUBLIC_OBJECT_BYTES],
    ) -> Result<HandlerResult, CommandError> {
        if request.operation != Operation::GetBackup {
            return Err(pool_error(Status::UnsupportedOperation));
        }
        require_pool(authority, pool)?;
        let authenticated = self
            .pool_sessions
            .authenticate_request(authority, request.map(), &mut self.sessions)
            .map_err(session_error)?;
        let generation = GenerationId::from_bytes(array(request.payload(), "generation")?);
        let backup = match generation::get_backup(pool, generation, store, object) {
            Ok(backup) => backup,
            Err(error) => {
                let status = match error {
                    generation::Error::ResultReclaimed => Status::StaleGeneration,
                    _ => Status::StateDamaged,
                };
                return self.respond_pool_error(
                    request,
                    response,
                    lease,
                    authority,
                    authenticated,
                    pool_error(status),
                );
            }
        };
        self.finish_pool_retrieval(
            request,
            response,
            lease,
            authority,
            authenticated,
            RetrievalPayload::Backup(backup),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_pool_retrieval(
        &mut self,
        request: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
        lease: RequestLease,
        authority: PoolAuthority,
        authenticated: kes_core::session::AuthenticatedRequest<'_>,
        payload: RetrievalPayload<'_>,
    ) -> Result<HandlerResult, CommandError> {
        let sequence = self
            .sessions
            .get(authority.scope())
            .ok_or(pool_error(Status::AuthFailed))?
            .response_sequence();
        let session = array(request.map(), "session")?;
        let device = self.device;
        let encode = |output: &mut [u8], mac| {
            encode_retrieval(
                output,
                device,
                authority.scope(),
                session,
                sequence,
                authenticated.sequence,
                authenticated.request,
                request.operation,
                &payload,
                mac,
            )
        };
        let length = encode(response, [0; 32])?;
        let unsigned = Envelope::parse(&response[..length], EnvelopeKind::DeviceResponse)
            .map_err(|_| unavailable())?;
        let mac = self
            .pool_sessions
            .response_mac(authority, unsigned.map(), authenticated, &mut self.sessions)
            .map_err(session_error)?;
        let response_length = encode(response, mac)?;
        Ok(HandlerResult {
            response_length,
            completed_at_ms: self
                .completion_clock
                .map_or(lease.admitted_at_ms(), |clock| clock()),
        })
    }
}

fn require_pool(authority: PoolAuthority, pool: &PoolRegistration) -> Result<(), CommandError> {
    if !authority.matches_pool(pool) {
        return Err(pool_error(Status::WrongPool));
    }
    Ok(())
}

const fn pool_error(status: Status) -> CommandError {
    CommandError {
        scope: ErrorScope::Pool,
        status,
    }
}

enum RetrievalPayload<'a> {
    Operation {
        outcome: OperationStatus,
        pool: &'a PoolRegistration,
    },
    Backup(generation::BackupResult<'a>),
    Status(&'a PoolRegistration),
    Descriptor {
        pool: &'a PoolRegistration,
        generation: &'a KESGeneration,
    },
    Context(PoolContextResponse<'a>),
    Failure(Status),
    #[cfg(all(
        any(feature = "development", feature = "a2-development"),
        not(feature = "release")
    ))]
    Inspection(&'a super::inspection::DevelopmentInspection<'a>),
}

impl RetrievalPayload<'_> {
    fn status(&self) -> &'static str {
        match self {
            Self::Backup(_)
            | Self::Status(_)
            | Self::Descriptor { .. }
            | Self::Operation {
                outcome: OperationStatus::Committed(_),
                ..
            } => "OK",
            #[cfg(all(
                any(feature = "development", feature = "a2-development"),
                not(feature = "release")
            ))]
            Self::Inspection(_) => "OK",
            Self::Context(PoolContextResponse::Expired(_)) => "EXPIRED",
            Self::Context(_) => "OK",
            Self::Failure(status) => status.as_str(),
            Self::Operation { outcome, .. } => match outcome {
                OperationStatus::InProgress { .. } => "IN_PROGRESS",
                OperationStatus::NotCommitted { .. } => "NOT_COMMITTED",
                OperationStatus::Unknown { .. } => "UNKNOWN",
                OperationStatus::ResultReclaimed { .. } => "RESULT_RECLAIMED",
                OperationStatus::Committed(_) => unreachable!(),
            },
        }
    }

    fn encode(&self, e: &mut Encoder<'_>) -> Result<(), kes_core::cbor::Error> {
        match self {
            #[cfg(all(
                any(feature = "development", feature = "a2-development"),
                not(feature = "release")
            ))]
            Self::Inspection(inspection) => inspection.encode(e)?,
            Self::Failure(_) => {
                e.map(2)?;
                e.text("scope")?;
                e.text("pool")?;
                e.text("diagnostic")?;
                e.text("operation rejected")?;
            }
            Self::Descriptor { pool, generation } => encode_descriptor(e, pool, generation)?,
            Self::Context(result) => {
                let (context, signature) = match result {
                    PoolContextResponse::Evolved(context)
                    | PoolContextResponse::Expired(context) => (context, None),
                    PoolContextResponse::Signed(signed) => (&signed.context, Some(*signed)),
                };
                e.map(if signature.is_some() { 8 } else { 6 })?;
                e.text("health")?;
                e.text("healthy")?;
                e.text("revision")?;
                e.uint(context.revision.get())?;
                e.text("lifecycle")?;
                e.text(lifecycle_name(context.lifecycle))?;
                if let Some(signature) = signature {
                    e.text("signature")?;
                    e.bytes(&signature.signature)?;
                }
                e.text("generation")?;
                e.bytes(context.generation.as_bytes())?;
                if let Some(signature) = signature {
                    e.text("message_digest")?;
                    e.bytes(&signature.message_digest)?;
                }
                e.text("relative_period")?;
                e.uint(context.relative_period.get().into())?;
                e.text("certificate_digest")?;
                e.bytes(&context.certificate_digest)?;
            }
            Self::Status(pool) => {
                e.map(9)?;
                e.text("active")?;
                if let Some(active) = pool.current() {
                    encode_descriptor(e, pool, active)?;
                } else {
                    e.null()?;
                }
                e.text("health")?;
                e.text("healthy")?;
                e.text("staged")?;
                if let Some(staged) = pool.staged() {
                    encode_descriptor(e, pool, staged)?;
                } else {
                    e.null()?;
                }
                e.text("revoked")?;
                e.boolean(pool.credential_revoked())?;
                e.text("revision")?;
                e.uint(pool.revision().get())?;
                e.text("directory")?;
                e.array(0)?;
                e.text("security_mode")?;
                e.text("development")?;
                e.text("blocking_reason")?;
                e.text("development firmware: release security unavailable")?;
                e.text("credential_epoch")?;
                e.uint(pool.credential_epoch().get())?;
            }
            Self::Backup(backup) => {
                e.map(3)?;
                e.text("backup")?;
                e.bytes(backup.bytes)?;
                e.text("generation")?;
                e.bytes(backup.generation.as_bytes())?;
                e.text("artifact_digest")?;
                e.bytes(&backup.digest)?;
            }
            Self::Operation {
                outcome: OperationStatus::Committed(descriptor),
                pool,
            } => {
                let retained = [pool.current(), pool.staged()]
                    .into_iter()
                    .flatten()
                    .find(|generation| generation.id() == descriptor.generation)
                    .expect("coordinator returns only retained committed generations");
                encode_descriptor(e, pool, retained)?;
            }
            Self::Operation { outcome, .. } => {
                let (request, number) = match outcome {
                    OperationStatus::InProgress {
                        request,
                        generation_number,
                    }
                    | OperationStatus::NotCommitted {
                        request,
                        generation_number,
                    }
                    | OperationStatus::ResultReclaimed {
                        request,
                        generation_number,
                    } => (*request, Some(*generation_number)),
                    OperationStatus::Unknown {
                        request,
                        generation_number,
                    } => (*request, *generation_number),
                    OperationStatus::Committed(_) => unreachable!(),
                };
                e.map(if number.is_some() { 2 } else { 1 })?;
                e.text("request")?;
                e.bytes(request.as_bytes())?;
                if let Some(number) = number {
                    e.text("generation_number")?;
                    e.uint(number.get())?;
                }
            }
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn encode_retrieval(
    output: &mut [u8],
    device: DeviceId,
    scope: Scope,
    session: [u8; 16],
    sequence: u64,
    request_sequence: u64,
    request: RequestId,
    operation: Operation,
    payload: &RetrievalPayload<'_>,
    mac: [u8; 32],
) -> Result<usize, CommandError> {
    let Scope::Pool { pool, incarnation } = scope else {
        return Err(pool_error(Status::WrongPool));
    };
    let encode = |e: &mut Encoder<'_>| -> Result<(), kes_core::cbor::Error> {
        e.map(12)?;
        e.text("op")?;
        e.text(operation.as_str())?;
        e.text("mac")?;
        e.bytes(&mac)?;
        e.text("seq")?;
        e.uint(sequence)?;
        e.text("pool")?;
        e.bytes(pool.as_bytes())?;
        e.text("device")?;
        e.bytes(device.as_bytes())?;
        e.text("status")?;
        e.text(payload.status())?;
        e.text("payload")?;
        payload.encode(e)?;
        e.text("request")?;
        e.bytes(request.as_bytes())?;
        e.text("session")?;
        e.bytes(&session)?;
        e.text("version")?;
        e.uint(1)?;
        e.text("incarnation")?;
        e.bytes(incarnation.as_bytes())?;
        e.text("request_seq")?;
        e.uint(request_sequence)?;
        Ok(())
    };
    let mut e = Encoder::new(output);
    encode(&mut e).map_err(|_| unavailable())?;
    finish(e)
}

fn lifecycle_name(lifecycle: Lifecycle) -> &'static str {
    match lifecycle {
        Lifecycle::Staged => "staged",
        Lifecycle::CertifiedStaged => "certified-staged",
        Lifecycle::Active => "active",
        Lifecycle::CurrentExpired => "expired",
        Lifecycle::Retired => "retired",
    }
}

fn encode_descriptor(
    e: &mut Encoder<'_>,
    pool: &PoolRegistration,
    generation: &KESGeneration,
) -> Result<(), kes_core::cbor::Error> {
    e.map(13)?;
    e.text("health")?;
    e.text("healthy")?;
    e.text("revision")?;
    e.uint(pool.revision().get())?;
    e.text("lifecycle")?;
    e.text(lifecycle_name(generation.lifecycle()))?;
    e.text("generation")?;
    e.bytes(generation.id().as_bytes())?;
    e.text("artifact_digest")?;
    e.bytes(generation.backup_digest())?;
    e.text("relative_period")?;
    e.uint(generation.relative_period().get().into())?;
    e.text("backup_available")?;
    e.boolean(generation.lifecycle() != Lifecycle::Retired)?;
    e.text("creation_request")?;
    e.bytes(generation.creation_request().as_bytes())?;
    e.text("verification_key")?;
    e.bytes(generation.verification_key())?;
    e.text("certificate_start")?;
    match generation.certificate() {
        Some(c) => e.uint(c.start_period().get())?,
        None => e.null()?,
    };
    e.text("generation_number")?;
    e.uint(generation.number().get())?;
    e.text("certificate_digest")?;
    match generation.certificate() {
        Some(c) => e.bytes(c.digest())?,
        None => e.null()?,
    };
    e.text("certificate_counter")?;
    match generation.certificate() {
        Some(c) => e.uint(c.counter().get())?,
        None => e.null()?,
    };
    Ok(())
}

const _: () = assert!(MAX_PUBLIC_OBJECT_BYTES <= 8192);
const _: () = assert!(MAX_FRAME_BYTES <= 8192);
