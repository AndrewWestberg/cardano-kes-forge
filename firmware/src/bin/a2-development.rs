#![no_main]
#![no_std]
#![forbid(unsafe_code)]

use core::{cell::RefCell, panic::PanicInfo};

use cortex_m_rt::entry;
use embassy_futures::{block_on, join::join3, yield_now};
use embassy_rp::{
    bind_interrupts,
    flash::Flash as HalFlash,
    peripherals,
    usb::{Driver, InterruptHandler},
};
use embassy_sync::{
    blocking_mutex::{Mutex, raw::ThreadModeRawMutex},
    signal::Signal,
};
use embassy_usb::{
    Builder, Config, Handler, UsbVersion,
    control::{OutResponse, Recipient, Request, RequestType},
    driver::{EndpointError, EndpointIn, EndpointOut},
};
use kes_core::{
    activation::{DurablePool, OperationError},
    crypto::{Generation, PublicTreeBuffer},
    enrollment::{EnrollmentStorage, Error as EnrollmentError},
    generation::{self, Admission, GenerationOperation, GenerationRequest, OperationStatus},
    journal::{
        DirectoryCodec, Journal, JournalContext, JournalError, JournalScope, JournalWorkspace,
        ObjectWorkspace, PoolCodec, Recovered, SecretCache, Workspaces,
    },
    session::{DeviceHpkeKey, DeviceIdentityKey, Scope},
    state::{
        Actor, Device, DirectorySnapshot, Health, MAX_PUBLIC_OBJECT_BYTES, ManagementReplay,
        ManagementResult, PoolRegistration,
    },
    types::{
        CredentialEpoch, DeviceId, GenerationNumber, IncarnationId, KesLifetime, PoolId, RequestId,
        Revision,
    },
};
use kes_firmware::{
    development::{
        DevelopmentEvidence, DevelopmentHandler, ManagementOperationStatus, ManagementPoolStatus,
        ManagementStatus, PoolContextResponse,
        device_management::{self, DeviceManagementError},
        device_retirement, inspection,
        pool_activation::{self, ActivationError},
        pool_deletion, pool_management, pool_observe,
        pool_sessions::PoolAuthority,
        pool_signing::{self, Outcome as SigningOutcome},
    },
    development_directory::DEVELOPMENT_POLICY_DIGEST,
    development_identity::{self, IdentityFlash},
    entropy::HealthCheckedEntropy,
    pool_service::FlashPublicObjects,
    recovery::{self, RecoveryError},
    scheduler::{GenerationLease, GenerationProgress, RequestLease, Scheduler},
    storage::{DIRECTORY, FittedFlash, POOLS, directory_layout, pool_layout},
    usb::{
        CommandError, HandlerResult, ReceiveStatus, ResponseFrame, SecureRequestHandler,
        UsbDispatcher,
    },
};
use kes_protocol::{Envelope, ErrorScope, MAX_FRAME_BYTES, Operation, Status};
use rp_pac as pac;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

// Unallocated prototype identifiers. This image is development-only and MUST
// never be distributed as a product USB identity.
const PROTOTYPE_VID: u16 = 0xcafe;
const PROTOTYPE_PID: u16 = 0x4b45;
const PACKET_BYTES: usize = 64;
const QUALIFICATION_MACHINE_KEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
const CAPABILITY_EVIDENCE: &[u8] = b"rp2350-a2;development;otp=untouched;\
    persistence=identity-only;firmware-digest=unmeasured;entropy=health-checked-a2-exploratory;\
    session-entropy=fresh-per-open";
const ENROLLMENT_CAPABILITY_EVIDENCE: &[u8] = b"rp2350-a2;development;otp=untouched;\
    persistence=identity-and-enrollment;firmware-digest=unmeasured;entropy=health-checked-a2-exploratory;\
    session-entropy=fresh-per-open";

bind_interrupts!(struct Irqs {
    USBCTRL_IRQ => InterruptHandler<peripherals::USB>;
});

/// Unauthenticated reset is limited to this explicitly disposable, unlocked
/// A2 image. It changes no flash or OTP and lets the operator reflash without
/// physically pressing BOOTSEL. Never include it in a release image.
struct DevelopmentBootsel;

impl Handler for DevelopmentBootsel {
    fn reset(&mut self) {
        // USB bus reset need not surface as a disabled endpoint read.
        with_state(State::disconnect);
    }

    fn configured(&mut self, configured: bool) {
        if !configured {
            with_state(State::disconnect);
        }
    }

    fn control_out(&mut self, request: Request, data: &[u8]) -> Option<OutResponse> {
        if request.request_type == RequestType::Vendor
            && request.recipient == Recipient::Device
            && request.request == 0x5a
            && request.value == 0x4b45
            && request.index == 0xa235
            && request.length == 0
            && data.is_empty()
        {
            // Schedule the bootrom reset without its NO_RETURN flag so the
            // control endpoint can acknowledge before the watchdog fires.
            return Some(if embassy_rp::rom_data::reboot(0x2, 100, 0, 0) == 0 {
                OutResponse::Accepted
            } else {
                OutResponse::Rejected
            });
        }
        None
    }
}

type A2Handler = DevelopmentHandler<HealthCheckedEntropy<'static>>;

#[allow(clippy::large_enum_variant)]
#[repr(u8)]
enum HandlerSlot {
    Empty,
    Active(A2Handler),
}

struct DurableRuntime {
    device: DeviceId,
    flash: FittedFlash<'static>,
    storage_root: Zeroizing<[u8; 32]>,
    journal: JournalWorkspace,
    object: ObjectWorkspace,
    cache: SecretCache,
    provisioned: bool,
    retirement_cleanup_verified: bool,
    pending_management_cleanup: bool,
}

struct ActiveGeneration {
    scope: Scope,
    slot: kes_core::types::HardwareSlot,
    operation: GenerationOperation,
    generator: Generation,
    lease: GenerationLease,
}

struct State {
    dispatcher: UsbDispatcher,
    handler: HandlerSlot,
    durable: Option<DurableRuntime>,
    generation: Option<ActiveGeneration>,
    generation_write: [u8; MAX_PUBLIC_OBJECT_BYTES],
    generation_read: [u8; MAX_PUBLIC_OBJECT_BYTES],
    public_tree: PublicTreeBuffer,
    response: [u8; MAX_FRAME_BYTES],
}

impl State {
    const fn new() -> Self {
        Self {
            dispatcher: UsbDispatcher::new(),
            handler: HandlerSlot::Empty,
            durable: None,
            generation: None,
            generation_write: [0; MAX_PUBLIC_OBJECT_BYTES],
            generation_read: [0; MAX_PUBLIC_OBJECT_BYTES],
            public_tree: PublicTreeBuffer::new(),
            response: [0; MAX_FRAME_BYTES],
        }
    }

    fn dispatch(&mut self, now_ms: u64) -> Option<ResponseFrame> {
        let HandlerSlot::Active(handler) = &mut self.handler else {
            return None;
        };
        let durable = self.durable.as_mut()?;
        if !durable.provisioned {
            return self
                .dispatcher
                .dispatch(now_ms, &mut self.response, handler)
                .ok();
        }
        let mut service = PersistentHandler {
            handler,
            durable,
            generation: &mut self.generation,
            public_object: &mut self.generation_write,
            public_tree: &mut self.public_tree,
        };
        let result = self
            .dispatcher
            .dispatch(now_ms, &mut self.response, &mut service)
            .ok();
        if self.generation.is_some() {
            GENERATION_SIGNAL.signal(());
        }
        result
    }

    /// Advance exactly one KES leaf, then yield to the USB executor.
    fn generation_turn(&mut self) -> bool {
        let Some(job) = self.generation.as_mut() else {
            return false;
        };
        let result =
            self.dispatcher
                .scheduler_mut()
                .generation_turn(job.lease, monotonic_ms(), |_| {
                    job.generator.step().map(|_| ())
                });
        if matches!(result, Ok(GenerationProgress::Advanced { .. })) {
            return true;
        }
        let job = self.generation.take().expect("active generation");
        let scope = job.scope;
        let slot = job.slot;
        let (HandlerSlot::Active(handler), Some(durable)) = (&mut self.handler, &mut self.durable)
        else {
            return false;
        };
        let completed = match result {
            Ok(GenerationProgress::Complete { .. }) => {
                handler.with_identity_and_entropy(|identity, rng| {
                    complete_generation_job(
                        durable,
                        rng,
                        identity,
                        job,
                        &mut self.generation_write,
                        &mut self.generation_read,
                    )
                    .is_ok()
                })
            }
            _ => {
                drop(job);
                false
            }
        };
        if !completed {
            let _ =
                handler.with_entropy(|rng| abort_interrupted_generation(durable, rng, scope, slot));
        }
        false
    }

    fn disconnect(&mut self) {
        self.dispatcher.discard_request();
        self.response.fill(0);
        if let HandlerSlot::Active(handler) = &mut self.handler {
            handler.disconnect();
        }
    }
}

/// Borrowed dispatch keeps each fitted-flash view local to the operation that
/// owns it. In particular, INFO and ordinary unsupported requests never scan.
struct PersistentHandler<'a> {
    handler: &'a mut A2Handler,
    durable: &'a mut DurableRuntime,
    generation: &'a mut Option<ActiveGeneration>,
    public_object: &'a mut [u8; MAX_PUBLIC_OBJECT_BYTES],
    public_tree: &'a mut PublicTreeBuffer,
}

impl PersistentHandler<'_> {
    fn execute_pool_operation(
        &mut self,
        request: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
        lease: RequestLease,
    ) -> Result<HandlerResult, CommandError> {
        let scope = pool_scope(request)?
            .ok_or_else(|| status_error(ErrorScope::Pool, Status::WrongPool))?;
        let durable = &mut *self.durable;
        let (authority, recovered) = self
            .handler
            .with_entropy(|rng| recover_pool(durable, rng, scope))?;
        let authenticated =
            self.handler
                .authenticate_pool_operation(request, authority, &recovered.state)?;
        let Scope::Pool { pool, incarnation } = scope else {
            return Err(status_error(ErrorScope::Pool, Status::WrongPool));
        };
        let slot = authority.slot();
        let layout =
            pool_layout(slot).map_err(|error| status_journal_error(ErrorScope::Pool, error))?;
        let journal = Journal::<PoolCodec>::new(
            JournalContext {
                device: durable.device,
                scope: JournalScope::Pool {
                    slot,
                    pool,
                    incarnation,
                },
            },
            layout,
            &durable.storage_root,
        )
        .map_err(|error| status_journal_error(ErrorScope::Pool, error))?;
        let mut flash = durable
            .flash
            .pool(slot)
            .map_err(|_| status_error(ErrorScope::Pool, Status::DeviceUnavailable))?;
        let mut work = Workspaces {
            journal: &mut durable.journal,
            object: &mut durable.object,
            cache: &mut durable.cache,
        };
        let mut owner = DurablePool::from_recovered(recovered);
        match request.operation {
            Operation::Certify | Operation::Activate | Operation::Schedule => {
                let outcome = match self
                    .handler
                    .with_entropy(|rng| {
                        pool_activation::execute(
                            request,
                            authority,
                            &mut owner,
                            &journal,
                            &mut flash,
                            layout,
                            rng,
                            &mut work,
                            self.public_object,
                            self.public_tree,
                        )
                    })
                    .map_err(activation_error)
                {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        return self.handler.respond_pool_error(
                            request,
                            response,
                            lease,
                            authority,
                            authenticated,
                            error,
                        );
                    }
                };
                self.handler.respond_pool_descriptor(
                    request,
                    response,
                    lease,
                    authority,
                    authenticated,
                    owner
                        .state()
                        .map_err(|error| CommandError::from_operation(ErrorScope::Pool, error))?,
                    outcome.context.generation,
                )
            }
            Operation::Sign | Operation::Evolve => {
                let outcome = match self.handler.with_entropy(|rng| {
                    pool_signing::execute(
                        request,
                        authenticated,
                        authority,
                        &mut owner,
                        &journal,
                        &mut flash,
                        layout,
                        rng,
                        &mut work,
                        self.public_object,
                        self.public_tree,
                    )
                }) {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        return self.handler.respond_pool_error(
                            request,
                            response,
                            lease,
                            authority,
                            authenticated,
                            error,
                        );
                    }
                };
                let context = match &outcome {
                    SigningOutcome::Signed(signed) => PoolContextResponse::Signed(signed),
                    SigningOutcome::Evolved(context) => PoolContextResponse::Evolved(*context),
                    SigningOutcome::Expired(context) => PoolContextResponse::Expired(*context),
                };
                self.handler.respond_pool_context(
                    request,
                    response,
                    lease,
                    authority,
                    authenticated,
                    owner
                        .state()
                        .map_err(|error| CommandError::from_operation(ErrorScope::Pool, error))?,
                    context,
                )
            }
            Operation::ObservePeriod => {
                let outcome = match self.handler.with_entropy(|rng| {
                    pool_observe::execute(
                        request,
                        authenticated,
                        authority,
                        &mut owner,
                        &journal,
                        &mut flash,
                        layout,
                        rng,
                        &mut work,
                        self.public_object,
                        self.public_tree,
                    )
                }) {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        return self.handler.respond_pool_error(
                            request,
                            response,
                            lease,
                            authority,
                            authenticated,
                            error,
                        );
                    }
                };
                let state = owner
                    .state()
                    .map_err(|error| CommandError::from_operation(ErrorScope::Pool, error))?;
                if outcome.status() == Status::Expired {
                    self.handler.respond_pool_context(
                        request,
                        response,
                        lease,
                        authority,
                        authenticated,
                        state,
                        PoolContextResponse::Expired(outcome.context),
                    )
                } else {
                    self.handler.respond_pool_descriptor(
                        request,
                        response,
                        lease,
                        authority,
                        authenticated,
                        state,
                        outcome.context.generation,
                    )
                }
            }
            Operation::DevInspect => {
                match inspection::inspect(request, authenticated, authority, &owner) {
                    Ok(inspected) => self.handler.respond_pool_inspection(
                        request,
                        response,
                        lease,
                        authority,
                        authenticated,
                        &inspected,
                    ),
                    Err(error) => self.handler.respond_pool_error(
                        request,
                        response,
                        lease,
                        authority,
                        authenticated,
                        error,
                    ),
                }
            }
            _ => Err(status_error(ErrorScope::Pool, Status::UnsupportedOperation)),
        }
    }

    fn begin_generation(
        &mut self,
        request: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
        lease: RequestLease,
        scheduler: &mut Scheduler,
    ) -> Result<HandlerResult, CommandError> {
        let scope = pool_scope(request)?
            .ok_or_else(|| status_error(ErrorScope::Pool, Status::WrongPool))?;
        let durable = &mut *self.durable;
        let (authority, recovered) = self
            .handler
            .with_entropy(|rng| recover_pool(durable, rng, scope))?;
        let authenticated =
            self.handler
                .authenticate_pool_operation(request, authority, &recovered.state)?;
        let result = (|| {
            let Scope::Pool { pool, incarnation } = scope else {
                return Err(status_error(ErrorScope::Pool, Status::WrongPool));
            };
            let number = GenerationNumber::new(
                request
                    .payload()
                    .required("next_generation_number")
                    .and_then(|value| value.uint())
                    .map_err(|_| status_error(ErrorScope::Pool, Status::InvalidFrame))?,
            );
            let revision = Revision::new(
                request
                    .payload()
                    .required("expected_revision")
                    .and_then(|value| value.uint())
                    .map_err(|_| status_error(ErrorScope::Pool, Status::InvalidFrame))?,
            );
            let generation_request = GenerationRequest {
                actor: Actor::Pool { pool, incarnation },
                request: authenticated.request,
                payload_digest: Sha256::digest(request.payload().encoded()).into(),
                next_generation_number: number,
                expected_revision: revision,
            };
            if let Some(active) = self.generation.as_ref()
                && (active.scope != scope
                    || active.operation.request() != authenticated.request
                    || active.operation.generation_number() != number)
            {
                return Err(status_error(ErrorScope::Pool, Status::Busy));
            }
            let mut owner = DurablePool::from_recovered(recovered);
            let lifetime = KesLifetime::new(u64::from(
                owner
                    .state()
                    .map_err(|error| CommandError::from_operation(ErrorScope::Pool, error))?
                    .network()
                    .max_kes_evolutions(),
            ))
            .map_err(|_| status_error(ErrorScope::Pool, Status::StateDamaged))?;
            let slot = authority.slot();
            let journal = Journal::<PoolCodec>::new(
                JournalContext {
                    device: durable.device,
                    scope: JournalScope::Pool {
                        slot,
                        pool,
                        incarnation,
                    },
                },
                pool_layout(slot).map_err(|error| status_journal_error(ErrorScope::Pool, error))?,
                &durable.storage_root,
            )
            .map_err(|error| status_journal_error(ErrorScope::Pool, error))?;
            let mut flash = durable
                .flash
                .pool(slot)
                .map_err(|_| status_error(ErrorScope::Pool, Status::DeviceUnavailable))?;
            let mut work = Workspaces {
                journal: &mut durable.journal,
                object: &mut durable.object,
                cache: &mut durable.cache,
            };
            let outcome = self.handler.with_entropy(|rng| {
                let admission = owner
                    .admit_generation(generation_request, &journal, &mut flash, rng, &mut work)
                    .map_err(generation_error)?;
                let operation = match admission {
                    Admission::Started(operation) => operation,
                    Admission::Existing(OperationStatus::NotCommitted { .. })
                        if self.generation.is_none() =>
                    {
                        owner
                            .restart_generation(
                                generation_request,
                                &journal,
                                &mut flash,
                                rng,
                                &mut work,
                            )
                            .map_err(generation_error)?
                    }
                    Admission::Existing(outcome) => return Ok(outcome),
                };
                let generation_lease = match scheduler.start_generation(lease, 64) {
                    Ok(value) => value,
                    Err(_) => {
                        let _ =
                            DurablePool::recover_generation(&journal, &mut flash, rng, &mut work);
                        return Err(status_error(ErrorScope::Pool, Status::Busy));
                    }
                };
                let generator = match generation::begin_key_generation(rng, lifetime) {
                    Ok(value) => value,
                    Err(_) => {
                        let _ = scheduler.cancel_generation(generation_lease);
                        let _ =
                            DurablePool::recover_generation(&journal, &mut flash, rng, &mut work);
                        return Err(status_error(ErrorScope::Pool, Status::EntropyFailure));
                    }
                };
                let outcome = OperationStatus::InProgress {
                    request: operation.request(),
                    generation_number: operation.generation_number(),
                };
                *self.generation = Some(ActiveGeneration {
                    scope,
                    slot,
                    operation,
                    generator,
                    lease: generation_lease,
                });
                Ok(outcome)
            })?;
            if matches!(
                outcome,
                OperationStatus::NotCommitted { .. }
                    | OperationStatus::Unknown { .. }
                    | OperationStatus::ResultReclaimed { .. }
            ) {
                return Err(status_error(ErrorScope::Pool, Status::StaleGeneration));
            }
            Ok((outcome, owner))
        })();
        match result {
            Ok((outcome, owner)) => self.handler.respond_pool_generation(
                request,
                response,
                lease,
                authority,
                authenticated,
                owner
                    .state()
                    .map_err(|error| CommandError::from_operation(ErrorScope::Pool, error))?,
                outcome,
            ),
            Err(error) => self.handler.respond_pool_error(
                request,
                response,
                lease,
                authority,
                authenticated,
                error,
            ),
        }
    }
    fn execute_pool_management(
        &mut self,
        request: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
        lease: RequestLease,
        scheduler: &mut Scheduler,
    ) -> Result<HandlerResult, CommandError> {
        let durable = &mut *self.durable;
        let directory = self
            .handler
            .with_entropy(|rng| recover_live_directory(durable, rng))?;
        let authenticated = self.handler.authenticate_management_request(
            request,
            directory.credential.epoch,
            directory.credential.revoked,
        )?;
        let result = (|| {
            let payload = request.payload();
            let pool = PoolId::try_from(
                payload
                    .required("pool")
                    .and_then(|v| v.bytes())
                    .map_err(|_| status_error(ErrorScope::Pool, Status::InvalidFrame))?,
            )
            .map_err(|_| status_error(ErrorScope::Pool, Status::InvalidFrame))?;
            let incarnation = IncarnationId::try_from(
                payload
                    .required("incarnation")
                    .and_then(|v| v.bytes())
                    .map_err(|_| status_error(ErrorScope::Pool, Status::InvalidFrame))?,
            )
            .map_err(|_| status_error(ErrorScope::Pool, Status::InvalidFrame))?;
            let sequence = payload
                .required("management_sequence")
                .and_then(|v| v.uint())
                .map_err(|_| status_error(ErrorScope::Device, Status::InvalidFrame))?;
            let scope = Scope::Pool { pool, incarnation };
            let (authority, recovered) = self
                .handler
                .with_entropy(|rng| recover_pool_from_directory(durable, rng, &directory, scope))?;
            let slot = authority.slot();
            if let Some(checkpoint) = recovered
                .state
                .generation_checkpoint()
                .filter(|checkpoint| {
                    checkpoint.outcome == generation::CheckpointOutcome::InProgress
                })
            {
                if !self.generation.as_ref().is_some_and(|job| {
                    job.scope == scope && job.operation.generation() == checkpoint.generation
                }) {
                    return Err(status_error(ErrorScope::Pool, Status::StateDamaged));
                }
            }
            let journal = Journal::<PoolCodec>::new(
                JournalContext {
                    device: durable.device,
                    scope: JournalScope::Pool {
                        slot,
                        pool,
                        incarnation,
                    },
                },
                pool_layout(slot).map_err(|error| status_journal_error(ErrorScope::Pool, error))?,
                &durable.storage_root,
            )
            .map_err(|error| status_journal_error(ErrorScope::Pool, error))?;
            let mut flash = durable
                .flash
                .pool(slot)
                .map_err(|_| status_error(ErrorScope::Pool, Status::DeviceUnavailable))?;
            let mut work = Workspaces {
                journal: &mut durable.journal,
                object: &mut durable.object,
                cache: &mut durable.cache,
            };
            let mut owner = DurablePool::from_recovered(recovered);
            let active = &mut *self.generation;
            let outcome = self.handler.with_entropy(|rng| {
                pool_management::execute(
                    payload.encoded(),
                    &directory,
                    slot,
                    &mut owner,
                    &journal,
                    &mut flash,
                    rng,
                    &mut work,
                    |generation| {
                        let job = active.take().expect("checkpoint matched live generation");
                        debug_assert_eq!(job.operation.generation(), generation);
                        let _ = scheduler.cancel_generation(job.lease);
                        drop(job);
                    },
                )
            });
            match outcome {
                Ok(outcome) => Ok((outcome, slot, sequence)),
                Err(error) => {
                    // A journal error can follow a committed credential change.
                    if matches!(
                        error,
                        pool_management::ManagementError::Policy(
                            generation::PoolManagementError::Operation(_)
                        )
                    ) {
                        self.handler.invalidate_pool_session(slot);
                    }
                    Err(pool_management_error(error))
                }
            }
        })();
        match result {
            Ok((outcome, slot, sequence)) => {
                let reply = self.handler.respond_management_ack(
                    request,
                    response,
                    lease,
                    authenticated,
                    sequence,
                    outcome.durable.revision.get(),
                    false,
                );
                if outcome.invalidate_pool_sessions {
                    self.handler.invalidate_pool_session(slot);
                }
                reply
            }
            Err(error) => self.handler.respond_management_error(
                request,
                response,
                lease,
                authenticated,
                error,
            ),
        }
    }

    fn execute_pool_deletion(
        &mut self,
        request: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
        lease: RequestLease,
        scheduler: &mut Scheduler,
    ) -> Result<HandlerResult, CommandError> {
        let durable = &mut *self.durable;
        let directory = self
            .handler
            .with_entropy(|rng| recover_live_directory(durable, rng))?;
        let authenticated = self.handler.authenticate_management_request(
            request,
            directory.credential.epoch,
            directory.credential.revoked,
        )?;
        let result = (|| {
            let payload = request.payload();
            let pool = PoolId::try_from(
                payload
                    .required("pool")
                    .and_then(|v| v.bytes())
                    .map_err(|_| status_error(ErrorScope::Pool, Status::InvalidFrame))?,
            )
            .map_err(|_| status_error(ErrorScope::Pool, Status::InvalidFrame))?;
            let incarnation = IncarnationId::try_from(
                payload
                    .required("incarnation")
                    .and_then(|v| v.bytes())
                    .map_err(|_| status_error(ErrorScope::Pool, Status::InvalidFrame))?,
            )
            .map_err(|_| status_error(ErrorScope::Pool, Status::InvalidFrame))?;
            let scope = Scope::Pool { pool, incarnation };
            let entry = directory
                .live
                .iter()
                .flatten()
                .find(|entry| entry.pool_id() == pool && entry.incarnation() == incarnation)
                .copied();
            let (slot, pool_state) = if let Some(entry) = entry {
                let (_, recovered) = self.handler.with_entropy(|rng| {
                    recover_pool_from_directory(durable, rng, &directory, scope)
                })?;
                if let Some(checkpoint) =
                    recovered
                        .state
                        .generation_checkpoint()
                        .filter(|checkpoint| {
                            checkpoint.outcome == generation::CheckpointOutcome::InProgress
                        })
                {
                    if !self.generation.as_ref().is_some_and(|job| {
                        job.scope == scope && job.operation.generation() == checkpoint.generation
                    }) {
                        return Err(status_error(ErrorScope::Pool, Status::StateDamaged));
                    }
                }
                (Some(entry.slot()), Some(recovered.state))
            } else {
                (None, None)
            };
            let journal = Journal::<DirectoryCodec>::new(
                JournalContext {
                    device: durable.device,
                    scope: JournalScope::Directory,
                },
                directory_layout()
                    .map_err(|error| status_journal_error(ErrorScope::Device, error))?,
                &durable.storage_root,
            )
            .map_err(|error| status_journal_error(ErrorScope::Device, error))?;
            let mut flash = durable
                .flash
                .directory()
                .map_err(|_| status_error(ErrorScope::Device, Status::DeviceUnavailable))?;
            let mut work = Workspaces {
                journal: &mut durable.journal,
                object: &mut durable.object,
                cache: &mut durable.cache,
            };
            let active = &mut *self.generation;
            let outcome = self.handler.with_entropy(|rng| {
                pool_deletion::execute(
                    payload.encoded(),
                    &directory,
                    slot,
                    pool_state.as_ref(),
                    &journal,
                    &mut flash,
                    rng,
                    &mut work,
                    |deleted_scope| {
                        if active
                            .as_ref()
                            .is_some_and(|job| job.scope == deleted_scope)
                        {
                            let job = active.take().expect("matching generation exists");
                            let _ = scheduler.cancel_generation(job.lease);
                            drop(job);
                        }
                    },
                )
            });
            drop(flash);
            drop(pool_state);
            let outcome = match outcome {
                Ok(outcome) => outcome,
                Err(error) => {
                    if matches!(
                        error,
                        pool_deletion::DeletionError::Journal(_)
                            | pool_deletion::DeletionError::ReadbackMismatch
                            | pool_deletion::DeletionError::StaleAuthority
                    ) {
                        durable.pending_management_cleanup = true;
                        if let Some(slot) = slot {
                            self.handler.invalidate_pool_session(slot);
                        }
                    }
                    return Err(pool_deletion_error(error));
                }
            };
            if let Some(slot) = outcome.affected_slot {
                self.handler.invalidate_pool_session(slot);
            }
            if outcome.cleanup_required {
                durable.pending_management_cleanup = true;
                let completed = self.handler.with_entropy(|rng| {
                    recovery::complete_pending_deletion(
                        &mut durable.flash,
                        rng,
                        &durable.storage_root,
                        durable.device,
                        &mut work,
                    )
                    .map_err(|_| status_error(ErrorScope::Device, Status::StateDamaged))
                })?;
                outcome
                    .confirm_completed(&completed.state)
                    .map_err(pool_deletion_error)?;
                durable.pending_management_cleanup = false;
            } else {
                outcome
                    .confirm_completed(&directory)
                    .map_err(pool_deletion_error)?;
            }
            Ok(outcome)
        })();
        match result {
            Ok(outcome) => self.handler.respond_management_ack(
                request,
                response,
                lease,
                authenticated,
                outcome.sequence.get(),
                outcome.revision.get(),
                false,
            ),
            Err(error) => self.handler.respond_management_error(
                request,
                response,
                lease,
                authenticated,
                error,
            ),
        }
    }

    fn execute_retirement(
        &mut self,
        request: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
        lease: RequestLease,
        scheduler: &mut Scheduler,
    ) -> Result<HandlerResult, CommandError> {
        let durable = &mut *self.durable;
        let directory = self
            .handler
            .with_entropy(|rng| recover_directory(durable, rng, true))?;
        let authenticated = self.handler.authenticate_management_request(
            request,
            directory.credential.epoch,
            directory.credential.revoked,
        )?;
        let result = (|| {
            let journal = Journal::<DirectoryCodec>::new(
                JournalContext {
                    device: durable.device,
                    scope: JournalScope::Directory,
                },
                directory_layout()
                    .map_err(|error| status_journal_error(ErrorScope::Device, error))?,
                &durable.storage_root,
            )
            .map_err(|error| status_journal_error(ErrorScope::Device, error))?;
            let mut flash = durable
                .flash
                .directory()
                .map_err(|_| status_error(ErrorScope::Device, Status::DeviceUnavailable))?;
            let mut work = Workspaces {
                journal: &mut durable.journal,
                object: &mut durable.object,
                cache: &mut durable.cache,
            };
            let active = &mut *self.generation;
            let result = self.handler.with_entropy(|rng| {
                device_retirement::prepare(
                    request,
                    &directory,
                    &journal,
                    &mut flash,
                    rng,
                    &mut work,
                    || {
                        if let Some(job) = active.take() {
                            let _ = scheduler.cancel_generation(job.lease);
                            drop(job);
                        }
                    },
                )
            });
            drop(flash);
            let preparation = match result {
                Ok(preparation) => preparation,
                Err(failure) => {
                    if failure.teardown_required {
                        if let Some(job) = self.generation.take() {
                            let _ = scheduler.cancel_generation(job.lease);
                            drop(job);
                        }
                        self.handler.invalidate_all_pool_sessions();
                        durable.retirement_cleanup_verified = false;
                        durable.pending_management_cleanup = true;
                    }
                    return Err(device_retirement_error(failure.error));
                }
            };
            self.handler.invalidate_all_pool_sessions();
            durable.retirement_cleanup_verified = false;
            durable.pending_management_cleanup = true;
            let completed = self.handler.with_entropy(|rng| {
                recovery::complete_retirement(
                    &mut durable.flash,
                    rng,
                    &durable.storage_root,
                    durable.device,
                    &mut work,
                )
                .map_err(|_| status_error(ErrorScope::Device, Status::StateDamaged))
            })?;
            let marker = completed
                .state
                .retirement
                .ok_or_else(|| status_error(ErrorScope::Device, Status::StateDamaged))?;
            if completed.state.live.iter().any(Option::is_some)
                || marker.revision != preparation.revision
                || marker.management_replay.sequence != preparation.sequence
                || marker.management_replay.request != authenticated.request
            {
                return Err(status_error(ErrorScope::Device, Status::StateDamaged));
            }
            durable.retirement_cleanup_verified = true;
            durable.pending_management_cleanup = false;
            Ok(preparation)
        })();
        match result {
            Ok(preparation) => self.handler.respond_management_ack(
                request,
                response,
                lease,
                authenticated,
                preparation.sequence.get(),
                preparation.revision.get(),
                false,
            ),
            Err(error) => self.handler.respond_management_error(
                request,
                response,
                lease,
                authenticated,
                error,
            ),
        }
    }

    fn execute_device_credential(
        &mut self,
        request: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
        lease: RequestLease,
    ) -> Result<HandlerResult, CommandError> {
        let durable = &mut *self.durable;
        let directory = self
            .handler
            .with_entropy(|rng| recover_live_directory(durable, rng))?;
        let authenticated = self.handler.authenticate_management_request(
            request,
            directory.credential.epoch,
            directory.credential.revoked,
        )?;
        let result = self.handler.with_entropy(|rng| {
            let journal = Journal::<DirectoryCodec>::new(
                JournalContext {
                    device: durable.device,
                    scope: JournalScope::Directory,
                },
                directory_layout()
                    .map_err(|error| (status_journal_error(ErrorScope::Device, error), true))?,
                &durable.storage_root,
            )
            .map_err(|error| (status_journal_error(ErrorScope::Device, error), true))?;
            let mut flash = durable.flash.directory().map_err(|_| {
                (
                    status_error(ErrorScope::Device, Status::DeviceUnavailable),
                    true,
                )
            })?;
            let mut work = Workspaces {
                journal: &mut durable.journal,
                object: &mut durable.object,
                cache: &mut durable.cache,
            };
            device_management::execute(request, &directory, &journal, &mut flash, rng, &mut work)
                .map_err(|error| {
                    let uncertain = matches!(
                        error,
                        DeviceManagementError::Journal(_) | DeviceManagementError::ReadbackMismatch
                    );
                    (device_management_error(error), uncertain)
                })
        });
        match result {
            Ok(outcome) => self.handler.respond_management_ack(
                request,
                response,
                lease,
                authenticated,
                outcome.sequence.get(),
                outcome.revision.get(),
                outcome.epoch_changed || outcome.revocation_changed,
            ),
            Err((error, true)) => {
                // A failed write can already be committed; never retain the old
                // credential session or claim an authenticated success.
                self.handler.invalidate_management_session();
                Err(error)
            }
            Err((error, false)) => self.handler.respond_management_error(
                request,
                response,
                lease,
                authenticated,
                error,
            ),
        }
    }
}

fn device_retirement_error(error: device_retirement::RetirementError) -> CommandError {
    use kes_core::retirement::Error as R;
    let status = match error {
        device_retirement::RetirementError::Journal(error) => {
            return status_journal_error(ErrorScope::Device, error);
        }
        device_retirement::RetirementError::Authorization(
            kes_core::management::Error::WrongDevice,
        ) => Status::WrongDevice,
        device_retirement::RetirementError::Authorization(_) => Status::AuthFailed,
        device_retirement::RetirementError::Retirement(R::Replay | R::ChangedReplay) => {
            Status::Replay
        }
        device_retirement::RetirementError::Retirement(R::RevisionConflict) => {
            Status::RevisionConflict
        }
        device_retirement::RetirementError::Retirement(R::CounterOverflow | R::Capacity) => {
            Status::Capacity
        }
        device_retirement::RetirementError::Retirement(R::CredentialRevoked) => Status::AuthFailed,
        device_retirement::RetirementError::Retirement(R::State(error)) => {
            return CommandError::from_operation(ErrorScope::Device, OperationError::State(error));
        }
        device_retirement::RetirementError::WrongRequest
        | device_retirement::RetirementError::Retirement(R::WrongAction | R::WrongTarget) => {
            Status::InvalidFrame
        }
        device_retirement::RetirementError::Retirement(_)
        | device_retirement::RetirementError::StaleAuthority
        | device_retirement::RetirementError::ReadbackMismatch => Status::StateDamaged,
    };
    status_error(ErrorScope::Device, status)
}

fn pool_deletion_error(error: pool_deletion::DeletionError) -> CommandError {
    use kes_core::deletion::Error as D;
    let status = match error {
        pool_deletion::DeletionError::Journal(error) => {
            return status_journal_error(ErrorScope::Pool, error);
        }
        pool_deletion::DeletionError::Authorization(kes_core::management::Error::WrongDevice) => {
            Status::WrongDevice
        }
        pool_deletion::DeletionError::Authorization(_) => Status::AuthFailed,
        pool_deletion::DeletionError::WrongScope
        | pool_deletion::DeletionError::Deletion(D::WrongTarget) => Status::WrongPool,
        pool_deletion::DeletionError::PendingOperation => Status::Busy,
        pool_deletion::DeletionError::Deletion(D::Replay | D::ChangedReplay) => Status::Replay,
        pool_deletion::DeletionError::Deletion(D::RevisionConflict) => Status::RevisionConflict,
        pool_deletion::DeletionError::Deletion(D::Capacity | D::CounterOverflow) => {
            Status::Capacity
        }
        pool_deletion::DeletionError::Deletion(D::State(error)) => {
            return CommandError::from_operation(ErrorScope::Pool, OperationError::State(error));
        }
        pool_deletion::DeletionError::Deletion(D::WrongAction | D::SameIncarnation) => {
            Status::InvalidFrame
        }
        pool_deletion::DeletionError::Deletion(_)
        | pool_deletion::DeletionError::StaleAuthority
        | pool_deletion::DeletionError::ReadbackMismatch
        | pool_deletion::DeletionError::CleanupIncomplete => Status::StateDamaged,
    };
    status_error(ErrorScope::Pool, status)
}

fn pool_management_error(error: pool_management::ManagementError) -> CommandError {
    use kes_core::{
        credentials::Error as C, generation::PoolManagementError as P, recipient::Error as R,
    };
    let status = match error {
        pool_management::ManagementError::Policy(P::Operation(error)) => {
            return CommandError::from_operation(ErrorScope::Pool, error);
        }
        pool_management::ManagementError::Signature(kes_core::management::Error::WrongDevice) => {
            Status::WrongDevice
        }
        pool_management::ManagementError::Signature(_) => Status::AuthFailed,
        pool_management::ManagementError::WrongScope => Status::WrongPool,
        pool_management::ManagementError::PendingDirectoryOperation => Status::Busy,
        pool_management::ManagementError::Policy(
            P::Credential(C::Replay | C::ChangedReplay)
            | P::Recipient(R::Replay | R::ChangedReplay),
        ) => Status::Replay,
        pool_management::ManagementError::Policy(
            P::Credential(C::RevisionConflict) | P::Recipient(R::RevisionConflict),
        ) => Status::RevisionConflict,
        pool_management::ManagementError::Policy(P::Credential(C::StaleGeneration)) => {
            Status::StaleGeneration
        }
        pool_management::ManagementError::Policy(
            P::Credential(C::CounterOverflow) | P::Recipient(R::CounterOverflow),
        ) => Status::Capacity,
        pool_management::ManagementError::Policy(P::Recipient(
            R::InvalidRecipient | R::SameRecipient,
        )) => Status::RecipientInvalid,
        pool_management::ManagementError::Policy(P::Credential(C::PendingOperation)) => {
            Status::Busy
        }
        pool_management::ManagementError::Policy(_) => Status::InvalidFrame,
    };
    status_error(ErrorScope::Pool, status)
}

fn device_management_error(error: DeviceManagementError) -> CommandError {
    use kes_core::credentials::Error as CredentialError;
    let status = match error {
        DeviceManagementError::Journal(error) => {
            return status_journal_error(ErrorScope::Device, error);
        }
        DeviceManagementError::Authorization(kes_core::management::Error::WrongDevice) => {
            Status::WrongDevice
        }
        DeviceManagementError::Authorization(_) => Status::AuthFailed,
        DeviceManagementError::Credential(
            CredentialError::Replay | CredentialError::ChangedReplay,
        ) => Status::Replay,
        DeviceManagementError::Credential(CredentialError::RevisionConflict) => {
            Status::RevisionConflict
        }
        DeviceManagementError::Credential(CredentialError::PendingOperation)
        | DeviceManagementError::PendingOperation => Status::Busy,
        DeviceManagementError::Credential(CredentialError::CounterOverflow) => Status::Capacity,
        DeviceManagementError::Credential(_) | DeviceManagementError::WrongRequest => {
            Status::InvalidFrame
        }
        DeviceManagementError::StaleAuthority | DeviceManagementError::ReadbackMismatch => {
            Status::StateDamaged
        }
    };
    status_error(ErrorScope::Device, status)
}

fn generation_error(
    error: generation::DurableGenerationError<core::convert::Infallible>,
) -> CommandError {
    match error {
        generation::DurableGenerationError::Operation(error) => {
            CommandError::from_operation(ErrorScope::Pool, error)
        }
        generation::DurableGenerationError::Generation(generation::Error::State(error)) => {
            CommandError::from_operation(ErrorScope::Pool, OperationError::State(error))
        }
        generation::DurableGenerationError::Generation(generation::Error::Busy) => {
            status_error(ErrorScope::Pool, Status::Busy)
        }
        generation::DurableGenerationError::Generation(generation::Error::Identity(_)) => {
            status_error(ErrorScope::Pool, Status::EntropyFailure)
        }
        generation::DurableGenerationError::Generation(_) => {
            status_error(ErrorScope::Pool, Status::StateDamaged)
        }
    }
}

fn activation_error(error: ActivationError) -> CommandError {
    match error {
        ActivationError::Protocol(error) => status_error(ErrorScope::Pool, error.status()),
        ActivationError::WrongPool => status_error(ErrorScope::Pool, Status::WrongPool),
        ActivationError::Operation(error) => CommandError::from_operation(ErrorScope::Pool, error),
        ActivationError::Storage(_) => status_error(ErrorScope::Pool, Status::StateDamaged),
    }
}

impl SecureRequestHandler for PersistentHandler<'_> {
    fn handle(
        &mut self,
        request: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
        lease: RequestLease,
        scheduler: &mut Scheduler,
    ) -> Result<HandlerResult, CommandError> {
        if self.durable.pending_management_cleanup {
            let durable = &mut *self.durable;
            self.handler
                .with_entropy(|rng| reconcile_management_cleanup(durable, rng))?;
        }
        match request.operation {
            Operation::Generate => self.begin_generation(request, response, lease, scheduler),
            Operation::Certify
            | Operation::Activate
            | Operation::Schedule
            | Operation::Sign
            | Operation::Evolve
            | Operation::ObservePeriod
            | Operation::DevInspect => self.execute_pool_operation(request, response, lease),
            Operation::Info => {
                let durable = &mut *self.durable;
                let authorities = self
                    .handler
                    .with_entropy(|rng| recover_pool_authorities(durable, rng, None))?;
                self.handler
                    .handle_persistent_info(request, response, lease, &authorities)
            }
            Operation::Status if pool_scope(request)?.is_some() => {
                let scope = pool_scope(request)?
                    .ok_or_else(|| status_error(ErrorScope::Pool, Status::WrongPool))?;
                let durable = &mut *self.durable;
                let (authority, recovered) = self
                    .handler
                    .with_entropy(|rng| recover_pool(durable, rng, scope))?;
                self.handler.handle_pool_status(
                    request,
                    response,
                    lease,
                    authority,
                    &recovered.state,
                )
            }
            Operation::Status => {
                let durable = &mut *self.durable;
                let status = self
                    .handler
                    .with_entropy(|rng| recover_management_status(durable, rng))?;
                self.handler
                    .handle_persistent_status(request, response, lease, &status)
            }
            Operation::OpStatus | Operation::GetBackup if pool_scope(request)?.is_some() => {
                let scope = pool_scope(request)?
                    .ok_or_else(|| status_error(ErrorScope::Pool, Status::WrongPool))?;
                let durable = &mut *self.durable;
                let (authority, recovered) = self
                    .handler
                    .with_entropy(|rng| recover_pool(durable, rng, scope))?;
                if request.operation == Operation::OpStatus {
                    self.handler.handle_pool_operation_status(
                        request,
                        response,
                        lease,
                        authority,
                        &recovered.state,
                    )
                } else {
                    let slot = authority.slot();
                    let layout = pool_layout(slot)
                        .map_err(|error| status_journal_error(ErrorScope::Pool, error))?;
                    let mut flash = durable
                        .flash
                        .pool(slot)
                        .map_err(|_| status_error(ErrorScope::Pool, Status::DeviceUnavailable))?;
                    let mut store =
                        FlashPublicObjects::new(&mut flash, layout, &recovered.state)
                            .map_err(|_| status_error(ErrorScope::Pool, Status::StateDamaged))?;
                    self.handler.handle_pool_get_backup(
                        request,
                        response,
                        lease,
                        authority,
                        &recovered.state,
                        &mut store,
                        &mut durable.object.bytes,
                    )
                }
            }
            Operation::OpStatus => {
                let query = request
                    .payload()
                    .required("request")
                    .and_then(|value| value.bytes())
                    .map_err(|_| status_error(ErrorScope::Device, Status::InvalidFrame))?;
                let query = RequestId::try_from(query)
                    .map_err(|_| status_error(ErrorScope::Device, Status::InvalidFrame))?;
                let durable = &mut *self.durable;
                let (epoch, revoked, outcome) = self
                    .handler
                    .with_entropy(|rng| recover_management_operation(durable, rng, query))?;
                self.handler.handle_management_operation_status(
                    request, response, lease, epoch, revoked, outcome,
                )
            }
            Operation::Open
                if !request
                    .map()
                    .required("pool")
                    .map_err(|_| status_error(ErrorScope::Pool, Status::InvalidFrame))?
                    .is_null() =>
            {
                let pool = request
                    .map()
                    .required("pool")
                    .and_then(|v| v.bytes())
                    .map_err(|_| status_error(ErrorScope::Pool, Status::InvalidFrame))?;
                let incarnation = request
                    .map()
                    .required("incarnation")
                    .and_then(|v| v.bytes())
                    .map_err(|_| status_error(ErrorScope::Pool, Status::InvalidFrame))?;
                let scope = Scope::Pool {
                    pool: PoolId::try_from(pool)
                        .map_err(|_| status_error(ErrorScope::Pool, Status::InvalidFrame))?,
                    incarnation: IncarnationId::try_from(incarnation)
                        .map_err(|_| status_error(ErrorScope::Pool, Status::InvalidFrame))?,
                };
                let durable = &mut *self.durable;
                let authorities = self
                    .handler
                    .with_entropy(|rng| recover_pool_authorities(durable, rng, Some(scope)))?;
                let authority = authorities
                    .into_iter()
                    .flatten()
                    .find(|authority| authority.scope() == scope)
                    .ok_or_else(|| status_error(ErrorScope::Pool, Status::WrongPool))?;
                self.handler
                    .handle_pool_open(request, response, lease, authority)
            }
            Operation::Manage
                if request
                    .payload()
                    .required("action")
                    .and_then(|value| value.text())
                    .ok()
                    != Some("ENROLL") =>
            {
                let action = request
                    .payload()
                    .required("action")
                    .and_then(|value| value.text())
                    .map_err(|_| status_error(ErrorScope::Device, Status::InvalidFrame))?;
                let device_target = request
                    .payload()
                    .required("pool")
                    .map_err(|_| status_error(ErrorScope::Device, Status::InvalidFrame))?
                    .is_null();
                match (action, device_target) {
                    ("CREDENTIAL_REPLACE" | "CREDENTIAL_REVOKE", true) => {
                        self.execute_device_credential(request, response, lease)
                    }
                    (
                        "CREDENTIAL_REPLACE" | "CREDENTIAL_REVOKE" | "RECIPIENT_REPLACE"
                        | "STAGED_DISCARD",
                        false,
                    ) => self.execute_pool_management(request, response, lease, scheduler),
                    ("POOL_DELETE", false) => {
                        self.execute_pool_deletion(request, response, lease, scheduler)
                    }
                    ("DEVICE_RETIRE", true) => {
                        self.execute_retirement(request, response, lease, scheduler)
                    }
                    _ => Err(status_error(
                        ErrorScope::Device,
                        Status::UnsupportedOperation,
                    )),
                }
            }
            Operation::Open | Operation::Manage => {
                let durable = &mut *self.durable;
                let storage = EnrollmentStorage::new(
                    durable.device,
                    DIRECTORY.offset() as u32,
                    POOLS.offset() as u32,
                    &durable.storage_root,
                )
                .map_err(|_| status_error(ErrorScope::Device, Status::StateDamaged))?;
                let mut flash = durable
                    .flash
                    .enrollment()
                    .map_err(|_| status_error(ErrorScope::Device, Status::DeviceUnavailable))?;
                let mut work = Workspaces {
                    journal: &mut durable.journal,
                    object: &mut durable.object,
                    cache: &mut durable.cache,
                };
                self.handler
                    .with_enrollment(&storage, &mut flash, &mut work)
                    .handle(request, response, lease, scheduler)
            }
            _ => self.handler.handle(request, response, lease, scheduler),
        }
    }
}

fn abort_interrupted_generation(
    durable: &mut DurableRuntime,
    rng: &mut HealthCheckedEntropy<'static>,
    scope: Scope,
    slot: kes_core::types::HardwareSlot,
) -> Result<(), CommandError> {
    let Scope::Pool { pool, incarnation } = scope else {
        return Err(status_error(ErrorScope::Pool, Status::WrongPool));
    };
    let journal = Journal::<PoolCodec>::new(
        JournalContext {
            device: durable.device,
            scope: JournalScope::Pool {
                slot,
                pool,
                incarnation,
            },
        },
        pool_layout(slot).map_err(|error| status_journal_error(ErrorScope::Pool, error))?,
        &durable.storage_root,
    )
    .map_err(|error| status_journal_error(ErrorScope::Pool, error))?;
    let mut flash = durable
        .flash
        .pool(slot)
        .map_err(|_| status_error(ErrorScope::Pool, Status::DeviceUnavailable))?;
    let mut work = Workspaces {
        journal: &mut durable.journal,
        object: &mut durable.object,
        cache: &mut durable.cache,
    };
    DurablePool::recover_generation(&journal, &mut flash, rng, &mut work)
        .map_err(|error| CommandError::from_operation(ErrorScope::Pool, error))?;
    Ok(())
}

fn complete_generation_job(
    durable: &mut DurableRuntime,
    rng: &mut HealthCheckedEntropy<'static>,
    identity: &DeviceIdentityKey,
    job: ActiveGeneration,
    write: &mut [u8; MAX_PUBLIC_OBJECT_BYTES],
    read: &mut [u8; MAX_PUBLIC_OBJECT_BYTES],
) -> Result<(), CommandError> {
    let (authority, recovered) = recover_pool(durable, rng, job.scope)?;
    if authority.slot() != job.slot {
        return Err(status_error(ErrorScope::Pool, Status::WrongPool));
    }
    let (key, tree) = job
        .generator
        .finish()
        .map_err(|_| status_error(ErrorScope::Pool, Status::StateDamaged))?;
    let verification_key = key
        .verification_key()
        .map_err(|_| status_error(ErrorScope::Pool, Status::StateDamaged))?;
    let tree = tree
        .verify(&verification_key)
        .map_err(|_| status_error(ErrorScope::Pool, Status::StateDamaged))?;
    let Scope::Pool { pool, incarnation } = job.scope else {
        return Err(status_error(ErrorScope::Pool, Status::WrongPool));
    };
    let slot = job.slot;
    let layout =
        pool_layout(slot).map_err(|error| status_journal_error(ErrorScope::Pool, error))?;
    let journal = Journal::<PoolCodec>::new(
        JournalContext {
            device: durable.device,
            scope: JournalScope::Pool {
                slot,
                pool,
                incarnation,
            },
        },
        layout,
        &durable.storage_root,
    )
    .map_err(|error| status_journal_error(ErrorScope::Pool, error))?;
    let mut flash = durable
        .flash
        .pool(slot)
        .map_err(|_| status_error(ErrorScope::Pool, Status::DeviceUnavailable))?;
    let mut work = Workspaces {
        journal: &mut durable.journal,
        object: &mut durable.object,
        cache: &mut durable.cache,
    };
    let mut owner = DurablePool::from_recovered(recovered);
    owner
        .complete_generation(
            &journal,
            &mut flash,
            rng,
            &mut work,
            |flash, rng, pool, coordinator| {
                let mut store = FlashPublicObjects::new(flash, layout, pool)
                    .map_err(generation::Error::Storage)?;
                coordinator.complete(
                    pool,
                    job.operation,
                    key,
                    &tree,
                    durable.device,
                    identity,
                    rng,
                    &mut store,
                    write,
                    read,
                )
            },
        )
        .map_err(|_| status_error(ErrorScope::Pool, Status::StateDamaged))?;
    Ok(())
}

fn pool_scope(request: Envelope<'_>) -> Result<Option<Scope>, CommandError> {
    let pool = request
        .map()
        .required("pool")
        .map_err(|_| status_error(ErrorScope::Pool, Status::InvalidFrame))?;
    if pool.is_null() {
        return Ok(None);
    }
    let pool = PoolId::try_from(
        pool.bytes()
            .map_err(|_| status_error(ErrorScope::Pool, Status::InvalidFrame))?,
    )
    .map_err(|_| status_error(ErrorScope::Pool, Status::InvalidFrame))?;
    let incarnation = IncarnationId::try_from(
        request
            .map()
            .required("incarnation")
            .and_then(|value| value.bytes())
            .map_err(|_| status_error(ErrorScope::Pool, Status::InvalidFrame))?,
    )
    .map_err(|_| status_error(ErrorScope::Pool, Status::InvalidFrame))?;
    Ok(Some(Scope::Pool { pool, incarnation }))
}

fn recover_live_directory(
    durable: &mut DurableRuntime,
    rng: &mut HealthCheckedEntropy<'static>,
) -> Result<DirectorySnapshot, CommandError> {
    recover_directory(durable, rng, false)
}

fn recover_directory(
    durable: &mut DurableRuntime,
    rng: &mut HealthCheckedEntropy<'static>,
    allow_retired: bool,
) -> Result<DirectorySnapshot, CommandError> {
    let mut work = Workspaces {
        journal: &mut durable.journal,
        object: &mut durable.object,
        cache: &mut durable.cache,
    };
    let storage = EnrollmentStorage::new(
        durable.device,
        DIRECTORY.offset() as u32,
        POOLS.offset() as u32,
        &durable.storage_root,
    )
    .map_err(status_enrollment_error)?;
    let mut region = durable
        .flash
        .enrollment()
        .map_err(|_| status_error(ErrorScope::Device, Status::DeviceUnavailable))?;
    let directory = storage
        .recover_pending(&mut region, rng, &mut work)
        .map_err(status_enrollment_error)?
        .state;
    if directory.config.identity.device_id() != &durable.device {
        return Err(status_error(ErrorScope::Device, Status::WrongDevice));
    }
    Device::from_authenticated_snapshot(&directory).map_err(|error| {
        CommandError::from_operation(ErrorScope::Device, OperationError::State(error))
    })?;
    if directory.config.health != Health::Healthy
        || directory.pending_enrollment.is_some()
        || directory.pending_deletion.is_some()
        || (directory.retirement.is_some()
            && (!allow_retired || !durable.retirement_cleanup_verified))
    {
        return Err(status_error(ErrorScope::Device, Status::StateDamaged));
    }
    Ok(directory)
}

/// Resolve an uncertain management write before admitting another command.
/// Only an authenticated durable intent can authorize destructive cleanup.
fn reconcile_management_cleanup(
    durable: &mut DurableRuntime,
    rng: &mut HealthCheckedEntropy<'static>,
) -> Result<(), CommandError> {
    let journal = Journal::<DirectoryCodec>::new(
        JournalContext {
            device: durable.device,
            scope: JournalScope::Directory,
        },
        directory_layout().map_err(|error| status_journal_error(ErrorScope::Device, error))?,
        &durable.storage_root,
    )
    .map_err(|error| status_journal_error(ErrorScope::Device, error))?;
    let mut work = Workspaces {
        journal: &mut durable.journal,
        object: &mut durable.object,
        cache: &mut durable.cache,
    };
    let directory = {
        let mut flash = durable
            .flash
            .directory()
            .map_err(|_| status_error(ErrorScope::Device, Status::DeviceUnavailable))?;
        journal
            .recover(&mut flash, rng, &mut work)
            .map_err(|error| status_journal_error(ErrorScope::Device, error))?
            .state
    };
    if directory.config.identity.device_id() != &durable.device {
        return Err(status_error(ErrorScope::Device, Status::WrongDevice));
    }
    Device::from_authenticated_snapshot(&directory).map_err(|error| {
        CommandError::from_operation(ErrorScope::Device, OperationError::State(error))
    })?;
    if directory.pending_deletion.is_some() {
        recovery::complete_pending_deletion(
            &mut durable.flash,
            rng,
            &durable.storage_root,
            durable.device,
            &mut work,
        )
        .map_err(|_| status_error(ErrorScope::Device, Status::StateDamaged))?;
    }
    if directory.retirement.is_some() {
        recovery::complete_retirement(
            &mut durable.flash,
            rng,
            &durable.storage_root,
            durable.device,
            &mut work,
        )
        .map_err(|_| status_error(ErrorScope::Device, Status::StateDamaged))?;
        durable.retirement_cleanup_verified = true;
    }
    durable.pending_management_cleanup = false;
    Ok(())
}

fn recover_pool(
    durable: &mut DurableRuntime,
    rng: &mut HealthCheckedEntropy<'static>,
    scope: Scope,
) -> Result<(PoolAuthority, Recovered<PoolRegistration>), CommandError> {
    let directory = recover_live_directory(durable, rng)?;
    recover_pool_from_directory(durable, rng, &directory, scope)
}

fn recover_pool_from_directory(
    durable: &mut DurableRuntime,
    rng: &mut HealthCheckedEntropy<'static>,
    directory: &DirectorySnapshot,
    scope: Scope,
) -> Result<(PoolAuthority, Recovered<PoolRegistration>), CommandError> {
    let Scope::Pool { pool, incarnation } = scope else {
        return Err(status_error(ErrorScope::Pool, Status::WrongPool));
    };
    let entry = directory
        .live
        .iter()
        .flatten()
        .copied()
        .find(|entry| entry.pool_id() == pool && entry.incarnation() == incarnation)
        .ok_or_else(|| status_error(ErrorScope::Pool, Status::WrongPool))?;
    let slot = entry.slot();
    let journal = Journal::<PoolCodec>::new(
        JournalContext {
            device: durable.device,
            scope: JournalScope::Pool {
                slot,
                pool,
                incarnation,
            },
        },
        pool_layout(slot).map_err(|error| status_journal_error(ErrorScope::Pool, error))?,
        &durable.storage_root,
    )
    .map_err(|error| status_journal_error(ErrorScope::Pool, error))?;
    let mut region = durable
        .flash
        .pool(slot)
        .map_err(|_| status_error(ErrorScope::Pool, Status::DeviceUnavailable))?;
    let mut work = Workspaces {
        journal: &mut durable.journal,
        object: &mut durable.object,
        cache: &mut durable.cache,
    };
    let recovered = journal
        .recover(&mut region, rng, &mut work)
        .map_err(|error| status_journal_error(ErrorScope::Pool, error))?;
    let authority = PoolAuthority::from_recovered(entry, &recovered)
        .map_err(|_| status_error(ErrorScope::Pool, Status::StateDamaged))?;
    Ok((authority, recovered))
}

/// Recover the signed-INFO counters or one OPEN authority directly from the
/// authenticated live directory and independently scoped pool journals.
fn recover_pool_authorities(
    durable: &mut DurableRuntime,
    rng: &mut HealthCheckedEntropy<'static>,
    wanted: Option<Scope>,
) -> Result<[Option<PoolAuthority>; kes_core::MAX_POOLS], CommandError> {
    let directory = recover_directory(durable, rng, true)?;
    let mut work = Workspaces {
        journal: &mut durable.journal,
        object: &mut durable.object,
        cache: &mut durable.cache,
    };
    let mut authorities = [None; kes_core::MAX_POOLS];
    for entry in directory.live.iter().flatten().copied() {
        if let Some(Scope::Pool { pool, incarnation }) = wanted {
            if entry.pool_id() != pool {
                continue;
            }
            if entry.incarnation() != incarnation {
                return Err(status_error(ErrorScope::Pool, Status::WrongPool));
            }
        }
        let slot = entry.slot();
        let journal = Journal::<PoolCodec>::new(
            JournalContext {
                device: durable.device,
                scope: JournalScope::Pool {
                    slot,
                    pool: entry.pool_id(),
                    incarnation: entry.incarnation(),
                },
            },
            pool_layout(slot).map_err(|error| status_journal_error(ErrorScope::Pool, error))?,
            &durable.storage_root,
        )
        .map_err(|error| status_journal_error(ErrorScope::Pool, error))?;
        let mut region = durable
            .flash
            .pool(slot)
            .map_err(|_| status_error(ErrorScope::Pool, Status::DeviceUnavailable))?;
        let recovered = journal
            .recover(&mut region, rng, &mut work)
            .map_err(|error| status_journal_error(ErrorScope::Pool, error))?;
        authorities[slot.get()] = Some(
            PoolAuthority::from_recovered(entry, &recovered)
                .map_err(|_| status_error(ErrorScope::Pool, Status::StateDamaged))?,
        );
    }
    Ok(authorities)
}

fn recover_management_status(
    durable: &mut DurableRuntime,
    rng: &mut HealthCheckedEntropy<'static>,
) -> Result<ManagementStatus, CommandError> {
    let mut work = Workspaces {
        journal: &mut durable.journal,
        object: &mut durable.object,
        cache: &mut durable.cache,
    };
    // Boot already reconciles enrollment/deletion/retirement. STATUS recovers
    // journals, but must not invent a management transaction to repair them.
    let (mut status, live) = {
        let journal = Journal::<DirectoryCodec>::new(
            JournalContext {
                device: durable.device,
                scope: JournalScope::Directory,
            },
            directory_layout().map_err(|error| status_journal_error(ErrorScope::Device, error))?,
            &durable.storage_root,
        )
        .map_err(|error| status_journal_error(ErrorScope::Device, error))?;
        let mut region = durable
            .flash
            .directory()
            .map_err(|_| status_error(ErrorScope::Device, Status::DeviceUnavailable))?;
        let recovered = journal
            .recover(&mut region, rng, &mut work)
            .map_err(|error| status_journal_error(ErrorScope::Device, error))?;
        let directory = &recovered.state;
        if directory.config.identity.device_id() != &durable.device {
            return Err(status_error(ErrorScope::Device, Status::WrongDevice));
        }
        Device::from_authenticated_snapshot(directory).map_err(|error| {
            CommandError::from_operation(ErrorScope::Device, OperationError::State(error))
        })?;
        match directory.config.health {
            Health::Healthy => {}
            Health::Damaged => return Err(status_error(ErrorScope::Device, Status::StateDamaged)),
            Health::Unavailable => {
                return Err(status_error(ErrorScope::Device, Status::DeviceUnavailable));
            }
        }
        if directory.pending_enrollment.is_some()
            || directory.pending_deletion.is_some()
            || (directory.retirement.is_some() && !durable.retirement_cleanup_verified)
        {
            return Err(status_error(ErrorScope::Device, Status::StateDamaged));
        }
        let mut status = ManagementStatus {
            revision: directory.revision.get(),
            credential_epoch: directory.credential.epoch,
            revoked: directory.credential.revoked,
            management_sequence: directory
                .credential
                .management_replay
                .map_or(0, |replay| replay.sequence.get()),
            retired: directory.retirement.is_some(),
            pools: [None; kes_core::MAX_POOLS],
        };
        for tombstone in directory.tombstones.iter().flatten() {
            // Older snapshots did not retain this value. Do not fabricate it.
            let epoch = tombstone
                .credential_epoch
                .ok_or_else(|| status_error(ErrorScope::Pool, Status::StateDamaged))?;
            let target = status
                .pools
                .iter_mut()
                .find(|slot| slot.is_none())
                .ok_or_else(|| status_error(ErrorScope::Device, Status::StateDamaged))?;
            *target = Some(ManagementPoolStatus {
                pool: tombstone.pool_id,
                incarnation: tombstone.last_incarnation,
                revision: tombstone.deletion_revision.get(),
                credential_epoch: epoch.get(),
                management_sequence: tombstone.management_sequence.get(),
                deleted: true,
                revoked: true,
                active: None,
                staged: None,
            });
        }
        (status, directory.live)
    };
    for entry in live.into_iter().flatten() {
        let slot = entry.slot();
        let journal = Journal::<PoolCodec>::new(
            JournalContext {
                device: durable.device,
                scope: JournalScope::Pool {
                    slot,
                    pool: entry.pool_id(),
                    incarnation: entry.incarnation(),
                },
            },
            pool_layout(slot).map_err(|error| status_journal_error(ErrorScope::Pool, error))?,
            &durable.storage_root,
        )
        .map_err(|error| status_journal_error(ErrorScope::Pool, error))?;
        // A new scoped view for every slot: enrollment's one-pool pin must
        // never be reused to inspect the next pool.
        let mut region = durable
            .flash
            .pool(slot)
            .map_err(|_| status_error(ErrorScope::Pool, Status::DeviceUnavailable))?;
        let recovered = journal
            .recover(&mut region, rng, &mut work)
            .map_err(|error| status_journal_error(ErrorScope::Pool, error))?;
        let pool = &recovered.state;
        if pool.pool_id() != entry.pool_id() || pool.incarnation() != entry.incarnation() {
            return Err(status_error(ErrorScope::Pool, Status::StateDamaged));
        }
        let target = status
            .pools
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or_else(|| status_error(ErrorScope::Device, Status::StateDamaged))?;
        *target = Some(ManagementPoolStatus {
            pool: pool.pool_id(),
            incarnation: pool.incarnation(),
            revision: pool.revision().get(),
            credential_epoch: pool.credential_epoch().get(),
            management_sequence: pool.management_sequence().get(),
            deleted: false,
            revoked: pool.credential_revoked(),
            active: pool.current().map(|generation| generation.id()),
            staged: pool.staged().map(|generation| generation.id()),
        });
    }
    Ok(status)
}

/// Resolve only authenticated, retained replay records. Absence is UNKNOWN:
/// a newer operation may have reclaimed the old result.
fn recover_management_operation(
    durable: &mut DurableRuntime,
    rng: &mut HealthCheckedEntropy<'static>,
    request: RequestId,
) -> Result<(CredentialEpoch, bool, ManagementOperationStatus), CommandError> {
    let mut work = Workspaces {
        journal: &mut durable.journal,
        object: &mut durable.object,
        cache: &mut durable.cache,
    };
    let storage = EnrollmentStorage::new(
        durable.device,
        DIRECTORY.offset() as u32,
        POOLS.offset() as u32,
        &durable.storage_root,
    )
    .map_err(|_| status_error(ErrorScope::Device, Status::StateDamaged))?;
    let directory = {
        let mut region = durable
            .flash
            .enrollment()
            .map_err(|_| status_error(ErrorScope::Device, Status::DeviceUnavailable))?;
        storage
            .recover_pending(&mut region, rng, &mut work)
            .map_err(status_enrollment_error)?
            .state
    };
    if directory.config.identity.device_id() != &durable.device {
        return Err(status_error(ErrorScope::Device, Status::WrongDevice));
    }
    Device::from_authenticated_snapshot(&directory).map_err(|error| {
        CommandError::from_operation(ErrorScope::Device, OperationError::State(error))
    })?;
    if directory.config.health != Health::Healthy
        || directory.pending_deletion.is_some()
        || directory.pending_enrollment.is_some()
        || (directory.retirement.is_some() && !durable.retirement_cleanup_verified)
    {
        return Err(status_error(ErrorScope::Device, Status::StateDamaged));
    }
    let mut result = ManagementOperationStatus::Unknown;
    if let Some(replay) = directory.credential.management_replay {
        match_management_replay(&mut result, request, &replay)?;
    }
    for tombstone in directory.tombstones.iter().flatten() {
        // Retirement creates one tombstone per pool with the same operation
        // ID; its authoritative device replay is the single global result.
        if directory.retirement.is_some_and(|retirement| {
            retirement.management_replay.request == request
                && tombstone.management_replay.request == request
        }) {
            continue;
        }
        match_management_replay(&mut result, request, &tombstone.management_replay)?;
    }
    for entry in directory.live.iter().flatten() {
        let slot = entry.slot();
        let journal = Journal::<PoolCodec>::new(
            JournalContext {
                device: durable.device,
                scope: JournalScope::Pool {
                    slot,
                    pool: entry.pool_id(),
                    incarnation: entry.incarnation(),
                },
            },
            pool_layout(slot).map_err(|error| status_journal_error(ErrorScope::Pool, error))?,
            &durable.storage_root,
        )
        .map_err(|error| status_journal_error(ErrorScope::Pool, error))?;
        let mut region = durable
            .flash
            .pool(slot)
            .map_err(|_| status_error(ErrorScope::Pool, Status::DeviceUnavailable))?;
        let recovered = journal
            .recover(&mut region, rng, &mut work)
            .map_err(|error| status_journal_error(ErrorScope::Pool, error))?;
        if recovered.state.pool_id() != entry.pool_id()
            || recovered.state.incarnation() != entry.incarnation()
        {
            return Err(status_error(ErrorScope::Pool, Status::StateDamaged));
        }
        match_management_replay(&mut result, request, recovered.state.management_replay())?;
    }
    Ok((
        directory.credential.epoch,
        directory.credential.revoked,
        result,
    ))
}

fn match_management_replay(
    result: &mut ManagementOperationStatus,
    request: RequestId,
    replay: &ManagementReplay,
) -> Result<(), CommandError> {
    if replay.request != request {
        return Ok(());
    }
    if !matches!(result, ManagementOperationStatus::Unknown) {
        return Err(status_error(ErrorScope::Device, Status::StateDamaged));
    }
    let ManagementResult::Committed { revision } = replay.result;
    *result = ManagementOperationStatus::Committed {
        management_sequence: replay.sequence.get(),
        revision: revision.get(),
    };
    Ok(())
}

fn status_enrollment_error(error: EnrollmentError) -> CommandError {
    match error {
        EnrollmentError::Journal(error) => status_journal_error(ErrorScope::Device, error),
        EnrollmentError::State(error) => {
            CommandError::from_operation(ErrorScope::Device, OperationError::State(error))
        }
        EnrollmentError::Authorization => status_error(ErrorScope::Device, Status::AuthFailed),
        EnrollmentError::ChangedReplay => status_error(ErrorScope::Device, Status::Replay),
        EnrollmentError::PendingOperation => status_error(ErrorScope::Device, Status::Busy),
        EnrollmentError::SlotNotErased | EnrollmentError::InconsistentState => {
            status_error(ErrorScope::Device, Status::StateDamaged)
        }
    }
}

fn status_error(scope: ErrorScope, status: Status) -> CommandError {
    CommandError { scope, status }
}

fn status_journal_error(scope: ErrorScope, error: JournalError) -> CommandError {
    CommandError::from_operation(scope, OperationError::Journal(error))
}

static STATE: Mutex<ThreadModeRawMutex, RefCell<State>> = Mutex::new(RefCell::new(State::new()));
static GENERATION_SIGNAL: Signal<ThreadModeRawMutex, ()> = Signal::new();

async fn generation_worker() -> ! {
    loop {
        GENERATION_SIGNAL.wait().await;
        while with_state(|state| state.generation_turn()) {
            yield_now().await;
        }
    }
}

fn with_state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    STATE.lock(|state| f(&mut state.borrow_mut()))
}

#[entry]
fn main() -> ! {
    let peripherals = embassy_rp::init(Default::default());
    let (handler, durable) = match boot_handler(peripherals.TRNG, peripherals.FLASH) {
        Ok(result) => result,
        Err(_) => fail_stop(),
    };
    with_state(|state| {
        state.handler = HandlerSlot::Active(handler);
        state.durable = Some(durable);
    });

    let driver = Driver::new(peripherals.USB, Irqs);
    let mut config = Config::new(PROTOTYPE_VID, PROTOTYPE_PID);
    config.bcd_usb = UsbVersion::Two;
    config.device_class = 0;
    config.device_sub_class = 0;
    config.device_protocol = 0;
    config.composite_with_iads = false;
    config.manufacturer = Some("KES Forge development");
    config.product = Some("KES authenticated A2 development");
    config.serial_number = Some("A2-AUTH-DEVELOPMENT");

    let mut config_descriptor = [0; 64];
    let mut bos_descriptor = [0; 16];
    let mut msos_descriptor = [0; 16];
    let mut control = [0; 128];
    let mut bootsel = DevelopmentBootsel;
    let mut builder = Builder::new(
        driver,
        config,
        &mut config_descriptor,
        &mut bos_descriptor,
        &mut msos_descriptor,
        &mut control,
    );
    builder.handler(&mut bootsel);
    let (out_endpoint, in_endpoint) = {
        let mut function = builder.function(0xff, 0x4b, 0x01);
        let mut interface = function.interface();
        let mut alternate = interface.alt_setting(0xff, 0x4b, 0x01, None);
        (
            alternate.endpoint_bulk_out(None, PACKET_BYTES as u16),
            alternate.endpoint_bulk_in(None, PACKET_BYTES as u16),
        )
    };
    let mut usb = builder.build();

    let _ = block_on(join3(
        usb.run(),
        serve(out_endpoint, in_endpoint),
        generation_worker(),
    ));
    fail_stop()
}

fn boot_handler(
    trng: embassy_rp::Peri<'static, peripherals::TRNG>,
    flash: embassy_rp::Peri<'static, peripherals::FLASH>,
) -> Result<(A2Handler, DurableRuntime), ()> {
    let mut entropy = HealthCheckedEntropy::new(trng).map_err(|_| ())?;
    let mut flash = FittedFlash::new(HalFlash::new_blocking(flash)).map_err(|_| ())?;
    let persisted = {
        let mut identity_flash = flash.development_identity().map_err(|_| ())?;
        development_identity::recover(&mut identity_flash).map_err(|_| ())?
    };
    let device = persisted.device();
    let keys = persisted.into_keys().map_err(|_| ())?;
    let identity = DeviceIdentityKey::from_seed(Zeroizing::new(*keys.identity_seed()));
    let hpke = DeviceHpkeKey::from_seed(Zeroizing::new(*keys.session_root()));
    let mut durable = DurableRuntime {
        device,
        flash,
        storage_root: keys.storage_root(),
        journal: JournalWorkspace::new(),
        object: ObjectWorkspace::new(),
        cache: SecretCache::new(),
        provisioned: false,
        retirement_cleanup_verified: false,
        pending_management_cleanup: false,
    };
    let recovery = {
        let mut work = Workspaces {
            journal: &mut durable.journal,
            object: &mut durable.object,
            cache: &mut durable.cache,
        };
        recovery::recover_boot(
            &mut durable.flash,
            &mut entropy,
            &durable.storage_root,
            device,
            &mut work,
        )
    };
    match recovery {
        Ok(boot) => {
            durable.provisioned = true;
            durable.retirement_cleanup_verified = boot.device.retirement().is_some();
        }
        Err(RecoveryError::Enrollment(EnrollmentError::Journal(JournalError::Uninitialized))) => {
            // A blank directory is permitted only for the identity-only image,
            // and only if no pool or reserved journal bytes are present.
            let mut region = durable.flash.development_identity().map_err(|_| ())?;
            let mut page = [0; 256];
            for offset in (development_identity::JOURNAL_START
                ..development_identity::IDENTITY_START)
                .step_by(page.len())
            {
                region.read(offset, &mut page).map_err(|_| ())?;
                if page.iter().any(|byte| *byte != 0xff) {
                    return Err(());
                }
            }
        }
        Err(_) => return Err(()),
    }
    let boot_nonce = *entropy.root_bytes().map_err(|_| ())?;
    let evidence = DevelopmentEvidence {
        // Zero is an explicit unmeasured sentinel for this disposable image.
        firmware_digest: [0; 32],
        hardware_policy_digest: DEVELOPMENT_POLICY_DIGEST,
        security_version: 0,
        capability_evidence: if durable.provisioned {
            ENROLLMENT_CAPABILITY_EVIDENCE
        } else {
            CAPABILITY_EVIDENCE
        },
    };
    let handler = DevelopmentHandler::new(
        device,
        identity,
        hpke,
        boot_nonce,
        QUALIFICATION_MACHINE_KEY,
        entropy,
        evidence,
    )
    .with_completion_clock(monotonic_ms);
    Ok((handler, durable))
}

async fn serve(mut out_endpoint: impl EndpointOut, mut in_endpoint: impl EndpointIn) -> ! {
    let mut packet = [0; PACKET_BYTES];

    'connection: loop {
        with_state(State::disconnect);
        packet.fill(0);
        out_endpoint.wait_enabled().await;
        in_endpoint.wait_enabled().await;
        loop {
            let length = match out_endpoint.read(&mut packet).await {
                Ok(length) => length,
                Err(EndpointError::Disabled) => continue 'connection,
                Err(EndpointError::BufferOverflow) => fail_stop(),
            };
            let now_ms = monotonic_ms();
            let ready = with_state(|state| {
                state
                    .dispatcher
                    .receive(&packet[..length], now_ms)
                    .ok()
                    .is_some_and(|progress| {
                        progress.consumed == length && progress.status == ReceiveStatus::Ready
                    })
            });
            if !ready {
                continue;
            }
            let frame = with_state(|state| state.dispatch(now_ms));
            let Some(frame) = frame else {
                continue;
            };
            if in_endpoint.write(&frame.prefix).await.is_err() {
                continue 'connection;
            }
            let mut offset = 0;
            while offset < frame.body_length {
                let packet_length = (frame.body_length - offset).min(PACKET_BYTES);
                with_state(|state| {
                    packet[..packet_length]
                        .copy_from_slice(&state.response[offset..offset + packet_length]);
                });
                let sent = in_endpoint.write(&packet[..packet_length]).await;
                packet[..packet_length].zeroize();
                if sent.is_err() {
                    continue 'connection;
                }
                offset += packet_length;
            }
            if frame.body_length.is_multiple_of(PACKET_BYTES)
                && in_endpoint.write(&[]).await.is_err()
            {
                continue 'connection;
            }
            with_state(|state| state.response[..frame.body_length].zeroize());
        }
    }
}

fn monotonic_ms() -> u64 {
    loop {
        let high = pac::TIMER0.timerawh().read();
        let low = pac::TIMER0.timerawl().read();
        if high == pac::TIMER0.timerawh().read() {
            return ((u64::from(high) << 32) | u64::from(low)) / 1_000;
        }
    }
}

fn fail_stop() -> ! {
    loop {
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    fail_stop()
}
