//! SIGN/EVOLVE execution for authenticated, freshly recovered development pools.
//!
//! The caller owns session authentication/response MACs and the original scheduler
//! lease. Call only while that lease permits dispatch; do not restart its deadline
//! around flash work, and discard late responses without claiming rollback.

use super::pool_sessions::PoolAuthority;
use crate::{pool_service::FlashPublicObjects, usb::CommandError};
use kes_core::{
    activation::{DurablePool, EvolutionRequest, OperationContext, OperationError},
    certificate::CertificateError,
    crypto::{CryptoError, PublicTreeBuffer},
    generation::PublicObjectStore,
    journal::{Flash, Journal, JournalLayout, PoolCodec, Workspaces},
    session::{AuthenticatedRequest, Scope},
    signing::{SigningRequest, SigningResult},
    state::{Actor, Lifecycle, MAX_PUBLIC_OBJECT_BYTES, PublicObject, StateError},
    types::{AbsolutePeriod, GenerationId, RequestId, Revision},
};
use kes_protocol::{Envelope, ErrorScope, MAX_MESSAGE_BYTES, Operation, Status};
use rand_chacha::rand_core::TryCryptoRng;

/// Only public results leave the durable owner. Expiry never includes a signature.
pub enum Outcome {
    Signed(SigningResult),
    Evolved(OperationContext),
    Expired(OperationContext),
}

impl Outcome {
    pub fn status(&self) -> Status {
        match self {
            Self::Expired(_) => Status::Expired,
            Self::Signed(_) | Self::Evolved(_) => Status::Ok,
        }
    }

    pub fn context(&self) -> &OperationContext {
        match self {
            Self::Signed(result) => &result.context,
            Self::Evolved(context) | Self::Expired(context) => context,
        }
    }
}

/// Execute against the sole mutable durable owner, never a cloned pool state.
///
/// `authority`, `owner`, `journal`, `layout` and slot-scoped `flash` must come
/// from the same authenticated recovery. Authentication must cover this exact
/// envelope. Neither scratch buffer contains secret material; the public tree
/// copy is required by the core's typed verified-tree API.
#[allow(clippy::too_many_arguments)]
pub fn execute<F: Flash, R: TryCryptoRng>(
    request: Envelope<'_>,
    authenticated: AuthenticatedRequest<'_>,
    authority: PoolAuthority,
    owner: &mut DurablePool,
    journal: &Journal<PoolCodec>,
    flash: &mut F,
    layout: JournalLayout,
    rng: &mut R,
    work: &mut Workspaces<'_>,
    object: &mut [u8; MAX_PUBLIC_OBJECT_BYTES],
    tree_buffer: &mut PublicTreeBuffer,
) -> Result<Outcome, CommandError> {
    if !matches!(request.operation, Operation::Sign | Operation::Evolve) {
        return Err(error(Status::UnsupportedOperation));
    }
    let pool = owner.state().map_err(operation_error)?;
    if !authority.matches_pool(pool) {
        return Err(error(Status::WrongPool));
    }
    if authenticated.scope != authority.scope()
        || authenticated.operation != request.operation.as_str()
        || authenticated.request != RequestId::from_bytes(array(request.map(), "request")?)
    {
        return Err(error(Status::AuthFailed));
    }
    let Scope::Pool {
        pool: pool_id,
        incarnation,
    } = authority.scope()
    else {
        return Err(error(Status::WrongPool));
    };
    // Check the wire scope as well as the session projection before object I/O.
    if array::<28>(request.map(), "pool")? != *pool_id.as_bytes()
        || array::<16>(request.map(), "incarnation")? != *incarnation.as_bytes()
    {
        return Err(error(Status::WrongPool));
    }
    let actor = Actor::Pool {
        pool: pool_id,
        incarnation,
    };
    let network = request.network().map_err(|_| error(Status::InvalidFrame))?;
    if &network != pool.network() {
        return Err(error(Status::WrongNetwork));
    }
    let payload = request.payload();
    let generation_id = GenerationId::from_bytes(array(payload, "generation")?);
    let certificate_digest = array(payload, "certificate_digest")?;
    let generation = pool
        .current()
        .filter(|current| current.id() == generation_id)
        .ok_or(error(Status::StaleGeneration))?;
    // Reject stale certificate context before reading or mutating anything.
    let certificate = generation
        .certificate()
        .ok_or(error(Status::CertificateInvalid))?;
    if certificate.digest() != &certificate_digest {
        return Err(error(Status::CertificateInvalid));
    }
    let absolute_period = AbsolutePeriod::new(uint(
        payload,
        if request.operation == Operation::Sign {
            "absolute_period"
        } else {
            "target_absolute_period"
        },
    )?);
    let expected_revision = if request.operation == Operation::Evolve {
        let revision = Revision::new(uint(payload, "expected_revision")?);
        if revision != pool.revision() {
            return Err(error(Status::RevisionConflict));
        }
        Some(revision)
    } else {
        None
    };
    let message = if request.operation == Operation::Sign {
        let message = payload
            .required("message")
            .and_then(|value| value.bytes())
            .map_err(|_| error(Status::InvalidFrame))?;
        if message.len() > MAX_MESSAGE_BYTES {
            return Err(error(Status::InvalidFrame));
        }
        message
    } else {
        &[]
    };
    let verification_key = *generation.verification_key();
    let reference = *generation.public_object_ref();
    // The adapter protects retained objects and restricts reads to this pool's
    // two immutable slots. Its reference comes only from authenticated state.
    let length = {
        let mut store = FlashPublicObjects::new(flash, layout, pool)
            .map_err(|_| error(Status::StateDamaged))?;
        store
            .read(&reference, object)
            .map_err(|_| error(Status::StateDamaged))?
    };
    let public = PublicObject::parse(&object[..length], &reference, &verification_key)
        .map_err(|_| error(Status::StateDamaged))?;
    tree_buffer.as_bytes_mut().copy_from_slice(public.tree());
    let tree = tree_buffer
        .verify(&verification_key)
        .map_err(|_| error(Status::StateDamaged))?;
    if let Some(expected_revision) = expected_revision {
        let result = owner.evolve(
            journal,
            flash,
            rng,
            work,
            EvolutionRequest {
                actor,
                expected_revision,
                generation: generation_id,
                certificate_digest,
                target_absolute_period: absolute_period,
                network: &network,
            },
            &tree,
        );
        let result = match result {
            Ok(result) => result,
            Err(OperationError::State(StateError::Certificate(CertificateError::Expired))) => {
                return expired(owner, generation_id);
            }
            Err(cause) => return Err(operation_error(cause)),
        };
        return Ok(if result.context.lifecycle == Lifecycle::CurrentExpired {
            Outcome::Expired(result.context)
        } else {
            Outcome::Evolved(result.context)
        });
    }
    match owner.sign(
        journal,
        flash,
        rng,
        work,
        SigningRequest {
            actor,
            generation: generation_id,
            certificate_digest,
            absolute_period,
            network: &network,
            message,
        },
        &tree,
    ) {
        Ok(result) => Ok(Outcome::Signed(result)),
        Err(OperationError::State(StateError::Certificate(CertificateError::Expired))) => {
            expired(owner, generation_id)
        }
        Err(cause) => Err(operation_error(cause)),
    }
}

fn expired(owner: &DurablePool, generation: GenerationId) -> Result<Outcome, CommandError> {
    // The core reports expiry only after clean persistence, or for an already
    // expired recovered generation. Publish only actual durable public metadata.
    let state = owner.state().map_err(operation_error)?;
    let current = state
        .current()
        .filter(|current| current.id() == generation)
        .ok_or(error(Status::StateDamaged))?;
    if current.lifecycle() != Lifecycle::CurrentExpired {
        return Err(error(Status::StateDamaged));
    }
    let certificate = current.certificate().ok_or(error(Status::StateDamaged))?;
    Ok(Outcome::Expired(OperationContext {
        revision: state.revision(),
        generation: current.id(),
        certificate_digest: *certificate.digest(),
        relative_period: current.relative_period(),
        lifecycle: current.lifecycle(),
    }))
}

fn array<const N: usize>(
    map: kes_core::cbor::Map<'_>,
    name: &str,
) -> Result<[u8; N], CommandError> {
    map.required(name)
        .and_then(|value| value.bytes())
        .map_err(|_| error(Status::InvalidFrame))?
        .try_into()
        .map_err(|_| error(Status::InvalidFrame))
}

fn uint(map: kes_core::cbor::Map<'_>, name: &str) -> Result<u64, CommandError> {
    map.required(name)
        .and_then(|value| value.uint())
        .map_err(|_| error(Status::InvalidFrame))
}

const fn error(status: Status) -> CommandError {
    CommandError {
        scope: ErrorScope::Pool,
        status,
    }
}

fn operation_error(cause: OperationError) -> CommandError {
    error(match cause {
        OperationError::Journal(kes_core::journal::JournalError::EntropyFailure) => {
            Status::EntropyFailure
        }
        OperationError::Journal(kes_core::journal::JournalError::RevisionConflict) => {
            Status::RevisionConflict
        }
        OperationError::State(StateError::Unauthorized) => Status::AuthFailed,
        OperationError::State(StateError::WrongPool | StateError::WrongIncarnation) => {
            Status::WrongPool
        }
        OperationError::State(StateError::StaleGeneration) => Status::StaleGeneration,
        OperationError::State(StateError::RevisionConflict) => Status::RevisionConflict,
        OperationError::State(
            StateError::SecurityNotReady | StateError::DevelopmentOptInRequired,
        ) => Status::SecurityNotReady,
        OperationError::State(StateError::Unavailable) => Status::DeviceUnavailable,
        OperationError::State(StateError::Certificate(CertificateError::WrongNetwork)) => {
            Status::WrongNetwork
        }
        OperationError::State(StateError::Certificate(CertificateError::NotYetValid)) => {
            Status::NotYetValid
        }
        OperationError::State(StateError::Certificate(_)) => Status::CertificateInvalid,
        OperationError::State(StateError::Crypto(CryptoError::StalePeriod)) => Status::StalePeriod,
        OperationError::State(StateError::Crypto(CryptoError::MessageTooLong)) => {
            Status::InvalidFrame
        }
        _ => Status::StateDamaged,
    })
}
