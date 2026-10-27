//! Authenticated operational period reconciliation, never a telemetry side effect.
//!
//! The caller retains the original scheduler lease: dispatch only before its
//! deadline, never renew it for flash work, and discard late replies without
//! claiming that an already committed rotation was rolled back.

use super::pool_sessions::PoolAuthority;
use crate::{pool_service::FlashPublicObjects, usb::CommandError};
use kes_core::{
    activation::{DurablePool, OperationContext, OperationError},
    certificate::CertificateError,
    crypto::{CryptoError, PublicTreeBuffer},
    generation::PublicObjectStore,
    journal::{Flash, Journal, JournalLayout, PoolCodec, Workspaces},
    rotation::{PeriodObservationOutcome, PeriodObservationRequest},
    session::{AuthenticatedRequest, Scope},
    state::{Actor, Lifecycle, MAX_PUBLIC_OBJECT_BYTES, PublicObject, StateError},
    types::{AbsolutePeriod, RequestId, Revision},
};
use kes_protocol::{Envelope, ErrorScope, Operation, Status};
use rand_chacha::rand_core::TryCryptoRng;

/// OK encodes the retained generation's Descriptor; EXPIRED encodes Context.
/// `committed_write` is false for pending schedules and exact-period retries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Outcome {
    pub context: OperationContext,
    pub committed_write: bool,
}
impl Outcome {
    pub fn status(&self) -> Status {
        if self.context.lifecycle == Lifecycle::CurrentExpired {
            Status::Expired
        } else {
            Status::Ok
        }
    }
}

/// Execute using the sole recovered owner and its matching slot-scoped journal.
///
/// Authentication MUST cover this exact envelope. Both scratch buffers are public
/// and distinct from journal workspaces. Load the scheduled target tree only at
/// eligibility; before then the core returns the actual active descriptor without
/// evolving it. The core alone owns atomic rotation, erasure, CLEAN and readback.
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
    if request.operation != Operation::ObservePeriod {
        return Err(error(Status::UnsupportedOperation));
    }
    let state = owner.state().map_err(operation_error)?;
    if !authority.matches_pool(state) {
        return Err(error(Status::WrongPool));
    }
    if authenticated.scope != authority.scope()
        || authenticated.operation != request.operation.as_str()
        || authenticated.request != RequestId::from_bytes(array(request.map(), "request")?)
        || authenticated.sequence != uint(request.map(), "seq")?
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
    if array::<28>(request.map(), "pool")? != *pool_id.as_bytes()
        || array::<16>(request.map(), "incarnation")? != *incarnation.as_bytes()
    {
        return Err(error(Status::WrongPool));
    }
    let network = request.network().map_err(|_| error(Status::InvalidFrame))?;
    if &network != state.network() {
        return Err(error(Status::WrongNetwork));
    }
    let expected_revision = Revision::new(uint(request.payload(), "expected_revision")?);
    if expected_revision != state.revision() {
        return Err(error(Status::RevisionConflict));
    }
    let previous_revision = state.revision();
    let absolute_period = AbsolutePeriod::new(uint(request.payload(), "absolute_period")?);
    // No active generation is not an empty successful Descriptor. Preserve the
    // core's STALE_GENERATION semantics, even if a certified staged key exists.
    let current = state.current().ok_or(error(Status::StaleGeneration))?;
    let target = match state.activation_intent() {
        Some(intent) if absolute_period >= intent.activation_absolute_period() => state
            .staged()
            .filter(|staged| staged.id() == intent.target_generation())
            .ok_or(error(Status::StateDamaged))?,
        _ => current,
    };
    let reference = *target.public_object_ref();
    let verification_key = *target.verification_key();
    let activating = state
        .activation_intent()
        .is_some_and(|intent| absolute_period >= intent.activation_absolute_period());
    let length = {
        let mut store = FlashPublicObjects::new(flash, layout, state)
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
    let result = owner.observe_period(
        journal,
        flash,
        rng,
        work,
        PeriodObservationRequest {
            actor: Actor::Pool {
                pool: pool_id,
                incarnation,
            },
            expected_revision,
            absolute_period,
            network: &network,
        },
        &tree,
    );
    let context = match result {
        Ok(
            PeriodObservationOutcome::Pending(context)
            | PeriodObservationOutcome::Activated(context),
        ) => context,
        Ok(PeriodObservationOutcome::Evolved(outcome)) => outcome.context,
        Err(OperationError::State(StateError::Certificate(CertificateError::Expired)))
            if !activating =>
        {
            // Only an already durably expired current generation can produce
            // EXPIRED Context. An expired replacement certificate is an error;
            // never mislabel an unchanged live active key as expired.
            let state = owner.state().map_err(operation_error)?;
            let current = state
                .current()
                .filter(|generation| generation.lifecycle() == Lifecycle::CurrentExpired)
                .ok_or(error(Status::CertificateInvalid))?;
            let certificate = current.certificate().ok_or(error(Status::StateDamaged))?;
            OperationContext {
                revision: state.revision(),
                generation: current.id(),
                certificate_digest: *certificate.digest(),
                relative_period: current.relative_period(),
                lifecycle: current.lifecycle(),
            }
        }
        Err(cause) => return Err(operation_error(cause)),
    };
    Ok(Outcome {
        committed_write: context.revision != previous_revision,
        context,
    })
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
        OperationError::State(StateError::Unauthorized | StateError::PolicyChanged) => {
            Status::AuthFailed
        }
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
        _ => Status::StateDamaged,
    })
}
