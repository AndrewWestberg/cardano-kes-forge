//! Execution of already session-authenticated pool lifecycle requests.
//! The caller recovers authority and the durable owner from the same slot before
//! each request, and authenticates the response only after this function returns.
//! All secret evolution, replacement cleanup and journal readback remain inside
//! the durable core owner; this module owns only bounded public scratch.

use crate::{
    development::pool_sessions::PoolAuthority,
    pool_service::{FlashPublicObjects, ObjectStoreError},
};
use kes_core::{
    activation::{
        ActivationRequest, CertificationRequest, DurablePool, OperationContext, OperationError,
        ScheduleRequest,
    },
    cbor::Map,
    crypto::PublicTreeBuffer,
    generation::PublicObjectStore,
    journal::{Flash, Journal, JournalLayout, PoolCodec, Workspaces},
    rotation::ReplacementActivationRequest,
    session::Scope,
    state::{Actor, MAX_PUBLIC_OBJECT_BYTES, PublicObject, StateError},
    types::{
        AbsolutePeriod, EnrolledGenesisHash, GenerationId, NetworkBinding, RequestId, Revision,
    },
};
use kes_protocol::{Envelope, Error as ProtocolError, Operation};
use rand_chacha::rand_core::TryCryptoRng;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationError {
    Protocol(ProtocolError),
    WrongPool,
    Operation(OperationError),
    Storage(ObjectStoreError),
}
impl From<ProtocolError> for ActivationError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}
impl From<kes_core::cbor::Error> for ActivationError {
    fn from(error: kes_core::cbor::Error) -> Self {
        Self::Protocol(error.into())
    }
}
impl From<OperationError> for ActivationError {
    fn from(error: OperationError) -> Self {
        Self::Operation(error)
    }
}

/// Public durable context; encode the protocol Descriptor from the retained
/// generation with this id in `pool.state()`. Never acknowledge an error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActivationOutcome {
    pub context: OperationContext,
    pub committed_write: bool,
}

/// Execute CERTIFY, ACTIVATE (first or replacement), or SCHEDULE.
///
/// `request` MUST already have passed session authentication against `authority`.
/// `flash` MUST be the matching slot-scoped flash used to recover `pool`, with
/// `layout` the layout used to construct `journal`. Both public scratch buffers
/// must be distinct from the journal workspaces. The temporary object-store
/// flash borrow ends before any durable transition. A success is returned only
/// after the core journal transaction completes cleanup and authenticated
/// readback, or the core proves an intrinsic CERTIFY/SCHEDULE no-write retry.
/// ACTIVATE retains the core's strict expected-revision semantics: reconcile a
/// lost response through recovered STATUS, never infer success from RAM.
#[allow(clippy::too_many_arguments)]
pub fn execute<F: Flash, R: TryCryptoRng>(
    request: Envelope<'_>,
    authority: PoolAuthority,
    pool: &mut DurablePool,
    journal: &Journal<PoolCodec>,
    flash: &mut F,
    layout: JournalLayout,
    rng: &mut R,
    work: &mut Workspaces<'_>,
    object_scratch: &mut [u8; MAX_PUBLIC_OBJECT_BYTES],
    tree_scratch: &mut PublicTreeBuffer,
) -> Result<ActivationOutcome, ActivationError> {
    if !matches!(
        request.operation,
        Operation::Certify | Operation::Activate | Operation::Schedule
    ) {
        return Err(ProtocolError::UnsupportedOperation.into());
    }
    let state = pool.state()?;
    if !authority.matches_pool(state) {
        return Err(ActivationError::WrongPool);
    }
    let Scope::Pool {
        pool: pool_id,
        incarnation,
    } = authority.scope()
    else {
        return Err(ActivationError::WrongPool);
    };
    if array::<28>(request.map(), "pool")? != *pool_id.as_bytes()
        || array::<16>(request.map(), "incarnation")? != *incarnation.as_bytes()
    {
        return Err(ActivationError::WrongPool);
    }
    let actor = Actor::Pool {
        pool: pool_id,
        incarnation,
    };
    let previous_revision = state.revision();
    let payload = request.payload();
    let generation = GenerationId::from_bytes(array(payload, "generation")?);
    let expected_revision = Revision::new(payload.required("expected_revision")?.uint()?);
    let context = match request.operation {
        Operation::Certify => {
            let network = network(payload.required("network")?.map()?)?;
            let canonical_certificate = payload.required("certificate")?.bytes()?;
            pool.certify(
                journal,
                flash,
                rng,
                work,
                CertificationRequest {
                    actor,
                    expected_revision,
                    generation,
                    canonical_certificate,
                    network: &network,
                },
            )?
        }
        Operation::Schedule => {
            let expected_active_generation = expected_active(payload)?.ok_or(
                ActivationError::Operation(OperationError::State(StateError::StaleGeneration)),
            )?;
            let outcome = pool.schedule(
                journal,
                flash,
                rng,
                work,
                ScheduleRequest {
                    actor,
                    expected_revision,
                    expected_active_generation,
                    generation,
                    certificate_digest: array(payload, "certificate_digest")?,
                    activation_absolute_period: AbsolutePeriod::new(
                        payload.required("activation_absolute_period")?.uint()?,
                    ),
                    creation_request: RequestId::from_bytes(array(request.map(), "request")?),
                },
            )?;
            return Ok(ActivationOutcome {
                context: outcome.context,
                committed_write: outcome.committed_write,
            });
        }
        Operation::Activate => {
            let expected_active_generation = expected_active(payload)?;
            let certificate_digest = array(payload, "certificate_digest")?;
            let current_absolute_period =
                AbsolutePeriod::new(payload.required("current_absolute_period")?.uint()?);
            let state = pool.state()?;
            let target = state
                .staged()
                .filter(|target| target.id() == generation)
                .ok_or(ActivationError::Operation(OperationError::State(
                    StateError::StaleGeneration,
                )))?;
            let reference = *target.public_object_ref();
            let verification_key = *target.verification_key();
            let length = {
                let mut store = FlashPublicObjects::new(flash, layout, state)
                    .map_err(ActivationError::Storage)?;
                store
                    .read(&reference, object_scratch)
                    .map_err(ActivationError::Storage)?
            };
            let object =
                PublicObject::parse(&object_scratch[..length], &reference, &verification_key)
                    .map_err(|error| ActivationError::Operation(OperationError::State(error)))?;
            // The crypto API deliberately requires an owned public tree buffer.
            // Verify after loading, against the authenticated generation key.
            tree_scratch.as_bytes_mut().copy_from_slice(object.tree());
            let tree = tree_scratch.verify(&verification_key).map_err(|_| {
                ActivationError::Operation(OperationError::State(StateError::InvalidObject))
            })?;
            match expected_active_generation {
                None => pool.activate_first(
                    journal,
                    flash,
                    rng,
                    work,
                    ActivationRequest {
                        actor,
                        expected_revision,
                        expected_active_generation,
                        generation,
                        certificate_digest,
                        current_absolute_period,
                    },
                    &tree,
                )?,
                Some(expected_active_generation) => pool.activate_replacement(
                    journal,
                    flash,
                    rng,
                    work,
                    ReplacementActivationRequest {
                        actor,
                        expected_revision,
                        expected_active_generation,
                        generation,
                        certificate_digest,
                        current_absolute_period,
                    },
                    &tree,
                )?,
            }
        }
        _ => return Err(ProtocolError::UnsupportedOperation.into()),
    };
    Ok(ActivationOutcome {
        context,
        committed_write: context.revision != previous_revision,
    })
}

fn array<const N: usize>(map: Map<'_>, name: &str) -> Result<[u8; N], ActivationError> {
    map.required(name)?
        .bytes()?
        .try_into()
        .map_err(|_| ProtocolError::InvalidLength.into())
}
fn expected_active(payload: Map<'_>) -> Result<Option<GenerationId>, ActivationError> {
    let value = payload.required("expected_active_generation")?;
    if value.is_null() {
        Ok(None)
    } else {
        Ok(Some(GenerationId::from_bytes(array(
            payload,
            "expected_active_generation",
        )?)))
    }
}
fn network(map: Map<'_>) -> Result<NetworkBinding, ActivationError> {
    NetworkBinding::from_enrolled_digest(
        u32::try_from(map.required("network_magic")?.uint()?)
            .map_err(|_| ProtocolError::InvalidValue)?,
        EnrolledGenesisHash::from_bytes(array(map, "shelley_genesis_digest")?),
        map.required("slots_per_kes_period")?.uint()?,
        map.required("max_kes_evolutions")?.uint()?,
    )
    .map_err(|_| ProtocolError::InvalidValue.into())
}
