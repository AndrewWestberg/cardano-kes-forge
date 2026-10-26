//! Durable low-level certification, first activation, and forward evolution.
//! Every acknowledged mutation returns only after journal CLEAN completion.

use crate::{
    crypto::{CryptoError, VerifiedPublicTree},
    journal::{Flash, Journal, JournalError, PoolCodec, ReadyToken, Recovered, Workspaces},
    state::{
        ActivationIntent, ActiveEvolutionTransition, Actor, CertificationOutcome,
        FirstActivationTransition, GenerationPolicy, KESGeneration, Lifecycle, PoolRegistration,
        ScheduleActivationTransition, StateError,
    },
    types::{AbsolutePeriod, GenerationId, NetworkBinding, RelativePeriod, RequestId, Revision},
};
use rand_chacha::rand_core::TryCryptoRng;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationError {
    State(StateError),
    Journal(JournalError),
    Invalidated,
    SelfVerification,
}
impl core::fmt::Display for OperationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::State(error) => core::fmt::Display::fmt(error, f),
            Self::Journal(error) => core::fmt::Display::fmt(error, f),
            Self::Invalidated => f.write_str("durable pool must be recovered before use"),
            Self::SelfVerification => f.write_str("generated signature failed self-verification"),
        }
    }
}
impl core::error::Error for OperationError {}
impl From<StateError> for OperationError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}
impl From<JournalError> for OperationError {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationContext {
    pub revision: Revision,
    pub generation: GenerationId,
    pub certificate_digest: [u8; 32],
    pub relative_period: RelativePeriod,
    pub lifecycle: Lifecycle,
}

pub struct CertificationRequest<'a> {
    pub actor: Actor,
    pub expected_revision: Revision,
    pub generation: GenerationId,
    pub canonical_certificate: &'a [u8],
    pub network: &'a NetworkBinding,
}

#[derive(Clone, Copy)]
pub struct ActivationRequest {
    pub actor: Actor,
    pub expected_revision: Revision,
    pub expected_active_generation: Option<GenerationId>,
    pub generation: GenerationId,
    pub certificate_digest: [u8; 32],
    pub current_absolute_period: AbsolutePeriod,
}

#[derive(Clone, Copy)]
pub struct ScheduleRequest {
    pub actor: Actor,
    pub expected_revision: Revision,
    pub expected_active_generation: GenerationId,
    pub generation: GenerationId,
    pub certificate_digest: [u8; 32],
    pub activation_absolute_period: AbsolutePeriod,
    pub creation_request: RequestId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScheduleOutcome {
    pub context: OperationContext,
    pub committed_write: bool,
}

pub struct EvolutionRequest<'a> {
    pub actor: Actor,
    pub expected_revision: Revision,
    pub generation: GenerationId,
    pub certificate_digest: [u8; 32],
    pub target_absolute_period: AbsolutePeriod,
    pub network: &'a NetworkBinding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvolutionOutcome {
    pub context: OperationContext,
    pub committed_write: bool,
}

/// Owns the sole decoded live pool state associated with one authenticated
/// journal token. A persistence failure wipes RAM secrets and requires recovery.
pub struct DurablePool {
    pub(crate) state: PoolRegistration,
    pub(crate) token: ReadyToken,
    pub(crate) usable: bool,
}
impl DurablePool {
    pub fn new(state: PoolRegistration, token: ReadyToken) -> Result<Self, OperationError> {
        if state.revision() != token.revision() {
            return Err(OperationError::Journal(JournalError::RevisionConflict));
        }
        Ok(Self {
            state,
            token,
            usable: true,
        })
    }

    pub fn from_recovered(recovered: Recovered<PoolRegistration>) -> Self {
        Self {
            state: recovered.state,
            token: recovered.token,
            usable: true,
        }
    }

    pub const fn is_usable(&self) -> bool {
        self.usable
    }

    pub fn state(&self) -> Result<&PoolRegistration, OperationError> {
        self.ensure_usable()?;
        Ok(&self.state)
    }

    pub const fn activation_intent(&self) -> Option<&ActivationIntent> {
        self.state.activation_intent()
    }

    pub fn stage_generation<F: Flash, R: TryCryptoRng>(
        &mut self,
        journal: &Journal<PoolCodec>,
        flash: &mut F,
        rng: &mut R,
        work: &mut Workspaces<'_>,
        actor: Actor,
        expected_revision: Revision,
        generation: KESGeneration,
        policy: GenerationPolicy,
    ) -> Result<Revision, OperationError> {
        self.ensure_usable()?;
        self.state
            .stage(actor, expected_revision, generation, policy)?;
        self.persist(journal, flash, rng, work)?;
        Ok(self.state.revision())
    }
    pub fn certify<F: Flash, R: TryCryptoRng>(
        &mut self,
        journal: &Journal<PoolCodec>,
        flash: &mut F,
        rng: &mut R,
        work: &mut Workspaces<'_>,
        request: CertificationRequest<'_>,
    ) -> Result<OperationContext, OperationError> {
        self.ensure_usable()?;
        let outcome = self.state.certify(
            request.actor,
            request.expected_revision,
            request.generation,
            request.canonical_certificate,
            request.network,
        )?;
        if matches!(outcome, CertificationOutcome::Applied { .. }) {
            self.persist(journal, flash, rng, work)?;
        }
        self.context(request.generation)
    }

    pub fn activate_first<F: Flash, R: TryCryptoRng>(
        &mut self,
        journal: &Journal<PoolCodec>,
        flash: &mut F,
        rng: &mut R,
        work: &mut Workspaces<'_>,
        request: ActivationRequest,
        tree: &VerifiedPublicTree<'_>,
    ) -> Result<OperationContext, OperationError> {
        self.ensure_usable()?;
        let result = self.state.activate_first_state(FirstActivationTransition {
            actor: request.actor,
            expected_revision: request.expected_revision,
            expected_active_generation: request.expected_active_generation,
            generation: request.generation,
            certificate_digest: request.certificate_digest,
            current_absolute_period: request.current_absolute_period,
            tree,
        });
        self.handle_transition_result(result)?;
        self.persist(journal, flash, rng, work)?;
        self.context(request.generation)
    }

    pub fn schedule<F: Flash, R: TryCryptoRng>(
        &mut self,
        journal: &Journal<PoolCodec>,
        flash: &mut F,
        rng: &mut R,
        work: &mut Workspaces<'_>,
        request: ScheduleRequest,
    ) -> Result<ScheduleOutcome, OperationError> {
        self.ensure_usable()?;
        let changed = self
            .state
            .schedule_activation_state(ScheduleActivationTransition {
                actor: request.actor,
                expected_revision: request.expected_revision,
                expected_active_generation: request.expected_active_generation,
                generation: request.generation,
                certificate_digest: request.certificate_digest,
                activation_absolute_period: request.activation_absolute_period,
                creation_request: request.creation_request,
            })?;
        if changed {
            self.persist(journal, flash, rng, work)?;
        }
        Ok(ScheduleOutcome {
            context: self.context(request.generation)?,
            committed_write: changed,
        })
    }

    pub fn evolve<F: Flash, R: TryCryptoRng>(
        &mut self,
        journal: &Journal<PoolCodec>,
        flash: &mut F,
        rng: &mut R,
        work: &mut Workspaces<'_>,
        request: EvolutionRequest<'_>,
        tree: &VerifiedPublicTree<'_>,
    ) -> Result<EvolutionOutcome, OperationError> {
        self.ensure_usable()?;
        let result = self.state.evolve_active_state(ActiveEvolutionTransition {
            actor: request.actor,
            expected_revision: request.expected_revision,
            generation: request.generation,
            certificate_digest: request.certificate_digest,
            target_absolute_period: request.target_absolute_period,
            request_network: request.network,
            tree,
        });
        let changed = self.handle_transition_result(result)?;
        if changed {
            self.persist(journal, flash, rng, work)?;
        }
        Ok(EvolutionOutcome {
            context: self.context(request.generation)?,
            committed_write: changed,
        })
    }

    pub(crate) fn current_generation(
        &self,
        generation: GenerationId,
    ) -> Result<&KESGeneration, OperationError> {
        self.ensure_usable()?;
        let current = self
            .state
            .current()
            .ok_or(OperationError::State(StateError::StaleGeneration))?;
        if current.id() != generation {
            return Err(OperationError::State(StateError::StaleGeneration));
        }
        Ok(current)
    }

    pub(crate) fn invalidate(&mut self) {
        self.state.erase_all_secrets();
        self.usable = false;
    }

    pub(crate) fn ensure_usable(&self) -> Result<(), OperationError> {
        if self.usable {
            Ok(())
        } else {
            Err(OperationError::Invalidated)
        }
    }

    pub(crate) fn handle_transition_result<T>(
        &mut self,
        result: Result<T, StateError>,
    ) -> Result<T, OperationError> {
        match result {
            Ok(value) => Ok(value),
            Err(StateError::Crypto(
                error @ (CryptoError::StalePeriod
                | CryptoError::LifetimeExceeded
                | CryptoError::InvalidPeriod
                | CryptoError::MessageTooLong),
            )) => Err(OperationError::State(StateError::Crypto(error))),
            Err(error @ StateError::Crypto(_)) => {
                self.invalidate();
                Err(OperationError::State(error))
            }
            Err(error) => Err(OperationError::State(error)),
        }
    }

    pub(crate) fn persist<F: Flash, R: TryCryptoRng>(
        &mut self,
        journal: &Journal<PoolCodec>,
        flash: &mut F,
        rng: &mut R,
        work: &mut Workspaces<'_>,
    ) -> Result<(), OperationError> {
        match journal.transact_successor(flash, rng, &self.token, &self.state, work) {
            Ok(token) => {
                self.token = token;
                Ok(())
            }
            Err(error) => {
                self.invalidate();
                Err(OperationError::Journal(error))
            }
        }
    }

    pub(crate) fn context(
        &self,
        generation: GenerationId,
    ) -> Result<OperationContext, OperationError> {
        self.ensure_usable()?;
        let target = self
            .state
            .current()
            .filter(|candidate| candidate.id() == generation)
            .or_else(|| {
                self.state
                    .staged()
                    .filter(|candidate| candidate.id() == generation)
            })
            .ok_or(OperationError::State(StateError::StaleGeneration))?;
        context(self.state.revision(), target)
    }
}

fn context(
    revision: Revision,
    generation: &KESGeneration,
) -> Result<OperationContext, OperationError> {
    let certificate = generation
        .certificate()
        .ok_or(OperationError::State(StateError::InvalidLifecycle))?;
    Ok(OperationContext {
        revision,
        generation: generation.id(),
        certificate_digest: *certificate.digest(),
        relative_period: generation.relative_period(),
        lifecycle: generation.lifecycle(),
    })
}
