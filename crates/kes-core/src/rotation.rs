//! Replacement activation and operational-period reconciliation.
//! Scheduled intent is durable state; telemetry reads never invoke these transitions.

use crate::{
    activation::{
        DurablePool, EvolutionOutcome, EvolutionRequest, OperationContext, OperationError,
    },
    crypto::VerifiedPublicTree,
    journal::{Flash, Journal, PoolCodec, Workspaces},
    state::{Actor, ReplacementActivationTransition, StateError},
    types::{AbsolutePeriod, GenerationId, NetworkBinding, Revision},
};
use rand_chacha::rand_core::TryCryptoRng;

#[derive(Clone, Copy)]
pub struct ReplacementActivationRequest {
    pub actor: Actor,
    pub expected_revision: Revision,
    pub expected_active_generation: GenerationId,
    pub generation: GenerationId,
    pub certificate_digest: [u8; 32],
    pub current_absolute_period: AbsolutePeriod,
}

pub struct PeriodObservationRequest<'a> {
    pub actor: Actor,
    pub expected_revision: Revision,
    pub absolute_period: AbsolutePeriod,
    pub network: &'a NetworkBinding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeriodObservationOutcome {
    Pending(OperationContext),
    Activated(OperationContext),
    Evolved(EvolutionOutcome),
}

impl DurablePool {
    pub fn activate_replacement<F: Flash, R: TryCryptoRng>(
        &mut self,
        journal: &Journal<PoolCodec>,
        flash: &mut F,
        rng: &mut R,
        work: &mut Workspaces<'_>,
        request: ReplacementActivationRequest,
        tree: &VerifiedPublicTree<'_>,
    ) -> Result<OperationContext, OperationError> {
        self.ensure_usable()?;
        let result = self
            .state
            .activate_replacement_state(ReplacementActivationTransition {
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

    pub fn observe_period<F: Flash, R: TryCryptoRng>(
        &mut self,
        journal: &Journal<PoolCodec>,
        flash: &mut F,
        rng: &mut R,
        work: &mut Workspaces<'_>,
        request: PeriodObservationRequest<'_>,
        tree: &VerifiedPublicTree<'_>,
    ) -> Result<PeriodObservationOutcome, OperationError> {
        self.ensure_usable()?;
        self.state.validate_period_observation(
            request.actor,
            request.expected_revision,
            request.network,
        )?;
        if let Some(intent) = self.state.activation_intent().copied() {
            if request.absolute_period < intent.activation_absolute_period() {
                let active = self
                    .state
                    .current()
                    .ok_or(OperationError::State(StateError::StaleGeneration))?;
                return Ok(PeriodObservationOutcome::Pending(
                    self.context(active.id())?,
                ));
            }
            let context = self.activate_replacement(
                journal,
                flash,
                rng,
                work,
                ReplacementActivationRequest {
                    actor: request.actor,
                    expected_revision: request.expected_revision,
                    expected_active_generation: intent.expected_active_generation(),
                    generation: intent.target_generation(),
                    certificate_digest: *intent.certificate_digest(),
                    current_absolute_period: request.absolute_period,
                },
                tree,
            )?;
            return Ok(PeriodObservationOutcome::Activated(context));
        }
        let active = self
            .state
            .current()
            .ok_or(OperationError::State(StateError::StaleGeneration))?;
        let generation = active.id();
        let certificate_digest = *active
            .certificate()
            .ok_or(OperationError::State(StateError::InvalidLifecycle))?
            .digest();
        let outcome = self.evolve(
            journal,
            flash,
            rng,
            work,
            EvolutionRequest {
                actor: request.actor,
                expected_revision: request.expected_revision,
                generation,
                certificate_digest,
                target_absolute_period: request.absolute_period,
                network: request.network,
            },
            tree,
        )?;
        Ok(PeriodObservationOutcome::Evolved(outcome))
    }
}
