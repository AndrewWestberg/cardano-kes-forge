//! Actors are authenticated caller scope metadata, not cryptographic proofs.
use super::object::{PublicObject, PublicObjectRef};
use super::{Actor, Lifecycle, StateError, require_management, require_pool};
use crate::certificate::{
    CertificateContext, CertificateError, LifetimeWindow, OperationalCertificate,
};
use crate::crypto::{CryptoError, KesKey, VerifiedPublicTree};
use crate::types::{
    AbsolutePeriod, CertificateCounter, CredentialEpoch, GenerationId, GenerationNumber,
    IncarnationId, KesLifetime, ManagementSequence, NetworkBinding, PoolId, RelativePeriod,
    RequestId, Revision,
};
use sha2::{Digest, Sha256};

mod codec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Enrollment {
    pub incarnation: IncarnationId,
    pub cold_verification_key: [u8; 32],
    pub network: NetworkBinding,
    pub machine_public_key: [u8; 32],
    pub recipient_public_key: [u8; 32],
    pub recipient_id: [u8; 32],
    pub management_sequence: ManagementSequence,
    pub management_request: RequestId,
    pub management_payload_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagementResult {
    Committed { revision: Revision },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificationOutcome {
    Applied { revision: Revision },
    AlreadyCertified { revision: Revision },
}

/// Durable replay identity and recorded public outcome; never a message body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagementReplay {
    pub sequence: ManagementSequence,
    pub request: RequestId,
    pub payload_digest: [u8; 32],
    pub result: ManagementResult,
}

/// Captures authorization/recipient policy, deliberately not active revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenerationPolicy {
    pool: PoolId,
    incarnation: IncarnationId,
    recipient_id: [u8; 32],
    recipient_policy_epoch: u64,
    credential_epoch: CredentialEpoch,
}
impl GenerationPolicy {
    pub const fn pool_id(&self) -> PoolId {
        self.pool
    }
    pub const fn incarnation(&self) -> IncarnationId {
        self.incarnation
    }
    pub const fn recipient_id(&self) -> &[u8; 32] {
        &self.recipient_id
    }
    pub const fn recipient_policy_epoch(&self) -> u64 {
        self.recipient_policy_epoch
    }
    pub const fn credential_epoch(&self) -> CredentialEpoch {
        self.credential_epoch
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActivationIntent {
    target_generation: GenerationId,
    certificate_digest: [u8; 32],
    activation_absolute_period: AbsolutePeriod,
    creation_request: RequestId,
    expected_active_generation: GenerationId,
    committed_revision: Revision,
}
impl ActivationIntent {
    pub const fn target_generation(&self) -> GenerationId {
        self.target_generation
    }
    pub const fn certificate_digest(&self) -> &[u8; 32] {
        &self.certificate_digest
    }
    pub const fn activation_absolute_period(&self) -> AbsolutePeriod {
        self.activation_absolute_period
    }
    pub const fn creation_request(&self) -> RequestId {
        self.creation_request
    }
    pub const fn expected_active_generation(&self) -> GenerationId {
        self.expected_active_generation
    }
    pub const fn committed_revision(&self) -> Revision {
        self.committed_revision
    }
}

/// A complete cold registration/snapshot workspace. Firmware must schedule a
/// bounded active cache rather than permanently replicate this record 32 times.
pub struct PoolRegistration {
    pool_id: PoolId,
    incarnation: IncarnationId,
    cold_verification_key: [u8; 32],
    network: NetworkBinding,
    credential_public_key: [u8; 32],
    credential_epoch: CredentialEpoch,
    credential_revoked: bool,
    recipient_public_key: [u8; 32],
    recipient_id: [u8; 32],
    recipient_policy_epoch: u64,
    management_replay: ManagementReplay,
    revision: Revision,
    generation_high_water: GenerationNumber,
    certificate_high_water: Option<CertificateCounter>,
    current: Option<KESGeneration>,
    staged: Option<KESGeneration>,
    generation_checkpoint: Option<crate::generation::GenerationCheckpoint>,
}

pub(crate) struct FirstActivationTransition<'a> {
    pub actor: Actor,
    pub expected_revision: Revision,
    pub expected_active_generation: Option<GenerationId>,
    pub generation: GenerationId,
    pub certificate_digest: [u8; 32],
    pub current_absolute_period: AbsolutePeriod,
    pub tree: &'a VerifiedPublicTree<'a>,
}

pub(crate) struct ActiveEvolutionTransition<'a> {
    pub actor: Actor,
    pub expected_revision: Revision,
    pub generation: GenerationId,
    pub certificate_digest: [u8; 32],
    pub target_absolute_period: AbsolutePeriod,
    pub request_network: &'a NetworkBinding,
    pub tree: &'a VerifiedPublicTree<'a>,
}
pub(crate) struct ScheduleActivationTransition {
    pub actor: Actor,
    pub expected_revision: Revision,
    pub expected_active_generation: GenerationId,
    pub generation: GenerationId,
    pub certificate_digest: [u8; 32],
    pub activation_absolute_period: AbsolutePeriod,
    pub creation_request: RequestId,
}

pub(crate) struct ReplacementActivationTransition<'a> {
    pub actor: Actor,
    pub expected_revision: Revision,
    pub expected_active_generation: GenerationId,
    pub generation: GenerationId,
    pub certificate_digest: [u8; 32],
    pub current_absolute_period: AbsolutePeriod,
    pub tree: &'a VerifiedPublicTree<'a>,
}

impl PoolRegistration {
    /// Data-policy constructor; management signature validation is upstream.
    pub fn new(actor: Actor, enrollment: Enrollment) -> Result<Self, StateError> {
        require_management(actor)?;
        let recipient_id: [u8; 32] = Sha256::digest(enrollment.recipient_public_key).into();
        if recipient_id != enrollment.recipient_id {
            return Err(StateError::InvalidRecipient);
        }
        let revision = Revision::new(0);
        Ok(Self {
            pool_id: PoolId::from_cold_verification_key(&enrollment.cold_verification_key),
            incarnation: enrollment.incarnation,
            cold_verification_key: enrollment.cold_verification_key,
            network: enrollment.network,
            credential_public_key: enrollment.machine_public_key,
            credential_epoch: CredentialEpoch::new(0),
            credential_revoked: false,
            recipient_public_key: enrollment.recipient_public_key,
            recipient_id,
            recipient_policy_epoch: 0,
            management_replay: ManagementReplay {
                sequence: enrollment.management_sequence,
                request: enrollment.management_request,
                payload_digest: enrollment.management_payload_digest,
                result: ManagementResult::Committed { revision },
            },
            revision,
            generation_high_water: GenerationNumber::new(0),
            certificate_high_water: None,
            current: None,
            staged: None,
            generation_checkpoint: None,
        })
    }
    pub const fn pool_id(&self) -> PoolId {
        self.pool_id
    }
    pub const fn incarnation(&self) -> IncarnationId {
        self.incarnation
    }
    pub const fn cold_verification_key(&self) -> &[u8; 32] {
        &self.cold_verification_key
    }
    pub const fn network(&self) -> &NetworkBinding {
        &self.network
    }
    pub const fn credential_public_key(&self) -> &[u8; 32] {
        &self.credential_public_key
    }
    pub const fn credential_epoch(&self) -> CredentialEpoch {
        self.credential_epoch
    }
    pub const fn credential_revoked(&self) -> bool {
        self.credential_revoked
    }
    pub const fn recipient_public_key(&self) -> &[u8; 32] {
        &self.recipient_public_key
    }
    pub const fn recipient_id(&self) -> &[u8; 32] {
        &self.recipient_id
    }
    pub const fn recipient_policy_epoch(&self) -> u64 {
        self.recipient_policy_epoch
    }
    pub const fn management_replay(&self) -> &ManagementReplay {
        &self.management_replay
    }
    pub const fn management_sequence(&self) -> ManagementSequence {
        self.management_replay.sequence
    }
    pub const fn revision(&self) -> Revision {
        self.revision
    }
    pub const fn generation_high_water(&self) -> GenerationNumber {
        self.generation_high_water
    }
    pub const fn certificate_high_water(&self) -> Option<CertificateCounter> {
        self.certificate_high_water
    }
    pub const fn current(&self) -> Option<&KESGeneration> {
        self.current.as_ref()
    }
    pub const fn staged(&self) -> Option<&KESGeneration> {
        self.staged.as_ref()
    }
    pub const fn activation_intent(&self) -> Option<&ActivationIntent> {
        match self.staged.as_ref() {
            Some(staged) => staged.activation_intent(),
            None => None,
        }
    }
    pub const fn generation_policy(&self) -> GenerationPolicy {
        GenerationPolicy {
            pool: self.pool_id,
            incarnation: self.incarnation,
            recipient_id: self.recipient_id,
            recipient_policy_epoch: self.recipient_policy_epoch,
            credential_epoch: self.credential_epoch,
        }
    }

    pub const fn generation_checkpoint(&self) -> Option<crate::generation::GenerationCheckpoint> {
        self.generation_checkpoint
    }

    pub(crate) fn set_generation_checkpoint(
        &mut self,
        checkpoint: crate::generation::GenerationCheckpoint,
    ) -> Result<(), StateError> {
        let revision = self
            .revision
            .checked_increment()
            .map_err(|_| StateError::CounterOverflow)?;
        self.generation_checkpoint = Some(checkpoint);
        self.revision = revision;
        Ok(())
    }

    pub(crate) fn finish_generation_checkpoint(
        &mut self,
        checkpoint: crate::generation::GenerationCheckpoint,
    ) {
        self.generation_checkpoint = Some(checkpoint);
    }

    fn abort_generation_checkpoint(&mut self) {
        if let Some(checkpoint) = self.generation_checkpoint.as_mut()
            && checkpoint.outcome == crate::generation::CheckpointOutcome::InProgress
        {
            checkpoint.outcome = crate::generation::CheckpointOutcome::NotCommitted;
        }
    }

    pub(crate) fn commit_recipient_replacement(
        &mut self,
        public_key: [u8; 32],
        recipient_id: [u8; 32],
        policy_epoch: u64,
        replay: ManagementReplay,
        revision: Revision,
    ) {
        self.recipient_public_key = public_key;
        self.recipient_id = recipient_id;
        self.recipient_policy_epoch = policy_epoch;
        self.management_replay = replay;
        self.abort_generation_checkpoint();
        self.revision = revision;
    }

    pub(crate) fn commit_credential_change(
        &mut self,
        public_key: [u8; 32],
        epoch: CredentialEpoch,
        revoked: bool,
        replay: ManagementReplay,
        revision: Revision,
    ) {
        self.credential_public_key = public_key;
        self.credential_epoch = epoch;
        self.credential_revoked = revoked;
        self.management_replay = replay;
        self.abort_generation_checkpoint();
        self.revision = revision;
    }

    pub(crate) fn commit_staged_discard(
        &mut self,
        replay: ManagementReplay,
        revision: Revision,
    ) -> Option<GenerationId> {
        let mut staged = self.staged.take()?;
        let generation = staged.id;
        staged.secret.erase();
        self.management_replay = replay;
        self.revision = revision;
        Some(generation)
    }

    pub(crate) fn merge_retained_history(
        &mut self,
        generation_high_water: GenerationNumber,
        certificate_high_water: Option<CertificateCounter>,
    ) {
        self.generation_high_water = generation_high_water;
        self.certificate_high_water = certificate_high_water;
    }

    pub(crate) fn commit_deletion_cleanup(&mut self, replay: ManagementReplay, revision: Revision) {
        self.erase_all_secrets();
        self.current = None;
        self.staged = None;
        self.abort_generation_checkpoint();
        self.management_replay = replay;
        self.revision = revision;
    }

    pub(crate) fn deletion_cleanup_matches(&self, replay: &ManagementReplay) -> bool {
        self.current.is_none()
            && self.staged.is_none()
            && self.management_replay.sequence == replay.sequence
            && self.management_replay.request == replay.request
            && self.management_replay.payload_digest == replay.payload_digest
            && self.management_replay.result == replay.result
    }

    /// Merge completion into the latest RAM revision. This neither publishes a
    /// flash object nor acknowledges durable secret cleanup.
    pub fn stage(
        &mut self,
        actor: Actor,
        expected_revision: Revision,
        generation: KESGeneration,
        captured_policy: GenerationPolicy,
    ) -> Result<(), StateError> {
        require_pool(actor, self.pool_id, self.incarnation)?;
        // Generation captures policy, not the active-state revision: unrelated
        // committed work may advance the pool while generation is in progress.
        if expected_revision > self.revision {
            return Err(StateError::RevisionConflict);
        }
        if self.credential_revoked || captured_policy != self.generation_policy() {
            return Err(StateError::PolicyChanged);
        }
        if self.staged.is_some() {
            return Err(StateError::StagedConflict);
        }
        if generation.pool != self.pool_id {
            return Err(StateError::WrongPool);
        }
        if generation.incarnation != self.incarnation {
            return Err(StateError::WrongIncarnation);
        }
        if generation.recipient_id != self.recipient_id {
            return Err(StateError::InvalidRecipient);
        }
        if generation.lifetime.get() != self.network.max_kes_evolutions() {
            return Err(StateError::InvalidSecret);
        }
        if generation.lifecycle != Lifecycle::Staged || generation.certificate.is_some() {
            return Err(StateError::InvalidLifecycle);
        }
        if generation.relative_period.get() != 0 || generation.is_secret_erased() {
            return Err(StateError::InvalidSecret);
        }
        let next_generation = self
            .generation_high_water
            .checked_increment()
            .map_err(|_| StateError::CounterOverflow)?;
        if generation.number != next_generation {
            return Err(StateError::GenerationConflict);
        }
        if self.current.as_ref().is_some_and(|current| {
            current.id == generation.id || current.creation_request == generation.creation_request
        }) {
            return Err(StateError::GenerationConflict);
        }
        let next_revision = self
            .revision
            .checked_increment()
            .map_err(|_| StateError::CounterOverflow)?;
        // All fallible checks precede mutation. Rejected candidate secrets drop
        // through KesKey's zeroizing owner, never leaving a partial staged slot.
        self.staged = Some(generation);
        self.generation_high_water = next_generation;
        self.revision = next_revision;
        Ok(())
    }

    /// Certify a RAM candidate; only activation advances the certificate high-water.
    pub fn certify(
        &mut self,
        actor: Actor,
        expected_revision: Revision,
        generation: GenerationId,
        canonical_certificate: &[u8],
        request_network: &NetworkBinding,
    ) -> Result<CertificationOutcome, StateError> {
        require_pool(actor, self.pool_id, self.incarnation)?;
        if self.credential_revoked {
            return Err(StateError::PolicyChanged);
        }
        if request_network != &self.network {
            return Err(CertificateError::WrongNetwork.into());
        }
        let (target, is_staged) = match self.staged.as_ref() {
            Some(staged) if staged.id == generation => (staged, true),
            _ => match self.current.as_ref() {
                Some(current) if current.id == generation => (current, false),
                _ => return Err(StateError::StaleGeneration),
            },
        };
        if expected_revision > self.revision {
            return Err(StateError::RevisionConflict);
        }
        if let Some(certificate) = target.certificate.as_ref() {
            if certificate.canonical_bytes() != canonical_certificate {
                return Err(StateError::CertificateConflict);
            }
            return Ok(CertificationOutcome::AlreadyCertified {
                revision: self.revision,
            });
        }
        if expected_revision != self.revision {
            return Err(StateError::RevisionConflict);
        }
        if !is_staged || target.lifecycle != Lifecycle::Staged {
            return Err(StateError::InvalidLifecycle);
        }
        if target.relative_period.get() != 0 || target.is_secret_erased() {
            return Err(StateError::InvalidSecret);
        }
        let certificate = OperationalCertificate::decode_and_verify(canonical_certificate)?;
        certificate.validate_bound(CertificateContext {
            pool: self.pool_id,
            cold_verification_key: &self.cold_verification_key,
            kes_verification_key: &target.verification_key,
            enrolled_network: &self.network,
            request_network,
            lifetime: target.lifetime,
            last_activated_counter: self.certificate_high_water,
        })?;
        let revision = self
            .revision
            .checked_increment()
            .map_err(|_| StateError::CounterOverflow)?;
        // The selected staged slot cannot change while exclusively borrowed.
        let target = self.staged.as_mut().expect("validated staged generation");
        target.certificate = Some(certificate);
        target.lifecycle = Lifecycle::CertifiedStaged;
        self.revision = revision;
        Ok(CertificationOutcome::Applied { revision })
    }

    pub(crate) fn activate_first_state(
        &mut self,
        transition: FirstActivationTransition<'_>,
    ) -> Result<(), StateError> {
        let FirstActivationTransition {
            actor,
            expected_revision,
            expected_active_generation,
            generation,
            certificate_digest,
            current_absolute_period,
            tree,
        } = transition;
        require_pool(actor, self.pool_id, self.incarnation)?;
        if self.credential_revoked {
            return Err(StateError::PolicyChanged);
        }
        if expected_revision != self.revision {
            return Err(StateError::RevisionConflict);
        }
        if expected_active_generation.is_some() || self.current.is_some() {
            return Err(StateError::InvalidLifecycle);
        }
        let staged = self.staged.as_ref().ok_or(StateError::StaleGeneration)?;
        if staged.id != generation {
            return Err(StateError::StaleGeneration);
        }
        if staged.lifecycle != Lifecycle::CertifiedStaged || staged.is_secret_erased() {
            return Err(StateError::InvalidLifecycle);
        }
        let certificate = staged
            .certificate
            .as_ref()
            .ok_or(StateError::InvalidLifecycle)?;
        if certificate.digest() != &certificate_digest {
            return Err(StateError::CertificateConflict);
        }
        if tree.root() != &staged.verification_key {
            return Err(StateError::InvalidObject);
        }
        let relative = LifetimeWindow::new(certificate.start_period(), staged.lifetime)?
            .relative_period(current_absolute_period)?;
        let counter = certificate.counter();
        let next_revision = self
            .revision
            .checked_increment()
            .map_err(|_| StateError::CounterOverflow)?;
        let staged = self.staged.as_mut().expect("validated staged generation");
        staged
            .secret
            .key
            .evolve_to(relative, tree)
            .map_err(StateError::from)?;
        staged.relative_period = relative;
        staged.lifecycle = Lifecycle::Active;
        self.current = self.staged.take();
        self.certificate_high_water = Some(counter);
        self.revision = next_revision;
        Ok(())
    }

    pub(crate) fn schedule_activation_state(
        &mut self,
        transition: ScheduleActivationTransition,
    ) -> Result<bool, StateError> {
        let ScheduleActivationTransition {
            actor,
            expected_revision,
            expected_active_generation,
            generation,
            certificate_digest,
            activation_absolute_period,
            creation_request,
        } = transition;
        require_pool(actor, self.pool_id, self.incarnation)?;
        if self.credential_revoked {
            return Err(StateError::PolicyChanged);
        }
        let current = self.current.as_ref().ok_or(StateError::StaleGeneration)?;
        if current.id != expected_active_generation {
            return Err(StateError::StaleGeneration);
        }
        let staged = self.staged.as_ref().ok_or(StateError::StaleGeneration)?;
        if staged.id != generation {
            return Err(StateError::StaleGeneration);
        }
        if let Some(intent) = staged.activation_intent {
            if intent.target_generation == generation
                && intent.certificate_digest == certificate_digest
                && intent.activation_absolute_period == activation_absolute_period
                && intent.creation_request == creation_request
                && intent.expected_active_generation == expected_active_generation
            {
                return Ok(false);
            }
            return Err(StateError::StagedConflict);
        }
        if expected_revision != self.revision {
            return Err(StateError::RevisionConflict);
        }
        if staged.lifecycle != Lifecycle::CertifiedStaged || staged.is_secret_erased() {
            return Err(StateError::InvalidLifecycle);
        }
        let certificate = staged
            .certificate
            .as_ref()
            .ok_or(StateError::InvalidLifecycle)?;
        if certificate.digest() != &certificate_digest {
            return Err(StateError::CertificateConflict);
        }
        LifetimeWindow::new(certificate.start_period(), staged.lifetime)?
            .relative_period(activation_absolute_period)?;
        let revision = self
            .revision
            .checked_increment()
            .map_err(|_| StateError::CounterOverflow)?;
        self.staged
            .as_mut()
            .expect("validated staged generation")
            .activation_intent = Some(ActivationIntent {
            target_generation: generation,
            certificate_digest,
            activation_absolute_period,
            creation_request,
            expected_active_generation,
            committed_revision: revision,
        });
        self.revision = revision;
        Ok(true)
    }

    pub(crate) fn activate_replacement_state(
        &mut self,
        transition: ReplacementActivationTransition<'_>,
    ) -> Result<(), StateError> {
        let ReplacementActivationTransition {
            actor,
            expected_revision,
            expected_active_generation,
            generation,
            certificate_digest,
            current_absolute_period,
            tree,
        } = transition;
        require_pool(actor, self.pool_id, self.incarnation)?;
        if self.credential_revoked {
            return Err(StateError::PolicyChanged);
        }
        if expected_revision != self.revision {
            return Err(StateError::RevisionConflict);
        }
        let current = self.current.as_ref().ok_or(StateError::StaleGeneration)?;
        if current.id != expected_active_generation {
            return Err(StateError::StaleGeneration);
        }
        let staged = self.staged.as_ref().ok_or(StateError::StaleGeneration)?;
        if staged.id != generation {
            return Err(StateError::StaleGeneration);
        }
        if staged.lifecycle != Lifecycle::CertifiedStaged || staged.is_secret_erased() {
            return Err(StateError::InvalidLifecycle);
        }
        let certificate = staged
            .certificate
            .as_ref()
            .ok_or(StateError::InvalidLifecycle)?;
        if certificate.digest() != &certificate_digest {
            return Err(StateError::CertificateConflict);
        }
        if tree.root() != &staged.verification_key {
            return Err(StateError::InvalidObject);
        }
        if let Some(intent) = staged.activation_intent
            && (intent.target_generation != generation
                || intent.certificate_digest != certificate_digest
                || intent.expected_active_generation != expected_active_generation
                || current_absolute_period < intent.activation_absolute_period)
        {
            return Err(StateError::StagedConflict);
        }
        let relative = LifetimeWindow::new(certificate.start_period(), staged.lifetime)?
            .relative_period(current_absolute_period)?;
        let counter = certificate.counter();
        let revision = self
            .revision
            .checked_increment()
            .map_err(|_| StateError::CounterOverflow)?;
        let staged = self.staged.as_mut().expect("validated staged generation");
        staged
            .secret
            .key
            .evolve_to(relative, tree)
            .map_err(StateError::from)?;
        staged.relative_period = relative;
        staged.lifecycle = Lifecycle::Active;
        staged.activation_intent = None;
        let current = self.current.as_mut().expect("validated active generation");
        current.secret.erase();
        current.lifecycle = Lifecycle::Retired;
        self.current = self.staged.take();
        self.certificate_high_water = Some(counter);
        self.revision = revision;
        Ok(())
    }

    pub(crate) fn evolve_active_state(
        &mut self,
        transition: ActiveEvolutionTransition<'_>,
    ) -> Result<bool, StateError> {
        let ActiveEvolutionTransition {
            actor,
            expected_revision,
            generation,
            certificate_digest,
            target_absolute_period,
            request_network,
            tree,
        } = transition;
        require_pool(actor, self.pool_id, self.incarnation)?;
        if self.credential_revoked {
            return Err(StateError::PolicyChanged);
        }
        if expected_revision != self.revision {
            return Err(StateError::RevisionConflict);
        }
        if request_network != &self.network {
            return Err(CertificateError::WrongNetwork.into());
        }
        let current = self.current.as_ref().ok_or(StateError::StaleGeneration)?;
        if current.id != generation {
            return Err(StateError::StaleGeneration);
        }
        if current.lifecycle == Lifecycle::CurrentExpired {
            return Err(CertificateError::Expired.into());
        }
        if current.lifecycle != Lifecycle::Active || current.is_secret_erased() {
            return Err(StateError::InvalidLifecycle);
        }
        let certificate = current
            .certificate
            .as_ref()
            .ok_or(StateError::InvalidLifecycle)?;
        if certificate.digest() != &certificate_digest {
            return Err(StateError::CertificateConflict);
        }
        if tree.root() != &current.verification_key {
            return Err(StateError::InvalidObject);
        }
        let relative = match LifetimeWindow::new(certificate.start_period(), current.lifetime)?
            .relative_period(target_absolute_period)
        {
            Ok(relative) => relative,
            Err(CertificateError::Expired) => {
                let next_revision = self
                    .revision
                    .checked_increment()
                    .map_err(|_| StateError::CounterOverflow)?;
                let current = self.current.as_mut().expect("validated active generation");
                current.secret.erase();
                current.lifecycle = Lifecycle::CurrentExpired;
                self.revision = next_revision;
                return Ok(true);
            }
            Err(error) => return Err(error.into()),
        };
        if relative < current.relative_period {
            return Err(CryptoError::StalePeriod.into());
        }
        if relative == current.relative_period {
            return Ok(false);
        }
        let next_revision = self
            .revision
            .checked_increment()
            .map_err(|_| StateError::CounterOverflow)?;
        let current = self.current.as_mut().expect("validated active generation");
        current
            .secret
            .key
            .evolve_to(relative, tree)
            .map_err(StateError::from)?;
        current.relative_period = relative;
        self.revision = next_revision;
        Ok(true)
    }
    pub(crate) fn validate_period_observation(
        &self,
        actor: Actor,
        expected_revision: Revision,
        network: &NetworkBinding,
    ) -> Result<(), StateError> {
        require_pool(actor, self.pool_id, self.incarnation)?;
        if self.credential_revoked {
            return Err(StateError::PolicyChanged);
        }
        if expected_revision != self.revision {
            return Err(StateError::RevisionConflict);
        }
        if network != &self.network {
            return Err(CertificateError::WrongNetwork.into());
        }
        Ok(())
    }

    pub(crate) fn erase_all_secrets(&mut self) {
        if let Some(current) = self.current.as_mut() {
            current.secret.erase();
        }
        if let Some(staged) = self.staged.as_mut() {
            staged.secret.erase();
        }
    }
}

pub struct GenerationSpec<'a> {
    pub generation_id: GenerationId,
    pub generation_number: GenerationNumber,
    pub creation_request: RequestId,
    pub creation_payload_digest: [u8; 32],
    pub pool: PoolId,
    pub incarnation: IncarnationId,
    pub verification_key: [u8; 32],
    pub lifetime: KesLifetime,
    pub recipient_id: [u8; 32],
    pub public_object: PublicObject<'a>,
}

/// Explicit erasure metadata cannot be confused with an all-zero live key.
/// No Clone/Debug/private serialization is implemented.
pub struct GenerationSecret {
    key: KesKey,
}
impl GenerationSecret {
    pub fn erased(lifetime: KesLifetime) -> Self {
        Self {
            key: KesKey::erased(lifetime),
        }
    }
    pub fn is_erased(&self) -> bool {
        !self.key.is_live()
    }
    pub fn key(&self) -> Option<&KesKey> {
        if self.key.is_live() {
            Some(&self.key)
        } else {
            None
        }
    }
    pub fn erase(&mut self) {
        self.key.erase();
    }
}

/// The public object is output from the trusted encrypted-backup producer.
/// That producer must bind its artifact to these pool/incarnation/generation,
/// period-zero VK and recipient fields. This data layer validates the immutable
/// object/tree/key bindings, not the artifact's future T030 cryptographic proof.
pub struct KESGeneration {
    id: GenerationId,
    number: GenerationNumber,
    creation_request: RequestId,
    creation_payload_digest: [u8; 32],
    pool: PoolId,
    incarnation: IncarnationId,
    verification_key: [u8; 32],
    lifetime: KesLifetime,
    relative_period: RelativePeriod,
    secret: GenerationSecret,
    lifecycle: Lifecycle,
    public_object: PublicObjectRef,
    backup_digest: [u8; 32],
    recipient_id: [u8; 32],
    certificate: Option<OperationalCertificate>,
    activation_intent: Option<ActivationIntent>,
}
impl KESGeneration {
    pub fn new_staged(spec: GenerationSpec<'_>, key: KesKey) -> Result<Self, StateError> {
        if !key.is_live()
            || key.period()?.get() != 0
            || key.lifetime() != spec.lifetime
            || key.verification_key()? != spec.verification_key
        {
            return Err(StateError::InvalidSecret);
        }
        if spec.generation_number.get() == 0 {
            return Err(StateError::GenerationConflict);
        }
        if spec.public_object.reference().generation != spec.generation_id
            || spec.public_object.verification_key() != spec.verification_key.as_slice()
        {
            return Err(StateError::InvalidObject);
        }
        let relative_period = key.period()?;
        let backup_digest = spec.public_object.backup_digest();
        Ok(Self {
            id: spec.generation_id,
            number: spec.generation_number,
            creation_request: spec.creation_request,
            creation_payload_digest: spec.creation_payload_digest,
            pool: spec.pool,
            incarnation: spec.incarnation,
            verification_key: spec.verification_key,
            lifetime: spec.lifetime,
            relative_period,
            secret: GenerationSecret { key },
            lifecycle: Lifecycle::Staged,
            public_object: *spec.public_object.reference(),
            backup_digest,
            recipient_id: spec.recipient_id,
            certificate: None,
            activation_intent: None,
        })
    }
    pub const fn id(&self) -> GenerationId {
        self.id
    }
    pub const fn number(&self) -> GenerationNumber {
        self.number
    }
    pub const fn creation_request(&self) -> RequestId {
        self.creation_request
    }
    pub const fn creation_payload_digest(&self) -> &[u8; 32] {
        &self.creation_payload_digest
    }
    pub const fn pool_id(&self) -> PoolId {
        self.pool
    }
    pub const fn incarnation(&self) -> IncarnationId {
        self.incarnation
    }
    pub const fn verification_key(&self) -> &[u8; 32] {
        &self.verification_key
    }
    pub const fn lifetime(&self) -> KesLifetime {
        self.lifetime
    }
    pub const fn relative_period(&self) -> RelativePeriod {
        self.relative_period
    }
    pub const fn lifecycle(&self) -> Lifecycle {
        self.lifecycle
    }
    pub fn is_secret_erased(&self) -> bool {
        self.secret.is_erased()
    }
    pub const fn secret(&self) -> &GenerationSecret {
        &self.secret
    }
    pub const fn public_object_ref(&self) -> &PublicObjectRef {
        &self.public_object
    }
    pub const fn backup_digest(&self) -> &[u8; 32] {
        &self.backup_digest
    }
    pub const fn recipient_id(&self) -> &[u8; 32] {
        &self.recipient_id
    }
    pub const fn certificate(&self) -> Option<&OperationalCertificate> {
        self.certificate.as_ref()
    }
    pub const fn activation_intent(&self) -> Option<&ActivationIntent> {
        self.activation_intent.as_ref()
    }
}

#[cfg(all(test, feature = "protected-runtime"))]
mod tests {
    extern crate std;
    use super::*;
    use crate::crypto::{Generation, verify};
    use crate::types::AbsolutePeriod;
    use ed25519_dalek::{Signer, SigningKey};
    use std::io::Read;
    use zeroize::Zeroizing;

    // Independent conventional CBOR and 48-byte message construction. All fields
    // used here fit the one-byte canonical unsigned representation.
    fn signed_certificate(cold: &SigningKey, hot: &[u8; 32], counter: u8) -> [u8; 138] {
        assert!(counter < 24);
        let mut message = [0; 48];
        message[..32].copy_from_slice(hot);
        message[32..40].copy_from_slice(&u64::from(counter).to_be_bytes());
        message[40..].copy_from_slice(&0u64.to_be_bytes());
        let signature = cold.sign(&message).to_bytes();
        let mut bytes = [0; 138];
        bytes[..4].copy_from_slice(&[0x82, 0x84, 0x58, 0x20]);
        bytes[4..36].copy_from_slice(hot);
        bytes[36] = counter;
        bytes[37] = 0;
        bytes[38..40].copy_from_slice(&[0x58, 0x40]);
        bytes[40..104].copy_from_slice(&signature);
        bytes[104..106].copy_from_slice(&[0x58, 0x20]);
        bytes[106..].copy_from_slice(&cold.verifying_key().to_bytes());
        bytes
    }

    #[test]
    fn conflicting_recertification_preserves_real_current_signing_key() {
        xtask::oracles::protect_memory().expect("protected no-swap disposable runtime required");
        let mut source = std::fs::File::open("/dev/urandom").expect("OS entropy unavailable");
        let mut cold_seed = Zeroizing::new([0; 32]);
        source
            .read_exact(&mut *cold_seed)
            .expect("OS entropy unavailable");
        let cold = SigningKey::from_bytes(&cold_seed);
        let mut seed = Zeroizing::new([0; 32]);
        source
            .read_exact(&mut *seed)
            .expect("OS entropy unavailable");
        let lifetime = KesLifetime::new(64).unwrap();
        let mut job = Generation::begin(&mut seed, lifetime).unwrap();
        for _ in 0..64 {
            job.step().unwrap();
        }
        let (key, tree) = job.finish().unwrap();
        let cache = tree.verify(&key.verification_key().unwrap()).unwrap();
        let hot = key.verification_key().unwrap();
        let recipient = [0x73; 32];
        let network =
            NetworkBinding::from_genesis_bytes(42, b"public current-state regression", 64, 64)
                .unwrap();
        let mut pool = PoolRegistration::new(
            Actor::Management,
            Enrollment {
                incarnation: IncarnationId::from_bytes([1; 16]),
                cold_verification_key: cold.verifying_key().to_bytes(),
                network,
                machine_public_key: [0x61; 32],
                recipient_public_key: recipient,
                recipient_id: Sha256::digest(recipient).into(),
                management_sequence: ManagementSequence::new(1),
                management_request: RequestId::from_bytes([2; 16]),
                management_payload_digest: [3; 32],
            },
        )
        .unwrap();
        let id = GenerationId::from_bytes([4; 16]);
        // The backup bytes are public syntax only, not a claim of encrypted-backup validation.
        let object = PublicObject::from_parts(id, cache.as_bytes(), b"KESBKP01\xa0", &hot).unwrap();
        let generation = KESGeneration::new_staged(
            GenerationSpec {
                generation_id: id,
                generation_number: GenerationNumber::new(1),
                creation_request: RequestId::from_bytes([5; 16]),
                creation_payload_digest: [6; 32],
                pool: pool.pool_id(),
                incarnation: pool.incarnation(),
                verification_key: hot,
                lifetime,
                recipient_id: *pool.recipient_id(),
                public_object: object,
            },
            key,
        )
        .unwrap();
        let actor = Actor::Pool {
            pool: pool.pool_id(),
            incarnation: pool.incarnation(),
        };
        pool.stage(actor, pool.revision(), generation, pool.generation_policy())
            .unwrap();
        let certificate = signed_certificate(&cold, &hot, 0);
        let original_revision = pool.revision();
        assert_eq!(
            pool.certify(actor, original_revision, id, &certificate, &network),
            Ok(CertificationOutcome::Applied {
                revision: Revision::new(2)
            })
        );
        assert_eq!(pool.certificate_high_water(), None);
        // Arrange a valid owned active snapshot directly in this private unit
        // fixture. This is not an activation implementation or durability proof.
        let mut current = pool.staged.take().unwrap();
        current.lifecycle = Lifecycle::Active;
        pool.current = Some(current);
        pool.certificate_high_water = Some(CertificateCounter::new(0));
        pool.revision = Revision::new(3);
        let window = pool
            .current()
            .unwrap()
            .certificate()
            .unwrap()
            .validate_bound(CertificateContext {
                pool: pool.pool_id(),
                cold_verification_key: pool.cold_verification_key(),
                kes_verification_key: &hot,
                enrolled_network: &network,
                request_network: &network,
                lifetime,
                last_activated_counter: None,
            })
            .unwrap();
        let period = window.relative_period(AbsolutePeriod::new(0)).unwrap();
        let message = b"public current-key preservation challenge";
        let mut signature_before = [0; crate::SIGNATURE_BYTES];
        pool.current()
            .unwrap()
            .secret()
            .key()
            .unwrap()
            .sign_into(period, message, &mut signature_before)
            .unwrap();
        verify(&hot, period, lifetime, message, &signature_before).unwrap();
        let reference = *pool.current().unwrap().public_object_ref();
        let backup_digest = *pool.current().unwrap().backup_digest();
        let different = signed_certificate(&cold, &hot, 1);
        assert_eq!(
            pool.certify(actor, pool.revision(), id, &different, &network),
            Err(StateError::CertificateConflict)
        );
        assert_eq!(
            pool.certify(actor, original_revision, id, &certificate, &network),
            Ok(CertificationOutcome::AlreadyCertified {
                revision: Revision::new(3)
            })
        );
        let current = pool.current().unwrap();
        assert_eq!(pool.revision(), Revision::new(3));
        assert_eq!(
            pool.certificate_high_water(),
            Some(CertificateCounter::new(0))
        );
        assert!(pool.staged().is_none());
        assert_eq!(current.lifecycle(), Lifecycle::Active);
        assert_eq!(current.public_object_ref(), &reference);
        assert_eq!(current.backup_digest(), &backup_digest);
        assert_eq!(
            current.certificate().unwrap().canonical_bytes(),
            certificate
        );
        let mut signature_after = [0; crate::SIGNATURE_BYTES];
        current
            .secret()
            .key()
            .unwrap()
            .sign_into(period, message, &mut signature_after)
            .unwrap();
        verify(&hot, period, lifetime, message, &signature_after).unwrap();
        assert_eq!(signature_before, signature_after);
    }
}
