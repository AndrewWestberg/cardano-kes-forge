//! Generation admission, immutable public-object publication and backup retrieval.
//! The caller owns the cooperative crypto scheduler and durable object backend.
use crate::backup::{self, Metadata};
use crate::crypto::{CryptoError, Generation, KesKey, VerifiedPublicTree};
use crate::session::DeviceIdentityKey;
use crate::state::{
    Actor, GenerationPolicy, GenerationSpec, KESGeneration, Lifecycle, MAX_PUBLIC_OBJECT_BYTES,
    PoolRegistration, PublicObject, PublicObjectRef, StateError,
};
use crate::types::{
    DeviceId, GenerationId, GenerationNumber, KesLifetime, RequestId, Revision, TypeError,
};
use rand_chacha::rand_core::TryCryptoRng;
use zeroize::Zeroizing;

/// Durable storage for immutable public generation objects. `write` must return
/// only after the exact bytes are durable; callers always read and validate them
/// before publishing the generation descriptor in pool state.
pub trait PublicObjectStore {
    type Error;

    fn write(&mut self, reference: &PublicObjectRef, bytes: &[u8]) -> Result<(), Self::Error>;
    fn read(
        &mut self,
        reference: &PublicObjectRef,
        output: &mut [u8],
    ) -> Result<usize, Self::Error>;
    fn discard(&mut self, reference: &PublicObjectRef) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenerationDescriptor {
    pub generation: GenerationId,
    pub generation_number: GenerationNumber,
    pub creation_request: RequestId,
    pub creation_payload_digest: [u8; 32],
    pub verification_key: [u8; 32],
    pub artifact_digest: [u8; 32],
    pub public_object: PublicObjectRef,
    pub lifecycle: Lifecycle,
}

impl GenerationDescriptor {
    fn from_generation(generation: &KESGeneration) -> Self {
        Self {
            generation: generation.id(),
            generation_number: generation.number(),
            creation_request: generation.creation_request(),
            creation_payload_digest: *generation.creation_payload_digest(),
            verification_key: *generation.verification_key(),
            artifact_digest: *generation.backup_digest(),
            public_object: *generation.public_object_ref(),
            lifecycle: generation.lifecycle(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationStatus {
    InProgress {
        request: RequestId,
        generation_number: GenerationNumber,
    },
    Committed(GenerationDescriptor),
    NotCommitted {
        request: RequestId,
        generation_number: GenerationNumber,
    },
    ResultReclaimed {
        request: RequestId,
        generation_number: GenerationNumber,
    },
    Unknown {
        request: RequestId,
        generation_number: Option<GenerationNumber>,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointOutcome {
    InProgress,
    Committed,
    NotCommitted,
}

/// Public replay checkpoint authenticated by the enclosing pool snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenerationCheckpoint {
    pub request: RequestId,
    pub payload_digest: [u8; 32],
    pub generation: GenerationId,
    pub generation_number: GenerationNumber,
    pub outcome: CheckpointOutcome,
    pub expected_revision: Revision,
    pub policy: GenerationPolicy,
    /// Distinguishes an explicit fresh attempt from stale pre-abort RAM handles.
    pub attempt: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecordState {
    InProgress,
    Committed,
    NotCommitted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GenerationRecord {
    request: RequestId,
    payload_digest: [u8; 32],
    generation: GenerationId,
    generation_number: GenerationNumber,
    state: RecordState,
    expected_revision: Revision,
    policy: GenerationPolicy,
    attempt: u64,
}

/// Per-pool public operation memory. Persist this record with the pool snapshot;
/// it contains no key material and prevents retries from becoming regeneration.
pub struct GenerationCoordinator {
    record: Option<GenerationRecord>,
}

impl GenerationCoordinator {
    pub const fn new() -> Self {
        Self { record: None }
    }
    /// Restore public replay memory without claiming that interrupted work has
    /// been cleaned. Durable recovery must journal the explicit abort before
    /// reporting `NOT_COMMITTED`; this does not reconstruct a crypto job.
    pub const fn from_checkpoint(checkpoint: GenerationCheckpoint) -> Self {
        let state = match checkpoint.outcome {
            CheckpointOutcome::InProgress => RecordState::InProgress,
            CheckpointOutcome::NotCommitted => RecordState::NotCommitted,
            CheckpointOutcome::Committed => RecordState::Committed,
        };
        Self {
            record: Some(GenerationRecord {
                request: checkpoint.request,
                payload_digest: checkpoint.payload_digest,
                generation: checkpoint.generation,
                generation_number: checkpoint.generation_number,
                state,
                expected_revision: checkpoint.expected_revision,
                policy: checkpoint.policy,
                attempt: checkpoint.attempt,
            }),
        }
    }

    pub const fn checkpoint(&self) -> Option<GenerationCheckpoint> {
        match self.record {
            Some(record) => Some(GenerationCheckpoint {
                request: record.request,
                payload_digest: record.payload_digest,
                generation: record.generation,
                generation_number: record.generation_number,
                expected_revision: record.expected_revision,
                policy: record.policy,
                attempt: record.attempt,
                outcome: match record.state {
                    RecordState::InProgress => CheckpointOutcome::InProgress,
                    RecordState::Committed => CheckpointOutcome::Committed,
                    RecordState::NotCommitted => CheckpointOutcome::NotCommitted,
                },
            }),
            None => None,
        }
    }

    pub fn admit(
        &mut self,
        pool: &PoolRegistration,
        request: GenerationRequest,
        entropy: &mut impl TryCryptoRng,
    ) -> Result<Admission, Error<core::convert::Infallible>> {
        authorize(request.actor, pool)?;
        if pool.credential_revoked() {
            return Err(Error::State(StateError::PolicyChanged));
        }
        if let Some(generation) = retained_by_request(pool, request.request, None) {
            if generation.number() != request.next_generation_number
                || generation.creation_payload_digest() != &request.payload_digest
            {
                return Err(Error::State(StateError::GenerationConflict));
            }
            return Ok(Admission::Existing(OperationStatus::Committed(
                GenerationDescriptor::from_generation(generation),
            )));
        }
        if let Some(record) = self.record {
            if record.request == request.request {
                if record.payload_digest != request.payload_digest
                    || record.generation_number != request.next_generation_number
                {
                    return Err(Error::State(StateError::GenerationConflict));
                }
                return Ok(Admission::Existing(self.status(
                    pool,
                    request.request,
                    Some(request.next_generation_number),
                )));
            }
            if record.state == RecordState::InProgress {
                return Err(Error::Busy);
            }
        }
        if request.expected_revision != pool.revision() {
            return Err(Error::State(StateError::RevisionConflict));
        }
        if pool.staged().is_some() {
            return Err(Error::State(StateError::StagedConflict));
        }
        let expected_number = pool
            .generation_high_water()
            .checked_increment()
            .map_err(|_| Error::State(StateError::CounterOverflow))?;
        if request.next_generation_number != expected_number {
            return Err(Error::State(StateError::StaleGeneration));
        }
        let generation = GenerationId::random(entropy).map_err(Error::Identity)?;
        let record = GenerationRecord {
            request: request.request,
            payload_digest: request.payload_digest,
            generation,
            generation_number: request.next_generation_number,
            expected_revision: request.expected_revision,
            policy: pool.generation_policy(),
            state: RecordState::InProgress,
            attempt: 0,
        };
        self.record = Some(record);
        Ok(Admission::Started(GenerationOperation {
            actor: request.actor,
            expected_revision: request.expected_revision,
            policy: pool.generation_policy(),
            record,
        }))
    }

    pub fn status(
        &self,
        pool: &PoolRegistration,
        request: RequestId,
        generation_number: Option<GenerationNumber>,
    ) -> OperationStatus {
        if let Some(generation) = retained_by_request(pool, request, generation_number) {
            return OperationStatus::Committed(GenerationDescriptor::from_generation(generation));
        }
        if let Some(record) = self.record.filter(|record| record.request == request) {
            if generation_number.is_some_and(|number| number != record.generation_number) {
                return OperationStatus::Unknown {
                    request,
                    generation_number,
                };
            }
            return match record.state {
                RecordState::InProgress => OperationStatus::InProgress {
                    request,
                    generation_number: record.generation_number,
                },
                RecordState::NotCommitted => OperationStatus::NotCommitted {
                    request,
                    generation_number: record.generation_number,
                },
                RecordState::Committed => OperationStatus::ResultReclaimed {
                    request,
                    generation_number: record.generation_number,
                },
            };
        }
        if generation_number.is_some_and(|number| retained_by_number(pool, number).is_some()) {
            return OperationStatus::Unknown {
                request,
                generation_number,
            };
        }
        if let Some(number) = generation_number
            && number.get() != 0
            && number <= pool.generation_high_water()
        {
            return OperationStatus::ResultReclaimed {
                request,
                generation_number: number,
            };
        }
        OperationStatus::Unknown {
            request,
            generation_number,
        }
    }

    pub const fn has_in_progress(&self) -> bool {
        matches!(
            self.record,
            Some(GenerationRecord {
                state: RecordState::InProgress,
                ..
            })
        )
    }

    pub(crate) fn cancel_for_policy_change(
        &mut self,
        workspace: Option<&mut KesKey>,
    ) -> Result<Option<GenerationId>, ()> {
        let Some(record) = self
            .record
            .filter(|record| record.state == RecordState::InProgress)
        else {
            return Ok(None);
        };
        let key = workspace.ok_or(())?;
        key.erase();
        self.mark_not_committed(record);
        Ok(Some(record.generation))
    }

    /// Mark a failed or cancelled cooperative job. The live workspace is erased
    /// explicitly; no partial public object or reusable initial plaintext remains.
    pub fn cancel(
        &mut self,
        operation: GenerationOperation,
        key: &mut KesKey,
    ) -> Result<(), Error<core::convert::Infallible>> {
        self.require_in_progress(&operation)?;
        key.erase();
        self.mark_not_committed(operation.record);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn complete<S: PublicObjectStore>(
        &mut self,
        pool: &mut PoolRegistration,
        operation: GenerationOperation,
        mut key: KesKey,
        tree: &VerifiedPublicTree<'_>,
        device: DeviceId,
        identity: &DeviceIdentityKey,
        entropy: &mut impl TryCryptoRng,
        store: &mut S,
        write_buffer: &mut [u8; MAX_PUBLIC_OBJECT_BYTES],
        read_buffer: &mut [u8; MAX_PUBLIC_OBJECT_BYTES],
    ) -> Result<GenerationDescriptor, Error<S::Error>> {
        self.require_in_progress(&operation).map_err(widen_error)?;
        if operation.policy != pool.generation_policy() {
            key.erase();
            self.mark_not_committed(operation.record);
            return Err(Error::State(StateError::PolicyChanged));
        }
        let verification_key = match key.verification_key() {
            Ok(value) => value,
            Err(error) => {
                key.erase();
                self.mark_not_committed(operation.record);
                return Err(Error::Crypto(error));
            }
        };
        let artifact = match identity.create_backup(
            &key,
            Metadata {
                device,
                pool: operation.policy.pool_id(),
                incarnation: operation.policy.incarnation(),
                generation: operation.record.generation,
                generation_number: operation.record.generation_number,
                recipient_public_key: *pool.recipient_public_key(),
                recipient_id: *operation.policy.recipient_id(),
            },
            entropy,
        ) {
            Ok(value) => value,
            Err(error) => {
                key.erase();
                self.mark_not_committed(operation.record);
                return Err(Error::Backup(error));
            }
        };
        let object = match PublicObject::from_parts(
            operation.record.generation,
            tree.as_bytes(),
            artifact.encoded(),
            &verification_key,
        ) {
            Ok(value) => value,
            Err(error) => {
                key.erase();
                self.mark_not_committed(operation.record);
                return Err(Error::State(error));
            }
        };
        let reference = *object.reference();
        let object_length = match object.encode_into(write_buffer) {
            Ok(value) => value,
            Err(error) => {
                key.erase();
                self.mark_not_committed(operation.record);
                return Err(Error::State(error));
            }
        };
        if let Err(error) = store.write(&reference, &write_buffer[..object_length]) {
            key.erase();
            self.mark_not_committed(operation.record);
            return Err(Error::Storage(error));
        }
        let read_length = match store.read(&reference, read_buffer) {
            Ok(value) => value,
            Err(error) => {
                let _ = store.discard(&reference);
                key.erase();
                self.mark_not_committed(operation.record);
                return Err(Error::Storage(error));
            }
        };
        let encoded = match read_buffer.get(..read_length) {
            Some(value) => value,
            None => {
                let _ = store.discard(&reference);
                key.erase();
                self.mark_not_committed(operation.record);
                return Err(Error::Readback(StateError::InvalidObject));
            }
        };
        let verified = match PublicObject::parse(encoded, &reference, &verification_key) {
            Ok(value) => value,
            Err(error) => {
                let _ = store.discard(&reference);
                key.erase();
                self.mark_not_committed(operation.record);
                return Err(Error::Readback(error));
            }
        };
        let generation = match KESGeneration::new_staged(
            GenerationSpec {
                generation_id: operation.record.generation,
                generation_number: operation.record.generation_number,
                creation_request: operation.record.request,
                creation_payload_digest: operation.record.payload_digest,
                pool: operation.policy.pool_id(),
                incarnation: operation.policy.incarnation(),
                verification_key,
                lifetime: key.lifetime(),
                recipient_id: *operation.policy.recipient_id(),
                public_object: verified,
            },
            key,
        ) {
            Ok(value) => value,
            Err(error) => {
                let _ = store.discard(&reference);
                self.mark_not_committed(operation.record);
                return Err(Error::State(error));
            }
        };
        if let Err(error) = pool.stage(
            operation.actor,
            operation.expected_revision,
            generation,
            operation.policy,
        ) {
            let _ = store.discard(&reference);
            self.mark_not_committed(operation.record);
            return Err(Error::State(error));
        }
        let descriptor = GenerationDescriptor::from_generation(
            pool.staged()
                .expect("successful stage publishes a generation"),
        );
        if let Some(record) = self.record.as_mut() {
            record.state = RecordState::Committed;
        }
        Ok(descriptor)
    }

    fn require_in_progress<E>(&self, operation: &GenerationOperation) -> Result<(), Error<E>> {
        if self.record == Some(operation.record)
            && operation.record.state == RecordState::InProgress
        {
            Ok(())
        } else {
            Err(Error::State(StateError::GenerationConflict))
        }
    }

    fn mark_not_committed(&mut self, expected: GenerationRecord) {
        if let Some(record) = self.record.as_mut().filter(|record| **record == expected) {
            record.state = RecordState::NotCommitted;
        }
    }
}

impl Default for GenerationCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy)]
pub struct GenerationRequest {
    pub actor: Actor,
    pub request: RequestId,
    pub payload_digest: [u8; 32],
    pub next_generation_number: GenerationNumber,
    pub expected_revision: Revision,
}

pub enum Admission {
    Started(GenerationOperation),
    Existing(OperationStatus),
}

/// Non-cloneable handle for one admitted generation. It captures policy epochs,
/// not an active-state snapshot, so completion can merge into a newer revision.
pub struct GenerationOperation {
    actor: Actor,
    expected_revision: Revision,
    policy: GenerationPolicy,
    record: GenerationRecord,
}

impl GenerationOperation {
    pub const fn generation(&self) -> GenerationId {
        self.record.generation
    }

    pub const fn generation_number(&self) -> GenerationNumber {
        self.record.generation_number
    }

    pub const fn request(&self) -> RequestId {
        self.record.request
    }
}

/// Seed an owned cooperative generation. The returned job performs one leaf per
/// `step`; the firmware scheduler retains the original request deadline.
pub fn begin_key_generation(
    entropy: &mut impl TryCryptoRng,
    lifetime: KesLifetime,
) -> Result<Generation, BeginError> {
    let mut seed = Zeroizing::new([0; 32]);
    entropy
        .try_fill_bytes(&mut seed[..])
        .map_err(|_| BeginError::Entropy)?;
    Generation::begin(&mut seed, lifetime).map_err(BeginError::Crypto)
}

pub struct BackupResult<'a> {
    pub generation: GenerationId,
    pub bytes: &'a [u8],
    pub digest: [u8; 32],
}

pub fn get_backup<'a, S: PublicObjectStore>(
    pool: &PoolRegistration,
    generation_id: GenerationId,
    store: &mut S,
    read_buffer: &'a mut [u8; MAX_PUBLIC_OBJECT_BYTES],
) -> Result<BackupResult<'a>, Error<S::Error>> {
    let generation = retained_by_id(pool, generation_id).ok_or(Error::ResultReclaimed)?;
    if !matches!(
        generation.lifecycle(),
        Lifecycle::Staged
            | Lifecycle::CertifiedStaged
            | Lifecycle::Active
            | Lifecycle::CurrentExpired
    ) {
        return Err(Error::ResultReclaimed);
    }
    let reference = *generation.public_object_ref();
    let verification_key = *generation.verification_key();
    let expected_digest = *generation.backup_digest();
    let length = store
        .read(&reference, read_buffer)
        .map_err(Error::Storage)?;
    let encoded = read_buffer
        .get(..length)
        .ok_or(Error::Readback(StateError::InvalidObject))?;
    let object =
        PublicObject::parse(encoded, &reference, &verification_key).map_err(Error::Readback)?;
    if object.backup_digest() != expected_digest {
        return Err(Error::Readback(StateError::InvalidObject));
    }
    Ok(BackupResult {
        generation: generation_id,
        bytes: object.encrypted_backup(),
        digest: expected_digest,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BeginError {
    Entropy,
    Crypto(CryptoError),
}

#[derive(Debug, Eq, PartialEq)]
pub enum Error<E> {
    Busy,
    Identity(TypeError),
    Crypto(CryptoError),
    Backup(backup::Error),
    State(StateError),
    Storage(E),
    Readback(StateError),
    ResultReclaimed,
}

fn widen_error<E>(error: Error<core::convert::Infallible>) -> Error<E> {
    match error {
        Error::Busy => Error::Busy,
        Error::Identity(error) => Error::Identity(error),
        Error::Crypto(error) => Error::Crypto(error),
        Error::Backup(error) => Error::Backup(error),
        Error::State(error) => Error::State(error),
        Error::Storage(never) => match never {},
        Error::Readback(error) => Error::Readback(error),
        Error::ResultReclaimed => Error::ResultReclaimed,
    }
}

fn authorize<E>(actor: Actor, pool: &PoolRegistration) -> Result<(), Error<E>> {
    match actor {
        Actor::Management => Err(Error::State(StateError::Unauthorized)),
        Actor::Pool {
            pool: actor_pool,
            incarnation: _,
        } if actor_pool != pool.pool_id() => Err(Error::State(StateError::WrongPool)),
        Actor::Pool {
            pool: _,
            incarnation,
        } if incarnation != pool.incarnation() => Err(Error::State(StateError::WrongIncarnation)),
        Actor::Pool { .. } => Ok(()),
    }
}

fn retained_by_request(
    pool: &PoolRegistration,
    request: RequestId,
    number: Option<GenerationNumber>,
) -> Option<&KESGeneration> {
    [pool.current(), pool.staged()]
        .into_iter()
        .flatten()
        .find(|generation| {
            generation.creation_request() == request
                && number.is_none_or(|number| number == generation.number())
        })
}

fn retained_by_number(
    pool: &PoolRegistration,
    generation_number: GenerationNumber,
) -> Option<&KESGeneration> {
    [pool.current(), pool.staged()]
        .into_iter()
        .flatten()
        .find(|generation| generation.number() == generation_number)
}

fn retained_by_id(pool: &PoolRegistration, generation_id: GenerationId) -> Option<&KESGeneration> {
    [pool.current(), pool.staged()]
        .into_iter()
        .flatten()
        .find(|generation| generation.id() == generation_id)
}

/// A durable operation failure. Journal failures invalidate the sole live owner;
/// callers must recover, never retry against its mutated RAM.
#[derive(Debug, Eq, PartialEq)]
pub enum DurableGenerationError<E> {
    Operation(crate::activation::OperationError),
    Generation(Error<E>),
}

/// A signed pool policy transaction, including its replay-only result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoolManagementOutcome {
    pub revision: Revision,
    pub committed_write: bool,
    pub cancelled_generation: Option<GenerationId>,
    pub archive: Option<crate::recipient::ArchiveRequirement>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PoolManagementError {
    Operation(crate::activation::OperationError),
    Credential(crate::credentials::Error),
    Recipient(crate::recipient::Error),
}

impl crate::activation::DurablePool {
    /// Apply an already offline-verified pool policy change or staged discard.
    ///
    /// `cancel` must synchronously drop/wipe the actual owned crypto job and
    /// retire its scheduler lease. The caller must first ensure that any live
    /// job belongs to this pool and its authenticated IN_PROGRESS checkpoint.
    /// The callback is infallible and runs only after every signed transition
    /// precondition succeeds, never on rejected requests or exact retries.
    /// Credential/recipient commits abort the checkpoint in the SAME snapshot,
    /// so an old operation cannot publish or restart under the new policy.
    /// Persistence failure invalidates this owner and must never be ACKed.
    #[allow(clippy::too_many_arguments)]
    pub fn manage_pool_policy<F: crate::journal::Flash, R: TryCryptoRng>(
        &mut self,
        envelope: &crate::management::VerifiedEnvelope<'_>,
        journal: &crate::journal::Journal<crate::journal::PoolCodec>,
        flash: &mut F,
        rng: &mut R,
        work: &mut crate::journal::Workspaces<'_>,
        cancel: impl FnOnce(GenerationId),
    ) -> Result<PoolManagementOutcome, PoolManagementError> {
        use crate::{
            credentials::CredentialOutcome, management::Action, recipient::ReplacementOutcome,
        };
        self.ensure_usable()
            .map_err(PoolManagementError::Operation)?;
        let checkpoint = self
            .state
            .generation_checkpoint()
            .filter(|checkpoint| checkpoint.outcome == CheckpointOutcome::InProgress);
        // This coordinator is only a public transition validator, not the
        // owner of the running secret job. The real job is erased by `cancel`
        // below, after validation. Never construct a dummy KesKey workspace.
        let mut validator = GenerationCoordinator::default();
        let (revision, committed_write, archive) = match envelope.fields().action {
            Action::CredentialReplace | Action::CredentialRevoke => {
                match crate::credentials::change_pool_credential(
                    &mut self.state,
                    &mut validator,
                    None,
                    envelope,
                )
                .map_err(PoolManagementError::Credential)?
                {
                    CredentialOutcome::Applied { revision, .. } => (revision, true, None),
                    CredentialOutcome::AlreadyCommitted { revision } => (revision, false, None),
                }
            }
            Action::RecipientReplace => {
                match crate::recipient::replace(&mut self.state, &mut validator, None, envelope)
                    .map_err(PoolManagementError::Recipient)?
                {
                    ReplacementOutcome::Applied {
                        revision, archive, ..
                    } => (revision, true, Some(archive)),
                    ReplacementOutcome::AlreadyCommitted { revision } => (revision, false, None),
                }
            }
            Action::StagedDiscard => {
                match crate::credentials::discard_staged(&mut self.state, envelope)
                    .map_err(PoolManagementError::Credential)?
                {
                    crate::credentials::DiscardOutcome::Applied { revision, .. } => {
                        (revision, true, None)
                    }
                    crate::credentials::DiscardOutcome::AlreadyCommitted { revision } => {
                        (revision, false, None)
                    }
                }
            }
            _ => {
                return Err(PoolManagementError::Credential(
                    crate::credentials::Error::WrongAction,
                ));
            }
        };
        let cancelled_generation = checkpoint
            .filter(|_| committed_write && envelope.fields().action != Action::StagedDiscard)
            .map(|checkpoint| checkpoint.generation);
        if let Some(generation) = cancelled_generation {
            cancel(generation);
        }
        if committed_write {
            self.persist(journal, flash, rng, work)
                .map_err(PoolManagementError::Operation)?;
        }
        Ok(PoolManagementOutcome {
            revision,
            committed_write,
            cancelled_generation,
            archive,
        })
    }
}

impl crate::activation::DurablePool {
    fn generation_coordinator(&self) -> GenerationCoordinator {
        self.state
            .generation_checkpoint()
            .map(GenerationCoordinator::from_checkpoint)
            .unwrap_or_default()
    }

    /// Recover authenticated authority and reclaim unreferenced public objects
    /// before durably aborting any interrupted, RAM-only cryptographic job.
    /// No fresh entropy is used to recreate that job or its secret.
    pub fn recover_generation<F: crate::journal::Flash, R: TryCryptoRng>(
        journal: &crate::journal::Journal<crate::journal::PoolCodec>,
        flash: &mut F,
        rng: &mut R,
        work: &mut crate::journal::Workspaces<'_>,
    ) -> Result<Self, crate::activation::OperationError> {
        let mut pool = Self::from_recovered(journal.recover(flash, rng, work)?);
        if let Some(mut checkpoint) = pool.state.generation_checkpoint()
            && checkpoint.outcome == CheckpointOutcome::InProgress
        {
            checkpoint.outcome = CheckpointOutcome::NotCommitted;
            pool.state.set_generation_checkpoint(checkpoint)?;
            pool.persist(journal, flash, rng, work)?;
        }
        Ok(pool)
    }

    pub fn generation_status(
        &self,
        request: RequestId,
        number: Option<GenerationNumber>,
    ) -> Result<OperationStatus, crate::activation::OperationError> {
        self.ensure_usable()?;
        Ok(self
            .generation_coordinator()
            .status(&self.state, request, number))
    }

    /// The ACK/operation handle is released only after admission reaches CLEAN.
    /// A lost ACK is reconciled from the intrinsic authenticated checkpoint.
    pub fn admit_generation<F: crate::journal::Flash, R: TryCryptoRng>(
        &mut self,
        request: GenerationRequest,
        journal: &crate::journal::Journal<crate::journal::PoolCodec>,
        flash: &mut F,
        rng: &mut R,
        work: &mut crate::journal::Workspaces<'_>,
    ) -> Result<Admission, DurableGenerationError<core::convert::Infallible>> {
        self.ensure_usable()
            .map_err(DurableGenerationError::Operation)?;
        let mut coordinator = self.generation_coordinator();
        let admission = coordinator
            .admit(&self.state, request, rng)
            .map_err(DurableGenerationError::Generation)?;
        if matches!(admission, Admission::Started(_)) {
            self.state
                .set_generation_checkpoint(coordinator.checkpoint().expect("admitted record"))
                .map_err(|e| DurableGenerationError::Operation(e.into()))?;
            self.persist(journal, flash, rng, work)
                .map_err(DurableGenerationError::Operation)?;
        }
        Ok(admission)
    }

    /// Explicit opt-in retry after authoritative NOT_COMMITTED. Preserve the
    /// assigned identity, original digest, policy and admission revision. A
    /// policy cancellation is terminal and cannot be restarted under new epochs.
    pub fn restart_generation<F: crate::journal::Flash, R: TryCryptoRng>(
        &mut self,
        request: GenerationRequest,
        journal: &crate::journal::Journal<crate::journal::PoolCodec>,
        flash: &mut F,
        rng: &mut R,
        work: &mut crate::journal::Workspaces<'_>,
    ) -> Result<GenerationOperation, DurableGenerationError<core::convert::Infallible>> {
        self.ensure_usable()
            .map_err(DurableGenerationError::Operation)?;
        authorize(request.actor, &self.state).map_err(DurableGenerationError::Generation)?;
        let mut checkpoint =
            self.state
                .generation_checkpoint()
                .ok_or(DurableGenerationError::Generation(Error::State(
                    StateError::GenerationConflict,
                )))?;
        if checkpoint.outcome != CheckpointOutcome::NotCommitted
            || checkpoint.request != request.request
            || checkpoint.payload_digest != request.payload_digest
            || checkpoint.generation_number != request.next_generation_number
            || checkpoint.expected_revision != request.expected_revision
        {
            return Err(DurableGenerationError::Generation(Error::State(
                StateError::GenerationConflict,
            )));
        }
        if checkpoint.policy != self.state.generation_policy() || self.state.credential_revoked() {
            return Err(DurableGenerationError::Generation(Error::State(
                StateError::PolicyChanged,
            )));
        }
        if self.state.staged().is_some() {
            return Err(DurableGenerationError::Generation(Error::State(
                StateError::StagedConflict,
            )));
        }
        checkpoint.outcome = CheckpointOutcome::InProgress;
        checkpoint.attempt =
            checkpoint
                .attempt
                .checked_add(1)
                .ok_or(DurableGenerationError::Generation(Error::State(
                    StateError::CounterOverflow,
                )))?;
        self.state
            .set_generation_checkpoint(checkpoint)
            .map_err(|e| DurableGenerationError::Operation(e.into()))?;
        self.persist(journal, flash, rng, work)
            .map_err(DurableGenerationError::Operation)?;
        let coordinator = GenerationCoordinator::from_checkpoint(checkpoint);
        Ok(GenerationOperation {
            actor: request.actor,
            expected_revision: checkpoint.expected_revision,
            policy: checkpoint.policy,
            record: coordinator.record.expect("restored record"),
        })
    }

    pub fn cancel_generation<F: crate::journal::Flash, R: TryCryptoRng>(
        &mut self,
        operation: GenerationOperation,
        key: &mut KesKey,
        journal: &crate::journal::Journal<crate::journal::PoolCodec>,
        flash: &mut F,
        rng: &mut R,
        work: &mut crate::journal::Workspaces<'_>,
    ) -> Result<(), DurableGenerationError<core::convert::Infallible>> {
        self.ensure_usable()
            .map_err(DurableGenerationError::Operation)?;
        let mut coordinator = self.generation_coordinator();
        coordinator
            .cancel(operation, key)
            .map_err(DurableGenerationError::Generation)?;
        // The actual job workspace is erased above. Recover physical object
        // authority as well; only verified cleanup permits the durable abort.
        self.invalidate();
        *self = Self::recover_generation(journal, flash, rng, work)
            .map_err(DurableGenerationError::Operation)?;
        Ok(())
    }

    /// Run immutable object publication using a scoped flash borrow, then commit
    /// the staged key and COMMITTED checkpoint in one journal transaction. The
    /// closure invokes `GenerationCoordinator::complete`; it must not acknowledge
    /// its RAM result. This shape lets the existing firmware object adapter share
    /// the same flash with the journal without a second state/storage authority.
    pub fn complete_generation<F: crate::journal::Flash, R: TryCryptoRng, E>(
        &mut self,
        journal: &crate::journal::Journal<crate::journal::PoolCodec>,
        flash: &mut F,
        rng: &mut R,
        work: &mut crate::journal::Workspaces<'_>,
        publish: impl FnOnce(
            &mut F,
            &mut R,
            &mut PoolRegistration,
            &mut GenerationCoordinator,
        ) -> Result<GenerationDescriptor, Error<E>>,
    ) -> Result<GenerationDescriptor, DurableGenerationError<E>> {
        self.ensure_usable()
            .map_err(DurableGenerationError::Operation)?;
        let mut coordinator = self.generation_coordinator();
        if !coordinator.has_in_progress() {
            return Err(DurableGenerationError::Generation(Error::State(
                StateError::GenerationConflict,
            )));
        }
        let original = coordinator.checkpoint().expect("in-progress record");
        let descriptor = match publish(flash, rng, &mut self.state, &mut coordinator) {
            Ok(descriptor) => descriptor,
            Err(error) => {
                // A failed public write/discard may leave an orphan. Discard all
                // RAM candidates and recover physical authority, including
                // erase/readback of both unreferenced slots, before recording
                // NOT_COMMITTED. A flash failure leaves this owner invalid.
                self.invalidate();
                *self = Self::recover_generation(journal, flash, rng, work)
                    .map_err(DurableGenerationError::Operation)?;
                return Err(DurableGenerationError::Generation(error));
            }
        };
        let checkpoint = coordinator.checkpoint().expect("operation record");
        let mut expected = original;
        expected.outcome = CheckpointOutcome::Committed;
        let staged_matches = self.state.staged().is_some_and(|g| {
            g.id() == original.generation
                && g.number() == original.generation_number
                && g.creation_request() == original.request
                && g.creation_payload_digest() == &original.payload_digest
                && GenerationDescriptor::from_generation(g) == descriptor
        });
        if checkpoint != expected
            || !staged_matches
            || original.policy != self.state.generation_policy()
            || self.state.credential_revoked()
        {
            self.invalidate();
            return Err(DurableGenerationError::Generation(Error::State(
                StateError::GenerationConflict,
            )));
        }
        self.state.finish_generation_checkpoint(checkpoint);
        self.persist(journal, flash, rng, work)
            .map_err(DurableGenerationError::Operation)?;
        Ok(descriptor)
    }
}
