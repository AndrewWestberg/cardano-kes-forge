//! Generation admission, immutable public-object publication and backup retrieval.
//! The caller owns the cooperative crypto scheduler and durable object backend.
use crate::backup::{self, Metadata};
use crate::crypto::{CryptoError, Generation, KesKey, PublicTreeBuffer, VerifiedPublicTree};
use crate::state::{
    Actor, GenerationPolicy, GenerationSpec, KESGeneration, Lifecycle, MAX_PUBLIC_OBJECT_BYTES,
    PoolRegistration, PublicObject, PublicObjectRef, StateError,
};
use crate::types::{DeviceId, GenerationId, GenerationNumber, RequestId, Revision, TypeError};
use ed25519_dalek::SigningKey;
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
    /// Restore authenticated public operation memory after reboot. A job cannot
    /// survive reboot without its secret workspace, so unfinished work becomes
    /// `NOT_COMMITTED`; a committed pool descriptor still takes precedence.
    pub const fn from_checkpoint(checkpoint: GenerationCheckpoint) -> Self {
        let state = match checkpoint.outcome {
            CheckpointOutcome::InProgress | CheckpointOutcome::NotCommitted => {
                RecordState::NotCommitted
            }
            CheckpointOutcome::Committed => RecordState::Committed,
        };
        Self {
            record: Some(GenerationRecord {
                request: checkpoint.request,
                payload_digest: checkpoint.payload_digest,
                generation: checkpoint.generation,
                generation_number: checkpoint.generation_number,
                state,
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
            state: RecordState::InProgress,
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
        identity: &SigningKey,
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
        let artifact = match backup::create(
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
            identity,
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

/// Seed a caller-owned cooperative generation. The returned job performs one
/// leaf per `step`; the firmware scheduler retains the original request deadline.
pub fn begin_key_generation<'state, 'tree>(
    entropy: &mut impl TryCryptoRng,
    key: &'state mut KesKey,
    tree: &'tree mut PublicTreeBuffer,
) -> Result<Generation<'state, 'tree>, BeginError> {
    let mut seed = Zeroizing::new([0; 32]);
    entropy
        .try_fill_bytes(&mut seed[..])
        .map_err(|_| BeginError::Entropy)?;
    Generation::begin(&mut seed, key, tree).map_err(BeginError::Crypto)
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
