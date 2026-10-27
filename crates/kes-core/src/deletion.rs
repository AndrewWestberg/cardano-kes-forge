//! Management-authorized pool deletion and history-preserving re-enrollment.
//! These transitions build authenticated-directory successors; the caller must
//! journal the pool cleanup and directory publication before acknowledging.
use crate::management::{Action, Target, VerifiedEnvelope};
use crate::state::{
    Actor, DeletionIntent, Device, DirectoryEntry, DirectorySnapshot, ManagementReplay,
    ManagementResult, PoolRegistration, PoolTombstone, StateError,
};
use crate::types::{HardwareSlot, Revision};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeletionOutcome {
    Applied {
        revision: Revision,
        tombstone: PoolTombstone,
    },
    AlreadyCommitted {
        revision: Revision,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparationOutcome {
    Prepared {
        revision: Revision,
        intent: DeletionIntent,
    },
    AlreadyPrepared {
        revision: Revision,
        intent: DeletionIntent,
    },
    AlreadyCommitted {
        revision: Revision,
    },
}

pub struct ReenrollmentOutcome {
    pub directory_revision: Revision,
    pub pool_revision: Revision,
    pub slot: HardwareSlot,
    pool: Option<PoolRegistration>,
}

impl ReenrollmentOutcome {
    pub const fn is_applied(&self) -> bool {
        self.pool.is_some()
    }

    pub fn into_pool(self) -> Option<PoolRegistration> {
        self.pool
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    WrongAction,
    WrongTarget,
    MissingPoolState,
    InconsistentPoolState,
    Replay,
    ChangedReplay,
    RevisionConflict,
    CounterOverflow,
    SameIncarnation,
    Capacity,
    State(StateError),
}

impl From<StateError> for Error {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

pub fn prepare_delete(
    directory: &mut DirectorySnapshot,
    pool: &PoolRegistration,
    envelope: &VerifiedEnvelope<'_>,
) -> Result<PreparationOutcome, Error> {
    Device::from_authenticated_snapshot(directory)?;
    if directory.pending_enrollment.is_some() {
        return Err(Error::State(StateError::InvalidLifecycle));
    }
    let fields = envelope.fields();
    if fields.action != Action::PoolDelete {
        return Err(Error::WrongAction);
    }
    let Target::Pool {
        pool: target_pool,
        incarnation,
    } = fields.target
    else {
        return Err(Error::WrongTarget);
    };
    if directory.config.identity.device_id() != &fields.device {
        return Err(Error::WrongTarget);
    }
    if let Some(tombstone) = directory
        .tombstones
        .iter()
        .flatten()
        .find(|value| value.pool_id == target_pool)
    {
        if tombstone.last_incarnation != incarnation {
            return Err(Error::WrongTarget);
        }
        if fields.sequence == tombstone.management_sequence {
            if fields.request == tombstone.management_replay.request
                && envelope.transcript_digest() == &tombstone.management_replay.payload_digest
            {
                return Ok(PreparationOutcome::AlreadyCommitted {
                    revision: tombstone.deletion_revision,
                });
            }
            return Err(Error::ChangedReplay);
        }
        return Err(Error::Replay);
    }
    if let Some(intent) = directory.pending_deletion {
        let replay = intent.tombstone.management_replay;
        if target_pool != intent.tombstone.pool_id
            || incarnation != intent.tombstone.last_incarnation
        {
            return Err(Error::InconsistentPoolState);
        }
        if fields.sequence == replay.sequence
            && fields.request == replay.request
            && envelope.transcript_digest() == &replay.payload_digest
        {
            return Ok(PreparationOutcome::AlreadyPrepared {
                revision: directory.revision,
                intent,
            });
        }
        return Err(Error::ChangedReplay);
    }
    if pool.pool_id() != target_pool || pool.incarnation() != incarnation {
        return Err(Error::InconsistentPoolState);
    }
    let next_sequence = pool
        .management_sequence()
        .checked_increment()
        .map_err(|_| Error::CounterOverflow)?;
    if fields.sequence != next_sequence {
        return Err(Error::Replay);
    }
    if fields.expected_revision != pool.revision() {
        return Err(Error::RevisionConflict);
    }
    let entry = directory
        .live
        .iter()
        .flatten()
        .find(|entry| entry.pool_id() == target_pool && entry.incarnation() == incarnation)
        .copied()
        .ok_or(Error::InconsistentPoolState)?;
    if directory.tombstones.iter().all(Option::is_some) {
        return Err(Error::Capacity);
    }
    let prepare_revision = directory
        .revision
        .checked_increment()
        .map_err(|_| Error::CounterOverflow)?;
    let deletion_revision = prepare_revision
        .checked_increment()
        .map_err(|_| Error::CounterOverflow)?;
    let pool_cleanup_revision = pool
        .revision()
        .checked_increment()
        .map_err(|_| Error::CounterOverflow)?;
    let replay = ManagementReplay {
        sequence: fields.sequence,
        request: fields.request,
        payload_digest: *envelope.transcript_digest(),
        result: ManagementResult::Committed {
            revision: deletion_revision,
        },
    };
    let intent = DeletionIntent {
        slot: entry.slot(),
        expected_pool_revision: pool.revision(),
        pool_cleanup_revision,
        tombstone: PoolTombstone {
            pool_id: target_pool,
            last_incarnation: incarnation,
            credential_epoch: Some(pool.credential_epoch()),
            management_sequence: fields.sequence,
            certificate_high_water: pool.certificate_high_water(),
            generation_high_water: pool.generation_high_water(),
            deletion_revision,
            management_replay: replay,
        },
    };
    directory.pending_deletion = Some(intent);
    directory.revision = prepare_revision;
    Ok(PreparationOutcome::Prepared {
        revision: prepare_revision,
        intent,
    })
}

pub fn cleanup_pending_pool(
    directory: &DirectorySnapshot,
    pool: &mut PoolRegistration,
) -> Result<bool, Error> {
    let intent = directory
        .pending_deletion
        .ok_or(Error::InconsistentPoolState)?;
    if pool.pool_id() != intent.tombstone.pool_id
        || pool.incarnation() != intent.tombstone.last_incarnation
    {
        return Err(Error::InconsistentPoolState);
    }
    let replay = ManagementReplay {
        result: ManagementResult::Committed {
            revision: intent.pool_cleanup_revision,
        },
        ..intent.tombstone.management_replay
    };
    if pool.deletion_cleanup_matches(&replay) {
        return Ok(false);
    }
    if pool.revision() != intent.expected_pool_revision {
        return Err(Error::RevisionConflict);
    }
    pool.commit_deletion_cleanup(replay, intent.pool_cleanup_revision);
    Ok(true)
}

pub fn finish_delete(
    directory: &mut DirectorySnapshot,
    pool: &PoolRegistration,
) -> Result<DeletionOutcome, Error> {
    Device::from_authenticated_snapshot(directory)?;
    let intent = directory
        .pending_deletion
        .ok_or(Error::InconsistentPoolState)?;
    let pool_replay = ManagementReplay {
        result: ManagementResult::Committed {
            revision: intent.pool_cleanup_revision,
        },
        ..intent.tombstone.management_replay
    };
    if pool.pool_id() != intent.tombstone.pool_id
        || pool.incarnation() != intent.tombstone.last_incarnation
        || pool.revision() != intent.pool_cleanup_revision
        || !pool.deletion_cleanup_matches(&pool_replay)
    {
        return Err(Error::InconsistentPoolState);
    }
    commit_delete(directory, intent)
}
/// Finalize a persisted deletion after the slot region has been completely
/// erased. The boot recovery owner MUST establish physical erasure before
/// calling this; the authenticated directory intent remains the authority.
pub fn finish_delete_after_erasure(
    directory: &mut DirectorySnapshot,
    erased_slot: HardwareSlot,
) -> Result<DeletionOutcome, Error> {
    Device::from_authenticated_snapshot(directory)?;
    let intent = directory
        .pending_deletion
        .ok_or(Error::InconsistentPoolState)?;
    if intent.slot != erased_slot {
        return Err(Error::InconsistentPoolState);
    }
    commit_delete(directory, intent)
}

fn commit_delete(
    directory: &mut DirectorySnapshot,
    intent: DeletionIntent,
) -> Result<DeletionOutcome, Error> {
    let live_index = directory
        .live
        .iter()
        .position(|entry| {
            entry.is_some_and(|entry| {
                entry.slot() == intent.slot
                    && entry.pool_id() == intent.tombstone.pool_id
                    && entry.incarnation() == intent.tombstone.last_incarnation
            })
        })
        .ok_or(Error::InconsistentPoolState)?;
    let tombstone_index = directory
        .tombstones
        .iter()
        .position(Option::is_none)
        .ok_or(Error::Capacity)?;
    directory.live[live_index] = None;
    directory.tombstones[tombstone_index] = Some(intent.tombstone);
    directory.pending_deletion = None;
    directory.revision = intent.tombstone.deletion_revision;
    Ok(DeletionOutcome::Applied {
        revision: intent.tombstone.deletion_revision,
        tombstone: intent.tombstone,
    })
}

pub fn delete(
    directory: &mut DirectorySnapshot,
    pool: Option<&mut PoolRegistration>,
    envelope: &VerifiedEnvelope<'_>,
) -> Result<DeletionOutcome, Error> {
    let Some(pool) = pool else {
        let target = envelope.fields().target;
        if let Target::Pool { pool, incarnation } = target
            && let Some(tombstone) = directory
                .tombstones
                .iter()
                .flatten()
                .find(|value| value.pool_id == pool)
            && tombstone.last_incarnation == incarnation
            && envelope.fields().sequence == tombstone.management_sequence
            && envelope.fields().request == tombstone.management_replay.request
            && envelope.transcript_digest() == &tombstone.management_replay.payload_digest
        {
            return Ok(DeletionOutcome::AlreadyCommitted {
                revision: tombstone.deletion_revision,
            });
        }
        return Err(Error::MissingPoolState);
    };
    match prepare_delete(directory, pool, envelope)? {
        PreparationOutcome::AlreadyCommitted { revision } => {
            return Ok(DeletionOutcome::AlreadyCommitted { revision });
        }
        PreparationOutcome::Prepared { .. } | PreparationOutcome::AlreadyPrepared { .. } => {}
    }
    cleanup_pending_pool(directory, pool)?;
    finish_delete(directory, pool)
}

pub fn reenroll(
    directory: &mut DirectorySnapshot,
    existing_pool: Option<&PoolRegistration>,
    envelope: &VerifiedEnvelope<'_>,
) -> Result<ReenrollmentOutcome, Error> {
    Device::from_authenticated_snapshot(directory)?;
    if directory.pending_deletion.is_some() || directory.pending_enrollment.is_some() {
        return Err(Error::State(StateError::InvalidLifecycle));
    }
    let fields = envelope.fields();
    if fields.action != Action::Enroll {
        return Err(Error::WrongAction);
    }
    let Target::Pool { pool, incarnation } = fields.target else {
        return Err(Error::WrongTarget);
    };
    if directory.config.identity.device_id() != &fields.device {
        return Err(Error::WrongTarget);
    }

    if let Some(entry) = directory
        .live
        .iter()
        .flatten()
        .find(|entry| entry.pool_id() == pool)
    {
        let existing = existing_pool.ok_or(Error::MissingPoolState)?;
        if entry.incarnation() != incarnation
            || existing.pool_id() != pool
            || existing.incarnation() != incarnation
        {
            return Err(Error::InconsistentPoolState);
        }
        let replay = existing.management_replay();
        if fields.sequence == replay.sequence {
            if fields.request == replay.request
                && envelope.transcript_digest() == &replay.payload_digest
            {
                let ManagementResult::Committed { revision } = replay.result;
                return Ok(ReenrollmentOutcome {
                    directory_revision: directory.revision,
                    pool_revision: revision,
                    slot: entry.slot(),
                    pool: None,
                });
            }
            return Err(Error::ChangedReplay);
        }
        return Err(Error::Replay);
    }
    if existing_pool.is_some() {
        return Err(Error::InconsistentPoolState);
    }

    let tombstone_index = directory
        .tombstones
        .iter()
        .position(|value| value.is_some_and(|value| value.pool_id == pool))
        .ok_or(Error::MissingPoolState)?;
    let tombstone = directory.tombstones[tombstone_index].expect("located tombstone");
    if incarnation == tombstone.last_incarnation {
        return Err(Error::SameIncarnation);
    }
    let next_sequence = tombstone
        .management_sequence
        .checked_increment()
        .map_err(|_| Error::CounterOverflow)?;
    if fields.sequence != next_sequence {
        return Err(Error::Replay);
    }
    if fields.expected_revision != directory.revision {
        return Err(Error::RevisionConflict);
    }
    let enrollment = envelope.enrollment().map_err(|_| Error::WrongTarget)?;
    let mut registration = PoolRegistration::new(Actor::Management, enrollment)?;
    registration.merge_retained_history(
        tombstone.generation_high_water,
        tombstone.certificate_high_water,
    );
    let slot_index = (0..crate::MAX_POOLS)
        .find(|index| {
            !directory
                .live
                .iter()
                .flatten()
                .any(|entry| entry.slot().get() == *index)
        })
        .ok_or(Error::Capacity)?;
    let storage_index = directory
        .live
        .iter()
        .position(Option::is_none)
        .ok_or(Error::Capacity)?;
    let slot = HardwareSlot::new(slot_index).map_err(|_| Error::Capacity)?;
    let revision = directory
        .revision
        .checked_increment()
        .map_err(|_| Error::CounterOverflow)?;
    directory.tombstones[tombstone_index] = None;
    directory.live[storage_index] = Some(DirectoryEntry::new(slot, pool, incarnation));
    directory.revision = revision;
    Ok(ReenrollmentOutcome {
        directory_revision: revision,
        pool_revision: registration.revision(),
        slot,
        pool: Some(registration),
    })
}
