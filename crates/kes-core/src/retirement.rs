//! Bounded, journal-owned device retirement.
//!
//! Persist `prepare` before reading/removing any pool. For each live slot,
//! persist `remove_pool` before physically erasing and read-verifying the whole
//! slot. Recovery must also erase unreferenced slots. Neither transition proves
//! physical cleanup or authorizes a success response: the firmware storage owner
//! must establish that every slot is blank before publishing the replay result.
use crate::management::{Action, Target, VerifiedEnvelope};
use crate::state::{
    Device, DeviceRetirement, DirectorySnapshot, ManagementReplay, ManagementResult,
    PoolRegistration, PoolTombstone, StateError,
};
use crate::types::{HardwareSlot, Revision};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Preparation {
    Prepared { revision: Revision },
    AlreadyPrepared { revision: Revision },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    WrongAction,
    WrongTarget,
    Replay,
    ChangedReplay,
    RevisionConflict,
    CounterOverflow,
    InconsistentPoolState,
    Capacity,
    CredentialRevoked,
    NotPrepared,
    State(StateError),
}

impl From<StateError> for Error {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

/// Build the global deny successor, leaving live references intact. An exact
/// replay returns only preparation evidence, NEVER evidence of erased flash.
/// The fixed replay revision identifies the deny marker; directory cleanup may
/// subsequently commit several strictly increasing revisions.
pub fn prepare(
    directory: &mut DirectorySnapshot,
    envelope: &VerifiedEnvelope<'_>,
) -> Result<Preparation, Error> {
    Device::from_authenticated_snapshot(directory)?;
    let fields = envelope.fields();
    if fields.action != Action::DeviceRetire {
        return Err(Error::WrongAction);
    }
    if fields.target != Target::Device || directory.config.identity.device_id() != &fields.device {
        return Err(Error::WrongTarget);
    }
    if directory.pending_deletion.is_some() || directory.pending_enrollment.is_some() {
        return Err(Error::InconsistentPoolState);
    }
    if let Some(retirement) = directory.retirement {
        let replay = retirement.management_replay;
        if fields.sequence != replay.sequence {
            return Err(Error::Replay);
        }
        if fields.request != replay.request
            || envelope.transcript_digest() != &replay.payload_digest
        {
            return Err(Error::ChangedReplay);
        }
        return Ok(Preparation::AlreadyPrepared {
            revision: retirement.revision,
        });
    }
    if directory.credential.revoked {
        return Err(Error::CredentialRevoked);
    }
    let next_sequence = match directory.credential.management_replay {
        Some(previous) => previous
            .sequence
            .checked_increment()
            .map_err(|_| Error::CounterOverflow)?,
        None => crate::types::ManagementSequence::new(1),
    };
    if fields.sequence != next_sequence {
        return Err(Error::Replay);
    }
    if fields.expected_revision != directory.revision {
        return Err(Error::RevisionConflict);
    }
    let live_count = directory.live.iter().flatten().count();
    if directory
        .tombstones
        .iter()
        .filter(|entry| entry.is_none())
        .count()
        < live_count
    {
        return Err(Error::Capacity);
    }
    // Reserve every required cleanup revision before committing permanent deny.
    // A later interrupted CLEAN may consume additional revisions; recovery still
    // fails closed on overflow rather than acknowledge incomplete erasure.
    directory
        .revision
        .get()
        .checked_add(1 + live_count as u64)
        .ok_or(Error::CounterOverflow)?;
    let revision = directory
        .revision
        .checked_increment()
        .map_err(|_| Error::CounterOverflow)?;
    let replay = ManagementReplay {
        sequence: fields.sequence,
        request: fields.request,
        payload_digest: *envelope.transcript_digest(),
        result: ManagementResult::Committed { revision },
    };
    directory.retirement = Some(DeviceRetirement {
        revision,
        management_replay: replay,
    });
    directory.credential.management_replay = Some(replay);
    directory.revision = revision;
    Ok(Preparation::Prepared { revision })
}

/// Build one directory cleanup successor from an authenticated pool snapshot.
/// The caller MUST have persisted the deny marker and MUST persist this
/// successor before erasing `slot`. Retained history is therefore durable even
/// if power fails during erasure. Only one cold pool needs to be resident.
pub fn remove_pool(
    directory: &mut DirectorySnapshot,
    slot: HardwareSlot,
    pool: &PoolRegistration,
) -> Result<Revision, Error> {
    Device::from_authenticated_snapshot(directory)?;
    let retirement = directory.retirement.ok_or(Error::NotPrepared)?;
    if directory.pending_deletion.is_some() || directory.pending_enrollment.is_some() {
        return Err(Error::InconsistentPoolState);
    }
    let live_index = directory
        .live
        .iter()
        .position(|entry| {
            entry.is_some_and(|entry| {
                entry.slot() == slot
                    && entry.pool_id() == pool.pool_id()
                    && entry.incarnation() == pool.incarnation()
            })
        })
        .ok_or(Error::InconsistentPoolState)?;
    let tombstone_index = directory
        .tombstones
        .iter()
        .position(Option::is_none)
        .ok_or(Error::Capacity)?;
    let revision = directory
        .revision
        .checked_increment()
        .map_err(|_| Error::CounterOverflow)?;
    directory.tombstones[tombstone_index] = Some(PoolTombstone {
        pool_id: pool.pool_id(),
        last_incarnation: pool.incarnation(),
        credential_epoch: Some(pool.credential_epoch()),
        management_sequence: retirement.management_replay.sequence,
        certificate_high_water: pool.certificate_high_water(),
        generation_high_water: pool.generation_high_water(),
        deletion_revision: revision,
        management_replay: ManagementReplay {
            result: ManagementResult::Committed { revision },
            ..retirement.management_replay
        },
    });
    directory.live[live_index] = None;
    directory.revision = revision;
    Ok(revision)
}
