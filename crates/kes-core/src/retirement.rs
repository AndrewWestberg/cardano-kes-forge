//! Management-authorized durable device retirement.
//! The successor records the global deny state before erasing pool secrets and
//! clearing live slots. External artifacts are intentionally outside this scope.
use crate::management::{Action, Target, VerifiedEnvelope};
use crate::state::{
    Device, DeviceRetirement, DirectorySnapshot, ManagementReplay, ManagementResult,
    PoolRegistration, PoolTombstone, StateError,
};
use crate::types::Revision;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Applied {
        revision: Revision,
        retired_pools: usize,
        external_backups_unchanged: bool,
    },
    AlreadyCommitted {
        revision: Revision,
        external_backups_unchanged: bool,
    },
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
    State(StateError),
}

impl From<StateError> for Error {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

pub fn retire(
    directory: &mut DirectorySnapshot,
    pools: &mut [PoolRegistration],
    envelope: &VerifiedEnvelope<'_>,
) -> Result<Outcome, Error> {
    Device::from_authenticated_snapshot(directory)?;
    if directory.pending_deletion.is_some() {
        return Err(Error::InconsistentPoolState);
    }
    let fields = envelope.fields();
    if fields.action != Action::DeviceRetire {
        return Err(Error::WrongAction);
    }
    if fields.target != Target::Device || directory.config.identity.device_id() != &fields.device {
        return Err(Error::WrongTarget);
    }
    let (revision, replay, resuming_cleanup) = if let Some(retirement) = directory.retirement {
        let replay = retirement.management_replay;
        if fields.sequence != replay.sequence {
            return Err(Error::Replay);
        }
        if fields.request != replay.request
            || envelope.transcript_digest() != &replay.payload_digest
        {
            return Err(Error::ChangedReplay);
        }
        if directory.live.iter().all(Option::is_none) {
            return Ok(Outcome::AlreadyCommitted {
                revision: retirement.revision,
                external_backups_unchanged: true,
            });
        }
        (retirement.revision, replay, true)
    } else {
        if directory.credential.revoked {
            return Err(Error::CredentialRevoked);
        }
        let expected_sequence = match directory.credential.management_replay {
            Some(previous) => previous
                .sequence
                .checked_increment()
                .map_err(|_| Error::CounterOverflow)?,
            None => crate::types::ManagementSequence::new(1),
        };
        if fields.sequence != expected_sequence {
            return Err(Error::Replay);
        }
        if fields.expected_revision != directory.revision {
            return Err(Error::RevisionConflict);
        }
        let revision = directory
            .revision
            .checked_increment()
            .map_err(|_| Error::CounterOverflow)?;
        (
            revision,
            ManagementReplay {
                sequence: fields.sequence,
                request: fields.request,
                payload_digest: *envelope.transcript_digest(),
                result: ManagementResult::Committed { revision },
            },
            false,
        )
    };

    let live_count = directory.live.iter().flatten().count();
    if pools.len() != live_count {
        return Err(Error::InconsistentPoolState);
    }
    for entry in directory.live.iter().flatten() {
        let matches = pools
            .iter()
            .filter(|pool| {
                pool.pool_id() == entry.pool_id() && pool.incarnation() == entry.incarnation()
            })
            .count();
        if matches != 1 {
            return Err(Error::InconsistentPoolState);
        }
    }
    let vacant_tombstones = directory
        .tombstones
        .iter()
        .filter(|entry| entry.is_none())
        .count();
    if vacant_tombstones < live_count {
        return Err(Error::Capacity);
    }
    if !resuming_cleanup {
        // Once this field is set, every operational entry point reconstructed
        // from the candidate fails closed even if cleanup is resumed after an
        // interruption.
        directory.retirement = Some(DeviceRetirement {
            revision,
            management_replay: replay,
        });
        directory.credential.management_replay = Some(replay);
    }
    for live_index in 0..directory.live.len() {
        let Some(entry) = directory.live[live_index] else {
            continue;
        };
        let pool = pools
            .iter_mut()
            .find(|pool| {
                pool.pool_id() == entry.pool_id() && pool.incarnation() == entry.incarnation()
            })
            .expect("pool set validated before retirement mutation");
        pool.erase_all_secrets();
        let tombstone_index = directory
            .tombstones
            .iter()
            .position(Option::is_none)
            .expect("tombstone capacity validated before retirement mutation");
        directory.tombstones[tombstone_index] = Some(PoolTombstone {
            pool_id: pool.pool_id(),
            last_incarnation: pool.incarnation(),
            management_sequence: fields.sequence,
            certificate_high_water: pool.certificate_high_water(),
            generation_high_water: pool.generation_high_water(),
            deletion_revision: revision,
            management_replay: replay,
        });
        directory.live[live_index] = None;
    }
    directory.revision = revision;
    Ok(Outcome::Applied {
        revision,
        retired_pools: live_count,
        external_backups_unchanged: true,
    })
}
