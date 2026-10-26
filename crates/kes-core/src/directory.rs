//! Management-authorized directory enrollment and replay reconciliation.
//! Journal persistence remains the caller's commit boundary; this layer mutates
//! only a validated RAM candidate and never acknowledges durability.
use crate::management::{Action, Target, VerifiedEnvelope};
use crate::state::{Actor, Device, ManagementResult, PoolRegistration, StateError};
use crate::types::{HardwareSlot, ManagementSequence, Revision};

pub enum EnrollmentOutcome {
    Applied {
        slot: HardwareSlot,
        directory_revision: Revision,
        pool: PoolRegistration,
    },
    AlreadyCommitted {
        slot: HardwareSlot,
        pool_revision: Revision,
        directory_revision: Revision,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    WrongAction,
    MissingPoolState,
    InconsistentPoolState,
    Replay,
    ChangedReplay,
    State(StateError),
}

impl From<StateError> for Error {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

/// Apply one verified ENROLL authorization. Exact replay returns its recorded
/// public outcome; changed or older sequence input cannot create another pool.
pub fn enroll(
    device: &mut Device,
    existing_pool: Option<&PoolRegistration>,
    envelope: &VerifiedEnvelope<'_>,
) -> Result<EnrollmentOutcome, Error> {
    let fields = envelope.fields();
    if fields.action != Action::Enroll {
        return Err(Error::WrongAction);
    }
    let Target::Pool { pool, incarnation } = fields.target else {
        return Err(Error::WrongAction);
    };

    if let Some(entry) = device.find(pool) {
        if entry.incarnation() != incarnation {
            return Err(Error::InconsistentPoolState);
        }
        let existing = existing_pool.ok_or(Error::MissingPoolState)?;
        if existing.pool_id() != pool || existing.incarnation() != incarnation {
            return Err(Error::InconsistentPoolState);
        }
        let replay = existing.management_replay();
        if fields.sequence == replay.sequence {
            if fields.request == replay.request
                && envelope.transcript_digest() == &replay.payload_digest
            {
                let ManagementResult::Committed { revision } = replay.result;
                return Ok(EnrollmentOutcome::AlreadyCommitted {
                    slot: entry.slot(),
                    pool_revision: revision,
                    directory_revision: device.directory_revision(),
                });
            }
            return Err(Error::ChangedReplay);
        }
        if fields.sequence < replay.sequence {
            return Err(Error::Replay);
        }
        return Err(Error::State(StateError::DuplicatePool));
    }
    if existing_pool.is_some() {
        return Err(Error::InconsistentPoolState);
    }
    if fields.sequence != ManagementSequence::new(1) {
        return Err(Error::Replay);
    }
    if fields.expected_revision != device.directory_revision() {
        return Err(Error::State(StateError::RevisionConflict));
    }

    let candidate = PoolRegistration::new(
        Actor::Management,
        envelope
            .enrollment()
            .map_err(|_| Error::State(StateError::InvalidObject))?,
    )?;
    let slot = device.enroll(Actor::Management, &candidate, fields.expected_revision)?;
    Ok(EnrollmentOutcome::Applied {
        slot,
        directory_revision: device.directory_revision(),
        pool: candidate,
    })
}
