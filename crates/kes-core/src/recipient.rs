//! Management-authorized recipient policy replacement for future generations.
//! Existing generation objects remain byte-identical and identify the prior
//! recipient until the operator has archived them or they are reclaimed.
use crate::crypto::KesKey;
use crate::generation::GenerationCoordinator;
use crate::management::{Action, Target, VerifiedEnvelope};
use crate::state::{ManagementReplay, ManagementResult, PoolRegistration};
use crate::types::{GenerationId, Revision};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreviousRecipientDisposition {
    ArchiveRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveRequirement {
    pub previous_recipient_id: [u8; 32],
    pub retained_generations: [Option<GenerationId>; 2],
    pub disposition: PreviousRecipientDisposition,
}

impl ArchiveRequirement {
    pub const fn required(&self) -> bool {
        matches!(
            self.disposition,
            PreviousRecipientDisposition::ArchiveRequired
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplacementOutcome {
    Applied {
        revision: Revision,
        cancelled_generation: Option<GenerationId>,
        archive: ArchiveRequirement,
    },
    AlreadyCommitted {
        revision: Revision,
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
    InvalidRecipient,
    SameRecipient,
    MissingGenerationWorkspace,
}

pub fn replace(
    pool: &mut PoolRegistration,
    coordinator: &mut GenerationCoordinator,
    generation_workspace: Option<&mut KesKey>,
    envelope: &VerifiedEnvelope<'_>,
) -> Result<ReplacementOutcome, Error> {
    let fields = envelope.fields();
    if fields.action != Action::RecipientReplace {
        return Err(Error::WrongAction);
    }
    if fields.target
        != (Target::Pool {
            pool: pool.pool_id(),
            incarnation: pool.incarnation(),
        })
    {
        return Err(Error::WrongTarget);
    }

    let replay = pool.management_replay();
    if fields.sequence == replay.sequence {
        if fields.request == replay.request
            && envelope.transcript_digest() == &replay.payload_digest
        {
            let ManagementResult::Committed { revision } = replay.result;
            return Ok(ReplacementOutcome::AlreadyCommitted { revision });
        }
        return Err(Error::ChangedReplay);
    }
    let next_sequence = replay
        .sequence
        .checked_increment()
        .map_err(|_| Error::CounterOverflow)?;
    if fields.sequence != next_sequence {
        return Err(Error::Replay);
    }
    if fields.expected_revision != pool.revision() {
        return Err(Error::RevisionConflict);
    }

    let (public_key, recipient_id) = envelope
        .recipient_replacement()
        .map_err(|_| Error::InvalidRecipient)?;
    if recipient_id == *pool.recipient_id() {
        return Err(Error::SameRecipient);
    }
    let policy_epoch = pool
        .recipient_policy_epoch()
        .checked_add(1)
        .ok_or(Error::CounterOverflow)?;
    let revision = pool
        .revision()
        .checked_increment()
        .map_err(|_| Error::CounterOverflow)?;
    if coordinator.has_in_progress() && generation_workspace.is_none() {
        return Err(Error::MissingGenerationWorkspace);
    }

    let previous_recipient_id = *pool.recipient_id();
    let retained_generations = [pool.current(), pool.staged()].map(|generation| {
        generation.and_then(|generation| {
            (generation.recipient_id() == &previous_recipient_id).then_some(generation.id())
        })
    });
    let cancelled_generation = coordinator
        .cancel_for_policy_change(generation_workspace)
        .map_err(|()| Error::MissingGenerationWorkspace)?;
    pool.commit_recipient_replacement(
        public_key,
        recipient_id,
        policy_epoch,
        ManagementReplay {
            sequence: fields.sequence,
            request: fields.request,
            payload_digest: *envelope.transcript_digest(),
            result: ManagementResult::Committed { revision },
        },
        revision,
    );
    Ok(ReplacementOutcome::Applied {
        revision,
        cancelled_generation,
        archive: ArchiveRequirement {
            previous_recipient_id,
            retained_generations,
            disposition: PreviousRecipientDisposition::ArchiveRequired,
        },
    })
}
