//! Management-authorized pool credential lifecycle and staged-generation discard.
//! The caller owns the journal transaction; these functions mutate only a fully
//! validated RAM successor and erase affected secret work before returning.
use crate::crypto::KesKey;
use crate::generation::GenerationCoordinator;
use crate::management::{Action, Target, VerifiedEnvelope};
use crate::state::{DirectorySnapshot, ManagementReplay, ManagementResult, PoolRegistration};
use crate::types::{GenerationId, Revision};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialOutcome {
    Applied {
        revision: Revision,
        cancelled_generation: Option<GenerationId>,
    },
    AlreadyCommitted {
        revision: Revision,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscardOutcome {
    Applied {
        revision: Revision,
        generation: GenerationId,
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
    InvalidPayload,
    InvalidEpoch,
    StaleGeneration,
    MissingGenerationWorkspace,
    PendingOperation,
}

pub fn change_pool_credential(
    pool: &mut PoolRegistration,
    coordinator: &mut GenerationCoordinator,
    generation_workspace: Option<&mut KesKey>,
    envelope: &VerifiedEnvelope<'_>,
) -> Result<CredentialOutcome, Error> {
    let fields = envelope.fields();
    if !matches!(
        fields.action,
        Action::CredentialReplace | Action::CredentialRevoke
    ) {
        return Err(Error::WrongAction);
    }
    require_pool_target(pool, fields.target)?;
    if let Some(revision) = exact_replay(pool, envelope)? {
        return Ok(CredentialOutcome::AlreadyCommitted { revision });
    }
    require_next(pool, envelope)?;

    let (epoch, replacement) = envelope
        .credential_change()
        .map_err(|_| Error::InvalidPayload)?;
    let next_epoch = pool
        .credential_epoch()
        .checked_increment()
        .map_err(|_| Error::CounterOverflow)?;
    if epoch != next_epoch || (fields.action == Action::CredentialReplace) != replacement.is_some()
    {
        return Err(Error::InvalidEpoch);
    }
    let revision = pool
        .revision()
        .checked_increment()
        .map_err(|_| Error::CounterOverflow)?;
    if coordinator.has_in_progress() && generation_workspace.is_none() {
        return Err(Error::MissingGenerationWorkspace);
    }
    let cancelled_generation = coordinator
        .cancel_for_policy_change(generation_workspace)
        .map_err(|()| Error::MissingGenerationWorkspace)?;
    let public_key = replacement.unwrap_or(*pool.credential_public_key());
    pool.commit_credential_change(
        public_key,
        epoch,
        fields.action == Action::CredentialRevoke,
        committed_replay(envelope, revision),
        revision,
    );
    Ok(CredentialOutcome::Applied {
        revision,
        cancelled_generation,
    })
}

pub fn change_device_credential(
    directory: &mut DirectorySnapshot,
    envelope: &VerifiedEnvelope<'_>,
) -> Result<CredentialOutcome, Error> {
    if directory.pending_enrollment.is_some() {
        return Err(Error::PendingOperation);
    }
    let fields = envelope.fields();
    if !matches!(
        fields.action,
        Action::CredentialReplace | Action::CredentialRevoke
    ) {
        return Err(Error::WrongAction);
    }
    if fields.target != Target::Device || directory.config.identity.device_id() != &fields.device {
        return Err(Error::WrongTarget);
    }
    if let Some(replay) = directory.credential.management_replay {
        if fields.sequence == replay.sequence {
            if fields.request == replay.request
                && envelope.transcript_digest() == &replay.payload_digest
            {
                let ManagementResult::Committed { revision } = replay.result;
                return Ok(CredentialOutcome::AlreadyCommitted { revision });
            }
            return Err(Error::ChangedReplay);
        }
        let next = replay
            .sequence
            .checked_increment()
            .map_err(|_| Error::CounterOverflow)?;
        if fields.sequence != next {
            return Err(Error::Replay);
        }
    } else if fields.sequence.get() != 1 {
        return Err(Error::Replay);
    }
    if fields.expected_revision != directory.revision {
        return Err(Error::RevisionConflict);
    }
    let (epoch, replacement) = envelope
        .credential_change()
        .map_err(|_| Error::InvalidPayload)?;
    let next_epoch = directory
        .credential
        .epoch
        .checked_increment()
        .map_err(|_| Error::CounterOverflow)?;
    if epoch != next_epoch || (fields.action == Action::CredentialReplace) != replacement.is_some()
    {
        return Err(Error::InvalidEpoch);
    }
    let revision = directory
        .revision
        .checked_increment()
        .map_err(|_| Error::CounterOverflow)?;
    if let Some(public_key) = replacement {
        directory.credential.public_key = public_key;
    }
    directory.credential.epoch = epoch;
    directory.credential.revoked = fields.action == Action::CredentialRevoke;
    directory.credential.management_replay = Some(committed_replay(envelope, revision));
    directory.revision = revision;
    Ok(CredentialOutcome::Applied {
        revision,
        cancelled_generation: None,
    })
}

pub fn discard_staged(
    pool: &mut PoolRegistration,
    envelope: &VerifiedEnvelope<'_>,
) -> Result<DiscardOutcome, Error> {
    let fields = envelope.fields();
    if fields.action != Action::StagedDiscard {
        return Err(Error::WrongAction);
    }
    require_pool_target(pool, fields.target)?;
    if let Some(revision) = exact_replay(pool, envelope)? {
        return Ok(DiscardOutcome::AlreadyCommitted { revision });
    }
    require_next(pool, envelope)?;
    let generation = envelope
        .staged_generation()
        .map_err(|_| Error::InvalidPayload)?;
    if pool.staged().is_none_or(|staged| staged.id() != generation) {
        return Err(Error::StaleGeneration);
    }
    let revision = pool
        .revision()
        .checked_increment()
        .map_err(|_| Error::CounterOverflow)?;
    let discarded = pool
        .commit_staged_discard(committed_replay(envelope, revision), revision)
        .ok_or(Error::StaleGeneration)?;
    Ok(DiscardOutcome::Applied {
        revision,
        generation: discarded,
    })
}

fn require_pool_target(pool: &PoolRegistration, target: Target) -> Result<(), Error> {
    if target
        == (Target::Pool {
            pool: pool.pool_id(),
            incarnation: pool.incarnation(),
        })
    {
        Ok(())
    } else {
        Err(Error::WrongTarget)
    }
}

fn exact_replay(
    pool: &PoolRegistration,
    envelope: &VerifiedEnvelope<'_>,
) -> Result<Option<Revision>, Error> {
    let fields = envelope.fields();
    let replay = pool.management_replay();
    if fields.sequence != replay.sequence {
        return Ok(None);
    }
    if fields.request == replay.request && envelope.transcript_digest() == &replay.payload_digest {
        let ManagementResult::Committed { revision } = replay.result;
        Ok(Some(revision))
    } else {
        Err(Error::ChangedReplay)
    }
}

fn require_next(pool: &PoolRegistration, envelope: &VerifiedEnvelope<'_>) -> Result<(), Error> {
    let fields = envelope.fields();
    let next = pool
        .management_sequence()
        .checked_increment()
        .map_err(|_| Error::CounterOverflow)?;
    if fields.sequence != next {
        return Err(Error::Replay);
    }
    if fields.expected_revision != pool.revision() {
        return Err(Error::RevisionConflict);
    }
    Ok(())
}

fn committed_replay(envelope: &VerifiedEnvelope<'_>, revision: Revision) -> ManagementReplay {
    let fields = envelope.fields();
    ManagementReplay {
        sequence: fields.sequence,
        request: fields.request,
        payload_digest: *envelope.transcript_digest(),
        result: ManagementResult::Committed { revision },
    }
}
