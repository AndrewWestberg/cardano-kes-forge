//! Signed pool deletion admission and durable deny intent for disposable A2.
//!
//! This backend never erases a pool or acknowledges a merely prepared deletion.
//! Physical cleanup belongs to the boot recovery owner, not a wire-selected slot.
use kes_core::{
    deletion::{self, PreparationOutcome},
    journal::{DirectoryCodec, Flash, Journal, JournalError, Workspaces},
    management::{self, Action, Target},
    session::Scope,
    state::{DirectorySnapshot, PoolRegistration},
    types::{HardwareSlot, ManagementSequence, RequestId, Revision},
};
use rand_chacha::rand_core::TryCryptoRng;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeletionError {
    Authorization(management::Error),
    Deletion(deletion::Error),
    Journal(JournalError),
    WrongScope,
    StaleAuthority,
    PendingOperation,
    ReadbackMismatch,
    CleanupIncomplete,
}

/// A recorded deletion result, NOT permission to ACK while `cleanup_required`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeletionOutcome {
    pub scope: Scope,
    /// Final deletion revision recorded in the intent/tombstone, not the
    /// intermediate directory intent revision or a later directory revision.
    pub revision: Revision,
    pub sequence: ManagementSequence,
    /// Authenticated physical slot for pending cleanup. Tombstones intentionally
    /// do not retain/reuse a physical slot, so completed retries return `None`.
    pub affected_slot: Option<HardwareSlot>,
    pub cleanup_required: bool,
    pub committed_write: bool,
    request: RequestId,
    digest: [u8; 32],
}

impl DeletionOutcome {
    /// Check the authenticated final directory after physical cleanup.
    /// `complete_pending_deletion` or boot recovery must first prove the erased
    /// slot and publish the tombstone; this check alone does not prove erasure.
    pub fn confirm_completed(&self, directory: &DirectorySnapshot) -> Result<(), DeletionError> {
        let Scope::Pool { pool, incarnation } = self.scope else {
            return Err(DeletionError::WrongScope);
        };
        if directory.pending_deletion.is_some()
            || directory.retirement.is_some()
            || directory
                .live
                .iter()
                .flatten()
                .any(|entry| entry.pool_id() == pool)
        {
            return Err(DeletionError::CleanupIncomplete);
        }
        if directory.tombstones.iter().flatten().any(|tombstone| {
            tombstone.pool_id == pool
                && tombstone.last_incarnation == incarnation
                && tombstone.deletion_revision == self.revision
                && tombstone.management_sequence == self.sequence
                && tombstone.management_replay.request == self.request
                && tombstone.management_replay.payload_digest == self.digest
        }) {
            Ok(())
        } else {
            Err(DeletionError::CleanupIncomplete)
        }
    }
}

/// Admit an already transport-authenticated POOL_DELETE and persist its intent.
///
/// The parent MUST bind the enclosing management session/request ID to `encoded`
/// using the freshly recovered directory credential before calling. Directory
/// access and generation admission must remain serialized through cleanup.
/// `slot` is the locally resolved live slot; `pool` is its freshly authenticated
/// journal state (reconcile the owned generation checkpoint first). Neither may
/// come from untrusted wire routing. Exact pending retries need the matching
/// slot but no pool state; tombstone retries need neither.
///
/// `cancel` synchronously drops any matching owned generation and retires its
/// scheduler lease. It is called only after signature, target, revision, sequence
/// and replay validation, immediately before committing deny (or resuming a
/// previously durable deny). It MUST NOT fail or mutate directory authority.
///
/// On a cleanup-required result, invalidate affected pool sessions immediately,
/// drop all pool/directory owners, then run `complete_pending_deletion` (or boot
/// recovery after reset). Only after read-verified erasure, final publication and
/// `confirm_completed` may the parent MAC an ACK with the recorded revision and
/// sequence. A tombstone-only exact replay has already crossed that barrier.
/// On ANY error do not ACK success: journal writes may be durable despite an
/// error. Never keep using caller RAM authority; recover before retrying. No
/// reset/provisioning fallback, OTP access or dummy secret workspace is allowed.
#[allow(clippy::too_many_arguments)]
pub fn execute<F: Flash, R: TryCryptoRng>(
    encoded: &[u8],
    authenticated_directory: &DirectorySnapshot,
    slot: Option<HardwareSlot>,
    pool: Option<&PoolRegistration>,
    journal: &Journal<DirectoryCodec>,
    flash: &mut F,
    rng: &mut R,
    work: &mut Workspaces<'_>,
    cancel: impl FnOnce(Scope),
) -> Result<DeletionOutcome, DeletionError> {
    let mut current = journal
        .recover(flash, rng, work)
        .map_err(DeletionError::Journal)?;
    if &current.state != authenticated_directory {
        return Err(DeletionError::StaleAuthority);
    }
    let envelope = management::parse_and_verify(
        encoded,
        *current.state.config.identity.device_id(),
        &current.state.config.management_root_public_key,
    )
    .map_err(DeletionError::Authorization)?;
    let fields = envelope.fields();
    let Target::Pool {
        pool: pool_id,
        incarnation,
    } = fields.target
    else {
        return Err(DeletionError::WrongScope);
    };
    if fields.action != Action::PoolDelete {
        return Err(DeletionError::Deletion(deletion::Error::WrongAction));
    }
    if current.state.pending_enrollment.is_some() || current.state.retirement.is_some() {
        return Err(DeletionError::PendingOperation);
    }
    let mut outcome = DeletionOutcome {
        scope: Scope::Pool {
            pool: pool_id,
            incarnation,
        },
        revision: fields.expected_revision,
        sequence: fields.sequence,
        affected_slot: None,
        cleanup_required: false,
        committed_write: false,
        request: fields.request,
        digest: *envelope.transcript_digest(),
    };
    // Do not require a pool journal after erasure, nor mistake an intent for a
    // tombstone. The core authenticates the complete exact-replay identity.
    if current
        .state
        .tombstones
        .iter()
        .flatten()
        .any(|value| value.pool_id == pool_id)
    {
        let deletion::DeletionOutcome::AlreadyCommitted { revision } =
            deletion::delete(&mut current.state, None, &envelope)
                .map_err(DeletionError::Deletion)?
        else {
            return Err(DeletionError::ReadbackMismatch);
        };
        outcome.revision = revision;
        outcome.confirm_completed(&current.state)?;
        return Ok(outcome);
    }
    let entry = current
        .state
        .live
        .iter()
        .flatten()
        .find(|entry| {
            entry.pool_id() == pool_id
                && entry.incarnation() == incarnation
                && Some(entry.slot()) == slot
        })
        .copied()
        .ok_or(DeletionError::WrongScope)?;
    let intent = if let Some(intent) = current.state.pending_deletion {
        let replay = intent.tombstone.management_replay;
        if intent.slot != entry.slot()
            || intent.tombstone.pool_id != pool_id
            || intent.tombstone.last_incarnation != incarnation
        {
            return Err(DeletionError::WrongScope);
        }
        if replay.sequence != fields.sequence
            || replay.request != fields.request
            || replay.payload_digest != *envelope.transcript_digest()
        {
            return Err(DeletionError::Deletion(deletion::Error::ChangedReplay));
        }
        intent
    } else {
        let pool = pool.ok_or(DeletionError::Deletion(deletion::Error::MissingPoolState))?;
        if pool.pool_id() != entry.pool_id() || pool.incarnation() != entry.incarnation() {
            return Err(DeletionError::WrongScope);
        }
        let PreparationOutcome::Prepared { intent, .. } =
            deletion::prepare_delete(&mut current.state, pool, &envelope)
                .map_err(DeletionError::Deletion)?
        else {
            return Err(DeletionError::ReadbackMismatch);
        };
        intent
    };
    outcome.revision = intent.tombstone.deletion_revision;
    outcome.affected_slot = Some(intent.slot);
    outcome.cleanup_required = true;
    cancel(outcome.scope);
    if authenticated_directory.pending_deletion.is_none() {
        let committed = journal
            .transact_successor(flash, rng, &current.token, &current.state, work)
            .map_err(DeletionError::Journal)?;
        drop(current);
        let readback = journal
            .recover(flash, rng, work)
            .map_err(DeletionError::Journal)?;
        if readback.token != committed || readback.state.pending_deletion != Some(intent) {
            return Err(DeletionError::ReadbackMismatch);
        }
        outcome.committed_write = true;
    }
    Ok(outcome)
}
