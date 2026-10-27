//! Offline-authorized pool policy changes for disposable development hardware.
//! No initialization, reset, OTP mutation, or transport authentication lives here.
use kes_core::{
    activation::DurablePool,
    generation::{PoolManagementError, PoolManagementOutcome},
    journal::{Flash, Journal, PoolCodec, Workspaces},
    management::{self, Action, Target},
    session::Scope,
    state::DirectorySnapshot,
    types::{GenerationId, HardwareSlot},
};
use rand_chacha::rand_core::TryCryptoRng;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagementError {
    Signature(management::Error),
    WrongScope,
    PendingDirectoryOperation,
    Policy(PoolManagementError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagementOutcome {
    pub durable: PoolManagementOutcome,
    pub scope: Scope,
    /// Invalidate this pool's sessions AFTER authenticating the management ACK.
    /// True on exact credential retry as well: old sessions must not survive.
    pub invalidate_pool_sessions: bool,
}

/// Execute CREDENTIAL_REPLACE/REVOKE, RECIPIENT_REPLACE, or STAGED_DISCARD.
///
/// The parent MUST authenticate the enclosing management session against the
/// freshly recovered directory credential before calling. `directory` must be
/// freshly authenticated and `pool` recovered from its matching live entry and
/// slot-scoped journal; `slot` is that physical slot, never a wire-selected one.
/// The offline root is taken ONLY from this directory, not caller wire data.
/// No directory or other pool state is modified. Existing immutable generation
/// artifacts survive credential/recipient changes byte-for-byte; after staged
/// discard, the next authenticated recovery reclaims its unreferenced object.
///
/// Before calling, the parent must reconcile the sole live owned generation job
/// with this pool's checkpoint. `cancel` synchronously takes/drops that job and
/// retires its scheduler lease. It runs only after signature, target, replay,
/// revision, epoch and payload validation, and only for an applied policy change.
/// A successful result means journal CLEAN plus authenticated readback (or an
/// authenticated exact no-write replay). On persistence error the owner is
/// invalid; recover it before any use and never encode SUCCESS. Keep the
/// management session alive to MAC the response, then invalidate pool sessions
/// when requested by the outcome.
#[allow(clippy::too_many_arguments)]
pub fn execute<F: Flash, R: TryCryptoRng>(
    encoded: &[u8],
    directory: &DirectorySnapshot,
    slot: HardwareSlot,
    pool: &mut DurablePool,
    journal: &Journal<PoolCodec>,
    flash: &mut F,
    rng: &mut R,
    work: &mut Workspaces<'_>,
    cancel: impl FnOnce(GenerationId),
) -> Result<ManagementOutcome, ManagementError> {
    if directory.pending_enrollment.is_some()
        || directory.pending_deletion.is_some()
        || directory.retirement.is_some()
    {
        return Err(ManagementError::PendingDirectoryOperation);
    }
    let envelope = management::parse_and_verify(
        encoded,
        *directory.config.identity.device_id(),
        &directory.config.management_root_public_key,
    )
    .map_err(ManagementError::Signature)?;
    let Target::Pool {
        pool: pool_id,
        incarnation,
    } = envelope.fields().target
    else {
        return Err(ManagementError::WrongScope);
    };
    let entry = directory
        .live
        .iter()
        .flatten()
        .find(|entry| {
            entry.pool_id() == pool_id && entry.incarnation() == incarnation && entry.slot() == slot
        })
        .ok_or(ManagementError::WrongScope)?;
    let state = pool
        .state()
        .map_err(|error| ManagementError::Policy(PoolManagementError::Operation(error)))?;
    if state.pool_id() != entry.pool_id() || state.incarnation() != entry.incarnation() {
        return Err(ManagementError::WrongScope);
    }
    let invalidate_pool_sessions = matches!(
        envelope.fields().action,
        Action::CredentialReplace | Action::CredentialRevoke
    );
    let durable = pool
        .manage_pool_policy(&envelope, journal, flash, rng, work, cancel)
        .map_err(ManagementError::Policy)?;
    Ok(ManagementOutcome {
        durable,
        scope: Scope::Pool {
            pool: pool_id,
            incarnation,
        },
        invalidate_pool_sessions,
    })
}
