//! Offline-authorized device transport credential changes for disposable A2.
//!
//! This is not device retirement or pool deletion. The caller MUST authenticate
//! the MANAGE request in Scope::Management against `authenticated_directory`
//! before calling, serialize directory access, and MAC/encode the ACK using the
//! old session before invalidating management sessions on a credential change.
//! No sessions, OTP, provisioning, pool journals or automatic resets live here.

use kes_core::{
    credentials::{self, CredentialOutcome},
    journal::{DirectoryCodec, Flash, Journal, JournalError, Workspaces},
    management::{self, Action, Target},
    state::DirectorySnapshot,
    types::{ManagementSequence, Revision},
};
use kes_protocol::{Envelope, Operation};
use rand_chacha::rand_core::TryCryptoRng;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceManagementError {
    WrongRequest,
    Authorization(management::Error),
    Credential(credentials::Error),
    Journal(JournalError),
    StaleAuthority,
    PendingOperation,
    ReadbackMismatch,
}

/// The recorded operation revision may precede the current directory revision
/// after unrelated directory work or interrupted-commit recovery. Exact retries
/// return that recorded result, without another credential transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceManagementOutcome {
    pub revision: Revision,
    pub sequence: ManagementSequence,
    pub committed_write: bool,
    pub epoch_changed: bool,
    pub revocation_changed: bool,
}

/// Execute an already session-authenticated device CREDENTIAL_REPLACE/REVOKE.
///
/// `journal` and `flash` must be the directory-scoped pair used to authenticate
/// `authenticated_directory`. Fresh authenticated recovery prevents stale RAM
/// from authorizing even a no-write retry. Recovery may finish an interrupted
/// journal transaction but never provisions or reconciles pending operations.
/// On any error, do not ACK success: the commit may already be durable, so
/// recover authority before retrying. Replacement can recover a revoked device
/// credential only if a separately authorized transport reaches this backend;
/// this function does not create a transport bypass.
#[allow(clippy::too_many_arguments)]
pub fn execute<F: Flash, R: TryCryptoRng>(
    request: Envelope<'_>,
    authenticated_directory: &DirectorySnapshot,
    journal: &Journal<DirectoryCodec>,
    flash: &mut F,
    rng: &mut R,
    work: &mut Workspaces<'_>,
) -> Result<DeviceManagementOutcome, DeviceManagementError> {
    if request.operation != Operation::Manage
        || !request.map().required("pool").is_ok_and(|v| v.is_null())
        || !request
            .map()
            .required("incarnation")
            .is_ok_and(|v| v.is_null())
        || !request
            .map()
            .required("device")
            .and_then(|v| v.bytes())
            .is_ok_and(|v| {
                v == authenticated_directory
                    .config
                    .identity
                    .device_id()
                    .as_bytes()
            })
    {
        return Err(DeviceManagementError::WrongRequest);
    }
    let mut current = journal
        .recover(flash, rng, work)
        .map_err(DeviceManagementError::Journal)?;
    if &current.state != authenticated_directory {
        return Err(DeviceManagementError::StaleAuthority);
    }
    if current.state.pending_enrollment.is_some()
        || current.state.pending_deletion.is_some()
        || current.state.retirement.is_some()
    {
        return Err(DeviceManagementError::PendingOperation);
    }
    let verified = management::parse_and_verify(
        request.payload().encoded(),
        *current.state.config.identity.device_id(),
        &current.state.config.management_root_public_key,
    )
    .map_err(DeviceManagementError::Authorization)?;
    if verified.fields().target != Target::Device
        || !matches!(
            verified.fields().action,
            Action::CredentialReplace | Action::CredentialRevoke
        )
    {
        return Err(DeviceManagementError::WrongRequest);
    }
    let before = current.state.credential;
    let transition = credentials::change_device_credential(&mut current.state, &verified)
        .map_err(DeviceManagementError::Credential)?;
    let revision = match transition {
        CredentialOutcome::AlreadyCommitted { revision } => {
            return Ok(DeviceManagementOutcome {
                revision,
                sequence: verified.fields().sequence,
                committed_write: false,
                epoch_changed: false,
                revocation_changed: false,
            });
        }
        CredentialOutcome::Applied { revision, .. } => revision,
    };
    let committed = journal
        .transact_successor(flash, rng, &current.token, &current.state, work)
        .map_err(DeviceManagementError::Journal)?;
    let expected_credential = current.state.credential;
    let _ = current;
    // CLEAN and old-bank erasure have completed. Authenticate the stored state
    // again rather than returning an acknowledgement from the RAM successor.
    let readback = journal
        .recover(flash, rng, work)
        .map_err(DeviceManagementError::Journal)?;
    if readback.token != committed || readback.state.credential != expected_credential {
        return Err(DeviceManagementError::ReadbackMismatch);
    }
    Ok(DeviceManagementOutcome {
        revision,
        sequence: verified.fields().sequence,
        committed_write: true,
        epoch_changed: before.epoch != readback.state.credential.epoch,
        revocation_changed: before.revoked != readback.state.credential.revoked,
    })
}
