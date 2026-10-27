//! Signed, journal-owned device deny preparation, NOT retirement completion.
//!
//! The caller must first authenticate MANAGE in Scope::Management against the
//! supplied directory and serialize the directory-scoped journal/flash owner.
//! Every returned preparation, including exact retries, still requires scoped
//! `recovery::complete_retirement` and read-verified erasure of ALL pool regions
//! before a MAC-authenticated success ACK. No marker alone proves cleanup.

use kes_core::{
    journal::{DirectoryCodec, Flash, Journal, JournalError, Workspaces},
    management::{self, Action, Target},
    retirement::{self, Preparation},
    state::DirectorySnapshot,
    types::{ManagementSequence, Revision},
};
use kes_protocol::{Envelope, Operation};
use rand_chacha::rand_core::TryCryptoRng;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetirementError {
    WrongRequest,
    Authorization(management::Error),
    Retirement(retirement::Error),
    Journal(JournalError),
    StaleAuthority,
    ReadbackMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetirementFailure {
    pub error: RetirementError,
    /// Stop live work and invalidate sessions before servicing another request.
    /// Recovery may have published an interrupted transaction even when the
    /// requested operation could not be acknowledged.
    pub teardown_required: bool,
}

impl RetirementFailure {
    fn rejected(error: RetirementError) -> Self {
        Self {
            error,
            teardown_required: false,
        }
    }

    fn uncertain(error: RetirementError) -> Self {
        Self {
            error,
            teardown_required: true,
        }
    }
}

/// Evidence of a durable deny marker only. This is never an ACK result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetirementPreparation {
    pub revision: Revision,
    pub sequence: ManagementSequence,
    pub committed_write: bool,
}

/// Verify fresh authority and persist the global deny successor through CLEAN.
///
/// `cancel` must synchronously wipe the owned live job and invalidate pool
/// sessions. It runs only after all signed transition checks pass and directly
/// before publishing a new deny marker. Retain the authenticated management
/// session only as needed to MAC the eventual cleanup ACK. Exact retries do not
/// call `cancel` and do not imply that cleanup has completed. On an uncertain
/// failure the caller must also tear down live state, then recover authority;
/// it must never reset/provision as a fallback.
#[allow(clippy::too_many_arguments)]
pub fn prepare<F: Flash, R: TryCryptoRng>(
    request: Envelope<'_>,
    authenticated_directory: &DirectorySnapshot,
    journal: &Journal<DirectoryCodec>,
    flash: &mut F,
    rng: &mut R,
    work: &mut Workspaces<'_>,
    cancel: impl FnOnce(),
) -> Result<RetirementPreparation, RetirementFailure> {
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
        return Err(RetirementFailure::rejected(RetirementError::WrongRequest));
    }
    let mut current = journal
        .recover(flash, rng, work)
        .map_err(|e| RetirementFailure::uncertain(RetirementError::Journal(e)))?;
    if &current.state != authenticated_directory {
        // Fresh authenticated recovery may have completed a pending deny write.
        return Err(RetirementFailure {
            error: RetirementError::StaleAuthority,
            teardown_required: current.state.retirement.is_some(),
        });
    }
    let verified = management::parse_and_verify(
        request.payload().encoded(),
        *current.state.config.identity.device_id(),
        &current.state.config.management_root_public_key,
    )
    .map_err(|e| RetirementFailure::rejected(RetirementError::Authorization(e)))?;
    if verified.fields().target != Target::Device
        || verified.fields().action != Action::DeviceRetire
    {
        return Err(RetirementFailure::rejected(RetirementError::WrongRequest));
    }
    let transition = retirement::prepare(&mut current.state, &verified)
        .map_err(|e| RetirementFailure::rejected(RetirementError::Retirement(e)))?;
    let revision = match transition {
        Preparation::AlreadyPrepared { revision } => {
            return Ok(RetirementPreparation {
                revision,
                sequence: verified.fields().sequence,
                committed_write: false,
            });
        }
        Preparation::Prepared { revision } => revision,
    };
    cancel();
    let committed = journal
        .transact_successor(flash, rng, &current.token, &current.state, work)
        .map_err(|e| RetirementFailure::uncertain(RetirementError::Journal(e)))?;
    let readback = journal
        .recover(flash, rng, work)
        .map_err(|e| RetirementFailure::uncertain(RetirementError::Journal(e)))?;
    if readback.token != committed || readback.state != current.state {
        return Err(RetirementFailure::uncertain(
            RetirementError::ReadbackMismatch,
        ));
    }
    Ok(RetirementPreparation {
        revision,
        sequence: verified.fields().sequence,
        committed_write: true,
    })
}
