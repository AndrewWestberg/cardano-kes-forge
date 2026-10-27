//! Authenticated enrollment transaction. A directory intent reserves an erased
//! slot before any pool write. Only that never-live slot may be reconstructed
//! after an interrupted initialization; live or unreserved damaged slots are
//! never reset. Call `recover_pending` at boot before serving pool operations.
use crate::journal::{
    DirectoryCodec, Flash, Journal, JournalContext, JournalError, JournalLayout, JournalScope,
    PoolCodec, Recovered, Workspaces,
};
use crate::management::{self, Action, Target};
use crate::state::{
    Actor, Device, DirectoryEntry, DirectorySnapshot, EnrollmentIntent, PoolRegistration,
    StateError,
};
use crate::types::{DeviceId, HardwareSlot, Revision};
use rand_chacha::rand_core::TryCryptoRng;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Journal(JournalError),
    Authorization,
    ChangedReplay,
    SlotNotErased,
    PendingOperation,
    InconsistentState,
    State(StateError),
}
impl From<JournalError> for Error {
    fn from(e: JournalError) -> Self {
        Self::Journal(e)
    }
}
impl From<StateError> for Error {
    fn from(e: StateError) -> Self {
        Self::State(e)
    }
}

/// Stable enrollment acknowledgement, independent of journal recovery replicas.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Acknowledgement {
    pub slot: HardwareSlot,
    pub pool_revision: Revision,
}

/// Fixed, non-overlapping directory and contiguous 32-KiB pool-slot regions.
/// The root is borrowed, never copied or persisted by this owner.
pub struct EnrollmentStorage<'a> {
    device: DeviceId,
    directory: Journal<DirectoryCodec>,
    pool_base: u32,
    root: &'a [u8; 32],
}
impl<'a> EnrollmentStorage<'a> {
    pub fn new(
        device: DeviceId,
        directory_base: u32,
        pool_base: u32,
        root: &'a [u8; 32],
    ) -> Result<Self, Error> {
        let directory_end = directory_base
            .checked_add(16384)
            .ok_or(JournalError::SizeLimit)?;
        let pool_end = pool_base
            .checked_add(crate::MAX_POOLS as u32 * 32768)
            .ok_or(JournalError::SizeLimit)?;
        if directory_base < pool_end && pool_base < directory_end {
            return Err(JournalError::InvalidContext.into());
        }
        JournalLayout::pool(pool_base)?;
        let directory = Journal::new(
            JournalContext {
                device,
                scope: JournalScope::Directory,
            },
            JournalLayout::directory(directory_base)?,
            root,
        )?;
        Ok(Self {
            device,
            directory,
            pool_base,
            root,
        })
    }
    fn base(&self, slot: HardwareSlot) -> u32 {
        self.pool_base + slot.get() as u32 * 32768
    }
    fn pool(
        &self,
        slot: HardwareSlot,
        pool: &PoolRegistration,
    ) -> Result<Journal<PoolCodec>, Error> {
        Ok(Journal::new(
            JournalContext {
                device: self.device,
                scope: JournalScope::Pool {
                    slot,
                    pool: pool.pool_id(),
                    incarnation: pool.incarnation(),
                },
            },
            JournalLayout::pool(self.base(slot))?,
            self.root,
        )?)
    }
    fn blank(&self, flash: &mut impl Flash, slot: HardwareSlot) -> Result<bool, Error> {
        flash.invalidate_cache().map_err(|_| JournalError::Flash)?;
        let mut page = [0; 256];
        for offset in (0..32768).step_by(256) {
            flash
                .read(self.base(slot) + offset, &mut page)
                .map_err(|_| JournalError::Flash)?;
            if page.iter().any(|b| *b != 255) {
                return Ok(false);
            }
        }
        Ok(true)
    }
    fn registration(
        directory: &DirectorySnapshot,
        intent: EnrollmentIntent,
    ) -> Result<PoolRegistration, Error> {
        let mut pool = PoolRegistration::new(Actor::Management, intent.enrollment)?;
        if let Some(t) = directory
            .tombstones
            .iter()
            .flatten()
            .find(|t| t.pool_id == pool.pool_id())
        {
            pool.merge_retained_history(t.generation_high_water, t.certificate_high_water);
        }
        Ok(pool)
    }
    /// Recover authenticated directory authority and finish any enrollment. No
    /// request or fresh management authorization is needed after intent COMMIT.
    /// Returned directory has no pending enrollment and is cleanup-complete.
    pub fn recover_pending(
        &self,
        flash: &mut impl Flash,
        rng: &mut impl TryCryptoRng,
        work: &mut Workspaces<'_>,
    ) -> Result<Recovered<DirectorySnapshot>, Error> {
        let mut directory = self.directory.recover(flash, rng, work)?;
        self.finish_pending(&mut directory, flash, rng, work)?;
        Ok(directory)
    }
    fn finish_pending(
        &self,
        directory: &mut Recovered<DirectorySnapshot>,
        flash: &mut impl Flash,
        rng: &mut impl TryCryptoRng,
        work: &mut Workspaces<'_>,
    ) -> Result<(), Error> {
        let Some(intent) = directory.state.pending_enrollment else {
            return Ok(());
        };
        Device::from_authenticated_snapshot(&directory.state)?;
        let pool = Self::registration(&directory.state, intent)?;
        let journal = self.pool(intent.slot, &pool)?;
        match journal.recover(flash, rng, work) {
            Ok(recovered) => {
                if recovered.state.management_replay() != pool.management_replay()
                    || recovered.state.generation_high_water() != pool.generation_high_water()
                    || recovered.state.certificate_high_water() != pool.certificate_high_water()
                    || recovered.state.cold_verification_key() != pool.cold_verification_key()
                    || recovered.state.network() != pool.network()
                    || recovered.state.credential_public_key() != pool.credential_public_key()
                    || recovered.state.credential_epoch() != pool.credential_epoch()
                    || recovered.state.credential_revoked()
                    || recovered.state.recipient_public_key() != pool.recipient_public_key()
                    || recovered.state.recipient_id() != pool.recipient_id()
                    || recovered.state.recipient_policy_epoch() != pool.recipient_policy_epoch()
                    || recovered.state.current().is_some()
                    || recovered.state.staged().is_some()
                    || recovered.state.generation_checkpoint().is_some()
                {
                    return Err(Error::InconsistentState);
                }
            }
            Err(
                JournalError::Uninitialized | JournalError::NotCommitted | JournalError::Damaged,
            ) => {
                // The authenticated intent was committed only after a complete
                // erased-region check. This slot has never been published and
                // may contain only this reconstructable, keyless enrollment.
                // Never apply this rule to an unreserved or live slot.
                for offset in (0..32768).step_by(4096) {
                    flash
                        .erase_sector(self.base(intent.slot) + offset)
                        .map_err(|_| JournalError::Flash)?;
                }
                if !self.blank(flash, intent.slot)? {
                    return Err(Error::SlotNotErased);
                }
                journal.initialize(flash, rng, &pool, work)?;
            }
            Err(error) => return Err(error.into()),
        }
        // Re-read, authenticate and reclaim before publishing the live entry.
        drop(journal.recover(flash, rng, work)?);
        let index = directory
            .state
            .live
            .iter()
            .position(Option::is_none)
            .ok_or(StateError::Capacity)?;
        directory.state.live[index] = Some(DirectoryEntry::new(
            intent.slot,
            pool.pool_id(),
            pool.incarnation(),
        ));
        for t in &mut directory.state.tombstones {
            if t.is_some_and(|t| t.pool_id == pool.pool_id()) {
                *t = None;
            }
        }
        directory.state.pending_enrollment = None;
        directory.state.revision = directory
            .state
            .revision
            .checked_increment()
            .map_err(|_| StateError::CounterOverflow)?;
        directory.token = self.directory.transact_successor(
            flash,
            rng,
            &directory.token,
            &directory.state,
            work,
        )?;
        Ok(())
    }
    /// Execute or exactly replay a verified ENROLL. All input authorization is
    /// rebound to the authenticated directory root. Errors are uncertain outcomes:
    /// discard cached state and call this again or `recover_pending`; never ACK.
    pub fn enroll(
        &self,
        encoded: &[u8],
        flash: &mut impl Flash,
        rng: &mut impl TryCryptoRng,
        work: &mut Workspaces<'_>,
    ) -> Result<Acknowledgement, Error> {
        let mut directory = self.directory.recover(flash, rng, work)?;
        let envelope = management::parse_and_verify(
            encoded,
            self.device,
            &directory.state.config.management_root_public_key,
        )
        .map_err(|_| Error::Authorization)?;
        let fields = envelope.fields();
        if fields.action != Action::Enroll || fields.device != self.device {
            return Err(Error::Authorization);
        }
        match directory.state.config.health {
            crate::state::Health::Healthy => {}
            crate::state::Health::Damaged => return Err(StateError::Damaged.into()),
            crate::state::Health::Unavailable => return Err(StateError::Unavailable.into()),
        }
        let Target::Pool {
            pool: target,
            incarnation,
        } = fields.target
        else {
            return Err(Error::Authorization);
        };
        if let Some(intent) = directory.state.pending_enrollment {
            let requested = envelope.enrollment().map_err(|_| Error::Authorization)?;
            if requested != intent.enrollment {
                return Err(Error::PendingOperation);
            }
            self.finish_pending(&mut directory, flash, rng, work)?;
        }
        if let Some(entry) = directory
            .state
            .live
            .iter()
            .flatten()
            .find(|e| e.pool_id() == target)
        {
            if entry.incarnation() != incarnation {
                return Err(Error::ChangedReplay);
            }
            let candidate = PoolRegistration::new(
                Actor::Management,
                envelope.enrollment().map_err(|_| Error::Authorization)?,
            )?;
            let recovered = self
                .pool(entry.slot(), &candidate)?
                .recover(flash, rng, work)?;
            if recovered.state.management_replay() != candidate.management_replay() {
                return Err(Error::ChangedReplay);
            }
            return Ok(Acknowledgement {
                slot: entry.slot(),
                pool_revision: Revision::new(0),
            });
        }
        if directory.state.pending_deletion.is_some() || directory.state.retirement.is_some() {
            return Err(Error::PendingOperation);
        }
        if fields.expected_revision != directory.state.revision {
            return Err(StateError::RevisionConflict.into());
        }
        let enrollment = envelope.enrollment().map_err(|_| Error::Authorization)?;
        let candidate = PoolRegistration::new(Actor::Management, enrollment)?;
        let mut device = Device::from_authenticated_snapshot(&directory.state)?;
        let slot = if directory
            .state
            .tombstones
            .iter()
            .flatten()
            .any(|t| t.pool_id == target)
        {
            let t = directory
                .state
                .tombstones
                .iter()
                .flatten()
                .find(|t| t.pool_id == target)
                .ok_or(Error::InconsistentState)?;
            if t.last_incarnation == incarnation
                || t.management_sequence.checked_increment().ok() != Some(fields.sequence)
            {
                return Err(Error::ChangedReplay);
            }
            HardwareSlot::new(
                (0..crate::MAX_POOLS)
                    .find(|i| {
                        !directory
                            .state
                            .live
                            .iter()
                            .flatten()
                            .any(|e| e.slot().get() == *i)
                    })
                    .ok_or(StateError::Capacity)?,
            )
            .map_err(|_| StateError::Capacity)?
        } else {
            if fields.sequence != crate::types::ManagementSequence::new(1) {
                return Err(Error::ChangedReplay);
            }
            device.enroll(Actor::Management, &candidate, directory.state.revision)?
        };
        if !self.blank(flash, slot)? {
            return Err(Error::SlotNotErased);
        }
        directory.state.pending_enrollment = Some(EnrollmentIntent { slot, enrollment });
        directory.state.revision = directory
            .state
            .revision
            .checked_increment()
            .map_err(|_| StateError::CounterOverflow)?;
        directory.token = self.directory.transact_successor(
            flash,
            rng,
            &directory.token,
            &directory.state,
            work,
        )?;
        self.finish_pending(&mut directory, flash, rng, work)?;
        Ok(Acknowledgement {
            slot,
            pool_revision: Revision::new(0),
        })
    }
}
