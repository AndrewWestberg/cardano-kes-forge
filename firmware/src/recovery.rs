//! Boot-wide authenticated directory, pool journal, and public-object recovery.
//! No request service may start until `recover_boot` returns.

use kes_core::{
    deletion, enrollment,
    journal::{
        DirectoryCodec, Flash, Journal, JournalContext, JournalError, JournalScope, PoolCodec,
        ReadyToken, Workspaces,
    },
    retirement,
    state::{Device, DirectorySnapshot, StateError},
    types::{DeviceId, HardwareSlot},
};
use rand_chacha::rand_core::TryCryptoRng;

use crate::storage::{
    FittedFlash, POOL_COUNT, StorageError, directory_layout, pool_layout, pool_partition,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryError {
    Storage(StorageError),
    DirectoryJournal(JournalError),
    DirectoryState(StateError),
    Deletion(deletion::Error),
    Enrollment(enrollment::Error),
    Retirement(retirement::Error),
    WrongDevice,
}

impl From<StorageError> for RecoveryError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

/// Authenticated hot directory plus slot eligibility. A set bit in
/// `quarantined_slots` prevents that slot from serving requests until an
/// attended repair or deletion transaction resolves it.
pub struct BootState {
    pub device: Device,
    pub directory_token: ReadyToken,
    pub ready_slots: u32,
    pub quarantined_slots: u32,
}

impl BootState {
    pub fn slot_ready(&self, slot: HardwareSlot) -> bool {
        self.ready_slots & slot_bit(slot) != 0
    }

    pub fn slot_quarantined(&self, slot: HardwareSlot) -> bool {
        self.quarantined_slots & slot_bit(slot) != 0
    }
}

/// Recovers the authoritative directory first, finishes every referenced pool's
/// predecessor/CLEAN and public-orphan cleanup, then checks every unreferenced
/// slot is blank. Pool damage is isolated in `quarantined_slots`; directory
/// damage fails the entire boot because no pool identity can then be trusted.
pub fn recover_boot(
    flash: &mut FittedFlash<'_>,
    rng: &mut impl TryCryptoRng,
    storage_root: &[u8; 32],
    expected_device: DeviceId,
    work: &mut Workspaces<'_>,
) -> Result<BootState, RecoveryError> {
    // An authenticated enrollment intent must be reconciled before scanning
    // live and unused slots. Its flash view is pinned to one pool for the
    // entire transaction and never exposes firmware or identity partitions.
    let enrollment = enrollment::EnrollmentStorage::new(
        expected_device,
        directory_layout()
            .and_then(|layout| layout.bank_offset(0))
            .map_err(RecoveryError::DirectoryJournal)?,
        pool_layout(HardwareSlot::new(0).expect("slot zero"))
            .and_then(|layout| layout.bank_offset(0))
            .map_err(RecoveryError::DirectoryJournal)?,
        storage_root,
    )
    .map_err(RecoveryError::Enrollment)?;
    let recovered_directory = {
        let mut region = flash.enrollment()?;
        enrollment
            .recover_pending(&mut region, rng, work)
            .map_err(RecoveryError::Enrollment)?
    };
    let mut directory_state = recovered_directory.state;
    let mut directory_token = recovered_directory.token;
    if directory_state.config.identity.device_id() != &expected_device {
        return Err(RecoveryError::WrongDevice);
    }

    if directory_state.pending_deletion.is_some() {
        let completed = complete_pending_deletion(flash, rng, storage_root, expected_device, work)?;
        directory_state = completed.state;
        directory_token = completed.token;
    }
    if directory_state.retirement.is_some() {
        let completed = complete_retirement(flash, rng, storage_root, expected_device, work)?;
        directory_state = completed.state;
        directory_token = completed.token;
    }
    let device = Device::from_authenticated_snapshot(&directory_state)
        .map_err(RecoveryError::DirectoryState)?;
    let mut live = [None; POOL_COUNT];
    for entry in directory_state.live.iter().flatten().copied() {
        let index = entry.slot().get();
        if live[index].replace(entry).is_some() {
            return Err(RecoveryError::DirectoryState(StateError::DuplicatePool));
        }
    }

    let mut ready_slots = 0u32;
    let mut quarantined_slots = 0u32;
    for (index, expected) in live.into_iter().enumerate() {
        let slot = HardwareSlot::new(index).expect("bounded firmware slot index");
        let bit = slot_bit(slot);
        let mut region = flash.pool(slot)?;
        let Some(expected) = expected else {
            if !region_is_blank(&mut region, slot)? {
                quarantined_slots |= bit;
            }
            continue;
        };
        let journal = match Journal::<PoolCodec>::new(
            JournalContext {
                device: expected_device,
                scope: JournalScope::Pool {
                    slot,
                    pool: expected.pool_id(),
                    incarnation: expected.incarnation(),
                },
            },
            pool_layout(slot).map_err(RecoveryError::DirectoryJournal)?,
            storage_root,
        ) {
            Ok(journal) => journal,
            Err(_) => {
                quarantined_slots |= bit;
                continue;
            }
        };
        // A RAM-only cooperative job cannot survive reset. Reclaim any
        // unpublished object before recording authoritative NOT_COMMITTED.
        match kes_core::activation::DurablePool::recover_generation(
            &journal,
            &mut region,
            rng,
            work,
        ) {
            Ok(recovered)
                if recovered.state().is_ok_and(|state| {
                    state.pool_id() == expected.pool_id()
                        && state.incarnation() == expected.incarnation()
                }) =>
            {
                ready_slots |= bit;
            }
            Ok(_) | Err(_) => quarantined_slots |= bit,
        }
    }

    Ok(BootState {
        device,
        directory_token,
        ready_slots,
        quarantined_slots,
    })
}

/// Finish one authenticated pool deletion without recovering unrelated pools.
/// This is safe while another pool owns an in-progress cooperative job.
pub fn complete_pending_deletion(
    flash: &mut FittedFlash<'_>,
    rng: &mut impl TryCryptoRng,
    storage_root: &[u8; 32],
    expected_device: DeviceId,
    work: &mut Workspaces<'_>,
) -> Result<kes_core::journal::Recovered<DirectorySnapshot>, RecoveryError> {
    let directory = Journal::<DirectoryCodec>::new(
        JournalContext {
            device: expected_device,
            scope: JournalScope::Directory,
        },
        directory_layout().map_err(RecoveryError::DirectoryJournal)?,
        storage_root,
    )
    .map_err(RecoveryError::DirectoryJournal)?;
    let recovered = {
        let mut region = flash.directory()?;
        directory
            .recover(&mut region, rng, work)
            .map_err(RecoveryError::DirectoryJournal)?
    };
    let mut state = recovered.state;
    if state.config.identity.device_id() != &expected_device {
        return Err(RecoveryError::WrongDevice);
    }
    Device::from_authenticated_snapshot(&state).map_err(RecoveryError::DirectoryState)?;
    let intent = state.pending_deletion.ok_or(RecoveryError::Deletion(
        deletion::Error::InconsistentPoolState,
    ))?;
    let slot = intent.slot;
    {
        let mut region = flash.pool(slot)?;
        if let Ok(journal) = Journal::<PoolCodec>::new(
            JournalContext {
                device: expected_device,
                scope: JournalScope::Pool {
                    slot,
                    pool: intent.tombstone.pool_id,
                    incarnation: intent.tombstone.last_incarnation,
                },
            },
            pool_layout(slot).map_err(RecoveryError::DirectoryJournal)?,
            storage_root,
        ) && let Ok(mut pool) = journal.recover(&mut region, rng, work)
            && pool.state.pool_id() == intent.tombstone.pool_id
            && pool.state.incarnation() == intent.tombstone.last_incarnation
            && deletion::cleanup_pending_pool(&state, &mut pool.state) == Ok(true)
        {
            // Erasing the entire slot is the final barrier even if this
            // intermediate secret-cleanup transaction was interrupted.
            let _ = journal.transact_successor(&mut region, rng, &pool.token, &pool.state, work);
        }
        erase_pool_region(&mut region, slot)?;
    }
    deletion::finish_delete_after_erasure(&mut state, slot).map_err(RecoveryError::Deletion)?;
    let token = {
        let mut region = flash.directory()?;
        directory
            .transact_successor(&mut region, rng, &recovered.token, &state, work)
            .map_err(RecoveryError::DirectoryJournal)?
    };
    Ok(kes_core::journal::Recovered { state, token })
}

/// Resume only an authenticated, durably committed global deny marker.
///
/// Drop any prior cold directory candidate before calling: recovery owns the
/// sole authenticated directory workspace. Success proves every physical pool
/// partition is blank, not just the absence of directory references. Public
/// replay success is forbidden before this barrier. A RAM-only preparation is
/// never authority: this function loads the marker from the actual journal.
pub fn complete_retirement(
    flash: &mut FittedFlash<'_>,
    rng: &mut impl TryCryptoRng,
    storage_root: &[u8; 32],
    expected_device: DeviceId,
    work: &mut Workspaces<'_>,
) -> Result<kes_core::journal::Recovered<DirectorySnapshot>, RecoveryError> {
    let directory = Journal::<DirectoryCodec>::new(
        JournalContext {
            device: expected_device,
            scope: JournalScope::Directory,
        },
        directory_layout().map_err(RecoveryError::DirectoryJournal)?,
        storage_root,
    )
    .map_err(RecoveryError::DirectoryJournal)?;
    // Authenticate the actual durable marker before ANY physical erasure. A
    // caller-held RAM candidate is not authority to destroy live pool state.
    let recovered = {
        let mut region = flash.directory()?;
        directory
            .recover(&mut region, rng, work)
            .map_err(RecoveryError::DirectoryJournal)?
    };
    let mut directory_state = recovered.state;
    let mut directory_token = recovered.token;
    if directory_state.config.identity.device_id() != &expected_device {
        return Err(RecoveryError::WrongDevice);
    }
    Device::from_authenticated_snapshot(&directory_state).map_err(RecoveryError::DirectoryState)?;
    if directory_state.retirement.is_none() || directory_state.pending_deletion.is_some() {
        return Err(RecoveryError::Retirement(retirement::Error::NotPrepared));
    }
    for index in 0..POOL_COUNT {
        let slot = HardwareSlot::new(index).expect("bounded firmware slot index");
        if let Some(entry) = directory_state
            .live
            .iter()
            .flatten()
            .find(|entry| entry.slot() == slot)
            .copied()
        {
            let pool_journal = Journal::<PoolCodec>::new(
                JournalContext {
                    device: expected_device,
                    scope: JournalScope::Pool {
                        slot,
                        pool: entry.pool_id(),
                        incarnation: entry.incarnation(),
                    },
                },
                pool_layout(slot).map_err(RecoveryError::DirectoryJournal)?,
                storage_root,
            )
            .map_err(RecoveryError::DirectoryJournal)?;
            {
                let mut region = flash.pool(slot)?;
                // A damaged/missing referenced pool cannot be treated as a
                // blank orphan: its retained high-water history is unknown.
                let recovered = pool_journal
                    .recover(&mut region, rng, work)
                    .map_err(RecoveryError::DirectoryJournal)?;
                retirement::remove_pool(&mut directory_state, slot, &recovered.state)
                    .map_err(RecoveryError::Retirement)?;
            }
            let mut region = flash.directory()?;
            directory_token = directory
                .transact_successor(&mut region, rng, &directory_token, &directory_state, work)
                .map_err(RecoveryError::DirectoryJournal)?;
        }
        let mut region = flash.pool(slot)?;
        erase_pool_region(&mut region, slot)?;
    }
    Ok(kes_core::journal::Recovered {
        state: directory_state,
        token: directory_token,
    })
}

pub(crate) fn erase_pool_region(
    flash: &mut impl Flash<Error = StorageError>,
    slot: HardwareSlot,
) -> Result<(), RecoveryError> {
    flash.invalidate_cache().map_err(RecoveryError::Storage)?;
    let partition = pool_partition(slot);
    for offset in (partition.offset()..partition.end()).step_by(4096) {
        let mut page = [0; 256];
        let mut blank = true;
        for page_offset in (offset..offset + 4096).step_by(page.len()) {
            flash
                .read(page_offset as u32, &mut page)
                .map_err(RecoveryError::Storage)?;
            blank &= page.iter().all(|byte| *byte == 0xff);
        }
        if !blank {
            flash
                .erase_sector(offset as u32)
                .map_err(RecoveryError::Storage)?;
            flash.invalidate_cache().map_err(RecoveryError::Storage)?;
            for page_offset in (offset..offset + 4096).step_by(page.len()) {
                flash
                    .read(page_offset as u32, &mut page)
                    .map_err(RecoveryError::Storage)?;
                if page.iter().any(|byte| *byte != 0xff) {
                    return Err(RecoveryError::DirectoryJournal(JournalError::Damaged));
                }
            }
        }
    }
    flash.invalidate_cache().map_err(RecoveryError::Storage)
}

fn region_is_blank(
    flash: &mut impl Flash<Error = StorageError>,
    slot: HardwareSlot,
) -> Result<bool, RecoveryError> {
    let partition = pool_partition(slot);
    let mut page = [0; 256];
    for offset in (partition.offset()..partition.end()).step_by(page.len()) {
        flash
            .read(offset as u32, &mut page)
            .map_err(RecoveryError::Storage)?;
        if page.iter().any(|byte| *byte != 0xff) {
            return Ok(false);
        }
    }
    Ok(true)
}

const fn slot_bit(slot: HardwareSlot) -> u32 {
    1u32 << slot.get()
}
