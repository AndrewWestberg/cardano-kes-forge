//! Boot-wide authenticated directory, pool journal, and public-object recovery.
//! No request service may start until `recover_boot` returns.

use kes_core::{
    deletion,
    journal::{
        DirectoryCodec, Flash, Journal, JournalContext, JournalError, JournalScope, PoolCodec,
        ReadyToken, Workspaces,
    },
    state::{Device, StateError},
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
    let directory = Journal::<DirectoryCodec>::new(
        JournalContext {
            device: expected_device,
            scope: JournalScope::Directory,
        },
        directory_layout().map_err(RecoveryError::DirectoryJournal)?,
        storage_root,
    )
    .map_err(RecoveryError::DirectoryJournal)?;
    let recovered_directory = {
        let mut region = flash.directory()?;
        directory
            .recover(&mut region, rng, work)
            .map_err(RecoveryError::DirectoryJournal)?
    };
    let mut directory_state = recovered_directory.state;
    let mut directory_token = recovered_directory.token;
    if directory_state.config.identity.device_id() != &expected_device {
        return Err(RecoveryError::WrongDevice);
    }

    if let Some(intent) = directory_state.pending_deletion {
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
            ) && let Ok(mut recovered) = journal.recover(&mut region, rng, work)
                && recovered.state.pool_id() == intent.tombstone.pool_id
                && recovered.state.incarnation() == intent.tombstone.last_incarnation
                && deletion::cleanup_pending_pool(&directory_state, &mut recovered.state)
                    == Ok(true)
            {
                let _ = journal.transact_successor(
                    &mut region,
                    rng,
                    &recovered.token,
                    &recovered.state,
                    work,
                );
            }
            erase_pool_region(&mut region, slot)?;
        }
        deletion::finish_delete_after_erasure(&mut directory_state, slot)
            .map_err(RecoveryError::Deletion)?;
        directory_token = {
            let mut region = flash.directory()?;
            directory
                .transact_successor(&mut region, rng, &directory_token, &directory_state, work)
                .map_err(RecoveryError::DirectoryJournal)?
        };
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
        match journal.recover(&mut region, rng, work) {
            Ok(recovered)
                if recovered.state.pool_id() == expected.pool_id()
                    && recovered.state.incarnation() == expected.incarnation() =>
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

fn erase_pool_region(
    flash: &mut impl Flash<Error = StorageError>,
    slot: HardwareSlot,
) -> Result<(), RecoveryError> {
    let partition = pool_partition(slot);
    for offset in (partition.offset()..partition.end()).step_by(4096) {
        flash
            .erase_sector(offset as u32)
            .map_err(RecoveryError::Storage)?;
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
