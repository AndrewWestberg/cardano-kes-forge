//! Fitted RP2350 flash layout and the only journal-facing flash adapter.
//!
//! Offsets are relative to the XIP flash device, not absolute XIP addresses.
//! The adapter deliberately exposes one directory or pool region at a time so a
//! malformed journal operation cannot cross into firmware or another pool.

use core::sync::atomic::{Ordering, compiler_fence};

use embassy_rp::{
    flash::{Blocking, ERASE_SIZE, Error as HalError, Flash as HalFlash, PAGE_SIZE},
    multicore::{CoreId, current_core},
    peripherals::FLASH,
};
use kes_core::{
    journal::{Flash as JournalFlash, FlashRules, JournalError, JournalLayout},
    types::HardwareSlot,
};

pub use crate::flash_identification::IdentificationError;

pub const FLASH_BYTES: usize = 4 * 1024 * 1024;
pub const BOOT_PARTITION_BYTES: usize = 64 * 1024;
pub const FIRMWARE_SLOT_BYTES: usize = 1024 * 1024;
pub const DIRECTORY_BYTES: usize = 16 * 1024;
pub const POOL_REGION_BYTES: usize = 32 * 1024;
pub const POOL_USED_BYTES: usize = 24 * 1024;
pub const POOL_RESERVED_BYTES: usize = POOL_REGION_BYTES - POOL_USED_BYTES;
pub const POOL_COUNT: usize = kes_core::MAX_POOLS;
pub const FLASH_RESERVATION_BYTES: usize = BOOT_PARTITION_BYTES
    + 2 * FIRMWARE_SLOT_BYTES
    + DIRECTORY_BYTES
    + POOL_COUNT * POOL_REGION_BYTES;
pub const SPARE_BYTES: usize = FLASH_BYTES - FLASH_RESERVATION_BYTES;

pub const PICO2_FLASH_MODEL: &str = "Winbond W25Q32RV";
pub const PICO2_FLASH_MIN_PROGRAM_ERASE_CYCLES: u32 = 100_000;
pub const PICO2_FLASH_JEDEC_ID: [u8; 3] = crate::flash_identification::APPROVED_JEDEC;

pub const BOOT_PARTITION: Partition = Partition::new(0, BOOT_PARTITION_BYTES);
pub const FIRMWARE_A: Partition = Partition::new(BOOT_PARTITION.end(), FIRMWARE_SLOT_BYTES);
pub const FIRMWARE_B: Partition = Partition::new(FIRMWARE_A.end(), FIRMWARE_SLOT_BYTES);
pub const DIRECTORY: Partition = Partition::new(FIRMWARE_B.end(), DIRECTORY_BYTES);
pub const POOLS: Partition = Partition::new(DIRECTORY.end(), POOL_COUNT * POOL_REGION_BYTES);
pub const SPARE: Partition = Partition::new(POOLS.end(), SPARE_BYTES);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Partition {
    offset: usize,
    length: usize,
}

impl Partition {
    pub const fn new(offset: usize, length: usize) -> Self {
        Self { offset, length }
    }

    pub const fn offset(self) -> usize {
        self.offset
    }

    pub const fn length(self) -> usize {
        self.length
    }

    pub const fn end(self) -> usize {
        self.offset + self.length
    }

    const fn contains(self, offset: usize, length: usize) -> bool {
        match offset.checked_add(length) {
            Some(end) => offset >= self.offset && end <= self.end(),
            None => false,
        }
    }
}

pub const fn pool_partition(slot: HardwareSlot) -> Partition {
    Partition::new(
        POOLS.offset() + slot.get() * POOL_REGION_BYTES,
        POOL_USED_BYTES,
    )
}

pub fn directory_layout() -> Result<JournalLayout, JournalError> {
    JournalLayout::directory(DIRECTORY.offset() as u32)
}

pub fn pool_layout(slot: HardwareSlot) -> Result<JournalLayout, JournalError> {
    JournalLayout::pool(pool_partition(slot).offset() as u32)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageError {
    WrongCore,
    WrongFlashProfile {
        jedec_id: [u8; 3],
        sfdp_header: [u8; 16],
        density_bits_minus_one: u32,
    },
    FlashIdentification(IdentificationError),
    OutOfRegion,
    Unaligned,
    Hal(HalError),
}

impl From<HalError> for StorageError {
    fn from(error: HalError) -> Self {
        Self::Hal(error)
    }
}

/// Sole owner of fitted flash mutations.
///
/// The HAL's blocking erase/program path executes its ROM call from SRAM,
/// rejects core 1, pauses core 1, disables interrupts, waits for flash DMA/XIP
/// streaming, restores XIP and flushes its cache before returning. This wrapper
/// additionally checks core 0 before reads and restricts every operation to one
/// authenticated-state region.
pub struct FittedFlash<'d> {
    inner: HalFlash<'d, FLASH, Blocking, FLASH_BYTES>,
}

impl<'d> FittedFlash<'d> {
    /// Identify the actual CS0 device, not the HAL's const-generic capacity or
    /// raw OTP/default ROM devinfo. Unknown or ambiguous profiles fail closed.
    pub fn new(inner: HalFlash<'d, FLASH, Blocking, FLASH_BYTES>) -> Result<Self, StorageError> {
        Self::require_core0()?;
        let identity =
            crate::flash_identification::identify().map_err(StorageError::FlashIdentification)?;
        if !identity.approved() {
            return Err(StorageError::WrongFlashProfile {
                jedec_id: identity.jedec_id,
                sfdp_header: identity.sfdp_header,
                density_bits_minus_one: identity.density_bits_minus_one,
            });
        }
        Ok(Self { inner })
    }

    pub fn directory(&mut self) -> Result<ScopedFlash<'_, 'd>, StorageError> {
        Self::require_core0()?;
        Ok(ScopedFlash {
            owner: self,
            partition: DIRECTORY,
        })
    }

    pub fn pool(&mut self, slot: HardwareSlot) -> Result<ScopedFlash<'_, 'd>, StorageError> {
        Self::require_core0()?;
        Ok(ScopedFlash {
            owner: self,
            partition: pool_partition(slot),
        })
    }

    /// One enrollment transaction may touch the directory and at most one
    /// complete pool slot. The slot is pinned by its first access; callers
    /// cannot use this view to spill into another pool or the firmware/identity
    /// partitions. Enrollment owns the slot reserve only for blank verification
    /// and recovery of an authenticated not-yet-live intent.
    pub fn enrollment(&mut self) -> Result<EnrollmentFlash<'_, 'd>, StorageError> {
        Self::require_core0()?;
        Ok(EnrollmentFlash {
            owner: self,
            slot: None,
        })
    }

    /// Explicit disposable-identity view: journal bytes are read-only and only
    /// the first two pages of the dedicated spare sector can be programmed.
    #[cfg(not(feature = "release"))]
    pub fn development_identity(
        &mut self,
    ) -> Result<DevelopmentIdentityFlash<'_, 'd>, StorageError> {
        Self::require_core0()?;
        Ok(DevelopmentIdentityFlash { owner: self })
    }

    fn require_core0() -> Result<(), StorageError> {
        if current_core() == CoreId::Core0 {
            Ok(())
        } else {
            Err(StorageError::WrongCore)
        }
    }
}

/// Restricted absolute-address view for the cross-journal enrollment protocol.
pub struct EnrollmentFlash<'a, 'd> {
    owner: &'a mut FittedFlash<'d>,
    slot: Option<usize>,
}

impl EnrollmentFlash<'_, '_> {
    fn check(&mut self, offset: u32, length: usize, alignment: usize) -> Result<(), StorageError> {
        FittedFlash::require_core0()?;
        let offset = offset as usize;
        if !offset.is_multiple_of(alignment) {
            return Err(StorageError::Unaligned);
        }
        if DIRECTORY.contains(offset, length) {
            return Ok(());
        }
        let relative = offset
            .checked_sub(POOLS.offset())
            .ok_or(StorageError::OutOfRegion)?;
        let slot = relative / POOL_REGION_BYTES;
        if slot >= POOL_COUNT
            || !Partition::new(POOLS.offset() + slot * POOL_REGION_BYTES, POOL_REGION_BYTES)
                .contains(offset, length)
            || self.slot.is_some_and(|pinned| pinned != slot)
        {
            return Err(StorageError::OutOfRegion);
        }
        self.slot = Some(slot);
        Ok(())
    }
}

impl JournalFlash for EnrollmentFlash<'_, '_> {
    type Error = StorageError;

    fn capacity(&self) -> u32 {
        FLASH_BYTES as u32
    }

    fn rules(&self) -> FlashRules {
        FlashRules::OnceOnlyClean
    }

    fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<(), Self::Error> {
        self.check(offset, out.len(), 1)?;
        self.owner.inner.blocking_read(offset, out)?;
        Ok(())
    }

    fn program_page(&mut self, offset: u32, page: &[u8; PAGE_SIZE]) -> Result<(), Self::Error> {
        self.check(offset, PAGE_SIZE, PAGE_SIZE)?;
        self.owner.inner.blocking_write(offset, page)?;
        Ok(())
    }

    fn erase_sector(&mut self, offset: u32) -> Result<(), Self::Error> {
        self.check(offset, ERASE_SIZE, ERASE_SIZE)?;
        let end = offset
            .checked_add(ERASE_SIZE as u32)
            .ok_or(StorageError::OutOfRegion)?;
        self.owner.inner.blocking_erase(offset, end)?;
        Ok(())
    }

    fn invalidate_cache(&mut self) -> Result<(), Self::Error> {
        FittedFlash::require_core0()?;
        compiler_fence(Ordering::SeqCst);
        Ok(())
    }
}

pub struct ScopedFlash<'a, 'd> {
    owner: &'a mut FittedFlash<'d>,
    partition: Partition,
}

impl ScopedFlash<'_, '_> {
    fn check(&self, offset: u32, length: usize, alignment: usize) -> Result<(), StorageError> {
        FittedFlash::require_core0()?;
        let offset = offset as usize;
        if !offset.is_multiple_of(alignment) {
            return Err(StorageError::Unaligned);
        }
        if !self.partition.contains(offset, length) {
            return Err(StorageError::OutOfRegion);
        }
        Ok(())
    }
}

impl JournalFlash for ScopedFlash<'_, '_> {
    type Error = StorageError;

    fn capacity(&self) -> u32 {
        FLASH_BYTES as u32
    }

    fn rules(&self) -> FlashRules {
        // Do not rely on a second page-program operation even if a particular
        // fitted part could accept an identical bit pattern.
        FlashRules::OnceOnlyClean
    }

    fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<(), Self::Error> {
        self.check(offset, out.len(), 1)?;
        self.owner.inner.blocking_read(offset, out)?;
        Ok(())
    }

    fn program_page(&mut self, offset: u32, page: &[u8; PAGE_SIZE]) -> Result<(), Self::Error> {
        self.check(offset, PAGE_SIZE, PAGE_SIZE)?;
        self.owner.inner.blocking_write(offset, page)?;
        Ok(())
    }

    fn erase_sector(&mut self, offset: u32) -> Result<(), Self::Error> {
        self.check(offset, ERASE_SIZE, ERASE_SIZE)?;
        let end = offset
            .checked_add(ERASE_SIZE as u32)
            .ok_or(StorageError::OutOfRegion)?;
        self.owner.inner.blocking_erase(offset, end)?;
        Ok(())
    }

    fn invalidate_cache(&mut self) -> Result<(), Self::Error> {
        FittedFlash::require_core0()?;
        // Every mutation is exclusively routed through `blocking_write` or
        // `blocking_erase`; both restore XIP and call the ROM cache flush before
        // returning. The fences prevent compiler motion across the journal's
        // explicit invalidation boundary. No external flash writer is allowed.
        compiler_fence(Ordering::SeqCst);
        Ok(())
    }
}

#[cfg(not(feature = "release"))]
pub struct DevelopmentIdentityFlash<'a, 'd> {
    owner: &'a mut FittedFlash<'d>,
}

#[cfg(not(feature = "release"))]
impl crate::development_identity::IdentityFlash for DevelopmentIdentityFlash<'_, '_> {
    type Error = StorageError;

    fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<(), Self::Error> {
        use crate::development_identity::{IDENTITY_BYTES, IDENTITY_START, JOURNAL_START};
        FittedFlash::require_core0()?;
        let readable = Partition::new(
            JOURNAL_START as usize,
            (IDENTITY_START + IDENTITY_BYTES - JOURNAL_START) as usize,
        );
        if !readable.contains(offset as usize, out.len()) {
            return Err(StorageError::OutOfRegion);
        }
        self.owner.inner.blocking_read(offset, out)?;
        Ok(())
    }

    fn program_page(&mut self, offset: u32, page: &[u8; PAGE_SIZE]) -> Result<(), Self::Error> {
        use crate::development_identity::IDENTITY_START;
        FittedFlash::require_core0()?;
        if offset != IDENTITY_START && offset != IDENTITY_START + PAGE_SIZE as u32 {
            return Err(StorageError::OutOfRegion);
        }
        let mut previous = zeroize::Zeroizing::new([0; PAGE_SIZE]);
        self.owner.inner.blocking_read(offset, &mut *previous)?;
        if previous.iter().any(|byte| *byte != 0xff) {
            return Err(StorageError::OutOfRegion);
        }
        self.owner.inner.blocking_write(offset, page)?;
        Ok(())
    }

    fn invalidate_cache(&mut self) -> Result<(), Self::Error> {
        FittedFlash::require_core0()?;
        compiler_fence(Ordering::SeqCst);
        Ok(())
    }
}

#[cfg(not(feature = "release"))]
const _: () = {
    use crate::development_identity::{IDENTITY_BYTES, IDENTITY_START, JOURNAL_START};
    assert!(JOURNAL_START as usize == DIRECTORY.offset());
    assert!(IDENTITY_START as usize == SPARE.offset());
    assert!(SPARE.contains(IDENTITY_START as usize, IDENTITY_BYTES as usize));
    assert!(IDENTITY_BYTES as usize == ERASE_SIZE);
};

const _: () = assert!(PAGE_SIZE == 256);
const _: () = assert!(ERASE_SIZE == 4096);
const _: () = assert!(POOL_COUNT == 32);
const _: () = assert!(POOL_REGION_BYTES == 32 * 1024);
const _: () = assert!(POOL_USED_BYTES == 2 * 4096 + 2 * 8192);
const _: () = assert!(POOL_RESERVED_BYTES == 8 * 1024);
const _: () = assert!(DIRECTORY.length() == 2 * 8192);
const _: () = assert!(FLASH_RESERVATION_BYTES == 3152 * 1024);
const _: () = assert!(SPARE_BYTES == 944 * 1024);
const _: () = assert!(SPARE.end() == FLASH_BYTES);
const _: () = {
    let first = Partition::new(POOLS.offset(), POOL_USED_BYTES);
    let last = Partition::new(
        POOLS.offset() + (POOL_COUNT - 1) * POOL_REGION_BYTES,
        POOL_USED_BYTES,
    );
    assert!(first.contains(first.offset(), first.length()));
    assert!(!first.contains(DIRECTORY.end() - 1, 1));
    assert!(!first.contains(first.end(), 1));
    assert!(last.end() <= POOLS.end());
    assert!(!last.contains(POOLS.end(), 1));
};
