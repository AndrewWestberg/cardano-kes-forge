//! Durable immutable generation objects for the secure single-flight dispatcher.
//!
//! This is the storage component, not a pool command dispatcher. Construct only
//! from the latest authenticated/recovered pool, and drop before mutating that
//! pool. Never recover its journal between object publication and the successor
//! transaction: recovery intentionally reclaims objects not yet referenced.
//! Production callers pass `FittedFlash::pool(slot)` and `pool_layout(slot)`.
//! The generic flash parameter is the actual journal flash interface, not a
//! command-forwarding backend. No secret or full object is cached here.

use kes_core::{
    generation::PublicObjectStore,
    journal::{Flash, JournalLayout},
    state::{MAX_PUBLIC_OBJECT_BYTES, PoolRegistration, PublicObject, PublicObjectRef},
};
use sha2::{Digest, Sha256};

const OBJECT_BYTES: usize = 8192;
const PAGE_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectStoreError {
    Flash,
    Layout,
    InvalidObject,
    MissingRetainedObject,
    MissingObject,
    Capacity,
    ProtectedObject,
    Readback,
}

/// One scoped flash borrow, two retained-slot bits and at most two unpublished
/// references. Scratch is one 256-byte page per operation; there is no allocator.
/// A new object uses two sector erases only if its unreferenced slot is dirty,
/// then ceil(object_length/256) single page programs. Exact retries do no writes.
/// Once a descriptor is committed, reconstruct this adapter from the new pool;
/// an old adapter must never be reused to discard a now-published object.
pub struct FlashPublicObjects<'a, F: Flash> {
    flash: &'a mut F,
    offsets: [u32; 2],
    protected: u8,
    pending: [Option<PublicObjectRef>; 2],
}

impl<'a, F: Flash> FlashPublicObjects<'a, F> {
    pub fn new(
        flash: &'a mut F,
        layout: JournalLayout,
        pool: &PoolRegistration,
    ) -> Result<Self, ObjectStoreError> {
        let offsets = [
            layout
                .object_offset(0)
                .map_err(|_| ObjectStoreError::Layout)?,
            layout
                .object_offset(1)
                .map_err(|_| ObjectStoreError::Layout)?,
        ];
        if offsets[1]
            .checked_add(OBJECT_BYTES as u32)
            .is_none_or(|end| end > flash.capacity())
        {
            return Err(ObjectStoreError::Layout);
        }
        let mut store = Self {
            flash,
            offsets,
            protected: 0,
            pending: [None; 2],
        };
        store
            .flash
            .invalidate_cache()
            .map_err(|_| ObjectStoreError::Flash)?;
        for generation in [pool.current(), pool.staged()].into_iter().flatten() {
            let reference = generation.public_object_ref();
            let mut found = None;
            for slot in 0..2 {
                if store.protected & (1 << slot) == 0 && store.matches(slot, reference)? {
                    found = Some(slot);
                    break;
                }
            }
            let slot = found.ok_or(ObjectStoreError::MissingRetainedObject)?;
            store.protected |= 1 << slot;
        }
        Ok(store)
    }

    fn valid_length(reference: &PublicObjectRef) -> Result<usize, ObjectStoreError> {
        let n = usize::from(reference.total_length);
        if !(4096..=MAX_PUBLIC_OBJECT_BYTES).contains(&n) {
            return Err(ObjectStoreError::InvalidObject);
        }
        Ok(n)
    }

    fn matches(
        &mut self,
        slot: usize,
        reference: &PublicObjectRef,
    ) -> Result<bool, ObjectStoreError> {
        let n = Self::valid_length(reference)?;
        let mut hash = Sha256::new();
        let mut page = [0; PAGE_BYTES];
        for start in (0..n).step_by(PAGE_BYTES) {
            let length = (n - start).min(PAGE_BYTES);
            self.flash
                .read(self.offsets[slot] + start as u32, &mut page[..length])
                .map_err(|_| ObjectStoreError::Flash)?;
            hash.update(&page[..length]);
        }
        Ok(hash.finalize()[..] == reference.digest)
    }

    fn find(&mut self, reference: &PublicObjectRef) -> Result<Option<usize>, ObjectStoreError> {
        for slot in 0..2 {
            if self.matches(slot, reference)? {
                return Ok(Some(slot));
            }
        }
        Ok(None)
    }

    fn blank(&mut self, slot: usize) -> Result<bool, ObjectStoreError> {
        let mut page = [0; PAGE_BYTES];
        for start in (0..OBJECT_BYTES).step_by(PAGE_BYTES) {
            self.flash
                .read(self.offsets[slot] + start as u32, &mut page)
                .map_err(|_| ObjectStoreError::Flash)?;
            if page.iter().any(|byte| *byte != 0xff) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn erase(&mut self, slot: usize) -> Result<(), ObjectStoreError> {
        if self.protected & (1 << slot) != 0 {
            return Err(ObjectStoreError::ProtectedObject);
        }
        if self.blank(slot)? {
            return Ok(());
        }
        for start in [0, 4096] {
            self.flash
                .erase_sector(self.offsets[slot] + start)
                .map_err(|_| ObjectStoreError::Flash)?;
        }
        self.flash
            .invalidate_cache()
            .map_err(|_| ObjectStoreError::Flash)?;
        if !self.blank(slot)? {
            return Err(ObjectStoreError::Readback);
        }
        Ok(())
    }
}

impl<F: Flash> PublicObjectStore for FlashPublicObjects<'_, F> {
    type Error = ObjectStoreError;

    fn write(&mut self, reference: &PublicObjectRef, bytes: &[u8]) -> Result<(), Self::Error> {
        let n = Self::valid_length(reference)?;
        if bytes.len() != n {
            return Err(ObjectStoreError::InvalidObject);
        }
        let vk = bytes[32..64]
            .try_into()
            .map_err(|_| ObjectStoreError::InvalidObject)?;
        PublicObject::parse(bytes, reference, vk).map_err(|_| ObjectStoreError::InvalidObject)?;
        self.flash
            .invalidate_cache()
            .map_err(|_| ObjectStoreError::Flash)?;
        if self.find(reference)?.is_some() {
            return Ok(());
        }
        let slot = (0..2)
            .find(|slot| self.protected & (1 << slot) == 0 && self.pending[*slot].is_none())
            .ok_or(ObjectStoreError::Capacity)?;
        self.erase(slot)?;
        // Retain ownership even on a partial program so discard can erase it.
        self.pending[slot] = Some(*reference);
        for start in (0..n).step_by(PAGE_BYTES) {
            let length = (n - start).min(PAGE_BYTES);
            let mut page = [0xff; PAGE_BYTES];
            page[..length].copy_from_slice(&bytes[start..start + length]);
            self.flash
                .program_page(self.offsets[slot] + start as u32, &page)
                .map_err(|_| ObjectStoreError::Flash)?;
        }
        self.flash
            .invalidate_cache()
            .map_err(|_| ObjectStoreError::Flash)?;
        if !self.matches(slot, reference)? {
            return Err(ObjectStoreError::Readback);
        }
        Ok(())
    }

    fn read(
        &mut self,
        reference: &PublicObjectRef,
        output: &mut [u8],
    ) -> Result<usize, Self::Error> {
        let n = Self::valid_length(reference)?;
        if output.len() < n {
            return Err(ObjectStoreError::Capacity);
        }
        self.flash
            .invalidate_cache()
            .map_err(|_| ObjectStoreError::Flash)?;
        let slot = self
            .find(reference)?
            .ok_or(ObjectStoreError::MissingObject)?;
        self.flash
            .read(self.offsets[slot], &mut output[..n])
            .map_err(|_| ObjectStoreError::Flash)?;
        let vk = output[32..64]
            .try_into()
            .map_err(|_| ObjectStoreError::InvalidObject)?;
        PublicObject::parse(&output[..n], reference, vk).map_err(|_| ObjectStoreError::Readback)?;
        Ok(n)
    }

    fn discard(&mut self, reference: &PublicObjectRef) -> Result<(), Self::Error> {
        // Only this adapter's unpublished writes may be discarded. In
        // particular a caller cannot erase a retained backup by naming it.
        if let Some(slot) = self
            .pending
            .iter()
            .position(|pending| pending.as_ref() == Some(reference))
        {
            self.erase(slot)?;
            self.pending[slot] = None;
            return Ok(());
        }
        if self.find(reference)?.is_some() {
            return Err(ObjectStoreError::ProtectedObject);
        }
        Ok(())
    }
}
