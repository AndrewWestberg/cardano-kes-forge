//! Persistent **debug-exposed disposable** A2 identity; never production trust.
//!
//! No OTP, host root import, erase, repair, or implicit initialization exists.
//! The caller must separately authorize first use, and must constrain its linked
//! image below JOURNAL_START (including the flash-base development image).
//! SHA-256 detects corruption, not malicious modification by an unlocked debugger.

use kes_core::types::DeviceId;
use rand_chacha::rand_core::TryCryptoRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::security::gateway::{DeviceKeys, GatewayError};

pub const JOURNAL_START: u32 = 2112 * 1024;
pub const IDENTITY_START: u32 = 3152 * 1024;
pub const IDENTITY_BYTES: u32 = 4096;
pub const PAGE_BYTES: usize = 256;
const MAGIC: &[u8; 16] = b"KES-A2-ROOT-v001";
const COMMIT: &[u8; 16] = b"KES-A2-COMMIT-01";

/// Implementations must exclusively own flash. Reads cover only the directory,
/// all pool regions (including reserves), and the identity sector. Programming
/// is restricted to the first two identity pages; no erasure is permitted.
/// `program_page` must reject a previously programmed page (OnceOnlyClean).
pub trait IdentityFlash {
    type Error;
    fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<(), Self::Error>;
    fn program_page(&mut self, offset: u32, page: &[u8; PAGE_BYTES]) -> Result<(), Self::Error>;
    fn invalidate_cache(&mut self) -> Result<(), Self::Error>;
}

/// A call-site assertion of a separately authorized, isolated disposable first
/// use, not proof of hardware security or a wire authorization mechanism.
pub enum InitializationAuthorization {
    IsolatedDisposableDevelopment,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError<E> {
    Flash(E),
    Uninitialized,
    ExistingJournalData,
    AlreadyInitialized,
    CorruptOrInterrupted,
    Entropy,
}

/// No Debug/Clone/serialization and no public raw-root accessor.
pub struct DisposableIdentity {
    device: DeviceId,
    root: Zeroizing<[u8; 32]>,
}

impl DisposableIdentity {
    pub fn device(&self) -> DeviceId {
        self.device
    }

    pub fn into_keys(self) -> Result<DeviceKeys, GatewayError> {
        DeviceKeys::derive(self.device, self.root)
    }
}

/// Read-only boot recovery. An erased identity is never silently regenerated,
/// including when an existing directory or any pool/reserve contains data.
pub fn recover<F: IdentityFlash>(
    flash: &mut F,
) -> Result<DisposableIdentity, IdentityError<F::Error>> {
    let mut record = Zeroizing::new([0; PAGE_BYTES]);
    read(flash, IDENTITY_START, &mut *record)?;
    if record.iter().all(|byte| *byte == 0xff) {
        require_erased(
            flash,
            IDENTITY_START + PAGE_BYTES as u32,
            IDENTITY_START + IDENTITY_BYTES,
        )?;
        require_empty_journals(flash)?;
        return Err(IdentityError::Uninitialized);
    }
    if &record[..16] != MAGIC || record[64..224].iter().any(|byte| *byte != 0xff) {
        return Err(IdentityError::CorruptOrInterrupted);
    }
    let digest = Sha256::digest(&record[..224]);
    if record[224..] != digest[..] {
        return Err(IdentityError::CorruptOrInterrupted);
    }
    let mut commit = Zeroizing::new([0; PAGE_BYTES]);
    read(flash, IDENTITY_START + PAGE_BYTES as u32, &mut *commit)?;
    if &commit[..16] != COMMIT
        || commit[16..48] != digest[..]
        || commit[48..].iter().any(|byte| *byte != 0xff)
    {
        return Err(IdentityError::CorruptOrInterrupted);
    }
    require_erased(
        flash,
        IDENTITY_START + 2 * PAGE_BYTES as u32,
        IDENTITY_START + IDENTITY_BYTES,
    )?;
    let mut device = [0; 16];
    device.copy_from_slice(&record[16..32]);
    let mut root = Zeroizing::new([0; 32]);
    root.copy_from_slice(&record[32..64]);
    Ok(DisposableIdentity {
        device: DeviceId::from_bytes(device),
        root,
    })
}

/// One-shot first use only. All journal and root-sector bytes must be erased.
/// Entropy comes from the device's health-checked source in the real runtime;
/// this API accepts no root or identity bytes. A torn write is terminal until a
/// separately authorized destructive whole-development reset outside this API.
/// Success requires cache invalidation and full readback of both pages.
pub fn initialize_disposable<F: IdentityFlash, R: TryCryptoRng>(
    flash: &mut F,
    rng: &mut R,
    _authorization: InitializationAuthorization,
) -> Result<DisposableIdentity, IdentityError<F::Error>> {
    match recover(flash) {
        Err(IdentityError::Uninitialized) => {}
        Ok(_) => return Err(IdentityError::AlreadyInitialized),
        Err(error) => return Err(error),
    }
    let mut record = Zeroizing::new([0xff; PAGE_BYTES]);
    record[..16].copy_from_slice(MAGIC);
    rng.try_fill_bytes(&mut record[16..64])
        .map_err(|_| IdentityError::Entropy)?;
    let digest = Sha256::digest(&record[..224]);
    record[224..].copy_from_slice(&digest);
    flash
        .program_page(IDENTITY_START, &record)
        .map_err(IdentityError::Flash)?;
    flash.invalidate_cache().map_err(IdentityError::Flash)?;
    let mut observed = Zeroizing::new([0; PAGE_BYTES]);
    read(flash, IDENTITY_START, &mut *observed)?;
    if *observed != *record {
        return Err(IdentityError::CorruptOrInterrupted);
    }
    let mut commit = Zeroizing::new([0xff; PAGE_BYTES]);
    commit[..16].copy_from_slice(COMMIT);
    commit[16..48].copy_from_slice(&digest);
    flash
        .program_page(IDENTITY_START + PAGE_BYTES as u32, &commit)
        .map_err(IdentityError::Flash)?;
    flash.invalidate_cache().map_err(IdentityError::Flash)?;
    // The exact committed format plus all unused sector bytes are checked.
    recover(flash)
}

fn read<F: IdentityFlash>(
    flash: &mut F,
    offset: u32,
    out: &mut [u8],
) -> Result<(), IdentityError<F::Error>> {
    flash.read(offset, out).map_err(IdentityError::Flash)
}

fn require_empty_journals<F: IdentityFlash>(flash: &mut F) -> Result<(), IdentityError<F::Error>> {
    match require_erased(flash, JOURNAL_START, IDENTITY_START) {
        Err(IdentityError::CorruptOrInterrupted) => Err(IdentityError::ExistingJournalData),
        result => result,
    }
}

fn require_erased<F: IdentityFlash>(
    flash: &mut F,
    start: u32,
    end: u32,
) -> Result<(), IdentityError<F::Error>> {
    let mut page = Zeroizing::new([0; PAGE_BYTES]);
    let mut offset = start;
    while offset < end {
        read(flash, offset, &mut *page)?;
        if page.iter().any(|byte| *byte != 0xff) {
            return Err(IdentityError::CorruptOrInterrupted);
        }
        offset += PAGE_BYTES as u32;
    }
    Ok(())
}
