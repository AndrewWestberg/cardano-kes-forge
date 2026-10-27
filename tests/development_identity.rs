//! Executes the firmware identity source against deterministic NOR semantics.
#[allow(dead_code)]
#[path = "../firmware/src/security/gateway.rs"]
mod gateway_impl;
mod security {
    pub mod gateway {
        pub use crate::gateway_impl::*;
    }
}
#[allow(dead_code)]
#[path = "../firmware/src/development/identity.rs"]
mod identity;

use identity::{
    IDENTITY_BYTES, IDENTITY_START, IdentityError, IdentityFlash, InitializationAuthorization,
    JOURNAL_START, PAGE_BYTES,
};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NorError {
    PowerCut,
    Bounds,
    Reprogram,
    Read,
}

struct Nor {
    bytes: Vec<u8>,
    programmed: [bool; 2],
    cut_after: Option<usize>,
    written: usize,
    reads_fail: bool,
    corrupt_readback: bool,
}

impl Nor {
    fn blank() -> Self {
        Self {
            // Include sentinels on both sides of the entire readable region.
            bytes: vec![0xff; (IDENTITY_START + IDENTITY_BYTES + 256) as usize],
            programmed: [false; 2],
            cut_after: None,
            written: 0,
            reads_fail: false,
            corrupt_readback: false,
        }
    }
}

impl IdentityFlash for Nor {
    type Error = NorError;

    fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<(), Self::Error> {
        if self.reads_fail {
            return Err(NorError::Read);
        }
        let end = offset
            .checked_add(out.len() as u32)
            .ok_or(NorError::Bounds)?;
        if offset < JOURNAL_START || end > IDENTITY_START + IDENTITY_BYTES {
            return Err(NorError::Bounds);
        }
        out.copy_from_slice(&self.bytes[offset as usize..end as usize]);
        if self.corrupt_readback && self.written > 0 && offset == IDENTITY_START {
            out[32] ^= 1;
        }
        Ok(())
    }

    fn program_page(&mut self, offset: u32, page: &[u8; PAGE_BYTES]) -> Result<(), Self::Error> {
        if offset != IDENTITY_START && offset != IDENTITY_START + PAGE_BYTES as u32 {
            return Err(NorError::Bounds);
        }
        let index = ((offset - IDENTITY_START) / PAGE_BYTES as u32) as usize;
        if self.programmed[index] {
            return Err(NorError::Reprogram);
        }
        self.programmed[index] = true;
        for (position, byte) in page.iter().enumerate() {
            if self.cut_after == Some(self.written) {
                return Err(NorError::PowerCut);
            }
            let old = &mut self.bytes[offset as usize + position];
            if *old & *byte != *byte {
                return Err(NorError::Reprogram);
            }
            *old &= *byte;
            self.written += 1;
        }
        Ok(())
    }

    fn invalidate_cache(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

fn initialize(flash: &mut Nor) -> Result<identity::DisposableIdentity, IdentityError<NorError>> {
    identity::initialize_disposable(
        flash,
        &mut ChaCha20Rng::from_seed([7; 32]),
        InitializationAuthorization::IsolatedDisposableDevelopment,
    )
}

#[test]
fn explicit_first_use_reboots_with_identical_device_and_derived_keys() {
    let mut flash = Nor::blank();
    flash.bytes[JOURNAL_START as usize - 1] = 0x12;
    flash.bytes[(IDENTITY_START + IDENTITY_BYTES) as usize] = 0x34;
    assert!(matches!(
        identity::recover(&mut flash),
        Err(IdentityError::Uninitialized)
    ));
    assert_eq!(flash.written, 0);
    let initial = initialize(&mut flash).unwrap();
    let device = initial.device();
    let initial = initial.into_keys().unwrap();
    let reboot = identity::recover(&mut flash).unwrap();
    assert_eq!(device, reboot.device());
    let reboot = reboot.into_keys().unwrap();
    assert_eq!(*initial.storage_root(), *reboot.storage_root());
    assert_eq!(initial.identity_seed(), reboot.identity_seed());
    assert_eq!(initial.session_root(), reboot.session_root());
    let before = flash.bytes.clone();
    assert!(matches!(
        initialize(&mut flash),
        Err(IdentityError::AlreadyInitialized)
    ));
    assert_eq!(flash.bytes, before);
    assert_eq!(flash.bytes[JOURNAL_START as usize - 1], 0x12);
    assert_eq!(
        flash.bytes[(IDENTITY_START + IDENTITY_BYTES) as usize],
        0x34
    );
    assert!(
        flash.bytes[JOURNAL_START as usize..IDENTITY_START as usize]
            .iter()
            .all(|byte| *byte == 0xff)
    );
    assert!(
        flash.bytes[(IDENTITY_START + 512) as usize..(IDENTITY_START + IDENTITY_BYTES) as usize]
            .iter()
            .all(|byte| *byte == 0xff)
    );
}

#[test]
fn every_initial_page_prefix_power_cut_is_recovered_or_refused_without_repair() {
    for cut in 0..512 {
        let mut flash = Nor::blank();
        flash.cut_after = Some(cut);
        assert!(matches!(
            initialize(&mut flash),
            Err(IdentityError::Flash(NorError::PowerCut))
        ));
        flash.cut_after = None;
        let before = flash.bytes.clone();
        let recovery = identity::recover(&mut flash);
        if cut == 0 {
            // No programmed bit and no journals: still genuinely blank.
            assert!(matches!(recovery, Err(IdentityError::Uninitialized)));
        } else if cut >= 304 {
            // All semantic COMMIT bytes are durable; remaining bytes are FF.
            assert!(recovery.is_ok());
            assert!(matches!(
                initialize(&mut flash),
                Err(IdentityError::AlreadyInitialized)
            ));
        } else {
            assert!(matches!(recovery, Err(IdentityError::CorruptOrInterrupted)));
            assert!(matches!(
                initialize(&mut flash),
                Err(IdentityError::CorruptOrInterrupted)
            ));
        }
        assert_eq!(flash.bytes, before, "cut {cut}");
    }
}

#[test]
fn blank_root_with_any_directory_pool_or_reserve_data_never_reinitializes() {
    // Scan every page, including both directory banks and every pool reserve.
    for offset in (JOURNAL_START..IDENTITY_START).step_by(PAGE_BYTES) {
        let mut flash = Nor::blank();
        flash.bytes[offset as usize + PAGE_BYTES - 1] = 0;
        let before = flash.bytes.clone();
        assert!(matches!(
            identity::recover(&mut flash),
            Err(IdentityError::ExistingJournalData)
        ));
        assert!(matches!(
            initialize(&mut flash),
            Err(IdentityError::ExistingJournalData)
        ));
        assert_eq!(flash.bytes, before);
        assert_eq!(flash.written, 0);
    }
}

#[test]
fn every_identity_byte_corruption_is_terminal_and_never_rewritten() {
    let mut flash = Nor::blank();
    initialize(&mut flash).unwrap();
    for offset in IDENTITY_START..IDENTITY_START + IDENTITY_BYTES {
        flash.bytes[offset as usize] ^= 1;
        let before = flash.bytes.clone();
        assert!(matches!(
            identity::recover(&mut flash),
            Err(IdentityError::CorruptOrInterrupted)
        ));
        assert!(matches!(
            initialize(&mut flash),
            Err(IdentityError::CorruptOrInterrupted)
        ));
        assert_eq!(flash.bytes, before);
        flash.bytes[offset as usize] ^= 1;
    }
}

#[test]
fn read_failure_or_failed_initial_readback_cannot_commit() {
    let mut flash = Nor::blank();
    flash.reads_fail = true;
    assert!(matches!(
        initialize(&mut flash),
        Err(IdentityError::Flash(NorError::Read))
    ));
    assert_eq!(flash.written, 0);
    flash.reads_fail = false;
    flash.corrupt_readback = true;
    assert!(matches!(
        initialize(&mut flash),
        Err(IdentityError::CorruptOrInterrupted)
    ));
    assert_eq!(flash.written, PAGE_BYTES);
    flash.corrupt_readback = false;
    assert!(matches!(
        identity::recover(&mut flash),
        Err(IdentityError::CorruptOrInterrupted)
    ));
}

struct FailedEntropy;

impl rand_chacha::rand_core::TryRngCore for FailedEntropy {
    type Error = std::io::Error;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Err(std::io::Error::other("deterministic entropy failure"))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Err(std::io::Error::other("deterministic entropy failure"))
    }
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), Self::Error> {
        // Partial entropy output must not result in a programmed record.
        out[0] = 1;
        Err(std::io::Error::other("deterministic entropy failure"))
    }
}

impl rand_chacha::rand_core::TryCryptoRng for FailedEntropy {}

#[test]
fn partial_entropy_failure_leaves_flash_completely_untouched() {
    let mut flash = Nor::blank();
    let before = flash.bytes.clone();
    let result = identity::initialize_disposable(
        &mut flash,
        &mut FailedEntropy,
        InitializationAuthorization::IsolatedDisposableDevelopment,
    );
    assert!(matches!(result, Err(IdentityError::Entropy)));
    assert_eq!(flash.written, 0);
    assert_eq!(flash.bytes, before);
}

#[test]
fn committed_root_recovers_with_journals_but_erased_root_refuses_them() {
    let mut flash = Nor::blank();
    let initial = initialize(&mut flash).unwrap();
    flash.bytes[JOURNAL_START as usize] = 0x12;
    flash.bytes[IDENTITY_START as usize - 1] = 0x34;
    assert_eq!(
        identity::recover(&mut flash).unwrap().device(),
        initial.device()
    );
    // Model a destructive external root erase, not an API operation.
    flash.bytes[IDENTITY_START as usize..(IDENTITY_START + IDENTITY_BYTES) as usize].fill(0xff);
    assert!(matches!(
        identity::recover(&mut flash),
        Err(IdentityError::ExistingJournalData)
    ));
    assert!(matches!(
        initialize(&mut flash),
        Err(IdentityError::ExistingJournalData)
    ));
}
