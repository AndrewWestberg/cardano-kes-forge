//! Explicit one-time provisioning for unlocked, disposable A2 development only.
//! Unmeasured sentinels are not production attestation. No erase or repair path.

use ed25519_dalek::VerifyingKey;
use kes_core::{
    journal::{
        DirectoryCodec, Flash, FlashRules, Journal, JournalContext, JournalError, JournalScope,
        Workspaces,
    },
    session::DeviceIdentityKey,
    state::{DeviceConfig, DeviceCredential, DeviceMode, DirectorySnapshot, Health},
    types::{DeviceId, DeviceIdentityBinding, Revision},
};
use zeroize::Zeroizing;

use crate::{
    development_identity::{
        self, IdentityError, IdentityFlash, InitializationAuthorization, PAGE_BYTES,
    },
    entropy::HealthCheckedEntropy,
    storage::{self, FittedFlash},
};

pub const DEVELOPMENT_POLICY_DIGEST: [u8; 32] = [
    0xa6, 0x22, 0x83, 0xc6, 0xd4, 0x21, 0x01, 0x29, 0xcf, 0x6f, 0x26, 0x8f, 0x61, 0x15, 0x0a, 0x23,
    0xc6, 0xf3, 0x2e, 0x60, 0x2c, 0xa9, 0x6f, 0x3c, 0x3d, 0x8c, 0x93, 0xec, 0x3a, 0xf2, 0x0f, 0xf2,
];
pub const UNMEASURED_FIRMWARE_DIGEST: [u8; 32] = [0; 32];
pub const UNMEASURED_PROVISIONING_EVIDENCE_DIGEST: [u8; 32] = [0; 32];
pub const DEVELOPMENT_SECURITY_VERSION: u64 = 0;
pub const A2_SILICON_REVISION: u8 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProvisionError {
    IdentityUninitialized,
    IdentityDamaged,
    InvalidPublicKey,
    AlreadyInitialized,
    Nonblank,
    Damaged,
    Entropy,
    Flash,
    KeyDerivation,
}

pub fn development_config(
    device: DeviceId,
    verification_key: [u8; 32],
    management_root_public_key: [u8; 32],
    management_transport_public_key: [u8; 32],
) -> DeviceConfig {
    DeviceConfig {
        identity: DeviceIdentityBinding::new(
            device,
            verification_key,
            UNMEASURED_PROVISIONING_EVIDENCE_DIGEST,
        ),
        silicon_revision: A2_SILICON_REVISION,
        firmware_digest: UNMEASURED_FIRMWARE_DIGEST,
        security_version: DEVELOPMENT_SECURITY_VERSION,
        hardware_policy_digest: DEVELOPMENT_POLICY_DIGEST,
        mode: DeviceMode::Development,
        health: Health::Healthy,
        management_root_public_key,
        management_transport_public_key,
    }
}

/// The only output is public configuration, after authenticated durable commit.
/// Existing bytes never authorize initialization, cleanup, or journal recovery.
pub fn provision_disposable(
    flash: &mut FittedFlash<'_>,
    entropy: &mut HealthCheckedEntropy<'_>,
    management_root_public_key: [u8; 32],
    management_transport_public_key: [u8; 32],
    _authorization: InitializationAuthorization,
    work: &mut Workspaces<'_>,
) -> Result<DeviceConfig, ProvisionError> {
    for bytes in [
        &management_root_public_key,
        &management_transport_public_key,
    ] {
        let key = VerifyingKey::from_bytes(bytes).map_err(|_| ProvisionError::InvalidPublicKey)?;
        if key.is_weak() {
            return Err(ProvisionError::InvalidPublicKey);
        }
    }
    let identity = {
        let mut view = flash
            .development_identity()
            .map_err(|_| ProvisionError::Flash)?;
        development_identity::recover(&mut view).map_err(|error| match error {
            IdentityError::Uninitialized => ProvisionError::IdentityUninitialized,
            IdentityError::Flash(_) => ProvisionError::Flash,
            _ => ProvisionError::IdentityDamaged,
        })?
    };
    let device = identity.device();
    let keys = identity
        .into_keys()
        .map_err(|_| ProvisionError::KeyDerivation)?;
    let verification_key =
        DeviceIdentityKey::from_seed(Zeroizing::new(*keys.identity_seed())).verification_key();
    let config = development_config(
        device,
        verification_key,
        management_root_public_key,
        management_transport_public_key,
    );
    let journal = Journal::<DirectoryCodec>::new(
        JournalContext {
            device,
            scope: JournalScope::Directory,
        },
        storage::directory_layout().map_err(|_| ProvisionError::Damaged)?,
        &keys.storage_root(),
    )
    .map_err(|_| ProvisionError::KeyDerivation)?;

    // Scan every directory and pool/reserve byte, not only the two journal banks.
    let mut directory_blank = true;
    let mut pools_blank = true;
    {
        let mut view = flash
            .development_identity()
            .map_err(|_| ProvisionError::Flash)?;
        let mut page = [0; PAGE_BYTES];
        let mut offset = storage::DIRECTORY.offset() as u32;
        while offset < storage::POOLS.end() as u32 {
            view.read(offset, &mut page)
                .map_err(|_| ProvisionError::Flash)?;
            if page.iter().any(|byte| *byte != 0xff) {
                if offset < storage::POOLS.offset() as u32 {
                    directory_blank = false;
                } else {
                    pools_blank = false;
                }
            }
            offset += PAGE_BYTES as u32;
        }
    }
    let mut view = flash.directory().map_err(|_| ProvisionError::Flash)?;
    let mut guarded = ProvisionFlash {
        inner: &mut view,
        read_only: !directory_blank,
    };
    if !directory_blank {
        // Authentication may distinguish an intact existing directory, but the
        // adapter forbids every write/erase: interrupted records stay damaged.
        return match journal.recover(&mut guarded, entropy, work) {
            Ok(_) => Err(ProvisionError::AlreadyInitialized),
            Err(_) => Err(ProvisionError::Damaged),
        };
    }
    if !pools_blank {
        return Err(ProvisionError::Nonblank);
    }
    let state = DirectorySnapshot {
        config,
        revision: Revision::new(0),
        retirement: None,
        credential: DeviceCredential::new(management_transport_public_key),
        pending_deletion: None,
        pending_enrollment: None,
        live: [None; kes_core::MAX_POOLS],
        tombstones: [None; kes_core::MAX_POOLS],
    };
    journal
        .initialize(&mut guarded, entropy, &state, work)
        .map_err(|error| match error {
            JournalError::EntropyFailure => ProvisionError::Entropy,
            JournalError::Flash => ProvisionError::Flash,
            JournalError::AlreadyInitialized => ProvisionError::Nonblank,
            _ => ProvisionError::Damaged,
        })?;
    Ok(config)
}

// Even if journal implementation changes, provisioning cannot erase or program
// any non-erased page. Read-only classification cannot repair a damaged journal.
struct ProvisionFlash<'a, F> {
    inner: &'a mut F,
    read_only: bool,
}

impl<F: Flash> Flash for ProvisionFlash<'_, F> {
    type Error = ();
    fn capacity(&self) -> u32 {
        self.inner.capacity()
    }
    fn rules(&self) -> FlashRules {
        FlashRules::OnceOnlyClean
    }
    fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<(), Self::Error> {
        self.inner.read(offset, out).map_err(|_| ())
    }
    fn program_page(&mut self, offset: u32, page: &[u8; 256]) -> Result<(), Self::Error> {
        if self.read_only {
            return Err(());
        }
        let mut previous = [0; 256];
        self.inner.read(offset, &mut previous).map_err(|_| ())?;
        if previous.iter().any(|byte| *byte != 0xff) {
            return Err(());
        }
        self.inner.program_page(offset, page).map_err(|_| ())
    }
    fn erase_sector(&mut self, _offset: u32) -> Result<(), Self::Error> {
        Err(())
    }
    fn invalidate_cache(&mut self) -> Result<(), Self::Error> {
        self.inner.invalidate_cache().map_err(|_| ())
    }
}
