//! Host-executed firmware recovery source with a bounded NOR flash fault model.
mod storage {
    use kes_core::journal::{Flash, FlashRules, JournalError, JournalLayout};
    use kes_core::types::HardwareSlot;
    pub const POOL_COUNT: usize = kes_core::MAX_POOLS;
    pub struct Partition {
        offset: usize,
        length: usize,
    }
    impl Partition {
        pub fn offset(&self) -> usize {
            self.offset
        }
        pub fn end(&self) -> usize {
            self.offset + self.length
        }
    }
    pub fn pool_partition(slot: HardwareSlot) -> Partition {
        Partition {
            offset: 16384 + slot.get() * 32768,
            length: 24576,
        }
    }
    pub fn pool_layout(slot: HardwareSlot) -> Result<JournalLayout, JournalError> {
        JournalLayout::pool(pool_partition(slot).offset as u32)
    }
    pub fn directory_layout() -> Result<JournalLayout, JournalError> {
        JournalLayout::directory(0)
    }
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct StorageError;
    pub struct FittedFlash<'a> {
        pub flash: &'a mut FakeFlash,
    }
    pub struct ScopedFlash<'a>(&'a mut FakeFlash);
    impl<'a> FittedFlash<'a> {
        pub fn directory(&mut self) -> Result<ScopedFlash<'_>, StorageError> {
            Ok(ScopedFlash(self.flash))
        }
        pub fn pool(&mut self, _: HardwareSlot) -> Result<ScopedFlash<'_>, StorageError> {
            Ok(ScopedFlash(self.flash))
        }
        pub fn enrollment(&mut self) -> Result<ScopedFlash<'_>, StorageError> {
            Ok(ScopedFlash(self.flash))
        }
    }
    impl Flash for ScopedFlash<'_> {
        type Error = StorageError;
        fn capacity(&self) -> u32 {
            self.0.capacity()
        }
        fn rules(&self) -> FlashRules {
            self.0.rules()
        }
        fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<(), Self::Error> {
            self.0.read(offset, out)
        }
        fn program_page(&mut self, offset: u32, page: &[u8; 256]) -> Result<(), Self::Error> {
            self.0.program_page(offset, page)
        }
        fn erase_sector(&mut self, offset: u32) -> Result<(), Self::Error> {
            self.0.erase_sector(offset)
        }
        fn invalidate_cache(&mut self) -> Result<(), Self::Error> {
            self.0.invalidate_cache()
        }
    }
    pub struct FakeFlash {
        pub bytes: Vec<u8>,
        pub ignore_erase: bool,
    }
    impl Flash for FakeFlash {
        type Error = StorageError;
        fn capacity(&self) -> u32 {
            self.bytes.len() as u32
        }
        fn rules(&self) -> FlashRules {
            FlashRules::OnceOnlyClean
        }
        fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<(), Self::Error> {
            let start = offset as usize;
            out.copy_from_slice(
                self.bytes
                    .get(start..start + out.len())
                    .ok_or(StorageError)?,
            );
            Ok(())
        }
        fn program_page(&mut self, offset: u32, page: &[u8; 256]) -> Result<(), Self::Error> {
            let start = offset as usize;
            let target = self.bytes.get_mut(start..start + 256).ok_or(StorageError)?;
            for (old, new) in target.iter_mut().zip(page) {
                *old &= new;
            }
            Ok(())
        }
        fn erase_sector(&mut self, offset: u32) -> Result<(), Self::Error> {
            if !self.ignore_erase {
                let start = offset as usize;
                self.bytes
                    .get_mut(start..start + 4096)
                    .ok_or(StorageError)?
                    .fill(0xff);
            }
            Ok(())
        }
        fn invalidate_cache(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }
}
#[allow(dead_code)]
#[path = "../../../firmware/src/recovery.rs"]
mod recovery;
use kes_core::types::HardwareSlot;

#[test]
fn firmware_recovery_refuses_a_falsely_successful_sector_erase() {
    let slot = HardwareSlot::new(0).unwrap();
    let offset = storage::pool_partition(slot).offset();
    let mut flash = storage::FakeFlash {
        bytes: vec![0xff; 16384 + 32768],
        ignore_erase: true,
    };
    flash.bytes[offset + 4095] = 0;
    assert!(recovery::erase_pool_region(&mut flash, slot).is_err());
    assert_eq!(flash.bytes[offset + 4095], 0);
    flash.ignore_erase = false;
    recovery::erase_pool_region(&mut flash, slot).unwrap();
    assert!(
        flash.bytes[offset..offset + 24576]
            .iter()
            .all(|byte| *byte == 0xff)
    );
}

#[test]
fn firmware_boot_finishes_committed_enrollment_before_exposing_the_slot() {
    use kes_core::{
        journal::{
            DirectoryCodec, Journal, JournalContext, JournalLayout, JournalScope, JournalWorkspace,
            ObjectWorkspace, SecretCache, Workspaces,
        },
        state::{
            DeviceConfig, DeviceCredential, DeviceMode, DirectorySnapshot, Enrollment,
            EnrollmentIntent, Health,
        },
        types::{
            DeviceId, DeviceIdentityBinding, IncarnationId, ManagementSequence, NetworkBinding,
            PoolId, RequestId, Revision,
        },
    };
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
    use sha2::{Digest, Sha256};
    use std::io::Read;
    use zeroize::Zeroizing;
    xtask::oracles::protect_memory().expect("fresh no-swap disposable lab required");

    let mut entropy = std::fs::File::open("/dev/urandom").unwrap();
    let mut seed = Zeroizing::new([0; 32]);
    let mut root = Zeroizing::new([0; 32]);
    entropy.read_exact(&mut seed[..]).unwrap();
    entropy.read_exact(&mut root[..]).unwrap();
    let mut rng = ChaCha20Rng::from_seed(*seed);
    let device = DeviceId::from_bytes([0x31; 16]);
    let slot = HardwareSlot::new(3).unwrap();
    let recipient = [0x44; 32];
    let cold = [0x55; 32];
    let enrollment = Enrollment {
        incarnation: IncarnationId::from_bytes([0x66; 16]),
        cold_verification_key: cold,
        network: NetworkBinding::from_genesis_bytes(42, b"disposable genesis", 64, 64).unwrap(),
        machine_public_key: [0x77; 32],
        recipient_public_key: recipient,
        recipient_id: Sha256::digest(recipient).into(),
        management_sequence: ManagementSequence::new(1),
        management_request: RequestId::from_bytes([0x88; 16]),
        management_payload_digest: [0x99; 32],
    };
    let mut directory = DirectorySnapshot {
        config: DeviceConfig {
            identity: DeviceIdentityBinding::new(device, [1; 32], [2; 32]),
            silicon_revision: 2,
            firmware_digest: [3; 32],
            security_version: 0,
            hardware_policy_digest: [4; 32],
            mode: DeviceMode::Development,
            health: Health::Healthy,
            management_root_public_key: [5; 32],
            management_transport_public_key: [6; 32],
        },
        revision: Revision::new(0),
        retirement: None,
        credential: DeviceCredential::new([6; 32]),
        pending_deletion: None,
        pending_enrollment: None,
        live: [None; kes_core::MAX_POOLS],
        tombstones: [None; kes_core::MAX_POOLS],
    };
    let mut flash = storage::FakeFlash {
        bytes: vec![0xff; 16384 + kes_core::MAX_POOLS * 32768],
        ignore_erase: false,
    };
    let journal = Journal::<DirectoryCodec>::new(
        JournalContext {
            device,
            scope: JournalScope::Directory,
        },
        JournalLayout::directory(0).unwrap(),
        &root,
    )
    .unwrap();
    let mut journal_work = JournalWorkspace::new();
    let mut object_work = ObjectWorkspace::new();
    let mut cache = SecretCache::new();
    let mut work = Workspaces {
        journal: &mut journal_work,
        object: &mut object_work,
        cache: &mut cache,
    };
    let token = journal
        .initialize(&mut flash, &mut rng, &directory, &mut work)
        .unwrap();
    directory.pending_enrollment = Some(EnrollmentIntent { slot, enrollment });
    directory.revision = Revision::new(1);
    journal
        .transact_successor(&mut flash, &mut rng, &token, &directory, &mut work)
        .unwrap();

    let mut fitted = storage::FittedFlash { flash: &mut flash };
    let boot = recovery::recover_boot(&mut fitted, &mut rng, &root, device, &mut work).unwrap();
    let entry = boot
        .device
        .find(PoolId::from_cold_verification_key(&cold))
        .unwrap();
    assert_eq!(entry.slot(), slot);
    assert!(boot.slot_ready(slot));
    assert!(!boot.slot_quarantined(slot));
}
