//! Source-included upload tests; fixture signatures are NOT an approved release
//! manifest transcript, ROM verifier or hardware/OTP qualification.
#[path = "../../../firmware/src/update.rs"]
mod update;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::{cell::RefCell, rc::Rc};
use update::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Io;
#[derive(Clone)]
struct Memory(Rc<RefCell<MemoryState>>);
struct MemoryState {
    intent: Option<Intent>,
    bytes: [u8; 8192],
    erases: usize,
    writes: usize,
    preserved: bool,
    corrupt: bool,
    fail_program: bool,
    fail_save_after_program: bool,
}
impl Memory {
    fn new() -> Self {
        Self(Rc::new(RefCell::new(MemoryState {
            intent: None,
            bytes: [255; 8192],
            erases: 0,
            writes: 0,
            preserved: true,
            corrupt: false,
            fail_program: false,
            fail_save_after_program: false,
        })))
    }
}
impl Storage for Memory {
    type Error = Io;
    fn load(&mut self) -> Result<Option<Intent>, Io> {
        Ok(self.0.borrow().intent)
    }
    fn save(&mut self, intent: &Intent) -> Result<(), Io> {
        let mut s = self.0.borrow_mut();
        if s.fail_save_after_program && s.writes > 0 && intent.phase == Phase::Uploading {
            return Err(Io);
        }
        s.intent = Some(*intent);
        Ok(())
    }
    fn check_preserved_image(&mut self) -> Result<(), Io> {
        if self.0.borrow().preserved {
            Ok(())
        } else {
            Err(Io)
        }
    }
    fn capacity(&self) -> u64 {
        8192
    }
    fn erase_inactive(&mut self) -> Result<(), Io> {
        let mut s = self.0.borrow_mut();
        assert!(s.preserved);
        s.bytes.fill(255);
        s.erases += 1;
        Ok(())
    }
    fn program(&mut self, offset: u64, bytes: &[u8]) -> Result<(), Io> {
        let mut s = self.0.borrow_mut();
        assert!(s.preserved);
        s.writes += 1;
        for (i, b) in bytes.iter().enumerate() {
            s.bytes[offset as usize + i] &= *b;
        }
        if s.corrupt {
            s.bytes[offset as usize] ^= 1;
        }
        if s.fail_program { Err(Io) } else { Ok(()) }
    }
    fn read(&mut self, offset: u64, bytes: &mut [u8]) -> Result<(), Io> {
        let length = bytes.len();
        bytes.copy_from_slice(
            self.0
                .borrow()
                .bytes
                .get(offset as usize..offset as usize + length)
                .ok_or(Io)?,
        );
        Ok(())
    }
}

struct FixtureTrust {
    key: VerifyingKey,
    authorized: bool,
    available: bool,
    policy: Policy,
}
// Test-only encoding: this intentionally does not define production wire bytes.
fn fixture_transcript(m: &Manifest) -> Vec<u8> {
    let mut b = b"fixture-only-not-release".to_vec();
    for value in [
        m.version,
        m.storage_schema,
        m.image_length,
        m.security_version,
    ] {
        b.extend(value.to_be_bytes());
    }
    b.extend(m.firmware_digest);
    b.extend(m.partition_manifest_digest);
    b.extend(m.hardware_policy_digest);
    b
}
fn manifest_digest(m: &Manifest) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(fixture_transcript(m));
    hash.update(m.signature);
    hash.finalize().into()
}
impl Trust for FixtureTrust {
    fn policy(&mut self) -> Result<Policy, Rejection> {
        if self.available {
            Ok(self.policy)
        } else {
            Err(Rejection::UnavailableTrust)
        }
    }
    fn verify_manifest(&mut self, manifest: &Manifest) -> Result<[u8; 32], Rejection> {
        self.key
            .verify_strict(
                &fixture_transcript(manifest),
                &ed25519_dalek::Signature::from_bytes(&manifest.signature),
            )
            .map_err(|_| Rejection::InvalidSignature)?;
        Ok(manifest_digest(manifest))
    }
    fn verify_management(
        &mut self,
        device: [u8; 16],
        _: &Manifest,
        _: [u8; 32],
        revision: u64,
    ) -> Result<(), Rejection> {
        if self.authorized && device == [3; 16] && revision == 7 {
            Ok(())
        } else {
            Err(Rejection::Unauthorized)
        }
    }
    fn verify_executable<S: Storage>(
        &mut self,
        _: &Manifest,
        slot: &mut S,
    ) -> Result<(), Rejection> {
        let mut marker = [0; 3];
        slot.read(0, &mut marker)
            .map_err(|_| Rejection::InvalidImage)?;
        if marker == *b"DEV" {
            Err(Rejection::DevelopmentImage)
        } else if marker == *b"REL" {
            Ok(())
        } else {
            Err(Rejection::InvalidImage)
        }
    }
}
fn fixture(image: &[u8]) -> (Manifest, FixtureTrust) {
    let key = SigningKey::from_bytes(&[42; 32]);
    let mut manifest = Manifest {
        version: 1,
        firmware_digest: Sha256::digest(image).into(),
        partition_manifest_digest: [1; 32],
        storage_schema: 1,
        image_length: image.len() as u64,
        security_version: 4,
        hardware_policy_digest: [2; 32],
        signature: [0; 64],
    };
    manifest.signature = key.sign(&fixture_transcript(&manifest)).to_bytes();
    (
        manifest,
        FixtureTrust {
            key: key.verifying_key(),
            authorized: true,
            available: true,
            policy: Policy {
                device: [3; 16],
                partition_manifest_digest: [1; 32],
                hardware_policy_digest: [2; 32],
                current_security_version: 3,
                rollback_floor: 3,
                maximum_security_version: 8,
                slot_capacity: 8192,
            },
        },
    )
}
fn image() -> Vec<u8> {
    let mut bytes = vec![27; 513];
    bytes[..3].copy_from_slice(b"REL");
    bytes
}

#[test]
fn verifies_sequential_readback_and_recovers_verified_candidate_without_installing() {
    let bytes = image();
    let (m, trust) = fixture(&bytes);
    let memory = Memory::new();
    let digest = manifest_digest(&m);
    let mut updater = Update::open(memory.clone(), trust).unwrap();
    assert_eq!(updater.begin(m, digest, 7).unwrap().offset, 0);
    assert_eq!(
        updater.chunk(digest, 0, &bytes[..256], 7).unwrap().offset,
        256
    );
    let (_, trust) = fixture(&bytes);
    drop(updater);
    let mut updater = Update::open(memory.clone(), trust).unwrap();
    assert_eq!(updater.status().unwrap().unwrap().offset, 256);
    updater.chunk(digest, 256, &bytes[256..], 7).unwrap();
    assert_eq!(
        updater
            .finalize(digest, m.firmware_digest, 7)
            .unwrap()
            .phase,
        Phase::Verified
    );
    let (_, trust) = fixture(&bytes);
    assert_eq!(
        Update::open(memory.clone(), trust)
            .unwrap()
            .status()
            .unwrap()
            .unwrap()
            .phase,
        Phase::Verified
    );
    assert!(memory.0.borrow().preserved);
    assert_eq!(memory.0.borrow().erases, 1);
}

#[test]
fn rejects_manifest_policy_and_authority_failures_before_erase() {
    let bytes = image();
    for case in 0..10 {
        let (mut m, mut trust) = fixture(&bytes);
        match case {
            0 => m.storage_schema = 2,
            1 => m.partition_manifest_digest = [9; 32],
            2 => m.security_version = 2,
            3 => m.security_version = 9,
            4 => m.signature = [0; 64],
            5 => trust.authorized = false,
            6 => trust.available = false,
            7 => m.image_length = 8193,
            8 => m.hardware_policy_digest = [8; 32],
            _ => m.version = 2,
        }
        let memory = Memory::new();
        let mut updater = Update::open(memory.clone(), trust).unwrap();
        assert!(
            updater.begin(m, manifest_digest(&m), 7).is_err(),
            "case {case}"
        );
        assert_eq!(memory.0.borrow().erases, 0);
    }
}

#[test]
fn rejects_offsets_lengths_revision_conflicts_and_wrong_final_digest() {
    let bytes = image();
    let (m, trust) = fixture(&bytes);
    let digest = manifest_digest(&m);
    let mut updater = Update::open(Memory::new(), trust).unwrap();
    updater.begin(m, digest, 7).unwrap();
    assert_eq!(
        updater.chunk(digest, 1, &bytes[..256], 7),
        Err(Error::Sequence)
    );
    assert_eq!(updater.chunk(digest, 0, &[], 7), Err(Error::Bounds));
    assert_eq!(
        updater.chunk(digest, 0, &bytes[..255], 7),
        Err(Error::Bounds)
    );
    assert_eq!(
        updater.chunk(digest, 0, &[0; MAX_CHUNK + 1], 7),
        Err(Error::Bounds)
    );
    assert_eq!(
        updater.chunk(digest, 0, &bytes[..256], 8),
        Err(Error::Revision)
    );
    assert_eq!(
        updater.chunk([9; 32], 0, &bytes[..256], 7),
        Err(Error::Conflict)
    );
    assert_eq!(
        updater.finalize(digest, m.firmware_digest, 7),
        Err(Error::Sequence)
    );
    updater.chunk(digest, 0, &bytes, 7).unwrap();
    assert_eq!(updater.finalize(digest, [0; 32], 7), Err(Error::Digest));
}

#[test]
fn interrupted_program_or_checkpoint_restarts_without_reprogramming_torn_pages() {
    let bytes = image();
    for save_failure in [false, true] {
        let (m, trust) = fixture(&bytes);
        let memory = Memory::new();
        let digest = manifest_digest(&m);
        let mut updater = Update::open(memory.clone(), trust).unwrap();
        updater.begin(m, digest, 7).unwrap();
        memory.0.borrow_mut().fail_program = !save_failure;
        memory.0.borrow_mut().fail_save_after_program = save_failure;
        assert_eq!(
            updater.chunk(digest, 0, &bytes[..256], 7),
            Err(Error::Storage(Io))
        );
        assert_eq!(updater.status(), Err(Error::RecoveryRequired));
        assert_eq!(memory.0.borrow().intent.unwrap().phase, Phase::Writing);
        memory.0.borrow_mut().fail_program = false;
        memory.0.borrow_mut().fail_save_after_program = false;
        let (_, trust) = fixture(&bytes);
        let mut reopened = Update::open(memory.clone(), trust).unwrap();
        assert_eq!(reopened.status().unwrap().unwrap().offset, 0);
        assert_eq!(memory.0.borrow().erases, 2);
        reopened.chunk(digest, 0, &bytes, 7).unwrap();
        reopened.finalize(digest, m.firmware_digest, 7).unwrap();
    }
}

#[test]
fn refuses_corruption_development_executable_and_missing_preserved_image() {
    let bytes = image();
    let (m, trust) = fixture(&bytes);
    let memory = Memory::new();
    let digest = manifest_digest(&m);
    let mut updater = Update::open(memory.clone(), trust).unwrap();
    updater.begin(m, digest, 7).unwrap();
    memory.0.borrow_mut().corrupt = true;
    assert_eq!(updater.chunk(digest, 0, &bytes, 7), Err(Error::Readback));
    assert_eq!(updater.status(), Err(Error::RecoveryRequired));

    let mut dev = image();
    dev[..3].copy_from_slice(b"DEV");
    let (m, trust) = fixture(&dev);
    let digest = manifest_digest(&m);
    let mut updater = Update::open(Memory::new(), trust).unwrap();
    updater.begin(m, digest, 7).unwrap();
    updater.chunk(digest, 0, &dev, 7).unwrap();
    assert_eq!(
        updater.finalize(digest, m.firmware_digest, 7),
        Err(Error::Trust(Rejection::DevelopmentImage))
    );

    let (m, trust) = fixture(&bytes);
    let memory = Memory::new();
    memory.0.borrow_mut().preserved = false;
    let mut updater = Update::open(memory.clone(), trust).unwrap();
    assert_eq!(
        updater.begin(m, manifest_digest(&m), 7),
        Err(Error::Storage(Io))
    );
    assert_eq!(memory.0.borrow().erases, 0);
}

#[test]
fn detects_post_upload_and_post_verified_corruption() {
    let bytes = image();
    for verified in [false, true] {
        let (m, trust) = fixture(&bytes);
        let memory = Memory::new();
        let digest = manifest_digest(&m);
        let mut updater = Update::open(memory.clone(), trust).unwrap();
        updater.begin(m, digest, 7).unwrap();
        updater.chunk(digest, 0, &bytes, 7).unwrap();
        if verified {
            updater.finalize(digest, m.firmware_digest, 7).unwrap();
        }
        memory.0.borrow_mut().bytes[200] ^= 1;
        if verified {
            let (_, trust) = fixture(&bytes);
            assert!(matches!(Update::open(memory, trust), Err(Error::Digest)));
        } else {
            assert_eq!(
                updater.finalize(digest, m.firmware_digest, 7),
                Err(Error::Digest)
            );
        }
    }
}
