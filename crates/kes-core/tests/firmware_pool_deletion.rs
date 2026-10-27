//! Host-isolated tests of firmware deletion admission; no hardware is accessed.
#[allow(dead_code)]
#[path = "journal_faults/flash.rs"]
mod flash;
#[path = "../../../firmware/src/development/pool_deletion.rs"]
mod pool_deletion;

use ed25519_dalek::{Signer, SigningKey};
use kes_core::{
    cbor::{Encoder, Value},
    deletion,
    journal::{
        DirectoryCodec, Flash, Journal, JournalContext, JournalLayout, JournalScope,
        JournalWorkspace, ObjectWorkspace, SecretCache, Workspaces,
    },
    management::{self, Action, SigningFields, Target},
    state::{
        Actor, DeviceConfig, DeviceCredential, DeviceMode, DirectoryEntry, DirectorySnapshot,
        Enrollment, Health, PoolRegistration,
    },
    types::{
        DeviceId, DeviceIdentityBinding, HardwareSlot, IncarnationId, ManagementSequence,
        NetworkBinding, RequestId, Revision,
    },
};
use pool_deletion::{DeletionError, DeletionOutcome};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use sha2::{Digest, Sha256};
use std::{cell::Cell, io::Read};
use zeroize::Zeroizing;

const DEVICE: DeviceId = DeviceId::from_bytes([0x31; 16]);
const SLOT_BYTES: usize = 32768;
const POOL_BASE: usize = 16384;
fn secret() -> Zeroizing<[u8; 32]> {
    xtask::oracles::protect_memory().expect("protected fresh no-swap lab required");
    let mut bytes = Zeroizing::new([0; 32]);
    std::fs::File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut bytes[..])
        .unwrap();
    bytes
}
struct Buffers {
    journal: JournalWorkspace,
    object: ObjectWorkspace,
    cache: SecretCache,
}
impl Buffers {
    fn new() -> Self {
        Self {
            journal: JournalWorkspace::new(),
            object: ObjectWorkspace::new(),
            cache: SecretCache::new(),
        }
    }
    fn work(&mut self) -> Workspaces<'_> {
        Workspaces {
            journal: &mut self.journal,
            object: &mut self.object,
            cache: &mut self.cache,
        }
    }
}
fn pool(index: u8) -> PoolRegistration {
    let recipient_public_key = [index + 1; 32];
    PoolRegistration::new(
        Actor::Management,
        Enrollment {
            incarnation: IncarnationId::from_bytes([index; 16]),
            cold_verification_key: [index; 32],
            network: NetworkBinding::from_genesis_bytes(42, b"isolated deletion", 64, 64).unwrap(),
            machine_public_key: [index + 2; 32],
            recipient_public_key,
            recipient_id: Sha256::digest(recipient_public_key).into(),
            management_sequence: ManagementSequence::new(1),
            management_request: RequestId::from_bytes([index + 3; 16]),
            management_payload_digest: [index + 4; 32],
        },
    )
    .unwrap()
}
struct Fixture {
    root: SigningKey,
    journal: Journal<DirectoryCodec>,
    flash: flash::NorFlash,
    rng: ChaCha20Rng,
    directory: DirectorySnapshot,
    pools: [PoolRegistration; 2],
    buffers: Buffers,
}
impl Fixture {
    fn new() -> Self {
        let root = SigningKey::from_bytes(&secret());
        let mut rng = ChaCha20Rng::from_seed(*secret());
        let journal = Journal::new(
            JournalContext {
                device: DEVICE,
                scope: JournalScope::Directory,
            },
            JournalLayout::directory(0).unwrap(),
            &secret(),
        )
        .unwrap();
        let pools = [pool(7), pool(17)];
        let mut live = [None; kes_core::MAX_POOLS];
        for (index, pool) in pools.iter().enumerate() {
            live[index] = Some(DirectoryEntry::new(
                HardwareSlot::new(index).unwrap(),
                pool.pool_id(),
                pool.incarnation(),
            ));
        }
        let directory = DirectorySnapshot {
            config: DeviceConfig {
                identity: DeviceIdentityBinding::new(DEVICE, [1; 32], [2; 32]),
                silicon_revision: 2,
                firmware_digest: [3; 32],
                security_version: 1,
                hardware_policy_digest: [4; 32],
                mode: DeviceMode::Development,
                health: Health::Healthy,
                management_root_public_key: root.verifying_key().to_bytes(),
                management_transport_public_key: [6; 32],
            },
            revision: Revision::new(0),
            retirement: None,
            credential: DeviceCredential::new([6; 32]),
            pending_deletion: None,
            pending_enrollment: None,
            live,
            tombstones: [None; kes_core::MAX_POOLS],
        };
        let mut flash = flash::NorFlash::new(POOL_BASE + 2 * SLOT_BYTES);
        let mut buffers = Buffers::new();
        journal
            .initialize(&mut flash, &mut rng, &directory, &mut buffers.work())
            .unwrap();
        // Public stand-ins for occupied physical slots; the admission backend
        // must never touch either. The authoritative pool registrations above
        // contain no generated secret and no flash-hardware dependency.
        for index in 0..2 {
            flash
                .program_page(
                    (POOL_BASE + index * SLOT_BYTES) as u32,
                    &[0x53 + index as u8; 256],
                )
                .unwrap();
        }
        Self {
            root,
            journal,
            flash,
            rng,
            directory,
            pools,
            buffers,
        }
    }
    fn execute(
        &mut self,
        bytes: &[u8],
        slot: Option<usize>,
        have_pool: bool,
        cancel: impl FnOnce(kes_core::session::Scope),
    ) -> Result<DeletionOutcome, DeletionError> {
        pool_deletion::execute(
            bytes,
            &self.directory,
            slot.map(|n| HardwareSlot::new(n).unwrap()),
            have_pool.then_some(&self.pools[0]),
            &self.journal,
            &mut self.flash,
            &mut self.rng,
            &mut self.buffers.work(),
            cancel,
        )
    }
    fn refresh(&mut self) {
        self.directory = self
            .journal
            .recover(&mut self.flash, &mut self.rng, &mut self.buffers.work())
            .unwrap()
            .state;
    }
    // Host model of the parent's recovery barrier: erase ONLY the durable
    // intent slot, read every page, then publish the authenticated tombstone.
    fn complete(&mut self) {
        let mut recovered = self
            .journal
            .recover(&mut self.flash, &mut self.rng, &mut self.buffers.work())
            .unwrap();
        let slot = recovered.state.pending_deletion.unwrap().slot;
        let base = POOL_BASE + slot.get() * SLOT_BYTES;
        for offset in (base..base + SLOT_BYTES).step_by(4096) {
            self.flash.erase_sector(offset as u32).unwrap();
        }
        self.flash.invalidate_cache().unwrap();
        for offset in (base..base + SLOT_BYTES).step_by(256) {
            let mut page = [0; 256];
            self.flash.read(offset as u32, &mut page).unwrap();
            assert_eq!(page, [0xff; 256]);
        }
        deletion::finish_delete_after_erasure(&mut recovered.state, slot).unwrap();
        self.journal
            .transact_successor(
                &mut self.flash,
                &mut self.rng,
                &recovered.token,
                &recovered.state,
                &mut self.buffers.work(),
            )
            .unwrap();
        self.refresh();
    }
}
fn request(
    root: &SigningKey,
    pool: &PoolRegistration,
    sequence: u64,
    revision: u64,
    request: u8,
) -> Vec<u8> {
    let payload = [0xa0];
    let fields = SigningFields {
        device: DEVICE,
        target: Target::Pool {
            pool: pool.pool_id(),
            incarnation: pool.incarnation(),
        },
        sequence: ManagementSequence::new(sequence),
        request: RequestId::from_bytes([request; 16]),
        expected_revision: Revision::new(revision),
        action: Action::PoolDelete,
        canonical_payload: Value::parse(&payload).unwrap(),
    };
    let mut message = [0; 4608];
    let n = management::encode_signing_message(fields, &mut message).unwrap();
    let signature = root.sign(&message[..n]);
    let mut bytes = [0; 2048];
    let mut e = Encoder::new(&mut bytes);
    e.map(9).unwrap();
    e.text("pool").unwrap();
    e.bytes(pool.pool_id().as_bytes()).unwrap();
    e.text("action").unwrap();
    e.text("POOL_DELETE").unwrap();
    e.text("device").unwrap();
    e.bytes(DEVICE.as_bytes()).unwrap();
    e.text("request").unwrap();
    e.bytes(&[request; 16]).unwrap();
    e.text("signature").unwrap();
    e.bytes(&signature.to_bytes()).unwrap();
    e.text("incarnation").unwrap();
    e.bytes(pool.incarnation().as_bytes()).unwrap();
    e.text("canonical_payload").unwrap();
    e.bytes(&payload).unwrap();
    e.text("expected_revision").unwrap();
    e.uint(revision).unwrap();
    e.text("management_sequence").unwrap();
    e.uint(sequence).unwrap();
    e.finish().unwrap().encoded().to_vec()
}

#[test]
fn durable_intent_is_not_ack_and_completed_replay_needs_no_erased_pool() {
    let mut f = Fixture::new();
    let bytes = request(&f.root, &f.pools[0], 2, 0, 0x41);
    let physical_before = f.flash.raw()[POOL_BASE..].to_vec();
    let cancelled = Cell::new(false);
    let result = f
        .execute(&bytes, Some(0), true, |scope| {
            assert!(matches!(scope, kes_core::session::Scope::Pool { .. }));
            cancelled.set(true);
        })
        .unwrap();
    assert!(cancelled.get());
    assert!(result.cleanup_required && result.committed_write);
    assert_eq!(result.revision, Revision::new(2));
    assert_eq!(result.sequence, ManagementSequence::new(2));
    assert_eq!(result.affected_slot, HardwareSlot::new(0).ok());
    assert_eq!(&f.flash.raw()[POOL_BASE..], physical_before);
    f.refresh();
    assert!(f.directory.live[0].is_some());
    assert_eq!(
        result.confirm_completed(&f.directory),
        Err(DeletionError::CleanupIncomplete)
    );
    let before = f.flash.raw().to_vec();
    let pending = f.execute(&bytes, Some(0), false, |_| {}).unwrap();
    assert!(pending.cleanup_required && !pending.committed_write);
    assert_eq!(pending.revision, result.revision);
    assert_eq!(f.flash.raw(), before);
    f.complete();
    result.confirm_completed(&f.directory).unwrap();
    assert!(
        !f.directory
            .live
            .iter()
            .flatten()
            .any(|entry| entry.pool_id() == f.pools[0].pool_id())
    );
    assert!(
        f.directory
            .live
            .iter()
            .flatten()
            .any(|entry| entry.pool_id() == f.pools[1].pool_id())
    );
    assert_eq!(
        &f.flash.raw()[POOL_BASE + SLOT_BYTES..],
        &physical_before[SLOT_BYTES..]
    );
    let tombstone = f
        .directory
        .tombstones
        .iter()
        .flatten()
        .find(|t| t.pool_id == f.pools[0].pool_id())
        .unwrap();
    assert_eq!(
        tombstone.credential_epoch,
        Some(f.pools[0].credential_epoch())
    );
    // Later unrelated directory publication must not change the recorded ACK.
    let recovered = f
        .journal
        .recover(&mut f.flash, &mut f.rng, &mut f.buffers.work())
        .unwrap();
    f.directory.revision = Revision::new(3);
    f.journal
        .transact_successor(
            &mut f.flash,
            &mut f.rng,
            &recovered.token,
            &f.directory,
            &mut f.buffers.work(),
        )
        .unwrap();
    let before = f.flash.raw().to_vec();
    let replay = f
        .execute(&bytes, None, false, |_| {
            panic!("completed replay cancelled work")
        })
        .unwrap();
    assert!(!replay.cleanup_required && !replay.committed_write);
    assert_eq!(replay.affected_slot, None);
    assert_eq!(replay.revision, result.revision);
    assert_eq!(f.flash.raw(), before);
}

#[test]
fn invalid_signature_revision_sequence_and_cross_pool_routing_do_not_cancel_or_mutate() {
    let mut f = Fixture::new();
    let wrong = SigningKey::from_bytes(&secret());
    let before = f.flash.raw().to_vec();
    for bytes in [
        request(&wrong, &f.pools[0], 2, 0, 0x41),
        request(&f.root, &f.pools[0], 2, 1, 0x41),
        request(&f.root, &f.pools[0], 3, 0, 0x41),
        request(&f.root, &f.pools[1], 2, 0, 0x41),
    ] {
        assert!(
            f.execute(&bytes, Some(0), true, |_| panic!(
                "invalid deletion cancelled work"
            ))
            .is_err()
        );
        assert_eq!(f.flash.raw(), before);
    }
    let bytes = request(&f.root, &f.pools[0], 2, 0, 0x41);
    assert_eq!(
        f.execute(&bytes, Some(1), true, |_| panic!("wrong slot"))
            .unwrap_err(),
        DeletionError::WrongScope
    );
    f.execute(&bytes, Some(0), true, |_| {}).unwrap();
    f.refresh();
    let changed = request(&f.root, &f.pools[0], 2, 0, 0x42);
    assert_eq!(
        f.execute(&changed, Some(0), false, |_| panic!("changed replay"))
            .unwrap_err(),
        DeletionError::Deletion(deletion::Error::ChangedReplay)
    );
    f.complete();
    assert!(
        f.execute(&changed, None, false, |_| panic!(
            "changed tombstone replay"
        ))
        .is_err()
    );
}

#[test]
fn interrupted_intent_commit_never_reports_success_or_changes_any_pool_bytes() {
    let mut f = Fixture::new();
    let bytes = request(&f.root, &f.pools[0], 2, 0, 0x41);
    let baseline = f.flash.copy_world();
    f.flash.arm_cut_after_bits(usize::MAX);
    f.execute(&bytes, Some(0), true, |_| {}).unwrap();
    let steps = f.flash.steps();
    for cut in [0, 1, 2048, steps / 2, steps.saturating_sub(1)] {
        f.flash = baseline.copy_world();
        f.flash.arm_cut_after_bits(cut);
        assert!(f.execute(&bytes, Some(0), true, |_| {}).is_err());
        assert_eq!(&f.flash.raw()[POOL_BASE..], &baseline.raw()[POOL_BASE..]);
        f.flash.disarm();
        // Once-only CLEAN may quarantine a torn marker; either authenticated
        // recovery succeeds or the backend must fail closed, never initialize.
        if let Ok(recovered) = f
            .journal
            .recover(&mut f.flash, &mut f.rng, &mut f.buffers.work())
        {
            assert!(recovered.state.tombstones.iter().all(Option::is_none));
            assert_eq!(recovered.state.live, f.directory.live);
            f.directory = recovered.state;
            let retry = f.execute(&bytes, Some(0), true, |_| {});
            if let Ok(result) = retry {
                assert!(result.cleanup_required);
                f.refresh();
                assert_eq!(
                    result.confirm_completed(&f.directory),
                    Err(DeletionError::CleanupIncomplete)
                );
            }
        }
        // The next cut starts from the same authenticated baseline authority.
        f.directory.pending_deletion = None;
        f.directory.revision = Revision::new(0);
    }
}

#[test]
fn interrupted_physical_erasure_keeps_durable_intent_and_other_pool_untouched() {
    let mut f = Fixture::new();
    let bytes = request(&f.root, &f.pools[0], 2, 0, 0x41);
    let result = f.execute(&bytes, Some(0), true, |_| {}).unwrap();
    f.refresh();
    let other = f.flash.raw()[POOL_BASE + SLOT_BYTES..].to_vec();
    f.flash.arm_cut_after_bits(17);
    assert!(f.flash.erase_sector(POOL_BASE as u32).is_err());
    f.flash.disarm();
    f.refresh();
    assert_eq!(
        result.confirm_completed(&f.directory),
        Err(DeletionError::CleanupIncomplete)
    );
    assert!(
        f.execute(&bytes, Some(0), false, |_| {})
            .unwrap()
            .cleanup_required
    );
    assert_eq!(&f.flash.raw()[POOL_BASE + SLOT_BYTES..], other);
    f.complete();
    result.confirm_completed(&f.directory).unwrap();
}
