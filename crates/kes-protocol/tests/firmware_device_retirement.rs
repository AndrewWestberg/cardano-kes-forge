//! Host tests of firmware deny preparation; a preparation is never cleanup ACK.
#[path = "../../../firmware/src/development/device_retirement.rs"]
mod device_retirement;
#[allow(dead_code)]
#[path = "../../kes-core/tests/journal_faults/flash.rs"]
mod flash;

use device_retirement::{RetirementError, RetirementPreparation};
use ed25519_dalek::{Signer, SigningKey};
use kes_core::{
    cbor::{Encoder, Value},
    journal::{
        DirectoryCodec, Journal, JournalContext, JournalLayout, JournalScope, JournalWorkspace,
        ObjectWorkspace, SecretCache, Workspaces,
    },
    management::{self, Action, SigningFields, Target},
    state::{
        DeviceConfig, DeviceCredential, DeviceMode, DirectoryEntry, DirectorySnapshot, Health,
    },
    types::{
        DeviceId, DeviceIdentityBinding, HardwareSlot, IncarnationId, ManagementSequence, PoolId,
        RequestId, Revision,
    },
};
use kes_protocol::{Envelope, EnvelopeKind};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use std::{cell::Cell, io::Read};
use zeroize::Zeroizing;

const DEVICE: DeviceId = DeviceId::from_bytes([0x31; 16]);
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
struct Fixture {
    root: SigningKey,
    journal: Journal<DirectoryCodec>,
    flash: flash::NorFlash,
    rng: ChaCha20Rng,
    directory: DirectorySnapshot,
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
        let mut live = [None; kes_core::MAX_POOLS];
        live[0] = Some(DirectoryEntry::new(
            HardwareSlot::new(0).unwrap(),
            PoolId::from_cold_verification_key(&[7; 32]),
            IncarnationId::from_bytes([8; 16]),
        ));
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
        let mut flash = flash::NorFlash::new(16384);
        let mut buffers = Buffers::new();
        journal
            .initialize(&mut flash, &mut rng, &directory, &mut buffers.work())
            .unwrap();
        Self {
            root,
            journal,
            flash,
            rng,
            directory,
            buffers,
        }
    }
    fn prepare(
        &mut self,
        bytes: &[u8],
        cancel: impl FnOnce(),
    ) -> Result<RetirementPreparation, device_retirement::RetirementFailure> {
        device_retirement::prepare(
            Envelope::parse(bytes, EnvelopeKind::DeviceRequest).unwrap(),
            &self.directory,
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
}

fn request(
    root: &SigningKey,
    sequence: u64,
    revision: u64,
    request: u8,
    action: Action,
) -> Vec<u8> {
    let payload = [0xa0];
    let fields = SigningFields {
        device: DEVICE,
        target: Target::Device,
        sequence: ManagementSequence::new(sequence),
        request: RequestId::from_bytes([request; 16]),
        expected_revision: Revision::new(revision),
        action,
        canonical_payload: Value::parse(&payload).unwrap(),
    };
    let mut message = [0; 4608];
    let n = management::encode_signing_message(fields, &mut message).unwrap();
    let signature = root.sign(&message[..n]);
    let mut signed = [0; 6144];
    let mut e = Encoder::new(&mut signed);
    e.map(9).unwrap();
    e.text("pool").unwrap();
    e.null().unwrap();
    e.text("action").unwrap();
    e.text(action.name()).unwrap();
    e.text("device").unwrap();
    e.bytes(DEVICE.as_bytes()).unwrap();
    e.text("request").unwrap();
    e.bytes(&[request; 16]).unwrap();
    e.text("signature").unwrap();
    e.bytes(&signature.to_bytes()).unwrap();
    e.text("incarnation").unwrap();
    e.null().unwrap();
    e.text("canonical_payload").unwrap();
    e.bytes(&payload).unwrap();
    e.text("expected_revision").unwrap();
    e.uint(revision).unwrap();
    e.text("management_sequence").unwrap();
    e.uint(sequence).unwrap();
    let signed = e.finish().unwrap();
    let mut bytes = [0; 8192];
    let mut e = Encoder::new(&mut bytes);
    // Canonical key order: encoded length first, then lexical order.
    e.map(11).unwrap();
    e.text("op").unwrap();
    e.text("MANAGE").unwrap();
    e.text("mac").unwrap();
    e.bytes(&[0; 32]).unwrap();
    e.text("seq").unwrap();
    e.uint(1).unwrap();
    e.text("pool").unwrap();
    e.null().unwrap();
    e.text("device").unwrap();
    e.bytes(DEVICE.as_bytes()).unwrap();
    e.text("payload").unwrap();
    e.value(signed).unwrap();
    e.text("request").unwrap();
    e.bytes(&[request; 16]).unwrap();
    e.text("session").unwrap();
    e.bytes(&[9; 16]).unwrap();
    e.text("version").unwrap();
    e.uint(1).unwrap();
    e.text("budget_ms").unwrap();
    e.uint(1000).unwrap();
    e.text("incarnation").unwrap();
    e.null().unwrap();
    e.finish().unwrap().encoded().to_vec()
}

#[test]
fn deny_marker_and_exact_replay_are_only_preparation_even_with_live_pools() {
    let mut f = Fixture::new();
    let bytes = request(&f.root, 1, 0, 0x41, Action::DeviceRetire);
    let cancelled = Cell::new(false);
    let result = f.prepare(&bytes, || cancelled.set(true)).unwrap();
    assert!(cancelled.get());
    assert!(result.committed_write);
    assert_eq!(result.revision, Revision::new(1));
    assert_eq!(result.sequence, ManagementSequence::new(1));
    f.refresh();
    assert!(f.directory.retirement.is_some());
    assert!(
        f.directory.live[0].is_some(),
        "deny preparation must not claim pool cleanup"
    );
    let before = f.flash.raw().to_vec();
    let replay = f
        .prepare(&bytes, || panic!("exact replay must not cancel again"))
        .unwrap();
    assert!(!replay.committed_write);
    assert_eq!(replay.revision, result.revision);
    assert_eq!(f.flash.raw(), before);
    // Cleanup recovery can advance the journal without changing the signed result.
    let ready = f
        .journal
        .recover(&mut f.flash, &mut f.rng, &mut f.buffers.work())
        .unwrap();
    f.directory.revision = Revision::new(2);
    f.journal
        .transact_successor(
            &mut f.flash,
            &mut f.rng,
            &ready.token,
            &f.directory,
            &mut f.buffers.work(),
        )
        .unwrap();
    assert_eq!(
        f.prepare(&bytes, || panic!("retry")).unwrap().revision,
        Revision::new(1)
    );
}

#[test]
fn malformed_root_stale_sequence_revision_and_changed_replays_do_not_cancel() {
    let mut f = Fixture::new();
    let other = SigningKey::from_bytes(&secret());
    let before = f.flash.raw().to_vec();
    for bytes in [
        request(&other, 1, 0, 0x41, Action::DeviceRetire),
        request(&f.root, 2, 0, 0x41, Action::DeviceRetire),
        request(&f.root, 1, 1, 0x41, Action::DeviceRetire),
    ] {
        let err = f
            .prepare(&bytes, || panic!("invalid request cancelled work"))
            .unwrap_err();
        assert!(!err.teardown_required);
        assert_eq!(f.flash.raw(), before);
    }
    let valid = request(&f.root, 1, 0, 0x41, Action::DeviceRetire);
    let mut malformed = valid.clone();
    // Corrupt the actual offline signature while retaining a structurally valid envelope.
    let parsed = Envelope::parse(&valid, EnvelopeKind::DeviceRequest).unwrap();
    let sig = parsed
        .payload()
        .required("signature")
        .unwrap()
        .bytes()
        .unwrap();
    let offset = sig.as_ptr() as usize - valid.as_ptr() as usize;
    malformed[offset] ^= 0x80;
    assert!(matches!(
        f.prepare(&malformed, || panic!("bad signature"))
            .unwrap_err()
            .error,
        RetirementError::Authorization(_)
    ));
    assert!(Envelope::parse(&valid[..valid.len() - 1], EnvelopeKind::DeviceRequest).is_err());
    f.prepare(&valid, || {}).unwrap();
    // The transport authenticated against revision zero; recovery now sees deny.
    let stale = f.prepare(&valid, || panic!("stale authority")).unwrap_err();
    assert_eq!(stale.error, RetirementError::StaleAuthority);
    assert!(stale.teardown_required);
    f.refresh();
    for bytes in [
        request(&f.root, 1, 0, 0x42, Action::DeviceRetire),
        request(&f.root, 1, 1, 0x41, Action::DeviceRetire),
        request(&f.root, 2, 1, 0x41, Action::DeviceRetire),
    ] {
        assert!(f.prepare(&bytes, || panic!("changed replay")).is_err());
    }
}

#[test]
fn interrupted_deny_publication_never_authorizes_success_and_requires_teardown() {
    let mut f = Fixture::new();
    let bytes = request(&f.root, 1, 0, 0x41, Action::DeviceRetire);
    let baseline = f.flash.copy_world();
    f.flash.arm_cut_after_bits(usize::MAX);
    f.prepare(&bytes, || {}).unwrap();
    let total = f.flash.steps();
    for cut in [
        0,
        1,
        2047,
        2048,
        total / 2,
        total.saturating_sub(2049),
        total.saturating_sub(2048),
        total.saturating_sub(1),
        total,
    ] {
        f.flash = baseline.copy_world();
        f.refresh();
        f.flash.arm_cut_after_bits(cut);
        let cancelled = Cell::new(false);
        let outcome = f.prepare(&bytes, || cancelled.set(true));
        assert!(cancelled.get());
        if let Err(failure) = outcome {
            assert!(
                failure.teardown_required,
                "write uncertainty must destroy live authority"
            );
        }
        f.flash.disarm();
        f.refresh();
        assert!(
            f.directory.live[0].is_some(),
            "preparation cannot acknowledge physical cleanup"
        );
        let replay = f.directory.retirement.is_some();
        let prepared = f.prepare(&bytes, || assert!(!replay)).unwrap();
        assert_eq!(prepared.committed_write, !replay);
        assert_eq!(prepared.revision, Revision::new(1));
        f.refresh();
        assert!(f.directory.retirement.is_some());
    }
}

#[test]
fn stale_authenticated_snapshot_cannot_authorize_a_new_retirement() {
    let mut f = Fixture::new();
    let bytes = request(&f.root, 1, 0, 0x41, Action::DeviceRetire);
    let ready = f
        .journal
        .recover(&mut f.flash, &mut f.rng, &mut f.buffers.work())
        .unwrap();
    let mut successor = ready.state;
    successor.revision = Revision::new(1);
    f.journal
        .transact_successor(
            &mut f.flash,
            &mut f.rng,
            &ready.token,
            &successor,
            &mut f.buffers.work(),
        )
        .unwrap();
    let before = f.flash.raw().to_vec();
    let error = f
        .prepare(&bytes, || {
            panic!("stale transport authority cancelled work")
        })
        .unwrap_err();
    assert_eq!(error.error, RetirementError::StaleAuthority);
    assert!(!error.teardown_required);
    assert_eq!(f.flash.raw(), before);
    f.refresh();
    let error = f
        .prepare(&bytes, || panic!("stale signed revision cancelled work"))
        .unwrap_err();
    assert!(matches!(
        error.error,
        RetirementError::Retirement(kes_core::retirement::Error::RevisionConflict)
    ));
    assert!(!error.teardown_required);
    assert!(f.directory.retirement.is_none());
}

#[test]
fn wrong_storage_authentication_cannot_turn_ram_authority_into_a_deny_marker() {
    let mut f = Fixture::new();
    let bytes = request(&f.root, 1, 0, 0x41, Action::DeviceRetire);
    f.journal = Journal::new(
        JournalContext {
            device: DEVICE,
            scope: JournalScope::Directory,
        },
        JournalLayout::directory(0).unwrap(),
        &secret(),
    )
    .unwrap();
    let error = f
        .prepare(&bytes, || {
            panic!("unauthenticated directory cancelled work")
        })
        .unwrap_err();
    assert!(matches!(error.error, RetirementError::Journal(_)));
    assert!(error.teardown_required);
}
