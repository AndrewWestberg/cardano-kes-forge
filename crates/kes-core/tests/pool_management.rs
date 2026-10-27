#[path = "../../../firmware/src/development/pool_management.rs"]
mod pool_management;
#[allow(dead_code)]
mod support;

use ed25519_dalek::{Signer, SigningKey};
use kes_core::{
    activation::DurablePool,
    cbor::{Encoder, Value},
    crypto::Generation,
    generation::{Admission, CheckpointOutcome, GenerationRequest},
    journal::Flash,
    management::{self, Action, SigningFields, Target},
    state::{
        DeviceConfig, DeviceCredential, DeviceMode, DirectoryEntry, DirectorySnapshot, Health,
    },
    types::{
        DeviceId, DeviceIdentityBinding, GenerationNumber, HardwareSlot, KesLifetime,
        ManagementSequence, RequestId, Revision,
    },
};
use rand_chacha::rand_core::TryRngCore;
use sha2::{Digest, Sha256};
use support::Fixture;
use zeroize::Zeroizing;

const DEVICE: DeviceId = DeviceId::from_bytes([0x19; 16]);

fn root(f: &mut Fixture) -> SigningKey {
    let mut seed = Zeroizing::new([0; 32]);
    f.entropy.try_fill_bytes(&mut seed[..]).unwrap();
    SigningKey::from_bytes(&seed)
}
fn directory(f: &Fixture, root: &SigningKey) -> DirectorySnapshot {
    let state = f.durable.state().unwrap();
    let mut live = [None; kes_core::MAX_POOLS];
    live[0] = Some(DirectoryEntry::new(
        HardwareSlot::new(0).unwrap(),
        state.pool_id(),
        state.incarnation(),
    ));
    DirectorySnapshot {
        config: DeviceConfig {
            identity: DeviceIdentityBinding::new(DEVICE, [0x32; 32], [0x33; 32]),
            silicon_revision: 2,
            firmware_digest: [0x34; 32],
            security_version: 1,
            hardware_policy_digest: [0x35; 32],
            mode: DeviceMode::Development,
            health: Health::Healthy,
            management_root_public_key: root.verifying_key().to_bytes(),
            management_transport_public_key: [0x36; 32],
        },
        revision: Revision::new(0),
        retirement: None,
        credential: DeviceCredential::new([0x36; 32]),
        pending_deletion: None,
        pending_enrollment: None,
        live,
        tombstones: [None; kes_core::MAX_POOLS],
    }
}
fn payload(action: Action, generation: &[u8; 16], epoch: u64) -> Vec<u8> {
    let mut bytes = [0; 256];
    let mut e = Encoder::new(&mut bytes);
    match action {
        Action::CredentialReplace => {
            e.map(2).unwrap();
            e.text("credential_epoch").unwrap();
            e.uint(epoch).unwrap();
            e.text("machine_public_key").unwrap();
            e.bytes(&[0x91; 32]).unwrap();
        }
        Action::CredentialRevoke => {
            e.map(1).unwrap();
            e.text("credential_epoch").unwrap();
            e.uint(epoch).unwrap();
        }
        Action::RecipientReplace => {
            e.map(2).unwrap();
            e.text("recipient_id").unwrap();
            e.bytes(&Sha256::digest([0x92; 32])).unwrap();
            e.text("recipient_public_key").unwrap();
            e.bytes(&[0x92; 32]).unwrap();
        }
        Action::StagedDiscard => {
            e.map(1).unwrap();
            e.text("generation").unwrap();
            e.bytes(generation).unwrap();
        }
        _ => unreachable!(),
    }
    e.finish().unwrap().encoded().to_vec()
}
fn signed(
    root: &SigningKey,
    target: Target,
    action: Action,
    sequence: u64,
    revision: Revision,
    request: u8,
    payload: &[u8],
) -> Vec<u8> {
    let fields = SigningFields {
        device: DEVICE,
        target,
        sequence: ManagementSequence::new(sequence),
        request: RequestId::from_bytes([request; 16]),
        expected_revision: revision,
        action,
        canonical_payload: Value::parse(payload).unwrap(),
    };
    let mut message = [0; 4608];
    let n = management::encode_signing_message(fields, &mut message).unwrap();
    let signature = root.sign(&message[..n]);
    let Target::Pool { pool, incarnation } = target else {
        unreachable!()
    };
    let mut bytes = [0; 6144];
    let mut e = Encoder::new(&mut bytes);
    e.map(9).unwrap();
    e.text("pool").unwrap();
    e.bytes(pool.as_bytes()).unwrap();
    e.text("action").unwrap();
    e.text(action.name()).unwrap();
    e.text("device").unwrap();
    e.bytes(DEVICE.as_bytes()).unwrap();
    e.text("request").unwrap();
    e.bytes(&[request; 16]).unwrap();
    e.text("signature").unwrap();
    e.bytes(&signature.to_bytes()).unwrap();
    e.text("incarnation").unwrap();
    e.bytes(incarnation.as_bytes()).unwrap();
    e.text("canonical_payload").unwrap();
    e.bytes(payload).unwrap();
    e.text("expected_revision").unwrap();
    e.uint(revision.get()).unwrap();
    e.text("management_sequence").unwrap();
    e.uint(sequence).unwrap();
    e.finish().unwrap().encoded().to_vec()
}
fn target(f: &Fixture) -> Target {
    let p = f.durable.state().unwrap();
    Target::Pool {
        pool: p.pool_id(),
        incarnation: p.incarnation(),
    }
}
fn execute(
    f: &mut Fixture,
    directory: &DirectorySnapshot,
    encoded: &[u8],
    cancel: impl FnOnce(kes_core::types::GenerationId),
) -> Result<pool_management::ManagementOutcome, pool_management::ManagementError> {
    pool_management::execute(
        encoded,
        directory,
        HardwareSlot::new(0).unwrap(),
        &mut f.durable,
        &f.journal,
        &mut f.flash,
        &mut f.entropy,
        &mut f.buffers.work(),
        cancel,
    )
}

#[test]
fn signed_policy_commits_and_exact_retry_preserves_immutable_object() {
    for action in [
        Action::CredentialReplace,
        Action::CredentialRevoke,
        Action::RecipientReplace,
    ] {
        let mut f = Fixture::new();
        let root = root(&mut f);
        let directory = directory(&f, &root);
        let revision = f.durable.state().unwrap().revision();
        let reference = *f
            .durable
            .state()
            .unwrap()
            .staged()
            .unwrap()
            .public_object_ref();
        let mut before = vec![0; usize::from(reference.total_length)];
        f.flash
            .read(f.layout.object_offset(0).unwrap(), &mut before)
            .unwrap();
        let request = signed(
            &root,
            target(&f),
            action,
            2,
            revision,
            0x41,
            &payload(action, f.generation.as_bytes(), 1),
        );
        let outcome = execute(&mut f, &directory, &request, |_| panic!("no live job")).unwrap();
        assert!(outcome.durable.committed_write);
        assert_eq!(
            outcome.invalidate_pool_sessions,
            action != Action::RecipientReplace
        );
        assert_eq!(
            f.durable
                .state()
                .unwrap()
                .staged()
                .unwrap()
                .public_object_ref(),
            &reference
        );
        let retry = execute(&mut f, &directory, &request, |_| {
            panic!("retry must not cancel")
        })
        .unwrap();
        assert!(!retry.durable.committed_write);
        assert_eq!(retry.durable.revision, outcome.durable.revision);
        let mut after = vec![0; before.len()];
        f.flash
            .read(f.layout.object_offset(0).unwrap(), &mut after)
            .unwrap();
        assert_eq!(before, after);
        let recovered = f
            .journal
            .recover(&mut f.flash, &mut f.entropy, &mut f.buffers.work())
            .unwrap();
        assert_eq!(recovered.state.revision(), outcome.durable.revision);
        assert_eq!(recovered.state.management_sequence().get(), 2);
        assert_eq!(directory.revision.get(), 0);
    }
}

#[test]
fn rejected_signatures_scopes_replays_epochs_and_revisions_never_cancel() {
    let mut f = Fixture::new();
    let root = root(&mut f);
    let directory = directory(&f, &root);
    let other_root = self::root(&mut f);
    let revision = f.durable.state().unwrap().revision();
    let action = Action::CredentialReplace;
    let data = payload(action, f.generation.as_bytes(), 1);
    let valid = signed(&root, target(&f), action, 2, revision, 0x41, &data);
    let wrong_root = signed(&other_root, target(&f), action, 2, revision, 0x41, &data);
    assert!(
        execute(&mut f, &directory, &wrong_root, |_| panic!(
            "unauthorized cancel"
        ))
        .is_err()
    );
    for (sequence, revision, epoch) in [
        (1, revision, 1),
        (3, revision, 1),
        (2, Revision::new(999), 1),
        (2, revision, 7),
    ] {
        let request = signed(
            &root,
            target(&f),
            action,
            sequence,
            revision,
            0x41,
            &payload(action, f.generation.as_bytes(), epoch),
        );
        assert!(
            execute(&mut f, &directory, &request, |_| panic!(
                "invalid precondition cancel"
            ))
            .is_err()
        );
    }
    let mut wrong_scope = self::directory(&f, &root);
    wrong_scope.live[0] = None;
    assert!(
        execute(&mut f, &wrong_scope, &valid, |_| panic!(
            "wrong scope cancel"
        ))
        .is_err()
    );
    execute(&mut f, &directory, &valid, |_| panic!("no live job")).unwrap();
    let changed = signed(&root, target(&f), action, 2, revision, 0x42, &data);
    assert!(
        execute(&mut f, &directory, &changed, |_| panic!(
            "changed replay cancel"
        ))
        .is_err()
    );
}

#[test]
fn staged_discard_cleans_object_and_owned_policy_cancellation_is_terminal() {
    let mut f = Fixture::new();
    let root = root(&mut f);
    let directory = directory(&f, &root);
    let revision = f.durable.state().unwrap().revision();
    let discard = signed(
        &root,
        target(&f),
        Action::StagedDiscard,
        2,
        revision,
        0x43,
        &payload(Action::StagedDiscard, f.generation.as_bytes(), 0),
    );
    execute(&mut f, &directory, &discard, |_| {
        panic!("discard does not cancel job")
    })
    .unwrap();
    assert!(f.durable.state().unwrap().staged().is_none());
    let recovered = f
        .journal
        .recover(&mut f.flash, &mut f.entropy, &mut f.buffers.work())
        .unwrap();
    f.durable = DurablePool::from_recovered(recovered);
    let mut erased = [0; 256];
    f.flash
        .read(f.layout.object_offset(0).unwrap(), &mut erased)
        .unwrap();
    assert_eq!(erased, [0xff; 256]);
    assert!(
        !execute(&mut f, &directory, &discard, |_| panic!("retry"))
            .unwrap()
            .durable
            .committed_write
    );
    let request = GenerationRequest {
        actor: f.actor,
        request: RequestId::from_bytes([0x44; 16]),
        payload_digest: [0x45; 32],
        next_generation_number: GenerationNumber::new(2),
        expected_revision: f.durable.state().unwrap().revision(),
    };
    let Admission::Started(operation) = f
        .durable
        .admit_generation(
            request,
            &f.journal,
            &mut f.flash,
            &mut f.entropy,
            &mut f.buffers.work(),
        )
        .unwrap()
    else {
        panic!("admit")
    };
    let mut seed = Zeroizing::new([0; 32]);
    f.entropy.try_fill_bytes(&mut seed[..]).unwrap();
    let mut job = Some(Generation::begin(&mut seed, KesLifetime::new(64).unwrap()).unwrap());
    job.as_mut().unwrap().step().unwrap();
    let revision = f.durable.state().unwrap().revision();
    let replace = signed(
        &root,
        target(&f),
        Action::RecipientReplace,
        3,
        revision,
        0x46,
        &payload(Action::RecipientReplace, f.generation.as_bytes(), 0),
    );
    let stale = signed(
        &root,
        target(&f),
        Action::RecipientReplace,
        3,
        Revision::new(999),
        0x46,
        &payload(Action::RecipientReplace, f.generation.as_bytes(), 0),
    );
    assert!(
        execute(&mut f, &directory, &stale, |_| panic!(
            "must keep actual job"
        ))
        .is_err()
    );
    assert!(job.is_some());
    let outcome = execute(&mut f, &directory, &replace, |generation| {
        assert_eq!(generation, operation.generation());
        drop(job.take().unwrap());
    })
    .unwrap();
    assert!(job.is_none());
    assert_eq!(
        outcome.durable.cancelled_generation,
        Some(operation.generation())
    );
    assert_eq!(
        f.durable
            .state()
            .unwrap()
            .generation_checkpoint()
            .unwrap()
            .outcome,
        CheckpointOutcome::NotCommitted
    );
    assert!(
        f.durable
            .restart_generation(
                request,
                &f.journal,
                &mut f.flash,
                &mut f.entropy,
                &mut f.buffers.work()
            )
            .is_err()
    );
    assert!(
        f.durable
            .complete_generation::<_, _, ()>(
                &f.journal,
                &mut f.flash,
                &mut f.entropy,
                &mut f.buffers.work(),
                |_, _, _, _| panic!("cancelled job must never reach object publication"),
            )
            .is_err()
    );
    let recovered = f
        .journal
        .recover(&mut f.flash, &mut f.entropy, &mut f.buffers.work())
        .unwrap();
    assert_eq!(
        recovered.state.generation_checkpoint().unwrap().outcome,
        CheckpointOutcome::NotCommitted
    );
}

#[test]
fn interrupted_policy_write_never_acknowledges_or_leaves_usable_ram() {
    let mut f = Fixture::new();
    let root = root(&mut f);
    let directory = directory(&f, &root);
    let old_revision = f.durable.state().unwrap().revision();
    let request = signed(
        &root,
        target(&f),
        Action::CredentialRevoke,
        2,
        old_revision,
        0x47,
        &payload(Action::CredentialRevoke, f.generation.as_bytes(), 1),
    );
    f.flash.fail_next_mutation();
    assert!(execute(&mut f, &directory, &request, |_| panic!("no active job")).is_err());
    assert!(!f.durable.is_usable());
    assert!(f.durable.state().is_err());
    f.durable = DurablePool::from_recovered(
        f.journal
            .recover(&mut f.flash, &mut f.entropy, &mut f.buffers.work())
            .unwrap(),
    );
    assert_eq!(f.durable.state().unwrap().revision(), old_revision);
    assert!(!f.durable.state().unwrap().credential_revoked());
    execute(&mut f, &directory, &request, |_| panic!("no active job")).unwrap();
    assert!(f.durable.state().unwrap().credential_revoked());
}

struct Interrupt<'a, F> {
    inner: &'a mut F,
    remaining: usize,
    triggered: bool,
}
impl<F> Interrupt<'_, F> {
    fn cut(&mut self) -> Result<(), ()> {
        if !self.triggered && self.remaining == 0 {
            self.triggered = true;
            return Err(());
        }
        self.remaining = self.remaining.saturating_sub(1);
        Ok(())
    }
}
impl<F: Flash> Flash for Interrupt<'_, F> {
    type Error = ();
    fn capacity(&self) -> u32 {
        self.inner.capacity()
    }
    fn rules(&self) -> kes_core::journal::FlashRules {
        self.inner.rules()
    }
    fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<(), ()> {
        self.inner.read(offset, out).map_err(|_| ())
    }
    fn program_page(&mut self, offset: u32, page: &[u8; 256]) -> Result<(), ()> {
        self.cut()?;
        self.inner.program_page(offset, page).map_err(|_| ())
    }
    fn erase_sector(&mut self, offset: u32) -> Result<(), ()> {
        self.cut()?;
        self.inner.erase_sector(offset).map_err(|_| ())
    }
    fn invalidate_cache(&mut self) -> Result<(), ()> {
        self.inner.invalidate_cache().map_err(|_| ())
    }
}

#[test]
fn policy_write_interruptions_recover_one_authoritative_result_and_retry() {
    // Cover snapshot pages, COMMIT, predecessor cleanup and CLEAN. Flash cuts
    // happen before mutations; partial-page NOR cuts are covered by journal_faults.
    let mut saw_committed_interruption = false;
    let mut saw_old_interruption = false;
    for cut in 0..24 {
        let mut f = Fixture::new();
        let root = root(&mut f);
        let directory = directory(&f, &root);
        let old_revision = f.durable.state().unwrap().revision();
        let request = signed(
            &root,
            target(&f),
            Action::CredentialRevoke,
            2,
            old_revision,
            0x48,
            &payload(Action::CredentialRevoke, f.generation.as_bytes(), 1),
        );
        let result = {
            let mut flash = Interrupt {
                inner: &mut f.flash,
                remaining: cut,
                triggered: false,
            };
            pool_management::execute(
                &request,
                &directory,
                HardwareSlot::new(0).unwrap(),
                &mut f.durable,
                &f.journal,
                &mut flash,
                &mut f.entropy,
                &mut f.buffers.work(),
                |_| panic!("no live job"),
            )
        };
        if result.is_err() {
            assert!(!f.durable.is_usable());
        }
        let recovered = f
            .journal
            .recover(&mut f.flash, &mut f.entropy, &mut f.buffers.work())
            .unwrap();
        let committed = recovered.state.credential_revoked();
        // A torn CLEAN page can require recreating the authoritative successor
        // at a higher revision; its recorded management result stays unchanged.
        assert!(recovered.state.revision().get() >= old_revision.get() + u64::from(committed));
        assert_eq!(
            recovered.state.management_sequence().get(),
            if committed { 2 } else { 1 }
        );
        if result.is_err() {
            saw_committed_interruption |= committed;
            saw_old_interruption |= !committed;
        }
        f.durable = DurablePool::from_recovered(recovered);
        let retry = execute(&mut f, &directory, &request, |_| {
            panic!("retry has no live job")
        })
        .unwrap();
        assert_eq!(retry.durable.committed_write, !committed);
        assert!(f.durable.state().unwrap().credential_revoked());
    }
    assert!(saw_committed_interruption);
    assert!(saw_old_interruption);
}

#[test]
fn signed_wrong_incarnation_slot_device_and_stale_discard_fail_closed() {
    let mut f = Fixture::new();
    let root = root(&mut f);
    let directory = directory(&f, &root);
    let revision = f.durable.state().unwrap().revision();
    let Target::Pool { pool, .. } = target(&f) else {
        unreachable!()
    };
    let wrong_incarnation = signed(
        &root,
        Target::Pool {
            pool,
            incarnation: kes_core::types::IncarnationId::from_bytes([0xff; 16]),
        },
        Action::CredentialRevoke,
        2,
        revision,
        0x49,
        &payload(Action::CredentialRevoke, f.generation.as_bytes(), 1),
    );
    assert!(
        execute(&mut f, &directory, &wrong_incarnation, |_| panic!(
            "wrong incarnation"
        ))
        .is_err()
    );
    let valid = signed(
        &root,
        target(&f),
        Action::CredentialRevoke,
        2,
        revision,
        0x49,
        &payload(Action::CredentialRevoke, f.generation.as_bytes(), 1),
    );
    assert!(
        pool_management::execute(
            &valid,
            &directory,
            HardwareSlot::new(1).unwrap(),
            &mut f.durable,
            &f.journal,
            &mut f.flash,
            &mut f.entropy,
            &mut f.buffers.work(),
            |_| panic!("wrong slot")
        )
        .is_err()
    );
    let mut wrong_device = self::directory(&f, &root);
    wrong_device.config.identity =
        DeviceIdentityBinding::new(DeviceId::from_bytes([0xff; 16]), [0x32; 32], [0x33; 32]);
    assert!(execute(&mut f, &wrong_device, &valid, |_| panic!("wrong device")).is_err());
    let stale = signed(
        &root,
        target(&f),
        Action::StagedDiscard,
        2,
        revision,
        0x49,
        &payload(Action::StagedDiscard, &[0xff; 16], 0),
    );
    assert!(execute(&mut f, &directory, &stale, |_| panic!("stale generation")).is_err());
    assert_eq!(f.durable.state().unwrap().revision(), revision);
    assert_eq!(
        f.durable.state().unwrap().staged().unwrap().id(),
        f.generation
    );
}
