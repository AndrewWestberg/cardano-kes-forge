#[allow(dead_code)]
#[path = "journal_faults/flash.rs"]
mod flash;
#[allow(dead_code)]
#[path = "../../../firmware/src/pool_service.rs"]
mod pool_service;
#[allow(dead_code)]
mod support;

use flash::NorFlash;
use kes_core::{
    activation::DurablePool,
    crypto::KesKey,
    generation::{self, Admission, CheckpointOutcome, GenerationRequest, OperationStatus},
    journal::{Flash, Journal, JournalContext, JournalScope, PoolCodec, SnapshotCodec},
    state::{Actor, Enrollment, PoolRegistration},
    types::{
        DeviceId, GenerationNumber, HardwareSlot, KesLifetime, ManagementSequence, RequestId,
        Revision,
    },
};
use pool_service::FlashPublicObjects;
use rand_chacha::rand_core::TryRngCore;
use support::Fixture;
use zeroize::Zeroizing;

// All private material comes from the existing protected, OS-entropy fixture.
// NOR world copies below contain encrypted snapshots/public data only.
fn setup(f: &mut Fixture) -> (NorFlash, Journal<PoolCodec>, DurablePool, GenerationRequest) {
    let source = f.durable.state().unwrap();
    let pool = PoolRegistration::new(
        Actor::Management,
        Enrollment {
            incarnation: source.incarnation(),
            cold_verification_key: *source.cold_verification_key(),
            network: f.network,
            machine_public_key: *source.credential_public_key(),
            recipient_public_key: *source.recipient_public_key(),
            recipient_id: *source.recipient_id(),
            management_sequence: ManagementSequence::new(1),
            management_request: RequestId::from_bytes([0x21; 16]),
            management_payload_digest: [0x22; 32],
        },
    )
    .unwrap();
    let mut root = Zeroizing::new([0; 32]);
    f.entropy.try_fill_bytes(&mut root[..]).unwrap();
    let journal = Journal::<PoolCodec>::new(
        JournalContext {
            device: DeviceId::from_bytes([0x23; 16]),
            scope: JournalScope::Pool {
                slot: HardwareSlot::new(0).unwrap(),
                pool: pool.pool_id(),
                incarnation: pool.incarnation(),
            },
        },
        f.layout,
        &root,
    )
    .unwrap();
    let request = GenerationRequest {
        actor: f.actor,
        request: RequestId::from_bytes([0x24; 16]),
        payload_digest: [0x25; 32],
        next_generation_number: GenerationNumber::new(1),
        expected_revision: Revision::new(0),
    };
    let mut flash = NorFlash::new(32768);
    let token = journal
        .initialize(&mut flash, &mut f.entropy, &pool, &mut f.buffers.work())
        .unwrap();
    (
        flash,
        journal,
        DurablePool::new(pool, token).unwrap(),
        request,
    )
}

#[test]
fn lost_ack_restart_explicit_retry_and_exactly_one_committed_generation() {
    let mut f = Fixture::new();
    let (mut flash, journal, mut pool, request) = setup(&mut f);
    let Admission::Started(operation) = pool
        .admit_generation(
            request,
            &journal,
            &mut flash,
            &mut f.entropy,
            &mut f.buffers.work(),
        )
        .unwrap()
    else {
        panic!("must admit")
    };
    let identity = operation.generation();
    let checkpoint = pool.state().unwrap().generation_checkpoint().unwrap();
    assert_eq!(checkpoint.policy, pool.state().unwrap().generation_policy());
    assert_eq!(checkpoint.expected_revision, request.expected_revision);
    assert!(matches!(
        pool.admit_generation(
            request,
            &journal,
            &mut flash,
            &mut f.entropy,
            &mut f.buffers.work()
        )
        .unwrap(),
        Admission::Existing(OperationStatus::InProgress { .. })
    ));
    assert!(
        pool.admit_generation(
            GenerationRequest {
                payload_digest: [0x99; 32],
                ..request
            },
            &journal,
            &mut flash,
            &mut f.entropy,
            &mut f.buffers.work()
        )
        .is_err()
    );
    // A physical unpublished object must be erased/read-verified before abort.
    flash
        .program_page(f.layout.object_offset(0).unwrap(), &[0; 256])
        .unwrap();
    // Retain only the non-secret old handle to prove it cannot act after retry.
    let stale_operation = operation;
    drop(pool);
    let raw = journal
        .recover(&mut flash, &mut f.entropy, &mut f.buffers.work())
        .unwrap();
    assert_eq!(raw.state.generation_checkpoint().unwrap(), checkpoint);
    drop(raw);
    let mut pool = DurablePool::recover_generation(
        &journal,
        &mut flash,
        &mut f.entropy,
        &mut f.buffers.work(),
    )
    .unwrap();
    assert!(flash.raw()[8192..24576].iter().all(|b| *b == 0xff));
    assert_eq!(
        pool.state()
            .unwrap()
            .generation_checkpoint()
            .unwrap()
            .generation,
        identity
    );
    assert!(matches!(
        pool.generation_status(request.request, Some(request.next_generation_number))
            .unwrap(),
        OperationStatus::NotCommitted { .. }
    ));
    assert!(matches!(
        pool.admit_generation(
            request,
            &journal,
            &mut flash,
            &mut f.entropy,
            &mut f.buffers.work()
        )
        .unwrap(),
        Admission::Existing(OperationStatus::NotCommitted { .. })
    ));
    let operation = pool
        .restart_generation(
            request,
            &journal,
            &mut flash,
            &mut f.entropy,
            &mut f.buffers.work(),
        )
        .unwrap();
    assert_eq!(operation.generation(), identity);
    assert_eq!(
        pool.state()
            .unwrap()
            .generation_checkpoint()
            .unwrap()
            .attempt,
        1
    );
    let mut erased = KesKey::erased(KesLifetime::new(64).unwrap());
    assert!(
        pool.cancel_generation(
            stale_operation,
            &mut erased,
            &journal,
            &mut flash,
            &mut f.entropy,
            &mut f.buffers.work()
        )
        .is_err()
    );
    assert!(pool.is_usable());
    let mut job = generation::begin_key_generation(&mut f.entropy, KesLifetime::new(64).unwrap()).unwrap();
    for _ in 0..64 {
        job.step().unwrap();
    }
    let (key, tree) = job.finish().unwrap();
    let verified = tree.verify(&key.verification_key().unwrap()).unwrap();
    let mut write = [0; 6144];
    let mut read = [0; 6144];
    let descriptor = pool
        .complete_generation(
            &journal,
            &mut flash,
            &mut f.entropy,
            &mut f.buffers.work(),
            |flash, rng, state, coordinator| {
                let mut store = FlashPublicObjects::new(flash, f.layout, state).unwrap();
                coordinator.complete(
                    state,
                    operation,
                    key,
                    &verified,
                    DeviceId::from_bytes([0x23; 16]),
                    &kes_core::session::DeviceIdentityKey::from_seed(zeroize::Zeroizing::new([0x23; 32])),
                    rng,
                    &mut store,
                    &mut write,
                    &mut read,
                )
            },
        )
        .unwrap();
    assert_eq!(descriptor.generation, identity);
    assert_eq!(
        pool.state().unwrap().generation_high_water(),
        GenerationNumber::new(1)
    );
    drop(pool);
    let mut pool = DurablePool::recover_generation(
        &journal,
        &mut flash,
        &mut f.entropy,
        &mut f.buffers.work(),
    )
    .unwrap();
    assert_eq!(
        pool.generation_status(request.request, Some(request.next_generation_number))
            .unwrap(),
        OperationStatus::Committed(descriptor)
    );
    assert_eq!(
        pool.state()
            .unwrap()
            .generation_checkpoint()
            .unwrap()
            .outcome,
        CheckpointOutcome::Committed
    );
    assert!(
        matches!(pool.admit_generation(request, &journal, &mut flash, &mut f.entropy,
        &mut f.buffers.work()).unwrap(), Admission::Existing(OperationStatus::Committed(found)) if found == descriptor)
    );
    assert!(
        pool.restart_generation(
            request,
            &journal,
            &mut flash,
            &mut f.entropy,
            &mut f.buffers.work()
        )
        .is_err()
    );
    assert!(
        pool.admit_generation(
            GenerationRequest {
                payload_digest: [0x99; 32],
                ..request
            },
            &journal,
            &mut flash,
            &mut f.entropy,
            &mut f.buffers.work()
        )
        .is_err()
    );
}

#[test]
fn admission_power_cuts_before_and_after_commit_never_ack_or_duplicate() {
    let mut f = Fixture::new();
    let (flash, journal, pool, request) = setup(&mut f);
    drop(pool);
    let baseline = flash.copy_world();
    let mut measured = baseline.copy_world();
    let mut owner = DurablePool::recover_generation(
        &journal,
        &mut measured,
        &mut f.entropy,
        &mut f.buffers.work(),
    )
    .unwrap();
    measured.arm_cut_after_bits(usize::MAX);
    assert!(matches!(
        owner
            .admit_generation(
                request,
                &journal,
                &mut measured,
                &mut f.entropy,
                &mut f.buffers.work()
            )
            .unwrap(),
        Admission::Started(_)
    ));
    let total = measured.steps();
    drop(owner);
    let mut before = 0;
    let mut after = 0;
    // Every page boundary, plus the successful end, bounds this sweep while
    // covering candidate programming, COMMIT, predecessor erase and CLEAN.
    for cut in (0..total).step_by(2048).chain(core::iter::once(total)) {
        let mut world = baseline.copy_world();
        let mut owner = DurablePool::recover_generation(
            &journal,
            &mut world,
            &mut f.entropy,
            &mut f.buffers.work(),
        )
        .unwrap();
        world.arm_cut_after_bits(cut);
        let ack = owner.admit_generation(
            request,
            &journal,
            &mut world,
            &mut f.entropy,
            &mut f.buffers.work(),
        );
        let committed = world.completed_page(f.layout.commit_offset(1).unwrap());
        if ack.is_err() {
            assert!(!owner.is_usable());
        }
        drop(ack);
        drop(owner);
        world.disarm();
        let owner = DurablePool::recover_generation(
            &journal,
            &mut world,
            &mut f.entropy,
            &mut f.buffers.work(),
        )
        .unwrap();
        match owner.state().unwrap().generation_checkpoint() {
            None => {
                assert!(!committed);
                before += 1;
            }
            Some(checkpoint) => {
                assert!(committed);
                assert_eq!(checkpoint.request, request.request);
                assert_eq!(checkpoint.payload_digest, request.payload_digest);
                assert_eq!(checkpoint.generation_number, request.next_generation_number);
                assert_eq!(checkpoint.outcome, CheckpointOutcome::NotCommitted);
                after += 1;
            }
        }
        assert!(owner.state().unwrap().staged().is_none());
        assert_eq!(
            owner.state().unwrap().generation_high_water(),
            GenerationNumber::new(0)
        );
    }
    assert!(before > 0 && after > 0);
}

#[test]
fn decoder_rejects_old_layout_unknown_outcome_and_inconsistent_admission() {
    let mut f = Fixture::new();
    let (mut flash, journal, mut pool, request) = setup(&mut f);
    let Admission::Started(_) = pool
        .admit_generation(
            request,
            &journal,
            &mut flash,
            &mut f.entropy,
            &mut f.buffers.work(),
        )
        .unwrap()
    else {
        panic!("must admit")
    };
    let state = pool.state().unwrap();
    let context = JournalContext {
        device: DeviceId::from_bytes([0x23; 16]),
        scope: JournalScope::Pool {
            slot: HardwareSlot::new(0).unwrap(),
            pool: state.pool_id(),
            incarnation: state.incarnation(),
        },
    };
    let mut encoded = Zeroizing::new([0; 3440]);
    let length = PoolCodec::encode(state, context, &mut encoded[..]).unwrap();
    assert!(length + 128 + 16 <= 3584);
    let checkpoint = kes_core::cbor::Value::parse(&encoded[..length])
        .unwrap()
        .array()
        .unwrap()
        .nth(13)
        .unwrap();
    let prior_length = checkpoint.encoded().as_ptr() as usize - encoded.as_ptr() as usize;
    let outcome = checkpoint.array().unwrap().nth(4).unwrap();
    let outcome_offset = outcome.encoded().as_ptr() as usize - encoded.as_ptr() as usize;
    let number = checkpoint.array().unwrap().nth(3).unwrap();
    let number_offset = number.encoded().as_ptr() as usize - encoded.as_ptr() as usize;
    encoded[outcome_offset] = 3;
    assert!(PoolCodec::decode(&encoded[..length], context).is_err());
    encoded[outcome_offset] = 0;
    encoded[number_offset] = 0;
    assert!(PoolCodec::decode(&encoded[..length], context).is_err());
    encoded[number_offset] = 1;
    encoded[0] = 0x8d;
    assert!(PoolCodec::decode(&encoded[..prior_length], context).is_err());
}

#[test]
fn failed_publication_cleanup_preserves_uncertainty_until_physical_recovery() {
    let mut f = Fixture::new();
    let (mut flash, journal, mut pool, request) = setup(&mut f);
    let Admission::Started(operation) = pool
        .admit_generation(
            request,
            &journal,
            &mut flash,
            &mut f.entropy,
            &mut f.buffers.work(),
        )
        .unwrap()
    else {
        panic!("must admit")
    };
    let identity = operation.generation();
    let result = pool.complete_generation(
        &journal,
        &mut flash,
        &mut f.entropy,
        &mut f.buffers.work(),
        |flash, _, _, _| {
            flash.program_page(8192, &[0; 256]).unwrap();
            flash.arm_cut_after_bits(0);
            Err(generation::Error::Storage(()))
        },
    );
    assert!(matches!(
        result,
        Err(generation::DurableGenerationError::Operation(_))
    ));
    assert!(!pool.is_usable());
    assert!(
        pool.generation_status(request.request, Some(request.next_generation_number))
            .is_err()
    );
    drop(pool);
    flash.disarm();
    let recovered = journal
        .recover(&mut flash, &mut f.entropy, &mut f.buffers.work())
        .unwrap();
    let checkpoint = recovered.state.generation_checkpoint().unwrap();
    assert_eq!(checkpoint.generation, identity);
    assert_eq!(checkpoint.outcome, CheckpointOutcome::InProgress);
    drop(recovered);
    let pool = DurablePool::recover_generation(
        &journal,
        &mut flash,
        &mut f.entropy,
        &mut f.buffers.work(),
    )
    .unwrap();
    assert!(flash.raw()[8192..24576].iter().all(|b| *b == 0xff));
    assert!(matches!(
        pool.generation_status(request.request, Some(request.next_generation_number))
            .unwrap(),
        OperationStatus::NotCommitted { .. }
    ));
}

#[test]
fn authenticated_policy_change_cancels_checkpoint_and_refuses_old_epoch_restart() {
    use ed25519_dalek::{Signer, SigningKey};
    use kes_core::{
        cbor::{Encoder, Value},
        credentials,
        management::{self, Action, SigningFields, Target},
    };
    let mut f = Fixture::new();
    let (mut flash, journal, mut pool, request) = setup(&mut f);
    let Admission::Started(operation) = pool
        .admit_generation(
            request,
            &journal,
            &mut flash,
            &mut f.entropy,
            &mut f.buffers.work(),
        )
        .unwrap()
    else {
        panic!("must admit")
    };
    let identity = operation.generation();
    let mut workspace = KesKey::erased(KesLifetime::new(64).unwrap());
    let mut job =
        generation::begin_key_generation(&mut f.entropy, workspace.lifetime()).unwrap();
    job.step().unwrap();
    drop(job); // real incomplete crypto workspace is wiped, never persisted
    drop(pool);
    let mut recovered = journal
        .recover(&mut flash, &mut f.entropy, &mut f.buffers.work())
        .unwrap();
    let mut coordinator = generation::GenerationCoordinator::from_checkpoint(
        recovered.state.generation_checkpoint().unwrap(),
    );
    let mut seed = Zeroizing::new([0; 32]);
    f.entropy.try_fill_bytes(&mut seed[..]).unwrap();
    let management_key = SigningKey::from_bytes(&seed);
    let target = Target::Pool {
        pool: recovered.state.pool_id(),
        incarnation: recovered.state.incarnation(),
    };
    let device = DeviceId::from_bytes([0x23; 16]);
    let mut payload = [0; 128];
    let mut e = Encoder::new(&mut payload);
    e.map(2).unwrap();
    e.text("credential_epoch").unwrap();
    e.uint(1).unwrap();
    e.text("machine_public_key").unwrap();
    e.bytes(&f.cold.verifying_key().to_bytes()).unwrap();
    let payload = e.finish().unwrap().encoded();
    let fields = SigningFields {
        device,
        target,
        sequence: ManagementSequence::new(2),
        request: RequestId::from_bytes([0x44; 16]),
        expected_revision: recovered.state.revision(),
        action: Action::CredentialReplace,
        canonical_payload: Value::parse(payload).unwrap(),
    };
    let mut message = [0; 4608];
    let length = management::encode_signing_message(fields, &mut message).unwrap();
    let signature = management_key.sign(&message[..length]).to_bytes();
    let mut envelope = [0; 6144];
    let mut e = Encoder::new(&mut envelope);
    e.map(9).unwrap();
    e.text("pool").unwrap();
    e.bytes(recovered.state.pool_id().as_bytes()).unwrap();
    e.text("action").unwrap();
    e.text(Action::CredentialReplace.name()).unwrap();
    e.text("device").unwrap();
    e.bytes(device.as_bytes()).unwrap();
    e.text("request").unwrap();
    e.bytes(&[0x44; 16]).unwrap();
    e.text("signature").unwrap();
    e.bytes(&signature).unwrap();
    e.text("incarnation").unwrap();
    e.bytes(recovered.state.incarnation().as_bytes()).unwrap();
    e.text("canonical_payload").unwrap();
    e.bytes(payload).unwrap();
    e.text("expected_revision").unwrap();
    e.uint(recovered.state.revision().get()).unwrap();
    e.text("management_sequence").unwrap();
    e.uint(2).unwrap();
    let envelope = e.finish().unwrap().encoded();
    let verified =
        management::parse_and_verify(envelope, device, &management_key.verifying_key().to_bytes())
            .unwrap();
    let outcome = credentials::change_pool_credential(
        &mut recovered.state,
        &mut coordinator,
        Some(&mut workspace),
        &verified,
    )
    .unwrap();
    assert!(
        matches!(outcome, credentials::CredentialOutcome::Applied { cancelled_generation: Some(id), .. } if id == identity)
    );
    assert!(workspace.canonical_state().is_err());
    assert_eq!(
        recovered.state.generation_checkpoint().unwrap().outcome,
        CheckpointOutcome::NotCommitted
    );
    journal
        .transact_successor(
            &mut flash,
            &mut f.entropy,
            &recovered.token,
            &recovered.state,
            &mut f.buffers.work(),
        )
        .unwrap();
    drop(recovered);
    let mut pool = DurablePool::recover_generation(
        &journal,
        &mut flash,
        &mut f.entropy,
        &mut f.buffers.work(),
    )
    .unwrap();
    assert!(matches!(
        pool.restart_generation(
            request,
            &journal,
            &mut flash,
            &mut f.entropy,
            &mut f.buffers.work()
        ),
        Err(generation::DurableGenerationError::Generation(
            generation::Error::State(kes_core::state::StateError::PolicyChanged)
        ))
    ));
    assert_eq!(
        pool.state()
            .unwrap()
            .generation_checkpoint()
            .unwrap()
            .generation,
        identity
    );
}

#[test]
fn publication_commit_power_cuts_restore_atomic_descriptor_and_checkpoint() {
    let mut f = Fixture::new();
    let mut committed_cases = 0;
    let mut aborted_cases = 0;
    // One sector erase, <=14 snapshot pages, COMMIT, predecessor erase,
    // CLEAN. Include a cut beyond that bound to exercise the actual ACK.
    let limit = 32768 + 14 * 2048 + 2048 + 32768 + 2048;
    for cut in (0..=limit).step_by(2048) {
        let (mut flash, journal, mut pool, request) = setup(&mut f);
        let Admission::Started(operation) = pool
            .admit_generation(
                request,
                &journal,
                &mut flash,
                &mut f.entropy,
                &mut f.buffers.work(),
            )
            .unwrap()
        else {
            panic!("must admit")
        };
        let identity = operation.generation();
        let mut job =
            generation::begin_key_generation(&mut f.entropy, KesLifetime::new(64).unwrap()).unwrap();
        for _ in 0..64 {
            job.step().unwrap();
        }
        let (key, tree) = job.finish().unwrap();
        let verified = tree.verify(&key.verification_key().unwrap()).unwrap();
        let result = pool.complete_generation(
            &journal,
            &mut flash,
            &mut f.entropy,
            &mut f.buffers.work(),
            |flash, rng, state, coordinator| {
                let descriptor = {
                    let mut store = FlashPublicObjects::new(flash, f.layout, state).unwrap();
                    coordinator.complete(
                        state,
                        operation,
                        key,
                        &verified,
                        DeviceId::from_bytes([0x23; 16]),
                        &kes_core::session::DeviceIdentityKey::from_seed(zeroize::Zeroizing::new([0x23; 32])),
                        rng,
                        &mut store,
                        &mut [0; 6144],
                        &mut [0; 6144],
                    )?
                };
                flash.arm_cut_after_bits(cut);
                Ok(descriptor)
            },
        );
        let committed = flash.completed_page(f.layout.commit_offset(0).unwrap());
        if result.is_err() {
            assert!(!pool.is_usable());
        }
        drop(pool);
        flash.disarm();
        let pool = DurablePool::recover_generation(
            &journal,
            &mut flash,
            &mut f.entropy,
            &mut f.buffers.work(),
        )
        .unwrap();
        let checkpoint = pool.state().unwrap().generation_checkpoint().unwrap();
        assert_eq!(checkpoint.generation, identity);
        match pool
            .generation_status(request.request, Some(request.next_generation_number))
            .unwrap()
        {
            OperationStatus::Committed(descriptor) => {
                assert!(committed);
                assert_eq!(checkpoint.outcome, CheckpointOutcome::Committed);
                assert_eq!(descriptor.generation, identity);
                assert_eq!(
                    pool.state().unwrap().generation_high_water(),
                    GenerationNumber::new(1)
                );
                if let Ok(ack) = result {
                    assert_eq!(descriptor, ack);
                }
                committed_cases += 1;
            }
            OperationStatus::NotCommitted { .. } => {
                assert!(!committed);
                assert!(result.is_err());
                assert!(pool.state().unwrap().staged().is_none());
                assert!(flash.raw()[8192..24576].iter().all(|b| *b == 0xff));
                aborted_cases += 1;
            }
            other => panic!("unexpected recovered status: {other:?}"),
        }
    }
    assert!(committed_cases > 0 && aborted_cases > 0);
}

#[test]
fn completion_merges_newer_durable_active_period_without_rollback() {
    use kes_core::activation::{ActivationRequest, CertificationRequest, EvolutionRequest};
    use kes_core::types::AbsolutePeriod;
    let mut f = Fixture::new();
    f.durable
        .certify(
            &f.journal,
            &mut f.flash,
            &mut f.entropy,
            &mut f.buffers.work(),
            CertificationRequest {
                actor: f.actor,
                expected_revision: Revision::new(1),
                generation: f.generation,
                canonical_certificate: &f.certificate,
                network: &f.network,
            },
        )
        .unwrap();
    let active_vk = *f
        .durable
        .state()
        .unwrap()
        .staged()
        .unwrap()
        .verification_key();
    let active_tree = f.tree.verify(&active_vk).unwrap();
    f.durable
        .activate_first(
            &f.journal,
            &mut f.flash,
            &mut f.entropy,
            &mut f.buffers.work(),
            ActivationRequest {
                actor: f.actor,
                expected_revision: Revision::new(2),
                expected_active_generation: None,
                generation: f.generation,
                certificate_digest: f.certificate_digest,
                current_absolute_period: AbsolutePeriod::new(102),
            },
            &active_tree,
        )
        .unwrap();
    let request = GenerationRequest {
        actor: f.actor,
        request: RequestId::from_bytes([0x48; 16]),
        payload_digest: [0x49; 32],
        next_generation_number: GenerationNumber::new(2),
        expected_revision: Revision::new(3),
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
        panic!("must admit")
    };
    f.durable
        .evolve(
            &f.journal,
            &mut f.flash,
            &mut f.entropy,
            &mut f.buffers.work(),
            EvolutionRequest {
                actor: f.actor,
                expected_revision: Revision::new(4),
                generation: f.generation,
                certificate_digest: f.certificate_digest,
                target_absolute_period: AbsolutePeriod::new(103),
                network: &f.network,
            },
            &active_tree,
        )
        .unwrap();
    let mut job = generation::begin_key_generation(&mut f.entropy, KesLifetime::new(64).unwrap()).unwrap();
    for _ in 0..64 {
        job.step().unwrap();
    }
    let (key, tree) = job.finish().unwrap();
    let verified = tree.verify(&key.verification_key().unwrap()).unwrap();
    let descriptor = f
        .durable
        .complete_generation(
            &f.journal,
            &mut f.flash,
            &mut f.entropy,
            &mut f.buffers.work(),
            |flash, rng, state, coordinator| {
                let mut store = FlashPublicObjects::new(flash, f.layout, state).unwrap();
                coordinator.complete(
                    state,
                    operation,
                    key,
                    &verified,
                    DeviceId::from_bytes([0x19; 16]),
                    &kes_core::session::DeviceIdentityKey::from_seed(zeroize::Zeroizing::new([0x19; 32])),
                    rng,
                    &mut store,
                    &mut [0; 6144],
                    &mut [0; 6144],
                )
            },
        )
        .unwrap();
    assert_eq!(f.durable.state().unwrap().revision(), Revision::new(6));
    assert_eq!(
        f.durable
            .state()
            .unwrap()
            .current()
            .unwrap()
            .relative_period()
            .get(),
        3
    );
    f.durable = DurablePool::recover_generation(
        &f.journal,
        &mut f.flash,
        &mut f.entropy,
        &mut f.buffers.work(),
    )
    .unwrap();
    let current = f.durable.state().unwrap().current().unwrap();
    assert_eq!(current.id(), f.generation);
    assert_eq!(current.relative_period().get(), 3);
    assert_eq!(current.verification_key(), &active_vk);
    assert_eq!(
        f.durable
            .generation_status(request.request, Some(request.next_generation_number))
            .unwrap(),
        OperationStatus::Committed(descriptor)
    );
}
