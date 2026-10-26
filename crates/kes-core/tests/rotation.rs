use kes_core::{
    activation::{
        ActivationRequest, CertificationRequest, DurablePool, OperationError, ScheduleRequest,
    },
    certificate::CertificateError,
    crypto::{Generation, KesKey, PublicTreeBuffer, verify},
    rotation::{PeriodObservationOutcome, PeriodObservationRequest},
    signing::SigningRequest,
    state::{GenerationSpec, KESGeneration, Lifecycle, PublicObject, StateError},
    types::{AbsolutePeriod, GenerationId, GenerationNumber, KesLifetime, RequestId, Revision},
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[path = "support/mod.rs"]
mod support;
use support::{Fixture, certificate};

fn activate_initial(fixture: &mut Fixture) {
    fixture
        .durable
        .certify(
            &fixture.journal,
            &mut fixture.flash,
            &mut fixture.entropy,
            &mut fixture.buffers.work(),
            CertificationRequest {
                actor: fixture.actor,
                expected_revision: Revision::new(1),
                generation: fixture.generation,
                canonical_certificate: &fixture.certificate,
                network: &fixture.network,
            },
        )
        .unwrap();
    let tree = fixture
        .tree
        .verify(
            fixture
                .durable
                .state()
                .unwrap()
                .staged()
                .unwrap()
                .verification_key(),
        )
        .unwrap();
    fixture
        .durable
        .activate_first(
            &fixture.journal,
            &mut fixture.flash,
            &mut fixture.entropy,
            &mut fixture.buffers.work(),
            ActivationRequest {
                actor: fixture.actor,
                expected_revision: Revision::new(2),
                expected_active_generation: None,
                generation: fixture.generation,
                certificate_digest: fixture.certificate_digest,
                current_absolute_period: AbsolutePeriod::new(100),
            },
            &tree,
        )
        .unwrap();
}

struct Replacement {
    generation: GenerationId,
    tree: PublicTreeBuffer,
    certificate: Vec<u8>,
    certificate_digest: [u8; 32],
    state: Option<KESGeneration>,
}

fn replacement(fixture: &mut Fixture, number: u64, tag: u8, counter: u64) -> Replacement {
    let lifetime = KesLifetime::new(64).unwrap();
    let mut seed = Zeroizing::new([tag; 32]);
    let mut key = KesKey::erased(lifetime);
    let mut tree = PublicTreeBuffer::new();
    let mut job = Generation::begin(&mut seed, &mut key, &mut tree).unwrap();
    for _ in 0..64 {
        job.step().unwrap();
    }
    let verified = job.finish().unwrap();
    let verification_key = key.verification_key().unwrap();
    let generation = GenerationId::from_bytes([tag; 16]);
    let backup = include_bytes!("../../../fuzz/corpus/frame/backup-public-structure");
    let object =
        PublicObject::from_parts(generation, verified.as_bytes(), backup, &verification_key)
            .unwrap();
    let mut object_bytes = vec![0; usize::from(object.reference().total_length)];
    object.encode_into(&mut object_bytes).unwrap();
    fixture
        .flash
        .install_public_object(fixture.layout.object_offset(1).unwrap(), &object_bytes);
    let state = KESGeneration::new_staged(
        GenerationSpec {
            generation_id: generation,
            generation_number: GenerationNumber::new(number),
            creation_request: RequestId::from_bytes([tag.wrapping_add(1); 16]),
            creation_payload_digest: [tag.wrapping_add(2); 32],
            pool: fixture.durable.state().unwrap().pool_id(),
            incarnation: fixture.durable.state().unwrap().incarnation(),
            verification_key,
            lifetime,
            recipient_id: *fixture
                .durable
                .state()
                .unwrap()
                .generation_policy()
                .recipient_id(),
            public_object: object,
        },
        key,
    )
    .unwrap();
    let certificate = certificate(&fixture.cold, &verification_key, counter, 110);
    Replacement {
        generation,
        tree,
        certificate_digest: Sha256::digest(&certificate).into(),
        certificate,
        state: Some(state),
    }
}

fn stage_and_certify(fixture: &mut Fixture) -> Replacement {
    let mut replacement = replacement(fixture, 2, 0x72, 1);
    let policy = fixture.durable.state().unwrap().generation_policy();
    fixture
        .durable
        .stage_generation(
            &fixture.journal,
            &mut fixture.flash,
            &mut fixture.entropy,
            &mut fixture.buffers.work(),
            fixture.actor,
            Revision::new(3),
            replacement.state.take().unwrap(),
            policy,
        )
        .unwrap();
    fixture
        .durable
        .certify(
            &fixture.journal,
            &mut fixture.flash,
            &mut fixture.entropy,
            &mut fixture.buffers.work(),
            CertificationRequest {
                actor: fixture.actor,
                expected_revision: Revision::new(4),
                generation: replacement.generation,
                canonical_certificate: &replacement.certificate,
                network: &fixture.network,
            },
        )
        .unwrap();
    replacement
}

fn reboot(fixture: &mut Fixture) {
    let recovered = fixture
        .journal
        .recover(
            &mut fixture.flash,
            &mut fixture.entropy,
            &mut fixture.buffers.work(),
        )
        .unwrap();
    fixture.durable = DurablePool::from_recovered(recovered);
}

#[test]
fn scheduled_intent_survives_restart_and_activates_only_at_eligible_period() {
    let mut fixture = Fixture::new();
    activate_initial(&mut fixture);
    let replacement = stage_and_certify(&mut fixture);
    let request = ScheduleRequest {
        actor: fixture.actor,
        expected_revision: Revision::new(5),
        expected_active_generation: fixture.generation,
        generation: replacement.generation,
        certificate_digest: replacement.certificate_digest,
        activation_absolute_period: AbsolutePeriod::new(112),
        creation_request: RequestId::from_bytes([0x7a; 16]),
    };
    let scheduled = fixture
        .durable
        .schedule(
            &fixture.journal,
            &mut fixture.flash,
            &mut fixture.entropy,
            &mut fixture.buffers.work(),
            request,
        )
        .unwrap();
    assert!(scheduled.committed_write);
    assert_eq!(scheduled.context.revision, Revision::new(6));
    let duplicate = fixture
        .durable
        .schedule(
            &fixture.journal,
            &mut fixture.flash,
            &mut fixture.entropy,
            &mut fixture.buffers.work(),
            request,
        )
        .unwrap();
    assert!(!duplicate.committed_write);
    reboot(&mut fixture);
    assert_eq!(
        fixture
            .durable
            .activation_intent()
            .unwrap()
            .creation_request(),
        request.creation_request
    );

    let active_tree = fixture
        .tree
        .verify(
            fixture
                .durable
                .state()
                .unwrap()
                .current()
                .unwrap()
                .verification_key(),
        )
        .unwrap();
    let pending = fixture
        .durable
        .observe_period(
            &fixture.journal,
            &mut fixture.flash,
            &mut fixture.entropy,
            &mut fixture.buffers.work(),
            PeriodObservationRequest {
                actor: fixture.actor,
                expected_revision: Revision::new(6),
                absolute_period: AbsolutePeriod::new(111),
                network: &fixture.network,
            },
            &active_tree,
        )
        .unwrap();
    assert!(matches!(pending, PeriodObservationOutcome::Pending(_)));
    assert_eq!(
        fixture.durable.state().unwrap().revision(),
        Revision::new(6)
    );

    let replacement_tree = replacement
        .tree
        .verify(
            fixture
                .durable
                .state()
                .unwrap()
                .staged()
                .unwrap()
                .verification_key(),
        )
        .unwrap();
    let activated = fixture
        .durable
        .observe_period(
            &fixture.journal,
            &mut fixture.flash,
            &mut fixture.entropy,
            &mut fixture.buffers.work(),
            PeriodObservationRequest {
                actor: fixture.actor,
                expected_revision: Revision::new(6),
                absolute_period: AbsolutePeriod::new(112),
                network: &fixture.network,
            },
            &replacement_tree,
        )
        .unwrap();
    assert!(matches!(activated, PeriodObservationOutcome::Activated(_)));
    assert_eq!(
        fixture.durable.state().unwrap().current().unwrap().id(),
        replacement.generation
    );
    assert_eq!(
        fixture
            .durable
            .state()
            .unwrap()
            .current()
            .unwrap()
            .relative_period()
            .get(),
        2
    );
    assert!(fixture.durable.state().unwrap().staged().is_none());
    assert!(fixture.durable.activation_intent().is_none());
    reboot(&mut fixture);
    assert_eq!(
        fixture.durable.state().unwrap().current().unwrap().id(),
        replacement.generation
    );
}

#[test]
fn schedule_rejects_wrong_context_periods_counter_replay_and_second_staged_key() {
    let mut fixture = Fixture::new();
    activate_initial(&mut fixture);
    let mut staged_replacement = replacement(&mut fixture, 2, 0x72, 0);
    let policy = fixture.durable.state().unwrap().generation_policy();
    fixture
        .durable
        .stage_generation(
            &fixture.journal,
            &mut fixture.flash,
            &mut fixture.entropy,
            &mut fixture.buffers.work(),
            fixture.actor,
            Revision::new(3),
            staged_replacement.state.take().unwrap(),
            policy,
        )
        .unwrap();
    assert!(matches!(
        fixture.durable.certify(
            &fixture.journal,
            &mut fixture.flash,
            &mut fixture.entropy,
            &mut fixture.buffers.work(),
            CertificationRequest {
                actor: fixture.actor,
                expected_revision: Revision::new(4),
                generation: staged_replacement.generation,
                canonical_certificate: &staged_replacement.certificate,
                network: &fixture.network,
            },
        ),
        Err(OperationError::State(StateError::Certificate(
            CertificateError::CounterNotIncreasing
        )))
    ));
    staged_replacement.certificate = certificate(
        &fixture.cold,
        fixture
            .durable
            .state()
            .unwrap()
            .staged()
            .unwrap()
            .verification_key(),
        1,
        110,
    );
    staged_replacement.certificate_digest = Sha256::digest(&staged_replacement.certificate).into();
    fixture
        .durable
        .certify(
            &fixture.journal,
            &mut fixture.flash,
            &mut fixture.entropy,
            &mut fixture.buffers.work(),
            CertificationRequest {
                actor: fixture.actor,
                expected_revision: Revision::new(4),
                generation: staged_replacement.generation,
                canonical_certificate: &staged_replacement.certificate,
                network: &fixture.network,
            },
        )
        .unwrap();

    for period in [109, 174] {
        assert!(matches!(
            fixture.durable.schedule(
                &fixture.journal,
                &mut fixture.flash,
                &mut fixture.entropy,
                &mut fixture.buffers.work(),
                ScheduleRequest {
                    actor: fixture.actor,
                    expected_revision: Revision::new(5),
                    expected_active_generation: fixture.generation,
                    generation: staged_replacement.generation,
                    certificate_digest: staged_replacement.certificate_digest,
                    activation_absolute_period: AbsolutePeriod::new(period),
                    creation_request: RequestId::from_bytes([period as u8; 16]),
                },
            ),
            Err(OperationError::State(StateError::Certificate(
                CertificateError::NotYetValid | CertificateError::Expired
            )))
        ));
    }
    assert!(matches!(
        fixture.durable.schedule(
            &fixture.journal,
            &mut fixture.flash,
            &mut fixture.entropy,
            &mut fixture.buffers.work(),
            ScheduleRequest {
                actor: fixture.actor,
                expected_revision: Revision::new(5),
                expected_active_generation: GenerationId::from_bytes([0xee; 16]),
                generation: staged_replacement.generation,
                certificate_digest: staged_replacement.certificate_digest,
                activation_absolute_period: AbsolutePeriod::new(112),
                creation_request: RequestId::from_bytes([0x7b; 16]),
            },
        ),
        Err(OperationError::State(StateError::StaleGeneration))
    ));
    assert!(matches!(
        fixture.durable.schedule(
            &fixture.journal,
            &mut fixture.flash,
            &mut fixture.entropy,
            &mut fixture.buffers.work(),
            ScheduleRequest {
                actor: fixture.actor,
                expected_revision: Revision::new(5),
                expected_active_generation: fixture.generation,
                generation: staged_replacement.generation,
                certificate_digest: [0xff; 32],
                activation_absolute_period: AbsolutePeriod::new(112),
                creation_request: RequestId::from_bytes([0x7c; 16]),
            },
        ),
        Err(OperationError::State(StateError::CertificateConflict))
    ));

    let mut third = replacement(&mut fixture, 3, 0x82, 2);
    let policy = fixture.durable.state().unwrap().generation_policy();
    assert!(matches!(
        fixture.durable.stage_generation(
            &fixture.journal,
            &mut fixture.flash,
            &mut fixture.entropy,
            &mut fixture.buffers.work(),
            fixture.actor,
            Revision::new(5),
            third.state.take().unwrap(),
            policy,
        ),
        Err(OperationError::State(StateError::StagedConflict))
    ));
    assert_eq!(
        fixture.durable.state().unwrap().revision(),
        Revision::new(5)
    );
}

#[test]
fn lost_activation_ack_reconciles_without_disrupting_an_unrelated_pool() {
    let mut rotating = Fixture::new();
    activate_initial(&mut rotating);
    let replacement = stage_and_certify(&mut rotating);
    rotating
        .durable
        .schedule(
            &rotating.journal,
            &mut rotating.flash,
            &mut rotating.entropy,
            &mut rotating.buffers.work(),
            ScheduleRequest {
                actor: rotating.actor,
                expected_revision: Revision::new(5),
                expected_active_generation: rotating.generation,
                generation: replacement.generation,
                certificate_digest: replacement.certificate_digest,
                activation_absolute_period: AbsolutePeriod::new(112),
                creation_request: RequestId::from_bytes([0x7d; 16]),
            },
        )
        .unwrap();

    let mut unaffected = Fixture::new();
    activate_initial(&mut unaffected);
    let unaffected_tree = unaffected
        .tree
        .verify(
            unaffected
                .durable
                .state()
                .unwrap()
                .current()
                .unwrap()
                .verification_key(),
        )
        .unwrap();
    let before = unaffected
        .durable
        .sign(
            &unaffected.journal,
            &mut unaffected.flash,
            &mut unaffected.entropy,
            &mut unaffected.buffers.work(),
            SigningRequest {
                actor: unaffected.actor,
                generation: unaffected.generation,
                certificate_digest: unaffected.certificate_digest,
                absolute_period: AbsolutePeriod::new(100),
                network: &unaffected.network,
                message: b"unrelated-before-rotation",
            },
            &unaffected_tree,
        )
        .unwrap();
    verify(
        unaffected_tree.root(),
        before.context.relative_period,
        KesLifetime::new(64).unwrap(),
        b"unrelated-before-rotation",
        &before.signature,
    )
    .unwrap();

    let replacement_tree = replacement
        .tree
        .verify(
            rotating
                .durable
                .state()
                .unwrap()
                .staged()
                .unwrap()
                .verification_key(),
        )
        .unwrap();
    let _lost_ack = rotating
        .durable
        .observe_period(
            &rotating.journal,
            &mut rotating.flash,
            &mut rotating.entropy,
            &mut rotating.buffers.work(),
            PeriodObservationRequest {
                actor: rotating.actor,
                expected_revision: Revision::new(6),
                absolute_period: AbsolutePeriod::new(112),
                network: &rotating.network,
            },
            &replacement_tree,
        )
        .unwrap();
    reboot(&mut rotating);
    assert_eq!(
        rotating.durable.state().unwrap().current().unwrap().id(),
        replacement.generation
    );
    assert_eq!(
        rotating
            .durable
            .state()
            .unwrap()
            .current()
            .unwrap()
            .lifecycle(),
        Lifecycle::Active
    );
    assert!(matches!(
        rotating.durable.sign(
            &rotating.journal,
            &mut rotating.flash,
            &mut rotating.entropy,
            &mut rotating.buffers.work(),
            SigningRequest {
                actor: rotating.actor,
                generation: rotating.generation,
                certificate_digest: rotating.certificate_digest,
                absolute_period: AbsolutePeriod::new(112),
                network: &rotating.network,
                message: b"stale captured attempt",
            },
            &replacement_tree,
        ),
        Err(OperationError::State(StateError::StaleGeneration))
    ));

    let after = unaffected
        .durable
        .sign(
            &unaffected.journal,
            &mut unaffected.flash,
            &mut unaffected.entropy,
            &mut unaffected.buffers.work(),
            SigningRequest {
                actor: unaffected.actor,
                generation: unaffected.generation,
                certificate_digest: unaffected.certificate_digest,
                absolute_period: AbsolutePeriod::new(101),
                network: &unaffected.network,
                message: b"unrelated-after-rotation",
            },
            &unaffected_tree,
        )
        .unwrap();
    verify(
        unaffected_tree.root(),
        after.context.relative_period,
        KesLifetime::new(64).unwrap(),
        b"unrelated-after-rotation",
        &after.signature,
    )
    .unwrap();
}
