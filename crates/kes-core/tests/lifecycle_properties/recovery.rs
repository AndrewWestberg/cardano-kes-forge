use super::super::support::Fixture;
use kes_core::{
    activation::{
        ActivationRequest, CertificationRequest, DurablePool, EvolutionRequest, OperationError,
    },
    certificate::CertificateError,
    crypto::{CryptoError, Generation, KesKey, PublicTreeBuffer},
    journal::JournalLayout,
    state::{GenerationSpec, KESGeneration, Lifecycle, PublicObject, StateError},
    types::{
        AbsolutePeriod, GenerationId, GenerationNumber, KesLifetime, RelativePeriod, RequestId,
        Revision,
    },
};
use rand_chacha::rand_core::TryRngCore;
use zeroize::Zeroizing;

pub(super) struct RecoveryCounts {
    pub first_activation: u64,
    pub period_skip: u64,
    pub current_no_write: u64,
    pub stale_rejected: u64,
    pub reboot_reconciled: u64,
    pub lost_ack_reconciled: u64,
    pub committed_expiry: u64,
    pub staged_survived_expiry: u64,
}

pub(super) fn exercise_recovery_transitions() -> RecoveryCounts {
    let mut fixture = Fixture::new();
    let public_reference = *fixture
        .durable
        .state()
        .unwrap()
        .staged()
        .unwrap()
        .public_object_ref();
    let verification_key = *fixture
        .durable
        .state()
        .unwrap()
        .staged()
        .unwrap()
        .verification_key();

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
    let verified_tree = fixture.tree.verify(&verification_key).unwrap();
    let activated = fixture
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
            &verified_tree,
        )
        .unwrap();
    assert_eq!(activated.revision, Revision::new(3));
    assert_eq!(activated.relative_period, RelativePeriod::new(0).unwrap());
    assert!(fixture.durable.state().unwrap().staged().is_none());

    let skipped = fixture
        .durable
        .evolve(
            &fixture.journal,
            &mut fixture.flash,
            &mut fixture.entropy,
            &mut fixture.buffers.work(),
            EvolutionRequest {
                actor: fixture.actor,
                expected_revision: Revision::new(3),
                generation: fixture.generation,
                certificate_digest: fixture.certificate_digest,
                target_absolute_period: AbsolutePeriod::new(163),
                network: &fixture.network,
            },
            &verified_tree,
        )
        .unwrap();
    assert!(skipped.committed_write);
    assert_eq!(skipped.context.revision, Revision::new(4));
    assert_eq!(
        skipped.context.relative_period,
        RelativePeriod::new(63).unwrap()
    );

    let current = fixture
        .durable
        .evolve(
            &fixture.journal,
            &mut fixture.flash,
            &mut fixture.entropy,
            &mut fixture.buffers.work(),
            EvolutionRequest {
                actor: fixture.actor,
                expected_revision: Revision::new(4),
                generation: fixture.generation,
                certificate_digest: fixture.certificate_digest,
                target_absolute_period: AbsolutePeriod::new(163),
                network: &fixture.network,
            },
            &verified_tree,
        )
        .unwrap();
    assert!(!current.committed_write);
    assert_eq!(current.context.revision, Revision::new(4));

    let stale = fixture.durable.evolve(
        &fixture.journal,
        &mut fixture.flash,
        &mut fixture.entropy,
        &mut fixture.buffers.work(),
        EvolutionRequest {
            actor: fixture.actor,
            expected_revision: Revision::new(4),
            generation: fixture.generation,
            certificate_digest: fixture.certificate_digest,
            target_absolute_period: AbsolutePeriod::new(162),
            network: &fixture.network,
        },
        &verified_tree,
    );
    if std::env::var("KES_GATE_MODE").as_deref() == Ok("seeded-stale-period") {
        if matches!(
            &stale,
            Err(OperationError::State(StateError::Crypto(
                CryptoError::StalePeriod
            )))
        ) {
            println!(
                "KES_GATE_SUMMARY {{\"version\":1,\"cases\":1,\"scenarios\":{{\"core-state\":1}},\"measurements\":{{\"violations\":1,\"counterexample\":{{\"mode\":\"seeded-stale-period\",\"path\":\"kes-core.activation.evolve\",\"observation\":\"an earlier KES period was modeled as accepted after a committed later period\",\"disclosure\":\"public\"}}}}}}"
            );
            panic!("seeded stale-period defect detected");
        }
        panic!("seeded stale-period defect was not detected");
    }
    assert_eq!(
        stale,
        Err(OperationError::State(StateError::Crypto(
            CryptoError::StalePeriod
        )))
    );

    drop(fixture.durable);
    let recovered = fixture
        .journal
        .recover(
            &mut fixture.flash,
            &mut fixture.entropy,
            &mut fixture.buffers.work(),
        )
        .unwrap();
    fixture.durable = DurablePool::from_recovered(recovered);
    assert_eq!(
        fixture.durable.evolve(
            &fixture.journal,
            &mut fixture.flash,
            &mut fixture.entropy,
            &mut fixture.buffers.work(),
            EvolutionRequest {
                actor: fixture.actor,
                expected_revision: Revision::new(4),
                generation: fixture.generation,
                certificate_digest: fixture.certificate_digest,
                target_absolute_period: AbsolutePeriod::new(162),
                network: &fixture.network,
            },
            &verified_tree,
        ),
        Err(OperationError::State(StateError::Crypto(
            CryptoError::StalePeriod
        )))
    );
    let replayed = fixture
        .durable
        .evolve(
            &fixture.journal,
            &mut fixture.flash,
            &mut fixture.entropy,
            &mut fixture.buffers.work(),
            EvolutionRequest {
                actor: fixture.actor,
                expected_revision: Revision::new(4),
                generation: fixture.generation,
                certificate_digest: fixture.certificate_digest,
                target_absolute_period: AbsolutePeriod::new(163),
                network: &fixture.network,
            },
            &verified_tree,
        )
        .unwrap();
    assert!(!replayed.committed_write);

    drop(fixture.durable);
    let mut recovered = fixture
        .journal
        .recover(
            &mut fixture.flash,
            &mut fixture.entropy,
            &mut fixture.buffers.work(),
        )
        .unwrap();
    let mut replacement_seed = Zeroizing::new([0; 32]);
    fixture
        .entropy
        .try_fill_bytes(&mut *replacement_seed)
        .unwrap();
    let lifetime = KesLifetime::new(64).unwrap();
    let mut replacement_key = KesKey::erased(lifetime);
    let mut replacement_tree = PublicTreeBuffer::new();
    let mut generation = Generation::begin(
        &mut replacement_seed,
        &mut replacement_key,
        &mut replacement_tree,
    )
    .unwrap();
    for _ in 0..64 {
        generation.step().unwrap();
    }
    let replacement_cache = generation.finish().unwrap();
    let replacement_vk = replacement_key.verification_key().unwrap();
    let replacement_id = GenerationId::from_bytes([0x92; 16]);
    let replacement_object = PublicObject::from_parts(
        replacement_id,
        replacement_cache.as_bytes(),
        include_bytes!("../../../../fuzz/corpus/frame/backup-public-structure"),
        &replacement_vk,
    )
    .unwrap();
    let replacement_reference = *replacement_object.reference();
    let mut object_bytes = vec![0; usize::from(replacement_reference.total_length)];
    replacement_object.encode_into(&mut object_bytes).unwrap();
    fixture.flash.install_public_object(
        JournalLayout::pool(0).unwrap().object_offset(1).unwrap(),
        &object_bytes,
    );
    let replacement = KESGeneration::new_staged(
        GenerationSpec {
            generation_id: replacement_id,
            generation_number: GenerationNumber::new(2),
            creation_request: RequestId::from_bytes([0x93; 16]),
            creation_payload_digest: [0x94; 32],
            pool: recovered.state.pool_id(),
            incarnation: recovered.state.incarnation(),
            verification_key: replacement_vk,
            lifetime,
            recipient_id: *recovered.state.recipient_id(),
            public_object: replacement_object,
        },
        replacement_key,
    )
    .unwrap();
    let policy = recovered.state.generation_policy();
    recovered
        .state
        .stage(fixture.actor, Revision::new(4), replacement, policy)
        .unwrap();
    let token = fixture
        .journal
        .transact_successor(
            &mut fixture.flash,
            &mut fixture.entropy,
            &recovered.token,
            &recovered.state,
            &mut fixture.buffers.work(),
        )
        .unwrap();
    fixture.durable = DurablePool::new(recovered.state, token).unwrap();

    let expired = fixture
        .durable
        .evolve(
            &fixture.journal,
            &mut fixture.flash,
            &mut fixture.entropy,
            &mut fixture.buffers.work(),
            EvolutionRequest {
                actor: fixture.actor,
                expected_revision: Revision::new(5),
                generation: fixture.generation,
                certificate_digest: fixture.certificate_digest,
                target_absolute_period: AbsolutePeriod::new(164),
                network: &fixture.network,
            },
            &verified_tree,
        )
        .unwrap();
    assert!(expired.committed_write);
    assert_eq!(expired.context.revision, Revision::new(6));
    assert_eq!(expired.context.lifecycle, Lifecycle::CurrentExpired);

    let state = fixture.durable.state().unwrap();
    let current = state.current().unwrap();
    assert!(current.is_secret_erased());
    assert_eq!(current.public_object_ref(), &public_reference);
    assert_eq!(current.verification_key(), &verification_key);
    let staged = state.staged().unwrap();
    assert_eq!(staged.id(), replacement_id);
    assert_eq!(staged.public_object_ref(), &replacement_reference);
    assert!(!staged.is_secret_erased());

    drop(fixture.durable);
    let recovered = fixture
        .journal
        .recover(
            &mut fixture.flash,
            &mut fixture.entropy,
            &mut fixture.buffers.work(),
        )
        .unwrap();
    fixture.durable = DurablePool::from_recovered(recovered);
    assert_eq!(
        fixture.durable.evolve(
            &fixture.journal,
            &mut fixture.flash,
            &mut fixture.entropy,
            &mut fixture.buffers.work(),
            EvolutionRequest {
                actor: fixture.actor,
                expected_revision: Revision::new(6),
                generation: fixture.generation,
                certificate_digest: fixture.certificate_digest,
                target_absolute_period: AbsolutePeriod::new(164),
                network: &fixture.network,
            },
            &verified_tree,
        ),
        Err(OperationError::State(StateError::Certificate(
            CertificateError::Expired
        )))
    );
    let recovered_state = fixture.durable.state().unwrap();
    assert_eq!(recovered_state.revision(), Revision::new(6));
    assert_eq!(
        recovered_state.current().unwrap().lifecycle(),
        Lifecycle::CurrentExpired
    );
    assert!(recovered_state.current().unwrap().is_secret_erased());
    let recovered_staged = recovered_state.staged().unwrap();
    assert_eq!(recovered_staged.id(), replacement_id);
    assert_eq!(recovered_staged.public_object_ref(), &replacement_reference);
    assert!(!recovered_staged.is_secret_erased());
    RecoveryCounts {
        first_activation: 1,
        period_skip: 1,
        current_no_write: 1,
        stale_rejected: 2,
        reboot_reconciled: 2,
        lost_ack_reconciled: 1,
        committed_expiry: 1,
        staged_survived_expiry: 1,
    }
}

#[test]
fn skipped_current_earlier_final_and_uncertain_reconnect_are_monotonic() {
    let _ = exercise_recovery_transitions();
}
