use kes_core::{
    activation::{ActivationRequest, CertificationRequest, EvolutionRequest, OperationError},
    certificate::CertificateError,
    crypto::{CryptoError, verify},
    signing::SigningRequest,
    state::{Lifecycle, StateError},
    types::{AbsolutePeriod, KesLifetime, Revision},
};
use sha2::{Digest, Sha256};
#[path = "support/mod.rs"]
mod support;
use support::Fixture;

#[test]
fn certify_activate_evolve_and_sign_only_after_durable_cleanup() {
    let mut fixture = Fixture::new();
    let certification = fixture
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
    assert_eq!(certification.revision, Revision::new(2));
    assert_eq!(certification.lifecycle, Lifecycle::CertifiedStaged);

    let verified_tree = fixture
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
                current_absolute_period: AbsolutePeriod::new(102),
            },
            &verified_tree,
        )
        .unwrap();
    assert_eq!(activated.revision, Revision::new(3));
    assert_eq!(activated.relative_period.get(), 2);
    assert_eq!(activated.lifecycle, Lifecycle::Active);

    let message = b"exact Cardano signable bytes";
    let signed = fixture
        .durable
        .sign(
            &fixture.journal,
            &mut fixture.flash,
            &mut fixture.entropy,
            &mut fixture.buffers.work(),
            SigningRequest {
                actor: fixture.actor,
                generation: fixture.generation,
                certificate_digest: fixture.certificate_digest,
                absolute_period: AbsolutePeriod::new(103),
                network: &fixture.network,
                message,
            },
            &verified_tree,
        )
        .unwrap();
    assert_eq!(signed.context.revision, Revision::new(4));
    assert_eq!(signed.context.relative_period.get(), 3);
    let expected_message_digest: [u8; 32] = Sha256::digest(message).into();
    assert_eq!(signed.message_digest, expected_message_digest);
    verify(
        fixture
            .durable
            .state()
            .unwrap()
            .current()
            .unwrap()
            .verification_key(),
        signed.context.relative_period,
        KesLifetime::new(64).unwrap(),
        message,
        &signed.signature,
    )
    .unwrap();

    let same = fixture
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
                target_absolute_period: AbsolutePeriod::new(103),
                network: &fixture.network,
            },
            &verified_tree,
        )
        .unwrap();
    assert!(!same.committed_write);
    assert_eq!(same.context.revision, Revision::new(4));

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
            target_absolute_period: AbsolutePeriod::new(102),
            network: &fixture.network,
        },
        &verified_tree,
    );
    assert_eq!(
        stale,
        Err(OperationError::State(StateError::Crypto(
            CryptoError::StalePeriod
        )))
    );
    assert!(fixture.durable.is_usable());

    drop(fixture.durable);
    let recovered = fixture
        .journal
        .recover(
            &mut fixture.flash,
            &mut fixture.entropy,
            &mut fixture.buffers.work(),
        )
        .unwrap();
    assert_eq!(recovered.state.revision(), Revision::new(4));
    let active = recovered.state.current().unwrap();
    assert_eq!(active.lifecycle(), Lifecycle::Active);
    assert_eq!(active.relative_period().get(), 3);
    assert!(recovered.state.staged().is_none());
}

#[test]
fn failed_cleanup_invalidates_ram_and_recovery_keeps_the_certified_staged_state() {
    let mut fixture = Fixture::new();
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
    let verified_tree = fixture
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
    fixture.flash.fail_next_mutation();
    assert_eq!(
        fixture.durable.activate_first(
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
                current_absolute_period: AbsolutePeriod::new(102),
            },
            &verified_tree,
        ),
        Err(OperationError::Journal(
            kes_core::journal::JournalError::Flash
        ))
    );
    assert!(!fixture.durable.is_usable());
    assert!(matches!(
        fixture.durable.state(),
        Err(OperationError::Invalidated)
    ));

    drop(fixture.durable);
    let recovered = fixture
        .journal
        .recover(
            &mut fixture.flash,
            &mut fixture.entropy,
            &mut fixture.buffers.work(),
        )
        .unwrap();
    assert_eq!(recovered.state.revision(), Revision::new(2));
    assert!(recovered.state.current().is_none());
    assert_eq!(
        recovered.state.staged().unwrap().lifecycle(),
        Lifecycle::CertifiedStaged
    );
}

#[test]
fn durable_lifecycle_property_covers_every_eligible_period_without_rollback() {
    let mut fixture = Fixture::new();
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
    let verified_tree = fixture
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
            &verified_tree,
        )
        .unwrap();

    for relative in 0u64..64 {
        let message = relative.to_be_bytes();
        let signed = fixture
            .durable
            .sign(
                &fixture.journal,
                &mut fixture.flash,
                &mut fixture.entropy,
                &mut fixture.buffers.work(),
                SigningRequest {
                    actor: fixture.actor,
                    generation: fixture.generation,
                    certificate_digest: fixture.certificate_digest,
                    absolute_period: AbsolutePeriod::new(100 + relative),
                    network: &fixture.network,
                    message: &message,
                },
                &verified_tree,
            )
            .unwrap();
        assert_eq!(signed.context.revision, Revision::new(3 + relative));
        assert_eq!(u64::from(signed.context.relative_period.get()), relative);
        verify(
            fixture
                .durable
                .state()
                .unwrap()
                .current()
                .unwrap()
                .verification_key(),
            signed.context.relative_period,
            KesLifetime::new(64).unwrap(),
            &message,
            &signed.signature,
        )
        .unwrap();

        if relative > 0 {
            assert!(matches!(
                fixture.durable.sign(
                    &fixture.journal,
                    &mut fixture.flash,
                    &mut fixture.entropy,
                    &mut fixture.buffers.work(),
                    SigningRequest {
                        actor: fixture.actor,
                        generation: fixture.generation,
                        certificate_digest: fixture.certificate_digest,
                        absolute_period: AbsolutePeriod::new(99 + relative),
                        network: &fixture.network,
                        message: &message,
                    },
                    &verified_tree,
                ),
                Err(OperationError::State(StateError::Crypto(
                    CryptoError::StalePeriod
                )))
            ));
            assert!(fixture.durable.is_usable());
        }
    }

    assert!(matches!(
        fixture.durable.sign(
            &fixture.journal,
            &mut fixture.flash,
            &mut fixture.entropy,
            &mut fixture.buffers.work(),
            SigningRequest {
                actor: fixture.actor,
                generation: fixture.generation,
                certificate_digest: fixture.certificate_digest,
                absolute_period: AbsolutePeriod::new(164),
                network: &fixture.network,
                message: b"expired",
            },
            &verified_tree,
        ),
        Err(OperationError::State(StateError::Certificate(
            CertificateError::Expired
        )))
    ));
    let expired = fixture.durable.state().unwrap();
    assert_eq!(expired.revision(), Revision::new(67));
    assert_eq!(
        expired.current().unwrap().lifecycle(),
        Lifecycle::CurrentExpired
    );
    assert!(expired.current().unwrap().is_secret_erased());
    assert!(fixture.durable.is_usable());

    drop(fixture.durable);
    let recovered = fixture
        .journal
        .recover(
            &mut fixture.flash,
            &mut fixture.entropy,
            &mut fixture.buffers.work(),
        )
        .unwrap();
    assert_eq!(recovered.state.revision(), Revision::new(67));
    assert_eq!(
        recovered.state.current().unwrap().lifecycle(),
        Lifecycle::CurrentExpired
    );
    assert!(recovered.state.current().unwrap().is_secret_erased());
}
