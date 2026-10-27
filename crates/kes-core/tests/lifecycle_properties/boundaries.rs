use super::super::{device, registration};
use super::{PUBLIC_ARTIFACT_SYNTAX, candidate};
use kes_core::crypto::{Generation, KesKey, PublicTreeBuffer, verify};
use kes_core::state::{
    Actor, Device, DeviceCredential, DeviceMode, DirectoryEntry, DirectorySnapshot,
    MAX_PUBLIC_OBJECT_BYTES, PublicObject, StateError,
};
use kes_core::types::{GenerationId, HardwareSlot, KesLifetime, RelativePeriod, Revision};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use zeroize::Zeroizing;

fn empty_snapshot(revision: u64) -> DirectorySnapshot {
    DirectorySnapshot {
        config: *device(DeviceMode::Development, 2).config(),
        revision: Revision::new(revision),
        retirement: None,
        credential: DeviceCredential::new([0x52; 32]),
        pending_deletion: None,
        pending_enrollment: None,
        live: [None; 32],
        tombstones: [None; 32],
    }
}
#[test]
fn authenticated_directory_metadata_cannot_alias_pool_identities_or_slots() {
    let first = registration(0);
    let second = registration(1);
    let mut snapshot = empty_snapshot(2);
    let slot = HardwareSlot::new(27).unwrap();
    snapshot.live[11] = Some(DirectoryEntry::new(
        slot,
        first.pool_id(),
        first.incarnation(),
    ));
    let restored = Device::from_authenticated_snapshot(&snapshot).unwrap();
    assert_eq!(restored.find(first.pool_id()).unwrap().slot(), slot);
    snapshot.live[19] = Some(DirectoryEntry::new(
        slot,
        second.pool_id(),
        second.incarnation(),
    ));
    assert_eq!(
        Device::from_authenticated_snapshot(&snapshot),
        Err(StateError::DuplicatePool)
    );
    snapshot.live[19] = Some(DirectoryEntry::new(
        HardwareSlot::new(3).unwrap(),
        first.pool_id(),
        second.incarnation(),
    ));
    assert_eq!(
        Device::from_authenticated_snapshot(&snapshot),
        Err(StateError::DuplicatePool)
    );
}
#[test]
fn exhausted_directory_revision_refuses_without_losing_existing_identity() {
    let first = registration(0);
    let second = registration(1);
    let mut snapshot = empty_snapshot(u64::MAX);
    let slot = HardwareSlot::new(9).unwrap();
    snapshot.live[0] = Some(DirectoryEntry::new(
        slot,
        first.pool_id(),
        first.incarnation(),
    ));
    let mut restored = Device::from_authenticated_snapshot(&snapshot).unwrap();
    assert_eq!(
        restored.enroll(Actor::Management, &second, Revision::new(u64::MAX)),
        Err(StateError::CounterOverflow)
    );
    assert_eq!(restored.directory_revision().get(), u64::MAX);
    assert_eq!(restored.pool_count(), 1);
    assert_eq!(restored.find(first.pool_id()).unwrap().slot(), slot);
    assert!(restored.find(second.pool_id()).is_none());
}
fn fill_tree(key: &mut KesKey, tree: &mut PublicTreeBuffer) {
    xtask::oracles::protect_memory().expect("fresh no-swap disposable lab required");
    let mut seed = Zeroizing::new([0u8; 32]);
    File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut *seed)
        .unwrap();
    let mut job = Generation::begin(&mut seed, key.lifetime()).unwrap();
    for _ in 0..64 {
        job.step().unwrap();
    }
    (*key, *tree) = job.finish().unwrap();
}
#[test]
fn public_object_requires_exact_authenticated_reference_and_consistent_tree() {
    let mut key = KesKey::erased(KesLifetime::new(64).unwrap());
    let mut tree = PublicTreeBuffer::new();
    fill_tree(&mut key, &mut tree);
    let root = key.verification_key().unwrap();
    let generation = GenerationId::from_bytes([0x31; 16]);
    let object =
        PublicObject::from_parts(generation, tree.as_bytes(), PUBLIC_ARTIFACT_SYNTAX, &root)
            .unwrap();
    let reference = *object.reference();
    let mut encoded = [0u8; MAX_PUBLIC_OBJECT_BYTES];
    let length = object.encode_into(&mut encoded).unwrap();
    let decoded = PublicObject::parse(&encoded[..length], &reference, &root).unwrap();
    assert_eq!(decoded.tree(), tree.as_bytes());
    assert_eq!(decoded.encrypted_backup(), PUBLIC_ARTIFACT_SYNTAX);
    assert_eq!(
        decoded.backup_digest(),
        <[u8; 32]>::from(Sha256::digest(PUBLIC_ARTIFACT_SYNTAX))
    );
    assert!(matches!(
        PublicObject::parse(&encoded[..length - 1], &reference, &root),
        Err(StateError::InvalidObject)
    ));
    assert!(matches!(
        PublicObject::parse(&encoded[..length + 1], &reference, &root),
        Err(StateError::InvalidObject)
    ));
    encoded[9] = 2;
    assert!(matches!(
        PublicObject::parse(&encoded[..length], &reference, &root),
        Err(StateError::UnsupportedVersion)
    ));
    encoded[9] = 1;
    let mut mismatched = reference;
    mismatched.generation = GenerationId::from_bytes([0x32; 16]);
    assert!(matches!(
        PublicObject::parse(&encoded[..length], &mismatched, &root),
        Err(StateError::InvalidObject)
    ));
    encoded[32 + 64 * 32] ^= 1;
    let mut forged_reference = reference;
    forged_reference.digest = Sha256::digest(&encoded[..length]).into();
    assert!(matches!(
        PublicObject::parse(&encoded[..length], &forged_reference, &root),
        Err(StateError::InvalidObject)
    ));
    encoded[32 + 64 * 32] ^= 1;
    encoded[4096] ^= 1;
    forged_reference.digest = Sha256::digest(&encoded[..length]).into();
    assert!(matches!(
        PublicObject::parse(&encoded[..length], &forged_reference, &root),
        Err(StateError::InvalidObject)
    ));
}
#[test]
fn rejected_staging_preserves_existing_key_and_immutable_public_reference() {
    xtask::oracles::protect_memory().expect("fresh no-swap disposable lab required");
    let mut source = File::open("/dev/urandom").unwrap();
    let mut pool = registration(0);
    let other = registration(1);
    let scope = Actor::Pool {
        pool: pool.pool_id(),
        incarnation: pool.incarnation(),
    };
    let policy = pool.generation_policy();
    let first = candidate(&pool, 1, 0, &mut source);
    let original_id = first.id();
    let original_reference = *first.public_object_ref();
    pool.stage(scope, Revision::new(0), first, policy).unwrap();
    assert_eq!(
        pool.generation_policy(),
        policy,
        "ordinary revision changes must not invalidate captured authorization policy"
    );
    let replacement = candidate(&pool, 2, 1, &mut source);
    assert_eq!(
        pool.stage(scope, Revision::new(1), replacement, policy),
        Err(StateError::StagedConflict)
    );
    let foreign_candidate = candidate(&pool, 2, 2, &mut source);
    let foreign = Actor::Pool {
        pool: other.pool_id(),
        incarnation: other.incarnation(),
    };
    assert_eq!(
        pool.stage(foreign, Revision::new(1), foreign_candidate, policy),
        Err(StateError::WrongPool)
    );
    assert_eq!(pool.revision().get(), 1);
    assert_eq!(pool.generation_high_water().get(), 1);
    let staged = pool.staged().unwrap();
    assert_eq!(staged.id(), original_id);
    assert_eq!(staged.public_object_ref(), &original_reference);
    let mut signature = [0u8; 448];
    let message = b"public lifecycle preservation probe";
    let period = RelativePeriod::new(0).unwrap();
    staged
        .secret()
        .key()
        .unwrap()
        .sign_into(period, message, &mut signature)
        .unwrap();
    verify(
        staged.verification_key(),
        period,
        staged.lifetime(),
        message,
        &signature,
    )
    .unwrap();
}

#[test]
fn certification_retries_and_rejections_preserve_staged_key_and_public_object() {
    use super::super::registration_with_cold;
    use super::signed_certificate;
    use ed25519_dalek::SigningKey;
    use kes_core::state::{CertificationOutcome, Lifecycle};
    use kes_core::types::NetworkBinding;
    xtask::oracles::protect_memory().expect("fresh no-swap disposable lab required");
    let mut source = File::open("/dev/urandom").unwrap();
    let mut seed = Zeroizing::new([0; 32]);
    source.read_exact(&mut *seed).unwrap();
    let cold = SigningKey::from_bytes(&seed);
    let mut pool = registration_with_cold(0, cold.verifying_key().to_bytes());
    let first = candidate(&pool, 1, 0, &mut source);
    let id = first.id();
    let vk = *first.verification_key();
    let reference = *first.public_object_ref();
    let backup = *first.backup_digest();
    let scope = super::actor(&pool);
    let policy = pool.generation_policy();
    pool.stage(scope, Revision::new(0), first, policy).unwrap();
    let network = *pool.network();
    let cert = signed_certificate(&cold, &vk, false);
    let changed = signed_certificate(&cold, &vk, true);
    let wrong =
        NetworkBinding::from_genesis_bytes(43, b"public lifecycle model genesis", 64, 64).unwrap();
    assert_eq!(
        pool.certify(scope, Revision::new(0), id, &cert, &network),
        Err(StateError::RevisionConflict)
    );
    let wrong_hot = signed_certificate(&cold, &[0x71; 32], false);
    assert!(matches!(
        pool.certify(scope, Revision::new(1), id, &wrong_hot, &network),
        Err(StateError::Certificate(
            kes_core::certificate::CertificateError::WrongKesKey
        ))
    ));
    source.read_exact(&mut *seed).unwrap();
    let other_cold = SigningKey::from_bytes(&seed);
    let wrong_cold = signed_certificate(&other_cold, &vk, false);
    assert!(matches!(
        pool.certify(scope, Revision::new(1), id, &wrong_cold, &network),
        Err(StateError::Certificate(
            kes_core::certificate::CertificateError::WrongColdKey
        ))
    ));
    assert!(
        pool.certify(
            scope,
            Revision::new(1),
            id,
            &cert[..cert.len() - 1],
            &network
        )
        .is_err()
    );
    assert_eq!(pool.staged().unwrap().lifecycle(), Lifecycle::Staged);
    assert!(pool.staged().unwrap().certificate().is_none());
    assert_eq!(
        pool.certify(scope, Revision::new(1), id, &cert, &network),
        Ok(CertificationOutcome::Applied {
            revision: Revision::new(2)
        })
    );
    for revision in [0, 1, 2] {
        assert_eq!(
            pool.certify(scope, Revision::new(revision), id, &cert, &network),
            Ok(CertificationOutcome::AlreadyCertified {
                revision: Revision::new(2)
            })
        );
    }
    assert_eq!(
        pool.certify(scope, Revision::new(3), id, &cert, &network),
        Err(StateError::RevisionConflict)
    );
    assert_eq!(
        pool.certify(scope, Revision::new(2), id, &changed, &network),
        Err(StateError::CertificateConflict)
    );
    assert!(
        pool.certify(scope, Revision::new(0), id, &cert, &wrong)
            .is_err()
    );
    check_certification_scope(&mut pool, id, &cert, &network);
    assert_eq!(pool.revision(), Revision::new(2));
    assert_eq!(pool.generation_high_water().get(), 1);
    assert_eq!(pool.certificate_high_water(), None);
    assert!(pool.current().is_none());
    let staged = pool.staged().unwrap();
    assert_eq!(staged.lifecycle(), Lifecycle::CertifiedStaged);
    assert_eq!(staged.public_object_ref(), &reference);
    assert_eq!(staged.backup_digest(), &backup);
    assert_eq!(staged.certificate().unwrap().canonical_bytes(), cert);
    assert_eq!(
        staged.certificate().unwrap().digest(),
        &<[u8; 32]>::from(Sha256::digest(&cert))
    );
    let period = RelativePeriod::new(0).unwrap();
    let mut signature = [0; 448];
    staged
        .secret()
        .key()
        .unwrap()
        .sign_into(period, b"certification preservation", &mut signature)
        .unwrap();
    verify(
        &vk,
        period,
        staged.lifetime(),
        b"certification preservation",
        &signature,
    )
    .unwrap();
}

fn check_certification_scope(
    pool: &mut kes_core::state::PoolRegistration,
    id: GenerationId,
    certificate: &[u8],
    network: &kes_core::types::NetworkBinding,
) {
    use kes_core::types::IncarnationId;
    let revision = pool.revision();
    assert_eq!(
        pool.certify(Actor::Management, revision, id, certificate, network),
        Err(StateError::Unauthorized)
    );
    let foreign = Actor::Pool {
        pool: registration(1).pool_id(),
        incarnation: pool.incarnation(),
    };
    assert_eq!(
        pool.certify(foreign, revision, id, certificate, network),
        Err(StateError::WrongPool)
    );
    let foreign = Actor::Pool {
        pool: pool.pool_id(),
        incarnation: IncarnationId::from_bytes([0xff; 16]),
    };
    assert_eq!(
        pool.certify(foreign, revision, id, certificate, network),
        Err(StateError::WrongIncarnation)
    );
    assert_eq!(
        pool.certify(
            super::actor(pool),
            revision,
            GenerationId::from_bytes([0xff; 16]),
            certificate,
            network
        ),
        Err(StateError::StaleGeneration)
    );
}
