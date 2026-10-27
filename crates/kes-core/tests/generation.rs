use kes_core::cbor::Value;
use kes_core::crypto::{CryptoError, Generation};
use kes_core::journal::{JournalContext, JournalScope, PoolCodec, SnapshotCodec};
use kes_core::state::{
    Actor, Enrollment, GenerationSpec, KESGeneration, PoolRegistration, PublicObject, StateError,
};
use kes_core::types::{
    DeviceId, GenerationId, GenerationNumber, HardwareSlot, IncarnationId, KesLifetime,
    ManagementSequence, NetworkBinding, RelativePeriod, RequestId, Revision, TypeError,
};
use rand_chacha::rand_core::{TryCryptoRng, TryRngCore};
use sha2::{Digest, Sha256};
use std::io;

const BACKUP: &[u8] = include_bytes!("../../../fuzz/corpus/frame/backup-public-structure");

struct FailedEntropy;

impl TryRngCore for FailedEntropy {
    type Error = io::Error;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Err(io::Error::other("entropy unavailable"))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Err(io::Error::other("entropy unavailable"))
    }

    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Self::Error> {
        Err(io::Error::other("entropy unavailable"))
    }
}

impl TryCryptoRng for FailedEntropy {}

fn pool() -> PoolRegistration {
    let recipient_public_key = [0x71; 32];
    PoolRegistration::new(
        Actor::Management,
        Enrollment {
            incarnation: IncarnationId::from_bytes([0x21; 16]),
            cold_verification_key: [0x31; 32],
            network: NetworkBinding::from_genesis_bytes(42, b"generation model", 129_600, 64)
                .unwrap(),
            machine_public_key: [0x41; 32],
            recipient_public_key,
            recipient_id: Sha256::digest(recipient_public_key).into(),
            management_sequence: ManagementSequence::new(1),
            management_request: RequestId::from_bytes([0x51; 16]),
            management_payload_digest: [0x61; 32],
        },
    )
    .unwrap()
}

fn actor(pool: &PoolRegistration) -> Actor {
    Actor::Pool {
        pool: pool.pool_id(),
        incarnation: pool.incarnation(),
    }
}

fn candidate(
    pool: &PoolRegistration,
    number: u64,
    generation_id: GenerationId,
    request: RequestId,
) -> KESGeneration {
    let lifetime = KesLifetime::new(64).unwrap();
    let mut seed = [number as u8 + 1; 32];
    let mut job = Generation::begin(&mut seed, lifetime).unwrap();
    for _ in 0..64 {
        job.step().unwrap();
    }
    let (key, tree) = job.finish().unwrap();
    let verified = tree.verify(&key.verification_key().unwrap()).unwrap();
    let verification_key = key.verification_key().unwrap();
    let object = PublicObject::from_parts(
        generation_id,
        verified.as_bytes(),
        BACKUP,
        &verification_key,
    )
    .unwrap();
    KESGeneration::new_staged(
        GenerationSpec {
            generation_id,
            generation_number: GenerationNumber::new(number),
            creation_request: request,
            creation_payload_digest: [number as u8; 32],
            pool: pool.pool_id(),
            incarnation: pool.incarnation(),
            verification_key,
            lifetime,
            recipient_id: *pool.recipient_id(),
            public_object: object,
        },
        key,
    )
    .unwrap()
}

fn context(pool: &PoolRegistration) -> JournalContext {
    JournalContext {
        device: DeviceId::from_bytes([0x11; 16]),
        scope: JournalScope::Pool {
            slot: HardwareSlot::new(0).unwrap(),
            pool: pool.pool_id(),
            incarnation: pool.incarnation(),
        },
    }
}

fn with_changed_policy(pool: &PoolRegistration, policy_index: usize) -> PoolRegistration {
    let context = context(pool);
    let mut encoded = [0; 3440];
    let length = PoolCodec::encode(pool, context, &mut encoded).unwrap();
    let offset = {
        let root = Value::parse(&encoded[..length]).unwrap();
        let mut policy = root
            .array()
            .unwrap()
            .nth(policy_index)
            .unwrap()
            .array()
            .unwrap();
        let epoch = policy.nth(1 + usize::from(policy_index == 6)).unwrap();
        assert_eq!(epoch.uint().unwrap(), 0);
        epoch.encoded().as_ptr() as usize - encoded.as_ptr() as usize
    };
    encoded[offset] = 1;
    PoolCodec::decode(&encoded[..length], context).unwrap()
}

#[test]
fn entropy_failure_and_incomplete_generation_publish_nothing() {
    let mut entropy = FailedEntropy;
    assert_eq!(
        GenerationId::random(&mut entropy),
        Err(TypeError::EntropyUnavailable)
    );
    assert_eq!(
        RequestId::random(&mut entropy),
        Err(TypeError::EntropyUnavailable)
    );

    let pool = pool();
    let lifetime = KesLifetime::new(64).unwrap();
    let mut seed = [0x81; 32];
    let mut job = Generation::begin(&mut seed, lifetime).unwrap();
    for _ in 0..63 {
        job.step().unwrap();
    }
    assert!(matches!(
        job.finish(),
        Err(CryptoError::GenerationIncomplete)
    ));
    assert!(pool.staged().is_none());
    assert_eq!(pool.generation_high_water(), GenerationNumber::new(0));
}

#[test]
fn request_and_generation_identity_are_stable_and_staged_capacity_is_one() {
    let mut pool = pool();
    let request = RequestId::from_bytes([0x91; 16]);
    let generation = GenerationId::from_bytes([0x92; 16]);
    let first = candidate(&pool, 1, generation, request);
    assert_eq!(first.id(), generation);
    assert_eq!(first.creation_request(), request);
    assert_eq!(first.creation_payload_digest(), &[1; 32]);
    let policy = pool.generation_policy();
    pool.stage(actor(&pool), Revision::new(0), first, policy)
        .unwrap();
    let retained = pool.staged().unwrap();
    assert_eq!(retained.id(), generation);
    assert_eq!(retained.creation_request(), request);

    let second = candidate(
        &pool,
        2,
        GenerationId::from_bytes([0x93; 16]),
        RequestId::from_bytes([0x94; 16]),
    );
    assert_eq!(
        pool.stage(actor(&pool), Revision::new(1), second, policy),
        Err(StateError::StagedConflict)
    );
    assert_eq!(pool.staged().unwrap().id(), generation);
}

#[test]
fn public_artifact_is_immutable_after_secret_evolution_and_parse_recovery() {
    let lifetime = KesLifetime::new(64).unwrap();
    let mut seed = [0xa1; 32];
    let mut job = Generation::begin(&mut seed, lifetime).unwrap();
    for _ in 0..64 {
        job.step().unwrap();
    }
    let (mut key, tree) = job.finish().unwrap();
    let verified = tree.verify(&key.verification_key().unwrap()).unwrap();
    let verification_key = key.verification_key().unwrap();
    let generation = GenerationId::from_bytes([0xa2; 16]);
    let object =
        PublicObject::from_parts(generation, verified.as_bytes(), BACKUP, &verification_key)
            .unwrap();
    let reference = *object.reference();
    let mut before = vec![0; usize::from(reference.total_length)];
    object.encode_into(&mut before).unwrap();

    key.evolve_to(RelativePeriod::new(17).unwrap(), &verified)
        .unwrap();
    let restored = PublicObject::parse(&before, &reference, &verification_key).unwrap();
    let mut after = vec![0; before.len()];
    restored.encode_into(&mut after).unwrap();
    assert_eq!(after, before);
    assert_eq!(restored.encrypted_backup(), BACKUP);
    assert_eq!(restored.reference(), &reference);
}

#[test]
fn recipient_or_credential_epoch_change_cancels_captured_generation_policy() {
    for index in [5, 6] {
        let original = pool();
        let captured = original.generation_policy();
        let generation = candidate(
            &original,
            1,
            GenerationId::from_bytes([0xb1; 16]),
            RequestId::from_bytes([0xb2; 16]),
        );
        let mut changed = with_changed_policy(&original, index);
        let revision = changed.revision();
        assert_eq!(
            changed.stage(actor(&changed), revision, generation, captured),
            Err(StateError::PolicyChanged)
        );
        assert!(changed.staged().is_none());
        assert_eq!(changed.generation_high_water(), GenerationNumber::new(0));
    }
}

#[test]
fn completion_merges_with_latest_revision_when_captured_policy_is_unchanged() {
    let mut pool = pool();
    let policy = pool.generation_policy();
    let generation = candidate(
        &pool,
        1,
        GenerationId::from_bytes([0xc1; 16]),
        RequestId::from_bytes([0xc2; 16]),
    );
    <PoolCodec as SnapshotCodec>::set_recovery_revision(&mut pool, Revision::new(7));
    pool.stage(actor(&pool), Revision::new(0), generation, policy)
        .unwrap();
    assert_eq!(pool.revision(), Revision::new(8));
    assert_eq!(
        pool.staged().unwrap().id(),
        GenerationId::from_bytes([0xc1; 16])
    );
}

#[test]
fn owned_generation_moves_between_turns_and_preserves_enrolled_lifetime() {
    assert!(core::mem::size_of::<Generation>() <= 5120);
    let mut seed = [0x42; 32];
    let lifetime = KesLifetime::new(32).unwrap();
    let mut scheduled = Some(Generation::begin(&mut seed, lifetime).unwrap());
    assert_eq!(seed, [0; 32]);
    for completed in 1..=64 {
        let mut job = scheduled.take().unwrap();
        assert_eq!(job.completed_leaves(), completed - 1);
        assert_eq!(job.step().unwrap(), completed);
        scheduled = Some(job);
    }
    let mut job = scheduled.take().unwrap();
    assert_eq!(job.step(), Err(CryptoError::GenerationComplete));
    let (mut key, tree) = job.finish().unwrap();
    assert_eq!(key.lifetime(), lifetime);
    assert_eq!(key.period().unwrap(), RelativePeriod::new(0).unwrap());
    let verification_key = key.verification_key().unwrap();
    let verified = tree.verify(&verification_key).unwrap();
    key.evolve_to(RelativePeriod::new(31).unwrap(), &verified).unwrap();
    assert_eq!(
        key.evolve_to(RelativePeriod::new(32).unwrap(), &verified),
        Err(CryptoError::LifetimeExceeded),
    );
}

#[test]
fn cancelled_owned_generation_does_not_retain_a_borrow_or_publish_a_key() {
    let lifetime = KesLifetime::new(64).unwrap();
    let mut seed = [0x43; 32];
    let mut job = Generation::begin(&mut seed, lifetime).unwrap();
    job.step().unwrap();
    drop(job); // Owned zeroizing signing state and seed stack are dropped together.
    assert_eq!(seed, [0; 32]);
    seed.fill(0x44);
    let job = Generation::begin(&mut seed, lifetime).unwrap();
    assert_eq!(job.completed_leaves(), 0);
    assert!(matches!(job.finish(), Err(CryptoError::GenerationIncomplete)));
}
