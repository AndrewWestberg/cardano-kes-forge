use kes_core::cbor::Value;
use kes_core::crypto::{CryptoError, Generation, KesKey, PublicTreeBuffer};
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
    let mut key = KesKey::erased(lifetime);
    let mut tree = PublicTreeBuffer::new();
    let mut job = Generation::begin(&mut seed, &mut key, &mut tree).unwrap();
    for _ in 0..64 {
        job.step().unwrap();
    }
    let verified = job.finish().unwrap();
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
    let mut key = KesKey::erased(lifetime);
    let mut tree = PublicTreeBuffer::new();
    let mut job = Generation::begin(&mut seed, &mut key, &mut tree).unwrap();
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
    let mut key = KesKey::erased(lifetime);
    let mut tree = PublicTreeBuffer::new();
    let mut job = Generation::begin(&mut seed, &mut key, &mut tree).unwrap();
    for _ in 0..64 {
        job.step().unwrap();
    }
    let verified = job.finish().unwrap();
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
