
use kes_core::cbor::Value;
use kes_core::generation::{
    Admission, CheckpointOutcome, Error, GenerationCoordinator, GenerationRequest, OperationStatus,
    PublicObjectStore, begin_key_generation, get_backup,
};
use kes_core::journal::{JournalContext, JournalScope, PoolCodec, SnapshotCodec};
use kes_core::state::{
    Actor, Enrollment, MAX_PUBLIC_OBJECT_BYTES, PoolRegistration, PublicObjectRef, StateError,
};
use kes_core::types::{
    DeviceId, GenerationNumber, HardwareSlot, IncarnationId, KesLifetime, ManagementSequence,
    NetworkBinding, RequestId, Revision,
};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use sha2::{Digest, Sha256};

fn pool() -> PoolRegistration {
    let recipient_public_key =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([0x71; 32])).to_bytes();
    PoolRegistration::new(
        Actor::Management,
        Enrollment {
            incarnation: IncarnationId::from_bytes([0x21; 16]),
            cold_verification_key: [0x31; 32],
            network: NetworkBinding::from_genesis_bytes(42, b"generation operations", 129_600, 64)
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

fn with_changed_recipient_epoch(pool: &PoolRegistration) -> PoolRegistration {
    let context = context(pool);
    let mut encoded = [0; 3440];
    let length = PoolCodec::encode(pool, context, &mut encoded).unwrap();
    let offset = {
        let root = Value::parse(&encoded[..length]).unwrap();
        let epoch = root
            .array()
            .unwrap()
            .nth(5)
            .unwrap()
            .array()
            .unwrap()
            .nth(1)
            .unwrap();
        assert_eq!(epoch.uint().unwrap(), 0);
        epoch.encoded().as_ptr() as usize - encoded.as_ptr() as usize
    };
    encoded[offset] = 1;
    PoolCodec::decode(&encoded[..length], context).unwrap()
}

struct MemoryStore {
    bytes: [u8; MAX_PUBLIC_OBJECT_BYTES],
    length: usize,
    reference: Option<PublicObjectRef>,
    writes: usize,
    reads: usize,
    discarded: bool,
    corrupt_read: bool,
}

impl MemoryStore {
    fn new() -> Self {
        Self {
            bytes: [0; MAX_PUBLIC_OBJECT_BYTES],
            length: 0,
            reference: None,
            writes: 0,
            reads: 0,
            discarded: false,
            corrupt_read: false,
        }
    }
}

impl PublicObjectStore for MemoryStore {
    type Error = ();

    fn write(&mut self, reference: &PublicObjectRef, bytes: &[u8]) -> Result<(), Self::Error> {
        self.bytes[..bytes.len()].copy_from_slice(bytes);
        self.length = bytes.len();
        self.reference = Some(*reference);
        self.writes += 1;
        Ok(())
    }

    fn read(
        &mut self,
        reference: &PublicObjectRef,
        output: &mut [u8],
    ) -> Result<usize, Self::Error> {
        assert_eq!(self.reference, Some(*reference));
        output[..self.length].copy_from_slice(&self.bytes[..self.length]);
        if self.corrupt_read {
            output[self.length - 1] ^= 1;
        }
        self.reads += 1;
        Ok(self.length)
    }

    fn discard(&mut self, reference: &PublicObjectRef) -> Result<(), Self::Error> {
        assert_eq!(self.reference, Some(*reference));
        self.bytes[..self.length].fill(0);
        self.length = 0;
        self.reference = None;
        self.discarded = true;
        Ok(())
    }
}

fn request(pool: &PoolRegistration, id: u8) -> GenerationRequest {
    GenerationRequest {
        actor: actor(pool),
        request: RequestId::from_bytes([id; 16]),
        payload_digest: [id.wrapping_add(1); 32],
        next_generation_number: GenerationNumber::new(1),
        expected_revision: pool.revision(),
    }
}

#[test]
fn generation_is_admitted_once_published_after_readback_and_retrieved_byte_exact() {
    let mut pool = pool();
    let mut coordinator = GenerationCoordinator::new();
    let mut entropy = ChaCha20Rng::from_seed([0x81; 32]);
    let operation = match coordinator
        .admit(&pool, request(&pool, 0x91), &mut entropy)
        .unwrap()
    {
        Admission::Started(operation) => operation,
        Admission::Existing(_) => panic!("fresh request must start"),
    };
    let generation_id = operation.generation();
    assert_eq!(
        coordinator.status(
            &pool,
            RequestId::from_bytes([0x91; 16]),
            Some(GenerationNumber::new(1))
        ),
        OperationStatus::InProgress {
            request: RequestId::from_bytes([0x91; 16]),
            generation_number: GenerationNumber::new(1)
        }
    );
    assert!(matches!(
        coordinator
            .admit(&pool, request(&pool, 0x91), &mut entropy)
            .unwrap(),
        Admission::Existing(OperationStatus::InProgress { .. })
    ));

    let mut job = begin_key_generation(&mut entropy, KesLifetime::new(64).unwrap()).unwrap();
    for completed in 1..=64 {
        assert_eq!(job.step().unwrap(), completed);
    }
    let (key, tree) = job.finish().unwrap();
    let verified = tree.verify(&key.verification_key().unwrap()).unwrap();
    <PoolCodec as SnapshotCodec>::set_recovery_revision(&mut pool, Revision::new(7));
    let mut store = MemoryStore::new();
    let mut write_buffer = [0; MAX_PUBLIC_OBJECT_BYTES];
    let mut read_buffer = [0; MAX_PUBLIC_OBJECT_BYTES];
    let descriptor = coordinator
        .complete(
            &mut pool,
            operation,
            key,
            &verified,
            DeviceId::from_bytes([0xa1; 16]),
            &kes_core::session::DeviceIdentityKey::from_seed(zeroize::Zeroizing::new([0xa2; 32])),
            &mut entropy,
            &mut store,
            &mut write_buffer,
            &mut read_buffer,
        )
        .unwrap();
    assert_eq!(store.writes, 1);
    assert_eq!(store.reads, 1);
    assert_eq!(descriptor.generation, generation_id);
    assert_eq!(pool.revision(), Revision::new(8));
    assert_eq!(
        descriptor.creation_request,
        RequestId::from_bytes([0x91; 16])
    );
    assert_eq!(descriptor.creation_payload_digest, [0x92; 32]);
    assert_eq!(descriptor.generation_number, GenerationNumber::new(1));
    assert!(matches!(
        coordinator.status(
            &pool,
            RequestId::from_bytes([0x91; 16]),
            Some(GenerationNumber::new(1))
        ),
        OperationStatus::Committed(committed) if committed == descriptor
    ));

    let original = store.bytes;
    let backup = get_backup(&pool, generation_id, &mut store, &mut read_buffer).unwrap();
    assert_eq!(&backup.bytes[..8], b"KESBKP01");
    assert_eq!(backup.digest, descriptor.artifact_digest);
    assert_eq!(store.bytes, original);
    assert!(matches!(
        coordinator.status(
            &pool,
            RequestId::from_bytes([0xee; 16]),
            Some(GenerationNumber::new(1))
        ),
        OperationStatus::Unknown { .. }
    ));
}

#[test]
fn corrupted_public_object_readback_never_publishes_and_records_not_committed() {
    let mut pool = pool();
    let mut coordinator = GenerationCoordinator::new();
    let mut entropy = ChaCha20Rng::from_seed([0xb1; 32]);
    let request = request(&pool, 0xb2);
    let operation = match coordinator.admit(&pool, request, &mut entropy).unwrap() {
        Admission::Started(operation) => operation,
        Admission::Existing(_) => panic!("fresh request must start"),
    };
    let mut job = begin_key_generation(&mut entropy, KesLifetime::new(64).unwrap()).unwrap();
    for _ in 0..64 {
        job.step().unwrap();
    }
    let (key, tree) = job.finish().unwrap();
    let verified = tree.verify(&key.verification_key().unwrap()).unwrap();
    let mut store = MemoryStore::new();
    store.corrupt_read = true;
    let error = coordinator
        .complete(
            &mut pool,
            operation,
            key,
            &verified,
            DeviceId::from_bytes([0xc1; 16]),
            &kes_core::session::DeviceIdentityKey::from_seed(zeroize::Zeroizing::new([0xc2; 32])),
            &mut entropy,
            &mut store,
            &mut [0; MAX_PUBLIC_OBJECT_BYTES],
            &mut [0; MAX_PUBLIC_OBJECT_BYTES],
        )
        .unwrap_err();
    assert_eq!(error, Error::Readback(StateError::InvalidObject));
    assert!(store.discarded);
    assert!(pool.staged().is_none());
    assert_eq!(pool.generation_high_water(), GenerationNumber::new(0));
    assert_eq!(
        coordinator.status(&pool, request.request, Some(request.next_generation_number)),
        OperationStatus::NotCommitted {
            request: request.request,
            generation_number: request.next_generation_number
        }
    );
}

#[test]
fn changed_generation_policy_cancels_before_public_object_write() {
    let original = pool();
    let request = request(&original, 0xcc);
    let mut coordinator = GenerationCoordinator::new();
    let mut entropy = ChaCha20Rng::from_seed([0xcd; 32]);
    let operation = match coordinator.admit(&original, request, &mut entropy).unwrap() {
        Admission::Started(operation) => operation,
        Admission::Existing(_) => panic!("fresh request must start"),
    };
    let mut job = begin_key_generation(&mut entropy, KesLifetime::new(64).unwrap()).unwrap();
    for _ in 0..64 {
        job.step().unwrap();
    }
    let (key, tree) = job.finish().unwrap();
    let verified = tree.verify(&key.verification_key().unwrap()).unwrap();
    let mut changed = with_changed_recipient_epoch(&original);
    let mut store = MemoryStore::new();
    let error = coordinator
        .complete(
            &mut changed,
            operation,
            key,
            &verified,
            DeviceId::from_bytes([0xce; 16]),
            &kes_core::session::DeviceIdentityKey::from_seed(zeroize::Zeroizing::new([0xcf; 32])),
            &mut entropy,
            &mut store,
            &mut [0; MAX_PUBLIC_OBJECT_BYTES],
            &mut [0; MAX_PUBLIC_OBJECT_BYTES],
        )
        .unwrap_err();
    assert_eq!(error, Error::State(StateError::PolicyChanged));
    assert_eq!(store.writes, 0);
    assert!(changed.staged().is_none());
    assert!(matches!(
        coordinator.status(
            &changed,
            request.request,
            Some(request.next_generation_number)
        ),
        OperationStatus::NotCommitted { .. }
    ));
}

#[test]
fn stale_revision_wrong_scope_and_unknown_or_reclaimed_status_are_distinct() {
    let pool = pool();
    let mut coordinator = GenerationCoordinator::new();
    let mut entropy = ChaCha20Rng::from_seed([0xd1; 32]);
    let mut stale = request(&pool, 0xd2);
    stale.expected_revision = Revision::new(7);
    assert!(matches!(
        coordinator.admit(&pool, stale, &mut entropy),
        Err(Error::State(StateError::RevisionConflict))
    ));
    let mut wrong_scope = request(&pool, 0xd3);
    wrong_scope.actor = Actor::Management;
    assert!(matches!(
        coordinator.admit(&pool, wrong_scope, &mut entropy),
        Err(Error::State(StateError::Unauthorized))
    ));
    assert!(matches!(
        coordinator.status(&pool, RequestId::from_bytes([0xd4; 16]), None),
        OperationStatus::Unknown { .. }
    ));
    assert!(matches!(
        coordinator.status(
            &pool,
            RequestId::from_bytes([0xd5; 16]),
            Some(GenerationNumber::new(0))
        ),
        OperationStatus::Unknown { .. }
    ));
    let operation = match coordinator
        .admit(&pool, request(&pool, 0xd6), &mut entropy)
        .unwrap()
    {
        Admission::Started(operation) => operation,
        Admission::Existing(_) => panic!("fresh request must start"),
    };
    let checkpoint = coordinator.checkpoint().unwrap();
    assert_eq!(checkpoint.outcome, CheckpointOutcome::InProgress);
    let restored = GenerationCoordinator::from_checkpoint(checkpoint);
    assert!(matches!(
        restored.status(
            &pool,
            operation.request(),
            Some(operation.generation_number())
        ),
        OperationStatus::InProgress { .. }
    ));
    let mut reclaimed =
        GenerationCoordinator::from_checkpoint(kes_core::generation::GenerationCheckpoint {
            outcome: CheckpointOutcome::Committed,
            ..checkpoint
        });
    assert!(matches!(
        reclaimed.status(
            &pool,
            operation.request(),
            Some(operation.generation_number())
        ),
        OperationStatus::ResultReclaimed { .. }
    ));
    assert!(matches!(
        reclaimed
            .admit(
                &pool,
                GenerationRequest {
                    actor: actor(&pool),
                    request: checkpoint.request,
                    payload_digest: checkpoint.payload_digest,
                    next_generation_number: checkpoint.generation_number,
                    expected_revision: pool.revision(),
                },
                &mut entropy,
            )
            .unwrap(),
        Admission::Existing(OperationStatus::ResultReclaimed { .. })
    ));
}
