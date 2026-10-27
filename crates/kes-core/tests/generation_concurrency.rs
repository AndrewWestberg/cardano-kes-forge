
use kes_core::{
    activation::{ActivationRequest, CertificationRequest},
    cbor::Value,
    crypto::{CryptoError, KesKey, PublicTreeBuffer},
    generation::{
        Admission, Error, GenerationCoordinator, GenerationOperation, GenerationRequest,
        OperationStatus, PublicObjectStore, begin_key_generation,
    },
    journal::{JournalContext, JournalScope, PoolCodec, SnapshotCodec},
    signing::SigningRequest,
    state::{
        Actor, Enrollment, MAX_PUBLIC_OBJECT_BYTES, PoolRegistration, PublicObjectRef, StateError,
    },
    types::{
        AbsolutePeriod, DeviceId, GenerationNumber, HardwareSlot, IncarnationId, KesLifetime,
        ManagementSequence, NetworkBinding, RelativePeriod, RequestId, Revision,
    },
};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use sha2::{Digest, Sha256};

#[allow(dead_code)]
#[path = "support/mod.rs"]
mod support;
use support::Fixture;

struct FaultStore {
    bytes: [u8; MAX_PUBLIC_OBJECT_BYTES],
    length: usize,
    reference: Option<PublicObjectRef>,
    writes: usize,
    reads: usize,
    discard_attempts: usize,
    corrupt_read: bool,
    fail_discard: bool,
}

impl FaultStore {
    fn new() -> Self {
        Self {
            bytes: [0; MAX_PUBLIC_OBJECT_BYTES],
            length: 0,
            reference: None,
            writes: 0,
            reads: 0,
            discard_attempts: 0,
            corrupt_read: false,
            fail_discard: false,
        }
    }
}

impl PublicObjectStore for FaultStore {
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
        self.discard_attempts += 1;
        if self.fail_discard {
            return Err(());
        }
        self.bytes[..self.length].fill(0);
        self.length = 0;
        self.reference = None;
        Ok(())
    }
}

fn pool() -> PoolRegistration {
    let recipient_public_key =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([0x71; 32])).to_bytes();
    PoolRegistration::new(
        Actor::Management,
        Enrollment {
            incarnation: IncarnationId::from_bytes([0x21; 16]),
            cold_verification_key: [0x31; 32],
            network: NetworkBinding::from_genesis_bytes(42, b"generation concurrency", 129_600, 64)
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
        device: DeviceId::from_bytes([0x19; 16]),
        scope: JournalScope::Pool {
            slot: HardwareSlot::new(0).unwrap(),
            pool: pool.pool_id(),
            incarnation: pool.incarnation(),
        },
    }
}

fn request(pool: &PoolRegistration, id: u8) -> GenerationRequest {
    GenerationRequest {
        actor: actor(pool),
        request: RequestId::from_bytes([id; 16]),
        payload_digest: [id.wrapping_add(1); 32],
        next_generation_number: GenerationNumber::new(pool.generation_high_water().get() + 1),
        expected_revision: pool.revision(),
    }
}

fn admit(
    coordinator: &mut GenerationCoordinator,
    pool: &PoolRegistration,
    id: u8,
    rng: &mut ChaCha20Rng,
) -> (GenerationRequest, GenerationOperation) {
    let request = request(pool, id);
    let operation = match coordinator.admit(pool, request, rng).unwrap() {
        Admission::Started(operation) => operation,
        Admission::Existing(_) => panic!("fresh generation replayed"),
    };
    (request, operation)
}

fn finish_generation<'tree>(
    rng: &mut ChaCha20Rng,
    key: &mut KesKey,
    tree: &'tree mut PublicTreeBuffer,
) -> kes_core::crypto::VerifiedPublicTree<'tree> {
    let mut job = begin_key_generation(rng, key.lifetime()).unwrap();
    for _ in 0..64 {
        job.step().unwrap();
    }
    (*key, *tree) = job.finish().unwrap();
    tree.verify(&key.verification_key().unwrap()).unwrap()
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

fn copy_pool(pool: &PoolRegistration) -> PoolRegistration {
    let context = context(pool);
    let mut encoded = [0; 3440];
    let length = PoolCodec::encode(pool, context, &mut encoded).unwrap();
    PoolCodec::decode(&encoded[..length], context).unwrap()
}

#[test]
fn generation_completion_merges_after_active_signing_advances_revision() {
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
    let active_tree = fixture
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
                current_absolute_period: AbsolutePeriod::new(102),
            },
            &active_tree,
        )
        .unwrap();

    let mut coordinator = GenerationCoordinator::new();
    let mut rng = ChaCha20Rng::from_seed([0x81; 32]);
    let (_, operation) = admit(
        &mut coordinator,
        fixture.durable.state().unwrap(),
        0x82,
        &mut rng,
    );
    let mut replacement_key = KesKey::erased(KesLifetime::new(64).unwrap());
    let mut replacement_tree = PublicTreeBuffer::new();
    let replacement_verified =
        finish_generation(&mut rng, &mut replacement_key, &mut replacement_tree);

    let signing = fixture
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
                message: b"advance active revision while replacement generation finishes",
            },
            &active_tree,
        )
        .unwrap();
    assert_eq!(signing.context.revision, Revision::new(4));
    assert_eq!(
        signing.context.relative_period,
        RelativePeriod::new(3).unwrap()
    );

    let mut latest = copy_pool(fixture.durable.state().unwrap());
    let mut store = FaultStore::new();
    let descriptor = coordinator
        .complete(
            &mut latest,
            operation,
            replacement_key,
            &replacement_verified,
            DeviceId::from_bytes([0x83; 16]),
            &kes_core::session::DeviceIdentityKey::from_seed(zeroize::Zeroizing::new([0x84; 32])),
            &mut rng,
            &mut store,
            &mut [0; MAX_PUBLIC_OBJECT_BYTES],
            &mut [0; MAX_PUBLIC_OBJECT_BYTES],
        )
        .unwrap();
    assert_eq!(latest.revision(), Revision::new(5));
    assert_eq!(latest.current().unwrap().relative_period().get(), 3);
    assert_eq!(latest.staged().unwrap().id(), descriptor.generation);
    assert_eq!(latest.generation_high_water(), GenerationNumber::new(2));
}

#[test]
fn recipient_or_credential_epoch_change_cancels_delayed_completion() {
    for (case, policy_index) in [("recipient", 5usize), ("credential", 6usize)] {
        let original = pool();
        let mut coordinator = GenerationCoordinator::new();
        let mut rng = ChaCha20Rng::from_seed([policy_index as u8; 32]);
        let (request, operation) = admit(&mut coordinator, &original, 0x91, &mut rng);
        let mut key = KesKey::erased(KesLifetime::new(64).unwrap());
        let mut tree = PublicTreeBuffer::new();
        let verified = finish_generation(&mut rng, &mut key, &mut tree);
        let mut changed = with_changed_policy(&original, policy_index);
        let mut store = FaultStore::new();
        let error = coordinator
            .complete(
                &mut changed,
                operation,
                key,
                &verified,
                DeviceId::from_bytes([0x92; 16]),
                &kes_core::session::DeviceIdentityKey::from_seed(zeroize::Zeroizing::new([0x93; 32])),
                &mut rng,
                &mut store,
                &mut [0; MAX_PUBLIC_OBJECT_BYTES],
                &mut [0; MAX_PUBLIC_OBJECT_BYTES],
            )
            .unwrap_err();
        assert_eq!(error, Error::State(StateError::PolicyChanged), "{case}");
        assert_eq!(store.writes, 0, "{case}");
        assert!(changed.staged().is_none(), "{case}");
        assert_eq!(
            coordinator.status(
                &changed,
                request.request,
                Some(request.next_generation_number)
            ),
            OperationStatus::NotCommitted {
                request: request.request,
                generation_number: request.next_generation_number,
            },
            "{case}"
        );
    }
}

#[test]
fn cancellation_wipes_workspace_and_rejects_delayed_completion() {
    let pool = pool();
    let mut coordinator = GenerationCoordinator::new();
    let mut rng = ChaCha20Rng::from_seed([0xa1; 32]);
    let (request, operation) = admit(&mut coordinator, &pool, 0xa2, &mut rng);
    let mut cancelled_key = KesKey::erased(KesLifetime::new(64).unwrap());
    let mut cancelled_tree = PublicTreeBuffer::new();
    {
        let _ = finish_generation(&mut rng, &mut cancelled_key, &mut cancelled_tree);
    }
    coordinator.cancel(operation, &mut cancelled_key).unwrap();
    assert_eq!(
        cancelled_key.sign_into(
            RelativePeriod::new(0).unwrap(),
            b"retired generation workspace",
            &mut [0; 448],
        ),
        Err(CryptoError::ErasedKey)
    );

    assert!(matches!(
        coordinator.admit(&pool, request, &mut rng),
        Ok(Admission::Existing(OperationStatus::NotCommitted {
            request: replay_request,
            generation_number,
        })) if replay_request == request.request
            && generation_number == request.next_generation_number
    ));
    assert!(pool.staged().is_none());
}

#[test]
fn interrupted_cleanup_and_delayed_reply_cannot_resurrect_orphaned_generation() {
    let mut pool = pool();
    let mut coordinator = GenerationCoordinator::new();
    let mut rng = ChaCha20Rng::from_seed([0xb1; 32]);
    let (request, operation) = admit(&mut coordinator, &pool, 0xb2, &mut rng);
    let generation = operation.generation();
    let mut key = KesKey::erased(KesLifetime::new(64).unwrap());
    let mut tree = PublicTreeBuffer::new();
    let verified = finish_generation(&mut rng, &mut key, &mut tree);
    let mut store = FaultStore::new();
    store.corrupt_read = true;
    store.fail_discard = true;
    assert_eq!(
        coordinator.complete(
            &mut pool,
            operation,
            key,
            &verified,
            DeviceId::from_bytes([0xb3; 16]),
            &kes_core::session::DeviceIdentityKey::from_seed(zeroize::Zeroizing::new([0xb4; 32])),
            &mut rng,
            &mut store,
            &mut [0; MAX_PUBLIC_OBJECT_BYTES],
            &mut [0; MAX_PUBLIC_OBJECT_BYTES],
        ),
        Err(Error::Readback(StateError::InvalidObject))
    );
    assert_eq!(store.writes, 1);
    assert_eq!(store.reads, 1);
    assert_eq!(store.discard_attempts, 1);
    assert!(
        store.reference.is_some(),
        "failed cleanup leaves an orphan only"
    );
    assert!(pool.staged().is_none());
    assert!(pool.current().is_none());
    assert_eq!(pool.generation_high_water(), GenerationNumber::new(0));

    let checkpoint = coordinator.checkpoint().unwrap();
    let mut rebooted = GenerationCoordinator::from_checkpoint(checkpoint);
    assert_eq!(
        rebooted.status(&pool, request.request, Some(request.next_generation_number)),
        OperationStatus::NotCommitted {
            request: request.request,
            generation_number: request.next_generation_number,
        }
    );

    assert!(matches!(
        rebooted.admit(&pool, request, &mut rng),
        Ok(Admission::Existing(OperationStatus::NotCommitted {
            request: replay_request,
            generation_number,
        })) if replay_request == request.request
            && generation_number == request.next_generation_number
    ));
    assert_eq!(store.writes, 1);
    assert!(pool.staged().is_none());
    assert!(!matches!(
        rebooted.status(&pool, request.request, Some(request.next_generation_number)),
        OperationStatus::Committed(descriptor) if descriptor.generation == generation
    ));
}
