use ed25519_dalek::{Signer, SigningKey};
use kes_core::cbor::{Encoder, Value};
use kes_core::crypto::{Generation, KesKey};
use kes_core::directory;
use kes_core::generation::{Admission, GenerationCoordinator, GenerationRequest, OperationStatus};
use kes_core::journal::{DirectoryCodec, JournalContext, JournalScope, PoolCodec, SnapshotCodec};
use kes_core::management::{self, Action, Error as ManagementError, SigningFields, Target};
use kes_core::recipient::{self, ReplacementOutcome};
use kes_core::state::{
    Actor, Device, DeviceConfig, DeviceCredential, DeviceMode, DirectoryEntry, DirectorySnapshot,
    GenerationSpec, Health, KESGeneration, PoolRegistration, PublicObject, StateError,
};
use kes_core::types::{
    DeviceId, DeviceIdentityBinding, GenerationId, GenerationNumber, IncarnationId, KesLifetime,
    ManagementSequence, PoolId, RequestId, Revision,
};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use sha2::{Digest, Sha256};

const DEVICE: DeviceId = DeviceId::from_bytes([0x11; 16]);
const BACKUP: &[u8] = include_bytes!("../../../fuzz/corpus/frame/backup-public-structure");

fn device(management: &SigningKey) -> Device {
    Device::new(DeviceConfig {
        identity: DeviceIdentityBinding::new(DEVICE, [0x12; 32], [0x13; 32]),
        silicon_revision: 2,
        firmware_digest: [0x14; 32],
        security_version: 1,
        hardware_policy_digest: [0x15; 32],
        mode: DeviceMode::Development,
        health: Health::Healthy,
        management_root_public_key: management.verifying_key().to_bytes(),
        management_transport_public_key: [0x16; 32],
    })
}

struct Envelope {
    bytes: [u8; 2048],
    length: usize,
}

#[derive(Clone, Copy)]
struct EnrollmentInput {
    cold_key: [u8; 32],
    incarnation: IncarnationId,
    sequence: u64,
    request: RequestId,
    expected_revision: Revision,
    machine_key: [u8; 32],
}

fn enrollment_envelope(management: &SigningKey, input: EnrollmentInput) -> Envelope {
    let pool = PoolId::from_cold_verification_key(&input.cold_key);
    let recipient_public =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([0x61; 32])).to_bytes();
    let recipient_id: [u8; 32] = Sha256::digest(recipient_public).into();
    let mut network_storage = [0; 256];
    let network = {
        let mut encoder = Encoder::new(&mut network_storage);
        encoder.map(4).unwrap();
        encoder.text("network_magic").unwrap();
        encoder.uint(42).unwrap();
        encoder.text("max_kes_evolutions").unwrap();
        encoder.uint(64).unwrap();
        encoder.text("slots_per_kes_period").unwrap();
        encoder.uint(129_600).unwrap();
        encoder.text("shelley_genesis_digest").unwrap();
        encoder.bytes(&[0x31; 32]).unwrap();
        encoder.finish().unwrap().encoded().len()
    };
    let mut payload_storage = [0; 1024];
    let payload_length = {
        let mut encoder = Encoder::new(&mut payload_storage);
        encoder.map(10).unwrap();
        encoder.text("pool").unwrap();
        encoder.bytes(pool.as_bytes()).unwrap();
        encoder.text("device").unwrap();
        encoder.bytes(DEVICE.as_bytes()).unwrap();
        encoder.text("network").unwrap();
        encoder
            .value(Value::parse(&network_storage[..network]).unwrap())
            .unwrap();
        encoder.text("version").unwrap();
        encoder.uint(1).unwrap();
        encoder.text("incarnation").unwrap();
        encoder.bytes(input.incarnation.as_bytes()).unwrap();
        encoder.text("recipient_id").unwrap();
        encoder.bytes(&recipient_id).unwrap();
        encoder.text("credential_epoch").unwrap();
        encoder.uint(0).unwrap();
        encoder.text("machine_public_key").unwrap();
        encoder.bytes(&input.machine_key).unwrap();
        encoder.text("recipient_public_key").unwrap();
        encoder.bytes(&recipient_public).unwrap();
        encoder.text("cold_verification_key").unwrap();
        encoder.bytes(&input.cold_key).unwrap();
        encoder.finish().unwrap().encoded().len()
    };
    let payload = Value::parse(&payload_storage[..payload_length]).unwrap();
    let fields = SigningFields {
        device: DEVICE,
        target: Target::Pool {
            pool,
            incarnation: input.incarnation,
        },
        sequence: ManagementSequence::new(input.sequence),
        request: input.request,
        expected_revision: input.expected_revision,
        action: Action::Enroll,
        canonical_payload: payload,
    };
    let mut message = [0; 4608];
    let message_length = management::encode_signing_message(fields, &mut message).unwrap();
    let signature = management.sign(&message[..message_length]).to_bytes();
    let mut result = Envelope {
        bytes: [0; 2048],
        length: 0,
    };
    let mut encoder = Encoder::new(&mut result.bytes);
    encoder.map(9).unwrap();
    encoder.text("pool").unwrap();
    encoder.bytes(pool.as_bytes()).unwrap();
    encoder.text("action").unwrap();
    encoder.text("ENROLL").unwrap();
    encoder.text("device").unwrap();
    encoder.bytes(DEVICE.as_bytes()).unwrap();
    encoder.text("request").unwrap();
    encoder.bytes(input.request.as_bytes()).unwrap();
    encoder.text("signature").unwrap();
    encoder.bytes(&signature).unwrap();
    encoder.text("incarnation").unwrap();
    encoder.bytes(input.incarnation.as_bytes()).unwrap();
    encoder.text("canonical_payload").unwrap();
    encoder.bytes(payload.encoded()).unwrap();
    encoder.text("expected_revision").unwrap();
    encoder.uint(input.expected_revision.get()).unwrap();
    encoder.text("management_sequence").unwrap();
    encoder.uint(input.sequence).unwrap();
    result.length = encoder.finish().unwrap().encoded().len();
    result
}

fn recipient_envelope(
    management: &SigningKey,
    pool: PoolId,
    incarnation: IncarnationId,
    sequence: u64,
    request: RequestId,
    expected_revision: Revision,
    recipient_public: [u8; 32],
) -> Envelope {
    let recipient_id: [u8; 32] = Sha256::digest(recipient_public).into();
    let mut payload_storage = [0; 256];
    let payload_length = {
        let mut encoder = Encoder::new(&mut payload_storage);
        encoder.map(2).unwrap();
        encoder.text("recipient_id").unwrap();
        encoder.bytes(&recipient_id).unwrap();
        encoder.text("recipient_public_key").unwrap();
        encoder.bytes(&recipient_public).unwrap();
        encoder.finish().unwrap().encoded().len()
    };
    let payload = Value::parse(&payload_storage[..payload_length]).unwrap();
    let fields = SigningFields {
        device: DEVICE,
        target: Target::Pool { pool, incarnation },
        sequence: ManagementSequence::new(sequence),
        request,
        expected_revision,
        action: Action::RecipientReplace,
        canonical_payload: payload,
    };
    let mut message = [0; 4608];
    let message_length = management::encode_signing_message(fields, &mut message).unwrap();
    let signature = management.sign(&message[..message_length]).to_bytes();
    let mut result = Envelope {
        bytes: [0; 2048],
        length: 0,
    };
    let mut encoder = Encoder::new(&mut result.bytes);
    encoder.map(9).unwrap();
    encoder.text("pool").unwrap();
    encoder.bytes(pool.as_bytes()).unwrap();
    encoder.text("action").unwrap();
    encoder.text("RECIPIENT_REPLACE").unwrap();
    encoder.text("device").unwrap();
    encoder.bytes(DEVICE.as_bytes()).unwrap();
    encoder.text("request").unwrap();
    encoder.bytes(request.as_bytes()).unwrap();
    encoder.text("signature").unwrap();
    encoder.bytes(&signature).unwrap();
    encoder.text("incarnation").unwrap();
    encoder.bytes(incarnation.as_bytes()).unwrap();
    encoder.text("canonical_payload").unwrap();
    encoder.bytes(payload.encoded()).unwrap();
    encoder.text("expected_revision").unwrap();
    encoder.uint(expected_revision.get()).unwrap();
    encoder.text("management_sequence").unwrap();
    encoder.uint(sequence).unwrap();
    result.length = encoder.finish().unwrap().encoded().len();
    result
}

fn input(index: u8, revision: Revision) -> EnrollmentInput {
    EnrollmentInput {
        cold_key: [index.wrapping_add(1); 32],
        incarnation: IncarnationId::from_bytes([index.wrapping_add(2); 16]),
        sequence: 1,
        request: RequestId::from_bytes([index.wrapping_add(3); 16]),
        expected_revision: revision,
        machine_key: [index.wrapping_add(4); 32],
    }
}

#[test]
fn signed_enrollment_binds_all_keys_and_exact_replay_returns_recorded_outcome() {
    let management = SigningKey::from_bytes(&[0x21; 32]);
    let mut device = device(&management);
    let input = input(1, Revision::new(0));
    let envelope = enrollment_envelope(&management, input);
    let verified = management::parse_and_verify(
        &envelope.bytes[..envelope.length],
        DEVICE,
        &management.verifying_key().to_bytes(),
    )
    .unwrap();
    let outcome = directory::enroll(&mut device, None, &verified).unwrap();
    assert!(outcome.is_applied());
    assert_eq!(outcome.directory_revision, Revision::new(1));
    let slot = outcome.slot;
    let pool = outcome.into_pool().expect("fresh enrollment returns pool");
    assert_eq!(pool.credential_public_key(), &[5; 32]);
    assert_eq!(
        pool.recipient_id(),
        &Sha256::digest(pool.recipient_public_key())[..]
    );
    assert_eq!(pool.management_sequence(), ManagementSequence::new(1));
    assert_eq!(
        pool.management_replay().payload_digest,
        *verified.transcript_digest()
    );
    let pool_context = JournalContext {
        device: DEVICE,
        scope: JournalScope::Pool {
            slot,
            pool: pool.pool_id(),
            incarnation: pool.incarnation(),
        },
    };
    let mut pool_bytes = [0; 3440];
    let pool_length = PoolCodec::encode(&pool, pool_context, &mut pool_bytes).unwrap();
    let pool = PoolCodec::decode(&pool_bytes[..pool_length], pool_context).unwrap();
    let mut live = [None; kes_core::MAX_POOLS];
    live[slot.get()] = Some(DirectoryEntry::new(
        slot,
        pool.pool_id(),
        pool.incarnation(),
    ));
    let snapshot = DirectorySnapshot {
        config: *device.config(),
        revision: device.directory_revision(),
        retirement: None,
        credential: DeviceCredential::new([0x16; 32]),
        pending_deletion: None,
        pending_enrollment: None,
        live,
        tombstones: [None; kes_core::state::DIRECTORY_IDENTITY_CAPACITY],
    };
    let directory_context = JournalContext {
        device: DEVICE,
        scope: JournalScope::Directory,
    };
    let mut directory_bytes = [0; 8192];
    let directory_length =
        DirectoryCodec::encode(&snapshot, directory_context, &mut directory_bytes).unwrap();
    let recovered =
        DirectoryCodec::decode(&directory_bytes[..directory_length], directory_context).unwrap();
    device = Device::from_authenticated_snapshot(&recovered).unwrap();
    let outcome = directory::enroll(&mut device, Some(&pool), &verified).unwrap();
    assert!(!outcome.is_applied());
    assert_eq!(outcome.slot, slot);
    assert_eq!(outcome.pool_revision, Revision::new(0));
    assert_eq!(outcome.directory_revision, Revision::new(1));
    assert_eq!(device.pool_count(), 1);
}

#[test]
fn changed_replay_bad_signature_and_non_management_authority_fail_closed() {
    let management = SigningKey::from_bytes(&[0x31; 32]);
    let machine = SigningKey::from_bytes(&[0x32; 32]);
    let mut device = device(&management);
    let original_input = input(2, Revision::new(0));
    let original = enrollment_envelope(&management, original_input);
    let verified = management::parse_and_verify(
        &original.bytes[..original.length],
        DEVICE,
        &management.verifying_key().to_bytes(),
    )
    .unwrap();
    let pool = directory::enroll(&mut device, None, &verified)
        .unwrap()
        .into_pool()
        .expect("fresh enrollment returns pool");

    let changed = enrollment_envelope(
        &management,
        EnrollmentInput {
            machine_key: [0xaa; 32],
            ..original_input
        },
    );
    let changed = management::parse_and_verify(
        &changed.bytes[..changed.length],
        DEVICE,
        &management.verifying_key().to_bytes(),
    )
    .unwrap();
    assert_eq!(
        directory::enroll(&mut device, Some(&pool), &changed).err(),
        Some(directory::Error::ChangedReplay)
    );

    let unauthorized = enrollment_envelope(&machine, input(3, device.directory_revision()));
    assert_eq!(
        management::parse_and_verify(
            &unauthorized.bytes[..unauthorized.length],
            DEVICE,
            &management.verifying_key().to_bytes(),
        )
        .err(),
        Some(ManagementError::Signature)
    );
    assert_eq!(device.pool_count(), 1);
}

#[test]
fn directory_accepts_at_most_thirty_two_live_registrations_without_eviction() {
    let management = SigningKey::from_bytes(&[0x41; 32]);
    let mut device = device(&management);
    let mut pools: Vec<PoolRegistration> = Vec::with_capacity(32);
    for index in 0..32u8 {
        let envelope = enrollment_envelope(&management, input(index, device.directory_revision()));
        let verified = management::parse_and_verify(
            &envelope.bytes[..envelope.length],
            DEVICE,
            &management.verifying_key().to_bytes(),
        )
        .unwrap();
        let pool = directory::enroll(&mut device, None, &verified)
            .unwrap()
            .into_pool()
            .expect("unique enrollment returns pool");
        pools.push(pool);
    }
    assert_eq!(device.pool_count(), 32);
    assert_eq!(device.retained_identity_count(), 32);

    let overflow = enrollment_envelope(&management, input(40, device.directory_revision()));
    let verified = management::parse_and_verify(
        &overflow.bytes[..overflow.length],
        DEVICE,
        &management.verifying_key().to_bytes(),
    )
    .unwrap();
    assert!(matches!(
        directory::enroll(&mut device, None, &verified),
        Err(directory::Error::State(StateError::Capacity))
    ));
    assert_eq!(device.pool_count(), 32);
    assert_eq!(pools.len(), 32);
}

fn staged_generation(pool: &PoolRegistration, id: GenerationId) -> KESGeneration {
    let lifetime = KesLifetime::new(64).unwrap();
    let mut seed = [0xb1; 32];
    let mut generation = Generation::begin(&mut seed, lifetime).unwrap();
    for _ in 0..64 {
        generation.step().unwrap();
    }
    let (key, tree) = generation.finish().unwrap();
    let verified = tree.verify(&key.verification_key().unwrap()).unwrap();
    let verification_key = key.verification_key().unwrap();
    let object =
        PublicObject::from_parts(id, verified.as_bytes(), BACKUP, &verification_key).unwrap();
    KESGeneration::new_staged(
        GenerationSpec {
            generation_id: id,
            generation_number: GenerationNumber::new(1),
            creation_request: RequestId::from_bytes([0xb2; 16]),
            creation_payload_digest: [0xb3; 32],
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

#[test]
fn recipient_replacement_cancels_unpublished_work_and_preserves_replay_identity() {
    let management = SigningKey::from_bytes(&[0x51; 32]);
    let mut device = device(&management);
    let enrollment = enrollment_envelope(&management, input(9, Revision::new(0)));
    let verified = management::parse_and_verify(
        &enrollment.bytes[..enrollment.length],
        DEVICE,
        &management.verifying_key().to_bytes(),
    )
    .unwrap();
    let mut pool = directory::enroll(&mut device, None, &verified)
        .unwrap()
        .into_pool()
        .expect("fresh enrollment returns pool");
    let old_recipient = *pool.recipient_id();
    let generation_request = RequestId::from_bytes([0xa1; 16]);
    let mut coordinator = GenerationCoordinator::new();
    let mut rng = ChaCha20Rng::from_seed([0xa2; 32]);
    let admitted = coordinator
        .admit(
            &pool,
            GenerationRequest {
                actor: kes_core::state::Actor::Pool {
                    pool: pool.pool_id(),
                    incarnation: pool.incarnation(),
                },
                request: generation_request,
                payload_digest: [0xa3; 32],
                next_generation_number: GenerationNumber::new(1),
                expected_revision: Revision::new(0),
            },
            &mut rng,
        )
        .unwrap();
    let operation = match admitted {
        Admission::Started(operation) => operation,
        Admission::Existing(_) => panic!("fresh generation replayed"),
    };
    let mut workspace = KesKey::erased(KesLifetime::new(64).unwrap());
    let replacement_public =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([0xa4; 32])).to_bytes();
    let replacement = recipient_envelope(
        &management,
        pool.pool_id(),
        pool.incarnation(),
        2,
        RequestId::from_bytes([0xa5; 16]),
        Revision::new(0),
        replacement_public,
    );
    let replacement = management::parse_and_verify(
        &replacement.bytes[..replacement.length],
        DEVICE,
        &management.verifying_key().to_bytes(),
    )
    .unwrap();
    assert_eq!(
        recipient::replace(&mut pool, &mut coordinator, None, &replacement),
        Err(recipient::Error::MissingGenerationWorkspace)
    );
    assert_eq!(pool.recipient_id(), &old_recipient);
    assert_eq!(pool.revision(), Revision::new(0));
    assert!(matches!(
        coordinator.status(&pool, generation_request, Some(GenerationNumber::new(1))),
        OperationStatus::InProgress { .. }
    ));
    let outcome = recipient::replace(
        &mut pool,
        &mut coordinator,
        Some(&mut workspace),
        &replacement,
    )
    .unwrap();
    match outcome {
        ReplacementOutcome::Applied {
            revision,
            cancelled_generation,
            archive,
        } => {
            assert_eq!(revision, Revision::new(1));
            assert_eq!(cancelled_generation, Some(operation.generation()));
            assert_eq!(archive.previous_recipient_id, old_recipient);
            assert!(archive.required());
        }
        ReplacementOutcome::AlreadyCommitted { .. } => panic!("fresh replacement replayed"),
    }
    assert_eq!(pool.recipient_public_key(), &replacement_public);
    assert_eq!(pool.recipient_policy_epoch(), 1);
    assert_eq!(
        coordinator.status(&pool, generation_request, Some(GenerationNumber::new(1))),
        OperationStatus::NotCommitted {
            request: generation_request,
            generation_number: GenerationNumber::new(1),
        }
    );
    assert_eq!(
        recipient::replace(&mut pool, &mut coordinator, None, &replacement).unwrap(),
        ReplacementOutcome::AlreadyCommitted {
            revision: Revision::new(1)
        }
    );
}

#[test]
fn recipient_replacement_is_future_only_and_requires_old_artifact_archival() {
    let management = SigningKey::from_bytes(&[0xc1; 32]);
    let mut device = device(&management);
    let enrollment = enrollment_envelope(&management, input(10, Revision::new(0)));
    let verified = management::parse_and_verify(
        &enrollment.bytes[..enrollment.length],
        DEVICE,
        &management.verifying_key().to_bytes(),
    )
    .unwrap();
    let mut pool = directory::enroll(&mut device, None, &verified)
        .unwrap()
        .into_pool()
        .expect("fresh enrollment returns pool");
    let old_policy = pool.generation_policy();
    let generation = GenerationId::from_bytes([0xc2; 16]);
    let staged = staged_generation(&pool, generation);
    let old_digest = *staged.backup_digest();
    let old_recipient = *staged.recipient_id();
    pool.stage(
        Actor::Pool {
            pool: pool.pool_id(),
            incarnation: pool.incarnation(),
        },
        Revision::new(0),
        staged,
        old_policy,
    )
    .unwrap();

    let replacement_public =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([0xc3; 32])).to_bytes();
    let replacement = recipient_envelope(
        &management,
        pool.pool_id(),
        pool.incarnation(),
        2,
        RequestId::from_bytes([0xc4; 16]),
        Revision::new(1),
        replacement_public,
    );
    let replacement = management::parse_and_verify(
        &replacement.bytes[..replacement.length],
        DEVICE,
        &management.verifying_key().to_bytes(),
    )
    .unwrap();
    let outcome = recipient::replace(
        &mut pool,
        &mut GenerationCoordinator::new(),
        None,
        &replacement,
    )
    .unwrap();
    let ReplacementOutcome::Applied { archive, .. } = outcome else {
        panic!("fresh replacement replayed");
    };
    assert!(archive.required());
    assert_eq!(archive.previous_recipient_id, old_recipient);
    assert_eq!(archive.retained_generations, [None, Some(generation)]);
    let retained = pool.staged().unwrap();
    assert_eq!(retained.id(), generation);
    assert_eq!(retained.recipient_id(), &old_recipient);
    assert_eq!(retained.backup_digest(), &old_digest);
    assert_eq!(pool.recipient_public_key(), &replacement_public);
    assert_ne!(pool.recipient_id(), &old_recipient);
}
