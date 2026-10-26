use ed25519_dalek::{Signer, SigningKey};
use kes_core::cbor::{Encoder, Value};
use kes_core::credentials::{self, CredentialOutcome, DiscardOutcome};
use kes_core::crypto::{Generation, KesKey, PublicTreeBuffer};
use kes_core::deletion::{self, DeletionOutcome};
use kes_core::generation::{Admission, GenerationCoordinator, GenerationRequest, OperationStatus};
use kes_core::journal::{DirectoryCodec, JournalContext, JournalScope, PoolCodec, SnapshotCodec};
use kes_core::management::{self, Action, SigningFields, Target};
use kes_core::retirement;
use kes_core::state::{
    Actor, Device, DeviceConfig, DeviceCredential, DeviceMode, DeviceRetirement, DirectoryEntry,
    DirectorySnapshot, Enrollment, GenerationSpec, Health, KESGeneration, ManagementReplay,
    ManagementResult, PoolRegistration, PublicObject, StateError, UsePolicy,
};
use kes_core::types::{
    CredentialEpoch, DeviceId, DeviceIdentityBinding, GenerationId, GenerationNumber, HardwareSlot,
    IncarnationId, KesLifetime, ManagementSequence, NetworkBinding, PoolId, RequestId, Revision,
};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use sha2::{Digest, Sha256};

const DEVICE: DeviceId = DeviceId::from_bytes([0x31; 16]);
const BACKUP: &[u8] = include_bytes!("../../../fuzz/corpus/frame/backup-public-structure");

fn config(management: &SigningKey) -> DeviceConfig {
    DeviceConfig {
        identity: DeviceIdentityBinding::new(DEVICE, [0x32; 32], [0x33; 32]),
        silicon_revision: 2,
        firmware_digest: [0x34; 32],
        security_version: 1,
        hardware_policy_digest: [0x35; 32],
        mode: DeviceMode::Development,
        health: Health::Healthy,
        management_root_public_key: management.verifying_key().to_bytes(),
        management_transport_public_key: [0x36; 32],
    }
}

fn network() -> NetworkBinding {
    NetworkBinding::from_genesis_bytes(42, b"management lifecycle genesis", 64, 64).unwrap()
}

fn pool(index: u8, incarnation: IncarnationId) -> PoolRegistration {
    let cold = [index; 32];
    let recipient_public_key = [index.wrapping_add(1); 32];
    PoolRegistration::new(
        Actor::Management,
        Enrollment {
            incarnation,
            cold_verification_key: cold,
            network: network(),
            machine_public_key: [index.wrapping_add(2); 32],
            recipient_public_key,
            recipient_id: Sha256::digest(recipient_public_key).into(),
            management_sequence: ManagementSequence::new(1),
            management_request: RequestId::from_bytes([index.wrapping_add(3); 16]),
            management_payload_digest: [index.wrapping_add(4); 32],
        },
    )
    .unwrap()
}

fn stage(pool: &mut PoolRegistration, byte: u8) -> GenerationId {
    let lifetime = KesLifetime::new(64).unwrap();
    let mut seed = [byte; 32];
    let mut key = KesKey::erased(lifetime);
    let mut tree = PublicTreeBuffer::new();
    let mut operation = Generation::begin(&mut seed, &mut key, &mut tree).unwrap();
    for _ in 0..64 {
        operation.step().unwrap();
    }
    let verified = operation.finish().unwrap();
    let verification_key = key.verification_key().unwrap();
    let generation = GenerationId::from_bytes([byte; 16]);
    let object =
        PublicObject::from_parts(generation, verified.as_bytes(), BACKUP, &verification_key)
            .unwrap();
    let staged = KESGeneration::new_staged(
        GenerationSpec {
            generation_id: generation,
            generation_number: GenerationNumber::new(pool.generation_high_water().get() + 1),
            creation_request: RequestId::from_bytes([byte.wrapping_add(1); 16]),
            creation_payload_digest: [byte.wrapping_add(2); 32],
            pool: pool.pool_id(),
            incarnation: pool.incarnation(),
            verification_key,
            lifetime,
            recipient_id: *pool.recipient_id(),
            public_object: object,
        },
        key,
    )
    .unwrap();
    let actor = Actor::Pool {
        pool: pool.pool_id(),
        incarnation: pool.incarnation(),
    };
    let revision = pool.revision();
    let policy = pool.generation_policy();
    pool.stage(actor, revision, staged, policy).unwrap();
    generation
}

fn encode_payload(fields: impl FnOnce(&mut Encoder<'_>)) -> Vec<u8> {
    let mut bytes = [0; 1024];
    let mut encoder = Encoder::new(&mut bytes);
    fields(&mut encoder);
    let length = encoder.finish().unwrap().encoded().len();
    bytes[..length].to_vec()
}

fn signed_envelope(
    management: &SigningKey,
    target: Target,
    sequence: u64,
    request: u8,
    expected_revision: Revision,
    action: Action,
    payload: &[u8],
) -> Vec<u8> {
    let payload = Value::parse(payload).unwrap();
    let fields = SigningFields {
        device: DEVICE,
        target,
        sequence: ManagementSequence::new(sequence),
        request: RequestId::from_bytes([request; 16]),
        expected_revision,
        action,
        canonical_payload: payload,
    };
    let mut message = [0; 4608];
    let message_length = management::encode_signing_message(fields, &mut message).unwrap();
    let signature = management.sign(&message[..message_length]).to_bytes();
    let mut output = [0; 6144];
    let mut encoder = Encoder::new(&mut output);
    encoder.map(9).unwrap();
    encoder.text("pool").unwrap();
    match target {
        Target::Device => encoder.null().unwrap(),
        Target::Pool { pool, .. } => encoder.bytes(pool.as_bytes()).unwrap(),
    }
    encoder.text("action").unwrap();
    encoder.text(action.name()).unwrap();
    encoder.text("device").unwrap();
    encoder.bytes(DEVICE.as_bytes()).unwrap();
    encoder.text("request").unwrap();
    encoder.bytes(&[request; 16]).unwrap();
    encoder.text("signature").unwrap();
    encoder.bytes(&signature).unwrap();
    encoder.text("incarnation").unwrap();
    match target {
        Target::Device => encoder.null().unwrap(),
        Target::Pool { incarnation, .. } => encoder.bytes(incarnation.as_bytes()).unwrap(),
    }
    encoder.text("canonical_payload").unwrap();
    encoder.bytes(payload.encoded()).unwrap();
    encoder.text("expected_revision").unwrap();
    encoder.uint(expected_revision.get()).unwrap();
    encoder.text("management_sequence").unwrap();
    encoder.uint(sequence).unwrap();
    let length = encoder.finish().unwrap().encoded().len();
    output[..length].to_vec()
}

fn verify<'a>(bytes: &'a [u8], management: &SigningKey) -> management::VerifiedEnvelope<'a> {
    management::parse_and_verify(bytes, DEVICE, &management.verifying_key().to_bytes()).unwrap()
}

fn enrollment_payload(
    cold: [u8; 32],
    incarnation: IncarnationId,
    machine_key: [u8; 32],
) -> Vec<u8> {
    let pool = PoolId::from_cold_verification_key(&cold);
    let recipient_public_key = [0x71; 32];
    let recipient_id: [u8; 32] = Sha256::digest(recipient_public_key).into();
    encode_payload(|encoder| {
        encoder.map(10).unwrap();
        encoder.text("pool").unwrap();
        encoder.bytes(pool.as_bytes()).unwrap();
        encoder.text("device").unwrap();
        encoder.bytes(DEVICE.as_bytes()).unwrap();
        encoder.text("network").unwrap();
        encoder.map(4).unwrap();
        encoder.text("network_magic").unwrap();
        encoder.uint(42).unwrap();
        encoder.text("max_kes_evolutions").unwrap();
        encoder.uint(64).unwrap();
        encoder.text("slots_per_kes_period").unwrap();
        encoder.uint(64).unwrap();
        encoder.text("shelley_genesis_digest").unwrap();
        encoder.bytes(network().genesis_hash().as_bytes()).unwrap();
        encoder.text("version").unwrap();
        encoder.uint(1).unwrap();
        encoder.text("incarnation").unwrap();
        encoder.bytes(incarnation.as_bytes()).unwrap();
        encoder.text("recipient_id").unwrap();
        encoder.bytes(&recipient_id).unwrap();
        encoder.text("credential_epoch").unwrap();
        encoder.uint(0).unwrap();
        encoder.text("machine_public_key").unwrap();
        encoder.bytes(&machine_key).unwrap();
        encoder.text("recipient_public_key").unwrap();
        encoder.bytes(&recipient_public_key).unwrap();
        encoder.text("cold_verification_key").unwrap();
        encoder.bytes(&cold).unwrap();
    })
}

fn directory_snapshot(
    management: &SigningKey,
    pools: &[&PoolRegistration],
    revision: u64,
) -> DirectorySnapshot {
    let mut live = [None; kes_core::MAX_POOLS];
    for (slot, pool) in pools.iter().enumerate() {
        live[slot] = Some(DirectoryEntry::new(
            HardwareSlot::new(slot).unwrap(),
            pool.pool_id(),
            pool.incarnation(),
        ));
    }
    DirectorySnapshot {
        config: config(management),
        revision: Revision::new(revision),
        retirement: None,
        credential: DeviceCredential::new([0x36; 32]),
        pending_deletion: None,
        live,
        tombstones: [None; kes_core::state::DIRECTORY_IDENTITY_CAPACITY],
    }
}

fn pool_context(pool: &PoolRegistration, slot: usize) -> JournalContext {
    JournalContext {
        device: DEVICE,
        scope: JournalScope::Pool {
            slot: HardwareSlot::new(slot).unwrap(),
            pool: pool.pool_id(),
            incarnation: pool.incarnation(),
        },
    }
}

#[test]
fn credential_replace_revoke_and_staged_discard_are_replay_safe_across_restart() {
    let management = SigningKey::from_bytes(&[0x41; 32]);
    let incarnation = IncarnationId::from_bytes([0x42; 16]);
    let mut registration = pool(0x43, incarnation);
    let generation = stage(&mut registration, 0x44);
    let unaffected = pool(0x45, IncarnationId::from_bytes([0x46; 16]));
    let unaffected_key = *unaffected.credential_public_key();

    let replacement_key = [0x47; 32];
    let replacement_payload = encode_payload(|encoder| {
        encoder.map(2).unwrap();
        encoder.text("credential_epoch").unwrap();
        encoder.uint(1).unwrap();
        encoder.text("machine_public_key").unwrap();
        encoder.bytes(&replacement_key).unwrap();
    });
    let target = Target::Pool {
        pool: registration.pool_id(),
        incarnation,
    };
    let replacement_bytes = signed_envelope(
        &management,
        target,
        2,
        0x48,
        registration.revision(),
        Action::CredentialReplace,
        &replacement_payload,
    );
    let replacement = verify(&replacement_bytes, &management);
    assert_eq!(
        credentials::change_pool_credential(
            &mut registration,
            &mut GenerationCoordinator::new(),
            None,
            &replacement,
        )
        .unwrap(),
        CredentialOutcome::Applied {
            revision: Revision::new(2),
            cancelled_generation: None,
        }
    );
    assert_eq!(registration.credential_public_key(), &replacement_key);
    assert_eq!(registration.credential_epoch(), CredentialEpoch::new(1));
    assert!(!registration.credential_revoked());
    assert_eq!(registration.staged().unwrap().id(), generation);
    assert_eq!(unaffected.credential_public_key(), &unaffected_key);

    let mut encoded = [0; 3440];
    let length =
        PoolCodec::encode(&registration, pool_context(&registration, 0), &mut encoded).unwrap();
    registration = PoolCodec::decode(&encoded[..length], pool_context(&registration, 0)).unwrap();
    assert_eq!(
        credentials::change_pool_credential(
            &mut registration,
            &mut GenerationCoordinator::new(),
            None,
            &replacement,
        )
        .unwrap(),
        CredentialOutcome::AlreadyCommitted {
            revision: Revision::new(2),
        }
    );

    let revoke_payload = encode_payload(|encoder| {
        encoder.map(1).unwrap();
        encoder.text("credential_epoch").unwrap();
        encoder.uint(2).unwrap();
    });
    let revoke_bytes = signed_envelope(
        &management,
        target,
        3,
        0x49,
        registration.revision(),
        Action::CredentialRevoke,
        &revoke_payload,
    );
    let revoke = verify(&revoke_bytes, &management);
    credentials::change_pool_credential(
        &mut registration,
        &mut GenerationCoordinator::new(),
        None,
        &revoke,
    )
    .unwrap();
    assert_eq!(registration.credential_epoch(), CredentialEpoch::new(2));
    assert!(registration.credential_revoked());

    let mut discard_pool = pool(0x51, IncarnationId::from_bytes([0x52; 16]));
    let discarded_generation = stage(&mut discard_pool, 0x53);
    let discard_payload = encode_payload(|encoder| {
        encoder.map(1).unwrap();
        encoder.text("generation").unwrap();
        encoder.bytes(discarded_generation.as_bytes()).unwrap();
    });
    let discard_bytes = signed_envelope(
        &management,
        Target::Pool {
            pool: discard_pool.pool_id(),
            incarnation: discard_pool.incarnation(),
        },
        2,
        0x54,
        discard_pool.revision(),
        Action::StagedDiscard,
        &discard_payload,
    );
    let discard = verify(&discard_bytes, &management);
    assert_eq!(
        credentials::discard_staged(&mut discard_pool, &discard).unwrap(),
        DiscardOutcome::Applied {
            revision: Revision::new(2),
            generation: discarded_generation,
        }
    );
    assert!(discard_pool.staged().is_none());
    assert_eq!(
        credentials::discard_staged(&mut discard_pool, &discard).unwrap(),
        DiscardOutcome::AlreadyCommitted {
            revision: Revision::new(2),
        }
    );

    let mut changing_pool = pool(0x59, IncarnationId::from_bytes([0x5a; 16]));
    let mut coordinator = GenerationCoordinator::new();
    let generation_request = RequestId::from_bytes([0x5b; 16]);
    let mut rng = ChaCha20Rng::from_seed([0x5c; 32]);
    let operation = match coordinator
        .admit(
            &changing_pool,
            GenerationRequest {
                actor: Actor::Pool {
                    pool: changing_pool.pool_id(),
                    incarnation: changing_pool.incarnation(),
                },
                request: generation_request,
                payload_digest: [0x5d; 32],
                next_generation_number: GenerationNumber::new(1),
                expected_revision: Revision::new(0),
            },
            &mut rng,
        )
        .unwrap()
    {
        Admission::Started(operation) => operation,
        Admission::Existing(_) => panic!("fresh generation replayed"),
    };
    let cancellation_payload = encode_payload(|encoder| {
        encoder.map(2).unwrap();
        encoder.text("credential_epoch").unwrap();
        encoder.uint(1).unwrap();
        encoder.text("machine_public_key").unwrap();
        encoder.bytes(&[0x5e; 32]).unwrap();
    });
    let cancellation_bytes = signed_envelope(
        &management,
        Target::Pool {
            pool: changing_pool.pool_id(),
            incarnation: changing_pool.incarnation(),
        },
        2,
        0x5f,
        Revision::new(0),
        Action::CredentialReplace,
        &cancellation_payload,
    );
    let mut generation_workspace = KesKey::erased(KesLifetime::new(64).unwrap());
    assert_eq!(
        credentials::change_pool_credential(
            &mut changing_pool,
            &mut coordinator,
            Some(&mut generation_workspace),
            &verify(&cancellation_bytes, &management),
        )
        .unwrap(),
        CredentialOutcome::Applied {
            revision: Revision::new(1),
            cancelled_generation: Some(operation.generation()),
        }
    );
    assert_eq!(
        coordinator.status(
            &changing_pool,
            generation_request,
            Some(GenerationNumber::new(1)),
        ),
        OperationStatus::NotCommitted {
            request: generation_request,
            generation_number: GenerationNumber::new(1),
        }
    );
}

#[test]
fn management_transport_credential_epoch_and_revocation_survive_restart() {
    let management = SigningKey::from_bytes(&[0x55; 32]);
    let mut directory = directory_snapshot(&management, &[], 0);
    let replacement_key = [0x56; 32];
    let replacement_payload = encode_payload(|encoder| {
        encoder.map(2).unwrap();
        encoder.text("credential_epoch").unwrap();
        encoder.uint(1).unwrap();
        encoder.text("machine_public_key").unwrap();
        encoder.bytes(&replacement_key).unwrap();
    });
    let replacement_bytes = signed_envelope(
        &management,
        Target::Device,
        1,
        0x57,
        Revision::new(0),
        Action::CredentialReplace,
        &replacement_payload,
    );
    let replacement = verify(&replacement_bytes, &management);
    assert_eq!(
        credentials::change_device_credential(&mut directory, &replacement).unwrap(),
        CredentialOutcome::Applied {
            revision: Revision::new(1),
            cancelled_generation: None,
        }
    );
    assert_eq!(directory.credential.public_key, replacement_key);
    assert_eq!(directory.credential.epoch, CredentialEpoch::new(1));

    let context = JournalContext {
        device: DEVICE,
        scope: JournalScope::Directory,
    };
    let mut encoded = [0; 8192];
    let length = DirectoryCodec::encode(&directory, context, &mut encoded).unwrap();
    directory = DirectoryCodec::decode(&encoded[..length], context).unwrap();
    assert_eq!(
        credentials::change_device_credential(&mut directory, &replacement).unwrap(),
        CredentialOutcome::AlreadyCommitted {
            revision: Revision::new(1),
        }
    );

    let revoke_payload = encode_payload(|encoder| {
        encoder.map(1).unwrap();
        encoder.text("credential_epoch").unwrap();
        encoder.uint(2).unwrap();
    });
    let revoke_bytes = signed_envelope(
        &management,
        Target::Device,
        2,
        0x58,
        Revision::new(1),
        Action::CredentialRevoke,
        &revoke_payload,
    );
    credentials::change_device_credential(&mut directory, &verify(&revoke_bytes, &management))
        .unwrap();
    assert_eq!(directory.credential.epoch, CredentialEpoch::new(2));
    assert!(directory.credential.revoked);
}

#[test]
fn erased_slot_recovery_finishes_pending_deletion_before_reuse() {
    let management = SigningKey::from_bytes(&[0x5a; 32]);
    let incarnation = IncarnationId::from_bytes([0x5b; 16]);
    let registration = pool(0x5c, incarnation);
    let pool_id = registration.pool_id();
    let mut directory = directory_snapshot(&management, &[&registration], 1);
    let payload = encode_payload(|encoder| encoder.map(0).unwrap());
    let encoded = signed_envelope(
        &management,
        Target::Pool {
            pool: pool_id,
            incarnation,
        },
        2,
        0x5d,
        registration.revision(),
        Action::PoolDelete,
        &payload,
    );
    deletion::prepare_delete(
        &mut directory,
        &registration,
        &verify(&encoded, &management),
    )
    .unwrap();

    let context = JournalContext {
        device: DEVICE,
        scope: JournalScope::Directory,
    };
    let mut bytes = [0; 8192];
    let length = DirectoryCodec::encode(&directory, context, &mut bytes).unwrap();
    directory = DirectoryCodec::decode(&bytes[..length], context).unwrap();
    <DirectoryCodec as SnapshotCodec>::set_recovery_revision(&mut directory, Revision::new(3));
    let length = DirectoryCodec::encode(&directory, context, &mut bytes).unwrap();
    directory = DirectoryCodec::decode(&bytes[..length], context).unwrap();
    assert_eq!(
        deletion::finish_delete_after_erasure(&mut directory, HardwareSlot::new(1).unwrap()).err(),
        Some(deletion::Error::InconsistentPoolState)
    );
    let DeletionOutcome::Applied {
        revision,
        tombstone,
    } = deletion::finish_delete_after_erasure(&mut directory, HardwareSlot::new(0).unwrap())
        .unwrap()
    else {
        panic!("erased slot recovery replayed");
    };
    assert_eq!(revision, Revision::new(4));
    assert_eq!(tombstone.pool_id, pool_id);
    assert!(directory.pending_deletion.is_none());
    assert!(directory.live.iter().all(Option::is_none));
}

#[test]
fn deletion_retains_history_and_only_fresh_incarnation_can_reenroll() {
    let management = SigningKey::from_bytes(&[0x61; 32]);
    let old_incarnation = IncarnationId::from_bytes([0x62; 16]);
    let mut registration = pool(0x63, old_incarnation);
    stage(&mut registration, 0x64);
    let pool_id = registration.pool_id();
    let high_water = registration.generation_high_water();
    let mut directory = directory_snapshot(&management, &[&registration], 1);
    let delete_payload = encode_payload(|encoder| encoder.map(0).unwrap());
    let delete_bytes = signed_envelope(
        &management,
        Target::Pool {
            pool: pool_id,
            incarnation: old_incarnation,
        },
        2,
        0x65,
        registration.revision(),
        Action::PoolDelete,
        &delete_payload,
    );
    let delete = verify(&delete_bytes, &management);
    let deletion::PreparationOutcome::Prepared {
        revision: prepare_revision,
        intent,
    } = deletion::prepare_delete(&mut directory, &registration, &delete).unwrap()
    else {
        panic!("fresh deletion was not prepared");
    };
    assert_eq!(prepare_revision, Revision::new(2));
    assert_eq!(intent.tombstone.generation_high_water, high_water);
    assert!(registration.staged().is_some());

    let context = JournalContext {
        device: DEVICE,
        scope: JournalScope::Directory,
    };
    let mut encoded = [0; 8192];
    let length = DirectoryCodec::encode(&directory, context, &mut encoded).unwrap();
    directory = DirectoryCodec::decode(&encoded[..length], context).unwrap();
    assert_eq!(
        deletion::prepare_delete(&mut directory, &registration, &delete).unwrap(),
        deletion::PreparationOutcome::AlreadyPrepared {
            revision: Revision::new(2),
            intent,
        }
    );
    assert!(deletion::cleanup_pending_pool(&directory, &mut registration).unwrap());
    assert!(registration.staged().is_none());

    let pool_context = pool_context(&registration, 0);
    let mut pool_bytes = [0; 3440];
    let pool_length = PoolCodec::encode(&registration, pool_context, &mut pool_bytes).unwrap();
    registration = PoolCodec::decode(&pool_bytes[..pool_length], pool_context).unwrap();
    let DeletionOutcome::Applied {
        revision,
        tombstone,
    } = deletion::finish_delete(&mut directory, &registration).unwrap()
    else {
        panic!("prepared deletion was not finalized");
    };
    assert_eq!(revision, Revision::new(3));
    assert_eq!(tombstone.generation_high_water, high_water);
    assert!(directory.pending_deletion.is_none());
    assert!(directory.live.iter().all(Option::is_none));

    let length = DirectoryCodec::encode(&directory, context, &mut encoded).unwrap();
    directory = DirectoryCodec::decode(&encoded[..length], context).unwrap();
    assert_eq!(
        deletion::delete(&mut directory, None, &delete).unwrap(),
        DeletionOutcome::AlreadyCommitted {
            revision: Revision::new(3),
        }
    );

    let stale_payload = enrollment_payload([0x63; 32], old_incarnation, [0x66; 32]);
    let stale_bytes = signed_envelope(
        &management,
        Target::Pool {
            pool: pool_id,
            incarnation: old_incarnation,
        },
        3,
        0x67,
        directory.revision,
        Action::Enroll,
        &stale_payload,
    );
    assert_eq!(
        deletion::reenroll(&mut directory, None, &verify(&stale_bytes, &management)).err(),
        Some(deletion::Error::SameIncarnation)
    );

    let new_incarnation = IncarnationId::from_bytes([0x68; 16]);
    let fresh_payload = enrollment_payload([0x63; 32], new_incarnation, [0x69; 32]);
    let fresh_bytes = signed_envelope(
        &management,
        Target::Pool {
            pool: pool_id,
            incarnation: new_incarnation,
        },
        3,
        0x6a,
        directory.revision,
        Action::Enroll,
        &fresh_payload,
    );
    let fresh = verify(&fresh_bytes, &management);
    let outcome = deletion::reenroll(&mut directory, None, &fresh).unwrap();
    assert!(outcome.is_applied());
    assert_eq!(outcome.directory_revision, Revision::new(4));
    let replacement = outcome
        .into_pool()
        .expect("fresh re-enrollment returns pool");
    assert_eq!(replacement.generation_high_water(), high_water);
    assert_eq!(replacement.incarnation(), new_incarnation);
    assert_eq!(
        replacement.management_sequence(),
        ManagementSequence::new(3)
    );
    let replay = deletion::reenroll(&mut directory, Some(&replacement), &fresh).unwrap();
    assert!(!replay.is_applied());
    assert_eq!(replay.directory_revision, Revision::new(4));
    assert_eq!(replay.pool_revision, Revision::new(0));
}

#[test]
fn retirement_denies_restart_and_erases_all_live_pool_secrets() {
    let management = SigningKey::from_bytes(&[0x71; 32]);
    let mut first = pool(0x72, IncarnationId::from_bytes([0x73; 16]));
    let mut second = pool(0x74, IncarnationId::from_bytes([0x75; 16]));
    stage(&mut first, 0x76);
    stage(&mut second, 0x77);
    let mut directory = directory_snapshot(&management, &[&first, &second], 2);
    let payload = encode_payload(|encoder| encoder.map(0).unwrap());
    let bytes = signed_envelope(
        &management,
        Target::Device,
        1,
        0x78,
        directory.revision,
        Action::DeviceRetire,
        &payload,
    );
    let envelope = verify(&bytes, &management);
    let mut pools = [first, second];
    let outcome = retirement::retire(&mut directory, &mut pools, &envelope).unwrap();
    assert_eq!(
        outcome,
        retirement::Outcome::Applied {
            revision: Revision::new(3),
            retired_pools: 2,
            external_backups_unchanged: true,
        }
    );
    assert!(
        pools
            .iter()
            .all(|pool| pool.staged().unwrap().is_secret_erased())
    );
    assert!(directory.live.iter().all(Option::is_none));
    assert_eq!(directory.tombstones.iter().flatten().count(), 2);

    let context = JournalContext {
        device: DEVICE,
        scope: JournalScope::Directory,
    };
    let mut encoded = [0; 8192];
    let length = DirectoryCodec::encode(&directory, context, &mut encoded).unwrap();
    let recovered = DirectoryCodec::decode(&encoded[..length], context).unwrap();
    let device = Device::from_authenticated_snapshot(&recovered).unwrap();
    assert_eq!(
        device
            .ensure_operational(UsePolicy::IsolatedDevelopment, None)
            .err(),
        Some(StateError::Retired)
    );
    assert_eq!(
        retirement::retire(&mut directory, &mut [], &envelope).unwrap(),
        retirement::Outcome::AlreadyCommitted {
            revision: Revision::new(3),
            external_backups_unchanged: true,
        }
    );

    let mut interrupted_pool = pool(0x79, IncarnationId::from_bytes([0x7a; 16]));
    stage(&mut interrupted_pool, 0x7b);
    let mut interrupted = directory_snapshot(&management, &[&interrupted_pool], 1);
    let interrupted_bytes = signed_envelope(
        &management,
        Target::Device,
        1,
        0x7c,
        interrupted.revision,
        Action::DeviceRetire,
        &payload,
    );
    let interrupted_envelope = verify(&interrupted_bytes, &management);
    let interrupted_revision = Revision::new(2);
    interrupted.revision = interrupted_revision;
    interrupted.retirement = Some(DeviceRetirement {
        revision: interrupted_revision,
        management_replay: ManagementReplay {
            sequence: ManagementSequence::new(1),
            request: RequestId::from_bytes([0x7c; 16]),
            payload_digest: *interrupted_envelope.transcript_digest(),
            result: ManagementResult::Committed {
                revision: interrupted_revision,
            },
        },
    });
    let interrupted_length = DirectoryCodec::encode(&interrupted, context, &mut encoded).unwrap();
    interrupted = DirectoryCodec::decode(&encoded[..interrupted_length], context).unwrap();
    assert_eq!(
        Device::from_authenticated_snapshot(&interrupted)
            .unwrap()
            .ensure_operational(UsePolicy::IsolatedDevelopment, None)
            .err(),
        Some(StateError::Retired)
    );
    let interrupted_pool_context = pool_context(&interrupted_pool, 0);
    let mut interrupted_pool_bytes = [0; 3440];
    let interrupted_pool_length = PoolCodec::encode(
        &interrupted_pool,
        interrupted_pool_context,
        &mut interrupted_pool_bytes,
    )
    .unwrap();
    interrupted_pool = PoolCodec::decode(
        &interrupted_pool_bytes[..interrupted_pool_length],
        interrupted_pool_context,
    )
    .unwrap();
    let mut remaining = [interrupted_pool];
    assert_eq!(
        retirement::retire(&mut interrupted, &mut remaining, &interrupted_envelope).unwrap(),
        retirement::Outcome::Applied {
            revision: interrupted_revision,
            retired_pools: 1,
            external_backups_unchanged: true,
        }
    );
    assert!(remaining[0].staged().unwrap().is_secret_erased());
    assert!(interrupted.live.iter().all(Option::is_none));
}
