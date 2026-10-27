use ed25519_dalek::{Signer, SigningKey};
use kes_core::cbor::{Encoder, Value};
use kes_core::credentials::{self, CredentialOutcome, DiscardOutcome};
use kes_core::crypto::{Generation, KesKey};
use kes_core::deletion::{self, DeletionOutcome};
use kes_core::generation::{Admission, GenerationCoordinator, GenerationRequest, OperationStatus};
use kes_core::journal::{DirectoryCodec, JournalContext, JournalScope, PoolCodec, SnapshotCodec};
use kes_core::management::{self, Action, SigningFields, Target};
#[cfg(feature = "protected-runtime")]
use kes_core::retirement;
use kes_core::session::{DeviceHpkeKey, OpenContext, Scope, SessionError, accept_open, begin_open};
use kes_core::state::{
    Actor, DeviceConfig, DeviceCredential, DeviceMode, DirectoryEntry, DirectorySnapshot,
    Enrollment, GenerationSpec, Health, KESGeneration, PoolRegistration, PublicObject,
};
#[cfg(feature = "protected-runtime")]
use kes_core::state::{Device, StateError, UsePolicy};
use kes_core::types::{
    CredentialEpoch, DeviceId, DeviceIdentityBinding, GenerationId, GenerationNumber, HardwareSlot,
    IncarnationId, KesLifetime, ManagementSequence, NetworkBinding, PoolId, RequestId, Revision,
};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[allow(dead_code)]
#[path = "journal_faults/flash.rs"]
mod enrollment_flash;

#[cfg(feature = "protected-runtime")]
#[allow(dead_code)]
#[path = "journal_faults/flash.rs"]
mod retirement_flash;

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
    let mut seed = [byte; 32];
    stage_seeded(pool, byte, &mut seed)
}

fn stage_seeded(pool: &mut PoolRegistration, byte: u8, seed: &mut [u8; 32]) -> GenerationId {
    let lifetime = KesLifetime::new(64).unwrap();
    let mut operation = Generation::begin(seed, lifetime).unwrap();
    for _ in 0..64 {
        operation.step().unwrap();
    }
    let (key, tree) = operation.finish().unwrap();
    let verified = tree.verify(&key.verification_key().unwrap()).unwrap();
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
        pending_enrollment: None,
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
    let stolen_initial = SigningKey::from_bytes(&[0x5c; 32]);
    directory.credential.public_key = stolen_initial.verifying_key().to_bytes();
    let replacement_signer = SigningKey::from_bytes(&[0x56; 32]);
    let replacement_key = replacement_signer.verifying_key().to_bytes();
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

    // OPEN authorization comes from the restored current directory, not the
    // initial ceremony or a candidate credential's self-declared epoch.
    let hpke = DeviceHpkeKey::from_seed(Zeroizing::new([0x59; 32]));
    let expected = OpenContext::new(
        DEVICE,
        [0x5a; 32],
        Scope::Management,
        directory.credential.epoch,
        0,
        RequestId::from_bytes([0x5b; 16]),
    );
    let unauthorized = SigningKey::from_bytes(&[0x5d; 32]);
    for (epoch, signer, error) in [
        (0, &stolen_initial, SessionError::InvalidStructure),
        (2, &unauthorized, SessionError::InvalidStructure),
        (1, &stolen_initial, SessionError::Authentication),
        (1, &unauthorized, SessionError::Authentication),
    ] {
        let candidate = OpenContext {
            credential_epoch: CredentialEpoch::new(epoch),
            ..expected
        };
        let mut host_rng = ChaCha20Rng::from_seed([0x5e; 32]);
        let (request, _) =
            begin_open(candidate, &hpke.public_key(), signer, &mut host_rng).unwrap();
        let mut device_rng = ChaCha20Rng::from_seed([0x5f; 32]);
        assert_eq!(
            accept_open(
                expected,
                &request,
                &hpke,
                &directory.credential.public_key,
                &mut device_rng,
            )
            .err(),
            Some(error)
        );
    }
    let mut host_rng = ChaCha20Rng::from_seed([0x60; 32]);
    let (request, _) = begin_open(
        expected,
        &hpke.public_key(),
        &replacement_signer,
        &mut host_rng,
    )
    .unwrap();
    let mut device_rng = ChaCha20Rng::from_seed([0x61; 32]);
    assert!(
        accept_open(
            expected,
            &request,
            &hpke,
            &directory.credential.public_key,
            &mut device_rng,
        )
        .is_ok()
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

#[cfg(feature = "protected-runtime")]
fn fresh_retirement_seed() -> Zeroizing<[u8; 32]> {
    use std::io::Read;
    xtask::oracles::protect_memory().expect("protected fresh no-swap runtime required");
    let mut seed = Zeroizing::new([0; 32]);
    std::fs::File::open("/dev/urandom")
        .expect("disposable test entropy unavailable")
        .read_exact(&mut *seed)
        .expect("disposable test entropy unavailable");
    seed
}

#[cfg(feature = "protected-runtime")]
#[test]
fn retirement_persists_deny_before_per_pool_history_cleanup() {
    use kes_core::journal::{
        Journal, JournalLayout, JournalWorkspace, ObjectWorkspace, SecretCache, Workspaces,
    };
    let management = SigningKey::from_bytes(&fresh_retirement_seed());
    let mut first = pool(0x72, IncarnationId::from_bytes([0x73; 16]));
    let mut second = pool(0x74, IncarnationId::from_bytes([0x75; 16]));
    stage_seeded(&mut first, 0x76, &mut fresh_retirement_seed());
    stage_seeded(&mut second, 0x77, &mut fresh_retirement_seed());
    let mut directory = directory_snapshot(&management, &[&first, &second], 0);
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
    let context = JournalContext {
        device: DEVICE,
        scope: JournalScope::Directory,
    };
    let storage_root = fresh_retirement_seed();
    let journal = Journal::<DirectoryCodec>::new(
        context,
        JournalLayout::directory(0).unwrap(),
        &storage_root,
    )
    .unwrap();
    let mut flash = retirement_flash::NorFlash::new(16384);
    let mut journal_workspace = JournalWorkspace::new();
    let mut object_workspace = ObjectWorkspace::new();
    let mut cache = SecretCache::new();
    let mut work = Workspaces {
        journal: &mut journal_workspace,
        object: &mut object_workspace,
        cache: &mut cache,
    };
    let rng_seed = fresh_retirement_seed();
    let mut rng = ChaCha20Rng::from_seed(*rng_seed);
    drop(rng_seed);
    let initial = journal
        .initialize(&mut flash, &mut rng, &directory, &mut work)
        .unwrap();
    assert_eq!(
        retirement::prepare(&mut directory, &envelope),
        Ok(retirement::Preparation::Prepared {
            revision: Revision::new(1)
        })
    );
    assert_eq!(directory.live.iter().flatten().count(), 2);
    let mut token = journal
        .transact_successor(&mut flash, &mut rng, &initial, &directory, &mut work)
        .unwrap();
    let recovered = journal.recover(&mut flash, &mut rng, &mut work).unwrap();
    directory = recovered.state;
    assert_eq!(
        Device::from_authenticated_snapshot(&directory)
            .unwrap()
            .ensure_operational(UsePolicy::IsolatedDevelopment, None)
            .err(),
        Some(StateError::Retired)
    );
    assert_eq!(
        retirement::prepare(&mut directory, &envelope),
        Ok(retirement::Preparation::AlreadyPrepared {
            revision: Revision::new(1)
        })
    );
    // Preparation is not a completed result, even when retried after reboot.
    assert_eq!(directory.live.iter().flatten().count(), 2);
    let baseline = flash.copy_world();
    retirement::remove_pool(&mut directory, HardwareSlot::new(0).unwrap(), &first).unwrap();
    // Cuts during directory publication must never restore an operational device.
    // The authoritative state may retain the live reference or its tombstone.
    for cut in [0, 1, 2047, 2048, 32767, 32768, 65535, 65536] {
        let mut interrupted = baseline.copy_world();
        interrupted.arm_cut_after_bits(cut);
        let _ =
            journal.transact_successor(&mut interrupted, &mut rng, &token, &directory, &mut work);
        interrupted.disarm();
        let recovered = journal
            .recover(&mut interrupted, &mut rng, &mut work)
            .unwrap();
        let denied = Device::from_authenticated_snapshot(&recovered.state).unwrap();
        assert_eq!(
            denied
                .ensure_operational(UsePolicy::IsolatedDevelopment, None)
                .err(),
            Some(StateError::Retired)
        );
        assert_eq!(
            recovered.state.live.iter().flatten().count()
                + recovered.state.tombstones.iter().flatten().count(),
            2
        );
    }
    token = journal
        .transact_successor(&mut flash, &mut rng, &token, &directory, &mut work)
        .unwrap();
    let tombstone = directory.tombstones.iter().flatten().next().unwrap();
    assert_eq!(
        tombstone.generation_high_water,
        first.generation_high_water()
    );
    assert_eq!(tombstone.last_incarnation, first.incarnation());
    retirement::remove_pool(&mut directory, HardwareSlot::new(1).unwrap(), &second).unwrap();
    journal
        .transact_successor(&mut flash, &mut rng, &token, &directory, &mut work)
        .unwrap();
    let recovered = journal.recover(&mut flash, &mut rng, &mut work).unwrap();
    assert!(recovered.state.live.iter().all(Option::is_none));
    assert_eq!(recovered.state.tombstones.iter().flatten().count(), 2);
    assert_eq!(
        recovered.state.retirement.unwrap().revision,
        Revision::new(1)
    );
    assert_eq!(recovered.state.revision, Revision::new(3));
    // Core deliberately does not claim physical erasure: firmware must erase
    // and read-verify all slots before exposing the marker's public result.
}

#[cfg(feature = "protected-runtime")]
#[test]
fn retirement_reserves_cleanup_revisions_and_rejects_changed_authorization() {
    let management = SigningKey::from_bytes(&fresh_retirement_seed());
    let registered = pool(0x82, IncarnationId::from_bytes([0x83; 16]));
    let payload = encode_payload(|encoder| encoder.map(0).unwrap());
    let mut exhausted = directory_snapshot(&management, &[&registered], u64::MAX - 1);
    let bytes = signed_envelope(
        &management,
        Target::Device,
        1,
        0x84,
        exhausted.revision,
        Action::DeviceRetire,
        &payload,
    );
    assert_eq!(
        retirement::prepare(&mut exhausted, &verify(&bytes, &management)),
        Err(retirement::Error::CounterOverflow)
    );
    assert!(exhausted.retirement.is_none());
    assert_eq!(exhausted.live.iter().flatten().count(), 1);

    let mut directory = directory_snapshot(&management, &[&registered], 0);
    assert_eq!(
        retirement::remove_pool(&mut directory, HardwareSlot::new(0).unwrap(), &registered,),
        Err(retirement::Error::NotPrepared)
    );
    let bytes = signed_envelope(
        &management,
        Target::Device,
        1,
        0x85,
        directory.revision,
        Action::DeviceRetire,
        &payload,
    );
    retirement::prepare(&mut directory, &verify(&bytes, &management)).unwrap();
    let changed = signed_envelope(
        &management,
        Target::Device,
        1,
        0x86,
        Revision::new(0),
        Action::DeviceRetire,
        &payload,
    );
    assert_eq!(
        retirement::prepare(&mut directory, &verify(&changed, &management)),
        Err(retirement::Error::ChangedReplay)
    );
    let next = signed_envelope(
        &management,
        Target::Device,
        2,
        0x87,
        directory.revision,
        Action::DeviceRetire,
        &payload,
    );
    assert_eq!(
        retirement::prepare(&mut directory, &verify(&next, &management)),
        Err(retirement::Error::Replay)
    );
    assert_eq!(
        retirement::remove_pool(&mut directory, HardwareSlot::new(1).unwrap(), &registered,),
        Err(retirement::Error::InconsistentPoolState)
    );
    assert_eq!(directory.live.iter().flatten().count(), 1);
    assert!(directory.tombstones.iter().all(Option::is_none));
}

fn durable_enrollment_fixture() -> (
    SigningKey,
    Zeroizing<[u8; 32]>,
    ChaCha20Rng,
    enrollment_flash::NorFlash,
    Vec<u8>,
) {
    use std::io::Read;
    xtask::oracles::protect_memory().expect("fresh no-swap disposable lab required");
    let mut seed = Zeroizing::new([0u8; 32]);
    let mut root = Zeroizing::new([0u8; 32]);
    let mut entropy = std::fs::File::open("/dev/urandom").unwrap();
    entropy.read_exact(&mut seed[..]).unwrap();
    let management = SigningKey::from_bytes(&seed);
    entropy.read_exact(&mut root[..]).unwrap();
    entropy.read_exact(&mut seed[..]).unwrap();
    let mut rng = ChaCha20Rng::from_seed(*seed);
    let mut flash = enrollment_flash::NorFlash::new(16384 + kes_core::MAX_POOLS * 32768);
    let journal = kes_core::journal::Journal::<DirectoryCodec>::new(
        JournalContext {
            device: DEVICE,
            scope: JournalScope::Directory,
        },
        kes_core::journal::JournalLayout::directory(0).unwrap(),
        &root,
    )
    .unwrap();
    let mut jw = kes_core::journal::JournalWorkspace::new();
    let mut ow = kes_core::journal::ObjectWorkspace::new();
    let mut cache = kes_core::journal::SecretCache::new();
    journal
        .initialize(
            &mut flash,
            &mut rng,
            &directory_snapshot(&management, &[], 0),
            &mut kes_core::journal::Workspaces {
                journal: &mut jw,
                object: &mut ow,
                cache: &mut cache,
            },
        )
        .unwrap();
    let cold = [0xa1; 32];
    let incarnation = IncarnationId::from_bytes([0xa2; 16]);
    let encoded = signed_envelope(
        &management,
        Target::Pool {
            pool: PoolId::from_cold_verification_key(&cold),
            incarnation,
        },
        1,
        0xa3,
        Revision::new(0),
        Action::Enroll,
        &enrollment_payload(cold, incarnation, [0xa4; 32]),
    );
    (management, root, rng, flash, encoded)
}

#[test]
fn durable_enrollment_clean_and_exact_replay_use_authenticated_journals() {
    let (_, root, mut rng, mut flash, encoded) = durable_enrollment_fixture();
    let storage = kes_core::enrollment::EnrollmentStorage::new(DEVICE, 0, 16384, &root).unwrap();
    let mut jw = kes_core::journal::JournalWorkspace::new();
    let mut ow = kes_core::journal::ObjectWorkspace::new();
    let mut cache = kes_core::journal::SecretCache::new();
    let mut work = kes_core::journal::Workspaces {
        journal: &mut jw,
        object: &mut ow,
        cache: &mut cache,
    };
    let ack = storage
        .enroll(&encoded, &mut flash, &mut rng, &mut work)
        .unwrap();
    assert_eq!(ack.pool_revision, Revision::new(0));
    assert_eq!(
        storage
            .enroll(&encoded, &mut flash, &mut rng, &mut work)
            .unwrap(),
        ack
    );
    let directory = storage
        .recover_pending(&mut flash, &mut rng, &mut work)
        .unwrap();
    assert!(directory.state.pending_enrollment.is_none());
    assert_eq!(directory.state.live.iter().flatten().count(), 1);
    assert!(cache.is_erased());
}

#[test]
fn durable_enrollment_power_cuts_recover_without_reusing_an_ambiguous_slot() {
    let (_, root, mut rng, flash, encoded) = durable_enrollment_fixture();
    let storage = kes_core::enrollment::EnrollmentStorage::new(DEVICE, 0, 16384, &root).unwrap();
    let mut jw = kes_core::journal::JournalWorkspace::new();
    let mut ow = kes_core::journal::ObjectWorkspace::new();
    let mut cache = kes_core::journal::SecretCache::new();
    let mut work = kes_core::journal::Workspaces {
        journal: &mut jw,
        object: &mut ow,
        cache: &mut cache,
    };
    let mut probe = flash.copy_world();
    probe.arm_cut_after_bits(usize::MAX);
    let expected = storage
        .enroll(&encoded, &mut probe, &mut rng, &mut work)
        .unwrap();
    let total = probe.steps();
    let mut cuts: Vec<usize> = (0..total).step_by(8191).collect();
    cuts.extend([1, 2047, 2048, total - 1, total]);
    for cut in cuts {
        let mut world = flash.copy_world();
        world.arm_cut_after_bits(cut);
        let first = storage.enroll(&encoded, &mut world, &mut rng, &mut work);
        world.disarm();
        let directory = storage
            .recover_pending(&mut world, &mut rng, &mut work)
            .unwrap_or_else(|e| panic!("recovery at bit {cut}: {e:?}"));
        assert!(directory.state.pending_enrollment.is_none());
        if first.is_ok() {
            assert_eq!(directory.state.live.iter().flatten().count(), 1);
        }
        let ack = storage
            .enroll(&encoded, &mut world, &mut rng, &mut work)
            .unwrap_or_else(|e| panic!("replay at bit {cut}: {e:?}"));
        assert_eq!(ack, expected);
        assert_eq!(
            storage
                .enroll(&encoded, &mut world, &mut rng, &mut work)
                .unwrap(),
            expected
        );
    }
}

#[test]
fn durable_enrollment_does_not_initialize_a_nonblank_unreserved_slot() {
    let (_, root, mut rng, mut flash, encoded) = durable_enrollment_fixture();
    flash.corrupt(16384 + 9000, 1).unwrap();
    let storage = kes_core::enrollment::EnrollmentStorage::new(DEVICE, 0, 16384, &root).unwrap();
    let mut jw = kes_core::journal::JournalWorkspace::new();
    let mut ow = kes_core::journal::ObjectWorkspace::new();
    let mut cache = kes_core::journal::SecretCache::new();
    let mut work = kes_core::journal::Workspaces {
        journal: &mut jw,
        object: &mut ow,
        cache: &mut cache,
    };
    assert_eq!(
        storage.enroll(&encoded, &mut flash, &mut rng, &mut work),
        Err(kes_core::enrollment::Error::SlotNotErased)
    );
    assert_eq!(flash.raw()[16384 + 9000], 254);
    let directory = storage
        .recover_pending(&mut flash, &mut rng, &mut work)
        .unwrap();
    assert!(directory.state.live.iter().all(Option::is_none));
    assert!(directory.state.pending_enrollment.is_none());
}

#[test]
fn durable_reenrollment_preserves_history_and_other_pool_slot() {
    let (management, root, mut rng, mut flash, encoded) = durable_enrollment_fixture();
    let storage = kes_core::enrollment::EnrollmentStorage::new(DEVICE, 0, 16384, &root).unwrap();
    let mut jw = kes_core::journal::JournalWorkspace::new();
    let mut ow = kes_core::journal::ObjectWorkspace::new();
    let mut cache = kes_core::journal::SecretCache::new();
    let mut work = kes_core::journal::Workspaces {
        journal: &mut jw,
        object: &mut ow,
        cache: &mut cache,
    };
    storage
        .enroll(&encoded, &mut flash, &mut rng, &mut work)
        .unwrap();
    let other_slot = flash.raw()[16384..16384 + 32768].to_vec();
    let cold = [0xb1; 32];
    let target = PoolId::from_cold_verification_key(&cold);
    let old_incarnation = IncarnationId::from_bytes([0xb2; 16]);
    let new_incarnation = IncarnationId::from_bytes([0xb3; 16]);
    let journal = kes_core::journal::Journal::<DirectoryCodec>::new(
        JournalContext {
            device: DEVICE,
            scope: JournalScope::Directory,
        },
        kes_core::journal::JournalLayout::directory(0).unwrap(),
        &root,
    )
    .unwrap();
    let mut directory = storage
        .recover_pending(&mut flash, &mut rng, &mut work)
        .unwrap();
    directory.state.revision = directory.state.revision.checked_increment().unwrap();
    let deletion_revision = directory.state.revision;
    directory.state.tombstones[0] = Some(kes_core::state::PoolTombstone {
        pool_id: target,
        last_incarnation: old_incarnation,
        credential_epoch: Some(kes_core::types::CredentialEpoch::new(0)),
        management_sequence: ManagementSequence::new(9),
        certificate_high_water: Some(kes_core::types::CertificateCounter::new(17)),
        generation_high_water: GenerationNumber::new(23),
        deletion_revision,
        management_replay: kes_core::state::ManagementReplay {
            sequence: ManagementSequence::new(9),
            request: RequestId::from_bytes([0xb4; 16]),
            payload_digest: [0xb5; 32],
            result: kes_core::state::ManagementResult::Committed {
                revision: deletion_revision,
            },
        },
    });
    journal
        .transact_successor(
            &mut flash,
            &mut rng,
            &directory.token,
            &directory.state,
            &mut work,
        )
        .unwrap();
    let reenroll = signed_envelope(
        &management,
        Target::Pool {
            pool: target,
            incarnation: new_incarnation,
        },
        10,
        0xb6,
        deletion_revision,
        Action::Enroll,
        &enrollment_payload(cold, new_incarnation, [0xb7; 32]),
    );
    let before_enrollment = flash.copy_world();
    flash.arm_cut_after_bits(usize::MAX);
    let ack = storage
        .enroll(&reenroll, &mut flash, &mut rng, &mut work)
        .unwrap();
    let transaction_bits = flash.steps();
    flash.disarm();
    assert_eq!(ack.slot.get(), 1);
    assert_eq!(&flash.raw()[16384..16384 + 32768], other_slot.as_slice());
    let pool_journal = kes_core::journal::Journal::<PoolCodec>::new(
        JournalContext {
            device: DEVICE,
            scope: JournalScope::Pool {
                slot: ack.slot,
                pool: target,
                incarnation: new_incarnation,
            },
        },
        kes_core::journal::JournalLayout::pool(16384 + 32768).unwrap(),
        &root,
    )
    .unwrap();
    let recovered = pool_journal
        .recover(&mut flash, &mut rng, &mut work)
        .unwrap();
    assert_eq!(
        recovered.state.generation_high_water(),
        GenerationNumber::new(23)
    );
    assert_eq!(
        recovered.state.certificate_high_water(),
        Some(kes_core::types::CertificateCounter::new(17))
    );
    assert_eq!(
        recovered.state.management_sequence(),
        ManagementSequence::new(10)
    );
    let directory = storage
        .recover_pending(&mut flash, &mut rng, &mut work)
        .unwrap();
    assert!(directory.state.tombstones.iter().all(Option::is_none));
    assert_eq!(directory.state.live.iter().flatten().count(), 2);
    assert_eq!(
        storage
            .enroll(&reenroll, &mut flash, &mut rng, &mut work)
            .unwrap(),
        ack
    );
    for cut in (0..transaction_bits).step_by(8191) {
        let mut world = before_enrollment.copy_world();
        world.arm_cut_after_bits(cut);
        let _ = storage.enroll(&reenroll, &mut world, &mut rng, &mut work);
        world.disarm();
        let directory = storage
            .recover_pending(&mut world, &mut rng, &mut work)
            .unwrap();
        // Before intent COMMIT the complete tombstone remains authoritative;
        // afterward recovery publishes a pool with the exact retained history.
        if let Some(t) = directory
            .state
            .tombstones
            .iter()
            .flatten()
            .find(|t| t.pool_id == target)
        {
            assert_eq!(t.generation_high_water, GenerationNumber::new(23));
            assert_eq!(
                t.certificate_high_water,
                Some(kes_core::types::CertificateCounter::new(17))
            );
            assert_eq!(t.management_sequence, ManagementSequence::new(9));
        }
        assert_eq!(
            storage
                .enroll(&reenroll, &mut world, &mut rng, &mut work)
                .unwrap(),
            ack
        );
        let recovered = pool_journal
            .recover(&mut world, &mut rng, &mut work)
            .unwrap();
        assert_eq!(
            recovered.state.generation_high_water(),
            GenerationNumber::new(23)
        );
        assert_eq!(
            recovered.state.certificate_high_water(),
            Some(kes_core::types::CertificateCounter::new(17))
        );
        assert_eq!(
            recovered.state.management_sequence(),
            ManagementSequence::new(10)
        );
        assert_eq!(&world.raw()[16384..16384 + 32768], other_slot.as_slice());
    }
}

#[test]
fn durable_enrollment_rejects_changed_replay_and_damaged_live_pool_without_reset() {
    let (management, root, mut rng, mut flash, encoded) = durable_enrollment_fixture();
    let storage = kes_core::enrollment::EnrollmentStorage::new(DEVICE, 0, 16384, &root).unwrap();
    let mut jw = kes_core::journal::JournalWorkspace::new();
    let mut ow = kes_core::journal::ObjectWorkspace::new();
    let mut cache = kes_core::journal::SecretCache::new();
    let mut work = kes_core::journal::Workspaces {
        journal: &mut jw,
        object: &mut ow,
        cache: &mut cache,
    };
    storage
        .enroll(&encoded, &mut flash, &mut rng, &mut work)
        .unwrap();
    let cold = [0xa1; 32];
    let incarnation = IncarnationId::from_bytes([0xa2; 16]);
    let changed = signed_envelope(
        &management,
        Target::Pool {
            pool: PoolId::from_cold_verification_key(&cold),
            incarnation,
        },
        1,
        0xa3,
        Revision::new(0),
        Action::Enroll,
        &enrollment_payload(cold, incarnation, [0xcc; 32]),
    );
    assert_eq!(
        storage.enroll(&changed, &mut flash, &mut rng, &mut work),
        Err(kes_core::enrollment::Error::ChangedReplay)
    );
    flash.corrupt(16384 + 64, 1).unwrap();
    let damaged = flash.raw()[16384..16384 + 32768].to_vec();
    assert!(
        storage
            .enroll(&encoded, &mut flash, &mut rng, &mut work)
            .is_err()
    );
    assert_eq!(&flash.raw()[16384..16384 + 32768], damaged.as_slice());
}

#[test]
fn pending_enrollment_rejects_other_requests_and_recovers_interrupted_recovery() {
    let (management, root, mut rng, flash, encoded) = durable_enrollment_fixture();
    let storage = kes_core::enrollment::EnrollmentStorage::new(DEVICE, 0, 16384, &root).unwrap();
    let directory_journal = kes_core::journal::Journal::<DirectoryCodec>::new(
        JournalContext {
            device: DEVICE,
            scope: JournalScope::Directory,
        },
        kes_core::journal::JournalLayout::directory(0).unwrap(),
        &root,
    )
    .unwrap();
    let mut jw = kes_core::journal::JournalWorkspace::new();
    let mut ow = kes_core::journal::ObjectWorkspace::new();
    let mut cache = kes_core::journal::SecretCache::new();
    let mut work = kes_core::journal::Workspaces {
        journal: &mut jw,
        object: &mut ow,
        cache: &mut cache,
    };
    let mut probe = flash.copy_world();
    probe.arm_cut_after_bits(usize::MAX);
    storage
        .enroll(&encoded, &mut probe, &mut rng, &mut work)
        .unwrap();
    let mut pending_world = None;
    for cut in (0..probe.steps()).step_by(8191) {
        let mut world = flash.copy_world();
        world.arm_cut_after_bits(cut);
        let _ = storage.enroll(&encoded, &mut world, &mut rng, &mut work);
        world.disarm();
        if directory_journal
            .recover(&mut world, &mut rng, &mut work)
            .unwrap()
            .state
            .pending_enrollment
            .is_some()
        {
            pending_world = Some(world);
            break;
        }
    }
    let mut pending_world =
        pending_world.expect("fault model must expose a durable enrollment intent");
    let cold = [0xd1; 32];
    let incarnation = IncarnationId::from_bytes([0xd2; 16]);
    let unrelated = signed_envelope(
        &management,
        Target::Pool {
            pool: PoolId::from_cold_verification_key(&cold),
            incarnation,
        },
        1,
        0xd3,
        Revision::new(0),
        Action::Enroll,
        &enrollment_payload(cold, incarnation, [0xd4; 32]),
    );
    let before = pending_world.raw()[16384..].to_vec();
    assert_eq!(
        storage.enroll(&unrelated, &mut pending_world, &mut rng, &mut work),
        Err(kes_core::enrollment::Error::PendingOperation)
    );
    assert_eq!(&pending_world.raw()[16384..], before.as_slice());
    for cut in [1, 2047, 2048, 8191, 32767, 65535] {
        let mut world = pending_world.copy_world();
        world.arm_cut_after_bits(cut);
        let _ = storage.recover_pending(&mut world, &mut rng, &mut work);
        world.disarm();
        let directory = storage
            .recover_pending(&mut world, &mut rng, &mut work)
            .unwrap();
        assert!(directory.state.pending_enrollment.is_none());
        assert_eq!(directory.state.live.iter().flatten().count(), 1);
        storage
            .enroll(&encoded, &mut world, &mut rng, &mut work)
            .unwrap();
    }
}
