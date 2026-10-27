#[allow(dead_code)]
#[path = "../../../firmware/src/pool_service.rs"]
mod pool_service;
#[allow(dead_code)]
mod support;

use kes_core::{
    generation::{self, Admission, GenerationCoordinator, GenerationRequest, PublicObjectStore},
    journal::{Flash, Journal, JournalContext, JournalLayout, JournalScope, PoolCodec},
    state::{Actor, Enrollment, PoolRegistration},
    types::{
        DeviceId, GenerationNumber, HardwareSlot, KesLifetime, ManagementSequence, RequestId,
        Revision,
    },
};
use pool_service::{FlashPublicObjects, ObjectStoreError};
use rand_chacha::rand_core::TryRngCore;
use support::Fixture;
use zeroize::Zeroizing;

// Use the existing protected OS-entropy fixture; every key and encrypted backup
// below is generated at execution time, never persisted in a test corpus.
fn blank_pool(f: &Fixture) -> PoolRegistration {
    let pool = f.durable.state().unwrap();
    PoolRegistration::new(
        Actor::Management,
        Enrollment {
            incarnation: pool.incarnation(),
            cold_verification_key: *pool.cold_verification_key(),
            network: f.network,
            machine_public_key: *pool.credential_public_key(),
            recipient_public_key: *pool.recipient_public_key(),
            recipient_id: *pool.recipient_id(),
            management_sequence: ManagementSequence::new(1),
            management_request: RequestId::from_bytes([0x32; 16]),
            management_payload_digest: [0x33; 32],
        },
    )
    .unwrap()
}

#[test]
fn real_generation_object_survives_journal_commit_reboot_and_backup_fetch() {
    let mut f = Fixture::new();
    let mut pool = blank_pool(&f);
    let device = DeviceId::from_bytes([0x71; 16]);
    let mut root = Zeroizing::new([0; 32]);
    f.entropy.try_fill_bytes(&mut root[..]).unwrap();
    let journal = Journal::<PoolCodec>::new(
        JournalContext {
            device,
            scope: JournalScope::Pool {
                slot: HardwareSlot::new(0).unwrap(),
                pool: pool.pool_id(),
                incarnation: pool.incarnation(),
            },
        },
        f.layout,
        &root,
    )
    .unwrap();
    // Reuse only the flash allocation, not the fixture's authenticated state.
    for offset in (0..32768).step_by(4096) {
        f.flash.erase_sector(offset).unwrap();
    }
    let initial = journal
        .initialize(&mut f.flash, &mut f.entropy, &pool, &mut f.buffers.work())
        .unwrap();
    let mut coordinator = GenerationCoordinator::new();
    let request = RequestId::from_bytes([0x55; 16]);
    let Admission::Started(operation) = coordinator
        .admit(
            &pool,
            GenerationRequest {
                actor: f.actor,
                request,
                payload_digest: [0x56; 32],
                next_generation_number: GenerationNumber::new(1),
                expected_revision: Revision::new(0),
            },
            &mut f.entropy,
        )
        .unwrap()
    else {
        panic!("new generation must start")
    };
    let mut job =
        generation::begin_key_generation(&mut f.entropy, KesLifetime::new(64).unwrap()).unwrap();
    for _ in 0..64 {
        job.step().unwrap();
    }
    let (key, tree) = job.finish().unwrap();
    let verified = tree.verify(&key.verification_key().unwrap()).unwrap();
    let mut write = [0; 6144];
    let mut read = [0; 6144];
    let descriptor = {
        let mut store = FlashPublicObjects::new(&mut f.flash, f.layout, &pool).unwrap();
        coordinator
            .complete(
                &mut pool,
                operation,
                key,
                &verified,
                device,
                &kes_core::session::DeviceIdentityKey::from_seed(zeroize::Zeroizing::new(
                    [0x23; 32],
                )),
                &mut f.entropy,
                &mut store,
                &mut write,
                &mut read,
            )
            .unwrap()
    };
    let token = journal
        .transact_successor(
            &mut f.flash,
            &mut f.entropy,
            &initial,
            &pool,
            &mut f.buffers.work(),
        )
        .unwrap();
    drop(pool);
    let recovered = journal
        .recover(&mut f.flash, &mut f.entropy, &mut f.buffers.work())
        .unwrap();
    assert!(recovered.token == token);
    let mut store = FlashPublicObjects::new(&mut f.flash, f.layout, &recovered.state).unwrap();
    let backup = generation::get_backup(
        &recovered.state,
        descriptor.generation,
        &mut store,
        &mut read,
    )
    .unwrap();
    assert_eq!(backup.digest, descriptor.artifact_digest);
    let exact = backup.bytes.to_vec();
    let backup = generation::get_backup(
        &recovered.state,
        descriptor.generation,
        &mut store,
        &mut read,
    )
    .unwrap();
    assert_eq!(backup.bytes, exact);
    assert_eq!(
        store.discard(&descriptor.public_object),
        Err(ObjectStoreError::ProtectedObject)
    );
    // An exact retry of the immutable object succeeds without programming: the
    // armed mutation failure remains for the following real flash mutation.
    store
        .write(
            &descriptor.public_object,
            &write[..usize::from(descriptor.public_object.total_length)],
        )
        .unwrap();
    f.flash.fail_next_mutation();
    let mut store = FlashPublicObjects::new(&mut f.flash, f.layout, &recovered.state).unwrap();
    store
        .write(
            &descriptor.public_object,
            &write[..usize::from(descriptor.public_object.total_length)],
        )
        .unwrap();
    assert!(f.flash.erase_sector(24576).is_err());
}

#[test]
fn malformed_object_and_missing_retained_reference_fail_closed() {
    let mut f = Fixture::new();
    let pool = f.durable.state().unwrap();
    let reference = *pool.staged().unwrap().public_object_ref();
    let mut read = [0; 6144];
    {
        let mut store = FlashPublicObjects::new(&mut f.flash, f.layout, pool).unwrap();
        let n = store.read(&reference, &mut read).unwrap();
        read[32] ^= 1;
        assert_eq!(
            store.write(&reference, &read[..n]),
            Err(ObjectStoreError::InvalidObject)
        );
        assert_eq!(
            store.discard(&reference),
            Err(ObjectStoreError::ProtectedObject)
        );
        assert_eq!(
            store.read(&reference, &mut [0; 8]),
            Err(ObjectStoreError::Capacity)
        );
    }
    f.flash
        .erase_sector(f.layout.object_offset(0).unwrap())
        .unwrap();
    assert!(matches!(
        FlashPublicObjects::new(&mut f.flash, f.layout, pool),
        Err(ObjectStoreError::MissingRetainedObject)
    ));
    assert!(matches!(
        FlashPublicObjects::new(&mut f.flash, JournalLayout::directory(0).unwrap(), pool),
        Err(ObjectStoreError::Layout)
    ));
}

#[test]
fn interrupted_unpublished_write_can_be_erased_without_touching_retained_backup() {
    use sha2::{Digest, Sha256};
    let mut f = Fixture::new();
    let pool = f.durable.state().unwrap();
    let retained = *pool.staged().unwrap().public_object_ref();
    let mut bytes = [0; 6144];
    let length = {
        let mut store = FlashPublicObjects::new(&mut f.flash, f.layout, pool).unwrap();
        store.read(&retained, &mut bytes).unwrap()
    };
    // A distinct public object exercises the free physical slot. Its backup is
    // only structural test input; cryptographic artifact creation is exercised
    // by the generation/commit/reboot test above.
    bytes[10] ^= 1;
    let mut candidate = retained;
    candidate.generation =
        kes_core::types::GenerationId::from_bytes(bytes[10..26].try_into().unwrap());
    candidate.digest = Sha256::digest(&bytes[..length]).into();
    f.flash.fail_next_mutation();
    {
        let mut store = FlashPublicObjects::new(&mut f.flash, f.layout, pool).unwrap();
        assert_eq!(
            store.write(&candidate, &bytes[..length]),
            Err(ObjectStoreError::Flash)
        );
        store.discard(&candidate).unwrap();
        assert_eq!(
            store.read(&candidate, &mut bytes),
            Err(ObjectStoreError::MissingObject)
        );
        let n = store.read(&retained, &mut bytes).unwrap();
        store.write(&retained, &bytes[..n]).unwrap();
    }
    let recovered = f
        .journal
        .recover(&mut f.flash, &mut f.entropy, &mut f.buffers.work())
        .unwrap();
    assert_eq!(
        *recovered.state.staged().unwrap().public_object_ref(),
        retained
    );
}
