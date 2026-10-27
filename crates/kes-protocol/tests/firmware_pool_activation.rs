//! Lifecycle wire execution against real durable journal and immutable objects.
//! Session authentication belongs to the router; these tests exercise its
//! already-authenticated execution seam, never a mock lifecycle backend.
#[allow(dead_code)]
#[path = "../../kes-core/tests/support/mod.rs"]
mod support;
#[allow(dead_code)]
#[path = "../../../firmware/src/development/pool_sessions.rs"]
mod pool_sessions_impl;
mod development { pub mod pool_sessions { pub use crate::pool_sessions_impl::*; } }
#[allow(dead_code)]
#[path = "../../../firmware/src/pool_service.rs"]
mod pool_service;
#[path = "../../../firmware/src/development/pool_activation.rs"]
mod pool_activation;

use kes_core::{
    activation::{DurablePool, OperationError},
    cbor::Encoder,
    crypto::PublicTreeBuffer,
    state::{DirectoryEntry, Lifecycle},
    types::{HardwareSlot, NetworkBinding},
};
use kes_protocol::{Envelope, EnvelopeKind, Operation, MAX_FRAME_BYTES};
use pool_activation::{ActivationError, execute};
use pool_sessions_impl::PoolAuthority;
use support::Fixture;

fn recover(f: &mut Fixture) -> PoolAuthority {
    let recovered = f.journal.recover(&mut f.flash, &mut f.entropy, &mut f.buffers.work()).unwrap();
    let authority = PoolAuthority::from_recovered(DirectoryEntry::new(
        HardwareSlot::new(0).unwrap(), recovered.state.pool_id(), recovered.state.incarnation()), &recovered).unwrap();
    f.durable = DurablePool::from_recovered(recovered);
    authority
}
fn wire(f: &Fixture, operation: Operation, revision: u64, network: NetworkBinding) -> Vec<u8> {
    let state = f.durable.state().unwrap();
    let mut bytes = [0; MAX_FRAME_BYTES];
    let mut e = Encoder::new(&mut bytes);
    e.map(11).unwrap();
    e.text("op").unwrap(); e.text(operation.as_str()).unwrap();
    e.text("mac").unwrap(); e.bytes(&[0; 32]).unwrap();
    e.text("seq").unwrap(); e.uint(1).unwrap();
    e.text("pool").unwrap(); e.bytes(state.pool_id().as_bytes()).unwrap();
    e.text("device").unwrap(); e.bytes(&[0x19; 16]).unwrap();
    e.text("payload").unwrap();
    if operation == Operation::Certify {
        e.map(4).unwrap();
        e.text("network").unwrap(); e.map(4).unwrap();
        e.text("network_magic").unwrap(); e.uint(network.network_magic().into()).unwrap();
        e.text("max_kes_evolutions").unwrap(); e.uint(network.max_kes_evolutions().into()).unwrap();
        e.text("slots_per_kes_period").unwrap(); e.uint(network.slots_per_kes_period()).unwrap();
        e.text("shelley_genesis_digest").unwrap(); e.bytes(network.genesis_hash().as_bytes()).unwrap();
        e.text("generation").unwrap(); e.bytes(f.generation.as_bytes()).unwrap();
        e.text("certificate").unwrap(); e.bytes(&f.certificate).unwrap();
        e.text("expected_revision").unwrap(); e.uint(revision).unwrap();
    } else {
        e.map(5).unwrap();
        e.text("generation").unwrap(); e.bytes(f.generation.as_bytes()).unwrap();
        e.text("expected_revision").unwrap(); e.uint(revision).unwrap();
        e.text("certificate_digest").unwrap(); e.bytes(&f.certificate_digest).unwrap();
        e.text("current_absolute_period").unwrap(); e.uint(103).unwrap();
        e.text("expected_active_generation").unwrap(); e.null().unwrap();
    }
    e.text("request").unwrap(); e.bytes(&[0x31; 16]).unwrap();
    e.text("session").unwrap(); e.bytes(&[0x32; 16]).unwrap();
    e.text("version").unwrap(); e.uint(1).unwrap();
    e.text("budget_ms").unwrap(); e.uint(500).unwrap();
    e.text("incarnation").unwrap(); e.bytes(state.incarnation().as_bytes()).unwrap();
    e.finish().unwrap().encoded().to_vec()
}
fn run(f: &mut Fixture, authority: PoolAuthority, wire: &[u8]) -> Result<pool_activation::ActivationOutcome, ActivationError> {
    execute(Envelope::parse(wire, EnvelopeKind::DeviceRequest).unwrap(), authority,
        &mut f.durable, &f.journal, &mut f.flash, f.layout, &mut f.entropy,
        &mut f.buffers.work(), &mut [0; 6144], &mut PublicTreeBuffer::new())
}

#[test]
fn certification_retry_and_activation_survive_authenticated_recovery() {
    let mut f = Fixture::new();
    let authority = recover(&mut f);
    let revision = f.durable.state().unwrap().revision().get();
    let certificate = wire(&f, Operation::Certify, revision, f.network);
    let certified = run(&mut f, authority, &certificate).unwrap();
    assert!(certified.committed_write);
    assert_eq!(certified.context.lifecycle, Lifecycle::CertifiedStaged);
    let authority = recover(&mut f);
    let retry = run(&mut f, authority, &certificate).unwrap();
    assert!(!retry.committed_write);
    assert_eq!(retry.context, certified.context);
    let activate = wire(&f, Operation::Activate, certified.context.revision.get(), f.network);
    let active = run(&mut f, authority, &activate).unwrap();
    assert!(active.committed_write);
    assert_eq!(active.context.relative_period.get(), 3);
    assert_eq!(active.context.lifecycle, Lifecycle::Active);
    recover(&mut f);
    let state = f.durable.state().unwrap();
    assert!(state.staged().is_none());
    assert_eq!(state.current().unwrap().id(), active.context.generation);
    assert_eq!(state.current().unwrap().relative_period().get(), 3);
}

#[test]
fn wrong_network_does_not_certify_and_storage_failure_never_acknowledges() {
    let mut f = Fixture::new();
    let authority = recover(&mut f);
    let revision = f.durable.state().unwrap().revision();
    let wrong_network = NetworkBinding::from_genesis_bytes(42, b"different genesis", 129600, 64).unwrap();
    let invalid = wire(&f, Operation::Certify, revision.get(), wrong_network);
    assert!(matches!(run(&mut f, authority, &invalid), Err(ActivationError::Operation(OperationError::State(_)))));
    assert_eq!(f.durable.state().unwrap().revision(), revision);
    assert!(f.durable.state().unwrap().staged().unwrap().certificate().is_none());
    let valid = wire(&f, Operation::Certify, revision.get(), f.network);
    f.flash.fail_next_mutation();
    assert!(matches!(run(&mut f, authority, &valid), Err(ActivationError::Operation(OperationError::Journal(_)))));
    assert!(!f.durable.is_usable());
}

#[test]
fn damaged_immutable_tree_blocks_activation_without_a_transition() {
    let mut f = Fixture::new();
    let authority = recover(&mut f);
    let certificate = wire(&f, Operation::Certify, f.durable.state().unwrap().revision().get(), f.network);
    let certified = run(&mut f, authority, &certificate).unwrap();
    let activate = wire(&f, Operation::Activate, certified.context.revision.get(), f.network);
    f.flash.install_public_object(f.layout.object_offset(0).unwrap() + 64, &[0xff; 32]);
    assert!(matches!(run(&mut f, authority, &activate), Err(ActivationError::Storage(_))));
    assert_eq!(f.durable.state().unwrap().revision(), certified.context.revision);
    assert_eq!(f.durable.state().unwrap().staged().unwrap().lifecycle(), Lifecycle::CertifiedStaged);
}

#[test]
fn replacement_schedule_retry_and_activation_are_durable() {
    use kes_core::{
        activation::StageGenerationRequest,
        crypto::Generation,
        state::{GenerationSpec, KESGeneration, PublicObject},
        types::{GenerationId, GenerationNumber, RequestId},
    };
    use rand_chacha::rand_core::TryRngCore;
    use sha2::{Digest, Sha256};
    use zeroize::Zeroizing;
    let mut f = Fixture::new();
    let authority = recover(&mut f);
    let certificate = wire(&f, Operation::Certify, f.durable.state().unwrap().revision().get(), f.network);
    let certified = run(&mut f, authority, &certificate).unwrap();
    let activate = wire(&f, Operation::Activate, certified.context.revision.get(), f.network);
    run(&mut f, authority, &activate).unwrap();
    let previous = f.generation;
    let mut seed = Zeroizing::new([0; 32]);
    f.entropy.try_fill_bytes(&mut *seed).unwrap();
    let mut job = Generation::begin(&mut seed, kes_core::types::KesLifetime::new(64).unwrap()).unwrap();
    for _ in 0..64 { job.step().unwrap(); }
    let (key, tree) = job.finish().unwrap();
    let verification_key = key.verification_key().unwrap();
    f.generation = GenerationId::random(&mut f.entropy).unwrap();
    let object = PublicObject::from_parts(f.generation, tree.as_bytes(),
        include_bytes!("../../../fuzz/corpus/frame/backup-public-structure"), &verification_key).unwrap();
    let mut encoded = [0; 6144];
    let length = object.encode_into(&mut encoded).unwrap();
    f.flash.install_public_object(f.layout.object_offset(1).unwrap(), &encoded[..length]);
    let state = f.durable.state().unwrap();
    let generation = KESGeneration::new_staged(GenerationSpec {
        generation_id: f.generation, generation_number: GenerationNumber::new(2),
        creation_request: RequestId::from_bytes([0x71; 16]), creation_payload_digest: [0x72; 32],
        pool: state.pool_id(), incarnation: state.incarnation(), verification_key,
        lifetime: key.lifetime(), recipient_id: *state.recipient_id(), public_object: object,
    }, key).unwrap();
    let request = StageGenerationRequest { actor: f.actor, expected_revision: state.revision(),
        generation, policy: state.generation_policy() };
    f.durable.stage_generation(&f.journal, &mut f.flash, &mut f.entropy, &mut f.buffers.work(), request).unwrap();
    f.certificate = support::certificate(&f.cold, &verification_key, 1, 100);
    f.certificate_digest = Sha256::digest(&f.certificate).into();
    let authority = recover(&mut f);
    let certificate = wire(&f, Operation::Certify, f.durable.state().unwrap().revision().get(), f.network);
    let certified = run(&mut f, authority, &certificate).unwrap();
    let encode_transition = |operation: Operation, revision: u64| {
        let state = f.durable.state().unwrap();
        let mut bytes = [0; MAX_FRAME_BYTES];
        let mut e = Encoder::new(&mut bytes);
        e.map(11).unwrap();
        e.text("op").unwrap(); e.text(operation.as_str()).unwrap();
        e.text("mac").unwrap(); e.bytes(&[0; 32]).unwrap();
        e.text("seq").unwrap(); e.uint(1).unwrap();
        e.text("pool").unwrap(); e.bytes(state.pool_id().as_bytes()).unwrap();
        e.text("device").unwrap(); e.bytes(&[0x19; 16]).unwrap();
        e.text("payload").unwrap(); e.map(5).unwrap();
        e.text("generation").unwrap(); e.bytes(f.generation.as_bytes()).unwrap();
        e.text("expected_revision").unwrap(); e.uint(revision).unwrap();
        e.text("certificate_digest").unwrap(); e.bytes(&f.certificate_digest).unwrap();
        e.text(if operation == Operation::Schedule { "activation_absolute_period" } else { "current_absolute_period" }).unwrap();
        e.uint(104).unwrap();
        e.text("expected_active_generation").unwrap(); e.bytes(previous.as_bytes()).unwrap();
        e.text("request").unwrap(); e.bytes(&[0x73; 16]).unwrap();
        e.text("session").unwrap(); e.bytes(&[0x74; 16]).unwrap();
        e.text("version").unwrap(); e.uint(1).unwrap();
        e.text("budget_ms").unwrap(); e.uint(500).unwrap();
        e.text("incarnation").unwrap(); e.bytes(state.incarnation().as_bytes()).unwrap();
        e.finish().unwrap().encoded().to_vec()
    };
    let schedule = encode_transition(Operation::Schedule, certified.context.revision.get());
    let activate = encode_transition(Operation::Activate, certified.context.revision.get() + 1);
    let scheduled = run(&mut f, authority, &schedule).unwrap();
    assert!(scheduled.committed_write);
    let authority = recover(&mut f);
    assert_eq!(f.durable.activation_intent().unwrap().target_generation(), f.generation);
    assert!(!run(&mut f, authority, &schedule).unwrap().committed_write);
    let active = run(&mut f, authority, &activate).unwrap();
    assert_eq!(active.context.relative_period.get(), 4);
    recover(&mut f);
    assert_eq!(f.durable.state().unwrap().current().unwrap().id(), f.generation);
    assert!(f.durable.state().unwrap().staged().is_none());
    assert!(f.durable.activation_intent().is_none());
}
