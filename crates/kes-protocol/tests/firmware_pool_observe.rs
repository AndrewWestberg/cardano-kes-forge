//! Adapter regressions with real journal recovery, object validation and rotation.
#[allow(dead_code)]
#[path = "../../kes-core/tests/support/mod.rs"]
mod support;
#[allow(dead_code)]
#[path = "../../../firmware/src/security/gateway.rs"]
mod gateway_impl;
mod security { pub mod gateway { pub use crate::gateway_impl::*; } }
#[allow(dead_code)]
#[path = "../../../firmware/src/scheduler.rs"]
mod scheduler;
#[allow(dead_code)]
#[path = "../../../firmware/src/usb.rs"]
mod usb;
#[allow(dead_code)]
#[path = "../../../firmware/src/pool_service.rs"]
mod pool_service;
#[allow(dead_code)]
#[path = "../../../firmware/src/development/pool_sessions.rs"]
mod pool_sessions;
#[allow(dead_code)]
#[path = "../../../firmware/src/development/pool_observe.rs"]
mod pool_observe;

use kes_core::{
    activation::{ActivationRequest, CertificationRequest, DurablePool, ScheduleRequest, StageGenerationRequest},
    cbor::Encoder,
    crypto::{Generation, PublicTreeBuffer},
    session::{AuthenticatedRequest, Scope},
    state::{DirectoryEntry, GenerationSpec, KESGeneration, Lifecycle, PublicObject},
    types::{AbsolutePeriod, GenerationId, GenerationNumber, HardwareSlot, KesLifetime, RequestId, Revision},
};
use kes_protocol::{Envelope, EnvelopeKind, MAX_FRAME_BYTES, Status};
use pool_observe::Outcome;
use pool_sessions::PoolAuthority;
use sha2::{Digest, Sha256};
use support::Fixture;
use zeroize::Zeroizing;

const REQUEST: RequestId = RequestId::from_bytes([0x37; 16]);

fn active() -> Fixture {
    let mut f = Fixture::new();
    f.durable.certify(&f.journal, &mut f.flash, &mut f.entropy, &mut f.buffers.work(),
        CertificationRequest { actor: f.actor, expected_revision: Revision::new(1),
            generation: f.generation, canonical_certificate: &f.certificate, network: &f.network }).unwrap();
    let key = *f.durable.state().unwrap().staged().unwrap().verification_key();
    let tree = f.tree.verify(&key).unwrap();
    f.durable.activate_first(&f.journal, &mut f.flash, &mut f.entropy, &mut f.buffers.work(),
        ActivationRequest { actor: f.actor, expected_revision: Revision::new(2),
            expected_active_generation: None, generation: f.generation,
            certificate_digest: f.certificate_digest, current_absolute_period: AbsolutePeriod::new(100) }, &tree).unwrap();
    f
}

fn scheduled(f: &mut Fixture) -> GenerationId {
    let lifetime = KesLifetime::new(64).unwrap();
    let mut seed = Zeroizing::new([0x72; 32]);
    let mut job = Generation::begin(&mut seed, lifetime).unwrap();
    for _ in 0..64 { job.step().unwrap(); }
    let (key, tree) = job.finish().unwrap();
    let verification_key = key.verification_key().unwrap();
    let verified = tree.verify(&verification_key).unwrap();
    let generation = GenerationId::from_bytes([0x72; 16]);
    let backup = include_bytes!("../../../fuzz/corpus/frame/backup-public-structure");
    let object = PublicObject::from_parts(generation, verified.as_bytes(), backup, &verification_key).unwrap();
    let mut bytes = vec![0; usize::from(object.reference().total_length)];
    object.encode_into(&mut bytes).unwrap();
    f.flash.install_public_object(f.layout.object_offset(1).unwrap(), &bytes);
    let state = f.durable.state().unwrap();
    let policy = state.generation_policy();
    let generation_state = KESGeneration::new_staged(GenerationSpec {
        generation_id: generation, generation_number: GenerationNumber::new(2),
        creation_request: RequestId::from_bytes([0x73; 16]), creation_payload_digest: [0x74; 32],
        pool: state.pool_id(), incarnation: state.incarnation(), verification_key, lifetime,
        recipient_id: *policy.recipient_id(), public_object: object,
    }, key).unwrap();
    f.durable.stage_generation(&f.journal, &mut f.flash, &mut f.entropy, &mut f.buffers.work(),
        StageGenerationRequest { actor: f.actor, expected_revision: Revision::new(3),
            generation: generation_state, policy }).unwrap();
    let certificate = support::certificate(&f.cold, &verification_key, 1, 110);
    let certificate_digest = Sha256::digest(&certificate).into();
    f.durable.certify(&f.journal, &mut f.flash, &mut f.entropy, &mut f.buffers.work(),
        CertificationRequest { actor: f.actor, expected_revision: Revision::new(4),
            generation, canonical_certificate: &certificate, network: &f.network }).unwrap();
    f.durable.schedule(&f.journal, &mut f.flash, &mut f.entropy, &mut f.buffers.work(),
        ScheduleRequest { actor: f.actor, expected_revision: Revision::new(5),
            expected_active_generation: f.generation, generation, certificate_digest,
            activation_absolute_period: AbsolutePeriod::new(112), creation_request: REQUEST }).unwrap();
    generation
}

fn wire(f: &Fixture, period: u64, revision: Revision, wrong_network: bool) -> Vec<u8> {
    let state = f.durable.state().unwrap();
    let mut bytes = [0; MAX_FRAME_BYTES];
    let mut e = Encoder::new(&mut bytes);
    e.map(11).unwrap();
    e.text("op").unwrap(); e.text("OBSERVE_PERIOD").unwrap();
    e.text("mac").unwrap(); e.bytes(&[0; 32]).unwrap();
    e.text("seq").unwrap(); e.uint(1).unwrap();
    e.text("pool").unwrap(); e.bytes(state.pool_id().as_bytes()).unwrap();
    e.text("device").unwrap(); e.bytes(&[0x19; 16]).unwrap();
    e.text("payload").unwrap(); e.map(3).unwrap();
    e.text("network").unwrap(); e.map(4).unwrap();
    e.text("network_magic").unwrap(); e.uint(if wrong_network { 43 } else { 42 }).unwrap();
    e.text("max_kes_evolutions").unwrap(); e.uint(64).unwrap();
    e.text("slots_per_kes_period").unwrap(); e.uint(f.network.slots_per_kes_period()).unwrap();
    e.text("shelley_genesis_digest").unwrap(); e.bytes(f.network.genesis_hash().as_bytes()).unwrap();
    e.text("absolute_period").unwrap(); e.uint(period).unwrap();
    e.text("expected_revision").unwrap(); e.uint(revision.get()).unwrap();
    e.text("request").unwrap(); e.bytes(REQUEST.as_bytes()).unwrap();
    e.text("session").unwrap(); e.bytes(&[0x38; 16]).unwrap();
    e.text("version").unwrap(); e.uint(1).unwrap();
    e.text("budget_ms").unwrap(); e.uint(500).unwrap();
    e.text("incarnation").unwrap(); e.bytes(state.incarnation().as_bytes()).unwrap();
    e.finish().unwrap().encoded().to_vec()
}

fn execute(f: &mut Fixture, bytes: &[u8], wrong_scope: bool) -> Result<Outcome, usb::CommandError> {
    let recovered = f.journal.recover(&mut f.flash, &mut f.entropy, &mut f.buffers.work()).unwrap();
    let authority = PoolAuthority::from_recovered(DirectoryEntry::new(HardwareSlot::new(0).unwrap(),
        recovered.state.pool_id(), recovered.state.incarnation()), &recovered).unwrap();
    f.durable = DurablePool::from_recovered(recovered);
    let request = Envelope::parse(bytes, EnvelopeKind::DeviceRequest).unwrap();
    let authenticated = AuthenticatedRequest {
        scope: if wrong_scope { Scope::Management } else { authority.scope() },
        operation: request.operation.as_str(), request: REQUEST, sequence: 1,
    };
    pool_observe::execute(request, authenticated, authority, &mut f.durable,
        &f.journal, &mut f.flash, f.layout, &mut f.entropy, &mut f.buffers.work(),
        &mut [0; 6144], &mut PublicTreeBuffer::new())
}

#[test]
fn scheduled_rotation_uses_target_tree_only_when_eligible_and_cleans_before_ack() {
    let mut f = active();
    let replacement = scheduled(&mut f);
    let bytes = wire(&f, 111, Revision::new(6), false);
    let pending = execute(&mut f, &bytes, false).unwrap();
    assert_eq!(pending.status(), Status::Ok);
    assert_eq!(pending.context.generation, f.generation);
    assert_eq!(pending.context.relative_period.get(), 0);
    assert!(!pending.committed_write);
    assert!(f.durable.activation_intent().is_some());
    let bytes = wire(&f, 112, Revision::new(6), false);
    let activated = execute(&mut f, &bytes, false).unwrap();
    assert_eq!(activated.status(), Status::Ok);
    assert_eq!(activated.context.generation, replacement);
    assert_eq!(activated.context.relative_period.get(), 2);
    assert!(activated.committed_write);
    let recovered = f.journal.recover(&mut f.flash, &mut f.entropy, &mut f.buffers.work()).unwrap();
    assert_eq!(recovered.state.revision(), activated.context.revision);
    assert_eq!(recovered.state.current().unwrap().id(), replacement);
    assert!(recovered.state.staged().is_none());
    assert!(recovered.state.activation_intent().is_none());
    let bytes = wire(&f, 113, activated.context.revision, false);
    let advanced = execute(&mut f, &bytes, false).unwrap();
    assert_eq!(advanced.context.generation, replacement);
    assert_eq!(advanced.context.relative_period.get(), 3);
    assert!(advanced.committed_write);
    let bytes = wire(&f, 113, advanced.context.revision, false);
    let repeated = execute(&mut f, &bytes, false).unwrap();
    assert_eq!(repeated.context, advanced.context);
    assert!(!repeated.committed_write);
    let bytes = wire(&f, 112, repeated.context.revision, false);
    assert_eq!(execute(&mut f, &bytes, false).err().unwrap().status, Status::StalePeriod);
    assert_eq!(f.durable.state().unwrap().revision(), repeated.context.revision);
}

#[test]
fn wrong_network_revision_and_session_scope_do_not_change_scheduled_state() {
    let mut f = active();
    scheduled(&mut f);
    let revision = f.durable.state().unwrap().revision();
    for (wrong_network, expected, wrong_scope, status) in [
        (true, revision, false, Status::WrongNetwork),
        (false, Revision::new(5), false, Status::RevisionConflict),
        (false, revision, true, Status::AuthFailed),
    ] {
        let bytes = wire(&f, 112, expected, wrong_network);
        assert_eq!(execute(&mut f, &bytes, wrong_scope).err().unwrap().status, status);
        assert_eq!(f.durable.state().unwrap().revision(), revision);
        assert_eq!(f.durable.state().unwrap().current().unwrap().id(), f.generation);
        assert!(f.durable.activation_intent().is_some());
    }
}

#[test]
fn no_active_generation_is_not_a_successful_empty_descriptor() {
    let mut f = Fixture::new();
    let revision = f.durable.state().unwrap().revision();
    let bytes = wire(&f, 100, revision, false);
    assert_eq!(execute(&mut f, &bytes, false).err().unwrap().status, Status::StaleGeneration);
    assert_eq!(f.durable.state().unwrap().revision(), revision);
}

#[test]
fn expiry_is_durable_and_repeat_returns_context_without_another_write() {
    let mut f = active();
    let revision = f.durable.state().unwrap().revision();
    let bytes = wire(&f, 164, revision, false);
    let expired = execute(&mut f, &bytes, false).unwrap();
    assert_eq!(expired.status(), Status::Expired);
    assert!(expired.committed_write);
    assert_eq!(expired.context.lifecycle, Lifecycle::CurrentExpired);
    let recovered = f.journal.recover(&mut f.flash, &mut f.entropy, &mut f.buffers.work()).unwrap();
    assert_eq!(recovered.state.revision(), expired.context.revision);
    assert!(recovered.state.current().unwrap().is_secret_erased());
    let bytes = wire(&f, 165, expired.context.revision, false);
    let repeated = execute(&mut f, &bytes, false).unwrap();
    assert_eq!(repeated.status(), Status::Expired);
    assert!(!repeated.committed_write);
    assert_eq!(repeated.context, expired.context);
}

#[test]
fn expired_replacement_does_not_claim_active_expiry_or_commit_rotation() {
    let mut f = active();
    scheduled(&mut f);
    let revision = f.durable.state().unwrap().revision();
    let bytes = wire(&f, 174, revision, false);
    assert_eq!(execute(&mut f, &bytes, false).err().unwrap().status, Status::CertificateInvalid);
    assert_eq!(f.durable.state().unwrap().revision(), revision);
    assert_eq!(f.durable.state().unwrap().current().unwrap().id(), f.generation);
    assert!(f.durable.activation_intent().is_some());
}

#[test]
fn failed_observation_commit_invalidates_owner_without_public_success() {
    let mut f = active();
    let revision = f.durable.state().unwrap().revision();
    let bytes = wire(&f, 102, revision, false);
    f.flash.fail_next_mutation();
    assert!(execute(&mut f, &bytes, false).is_err());
    assert!(f.durable.state().is_err());
}
