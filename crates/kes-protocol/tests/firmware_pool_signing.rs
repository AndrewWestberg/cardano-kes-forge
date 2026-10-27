//! Execution-layer regressions. Authentication/MAC routing is tested separately;
//! these tests supply its public AuthenticatedRequest output explicitly.
#[allow(dead_code)]
#[path = "../../../firmware/src/security/gateway.rs"]
mod gateway_impl;
#[allow(dead_code)]
#[path = "../../kes-core/tests/support/mod.rs"]
mod support;
mod security {
    pub mod gateway {
        pub use crate::gateway_impl::*;
    }
}
#[allow(dead_code)]
#[path = "../../../firmware/src/pool_service.rs"]
mod pool_service;
#[allow(dead_code)]
#[path = "../../../firmware/src/development/pool_sessions.rs"]
mod pool_sessions;
#[allow(dead_code)]
#[path = "../../../firmware/src/development/pool_signing.rs"]
mod pool_signing;
#[allow(dead_code)]
#[path = "../../../firmware/src/scheduler.rs"]
mod scheduler;
#[allow(dead_code)]
#[path = "../../../firmware/src/usb.rs"]
mod usb;

use kes_core::{
    activation::{ActivationRequest, CertificationRequest},
    cbor::Encoder,
    crypto::{PublicTreeBuffer, verify},
    session::{AuthenticatedRequest, Scope},
    state::{DirectoryEntry, Lifecycle},
    types::{AbsolutePeriod, HardwareSlot, RequestId},
};
use kes_protocol::{Envelope, EnvelopeKind, MAX_FRAME_BYTES, Operation, Status};
use pool_sessions::PoolAuthority;
use pool_signing::Outcome;
use support::Fixture;

const REQUEST: RequestId = RequestId::from_bytes([0x27; 16]);

fn active() -> Fixture {
    let mut f = Fixture::new();
    let revision = f.durable.state().unwrap().revision();
    f.durable
        .certify(
            &f.journal,
            &mut f.flash,
            &mut f.entropy,
            &mut f.buffers.work(),
            CertificationRequest {
                actor: f.actor,
                expected_revision: revision,
                generation: f.generation,
                canonical_certificate: &f.certificate,
                network: &f.network,
            },
        )
        .unwrap();
    let revision = f.durable.state().unwrap().revision();
    let key = *f
        .durable
        .state()
        .unwrap()
        .staged()
        .unwrap()
        .verification_key();
    let tree = f.tree.verify(&key).unwrap();
    f.durable
        .activate_first(
            &f.journal,
            &mut f.flash,
            &mut f.entropy,
            &mut f.buffers.work(),
            ActivationRequest {
                actor: f.actor,
                expected_revision: revision,
                expected_active_generation: None,
                generation: f.generation,
                certificate_digest: f.certificate_digest,
                current_absolute_period: AbsolutePeriod::new(100),
            },
            &tree,
        )
        .unwrap();
    f
}

fn authority(f: &mut Fixture) -> PoolAuthority {
    let recovered = f
        .journal
        .recover(&mut f.flash, &mut f.entropy, &mut f.buffers.work())
        .unwrap();
    PoolAuthority::from_recovered(
        DirectoryEntry::new(
            HardwareSlot::new(0).unwrap(),
            recovered.state.pool_id(),
            recovered.state.incarnation(),
        ),
        &recovered,
    )
    .unwrap()
}

fn wire(
    f: &Fixture,
    operation: Operation,
    period: u64,
    message: &[u8],
    wrong_network: bool,
) -> Vec<u8> {
    let pool = f.durable.state().unwrap();
    let mut bytes = [0; MAX_FRAME_BYTES];
    let mut e = Encoder::new(&mut bytes);
    e.map(11).unwrap();
    e.text("op").unwrap();
    e.text(operation.as_str()).unwrap();
    e.text("mac").unwrap();
    e.bytes(&[0; 32]).unwrap();
    e.text("seq").unwrap();
    e.uint(1).unwrap();
    e.text("pool").unwrap();
    e.bytes(pool.pool_id().as_bytes()).unwrap();
    e.text("device").unwrap();
    e.bytes(&[0x19; 16]).unwrap();
    e.text("payload").unwrap();
    e.map(5).unwrap();
    if operation == Operation::Sign {
        e.text("message").unwrap();
        e.bytes(message).unwrap();
    }
    e.text("network").unwrap();
    e.map(4).unwrap();
    e.text("network_magic").unwrap();
    e.uint(if wrong_network { 43 } else { 42 }).unwrap();
    e.text("max_kes_evolutions").unwrap();
    e.uint(64).unwrap();
    e.text("slots_per_kes_period").unwrap();
    e.uint(f.network.slots_per_kes_period()).unwrap();
    e.text("shelley_genesis_digest").unwrap();
    e.bytes(f.network.genesis_hash().as_bytes()).unwrap();
    e.text("generation").unwrap();
    e.bytes(f.generation.as_bytes()).unwrap();
    if operation == Operation::Sign {
        e.text("absolute_period").unwrap();
        e.uint(period).unwrap();
    } else {
        e.text("expected_revision").unwrap();
        e.uint(pool.revision().get()).unwrap();
    }
    e.text("certificate_digest").unwrap();
    e.bytes(&f.certificate_digest).unwrap();
    if operation == Operation::Evolve {
        e.text("target_absolute_period").unwrap();
        e.uint(period).unwrap();
    }
    e.text("request").unwrap();
    e.bytes(REQUEST.as_bytes()).unwrap();
    e.text("session").unwrap();
    e.bytes(&[0x28; 16]).unwrap();
    e.text("version").unwrap();
    e.uint(1).unwrap();
    e.text("budget_ms").unwrap();
    e.uint(500).unwrap();
    e.text("incarnation").unwrap();
    e.bytes(pool.incarnation().as_bytes()).unwrap();
    e.finish().unwrap().encoded().to_vec()
}

fn execute(f: &mut Fixture, bytes: &[u8], wrong_scope: bool) -> Result<Outcome, usb::CommandError> {
    let authority = authority(f);
    let request = Envelope::parse(bytes, EnvelopeKind::DeviceRequest).unwrap();
    let authenticated = AuthenticatedRequest {
        scope: if wrong_scope {
            Scope::Management
        } else {
            authority.scope()
        },
        operation: request.operation.as_str(),
        request: REQUEST,
        sequence: 1,
    };
    pool_signing::execute(
        request,
        authenticated,
        authority,
        &mut f.durable,
        &f.journal,
        &mut f.flash,
        f.layout,
        &mut f.entropy,
        &mut f.buffers.work(),
        &mut [0; 6144],
        &mut PublicTreeBuffer::new(),
    )
}

#[test]
fn exact_message_signing_and_evolution_are_committed_before_success() {
    let mut f = active();
    let message = [0xab; 4096];
    let bytes = wire(&f, Operation::Sign, 102, &message, false);
    let Outcome::Signed(result) = execute(&mut f, &bytes, false).unwrap() else {
        panic!("signature");
    };
    let current = f.durable.state().unwrap().current().unwrap();
    verify(
        current.verification_key(),
        result.context.relative_period,
        current.lifetime(),
        &message,
        &result.signature,
    )
    .unwrap();
    assert!(
        verify(
            current.verification_key(),
            result.context.relative_period,
            current.lifetime(),
            b"different",
            &result.signature
        )
        .is_err()
    );
    let recovered = f
        .journal
        .recover(&mut f.flash, &mut f.entropy, &mut f.buffers.work())
        .unwrap();
    assert_eq!(recovered.state.revision(), result.context.revision);
    assert_eq!(
        recovered.state.current().unwrap().relative_period().get(),
        2
    );
    let bytes = wire(&f, Operation::Evolve, 103, &[], false);
    let Outcome::Evolved(context) = execute(&mut f, &bytes, false).unwrap() else {
        panic!("evolution");
    };
    assert_eq!(context.relative_period.get(), 3);
}

#[test]
fn expiry_returns_committed_public_context_on_initial_and_repeated_operations() {
    let mut f = active();
    for operation in [Operation::Sign, Operation::Evolve, Operation::Sign] {
        let bytes = wire(&f, operation, 164, b"must not sign", false);
        let result = execute(&mut f, &bytes, false).unwrap();
        assert_eq!(result.status(), Status::Expired);
        assert_eq!(result.context().lifecycle, Lifecycle::CurrentExpired);
        let recovered = f
            .journal
            .recover(&mut f.flash, &mut f.entropy, &mut f.buffers.work())
            .unwrap();
        assert_eq!(result.context().revision, recovered.state.revision());
        assert!(recovered.state.current().unwrap().is_secret_erased());
    }
}

#[test]
fn mismatched_network_scope_and_damaged_object_never_sign_or_mutate() {
    let mut f = active();
    let revision = f.durable.state().unwrap().revision();
    let bytes = wire(&f, Operation::Sign, 102, b"exact", true);
    assert_eq!(
        execute(&mut f, &bytes, false).err().unwrap().status,
        Status::WrongNetwork
    );
    let bytes = wire(&f, Operation::Sign, 102, b"exact", false);
    assert_eq!(
        execute(&mut f, &bytes, true).err().unwrap().status,
        Status::AuthFailed
    );
    let offset = f.layout.object_offset(0).unwrap();
    f.flash.install_public_object(offset, b"BROKEN!!");
    // The router re-recovers before every operation, so object authentication
    // rejects the damaged slot before a signing owner can be dispatched.
    assert!(matches!(
        f.journal
            .recover(&mut f.flash, &mut f.entropy, &mut f.buffers.work()),
        Err(kes_core::journal::JournalError::Damaged)
    ));
    assert_eq!(f.durable.state().unwrap().revision(), revision);
}

#[test]
fn failed_durable_evolution_never_returns_signature_and_invalidates_owner() {
    let mut f = active();
    let bytes = wire(&f, Operation::Sign, 102, b"exact", false);
    f.flash.fail_next_mutation();
    assert!(execute(&mut f, &bytes, false).is_err());
    assert!(f.durable.state().is_err());
}
