//! Real HPKE/session-MAC protocol regressions over isolated NOR journal fixtures.

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
#[allow(dead_code, unused_imports, unexpected_cfgs)]
#[path = "../../../firmware/src/development.rs"]
mod development;
#[allow(dead_code)]
#[path = "../../../firmware/src/pool_service.rs"]
mod pool_service;
#[allow(dead_code)]
#[path = "../../../firmware/src/scheduler.rs"]
mod scheduler;
#[allow(dead_code)]
#[path = "../../../firmware/src/usb.rs"]
mod usb;

use development::{DevelopmentEvidence, DevelopmentHandler, pool_sessions::PoolAuthority};
use kes_core::{
    activation::DurablePool,
    cbor::Encoder,
    crypto::KesKey,
    generation::{self, Admission, GenerationRequest},
    journal::{Flash, Recovered},
    session::{
        DeviceHpkeKey, DeviceIdentityKey, HostSession, OpenContext, OpenRequest, Scope, begin_open,
    },
    state::{Actor, DirectoryEntry, Enrollment, PoolRegistration},
    types::{DeviceId, GenerationNumber, HardwareSlot, KesLifetime, ManagementSequence, RequestId},
};
use kes_protocol::{Envelope, EnvelopeKind, MAX_FRAME_BYTES, Operation, Status};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use scheduler::Scheduler;
use sha2::{Digest, Sha256};
use support::Fixture;
use zeroize::Zeroizing;

const DEVICE: DeviceId = DeviceId::from_bytes([0x19; 16]);
const NONCE: [u8; 32] = [0x41; 32];
const TARGET: RequestId = RequestId::from_bytes([0x42; 16]);

fn setup() -> (Fixture, DurablePool, DevelopmentHandler) {
    let mut f = Fixture::new();
    let previous = f.durable.state().unwrap();
    let pool = PoolRegistration::new(
        Actor::Management,
        Enrollment {
            incarnation: previous.incarnation(),
            cold_verification_key: *previous.cold_verification_key(),
            network: f.network,
            machine_public_key: f.cold.verifying_key().to_bytes(),
            recipient_public_key: *previous.recipient_public_key(),
            recipient_id: *previous.recipient_id(),
            management_sequence: ManagementSequence::new(1),
            management_request: TARGET,
            management_payload_digest: [0x43; 32],
        },
    )
    .unwrap();
    for offset in (0..32768).step_by(4096) {
        f.flash.erase_sector(offset).unwrap();
    }
    f.journal
        .initialize(&mut f.flash, &mut f.entropy, &pool, &mut f.buffers.work())
        .unwrap();
    let recovered = f
        .journal
        .recover(&mut f.flash, &mut f.entropy, &mut f.buffers.work())
        .unwrap();
    let owner = DurablePool::from_recovered(recovered);
    let handler = DevelopmentHandler::new(
        DEVICE,
        DeviceIdentityKey::from_seed(Zeroizing::new([0x44; 32])),
        DeviceHpkeKey::from_seed(Zeroizing::new([0x45; 32])),
        NONCE,
        f.cold.verifying_key().to_bytes(),
        ChaCha20Rng::from_seed([0x46; 32]),
        DevelopmentEvidence {
            firmware_digest: [0; 32],
            hardware_policy_digest: [0; 32],
            security_version: 0,
            capability_evidence: b"pool retrieval regression",
        },
    );
    (f, owner, handler)
}

fn recover(f: &mut Fixture) -> Recovered<PoolRegistration> {
    f.journal
        .recover(&mut f.flash, &mut f.entropy, &mut f.buffers.work())
        .unwrap()
}
fn authority(recovered: &Recovered<PoolRegistration>) -> PoolAuthority {
    PoolAuthority::from_recovered(
        DirectoryEntry::new(
            HardwareSlot::new(0).unwrap(),
            recovered.state.pool_id(),
            recovered.state.incarnation(),
        ),
        recovered,
    )
    .unwrap()
}
fn lease(operation: Operation) -> scheduler::RequestLease {
    Scheduler::new().admit(operation, 500, 100).unwrap()
}
fn open_wire(open: &OpenRequest) -> Vec<u8> {
    let Scope::Pool { pool, incarnation } = open.context.scope else {
        panic!("pool");
    };
    let mut bytes = [0; MAX_FRAME_BYTES];
    let mut e = Encoder::new(&mut bytes);
    e.map(7).unwrap();
    e.text("op").unwrap();
    e.text("OPEN").unwrap();
    e.text("pool").unwrap();
    e.bytes(pool.as_bytes()).unwrap();
    e.text("device").unwrap();
    e.bytes(DEVICE.as_bytes()).unwrap();
    e.text("payload").unwrap();
    e.map(6).unwrap();
    e.text("signature").unwrap();
    e.bytes(&open.signature).unwrap();
    e.text("boot_nonce").unwrap();
    e.bytes(&NONCE).unwrap();
    e.text("ciphertext").unwrap();
    e.bytes(&open.ciphertext).unwrap();
    e.text("open_counter").unwrap();
    e.uint(open.context.open_counter).unwrap();
    e.text("encapsulation").unwrap();
    e.bytes(&open.encapsulation).unwrap();
    e.text("credential_epoch").unwrap();
    e.uint(open.context.credential_epoch.get()).unwrap();
    e.text("request").unwrap();
    e.bytes(open.context.request.as_bytes()).unwrap();
    e.text("version").unwrap();
    e.uint(1).unwrap();
    e.text("incarnation").unwrap();
    e.bytes(incarnation.as_bytes()).unwrap();
    e.finish().unwrap().encoded().to_vec()
}
fn connect(f: &mut Fixture, handler: &mut DevelopmentHandler) -> HostSession {
    let recovered = recover(f);
    let a = authority(&recovered);
    let context = OpenContext::new(
        DEVICE,
        NONCE,
        a.scope(),
        recovered.state.credential_epoch(),
        0,
        RequestId::from_bytes([0x47; 16]),
    );
    let (open, pending) = begin_open(
        context,
        &DeviceHpkeKey::from_seed(Zeroizing::new([0x45; 32])).public_key(),
        &f.cold,
        &mut ChaCha20Rng::from_seed([0x48; 32]),
    )
    .unwrap();
    let wire = open_wire(&open);
    let mut response = [0; MAX_FRAME_BYTES];
    let result = handler
        .handle_pool_open(
            Envelope::parse(&wire, EnvelopeKind::OpenRequest).unwrap(),
            &mut response,
            lease(Operation::Open),
            a,
        )
        .unwrap();
    pending
        .complete(
            Envelope::parse(
                &response[..result.response_length],
                EnvelopeKind::OpenResponse,
            )
            .unwrap()
            .map(),
        )
        .unwrap()
}

fn request(
    host: &mut HostSession,
    scope: Scope,
    operation: Operation,
    sequence: u64,
    target: &[u8; 16],
    number: Option<u64>,
) -> Vec<u8> {
    let Scope::Pool { pool, incarnation } = scope else {
        panic!("pool");
    };
    let session = *host.session_id();
    let encode = |mac: [u8; 32]| {
        let mut bytes = [0; MAX_FRAME_BYTES];
        let mut e = Encoder::new(&mut bytes);
        e.map(11).unwrap();
        e.text("op").unwrap();
        e.text(operation.as_str()).unwrap();
        e.text("mac").unwrap();
        e.bytes(&mac).unwrap();
        e.text("seq").unwrap();
        e.uint(sequence).unwrap();
        e.text("pool").unwrap();
        e.bytes(pool.as_bytes()).unwrap();
        e.text("device").unwrap();
        e.bytes(DEVICE.as_bytes()).unwrap();
        e.text("payload").unwrap();
        e.map(if number.is_some() { 2 } else { 1 }).unwrap();
        e.text(if operation == Operation::GetBackup {
            "generation"
        } else {
            "request"
        })
        .unwrap();
        e.bytes(target).unwrap();
        if let Some(n) = number {
            e.text("generation_number").unwrap();
            e.uint(n).unwrap();
        }
        e.text("request").unwrap();
        e.bytes(&[sequence as u8 + 0x50; 16]).unwrap();
        e.text("session").unwrap();
        e.bytes(&session).unwrap();
        e.text("version").unwrap();
        e.uint(1).unwrap();
        e.text("budget_ms").unwrap();
        e.uint(500).unwrap();
        e.text("incarnation").unwrap();
        e.bytes(incarnation.as_bytes()).unwrap();
        e.finish().unwrap().encoded().to_vec()
    };
    let unsigned = encode([0; 32]);
    let mac = host
        .request_mac(
            Envelope::parse(&unsigned, EnvelopeKind::DeviceRequest)
                .unwrap()
                .map(),
        )
        .unwrap();
    encode(mac)
}
fn status(
    f: &mut Fixture,
    handler: &mut DevelopmentHandler,
    host: &mut HostSession,
    sequence: u64,
    target: RequestId,
    number: Option<u64>,
) -> Vec<u8> {
    let recovered = recover(f);
    let a = authority(&recovered);
    let wire = request(
        host,
        a.scope(),
        Operation::OpStatus,
        sequence,
        target.as_bytes(),
        number,
    );
    let mut response = [0; MAX_FRAME_BYTES];
    let result = handler
        .handle_pool_operation_status(
            Envelope::parse(&wire, EnvelopeKind::DeviceRequest).unwrap(),
            &mut response,
            lease(Operation::OpStatus),
            a,
            &recovered.state,
        )
        .unwrap();
    let bytes = response[..result.response_length].to_vec();
    let envelope = Envelope::parse(&bytes, EnvelopeKind::DeviceResponse).unwrap();
    host.authenticate_response(
        envelope.map(),
        RequestId::from_bytes([sequence as u8 + 0x50; 16]),
        "OP_STATUS",
        sequence,
    )
    .unwrap();
    bytes
}
fn assert_status(bytes: &[u8], expected: &str) {
    let envelope = Envelope::parse(bytes, EnvelopeKind::DeviceResponse).unwrap();
    assert_eq!(
        envelope.map().required("status").unwrap().text().unwrap(),
        expected
    );
}
fn admit(f: &mut Fixture, owner: &mut DurablePool) -> kes_core::generation::GenerationOperation {
    let state = owner.state().unwrap();
    let request = GenerationRequest {
        actor: Actor::Pool {
            pool: state.pool_id(),
            incarnation: state.incarnation(),
        },
        request: TARGET,
        payload_digest: [0x48; 32],
        next_generation_number: GenerationNumber::new(1),
        expected_revision: state.revision(),
    };
    let Admission::Started(operation) = owner
        .admit_generation(
            request,
            &f.journal,
            &mut f.flash,
            &mut f.entropy,
            &mut f.buffers.work(),
        )
        .unwrap()
    else {
        panic!("new admission");
    };
    operation
}

#[test]
fn reconciliation_preserves_unknown_and_requires_durable_abort_for_not_committed() {
    let (mut f, mut owner, mut handler) = setup();
    let mut host = connect(&mut f, &mut handler);
    assert_status(
        &status(&mut f, &mut handler, &mut host, 0, TARGET, None),
        "UNKNOWN",
    );
    let operation = admit(&mut f, &mut owner);
    assert_status(
        &status(&mut f, &mut handler, &mut host, 1, TARGET, Some(1)),
        "IN_PROGRESS",
    );
    assert_status(
        &status(&mut f, &mut handler, &mut host, 2, TARGET, Some(2)),
        "UNKNOWN",
    );
    let mut key = KesKey::erased(KesLifetime::new(64).unwrap());
    owner
        .cancel_generation(
            operation,
            &mut key,
            &f.journal,
            &mut f.flash,
            &mut f.entropy,
            &mut f.buffers.work(),
        )
        .unwrap();
    assert_status(
        &status(&mut f, &mut handler, &mut host, 3, TARGET, Some(1)),
        "NOT_COMMITTED",
    );
    assert_status(
        &status(
            &mut f,
            &mut handler,
            &mut host,
            4,
            RequestId::from_bytes([0x99; 16]),
            Some(1),
        ),
        "UNKNOWN",
    );
}

#[test]
fn committed_backup_is_exact_immutable_authenticated_and_missing_generation_is_refused() {
    let (mut f, mut owner, mut handler) = setup();
    let mut host = connect(&mut f, &mut handler);
    let operation = admit(&mut f, &mut owner);
    let mut job =
        generation::begin_key_generation(&mut f.entropy, KesLifetime::new(64).unwrap()).unwrap();
    for _ in 0..64 {
        job.step().unwrap();
    }
    let (key, tree) = job.finish().unwrap();
    let verified = tree.verify(&key.verification_key().unwrap()).unwrap();
    let identity = DeviceIdentityKey::from_seed(Zeroizing::new([0x44; 32]));
    let mut write = [0; 6144];
    let mut read = [0; 6144];
    let descriptor = owner
        .complete_generation(
            &f.journal,
            &mut f.flash,
            &mut f.entropy,
            &mut f.buffers.work(),
            |flash, rng, pool, coordinator| {
                let mut store =
                    pool_service::FlashPublicObjects::new(flash, f.layout, pool).unwrap();
                coordinator.complete(
                    pool, operation, key, &verified, DEVICE, &identity, rng, &mut store,
                    &mut write, &mut read,
                )
            },
        )
        .unwrap();
    let committed = status(&mut f, &mut handler, &mut host, 0, TARGET, Some(1));
    assert_status(&committed, "OK");
    let payload = Envelope::parse(&committed, EnvelopeKind::DeviceResponse)
        .unwrap()
        .payload();
    assert_eq!(
        payload
            .required("verification_key")
            .unwrap()
            .bytes()
            .unwrap(),
        descriptor.verification_key
    );
    let recovered = recover(&mut f);
    let a = authority(&recovered);
    let mut store =
        pool_service::FlashPublicObjects::new(&mut f.flash, f.layout, &recovered.state).unwrap();
    let expected = generation::get_backup(
        &recovered.state,
        descriptor.generation,
        &mut store,
        &mut read,
    )
    .unwrap()
    .bytes
    .to_vec();
    for seq in 1..=2 {
        let wire = request(
            &mut host,
            a.scope(),
            Operation::GetBackup,
            seq,
            descriptor.generation.as_bytes(),
            None,
        );
        let mut response = [0; MAX_FRAME_BYTES];
        let result = handler
            .handle_pool_get_backup(
                Envelope::parse(&wire, EnvelopeKind::DeviceRequest).unwrap(),
                &mut response,
                lease(Operation::GetBackup),
                a,
                &recovered.state,
                &mut store,
                &mut read,
            )
            .unwrap();
        let envelope = Envelope::parse(
            &response[..result.response_length],
            EnvelopeKind::DeviceResponse,
        )
        .unwrap();
        host.authenticate_response(
            envelope.map(),
            RequestId::from_bytes([seq as u8 + 0x50; 16]),
            "GET_BACKUP",
            seq,
        )
        .unwrap();
        assert_eq!(
            envelope
                .payload()
                .required("backup")
                .unwrap()
                .bytes()
                .unwrap(),
            expected
        );
        assert_eq!(
            envelope
                .payload()
                .required("artifact_digest")
                .unwrap()
                .bytes()
                .unwrap(),
            Sha256::digest(&expected).as_slice()
        );
    }
    let missing = request(
        &mut host,
        a.scope(),
        Operation::GetBackup,
        3,
        &[0xfe; 16],
        None,
    );
    let mut response = [0; MAX_FRAME_BYTES];
    let result = handler
        .handle_pool_get_backup(
            Envelope::parse(&missing, EnvelopeKind::DeviceRequest).unwrap(),
            &mut response,
            lease(Operation::GetBackup),
            a,
            &recovered.state,
            &mut store,
            &mut read,
        )
        .unwrap();
    let rejected = Envelope::parse(
        &response[..result.response_length],
        EnvelopeKind::DeviceResponse,
    )
    .unwrap();
    host.authenticate_response(
        rejected.map(),
        RequestId::from_bytes([0x53; 16]),
        "GET_BACKUP",
        3,
    )
    .unwrap();
    assert_eq!(rejected.status, Some(Status::StaleGeneration));
    drop(store);
    let mut recovered = recover(&mut f);
    let signed = management_change(
        &f,
        &recovered.state,
        kes_core::management::Action::StagedDiscard,
        |e| {
            e.map(1).unwrap();
            e.text("generation").unwrap();
            e.bytes(descriptor.generation.as_bytes()).unwrap();
        },
    );
    let verified =
        kes_core::management::parse_and_verify(&signed, DEVICE, &f.cold.verifying_key().to_bytes())
            .unwrap();
    kes_core::credentials::discard_staged(&mut recovered.state, &verified).unwrap();
    f.journal
        .transact_successor(
            &mut f.flash,
            &mut f.entropy,
            &recovered.token,
            &recovered.state,
            &mut f.buffers.work(),
        )
        .unwrap();
    assert_status(
        &status(&mut f, &mut handler, &mut host, 4, TARGET, Some(1)),
        "RESULT_RECLAIMED",
    );
}

#[test]
fn pool_status_rejects_replayed_or_corrupted_mac_and_cross_pool_authority() {
    for attack in 0..3 {
        let (mut f, _, mut handler) = setup();
        let mut host = connect(&mut f, &mut handler);
        let recovered = recover(&mut f);
        let a = authority(&recovered);
        let mut wire = request(
            &mut host,
            a.scope(),
            Operation::OpStatus,
            0,
            TARGET.as_bytes(),
            Some(1),
        );
        let mut response = [0; MAX_FRAME_BYTES];
        match attack {
            0 => {
                let envelope = Envelope::parse(&wire, EnvelopeKind::DeviceRequest).unwrap();
                handler
                    .handle_pool_operation_status(
                        envelope,
                        &mut response,
                        lease(Operation::OpStatus),
                        a,
                        &recovered.state,
                    )
                    .unwrap();
                assert_eq!(
                    handler
                        .handle_pool_operation_status(
                            envelope,
                            &mut response,
                            lease(Operation::OpStatus),
                            a,
                            &recovered.state
                        )
                        .unwrap_err()
                        .status,
                    Status::Replay
                );
            }
            1 => {
                let mac = Envelope::parse(&wire, EnvelopeKind::DeviceRequest)
                    .unwrap()
                    .map()
                    .required("mac")
                    .unwrap()
                    .bytes()
                    .unwrap();
                let offset = mac.as_ptr() as usize - wire.as_ptr() as usize;
                wire[offset] ^= 1;
                assert_eq!(
                    handler
                        .handle_pool_operation_status(
                            Envelope::parse(&wire, EnvelopeKind::DeviceRequest).unwrap(),
                            &mut response,
                            lease(Operation::OpStatus),
                            a,
                            &recovered.state
                        )
                        .unwrap_err()
                        .status,
                    Status::AuthFailed
                );
            }
            _ => {
                let (mut other, _, _) = setup();
                let wrong_pool = recover(&mut other);
                assert_eq!(
                    handler
                        .handle_pool_operation_status(
                            Envelope::parse(&wire, EnvelopeKind::DeviceRequest).unwrap(),
                            &mut response,
                            lease(Operation::OpStatus),
                            a,
                            &wrong_pool.state
                        )
                        .unwrap_err()
                        .status,
                    Status::WrongPool
                );
            }
        }
    }
}

fn management_change(
    f: &Fixture,
    pool: &PoolRegistration,
    action: kes_core::management::Action,
    payload: impl FnOnce(&mut Encoder<'_>),
) -> Vec<u8> {
    use ed25519_dalek::Signer;
    use kes_core::{
        cbor::Value,
        management::{self, SigningFields, Target},
    };
    let mut bytes = [0; 1024];
    let mut e = Encoder::new(&mut bytes);
    payload(&mut e);
    let payload = e.finish().unwrap();
    let fields = SigningFields {
        device: DEVICE,
        target: Target::Pool {
            pool: pool.pool_id(),
            incarnation: pool.incarnation(),
        },
        sequence: ManagementSequence::new(pool.management_sequence().get() + 1),
        request: RequestId::from_bytes([0x72; 16]),
        expected_revision: pool.revision(),
        action,
        canonical_payload: Value::parse(payload.encoded()).unwrap(),
    };
    let mut transcript = [0; 4608];
    let length = management::encode_signing_message(fields, &mut transcript).unwrap();
    let signature = f.cold.sign(&transcript[..length]).to_bytes();
    let mut output = [0; 6144];
    let mut e = Encoder::new(&mut output);
    e.map(9).unwrap();
    e.text("pool").unwrap();
    e.bytes(pool.pool_id().as_bytes()).unwrap();
    e.text("action").unwrap();
    e.text(action.name()).unwrap();
    e.text("device").unwrap();
    e.bytes(DEVICE.as_bytes()).unwrap();
    e.text("request").unwrap();
    e.bytes(fields.request.as_bytes()).unwrap();
    e.text("signature").unwrap();
    e.bytes(&signature).unwrap();
    e.text("incarnation").unwrap();
    e.bytes(pool.incarnation().as_bytes()).unwrap();
    e.text("canonical_payload").unwrap();
    e.bytes(payload.encoded()).unwrap();
    e.text("expected_revision").unwrap();
    e.uint(pool.revision().get()).unwrap();
    e.text("management_sequence").unwrap();
    e.uint(fields.sequence.get()).unwrap();
    e.finish().unwrap().encoded().to_vec()
}

#[test]
fn freshly_recovered_epoch_rotation_and_revocation_reject_old_session() {
    use kes_core::management::Action;
    for action in [Action::CredentialReplace, Action::CredentialRevoke] {
        let (mut f, _, mut handler) = setup();
        let mut host = connect(&mut f, &mut handler);
        let mut recovered = recover(&mut f);
        let previous = authority(&recovered);
        let wire = request(
            &mut host,
            previous.scope(),
            Operation::OpStatus,
            0,
            TARGET.as_bytes(),
            None,
        );
        let signed = management_change(&f, &recovered.state, action, |e| {
            e.map(if action == Action::CredentialReplace {
                2
            } else {
                1
            })
            .unwrap();
            e.text("credential_epoch").unwrap();
            e.uint(1).unwrap();
            if action == Action::CredentialReplace {
                e.text("machine_public_key").unwrap();
                e.bytes(&f.cold.verifying_key().to_bytes()).unwrap();
            }
        });
        let verified = kes_core::management::parse_and_verify(
            &signed,
            DEVICE,
            &f.cold.verifying_key().to_bytes(),
        )
        .unwrap();
        kes_core::credentials::change_pool_credential(
            &mut recovered.state,
            &mut generation::GenerationCoordinator::new(),
            None,
            &verified,
        )
        .unwrap();
        f.journal
            .transact_successor(
                &mut f.flash,
                &mut f.entropy,
                &recovered.token,
                &recovered.state,
                &mut f.buffers.work(),
            )
            .unwrap();
        let recovered = recover(&mut f);
        let mut response = [0; MAX_FRAME_BYTES];
        assert_eq!(
            handler
                .handle_pool_operation_status(
                    Envelope::parse(&wire, EnvelopeKind::DeviceRequest).unwrap(),
                    &mut response,
                    lease(Operation::OpStatus),
                    authority(&recovered),
                    &recovered.state
                )
                .unwrap_err()
                .status,
            Status::AuthFailed
        );
    }
}
