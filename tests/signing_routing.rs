use cardano_kes_forge::host::latency;
use cardano_kes_forge::host::observation::{NetworkContext, State};
use cardano_kes_forge::host::signing::{Binding, Error, Router, Session};
use kes_core::cbor::Encoder;
use kes_core::crypto::{Generation, KesKey, PublicTreeBuffer};
use kes_core::types::{KesLifetime, RelativePeriod};
use kes_protocol::{Envelope, EnvelopeKind, Operation};
use sha2::{Digest, Sha256};
use std::time::Duration;

const CONNECTION: &str = "pool-0";
const GENERATION: [u8; 16] = [5; 16];
const CERTIFICATE: [u8; 32] = [6; 32];
const GENESIS: [u8; 32] = [4; 32];
const MESSAGE: &[u8] = b"exact native header bytes";

#[test]
fn sign_is_independently_verified_and_operational_observation_is_context_bound() {
    let lifetime = KesLifetime::new(64).unwrap();
    let mut key = KesKey::erased(lifetime);
    let mut tree = PublicTreeBuffer::new();
    let mut seed = [9; 32];
    let mut generation = Generation::begin(&mut seed, &mut key, &mut tree).unwrap();
    for _ in 0..64 {
        generation.step().unwrap();
    }
    let public_tree = generation.finish().unwrap();
    let verification_key = key.verification_key().unwrap();
    let session = Session {
        boot_nonce: [7; 32],
        session: [8; 16],
    };
    let mut router = Router::new([(
        CONNECTION.to_owned(),
        Binding {
            device: [1; 16],
            pool: [2; 28],
            incarnation: [3; 16],
            network: NetworkContext {
                network_magic: 42,
                shelley_genesis_digest: GENESIS,
                slots_per_kes_period: 64,
                max_kes_evolutions: 64,
            },
        },
    )])
    .unwrap();

    let status_request = status_request([1; 16]);
    let status_response = status_response([1; 16], &verification_key);
    Envelope::parse(&status_request, EnvelopeKind::LocalRequest).unwrap();
    Envelope::parse(&status_response, EnvelopeKind::LocalResponse).unwrap();
    router
        .complete(
            CONNECTION,
            &status_request,
            &status_response,
            session,
            Duration::from_micros(100),
        )
        .unwrap();
    assert_eq!(
        router
            .observation(CONNECTION, router.monotonic_ms())
            .unwrap()
            .state,
        State::Unavailable
    );

    let evolve_request = operational_request(Operation::Evolve, [2; 16]);
    let evolve_response = evolve_response([2; 16]);
    router
        .complete(
            CONNECTION,
            &evolve_request,
            &evolve_response,
            session,
            Duration::from_micros(900),
        )
        .unwrap();
    key.evolve_to(RelativePeriod::new(1).unwrap(), &public_tree)
        .unwrap();
    let mut signature = [0; 448];
    key.sign_into(RelativePeriod::new(1).unwrap(), MESSAGE, &mut signature)
        .unwrap();
    let sign_request = operational_request(Operation::Sign, [3; 16]);
    let valid_sign_response = sign_response([3; 16], &signature, Sha256::digest(MESSAGE).into());
    router
        .complete(
            CONNECTION,
            &sign_request,
            &valid_sign_response,
            session,
            Duration::from_micros(1),
        )
        .unwrap();
    let sample = router
        .latency(CONNECTION, latency::Operation::Sign, router.monotonic_ms())
        .unwrap()
        .sample
        .unwrap();
    assert_eq!(sample.outcome, latency::Outcome::Success);
    assert_eq!(sample.duration_ms, 1);

    let observe_request = operational_request(Operation::ObservePeriod, [4; 16]);
    let observe_response =
        descriptor_response(Operation::ObservePeriod, [4; 16], &verification_key);
    router
        .complete(
            CONNECTION,
            &observe_request,
            &observe_response,
            session,
            Duration::from_millis(2),
        )
        .unwrap();
    let view = router
        .observation(CONNECTION, router.monotonic_ms())
        .unwrap();
    assert_eq!(view.state, State::Fresh);
    assert_eq!(view.remaining_validity_periods, Some(63));

    let wrong_digest = sign_response([5; 16], &signature, [0; 32]);
    assert_eq!(
        router.complete(
            CONNECTION,
            &operational_request(Operation::Sign, [5; 16]),
            &wrong_digest,
            session,
            Duration::from_millis(3),
        ),
        Err(Error::ContextMismatch)
    );
    let failed = router
        .latency(CONNECTION, latency::Operation::Sign, router.monotonic_ms())
        .unwrap()
        .sample
        .unwrap();
    assert_eq!(failed.outcome, latency::Outcome::Error);
    assert_eq!(failed.code, "INVALID_RESPONSE");

    router.disconnect(CONNECTION);
    assert_eq!(
        router
            .observation(CONNECTION, router.monotonic_ms())
            .unwrap()
            .state,
        State::Unavailable
    );
}

fn status_request(request: [u8; 16]) -> Vec<u8> {
    envelope_request(Operation::Status, request, |encoder| {
        encoder.map(0).unwrap();
    })
}

fn operational_request(operation: Operation, request: [u8; 16]) -> Vec<u8> {
    envelope_request(operation, request, |encoder| match operation {
        Operation::Sign => {
            encoder.map(5).unwrap();
            encoder.text("message").unwrap();
            encoder.bytes(MESSAGE).unwrap();
            network(encoder);
            encoder.text("generation").unwrap();
            encoder.bytes(&GENERATION).unwrap();
            encoder.text("absolute_period").unwrap();
            encoder.uint(11).unwrap();
            encoder.text("certificate_digest").unwrap();
            encoder.bytes(&CERTIFICATE).unwrap();
        }
        Operation::Evolve => {
            encoder.map(5).unwrap();
            network(encoder);
            encoder.text("generation").unwrap();
            encoder.bytes(&GENERATION).unwrap();
            encoder.text("expected_revision").unwrap();
            encoder.uint(1).unwrap();
            encoder.text("certificate_digest").unwrap();
            encoder.bytes(&CERTIFICATE).unwrap();
            encoder.text("target_absolute_period").unwrap();
            encoder.uint(11).unwrap();
        }
        Operation::ObservePeriod => {
            encoder.map(3).unwrap();
            network(encoder);
            encoder.text("absolute_period").unwrap();
            encoder.uint(11).unwrap();
            encoder.text("expected_revision").unwrap();
            encoder.uint(2).unwrap();
        }
        _ => unreachable!(),
    })
}

fn envelope_request(
    operation: Operation,
    request: [u8; 16],
    payload: impl FnOnce(&mut Encoder<'_>),
) -> Vec<u8> {
    let mut storage = [0; kes_protocol::MAX_FRAME_BYTES];
    let mut encoder = Encoder::new(&mut storage);
    encoder.map(6).unwrap();
    encoder.text("op").unwrap();
    encoder.text(operation.as_str()).unwrap();
    encoder.text("payload").unwrap();
    payload(&mut encoder);
    encoder.text("request").unwrap();
    encoder.bytes(&request).unwrap();
    encoder.text("version").unwrap();
    encoder.uint(1).unwrap();
    encoder.text("budget_ms").unwrap();
    encoder.uint(500).unwrap();
    encoder.text("connection").unwrap();
    encoder.text(CONNECTION).unwrap();
    encoder.finish().unwrap().encoded().to_vec()
}

fn network(encoder: &mut Encoder<'_>) {
    encoder.text("network").unwrap();
    encoder.map(4).unwrap();
    encoder.text("network_magic").unwrap();
    encoder.uint(42).unwrap();
    encoder.text("max_kes_evolutions").unwrap();
    encoder.uint(64).unwrap();
    encoder.text("slots_per_kes_period").unwrap();
    encoder.uint(64).unwrap();
    encoder.text("shelley_genesis_digest").unwrap();
    encoder.bytes(&GENESIS).unwrap();
}

fn status_response(request: [u8; 16], verification_key: &[u8; 32]) -> Vec<u8> {
    envelope_response(Operation::Status, request, |encoder| {
        encoder.map(9).unwrap();
        encoder.text("active").unwrap();
        descriptor(encoder, verification_key, 1, 0);
        encoder.text("health").unwrap();
        encoder.text("healthy").unwrap();
        encoder.text("staged").unwrap();
        encoder.null().unwrap();
        encoder.text("revoked").unwrap();
        encoder.boolean(false).unwrap();
        encoder.text("revision").unwrap();
        encoder.uint(1).unwrap();
        encoder.text("directory").unwrap();
        encoder.array(0).unwrap();
        encoder.text("security_mode").unwrap();
        encoder.text("development").unwrap();
        encoder.text("blocking_reason").unwrap();
        encoder.text("").unwrap();
        encoder.text("credential_epoch").unwrap();
        encoder.uint(0).unwrap();
    })
}

fn descriptor_response(
    operation: Operation,
    request: [u8; 16],
    verification_key: &[u8; 32],
) -> Vec<u8> {
    envelope_response(operation, request, |encoder| {
        descriptor(encoder, verification_key, 2, 1)
    })
}

fn descriptor(
    encoder: &mut Encoder<'_>,
    verification_key: &[u8; 32],
    revision: u64,
    relative_period: u64,
) {
    encoder.map(13).unwrap();
    encoder.text("health").unwrap();
    encoder.text("healthy").unwrap();
    encoder.text("revision").unwrap();
    encoder.uint(revision).unwrap();
    encoder.text("lifecycle").unwrap();
    encoder.text("active").unwrap();
    encoder.text("generation").unwrap();
    encoder.bytes(&GENERATION).unwrap();
    encoder.text("artifact_digest").unwrap();
    encoder.bytes(&[10; 32]).unwrap();
    encoder.text("relative_period").unwrap();
    encoder.uint(relative_period).unwrap();
    encoder.text("backup_available").unwrap();
    encoder.boolean(true).unwrap();
    encoder.text("creation_request").unwrap();
    encoder.bytes(&[11; 16]).unwrap();
    encoder.text("verification_key").unwrap();
    encoder.bytes(verification_key).unwrap();
    encoder.text("certificate_start").unwrap();
    encoder.uint(10).unwrap();
    encoder.text("generation_number").unwrap();
    encoder.uint(1).unwrap();
    encoder.text("certificate_digest").unwrap();
    encoder.bytes(&CERTIFICATE).unwrap();
    encoder.text("certificate_counter").unwrap();
    encoder.uint(1).unwrap();
}

fn evolve_response(request: [u8; 16]) -> Vec<u8> {
    envelope_response(Operation::Evolve, request, |encoder| {
        encoder.map(6).unwrap();
        encoder.text("health").unwrap();
        encoder.text("healthy").unwrap();
        encoder.text("revision").unwrap();
        encoder.uint(2).unwrap();
        encoder.text("lifecycle").unwrap();
        encoder.text("active").unwrap();
        encoder.text("generation").unwrap();
        encoder.bytes(&GENERATION).unwrap();
        encoder.text("relative_period").unwrap();
        encoder.uint(1).unwrap();
        encoder.text("certificate_digest").unwrap();
        encoder.bytes(&CERTIFICATE).unwrap();
    })
}

fn sign_response(request: [u8; 16], signature: &[u8; 448], digest: [u8; 32]) -> Vec<u8> {
    envelope_response(Operation::Sign, request, |encoder| {
        encoder.map(8).unwrap();
        encoder.text("health").unwrap();
        encoder.text("healthy").unwrap();
        encoder.text("revision").unwrap();
        encoder.uint(2).unwrap();
        encoder.text("lifecycle").unwrap();
        encoder.text("active").unwrap();
        encoder.text("signature").unwrap();
        encoder.bytes(signature).unwrap();
        encoder.text("generation").unwrap();
        encoder.bytes(&GENERATION).unwrap();
        encoder.text("message_digest").unwrap();
        encoder.bytes(&digest).unwrap();
        encoder.text("relative_period").unwrap();
        encoder.uint(1).unwrap();
        encoder.text("certificate_digest").unwrap();
        encoder.bytes(&CERTIFICATE).unwrap();
    })
}

fn envelope_response(
    operation: Operation,
    request: [u8; 16],
    payload: impl FnOnce(&mut Encoder<'_>),
) -> Vec<u8> {
    let mut storage = [0; kes_protocol::MAX_FRAME_BYTES];
    let mut encoder = Encoder::new(&mut storage);
    encoder.map(6).unwrap();
    encoder.text("op").unwrap();
    encoder.text(operation.as_str()).unwrap();
    encoder.text("status").unwrap();
    encoder.text("OK").unwrap();
    encoder.text("payload").unwrap();
    payload(&mut encoder);
    encoder.text("request").unwrap();
    encoder.bytes(&request).unwrap();
    encoder.text("version").unwrap();
    encoder.uint(1).unwrap();
    encoder.text("connection").unwrap();
    encoder.text(CONNECTION).unwrap();
    encoder.finish().unwrap().encoded().to_vec()
}
