use cardano_kes_forge::host::latency;
use cardano_kes_forge::host::observation::{NetworkContext, State};
use cardano_kes_forge::host::signing::{Binding, Error, Router, Session};
use kes_core::cbor::Encoder;
use kes_core::crypto::Generation;
use kes_core::types::{KesLifetime, RelativePeriod};
use kes_protocol::{Envelope, EnvelopeKind, Operation, Status};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::time::Duration;

const CONNECTION: &str = "pool-0";
const GENERATION: [u8; 16] = [5; 16];
const CERTIFICATE: [u8; 32] = [6; 32];
const GENESIS: [u8; 32] = [4; 32];
const MESSAGE: &[u8] = b"exact native header bytes";

#[test]
fn sign_is_independently_verified_and_operational_observation_is_context_bound() {
    let lifetime = KesLifetime::new(64).unwrap();
    let mut seed = [0; 32];
    std::fs::File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut seed)
        .unwrap();
    let mut generation = Generation::begin(&mut seed, lifetime).unwrap();
    for _ in 0..64 {
        generation.step().unwrap();
    }
    let (mut key, tree) = generation.finish().unwrap();
    let public_tree = tree.verify(&key.verification_key().unwrap()).unwrap();
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

    let evolve_request = operational_request(Operation::Evolve, [2; 16], 11);
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
    let evolved = router
        .observation(CONNECTION, router.monotonic_ms())
        .unwrap();
    assert_eq!(evolved.state, State::Fresh);
    assert_eq!(evolved.remaining_validity_periods, Some(63));
    router.disconnect(CONNECTION);
    router
        .complete(
            CONNECTION,
            &status_request,
            &status_response_at([1; 16], &verification_key, 2, 1),
            session,
            Duration::ZERO,
        )
        .unwrap();
    assert_eq!(
        router
            .observation(CONNECTION, router.monotonic_ms())
            .unwrap()
            .state,
        State::Unavailable,
    );
    key.evolve_to(RelativePeriod::new(1).unwrap(), &public_tree)
        .unwrap();
    let mut signature = [0; 448];
    key.sign_into(RelativePeriod::new(1).unwrap(), MESSAGE, &mut signature)
        .unwrap();
    let sign_request = operational_request(Operation::Sign, [3; 16], 11);
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
    let signed = router
        .observation(CONNECTION, router.monotonic_ms())
        .unwrap();
    assert_eq!(signed.state, State::Fresh);
    assert_eq!(signed.remaining_validity_periods, Some(63));
    let sample = router
        .latency(CONNECTION, latency::Operation::Sign, router.monotonic_ms())
        .unwrap()
        .sample
        .unwrap();
    assert_eq!(sample.outcome, latency::Outcome::Success);

    let observe_request = operational_request(Operation::ObservePeriod, [4; 16], 11);
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
            &operational_request(Operation::Sign, [5; 16], 11),
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
    assert_eq!(failed.code, "INVALID_FRAME");

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

fn operational_request(operation: Operation, request: [u8; 16], period: u64) -> Vec<u8> {
    envelope_request(operation, request, |encoder| match operation {
        Operation::Sign => {
            encoder.map(5).unwrap();
            encoder.text("message").unwrap();
            encoder.bytes(MESSAGE).unwrap();
            network(encoder);
            encoder.text("generation").unwrap();
            encoder.bytes(&GENERATION).unwrap();
            encoder.text("absolute_period").unwrap();
            encoder.uint(period).unwrap();
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
            encoder.uint(period).unwrap();
        }
        Operation::ObservePeriod => {
            encoder.map(3).unwrap();
            network(encoder);
            encoder.text("absolute_period").unwrap();
            encoder.uint(period).unwrap();
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
    status_response_at(request, verification_key, 1, 0)
}

fn status_response_at(
    request: [u8; 16],
    verification_key: &[u8; 32],
    revision: u64,
    relative: u64,
) -> Vec<u8> {
    status_response_with_health(request, verification_key, revision, relative, "healthy")
}

fn status_response_with_health(
    request: [u8; 16],
    verification_key: &[u8; 32],
    revision: u64,
    relative: u64,
    health: &str,
) -> Vec<u8> {
    envelope_response(Operation::Status, request, Status::Ok, |encoder| {
        encoder.map(9).unwrap();
        encoder.text("active").unwrap();
        descriptor(encoder, verification_key, revision, relative);
        encoder.text("health").unwrap();
        encoder.text(health).unwrap();
        encoder.text("staged").unwrap();
        encoder.null().unwrap();
        encoder.text("revoked").unwrap();
        encoder.boolean(false).unwrap();
        encoder.text("revision").unwrap();
        encoder.uint(revision).unwrap();
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
    envelope_response(operation, request, Status::Ok, |encoder| {
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
    envelope_response(Operation::Evolve, request, Status::Ok, |encoder| {
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
    envelope_response(Operation::Sign, request, Status::Ok, |encoder| {
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
    status: Status,
    payload: impl FnOnce(&mut Encoder<'_>),
) -> Vec<u8> {
    let mut storage = [0; kes_protocol::MAX_FRAME_BYTES];
    let mut encoder = Encoder::new(&mut storage);
    encoder.map(6).unwrap();
    encoder.text("op").unwrap();
    encoder.text(operation.as_str()).unwrap();
    encoder.text("status").unwrap();
    encoder.text(status.as_str()).unwrap();
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

#[test]
fn healthy_status_restores_current_readiness_without_refreshing_observations() {
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
    let key = [9; 32];
    router
        .complete(
            CONNECTION,
            &status_request([1; 16]),
            &status_response([1; 16], &key),
            session,
            Duration::ZERO,
        )
        .unwrap();
    router
        .complete(
            CONNECTION,
            &operational_request(Operation::ObservePeriod, [2; 16], 11),
            &descriptor_response(Operation::ObservePeriod, [2; 16], &key),
            session,
            Duration::ZERO,
        )
        .unwrap();
    let before = router
        .observation(CONNECTION, router.monotonic_ms())
        .unwrap();
    assert_eq!(before.ready, Some(true));
    let confirmed_at = before.confirmed_observed_at.unwrap().to_owned();
    let node_at = before.node_period_observed_at.unwrap().to_owned();
    router
        .complete(
            CONNECTION,
            &status_request([3; 16]),
            &status_response_with_health([3; 16], &key, 2, 1, "unavailable"),
            session,
            Duration::ZERO,
        )
        .unwrap();
    assert_eq!(
        router
            .observation(CONNECTION, router.monotonic_ms())
            .unwrap()
            .ready,
        Some(false)
    );
    router
        .complete(
            CONNECTION,
            &status_request([4; 16]),
            &status_response_at([4; 16], &key, 2, 1),
            session,
            Duration::ZERO,
        )
        .unwrap();
    let recovered = router
        .observation(CONNECTION, router.monotonic_ms())
        .unwrap();
    assert_eq!(recovered.ready, Some(true));
    assert_eq!(recovered.confirmed_observed_at, Some(confirmed_at.as_str()));
    assert_eq!(recovered.node_period_observed_at, Some(node_at.as_str()));
    let response = status_response_at([4; 16], &key, 2, 1);
    let mut enriched = [0; kes_protocol::MAX_FRAME_BYTES];
    let length = cardano_kes_forge::host::client::operator_status::attach_at(
        &response,
        &mut enriched,
        &[1; 16],
        Some((&[2; 28], &[3; 16])),
        &router,
        CONNECTION,
        router.monotonic_ms(),
    )
    .unwrap();
    let public = cardano_kes_forge::host::client::operator_status::render(
        Envelope::parse(&enriched[..length], EnvelopeKind::LocalResponse).unwrap(),
        [1; 16],
        Some([2; 28]),
        Some([3; 16]),
        None,
        [4; 16],
    )
    .unwrap();
    assert_eq!(public["result"]["ready"], true);
    assert_eq!(
        public["result"]["observation"]["confirmedObservedAt"],
        confirmed_at
    );
    assert_eq!(
        public["result"]["observation"]["nodePeriodObservedAt"],
        node_at
    );
    assert_eq!(
        router
            .observation(CONNECTION, router.monotonic_ms() + 30_000)
            .unwrap()
            .ready,
        None
    );
}

#[test]
fn operator_reads_preserve_ages_and_timeout_history_without_manufacturing_readiness() {
    use cardano_kes_forge::host::client::operator_status;
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
    let verification = [9; 32];
    let first = status_response([1; 16], &verification);
    router
        .complete(
            CONNECTION,
            &status_request([1; 16]),
            &first,
            session,
            Duration::ZERO,
        )
        .unwrap();
    let read = |router: &Router, wire: &[u8], now| {
        let mut bytes = [0; kes_protocol::MAX_FRAME_BYTES];
        let length = operator_status::attach_at(
            wire,
            &mut bytes,
            &[1; 16],
            Some((&[2; 28], &[3; 16])),
            router,
            CONNECTION,
            now,
        )
        .unwrap();
        let response = Envelope::parse(&bytes[..length], EnvelopeKind::LocalResponse).unwrap();
        operator_status::render(
            response,
            [1; 16],
            Some([2; 28]),
            Some([3; 16]),
            None,
            [1; 16],
        )
        .unwrap()
    };
    let absent = read(&router, &first, router.monotonic_ms());
    assert_eq!(absent["result"]["observation"]["state"], "unavailable");
    assert!(absent["result"]["ready"].is_null());
    assert!(absent["result"]["remainingValidityPeriods"].is_null());
    assert_eq!(absent["result"]["latency"].as_object().unwrap().len(), 8);

    let observe = operational_request(Operation::ObservePeriod, [2; 16], 11);
    let response = descriptor_response(Operation::ObservePeriod, [2; 16], &verification);
    router
        .complete(
            CONNECTION,
            &observe,
            &response,
            session,
            Duration::from_millis(9),
        )
        .unwrap();
    let sample_time = router
        .latency(
            CONNECTION,
            latency::Operation::ObservePeriod,
            router.monotonic_ms(),
        )
        .unwrap()
        .sample
        .unwrap()
        .completed_monotonic_ms;
    let read_at = router.monotonic_ms();
    let joined = router.observation(CONNECTION, read_at).unwrap();
    let observation_time = read_at
        - joined
            .confirmed_age_ms
            .unwrap()
            .max(joined.node_period_age_ms.unwrap());
    let current = status_response_at([1; 16], &verification, 2, 1);
    // STATUS reconciles the same public descriptor without renewing either
    // operational clock or replacing the last latency sample.
    std::thread::sleep(Duration::from_millis(2));
    router
        .complete(
            CONNECTION,
            &status_request([1; 16]),
            &current,
            session,
            Duration::ZERO,
        )
        .unwrap();
    let fresh = read(&router, &current, observation_time + 29_999);
    assert_eq!(fresh["result"]["observation"]["state"], "fresh");
    assert_eq!(fresh["result"]["remainingValidityPeriods"], 63);
    let observed_at = fresh["result"]["observation"]["confirmedObservedAt"].clone();
    assert!(observed_at.as_str().unwrap().ends_with('Z'));
    let stale = read(&router, &current, observation_time + 30_000);
    assert_eq!(stale["result"]["observation"]["state"], "stale");
    assert_eq!(
        stale["result"]["observation"]["confirmedObservedAt"],
        observed_at
    );
    assert!(stale["result"]["ready"].is_null());
    assert!(stale["result"]["remainingValidityPeriods"].is_null());
    let stale_latency = read(&router, &current, sample_time + 30_000);
    assert_eq!(
        stale_latency["result"]["latency"]["OBSERVE_PERIOD"]["state"],
        "stale"
    );
    assert_eq!(
        stale_latency["result"]["latency"]["OBSERVE_PERIOD"]["sample"]["ageMs"],
        30_000
    );
    assert!(
        operator_status::render(
            Envelope::parse(&first, EnvelopeKind::LocalResponse).unwrap(),
            [1; 16],
            Some([2; 28]),
            Some([3; 16]),
            None,
            [1; 16]
        )
        .is_err()
    );

    // A deadline can be authenticated by the device after a mutation committed.
    // It is not equivalent to an explicit, definitely-not-committed refusal.
    let authenticated_timeout = envelope_response(
        Operation::ObservePeriod,
        [2; 16],
        Status::DeadlineExceeded,
        |encoder| {
            encoder.map(2).unwrap();
            encoder.text("scope").unwrap();
            encoder.text("pool").unwrap();
            encoder.text("diagnostic").unwrap();
            encoder.text("completion deadline").unwrap();
        },
    );
    router
        .complete(
            CONNECTION,
            &observe,
            &authenticated_timeout,
            session,
            Duration::from_millis(500),
        )
        .unwrap();
    let uncertain = read(&router, &current, router.monotonic_ms());
    assert_eq!(uncertain["result"]["observation"]["state"], "unavailable");
    assert!(uncertain["result"]["ready"].is_null());
    assert!(uncertain["result"]["remainingValidityPeriods"].is_null());

    router.terminal(
        CONNECTION,
        &observe,
        Status::DeadlineExceeded,
        Duration::from_millis(500),
    );
    let unavailable = read(&router, &current, router.monotonic_ms());
    assert_eq!(unavailable["result"]["observation"]["state"], "unavailable");
    assert!(unavailable["result"]["ready"].is_null());
    assert_eq!(
        unavailable["result"]["observation"]["historical"]["generation"],
        "05".repeat(16)
    );
    assert_eq!(
        unavailable["result"]["latency"]["OBSERVE_PERIOD"]["sample"]["code"],
        "DEADLINE_EXCEEDED"
    );
    let next_session = Session {
        session: [99; 16],
        ..session
    };
    router
        .complete(
            CONNECTION,
            &status_request([1; 16]),
            &current,
            next_session,
            Duration::ZERO,
        )
        .unwrap();
    let reset = read(&router, &current, router.monotonic_ms());
    assert_eq!(
        reset["result"]["latency"]["OBSERVE_PERIOD"]["state"],
        "unavailable"
    );
    assert!(reset["result"]["remainingValidityPeriods"].is_null());
}

#[test]
fn authenticated_committed_expiry_reports_fresh_unready_without_a_signature() {
    for operation in [Operation::Sign, Operation::Evolve, Operation::ObservePeriod] {
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
        let session = Session {
            boot_nonce: [7; 32],
            session: [8; 16],
        };
        router
            .complete(
                CONNECTION,
                &status_request([1; 16]),
                &status_response([1; 16], &[9; 32]),
                session,
                Duration::ZERO,
            )
            .unwrap();
        let expired = envelope_response(operation, [3; 16], Status::Expired, |encoder| {
            encoder.map(6).unwrap();
            encoder.text("health").unwrap();
            encoder.text("healthy").unwrap();
            encoder.text("revision").unwrap();
            encoder.uint(2).unwrap();
            encoder.text("lifecycle").unwrap();
            encoder.text("expired").unwrap();
            encoder.text("generation").unwrap();
            encoder.bytes(&GENERATION).unwrap();
            encoder.text("relative_period").unwrap();
            encoder.uint(63).unwrap();
            encoder.text("certificate_digest").unwrap();
            encoder.bytes(&CERTIFICATE).unwrap();
        });
        router
            .complete(
                CONNECTION,
                &operational_request(operation, [3; 16], 74),
                &expired,
                session,
                Duration::ZERO,
            )
            .unwrap();
        let view = router
            .observation(CONNECTION, router.monotonic_ms())
            .unwrap();
        assert_eq!(view.state, State::Fresh);
        assert_eq!(view.ready, Some(false));
        assert_eq!(view.remaining_validity_periods, Some(0));
        assert_eq!(
            router
                .historical_public(CONNECTION)
                .unwrap()
                .map()
                .unwrap()
                .required("lifecycle")
                .unwrap()
                .text()
                .unwrap(),
            "expired",
        );
        assert_eq!(
            router.complete(
                CONNECTION,
                &operational_request(operation, [3; 16], 73),
                &expired,
                session,
                Duration::ZERO,
            ),
            Err(Error::ContextMismatch),
        );
    }
}
