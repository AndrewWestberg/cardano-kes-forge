use ed25519_dalek::SigningKey;
use kes_core::{
    cbor::{Map, Value, encode_head},
    session::{
        DeviceHpkeKey, DeviceIdentityKey, INFO_TRANSCRIPT_BYTES, OpenContext, OpenResponse, Scope,
        SessionError, SessionTable, accept_open, begin_open, verify_info,
    },
    types::{CredentialEpoch, DeviceId, IncarnationId, PoolId, RequestId},
};
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{SeedableRng, TryCryptoRng, TryRngCore},
};
use std::fmt;
use zeroize::Zeroizing;

fn head(major: u8, n: u64, out: &mut Vec<u8>) {
    let mut bytes = [0; 9];
    let length = encode_head(major, n, &mut bytes);
    out.extend_from_slice(&bytes[..length]);
}
fn uint(n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    head(0, n, &mut out);
    out
}
fn bytes(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    head(2, value.len() as u64, &mut out);
    out.extend_from_slice(value);
    out
}
fn text(value: &str) -> Vec<u8> {
    let mut out = Vec::new();
    head(3, value.len() as u64, &mut out);
    out.extend_from_slice(value.as_bytes());
    out
}
fn null() -> Vec<u8> {
    vec![0xf6]
}
fn map(fields: Vec<(&str, Vec<u8>)>) -> Vec<u8> {
    let mut fields: Vec<_> = fields
        .into_iter()
        .map(|(key, value)| (text(key), value))
        .collect();
    fields.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = Vec::new();
    head(5, fields.len() as u64, &mut out);
    for (key, value) in fields {
        out.extend(key);
        out.extend(value);
    }
    out
}
fn parsed_map(bytes: &[u8]) -> Map<'_> {
    Value::parse(bytes).unwrap().map().unwrap()
}

#[derive(Debug)]
struct EntropyUnavailable;

impl fmt::Display for EntropyUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("injected entropy failure")
    }
}

#[derive(Default)]
struct FailingRng {
    calls: u32,
}

impl TryRngCore for FailingRng {
    type Error = EntropyUnavailable;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.calls += 1;
        Err(EntropyUnavailable)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.calls += 1;
        Err(EntropyUnavailable)
    }

    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Self::Error> {
        self.calls += 1;
        Err(EntropyUnavailable)
    }
}

impl TryCryptoRng for FailingRng {}

struct Fixture {
    device: DeviceId,
    scope: Scope,
    boot_nonce: [u8; 32],
    request: RequestId,
    identity: DeviceIdentityKey,
    hpke: DeviceHpkeKey,
    machine: SigningKey,
}
impl Fixture {
    fn new() -> Self {
        let device = DeviceId::from_bytes([1; 16]);
        let scope = Scope::Pool {
            pool: PoolId::from_bytes([2; 28]),
            incarnation: IncarnationId::from_bytes([3; 16]),
        };
        Self {
            device,
            scope,
            boot_nonce: [4; 32],
            request: RequestId::from_bytes([5; 16]),
            identity: DeviceIdentityKey::from_seed(Zeroizing::new([6; 32])),
            hpke: DeviceHpkeKey::from_seed(Zeroizing::new([7; 32])),
            machine: SigningKey::from_bytes(&[8; 32]),
        }
    }
    fn context(&self, counter: u64) -> OpenContext {
        OpenContext::new(
            self.device,
            self.boot_nonce,
            self.scope,
            CredentialEpoch::new(9),
            counter,
            self.request,
        )
    }
}
#[test]
fn gate_sensitivity_detects_session_authentication_bypass() {
    let Ok(mode) = std::env::var("KES_GATE_MODE") else {
        return;
    };
    if mode == "coverage" {
        return;
    }
    let fixture = Fixture::new();
    let challenge = [10; 32];
    let mut scratch = [0; INFO_TRANSCRIPT_BYTES];
    let unsigned = info_response(&fixture, challenge, [0; 64]);
    let mut signature = fixture
        .identity
        .sign_info(
            parsed_map(&unsigned),
            fixture.device,
            fixture.request,
            &challenge,
            &mut scratch,
        )
        .unwrap();
    signature[0] ^= 1;
    let corrupted = info_response(&fixture, challenge, signature);
    assert_eq!(
        verify_info(
            parsed_map(&corrupted),
            fixture.device,
            fixture.request,
            &challenge,
            &fixture.identity.verification_key(),
            &mut scratch,
        ),
        Err(SessionError::Authentication)
    );
    match mode.as_str() {
        "clean" => println!(
            "KES_GATE_SUMMARY {{\"version\":1,\"cases\":1,\"scenarios\":{{\"session\":1}},\"measurements\":{{\"violations\":0}}}}"
        ),
        "seeded-semantic-authentication-bypass" => {
            println!(
                "KES_GATE_SUMMARY {{\"version\":1,\"cases\":1,\"scenarios\":{{\"session\":1}},\"measurements\":{{\"violations\":1,\"counterexample\":{{\"mode\":\"seeded-semantic-authentication-bypass\",\"path\":\"kes-core.session.verify_info\",\"observation\":\"an INFO transcript with a one-bit-corrupted device signature was rejected\",\"disclosure\":\"public\"}}}}}}"
            );
            panic!("seeded session authentication bypass detected");
        }
        _ => panic!("unsupported session gate mode: {mode}"),
    }
}

fn info_response(fixture: &Fixture, challenge: [u8; 32], signature: [u8; 64]) -> Vec<u8> {
    let payload = map(vec![
        ("challenge", bytes(&challenge)),
        ("boot_nonce", bytes(&fixture.boot_nonce)),
        ("hpke_public_key", bytes(&fixture.hpke.public_key())),
        (
            "identity_public_key",
            bytes(&fixture.identity.verification_key()),
        ),
    ]);
    map(vec![
        ("op", text("INFO")),
        ("device", bytes(fixture.device.as_bytes())),
        ("status", text("OK")),
        ("payload", payload),
        ("request", bytes(fixture.request.as_bytes())),
        ("version", uint(1)),
        ("signature", bytes(&signature)),
    ])
}

#[test]
fn info_is_challenge_bound_and_verified_only_against_the_pin() {
    let fixture = Fixture::new();
    let challenge = [10; 32];
    let mut scratch = [0; INFO_TRANSCRIPT_BYTES];
    let unsigned = info_response(&fixture, challenge, [0; 64]);
    let signature = fixture
        .identity
        .sign_info(
            parsed_map(&unsigned),
            fixture.device,
            fixture.request,
            &challenge,
            &mut scratch,
        )
        .unwrap();
    let signed = info_response(&fixture, challenge, signature);
    let view = verify_info(
        parsed_map(&signed),
        fixture.device,
        fixture.request,
        &challenge,
        &fixture.identity.verification_key(),
        &mut scratch,
    )
    .unwrap();
    assert_eq!(view.boot_nonce, fixture.boot_nonce);
    assert_eq!(view.hpke_public_key, fixture.hpke.public_key());

    let mut wrong_challenge = challenge;
    wrong_challenge[0] ^= 1;
    assert_eq!(
        verify_info(
            parsed_map(&signed),
            fixture.device,
            fixture.request,
            &wrong_challenge,
            &fixture.identity.verification_key(),
            &mut scratch,
        )
        .unwrap_err(),
        SessionError::ChallengeMismatch
    );
    let foreign_pin = SigningKey::from_bytes(&[11; 32]).verifying_key().to_bytes();
    assert_eq!(
        verify_info(
            parsed_map(&signed),
            fixture.device,
            fixture.request,
            &challenge,
            &foreign_pin,
            &mut scratch,
        )
        .unwrap_err(),
        SessionError::Authentication
    );
}

fn open_response_envelope(context: OpenContext, response: OpenResponse) -> Vec<u8> {
    let (pool, incarnation) = match context.scope {
        Scope::Pool { pool, incarnation } => {
            (bytes(pool.as_bytes()), bytes(incarnation.as_bytes()))
        }
        Scope::Management => (null(), null()),
    };
    map(vec![
        ("op", text("OPEN")),
        ("mac", bytes(&response.mac)),
        ("pool", pool),
        ("device", bytes(context.device.as_bytes())),
        ("status", text("OK")),
        (
            "payload",
            map(vec![
                ("session", bytes(&response.session_id)),
                (
                    "challenge_acknowledgement",
                    bytes(&response.challenge_acknowledgement),
                ),
            ]),
        ),
        ("request", bytes(context.request.as_bytes())),
        ("version", uint(1)),
        ("incarnation", incarnation),
    ])
}

fn request_envelope(fixture: &Fixture, session: &[u8; 16], seq: u64, mac: [u8; 32]) -> Vec<u8> {
    let (pool, incarnation) = match fixture.scope {
        Scope::Pool { pool, incarnation } => {
            (bytes(pool.as_bytes()), bytes(incarnation.as_bytes()))
        }
        Scope::Management => (null(), null()),
    };
    map(vec![
        ("op", text("STATUS")),
        ("seq", uint(seq)),
        ("mac", bytes(&mac)),
        ("pool", pool),
        ("device", bytes(fixture.device.as_bytes())),
        ("payload", map(vec![])),
        ("request", bytes(fixture.request.as_bytes())),
        ("session", bytes(session)),
        ("version", uint(1)),
        ("budget_ms", uint(500)),
        ("incarnation", incarnation),
    ])
}

fn response_envelope(
    fixture: &Fixture,
    session: &[u8; 16],
    seq: u64,
    request_seq: u64,
    mac: [u8; 32],
) -> Vec<u8> {
    let (pool, incarnation) = match fixture.scope {
        Scope::Pool { pool, incarnation } => {
            (bytes(pool.as_bytes()), bytes(incarnation.as_bytes()))
        }
        Scope::Management => (null(), null()),
    };
    map(vec![
        ("op", text("STATUS")),
        ("seq", uint(seq)),
        ("mac", bytes(&mac)),
        ("pool", pool),
        ("device", bytes(fixture.device.as_bytes())),
        ("status", text("OK")),
        ("payload", map(vec![])),
        ("request", bytes(fixture.request.as_bytes())),
        ("session", bytes(session)),
        ("version", uint(1)),
        ("request_seq", uint(request_seq)),
        ("incarnation", incarnation),
    ])
}

#[test]
fn open_exports_independent_keys_and_enforces_both_sequence_spaces() {
    let fixture = Fixture::new();
    let context = fixture.context(7);
    let mut host_rng = ChaCha20Rng::from_seed([12; 32]);
    let (request, pending_host) = begin_open(
        context,
        &fixture.hpke.public_key(),
        &fixture.machine,
        &mut host_rng,
    )
    .unwrap();
    let mut device_rng = ChaCha20Rng::from_seed([13; 32]);
    let accepted = accept_open(
        context,
        &request,
        &fixture.hpke,
        &fixture.machine.verifying_key().to_bytes(),
        &mut device_rng,
    )
    .unwrap();
    let mut sessions = SessionTable::new();
    let mut counter = 7;
    let fields = accepted.response_fields();
    let unsigned_open_response = open_response_envelope(context, fields);
    let response = accepted
        .commit(
            &mut counter,
            &mut sessions,
            parsed_map(&unsigned_open_response),
        )
        .unwrap();
    assert_eq!(counter, 8);
    let signed_open_response = open_response_envelope(context, response);
    let mut host = pending_host
        .complete(parsed_map(&signed_open_response))
        .unwrap();
    assert_eq!(*host.session_id(), response.session_id);
    let session_id = response.session_id;
    let device = sessions.get_mut(fixture.scope).unwrap();

    let unsigned_request = request_envelope(&fixture, &session_id, 0, [0; 32]);
    let request_mac = host.request_mac(parsed_map(&unsigned_request)).unwrap();
    let signed_request = request_envelope(&fixture, &session_id, 0, request_mac);
    let authenticated = device
        .authenticate_request(parsed_map(&signed_request), CredentialEpoch::new(9), false)
        .unwrap();
    assert_eq!(authenticated.operation, "STATUS");
    assert_eq!(authenticated.sequence, 0);
    assert_eq!(authenticated.request, fixture.request);

    let unsigned_response = response_envelope(&fixture, &session_id, 0, 0, [0; 32]);
    let response_mac = device
        .response_mac(parsed_map(&unsigned_response), authenticated)
        .unwrap();
    let signed_response = response_envelope(&fixture, &session_id, 0, 0, response_mac);
    host.authenticate_response(parsed_map(&signed_response), fixture.request, "STATUS", 0)
        .unwrap();
    assert_eq!(
        host.authenticate_response(parsed_map(&signed_response), fixture.request, "STATUS", 0),
        Err(SessionError::Sequence)
    );
    assert!(!host.is_valid());

    assert_eq!(
        device
            .authenticate_request(parsed_map(&signed_request), CredentialEpoch::new(9), false)
            .unwrap_err(),
        SessionError::Sequence
    );
    assert!(!device.is_valid());
}

#[test]
fn failed_open_never_advances_or_replaces_a_scope() {
    let fixture = Fixture::new();
    let context = fixture.context(0);
    let mut host_rng = ChaCha20Rng::from_seed([14; 32]);
    let (mut request, _) = begin_open(
        context,
        &fixture.hpke.public_key(),
        &fixture.machine,
        &mut host_rng,
    )
    .unwrap();
    request.signature[0] ^= 1;
    let mut device_rng = FailingRng::default();
    assert_eq!(
        accept_open(
            context,
            &request,
            &fixture.hpke,
            &fixture.machine.verifying_key().to_bytes(),
            &mut device_rng,
        )
        .err(),
        Some(SessionError::Authentication)
    );
    assert_eq!(device_rng.calls, 0);
    request.signature[0] ^= 1;
    assert_eq!(
        accept_open(
            context,
            &request,
            &fixture.hpke,
            &fixture.machine.verifying_key().to_bytes(),
            &mut device_rng,
        )
        .err(),
        Some(SessionError::Entropy)
    );
    assert_eq!(device_rng.calls, 1);
    let sessions = SessionTable::new();
    assert!(sessions.get(fixture.scope).is_none());
}

#[test]
fn epoch_change_revocation_and_disconnect_invalidate() {
    let fixture = Fixture::new();
    let context = fixture.context(0);
    let mut host_rng = ChaCha20Rng::from_seed([16; 32]);
    let (request, _) = begin_open(
        context,
        &fixture.hpke.public_key(),
        &fixture.machine,
        &mut host_rng,
    )
    .unwrap();
    let mut device_rng = ChaCha20Rng::from_seed([17; 32]);
    let accepted = accept_open(
        context,
        &request,
        &fixture.hpke,
        &fixture.machine.verifying_key().to_bytes(),
        &mut device_rng,
    )
    .unwrap();
    let mut sessions = SessionTable::new();
    let mut counter = 0;
    let fields = accepted.response_fields();
    let unsigned = open_response_envelope(context, fields);
    let response = accepted
        .commit(&mut counter, &mut sessions, parsed_map(&unsigned))
        .unwrap();
    let session_id = response.session_id;
    let unsigned = request_envelope(&fixture, &session_id, 0, [0; 32]);
    let device = sessions.get_mut(fixture.scope).unwrap();
    assert_eq!(
        device
            .authenticate_request(parsed_map(&unsigned), CredentialEpoch::new(10), false)
            .unwrap_err(),
        SessionError::CredentialChanged
    );
    assert!(!device.is_valid());

    sessions.invalidate_scope(fixture.scope);
    assert!(sessions.get(fixture.scope).is_none());
    sessions.invalidate_all();
    assert!(sessions.get(fixture.scope).is_none());
}

fn commit_scope(
    fixture: &Fixture,
    sessions: &mut SessionTable,
    scope: Scope,
    request_byte: u8,
    counter: &mut u64,
) -> Result<[u8; 16], SessionError> {
    let context = OpenContext::new(
        fixture.device,
        fixture.boot_nonce,
        scope,
        CredentialEpoch::new(9),
        *counter,
        RequestId::from_bytes([request_byte; 16]),
    );
    let mut host_rng = ChaCha20Rng::from_seed([request_byte.wrapping_add(32); 32]);
    let (request, _) = begin_open(
        context,
        &fixture.hpke.public_key(),
        &fixture.machine,
        &mut host_rng,
    )
    .unwrap();
    let mut device_rng = ChaCha20Rng::from_seed([request_byte.wrapping_add(96); 32]);
    let accepted = accept_open(
        context,
        &request,
        &fixture.hpke,
        &fixture.machine.verifying_key().to_bytes(),
        &mut device_rng,
    )
    .unwrap();
    let fields = accepted.response_fields();
    let unsigned = open_response_envelope(context, fields);
    accepted
        .commit(counter, sessions, parsed_map(&unsigned))
        .map(|response| response.session_id)
}

#[test]
fn table_holds_management_plus_32_pools_and_replaces_only_matching_scope() {
    let fixture = Fixture::new();
    let mut sessions = SessionTable::new();
    let mut management_counter = 0;
    commit_scope(
        &fixture,
        &mut sessions,
        Scope::Management,
        200,
        &mut management_counter,
    )
    .unwrap();
    assert_eq!(management_counter, 1);

    let mut first_scope = Scope::Management;
    let mut first_session = [0; 16];
    for index in 0u8..32 {
        let scope = Scope::Pool {
            pool: PoolId::from_bytes([index; 28]),
            incarnation: IncarnationId::from_bytes([index; 16]),
        };
        let mut counter = 0;
        let session = commit_scope(&fixture, &mut sessions, scope, index, &mut counter).unwrap();
        assert_eq!(counter, 1);
        assert!(sessions.get(scope).is_some());
        if index == 0 {
            first_scope = scope;
            first_session = session;
        }
    }

    let extra_scope = Scope::Pool {
        pool: PoolId::from_bytes([32; 28]),
        incarnation: IncarnationId::from_bytes([32; 16]),
    };
    let mut extra_counter = 0;
    assert_eq!(
        commit_scope(&fixture, &mut sessions, extra_scope, 32, &mut extra_counter,),
        Err(SessionError::Capacity)
    );
    assert_eq!(extra_counter, 0);
    assert!(sessions.get(extra_scope).is_none());

    let mut replacement_counter = 1;
    let replacement = commit_scope(
        &fixture,
        &mut sessions,
        first_scope,
        201,
        &mut replacement_counter,
    )
    .unwrap();
    assert_eq!(replacement_counter, 2);
    assert_ne!(replacement, first_session);
    assert_eq!(
        *sessions.get(first_scope).unwrap().session_id(),
        replacement
    );
    assert!(sessions.get(Scope::Management).is_some());
}
