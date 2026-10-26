#![no_main]

use ed25519_dalek::SigningKey;
use kes_core::{
    cbor::{Map, Value, encode_head},
    session::{
        DeviceHpkeKey, DeviceIdentityKey, INFO_TRANSCRIPT_BYTES, OpenContext, OpenResponse, Scope,
        SessionError, SessionTable, accept_open, begin_open, verify_info,
    },
    types::{CredentialEpoch, DeviceId, IncarnationId, PoolId, RequestId},
};
use libfuzzer_sys::fuzz_target;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use sha2::{Digest, Sha256};
use std::sync::{
    Once,
    atomic::{AtomicU64, Ordering},
};
use zeroize::Zeroizing;

static CHECKS: AtomicU64 = AtomicU64::new(0);
static VIOLATIONS: AtomicU64 = AtomicU64::new(0);
static INIT: Once = Once::new();
extern "C" fn summary() {
    println!(
        "KES_FUZZ_SUMMARY {{\"version\":1,\"semantic_checks\":{},\"violations\":{}}}",
        CHECKS.load(Ordering::Relaxed),
        VIOLATIONS.load(Ordering::Relaxed)
    );
}
fn check(ok: bool) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        VIOLATIONS.fetch_add(1, Ordering::Relaxed);
        std::process::exit(1);
    }
}
fn initialize() {
    INIT.call_once(|| {
        // Test-only keys are derived at runtime from public labels. They are not
        // credentials, fixtures, corpus secrets, or production entropy.
        if unsafe { libc::atexit(summary) } != 0 {
            std::process::exit(2);
        }
    });
}

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
fn parsed(bytes: &[u8]) -> Map<'_> {
    Value::parse(bytes).unwrap().map().unwrap()
}
fn public_seed(label: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(label);
    hash.update(data);
    hash.finalize().into()
}

#[derive(Clone, Copy)]
struct PublicContext {
    device: DeviceId,
    scope: Scope,
    boot_nonce: [u8; 32],
    request: RequestId,
    epoch: CredentialEpoch,
}
impl PublicContext {
    fn from_data(data: &[u8]) -> Self {
        let digest = public_seed(b"session-fuzz-public-context", data);
        let mut device = [0; 16];
        device.copy_from_slice(&digest[..16]);
        let mut incarnation = [0; 16];
        incarnation.copy_from_slice(&digest[16..]);
        let cold = public_seed(b"session-fuzz-public-pool", data);
        Self {
            device: DeviceId::from_bytes(device),
            scope: Scope::Pool {
                pool: PoolId::from_cold_verification_key(&cold),
                incarnation: IncarnationId::from_bytes(incarnation),
            },
            boot_nonce: public_seed(b"session-fuzz-public-boot", data),
            request: RequestId::from_bytes(incarnation),
            epoch: CredentialEpoch::new(u64::from(data.first().copied().unwrap_or(0))),
        }
    }
    fn open(self, counter: u64) -> OpenContext {
        OpenContext::new(
            self.device,
            self.boot_nonce,
            self.scope,
            self.epoch,
            counter,
            self.request,
        )
    }
}

fn info_response(
    public: PublicContext,
    identity_key: [u8; 32],
    hpke_key: [u8; 32],
    challenge: [u8; 32],
    signature: [u8; 64],
) -> Vec<u8> {
    map(vec![
        ("op", text("INFO")),
        ("device", bytes(public.device.as_bytes())),
        ("status", text("OK")),
        (
            "payload",
            map(vec![
                ("challenge", bytes(&challenge)),
                ("boot_nonce", bytes(&public.boot_nonce)),
                ("hpke_public_key", bytes(&hpke_key)),
                ("identity_public_key", bytes(&identity_key)),
            ]),
        ),
        ("request", bytes(public.request.as_bytes())),
        ("version", uint(1)),
        ("signature", bytes(&signature)),
    ])
}

fn open_response_envelope(public: PublicContext, response: OpenResponse) -> Vec<u8> {
    let (pool, incarnation) = match public.scope {
        Scope::Management => (null(), null()),
        Scope::Pool { pool, incarnation } => {
            (bytes(pool.as_bytes()), bytes(incarnation.as_bytes()))
        }
    };
    map(vec![
        ("op", text("OPEN")),
        ("mac", bytes(&response.mac)),
        ("pool", pool),
        ("device", bytes(public.device.as_bytes())),
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
        ("request", bytes(public.request.as_bytes())),
        ("version", uint(1)),
        ("incarnation", incarnation),
    ])
}

fn request_envelope(
    public: PublicContext,
    session: &[u8; 16],
    sequence: u64,
    mac: [u8; 32],
) -> Vec<u8> {
    let (pool, incarnation) = match public.scope {
        Scope::Management => (null(), null()),
        Scope::Pool { pool, incarnation } => {
            (bytes(pool.as_bytes()), bytes(incarnation.as_bytes()))
        }
    };
    map(vec![
        ("op", text("STATUS")),
        ("seq", uint(sequence)),
        ("mac", bytes(&mac)),
        ("pool", pool),
        ("device", bytes(public.device.as_bytes())),
        ("payload", map(vec![])),
        ("request", bytes(public.request.as_bytes())),
        ("session", bytes(session)),
        ("version", uint(1)),
        ("budget_ms", uint(500)),
        ("incarnation", incarnation),
    ])
}

fn response_envelope(
    public: PublicContext,
    session: &[u8; 16],
    sequence: u64,
    request_sequence: u64,
    mac: [u8; 32],
) -> Vec<u8> {
    let (pool, incarnation) = match public.scope {
        Scope::Management => (null(), null()),
        Scope::Pool { pool, incarnation } => {
            (bytes(pool.as_bytes()), bytes(incarnation.as_bytes()))
        }
    };
    map(vec![
        ("op", text("STATUS")),
        ("seq", uint(sequence)),
        ("mac", bytes(&mac)),
        ("pool", pool),
        ("device", bytes(public.device.as_bytes())),
        ("status", text("OK")),
        ("payload", map(vec![])),
        ("request", bytes(public.request.as_bytes())),
        ("session", bytes(session)),
        ("version", uint(1)),
        ("request_seq", uint(request_sequence)),
        ("incarnation", incarnation),
    ])
}

fuzz_target!(|data: &[u8]| {
    initialize();
    let public = PublicContext::from_data(data);
    let identity =
        DeviceIdentityKey::from_seed(Zeroizing::new(public_seed(b"session-fuzz-identity", data)));
    let hpke = DeviceHpkeKey::from_seed(Zeroizing::new(public_seed(b"session-fuzz-hpke", data)));
    let machine = SigningKey::from_bytes(&public_seed(b"session-fuzz-machine", data));
    let challenge = public_seed(b"session-fuzz-info-challenge", data);
    let mut scratch = [0; INFO_TRANSCRIPT_BYTES];
    let unsigned_info = info_response(
        public,
        identity.verification_key(),
        hpke.public_key(),
        challenge,
        [0; 64],
    );
    let info_signature = identity
        .sign_info(
            parsed(&unsigned_info),
            public.device,
            public.request,
            &challenge,
            &mut scratch,
        )
        .unwrap();
    let signed_info = info_response(
        public,
        identity.verification_key(),
        hpke.public_key(),
        challenge,
        info_signature,
    );
    check(
        verify_info(
            parsed(&signed_info),
            public.device,
            public.request,
            &challenge,
            &identity.verification_key(),
            &mut scratch,
        )
        .is_ok(),
    );
    let mut wrong_challenge = challenge;
    wrong_challenge[0] ^= 1;
    check(
        verify_info(
            parsed(&signed_info),
            public.device,
            public.request,
            &wrong_challenge,
            &identity.verification_key(),
            &mut scratch,
        ) == Err(SessionError::ChallengeMismatch),
    );

    let counter = u64::from(data.get(1).copied().unwrap_or(0));
    let context = public.open(counter);
    let mut host_rng = ChaCha20Rng::from_seed(public_seed(b"session-fuzz-host-rng", data));
    let (open_request, pending) =
        begin_open(context, &hpke.public_key(), &machine, &mut host_rng).unwrap();
    let mut device_rng = ChaCha20Rng::from_seed(public_seed(b"session-fuzz-device-rng", data));
    let accepted = accept_open(
        context,
        &open_request,
        &hpke,
        &machine.verifying_key().to_bytes(),
        &mut device_rng,
    )
    .unwrap();
    let mut table = SessionTable::new();
    let mut stored_counter = counter;
    let fields = accepted.response_fields();
    let unsigned_open_response = open_response_envelope(public, fields);
    let open_response = accepted
        .commit(
            &mut stored_counter,
            &mut table,
            parsed(&unsigned_open_response),
        )
        .unwrap();
    check(stored_counter == counter + 1);
    let signed_open_response = open_response_envelope(public, open_response);
    let mut host = pending.complete(parsed(&signed_open_response)).unwrap();
    let session_id = open_response.session_id;
    let device = table.get_mut(public.scope).unwrap();

    let unsigned_request = request_envelope(public, &session_id, 0, [0; 32]);
    let request_mac = host.request_mac(parsed(&unsigned_request)).unwrap();
    let signed_request = request_envelope(public, &session_id, 0, request_mac);
    let action = data.get(2).copied().unwrap_or(0) % 7;
    if action == 1 {
        let mut bad_mac = request_mac;
        bad_mac[0] ^= 1;
        let bad_request = request_envelope(public, &session_id, 0, bad_mac);
        check(
            device
                .authenticate_request(parsed(&bad_request), public.epoch, false)
                .err()
                == Some(SessionError::Authentication),
        );
        check(!device.is_valid());
        return;
    }
    if action == 2 {
        check(
            device
                .authenticate_request(
                    parsed(&signed_request),
                    CredentialEpoch::new(public.epoch.get() + 1),
                    false,
                )
                .err()
                == Some(SessionError::CredentialChanged),
        );
        check(!device.is_valid());
        return;
    }
    if action == 3 {
        check(
            device
                .authenticate_request(parsed(&signed_request), public.epoch, true)
                .err()
                == Some(SessionError::Revoked),
        );
        check(!device.is_valid());
        return;
    }
    if action == 4 {
        let skipped = request_envelope(public, &session_id, 1, request_mac);
        check(
            device
                .authenticate_request(parsed(&skipped), public.epoch, false)
                .err()
                == Some(SessionError::Sequence),
        );
        check(!device.is_valid());
        return;
    }

    let authenticated = device
        .authenticate_request(parsed(&signed_request), public.epoch, false)
        .unwrap();
    check(authenticated.scope == public.scope);
    let unsigned_response = response_envelope(public, &session_id, 0, 0, [0; 32]);
    let response_mac = device
        .response_mac(parsed(&unsigned_response), authenticated)
        .unwrap();
    let signed_response = response_envelope(public, &session_id, 0, 0, response_mac);
    check(
        host.authenticate_response(parsed(&signed_response), public.request, "STATUS", 0)
            .is_ok(),
    );
    check(
        device
            .authenticate_request(parsed(&signed_request), public.epoch, false)
            .err()
            == Some(SessionError::Sequence),
    );
    check(!device.is_valid());

    if action == 5 {
        let mut bad_open = open_request;
        bad_open.signature[0] ^= 1;
        let mut retry_rng = ChaCha20Rng::from_seed(public_seed(b"session-fuzz-retry-rng", data));
        check(
            accept_open(
                context,
                &bad_open,
                &hpke,
                &machine.verifying_key().to_bytes(),
                &mut retry_rng,
            )
            .err()
                == Some(SessionError::Authentication),
        );
    }
    if action == 6 {
        let mut wrong = context;
        wrong.boot_nonce[0] ^= 1;
        let mut retry_rng = ChaCha20Rng::from_seed(public_seed(b"session-fuzz-context-rng", data));
        check(
            accept_open(
                wrong,
                &open_request,
                &hpke,
                &machine.verifying_key().to_bytes(),
                &mut retry_rng,
            )
            .err()
                == Some(SessionError::InvalidStructure),
        );
    }
});
