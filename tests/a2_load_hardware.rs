//! Real A2 signing latency campaign (disposable lab, no OTP writes).
//!
//! Measures the original host-admission-to-independent-verification latency for
//! one warm pool with maximum 4096-byte messages. This is exploratory A2
//! performance evidence, not the A4 release load campaign.
use cardano_kes_forge::host::{
    client::{DevelopmentIdentity, DeviceWire},
    usb::UsbWire,
};
use kes_core::{
    cbor::{Encoder, Value},
    session::{HostSession, OpenContext, begin_open},
    types::{
        CredentialEpoch, DeviceId, IncarnationId, KesLifetime, PoolId, RelativePeriod, RequestId,
    },
};
use kes_protocol::{Envelope, EnvelopeKind, MAX_FRAME_BYTES};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Read,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
#[path = "support/a2.rs"]
mod a2;

const SELECTOR: &str = "vid=cafe,pid=4b45,serial=A2-AUTH-DEVELOPMENT";

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut bytes)
        .unwrap();
    bytes
}

fn encode(f: impl FnOnce(&mut Encoder<'_>)) -> Vec<u8> {
    let mut buffer = [0; MAX_FRAME_BYTES];
    let mut encoder = Encoder::new(&mut buffer);
    f(&mut encoder);
    encoder.finish().unwrap().encoded().to_vec()
}

fn exchange(wire: &mut UsbWire, body: &[u8], timeout: Duration) -> Vec<u8> {
    let mut output = [0; MAX_FRAME_BYTES];
    let n = wire.exchange(body, &mut output, timeout).unwrap();
    output[..n].to_vec()
}

fn info(
    wire: &mut UsbWire,
    identity: &DevelopmentIdentity,
    pool: (PoolId, IncarnationId),
) -> ([u8; 32], [u8; 32], u64) {
    let request = RequestId::from_bytes(random());
    let challenge = random::<32>();
    let input = encode(|e| {
        e.map(4).unwrap();
        e.text("op").unwrap();
        e.text("INFO").unwrap();
        e.text("payload").unwrap();
        e.map(1).unwrap();
        e.text("challenge").unwrap();
        e.bytes(&challenge).unwrap();
        e.text("request").unwrap();
        e.bytes(request.as_bytes()).unwrap();
        e.text("version").unwrap();
        e.uint(1).unwrap();
    });
    let bytes = exchange(wire, &input, Duration::from_secs(2));
    let info = Envelope::parse(&bytes, EnvelopeKind::InfoResponse).unwrap();
    let device = DeviceId::from_bytes(identity.device);
    let mut scratch = [0; kes_core::session::INFO_TRANSCRIPT_BYTES];
    let verified = kes_core::session::verify_info(
        info.map(),
        device,
        request,
        &challenge,
        &identity.identity_public_key,
        &mut scratch,
    )
    .unwrap();
    let mut counter = None;
    for entry in info
        .payload()
        .required("open_counters")
        .unwrap()
        .array()
        .unwrap()
    {
        let entry = entry.map().unwrap();
        let pool_value = entry.required("pool").unwrap();
        if pool_value.is_null() {
            continue;
        }
        if pool_value.bytes().unwrap() == pool.0.as_bytes()
            && entry.required("incarnation").unwrap().bytes().unwrap() == pool.1.as_bytes()
        {
            counter = Some(entry.required("open_counter").unwrap().uint().unwrap());
        }
    }
    (
        verified.boot_nonce,
        verified.hpke_public_key,
        counter.unwrap(),
    )
}

struct PoolOperation<'a> {
    name: &'a str,
    request: RequestId,
    payload: &'a [u8],
    budget_ms: u64,
}

fn pool_operation(
    wire: &mut UsbWire,
    host: &mut HostSession,
    device: DeviceId,
    scope: (PoolId, IncarnationId),
    sequence: u64,
    operation: PoolOperation<'_>,
) -> Vec<u8> {
    let PoolOperation {
        name: operation,
        request,
        payload,
        budget_ms,
    } = operation;
    let session = *host.session_id();
    let message = |mac: [u8; 32]| {
        encode(|e| {
            e.map(11).unwrap();
            e.text("op").unwrap();
            e.text(operation).unwrap();
            e.text("mac").unwrap();
            e.bytes(&mac).unwrap();
            e.text("seq").unwrap();
            e.uint(sequence).unwrap();
            e.text("pool").unwrap();
            e.bytes(scope.0.as_bytes()).unwrap();
            e.text("device").unwrap();
            e.bytes(device.as_bytes()).unwrap();
            e.text("payload").unwrap();
            e.value(Value::parse(payload).unwrap()).unwrap();
            e.text("request").unwrap();
            e.bytes(request.as_bytes()).unwrap();
            e.text("session").unwrap();
            e.bytes(&session).unwrap();
            e.text("version").unwrap();
            e.uint(1).unwrap();
            e.text("budget_ms").unwrap();
            e.uint(budget_ms).unwrap();
            e.text("incarnation").unwrap();
            e.bytes(scope.1.as_bytes()).unwrap();
        })
    };
    let unsigned = message([0; 32]);
    let mac = host
        .request_mac(
            Envelope::parse(&unsigned, EnvelopeKind::DeviceRequest)
                .unwrap()
                .map(),
        )
        .unwrap();
    let reply = exchange(wire, &message(mac), Duration::from_millis(budget_ms));
    let reply = Envelope::parse(&reply, EnvelopeKind::DeviceResponse).unwrap();
    let status = reply.status.unwrap();
    host.authenticate_response(reply.map(), request, operation, sequence)
        .unwrap_or_else(|_| panic!("response authentication failed for {status}"));
    reply.encoded().to_vec()
}

fn open_request(open: &kes_core::session::OpenRequest) -> Vec<u8> {
    let kes_core::session::Scope::Pool { pool, incarnation } = open.context.scope else {
        panic!("expected pool scope")
    };
    encode(|e| {
        e.map(7).unwrap();
        e.text("op").unwrap();
        e.text("OPEN").unwrap();
        e.text("pool").unwrap();
        e.bytes(pool.as_bytes()).unwrap();
        e.text("device").unwrap();
        e.bytes(open.context.device.as_bytes()).unwrap();
        e.text("payload").unwrap();
        e.map(6).unwrap();
        e.text("signature").unwrap();
        e.bytes(&open.signature).unwrap();
        e.text("boot_nonce").unwrap();
        e.bytes(&open.context.boot_nonce).unwrap();
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
    })
}

fn open_pool(
    wire: &mut UsbWire,
    identity: &DevelopmentIdentity,
    scope: (PoolId, IncarnationId),
    nonce: [u8; 32],
    hpke: [u8; 32],
    counter: u64,
    seed: [u8; 32],
) -> HostSession {
    let context = OpenContext::new(
        DeviceId::from_bytes(identity.device),
        nonce,
        kes_core::session::Scope::Pool {
            pool: scope.0,
            incarnation: scope.1,
        },
        CredentialEpoch::new(0),
        counter,
        RequestId::from_bytes(random()),
    );
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let rng_seed = Zeroizing::new(random::<32>());
    let mut rng = ChaCha20Rng::from_seed(*rng_seed);
    let (open, pending) = begin_open(context, &hpke, &key, &mut rng).unwrap();
    let bytes = exchange(wire, &open_request(&open), Duration::from_secs(2));
    let response = Envelope::parse(&bytes, EnvelopeKind::OpenResponse).unwrap();
    pending.complete(response.map()).unwrap()
}

#[test]
#[ignore = "requires a committed disposable A2 pool and explicit load campaign authorization"]
fn a2_warm_signing_latency_campaign() {
    assert_eq!(
        std::env::var("KES_A2_AUTHORIZE_DISPOSABLE_LOAD").as_deref(),
        Ok("yes")
    );
    let requests: usize = std::env::var("KES_A2_LOAD_REQUESTS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1000);
    assert!((10..=100_000).contains(&requests));
    let seed: u8 = std::env::var("KES_A2_LOAD_MACHINE_SEED")
        .ok()
        .and_then(|value| u8::from_str_radix(&value, 16).ok())
        .unwrap_or(0xa8);
    let authorization =
        std::fs::read(std::env::var_os("KES_A2_LOAD_ENROLLMENT_AUTHORIZATION").unwrap()).unwrap();
    let signed = Value::parse(&authorization).unwrap().map().unwrap();
    let enrollment = Value::parse(
        signed
            .required("canonical_payload")
            .unwrap()
            .bytes()
            .unwrap(),
    )
    .unwrap()
    .map()
    .unwrap();
    let pool = PoolId::from_bytes(
        signed
            .required("pool")
            .unwrap()
            .bytes()
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let incarnation = IncarnationId::from_bytes(
        signed
            .required("incarnation")
            .unwrap()
            .bytes()
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let lifetime = KesLifetime::new(
        enrollment
            .required("network")
            .unwrap()
            .map()
            .unwrap()
            .required("max_kes_evolutions")
            .unwrap()
            .uint()
            .unwrap(),
    )
    .unwrap();
    let scope = (pool, incarnation);
    let mut wire = UsbWire::open(SELECTOR).unwrap();
    let (_management, identity) = a2::open(&mut wire).unwrap();
    let device = DeviceId::from_bytes(identity.device);
    let (nonce, hpke, counter) = info(&mut wire, &identity, scope);
    let mut session = open_pool(
        &mut wire, &identity, scope, nonce, hpke, counter, [seed; 32],
    );
    let status_bytes = pool_operation(
        &mut wire,
        &mut session,
        device,
        scope,
        0,
        PoolOperation {
            name: "STATUS",
            request: RequestId::from_bytes(random()),
            payload: &[0xa0],
            budget_ms: 2000,
        },
    );
    let status = Envelope::parse(&status_bytes, EnvelopeKind::DeviceResponse).unwrap();
    assert_eq!(status.status.unwrap().as_str(), "OK");
    let active = status.payload().required("active").unwrap();
    assert!(!active.is_null(), "pool needs an active generation");
    let descriptor = active.map().unwrap();
    let generation: [u8; 16] = descriptor
        .required("generation")
        .unwrap()
        .bytes()
        .unwrap()
        .try_into()
        .unwrap();
    let verification_key: [u8; 32] = descriptor
        .required("verification_key")
        .unwrap()
        .bytes()
        .unwrap()
        .try_into()
        .unwrap();
    let certificate_digest: [u8; 32] = descriptor
        .required("certificate_digest")
        .unwrap()
        .bytes()
        .unwrap()
        .try_into()
        .unwrap();
    let relative = descriptor
        .required("relative_period")
        .unwrap()
        .uint()
        .unwrap();
    let certificate_start = descriptor
        .required("certificate_start")
        .unwrap()
        .uint()
        .unwrap();
    let network = enrollment.required("network").unwrap();
    let message_bytes: usize = std::env::var("KES_A2_LOAD_MESSAGE_BYTES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(4096);
    assert!(message_bytes > 0 && message_bytes <= 4096);
    let message = vec![0x5a; message_bytes];
    let payload = encode(|e| {
        e.map(5).unwrap();
        e.text("message").unwrap();
        e.bytes(&message).unwrap();
        e.text("network").unwrap();
        e.value(network).unwrap();
        e.text("generation").unwrap();
        e.bytes(&generation).unwrap();
        e.text("absolute_period").unwrap();
        e.uint(certificate_start + relative).unwrap();
        e.text("certificate_digest").unwrap();
        e.bytes(&certificate_digest).unwrap();
    });
    let mut status_samples = Vec::new();
    let mut status_sequence = 1u64;
    for _ in 0..5 {
        let begin = Instant::now();
        let _ = pool_operation(
            &mut wire,
            &mut session,
            device,
            scope,
            status_sequence,
            PoolOperation {
                name: "STATUS",
                request: RequestId::from_bytes(random()),
                payload: &[0xa0],
                budget_ms: 2000,
            },
        );
        status_sequence += 1;
        status_samples.push(begin.elapsed().as_millis());
    }
    let mut durations = Vec::with_capacity(requests);
    let started = Instant::now();
    for sequence in status_sequence..status_sequence + requests as u64 {
        let request = RequestId::from_bytes(random());
        let begin = Instant::now();
        let reply = pool_operation(
            &mut wire,
            &mut session,
            device,
            scope,
            sequence,
            PoolOperation {
                name: "SIGN",
                request,
                payload: &payload,
                budget_ms: 1000,
            },
        );
        durations.push(begin.elapsed());
        let reply = Envelope::parse(&reply, EnvelopeKind::DeviceResponse).unwrap();
        assert_eq!(reply.status.unwrap().as_str(), "OK");
        assert_eq!(
            reply
                .payload()
                .required("message_digest")
                .unwrap()
                .bytes()
                .unwrap(),
            Sha256::digest(&message).as_slice()
        );
        let signature = reply
            .payload()
            .required("signature")
            .unwrap()
            .bytes()
            .unwrap();
        kes_core::crypto::verify(
            &verification_key,
            RelativePeriod::new(relative).unwrap(),
            lifetime,
            &message,
            signature,
        )
        .unwrap();
    }
    let elapsed = started.elapsed();
    durations.sort_unstable();
    let percentile = |p: usize| durations[(durations.len() - 1) * p / 100];
    let total_ms: u128 = durations.iter().map(|d| d.as_millis()).sum();
    let report = serde_json::json!({
        "version": 1,
        "campaign": "a2-warm-signing-latency",
        "requests": requests,
        "message_bytes": message.len(),
        "generation_id": hex(&generation),
        "verification_key_sha256": hex(&Sha256::digest(verification_key)),
        "relative_period": relative,
        "elapsed_ms": elapsed.as_millis(),
        "mean_ms": total_ms as f64 / requests as f64,
        "p50_ms": percentile(50).as_millis(),
        "p95_ms": percentile(95).as_millis(),
        "p99_ms": percentile(99).as_millis(),
        "max_ms": durations[durations.len()-1].as_millis(),
        "within_100ms": durations.iter().filter(|d| d.as_millis() <= 100).count() as f64 / requests as f64,
        "status_roundtrip_ms": status_samples,
        "signatures_independently_verified": requests,
        "threshold_met": percentile(99).as_millis() <= 100,
        "a4_release_acceptance": false,
    });
    if let Some(path) = std::env::var_os("KES_A2_LOAD_EVIDENCE") {
        std::fs::write(path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    }
    eprintln!("{report}");
    if std::env::var("KES_A2_LOAD_ENFORCE_THRESHOLD").as_deref() == Ok("yes") {
        assert!(percentile(99).as_millis() <= 100, "A2 p99 exceeded 100 ms");
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    output
}
