//! Real pool-scoped HPKE OPEN on the explicitly disposable A2 lab board.
//! The fixture machine seeds below are public and must never be used in production.
use cardano_kes_forge::backup::{
    recipient,
    recover::{self, Expectations},
};
use cardano_kes_forge::host::{
    client::{DevelopmentIdentity, DeviceWire},
    usb::UsbWire,
};
use ed25519_dalek::{Signer, SigningKey};
use kes_core::{
    cbor::{Encoder, Value},
    session::{
        HostSession, INFO_TRANSCRIPT_BYTES, OpenContext, OpenRequest, Scope, begin_open,
        verify_info,
    },
    types::{
        CredentialEpoch, DeviceId, IncarnationId, KesLifetime, PoolId, RelativePeriod, RequestId,
    },
};
use kes_protocol::{Envelope, EnvelopeKind, MAX_FRAME_BYTES};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::Read,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
#[path = "support/a2.rs"]
mod a2;

const SELECTOR: &str = "vid=cafe,pid=4b45,serial=A2-AUTH-DEVELOPMENT";
fn random<const N: usize>() -> [u8; N] {
    let mut b = [0; N];
    File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut b)
        .unwrap();
    b
}
fn encode(f: impl FnOnce(&mut Encoder<'_>)) -> Vec<u8> {
    let mut b = [0; MAX_FRAME_BYTES];
    let mut e = Encoder::new(&mut b);
    f(&mut e);
    e.finish().unwrap().encoded().to_vec()
}
fn exchange(wire: &mut UsbWire, body: &[u8]) -> Vec<u8> {
    let mut output = [0; MAX_FRAME_BYTES];
    let n = wire
        .exchange(body, &mut output, Duration::from_secs(5))
        .unwrap();
    output[..n].to_vec()
}
fn info(
    wire: &mut UsbWire,
    identity: &DevelopmentIdentity,
    pools: &[(PoolId, IncarnationId); 2],
) -> ([u8; 32], [u8; 32], [u64; 2]) {
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
    let bytes = exchange(wire, &input);
    let info = Envelope::parse(&bytes, EnvelopeKind::InfoResponse).unwrap();
    let device = DeviceId::from_bytes(identity.device);
    let mut scratch = [0; INFO_TRANSCRIPT_BYTES];
    let verified = verify_info(
        info.map(),
        device,
        request,
        &challenge,
        &identity.identity_public_key,
        &mut scratch,
    )
    .unwrap();
    let mut counters = [None; 2];
    for item in info
        .payload()
        .required("open_counters")
        .unwrap()
        .array()
        .unwrap()
    {
        let m = item.map().unwrap();
        let p = m.required("pool").unwrap();
        let i = m.required("incarnation").unwrap();
        if p.is_null() {
            continue;
        }
        for (slot, (pool, incarnation)) in pools.iter().enumerate() {
            if p.bytes().unwrap() == pool.as_bytes() && i.bytes().unwrap() == incarnation.as_bytes()
            {
                assert!(counters[slot].is_none());
                counters[slot] = Some(m.required("open_counter").unwrap().uint().unwrap());
            }
        }
    }
    (
        verified.boot_nonce,
        verified.hpke_public_key,
        [counters[0].unwrap(), counters[1].unwrap()],
    )
}
fn open_request(open: &OpenRequest) -> Vec<u8> {
    let Scope::Pool { pool, incarnation } = open.context.scope else {
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
    fixture: u8,
) -> HostSession {
    let context = OpenContext::new(
        DeviceId::from_bytes(identity.device),
        nonce,
        Scope::Pool {
            pool: scope.0,
            incarnation: scope.1,
        },
        CredentialEpoch::new(0),
        counter,
        RequestId::from_bytes(random()),
    );
    let key = SigningKey::from_bytes(&[fixture; 32]);
    let seed = Zeroizing::new(random::<32>());
    let mut rng = ChaCha20Rng::from_seed(*seed);
    let (open, pending) = begin_open(context, &hpke, &key, &mut rng).unwrap();
    let bytes = exchange(wire, &open_request(&open));
    let response = Envelope::parse(&bytes, EnvelopeKind::OpenResponse).unwrap();
    pending.complete(response.map()).unwrap()
}
fn pool(path: std::ffi::OsString) -> (PoolId, IncarnationId) {
    let bytes = fs::read(path).unwrap();
    let m = Value::parse(&bytes).unwrap().map().unwrap();
    (
        PoolId::try_from(m.required("pool").unwrap().bytes().unwrap()).unwrap(),
        IncarnationId::try_from(m.required("incarnation").unwrap().bytes().unwrap()).unwrap(),
    )
}
#[test]
#[ignore = "requires two disposable A2 enrollments with the documented public test machine seeds"]
fn independent_pool_open_counters_are_signed_and_advance() {
    let pools = [
        pool(std::env::var_os("KES_A2_ENROLLMENT_AUTHORIZATION").unwrap()),
        pool(std::env::var_os("KES_A2_ENROLLMENT_2_AUTHORIZATION").unwrap()),
    ];
    let mut wire = UsbWire::open(SELECTOR).unwrap();
    let (_management, identity) = a2::open(&mut wire).unwrap();
    let (nonce, hpke, before) = info(&mut wire, &identity, &pools);
    open_pool(&mut wire, &identity, pools[0], nonce, hpke, before[0], 0xa2);
    let (nonce, hpke, after_first) = info(&mut wire, &identity, &pools);
    assert_eq!(after_first, [before[0] + 1, before[1]]);
    open_pool(
        &mut wire,
        &identity,
        pools[1],
        nonce,
        hpke,
        after_first[1],
        0xa4,
    );
    let (_, _, after_second) = info(&mut wire, &identity, &pools);
    assert_eq!(after_second, [before[0] + 1, before[1] + 1]);
}

fn unknown_operation(
    wire: &mut UsbWire,
    host: &mut HostSession,
    device: DeviceId,
    scope: (PoolId, IncarnationId),
    sequence: u64,
) {
    let request = RequestId::from_bytes(random());
    let target = RequestId::from_bytes(random());
    let session = *host.session_id();
    let encode_request = |mac: [u8; 32]| {
        encode(|e| {
            e.map(11).unwrap();
            e.text("op").unwrap();
            e.text("OP_STATUS").unwrap();
            e.text("mac").unwrap();
            e.bytes(&mac).unwrap();
            e.text("seq").unwrap();
            e.uint(sequence).unwrap();
            e.text("pool").unwrap();
            e.bytes(scope.0.as_bytes()).unwrap();
            e.text("device").unwrap();
            e.bytes(device.as_bytes()).unwrap();
            e.text("payload").unwrap();
            e.map(1).unwrap();
            e.text("request").unwrap();
            e.bytes(target.as_bytes()).unwrap();
            e.text("request").unwrap();
            e.bytes(request.as_bytes()).unwrap();
            e.text("session").unwrap();
            e.bytes(&session).unwrap();
            e.text("version").unwrap();
            e.uint(1).unwrap();
            e.text("budget_ms").unwrap();
            e.uint(2000).unwrap();
            e.text("incarnation").unwrap();
            e.bytes(scope.1.as_bytes()).unwrap();
        })
    };
    let unsigned = encode_request([0; 32]);
    let mac = host
        .request_mac(
            Envelope::parse(&unsigned, EnvelopeKind::DeviceRequest)
                .unwrap()
                .map(),
        )
        .unwrap();
    let reply = exchange(wire, &encode_request(mac));
    let reply = Envelope::parse(&reply, EnvelopeKind::DeviceResponse).unwrap();
    host.authenticate_response(reply.map(), request, "OP_STATUS", sequence)
        .unwrap();
    assert_eq!(reply.status.unwrap().as_str(), "UNKNOWN");
    assert_eq!(
        reply
            .payload()
            .required("request")
            .unwrap()
            .bytes()
            .unwrap(),
        target.as_bytes()
    );
}

#[test]
#[ignore = "requires two disposable A2 enrollments with the documented public test machine seeds"]
fn independent_pool_operation_status_sessions_interleave() {
    let pools = [
        pool(std::env::var_os("KES_A2_ENROLLMENT_AUTHORIZATION").unwrap()),
        pool(std::env::var_os("KES_A2_ENROLLMENT_2_AUTHORIZATION").unwrap()),
    ];
    let mut wire = UsbWire::open(SELECTOR).unwrap();
    let (_management, identity) = a2::open(&mut wire).unwrap();
    let (nonce, hpke, counters) = info(&mut wire, &identity, &pools);
    let mut first = open_pool(
        &mut wire,
        &identity,
        pools[0],
        nonce,
        hpke,
        counters[0],
        0xa2,
    );
    let mut second = open_pool(
        &mut wire,
        &identity,
        pools[1],
        nonce,
        hpke,
        counters[1],
        0xa4,
    );
    let device = DeviceId::from_bytes(identity.device);
    unknown_operation(&mut wire, &mut first, device, pools[0], 0);
    unknown_operation(&mut wire, &mut second, device, pools[1], 0);
    unknown_operation(&mut wire, &mut first, device, pools[0], 1);
    unknown_operation(&mut wire, &mut second, device, pools[1], 1);
}

fn pool_operation(
    wire: &mut UsbWire,
    host: &mut HostSession,
    device: DeviceId,
    scope: (PoolId, IncarnationId),
    sequence: u64,
    operation: &str,
    request: RequestId,
    payload: &[u8],
    budget_ms: u64,
) -> Vec<u8> {
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
    let reply = exchange(wire, &message(mac));
    let envelope = Envelope::parse(&reply, EnvelopeKind::DeviceResponse).unwrap();
    host.authenticate_response(envelope.map(), request, operation, sequence)
        .unwrap();
    reply
}

struct FixtureRecipientEntropy {
    first: bool,
    random: recipient::OsEntropy,
}
impl recipient::Entropy for FixtureRecipientEntropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), recipient::Error> {
        if self.first {
            assert_eq!(output.len(), 32);
            output.fill(0xaa);
            self.first = false;
            Ok(())
        } else {
            self.random.fill(output)
        }
    }
}

#[test]
#[ignore = "writes one disposable A2 generation; requires explicitly enrolled recovery fixture"]
fn cooperative_generation_backup_and_recovery_on_a2() {
    const CREATION: RequestId = RequestId::from_bytes([0xac; 16]);
    let pools = [
        pool(std::env::var_os("KES_A2_RECOVERY_ENROLLMENT_AUTHORIZATION").unwrap()),
        pool(std::env::var_os("KES_A2_ENROLLMENT_AUTHORIZATION").unwrap()),
    ];
    let mut wire = UsbWire::open(SELECTOR).unwrap();
    let (_management, identity) = a2::open(&mut wire).unwrap();
    let device = DeviceId::from_bytes(identity.device);
    let (nonce, hpke, counters) = info(&mut wire, &identity, &pools);
    let mut session = open_pool(
        &mut wire,
        &identity,
        pools[0],
        nonce,
        hpke,
        counters[0],
        0xa8,
    );
    let generate_payload = encode(|e| {
        e.map(2).unwrap();
        e.text("expected_revision").unwrap();
        e.uint(0).unwrap();
        e.text("next_generation_number").unwrap();
        e.uint(1).unwrap();
    });
    let ack = pool_operation(
        &mut wire,
        &mut session,
        device,
        pools[0],
        0,
        "GENERATE",
        CREATION,
        &generate_payload,
        600_000,
    );
    let ack = Envelope::parse(&ack, EnvelopeKind::DeviceResponse).unwrap();
    assert!(matches!(ack.status.unwrap().as_str(), "IN_PROGRESS" | "OK"));
    let status_payload = encode(|e| {
        e.map(2).unwrap();
        e.text("request").unwrap();
        e.bytes(CREATION.as_bytes()).unwrap();
        e.text("generation_number").unwrap();
        e.uint(1).unwrap();
    });
    let started = Instant::now();
    let mut sequence = 1;
    let descriptor = loop {
        assert!(
            started.elapsed() < Duration::from_secs(180),
            "device generation did not finish"
        );
        let reply = pool_operation(
            &mut wire,
            &mut session,
            device,
            pools[0],
            sequence,
            "OP_STATUS",
            RequestId::from_bytes(random()),
            &status_payload,
            2_000,
        );
        sequence += 1;
        let envelope = Envelope::parse(&reply, EnvelopeKind::DeviceResponse).unwrap();
        match envelope.status.unwrap().as_str() {
            "IN_PROGRESS" => std::thread::sleep(Duration::from_millis(25)),
            "OK" => break reply,
            other => panic!("generation reconciled as {other}"),
        }
    };
    let descriptor = Envelope::parse(&descriptor, EnvelopeKind::DeviceResponse).unwrap();
    let payload = descriptor.payload();
    assert_eq!(
        payload
            .required("creation_request")
            .unwrap()
            .bytes()
            .unwrap(),
        CREATION.as_bytes()
    );
    let generation: [u8; 16] = payload
        .required("generation")
        .unwrap()
        .bytes()
        .unwrap()
        .try_into()
        .unwrap();
    let verification_key: [u8; 32] = payload
        .required("verification_key")
        .unwrap()
        .bytes()
        .unwrap()
        .try_into()
        .unwrap();
    let digest: [u8; 32] = payload
        .required("artifact_digest")
        .unwrap()
        .bytes()
        .unwrap()
        .try_into()
        .unwrap();
    let backup_payload = encode(|e| {
        e.map(1).unwrap();
        e.text("generation").unwrap();
        e.bytes(&generation).unwrap();
    });
    let mut exact = None;
    for _ in 0..2 {
        let reply = pool_operation(
            &mut wire,
            &mut session,
            device,
            pools[0],
            sequence,
            "GET_BACKUP",
            RequestId::from_bytes(random()),
            &backup_payload,
            2_000,
        );
        sequence += 1;
        let envelope = Envelope::parse(&reply, EnvelopeKind::DeviceResponse).unwrap();
        assert_eq!(envelope.status.unwrap().as_str(), "OK");
        let backup = envelope
            .payload()
            .required("backup")
            .unwrap()
            .bytes()
            .unwrap()
            .to_vec();
        assert_eq!(<[u8; 32]>::from(Sha256::digest(&backup)), digest);
        assert_eq!(
            envelope
                .payload()
                .required("artifact_digest")
                .unwrap()
                .bytes()
                .unwrap(),
            digest
        );
        if let Some(previous) = exact.as_ref() {
            assert_eq!(&backup, previous);
        }
        exact = Some(backup);
    }
    let status = pool_operation(
        &mut wire,
        &mut session,
        device,
        pools[0],
        sequence,
        "STATUS",
        RequestId::from_bytes(random()),
        &[0xa0],
        2_000,
    );
    let status = Envelope::parse(&status, EnvelopeKind::DeviceResponse).unwrap();
    assert_eq!(status.status.unwrap().as_str(), "OK");
    let active = status.payload().required("active").unwrap();
    let staged = status.payload().required("staged").unwrap();
    let retained = [active, staged]
        .into_iter()
        .filter(|value| !value.is_null())
        .map(|value| value.map().unwrap())
        .find(|value| value.required("generation").unwrap().bytes().unwrap() == generation)
        .unwrap();
    assert_eq!(
        retained.required("generation").unwrap().bytes().unwrap(),
        generation
    );
    assert_eq!(
        retained
            .required("verification_key")
            .unwrap()
            .bytes()
            .unwrap(),
        verification_key
    );
    assert_eq!(
        status
            .payload()
            .required("directory")
            .unwrap()
            .array()
            .unwrap()
            .count(),
        0
    );
    let (_, recipient) = recipient::create(
        b"public disposable A2 fixture passphrase",
        &mut FixtureRecipientEntropy {
            first: true,
            random: recipient::OsEntropy::new().unwrap(),
        },
    )
    .unwrap();
    let recovered = recover::recover(
        exact.as_ref().unwrap(),
        &recipient,
        b"public disposable A2 fixture passphrase",
        Expectations {
            device: identity.device,
            pool: *pools[0].0.as_bytes(),
            incarnation: *pools[0].1.as_bytes(),
            generation,
            verification_key,
            identity_public_key: identity.identity_public_key,
        },
    )
    .unwrap();
    assert_eq!(recovered.len(), 608);
}

#[test]
#[ignore = "certifies, activates, and evolves a known disposable A2 pool"]
fn disposable_pool_certify_activate_evolve_and_sign() {
    assert_eq!(
        std::env::var("KES_A2_AUTHORIZE_DISPOSABLE_ACTIVATION").as_deref(),
        Ok("yes")
    );
    let authorization =
        fs::read(std::env::var_os("KES_A2_RECOVERY_ENROLLMENT_AUTHORIZATION").unwrap()).unwrap();
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
    let network = enrollment.required("network").unwrap();
    let lifetime = KesLifetime::new(
        network
            .map()
            .unwrap()
            .required("max_kes_evolutions")
            .unwrap()
            .uint()
            .unwrap(),
    )
    .unwrap();
    let pools = [
        pool(std::env::var_os("KES_A2_RECOVERY_ENROLLMENT_AUTHORIZATION").unwrap()),
        pool(std::env::var_os("KES_A2_ENROLLMENT_AUTHORIZATION").unwrap()),
    ];
    let mut wire = UsbWire::open(SELECTOR).unwrap();
    let (_management, identity) = a2::open(&mut wire).unwrap();
    let device = DeviceId::from_bytes(identity.device);
    let (nonce, hpke, counters) = info(&mut wire, &identity, &pools);
    let mut session = open_pool(
        &mut wire,
        &identity,
        pools[0],
        nonce,
        hpke,
        counters[0],
        0xa8,
    );
    let mut sequence = 0;
    let status = pool_operation(
        &mut wire,
        &mut session,
        device,
        pools[0],
        sequence,
        "STATUS",
        RequestId::from_bytes(random()),
        &[0xa0],
        2000,
    );
    sequence += 1;
    let status = Envelope::parse(&status, EnvelopeKind::DeviceResponse).unwrap();
    assert_eq!(status.status.unwrap().as_str(), "OK");
    let active = status.payload().required("active").unwrap();
    let staged = status.payload().required("staged").unwrap();
    let retained = if active.is_null() { staged } else { active }
        .map()
        .unwrap();
    let generation: [u8; 16] = retained
        .required("generation")
        .unwrap()
        .bytes()
        .unwrap()
        .try_into()
        .unwrap();
    let verification_key: [u8; 32] = retained
        .required("verification_key")
        .unwrap()
        .bytes()
        .unwrap()
        .try_into()
        .unwrap();
    let mut revision = status
        .payload()
        .required("revision")
        .unwrap()
        .uint()
        .unwrap();
    let cold = SigningKey::from_bytes(&[0xa6; 32]);
    let mut signable = [0; 48];
    signable[..32].copy_from_slice(&verification_key);
    let cold_signature = cold.sign(&signable).to_bytes();
    let certificate = encode(|e| {
        e.array(2).unwrap();
        e.array(4).unwrap();
        e.bytes(&verification_key).unwrap();
        e.uint(0).unwrap();
        e.uint(0).unwrap();
        e.bytes(&cold_signature).unwrap();
        e.bytes(&cold.verifying_key().to_bytes()).unwrap();
    });
    let certificate_digest: [u8; 32] = Sha256::digest(&certificate).into();
    if active.is_null() {
        if retained.required("lifecycle").unwrap().text().unwrap() == "staged" {
            let payload = encode(|e| {
                e.map(4).unwrap();
                e.text("network").unwrap();
                e.value(network).unwrap();
                e.text("generation").unwrap();
                e.bytes(&generation).unwrap();
                e.text("certificate").unwrap();
                e.bytes(&certificate).unwrap();
                e.text("expected_revision").unwrap();
                e.uint(revision).unwrap();
            });
            let reply = pool_operation(
                &mut wire,
                &mut session,
                device,
                pools[0],
                sequence,
                "CERTIFY",
                RequestId::from_bytes(random()),
                &payload,
                2_000,
            );
            sequence += 1;
            let reply = Envelope::parse(&reply, EnvelopeKind::DeviceResponse).unwrap();
            assert_eq!(reply.status.unwrap().as_str(), "OK");
            assert_eq!(
                reply
                    .payload()
                    .required("certificate_digest")
                    .unwrap()
                    .bytes()
                    .unwrap(),
                certificate_digest
            );
            revision = reply
                .payload()
                .required("revision")
                .unwrap()
                .uint()
                .unwrap();
        }
        let payload = encode(|e| {
            e.map(5).unwrap();
            e.text("generation").unwrap();
            e.bytes(&generation).unwrap();
            e.text("expected_revision").unwrap();
            e.uint(revision).unwrap();
            e.text("certificate_digest").unwrap();
            e.bytes(&certificate_digest).unwrap();
            e.text("current_absolute_period").unwrap();
            e.uint(0).unwrap();
            e.text("expected_active_generation").unwrap();
            e.null().unwrap();
        });
        let reply = pool_operation(
            &mut wire,
            &mut session,
            device,
            pools[0],
            sequence,
            "ACTIVATE",
            RequestId::from_bytes(random()),
            &payload,
            2_000,
        );
        sequence += 1;
        let reply = Envelope::parse(&reply, EnvelopeKind::DeviceResponse).unwrap();
        assert_eq!(reply.status.unwrap().as_str(), "OK");
        assert_eq!(
            reply
                .payload()
                .required("lifecycle")
                .unwrap()
                .text()
                .unwrap(),
            "active"
        );
        revision = reply
            .payload()
            .required("revision")
            .unwrap()
            .uint()
            .unwrap();
    } else {
        assert_eq!(
            retained
                .required("certificate_digest")
                .unwrap()
                .bytes()
                .unwrap(),
            certificate_digest
        );
    }
    let evolve = encode(|e| {
        e.map(5).unwrap();
        e.text("network").unwrap();
        e.value(network).unwrap();
        e.text("generation").unwrap();
        e.bytes(&generation).unwrap();
        e.text("expected_revision").unwrap();
        e.uint(revision).unwrap();
        e.text("certificate_digest").unwrap();
        e.bytes(&certificate_digest).unwrap();
        e.text("target_absolute_period").unwrap();
        e.uint(1).unwrap();
    });
    let reply = pool_operation(
        &mut wire,
        &mut session,
        device,
        pools[0],
        sequence,
        "EVOLVE",
        RequestId::from_bytes(random()),
        &evolve,
        2_000,
    );
    sequence += 1;
    let reply = Envelope::parse(&reply, EnvelopeKind::DeviceResponse).unwrap();
    assert_eq!(reply.status.unwrap().as_str(), "OK");
    assert_eq!(
        reply
            .payload()
            .required("relative_period")
            .unwrap()
            .uint()
            .unwrap(),
        1
    );
    revision = reply
        .payload()
        .required("revision")
        .unwrap()
        .uint()
        .unwrap();
    let message = b"disposable A2 exact signing message";
    let sign = encode(|e| {
        e.map(5).unwrap();
        e.text("message").unwrap();
        e.bytes(message).unwrap();
        e.text("network").unwrap();
        e.value(network).unwrap();
        e.text("generation").unwrap();
        e.bytes(&generation).unwrap();
        e.text("absolute_period").unwrap();
        e.uint(1).unwrap();
        e.text("certificate_digest").unwrap();
        e.bytes(&certificate_digest).unwrap();
    });
    let reply = pool_operation(
        &mut wire,
        &mut session,
        device,
        pools[0],
        sequence,
        "SIGN",
        RequestId::from_bytes(random()),
        &sign,
        500,
    );
    let reply = Envelope::parse(&reply, EnvelopeKind::DeviceResponse).unwrap();
    assert_eq!(reply.status.unwrap().as_str(), "OK");
    assert_eq!(
        reply
            .payload()
            .required("relative_period")
            .unwrap()
            .uint()
            .unwrap(),
        1
    );
    assert_eq!(
        reply
            .payload()
            .required("message_digest")
            .unwrap()
            .bytes()
            .unwrap(),
        Sha256::digest(message).as_slice()
    );
    let signature = reply
        .payload()
        .required("signature")
        .unwrap()
        .bytes()
        .unwrap();
    kes_core::crypto::verify(
        &verification_key,
        RelativePeriod::new(1).unwrap(),
        lifetime,
        message,
        signature,
    )
    .unwrap();
    assert!(
        kes_core::crypto::verify(
            &verification_key,
            RelativePeriod::new(1).unwrap(),
            lifetime,
            b"altered",
            signature
        )
        .is_err()
    );
    sequence += 1;
    let network_fields = network.map().unwrap();
    let wrong_network = encode(|e| {
        e.map(5).unwrap();
        e.text("message").unwrap();
        e.bytes(message).unwrap();
        e.text("network").unwrap();
        e.map(4).unwrap();
        e.text("network_magic").unwrap();
        e.uint(
            network_fields
                .required("network_magic")
                .unwrap()
                .uint()
                .unwrap()
                + 1,
        )
        .unwrap();
        e.text("max_kes_evolutions").unwrap();
        e.value(network_fields.required("max_kes_evolutions").unwrap())
            .unwrap();
        e.text("slots_per_kes_period").unwrap();
        e.value(network_fields.required("slots_per_kes_period").unwrap())
            .unwrap();
        e.text("shelley_genesis_digest").unwrap();
        e.value(network_fields.required("shelley_genesis_digest").unwrap())
            .unwrap();
        e.text("generation").unwrap();
        e.bytes(&generation).unwrap();
        e.text("absolute_period").unwrap();
        e.uint(1).unwrap();
        e.text("certificate_digest").unwrap();
        e.bytes(&certificate_digest).unwrap();
    });
    let reply = pool_operation(
        &mut wire,
        &mut session,
        device,
        pools[0],
        sequence,
        "SIGN",
        RequestId::from_bytes(random()),
        &wrong_network,
        500,
    );
    let reply = Envelope::parse(&reply, EnvelopeKind::DeviceResponse).unwrap();
    assert_eq!(reply.status.unwrap().as_str(), "WRONG_NETWORK");
    sequence += 1;
    let stale_generation = encode(|e| {
        e.map(2).unwrap();
        e.text("expected_revision").unwrap();
        e.uint(0).unwrap();
        e.text("next_generation_number").unwrap();
        e.uint(2).unwrap();
    });
    let reply = pool_operation(
        &mut wire,
        &mut session,
        device,
        pools[0],
        sequence,
        "GENERATE",
        RequestId::from_bytes(random()),
        &stale_generation,
        600_000,
    );
    let reply = Envelope::parse(&reply, EnvelopeKind::DeviceResponse).unwrap();
    assert_eq!(reply.status.unwrap().as_str(), "REVISION_CONFLICT");
    sequence += 1;
    let reply = pool_operation(
        &mut wire,
        &mut session,
        device,
        pools[0],
        sequence,
        "SIGN",
        RequestId::from_bytes(random()),
        &sign,
        500,
    );
    let reply = Envelope::parse(&reply, EnvelopeKind::DeviceResponse).unwrap();
    assert_eq!(reply.status.unwrap().as_str(), "OK");
    kes_core::crypto::verify(
        &verification_key,
        RelativePeriod::new(1).unwrap(),
        lifetime,
        message,
        reply
            .payload()
            .required("signature")
            .unwrap()
            .bytes()
            .unwrap(),
    )
    .unwrap();
    sequence += 1;
    let observe = encode(|e| {
        e.map(3).unwrap();
        e.text("network").unwrap();
        e.value(network).unwrap();
        e.text("absolute_period").unwrap();
        e.uint(1).unwrap();
        e.text("expected_revision").unwrap();
        e.uint(revision).unwrap();
    });
    let reply = pool_operation(
        &mut wire,
        &mut session,
        device,
        pools[0],
        sequence,
        "OBSERVE_PERIOD",
        RequestId::from_bytes(random()),
        &observe,
        2_000,
    );
    let reply = Envelope::parse(&reply, EnvelopeKind::DeviceResponse).unwrap();
    assert_eq!(reply.status.unwrap().as_str(), "OK");
    assert_eq!(
        reply
            .payload()
            .required("generation")
            .unwrap()
            .bytes()
            .unwrap(),
        generation
    );
    assert_eq!(
        reply
            .payload()
            .required("revision")
            .unwrap()
            .uint()
            .unwrap(),
        revision
    );
}

#[test]
#[ignore = "requires an explicitly deleted and re-enrolled disposable A2 pool"]
fn old_incarnation_is_rejected_after_reenrollment() {
    let old = pool(std::env::var_os("KES_A2_OLD_ENROLLMENT_AUTHORIZATION").unwrap());
    let fresh = pool(std::env::var_os("KES_A2_ENROLLMENT_2_AUTHORIZATION").unwrap());
    let other = pool(std::env::var_os("KES_A2_ENROLLMENT_AUTHORIZATION").unwrap());
    assert_eq!(old.0, fresh.0);
    assert_ne!(old.1, fresh.1);
    let pools = [fresh, other];
    let mut wire = UsbWire::open(SELECTOR).unwrap();
    let (_, identity) = a2::open(&mut wire).unwrap();
    let (nonce, hpke, counters) = info(&mut wire, &identity, &pools);
    let context = OpenContext::new(
        DeviceId::from_bytes(identity.device),
        nonce,
        Scope::Pool {
            pool: old.0,
            incarnation: old.1,
        },
        CredentialEpoch::new(0),
        counters[0],
        RequestId::from_bytes(random()),
    );
    let key = SigningKey::from_bytes(&[0xa4; 32]);
    let seed = Zeroizing::new(random::<32>());
    let mut rng = ChaCha20Rng::from_seed(*seed);
    let (stale, _) = begin_open(context, &hpke, &key, &mut rng).unwrap();
    let mut output = [0; MAX_FRAME_BYTES];
    assert!(
        wire.exchange(&open_request(&stale), &mut output, Duration::from_secs(2))
            .is_err()
    );
    drop(wire);
    let mut wire = UsbWire::open(SELECTOR).unwrap();
    let (_, identity) = a2::open(&mut wire).unwrap();
    let (nonce, hpke, counters) = info(&mut wire, &identity, &pools);
    let session = open_pool(&mut wire, &identity, fresh, nonce, hpke, counters[0], 0xa4);
    assert!(session.is_valid());
}
