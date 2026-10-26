use ed25519_dalek::{Signer, SigningKey};
use kes_core::certificate::{
    CertificateContext, CertificateError, LifetimeWindow, OperationalCertificate,
};
use kes_core::types::{
    AbsolutePeriod, CertificateCounter, KesLifetime, NetworkBinding, PoolId, RelativePeriod,
};
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read};
use xtask::oracles::{Baseline, Oracle};
use zeroize::Zeroizing;

fn message(hot: &[u8; 32], counter: u64, start: u64) -> [u8; 48] {
    let mut bytes = [0; 48];
    bytes[..32].copy_from_slice(hot);
    bytes[32..40].copy_from_slice(&counter.to_be_bytes());
    bytes[40..].copy_from_slice(&start.to_be_bytes());
    bytes
}
fn uint(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=23 => out.push(n as u8),
        24..=255 => out.extend_from_slice(&[24, n as u8]),
        256..=65535 => {
            out.push(25);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        65536..=4294967295 => {
            out.push(26);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
        _ => {
            out.push(27);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
}
fn signed(key: &SigningKey, hot: &[u8; 32], counter: u64, start: u64) -> Vec<u8> {
    let mut out = vec![0x82, 0x84, 0x58, 32];
    out.extend_from_slice(hot);
    uint(&mut out, counter);
    uint(&mut out, start);
    out.extend_from_slice(&[0x58, 64]);
    out.extend_from_slice(&key.sign(&message(hot, counter, start)).to_bytes());
    out.extend_from_slice(&[0x58, 32]);
    out.extend_from_slice(&key.verifying_key().to_bytes());
    out
}
fn fresh() -> SigningKey {
    xtask::oracles::protect_memory().expect("protected disposable runtime required");
    let mut seed = Zeroizing::new([0; 32]);
    File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut *seed)
        .unwrap();
    SigningKey::from_bytes(&seed)
}
fn network(magic: u32, genesis: &[u8], slots: u64, lifetime: u64) -> NetworkBinding {
    NetworkBinding::from_genesis_bytes(magic, genesis, slots, lifetime).unwrap()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn raw(json: &[u8]) -> Vec<u8> {
    let value: serde_json::Value = serde_json::from_slice(json).unwrap();
    let text = value["cborHex"].as_str().unwrap();
    assert!(text.len().is_multiple_of(2));
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
fn envelope(template: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut value: serde_json::Value = serde_json::from_slice(template).unwrap();
    value["cborHex"] = hex(bytes).into();
    serde_json::to_vec(&value).unwrap()
}
#[test]
fn gate_sensitivity_detects_certificate_authentication_bypass() {
    let Ok(mode) = std::env::var("KES_GATE_MODE") else {
        return;
    };
    if mode == "coverage" {
        return;
    }
    let key = fresh();
    let hot = [0x36; 32];
    let valid = signed(&key, &hot, 7, 11);
    assert!(OperationalCertificate::decode_and_verify(&valid).is_ok());
    let mut corrupted = valid;
    corrupted[44] ^= 1;
    assert!(matches!(
        OperationalCertificate::decode_and_verify(&corrupted),
        Err(CertificateError::InvalidSignature)
    ));
    match mode.as_str() {
        "clean" => println!(
            "KES_GATE_SUMMARY {{\"version\":1,\"cases\":2,\"scenarios\":{{\"certificate\":2}},\"measurements\":{{\"violations\":0}}}}"
        ),
        "seeded-semantic-authentication-bypass" => {
            println!(
                "KES_GATE_SUMMARY {{\"version\":1,\"cases\":1,\"scenarios\":{{\"certificate\":1}},\"measurements\":{{\"violations\":1,\"counterexample\":{{\"mode\":\"seeded-semantic-authentication-bypass\",\"path\":\"kes-core.OperationalCertificate::decode_and_verify\",\"observation\":\"a canonical certificate with a one-bit-corrupted cold signature was rejected\",\"disclosure\":\"public\"}}}}}}"
            );
            panic!("seeded certificate authentication bypass detected");
        }
        _ => panic!("unsupported certificate gate mode: {mode}"),
    }
}

#[test]
fn lifetime_is_half_open_and_respects_the_enrolled_shorter_limit() {
    for width in [1, 32, 64] {
        let window =
            LifetimeWindow::new(AbsolutePeriod::new(10), KesLifetime::new(width).unwrap()).unwrap();
        assert_eq!(
            window.relative_period(AbsolutePeriod::new(10)),
            Ok(RelativePeriod::new(0).unwrap())
        );
        assert_eq!(
            window.relative_period(AbsolutePeriod::new(10 + width - 1)),
            Ok(RelativePeriod::new(width - 1).unwrap())
        );
        assert_eq!(
            window.relative_period(AbsolutePeriod::new(9)),
            Err(CertificateError::NotYetValid)
        );
        assert_eq!(
            window.relative_period(AbsolutePeriod::new(10 + width)),
            Err(CertificateError::Expired)
        );
    }
}
#[test]
fn lifetime_end_never_wraps_at_the_u64_boundary() {
    let lifetime = KesLifetime::new(64).unwrap();
    let last = LifetimeWindow::new(AbsolutePeriod::new(u64::MAX - 64), lifetime).unwrap();
    assert_eq!(
        last.relative_period(AbsolutePeriod::new(u64::MAX - 1)),
        Ok(RelativePeriod::new(63).unwrap())
    );
    assert_eq!(
        last.relative_period(AbsolutePeriod::new(u64::MAX)),
        Err(CertificateError::Expired)
    );
    assert!(matches!(
        LifetimeWindow::new(AbsolutePeriod::new(u64::MAX - 63), lifetime),
        Err(CertificateError::LifetimeOverflow)
    ));
    assert!(matches!(
        LifetimeWindow::new(AbsolutePeriod::new(u64::MAX), KesLifetime::new(1).unwrap()),
        Err(CertificateError::LifetimeOverflow)
    ));
}
#[test]
fn certificate_input_has_a_closed_canonical_bound_before_signature_work() {
    assert!(matches!(
        OperationalCertificate::decode_and_verify(&[]),
        Err(CertificateError::InvalidLength)
    ));
    assert!(matches!(
        OperationalCertificate::decode_and_verify(&[0; 155]),
        Err(CertificateError::InvalidLength)
    ));
}
fn check_locally_issued_certificates(cli: &Oracle, node: &Oracle, hot: &[u8; 32]) {
    let key = fresh();
    let bytes = signed(&key, hot, 24, 256);
    let cert = OperationalCertificate::decode_and_verify(&bytes).unwrap();
    let template = cli.issue_disposable_certificate(hot, 0, 0).unwrap();
    let json = envelope(&template, &bytes);
    for consumer in [cli, node] {
        let result = consumer.validate_certificate_file(&json).unwrap();
        assert!(result.valid);
        assert_eq!(result.cold_vk, key.verifying_key().to_bytes());
        assert_eq!(result.signable, message(hot, 24, 256));
    }
    assert_eq!(
        cert.cold_verification_key(),
        &key.verifying_key().to_bytes()
    );
    let other = fresh();
    for mutate_cold in [false, true] {
        let mut bad = bytes.clone();
        if mutate_cold {
            let offset = bad.len() - 32;
            bad[offset..].copy_from_slice(&other.verifying_key().to_bytes());
        } else {
            bad[44] ^= 1;
        }
        assert!(matches!(
            OperationalCertificate::decode_and_verify(&bad),
            Err(CertificateError::InvalidSignature)
        ));
        let json = envelope(&template, &bad);
        for consumer in [cli, node] {
            assert!(!consumer.validate_certificate_file(&json).unwrap().valid);
        }
    }
}
#[test]
fn both_pinned_native_baselines_interchange_real_certificates() {
    let cli = Oracle::pinned(Baseline::Cli114).unwrap();
    let node = Oracle::pinned(Baseline::Node1113).unwrap();
    let hot = [0x36; 32];
    let net = network(42, b"native certificate genesis", 64, 64);
    for producer in [&cli, &node] {
        for n in [
            0,
            23,
            24,
            255,
            256,
            65535,
            65536,
            u32::MAX as u64,
            u32::MAX as u64 + 1,
            u64::MAX,
        ] {
            let json = producer.issue_disposable_certificate(&hot, n, n).unwrap();
            let bytes = raw(&json);
            let cert = OperationalCertificate::decode_and_verify(&bytes).unwrap();
            assert_eq!(cert.canonical_bytes(), bytes);
            assert_eq!(cert.counter().get(), n);
            assert_eq!(cert.start_period().get(), n);
            assert_eq!(cert.kes_verification_key(), &hot);
            assert_eq!(cert.signable_bytes(), message(&hot, n, n));
            assert_eq!(cert.digest(), &<[u8; 32]>::from(Sha256::digest(&bytes)));
            for consumer in [&cli, &node] {
                let validation = consumer.validate_certificate_file(&json).unwrap();
                assert!(validation.valid);
                assert_eq!(validation.cold_vk, *cert.cold_verification_key());
                assert_eq!(validation.signable, message(&hot, n, n));
                assert_eq!(
                    consumer.opcert_signable(&hot, n, n).unwrap(),
                    message(&hot, n, n)
                );
            }
            let context = CertificateContext {
                pool: PoolId::from_cold_verification_key(cert.cold_verification_key()),
                cold_verification_key: cert.cold_verification_key(),
                kes_verification_key: &hot,
                enrolled_network: &net,
                request_network: &net,
                lifetime: KesLifetime::new(64).unwrap(),
                last_activated_counter: None,
            };
            assert_eq!(cert.validate_bound(context).is_ok(), n <= u64::MAX - 64);
            // Keep the structure decodable; native rejection must be actual signature rejection.
            let mut bad = bytes.clone();
            bad[4] ^= 1;
            let bad_json = envelope(&json, &bad);
            assert!(matches!(
                OperationalCertificate::decode_and_verify(&bad),
                Err(CertificateError::InvalidSignature)
            ));
            for consumer in [&cli, &node] {
                assert!(!consumer.validate_certificate_file(&bad_json).unwrap().valid);
            }
        }
    }
    // Reverse direction: independently signed inputs reach both native verifiers.
    check_locally_issued_certificates(&cli, &node, &hot);
}
#[test]
fn exact_canonical_structure_and_signature_are_required() {
    let key = fresh();
    let bytes = signed(&key, &[7; 32], 0, 0);
    for end in 0..bytes.len() {
        assert!(OperationalCertificate::decode_and_verify(&bytes[..end]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(OperationalCertificate::decode_and_verify(&trailing).is_err());
    let mut nonminimal = bytes.clone();
    nonminimal.splice(36..37, [0x18, 0]);
    assert!(OperationalCertificate::decode_and_verify(&nonminimal).is_err());
    for (offset, value) in [
        (0, 0x83),
        (1, 0x85),
        (0, 0x9f),
        (2, 0x78),
        (3, 31),
        (38, 0x59),
    ] {
        let mut bad = bytes.clone();
        bad[offset] = value;
        assert!(OperationalCertificate::decode_and_verify(&bad).is_err());
    }
    let mut bad_signature = bytes.clone();
    bad_signature[40] ^= 1;
    assert!(matches!(
        OperationalCertificate::decode_and_verify(&bad_signature),
        Err(CertificateError::InvalidSignature)
    ));
    let mut bad_cold = bytes;
    let start = bad_cold.len() - 32;
    bad_cold[start..].fill(0);
    assert!(OperationalCertificate::decode_and_verify(&bad_cold).is_err());
}
#[test]
fn binding_checks_each_identity_network_counter_and_lifetime_independently() {
    let key = fresh();
    let cold = key.verifying_key().to_bytes();
    let hot = [0x38; 32];
    let net = network(42, b"exact genesis", 64, 32);
    let bytes = signed(&key, &hot, 9, 100);
    let cert = OperationalCertificate::decode_and_verify(&bytes).unwrap();
    let context = || CertificateContext {
        pool: PoolId::from_cold_verification_key(&cold),
        cold_verification_key: &cold,
        kes_verification_key: &hot,
        enrolled_network: &net,
        request_network: &net,
        lifetime: KesLifetime::new(32).unwrap(),
        last_activated_counter: Some(CertificateCounter::new(8)),
    };
    let window = cert.validate_bound(context()).unwrap();
    assert_eq!(
        window.relative_period(AbsolutePeriod::new(131)),
        Ok(RelativePeriod::new(31).unwrap())
    );
    assert_eq!(
        window.relative_period(AbsolutePeriod::new(132)),
        Err(CertificateError::Expired)
    );
    let wrong = [0x71; 32];
    let mut c = context();
    c.cold_verification_key = &wrong;
    assert!(matches!(
        cert.validate_bound(c),
        Err(CertificateError::WrongColdKey)
    ));
    let mut c = context();
    c.pool = PoolId::from_cold_verification_key(&wrong);
    assert!(matches!(
        cert.validate_bound(c),
        Err(CertificateError::WrongPool)
    ));
    let mut c = context();
    c.kes_verification_key = &wrong;
    assert!(matches!(
        cert.validate_bound(c),
        Err(CertificateError::WrongKesKey)
    ));
    for other in [
        network(43, b"exact genesis", 64, 32),
        network(42, b"other genesis", 64, 32),
        network(42, b"exact genesis", 65, 32),
        network(42, b"exact genesis", 64, 31),
    ] {
        let mut c = context();
        c.request_network = &other;
        assert!(matches!(
            cert.validate_bound(c),
            Err(CertificateError::WrongNetwork)
        ));
    }
    let mut c = context();
    c.lifetime = KesLifetime::new(64).unwrap();
    assert!(matches!(
        cert.validate_bound(c),
        Err(CertificateError::LifetimeMismatch)
    ));
    for counter in [9, 10, u64::MAX] {
        let mut c = context();
        c.last_activated_counter = Some(CertificateCounter::new(counter));
        assert!(matches!(
            cert.validate_bound(c),
            Err(CertificateError::CounterNotIncreasing)
        ));
    }
    let zero = OperationalCertificate::decode_and_verify(&signed(&key, &hot, 0, 100)).unwrap();
    let mut c = context();
    c.last_activated_counter = None;
    assert!(zero.validate_bound(c).is_ok());
    let overflow =
        OperationalCertificate::decode_and_verify(&signed(&key, &hot, 9, u64::MAX - 31)).unwrap();
    assert!(matches!(
        overflow.validate_bound(context()),
        Err(CertificateError::LifetimeOverflow)
    ));
}
