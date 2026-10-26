#![no_main]
use kes_core::certificate::{
    CertificateContext, CertificateError, LifetimeWindow, MAX_CANONICAL_CERTIFICATE_BYTES,
    OperationalCertificate,
};
use kes_core::types::{
    AbsolutePeriod, CertificateCounter, KesLifetime, NetworkBinding, PoolId, RelativePeriod,
};
use libfuzzer_sys::fuzz_target;
use std::sync::{
    Once,
    atomic::{AtomicU64, Ordering},
};

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
        // A no-argument process-exit callback, no pointers across the FFI and no
        // unwinding. Inputs/certificates here are public; no private key exists.
        if unsafe { libc::atexit(summary) } != 0 {
            std::process::exit(2);
        }
    });
}
fn check_window(window: &LifetimeWindow, start: u64, width: u64, end: u64) {
    check(
        window.relative_period(AbsolutePeriod::new(start)) == Ok(RelativePeriod::new(0).unwrap()),
    );
    check(
        window.relative_period(AbsolutePeriod::new(end - 1))
            == Ok(RelativePeriod::new(width - 1).unwrap()),
    );
    check(window.relative_period(AbsolutePeriod::new(end)) == Err(CertificateError::Expired));
    if start != 0 {
        check(
            window.relative_period(AbsolutePeriod::new(start - 1))
                == Err(CertificateError::NotYetValid),
        );
    }
}
fn arithmetic(data: &[u8]) {
    let start = data
        .iter()
        .take(8)
        .fold(0u64, |n, b| (n << 8) | u64::from(*b));
    let width = u64::from(data.get(8).copied().unwrap_or(0) % 64) + 1;
    let wide_end = u128::from(start) + u128::from(width);
    match (
        LifetimeWindow::new(AbsolutePeriod::new(start), KesLifetime::new(width).unwrap()),
        wide_end <= u128::from(u64::MAX),
    ) {
        (Ok(window), true) => check_window(&window, start, width, wide_end as u64),
        (Err(CertificateError::LifetimeOverflow), false) => check(true),
        _ => check(false),
    }
    // Every iteration reaches checked-add overflow and the last valid endpoint,
    // even when parser mutations contain no authentic cold signature.
    check(matches!(
        LifetimeWindow::new(AbsolutePeriod::new(u64::MAX), KesLifetime::new(1).unwrap()),
        Err(CertificateError::LifetimeOverflow)
    ));
    let last = LifetimeWindow::new(
        AbsolutePeriod::new(u64::MAX - 64),
        KesLifetime::new(64).unwrap(),
    )
    .unwrap();
    check_window(&last, u64::MAX - 64, 64, u64::MAX);
}
fn context<'a>(
    certificate: &'a OperationalCertificate,
    network: &'a NetworkBinding,
    lifetime: KesLifetime,
) -> CertificateContext<'a> {
    CertificateContext {
        pool: PoolId::from_cold_verification_key(certificate.cold_verification_key()),
        cold_verification_key: certificate.cold_verification_key(),
        kes_verification_key: certificate.kes_verification_key(),
        enrolled_network: network,
        request_network: network,
        lifetime,
        last_activated_counter: None,
    }
}
fn bindings(certificate: &OperationalCertificate, width: u64) {
    let lifetime = KesLifetime::new(width).unwrap();
    let network =
        NetworkBinding::from_genesis_bytes(42, b"public certificate fuzz genesis", 64, width)
            .unwrap();
    let start = certificate.start_period().get();
    let wide_end = u128::from(start) + u128::from(width);
    match (
        certificate.validate_bound(context(certificate, &network, lifetime)),
        wide_end <= u128::from(u64::MAX),
    ) {
        (Ok(window), true) => check_window(&window, start, width, wide_end as u64),
        (Err(CertificateError::LifetimeOverflow), false) => {
            check(true);
            return;
        }
        _ => {
            check(false);
            return;
        }
    }
    let mut equal_counter = context(certificate, &network, lifetime);
    equal_counter.last_activated_counter = Some(certificate.counter());
    check(
        certificate.validate_bound(equal_counter).err()
            == Some(CertificateError::CounterNotIncreasing),
    );
    if certificate.counter().get() != 0 {
        let mut prior_counter = context(certificate, &network, lifetime);
        prior_counter.last_activated_counter =
            Some(CertificateCounter::new(certificate.counter().get() - 1));
        check(certificate.validate_bound(prior_counter).is_ok());
    }
    let mut wrong_vk = *certificate.kes_verification_key();
    wrong_vk[0] ^= 1;
    let mut wrong_key = context(certificate, &network, lifetime);
    wrong_key.kes_verification_key = &wrong_vk;
    check(certificate.validate_bound(wrong_key).err() == Some(CertificateError::WrongKesKey));
    let mut foreign_pool = [0u8; 28];
    foreign_pool.copy_from_slice(
        PoolId::from_cold_verification_key(certificate.cold_verification_key()).as_bytes(),
    );
    foreign_pool[0] ^= 1;
    let mut wrong_pool = context(certificate, &network, lifetime);
    wrong_pool.pool = PoolId::from_bytes(foreign_pool);
    check(certificate.validate_bound(wrong_pool).err() == Some(CertificateError::WrongPool));
    for foreign in [
        NetworkBinding::from_genesis_bytes(43, b"public certificate fuzz genesis", 64, width)
            .unwrap(),
        NetworkBinding::from_genesis_bytes(42, b"other public certificate fuzz genesis", 64, width)
            .unwrap(),
        NetworkBinding::from_genesis_bytes(42, b"public certificate fuzz genesis", 65, width)
            .unwrap(),
        NetworkBinding::from_genesis_bytes(
            42,
            b"public certificate fuzz genesis",
            64,
            if width == 64 { 63 } else { width + 1 },
        )
        .unwrap(),
    ] {
        let mut wrong_network = context(certificate, &network, lifetime);
        wrong_network.request_network = &foreign;
        check(
            certificate.validate_bound(wrong_network).err() == Some(CertificateError::WrongNetwork),
        );
    }
    let alternate_lifetime = KesLifetime::new(if width == 64 { 63 } else { width + 1 }).unwrap();
    check(
        certificate
            .validate_bound(context(certificate, &network, alternate_lifetime))
            .err()
            == Some(CertificateError::LifetimeMismatch),
    );
}
fn corruptions(certificate: &OperationalCertificate) {
    let original = certificate.canonical_bytes();
    let mut corrupted = [0u8; MAX_CANONICAL_CERTIFICATE_BYTES + 1];
    corrupted[..original.len()].copy_from_slice(original);
    // The final cold-key bytestring occupies34 bytes. Set the high S bit of
    // the preceding Ed25519 signature, preserving canonical CBOR structure.
    corrupted[original.len() - 35] ^= 0x80;
    check(OperationalCertificate::decode_and_verify(&corrupted[..original.len()]).is_err());
    corrupted[original.len() - 35] ^= 0x80;
    check(OperationalCertificate::decode_and_verify(&corrupted[..original.len() + 1]).is_err());
}
fuzz_target!(|data: &[u8]| {
    initialize();
    arithmetic(data);
    check(matches!(
        OperationalCertificate::decode_and_verify(&[]),
        Err(CertificateError::InvalidLength)
    ));
    check(matches!(
        OperationalCertificate::decode_and_verify(&[0u8; MAX_CANONICAL_CERTIFICATE_BYTES + 1]),
        Err(CertificateError::InvalidLength)
    ));
    if let Ok(certificate) = OperationalCertificate::decode_and_verify(data) {
        // These independently minted public corpus seeds reach actual cold
        // signature verification and each policy boundary without a private
        // signing seed in the fuzz process or corpus.
        for width in [1, 32, 64] {
            bindings(&certificate, width);
        }
        corruptions(&certificate);
    }
});
