use kes_core::crypto::{
    AlgorithmVersion, CryptoError, Generation, KesKey, PublicTreeBuffer, SUM6_V1,
    VerifiedPublicTree, verify,
};
use kes_core::types::{KesLifetime, RelativePeriod};
use kes_summed_ed25519::kes::Sum6Kes;
use kes_summed_ed25519::traits::{KesSig, KesSk};
use std::io::{Read, Write};
use xtask::oracles::{Baseline, Oracle};
use zeroize::Zeroizing;

fn relative(n: u8) -> RelativePeriod {
    RelativePeriod::new(u64::from(n)).unwrap()
}
fn lifetime(n: u8) -> KesLifetime {
    KesLifetime::new(u64::from(n)).unwrap()
}
fn fresh_seed() -> Zeroizing<[u8; 32]> {
    xtask::oracles::protect_memory().expect("fresh no-swap disposable lab required");
    let mut seed = Zeroizing::new([0; 32]);
    std::fs::File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut *seed)
        .unwrap();
    seed
}
fn generate<'tree>(
    seed: &mut [u8; 32],
    key: &mut KesKey,
    tree: &'tree mut PublicTreeBuffer,
) -> VerifiedPublicTree<'tree> {
    let mut job = Generation::begin(seed, key, tree).unwrap();
    for leaf in 1..=64 {
        assert_eq!(job.step().unwrap(), leaf);
    }
    job.finish().unwrap()
}
fn conventional_file(bytes: &[u8; 608]) -> Zeroizing<Vec<u8>> {
    let mut file = Zeroizing::new(Vec::with_capacity(1400));
    file.extend_from_slice(b"{\"type\":\"KesSigningKey_ed25519_kes_2^6\",\"description\":\"disposable interoperability input\",\"cborHex\":\"590260");
    for byte in bytes {
        write!(&mut *file, "{byte:02x}").unwrap();
    }
    file.extend_from_slice(b"\"}");
    file
}

#[test]
fn all_periods_match_both_native_releases_and_original_rust() {
    xtask::oracles::protect_memory().expect("fresh no-swap disposable lab required");
    let oracles = [
        Oracle::pinned(Baseline::Cli114).unwrap(),
        Oracle::pinned(Baseline::Node1113).unwrap(),
    ];
    let mut seed = fresh_seed();
    let mut original_seed = Zeroizing::new(*seed);
    let (cli_vk, mut cli_state) = oracles[0].generate_from_seed(&seed).unwrap();
    let (node_vk, mut node_state) = oracles[1].generate_from_seed(&seed).unwrap();
    assert_eq!(cli_vk, node_vk);
    let mut key = KesKey::erased(lifetime(64));
    let mut tree = PublicTreeBuffer::new();
    let cache = generate(&mut seed, &mut key, &mut tree);
    let vk = key.verification_key().unwrap();
    assert_eq!(vk, cli_vk);
    let mut original_buffer = Zeroizing::new([0u8; 612]);
    let (mut original, original_vk) = Sum6Kes::keygen(&mut *original_buffer, &mut *original_seed);
    assert!(original_vk.as_bytes() == vk, "public root mismatch");
    let file = conventional_file(key.canonical_state().unwrap().bytes());
    for oracle in &oracles {
        assert_eq!(oracle.validate_signing_key_file(&file).unwrap(), vk);
    }
    drop(file);
    let public_message = [0x42; 4096];
    let mut native_signatures = 0;
    let mut native_valid = 0;
    let mut native_corrupt = 0;
    let mut native_evolutions = 0;
    let mut terminal_rejections = 0;
    for period in 0..64u8 {
        let canonical = key.canonical_state().unwrap();
        assert!(
            canonical.bytes() == cli_state.as_bytes(),
            "CLI canonical mismatch at period {period}"
        );
        assert!(
            canonical.bytes() == node_state.as_bytes(),
            "node canonical mismatch at period {period}"
        );
        assert!(
            canonical.bytes().as_slice() == &original.as_bytes()[..608],
            "original canonical mismatch at period {period}"
        );
        let restored = KesKey::from_canonical(
            canonical.algorithm(),
            canonical.bytes(),
            canonical.relative_period(),
            lifetime(64),
        )
        .unwrap();
        assert_eq!(restored.verification_key().unwrap(), vk);
        assert_eq!(oracles[0].derive_vk(&cli_state).unwrap(), vk);
        assert_eq!(oracles[1].derive_vk(&node_state).unwrap(), vk);
        for size in [0, 256, 4096] {
            let message = &public_message[..size];
            let mut signature = [0; 448];
            key.sign_into(relative(period), message, &mut signature)
                .unwrap();
            let original_signature = original.sign(message);
            assert_eq!(signature, original_signature.to_bytes());
            original_signature
                .verify(u32::from(period), &original_vk, message)
                .unwrap();
            let mut corrupted = signature;
            corrupted[0] ^= 1;
            assert_eq!(
                verify(&vk, relative(period), lifetime(64), message, &corrupted),
                Err(CryptoError::InvalidSignature)
            );
            for (oracle, state) in [(&oracles[0], &cli_state), (&oracles[1], &node_state)] {
                let native = oracle.sign(state, period, message).unwrap();
                assert_eq!(native, signature);
                native_signatures += 1;
                verify(&vk, relative(period), lifetime(64), message, &native).unwrap();
                assert!(oracle.verify(&vk, period, message, &signature).unwrap());
                native_valid += 1;
                assert!(!oracle.verify(&vk, period, message, &corrupted).unwrap());
                native_corrupt += 1;
            }
        }
        let next_cli = oracles[0].evolve(&cli_state, period).unwrap();
        let next_node = oracles[1].evolve(&node_state, period).unwrap();
        if period < 63 {
            key.evolve_to(relative(period + 1), &cache).unwrap();
            original.update().unwrap();
            cli_state = next_cli.expect("CLI ended before final period");
            node_state = next_node.expect("node ended before final period");
            native_evolutions += 2;
        } else {
            assert!(next_cli.is_none() && next_node.is_none());
            terminal_rejections += 2;
        }
    }
    println!(
        "KES_INTEROP_SUMMARY {{\"periods\":64,\"native_signatures\":{native_signatures},\"native_valid_verifications\":{native_valid},\"native_corrupt_rejections\":{native_corrupt},\"native_evolutions\":{native_evolutions},\"terminal_rejections\":{terminal_rejections}}}"
    );
    if let Ok(mode) = std::env::var("KES_GATE_MODE") {
        match mode.as_str() {
            "clean" => println!(
                "KES_GATE_SUMMARY {{\"version\":1,\"cases\":64,\"scenarios\":{{\"native-crypto\":64}},\"measurements\":{{\"violations\":0,\"periods\":64,\"independent_oracles\":2,\"mismatches\":0,\"unmodified_cli_11_4\":true,\"native_corrupt_rejections\":{native_corrupt}}}}}"
            ),
            "seeded-corrupted-signature" => {
                println!(
                    "KES_GATE_SUMMARY {{\"version\":1,\"cases\":64,\"scenarios\":{{\"native-crypto\":64}},\"measurements\":{{\"violations\":1,\"native_corrupt_rejections\":{native_corrupt},\"counterexample\":{{\"mode\":\"seeded-corrupted-signature\",\"path\":\"kes-core.crypto.verify/native-oracles\",\"observation\":\"bit 0 of a 448-byte public signature was flipped and rejected by Rust plus both native baselines\",\"disclosure\":\"public\"}}}}}}"
                );
                panic!("seeded corrupted signature detected");
            }
            "coverage" => {}
            _ => panic!("unsupported native crypto gate mode: {mode}"),
        }
    }
}

#[test]
fn shortened_enrolled_lifetimes_refuse_first_invalid_period_without_erasure() {
    for bound in [1, 32, 63] {
        let enrolled = lifetime(bound);
        let mut seed = fresh_seed();
        let mut key = KesKey::erased(enrolled);
        let mut tree = PublicTreeBuffer::new();
        let cache = generate(&mut seed, &mut key, &mut tree);
        let final_period = relative(bound - 1);
        key.evolve_to(final_period, &cache).unwrap();
        let vk = key.verification_key().unwrap();
        let message = b"public lifetime boundary";
        let mut before = [0; 448];
        key.sign_into(final_period, message, &mut before).unwrap();
        verify(&vk, final_period, enrolled, message, &before).unwrap();
        assert_eq!(
            key.evolve_to(relative(bound), &cache),
            Err(CryptoError::LifetimeExceeded)
        );
        assert_eq!(
            key.sign_into(relative(bound), message, &mut [0; 448]),
            Err(CryptoError::LifetimeExceeded)
        );
        assert_eq!(
            verify(&vk, relative(bound), enrolled, message, &before),
            Err(CryptoError::LifetimeExceeded)
        );
        let mut after = [0; 448];
        key.sign_into(final_period, message, &mut after).unwrap();
        assert_eq!(before, after);
        if bound > 1 {
            assert_eq!(
                key.evolve_to(relative(0), &cache),
                Err(CryptoError::StalePeriod)
            );
        }
    }
}

#[test]
fn canonical_import_requires_explicit_supported_metadata_and_no_rust_suffix() {
    let mut seed = fresh_seed();
    let mut key = KesKey::erased(lifetime(64));
    let mut tree = PublicTreeBuffer::new();
    let cache = generate(&mut seed, &mut key, &mut tree);
    key.evolve_to(relative(32), &cache).unwrap();
    let canonical = key.canonical_state().unwrap();
    for unsupported in [
        AlgorithmVersion {
            algorithm: 2,
            version: 1,
        },
        AlgorithmVersion {
            algorithm: 1,
            version: 2,
        },
    ] {
        assert!(matches!(
            KesKey::from_canonical(unsupported, canonical.bytes(), relative(32), lifetime(64)),
            Err(CryptoError::UnsupportedAlgorithmVersion)
        ));
    }
    let mut suffixed = Zeroizing::new([0; 612]);
    suffixed[..608].copy_from_slice(canonical.bytes());
    suffixed[608..].copy_from_slice(&32u32.to_be_bytes());
    assert!(matches!(
        KesKey::from_canonical(SUM6_V1, &*suffixed, relative(32), lifetime(64)),
        Err(CryptoError::InvalidLength {
            expected: 608,
            actual: 612
        })
    ));
    assert!(matches!(
        KesKey::from_canonical(SUM6_V1, canonical.bytes(), relative(32), lifetime(32)),
        Err(CryptoError::LifetimeExceeded)
    ));
    let mut corrupted = Zeroizing::new(*canonical.bytes());
    corrupted[0] ^= 1;
    assert!(matches!(
        KesKey::from_canonical(SUM6_V1, &*corrupted, relative(32), lifetime(64)),
        Err(CryptoError::MalformedState)
    ));
    assert!(matches!(
        KesKey::from_canonical(SUM6_V1, canonical.bytes(), relative(31), lifetime(64)),
        Err(CryptoError::MalformedState)
    ));
    let vk = key.verification_key().unwrap();
    let mut signature = [0; 448];
    key.sign_into(relative(32), b"public import check", &mut signature)
        .unwrap();
    assert_eq!(
        key.sign_into(relative(31), b"public import check", &mut [0; 448]),
        Err(CryptoError::PeriodMismatch)
    );
    assert_eq!(
        key.sign_into(relative(32), &[0; 4097], &mut [0; 448]),
        Err(CryptoError::MessageTooLong)
    );
    assert_eq!(
        verify(
            &vk,
            relative(32),
            lifetime(64),
            b"public import check",
            &signature[..447]
        ),
        Err(CryptoError::InvalidLength {
            expected: 448,
            actual: 447
        })
    );
    assert_eq!(
        verify(
            &vk,
            relative(32),
            lifetime(64),
            b"different public message",
            &signature
        ),
        Err(CryptoError::InvalidSignature)
    );
    let mut wrong_vk = vk;
    wrong_vk[0] ^= 1;
    assert_eq!(
        verify(
            &wrong_vk,
            relative(32),
            lifetime(64),
            b"public import check",
            &signature
        ),
        Err(CryptoError::InvalidSignature)
    );
    key.erase();
    assert_eq!(
        key.sign_into(relative(32), b"public import check", &mut signature),
        Err(CryptoError::ErasedKey)
    );
    assert!(matches!(key.canonical_state(), Err(CryptoError::ErasedKey)));
}
