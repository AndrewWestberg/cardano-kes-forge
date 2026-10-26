use kes_core::types::{
    AbsolutePeriod, DeviceId, HardwareSlot, NetworkBinding, PoolId, RelativePeriod, Revision,
    TypeError,
};

#[test]
fn pool_id_matches_the_unmodified_cli_public_key_vector() {
    // Public verification-key bytes, not a signing seed. Independently derived
    // with cardano-cli 11.4.0.0 conway stake-pool id --output-hex.
    let pool = PoolId::from_cold_verification_key(&[0x42; 32]);
    assert_eq!(
        pool.to_string(),
        "f3edd4f4310295c8f985db0d16fe0b6fbf9105018a6782f0160a0c4c"
    );
}

#[test]
fn identity_decoding_rejects_short_ids_and_pool_labels() {
    assert_eq!(
        DeviceId::try_from(&[0_u8; 15][..]),
        Err(TypeError::InvalidLength {
            expected: 16,
            actual: 15
        })
    );
    assert_eq!(
        PoolId::try_from(&b"pool-01"[..]),
        Err(TypeError::InvalidLength {
            expected: 28,
            actual: 7
        })
    );
}

#[test]
fn checked_counters_fail_instead_of_wrapping() {
    let last = Revision::new(u64::MAX - 1).checked_increment().unwrap();
    assert_eq!(last.get(), u64::MAX);
    assert_eq!(last.checked_increment(), Err(TypeError::Overflow));
    let start = AbsolutePeriod::new(u64::MAX - 63);
    assert_eq!(start.checked_add(64), Err(TypeError::Overflow));
    assert_eq!(start.get(), u64::MAX - 63);
}

#[test]
fn primitive_period_and_internal_slot_bounds_are_distinct() {
    assert_eq!(RelativePeriod::new(63).unwrap().get(), 63);
    assert_eq!(
        RelativePeriod::new(64),
        Err(TypeError::RelativePeriodOutOfRange)
    );
    assert_eq!(HardwareSlot::new(31).unwrap().get(), 31);
    assert_eq!(HardwareSlot::new(32), Err(TypeError::SlotOutOfRange));
}

#[test]
fn enrolled_network_limits_reject_empty_or_excessive_lifetimes() {
    let create = |slots, lifetime| NetworkBinding::from_genesis_bytes(42, b"{}", slots, lifetime);
    assert_eq!(create(0, 64), Err(TypeError::ZeroSlotsPerKesPeriod));
    assert_eq!(create(64, 0), Err(TypeError::InvalidKesLifetime));
    assert_eq!(create(64, 65), Err(TypeError::InvalidKesLifetime));
    assert_eq!(create(64, 1).unwrap().max_kes_evolutions(), 1);
    assert_eq!(create(64, 64).unwrap().max_kes_evolutions(), 64);
}

#[test]
fn genesis_binding_hashes_exact_bytes_not_json_equivalence() {
    let compact =
        NetworkBinding::from_genesis_bytes(42, b"{\"networkId\":\"Testnet\"}", 64, 64).unwrap();
    let spaced =
        NetworkBinding::from_genesis_bytes(42, b"{ \"networkId\": \"Testnet\" }\n", 64, 64)
            .unwrap();
    // Independent hashlib SHA-256 observations of public JSON bytes.
    assert_eq!(
        compact.genesis_hash().to_string(),
        "7aeec87f7fa6afd2e02fed8c9d404c210340cb853e19c28e6303c867ae941702"
    );
    assert_eq!(
        spaced.genesis_hash().to_string(),
        "c70a4df8e839267f69dea342fc10940fa1376029392a53e966d8280017efbf4e"
    );
    assert_ne!(compact, spaced);
}
