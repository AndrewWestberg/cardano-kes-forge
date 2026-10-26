use kes_core::state::{
    Actor, Device, DeviceConfig, DeviceMode, Enrollment, Health, PoolRegistration, StateError,
    UsePolicy,
};
use kes_core::types::{
    DeviceId, DeviceIdentityBinding, IncarnationId, ManagementSequence, NetworkBinding, RequestId,
};
use sha2::{Digest, Sha256};

#[path = "lifecycle_properties/model.rs"]
mod model;
#[path = "support/mod.rs"]
mod support;

fn device(mode: DeviceMode, revision: u8) -> Device {
    Device::new(DeviceConfig {
        identity: DeviceIdentityBinding::new(
            DeviceId::from_bytes([0x19; 16]),
            [0x42; 32],
            [0x29; 32],
        ),
        silicon_revision: revision,
        firmware_digest: [0x37; 32],
        security_version: 1,
        hardware_policy_digest: [0x43; 32],
        mode,
        health: Health::Healthy,
        management_root_public_key: [0x51; 32],
        management_transport_public_key: [0x52; 32],
    })
}
fn registration(index: u8) -> PoolRegistration {
    let mut cold = [0x42; 32];
    cold[0] = index;
    registration_with_cold(index, cold)
}
fn registration_with_cold(index: u8, cold: [u8; 32]) -> PoolRegistration {
    let recipient = [0x73; 32];
    PoolRegistration::new(
        Actor::Management,
        Enrollment {
            incarnation: IncarnationId::from_bytes([index; 16]),
            cold_verification_key: cold,
            network: NetworkBinding::from_genesis_bytes(
                42,
                b"public lifecycle model genesis",
                64,
                64,
            )
            .unwrap(),
            machine_public_key: [0x61; 32],
            recipient_public_key: recipient,
            recipient_id: Sha256::digest(recipient).into(),
            management_sequence: ManagementSequence::new(1),
            management_request: RequestId::from_bytes([index; 16]),
            management_payload_digest: [index; 32],
        },
    )
    .unwrap()
}
#[test]
fn directory_capacity_preserves_full_pool_identity_and_stable_slots() {
    let mut device = device(DeviceMode::Development, 2);
    let mut previous = [None; 32];
    for index in 0..32u8 {
        let pool = registration(index);
        let id = pool.pool_id();
        let slot = device
            .enroll(Actor::Management, &pool, device.directory_revision())
            .unwrap();
        previous[usize::from(index)] = Some((id, slot));
        for (id, slot) in previous.iter().flatten() {
            assert_eq!(device.find(*id).unwrap().slot(), *slot);
        }
    }
    let identities: Vec<String> = previous
        .iter()
        .flatten()
        .map(|(pool, _)| {
            pool.as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect()
        })
        .collect();
    println!(
        "KES_POOL_IDENTITIES {}",
        serde_json::to_string(&identities).unwrap()
    );
    let extra = registration(32);
    assert_eq!(
        device.enroll(Actor::Management, &extra, device.directory_revision()),
        Err(StateError::Capacity)
    );
    assert_eq!(device.pool_count(), 32);
    let actor = Actor::Pool {
        pool: extra.pool_id(),
        incarnation: extra.incarnation(),
    };
    assert_eq!(
        device.enroll(actor, &extra, device.directory_revision()),
        Err(StateError::Unauthorized)
    );
    assert_eq!(device.pool_count(), 32);
}
#[test]
fn a_release_label_is_not_verified_readiness_and_development_is_explicit() {
    let release = device(DeviceMode::Release, 4);
    assert_eq!(
        release.ensure_operational(UsePolicy::Production, None),
        Err(StateError::SecurityNotReady)
    );
    let development = device(DeviceMode::Development, 2);
    assert_eq!(
        development.ensure_operational(UsePolicy::Production, None),
        Err(StateError::DevelopmentOptInRequired)
    );
    development
        .ensure_operational(UsePolicy::IsolatedDevelopment, None)
        .unwrap();
}
