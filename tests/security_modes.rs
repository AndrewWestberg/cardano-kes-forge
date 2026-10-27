use cardano_kes_forge::host::{bootstrap, provisioning, security};
use ed25519_dalek::{Signer, SigningKey};
use kes_core::state::{
    Actor, Device, DeviceConfig, DeviceMode, Enrollment, Health, PoolRegistration, StateError,
    UsePolicy,
};
use kes_core::types::{
    DeviceId, DeviceIdentityBinding, IncarnationId, ManagementSequence, NetworkBinding, RequestId,
    Revision,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct Directory(PathBuf);

impl Directory {
    fn new(mode: u32) -> Self {
        let nonce = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "kes-forge-security-contract-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        Self(path)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        output.push(ALPHABET[usize::from(a >> 2)] as char);
        output.push(ALPHABET[usize::from((a & 3) << 4 | b >> 4)] as char);
        output.push(if chunk.len() > 1 {
            ALPHABET[usize::from((b & 15) << 2 | c >> 6)] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            ALPHABET[usize::from(c & 63)] as char
        } else {
            '='
        });
    }
    output
}

fn spki(key: &SigningKey) -> String {
    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    der.extend(key.verifying_key().to_bytes());
    base64(&der)
}

fn pkcs8(key: &SigningKey) -> String {
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend(key.to_bytes());
    base64(&der)
}

fn authority_public(key: &SigningKey, role: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "version": 1,
        "algorithm": "Ed25519",
        "role": role,
        "publicKey": spki(key),
    }))
    .unwrap()
}

fn machine_public(key: &SigningKey, scope: &str) -> Vec<u8> {
    let (pool, incarnation) = if scope == "pool" {
        (json!("22".repeat(28)), json!("33".repeat(16)))
    } else {
        (serde_json::Value::Null, serde_json::Value::Null)
    };
    serde_json::to_vec(&json!({
        "version": 1,
        "algorithm": "Ed25519",
        "scope": scope,
        "deviceId": "11".repeat(16),
        "poolId": pool,
        "incarnationId": incarnation,
        "credentialEpoch": 0,
        "publicKey": spki(key),
    }))
    .unwrap()
}

#[test]
fn exact_authority_and_machine_schemas_keep_roles_scopes_and_keypairs_separate() {
    let management = SigningKey::from_bytes(&[0x11; 32]);
    let reviewer = SigningKey::from_bytes(&[0x12; 32]);
    let management_public = authority_public(&management, "management");
    assert!(
        bootstrap::authority_public(&management_public, bootstrap::AuthorityRole::Management)
            .is_ok()
    );
    assert_eq!(
        bootstrap::authority_public(
            &management_public,
            bootstrap::AuthorityRole::ProvisioningReviewer,
        ),
        Err(bootstrap::Error::WrongRole)
    );
    assert!(
        bootstrap::authority_public(
            &authority_public(&reviewer, "provisioning-reviewer"),
            bootstrap::AuthorityRole::ProvisioningReviewer,
        )
        .is_ok()
    );

    let private = serde_json::to_vec(&json!({
        "version": 1,
        "algorithm": "Ed25519",
        "role": "management",
        "publicKey": spki(&management),
        "privateKey": pkcs8(&management),
    }))
    .unwrap();
    assert!(bootstrap::authority_private(&private, bootstrap::AuthorityRole::Management).is_ok());
    let mismatched = String::from_utf8(private)
        .unwrap()
        .replace(&pkcs8(&management), &pkcs8(&reviewer));
    assert_eq!(
        bootstrap::authority_private(mismatched.as_bytes(), bootstrap::AuthorityRole::Management,)
            .err(),
        Some(bootstrap::Error::WrongIdentity)
    );

    let transport = machine_public(&management, "management");
    assert!(bootstrap::machine_public(&transport, bootstrap::MachineScope::Management).is_ok());
    assert_eq!(
        bootstrap::machine_public(&transport, bootstrap::MachineScope::Pool),
        Err(bootstrap::Error::WrongScope)
    );
    for required in ["poolId", "incarnationId"] {
        let mut missing: serde_json::Value = serde_json::from_slice(&transport).unwrap();
        missing.as_object_mut().unwrap().remove(required);
        assert_eq!(
            bootstrap::machine_public(
                &serde_json::to_vec(&missing).unwrap(),
                bootstrap::MachineScope::Management,
            ),
            Err(bootstrap::Error::InvalidSchema)
        );
    }
    let extra = String::from_utf8(management_public)
        .unwrap()
        .replace("\"version\":1", "\"version\":1,\"unexpected\":true");
    assert_eq!(
        bootstrap::authority_public(extra.as_bytes(), bootstrap::AuthorityRole::Management),
        Err(bootstrap::Error::InvalidSchema)
    );
}

#[test]
fn private_custody_paths_require_regular_owner_only_file_and_parent() {
    let directory = Directory::new(0o700);
    let private = directory.0.join("authority.key");
    fs::write(&private, b"private").unwrap();
    fs::set_permissions(&private, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(bootstrap::validate_private_path(&private), Ok(()));

    fs::set_permissions(&private, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        bootstrap::validate_private_path(&private),
        Err(bootstrap::Error::UnsafePath)
    );
    fs::set_permissions(&private, fs::Permissions::from_mode(0o600)).unwrap();
    let link = directory.0.join("authority-link.key");
    symlink(&private, &link).unwrap();
    assert_eq!(
        bootstrap::validate_private_path(&link),
        Err(bootstrap::Error::UnsafePath)
    );

    let unsafe_directory = Directory::new(0o755);
    let unsafe_private = unsafe_directory.0.join("authority.key");
    fs::write(&unsafe_private, b"private").unwrap();
    fs::set_permissions(&unsafe_private, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        bootstrap::validate_private_path(&unsafe_private),
        Err(bootstrap::Error::UnsafePath)
    );
}

#[test]
fn daemon_schema_supports_zero_pool_bootstrap_and_exact_uid_authorizations() {
    let valid = serde_json::to_vec(&json!({
        "version": 1,
        "socketPath": "/run/kes-forged.sock",
        "usbDevice": "bus=1,address=13",
        "deviceConfigFile": "device.json",
        "poolConnectionFiles": [],
        "allowedPeerUids": [
            {"uid": 1000, "connections": ["management"]},
            {"uid": 1001, "connections": ["pool-0", "pool-1"]}
        ]
    }))
    .unwrap();
    let parsed = bootstrap::daemon_config(&valid).unwrap();
    assert!(parsed.pool_connection_files.is_empty());
    assert_eq!(
        parsed.allowed_peer_uids[1].connections,
        ["pool-0", "pool-1"]
    );

    let duplicate_uid = String::from_utf8(valid.clone())
        .unwrap()
        .replace("\"uid\":1001", "\"uid\":1000");
    assert_eq!(
        bootstrap::daemon_config(duplicate_uid.as_bytes()),
        Err(bootstrap::Error::InvalidSchema)
    );
    let duplicate_connection = String::from_utf8(valid)
        .unwrap()
        .replace("\"pool-1\"", "\"pool-0\"");
    assert_eq!(
        bootstrap::daemon_config(duplicate_connection.as_bytes()),
        Err(bootstrap::Error::InvalidSchema)
    );
}

#[test]
fn fresh_signed_online_evidence_enforces_modes_pins_and_no_release_downgrade() {
    let identity = SigningKey::from_bytes(&[0x21; 32]);
    let mut pins = security::Pins {
        device: [0x31; 16],
        identity_public_key: identity.verifying_key().to_bytes(),
        silicon_revision: 2,
        rom_revision: "RP2350-ROM-A2".to_owned(),
        flash_part: "W25Q32JV".to_owned(),
        flash_capacity_bytes: 4_194_304,
        firmware_digest: [0x41; 32],
        hardware_policy_digest: [0x42; 32],
        security_version: 7,
    };
    let challenge = [0x51; 32];
    let mut evidence = security::OnlineEvidence {
        mode: security::Mode::Development,
        challenge,
        boot_nonce: [0x52; 32],
        device: pins.device,
        silicon_revision: pins.silicon_revision,
        rom_revision: pins.rom_revision.clone(),
        flash_part: pins.flash_part.clone(),
        flash_capacity_bytes: pins.flash_capacity_bytes,
        firmware_digest: [0; 32],
        hardware_policy_digest: [0; 32],
        security_version: 0,
        signature: [0; 64],
    };
    evidence.signature = identity
        .sign(&security::evidence_message(&evidence))
        .to_bytes();
    let mut verifier = security::ReadinessVerifier::default();
    assert_eq!(
        verifier.verify(&pins, challenge, evidence.clone(), false),
        Err(security::Error::DevelopmentOptInRequired)
    );
    assert!(
        verifier
            .verify(&pins, challenge, evidence.clone(), true)
            .is_ok()
    );
    assert_eq!(
        verifier.verify(&pins, challenge, evidence.clone(), true),
        Err(security::Error::ReplayedChallenge)
    );
    assert_eq!(
        verifier.verify(&pins, [0x53; 32], evidence.clone(), true),
        Err(security::Error::StaleChallenge)
    );

    evidence.mode = security::Mode::ReleaseUnprovisioned;
    evidence.challenge = [0x54; 32];
    evidence.signature = identity
        .sign(&security::evidence_message(&evidence))
        .to_bytes();
    assert_eq!(
        verifier.verify(&pins, evidence.challenge, evidence.clone(), false),
        Err(security::Error::NotReady)
    );
    evidence.mode = security::Mode::ReleaseReady;
    evidence.challenge = [0x55; 32];
    evidence.firmware_digest = pins.firmware_digest;
    evidence.hardware_policy_digest = pins.hardware_policy_digest;
    evidence.security_version = pins.security_version;
    evidence.signature = identity
        .sign(&security::evidence_message(&evidence))
        .to_bytes();
    assert_eq!(
        verifier.verify(&pins, evidence.challenge, evidence.clone(), false),
        Err(security::Error::UnsupportedSilicon)
    );
    pins.silicon_revision = 4;
    pins.rom_revision = "RP2350-ROM-A4".to_owned();
    evidence.silicon_revision = pins.silicon_revision;
    evidence.rom_revision = pins.rom_revision.clone();
    evidence.challenge = [0x56; 32];
    evidence.signature = identity
        .sign(&security::evidence_message(&evidence))
        .to_bytes();
    assert!(
        verifier
            .verify(&pins, evidence.challenge, evidence.clone(), false)
            .is_ok()
    );
    evidence.challenge = [0x57; 32];
    evidence.firmware_digest[0] ^= 1;
    evidence.signature = identity
        .sign(&security::evidence_message(&evidence))
        .to_bytes();
    assert_eq!(
        verifier.verify(&pins, evidence.challenge, evidence, false),
        Err(security::Error::PinMismatch)
    );
    assert_eq!(
        security::validate_transition(
            security::Mode::ReleaseUnprovisioned,
            security::Mode::Development,
        ),
        Err(security::Error::ReleaseDowngrade)
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn digest(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

#[test]
fn provisioning_manifest_requires_exact_a4_inputs_distinct_authorities_and_consent() {
    let directory = Directory::new(0o700);
    let management = SigningKey::from_bytes(&[0x61; 32]);
    let reviewer = SigningKey::from_bytes(&[0x62; 32]);
    let files = [
        ("inspection.json", b"inspection".as_slice()),
        ("policy.json", b"policy".as_slice()),
        ("recipe.json", b"recipe".as_slice()),
        ("firmware.bin", b"firmware".as_slice()),
        ("partition.json", b"partition".as_slice()),
    ];
    for (name, bytes) in files {
        fs::write(directory.0.join(name), bytes).unwrap();
    }
    let management_bytes = authority_public(&management, "management");
    let transport_bytes = machine_public(&management, "management");
    let reviewer_bytes = authority_public(&reviewer, "provisioning-reviewer");
    fs::write(directory.0.join("management.json"), &management_bytes).unwrap();
    fs::write(directory.0.join("transport.json"), &transport_bytes).unwrap();
    fs::write(directory.0.join("reviewer.json"), &reviewer_bytes).unwrap();

    let mut manifest_value = json!({
        "version": 1,
        "ceremonyId": "aa".repeat(16),
        "deviceId": "11".repeat(16),
        "usbDevice": "bus=1,address=13",
        "inspectionFile": "inspection.json",
        "inspectionDigest": digest(b"inspection"),
        "siliconRevision": "A4",
        "romRevision": "RP2350-ROM-A4",
        "flashPart": "W25Q32JV",
        "flashCapacityBytes": 4194304u64,
        "policyFile": "policy.json",
        "policyDigest": digest(b"policy"),
        "recipeFile": "recipe.json",
        "recipeDigest": digest(b"recipe"),
        "firmwareFile": "firmware.bin",
        "firmwareDigest": digest(b"firmware"),
        "partitionManifestFile": "partition.json",
        "partitionManifestDigest": digest(b"partition"),
        "bootKeyFingerprint": "bb".repeat(32),
        "securityVersion": 1,
        "managementPublicKeyFile": "management.json",
        "managementPublicKeyDigest": digest(&management_bytes),
        "managementTransportPublicKeyFile": "transport.json",
        "managementTransportPublicKeyDigest": digest(&transport_bytes),
        "reviewerPublicKeyFile": "reviewer.json",
        "reviewerPublicKeyDigest": digest(&reviewer_bytes),
        "steps": [
            {"index": 0, "action": "install-image", "target": "FLASH_SLOT_A", "before": "empty", "after": "verified", "irreversible": false},
            {"index": 1, "action": "otp-lock", "target": "CRIT1", "before": "unlocked", "after": "locked", "irreversible": true}
        ],
        "signature": null
    });
    let unsigned_signature_bytes = serde_json::to_vec(&manifest_value).unwrap();
    let manifest_signature = reviewer
        .sign(&provisioning::manifest_signature_message(&unsigned_signature_bytes).unwrap())
        .to_bytes();
    manifest_value["signature"] = json!(base64(&manifest_signature));
    let bytes = serde_json::to_vec(&manifest_value).unwrap();
    let mut manifest = provisioning::parse_manifest(&bytes).unwrap();
    provisioning::validate_references(&manifest, &directory.0).unwrap();
    assert_eq!(
        provisioning::authorize_apply(&manifest, false),
        Err(provisioning::Error::IrreversibleConsentRequired)
    );
    assert_eq!(provisioning::authorize_apply(&manifest, true), Ok(()));

    let mut record = json!({
        "version": 1,
        "ceremonyId": "aa".repeat(16),
        "manifestDigest": digest(&bytes),
        "deviceId": "11".repeat(16),
        "identityPublicKey": spki(&management),
        "hpkePublicKey": "cc".repeat(32),
        "managementPublicKey": spki(&management),
        "managementTransportPublicKey": spki(&management),
        "credentialEpoch": 0,
        "siliconRevision": "A4",
        "romRevision": "RP2350-ROM-A4",
        "flashPart": "W25Q32JV",
        "flashCapacityBytes": 4194304u64,
        "bootKeyFingerprint": "bb".repeat(32),
        "policyDigest": digest(b"policy"),
        "firmwareDigest": digest(b"firmware"),
        "securityVersion": 1,
        "toolVersion": "2.3.1",
        "toolDigest": "dd".repeat(32),
        "results": [
            {"index": 0, "observed": "verified", "passed": true},
            {"index": 1, "observed": "locked", "passed": true}
        ],
        "completedAt": "2026-01-02T03:04:05Z",
        "reviewerPublicKey": spki(&reviewer),
        "signature": base64(&[0; 64])
    });
    let unsigned_record = serde_json::to_vec(&record).unwrap();
    let record_signature = reviewer
        .sign(&provisioning::record_signature_message(&unsigned_record).unwrap())
        .to_bytes();
    record["signature"] = json!(base64(&record_signature));
    let record_bytes = serde_json::to_vec(&record).unwrap();
    let identity = cardano_kes_forge::host::config::DeviceIdentity {
        device_id: [0x11; 16],
        identity_public_key: management.verifying_key().to_bytes(),
        hpke_public_key: [0xcc; 32],
        management_public_key: management.verifying_key().to_bytes(),
        management_transport_public_key: management.verifying_key().to_bytes(),
        credential_epoch: 0,
        boot_key_fingerprint: [0xbb; 32],
        hardware_policy_digest: Sha256::digest(b"policy").into(),
        firmware_digest: Sha256::digest(b"firmware").into(),
        security_version: 1,
        provisioning_record_file: directory.0.join("record.json"),
        provisioning_manifest_file: directory.0.join("manifest.json"),
        reviewer_public_key_file: directory.0.join("reviewer.json"),
    };
    assert!(
        provisioning::verify_release_readiness(&identity, &bytes, &record_bytes, &reviewer_bytes,)
            .is_ok()
    );
    assert_eq!(
        provisioning::verify_release_readiness(
            &identity,
            &unsigned_signature_bytes,
            &record_bytes,
            &reviewer_bytes,
        ),
        Err(provisioning::Error::Unsigned)
    );

    let mut initial_security_version = manifest_value.clone();
    initial_security_version["securityVersion"] = json!(0);
    assert!(
        provisioning::parse_manifest(&serde_json::to_vec(&initial_security_version).unwrap())
            .is_ok()
    );

    let mut missing_signature = manifest_value.clone();
    missing_signature
        .as_object_mut()
        .unwrap()
        .remove("signature");
    assert_eq!(
        provisioning::parse_manifest(&serde_json::to_vec(&missing_signature).unwrap()),
        Err(provisioning::Error::InvalidSchema)
    );

    let mut a2 = manifest_value.clone();
    a2["siliconRevision"] = json!("A2");
    assert_eq!(
        provisioning::parse_manifest(&serde_json::to_vec(&a2).unwrap()),
        Err(provisioning::Error::UnsupportedHardware)
    );
    let wrong_reviewer = authority_public(&management, "management");
    fs::write(directory.0.join("reviewer.json"), &wrong_reviewer).unwrap();
    manifest.reviewer_public_key_digest = digest(&wrong_reviewer);
    assert_eq!(
        provisioning::validate_references(&manifest, &directory.0),
        Err(provisioning::Error::AuthorityMismatch)
    );
    fs::write(directory.0.join("reviewer.json"), &reviewer_bytes).unwrap();
    manifest.reviewer_public_key_digest = digest(&reviewer_bytes);

    fs::remove_file(directory.0.join("inspection.json")).unwrap();
    assert_eq!(
        provisioning::validate_references(&manifest, &directory.0),
        Err(provisioning::Error::MissingPrerequisite)
    );
}

#[test]
fn enrollment_precedes_daemon_configuration_and_device_policy_rejects_production_on_a2() {
    let identity =
        DeviceIdentityBinding::new(DeviceId::from_bytes([0x81; 16]), [0x82; 32], [0x83; 32]);
    let mut device = Device::new(DeviceConfig {
        identity,
        silicon_revision: 2,
        firmware_digest: [0x84; 32],
        security_version: 0,
        hardware_policy_digest: [0x85; 32],
        mode: DeviceMode::Development,
        health: Health::Healthy,
        management_root_public_key: [0x86; 32],
        management_transport_public_key: [0x8c; 32],
    });
    let recipient = [0x87; 32];
    let pool = PoolRegistration::new(
        Actor::Management,
        Enrollment {
            incarnation: IncarnationId::from_bytes([0x88; 16]),
            cold_verification_key: [0x89; 32],
            network: NetworkBinding::from_genesis_bytes(42, b"bootstrap", 64, 64).unwrap(),
            machine_public_key: [0x8a; 32],
            recipient_public_key: recipient,
            recipient_id: Sha256::digest(recipient).into(),
            management_sequence: ManagementSequence::new(1),
            management_request: RequestId::from_bytes([0x8b; 16]),
            management_payload_digest: [0x8c; 32],
        },
    )
    .unwrap();
    device
        .enroll(Actor::Management, &pool, Revision::new(0))
        .unwrap();
    assert_eq!(device.pool_count(), 1);
    assert_eq!(
        device.ensure_operational(UsePolicy::Production, None),
        Err(StateError::DevelopmentOptInRequired)
    );
    assert_eq!(
        device.ensure_operational(UsePolicy::IsolatedDevelopment, None),
        Ok(())
    );
}
