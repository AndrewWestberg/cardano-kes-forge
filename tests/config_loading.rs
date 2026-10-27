use cardano_kes_forge::host::config::{
    DaemonConfig, DeviceConfig, DeviceConnection, Error, PublicPoolConnection,
};
use ed25519_dalek::SigningKey;
use serde_json::json;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
const DEVICE: &str = "01010101010101010101010101010101";
const POOL: &str = "02020202020202020202020202020202020202020202020202020202";
const INCARNATION: &str = "03030303030303030303030303030303";
const DIGEST: &str = "0404040404040404040404040404040404040404040404040404040404040404";

struct Fixture {
    root: PathBuf,
    daemon: PathBuf,
    pool_credential: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "kes-forge-config-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let management = SigningKey::from_bytes(&[5; 32]);
        let pool = SigningKey::from_bytes(&[6; 32]);
        let management_spki = spki(&management);
        let pool_spki = spki(&pool);
        for name in ["record.json", "manifest.json", "reviewer.json"] {
            write(&root.join(name), b"{}", 0o644);
        }
        write_json(
            &root.join("identity.json"),
            &json!({
                "version": 1, "deviceId": DEVICE,
                "identityPublicKey": management_spki,
                "hpkePublicKey": DIGEST,
                "managementPublicKey": management_spki,
                "managementTransportPublicKey": management_spki,
                "credentialEpoch": 0, "bootKeyFingerprint": DIGEST,
                "hardwarePolicyDigest": DIGEST, "firmwareDigest": DIGEST,
                "securityVersion": 1, "provisioningRecordFile": "record.json",
                "provisioningManifestFile": "manifest.json", "reviewerPublicKeyFile": "reviewer.json"
            }),
            0o644,
        );
        write_json(
            &root.join("management.key.json"),
            &json!({
                "version": 1, "algorithm": "Ed25519", "scope": "management",
                "deviceId": DEVICE, "poolId": null, "incarnationId": null,
                "credentialEpoch": 0, "publicKey": management_spki,
                "privateKey": pkcs8(&management)
            }),
            0o600,
        );
        let pool_credential = root.join("pool.key.json");
        write_json(
            &pool_credential,
            &json!({
                "version": 1, "algorithm": "Ed25519", "scope": "pool",
                "deviceId": DEVICE, "poolId": POOL, "incarnationId": INCARNATION,
                "credentialEpoch": 0, "publicKey": pool_spki, "privateKey": pkcs8(&pool)
            }),
            0o600,
        );
        write_json(
            &root.join("device.json"),
            &json!({
                "version": 1, "socketPath": "kes.sock", "deviceId": DEVICE,
                "deviceIdentityFile": "identity.json", "connectionName": "mgmt",
                "credentialFile": "management.key.json", "credentialEpoch": 0,
                "securityPolicy": "isolated-development"
            }),
            0o644,
        );
        write_json(
            &root.join("pool.json"),
            &json!({
                "version": 1, "socketPath": "kes.sock", "deviceId": DEVICE,
                "deviceIdentityFile": "identity.json", "poolId": POOL,
                "incarnationId": INCARNATION,
                "networkBinding": {"networkMagic": 42, "shelleyGenesisDigest": DIGEST,
                    "slotsPerKesPeriod": 64, "maxKesEvolutions": 64},
                "connectionName": "pool-0", "credentialFile": "pool.key.json",
                "securityPolicy": "isolated-development"
            }),
            0o644,
        );
        let daemon = root.join("daemon.json");
        write_json(
            &daemon,
            &json!({
                "version": 1, "socketPath": "kes.sock", "usbDevice": "stable-selector",
                "deviceConfigFile": "device.json", "poolConnectionFiles": ["pool.json"],
                "allowedPeerUids": [{"uid": rustix::process::getuid().as_raw(),
                    "connections": ["mgmt", "pool-0"]}]
            }),
            0o644,
        );
        Self {
            root,
            daemon,
            pool_credential,
        }
    }

    fn management_candidate(&self, key: &SigningKey, epoch: u64) {
        let path = self.root.join("management.key.json");
        let mut credential: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        credential["publicKey"] = json!(spki(key));
        credential["privateKey"] = json!(pkcs8(key));
        credential["credentialEpoch"] = json!(epoch);
        write_json(&path, &credential, 0o600);
        set_field(
            &self.root.join("device.json"),
            "credentialEpoch",
            json!(epoch),
            0o644,
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn complete_relative_configuration_graph_is_cross_checked() {
    let fixture = Fixture::new();
    let config = DaemonConfig::load(&fixture.daemon).unwrap();
    assert_eq!(config.socket_path, fixture.root.join("kes.sock"));
    assert_eq!(config.device.connection_name, "mgmt");
    assert_eq!(config.pools.len(), 1);
    assert_eq!(config.pools[0].connection_name, "pool-0");
    assert_eq!(config.pools[0].credential.epoch, 0);
}

#[test]
fn operator_management_connection_does_not_open_daemon_private_credentials() {
    let fixture = Fixture::new();
    let device_path = fixture.root.join("device.json");
    fs::remove_file(fixture.root.join("management.key.json")).unwrap();
    let public = DeviceConnection::load(&device_path).unwrap();
    assert_eq!(public.socket_path, fixture.root.join("kes.sock"));
    assert_eq!(public.connection_name, "mgmt");
    assert_eq!(public.device_id, public.identity.device_id);
    assert_eq!(
        DeviceConfig::load(&device_path).err(),
        Some(Error::Unreadable)
    );

    let bytes = fs::read_to_string(&device_path).unwrap();
    write(
        &device_path,
        bytes
            .replace(DEVICE, "ffffffffffffffffffffffffffffffff")
            .as_bytes(),
        0o644,
    );
    assert_eq!(
        DeviceConnection::load(&device_path).err(),
        Some(Error::Security)
    );
}

#[test]
fn private_credential_mode_and_unknown_uid_mapping_fail_closed() {
    let fixture = Fixture::new();
    fs::set_permissions(&fixture.pool_credential, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        DaemonConfig::load(&fixture.daemon).err(),
        Some(Error::Security)
    );

    fs::set_permissions(&fixture.pool_credential, fs::Permissions::from_mode(0o600)).unwrap();
    let bytes = fs::read_to_string(&fixture.daemon).unwrap();
    let changed = bytes.replace("pool-0", "not-registered");
    write(&fixture.daemon, changed.as_bytes(), 0o644);
    assert_eq!(
        DaemonConfig::load(&fixture.daemon).err(),
        Some(Error::Security)
    );
}

#[test]
fn release_required_configuration_rejects_unverified_ceremony_files() {
    let fixture = Fixture::new();
    let device = fixture.root.join("device.json");
    let bytes = fs::read_to_string(&device).unwrap();
    write(
        &device,
        bytes
            .replace("isolated-development", "release-required")
            .as_bytes(),
        0o644,
    );
    assert_eq!(
        DaemonConfig::load(&fixture.daemon).err(),
        Some(Error::Security)
    );
    let pool = fixture.root.join("pool.json");
    let pool_bytes = fs::read_to_string(&pool).unwrap();
    write(
        &pool,
        pool_bytes
            .replace("isolated-development", "release-required")
            .as_bytes(),
        0o644,
    );
    assert_eq!(
        PublicPoolConnection::load(&pool).err(),
        Some(Error::Security)
    );
}

#[test]
fn replacement_candidate_loads_without_mutating_historical_ceremony() {
    let fixture = Fixture::new();
    let evidence: Vec<_> = [
        "identity.json",
        "record.json",
        "manifest.json",
        "reviewer.json",
    ]
    .into_iter()
    .map(|name| {
        let path = fixture.root.join(name);
        let bytes = fs::read(&path).unwrap();
        (path, bytes)
    })
    .collect();
    let replacement = SigningKey::from_bytes(&[7; 32]);
    fixture.management_candidate(&replacement, 1);
    let config = DaemonConfig::load(&fixture.daemon).unwrap();
    assert_eq!(config.device.credential.epoch, 1);
    assert_eq!(
        config.device.credential.public_key,
        replacement.verifying_key().to_bytes()
    );
    assert_eq!(config.device.identity.credential_epoch, 0);
    assert_eq!(
        config.device.identity.management_transport_public_key,
        SigningKey::from_bytes(&[5; 32]).verifying_key().to_bytes()
    );
    // Loading is candidate validation only; no device has authorized service.
    for (path, original) in evidence {
        assert_eq!(fs::read(path).unwrap(), original);
    }
    fs::remove_file(fixture.root.join("management.key.json")).unwrap();
    assert_eq!(
        DeviceConnection::load(&fixture.root.join("device.json"))
            .unwrap()
            .credential_epoch,
        1
    );
}

#[test]
fn initial_key_mismatch_config_epoch_mismatch_and_historical_rollback_fail_closed() {
    let fixture = Fixture::new();
    let path = fixture.root.join("device.json");
    let replacement = SigningKey::from_bytes(&[7; 32]);
    fixture.management_candidate(&replacement, 0);
    assert_eq!(DeviceConfig::load(&path).err(), Some(Error::Security));

    fixture.management_candidate(&replacement, 1);
    set_field(&path, "credentialEpoch", json!(2), 0o644);
    assert_eq!(DeviceConfig::load(&path).err(), Some(Error::Security));

    // A nonzero initial ceremony epoch is a floor, never current-policy proof.
    set_field(
        &fixture.root.join("identity.json"),
        "credentialEpoch",
        json!(2),
        0o644,
    );
    fixture.management_candidate(&replacement, 1);
    assert_eq!(DeviceConnection::load(&path).err(), Some(Error::Security));
    assert_eq!(DeviceConfig::load(&path).err(), Some(Error::Security));
}

#[test]
fn higher_epoch_management_candidates_still_require_exact_scope_identity_and_keypair() {
    for (field, value) in [
        ("deviceId", json!("ffffffffffffffffffffffffffffffff")),
        ("scope", json!("pool")),
        ("poolId", json!(POOL)),
        ("incarnationId", json!(INCARNATION)),
        ("publicKey", json!(spki(&SigningKey::from_bytes(&[8; 32])))),
    ] {
        let fixture = Fixture::new();
        fixture.management_candidate(&SigningKey::from_bytes(&[7; 32]), 1);
        set_field(
            &fixture.root.join("management.key.json"),
            field,
            value,
            0o600,
        );
        assert_eq!(
            DeviceConfig::load(&fixture.root.join("device.json")).err(),
            Some(if field == "scope" {
                Error::Invalid
            } else {
                Error::Security
            }),
            "{field}"
        );
    }
}

#[test]
fn pool_replacement_candidates_are_not_bound_to_management_ceremony_epoch() {
    let fixture = Fixture::new();
    set_field(&fixture.pool_credential, "credentialEpoch", json!(3), 0o600);
    let config = DaemonConfig::load(&fixture.daemon).unwrap();
    assert_eq!(config.pools[0].credential.epoch, 3);
    assert_eq!(config.device.identity.credential_epoch, 0);
    for (field, value) in [
        ("deviceId", json!("ffffffffffffffffffffffffffffffff")),
        (
            "poolId",
            json!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        ),
        ("incarnationId", json!("ffffffffffffffffffffffffffffffff")),
        ("scope", json!("management")),
    ] {
        let fixture = Fixture::new();
        set_field(&fixture.pool_credential, "credentialEpoch", json!(3), 0o600);
        set_field(&fixture.pool_credential, field, value, 0o600);
        assert_eq!(
            DaemonConfig::load(&fixture.daemon).err(),
            Some(if field == "scope" {
                Error::Invalid
            } else {
                Error::Security
            }),
            "{field}"
        );
    }
}

fn set_field(path: &Path, field: &str, value: serde_json::Value, mode: u32) {
    let mut document: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    document[field] = value;
    write_json(path, &document, mode);
}

fn write_json(path: &Path, value: &serde_json::Value, mode: u32) {
    write(path, serde_json::to_vec(value).unwrap().as_slice(), mode);
}
fn write(path: &Path, bytes: &[u8], mode: u32) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
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
fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        output.push(TABLE[((value >> 18) & 63) as usize] as char);
        output.push(TABLE[((value >> 12) & 63) as usize] as char);
        output.push(if chunk.len() > 1 {
            TABLE[((value >> 6) & 63) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            TABLE[(value & 63) as usize] as char
        } else {
            '='
        });
    }
    output
}
