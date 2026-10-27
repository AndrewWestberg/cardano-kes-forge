use cardano_kes_forge::host::client::{AuthenticatedClient, DeviceWire, Error};
use cardano_kes_forge::host::config::{
    DeviceConfig, DeviceIdentity, LockedSigningKey, MachineCredential,
};
use cardano_kes_forge::host::{provisioning, security};
use ed25519_dalek::{Signer, SigningKey};
use kes_core::cbor::Value;
use kes_core::session::{
    DeviceHpkeKey, DeviceIdentityKey, OpenContext, OpenRequest, Scope, SessionTable, accept_open,
};
use kes_core::types::{CredentialEpoch, DeviceId, RequestId};
use kes_protocol::{Envelope, EnvelopeKind, Operation, Status};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;
use zeroize::Zeroizing;

const DEVICE: [u8; 16] = [1; 16];
const BOOT: [u8; 32] = [2; 32];
const FIRMWARE: [u8; 32] = [3; 32];
const POLICY: [u8; 32] = [4; 32];

struct Device {
    identity: DeviceIdentityKey,
    hpke: DeviceHpkeKey,
    machine_public: [u8; 32],
    sessions: SessionTable,
    counter: u64,
    mode: &'static str,
    status_mode: Option<&'static str>,
    evidence_key: Option<SigningKey>,
    evidence_fault: &'static str,
    firmware: [u8; 32],
    policy: [u8; 32],
}

impl Device {
    fn new(machine_public: [u8; 32]) -> Self {
        Self {
            identity: DeviceIdentityKey::from_seed(Zeroizing::new([5; 32])),
            hpke: DeviceHpkeKey::from_seed(Zeroizing::new([6; 32])),
            machine_public,
            sessions: SessionTable::new(),
            counter: 0,
            mode: "development",
            status_mode: None,
            evidence_key: None,
            evidence_fault: "",
            firmware: FIRMWARE,
            policy: POLICY,
        }
    }

    fn info(&self, request: Envelope<'_>) -> Vec<u8> {
        let request_id = *request.request().unwrap().as_bytes();
        let challenge: [u8; 32] = request
            .payload()
            .required("challenge")
            .unwrap()
            .bytes()
            .unwrap()
            .try_into()
            .unwrap();
        let capability = self.capability(challenge);
        let unsigned = info_response(self, request_id, challenge, &capability, [0; 64]);
        let map = Envelope::parse(&unsigned, EnvelopeKind::InfoResponse)
            .unwrap()
            .map();
        let mut scratch = [0; kes_core::session::INFO_TRANSCRIPT_BYTES];
        let signature = self
            .identity
            .sign_info(
                map,
                DeviceId::from_bytes(DEVICE),
                RequestId::from_bytes(request_id),
                &challenge,
                &mut scratch,
            )
            .unwrap();
        info_response(self, request_id, challenge, &capability, signature)
    }

    fn capability(&self, challenge: [u8; 32]) -> Vec<u8> {
        let Some(key) = &self.evidence_key else {
            return b"test".to_vec();
        };
        let mut evidence = security::OnlineEvidence {
            mode: security::Mode::ReleaseReady,
            challenge,
            boot_nonce: BOOT,
            device: DEVICE,
            silicon_revision: 4,
            rom_revision: "RP2350-ROM-A4".to_owned(),
            flash_part: "W25Q32JV".to_owned(),
            flash_capacity_bytes: 4_194_304,
            firmware_digest: self.firmware,
            hardware_policy_digest: self.policy,
            security_version: 1,
            signature: [0; 64],
        };
        match self.evidence_fault {
            "replay" => evidence.challenge = [0; 32],
            "boot" => evidence.boot_nonce = [42; 32],
            "device" => evidence.device = [42; 16],
            "silicon" => evidence.silicon_revision = 5,
            "rom" => evidence.rom_revision = "RP2350-ROM-A5".to_owned(),
            "flash" => evidence.flash_part = "other".to_owned(),
            "capacity" => evidence.flash_capacity_bytes *= 2,
            "firmware" => evidence.firmware_digest = [42; 32],
            "policy" => evidence.hardware_policy_digest = [42; 32],
            "version" => evidence.security_version = 2,
            "mode" => evidence.mode = security::Mode::Development,
            _ => {}
        }
        evidence.signature = key.sign(&security::evidence_message(&evidence)).to_bytes();
        if self.evidence_fault == "signature" {
            evidence.signature[0] ^= 1;
        }
        let mode = if evidence.mode == security::Mode::Development {
            "development"
        } else {
            "release-ready"
        };
        let mut fields = vec![
            ("version", u(1)),
            ("mode", t(mode)),
            ("challenge", b(&evidence.challenge)),
            ("boot_nonce", b(&evidence.boot_nonce)),
            ("device", b(&evidence.device)),
            ("silicon_revision", u(u64::from(evidence.silicon_revision))),
            ("rom_revision", t(&evidence.rom_revision)),
            ("flash_part", t(&evidence.flash_part)),
            ("flash_capacity_bytes", u(evidence.flash_capacity_bytes)),
            ("firmware_digest", b(&evidence.firmware_digest)),
            (
                "hardware_policy_digest",
                b(&evidence.hardware_policy_digest),
            ),
            ("security_version", u(evidence.security_version)),
            ("signature", b(&evidence.signature)),
        ];
        if self.evidence_fault == "unknown" {
            fields.push(("extra", u(1)));
        }
        match self.evidence_fault {
            "utf8" => fields.push(("extra", vec![0x61, 0xff])),
            "integer" => fields.push(("extra", vec![0x20])),
            _ => {}
        }
        let mut encoded = map_raw(fields);
        if self.evidence_fault == "trailing" {
            encoded.push(0);
        }
        if self.evidence_fault == "noncanonical" {
            encoded.splice(0..1, [0xb8, 13]);
        }
        encoded
    }

    fn open(&mut self, envelope: Envelope<'_>) -> Vec<u8> {
        let payload = envelope.payload();
        let request_id = *envelope.request().unwrap().as_bytes();
        let context = OpenContext::new(
            DeviceId::from_bytes(DEVICE),
            BOOT,
            Scope::Management,
            CredentialEpoch::new(0),
            self.counter,
            RequestId::from_bytes(request_id),
        );
        let request = OpenRequest {
            context,
            encapsulation: fixed(payload, "encapsulation"),
            ciphertext: fixed(payload, "ciphertext"),
            signature: fixed(payload, "signature"),
        };
        let mut rng = ChaCha20Rng::from_seed(*fresh_seed());
        let accepted = accept_open(
            context,
            &request,
            &self.hpke,
            &self.machine_public,
            &mut rng,
        )
        .unwrap();
        let fields = accepted.response_fields();
        let unsigned = open_response(request_id, fields, [0; 32]);
        let map = Envelope::parse(&unsigned, EnvelopeKind::OpenResponse)
            .unwrap()
            .map();
        let response = accepted
            .commit(&mut self.counter, &mut self.sessions, map)
            .unwrap();
        open_response(request_id, response, response.mac)
    }

    fn authenticated(&mut self, envelope: Envelope<'_>) -> Vec<u8> {
        let session = self.sessions.get_mut(Scope::Management).unwrap();
        let authenticated = session
            .authenticate_request(envelope.map(), CredentialEpoch::new(0), false)
            .unwrap();
        let unsigned = device_response(
            *authenticated.request.as_bytes(),
            authenticated.operation,
            *session.session_id(),
            authenticated.sequence,
            0,
            self.status_mode,
            [0; 32],
        );
        let map = Envelope::parse(&unsigned, EnvelopeKind::DeviceResponse)
            .unwrap()
            .map();
        let mac = session.response_mac(map, authenticated).unwrap();
        device_response(
            *authenticated.request.as_bytes(),
            authenticated.operation,
            *session.session_id(),
            authenticated.sequence,
            0,
            self.status_mode,
            mac,
        )
    }
}

impl DeviceWire for Device {
    fn exchange(
        &mut self,
        request: &[u8],
        response: &mut [u8; kes_protocol::MAX_FRAME_BYTES],
        _timeout: Duration,
    ) -> Result<usize, Error> {
        let envelope = Envelope::parse_device_ingress(request).unwrap();
        let encoded = match envelope.operation {
            Operation::Info => self.info(envelope),
            Operation::Open => self.open(envelope),
            _ => self.authenticated(envelope),
        };
        response[..encoded.len()].copy_from_slice(&encoded);
        Ok(encoded.len())
    }
}

#[test]
fn pinned_info_open_and_committed_response_are_authenticated() {
    let machine = SigningKey::from_bytes(&[8; 32]);
    let mut device = Device::new(machine.verifying_key().to_bytes());
    let mut config = DeviceConfig {
        socket_path: PathBuf::from("unused.sock"),
        device_id: DEVICE,
        device_identity_file: PathBuf::from("unused.identity.json"),
        connection_name: "mgmt".to_owned(),
        credential_file: PathBuf::from("unused.key.json"),
        credential: MachineCredential {
            epoch: 0,
            public_key: machine.verifying_key().to_bytes(),
            signing_key: LockedSigningKey::new(machine).unwrap(),
        },
        identity: DeviceIdentity {
            device_id: DEVICE,
            identity_public_key: device.identity.verification_key(),
            hpke_public_key: device.hpke.public_key(),
            management_public_key: [9; 32],
            management_transport_public_key: device.machine_public,
            credential_epoch: 0,
            boot_key_fingerprint: [10; 32],
            hardware_policy_digest: POLICY,
            firmware_digest: FIRMWARE,
            security_version: 1,
            provisioning_record_file: PathBuf::from("record.json"),
            provisioning_manifest_file: PathBuf::from("manifest.json"),
            reviewer_public_key_file: PathBuf::from("reviewer.json"),
        },
        security_policy: "isolated-development".to_owned(),
    };
    config.security_policy = "release-required".to_owned();
    assert!(matches!(
        AuthenticatedClient::open_management(&mut device, &config),
        Err(Error::Security)
    ));
    let mut unsigned_evidence = Device::new(config.credential.public_key);
    unsigned_evidence.mode = "release-ready";
    assert!(matches!(
        AuthenticatedClient::open_management(&mut unsigned_evidence, &config),
        Err(Error::Security)
    ));
    let mut unprovisioned = Device::new(config.credential.public_key);
    unprovisioned.mode = "release-unprovisioned";
    let mut diagnostic = AuthenticatedClient::open_management(&mut unprovisioned, &config).unwrap();
    let mut response = [0; kes_protocol::MAX_FRAME_BYTES];
    let manage = map(vec![
        ("version", u(1)),
        ("connection", t("mgmt")),
        ("request", b(&[12; 16])),
        ("budget_ms", u(500)),
        ("op", t("OP_STATUS")),
        ("payload", map(vec![("request", b(&[13; 16]))])),
    ]);
    assert!(matches!(
        diagnostic.exchange_local(
            &mut unprovisioned,
            &manage,
            &mut response,
            Duration::from_millis(500)
        ),
        Err(Error::Security)
    ));
    assert!(
        diagnostic
            .exchange_local(
                &mut unprovisioned,
                &local_status_request(),
                &mut response,
                Duration::from_millis(500)
            )
            .is_ok()
    );
    config.security_policy = "isolated-development".to_owned();
    let mut inconsistent = Device::new(config.credential.public_key);
    inconsistent.status_mode = Some("release-ready");
    let mut client = AuthenticatedClient::open_management(&mut inconsistent, &config).unwrap();
    let mut response = [0; kes_protocol::MAX_FRAME_BYTES];
    assert!(matches!(
        client.exchange_local(
            &mut inconsistent,
            &local_status_request(),
            &mut response,
            Duration::from_millis(500)
        ),
        Err(Error::Security)
    ));
    config.security_policy = "isolated-development".to_owned();
    let mut device = Device::new(config.credential.public_key);
    let mut client = AuthenticatedClient::open_management(&mut device, &config).unwrap();
    let local = local_status_request();
    let mut response = [0; kes_protocol::MAX_FRAME_BYTES];
    let length = client
        .exchange_local(
            &mut device,
            &local,
            &mut response,
            Duration::from_millis(500),
        )
        .unwrap();
    let response = Envelope::parse(&response[..length], EnvelopeKind::LocalResponse).unwrap();
    assert_eq!(response.operation, Operation::Status);
    assert_eq!(response.status, Some(Status::Busy));
    assert_eq!(
        response
            .map()
            .required("connection")
            .unwrap()
            .text()
            .unwrap(),
        "mgmt"
    );
}

fn local_status_request() -> Vec<u8> {
    map(vec![
        ("version", u(1)),
        ("connection", t("mgmt")),
        ("request", b(&[11; 16])),
        ("budget_ms", u(500)),
        ("op", t("STATUS")),
        ("payload", map(vec![])),
    ])
}

fn info_response(
    device: &Device,
    request: [u8; 16],
    challenge: [u8; 32],
    capability: &[u8],
    signature: [u8; 64],
) -> Vec<u8> {
    map(vec![
        ("version", u(1)),
        ("op", t("INFO")),
        ("request", b(&request)),
        ("device", b(&DEVICE)),
        ("status", t("OK")),
        (
            "payload",
            map(vec![
                ("challenge", b(&challenge)),
                (
                    "identity_public_key",
                    b(&device.identity.verification_key()),
                ),
                ("hpke_public_key", b(&device.hpke.public_key())),
                ("boot_nonce", b(&BOOT)),
                (
                    "open_counters",
                    array(vec![map(vec![
                        ("pool", null()),
                        ("incarnation", null()),
                        ("open_counter", u(0)),
                    ])]),
                ),
                ("firmware_digest", b(&device.firmware)),
                ("security_version", u(1)),
                ("hardware_policy_digest", b(&device.policy)),
                ("security_mode", t(device.mode)),
                ("capability_evidence", b(capability)),
                (
                    "limits",
                    map(vec![
                        ("frame_bytes", u(8192)),
                        ("message_bytes", u(4096)),
                        ("certificate_bytes", u(1024)),
                        ("backup_bytes", u(2048)),
                        ("pools", u(32)),
                        ("sessions", u(33)),
                    ]),
                ),
            ]),
        ),
        ("signature", b(&signature)),
    ])
}

fn open_response(
    request: [u8; 16],
    fields: kes_core::session::OpenResponse,
    mac: [u8; 32],
) -> Vec<u8> {
    map(vec![
        ("version", u(1)),
        ("op", t("OPEN")),
        ("device", b(&DEVICE)),
        ("pool", null()),
        ("incarnation", null()),
        ("request", b(&request)),
        ("status", t("OK")),
        (
            "payload",
            map(vec![
                ("session", b(&fields.session_id)),
                (
                    "challenge_acknowledgement",
                    b(&fields.challenge_acknowledgement),
                ),
            ]),
        ),
        ("mac", b(&mac)),
    ])
}

fn device_response(
    request: [u8; 16],
    operation: &str,
    session: [u8; 16],
    request_sequence: u64,
    sequence: u64,
    mode: Option<&str>,
    mac: [u8; 32],
) -> Vec<u8> {
    map(vec![
        ("version", u(1)),
        ("op", t(operation)),
        ("device", b(&DEVICE)),
        ("pool", null()),
        ("incarnation", null()),
        ("session", b(&session)),
        ("seq", u(sequence)),
        ("request_seq", u(request_sequence)),
        ("request", b(&request)),
        ("status", t(if mode.is_some() { "OK" } else { "BUSY" })),
        (
            "payload",
            if let Some(mode) = mode {
                map(vec![
                    ("health", t("healthy")),
                    ("security_mode", t(mode)),
                    ("revision", u(0)),
                    ("credential_epoch", u(0)),
                    ("revoked", vec![0xf4]),
                    ("active", null()),
                    ("staged", null()),
                    ("blocking_reason", t("")),
                    ("directory", array(vec![])),
                ])
            } else {
                map(vec![("scope", t("device")), ("diagnostic", t("test"))])
            },
        ),
        ("mac", b(&mac)),
    ])
}

fn fixed<const N: usize>(map: kes_core::cbor::Map<'_>, key: &str) -> [u8; N] {
    map.required(key)
        .unwrap()
        .bytes()
        .unwrap()
        .try_into()
        .unwrap()
}

fn head(major: u8, value: u64, out: &mut Vec<u8>) {
    let mut encoded = [0; 9];
    let length = kes_core::cbor::encode_head(major, value, &mut encoded);
    out.extend_from_slice(&encoded[..length]);
}
fn u(value: u64) -> Vec<u8> {
    let mut out = vec![];
    head(0, value, &mut out);
    out
}
fn b(value: &[u8]) -> Vec<u8> {
    let mut out = vec![];
    head(2, value.len() as u64, &mut out);
    out.extend_from_slice(value);
    out
}
fn t(value: &str) -> Vec<u8> {
    let mut out = vec![];
    head(3, value.len() as u64, &mut out);
    out.extend_from_slice(value.as_bytes());
    out
}
fn null() -> Vec<u8> {
    vec![0xf6]
}
fn array(values: Vec<Vec<u8>>) -> Vec<u8> {
    let mut out = vec![];
    head(4, values.len() as u64, &mut out);
    for value in values {
        out.extend(value);
    }
    out
}
fn map_raw(fields: Vec<(&str, Vec<u8>)>) -> Vec<u8> {
    let mut fields: Vec<_> = fields
        .into_iter()
        .map(|(key, value)| (t(key), value))
        .collect();
    fields.sort_by(|left, right| left.0.cmp(&right.0));
    let mut out = vec![];
    head(5, fields.len() as u64, &mut out);
    for (key, value) in fields {
        out.extend(key);
        out.extend(value);
    }
    out
}

fn map(fields: Vec<(&str, Vec<u8>)>) -> Vec<u8> {
    let out = map_raw(fields);
    Value::parse(&out).unwrap();
    out
}

fn fresh_seed() -> Zeroizing<[u8; 32]> {
    let mut seed = Zeroizing::new([0; 32]);
    std::fs::File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut seed[..])
        .unwrap();
    seed
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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

fn spki(key: [u8; 32]) -> String {
    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0,
    ];
    der.extend(key);
    base64(&der)
}

struct ReleaseFixture {
    directory: PathBuf,
    config: DeviceConfig,
    device: Device,
}

impl Drop for ReleaseFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

impl ReleaseFixture {
    fn new() -> Self {
        Self::with_authority_mismatch("")
    }

    fn with_authority_mismatch(mismatch: &str) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let directory = std::env::temp_dir().join(format!("kes-online-{}", hex(&fresh_seed()[..])));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let machine = SigningKey::from_bytes(&fresh_seed());
        let reviewer = SigningKey::from_bytes(&fresh_seed());
        let management = SigningKey::from_bytes(&fresh_seed());
        let identity_seed = fresh_seed();
        let identity_signer = SigningKey::from_bytes(&identity_seed);
        let mut device = Device::new(machine.verifying_key().to_bytes());
        device.identity = DeviceIdentityKey::from_seed(identity_seed);
        device.hpke = DeviceHpkeKey::from_seed(fresh_seed());
        device.evidence_key = Some(identity_signer);
        device.mode = "release-ready";
        device.status_mode = Some("release-ready");
        device.firmware = Sha256::digest(b"disposable signed fixture firmware").into();
        device.policy = Sha256::digest(b"disposable approved fixture policy").into();
        let hash = |bytes: &[u8]| hex(&Sha256::digest(bytes));
        let authority = |key: &SigningKey, role| {
            serde_json::to_vec(&json!({
                "version": 1, "algorithm": "Ed25519", "role": role,
                "publicKey": spki(key.verifying_key().to_bytes())
            }))
            .unwrap()
        };
        let reviewer_bytes = authority(&reviewer, "provisioning-reviewer");
        let other = SigningKey::from_bytes(&fresh_seed());
        let manifest_reviewer_bytes = if mismatch == "reviewer" {
            authority(&other, "provisioning-reviewer")
        } else {
            reviewer_bytes.clone()
        };
        let management_bytes = authority(
            if mismatch == "management" {
                &other
            } else {
                &management
            },
            "management",
        );
        let transport_key = if mismatch == "transport" {
            &other
        } else {
            &machine
        };
        let transport_bytes = serde_json::to_vec(&json!({
            "version": 1, "algorithm": "Ed25519", "scope": "management",
            "deviceId": hex(&DEVICE), "poolId": null, "incarnationId": null,
            "credentialEpoch": 0, "publicKey": spki(transport_key.verifying_key().to_bytes())
        }))
        .unwrap();
        let references: [(&str, &[u8]); 8] = [
            ("inspection.json", b"disposable direct inspection"),
            ("policy.json", b"disposable approved fixture policy"),
            ("recipe.json", b"disposable reviewed fixture recipe"),
            ("firmware.bin", b"disposable signed fixture firmware"),
            ("partition.json", b"disposable partition manifest"),
            ("management.json", &management_bytes),
            ("transport.json", &transport_bytes),
            ("manifest-reviewer.json", &manifest_reviewer_bytes),
        ];
        std::fs::write(directory.join("reviewer.json"), &reviewer_bytes).unwrap();
        for (name, bytes) in references {
            std::fs::write(directory.join(name), bytes).unwrap();
        }
        let mut manifest = json!({
            "version": 1, "ceremonyId": "aa".repeat(16), "deviceId": hex(&DEVICE),
            "usbDevice": "bus=1,address=13", "inspectionFile": "inspection.json",
            "inspectionDigest": hash(references[0].1), "siliconRevision": "A4",
            "romRevision": "RP2350-ROM-A4", "flashPart": "W25Q32JV", "flashCapacityBytes": 4194304,
            "policyFile": "policy.json", "policyDigest": hex(&device.policy),
            "recipeFile": "recipe.json", "recipeDigest": hash(references[2].1),
            "firmwareFile": "firmware.bin", "firmwareDigest": hex(&device.firmware),
            "partitionManifestFile": "partition.json", "partitionManifestDigest": hash(references[4].1),
            "bootKeyFingerprint": "bb".repeat(32), "securityVersion": 1,
            "managementPublicKeyFile": "management.json", "managementPublicKeyDigest": hash(&management_bytes),
            "managementTransportPublicKeyFile": "transport.json", "managementTransportPublicKeyDigest": hash(&transport_bytes),
            "reviewerPublicKeyFile": "manifest-reviewer.json", "reviewerPublicKeyDigest": hash(&manifest_reviewer_bytes),
            "steps": [
                {"index": 0, "action": "install-image", "target": "FLASH_SLOT_A", "before": "empty", "after": "verified", "irreversible": false},
                {"index": 1, "action": "otp-lock", "target": "CRIT1", "before": "unlocked", "after": "locked", "irreversible": true}
            ], "signature": null
        });
        let message =
            provisioning::manifest_signature_message(&serde_json::to_vec(&manifest).unwrap())
                .unwrap();
        manifest["signature"] = json!(base64(&reviewer.sign(&message).to_bytes()));
        let manifest = serde_json::to_vec(&manifest).unwrap();
        let mut record = json!({
            "version": 1, "ceremonyId": "aa".repeat(16), "manifestDigest": hash(&manifest),
            "deviceId": hex(&DEVICE), "identityPublicKey": spki(device.identity.verification_key()),
            "hpkePublicKey": hex(&device.hpke.public_key()), "managementPublicKey": spki(management.verifying_key().to_bytes()),
            "managementTransportPublicKey": spki(machine.verifying_key().to_bytes()), "credentialEpoch": 0,
            "siliconRevision": "A4", "romRevision": "RP2350-ROM-A4", "flashPart": "W25Q32JV",
            "flashCapacityBytes": 4194304, "bootKeyFingerprint": "bb".repeat(32),
            "policyDigest": hex(&device.policy), "firmwareDigest": hex(&device.firmware), "securityVersion": 1,
            "toolVersion": "2.3.1", "toolDigest": "dd".repeat(32),
            "results": [{"index": 0, "observed": "verified", "passed": true}, {"index": 1, "observed": "locked", "passed": true}],
            "completedAt": "2026-01-02T03:04:05Z", "reviewerPublicKey": spki(reviewer.verifying_key().to_bytes()), "signature": null
        });
        let message =
            provisioning::record_signature_message(&serde_json::to_vec(&record).unwrap()).unwrap();
        record["signature"] = json!(base64(&reviewer.sign(&message).to_bytes()));
        std::fs::write(directory.join("manifest.json"), manifest).unwrap();
        std::fs::write(
            directory.join("record.json"),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        for entry in std::fs::read_dir(&directory).unwrap() {
            std::fs::set_permissions(
                entry.unwrap().path(),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        let config = DeviceConfig {
            socket_path: directory.join("unused.sock"),
            device_id: DEVICE,
            device_identity_file: directory.join("identity.json"),
            connection_name: "mgmt".to_owned(),
            credential_file: directory.join("unused.key.json"),
            credential: MachineCredential {
                epoch: 0,
                public_key: machine.verifying_key().to_bytes(),
                signing_key: LockedSigningKey::new(machine).unwrap(),
            },
            identity: DeviceIdentity {
                device_id: DEVICE,
                identity_public_key: device.identity.verification_key(),
                hpke_public_key: device.hpke.public_key(),
                management_public_key: management.verifying_key().to_bytes(),
                management_transport_public_key: device.machine_public,
                credential_epoch: 0,
                boot_key_fingerprint: [0xbb; 32],
                hardware_policy_digest: device.policy,
                firmware_digest: device.firmware,
                security_version: 1,
                provisioning_record_file: directory.join("record.json"),
                provisioning_manifest_file: directory.join("manifest.json"),
                reviewer_public_key_file: directory.join("reviewer.json"),
            },
            security_policy: "release-required".to_owned(),
        };
        Self {
            directory,
            config,
            device,
        }
    }
}

#[test]
fn release_client_requires_separate_ceremony_and_fresh_independently_signed_evidence() {
    let mut fixture = ReleaseFixture::new();
    assert_eq!(
        security::decode_online_evidence(&[0; 2049]),
        Err(security::Error::InvalidEncoding)
    );
    let mut client =
        AuthenticatedClient::open_management(&mut fixture.device, &fixture.config).unwrap();
    assert_eq!(fixture.device.counter, 1);
    let mut response = [0; kes_protocol::MAX_FRAME_BYTES];
    client
        .exchange_local(
            &mut fixture.device,
            &local_status_request(),
            &mut response,
            Duration::from_millis(500),
        )
        .unwrap();
    // The evidence is signed after each unpredictable client challenge, not a
    // canned response or a replacement for the real readiness verifier.
    for fault in [
        "replay",
        "boot",
        "device",
        "silicon",
        "rom",
        "flash",
        "capacity",
        "firmware",
        "policy",
        "version",
        "mode",
        "signature",
        "unknown",
        "trailing",
        "noncanonical",
        "utf8",
        "integer",
    ] {
        let mut fixture = ReleaseFixture::new();
        fixture.device.evidence_fault = fault;
        assert!(
            matches!(
                AuthenticatedClient::open_management(&mut fixture.device, &fixture.config),
                Err(Error::Security)
            ),
            "{fault}"
        );
        assert_eq!(fixture.device.counter, 0, "{fault} reached OPEN");
    }
    let mut fixture = ReleaseFixture::new();
    fixture.device.evidence_key = Some(SigningKey::from_bytes(&fresh_seed()));
    assert!(matches!(
        AuthenticatedClient::open_management(&mut fixture.device, &fixture.config),
        Err(Error::Security)
    ));
    assert_eq!(fixture.device.counter, 0);
    for authority in ["management", "transport", "reviewer"] {
        let mut fixture = ReleaseFixture::with_authority_mismatch(authority);
        assert!(
            matches!(
                AuthenticatedClient::open_management(&mut fixture.device, &fixture.config),
                Err(Error::Security)
            ),
            "{authority} reference mismatch"
        );
        assert_eq!(fixture.device.counter, 0);
    }
    for missing in [
        "record.json",
        "manifest.json",
        "reviewer.json",
        "policy.json",
    ] {
        let mut fixture = ReleaseFixture::new();
        std::fs::remove_file(fixture.directory.join(missing)).unwrap();
        assert!(
            matches!(
                AuthenticatedClient::open_management(&mut fixture.device, &fixture.config),
                Err(Error::Security)
            ),
            "{missing}"
        );
        assert_eq!(fixture.device.counter, 0);
    }
    for changed in [
        "record.json",
        "manifest.json",
        "reviewer.json",
        "policy.json",
    ] {
        let mut fixture = ReleaseFixture::new();
        std::fs::write(fixture.directory.join(changed), b"tampered").unwrap();
        assert!(
            matches!(
                AuthenticatedClient::open_management(&mut fixture.device, &fixture.config),
                Err(Error::Security)
            ),
            "{changed}"
        );
        assert_eq!(fixture.device.counter, 0);
    }
}
