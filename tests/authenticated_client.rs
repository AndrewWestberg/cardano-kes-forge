use cardano_kes_forge::host::client::{AuthenticatedClient, DeviceWire, Error};
use cardano_kes_forge::host::config::{
    DeviceConfig, DeviceIdentity, LockedSigningKey, MachineCredential,
};
use ed25519_dalek::SigningKey;
use kes_core::cbor::Value;
use kes_core::session::{
    DeviceHpkeKey, DeviceIdentityKey, OpenContext, OpenRequest, Scope, SessionTable, accept_open,
};
use kes_core::types::{CredentialEpoch, DeviceId, RequestId};
use kes_protocol::{Envelope, EnvelopeKind, Operation, Status};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
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
}

impl Device {
    fn new(machine_public: [u8; 32]) -> Self {
        Self {
            identity: DeviceIdentityKey::from_seed(Zeroizing::new([5; 32])),
            hpke: DeviceHpkeKey::from_seed(Zeroizing::new([6; 32])),
            machine_public,
            sessions: SessionTable::new(),
            counter: 0,
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
        let unsigned = info_response(
            request_id,
            challenge,
            self.identity.verification_key(),
            self.hpke.public_key(),
            [0; 64],
        );
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
        info_response(
            request_id,
            challenge,
            self.identity.verification_key(),
            self.hpke.public_key(),
            signature,
        )
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
        let mut rng = ChaCha20Rng::from_seed([7; 32]);
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
    let config = DeviceConfig {
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
    request: [u8; 16],
    challenge: [u8; 32],
    identity: [u8; 32],
    hpke: [u8; 32],
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
                ("identity_public_key", b(&identity)),
                ("hpke_public_key", b(&hpke)),
                ("boot_nonce", b(&BOOT)),
                (
                    "open_counters",
                    array(vec![map(vec![
                        ("pool", null()),
                        ("incarnation", null()),
                        ("open_counter", u(0)),
                    ])]),
                ),
                ("firmware_digest", b(&FIRMWARE)),
                ("security_version", u(1)),
                ("hardware_policy_digest", b(&POLICY)),
                ("security_mode", t("development")),
                ("capability_evidence", b(b"test")),
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
        ("status", t("BUSY")),
        (
            "payload",
            map(vec![("scope", t("device")), ("diagnostic", t("test"))]),
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
fn map(fields: Vec<(&str, Vec<u8>)>) -> Vec<u8> {
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
    Value::parse(&out).unwrap();
    out
}
