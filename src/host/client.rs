#[path = "client_helpers.rs"]
mod helpers;

#[path = "operator_status.rs"]
pub mod operator_status;

use crate::host::config::{
    DeviceConfig, DeviceConnection, MachineCredential, PoolConnection, PublicPoolConnection,
};
use helpers::*;
use kes_core::cbor::{Encoder, Map, Value};
use kes_core::session::{
    HostSession, INFO_TRANSCRIPT_BYTES, OpenContext, Scope, begin_open, verify_info,
};
use kes_core::types::{CredentialEpoch, DeviceId, IncarnationId, PoolId, RequestId};
use kes_protocol::{Envelope, EnvelopeKind, Operation, Status};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;
use zeroize::Zeroizing;

const A2_DEVELOPMENT_CAPABILITY: &[u8] = b"rp2350-a2;development;otp=untouched;\
    persistence=identity-only;firmware-digest=unmeasured;entropy=health-checked-a2-exploratory;\
    session-entropy=fresh-per-open";
const A2_ENROLLMENT_CAPABILITY: &[u8] = b"rp2350-a2;development;otp=untouched;\
    persistence=identity-and-enrollment;firmware-digest=unmeasured;entropy=health-checked-a2-exploratory;\
    session-entropy=fresh-per-open";
const A2_DEVELOPMENT_POLICY_DIGEST: [u8; 32] = [
    0xa6, 0x22, 0x83, 0xc6, 0xd4, 0x21, 0x01, 0x29, 0xcf, 0x6f, 0x26, 0x8f, 0x61, 0x15, 0x0a, 0x23,
    0xc6, 0xf3, 0x2e, 0x60, 0x2c, 0xa9, 0x6f, 0x3c, 0x3d, 0x8c, 0x93, 0xec, 0x3a, 0xf2, 0x0f, 0xf2,
];
const A2_QUALIFICATION_MACHINE_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DevelopmentIdentity {
    pub device: [u8; 16],
    pub identity_public_key: [u8; 32],
    pub hpke_public_key: [u8; 32],
    pub boot_nonce: [u8; 32],
}

#[derive(Debug)]
pub enum Error {
    Unavailable,
    /// A device transfer may have entered or completed the secure workspace.
    /// The physical handle must not be reused until the daemon restarts.
    Uncertain,
    Conflict,
    Security,
    Integrity,
    Damaged,
    InProgress,
    Unknown,
    NotCommitted,
    ResultReclaimed,
}

/// Exclusive framed device exchange. The daemon owns the sole implementation
/// and never shares a physical handle with local clients.
pub trait DeviceWire {
    fn exchange(
        &mut self,
        request: &[u8],
        response: &mut [u8; kes_protocol::MAX_FRAME_BYTES],
        timeout: Duration,
    ) -> Result<usize, Error>;
}

pub struct AuthenticatedClient {
    connection: String,
    device: [u8; 16],
    pool: Option<[u8; 28]>,
    incarnation: Option<[u8; 16]>,
    session: HostSession,
    boot_nonce: [u8; 32],
    security_mode: &'static str,
    request_sequence: u64,
    valid: bool,
}

struct SessionBinding<'a> {
    connection: &'a str,
    device: [u8; 16],
    pool: Option<[u8; 28]>,
    incarnation: Option<[u8; 16]>,
    identity_public_key: [u8; 32],
    hpke_public_key: [u8; 32],
    firmware_digest: [u8; 32],
    hardware_policy_digest: [u8; 32],
    security_policy: &'a str,
    security_version: u64,
    credential: &'a MachineCredential,
    identity: &'a crate::host::config::DeviceIdentity,
}

impl AuthenticatedClient {
    pub fn open_pool(
        wire: &mut impl DeviceWire,
        connection: &PoolConnection,
    ) -> Result<Self, Error> {
        let identity = crate::host::config::DeviceIdentity::load(&connection.device_identity_file)
            .map_err(|_| Error::Security)?;
        Self::open(
            wire,
            SessionBinding {
                connection: &connection.connection_name,
                device: connection.device_id,
                pool: Some(connection.pool_id),
                incarnation: Some(connection.incarnation_id),
                identity_public_key: identity.identity_public_key,
                hpke_public_key: identity.hpke_public_key,
                firmware_digest: identity.firmware_digest,
                hardware_policy_digest: identity.hardware_policy_digest,
                security_policy: &connection.security_policy,
                security_version: identity.security_version,
                credential: &connection.credential,
                identity: &identity,
            },
        )
    }

    pub fn open_management(
        wire: &mut impl DeviceWire,
        connection: &DeviceConfig,
    ) -> Result<Self, Error> {
        Self::open(
            wire,
            SessionBinding {
                connection: &connection.connection_name,
                device: connection.device_id,
                pool: None,
                incarnation: None,
                identity_public_key: connection.identity.identity_public_key,
                hpke_public_key: connection.identity.hpke_public_key,
                firmware_digest: connection.identity.firmware_digest,
                hardware_policy_digest: connection.identity.hardware_policy_digest,
                security_policy: &connection.security_policy,
                security_version: connection.identity.security_version,
                credential: &connection.credential,
                identity: &connection.identity,
            },
        )
    }

    fn open(wire: &mut impl DeviceWire, binding: SessionBinding<'_>) -> Result<Self, Error> {
        let mut entropy = File::open("/dev/urandom").map_err(|_| Error::Unavailable)?;
        let mut challenge = [0; 32];
        let mut info_request = [0; 16];
        entropy
            .read_exact(&mut challenge)
            .and_then(|()| entropy.read_exact(&mut info_request))
            .map_err(|_| Error::Unavailable)?;
        let info_encoded = encode_info_request(info_request, challenge)?;
        let mut response = [0; kes_protocol::MAX_FRAME_BYTES];
        let length = wire.exchange(
            &info_encoded,
            &mut response,
            Duration::from_millis(u64::from(kes_protocol::STATUS_BUDGET_MS)),
        )?;
        let info = Envelope::parse(&response[..length], EnvelopeKind::InfoResponse)
            .map_err(|_| Error::Integrity)?;
        let device = DeviceId::from_bytes(binding.device);
        let info_request_id = RequestId::from_bytes(info_request);
        let mut scratch = [0; INFO_TRANSCRIPT_BYTES];
        let view = verify_info(
            info.map(),
            device,
            info_request_id,
            &challenge,
            &binding.identity_public_key,
            &mut scratch,
        )
        .map_err(|_| Error::Security)?;
        if view.hpke_public_key != binding.hpke_public_key {
            return Err(Error::Security);
        }
        let security_mode = match (
            binding.security_policy,
            info.payload()
                .required("security_mode")
                .and_then(|value| value.text())
                .map_err(|_| Error::Integrity)?,
        ) {
            ("release-required" | "isolated-development", "release-ready") => {
                verify_release_info(info.payload(), &binding, challenge, view.boot_nonce)?;
                "release-ready"
            }
            ("isolated-development", "development") => "development",
            ("release-required" | "isolated-development", "release-unprovisioned")
                if binding.pool.is_none() =>
            {
                "release-unprovisioned"
            }
            _ => return Err(Error::Security),
        };
        validate_info_identity(info.payload(), &binding)?;
        let open_counter = open_counter(info.payload(), binding.pool, binding.incarnation)?;
        let mut open_request = [0; 16];
        let mut seed = Zeroizing::new([0; 32]);
        entropy
            .read_exact(&mut open_request)
            .and_then(|()| entropy.read_exact(&mut *seed))
            .map_err(|_| Error::Unavailable)?;
        let scope = match (binding.pool, binding.incarnation) {
            (Some(pool), Some(incarnation)) => Scope::Pool {
                pool: PoolId::from_bytes(pool),
                incarnation: IncarnationId::from_bytes(incarnation),
            },
            (None, None) => Scope::Management,
            _ => return Err(Error::Security),
        };
        let context = OpenContext::new(
            device,
            view.boot_nonce,
            scope,
            CredentialEpoch::new(binding.credential.epoch),
            open_counter,
            RequestId::from_bytes(open_request),
        );
        let mut rng = ChaCha20Rng::from_seed(*seed);
        let (open, pending) = begin_open(
            context,
            &view.hpke_public_key,
            &binding.credential.signing_key,
            &mut rng,
        )
        .map_err(|_| Error::Security)?;
        let encoded_open = encode_open_request(&open)?;
        let length = wire.exchange(
            &encoded_open,
            &mut response,
            Duration::from_millis(u64::from(kes_protocol::STATUS_BUDGET_MS)),
        )?;
        let response_envelope = Envelope::parse(&response[..length], EnvelopeKind::OpenResponse)
            .map_err(|_| Error::Integrity)?;
        let session = pending
            .complete(response_envelope.map())
            .map_err(|_| Error::Security)?;
        Ok(Self {
            connection: binding.connection.to_owned(),
            device: binding.device,
            pool: binding.pool,
            incarnation: binding.incarnation,
            session,
            boot_nonce: view.boot_nonce,
            security_mode,
            request_sequence: 0,
            valid: true,
        })
    }

    pub const fn boot_nonce(&self) -> [u8; 32] {
        self.boot_nonce
    }

    pub const fn session_id(&self) -> [u8; 16] {
        *self.session.session_id()
    }

    pub fn invalidate(&mut self) {
        self.valid = false;
    }
    /// Direct, development-only extraction. The caller must lock `response`
    /// before calling; the secret-bearing response is never copied to a local
    /// socket frame or an unprotected intermediate buffer here.
    #[cfg(feature = "development")]
    pub fn exchange_development(
        &mut self,
        wire: &mut impl DeviceWire,
        request: [u8; 16],
        generation: [u8; 16],
        response: &mut [u8; kes_protocol::MAX_FRAME_BYTES],
        timeout: Duration,
    ) -> Result<usize, Error> {
        if !self.valid
            || self.security_mode != "development"
            || self.pool.is_none()
            || self.incarnation.is_none()
            || timeout.is_zero()
        {
            return Err(Error::Security);
        }
        let mut payload_bytes = [0; 64];
        let mut encoder = Encoder::new(&mut payload_bytes);
        encoder.map(2).map_err(|_| Error::Integrity)?;
        encoder.text("generation").map_err(|_| Error::Integrity)?;
        encoder.bytes(&generation).map_err(|_| Error::Integrity)?;
        encoder
            .text("protected_output")
            .map_err(|_| Error::Integrity)?;
        encoder.boolean(true).map_err(|_| Error::Integrity)?;
        let payload = encoder
            .finish()
            .map_err(|_| Error::Integrity)?
            .map()
            .map_err(|_| Error::Integrity)?;
        let sequence = self.request_sequence;
        let mut bytes = [0; kes_protocol::MAX_FRAME_BYTES];
        let budget = kes_protocol::STATUS_BUDGET_MS
            .min(u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX));
        if budget == 0 {
            return Err(Error::Unavailable);
        }
        let unsigned_length = encode_device_request(
            &mut bytes,
            self.device,
            self.pool,
            self.incarnation,
            self.session.session_id(),
            sequence,
            &request,
            budget,
            Operation::DevInspect,
            payload,
            &[0; 32],
        )?;
        let unsigned = Envelope::parse(&bytes[..unsigned_length], EnvelopeKind::DeviceRequest)
            .map_err(|_| Error::Integrity)?;
        let mac = self.session.request_mac(unsigned.map()).map_err(|_| {
            self.valid = false;
            Error::Security
        })?;
        self.request_sequence = self.request_sequence.checked_add(1).ok_or_else(|| {
            self.valid = false;
            Error::Security
        })?;
        let length = encode_device_request(
            &mut bytes,
            self.device,
            self.pool,
            self.incarnation,
            self.session.session_id(),
            sequence,
            &request,
            budget,
            Operation::DevInspect,
            payload,
            &mac,
        )
        .inspect_err(|_| {
            self.valid = false;
        })?;
        let length = wire
            .exchange(&bytes[..length], response, timeout)
            .inspect_err(|_| {
                self.valid = false;
            })?;
        let reply =
            Envelope::parse(&response[..length], EnvelopeKind::DeviceResponse).map_err(|_| {
                self.valid = false;
                Error::Integrity
            })?;
        self.session
            .authenticate_response(
                reply.map(),
                RequestId::from_bytes(request),
                Operation::DevInspect.as_str(),
                sequence,
            )
            .map_err(|_| {
                self.valid = false;
                Error::Security
            })?;
        Ok(length)
    }

    /// Authenticates one local request, sends one device request, authenticates
    /// its bound response, and replaces the frame with a local response.
    pub fn exchange_local(
        &mut self,
        wire: &mut impl DeviceWire,
        local_request: &[u8],
        local_response: &mut [u8; kes_protocol::MAX_FRAME_BYTES],
        timeout: Duration,
    ) -> Result<usize, Error> {
        if !self.valid {
            return Err(Error::Unavailable);
        }
        let local = Envelope::parse(local_request, EnvelopeKind::LocalRequest)
            .map_err(|_| Error::Integrity)?;
        if self.security_mode == "release-unprovisioned" && local.operation != Operation::Status {
            return Err(Error::Security);
        }
        let connection = local
            .map()
            .required("connection")
            .and_then(|value| value.text())
            .map_err(|_| Error::Integrity)?;
        if connection != self.connection {
            return Err(Error::Security);
        }
        let request = local.request().map_err(|_| Error::Integrity)?;
        let budget = local
            .map()
            .required("budget_ms")
            .and_then(|value| value.uint())
            .map_err(|_| Error::Integrity)?;
        let sequence = self.request_sequence;
        let mut device_request = [0; kes_protocol::MAX_FRAME_BYTES];
        let unsigned_length = encode_device_request(
            &mut device_request,
            self.device,
            self.pool,
            self.incarnation,
            self.session.session_id(),
            sequence,
            request.as_bytes(),
            u32::try_from(budget).map_err(|_| Error::Integrity)?,
            local.operation,
            local.payload(),
            &[0; 32],
        )?;
        let unsigned = Envelope::parse(
            &device_request[..unsigned_length],
            EnvelopeKind::DeviceRequest,
        )
        .map_err(|_| Error::Integrity)?;
        let mac = self
            .session
            .request_mac(unsigned.map())
            .map_err(|_| Error::Security)?;
        self.request_sequence = self
            .request_sequence
            .checked_add(1)
            .ok_or(Error::Security)?;
        let request_length = encode_device_request(
            &mut device_request,
            self.device,
            self.pool,
            self.incarnation,
            self.session.session_id(),
            sequence,
            request.as_bytes(),
            u32::try_from(budget).map_err(|_| Error::Integrity)?,
            local.operation,
            local.payload(),
            &mac,
        )?;
        let mut device_response = [0; kes_protocol::MAX_FRAME_BYTES];
        let response_length = match wire.exchange(
            &device_request[..request_length],
            &mut device_response,
            timeout,
        ) {
            Ok(length) => length,
            Err(error) => {
                self.valid = false;
                return Err(error);
            }
        };
        let response = Envelope::parse(
            &device_response[..response_length],
            EnvelopeKind::DeviceResponse,
        )
        .map_err(|_| {
            self.valid = false;
            Error::Integrity
        })?;
        self.session
            .authenticate_response(response.map(), request, local.operation.as_str(), sequence)
            .map_err(|_| {
                self.valid = false;
                Error::Security
            })?;
        if response.operation == Operation::Status
            && response.status == Some(Status::Ok)
            && response
                .payload()
                .required("security_mode")
                .and_then(|value| value.text())
                .map_err(|_| Error::Integrity)?
                != self.security_mode
        {
            self.valid = false;
            return Err(Error::Security);
        }
        encode_local_response(
            local_response,
            &self.connection,
            request.as_bytes(),
            response.operation,
            response.status.ok_or(Error::Integrity)?,
            response.payload(),
        )
    }

    /// Opens the disposable A2 management session using the public qualification
    /// credential. Identity self-pinning is intentionally confined to this
    /// development-only method and is never used by production configuration.
    pub fn open_a2_development(
        wire: &mut impl DeviceWire,
    ) -> Result<(Self, DevelopmentIdentity), Error> {
        let machine = ed25519_dalek::SigningKey::from_bytes(&A2_QUALIFICATION_MACHINE_SEED);
        Self::open_a2_development_with_credential(wire, &machine, CredentialEpoch::new(0))
    }

    /// Self-pin only disposable A2 hardware with the caller's rotated
    /// management credential. Never use this path for release trust.
    pub fn open_a2_development_with_credential(
        wire: &mut impl DeviceWire,
        machine: &ed25519_dalek::SigningKey,
        epoch: CredentialEpoch,
    ) -> Result<(Self, DevelopmentIdentity), Error> {
        let mut entropy = File::open("/dev/urandom").map_err(|_| Error::Unavailable)?;
        let mut challenge = [0; 32];
        let mut info_request = [0; 16];
        entropy
            .read_exact(&mut challenge)
            .and_then(|()| entropy.read_exact(&mut info_request))
            .map_err(|_| Error::Unavailable)?;
        let info_encoded = encode_info_request(info_request, challenge)?;
        let mut response = [0; kes_protocol::MAX_FRAME_BYTES];
        let length = wire.exchange(
            &info_encoded,
            &mut response,
            Duration::from_millis(u64::from(kes_protocol::STATUS_BUDGET_MS)),
        )?;
        let info = Envelope::parse(&response[..length], EnvelopeKind::InfoResponse)
            .map_err(|_| Error::Integrity)?;
        let device_bytes: [u8; 16] = info
            .map()
            .required("device")
            .and_then(|value| value.bytes())
            .map_err(|_| Error::Integrity)?
            .try_into()
            .map_err(|_| Error::Integrity)?;
        let payload = info.payload();
        let identity_public_key: [u8; 32] = payload
            .required("identity_public_key")
            .and_then(|value| value.bytes())
            .map_err(|_| Error::Integrity)?
            .try_into()
            .map_err(|_| Error::Integrity)?;
        let device = DeviceId::from_bytes(device_bytes);
        let mut scratch = [0; INFO_TRANSCRIPT_BYTES];
        let view = verify_info(
            info.map(),
            device,
            RequestId::from_bytes(info_request),
            &challenge,
            &identity_public_key,
            &mut scratch,
        )
        .map_err(|_| Error::Security)?;
        let firmware_digest = payload
            .required("firmware_digest")
            .and_then(|value| value.bytes())
            .map_err(|_| Error::Integrity)?;
        let policy_digest = payload
            .required("hardware_policy_digest")
            .and_then(|value| value.bytes())
            .map_err(|_| Error::Integrity)?;
        let mode = payload
            .required("security_mode")
            .and_then(|value| value.text())
            .map_err(|_| Error::Integrity)?;
        let capability = payload
            .required("capability_evidence")
            .and_then(|value| value.bytes())
            .map_err(|_| Error::Integrity)?;
        let security_version = payload
            .required("security_version")
            .and_then(|value| value.uint())
            .map_err(|_| Error::Integrity)?;
        if mode != "development"
            || firmware_digest != [0; 32]
            || policy_digest != A2_DEVELOPMENT_POLICY_DIGEST
            || (capability != A2_DEVELOPMENT_CAPABILITY && capability != A2_ENROLLMENT_CAPABILITY)
            || security_version != 0
        {
            return Err(Error::Security);
        }
        let counter = open_counter(payload, None, None)?;
        let mut open_request = [0; 16];
        let mut seed = Zeroizing::new([0; 32]);
        entropy
            .read_exact(&mut open_request)
            .and_then(|()| entropy.read_exact(&mut *seed))
            .map_err(|_| Error::Unavailable)?;
        let context = OpenContext::new(
            device,
            view.boot_nonce,
            Scope::Management,
            epoch,
            counter,
            RequestId::from_bytes(open_request),
        );
        let mut rng = ChaCha20Rng::from_seed(*seed);
        let (open, pending) = begin_open(context, &view.hpke_public_key, machine, &mut rng)
            .map_err(|_| Error::Security)?;
        let encoded_open = encode_open_request(&open)?;
        let length = wire.exchange(
            &encoded_open,
            &mut response,
            Duration::from_millis(u64::from(kes_protocol::STATUS_BUDGET_MS)),
        )?;
        let open_response = Envelope::parse(&response[..length], EnvelopeKind::OpenResponse)
            .map_err(|_| Error::Integrity)?;
        let session = pending
            .complete(open_response.map())
            .map_err(|_| Error::Security)?;
        let identity = DevelopmentIdentity {
            device: device_bytes,
            identity_public_key,
            hpke_public_key: view.hpke_public_key,
            boot_nonce: view.boot_nonce,
        };
        Ok((
            Self {
                connection: "a2-development".to_owned(),
                device: device_bytes,
                pool: None,
                incarnation: None,
                session,
                boot_nonce: view.boot_nonce,
                security_mode: "development",
                request_sequence: 0,
                valid: true,
            },
            identity,
        ))
    }
}

pub struct GenerationResult {
    pub generation: [u8; 16],
    pub generation_number: u64,
    pub creation_request: [u8; 16],
    pub verification_key: [u8; 32],
    pub artifact_digest: [u8; 32],
    pub revision: u64,
}

pub struct BackupResult {
    pub generation: [u8; 16],
    pub backup: Vec<u8>,
    pub artifact_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Descriptor {
    pub generation: [u8; 16],
    pub verification_key: [u8; 32],
    pub certificate_digest: Option<[u8; 32]>,
    pub certificate_start: Option<u64>,
    pub certificate_counter: Option<u64>,
    pub revision: u64,
    pub relative_period: u64,
    pub lifecycle: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoolStatus {
    pub revision: u64,
    pub active: Option<Descriptor>,
    pub staged: Option<Descriptor>,
}

pub fn pool_status(
    connection: &PublicPoolConnection,
    request: [u8; 16],
) -> Result<PoolStatus, Error> {
    let mut response = [0; kes_protocol::MAX_FRAME_BYTES];
    let length = exchange(
        LocalConnection::Pool(connection),
        request,
        Operation::Status,
        kes_protocol::STATUS_BUDGET_MS,
        |encoder| encoder.map(0),
        &mut response,
    )?;
    let envelope = parse_response(
        &connection.connection_name,
        request,
        Operation::Status,
        &response[..length],
    )?;
    require_ok(envelope.status.ok_or(Error::Integrity)?)?;
    let payload = envelope.payload();
    Ok(PoolStatus {
        revision: number(payload, "revision")?,
        active: optional_descriptor(payload.required("active").map_err(|_| Error::Integrity)?)?,
        staged: optional_descriptor(payload.required("staged").map_err(|_| Error::Integrity)?)?,
    })
}

pub fn certify(
    connection: &PublicPoolConnection,
    request: [u8; 16],
    generation: [u8; 16],
    canonical_certificate: &[u8],
    expected_revision: u64,
) -> Result<Descriptor, Error> {
    Value::parse(canonical_certificate).map_err(|_| Error::Integrity)?;
    rotation_exchange(connection, request, Operation::Certify, |encoder| {
        encoder.map(4)?;
        encoder.text("network")?;
        encode_network(encoder, connection)?;
        encoder.text("generation")?;
        encoder.bytes(&generation)?;
        encoder.text("certificate")?;
        encoder.bytes(canonical_certificate)?;
        encoder.text("expected_revision")?;
        encoder.uint(expected_revision)
    })
}

pub fn activate(
    connection: &PublicPoolConnection,
    request: [u8; 16],
    generation: [u8; 16],
    certificate_digest: [u8; 32],
    current_absolute_period: u64,
    expected_active_generation: Option<[u8; 16]>,
    expected_revision: u64,
) -> Result<Descriptor, Error> {
    rotation_exchange(connection, request, Operation::Activate, |encoder| {
        encoder.map(5)?;
        encoder.text("generation")?;
        encoder.bytes(&generation)?;
        encoder.text("expected_revision")?;
        encoder.uint(expected_revision)?;
        encoder.text("certificate_digest")?;
        encoder.bytes(&certificate_digest)?;
        encoder.text("current_absolute_period")?;
        encoder.uint(current_absolute_period)?;
        encoder.text("expected_active_generation")?;
        encode_optional_bytes(encoder, expected_active_generation.as_ref())
    })
}

pub fn schedule(
    connection: &PublicPoolConnection,
    request: [u8; 16],
    generation: [u8; 16],
    certificate_digest: [u8; 32],
    activation_absolute_period: u64,
    expected_active_generation: [u8; 16],
    expected_revision: u64,
) -> Result<Descriptor, Error> {
    rotation_exchange(connection, request, Operation::Schedule, |encoder| {
        encoder.map(5)?;
        encoder.text("generation")?;
        encoder.bytes(&generation)?;
        encoder.text("expected_revision")?;
        encoder.uint(expected_revision)?;
        encoder.text("certificate_digest")?;
        encoder.bytes(&certificate_digest)?;
        encoder.text("activation_absolute_period")?;
        encoder.uint(activation_absolute_period)?;
        encoder.text("expected_active_generation")?;
        encoder.bytes(&expected_active_generation)
    })
}

pub fn generate(
    connection: &PublicPoolConnection,
    request: [u8; 16],
    generation_number: u64,
    expected_revision: u64,
) -> Result<GenerationResult, Error> {
    let mut response = [0; kes_protocol::MAX_FRAME_BYTES];
    let initial = exchange(
        LocalConnection::Pool(connection),
        request,
        Operation::Generate,
        kes_protocol::GENERATION_BUDGET_MS,
        |encoder| {
            encoder.map(2)?;
            encoder.text("expected_revision")?;
            encoder.uint(expected_revision)?;
            encoder.text("next_generation_number")?;
            encoder.uint(generation_number)
        },
        &mut response,
    );
    match initial {
        Ok(length) => {
            let envelope = parse_response(
                &connection.connection_name,
                request,
                Operation::Generate,
                &response[..length],
            )?;
            match envelope.status.ok_or(Error::Integrity)? {
                Status::Ok => parse_generation_envelope(envelope, request, generation_number),
                Status::InProgress => {
                    let payload = envelope.payload();
                    if fixed::<16>(payload, "request")? != request
                        || number(payload, "generation_number")? != generation_number
                    {
                        return Err(Error::Security);
                    }
                    generation_status(connection, request, generation_number)
                }
                status => {
                    require_ok(status)?;
                    unreachable!()
                }
            }
        }
        Err(Error::Unavailable) => generation_status(connection, request, generation_number),
        Err(error) => Err(error),
    }
}

pub fn generation_status(
    connection: &PublicPoolConnection,
    request: [u8; 16],
    generation_number: u64,
) -> Result<GenerationResult, Error> {
    let mut response = [0; kes_protocol::MAX_FRAME_BYTES];
    let length = exchange(
        LocalConnection::Pool(connection),
        request,
        Operation::OpStatus,
        kes_protocol::STATUS_BUDGET_MS,
        |encoder| {
            encoder.map(2)?;
            encoder.text("request")?;
            encoder.bytes(&request)?;
            encoder.text("generation_number")?;
            encoder.uint(generation_number)
        },
        &mut response,
    )?;
    parse_generation_response(
        connection,
        request,
        generation_number,
        Operation::OpStatus,
        &response[..length],
    )
}

pub fn get_backup(
    connection: &PublicPoolConnection,
    request: [u8; 16],
    generation: [u8; 16],
) -> Result<BackupResult, Error> {
    let mut response = [0; kes_protocol::MAX_FRAME_BYTES];
    let length = exchange(
        LocalConnection::Pool(connection),
        request,
        Operation::GetBackup,
        kes_protocol::GENERATION_BUDGET_MS,
        |encoder| {
            encoder.map(1)?;
            encoder.text("generation")?;
            encoder.bytes(&generation)
        },
        &mut response,
    )?;
    let envelope = parse_response(
        &connection.connection_name,
        request,
        Operation::GetBackup,
        &response[..length],
    )?;
    require_ok(envelope.status.ok_or(Error::Integrity)?)?;
    let payload = envelope.payload();
    let returned_generation = fixed(payload, "generation")?;
    if returned_generation != generation {
        return Err(Error::Security);
    }
    let backup = payload
        .required("backup")
        .map_err(|_| Error::Integrity)?
        .bytes()
        .map_err(|_| Error::Integrity)?
        .to_vec();
    Ok(BackupResult {
        generation,
        backup,
        artifact_digest: fixed(payload, "artifact_digest")?,
    })
}

fn rotation_exchange(
    connection: &PublicPoolConnection,
    request: [u8; 16],
    operation: Operation,
    payload: impl FnOnce(&mut Encoder<'_>) -> Result<(), kes_core::cbor::Error>,
) -> Result<Descriptor, Error> {
    let mut response = [0; kes_protocol::MAX_FRAME_BYTES];
    let length = exchange(
        LocalConnection::Pool(connection),
        request,
        operation,
        kes_protocol::STATUS_BUDGET_MS,
        payload,
        &mut response,
    )?;
    let envelope = parse_response(
        &connection.connection_name,
        request,
        operation,
        &response[..length],
    )?;
    require_ok(envelope.status.ok_or(Error::Integrity)?)?;
    parse_descriptor(envelope.payload())
}

fn parse_descriptor(payload: Map<'_>) -> Result<Descriptor, Error> {
    Ok(Descriptor {
        generation: fixed(payload, "generation")?,
        verification_key: fixed(payload, "verification_key")?,
        certificate_digest: optional_fixed(
            payload
                .required("certificate_digest")
                .map_err(|_| Error::Integrity)?,
        )?,
        certificate_start: optional_number(
            payload
                .required("certificate_start")
                .map_err(|_| Error::Integrity)?,
        )?,
        certificate_counter: optional_number(
            payload
                .required("certificate_counter")
                .map_err(|_| Error::Integrity)?,
        )?,
        revision: number(payload, "revision")?,
        relative_period: number(payload, "relative_period")?,
        lifecycle: payload
            .required("lifecycle")
            .map_err(|_| Error::Integrity)?
            .text()
            .map_err(|_| Error::Integrity)?
            .to_owned(),
    })
}

fn optional_descriptor(value: Value<'_>) -> Result<Option<Descriptor>, Error> {
    if value.is_null() {
        Ok(None)
    } else {
        value
            .map()
            .map_err(|_| Error::Integrity)
            .and_then(parse_descriptor)
            .map(Some)
    }
}

fn optional_fixed<const N: usize>(value: Value<'_>) -> Result<Option<[u8; N]>, Error> {
    if value.is_null() {
        Ok(None)
    } else {
        value
            .bytes()
            .map_err(|_| Error::Integrity)?
            .try_into()
            .map(Some)
            .map_err(|_| Error::Integrity)
    }
}

fn optional_number(value: Value<'_>) -> Result<Option<u64>, Error> {
    if value.is_null() {
        Ok(None)
    } else {
        value.uint().map(Some).map_err(|_| Error::Integrity)
    }
}

fn encode_optional_bytes(
    encoder: &mut Encoder<'_>,
    value: Option<&[u8; 16]>,
) -> Result<(), kes_core::cbor::Error> {
    match value {
        Some(bytes) => encoder.bytes(bytes),
        None => encoder.null(),
    }
}

fn encode_network(
    encoder: &mut Encoder<'_>,
    connection: &PublicPoolConnection,
) -> Result<(), kes_core::cbor::Error> {
    let network = &connection.network_binding;
    let digest = decode_hex_32(&network.shelley_genesis_digest)
        .expect("validated PoolConnection contains a canonical genesis digest");
    encoder.map(4)?;
    encoder.text("network_magic")?;
    encoder.uint(network.network_magic)?;
    encoder.text("max_kes_evolutions")?;
    encoder.uint(network.max_kes_evolutions)?;
    encoder.text("slots_per_kes_period")?;
    encoder.uint(network.slots_per_kes_period)?;
    encoder.text("shelley_genesis_digest")?;
    encoder.bytes(&digest)
}

fn decode_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut output = [0; 32];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        output[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(output)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn parse_generation_response(
    connection: &PublicPoolConnection,
    request: [u8; 16],
    generation_number: u64,
    operation: Operation,
    response: &[u8],
) -> Result<GenerationResult, Error> {
    let envelope = parse_response(&connection.connection_name, request, operation, response)?;
    parse_generation_envelope(envelope, request, generation_number)
}

fn parse_generation_envelope(
    envelope: Envelope<'_>,
    request: [u8; 16],
    generation_number: u64,
) -> Result<GenerationResult, Error> {
    require_ok(envelope.status.ok_or(Error::Integrity)?)?;
    let payload = envelope.payload();
    let result = GenerationResult {
        generation: fixed(payload, "generation")?,
        generation_number: number(payload, "generation_number")?,
        creation_request: fixed(payload, "creation_request")?,
        verification_key: fixed(payload, "verification_key")?,
        artifact_digest: fixed(payload, "artifact_digest")?,
        revision: number(payload, "revision")?,
    };
    if result.generation_number != generation_number || result.creation_request != request {
        return Err(Error::Security);
    }
    Ok(result)
}

/// Send a public management request through the configured local daemon. The
/// daemon owns transport credentials; this API never accepts offline authority.
/// Preserve typed response statuses so the caller can reconcile uncertain work.
pub fn management_exchange(
    config: &DeviceConnection,
    request: [u8; 16],
    operation: Operation,
    canonical_payload: &[u8],
) -> Result<Vec<u8>, Error> {
    if !matches!(
        operation,
        Operation::Status | Operation::Manage | Operation::OpStatus
    ) {
        return Err(Error::Security);
    }
    let payload = Value::parse(canonical_payload).map_err(|_| Error::Integrity)?;
    payload.map().map_err(|_| Error::Integrity)?;
    let mut response = vec![0; kes_protocol::MAX_FRAME_BYTES];
    let length = exchange(
        LocalConnection::Device(config),
        request,
        operation,
        kes_protocol::STATUS_BUDGET_MS,
        |encoder| encoder.value(payload),
        &mut response,
    )?;
    parse_response(
        &config.connection_name,
        request,
        operation,
        &response[..length],
    )?;
    response.truncate(length);
    Ok(response)
}

enum LocalConnection<'a> {
    Device(&'a DeviceConnection),
    Pool(&'a PublicPoolConnection),
}

fn exchange(
    connection: LocalConnection<'_>,
    request: [u8; 16],
    operation: Operation,
    budget_ms: u32,
    payload: impl FnOnce(&mut Encoder<'_>) -> Result<(), kes_core::cbor::Error>,
    response: &mut [u8],
) -> Result<usize, Error> {
    let (socket_path, connection_name) = match connection {
        LocalConnection::Device(device) => (&device.socket_path, &device.connection_name),
        LocalConnection::Pool(pool) => (&pool.socket_path, &pool.connection_name),
    };
    let mut body = [0; kes_protocol::MAX_FRAME_BYTES];
    let mut encoder = Encoder::new(&mut body);
    encoder.map(7).map_err(|_| Error::Integrity)?;
    encoder.text("op").map_err(|_| Error::Integrity)?;
    encoder
        .text(operation.as_str())
        .map_err(|_| Error::Integrity)?;
    encoder.text("target").map_err(|_| Error::Integrity)?;
    encode_local_target(&mut encoder, &connection).map_err(|_| Error::Integrity)?;
    encoder.text("payload").map_err(|_| Error::Integrity)?;
    payload(&mut encoder).map_err(|_| Error::Integrity)?;
    encoder.text("request").map_err(|_| Error::Integrity)?;
    encoder.bytes(&request).map_err(|_| Error::Integrity)?;
    encoder.text("version").map_err(|_| Error::Integrity)?;
    encoder.uint(1).map_err(|_| Error::Integrity)?;
    encoder.text("budget_ms").map_err(|_| Error::Integrity)?;
    encoder
        .uint(u64::from(budget_ms))
        .map_err(|_| Error::Integrity)?;
    encoder.text("connection").map_err(|_| Error::Integrity)?;
    encoder
        .text(connection_name)
        .map_err(|_| Error::Integrity)?;
    let encoded = encoder.finish().map_err(|_| Error::Integrity)?.encoded();
    Envelope::parse(encoded, EnvelopeKind::LocalRequest).map_err(|_| Error::Integrity)?;

    let mut stream = UnixStream::connect(socket_path).map_err(|_| Error::Unavailable)?;
    let timeout = Duration::from_millis(u64::from(budget_ms));
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|_| Error::Unavailable)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| Error::Unavailable)?;
    stream
        .write_all(&(encoded.len() as u32).to_be_bytes())
        .and_then(|()| stream.write_all(encoded))
        .map_err(|_| Error::Unavailable)?;
    let mut prefix = [0; 4];
    stream
        .read_exact(&mut prefix)
        .map_err(|_| Error::Unavailable)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > response.len() {
        return Err(Error::Integrity);
    }
    stream
        .read_exact(&mut response[..length])
        .map_err(|_| Error::Unavailable)?;
    Ok(length)
}

fn parse_response<'a>(
    connection_name: &str,
    request: [u8; 16],
    operation: Operation,
    response: &'a [u8],
) -> Result<Envelope<'a>, Error> {
    let envelope =
        Envelope::parse(response, EnvelopeKind::LocalResponse).map_err(|_| Error::Integrity)?;
    if envelope.operation != operation
        || envelope.request().map_err(|_| Error::Integrity)?.as_bytes() != &request
    {
        return Err(Error::Security);
    }
    let returned_connection = envelope
        .map()
        .required("connection")
        .map_err(|_| Error::Integrity)?
        .text()
        .map_err(|_| Error::Integrity)?;
    if returned_connection != connection_name {
        return Err(Error::Security);
    }
    Ok(envelope)
}

fn fixed<const N: usize>(map: Map<'_>, field: &str) -> Result<[u8; N], Error> {
    map.required(field)
        .map_err(|_| Error::Integrity)?
        .bytes()
        .map_err(|_| Error::Integrity)?
        .try_into()
        .map_err(|_| Error::Integrity)
}

fn number(map: Map<'_>, field: &str) -> Result<u64, Error> {
    map.required(field)
        .map_err(|_| Error::Integrity)?
        .uint()
        .map_err(|_| Error::Integrity)
}

fn require_ok(status: Status) -> Result<(), Error> {
    match status {
        Status::Ok => Ok(()),
        Status::AuthFailed
        | Status::Replay
        | Status::WrongDevice
        | Status::WrongPool
        | Status::WrongNetwork
        | Status::SecurityNotReady
        | Status::RecipientInvalid => Err(Error::Security),
        Status::Capacity
        | Status::RevisionConflict
        | Status::StagedConflict
        | Status::StaleGeneration
        | Status::StalePeriod
        | Status::NotYetValid
        | Status::Expired
        | Status::CertificateInvalid => Err(Error::Conflict),
        Status::ResultReclaimed => Err(Error::ResultReclaimed),
        Status::InProgress => Err(Error::InProgress),
        Status::Unknown => Err(Error::Unknown),
        Status::NotCommitted => Err(Error::NotCommitted),
        Status::StateDamaged => Err(Error::Damaged),
        _ => Err(Error::Unavailable),
    }
}
