//! Public management handoffs and offline authorization. Transport credentials
//! never confer the authority represented by an offline management signature.
use super::{
    bootstrap, client, config,
    operations::{Identity, OperationRecord, State},
};
use kes_core::{
    cbor::{Encoder, Map, Value},
    management::{self, Action, SigningFields, Target},
    types::*,
};
use kes_protocol::{Envelope, EnvelopeKind, Operation, Status};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Invalid,
    Security,
    Conflict,
    Unavailable,
    Integrity,
    Filesystem,
}
impl Error {
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::Invalid => 2,
            Self::Security => 3,
            Self::Conflict => 4,
            Self::Unavailable => 5,
            Self::Integrity => 6,
            Self::Filesystem => 7,
        }
    }
    pub const fn code(self) -> &'static str {
        match self {
            Self::Invalid => "INVALID_CONFIGURATION",
            Self::Security => "AUTHENTICATION_FAILED",
            Self::Conflict => "CONFLICT",
            Self::Unavailable => "UNAVAILABLE",
            Self::Integrity => "INTEGRITY_FAILURE",
            Self::Filesystem => "PUBLICATION_FAILED",
        }
    }
}
impl From<kes_core::cbor::Error> for Error {
    fn from(_: kes_core::cbor::Error) -> Self {
        Self::Invalid
    }
}
impl From<management::Error> for Error {
    fn from(_: management::Error) -> Self {
        Self::Invalid
    }
}
pub fn action(name: &str) -> Result<Action, Error> {
    Ok(match name {
        "ENROLL" => Action::Enroll,
        "RECIPIENT_REPLACE" => Action::RecipientReplace,
        "CREDENTIAL_REPLACE" => Action::CredentialReplace,
        "CREDENTIAL_REVOKE" => Action::CredentialRevoke,
        "STAGED_DISCARD" => Action::StagedDiscard,
        "POOL_DELETE" => Action::PoolDelete,
        "DEVICE_RETIRE" => Action::DeviceRetire,
        "FIRMWARE_AUTHORIZE" => Action::FirmwareAuthorize,
        _ => return Err(Error::Invalid),
    })
}

/// Non-enrollment payload handoff. canonicalPayload is exact lowercase hex of
/// the contract's canonical closed CBOR action map, not JSON-normalized CBOR.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PayloadFile {
    version: u64,
    pool_id: serde_json::Value,
    incarnation_id: serde_json::Value,
    canonical_payload: String,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrollmentPayload {
    pub version: u64,
    pub device_id: String,
    pub pool_id: String,
    pub incarnation_id: String,
    pub cold_verification_key: String,
    pub network_binding: Network,
    pub machine_public_key: String,
    pub credential_epoch: u64,
    pub recipient_public_key: String,
    pub recipient_id: String,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Network {
    pub network_magic: u32,
    pub shelley_genesis_digest: String,
    pub slots_per_kes_period: u64,
    pub max_kes_evolutions: u64,
}

pub fn read_public(path: &Path) -> Result<Vec<u8>, Error> {
    read_public_bounded(path, 16384)
}

pub(crate) fn read_public_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, Error> {
    validate_ancestry(path, false)?;
    let mut file = checked_file(path, false)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(limit.checked_add(1).ok_or(Error::Invalid)? as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Filesystem)?;
    if bytes.len() > limit {
        return Err(Error::Invalid);
    }
    Ok(bytes)
}
pub(crate) fn checked_file(path: &Path, private: bool) -> Result<File, Error> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|_| Error::Filesystem)?;
    let m = file.metadata().map_err(|_| Error::Filesystem)?;
    let uid = rustix::process::getuid().as_raw();
    if !m.is_file()
        || (m.uid() != uid && (private || m.uid() != 0))
        || if private {
            m.mode() & 0o777 != 0o600
        } else {
            m.mode() & 0o022 != 0
        }
    {
        return Err(Error::Security);
    }
    Ok(file)
}
pub(crate) fn validate_ancestry(path: &Path, private: bool) -> Result<(), Error> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| Error::Filesystem)?
            .join(path)
    };
    if absolute
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(Error::Security);
    }
    let mut directory = absolute.parent().ok_or(Error::Security)?;
    let mut immediate = true;
    loop {
        let m = std::fs::symlink_metadata(directory).map_err(|_| Error::Filesystem)?;
        let uid = rustix::process::getuid().as_raw();
        if !m.is_dir()
            || (m.uid() != uid && m.uid() != 0)
            || (m.mode() & 0o022 != 0 && !(m.uid() == 0 && m.mode() & 0o1000 != 0))
            || (immediate && private && (m.uid() != uid || m.mode() & 0o077 != 0))
        {
            return Err(Error::Security);
        }
        immediate = false;
        match directory.parent() {
            Some(parent) => directory = parent,
            None => break,
        }
    }
    Ok(())
}
pub fn publish(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    validate_ancestry(path, false)?;
    // Shared atomic anonymous-inode publication accepts only exact public retries.
    super::publication::publish_rotation_certificate(path, bytes).map_err(|_| Error::Filesystem)
}
pub fn hex(bytes: &[u8]) -> String {
    const D: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 15) as usize] as char)
    }
    s
}
fn unhex(s: &str) -> Result<Vec<u8>, Error> {
    if !s.len().is_multiple_of(2) {
        return Err(Error::Invalid);
    }
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| {
            let n = |b| match b {
                b'0'..=b'9' => Ok(b - b'0'),
                b'a'..=b'f' => Ok(b - b'a' + 10),
                _ => Err(Error::Invalid),
            };
            Ok(n(p[0])? * 16 + n(p[1])?)
        })
        .collect()
}
fn fixed<const N: usize>(v: Value<'_>) -> Result<[u8; N], Error> {
    v.bytes()?.try_into().map_err(|_| Error::Invalid)
}
fn target(pool: Value<'_>, incarnation: Value<'_>) -> Result<Target, Error> {
    match (pool.is_null(), incarnation.is_null()) {
        (true, true) => Ok(Target::Device),
        (false, false) => Ok(Target::Pool {
            pool: PoolId::from_bytes(fixed(pool)?),
            incarnation: IncarnationId::from_bytes(fixed(incarnation)?),
        }),
        _ => Err(Error::Invalid),
    }
}
fn json_target(pool: &serde_json::Value, inc: &serde_json::Value) -> Result<Target, Error> {
    match (pool, inc) {
        (serde_json::Value::Null, serde_json::Value::Null) => Ok(Target::Device),
        (serde_json::Value::String(p), serde_json::Value::String(i)) => Ok(Target::Pool {
            pool: PoolId::from_bytes(config::decode_hex(p).ok_or(Error::Invalid)?),
            incarnation: IncarnationId::from_bytes(config::decode_hex(i).ok_or(Error::Invalid)?),
        }),
        _ => Err(Error::Invalid),
    }
}
fn encode(
    build: impl FnOnce(&mut Encoder<'_>) -> Result<(), kes_core::cbor::Error>,
) -> Result<Vec<u8>, Error> {
    let mut bytes = [0; 8192];
    let mut e = Encoder::new(&mut bytes);
    build(&mut e)?;
    Ok(e.finish()?.encoded().to_vec())
}
fn enrollment_cbor(p: &EnrollmentPayload) -> Result<Vec<u8>, Error> {
    let device = config::decode_hex::<16>(&p.device_id).ok_or(Error::Invalid)?;
    let pool = config::decode_hex::<28>(&p.pool_id).ok_or(Error::Invalid)?;
    let inc = config::decode_hex::<16>(&p.incarnation_id).ok_or(Error::Invalid)?;
    let cold = config::decode_hex::<32>(&p.cold_verification_key).ok_or(Error::Invalid)?;
    let machine = config::decode_spki(&p.machine_public_key).ok_or(Error::Invalid)?;
    let recipient = config::decode_hex::<32>(&p.recipient_public_key).ok_or(Error::Invalid)?;
    let rid = config::decode_hex::<32>(&p.recipient_id).ok_or(Error::Invalid)?;
    let digest = config::decode_hex::<32>(&p.network_binding.shelley_genesis_digest)
        .ok_or(Error::Invalid)?;
    encode(|e| {
        e.map(10)?;
        e.text("pool")?;
        e.bytes(&pool)?;
        e.text("device")?;
        e.bytes(&device)?;
        e.text("network")?;
        e.map(4)?;
        e.text("network_magic")?;
        e.uint(u64::from(p.network_binding.network_magic))?;
        e.text("max_kes_evolutions")?;
        e.uint(p.network_binding.max_kes_evolutions)?;
        e.text("slots_per_kes_period")?;
        e.uint(p.network_binding.slots_per_kes_period)?;
        e.text("shelley_genesis_digest")?;
        e.bytes(&digest)?;
        e.text("version")?;
        e.uint(p.version)?;
        e.text("incarnation")?;
        e.bytes(&inc)?;
        e.text("recipient_id")?;
        e.bytes(&rid)?;
        e.text("credential_epoch")?;
        e.uint(p.credential_epoch)?;
        e.text("machine_public_key")?;
        e.bytes(&machine)?;
        e.text("recipient_public_key")?;
        e.bytes(&recipient)?;
        e.text("cold_verification_key")?;
        e.bytes(&cold)
    })
}

pub struct EnrollmentInputs<'a> {
    pub device_config: &'a Path,
    pub cold_key: &'a Path,
    pub genesis: &'a Path,
    pub network_magic: u32,
    pub recipient: &'a Path,
    pub machine: &'a Path,
    pub incarnation: [u8; 16],
}
pub fn enrollment_create(input: EnrollmentInputs<'_>, out: &Path) -> Result<(), Error> {
    let config =
        config::DeviceConnection::load(input.device_config).map_err(|_| Error::Security)?;
    let status = client::management_exchange(&config, random()?, Operation::Status, &[0xa0])
        .map_err(client_error)?;
    let reply = response(&status)?;
    ok(reply.status.ok_or(Error::Integrity)?)?;
    for entry in reply.payload().required("directory")?.array()? {
        if fixed::<16>(entry.map()?.required("incarnation")?)? == input.incarnation {
            return Err(Error::Conflict);
        }
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Cold {
        #[serde(rename = "type")]
        kind: String,
        description: String,
        #[serde(rename = "cborHex")]
        cbor_hex: String,
    }
    let cold: Cold =
        serde_json::from_slice(&read_public(input.cold_key)?).map_err(|_| Error::Invalid)?;
    let _ = cold.description;
    if cold.kind != "StakePoolVerificationKey_ed25519" {
        return Err(Error::Invalid);
    }
    let cold_bytes = unhex(&cold.cbor_hex)?;
    let vk: [u8; 32] = fixed(Value::parse(&cold_bytes)?)?;
    let pool = PoolId::from_cold_verification_key(&vk);
    let genesis = read_public(input.genesis)?;
    // Shelley genesis has many unrelated fields. Deserialize only required network
    // fields while still rejecting duplicates of those fields and trailing data.
    #[derive(Deserialize)]
    struct Genesis {
        #[serde(rename = "networkMagic")]
        magic: u32,
        #[serde(rename = "slotsPerKESPeriod")]
        slots: u64,
        #[serde(rename = "maxKESEvolutions")]
        evolutions: u64,
    }
    let g: Genesis = serde_json::from_slice(&genesis).map_err(|_| Error::Invalid)?;
    if g.magic != input.network_magic || g.slots == 0 || !(1..=64).contains(&g.evolutions) {
        return Err(Error::Invalid);
    }
    let m = bootstrap::machine_public(&read_public(input.machine)?, bootstrap::MachineScope::Pool)
        .map_err(|_| Error::Invalid)?;
    if m.device != config.device_id
        || m.pool != Some(*pool.as_bytes())
        || m.incarnation != Some(input.incarnation)
        || m.epoch != 0
    {
        return Err(Error::Security);
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Recipient {
        version: u64,
        algorithm: String,
        public_key: String,
        recipient_id: String,
    }
    let r: Recipient =
        serde_json::from_slice(&read_public(input.recipient)?).map_err(|_| Error::Invalid)?;
    let rp = config::decode_hex::<32>(&r.public_key).ok_or(Error::Invalid)?;
    let ri = config::decode_hex::<32>(&r.recipient_id).ok_or(Error::Invalid)?;
    if r.version != 1 || r.algorithm != "X25519" || <[u8; 32]>::from(Sha256::digest(rp)) != ri {
        return Err(Error::Invalid);
    }
    let mut spki = [0; 44];
    spki[..12].copy_from_slice(&[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0,
    ]);
    spki[12..].copy_from_slice(&m.public_key);
    let payload = EnrollmentPayload {
        version: 1,
        device_id: hex(&config.device_id),
        pool_id: hex(pool.as_bytes()),
        incarnation_id: hex(&input.incarnation),
        cold_verification_key: hex(&vk),
        network_binding: Network {
            network_magic: g.magic,
            shelley_genesis_digest: hex(&Sha256::digest(&genesis)),
            slots_per_kes_period: g.slots,
            max_kes_evolutions: g.evolutions,
        },
        machine_public_key: config::encode_base64(&spki),
        credential_epoch: 0,
        recipient_public_key: r.public_key,
        recipient_id: r.recipient_id,
    };
    let canonical = enrollment_cbor(&payload)?;
    management::validate_payload(
        Action::Enroll,
        Value::parse(&canonical)?,
        DeviceId::from_bytes(config.device_id),
        Target::Pool {
            pool,
            incarnation: IncarnationId::from_bytes(input.incarnation),
        },
    )?;
    publish(
        out,
        &serde_json::to_vec(&payload).map_err(|_| Error::Invalid)?,
    )
}

pub fn parse_request(bytes: &[u8]) -> Result<SigningFields<'_>, Error> {
    let m = Value::parse(bytes)?.map()?;
    if m.len() != 8 {
        return Err(Error::Invalid);
    }
    let a = action(m.required("action")?.text()?)?;
    let d = DeviceId::from_bytes(fixed(m.required("device")?)?);
    let t = target(m.required("pool")?, m.required("incarnation")?)?;
    let raw = m.required("canonical_payload")?.bytes()?;
    if raw.len() > 4096 {
        return Err(Error::Invalid);
    }
    let payload = Value::parse(raw)?;
    management::validate_target(a, t)?;
    management::validate_payload(a, payload, d, t)?;
    if m.required("management_sequence")?.uint()? == 0
        || m.required("expected_revision")?.uint()? == u64::MAX
    {
        return Err(Error::Conflict);
    }
    Ok(SigningFields {
        device: d,
        target: t,
        sequence: ManagementSequence::new(m.required("management_sequence")?.uint()?),
        request: RequestId::from_bytes(fixed(m.required("request")?)?),
        expected_revision: Revision::new(m.required("expected_revision")?.uint()?),
        action: a,
        canonical_payload: payload,
    })
}
fn envelope(fields: SigningFields<'_>, signature: Option<&[u8; 64]>) -> Result<Vec<u8>, Error> {
    encode(|e| {
        e.map(if signature.is_some() { 9 } else { 8 })?;
        e.text("pool")?;
        match fields.target {
            Target::Device => e.null()?,
            Target::Pool { pool, .. } => e.bytes(pool.as_bytes())?,
        };
        e.text("action")?;
        e.text(fields.action.name())?;
        e.text("device")?;
        e.bytes(fields.device.as_bytes())?;
        e.text("request")?;
        e.bytes(fields.request.as_bytes())?;
        if let Some(s) = signature {
            e.text("signature")?;
            e.bytes(s)?
        }
        e.text("incarnation")?;
        match fields.target {
            Target::Device => e.null()?,
            Target::Pool { incarnation, .. } => e.bytes(incarnation.as_bytes())?,
        };
        e.text("canonical_payload")?;
        e.bytes(fields.canonical_payload.encoded())?;
        e.text("expected_revision")?;
        e.uint(fields.expected_revision.get())?;
        e.text("management_sequence")?;
        e.uint(fields.sequence.get())
    })
}
fn response(bytes: &[u8]) -> Result<Envelope<'_>, Error> {
    Envelope::parse(bytes, EnvelopeKind::LocalResponse).map_err(|_| Error::Integrity)
}
fn ok(status: Status) -> Result<(), Error> {
    match status {
        Status::Ok => Ok(()),
        Status::AuthFailed
        | Status::WrongDevice
        | Status::WrongPool
        | Status::WrongNetwork
        | Status::SecurityNotReady => Err(Error::Security),
        Status::EntropyFailure
        | Status::DeviceUnavailable
        | Status::DeadlineExceeded
        | Status::Busy
        | Status::Unknown
        | Status::InProgress => Err(Error::Unavailable),
        Status::StateDamaged => Err(Error::Integrity),
        Status::InvalidFrame | Status::UnsupportedVersion | Status::UnsupportedOperation => {
            Err(Error::Invalid)
        }
        _ => Err(Error::Conflict),
    }
}
fn client_error(e: client::Error) -> Error {
    match e {
        client::Error::Security => Error::Security,
        client::Error::Integrity | client::Error::Damaged => Error::Integrity,
        client::Error::Conflict | client::Error::NotCommitted => Error::Conflict,
        _ => Error::Unavailable,
    }
}
fn random() -> Result<[u8; 16], Error> {
    let mut b = [0; 16];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .map_err(|_| Error::Unavailable)?;
    Ok(b)
}

pub fn prepare(
    config: &config::DeviceConnection,
    a: Action,
    payload_path: &Path,
    out: &Path,
) -> Result<(), Error> {
    let bytes = read_public(payload_path)?;
    let (t, payload) = if a == Action::Enroll {
        let p: EnrollmentPayload = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
        if p.device_id != hex(&config.device_id) {
            return Err(Error::Security);
        }
        let t = Target::Pool {
            pool: PoolId::from_bytes(config::decode_hex(&p.pool_id).ok_or(Error::Invalid)?),
            incarnation: IncarnationId::from_bytes(
                config::decode_hex(&p.incarnation_id).ok_or(Error::Invalid)?,
            ),
        };
        (t, enrollment_cbor(&p)?)
    } else {
        let p: PayloadFile = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
        if p.version != 1 {
            return Err(Error::Invalid);
        }
        (
            json_target(&p.pool_id, &p.incarnation_id)?,
            unhex(&p.canonical_payload)?,
        )
    };
    management::validate_target(a, t)?;
    management::validate_payload(
        a,
        Value::parse(&payload)?,
        DeviceId::from_bytes(config.device_id),
        t,
    )?;
    let (revision, sequence) = current_context(config, a, t, &payload)?;
    let fields = SigningFields {
        device: DeviceId::from_bytes(config.device_id),
        target: t,
        sequence: ManagementSequence::new(sequence.checked_add(1).ok_or(Error::Conflict)?),
        request: RequestId::from_bytes(random()?),
        expected_revision: Revision::new(revision),
        action: a,
        canonical_payload: Value::parse(&payload)?,
    };
    publish(out, &envelope(fields, None)?)
}

#[cfg(all(
    feature = "management",
    not(any(
        feature = "primary",
        feature = "development",
        feature = "recovery",
        feature = "provisioning"
    ))
))]
pub fn sign(request_path: &Path, key_path: &Path, out: &Path) -> Result<(), Error> {
    use crate::backup::publication::{MemoryProtector, SystemMemory};
    use ed25519_dalek::{Signer, SigningKey};
    use zeroize::{Zeroize, Zeroizing};
    rustix::process::setrlimit(
        rustix::process::Resource::Core,
        rustix::process::Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(|_| Error::Security)?;
    let request = read_public(request_path)?;
    let fields = parse_request(&request)?;
    validate_ancestry(key_path, true)?;
    let mut file = checked_file(key_path, true)?;
    let mut bytes = Zeroizing::new(vec![0; 16385]);
    let _guard = SystemMemory
        .protect(&mut bytes)
        .map_err(|_| Error::Security)?;
    let mut n = 0;
    loop {
        let count = file.read(&mut bytes[n..]).map_err(|_| Error::Filesystem)?;
        if count == 0 {
            break;
        }
        n += count;
        if n == bytes.len() {
            return Err(Error::Invalid);
        }
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Key<'a> {
        version: u64,
        algorithm: &'a str,
        role: &'a str,
        public_key: &'a str,
        private_key: &'a str,
    }
    let key: Key<'_> = serde_json::from_slice(&bytes[..n]).map_err(|_| Error::Invalid)?;
    if key.version != 1 || key.algorithm != "Ed25519" || key.role != "management" {
        return Err(Error::Security);
    }
    let mut der = Zeroizing::new([0; 48]);
    let _der_guard = SystemMemory
        .protect(&mut der[..])
        .map_err(|_| Error::Security)?;
    // The exact PKCS#8 wrapper is 48 bytes and has no base64 padding.
    // Decode directly into protected storage; never allocate a plaintext DER Vec.
    if key.private_key.len() != 64 {
        return Err(Error::Invalid);
    }
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (input, output) in key
        .private_key
        .as_bytes()
        .as_chunks::<4>()
        .0
        .iter()
        .zip(der.as_chunks_mut::<3>().0.iter_mut())
    {
        let mut word = 0u32;
        for byte in input {
            let digit = alphabet
                .iter()
                .position(|v| v == byte)
                .ok_or(Error::Invalid)?;
            word = (word << 6) | digit as u32;
        }
        output.copy_from_slice(&word.to_be_bytes()[1..]);
    }
    const PREFIX: &[u8] = &[
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    if der.len() != 48 || &der[..16] != PREFIX {
        return Err(Error::Invalid);
    }
    let mut seed = Zeroizing::new([0; 32]);
    let _seed_guard = SystemMemory
        .protect(&mut seed[..])
        .map_err(|_| Error::Security)?;
    seed.copy_from_slice(&der[16..]);
    let signing = config::LockedSigningKey::new(SigningKey::from_bytes(&seed))
        .map_err(|_| Error::Security)?;
    if Some(signing.verifying_key().to_bytes()) != config::decode_spki(key.public_key) {
        return Err(Error::Security);
    }
    let mut message = [0; 4608];
    let length = management::encode_signing_message(fields, &mut message)?;
    let signature = signing.sign(&message[..length]).to_bytes();
    let signed = envelope(fields, Some(&signature))?;
    management::parse_and_verify(&signed, fields.device, &signing.verifying_key().to_bytes())
        .map_err(|_| Error::Integrity)?;
    seed.zeroize();
    publish(out, &signed)
}

#[derive(Debug)]
pub struct Outcome {
    pub request: [u8; 16],
    pub pool: Option<[u8; 28]>,
    pub sequence: u64,
    pub revision: u64,
}
pub fn apply(config: &config::DeviceConnection, authorization: &Path) -> Result<Outcome, Error> {
    let signed = read_public(authorization)?;
    let verified = management::parse_and_verify(
        &signed,
        DeviceId::from_bytes(config.device_id),
        &config.identity.management_public_key,
    )
    .map_err(|_| Error::Security)?;
    let fields = *verified.fields();
    let (pool, incarnation) = match fields.target {
        Target::Device => (None, None),
        Target::Pool { pool, incarnation } => {
            (Some(*pool.as_bytes()), Some(*incarnation.as_bytes()))
        }
    };
    let request = *fields.request.as_bytes();
    let identity = Identity {
        device: config.device_id,
        pool,
        incarnation,
        request,
        generation_number: None,
    };
    let record_path = record_path(authorization, request);
    let mut record = OperationRecord::begin(&record_path, "MANAGE", identity, &signed)
        .map_err(|_| Error::Filesystem)?;
    let outcome = |m: Map<'_>| -> Result<Outcome, Error> {
        let sequence = m
            .required("management_sequence")
            .and_then(|value| value.uint())
            .map_err(|_| Error::Integrity)?;
        let revision = m
            .required("revision")
            .and_then(|value| value.uint())
            .map_err(|_| Error::Integrity)?;
        if sequence != fields.sequence.get()
            || (fields.action != Action::Enroll && revision <= fields.expected_revision.get())
        {
            return Err(Error::Integrity);
        }
        Ok(Outcome {
            request,
            pool,
            sequence,
            revision,
        })
    };
    if record.was_resumed() {
        let payload = encode(|e| {
            e.map(1)?;
            e.text("request")?;
            e.bytes(&request)
        })?;
        let bytes = client::management_exchange(config, request, Operation::OpStatus, &payload)
            .map_err(client_error)?;
        let reply = response(&bytes)?;
        match reconcile(reply.status.ok_or(Error::Integrity)?)? {
            Reconciliation::Committed => {
                let result = outcome(reply.payload())?;
                record
                    .record_committed(None)
                    .map_err(|_| Error::Filesystem)?;
                return Ok(result);
            }
            Reconciliation::Retry => {
                if record.state() == State::Committed {
                    return Err(Error::Integrity);
                }
                record
                    .record_not_committed()
                    .map_err(|_| Error::Filesystem)?;
            }
            Reconciliation::Reclaimed => {
                if record.state() != State::Committed {
                    record
                        .record_result_reclaimed()
                        .map_err(|_| Error::Filesystem)?;
                }
                return Err(Error::Conflict);
            }
        }
    }
    let (revision, sequence) = current_context(
        config,
        fields.action,
        fields.target,
        fields.canonical_payload.encoded(),
    )?;
    if revision != fields.expected_revision.get()
        || sequence.checked_add(1) != Some(fields.sequence.get())
    {
        return Err(Error::Conflict);
    }
    let bytes = match client::management_exchange(config, request, Operation::Manage, &signed) {
        Ok(bytes) => bytes,
        Err(e) => {
            record.record_unknown().map_err(|_| Error::Filesystem)?;
            return Err(client_error(e));
        }
    };
    let reply = response(&bytes)?;
    let status = reply.status.ok_or(Error::Integrity)?;
    if let Err(error) = ok(status) {
        if matches!(
            status,
            Status::DeadlineExceeded
                | Status::DeviceUnavailable
                | Status::Unknown
                | Status::InProgress
                | Status::StateDamaged
        ) {
            record.record_unknown().map_err(|_| Error::Filesystem)?;
        } else {
            record
                .record_not_committed()
                .map_err(|_| Error::Filesystem)?;
        }
        return Err(error);
    }
    let result = outcome(reply.payload())?;
    record
        .record_committed(None)
        .map_err(|_| Error::Filesystem)?;
    Ok(result)
}
fn record_path(authorization: &Path, request: [u8; 16]) -> PathBuf {
    authorization.with_file_name(format!(
        ".kes-forge-management-{}.operation.json",
        hex(&request)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fields<'a>(payload: Value<'a>) -> SigningFields<'a> {
        SigningFields {
            device: DeviceId::from_bytes([1; 16]),
            target: Target::Device,
            sequence: ManagementSequence::new(1),
            request: RequestId::from_bytes([2; 16]),
            expected_revision: Revision::new(0),
            action: Action::DeviceRetire,
            canonical_payload: payload,
        }
    }
    #[test]
    fn device_target_is_rejected_for_pool_only_management_action() {
        let f = fields(Value::parse(&[0xa0]).unwrap());
        let wrong = SigningFields {
            action: Action::PoolDelete,
            ..f
        };
        assert!(parse_request(&envelope(wrong, None).unwrap()).is_err());
    }
    #[test]
    fn rejects_unpaired_targets_and_unknown_action() {
        assert!(json_target(&serde_json::json!("00"), &serde_json::Value::Null).is_err());
        assert_eq!(action("RETIRE"), Err(Error::Invalid));
    }
    #[test]
    fn output_custody_rejects_parent_traversal() {
        assert_eq!(
            validate_ancestry(Path::new("../handoff"), false),
            Err(Error::Security)
        );
    }
    fn status(revision: u64, sequence: u64, pool_sequence: u64, deleted: bool) -> Vec<u8> {
        encode(|e| {
            e.map(4)?;
            e.text("revision")?;
            e.uint(revision)?;
            e.text("directory")?;
            e.array(1)?;
            e.map(6)?;
            e.text("pool")?;
            e.bytes(&[3; 28])?;
            e.text("deleted")?;
            e.boolean(deleted)?;
            e.text("revision")?;
            e.uint(4)?;
            e.text("incarnation")?;
            e.bytes(&[4; 16])?;
            e.text("credential_epoch")?;
            e.uint(8)?;
            e.text("management_sequence")?;
            e.uint(pool_sequence)?;
            e.text("credential_epoch")?;
            e.uint(7)?;
            e.text("management_sequence")?;
            e.uint(sequence)
        })
        .unwrap()
    }
    #[test]
    fn pool_counters_do_not_use_device_sequence() {
        let bytes = status(50, 70, 9, false);
        let target = Target::Pool {
            pool: PoolId::from_bytes([3; 28]),
            incarnation: IncarnationId::from_bytes([4; 16]),
        };
        assert_eq!(
            status_context(
                Value::parse(&bytes).unwrap().map().unwrap(),
                Action::PoolDelete,
                target,
                &[0xa0]
            ),
            Ok((4, 9))
        );
    }
    #[test]
    fn enrollment_uses_directory_revision_and_tombstone_sequence() {
        let target = Target::Pool {
            pool: PoolId::from_bytes([3; 28]),
            incarnation: IncarnationId::from_bytes([5; 16]),
        };
        let bytes = status(50, 70, 9, true);
        assert_eq!(
            status_context(
                Value::parse(&bytes).unwrap().map().unwrap(),
                Action::Enroll,
                target,
                &[0xa0]
            ),
            Ok((50, 9))
        );
        let live = status(50, 70, 9, false);
        assert_eq!(
            status_context(
                Value::parse(&live).unwrap().map().unwrap(),
                Action::Enroll,
                target,
                &[0xa0]
            ),
            Err(Error::Conflict)
        );
    }
    #[test]
    fn counter_overflow_is_not_wrapped() {
        for (revision, sequence) in [(u64::MAX, 0), (0, u64::MAX)] {
            let bytes = status(revision, sequence, 0, false);
            assert_eq!(
                status_context(
                    Value::parse(&bytes).unwrap().map().unwrap(),
                    Action::DeviceRetire,
                    Target::Device,
                    &[0xa0]
                ),
                Err(Error::Conflict)
            );
        }
    }
    #[test]
    fn signed_authorization_is_bound_to_target_and_payload() {
        use ed25519_dalek::{Signer, SigningKey};
        let key = SigningKey::from_bytes(&[7; 32]);
        let f = fields(Value::parse(&[0xa0]).unwrap());
        let mut message = [0; 4608];
        let n = management::encode_signing_message(f, &mut message).unwrap();
        let signature = key.sign(&message[..n]).to_bytes();
        let signed = envelope(f, Some(&signature)).unwrap();
        assert!(
            management::parse_and_verify(&signed, f.device, &key.verifying_key().to_bytes())
                .is_ok()
        );
        let changed = SigningFields {
            request: RequestId::from_bytes([8; 16]),
            ..f
        };
        let tampered = envelope(changed, Some(&signature)).unwrap();
        assert!(
            management::parse_and_verify(&tampered, f.device, &key.verifying_key().to_bytes())
                .is_err()
        );
        assert!(
            management::parse_and_verify(
                &signed,
                DeviceId::from_bytes([8; 16]),
                &key.verifying_key().to_bytes()
            )
            .is_err()
        );
    }
}

fn current_context(
    config: &config::DeviceConnection,
    a: Action,
    t: Target,
    payload: &[u8],
) -> Result<(u64, u64), Error> {
    let status = client::management_exchange(config, random()?, Operation::Status, &[0xa0])
        .map_err(client_error)?;
    let status = response(&status)?;
    ok(status.status.ok_or(Error::Integrity)?)?;
    let root = status.payload();
    status_context(root, a, t, payload).map_err(|error| match error {
        Error::Invalid => Error::Integrity,
        other => other,
    })
}
fn status_context(
    root: Map<'_>,
    a: Action,
    t: Target,
    payload: &[u8],
) -> Result<(u64, u64), Error> {
    let mut revision = root.required("revision")?.uint()?;
    let mut sequence = root.required("management_sequence")?.uint()?;
    if let Target::Pool { pool, incarnation } = t {
        let mut found = false;
        for entry in root.required("directory")?.array()? {
            let entry = entry.map()?;
            let old = fixed::<16>(entry.required("incarnation")?)?;
            if a == Action::Enroll && old == *incarnation.as_bytes() {
                return Err(Error::Conflict);
            }
            if fixed::<28>(entry.required("pool")?)? == *pool.as_bytes() {
                if found {
                    return Err(Error::Integrity);
                }
                found = true;
                let deleted = entry.required("deleted")?.boolean()?;
                if (a == Action::Enroll && !deleted)
                    || (a != Action::Enroll && (deleted || old != *incarnation.as_bytes()))
                {
                    return Err(Error::Conflict);
                }
                if a == Action::StagedDiscard {
                    let staged = entry.required("staged")?;
                    let requested = Value::parse(payload)?.map()?.required("generation")?;
                    if staged.is_null() || fixed::<16>(staged)? != fixed::<16>(requested)? {
                        return Err(Error::Conflict);
                    }
                }
                if a != Action::Enroll {
                    revision = entry.required("revision")?.uint()?;
                }
                sequence = entry.required("management_sequence")?.uint()?;
            }
        }
        if !found {
            if a != Action::Enroll {
                return Err(Error::Conflict);
            }
            sequence = 0;
        }
    }
    if matches!(a, Action::CredentialReplace | Action::CredentialRevoke) {
        let requested = Value::parse(payload)?
            .map()?
            .required("credential_epoch")?
            .uint()?;
        let mut epoch = root.required("credential_epoch")?.uint()?;
        if let Target::Pool { pool, .. } = t {
            for entry in root.required("directory")?.array()? {
                let m = entry.map()?;
                if fixed::<28>(m.required("pool")?)? == *pool.as_bytes() {
                    epoch = m.required("credential_epoch")?.uint()?;
                }
            }
        }
        if epoch.checked_add(1) != Some(requested) {
            return Err(Error::Conflict);
        }
    }
    revision.checked_add(1).ok_or(Error::Conflict)?;
    sequence.checked_add(1).ok_or(Error::Conflict)?;
    Ok((revision, sequence))
}

#[derive(Debug, Eq, PartialEq)]
enum Reconciliation {
    Committed,
    Retry,
    Reclaimed,
}
fn reconcile(status: Status) -> Result<Reconciliation, Error> {
    match status {
        Status::Ok => Ok(Reconciliation::Committed),
        Status::NotCommitted => Ok(Reconciliation::Retry),
        Status::ResultReclaimed => Ok(Reconciliation::Reclaimed),
        status => {
            ok(status)?;
            Err(Error::Unavailable)
        }
    }
}

#[cfg(test)]
mod replay_tests {
    use super::*;
    #[test]
    fn uncertain_results_never_authorize_mutation_replay() {
        for status in [
            Status::Unknown,
            Status::InProgress,
            Status::DeviceUnavailable,
            Status::DeadlineExceeded,
        ] {
            assert_eq!(reconcile(status), Err(Error::Unavailable));
        }
        assert_eq!(reconcile(Status::NotCommitted), Ok(Reconciliation::Retry));
        assert_eq!(
            reconcile(Status::ResultReclaimed),
            Ok(Reconciliation::Reclaimed)
        );
        assert_eq!(reconcile(Status::AuthFailed), Err(Error::Security));
    }
}

#[cfg(test)]
mod socket_regressions {
    use super::*;
    use crate::backup::publication::{MemoryProtector, SystemMemory};
    use ed25519_dalek::{Signer, SigningKey};
    use std::{
        io::Write,
        os::unix::{fs::PermissionsExt, net::UnixListener},
        thread,
        time::{Duration, Instant},
    };
    use zeroize::Zeroizing;

    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn post_commit_deadline_remains_unknown_until_authoritative_reconciliation() {
        let request = random().unwrap();
        let root = std::env::temp_dir().join(format!("kes-management-{}", hex(&request)));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let _cleanup = Cleanup(root.clone());
        let socket = root.join("daemon.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();

        let mut seed = Zeroizing::new([0; 32]);
        let _memory = SystemMemory.protect(&mut seed[..]).unwrap();
        File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut seed[..])
            .unwrap();
        let key = config::LockedSigningKey::new(SigningKey::from_bytes(&seed)).unwrap();
        let public_key = key.verifying_key().to_bytes();
        let fields = SigningFields {
            device: DeviceId::from_bytes([1; 16]),
            target: Target::Device,
            sequence: ManagementSequence::new(1),
            request: RequestId::from_bytes(request),
            expected_revision: Revision::new(0),
            action: Action::DeviceRetire,
            canonical_payload: Value::parse(&[0xa0]).unwrap(),
        };
        let mut transcript = [0; 4608];
        let length = management::encode_signing_message(fields, &mut transcript).unwrap();
        let signed = envelope(fields, Some(&key.sign(&transcript[..length]).to_bytes())).unwrap();
        let authorization = root.join("authorization.cbor");
        publish(&authorization, &signed).unwrap();
        let connection = config::DeviceConnection {
            socket_path: socket,
            device_id: [1; 16],
            device_identity_file: root.join("identity.json"),
            connection_name: "management".into(),
            credential_file: root.join("inaccessible-daemon-only.key"),
            credential_epoch: 0,
            identity: config::DeviceIdentity {
                device_id: [1; 16],
                identity_public_key: public_key,
                hpke_public_key: [0; 32],
                management_public_key: public_key,
                management_transport_public_key: public_key,
                credential_epoch: 0,
                boot_key_fingerprint: [0; 32],
                hardware_policy_digest: [0; 32],
                firmware_digest: [0; 32],
                security_version: 0,
                provisioning_record_file: root.join("record.json"),
                provisioning_manifest_file: root.join("manifest.json"),
                reviewer_public_key_file: root.join("reviewer.json"),
            },
            security_policy: "isolated-development".into(),
        };

        let server = thread::spawn(move || {
            for operation in [Operation::Status, Operation::Manage, Operation::OpStatus] {
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline);
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => panic!("socket consumer failed: {error}"),
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut prefix = [0; 4];
                stream.read_exact(&mut prefix).unwrap();
                let length = u32::from_be_bytes(prefix) as usize;
                assert!(length <= kes_protocol::MAX_FRAME_BYTES);
                let mut bytes = vec![0; length];
                stream.read_exact(&mut bytes).unwrap();
                let incoming = Envelope::parse(&bytes, EnvelopeKind::LocalRequest).unwrap();
                assert_eq!(incoming.operation, operation);
                if operation == Operation::Manage {
                    management::parse_and_verify(
                        incoming.payload().encoded(),
                        fields.device,
                        &public_key,
                    )
                    .unwrap();
                }
                let status = if operation == Operation::Manage {
                    Status::DeadlineExceeded
                } else {
                    Status::Ok
                };
                let payload = encode(|e| {
                    if operation == Operation::Status {
                        e.map(10)?;
                        e.text("active")?;
                        e.null()?;
                        e.text("health")?;
                        e.text("healthy")?;
                        e.text("staged")?;
                        e.null()?;
                        e.text("revoked")?;
                        e.boolean(false)?;
                        e.text("revision")?;
                        e.uint(0)?;
                        e.text("directory")?;
                        e.array(0)?;
                        e.text("security_mode")?;
                        e.text("development")?;
                        e.text("blocking_reason")?;
                        e.text("")?;
                        e.text("credential_epoch")?;
                        e.uint(0)?;
                        e.text("management_sequence")?;
                        e.uint(0)?;
                    } else if operation == Operation::Manage {
                        e.map(2)?;
                        e.text("scope")?;
                        e.text("device")?;
                        e.text("diagnostic")?;
                        e.text("deadline after commit")?;
                    } else {
                        e.map(2)?;
                        e.text("revision")?;
                        e.uint(1)?;
                        e.text("management_sequence")?;
                        e.uint(1)?;
                    }
                    Ok(())
                })
                .unwrap();
                let response = encode(|e| {
                    e.map(6)?;
                    e.text("op")?;
                    e.text(operation.as_str())?;
                    e.text("status")?;
                    e.text(status.as_str())?;
                    e.text("payload")?;
                    e.value(Value::parse(&payload)?)?;
                    e.text("request")?;
                    e.bytes(incoming.request().unwrap().as_bytes())?;
                    e.text("version")?;
                    e.uint(1)?;
                    e.text("connection")?;
                    e.text("management")
                })
                .unwrap();
                stream
                    .write_all(&(response.len() as u32).to_be_bytes())
                    .unwrap();
                stream.write_all(&response).unwrap();
            }
        });
        assert_eq!(
            apply(&connection, &authorization).err(),
            Some(Error::Unavailable)
        );
        let record = record_path(&authorization, request);
        assert_eq!(
            OperationRecord::load(&record).unwrap().state(),
            State::Unknown
        );
        let reconciled = apply(&connection, &authorization).unwrap();
        assert_eq!((reconciled.sequence, reconciled.revision), (1, 1));
        assert_eq!(
            OperationRecord::load(&record).unwrap().state(),
            State::Committed
        );
        server.join().unwrap();
    }
}
