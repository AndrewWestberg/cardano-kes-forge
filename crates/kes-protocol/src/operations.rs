//! Closed v1 wire schemas. Parsing proves syntax only, never authority or trust.
use crate::backup::BackupArtifact;
use crate::error::{Error, Status};
use kes_core::cbor::{Map, Value};
use kes_core::types::{DeviceId, GenerationId, IncarnationId, PoolId, RequestId};

macro_rules! operations {($($v:ident=>$s:literal),+$(,)?)=>{
#[derive(Clone,Copy,Debug,Eq,PartialEq)] pub enum Operation {$($v),+}
impl Operation {pub const fn as_str(self)->&'static str {match self {$(Self::$v=>$s),+}} pub fn parse(s:&str)->Result<Self,Error>{match s {$($s=>Ok(Self::$v)),+,_=>Err(Error::UnsupportedOperation)}}}
};}
operations! {Info=>"INFO",Open=>"OPEN",Status=>"STATUS",Generate=>"GENERATE",OpStatus=>"OP_STATUS",GetBackup=>"GET_BACKUP",Certify=>"CERTIFY",Activate=>"ACTIVATE",Schedule=>"SCHEDULE",Evolve=>"EVOLVE",Sign=>"SIGN",ObservePeriod=>"OBSERVE_PERIOD",Manage=>"MANAGE",UpdateBegin=>"UPDATE_BEGIN",UpdateChunk=>"UPDATE_CHUNK",UpdateFinalize=>"UPDATE_FINALIZE",DevInspect=>"DEV_INSPECT"}
#[derive(Clone, Copy)]
enum Kind {
    U,
    U32,
    Positive,
    Relative,
    Lifetime,
    B(usize),
    Bytes(usize),
    Text(usize),
    Utc,
    Bool,
    NullB(usize),
    NullableU,
    Network,
    NullableDescriptor,
    Descriptors,
    Counters,
    Limits,
    Action,
    Enrollment,
    Manifest,
    Health,
    Lifecycle,
    Security,
    Payload,
    Connection,
    Target,
    ScopeText,
    Certificate,
    Backup,
}
#[derive(Clone, Copy)]
struct Field {
    name: &'static str,
    kind: Kind,
    optional: bool,
}
const fn f(name: &'static str, kind: Kind) -> Field {
    Field {
        name,
        kind,
        optional: false,
    }
}
const fn o(name: &'static str, kind: Kind) -> Field {
    Field {
        name,
        kind,
        optional: true,
    }
}
use Kind::*;
const NETWORK: &[Field] = &[
    f("network_magic", U32),
    f("shelley_genesis_digest", B(32)),
    f("slots_per_kes_period", Positive),
    f("max_kes_evolutions", Lifetime),
];
const DESCRIPTOR: &[Field] = &[
    f("generation", B(16)),
    f("generation_number", U),
    f("creation_request", B(16)),
    f("verification_key", B(32)),
    f("artifact_digest", B(32)),
    f("revision", U),
    f("certificate_digest", NullB(32)),
    f("relative_period", Relative),
    f("lifecycle", Lifecycle),
    f("health", Health),
    f("backup_available", Bool),
    f("certificate_start", NullableU),
    f("certificate_counter", NullableU),
];
const CONTEXT: &[Field] = &[
    f("revision", U),
    f("generation", B(16)),
    f("certificate_digest", B(32)),
    f("relative_period", Relative),
    f("lifecycle", Lifecycle),
    f("health", Health),
];
const LIMITS: &[Field] = &[
    f("frame_bytes", U32),
    f("message_bytes", U32),
    f("certificate_bytes", U32),
    f("backup_bytes", U32),
    f("pools", U32),
    f("sessions", U32),
];
const ENROLLMENT: &[Field] = &[
    f("version", U),
    f("device", B(16)),
    f("pool", B(28)),
    f("incarnation", B(16)),
    f("cold_verification_key", B(32)),
    f("network", Network),
    f("machine_public_key", B(32)),
    f("credential_epoch", U),
    f("recipient_public_key", B(32)),
    f("recipient_id", B(32)),
];
const MANIFEST: &[Field] = &[
    f("version", U),
    f("firmware_digest", B(32)),
    f("partition_manifest_digest", B(32)),
    f("storage_schema", U),
    f("image_length", Positive),
    f("security_version", U),
    f("hardware_policy_digest", B(32)),
    f("signature", B(64)),
];
fn schema(map: Map<'_>, fields: &[Field]) -> Result<(), Error> {
    for entry in map {
        let (key, value) = entry?;
        let field = fields
            .iter()
            .find(|f| f.name == key)
            .ok_or(Error::UnknownField)?;
        validate(value, field.kind)?;
    }
    for field in fields {
        if !field.optional && map.get(field.name)?.is_none() {
            return Err(Error::MissingField);
        }
    }
    Ok(())
}
fn bounded_text<'a>(v: Value<'a>, max: usize) -> Result<&'a str, Error> {
    let s = v.text()?;
    if s.len() > max || s.as_bytes().contains(&0) {
        return Err(Error::InvalidLength);
    }
    Ok(s)
}
fn one_of(v: Value<'_>, choices: &[&str]) -> Result<(), Error> {
    if choices.contains(&v.text()?) {
        Ok(())
    } else {
        Err(Error::InvalidValue)
    }
}
fn validate(v: Value<'_>, kind: Kind) -> Result<(), Error> {
    match kind {
        U => {
            v.uint()?;
        }
        U32 => {
            u32::try_from(v.uint()?).map_err(|_| Error::InvalidValue)?;
        }
        Positive => {
            if v.uint()? == 0 {
                return Err(Error::InvalidValue);
            }
        }
        Relative => {
            if v.uint()? > 63 {
                return Err(Error::InvalidValue);
            }
        }
        Lifetime => {
            if !(1..=64).contains(&v.uint()?) {
                return Err(Error::InvalidValue);
            }
        }
        B(n) => {
            if v.bytes()?.len() != n {
                return Err(Error::InvalidLength);
            }
        }
        Bytes(n) => {
            if v.bytes()?.len() > n {
                return Err(Error::InvalidLength);
            }
        }
        Text(n) => {
            bounded_text(v, n)?;
        }
        Utc => {
            let s = bounded_text(v, 32)?;
            let b = s.as_bytes();
            if b.len() < 20
                || b[4] != b'-'
                || b[7] != b'-'
                || b[10] != b'T'
                || b[13] != b':'
                || b[16] != b':'
                || b.last() != Some(&b'Z')
                || !b[..19]
                    .iter()
                    .enumerate()
                    .all(|(i, c)| matches!(i, 4 | 7 | 10 | 13 | 16) || c.is_ascii_digit())
                || (b.len() > 20
                    && (b[19] != b'.' || !b[20..b.len() - 1].iter().all(u8::is_ascii_digit)))
            {
                return Err(Error::InvalidValue);
            }
        }
        Bool => {
            v.boolean()?;
        }
        NullB(n) => {
            if !v.is_null() {
                validate(v, B(n))?;
            }
        }
        NullableU => {
            if !v.is_null() {
                v.uint()?;
            }
        }
        Target => {
            let mut items = v.array()?;
            let device = items.next().ok_or(Error::InvalidLength)?;
            let pool = items.next().ok_or(Error::InvalidLength)?;
            let incarnation = items.next().ok_or(Error::InvalidLength)?;
            if items.next().is_some() {
                return Err(Error::InvalidLength);
            }
            validate(device, B(16))?;
            validate(pool, NullB(28))?;
            validate(incarnation, NullB(16))?;
            if pool.is_null() != incarnation.is_null() {
                return Err(Error::InvalidValue);
            }
        }
        Network => schema(v.map()?, NETWORK)?,
        NullableDescriptor => {
            if !v.is_null() {
                schema(v.map()?, DESCRIPTOR)?;
            }
        }
        Descriptors => {
            let mut count = 0;
            for d in v.array()? {
                schema(
                    d.map()?,
                    &[
                        f("pool", B(28)),
                        f("incarnation", B(16)),
                        f("revision", U),
                        f("credential_epoch", U),
                        f("management_sequence", U),
                        f("deleted", Bool),
                        f("revoked", Bool),
                        f("health", Health),
                        f("active", NullB(16)),
                        f("staged", NullB(16)),
                    ],
                )?;
                count += 1;
                if count > 32 {
                    return Err(Error::InvalidLength);
                }
            }
        }
        Counters => {
            let mut count = 0;
            for counter in v.array()? {
                let m = counter.map()?;
                schema(
                    m,
                    &[
                        f("pool", NullB(28)),
                        f("incarnation", NullB(16)),
                        f("open_counter", U),
                    ],
                )?;
                scope(m)?;
                count += 1;
                if count > 33 {
                    return Err(Error::InvalidLength);
                }
            }
        }
        Limits => {
            let m = v.map()?;
            schema(m, LIMITS)?;
            for (k, n) in [
                ("frame_bytes", 8192),
                ("message_bytes", 4096),
                ("certificate_bytes", 1024),
                ("backup_bytes", 2048),
                ("pools", 32),
                ("sessions", 33),
            ] {
                if m.required(k)?.uint()? != n {
                    return Err(Error::InvalidValue);
                }
            }
        }
        Action => {
            one_of(
                v,
                &[
                    "ENROLL",
                    "CREDENTIAL_REPLACE",
                    "CREDENTIAL_REVOKE",
                    "RECIPIENT_REPLACE",
                    "STAGED_DISCARD",
                    "POOL_DELETE",
                    "DEVICE_RETIRE",
                    "FIRMWARE_AUTHORIZE",
                ],
            )?;
        }
        Enrollment => {
            schema(v.map()?, ENROLLMENT)?;
            version(v.map()?)?;
        }
        Manifest => {
            let m = v.map()?;
            schema(m, MANIFEST)?;
            version(m)?;
            if m.required("storage_schema")?.uint()? != 1 {
                return Err(Error::UnsupportedVersion);
            }
        }
        Health => one_of(v, &["healthy", "damaged", "unavailable"])?,
        Lifecycle => one_of(
            v,
            &["staged", "certified-staged", "active", "expired", "retired"],
        )?,
        Security => one_of(
            v,
            &["development", "release-unprovisioned", "release-ready"],
        )?,
        Payload => {
            v.map()?;
        }
        Connection => {
            let s = v.text()?;
            if s.is_empty()
                || s.len() > 64
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            {
                return Err(Error::InvalidValue);
            }
        }
        ScopeText => one_of(v, &["device", "pool"])?,
        Certificate => {
            validate(v, Bytes(1024))?;
            validate_certificate(v.bytes()?)?;
        }
        Backup => {
            BackupArtifact::parse(v.bytes()?)?;
        }
    }
    Ok(())
}
fn version(m: Map<'_>) -> Result<(), Error> {
    if m.required("version")?.uint()? != 1 {
        return Err(Error::UnsupportedVersion);
    }
    Ok(())
}
fn scope(m: Map<'_>) -> Result<bool, Error> {
    let pool = m.required("pool")?;
    let incarnation = m.required("incarnation")?;
    if pool.is_null() != incarnation.is_null() {
        return Err(Error::InvalidValue);
    }
    Ok(!pool.is_null())
}
fn pool_operation(op: Operation) -> bool {
    !matches!(
        op,
        Operation::Info
            | Operation::Open
            | Operation::Status
            | Operation::OpStatus
            | Operation::Manage
            | Operation::UpdateBegin
            | Operation::UpdateChunk
            | Operation::UpdateFinalize
    )
}
fn device_operation(op: Operation) -> bool {
    matches!(
        op,
        Operation::UpdateBegin | Operation::UpdateChunk | Operation::UpdateFinalize
    )
}

/// A borrowed schema-checked frame. No authentication has been performed.
#[derive(Clone, Copy)]
pub struct Envelope<'a> {
    pub operation: Operation,
    pub kind: EnvelopeKind,
    pub status: Option<Status>,
    map: Map<'a>,
    payload: Map<'a>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvelopeKind {
    DeviceRequest,
    DeviceResponse,
    LocalRequest,
    LocalResponse,
    InfoRequest,
    InfoResponse,
    OpenRequest,
    OpenResponse,
}
impl<'a> Envelope<'a> {
    pub fn parse(encoded: &'a [u8], kind: EnvelopeKind) -> Result<Self, Error> {
        let map = Value::parse(encoded)?.map()?;
        version(map)?;
        let operation = Operation::parse(map.required("op")?.text()?)?;
        Self::parse_map(map, kind, operation)
    }

    /// Parses one request arriving at the device and selects the only valid
    /// envelope class from its operation without reparsing the frame.
    pub fn parse_device_ingress(encoded: &'a [u8]) -> Result<Self, Error> {
        let map = Value::parse(encoded)?.map()?;
        version(map)?;
        let operation = Operation::parse(map.required("op")?.text()?)?;
        let kind = match operation {
            Operation::Info => EnvelopeKind::InfoRequest,
            Operation::Open => EnvelopeKind::OpenRequest,
            _ => EnvelopeKind::DeviceRequest,
        };
        Self::parse_map(map, kind, operation)
    }

    fn parse_map(map: Map<'a>, kind: EnvelopeKind, operation: Operation) -> Result<Self, Error> {
        let response = matches!(
            kind,
            EnvelopeKind::DeviceResponse
                | EnvelopeKind::LocalResponse
                | EnvelopeKind::InfoResponse
                | EnvelopeKind::OpenResponse
        );
        let fields: &[Field] = match kind {
            EnvelopeKind::DeviceRequest => &[
                f("version", U),
                f("op", Text(32)),
                f("device", B(16)),
                f("pool", NullB(28)),
                f("incarnation", NullB(16)),
                f("session", B(16)),
                f("seq", U),
                f("request", B(16)),
                f("budget_ms", U32),
                f("payload", Payload),
                f("mac", B(32)),
            ],
            EnvelopeKind::DeviceResponse => &[
                f("version", U),
                f("op", Text(32)),
                f("device", B(16)),
                f("pool", NullB(28)),
                f("incarnation", NullB(16)),
                f("session", B(16)),
                f("seq", U),
                f("request_seq", U),
                f("request", B(16)),
                f("status", Text(32)),
                f("payload", Payload),
                f("mac", B(32)),
            ],
            EnvelopeKind::LocalRequest => &[
                f("version", U),
                f("connection", Connection),
                f("request", B(16)),
                f("budget_ms", U32),
                f("op", Text(32)),
                f("payload", Payload),
                o("target", Target),
            ],
            EnvelopeKind::LocalResponse => &[
                f("version", U),
                f("connection", Connection),
                f("request", B(16)),
                f("op", Text(32)),
                f("status", Text(32)),
                f("payload", Payload),
            ],
            EnvelopeKind::InfoRequest => &[
                f("version", U),
                f("op", Text(32)),
                f("request", B(16)),
                f("payload", Payload),
            ],
            EnvelopeKind::InfoResponse => &[
                f("version", U),
                f("op", Text(32)),
                f("request", B(16)),
                f("device", B(16)),
                f("status", Text(32)),
                f("payload", Payload),
                f("signature", B(64)),
            ],
            EnvelopeKind::OpenRequest => &[
                f("version", U),
                f("op", Text(32)),
                f("device", B(16)),
                f("pool", NullB(28)),
                f("incarnation", NullB(16)),
                f("request", B(16)),
                f("payload", Payload),
            ],
            EnvelopeKind::OpenResponse => &[
                f("version", U),
                f("op", Text(32)),
                f("device", B(16)),
                f("pool", NullB(28)),
                f("incarnation", NullB(16)),
                f("request", B(16)),
                f("status", Text(32)),
                f("payload", Payload),
                f("mac", B(32)),
            ],
        };
        if matches!(
            kind,
            EnvelopeKind::DeviceRequest | EnvelopeKind::DeviceResponse | EnvelopeKind::OpenResponse
        ) {
            let mac = map.get("mac")?.ok_or(Error::AuthenticationField)?;
            if mac.bytes().map_err(|_| Error::AuthenticationField)?.len() != 32 {
                return Err(Error::AuthenticationField);
            }
        }
        envelope_schema(map, fields)?;
        if matches!(kind, EnvelopeKind::InfoRequest | EnvelopeKind::InfoResponse) {
            if operation != Operation::Info {
                return Err(Error::UnsupportedOperation);
            }
        } else if matches!(kind, EnvelopeKind::OpenRequest | EnvelopeKind::OpenResponse) {
            if operation != Operation::Open {
                return Err(Error::UnsupportedOperation);
            }
        } else if matches!(operation, Operation::Info | Operation::Open) {
            return Err(Error::UnsupportedOperation);
        }
        if map.get("pool")?.is_some() {
            let pool = scope(map)?;
            if (pool_operation(operation) && !pool) || (device_operation(operation) && pool) {
                return Err(Error::InvalidValue);
            }
        }
        if matches!(
            kind,
            EnvelopeKind::LocalRequest | EnvelopeKind::LocalResponse
        ) && operation == Operation::DevInspect
        {
            return Err(Error::UnsupportedOperation);
        }
        let payload = map.required("payload")?.map()?;
        let status = if response {
            Some(Status::parse(map.required("status")?.text()?)?)
        } else {
            None
        };
        if let Some(status) = status {
            if kind == EnvelopeKind::LocalResponse
                && operation == Operation::Status
                && status == Status::Ok
            {
                local_status_payload(payload)?;
            } else {
                response_payload(operation, status, payload)?;
            }
        } else {
            if kind == EnvelopeKind::LocalRequest && operation == Operation::Status {
                schema(
                    payload,
                    &[o("generation", B(16)), o("host_diagnostics", Bool)],
                )?;
                if let Some(value) = payload.get("host_diagnostics")?
                    && !value.boolean()?
                {
                    return Err(Error::InvalidValue);
                }
            } else {
                request_payload(operation, payload)?;
            }
        }
        if operation == Operation::Manage && !response {
            if let Some(device) = map.get("device")?
                && device.encoded() != payload.required("device")?.encoded()
            {
                return Err(Error::InvalidValue);
            }
            if map.get("pool")?.is_some() && scope(map)? {
                for key in ["pool", "incarnation"] {
                    if map.required(key)?.encoded() != payload.required(key)?.encoded() {
                        return Err(Error::InvalidValue);
                    }
                }
            }
        }
        Ok(Self {
            operation,
            kind,
            status,
            map,
            payload,
        })
    }
    pub fn map(self) -> Map<'a> {
        self.map
    }
    pub fn payload(self) -> Map<'a> {
        self.payload
    }
    pub fn encoded(self) -> &'a [u8] {
        self.map.encoded()
    }
    pub fn device(self) -> Result<DeviceId, Error> {
        DeviceId::try_from(self.map.required("device")?.bytes()?).map_err(|_| Error::InvalidLength)
    }
    pub fn pool(self) -> Result<Option<PoolId>, Error> {
        let v = self.map.required("pool")?;
        if v.is_null() {
            Ok(None)
        } else {
            PoolId::try_from(v.bytes()?)
                .map(Some)
                .map_err(|_| Error::InvalidLength)
        }
    }
    pub fn incarnation(self) -> Result<Option<IncarnationId>, Error> {
        let v = self.map.required("incarnation")?;
        if v.is_null() {
            Ok(None)
        } else {
            IncarnationId::try_from(v.bytes()?)
                .map(Some)
                .map_err(|_| Error::InvalidLength)
        }
    }
    pub fn request(self) -> Result<RequestId, Error> {
        RequestId::try_from(self.map.required("request")?.bytes()?)
            .map_err(|_| Error::InvalidLength)
    }
    pub fn generation(self) -> Result<GenerationId, Error> {
        GenerationId::try_from(self.payload.required("generation")?.bytes()?)
            .map_err(|_| Error::InvalidLength)
    }
    pub fn message(self) -> Result<&'a [u8], Error> {
        if self.operation != Operation::Sign {
            return Err(Error::InvalidValue);
        }
        self.payload
            .required("message")?
            .bytes()
            .map_err(Error::from)
    }
    pub fn network(self) -> Result<kes_core::types::NetworkBinding, Error> {
        use kes_core::types::{EnrolledGenesisHash, NetworkBinding};
        let m = self.payload.required("network")?.map()?;
        let digest = EnrolledGenesisHash::try_from(m.required("shelley_genesis_digest")?.bytes()?)
            .map_err(|_| Error::InvalidLength)?;
        NetworkBinding::from_enrolled_digest(
            u32::try_from(m.required("network_magic")?.uint()?).map_err(|_| Error::InvalidValue)?,
            digest,
            m.required("slots_per_kes_period")?.uint()?,
            m.required("max_kes_evolutions")?.uint()?,
        )
        .map_err(|_| Error::InvalidValue)
    }
}
fn envelope_schema(m: Map<'_>, fields: &[Field]) -> Result<(), Error> {
    schema(m, fields)
}
fn request_payload(op: Operation, m: Map<'_>) -> Result<(), Error> {
    use Operation::*;
    let fields: &[Field] = match op {
        Info => &[f("challenge", B(32))],
        Open => &[
            f("boot_nonce", B(32)),
            f("credential_epoch", U),
            f("open_counter", U),
            f("encapsulation", B(32)),
            f("ciphertext", B(48)),
            f("signature", B(64)),
        ],
        Status => &[o("generation", B(16))],
        Generate => &[f("next_generation_number", U), f("expected_revision", U)],
        OpStatus => &[f("request", B(16)), o("generation_number", U)],
        GetBackup => &[f("generation", B(16))],
        Certify => &[
            f("generation", B(16)),
            f("certificate", Certificate),
            f("network", Network),
            f("expected_revision", U),
        ],
        Activate => &[
            f("generation", B(16)),
            f("certificate_digest", B(32)),
            f("current_absolute_period", U),
            f("expected_active_generation", NullB(16)),
            f("expected_revision", U),
        ],
        Schedule => &[
            f("generation", B(16)),
            f("certificate_digest", B(32)),
            f("activation_absolute_period", U),
            f("expected_active_generation", NullB(16)),
            f("expected_revision", U),
        ],
        Evolve => &[
            f("generation", B(16)),
            f("certificate_digest", B(32)),
            f("target_absolute_period", U),
            f("network", Network),
            f("expected_revision", U),
        ],
        Sign => &[
            f("generation", B(16)),
            f("certificate_digest", B(32)),
            f("absolute_period", U),
            f("network", Network),
            f("message", Bytes(4096)),
        ],
        ObservePeriod => &[
            f("absolute_period", U),
            f("network", Network),
            f("expected_revision", U),
        ],
        Manage => return management(m),
        UpdateBegin => &[f("manifest_digest", B(32)), f("expected_revision", U)],
        UpdateChunk => &[
            f("manifest_digest", B(32)),
            f("offset", U),
            f("bytes", Bytes(4096)),
            f("expected_revision", U),
        ],
        UpdateFinalize => &[
            f("manifest_digest", B(32)),
            f("final_digest", B(32)),
            f("expected_revision", U),
        ],
        DevInspect => &[f("generation", B(16)), f("protected_output", Bool)],
    };
    schema(m, fields)?;
    if op == DevInspect && !m.required("protected_output")?.boolean()? {
        return Err(Error::InvalidValue);
    }
    if op == UpdateChunk
        && m.required("offset")?
            .uint()?
            .checked_add(m.required("bytes")?.bytes()?.len() as u64)
            .is_none()
    {
        return Err(Error::InvalidValue);
    }
    Ok(())
}
fn context(m: Map<'_>, extra: &[Field]) -> Result<(), Error> {
    for e in m {
        let (k, v) = e?;
        let field = CONTEXT
            .iter()
            .chain(extra.iter())
            .find(|f| f.name == k)
            .ok_or(Error::UnknownField)?;
        validate(v, field.kind)?;
    }
    for f in CONTEXT.iter().chain(extra.iter()) {
        if !f.optional {
            m.required(f.name)?;
        }
    }
    Ok(())
}

// Local diagnostics are positional arrays to stay within the four-level CBOR
// nesting bound. They are never accepted in authenticated device responses.
fn tuple(value: Value<'_>, kinds: &[Kind]) -> Result<(), Error> {
    let mut values = value.array()?;
    for kind in kinds {
        validate(values.next().ok_or(Error::InvalidLength)?, *kind)?;
    }
    if values.next().is_some() {
        return Err(Error::InvalidLength);
    }
    Ok(())
}

const HOST_CONTEXT: &[Kind] = &[
    B(16),
    B(32),
    B(16),
    B(28),
    B(16),
    U32,
    B(32),
    Positive,
    Lifetime,
    NullB(16),
    NullB(32),
    NullableU,
];

fn local_status_payload(m: Map<'_>) -> Result<(), Error> {
    // Validate the unchanged wire subset separately, closing both schemas.
    for entry in m {
        let (key, value) = entry?;
        match key {
            "host_device" => validate(value, B(16))?,
            "host_pool" => validate(value, NullB(28))?,
            "host_incarnation" => validate(value, NullB(16))?,
            "host_observation" if !value.is_null() => {
                let mut a = value.array()?;
                one_of(
                    a.next().ok_or(Error::InvalidLength)?,
                    &["fresh", "stale", "unavailable"],
                )?;
                for k in [NullableU, NullableU, Utc, Utc] {
                    let v = a.next().ok_or(Error::InvalidLength)?;
                    if !v.is_null() {
                        validate(v, k)?;
                    }
                }
                let context = a.next().ok_or(Error::InvalidLength)?;
                if !context.is_null() {
                    tuple(context, HOST_CONTEXT)?;
                }
                let historical = a.next().ok_or(Error::InvalidLength)?;
                validate(historical, NullableDescriptor)?;
                let ready = a.next().ok_or(Error::InvalidLength)?;
                if !ready.is_null() {
                    validate(ready, Bool)?;
                }
                validate(a.next().ok_or(Error::InvalidLength)?, NullableU)?;
                if a.next().is_some() {
                    return Err(Error::InvalidLength);
                }
            }
            "host_latency" if !value.is_null() => {
                let mut a = value.array()?;
                for _ in 0..8 {
                    let v = a.next().ok_or(Error::InvalidLength)?;
                    if !v.is_null() {
                        tuple(
                            v,
                            &[
                                B(16),
                                U,
                                Text(7),
                                Text(64),
                                Utc,
                                U,
                                B(16),
                                B(32),
                                B(16),
                                B(28),
                                B(16),
                                U32,
                                B(32),
                                Positive,
                                Lifetime,
                                NullB(16),
                                NullB(32),
                                NullableU,
                            ],
                        )?;
                        let mut fields = v.array()?;
                        let outcome = fields.nth(2).ok_or(Error::InvalidLength)?;
                        one_of(outcome, &["success", "error"])?;
                        Status::parse(fields.next().ok_or(Error::InvalidLength)?.text()?)?;
                    }
                }
                if a.next().is_some() {
                    return Err(Error::InvalidLength);
                }
            }
            "host_observation" | "host_latency" => {}
            _ => {
                let field = STATUS_FIELDS
                    .iter()
                    .find(|f| f.name == key)
                    .ok_or(Error::UnknownField)?;
                validate(value, field.kind)?;
            }
        }
    }
    for field in STATUS_FIELDS {
        if !field.optional {
            m.required(field.name)?;
        }
    }
    let count = [
        "host_device",
        "host_pool",
        "host_incarnation",
        "host_observation",
        "host_latency",
    ]
    .iter()
    .filter(|key| m.get(key).ok().flatten().is_some())
    .count();
    if count != 0 && count != 5 {
        return Err(Error::MissingField);
    }
    Ok(())
}

const STATUS_FIELDS: &[Field] = &[
    f("health", Health),
    f("security_mode", Security),
    f("revision", U),
    f("credential_epoch", U),
    f("revoked", Bool),
    f("active", NullableDescriptor),
    f("staged", NullableDescriptor),
    f("blocking_reason", Text(256)),
    f("directory", Descriptors),
    o("management_sequence", U),
];
fn response_payload(op: Operation, status: Status, m: Map<'_>) -> Result<(), Error> {
    if status == Status::InProgress {
        if !matches!(op, Operation::Generate | Operation::OpStatus) {
            return Err(Error::InvalidValue);
        }
        return schema(m, &[f("request", B(16)), f("generation_number", U)]);
    }
    if matches!(
        status,
        Status::NotCommitted | Status::ResultReclaimed | Status::Unknown
    ) {
        if op != Operation::OpStatus {
            return Err(Error::InvalidValue);
        }
        return schema(m, &[f("request", B(16)), o("generation_number", U)]);
    }
    if status == Status::Expired
        && matches!(
            op,
            Operation::Sign | Operation::Evolve | Operation::ObservePeriod
        )
    {
        return context(m, &[]);
    }
    if status != Status::Ok {
        return schema(m, &[f("scope", ScopeText), f("diagnostic", Text(256))]);
    }
    {
        use Operation::*;
        match op {
            Info => schema(
                m,
                &[
                    f("challenge", B(32)),
                    f("identity_public_key", B(32)),
                    f("hpke_public_key", B(32)),
                    f("boot_nonce", B(32)),
                    f("open_counters", Counters),
                    f("firmware_digest", B(32)),
                    f("security_version", U),
                    f("hardware_policy_digest", B(32)),
                    f("security_mode", Security),
                    f("capability_evidence", Bytes(2048)),
                    f("limits", Limits),
                ],
            ),
            Open => schema(
                m,
                &[f("session", B(16)), f("challenge_acknowledgement", B(32))],
            ),
            Status => schema(m, STATUS_FIELDS),
            Generate => schema(m, DESCRIPTOR),
            OpStatus if m.get("management_sequence")?.is_some() => {
                schema(m, &[f("management_sequence", U), f("revision", U)])
            }
            OpStatus => schema(m, DESCRIPTOR),
            GetBackup => schema(
                m,
                &[
                    f("generation", B(16)),
                    f("backup", Backup),
                    f("artifact_digest", B(32)),
                ],
            ),
            Certify | Activate | Schedule | ObservePeriod => schema(m, DESCRIPTOR),
            Evolve => context(m, &[]),
            Sign => context(m, &[f("signature", B(448)), f("message_digest", B(32))]),
            Manage => schema(m, &[f("management_sequence", U), f("revision", U)]),
            UpdateBegin | UpdateChunk | UpdateFinalize => schema(
                m,
                &[
                    f("manifest_digest", B(32)),
                    f("offset", U),
                    f("revision", U),
                ],
            ),
            DevInspect => context(m, &[f("state", B(608))]),
        }
    }
}
fn management(m: Map<'_>) -> Result<(), Error> {
    // canonical_payload is an encoded byte string, preserving exact signed bytes.
    schema(
        m,
        &[
            f("device", B(16)),
            f("pool", NullB(28)),
            f("incarnation", NullB(16)),
            f("management_sequence", U),
            f("request", B(16)),
            f("expected_revision", U),
            f("action", Action),
            f("canonical_payload", Bytes(4096)),
            f("signature", B(64)),
        ],
    )?;
    let pool = scope(m)?;
    let action = m.required("action")?.text()?;
    let payload = Value::parse(m.required("canonical_payload")?.bytes()?)?.map()?;
    if !pool
        && !matches!(
            action,
            "DEVICE_RETIRE" | "FIRMWARE_AUTHORIZE" | "CREDENTIAL_REPLACE" | "CREDENTIAL_REVOKE"
        )
    {
        return Err(Error::InvalidValue);
    }
    if pool && matches!(action, "DEVICE_RETIRE" | "FIRMWARE_AUTHORIZE") {
        return Err(Error::InvalidValue);
    }
    match action {
        "ENROLL" => {
            validate(Value::parse(payload.encoded())?, Enrollment)?;
            for key in ["device", "pool", "incarnation"] {
                if payload.required(key)?.encoded() != m.required(key)?.encoded() {
                    return Err(Error::InvalidValue);
                }
            }
            if payload.required("credential_epoch")?.uint()? != 0 {
                return Err(Error::InvalidValue);
            }
        }
        "CREDENTIAL_REPLACE" => schema(
            payload,
            &[f("machine_public_key", B(32)), f("credential_epoch", U)],
        )?,
        "CREDENTIAL_REVOKE" => schema(payload, &[f("credential_epoch", U)])?,
        "RECIPIENT_REPLACE" => schema(
            payload,
            &[f("recipient_public_key", B(32)), f("recipient_id", B(32))],
        )?,
        "STAGED_DISCARD" => schema(payload, &[f("generation", B(16))])?,
        "POOL_DELETE" | "DEVICE_RETIRE" => schema(payload, &[])?,
        "FIRMWARE_AUTHORIZE" => {
            validate(Value::parse(payload.encoded())?, Manifest)?;
        }
        _ => return Err(Error::UnsupportedOperation),
    }
    Ok(())
}

fn tuple_text(text: &str, sink: &mut impl FnMut(&[u8])) {
    let mut h = [0; 9];
    let n = kes_core::cbor::encode_head(3, text.len() as u64, &mut h);
    sink(&h[..n]);
    sink(text.as_bytes());
}
/// Exact RFC9180 info tuple; callback chunks borrow the original envelope.
pub fn visit_session_info(
    envelope: Envelope<'_>,
    mut sink: impl FnMut(&[u8]),
) -> Result<(), Error> {
    if envelope.kind != EnvelopeKind::OpenRequest {
        return Err(Error::InvalidValue);
    }
    sink(&[0x88]);
    tuple_text("cardano-kes-forge/session/v1", &mut sink);
    let m = envelope.map;
    let p = envelope.payload;
    for value in [
        m.required("device")?,
        p.required("boot_nonce")?,
        m.required("pool")?,
        m.required("incarnation")?,
        p.required("credential_epoch")?,
        p.required("open_counter")?,
        m.required("request")?,
    ] {
        sink(value.encoded());
    }
    Ok(())
}
/// OPEN signature signs the same eight-element tuple extended by encapsulation
/// and ciphertext (ten elements total), not a reconstructed plaintext challenge.
pub fn visit_open_signature(
    envelope: Envelope<'_>,
    mut sink: impl FnMut(&[u8]),
) -> Result<(), Error> {
    if envelope.kind != EnvelopeKind::OpenRequest {
        return Err(Error::InvalidValue);
    }
    sink(&[0x8a]);
    tuple_text("cardano-kes-forge/session/v1", &mut sink);
    let m = envelope.map;
    let p = envelope.payload;
    for value in [
        m.required("device")?,
        p.required("boot_nonce")?,
        m.required("pool")?,
        m.required("incarnation")?,
        p.required("credential_epoch")?,
        p.required("open_counter")?,
        m.required("request")?,
        p.required("encapsulation")?,
        p.required("ciphertext")?,
    ] {
        sink(value.encoded());
    }
    Ok(())
}
pub fn visit_management_tuple(
    envelope: Envelope<'_>,
    mut sink: impl FnMut(&[u8]),
) -> Result<(), Error> {
    if envelope.operation != Operation::Manage || envelope.status.is_some() {
        return Err(Error::InvalidValue);
    }
    let m = envelope.payload;
    sink(&[0x89]);
    tuple_text("cardano-kes-forge/manage/v1", &mut sink);
    for key in [
        "device",
        "pool",
        "incarnation",
        "management_sequence",
        "request",
        "expected_revision",
        "action",
    ] {
        sink(m.required(key)?.encoded());
    }
    sink(m.required("canonical_payload")?.bytes()?);
    Ok(())
}

/// Recognize only the pinned Cardano `(OCert, cold VK)` structural encoding.
/// This does not verify the cold signature, pool hash or certificate counter.
pub fn validate_certificate(bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() > 1024 {
        return Err(Error::Oversize);
    }
    let mut outer = Value::parse(bytes)?.array()?;
    let cert = outer.next().ok_or(Error::MissingField)?;
    validate(outer.next().ok_or(Error::MissingField)?, B(32))?;
    if outer.next().is_some() {
        return Err(Error::InvalidLength);
    }
    let mut fields = cert.array()?;
    for kind in [B(32), U, U, B(64)] {
        validate(fields.next().ok_or(Error::MissingField)?, kind)?;
    }
    if fields.next().is_some() {
        return Err(Error::InvalidLength);
    }
    Ok(())
}
