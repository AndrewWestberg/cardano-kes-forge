//! Offline-authorized management envelope validation. Parsing is allocation-free;
//! the enclosing journal owns durable replay and mutation boundaries.
use crate::cbor::{self, Encoder, Map, Value};
use crate::state::Enrollment;
use crate::types::{
    CredentialEpoch, DeviceId, EnrolledGenesisHash, IncarnationId, ManagementSequence,
    NetworkBinding, PoolId, RequestId, Revision,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

pub const MAX_MANAGEMENT_PAYLOAD_BYTES: usize = 4096;
const SIGNING_MESSAGE_BYTES: usize = 4608;
const DOMAIN: &str = "cardano-kes-forge/manage/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Enroll,
    RecipientReplace,
    StagedDiscard,
    PoolDelete,
    CredentialReplace,
    CredentialRevoke,
    DeviceRetire,
    FirmwareAuthorize,
}

impl Action {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Enroll => "ENROLL",
            Self::RecipientReplace => "RECIPIENT_REPLACE",
            Self::StagedDiscard => "STAGED_DISCARD",
            Self::PoolDelete => "POOL_DELETE",
            Self::CredentialReplace => "CREDENTIAL_REPLACE",
            Self::CredentialRevoke => "CREDENTIAL_REVOKE",
            Self::DeviceRetire => "DEVICE_RETIRE",
            Self::FirmwareAuthorize => "FIRMWARE_AUTHORIZE",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Target {
    Device,
    Pool {
        pool: PoolId,
        incarnation: IncarnationId,
    },
}

#[derive(Clone, Copy)]
pub struct SigningFields<'a> {
    pub device: DeviceId,
    pub target: Target,
    pub sequence: ManagementSequence,
    pub request: RequestId,
    pub expected_revision: Revision,
    pub action: Action,
    pub canonical_payload: Value<'a>,
}

pub struct VerifiedEnvelope<'a> {
    fields: SigningFields<'a>,
    transcript_digest: [u8; 32],
}

impl<'a> VerifiedEnvelope<'a> {
    pub const fn fields(&self) -> &SigningFields<'a> {
        &self.fields
    }

    pub const fn transcript_digest(&self) -> &[u8; 32] {
        &self.transcript_digest
    }

    pub fn enrollment(&self) -> Result<Enrollment, Error> {
        if self.fields.action != Action::Enroll {
            return Err(Error::WrongAction);
        }
        let payload = self.fields.canonical_payload.map()?;
        let cold_verification_key = fixed(payload.required("cold_verification_key")?)?;
        let pool = PoolId::from_cold_verification_key(&cold_verification_key);
        let Target::Pool {
            pool: target_pool,
            incarnation,
        } = self.fields.target
        else {
            return Err(Error::WrongTarget);
        };
        if pool != target_pool {
            return Err(Error::WrongTarget);
        }
        let network = parse_network(payload.required("network")?)?;
        let credential_epoch = CredentialEpoch::new(payload.required("credential_epoch")?.uint()?);
        if credential_epoch.get() != 0 {
            return Err(Error::InvalidPayload);
        }
        Ok(Enrollment {
            incarnation,
            cold_verification_key,
            network,
            machine_public_key: fixed(payload.required("machine_public_key")?)?,
            recipient_public_key: fixed(payload.required("recipient_public_key")?)?,
            recipient_id: fixed(payload.required("recipient_id")?)?,
            management_sequence: self.fields.sequence,
            management_request: self.fields.request,
            management_payload_digest: self.transcript_digest,
        })
    }

    pub fn recipient_replacement(&self) -> Result<([u8; 32], [u8; 32]), Error> {
        if self.fields.action != Action::RecipientReplace {
            return Err(Error::WrongAction);
        }
        let payload = self.fields.canonical_payload.map()?;
        let public_key = fixed(payload.required("recipient_public_key")?)?;
        let recipient_id = fixed(payload.required("recipient_id")?)?;
        if <[u8; 32]>::from(Sha256::digest(public_key)) != recipient_id {
            return Err(Error::InvalidPayload);
        }
        Ok((public_key, recipient_id))
    }

    pub fn credential_change(&self) -> Result<(CredentialEpoch, Option<[u8; 32]>), Error> {
        let payload = self.fields.canonical_payload.map()?;
        let epoch = CredentialEpoch::new(payload.required("credential_epoch")?.uint()?);
        match self.fields.action {
            Action::CredentialReplace => {
                Ok((epoch, Some(fixed(payload.required("machine_public_key")?)?)))
            }
            Action::CredentialRevoke => Ok((epoch, None)),
            _ => Err(Error::WrongAction),
        }
    }

    pub fn staged_generation(&self) -> Result<crate::types::GenerationId, Error> {
        if self.fields.action != Action::StagedDiscard {
            return Err(Error::WrongAction);
        }
        Ok(crate::types::GenerationId::from_bytes(fixed(
            self.fields
                .canonical_payload
                .map()?
                .required("generation")?,
        )?))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Cbor(cbor::Error),
    InvalidStructure,
    InvalidPayload,
    WrongDevice,
    WrongTarget,
    WrongAction,
    InvalidAuthority,
    Signature,
}

impl From<cbor::Error> for Error {
    fn from(error: cbor::Error) -> Self {
        Self::Cbor(error)
    }
}

pub fn parse_and_verify<'a>(
    encoded: &'a [u8],
    expected_device: DeviceId,
    management_root_public_key: &[u8; 32],
) -> Result<VerifiedEnvelope<'a>, Error> {
    let outer = Value::parse(encoded)?.map()?;
    exact_fields(
        outer,
        &[
            "device",
            "pool",
            "incarnation",
            "management_sequence",
            "request",
            "expected_revision",
            "action",
            "canonical_payload",
            "signature",
        ],
    )?;
    let device = DeviceId::from_bytes(fixed(outer.required("device")?)?);
    if device != expected_device {
        return Err(Error::WrongDevice);
    }
    let pool = nullable_fixed::<28>(outer.required("pool")?)?.map(PoolId::from_bytes);
    let incarnation =
        nullable_fixed::<16>(outer.required("incarnation")?)?.map(IncarnationId::from_bytes);
    let target = match (pool, incarnation) {
        (None, None) => Target::Device,
        (Some(pool), Some(incarnation)) => Target::Pool { pool, incarnation },
        _ => return Err(Error::WrongTarget),
    };
    let action = parse_action(outer.required("action")?.text()?)?;
    validate_target(action, target)?;
    let payload_bytes = outer.required("canonical_payload")?.bytes()?;
    if payload_bytes.len() > MAX_MANAGEMENT_PAYLOAD_BYTES {
        return Err(Error::InvalidPayload);
    }
    let canonical_payload = Value::parse(payload_bytes)?;
    validate_payload(action, canonical_payload, device, target)?;
    let fields = SigningFields {
        device,
        target,
        sequence: ManagementSequence::new(outer.required("management_sequence")?.uint()?),
        request: RequestId::try_from(outer.required("request")?.bytes()?)
            .map_err(|_| Error::InvalidStructure)?,
        expected_revision: Revision::new(outer.required("expected_revision")?.uint()?),
        action,
        canonical_payload,
    };
    let signature_bytes: [u8; 64] = fixed(outer.required("signature")?)?;
    let signature = Signature::from_bytes(&signature_bytes);
    let public_key = VerifyingKey::from_bytes(management_root_public_key)
        .map_err(|_| Error::InvalidAuthority)?;
    let mut message = [0; SIGNING_MESSAGE_BYTES];
    let length = encode_signing_message(fields, &mut message)?;
    public_key
        .verify(&message[..length], &signature)
        .map_err(|_| Error::Signature)?;
    Ok(VerifiedEnvelope {
        fields,
        transcript_digest: Sha256::digest(&message[..length]).into(),
    })
}

pub fn encode_signing_message(
    fields: SigningFields<'_>,
    output: &mut [u8],
) -> Result<usize, Error> {
    let mut encoder = Encoder::new(output);
    encoder.array(9)?;
    encoder.text(DOMAIN)?;
    encoder.bytes(fields.device.as_bytes())?;
    match fields.target {
        Target::Device => {
            encoder.null()?;
            encoder.null()?;
        }
        Target::Pool { pool, incarnation } => {
            encoder.bytes(pool.as_bytes())?;
            encoder.bytes(incarnation.as_bytes())?;
        }
    }
    encoder.uint(fields.sequence.get())?;
    encoder.bytes(fields.request.as_bytes())?;
    encoder.uint(fields.expected_revision.get())?;
    encoder.text(fields.action.name())?;
    encoder.value(fields.canonical_payload)?;
    Ok(encoder.finish()?.encoded().len())
}

fn parse_action(value: &str) -> Result<Action, Error> {
    match value {
        "ENROLL" => Ok(Action::Enroll),
        "RECIPIENT_REPLACE" => Ok(Action::RecipientReplace),
        "STAGED_DISCARD" => Ok(Action::StagedDiscard),
        "POOL_DELETE" => Ok(Action::PoolDelete),
        "CREDENTIAL_REPLACE" => Ok(Action::CredentialReplace),
        "CREDENTIAL_REVOKE" => Ok(Action::CredentialRevoke),
        "DEVICE_RETIRE" => Ok(Action::DeviceRetire),
        "FIRMWARE_AUTHORIZE" => Ok(Action::FirmwareAuthorize),
        _ => Err(Error::WrongAction),
    }
}

fn validate_target(action: Action, target: Target) -> Result<(), Error> {
    let valid = match action {
        Action::Enroll | Action::RecipientReplace | Action::StagedDiscard | Action::PoolDelete => {
            matches!(target, Target::Pool { .. })
        }
        Action::DeviceRetire | Action::FirmwareAuthorize => target == Target::Device,
        Action::CredentialReplace | Action::CredentialRevoke => true,
    };
    if valid {
        Ok(())
    } else {
        Err(Error::WrongTarget)
    }
}

fn validate_payload(
    action: Action,
    value: Value<'_>,
    device: DeviceId,
    target: Target,
) -> Result<(), Error> {
    let payload = value.map()?;
    match action {
        Action::Enroll => {
            exact_fields(
                payload,
                &[
                    "version",
                    "device",
                    "pool",
                    "incarnation",
                    "cold_verification_key",
                    "network",
                    "machine_public_key",
                    "credential_epoch",
                    "recipient_public_key",
                    "recipient_id",
                ],
            )?;
            if payload.required("version")?.uint()? != 1
                || DeviceId::from_bytes(fixed(payload.required("device")?)?) != device
                || payload.required("credential_epoch")?.uint()? != 0
            {
                return Err(Error::InvalidPayload);
            }
            let Target::Pool { pool, incarnation } = target else {
                return Err(Error::WrongTarget);
            };
            if PoolId::from_bytes(fixed(payload.required("pool")?)?) != pool
                || IncarnationId::from_bytes(fixed(payload.required("incarnation")?)?)
                    != incarnation
            {
                return Err(Error::WrongTarget);
            }
            let cold: [u8; 32] = fixed(payload.required("cold_verification_key")?)?;
            if PoolId::from_cold_verification_key(&cold) != pool {
                return Err(Error::InvalidPayload);
            }
            parse_network(payload.required("network")?)?;
            fixed::<32>(payload.required("machine_public_key")?)?;
            let recipient_public: [u8; 32] = fixed(payload.required("recipient_public_key")?)?;
            let recipient_id: [u8; 32] = fixed(payload.required("recipient_id")?)?;
            if <[u8; 32]>::from(Sha256::digest(recipient_public)) != recipient_id {
                return Err(Error::InvalidPayload);
            }
        }
        Action::RecipientReplace => {
            exact_fields(payload, &["recipient_public_key", "recipient_id"])?;
            let public: [u8; 32] = fixed(payload.required("recipient_public_key")?)?;
            let id: [u8; 32] = fixed(payload.required("recipient_id")?)?;
            if <[u8; 32]>::from(Sha256::digest(public)) != id {
                return Err(Error::InvalidPayload);
            }
        }
        Action::StagedDiscard => {
            exact_fields(payload, &["generation"])?;
            fixed::<16>(payload.required("generation")?)?;
        }
        Action::PoolDelete | Action::DeviceRetire => exact_fields(payload, &[])?,
        Action::CredentialReplace => {
            exact_fields(payload, &["machine_public_key", "credential_epoch"])?;
            fixed::<32>(payload.required("machine_public_key")?)?;
            payload.required("credential_epoch")?.uint()?;
        }
        Action::CredentialRevoke => {
            exact_fields(payload, &["credential_epoch"])?;
            payload.required("credential_epoch")?.uint()?;
        }
        Action::FirmwareAuthorize => validate_manifest(payload)?,
    }
    Ok(())
}

fn validate_manifest(payload: Map<'_>) -> Result<(), Error> {
    exact_fields(
        payload,
        &[
            "version",
            "firmware_digest",
            "partition_manifest_digest",
            "storage_schema",
            "image_length",
            "security_version",
            "hardware_policy_digest",
            "signature",
        ],
    )?;
    if payload.required("version")?.uint()? != 1
        || payload.required("storage_schema")?.uint()? != 1
        || payload.required("image_length")?.uint()? == 0
    {
        return Err(Error::InvalidPayload);
    }
    fixed::<32>(payload.required("firmware_digest")?)?;
    fixed::<32>(payload.required("partition_manifest_digest")?)?;
    payload.required("security_version")?.uint()?;
    fixed::<32>(payload.required("hardware_policy_digest")?)?;
    fixed::<64>(payload.required("signature")?)?;
    Ok(())
}

fn parse_network(value: Value<'_>) -> Result<NetworkBinding, Error> {
    let network = value.map()?;
    exact_fields(
        network,
        &[
            "network_magic",
            "shelley_genesis_digest",
            "slots_per_kes_period",
            "max_kes_evolutions",
        ],
    )?;
    let network_magic = u32::try_from(network.required("network_magic")?.uint()?)
        .map_err(|_| Error::InvalidPayload)?;
    let digest =
        EnrolledGenesisHash::from_bytes(fixed(network.required("shelley_genesis_digest")?)?);
    NetworkBinding::from_enrolled_digest(
        network_magic,
        digest,
        network.required("slots_per_kes_period")?.uint()?,
        network.required("max_kes_evolutions")?.uint()?,
    )
    .map_err(|_| Error::InvalidPayload)
}

fn exact_fields(map: Map<'_>, expected: &[&str]) -> Result<(), Error> {
    if map.len() != expected.len() {
        return Err(Error::InvalidStructure);
    }
    for field in map {
        let (name, _) = field?;
        if !expected.contains(&name) {
            return Err(Error::InvalidStructure);
        }
    }
    Ok(())
}

fn nullable_fixed<const N: usize>(value: Value<'_>) -> Result<Option<[u8; N]>, Error> {
    if value.is_null() {
        Ok(None)
    } else {
        fixed(value).map(Some)
    }
}

fn fixed<const N: usize>(value: Value<'_>) -> Result<[u8; N], Error> {
    value
        .bytes()?
        .try_into()
        .map_err(|_| Error::InvalidStructure)
}
