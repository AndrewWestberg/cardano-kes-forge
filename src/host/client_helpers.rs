use super::*;

pub(super) fn encode_local_target(
    encoder: &mut Encoder<'_>,
    connection: &LocalConnection<'_>,
) -> Result<(), kes_core::cbor::Error> {
    encoder.array(3)?;
    match connection {
        LocalConnection::Device(device) => {
            encoder.bytes(&device.device_id)?;
            encoder.null()?;
            encoder.null()
        }
        LocalConnection::Pool(pool) => {
            encoder.bytes(&pool.device_id)?;
            encoder.bytes(&pool.pool_id)?;
            encoder.bytes(&pool.incarnation_id)
        }
    }
}

pub(super) fn encode_info_request(
    request: [u8; 16],
    challenge: [u8; 32],
) -> Result<Vec<u8>, Error> {
    let mut storage = [0; kes_protocol::MAX_FRAME_BYTES];
    let mut encoder = Encoder::new(&mut storage);
    encoder.map(4).map_err(|_| Error::Integrity)?;
    encoder.text("op").map_err(|_| Error::Integrity)?;
    encoder.text("INFO").map_err(|_| Error::Integrity)?;
    encoder.text("payload").map_err(|_| Error::Integrity)?;
    encoder.map(1).map_err(|_| Error::Integrity)?;
    encoder.text("challenge").map_err(|_| Error::Integrity)?;
    encoder.bytes(&challenge).map_err(|_| Error::Integrity)?;
    encoder.text("request").map_err(|_| Error::Integrity)?;
    encoder.bytes(&request).map_err(|_| Error::Integrity)?;
    encoder.text("version").map_err(|_| Error::Integrity)?;
    encoder.uint(1).map_err(|_| Error::Integrity)?;
    Ok(encoder
        .finish()
        .map_err(|_| Error::Integrity)?
        .encoded()
        .to_vec())
}

pub(super) fn encode_open_request(open: &kes_core::session::OpenRequest) -> Result<Vec<u8>, Error> {
    let mut storage = [0; kes_protocol::MAX_FRAME_BYTES];
    let mut encoder = Encoder::new(&mut storage);
    encoder.map(7).map_err(|_| Error::Integrity)?;
    encoder.text("op").map_err(|_| Error::Integrity)?;
    encoder.text("OPEN").map_err(|_| Error::Integrity)?;
    encoder.text("pool").map_err(|_| Error::Integrity)?;
    match open.context.scope {
        Scope::Management => encoder.null().map_err(|_| Error::Integrity)?,
        Scope::Pool { pool, .. } => encoder
            .bytes(pool.as_bytes())
            .map_err(|_| Error::Integrity)?,
    }
    encoder.text("device").map_err(|_| Error::Integrity)?;
    encoder
        .bytes(open.context.device.as_bytes())
        .map_err(|_| Error::Integrity)?;
    encoder.text("payload").map_err(|_| Error::Integrity)?;
    encoder.map(6).map_err(|_| Error::Integrity)?;
    encoder.text("signature").map_err(|_| Error::Integrity)?;
    encoder
        .bytes(&open.signature)
        .map_err(|_| Error::Integrity)?;
    encoder.text("boot_nonce").map_err(|_| Error::Integrity)?;
    encoder
        .bytes(&open.context.boot_nonce)
        .map_err(|_| Error::Integrity)?;
    encoder.text("ciphertext").map_err(|_| Error::Integrity)?;
    encoder
        .bytes(&open.ciphertext)
        .map_err(|_| Error::Integrity)?;
    encoder.text("open_counter").map_err(|_| Error::Integrity)?;
    encoder
        .uint(open.context.open_counter)
        .map_err(|_| Error::Integrity)?;
    encoder
        .text("encapsulation")
        .map_err(|_| Error::Integrity)?;
    encoder
        .bytes(&open.encapsulation)
        .map_err(|_| Error::Integrity)?;
    encoder
        .text("credential_epoch")
        .map_err(|_| Error::Integrity)?;
    encoder
        .uint(open.context.credential_epoch.get())
        .map_err(|_| Error::Integrity)?;
    encoder.text("request").map_err(|_| Error::Integrity)?;
    encoder
        .bytes(open.context.request.as_bytes())
        .map_err(|_| Error::Integrity)?;
    encoder.text("version").map_err(|_| Error::Integrity)?;
    encoder.uint(1).map_err(|_| Error::Integrity)?;
    encoder.text("incarnation").map_err(|_| Error::Integrity)?;
    match open.context.scope {
        Scope::Management => encoder.null().map_err(|_| Error::Integrity)?,
        Scope::Pool { incarnation, .. } => encoder
            .bytes(incarnation.as_bytes())
            .map_err(|_| Error::Integrity)?,
    }
    Ok(encoder
        .finish()
        .map_err(|_| Error::Integrity)?
        .encoded()
        .to_vec())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn encode_device_request(
    output: &mut [u8; kes_protocol::MAX_FRAME_BYTES],
    device: [u8; 16],
    pool: Option<[u8; 28]>,
    incarnation: Option<[u8; 16]>,
    session: &[u8; 16],
    sequence: u64,
    request: &[u8; 16],
    budget_ms: u32,
    operation: Operation,
    payload: Map<'_>,
    mac: &[u8; 32],
) -> Result<usize, Error> {
    let mut encoder = Encoder::new(output);
    encoder.map(11).map_err(|_| Error::Integrity)?;
    encoder.text("op").map_err(|_| Error::Integrity)?;
    encoder
        .text(operation.as_str())
        .map_err(|_| Error::Integrity)?;
    encoder.text("mac").map_err(|_| Error::Integrity)?;
    encoder.bytes(mac).map_err(|_| Error::Integrity)?;
    encoder.text("seq").map_err(|_| Error::Integrity)?;
    encoder.uint(sequence).map_err(|_| Error::Integrity)?;
    encoder.text("pool").map_err(|_| Error::Integrity)?;
    match pool {
        Some(value) => encoder.bytes(&value).map_err(|_| Error::Integrity)?,
        None => encoder.null().map_err(|_| Error::Integrity)?,
    }
    encoder.text("device").map_err(|_| Error::Integrity)?;
    encoder.bytes(&device).map_err(|_| Error::Integrity)?;
    encoder.text("payload").map_err(|_| Error::Integrity)?;
    if operation == Operation::Status
        && payload
            .get("host_diagnostics")
            .map_err(|_| Error::Integrity)?
            .is_some()
    {
        encoder
            .map(payload.len() - 1)
            .map_err(|_| Error::Integrity)?;
        for field in payload {
            let (key, value) = field.map_err(|_| Error::Integrity)?;
            if key != "host_diagnostics" {
                encoder
                    .text(key)
                    .and_then(|()| encoder.value(value))
                    .map_err(|_| Error::Integrity)?;
            }
        }
    } else {
        encoder
            .value(Value::parse(payload.encoded()).map_err(|_| Error::Integrity)?)
            .map_err(|_| Error::Integrity)?;
    }
    encoder.text("request").map_err(|_| Error::Integrity)?;
    encoder.bytes(request).map_err(|_| Error::Integrity)?;
    encoder.text("session").map_err(|_| Error::Integrity)?;
    encoder.bytes(session).map_err(|_| Error::Integrity)?;
    encoder.text("version").map_err(|_| Error::Integrity)?;
    encoder.uint(1).map_err(|_| Error::Integrity)?;
    encoder.text("budget_ms").map_err(|_| Error::Integrity)?;
    encoder
        .uint(u64::from(budget_ms))
        .map_err(|_| Error::Integrity)?;
    encoder.text("incarnation").map_err(|_| Error::Integrity)?;
    match incarnation {
        Some(value) => encoder.bytes(&value).map_err(|_| Error::Integrity)?,
        None => encoder.null().map_err(|_| Error::Integrity)?,
    }
    Ok(encoder
        .finish()
        .map_err(|_| Error::Integrity)?
        .encoded()
        .len())
}

pub(super) fn encode_local_response(
    output: &mut [u8; kes_protocol::MAX_FRAME_BYTES],
    connection: &str,
    request: &[u8; 16],
    operation: Operation,
    status: Status,
    payload: Map<'_>,
) -> Result<usize, Error> {
    let mut encoder = Encoder::new(output);
    encoder.map(6).map_err(|_| Error::Integrity)?;
    encoder.text("op").map_err(|_| Error::Integrity)?;
    encoder
        .text(operation.as_str())
        .map_err(|_| Error::Integrity)?;
    encoder.text("status").map_err(|_| Error::Integrity)?;
    encoder
        .text(status.as_str())
        .map_err(|_| Error::Integrity)?;
    encoder.text("payload").map_err(|_| Error::Integrity)?;
    encoder
        .value(Value::parse(payload.encoded()).map_err(|_| Error::Integrity)?)
        .map_err(|_| Error::Integrity)?;
    encoder.text("request").map_err(|_| Error::Integrity)?;
    encoder.bytes(request).map_err(|_| Error::Integrity)?;
    encoder.text("version").map_err(|_| Error::Integrity)?;
    encoder.uint(1).map_err(|_| Error::Integrity)?;
    encoder.text("connection").map_err(|_| Error::Integrity)?;
    encoder.text(connection).map_err(|_| Error::Integrity)?;
    Ok(encoder
        .finish()
        .map_err(|_| Error::Integrity)?
        .encoded()
        .len())
}

pub(super) fn validate_info_identity(
    payload: Map<'_>,
    binding: &SessionBinding<'_>,
) -> Result<(), Error> {
    if fixed::<32>(payload, "firmware_digest")? != binding.firmware_digest
        || fixed::<32>(payload, "hardware_policy_digest")? != binding.hardware_policy_digest
        || number(payload, "security_version")? != binding.security_version
    {
        return Err(Error::Security);
    }
    Ok(())
}

pub(super) fn verify_release_info(
    payload: Map<'_>,
    binding: &SessionBinding<'_>,
    challenge: [u8; 32],
    boot_nonce: [u8; 32],
) -> Result<(), Error> {
    use crate::host::security::{self, Mode, Pins, ReadinessVerifier};
    if binding.device != binding.identity.device_id {
        return Err(Error::Security);
    }
    let record = binding
        .identity
        .verified_release_record()
        .map_err(|_| Error::Security)?;
    let silicon_revision = record
        .silicon_revision
        .strip_prefix('A')
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or(Error::Security)?;
    let pins = Pins {
        device: binding.device,
        identity_public_key: binding.identity_public_key,
        silicon_revision,
        rom_revision: record.rom_revision,
        flash_part: record.flash_part,
        flash_capacity_bytes: record.flash_capacity_bytes,
        firmware_digest: binding.firmware_digest,
        hardware_policy_digest: binding.hardware_policy_digest,
        security_version: binding.security_version,
    };
    let bytes = payload
        .required("capability_evidence")
        .and_then(|v| v.bytes())
        .map_err(|_| Error::Security)?;
    let evidence = security::decode_online_evidence(bytes).map_err(|_| Error::Security)?;
    if evidence.mode != Mode::ReleaseReady || evidence.boot_nonce != boot_nonce {
        return Err(Error::Security);
    }
    // A new unpredictable challenge is generated for each INFO. Both signatures
    // bind it; no evidence or roots supplied by the device become host pins.
    ReadinessVerifier::default()
        .verify(&pins, challenge, evidence, false)
        .map_err(|_| Error::Security)?;
    Ok(())
}

pub(super) fn open_counter(
    payload: Map<'_>,
    expected_pool: Option<[u8; 28]>,
    expected_incarnation: Option<[u8; 16]>,
) -> Result<u64, Error> {
    let counters = payload
        .required("open_counters")
        .and_then(|value| value.array())
        .map_err(|_| Error::Integrity)?;
    let mut matched = None;
    for value in counters {
        let map = value.map().map_err(|_| Error::Integrity)?;
        let pool = optional_fixed(map, "pool")?;
        let incarnation = optional_fixed(map, "incarnation")?;
        if pool == expected_pool && incarnation == expected_incarnation {
            if matched.is_some() {
                return Err(Error::Security);
            }
            matched = Some(number(map, "open_counter")?);
        }
    }
    matched.ok_or(Error::Security)
}

fn optional_fixed<const N: usize>(map: Map<'_>, field: &str) -> Result<Option<[u8; N]>, Error> {
    let value = map.required(field).map_err(|_| Error::Integrity)?;
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
