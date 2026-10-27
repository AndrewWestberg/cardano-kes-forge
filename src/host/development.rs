//! Direct USB extraction, never routed through a node/daemon socket.
//! KESDEV01 is exactly 733 bytes: magic[8], device[16], pool[28],
//! incarnation[16], generation[16], revision[u64 big-endian], relative_period[u8],
//! certificate_digest[32], current_state[608]. It is deliberately neither a
//! Cardano signing-key envelope, immutable initial backup, nor an import format.
#![cfg(feature = "development")]

use crate::backup::publication::{self, MemoryProtector, SystemMemory};
use crate::host::{
    client::{AuthenticatedClient, DeviceWire},
    config::PoolConnection,
    usb::UsbWire,
};
use kes_core::cbor::Map;
use kes_protocol::{Envelope, EnvelopeKind, MAX_FRAME_BYTES, Operation, Status};
use std::{fs::File, io::Read, path::Path, time::Duration};
use zeroize::{Zeroize, Zeroizing};

pub const OUTPUT_BYTES: usize = 733;
pub const MAGIC: &[u8; 8] = b"KESDEV01";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Usage,
    Security,
    Unavailable,
    Integrity,
    Publication,
}

/// Require a fresh no-swap cgroup before opening USB or reading credentials.
/// USB uses a transient library-owned packet buffer, so locking only our output
/// buffers would not protect every copy. This development-only command refuses
/// execution unless the kernel reports both zero swap limit and zero swap usage.
fn protect_process() -> Result<(), Error> {
    crate::host::memory::protect_secret_process().map_err(|_| Error::Security)
}

pub fn inspect(
    connection_file: &Path,
    selector: &str,
    generation: [u8; 16],
    output: &Path,
    allow_development: bool,
) -> Result<(), Error> {
    if !allow_development || !development_profile() {
        return Err(Error::Security);
    }
    protect_process()?;
    let connection = PoolConnection::load(connection_file).map_err(|_| Error::Security)?;
    if connection.security_policy != "isolated-development" {
        return Err(Error::Security);
    }
    let mut wire = UsbWire::open(selector).map_err(|_| Error::Unavailable)?;
    extract(&mut wire, &connection, generation, output)
}

pub const fn development_profile() -> bool {
    cfg!(feature = "development")
        && !cfg!(any(
            feature = "primary",
            feature = "recovery",
            feature = "management",
            feature = "provisioning"
        ))
}

fn extract(
    wire: &mut impl DeviceWire,
    connection: &PoolConnection,
    generation: [u8; 16],
    output: &Path,
) -> Result<(), Error> {
    let mut session =
        AuthenticatedClient::open_pool(wire, connection).map_err(|_| Error::Security)?;
    let mut request = [0; 16];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut request))
        .map_err(|_| Error::Unavailable)?;
    // Neither allocation may resize once protected. Both wipe before unlocking.
    let mut response = Zeroizing::new(vec![0; MAX_FRAME_BYTES]);
    let response_guard = SystemMemory
        .protect(&mut response)
        .map_err(|_| Error::Security)?;
    let mut encoded = Zeroizing::new(vec![0; OUTPUT_BYTES]);
    let encoded_guard = SystemMemory
        .protect(&mut encoded)
        .map_err(|_| Error::Security)?;
    let result = (|| {
        let response_array: &mut [u8; MAX_FRAME_BYTES] = response
            .as_mut_slice()
            .try_into()
            .map_err(|_| Error::Integrity)?;
        let length = session
            .exchange_development(
                wire,
                request,
                generation,
                response_array,
                Duration::from_secs(10),
            )
            .map_err(|_| Error::Unavailable)?;
        let envelope = Envelope::parse(&response[..length], EnvelopeKind::DeviceResponse)
            .map_err(|_| Error::Integrity)?;
        if envelope.operation != Operation::DevInspect
            || envelope.status != Some(Status::Ok)
            || fixed::<16>(envelope.map(), "device")? != connection.device_id
            || fixed::<28>(envelope.map(), "pool")? != connection.pool_id
            || fixed::<16>(envelope.map(), "incarnation")? != connection.incarnation_id
        {
            return Err(Error::Security);
        }
        encode_output(
            &mut encoded,
            connection.device_id,
            connection.pool_id,
            connection.incarnation_id,
            generation,
            envelope.payload(),
        )?;
        publication::publish_secret(output, &mut encoded).map_err(|_| Error::Publication)
    })();
    encoded.zeroize();
    response.zeroize();
    drop(encoded_guard);
    drop(response_guard);
    result
}

fn encode_output(
    output: &mut [u8],
    device: [u8; 16],
    pool: [u8; 28],
    incarnation: [u8; 16],
    generation: [u8; 16],
    payload: Map<'_>,
) -> Result<(), Error> {
    if output.len() != OUTPUT_BYTES
        || fixed::<16>(payload, "generation")? != generation
        || payload
            .required("health")
            .and_then(|v| v.text())
            .map_err(|_| Error::Integrity)?
            != "healthy"
        || payload
            .required("lifecycle")
            .and_then(|v| v.text())
            .map_err(|_| Error::Integrity)?
            != "active"
    {
        return Err(Error::Integrity);
    }
    let period = payload
        .required("relative_period")
        .and_then(|v| v.uint())
        .map_err(|_| Error::Integrity)?;
    if period > 63 {
        return Err(Error::Integrity);
    }
    let revision = payload
        .required("revision")
        .and_then(|v| v.uint())
        .map_err(|_| Error::Integrity)?;
    let certificate = fixed::<32>(payload, "certificate_digest")?;
    let state = payload
        .required("state")
        .and_then(|v| v.bytes())
        .map_err(|_| Error::Integrity)?;
    if state.len() != 608 {
        return Err(Error::Integrity);
    }
    output[..8].copy_from_slice(MAGIC);
    output[8..24].copy_from_slice(&device);
    output[24..52].copy_from_slice(&pool);
    output[52..68].copy_from_slice(&incarnation);
    output[68..84].copy_from_slice(&generation);
    output[84..92].copy_from_slice(&revision.to_be_bytes());
    output[92] = period as u8;
    output[93..125].copy_from_slice(&certificate);
    output[125..].copy_from_slice(state);
    Ok(())
}
fn fixed<const N: usize>(map: Map<'_>, name: &str) -> Result<[u8; N], Error> {
    map.required(name)
        .and_then(|v| v.bytes())
        .map_err(|_| Error::Integrity)?
        .try_into()
        .map_err(|_| Error::Integrity)
}

#[cfg(test)]
#[path = "development_tests.rs"]
mod tests;
