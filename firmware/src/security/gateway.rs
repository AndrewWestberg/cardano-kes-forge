//! Narrow copy boundary between non-secure USB framing and secure dispatch.

use core::fmt;

use hkdf::Hkdf;
use kes_core::types::DeviceId;
use kes_protocol::MAX_FRAME_BYTES;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

const STORAGE_LABEL: &[u8] = b"cardano-kes-forge/storage-root/v1";
const SESSION_LABEL: &[u8] = b"cardano-kes-forge/session-root/v1";
const IDENTITY_LABEL: &[u8] = b"cardano-kes-forge/device-identity-seed/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayError {
    Busy,
    Empty,
    Oversize,
    LengthMismatch,
    ResponseTooLarge,
    OutputTooSmall,
    KeyDerivation,
}

impl fmt::Display for GatewayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Busy => "secure gateway is busy",
            Self::Empty => "non-secure request is empty",
            Self::Oversize => "non-secure request exceeds the secure buffer",
            Self::LengthMismatch => "non-secure request length changed",
            Self::ResponseTooLarge => "secure response exceeds the bounded buffer",
            Self::OutputTooSmall => "non-secure response destination is too small",
            Self::KeyDerivation => "device key derivation failed",
        })
    }
}

impl core::error::Error for GatewayError {}

/// Domain-separated keys derived while the device root remains in secure RAM.
/// No secret key implements Debug, Clone or serialization.
pub struct DeviceKeys {
    storage_root: Zeroizing<[u8; 32]>,
    session_root: Zeroizing<[u8; 32]>,
    identity_seed: Zeroizing<[u8; 32]>,
}

impl DeviceKeys {
    pub fn derive(device: DeviceId, root: Zeroizing<[u8; 32]>) -> Result<Self, GatewayError> {
        let hkdf = Hkdf::<Sha256>::new(Some(device.as_bytes()), &*root);
        let mut keys = Self {
            storage_root: Zeroizing::new([0; 32]),
            session_root: Zeroizing::new([0; 32]),
            identity_seed: Zeroizing::new([0; 32]),
        };
        hkdf.expand(STORAGE_LABEL, &mut *keys.storage_root)
            .map_err(|_| GatewayError::KeyDerivation)?;
        hkdf.expand(SESSION_LABEL, &mut *keys.session_root)
            .map_err(|_| GatewayError::KeyDerivation)?;
        hkdf.expand(IDENTITY_LABEL, &mut *keys.identity_seed)
            .map_err(|_| GatewayError::KeyDerivation)?;
        Ok(keys)
    }

    pub fn storage_root(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.storage_root)
    }

    pub fn session_root(&self) -> &[u8; 32] {
        &self.session_root
    }

    pub fn identity_seed(&self) -> &[u8; 32] {
        &self.identity_seed
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum State {
    Idle,
    Admitted,
}

/// Secure-owned fixed request/response storage. Non-secure slices are used only
/// during the two bounded copies and are never retained in secure state.
pub struct Gateway {
    request: [u8; MAX_FRAME_BYTES],
    response: [u8; MAX_FRAME_BYTES],
    state: State,
}

impl Gateway {
    pub const fn new() -> Self {
        Self {
            request: [0; MAX_FRAME_BYTES],
            response: [0; MAX_FRAME_BYTES],
            state: State::Idle,
        }
    }

    pub fn admit<'a>(
        &'a mut self,
        nonsecure_request: &[u8],
        declared_length: usize,
    ) -> Result<SecureTransaction<'a>, GatewayError> {
        if self.state != State::Idle {
            return Err(GatewayError::Busy);
        }
        if declared_length == 0 {
            return Err(GatewayError::Empty);
        }
        if declared_length > MAX_FRAME_BYTES {
            return Err(GatewayError::Oversize);
        }
        if nonsecure_request.len() != declared_length {
            return Err(GatewayError::LengthMismatch);
        }
        self.request[..declared_length].copy_from_slice(nonsecure_request);
        self.state = State::Admitted;
        Ok(SecureTransaction {
            gateway: self,
            request_length: declared_length,
        })
    }
}

impl Default for Gateway {
    fn default() -> Self {
        Self::new()
    }
}

pub struct SecureTransaction<'a> {
    gateway: &'a mut Gateway,
    request_length: usize,
}

impl SecureTransaction<'_> {
    pub fn request(&self) -> &[u8] {
        &self.gateway.request[..self.request_length]
    }

    pub fn response(&mut self) -> &mut [u8; MAX_FRAME_BYTES] {
        &mut self.gateway.response
    }

    /// Borrows the exact secure request and the distinct fixed response buffer
    /// together so dispatch never copies a per-operation body.
    pub fn buffers(&mut self) -> (&[u8], &mut [u8; MAX_FRAME_BYTES]) {
        (
            &self.gateway.request[..self.request_length],
            &mut self.gateway.response,
        )
    }

    pub fn complete(
        self,
        response_length: usize,
        nonsecure_output: &mut [u8],
    ) -> Result<usize, GatewayError> {
        if response_length > MAX_FRAME_BYTES {
            return Err(GatewayError::ResponseTooLarge);
        }
        if nonsecure_output.len() < response_length {
            return Err(GatewayError::OutputTooSmall);
        }
        nonsecure_output[..response_length]
            .copy_from_slice(&self.gateway.response[..response_length]);
        Ok(response_length)
    }
}

impl Drop for SecureTransaction<'_> {
    fn drop(&mut self) {
        self.gateway.request.zeroize();
        self.gateway.response.zeroize();
        self.gateway.state = State::Idle;
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.request.zeroize();
        self.response.zeroize();
    }
}

const _: () = assert!(MAX_FRAME_BYTES == 8192);
