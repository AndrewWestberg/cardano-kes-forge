//! Bounded canonical operational certificates and their enrollment bindings.
use crate::cbor::{self, Value};
use crate::types::{
    AbsolutePeriod, CertificateCounter, KesLifetime, NetworkBinding, PoolId, RelativePeriod,
};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

pub const MAX_CANONICAL_CERTIFICATE_BYTES: usize = 154;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateError {
    Cbor(cbor::Error),
    InvalidLength,
    InvalidStructure,
    InvalidColdKey,
    InvalidSignature,
    WrongColdKey,
    WrongPool,
    WrongKesKey,
    WrongNetwork,
    LifetimeMismatch,
    LifetimeOverflow,
    NotYetValid,
    Expired,
    CounterNotIncreasing,
}
impl core::fmt::Display for CertificateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Cbor(error) => return core::fmt::Display::fmt(error, f),
            Self::InvalidLength => "certificate length invalid",
            Self::InvalidStructure => "certificate structure invalid",
            Self::InvalidColdKey => "certificate cold key invalid",
            Self::InvalidSignature => "certificate cold signature invalid",
            Self::WrongColdKey => "certificate cold key mismatch",
            Self::WrongPool => "certificate pool identity mismatch",
            Self::WrongKesKey => "certificate KES key mismatch",
            Self::WrongNetwork => "certificate request network mismatch",
            Self::LifetimeMismatch => "certificate lifetime mismatch",
            Self::LifetimeOverflow => "certificate lifetime end overflow",
            Self::NotYetValid => "certificate not yet valid",
            Self::Expired => "certificate expired",
            Self::CounterNotIncreasing => "certificate counter must increase",
        })
    }
}
impl core::error::Error for CertificateError {}
impl From<cbor::Error> for CertificateError {
    fn from(error: cbor::Error) -> Self {
        Self::Cbor(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifetimeWindow {
    start: AbsolutePeriod,
    end_exclusive: AbsolutePeriod,
    lifetime: KesLifetime,
}
impl LifetimeWindow {
    pub fn new(start: AbsolutePeriod, lifetime: KesLifetime) -> Result<Self, CertificateError> {
        let end_exclusive = start
            .checked_add(u64::from(lifetime.get()))
            .map_err(|_| CertificateError::LifetimeOverflow)?;
        Ok(Self {
            start,
            end_exclusive,
            lifetime,
        })
    }
    pub fn relative_period(
        &self,
        period: AbsolutePeriod,
    ) -> Result<RelativePeriod, CertificateError> {
        if period < self.start {
            return Err(CertificateError::NotYetValid);
        }
        if period >= self.end_exclusive {
            return Err(CertificateError::Expired);
        }
        // The checked half-open window bounds the difference to 0..L-1, L<=64.
        RelativePeriod::new(period.get() - self.start.get()).map_err(|_| CertificateError::Expired)
    }
    pub const fn start(&self) -> AbsolutePeriod {
        self.start
    }
    pub const fn end_exclusive(&self) -> AbsolutePeriod {
        self.end_exclusive
    }
    pub const fn lifetime(&self) -> KesLifetime {
        self.lifetime
    }
}

pub struct CertificateContext<'a> {
    pub pool: PoolId,
    pub cold_verification_key: &'a [u8; 32],
    pub kes_verification_key: &'a [u8; 32],
    pub enrolled_network: &'a NetworkBinding,
    pub request_network: &'a NetworkBinding,
    pub lifetime: KesLifetime,
    pub last_activated_counter: Option<CertificateCounter>,
}

/// Owned public bytes, constructed only after canonical decoding and strict verification.
pub struct OperationalCertificate {
    canonical_bytes: [u8; MAX_CANONICAL_CERTIFICATE_BYTES],
    canonical_length: u8,
    counter: CertificateCounter,
    start_period: AbsolutePeriod,
    digest: [u8; 32],
}
impl OperationalCertificate {
    pub fn decode_and_verify(bytes: &[u8]) -> Result<Self, CertificateError> {
        if bytes.is_empty() || bytes.len() > MAX_CANONICAL_CERTIFICATE_BYTES {
            return Err(CertificateError::InvalidLength);
        }
        let structure = || CertificateError::InvalidStructure;
        let mut outer = Value::parse(bytes)?.array().map_err(|_| structure())?;
        let mut body = outer
            .next()
            .ok_or_else(structure)?
            .array()
            .map_err(|_| structure())?;
        let hot: &[u8; 32] = body
            .next()
            .ok_or_else(structure)?
            .bytes()
            .map_err(|_| structure())?
            .try_into()
            .map_err(|_| structure())?;
        let counter = CertificateCounter::new(
            body.next()
                .ok_or_else(structure)?
                .uint()
                .map_err(|_| structure())?,
        );
        let start_period = AbsolutePeriod::new(
            body.next()
                .ok_or_else(structure)?
                .uint()
                .map_err(|_| structure())?,
        );
        let signature: &[u8; 64] = body
            .next()
            .ok_or_else(structure)?
            .bytes()
            .map_err(|_| structure())?
            .try_into()
            .map_err(|_| structure())?;
        if body.next().is_some() {
            return Err(structure());
        }
        let cold: &[u8; 32] = outer
            .next()
            .ok_or_else(structure)?
            .bytes()
            .map_err(|_| structure())?
            .try_into()
            .map_err(|_| structure())?;
        if outer.next().is_some() {
            return Err(structure());
        }
        let verifier =
            VerifyingKey::from_bytes(cold).map_err(|_| CertificateError::InvalidColdKey)?;
        let mut message = [0; 48];
        message[..32].copy_from_slice(hot);
        message[32..40].copy_from_slice(&counter.get().to_be_bytes());
        message[40..].copy_from_slice(&start_period.get().to_be_bytes());
        verifier
            .verify_strict(&message, &Signature::from_bytes(signature))
            .map_err(|_| CertificateError::InvalidSignature)?;
        let mut canonical_bytes = [0; MAX_CANONICAL_CERTIFICATE_BYTES];
        canonical_bytes[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            canonical_bytes,
            canonical_length: bytes.len() as u8,
            counter,
            start_period,
            digest: Sha256::digest(bytes).into(),
        })
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes[..usize::from(self.canonical_length)]
    }
    pub fn cold_verification_key(&self) -> &[u8; 32] {
        // Canonical B32 is the last field, and both its length and position were validated.
        self.canonical_bytes()[usize::from(self.canonical_length) - 32..]
            .try_into()
            .expect("validated certificate cold key length")
    }
    pub fn kes_verification_key(&self) -> &[u8; 32] {
        // Canonical two/four-element arrays and the B32 header occupy four bytes.
        self.canonical_bytes[4..36]
            .try_into()
            .expect("validated certificate KES key length")
    }
    pub const fn counter(&self) -> CertificateCounter {
        self.counter
    }
    pub const fn start_period(&self) -> AbsolutePeriod {
        self.start_period
    }
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub fn signable_bytes(&self) -> [u8; 48] {
        let mut message = [0; 48];
        message[..32].copy_from_slice(self.kes_verification_key());
        message[32..40].copy_from_slice(&self.counter.get().to_be_bytes());
        message[40..].copy_from_slice(&self.start_period.get().to_be_bytes());
        message
    }
    pub fn validate_bound(
        &self,
        context: CertificateContext<'_>,
    ) -> Result<LifetimeWindow, CertificateError> {
        if self.cold_verification_key() != context.cold_verification_key {
            return Err(CertificateError::WrongColdKey);
        }
        if PoolId::from_cold_verification_key(self.cold_verification_key()) != context.pool {
            return Err(CertificateError::WrongPool);
        }
        if self.kes_verification_key() != context.kes_verification_key {
            return Err(CertificateError::WrongKesKey);
        }
        if context.enrolled_network != context.request_network {
            return Err(CertificateError::WrongNetwork);
        }
        if context.lifetime.get() != context.enrolled_network.max_kes_evolutions() {
            return Err(CertificateError::LifetimeMismatch);
        }
        if context
            .last_activated_counter
            .is_some_and(|last| self.counter <= last)
        {
            return Err(CertificateError::CounterNotIncreasing);
        }
        LifetimeWindow::new(self.start_period, context.lifetime)
    }
}
