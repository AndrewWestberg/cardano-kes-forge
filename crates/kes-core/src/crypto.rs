//! Sum6KES adapter. Only the authenticated state owner may create/import keys,
//! supply entropy or choose enrollment policy. No wire/private-key import is
//! introduced here. Evolution mutates a caller-owned RAM candidate; persistence
//! and committed expiry/erasure remain the transaction owner's responsibility.
use crate::types::{KesLifetime, RelativePeriod};
use crate::{SIGNATURE_BYTES, SIGNING_STATE_BYTES};
use kes_summed_ed25519_adapted as sum6;
pub use sum6::{PublicTreeBuffer, VerifiedPublicTree};

const MAX_MESSAGE_BYTES: usize = 4096;

/// Closed algorithm/schema identity at private snapshot/container boundaries.
/// Conventional Cardano envelopes instead carry their standard explicit key
/// type and serialize only the exact608 bytes, never these metadata fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlgorithmVersion {
    pub algorithm: u16,
    pub version: u16,
}
pub const SUM6_V1: AlgorithmVersion = AlgorithmVersion {
    algorithm: 1,
    version: 1,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoError {
    UnsupportedAlgorithmVersion,
    InvalidLength { expected: usize, actual: usize },
    InvalidPeriod,
    LifetimeExceeded,
    StalePeriod,
    PeriodMismatch,
    MessageTooLong,
    ErasedKey,
    MalformedState,
    InvalidSignature,
    InvalidPublicTree,
    TreeMismatch,
    OutputInUse,
    GenerationIncomplete,
    GenerationComplete,
}
impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(f, "expected {expected} bytes, received {actual}")
            }
            Self::UnsupportedAlgorithmVersion => f.write_str("unsupported KES algorithm/schema"),
            Self::InvalidPeriod => f.write_str("invalid KES relative period"),
            Self::LifetimeExceeded => f.write_str("period outside enrolled KES lifetime"),
            Self::StalePeriod => f.write_str("KES cannot evolve backwards"),
            Self::PeriodMismatch => f.write_str("signing key is not at requested period"),
            Self::MessageTooLong => f.write_str("signing message exceeds4096 bytes"),
            Self::ErasedKey => f.write_str("KES secret is not live"),
            Self::MalformedState => f.write_str("malformed canonical KES state"),
            Self::InvalidSignature => f.write_str("invalid Sum6KES signature"),
            Self::InvalidPublicTree => f.write_str("invalid KES public tree"),
            Self::TreeMismatch => f.write_str("KES public tree/key mismatch"),
            Self::OutputInUse => f.write_str("generation output already live"),
            Self::GenerationIncomplete => f.write_str("KES generation incomplete"),
            Self::GenerationComplete => f.write_str("KES generation already complete"),
        }
    }
}
impl core::error::Error for CryptoError {}
impl From<sum6::Error> for CryptoError {
    fn from(error: sum6::Error) -> Self {
        match error {
            sum6::Error::InvalidPeriod => Self::InvalidPeriod,
            sum6::Error::ErasedKey => Self::ErasedKey,
            sum6::Error::Exhausted => Self::LifetimeExceeded,
            sum6::Error::InvalidState => Self::MalformedState,
            sum6::Error::InvalidSignature => Self::InvalidSignature,
            sum6::Error::InvalidPublicTree => Self::InvalidPublicTree,
            sum6::Error::TreeMismatch => Self::TreeMismatch,
            sum6::Error::OutputInUse => Self::OutputInUse,
            sum6::Error::GenerationIncomplete => Self::GenerationIncomplete,
            sum6::Error::GenerationComplete => Self::GenerationComplete,
        }
    }
}

/// Secret borrowed serialization view: intentionally no Debug/serde/Clone.
pub struct CanonicalState<'a> {
    bytes: &'a [u8; SIGNING_STATE_BYTES],
    period: RelativePeriod,
}
impl<'a> CanonicalState<'a> {
    pub const fn algorithm(&self) -> AlgorithmVersion {
        SUM6_V1
    }
    pub const fn relative_period(&self) -> RelativePeriod {
        self.period
    }
    pub const fn bytes(&self) -> &'a [u8; SIGNING_STATE_BYTES] {
        self.bytes
    }
}

/// Owns fixed zeroizing private state and immutable enrolled lifetime. Request
/// fields cannot extend that lifetime. Public generation metadata/VK must be
/// retained separately when a committed expiry erases this secret.
pub struct KesKey {
    state: sum6::SigningState,
    lifetime: KesLifetime,
}
impl KesKey {
    pub fn erased(lifetime: KesLifetime) -> Self {
        Self {
            state: sum6::SigningState::erased(),
            lifetime,
        }
    }
    pub fn is_live(&self) -> bool {
        self.state.is_live()
    }
    pub const fn lifetime(&self) -> KesLifetime {
        self.lifetime
    }
    pub fn erase(&mut self) {
        self.state.erase();
    }
    pub fn period(&self) -> Result<RelativePeriod, CryptoError> {
        let value = self.state.period().ok_or(CryptoError::ErasedKey)?;
        RelativePeriod::new(u64::from(value)).map_err(|_| CryptoError::InvalidPeriod)
    }
    pub fn from_canonical(
        algorithm: AlgorithmVersion,
        bytes: &[u8],
        period: RelativePeriod,
        lifetime: KesLifetime,
    ) -> Result<Self, CryptoError> {
        if algorithm != SUM6_V1 {
            return Err(CryptoError::UnsupportedAlgorithmVersion);
        }
        let fixed: &[u8; SIGNING_STATE_BYTES] =
            bytes.try_into().map_err(|_| CryptoError::InvalidLength {
                expected: SIGNING_STATE_BYTES,
                actual: bytes.len(),
            })?;
        within_lifetime(period, lifetime)?;
        Ok(Self {
            state: sum6::SigningState::from_canonical(fixed, period.get())?,
            lifetime,
        })
    }
    pub fn canonical_state(&self) -> Result<CanonicalState<'_>, CryptoError> {
        Ok(CanonicalState {
            period: self.period()?,
            bytes: self.state.canonical_bytes()?,
        })
    }
    pub fn verification_key(&self) -> Result<[u8; 32], CryptoError> {
        self.state.verification_key().map_err(Into::into)
    }
    pub fn sign_into(
        &self,
        expected_period: RelativePeriod,
        message: &[u8],
        output: &mut [u8; SIGNATURE_BYTES],
    ) -> Result<(), CryptoError> {
        bounded_message(message)?;
        within_lifetime(expected_period, self.lifetime)?;
        if expected_period != self.period()? {
            return Err(CryptoError::PeriodMismatch);
        }
        self.state.sign_into(message, output).map_err(Into::into)
    }
    /// Same-period requests are no-write successes; backwards/out-of-lifetime
    /// requests leave the key unchanged. Do not confuse refusal with committed
    /// expiry: the caller must durably erase before acknowledging that transition.
    pub fn evolve_to(
        &mut self,
        target: RelativePeriod,
        cache: &VerifiedPublicTree<'_>,
    ) -> Result<(), CryptoError> {
        within_lifetime(target, self.lifetime)?;
        let current = self.period()?;
        if target < current {
            return Err(CryptoError::StalePeriod);
        }
        for _ in current.get()..target.get() {
            self.state.evolve(cache)?;
        }
        Ok(())
    }
}

fn bounded_message(message: &[u8]) -> Result<(), CryptoError> {
    if message.len() > MAX_MESSAGE_BYTES {
        Err(CryptoError::MessageTooLong)
    } else {
        Ok(())
    }
}
fn within_lifetime(period: RelativePeriod, lifetime: KesLifetime) -> Result<(), CryptoError> {
    if period.get() >= lifetime.get() {
        Err(CryptoError::LifetimeExceeded)
    } else {
        Ok(())
    }
}
pub fn verify(
    verification_key: &[u8; 32],
    period: RelativePeriod,
    lifetime: KesLifetime,
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    bounded_message(message)?;
    within_lifetime(period, lifetime)?;
    let fixed: &[u8; SIGNATURE_BYTES] =
        signature
            .try_into()
            .map_err(|_| CryptoError::InvalidLength {
                expected: SIGNATURE_BYTES,
                actual: signature.len(),
            })?;
    sum6::verify(verification_key, period.get(), message, fixed).map_err(Into::into)
}

/// Owned, allocation-free cooperative job, safe to retain between scheduler
/// turns. Input entropy must be fresh and healthy; `begin` wipes the seed.
/// Cancellation/drop wipes all unpublished secret material.
pub struct Generation {
    inner: sum6::Generation,
    lifetime: KesLifetime,
}
impl Generation {
    pub fn begin(seed: &mut [u8; 32], lifetime: KesLifetime) -> Result<Self, CryptoError> {
        Ok(Self {
            inner: sum6::Generation::begin(seed)?,
            lifetime,
        })
    }
    pub fn step(&mut self) -> Result<u8, CryptoError> {
        Ok(self.inner.step()?.completed_leaves)
    }
    pub const fn completed_leaves(&self) -> u8 {
        self.inner.completed_leaves()
    }
    pub fn finish(self) -> Result<(KesKey, PublicTreeBuffer), CryptoError> {
        let (state, tree) = self.inner.finish()?;
        Ok((KesKey { state, lifetime: self.lifetime }, tree))
    }
}
