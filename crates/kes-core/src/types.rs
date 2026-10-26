//! Public identities and checked network/arithmetic boundaries. No secret state,
//! implicit identifier defaults, host allocation or node-specific genesis codec.
use blake2::{Blake2b, Digest, digest::consts::U28};
use core::fmt;
use core::num::NonZeroU64;
use rand_chacha::rand_core::TryCryptoRng;
use sha2::Sha256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TypeError {
    InvalidLength { expected: usize, actual: usize },
    EntropyUnavailable,
    Overflow,
    RelativePeriodOutOfRange,
    SlotOutOfRange,
    ZeroSlotsPerKesPeriod,
    InvalidKesLifetime,
}

impl fmt::Display for TypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => write!(
                f,
                "expected {expected} public identity bytes, received {actual}"
            ),
            Self::EntropyUnavailable => f.write_str("identifier entropy unavailable"),
            Self::Overflow => f.write_str("unsigned counter overflow"),
            Self::RelativePeriodOutOfRange => {
                f.write_str("relative KES period must be 0 through 63")
            }
            Self::SlotOutOfRange => f.write_str("internal hardware slot must be 0 through 31"),
            Self::ZeroSlotsPerKesPeriod => f.write_str("slots per KES period must be positive"),
            Self::InvalidKesLifetime => f.write_str("KES lifetime must be 1 through 64"),
        }
    }
}

impl core::error::Error for TypeError {}

fn public_hex(bytes: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in bytes {
        write!(f, "{byte:02x}")?;
    }
    Ok(())
}

macro_rules! fixed_public_bytes {
    ($name:ident, $size:expr) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(transparent)]
        pub struct $name([u8; $size]);

        impl $name {
            /// Decode public bytes. Creation-time randomness or the enclosing
            /// authenticated binding must be established by the owning workflow.
            pub const fn from_bytes(bytes: [u8; $size]) -> Self {
                Self(bytes)
            }
            pub const fn as_bytes(&self) -> &[u8; $size] {
                &self.0
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = TypeError;
            fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
                let value = bytes.try_into().map_err(|_| TypeError::InvalidLength {
                    expected: $size,
                    actual: bytes.len(),
                })?;
                Ok(Self(value))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                public_hex(&self.0, f)
            }
        }
    };
}

macro_rules! random_identifier {
    ($name:ident) => {
        fixed_public_bytes!($name, 16);
        impl $name {
            /// Consume fresh CSPRNG output independently for this identifier.
            /// The caller owns entropy health, correct seeding and reseeding.
            pub fn random<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, TypeError> {
                let mut bytes = [0u8; 16];
                rng.try_fill_bytes(&mut bytes)
                    .map_err(|_| TypeError::EntropyUnavailable)?;
                Ok(Self(bytes))
            }
        }
    };
}

random_identifier!(DeviceId);
random_identifier!(IncarnationId);
random_identifier!(GenerationId);
random_identifier!(RequestId);
fixed_public_bytes!(PoolId, 28);
fixed_public_bytes!(EnrolledGenesisHash, 32);

impl PoolId {
    /// Parameterized BLAKE2b-224, not truncated BLAKE2b-512. Cold verification
    /// keys are public; a pool label or internal slot is never an identity.
    pub fn from_cold_verification_key(cold_verification_key: &[u8; 32]) -> Self {
        Self(Blake2b::<U28>::digest(cold_verification_key).into())
    }
}

impl EnrolledGenesisHash {
    /// SHA-256 of the exact enrolled Shelley genesis file bytes. Do not parse,
    /// normalize or substitute the ledger/node's differently encoded hash type.
    pub fn from_exact_bytes(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }
}

/// An explicit public pin tuple, not proof of provisioning or release readiness.
/// Provisioning/session validation authenticates this binding before use; INFO
/// alone must never create a trusted pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceIdentityBinding {
    device_id: DeviceId,
    identity_verification_key: [u8; 32],
    provisioning_evidence_digest: [u8; 32],
}

impl DeviceIdentityBinding {
    pub const fn new(
        device_id: DeviceId,
        identity_verification_key: [u8; 32],
        provisioning_evidence_digest: [u8; 32],
    ) -> Self {
        Self {
            device_id,
            identity_verification_key,
            provisioning_evidence_digest,
        }
    }
    pub const fn device_id(&self) -> &DeviceId {
        &self.device_id
    }
    pub const fn identity_verification_key(&self) -> &[u8; 32] {
        &self.identity_verification_key
    }
    pub const fn provisioning_evidence_digest(&self) -> &[u8; 32] {
        &self.provisioning_evidence_digest
    }
}

macro_rules! checked_counter {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(transparent)]
        pub struct $name(u64);
        impl $name {
            pub const fn new(value: u64) -> Self {
                Self(value)
            }
            pub const fn get(self) -> u64 {
                self.0
            }
            pub fn checked_add(self, amount: u64) -> Result<Self, TypeError> {
                self.0
                    .checked_add(amount)
                    .map(Self)
                    .ok_or(TypeError::Overflow)
            }
            pub fn checked_increment(self) -> Result<Self, TypeError> {
                self.checked_add(1)
            }
        }
    };
}

checked_counter!(Revision);
checked_counter!(GenerationNumber);
checked_counter!(ManagementSequence);
checked_counter!(CredentialEpoch);
checked_counter!(CertificateCounter);
checked_counter!(AbsolutePeriod);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelativePeriod(u8);

impl RelativePeriod {
    pub fn new(value: u64) -> Result<Self, TypeError> {
        if value >= u64::from(crate::KES_PERIODS) {
            return Err(TypeError::RelativePeriodOutOfRange);
        }
        Ok(Self(value as u8))
    }
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// A flash/RAM location only. It has no conversion to PoolId and is never an
/// externally stable pool identity or descriptor field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HardwareSlot(u8);

impl HardwareSlot {
    pub fn new(value: usize) -> Result<Self, TypeError> {
        if value >= crate::MAX_POOLS {
            return Err(TypeError::SlotOutOfRange);
        }
        Ok(Self(value as u8))
    }
    pub const fn get(self) -> usize {
        self.0 as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KesLifetime(u8);

impl KesLifetime {
    pub fn new(value: u64) -> Result<Self, TypeError> {
        if !(1..=u64::from(crate::KES_PERIODS)).contains(&value) {
            return Err(TypeError::InvalidKesLifetime);
        }
        Ok(Self(value as u8))
    }
    pub const fn get(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkBinding {
    network_magic: u32,
    genesis_hash: EnrolledGenesisHash,
    slots_per_kes_period: NonZeroU64,
    max_kes_evolutions: KesLifetime,
}

fn network_limits(slots: u64, lifetime: u64) -> Result<(NonZeroU64, KesLifetime), TypeError> {
    Ok((
        NonZeroU64::new(slots).ok_or(TypeError::ZeroSlotsPerKesPeriod)?,
        KesLifetime::new(lifetime)?,
    ))
}

impl NetworkBinding {
    /// Enrollment validates the actual genesis structure/parameters separately;
    /// this boundary hashes exact bytes only after checking numeric limits.
    pub fn from_genesis_bytes(
        network_magic: u32,
        genesis: &[u8],
        slots: u64,
        lifetime: u64,
    ) -> Result<Self, TypeError> {
        let (slots_per_kes_period, max_kes_evolutions) = network_limits(slots, lifetime)?;
        Ok(Self {
            network_magic,
            genesis_hash: EnrolledGenesisHash::from_exact_bytes(genesis),
            slots_per_kes_period,
            max_kes_evolutions,
        })
    }

    /// Decode an already enrolled digest from authenticated storage/wire data;
    /// the distinct digest type prevents implicit node-genesis-hash substitution.
    pub fn from_enrolled_digest(
        network_magic: u32,
        genesis_hash: EnrolledGenesisHash,
        slots: u64,
        lifetime: u64,
    ) -> Result<Self, TypeError> {
        let (slots_per_kes_period, max_kes_evolutions) = network_limits(slots, lifetime)?;
        Ok(Self {
            network_magic,
            genesis_hash,
            slots_per_kes_period,
            max_kes_evolutions,
        })
    }
    pub const fn network_magic(&self) -> u32 {
        self.network_magic
    }
    pub const fn genesis_hash(&self) -> &EnrolledGenesisHash {
        &self.genesis_hash
    }
    pub const fn slots_per_kes_period(&self) -> u64 {
        self.slots_per_kes_period.get()
    }
    pub const fn max_kes_evolutions(&self) -> u8 {
        self.max_kes_evolutions.get()
    }
}
