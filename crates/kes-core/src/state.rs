//! Shared state policy and persisted/public record types. This layer consumes
//! already-authenticated scope metadata; Actor is not a wire authority proof.
//! Mutation here prepares a RAM candidate, never a durable ACK or readiness
//! measurement. Journal/session/firmware owners must establish those boundaries.
mod device;
mod object;
mod pool;

pub use device::{
    DEVICE_HOT_STATE_LIMIT, DIRECTORY_IDENTITY_CAPACITY, DIRECTORY_WORKSPACE_LIMIT, DeletionIntent,
    Device, DeviceConfig, DeviceCredential, DeviceRetirement, DeviceSecrets, DirectoryEntry,
    DirectorySnapshot, PoolTombstone, ReleaseReadinessBinding, VerifiedReleaseReadiness,
};
pub use object::{
    MAX_ENCRYPTED_BACKUP_BYTES, MAX_PUBLIC_OBJECT_BYTES, PUBLIC_OBJECT_HEADER_BYTES,
    PUBLIC_OBJECT_VERSION, PublicObject, PublicObjectRef,
};
pub use pool::{
    ActivationIntent, CertificationOutcome, Enrollment, GenerationPolicy, GenerationSecret,
    GenerationSpec, KESGeneration, ManagementReplay, ManagementResult, PoolRegistration,
};
pub(crate) use pool::{
    ActiveEvolutionTransition, FirstActivationTransition, ReplacementActivationTransition,
    ScheduleActivationTransition,
};

use crate::certificate::CertificateError;
use crate::crypto::CryptoError;
use crate::types::{IncarnationId, PoolId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Actor {
    Management,
    Pool {
        pool: PoolId,
        incarnation: IncarnationId,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceMode {
    Development,
    Release,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Health {
    Healthy,
    Damaged,
    Unavailable,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsePolicy {
    Production,
    IsolatedDevelopment,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Lifecycle {
    Staged,
    CertifiedStaged,
    Active,
    CurrentExpired,
    Retired,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateError {
    Capacity,
    DirectoryFull,
    Unauthorized,
    WrongPool,
    WrongIncarnation,
    WrongDevice,
    DuplicatePool,
    IncarnationConflict,
    Retired,
    InvalidPoolId,
    InvalidRecipient,
    InvalidObject,
    UnsupportedVersion,
    TooLarge,
    GenerationConflict,
    StagedConflict,
    StaleGeneration,
    RevisionConflict,
    PolicyChanged,
    CounterOverflow,
    Damaged,
    Unavailable,
    SecurityNotReady,
    DevelopmentOptInRequired,
    InvalidLifecycle,
    InvalidSecret,
    CertificateConflict,
    Certificate(CertificateError),
    Crypto(CryptoError),
}
impl core::fmt::Display for StateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Capacity => "live pool capacity reached",
            Self::DirectoryFull => "retained directory history full",
            Self::DuplicatePool => "pool identity already registered",
            Self::IncarnationConflict => "retained incarnation cannot be reused",
            Self::Retired => "device is durably retired",
            Self::Unauthorized => "scope is not authorized",
            Self::WrongPool => "pool scope mismatch",
            Self::WrongIncarnation => "incarnation scope mismatch",
            Self::WrongDevice => "device mismatch",
            Self::InvalidPoolId => "cold-key pool identity mismatch",
            Self::InvalidRecipient => "recipient identity invalid",
            Self::InvalidObject => "public object invalid",
            Self::UnsupportedVersion => "state/object version unsupported",
            Self::TooLarge => "state/object bound exceeded",
            Self::GenerationConflict => "generation identity conflict",
            Self::StagedConflict => "staged generation already exists",
            Self::StaleGeneration => "generation number is stale",
            Self::RevisionConflict => "state revision conflict",
            Self::PolicyChanged => "captured generation policy changed",
            Self::CounterOverflow => "state counter exhausted",
            Self::Damaged => "state quarantined",
            Self::Unavailable => "device state unavailable",
            Self::SecurityNotReady => "verified release readiness absent",
            Self::DevelopmentOptInRequired => "isolated development requires explicit opt-in",
            Self::InvalidLifecycle => "invalid lifecycle transition",
            Self::InvalidSecret => "secret/state binding invalid",
            Self::CertificateConflict => "certificate binding conflicts",
            Self::Certificate(error) => return core::fmt::Display::fmt(error, f),
            Self::Crypto(_) => "cryptographic state rejected",
        })
    }
}
impl core::error::Error for StateError {}
impl From<CryptoError> for StateError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}
impl From<CertificateError> for StateError {
    fn from(error: CertificateError) -> Self {
        Self::Certificate(error)
    }
}

pub(crate) fn require_management(actor: Actor) -> Result<(), StateError> {
    match actor {
        Actor::Management => Ok(()),
        Actor::Pool { .. } => Err(StateError::Unauthorized),
    }
}
pub(crate) fn require_pool(
    actor: Actor,
    pool: PoolId,
    incarnation: IncarnationId,
) -> Result<(), StateError> {
    match actor {
        Actor::Management => Err(StateError::Unauthorized),
        Actor::Pool {
            pool: actor_pool,
            incarnation: actor_incarnation,
        } => {
            if actor_pool != pool {
                return Err(StateError::WrongPool);
            }
            if actor_incarnation != incarnation {
                return Err(StateError::WrongIncarnation);
            }
            Ok(())
        }
    }
}
