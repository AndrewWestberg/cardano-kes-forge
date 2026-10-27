//! Device-wide public state and bounded directory candidates. None of these
//! records authenticates a snapshot, management signature or hardware reading.
//! The journal/authorization owners must establish those trust boundaries before
//! supplying records here. Enrollment changes RAM only, never a durable ACK.
use super::pool::{ManagementReplay, ManagementResult, PoolRegistration};
use super::{Actor, DeviceMode, Health, StateError, UsePolicy, require_management};
use crate::types::{
    CertificateCounter, CredentialEpoch, DeviceIdentityBinding, GenerationNumber, HardwareSlot,
    IncarnationId, ManagementSequence, PoolId, Revision,
};
use zeroize::Zeroizing;

mod codec;

/// Live registrations and retained identities share this bound. Exhaustion must
/// fail closed; neither enrollment nor snapshot loading evicts old history.
pub const DIRECTORY_IDENTITY_CAPACITY: usize = crate::MAX_POOLS;
pub const DEVICE_HOT_STATE_LIMIT: usize = 4096;
pub const DIRECTORY_WORKSPACE_LIMIT: usize = 8192;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceConfig {
    pub identity: DeviceIdentityBinding,
    pub silicon_revision: u8,
    pub firmware_digest: [u8; 32],
    pub security_version: u64,
    pub hardware_policy_digest: [u8; 32],
    pub mode: DeviceMode,
    pub health: Health,
    pub management_root_public_key: [u8; 32],
    pub management_transport_public_key: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectoryEntry {
    slot: HardwareSlot,
    pool_id: PoolId,
    incarnation: IncarnationId,
}

impl DirectoryEntry {
    /// Decode public directory metadata, not proof of authenticated persistence.
    pub const fn new(slot: HardwareSlot, pool_id: PoolId, incarnation: IncarnationId) -> Self {
        Self {
            slot,
            pool_id,
            incarnation,
        }
    }
    pub const fn slot(&self) -> HardwareSlot {
        self.slot
    }
    pub const fn pool_id(&self) -> PoolId {
        self.pool_id
    }
    pub const fn incarnation(&self) -> IncarnationId {
        self.incarnation
    }
}

/// Complete cold deletion history. It is retained in the authenticated directory
/// snapshot, not replicated in every resident pool record. Replay metadata is
/// preserved in addition to the required monotonic high-water marks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolTombstone {
    pub pool_id: PoolId,
    pub last_incarnation: IncarnationId,
    /// Last credential epoch, absent only for authenticated pre-v5 snapshots.
    pub credential_epoch: Option<CredentialEpoch>,
    pub management_sequence: ManagementSequence,
    pub certificate_high_water: Option<CertificateCounter>,
    pub generation_high_water: GenerationNumber,
    pub deletion_revision: Revision,
    pub management_replay: ManagementReplay,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeletionIntent {
    pub slot: HardwareSlot,
    pub expected_pool_revision: Revision,
    pub pool_cleanup_revision: Revision,
    pub tombstone: PoolTombstone,
}

/// Authenticated authority to initialize exactly one previously erased, non-live
/// slot. Retained history stays in the directory until publication completes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnrollmentIntent {
    pub slot: HardwareSlot,
    pub enrollment: super::pool::Enrollment,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceRetirement {
    pub revision: Revision,
    pub management_replay: ManagementReplay,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceCredential {
    pub public_key: [u8; 32],
    pub epoch: CredentialEpoch,
    pub revoked: bool,
    pub management_replay: Option<ManagementReplay>,
}

impl DeviceCredential {
    pub const fn new(public_key: [u8; 32]) -> Self {
        Self {
            public_key,
            epoch: CredentialEpoch::new(0),
            revoked: false,
            management_replay: None,
        }
    }
}

/// A single cold directory candidate/load workspace. Do not keep one copy per
/// pool or retain it alongside a second journal workspace: its entire size is
/// charged to the shared 8192-byte journal candidate/authentication allocation.
/// Fields are decoded metadata, not authenticated by construction. The external
/// authenticated snapshot owner must validate AEAD, parent/commit/cleanup state
/// and device identity before passing this record to Device.
#[derive(Debug, PartialEq, Eq)]
pub struct DirectorySnapshot {
    pub config: DeviceConfig,
    pub revision: Revision,
    pub retirement: Option<DeviceRetirement>,
    pub credential: DeviceCredential,
    pub pending_deletion: Option<DeletionIntent>,
    pub pending_enrollment: Option<EnrollmentIntent>,
    pub live: [Option<DirectoryEntry>; crate::MAX_POOLS],
    pub tombstones: [Option<PoolTombstone>; DIRECTORY_IDENTITY_CAPACITY],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DirectoryRecord {
    Live(DirectoryEntry),
    Retained {
        pool: PoolId,
        incarnation: IncarnationId,
    },
}

impl DirectoryRecord {
    fn pool_id(self) -> PoolId {
        match self {
            Self::Live(entry) => entry.pool_id(),
            Self::Retained { pool, .. } => pool,
        }
    }
}

/// Compact public hot directory. Cold replay/tombstone bodies stay in the shared
/// authenticated snapshot workspace; only their non-reusable identities remain
/// hot. No KES secret, public tree, request body or cold certificate is resident.
#[derive(Debug, PartialEq, Eq)]
pub struct Device {
    config: DeviceConfig,
    directory_revision: Revision,
    credential: DeviceCredential,
    pending_deletion: bool,
    retirement: Option<DeviceRetirement>,
    directory: [Option<DirectoryRecord>; DIRECTORY_IDENTITY_CAPACITY],
}

impl Device {
    pub const fn new(config: DeviceConfig) -> Self {
        Self {
            config,
            directory_revision: Revision::new(0),
            retirement: None,
            credential: DeviceCredential::new(config.management_transport_public_key),
            pending_deletion: false,
            directory: [None; DIRECTORY_IDENTITY_CAPACITY],
        }
    }

    /// Restore an externally authenticated directory, checking its structural
    /// invariants without discarding or silently repairing any retained history.
    /// This method does NOT authenticate the supplied bytes or authorize retire.
    pub fn from_authenticated_snapshot(snapshot: &DirectorySnapshot) -> Result<Self, StateError> {
        let mut device = Self::new(snapshot.config);
        device.directory_revision = snapshot.revision;
        if let Some(retirement) = snapshot.retirement
            && retirement.revision > snapshot.revision
        {
            return Err(StateError::RevisionConflict);
        }
        match snapshot.credential.management_replay {
            Some(replay) => {
                let ManagementResult::Committed { revision } = replay.result;
                if revision > snapshot.revision {
                    return Err(StateError::RevisionConflict);
                }
            }
            None => {
                if snapshot.credential.epoch.get() != 0
                    || snapshot.credential.revoked
                    || snapshot.credential.public_key
                        != snapshot.config.management_transport_public_key
                {
                    return Err(StateError::InvalidObject);
                }
            }
        }
        if let Some(intent) = snapshot.pending_enrollment {
            let pool = PoolRegistration::new(Actor::Management, intent.enrollment)?;
            if snapshot.pending_deletion.is_some()
                || snapshot.retirement.is_some()
                || snapshot
                    .live
                    .iter()
                    .flatten()
                    .any(|entry| entry.slot() == intent.slot || entry.pool_id() == pool.pool_id())
            {
                return Err(StateError::InvalidObject);
            }
            if let Some(tombstone) = snapshot
                .tombstones
                .iter()
                .flatten()
                .find(|t| t.pool_id == pool.pool_id())
            {
                if tombstone.last_incarnation == pool.incarnation()
                    || tombstone.management_sequence.checked_increment().ok()
                        != Some(pool.management_sequence())
                {
                    return Err(StateError::InvalidObject);
                }
            } else if pool.management_sequence() != ManagementSequence::new(1)
                || snapshot.live.iter().flatten().count()
                    + snapshot.tombstones.iter().flatten().count()
                    >= DIRECTORY_IDENTITY_CAPACITY
            {
                return Err(StateError::InvalidObject);
            }
            device.pending_deletion = true;
        }
        if let Some(intent) = snapshot.pending_deletion {
            let expected_deletion_revision = snapshot
                .revision
                .checked_increment()
                .map_err(|_| StateError::CounterOverflow)?;
            let expected_cleanup_revision = intent
                .expected_pool_revision
                .checked_increment()
                .map_err(|_| StateError::CounterOverflow)?;
            let live_matches = snapshot.live.iter().flatten().any(|entry| {
                entry.slot() == intent.slot
                    && entry.pool_id() == intent.tombstone.pool_id
                    && entry.incarnation() == intent.tombstone.last_incarnation
            });
            if intent.tombstone.deletion_revision != expected_deletion_revision
                || intent.pool_cleanup_revision != expected_cleanup_revision
                || intent.tombstone.management_sequence
                    != intent.tombstone.management_replay.sequence
                || !live_matches
                || snapshot
                    .tombstones
                    .iter()
                    .flatten()
                    .any(|tombstone| tombstone.pool_id == intent.tombstone.pool_id)
            {
                return Err(StateError::InvalidObject);
            }
            device.pending_deletion = true;
        }
        device.credential = snapshot.credential;
        device.retirement = snapshot.retirement;
        for entry in snapshot.live.iter().flatten() {
            if device.directory.iter().flatten().any(|record| {
                record.pool_id() == entry.pool_id()
                    || matches!(record, DirectoryRecord::Live(other) if other.slot() == entry.slot())
            }) {
                return Err(StateError::DuplicatePool);
            }
            device.insert_record(DirectoryRecord::Live(*entry))?;
        }
        for tombstone in snapshot.tombstones.iter().flatten() {
            if tombstone.deletion_revision > snapshot.revision {
                return Err(StateError::RevisionConflict);
            }
            if tombstone.management_sequence != tombstone.management_replay.sequence {
                return Err(StateError::InvalidObject);
            }
            if device
                .directory
                .iter()
                .flatten()
                .any(|record| record.pool_id() == tombstone.pool_id)
            {
                return Err(StateError::DuplicatePool);
            }
            device.insert_record(DirectoryRecord::Retained {
                pool: tombstone.pool_id,
                incarnation: tombstone.last_incarnation,
            })?;
        }
        Ok(device)
    }

    fn insert_record(&mut self, record: DirectoryRecord) -> Result<(), StateError> {
        let vacant = self
            .directory
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or(StateError::DirectoryFull)?;
        *vacant = Some(record);
        Ok(())
    }

    pub const fn config(&self) -> &DeviceConfig {
        &self.config
    }
    pub const fn identity(&self) -> &DeviceIdentityBinding {
        &self.config.identity
    }
    pub const fn directory_revision(&self) -> Revision {
        self.directory_revision
    }
    pub const fn retirement(&self) -> Option<&DeviceRetirement> {
        self.retirement.as_ref()
    }
    pub const fn credential(&self) -> &DeviceCredential {
        &self.credential
    }
    pub fn pool_count(&self) -> usize {
        self.directory
            .iter()
            .flatten()
            .filter(|record| matches!(record, DirectoryRecord::Live(_)))
            .count()
    }
    pub fn retained_identity_count(&self) -> usize {
        self.directory.iter().flatten().count()
    }
    pub fn find(&self, pool: PoolId) -> Option<&DirectoryEntry> {
        self.directory
            .iter()
            .flatten()
            .find_map(|record| match record {
                DirectoryRecord::Live(entry) if entry.pool_id() == pool => Some(entry),
                _ => None,
            })
    }

    pub fn enroll(
        &mut self,
        actor: Actor,
        pool: &PoolRegistration,
        expected_directory_revision: Revision,
    ) -> Result<HardwareSlot, StateError> {
        require_management(actor)?;
        self.ensure_available()?;
        if self.pending_deletion {
            return Err(StateError::InvalidLifecycle);
        }
        if expected_directory_revision != self.directory_revision {
            return Err(StateError::RevisionConflict);
        }
        let pool_id = PoolId::from_cold_verification_key(pool.cold_verification_key());
        if pool_id != pool.pool_id() {
            return Err(StateError::InvalidPoolId);
        }
        for record in self.directory.iter().flatten() {
            match record {
                DirectoryRecord::Live(entry) if entry.pool_id() == pool_id => {
                    return Err(StateError::DuplicatePool);
                }
                DirectoryRecord::Retained {
                    pool: retained,
                    incarnation,
                } if *retained == pool_id => {
                    if *incarnation == pool.incarnation() {
                        return Err(StateError::IncarnationConflict);
                    }
                    // Re-enrollment needs the later management transaction to
                    // merge cold high-water/replay state; never reset it here.
                    return Err(StateError::InvalidLifecycle);
                }
                _ => {}
            }
        }
        if self.pool_count() == crate::MAX_POOLS {
            return Err(StateError::Capacity);
        }
        let vacant = self
            .directory
            .iter()
            .position(Option::is_none)
            .ok_or(StateError::DirectoryFull)?;
        let slot_index = (0..crate::MAX_POOLS)
            .find(|index| {
                !self.directory.iter().flatten().any(|record| {
                matches!(record, DirectoryRecord::Live(entry) if entry.slot().get() == *index)
            })
            })
            .ok_or(StateError::Capacity)?;
        let slot = HardwareSlot::new(slot_index).map_err(|_| StateError::Capacity)?;
        let next_revision = self
            .directory_revision
            .checked_increment()
            .map_err(|_| StateError::CounterOverflow)?;
        self.directory[vacant] = Some(DirectoryRecord::Live(DirectoryEntry::new(
            slot,
            pool_id,
            pool.incarnation(),
        )));
        self.directory_revision = next_revision;
        Ok(slot)
    }

    fn ensure_available(&self) -> Result<(), StateError> {
        if self.retirement.is_some() {
            return Err(StateError::Retired);
        }
        match self.config.health {
            Health::Healthy => Ok(()),
            Health::Damaged => Err(StateError::Damaged),
            Health::Unavailable => Err(StateError::Unavailable),
        }
    }

    pub fn ensure_operational(
        &self,
        policy: UsePolicy,
        readiness: Option<&VerifiedReleaseReadiness>,
    ) -> Result<(), StateError> {
        self.ensure_available()?;
        match (self.config.mode, policy) {
            (DeviceMode::Development, UsePolicy::Production) => {
                Err(StateError::DevelopmentOptInRequired)
            }
            (DeviceMode::Development, UsePolicy::IsolatedDevelopment) => {
                // Approved A2 is disposable, isolated development only. A3 and
                // unidentified earlier silicon have no approved exception.
                if self.config.silicon_revision == 2 || self.config.silicon_revision >= 4 {
                    Ok(())
                } else {
                    Err(StateError::SecurityNotReady)
                }
            }
            (DeviceMode::Release, _) => {
                if self.config.silicon_revision < 4 {
                    return Err(StateError::SecurityNotReady);
                }
                let proof = readiness.ok_or(StateError::SecurityNotReady)?;
                if proof.binding.identity != self.config.identity
                    || proof.binding.silicon_revision != self.config.silicon_revision
                    || proof.binding.firmware_digest != self.config.firmware_digest
                    || proof.binding.security_version != self.config.security_version
                    || proof.binding.hardware_policy_digest != self.config.hardware_policy_digest
                    || proof.binding.management_root_public_key
                        != self.config.management_root_public_key
                {
                    return Err(StateError::SecurityNotReady);
                }
                Ok(())
            }
        }
    }
}

/// Complete immutable context to which the trusted hardware verifier must bind
/// its result. These public bytes alone are not a proof or readiness grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReleaseReadinessBinding {
    pub identity: DeviceIdentityBinding,
    pub silicon_revision: u8,
    pub firmware_digest: [u8; 32],
    pub security_version: u64,
    pub hardware_policy_digest: [u8; 32],
    pub management_root_public_key: [u8; 32],
    pub measured_security_state_digest: [u8; 32],
}

/// Sealed successful-verification result. There is intentionally no constructor,
/// deserializer, boolean conversion or mock verifier in the state layer. The
/// future trusted T018/T041 hardware verifier must produce this only after all
/// required policy/readback checks; until then production always lacks proof.
pub struct VerifiedReleaseReadiness {
    binding: ReleaseReadinessBinding,
}

impl VerifiedReleaseReadiness {
    pub const fn binding(&self) -> &ReleaseReadinessBinding {
        &self.binding
    }
}

/// Fixed OTP-derived material, separate from all public directory/state records.
/// No root is retained here. The trusted entropy/OTP owner derives independent
/// domain-separated keys, clears root/intermediate RAM and closes OTP read access.
/// Zeroizing owns each supplied buffer; there are no RNG or default-key paths,
/// Debug/Clone implementations, or public serialization traits.
pub struct DeviceSecrets {
    storage_key: Zeroizing<[u8; 32]>,
    identity_seed: Zeroizing<[u8; 32]>,
    session_key: Zeroizing<[u8; 32]>,
}

impl DeviceSecrets {
    /// Consume real domain-separated OTP derivations. This is an internal trust
    /// boundary, not a wire import/provisioning API or proof of source entropy.
    pub fn from_otp_derived_material(
        storage_key: Zeroizing<[u8; 32]>,
        identity_seed: Zeroizing<[u8; 32]>,
        session_key: Zeroizing<[u8; 32]>,
    ) -> Self {
        Self {
            storage_key,
            identity_seed,
            session_key,
        }
    }
    pub fn with_storage_key<R>(&self, use_key: impl FnOnce(&[u8; 32]) -> R) -> R {
        use_key(&self.storage_key)
    }
    pub fn with_identity_seed<R>(&self, use_seed: impl FnOnce(&[u8; 32]) -> R) -> R {
        use_seed(&self.identity_seed)
    }
    pub fn with_session_key<R>(&self, use_key: impl FnOnce(&[u8; 32]) -> R) -> R {
        use_key(&self.session_key)
    }
}

// Structural bounds only: actual firmware linkage/stack high-water accounting
// remains the physical R4 qualification owner's responsibility.
const _: () = assert!(core::mem::size_of::<Device>() <= DEVICE_HOT_STATE_LIMIT);
const _: () = assert!(core::mem::size_of::<DirectorySnapshot>() <= DIRECTORY_WORKSPACE_LIMIT);
const _: () = assert!(core::mem::size_of::<DeviceSecrets>() == 96);
