//! Authenticated inactive-slot upload, not a release installation service.
//!
//! The independent verifier must implement the approved manifest encoding,
//! signature transcript and ROM trust policy; none is selected here because the
//! v1 contracts do not specify them. There is deliberately no default verifier,
//! flash/OTP adapter, trial-boot operation or installed/success result. `Verified`
//! means only that the inactive candidate passed readback and executable checks.
//! Trial, two-candidate copying and monotonic OTP finalization require a reviewed
//! vendor recovery protocol before they can be implemented.

use sha2::{Digest, Sha256};

pub const MAX_CHUNK: usize = 4096;
pub const STORAGE_SCHEMA: u64 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Manifest {
    pub version: u64,
    pub firmware_digest: [u8; 32],
    pub partition_manifest_digest: [u8; 32],
    pub storage_schema: u64,
    pub image_length: u64,
    pub security_version: u64,
    pub hardware_policy_digest: [u8; 32],
    pub signature: [u8; 64],
}

/// Trusted, current hardware policy, never populated from an upload request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Policy {
    pub device: [u8; 16],
    pub partition_manifest_digest: [u8; 32],
    pub hardware_policy_digest: [u8; 32],
    pub current_security_version: u64,
    pub rollback_floor: u64,
    /// Highest version supportable without exhausting the approved OTP policy.
    pub maximum_security_version: u64,
    pub slot_capacity: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rejection {
    UnavailableTrust,
    Unauthorized,
    InvalidSignature,
    DevelopmentImage,
    InvalidImage,
    HardwarePolicy,
}

/// Supplied by the secure runtime, independently of the management transport.
/// No caller-selected key or mutable release/development label establishes trust.
pub trait Trust {
    fn policy(&mut self) -> Result<Policy, Rejection>;
    /// Verify the distinct firmware authority against provisioned ROM trust,
    /// including exact approved encoding/transcript, and return the digest of
    /// that signed manifest. Must reject unsigned and development-authorized
    /// manifests; a management signature alone is insufficient.
    fn verify_manifest(&mut self, manifest: &Manifest) -> Result<[u8; 32], Rejection>;
    /// Check the replay-safe, durably committed FIRMWARE_AUTHORIZE result. It
    /// must bind device, manifest (all fields), digest and expected revision to
    /// the next offline management sequence, not just the transport credential.
    fn verify_management(
        &mut self,
        device: [u8; 16],
        manifest: &Manifest,
        digest: [u8; 32],
        expected_revision: u64,
    ) -> Result<(), Rejection>;
    /// Independently parse/verify the uploaded executable's ROM signature,
    /// release provenance, partition metadata, schema and security version.
    /// Implementations may read only through this fixed inactive-slot view.
    fn verify_executable<S: Storage>(
        &mut self,
        manifest: &Manifest,
        slot: &mut S,
    ) -> Result<(), Rejection>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Durable before erase; recovery may safely repeat inactive-slot erase.
    Preparing,
    Uploading,
    /// Durable before program; recovery erases/restarts instead of attempting
    /// an unqualified repeat program of a partially programmed NOR page.
    Writing,
    Verified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Intent {
    pub device: [u8; 16],
    pub manifest: Manifest,
    pub manifest_digest: [u8; 32],
    pub revision: u64,
    pub offset: u64,
    pub phase: Phase,
}

/// Required secure backend, deliberately not implemented by FittedFlash: its
/// existing adapter exposes journals only, not an approved update partition.
///
/// All methods address the one pinned inactive slot; no absolute address API.
/// Before any erase/program, `check_preserved_image` must verify an admissible
/// active image and ensure this view cannot modify it or switch boot selection.
/// `load` authenticates intent/device binding and rejects stale/ambiguous state.
/// `save` must durably commit and read-verify an authenticated successor using a
/// qualified journal, preserving old/new authority under interruption. On save
/// failure the caller must reopen/reconcile, never acknowledge success.
/// Program must honor fitted page rules (including safe final-page padding),
/// erase must read-verify blankness, and reads must invalidate stale XIP caches.
/// No implementation may mutate OTP, boot selectors, active firmware or pools.
pub trait Storage {
    type Error;
    fn load(&mut self) -> Result<Option<Intent>, Self::Error>;
    fn save(&mut self, intent: &Intent) -> Result<(), Self::Error>;
    fn check_preserved_image(&mut self) -> Result<(), Self::Error>;
    fn capacity(&self) -> u64;
    fn erase_inactive(&mut self) -> Result<(), Self::Error>;
    fn program(&mut self, offset: u64, bytes: &[u8]) -> Result<(), Self::Error>;
    fn read(&mut self, offset: u64, bytes: &mut [u8]) -> Result<(), Self::Error>;
}

#[derive(Debug, Eq, PartialEq)]
pub enum Error<E> {
    Trust(Rejection),
    Storage(E),
    Manifest,
    Schema,
    Partition,
    Downgrade,
    RollbackCapacity,
    Bounds,
    Conflict,
    Revision,
    Sequence,
    Readback,
    Digest,
    RecoveryRequired,
}

/// Owns the secure storage view for the duration of a request sequence. After
/// any backend error the handle becomes unusable; `open` reconciles persistence.
pub struct Update<S, T> {
    storage: S,
    trust: T,
    intent: Option<Intent>,
    healthy: bool,
}

impl<S: Storage, T: Trust> Update<S, T> {
    pub fn open(storage: S, trust: T) -> Result<Self, Error<S::Error>> {
        let mut this = Self {
            storage,
            trust,
            intent: None,
            healthy: true,
        };
        this.intent = this.storage.load().map_err(Error::Storage)?;
        if let Some(intent) = this.intent {
            this.validate(&intent.manifest, intent.manifest_digest, intent.revision)?;
            if intent.device != this.trust.policy().map_err(Error::Trust)?.device
                || intent.offset > intent.manifest.image_length
                || (intent.phase == Phase::Preparing && intent.offset != 0)
                || (intent.phase == Phase::Verified
                    && intent.offset != intent.manifest.image_length)
                || (intent.offset != intent.manifest.image_length
                    && !intent.offset.is_multiple_of(256))
            {
                return Err(Error::Conflict);
            }
            this.storage
                .check_preserved_image()
                .map_err(Error::Storage)?;
            if matches!(intent.phase, Phase::Preparing | Phase::Writing) {
                this.restart(intent)?;
            } else {
                if intent.phase == Phase::Verified {
                    this.check_image()?;
                }
            }
        }
        Ok(this)
    }
    pub fn status(&self) -> Result<Option<Intent>, Error<S::Error>> {
        if !self.healthy {
            return Err(Error::RecoveryRequired);
        }
        Ok(self.intent)
    }

    fn validate(
        &mut self,
        m: &Manifest,
        digest: [u8; 32],
        revision: u64,
    ) -> Result<(), Error<S::Error>> {
        let policy = self.trust.policy().map_err(Error::Trust)?;
        if m.version != 1 || m.image_length == 0 {
            return Err(Error::Manifest);
        }
        if m.storage_schema != STORAGE_SCHEMA {
            return Err(Error::Schema);
        }
        if m.partition_manifest_digest != policy.partition_manifest_digest {
            return Err(Error::Partition);
        }
        if m.hardware_policy_digest != policy.hardware_policy_digest {
            return Err(Error::Trust(Rejection::HardwarePolicy));
        }
        if m.security_version < policy.current_security_version
            || m.security_version < policy.rollback_floor
        {
            return Err(Error::Downgrade);
        }
        if m.security_version > policy.maximum_security_version {
            return Err(Error::RollbackCapacity);
        }
        if policy.slot_capacity == 0
            || policy.slot_capacity != self.storage.capacity()
            || m.image_length > policy.slot_capacity
        {
            return Err(Error::Bounds);
        }
        if self.trust.verify_manifest(m).map_err(Error::Trust)? != digest {
            return Err(Error::Digest);
        }
        self.trust
            .verify_management(policy.device, m, digest, revision)
            .map_err(Error::Trust)
    }

    pub fn begin(
        &mut self,
        manifest: Manifest,
        digest: [u8; 32],
        expected_revision: u64,
    ) -> Result<Intent, Error<S::Error>> {
        self.status()?;
        self.validate(&manifest, digest, expected_revision)?;
        if let Some(intent) = self.intent {
            if intent.manifest == manifest
                && intent.manifest_digest == digest
                && intent.revision == expected_revision
            {
                return Ok(intent);
            }
            return Err(Error::Conflict);
        }
        let intent = Intent {
            device: self.trust.policy().map_err(Error::Trust)?.device,
            manifest,
            manifest_digest: digest,
            revision: expected_revision,
            offset: 0,
            phase: Phase::Preparing,
        };
        self.restart(intent)?;
        self.status()?.ok_or(Error::Conflict)
    }

    fn save(&mut self, intent: Intent) -> Result<(), Error<S::Error>> {
        self.healthy = false;
        self.storage.save(&intent).map_err(Error::Storage)?;
        self.intent = Some(intent);
        self.healthy = true;
        Ok(())
    }

    fn restart(&mut self, mut intent: Intent) -> Result<(), Error<S::Error>> {
        intent.phase = Phase::Preparing;
        intent.offset = 0;
        self.save(intent)?;
        self.healthy = false;
        self.storage
            .check_preserved_image()
            .map_err(Error::Storage)?;
        self.storage.erase_inactive().map_err(Error::Storage)?;
        intent.phase = Phase::Uploading;
        self.save(intent)
    }

    fn matching(&self, digest: [u8; 32], revision: u64) -> Result<Intent, Error<S::Error>> {
        let intent = self.status()?.ok_or(Error::Sequence)?;
        if intent.manifest_digest != digest {
            return Err(Error::Conflict);
        }
        if intent.revision != revision {
            return Err(Error::Revision);
        }
        Ok(intent)
    }

    pub fn chunk(
        &mut self,
        digest: [u8; 32],
        offset: u64,
        bytes: &[u8],
        revision: u64,
    ) -> Result<Intent, Error<S::Error>> {
        let mut intent = self.matching(digest, revision)?;
        if intent.phase != Phase::Uploading || offset != intent.offset {
            return Err(Error::Sequence);
        }
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or(Error::Bounds)?;
        if bytes.is_empty() || bytes.len() > MAX_CHUNK || end > intent.manifest.image_length {
            return Err(Error::Bounds);
        }
        // Require full pages except the final image fragment. This prevents the
        // next request from reprogramming a previously touched physical page.
        if !offset.is_multiple_of(256)
            || (end != intent.manifest.image_length && !bytes.len().is_multiple_of(256))
        {
            return Err(Error::Bounds);
        }
        intent.phase = Phase::Writing;
        self.save(intent)?;
        self.healthy = false;
        self.storage
            .check_preserved_image()
            .map_err(Error::Storage)?;
        self.storage
            .program(offset, bytes)
            .map_err(Error::Storage)?;
        let mut readback = [0u8; MAX_CHUNK];
        self.storage
            .read(offset, &mut readback[..bytes.len()])
            .map_err(Error::Storage)?;
        if readback[..bytes.len()] != *bytes {
            return Err(Error::Readback);
        }
        intent.offset = end;
        intent.phase = Phase::Uploading;
        self.save(intent)?;
        Ok(intent)
    }

    fn check_image(&mut self) -> Result<(), Error<S::Error>> {
        let intent = self.intent.ok_or(Error::Sequence)?;
        let mut hash = Sha256::new();
        let mut bytes = [0u8; MAX_CHUNK];
        let mut offset = 0;
        while offset < intent.manifest.image_length {
            let size =
                core::cmp::min(intent.manifest.image_length - offset, MAX_CHUNK as u64) as usize;
            self.storage
                .read(offset, &mut bytes[..size])
                .map_err(Error::Storage)?;
            hash.update(&bytes[..size]);
            offset += size as u64;
        }
        let actual: [u8; 32] = hash.finalize().into();
        if actual != intent.manifest.firmware_digest {
            return Err(Error::Digest);
        }
        self.trust
            .verify_executable(&intent.manifest, &mut self.storage)
            .map_err(Error::Trust)
    }

    /// Returns a verified inactive candidate, NOT installation or OTP success.
    pub fn finalize(
        &mut self,
        digest: [u8; 32],
        final_digest: [u8; 32],
        revision: u64,
    ) -> Result<Intent, Error<S::Error>> {
        let mut intent = self.matching(digest, revision)?;
        if intent.offset != intent.manifest.image_length {
            return Err(Error::Sequence);
        }
        if final_digest != intent.manifest.firmware_digest {
            return Err(Error::Digest);
        }
        self.validate(&intent.manifest, digest, revision)?;
        self.healthy = false;
        self.storage
            .check_preserved_image()
            .map_err(Error::Storage)?;
        self.check_image()?;
        intent.phase = Phase::Verified;
        self.save(intent)?;
        Ok(intent)
    }
}
