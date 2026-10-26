//! Authenticated two-bank journal. A committed successor is authoritative even
//! when predecessor erasure or the final cleanup acknowledgement was interrupted.
use crate::{
    cbor,
    crypto::KesKey,
    state::{PublicObject, PublicObjectRef, StateError},
    types::{DeviceId, HardwareSlot, IncarnationId, PoolId, Revision},
};
use chacha20poly1305::{
    Tag, XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, KeyInit},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_chacha::rand_core::TryCryptoRng;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub(crate) mod codec;
pub use codec::{DirectoryCodec, PoolCodec};

struct CandidateWrite<'a, S> {
    state: &'a S,
    bank: u8,
    parent: Option<(&'a Marker, &'a [u8; 256])>,
    replica: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalScope {
    Directory,
    Pool {
        slot: HardwareSlot,
        pool: PoolId,
        incarnation: IncarnationId,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalContext {
    pub device: DeviceId,
    pub scope: JournalScope,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalLayout {
    base: u32,
    directory: bool,
}
impl JournalLayout {
    pub fn pool(base: u32) -> Result<Self, JournalError> {
        Self::create(base, false)
    }
    pub fn directory(base: u32) -> Result<Self, JournalError> {
        Self::create(base, true)
    }
    fn create(base: u32, directory: bool) -> Result<Self, JournalError> {
        if !base.is_multiple_of(4096) {
            return Err(JournalError::InvalidContext);
        }
        base.checked_add(if directory { 16384 } else { 32768 })
            .ok_or(JournalError::SizeLimit)?;
        Ok(Self { base, directory })
    }
    pub const fn bank_bytes(self) -> usize {
        if self.directory { 8192 } else { 4096 }
    }
    pub const fn snapshot_bytes(self) -> usize {
        self.bank_bytes() - 512
    }
    pub fn bank_offset(self, bank: u8) -> Result<u32, JournalError> {
        if bank > 1 {
            return Err(JournalError::InvalidContext);
        }
        self.base
            .checked_add(u32::from(bank) * self.bank_bytes() as u32)
            .ok_or(JournalError::SizeLimit)
    }
    pub fn commit_offset(self, bank: u8) -> Result<u32, JournalError> {
        self.bank_offset(bank)?
            .checked_add(self.snapshot_bytes() as u32)
            .ok_or(JournalError::SizeLimit)
    }
    pub fn clean_offset(self, bank: u8) -> Result<u32, JournalError> {
        self.commit_offset(bank)?
            .checked_add(256)
            .ok_or(JournalError::SizeLimit)
    }
    pub fn object_offset(self, index: u8) -> Result<u32, JournalError> {
        if self.directory || index > 1 {
            return Err(JournalError::InvalidContext);
        }
        self.base
            .checked_add(8192 + u32::from(index) * 8192)
            .ok_or(JournalError::SizeLimit)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlashRules {
    OnceOnlyClean,
    QualifiedIdenticalCleanRetry,
}
pub trait Flash {
    type Error;
    fn capacity(&self) -> u32;
    fn rules(&self) -> FlashRules;
    fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<(), Self::Error>;
    fn program_page(&mut self, offset: u32, page: &[u8; 256]) -> Result<(), Self::Error>;
    fn erase_sector(&mut self, offset: u32) -> Result<(), Self::Error>;
    fn invalidate_cache(&mut self) -> Result<(), Self::Error>;
}
pub struct JournalWorkspace {
    bytes: Zeroizing<[u8; 8192]>,
}
impl JournalWorkspace {
    pub fn new() -> Self {
        Self {
            bytes: Zeroizing::new([0; 8192]),
        }
    }
}
impl Default for JournalWorkspace {
    fn default() -> Self {
        Self::new()
    }
}
pub struct ObjectWorkspace {
    pub bytes: [u8; 6144],
}
impl ObjectWorkspace {
    pub fn new() -> Self {
        Self { bytes: [0; 6144] }
    }
}
impl Default for ObjectWorkspace {
    fn default() -> Self {
        Self::new()
    }
}
pub struct SecretCache {
    bytes: Zeroizing<[u8; 64]>,
}
impl SecretCache {
    pub fn new() -> Self {
        Self {
            bytes: Zeroizing::new([0; 64]),
        }
    }
    pub fn with_bytes_mut<T>(&mut self, f: impl FnOnce(&mut [u8; 64]) -> T) -> T {
        f(&mut self.bytes)
    }
    pub fn is_erased(&self) -> bool {
        self.bytes.iter().all(|b| *b == 0)
    }
    pub fn erase(&mut self) {
        self.bytes.zeroize();
    }
}
impl Default for SecretCache {
    fn default() -> Self {
        Self::new()
    }
}
pub struct Workspaces<'a> {
    pub journal: &'a mut JournalWorkspace,
    pub object: &'a mut ObjectWorkspace,
    pub cache: &'a mut SecretCache,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectBinding {
    pub reference: PublicObjectRef,
    pub verification_key: [u8; 32],
    pub backup_digest: [u8; 32],
}
pub trait SnapshotCodec {
    type State;
    fn encode(
        state: &Self::State,
        context: JournalContext,
        out: &mut [u8],
    ) -> Result<usize, JournalError>;
    fn decode(input: &[u8], context: JournalContext) -> Result<Self::State, JournalError>;
    fn revision(state: &Self::State) -> Revision;
    fn set_recovery_revision(state: &mut Self::State, revision: Revision);
    fn objects(state: &Self::State) -> [Option<ObjectBinding>; 2];
    fn private_keys(state: &mut Self::State) -> [Option<&mut KesKey>; 2];
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalError {
    Codec(cbor::Error),
    State(StateError),
    InvalidContext,
    SizeLimit,
    EntropyFailure,
    Flash,
    Uninitialized,
    NotCommitted,
    AlreadyInitialized,
    Damaged,
    RevisionConflict,
    CounterOverflow,
    ObjectMissing,
    ObjectInvalid,
}
impl core::fmt::Display for JournalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Codec(_) => "invalid journal encoding",
            Self::State(_) => "invalid journal state",
            Self::InvalidContext => "invalid journal context",
            Self::SizeLimit => "journal size limit",
            Self::EntropyFailure => "journal entropy unavailable",
            Self::Flash => "journal flash failure",
            Self::Uninitialized => "journal uninitialized",
            Self::NotCommitted => "journal not committed",
            Self::AlreadyInitialized => "journal already initialized",
            Self::Damaged => "journal damaged",
            Self::RevisionConflict => "journal revision conflict",
            Self::CounterOverflow => "journal revision exhausted",
            Self::ObjectMissing => "journal object missing",
            Self::ObjectInvalid => "journal object invalid",
        })
    }
}
impl core::error::Error for JournalError {}
impl From<cbor::Error> for JournalError {
    fn from(e: cbor::Error) -> Self {
        Self::Codec(e)
    }
}
impl From<StateError> for JournalError {
    fn from(e: StateError) -> Self {
        Self::State(e)
    }
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ReadyToken {
    context: JournalContext,
    revision: Revision,
    bank: u8,
    digest: [u8; 32],
    commit: [u8; 32],
    clean: [u8; 32],
}
impl ReadyToken {
    pub const fn revision(&self) -> Revision {
        self.revision
    }
    pub const fn bank(&self) -> u8 {
        self.bank
    }
}
pub struct Recovered<S> {
    pub state: S,
    pub token: ReadyToken,
}
pub struct Mutation<'a, C: SnapshotCodec> {
    pub expected: &'a ReadyToken,
    pub successor: &'a C::State,
    pub retired: &'a mut C::State,
}
pub struct Journal<C: SnapshotCodec> {
    context: JournalContext,
    layout: JournalLayout,
    snapshot_key: Zeroizing<[u8; 32]>,
    marker_key: Zeroizing<[u8; 32]>,
    codec: core::marker::PhantomData<C>,
}

// Marker copies contain only authenticated public metadata, never key material.
#[derive(Clone, Copy)]
struct Marker {
    page: [u8; 256],
}
impl Marker {
    fn bank(&self) -> u8 {
        self.page[10]
    }
    fn revision(&self) -> u64 {
        u64::from_be_bytes(self.page[12..20].try_into().unwrap())
    }
    fn parent(&self) -> u64 {
        u64::from_be_bytes(self.page[20..28].try_into().unwrap())
    }
    fn digest(&self) -> [u8; 32] {
        self.page[28..60].try_into().unwrap()
    }
    fn tag(&self) -> [u8; 32] {
        self.page[184..216].try_into().unwrap()
    }
    fn compact(&self) -> [u8; 92] {
        let mut b = [0; 92];
        b[..60].copy_from_slice(&self.page[..60]);
        b[60..].copy_from_slice(&self.page[184..216]);
        b
    }
    fn has_parent(&self) -> bool {
        self.page[11] & 1 != 0
    }
}
struct Authority {
    commit: Marker,
    clean: [u8; 256],
    clean_valid: bool,
}
fn erased(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| *b == 255)
}
// A prefix-bit interrupted erase can only set bits; interrupted programming can
// only clear bits. These are deliberately different predicates.
fn erase_compatible(actual: &[u8], original: &[u8]) -> bool {
    actual.iter().zip(original).all(|(a, o)| a & o == *o)
}
fn program_compatible(actual: &[u8], intended: &[u8]) -> bool {
    actual.iter().zip(intended).all(|(a, i)| a & i == *i)
}

impl<C: SnapshotCodec> Journal<C> {
    pub fn new(
        context: JournalContext,
        layout: JournalLayout,
        storage_root: &[u8; 32],
    ) -> Result<Self, JournalError> {
        if matches!(context.scope, JournalScope::Directory) != layout.directory {
            return Err(JournalError::InvalidContext);
        }
        let binding = Self::context_bytes(context);
        let hk = Hkdf::<Sha256>::new(Some(b"KES journal v1 HKDF-SHA256"), &storage_root[..]);
        let mut snapshot_key = Zeroizing::new([0; 32]);
        let mut marker_key = Zeroizing::new([0; 32]);
        let mut info = [0u8; 96];
        info[..77].copy_from_slice(&binding);
        info[77..85].copy_from_slice(b"snapshot");
        hk.expand(&info[..85], &mut snapshot_key[..])
            .map_err(|_| JournalError::InvalidContext)?;
        info[77..85].copy_from_slice(b"marker\0\0");
        hk.expand(&info[..85], &mut marker_key[..])
            .map_err(|_| JournalError::InvalidContext)?;
        Ok(Self {
            context,
            layout,
            snapshot_key,
            marker_key,
            codec: core::marker::PhantomData,
        })
    }
    fn context_bytes(context: JournalContext) -> [u8; 77] {
        let mut b = [0; 77];
        b[..16].copy_from_slice(context.device.as_bytes());
        match context.scope {
            JournalScope::Directory => {
                b[16] = 2;
                b[17] = 255;
            }
            JournalScope::Pool {
                slot,
                pool,
                incarnation,
            } => {
                b[16] = 1;
                b[17] = slot.get() as u8;
                b[18..46].copy_from_slice(pool.as_bytes());
                b[46..62].copy_from_slice(incarnation.as_bytes());
            }
        }
        b
    }
    fn capacity(&self, flash: &impl Flash) -> Result<(), JournalError> {
        let end = self
            .layout
            .base
            .checked_add(if self.layout.directory { 16384 } else { 32768 })
            .ok_or(JournalError::SizeLimit)?;
        if end > flash.capacity() {
            Err(JournalError::SizeLimit)
        } else {
            Ok(())
        }
    }
    fn mac(&self, page: &[u8; 256]) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.marker_key[..])
            .expect("fixed HMAC key length");
        mac.update(if page[9] == 1 {
            b"KES journal COMMIT v1"
        } else {
            b"KES journal CLEAN v1"
        });
        mac.update(&Self::context_bytes(self.context));
        mac.update(&page[..184]);
        mac.finalize().into_bytes().into()
    }
    fn valid_marker(&self, page: &[u8; 256], bank: u8, phase: u8) -> bool {
        if &page[..8] != b"KESMKR01"
            || page[8] != 1
            || page[9] != phase
            || page[10] != bank
            || page[11] & !3 != 0
            || !erased(&page[216..])
        {
            return false;
        }
        let m = Marker { page: *page };
        if m.has_parent() {
            if m.revision() == 0 || m.parent().checked_add(1) != Some(m.revision()) {
                return false;
            }
        } else if m.revision() != 0 || m.parent() != 0 || page[11] != 0 || !erased(&page[60..184]) {
            return false;
        }
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.marker_key[..])
            .expect("fixed HMAC key length");
        mac.update(if phase == 1 {
            b"KES journal COMMIT v1"
        } else {
            b"KES journal CLEAN v1"
        });
        mac.update(&Self::context_bytes(self.context));
        mac.update(&page[..184]);
        mac.verify_slice(&page[184..216]).is_ok()
    }
    fn make_marker(
        &self,
        bank: u8,
        revision: Revision,
        digest: [u8; 32],
        parent: Option<(&Marker, &[u8; 256])>,
        replica: bool,
    ) -> Marker {
        let mut p = [255; 256];
        p[..8].copy_from_slice(b"KESMKR01");
        p[8] = 1;
        p[9] = 1;
        p[10] = bank;
        p[11] = u8::from(parent.is_some()) | (u8::from(replica) << 1);
        p[12..20].copy_from_slice(&revision.get().to_be_bytes());
        p[20..28].copy_from_slice(&parent.map_or(0, |(m, _)| m.revision()).to_be_bytes());
        p[28..60].copy_from_slice(&digest);
        if let Some((m, c)) = parent {
            p[60..152].copy_from_slice(&m.compact());
            p[152..184].copy_from_slice(&c[184..216]);
        }
        let tag = self.mac(&p);
        p[184..216].copy_from_slice(&tag);
        Marker { page: p }
    }
    fn clean_page(&self, m: &Marker) -> [u8; 256] {
        let mut p = m.page;
        p[9] = 2;
        let tag = self.mac(&p);
        p[184..216].copy_from_slice(&tag);
        p
    }
    fn token(&self, m: &Marker) -> ReadyToken {
        ReadyToken {
            context: self.context,
            revision: Revision::new(m.revision()),
            bank: m.bank(),
            digest: m.digest(),
            commit: m.tag(),
            clean: self.clean_page(m)[184..216].try_into().unwrap(),
        }
    }
    fn read_page(&self, f: &mut impl Flash, offset: u32) -> Result<[u8; 256], JournalError> {
        let mut p = [0; 256];
        f.read(offset, &mut p).map_err(|_| JournalError::Flash)?;
        Ok(p)
    }
    fn blank_bank(
        &self,
        f: &mut impl Flash,
        bank: u8,
        work: &mut JournalWorkspace,
    ) -> Result<bool, JournalError> {
        let n = self.layout.bank_bytes();
        f.read(self.layout.bank_offset(bank)?, &mut work.bytes[..n])
            .map_err(|_| JournalError::Flash)?;
        let blank = erased(&work.bytes[..n]);
        work.bytes.zeroize();
        Ok(blank)
    }
    fn erase_bank(
        &self,
        f: &mut impl Flash,
        bank: u8,
        work: &mut JournalWorkspace,
    ) -> Result<(), JournalError> {
        let base = self.layout.bank_offset(bank)?;
        for i in (0..self.layout.bank_bytes()).step_by(4096) {
            f.erase_sector(base + i as u32)
                .map_err(|_| JournalError::Flash)?;
        }
        f.invalidate_cache().map_err(|_| JournalError::Flash)?;
        if !self.blank_bank(f, bank, work)? {
            return Err(JournalError::Damaged);
        }
        Ok(())
    }
    fn authority(
        &self,
        f: &mut impl Flash,
        work: &mut JournalWorkspace,
    ) -> Result<Authority, JournalError> {
        let commits = [
            self.read_page(f, self.layout.commit_offset(0)?)?,
            self.read_page(f, self.layout.commit_offset(1)?)?,
        ];
        let cleans = [
            self.read_page(f, self.layout.clean_offset(0)?)?,
            self.read_page(f, self.layout.clean_offset(1)?)?,
        ];
        let valid = [
            self.valid_marker(&commits[0], 0, 1),
            self.valid_marker(&commits[1], 1, 1),
        ];
        let bank = match valid {
            [false, false] => {
                if self.blank_bank(f, 0, work)? && self.blank_bank(f, 1, work)? {
                    return Err(JournalError::Uninitialized);
                }
                if commits.iter().all(|p| erased(p)) && cleans.iter().all(|p| erased(p)) {
                    return Err(JournalError::NotCommitted);
                }
                return Err(JournalError::Damaged);
            }
            [true, false] => 0,
            [false, true] => 1,
            [true, true] => {
                let a = Marker { page: commits[0] };
                let b = Marker { page: commits[1] };
                if a.revision() == b.revision() {
                    return Err(JournalError::Damaged);
                }
                let (new, old) = if a.revision() > b.revision() {
                    (a, b)
                } else {
                    (b, a)
                };
                if !new.has_parent()
                    || old.revision().checked_add(1) != Some(new.revision())
                    || new.parent() != old.revision()
                    || new.page[60..152] != old.compact()
                {
                    return Err(JournalError::Damaged);
                }
                new.bank() as usize
            }
        };
        let m = Marker {
            page: commits[bank],
        };
        let other = 1 - bank;
        let clean_expected = self.clean_page(&m);
        let clean_valid =
            self.valid_marker(&cleans[bank], bank as u8, 2) && cleans[bank] == clean_expected;
        if !clean_valid && !program_compatible(&cleans[bank], &clean_expected) {
            return Err(JournalError::Damaged);
        }
        if m.has_parent() {
            if valid[other] {
                if m.page[60..152]
                    != (Marker {
                        page: commits[other],
                    })
                    .compact()
                {
                    return Err(JournalError::Damaged);
                }
            } else if !erase_compatible(&commits[other][..60], &m.page[60..120])
                || !erase_compatible(&commits[other][184..216], &m.page[120..152])
            {
                return Err(JournalError::Damaged);
            }
            if !erase_compatible(&cleans[other][184..216], &m.page[152..184]) {
                return Err(JournalError::Damaged);
            }
            // Without recoveryReplica the parent CLEAN was authenticated before
            // COMMIT. With it, the observed torn parent tag is itself sealed.
            if m.page[11] & 2 == 0 {
                let mut base = [0; 60];
                base.copy_from_slice(&m.page[60..120]);
                base[9] = 2;
                if !erase_compatible(&cleans[other][..60], &base) {
                    return Err(JournalError::Damaged);
                }
            }
        } else if !erased(&commits[other]) || !erased(&cleans[other]) {
            return Err(JournalError::Damaged);
        }
        if !m.has_parent() && !clean_valid && !self.blank_bank(f, other as u8, work)? {
            return Err(JournalError::Damaged);
        }
        Ok(Authority {
            commit: m,
            clean: cleans[bank],
            clean_valid,
        })
    }
    fn objects(
        &self,
        f: &mut impl Flash,
        state: &C::State,
        work: &mut ObjectWorkspace,
    ) -> Result<u8, JournalError> {
        let mut used = 0u8;
        for binding in C::objects(state).into_iter().flatten() {
            let n = usize::from(binding.reference.total_length);
            if !(4096..=6144).contains(&n) || self.layout.directory {
                return Err(JournalError::ObjectInvalid);
            }
            let mut found = None;
            for slot in 0..2 {
                if used & (1 << slot) != 0 {
                    continue;
                }
                f.read(self.layout.object_offset(slot)?, &mut work.bytes[..n])
                    .map_err(|_| JournalError::Flash)?;
                if let Ok(object) = PublicObject::parse(
                    &work.bytes[..n],
                    &binding.reference,
                    &binding.verification_key,
                ) && object.backup_digest() == binding.backup_digest
                {
                    found = Some(slot);
                    break;
                }
            }
            let slot = found.ok_or(JournalError::ObjectMissing)?;
            used |= 1 << slot;
        }
        Ok(used)
    }

    fn reclaim_public_orphans(
        &self,
        f: &mut impl Flash,
        referenced: u8,
        work: &mut JournalWorkspace,
    ) -> Result<(), JournalError> {
        if self.layout.directory {
            return Ok(());
        }
        for slot in 0..2 {
            if referenced & (1 << slot) != 0 {
                continue;
            }
            let offset = self.layout.object_offset(slot)?;
            f.read(offset, &mut work.bytes[..8192])
                .map_err(|_| JournalError::Flash)?;
            if !erased(&work.bytes[..8192]) {
                f.erase_sector(offset).map_err(|_| JournalError::Flash)?;
                f.erase_sector(offset + 4096)
                    .map_err(|_| JournalError::Flash)?;
                f.invalidate_cache().map_err(|_| JournalError::Flash)?;
                f.read(offset, &mut work.bytes[..8192])
                    .map_err(|_| JournalError::Flash)?;
                if !erased(&work.bytes[..8192]) {
                    return Err(JournalError::Damaged);
                }
            }
            work.bytes.zeroize();
        }
        Ok(())
    }
    fn header(&self, bank: u8, revision: Revision, nonce: &[u8; 24], len: usize) -> [u8; 128] {
        let mut h = [0; 128];
        h[..8].copy_from_slice(b"KESJNL01");
        h[8..10].copy_from_slice(&1u16.to_be_bytes());
        h[11] = bank;
        h[13] = u8::from(revision.get() == 0);
        h[14..16].copy_from_slice(&(len as u16).to_be_bytes());
        h[16..32].copy_from_slice(self.context.device.as_bytes());
        match self.context.scope {
            JournalScope::Directory => {
                h[10] = 2;
                h[12] = 255;
            }
            JournalScope::Pool {
                slot,
                pool,
                incarnation,
            } => {
                h[10] = 1;
                h[12] = slot.get() as u8;
                h[32..60].copy_from_slice(pool.as_bytes());
                h[60..76].copy_from_slice(incarnation.as_bytes());
            }
        }
        h[76..84].copy_from_slice(&revision.get().to_be_bytes());
        h[84..92].copy_from_slice(&revision.get().saturating_sub(1).to_be_bytes());
        h[92..116].copy_from_slice(nonce);
        h
    }
    fn aad(header: &[u8; 128]) -> [u8; 152] {
        let mut aad = [0; 152];
        aad[..24].copy_from_slice(b"KES journal snapshot v1\0");
        aad[24..].copy_from_slice(header);
        aad
    }
    fn load(
        &self,
        f: &mut impl Flash,
        m: &Marker,
        work: &mut Workspaces<'_>,
    ) -> Result<(C::State, u8), JournalError> {
        let max = self.layout.snapshot_bytes();
        let b = &mut work.journal.bytes[..max];
        f.read(self.layout.bank_offset(m.bank())?, b)
            .map_err(|_| JournalError::Flash)?;
        let h: [u8; 128] = b[..128].try_into().unwrap();
        let n = u16::from_be_bytes([h[14], h[15]]) as usize;
        if n < 16 || n > max - 128 {
            return Err(JournalError::Damaged);
        }
        let nonce: [u8; 24] = h[92..116].try_into().unwrap();
        if h != self.header(m.bank(), Revision::new(m.revision()), &nonce, n)
            || Sha256::digest(&b[..128 + n])[..] != m.digest()
        {
            return Err(JournalError::Damaged);
        }
        let tag: [u8; 16] = b[128 + n - 16..128 + n].try_into().unwrap();
        let cipher = XChaCha20Poly1305::new_from_slice(&self.snapshot_key[..])
            .map_err(|_| JournalError::Damaged)?;
        let nonce = XNonce::from(nonce);
        let tag = Tag::from(tag);
        cipher
            .decrypt_in_place_detached(&nonce, &Self::aad(&h), &mut b[128..128 + n - 16], &tag)
            .map_err(|_| JournalError::Damaged)?;
        let state =
            C::decode(&b[128..128 + n - 16], self.context).map_err(|_| JournalError::Damaged)?;
        if C::revision(&state).get() != m.revision() {
            return Err(JournalError::Damaged);
        }
        let objects = self
            .objects(f, &state, work.object)
            .map_err(|_| JournalError::Damaged)?;
        work.journal.bytes.zeroize();
        Ok((state, objects))
    }
    fn candidate(
        &self,
        f: &mut impl Flash,
        input: CandidateWrite<'_, C::State>,
        nonce: &[u8; 24],
        work: &mut Workspaces<'_>,
    ) -> Result<Marker, JournalError> {
        let CandidateWrite {
            state,
            bank,
            parent,
            replica,
        } = input;
        self.objects(f, state, work.object)?;
        let max = self.layout.snapshot_bytes();
        work.journal.bytes.fill(255);
        let n = C::encode(state, self.context, &mut work.journal.bytes[128..max - 16])?;
        if n > max - 144 {
            return Err(JournalError::SizeLimit);
        }
        {
            let check = C::decode(&work.journal.bytes[128..128 + n], self.context)?;
            if C::revision(&check) != C::revision(state) {
                return Err(JournalError::RevisionConflict);
            }
            self.objects(f, &check, work.object)?;
        }
        let h = self.header(bank, C::revision(state), nonce, n + 16);
        work.journal.bytes[..128].copy_from_slice(&h);
        let cipher = XChaCha20Poly1305::new_from_slice(&self.snapshot_key[..])
            .map_err(|_| JournalError::Damaged)?;
        let nonce = XNonce::from(*nonce);
        let tag = cipher
            .encrypt_in_place_detached(
                &nonce,
                &Self::aad(&h),
                &mut work.journal.bytes[128..128 + n],
            )
            .map_err(|_| JournalError::Damaged)?;
        work.journal.bytes[128 + n..144 + n].copy_from_slice(&tag);
        let digest = Sha256::digest(&work.journal.bytes[..144 + n]).into();
        let m = self.make_marker(bank, C::revision(state), digest, parent, replica);
        let base = self.layout.bank_offset(bank)?;
        for offset in (0..(144 + n).div_ceil(256) * 256).step_by(256) {
            let page: &[u8; 256] = work.journal.bytes[offset..offset + 256].try_into().unwrap();
            f.program_page(base + offset as u32, page)
                .map_err(|_| JournalError::Flash)?;
        }
        f.invalidate_cache().map_err(|_| JournalError::Flash)?;
        drop(self.load(f, &m, work)?);
        self.program_verified(f, self.layout.commit_offset(bank)?, &m.page)?;
        Ok(m)
    }
    fn program_verified(
        &self,
        f: &mut impl Flash,
        offset: u32,
        page: &[u8; 256],
    ) -> Result<(), JournalError> {
        f.program_page(offset, page)
            .map_err(|_| JournalError::Flash)?;
        f.invalidate_cache().map_err(|_| JournalError::Flash)?;
        if self.read_page(f, offset)? != *page {
            return Err(JournalError::Damaged);
        }
        Ok(())
    }
    fn nonce(rng: &mut impl TryCryptoRng) -> Result<[u8; 24], JournalError> {
        let mut nonce = [0; 24];
        rng.try_fill_bytes(&mut nonce)
            .map_err(|_| JournalError::EntropyFailure)?;
        Ok(nonce)
    }
    fn wipe(work: &mut Workspaces<'_>) {
        work.journal.bytes.zeroize();
        work.cache.erase();
    }
    fn finish(
        &self,
        f: &mut impl Flash,
        m: &Marker,
        work: &mut Workspaces<'_>,
    ) -> Result<ReadyToken, JournalError> {
        Self::wipe(work);
        f.invalidate_cache().map_err(|_| JournalError::Flash)?;
        self.program_verified(f, self.layout.clean_offset(m.bank())?, &self.clean_page(m))?;
        Ok(self.token(m))
    }
    pub fn initialize(
        &self,
        f: &mut impl Flash,
        rng: &mut impl TryCryptoRng,
        state: &C::State,
        work: &mut Workspaces<'_>,
    ) -> Result<ReadyToken, JournalError> {
        let result = (|| {
            self.capacity(f)?;
            f.invalidate_cache().map_err(|_| JournalError::Flash)?;
            if C::revision(state).get() != 0 {
                return Err(JournalError::RevisionConflict);
            }
            if !self.blank_bank(f, 0, work.journal)? || !self.blank_bank(f, 1, work.journal)? {
                return Err(JournalError::AlreadyInitialized);
            }
            let nonce = Self::nonce(rng)?;
            let m = self.candidate(
                f,
                CandidateWrite {
                    state,
                    bank: 0,
                    parent: None,
                    replica: false,
                },
                &nonce,
                work,
            )?;
            self.finish(f, &m, work)
        })();
        work.journal.bytes.zeroize();
        result
    }
    pub fn transact(
        &self,
        f: &mut impl Flash,
        rng: &mut impl TryCryptoRng,
        mutation: Mutation<'_, C>,
        work: &mut Workspaces<'_>,
    ) -> Result<ReadyToken, JournalError> {
        self.transact_candidate(
            f,
            rng,
            mutation.expected,
            mutation.successor,
            Some(mutation.retired),
            work,
        )
    }

    /// Persist a successor produced by mutating the sole live state owner in
    /// place. The caller must discard that owner on failure. Unlike `transact`,
    /// this does not erase keys from a separate retired RAM snapshot because no
    /// such owner may exist.
    pub fn transact_successor(
        &self,
        f: &mut impl Flash,
        rng: &mut impl TryCryptoRng,
        expected: &ReadyToken,
        successor: &C::State,
        work: &mut Workspaces<'_>,
    ) -> Result<ReadyToken, JournalError> {
        self.transact_candidate(f, rng, expected, successor, None, work)
    }

    fn transact_candidate(
        &self,
        f: &mut impl Flash,
        rng: &mut impl TryCryptoRng,
        expected: &ReadyToken,
        successor: &C::State,
        mut retired: Option<&mut C::State>,
        work: &mut Workspaces<'_>,
    ) -> Result<ReadyToken, JournalError> {
        let result = (|| {
            self.capacity(f)?;
            if expected.context != self.context {
                return Err(JournalError::InvalidContext);
            }
            f.invalidate_cache().map_err(|_| JournalError::Flash)?;
            let a = self.authority(f, work.journal)?;
            if !a.clean_valid || self.token(&a.commit) != *expected {
                return Err(JournalError::RevisionConflict);
            }
            drop(self.load(f, &a.commit, work)?);
            let next = a
                .commit
                .revision()
                .checked_add(1)
                .ok_or(JournalError::CounterOverflow)?;
            if C::revision(successor).get() != next
                || retired
                    .as_deref()
                    .is_some_and(|state| C::revision(state).get() != a.commit.revision())
            {
                return Err(JournalError::RevisionConflict);
            }
            let nonce = Self::nonce(rng)?;
            let bank = 1 - a.commit.bank();
            self.erase_bank(f, bank, work.journal)?;
            let m = self.candidate(
                f,
                CandidateWrite {
                    state: successor,
                    bank,
                    parent: Some((&a.commit, &a.clean)),
                    replica: false,
                },
                &nonce,
                work,
            )?;
            self.erase_bank(f, a.commit.bank(), work.journal)?;
            f.invalidate_cache().map_err(|_| JournalError::Flash)?;
            if let Some(state) = retired.as_deref_mut() {
                for key in C::private_keys(state).into_iter().flatten() {
                    key.erase();
                }
            }
            self.finish(f, &m, work)
        })();
        work.journal.bytes.zeroize();
        result
    }
    pub fn recover(
        &self,
        f: &mut impl Flash,
        rng: &mut impl TryCryptoRng,
        work: &mut Workspaces<'_>,
    ) -> Result<Recovered<C::State>, JournalError> {
        let result = (|| {
            self.capacity(f)?;
            f.invalidate_cache().map_err(|_| JournalError::Flash)?;
            let a = self.authority(f, work.journal)?;
            let (mut state, object_slots) = self.load(f, &a.commit, work)?;
            if a.clean_valid {
                if !self.blank_bank(f, 1 - a.commit.bank(), work.journal)? {
                    self.erase_bank(f, 1 - a.commit.bank(), work.journal)?;
                }
                self.reclaim_public_orphans(f, object_slots, work.journal)?;
                Self::wipe(work);
                f.invalidate_cache().map_err(|_| JournalError::Flash)?;
                return Ok(Recovered {
                    state,
                    token: self.token(&a.commit),
                });
            }
            if f.rules() == FlashRules::QualifiedIdenticalCleanRetry {
                self.erase_bank(f, 1 - a.commit.bank(), work.journal)?;
                let token = self.finish(f, &a.commit, work)?;
                self.reclaim_public_orphans(f, object_slots, work.journal)?;
                return Ok(Recovered { state, token });
            }
            let next = a
                .commit
                .revision()
                .checked_add(1)
                .ok_or(JournalError::CounterOverflow)?;
            let nonce = Self::nonce(rng)?;
            C::set_recovery_revision(&mut state, Revision::new(next));
            let bank = 1 - a.commit.bank();
            self.erase_bank(f, bank, work.journal)?;
            let m = self.candidate(
                f,
                CandidateWrite {
                    state: &state,
                    bank,
                    parent: Some((&a.commit, &a.clean)),
                    replica: true,
                },
                &nonce,
                work,
            )?;
            self.erase_bank(f, a.commit.bank(), work.journal)?;
            let token = self.finish(f, &m, work)?;
            self.reclaim_public_orphans(f, object_slots, work.journal)?;
            Ok(Recovered { state, token })
        })();
        Self::wipe(work);
        result
    }
}

const _: () = assert!(core::mem::size_of::<JournalWorkspace>() == 8192);
const _: () =
    assert!(core::mem::size_of::<ObjectWorkspace>() + core::mem::size_of::<SecretCache>() <= 32768);
