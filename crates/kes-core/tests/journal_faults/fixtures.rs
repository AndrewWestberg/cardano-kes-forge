use super::flash::NorFlash;
use ed25519_dalek::{Signer, SigningKey};
use kes_core::{
    cbor::Encoder,
    crypto::{Generation, KesKey, PublicTreeBuffer},
    journal::{Journal, JournalContext, JournalLayout, JournalScope, PoolCodec, SnapshotCodec},
    state::{PoolRegistration, PublicObject},
    types::{
        DeviceId, GenerationId, HardwareSlot, IncarnationId, KesLifetime, PoolId, RelativePeriod,
    },
};
use rand_chacha::rand_core::{TryCryptoRng, TryRngCore};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read},
};
use zeroize::Zeroizing;

pub(super) struct OsEntropy {
    source: File,
    fail: bool,
}
impl OsEntropy {
    pub(super) fn new() -> Self {
        xtask::oracles::protect_memory().expect("protected fresh no-swap runtime required");
        Self {
            source: File::open("/dev/urandom").unwrap(),
            fail: false,
        }
    }
    pub(super) fn failing() -> Self {
        let mut rng = Self::new();
        rng.fail = true;
        rng
    }
}
impl TryRngCore for OsEntropy {
    type Error = io::Error;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_ne_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_ne_bytes(b))
    }
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), Self::Error> {
        if self.fail {
            return Err(io::Error::other("injected entropy failure"));
        }
        self.source.read_exact(out)
    }
}
impl TryCryptoRng for OsEntropy {}
pub(super) fn fresh_storage_root() -> Zeroizing<[u8; 32]> {
    let mut rng = OsEntropy::new();
    let mut root = Zeroizing::new([0; 32]);
    rng.try_fill_bytes(&mut *root).unwrap();
    root
}

pub(super) struct Fixture {
    pub context: JournalContext,
    pub layout: JournalLayout,
    pub vk: [u8; 32],
    root: Zeroizing<[u8; 32]>,
    bodies: [Zeroizing<Vec<u8>>; 4],
    object: Vec<u8>,
}
impl Fixture {
    pub fn new() -> Self {
        let mut rng = OsEntropy::new();
        let mut seed = fresh_storage_root();
        let cold = SigningKey::from_bytes(&fresh_storage_root());
        let cold_vk = cold.verifying_key().to_bytes();
        let pool = PoolId::from_cold_verification_key(&cold_vk);
        let incarnation = IncarnationId::random(&mut rng).unwrap();
        let generation = GenerationId::random(&mut rng).unwrap();
        let context = JournalContext {
            device: DeviceId::random(&mut rng).unwrap(),
            scope: JournalScope::Pool {
                slot: HardwareSlot::new(0).unwrap(),
                pool,
                incarnation,
            },
        };
        let mut key = KesKey::erased(KesLifetime::new(64).unwrap());
        let mut tree = PublicTreeBuffer::new();
        let mut job = Generation::begin(&mut seed, &mut key, &mut tree).unwrap();
        for _ in 0..64 {
            job.step().unwrap();
        }
        let verified = job.finish().unwrap();
        let vk = key.verification_key().unwrap();
        // Public structural backup envelope, not a claim of HPKE producer validation.
        let backup = include_bytes!("../../../../fuzz/corpus/frame/backup-public-structure");
        let object =
            PublicObject::from_parts(generation, verified.as_bytes(), backup, &vk).unwrap();
        let reference = *object.reference();
        let backup_digest = object.backup_digest();
        let mut object_bytes = vec![0; usize::from(reference.total_length)];
        object.encode_into(&mut object_bytes).unwrap();
        // Construct the OCert's 48-byte signable independently of product helpers.
        let mut signable = [0; 48];
        signable[..32].copy_from_slice(&vk);
        signable[32..40].copy_from_slice(&0u64.to_be_bytes());
        signable[40..].copy_from_slice(&100u64.to_be_bytes());
        let signature = cold.sign(&signable).to_bytes();
        let mut certificate = [0; 154];
        let mut e = Encoder::new(&mut certificate);
        e.array(2).unwrap();
        e.array(4).unwrap();
        e.bytes(&vk).unwrap();
        e.uint(0).unwrap();
        e.uint(100).unwrap();
        e.bytes(&signature).unwrap();
        e.bytes(&cold_vk).unwrap();
        let certificate = e.finish().unwrap().encoded();
        let recipient_public = [0x42; 32];
        let recipient_id: [u8; 32] = Sha256::digest(recipient_public).into();
        let bodies = std::array::from_fn(|period| {
            key.evolve_to(RelativePeriod::new(period as u64).unwrap(), &verified)
                .unwrap();
            let mut body = Zeroizing::new(vec![0; 3440]);
            let mut e = Encoder::new(&mut body);
            e.array(13).unwrap();
            e.uint(1).unwrap();
            e.bytes(pool.as_bytes()).unwrap();
            e.bytes(incarnation.as_bytes()).unwrap();
            e.bytes(&cold_vk).unwrap();
            e.array(4).unwrap();
            e.uint(42).unwrap();
            e.bytes(&[0x31; 32]).unwrap();
            e.uint(129600).unwrap();
            e.uint(64).unwrap();
            e.array(3).unwrap();
            e.bytes(&[0x41; 32]).unwrap();
            e.uint(0).unwrap();
            e.boolean(false).unwrap();
            e.array(3).unwrap();
            e.bytes(&recipient_public).unwrap();
            e.bytes(&recipient_id).unwrap();
            e.uint(0).unwrap();
            e.array(5).unwrap();
            e.uint(1).unwrap();
            e.bytes(&[0x51; 16]).unwrap();
            e.bytes(&[0x52; 32]).unwrap();
            e.uint(0).unwrap();
            e.uint(0).unwrap();
            e.uint(period as u64).unwrap();
            e.uint(1).unwrap();
            e.uint(0).unwrap();
            e.array(18).unwrap();
            e.uint(1).unwrap();
            e.uint(1).unwrap();
            e.bytes(generation.as_bytes()).unwrap();
            e.uint(1).unwrap();
            e.bytes(&[0x61; 16]).unwrap();
            e.bytes(&[0x62; 32]).unwrap();
            e.bytes(pool.as_bytes()).unwrap();
            e.bytes(incarnation.as_bytes()).unwrap();
            e.bytes(&vk).unwrap();
            e.uint(64).unwrap();
            e.uint(period as u64).unwrap();
            e.bytes(key.canonical_state().unwrap().bytes()).unwrap();
            e.uint(2).unwrap();
            e.array(4).unwrap();
            e.uint(1).unwrap();
            e.bytes(generation.as_bytes()).unwrap();
            e.uint(u64::from(reference.total_length)).unwrap();
            e.bytes(&reference.digest).unwrap();
            e.bytes(&backup_digest).unwrap();
            e.bytes(&recipient_id).unwrap();
            e.bytes(certificate).unwrap();
            e.uint(0).unwrap();
            e.null().unwrap();
            let len = e.finish().unwrap().encoded().len();
            body.truncate(len);
            body
        });
        Self {
            context,
            layout: JournalLayout::pool(0).unwrap(),
            vk,
            root: fresh_storage_root(),
            bodies,
            object: object_bytes,
        }
    }
    // Explicit protected-lab OTP duplication for independent encrypted flash worlds.
    pub fn journal(&self) -> Journal<PoolCodec> {
        Journal::new(self.context, self.layout, &self.root).unwrap()
    }
    pub fn journal_in_context(&self, context: JournalContext) -> Journal<PoolCodec> {
        Journal::new(context, self.layout, &self.root).unwrap()
    }
    pub fn pool_state(&self, revision: u64) -> PoolRegistration {
        PoolCodec::decode(&self.bodies[revision as usize], self.context).unwrap()
    }
    pub fn body_bytes(&self, revision: usize) -> &[u8] {
        &self.bodies[revision]
    }
    pub fn body(&self, revision: usize) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.body_bytes(revision).to_vec())
    }
    pub fn populated_flash(&self) -> NorFlash {
        let mut flash = NorFlash::new(32768);
        flash
            .install_public_object(self.layout.object_offset(0).unwrap(), &self.object)
            .unwrap();
        flash
    }
}
