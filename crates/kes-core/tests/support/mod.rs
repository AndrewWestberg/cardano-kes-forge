use ed25519_dalek::{Signer, SigningKey};
use kes_core::{
    activation::DurablePool,
    cbor::Encoder,
    crypto::{Generation, KesKey, PublicTreeBuffer},
    journal::{
        Flash, FlashRules, Journal, JournalContext, JournalLayout, JournalScope, JournalWorkspace,
        ObjectWorkspace, PoolCodec, SecretCache, Workspaces,
    },
    state::{Actor, Enrollment, GenerationSpec, KESGeneration, PoolRegistration, PublicObject},
    types::{
        DeviceId, GenerationId, GenerationNumber, HardwareSlot, IncarnationId, KesLifetime,
        ManagementSequence, NetworkBinding, RequestId, Revision,
    },
};
use rand_chacha::rand_core::{TryCryptoRng, TryRngCore};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read},
};
use zeroize::Zeroizing;
pub(super) struct TestFlash {
    bytes: Vec<u8>,
    fail_next_mutation: bool,
}
impl TestFlash {
    fn new(capacity: usize) -> Self {
        Self {
            bytes: vec![0xff; capacity],
            fail_next_mutation: false,
        }
    }
    pub(super) fn install_public_object(&mut self, offset: u32, object: &[u8]) {
        let start = offset as usize;
        self.bytes[start..start + object.len()].copy_from_slice(object);
    }
    #[allow(dead_code)] // Used by the operations test target; this module is shared.
    pub(super) fn fail_next_mutation(&mut self) {
        self.fail_next_mutation = true;
    }
}
impl Flash for TestFlash {
    type Error = ();

    fn capacity(&self) -> u32 {
        self.bytes.len() as u32
    }
    fn rules(&self) -> FlashRules {
        FlashRules::OnceOnlyClean
    }
    fn read(&mut self, offset: u32, output: &mut [u8]) -> Result<(), Self::Error> {
        let start = offset as usize;
        let end = start.checked_add(output.len()).ok_or(())?;
        output.copy_from_slice(self.bytes.get(start..end).ok_or(())?);
        Ok(())
    }
    fn program_page(&mut self, offset: u32, page: &[u8; 256]) -> Result<(), Self::Error> {
        if core::mem::take(&mut self.fail_next_mutation) {
            return Err(());
        }
        let start = offset as usize;
        if !start.is_multiple_of(256) {
            return Err(());
        }
        let target = self.bytes.get_mut(start..start + 256).ok_or(())?;
        if target.iter().zip(page).any(|(old, new)| old & new != *new) {
            return Err(());
        }
        for (old, new) in target.iter_mut().zip(page) {
            *old &= *new;
        }
        Ok(())
    }
    fn erase_sector(&mut self, offset: u32) -> Result<(), Self::Error> {
        if core::mem::take(&mut self.fail_next_mutation) {
            return Err(());
        }
        let start = offset as usize;
        if !start.is_multiple_of(4096) {
            return Err(());
        }
        self.bytes
            .get_mut(start..start + 4096)
            .ok_or(())?
            .fill(0xff);
        Ok(())
    }
    fn invalidate_cache(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

pub(super) struct OsEntropy(File);
impl OsEntropy {
    fn new() -> Self {
        xtask::oracles::protect_memory().expect("fresh no-swap disposable lab required");
        Self(File::open("/dev/urandom").unwrap())
    }
}
impl TryRngCore for OsEntropy {
    type Error = io::Error;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_ne_bytes(bytes))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_ne_bytes(bytes))
    }
    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        self.0.read_exact(output)
    }
}
impl TryCryptoRng for OsEntropy {}

pub(super) struct Buffers {
    journal: JournalWorkspace,
    object: ObjectWorkspace,
    cache: SecretCache,
}
impl Buffers {
    fn new() -> Self {
        Self {
            journal: JournalWorkspace::new(),
            object: ObjectWorkspace::new(),
            cache: SecretCache::new(),
        }
    }
    pub(super) fn work(&mut self) -> Workspaces<'_> {
        Workspaces {
            journal: &mut self.journal,
            object: &mut self.object,
            cache: &mut self.cache,
        }
    }
}

pub(super) fn certificate(
    cold: &SigningKey,
    kes_vk: &[u8; 32],
    counter: u64,
    start: u64,
) -> Vec<u8> {
    let mut signable = [0; 48];
    signable[..32].copy_from_slice(kes_vk);
    signable[32..40].copy_from_slice(&counter.to_be_bytes());
    signable[40..].copy_from_slice(&start.to_be_bytes());
    let signature = cold.sign(&signable).to_bytes();
    let mut bytes = [0; 154];
    let mut encoder = Encoder::new(&mut bytes);
    encoder.array(2).unwrap();
    encoder.array(4).unwrap();
    encoder.bytes(kes_vk).unwrap();
    encoder.uint(counter).unwrap();
    encoder.uint(start).unwrap();
    encoder.bytes(&signature).unwrap();
    encoder.bytes(&cold.verifying_key().to_bytes()).unwrap();
    encoder.finish().unwrap().encoded().to_vec()
}

pub(super) struct Fixture {
    pub(super) actor: Actor,
    pub(super) cold: SigningKey,
    pub(super) generation: GenerationId,
    pub(super) network: NetworkBinding,
    pub(super) tree: PublicTreeBuffer,
    pub(super) certificate: Vec<u8>,
    pub(super) certificate_digest: [u8; 32],
    pub(super) journal: Journal<PoolCodec>,
    pub(super) layout: JournalLayout,
    pub(super) flash: TestFlash,
    pub(super) entropy: OsEntropy,
    pub(super) buffers: Buffers,
    pub(super) durable: DurablePool,
}
impl Fixture {
    pub(super) fn new() -> Self {
        let mut entropy = OsEntropy::new();
        let mut cold_seed = Zeroizing::new([0; 32]);
        entropy.try_fill_bytes(&mut *cold_seed).unwrap();
        let cold = SigningKey::from_bytes(&cold_seed);
        let cold_vk = cold.verifying_key().to_bytes();
        let mut incarnation_bytes = [0; 16];
        entropy.try_fill_bytes(&mut incarnation_bytes).unwrap();
        let incarnation = IncarnationId::from_bytes(incarnation_bytes);
        let network = NetworkBinding::from_genesis_bytes(
            42,
            b"durable operation regression genesis",
            129_600,
            64,
        )
        .unwrap();
        let recipient_public_key = [0x73; 32];
        let recipient_id = Sha256::digest(recipient_public_key).into();
        let mut pool = PoolRegistration::new(
            Actor::Management,
            Enrollment {
                incarnation,
                cold_verification_key: cold_vk,
                network,
                machine_public_key: [0x61; 32],
                recipient_public_key,
                recipient_id,
                management_sequence: ManagementSequence::new(1),
                management_request: RequestId::from_bytes([0x51; 16]),
                management_payload_digest: [0x52; 32],
            },
        )
        .unwrap();
        let actor = Actor::Pool {
            pool: pool.pool_id(),
            incarnation,
        };
        let context = JournalContext {
            device: DeviceId::from_bytes([0x19; 16]),
            scope: JournalScope::Pool {
                slot: HardwareSlot::new(0).unwrap(),
                pool: pool.pool_id(),
                incarnation,
            },
        };
        let layout = JournalLayout::pool(0).unwrap();
        let mut storage_root = Zeroizing::new([0; 32]);
        entropy.try_fill_bytes(&mut *storage_root).unwrap();
        let journal = Journal::new(context, layout, &storage_root).unwrap();
        let mut flash = TestFlash::new(32 * 1024);
        let mut buffers = Buffers::new();
        let token = journal
            .initialize(&mut flash, &mut entropy, &pool, &mut buffers.work())
            .unwrap();

        let mut seed = Zeroizing::new([0; 32]);
        entropy.try_fill_bytes(&mut *seed).unwrap();
        let lifetime = KesLifetime::new(64).unwrap();
        let mut key = KesKey::erased(lifetime);
        let mut tree = PublicTreeBuffer::new();
        let mut generation_job = Generation::begin(&mut seed, &mut key, &mut tree).unwrap();
        for _ in 0..64 {
            generation_job.step().unwrap();
        }
        let verified_tree = generation_job.finish().unwrap();
        let verification_key = key.verification_key().unwrap();
        let mut generation_bytes = [0; 16];
        entropy.try_fill_bytes(&mut generation_bytes).unwrap();
        let generation = GenerationId::from_bytes(generation_bytes);
        let backup = include_bytes!("../../../../fuzz/corpus/frame/backup-public-structure");
        let object = PublicObject::from_parts(
            generation,
            verified_tree.as_bytes(),
            backup,
            &verification_key,
        )
        .unwrap();
        let object_offset = layout.object_offset(0).unwrap();
        let mut object_bytes = vec![0; usize::from(object.reference().total_length)];
        object.encode_into(&mut object_bytes).unwrap();
        flash.install_public_object(object_offset, &object_bytes);
        let staged = KESGeneration::new_staged(
            GenerationSpec {
                generation_id: generation,
                generation_number: GenerationNumber::new(1),
                creation_request: RequestId::from_bytes([0x62; 16]),
                creation_payload_digest: [0x63; 32],
                pool: pool.pool_id(),
                incarnation,
                verification_key,
                lifetime,
                recipient_id,
                public_object: object,
            },
            key,
        )
        .unwrap();
        let policy = pool.generation_policy();
        pool.stage(actor, Revision::new(0), staged, policy).unwrap();
        let token = journal
            .transact_successor(&mut flash, &mut entropy, &token, &pool, &mut buffers.work())
            .unwrap();
        let certificate = certificate(&cold, &verification_key, 0, 100);
        let certificate_digest = Sha256::digest(&certificate).into();
        let durable = DurablePool::new(pool, token).unwrap();
        Self {
            cold,
            actor,
            generation,
            network,
            tree,
            certificate,
            certificate_digest,
            journal,
            layout,
            flash,
            entropy,
            buffers,
            durable,
        }
    }
}
