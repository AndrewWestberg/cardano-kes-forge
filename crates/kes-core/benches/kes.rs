use core::hint::black_box;
use std::time::Duration;

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use kes_core::{
    SIGNATURE_BYTES,
    cbor::{Encoder, Value},
    crypto::{Generation, KesKey, PublicTreeBuffer, SUM6_V1, verify},
    journal::{
        Flash, FlashRules, Journal, JournalContext, JournalLayout, JournalScope, JournalWorkspace,
        ObjectWorkspace, PoolCodec, SecretCache, SnapshotCodec, Workspaces,
    },
    state::{Actor, Enrollment, GenerationSpec, KESGeneration, PoolRegistration, PublicObject},
    types::{
        DeviceId, GenerationId, GenerationNumber, HardwareSlot, IncarnationId, KesLifetime,
        ManagementSequence, NetworkBinding, RelativePeriod, RequestId, Revision,
    },
};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use sha2::{Digest, Sha256};

const PERIODS: u64 = 64;
const JOURNAL_BYTES: usize = 32 * 1024;

struct RamFlash {
    bytes: Vec<u8>,
}

impl RamFlash {
    fn erased() -> Self {
        Self {
            bytes: vec![0xff; JOURNAL_BYTES],
        }
    }
}

impl Flash for RamFlash {
    type Error = ();

    fn capacity(&self) -> u32 {
        self.bytes.len() as u32
    }

    fn rules(&self) -> FlashRules {
        FlashRules::OnceOnlyClean
    }

    fn read(&mut self, offset: u32, output: &mut [u8]) -> Result<(), Self::Error> {
        let start = offset as usize;
        output.copy_from_slice(self.bytes.get(start..start + output.len()).ok_or(())?);
        Ok(())
    }

    fn program_page(&mut self, offset: u32, page: &[u8; 256]) -> Result<(), Self::Error> {
        let start = offset as usize;
        if !start.is_multiple_of(256) {
            return Err(());
        }
        let output = self.bytes.get_mut(start..start + page.len()).ok_or(())?;
        if output.iter().zip(page).any(|(old, new)| old & new != *new) {
            return Err(());
        }
        output
            .iter_mut()
            .zip(page)
            .for_each(|(old, new)| *old &= *new);
        Ok(())
    }

    fn erase_sector(&mut self, offset: u32) -> Result<(), Self::Error> {
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

struct Buffers {
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

    fn work(&mut self) -> Workspaces<'_> {
        Workspaces {
            journal: &mut self.journal,
            object: &mut self.object,
            cache: &mut self.cache,
        }
    }
}

fn relative(period: u64) -> RelativePeriod {
    RelativePeriod::new(period).unwrap()
}

fn generated(seed_byte: u8) -> (KesKey, PublicTreeBuffer) {
    let mut seed = [seed_byte; 32];
    let mut generation = Generation::begin(&mut seed, KesLifetime::new(PERIODS).unwrap()).unwrap();
    for _ in 0..PERIODS {
        black_box(generation.step().unwrap());
    }
    black_box(generation.finish().unwrap())
}

fn evolution_inputs() -> (
    Vec<[u8; kes_core::SIGNING_STATE_BYTES]>,
    PublicTreeBuffer,
    [u8; 32],
) {
    let (mut key, tree) = generated(0x42);
    let verification_key = key.verification_key().unwrap();
    let cache = tree.verify(&verification_key).unwrap();
    let mut states = Vec::with_capacity(PERIODS as usize);
    states.push(*key.canonical_state().unwrap().bytes());
    for period in 1..PERIODS {
        key.evolve_to(relative(period), &cache).unwrap();
        states.push(*key.canonical_state().unwrap().bytes());
    }
    (states, tree, verification_key)
}

fn benchmark_generation(criterion: &mut Criterion) {
    criterion.bench_function("generation/sum6_64_leaves", |bench| {
        bench.iter_batched(
            || [0x31; 32],
            |mut seed| {
                let mut generation =
                    Generation::begin(&mut seed, KesLifetime::new(PERIODS).unwrap()).unwrap();
                for _ in 0..PERIODS {
                    black_box(generation.step().unwrap());
                }
                let (key, tree) = black_box(generation.finish().unwrap());
                black_box(tree.as_bytes());
                black_box(key.verification_key().unwrap());
            },
            BatchSize::LargeInput,
        );
    });
}

fn benchmark_evolution(criterion: &mut Criterion) {
    let (states, tree, verification_key) = evolution_inputs();
    let cache = tree.verify(&verification_key).unwrap();
    let lifetime = KesLifetime::new(PERIODS).unwrap();
    let mut group = criterion.benchmark_group("evolution");
    for from in 0..PERIODS - 1 {
        let state = states[from as usize];
        let target = relative(from + 1);
        group.bench_with_input(
            BenchmarkId::new("boundary", format_args!("{from:02}_to_{:02}", from + 1)),
            &from,
            |bench, _| {
                bench.iter_batched(
                    || KesKey::from_canonical(SUM6_V1, &state, relative(from), lifetime).unwrap(),
                    |mut key| {
                        key.evolve_to(target, &cache).unwrap();
                        black_box(key.canonical_state().unwrap().bytes());
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn benchmark_signing(criterion: &mut Criterion) {
    let (states, _, verification_key) = evolution_inputs();
    let lifetime = KesLifetime::new(PERIODS).unwrap();
    let period = relative(32);
    let key = KesKey::from_canonical(SUM6_V1, &states[32], period, lifetime).unwrap();
    let messages = [
        ("0", vec![]),
        ("256", vec![0x52; 256]),
        ("4096", vec![0x53; 4096]),
    ];
    let mut group = criterion.benchmark_group("sign");
    for (name, message) in &messages {
        group.bench_with_input(
            BenchmarkId::new("bytes", name),
            message,
            |bench, message| {
                bench.iter(|| {
                    let mut signature = [0; SIGNATURE_BYTES];
                    key.sign_into(period, black_box(message), &mut signature)
                        .unwrap();
                    black_box(signature);
                });
            },
        );
    }
    group.finish();

    let mut signatures = Vec::with_capacity(messages.len());
    for (_, message) in &messages {
        let mut signature = [0; SIGNATURE_BYTES];
        key.sign_into(period, message, &mut signature).unwrap();
        signatures.push(signature);
    }
    let mut group = criterion.benchmark_group("verify");
    for ((name, message), signature) in messages.iter().zip(&signatures) {
        group.bench_with_input(
            BenchmarkId::new("bytes", name),
            message,
            |bench, message| {
                bench.iter(|| {
                    verify(
                        black_box(&verification_key),
                        period,
                        lifetime,
                        black_box(message),
                        black_box(signature),
                    )
                    .unwrap();
                });
            },
        );
    }
    group.finish();
}

fn encode_codec(output: &mut [u8; 8192], message: &[u8]) -> usize {
    let mut encoder = Encoder::new(output);
    encoder.map(4).unwrap();
    encoder.text("period").unwrap();
    encoder.uint(63).unwrap();
    encoder.text("message").unwrap();
    encoder.bytes(message).unwrap();
    encoder.text("operation").unwrap();
    encoder.uint(8).unwrap();
    encoder.text("requestId").unwrap();
    encoder.bytes(&[0x61; 16]).unwrap();
    encoder.finish().unwrap().encoded().len()
}

fn benchmark_codecs(criterion: &mut Criterion) {
    let message = [0x5a; 4096];
    criterion.bench_function("codec/cbor_encode_4096", |bench| {
        let mut output = [0; 8192];
        bench.iter(|| black_box(encode_codec(&mut output, black_box(&message))));
    });
    let mut encoded = [0; 8192];
    let length = encode_codec(&mut encoded, &message);
    criterion.bench_function("codec/cbor_decode_4096", |bench| {
        bench.iter(|| {
            let map = Value::parse(black_box(&encoded[..length]))
                .unwrap()
                .map()
                .unwrap();
            black_box(map.required("message").unwrap().bytes().unwrap());
            black_box(map.required("operation").unwrap().uint().unwrap());
            black_box(map.required("period").unwrap().uint().unwrap());
            black_box(map.required("requestId").unwrap().bytes().unwrap());
        });
    });
}

fn staged_pool() -> (PoolRegistration, JournalContext) {
    let incarnation = IncarnationId::from_bytes([0x21; 16]);
    let network =
        NetworkBinding::from_genesis_bytes(42, b"benchmark genesis", 129_600, 64).unwrap();
    let recipient_public_key = [0x32; 32];
    let recipient_id = Sha256::digest(recipient_public_key).into();
    let mut pool = PoolRegistration::new(
        Actor::Management,
        Enrollment {
            incarnation,
            cold_verification_key: [0x41; 32],
            network,
            machine_public_key: [0x42; 32],
            recipient_public_key,
            recipient_id,
            management_sequence: ManagementSequence::new(1),
            management_request: RequestId::from_bytes([0x43; 16]),
            management_payload_digest: [0x44; 32],
        },
    )
    .unwrap();
    let actor = Actor::Pool {
        pool: pool.pool_id(),
        incarnation,
    };
    let (key, tree) = generated(0x45);
    let verification_key = key.verification_key().unwrap();
    let generation_id = GenerationId::from_bytes([0x46; 16]);
    let cache = tree.verify(&verification_key).unwrap();
    let object = PublicObject::from_parts(
        generation_id,
        cache.as_bytes(),
        include_bytes!("../../../fuzz/corpus/frame/backup-public-structure"),
        &verification_key,
    )
    .unwrap();
    let staged = KESGeneration::new_staged(
        GenerationSpec {
            generation_id,
            generation_number: GenerationNumber::new(1),
            creation_request: RequestId::from_bytes([0x47; 16]),
            creation_payload_digest: [0x48; 32],
            pool: pool.pool_id(),
            incarnation,
            verification_key,
            lifetime: KesLifetime::new(PERIODS).unwrap(),
            recipient_id,
            public_object: object,
        },
        key,
    )
    .unwrap();
    let policy = pool.generation_policy();
    pool.stage(actor, Revision::new(0), staged, policy).unwrap();
    let context = JournalContext {
        device: DeviceId::from_bytes([0x49; 16]),
        scope: JournalScope::Pool {
            slot: HardwareSlot::new(0).unwrap(),
            pool: pool.pool_id(),
            incarnation,
        },
    };
    (pool, context)
}

fn blank_pool() -> (PoolRegistration, JournalContext) {
    let incarnation = IncarnationId::from_bytes([0x51; 16]);
    let network =
        NetworkBinding::from_genesis_bytes(42, b"journal benchmark genesis", 129_600, 64).unwrap();
    let recipient_public_key = [0x52; 32];
    let recipient_id = Sha256::digest(recipient_public_key).into();
    let pool = PoolRegistration::new(
        Actor::Management,
        Enrollment {
            incarnation,
            cold_verification_key: [0x53; 32],
            network,
            machine_public_key: [0x54; 32],
            recipient_public_key,
            recipient_id,
            management_sequence: ManagementSequence::new(1),
            management_request: RequestId::from_bytes([0x55; 16]),
            management_payload_digest: [0x56; 32],
        },
    )
    .unwrap();
    let context = JournalContext {
        device: DeviceId::from_bytes([0x57; 16]),
        scope: JournalScope::Pool {
            slot: HardwareSlot::new(0).unwrap(),
            pool: pool.pool_id(),
            incarnation,
        },
    };
    (pool, context)
}

fn journal(context: JournalContext) -> Journal<PoolCodec> {
    Journal::new(context, JournalLayout::pool(0).unwrap(), &[0x58; 32]).unwrap()
}

fn benchmark_journal(criterion: &mut Criterion) {
    let (pool, context) = staged_pool();
    let mut encoded = [0; 8192];
    let length = PoolCodec::encode(&pool, context, &mut encoded).unwrap();
    criterion.bench_function("journal/snapshot_encode_staged", |bench| {
        let mut output = [0; 8192];
        bench
            .iter(|| black_box(PoolCodec::encode(black_box(&pool), context, &mut output).unwrap()));
    });
    criterion.bench_function("journal/snapshot_decode_staged", |bench| {
        bench
            .iter(|| black_box(PoolCodec::decode(black_box(&encoded[..length]), context).unwrap()));
    });

    criterion.bench_function("journal/initialize_authenticated", |bench| {
        bench.iter_batched(
            || {
                let (pool, context) = blank_pool();
                (
                    pool,
                    journal(context),
                    RamFlash::erased(),
                    ChaCha20Rng::from_seed([0x59; 32]),
                    Buffers::new(),
                )
            },
            |(pool, journal, mut flash, mut entropy, mut buffers)| {
                black_box(
                    journal
                        .initialize(&mut flash, &mut entropy, &pool, &mut buffers.work())
                        .unwrap(),
                );
            },
            BatchSize::LargeInput,
        );
    });

    criterion.bench_function("journal/recover_authenticated", |bench| {
        bench.iter_batched(
            || {
                let (pool, context) = blank_pool();
                let journal = journal(context);
                let mut flash = RamFlash::erased();
                let mut entropy = ChaCha20Rng::from_seed([0x5a; 32]);
                let mut buffers = Buffers::new();
                journal
                    .initialize(&mut flash, &mut entropy, &pool, &mut buffers.work())
                    .unwrap();
                (journal, flash, entropy, buffers)
            },
            |(journal, mut flash, mut entropy, mut buffers)| {
                black_box(
                    journal
                        .recover(&mut flash, &mut entropy, &mut buffers.work())
                        .unwrap(),
                );
            },
            BatchSize::LargeInput,
        );
    });
}

fn controlled_delay() {
    let delay = std::env::var("KES_BENCH_CONTROLLED_DELAY_US")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    if delay != 0 {
        std::thread::sleep(Duration::from_micros(delay));
    }
}

fn benchmark_sensitivity(criterion: &mut Criterion) {
    criterion.bench_function("sensitivity/controlled_delay", |bench| {
        bench.iter(|| {
            controlled_delay();
            black_box(Sha256::digest(black_box(
                b"public performance sensitivity probe",
            )));
        });
    });
}

fn print_metadata() {
    println!(
        "KES_BENCH_METADATA {{\"version\":1,\"core_allocations_per_operation\":0,\"maximum_message_bytes\":4096,\"journal_workspace_bytes\":{},\"object_workspace_bytes\":{},\"secret_cache_bytes\":{},\"public_tree_bytes\":{},\"signing_state_bytes\":{},\"signature_bytes\":{},\"evolution_boundaries\":63}}",
        std::mem::size_of::<JournalWorkspace>(),
        std::mem::size_of::<ObjectWorkspace>(),
        std::mem::size_of::<SecretCache>(),
        std::mem::size_of::<PublicTreeBuffer>(),
        kes_core::SIGNING_STATE_BYTES,
        SIGNATURE_BYTES,
    );
}

fn benchmarks(criterion: &mut Criterion) {
    print_metadata();
    benchmark_generation(criterion);
    benchmark_evolution(criterion);
    benchmark_signing(criterion);
    benchmark_codecs(criterion);
    benchmark_journal(criterion);
    benchmark_sensitivity(criterion);
}

criterion_group! {
    name = core_benches;
    config = Criterion::default()
        .sample_size(100)
        .warm_up_time(Duration::from_secs(5))
        .measurement_time(Duration::from_secs(10));
    targets = benchmarks
}
criterion_main!(core_benches);
