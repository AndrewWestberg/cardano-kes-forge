#![no_main]
// Build with cargo-fuzz --no-trace-compares. Runtime disables comparison,
// memmem and value hints too: private runtime bytes must never enter generated
// corpus/dictionaries. Input is a PUBLIC mutation/cut script, never key entropy.
#[path = "../../crates/kes-core/tests/journal_faults/fixtures.rs"]
mod fixtures;
#[path = "../../crates/kes-core/tests/journal_faults/flash.rs"]
mod flash;
use fixtures::{Fixture, OsEntropy};
use flash::NorFlash;
use kes_core::crypto::verify;
use kes_core::journal::{
    FlashRules, Journal, JournalError, JournalWorkspace, Mutation, ObjectWorkspace, PoolCodec,
    ReadyToken, SecretCache, SnapshotCodec, Workspaces,
};
use kes_core::state::{Lifecycle, PoolRegistration};
use kes_core::types::HardwareSlot;
use libfuzzer_sys::fuzz_target;
use rand_chacha::rand_core::TryRngCore;
use std::sync::{
    Once,
    atomic::{AtomicU64, Ordering},
};
static CHECKS: AtomicU64 = AtomicU64::new(0);
static VIOLATIONS: AtomicU64 = AtomicU64::new(0);
static INIT: Once = Once::new();
extern "C" fn summary() {
    println!(
        "KES_FUZZ_SUMMARY {{\"version\":1,\"semantic_checks\":{},\"violations\":{}}}",
        CHECKS.load(Ordering::Relaxed),
        VIOLATIONS.load(Ordering::Relaxed)
    );
}
fn check(ok: bool) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        VIOLATIONS.fetch_add(1, Ordering::Relaxed);
        std::process::exit(1);
    }
}
fn privacy_failure() -> ! {
    eprintln!("snapshot fuzzing requires private-safe hint flags and protected fresh runtime");
    std::process::exit(2);
}
fn initialize() {
    INIT.call_once(|| {
        // No pointers across FFI; callback never unwinds and emits counts only.
        if unsafe { libc::atexit(summary) } != 0 {
            std::process::exit(2);
        }
        let required = [
            ("-use_cmp=", "-use_cmp=0"),
            ("-use_memmem=", "-use_memmem=0"),
            ("-use_value_profile=", "-use_value_profile=0"),
        ];
        let mut seen = [false; 3];
        for argument in std::env::args().skip(1) {
            for (index, (prefix, exact)) in required.iter().enumerate() {
                if argument.starts_with(prefix) {
                    if seen[index] || argument != *exact {
                        privacy_failure();
                    }
                    seen[index] = true;
                }
            }
        }
        if seen != [true; 3] || xtask::oracles::protect_memory().is_err() {
            privacy_failure();
        }
    });
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
    fn dirty(&mut self, rng: &mut OsEntropy) {
        self.cache.with_bytes_mut(|bytes| {
            rng.try_fill_bytes(bytes)
                .expect("runtime cache entropy unavailable")
        });
    }
}
fn selector(data: &[u8]) -> usize {
    data.iter()
        .skip(1)
        .take(4)
        .fold(0usize, |n, b| (n << 8) | usize::from(*b))
}
fn observe(state: &PoolRegistration, fixture: &Fixture) -> Option<u8> {
    let current = state.current()?;
    check(current.verification_key() == &fixture.vk);
    if let Some(key) = current.secret().key() {
        let period = current.relative_period();
        let mut signature = [0u8; 448];
        let message = b"public authenticated snapshot fuzz observation";
        check(key.sign_into(period, message, &mut signature).is_ok());
        check(verify(&fixture.vk, period, current.lifetime(), message, &signature).is_ok());
        Some(period.get())
    } else {
        check(current.lifecycle() == Lifecycle::CurrentExpired);
        None
    }
}
fn mutate(
    journal: &Journal<PoolCodec>,
    flash: &mut NorFlash,
    rng: &mut OsEntropy,
    token: &ReadyToken,
    old: &mut PoolRegistration,
    next: &PoolRegistration,
    buffers: &mut Buffers,
) -> Result<ReadyToken, JournalError> {
    journal.transact(
        flash,
        rng,
        Mutation {
            expected: token,
            successor: next,
            retired: old,
        },
        &mut buffers.work(),
    )
}
fn full_success(
    fixture: &Fixture,
    journal: &Journal<PoolCodec>,
    base: &NorFlash,
    token: &ReadyToken,
    rng: &mut OsEntropy,
) -> (NorFlash, ReadyToken, usize) {
    let mut flash = base.copy_world();
    let mut old = fixture.pool_state(0);
    let next = fixture.pool_state(1);
    let mut buffers = Buffers::new();
    buffers.dirty(rng);
    let ready = mutate(
        journal,
        &mut flash,
        rng,
        token,
        &mut old,
        &next,
        &mut buffers,
    )
    .unwrap();
    check(old.current().unwrap().is_secret_erased());
    check(buffers.cache.is_erased());
    check(observe(&next, fixture) == Some(1));
    let erased = fixture.layout.bank_offset(token.bank()).unwrap() as usize;
    check(
        flash.raw()[erased..erased + fixture.layout.bank_bytes()]
            .iter()
            .all(|&byte| byte == 0xff),
    );
    let steps = flash.steps();
    (flash, ready, steps)
}
fn cut_case(
    fixture: &Fixture,
    journal: &Journal<PoolCodec>,
    base: &NorFlash,
    token: &ReadyToken,
    rng: &mut OsEntropy,
    cut: usize,
) {
    let mut flash = base.copy_world();
    flash.arm_cut_after_bits(cut);
    let mut old = fixture.pool_state(0);
    let next = fixture.pool_state(1);
    let mut buffers = Buffers::new();
    buffers.dirty(rng);
    let acknowledged = match mutate(
        journal,
        &mut flash,
        rng,
        token,
        &mut old,
        &next,
        &mut buffers,
    ) {
        Ok(_) => true,
        Err(JournalError::Flash) => false,
        Err(_) => {
            check(false);
            return;
        }
    };
    let offset = fixture.layout.commit_offset(1 - token.bank()).unwrap();
    let committed = flash.completed_page(offset);
    let touched = flash.raw()[offset as usize..offset as usize + 256]
        .iter()
        .any(|&byte| byte != 0xff);
    // Simulated reboot drops all old volatile owners, not just their names.
    drop(old);
    drop(next);
    drop(buffers);
    flash.disarm();
    let mut reboot = Buffers::new();
    reboot.dirty(rng);
    match journal.recover(&mut flash, rng, &mut reboot.work()) {
        Ok(recovered) => {
            let period = observe(&recovered.state, fixture);
            check(
                period
                    == Some(if committed || acknowledged || touched {
                        1
                    } else {
                        0
                    }),
            );
            check(reboot.cache.is_erased());
            let obsolete = fixture
                .layout
                .bank_offset(1 - recovered.token.bank())
                .unwrap() as usize;
            check(
                flash.raw()[obsolete..obsolete + fixture.layout.bank_bytes()]
                    .iter()
                    .all(|&byte| byte == 0xff),
            );
        }
        Err(JournalError::Damaged) => check(touched && !committed && !acknowledged),
        Err(_) => check(false),
    }
}
fn damage_authority(
    fixture: &Fixture,
    journal: &Journal<PoolCodec>,
    mut flash: NorFlash,
    token: &ReadyToken,
    rng: &mut OsEntropy,
    data: &[u8],
) {
    let start = fixture.layout.bank_offset(token.bank()).unwrap() as usize;
    let length = 128
        + usize::from(u16::from_be_bytes([
            flash.raw()[start + 14],
            flash.raw()[start + 15],
        ]));
    let offset = start + selector(data) % length;
    let replacement = flash.raw()[offset] ^ 1;
    flash.replace_range(offset, &[replacement]).unwrap();
    let mut buffers = Buffers::new();
    check(matches!(
        journal.recover(&mut flash, rng, &mut buffers.work()),
        Err(JournalError::Damaged)
    ));
}
fn damage_object(
    fixture: &Fixture,
    journal: &Journal<PoolCodec>,
    mut flash: NorFlash,
    rng: &mut OsEntropy,
) {
    flash
        .corrupt(fixture.layout.object_offset(0).unwrap() as usize, 1)
        .unwrap();
    let mut buffers = Buffers::new();
    check(matches!(
        journal.recover(&mut flash, rng, &mut buffers.work()),
        Err(JournalError::Damaged)
    ));
}
fn payload_invariants(fixture: &Fixture, data: &[u8]) {
    let mut body = fixture.body(1);
    let index = selector(data) % body.len();
    body[index] ^= data.last().copied().unwrap_or(1) | 1;
    if let Ok(state) = PoolCodec::decode(&body, fixture.context) {
        let kes_core::journal::JournalScope::Pool { pool, .. } = fixture.context.scope else {
            check(false);
            return;
        };
        check(state.pool_id() == pool);
        if let Some(current) = state.current() {
            check(current.pool_id() == state.pool_id());
            check(current.incarnation() == state.incarnation());
            check(current.number().get() <= state.generation_high_water().get());
            if current.secret().key().is_some() {
                let _ = observe(&state, fixture);
            }
        }
    }
}
fn scope_invariant(fixture: &Fixture, mut flash: NorFlash, rng: &mut OsEntropy) {
    let mut context = fixture.context;
    if let kes_core::journal::JournalScope::Pool {
        pool, incarnation, ..
    } = context.scope
    {
        context.scope = kes_core::journal::JournalScope::Pool {
            slot: HardwareSlot::new(1).unwrap(),
            pool,
            incarnation,
        };
    }
    let other = fixture.journal_in_context(context);
    let mut buffers = Buffers::new();
    check(matches!(
        other.recover(&mut flash, rng, &mut buffers.work()),
        Err(JournalError::Damaged)
    ));
}
fn unauthenticated_noise(
    fixture: &Fixture,
    journal: &Journal<PoolCodec>,
    rng: &mut OsEntropy,
    data: &[u8],
) {
    let mut flash = fixture.populated_flash();
    let length = data.len().min(256);
    flash.replace_range(0, &data[..length]).unwrap();
    let mut buffers = Buffers::new();
    let result = journal.recover(&mut flash, rng, &mut buffers.work());
    if data[..length].iter().all(|&byte| byte == 0xff) {
        check(matches!(result, Err(JournalError::Uninitialized)));
    } else {
        check(matches!(
            result,
            Err(JournalError::NotCommitted | JournalError::Damaged)
        ));
    }
}
fn entropy_failure(
    fixture: &Fixture,
    journal: &Journal<PoolCodec>,
    base: &NorFlash,
    token: &ReadyToken,
    rng: &mut OsEntropy,
) {
    let mut flash = base.copy_world();
    let mut old = fixture.pool_state(0);
    let next = fixture.pool_state(1);
    let mut buffers = Buffers::new();
    let mut failed = OsEntropy::failing();
    check(matches!(
        mutate(
            journal,
            &mut flash,
            &mut failed,
            token,
            &mut old,
            &next,
            &mut buffers
        ),
        Err(JournalError::EntropyFailure)
    ));
    check(flash.raw() == base.raw());
    let recovered = journal
        .recover(&mut flash, rng, &mut buffers.work())
        .unwrap();
    check(observe(&recovered.state, fixture) == Some(0));
}
fuzz_target!(|data: &[u8]| {
    initialize();
    let fixture = Fixture::new();
    let journal = fixture.journal();
    let mut rng = OsEntropy::new();
    let mut base = fixture.populated_flash();
    if data.get(1).is_some_and(|byte| byte & 1 != 0) {
        base.set_rules(FlashRules::QualifiedIdenticalCleanRetry);
    }
    let initial = fixture.pool_state(0);
    let mut buffers = Buffers::new();
    let token = journal
        .initialize(&mut base, &mut rng, &initial, &mut buffers.work())
        .unwrap();
    let (full, ready, steps) = full_success(&fixture, &journal, &base, &token, &mut rng);
    match data.first().copied().unwrap_or(0) % 8 {
        0 => {
            let mut flash = full;
            let mut work = Buffers::new();
            let recovered = journal
                .recover(&mut flash, &mut rng, &mut work.work())
                .unwrap();
            check(observe(&recovered.state, &fixture) == Some(1));
        }
        1 => cut_case(
            &fixture,
            &journal,
            &base,
            &token,
            &mut rng,
            selector(data) % (steps + 1),
        ),
        2 => damage_authority(&fixture, &journal, full, &ready, &mut rng, data),
        3 => damage_object(&fixture, &journal, full, &mut rng),
        4 => payload_invariants(&fixture, data),
        5 => scope_invariant(&fixture, full, &mut rng),
        6 => unauthenticated_noise(&fixture, &journal, &mut rng, data),
        7 => entropy_failure(&fixture, &journal, &base, &token, &mut rng),
        _ => unreachable!(),
    }
});
