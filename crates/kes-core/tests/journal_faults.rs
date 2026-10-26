#[path = "journal_faults/directory.rs"]
mod directory;
#[path = "journal_faults/fixtures.rs"]
mod fixtures;
#[path = "journal_faults/flash.rs"]
mod flash;

use fixtures::{Fixture, OsEntropy};
use flash::NorFlash;
use kes_core::{
    crypto::CryptoError,
    journal::{
        FlashRules, JournalError, JournalWorkspace, Mutation, ObjectWorkspace, PoolCodec,
        ReadyToken, SecretCache, SnapshotCodec, Workspaces,
    },
    state::PoolRegistration,
    types::{RelativePeriod, Revision},
};
use kes_summed_ed25519::{PublicKey, kes::Sum6KesSig, traits::KesSig};
use rand_chacha::rand_core::TryRngCore;

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
    fn dirty_cache(&mut self) {
        let mut rng = OsEntropy::new();
        self.cache.with_bytes_mut(|bytes| {
            rng.try_fill_bytes(bytes)
                .expect("disposable cache entropy unavailable")
        });
    }
}
fn blank(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0xff)
}
fn bank<'a>(f: &Fixture, flash: &'a NorFlash, index: u8) -> &'a [u8] {
    let start = f.layout.bank_offset(index).unwrap() as usize;
    &flash.raw()[start..start + f.layout.bank_bytes()]
}
fn assert_key(state: &PoolRegistration, fixture: &Fixture, period: u64) {
    let key = state
        .current()
        .unwrap()
        .secret()
        .key()
        .expect("ready state must own live KES key");
    assert_eq!(key.period().unwrap().get(), period as u8);
    assert_eq!(key.verification_key().unwrap(), fixture.vk);
    let mut signature = [0; 448];
    let message = b"public journal successor signature challenge";
    key.sign_into(
        RelativePeriod::new(period).unwrap(),
        message,
        &mut signature,
    )
    .unwrap();
    // Independent upstream implementation, not the journal's signature verifier.
    Sum6KesSig::from_bytes(&signature)
        .unwrap()
        .verify(
            period as u32,
            &PublicKey::from_bytes(&fixture.vk).unwrap(),
            message,
        )
        .unwrap();
    if period != 0 {
        assert_eq!(
            key.sign_into(RelativePeriod::new(0).unwrap(), message, &mut [0; 448]),
            Err(CryptoError::PeriodMismatch)
        );
    }
}
fn initialized(f: &Fixture) -> (NorFlash, ReadyToken) {
    let mut flash = f.populated_flash();
    let token = f
        .journal()
        .initialize(
            &mut flash,
            &mut OsEntropy::new(),
            &f.pool_state(0),
            &mut Buffers::new().work(),
        )
        .unwrap();
    (flash, token)
}
fn advance(
    f: &Fixture,
    flash: &mut NorFlash,
    token: &ReadyToken,
    from: u64,
    to: u64,
) -> Result<ReadyToken, JournalError> {
    // These volatile private owners are dropped before the caller reboots.
    let mut retired = f.pool_state(from);
    let successor = f.pool_state(to);
    f.journal().transact(
        flash,
        &mut OsEntropy::new(),
        Mutation {
            expected: token,
            successor: &successor,
            retired: &mut retired,
        },
        &mut Buffers::new().work(),
    )
}
fn recover(
    f: &Fixture,
    flash: &mut NorFlash,
) -> Result<kes_core::journal::Recovered<PoolRegistration>, JournalError> {
    let mut buffers = Buffers::new();
    buffers.dirty_cache();
    let result = f
        .journal()
        .recover(flash, &mut OsEntropy::new(), &mut buffers.work());
    if result.is_ok() {
        assert!(buffers.cache.is_erased());
    }
    result
}
fn completed_steps(f: &Fixture, baseline: &NorFlash, token: &ReadyToken) -> usize {
    let mut world = baseline.copy_world();
    world.arm_cut_after_bits(usize::MAX);
    advance(f, &mut world, token, 0, 1).unwrap();
    world.steps()
}

#[test]
fn gate_sensitivity_detects_acknowledgement_and_erasure_regressions() {
    let Ok(mode) = std::env::var("KES_GATE_MODE") else {
        return;
    };
    if mode == "coverage" || mode == "software-fault-campaign" {
        return;
    }
    let f = Fixture::new();
    let (baseline, token) = initialized(&f);
    let mut committed = baseline.copy_world();
    let acknowledged = advance(&f, &mut committed, &token, 0, 1).unwrap();
    assert_eq!(acknowledged.revision(), Revision::new(1));
    match mode.as_str() {
        "clean" => {
            let recovered = recover(&f, &mut committed).unwrap();
            assert_eq!(recovered.token.revision(), acknowledged.revision());
            assert!(blank(bank(&f, &committed, token.bank())));
            println!(
                "KES_GATE_SUMMARY {{\"version\":1,\"cases\":2,\"scenarios\":{{\"software-journal\":2}},\"measurements\":{{\"violations\":0}}}}"
            );
        }
        "seeded-drop-acknowledged-commit" => {
            let recovered = recover(&f, &mut baseline.copy_world()).unwrap();
            assert!(recovered.token.revision() < acknowledged.revision());
            println!(
                "KES_GATE_SUMMARY {{\"version\":1,\"cases\":1,\"scenarios\":{{\"software-journal\":1}},\"measurements\":{{\"violations\":1,\"counterexample\":{{\"mode\":\"seeded-drop-acknowledged-commit\",\"path\":\"kes-core.journal.recover\",\"observation\":\"acknowledged revision 1 recovered as revision 0 after injected retained-state loss\",\"disclosure\":\"public\"}}}}}}"
            );
            panic!("seeded acknowledged-commit loss detected");
        }
        "seeded-skip-old-bank-erase" => {
            let old = f.layout.bank_offset(token.bank()).unwrap() as usize;
            committed.replace_range(old, &[0]).unwrap();
            assert!(!blank(bank(&f, &committed, token.bank())));
            println!(
                "KES_GATE_SUMMARY {{\"version\":1,\"cases\":1,\"scenarios\":{{\"software-journal\":1}},\"measurements\":{{\"violations\":1,\"counterexample\":{{\"mode\":\"seeded-skip-old-bank-erase\",\"path\":\"kes-core.journal.transact\",\"observation\":\"the acknowledged predecessor bank retained an injected non-erased public ciphertext byte\",\"disclosure\":\"public\"}}}}}}"
            );
            panic!("seeded predecessor erase omission detected");
        }
        "seeded-semantic-authentication-bypass" => {
            let successor = f.layout.bank_offset(acknowledged.bank()).unwrap() as usize;
            committed.corrupt(successor + 300, 1).unwrap();
            assert!(matches!(
                recover(&f, &mut committed),
                Err(JournalError::Damaged | JournalError::NotCommitted)
            ));
            println!(
                "KES_GATE_SUMMARY {{\"version\":1,\"cases\":1,\"scenarios\":{{\"snapshot\":1}},\"measurements\":{{\"violations\":1,\"counterexample\":{{\"mode\":\"seeded-semantic-authentication-bypass\",\"path\":\"kes-core.journal.recover\",\"observation\":\"a one-bit-corrupted authenticated successor snapshot was rejected without predecessor fallback\",\"disclosure\":\"public\"}}}}}}"
            );
            panic!("seeded snapshot authentication bypass detected");
        }
        _ => panic!("unsupported journal gate mode: {mode}"),
    }
}

#[test]
fn ack_means_physical_predecessor_erasure_retired_owner_erasure_and_independent_signature() {
    let f = Fixture::new();
    let (mut flash, old_token) = initialized(&f);
    let mut old = f.pool_state(0);
    let next = f.pool_state(1);
    let mut buffers = Buffers::new();
    buffers.dirty_cache();
    let token = f
        .journal()
        .transact(
            &mut flash,
            &mut OsEntropy::new(),
            Mutation {
                expected: &old_token,
                successor: &next,
                retired: &mut old,
            },
            &mut buffers.work(),
        )
        .unwrap();
    assert_eq!(token.revision(), Revision::new(1));
    assert!(blank(bank(&f, &flash, old_token.bank())));
    let mut cached_read = vec![0; f.layout.bank_bytes()];
    kes_core::journal::Flash::read(
        &mut flash,
        f.layout.bank_offset(old_token.bank()).unwrap(),
        &mut cached_read,
    )
    .unwrap();
    assert!(
        blank(&cached_read),
        "storage cache must not retain predecessor ciphertext"
    );
    for key in PoolCodec::private_keys(&mut old).into_iter().flatten() {
        assert!(!key.is_live());
        assert_eq!(
            key.sign_into(RelativePeriod::new(0).unwrap(), b"retired", &mut [0; 448]),
            Err(CryptoError::ErasedKey)
        );
    }
    assert!(old.current().unwrap().secret().key().is_none());
    assert!(buffers.cache.is_erased());
    assert_key(&next, &f, 1);
    drop(old);
    drop(next);
    drop(buffers);
    let recovered = recover(&f, &mut flash).unwrap();
    assert_eq!(recovered.token.revision(), Revision::new(1));
    assert_key(&recovered.state, &f, 1);
    assert!(blank(bank(&f, &flash, 1 - recovered.token.bank())));
    assert!(blank(&flash.raw()[24576..32768]));
    for _ in 0..3 {
        let recovered = recover(&f, &mut flash).unwrap();
        assert_key(&recovered.state, &f, 1);
    }
}

#[test]
fn every_transaction_prefix_bit_cut_drops_volatile_owners_and_never_rolls_back_commit() {
    if let Ok(mode) = std::env::var("KES_GATE_MODE")
        && mode != "software-fault-campaign"
    {
        return;
    }
    let f = Fixture::new();
    let (baseline, token) = initialized(&f);
    let total = completed_steps(&f, &baseline, &token);
    let erase_bits = f.layout.bank_bytes() * 8;
    let clean_bits = 256 * 8;
    assert!(total > erase_bits + clean_bits);
    let commit_end = total - erase_bits - clean_bits;
    #[derive(Default)]
    struct Counts {
        ready_old: usize,
        ready_new: usize,
        quarantined: usize,
        post_commit: usize,
        interrupted_erase: usize,
    }
    impl Counts {
        fn merge(&mut self, other: Self) {
            self.ready_old += other.ready_old;
            self.ready_new += other.ready_new;
            self.quarantined += other.quarantined;
            self.post_commit += other.post_commit;
            self.interrupted_erase += other.interrupted_erase;
        }
    }
    let worker_limit = if std::env::var("KES_GATE_MODE").as_deref() == Ok("software-fault-campaign")
    {
        32
    } else {
        8
    };
    let workers = std::thread::available_parallelism()
        .map_or(1, usize::from)
        .min(worker_limit)
        .min(total + 1);
    let counts = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for worker in 0..workers {
            let fixture = &f;
            let baseline = &baseline;
            let token = &token;
            handles.push(scope.spawn(move || {
                let mut counts = Counts::default();
                for cut in (worker..=total).step_by(workers) {
                    let mut flash = baseline.copy_world();
                    flash.arm_cut_after_bits(cut);
                    let result = advance(fixture, &mut flash, token, 0, 1);
                    let committed = flash
                        .completed_page(fixture.layout.commit_offset(1 - token.bank()).unwrap());
                    if cut < total {
                        assert!(matches!(result, Err(JournalError::Flash)));
                    } else {
                        assert!(result.is_ok());
                    }
                    // Simulated reboot keeps encrypted/public cells only, no old RAM owner.
                    let mut reboot = flash.copy_world();
                    drop(flash);
                    match recover(fixture, &mut reboot) {
                        Ok(recovered) => {
                            let period = recovered
                                .state
                                .current()
                                .unwrap()
                                .secret()
                                .key()
                                .unwrap()
                                .period()
                                .unwrap()
                                .get();
                            assert!(period == 0 || period == 1);
                            if committed {
                                assert_eq!(period, 1, "completed COMMIT must never roll back");
                                counts.post_commit += 1;
                            }
                            if cut > commit_end && cut < commit_end + erase_bits {
                                counts.interrupted_erase += 1;
                                assert_eq!(period, 1);
                            }
                            if period == 0 {
                                counts.ready_old += 1;
                            } else {
                                counts.ready_new += 1;
                            }
                            assert!(blank(bank(fixture, &reboot, 1 - recovered.token.bank())));
                            assert_key(&recovered.state, fixture, u64::from(period));
                        }
                        Err(error) => {
                            assert!(!committed, "fully committed successor cleanup must recover");
                            assert!(matches!(
                                error,
                                JournalError::Damaged | JournalError::NotCommitted
                            ));
                            counts.quarantined += 1;
                        }
                    }
                }
                counts
            }));
        }
        let mut aggregate = Counts::default();
        for handle in handles {
            aggregate.merge(handle.join().expect("fault-campaign worker panicked"));
        }
        aggregate
    });
    let Counts {
        ready_old,
        ready_new,
        quarantined,
        post_commit,
        interrupted_erase,
    } = counts;
    assert!(
        ready_old > 0
            && ready_new > 0
            && quarantined > 0
            && post_commit > 0
            && interrupted_erase > 0
    );
    assert_eq!(ready_old + ready_new + quarantined, total + 1);
    println!(
        "POOL_JOURNAL_CUTS {{\"bit_attempts\":{total},\"cuts\":{},\"ready_old\":{ready_old},\"ready_new\":{ready_new},\"quarantined\":{quarantined},\"post_commit_ready\":{post_commit},\"interrupted_erase_ready\":{interrupted_erase}}}",
        total + 1
    );
    if std::env::var("KES_GATE_MODE").as_deref() == Ok("software-fault-campaign") {
        println!(
            "KES_GATE_SUMMARY {{\"version\":1,\"cases\":{},\"scenarios\":{{\"software-journal\":{}}},\"measurements\":{{\"violations\":0,\"software_cut_points\":{{\"ready-old\":{ready_old},\"ready-new\":{ready_new},\"quarantined\":{quarantined}}},\"disposable_fixture_authorized\":true,\"network\":\"controlled\",\"ack_regressions\":0,\"lost_retained_artifacts\":0,\"cross_pool_mutations\":0,\"partial_plaintext_publications\":0,\"recovery_failures\":0,\"pool_local_quarantines\":{quarantined},\"device_wide_corruptions\":0}}}}",
            total + 1,
            total + 1
        );
    }
}

#[test]
fn torn_clean_relocates_once_only_but_qualified_identical_retry_keeps_revision() {
    let f = Fixture::new();
    let (baseline, token) = initialized(&f);
    let total = completed_steps(&f, &baseline, &token);
    for rules in [
        FlashRules::OnceOnlyClean,
        FlashRules::QualifiedIdenticalCleanRetry,
    ] {
        for clean_progress in [0, 101] {
            let mut flash = baseline.copy_world();
            flash.set_rules(rules);
            flash.arm_cut_after_bits(total - 2048 + clean_progress);
            assert!(matches!(
                advance(&f, &mut flash, &token, 0, 1),
                Err(JournalError::Flash)
            ));
            let mut reboot = flash.copy_world();
            drop(flash);
            let recovered = recover(&f, &mut reboot).unwrap();
            assert_key(&recovered.state, &f, 1);
            assert_eq!(
                recovered.state.current().unwrap().public_object_ref(),
                f.pool_state(1).current().unwrap().public_object_ref()
            );
            match rules {
                FlashRules::OnceOnlyClean => {
                    assert_eq!(recovered.token.revision(), Revision::new(2));
                    assert_eq!(recovered.state.revision(), Revision::new(2));
                }
                FlashRules::QualifiedIdenticalCleanRetry => {
                    assert_eq!(recovered.token.revision(), Revision::new(1))
                }
            }
            assert!(blank(bank(&f, &reboot, 1 - recovered.token.bank())));
        }
    }
}

#[test]
fn committed_corruption_and_missing_objects_never_fall_back_to_predecessor() {
    let f = Fixture::new();
    let (baseline, token) = initialized(&f);
    let total = completed_steps(&f, &baseline, &token);
    let mut committed = baseline.copy_world();
    committed.arm_cut_after_bits(total - f.layout.bank_bytes() * 8 - 2048);
    assert!(matches!(
        advance(&f, &mut committed, &token, 0, 1),
        Err(JournalError::Flash)
    ));
    committed.disarm();
    let next_bank = 1 - token.bank();
    let base = f.layout.bank_offset(next_bank).unwrap() as usize;
    let length =
        u16::from_be_bytes(committed.raw()[base + 14..base + 16].try_into().unwrap()) as usize;
    for offset in [
        base,
        base + 8,
        base + 13,
        base + 76,
        base + 116,
        base + 128,
        base + 128 + length - 1,
        f.layout.commit_offset(next_bank).unwrap() as usize + 184,
        f.layout.object_offset(0).unwrap() as usize + 64,
    ] {
        let mut world = committed.copy_world();
        world.corrupt(offset, 1).unwrap();
        assert!(
            matches!(recover(&f, &mut world), Err(JournalError::Damaged)),
            "authoritative corruption cannot expose old key"
        );
    }
    let mut world = committed.copy_world();
    world
        .replace_range(
            f.layout.object_offset(0).unwrap() as usize,
            &vec![0xff; 8192],
        )
        .unwrap();
    assert!(matches!(
        recover(&f, &mut world),
        Err(JournalError::Damaged | JournalError::ObjectMissing | JournalError::ObjectInvalid)
    ));
}

#[test]
fn independently_authenticated_mixed_histories_require_exact_parent_witness() {
    let f = Fixture::new();
    let (baseline, token) = initialized(&f);
    let mut a = baseline.copy_world();
    let a1 = advance(&f, &mut a, &token, 0, 1).unwrap();
    let mut b = baseline.copy_world();
    let b1 = advance(&f, &mut b, &token, 0, 1).unwrap();
    // Same logical r1, independently authenticated nonces/COMMIT identities.
    assert_ne!(bank(&f, &a, a1.bank()), bank(&f, &b, b1.bank()));
    let mut a2 = a.copy_world();
    let total = {
        a2.arm_cut_after_bits(usize::MAX);
        advance(&f, &mut a2, &a1, 1, 2).unwrap();
        a2.steps()
    };
    let mut torn = a.copy_world();
    torn.arm_cut_after_bits(total - f.layout.bank_bytes() * 8 - 2048);
    assert!(matches!(
        advance(&f, &mut torn, &a1, 1, 2),
        Err(JournalError::Flash)
    ));
    torn.disarm();
    // Both COMMITs validate separately; B's r1 is not A's authenticated parent.
    torn.replace_range(
        f.layout.bank_offset(b1.bank()).unwrap() as usize,
        bank(&f, &b, b1.bank()),
    )
    .unwrap();
    assert!(matches!(recover(&f, &mut torn), Err(JournalError::Damaged)));
    let a2_token = recover(&f, &mut a2).unwrap().token;
    let a3 = advance(&f, &mut a2, &a2_token, 2, 3).unwrap();
    // r0/r3 are independently valid but cannot be adjacent authorities.
    let mut nonconsecutive = baseline.copy_world();
    nonconsecutive
        .replace_range(
            f.layout.bank_offset(a3.bank()).unwrap() as usize,
            bank(&f, &a2, a3.bank()),
        )
        .unwrap();
    assert!(matches!(
        recover(&f, &mut nonconsecutive),
        Err(JournalError::Damaged)
    ));
}

#[test]
fn erased_is_not_dirty_uncommitted_and_initialization_is_explicit() {
    let f = Fixture::new();
    let mut erased = f.populated_flash();
    assert!(matches!(
        recover(&f, &mut erased),
        Err(JournalError::Uninitialized)
    ));
    erased
        .corrupt(f.layout.bank_offset(0).unwrap() as usize, 1)
        .unwrap();
    assert!(matches!(
        recover(&f, &mut erased),
        Err(JournalError::NotCommitted | JournalError::Damaged)
    ));
    assert!(
        f.journal()
            .initialize(
                &mut erased,
                &mut OsEntropy::new(),
                &f.pool_state(0),
                &mut Buffers::new().work()
            )
            .is_err()
    );
    let (mut initialized, _) = initialized(&f);
    assert!(matches!(
        f.journal().initialize(
            &mut initialized,
            &mut OsEntropy::new(),
            &f.pool_state(0),
            &mut Buffers::new().work()
        ),
        Err(JournalError::AlreadyInitialized)
    ));
}

#[test]
fn entropy_failure_and_stale_or_wrong_scope_tokens_never_mutate_flash() {
    let f = Fixture::new();
    let mut blank_flash = f.populated_flash();
    let before = blank_flash.raw().to_vec();
    assert!(matches!(
        f.journal().initialize(
            &mut blank_flash,
            &mut OsEntropy::failing(),
            &f.pool_state(0),
            &mut Buffers::new().work()
        ),
        Err(JournalError::EntropyFailure)
    ));
    assert_eq!(blank_flash.raw(), before);
    let (mut flash, token) = initialized(&f);
    let before = flash.raw().to_vec();
    let mut old = f.pool_state(0);
    let next = f.pool_state(1);
    assert!(matches!(
        f.journal().transact(
            &mut flash,
            &mut OsEntropy::failing(),
            Mutation {
                expected: &token,
                successor: &next,
                retired: &mut old
            },
            &mut Buffers::new().work()
        ),
        Err(JournalError::EntropyFailure)
    ));
    assert_eq!(flash.raw(), before);
    assert_key(&old, &f, 0);
    let next_token = advance(&f, &mut flash, &token, 0, 1).unwrap();
    let before = flash.raw().to_vec();
    assert!(advance(&f, &mut flash, &token, 0, 1).is_err());
    assert_eq!(flash.raw(), before);
    let other = Fixture::new();
    let (_, other_token) = initialized(&other);
    assert!(advance(&f, &mut flash, &other_token, 1, 2).is_err());
    assert_eq!(flash.raw(), before);
    assert!(
        other
            .journal()
            .recover(
                &mut flash,
                &mut OsEntropy::new(),
                &mut Buffers::new().work()
            )
            .is_err()
    );
    assert_eq!(flash.raw(), before);
    assert_eq!(
        recover(&f, &mut flash).unwrap().token.revision(),
        next_token.revision()
    );
}

#[test]
fn codec_rejects_authenticated_payload_shape_and_private_period_contradictions() {
    let f = Fixture::new();
    for revision in 0..4 {
        let state = f.pool_state(revision);
        assert_eq!(state.revision(), Revision::new(revision));
        assert_key(&state, &f, revision);
        let mut encoded = zeroize::Zeroizing::new([0; 3440]);
        let length = PoolCodec::encode(&state, f.context, &mut *encoded).unwrap();
        assert!(
            encoded[..length] == *f.body_bytes(revision as usize),
            "snapshot must preserve all fields"
        );
    }
    let mut body = f.body(1);
    body[0] = 0x8c;
    assert!(PoolCodec::decode(&body, f.context).is_err());
    let mut body = f.body(1);
    body.push(0);
    assert!(PoolCodec::decode(&body, f.context).is_err());
    let other = Fixture::new();
    assert!(PoolCodec::decode(f.body_bytes(1), other.context).is_err());
    let mut body = f.body(1);
    let (secret_offset, lifecycle_offset) = {
        let pool = kes_core::cbor::Value::parse(&body).unwrap();
        let generation = pool.array().unwrap().nth(11).unwrap();
        let secret = generation
            .array()
            .unwrap()
            .nth(11)
            .unwrap()
            .bytes()
            .unwrap();
        let lifecycle = generation.array().unwrap().nth(12).unwrap();
        (
            secret.as_ptr() as usize - body.as_ptr() as usize,
            lifecycle.encoded().as_ptr() as usize - body.as_ptr() as usize,
        )
    };
    body[lifecycle_offset] = 0;
    assert!(
        PoolCodec::decode(&body, f.context).is_err(),
        "current cannot restore staged lifecycle"
    );
    body[lifecycle_offset] = 2;
    body[secret_offset..secret_offset + 608].fill(0);
    assert!(
        PoolCodec::decode(&body, f.context).is_err(),
        "live period requires a canonical private key"
    );
}

#[test]
fn committed_cleanup_entropy_failure_and_same_root_wrong_context_fail_closed() {
    let f = Fixture::new();
    let (baseline, token) = initialized(&f);
    let total = completed_steps(&f, &baseline, &token);
    let mut torn = baseline.copy_world();
    torn.arm_cut_after_bits(total - 2048);
    assert!(matches!(
        advance(&f, &mut torn, &token, 0, 1),
        Err(JournalError::Flash)
    ));
    let mut reboot = torn.copy_world();
    drop(torn);
    let before = reboot.raw().to_vec();
    assert!(matches!(
        f.journal().recover(
            &mut reboot,
            &mut OsEntropy::failing(),
            &mut Buffers::new().work()
        ),
        Err(JournalError::EntropyFailure)
    ));
    assert_eq!(reboot.raw(), before);
    let recovered = recover(&f, &mut reboot).unwrap();
    assert_key(&recovered.state, &f, 1);
    let before = reboot.raw().to_vec();
    let mut context = f.context;
    context.device = kes_core::types::DeviceId::random(&mut OsEntropy::new()).unwrap();
    let wrong = f.journal_in_context(context);
    assert!(
        wrong
            .recover(
                &mut reboot,
                &mut OsEntropy::new(),
                &mut Buffers::new().work()
            )
            .is_err()
    );
    assert_eq!(reboot.raw(), before);
    let mut context = f.context;
    if let kes_core::journal::JournalScope::Pool {
        pool, incarnation, ..
    } = context.scope
    {
        context.scope = kes_core::journal::JournalScope::Pool {
            slot: kes_core::types::HardwareSlot::new(1).unwrap(),
            pool,
            incarnation,
        };
    }
    assert!(
        f.journal_in_context(context)
            .recover(
                &mut reboot,
                &mut OsEntropy::new(),
                &mut Buffers::new().work()
            )
            .is_err()
    );
    assert_eq!(reboot.raw(), before);
    assert_key(&recover(&f, &mut reboot).unwrap().state, &f, 1);
}

#[test]
fn acknowledged_authority_marker_body_and_object_corruption_is_not_blank_or_fallback() {
    let f = Fixture::new();
    let (mut flash, token) = initialized(&f);
    let next = advance(&f, &mut flash, &token, 0, 1).unwrap();
    let base = f.layout.bank_offset(next.bank()).unwrap() as usize;
    for offset in [
        base + 128,
        f.layout.commit_offset(next.bank()).unwrap() as usize + 184,
        f.layout.clean_offset(next.bank()).unwrap() as usize + 216,
        f.layout.object_offset(0).unwrap() as usize,
    ] {
        let mut world = flash.copy_world();
        world.corrupt(offset, 1).unwrap();
        assert!(matches!(
            recover(&f, &mut world),
            Err(JournalError::Damaged | JournalError::ObjectInvalid)
        ));
    }
}

#[test]
fn recovery_reclaims_only_unreferenced_public_object_slots() {
    let fixture = Fixture::new();
    let (mut flash, _) = initialized(&fixture);
    let referenced = fixture.layout.object_offset(0).unwrap() as usize;
    let orphan = fixture.layout.object_offset(1).unwrap() as usize;
    flash.replace_range(orphan, &[0x5a; 8192]).unwrap();
    assert!(!blank(&flash.raw()[referenced..referenced + 8192]));
    assert!(!blank(&flash.raw()[orphan..orphan + 8192]));

    let recovered = recover(&fixture, &mut flash).unwrap();
    assert_key(&recovered.state, &fixture, 0);
    assert!(!blank(&flash.raw()[referenced..referenced + 8192]));
    assert!(blank(&flash.raw()[orphan..orphan + 8192]));
}
