use super::{device, registration_with_cold};
use ed25519_dalek::{Signer, SigningKey};
use kes_core::crypto::Generation;
use kes_core::state::{
    Actor, CertificationOutcome, Device, DeviceMode, GenerationSpec, KESGeneration, Lifecycle,
    PoolRegistration, PublicObject, StateError,
};
use kes_core::types::{
    GenerationId, GenerationNumber, HardwareSlot, KesLifetime, NetworkBinding, RequestId, Revision,
};
use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::fs::File;
use std::io::Read;
use zeroize::Zeroizing;

#[path = "boundaries.rs"]
mod boundaries;
#[path = "recovery.rs"]
mod recovery;

// Public unauthenticated ciphertext/signature syntax only. This model checks
// object references and RAM policy, not T030 artifact cryptography/publication.
const PUBLIC_ARTIFACT_SYNTAX: &[u8] =
    include_bytes!("../../../../fuzz/corpus/frame/backup-public-structure");
type Operations = Vec<(u8, u8, u8)>;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SeededDefect {
    CrossPoolAuthorization,
}
#[derive(Clone, Copy, Debug, Default)]
struct ExpectedPool {
    enrolled: bool,
    slot: Option<HardwareSlot>,
    revision: u64,
    generation: u64,
    staged: Option<GenerationId>,
    certificate: Option<[u8; 32]>,
    verification_key: Option<[u8; 32]>,
    object_digest: Option<[u8; 32]>,
    backup_digest: Option<[u8; 32]>,
}
struct CaseState {
    device: Device,
    pools: [PoolRegistration; 33],
    expected: [ExpectedPool; 33],
    cold: [SigningKey; 33],
    defect: Option<SeededDefect>,
}
#[derive(Default)]
struct Counts {
    accepted: u64,
    rejected: u64,
    shrinks: u64,
    violations: u64,
    failed_once: bool,
    min: usize,
    max: usize,
    enrolled: u64,
    enroll_rejected: u64,
    observed: u64,
    staged: u64,
    stage_rejected: u64,
    scope_rejected: u64,
    revision_rejected: u64,
    policy_rejected: u64,
    staged_conflict: u64,
    certified: u64,
    retried: u64,
    certificate_conflict: u64,
    network_rejected: u64,
    certificate_rejected: u64,
}
impl Counts {
    fn rejection(&mut self, error: StateError) {
        match error {
            StateError::Unauthorized | StateError::WrongPool | StateError::WrongIncarnation => {
                self.scope_rejected += 1
            }
            StateError::RevisionConflict => self.revision_rejected += 1,
            StateError::PolicyChanged => self.policy_rejected += 1,
            StateError::StagedConflict => self.staged_conflict += 1,
            _ => {}
        }
    }
    fn emit(&self, recovery: recovery::RecoveryCounts) {
        let Self {
            accepted,
            rejected,
            shrinks,
            violations,
            min,
            max,
            enrolled,
            enroll_rejected,
            observed,
            staged,
            stage_rejected,
            scope_rejected,
            revision_rejected,
            policy_rejected,
            staged_conflict,
            certified,
            retried,
            certificate_conflict,
            network_rejected,
            certificate_rejected,
            ..
        } = self;
        let mut measurements = serde_json::json!({
            "proptest_version": "1.11.0",
            "accepted_sequences": accepted,
            "minimum_sequence_length": min,
            "maximum_sequence_length": max,
            "pool_count": 32,
            "violations": violations,
            "rejected_sequences": rejected,
            "shrink_iterations": shrinks,
            "transitions": {
                "directory-enroll": enrolled,
                "directory-reject": enroll_rejected,
                "directory-observe": observed,
                "generation-stage": staged,
                "generation-reject": stage_rejected,
                "scope-reject": scope_rejected,
                "revision-reject": revision_rejected,
                "policy-reject": policy_rejected,
                "staged-conflict": staged_conflict,
                "certificate-apply": certified,
                "certificate-retry": retried,
                "certificate-conflict": certificate_conflict,
                "certificate-network-reject": network_rejected,
                "certificate-reject": certificate_rejected,
                "first-activation": recovery.first_activation,
                "period-skip": recovery.period_skip,
                "period-current-no-write": recovery.current_no_write,
                "period-stale-reject": recovery.stale_rejected,
                "reboot-reconcile": recovery.reboot_reconciled,
                "lost-ack-reconcile": recovery.lost_ack_reconciled,
                "committed-expiry": recovery.committed_expiry,
                "staged-survives-expiry": recovery.staged_survived_expiry,
            }
        });
        if std::env::var("KES_GATE_MODE").as_deref() == Ok("coverage") {
            measurements["build"] =
                serde_json::json!(std::env::var("KES_GATE_BUILD").expect("coverage build missing"));
            measurements["changed_branches"] = serde_json::json!({
                "authorization-isolation": scope_rejected,
                "directory-revision": revision_rejected,
                "generation-lifecycle": staged,
                "certificate-validation": certified,
            });
        }
        println!(
            "KES_GATE_SUMMARY {}",
            serde_json::json!({
                "version": 1,
                "cases": accepted,
                "scenarios": {"core-state": accepted},
                "measurements": measurements,
            })
        );
    }
}
fn candidate(
    pool: &PoolRegistration,
    number: u64,
    step: usize,
    source: &mut File,
) -> KESGeneration {
    let mut seed = Zeroizing::new([0u8; 32]);
    source
        .read_exact(&mut *seed)
        .expect("disposable fixture entropy unavailable");
    let lifetime = KesLifetime::new(u64::from(pool.network().max_kes_evolutions())).unwrap();
    let mut job = Generation::begin(&mut seed, lifetime).unwrap();
    for _ in 0..64 {
        job.step().unwrap();
    }
    let (key, tree) = job.finish().unwrap();
    let cache = tree.verify(&key.verification_key().unwrap()).unwrap();
    let verification_key = key.verification_key().unwrap();
    let mut public_id = [0u8; 16];
    public_id[..8].copy_from_slice(&(step as u64 + 1).to_be_bytes());
    public_id[8..].copy_from_slice(&number.to_be_bytes());
    let generation_id = GenerationId::from_bytes(public_id);
    let object = PublicObject::from_parts(
        generation_id,
        cache.as_bytes(),
        PUBLIC_ARTIFACT_SYNTAX,
        &verification_key,
    )
    .unwrap();
    KESGeneration::new_staged(
        GenerationSpec {
            generation_id,
            generation_number: GenerationNumber::new(number),
            creation_request: RequestId::from_bytes(public_id),
            creation_payload_digest: [0x47; 32],
            pool: pool.pool_id(),
            incarnation: pool.incarnation(),
            verification_key,
            lifetime,
            recipient_id: *pool.recipient_id(),
            public_object: object,
        },
        key,
    )
    .unwrap()
}
fn actor(pool: &PoolRegistration) -> Actor {
    Actor::Pool {
        pool: pool.pool_id(),
        incarnation: pool.incarnation(),
    }
}
fn apply_enrollment(
    kind: u8,
    index: usize,
    aux: u8,
    case: &mut CaseState,
    counts: &mut Counts,
) -> Result<(), TestCaseError> {
    let CaseState {
        device,
        pools,
        expected,
        ..
    } = case;
    let management = kind.is_multiple_of(2);
    let stale = kind == 15 || aux & 0x80 != 0;
    let scope = if management {
        Actor::Management
    } else {
        actor(&pools[index])
    };
    let expected_revision = device.directory_revision().get() + u64::from(stale);
    let valid = management
        && !stale
        && !expected[index].enrolled
        && expected.iter().filter(|p| p.enrolled).count() < 32;
    let result = device.enroll(scope, &pools[index], Revision::new(expected_revision));
    prop_assert_eq!(
        result.is_ok(),
        valid,
        "directory acceptance disagrees with independent model"
    );
    match result {
        Ok(slot) => {
            expected[index].enrolled = true;
            expected[index].slot = Some(slot);
            counts.enrolled += 1;
        }
        Err(error) => {
            counts.enroll_rejected += 1;
            counts.rejection(error);
        }
    }
    Ok(())
}
fn apply_generation(
    kind: u8,
    index: usize,
    aux: u8,
    step: usize,
    case: &mut CaseState,
    counts: &mut Counts,
    source: &mut File,
) -> Result<(), TestCaseError> {
    let CaseState {
        device,
        pools,
        expected,
        defect,
        ..
    } = case;
    if device.find(pools[index].pool_id()).is_none() {
        counts.observed += 1;
        return Ok(());
    }
    let other = (index + 1) % 33;
    let correct_scope = kind != 12;
    let stale_policy = kind == 13;
    let stale_revision = aux & 0x40 != 0;
    let wrong_number = aux & 1 != 0;
    let scope = if correct_scope {
        actor(&pools[index])
    } else {
        actor(&pools[other])
    };
    let policy = if stale_policy {
        pools[other].generation_policy()
    } else {
        pools[index].generation_policy()
    };
    let number = expected[index].generation + if wrong_number { 2 } else { 1 };
    let candidate = candidate(&pools[index], number, step, source);
    let generation_id = candidate.id();
    let revision = Revision::new(expected[index].revision + u64::from(stale_revision));
    let verification_key = *candidate.verification_key();
    let object_digest = candidate.public_object_ref().digest;
    let backup_digest = *candidate.backup_digest();
    let valid = (correct_scope
        && !stale_policy
        && !stale_revision
        && !wrong_number
        && expected[index].staged.is_none())
        || (*defect == Some(SeededDefect::CrossPoolAuthorization)
            && !correct_scope
            && !stale_policy
            && !stale_revision
            && !wrong_number
            && expected[index].staged.is_none());
    let result = pools[index].stage(scope, revision, candidate, policy);
    prop_assert_eq!(
        result.is_ok(),
        valid,
        "staging acceptance disagrees with independent model"
    );
    match result {
        Ok(()) => {
            expected[index].revision += 1;
            expected[index].generation = number;
            expected[index].staged = Some(generation_id);
            counts.staged += 1;
            expected[index].verification_key = Some(verification_key);
            expected[index].object_digest = Some(object_digest);
            expected[index].backup_digest = Some(backup_digest);
        }
        Err(error) => {
            counts.stage_rejected += 1;
            counts.rejection(error);
        }
    }
    Ok(())
}
fn check_directory(
    device: &Device,
    pools: &[PoolRegistration; 33],
    expected: &[ExpectedPool; 33],
) -> Result<(), TestCaseError> {
    let live = expected.iter().filter(|p| p.enrolled).count();
    prop_assert_eq!(device.pool_count(), live);
    prop_assert!(live <= 32);
    prop_assert_eq!(device.directory_revision().get(), live as u64);
    for (index, pool) in pools.iter().enumerate() {
        match (device.find(pool.pool_id()), expected[index].slot) {
            (Some(actual), Some(slot)) => {
                prop_assert!(expected[index].enrolled);
                prop_assert_eq!(actual.slot(), slot);
                prop_assert_eq!(actual.incarnation(), pool.incarnation());
                for prior in &expected[..index] {
                    prop_assert!(
                        prior.slot != Some(slot),
                        "two pool identities alias one hardware slot"
                    );
                }
            }
            (None, None) => prop_assert!(!expected[index].enrolled),
            _ => {
                return Err(TestCaseError::fail(
                    "directory identity/slot disappeared or appeared",
                ));
            }
        }
    }
    Ok(())
}
fn check_generations(
    pools: &[PoolRegistration; 33],
    expected: &[ExpectedPool; 33],
) -> Result<(), TestCaseError> {
    for (pool, model) in pools.iter().zip(expected) {
        prop_assert_eq!(pool.revision().get(), model.revision);
        prop_assert_eq!(pool.generation_high_water().get(), model.generation);
        prop_assert_eq!(pool.staged().map(KESGeneration::id), model.staged);
        prop_assert!(
            pool.current().is_none(),
            "initial state scope invented an activation"
        );
        if let Some(generation) = pool.staged() {
            prop_assert_eq!(generation.pool_id(), pool.pool_id());
            prop_assert_eq!(generation.incarnation(), pool.incarnation());
            prop_assert!(!generation.is_secret_erased());
            prop_assert_eq!(
                generation.verification_key(),
                &model.verification_key.unwrap()
            );
            prop_assert_eq!(
                generation.public_object_ref().digest,
                model.object_digest.unwrap()
            );
            prop_assert_eq!(generation.backup_digest(), &model.backup_digest.unwrap());
            prop_assert_eq!(
                generation.lifecycle(),
                if model.certificate.is_some() {
                    Lifecycle::CertifiedStaged
                } else {
                    Lifecycle::Staged
                }
            );
            prop_assert_eq!(
                generation.certificate().map(|c| *c.digest()),
                model.certificate
            );
            prop_assert_eq!(pool.certificate_high_water(), None);
            prop_assert_eq!(generation.public_object_ref().generation, generation.id());
        }
    }
    Ok(())
}
// Independent wire builder: never signs a message returned by the implementation.
fn signed_certificate(key: &SigningKey, hot: &[u8; 32], changed: bool) -> Vec<u8> {
    let counter = u8::from(changed);
    let mut message = [0; 48];
    message[..32].copy_from_slice(hot);
    message[39] = counter;
    let mut bytes = vec![0x82, 0x84, 0x58, 32];
    bytes.extend_from_slice(hot);
    bytes.extend_from_slice(&[counter, 0, 0x58, 64]);
    bytes.extend_from_slice(&key.sign(&message).to_bytes());
    bytes.extend_from_slice(&[0x58, 32]);
    bytes.extend_from_slice(&key.verifying_key().to_bytes());
    bytes
}
fn apply_certificate(
    kind: u8,
    index: usize,
    case: &mut CaseState,
    counts: &mut Counts,
) -> Result<(), TestCaseError> {
    let Some(id) = case.expected[index].staged else {
        counts.observed += 1;
        return Ok(());
    };
    let model = case.expected[index];
    let bytes = signed_certificate(
        &case.cold[index],
        &model.verification_key.unwrap(),
        kind == 18,
    );
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    let pool = &mut case.pools[index];
    let scope = match kind {
        20 => Actor::Management,
        21 => Actor::Pool {
            pool: pool.pool_id(),
            incarnation: kes_core::types::IncarnationId::from_bytes([0xff; 16]),
        },
        _ => actor(pool),
    };
    let wrong_network =
        NetworkBinding::from_genesis_bytes(43, b"public lifecycle model genesis", 64, 64).unwrap();
    let network = if kind == 19 {
        wrong_network
    } else {
        *pool.network()
    };
    let revision = match kind {
        17 => model.revision.saturating_sub(1),
        22 => model.revision + 1,
        _ => model.revision,
    };
    let generation = if kind == 23 {
        GenerationId::from_bytes([0xff; 16])
    } else {
        id
    };
    let duplicate = model.certificate == Some(digest);
    let valid = !matches!(kind, 19..=23)
        && (duplicate || (model.certificate.is_none() && revision == model.revision));
    let before_signature = {
        let mut signature = [0; 448];
        pool.staged()
            .unwrap()
            .secret()
            .key()
            .unwrap()
            .sign_into(
                kes_core::types::RelativePeriod::new(0).unwrap(),
                b"certificate model preservation",
                &mut signature,
            )
            .unwrap();
        signature
    };
    let result = pool.certify(scope, Revision::new(revision), generation, &bytes, &network);
    prop_assert_eq!(
        result.is_ok(),
        valid,
        "certification disagrees with independent reference"
    );
    match result {
        Ok(CertificationOutcome::Applied { revision }) => {
            prop_assert!(!duplicate);
            case.expected[index].revision += 1;
            case.expected[index].certificate = Some(digest);
            prop_assert_eq!(revision.get(), case.expected[index].revision);
            counts.certified += 1;
        }
        Ok(CertificationOutcome::AlreadyCertified { revision }) => {
            prop_assert!(duplicate);
            prop_assert_eq!(revision.get(), model.revision);
            counts.retried += 1;
        }
        Err(error) => {
            if kind == 19 {
                counts.network_rejected += 1;
            }
            if model.certificate.is_some() && !duplicate && !matches!(kind, 19..=23) {
                prop_assert_eq!(error, StateError::CertificateConflict);
                counts.certificate_conflict += 1;
            }
            counts.certificate_rejected += 1;
            counts.rejection(error);
        }
    }
    let mut after_signature = [0; 448];
    pool.staged()
        .unwrap()
        .secret()
        .key()
        .unwrap()
        .sign_into(
            kes_core::types::RelativePeriod::new(0).unwrap(),
            b"certificate model preservation",
            &mut after_signature,
        )
        .unwrap();
    prop_assert_eq!(
        before_signature,
        after_signature,
        "certify/retry/rejection replaced or changed the staged secret"
    );
    kes_core::crypto::verify(
        &model.verification_key.unwrap(),
        kes_core::types::RelativePeriod::new(0).unwrap(),
        pool.staged().unwrap().lifetime(),
        b"certificate model preservation",
        &after_signature,
    )
    .unwrap();
    Ok(())
}
fn exercise(
    operations: &[(u8, u8, u8)],
    counts: &mut Counts,
    source: &mut File,
    defect: Option<SeededDefect>,
) -> Result<(), TestCaseError> {
    let cold: [SigningKey; 33] = core::array::from_fn(|_| {
        let mut seed = Zeroizing::new([0; 32]);
        source
            .read_exact(&mut *seed)
            .expect("disposable fixture entropy unavailable");
        SigningKey::from_bytes(&seed)
    });
    let mut case = CaseState {
        device: device(DeviceMode::Development, 2),
        pools: core::array::from_fn(|index| {
            registration_with_cold(index as u8, cold[index].verifying_key().to_bytes())
        }),
        expected: [ExpectedPool::default(); 33],
        cold,
        defect,
    };
    for (step, &(kind, index, aux)) in operations.iter().enumerate() {
        let index = usize::from(index);
        match kind {
            0..=7 | 15 => apply_enrollment(kind, index, aux, &mut case, counts)?,
            8..=13 => apply_generation(kind, index, aux, step, &mut case, counts, source)?,
            14 => {
                let _ = case.device.find(case.pools[index].pool_id());
                counts.observed += 1;
            }
            16..=23 => apply_certificate(kind, index, &mut case, counts)?,
            _ => {
                return Err(TestCaseError::fail(
                    "operation strategy violated closed range",
                ));
            }
        }
        check_directory(&case.device, &case.pools, &case.expected)?;
        check_generations(&case.pools, &case.expected)?;
    }
    Ok(())
}
fn run_seeded(defect: SeededDefect, mode: &str, operations: &[(u8, u8, u8)]) -> ! {
    xtask::oracles::protect_memory().expect("fresh no-swap disposable lab required");
    let mut source = File::open("/dev/urandom").expect("disposable fixture entropy unavailable");
    let mut counts = Counts {
        min: operations.len(),
        max: operations.len(),
        ..Counts::default()
    };
    if exercise(operations, &mut counts, &mut source, Some(defect)).is_ok() {
        panic!("seeded defect was not detected");
    }
    let (path, observation) = match defect {
        SeededDefect::CrossPoolAuthorization => (
            "kes-core.lifecycle.stage",
            "pool[1] authorization was modeled as valid for pool[0]",
        ),
    };
    println!(
        "KES_GATE_SUMMARY {{\"version\":1,\"cases\":1,\"scenarios\":{{\"core-state\":1}},\"measurements\":{{\"violations\":1,\"counterexample\":{{\"mode\":\"{mode}\",\"path\":\"{path}\",\"observation\":\"{observation}\",\"disclosure\":\"public\"}}}}}}"
    );
    panic!("seeded lifecycle defect detected");
}

#[test]
fn lifecycle_campaign_covers_current_scoped_transitions() {
    let mode = std::env::var("KES_GATE_MODE").unwrap_or_else(|_| "clean".into());
    let recovery = match mode.as_str() {
        "seeded-cross-pool-authorization" => run_seeded(
            SeededDefect::CrossPoolAuthorization,
            &mode,
            &[(0, 0, 0), (12, 0, 0)],
        ),
        "seeded-stale-period" => return,
        "clean" | "campaign" | "coverage" => recovery::exercise_recovery_transitions(),
        _ => panic!("unsupported lifecycle gate mode: {mode}"),
    };
    xtask::oracles::protect_memory().expect("fresh no-swap disposable lab required");
    let source =
        RefCell::new(File::open("/dev/urandom").expect("disposable fixture entropy unavailable"));
    let counters = RefCell::new(Counts {
        min: usize::MAX,
        ..Counts::default()
    });
    let strategy = proptest::collection::vec((0u8..24, 0u8..33, any::<u8>()), 1..=256);
    let config = Config {
        failure_persistence: None,
        cases: 10_000,
        verbose: 0,
        ..Config::default()
    };
    let expected_cases = u64::from(config.cases);
    let result = TestRunner::new(config).run(&strategy, |operations: Operations| {
        let mut counts = counters.borrow_mut();
        if counts.failed_once {
            counts.shrinks += 1;
        }
        match exercise(&operations, &mut counts, &mut source.borrow_mut(), None) {
            Ok(()) => {
                if !counts.failed_once {
                    counts.accepted += 1;
                    counts.min = counts.min.min(operations.len());
                    counts.max = counts.max.max(operations.len());
                }
                Ok(())
            }
            Err(error) => {
                match &error {
                    TestCaseError::Reject(_) => counts.rejected += 1,
                    TestCaseError::Fail(_) => {
                        counts.violations += 1;
                        counts.failed_once = true;
                    }
                }
                Err(error)
            }
        }
    });
    let counts = counters.into_inner();
    counts.emit(recovery);
    assert!(
        result.is_ok(),
        "lifecycle model invariant violation; public counters emitted, private inputs not retained"
    );
    assert_eq!(counts.accepted, expected_cases);
    assert!(
        counts.certified > 0
            && counts.retried > 0
            && counts.certificate_conflict > 0
            && counts.network_rejected > 0
    );
}
