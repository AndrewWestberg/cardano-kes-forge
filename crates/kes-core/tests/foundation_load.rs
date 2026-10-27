#![cfg(feature = "native-oracles")]

use kes_core::{
    activation::{
        ActivationRequest, CertificationRequest, EvolutionRequest, StageGenerationRequest,
    },
    crypto::{Generation, KesKey, PublicTreeBuffer, verify},
    rotation::ReplacementActivationRequest,
    signing::SigningRequest,
    state::{GenerationSpec, KESGeneration, PublicObject},
    types::{AbsolutePeriod, GenerationId, GenerationNumber, KesLifetime, RequestId},
};
use rand_chacha::rand_core::TryRngCore;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    mem::size_of,
    time::{Duration, Instant},
};
use xtask::oracles::{Baseline, Oracle};
use zeroize::Zeroizing;

#[path = "support/mod.rs"]
mod support;
use support::{Fixture, certificate};

const POOLS: usize = 32;
const MESSAGE_BYTES: usize = 4096;

struct Pending {
    pool_index: usize,
    message: [u8; MESSAGE_BYTES],
    admitted: Instant,
    deadline: Instant,
}

struct Replacement {
    generation: GenerationId,
    tree: PublicTreeBuffer,
    certificate_digest: [u8; 32],
}

fn activate_initial(f: &mut Fixture) {
    let revision = f.durable.state().unwrap().revision();
    f.durable
        .certify(
            &f.journal,
            &mut f.flash,
            &mut f.entropy,
            &mut f.buffers.work(),
            CertificationRequest {
                actor: f.actor,
                expected_revision: revision,
                generation: f.generation,
                canonical_certificate: &f.certificate,
                network: &f.network,
            },
        )
        .unwrap();
    let tree = f
        .tree
        .verify(
            f.durable
                .state()
                .unwrap()
                .staged()
                .unwrap()
                .verification_key(),
        )
        .unwrap();
    let revision = f.durable.state().unwrap().revision();
    f.durable
        .activate_first(
            &f.journal,
            &mut f.flash,
            &mut f.entropy,
            &mut f.buffers.work(),
            ActivationRequest {
                actor: f.actor,
                expected_revision: revision,
                expected_active_generation: None,
                generation: f.generation,
                certificate_digest: f.certificate_digest,
                current_absolute_period: AbsolutePeriod::new(100),
            },
            &tree,
        )
        .unwrap();
}

// Both the synchronous setup and the separately interleaved job use fresh OS entropy.
fn prepare_replacement(f: &mut Fixture, number: u64, object_slot: u8, start: u64) -> Replacement {
    let mut seed = Zeroizing::new([0; 32]);
    f.entropy.try_fill_bytes(&mut *seed).unwrap();
    let mut job = Generation::begin(&mut seed, KesLifetime::new(64).unwrap()).unwrap();
    for _ in 0..64 {
        job.step().unwrap();
    }
    let (key, tree) = job.finish().unwrap();
    install_staged(f, key, tree, number, object_slot, start)
}

fn install_staged(
    f: &mut Fixture,
    key: KesKey,
    tree: PublicTreeBuffer,
    number: u64,
    object_slot: u8,
    start: u64,
) -> Replacement {
    let verification_key = key.verification_key().unwrap();
    let generation = GenerationId::random(&mut f.entropy).unwrap();
    let creation_request = RequestId::random(&mut f.entropy).unwrap();
    let verified = tree.verify(&verification_key).unwrap();
    let backup = include_bytes!("../../../fuzz/corpus/frame/backup-public-structure");
    let object =
        PublicObject::from_parts(generation, verified.as_bytes(), backup, &verification_key)
            .unwrap();
    let mut object_bytes = vec![0; usize::from(object.reference().total_length)];
    object.encode_into(&mut object_bytes).unwrap();
    f.flash
        .install_public_object(f.layout.object_offset(object_slot).unwrap(), &object_bytes);
    let pool = f.durable.state().unwrap();
    let policy = pool.generation_policy();
    let staged = KESGeneration::new_staged(
        GenerationSpec {
            generation_id: generation,
            generation_number: GenerationNumber::new(number),
            creation_request,
            creation_payload_digest: Sha256::digest(&object_bytes).into(),
            pool: pool.pool_id(),
            incarnation: pool.incarnation(),
            verification_key,
            lifetime: KesLifetime::new(64).unwrap(),
            recipient_id: *policy.recipient_id(),
            public_object: object,
        },
        key,
    )
    .unwrap();
    let revision = f.durable.state().unwrap().revision();
    f.durable
        .stage_generation(
            &f.journal,
            &mut f.flash,
            &mut f.entropy,
            &mut f.buffers.work(),
            StageGenerationRequest {
                actor: f.actor,
                expected_revision: revision,
                generation: staged,
                policy,
            },
        )
        .unwrap();
    let cert = certificate(&f.cold, &verification_key, number - 1, start);
    let certificate_digest = Sha256::digest(&cert).into();
    let revision = f.durable.state().unwrap().revision();
    f.durable
        .certify(
            &f.journal,
            &mut f.flash,
            &mut f.entropy,
            &mut f.buffers.work(),
            CertificationRequest {
                actor: f.actor,
                expected_revision: revision,
                generation,
                canonical_certificate: &cert,
                network: &f.network,
            },
        )
        .unwrap();
    Replacement {
        generation,
        tree,
        certificate_digest,
    }
}

fn elapsed_ns(origin: Instant, instant: Instant) -> u64 {
    u64::try_from(instant.duration_since(origin).as_nanos()).unwrap()
}
struct Wave {
    name: &'static str,
    absolute_period: u64,
    activate: bool,
}

// Fixed-capacity FIFO: admission owns the full maximum-size message. No timestamps
// are reconstructed at dispatch, and no second operation is dispatched in flight.
fn run_wave(
    pools: &mut [Fixture],
    replacements: &[Replacement],
    oracles: &[Oracle; 2],
    origin: Instant,
    wave: Wave,
    background: Option<&mut Generation>,
) -> Value {
    let Wave {
        name: phase,
        absolute_period,
        activate,
    } = wave;
    let mut queue: [Option<Pending>; POOLS] = std::array::from_fn(|_| None);
    let mut queued = 0;
    for (pool_index, slot) in queue.iter_mut().enumerate() {
        let mut message = [0x46; MESSAGE_BYTES];
        message[..8].copy_from_slice(&(pool_index as u64).to_be_bytes());
        message[8..16].copy_from_slice(&absolute_period.to_be_bytes());
        let admitted = Instant::now();
        *slot = Some(Pending {
            pool_index,
            message,
            admitted,
            deadline: admitted + Duration::from_millis(500),
        });
        queued += 1;
    }
    assert_eq!(queued, POOLS);
    let mut background = background;
    let mut records = Vec::with_capacity(POOLS);
    let mut in_flight = 0;
    for slot in &mut queue {
        // One real leaf, never a full-tree computation disguised as a yield.
        let leaf = if let Some(job) = background.as_deref_mut() {
            let started = Instant::now();
            job.step().unwrap();
            Some(
                json!({"started_ns": elapsed_ns(origin, started), "finished_ns": elapsed_ns(origin, Instant::now())}),
            )
        } else {
            None
        };
        let request = slot.take().unwrap();
        queued -= 1;
        assert_eq!(in_flight, 0);
        in_flight += 1;
        let dispatched = Instant::now();
        let f = &mut pools[request.pool_index];
        if activate {
            let replacement = &replacements[request.pool_index];
            let tree = replacement
                .tree
                .verify(
                    f.durable
                        .state()
                        .unwrap()
                        .staged()
                        .unwrap()
                        .verification_key(),
                )
                .unwrap();
            let revision = f.durable.state().unwrap().revision();
            let previous = f.durable.state().unwrap().current().unwrap().id();
            f.durable
                .activate_replacement(
                    &f.journal,
                    &mut f.flash,
                    &mut f.entropy,
                    &mut f.buffers.work(),
                    ReplacementActivationRequest {
                        actor: f.actor,
                        expected_revision: revision,
                        expected_active_generation: previous,
                        generation: replacement.generation,
                        certificate_digest: replacement.certificate_digest,
                        current_absolute_period: AbsolutePeriod::new(absolute_period),
                    },
                    &tree,
                )
                .unwrap();
        }
        let current = f.durable.state().unwrap().current().unwrap();
        let generation = current.id();
        let vk = *current.verification_key();
        let digest = *current.certificate().unwrap().digest();
        let tree_buffer = if generation == f.generation {
            &f.tree
        } else {
            &replacements[request.pool_index].tree
        };
        let tree = tree_buffer.verify(&vk).unwrap();
        let signed = f
            .durable
            .sign(
                &f.journal,
                &mut f.flash,
                &mut f.entropy,
                &mut f.buffers.work(),
                SigningRequest {
                    actor: f.actor,
                    generation,
                    certificate_digest: digest,
                    absolute_period: AbsolutePeriod::new(absolute_period),
                    network: &f.network,
                    message: &request.message,
                },
                &tree,
            )
            .unwrap();
        verify(
            &vk,
            signed.context.relative_period,
            KesLifetime::new(64).unwrap(),
            &request.message,
            &signed.signature,
        )
        .unwrap();
        assert_eq!(signed.context.generation, generation);
        assert_eq!(signed.context.certificate_digest, digest);
        let expected_message_digest: [u8; 32] = Sha256::digest(request.message.as_slice()).into();
        assert_eq!(signed.message_digest, expected_message_digest);
        for oracle in oracles {
            assert!(
                oracle
                    .verify(
                        &vk,
                        signed.context.relative_period.get(),
                        &request.message,
                        &signed.signature
                    )
                    .unwrap()
            );
        }
        let completed = Instant::now();
        assert!(request.admitted <= dispatched && dispatched <= completed);
        assert!(completed > dispatched);
        records.push(json!({
            "pool_index": request.pool_index,
            "pool_id": f.durable.state().unwrap().pool_id().to_string(),
            "generation_id": generation.to_string(),
            "absolute_period": absolute_period,
            "relative_period": signed.context.relative_period.get(),
            "original_deadline_ns": elapsed_ns(origin, request.deadline),
            "deadline_missed": completed > request.deadline,
            "timely_usable_completion": completed <= request.deadline,
            "message_bytes": MESSAGE_BYTES,
            "admitted_ns": elapsed_ns(origin, request.admitted),
            "dispatched_ns": elapsed_ns(origin, dispatched),
            "verified_completion_ns": elapsed_ns(origin, completed),
            "queue_wait_ns": elapsed_ns(request.admitted, dispatched),
            "dispatch_to_verified_ns": elapsed_ns(dispatched, completed),
            "admission_to_verified_ns": elapsed_ns(request.admitted, completed),
            "generation_leaf": leaf,
        }));
        in_flight -= 1;
    }
    assert_eq!((queued, in_flight), (0, 0));
    json!({"name": phase, "requests": records.len(), "verified_completions": records.len(), "records": records})
}

fn emit_phase(mut phase: Value) -> Value {
    let records = phase.as_object_mut().unwrap().remove("records").unwrap();
    let records = records.as_array().unwrap();
    let mut max_queue_wait_ns = 0;
    let mut max_dispatch_to_verified_ns = 0;
    let mut max_admission_to_verified_ns = 0;
    let mut deadline_misses = 0;
    let mut leaf_steps = 0;
    for record in records {
        max_queue_wait_ns = max_queue_wait_ns.max(record["queue_wait_ns"].as_u64().unwrap());
        max_dispatch_to_verified_ns =
            max_dispatch_to_verified_ns.max(record["dispatch_to_verified_ns"].as_u64().unwrap());
        max_admission_to_verified_ns =
            max_admission_to_verified_ns.max(record["admission_to_verified_ns"].as_u64().unwrap());
        deadline_misses += usize::from(record["deadline_missed"].as_bool().unwrap());
        leaf_steps += usize::from(!record["generation_leaf"].is_null());
        let request = json!({"schema_version": 1, "phase": phase["name"], "request": record});
        println!("KES_FOUNDATION_LOAD_REQUEST {request}");
    }
    phase["max_queue_wait_ns"] = json!(max_queue_wait_ns);
    phase["max_dispatch_to_verified_ns"] = json!(max_dispatch_to_verified_ns);
    phase["max_admission_to_verified_ns"] = json!(max_admission_to_verified_ns);
    phase["deadline_misses"] = json!(deadline_misses);
    phase["timely_usable_completions"] = json!(records.len() - deadline_misses);
    phase["generation_leaf_steps"] = json!(leaf_steps);
    phase["native_verifications"] = json!(records.len() * 2);
    phase
}
#[test]
fn real_32_pool_host_software_load_control() {
    xtask::oracles::protect_memory().expect("fresh no-swap disposable lab required");
    let oracles = [
        Oracle::pinned(Baseline::Cli114).unwrap(),
        Oracle::pinned(Baseline::Node1113).unwrap(),
    ];
    let origin = Instant::now();
    let mut pools: Vec<Fixture> = (0..POOLS).map(|_| Fixture::new()).collect();
    let identities: BTreeSet<_> = pools
        .iter()
        .map(|f| f.durable.state().unwrap().pool_id())
        .collect();
    assert_eq!(identities.len(), POOLS);
    for f in &mut pools {
        activate_initial(f);
    }
    let replacements: Vec<_> = pools
        .iter_mut()
        .map(|f| prepare_replacement(f, 2, 1, 132))
        .collect();
    assert!(
        pools
            .iter()
            .all(|f| f.durable.state().unwrap().current().is_some()
                && f.durable.state().unwrap().staged().is_some())
    );
    let aligned = run_wave(
        &mut pools,
        &replacements,
        &oracles,
        origin,
        Wave {
            name: "aligned_evolution",
            absolute_period: 101,
            activate: false,
        },
        None,
    );
    // Align every real journal/key at relative period 31 before admitting the
    // midpoint wave. Preparation is outside the reported request latency.
    for f in &mut pools {
        let tree = f
            .tree
            .verify(
                f.durable
                    .state()
                    .unwrap()
                    .current()
                    .unwrap()
                    .verification_key(),
            )
            .unwrap();
        let revision = f.durable.state().unwrap().revision();
        f.durable
            .evolve(
                &f.journal,
                &mut f.flash,
                &mut f.entropy,
                &mut f.buffers.work(),
                EvolutionRequest {
                    actor: f.actor,
                    expected_revision: revision,
                    generation: f.generation,
                    certificate_digest: f.certificate_digest,
                    target_absolute_period: AbsolutePeriod::new(131),
                    network: &f.network,
                },
                &tree,
            )
            .unwrap();
        assert_eq!(
            f.durable
                .state()
                .unwrap()
                .current()
                .unwrap()
                .relative_period()
                .get(),
            31
        );
    }
    let midpoint = run_wave(
        &mut pools,
        &replacements,
        &oracles,
        origin,
        Wave {
            name: "midpoint_31_to_32",
            absolute_period: 132,
            activate: false,
        },
        None,
    );
    let activation = run_wave(
        &mut pools,
        &replacements,
        &oracles,
        origin,
        Wave {
            name: "activation",
            absolute_period: 132,
            activate: true,
        },
        None,
    );
    assert!(
        pools
            .iter()
            .all(|f| f.durable.state().unwrap().staged().is_none())
    );

    // Restore all but the target vacancy before admitting background work:
    // 32 active + 31 staged, then one real leaf per dispatched request.
    for f in pools.iter_mut().skip(1) {
        prepare_replacement(f, 3, 0, 140);
    }
    let staged_at_background_start = pools
        .iter()
        .filter(|f| f.durable.state().unwrap().staged().is_some())
        .count();
    assert_eq!(staged_at_background_start, POOLS - 1);
    assert!(pools[0].durable.state().unwrap().staged().is_none());
    let mut seed = Zeroizing::new([0; 32]);
    pools[0].entropy.try_fill_bytes(&mut *seed).unwrap();
    let mut job = Generation::begin(&mut seed, KesLifetime::new(64).unwrap()).unwrap();
    let mut background = run_wave(
        &mut pools,
        &replacements,
        &oracles,
        origin,
        Wave {
            name: "background_generation",
            absolute_period: 133,
            activate: false,
        },
        Some(&mut job),
    );
    let mut second = run_wave(
        &mut pools,
        &replacements,
        &oracles,
        origin,
        Wave {
            name: "background_generation",
            absolute_period: 134,
            activate: false,
        },
        Some(&mut job),
    );
    let (background_key, background_tree) = job.finish().unwrap();
    background["records"]
        .as_array_mut()
        .unwrap()
        .append(second["records"].as_array_mut().unwrap());
    let background_completions = background["records"].as_array().unwrap().len();
    background["requests"] = json!(background_completions);
    background["verified_completions"] = json!(background_completions);
    let generated = install_staged(&mut pools[0], background_key, background_tree, 3, 0, 140);
    assert_eq!(
        pools[0].durable.state().unwrap().staged().unwrap().id(),
        generated.generation
    );

    // Real authenticated journal replay must retain every active key/period and
    // the newly filled vacancy, not merely the in-process signing state.
    for (index, f) in pools.iter_mut().enumerate() {
        let recovered = f
            .journal
            .recover(&mut f.flash, &mut f.entropy, &mut f.buffers.work())
            .unwrap();
        assert_eq!(
            recovered.state.current().unwrap().id(),
            replacements[index].generation
        );
        assert_eq!(
            recovered.state.current().unwrap().relative_period().get(),
            2
        );
        assert!(recovered.state.staged().is_some());
    }
    let summary = json!({
        "schema_version": 1,
        "scope": "host/software-only",
        "a4_p1_acceptance": false,
        "pool_count": POOLS,
        "queue_capacity": POOLS,
        "max_message_bytes": MESSAGE_BYTES,
        "max_in_flight": 1,
        "journal_backend": "in-memory NOR Flash model with real Journal<PoolCodec> commits/recovery",
        "timestamp_clock": "monotonic Instant nanoseconds since test start; completion includes local and both pinned native verifiers",
        "physical_ram_high_water_bytes": null,
        "background_leaf_steps": 64,
        "background_staged_vacancies_at_start": POOLS - staged_at_background_start,
        "background_staged_generations_at_start": staged_at_background_start,
        "background_generations_staged": 1,
        "journal_recoveries": POOLS,
        "native_verifiers": [oracles[0].identity.clone(), oracles[1].identity.clone()],
        "memory_type_sizes_bytes": {
            "pending": size_of::<Pending>(),
            "bounded_queue": size_of::<[Option<Pending>; POOLS]>(),
            "fixture": size_of::<Fixture>(),
            "kes_key": size_of::<KesKey>(),
            "public_tree_buffer": size_of::<PublicTreeBuffer>(),
            "generation_job": size_of::<Generation>(),
        },
        "limitations": [
            "No A4/P1 timing, physical device RAM, USB transport, firmware scheduler or flash latency acceptance",
            "Flash persistence is modeled in host memory; no physical power-loss test",
            "Type sizes exclude heap allocations, stack high-water, oracle processes and allocator overhead",
            "Synchronous single-flight dispatch includes per-signature native verifier process overhead, not in-process node/P1 performance",
            "Pool setup and alignment to relative period 31 occur outside request latency"
        ],
        "phases": [emit_phase(aligned), emit_phase(midpoint), emit_phase(activation), emit_phase(background)],
    });
    println!("KES_FOUNDATION_LOAD_SUMMARY {summary}");
}
