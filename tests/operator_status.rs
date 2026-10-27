use cardano_kes_forge::host::{latency, observation};
use std::time::Duration;

fn network() -> observation::NetworkContext {
    observation::NetworkContext {
        network_magic: 42,
        shelley_genesis_digest: [9; 32],
        slots_per_kes_period: 64,
        max_kes_evolutions: 64,
    }
}

fn context(generation: u8, revision: u64) -> observation::ObservationContext {
    observation::ObservationContext {
        device: [1; 16],
        boot_nonce: [2; 32],
        session: [3; 16],
        pool: [4; 28],
        incarnation: [5; 16],
        network: network(),
        generation: [generation; 16],
        certificate_digest: [7; 32],
        revision,
    }
}

#[test]
fn observations_are_unavailable_fresh_stale_and_immediately_invalidated() {
    let mut cache = observation::Cache::default();
    assert_eq!(cache.view(1).state, observation::State::Unavailable);

    cache.connect();
    let current = context(6, 8);
    assert!(cache.record_confirmed(observation::ConfirmedObservation {
        generation_number: 6,
        context: current.clone(),
        relative_period: 4,
        service_ready: true,
        observed_at: "2026-01-02T03:04:05Z".to_owned(),
        monotonic_ms: 1_000,
    }));
    assert_eq!(cache.view(1_001).state, observation::State::Unavailable);
    assert!(
        cache.record_node_period(observation::NodePeriodObservation {
            context: current,
            absolute_period: 104,
            observed_at: "2026-01-02T03:04:06Z".to_owned(),
            monotonic_ms: 1_001,
        })
    );

    let fresh = cache.view(30_999);
    assert_eq!(fresh.state, observation::State::Fresh);
    assert_eq!(fresh.ready, Some(true));
    assert_eq!(fresh.remaining_validity_periods, Some(60));
    assert_eq!(fresh.confirmed_age_ms, Some(29_999));

    assert_eq!(cache.view(31_000).state, observation::State::Stale);
    let stale = cache.view(31_001);
    assert_eq!(stale.state, observation::State::Stale);
    assert_eq!(stale.ready, None);
    assert_eq!(stale.remaining_validity_periods, None);

    cache.disconnect();
    let unavailable = cache.view(31_002);
    assert_eq!(unavailable.state, observation::State::Unavailable);
    assert!(unavailable.historical.is_some());
    assert_eq!(unavailable.ready, None);
}

#[test]
fn mismatched_or_lower_revision_observations_never_become_ready() {
    let mut cache = observation::Cache::default();
    cache.connect();
    let current = context(6, 8);
    assert!(cache.record_confirmed(observation::ConfirmedObservation {
        generation_number: 6,
        context: current.clone(),
        relative_period: 4,
        service_ready: true,
        observed_at: "2026-01-02T03:04:05Z".to_owned(),
        monotonic_ms: 1_000,
    }));
    let mut mismatched = current.clone();
    mismatched.generation = [10; 16];
    assert!(
        !cache.record_node_period(observation::NodePeriodObservation {
            context: mismatched,
            absolute_period: 104,
            observed_at: "2026-01-02T03:04:06Z".to_owned(),
            monotonic_ms: 1_001,
        })
    );
    let mut older = current;
    older.revision = 7;
    assert!(!cache.record_confirmed(observation::ConfirmedObservation {
        generation_number: 6,
        context: older,
        relative_period: 3,
        service_ready: true,
        observed_at: "2026-01-02T03:04:07Z".to_owned(),
        monotonic_ms: 1_002,
    }));
    assert_eq!(cache.view(1_003).state, observation::State::Unavailable);
}

#[test]
fn confirmed_evolution_never_regresses_even_with_a_newer_pool_revision() {
    let mut cache = observation::Cache::default();
    cache.connect();
    let current = context(6, 8);
    assert!(cache.record_confirmed(observation::ConfirmedObservation {
        generation_number: 6,
        context: current.clone(),
        relative_period: 4,
        service_ready: true,
        observed_at: "2026-01-02T03:04:05Z".to_owned(),
        monotonic_ms: 1_000,
    }));
    assert!(
        cache.record_node_period(observation::NodePeriodObservation {
            context: current.clone(),
            absolute_period: 104,
            observed_at: "2026-01-02T03:04:06Z".to_owned(),
            monotonic_ms: 1_001,
        })
    );
    let mut newer = current;
    newer.revision = 9;
    assert!(!cache.record_confirmed(observation::ConfirmedObservation {
        generation_number: 6,
        context: newer,
        relative_period: 3,
        service_ready: true,
        observed_at: "2026-01-02T03:04:07Z".to_owned(),
        monotonic_ms: 1_002,
    }));
    let view = cache.view(1_003);
    assert_eq!(view.state, observation::State::Fresh);
    assert_eq!(view.historical.unwrap().relative_period, 4);
    assert_eq!(view.remaining_validity_periods, Some(60));
}

#[test]
fn retired_generation_cannot_return_after_activation_or_disconnect() {
    let mut cache = observation::Cache::default();
    cache.connect();
    let old = context(6, 8);
    assert!(cache.record_confirmed(observation::ConfirmedObservation {
        generation_number: 6,
        context: old.clone(),
        relative_period: 4,
        service_ready: true,
        observed_at: "2026-01-02T03:04:05Z".to_owned(),
        monotonic_ms: 1_000,
    }));

    let mut conflicting = old.clone();
    conflicting.generation = [9; 16];
    assert!(!cache.record_confirmed(observation::ConfirmedObservation {
        generation_number: 9,
        context: conflicting,
        relative_period: 0,
        service_ready: true,
        observed_at: "2026-01-02T03:04:06Z".to_owned(),
        monotonic_ms: 1_001,
    }));

    let mut replacement = old.clone();
    replacement.generation = [10; 16];
    replacement.certificate_digest = [11; 32];
    replacement.revision = 9;
    assert!(cache.record_confirmed(observation::ConfirmedObservation {
        generation_number: 10,
        context: replacement,
        relative_period: 0,
        service_ready: true,
        observed_at: "2026-01-02T03:04:07Z".to_owned(),
        monotonic_ms: 1_002,
    }));
    assert_eq!(cache.view(1_003).state, observation::State::Unavailable);

    cache.disconnect();
    cache.connect();
    assert!(!cache.record_confirmed(observation::ConfirmedObservation {
        generation_number: 6,
        context: old,
        relative_period: 5,
        service_ready: true,
        observed_at: "2026-01-02T03:04:08Z".to_owned(),
        monotonic_ms: 1_003,
    }));
    let view = cache.view(1_004);
    assert_eq!(view.state, observation::State::Unavailable);
    assert_eq!(view.historical.unwrap().generation, [10; 16]);
}

#[test]
fn latency_uses_original_rounded_duration_and_fixed_freshness_boundary() {
    assert_eq!(latency::ceil_milliseconds(Duration::from_nanos(1)), 1);
    assert_eq!(latency::ceil_milliseconds(Duration::from_millis(12)), 12);
    assert_eq!(
        latency::ceil_milliseconds(Duration::from_nanos(12_000_001)),
        13
    );

    let mut samples = latency::Samples::default();
    assert_eq!(
        samples.view(latency::Operation::Sign, 1).state,
        latency::State::Unavailable
    );
    samples.record(latency::Sample {
        operation: latency::Operation::Sign,
        request: [11; 16],
        duration_ms: 13,
        outcome: latency::Outcome::Error,
        code: "DEADLINE_EXCEEDED".to_owned(),
        observed_at: "2026-01-02T03:04:08Z".to_owned(),
        completed_monotonic_ms: 2_000,
        context: latency::Context {
            device: [1; 16],
            boot_nonce: [2; 32],
            session: [3; 16],
            pool: [4; 28],
            incarnation: [5; 16],
            network: network(),
            generation: Some([6; 16]),
            certificate_digest: Some([7; 32]),
            revision: Some(8),
        },
    });
    assert_eq!(
        samples.view(latency::Operation::Sign, 31_999).state,
        latency::State::Fresh
    );
    let stale = samples.view(latency::Operation::Sign, 32_000);
    assert_eq!(stale.state, latency::State::Stale);
    assert_eq!(stale.age_ms, Some(30_000));
    assert_eq!(stale.sample.unwrap().code, "DEADLINE_EXCEEDED");

    samples.clear_for_session_replacement();
    assert_eq!(
        samples.view(latency::Operation::Sign, 32_001).state,
        latency::State::Unavailable
    );
}

#[test]
fn certificate_bounds_use_observed_node_period_and_keep_expired_readiness_distinct() {
    let mut cache = observation::Cache::default();
    cache.connect();
    cache.set_certificate_start(100);
    let current = context(6, 8);
    cache.record_confirmed(observation::ConfirmedObservation {
        generation_number: 6,
        context: current.clone(),
        relative_period: 63,
        service_ready: false,
        observed_at: "2026-01-02T03:04:05Z".into(),
        monotonic_ms: 1000,
    });
    assert_eq!(cache.view(1000).remaining_validity_periods, None);
    cache.record_node_period(observation::NodePeriodObservation {
        context: current,
        absolute_period: 164,
        observed_at: "2026-01-02T03:04:05Z".into(),
        monotonic_ms: 1000,
    });
    let fresh = cache.view(1001);
    assert_eq!(fresh.state, observation::State::Fresh);
    assert_eq!(fresh.ready, Some(false));
    assert_eq!(fresh.remaining_validity_periods, Some(0));
    let stale = cache.view(31000);
    assert_eq!(stale.ready, None);
    assert_eq!(stale.remaining_validity_periods, None);
    cache.set_mutation_unresolved(true);
    assert_eq!(cache.view(1001).state, observation::State::Unavailable);
    assert!(cache.view(1001).historical.is_some());
}

#[test]
fn retired_generation_with_forged_newer_revision_and_changed_pool_stays_historical() {
    let mut cache = observation::Cache::default();
    cache.connect();
    let record = |context: observation::ObservationContext, monotonic_ms| {
        observation::ConfirmedObservation {
            generation_number: u64::from(context.generation[0]),
            context,
            relative_period: 4,
            service_ready: true,
            observed_at: "2026-01-02T03:04:05Z".into(),
            monotonic_ms,
        }
    };
    assert!(cache.record_confirmed(record(context(6, 8), 1000)));
    assert!(cache.record_confirmed(record(context(10, 9), 1001)));
    cache.invalidate_session();
    cache.connect();
    assert!(!cache.record_confirmed(record(context(6, 100), 1002)));
    let mut other_pool = context(11, 101);
    other_pool.pool = [99; 28];
    assert!(!cache.record_confirmed(record(other_pool, 1003)));
    assert_eq!(cache.view(1004).historical.unwrap().generation, [10; 16]);
    assert_eq!(cache.view(1004).ready, None);
}

// Exercise the normal acknowledgement producer and the exact local STATUS
// encoding/rendering path, rather than manufacturing diagnostic JSON.
mod routed_status {
    use super::*;
    use cardano_kes_forge::host::{client::operator_status, signing};
    use kes_core::cbor::Encoder;
    use kes_protocol::{Envelope, EnvelopeKind, Operation, Status};

    const CONNECTION: &str = "pool-0";
    const SESSION: signing::Session = signing::Session {
        boot_nonce: [2; 32],
        session: [3; 16],
    };

    fn router() -> signing::Router {
        signing::Router::new([(
            CONNECTION.into(),
            signing::Binding {
                device: [1; 16],
                pool: [4; 28],
                incarnation: [5; 16],
                network: network(),
            },
        )])
        .unwrap()
    }

    fn frame(
        operation: Operation,
        response: bool,
        payload: impl FnOnce(&mut Encoder<'_>),
    ) -> Vec<u8> {
        let mut bytes = [0; kes_protocol::MAX_FRAME_BYTES];
        let mut e = Encoder::new(&mut bytes);
        e.map(6).unwrap();
        e.text("op").unwrap();
        e.text(operation.as_str()).unwrap();
        if response {
            e.text("status").unwrap();
            e.text("OK").unwrap();
        }
        e.text("payload").unwrap();
        payload(&mut e);
        e.text("request").unwrap();
        e.bytes(&[12; 16]).unwrap();
        e.text("version").unwrap();
        e.uint(1).unwrap();
        if !response {
            e.text("budget_ms").unwrap();
            e.uint(500).unwrap();
        }
        e.text("connection").unwrap();
        e.text(CONNECTION).unwrap();
        e.finish().unwrap().encoded().to_vec()
    }

    fn descriptor(e: &mut Encoder<'_>, generation: u8, revision: u64, staged: bool) {
        e.map(13).unwrap();
        e.text("health").unwrap();
        e.text("healthy").unwrap();
        e.text("revision").unwrap();
        e.uint(revision).unwrap();
        e.text("lifecycle").unwrap();
        e.text(if staged { "certified-staged" } else { "active" })
            .unwrap();
        e.text("generation").unwrap();
        e.bytes(&[generation; 16]).unwrap();
        e.text("artifact_digest").unwrap();
        e.bytes(&[8; 32]).unwrap();
        e.text("relative_period").unwrap();
        e.uint(4).unwrap();
        e.text("backup_available").unwrap();
        e.boolean(true).unwrap();
        e.text("creation_request").unwrap();
        e.bytes(&[9; 16]).unwrap();
        e.text("verification_key").unwrap();
        e.bytes(&[10; 32]).unwrap();
        e.text("certificate_start").unwrap();
        e.uint(100).unwrap();
        e.text("generation_number").unwrap();
        e.uint(u64::from(generation)).unwrap();
        e.text("certificate_digest").unwrap();
        e.bytes(&[7; 32]).unwrap();
        e.text("certificate_counter").unwrap();
        e.uint(1).unwrap();
    }

    fn status(generation: u8, revision: u64, staged: bool) -> Vec<u8> {
        status_authorized(generation, revision, staged, 0, false)
    }

    fn status_authorized(
        generation: u8,
        revision: u64,
        staged: bool,
        epoch: u64,
        revoked: bool,
    ) -> Vec<u8> {
        frame(Operation::Status, true, |e| {
            e.map(9).unwrap();
            e.text("active").unwrap();
            descriptor(e, generation, revision, false);
            e.text("health").unwrap();
            e.text("healthy").unwrap();
            e.text("staged").unwrap();
            if staged {
                descriptor(e, 20, revision, true);
            } else {
                e.null().unwrap();
            }
            e.text("revoked").unwrap();
            e.boolean(revoked).unwrap();
            e.text("revision").unwrap();
            e.uint(revision).unwrap();
            e.text("directory").unwrap();
            e.array(0).unwrap();
            e.text("security_mode").unwrap();
            e.text("development").unwrap();
            e.text("blocking_reason").unwrap();
            e.text("").unwrap();
            e.text("credential_epoch").unwrap();
            e.uint(epoch).unwrap();
        })
    }

    fn status_request() -> Vec<u8> {
        frame(Operation::Status, false, |e| {
            e.map(0).unwrap();
        })
    }

    fn observe() -> Vec<u8> {
        frame(Operation::ObservePeriod, false, |e| {
            e.map(3).unwrap();
            e.text("network").unwrap();
            e.map(4).unwrap();
            e.text("network_magic").unwrap();
            e.uint(42).unwrap();
            e.text("max_kes_evolutions").unwrap();
            e.uint(64).unwrap();
            e.text("slots_per_kes_period").unwrap();
            e.uint(64).unwrap();
            e.text("shelley_genesis_digest").unwrap();
            e.bytes(&[9; 32]).unwrap();
            e.text("absolute_period").unwrap();
            e.uint(104).unwrap();
            e.text("expected_revision").unwrap();
            e.uint(8).unwrap();
        })
    }

    fn read(router: &signing::Router, wire: &[u8], now: u64) -> serde_json::Value {
        let mut bytes = [0; kes_protocol::MAX_FRAME_BYTES];
        let length = operator_status::attach_at(
            wire,
            &mut bytes,
            &[1; 16],
            Some((&[4; 28], &[5; 16])),
            router,
            CONNECTION,
            now,
        )
        .unwrap();
        operator_status::render(
            Envelope::parse(&bytes[..length], EnvelopeKind::LocalResponse).unwrap(),
            [1; 16],
            Some([4; 28]),
            Some([5; 16]),
            None,
            [12; 16],
        )
        .unwrap()
    }

    fn initialized() -> signing::Router {
        let mut router = router();
        router
            .complete(
                CONNECTION,
                &status_request(),
                &status(6, 8, false),
                SESSION,
                Duration::ZERO,
            )
            .unwrap();
        let response = frame(Operation::ObservePeriod, true, |e| {
            descriptor(e, 6, 8, false)
        });
        router
            .complete(
                CONNECTION,
                &observe(),
                &response,
                SESSION,
                Duration::from_micros(75_001),
            )
            .unwrap();
        router
    }

    #[test]
    fn staging_and_repeated_status_do_not_renew_operational_clocks_or_samples() {
        let mut router = initialized();
        let before = read(&router, &status(6, 8, false), router.monotonic_ms());
        let sample = &before["result"]["latency"]["OBSERVE_PERIOD"]["sample"];
        assert_eq!(sample["outcome"], "success");
        assert_eq!(sample["code"], "OK");
        // Includes admission-to-response elapsed time and daemon validation.
        assert!(sample["durationMs"].as_u64().unwrap() >= 76);
        let now = router.monotonic_ms();
        let base = now
            - router
                .observation(CONNECTION, now)
                .unwrap()
                .confirmed_age_ms
                .unwrap();
        let staged = status(6, 9, true);
        router
            .complete(
                CONNECTION,
                &status_request(),
                &staged,
                SESSION,
                Duration::from_millis(10),
            )
            .unwrap();
        for (age, expected) in [(29_999, "fresh"), (30_000, "stale"), (30_001, "stale")] {
            let rendered = read(&router, &staged, base + age);
            let result = &rendered["result"];
            assert_eq!(result["observation"]["confirmedAgeMs"], age);
            if age == 29_999 {
                assert_eq!(
                    result["observation"]["context"],
                    before["result"]["observation"]["context"]
                );
                assert_eq!(result["ready"], true);
                assert_eq!(result["remainingValidityPeriods"], 60);
            }
            assert_eq!(result["observation"]["state"], expected);
            assert_eq!(
                result["observation"]["confirmedObservedAt"],
                before["result"]["observation"]["confirmedObservedAt"]
            );
            assert_eq!(
                result["observation"]["nodePeriodObservedAt"],
                before["result"]["observation"]["nodePeriodObservedAt"]
            );
            assert_eq!(
                result["latency"]["OBSERVE_PERIOD"]["sample"]["durationMs"],
                before["result"]["latency"]["OBSERVE_PERIOD"]["sample"]["durationMs"]
            );
            assert_eq!(result["active"]["certificateStart"], 100);
            assert_eq!(result["staged"]["generation"], "14".repeat(16));
            if age >= 30_000 {
                assert!(result["ready"].is_null());
                assert!(result["remainingValidityPeriods"].is_null());
            }
        }
    }

    #[test]
    fn timeout_is_visible_without_readiness_and_restart_or_session_replacement_clears_samples() {
        let mut router = initialized();
        router.terminal(
            CONNECTION,
            &observe(),
            Status::DeadlineExceeded,
            Duration::from_micros(500_001),
        );
        let wire = status(6, 8, false);
        let terminal = read(&router, &wire, router.monotonic_ms());
        let sample = &terminal["result"]["latency"]["OBSERVE_PERIOD"]["sample"];
        assert_eq!(sample["durationMs"], 501);
        assert_eq!(sample["outcome"], "error");
        assert_eq!(sample["code"], "DEADLINE_EXCEEDED");
        assert_eq!(terminal["result"]["observation"]["state"], "unavailable");
        assert!(terminal["result"]["ready"].is_null());
        assert_eq!(
            terminal["result"]["observation"]["historical"]["generation"],
            "06".repeat(16)
        );
        let replacement = signing::Session {
            session: [30; 16],
            ..SESSION
        };
        router
            .complete(
                CONNECTION,
                &status_request(),
                &wire,
                replacement,
                Duration::ZERO,
            )
            .unwrap();
        let replaced = read(&router, &wire, router.monotonic_ms());
        assert_eq!(
            replaced["result"]["latency"]["OBSERVE_PERIOD"]["state"],
            "unavailable"
        );
        assert!(replaced["result"]["ready"].is_null());
        let restarted = read(&self::router(), &wire, 0);
        assert_eq!(restarted["result"]["observation"]["state"], "unavailable");
        assert!(restarted["result"]["latency"]["OBSERVE_PERIOD"]["sample"].is_null());
    }

    #[test]
    fn activation_status_discards_old_node_join_and_delayed_retired_reply() {
        let mut router = initialized();
        let replacement = status(10, 9, false);
        router
            .complete(
                CONNECTION,
                &status_request(),
                &replacement,
                SESSION,
                Duration::ZERO,
            )
            .unwrap();
        let activated = read(&router, &replacement, router.monotonic_ms());
        assert!(activated["result"]["ready"].is_null());
        let delayed = status(6, 100, false);
        assert_eq!(
            router.complete(
                CONNECTION,
                &status_request(),
                &delayed,
                SESSION,
                Duration::ZERO
            ),
            Err(signing::Error::ContextMismatch)
        );
        let rejected = read(&router, &replacement, router.monotonic_ms());
        assert!(rejected["result"]["ready"].is_null());
        assert_eq!(
            rejected["result"]["observation"]["historical"]["generation"],
            "0a".repeat(16)
        );
    }

    #[test]
    fn staging_cannot_preserve_readiness_across_authorization_changes() {
        for (epoch, revoked) in [(1, false), (0, true)] {
            let mut router = initialized();
            let changed = status_authorized(6, 9, true, epoch, revoked);
            router
                .complete(
                    CONNECTION,
                    &status_request(),
                    &changed,
                    SESSION,
                    Duration::ZERO,
                )
                .unwrap();
            let result = read(&router, &changed, router.monotonic_ms());
            assert_eq!(result["result"]["observation"]["state"], "unavailable");
            assert!(result["result"]["ready"].is_null());
            assert!(result["result"]["remainingValidityPeriods"].is_null());
            // Repeating the new STATUS does not recover the invalidated join.
            router
                .complete(
                    CONNECTION,
                    &status_request(),
                    &changed,
                    SESSION,
                    Duration::ZERO,
                )
                .unwrap();
            assert!(read(&router, &changed, router.monotonic_ms())["result"]["ready"].is_null());
        }
    }

    #[test]
    fn real_daemon_queue_time_reaches_success_and_expired_operator_samples() {
        use cardano_kes_forge::host::{
            daemon::{Config, Daemon, DeviceTransport, TransportError},
            socket::Frame,
        };
        use std::{
            io::{Read, Write},
            os::unix::{fs::PermissionsExt, net::UnixStream},
            sync::{
                Arc, Mutex,
                atomic::{AtomicBool, Ordering},
                mpsc,
            },
            thread,
            time::Instant,
        };

        // Controlled acknowledgements behind the real daemon's single-flight
        // scheduler; diagnostics are produced by the normal Router, not fixtures.
        struct QueuedTransport {
            router: Arc<Mutex<signing::Router>>,
            delay: Duration,
            entered: mpsc::SyncSender<()>,
            finished: mpsc::SyncSender<()>,
        }
        impl DeviceTransport for QueuedTransport {
            fn exchange(
                &mut self,
                frame: &mut Frame,
                remaining: Duration,
            ) -> Result<(), TransportError> {
                self.exchange_admitted(frame, remaining, Instant::now())
            }
            fn exchange_admitted(
                &mut self,
                job: &mut Frame,
                _: Duration,
                admitted: Instant,
            ) -> Result<(), TransportError> {
                let request = job.as_slice().to_vec();
                let op = Envelope::parse(&request, EnvelopeKind::LocalRequest)
                    .unwrap()
                    .operation;
                let reply = if op == Operation::Status {
                    self.entered.send(()).unwrap();
                    thread::sleep(self.delay);
                    status(6, 8, false)
                } else {
                    frame(Operation::ObservePeriod, true, |e| {
                        descriptor(e, 6, 8, false)
                    })
                };
                self.router
                    .lock()
                    .unwrap()
                    .complete(CONNECTION, &request, &reply, SESSION, admitted.elapsed())
                    .unwrap();
                job.replace(&reply).unwrap();
                if op != Operation::Status {
                    self.finished.send(()).unwrap();
                }
                Ok(())
            }
            fn expired(&mut self, job: &Frame, admitted: Instant) {
                self.router.lock().unwrap().terminal(
                    CONNECTION,
                    job.as_slice(),
                    Status::DeadlineExceeded,
                    admitted.elapsed(),
                );
                if Envelope::parse(job.as_slice(), EnvelopeKind::LocalRequest)
                    .is_ok_and(|request| request.operation == Operation::ObservePeriod)
                {
                    self.finished.send(()).unwrap();
                }
            }
        }

        fn send(socket: &std::path::Path, bytes: Vec<u8>) -> thread::JoinHandle<Status> {
            let mut stream = UnixStream::connect(socket).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            stream
                .write_all(&(bytes.len() as u32).to_be_bytes())
                .unwrap();
            stream.write_all(&bytes).unwrap();
            thread::spawn(move || {
                let mut prefix = [0; 4];
                stream.read_exact(&mut prefix).unwrap();
                let mut reply = vec![0; u32::from_be_bytes(prefix) as usize];
                stream.read_exact(&mut reply).unwrap();
                Envelope::parse(&reply, EnvelopeKind::LocalResponse)
                    .unwrap()
                    .status
                    .unwrap()
            })
        }

        for (delay_ms, outcome, code) in
            [(80, "success", "OK"), (650, "error", "DEADLINE_EXCEEDED")]
        {
            let root = std::env::temp_dir().join(format!(
                "kes-status-queue-{}-{delay_ms}",
                std::process::id()
            ));
            std::fs::create_dir(&root).unwrap();
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o750)).unwrap();
            let socket = root.join("daemon.sock");
            let router = Arc::new(Mutex::new(initialized()));
            let (entered_tx, entered_rx) = mpsc::sync_channel(1);
            let (finished_tx, finished_rx) = mpsc::sync_channel(2);
            let uid = rustix::process::getuid().as_raw();
            let daemon = Daemon::new(
                Config {
                    management_connection: "management".into(),
                    pool_connections: vec![CONNECTION.into()],
                    allowed_peer_uids: vec![(uid, vec![CONNECTION.into()])],
                },
                QueuedTransport {
                    router: Arc::clone(&router),
                    delay: Duration::from_millis(delay_ms),
                    entered: entered_tx,
                    finished: finished_tx,
                },
            )
            .unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let server_stop = Arc::clone(&stop);
            let server_socket = socket.clone();
            let server =
                thread::spawn(move || daemon.serve_until(&server_socket, &server_stop).unwrap());
            let ready_deadline = Instant::now() + Duration::from_secs(3);
            while !socket.exists() {
                assert!(Instant::now() < ready_deadline);
                thread::sleep(Duration::from_millis(1));
            }
            let blocker = send(&socket, status_request());
            entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            let queued = send(&socket, observe());
            let result = queued.join().unwrap();
            blocker.join().unwrap();
            finished_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            stop.store(true, Ordering::Release);
            server.join().unwrap();
            std::fs::remove_dir_all(root).unwrap();

            let router = router.lock().unwrap();
            let rendered = read(&router, &status(6, 8, false), router.monotonic_ms());
            let sample = &rendered["result"]["latency"]["OBSERVE_PERIOD"]["sample"];
            assert_eq!(sample["outcome"], outcome);
            assert_eq!(sample["code"], code);
            assert_eq!(result.as_str(), code);
            assert!(
                sample["durationMs"].as_u64().unwrap()
                    >= if outcome == "success" { 50 } else { 500 }
            );
            if outcome == "error" {
                assert!(rendered["result"]["ready"].is_null());
                assert!(rendered["result"]["remainingValidityPeriods"].is_null());
            }
        }
    }
}

#[test]
fn generation_high_water_allows_many_rotations_without_forgetting_retired_numbers() {
    let mut cache = observation::Cache::default();
    cache.connect();
    let record = |number: u64, revision: u64| {
        let mut context = context(0, revision);
        context.generation[..8].copy_from_slice(&number.to_be_bytes());
        observation::ConfirmedObservation {
            context,
            generation_number: number,
            relative_period: 0,
            service_ready: true,
            observed_at: "2026-01-02T03:04:05Z".into(),
            monotonic_ms: revision,
        }
    };
    for number in 1..=1024 {
        assert!(cache.record_confirmed(record(number, number)));
    }
    cache.invalidate_session();
    cache.connect();
    assert!(!cache.record_confirmed(record(1, 2048)));
    let mut reused_number = record(1024, 2049);
    reused_number.context.generation = [99; 16];
    assert!(!cache.record_confirmed(reused_number));
    let mut changed_number = record(1024, 2050);
    changed_number.generation_number = 1025;
    assert!(!cache.record_confirmed(changed_number));
    assert_eq!(cache.view(2051).historical.unwrap().revision, 1024);
    assert!(cache.view(2051).ready.is_none());
}
