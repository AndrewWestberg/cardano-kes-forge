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
        context: older,
        relative_period: 3,
        service_ready: true,
        observed_at: "2026-01-02T03:04:07Z".to_owned(),
        monotonic_ms: 1_002,
    }));
    assert_eq!(cache.view(1_003).state, observation::State::Unavailable);
}

#[test]
fn retired_generation_cannot_return_after_activation_or_disconnect() {
    let mut cache = observation::Cache::default();
    cache.connect();
    let old = context(6, 8);
    assert!(cache.record_confirmed(observation::ConfirmedObservation {
        context: old.clone(),
        relative_period: 4,
        service_ready: true,
        observed_at: "2026-01-02T03:04:05Z".to_owned(),
        monotonic_ms: 1_000,
    }));

    let mut conflicting = old.clone();
    conflicting.generation = [9; 16];
    assert!(!cache.record_confirmed(observation::ConfirmedObservation {
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
