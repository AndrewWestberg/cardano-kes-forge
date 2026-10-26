#[allow(dead_code)]
#[path = "../../../firmware/src/scheduler.rs"]
mod scheduler;

use kes_protocol::Operation;
use scheduler::{GenerationProgress, GenerationTurnError, Scheduler, SchedulerError};

#[test]
fn admission_preserves_the_original_deadline_and_operation_caps() {
    let mut scheduler = Scheduler::new();
    let sign = scheduler.admit(Operation::Sign, 900, 1_000).unwrap();
    assert_eq!(sign.admitted_at_ms(), 1_000);
    assert_eq!(sign.deadline_ms(), 1_500);
    assert_eq!(scheduler.remaining_ms(sign, 1_200), Ok(300));
    assert_eq!(
        scheduler.admit(Operation::Status, 10, 1_201),
        Err(SchedulerError::Busy)
    );
    assert_eq!(scheduler.finish(sign, 1_500), Err(SchedulerError::Expired));

    let status = scheduler.admit(Operation::Status, 9_000, 2_000).unwrap();
    assert_eq!(status.deadline_ms(), 4_000);
    scheduler.finish(status, 3_999).unwrap();

    let other = scheduler.admit(Operation::Evolve, 37, 5_000).unwrap();
    assert_eq!(other.deadline_ms(), 5_037);
    assert_eq!(
        scheduler.remaining_ms(other, 4_999),
        Err(SchedulerError::ClockRegressed)
    );
    scheduler.abort(other).unwrap();
    assert!(!scheduler.request_active());
}

#[test]
fn generation_runs_one_leaf_per_turn_under_one_global_deadline() {
    let mut scheduler = Scheduler::new();
    let request = scheduler.admit(Operation::Generate, 900_000, 10).unwrap();
    assert_eq!(request.deadline_ms(), 600_010);
    let generation = scheduler.start_generation(request, 3).unwrap();
    scheduler.finish(request, 11).unwrap();

    let mut leaves = Vec::new();
    assert_eq!(
        scheduler.generation_turn(generation, 12, |leaf| {
            leaves.push(leaf);
            Ok::<_, ()>(())
        }),
        Ok(GenerationProgress::Advanced {
            completed_leaves: 1,
            total_leaves: 3,
        })
    );
    assert_eq!(
        scheduler.generation_turn(generation, 13, |leaf| {
            leaves.push(leaf);
            Ok::<_, ()>(())
        }),
        Ok(GenerationProgress::Advanced {
            completed_leaves: 2,
            total_leaves: 3,
        })
    );
    assert_eq!(
        scheduler.generation_turn(generation, 14, |leaf| {
            leaves.push(leaf);
            Ok::<_, ()>(())
        }),
        Ok(GenerationProgress::Complete { total_leaves: 3 })
    );
    assert_eq!(leaves, [0, 1, 2]);
    assert!(!scheduler.generation_active());

    let second_request = scheduler.admit(Operation::Generate, 100, 20).unwrap();
    let second = scheduler.start_generation(second_request, 2).unwrap();
    assert_eq!(
        scheduler.start_generation(second_request, 2),
        Err(SchedulerError::GenerationBusy)
    );
    scheduler.finish(second_request, 21).unwrap();
    assert_eq!(
        scheduler.generation_turn(second, 121, |_| Ok::<_, ()>(())),
        Err(GenerationTurnError::Scheduler(SchedulerError::Expired))
    );
    assert!(!scheduler.generation_active());

    let late_request = scheduler.admit(Operation::Generate, 100, 200).unwrap();
    scheduler.start_generation(late_request, 64).unwrap();
    assert_eq!(
        scheduler.finish(late_request, 300),
        Err(SchedulerError::Expired)
    );
    assert!(!scheduler.generation_active());

    let aborted_request = scheduler.admit(Operation::Generate, 100, 400).unwrap();
    scheduler.start_generation(aborted_request, 64).unwrap();
    scheduler.abort(aborted_request).unwrap();
    assert!(!scheduler.generation_active());
}

#[test]
fn generation_failure_clears_the_global_job_without_a_second_step() {
    let mut scheduler = Scheduler::new();
    let request = scheduler.admit(Operation::Generate, 100, 0).unwrap();
    let generation = scheduler.start_generation(request, 64).unwrap();
    scheduler.finish(request, 0).unwrap();
    let mut calls = 0;
    assert_eq!(
        scheduler.generation_turn(generation, 1, |_| {
            calls += 1;
            Err("crypto")
        }),
        Err(GenerationTurnError::Step("crypto"))
    );
    assert_eq!(calls, 1);
    assert!(!scheduler.generation_active());
}
