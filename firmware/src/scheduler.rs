//! Fixed-metadata, single-flight device scheduling.
//!
//! Request bodies remain in the gateway buffers. The scheduler stores only
//! deadlines and opaque leases; it owns no queue and never resets a deadline.

use kes_protocol::{GENERATION_BUDGET_MS, Operation, SIGNING_BUDGET_MS, STATUS_BUDGET_MS};

pub const DISPATCH_METADATA_LIMIT: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedulerError {
    Busy,
    Expired,
    ClockRegressed,
    DeadlineOverflow,
    InvalidLease,
    TokenExhausted,
    WrongOperation,
    GenerationBusy,
    InvalidLeafCount,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestLease {
    token: u32,
    operation: Operation,
    admitted_at_ms: u64,
    deadline_ms: u64,
}

impl RequestLease {
    pub const fn operation(self) -> Operation {
        self.operation
    }

    pub const fn admitted_at_ms(self) -> u64 {
        self.admitted_at_ms
    }

    pub const fn deadline_ms(self) -> u64 {
        self.deadline_ms
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenerationLease {
    token: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationProgress {
    Advanced {
        completed_leaves: u8,
        total_leaves: u8,
    },
    Complete {
        total_leaves: u8,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationTurnError<E> {
    Scheduler(SchedulerError),
    Step(E),
}

#[derive(Clone, Copy)]
struct GenerationJob {
    token: u32,
    request_token: u32,
    admitted_at_ms: u64,
    deadline_ms: u64,
    completed_leaves: u8,
    total_leaves: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum RequestSlot {
    Empty,
    Active(RequestLease),
}

#[derive(Clone, Copy)]
#[repr(u8)]
enum GenerationSlot {
    Empty,
    Active(GenerationJob),
}

pub struct Scheduler {
    request: RequestSlot,
    generation: GenerationSlot,
    next_request_token: u32,
    next_generation_token: u32,
}

impl Scheduler {
    pub const fn new() -> Self {
        Self {
            request: RequestSlot::Empty,
            generation: GenerationSlot::Empty,
            next_request_token: 0,
            next_generation_token: 0,
        }
    }

    pub fn request_active(&self) -> bool {
        matches!(self.request, RequestSlot::Active(_))
    }

    pub fn generation_active(&self) -> bool {
        matches!(self.generation, GenerationSlot::Active(_))
    }

    pub fn admit(
        &mut self,
        operation: Operation,
        remaining_budget_ms: u32,
        now_ms: u64,
    ) -> Result<RequestLease, SchedulerError> {
        if self.request_active() {
            return Err(SchedulerError::Busy);
        }
        let budget_ms = bounded_budget(operation, remaining_budget_ms);
        if budget_ms == 0 {
            return Err(SchedulerError::Expired);
        }
        let deadline_ms = now_ms
            .checked_add(u64::from(budget_ms))
            .ok_or(SchedulerError::DeadlineOverflow)?;
        let token = self.take_request_token()?;
        let lease = RequestLease {
            token,
            operation,
            admitted_at_ms: now_ms,
            deadline_ms,
        };
        self.request = RequestSlot::Active(lease);
        Ok(lease)
    }

    pub fn remaining_ms(&self, lease: RequestLease, now_ms: u64) -> Result<u32, SchedulerError> {
        self.require_request(lease)?;
        remaining(lease.admitted_at_ms, lease.deadline_ms, now_ms)
    }

    pub fn finish(&mut self, lease: RequestLease, now_ms: u64) -> Result<(), SchedulerError> {
        self.require_request(lease)?;
        let result = remaining(lease.admitted_at_ms, lease.deadline_ms, now_ms).map(|_| ());
        self.request = RequestSlot::Empty;
        if result.is_err() {
            self.clear_generation_for_request(lease);
        }
        result
    }

    pub fn abort(&mut self, lease: RequestLease) -> Result<(), SchedulerError> {
        self.require_request(lease)?;
        self.request = RequestSlot::Empty;
        self.clear_generation_for_request(lease);
        Ok(())
    }

    pub fn start_generation(
        &mut self,
        request: RequestLease,
        total_leaves: u8,
    ) -> Result<GenerationLease, SchedulerError> {
        self.require_request(request)?;
        if request.operation != Operation::Generate {
            return Err(SchedulerError::WrongOperation);
        }
        if self.generation_active() {
            return Err(SchedulerError::GenerationBusy);
        }
        if total_leaves == 0 {
            return Err(SchedulerError::InvalidLeafCount);
        }
        let token = self.take_generation_token()?;
        self.generation = GenerationSlot::Active(GenerationJob {
            token,
            request_token: request.token,
            admitted_at_ms: request.admitted_at_ms,
            deadline_ms: request.deadline_ms,
            completed_leaves: 0,
            total_leaves,
        });
        Ok(GenerationLease { token })
    }

    /// Runs exactly one cryptographic leaf step. Any error retires the job so
    /// unpublished partial secret output can be wiped by its external owner.
    pub fn generation_turn<E>(
        &mut self,
        lease: GenerationLease,
        now_ms: u64,
        step: impl FnOnce(u8) -> Result<(), E>,
    ) -> Result<GenerationProgress, GenerationTurnError<E>> {
        let GenerationSlot::Active(job) = self.generation else {
            return Err(GenerationTurnError::Scheduler(SchedulerError::InvalidLease));
        };
        if job.token != lease.token {
            return Err(GenerationTurnError::Scheduler(SchedulerError::InvalidLease));
        }
        if let Err(error) = remaining(job.admitted_at_ms, job.deadline_ms, now_ms) {
            self.generation = GenerationSlot::Empty;
            return Err(GenerationTurnError::Scheduler(error));
        }
        if let Err(error) = step(job.completed_leaves) {
            self.generation = GenerationSlot::Empty;
            return Err(GenerationTurnError::Step(error));
        }
        let completed_leaves = job.completed_leaves + 1;
        if completed_leaves == job.total_leaves {
            self.generation = GenerationSlot::Empty;
            Ok(GenerationProgress::Complete {
                total_leaves: job.total_leaves,
            })
        } else {
            self.generation = GenerationSlot::Active(GenerationJob {
                completed_leaves,
                ..job
            });
            Ok(GenerationProgress::Advanced {
                completed_leaves,
                total_leaves: job.total_leaves,
            })
        }
    }

    pub fn cancel_generation(&mut self, lease: GenerationLease) -> Result<(), SchedulerError> {
        let GenerationSlot::Active(generation) = self.generation else {
            return Err(SchedulerError::InvalidLease);
        };
        if generation.token != lease.token {
            return Err(SchedulerError::InvalidLease);
        }
        self.generation = GenerationSlot::Empty;
        Ok(())
    }

    fn clear_generation_for_request(&mut self, request: RequestLease) {
        if matches!(
            self.generation,
            GenerationSlot::Active(generation) if generation.request_token == request.token
        ) {
            self.generation = GenerationSlot::Empty;
        }
    }

    fn require_request(&self, lease: RequestLease) -> Result<(), SchedulerError> {
        if self.request == RequestSlot::Active(lease) {
            Ok(())
        } else {
            Err(SchedulerError::InvalidLease)
        }
    }

    fn take_request_token(&mut self) -> Result<u32, SchedulerError> {
        let token = self
            .next_request_token
            .checked_add(1)
            .ok_or(SchedulerError::TokenExhausted)?;
        token.checked_add(1).ok_or(SchedulerError::TokenExhausted)?;
        self.next_request_token = token;
        Ok(token)
    }

    fn take_generation_token(&mut self) -> Result<u32, SchedulerError> {
        let token = self
            .next_generation_token
            .checked_add(1)
            .ok_or(SchedulerError::TokenExhausted)?;
        token.checked_add(1).ok_or(SchedulerError::TokenExhausted)?;
        self.next_generation_token = token;
        Ok(token)
    }
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

const fn bounded_budget(operation: Operation, requested_ms: u32) -> u32 {
    let ceiling = match operation {
        Operation::Sign => SIGNING_BUDGET_MS,
        Operation::Info | Operation::Open | Operation::Status | Operation::OpStatus => {
            STATUS_BUDGET_MS
        }
        Operation::Generate => GENERATION_BUDGET_MS,
        _ => requested_ms,
    };
    if requested_ms < ceiling {
        requested_ms
    } else {
        ceiling
    }
}

fn remaining(admitted_at_ms: u64, deadline_ms: u64, now_ms: u64) -> Result<u32, SchedulerError> {
    if now_ms < admitted_at_ms {
        return Err(SchedulerError::ClockRegressed);
    }
    let remaining = deadline_ms
        .checked_sub(now_ms)
        .filter(|remaining| *remaining != 0)
        .ok_or(SchedulerError::Expired)?;
    u32::try_from(remaining).map_err(|_| SchedulerError::DeadlineOverflow)
}

const _: () = assert!(core::mem::size_of::<Scheduler>() <= DISPATCH_METADATA_LIMIT);
