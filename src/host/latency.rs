use super::observation::NetworkContext;
use std::time::Duration;

pub const LATENCY_MAX_AGE_MS: u64 = 30_000;
pub const OPERATION_COUNT: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Generate,
    GetBackup,
    Certify,
    Activate,
    Schedule,
    Evolve,
    Sign,
    ObservePeriod,
}

impl Operation {
    pub const ALL: [Self; OPERATION_COUNT] = [
        Self::Generate,
        Self::GetBackup,
        Self::Certify,
        Self::Activate,
        Self::Schedule,
        Self::Evolve,
        Self::Sign,
        Self::ObservePeriod,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Generate => "GENERATE",
            Self::GetBackup => "GET_BACKUP",
            Self::Certify => "CERTIFY",
            Self::Activate => "ACTIVATE",
            Self::Schedule => "SCHEDULE",
            Self::Evolve => "EVOLVE",
            Self::Sign => "SIGN",
            Self::ObservePeriod => "OBSERVE_PERIOD",
        }
    }

    const fn index(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Success,
    Error,
}

impl Outcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Context {
    pub device: [u8; 16],
    pub boot_nonce: [u8; 32],
    pub session: [u8; 16],
    pub pool: [u8; 28],
    pub incarnation: [u8; 16],
    pub network: NetworkContext,
    pub generation: Option<[u8; 16]>,
    pub certificate_digest: Option<[u8; 32]>,
    pub revision: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sample {
    pub operation: Operation,
    pub request: [u8; 16],
    pub duration_ms: u64,
    pub outcome: Outcome,
    pub code: String,
    pub observed_at: String,
    pub completed_monotonic_ms: u64,
    pub context: Context,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Fresh,
    Stale,
    Unavailable,
}

impl State {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Stale => "stale",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct View<'a> {
    pub state: State,
    pub sample: Option<&'a Sample>,
    pub age_ms: Option<u64>,
}

pub struct Samples {
    entries: [Option<Sample>; OPERATION_COUNT],
}

impl Default for Samples {
    fn default() -> Self {
        Self {
            entries: std::array::from_fn(|_| None),
        }
    }
}

impl Samples {
    pub fn record(&mut self, sample: Sample) {
        let index = sample.operation.index();
        self.entries[index] = Some(sample);
    }

    pub fn clear_for_session_replacement(&mut self) {
        self.entries = std::array::from_fn(|_| None);
    }

    pub fn view(&self, operation: Operation, now_ms: u64) -> View<'_> {
        let Some(sample) = self.entries[operation.index()].as_ref() else {
            return View {
                state: State::Unavailable,
                sample: None,
                age_ms: None,
            };
        };
        let age_ms = now_ms.saturating_sub(sample.completed_monotonic_ms);
        View {
            state: if age_ms < LATENCY_MAX_AGE_MS {
                State::Fresh
            } else {
                State::Stale
            },
            sample: Some(sample),
            age_ms: Some(age_ms),
        }
    }
}

pub fn ceil_milliseconds(duration: Duration) -> u64 {
    let nanos = duration.as_nanos();
    let rounded = nanos.saturating_add(999_999) / 1_000_000;
    u64::try_from(rounded).unwrap_or(u64::MAX)
}
