use std::time::Duration;

pub const OBSERVATION_MAX_AGE: Duration = Duration::from_millis(30_000);
pub const OBSERVATION_MAX_AGE_MS: u64 = 30_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkContext {
    pub network_magic: u32,
    pub shelley_genesis_digest: [u8; 32],
    pub slots_per_kes_period: u64,
    pub max_kes_evolutions: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationContext {
    pub device: [u8; 16],
    pub boot_nonce: [u8; 32],
    pub session: [u8; 16],
    pub pool: [u8; 28],
    pub incarnation: [u8; 16],
    pub network: NetworkContext,
    pub generation: [u8; 16],
    pub certificate_digest: [u8; 32],
    pub revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoricalDescriptor {
    pub generation: [u8; 16],
    pub certificate_digest: [u8; 32],
    pub revision: u64,
    pub relative_period: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfirmedObservation {
    pub context: ObservationContext,
    pub relative_period: u64,
    pub service_ready: bool,
    pub observed_at: String,
    pub monotonic_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodePeriodObservation {
    pub context: ObservationContext,
    pub absolute_period: u64,
    pub observed_at: String,
    pub monotonic_ms: u64,
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
    pub confirmed_age_ms: Option<u64>,
    pub node_period_age_ms: Option<u64>,
    pub confirmed_observed_at: Option<&'a str>,
    pub node_period_observed_at: Option<&'a str>,
    pub context: Option<&'a ObservationContext>,
    pub historical: Option<&'a HistoricalDescriptor>,
    pub ready: Option<bool>,
    pub remaining_validity_periods: Option<u64>,
}

#[derive(Default)]
pub struct Cache {
    confirmed: Option<ConfirmedObservation>,
    node_period: Option<NodePeriodObservation>,
    historical: Option<HistoricalDescriptor>,
    connected: bool,
    mutation_unresolved: bool,
}

impl Cache {
    pub fn connect(&mut self) {
        self.connected = true;
    }

    pub fn disconnect(&mut self) {
        self.connected = false;
        self.invalidate_current();
    }

    pub fn set_mutation_unresolved(&mut self, unresolved: bool) {
        self.mutation_unresolved = unresolved;
        if unresolved {
            self.invalidate_current();
        }
    }

    pub fn record_confirmed(&mut self, observation: ConfirmedObservation) -> bool {
        if let Some(historical) = self.historical.as_ref() {
            if observation.context.revision < historical.revision
                || (observation.context.revision == historical.revision
                    && (observation.context.generation != historical.generation
                        || observation.context.certificate_digest != historical.certificate_digest))
            {
                return false;
            }
        }
        if let Some(current) = self.confirmed.as_ref() {
            if !same_pool_context(&observation.context, &current.context) {
                return false;
            }
            if observation.context != current.context {
                self.invalidate_current();
            }
        }
        self.historical = Some(HistoricalDescriptor {
            generation: observation.context.generation,
            certificate_digest: observation.context.certificate_digest,
            revision: observation.context.revision,
            relative_period: observation.relative_period,
        });
        self.confirmed = Some(observation);
        true
    }

    pub fn record_node_period(&mut self, observation: NodePeriodObservation) -> bool {
        if self
            .confirmed
            .as_ref()
            .is_none_or(|confirmed| confirmed.context != observation.context)
        {
            return false;
        }
        self.node_period = Some(observation);
        true
    }

    pub fn invalidate_session(&mut self) {
        self.connected = false;
        self.invalidate_current();
    }

    pub fn view(&self, now_ms: u64) -> View<'_> {
        let confirmed_age_ms = self
            .confirmed
            .as_ref()
            .map(|value| now_ms.saturating_sub(value.monotonic_ms));
        let node_period_age_ms = self
            .node_period
            .as_ref()
            .map(|value| now_ms.saturating_sub(value.monotonic_ms));
        let matched = self
            .confirmed
            .as_ref()
            .zip(self.node_period.as_ref())
            .filter(|(confirmed, node)| confirmed.context == node.context);
        let state = if !self.connected || self.mutation_unresolved || matched.is_none() {
            State::Unavailable
        } else if confirmed_age_ms.is_some_and(|age| age >= OBSERVATION_MAX_AGE_MS)
            || node_period_age_ms.is_some_and(|age| age >= OBSERVATION_MAX_AGE_MS)
        {
            State::Stale
        } else {
            State::Fresh
        };
        let (context, ready, remaining_validity_periods) = if state == State::Fresh {
            let (confirmed, _) = matched.expect("fresh observations are matched");
            (
                Some(&confirmed.context),
                Some(confirmed.service_ready),
                confirmed
                    .context
                    .network
                    .max_kes_evolutions
                    .checked_sub(confirmed.relative_period),
            )
        } else {
            (None, None, None)
        };
        View {
            state,
            confirmed_age_ms,
            node_period_age_ms,
            confirmed_observed_at: self
                .confirmed
                .as_ref()
                .map(|value| value.observed_at.as_str()),
            node_period_observed_at: self
                .node_period
                .as_ref()
                .map(|value| value.observed_at.as_str()),
            context,
            historical: self.historical.as_ref(),
            ready,
            remaining_validity_periods,
        }
    }

    fn invalidate_current(&mut self) {
        self.confirmed = None;
        self.node_period = None;
    }
}

fn same_pool_context(left: &ObservationContext, right: &ObservationContext) -> bool {
    left.device == right.device
        && left.pool == right.pool
        && left.incarnation == right.incarnation
        && left.network == right.network
}
