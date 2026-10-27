use super::latency;
use super::observation::{
    Cache, ConfirmedObservation, NetworkContext, NodePeriodObservation, ObservationContext, View,
};
use super::rotation::{self, Cache as RotationCache, Descriptor, Intent};
use kes_core::cbor::Map;
use kes_core::crypto::verify;
use kes_core::types::{KesLifetime, RelativePeriod};
use kes_protocol::{Envelope, EnvelopeKind, Operation, Status};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Binding {
    pub device: [u8; 16],
    pub pool: [u8; 28],
    pub incarnation: [u8; 16],
    pub network: NetworkContext,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Session {
    pub boot_nonce: [u8; 32],
    pub session: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    UnknownConnection,
    InvalidRequest,
    InvalidResponse,
    ContextMismatch,
    Signature,
}

struct PoolState {
    binding: Binding,
    active: Option<Descriptor>,
    session: Option<Session>,
    authorization: Option<(u64, bool)>,
    observations: Cache,
    latency: latency::Samples,
    rotation: RotationCache,
    historical_public: Option<Vec<u8>>,
}

pub struct Router {
    started: Instant,
    pools: BTreeMap<String, PoolState>,
}

impl Router {
    pub fn new(bindings: impl IntoIterator<Item = (String, Binding)>) -> Result<Self, Error> {
        let mut pools = BTreeMap::new();
        for (connection, binding) in bindings {
            if connection.is_empty()
                || pools
                    .insert(
                        connection,
                        PoolState {
                            binding,
                            active: None,
                            session: None,
                            authorization: None,
                            observations: Cache::default(),
                            latency: latency::Samples::default(),
                            rotation: RotationCache::default(),
                            historical_public: None,
                        },
                    )
                    .is_some()
            {
                return Err(Error::InvalidRequest);
            }
        }
        Ok(Self {
            started: Instant::now(),
            pools,
        })
    }

    /// Validates an authenticated local response before it is returned to the
    /// native caller. Successful SIGN responses are independently checked with
    /// the authenticated active descriptor's public KES key.
    pub fn complete(
        &mut self,
        connection: &str,
        request_bytes: &[u8],
        response_bytes: &[u8],
        session: Session,
        elapsed: Duration,
    ) -> Result<(), Error> {
        let validation_started = Instant::now();
        let now_ms = latency::ceil_milliseconds(self.started.elapsed());
        let observed_at = wall_time();
        let state = self
            .pools
            .get_mut(connection)
            .ok_or(Error::UnknownConnection)?;
        if state.session != Some(session) {
            state.session = Some(session);
            state.active = None;
            state.authorization = None;
            state.rotation.mark_unreconciled();
            state.observations.invalidate_session();
            state.observations.connect();
            state.latency.clear_for_session_replacement();
        } else {
            state.observations.connect();
        }
        let request = Envelope::parse(request_bytes, EnvelopeKind::LocalRequest)
            .map_err(|_| Error::InvalidRequest)?;
        let response = Envelope::parse(response_bytes, EnvelopeKind::LocalResponse)
            .map_err(|_| Error::InvalidResponse)?;
        let request_id = *request
            .request()
            .map_err(|_| Error::InvalidRequest)?
            .as_bytes();
        if request.operation != response.operation
            || request
                .map()
                .required("connection")
                .and_then(|value| value.text())
                .map_err(|_| Error::InvalidRequest)?
                != connection
            || response
                .map()
                .required("connection")
                .and_then(|value| value.text())
                .map_err(|_| Error::InvalidResponse)?
                != connection
            || response
                .request()
                .map_err(|_| Error::InvalidResponse)?
                .as_bytes()
                != &request_id
        {
            return Err(Error::ContextMismatch);
        }
        let status = response.status.ok_or(Error::InvalidResponse)?;
        let validation = match status {
            Status::Ok => validate_success(state, request, response, session, now_ms, &observed_at),
            Status::Expired => {
                validate_expired(state, request, response, session, now_ms, &observed_at)
            }
            _ => Ok(()),
        };
        if validation.is_ok() && status == Status::Ok {
            retain_public_descriptor(state, request.operation, response.payload())?;
        }
        if validation.is_ok() && status == Status::Expired {
            refresh_public_context(state, response.payload())?;
        }
        if validation.is_err()
            || matches!(
                status,
                Status::DeadlineExceeded
                    | Status::DeviceUnavailable
                    | Status::Unknown
                    | Status::StateDamaged
                    | Status::SecurityNotReady
                    | Status::AuthFailed
                    | Status::StaleGeneration
            )
        {
            state.observations.set_mutation_unresolved(true);
            state.rotation.mark_unreconciled();
        }
        record_latency(
            state,
            request.operation,
            request_id,
            elapsed.saturating_add(validation_started.elapsed()),
            status,
            validation.as_ref().err(),
            latency::ceil_milliseconds(self.started.elapsed()),
            observed_at,
            session,
        );
        validation
    }

    pub fn disconnect(&mut self, connection: &str) {
        if let Some(state) = self.pools.get_mut(connection) {
            state.session = None;
            state.active = None;
            state.rotation.mark_unreconciled();
            state.observations.disconnect();
            state.latency.clear_for_session_replacement();
        }
    }

    pub fn observation(&self, connection: &str, now_ms: u64) -> Option<View<'_>> {
        self.pools
            .get(connection)
            .map(|state| state.observations.view(now_ms))
    }

    pub fn rotation(&self, connection: &str) -> Option<rotation::View<'_>> {
        self.pools
            .get(connection)
            .map(|state| state.rotation.view())
    }

    pub fn latency(
        &self,
        connection: &str,
        operation: latency::Operation,
        now_ms: u64,
    ) -> Option<latency::View<'_>> {
        self.pools
            .get(connection)
            .map(|state| state.latency.view(operation, now_ms))
    }

    pub fn monotonic_ms(&self) -> u64 {
        latency::ceil_milliseconds(self.started.elapsed())
    }

    pub fn terminal(
        &mut self,
        connection: &str,
        request_bytes: &[u8],
        status: Status,
        elapsed: Duration,
    ) {
        if let Ok(request) = Envelope::parse(request_bytes, EnvelopeKind::LocalRequest)
            && let Ok(id) = request.request()
        {
            self.terminal_by_id(
                connection,
                request.operation,
                *id.as_bytes(),
                status,
                elapsed,
            );
        }
    }

    /// Record terminal dispatch failure using the already validated job identity.
    pub fn terminal_by_id(
        &mut self,
        connection: &str,
        operation: Operation,
        request: [u8; 16],
        status: Status,
        elapsed: Duration,
    ) {
        let now_ms = self.monotonic_ms();
        let Some(state) = self.pools.get_mut(connection) else {
            return;
        };
        let Some(session) = state.session else {
            return;
        };
        record_latency(
            state,
            operation,
            request,
            elapsed,
            status,
            None,
            now_ms,
            wall_time(),
            session,
        );
        if matches!(
            operation,
            Operation::Generate
                | Operation::Certify
                | Operation::Activate
                | Operation::Schedule
                | Operation::Evolve
                | Operation::Sign
                | Operation::ObservePeriod
        ) {
            state.observations.set_mutation_unresolved(true);
            state.rotation.mark_unreconciled();
        }
        state.observations.disconnect();
    }

    pub fn historical_public(&self, connection: &str) -> Option<kes_core::cbor::Value<'_>> {
        self.pools
            .get(connection)?
            .historical_public
            .as_deref()
            .and_then(|bytes| kes_core::cbor::Value::parse(bytes).ok())
    }
}

fn retain_public_descriptor(
    state: &mut PoolState,
    op: Operation,
    payload: Map<'_>,
) -> Result<(), Error> {
    let descriptor = match op {
        Operation::Status => {
            let value = payload
                .required("active")
                .map_err(|_| Error::InvalidResponse)?;
            if value.is_null() {
                return Ok(());
            }
            Some(value)
        }
        Operation::Activate | Operation::ObservePeriod => Some(
            kes_core::cbor::Value::parse(payload.encoded()).map_err(|_| Error::InvalidResponse)?,
        ),
        Operation::Sign | Operation::Evolve => None,
        _ => return Ok(()),
    };
    if let Some(descriptor) = descriptor {
        if state.historical_public.as_deref() != Some(descriptor.encoded()) {
            let bytes = state.historical_public.get_or_insert_with(Vec::new);
            bytes.clear();
            bytes.extend_from_slice(descriptor.encoded());
        }
    } else {
        refresh_public_context(state, payload)?;
    }
    Ok(())
}

fn refresh_public_context(state: &mut PoolState, payload: Map<'_>) -> Result<(), Error> {
    if let Some(previous) = state.historical_public.as_deref() {
        let previous = kes_core::cbor::Value::parse(previous)
            .and_then(|v| v.map())
            .map_err(|_| Error::InvalidResponse)?;
        let mut storage = [0; 2048];
        let mut encoder = kes_core::cbor::Encoder::new(&mut storage);
        encoder
            .map(previous.len())
            .map_err(|_| Error::InvalidResponse)?;
        for field in previous {
            let (key, old) = field.map_err(|_| Error::InvalidResponse)?;
            let value = if matches!(key, "revision" | "relative_period" | "lifecycle" | "health") {
                payload.required(key).map_err(|_| Error::InvalidResponse)?
            } else {
                old
            };
            encoder
                .text(key)
                .and_then(|()| encoder.value(value))
                .map_err(|_| Error::InvalidResponse)?;
        }
        let encoded = encoder.finish().map_err(|_| Error::InvalidResponse)?;
        let bytes = state
            .historical_public
            .as_mut()
            .expect("descriptor was present");
        bytes.clear();
        bytes.extend_from_slice(encoded.encoded());
    }
    Ok(())
}

fn validate_success(
    state: &mut PoolState,
    request: Envelope<'_>,
    response: Envelope<'_>,
    session: Session,
    now_ms: u64,
    observed_at: &str,
) -> Result<(), Error> {
    match request.operation {
        Operation::Status => {
            let payload = response.payload();
            let revision = number(payload, "revision", true)?;
            let active = optional_descriptor(payload, "active")?;
            let staged = optional_descriptor(payload, "staged")?;
            let epoch = number(payload, "credential_epoch", true)?;
            let revoked = payload
                .required("revoked")
                .and_then(|value| value.boolean())
                .map_err(|_| Error::InvalidResponse)?;
            if state
                .authorization
                .is_some_and(|(previous, _)| epoch < previous)
            {
                return Err(Error::ContextMismatch);
            }
            let authorization_changed = state
                .authorization
                .is_some_and(|previous| previous != (epoch, revoked));
            let mut reconciled = state.rotation.clone();
            reconciled
                .reconcile_status(revision, active.clone(), staged)
                .map_err(|_| Error::ContextMismatch)?;
            if let Some(active) = active {
                // A pool revision can advance for staging alone. Preserve the
                // active observation clocks and node join in that case; STATUS
                // must not turn a silent native client into fresh evidence.
                let same_facts = state.active.as_ref().is_some_and(|current| {
                    let mut current = current.clone();
                    current.revision = active.revision;
                    current == active
                });
                if same_facts {
                    state.active = Some(active);
                } else {
                    install_active(state, active, session, now_ms, observed_at)?;
                }
                let usable = text(payload, "health")? == "healthy"
                    && text(payload, "security_mode")? != "release-unprovisioned"
                    && !payload
                        .required("revoked")
                        .and_then(|v| v.boolean())
                        .map_err(|_| Error::InvalidResponse)?;
                state.observations.restrict_readiness(usable);
            } else {
                state.active = None;
                state.observations.set_mutation_unresolved(true);
            }
            if authorization_changed || revoked {
                state.observations.set_mutation_unresolved(true);
            }
            state.authorization = Some((epoch, revoked));
            state.rotation = reconciled;
            Ok(())
        }
        Operation::Certify => {
            let descriptor = descriptor(response.payload())?;
            if fixed::<16>(request.payload(), "generation")? != descriptor.generation {
                return Err(Error::ContextMismatch);
            }
            let certificate = request
                .payload()
                .required("certificate")
                .and_then(|value| value.bytes())
                .map_err(|_| Error::InvalidRequest)?;
            let digest: [u8; 32] = Sha256::digest(certificate).into();
            if descriptor.certificate_digest != Some(digest) {
                return Err(Error::ContextMismatch);
            }
            let mut reconciled = state.rotation.clone();
            reconciled
                .record_certified(descriptor)
                .map_err(|_| Error::ContextMismatch)?;
            state.rotation = reconciled;
            Ok(())
        }
        Operation::Schedule => {
            let descriptor = descriptor(response.payload())?;
            validate_named_identity(request.payload(), &descriptor)?;
            let expected_active_generation =
                optional_fixed(request.payload(), "expected_active_generation")?
                    .ok_or(Error::ContextMismatch)?;
            let mut reconciled = state.rotation.clone();
            reconciled
                .record_schedule(
                    descriptor.clone(),
                    Intent {
                        target_generation: descriptor.generation,
                        certificate_digest: descriptor
                            .certificate_digest
                            .ok_or(Error::ContextMismatch)?,
                        activation_absolute_period: number(
                            request.payload(),
                            "activation_absolute_period",
                            false,
                        )?,
                        creation_request: *request
                            .request()
                            .map_err(|_| Error::InvalidRequest)?
                            .as_bytes(),
                        expected_active_generation,
                        committed_revision: descriptor.revision,
                    },
                )
                .map_err(|_| Error::ContextMismatch)?;
            state.rotation = reconciled;
            Ok(())
        }
        Operation::Activate => {
            let descriptor = descriptor(response.payload())?;
            validate_named_identity(request.payload(), &descriptor)?;
            validate_descriptor_period(request.payload(), &descriptor, "current_absolute_period")?;
            let mut reconciled = state.rotation.clone();
            reconciled
                .record_active(descriptor.clone())
                .map_err(|_| Error::ContextMismatch)?;
            install_active(state, descriptor, session, now_ms, observed_at)?;
            state.rotation = reconciled;
            Ok(())
        }
        Operation::ObservePeriod => {
            validate_network(request.payload(), &state.binding.network)?;
            let descriptor = descriptor(response.payload())?;
            validate_descriptor_period(request.payload(), &descriptor, "absolute_period")?;
            let mut reconciled = state.rotation.clone();
            reconciled
                .record_active(descriptor.clone())
                .map_err(|_| Error::ContextMismatch)?;
            install_active(state, descriptor, session, now_ms, observed_at)?;
            let absolute_period = number(request.payload(), "absolute_period", false)?;
            record_node_period(state, session, absolute_period, now_ms, observed_at)?;
            state.rotation = reconciled;
            Ok(())
        }
        Operation::Evolve => {
            validate_network(request.payload(), &state.binding.network)?;
            let active = state.active.as_mut().ok_or(Error::ContextMismatch)?;
            let revision = validate_context(response.payload(), active)?;
            validate_named_identity(request.payload(), active)?;
            let relative = validate_response_period(
                request.payload(),
                response.payload(),
                active,
                "target_absolute_period",
            )?;
            active.revision = revision;
            active.relative_period = relative;
            let absolute = number(request.payload(), "target_absolute_period", false)?;
            record_confirmed(state, session, now_ms, observed_at)?;
            record_node_period(state, session, absolute, now_ms, observed_at)
        }
        Operation::Sign => verify_sign(
            state,
            request.payload(),
            response.payload(),
            session,
            now_ms,
            observed_at,
        ),
        _ => Ok(()),
    }
}

fn validate_expired(
    state: &mut PoolState,
    request: Envelope<'_>,
    response: Envelope<'_>,
    session: Session,
    now_ms: u64,
    observed_at: &str,
) -> Result<(), Error> {
    let field = match request.operation {
        Operation::Evolve => "target_absolute_period",
        Operation::Sign | Operation::ObservePeriod => "absolute_period",
        _ => return Err(Error::ContextMismatch),
    };
    validate_network(request.payload(), &state.binding.network)?;
    let absolute = number(request.payload(), field, false)?;
    let lifetime = state.binding.network.max_kes_evolutions;
    let active = state.active.as_mut().ok_or(Error::ContextMismatch)?;
    if request.operation != Operation::ObservePeriod {
        validate_named_identity(request.payload(), active)?;
    }
    let payload = response.payload();
    let revision = validate_context(payload, active)?;
    let relative = number(payload, "relative_period", true)?;
    let end = active
        .certificate_start
        .and_then(|start| start.checked_add(lifetime))
        .ok_or(Error::ContextMismatch)?;
    if absolute < end
        || relative.checked_add(1) != Some(lifetime)
        || text(payload, "lifecycle")? != "expired"
        || text(payload, "health")? != "healthy"
        || (revision == active.revision && active.lifecycle != "expired")
    {
        return Err(Error::ContextMismatch);
    }
    active.revision = revision;
    active.relative_period = relative;
    "expired".clone_into(&mut active.lifecycle);
    "healthy".clone_into(&mut active.health);
    record_confirmed(state, session, now_ms, observed_at)?;
    record_node_period(state, session, absolute, now_ms, observed_at)
}

fn verify_sign(
    state: &mut PoolState,
    request: Map<'_>,
    response: Map<'_>,
    session: Session,
    now_ms: u64,
    observed_at: &str,
) -> Result<(), Error> {
    validate_network(request, &state.binding.network)?;
    let active = state.active.as_mut().ok_or(Error::ContextMismatch)?;
    validate_named_identity(request, active)?;
    let revision = validate_context(response, active)?;
    let relative_value = validate_response_period(request, response, active, "absolute_period")?;
    let message = request
        .required("message")
        .and_then(|value| value.bytes())
        .map_err(|_| Error::InvalidRequest)?;
    let digest: [u8; 32] = Sha256::digest(message).into();
    if fixed(response, "message_digest")? != digest {
        return Err(Error::ContextMismatch);
    }
    let relative = RelativePeriod::new(relative_value).map_err(|_| Error::ContextMismatch)?;
    let lifetime = KesLifetime::new(state.binding.network.max_kes_evolutions)
        .map_err(|_| Error::ContextMismatch)?;
    let signature = response
        .required("signature")
        .and_then(|value| value.bytes())
        .map_err(|_| Error::InvalidResponse)?;
    verify(
        &active.verification_key,
        relative,
        lifetime,
        message,
        signature,
    )
    .map_err(|_| Error::Signature)?;
    active.revision = revision;
    active.relative_period = relative_value;
    let absolute = number(request, "absolute_period", false)?;
    record_confirmed(state, session, now_ms, observed_at)?;
    record_node_period(state, session, absolute, now_ms, observed_at)
}

fn install_active(
    state: &mut PoolState,
    descriptor: Descriptor,
    session: Session,
    now_ms: u64,
    observed_at: &str,
) -> Result<(), Error> {
    let lifecycle_valid = descriptor.lifecycle == "active"
        || (descriptor.lifecycle == "expired"
            && descriptor.relative_period.checked_add(1)
                == Some(state.binding.network.max_kes_evolutions));
    if !lifecycle_valid
        || descriptor.certificate_digest.is_none()
        || descriptor.certificate_start.is_none()
        || descriptor.relative_period >= state.binding.network.max_kes_evolutions
        || state
            .active
            .as_ref()
            .is_some_and(|current| descriptor.revision < current.revision)
    {
        return Err(Error::ContextMismatch);
    }
    let previous = state.active.replace(descriptor);
    if let Err(error) = record_confirmed(state, session, now_ms, observed_at) {
        state.active = previous;
        return Err(error);
    }
    Ok(())
}

fn record_confirmed(
    state: &mut PoolState,
    session: Session,
    now_ms: u64,
    observed_at: &str,
) -> Result<(), Error> {
    let active = state.active.as_ref().ok_or(Error::ContextMismatch)?.clone();
    if !state.observations.record_confirmed(ConfirmedObservation {
        context: observation_context(state, session)?,
        generation_number: active.generation_number,
        relative_period: active.relative_period,
        service_ready: active.lifecycle == "active" && active.health == "healthy",
        observed_at: observed_at.to_owned(),
        monotonic_ms: now_ms,
    }) {
        return Err(Error::ContextMismatch);
    }
    state
        .rotation
        .record_active(active.clone())
        .map_err(|_| Error::ContextMismatch)?;
    state.observations.set_mutation_unresolved(false);
    state
        .observations
        .set_certificate_start(active.certificate_start.ok_or(Error::ContextMismatch)?);
    Ok(())
}

fn record_node_period(
    state: &mut PoolState,
    session: Session,
    absolute_period: u64,
    now_ms: u64,
    observed_at: &str,
) -> Result<(), Error> {
    let context = observation_context(state, session)?;
    if !state
        .observations
        .record_node_period(NodePeriodObservation {
            context,
            absolute_period,
            observed_at: observed_at.to_owned(),
            monotonic_ms: now_ms,
        })
    {
        return Err(Error::ContextMismatch);
    }
    Ok(())
}

fn observation_context(state: &PoolState, session: Session) -> Result<ObservationContext, Error> {
    let active = state.active.as_ref().ok_or(Error::ContextMismatch)?;
    Ok(ObservationContext {
        device: state.binding.device,
        boot_nonce: session.boot_nonce,
        session: session.session,
        pool: state.binding.pool,
        incarnation: state.binding.incarnation,
        network: state.binding.network.clone(),
        generation: active.generation,
        certificate_digest: active.certificate_digest.ok_or(Error::ContextMismatch)?,
        revision: active.revision,
    })
}

fn descriptor(map: Map<'_>) -> Result<Descriptor, Error> {
    Ok(Descriptor {
        generation: fixed(map, "generation")?,
        generation_number: number(map, "generation_number", true)?,
        verification_key: fixed(map, "verification_key")?,
        certificate_digest: optional_fixed(map, "certificate_digest")?,
        certificate_start: optional_number(map, "certificate_start")?,
        revision: number(map, "revision", true)?,
        relative_period: number(map, "relative_period", true)?,
        lifecycle: text(map, "lifecycle")?.to_owned(),
        health: text(map, "health")?.to_owned(),
    })
}

fn optional_descriptor(map: Map<'_>, name: &str) -> Result<Option<Descriptor>, Error> {
    let value = map.required(name).map_err(|_| Error::InvalidResponse)?;
    if value.is_null() {
        Ok(None)
    } else {
        descriptor(value.map().map_err(|_| Error::InvalidResponse)?).map(Some)
    }
}

fn validate_named_identity(map: Map<'_>, active: &Descriptor) -> Result<(), Error> {
    if fixed::<16>(map, "generation")? != active.generation
        || fixed::<32>(map, "certificate_digest")?
            != active.certificate_digest.ok_or(Error::ContextMismatch)?
    {
        return Err(Error::ContextMismatch);
    }
    Ok(())
}

fn validate_context(map: Map<'_>, active: &Descriptor) -> Result<u64, Error> {
    validate_named_identity(map, active)?;
    let revision = number(map, "revision", true)?;
    if revision < active.revision {
        return Err(Error::ContextMismatch);
    }
    Ok(revision)
}

fn validate_descriptor_period(
    request: Map<'_>,
    descriptor: &Descriptor,
    field: &str,
) -> Result<(), Error> {
    let start = descriptor.certificate_start.ok_or(Error::ContextMismatch)?;
    let expected = start
        .checked_add(descriptor.relative_period)
        .ok_or(Error::ContextMismatch)?;
    if number(request, field, false)? != expected {
        return Err(Error::ContextMismatch);
    }
    Ok(())
}

fn validate_response_period(
    request: Map<'_>,
    response: Map<'_>,
    active: &Descriptor,
    field: &str,
) -> Result<u64, Error> {
    let start = active.certificate_start.ok_or(Error::ContextMismatch)?;
    let absolute = number(request, field, false)?;
    let relative = absolute.checked_sub(start).ok_or(Error::ContextMismatch)?;
    if number(response, "relative_period", true)? != relative {
        return Err(Error::ContextMismatch);
    }
    Ok(relative)
}

fn validate_network(payload: Map<'_>, expected: &NetworkContext) -> Result<(), Error> {
    let network = payload
        .required("network")
        .and_then(|value| value.map())
        .map_err(|_| Error::InvalidRequest)?;
    if number(network, "network_magic", false)? != u64::from(expected.network_magic)
        || fixed::<32>(network, "shelley_genesis_digest")? != expected.shelley_genesis_digest
        || number(network, "slots_per_kes_period", false)? != expected.slots_per_kes_period
        || number(network, "max_kes_evolutions", false)? != expected.max_kes_evolutions
    {
        return Err(Error::ContextMismatch);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn record_latency(
    state: &mut PoolState,
    operation: Operation,
    request: [u8; 16],
    elapsed: Duration,
    status: Status,
    validation_error: Option<&Error>,
    now_ms: u64,
    observed_at: String,
    session: Session,
) {
    let Some(operation) = latency_operation(operation) else {
        return;
    };
    let active = state.active.as_ref();
    state.latency.record(latency::Sample {
        operation,
        request,
        duration_ms: latency::ceil_milliseconds(elapsed),
        outcome: if matches!(status, Status::Ok | Status::InProgress) && validation_error.is_none()
        {
            latency::Outcome::Success
        } else {
            latency::Outcome::Error
        },
        code: if validation_error.is_some() {
            Status::InvalidFrame.as_str().to_owned()
        } else {
            status.as_str().to_owned()
        },
        observed_at,
        completed_monotonic_ms: now_ms,
        context: latency::Context {
            device: state.binding.device,
            boot_nonce: session.boot_nonce,
            session: session.session,
            pool: state.binding.pool,
            incarnation: state.binding.incarnation,
            network: state.binding.network.clone(),
            generation: active.map(|value| value.generation),
            certificate_digest: active.and_then(|value| value.certificate_digest),
            revision: active.map(|value| value.revision),
        },
    });
}

fn latency_operation(operation: Operation) -> Option<latency::Operation> {
    Some(match operation {
        Operation::Generate => latency::Operation::Generate,
        Operation::GetBackup => latency::Operation::GetBackup,
        Operation::Certify => latency::Operation::Certify,
        Operation::Activate => latency::Operation::Activate,
        Operation::Schedule => latency::Operation::Schedule,
        Operation::Evolve => latency::Operation::Evolve,
        Operation::Sign => latency::Operation::Sign,
        Operation::ObservePeriod => latency::Operation::ObservePeriod,
        _ => return None,
    })
}

fn fixed<const N: usize>(map: Map<'_>, field: &str) -> Result<[u8; N], Error> {
    map.required(field)
        .and_then(|value| value.bytes())
        .map_err(|_| Error::InvalidResponse)?
        .try_into()
        .map_err(|_| Error::InvalidResponse)
}

fn optional_fixed<const N: usize>(map: Map<'_>, field: &str) -> Result<Option<[u8; N]>, Error> {
    let value = map.required(field).map_err(|_| Error::InvalidResponse)?;
    if value.is_null() {
        Ok(None)
    } else {
        value
            .bytes()
            .map_err(|_| Error::InvalidResponse)?
            .try_into()
            .map(Some)
            .map_err(|_| Error::InvalidResponse)
    }
}

fn optional_number(map: Map<'_>, field: &str) -> Result<Option<u64>, Error> {
    let value = map.required(field).map_err(|_| Error::InvalidResponse)?;
    if value.is_null() {
        Ok(None)
    } else {
        value.uint().map(Some).map_err(|_| Error::InvalidResponse)
    }
}

fn number(map: Map<'_>, field: &str, response: bool) -> Result<u64, Error> {
    map.required(field)
        .and_then(|value| value.uint())
        .map_err(|_| {
            if response {
                Error::InvalidResponse
            } else {
                Error::InvalidRequest
            }
        })
}

fn text<'a>(map: Map<'a>, field: &str) -> Result<&'a str, Error> {
    map.required(field)
        .and_then(|value| value.text())
        .map_err(|_| Error::InvalidResponse)
}

fn wall_time() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = duration.as_secs();
    // Gregorian civil date conversion from days since the Unix epoch.
    let days = i64::try_from(seconds / 86400).unwrap_or(i64::MAX) + 719468;
    let era = days / 146097;
    let doe = days - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        seconds / 3600 % 24,
        seconds / 60 % 60,
        seconds % 60,
        duration.subsec_millis()
    )
}
