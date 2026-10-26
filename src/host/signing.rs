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
    observations: Cache,
    latency: latency::Samples,
    rotation: RotationCache,
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
                            observations: Cache::default(),
                            latency: latency::Samples::default(),
                            rotation: RotationCache::default(),
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
        let now_ms = latency::ceil_milliseconds(self.started.elapsed());
        let observed_at = wall_time();
        let state = self
            .pools
            .get_mut(connection)
            .ok_or(Error::UnknownConnection)?;
        if state.session != Some(session) {
            state.session = Some(session);
            state.active = None;
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
        let validation = if status == Status::Ok {
            validate_success(state, request, response, session, now_ms, &observed_at)
        } else {
            Ok(())
        };
        record_latency(
            state,
            request.operation,
            request_id,
            elapsed,
            status,
            validation.as_ref().err(),
            now_ms,
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
            let mut reconciled = state.rotation.clone();
            reconciled
                .reconcile_status(revision, active.clone(), staged)
                .map_err(|_| Error::ContextMismatch)?;
            if let Some(active) = active {
                install_active(state, active, session, now_ms, observed_at)?;
            } else {
                state.active = None;
                state.observations.set_mutation_unresolved(true);
            }
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
            let context = observation_context(state, session)?;
            let absolute_period = number(request.payload(), "absolute_period", false)?;
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
            record_confirmed(state, session, now_ms, observed_at)
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
    record_confirmed(state, session, now_ms, observed_at)
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
    state.active = Some(descriptor);
    record_confirmed(state, session, now_ms, observed_at)
}

fn record_confirmed(
    state: &mut PoolState,
    session: Session,
    now_ms: u64,
    observed_at: &str,
) -> Result<(), Error> {
    let active = state.active.as_ref().ok_or(Error::ContextMismatch)?.clone();
    state
        .rotation
        .record_active(active.clone())
        .map_err(|_| Error::ContextMismatch)?;
    state.observations.set_mutation_unresolved(false);
    if !state.observations.record_confirmed(ConfirmedObservation {
        context: observation_context(state, session)?,
        relative_period: active.relative_period,
        service_ready: active.lifecycle == "active" && active.health == "healthy",
        observed_at: observed_at.to_owned(),
        monotonic_ms: now_ms,
    }) {
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
        outcome: if status == Status::Ok && validation_error.is_none() {
            latency::Outcome::Success
        } else {
            latency::Outcome::Error
        },
        code: if validation_error.is_some() {
            "INVALID_RESPONSE".to_owned()
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
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    format!("unix-ms:{millis}")
}
