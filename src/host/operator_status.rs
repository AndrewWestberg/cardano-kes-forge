use super::{Error, LocalConnection, exchange, parse_response, require_ok};
use crate::host::{config::PublicPoolConnection, latency, observation, signing};
use kes_core::cbor::{Encoder, Error as CborError, Value};
use kes_protocol::{Envelope, EnvelopeKind, Operation, Status};
use serde_json::{Value as Json, json};

type Result<T, E = CborError> = std::result::Result<T, E>;

fn optional<T>(
    e: &mut Encoder<'_>,
    v: Option<T>,
    f: impl FnOnce(&mut Encoder<'_>, T) -> Result<()>,
) -> Result<()> {
    match v {
        Some(v) => f(e, v),
        None => e.null(),
    }
}

fn context(e: &mut Encoder<'_>, c: &latency::Context) -> Result<()> {
    e.bytes(&c.device)?;
    e.bytes(&c.boot_nonce)?;
    e.bytes(&c.session)?;
    e.bytes(&c.pool)?;
    e.bytes(&c.incarnation)?;
    e.uint(u64::from(c.network.network_magic))?;
    e.bytes(&c.network.shelley_genesis_digest)?;
    e.uint(c.network.slots_per_kes_period)?;
    e.uint(c.network.max_kes_evolutions)?;
    optional(e, c.generation.as_ref(), |e, v| e.bytes(v))?;
    optional(e, c.certificate_digest.as_ref(), |e, v| e.bytes(v))?;
    optional(e, c.revision, |e, v| e.uint(v))
}

/// Append daemon-owned diagnostics, preserving every wire STATUS field.
/// Flat context tuples avoid exceeding the protocol's four-level nesting bound.
pub fn attach(
    response: &[u8],
    out: &mut [u8],
    device: &[u8; 16],
    target: Option<(&[u8; 28], &[u8; 16])>,
    router: &signing::Router,
    connection: &str,
) -> Result<usize> {
    attach_at(
        response,
        out,
        device,
        target,
        router,
        connection,
        router.monotonic_ms(),
    )
}

/// Serialize a snapshot at the daemon monotonic read instant. The caller must
/// use the Router clock domain, never a client-provided timestamp.
pub fn attach_at(
    response: &[u8],
    out: &mut [u8],
    device: &[u8; 16],
    target: Option<(&[u8; 28], &[u8; 16])>,
    router: &signing::Router,
    connection: &str,
    now: u64,
) -> Result<usize> {
    let (pool, incarnation) = target
        .map(|(pool, incarnation)| (Some(pool), Some(incarnation)))
        .unwrap_or((None, None));
    let envelope = Envelope::parse(response, EnvelopeKind::LocalResponse)
        .map_err(|_| CborError::InvalidType)?;
    if envelope.operation != Operation::Status || envelope.status != Some(Status::Ok) {
        out[..response.len()].copy_from_slice(response);
        return Ok(response.len());
    }
    let mut extras = [0; kes_protocol::MAX_FRAME_BYTES];
    let mut x = Encoder::new(&mut extras);
    // Canonical key ordering: host_pool, host_device, host_latency,
    // host_incarnation, host_observation.
    x.map(5)?;
    x.text("host_pool")?;
    optional(&mut x, pool, |e, v| e.bytes(v))?;
    x.text("host_device")?;
    x.bytes(device)?;
    x.text("host_latency")?;
    if pool.is_some() {
        x.array(8)?;
        for op in latency::Operation::ALL {
            let view = router.latency(connection, op, now);
            if let Some((sample, age)) = view.as_ref().and_then(|v| v.sample.zip(v.age_ms)) {
                x.array(18)?;
                x.bytes(&sample.request)?;
                x.uint(sample.duration_ms)?;
                x.text(sample.outcome.as_str())?;
                x.text(&sample.code)?;
                x.text(&sample.observed_at)?;
                x.uint(age)?;
                context(&mut x, &sample.context)?;
            } else {
                x.null()?;
            }
        }
    } else {
        x.null()?;
    }
    x.text("host_incarnation")?;
    optional(&mut x, incarnation, |e, v| e.bytes(v))?;
    x.text("host_observation")?;
    if let Some(view) = pool.and_then(|_| router.observation(connection, now)) {
        x.array(9)?;
        x.text(view.state.as_str())?;
        optional(&mut x, view.confirmed_age_ms, |e, v| e.uint(v))?;
        optional(&mut x, view.node_period_age_ms, |e, v| e.uint(v))?;
        optional(&mut x, view.confirmed_observed_at, |e, v| e.text(v))?;
        optional(&mut x, view.node_period_observed_at, |e, v| e.text(v))?;
        if let Some(c) = view.context {
            x.array(12)?;
            context(
                &mut x,
                &latency::Context {
                    device: c.device,
                    boot_nonce: c.boot_nonce,
                    session: c.session,
                    pool: c.pool,
                    incarnation: c.incarnation,
                    network: c.network.clone(),
                    generation: Some(c.generation),
                    certificate_digest: Some(c.certificate_digest),
                    revision: Some(c.revision),
                },
            )?;
        } else {
            x.null()?;
        }
        if let Some(historical) = router.historical_public(connection) {
            x.value(historical)?;
        } else {
            x.null()?;
        }
        optional(&mut x, view.ready, |e, v| e.boolean(v))?;
        optional(&mut x, view.remaining_validity_periods, |e, v| e.uint(v))?;
    } else {
        x.null()?;
    }
    let extra = x.finish()?.map()?;
    let payload = envelope.payload();
    let mut e = Encoder::new(out);
    e.map(envelope.map().len())?;
    for field in envelope.map() {
        let (key, value) = field?;
        e.text(key)?;
        if key == "payload" {
            e.map(payload.len() + extra.len())?;
            let mut left = payload.peekable();
            let mut right = extra.peekable();
            while left.peek().is_some() || right.peek().is_some() {
                let take_left = match (left.peek(), right.peek()) {
                    (Some(Ok((a, _))), Some(Ok((b, _)))) => (a.len(), a) < (b.len(), b),
                    (Some(_), _) => true,
                    _ => false,
                };
                let (k, v) = if take_left { left.next() } else { right.next() }
                    .ok_or(CborError::MissingField)??;
                e.text(k)?;
                e.value(v)?;
            }
        } else {
            e.value(value)?;
        }
    }
    Ok(e.finish()?.encoded().len())
}

pub fn pool(
    connection: &PublicPoolConnection,
    request: [u8; 16],
) -> std::result::Result<Json, Error> {
    let mut response = [0; kes_protocol::MAX_FRAME_BYTES];
    let length = exchange(
        LocalConnection::Pool(connection),
        request,
        Operation::Status,
        kes_protocol::STATUS_BUDGET_MS,
        |e| {
            e.map(1)?;
            e.text("host_diagnostics")?;
            e.boolean(true)
        },
        &mut response,
    )?;
    let envelope = parse_response(
        &connection.connection_name,
        request,
        Operation::Status,
        &response[..length],
    )?;
    render(
        envelope,
        connection.device_id,
        Some(connection.pool_id),
        Some(connection.incarnation_id),
        Some(&connection.network_binding),
        request,
    )
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 15)]));
    }
    out
}
fn public(v: Value<'_>) -> std::result::Result<Json, Error> {
    if v.is_null() {
        return Ok(Json::Null);
    }
    if let Ok(v) = v.uint() {
        return Ok(json!(v));
    }
    if let Ok(v) = v.boolean() {
        return Ok(json!(v));
    }
    if let Ok(v) = v.text() {
        return Ok(json!(v));
    }
    if let Ok(v) = v.bytes() {
        return Ok(json!(hex(v)));
    }
    if let Ok(v) = v.array() {
        return v
            .map(public)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map(Json::from);
    }
    let mut result = serde_json::Map::new();
    for entry in v.map().map_err(|_| Error::Integrity)? {
        let (k, v) = entry.map_err(|_| Error::Integrity)?;
        result.insert(camel(k), public(v)?);
    }
    Ok(Json::Object(result))
}
fn camel(s: &str) -> String {
    let mut out = String::new();
    let mut upper = false;
    for c in s.chars() {
        if c == '_' {
            upper = true;
        } else if upper {
            out.extend(c.to_uppercase());
            upper = false;
        } else {
            out.push(c);
        }
    }
    out
}
fn array(v: Value<'_>) -> std::result::Result<Vec<Value<'_>>, Error> {
    v.array().map(|v| v.collect()).map_err(|_| Error::Integrity)
}
fn context_json(
    values: &[Value<'_>],
    device: [u8; 16],
    pool: [u8; 28],
    incarnation: [u8; 16],
    network: Option<&crate::host::config::NetworkBinding>,
) -> std::result::Result<Json, Error> {
    let v = values
        .iter()
        .copied()
        .map(public)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if v.len() != 12 || v[0] != hex(&device) || v[3] != hex(&pool) || v[4] != hex(&incarnation) {
        return Err(Error::Security);
    }
    if let Some(n) = network
        && (v[5] != n.network_magic
            || v[6] != n.shelley_genesis_digest
            || v[7] != n.slots_per_kes_period
            || v[8] != n.max_kes_evolutions)
    {
        return Err(Error::Security);
    }
    Ok(
        json!({"deviceId":v[0],"bootNonce":v[1],"sessionId":v[2],"poolId":v[3],"incarnationId":v[4],"networkBinding":{"networkMagic":v[5],"shelleyGenesisDigest":v[6],"slotsPerKesPeriod":v[7],"maxKesEvolutions":v[8]},"generationId":v[9],"certificateDigest":v[10],"revision":v[11]}),
    )
}

pub fn render(
    envelope: Envelope<'_>,
    device: [u8; 16],
    pool: Option<[u8; 28]>,
    incarnation: Option<[u8; 16]>,
    network: Option<&crate::host::config::NetworkBinding>,
    request: [u8; 16],
) -> std::result::Result<Json, Error> {
    require_ok(envelope.status.ok_or(Error::Integrity)?)?;
    let m = envelope.payload();
    for (key, expected) in [
        ("host_device", Some(hex(&device))),
        ("host_pool", pool.map(|v| hex(&v))),
        ("host_incarnation", incarnation.map(|v| hex(&v))),
    ] {
        if public(m.required(key).map_err(|_| Error::Integrity)?)?
            != expected.map_or(Json::Null, Json::from)
        {
            return Err(Error::Security);
        }
    }
    let mut result = serde_json::Map::new();
    for field in m {
        let (k, v) = field.map_err(|_| Error::Integrity)?;
        if !k.starts_with("host_") {
            result.insert(camel(k), public(v)?);
        }
    }
    result.insert("releaseEvidenceVerified".into(), json!(false));
    let mut observation = Json::Null;
    let mut ready = Json::Null;
    let mut remaining = Json::Null;
    let mut latencies = Json::Null;
    if let Some((pool, incarnation)) = pool.zip(incarnation) {
        let a = array(
            m.required("host_observation")
                .map_err(|_| Error::Integrity)?,
        )?;
        let context = if a[5].is_null() {
            Json::Null
        } else {
            context_json(&array(a[5])?, device, pool, incarnation, network)?
        };
        let historical = public(a[6])?;
        ready = public(a[7])?;
        remaining = public(a[8])?;
        let state = a[0].text().map_err(|_| Error::Integrity)?;
        if state == "fresh" {
            let active = result.get("active").ok_or(Error::Integrity)?;
            if context.is_null()
                || context["generationId"] != active["generation"]
                || context["certificateDigest"] != active["certificateDigest"]
                // Staging may advance the pool revision without changing the
                // active facts or either operational observation. Keep their
                // original context/timestamps; never accept a future revision.
                || context["revision"].as_u64().is_none_or(|revision| {
                    active["revision"].as_u64().is_none_or(|active| revision > active)
                })
                || context["generationId"].is_null()
                || context["certificateDigest"].is_null()
                || a[1].uint().map_err(|_| Error::Integrity)? >= 30000
                || a[2].uint().map_err(|_| Error::Integrity)? >= 30000
                || !ready.is_boolean()
                || !remaining.is_u64()
            {
                return Err(Error::Integrity);
            }
        } else if !ready.is_null() || !remaining.is_null() || !context.is_null() {
            return Err(Error::Integrity);
        }
        observation = json!({"state":state,"observationMaxAgeMs":observation::OBSERVATION_MAX_AGE_MS,"confirmedAgeMs":public(a[1])?,"nodePeriodAgeMs":public(a[2])?,"confirmedObservedAt":public(a[3])?,"nodePeriodObservedAt":public(a[4])?,"context":context,"historical":historical});
        let mut entries = serde_json::Map::new();
        for (op, v) in latency::Operation::ALL.into_iter().zip(array(
            m.required("host_latency").map_err(|_| Error::Integrity)?,
        )?) {
            let entry = if v.is_null() {
                json!({"state":"unavailable","sample":null})
            } else {
                let a = array(v)?;
                let age = a[5].uint().map_err(|_| Error::Integrity)?;
                json!({"state":if age<30000{"fresh"}else{"stale"},"sample":{"operation":op.as_str(),"requestId":public(a[0])?,"durationMs":public(a[1])?,"outcome":public(a[2])?,"code":public(a[3])?,"observedAt":public(a[4])?,"ageMs":age,"context":context_json(&a[6..],device,pool,incarnation,network)?}})
            };
            entries.insert(op.as_str().into(), entry);
        }
        latencies = Json::Object(entries);
    } else if !m
        .required("host_observation")
        .map_err(|_| Error::Integrity)?
        .is_null()
        || !m
            .required("host_latency")
            .map_err(|_| Error::Integrity)?
            .is_null()
    {
        return Err(Error::Integrity);
    }
    let active = result.get("active").cloned().unwrap_or(Json::Null);
    result.insert(
        "certificateStart".into(),
        active
            .get("certificateStart")
            .cloned()
            .unwrap_or(Json::Null),
    );
    result.insert(
        "confirmedRelativePeriod".into(),
        active.get("relativePeriod").cloned().unwrap_or(Json::Null),
    );
    result.insert(
        "backupAvailable".into(),
        active.get("backupAvailable").cloned().unwrap_or(Json::Null),
    );
    result.insert("observation".into(), observation);
    result.insert("ready".into(), ready);
    result.insert("remainingValidityPeriods".into(), remaining);
    result.insert("latency".into(), latencies);
    Ok(
        json!({"version":1,"operation":"STATUS","requestId":hex(&request),"deviceId":hex(&device),"poolId":pool.map(|v|hex(&v)),"generationId":active.get("generation").cloned().unwrap_or(Json::Null),"revision":result.get("revision"),"result":result}),
    )
}
