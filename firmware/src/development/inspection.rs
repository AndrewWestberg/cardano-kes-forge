//! Deliberate current-state extraction for disposable development firmware only.
//! The development module registration MUST be feature-gated; no release router
//! may call this handler. Authentication and fresh journal recovery precede it.
#![cfg(all(
    any(feature = "development", feature = "a2-development"),
    not(feature = "release")
))]

use super::pool_sessions::PoolAuthority;
use crate::usb::CommandError;
use kes_core::{
    activation::DurablePool,
    cbor::{Encoder, Map},
    crypto::CanonicalState,
    session::AuthenticatedRequest,
    state::Lifecycle,
    types::{GenerationId, RequestId},
};
use kes_protocol::{Envelope, ErrorScope, Operation, Status};

/// Borrowing prevents the inspected secret outliving its recovered durable owner.
/// Intentionally not Debug/Clone/serde and never a backup artifact.
pub struct DevelopmentInspection<'a> {
    revision: u64,
    generation: GenerationId,
    certificate_digest: [u8; 32],
    state: CanonicalState<'a>,
}

impl DevelopmentInspection<'_> {
    /// Encode only inside the authenticated response's protected workspace.
    pub fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), kes_core::cbor::Error> {
        encoder.map(7)?;
        encoder.text("state")?;
        encoder.bytes(self.state.bytes())?;
        encoder.text("health")?;
        encoder.text("healthy")?;
        encoder.text("revision")?;
        encoder.uint(self.revision)?;
        encoder.text("lifecycle")?;
        encoder.text("active")?;
        encoder.text("generation")?;
        encoder.bytes(self.generation.as_bytes())?;
        encoder.text("relative_period")?;
        encoder.uint(self.state.relative_period().get().into())?;
        encoder.text("certificate_digest")?;
        encoder.bytes(&self.certificate_digest)
    }
}

pub fn inspect<'a>(
    request: Envelope<'_>,
    authenticated: AuthenticatedRequest<'_>,
    authority: PoolAuthority,
    owner: &'a DurablePool,
) -> Result<DevelopmentInspection<'a>, CommandError> {
    if request.operation != Operation::DevInspect {
        return Err(error(Status::UnsupportedOperation));
    }
    if !request
        .payload()
        .required("protected_output")
        .and_then(|v| v.boolean())
        .map_err(|_| error(Status::InvalidFrame))?
    {
        return Err(error(Status::SecurityNotReady));
    }
    if authenticated.scope != authority.scope()
        || authenticated.operation != Operation::DevInspect.as_str()
        || authenticated.request != RequestId::from_bytes(array(request.map(), "request")?)
    {
        return Err(error(Status::AuthFailed));
    }
    let pool = owner.state().map_err(|_| error(Status::StateDamaged))?;
    if !authority.matches_pool(pool)
        || pool.credential_revoked()
        || array::<28>(request.map(), "pool")? != *pool.pool_id().as_bytes()
        || array::<16>(request.map(), "incarnation")? != *pool.incarnation().as_bytes()
    {
        return Err(error(Status::WrongPool));
    }
    let generation = GenerationId::from_bytes(array(request.payload(), "generation")?);
    let current = pool
        .current()
        .filter(|g| g.id() == generation)
        .ok_or(error(Status::StaleGeneration))?;
    if current.lifecycle() != Lifecycle::Active || current.is_secret_erased() {
        return Err(error(Status::StaleGeneration));
    }
    let certificate = current
        .certificate()
        .ok_or(error(Status::CertificateInvalid))?;
    let key = current
        .secret()
        .key()
        .ok_or(error(Status::StaleGeneration))?;
    let state = key
        .canonical_state()
        .map_err(|_| error(Status::StateDamaged))?;
    if state.relative_period() != current.relative_period()
        || key
            .verification_key()
            .map_err(|_| error(Status::StateDamaged))?
            != *current.verification_key()
    {
        return Err(error(Status::StateDamaged));
    }
    Ok(DevelopmentInspection {
        revision: pool.revision().get(),
        generation,
        certificate_digest: *certificate.digest(),
        state,
    })
}

fn array<const N: usize>(map: Map<'_>, name: &str) -> Result<[u8; N], CommandError> {
    map.required(name)
        .and_then(|v| v.bytes())
        .map_err(|_| error(Status::InvalidFrame))?
        .try_into()
        .map_err(|_| error(Status::InvalidFrame))
}
const fn error(status: Status) -> CommandError {
    CommandError {
        scope: ErrorScope::Pool,
        status,
    }
}
