//! Development-only pool OPEN routing over authenticated, recovered pool state.
//! No flash writes, credential defaults, management authority, or release claims.

use kes_core::{
    MAX_POOLS,
    cbor::{self, Encoder, Map},
    journal::Recovered,
    session::{
        AcceptedOpen, AuthenticatedRequest, DeviceHpkeKey, OpenContext, OpenRequest, OpenResponse,
        Scope, SessionError, SessionTable, accept_open,
    },
    state::{DirectoryEntry, PoolRegistration},
    types::{CredentialEpoch, DeviceId, HardwareSlot, IncarnationId, PoolId},
};
use rand_chacha::rand_core::TryCryptoRng;

/// Public authority extracted only after authenticated directory AND pool recovery.
/// The caller must recover the pool journal with the current device, matching
/// pool/incarnation and the directory's physical slot. Never use unverified wire
/// metadata as the directory entry, or retain this projection across mutations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoolAuthority {
    slot: HardwareSlot,
    pool: PoolId,
    incarnation: IncarnationId,
    public_key: [u8; 32],
    epoch: CredentialEpoch,
    revoked: bool,
}

impl PoolAuthority {
    pub fn from_recovered(
        entry: DirectoryEntry,
        recovered: &Recovered<PoolRegistration>,
    ) -> Result<Self, SessionError> {
        let state = &recovered.state;
        if entry.pool_id() != state.pool_id() || entry.incarnation() != state.incarnation() {
            return Err(SessionError::WrongScope);
        }
        if recovered.token.revision() != state.revision() {
            return Err(SessionError::InvalidStructure);
        }
        Ok(Self {
            slot: entry.slot(),
            pool: state.pool_id(),
            incarnation: state.incarnation(),
            public_key: *state.credential_public_key(),
            epoch: state.credential_epoch(),
            revoked: state.credential_revoked(),
        })
    }

    /// Check a freshly recovered pool against this session authority projection.
    /// This does not authenticate storage; the caller must recover it first.
    pub fn matches_pool(self, pool: &PoolRegistration) -> bool {
        self.pool == pool.pool_id()
            && self.incarnation == pool.incarnation()
            && self.public_key == *pool.credential_public_key()
            && self.epoch == pool.credential_epoch()
            && self.revoked == pool.credential_revoked()
    }
    pub const fn slot(self) -> HardwareSlot {
        self.slot
    }

    pub const fn scope(self) -> Scope {
        Scope::Pool {
            pool: self.pool,
            incarnation: self.incarnation,
        }
    }
}

/// Encode inside INFO's authenticated `open_counters` array, after the
/// management counter. No slot number or unauthenticated credential is exposed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoolOpenCounter {
    pub pool: PoolId,
    pub incarnation: IncarnationId,
    pub open_counter: u64,
}

impl PoolOpenCounter {
    pub fn encode(self, encoder: &mut Encoder<'_>) -> Result<(), cbor::Error> {
        encoder.map(3)?;
        encoder.text("pool")?;
        encoder.bytes(self.pool.as_bytes())?;
        encoder.text("incarnation")?;
        encoder.bytes(self.incarnation.as_bytes())?;
        encoder.text("open_counter")?;
        encoder.uint(self.open_counter)
    }
}

/// Only bounded public bindings and per-boot counters live here. All scopes
/// share the handler's existing 33-entry SessionTable; no second table exists.
pub struct PoolSessions {
    device: DeviceId,
    boot_nonce: [u8; 32],
    counters: [u64; MAX_POOLS],
    bindings: [Option<PoolAuthority>; MAX_POOLS],
}

impl PoolSessions {
    /// Recreate on reboot with the SAME fresh nonce advertised by signed INFO.
    pub const fn new(device: DeviceId, boot_nonce: [u8; 32]) -> Self {
        Self {
            device,
            boot_nonce,
            counters: [0; MAX_POOLS],
            bindings: [None; MAX_POOLS],
        }
    }

    fn synchronize(&mut self, authority: PoolAuthority, sessions: &mut SessionTable) {
        let index = authority.slot.get();
        if self.bindings[index] != Some(authority) {
            if let Some(previous) = self.bindings[index] {
                sessions.invalidate_scope(previous.scope());
            }
            // Also reject any session inserted through a different router.
            sessions.invalidate_scope(authority.scope());
            self.bindings[index] = Some(authority);
        }
    }

    pub fn info_counter(
        &mut self,
        authority: PoolAuthority,
        sessions: &mut SessionTable,
    ) -> PoolOpenCounter {
        self.synchronize(authority, sessions);
        PoolOpenCounter {
            pool: authority.pool,
            incarnation: authority.incarnation,
            open_counter: self.counters[authority.slot.get()],
        }
    }

    /// Invalidate removed/unrecoverable pool state without recycling its counter.
    pub fn invalidate_slot(&mut self, slot: HardwareSlot, sessions: &mut SessionTable) {
        if let Some(previous) = self.bindings[slot.get()].take() {
            sessions.invalidate_scope(previous.scope());
        }
    }

    /// USB reset/disconnect destroys pool secrets but NEVER resets counters.
    /// The parent separately invalidates management scope on the same event.
    pub fn disconnect(&mut self, sessions: &mut SessionTable) {
        for binding in self.bindings.iter().flatten() {
            sessions.invalidate_scope(binding.scope());
        }
    }

    pub fn prepare_open<'a, R: TryCryptoRng + ?Sized>(
        &'a mut self,
        authority: PoolAuthority,
        request: &OpenRequest,
        hpke: &DeviceHpkeKey,
        rng: &mut R,
        sessions: &'a mut SessionTable,
    ) -> Result<PendingPoolOpen<'a>, SessionError> {
        self.synchronize(authority, sessions);
        if authority.revoked {
            return Err(SessionError::Revoked);
        }
        if request.context.scope != authority.scope() {
            return Err(SessionError::WrongScope);
        }
        if request.context.credential_epoch != authority.epoch {
            return Err(SessionError::CredentialChanged);
        }
        let counter = &mut self.counters[authority.slot.get()];
        let context = OpenContext::new(
            self.device,
            self.boot_nonce,
            authority.scope(),
            authority.epoch,
            *counter,
            request.context.request,
        );
        let accepted = accept_open(context, request, hpke, &authority.public_key, rng)?;
        Ok(PendingPoolOpen {
            context,
            accepted,
            counter,
            sessions,
        })
    }

    /// Recover authority again before EACH pool operation, including generation.
    /// Successful MAC verification alone does not bypass the operation's policy.
    pub fn authenticate_request<'a>(
        &mut self,
        authority: PoolAuthority,
        request: Map<'a>,
        sessions: &mut SessionTable,
    ) -> Result<AuthenticatedRequest<'a>, SessionError> {
        self.synchronize(authority, sessions);
        if authority.revoked {
            return Err(SessionError::Revoked);
        }
        sessions
            .get_mut(authority.scope())
            .ok_or(SessionError::WrongSession)?
            .authenticate_request(request, authority.epoch, authority.revoked)
    }

    pub fn response_mac(
        &mut self,
        authority: PoolAuthority,
        response: Map<'_>,
        request: AuthenticatedRequest<'_>,
        sessions: &mut SessionTable,
    ) -> Result<[u8; 32], SessionError> {
        self.synchronize(authority, sessions);
        if authority.revoked {
            return Err(SessionError::Revoked);
        }
        if request.scope != authority.scope() {
            return Err(SessionError::WrongScope);
        }
        sessions
            .get_mut(authority.scope())
            .ok_or(SessionError::WrongSession)?
            .response_mac(response, request)
    }
}

/// Borrows the router and shared table until response commit, preventing a
/// disconnect, credential refresh, or competing OPEN between accept and commit.
/// Dropping before commit neither advances the counter nor installs a session.
pub struct PendingPoolOpen<'a> {
    context: OpenContext,
    accepted: AcceptedOpen,
    counter: &'a mut u64,
    sessions: &'a mut SessionTable,
}

impl PendingPoolOpen<'_> {
    pub const fn context(&self) -> OpenContext {
        self.context
    }
    pub fn response_fields(&self) -> OpenResponse {
        self.accepted.response_fields()
    }

    /// Supply the canonical unsigned OPEN response, then encode the returned MAC
    /// into the final response before transmitting. Existing core code validates
    /// its device/scope/request/epoch/session bindings before atomic installation.
    pub fn commit(self, unsigned_response: Map<'_>) -> Result<OpenResponse, SessionError> {
        self.accepted
            .commit(self.counter, self.sessions, unsigned_response)
    }
}

#[cfg(test)]
#[path = "pool_sessions_tests.rs"]
mod tests;
