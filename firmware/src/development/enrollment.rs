//! Borrowed, durable ENROLL dispatch for disposable development hardware.
//!
//! The caller owns fitted-flash checks, the flash programming scope, explicit
//! directory provisioning, storage-root lifetime and workspace allocations.
//! No blank/corrupt journal is initialized here. Other management actions are
//! not implemented by this enrollment-specific handler.
use super::*;
use kes_core::{
    activation::OperationError,
    enrollment::{EnrollmentStorage, Error as EnrollmentError},
    journal::{Flash, Workspaces},
};

pub struct EnrollmentHandler<'a, 'key, 'work, R: TryCryptoRng, F: Flash> {
    handler: &'a mut DevelopmentHandler<R>,
    storage: &'a EnrollmentStorage<'key>,
    flash: &'a mut F,
    work: &'a mut Workspaces<'work>,
}

impl<'a, 'key, 'work, R: TryCryptoRng, F: Flash> EnrollmentHandler<'a, 'key, 'work, R, F> {
    pub(super) fn new(
        handler: &'a mut DevelopmentHandler<R>,
        storage: &'a EnrollmentStorage<'key>,
        flash: &'a mut F,
        work: &'a mut Workspaces<'work>,
    ) -> Self {
        Self {
            handler,
            storage,
            flash,
            work,
        }
    }

    fn manage(
        &mut self,
        envelope: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
        epoch: CredentialEpoch,
        revoked: bool,
    ) -> Result<usize, CommandError> {
        let request_session = array::<16>(envelope.map(), "session")?;
        let signed_request = array::<16>(envelope.payload(), "request")?;
        let session = self
            .handler
            .sessions
            .get_mut(Scope::Management)
            .filter(|session| session.session_id() == &request_session)
            .ok_or(CommandError {
                scope: ErrorScope::Device,
                status: Status::AuthFailed,
            })?;
        let authenticated = session
            .authenticate_request(envelope.map(), epoch, revoked)
            .map_err(session_error)?;
        if signed_request != *authenticated.request.as_bytes() {
            self.handler.sessions.invalidate_scope(Scope::Management);
            return Err(CommandError {
                scope: ErrorScope::Device,
                status: Status::AuthFailed,
            });
        }
        if envelope
            .payload()
            .required("action")
            .and_then(|value| value.text())
            .map_err(|_| invalid_frame())?
            != "ENROLL"
        {
            return Err(CommandError {
                scope: ErrorScope::Device,
                status: Status::UnsupportedOperation,
            });
        }
        let sequence = uint(envelope.payload(), "management_sequence")?;
        // EnrollmentStorage verifies the offline Ed25519 signature using the
        // authenticated directory root, binds the signed device/target/payload,
        // commits the directory intent and pool journal, and reconciles exact
        // replay. Only its cleanup-complete acknowledgement permits an OK MAC.
        let acknowledgement = self
            .storage
            .enroll(
                envelope.payload().encoded(),
                self.flash,
                &mut self.handler.rng,
                self.work,
            )
            .map_err(enrollment_error)?;
        let length = encode_acknowledgement(
            response,
            self.handler.device,
            request_session,
            self.handler.response_sequence,
            authenticated.sequence,
            authenticated.request,
            sequence,
            acknowledgement.pool_revision.get(),
            [0; 32],
        )?;
        let unsigned = Envelope::parse(&response[..length], EnvelopeKind::DeviceResponse)
            .map_err(|_| unavailable())?;
        let mac = session
            .response_mac(unsigned.map(), authenticated)
            .map_err(session_error)?;
        let length = encode_acknowledgement(
            response,
            self.handler.device,
            request_session,
            self.handler.response_sequence,
            authenticated.sequence,
            authenticated.request,
            sequence,
            acknowledgement.pool_revision.get(),
            mac,
        )?;
        self.handler.response_sequence =
            self.handler
                .response_sequence
                .checked_add(1)
                .ok_or(CommandError {
                    scope: ErrorScope::Device,
                    status: Status::Replay,
                })?;
        Ok(length)
    }
}

impl<R: TryCryptoRng, F: Flash> SecureRequestHandler for EnrollmentHandler<'_, '_, '_, R, F> {
    fn handle(
        &mut self,
        request: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
        lease: RequestLease,
        scheduler: &mut Scheduler,
    ) -> Result<HandlerResult, CommandError> {
        if !matches!(
            request.operation,
            Operation::Open | Operation::Status | Operation::Manage
        ) {
            return self.handler.handle(request, response, lease, scheduler);
        }
        // Recover, never initialize. Transport credentials are authenticated
        // storage authority, not a stale RAM copy supplied at startup.
        let directory = self
            .storage
            .recover_pending(self.flash, &mut self.handler.rng, self.work)
            .map_err(enrollment_error)?;
        if directory.state.config.identity.device_id() != &self.handler.device {
            return Err(CommandError {
                scope: ErrorScope::Device,
                status: Status::WrongDevice,
            });
        }
        let credential = directory.state.credential;
        let response_length = match request.operation {
            Operation::Open => {
                if credential.revoked {
                    return Err(CommandError {
                        scope: ErrorScope::Device,
                        status: Status::AuthFailed,
                    });
                }
                self.handler.open_with_credential(
                    request,
                    response,
                    credential.epoch,
                    credential.public_key,
                )?
            }
            // The storage-free handler reports an empty RAM directory. Never
            // expose that as persistent truth after a durable enrollment.
            Operation::Status => {
                return Err(CommandError {
                    scope: ErrorScope::Device,
                    status: Status::UnsupportedOperation,
                });
            }
            Operation::Manage => {
                self.manage(request, response, credential.epoch, credential.revoked)?
            }
            _ => unreachable!(),
        };
        Ok(HandlerResult {
            response_length,
            completed_at_ms: self
                .handler
                .completion_clock
                .map_or(lease.admitted_at_ms(), |clock| clock()),
        })
    }
}

impl<R: TryCryptoRng> DevelopmentHandler<R> {
    /// Authenticate the transport and bind its request ID to the signed handoff.
    pub fn authenticate_management_request<'a>(
        &mut self,
        request: Envelope<'a>,
        epoch: CredentialEpoch,
        revoked: bool,
    ) -> Result<kes_core::session::AuthenticatedRequest<'a>, CommandError> {
        if request.operation != Operation::Manage {
            return Err(invalid_frame());
        }
        let session_id = array::<16>(request.map(), "session")?;
        let signed_request = array::<16>(request.payload(), "request")?;
        let session = self
            .sessions
            .get_mut(Scope::Management)
            .filter(|session| session.session_id() == &session_id)
            .ok_or(CommandError {
                scope: ErrorScope::Device,
                status: Status::AuthFailed,
            })?;
        let authenticated = session
            .authenticate_request(request.map(), epoch, revoked)
            .map_err(session_error)?;
        if signed_request != *authenticated.request.as_bytes() {
            self.sessions.invalidate_scope(Scope::Management);
            return Err(CommandError {
                scope: ErrorScope::Device,
                status: Status::AuthFailed,
            });
        }
        Ok(authenticated)
    }

    /// MAC the committed result before invalidating a replaced/revoked session.
    #[allow(clippy::too_many_arguments)]
    pub fn respond_management_ack(
        &mut self,
        request: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
        lease: RequestLease,
        authenticated: kes_core::session::AuthenticatedRequest<'_>,
        management_sequence: u64,
        revision: u64,
        invalidate: bool,
    ) -> Result<HandlerResult, CommandError> {
        let result = (|| {
            let session_id = array::<16>(request.map(), "session")?;
            let session = self
                .sessions
                .get_mut(Scope::Management)
                .filter(|session| session.session_id() == &session_id)
                .ok_or(CommandError {
                    scope: ErrorScope::Device,
                    status: Status::AuthFailed,
                })?;
            let length = encode_acknowledgement(
                response,
                self.device,
                session_id,
                self.response_sequence,
                authenticated.sequence,
                authenticated.request,
                management_sequence,
                revision,
                [0; 32],
            )?;
            let unsigned = Envelope::parse(&response[..length], EnvelopeKind::DeviceResponse)
                .map_err(|_| unavailable())?;
            let mac = session
                .response_mac(unsigned.map(), authenticated)
                .map_err(session_error)?;
            let response_length = encode_acknowledgement(
                response,
                self.device,
                session_id,
                self.response_sequence,
                authenticated.sequence,
                authenticated.request,
                management_sequence,
                revision,
                mac,
            )?;
            self.response_sequence = self.response_sequence.checked_add(1).ok_or(CommandError {
                scope: ErrorScope::Device,
                status: Status::Replay,
            })?;
            Ok(HandlerResult {
                response_length,
                completed_at_ms: self
                    .completion_clock
                    .map_or(lease.admitted_at_ms(), |clock| clock()),
            })
        })();
        if invalidate {
            self.sessions.invalidate_scope(Scope::Management);
            self.response_sequence = 0;
        }
        result
    }
    /// Respond to an authenticated but rejected management operation.
    pub fn respond_management_error(
        &mut self,
        request: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
        lease: RequestLease,
        authenticated: kes_core::session::AuthenticatedRequest<'_>,
        error: CommandError,
    ) -> Result<HandlerResult, CommandError> {
        if matches!(
            error.status,
            Status::Ok
                | Status::InProgress
                | Status::NotCommitted
                | Status::Unknown
                | Status::ResultReclaimed
        ) {
            return Err(error);
        }
        let session_id = array::<16>(request.map(), "session")?;
        let session = self
            .sessions
            .get_mut(Scope::Management)
            .filter(|session| session.session_id() == &session_id)
            .ok_or(CommandError {
                scope: ErrorScope::Device,
                status: Status::AuthFailed,
            })?;
        let length = encode_failure(
            response,
            self.device,
            session_id,
            self.response_sequence,
            authenticated,
            error,
            [0; 32],
        )?;
        let unsigned = Envelope::parse(&response[..length], EnvelopeKind::DeviceResponse)
            .map_err(|_| unavailable())?;
        let mac = session
            .response_mac(unsigned.map(), authenticated)
            .map_err(session_error)?;
        let response_length = encode_failure(
            response,
            self.device,
            session_id,
            self.response_sequence,
            authenticated,
            error,
            mac,
        )?;
        self.response_sequence = self.response_sequence.checked_add(1).ok_or(CommandError {
            scope: ErrorScope::Device,
            status: Status::Replay,
        })?;
        Ok(HandlerResult {
            response_length,
            completed_at_ms: self
                .completion_clock
                .map_or(lease.admitted_at_ms(), |clock| clock()),
        })
    }
}

fn enrollment_error(error: EnrollmentError) -> CommandError {
    let status = match error {
        EnrollmentError::Journal(error) => {
            return CommandError::from_operation(
                ErrorScope::Device,
                OperationError::Journal(error),
            );
        }
        EnrollmentError::State(error) => {
            return CommandError::from_operation(ErrorScope::Device, OperationError::State(error));
        }
        EnrollmentError::Authorization => Status::AuthFailed,
        EnrollmentError::ChangedReplay => Status::Replay,
        EnrollmentError::PendingOperation => Status::Busy,
        EnrollmentError::SlotNotErased | EnrollmentError::InconsistentState => Status::StateDamaged,
    };
    CommandError {
        scope: ErrorScope::Device,
        status,
    }
}

fn encode_failure(
    output: &mut [u8],
    device: DeviceId,
    session: [u8; 16],
    sequence: u64,
    request: kes_core::session::AuthenticatedRequest<'_>,
    error: CommandError,
    mac: [u8; 32],
) -> Result<usize, CommandError> {
    let mut encoder = Encoder::new(output);
    (|| -> Result<(), kes_core::cbor::Error> {
        encoder.map(12)?;
        encoder.text("op")?;
        encoder.text("MANAGE")?;
        encoder.text("mac")?;
        encoder.bytes(&mac)?;
        encoder.text("seq")?;
        encoder.uint(sequence)?;
        encoder.text("pool")?;
        encoder.null()?;
        encoder.text("device")?;
        encoder.bytes(device.as_bytes())?;
        encoder.text("status")?;
        encoder.text(error.status.as_str())?;
        encoder.text("payload")?;
        encoder.map(2)?;
        encoder.text("scope")?;
        encoder.text(error.scope.as_str())?;
        encoder.text("diagnostic")?;
        encoder.text("operation rejected")?;
        encoder.text("request")?;
        encoder.bytes(request.request.as_bytes())?;
        encoder.text("session")?;
        encoder.bytes(&session)?;
        encoder.text("version")?;
        encoder.uint(1)?;
        encoder.text("incarnation")?;
        encoder.null()?;
        encoder.text("request_seq")?;
        encoder.uint(request.sequence)?;
        Ok(())
    })()
    .map_err(|_| unavailable())?;
    finish(encoder)
}

#[allow(clippy::too_many_arguments)]
fn encode_acknowledgement(
    output: &mut [u8],
    device: DeviceId,
    session: [u8; 16],
    sequence: u64,
    request_sequence: u64,
    request: RequestId,
    management_sequence: u64,
    revision: u64,
    mac: [u8; 32],
) -> Result<usize, CommandError> {
    let mut encoder = Encoder::new(output);
    let result = (|| -> Result<(), kes_core::cbor::Error> {
        encoder.map(12)?;
        encoder.text("op")?;
        encoder.text("MANAGE")?;
        encoder.text("mac")?;
        encoder.bytes(&mac)?;
        encoder.text("seq")?;
        encoder.uint(sequence)?;
        encoder.text("pool")?;
        encoder.null()?;
        encoder.text("device")?;
        encoder.bytes(device.as_bytes())?;
        encoder.text("status")?;
        encoder.text("OK")?;
        encoder.text("payload")?;
        encoder.map(2)?;
        encoder.text("revision")?;
        encoder.uint(revision)?;
        encoder.text("management_sequence")?;
        encoder.uint(management_sequence)?;
        encoder.text("request")?;
        encoder.bytes(request.as_bytes())?;
        encoder.text("session")?;
        encoder.bytes(&session)?;
        encoder.text("version")?;
        encoder.uint(1)?;
        encoder.text("incarnation")?;
        encoder.null()?;
        encoder.text("request_seq")?;
        encoder.uint(request_sequence)?;
        Ok(())
    })();
    result.map_err(|_| unavailable())?;
    finish(encoder)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acknowledgement_is_canonical_and_binds_public_result() {
        let mut output = [0; MAX_FRAME_BYTES];
        let device = DeviceId::from_bytes([1; 16]);
        let request = RequestId::from_bytes([2; 16]);
        let length =
            encode_acknowledgement(&mut output, device, [3; 16], 4, 5, request, 6, 7, [8; 32])
                .unwrap();
        let response = Envelope::parse(&output[..length], EnvelopeKind::DeviceResponse).unwrap();
        assert_eq!(response.operation, Operation::Manage);
        assert_eq!(uint(response.payload(), "management_sequence").unwrap(), 6);
        assert_eq!(uint(response.payload(), "revision").unwrap(), 7);
        assert_eq!(uint(response.map(), "seq").unwrap(), 4);
        assert_eq!(uint(response.map(), "request_seq").unwrap(), 5);
        assert_eq!(request_id(response).unwrap(), request);
        assert_eq!(array::<32>(response.map(), "mac").unwrap(), [8; 32]);
    }

    #[test]
    fn uncertain_storage_outcomes_never_map_to_success() {
        use kes_core::{journal::JournalError, state::StateError};
        let cases = [
            (EnrollmentError::Authorization, Status::AuthFailed),
            (EnrollmentError::ChangedReplay, Status::Replay),
            (EnrollmentError::PendingOperation, Status::Busy),
            (EnrollmentError::SlotNotErased, Status::StateDamaged),
            (EnrollmentError::InconsistentState, Status::StateDamaged),
            (
                EnrollmentError::Journal(JournalError::EntropyFailure),
                Status::EntropyFailure,
            ),
            (
                EnrollmentError::Journal(JournalError::Flash),
                Status::DeviceUnavailable,
            ),
            (
                EnrollmentError::State(StateError::RevisionConflict),
                Status::RevisionConflict,
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(enrollment_error(error).status, expected);
        }
    }
}
