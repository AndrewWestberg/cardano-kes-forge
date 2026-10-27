//! Authenticated management operation reconciliation from caller-recovered journal evidence.

use super::*;

/// Evidence for the request ID in the OP_STATUS payload, recovered from the
/// authoritative management journal. Absence alone does not prove non-commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagementOperationStatus {
    Committed {
        management_sequence: u64,
        revision: u64,
    },
    Unknown,
}

impl<R: TryCryptoRng> DevelopmentHandler<R> {
    /// Authenticate against the recovered current management credential before
    /// returning journal evidence. The caller must recover `outcome` for exactly
    /// `request.payload().request`; this method never infers NOT_COMMITTED.
    pub fn handle_management_operation_status(
        &mut self,
        request: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
        lease: RequestLease,
        epoch: CredentialEpoch,
        revoked: bool,
        outcome: ManagementOperationStatus,
    ) -> Result<HandlerResult, CommandError> {
        if request.operation != Operation::OpStatus {
            return Err(CommandError {
                scope: ErrorScope::Device,
                status: Status::UnsupportedOperation,
            });
        }
        // Management reconciliation has no generation-number selector.
        if request
            .payload()
            .get("generation_number")
            .map_err(|_| invalid_frame())?
            .is_some()
        {
            return Err(invalid_frame());
        }
        let target = RequestId::from_bytes(array::<16>(request.payload(), "request")?);
        let request_session = array::<16>(request.map(), "session")?;
        let next_response_sequence = self.response_sequence.checked_add(1).ok_or(CommandError {
            scope: ErrorScope::Device,
            status: Status::Replay,
        })?;
        let session = self
            .sessions
            .get_mut(Scope::Management)
            .filter(|session| session.session_id() == &request_session)
            .ok_or(CommandError {
                scope: ErrorScope::Device,
                status: Status::AuthFailed,
            })?;
        let authenticated = session
            .authenticate_request(request.map(), epoch, revoked)
            .map_err(session_error)?;
        let unsigned_length = encode_operation_status_response(
            response,
            self.device,
            request_session,
            self.response_sequence,
            authenticated.sequence,
            authenticated.request,
            target,
            outcome,
            [0; 32],
        )?;
        let unsigned = Envelope::parse(&response[..unsigned_length], EnvelopeKind::DeviceResponse)
            .map_err(|_| unavailable())?;
        let mac = session
            .response_mac(unsigned.map(), authenticated)
            .map_err(session_error)?;
        let response_length = encode_operation_status_response(
            response,
            self.device,
            request_session,
            self.response_sequence,
            authenticated.sequence,
            authenticated.request,
            target,
            outcome,
            mac,
        )?;
        self.response_sequence = next_response_sequence;
        Ok(HandlerResult {
            response_length,
            completed_at_ms: self
                .completion_clock
                .map_or(lease.admitted_at_ms(), |clock| clock()),
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn encode_operation_status_response(
    output: &mut [u8],
    device: DeviceId,
    session: [u8; 16],
    sequence: u64,
    request_sequence: u64,
    request: RequestId,
    target: RequestId,
    outcome: ManagementOperationStatus,
    mac: [u8; 32],
) -> Result<usize, CommandError> {
    let encode = |encoder: &mut Encoder<'_>| -> Result<(), kes_core::cbor::Error> {
        encoder.map(12)?;
        encoder.text("op")?;
        encoder.text("OP_STATUS")?;
        encoder.text("mac")?;
        encoder.bytes(&mac)?;
        encoder.text("seq")?;
        encoder.uint(sequence)?;
        encoder.text("pool")?;
        encoder.null()?;
        encoder.text("device")?;
        encoder.bytes(device.as_bytes())?;
        encoder.text("status")?;
        encoder.text(match outcome {
            ManagementOperationStatus::Committed { .. } => "OK",
            ManagementOperationStatus::Unknown => "UNKNOWN",
        })?;
        encoder.text("payload")?;
        match outcome {
            ManagementOperationStatus::Committed {
                management_sequence,
                revision,
            } => {
                encoder.map(2)?;
                encoder.text("revision")?;
                encoder.uint(revision)?;
                encoder.text("management_sequence")?;
                encoder.uint(management_sequence)?;
            }
            ManagementOperationStatus::Unknown => {
                encoder.map(1)?;
                encoder.text("request")?;
                encoder.bytes(target.as_bytes())?;
            }
        }
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
    };
    let mut encoder = Encoder::new(output);
    encode(&mut encoder).map_err(|_| unavailable())?;
    finish(encoder)
}
