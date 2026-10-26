//! Authenticated, RAM-only development handler for reversible hardware testing.
//!
//! This handler deliberately supports only INFO, OPEN, and management STATUS.
//! It does not provision OTP, persist credentials, or claim release readiness.

use kes_core::{
    MAX_POOLS,
    cbor::Encoder,
    session::{
        DeviceHpkeKey, DeviceIdentityKey, INFO_TRANSCRIPT_BYTES, OpenContext, OpenRequest, Scope,
        SessionError, SessionTable, accept_open,
    },
    types::{CredentialEpoch, DeviceId, RequestId},
};
use kes_protocol::{
    Envelope, EnvelopeKind, ErrorScope, MAX_BACKUP_BYTES, MAX_CERTIFICATE_BYTES, MAX_FRAME_BYTES,
    MAX_MESSAGE_BYTES, MAX_SESSIONS, Operation, Status,
};
use rand_chacha::{ChaCha20Rng, rand_core::TryCryptoRng};

use crate::{
    scheduler::{RequestLease, Scheduler},
    usb::{CommandError, HandlerResult, SecureRequestHandler},
};

const DEVELOPMENT_REVISION: u64 = 0;
const DEVELOPMENT_EPOCH: CredentialEpoch = CredentialEpoch::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DevelopmentEvidence {
    pub firmware_digest: [u8; 32],
    pub hardware_policy_digest: [u8; 32],
    pub security_version: u64,
    pub capability_evidence: &'static [u8],
}

pub struct DevelopmentHandler<R: TryCryptoRng = ChaCha20Rng> {
    device: DeviceId,
    identity: DeviceIdentityKey,
    hpke: DeviceHpkeKey,
    boot_nonce: [u8; 32],
    machine_verification_key: [u8; 32],
    rng: R,
    evidence: DevelopmentEvidence,
    completion_clock: Option<fn() -> u64>,
    open_counter: u64,
    response_sequence: u64,
    sessions: SessionTable,
    info_scratch: [u8; INFO_TRANSCRIPT_BYTES],
}

impl<R: TryCryptoRng> DevelopmentHandler<R> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        device: DeviceId,
        identity: DeviceIdentityKey,
        hpke: DeviceHpkeKey,
        boot_nonce: [u8; 32],
        machine_verification_key: [u8; 32],
        rng: R,
        evidence: DevelopmentEvidence,
    ) -> Self {
        Self {
            device,
            identity,
            hpke,
            boot_nonce,
            machine_verification_key,
            rng,
            evidence,
            completion_clock: None,
            open_counter: 0,
            response_sequence: 0,
            sessions: SessionTable::new(),
            info_scratch: [0; INFO_TRANSCRIPT_BYTES],
        }
    }

    pub fn with_completion_clock(mut self, clock: fn() -> u64) -> Self {
        self.completion_clock = Some(clock);
        self
    }

    fn info(
        &mut self,
        request: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
    ) -> Result<usize, CommandError> {
        let request_id = request_id(request)?;
        let challenge = array::<32>(request.payload(), "challenge")?;
        let unsigned_length = encode_info_response(
            response,
            self.device,
            request_id,
            challenge,
            self.identity.verification_key(),
            self.hpke.public_key(),
            self.boot_nonce,
            self.open_counter,
            self.evidence,
            [0; 64],
        )?;
        let unsigned = Envelope::parse(&response[..unsigned_length], EnvelopeKind::InfoResponse)
            .map_err(|_| unavailable())?;
        let signature = self
            .identity
            .sign_info(
                unsigned.map(),
                self.device,
                request_id,
                &challenge,
                &mut self.info_scratch,
            )
            .map_err(session_error)?;
        encode_info_response(
            response,
            self.device,
            request_id,
            challenge,
            self.identity.verification_key(),
            self.hpke.public_key(),
            self.boot_nonce,
            self.open_counter,
            self.evidence,
            signature,
        )
    }

    fn open(
        &mut self,
        envelope: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
    ) -> Result<usize, CommandError> {
        let request = parse_open_request(envelope)?;
        if request.context.scope != Scope::Management {
            return Err(CommandError {
                scope: ErrorScope::Pool,
                status: Status::WrongPool,
            });
        }
        let expected = OpenContext::new(
            self.device,
            self.boot_nonce,
            Scope::Management,
            DEVELOPMENT_EPOCH,
            self.open_counter,
            request.context.request,
        );
        let accepted = accept_open(
            expected,
            &request,
            &self.hpke,
            &self.machine_verification_key,
            &mut self.rng,
        )
        .map_err(session_error)?;
        let fields = accepted.response_fields();
        let unsigned_length = encode_open_response(
            response,
            expected,
            fields.session_id,
            fields.challenge_acknowledgement,
            [0; 32],
        )?;
        let authenticated = {
            let unsigned =
                Envelope::parse(&response[..unsigned_length], EnvelopeKind::OpenResponse)
                    .map_err(|_| unavailable())?;
            accepted
                .commit(&mut self.open_counter, &mut self.sessions, unsigned.map())
                .map_err(session_error)?
        };
        self.response_sequence = 0;
        encode_open_response(
            response,
            expected,
            authenticated.session_id,
            authenticated.challenge_acknowledgement,
            authenticated.mac,
        )
    }

    fn status(
        &mut self,
        envelope: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
    ) -> Result<usize, CommandError> {
        let request_session = array::<16>(envelope.map(), "session")?;
        let session = self
            .sessions
            .get_mut(Scope::Management)
            .filter(|session| session.session_id() == &request_session)
            .ok_or(CommandError {
                scope: ErrorScope::Device,
                status: Status::AuthFailed,
            })?;
        let authenticated = session
            .authenticate_request(envelope.map(), DEVELOPMENT_EPOCH, false)
            .map_err(session_error)?;
        let unsigned_length = encode_status_response(
            response,
            self.device,
            request_session,
            self.response_sequence,
            authenticated.sequence,
            authenticated.request,
            [0; 32],
        )?;
        let mac = {
            let unsigned =
                Envelope::parse(&response[..unsigned_length], EnvelopeKind::DeviceResponse)
                    .map_err(|_| unavailable())?;
            session
                .response_mac(unsigned.map(), authenticated)
                .map_err(session_error)?
        };
        let length = encode_status_response(
            response,
            self.device,
            request_session,
            self.response_sequence,
            authenticated.sequence,
            authenticated.request,
            mac,
        )?;
        self.response_sequence = self.response_sequence.checked_add(1).ok_or(CommandError {
            scope: ErrorScope::Device,
            status: Status::Replay,
        })?;
        Ok(length)
    }
}

impl<R: TryCryptoRng> SecureRequestHandler for DevelopmentHandler<R> {
    fn handle(
        &mut self,
        request: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
        lease: RequestLease,
        _scheduler: &mut Scheduler,
    ) -> Result<HandlerResult, CommandError> {
        let response_length = match request.operation {
            Operation::Info => self.info(request, response)?,
            Operation::Open => self.open(request, response)?,
            Operation::Status => self.status(request, response)?,
            _ => {
                return Err(CommandError {
                    scope: ErrorScope::Device,
                    status: Status::UnsupportedOperation,
                });
            }
        };
        let completed_at_ms = self
            .completion_clock
            .map_or(lease.admitted_at_ms(), |clock| clock());
        Ok(HandlerResult {
            response_length,
            completed_at_ms,
        })
    }
}

fn parse_open_request(envelope: Envelope<'_>) -> Result<OpenRequest, CommandError> {
    let map = envelope.map();
    let pool = map.required("pool").map_err(|_| invalid_frame())?;
    let incarnation = map.required("incarnation").map_err(|_| invalid_frame())?;
    if !pool.is_null() || !incarnation.is_null() {
        return Err(CommandError {
            scope: ErrorScope::Pool,
            status: Status::WrongPool,
        });
    }
    let payload = envelope.payload();
    let context = OpenContext::new(
        DeviceId::try_from(bytes(map, "device")?).map_err(|_| invalid_frame())?,
        array(payload, "boot_nonce")?,
        Scope::Management,
        CredentialEpoch::new(uint(payload, "credential_epoch")?),
        uint(payload, "open_counter")?,
        request_id(envelope)?,
    );
    Ok(OpenRequest {
        context,
        encapsulation: array(payload, "encapsulation")?,
        ciphertext: array(payload, "ciphertext")?,
        signature: array(payload, "signature")?,
    })
}

fn request_id(envelope: Envelope<'_>) -> Result<RequestId, CommandError> {
    RequestId::try_from(bytes(envelope.map(), "request")?).map_err(|_| invalid_frame())
}

fn bytes<'a>(map: kes_core::cbor::Map<'a>, key: &str) -> Result<&'a [u8], CommandError> {
    map.required(key)
        .and_then(|value| value.bytes())
        .map_err(|_| invalid_frame())
}

fn array<const N: usize>(map: kes_core::cbor::Map<'_>, key: &str) -> Result<[u8; N], CommandError> {
    bytes(map, key)?.try_into().map_err(|_| invalid_frame())
}

fn uint(map: kes_core::cbor::Map<'_>, key: &str) -> Result<u64, CommandError> {
    map.required(key)
        .and_then(|value| value.uint())
        .map_err(|_| invalid_frame())
}

#[allow(clippy::too_many_arguments)]
fn encode_info_response(
    output: &mut [u8],
    device: DeviceId,
    request: RequestId,
    challenge: [u8; 32],
    identity_public_key: [u8; 32],
    hpke_public_key: [u8; 32],
    boot_nonce: [u8; 32],
    open_counter: u64,
    evidence: DevelopmentEvidence,
    signature: [u8; 64],
) -> Result<usize, CommandError> {
    let mut encoder = Encoder::new(output);
    encoder.map(7).map_err(|_| unavailable())?;
    encoder.text("op").map_err(|_| unavailable())?;
    encoder.text("INFO").map_err(|_| unavailable())?;
    encoder.text("device").map_err(|_| unavailable())?;
    encoder
        .bytes(device.as_bytes())
        .map_err(|_| unavailable())?;
    encoder.text("status").map_err(|_| unavailable())?;
    encoder.text("OK").map_err(|_| unavailable())?;
    encoder.text("payload").map_err(|_| unavailable())?;
    encoder.map(11).map_err(|_| unavailable())?;
    encoder.text("limits").map_err(|_| unavailable())?;
    encoder.map(6).map_err(|_| unavailable())?;
    encoder.text("pools").map_err(|_| unavailable())?;
    encoder.uint(MAX_POOLS as u64).map_err(|_| unavailable())?;
    encoder.text("sessions").map_err(|_| unavailable())?;
    encoder
        .uint(MAX_SESSIONS as u64)
        .map_err(|_| unavailable())?;
    encoder.text("frame_bytes").map_err(|_| unavailable())?;
    encoder
        .uint(MAX_FRAME_BYTES as u64)
        .map_err(|_| unavailable())?;
    encoder.text("backup_bytes").map_err(|_| unavailable())?;
    encoder
        .uint(MAX_BACKUP_BYTES as u64)
        .map_err(|_| unavailable())?;
    encoder.text("message_bytes").map_err(|_| unavailable())?;
    encoder
        .uint(MAX_MESSAGE_BYTES as u64)
        .map_err(|_| unavailable())?;
    encoder
        .text("certificate_bytes")
        .map_err(|_| unavailable())?;
    encoder
        .uint(MAX_CERTIFICATE_BYTES as u64)
        .map_err(|_| unavailable())?;
    encoder.text("challenge").map_err(|_| unavailable())?;
    encoder.bytes(&challenge).map_err(|_| unavailable())?;
    encoder.text("boot_nonce").map_err(|_| unavailable())?;
    encoder.bytes(&boot_nonce).map_err(|_| unavailable())?;
    encoder.text("open_counters").map_err(|_| unavailable())?;
    encoder.array(1).map_err(|_| unavailable())?;
    encoder.map(3).map_err(|_| unavailable())?;
    encoder.text("pool").map_err(|_| unavailable())?;
    encoder.null().map_err(|_| unavailable())?;
    encoder.text("incarnation").map_err(|_| unavailable())?;
    encoder.null().map_err(|_| unavailable())?;
    encoder.text("open_counter").map_err(|_| unavailable())?;
    encoder.uint(open_counter).map_err(|_| unavailable())?;
    encoder.text("security_mode").map_err(|_| unavailable())?;
    encoder.text("development").map_err(|_| unavailable())?;
    encoder.text("firmware_digest").map_err(|_| unavailable())?;
    encoder
        .bytes(&evidence.firmware_digest)
        .map_err(|_| unavailable())?;
    encoder.text("hpke_public_key").map_err(|_| unavailable())?;
    encoder.bytes(&hpke_public_key).map_err(|_| unavailable())?;
    encoder
        .text("security_version")
        .map_err(|_| unavailable())?;
    encoder
        .uint(evidence.security_version)
        .map_err(|_| unavailable())?;
    encoder
        .text("capability_evidence")
        .map_err(|_| unavailable())?;
    encoder
        .bytes(evidence.capability_evidence)
        .map_err(|_| unavailable())?;
    encoder
        .text("identity_public_key")
        .map_err(|_| unavailable())?;
    encoder
        .bytes(&identity_public_key)
        .map_err(|_| unavailable())?;
    encoder
        .text("hardware_policy_digest")
        .map_err(|_| unavailable())?;
    encoder
        .bytes(&evidence.hardware_policy_digest)
        .map_err(|_| unavailable())?;
    encoder.text("request").map_err(|_| unavailable())?;
    encoder
        .bytes(request.as_bytes())
        .map_err(|_| unavailable())?;
    encoder.text("version").map_err(|_| unavailable())?;
    encoder.uint(1).map_err(|_| unavailable())?;
    encoder.text("signature").map_err(|_| unavailable())?;
    encoder.bytes(&signature).map_err(|_| unavailable())?;
    finish(encoder)
}

fn encode_open_response(
    output: &mut [u8],
    context: OpenContext,
    session: [u8; 16],
    challenge_acknowledgement: [u8; 32],
    mac: [u8; 32],
) -> Result<usize, CommandError> {
    let mut encoder = Encoder::new(output);
    encoder.map(9).map_err(|_| unavailable())?;
    encoder.text("op").map_err(|_| unavailable())?;
    encoder.text("OPEN").map_err(|_| unavailable())?;
    encoder.text("mac").map_err(|_| unavailable())?;
    encoder.bytes(&mac).map_err(|_| unavailable())?;
    encoder.text("pool").map_err(|_| unavailable())?;
    encoder.null().map_err(|_| unavailable())?;
    encoder.text("device").map_err(|_| unavailable())?;
    encoder
        .bytes(context.device.as_bytes())
        .map_err(|_| unavailable())?;
    encoder.text("status").map_err(|_| unavailable())?;
    encoder.text("OK").map_err(|_| unavailable())?;
    encoder.text("payload").map_err(|_| unavailable())?;
    encoder.map(2).map_err(|_| unavailable())?;
    encoder.text("session").map_err(|_| unavailable())?;
    encoder.bytes(&session).map_err(|_| unavailable())?;
    encoder
        .text("challenge_acknowledgement")
        .map_err(|_| unavailable())?;
    encoder
        .bytes(&challenge_acknowledgement)
        .map_err(|_| unavailable())?;
    encoder.text("request").map_err(|_| unavailable())?;
    encoder
        .bytes(context.request.as_bytes())
        .map_err(|_| unavailable())?;
    encoder.text("version").map_err(|_| unavailable())?;
    encoder.uint(1).map_err(|_| unavailable())?;
    encoder.text("incarnation").map_err(|_| unavailable())?;
    encoder.null().map_err(|_| unavailable())?;
    finish(encoder)
}

fn encode_status_response(
    output: &mut [u8],
    device: DeviceId,
    session: [u8; 16],
    sequence: u64,
    request_sequence: u64,
    request: RequestId,
    mac: [u8; 32],
) -> Result<usize, CommandError> {
    let mut encoder = Encoder::new(output);
    encoder.map(12).map_err(|_| unavailable())?;
    encoder.text("op").map_err(|_| unavailable())?;
    encoder.text("STATUS").map_err(|_| unavailable())?;
    encoder.text("mac").map_err(|_| unavailable())?;
    encoder.bytes(&mac).map_err(|_| unavailable())?;
    encoder.text("seq").map_err(|_| unavailable())?;
    encoder.uint(sequence).map_err(|_| unavailable())?;
    encoder.text("pool").map_err(|_| unavailable())?;
    encoder.null().map_err(|_| unavailable())?;
    encoder.text("device").map_err(|_| unavailable())?;
    encoder
        .bytes(device.as_bytes())
        .map_err(|_| unavailable())?;
    encoder.text("status").map_err(|_| unavailable())?;
    encoder.text("OK").map_err(|_| unavailable())?;
    encoder.text("payload").map_err(|_| unavailable())?;
    encoder.map(9).map_err(|_| unavailable())?;
    encoder.text("active").map_err(|_| unavailable())?;
    encoder.null().map_err(|_| unavailable())?;
    encoder.text("health").map_err(|_| unavailable())?;
    encoder.text("healthy").map_err(|_| unavailable())?;
    encoder.text("staged").map_err(|_| unavailable())?;
    encoder.null().map_err(|_| unavailable())?;
    encoder.text("revoked").map_err(|_| unavailable())?;
    encoder.boolean(false).map_err(|_| unavailable())?;
    encoder.text("revision").map_err(|_| unavailable())?;
    encoder
        .uint(DEVELOPMENT_REVISION)
        .map_err(|_| unavailable())?;
    encoder.text("directory").map_err(|_| unavailable())?;
    encoder.array(0).map_err(|_| unavailable())?;
    encoder.text("security_mode").map_err(|_| unavailable())?;
    encoder.text("development").map_err(|_| unavailable())?;
    encoder.text("blocking_reason").map_err(|_| unavailable())?;
    encoder
        .text("development firmware: persistent pool state is unavailable")
        .map_err(|_| unavailable())?;
    encoder
        .text("credential_epoch")
        .map_err(|_| unavailable())?;
    encoder
        .uint(DEVELOPMENT_EPOCH.get())
        .map_err(|_| unavailable())?;
    encoder.text("request").map_err(|_| unavailable())?;
    encoder
        .bytes(request.as_bytes())
        .map_err(|_| unavailable())?;
    encoder.text("session").map_err(|_| unavailable())?;
    encoder.bytes(&session).map_err(|_| unavailable())?;
    encoder.text("version").map_err(|_| unavailable())?;
    encoder.uint(1).map_err(|_| unavailable())?;
    encoder.text("incarnation").map_err(|_| unavailable())?;
    encoder.null().map_err(|_| unavailable())?;
    encoder.text("request_seq").map_err(|_| unavailable())?;
    encoder.uint(request_sequence).map_err(|_| unavailable())?;
    finish(encoder)
}

fn finish(encoder: Encoder<'_>) -> Result<usize, CommandError> {
    encoder
        .finish()
        .map(|encoded| encoded.encoded().len())
        .map_err(|_| unavailable())
}

fn session_error(error: SessionError) -> CommandError {
    let status = match error {
        SessionError::Sequence | SessionError::CounterOverflow => Status::Replay,
        SessionError::Capacity => Status::Capacity,
        SessionError::Entropy => Status::EntropyFailure,
        SessionError::Cbor(_) | SessionError::InvalidStructure | SessionError::BufferTooSmall => {
            Status::InvalidFrame
        }
        SessionError::WrongDevice => Status::WrongDevice,
        SessionError::WrongScope => Status::WrongPool,
        SessionError::WrongSession
        | SessionError::ChallengeMismatch
        | SessionError::CredentialChanged
        | SessionError::Revoked
        | SessionError::Authentication
        | SessionError::Hpke => Status::AuthFailed,
    };
    CommandError {
        scope: ErrorScope::Device,
        status,
    }
}

const fn invalid_frame() -> CommandError {
    CommandError {
        scope: ErrorScope::Device,
        status: Status::InvalidFrame,
    }
}

const fn unavailable() -> CommandError {
    CommandError {
        scope: ErrorScope::Device,
        status: Status::DeviceUnavailable,
    }
}
