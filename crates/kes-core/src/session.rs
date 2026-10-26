//! Challenge-bound identity, HPKE session establishment, and sequenced HMAC envelopes.

use core::fmt;

use crate::{
    MAX_POOLS,
    cbor::{self, Encoder, Map},
    types::{CredentialEpoch, DeviceId, IncarnationId, PoolId, RequestId},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
    aead::{AeadTag, ChaCha20Poly1305},
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
    setup_receiver, setup_sender,
};
use rand_chacha::rand_core::{CryptoRng, RngCore, TryCryptoRng};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

pub const MAX_SESSIONS: usize = MAX_POOLS + 1;
pub const INFO_TRANSCRIPT_BYTES: usize = cbor::MAX_ENCODED_BYTES + INFO_DOMAIN.len();

const INFO_DOMAIN: &[u8] = b"cardano-kes-forge/info/v1";
const SESSION_DOMAIN: &str = "cardano-kes-forge/session/v1";
const REQUEST_EXPORT_LABEL: &[u8] = b"cardano-kes-forge/request/v1";
const RESPONSE_EXPORT_LABEL: &[u8] = b"cardano-kes-forge/response/v1";
const REQUEST_FRAME_DOMAIN: &[u8] = b"cardano-kes-forge/request-frame/v1";
const RESPONSE_FRAME_DOMAIN: &[u8] = b"cardano-kes-forge/response-frame/v1";
const OPEN_ACK_DOMAIN: &[u8] = b"cardano-kes-forge/open-ack/v1";
const HPKE_CIPHERTEXT_BYTES: usize = 48;
const TRANSCRIPT_BYTES: usize = 320;

type Kem = X25519HkdfSha256;
type Kdf = HkdfSha256;
type Aead = ChaCha20Poly1305;
type HmacSha256 = Hmac<Sha256>;
type HpkePrivateKey = <Kem as KemTrait>::PrivateKey;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionError {
    Cbor(cbor::Error),
    InvalidStructure,
    WrongDevice,
    WrongScope,
    WrongSession,
    ChallengeMismatch,
    CredentialChanged,
    Revoked,
    Authentication,
    Hpke,
    Sequence,
    CounterOverflow,
    Capacity,
    Entropy,
    BufferTooSmall,
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Cbor(error) => return fmt::Display::fmt(error, f),
            Self::InvalidStructure => "session structure is invalid",
            Self::WrongDevice => "session device identity mismatch",
            Self::WrongScope => "session scope mismatch",
            Self::WrongSession => "session identifier mismatch",
            Self::ChallengeMismatch => "session challenge mismatch",
            Self::CredentialChanged => "session credential epoch changed",
            Self::Revoked => "session credential is revoked",
            Self::Authentication => "session authentication failed",
            Self::Hpke => "HPKE session establishment failed",
            Self::Sequence => "session sequence is replayed, skipped, or exhausted",
            Self::CounterOverflow => "session open counter overflow",
            Self::Capacity => "session capacity exhausted",
            Self::Entropy => "session entropy unavailable",
            Self::BufferTooSmall => "session transcript buffer is too small",
        })
    }
}
impl core::error::Error for SessionError {}
impl From<cbor::Error> for SessionError {
    fn from(error: cbor::Error) -> Self {
        Self::Cbor(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scope {
    Management,
    Pool {
        pool: PoolId,
        incarnation: IncarnationId,
    },
}

/// Create the public per-boot anti-replay nonce from an already health-checked
/// and freshly seeded cryptographic RNG.
pub fn fresh_boot_nonce<R: CryptoRng + RngCore>(rng: &mut R) -> [u8; 32] {
    let mut nonce = [0; 32];
    rng.fill_bytes(&mut nonce);
    nonce
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenContext {
    pub device: DeviceId,
    pub boot_nonce: [u8; 32],
    pub scope: Scope,
    pub credential_epoch: CredentialEpoch,
    pub open_counter: u64,
    pub request: RequestId,
}
impl OpenContext {
    pub const fn new(
        device: DeviceId,
        boot_nonce: [u8; 32],
        scope: Scope,
        credential_epoch: CredentialEpoch,
        open_counter: u64,
        request: RequestId,
    ) -> Self {
        Self {
            device,
            boot_nonce,
            scope,
            credential_epoch,
            open_counter,
            request,
        }
    }
}

pub struct DeviceIdentityKey(SigningKey);
impl DeviceIdentityKey {
    pub fn from_seed(seed: Zeroizing<[u8; 32]>) -> Self {
        Self(SigningKey::from_bytes(&seed))
    }
    pub fn verification_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    pub fn sign_info(
        &self,
        response: Map<'_>,
        expected_device: DeviceId,
        expected_request: RequestId,
        expected_challenge: &[u8; 32],
        scratch: &mut [u8],
    ) -> Result<[u8; 64], SessionError> {
        validate_info(
            response,
            expected_device,
            expected_request,
            expected_challenge,
            &self.verification_key(),
        )?;
        let length = info_transcript(response, scratch)?;
        Ok(self.0.sign(&scratch[..length]).to_bytes())
    }
}

pub struct DeviceHpkeKey {
    private: HpkePrivateKey,
    public: [u8; 32],
}
impl DeviceHpkeKey {
    pub fn from_seed(seed: Zeroizing<[u8; 32]>) -> Self {
        let (private, public) = Kem::derive_keypair(&*seed);
        let mut public_bytes = [0; 32];
        public.write_exact(&mut public_bytes);
        Self {
            private,
            public: public_bytes,
        }
    }
    pub const fn public_key(&self) -> [u8; 32] {
        self.public
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InfoView {
    pub boot_nonce: [u8; 32],
    pub hpke_public_key: [u8; 32],
}

pub fn verify_info(
    response: Map<'_>,
    expected_device: DeviceId,
    expected_request: RequestId,
    expected_challenge: &[u8; 32],
    pinned_identity_key: &[u8; 32],
    scratch: &mut [u8],
) -> Result<InfoView, SessionError> {
    let view = validate_info(
        response,
        expected_device,
        expected_request,
        expected_challenge,
        pinned_identity_key,
    )?;
    let signature: &[u8; 64] = response
        .required("signature")?
        .bytes()?
        .try_into()
        .map_err(|_| SessionError::InvalidStructure)?;
    let key =
        VerifyingKey::from_bytes(pinned_identity_key).map_err(|_| SessionError::Authentication)?;
    let length = info_transcript(response, scratch)?;
    key.verify_strict(&scratch[..length], &Signature::from_bytes(signature))
        .map_err(|_| SessionError::Authentication)?;
    Ok(view)
}

fn validate_info(
    response: Map<'_>,
    expected_device: DeviceId,
    expected_request: RequestId,
    expected_challenge: &[u8; 32],
    expected_identity_key: &[u8; 32],
) -> Result<InfoView, SessionError> {
    if response.required("version")?.uint()? != 1
        || response.required("op")?.text()? != "INFO"
        || response.required("status")?.text()? != "OK"
    {
        return Err(SessionError::InvalidStructure);
    }
    require_bytes(response, "device", expected_device.as_bytes())
        .map_err(|_| SessionError::WrongDevice)?;
    require_bytes(response, "request", expected_request.as_bytes())?;
    let payload = response.required("payload")?.map()?;
    require_bytes(payload, "challenge", expected_challenge)
        .map_err(|_| SessionError::ChallengeMismatch)?;
    require_bytes(payload, "identity_public_key", expected_identity_key)
        .map_err(|_| SessionError::Authentication)?;
    let boot_nonce = array(payload, "boot_nonce")?;
    let hpke_public_key = array(payload, "hpke_public_key")?;
    let _: &[u8; 64] = response
        .required("signature")?
        .bytes()?
        .try_into()
        .map_err(|_| SessionError::InvalidStructure)?;
    Ok(InfoView {
        boot_nonce,
        hpke_public_key,
    })
}

fn info_transcript(response: Map<'_>, scratch: &mut [u8]) -> Result<usize, SessionError> {
    let required = INFO_DOMAIN
        .len()
        .checked_add(response.encoded().len())
        .ok_or(SessionError::BufferTooSmall)?;
    if scratch.len() < required || scratch.len() < INFO_DOMAIN.len() + 1 {
        return Err(SessionError::BufferTooSmall);
    }
    scratch[..INFO_DOMAIN.len()].copy_from_slice(INFO_DOMAIN);
    let mut position = INFO_DOMAIN.len();
    cbor::visit_without(response, "signature", |chunk| {
        let end = position + chunk.len();
        if end <= scratch.len() {
            scratch[position..end].copy_from_slice(chunk);
        }
        position = end;
    })?;
    if position > scratch.len() {
        return Err(SessionError::BufferTooSmall);
    }
    Ok(position)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenRequest {
    pub context: OpenContext,
    pub encapsulation: [u8; 32],
    pub ciphertext: [u8; HPKE_CIPHERTEXT_BYTES],
    pub signature: [u8; 64],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenResponse {
    pub session_id: [u8; 16],
    pub challenge_acknowledgement: [u8; 32],
    pub mac: [u8; 32],
}

struct SessionKeys {
    request: Zeroizing<[u8; 32]>,
    response: Zeroizing<[u8; 32]>,
}

pub struct PendingHostOpen {
    context: OpenContext,
    challenge: Zeroizing<[u8; 32]>,
    keys: SessionKeys,
}

pub fn begin_open<R: CryptoRng + RngCore>(
    context: OpenContext,
    device_hpke_public_key: &[u8; 32],
    machine_signing_key: &SigningKey,
    rng: &mut R,
) -> Result<(OpenRequest, PendingHostOpen), SessionError> {
    let public = <Kem as KemTrait>::PublicKey::from_bytes(device_hpke_public_key)
        .map_err(|_| SessionError::Hpke)?;
    let mut transcript = [0; TRANSCRIPT_BYTES];
    let transcript_length = encode_context(&context, &mut transcript)?;
    let (encapsulation, mut sender) = setup_sender::<Aead, Kdf, Kem, _>(
        &OpModeS::Base,
        &public,
        &transcript[..transcript_length],
        rng,
    )
    .map_err(|_| SessionError::Hpke)?;
    let mut challenge = Zeroizing::new([0; 32]);
    rng.fill_bytes(&mut *challenge);
    let mut ciphertext = [0; HPKE_CIPHERTEXT_BYTES];
    ciphertext[..32].copy_from_slice(&*challenge);
    let tag = sender
        .seal_in_place_detached(&mut ciphertext[..32], &transcript[..transcript_length])
        .map_err(|_| SessionError::Hpke)?;
    tag.write_exact(&mut ciphertext[32..]);
    let keys = export_keys_sender(&sender)?;
    let mut encapsulation_bytes = [0; 32];
    encapsulation.write_exact(&mut encapsulation_bytes);
    let signature_length =
        encode_open_signature(&context, &encapsulation_bytes, &ciphertext, &mut transcript)?;
    let signature = machine_signing_key
        .sign(&transcript[..signature_length])
        .to_bytes();
    Ok((
        OpenRequest {
            context,
            encapsulation: encapsulation_bytes,
            ciphertext,
            signature,
        },
        PendingHostOpen {
            context,
            challenge,
            keys,
        },
    ))
}

pub struct AcceptedOpen {
    context: OpenContext,
    response: OpenResponse,
    session: DeviceSession,
}

pub fn accept_open<R: TryCryptoRng + ?Sized>(
    expected: OpenContext,
    request: &OpenRequest,
    device_hpke_key: &DeviceHpkeKey,
    machine_verification_key: &[u8; 32],
    rng: &mut R,
) -> Result<AcceptedOpen, SessionError> {
    if request.context != expected {
        return Err(SessionError::InvalidStructure);
    }
    let verifier = VerifyingKey::from_bytes(machine_verification_key)
        .map_err(|_| SessionError::Authentication)?;
    let mut transcript = [0; TRANSCRIPT_BYTES];
    let signature_length = encode_open_signature(
        &expected,
        &request.encapsulation,
        &request.ciphertext,
        &mut transcript,
    )?;
    verifier
        .verify_strict(
            &transcript[..signature_length],
            &Signature::from_bytes(&request.signature),
        )
        .map_err(|_| SessionError::Authentication)?;

    let info_length = encode_context(&expected, &mut transcript)?;
    let encapsulation = <Kem as KemTrait>::EncappedKey::from_bytes(&request.encapsulation)
        .map_err(|_| SessionError::Hpke)?;
    let mut receiver = setup_receiver::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &device_hpke_key.private,
        &encapsulation,
        &transcript[..info_length],
    )
    .map_err(|_| SessionError::Hpke)?;
    let mut challenge = Zeroizing::new([0; 32]);
    challenge.copy_from_slice(&request.ciphertext[..32]);
    let tag =
        AeadTag::<Aead>::from_bytes(&request.ciphertext[32..]).map_err(|_| SessionError::Hpke)?;
    receiver
        .open_in_place_detached(&mut *challenge, &transcript[..info_length], &tag)
        .map_err(|_| SessionError::Authentication)?;
    let keys = export_keys_receiver(&receiver)?;
    let mut session_id = [0; 16];
    rng.try_fill_bytes(&mut session_id)
        .map_err(|_| SessionError::Entropy)?;
    let acknowledgement = open_ack(
        &keys.response,
        &transcript[..info_length],
        &challenge,
        &session_id,
    )?;
    let response = OpenResponse {
        session_id,
        challenge_acknowledgement: acknowledgement,
        mac: [0; 32],
    };
    let session = DeviceSession::new(expected, session_id, keys);
    Ok(AcceptedOpen {
        context: expected,
        response,
        session,
    })
}

impl AcceptedOpen {
    pub const fn response_fields(&self) -> OpenResponse {
        self.response
    }

    pub fn commit(
        self,
        current_open_counter: &mut u64,
        sessions: &mut SessionTable,
        response: Map<'_>,
    ) -> Result<OpenResponse, SessionError> {
        if *current_open_counter != self.context.open_counter {
            return Err(SessionError::Sequence);
        }
        let next = current_open_counter
            .checked_add(1)
            .ok_or(SessionError::CounterOverflow)?;
        let supplied = open_response_from_map(self.context, response)?;
        if supplied.session_id != self.response.session_id
            || supplied.challenge_acknowledgement != self.response.challenge_acknowledgement
        {
            return Err(SessionError::InvalidStructure);
        }
        let mut authenticated = self.response;
        authenticated.mac = calculate_map_mac(
            &self.session.0.keys.response,
            RESPONSE_FRAME_DOMAIN,
            response,
        )?;
        sessions.prepare_replace(self.context.scope)?;
        *current_open_counter = next;
        sessions.replace_prepared(self.session);
        Ok(authenticated)
    }
}

impl PendingHostOpen {
    pub fn complete(self, response: Map<'_>) -> Result<HostSession, SessionError> {
        let supplied = open_response_from_map(self.context, response)?;
        let mut transcript = [0; TRANSCRIPT_BYTES];
        let length = encode_context(&self.context, &mut transcript)?;
        verify_keyed_chunks(
            &self.keys.response,
            &[
                OPEN_ACK_DOMAIN,
                &transcript[..length],
                &*self.challenge,
                &supplied.session_id,
            ],
            &supplied.challenge_acknowledgement,
        )?;
        verify_map_mac(&self.keys.response, RESPONSE_FRAME_DOMAIN, response)?;
        Ok(HostSession::new(
            self.context,
            supplied.session_id,
            self.keys,
        ))
    }
}

fn encode_context(context: &OpenContext, out: &mut [u8]) -> Result<usize, SessionError> {
    let mut encoder = Encoder::new(out);
    encoder.array(8)?;
    write_context_elements(context, &mut encoder)?;
    Ok(encoder.finish()?.encoded().len())
}

fn encode_open_signature(
    context: &OpenContext,
    encapsulation: &[u8; 32],
    ciphertext: &[u8; HPKE_CIPHERTEXT_BYTES],
    out: &mut [u8],
) -> Result<usize, SessionError> {
    let mut encoder = Encoder::new(out);
    encoder.array(10)?;
    write_context_elements(context, &mut encoder)?;
    encoder.bytes(encapsulation)?;
    encoder.bytes(ciphertext)?;
    Ok(encoder.finish()?.encoded().len())
}

fn write_context_elements(
    context: &OpenContext,
    encoder: &mut Encoder<'_>,
) -> Result<(), SessionError> {
    encoder.text(SESSION_DOMAIN)?;
    encoder.bytes(context.device.as_bytes())?;
    encoder.bytes(&context.boot_nonce)?;
    match context.scope {
        Scope::Management => {
            encoder.null()?;
            encoder.null()?;
        }
        Scope::Pool { pool, incarnation } => {
            encoder.bytes(pool.as_bytes())?;
            encoder.bytes(incarnation.as_bytes())?;
        }
    }
    encoder.uint(context.credential_epoch.get())?;
    encoder.uint(context.open_counter)?;
    encoder.bytes(context.request.as_bytes())?;
    Ok(())
}

fn export_keys_sender(
    context: &hpke::aead::AeadCtxS<Aead, Kdf, Kem>,
) -> Result<SessionKeys, SessionError> {
    let mut keys = SessionKeys {
        request: Zeroizing::new([0; 32]),
        response: Zeroizing::new([0; 32]),
    };
    context
        .export(REQUEST_EXPORT_LABEL, &mut *keys.request)
        .map_err(|_| SessionError::Hpke)?;
    context
        .export(RESPONSE_EXPORT_LABEL, &mut *keys.response)
        .map_err(|_| SessionError::Hpke)?;
    Ok(keys)
}
fn export_keys_receiver(
    context: &hpke::aead::AeadCtxR<Aead, Kdf, Kem>,
) -> Result<SessionKeys, SessionError> {
    let mut keys = SessionKeys {
        request: Zeroizing::new([0; 32]),
        response: Zeroizing::new([0; 32]),
    };
    context
        .export(REQUEST_EXPORT_LABEL, &mut *keys.request)
        .map_err(|_| SessionError::Hpke)?;
    context
        .export(RESPONSE_EXPORT_LABEL, &mut *keys.response)
        .map_err(|_| SessionError::Hpke)?;
    Ok(keys)
}

fn open_ack(
    key: &[u8; 32],
    transcript: &[u8],
    challenge: &[u8; 32],
    session_id: &[u8; 16],
) -> Result<[u8; 32], SessionError> {
    keyed_chunks(key, &[OPEN_ACK_DOMAIN, transcript, challenge, session_id])
}
fn keyed_chunks(key: &[u8; 32], chunks: &[&[u8]]) -> Result<[u8; 32], SessionError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| SessionError::Authentication)?;
    for chunk in chunks {
        mac.update(chunk);
    }
    Ok(mac.finalize().into_bytes().into())
}
fn verify_keyed_chunks(
    key: &[u8; 32],
    chunks: &[&[u8]],
    supplied: &[u8],
) -> Result<(), SessionError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| SessionError::Authentication)?;
    for chunk in chunks {
        mac.update(chunk);
    }
    mac.verify_slice(supplied)
        .map_err(|_| SessionError::Authentication)
}

#[derive(Clone, Copy, Debug)]
pub struct AuthenticatedRequest<'a> {
    pub scope: Scope,
    pub operation: &'a str,
    pub request: RequestId,
    pub sequence: u64,
}

struct SessionState {
    context: OpenContext,
    session_id: [u8; 16],
    keys: SessionKeys,
    request_sequence: u64,
    response_sequence: u64,
    valid: bool,
}
impl SessionState {
    fn new(context: OpenContext, session_id: [u8; 16], keys: SessionKeys) -> Self {
        Self {
            context,
            session_id,
            keys,
            request_sequence: 0,
            response_sequence: 0,
            valid: true,
        }
    }
    fn invalidate(&mut self) {
        self.keys.request.zeroize();
        self.keys.response.zeroize();
        self.valid = false;
    }
    fn check_common(&self, map: Map<'_>) -> Result<(), SessionError> {
        if !self.valid {
            return Err(SessionError::Authentication);
        }
        if map.required("version")?.uint()? != 1 {
            return Err(SessionError::InvalidStructure);
        }
        require_bytes(map, "device", self.context.device.as_bytes())
            .map_err(|_| SessionError::WrongDevice)?;
        let scope = scope_from_map(map)?;
        if scope != self.context.scope {
            return Err(SessionError::WrongScope);
        }
        require_bytes(map, "session", &self.session_id).map_err(|_| SessionError::WrongSession)
    }
}

pub struct DeviceSession(SessionState);
impl DeviceSession {
    fn new(context: OpenContext, session_id: [u8; 16], keys: SessionKeys) -> Self {
        Self(SessionState::new(context, session_id, keys))
    }
    pub const fn session_id(&self) -> &[u8; 16] {
        &self.0.session_id
    }
    pub const fn scope(&self) -> Scope {
        self.0.context.scope
    }
    pub const fn is_valid(&self) -> bool {
        self.0.valid
    }
    pub fn authenticate_request<'a>(
        &mut self,
        map: Map<'a>,
        current_epoch: CredentialEpoch,
        revoked: bool,
    ) -> Result<AuthenticatedRequest<'a>, SessionError> {
        let result = self.authenticate_request_inner(map, current_epoch, revoked);
        if result.is_err() {
            self.0.invalidate();
        }
        result
    }
    fn authenticate_request_inner<'a>(
        &mut self,
        map: Map<'a>,
        current_epoch: CredentialEpoch,
        revoked: bool,
    ) -> Result<AuthenticatedRequest<'a>, SessionError> {
        if revoked {
            return Err(SessionError::Revoked);
        }
        if current_epoch != self.0.context.credential_epoch {
            return Err(SessionError::CredentialChanged);
        }
        self.0.check_common(map)?;
        let sequence = map.required("seq")?.uint()?;
        if sequence != self.0.request_sequence || sequence == u64::MAX {
            return Err(SessionError::Sequence);
        }
        verify_map_mac(&self.0.keys.request, REQUEST_FRAME_DOMAIN, map)?;
        self.0.request_sequence = sequence + 1;
        Ok(AuthenticatedRequest {
            scope: self.0.context.scope,
            operation: map.required("op")?.text()?,
            request: RequestId::try_from(map.required("request")?.bytes()?)
                .map_err(|_| SessionError::InvalidStructure)?,
            sequence,
        })
    }
    pub fn response_mac(
        &mut self,
        map: Map<'_>,
        request: AuthenticatedRequest<'_>,
    ) -> Result<[u8; 32], SessionError> {
        let result = self.response_mac_inner(map, request);
        if result.is_err() {
            self.0.invalidate();
        }
        result
    }
    fn response_mac_inner(
        &mut self,
        map: Map<'_>,
        request: AuthenticatedRequest<'_>,
    ) -> Result<[u8; 32], SessionError> {
        self.0.check_common(map)?;
        validate_response_binding(map, request.request, request.operation, request.sequence)?;
        let sequence = map.required("seq")?.uint()?;
        if sequence != self.0.response_sequence || sequence == u64::MAX {
            return Err(SessionError::Sequence);
        }
        let mac = calculate_map_mac(&self.0.keys.response, RESPONSE_FRAME_DOMAIN, map)?;
        self.0.response_sequence = sequence + 1;
        Ok(mac)
    }
}

pub struct HostSession(SessionState);
impl HostSession {
    fn new(context: OpenContext, session_id: [u8; 16], keys: SessionKeys) -> Self {
        Self(SessionState::new(context, session_id, keys))
    }
    pub const fn session_id(&self) -> &[u8; 16] {
        &self.0.session_id
    }
    pub const fn is_valid(&self) -> bool {
        self.0.valid
    }
    pub fn request_mac(&mut self, map: Map<'_>) -> Result<[u8; 32], SessionError> {
        let result = self.request_mac_inner(map);
        if result.is_err() {
            self.0.invalidate();
        }
        result
    }
    fn request_mac_inner(&mut self, map: Map<'_>) -> Result<[u8; 32], SessionError> {
        self.0.check_common(map)?;
        let sequence = map.required("seq")?.uint()?;
        if sequence != self.0.request_sequence || sequence == u64::MAX {
            return Err(SessionError::Sequence);
        }
        let mac = calculate_map_mac(&self.0.keys.request, REQUEST_FRAME_DOMAIN, map)?;
        self.0.request_sequence = sequence + 1;
        Ok(mac)
    }
    pub fn authenticate_response(
        &mut self,
        map: Map<'_>,
        request: RequestId,
        operation: &str,
        request_sequence: u64,
    ) -> Result<(), SessionError> {
        let result = self.authenticate_response_inner(map, request, operation, request_sequence);
        if result.is_err() {
            self.0.invalidate();
        }
        result
    }
    fn authenticate_response_inner(
        &mut self,
        map: Map<'_>,
        request: RequestId,
        operation: &str,
        request_sequence: u64,
    ) -> Result<(), SessionError> {
        self.0.check_common(map)?;
        validate_response_binding(map, request, operation, request_sequence)?;
        let sequence = map.required("seq")?.uint()?;
        if sequence != self.0.response_sequence || sequence == u64::MAX {
            return Err(SessionError::Sequence);
        }
        verify_map_mac(&self.0.keys.response, RESPONSE_FRAME_DOMAIN, map)?;
        self.0.response_sequence = sequence + 1;
        Ok(())
    }
}

fn validate_response_binding(
    map: Map<'_>,
    request: RequestId,
    operation: &str,
    request_sequence: u64,
) -> Result<(), SessionError> {
    require_bytes(map, "request", request.as_bytes())?;
    if map.required("op")?.text()? != operation
        || map.required("request_seq")?.uint()? != request_sequence
    {
        return Err(SessionError::Authentication);
    }
    Ok(())
}

fn calculate_map_mac(
    key: &[u8; 32],
    domain: &[u8],
    map: Map<'_>,
) -> Result<[u8; 32], SessionError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| SessionError::Authentication)?;
    mac.update(domain);
    cbor::visit_without(map, "mac", |chunk| mac.update(chunk))?;
    Ok(mac.finalize().into_bytes().into())
}
fn verify_map_mac(key: &[u8; 32], domain: &[u8], map: Map<'_>) -> Result<(), SessionError> {
    let supplied = map.required("mac")?.bytes()?;
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| SessionError::Authentication)?;
    mac.update(domain);
    cbor::visit_without(map, "mac", |chunk| mac.update(chunk))?;
    mac.verify_slice(supplied)
        .map_err(|_| SessionError::Authentication)
}
fn open_response_from_map(
    context: OpenContext,
    map: Map<'_>,
) -> Result<OpenResponse, SessionError> {
    if map.required("version")?.uint()? != 1
        || map.required("op")?.text()? != "OPEN"
        || map.required("status")?.text()? != "OK"
    {
        return Err(SessionError::InvalidStructure);
    }
    require_bytes(map, "device", context.device.as_bytes())
        .map_err(|_| SessionError::WrongDevice)?;
    require_bytes(map, "request", context.request.as_bytes())?;
    if scope_from_map(map)? != context.scope {
        return Err(SessionError::WrongScope);
    }
    let payload = map.required("payload")?.map()?;
    Ok(OpenResponse {
        session_id: array(payload, "session")?,
        challenge_acknowledgement: array(payload, "challenge_acknowledgement")?,
        mac: array(map, "mac")?,
    })
}

pub struct SessionTable {
    sessions: [Option<DeviceSession>; MAX_SESSIONS],
    prepared: Option<Scope>,
}
impl SessionTable {
    pub fn new() -> Self {
        Self {
            sessions: core::array::from_fn(|_| None),
            prepared: None,
        }
    }
    fn prepare_replace(&mut self, scope: Scope) -> Result<(), SessionError> {
        let replacing = self.sessions.iter().any(|entry| {
            entry
                .as_ref()
                .is_some_and(|session| session.scope() == scope)
        });
        let pool_count = self
            .sessions
            .iter()
            .flatten()
            .filter(|session| matches!(session.scope(), Scope::Pool { .. }))
            .count();
        let within_scope_limit = replacing
            || match scope {
                Scope::Management => self.get(Scope::Management).is_none(),
                Scope::Pool { .. } => pool_count < MAX_POOLS,
            };
        if within_scope_limit && (replacing || self.sessions.iter().any(Option::is_none)) {
            self.prepared = Some(scope);
            Ok(())
        } else {
            Err(SessionError::Capacity)
        }
    }
    fn replace_prepared(&mut self, session: DeviceSession) {
        let scope = self.prepared.take();
        debug_assert_eq!(scope, Some(session.scope()));
        if let Some(entry) = self.sessions.iter_mut().find(|entry| {
            entry
                .as_ref()
                .is_some_and(|current| current.scope() == session.scope())
        }) {
            *entry = Some(session);
            return;
        }
        if let Some(entry) = self.sessions.iter_mut().find(|entry| entry.is_none()) {
            *entry = Some(session);
        }
    }
    pub fn get(&self, scope: Scope) -> Option<&DeviceSession> {
        self.sessions
            .iter()
            .flatten()
            .find(|session| session.scope() == scope)
    }
    pub fn get_mut(&mut self, scope: Scope) -> Option<&mut DeviceSession> {
        self.sessions
            .iter_mut()
            .flatten()
            .find(|session| session.scope() == scope)
    }
    pub fn invalidate_scope(&mut self, scope: Scope) {
        if let Some(entry) = self.sessions.iter_mut().find(|entry| {
            entry
                .as_ref()
                .is_some_and(|session| session.scope() == scope)
        }) {
            *entry = None;
        }
    }
    pub fn invalidate_all(&mut self) {
        for entry in &mut self.sessions {
            *entry = None;
        }
        self.prepared = None;
    }
}
impl Default for SessionTable {
    fn default() -> Self {
        Self::new()
    }
}

const _: () = assert!(core::mem::size_of::<DeviceSession>() <= 256);
const _: () = assert!(core::mem::size_of::<SessionTable>() <= 33 * 256);

fn scope_from_map(map: Map<'_>) -> Result<Scope, SessionError> {
    let pool = map.required("pool")?;
    let incarnation = map.required("incarnation")?;
    match (pool.is_null(), incarnation.is_null()) {
        (true, true) => Ok(Scope::Management),
        (false, false) => Ok(Scope::Pool {
            pool: PoolId::try_from(pool.bytes()?).map_err(|_| SessionError::InvalidStructure)?,
            incarnation: IncarnationId::try_from(incarnation.bytes()?)
                .map_err(|_| SessionError::InvalidStructure)?,
        }),
        _ => Err(SessionError::InvalidStructure),
    }
}
fn require_bytes(map: Map<'_>, key: &str, expected: &[u8]) -> Result<(), SessionError> {
    if map.required(key)?.bytes()? == expected {
        Ok(())
    } else {
        Err(SessionError::InvalidStructure)
    }
}
fn array<const N: usize>(map: Map<'_>, key: &str) -> Result<[u8; N], SessionError> {
    map.required(key)?
        .bytes()?
        .try_into()
        .map_err(|_| SessionError::InvalidStructure)
}
