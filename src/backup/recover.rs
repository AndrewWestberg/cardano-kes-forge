use crate::backup::{publication, recipient::RecipientKeyFile};
use crate::host::config::DeviceIdentity;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR,
    aead::{AeadTag, ChaCha20Poly1305},
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
    setup_receiver,
};
use kes_core::{
    SIGNING_STATE_BYTES,
    cbor::{Encoder, Map},
    crypto::{KesKey, SUM6_V1},
    types::{KesLifetime, RelativePeriod},
};
use kes_protocol::backup::BackupArtifact;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::{ffi::c_void, ops::Deref};
use zeroize::{Zeroize, Zeroizing};

type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;
type Kem = X25519HkdfSha256;

#[derive(Clone, Copy)]
pub struct Expectations {
    pub device: [u8; 16],
    pub pool: [u8; 28],
    pub incarnation: [u8; 16],
    pub generation: [u8; 16],
    pub verification_key: [u8; 32],
    pub identity_public_key: [u8; 32],
}

pub struct RecoveryFiles<'a> {
    pub artifact: &'a Path,
    pub recipient_key: &'a Path,
    pub device_identity: &'a Path,
    pub expected_device: [u8; 16],
    pub expected_pool: [u8; 28],
    pub expected_generation: [u8; 16],
    pub verification_key: &'a Path,
    pub output: &'a Path,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VerificationKeyEnvelope {
    #[serde(rename = "type")]
    kind: String,
    description: String,
    cbor_hex: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidArtifact,
    WrongBinding,
    InvalidSignature,
    WrongRecipient,
    WrongPassword,
    Decryption,
    InvalidState,
    MemoryProtection,
    Publication(publication::Error),
    InvalidInput,
}

struct LockedPrivateKey {
    bytes: Box<[u8; 32]>,
    pointer: *mut c_void,
}

impl LockedPrivateKey {
    fn new() -> Result<Self, Error> {
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
            .map_err(|_| Error::MemoryProtection)?;
        let mut bytes = Box::new([0; 32]);
        let pointer = bytes.as_mut_ptr().cast::<c_void>();
        unsafe {
            rustix::mm::mlock(pointer, bytes.len()).map_err(|_| Error::MemoryProtection)?;
        }
        Ok(Self { bytes, pointer })
    }
}

impl Drop for LockedPrivateKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
        unsafe {
            let _ = rustix::mm::munlock(self.pointer, self.bytes.len());
        }
    }
}

pub struct RecoveredState {
    state: Box<[u8; SIGNING_STATE_BYTES]>,
    pointer: *mut c_void,
}

impl RecoveredState {
    fn new() -> Result<Self, Error> {
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
            .map_err(|_| Error::MemoryProtection)?;
        let mut state = Box::new([0; SIGNING_STATE_BYTES]);
        let pointer = state.as_mut_ptr().cast::<c_void>();
        unsafe {
            rustix::mm::mlock(pointer, SIGNING_STATE_BYTES).map_err(|_| Error::MemoryProtection)?;
        }
        Ok(Self { state, pointer })
    }
}

impl Deref for RecoveredState {
    type Target = [u8; SIGNING_STATE_BYTES];

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl Drop for RecoveredState {
    fn drop(&mut self) {
        self.state.zeroize();
        unsafe {
            let _ = rustix::mm::munlock(self.pointer, SIGNING_STATE_BYTES);
        }
    }
}

pub fn recover(
    artifact_bytes: &[u8],
    recipient: &RecipientKeyFile,
    passphrase: &[u8],
    expected: Expectations,
) -> Result<RecoveredState, Error> {
    let artifact = BackupArtifact::parse(artifact_bytes).map_err(|_| Error::InvalidArtifact)?;
    let map = artifact.map();
    binding(map, "device", &expected.device)?;
    binding(map, "pool", &expected.pool)?;
    binding(map, "incarnation", &expected.incarnation)?;
    binding(map, "generation", &expected.generation)?;
    binding(map, "verification_key", &expected.verification_key)?;
    verify_signature(map, expected.identity_public_key)?;

    let public = recipient.public().map_err(|_| Error::WrongRecipient)?;
    binding(map, "recipient_public_key", &public.public_key).map_err(|_| Error::WrongRecipient)?;
    binding(map, "recipient_id", &public.recipient_id).map_err(|_| Error::WrongRecipient)?;
    let recipient_digest: [u8; 32] = Sha256::digest(public.public_key).into();
    if recipient_digest != public.recipient_id {
        return Err(Error::WrongRecipient);
    }
    let mut private = LockedPrivateKey::new()?;
    recipient
        .unlock_into(passphrase, &mut private.bytes)
        .map_err(|_| Error::WrongPassword)?;
    let private = <Kem as KemTrait>::PrivateKey::from_bytes(&private.bytes[..])
        .map_err(|_| Error::WrongRecipient)?;
    let encapsulation = map
        .required("encapsulation")
        .map_err(|_| Error::InvalidArtifact)?
        .bytes()
        .map_err(|_| Error::InvalidArtifact)?;
    let encapsulation = <Kem as KemTrait>::EncappedKey::from_bytes(encapsulation)
        .map_err(|_| Error::InvalidArtifact)?;
    let header = header(map)?;
    let mut info = Vec::with_capacity(34 + header.len());
    info.extend_from_slice(b"cardano-kes-forge/backup/v1");
    info.extend_from_slice(&header);
    let mut aad = Vec::with_capacity(8 + header.len());
    aad.extend_from_slice(b"KESBKP01");
    aad.extend_from_slice(&header);
    let mut receiver =
        setup_receiver::<Aead, Kdf, Kem>(&OpModeR::Base, &private, &encapsulation, &info)
            .map_err(|_| Error::Decryption)?;
    let ciphertext = map
        .required("ciphertext")
        .map_err(|_| Error::InvalidArtifact)?
        .bytes()
        .map_err(|_| Error::InvalidArtifact)?;
    let mut state = RecoveredState::new()?;
    state.state.copy_from_slice(
        ciphertext
            .get(..SIGNING_STATE_BYTES)
            .ok_or(Error::InvalidArtifact)?,
    );
    let tag = AeadTag::<Aead>::from_bytes(&ciphertext[SIGNING_STATE_BYTES..])
        .map_err(|_| Error::InvalidArtifact)?;
    receiver
        .open_in_place_detached(&mut state.state[..], &aad, &tag)
        .map_err(|_| Error::Decryption)?;
    let key = KesKey::from_canonical(
        SUM6_V1,
        &state.state[..],
        RelativePeriod::new(0).map_err(|_| Error::InvalidState)?,
        KesLifetime::new(64).map_err(|_| Error::InvalidState)?,
    )
    .map_err(|_| Error::InvalidState)?;
    if key.verification_key().map_err(|_| Error::InvalidState)? != expected.verification_key {
        return Err(Error::InvalidState);
    }
    Ok(state)
}

pub fn cardano_envelope(state: &[u8; SIGNING_STATE_BYTES]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut envelope = Zeroizing::new(Vec::with_capacity(1_360));
    envelope.extend_from_slice(
        br#"{"type":"KesSigningKey_ed25519_kes_2^6","description":"KES Signing Key","cborHex":"590260"#,
    );
    append_hex(&mut envelope, state);
    envelope.extend_from_slice(br#""}"#);
    Ok(envelope)
}

pub fn recover_to_file(
    artifact_bytes: &[u8],
    recipient: &RecipientKeyFile,
    passphrase: &[u8],
    expected: Expectations,
    output: &std::path::Path,
) -> Result<(), Error> {
    let state = recover(artifact_bytes, recipient, passphrase, expected)?;
    let mut envelope = cardano_envelope(&state)?;
    publication::publish_secret(output, &mut envelope).map_err(Error::Publication)
}

pub fn recover_files(files: RecoveryFiles<'_>, passphrase: &[u8]) -> Result<(), Error> {
    let artifact_bytes = read_bounded(files.artifact, false)?;
    let recipient_bytes = read_bounded(files.recipient_key, true)?;
    let recipient = RecipientKeyFile::parse(recipient_bytes).map_err(|_| Error::InvalidInput)?;
    let identity = DeviceIdentity::load(files.device_identity).map_err(|_| Error::InvalidInput)?;
    if identity.device_id != files.expected_device {
        return Err(Error::WrongBinding);
    }
    let verification_bytes = read_bounded(files.verification_key, false)?;
    let verification_key = decode_verification_key(&verification_bytes)?;
    let artifact = BackupArtifact::parse(&artifact_bytes).map_err(|_| Error::InvalidArtifact)?;
    let incarnation = artifact
        .map()
        .required("incarnation")
        .map_err(|_| Error::InvalidArtifact)?
        .bytes()
        .map_err(|_| Error::InvalidArtifact)?
        .try_into()
        .map_err(|_| Error::InvalidArtifact)?;
    recover_to_file(
        &artifact_bytes,
        &recipient,
        passphrase,
        Expectations {
            device: files.expected_device,
            pool: files.expected_pool,
            incarnation,
            generation: files.expected_generation,
            verification_key,
            identity_public_key: identity.identity_public_key,
        },
        files.output,
    )
}

fn decode_verification_key(bytes: &[u8]) -> Result<[u8; 32], Error> {
    let envelope: VerificationKeyEnvelope =
        serde_json::from_slice(bytes).map_err(|_| Error::InvalidInput)?;
    if envelope.kind != "KesVerificationKey_ed25519_kes_2^6"
        || envelope.description.is_empty()
        || envelope.cbor_hex.len() != 68
        || !envelope.cbor_hex.starts_with("5820")
    {
        return Err(Error::InvalidInput);
    }
    decode_hex(&envelope.cbor_hex[4..]).ok_or(Error::InvalidInput)
}

fn read_bounded(path: &Path, private: bool) -> Result<Vec<u8>, Error> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|_| Error::InvalidInput)?;
    let metadata = file.metadata().map_err(|_| Error::InvalidInput)?;
    let mode = metadata.permissions().mode() & 0o777;
    if !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || (private && mode != 0o600)
        || (!private && mode & 0o022 != 0)
    {
        return Err(Error::InvalidInput);
    }
    if private {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let metadata = std::fs::symlink_metadata(parent).map_err(|_| Error::InvalidInput)?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != rustix::process::getuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(Error::InvalidInput);
        }
    }
    if metadata.len() > 16_384 {
        return Err(Error::InvalidInput);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|_| Error::InvalidInput)?;
    Ok(bytes)
}

fn decode_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2 {
        return None;
    }
    let mut decoded = [0; N];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(decoded)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn verify_signature(map: Map<'_>, identity_public_key: [u8; 32]) -> Result<(), Error> {
    let signature: [u8; 64] = map
        .required("device_signature")
        .map_err(|_| Error::InvalidArtifact)?
        .bytes()
        .map_err(|_| Error::InvalidArtifact)?
        .try_into()
        .map_err(|_| Error::InvalidArtifact)?;
    let mut storage = [0; kes_protocol::MAX_BACKUP_BYTES];
    let mut encoder = Encoder::new(&mut storage);
    encoder.map(15).map_err(|_| Error::InvalidArtifact)?;
    for field in map {
        let (key, value) = field.map_err(|_| Error::InvalidArtifact)?;
        if key != "device_signature" {
            encoder.text(key).map_err(|_| Error::InvalidArtifact)?;
            encoder.value(value).map_err(|_| Error::InvalidArtifact)?;
        }
    }
    let unsigned = encoder.finish().map_err(|_| Error::InvalidArtifact)?;
    let mut message = Vec::with_capacity(48 + unsigned.encoded().len());
    message.extend_from_slice(b"cardano-kes-forge/backup-signature/v1");
    message.extend_from_slice(b"KESBKP01");
    message.extend_from_slice(unsigned.encoded());
    let key =
        VerifyingKey::from_bytes(&identity_public_key).map_err(|_| Error::InvalidSignature)?;
    key.verify(&message, &Signature::from_bytes(&signature))
        .map_err(|_| Error::InvalidSignature)
}

fn header(map: Map<'_>) -> Result<Vec<u8>, Error> {
    let mut storage = [0; 512];
    let mut encoder = Encoder::new(&mut storage);
    encoder.map(13).map_err(|_| Error::InvalidArtifact)?;
    for key in [
        "kdf",
        "kem",
        "aead",
        "pool",
        "device",
        "period",
        "version",
        "generation",
        "incarnation",
        "recipient_id",
        "verification_key",
        "generation_number",
        "recipient_public_key",
    ] {
        encoder.text(key).map_err(|_| Error::InvalidArtifact)?;
        encoder
            .value(map.required(key).map_err(|_| Error::InvalidArtifact)?)
            .map_err(|_| Error::InvalidArtifact)?;
    }
    encoder
        .finish()
        .map(|value| value.encoded().to_vec())
        .map_err(|_| Error::InvalidArtifact)
}

fn binding(map: Map<'_>, field: &str, expected: &[u8]) -> Result<(), Error> {
    let actual = map
        .required(field)
        .map_err(|_| Error::InvalidArtifact)?
        .bytes()
        .map_err(|_| Error::InvalidArtifact)?;
    if actual == expected {
        Ok(())
    } else {
        Err(Error::WrongBinding)
    }
}

fn append_hex(output: &mut Vec<u8>, bytes: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    output.reserve(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize]);
        output.push(DIGITS[(byte & 15) as usize]);
    }
}
