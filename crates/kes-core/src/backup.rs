use crate::cbor::Encoder;
use crate::crypto::{KesKey, SUM6_V1};
use crate::types::{DeviceId, GenerationId, GenerationNumber, IncarnationId, PoolId};
use crate::{SIGNING_STATE_BYTES, crypto::CryptoError};
use ed25519_dalek::{Signer, SigningKey};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeS, Serializable, aead::ChaCha20Poly1305,
    kdf::HkdfSha256, kem::X25519HkdfSha256, setup_sender,
};
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{SeedableRng, TryCryptoRng},
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const MAGIC: &[u8; 8] = b"KESBKP01";
pub const MAX_BACKUP_BYTES: usize = 2048;
pub const CIPHERTEXT_BYTES: usize = SIGNING_STATE_BYTES + 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Crypto(CryptoError),
    Entropy,
    InvalidRecipient,
    Hpke,
    Encoding,
}

impl From<CryptoError> for Error {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

#[derive(Clone, Copy)]
pub struct Metadata {
    pub device: DeviceId,
    pub pool: PoolId,
    pub incarnation: IncarnationId,
    pub generation: GenerationId,
    pub generation_number: GenerationNumber,
    pub recipient_public_key: [u8; 32],
    pub recipient_id: [u8; 32],
}

pub struct BackupArtifact {
    bytes: [u8; MAX_BACKUP_BYTES],
    length: usize,
}

impl BackupArtifact {
    pub fn encoded(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

pub fn create(
    key: &KesKey,
    metadata: Metadata,
    identity: &SigningKey,
    entropy: &mut impl TryCryptoRng,
) -> Result<BackupArtifact, Error> {
    let canonical = key.canonical_state()?;
    if canonical.algorithm() != SUM6_V1 || canonical.relative_period().get() != 0 {
        return Err(Error::Crypto(CryptoError::InvalidPeriod));
    }
    let verification_key = key.verification_key()?;
    let recipient_id: [u8; 32] = Sha256::digest(metadata.recipient_public_key).into();
    if recipient_id != metadata.recipient_id {
        return Err(Error::InvalidRecipient);
    }

    type Aead = ChaCha20Poly1305;
    type Kdf = HkdfSha256;
    type Kem = X25519HkdfSha256;
    let recipient = <Kem as KemTrait>::PublicKey::from_bytes(&metadata.recipient_public_key)
        .map_err(|_| Error::InvalidRecipient)?;
    let mut header_storage = [0; 512];
    let header_length = encode_header(&mut header_storage, metadata, &verification_key)?;
    let header = &header_storage[..header_length];
    let mut info = [0; 512];
    let info_prefix = b"cardano-kes-forge/backup/v1";
    let info_length = info_prefix.len() + header.len();
    info[..info_prefix.len()].copy_from_slice(info_prefix);
    info[info_prefix.len()..info_length].copy_from_slice(header);
    let mut aad = [0; 512];
    let aad_length = MAGIC.len() + header.len();
    aad[..MAGIC.len()].copy_from_slice(MAGIC);
    aad[MAGIC.len()..aad_length].copy_from_slice(header);

    let mut seed = Zeroizing::new([0; 32]);
    entropy
        .try_fill_bytes(&mut seed[..])
        .map_err(|_| Error::Entropy)?;
    let mut rng = ChaCha20Rng::from_seed(*seed);
    let (encapsulation, mut sender) = setup_sender::<Aead, Kdf, Kem, _>(
        &OpModeS::Base,
        &recipient,
        &info[..info_length],
        &mut rng,
    )
    .map_err(|_| Error::Hpke)?;
    let mut ciphertext: Zeroizing<[u8; CIPHERTEXT_BYTES]> = Zeroizing::new([0; CIPHERTEXT_BYTES]);
    ciphertext[..SIGNING_STATE_BYTES].copy_from_slice(canonical.bytes());
    let tag = sender
        .seal_in_place_detached(&mut ciphertext[..SIGNING_STATE_BYTES], &aad[..aad_length])
        .map_err(|_| Error::Hpke)?;
    ciphertext[SIGNING_STATE_BYTES..].copy_from_slice(&tag.to_bytes());
    let encapsulation: [u8; 32] = encapsulation.to_bytes().into();

    let mut unsigned_storage = [0; MAX_BACKUP_BYTES];
    let unsigned = encode_map(
        &mut unsigned_storage,
        metadata,
        &verification_key,
        &encapsulation,
        &ciphertext,
        None,
    )?;
    let mut signed = [0; MAX_BACKUP_BYTES + 48];
    let domain = b"cardano-kes-forge/backup-signature/v1";
    let signed_length = domain.len() + MAGIC.len() + unsigned.len();
    signed[..domain.len()].copy_from_slice(domain);
    signed[domain.len()..domain.len() + MAGIC.len()].copy_from_slice(MAGIC);
    signed[domain.len() + MAGIC.len()..signed_length].copy_from_slice(unsigned);
    let signature = identity.sign(&signed[..signed_length]).to_bytes();

    let mut artifact = BackupArtifact {
        bytes: [0; MAX_BACKUP_BYTES],
        length: 0,
    };
    artifact.bytes[..MAGIC.len()].copy_from_slice(MAGIC);
    let encoded = encode_map(
        &mut artifact.bytes[MAGIC.len()..],
        metadata,
        &verification_key,
        &encapsulation,
        &ciphertext,
        Some(&signature),
    )?;
    artifact.length = MAGIC.len() + encoded.len();
    Ok(artifact)
}

fn encode_header(
    storage: &mut [u8; 512],
    metadata: Metadata,
    verification_key: &[u8; 32],
) -> Result<usize, Error> {
    let mut encoder = Encoder::new(storage);
    encode_header_fields(&mut encoder, metadata, verification_key)?;
    Ok(encoder
        .finish()
        .map_err(|_| Error::Encoding)?
        .encoded()
        .len())
}

fn encode_header_fields(
    encoder: &mut Encoder<'_>,
    metadata: Metadata,
    verification_key: &[u8; 32],
) -> Result<(), Error> {
    encoder.map(13).map_err(|_| Error::Encoding)?;
    encoder.text("kdf").map_err(|_| Error::Encoding)?;
    encoder.uint(1).map_err(|_| Error::Encoding)?;
    encoder.text("kem").map_err(|_| Error::Encoding)?;
    encoder.uint(32).map_err(|_| Error::Encoding)?;
    encoder.text("aead").map_err(|_| Error::Encoding)?;
    encoder.uint(3).map_err(|_| Error::Encoding)?;
    encoder.text("pool").map_err(|_| Error::Encoding)?;
    encoder
        .bytes(metadata.pool.as_bytes())
        .map_err(|_| Error::Encoding)?;
    encoder.text("device").map_err(|_| Error::Encoding)?;
    encoder
        .bytes(metadata.device.as_bytes())
        .map_err(|_| Error::Encoding)?;
    encoder.text("period").map_err(|_| Error::Encoding)?;
    encoder.uint(0).map_err(|_| Error::Encoding)?;
    encoder.text("version").map_err(|_| Error::Encoding)?;
    encoder.uint(1).map_err(|_| Error::Encoding)?;
    encoder.text("generation").map_err(|_| Error::Encoding)?;
    encoder
        .bytes(metadata.generation.as_bytes())
        .map_err(|_| Error::Encoding)?;
    encoder.text("incarnation").map_err(|_| Error::Encoding)?;
    encoder
        .bytes(metadata.incarnation.as_bytes())
        .map_err(|_| Error::Encoding)?;
    encoder.text("recipient_id").map_err(|_| Error::Encoding)?;
    encoder
        .bytes(&metadata.recipient_id)
        .map_err(|_| Error::Encoding)?;
    encoder
        .text("verification_key")
        .map_err(|_| Error::Encoding)?;
    encoder
        .bytes(verification_key)
        .map_err(|_| Error::Encoding)?;
    encoder
        .text("generation_number")
        .map_err(|_| Error::Encoding)?;
    encoder
        .uint(metadata.generation_number.get())
        .map_err(|_| Error::Encoding)?;
    encoder
        .text("recipient_public_key")
        .map_err(|_| Error::Encoding)?;
    encoder
        .bytes(&metadata.recipient_public_key)
        .map_err(|_| Error::Encoding)
}

fn encode_map<'a>(
    storage: &'a mut [u8],
    metadata: Metadata,
    verification_key: &[u8; 32],
    encapsulation: &[u8; 32],
    ciphertext: &[u8; CIPHERTEXT_BYTES],
    signature: Option<&[u8; 64]>,
) -> Result<&'a [u8], Error> {
    let mut encoder = Encoder::new(storage);
    encoder
        .map(if signature.is_some() { 16 } else { 15 })
        .map_err(|_| Error::Encoding)?;
    encoder.text("kdf").map_err(|_| Error::Encoding)?;
    encoder.uint(1).map_err(|_| Error::Encoding)?;
    encoder.text("kem").map_err(|_| Error::Encoding)?;
    encoder.uint(32).map_err(|_| Error::Encoding)?;
    encoder.text("aead").map_err(|_| Error::Encoding)?;
    encoder.uint(3).map_err(|_| Error::Encoding)?;
    encoder.text("pool").map_err(|_| Error::Encoding)?;
    encoder
        .bytes(metadata.pool.as_bytes())
        .map_err(|_| Error::Encoding)?;
    encoder.text("device").map_err(|_| Error::Encoding)?;
    encoder
        .bytes(metadata.device.as_bytes())
        .map_err(|_| Error::Encoding)?;
    encoder.text("period").map_err(|_| Error::Encoding)?;
    encoder.uint(0).map_err(|_| Error::Encoding)?;
    encoder.text("version").map_err(|_| Error::Encoding)?;
    encoder.uint(1).map_err(|_| Error::Encoding)?;
    encoder.text("ciphertext").map_err(|_| Error::Encoding)?;
    encoder.bytes(ciphertext).map_err(|_| Error::Encoding)?;
    encoder.text("generation").map_err(|_| Error::Encoding)?;
    encoder
        .bytes(metadata.generation.as_bytes())
        .map_err(|_| Error::Encoding)?;
    encoder.text("incarnation").map_err(|_| Error::Encoding)?;
    encoder
        .bytes(metadata.incarnation.as_bytes())
        .map_err(|_| Error::Encoding)?;
    encoder.text("recipient_id").map_err(|_| Error::Encoding)?;
    encoder
        .bytes(&metadata.recipient_id)
        .map_err(|_| Error::Encoding)?;
    encoder.text("encapsulation").map_err(|_| Error::Encoding)?;
    encoder.bytes(encapsulation).map_err(|_| Error::Encoding)?;
    if let Some(signature) = signature {
        encoder
            .text("device_signature")
            .map_err(|_| Error::Encoding)?;
        encoder.bytes(signature).map_err(|_| Error::Encoding)?;
    }
    encoder
        .text("verification_key")
        .map_err(|_| Error::Encoding)?;
    encoder
        .bytes(verification_key)
        .map_err(|_| Error::Encoding)?;
    encoder
        .text("generation_number")
        .map_err(|_| Error::Encoding)?;
    encoder
        .uint(metadata.generation_number.get())
        .map_err(|_| Error::Encoding)?;
    encoder
        .text("recipient_public_key")
        .map_err(|_| Error::Encoding)?;
    encoder
        .bytes(&metadata.recipient_public_key)
        .map_err(|_| Error::Encoding)?;
    Ok(encoder.finish().map_err(|_| Error::Encoding)?.encoded())
}
