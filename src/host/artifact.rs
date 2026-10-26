use crate::host::config::PoolConnection;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use kes_core::cbor::Encoder;
use kes_protocol::backup::BackupArtifact;
use sha2::{Digest, Sha256};

pub struct ExpectedArtifact<'a> {
    pub connection: &'a PoolConnection,
    pub generation: [u8; 16],
    pub verification_key: Option<[u8; 32]>,
    pub generation_number: Option<u64>,
    pub artifact_digest: [u8; 32],
}

pub fn validate(bytes: &[u8], expected: ExpectedArtifact<'_>) -> Result<(), ()> {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    if digest != expected.artifact_digest {
        return Err(());
    }
    let artifact = BackupArtifact::parse(bytes).map_err(|_| ())?;
    let map = artifact.map();
    require(map, "device", &expected.connection.device_id)?;
    require(map, "pool", &expected.connection.pool_id)?;
    require(map, "incarnation", &expected.connection.incarnation_id)?;
    require(map, "generation", &expected.generation)?;
    if let Some(verification_key) = expected.verification_key {
        require(map, "verification_key", &verification_key)?;
    }
    if let Some(generation_number) = expected.generation_number {
        if map
            .required("generation_number")
            .map_err(|_| ())?
            .uint()
            .map_err(|_| ())?
            != generation_number
        {
            return Err(());
        }
    }
    if map
        .required("period")
        .map_err(|_| ())?
        .uint()
        .map_err(|_| ())?
        != 0
    {
        return Err(());
    }
    let recipient_public_key = map
        .required("recipient_public_key")
        .map_err(|_| ())?
        .bytes()
        .map_err(|_| ())?;
    let recipient_id: [u8; 32] = Sha256::digest(recipient_public_key).into();
    require(map, "recipient_id", &recipient_id)?;

    let signature: [u8; 64] = map
        .required("device_signature")
        .map_err(|_| ())?
        .bytes()
        .map_err(|_| ())?
        .try_into()
        .map_err(|_| ())?;
    let mut unsigned = [0; kes_protocol::MAX_BACKUP_BYTES];
    let mut encoder = Encoder::new(&mut unsigned);
    encoder.map(15).map_err(|_| ())?;
    for field in map {
        let (key, value) = field.map_err(|_| ())?;
        if key != "device_signature" {
            encoder.text(key).map_err(|_| ())?;
            encoder.value(value).map_err(|_| ())?;
        }
    }
    let unsigned = encoder.finish().map_err(|_| ())?;
    let mut signed = Vec::with_capacity(40 + unsigned.encoded().len());
    signed.extend_from_slice(b"cardano-kes-forge/backup-signature/v1");
    signed.extend_from_slice(b"KESBKP01");
    signed.extend_from_slice(unsigned.encoded());
    let key = VerifyingKey::from_bytes(&expected.connection.identity_public_key).map_err(|_| ())?;
    key.verify(&signed, &Signature::from_bytes(&signature))
        .map_err(|_| ())
}

fn require(map: kes_core::cbor::Map<'_>, field: &str, expected: &[u8]) -> Result<(), ()> {
    let actual = map
        .required(field)
        .map_err(|_| ())?
        .bytes()
        .map_err(|_| ())?;
    if actual == expected { Ok(()) } else { Err(()) }
}
