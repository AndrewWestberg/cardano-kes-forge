//! Immutable public storage views. The backup input is already-encrypted producer
//! output; structural identification here is not HPKE/signature verification.
//! A reference digest is trusted only when bound by an authenticated snapshot.
use super::StateError;
use crate::types::GenerationId;
use blake2::{Blake2b, digest::consts::U32};
use sha2::{Digest, Sha256};

pub const PUBLIC_OBJECT_VERSION: u16 = 1;
pub const PUBLIC_OBJECT_HEADER_BYTES: usize = 32;
pub const PUBLIC_TREE_BYTES: usize = 4064;
pub const MAX_ENCRYPTED_BACKUP_BYTES: usize = 2048;
pub const MAX_PUBLIC_OBJECT_BYTES: usize = 6144;
const MAGIC: &[u8; 8] = b"KESPUB01";

/// Public address metadata, not proof that the referenced bytes are authentic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicObjectRef {
    pub version: u16,
    pub generation: GenerationId,
    pub total_length: u16,
    pub digest: [u8; 32],
}

/// An immutable borrowed tree and encrypted artifact. No plaintext secret field,
/// allocation, per-pool tree copy, or mutable view is exposed.
pub struct PublicObject<'a> {
    reference: PublicObjectRef,
    tree: &'a [u8; PUBLIC_TREE_BYTES],
    encrypted_backup: &'a [u8],
}

impl<'a> PublicObject<'a> {
    pub fn from_parts(
        generation: GenerationId,
        tree: &'a [u8; PUBLIC_TREE_BYTES],
        encrypted_backup: &'a [u8],
        expected_verification_key: &[u8; 32],
    ) -> Result<Self, StateError> {
        if encrypted_backup.len() > MAX_ENCRYPTED_BACKUP_BYTES {
            return Err(StateError::TooLarge);
        }
        // Identification only: full canonical-CBOR/HPKE/device-signature checks
        // belong to the actual encrypted-backup producer/consumer (T030).
        if encrypted_backup.len() <= 8
            || &encrypted_backup[..8] != b"KESBKP01"
            || encrypted_backup[8] >> 5 != 5
        {
            return Err(StateError::InvalidObject);
        }
        validate_tree(tree, expected_verification_key)?;
        let header = header(generation, encrypted_backup.len() as u16);
        let mut hash = Sha256::new();
        hash.update(header);
        hash.update(tree);
        hash.update(encrypted_backup);
        Ok(Self {
            reference: PublicObjectRef {
                version: PUBLIC_OBJECT_VERSION,
                generation,
                total_length: (4096 + encrypted_backup.len()) as u16,
                digest: hash.finalize().into(),
            },
            tree,
            encrypted_backup,
        })
    }

    /// Decode exact bytes against an externally authenticated reference. Hash
    /// equality alone cannot authenticate a reference supplied by an attacker.
    pub fn parse(
        bytes: &'a [u8],
        expected: &PublicObjectRef,
        expected_verification_key: &[u8; 32],
    ) -> Result<Self, StateError> {
        if bytes.len() > MAX_PUBLIC_OBJECT_BYTES {
            return Err(StateError::TooLarge);
        }
        if bytes.len() < 4096 || &bytes[..8] != MAGIC {
            return Err(StateError::InvalidObject);
        }
        let version = u16::from_be_bytes([bytes[8], bytes[9]]);
        if version != PUBLIC_OBJECT_VERSION {
            return Err(StateError::UnsupportedVersion);
        }
        let generation = GenerationId::from_bytes(
            bytes[10..26]
                .try_into()
                .map_err(|_| StateError::InvalidObject)?,
        );
        let tree_length = u16::from_be_bytes([bytes[26], bytes[27]]);
        let backup_length = u16::from_be_bytes([bytes[28], bytes[29]]);
        if tree_length as usize != PUBLIC_TREE_BYTES
            || bytes[30..32] != [0, 0]
            || bytes.len() != 4096 + backup_length as usize
        {
            return Err(StateError::InvalidObject);
        }
        let tree = bytes[32..4096]
            .try_into()
            .map_err(|_| StateError::InvalidObject)?;
        let object = Self::from_parts(generation, tree, &bytes[4096..], expected_verification_key)?;
        if object.reference != *expected {
            return Err(StateError::InvalidObject);
        }
        Ok(object)
    }

    pub const fn reference(&self) -> &PublicObjectRef {
        &self.reference
    }
    pub const fn tree(&self) -> &'a [u8; PUBLIC_TREE_BYTES] {
        self.tree
    }
    pub const fn encrypted_backup(&self) -> &'a [u8] {
        self.encrypted_backup
    }
    pub fn backup_digest(&self) -> [u8; 32] {
        Sha256::digest(self.encrypted_backup).into()
    }
    pub fn verification_key(&self) -> &[u8] {
        &self.tree[..32]
    }

    /// Writes only the exact object prefix, returning its length. Remaining
    /// caller buffer bytes are untouched and are not part of the object.
    pub fn encode_into(&self, output: &mut [u8]) -> Result<usize, StateError> {
        let length = usize::from(self.reference.total_length);
        if output.len() < length {
            return Err(StateError::Capacity);
        }
        output[..32].copy_from_slice(&header(
            self.reference.generation,
            self.encrypted_backup.len() as u16,
        ));
        output[32..4096].copy_from_slice(self.tree);
        output[4096..length].copy_from_slice(self.encrypted_backup);
        Ok(length)
    }
}

fn header(generation: GenerationId, backup_length: u16) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..10].copy_from_slice(&PUBLIC_OBJECT_VERSION.to_be_bytes());
    bytes[10..26].copy_from_slice(generation.as_bytes());
    bytes[26..28].copy_from_slice(&(PUBLIC_TREE_BYTES as u16).to_be_bytes());
    bytes[28..30].copy_from_slice(&backup_length.to_be_bytes());
    bytes
}

fn validate_tree(tree: &[u8; PUBLIC_TREE_BYTES], expected: &[u8; 32]) -> Result<(), StateError> {
    if &tree[..32] != expected {
        return Err(StateError::InvalidObject);
    }
    // Breadth-first Sum6 tree: 63 internal nodes, followed by 64 leaves.
    for node in 0..63 {
        let children = (2 * node + 1) * 32;
        let digest = Blake2b::<U32>::digest(&tree[children..children + 64]);
        if tree[node * 32..(node + 1) * 32] != digest[..] {
            return Err(StateError::InvalidObject);
        }
    }
    Ok(())
}
