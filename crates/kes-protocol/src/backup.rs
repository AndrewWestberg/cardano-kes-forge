use crate::{Error, MAX_BACKUP_BYTES};
use kes_core::cbor::{Map, Value};

#[derive(Clone, Copy)]
pub struct BackupArtifact<'a> {
    bytes: &'a [u8],
    map: Map<'a>,
}

impl<'a> BackupArtifact<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_BACKUP_BYTES {
            return Err(Error::Oversize);
        }
        if bytes.get(..8) != Some(b"KESBKP01") {
            return Err(Error::InvalidValue);
        }
        let map = Value::parse(&bytes[8..])?.map()?;
        let mut fields = 0u16;
        let mut count = 0usize;
        for item in map {
            let (key, value) = item?;
            let (bit, length) = match key {
                "version" => (0, None),
                "kem" => (1, None),
                "kdf" => (2, None),
                "aead" => (3, None),
                "device" => (4, Some(16)),
                "incarnation" => (5, Some(16)),
                "generation" => (6, Some(16)),
                "pool" => (7, Some(28)),
                "generation_number" => (8, None),
                "verification_key" => (9, Some(32)),
                "recipient_public_key" => (10, Some(32)),
                "recipient_id" => (11, Some(32)),
                "period" => (12, None),
                "encapsulation" => (13, Some(32)),
                "ciphertext" => (14, Some(624)),
                "device_signature" => (15, Some(64)),
                _ => return Err(Error::UnknownField),
            };
            let mask = 1u16 << bit;
            if fields & mask != 0 {
                return Err(Error::DuplicateOrUnsortedKey);
            }
            fields |= mask;
            count += 1;
            if let Some(length) = length {
                if value.bytes()?.len() != length {
                    return Err(Error::InvalidLength);
                }
            } else {
                value.uint()?;
            }
        }
        if count != 16 || fields != u16::MAX {
            return Err(Error::MissingField);
        }
        if map.required("version")?.uint()? != 1 {
            return Err(Error::UnsupportedVersion);
        }
        for (key, expected) in [("kem", 32), ("kdf", 1), ("aead", 3), ("period", 0)] {
            if map.required(key)?.uint()? != expected {
                return Err(Error::InvalidValue);
            }
        }
        Ok(Self { bytes, map })
    }

    pub fn encoded(self) -> &'a [u8] {
        self.bytes
    }

    pub fn map(self) -> Map<'a> {
        self.map
    }
}
