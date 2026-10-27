//! Canonical authenticated snapshot payloads; authentication belongs to the journal.
use super::JournalError;
use crate::cbor::{self, Array, Encoder, Value};
use crate::state::{ManagementReplay, ManagementResult};
use crate::types::{ManagementSequence, RequestId, Revision};

pub struct PoolCodec;
pub struct DirectoryCodec;

impl PoolCodec {
    /// Includes the 128-byte authenticated header and 16-byte AEAD tag.
    pub const MAX_SNAPSHOT_BYTES: usize = 3584;
    pub const MAX_PLAINTEXT_BYTES: usize = Self::MAX_SNAPSHOT_BYTES - 128 - 16;
}

pub(crate) fn array(value: Value<'_>, count: usize) -> Result<Array<'_>, JournalError> {
    let values = value.array()?;
    if values.count() != count {
        return Err(cbor::Error::InvalidType.into());
    }
    Ok(value.array()?)
}
pub(crate) fn next<'a>(values: &mut Array<'a>) -> Result<Value<'a>, JournalError> {
    values
        .next()
        .ok_or_else(|| cbor::Error::MissingField.into())
}
pub(crate) fn uint(values: &mut Array<'_>) -> Result<u64, JournalError> {
    Ok(next(values)?.uint()?)
}
pub(crate) fn fixed<const N: usize>(values: &mut Array<'_>) -> Result<[u8; N], JournalError> {
    next(values)?
        .bytes()?
        .try_into()
        .map_err(|_| cbor::Error::InvalidType.into())
}
pub(crate) fn expect(values: &mut Array<'_>, expected: u64) -> Result<(), JournalError> {
    if uint(values)? != expected {
        return Err(cbor::Error::InvalidType.into());
    }
    Ok(())
}
pub(crate) fn decode_counter(
    value: Value<'_>,
) -> Result<Option<crate::types::CertificateCounter>, JournalError> {
    if value.is_null() {
        Ok(None)
    } else {
        Ok(Some(crate::types::CertificateCounter::new(value.uint()?)))
    }
}
pub(crate) fn encode_counter(
    out: &mut Encoder<'_>,
    value: Option<crate::types::CertificateCounter>,
) -> Result<(), JournalError> {
    match value {
        Some(value) => out.uint(value.get())?,
        None => out.null()?,
    }
    Ok(())
}
pub(crate) fn decode_replay(value: Value<'_>) -> Result<ManagementReplay, JournalError> {
    let mut values = array(value, 5)?;
    let sequence = ManagementSequence::new(uint(&mut values)?);
    let request = RequestId::from_bytes(fixed(&mut values)?);
    let payload_digest = fixed(&mut values)?;
    expect(&mut values, 0)?;
    let revision = Revision::new(uint(&mut values)?);
    Ok(ManagementReplay {
        sequence,
        request,
        payload_digest,
        result: ManagementResult::Committed { revision },
    })
}
pub(crate) fn encode_replay(
    out: &mut Encoder<'_>,
    replay: &ManagementReplay,
) -> Result<(), JournalError> {
    out.array(5)?;
    out.uint(replay.sequence.get())?;
    out.bytes(replay.request.as_bytes())?;
    out.bytes(&replay.payload_digest)?;
    out.uint(0)?;
    let ManagementResult::Committed { revision } = replay.result;
    out.uint(revision.get())?;
    Ok(())
}
pub(crate) fn replay_revision(replay: &ManagementReplay) -> Revision {
    let ManagementResult::Committed { revision } = replay.result;
    revision
}
