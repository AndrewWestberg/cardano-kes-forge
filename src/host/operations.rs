use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum State {
    Pending,
    InProgress,
    Unknown,
    NotCommitted,
    ResultReclaimed,
    Committed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    pub device: [u8; 16],
    pub pool: Option<[u8; 28]>,
    pub incarnation: Option<[u8; 16]>,
    pub request: [u8; 16],
    pub generation_number: Option<u64>,
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Invalid,
    Conflict,
    Rollback,
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecordFile {
    version: u64,
    operation: String,
    device_id: String,
    pool_id: Option<String>,
    incarnation_id: Option<String>,
    request_id: String,
    payload_digest: String,
    #[serde(default)]
    canonical_payload: Option<String>,
    generation_number: Option<u64>,
    committed_generation_id: Option<String>,
    state: State,
}

pub struct OperationRecord {
    path: PathBuf,
    operation: String,
    identity: Identity,
    payload_digest: [u8; 32],
    canonical_payload: Option<Vec<u8>>,
    committed_generation: Option<[u8; 16]>,
    state: State,
    resumed: bool,
}

impl OperationRecord {
    /// Creates the durable identity record before dispatch, or resumes the exact
    /// same operation after a process restart. `payload` is the canonical
    /// operation payload, not a reserialized host value.
    pub fn begin(
        path: &Path,
        operation: &str,
        identity: Identity,
        payload: &[u8],
    ) -> Result<Self, Error> {
        validate_operation(operation)?;
        let payload_digest: [u8; 32] = Sha256::digest(payload).into();
        match fs::symlink_metadata(path) {
            Ok(_) => {
                let record = Self::load(path)?;
                if record.operation != operation
                    || record.identity != identity
                    || record.payload_digest != payload_digest
                {
                    return Err(Error::Conflict);
                }
                Ok(record)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let record = Self {
                    path: path.to_path_buf(),
                    operation: operation.to_owned(),
                    identity,
                    payload_digest,
                    canonical_payload: Some(payload.to_vec()),
                    committed_generation: None,
                    state: State::Pending,
                    resumed: false,
                };
                record.publish_new()?;
                Ok(record)
            }
            Err(error) => Err(Error::Io(error)),
        }
    }

    pub fn load(path: &Path) -> Result<Self, Error> {
        let metadata = fs::symlink_metadata(path)?;
        let uid = rustix::process::getuid().as_raw();
        if !metadata.file_type().is_file()
            || metadata.uid() != uid
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err(Error::Invalid);
        }
        validate_parent(path)?;
        let bytes = fs::read(path)?;
        if bytes.len() > 16_384 {
            return Err(Error::Invalid);
        }
        let file: RecordFile = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
        if file.version != 1 {
            return Err(Error::Invalid);
        }
        validate_operation(&file.operation)?;
        let identity = Identity {
            device: decode_hex(&file.device_id).ok_or(Error::Invalid)?,
            pool: decode_optional(&file.pool_id)?,
            incarnation: decode_optional(&file.incarnation_id)?,
            request: decode_hex(&file.request_id).ok_or(Error::Invalid)?,
            generation_number: file.generation_number,
        };
        if identity.pool.is_some() != identity.incarnation.is_some() {
            return Err(Error::Invalid);
        }
        let committed_generation = decode_optional(&file.committed_generation_id)?;
        let payload_digest = decode_hex(&file.payload_digest).ok_or(Error::Invalid)?;
        let canonical_payload = file
            .canonical_payload
            .as_deref()
            .map(decode_hex_vec)
            .transpose()?;
        if canonical_payload
            .as_ref()
            .is_some_and(|payload| <[u8; 32]>::from(Sha256::digest(payload)) != payload_digest)
        {
            return Err(Error::Invalid);
        }
        if (file.state == State::Committed
            && identity.generation_number.is_some() != committed_generation.is_some())
            || (file.state != State::Committed && committed_generation.is_some())
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            path: path.to_path_buf(),
            operation: file.operation,
            identity,
            payload_digest,
            committed_generation,
            canonical_payload,
            state: file.state,
            resumed: true,
        })
    }

    pub const fn identity(&self) -> Identity {
        self.identity
    }

    pub const fn state(&self) -> State {
        self.state
    }

    pub const fn was_resumed(&self) -> bool {
        self.resumed
    }

    pub const fn committed_generation(&self) -> Option<[u8; 16]> {
        self.committed_generation
    }

    pub fn canonical_payload(&self) -> Option<&[u8]> {
        self.canonical_payload.as_deref()
    }

    pub const fn requires_status_reconciliation(&self) -> bool {
        matches!(
            self.state,
            State::Pending | State::InProgress | State::Unknown
        )
    }

    pub fn record_in_progress(&mut self) -> Result<(), Error> {
        self.transition(State::InProgress, None)
    }

    pub fn record_unknown(&mut self) -> Result<(), Error> {
        self.transition(State::Unknown, None)
    }

    pub fn record_not_committed(&mut self) -> Result<(), Error> {
        self.transition(State::NotCommitted, None)
    }

    pub fn record_result_reclaimed(&mut self) -> Result<(), Error> {
        self.transition(State::ResultReclaimed, None)
    }

    pub fn record_committed(&mut self, generation: Option<[u8; 16]>) -> Result<(), Error> {
        if self.identity.generation_number.is_some() != generation.is_some() {
            return Err(Error::Conflict);
        }
        self.transition(State::Committed, generation)
    }

    fn transition(
        &mut self,
        next: State,
        committed_generation: Option<[u8; 16]>,
    ) -> Result<(), Error> {
        if self.state == State::Committed
            && next == State::Committed
            && self.committed_generation != committed_generation
        {
            return Err(Error::Conflict);
        }
        let allowed = match (self.state, next) {
            (current, candidate) if current == candidate => true,
            (
                State::Pending,
                State::InProgress | State::Unknown | State::NotCommitted | State::ResultReclaimed,
            ) => true,
            (State::InProgress, State::Unknown | State::NotCommitted | State::ResultReclaimed) => {
                true
            }
            (State::Unknown, State::InProgress | State::NotCommitted | State::ResultReclaimed) => {
                true
            }
            (State::Pending | State::InProgress | State::Unknown, State::Committed) => true,
            _ => false,
        };
        if !allowed {
            return Err(Error::Rollback);
        }
        if next != State::Committed && committed_generation.is_some() {
            return Err(Error::Conflict);
        }
        let old_state = self.state;
        let old_generation = self.committed_generation;
        self.state = next;
        self.committed_generation = committed_generation;
        if let Err(error) = self.replace() {
            self.state = old_state;
            self.committed_generation = old_generation;
            return Err(error);
        }
        Ok(())
    }

    fn publish_new(&self) -> Result<(), Error> {
        validate_parent(&self.path)?;
        let encoded = self.encoded()?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&self.path)?;
        file.write_all(&encoded)?;
        file.sync_all()?;
        sync_parent(&self.path)?;
        Ok(())
    }

    fn replace(&self) -> Result<(), Error> {
        validate_parent(&self.path)?;
        let encoded = self.encoded()?;
        let parent = parent(&self.path);
        let name = self
            .path
            .file_name()
            .ok_or(Error::Invalid)?
            .to_string_lossy();
        let temporary = parent.join(format!(".{name}.{}.tmp", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        let result = (|| {
            file.write_all(&encoded)?;
            file.sync_all()?;
            fs::rename(&temporary, &self.path)?;
            sync_parent(&self.path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result.map_err(Error::Io)
    }

    fn encoded(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec_pretty(&RecordFile {
            version: 1,
            operation: self.operation.clone(),
            device_id: hex(&self.identity.device),
            pool_id: self.identity.pool.as_ref().map(|value| hex(value)),
            incarnation_id: self.identity.incarnation.as_ref().map(|value| hex(value)),
            request_id: hex(&self.identity.request),
            payload_digest: hex(&self.payload_digest),
            canonical_payload: self.canonical_payload.as_ref().map(|value| hex(value)),
            generation_number: self.identity.generation_number,
            committed_generation_id: self.committed_generation.as_ref().map(|value| hex(value)),
            state: self.state,
        })
        .map_err(|_| Error::Invalid)
    }
}

fn validate_operation(operation: &str) -> Result<(), Error> {
    if operation.is_empty()
        || operation.len() > 32
        || !operation
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte == b'_')
    {
        Err(Error::Invalid)
    } else {
        Ok(())
    }
}

fn validate_parent(path: &Path) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(parent(path))?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(Error::Invalid);
    }
    Ok(())
}

fn sync_parent(path: &Path) -> io::Result<()> {
    OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::DIRECTORY.bits() as i32)
        .open(parent(path))?
        .sync_all()
}

fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

fn decode_optional<const N: usize>(value: &Option<String>) -> Result<Option<[u8; N]>, Error> {
    value
        .as_deref()
        .map(|text| decode_hex(text).ok_or(Error::Invalid))
        .transpose()
}

fn decode_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2 {
        return None;
    }
    let mut output = [0; N];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(output)
}
fn decode_hex_vec(text: &str) -> Result<Vec<u8>, Error> {
    if !text.len().is_multiple_of(2) || text.len() > 16_384 * 2 {
        return Err(Error::Invalid);
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            Ok((nibble(pair[0]).ok_or(Error::Invalid)? << 4)
                | nibble(pair[1]).ok_or(Error::Invalid)?)
        })
        .collect()
}

fn nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 15)] as char);
    }
    output
}
