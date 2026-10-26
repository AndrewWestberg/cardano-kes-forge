use kes_protocol::{MAX_FRAME_BYTES, ReceiverState};
use std::fs::{self, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const MAX_PEERS: usize = 64;
pub const PARTIAL_FRAME_TIMEOUT: Duration = Duration::from_millis(2_000);

pub struct Frame {
    bytes: Box<[u8; MAX_FRAME_BYTES]>,
    len: usize,
}

impl Frame {
    pub fn copy_from(bytes: &[u8]) -> io::Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid frame length",
            ));
        }
        let mut frame = Self::empty();
        frame.bytes[..bytes.len()].copy_from_slice(bytes);
        frame.len = bytes.len();
        Ok(frame)
    }

    pub fn empty() -> Self {
        Self {
            bytes: Box::new([0; MAX_FRAME_BYTES]),
            len: 0,
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub fn replace(&mut self, bytes: &[u8]) -> io::Result<()> {
        if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid frame length",
            ));
        }
        self.bytes[..bytes.len()].copy_from_slice(bytes);
        self.len = bytes.len();
        Ok(())
    }

    pub(crate) fn storage(&mut self) -> &mut [u8; MAX_FRAME_BYTES] {
        &mut self.bytes
    }

    pub(crate) fn set_len(&mut self, len: usize) {
        self.len = len;
    }
}

pub struct ProtectedListener {
    listener: UnixListener,
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl ProtectedListener {
    pub fn bind(path: &Path) -> io::Result<Self> {
        validate_socket_parent(path)?;
        match fs::symlink_metadata(path) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "refusing to replace an existing socket path",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let listener = UnixListener::bind(path)?;
        if let Err(error) = fs::set_permissions(path, Permissions::from_mode(0o660)) {
            let _ = fs::remove_file(path);
            return Err(error);
        }
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != rustix::process::getuid().as_raw()
            || metadata.mode() & 0o777 != 0o660
        {
            let _ = fs::remove_file(path);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "socket ownership or mode changed during bind",
            ));
        }
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            path: path.to_path_buf(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    pub fn accept(&self) -> io::Result<(UnixStream, u32)> {
        let (stream, _) = self.listener.accept()?;
        let uid = rustix::net::sockopt::socket_peercred(&stream)?.uid.as_raw();
        Ok((stream, uid))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ProtectedListener {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub fn validate_socket_parent(path: &Path) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socket has no parent directory",
        )
    })?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socket parent must be daemon-owned and not writable by group/other",
        ));
    }
    Ok(())
}

pub fn read_frame(stream: &mut UnixStream) -> io::Result<Frame> {
    stream.set_read_timeout(None)?;
    let mut first = [0; 1];
    stream.read_exact(&mut first)?;
    let started = Instant::now();
    let mut receiver = ReceiverState::new();
    let mut frame = Frame::empty();
    receiver
        .push(frame.storage(), &first, 0)
        .map_err(protocol_io)?;
    let mut scratch = [0; 1_024];
    loop {
        if let Some(length) = receiver.complete(frame.storage()).map(<[u8]>::len) {
            frame.set_len(length);
            stream.set_read_timeout(None)?;
            return Ok(frame);
        }
        let elapsed = started.elapsed();
        let remaining = PARTIAL_FRAME_TIMEOUT
            .checked_sub(elapsed)
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "partial frame expired"))?;
        stream.set_read_timeout(Some(remaining))?;
        let count = stream.read(&mut scratch).map_err(normalize_timeout)?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "peer closed an incomplete frame",
            ));
        }
        let now_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let used = receiver
            .push(frame.storage(), &scratch[..count], now_ms)
            .map_err(protocol_io)?;
        if used != count {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "multiple frames in one peer read are not permitted",
            ));
        }
    }
}

pub fn write_frame(stream: &mut UnixStream, frame: &Frame) -> io::Result<()> {
    let length = u32::try_from(frame.as_slice().len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame length overflow"))?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(frame.as_slice())?;
    stream.flush()
}

fn protocol_io(error: kes_protocol::Error) -> io::Error {
    let kind = match error {
        kes_protocol::Error::Timeout => io::ErrorKind::TimedOut,
        _ => io::ErrorKind::InvalidData,
    };
    io::Error::new(kind, error)
}

fn normalize_timeout(error: io::Error) -> io::Error {
    if matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ) {
        io::Error::new(io::ErrorKind::TimedOut, "partial frame expired")
    } else {
        error
    }
}
