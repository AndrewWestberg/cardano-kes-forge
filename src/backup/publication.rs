use rustix::fs::{AtFlags, Mode, OFlags};
use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_STAGING_FILE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    ExistingOutput,
    UnsafeDirectory,
    MemoryProtection,
    UnsupportedFilesystem,
    Interrupted,
    Io,
    DurabilityUncertain,
    UnsafeInput,
}

pub trait MemoryProtector {
    type Guard;
    fn protect(&self, secret: &mut [u8]) -> Result<Self::Guard, Error>;
}

pub trait PublicationFault {
    fn before_link(&self) -> Result<(), Error>;

    fn after_link(&self) -> Result<(), Error> {
        Ok(())
    }
}

pub struct NoFault;

impl PublicationFault for NoFault {
    fn before_link(&self) -> Result<(), Error> {
        Ok(())
    }
}

pub struct SystemMemory;

pub struct SystemMemoryGuard {
    pointer: *mut c_void,
    length: usize,
}

impl Drop for SystemMemoryGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = rustix::mm::munlock(self.pointer, self.length);
        }
    }
}

impl MemoryProtector for SystemMemory {
    type Guard = SystemMemoryGuard;

    fn protect(&self, secret: &mut [u8]) -> Result<Self::Guard, Error> {
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
            .map_err(|_| Error::MemoryProtection)?;
        let pointer = secret.as_mut_ptr().cast::<c_void>();
        unsafe {
            rustix::mm::mlock(pointer, secret.len()).map_err(|_| Error::MemoryProtection)?;
        }
        Ok(SystemMemoryGuard {
            pointer,
            length: secret.len(),
        })
    }
}

struct SecretWipe {
    pointer: *mut u8,
    length: usize,
}

impl Drop for SecretWipe {
    fn drop(&mut self) {
        unsafe {
            std::slice::from_raw_parts_mut(self.pointer, self.length).fill(0);
        }
    }
}

pub fn publish_secret(path: &Path, secret: &mut [u8]) -> Result<(), Error> {
    publish_secret_with(path, secret, &SystemMemory, &NoFault)
}

pub fn publish_secret_with<P: MemoryProtector, F: PublicationFault>(
    path: &Path,
    secret: &mut [u8],
    protector: &P,
    fault: &F,
) -> Result<(), Error> {
    let _guard = match protector.protect(secret) {
        Ok(guard) => guard,
        Err(error) => {
            secret.fill(0);
            return Err(error);
        }
    };
    let _wipe = SecretWipe {
        pointer: secret.as_mut_ptr(),
        length: secret.len(),
    };
    match std::fs::symlink_metadata(path) {
        Ok(_) => return Err(Error::ExistingOutput),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(Error::Io),
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path.file_name().ok_or(Error::UnsafeDirectory)?;
    validate_ancestors(parent)?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags((OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC).bits() as i32)
        .open(parent)
        .map_err(|_| Error::UnsafeDirectory)?;
    let metadata = directory.metadata().map_err(|_| Error::UnsafeDirectory)?;
    if !metadata.file_type().is_dir()
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != rustix::process::getuid().as_raw()
    {
        return Err(Error::UnsafeDirectory);
    }

    let descriptor = rustix::fs::openat(
        &directory,
        ".",
        OFlags::WRONLY | OFlags::CLOEXEC | OFlags::TMPFILE,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| Error::UnsupportedFilesystem)?;
    let mut anonymous = File::from(descriptor);
    anonymous.write_all(secret).map_err(|_| Error::Io)?;
    anonymous.sync_all().map_err(|_| Error::Io)?;
    fault.before_link()?;
    rustix::fs::linkat(&anonymous, "", &directory, name, AtFlags::EMPTY_PATH).map_err(|error| {
        if error == rustix::io::Errno::EXIST {
            Error::ExistingOutput
        } else {
            Error::Io
        }
    })?;
    fault.after_link().map_err(|_| Error::DurabilityUncertain)?;
    directory.sync_all().map_err(|_| Error::DurabilityUncertain)
}

fn validate_ancestors(parent: &Path) -> Result<(), Error> {
    let uid = rustix::process::getuid().as_raw();
    let mut current = Some(parent);
    while let Some(path) = current {
        let checked = if path.as_os_str().is_empty() {
            Path::new(".")
        } else {
            path
        };
        let metadata = std::fs::symlink_metadata(checked).map_err(|_| Error::UnsafeDirectory)?;
        let mode = metadata.mode();
        let root_sticky_directory =
            metadata.uid() == 0 && mode & 0o1000 != 0 && metadata.file_type().is_dir();
        if !metadata.file_type().is_dir()
            || (metadata.uid() != uid && metadata.uid() != 0)
            || (mode & 0o022 != 0 && !root_sticky_directory)
        {
            return Err(Error::UnsafeDirectory);
        }
        current = path.parent().filter(|ancestor| *ancestor != path);
    }
    Ok(())
}

pub fn replace_encrypted<F: PublicationFault>(
    path: &Path,
    encrypted: &[u8],
    fault: &F,
) -> Result<(), Error> {
    let target = std::fs::symlink_metadata(path).map_err(|_| Error::UnsafeInput)?;
    if !target.file_type().is_file()
        || target.mode() & 0o777 != 0o600
        || target.uid() != rustix::process::getuid().as_raw()
    {
        return Err(Error::UnsafeInput);
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    validate_ancestors(parent)?;
    let metadata = std::fs::symlink_metadata(parent).map_err(|_| Error::UnsafeDirectory)?;
    if !metadata.file_type().is_dir()
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != rustix::process::getuid().as_raw()
    {
        return Err(Error::UnsafeDirectory);
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(Error::UnsafeInput)?;
    let nonce = NEXT_STAGING_FILE.fetch_add(1, Ordering::Relaxed);
    let staging = parent.join(format!(".{name}.rewrap.{}.{}", std::process::id(), nonce));
    let mut cleanup = StagingFile {
        path: staging.clone(),
    };
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&staging)
        .map_err(|_| Error::Io)?;
    file.write_all(encrypted).map_err(|_| Error::Io)?;
    file.sync_all().map_err(|_| Error::Io)?;
    fault.before_link()?;
    std::fs::rename(&staging, path).map_err(|_| Error::Io)?;
    cleanup.path = PathBuf::new();
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| Error::Io)
}

struct StagingFile {
    path: PathBuf,
}

impl Drop for StagingFile {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
