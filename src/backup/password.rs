use crate::backup::publication::{self, NoFault, PublicationFault};
use crate::backup::recipient::{self, Entropy, OsEntropy, RecipientKeyFile};
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidInput,
    WrongPassword,
    InvalidReplacement,
    Entropy,
    Publication(publication::Error),
    MemoryProtection,
    Terminal,
}

pub fn change_password_interactive(path: &Path) -> Result<(), Error> {
    let protected = load(path)?;
    let old = recipient::prompt_existing_passphrase().map_err(prompt_error)?;
    protected.unlock(&old).map_err(|error| match error {
        recipient::Error::Authentication => Error::WrongPassword,
        recipient::Error::MemoryProtection => Error::MemoryProtection,
        _ => Error::InvalidInput,
    })?;
    let new = recipient::prompt_new_passphrase().map_err(prompt_error)?;
    let mut entropy = OsEntropy::new().map_err(|_| Error::Entropy)?;
    change_password_loaded(path, protected, &old, &new, &mut entropy, &NoFault)
}

fn prompt_error(error: recipient::Error) -> Error {
    match error {
        recipient::Error::MemoryProtection => Error::MemoryProtection,
        _ => Error::Terminal,
    }
}

pub fn change_password_with<E: Entropy, F: PublicationFault>(
    path: &Path,
    old_passphrase: &[u8],
    new_passphrase: &[u8],
    entropy: &mut E,
    fault: &F,
) -> Result<(), Error> {
    let protected = load(path)?;
    change_password_loaded(
        path,
        protected,
        old_passphrase,
        new_passphrase,
        entropy,
        fault,
    )
}

fn change_password_loaded<E: Entropy, F: PublicationFault>(
    path: &Path,
    protected: RecipientKeyFile,
    old_passphrase: &[u8],
    new_passphrase: &[u8],
    entropy: &mut E,
    fault: &F,
) -> Result<(), Error> {
    let public = protected.public().map_err(|_| Error::InvalidInput)?;
    let replacement = protected
        .rewrap(old_passphrase, new_passphrase, entropy)
        .map_err(|error| match error {
            recipient::Error::Authentication => Error::WrongPassword,
            recipient::Error::Entropy => Error::Entropy,
            recipient::Error::EmptyPassphrase
            | recipient::Error::InvalidPassphrase
            | recipient::Error::ConfirmationMismatch => Error::InvalidReplacement,
            recipient::Error::MemoryProtection => Error::MemoryProtection,
            recipient::Error::InvalidFormat
            | recipient::Error::UnsupportedParameters
            | recipient::Error::TerminalUnavailable => Error::InvalidInput,
        })?;
    if replacement
        .public()
        .map_err(|_| Error::InvalidReplacement)?
        != public
        || replacement.unlock(new_passphrase).is_err()
    {
        return Err(Error::InvalidReplacement);
    }
    publication::replace_encrypted(path, replacement.encoded(), fault).map_err(Error::Publication)
}

fn load(path: &Path) -> Result<RecipientKeyFile, Error> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent_metadata = std::fs::symlink_metadata(parent).map_err(|_| Error::InvalidInput)?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.uid() != rustix::process::getuid().as_raw()
        || parent_metadata.permissions().mode() & 0o077 != 0
    {
        return Err(Error::InvalidInput);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|_| Error::InvalidInput)?;
    let metadata = file.metadata().map_err(|_| Error::InvalidInput)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.len() > 16_384
    {
        return Err(Error::InvalidInput);
    }
    let mut encoded = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut encoded)
        .map_err(|_| Error::InvalidInput)?;
    RecipientKeyFile::parse(encoded).map_err(|_| Error::InvalidInput)
}
