use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    Tag, XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, KeyInit},
};
use kes_core::cbor::{Encoder, Map, Value};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"KESRCP01";
const MEMORY_KIB: u32 = 65_536;
const ITERATIONS: u32 = 3;
const PARALLELISM: u32 = 4;
const ARGON_VERSION: u64 = 19;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    EmptyPassphrase,
    InvalidPassphrase,
    Entropy,
    InvalidFormat,
    UnsupportedParameters,
    Authentication,
    TerminalUnavailable,
    ConfirmationMismatch,
    MemoryProtection,
}

pub trait Entropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Error>;
}

pub struct OsEntropy(File);

impl OsEntropy {
    pub fn new() -> Result<Self, Error> {
        File::open("/dev/urandom")
            .map(Self)
            .map_err(|_| Error::Entropy)
    }
}

impl Entropy for OsEntropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
        self.0.read_exact(output).map_err(|_| Error::Entropy)
    }
}

struct EchoGuard {
    terminal: File,
    original: rustix::termios::Termios,
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        let _ = rustix::termios::tcsetattr(
            &self.terminal,
            rustix::termios::OptionalActions::Now,
            &self.original,
        );
    }
}

pub fn prompt_new_passphrase() -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut terminal = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| Error::TerminalUnavailable)?;
    let original = rustix::termios::tcgetattr(&terminal).map_err(|_| Error::TerminalUnavailable)?;
    let restore_terminal = terminal
        .try_clone()
        .map_err(|_| Error::TerminalUnavailable)?;
    let mut hidden = original.clone();
    hidden.local_modes.remove(
        rustix::termios::LocalModes::ECHO
            | rustix::termios::LocalModes::ECHOE
            | rustix::termios::LocalModes::ECHOK
            | rustix::termios::LocalModes::ECHONL,
    );
    rustix::termios::tcsetattr(&terminal, rustix::termios::OptionalActions::Now, &hidden)
        .map_err(|_| Error::TerminalUnavailable)?;
    let _guard = EchoGuard {
        terminal: restore_terminal,
        original,
    };
    terminal
        .write_all(b"Recipient passphrase: ")
        .and_then(|()| terminal.flush())
        .map_err(|_| Error::TerminalUnavailable)?;
    let first = read_terminal_line(&mut terminal)?;
    terminal
        .write_all(b"\nConfirm recipient passphrase: ")
        .and_then(|()| terminal.flush())
        .map_err(|_| Error::TerminalUnavailable)?;
    let second = read_terminal_line(&mut terminal)?;
    terminal
        .write_all(b"\n")
        .and_then(|()| terminal.flush())
        .map_err(|_| Error::TerminalUnavailable)?;
    validate_passphrase(&first)?;
    if first.as_slice() != second.as_slice() {
        return Err(Error::ConfirmationMismatch);
    }
    Ok(first)
}

pub fn prompt_existing_passphrase() -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut terminal = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| Error::TerminalUnavailable)?;
    let original = rustix::termios::tcgetattr(&terminal).map_err(|_| Error::TerminalUnavailable)?;
    let restore_terminal = terminal
        .try_clone()
        .map_err(|_| Error::TerminalUnavailable)?;
    let mut hidden = original.clone();
    hidden.local_modes.remove(
        rustix::termios::LocalModes::ECHO
            | rustix::termios::LocalModes::ECHONL
            | rustix::termios::LocalModes::ECHOK
            | rustix::termios::LocalModes::ECHOE,
    );
    rustix::termios::tcsetattr(&terminal, rustix::termios::OptionalActions::Now, &hidden)
        .map_err(|_| Error::TerminalUnavailable)?;
    let _guard = EchoGuard {
        terminal: restore_terminal,
        original,
    };
    terminal
        .write_all(b"Recipient passphrase: ")
        .and_then(|()| terminal.flush())
        .map_err(|_| Error::TerminalUnavailable)?;
    let passphrase = read_terminal_line(&mut terminal)?;
    terminal
        .write_all(b"\n")
        .and_then(|()| terminal.flush())
        .map_err(|_| Error::TerminalUnavailable)?;
    validate_passphrase(&passphrase)?;
    Ok(passphrase)
}

fn read_terminal_line(terminal: &mut File) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut value = Zeroizing::new(Vec::with_capacity(64));
    let mut byte = [0];
    while value.len() <= 4096 {
        if terminal
            .read(&mut byte)
            .map_err(|_| Error::TerminalUnavailable)?
            != 1
        {
            return Err(Error::TerminalUnavailable);
        }
        if byte[0] == b'\n' {
            if value.last() == Some(&b'\r') {
                value.pop();
            }
            return Ok(value);
        }
        value.push(byte[0]);
    }
    Err(Error::InvalidPassphrase)
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RecipientPublic {
    pub public_key: [u8; 32],
    pub recipient_id: [u8; 32],
}

impl RecipientPublic {
    pub fn json(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec_pretty(&json!({
            "version": 1,
            "algorithm": "X25519",
            "publicKey": hex(&self.public_key),
            "recipientId": hex(&self.recipient_id),
        }))
        .map_err(|_| Error::InvalidFormat)
    }
}

pub struct RecipientKeyFile {
    encoded: Vec<u8>,
}

impl RecipientKeyFile {
    pub fn parse(encoded: Vec<u8>) -> Result<Self, Error> {
        parse_fields(&encoded)?;
        Ok(Self { encoded })
    }

    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    pub fn public(&self) -> Result<RecipientPublic, Error> {
        let fields = parse_fields(&self.encoded)?;
        Ok(RecipientPublic {
            public_key: fields.public_key,
            recipient_id: fields.recipient_id,
        })
    }

    pub fn unlock(&self, passphrase: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
        let mut private = Zeroizing::new([0; 32]);
        self.unlock_into(passphrase, &mut private)?;
        Ok(private)
    }

    pub(crate) fn unlock_into(
        &self,
        passphrase: &[u8],
        private: &mut [u8; 32],
    ) -> Result<(), Error> {
        validate_passphrase(passphrase)?;
        let fields = parse_fields(&self.encoded)?;
        let aad = header(
            &fields.salt,
            &fields.nonce,
            &fields.public_key,
            &fields.recipient_id,
        )?;
        let mut key = derive_key(passphrase, &fields.salt)?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| Error::InvalidFormat)?;
        private.copy_from_slice(fields.ciphertext.get(..32).ok_or(Error::InvalidFormat)?);
        let tag_bytes: [u8; 16] = fields.ciphertext[32..]
            .try_into()
            .map_err(|_| Error::InvalidFormat)?;
        cipher
            .decrypt_in_place_detached(
                &XNonce::from(fields.nonce),
                &aad,
                &mut private[..],
                &Tag::from(tag_bytes),
            )
            .map_err(|_| Error::Authentication)?;
        key.fill(0);
        verify_private(private, fields.public_key, fields.recipient_id)
    }

    pub fn rewrap(
        &self,
        old_passphrase: &[u8],
        new_passphrase: &[u8],
        entropy: &mut impl Entropy,
    ) -> Result<Self, Error> {
        with_locked_private(|private| {
            self.unlock_into(old_passphrase, private)?;
            validate_passphrase(new_passphrase)?;
            let public = self.public()?;
            encode_private(private, public, new_passphrase, entropy)
        })
    }
}

pub fn create_interactive() -> Result<(RecipientPublic, RecipientKeyFile), Error> {
    let passphrase = prompt_new_passphrase()?;
    let mut entropy = OsEntropy::new()?;
    create(&passphrase, &mut entropy)
}

pub fn create(
    passphrase: &[u8],
    entropy: &mut impl Entropy,
) -> Result<(RecipientPublic, RecipientKeyFile), Error> {
    validate_passphrase(passphrase)?;
    with_locked_private(|private| {
        entropy.fill(&mut private[..])?;
        let secret = StaticSecret::from(*private);
        let public_key = PublicKey::from(&secret).to_bytes();
        let recipient_id = Sha256::digest(public_key).into();
        let public = RecipientPublic {
            public_key,
            recipient_id,
        };
        let protected = encode_private(private, public, passphrase, entropy)?;
        Ok((public, protected))
    })
}

fn with_locked_private<T>(
    operation: impl FnOnce(&mut [u8; 32]) -> Result<T, Error>,
) -> Result<T, Error> {
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(|_| Error::MemoryProtection)?;
    let mut private = Box::new([0; 32]);
    let pointer = private.as_mut_ptr().cast::<c_void>();
    unsafe {
        rustix::mm::mlock(pointer, private.len()).map_err(|_| Error::MemoryProtection)?;
    }
    let result = operation(&mut private);
    private.zeroize();
    unsafe {
        let _ = rustix::mm::munlock(pointer, private.len());
    }
    result
}

fn encode_private(
    private: &[u8; 32],
    public: RecipientPublic,
    passphrase: &[u8],
    entropy: &mut impl Entropy,
) -> Result<RecipientKeyFile, Error> {
    let mut salt = [0; 16];
    let mut nonce = [0; 24];
    entropy.fill(&mut salt)?;
    entropy.fill(&mut nonce)?;
    let aad = header(&salt, &nonce, &public.public_key, &public.recipient_id)?;
    let mut key = derive_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| Error::InvalidFormat)?;
    let mut ciphertext: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(48));
    ciphertext.extend_from_slice(private);
    let tag = cipher
        .encrypt_in_place_detached(&XNonce::from(nonce), &aad, &mut ciphertext[..])
        .map_err(|_| Error::Authentication)?;
    ciphertext.extend_from_slice(&tag);
    key.fill(0);

    let mut map = [0; 512];
    let mut encoder = Encoder::new(&mut map);
    encode_fields(
        &mut encoder,
        &salt,
        &nonce,
        &public.public_key,
        &public.recipient_id,
        Some(&ciphertext[..]),
    )?;
    let value = encoder.finish().map_err(|_| Error::InvalidFormat)?;
    let mut encoded = Vec::with_capacity(MAGIC.len() + value.encoded().len());
    encoded.extend_from_slice(MAGIC);
    encoded.extend_from_slice(value.encoded());
    let file = RecipientKeyFile { encoded };
    let unlocked = file.unlock(passphrase)?;
    if unlocked.as_ref() != private {
        return Err(Error::Authentication);
    }
    Ok(file)
}

fn header(
    salt: &[u8; 16],
    nonce: &[u8; 24],
    public_key: &[u8; 32],
    recipient_id: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    let mut map = [0; 512];
    let mut encoder = Encoder::new(&mut map);
    encode_fields(&mut encoder, salt, nonce, public_key, recipient_id, None)?;
    let value = encoder.finish().map_err(|_| Error::InvalidFormat)?;
    let mut output = Vec::with_capacity(MAGIC.len() + value.encoded().len());
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(value.encoded());
    Ok(output)
}

fn encode_fields(
    encoder: &mut Encoder<'_>,
    salt: &[u8; 16],
    nonce: &[u8; 24],
    public_key: &[u8; 32],
    recipient_id: &[u8; 32],
    ciphertext: Option<&[u8]>,
) -> Result<(), Error> {
    encoder
        .map(if ciphertext.is_some() { 12 } else { 11 })
        .map_err(|_| Error::InvalidFormat)?;
    encoder.text("kdf").map_err(|_| Error::InvalidFormat)?;
    encoder.text("argon2id").map_err(|_| Error::InvalidFormat)?;
    encoder.text("aead").map_err(|_| Error::InvalidFormat)?;
    encoder
        .text("XChaCha20Poly1305")
        .map_err(|_| Error::InvalidFormat)?;
    encoder.text("salt").map_err(|_| Error::InvalidFormat)?;
    encoder.bytes(salt).map_err(|_| Error::InvalidFormat)?;
    encoder.text("nonce").map_err(|_| Error::InvalidFormat)?;
    encoder.bytes(nonce).map_err(|_| Error::InvalidFormat)?;
    encoder.text("version").map_err(|_| Error::InvalidFormat)?;
    encoder.uint(1).map_err(|_| Error::InvalidFormat)?;
    if let Some(ciphertext) = ciphertext {
        encoder
            .text("ciphertext")
            .map_err(|_| Error::InvalidFormat)?;
        encoder
            .bytes(ciphertext)
            .map_err(|_| Error::InvalidFormat)?;
    }
    encoder
        .text("iterations")
        .map_err(|_| Error::InvalidFormat)?;
    encoder
        .uint(u64::from(ITERATIONS))
        .map_err(|_| Error::InvalidFormat)?;
    encoder
        .text("memory_kib")
        .map_err(|_| Error::InvalidFormat)?;
    encoder
        .uint(u64::from(MEMORY_KIB))
        .map_err(|_| Error::InvalidFormat)?;
    encoder
        .text("public_key")
        .map_err(|_| Error::InvalidFormat)?;
    encoder
        .bytes(public_key)
        .map_err(|_| Error::InvalidFormat)?;
    encoder
        .text("parallelism")
        .map_err(|_| Error::InvalidFormat)?;
    encoder
        .uint(u64::from(PARALLELISM))
        .map_err(|_| Error::InvalidFormat)?;
    encoder
        .text("recipient_id")
        .map_err(|_| Error::InvalidFormat)?;
    encoder
        .bytes(recipient_id)
        .map_err(|_| Error::InvalidFormat)?;
    encoder
        .text("argon_version")
        .map_err(|_| Error::InvalidFormat)?;
    encoder
        .uint(ARGON_VERSION)
        .map_err(|_| Error::InvalidFormat)
}

struct Fields<'a> {
    salt: [u8; 16],
    nonce: [u8; 24],
    public_key: [u8; 32],
    recipient_id: [u8; 32],
    ciphertext: &'a [u8],
}

fn parse_fields(encoded: &[u8]) -> Result<Fields<'_>, Error> {
    if encoded.get(..8) != Some(MAGIC) {
        return Err(Error::InvalidFormat);
    }
    let map = Value::parse(&encoded[8..])
        .map_err(|_| Error::InvalidFormat)?
        .map()
        .map_err(|_| Error::InvalidFormat)?;
    require_keys(map)?;
    if uint(map, "version")? != 1
        || text(map, "kdf")? != "argon2id"
        || text(map, "aead")? != "XChaCha20Poly1305"
    {
        return Err(Error::InvalidFormat);
    }
    if uint(map, "argon_version")? != ARGON_VERSION
        || uint(map, "memory_kib")? != u64::from(MEMORY_KIB)
        || uint(map, "iterations")? != u64::from(ITERATIONS)
        || uint(map, "parallelism")? != u64::from(PARALLELISM)
    {
        return Err(Error::UnsupportedParameters);
    }
    let fields = Fields {
        salt: fixed(map, "salt")?,
        nonce: fixed(map, "nonce")?,
        public_key: fixed(map, "public_key")?,
        recipient_id: fixed(map, "recipient_id")?,
        ciphertext: map
            .required("ciphertext")
            .map_err(|_| Error::InvalidFormat)?
            .bytes()
            .map_err(|_| Error::InvalidFormat)?,
    };
    if fields.ciphertext.len() != 48 {
        return Err(Error::InvalidFormat);
    }
    let expected_id: [u8; 32] = Sha256::digest(fields.public_key).into();
    if fields.recipient_id != expected_id {
        return Err(Error::InvalidFormat);
    }
    Ok(fields)
}

fn require_keys(map: Map<'_>) -> Result<(), Error> {
    const KEYS: [&str; 12] = [
        "kdf",
        "aead",
        "salt",
        "nonce",
        "version",
        "ciphertext",
        "iterations",
        "memory_kib",
        "public_key",
        "parallelism",
        "recipient_id",
        "argon_version",
    ];
    let mut count = 0;
    for field in map {
        let (key, _) = field.map_err(|_| Error::InvalidFormat)?;
        if !KEYS.contains(&key) {
            return Err(Error::InvalidFormat);
        }
        count += 1;
    }
    if count == KEYS.len() {
        Ok(())
    } else {
        Err(Error::InvalidFormat)
    }
}

fn derive_key(passphrase: &[u8], salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let params = Params::new(MEMORY_KIB, ITERATIONS, PARALLELISM, Some(32))
        .map_err(|_| Error::UnsupportedParameters)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0; 32]);
    argon
        .hash_password_into(passphrase, salt, &mut key[..])
        .map_err(|_| Error::Authentication)?;
    Ok(key)
}

fn validate_passphrase(passphrase: &[u8]) -> Result<(), Error> {
    if passphrase.is_empty() {
        Err(Error::EmptyPassphrase)
    } else if std::str::from_utf8(passphrase).is_err() {
        Err(Error::InvalidPassphrase)
    } else {
        Ok(())
    }
}

fn verify_private(
    private: &[u8; 32],
    expected_public: [u8; 32],
    expected_id: [u8; 32],
) -> Result<(), Error> {
    let public = PublicKey::from(&StaticSecret::from(*private)).to_bytes();
    let recipient_id: [u8; 32] = Sha256::digest(public).into();
    if public == expected_public && recipient_id == expected_id {
        Ok(())
    } else {
        Err(Error::Authentication)
    }
}

fn fixed<const N: usize>(map: Map<'_>, field: &str) -> Result<[u8; N], Error> {
    map.required(field)
        .map_err(|_| Error::InvalidFormat)?
        .bytes()
        .map_err(|_| Error::InvalidFormat)?
        .try_into()
        .map_err(|_| Error::InvalidFormat)
}

fn uint(map: Map<'_>, field: &str) -> Result<u64, Error> {
    map.required(field)
        .map_err(|_| Error::InvalidFormat)?
        .uint()
        .map_err(|_| Error::InvalidFormat)
}

fn text<'a>(map: Map<'a>, field: &str) -> Result<&'a str, Error> {
    map.required(field)
        .map_err(|_| Error::InvalidFormat)?
        .text()
        .map_err(|_| Error::InvalidFormat)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 15) as usize] as char);
    }
    output
}
