//! Stable public statuses and structural codec failures (not authentication).
use core::fmt;

macro_rules! statuses {
    ($($variant:ident => $wire:literal),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum Status { $($variant),+ }
        impl Status {
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];
            pub const fn as_str(self) -> &'static str { match self { $(Self::$variant => $wire),+ } }
            pub fn parse(value: &str) -> Result<Self, Error> { match value { $($wire => Ok(Self::$variant)),+, _ => Err(Error::InvalidValue) } }
        }
    };
}
statuses! {
    InvalidFrame => "INVALID_FRAME", UnsupportedVersion => "UNSUPPORTED_VERSION",
    UnsupportedOperation => "UNSUPPORTED_OPERATION", AuthFailed => "AUTH_FAILED",
    Replay => "REPLAY", WrongDevice => "WRONG_DEVICE", WrongPool => "WRONG_POOL",
    WrongNetwork => "WRONG_NETWORK", SecurityNotReady => "SECURITY_NOT_READY",
    EntropyFailure => "ENTROPY_FAILURE", Capacity => "CAPACITY", Busy => "BUSY",
    DeadlineExceeded => "DEADLINE_EXCEEDED", RevisionConflict => "REVISION_CONFLICT",
    StagedConflict => "STAGED_CONFLICT", StaleGeneration => "STALE_GENERATION",
    StalePeriod => "STALE_PERIOD", NotYetValid => "NOT_YET_VALID", Expired => "EXPIRED",
    CertificateInvalid => "CERTIFICATE_INVALID", RecipientInvalid => "RECIPIENT_INVALID",
    ResultReclaimed => "RESULT_RECLAIMED", StateDamaged => "STATE_DAMAGED",
    DeviceUnavailable => "DEVICE_UNAVAILABLE", InProgress => "IN_PROGRESS",
    Unknown => "UNKNOWN", NotCommitted => "NOT_COMMITTED", Ok => "OK"
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Oversize,
    Incomplete,
    Timeout,
    ClockRegressed,
    NonCanonical,
    DuplicateOrUnsortedKey,
    Nesting,
    InvalidType,
    InvalidUtf8,
    TrailingBytes,
    UnknownField,
    MissingField,
    InvalidLength,
    InvalidValue,
    UnsupportedVersion,
    UnsupportedOperation,
    BufferTooSmall,
    AuthenticationField,
}
impl Error {
    pub const fn status(self) -> Status {
        match self {
            Self::UnsupportedVersion => Status::UnsupportedVersion,
            Self::UnsupportedOperation => Status::UnsupportedOperation,
            Self::Timeout => Status::DeadlineExceeded,
            Self::AuthenticationField => Status::AuthFailed,
            _ => Status::InvalidFrame,
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "protocol {:?}", self)
    }
}
impl core::error::Error for Error {}

impl From<kes_core::cbor::Error> for Error {
    fn from(error: kes_core::cbor::Error) -> Self {
        match error {
            kes_core::cbor::Error::Oversize => Self::Oversize,
            kes_core::cbor::Error::Incomplete => Self::Incomplete,
            kes_core::cbor::Error::NonCanonical => Self::NonCanonical,
            kes_core::cbor::Error::DuplicateOrUnsortedKey => Self::DuplicateOrUnsortedKey,
            kes_core::cbor::Error::Nesting => Self::Nesting,
            kes_core::cbor::Error::InvalidType => Self::InvalidType,
            kes_core::cbor::Error::InvalidUtf8 => Self::InvalidUtf8,
            kes_core::cbor::Error::TrailingBytes => Self::TrailingBytes,
            kes_core::cbor::Error::MissingField => Self::MissingField,
            kes_core::cbor::Error::BufferTooSmall => Self::BufferTooSmall,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorScope {
    Device,
    Pool,
}
impl ErrorScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::Pool => "pool",
        }
    }
    pub fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "device" => Ok(Self::Device),
            "pool" => Ok(Self::Pool),
            _ => Err(Error::InvalidValue),
        }
    }
}
impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
