#![no_std]
#![forbid(unsafe_code)]

pub mod backup;
pub mod error;
pub mod frame;
pub mod operations;
pub use error::{Error, ErrorScope, Status};
pub use frame::{Receiver, ReceiverState, decode_frame, encode_frame};
pub use operations::{Envelope, EnvelopeKind, Operation};

pub const VERSION: u8 = 1;
pub const MAX_FRAME_BYTES: usize = kes_core::cbor::MAX_ENCODED_BYTES;
pub const MAX_MESSAGE_BYTES: usize = 4096;
pub const MAX_CERTIFICATE_BYTES: usize = 1024;
pub const MAX_BACKUP_BYTES: usize = 2048;
pub const MAX_NESTING_DEPTH: usize = kes_core::cbor::MAX_NESTING_DEPTH;
pub const MAX_SESSIONS: usize = kes_core::MAX_POOLS + 1;
pub const FRAME_TIMEOUT_MS: u32 = 2000;
pub const SIGNING_BUDGET_MS: u32 = 500;
pub const STATUS_BUDGET_MS: u32 = 2000;
pub const GENERATION_BUDGET_MS: u32 = 600_000;
