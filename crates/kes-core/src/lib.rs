#![no_std]
#![forbid(unsafe_code)]

pub mod activation;
pub mod backup;
pub mod cbor;
pub mod certificate;
pub mod credentials;
pub mod crypto;
pub mod deletion;
pub mod directory;
pub mod generation;
pub mod journal;
pub mod management;
pub mod recipient;
pub mod retirement;
pub mod rotation;
pub mod session;
pub mod signing;
pub mod state;
pub mod types;

pub const MAX_POOLS: usize = 32;
pub const MAX_GENERATIONS_PER_POOL: usize = 2;
pub const KES_PERIODS: u8 = 64;
pub const VERIFICATION_KEY_BYTES: usize = 32;
pub const SIGNATURE_BYTES: usize = 448;
pub const SIGNING_STATE_BYTES: usize = 608;
pub const PUBLIC_TREE_BYTES: usize = 4064;
pub const KES_RAM_LIMIT_BYTES: usize = 256 * 1024;
pub const MIN_FREE_SRAM_BYTES: usize = 32 * 1024;
