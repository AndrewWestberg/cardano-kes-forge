#![no_std]
#![deny(unsafe_code)]

pub mod development;
#[cfg(not(feature = "release"))]
#[path = "development/directory.rs"]
pub mod development_directory;
#[cfg(not(feature = "release"))]
#[path = "development/identity.rs"]
pub mod development_identity;
pub mod entropy;
// The sole handwritten unsafe boundary is the RAM-resident RP2350 QMI read.
#[allow(unsafe_code)]
mod flash_identification;
pub mod pool_service;
pub mod recovery;
pub mod scheduler;
pub mod security;

pub mod storage;

pub mod usb;
pub mod update;
#[cfg(not(target_arch = "arm"))]
compile_error!("kes-firmware requires the thumbv8m.main-none-eabihf target");
#[cfg(not(target_os = "none"))]
compile_error!("kes-firmware requires a bare-metal target");
#[cfg(not(any(
    feature = "development",
    feature = "release",
    feature = "usb-preflight",
    feature = "a2-development",
    feature = "a2-entropy-diagnostic"
)))]
compile_error!(
    "select one firmware mode: development, release, usb-preflight, a2-development, or a2-entropy-diagnostic"
);
#[cfg(any(
    all(
        feature = "development",
        any(
            feature = "release",
            feature = "usb-preflight",
            feature = "a2-development",
            feature = "a2-entropy-diagnostic"
        )
    ),
    all(
        feature = "release",
        any(
            feature = "usb-preflight",
            feature = "a2-development",
            feature = "a2-entropy-diagnostic"
        )
    ),
    all(
        feature = "usb-preflight",
        any(feature = "a2-development", feature = "a2-entropy-diagnostic")
    ),
    all(feature = "a2-development", feature = "a2-entropy-diagnostic")
))]
compile_error!("firmware modes are mutually exclusive");

pub const DEVELOPMENT: bool = cfg!(feature = "development");
pub const RELEASE: bool = cfg!(feature = "release");
pub const A2_DEVELOPMENT: bool = cfg!(feature = "a2-development");
pub const USB_PREFLIGHT: bool = cfg!(feature = "usb-preflight");
pub const A2_ENTROPY_DIAGNOSTIC: bool = cfg!(feature = "a2-entropy-diagnostic");
pub const KES_RAM_LIMIT_BYTES: usize = kes_core::KES_RAM_LIMIT_BYTES;
pub const ACTIVE_CACHE_BUDGET_BYTES: usize = 151_552;
pub const DEVICE_FRAME_STORAGE_BYTES: usize = 3 * kes_protocol::MAX_FRAME_BYTES;
pub const SESSION_RECORD_BUDGET_BYTES: usize = 8_448;
pub const HOT_POOL_METADATA_BUDGET_BYTES: usize = 8_192;
pub const DISPATCH_METADATA_BUDGET_BYTES: usize = 4_096;
pub const SHARED_CRYPTO_WORKSPACE_BUDGET_BYTES: usize = 32_768;
pub const JOURNAL_WORKSPACE_BUDGET_BYTES: usize = 8_192;
pub const COMBINED_STACK_BUDGET_BYTES: usize = 16_384;
pub const UNALLOCATED_KES_MARGIN_BYTES: usize = 7_936;
pub const FLASH_RESERVATION_BYTES: usize = storage::FLASH_RESERVATION_BYTES;
pub const POOL_REGION_BYTES: usize = storage::POOL_REGION_BYTES;

const _: () = assert!(DEVICE_FRAME_STORAGE_BYTES == 24_576);
const _: () = assert!(kes_core::session::MAX_SESSIONS == 33);
const _: () = assert!(
    ACTIVE_CACHE_BUDGET_BYTES
        + DEVICE_FRAME_STORAGE_BYTES
        + SESSION_RECORD_BUDGET_BYTES
        + HOT_POOL_METADATA_BUDGET_BYTES
        + DISPATCH_METADATA_BUDGET_BYTES
        + SHARED_CRYPTO_WORKSPACE_BUDGET_BYTES
        + JOURNAL_WORKSPACE_BUDGET_BYTES
        + COMBINED_STACK_BUDGET_BYTES
        + UNALLOCATED_KES_MARGIN_BYTES
        == KES_RAM_LIMIT_BYTES
);
