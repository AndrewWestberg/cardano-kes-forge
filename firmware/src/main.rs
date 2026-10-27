#![no_main]
#![no_std]
#![forbid(unsafe_code)]

#[cfg(any(feature = "development", feature = "release"))]
use core::cell::RefCell;
use core::panic::PanicInfo;

use cortex_m_rt::entry;
#[cfg(any(feature = "development", feature = "release"))]
use embassy_rp::flash::Flash as HalFlash;
#[cfg(any(feature = "development", feature = "release"))]
use embassy_sync::blocking_mutex::{Mutex, raw::ThreadModeRawMutex};
#[cfg(feature = "development")]
use kes_core::types::DeviceId;
#[cfg(feature = "development")]
use kes_firmware::{entropy::EntropyError, security::gateway::GatewayError};
#[cfg(any(feature = "development", feature = "release"))]
use kes_firmware::{
    entropy::HealthCheckedEntropy, security::gateway::DeviceKeys, storage::FittedFlash,
    usb::UsbDispatcher,
};

#[cfg(any(feature = "development", feature = "release"))]
struct Runtime<'d> {
    _flash: FittedFlash<'d>,
    _entropy: HealthCheckedEntropy<'d>,
    _keys: DeviceKeys,
}

// Frame storage is static, not charged to either core's bounded stack. Only
// core0 thread mode may enter this owner; interrupt handlers and core1 do not.
#[cfg(any(feature = "development", feature = "release"))]
static USB_DISPATCHER: Mutex<ThreadModeRawMutex, RefCell<UsbDispatcher>> =
    Mutex::new(RefCell::new(UsbDispatcher::new()));

#[cfg(any(feature = "development", feature = "release"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BootError {
    #[cfg(feature = "development")]
    Entropy,
    #[cfg(feature = "development")]
    Gateway,
    #[cfg(feature = "development")]
    Identity,
    #[cfg(feature = "release")]
    SecurityNotReady,
}

#[cfg(feature = "development")]
#[cfg(any(feature = "development", feature = "release"))]
impl From<EntropyError> for BootError {
    fn from(_: EntropyError) -> Self {
        Self::Entropy
    }
}

#[cfg(feature = "development")]
#[cfg(any(feature = "development", feature = "release"))]
impl From<GatewayError> for BootError {
    fn from(_: GatewayError) -> Self {
        Self::Gateway
    }
}

#[cfg(any(feature = "development", feature = "release"))]
#[entry]
fn main() -> ! {
    let peripherals = embassy_rp::init(Default::default());
    let flash = HalFlash::new_blocking(peripherals.FLASH);
    let fitted = match FittedFlash::new(flash) {
        Ok(fitted) => fitted,
        Err(_) => fail_stop(),
    };
    let entropy = match HealthCheckedEntropy::new(peripherals.TRNG) {
        Ok(entropy) => entropy,
        Err(_) => fail_stop(),
    };
    #[cfg(feature = "development")]
    let runtime = boot_development(fitted, entropy);
    #[cfg(feature = "release")]
    let runtime = boot_release(fitted, entropy);

    let mut runtime = match runtime {
        Ok(runtime) => runtime,
        Err(_) => fail_stop(),
    };
    loop {
        core::hint::black_box(&mut runtime);
        core::hint::black_box(&USB_DISPATCHER);
        core::hint::spin_loop();
    }
}

#[cfg(feature = "development")]
#[cfg(any(feature = "development", feature = "release"))]
fn boot_development<'d>(
    flash: FittedFlash<'d>,
    mut entropy: HealthCheckedEntropy<'d>,
) -> Result<Runtime<'d>, BootError> {
    // Development identity and root are fresh on every boot: disposable and
    // explicitly unsuitable for enrollment or production custody.
    let device = DeviceId::random(&mut entropy).map_err(|_| BootError::Identity)?;
    let root = entropy.root_bytes()?;
    let keys = DeviceKeys::derive(device, root)?;
    Ok(Runtime {
        _flash: flash,
        _entropy: entropy,
        _keys: keys,
    })
}

#[cfg(feature = "release")]
#[cfg(any(feature = "development", feature = "release"))]
fn boot_release<'d>(
    _flash: FittedFlash<'d>,
    _entropy: HealthCheckedEntropy<'d>,
) -> Result<Runtime<'d>, BootError> {
    // Release startup never substitutes an ephemeral root. T041 supplies the
    // reviewed OTP layout, lock/readback policy and release-readiness evidence.
    Err(BootError::SecurityNotReady)
}

#[cfg(not(any(feature = "development", feature = "release")))]
#[entry]
fn main() -> ! {
    // A2/preflight images have their own entrypoints; this generic binary must
    // still link (do nothing) if the workspace builds every default target.
    // Keep the RP2350 PAC linked so cortex-m-rt finds its interrupt vector table.
    core::hint::black_box(rp_pac::NVIC_PRIO_BITS);
    fail_stop()
}

fn fail_stop() -> ! {
    loop {
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    fail_stop()
}
