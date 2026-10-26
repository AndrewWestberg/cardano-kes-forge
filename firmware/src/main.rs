#![no_main]
#![no_std]
#![forbid(unsafe_code)]

use core::{cell::RefCell, panic::PanicInfo};

use cortex_m_rt::entry;
use embassy_rp::flash::Flash as HalFlash;
use embassy_sync::blocking_mutex::{Mutex, raw::ThreadModeRawMutex};
#[cfg(feature = "development")]
use kes_core::types::DeviceId;
#[cfg(feature = "development")]
use kes_firmware::{entropy::EntropyError, security::gateway::GatewayError};
use kes_firmware::{
    entropy::HealthCheckedEntropy, security::gateway::DeviceKeys, storage::FittedFlash,
    usb::UsbDispatcher,
};
use rp_pac as pac;

struct Runtime<'d> {
    _flash: FittedFlash<'d>,
    _entropy: HealthCheckedEntropy<'d>,
    _keys: DeviceKeys,
}

// Frame storage is static, not charged to either core's bounded stack. Only
// core0 thread mode may enter this owner; interrupt handlers and core1 do not.
static USB_DISPATCHER: Mutex<ThreadModeRawMutex, RefCell<UsbDispatcher>> =
    Mutex::new(RefCell::new(UsbDispatcher::new()));

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
impl From<EntropyError> for BootError {
    fn from(_: EntropyError) -> Self {
        Self::Entropy
    }
}

#[cfg(feature = "development")]
impl From<GatewayError> for BootError {
    fn from(_: GatewayError) -> Self {
        Self::Gateway
    }
}

#[entry]
fn main() -> ! {
    let peripherals = embassy_rp::init(Default::default());
    let flash_devinfo = u32::from(pac::OTP_DATA.flash_devinfo().read().0);
    let flash = HalFlash::new_blocking(peripherals.FLASH);
    let fitted = match FittedFlash::new(flash, flash_devinfo) {
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
fn boot_release<'d>(
    _flash: FittedFlash<'d>,
    _entropy: HealthCheckedEntropy<'d>,
) -> Result<Runtime<'d>, BootError> {
    // Release startup never substitutes an ephemeral root. T041 supplies the
    // reviewed OTP layout, lock/readback policy and release-readiness evidence.
    Err(BootError::SecurityNotReady)
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
