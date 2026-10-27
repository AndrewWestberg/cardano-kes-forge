#![no_main]
#![no_std]
#![forbid(unsafe_code)]

use core::{cell::RefCell, panic::PanicInfo};

use cortex_m_rt::entry;
use embassy_futures::{block_on, join::join};
use embassy_rp::{
    bind_interrupts,
    flash::Flash as HalFlash,
    peripherals,
    usb::{Driver, InterruptHandler},
};
use embassy_sync::blocking_mutex::{Mutex, raw::ThreadModeRawMutex};
use embassy_usb::{
    Builder, Config, UsbVersion,
    driver::{EndpointError, EndpointIn, EndpointOut},
};
use kes_core::journal::{JournalWorkspace, ObjectWorkspace, SecretCache, Workspaces};
use kes_core::session::{DeviceHpkeKey, DeviceIdentityKey};
use kes_firmware::{
    development_directory::{self, ProvisionError},
    development_identity::{
        self as identity, DisposableIdentity, IdentityError, InitializationAuthorization,
    },
    entropy::HealthCheckedEntropy,
    storage::{FittedFlash, IdentificationError, StorageError},
};
use kes_protocol::{MAX_FRAME_BYTES, ReceiverState};
use zeroize::Zeroizing;

const PACKET_BYTES: usize = 64;
const INITIALIZE: &[u8] = b"KES-A2-IDENTITY/v1:INITIALIZE-DISPOSABLE";
const READ: &[u8] = b"KES-A2-IDENTITY/v1:READ-PUBLIC";
const PUBLIC: &[u8] = b"KES-A2-IDENTITY/v1:PUBLIC:";
const REBOOT_BOOTSEL: &[u8] = b"KES-A2-IDENTITY/v1:REBOOT-BOOTSEL";
const REBOOTING: &[u8] = b"KES-A2-IDENTITY/v1:REBOOTING";
const PROVISION_DIRECTORY: &[u8] = b"KES-A2-IDENTITY/v1:PROVISION-DISPOSABLE-DIRECTORY:";
const DIRECTORY_PUBLIC: &[u8] = b"KES-A2-IDENTITY/v1:DIRECTORY-PUBLIC:";

bind_interrupts!(struct Irqs { USBCTRL_IRQ => InterruptHandler<peripherals::USB>; });

struct State {
    flash_peripheral: Option<embassy_rp::Peri<'static, peripherals::FLASH>>,
    trng_peripheral: Option<embassy_rp::Peri<'static, peripherals::TRNG>>,
    hardware_error: Option<&'static [u8]>,
    observed_profile: Option<([u8; 3], [u8; 16], u32)>,
    flash: Option<FittedFlash<'static>>,
    entropy: Option<HealthCheckedEntropy<'static>>,
    receiver: ReceiverState,
    request: [u8; MAX_FRAME_BYTES],
    response: [u8; MAX_FRAME_BYTES],
    reboot_requested: bool,
    journal_workspace: Option<JournalWorkspace>,
    object_workspace: Option<ObjectWorkspace>,
    secret_cache: Option<SecretCache>,
}

impl State {
    const fn new() -> Self {
        Self {
            flash_peripheral: None,
            trng_peripheral: None,
            hardware_error: None,
            observed_profile: None,
            flash: None,
            entropy: None,
            receiver: ReceiverState::new(),
            request: [0; MAX_FRAME_BYTES],
            reboot_requested: false,
            response: [0; MAX_FRAME_BYTES],
            journal_workspace: None,
            object_workspace: None,
            secret_cache: None,
        }
    }

    fn prepare_hardware(&mut self, need_entropy: bool) -> Result<(), &'static [u8]> {
        if let Some(error) = self.hardware_error {
            return Err(error);
        }
        if self.flash.is_none() {
            let peripheral = self
                .flash_peripheral
                .take()
                .ok_or(b"FLASH_STATE" as &[u8])?;
            match FittedFlash::new(HalFlash::new_blocking(peripheral)) {
                Ok(flash) => self.flash = Some(flash),
                Err(error) => {
                    let code: &'static [u8] = match error {
                        StorageError::WrongCore => b"FLASH_CORE",
                        StorageError::WrongFlashProfile {
                            jedec_id,
                            sfdp_header,
                            density_bits_minus_one,
                        } => {
                            self.observed_profile =
                                Some((jedec_id, sfdp_header, density_bits_minus_one));
                            b"FLASH_PROFILE"
                        }
                        StorageError::FlashIdentification(IdentificationError::Busy) => {
                            b"FLASH_IDENTIFICATION_BUSY"
                        }
                        StorageError::FlashIdentification(IdentificationError::UnsupportedBus) => {
                            b"FLASH_IDENTIFICATION_UNSUPPORTED_BUS"
                        }
                        StorageError::FlashIdentification(IdentificationError::MissingRomData) => {
                            b"FLASH_IDENTIFICATION_ROM"
                        }
                        StorageError::FlashIdentification(IdentificationError::Timeout) => {
                            b"FLASH_IDENTIFICATION_TIMEOUT"
                        }
                        _ => b"FLASH_INIT",
                    };
                    self.hardware_error = Some(code);
                    return Err(code);
                }
            }
        }
        if need_entropy && self.entropy.is_none() {
            let peripheral = self
                .trng_peripheral
                .take()
                .ok_or(b"ENTROPY_STATE" as &[u8])?;
            match HealthCheckedEntropy::new(peripheral) {
                Ok(entropy) => self.entropy = Some(entropy),
                Err(_) => {
                    self.hardware_error = Some(b"ENTROPY_CONFIGURATION");
                    return Err(b"ENTROPY_CONFIGURATION");
                }
            }
        }
        Ok(())
    }

    fn receive(&mut self, packet: &[u8], now_ms: u64) -> Option<usize> {
        let consumed = match self.receiver.push(&mut self.request, packet, now_ms) {
            Ok(consumed) => consumed,
            Err(_) => {
                self.reset();
                return None;
            }
        };
        if consumed != packet.len() {
            self.reset();
            return None;
        }
        let request = self.receiver.complete(&self.request)?;
        let initialize = request == INITIALIZE;
        let read = request == READ;
        let reboot = request == REBOOT_BOOTSEL;
        let provision_keys = request.strip_prefix(PROVISION_DIRECTORY).and_then(|bytes| {
            if bytes.len() != 64 {
                return None;
            }
            let mut root = [0; 32];
            let mut transport = [0; 32];
            root.copy_from_slice(&bytes[..32]);
            transport.copy_from_slice(&bytes[32..]);
            Some((root, transport))
        });
        self.receiver.reset();
        self.request.fill(0);
        if reboot {
            self.reboot_requested = true;
            self.response[..REBOOTING.len()].copy_from_slice(REBOOTING);
            return Some(REBOOTING.len());
        }
        if !initialize && !read && provision_keys.is_none() {
            return Some(self.error(b"INVALID_REQUEST"));
        }
        if let Err(code) = self.prepare_hardware(initialize || provision_keys.is_some()) {
            return Some(self.error(code));
        }
        if let Some((root, transport)) = provision_keys {
            return Some(self.provision_directory(root, transport));
        }
        let result = match self
            .flash
            .as_mut()
            .expect("initialized flash")
            .development_identity()
        {
            Ok(mut flash) => {
                if initialize {
                    identity::initialize_disposable(
                        &mut flash,
                        self.entropy.as_mut().expect("initialized entropy"),
                        InitializationAuthorization::IsolatedDisposableDevelopment,
                    )
                } else {
                    identity::recover(&mut flash)
                }
            }
            Err(_) => return Some(self.error(b"FLASH")),
        };
        Some(match result {
            Ok(identity) => self.public(identity),
            Err(IdentityError::Uninitialized) => self.error(b"UNINITIALIZED"),
            Err(IdentityError::ExistingJournalData) => self.error(b"EXISTING_JOURNALS"),
            Err(IdentityError::AlreadyInitialized) => self.error(b"ALREADY_INITIALIZED"),
            Err(IdentityError::CorruptOrInterrupted) => self.error(b"CORRUPT_OR_INTERRUPTED"),
            Err(IdentityError::Entropy) => self.error(b"ENTROPY"),
            Err(IdentityError::Flash(_)) => self.error(b"FLASH"),
        })
    }

    fn provision_directory(&mut self, root: [u8; 32], transport: [u8; 32]) -> usize {
        let journal = self
            .journal_workspace
            .get_or_insert_with(JournalWorkspace::new);
        let object = self
            .object_workspace
            .get_or_insert_with(ObjectWorkspace::new);
        let cache = self.secret_cache.get_or_insert_with(SecretCache::new);
        let result = development_directory::provision_disposable(
            self.flash.as_mut().expect("initialized flash"),
            self.entropy.as_mut().expect("initialized entropy"),
            root,
            transport,
            InitializationAuthorization::IsolatedDisposableDevelopment,
            &mut Workspaces {
                journal,
                object,
                cache,
            },
        );
        match result {
            Ok(config) => {
                let mut offset = 0;
                for bytes in [
                    DIRECTORY_PUBLIC,
                    config.identity.device_id().as_bytes(),
                    config.identity.identity_verification_key(),
                    &config.management_root_public_key,
                    &config.management_transport_public_key,
                ] {
                    self.response[offset..offset + bytes.len()].copy_from_slice(bytes);
                    offset += bytes.len();
                }
                offset
            }
            Err(error) => self.error(match error {
                ProvisionError::IdentityUninitialized => b"UNINITIALIZED",
                ProvisionError::IdentityDamaged => b"CORRUPT_OR_INTERRUPTED",
                ProvisionError::InvalidPublicKey => b"DIRECTORY_INVALID_PUBLIC_KEY",
                ProvisionError::AlreadyInitialized => b"DIRECTORY_ALREADY_INITIALIZED",
                ProvisionError::Nonblank => b"DIRECTORY_NONBLANK",
                ProvisionError::Damaged => b"DIRECTORY_DAMAGED",
                ProvisionError::Entropy => b"ENTROPY",
                ProvisionError::Flash => b"FLASH",
                ProvisionError::KeyDerivation => b"KEY_DERIVATION",
            }),
        }
    }

    fn public(&mut self, identity: DisposableIdentity) -> usize {
        let device = identity.device();
        let keys = match identity.into_keys() {
            Ok(keys) => keys,
            Err(_) => return self.error(b"KEY_DERIVATION"),
        };
        let identity_key = DeviceIdentityKey::from_seed(Zeroizing::new(*keys.identity_seed()));
        let hpke = DeviceHpkeKey::from_seed(Zeroizing::new(*keys.session_root()));
        let mut offset = 0;
        for bytes in [
            PUBLIC,
            device.as_bytes(),
            &identity_key.verification_key(),
            &hpke.public_key(),
        ] {
            self.response[offset..offset + bytes.len()].copy_from_slice(bytes);
            offset += bytes.len();
        }
        offset
    }

    fn error(&mut self, code: &[u8]) -> usize {
        const PREFIX: &[u8] = b"KES-A2-IDENTITY/v1:ERROR:";
        self.response[..PREFIX.len()].copy_from_slice(PREFIX);
        self.response[PREFIX.len()..PREFIX.len() + code.len()].copy_from_slice(code);
        let mut offset = PREFIX.len() + code.len();
        if code == b"FLASH_PROFILE"
            && let Some((jedec, header, density)) = self.observed_profile
        {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            for bytes in [&jedec[..], &header[..], &density.to_be_bytes()[..]] {
                self.response[offset] = b':';
                offset += 1;
                for byte in bytes {
                    self.response[offset] = HEX[usize::from(byte >> 4)];
                    self.response[offset + 1] = HEX[usize::from(byte & 0x0f)];
                    offset += 2;
                }
            }
        }
        offset
    }

    fn reset(&mut self) {
        self.receiver.reset();
        self.request.fill(0);
        self.reboot_requested = false;
    }
}

static STATE: Mutex<ThreadModeRawMutex, RefCell<State>> = Mutex::new(RefCell::new(State::new()));

fn with_state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    STATE.lock(|state| f(&mut state.borrow_mut()))
}

#[entry]
fn main() -> ! {
    let peripherals = embassy_rp::init(Default::default());
    // Start USB before probing storage/TRNG so a bounded public diagnostic is
    // available if initialization fails. Neither peripheral is touched here.
    with_state(|state| {
        state.flash_peripheral = Some(peripherals.FLASH);
        state.trng_peripheral = Some(peripherals.TRNG);
    });

    let driver = Driver::new(peripherals.USB, Irqs);
    let mut config = Config::new(0xcafe, 0x4b45);
    config.bcd_usb = UsbVersion::Two;
    config.device_class = 0;
    config.device_sub_class = 0;
    config.device_protocol = 0;
    config.composite_with_iads = false;
    config.manufacturer = Some("KES Forge development");
    config.product = Some("KES A2 identity initializer");
    config.serial_number = Some("A2-IDENTITY-INITIALIZER");
    let mut config_descriptor = [0; 64];
    let mut bos_descriptor = [0; 16];
    let mut msos_descriptor = [0; 16];
    let mut control = [0; 128];
    let mut builder = Builder::new(
        driver,
        config,
        &mut config_descriptor,
        &mut bos_descriptor,
        &mut msos_descriptor,
        &mut control,
    );
    let (out, input) = {
        let mut function = builder.function(0xff, 0x4b, 0x01);
        let mut interface = function.interface();
        let mut alternate = interface.alt_setting(0xff, 0x4b, 0x01, None);
        (
            alternate.endpoint_bulk_out(None, PACKET_BYTES as u16),
            alternate.endpoint_bulk_in(None, PACKET_BYTES as u16),
        )
    };
    let mut usb = builder.build();
    let _ = block_on(join(usb.run(), serve(out, input)));
    fail_stop()
}

async fn serve(mut out: impl EndpointOut, mut input: impl EndpointIn) -> ! {
    let mut packet = [0; PACKET_BYTES];
    'connection: loop {
        out.wait_enabled().await;
        input.wait_enabled().await;
        loop {
            let length = match out.read(&mut packet).await {
                Ok(length) => length,
                Err(EndpointError::Disabled) => {
                    with_state(State::reset);
                    continue 'connection;
                }
                Err(EndpointError::BufferOverflow) => fail_stop(),
            };
            let Some(length) = with_state(|state| state.receive(&packet[..length], monotonic_ms()))
            else {
                continue;
            };
            if input.write(&(length as u32).to_be_bytes()).await.is_err() {
                with_state(State::reset);
                continue 'connection;
            }
            let mut offset = 0;
            while offset < length {
                let count = (length - offset).min(PACKET_BYTES);
                with_state(|state| {
                    packet[..count].copy_from_slice(&state.response[offset..offset + count])
                });
                if input.write(&packet[..count]).await.is_err() {
                    with_state(State::reset);
                    continue 'connection;
                }
                offset += count;
            }
            if length.is_multiple_of(PACKET_BYTES) && input.write(&[]).await.is_err() {
                with_state(State::reset);
                continue 'connection;
            }
            with_state(|state| state.response[..length].fill(0));
            if with_state(|state| core::mem::take(&mut state.reboot_requested)) {
                // This explicitly disposable diagnostic image supports a remote
                // return to BOOTSEL; no OTP or journal contents are changed.
                embassy_rp::rom_data::reset_to_usb_boot(0, 0);
            }
        }
    }
}

fn monotonic_ms() -> u64 {
    loop {
        let high = rp_pac::TIMER0.timerawh().read();
        let low = rp_pac::TIMER0.timerawl().read();
        if high == rp_pac::TIMER0.timerawh().read() {
            return ((u64::from(high) << 32) | u64::from(low)) / 1_000;
        }
    }
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
