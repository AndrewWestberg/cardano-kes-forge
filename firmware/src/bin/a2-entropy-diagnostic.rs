#![no_main]
#![no_std]
#![forbid(unsafe_code)]

use core::{cell::RefCell, panic::PanicInfo};

use cortex_m_rt::entry;
use embassy_futures::{block_on, join::join};
use embassy_rp::{
    Peri, bind_interrupts, peripherals,
    usb::{Driver, InterruptHandler},
};
use embassy_sync::blocking_mutex::{Mutex, raw::ThreadModeRawMutex};
use embassy_usb::{
    Builder, Config, UsbVersion,
    driver::{EndpointError, EndpointIn, EndpointOut},
};
use kes_firmware::entropy::{EntropyError, HealthCheckedEntropy};
use kes_protocol::{Error as ProtocolError, MAX_FRAME_BYTES, ReceiverState};

// Unallocated prototype identifiers. This one-purpose image is never a product
// identity and never writes OTP, flash, keys, or raw entropy to the host.
const PROTOTYPE_VID: u16 = 0xcafe;
const PROTOTYPE_PID: u16 = 0x4b45;
const PACKET_BYTES: usize = 64;
const REQUEST: &[u8] = b"KES-TRNG-DIAGNOSTIC/v1";
const HEALTHY: &[u8] =
    b"KES-TRNG-DIAGNOSTIC/v1:HEALTHY:sample_count=200:inverter=1:blocks=4:distinct=true";
const INVALID: &[u8] = b"KES-TRNG-DIAGNOSTIC/v1:INVALID";

bind_interrupts!(struct Irqs {
    USBCTRL_IRQ => InterruptHandler<peripherals::USB>;
});

#[derive(Clone, Copy, Eq, PartialEq)]
enum Outcome {
    Pending,
    Healthy,
    Latched,
    Timeout,
    Configuration,
    Autocorrelation,
    ContinuousTest,
    VonNeumann,
    Derivation,
    Internal,
    BlockCount,
    ZeroOutput,
    DuplicateOutput,
}

impl Outcome {
    const fn response(self) -> &'static [u8] {
        match self {
            Self::Pending => b"KES-TRNG-DIAGNOSTIC/v1:ERROR:pending",
            Self::Healthy => HEALTHY,
            Self::Latched => b"KES-TRNG-DIAGNOSTIC/v1:ERROR:latched",
            Self::Timeout => b"KES-TRNG-DIAGNOSTIC/v1:ERROR:timeout",
            Self::Configuration => b"KES-TRNG-DIAGNOSTIC/v1:ERROR:configuration",
            Self::Autocorrelation => b"KES-TRNG-DIAGNOSTIC/v1:ERROR:autocorrelation",
            Self::ContinuousTest => b"KES-TRNG-DIAGNOSTIC/v1:ERROR:continuous_test",
            Self::VonNeumann => b"KES-TRNG-DIAGNOSTIC/v1:ERROR:von_neumann",
            Self::Derivation => b"KES-TRNG-DIAGNOSTIC/v1:ERROR:derivation",
            Self::Internal => b"KES-TRNG-DIAGNOSTIC/v1:ERROR:internal",
            Self::BlockCount => b"KES-TRNG-DIAGNOSTIC/v1:ERROR:block_count",
            Self::ZeroOutput => b"KES-TRNG-DIAGNOSTIC/v1:ERROR:zero_output",
            Self::DuplicateOutput => b"KES-TRNG-DIAGNOSTIC/v1:ERROR:duplicate_output",
        }
    }
}

impl From<EntropyError> for Outcome {
    fn from(error: EntropyError) -> Self {
        match error {
            EntropyError::Latched => Self::Latched,
            EntropyError::Timeout => Self::Timeout,
            EntropyError::Configuration => Self::Configuration,
            EntropyError::Autocorrelation => Self::Autocorrelation,
            EntropyError::ContinuousTest => Self::ContinuousTest,
            EntropyError::VonNeumann => Self::VonNeumann,
            EntropyError::Derivation => Self::Derivation,
        }
    }
}

struct Diagnostic<'d> {
    trng: Option<Peri<'d, peripherals::TRNG>>,
    outcome: Outcome,
}

impl<'d> Diagnostic<'d> {
    const fn new(trng: Peri<'d, peripherals::TRNG>) -> Self {
        Self {
            trng: Some(trng),
            outcome: Outcome::Pending,
        }
    }

    fn run_once(&mut self) -> Outcome {
        if self.outcome != Outcome::Pending {
            return self.outcome;
        }
        let Some(trng) = self.trng.take() else {
            self.outcome = Outcome::Internal;
            return self.outcome;
        };
        let mut entropy = match HealthCheckedEntropy::new(trng) {
            Ok(entropy) => entropy,
            Err(error) => {
                self.outcome = error.into();
                return self.outcome;
            }
        };
        let first = match entropy.root_bytes() {
            Ok(bytes) => bytes,
            Err(error) => {
                self.outcome = error.into();
                return self.outcome;
            }
        };
        let second = match entropy.root_bytes() {
            Ok(bytes) => bytes,
            Err(error) => {
                self.outcome = error.into();
                return self.outcome;
            }
        };
        let counters = entropy.counters();
        self.outcome = if counters.successful_blocks != 4 || counters.failures != 0 {
            Outcome::BlockCount
        } else if first.iter().all(|byte| *byte == 0) || second.iter().all(|byte| *byte == 0) {
            Outcome::ZeroOutput
        } else if first == second {
            Outcome::DuplicateOutput
        } else {
            Outcome::Healthy
        };
        self.outcome
    }
}

struct Frames {
    receive: [u8; MAX_FRAME_BYTES],
    response: [u8; MAX_FRAME_BYTES],
    receiver: ReceiverState,
}

impl Frames {
    const fn new() -> Self {
        Self {
            receive: [0; MAX_FRAME_BYTES],
            response: [0; MAX_FRAME_BYTES],
            receiver: ReceiverState::new(),
        }
    }

    fn receive(&mut self, packet: &[u8], now_ms: u64) -> Option<bool> {
        let consumed = match self.receiver.push(&mut self.receive, packet, now_ms) {
            Ok(consumed) => consumed,
            Err(ProtocolError::Timeout) => {
                self.reset();
                match self.receiver.push(&mut self.receive, packet, now_ms) {
                    Ok(consumed) => consumed,
                    Err(_) => {
                        self.reset();
                        return None;
                    }
                }
            }
            Err(_) => {
                self.reset();
                return None;
            }
        };
        if consumed != packet.len() {
            self.reset();
            return None;
        }
        let body = self.receiver.complete(&self.receive)?;
        let valid = body == REQUEST;
        self.reset();
        Some(valid)
    }

    fn set_response(&mut self, response: &[u8]) -> usize {
        self.response[..response.len()].copy_from_slice(response);
        response.len()
    }

    fn reset(&mut self) {
        self.receive.fill(0);
        self.receiver.reset();
    }
}

static FRAMES: Mutex<ThreadModeRawMutex, RefCell<Frames>> = Mutex::new(RefCell::new(Frames::new()));

#[entry]
fn main() -> ! {
    let peripherals = embassy_rp::init(Default::default());
    let driver = Driver::new(peripherals.USB, Irqs);
    let diagnostic = Diagnostic::new(peripherals.TRNG);

    let mut config = Config::new(PROTOTYPE_VID, PROTOTYPE_PID);
    config.bcd_usb = UsbVersion::Two;
    config.device_class = 0;
    config.device_sub_class = 0;
    config.device_protocol = 0;
    config.composite_with_iads = false;
    config.manufacturer = Some("KES Forge development");
    config.product = Some("KES A2 entropy diagnostic");
    config.serial_number = Some("A2-TRNG-DIAGNOSTIC");

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
    let (out_endpoint, in_endpoint) = {
        let mut function = builder.function(0xff, 0x4b, 0x01);
        let mut interface = function.interface();
        let mut alternate = interface.alt_setting(0xff, 0x4b, 0x01, None);
        (
            alternate.endpoint_bulk_out(None, PACKET_BYTES as u16),
            alternate.endpoint_bulk_in(None, PACKET_BYTES as u16),
        )
    };
    let mut usb = builder.build();

    let _ = block_on(join(
        usb.run(),
        serve(out_endpoint, in_endpoint, diagnostic),
    ));
    fail_stop()
}

async fn serve(
    mut out_endpoint: impl EndpointOut,
    mut in_endpoint: impl EndpointIn,
    mut diagnostic: Diagnostic<'_>,
) -> ! {
    let mut packet = [0; PACKET_BYTES];

    'connection: loop {
        out_endpoint.wait_enabled().await;
        in_endpoint.wait_enabled().await;
        loop {
            let length = match out_endpoint.read(&mut packet).await {
                Ok(length) => length,
                Err(EndpointError::Disabled) => continue 'connection,
                Err(EndpointError::BufferOverflow) => fail_stop(),
            };
            let valid = FRAMES.lock(|frames| {
                frames
                    .borrow_mut()
                    .receive(&packet[..length], monotonic_ms())
            });
            let Some(valid) = valid else {
                continue;
            };
            let response = if valid {
                diagnostic.run_once().response()
            } else {
                INVALID
            };
            let response_length = FRAMES.lock(|frames| frames.borrow_mut().set_response(response));
            let prefix = (response_length as u32).to_be_bytes();
            if in_endpoint.write(&prefix).await.is_err() {
                continue 'connection;
            }
            let mut offset = 0;
            while offset < response_length {
                let packet_length = (response_length - offset).min(PACKET_BYTES);
                FRAMES.lock(|frames| {
                    packet[..packet_length]
                        .copy_from_slice(&frames.borrow().response[offset..offset + packet_length]);
                });
                if in_endpoint.write(&packet[..packet_length]).await.is_err() {
                    continue 'connection;
                }
                offset += packet_length;
            }
            if response_length.is_multiple_of(PACKET_BYTES) && in_endpoint.write(&[]).await.is_err()
            {
                continue 'connection;
            }
            FRAMES.lock(|frames| {
                frames.borrow_mut().response[..response_length].fill(0);
            });
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
