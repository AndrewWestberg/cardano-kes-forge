#![no_main]
#![no_std]
#![forbid(unsafe_code)]

use core::{cell::RefCell, panic::PanicInfo};

use cortex_m_rt::entry;
use embassy_futures::{block_on, join::join};
use embassy_rp::{
    bind_interrupts, peripherals,
    usb::{Driver, InterruptHandler},
};
use embassy_sync::blocking_mutex::{Mutex, raw::ThreadModeRawMutex};
use embassy_usb::{
    Builder, Config, UsbVersion,
    driver::{EndpointError, EndpointIn, EndpointOut},
};
use kes_core::{
    session::{DeviceHpkeKey, DeviceIdentityKey},
    types::DeviceId,
};
use kes_firmware::{
    development::{DevelopmentEvidence, DevelopmentHandler},
    entropy::{EntropyError, HealthCheckedEntropy},
    usb::{ReceiveStatus, ResponseFrame, UsbDispatcher},
};
use kes_protocol::MAX_FRAME_BYTES;
use rp_pac as pac;

// Unallocated prototype identifiers. This image is development-only and MUST
// never be distributed as a product USB identity.
const PROTOTYPE_VID: u16 = 0xcafe;
const PROTOTYPE_PID: u16 = 0x4b45;
const PACKET_BYTES: usize = 64;
const QUALIFICATION_MACHINE_KEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
const DEVELOPMENT_POLICY_DIGEST: [u8; 32] = [
    0xa6, 0x22, 0x83, 0xc6, 0xd4, 0x21, 0x01, 0x29, 0xcf, 0x6f, 0x26, 0x8f, 0x61, 0x15, 0x0a, 0x23,
    0xc6, 0xf3, 0x2e, 0x60, 0x2c, 0xa9, 0x6f, 0x3c, 0x3d, 0x8c, 0x93, 0xec, 0x3a, 0xf2, 0x0f, 0xf2,
];
const CAPABILITY_EVIDENCE: &[u8] = b"rp2350-a2;development;otp=untouched;\
    persistence=none;firmware-digest=unmeasured;entropy=health-checked-a2-exploratory;\
    session-entropy=fresh-per-open";

bind_interrupts!(struct Irqs {
    USBCTRL_IRQ => InterruptHandler<peripherals::USB>;
});

type A2Handler = DevelopmentHandler<HealthCheckedEntropy<'static>>;

#[allow(clippy::large_enum_variant)]
#[repr(u8)]
enum HandlerSlot {
    Empty,
    Active(A2Handler),
}

struct State {
    dispatcher: UsbDispatcher,
    handler: HandlerSlot,
    response: [u8; MAX_FRAME_BYTES],
}

impl State {
    const fn new() -> Self {
        Self {
            dispatcher: UsbDispatcher::new(),
            handler: HandlerSlot::Empty,
            response: [0; MAX_FRAME_BYTES],
        }
    }

    fn dispatch(&mut self, now_ms: u64) -> Option<ResponseFrame> {
        let HandlerSlot::Active(handler) = &mut self.handler else {
            return None;
        };
        self.dispatcher
            .dispatch(now_ms, &mut self.response, handler)
            .ok()
    }
}

static STATE: Mutex<ThreadModeRawMutex, RefCell<State>> = Mutex::new(RefCell::new(State::new()));

fn with_state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    STATE.lock(|state| f(&mut state.borrow_mut()))
}

#[entry]
fn main() -> ! {
    let peripherals = embassy_rp::init(Default::default());
    let handler = match boot_handler(peripherals.TRNG) {
        Ok(handler) => handler,
        Err(_) => fail_stop(),
    };
    with_state(|state| state.handler = HandlerSlot::Active(handler));

    let driver = Driver::new(peripherals.USB, Irqs);
    let mut config = Config::new(PROTOTYPE_VID, PROTOTYPE_PID);
    config.bcd_usb = UsbVersion::Two;
    config.device_class = 0;
    config.device_sub_class = 0;
    config.device_protocol = 0;
    config.composite_with_iads = false;
    config.manufacturer = Some("KES Forge development");
    config.product = Some("KES authenticated A2 development");
    config.serial_number = Some("A2-AUTH-DEVELOPMENT");

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

    let _ = block_on(join(usb.run(), serve(out_endpoint, in_endpoint)));
    fail_stop()
}

fn boot_handler(
    trng: embassy_rp::Peri<'static, peripherals::TRNG>,
) -> Result<A2Handler, EntropyError> {
    let mut entropy = HealthCheckedEntropy::new(trng)?;
    let device_entropy = entropy.root_bytes()?;
    let mut device_bytes = [0; 16];
    device_bytes.copy_from_slice(&device_entropy[..16]);
    let device = DeviceId::from_bytes(device_bytes);
    let identity = DeviceIdentityKey::from_seed(entropy.root_bytes()?);
    let hpke = DeviceHpkeKey::from_seed(entropy.root_bytes()?);
    let boot_nonce = *entropy.root_bytes()?;
    let evidence = DevelopmentEvidence {
        // Zero is an explicit unmeasured sentinel for this disposable image.
        firmware_digest: [0; 32],
        hardware_policy_digest: DEVELOPMENT_POLICY_DIGEST,
        security_version: 0,
        capability_evidence: CAPABILITY_EVIDENCE,
    };
    Ok(DevelopmentHandler::new(
        device,
        identity,
        hpke,
        boot_nonce,
        QUALIFICATION_MACHINE_KEY,
        entropy,
        evidence,
    )
    .with_completion_clock(monotonic_ms))
}

async fn serve(mut out_endpoint: impl EndpointOut, mut in_endpoint: impl EndpointIn) -> ! {
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
            let now_ms = monotonic_ms();
            let ready = with_state(|state| {
                state
                    .dispatcher
                    .receive(&packet[..length], now_ms)
                    .ok()
                    .is_some_and(|progress| {
                        progress.consumed == length && progress.status == ReceiveStatus::Ready
                    })
            });
            if !ready {
                continue;
            }
            let frame = with_state(|state| state.dispatch(now_ms));
            let Some(frame) = frame else {
                continue;
            };
            if in_endpoint.write(&frame.prefix).await.is_err() {
                continue 'connection;
            }
            let mut offset = 0;
            while offset < frame.body_length {
                let packet_length = (frame.body_length - offset).min(PACKET_BYTES);
                with_state(|state| {
                    packet[..packet_length]
                        .copy_from_slice(&state.response[offset..offset + packet_length]);
                });
                if in_endpoint.write(&packet[..packet_length]).await.is_err() {
                    continue 'connection;
                }
                offset += packet_length;
            }
            if frame.body_length.is_multiple_of(PACKET_BYTES)
                && in_endpoint.write(&[]).await.is_err()
            {
                continue 'connection;
            }
            with_state(|state| state.response[..frame.body_length].fill(0));
        }
    }
}

fn monotonic_ms() -> u64 {
    loop {
        let high = pac::TIMER0.timerawh().read();
        let low = pac::TIMER0.timerawl().read();
        if high == pac::TIMER0.timerawh().read() {
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
