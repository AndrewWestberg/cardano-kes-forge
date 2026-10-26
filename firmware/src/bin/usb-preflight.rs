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
use kes_protocol::{Error as ProtocolError, MAX_FRAME_BYTES, ReceiverState};

// Unallocated prototype identifiers, intentionally unsuitable for distribution.
// The product string and protocol response also label this image as preflight-only.
const PROTOTYPE_VID: u16 = 0xcafe;
const PROTOTYPE_PID: u16 = 0x4b45;
const PACKET_BYTES: usize = 64;
const PREFLIGHT_REQUEST: &[u8] = b"KES-USB-PREFLIGHT/v1";
const PREFLIGHT_RESPONSE: &[u8] = b"KES-USB-PREFLIGHT/v1:RP2350-A2:OK";

bind_interrupts!(struct Irqs {
    USBCTRL_IRQ => InterruptHandler<peripherals::USB>;
});

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

    fn receive(&mut self, packet: &[u8], now_ms: u64) -> Option<usize> {
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
        let response = if body == PREFLIGHT_REQUEST {
            PREFLIGHT_RESPONSE
        } else {
            b"KES-USB-PREFLIGHT/v1:INVALID"
        };
        self.response[..response.len()].copy_from_slice(response);
        let length = response.len();
        self.reset();
        Some(length)
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

    let mut config = Config::new(PROTOTYPE_VID, PROTOTYPE_PID);
    config.bcd_usb = UsbVersion::Two;
    config.device_class = 0;
    config.device_sub_class = 0;
    config.device_protocol = 0;
    config.composite_with_iads = false;
    config.manufacturer = Some("KES Forge development");
    config.product = Some("KES USB preflight");
    config.serial_number = Some("A2-PREFLIGHT");

    let mut config_descriptor = [0; 64];
    let mut bos_descriptor = [0; 16];
    let mut msos_descriptor = [0; 16];
    let mut control = [0; 64];
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
            let response_length = FRAMES.lock(|frames| {
                frames
                    .borrow_mut()
                    .receive(&packet[..length], monotonic_ms())
            });
            let Some(response_length) = response_length else {
                continue;
            };
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
            FRAMES.lock(|frames| frames.borrow_mut().response[..response_length].fill(0));
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
