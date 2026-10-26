use cardano_kes_forge::host::{
    client::{DeviceWire, Error as ClientError},
    usb::{OpenError, UsbWire},
};
use kes_protocol::{FRAME_TIMEOUT_MS, MAX_FRAME_BYTES};
use nusb::{
    MaybeFuture,
    transfer::{Buffer, Bulk, Out},
};
use std::{thread, time::Duration};

const VID: u16 = 0xcafe;
const PID: u16 = 0x4b45;
const SERIAL_SELECTOR: &str = "vid=cafe,pid=4b45,serial=A2-PREFLIGHT";
const REQUEST: &[u8] = b"KES-USB-PREFLIGHT/v1";
const OK_RESPONSE: &[u8] = b"KES-USB-PREFLIGHT/v1:RP2350-A2:OK";
const INVALID_RESPONSE: &[u8] = b"KES-USB-PREFLIGHT/v1:INVALID";
const TIMEOUT: Duration = Duration::from_secs(2);

fn exchange(wire: &mut UsbWire, request: &[u8], expected: &[u8]) {
    let mut response = [0; MAX_FRAME_BYTES];
    let length = wire.exchange(request, &mut response, TIMEOUT).unwrap();
    assert_eq!(&response[..length], expected);
}

fn selectors() -> [String; 2] {
    let device = nusb::list_devices()
        .wait()
        .unwrap()
        .find(|device| device.vendor_id() == VID && device.product_id() == PID)
        .expect("the disposable KES USB preflight image must be connected");
    let port = device
        .port_chain()
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(".");
    [
        format!(
            "bus={},address={}",
            device.busnum(),
            device.device_address()
        ),
        format!(
            "vid={VID:04x},pid={PID:04x},bus={},port={port}",
            device.busnum()
        ),
    ]
}

fn raw_out(bytes: &[u8]) {
    let device = nusb::list_devices()
        .wait()
        .unwrap()
        .find(|device| device.vendor_id() == VID && device.product_id() == PID)
        .expect("the disposable KES USB preflight image must be connected")
        .open()
        .wait()
        .unwrap();
    let interface = device.claim_interface(0).wait().unwrap();
    let mut endpoint = interface.endpoint::<Bulk, Out>(0x01).unwrap();
    let mut buffer = Buffer::new(bytes.len());
    buffer.extend_from_slice(bytes);
    let completion = endpoint.transfer_blocking(buffer, TIMEOUT);
    assert!(completion.status.is_ok());
    assert_eq!(completion.actual_len, bytes.len());
}

#[test]
#[ignore = "requires the authorized disposable RP2350 A2 USB preflight image"]
fn physical_preflight_exercises_bounds_recovery_and_exclusive_claim() {
    let mut wire = UsbWire::open(SERIAL_SELECTOR).unwrap();
    exchange(&mut wire, REQUEST, OK_RESPONSE);
    exchange(&mut wire, b"not-the-preflight-request", INVALID_RESPONSE);

    for iteration in 0u16..256 {
        let (request, expected): (&[u8], &[u8]) = if iteration.is_multiple_of(2) {
            (REQUEST, OK_RESPONSE)
        } else {
            (b"invalid", INVALID_RESPONSE)
        };
        exchange(&mut wire, request, expected);
    }

    exchange(&mut wire, &[0xa5; MAX_FRAME_BYTES], INVALID_RESPONSE);
    let mut response = [0; MAX_FRAME_BYTES];
    assert!(matches!(
        wire.exchange(&[], &mut response, TIMEOUT),
        Err(ClientError::Unavailable)
    ));
    assert!(matches!(
        wire.exchange(&[0; MAX_FRAME_BYTES + 1], &mut response, TIMEOUT),
        Err(ClientError::Unavailable)
    ));
    assert!(matches!(
        wire.exchange(REQUEST, &mut response, Duration::ZERO),
        Err(ClientError::Unavailable)
    ));
    assert!(matches!(
        UsbWire::open(SERIAL_SELECTOR),
        Err(OpenError::Claim(_))
    ));
    drop(wire);

    for selector in selectors() {
        let mut selected = UsbWire::open(&selector).unwrap();
        exchange(&mut selected, REQUEST, OK_RESPONSE);
    }

    raw_out(&(MAX_FRAME_BYTES as u32 + 1).to_be_bytes());
    exchange(
        &mut UsbWire::open(SERIAL_SELECTOR).unwrap(),
        REQUEST,
        OK_RESPONSE,
    );

    raw_out(&0u32.to_be_bytes());
    exchange(
        &mut UsbWire::open(SERIAL_SELECTOR).unwrap(),
        REQUEST,
        OK_RESPONSE,
    );

    raw_out(&[0, 0, 0, 1, b'x', b'y']);
    exchange(
        &mut UsbWire::open(SERIAL_SELECTOR).unwrap(),
        REQUEST,
        OK_RESPONSE,
    );

    let mut partial = 100u32.to_be_bytes().to_vec();
    partial.extend_from_slice(b"partial");
    raw_out(&partial);
    thread::sleep(Duration::from_millis(u64::from(FRAME_TIMEOUT_MS) + 100));
    exchange(
        &mut UsbWire::open(SERIAL_SELECTOR).unwrap(),
        REQUEST,
        OK_RESPONSE,
    );
}
