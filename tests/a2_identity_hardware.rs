use cardano_kes_forge::host::{client::DeviceWire, usb::UsbWire};
use kes_protocol::MAX_FRAME_BYTES;
use nusb::MaybeFuture;
use std::time::Duration;

const SELECTOR: &str = "vid=cafe,pid=4b45,serial=A2-IDENTITY-INITIALIZER";
const READ: &[u8] = b"KES-A2-IDENTITY/v1:READ-PUBLIC";
const INITIALIZE: &[u8] = b"KES-A2-IDENTITY/v1:INITIALIZE-DISPOSABLE";
const PUBLIC: &[u8] = b"KES-A2-IDENTITY/v1:PUBLIC:";
const UNINITIALIZED: &[u8] = b"KES-A2-IDENTITY/v1:ERROR:UNINITIALIZED";
const ALREADY: &[u8] = b"KES-A2-IDENTITY/v1:ERROR:ALREADY_INITIALIZED";

fn exchange(wire: &mut UsbWire, request: &[u8]) -> Vec<u8> {
    let mut output = [0; MAX_FRAME_BYTES];
    let length = wire
        .exchange(request, &mut output, Duration::from_secs(15))
        .unwrap();
    output[..length].to_vec()
}

#[test]
#[ignore = "writes disposable A2 identity flash; requires explicit authorization and initializer image"]
fn authorized_disposable_identity_is_initialized_once_and_read_back() {
    assert_eq!(
        std::env::var("KES_A2_AUTHORIZE_DISPOSABLE_IDENTITY_INITIALIZATION").as_deref(),
        Ok("yes"),
        "explicit disposable identity initialization authorization is required"
    );
    let mut wire = UsbWire::open(SELECTOR).unwrap();
    assert_eq!(exchange(&mut wire, READ), UNINITIALIZED);
    assert_eq!(
        exchange(&mut wire, b"KES-A2-IDENTITY/v1:INITIALIZE"),
        b"KES-A2-IDENTITY/v1:ERROR:INVALID_REQUEST"
    );
    assert_eq!(exchange(&mut wire, READ), UNINITIALIZED);
    let public = exchange(&mut wire, INITIALIZE);
    assert_eq!(public.len(), PUBLIC.len() + 16 + 32 + 32);
    assert!(public.starts_with(PUBLIC));
    assert_eq!(exchange(&mut wire, READ), public);
    assert_eq!(exchange(&mut wire, INITIALIZE), ALREADY);
    drop(wire);
    let device = nusb::list_devices()
        .wait()
        .unwrap()
        .find(|device| {
            device.vendor_id() == 0xcafe
                && device.product_id() == 0x4b45
                && device.serial_number() == Some("A2-IDENTITY-INITIALIZER")
        })
        .unwrap()
        .open()
        .wait()
        .unwrap();
    device.reset().wait().unwrap();
    drop(device);
    std::thread::sleep(Duration::from_millis(200));
    let mut wire = UsbWire::open(SELECTOR).unwrap();
    assert_eq!(exchange(&mut wire, READ), public);
}

#[test]
#[ignore = "reboots the disposable A2 initializer into BOOTSEL"]
fn disposable_initializer_can_return_to_bootsel() {
    let mut wire = UsbWire::open(SELECTOR).unwrap();
    assert_eq!(
        exchange(&mut wire, b"KES-A2-IDENTITY/v1:REBOOT-BOOTSEL"),
        b"KES-A2-IDENTITY/v1:REBOOTING"
    );
}
