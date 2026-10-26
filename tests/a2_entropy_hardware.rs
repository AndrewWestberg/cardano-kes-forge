use cardano_kes_forge::host::{
    client::DeviceWire,
    usb::{OpenError, UsbWire},
};
use kes_protocol::MAX_FRAME_BYTES;
use std::time::Duration;

const SELECTOR: &str = "vid=cafe,pid=4b45,serial=A2-TRNG-DIAGNOSTIC";
const REQUEST: &[u8] = b"KES-TRNG-DIAGNOSTIC/v1";
const HEALTHY: &[u8] =
    b"KES-TRNG-DIAGNOSTIC/v1:HEALTHY:sample_count=200:inverter=1:blocks=4:distinct=true";
const INVALID: &[u8] = b"KES-TRNG-DIAGNOSTIC/v1:INVALID";
const TIMEOUT: Duration = Duration::from_secs(2);

fn exchange(wire: &mut UsbWire, request: &[u8], expected: &[u8]) {
    let mut response = [0; MAX_FRAME_BYTES];
    let length = wire.exchange(request, &mut response, TIMEOUT).unwrap();
    assert_eq!(&response[..length], expected);
}

#[test]
#[ignore = "requires the authorized disposable RP2350 A2 entropy diagnostic image"]
fn health_checked_trng_reports_bounded_public_status_without_sample_bytes() {
    let mut wire = UsbWire::open(SELECTOR).unwrap();
    exchange(&mut wire, REQUEST, HEALTHY);
    exchange(&mut wire, b"not-the-diagnostic-request", INVALID);
    assert!(matches!(UsbWire::open(SELECTOR), Err(OpenError::Claim(_))));
    drop(wire);

    let mut replacement = UsbWire::open(SELECTOR).unwrap();
    exchange(&mut replacement, REQUEST, HEALTHY);
}
