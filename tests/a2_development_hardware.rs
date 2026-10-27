use cardano_kes_forge::host::{
    client::{DeviceWire, Error as ClientError},
    usb::UsbWire,
};
use kes_core::cbor::Encoder;
use kes_protocol::{Envelope, EnvelopeKind, MAX_FRAME_BYTES};
use nusb::MaybeFuture;
use sha2::{Digest, Sha256};
use std::time::Duration;
#[path = "support/a2.rs"]
mod a2;

const SELECTOR: &str = "vid=cafe,pid=4b45,serial=A2-AUTH-DEVELOPMENT";

fn local_status(request: [u8; 16]) -> Vec<u8> {
    let mut output = [0; MAX_FRAME_BYTES];
    let mut encoder = Encoder::new(&mut output);
    encoder.map(6).unwrap();
    encoder.text("op").unwrap();
    encoder.text("STATUS").unwrap();
    encoder.text("payload").unwrap();
    encoder.map(0).unwrap();
    encoder.text("request").unwrap();
    encoder.bytes(&request).unwrap();
    encoder.text("version").unwrap();
    encoder.uint(1).unwrap();
    encoder.text("budget_ms").unwrap();
    encoder.uint(500).unwrap();
    encoder.text("connection").unwrap();
    encoder.text("a2-development").unwrap();
    encoder.finish().unwrap().encoded().to_vec()
}

fn operator_status(request: [u8; 16], device: [u8; 16]) -> Vec<u8> {
    let mut output = [0; MAX_FRAME_BYTES];
    let mut encoder = Encoder::new(&mut output);
    encoder.map(7).unwrap();
    encoder.text("op").unwrap();
    encoder.text("STATUS").unwrap();
    encoder.text("target").unwrap();
    encoder.array(3).unwrap();
    encoder.bytes(&device).unwrap();
    encoder.null().unwrap();
    encoder.null().unwrap();
    encoder.text("payload").unwrap();
    encoder.map(1).unwrap();
    encoder.text("host_diagnostics").unwrap();
    encoder.boolean(true).unwrap();
    encoder.text("request").unwrap();
    encoder.bytes(&request).unwrap();
    encoder.text("version").unwrap();
    encoder.uint(1).unwrap();
    encoder.text("budget_ms").unwrap();
    encoder.uint(500).unwrap();
    encoder.text("connection").unwrap();
    encoder.text("a2-development").unwrap();
    encoder.finish().unwrap().encoded().to_vec()
}

fn invalid_authenticated_status(
    device: [u8; 16],
    session: [u8; 16],
    request: [u8; 16],
    sequence: u64,
) -> Vec<u8> {
    let mut output = [0; MAX_FRAME_BYTES];
    let mut encoder = Encoder::new(&mut output);
    encoder.map(11).unwrap();
    encoder.text("op").unwrap();
    encoder.text("STATUS").unwrap();
    encoder.text("mac").unwrap();
    encoder.bytes(&[0; 32]).unwrap();
    encoder.text("seq").unwrap();
    encoder.uint(sequence).unwrap();
    encoder.text("pool").unwrap();
    encoder.null().unwrap();
    encoder.text("device").unwrap();
    encoder.bytes(&device).unwrap();
    encoder.text("payload").unwrap();
    encoder.map(0).unwrap();
    encoder.text("request").unwrap();
    encoder.bytes(&request).unwrap();
    encoder.text("session").unwrap();
    encoder.bytes(&session).unwrap();
    encoder.text("version").unwrap();
    encoder.uint(1).unwrap();
    encoder.text("budget_ms").unwrap();
    encoder.uint(500).unwrap();
    encoder.text("incarnation").unwrap();
    encoder.null().unwrap();
    encoder.finish().unwrap().encoded().to_vec()
}

#[test]
#[ignore = "requires the authorized disposable RP2350 A2 authenticated development image"]
fn authenticated_a2_info_open_status_fail_closed_and_reopen() {
    let mut wire = UsbWire::open(SELECTOR).unwrap();
    let (mut client, identity) = a2::open(&mut wire).unwrap();
    assert_eq!(client.boot_nonce(), identity.boot_nonce);
    assert_ne!(identity.device, [0xa2; 16]);
    assert_ne!(identity.boot_nonce, [0x33; 32]);
    let mut fingerprint = Sha256::new();
    fingerprint.update(identity.device);
    fingerprint.update(identity.identity_public_key);
    fingerprint.update(identity.hpke_public_key);
    fingerprint.update(identity.boot_nonce);
    eprintln!(
        "A2 public boot identity SHA-256: {:x}",
        fingerprint.finalize()
    );

    let request = [0x31; 16];
    let mut response = [0; MAX_FRAME_BYTES];
    let length = client
        .exchange_local(
            &mut wire,
            &local_status(request),
            &mut response,
            Duration::from_secs(2),
        )
        .unwrap();
    let status = Envelope::parse(&response[..length], EnvelopeKind::LocalResponse).unwrap();
    assert_eq!(status.status.unwrap().as_str(), "OK");
    assert_eq!(
        status
            .payload()
            .required("security_mode")
            .unwrap()
            .text()
            .unwrap(),
        "development"
    );
    // Local-only additions must be removed before authenticated USB encoding;
    // the older A2 firmware rejects unknown device-wire fields.
    let length = client
        .exchange_local(
            &mut wire,
            &operator_status([0x33; 16], identity.device),
            &mut response,
            Duration::from_secs(2),
        )
        .unwrap();
    let status = Envelope::parse(&response[..length], EnvelopeKind::LocalResponse).unwrap();
    assert_eq!(status.status.unwrap().as_str(), "OK");

    let invalid = invalid_authenticated_status(identity.device, client.session_id(), [0x32; 16], 2);
    assert!(matches!(
        wire.exchange(&invalid, &mut response, Duration::from_millis(750)),
        Err(ClientError::Uncertain)
    ));
    drop(wire);

    let mut replacement = UsbWire::open(SELECTOR).unwrap();
    let (replacement_client, replacement_identity) = a2::open(&mut replacement).unwrap();
    assert_eq!(replacement_identity.device, identity.device);
    assert_eq!(
        replacement_identity.identity_public_key,
        identity.identity_public_key
    );
    assert_ne!(replacement_client.session_id(), client.session_id());
}

#[test]
#[ignore = "requires the authorized disposable RP2350 A2 authenticated development image"]
fn usb_bus_reset_invalidates_authenticated_session() {
    let mut wire = UsbWire::open(SELECTOR).unwrap();
    let (mut client, identity) = a2::open(&mut wire).unwrap();
    let mut response = [0; MAX_FRAME_BYTES];
    client
        .exchange_local(
            &mut wire,
            &local_status([0x61; 16]),
            &mut response,
            Duration::from_secs(2),
        )
        .unwrap();
    drop(wire);

    let device = nusb::list_devices()
        .wait()
        .unwrap()
        .find(|device| {
            device.vendor_id() == 0xcafe
                && device.product_id() == 0x4b45
                && device.serial_number() == Some("A2-AUTH-DEVELOPMENT")
        })
        .unwrap()
        .open()
        .wait()
        .unwrap();
    device.reset().wait().unwrap();
    drop(device);
    std::thread::sleep(Duration::from_millis(200));

    let mut wire = UsbWire::open(SELECTOR).unwrap();
    assert!(
        client
            .exchange_local(
                &mut wire,
                &local_status([0x62; 16]),
                &mut response,
                Duration::from_millis(750),
            )
            .is_err()
    );
    drop(wire);
    let mut wire = UsbWire::open(SELECTOR).unwrap();
    let (mut reopened, reopened_identity) = a2::open(&mut wire).unwrap();
    assert_eq!(reopened_identity.device, identity.device);
    reopened
        .exchange_local(
            &mut wire,
            &local_status([0x63; 16]),
            &mut response,
            Duration::from_secs(2),
        )
        .unwrap();
}

#[test]
#[ignore = "reboots the disposable A2 development image into BOOTSEL"]
fn disposable_development_can_return_to_bootsel() {
    use nusb::transfer::{ControlOut, ControlType, Recipient};

    let device = nusb::list_devices()
        .wait()
        .unwrap()
        .find(|device| {
            device.vendor_id() == 0xcafe
                && device.product_id() == 0x4b45
                && device.serial_number() == Some("A2-AUTH-DEVELOPMENT")
        })
        .unwrap()
        .open()
        .wait()
        .unwrap();
    device
        .control_out(
            ControlOut {
                control_type: ControlType::Vendor,
                recipient: Recipient::Device,
                request: 0x5a,
                value: 0x4b45,
                index: 0xa235,
                data: &[],
            },
            Duration::from_secs(2),
        )
        .wait()
        .unwrap();
}
