use cardano_kes_forge::host::{
    client::{AuthenticatedClient, DeviceWire, Error as ClientError},
    usb::UsbWire,
};
use kes_core::cbor::Encoder;
use kes_protocol::{Envelope, EnvelopeKind, MAX_FRAME_BYTES};
use sha2::{Digest, Sha256};
use std::time::Duration;

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
    let (mut client, identity) = AuthenticatedClient::open_a2_development(&mut wire).unwrap();
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
    assert_eq!(
        status
            .payload()
            .required("blocking_reason")
            .unwrap()
            .text()
            .unwrap(),
        "development firmware: persistent pool state is unavailable"
    );

    let invalid = invalid_authenticated_status(identity.device, client.session_id(), [0x32; 16], 1);
    assert!(matches!(
        wire.exchange(&invalid, &mut response, Duration::from_millis(750)),
        Err(ClientError::Uncertain)
    ));
    drop(wire);

    let mut replacement = UsbWire::open(SELECTOR).unwrap();
    let (replacement_client, replacement_identity) =
        AuthenticatedClient::open_a2_development(&mut replacement).unwrap();
    assert_eq!(replacement_identity.device, identity.device);
    assert_eq!(
        replacement_identity.identity_public_key,
        identity.identity_public_key
    );
    assert_ne!(replacement_client.session_id(), client.session_id());
}
