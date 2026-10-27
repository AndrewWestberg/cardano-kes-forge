use cardano_kes_forge::host::{
    bootstrap::{AuthorityRole, authority_public},
    client::DeviceWire,
    usb::UsbWire,
};
use kes_core::cbor::{Encoder, Value};
use kes_protocol::{Envelope, EnvelopeKind, MAX_FRAME_BYTES};
use std::{fs, time::Duration};
#[path = "support/a2.rs"]
mod a2;

const SELECTOR: &str = "vid=cafe,pid=4b45,serial=A2-IDENTITY-INITIALIZER";
const READ: &[u8] = b"KES-A2-IDENTITY/v1:READ-PUBLIC";
const PUBLIC: &[u8] = b"KES-A2-IDENTITY/v1:PUBLIC:";
const PROVISION: &[u8] = b"KES-A2-IDENTITY/v1:PROVISION-DISPOSABLE-DIRECTORY:";
const DIRECTORY: &[u8] = b"KES-A2-IDENTITY/v1:DIRECTORY-PUBLIC:";
const TRANSPORT: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

fn exchange(wire: &mut UsbWire, request: &[u8]) -> Vec<u8> {
    let mut output = [0; MAX_FRAME_BYTES];
    let n = wire
        .exchange(request, &mut output, Duration::from_secs(30))
        .unwrap();
    output[..n].to_vec()
}

#[test]
#[ignore = "one-time write to explicitly authorized disposable A2 directory"]
fn authorized_disposable_directory_is_provisioned_once() {
    assert_eq!(
        std::env::var("KES_A2_AUTHORIZE_DISPOSABLE_DIRECTORY_PROVISIONING").as_deref(),
        Ok("yes")
    );
    let path =
        std::env::var_os("KES_A2_MANAGEMENT_PUBLIC_KEY").expect("management public key path");
    let root = authority_public(&fs::read(path).unwrap(), AuthorityRole::Management)
        .unwrap()
        .public_key;
    let mut wire = UsbWire::open(SELECTOR).unwrap();
    let identity = exchange(&mut wire, READ);
    assert_eq!(identity.len(), PUBLIC.len() + 16 + 32 + 32);
    assert!(identity.starts_with(PUBLIC));

    let mut invalid = PROVISION.to_vec();
    invalid.extend_from_slice(&[0; 32]);
    invalid.extend_from_slice(&TRANSPORT);
    assert_eq!(
        exchange(&mut wire, &invalid),
        b"KES-A2-IDENTITY/v1:ERROR:DIRECTORY_INVALID_PUBLIC_KEY"
    );
    invalid.pop();
    assert_eq!(
        exchange(&mut wire, &invalid),
        b"KES-A2-IDENTITY/v1:ERROR:INVALID_REQUEST"
    );

    let mut request = PROVISION.to_vec();
    request.extend_from_slice(&root);
    request.extend_from_slice(&TRANSPORT);
    let response = exchange(&mut wire, &request);
    assert_eq!(response.len(), DIRECTORY.len() + 16 + 32 + 32 + 32);
    assert!(response.starts_with(DIRECTORY));
    assert_eq!(
        &response[DIRECTORY.len()..DIRECTORY.len() + 48],
        &identity[PUBLIC.len()..PUBLIC.len() + 48]
    );
    assert_eq!(&response[DIRECTORY.len() + 48..DIRECTORY.len() + 80], &root);
    assert_eq!(&response[DIRECTORY.len() + 80..], &TRANSPORT);
    assert_eq!(
        exchange(&mut wire, &request),
        b"KES-A2-IDENTITY/v1:ERROR:DIRECTORY_ALREADY_INITIALIZED"
    );
    assert_eq!(exchange(&mut wire, READ), identity);
}

#[test]
#[ignore = "requires the provisioned disposable A2 development runtime"]
fn provisioned_directory_boots_and_authenticates_management() {
    let mut wire = UsbWire::open("vid=cafe,pid=4b45,serial=A2-AUTH-DEVELOPMENT").unwrap();
    let (client, identity) = a2::open(&mut wire).unwrap();
    assert_eq!(client.boot_nonce(), identity.boot_nonce);
}

#[test]
#[ignore = "requires a provisioned disposable A2 with a signed enrollment"]
fn management_status_reports_enrolled_pool_after_reboot() {
    let path = std::env::var_os("KES_A2_ENROLLMENT_AUTHORIZATION")
        .expect("signed public enrollment authorization path");
    let signed = fs::read(path).unwrap();
    let signed = Value::parse(&signed).unwrap().map().unwrap();
    let expected_pool = signed.required("pool").unwrap().bytes().unwrap();
    let expected_incarnation = signed.required("incarnation").unwrap().bytes().unwrap();
    let expected_sequence = signed
        .required("management_sequence")
        .unwrap()
        .uint()
        .unwrap();
    let mut wire = UsbWire::open("vid=cafe,pid=4b45,serial=A2-AUTH-DEVELOPMENT").unwrap();
    let (mut client, identity) = a2::open(&mut wire).unwrap();
    let mut request = [0; MAX_FRAME_BYTES];
    let mut encoder = Encoder::new(&mut request);
    encoder.map(6).unwrap();
    encoder.text("op").unwrap();
    encoder.text("STATUS").unwrap();
    encoder.text("payload").unwrap();
    encoder.map(0).unwrap();
    encoder.text("request").unwrap();
    encoder.bytes(&[0x81; 16]).unwrap();
    encoder.text("version").unwrap();
    encoder.uint(1).unwrap();
    encoder.text("budget_ms").unwrap();
    encoder.uint(2000).unwrap();
    encoder.text("connection").unwrap();
    encoder.text("a2-development").unwrap();
    let request = encoder.finish().unwrap();
    let mut response = [0; MAX_FRAME_BYTES];
    let n = client
        .exchange_local(
            &mut wire,
            request.encoded(),
            &mut response,
            Duration::from_secs(5),
        )
        .unwrap();
    let response = Envelope::parse(&response[..n], EnvelopeKind::LocalResponse).unwrap();
    assert_eq!(response.status.unwrap().as_str(), "OK");
    assert_eq!(client.boot_nonce(), identity.boot_nonce);
    let mut found = false;
    for entry in response
        .payload()
        .required("directory")
        .unwrap()
        .array()
        .unwrap()
    {
        let entry = entry.map().unwrap();
        if entry.required("pool").unwrap().bytes().unwrap() == expected_pool {
            assert!(!found);
            found = true;
            assert_eq!(
                entry.required("incarnation").unwrap().bytes().unwrap(),
                expected_incarnation
            );
            assert_eq!(
                entry
                    .required("management_sequence")
                    .unwrap()
                    .uint()
                    .unwrap(),
                expected_sequence
            );
            assert!(!entry.required("deleted").unwrap().boolean().unwrap());
        }
    }
    assert!(found, "authenticated status omitted the committed pool");
}

#[test]
#[ignore = "requires a committed enrollment on the disposable A2"]
fn management_operation_status_recovers_committed_enrollment() {
    let path = std::env::var_os("KES_A2_ENROLLMENT_AUTHORIZATION")
        .expect("signed public enrollment authorization path");
    let signed = fs::read(path).unwrap();
    let signed = Value::parse(&signed).unwrap().map().unwrap();
    let operation = signed.required("request").unwrap().bytes().unwrap();
    let expected_sequence = signed
        .required("management_sequence")
        .unwrap()
        .uint()
        .unwrap();
    let mut wire = UsbWire::open("vid=cafe,pid=4b45,serial=A2-AUTH-DEVELOPMENT").unwrap();
    let (mut client, _) = a2::open(&mut wire).unwrap();
    let mut request = [0; MAX_FRAME_BYTES];
    let mut encoder = Encoder::new(&mut request);
    encoder.map(6).unwrap();
    encoder.text("op").unwrap();
    encoder.text("OP_STATUS").unwrap();
    encoder.text("payload").unwrap();
    encoder.map(1).unwrap();
    encoder.text("request").unwrap();
    encoder.bytes(operation).unwrap();
    encoder.text("request").unwrap();
    encoder.bytes(&[0x83; 16]).unwrap();
    encoder.text("version").unwrap();
    encoder.uint(1).unwrap();
    encoder.text("budget_ms").unwrap();
    encoder.uint(2000).unwrap();
    encoder.text("connection").unwrap();
    encoder.text("a2-development").unwrap();
    let request = encoder.finish().unwrap();
    let mut response = [0; MAX_FRAME_BYTES];
    let n = client
        .exchange_local(
            &mut wire,
            request.encoded(),
            &mut response,
            Duration::from_secs(5),
        )
        .unwrap();
    let response = Envelope::parse(&response[..n], EnvelopeKind::LocalResponse).unwrap();
    assert_eq!(response.status.unwrap().as_str(), "OK");
    assert_eq!(
        response
            .payload()
            .required("management_sequence")
            .unwrap()
            .uint()
            .unwrap(),
        expected_sequence
    );
    assert_eq!(
        response
            .payload()
            .required("revision")
            .unwrap()
            .uint()
            .unwrap(),
        0
    );
}
