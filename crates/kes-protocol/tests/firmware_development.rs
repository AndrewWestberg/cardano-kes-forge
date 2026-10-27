#[allow(dead_code)]
#[path = "../../../firmware/src/security/gateway.rs"]
mod gateway_impl;
#[allow(dead_code)]
#[path = "../../../firmware/src/scheduler.rs"]
mod scheduler;
mod security {
    pub mod gateway {
        pub use crate::gateway_impl::*;
    }
}
#[allow(dead_code, unused_imports, unexpected_cfgs)]
#[path = "../../../firmware/src/development.rs"]
mod development;
#[path = "firmware_development/operation_status.rs"]
mod operation_status;
#[allow(dead_code)]
#[path = "../../../firmware/src/pool_service.rs"]
mod pool_service;
#[allow(dead_code)]
#[path = "../../../firmware/src/usb.rs"]
mod usb;

use development::{DevelopmentEvidence, DevelopmentHandler};
use ed25519_dalek::SigningKey;
use kes_core::{
    cbor::{Encoder, Map, Value},
    session::{
        DeviceHpkeKey, DeviceIdentityKey, INFO_TRANSCRIPT_BYTES, OpenContext, OpenRequest, Scope,
        begin_open, verify_info,
    },
    types::{CredentialEpoch, DeviceId, RequestId},
};
use kes_protocol::{Envelope, EnvelopeKind, MAX_FRAME_BYTES};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use usb::{ReceiveStatus, UsbDispatcher};
use zeroize::Zeroizing;

const DEVICE: DeviceId = DeviceId::from_bytes([1; 16]);
const BOOT_NONCE: [u8; 32] = [2; 32];
const IDENTITY_SEED: [u8; 32] = [3; 32];
const HPKE_SEED: [u8; 32] = [4; 32];
const MACHINE_SEED: [u8; 32] = [5; 32];
const FIRMWARE_DIGEST: [u8; 32] = [6; 32];
const POLICY_DIGEST: [u8; 32] = [7; 32];

fn info_request(request: RequestId, challenge: [u8; 32]) -> Vec<u8> {
    let mut output = [0; MAX_FRAME_BYTES];
    let mut encoder = Encoder::new(&mut output);
    encoder.map(4).unwrap();
    encoder.text("op").unwrap();
    encoder.text("INFO").unwrap();
    encoder.text("payload").unwrap();
    encoder.map(1).unwrap();
    encoder.text("challenge").unwrap();
    encoder.bytes(&challenge).unwrap();
    encoder.text("request").unwrap();
    encoder.bytes(request.as_bytes()).unwrap();
    encoder.text("version").unwrap();
    encoder.uint(1).unwrap();
    encoder.finish().unwrap().encoded().to_vec()
}

fn open_request(open: &OpenRequest) -> Vec<u8> {
    let mut output = [0; MAX_FRAME_BYTES];
    let mut encoder = Encoder::new(&mut output);
    encoder.map(7).unwrap();
    encoder.text("op").unwrap();
    encoder.text("OPEN").unwrap();
    encoder.text("pool").unwrap();
    encoder.null().unwrap();
    encoder.text("device").unwrap();
    encoder.bytes(open.context.device.as_bytes()).unwrap();
    encoder.text("payload").unwrap();
    encoder.map(6).unwrap();
    encoder.text("signature").unwrap();
    encoder.bytes(&open.signature).unwrap();
    encoder.text("boot_nonce").unwrap();
    encoder.bytes(&open.context.boot_nonce).unwrap();
    encoder.text("ciphertext").unwrap();
    encoder.bytes(&open.ciphertext).unwrap();
    encoder.text("open_counter").unwrap();
    encoder.uint(open.context.open_counter).unwrap();
    encoder.text("encapsulation").unwrap();
    encoder.bytes(&open.encapsulation).unwrap();
    encoder.text("credential_epoch").unwrap();
    encoder.uint(open.context.credential_epoch.get()).unwrap();
    encoder.text("request").unwrap();
    encoder.bytes(open.context.request.as_bytes()).unwrap();
    encoder.text("version").unwrap();
    encoder.uint(1).unwrap();
    encoder.text("incarnation").unwrap();
    encoder.null().unwrap();
    encoder.finish().unwrap().encoded().to_vec()
}

fn status_request(session: &[u8; 16], request: RequestId, sequence: u64, mac: [u8; 32]) -> Vec<u8> {
    let mut output = [0; MAX_FRAME_BYTES];
    let mut encoder = Encoder::new(&mut output);
    encoder.map(11).unwrap();
    encoder.text("op").unwrap();
    encoder.text("STATUS").unwrap();
    encoder.text("mac").unwrap();
    encoder.bytes(&mac).unwrap();
    encoder.text("seq").unwrap();
    encoder.uint(sequence).unwrap();
    encoder.text("pool").unwrap();
    encoder.null().unwrap();
    encoder.text("device").unwrap();
    encoder.bytes(DEVICE.as_bytes()).unwrap();
    encoder.text("payload").unwrap();
    encoder.map(0).unwrap();
    encoder.text("request").unwrap();
    encoder.bytes(request.as_bytes()).unwrap();
    encoder.text("session").unwrap();
    encoder.bytes(session).unwrap();
    encoder.text("version").unwrap();
    encoder.uint(1).unwrap();
    encoder.text("budget_ms").unwrap();
    encoder.uint(500).unwrap();
    encoder.text("incarnation").unwrap();
    encoder.null().unwrap();
    encoder.finish().unwrap().encoded().to_vec()
}

fn dispatch(
    dispatcher: &mut UsbDispatcher,
    handler: &mut impl usb::SecureRequestHandler,
    request: &[u8],
    now_ms: u64,
) -> Result<Vec<u8>, usb::UsbError> {
    let mut framed = Vec::with_capacity(request.len() + 4);
    framed.extend_from_slice(&(request.len() as u32).to_be_bytes());
    framed.extend_from_slice(request);
    let midpoint = framed.len().min(3);
    assert_eq!(
        dispatcher.receive(&framed[..midpoint], now_ms)?.status,
        ReceiveStatus::Pending
    );
    assert_eq!(
        dispatcher.receive(&framed[midpoint..], now_ms + 1)?.status,
        ReceiveStatus::Ready
    );
    let mut output = [0; MAX_FRAME_BYTES];
    let response = dispatcher.dispatch(now_ms + 1, &mut output, handler)?;
    assert_eq!(response.prefix, (response.body_length as u32).to_be_bytes());
    Ok(output[..response.body_length].to_vec())
}

fn map(bytes: &[u8]) -> Map<'_> {
    Value::parse(bytes).unwrap().map().unwrap()
}

#[test]
fn concrete_handler_authenticates_info_open_and_status_then_rejects_replay() {
    let identity = DeviceIdentityKey::from_seed(Zeroizing::new(IDENTITY_SEED));
    let identity_public_key = identity.verification_key();
    let hpke = DeviceHpkeKey::from_seed(Zeroizing::new(HPKE_SEED));
    let hpke_public_key = hpke.public_key();
    let machine = SigningKey::from_bytes(&MACHINE_SEED);
    let evidence = DevelopmentEvidence {
        firmware_digest: FIRMWARE_DIGEST,
        hardware_policy_digest: POLICY_DIGEST,
        security_version: 0,
        capability_evidence: b"disposable-a2-no-otp",
    };
    let mut handler = DevelopmentHandler::new(
        DEVICE,
        identity,
        hpke,
        BOOT_NONCE,
        machine.verifying_key().to_bytes(),
        ChaCha20Rng::from_seed([8; 32]),
        evidence,
    );
    let mut dispatcher = UsbDispatcher::new();

    let info_request_id = RequestId::from_bytes([9; 16]);
    let challenge = [10; 32];
    let info = dispatch(
        &mut dispatcher,
        &mut handler,
        &info_request(info_request_id, challenge),
        100,
    )
    .unwrap();
    let info_envelope = Envelope::parse(&info, EnvelopeKind::InfoResponse).unwrap();
    let mut scratch = [0; INFO_TRANSCRIPT_BYTES];
    let view = verify_info(
        info_envelope.map(),
        DEVICE,
        info_request_id,
        &challenge,
        &identity_public_key,
        &mut scratch,
    )
    .unwrap();
    assert_eq!(view.boot_nonce, BOOT_NONCE);
    assert_eq!(view.hpke_public_key, hpke_public_key);
    let payload = info_envelope.payload();
    assert_eq!(
        payload
            .required("firmware_digest")
            .unwrap()
            .bytes()
            .unwrap(),
        FIRMWARE_DIGEST
    );
    assert_eq!(
        payload
            .required("hardware_policy_digest")
            .unwrap()
            .bytes()
            .unwrap(),
        POLICY_DIGEST
    );
    assert_eq!(
        payload.required("security_mode").unwrap().text().unwrap(),
        "development"
    );
    let counter = payload
        .required("open_counters")
        .unwrap()
        .array()
        .unwrap()
        .next()
        .unwrap()
        .map()
        .unwrap()
        .required("open_counter")
        .unwrap()
        .uint()
        .unwrap();
    assert_eq!(counter, 0);

    let open_request_id = RequestId::from_bytes([11; 16]);
    let context = OpenContext::new(
        DEVICE,
        BOOT_NONCE,
        Scope::Management,
        CredentialEpoch::new(0),
        counter,
        open_request_id,
    );
    let mut host_rng = ChaCha20Rng::from_seed([12; 32]);
    let (open, pending) = begin_open(context, &hpke_public_key, &machine, &mut host_rng).unwrap();
    let open_response = dispatch(&mut dispatcher, &mut handler, &open_request(&open), 200).unwrap();
    let open_envelope = Envelope::parse(&open_response, EnvelopeKind::OpenResponse).unwrap();
    let mut host = pending.complete(open_envelope.map()).unwrap();

    let status_request_id = RequestId::from_bytes([13; 16]);
    let unsigned = status_request(host.session_id(), status_request_id, 0, [0; 32]);
    let mac = host.request_mac(map(&unsigned)).unwrap();
    let authenticated = status_request(host.session_id(), status_request_id, 0, mac);
    let status = dispatch(&mut dispatcher, &mut handler, &authenticated, 300).unwrap();
    let status_envelope = Envelope::parse(&status, EnvelopeKind::DeviceResponse).unwrap();
    host.authenticate_response(status_envelope.map(), status_request_id, "STATUS", 0)
        .unwrap();
    assert_eq!(
        status_envelope
            .payload()
            .required("security_mode")
            .unwrap()
            .text()
            .unwrap(),
        "development"
    );

    let replay = dispatch(&mut dispatcher, &mut handler, &authenticated, 400).unwrap_err();
    assert_eq!(replay.status, kes_protocol::Status::Replay);

    let next_context = OpenContext::new(
        DEVICE,
        BOOT_NONCE,
        Scope::Management,
        CredentialEpoch::new(0),
        1,
        RequestId::from_bytes([14; 16]),
    );
    let (next_open, pending) =
        begin_open(next_context, &hpke_public_key, &machine, &mut host_rng).unwrap();
    let response = dispatch(
        &mut dispatcher,
        &mut handler,
        &open_request(&next_open),
        500,
    )
    .unwrap();
    let mut next_host = pending
        .complete(
            Envelope::parse(&response, EnvelopeKind::OpenResponse)
                .unwrap()
                .map(),
        )
        .unwrap();
    let request_id = RequestId::from_bytes([15; 16]);
    let unsigned = status_request(next_host.session_id(), request_id, 0, [0; 32]);
    let mac = next_host.request_mac(map(&unsigned)).unwrap();
    let old_session_request = status_request(next_host.session_id(), request_id, 0, mac);
    handler.disconnect();
    let disconnected =
        dispatch(&mut dispatcher, &mut handler, &old_session_request, 600).unwrap_err();
    assert_eq!(disconnected.status, kes_protocol::Status::AuthFailed);

    // The counter remains monotonic across disconnect, so an old OPEN cannot
    // re-establish the invalidated session.
    assert!(
        dispatch(
            &mut dispatcher,
            &mut handler,
            &open_request(&next_open),
            700
        )
        .is_err()
    );
    let final_context = OpenContext::new(
        DEVICE,
        BOOT_NONCE,
        Scope::Management,
        CredentialEpoch::new(0),
        2,
        RequestId::from_bytes([16; 16]),
    );
    let (final_open, pending) =
        begin_open(final_context, &hpke_public_key, &machine, &mut host_rng).unwrap();
    let response = dispatch(
        &mut dispatcher,
        &mut handler,
        &open_request(&final_open),
        800,
    )
    .unwrap();
    let mut final_host = pending
        .complete(
            Envelope::parse(&response, EnvelopeKind::OpenResponse)
                .unwrap()
                .map(),
        )
        .unwrap();
    let request_id = RequestId::from_bytes([17; 16]);
    let unsigned = status_request(final_host.session_id(), request_id, 0, [0; 32]);
    let mac = final_host.request_mac(map(&unsigned)).unwrap();
    let request = status_request(final_host.session_id(), request_id, 0, mac);
    let response = dispatch(&mut dispatcher, &mut handler, &request, 900).unwrap();
    final_host
        .authenticate_response(
            Envelope::parse(&response, EnvelopeKind::DeviceResponse)
                .unwrap()
                .map(),
            request_id,
            "STATUS",
            0,
        )
        .unwrap();
}

#[path = "firmware_development/enrollment.rs"]
mod enrollment;

#[path = "firmware_development/status.rs"]
mod status;
