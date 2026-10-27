#[allow(dead_code)]
#[path = "../firmware/src/security/gateway.rs"]
mod gateway_impl;
#[allow(dead_code)]
#[path = "../firmware/src/scheduler.rs"]
mod scheduler;
mod security {
    pub mod gateway {
        pub use crate::gateway_impl::*;
    }
}
#[allow(dead_code)]
#[path = "../firmware/src/usb.rs"]
mod firmware_usb;
mod usb {
    pub use crate::firmware_usb::*;
}
#[allow(dead_code)]
#[path = "../firmware/src/development.rs"]
mod development;

use cardano_kes_forge::host::client::{AuthenticatedClient, DeviceWire, Error as ClientError};
use development::{DevelopmentEvidence, DevelopmentHandler};
use kes_core::{
    cbor::Encoder,
    session::{DeviceHpkeKey, DeviceIdentityKey},
    types::DeviceId,
};
use kes_protocol::{Envelope, EnvelopeKind, MAX_FRAME_BYTES};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use std::time::Duration;
use usb::UsbDispatcher;
use zeroize::Zeroizing;

const MACHINE_PUBLIC_KEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
const POLICY_DIGEST: [u8; 32] = [
    0xa6, 0x22, 0x83, 0xc6, 0xd4, 0x21, 0x01, 0x29, 0xcf, 0x6f, 0x26, 0x8f, 0x61, 0x15, 0x0a, 0x23,
    0xc6, 0xf3, 0x2e, 0x60, 0x2c, 0xa9, 0x6f, 0x3c, 0x3d, 0x8c, 0x93, 0xec, 0x3a, 0xf2, 0x0f, 0xf2,
];

struct HandlerWire {
    dispatcher: UsbDispatcher,
    handler: DevelopmentHandler,
    now_ms: u64,
}

impl DeviceWire for HandlerWire {
    fn exchange(
        &mut self,
        request: &[u8],
        response: &mut [u8; MAX_FRAME_BYTES],
        _timeout: Duration,
    ) -> Result<usize, ClientError> {
        let mut frame = Vec::with_capacity(request.len() + 4);
        frame.extend_from_slice(&(request.len() as u32).to_be_bytes());
        frame.extend_from_slice(request);
        self.dispatcher
            .receive(&frame, self.now_ms)
            .map_err(|_| ClientError::Integrity)?;
        let result = self
            .dispatcher
            .dispatch(self.now_ms, response, &mut self.handler)
            .map_err(|_| ClientError::Security)?;
        self.now_ms += 10;
        Ok(result.body_length)
    }
}

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

#[test]
fn development_bootstrap_self_pins_only_the_labeled_disposable_image() {
    let handler = DevelopmentHandler::new(
        DeviceId::from_bytes([1; 16]),
        DeviceIdentityKey::from_seed(Zeroizing::new([2; 32])),
        DeviceHpkeKey::from_seed(Zeroizing::new([3; 32])),
        [4; 32],
        MACHINE_PUBLIC_KEY,
        ChaCha20Rng::from_seed([5; 32]),
        DevelopmentEvidence {
            firmware_digest: [0; 32],
            hardware_policy_digest: POLICY_DIGEST,
            security_version: 0,
            capability_evidence: b"rp2350-a2;development;otp=untouched;\
                persistence=identity-only;firmware-digest=unmeasured;\
                entropy=health-checked-a2-exploratory;session-entropy=fresh-per-open",
        },
    );
    let mut wire = HandlerWire {
        dispatcher: UsbDispatcher::new(),
        handler,
        now_ms: 10,
    };
    let (mut client, identity) = AuthenticatedClient::open_a2_development(&mut wire).unwrap();
    assert_eq!(identity.device, [1; 16]);
    assert_eq!(identity.boot_nonce, [4; 32]);

    let mut output = [0; MAX_FRAME_BYTES];
    let request = [6; 16];
    let length = client
        .exchange_local(
            &mut wire,
            &local_status(request),
            &mut output,
            Duration::from_secs(2),
        )
        .unwrap();
    let status = Envelope::parse(&output[..length], EnvelopeKind::LocalResponse).unwrap();
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
}

#[test]
fn development_bootstrap_rejects_evidence_outside_the_a2_policy() {
    let handler = DevelopmentHandler::new(
        DeviceId::from_bytes([1; 16]),
        DeviceIdentityKey::from_seed(Zeroizing::new([2; 32])),
        DeviceHpkeKey::from_seed(Zeroizing::new([3; 32])),
        [4; 32],
        MACHINE_PUBLIC_KEY,
        ChaCha20Rng::from_seed([5; 32]),
        DevelopmentEvidence {
            firmware_digest: [0; 32],
            hardware_policy_digest: POLICY_DIGEST,
            security_version: 0,
            capability_evidence: b"release-unprovisioned",
        },
    );
    let mut wire = HandlerWire {
        dispatcher: UsbDispatcher::new(),
        handler,
        now_ms: 10,
    };
    assert!(matches!(
        AuthenticatedClient::open_a2_development(&mut wire),
        Err(ClientError::Security)
    ));
}
