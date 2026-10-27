use super::*;
use development::{ManagementPoolStatus, ManagementStatus};
use kes_core::{
    session::HostSession,
    types::{GenerationId, IncarnationId, PoolId},
};
use kes_protocol::{Operation, Status};
use usb::SecureRequestHandler;

struct Persistent {
    handler: DevelopmentHandler,
    status: ManagementStatus,
}

impl SecureRequestHandler for Persistent {
    fn handle(
        &mut self,
        request: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
        lease: scheduler::RequestLease,
        scheduler: &mut scheduler::Scheduler,
    ) -> Result<usb::HandlerResult, usb::CommandError> {
        if request.operation == Operation::Status {
            self.handler
                .handle_persistent_status(request, response, lease, &self.status)
        } else {
            self.handler.handle(request, response, lease, scheduler)
        }
    }
}

fn fixture() -> (Persistent, UsbDispatcher, HostSession) {
    let hpke = DeviceHpkeKey::from_seed(Zeroizing::new(HPKE_SEED));
    let public_key = hpke.public_key();
    let machine = SigningKey::from_bytes(&MACHINE_SEED);
    let mut pools = [None; kes_core::MAX_POOLS];
    // A hole exercises summary traversal rather than assuming packed slots.
    pools[1] = Some(ManagementPoolStatus {
        pool: PoolId::from_bytes([21; 28]),
        incarnation: IncarnationId::from_bytes([22; 16]),
        revision: 23,
        credential_epoch: 24,
        management_sequence: 25,
        deleted: false,
        revoked: true,
        active: Some(GenerationId::from_bytes([26; 16])),
        staged: Some(GenerationId::from_bytes([27; 16])),
    });
    pools[2] = Some(ManagementPoolStatus {
        pool: PoolId::from_bytes([31; 28]),
        incarnation: IncarnationId::from_bytes([32; 16]),
        revision: 33,
        credential_epoch: 34,
        management_sequence: 35,
        deleted: true,
        revoked: true,
        active: None,
        staged: None,
    });
    let mut persistent = Persistent {
        handler: DevelopmentHandler::new(
            DEVICE,
            DeviceIdentityKey::from_seed(Zeroizing::new(IDENTITY_SEED)),
            hpke,
            BOOT_NONCE,
            machine.verifying_key().to_bytes(),
            ChaCha20Rng::from_seed([8; 32]),
            DevelopmentEvidence {
                firmware_digest: FIRMWARE_DIGEST,
                hardware_policy_digest: POLICY_DIGEST,
                security_version: 0,
                capability_evidence: b"disposable-a2-no-otp",
            },
        ),
        status: ManagementStatus {
            revision: 41,
            credential_epoch: CredentialEpoch::new(0),
            revoked: false,
            management_sequence: 42,
            retired: false,
            pools,
        },
    };
    let context = OpenContext::new(
        DEVICE,
        BOOT_NONCE,
        Scope::Management,
        CredentialEpoch::new(0),
        0,
        RequestId::from_bytes([43; 16]),
    );
    let (open, pending) = begin_open(
        context,
        &public_key,
        &machine,
        &mut ChaCha20Rng::from_seed([44; 32]),
    )
    .unwrap();
    let mut dispatcher = UsbDispatcher::new();
    let response = dispatch(&mut dispatcher, &mut persistent, &open_request(&open), 10).unwrap();
    let host = pending
        .complete(
            Envelope::parse(&response, EnvelopeKind::OpenResponse)
                .unwrap()
                .map(),
        )
        .unwrap();
    (persistent, dispatcher, host)
}

fn authenticated_request(host: &mut HostSession, sequence: u64) -> Vec<u8> {
    let request = RequestId::from_bytes([45; 16]);
    let unsigned = status_request(host.session_id(), request, sequence, [0; 32]);
    let mac = host.request_mac(map(&unsigned)).unwrap();
    status_request(host.session_id(), request, sequence, mac)
}

#[test]
fn persistent_status_authenticates_complete_live_directory_and_response_sequence() {
    let (mut persistent, mut dispatcher, mut host) = fixture();
    for sequence in 0..2 {
        let request = authenticated_request(&mut host, sequence);
        let response = dispatch(
            &mut dispatcher,
            &mut persistent,
            &request,
            100 + sequence * 100,
        )
        .unwrap();
        let envelope = Envelope::parse(&response, EnvelopeKind::DeviceResponse).unwrap();
        host.authenticate_response(
            envelope.map(),
            RequestId::from_bytes([45; 16]),
            "STATUS",
            sequence,
        )
        .unwrap();
        assert_eq!(
            envelope.map().required("seq").unwrap().uint().unwrap(),
            sequence
        );
        let payload = envelope.payload();
        assert_eq!(payload.required("revision").unwrap().uint().unwrap(), 41);
        assert_eq!(
            payload
                .required("credential_epoch")
                .unwrap()
                .uint()
                .unwrap(),
            0
        );
        assert_eq!(
            payload
                .required("management_sequence")
                .unwrap()
                .uint()
                .unwrap(),
            42
        );
        assert!(!payload.required("revoked").unwrap().boolean().unwrap());
        assert!(payload.required("active").unwrap().is_null());
        assert!(payload.required("staged").unwrap().is_null());
        assert_eq!(
            payload.required("health").unwrap().text().unwrap(),
            "healthy"
        );
        let entries: Vec<_> = payload
            .required("directory")
            .unwrap()
            .array()
            .unwrap()
            .collect();
        assert_eq!(entries.len(), 2);
        for (entry, expected) in entries.iter().zip(persistent.status.pools.iter().flatten()) {
            let entry = entry.map().unwrap();
            assert_eq!(
                entry.required("pool").unwrap().bytes().unwrap(),
                expected.pool.as_bytes()
            );
            assert_eq!(
                entry.required("incarnation").unwrap().bytes().unwrap(),
                expected.incarnation.as_bytes()
            );
            assert_eq!(
                entry.required("revision").unwrap().uint().unwrap(),
                expected.revision
            );
            assert_eq!(
                entry.required("credential_epoch").unwrap().uint().unwrap(),
                expected.credential_epoch
            );
            assert_eq!(
                entry
                    .required("management_sequence")
                    .unwrap()
                    .uint()
                    .unwrap(),
                expected.management_sequence
            );
            assert_eq!(
                entry.required("revoked").unwrap().boolean().unwrap(),
                expected.revoked
            );
            assert_eq!(
                entry.required("deleted").unwrap().boolean().unwrap(),
                expected.deleted
            );
            assert_eq!(entry.required("health").unwrap().text().unwrap(), "healthy");
            for (key, generation) in [("active", expected.active), ("staged", expected.staged)] {
                let value = entry.required(key).unwrap();
                match generation {
                    Some(generation) => assert_eq!(value.bytes().unwrap(), generation.as_bytes()),
                    None => assert!(value.is_null()),
                }
            }
        }
        if sequence == 1 {
            let replay = dispatch(&mut dispatcher, &mut persistent, &request, 350).unwrap_err();
            assert_eq!(replay.status, Status::Replay);
        }
    }
}

#[test]
fn persistent_status_rejects_request_and_response_tampering() {
    let (mut persistent, mut dispatcher, mut host) = fixture();
    let request = authenticated_request(&mut host, 0);
    let mut tampered = request.clone();
    let mac = map(&request).required("mac").unwrap().bytes().unwrap();
    let offset = request
        .windows(mac.len())
        .position(|bytes| bytes == mac)
        .unwrap();
    tampered[offset] ^= 1;
    assert_eq!(
        dispatch(&mut dispatcher, &mut persistent, &tampered, 100)
            .unwrap_err()
            .status,
        Status::AuthFailed
    );
    // Authentication failures invalidate the device session; use a new OPEN
    // for the independent response-tampering case.
    let (mut persistent, mut dispatcher, mut host) = fixture();
    let request = authenticated_request(&mut host, 0);
    let response = dispatch(&mut dispatcher, &mut persistent, &request, 200).unwrap();
    let mut tampered = response.clone();
    // Mutate a pool identity while retaining canonical CBOR and valid schema.
    let offset = response
        .windows(28)
        .position(|bytes| bytes == [21; 28])
        .unwrap();
    tampered[offset] ^= 1;
    assert!(
        host.authenticate_response(
            Envelope::parse(&tampered, EnvelopeKind::DeviceResponse)
                .unwrap()
                .map(),
            RequestId::from_bytes([45; 16]),
            "STATUS",
            0,
        )
        .is_err()
    );
}

#[test]
fn persistent_status_refuses_revoked_or_stale_directory_credentials() {
    for revoked in [false, true] {
        let (mut persistent, mut dispatcher, mut host) = fixture();
        if revoked {
            persistent.status.revoked = true;
        } else {
            persistent.status.credential_epoch = CredentialEpoch::new(1);
        }
        let request = authenticated_request(&mut host, 0);
        assert_eq!(
            dispatch(&mut dispatcher, &mut persistent, &request, 100)
                .unwrap_err()
                .status,
            Status::AuthFailed
        );
    }
}
