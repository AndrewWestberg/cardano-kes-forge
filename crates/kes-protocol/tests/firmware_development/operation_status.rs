use super::*;
use development::ManagementOperationStatus;
use kes_core::session::HostSession;
use kes_protocol::{Operation, Status};
use scheduler::{RequestLease, Scheduler};
use usb::{CommandError, HandlerResult, SecureRequestHandler};

struct ReconciliationHandler {
    inner: DevelopmentHandler,
    epoch: CredentialEpoch,
    revoked: bool,
    outcome: ManagementOperationStatus,
}

impl SecureRequestHandler for ReconciliationHandler {
    fn handle(
        &mut self,
        request: Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
        lease: RequestLease,
        scheduler: &mut Scheduler,
    ) -> Result<HandlerResult, CommandError> {
        if request.operation == Operation::OpStatus {
            self.inner.handle_management_operation_status(
                request,
                response,
                lease,
                self.epoch,
                self.revoked,
                self.outcome,
            )
        } else {
            self.inner.handle(request, response, lease, scheduler)
        }
    }
}

fn connected() -> (ReconciliationHandler, UsbDispatcher, HostSession) {
    let identity = DeviceIdentityKey::from_seed(Zeroizing::new(IDENTITY_SEED));
    let hpke = DeviceHpkeKey::from_seed(Zeroizing::new(HPKE_SEED));
    let public = hpke.public_key();
    let machine = SigningKey::from_bytes(&MACHINE_SEED);
    let mut handler = ReconciliationHandler {
        inner: DevelopmentHandler::new(
            DEVICE,
            identity,
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
        epoch: CredentialEpoch::new(0),
        revoked: false,
        outcome: ManagementOperationStatus::Unknown,
    };
    let context = OpenContext::new(
        DEVICE,
        BOOT_NONCE,
        Scope::Management,
        CredentialEpoch::new(0),
        0,
        RequestId::from_bytes([11; 16]),
    );
    let (open, pending) = begin_open(
        context,
        &public,
        &machine,
        &mut ChaCha20Rng::from_seed([12; 32]),
    )
    .unwrap();
    let mut dispatcher = UsbDispatcher::new();
    let response = dispatch(&mut dispatcher, &mut handler, &open_request(&open), 100).unwrap();
    let envelope = Envelope::parse(&response, EnvelopeKind::OpenResponse).unwrap();
    (
        handler,
        dispatcher,
        pending.complete(envelope.map()).unwrap(),
    )
}

fn query(
    session: &[u8; 16],
    request: RequestId,
    target: RequestId,
    seq: u64,
    mac: [u8; 32],
) -> Vec<u8> {
    let mut output = [0; MAX_FRAME_BYTES];
    let mut e = Encoder::new(&mut output);
    e.map(11).unwrap();
    e.text("op").unwrap();
    e.text("OP_STATUS").unwrap();
    e.text("mac").unwrap();
    e.bytes(&mac).unwrap();
    e.text("seq").unwrap();
    e.uint(seq).unwrap();
    e.text("pool").unwrap();
    e.null().unwrap();
    e.text("device").unwrap();
    e.bytes(DEVICE.as_bytes()).unwrap();
    e.text("payload").unwrap();
    e.map(1).unwrap();
    e.text("request").unwrap();
    e.bytes(target.as_bytes()).unwrap();
    e.text("request").unwrap();
    e.bytes(request.as_bytes()).unwrap();
    e.text("session").unwrap();
    e.bytes(session).unwrap();
    e.text("version").unwrap();
    e.uint(1).unwrap();
    e.text("budget_ms").unwrap();
    e.uint(500).unwrap();
    e.text("incarnation").unwrap();
    e.null().unwrap();
    e.finish().unwrap().encoded().to_vec()
}

fn signed_query(
    host: &mut HostSession,
    request: RequestId,
    target: RequestId,
    seq: u64,
) -> Vec<u8> {
    let unsigned = query(host.session_id(), request, target, seq, [0; 32]);
    let mac = host.request_mac(map(&unsigned)).unwrap();
    query(host.session_id(), request, target, seq, mac)
}

#[test]
fn journal_outcomes_are_authenticated_and_unknown_is_not_noncommitment() {
    let (mut handler, mut dispatcher, mut host) = connected();
    let target = RequestId::from_bytes([42; 16]);
    for (seq, outcome) in [
        ManagementOperationStatus::Committed {
            management_sequence: 7,
            revision: 9,
        },
        ManagementOperationStatus::Unknown,
    ]
    .into_iter()
    .enumerate()
    {
        handler.outcome = outcome;
        let request = RequestId::from_bytes([50 + seq as u8; 16]);
        let wire = signed_query(&mut host, request, target, seq as u64);
        let response =
            dispatch(&mut dispatcher, &mut handler, &wire, 200 + seq as u64 * 100).unwrap();
        let envelope = Envelope::parse(&response, EnvelopeKind::DeviceResponse).unwrap();
        host.authenticate_response(envelope.map(), request, "OP_STATUS", seq as u64)
            .unwrap();
        assert_eq!(
            envelope.map().required("seq").unwrap().uint().unwrap(),
            seq as u64
        );
        match outcome {
            ManagementOperationStatus::Committed {
                management_sequence,
                revision,
            } => {
                assert_eq!(
                    envelope.map().required("status").unwrap().text().unwrap(),
                    "OK"
                );
                assert_eq!(
                    envelope
                        .payload()
                        .required("management_sequence")
                        .unwrap()
                        .uint()
                        .unwrap(),
                    management_sequence
                );
                assert_eq!(
                    envelope
                        .payload()
                        .required("revision")
                        .unwrap()
                        .uint()
                        .unwrap(),
                    revision
                );
            }
            ManagementOperationStatus::Unknown => {
                assert_eq!(
                    envelope.map().required("status").unwrap().text().unwrap(),
                    "UNKNOWN"
                );
                assert_eq!(
                    envelope
                        .payload()
                        .required("request")
                        .unwrap()
                        .bytes()
                        .unwrap(),
                    target.as_bytes()
                );
                assert!(
                    envelope
                        .payload()
                        .get("management_sequence")
                        .unwrap()
                        .is_none()
                );
            }
        }
    }
}

#[test]
fn operation_status_checks_current_credential_mac_session_and_replay() {
    for failure in 0..5 {
        let (mut handler, mut dispatcher, mut host) = connected();
        let request = RequestId::from_bytes([51; 16]);
        let target = RequestId::from_bytes([42; 16]);
        let mut wire = signed_query(&mut host, request, target, 0);
        match failure {
            0 => handler.epoch = CredentialEpoch::new(1),
            1 => handler.revoked = true,
            2 => wire = query(host.session_id(), request, target, 0, [0; 32]),
            3 => wire = query(&[0; 16], request, target, 0, [0; 32]),
            4 => {
                let response = dispatch(&mut dispatcher, &mut handler, &wire, 200).unwrap();
                host.authenticate_response(map(&response), request, "OP_STATUS", 0)
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let error = dispatch(&mut dispatcher, &mut handler, &wire, 300).unwrap_err();
        assert_eq!(
            error.status,
            if failure == 4 {
                Status::Replay
            } else {
                Status::AuthFailed
            }
        );
    }
}

#[test]
fn operation_status_response_is_bound_to_query_not_target_request() {
    let (mut handler, mut dispatcher, mut host) = connected();
    let request = RequestId::from_bytes([51; 16]);
    let target = RequestId::from_bytes([42; 16]);
    let wire = signed_query(&mut host, request, target, 0);
    let response = dispatch(&mut dispatcher, &mut handler, &wire, 200).unwrap();
    assert!(
        host.authenticate_response(map(&response), target, "OP_STATUS", 0)
            .is_err()
    );
}
