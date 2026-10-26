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
#[allow(dead_code)]
#[path = "../../../firmware/src/usb.rs"]
mod usb;

use kes_core::{
    activation::OperationError, cbor::encode_head, certificate::CertificateError,
    journal::JournalError, state::StateError,
};
use kes_protocol::{ErrorScope, MAX_FRAME_BYTES, Status};
use usb::{
    CommandError, HandlerResult, ReceiveStatus, SecureRequestHandler, UsbCause, UsbDispatcher,
};

fn head(major: u8, n: u64, out: &mut Vec<u8>) {
    let mut encoded = [0; 9];
    let length = encode_head(major, n, &mut encoded);
    out.extend_from_slice(&encoded[..length]);
}

fn uint(n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    head(0, n, &mut out);
    out
}

fn bytes(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    head(2, value.len() as u64, &mut out);
    out.extend_from_slice(value);
    out
}

fn text(value: &str) -> Vec<u8> {
    let mut out = Vec::new();
    head(3, value.len() as u64, &mut out);
    out.extend_from_slice(value.as_bytes());
    out
}

fn map(fields: Vec<(&str, Vec<u8>)>) -> Vec<u8> {
    let mut fields: Vec<_> = fields
        .into_iter()
        .map(|(key, value)| (text(key), value))
        .collect();
    fields.sort_by(|left, right| left.0.cmp(&right.0));
    let mut out = Vec::new();
    head(5, fields.len() as u64, &mut out);
    for (key, value) in fields {
        out.extend(key);
        out.extend(value);
    }
    out
}

fn network() -> Vec<u8> {
    map(vec![
        ("network_magic", uint(42)),
        ("shelley_genesis_digest", bytes(&[3; 32])),
        ("slots_per_kes_period", uint(10)),
        ("max_kes_evolutions", uint(64)),
    ])
}

fn sign_request() -> Vec<u8> {
    map(vec![
        ("version", uint(1)),
        ("op", text("SIGN")),
        ("device", bytes(&[1; 16])),
        ("pool", bytes(&[2; 28])),
        ("incarnation", bytes(&[3; 16])),
        ("session", bytes(&[4; 16])),
        ("seq", uint(0)),
        ("request", bytes(&[5; 16])),
        ("budget_ms", uint(500)),
        (
            "payload",
            map(vec![
                ("generation", bytes(&[6; 16])),
                ("certificate_digest", bytes(&[7; 32])),
                ("absolute_period", uint(8)),
                ("network", network()),
                ("message", bytes(b"exact signing bytes")),
            ]),
        ),
        ("mac", bytes(&[8; 32])),
    ])
}

fn error_response() -> Vec<u8> {
    map(vec![
        ("version", uint(1)),
        ("op", text("SIGN")),
        ("device", bytes(&[1; 16])),
        ("pool", bytes(&[2; 28])),
        ("incarnation", bytes(&[3; 16])),
        ("session", bytes(&[4; 16])),
        ("seq", uint(0)),
        ("request_seq", uint(0)),
        ("request", bytes(&[5; 16])),
        ("status", text("AUTH_FAILED")),
        (
            "payload",
            map(vec![
                ("scope", text("pool")),
                ("diagnostic", text("rejected")),
            ]),
        ),
        ("mac", bytes(&[9; 32])),
    ])
}

fn frame(body: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(body.len() + 4);
    framed.extend_from_slice(&(body.len() as u32).to_be_bytes());
    framed.extend_from_slice(body);
    framed
}

#[derive(Clone, Copy)]
enum Mode {
    Respond,
    CommandError,
    InvalidResponse,
    Late,
}

struct Handler {
    mode: Mode,
    calls: usize,
}

impl SecureRequestHandler for Handler {
    fn handle(
        &mut self,
        request: kes_protocol::Envelope<'_>,
        response: &mut [u8; MAX_FRAME_BYTES],
        lease: scheduler::RequestLease,
        _scheduler: &mut scheduler::Scheduler,
    ) -> Result<HandlerResult, CommandError> {
        self.calls += 1;
        assert_eq!(request.message().unwrap(), b"exact signing bytes");
        assert_eq!(lease.deadline_ms(), 600);
        match self.mode {
            Mode::Respond | Mode::Late => {
                let encoded = error_response();
                response[..encoded.len()].copy_from_slice(&encoded);
                Ok(HandlerResult {
                    response_length: encoded.len(),
                    completed_at_ms: if matches!(self.mode, Mode::Late) {
                        600
                    } else {
                        101
                    },
                })
            }
            Mode::CommandError => Err(CommandError {
                scope: ErrorScope::Pool,
                status: Status::AuthFailed,
            }),
            Mode::InvalidResponse => {
                response[0] = 0xff;
                Ok(HandlerResult {
                    response_length: 1,
                    completed_at_ms: 101,
                })
            }
        }
    }
}

fn admit(dispatcher: &mut UsbDispatcher) {
    let framed = frame(&sign_request());
    assert_eq!(
        dispatcher.receive(&framed[..3], 99).unwrap().status,
        ReceiveStatus::Pending
    );
    let progress = dispatcher.receive(&framed[3..], 100).unwrap();
    assert_eq!(progress.consumed, framed.len() - 3);
    assert_eq!(progress.status, ReceiveStatus::Ready);
}

#[test]
fn dispatch_copies_one_exact_body_and_returns_a_separate_prefix() {
    let mut dispatcher = UsbDispatcher::new();
    admit(&mut dispatcher);
    let busy = dispatcher.receive(&[0], 100).unwrap_err();
    assert_eq!(busy.scope, ErrorScope::Device);
    assert_eq!(busy.status, Status::Busy);

    let mut handler = Handler {
        mode: Mode::Respond,
        calls: 0,
    };
    let mut output = [0; MAX_FRAME_BYTES];
    let response = dispatcher.dispatch(100, &mut output, &mut handler).unwrap();
    assert_eq!(response.prefix, (response.body_length as u32).to_be_bytes());
    assert_eq!(&output[..response.body_length], error_response());
    assert_eq!(handler.calls, 1);
    assert!(!dispatcher.scheduler().request_active());
}

#[test]
fn handler_response_and_deadline_failures_release_single_flight_state() {
    let mut dispatcher = UsbDispatcher::new();
    let mut output = [0; MAX_FRAME_BYTES];

    admit(&mut dispatcher);
    let mut rejected = Handler {
        mode: Mode::CommandError,
        calls: 0,
    };
    let error = dispatcher
        .dispatch(100, &mut output, &mut rejected)
        .unwrap_err();
    assert_eq!(error.scope, ErrorScope::Pool);
    assert_eq!(error.status, Status::AuthFailed);
    assert!(matches!(error.cause, UsbCause::Command(_)));
    assert!(!dispatcher.scheduler().request_active());

    admit(&mut dispatcher);
    let mut invalid = Handler {
        mode: Mode::InvalidResponse,
        calls: 0,
    };
    assert_eq!(
        dispatcher
            .dispatch(100, &mut output, &mut invalid)
            .unwrap_err()
            .status,
        Status::DeviceUnavailable
    );
    assert!(!dispatcher.scheduler().request_active());

    admit(&mut dispatcher);
    let mut late = Handler {
        mode: Mode::Late,
        calls: 0,
    };
    assert_eq!(
        dispatcher
            .dispatch(100, &mut output, &mut late)
            .unwrap_err()
            .status,
        Status::DeadlineExceeded
    );
    assert!(!dispatcher.scheduler().request_active());

    admit(&mut dispatcher);
    let mut valid = Handler {
        mode: Mode::Respond,
        calls: 0,
    };
    dispatcher.dispatch(100, &mut output, &mut valid).unwrap();
}

#[test]
fn operation_failures_keep_pool_scope_and_stable_statuses() {
    assert_eq!(
        CommandError::from_operation(
            ErrorScope::Pool,
            OperationError::State(StateError::Unauthorized),
        ),
        CommandError {
            scope: ErrorScope::Pool,
            status: Status::AuthFailed,
        }
    );
    assert_eq!(
        CommandError::from_operation(
            ErrorScope::Pool,
            OperationError::State(StateError::Certificate(CertificateError::Expired)),
        )
        .status,
        Status::Expired
    );
    assert_eq!(
        CommandError::from_operation(
            ErrorScope::Pool,
            OperationError::Journal(JournalError::Flash),
        )
        .status,
        Status::DeviceUnavailable
    );
}
