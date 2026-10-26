#![no_main]
use kes_core::cbor::{Encoder, Value};
use kes_protocol::{Envelope, EnvelopeKind as K, Error, MAX_FRAME_BYTES, Receiver};
use libfuzzer_sys::fuzz_target;
use std::sync::{
    Once,
    atomic::{AtomicU64, Ordering},
};
static CHECKS: AtomicU64 = AtomicU64::new(0);
static VIOLATIONS: AtomicU64 = AtomicU64::new(0);
static INIT: Once = Once::new();
extern "C" fn summary() {
    println!(
        "KES_FUZZ_SUMMARY {{\"version\":1,\"semantic_checks\":{},\"violations\":{}}}",
        CHECKS.load(Ordering::Relaxed),
        VIOLATIONS.load(Ordering::Relaxed)
    );
}
fn check(ok: bool) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        VIOLATIONS.fetch_add(1, Ordering::Relaxed);
        std::process::exit(1);
    }
}
fn initialize() {
    INIT.call_once(|| {
        // libc invokes this no-argument callback once on normal libFuzzer exit.
        // No memory is dereferenced across the FFI and the callback never unwinds.
        let result = unsafe { libc::atexit(summary) };
        if result != 0 {
            std::process::exit(2);
        }
    });
}
fn canonical(value: Value<'_>, out: &mut Encoder<'_>) {
    let raw = value.encoded();
    match raw[0] >> 5 {
        0 => out.uint(value.uint().unwrap()).unwrap(),
        2 => out.bytes(value.bytes().unwrap()).unwrap(),
        3 => out.text(value.text().unwrap()).unwrap(),
        4 => {
            let array = value.array().unwrap();
            let count = array.count();
            out.array(count).unwrap();
            for v in value.array().unwrap() {
                canonical(v, out);
            }
        }
        5 => {
            let map = value.map().unwrap();
            out.map(map.len()).unwrap();
            for field in map {
                let (k, v) = field.unwrap();
                out.text(k).unwrap();
                canonical(v, out);
            }
        }
        7 => {
            if value.is_null() {
                out.null().unwrap();
            } else {
                out.boolean(value.boolean().unwrap()).unwrap();
            }
        }
        _ => check(false),
    }
}
fn head(major: u8, n: u64, out: &mut Vec<u8>) {
    let mut h = [0; 9];
    let len = kes_core::cbor::encode_head(major, n, &mut h);
    out.extend_from_slice(&h[..len]);
}
fn uint(n: u64) -> Vec<u8> {
    let mut out = vec![];
    head(0, n, &mut out);
    out
}
fn bytes(data: &[u8]) -> Vec<u8> {
    let mut out = vec![];
    head(2, data.len() as u64, &mut out);
    out.extend_from_slice(data);
    out
}
fn text(data: &str) -> Vec<u8> {
    let mut out = vec![];
    head(3, data.len() as u64, &mut out);
    out.extend_from_slice(data.as_bytes());
    out
}
fn map(fields: Vec<(&str, Vec<u8>)>) -> Vec<u8> {
    let mut fields: Vec<_> = fields.into_iter().map(|(k, v)| (text(k), v)).collect();
    fields.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = vec![];
    head(5, fields.len() as u64, &mut out);
    for (k, v) in fields {
        out.extend(k);
        out.extend(v);
    }
    out
}
fn sign(message: &[u8], pool: bool, extra: bool) -> Vec<u8> {
    let network = map(vec![
        ("network_magic", uint(42)),
        ("shelley_genesis_digest", bytes(&[0; 32])),
        ("slots_per_kes_period", uint(1)),
        ("max_kes_evolutions", uint(64)),
    ]);
    let mut payload = vec![
        ("generation", bytes(&[0; 16])),
        ("certificate_digest", bytes(&[0; 32])),
        ("absolute_period", uint(1)),
        ("network", network),
        ("message", bytes(message)),
    ];
    if extra {
        payload.push(("unexpected", uint(0)));
    }
    map(vec![
        ("version", uint(1)),
        ("op", text("SIGN")),
        ("device", bytes(&[0; 16])),
        ("pool", if pool { bytes(&[0; 28]) } else { vec![0xf6] }),
        (
            "incarnation",
            if pool { bytes(&[0; 16]) } else { vec![0xf6] },
        ),
        ("session", bytes(&[0; 16])),
        ("seq", uint(1)),
        ("request", bytes(&[0; 16])),
        ("budget_ms", uint(500)),
        ("payload", map(payload)),
        ("mac", bytes(&[0; 32])),
    ])
}
fuzz_target!(|data: &[u8]| {
    initialize();
    if let Ok(value) = Value::parse(data) {
        // CBOR maps use text keys in this protocol; reject other key kinds before
        // attempting the schema-specific re-encoder (generic CBOR is not a frame).
        if let Ok(map) = value.map()
            && map.clone().all(|field| field.is_ok())
        {
            let mut storage = [0; MAX_FRAME_BYTES];
            let mut writer = Encoder::new(&mut storage);
            canonical(value, &mut writer);
            let rebuilt = writer.finish().unwrap();
            check(rebuilt.encoded() == data);
        }
    }
    {
        let mut storage = [0; MAX_FRAME_BYTES];
        let mut receiver = Receiver::new(&mut storage);
        let split = data.first().map_or(0, |b| usize::from(*b).min(data.len()));
        let received = receiver.push(&data[..split], 0).and_then(|first| {
            receiver
                .push(&data[first..], 1)
                .map(|second| first + second)
        });
        match received {
            Ok(consumed) => {
                check(consumed <= data.len());
                if let Some(body) = receiver.complete() {
                    check(consumed == body.len() + 4);
                    check(body == &data[4..consumed]);
                    if let Ok(frame) = kes_protocol::decode_frame(&data[..consumed]) {
                        check(frame.encoded() == body);
                    }
                }
            }
            Err(Error::Oversize) => {
                check(data.len() >= 4);
                let n = u32::from_be_bytes(data[..4].try_into().unwrap());
                check(n > MAX_FRAME_BYTES as u32);
            }
            Err(Error::InvalidLength) => {
                check(data.len() >= 4);
                check(data[..4] == [0, 0, 0, 0]);
            }
            Err(_) => check(false),
        }
    }
    for kind in [
        K::DeviceRequest,
        K::DeviceResponse,
        K::LocalRequest,
        K::LocalResponse,
        K::InfoRequest,
        K::InfoResponse,
        K::OpenRequest,
        K::OpenResponse,
    ] {
        if let Ok(envelope) = Envelope::parse(data, kind) {
            check(envelope.encoded() == data);
            let mut storage = [0; MAX_FRAME_BYTES];
            let mut writer = Encoder::new(&mut storage);
            canonical(Value::parse(envelope.encoded()).unwrap(), &mut writer);
            check(writer.finish().unwrap().encoded() == data);
            if envelope.operation == kes_protocol::Operation::Sign
                && matches!(kind, K::DeviceRequest | K::LocalRequest)
            {
                let message = envelope.message().unwrap();
                check(message.len() <= 4096);
                check(
                    message.as_ptr() as usize >= data.as_ptr() as usize
                        && message.as_ptr() as usize + message.len()
                            <= data.as_ptr() as usize + data.len(),
                );
            }
        }
    }
    // Every iteration exercises both accepted exact raw content and adversarial
    // operation boundaries, even when mutations are not valid CBOR.
    let message = &data[..data.len().min(4096)];
    let wire = sign(message, true, false);
    let parsed = Envelope::parse(&wire, K::DeviceRequest);
    check(parsed.is_ok());
    check(parsed.unwrap().message().unwrap() == message);
    check(Envelope::parse(&sign(message, false, false), K::DeviceRequest).is_err());
    check(Envelope::parse(&sign(message, true, true), K::DeviceRequest).is_err());
    check(matches!(
        Envelope::parse(&sign(&[0; 4097], true, false), K::DeviceRequest),
        Err(Error::InvalidLength)
    ));
    check(kes_protocol::operations::validate_certificate(&[0; 1025]) == Err(Error::Oversize));
    check(
        kes_protocol::backup::BackupArtifact::parse(&[0; 2049]).err() == Some(Error::Oversize),
    );
    if let Ok(artifact) = kes_protocol::backup::BackupArtifact::parse(data) {
        check(data.len() <= 2048);
        check(artifact.encoded() == data);
        let mut storage = [0; MAX_FRAME_BYTES];
        let mut writer = Encoder::new(&mut storage);
        canonical(Value::parse(artifact.map().encoded()).unwrap(), &mut writer);
        check(writer.finish().unwrap().encoded() == &data[8..]);
    }
    if kes_protocol::operations::validate_certificate(data).is_ok() {
        check(data.len() <= 1024);
        let mut outer = Value::parse(data).unwrap().array().unwrap();
        let fields = outer.next().unwrap();
        check(outer.next().unwrap().bytes().unwrap().len() == 32);
        check(outer.next().is_none());
        check(fields.array().unwrap().count() == 4);
    }
    let mut storage = [0; MAX_FRAME_BYTES];
    let mut rx = Receiver::new(&mut storage);
    check(rx.push(&[0], 0) == Ok(1));
    check(rx.push(&[0], 1999) == Ok(1));
    check(rx.push(&[0], 2000) == Err(Error::Timeout));
    rx.reset();
    check(rx.push(&[0, 0, 32, 1], 0) == Err(Error::Oversize));
    rx.reset();
    let mut frame = vec![];
    frame.extend_from_slice(&(wire.len() as u32).to_be_bytes());
    frame.extend_from_slice(&wire);
    let split = if data.is_empty() {
        0
    } else {
        usize::from(data[0]).min(frame.len())
    };
    check(rx.push(&frame[..split], 0) == Ok(split));
    check(rx.push(&frame[split..], 1) == Ok(frame.len() - split));
    check(rx.complete() == Some(wire.as_slice()));
    let mut trailing = wire.clone();
    trailing.push(0);
    check(Envelope::parse(&trailing, K::DeviceRequest).is_err());
    check(Value::parse(&[0xa2, 0x61, b'a', 0, 0x61, b'a', 1]).is_err());
    check(Value::parse(&[0x18, 0x17]).is_err());
    check(Value::parse(&[0x81, 0x81, 0x81, 0x81, 0x81, 0]).is_err());
});
