use super::*;
use kes_core::cbor::{Encoder, Value};

fn payload(period: u64, generation: [u8; 16], lifecycle: &str, state_length: usize) -> Vec<u8> {
    let mut buffer = vec![0; 1024];
    let mut e = Encoder::new(&mut buffer);
    e.map(7).unwrap();
    e.text("state").unwrap(); e.bytes(&vec![0x53; state_length]).unwrap();
    e.text("health").unwrap(); e.text("healthy").unwrap();
    e.text("revision").unwrap(); e.uint(42).unwrap();
    e.text("lifecycle").unwrap(); e.text(lifecycle).unwrap();
    e.text("generation").unwrap(); e.bytes(&generation).unwrap();
    e.text("relative_period").unwrap(); e.uint(period).unwrap();
    e.text("certificate_digest").unwrap(); e.bytes(&[0x66; 32]).unwrap();
    let length = e.finish().unwrap().encoded().len();
    buffer.truncate(length);
    buffer
}

#[test]
fn current_state_format_preserves_identity_context_period_and_exact_bytes() {
    let bytes = payload(37, [4; 16], "active", 608);
    let mut output = [0; OUTPUT_BYTES];
    encode_output(&mut output, [1; 16], [2; 28], [3; 16], [4; 16],
        Value::parse(&bytes).unwrap().map().unwrap()).unwrap();
    assert_eq!(&output[..8], b"KESDEV01");
    assert_eq!(&output[8..24], &[1; 16]);
    assert_eq!(&output[24..52], &[2; 28]);
    assert_eq!(&output[52..68], &[3; 16]);
    assert_eq!(&output[68..84], &[4; 16]);
    assert_eq!(&output[84..92], &42u64.to_be_bytes());
    assert_eq!(output[92], 37);
    assert_eq!(&output[93..125], &[0x66; 32]);
    assert_eq!(&output[125..], &[0x53; 608]);
    assert_ne!(&output[..8], b"KESBKP01");
}

#[test]
fn rejects_wrong_generation_erased_lifecycle_and_nonexact_state_without_writing() {
    for (period, generation, lifecycle, length) in [
        (0, [5; 16], "active", 608), (64, [4; 16], "active", 608),
        (0, [4; 16], "expired", 608), (0, [4; 16], "retired", 608),
        (0, [4; 16], "staged", 608), (0, [4; 16], "active", 607),
        (0, [4; 16], "active", 609),
    ] {
        let bytes = payload(period, generation, lifecycle, length);
        let mut output = [0; OUTPUT_BYTES];
        assert_eq!(encode_output(&mut output, [1; 16], [2; 28], [3; 16], [4; 16],
            Value::parse(&bytes).unwrap().map().unwrap()), Err(Error::Integrity));
        assert_eq!(output, [0; OUTPUT_BYTES]);
    }
}
