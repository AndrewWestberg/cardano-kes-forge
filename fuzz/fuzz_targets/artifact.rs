#![no_main]
use kes_core::cbor::{Encoder, Value};
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

fn initialize() {
    INIT.call_once(|| {
        // The no-argument callback has no borrowed state and cannot unwind.
        if unsafe { libc::atexit(summary) } != 0 {
            std::process::exit(2);
        }
    });
}

fn check(value: bool) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !value {
        VIOLATIONS.fetch_add(1, Ordering::Relaxed);
        std::process::exit(1);
    }
}

fuzz_target!(|data: &[u8]| {
    initialize();
    if data.len() > kes_protocol::MAX_BACKUP_BYTES {
        check(matches!(
            kes_protocol::backup::BackupArtifact::parse(data),
            Err(kes_protocol::Error::Oversize)
        ));
        return;
    }
    let Ok(artifact) = kes_protocol::backup::BackupArtifact::parse(data) else {
        return;
    };
    check(data.len() <= kes_protocol::MAX_BACKUP_BYTES);
    check(artifact.encoded() == data);
    let map = artifact.map();
    check(map.required("version").unwrap().uint().unwrap() == 1);
    check(map.required("kem").unwrap().uint().unwrap() == 32);
    check(map.required("kdf").unwrap().uint().unwrap() == 1);
    check(map.required("aead").unwrap().uint().unwrap() == 3);
    check(map.required("period").unwrap().uint().unwrap() == 0);
    check(map.required("ciphertext").unwrap().bytes().unwrap().len() == 624);

    let mut storage = [0; kes_protocol::MAX_BACKUP_BYTES];
    let mut encoder = Encoder::new(&mut storage);
    encoder.value(Value::parse(&data[8..]).unwrap()).unwrap();
    let canonical = encoder.finish().unwrap();
    check(canonical.encoded() == &data[8..]);
    check(
        kes_protocol::backup::BackupArtifact::parse(data)
            .unwrap()
            .encoded()
            == data,
    );
});
