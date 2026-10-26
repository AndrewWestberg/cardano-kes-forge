#![no_main]
use kes_core::cbor::{Encoder, Value};
use libfuzzer_sys::fuzz_target;

fn check(value: bool) {
    if !value {
        std::process::abort();
    }
}

fuzz_target!(|data: &[u8]| {
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
    check(kes_protocol::backup::BackupArtifact::parse(data)
        .unwrap()
        .encoded()
        == data);
});
