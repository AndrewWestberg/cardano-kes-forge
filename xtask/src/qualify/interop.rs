//! Offline disposable-key interoperability. This never contacts or writes a device.
//! `Inputs` pins must come from the operator's authenticated generation/recovery
//! handoff, not from unauthenticated USB INFO. Success is not complete T051:
//! device-side certification, live network authorization and artifact retrieval
//! across device evolution still require their authenticated hardware campaign.
use crate::oracles::{self, Baseline, Oracle, SecretState};
use ed25519_dalek::{Signature, VerifyingKey};
use kes_core::cbor::Encoder;
use kes_protocol::backup::BackupArtifact;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};
use zeroize::Zeroizing;

type Result<T, E = String> = std::result::Result<T, E>;
const INVALID: &str =
    "interop prerequisite or native comparison failed (private inputs suppressed)";

/// All material must be disposable. Public pins are independently authenticated
/// operator inputs. The certificate is a real cold-workstation-issued envelope.
/// Paths must be absolute, symlink-free and protected against replacement.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inputs {
    pub disposable_lab_authorized: bool,
    pub recovered_signing_key: PathBuf,
    pub verification_key: PathBuf,
    pub backup_artifact: PathBuf,
    pub certificate: PathBuf,
    pub device_id: [u8; 16],
    pub identity_public_key: [u8; 32],
    pub provisioning_evidence_sha256: [u8; 32],
    pub pool_id: [u8; 28],
    pub incarnation_id: [u8; 16],
    pub generation_id: [u8; 16],
    pub cold_verification_key: [u8; 32],
    pub certificate_counter: u64,
    pub certificate_start: u64,
}

#[derive(Serialize)]
pub struct Report {
    pub schema_version: u8,
    pub verdict: &'static str,
    pub complete_t051: bool,
    pub public_inputs: Value,
    pub native_oracles: Vec<Value>,
    pub cases: Vec<&'static str>,
    pub not_exercised: Vec<&'static str>,
}

struct Envelope<'a> {
    kind: &'a str,
    description: &'a str,
    cbor_hex: &'a str,
}

/// Returns public evidence only. Does not publish a report or private material.
/// Native transport errors propagate; they are never treated as negative passes.
pub fn run(inputs: &Inputs) -> Result<Report> {
    require(inputs.disposable_lab_authorized)?;
    oracles::protect_memory()?; // Must precede opening/reading any private file.
    let cli = Oracle::pinned(Baseline::Cli114)?;
    let node = Oracle::pinned(Baseline::Node1113)?;
    let oracles = [&cli, &node];
    let vk_json = read_protected(&inputs.verification_key, false, 4096)?;
    let artifact_bytes = read_protected(&inputs.backup_artifact, false, 2048)?;
    let certificate = read_protected(&inputs.certificate, false, 4096)?;
    let vk = cli.validate_vk_file(&vk_json)?;
    require(node.validate_vk_file(&vk_json)? == vk)?;
    authenticate_artifact(inputs, &artifact_bytes, &vk)?;
    require(
        kes_core::types::PoolId::from_cold_verification_key(&inputs.cold_verification_key)
            .as_bytes()
            == &inputs.pool_id,
    )?;
    let expected_signable =
        cli.opcert_signable(&vk, inputs.certificate_counter, inputs.certificate_start)?;
    require(
        node.opcert_signable(&vk, inputs.certificate_counter, inputs.certificate_start)?
            == expected_signable,
    )?;
    for oracle in oracles {
        let checked = oracle.validate_certificate_file(&certificate)?;
        require(
            checked.valid
                && checked.cold_vk == inputs.cold_verification_key
                && checked.signable == expected_signable,
        )?;
    }
    let bad_certificate = corrupt_certificate_signature(&certificate)?;
    for oracle in oracles {
        require(!oracle.validate_certificate_file(&bad_certificate)?.valid)?;
        // Real native issuance is an independent disposable-cold-key check,
        // never substituted for the operator's device-bound certificate above.
        let issued = oracle.issue_disposable_certificate(
            &vk,
            inputs.certificate_counter,
            inputs.certificate_start,
        )?;
        for verifier in oracles {
            let checked = verifier.validate_certificate_file(&issued)?;
            require(checked.valid && checked.signable == expected_signable)?;
        }
    }
    let secret_json = read_protected(&inputs.recovered_signing_key, true, 4096)?;
    for oracle in oracles {
        require(oracle.validate_signing_key_file(&secret_json)? == vk)?;
    }
    // This closed borrowed parser never allocates decoded secret strings, even
    // on malformed input. Escaped strings are intentionally refused.
    let envelope = private_envelope(&secret_json)?;
    require(envelope.kind == "KesSigningKey_ed25519_kes_2^6")?;
    let _ = envelope.description;
    require(envelope.cbor_hex.len() == 1222 && envelope.cbor_hex.starts_with("590260"))?;
    let mut canonical = Zeroizing::new([0u8; 608]);
    decode_hex(&envelope.cbor_hex.as_bytes()[6..], &mut canonical[..])?;
    let mut states = [
        SecretState::from_bytes(&canonical[..])?,
        SecretState::from_bytes(&canonical[..])?,
    ];
    drop(canonical);
    drop(secret_json);
    let mut transcript = Sha256::new();
    for period in 0..64u8 {
        require(states[0].as_bytes() == states[1].as_bytes())?;
        let message = format!(
            "cardano-kes-forge/disposable-interop/v1:{}:{period}",
            hex(&Sha256::digest(&artifact_bytes))
        );
        let mut altered = message.as_bytes().to_vec();
        altered[0] ^= 1;
        for (producer, state) in oracles.iter().zip(states.iter()) {
            require(producer.derive_vk(state)? == vk)?;
            let signature = producer.sign(state, period, message.as_bytes())?;
            let mut damaged = signature;
            damaged[0] ^= 1;
            let mut wrong_vk = vk;
            wrong_vk[0] ^= 1;
            for verifier in oracles {
                require(verifier.verify(&vk, period, message.as_bytes(), &signature)?)?;
                require(!verifier.verify(&vk, period, &altered, &signature)?)?;
                require(!verifier.verify(&vk, period, message.as_bytes(), &damaged)?)?;
                require(!verifier.verify(&wrong_vk, period, message.as_bytes(), &signature)?)?;
            }
            transcript.update(signature);
        }
        let next_cli = cli.evolve(&states[0], period)?;
        let next_node = node.evolve(&states[1], period)?;
        if period == 63 {
            require(next_cli.is_none() && next_node.is_none())?;
        } else {
            states = [next_cli.ok_or(INVALID)?, next_node.ok_or(INVALID)?];
        }
    }
    // The oracle API itself refuses period 64 before native exchange. Do not
    // mislabel that host check as native period-64 signing verification.
    Ok(Report {
        schema_version: 1,
        verdict: "offline-native-interop-pass-device-network-campaign-pending",
        complete_t051: false,
        public_inputs: json!({
            "verification_key": hex(&vk), "verification_key_file_sha256": digest(&vk_json),
            "artifact_sha256": digest(&artifact_bytes), "certificate_sha256": digest(&certificate),
            "device_id": hex(&inputs.device_id), "identity_public_key": hex(&inputs.identity_public_key),
            "provisioning_evidence_sha256": hex(&inputs.provisioning_evidence_sha256),
            "pool_id": hex(&inputs.pool_id), "incarnation_id": hex(&inputs.incarnation_id),
            "generation_id": hex(&inputs.generation_id), "cold_verification_key": hex(&inputs.cold_verification_key),
            "certificate_counter": inputs.certificate_counter, "certificate_start": inputs.certificate_start,
            "signature_transcript_sha256": hex(&transcript.finalize()),
            "recovered_private_input_identity": "same derived VK, exact canonical period-zero state; private hashes deliberately omitted"
        }),
        native_oracles: vec![cli.identity, node.identity],
        cases: vec![
            "signed-artifact-and-operator-scope-binding",
            "both-native-conventional-vk-and-key-files",
            "all-64-identical-native-states",
            "both-native-cross-signature-verification",
            "altered-message-signature-key-rejection-every-period",
            "native-final-evolution-refuses-period-64",
            "operator-certificate-cold-signature-and-hot-key-binding",
            "altered-certificate-signature-rejected-both-native",
            "both-native-disposable-certificate-issuance",
        ],
        not_exercised: vec![
            "authenticated live-device generation and unchanged artifact retrieval across evolution",
            "device CERTIFY wrong-certificate/key/network rejection",
            "network is not a signed certificate field; enrollment/session authorization not tested",
            "native signing/verification at period 64 (public oracle API refuses it before exchange)",
            "unmodified cardano-cli executable issue-op-cert invocation (drivers use pinned native libraries)",
            "provisioning evidence contents and hardware release readiness; supplied digest is only an operator pin",
        ],
    })
}

fn authenticate_artifact(inputs: &Inputs, bytes: &[u8], vk: &[u8; 32]) -> Result<()> {
    let artifact = BackupArtifact::parse(bytes).map_err(|_| INVALID)?;
    let map = artifact.map();
    for (name, expected) in [
        ("device", &inputs.device_id[..]),
        ("pool", &inputs.pool_id[..]),
        ("incarnation", &inputs.incarnation_id[..]),
        ("generation", &inputs.generation_id[..]),
        ("verification_key", &vk[..]),
    ] {
        require(
            map.required(name)
                .and_then(|v| v.bytes())
                .map_err(|_| INVALID)?
                == expected,
        )?;
    }
    let signature: [u8; 64] = map
        .required("device_signature")
        .and_then(|v| v.bytes())
        .map_err(|_| INVALID)?
        .try_into()
        .map_err(|_| INVALID)?;
    let mut storage = [0u8; 2048];
    let mut encoder = Encoder::new(&mut storage);
    encoder.map(15).map_err(|_| INVALID)?;
    for item in map {
        let (name, value) = item.map_err(|_| INVALID)?;
        if name != "device_signature" {
            encoder.text(name).map_err(|_| INVALID)?;
            encoder.value(value).map_err(|_| INVALID)?;
        }
    }
    let unsigned = encoder.finish().map_err(|_| INVALID)?;
    let mut message = b"cardano-kes-forge/backup-signature/v1KESBKP01".to_vec();
    message.extend_from_slice(unsigned.encoded());
    VerifyingKey::from_bytes(&inputs.identity_public_key)
        .map_err(|_| INVALID)?
        .verify_strict(&message, &Signature::from_bytes(&signature))
        .map_err(|_| INVALID.to_owned())
}

fn corrupt_certificate_signature(json: &[u8]) -> Result<Vec<u8>> {
    let mut envelope: Value = serde_json::from_slice(json).map_err(|_| INVALID)?;
    let text = envelope["cborHex"].as_str().ok_or(INVALID)?;
    let mut bytes = vec![0u8; text.len() / 2];
    decode_hex(text.as_bytes(), &mut bytes)?;
    let mut outer = kes_core::cbor::Value::parse(&bytes)
        .map_err(|_| INVALID)?
        .array()
        .map_err(|_| INVALID)?;
    let mut body = outer.next().ok_or(INVALID)?.array().map_err(|_| INVALID)?;
    let signature = body.nth(3).ok_or(INVALID)?.bytes().map_err(|_| INVALID)?;
    require(signature.len() == 64)?;
    let offset = signature.as_ptr() as usize - bytes.as_ptr() as usize;
    bytes[offset] ^= 1;
    envelope["cborHex"] = Value::String(hex(&bytes));
    serde_json::to_vec(&envelope).map_err(|_| INVALID.to_owned())
}

// Walk held directory descriptors, never canonicalize-then-open. All buffers,
// including the private JSON read on I/O failures, have zeroizing ownership.
fn read_protected(path: &Path, private: bool, bound: u64) -> Result<Zeroizing<Vec<u8>>> {
    use rustix::fs::{Mode, OFlags, open, openat};
    require(path.is_absolute())?;
    let mut parts = path.components();
    require(matches!(parts.next(), Some(Component::RootDir)))?;
    let names: Vec<_> = parts
        .map(|part| match part {
            Component::Normal(name) => Ok(name),
            _ => Err(INVALID),
        })
        .collect::<std::result::Result<_, _>>()?;
    require(!names.is_empty())?;
    let mut directory = File::from(
        open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| INVALID)?,
    );
    let uid = rustix::process::geteuid().as_raw();
    for name in &names[..names.len() - 1] {
        directory = File::from(
            openat(
                &directory,
                *name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| INVALID)?,
        );
        let meta = directory.metadata().map_err(|_| INVALID)?;
        require(
            (meta.uid() == uid || meta.uid() == 0)
                && (meta.mode() & 0o022 == 0 || (meta.uid() == 0 && meta.mode() & 0o1000 != 0)),
        )?;
    }
    let file = File::from(
        openat(
            &directory,
            names[names.len() - 1],
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| INVALID)?,
    );
    let meta = file.metadata().map_err(|_| INVALID)?;
    require(meta.is_file() && meta.len() <= bound && meta.nlink() == 1)?;
    require(if private {
        meta.uid() == uid && meta.mode() & 0o777 == 0o600
    } else {
        (meta.uid() == uid || meta.uid() == 0) && meta.mode() & 0o022 == 0
    })?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(bound as usize + 1));
    file.take(bound + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| INVALID)?;
    require(bytes.len() as u64 == meta.len())?;
    Ok(bytes)
}
fn private_envelope(bytes: &[u8]) -> Result<Envelope<'_>> {
    struct Cursor<'a> {
        bytes: &'a [u8],
        position: usize,
    }
    impl<'a> Cursor<'a> {
        fn whitespace(&mut self) {
            while self
                .bytes
                .get(self.position)
                .is_some_and(|b| matches!(b, b' ' | b'\n' | b'\r' | b'\t'))
            {
                self.position += 1;
            }
        }
        fn token(&mut self, expected: u8) -> Result<()> {
            self.whitespace();
            require(self.bytes.get(self.position) == Some(&expected))?;
            self.position += 1;
            Ok(())
        }
        fn string(&mut self) -> Result<&'a str> {
            self.token(b'"')?;
            let start = self.position;
            while let Some(&byte) = self.bytes.get(self.position) {
                if byte == b'"' {
                    let value = std::str::from_utf8(&self.bytes[start..self.position])
                        .map_err(|_| INVALID)?;
                    self.position += 1;
                    return Ok(value);
                }
                require(byte >= 0x20 && byte != b'\\')?;
                self.position += 1;
            }
            Err(INVALID.into())
        }
    }
    let mut cursor = Cursor { bytes, position: 0 };
    cursor.token(b'{')?;
    let mut fields = [None; 3];
    for index in 0..3 {
        if index != 0 {
            cursor.token(b',')?;
        }
        let field = match cursor.string()? {
            "type" => 0,
            "description" => 1,
            "cborHex" => 2,
            _ => return Err(INVALID.into()),
        };
        require(fields[field].is_none())?;
        cursor.token(b':')?;
        fields[field] = Some(cursor.string()?);
    }
    cursor.token(b'}')?;
    cursor.whitespace();
    require(cursor.position == bytes.len())?;
    Ok(Envelope {
        kind: fields[0].ok_or(INVALID)?,
        description: fields[1].ok_or(INVALID)?,
        cbor_hex: fields[2].ok_or(INVALID)?,
    })
}
fn require(value: bool) -> Result<()> {
    if value { Ok(()) } else { Err(INVALID.into()) }
}
fn decode_hex(text: &[u8], output: &mut [u8]) -> Result<()> {
    require(text.len() == output.len() * 2)?;
    fn digit(byte: u8) -> Result<u8> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err(INVALID.into()),
        }
    }
    for (pair, destination) in text.as_chunks::<2>().0.iter().zip(output) {
        *destination = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    Ok(())
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 15) as usize] as char);
    }
    out
}
fn digest(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
