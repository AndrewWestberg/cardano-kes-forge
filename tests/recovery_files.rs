use cardano_kes_forge::backup::password;
use cardano_kes_forge::backup::publication::{
    self, Error as PublicationError, MemoryProtector, NoFault, PublicationFault,
};
use cardano_kes_forge::backup::recipient::{self, Entropy, Error, RecipientKeyFile};
use cardano_kes_forge::backup::recover::{self, Error as RecoverError, Expectations};
use ed25519_dalek::{Signer, SigningKey};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeS, Serializable, aead::ChaCha20Poly1305,
    kdf::HkdfSha256, kem::X25519HkdfSha256, setup_sender,
};
use kes_core::cbor::{Encoder, Value};
use kes_core::crypto::Generation;
use kes_core::types::{
    DeviceId, GenerationId, GenerationNumber, IncarnationId, KesLifetime, PoolId, RelativePeriod,
};
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{SeedableRng, TryCryptoRng, TryRngCore},
};
use std::fs;
use std::io;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct Directory(PathBuf);

impl Directory {
    fn new(mode: u32) -> Self {
        let nonce = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "kes-forge-recovery-contract-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        Self(path)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

struct TestProtector;

impl MemoryProtector for TestProtector {
    type Guard = ();

    fn protect(&self, _: &mut [u8]) -> Result<Self::Guard, PublicationError> {
        Ok(())
    }
}

struct FailedProtector;

impl MemoryProtector for FailedProtector {
    type Guard = ();

    fn protect(&self, _: &mut [u8]) -> Result<Self::Guard, PublicationError> {
        Err(PublicationError::MemoryProtection)
    }
}

struct InterruptBeforeLink;

impl PublicationFault for InterruptBeforeLink {
    fn before_link(&self) -> Result<(), PublicationError> {
        Err(PublicationError::Interrupted)
    }
}

struct InterruptAfterLink;

impl PublicationFault for InterruptAfterLink {
    fn before_link(&self) -> Result<(), PublicationError> {
        Ok(())
    }

    fn after_link(&self) -> Result<(), PublicationError> {
        Err(PublicationError::Interrupted)
    }
}

struct FailedEntropy;

impl TryRngCore for FailedEntropy {
    type Error = io::Error;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Err(io::Error::other("entropy unavailable"))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Err(io::Error::other("entropy unavailable"))
    }

    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Self::Error> {
        Err(io::Error::other("entropy unavailable"))
    }
}

impl TryCryptoRng for FailedEntropy {}

struct DeterministicEntropy(u8);

impl Entropy for DeterministicEntropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
        for byte in output {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

fn recipient() -> (recipient::RecipientPublic, RecipientKeyFile) {
    recipient::create(
        b"correct horse battery staple",
        &mut DeterministicEntropy(1),
    )
    .unwrap()
}

fn backup_header(recipient_public: &[u8; 32], recipient_id: &[u8; 32], vk: &[u8; 32]) -> Vec<u8> {
    let mut storage = [0; 512];
    let mut encoder = Encoder::new(&mut storage);
    encoder.map(13).unwrap();
    encoder.text("kdf").unwrap();
    encoder.uint(1).unwrap();
    encoder.text("kem").unwrap();
    encoder.uint(32).unwrap();
    encoder.text("aead").unwrap();
    encoder.uint(3).unwrap();
    encoder.text("pool").unwrap();
    encoder.bytes(&[0x20; 28]).unwrap();
    encoder.text("device").unwrap();
    encoder.bytes(&[0x10; 16]).unwrap();
    encoder.text("period").unwrap();
    encoder.uint(0).unwrap();
    encoder.text("version").unwrap();
    encoder.uint(1).unwrap();
    encoder.text("generation").unwrap();
    encoder.bytes(&[0x40; 16]).unwrap();
    encoder.text("incarnation").unwrap();
    encoder.bytes(&[0x30; 16]).unwrap();
    encoder.text("recipient_id").unwrap();
    encoder.bytes(recipient_id).unwrap();
    encoder.text("verification_key").unwrap();
    encoder.bytes(vk).unwrap();
    encoder.text("generation_number").unwrap();
    encoder.uint(1).unwrap();
    encoder.text("recipient_public_key").unwrap();
    encoder.bytes(recipient_public).unwrap();
    encoder.finish().unwrap().encoded().to_vec()
}

fn backup_map(
    recipient_public: &[u8; 32],
    recipient_id: &[u8; 32],
    vk: &[u8; 32],
    encapsulation: &[u8; 32],
    ciphertext: &[u8; 624],
    signature: Option<&[u8; 64]>,
) -> Vec<u8> {
    let mut storage = [0; kes_protocol::MAX_BACKUP_BYTES];
    let mut encoder = Encoder::new(&mut storage);
    encoder
        .map(if signature.is_some() { 16 } else { 15 })
        .unwrap();
    encoder.text("kdf").unwrap();
    encoder.uint(1).unwrap();
    encoder.text("kem").unwrap();
    encoder.uint(32).unwrap();
    encoder.text("aead").unwrap();
    encoder.uint(3).unwrap();
    encoder.text("pool").unwrap();
    encoder.bytes(&[0x20; 28]).unwrap();
    encoder.text("device").unwrap();
    encoder.bytes(&[0x10; 16]).unwrap();
    encoder.text("period").unwrap();
    encoder.uint(0).unwrap();
    encoder.text("version").unwrap();
    encoder.uint(1).unwrap();
    encoder.text("ciphertext").unwrap();
    encoder.bytes(ciphertext).unwrap();
    encoder.text("generation").unwrap();
    encoder.bytes(&[0x40; 16]).unwrap();
    encoder.text("incarnation").unwrap();
    encoder.bytes(&[0x30; 16]).unwrap();
    encoder.text("recipient_id").unwrap();
    encoder.bytes(recipient_id).unwrap();
    encoder.text("encapsulation").unwrap();
    encoder.bytes(encapsulation).unwrap();
    if let Some(signature) = signature {
        encoder.text("device_signature").unwrap();
        encoder.bytes(signature).unwrap();
    }
    encoder.text("verification_key").unwrap();
    encoder.bytes(vk).unwrap();
    encoder.text("generation_number").unwrap();
    encoder.uint(1).unwrap();
    encoder.text("recipient_public_key").unwrap();
    encoder.bytes(recipient_public).unwrap();
    encoder.finish().unwrap().encoded().to_vec()
}

fn recoverable_backup() -> (
    Vec<u8>,
    RecipientKeyFile,
    Expectations,
    [u8; kes_core::SIGNING_STATE_BYTES],
) {
    let (recipient_public, recipient_file) =
        recipient::create(b"recovery password", &mut DeterministicEntropy(11)).unwrap();

    let lifetime = KesLifetime::new(64).unwrap();
    let mut seed = [0x41; 32];
    let mut generation = Generation::begin(&mut seed, lifetime).unwrap();
    for _ in 0..64 {
        generation.step().unwrap();
    }
    let (key, _tree) = generation.finish().unwrap();
    let verification_key = key.verification_key().unwrap();
    let state = *key.canonical_state().unwrap().bytes();

    type Aead = ChaCha20Poly1305;
    type Kdf = HkdfSha256;
    type Kem = X25519HkdfSha256;
    let public = <Kem as KemTrait>::PublicKey::from_bytes(&recipient_public.public_key).unwrap();
    let header = backup_header(
        &recipient_public.public_key,
        &recipient_public.recipient_id,
        &verification_key,
    );
    let mut info = b"cardano-kes-forge/backup/v1".to_vec();
    info.extend_from_slice(&header);
    let mut aad = b"KESBKP01".to_vec();
    aad.extend_from_slice(&header);
    let mut rng = ChaCha20Rng::from_seed([0x42; 32]);
    let (encapsulation, mut sender) =
        setup_sender::<Aead, Kdf, Kem, _>(&OpModeS::Base, &public, &info, &mut rng).unwrap();
    let mut encrypted = state;
    let tag = sender.seal_in_place_detached(&mut encrypted, &aad).unwrap();
    let mut ciphertext = [0; 624];
    ciphertext[..608].copy_from_slice(&encrypted);
    ciphertext[608..].copy_from_slice(&tag.to_bytes());
    let encapsulation: [u8; 32] = encapsulation.to_bytes().into();
    let unsigned = backup_map(
        &recipient_public.public_key,
        &recipient_public.recipient_id,
        &verification_key,
        &encapsulation,
        &ciphertext,
        None,
    );
    let identity = SigningKey::from_bytes(&[0x51; 32]);
    let mut signed = b"cardano-kes-forge/backup-signature/v1".to_vec();
    signed.extend_from_slice(b"KESBKP01");
    signed.extend_from_slice(&unsigned);
    let signature = identity.sign(&signed).to_bytes();
    let artifact = [
        b"KESBKP01".as_slice(),
        backup_map(
            &recipient_public.public_key,
            &recipient_public.recipient_id,
            &verification_key,
            &encapsulation,
            &ciphertext,
            Some(&signature),
        )
        .as_slice(),
    ]
    .concat();
    (
        artifact,
        recipient_file,
        Expectations {
            device: [0x10; 16],
            pool: [0x20; 28],
            incarnation: [0x30; 16],
            generation: [0x40; 16],
            verification_key,
            identity_public_key: identity.verifying_key().to_bytes(),
        },
        state,
    )
}

#[test]
fn authenticated_backup_recovery_rejects_wrong_inputs_and_decodes_cardano_key() {
    let (artifact, recipient, expected, state) = recoverable_backup();
    let original_artifact = artifact.clone();
    let recovered =
        recover::recover(&artifact, &recipient, b"recovery password", expected).unwrap();
    assert_eq!(&recovered[..], &state);
    let envelope: serde_json::Value =
        serde_json::from_slice(&recover::cardano_envelope(&recovered).unwrap()).unwrap();
    assert_eq!(envelope["type"], "KesSigningKey_ed25519_kes_2^6");
    assert!(envelope["cborHex"].as_str().unwrap().starts_with("590260"));
    assert_eq!(envelope["cborHex"].as_str().unwrap().len(), 6 + 608 * 2);

    assert!(matches!(
        recover::recover(&artifact, &recipient, b"wrong password", expected),
        Err(RecoverError::WrongPassword)
    ));
    let (_, wrong_recipient) =
        recipient::create(b"recovery password", &mut DeterministicEntropy(99)).unwrap();
    assert!(matches!(
        recover::recover(&artifact, &wrong_recipient, b"recovery password", expected),
        Err(RecoverError::WrongRecipient)
    ));

    let artifact_map = Value::parse(&artifact[8..]).unwrap().map().unwrap();
    for (field, expected_error) in [
        ("ciphertext", RecoverError::InvalidSignature),
        ("device_signature", RecoverError::InvalidSignature),
    ] {
        let value = artifact_map.required(field).unwrap().bytes().unwrap();
        let offset = value.as_ptr() as usize - artifact.as_ptr() as usize;
        let mut altered = artifact.clone();
        altered[offset] ^= 1;
        assert_eq!(
            recover::recover(&altered, &recipient, b"recovery password", expected).err(),
            Some(expected_error)
        );
    }

    let mut wrong_binding = expected;
    wrong_binding.pool[0] ^= 1;
    assert!(matches!(
        recover::recover(&artifact, &recipient, b"recovery password", wrong_binding,),
        Err(RecoverError::WrongBinding)
    ));
    assert_eq!(artifact, original_artifact);

    let directory = Directory::new(0o700);
    let output = directory.0.join("kes.skey");
    recover::recover_to_file(
        &artifact,
        &recipient,
        b"recovery password",
        expected,
        &output,
    )
    .unwrap();
    assert_eq!(
        fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let published: serde_json::Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(published["type"], "KesSigningKey_ed25519_kes_2^6");
    assert_eq!(published["cborHex"].as_str().unwrap().len(), 6 + 608 * 2);
}

/// The gate seeds the implementation in a disposable workspace, not this
/// detector: mode selection never changes the expected authentication policy.
#[test]
fn artifact_output_sensitivity_uses_authenticated_recovery_and_no_clobber()
-> Result<(), &'static str> {
    let mode = std::env::var("KES_GATE_MODE").ok();
    let report = matches!(
        mode.as_deref(),
        Some("clean" | "seeded-artifact-authentication-or-publication")
    );
    let (artifact, recipient, expected, state) = recoverable_backup();
    let directory = Directory::new(0o700);
    let original = directory.0.join("original.skey");
    recover::recover_to_file(
        &artifact,
        &recipient,
        b"recovery password",
        expected,
        &original,
    )
    .map_err(|_| "authentic recovery failed")?;
    let envelope =
        recover::cardano_envelope(&state).map_err(|_| "conventional key envelope failed")?;
    if fs::read(&original).map_err(|_| "published key unavailable")? != envelope[..]
        || fs::metadata(&original)
            .map_err(|_| "published metadata unavailable")?
            .permissions()
            .mode()
            & 0o777
            != 0o600
    {
        return Err("authentic publication did not preserve the protected key");
    }
    let retry = recover::recover_to_file(
        &artifact,
        &recipient,
        b"recovery password",
        expected,
        &original,
    );
    if retry != Err(RecoverError::Publication(PublicationError::ExistingOutput))
        || fs::read(&original).map_err(|_| "original output unavailable")? != envelope[..]
    {
        return Err("recovery output was not no-clobber");
    }

    let signature = Value::parse(&artifact[8..])
        .map_err(|_| "fixture artifact invalid")?
        .map()
        .map_err(|_| "fixture artifact is not a map")?
        .required("device_signature")
        .map_err(|_| "fixture signature missing")?
        .bytes()
        .map_err(|_| "fixture signature invalid")?;
    let offset = signature.as_ptr() as usize - artifact.as_ptr() as usize;
    let mut corrupted = artifact.clone();
    corrupted[offset] ^= 1;
    let unauthenticated = directory.0.join("unauthenticated.skey");
    let result = recover::recover_to_file(
        &corrupted,
        &recipient,
        b"recovery password",
        expected,
        &unauthenticated,
    );
    let violation = match result {
        Err(RecoverError::InvalidSignature) if !unauthenticated.exists() => false,
        Ok(()) => {
            if fs::read(&unauthenticated).map_err(|_| "unauthenticated output unavailable")?
                != envelope[..]
            {
                return Err("unexpected unauthenticated output; no detection credit");
            }
            true
        }
        _ => return Err("unexpected recovery result; no authentication detection credit"),
    };
    if report {
        let mut measurements = serde_json::json!({
            "violations": u64::from(violation),
            "authentic_recovery": 1,
            "no_clobber_rejections": 1,
            "corrupted_signature_publications": u64::from(violation),
        });
        if violation {
            measurements["counterexample"] = serde_json::json!({
                "mode": "seeded-artifact-authentication-or-publication",
                "path": "backup.recover::recover_to_file",
                "observation": "a one-bit-corrupted device signature produced the complete conventional signing-key file",
                "disclosure": "public",
            });
        }
        println!(
            "KES_GATE_SUMMARY {}",
            serde_json::json!({
                "version": 1,
                "cases": 3,
                "scenarios": {"artifact-output": 3},
                "measurements": measurements,
            })
        );
    }
    if violation {
        return Err("unauthenticated plaintext publication detected");
    }
    Ok(())
}

#[test]
fn core_backup_producer_roundtrips_and_freezes_period_zero_artifact() {
    let (recipient_public, recipient_file) =
        recipient::create(b"producer password", &mut DeterministicEntropy(201)).unwrap();
    let lifetime = KesLifetime::new(64).unwrap();
    let mut seed = [0xd1; 32];
    let mut job = Generation::begin(&mut seed, lifetime).unwrap();
    for _ in 0..64 {
        job.step().unwrap();
    }
    let (mut key, tree) = job.finish().unwrap();
    let verified = tree.verify(&key.verification_key().unwrap()).unwrap();
    let verification_key = key.verification_key().unwrap();
    let identity = SigningKey::from_bytes(&[0xd2; 32]);
    let metadata = kes_core::backup::Metadata {
        device: DeviceId::from_bytes([0xd3; 16]),
        pool: PoolId::from_bytes([0xd4; 28]),
        incarnation: IncarnationId::from_bytes([0xd5; 16]),
        generation: GenerationId::from_bytes([0xd6; 16]),
        generation_number: GenerationNumber::new(9),
        recipient_public_key: recipient_public.public_key,
        recipient_id: recipient_public.recipient_id,
    };

    let mut wrong_recipient = metadata;
    wrong_recipient.recipient_id[0] ^= 1;
    assert_eq!(
        kes_core::backup::create(
            &key,
            wrong_recipient,
            &identity,
            &mut ChaCha20Rng::from_seed([0xd7; 32]),
        )
        .err(),
        Some(kes_core::backup::Error::InvalidRecipient)
    );
    assert_eq!(
        kes_core::backup::create(&key, metadata, &identity, &mut FailedEntropy).err(),
        Some(kes_core::backup::Error::Entropy)
    );

    let artifact = kes_core::backup::create(
        &key,
        metadata,
        &identity,
        &mut ChaCha20Rng::from_seed([0xd8; 32]),
    )
    .unwrap();
    let encoded = artifact.encoded().to_vec();
    kes_protocol::backup::BackupArtifact::parse(&encoded).unwrap();
    let recovered = recover::recover(
        &encoded,
        &recipient_file,
        b"producer password",
        Expectations {
            device: [0xd3; 16],
            pool: [0xd4; 28],
            incarnation: [0xd5; 16],
            generation: [0xd6; 16],
            verification_key,
            identity_public_key: identity.verifying_key().to_bytes(),
        },
    )
    .unwrap();
    assert_eq!(&recovered[..], key.canonical_state().unwrap().bytes());

    key.evolve_to(RelativePeriod::new(1).unwrap(), &verified)
        .unwrap();
    assert_eq!(artifact.encoded(), encoded);
}

#[test]
fn protected_recipient_roundtrip_and_rewrap_preserve_public_identity() {
    let (public, protected) = recipient();
    let original = protected.encoded().to_vec();
    let private = protected.unlock(b"correct horse battery staple").unwrap();
    assert_ne!(&private[..], &[0; 32]);
    assert!(protected.public().unwrap() == public);
    assert_eq!(protected.encoded(), original);
    assert!(matches!(
        protected.unlock(b"wrong password"),
        Err(Error::Authentication)
    ));
    assert_eq!(protected.encoded(), original);

    let replacement = protected
        .rewrap(
            b"correct horse battery staple",
            b"new long unique passphrase",
            &mut DeterministicEntropy(97),
        )
        .unwrap();
    assert!(replacement.public().unwrap() == public);
    assert_ne!(replacement.encoded(), original);
    assert!(matches!(
        replacement.unlock(b"correct horse battery staple"),
        Err(Error::Authentication)
    ));
    assert_eq!(
        &replacement.unlock(b"new long unique passphrase").unwrap()[..],
        &private[..]
    );
    assert_eq!(protected.encoded(), original);

    let public_json: serde_json::Value = serde_json::from_slice(&public.json().unwrap()).unwrap();
    assert_eq!(public_json["version"], 1);
    assert_eq!(public_json["algorithm"], "X25519");
    assert_eq!(public_json["publicKey"].as_str().unwrap().len(), 64);
    assert_eq!(public_json["recipientId"].as_str().unwrap().len(), 64);
}

#[test]
fn interrupted_password_rewrap_preserves_old_file_and_success_atomically_replaces_it() {
    let directory = Directory::new(0o700);
    let key_path = directory.0.join("recipient.key");
    let (public, protected) = recipient();
    fs::write(&key_path, protected.encoded()).unwrap();
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
    let original = protected.encoded().to_vec();
    assert_eq!(
        password::change_password_with(
            &key_path,
            b"correct horse battery staple",
            b"replacement password",
            &mut DeterministicEntropy(151),
            &InterruptBeforeLink,
        ),
        Err(password::Error::Publication(PublicationError::Interrupted))
    );
    assert_eq!(fs::read(&key_path).unwrap(), original);
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);

    password::change_password_with(
        &key_path,
        b"correct horse battery staple",
        b"replacement password",
        &mut DeterministicEntropy(177),
        &NoFault,
    )
    .unwrap();
    let installed = RecipientKeyFile::parse(fs::read(&key_path).unwrap()).unwrap();
    assert!(installed.public().unwrap() == public);
    assert_ne!(installed.encoded(), original);
    installed.unlock(b"replacement password").unwrap();
    assert!(matches!(
        installed.unlock(b"correct horse battery staple"),
        Err(Error::Authentication)
    ));
    assert_eq!(
        fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);
}

#[test]
fn altered_ciphertext_and_recipient_binding_fail_without_mutating_input() {
    let (_, protected) = recipient();
    let original = protected.encoded().to_vec();

    let ciphertext = Value::parse(&original[8..])
        .unwrap()
        .map()
        .unwrap()
        .required("ciphertext")
        .unwrap()
        .bytes()
        .unwrap();
    let offset = ciphertext.as_ptr() as usize - original.as_ptr() as usize;
    let mut altered_ciphertext = original.clone();
    altered_ciphertext[offset] ^= 1;
    let altered = RecipientKeyFile::parse(altered_ciphertext.clone()).unwrap();
    assert!(matches!(
        altered.unlock(b"correct horse battery staple"),
        Err(Error::Authentication)
    ));
    assert_eq!(altered.encoded(), altered_ciphertext);

    let mut altered_recipient = original.clone();
    let public = protected.public().unwrap();
    let offset = altered_recipient
        .windows(public.recipient_id.len())
        .position(|window| window == public.recipient_id)
        .unwrap();
    altered_recipient[offset] ^= 1;
    assert!(matches!(
        RecipientKeyFile::parse(altered_recipient),
        Err(Error::InvalidFormat)
    ));
    assert_eq!(protected.encoded(), original);
}

#[test]
fn hostile_kdf_parameters_are_rejected_before_password_work() {
    let (_, protected) = recipient();
    let original = protected.encoded().to_vec();
    let mut hostile = original.clone();
    let encoded_memory = [0x1a, 0x00, 0x01, 0x00, 0x00];
    let offset = hostile
        .windows(encoded_memory.len())
        .position(|window| window == encoded_memory)
        .unwrap();
    hostile[offset + 2] = 2;
    assert!(matches!(
        RecipientKeyFile::parse(hostile),
        Err(Error::UnsupportedParameters)
    ));
    assert_eq!(protected.encoded(), original);
}

#[test]
fn empty_or_non_utf8_passphrases_fail_without_entropy_use() {
    struct FailingEntropy;
    impl Entropy for FailingEntropy {
        fn fill(&mut self, _: &mut [u8]) -> Result<(), Error> {
            panic!("invalid passphrase must be rejected before entropy use")
        }
    }
    assert!(matches!(
        recipient::create(b"", &mut FailingEntropy),
        Err(Error::EmptyPassphrase)
    ));
    assert!(matches!(
        recipient::create(&[0xff], &mut FailingEntropy),
        Err(Error::InvalidPassphrase)
    ));
}

#[test]
fn plaintext_publication_is_no_replace_and_never_leaves_a_named_partial_file() {
    let directory = Directory::new(0o700);
    let output = directory.0.join("kes.skey");
    let mut secret = vec![0x91; 640];
    let expected = secret.clone();
    publication::publish_secret_with(&output, &mut secret, &TestProtector, &NoFault).unwrap();
    assert_eq!(fs::read(&output).unwrap(), expected);
    assert!(secret.iter().all(|byte| *byte == 0));
    assert_eq!(
        fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let mut replacement = vec![0x92; 640];
    assert_eq!(
        publication::publish_secret_with(&output, &mut replacement, &TestProtector, &NoFault,),
        Err(PublicationError::ExistingOutput)
    );
    assert!(replacement.iter().all(|byte| *byte == 0));
    assert_eq!(fs::read(&output).unwrap(), expected);

    let interrupted = directory.0.join("interrupted.skey");
    let mut interrupted_secret = vec![0x93; 640];
    assert_eq!(
        publication::publish_secret_with(
            &interrupted,
            &mut interrupted_secret,
            &TestProtector,
            &InterruptBeforeLink,
        ),
        Err(PublicationError::Interrupted)
    );
    assert!(interrupted_secret.iter().all(|byte| *byte == 0));
    assert!(!interrupted.exists());
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);

    let uncertain = directory.0.join("uncertain.skey");
    let mut uncertain_secret = vec![0x94; 640];
    assert_eq!(
        publication::publish_secret_with(
            &uncertain,
            &mut uncertain_secret,
            &TestProtector,
            &InterruptAfterLink,
        ),
        Err(PublicationError::DurabilityUncertain)
    );
    assert!(uncertain_secret.iter().all(|byte| *byte == 0));
    assert_eq!(fs::read(&uncertain).unwrap(), vec![0x94; 640]);
    let mut retry = vec![0x95; 640];
    assert_eq!(
        publication::publish_secret_with(&uncertain, &mut retry, &TestProtector, &NoFault),
        Err(PublicationError::ExistingOutput)
    );
    assert!(retry.iter().all(|byte| *byte == 0));
    assert_eq!(fs::read(&uncertain).unwrap(), vec![0x94; 640]);
}

#[test]
fn unsafe_paths_and_memory_protection_failure_publish_nothing() {
    let directory = Directory::new(0o700);
    let target = directory.0.join("target");
    fs::write(&target, b"preserved").unwrap();
    let link = directory.0.join("kes.skey");
    symlink(&target, &link).unwrap();
    let mut secret = vec![0xa1; 640];
    assert_eq!(
        publication::publish_secret_with(&link, &mut secret, &TestProtector, &NoFault),
        Err(PublicationError::ExistingOutput)
    );
    assert_eq!(fs::read(&target).unwrap(), b"preserved");

    let protected_failure = directory.0.join("memory-failed.skey");
    assert_eq!(
        publication::publish_secret_with(
            &protected_failure,
            &mut secret,
            &FailedProtector,
            &NoFault,
        ),
        Err(PublicationError::MemoryProtection)
    );
    assert!(!protected_failure.exists());

    let unsafe_directory = Directory::new(0o755);
    let unsafe_output = unsafe_directory.0.join("kes.skey");
    assert_eq!(
        publication::publish_secret_with(&unsafe_output, &mut secret, &TestProtector, &NoFault,),
        Err(PublicationError::UnsafeDirectory)
    );
    assert!(!unsafe_output.exists());
}
