//! Host-executed operator transitions, not hardware-loss or remote-wipe evidence.
use cardano_kes_forge::backup::{
    recipient::{self, Entropy, RecipientKeyFile},
    recover::{self, Expectations},
};
use ed25519_dalek::{Signer, SigningKey};
use kes_core::{
    cbor::{Encoder, Value},
    credentials,
    crypto::{self, KesKey, PublicTreeBuffer, SUM6_V1},
    generation::{
        Admission, GenerationCoordinator, GenerationRequest, PublicObjectStore,
        begin_key_generation, get_backup,
    },
    management::{self, Action, SigningFields, Target},
    session::{
        DeviceHpkeKey, DeviceIdentityKey, OpenContext, Scope, SessionError, accept_open, begin_open,
    },
    state::{
        Actor, Enrollment, MAX_PUBLIC_OBJECT_BYTES, PoolRegistration, PublicObjectRef, StateError,
    },
    types::{
        AbsolutePeriod, CredentialEpoch, DeviceId, GenerationNumber, IncarnationId, KesLifetime,
        ManagementSequence, NetworkBinding, RequestId,
    },
};
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{RngCore, SeedableRng},
};
use std::{
    fs,
    io::Read,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};
use zeroize::Zeroizing;

const PASSWORD: &[u8] = b"disposable operator recovery passphrase";
static NEXT: AtomicU64 = AtomicU64::new(0);

// Same process-tree protection as xtask::oracles::protect_memory, without adding
// a dependency on the qualification runner to this integration test target.
fn protected_rng() -> ChaCha20Rng {
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable).unwrap();
    let membership = fs::read_to_string("/proc/self/cgroup").unwrap();
    let relative = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .expect("cgroup-v2 required");
    let path = Path::new(relative);
    assert!(path.is_absolute());
    assert!(!path.components().any(|part| matches!(
        part,
        std::path::Component::ParentDir | std::path::Component::CurDir
    )));
    let root = Path::new("/sys/fs/cgroup").join(path.strip_prefix("/").unwrap());
    for name in ["memory.swap.max", "memory.swap.current"] {
        assert_eq!(
            fs::read_to_string(root.join(name)).unwrap().trim(),
            "0",
            "fresh MemorySwapMax=0 disposable lab required"
        );
    }
    let mut seed = Zeroizing::new([0; 32]);
    fs::File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut seed[..])
        .unwrap();
    ChaCha20Rng::from_seed(*seed)
}

struct RecipientEntropy<'a>(&'a mut ChaCha20Rng);
impl Entropy for RecipientEntropy<'_> {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), recipient::Error> {
        self.0.fill_bytes(output);
        Ok(())
    }
}

// Storage adapter retains the real coordinator-produced public object; it does
// not synthesize an artifact, a signing result, or a protocol response.
#[derive(Default)]
struct ObjectStore {
    object: Option<(PublicObjectRef, Vec<u8>)>,
}
impl PublicObjectStore for ObjectStore {
    type Error = ();
    fn write(&mut self, reference: &PublicObjectRef, bytes: &[u8]) -> Result<(), ()> {
        self.object = Some((*reference, bytes.to_vec()));
        Ok(())
    }
    fn read(&mut self, reference: &PublicObjectRef, output: &mut [u8]) -> Result<usize, ()> {
        let (stored, bytes) = self.object.as_ref().ok_or(())?;
        if stored != reference || output.len() < bytes.len() {
            return Err(());
        }
        output[..bytes.len()].copy_from_slice(bytes);
        Ok(bytes.len())
    }
    fn discard(&mut self, reference: &PublicObjectRef) -> Result<(), ()> {
        if self.object.as_ref().map(|entry| &entry.0) != Some(reference) {
            return Err(());
        }
        self.object = None;
        Ok(())
    }
}

fn signing_key(rng: &mut ChaCha20Rng) -> SigningKey {
    let mut seed = Zeroizing::new([0; 32]);
    rng.fill_bytes(&mut *seed);
    SigningKey::from_bytes(&seed)
}
fn identity(rng: &mut ChaCha20Rng) -> DeviceIdentityKey {
    let mut seed = Zeroizing::new([0; 32]);
    rng.fill_bytes(&mut *seed);
    DeviceIdentityKey::from_seed(seed)
}
fn actor(pool: &PoolRegistration) -> Actor {
    Actor::Pool {
        pool: pool.pool_id(),
        incarnation: pool.incarnation(),
    }
}
fn registration(
    cold: &SigningKey,
    machine: &SigningKey,
    public: &recipient::RecipientPublic,
    incarnation: u8,
) -> PoolRegistration {
    PoolRegistration::new(
        Actor::Management,
        Enrollment {
            incarnation: IncarnationId::from_bytes([incarnation; 16]),
            cold_verification_key: cold.verifying_key().to_bytes(),
            network: NetworkBinding::from_genesis_bytes(42, b"operator recovery lab", 129_600, 64)
                .unwrap(),
            machine_public_key: machine.verifying_key().to_bytes(),
            recipient_public_key: public.public_key,
            recipient_id: public.recipient_id,
            management_sequence: ManagementSequence::new(1),
            management_request: RequestId::from_bytes([incarnation; 16]),
            management_payload_digest: [incarnation; 32],
        },
    )
    .unwrap()
}

struct Produced {
    pool: PoolRegistration,
    store: ObjectStore,
    tree: PublicTreeBuffer,
    expected: Expectations,
    artifact: Vec<u8>,
}
fn generate(
    mut pool: PoolRegistration,
    device: DeviceId,
    identity: &DeviceIdentityKey,
    rng: &mut ChaCha20Rng,
) -> Produced {
    let mut coordinator = GenerationCoordinator::new();
    let operation = match coordinator
        .admit(
            &pool,
            GenerationRequest {
                actor: actor(&pool),
                request: RequestId::from_bytes([0x51; 16]),
                payload_digest: [0x52; 32],
                next_generation_number: GenerationNumber::new(1),
                expected_revision: pool.revision(),
            },
            rng,
        )
        .unwrap()
    {
        Admission::Started(operation) => operation,
        Admission::Existing(_) => panic!("fresh device replayed generation"),
    };
    let mut job = begin_key_generation(rng, KesLifetime::new(64).unwrap()).unwrap();
    for completed in 1..=64 {
        assert_eq!(job.step().unwrap(), completed);
    }
    let (key, tree) = job.finish().unwrap();
    let verified = tree.verify(&key.verification_key().unwrap()).unwrap();
    let mut store = ObjectStore::default();
    let mut write = [0; MAX_PUBLIC_OBJECT_BYTES];
    let mut read = [0; MAX_PUBLIC_OBJECT_BYTES];
    let descriptor = coordinator
        .complete(
            &mut pool, operation, key, &verified, device, identity, rng, &mut store, &mut write,
            &mut read,
        )
        .unwrap();
    let artifact = get_backup(&pool, descriptor.generation, &mut store, &mut read)
        .unwrap()
        .bytes
        .to_vec();
    let expected = Expectations {
        device: *device.as_bytes(),
        pool: *pool.pool_id().as_bytes(),
        incarnation: *pool.incarnation().as_bytes(),
        generation: *descriptor.generation.as_bytes(),
        verification_key: descriptor.verification_key,
        identity_public_key: identity.verification_key(),
    };
    Produced {
        pool,
        store,
        tree,
        expected,
        artifact,
    }
}
fn certificate(cold: &SigningKey, vk: &[u8; 32], counter: u64, start: u64) -> Vec<u8> {
    let mut message = [0; 48];
    message[..32].copy_from_slice(vk);
    message[32..40].copy_from_slice(&counter.to_be_bytes());
    message[40..].copy_from_slice(&start.to_be_bytes());
    let signature = cold.sign(&message).to_bytes();
    let mut bytes = [0; 154];
    let mut encoder = Encoder::new(&mut bytes);
    encoder.array(2).unwrap();
    encoder.array(4).unwrap();
    encoder.bytes(vk).unwrap();
    encoder.uint(counter).unwrap();
    encoder.uint(start).unwrap();
    encoder.bytes(&signature).unwrap();
    encoder.bytes(&cold.verifying_key().to_bytes()).unwrap();
    encoder.finish().unwrap().encoded().to_vec()
}
fn certify(produced: &mut Produced, bytes: &[u8]) {
    let network = *produced.pool.network();
    produced
        .pool
        .certify(
            actor(&produced.pool),
            produced.pool.revision(),
            produced.pool.staged().unwrap().id(),
            bytes,
            &network,
        )
        .unwrap();
}
fn sign_and_verify(key: &KesKey, vk: &[u8; 32], period: u64, body: &[u8]) {
    let mut signature = [0; kes_core::SIGNATURE_BYTES];
    let period = kes_core::types::RelativePeriod::new(period).unwrap();
    key.sign_into(period, body, &mut signature).unwrap();
    crypto::verify(vk, period, key.lifetime(), body, &signature).unwrap();
    assert!(
        crypto::verify(
            vk,
            period,
            key.lifetime(),
            b"different block body",
            &signature
        )
        .is_err()
    );
}

#[test]
fn absent_original_recovers_single_certificate_with_disjoint_producer_intervals() {
    let mut rng = protected_rng();
    let cold = signing_key(&mut rng);
    let machine = signing_key(&mut rng);
    let original_identity = identity(&mut rng);
    let (public, recipient) = recipient::create(PASSWORD, &mut RecipientEntropy(&mut rng)).unwrap();
    let mut original = generate(
        registration(&cold, &machine, &public, 1),
        DeviceId::from_bytes([1; 16]),
        &original_identity,
        &mut rng,
    );
    let certificate_bytes = certificate(&cold, &original.expected.verification_key, 7, 100);
    certify(&mut original, &certificate_bytes);
    let certificate = original.pool.staged().unwrap().certificate().unwrap();
    let digest = *certificate.digest();
    let vk = original.expected.verification_key;
    let verified = original.tree.verify(&vk).unwrap();
    let source = original.pool.staged().unwrap().secret().key().unwrap();
    let mut primary = KesKey::from_canonical(
        SUM6_V1,
        source.canonical_state().unwrap().bytes(),
        kes_core::types::RelativePeriod::new(0).unwrap(),
        source.lifetime(),
    )
    .unwrap();
    // Explicit operator stop at 103: the original produces only [100, 103).
    for absolute in 100..103 {
        let period = kes_core::certificate::LifetimeWindow::new(
            certificate.start_period(),
            primary.lifetime(),
        )
        .unwrap()
        .relative_period(AbsolutePeriod::new(absolute))
        .unwrap();
        primary.evolve_to(period, &verified).unwrap();
        sign_and_verify(&primary, &vk, period.get().into(), b"primary block body");
    }
    primary.erase();
    assert!(!primary.is_live());
    let expected = original.expected;
    let artifact = original.artifact.clone();
    let tree = original.tree;
    // No connection, original key, pool, or device identity secret is available
    // to the recovery step. This models absence, not remote erasure.
    drop(original.pool);
    drop(original.store);
    drop(original_identity);
    let recovered = recover::recover(&artifact, &recipient, PASSWORD, expected).unwrap();
    let mut backup = KesKey::from_canonical(
        SUM6_V1,
        &recovered[..],
        kes_core::types::RelativePeriod::new(0).unwrap(),
        KesLifetime::new(64).unwrap(),
    )
    .unwrap();
    let certificate =
        kes_core::certificate::OperationalCertificate::decode_and_verify(&certificate_bytes)
            .unwrap();
    assert_eq!(certificate.digest(), &digest);
    let verified = tree.verify(&vk).unwrap();
    for absolute in 103..106 {
        let period = kes_core::certificate::LifetimeWindow::new(
            certificate.start_period(),
            backup.lifetime(),
        )
        .unwrap()
        .relative_period(AbsolutePeriod::new(absolute))
        .unwrap();
        backup.evolve_to(period, &verified).unwrap();
        sign_and_verify(&backup, &vk, period.get().into(), b"backup block body");
    }
    assert!(
        backup
            .evolve_to(kes_core::types::RelativePeriod::new(2).unwrap(), &verified)
            .is_err()
    );
    assert!(
        kes_core::certificate::LifetimeWindow::new(certificate.start_period(), backup.lifetime())
            .unwrap()
            .relative_period(AbsolutePeriod::new(164))
            .is_err()
    );
}

#[test]
fn replacement_requires_fresh_trust_generation_and_certificate_not_an_import() {
    let mut rng = protected_rng();
    let cold = signing_key(&mut rng);
    let old_machine = signing_key(&mut rng);
    let new_machine = signing_key(&mut rng);
    let old_identity = identity(&mut rng);
    let new_identity = identity(&mut rng);
    let (old_public, old_recipient) =
        recipient::create(PASSWORD, &mut RecipientEntropy(&mut rng)).unwrap();
    let (new_public, new_recipient) =
        recipient::create(PASSWORD, &mut RecipientEntropy(&mut rng)).unwrap();
    let mut old = generate(
        registration(&cold, &old_machine, &old_public, 1),
        DeviceId::from_bytes([1; 16]),
        &old_identity,
        &mut rng,
    );
    let old_certificate = certificate(&cold, &old.expected.verification_key, 7, 100);
    certify(&mut old, &old_certificate);
    let mut replacement = generate(
        registration(&cold, &new_machine, &new_public, 2),
        DeviceId::from_bytes([2; 16]),
        &new_identity,
        &mut rng,
    );
    assert_eq!(replacement.pool.pool_id(), old.pool.pool_id());
    assert_ne!(replacement.pool.incarnation(), old.pool.incarnation());
    assert_ne!(
        replacement.pool.credential_public_key(),
        old.pool.credential_public_key()
    );
    assert_ne!(
        replacement.expected.identity_public_key,
        old.expected.identity_public_key
    );
    assert_ne!(replacement.expected.generation, old.expected.generation);
    assert_ne!(
        replacement.expected.verification_key,
        old.expected.verification_key
    );
    let network = *replacement.pool.network();
    assert!(
        replacement
            .pool
            .certify(
                actor(&replacement.pool),
                replacement.pool.revision(),
                replacement.pool.staged().unwrap().id(),
                &old_certificate,
                &network
            )
            .is_err()
    );
    assert!(replacement.pool.staged().unwrap().certificate().is_none());
    let new_certificate = certificate(&cold, &replacement.expected.verification_key, 8, 164);
    certify(&mut replacement, &new_certificate);
    let old_cert = old.pool.staged().unwrap().certificate().unwrap();
    let new_cert = replacement.pool.staged().unwrap().certificate().unwrap();
    assert_ne!(old_cert.digest(), new_cert.digest());
    assert!(new_cert.counter() > old_cert.counter());
    let old_state =
        recover::recover(&old.artifact, &old_recipient, PASSWORD, old.expected).unwrap();
    let new_state = recover::recover(
        &replacement.artifact,
        &new_recipient,
        PASSWORD,
        replacement.expected,
    )
    .unwrap();
    assert_ne!(&old_state[..], &new_state[..]);
    assert!(matches!(
        recover::recover(
            &old.artifact,
            &old_recipient,
            PASSWORD,
            replacement.expected
        ),
        Err(recover::Error::WrongBinding)
    ));
    assert!(matches!(
        recover::recover(&old.artifact, &new_recipient, PASSWORD, old.expected),
        Err(recover::Error::WrongRecipient)
    ));
    // A replacement device does not accept a private-state import operation.
    let mut frame = [0; 128];
    let mut encoder = Encoder::new(&mut frame);
    encoder.map(4).unwrap();
    encoder.text("op").unwrap();
    encoder.text("IMPORT_PRIVATE_KEY").unwrap();
    encoder.text("payload").unwrap();
    encoder.map(0).unwrap();
    encoder.text("request").unwrap();
    encoder.bytes(&[7; 16]).unwrap();
    encoder.text("version").unwrap();
    encoder.uint(1).unwrap();
    let frame = encoder.finish().unwrap();
    assert_eq!(
        kes_protocol::Envelope::parse(frame.encoded(), kes_protocol::EnvelopeKind::DeviceRequest)
            .err(),
        Some(kes_protocol::Error::UnsupportedOperation),
    );
    // Caller-selected monotonically increasing OCert counter is an operator
    // obligation across independent devices; no cross-device ledger is implied.
}

fn revoke(pool: &mut PoolRegistration, management_key: &SigningKey, device: DeviceId) {
    let mut storage = [0; 64];
    let mut encoder = Encoder::new(&mut storage);
    encoder.map(1).unwrap();
    encoder.text("credential_epoch").unwrap();
    encoder.uint(1).unwrap();
    let payload = encoder.finish().unwrap().encoded();
    let target = Target::Pool {
        pool: pool.pool_id(),
        incarnation: pool.incarnation(),
    };
    let fields = SigningFields {
        device,
        target,
        sequence: ManagementSequence::new(2),
        request: RequestId::from_bytes([0x71; 16]),
        expected_revision: pool.revision(),
        action: Action::CredentialRevoke,
        canonical_payload: Value::parse(payload).unwrap(),
    };
    let mut message = [0; 4608];
    let length = management::encode_signing_message(fields, &mut message).unwrap();
    let signature = management_key.sign(&message[..length]).to_bytes();
    let mut envelope = [0; 6144];
    let mut e = Encoder::new(&mut envelope);
    e.map(9).unwrap();
    e.text("pool").unwrap();
    e.bytes(pool.pool_id().as_bytes()).unwrap();
    e.text("action").unwrap();
    e.text(Action::CredentialRevoke.name()).unwrap();
    e.text("device").unwrap();
    e.bytes(device.as_bytes()).unwrap();
    e.text("request").unwrap();
    e.bytes(&[0x71; 16]).unwrap();
    e.text("signature").unwrap();
    e.bytes(&signature).unwrap();
    e.text("incarnation").unwrap();
    e.bytes(pool.incarnation().as_bytes()).unwrap();
    e.text("canonical_payload").unwrap();
    e.bytes(payload).unwrap();
    e.text("expected_revision").unwrap();
    e.uint(pool.revision().get()).unwrap();
    e.text("management_sequence").unwrap();
    e.uint(2).unwrap();
    let bytes = e.finish().unwrap().encoded();
    let verified =
        management::parse_and_verify(bytes, device, &management_key.verifying_key().to_bytes())
            .unwrap();
    credentials::change_pool_credential(pool, &mut GenerationCoordinator::new(), None, &verified)
        .unwrap();
}

#[test]
fn revoked_original_credential_cannot_reconnect_after_operator_transition() {
    let mut rng = protected_rng();
    let cold = signing_key(&mut rng);
    let machine = signing_key(&mut rng);
    let management_key = signing_key(&mut rng);
    let device_identity = identity(&mut rng);
    let (public, _) = recipient::create(PASSWORD, &mut RecipientEntropy(&mut rng)).unwrap();
    let device = DeviceId::from_bytes([1; 16]);
    let mut produced = generate(
        registration(&cold, &machine, &public, 1),
        device,
        &device_identity,
        &mut rng,
    );
    let mut seed = Zeroizing::new([0; 32]);
    rng.fill_bytes(&mut *seed);
    let hpke = DeviceHpkeKey::from_seed(seed);
    let context = OpenContext::new(
        device,
        [0x61; 32],
        Scope::Pool {
            pool: produced.pool.pool_id(),
            incarnation: produced.pool.incarnation(),
        },
        produced.pool.credential_epoch(),
        0,
        RequestId::from_bytes([0x62; 16]),
    );
    let (old_open, _) = begin_open(context, &hpke.public_key(), &machine, &mut rng).unwrap();
    assert!(
        accept_open(
            context,
            &old_open,
            &hpke,
            produced.pool.credential_public_key(),
            &mut rng
        )
        .is_ok()
    );
    revoke(&mut produced.pool, &management_key, device);
    assert!(produced.pool.credential_revoked());
    assert_eq!(produced.pool.credential_epoch(), CredentialEpoch::new(1));
    let current = OpenContext {
        credential_epoch: produced.pool.credential_epoch(),
        ..context
    };
    assert_eq!(
        accept_open(
            current,
            &old_open,
            &hpke,
            produced.pool.credential_public_key(),
            &mut rng
        )
        .err(),
        Some(SessionError::InvalidStructure)
    );
    // Even a newly signed generation request under the old actor is denied by
    // the authoritative revoked pool policy, not merely a stale OPEN counter.
    let mut coordinator = GenerationCoordinator::new();
    assert!(
        coordinator
            .admit(
                &produced.pool,
                GenerationRequest {
                    actor: actor(&produced.pool),
                    request: RequestId::from_bytes([0x72; 16]),
                    payload_digest: [0x73; 32],
                    next_generation_number: GenerationNumber::new(2),
                    expected_revision: produced.pool.revision(),
                },
                &mut rng
            )
            .is_err()
    );
    let cert = certificate(&cold, &produced.expected.verification_key, 7, 100);
    let network = *produced.pool.network();
    assert_eq!(
        produced.pool.certify(
            actor(&produced.pool),
            produced.pool.revision(),
            produced.pool.staged().unwrap().id(),
            &cert,
            &network
        ),
        Err(StateError::PolicyChanged)
    );
}

#[test]
fn recovery_cannot_replace_missing_recipient_or_missing_authentic_artifact() {
    let mut rng = protected_rng();
    let cold = signing_key(&mut rng);
    let machine = signing_key(&mut rng);
    let device_identity = identity(&mut rng);
    let (public, recipient) = recipient::create(PASSWORD, &mut RecipientEntropy(&mut rng)).unwrap();
    let produced = generate(
        registration(&cold, &machine, &public, 1),
        DeviceId::from_bytes([1; 16]),
        &device_identity,
        &mut rng,
    );
    assert!(matches!(
        recover::recover(&[], &recipient, PASSWORD, produced.expected),
        Err(recover::Error::InvalidArtifact)
    ));
    assert!(matches!(
        recover::recover(
            &produced.artifact,
            &recipient,
            b"wrong passphrase",
            produced.expected
        ),
        Err(recover::Error::WrongPassword)
    ));
    let (_, unrelated): (_, RecipientKeyFile) =
        recipient::create(PASSWORD, &mut RecipientEntropy(&mut rng)).unwrap();
    assert!(matches!(
        recover::recover(&produced.artifact, &unrelated, PASSWORD, produced.expected),
        Err(recover::Error::WrongRecipient)
    ));
    let root = std::env::temp_dir().join(format!(
        "kes-replacement-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let artifact_path = root.join("retained.kes-backup");
    fs::write(&artifact_path, &produced.artifact).unwrap();
    let missing = root.join("missing");
    let output = root.join("recovered.skey");
    for artifact in [&artifact_path, &missing] {
        assert_eq!(
            recover::recover_files(
                recover::RecoveryFiles {
                    artifact,
                    recipient_key: &missing,
                    device_identity: &missing,
                    expected_device: produced.expected.device,
                    expected_pool: produced.expected.pool,
                    expected_generation: produced.expected.generation,
                    verification_key: &missing,
                    output: &output,
                },
                PASSWORD
            ),
            Err(recover::Error::InvalidInput)
        );
        assert!(!output.exists());
    }
    let generation = produced.pool.staged().unwrap().id();
    let mut lost_storage = ObjectStore::default();
    let mut buffer = [0; MAX_PUBLIC_OBJECT_BYTES];
    assert!(get_backup(&produced.pool, generation, &mut lost_storage, &mut buffer).is_err());
    fs::remove_dir_all(root).unwrap();
}
