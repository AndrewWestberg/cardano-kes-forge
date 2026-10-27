//! Already-authenticated protocol seam; real offline signatures and NOR journal.
#[path = "../../../firmware/src/development/device_management.rs"]
mod device_management;
use device_management::{DeviceManagementError as Error, execute};
use ed25519_dalek::{Signer, SigningKey};
use kes_core::{
    cbor::{Encoder, Value},
    credentials,
    journal::{
        DirectoryCodec, Flash, FlashRules, Journal, JournalContext, JournalLayout, JournalScope,
        JournalWorkspace, ObjectWorkspace, SecretCache, Workspaces,
    },
    management::{self, Action, SigningFields, Target},
    state::{DeviceConfig, DeviceCredential, DeviceMode, DirectorySnapshot, Health},
    types::{DeviceId, DeviceIdentityBinding, ManagementSequence, RequestId, Revision},
};
use kes_protocol::{Envelope, EnvelopeKind, MAX_FRAME_BYTES};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use zeroize::Zeroizing;
const DEVICE: DeviceId = DeviceId::from_bytes([1; 16]);

struct Nor {
    bytes: Vec<u8>,
    mutations: usize,
    fail_at: Option<usize>,
    ignore_erase: bool,
}
impl Nor {
    fn mutate(&mut self) -> Result<(), ()> {
        self.mutations += 1;
        if self.fail_at == Some(self.mutations) {
            Err(())
        } else {
            Ok(())
        }
    }
}
impl Flash for Nor {
    type Error = ();
    fn capacity(&self) -> u32 {
        self.bytes.len() as u32
    }
    fn rules(&self) -> FlashRules {
        FlashRules::OnceOnlyClean
    }
    fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<(), ()> {
        out.copy_from_slice(
            self.bytes
                .get(offset as usize..offset as usize + out.len())
                .ok_or(())?,
        );
        Ok(())
    }
    fn program_page(&mut self, offset: u32, page: &[u8; 256]) -> Result<(), ()> {
        self.mutate()?;
        if !offset.is_multiple_of(256) {
            return Err(());
        }
        let target = self
            .bytes
            .get_mut(offset as usize..offset as usize + 256)
            .ok_or(())?;
        if target.iter().any(|b| *b != 0xff) {
            return Err(());
        }
        for (old, new) in target.iter_mut().zip(page) {
            *old &= new;
        }
        Ok(())
    }
    fn erase_sector(&mut self, offset: u32) -> Result<(), ()> {
        self.mutate()?;
        if !offset.is_multiple_of(4096) {
            return Err(());
        }
        if !self.ignore_erase {
            self.bytes
                .get_mut(offset as usize..offset as usize + 4096)
                .ok_or(())?
                .fill(0xff);
        }
        Ok(())
    }
    fn invalidate_cache(&mut self) -> Result<(), ()> {
        Ok(())
    }
}
struct Buffers {
    journal: JournalWorkspace,
    object: ObjectWorkspace,
    cache: SecretCache,
}
impl Buffers {
    fn work(&mut self) -> Workspaces<'_> {
        Workspaces {
            journal: &mut self.journal,
            object: &mut self.object,
            cache: &mut self.cache,
        }
    }
}
struct Fixture {
    root: SigningKey,
    journal: Journal<DirectoryCodec>,
    flash: Nor,
    rng: ChaCha20Rng,
    buffers: Buffers,
}
impl Fixture {
    fn new() -> Self {
        Self::with_directory(|_| {})
    }
    fn with_directory(configure: impl FnOnce(&mut DirectorySnapshot)) -> Self {
        let root = SigningKey::from_bytes(&[2; 32]);
        let transport = SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes();
        let mut directory = DirectorySnapshot {
            config: DeviceConfig {
                identity: DeviceIdentityBinding::new(DEVICE, [4; 32], [5; 32]),
                silicon_revision: 2,
                firmware_digest: [6; 32],
                security_version: 0,
                hardware_policy_digest: [7; 32],
                mode: DeviceMode::Development,
                health: Health::Healthy,
                management_root_public_key: root.verifying_key().to_bytes(),
                management_transport_public_key: transport,
            },
            revision: Revision::new(0),
            retirement: None,
            credential: DeviceCredential::new(transport),
            pending_deletion: None,
            pending_enrollment: None,
            live: [None; kes_core::MAX_POOLS],
            tombstones: [None; kes_core::state::DIRECTORY_IDENTITY_CAPACITY],
        };
        configure(&mut directory);
        let journal = Journal::new(
            JournalContext {
                device: DEVICE,
                scope: JournalScope::Directory,
            },
            JournalLayout::directory(0).unwrap(),
            &Zeroizing::new([8; 32]),
        )
        .unwrap();
        let mut f = Self {
            root,
            journal,
            flash: Nor {
                bytes: vec![0xff; 16384],
                mutations: 0,
                fail_at: None,
                ignore_erase: false,
            },
            rng: ChaCha20Rng::from_seed([9; 32]),
            buffers: Buffers {
                journal: JournalWorkspace::new(),
                object: ObjectWorkspace::new(),
                cache: SecretCache::new(),
            },
        };
        f.journal
            .initialize(&mut f.flash, &mut f.rng, &directory, &mut f.buffers.work())
            .unwrap();
        f
    }
    fn recover(&mut self) -> DirectorySnapshot {
        self.journal
            .recover(&mut self.flash, &mut self.rng, &mut self.buffers.work())
            .unwrap()
            .state
    }
    fn run(
        &mut self,
        authority: &DirectorySnapshot,
        bytes: &[u8],
    ) -> Result<device_management::DeviceManagementOutcome, Error> {
        execute(
            Envelope::parse(bytes, EnvelopeKind::DeviceRequest).unwrap(),
            authority,
            &self.journal,
            &mut self.flash,
            &mut self.rng,
            &mut self.buffers.work(),
        )
    }
}

fn wire(
    root: &SigningKey,
    action: Action,
    sequence: u64,
    revision: u64,
    epoch: u64,
    device: DeviceId,
    target: Target,
    request: u8,
) -> Vec<u8> {
    let replacement = SigningKey::from_bytes(&[10; 32]).verifying_key().to_bytes();
    let mut payload = [0; 256];
    let mut e = Encoder::new(&mut payload);
    e.map(if action == Action::CredentialReplace {
        2
    } else {
        1
    })
    .unwrap();
    e.text("credential_epoch").unwrap();
    e.uint(epoch).unwrap();
    if action == Action::CredentialReplace {
        e.text("machine_public_key").unwrap();
        e.bytes(&replacement).unwrap();
    }
    let canonical = e.finish().unwrap();
    let fields = SigningFields {
        device,
        target,
        sequence: ManagementSequence::new(sequence),
        request: RequestId::from_bytes([request; 16]),
        expected_revision: Revision::new(revision),
        action,
        canonical_payload: canonical,
    };
    let mut message = [0; 4608];
    let length = management::encode_signing_message(fields, &mut message).unwrap();
    let signature = root.sign(&message[..length]).to_bytes();
    let mut signed = [0; 2048];
    let mut e = Encoder::new(&mut signed);
    e.map(9).unwrap();
    e.text("pool").unwrap();
    match target {
        Target::Device => e.null().unwrap(),
        Target::Pool { pool, .. } => e.bytes(pool.as_bytes()).unwrap(),
    };
    e.text("action").unwrap();
    e.text(action.name()).unwrap();
    e.text("device").unwrap();
    e.bytes(device.as_bytes()).unwrap();
    e.text("request").unwrap();
    e.bytes(fields.request.as_bytes()).unwrap();
    e.text("signature").unwrap();
    e.bytes(&signature).unwrap();
    e.text("incarnation").unwrap();
    match target {
        Target::Device => e.null().unwrap(),
        Target::Pool { incarnation, .. } => e.bytes(incarnation.as_bytes()).unwrap(),
    };
    e.text("canonical_payload").unwrap();
    e.bytes(canonical.encoded()).unwrap();
    e.text("expected_revision").unwrap();
    e.uint(revision).unwrap();
    e.text("management_sequence").unwrap();
    e.uint(sequence).unwrap();
    let signed = e.finish().unwrap();
    let mut output = [0; MAX_FRAME_BYTES];
    let mut e = Encoder::new(&mut output);
    e.map(11).unwrap();
    e.text("op").unwrap();
    e.text("MANAGE").unwrap();
    e.text("mac").unwrap();
    e.bytes(&[0; 32]).unwrap();
    e.text("seq").unwrap();
    e.uint(1).unwrap();
    e.text("pool").unwrap();
    e.null().unwrap();
    e.text("device").unwrap();
    e.bytes(DEVICE.as_bytes()).unwrap();
    e.text("payload").unwrap();
    e.value(Value::parse(signed.encoded()).unwrap()).unwrap();
    e.text("request").unwrap();
    e.bytes(&[request; 16]).unwrap();
    e.text("session").unwrap();
    e.bytes(&[11; 16]).unwrap();
    e.text("version").unwrap();
    e.uint(1).unwrap();
    e.text("budget_ms").unwrap();
    e.uint(500).unwrap();
    e.text("incarnation").unwrap();
    e.null().unwrap();
    e.finish().unwrap().encoded().to_vec()
}

#[test]
fn replacement_revocation_and_exact_replay_are_durable_without_touching_pools() {
    let mut f = Fixture::new();
    let authority = f.recover();
    let replace = wire(
        &f.root,
        Action::CredentialReplace,
        1,
        0,
        1,
        DEVICE,
        Target::Device,
        12,
    );
    let result = f.run(&authority, &replace).unwrap();
    assert_eq!(result.revision.get(), 1);
    assert_eq!(result.sequence.get(), 1);
    assert!(result.committed_write && result.epoch_changed && !result.revocation_changed);
    let updated = f.recover();
    assert_eq!(updated.live, authority.live);
    assert_eq!(updated.tombstones, authority.tombstones);
    assert_eq!(
        updated.credential.public_key,
        SigningKey::from_bytes(&[10; 32]).verifying_key().to_bytes()
    );
    let writes = f.flash.mutations;
    let retry = f.run(&updated, &replace).unwrap();
    assert_eq!(retry.revision, result.revision);
    assert!(!retry.committed_write && !retry.epoch_changed && !retry.revocation_changed);
    assert_eq!(f.flash.mutations, writes);
    assert_eq!(f.run(&authority, &replace), Err(Error::StaleAuthority));
    let revoke = wire(
        &f.root,
        Action::CredentialRevoke,
        2,
        1,
        2,
        DEVICE,
        Target::Device,
        13,
    );
    let revoked = f.run(&updated, &revoke).unwrap();
    assert!(revoked.committed_write && revoked.epoch_changed && revoked.revocation_changed);
    let updated = f.recover();
    assert!(updated.credential.revoked);
    assert_eq!(updated.credential.epoch.get(), 2);
    let writes = f.flash.mutations;
    assert!(!f.run(&updated, &revoke).unwrap().committed_write);
    assert_eq!(f.flash.mutations, writes);
}

#[test]
fn forged_wrong_device_scope_revision_and_changed_replay_fail_closed() {
    use kes_core::types::{IncarnationId, PoolId};
    let mut f = Fixture::new();
    let authority = f.recover();
    let forged = wire(
        &SigningKey::from_bytes(&[99; 32]),
        Action::CredentialReplace,
        1,
        0,
        1,
        DEVICE,
        Target::Device,
        12,
    );
    let wrong_device = wire(
        &f.root,
        Action::CredentialReplace,
        1,
        0,
        1,
        DeviceId::from_bytes([99; 16]),
        Target::Device,
        12,
    );
    let wrong_scope = wire(
        &f.root,
        Action::CredentialReplace,
        1,
        0,
        1,
        DEVICE,
        Target::Pool {
            pool: PoolId::from_bytes([33; 28]),
            incarnation: IncarnationId::from_bytes([34; 16]),
        },
        12,
    );
    let stale = wire(
        &f.root,
        Action::CredentialReplace,
        1,
        9,
        1,
        DEVICE,
        Target::Device,
        12,
    );
    let writes = f.flash.mutations;
    assert!(matches!(
        f.run(&authority, &forged),
        Err(Error::Authorization(_))
    ));
    assert!(Envelope::parse(&wrong_device, EnvelopeKind::DeviceRequest).is_err());
    assert_eq!(f.run(&authority, &wrong_scope), Err(Error::WrongRequest));
    assert_eq!(
        f.run(&authority, &stale),
        Err(Error::Credential(credentials::Error::RevisionConflict))
    );
    assert_eq!(f.flash.mutations, writes);
    let valid = wire(
        &f.root,
        Action::CredentialReplace,
        1,
        0,
        1,
        DEVICE,
        Target::Device,
        12,
    );
    f.run(&authority, &valid).unwrap();
    let authority = f.recover();
    let changed = wire(
        &f.root,
        Action::CredentialReplace,
        1,
        0,
        1,
        DEVICE,
        Target::Device,
        14,
    );
    let skipped = wire(
        &f.root,
        Action::CredentialReplace,
        3,
        1,
        2,
        DEVICE,
        Target::Device,
        15,
    );
    let writes = f.flash.mutations;
    assert_eq!(
        f.run(&authority, &changed),
        Err(Error::Credential(credentials::Error::ChangedReplay))
    );
    assert_eq!(
        f.run(&authority, &skipped),
        Err(Error::Credential(credentials::Error::Replay))
    );
    assert_eq!(f.flash.mutations, writes);
}

#[test]
fn flash_failure_or_lying_cleanup_never_returns_an_acknowledgement() {
    for ignore_erase in [false, true] {
        let mut f = Fixture::new();
        let authority = f.recover();
        let request = wire(
            &f.root,
            Action::CredentialReplace,
            1,
            0,
            1,
            DEVICE,
            Target::Device,
            12,
        );
        if ignore_erase {
            f.flash.ignore_erase = true;
        } else {
            f.flash.fail_at = Some(f.flash.mutations + 1);
        }
        assert!(matches!(
            f.run(&authority, &request),
            Err(Error::Journal(_))
        ));
    }
}

#[test]
fn pending_enrollment_and_deletion_fail_closed_without_journal_writes() {
    use kes_core::{
        state::{
            DeletionIntent, DirectoryEntry, Enrollment, EnrollmentIntent, ManagementReplay,
            ManagementResult, PoolTombstone,
        },
        types::{HardwareSlot, IncarnationId, NetworkBinding, PoolId},
    };
    use sha2::{Digest, Sha256};
    for deleting in [false, true] {
        let mut f = Fixture::with_directory(|directory| {
            let slot = HardwareSlot::new(0).unwrap();
            let cold = SigningKey::from_bytes(&[31; 32]).verifying_key().to_bytes();
            let pool = PoolId::from_cold_verification_key(&cold);
            let incarnation = IncarnationId::from_bytes([32; 16]);
            let replay = ManagementReplay {
                sequence: ManagementSequence::new(1),
                request: RequestId::from_bytes([33; 16]),
                payload_digest: [34; 32],
                result: ManagementResult::Committed {
                    revision: Revision::new(1),
                },
            };
            if deleting {
                directory.live[0] = Some(DirectoryEntry::new(slot, pool, incarnation));
                directory.pending_deletion = Some(DeletionIntent {
                    slot,
                    expected_pool_revision: Revision::new(0),
                    pool_cleanup_revision: Revision::new(1),
                    tombstone: PoolTombstone {
                        pool_id: pool,
                        last_incarnation: incarnation,
                        management_sequence: replay.sequence,
                        credential_epoch: Some(kes_core::types::CredentialEpoch::new(0)),
                        management_replay: replay,
                        deletion_revision: Revision::new(1),
                        certificate_high_water: None,
                        generation_high_water: kes_core::types::GenerationNumber::new(0),
                    },
                });
            } else {
                let recipient = [35; 32];
                directory.pending_enrollment = Some(EnrollmentIntent {
                    slot,
                    enrollment: Enrollment {
                        incarnation,
                        cold_verification_key: cold,
                        network: NetworkBinding::from_genesis_bytes(42, b"test genesis", 64, 64)
                            .unwrap(),
                        machine_public_key: SigningKey::from_bytes(&[36; 32])
                            .verifying_key()
                            .to_bytes(),
                        recipient_public_key: recipient,
                        recipient_id: Sha256::digest(recipient).into(),
                        management_sequence: replay.sequence,
                        management_request: replay.request,
                        management_payload_digest: replay.payload_digest,
                    },
                });
            }
        });
        let authority = f.recover();
        let request = wire(
            &f.root,
            Action::CredentialReplace,
            1,
            0,
            1,
            DEVICE,
            Target::Device,
            12,
        );
        let writes = f.flash.mutations;
        assert_eq!(f.run(&authority, &request), Err(Error::PendingOperation));
        assert_eq!(f.flash.mutations, writes);
    }
}
