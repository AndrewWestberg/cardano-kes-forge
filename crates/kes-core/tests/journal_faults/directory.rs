use super::fixtures::{OsEntropy, fresh_storage_root};
use super::flash::NorFlash;
use kes_core::journal::{
    DirectoryCodec, Journal, JournalContext, JournalError, JournalLayout, JournalScope,
    JournalWorkspace, Mutation, ObjectWorkspace, ReadyToken, Recovered, SecretCache, Workspaces,
};
use kes_core::state::{
    Actor, Device, DeviceConfig, DeviceCredential, DeviceMode, DeviceRetirement, DirectoryEntry,
    DirectorySnapshot, Enrollment, Health, ManagementReplay, ManagementResult, PoolRegistration,
    PoolTombstone, StateError, UsePolicy,
};
use kes_core::types::{
    CertificateCounter, DeviceId, DeviceIdentityBinding, GenerationNumber, HardwareSlot,
    IncarnationId, ManagementSequence, NetworkBinding, PoolId, RequestId, Revision,
};
use sha2::{Digest, Sha256};

struct Buffers {
    journal: JournalWorkspace,
    object: ObjectWorkspace,
    cache: SecretCache,
}
impl Buffers {
    fn new() -> Self {
        Self {
            journal: JournalWorkspace::new(),
            object: ObjectWorkspace::new(),
            cache: SecretCache::new(),
        }
    }
    fn work(&mut self) -> Workspaces<'_> {
        Workspaces {
            journal: &mut self.journal,
            object: &mut self.object,
            cache: &mut self.cache,
        }
    }
}
fn context() -> JournalContext {
    JournalContext {
        device: DeviceId::from_bytes([0x19; 16]),
        scope: JournalScope::Directory,
    }
}
fn empty() -> DirectorySnapshot {
    DirectorySnapshot {
        config: DeviceConfig {
            identity: DeviceIdentityBinding::new(context().device, [0x42; 32], [0x29; 32]),
            silicon_revision: 2,
            firmware_digest: [0x37; 32],
            security_version: 1,
            hardware_policy_digest: [0x43; 32],
            mode: DeviceMode::Development,
            health: Health::Healthy,
            management_root_public_key: [0x51; 32],
            management_transport_public_key: [0x52; 32],
        },
        revision: Revision::new(0),
        retirement: None,
        credential: DeviceCredential::new([0x52; 32]),
        pending_deletion: None,
        pending_enrollment: None,
        live: [None; 32],
        tombstones: [None; 32],
    }
}
fn copy_public(state: &DirectorySnapshot) -> DirectorySnapshot {
    DirectorySnapshot {
        config: state.config,
        revision: state.revision,
        retirement: state.retirement,
        credential: state.credential,
        pending_deletion: state.pending_deletion,
        pending_enrollment: state.pending_enrollment,
        live: state.live,
        tombstones: state.tombstones,
    }
}
fn pool_id(index: u8) -> PoolId {
    let mut public_cold = [0x42; 32];
    public_cold[0] = index;
    PoolId::from_cold_verification_key(&public_cold)
}
fn replay(sequence: u64, revision: Revision, label: u8) -> ManagementReplay {
    ManagementReplay {
        sequence: ManagementSequence::new(sequence),
        request: RequestId::from_bytes([label; 16]),
        payload_digest: [label; 32],
        result: ManagementResult::Committed { revision },
    }
}

#[test]
fn prior_directory_tombstone_keeps_unknown_credential_epoch_on_migration() {
    use kes_core::{
        cbor::{Encoder, Value},
        journal::SnapshotCodec,
    };
    let mut state = empty();
    state.revision = Revision::new(1);
    state.tombstones[0] = Some(PoolTombstone {
        pool_id: pool_id(0),
        last_incarnation: IncarnationId::from_bytes([1; 16]),
        credential_epoch: Some(kes_core::types::CredentialEpoch::new(7)),
        management_sequence: ManagementSequence::new(2),
        certificate_high_water: None,
        generation_high_water: GenerationNumber::new(1),
        deletion_revision: state.revision,
        management_replay: replay(2, state.revision, 3),
    });
    let mut current = [0; 7536];
    let len = DirectoryCodec::encode(&state, context(), &mut current).unwrap();
    let mut old = [0; 7536];
    let mut encoder = Encoder::new(&mut old);
    encoder.array(9).unwrap();
    for (index, value) in Value::parse(&current[..len])
        .unwrap()
        .array()
        .unwrap()
        .enumerate()
    {
        match index {
            0 => encoder.uint(4).unwrap(),
            5 => {
                encoder.array(1).unwrap();
                encoder.array(7).unwrap();
                for field in value
                    .array()
                    .unwrap()
                    .next()
                    .unwrap()
                    .array()
                    .unwrap()
                    .take(7)
                {
                    encoder.value(field).unwrap();
                }
            }
            _ => encoder.value(value).unwrap(),
        }
    }
    let old = encoder.finish().unwrap();
    let migrated = DirectoryCodec::decode(old.encoded(), context()).unwrap();
    let tombstone = migrated.tombstones.iter().flatten().next().unwrap();
    assert_eq!(tombstone.pool_id, pool_id(0));
    assert_eq!(tombstone.credential_epoch, None);
    assert_eq!(
        tombstone.management_replay,
        state.tombstones[0].unwrap().management_replay
    );
    let len = DirectoryCodec::encode(&migrated, context(), &mut current).unwrap();
    let roundtrip = DirectoryCodec::decode(&current[..len], context()).unwrap();
    assert_eq!(roundtrip.tombstones[0].unwrap().credential_epoch, None);
}
fn commit(
    journal: &Journal<DirectoryCodec>,
    flash: &mut NorFlash,
    rng: &mut OsEntropy,
    token: &ReadyToken,
    old: &mut DirectorySnapshot,
    next: &DirectorySnapshot,
    buffers: &mut Buffers,
) -> Result<ReadyToken, JournalError> {
    journal.transact(
        flash,
        rng,
        Mutation {
            expected: token,
            successor: next,
            retired: old,
        },
        &mut buffers.work(),
    )
}
fn enrollment_for_overflow_identity() -> PoolRegistration {
    let mut cold = [0x42; 32];
    cold[0] = 32;
    let recipient = [0x73; 32];
    PoolRegistration::new(
        Actor::Management,
        Enrollment {
            incarnation: IncarnationId::from_bytes([32; 16]),
            cold_verification_key: cold,
            network: NetworkBinding::from_genesis_bytes(
                42,
                b"public directory capacity genesis",
                64,
                64,
            )
            .unwrap(),
            machine_public_key: [0x61; 32],
            recipient_public_key: recipient,
            recipient_id: Sha256::digest(recipient).into(),
            management_sequence: ManagementSequence::new(1),
            management_request: RequestId::from_bytes([32; 16]),
            management_payload_digest: [32; 32],
        },
    )
    .unwrap()
}
fn check_retained_history(state: &DirectorySnapshot) {
    for index in 0..32 {
        let retained = state
            .tombstones
            .iter()
            .flatten()
            .find(|entry| entry.pool_id == pool_id(index))
            .unwrap();
        assert_eq!(
            retained.last_incarnation,
            IncarnationId::from_bytes([index; 16])
        );
        assert_eq!(retained.management_sequence, ManagementSequence::new(2));
        assert_eq!(
            retained.certificate_high_water,
            Some(CertificateCounter::new(if index == 13 {
                u64::MAX
            } else {
                u64::from(index)
            }))
        );
        assert_eq!(
            retained.generation_high_water,
            GenerationNumber::new(if index == 15 {
                u64::MAX
            } else {
                u64::from(index) + 1
            })
        );
        assert_eq!(
            retained.deletion_revision,
            Revision::new(33 + u64::from(index))
        );
        assert_eq!(
            retained.management_replay,
            replay(2, retained.deletion_revision, index)
        );
    }
    let mut device = Device::from_authenticated_snapshot(state).unwrap();
    assert_eq!(device.pool_count(), 0);
    assert_eq!(device.retained_identity_count(), 32);
    assert_eq!(
        device.enroll(
            Actor::Management,
            &enrollment_for_overflow_identity(),
            state.revision
        ),
        Err(StateError::DirectoryFull)
    );
}
#[test]
fn directory_history_and_retirement_survive_authenticated_two_sector_storage() {
    let journal = Journal::<DirectoryCodec>::new(
        context(),
        JournalLayout::directory(0).unwrap(),
        &fresh_storage_root(),
    )
    .unwrap();
    let mut flash = NorFlash::new(16384);
    let mut rng = OsEntropy::new();
    let mut buffers = Buffers::new();
    let mut state = empty();
    let mut token = journal
        .initialize(&mut flash, &mut rng, &state, &mut buffers.work())
        .unwrap();
    for index in 0..32u8 {
        let mut next = copy_public(&state);
        next.revision = state.revision.checked_increment().unwrap();
        next.live[usize::from(index)] = Some(DirectoryEntry::new(
            HardwareSlot::new(usize::from(index) * 17 % 32).unwrap(),
            pool_id(index),
            IncarnationId::from_bytes([index; 16]),
        ));
        token = commit(
            &journal,
            &mut flash,
            &mut rng,
            &token,
            &mut state,
            &next,
            &mut buffers,
        )
        .unwrap();
        state = next;
    }
    // These are complete authenticated storage data fixtures, not a claim that
    // future management deletion/retirement handlers have been implemented.
    for index in 0..32u8 {
        let mut next = copy_public(&state);
        next.revision = state.revision.checked_increment().unwrap();
        next.live[usize::from(index)] = None;
        next.tombstones[usize::from(index)] = Some(PoolTombstone {
            pool_id: pool_id(index),
            last_incarnation: IncarnationId::from_bytes([index; 16]),
            credential_epoch: Some(kes_core::types::CredentialEpoch::new(u64::from(index))),
            management_sequence: ManagementSequence::new(2),
            certificate_high_water: Some(CertificateCounter::new(if index == 13 {
                u64::MAX
            } else {
                u64::from(index)
            })),
            generation_high_water: GenerationNumber::new(if index == 15 {
                u64::MAX
            } else {
                u64::from(index) + 1
            }),
            deletion_revision: next.revision,
            management_replay: replay(2, next.revision, index),
        });
        token = commit(
            &journal,
            &mut flash,
            &mut rng,
            &token,
            &mut state,
            &next,
            &mut buffers,
        )
        .unwrap();
        state = next;
    }
    let recovered = journal
        .recover(&mut flash, &mut rng, &mut buffers.work())
        .unwrap();
    check_retained_history(&recovered.state);
    assert_eq!(recovered.token.revision(), Revision::new(64));
    state = recovered.state;
    token = recovered.token;
    let mut next = copy_public(&state);
    next.revision = Revision::new(65);
    next.config.health = Health::Unavailable;
    next.retirement = Some(DeviceRetirement {
        revision: next.revision,
        management_replay: replay(1, next.revision, 0xee),
    });
    commit(
        &journal,
        &mut flash,
        &mut rng,
        &token,
        &mut state,
        &next,
        &mut buffers,
    )
    .unwrap();
    let retired = journal
        .recover(&mut flash, &mut rng, &mut buffers.work())
        .unwrap();
    assert_eq!(retired.state.config.health, Health::Unavailable);
    assert_eq!(retired.state.retirement, next.retirement);
    let restored = Device::from_authenticated_snapshot(&retired.state).unwrap();
    assert_eq!(
        restored.ensure_operational(UsePolicy::IsolatedDevelopment, None),
        Err(StateError::Retired)
    );
    assert_eq!(restored.retained_identity_count(), 32);
}
fn first_enrollment() -> DirectorySnapshot {
    let mut next = empty();
    next.revision = Revision::new(1);
    next.live[9] = Some(DirectoryEntry::new(
        HardwareSlot::new(29).unwrap(),
        pool_id(0),
        IncarnationId::from_bytes([0; 16]),
    ));
    next
}
fn check_cut_recovery(
    recovered: Recovered<DirectorySnapshot>,
    flash: &NorFlash,
    layout: JournalLayout,
    must_be_successor: bool,
) -> bool {
    let device = Device::from_authenticated_snapshot(&recovered.state).unwrap();
    let successor = device.find(pool_id(0)).is_some();
    if must_be_successor {
        assert!(successor, "committed directory successor rolled back");
    }
    if successor {
        assert_eq!(
            device.find(pool_id(0)).unwrap().slot(),
            HardwareSlot::new(29).unwrap()
        );
        assert!(recovered.token.revision().get() >= 1);
    } else {
        assert_eq!(recovered.token.revision(), Revision::new(0));
    }
    let obsolete =
        usize::try_from(layout.bank_offset(1 - recovered.token.bank()).unwrap()).unwrap();
    assert!(
        flash.raw()[obsolete..obsolete + layout.bank_bytes()]
            .iter()
            .all(|&byte| byte == 0xff),
        "Ready returned with an obsolete directory bank retained"
    );
    successor
}
#[test]
fn directory_byte_boundary_cuts_cover_both_erase_sectors_without_rollback() {
    if std::env::var_os("KES_GATE_MODE").is_some() {
        return;
    }
    let layout = JournalLayout::directory(0).unwrap();
    let journal = Journal::<DirectoryCodec>::new(context(), layout, &fresh_storage_root()).unwrap();
    let mut rng = OsEntropy::new();
    let mut buffers = Buffers::new();
    let mut baseline = NorFlash::new(16384);
    let initial = empty();
    let token = journal
        .initialize(&mut baseline, &mut rng, &initial, &mut buffers.work())
        .unwrap();
    let next = first_enrollment();
    let mut full = baseline.copy_world();
    let mut old = copy_public(&initial);
    commit(
        &journal,
        &mut full,
        &mut rng,
        &token,
        &mut old,
        &next,
        &mut buffers,
    )
    .unwrap();
    let bits = full.steps();
    let candidate = 1 - token.bank();
    let commit_offset = layout.commit_offset(candidate).unwrap();
    let mut cases = 0u64;
    let mut successor_recoveries = 0u64;
    let mut old_recoveries = 0u64;
    let mut quarantines = 0u64;
    for cut in (0..=bits).step_by(8) {
        let mut flash = baseline.copy_world();
        flash.arm_cut_after_bits(cut);
        let mut retired = copy_public(&initial);
        let mut buffers = Buffers::new();
        let acknowledged = match commit(
            &journal,
            &mut flash,
            &mut rng,
            &token,
            &mut retired,
            &next,
            &mut buffers,
        ) {
            Ok(_) => true,
            Err(JournalError::Flash) => false,
            Err(_) => panic!("directory mutation failed outside the armed physical cut"),
        };
        let committed = flash.completed_page(commit_offset);
        flash.disarm();
        let mut reboot_buffers = Buffers::new();
        match journal.recover(&mut flash, &mut rng, &mut reboot_buffers.work()) {
            Ok(recovered) => {
                if check_cut_recovery(recovered, &flash, layout, committed || acknowledged) {
                    successor_recoveries += 1;
                } else {
                    old_recoveries += 1;
                }
            }
            Err(JournalError::Damaged) => {
                assert!(
                    !committed && !acknowledged,
                    "recoverable committed directory was quarantined"
                );
                quarantines += 1;
            }
            Err(_) => {
                panic!("acknowledged directory silently became blank/uncommitted or unrecoverable")
            }
        }
        cases += 1;
    }
    println!(
        "KES_DIRECTORY_FAULT_SUMMARY {{\"version\":1,\"byte_boundary_cuts\":{cases},\"successor_recoveries\":{successor_recoveries},\"old_recoveries\":{old_recoveries},\"ambiguous_quarantines\":{quarantines}}}"
    );
    assert!(successor_recoveries > 0 && old_recoveries > 0 && quarantines > 0);
}
