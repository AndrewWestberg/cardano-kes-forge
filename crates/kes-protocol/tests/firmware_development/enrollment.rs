//! Host regression for the actual firmware adapter, canonical USB dispatch and
//! authenticated journals. Provisioning is an explicit fixture action, not boot.
use super::*;
use ed25519_dalek::Signer;
use kes_core::{
    enrollment::EnrollmentStorage,
    journal::{
        DirectoryCodec, Flash, Journal, JournalContext, JournalLayout, JournalScope,
        JournalWorkspace, ObjectWorkspace, SecretCache, Workspaces,
    },
    management::{self, Action, SigningFields, Target},
    session::HostSession,
    state::{DeviceConfig, DeviceCredential, DeviceMode, DirectorySnapshot, Health},
    types::{DeviceIdentityBinding, IncarnationId, ManagementSequence, PoolId, Revision},
};
use sha2::{Digest, Sha256};

#[allow(dead_code)]
#[path = "../../../kes-core/tests/journal_faults/flash.rs"]
mod flash;
use flash::NorFlash;

const ROOT: [u8; 32] = [0xa0; 32];
const COLD: [u8; 32] = [0xa1; 32];
const INCARNATION: IncarnationId = IncarnationId::from_bytes([0xa2; 16]);

fn handler(boot: u8) -> DevelopmentHandler {
    DevelopmentHandler::new(
        DEVICE,
        DeviceIdentityKey::from_seed(Zeroizing::new(IDENTITY_SEED)),
        DeviceHpkeKey::from_seed(Zeroizing::new(HPKE_SEED)),
        [boot; 32],
        // Deliberately not the directory credential: storage must be authority.
        SigningKey::from_bytes(&[0xee; 32])
            .verifying_key()
            .to_bytes(),
        ChaCha20Rng::from_seed([boot; 32]),
        DevelopmentEvidence {
            firmware_digest: FIRMWARE_DIGEST,
            hardware_policy_digest: POLICY_DIGEST,
            security_version: 0,
            capability_evidence: b"disposable-a2-no-otp",
        },
    )
}

fn encoded(build: impl FnOnce(&mut Encoder<'_>)) -> Vec<u8> {
    let mut bytes = [0; MAX_FRAME_BYTES];
    let mut encoder = Encoder::new(&mut bytes);
    build(&mut encoder);
    encoder.finish().unwrap().encoded().to_vec()
}

fn signed_enrollment(signer: &SigningKey, request: u8) -> Vec<u8> {
    let pool = PoolId::from_cold_verification_key(&COLD);
    let recipient = [0x71; 32];
    let recipient_id: [u8; 32] = Sha256::digest(recipient).into();
    let payload = encoded(|e| {
        e.map(10).unwrap();
        e.text("pool").unwrap();
        e.bytes(pool.as_bytes()).unwrap();
        e.text("device").unwrap();
        e.bytes(DEVICE.as_bytes()).unwrap();
        e.text("network").unwrap();
        e.map(4).unwrap();
        e.text("network_magic").unwrap();
        e.uint(42).unwrap();
        e.text("max_kes_evolutions").unwrap();
        e.uint(64).unwrap();
        e.text("slots_per_kes_period").unwrap();
        e.uint(64).unwrap();
        e.text("shelley_genesis_digest").unwrap();
        e.bytes(&[0x72; 32]).unwrap();
        e.text("version").unwrap();
        e.uint(1).unwrap();
        e.text("incarnation").unwrap();
        e.bytes(INCARNATION.as_bytes()).unwrap();
        e.text("recipient_id").unwrap();
        e.bytes(&recipient_id).unwrap();
        e.text("credential_epoch").unwrap();
        e.uint(0).unwrap();
        e.text("machine_public_key").unwrap();
        e.bytes(&[0x73; 32]).unwrap();
        e.text("recipient_public_key").unwrap();
        e.bytes(&recipient).unwrap();
        e.text("cold_verification_key").unwrap();
        e.bytes(&COLD).unwrap();
    });
    let mut transcript = [0; 4608];
    let length = management::encode_signing_message(
        SigningFields {
            device: DEVICE,
            target: Target::Pool {
                pool,
                incarnation: INCARNATION,
            },
            sequence: ManagementSequence::new(1),
            request: RequestId::from_bytes([request; 16]),
            expected_revision: Revision::new(0),
            action: Action::Enroll,
            canonical_payload: Value::parse(&payload).unwrap(),
        },
        &mut transcript,
    )
    .unwrap();
    let signature = signer.sign(&transcript[..length]).to_bytes();
    encoded(|e| {
        e.map(9).unwrap();
        e.text("pool").unwrap();
        e.bytes(pool.as_bytes()).unwrap();
        e.text("action").unwrap();
        e.text("ENROLL").unwrap();
        e.text("device").unwrap();
        e.bytes(DEVICE.as_bytes()).unwrap();
        e.text("request").unwrap();
        e.bytes(&[request; 16]).unwrap();
        e.text("signature").unwrap();
        e.bytes(&signature).unwrap();
        e.text("incarnation").unwrap();
        e.bytes(INCARNATION.as_bytes()).unwrap();
        e.text("canonical_payload").unwrap();
        e.bytes(&payload).unwrap();
        e.text("expected_revision").unwrap();
        e.uint(0).unwrap();
        e.text("management_sequence").unwrap();
        e.uint(1).unwrap();
    })
}

fn manage(session: &[u8; 16], sequence: u64, payload: &[u8], mac: [u8; 32]) -> Vec<u8> {
    encoded(|e| {
        e.map(11).unwrap();
        e.text("op").unwrap();
        e.text("MANAGE").unwrap();
        e.text("mac").unwrap();
        e.bytes(&mac).unwrap();
        e.text("seq").unwrap();
        e.uint(sequence).unwrap();
        e.text("pool").unwrap();
        e.null().unwrap();
        e.text("device").unwrap();
        e.bytes(DEVICE.as_bytes()).unwrap();
        e.text("payload").unwrap();
        e.value(Value::parse(payload).unwrap()).unwrap();
        e.text("request").unwrap();
        e.bytes(map(payload).required("request").unwrap().bytes().unwrap())
            .unwrap();
        e.text("session").unwrap();
        e.bytes(session).unwrap();
        e.text("version").unwrap();
        e.uint(1).unwrap();
        e.text("budget_ms").unwrap();
        e.uint(500).unwrap();
        e.text("incarnation").unwrap();
        e.null().unwrap();
    })
}

struct Rig {
    flash: NorFlash,
    firmware: DevelopmentHandler,
    usb: UsbDispatcher,
    journal: JournalWorkspace,
    object: ObjectWorkspace,
    cache: SecretCache,
    now: u64,
}

impl Rig {
    fn new(mut flash: NorFlash, boot: u8) -> Self {
        flash.invalidate_cache().unwrap();
        Self {
            flash,
            firmware: handler(boot),
            usb: UsbDispatcher::new(),
            journal: JournalWorkspace::new(),
            object: ObjectWorkspace::new(),
            cache: SecretCache::new(),
            now: 100,
        }
    }

    fn send(&mut self, request: &[u8]) -> Result<Vec<u8>, usb::UsbError> {
        self.now += 10;
        let storage = EnrollmentStorage::new(DEVICE, 0, 16384, &ROOT).unwrap();
        let mut work = Workspaces {
            journal: &mut self.journal,
            object: &mut self.object,
            cache: &mut self.cache,
        };
        dispatch(
            &mut self.usb,
            &mut self
                .firmware
                .with_enrollment(&storage, &mut self.flash, &mut work),
            request,
            self.now,
        )
    }

    fn open(&mut self, machine: &SigningKey) -> Result<HostSession, usb::UsbError> {
        let request = RequestId::from_bytes([0xb2; 16]);
        let challenge = [0xb3; 32];
        let info = self.send(&info_request(request, challenge)).unwrap();
        let envelope = Envelope::parse(&info, EnvelopeKind::InfoResponse).unwrap();
        let identity = DeviceIdentityKey::from_seed(Zeroizing::new(IDENTITY_SEED));
        let mut scratch = [0; INFO_TRANSCRIPT_BYTES];
        let view = verify_info(
            envelope.map(),
            DEVICE,
            request,
            &challenge,
            &identity.verification_key(),
            &mut scratch,
        )
        .unwrap();
        let counters = envelope.payload().required("open_counters").unwrap();
        let counter = counters
            .array()
            .unwrap()
            .next()
            .unwrap()
            .map()
            .unwrap()
            .required("open_counter")
            .unwrap()
            .uint()
            .unwrap();
        let context = OpenContext::new(
            DEVICE,
            view.boot_nonce,
            Scope::Management,
            CredentialEpoch::new(0),
            counter,
            RequestId::from_bytes([0xb4; 16]),
        );
        let (open, pending) = begin_open(
            context,
            &view.hpke_public_key,
            machine,
            &mut ChaCha20Rng::from_seed([0xb5; 32]),
        )
        .unwrap();
        let response = self.send(&open_request(&open))?;
        Ok(pending
            .complete(
                Envelope::parse(&response, EnvelopeKind::OpenResponse)
                    .unwrap()
                    .map(),
            )
            .unwrap())
    }

    fn enroll(
        &mut self,
        host: &mut HostSession,
        payload: &[u8],
        seq: u64,
    ) -> Result<Vec<u8>, usb::UsbError> {
        let unsigned = manage(host.session_id(), seq, payload, [0; 32]);
        let mac = host.request_mac(map(&unsigned)).unwrap();
        let response = self.send(&manage(host.session_id(), seq, payload, mac))?;
        let envelope = Envelope::parse(&response, EnvelopeKind::DeviceResponse).unwrap();
        host.authenticate_response(
            envelope.map(),
            RequestId::try_from(map(payload).required("request").unwrap().bytes().unwrap())
                .unwrap(),
            "MANAGE",
            seq,
        )
        .unwrap();
        assert_eq!(
            envelope.map().required("status").unwrap().text().unwrap(),
            "OK"
        );
        assert_eq!(
            envelope
                .payload()
                .required("revision")
                .unwrap()
                .uint()
                .unwrap(),
            0
        );
        assert_eq!(
            envelope
                .payload()
                .required("management_sequence")
                .unwrap()
                .uint()
                .unwrap(),
            1
        );
        Ok(response)
    }

    fn assert_durable(&mut self) {
        let storage = EnrollmentStorage::new(DEVICE, 0, 16384, &ROOT).unwrap();
        let directory = storage
            .recover_pending(
                &mut self.flash,
                &mut ChaCha20Rng::from_seed([0xb6; 32]),
                &mut Workspaces {
                    journal: &mut self.journal,
                    object: &mut self.object,
                    cache: &mut self.cache,
                },
            )
            .unwrap();
        assert!(directory.state.pending_enrollment.is_none());
        let entries: Vec<_> = directory.state.live.iter().flatten().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].pool_id(),
            PoolId::from_cold_verification_key(&COLD)
        );
        assert_eq!(entries[0].incarnation(), INCARNATION);
        assert!(self.cache.is_erased());
    }
}

fn provision(management: &SigningKey) -> NorFlash {
    let machine = SigningKey::from_bytes(&MACHINE_SEED)
        .verifying_key()
        .to_bytes();
    let snapshot = DirectorySnapshot {
        config: DeviceConfig {
            identity: DeviceIdentityBinding::new(DEVICE, [0x32; 32], [0x33; 32]),
            silicon_revision: 2,
            firmware_digest: FIRMWARE_DIGEST,
            security_version: 0,
            hardware_policy_digest: POLICY_DIGEST,
            mode: DeviceMode::Development,
            health: Health::Healthy,
            management_root_public_key: management.verifying_key().to_bytes(),
            management_transport_public_key: machine,
        },
        revision: Revision::new(0),
        retirement: None,
        credential: DeviceCredential::new(machine),
        pending_deletion: None,
        pending_enrollment: None,
        live: [None; kes_core::MAX_POOLS],
        tombstones: [None; kes_core::state::DIRECTORY_IDENTITY_CAPACITY],
    };
    let mut rig = Rig::new(NorFlash::new(16384 + 32768 * kes_core::MAX_POOLS), 2);
    Journal::<DirectoryCodec>::new(
        JournalContext {
            device: DEVICE,
            scope: JournalScope::Directory,
        },
        JournalLayout::directory(0).unwrap(),
        &ROOT,
    )
    .unwrap()
    .initialize(
        &mut rig.flash,
        &mut ChaCha20Rng::from_seed([0xb7; 32]),
        &snapshot,
        &mut Workspaces {
            journal: &mut rig.journal,
            object: &mut rig.object,
            cache: &mut rig.cache,
        },
    )
    .unwrap();
    rig.flash
}

#[test]
fn durable_enrollment_requires_both_authorities_and_replays_across_a_real_reboot() {
    let management = SigningKey::from_bytes(&[0xc0; 32]);
    let machine = SigningKey::from_bytes(&MACHINE_SEED);
    let signed = signed_enrollment(&management, 0xc1);
    let baseline = provision(&management);
    let mut rig = Rig::new(baseline.copy_world(), 2);
    assert_eq!(
        rig.open(&SigningKey::from_bytes(&[0xc2; 32]))
            .err()
            .unwrap()
            .status,
        kes_protocol::Status::AuthFailed
    );
    assert_eq!(rig.flash.raw(), baseline.raw());

    // Valid transport authentication cannot substitute for the offline root.
    let mut host = rig.open(&machine).unwrap();
    let unauthorized = signed_enrollment(&SigningKey::from_bytes(&[0xc3; 32]), 0xc1);
    assert_eq!(
        rig.enroll(&mut host, &unauthorized, 0).unwrap_err().status,
        kes_protocol::Status::AuthFailed
    );
    assert_eq!(rig.flash.raw(), baseline.raw());

    // Alter an actually signed field, then authenticate that altered transport.
    let mut tampered = signed.clone();
    let request = map(&signed).required("request").unwrap().bytes().unwrap();
    let position = signed
        .windows(request.len())
        .position(|w| w == request)
        .unwrap();
    tampered[position] ^= 1;
    let mut host = rig.open(&machine).unwrap();
    assert_eq!(
        rig.enroll(&mut host, &tampered, 0).unwrap_err().status,
        kes_protocol::Status::AuthFailed
    );
    assert_eq!(rig.flash.raw(), baseline.raw());

    let mut host = rig.open(&machine).unwrap();
    assert_eq!(
        rig.send(&manage(host.session_id(), 0, &signed, [0; 32]))
            .unwrap_err()
            .status,
        kes_protocol::Status::AuthFailed
    );
    assert_eq!(rig.flash.raw(), baseline.raw());
    host = rig.open(&machine).unwrap();
    rig.enroll(&mut host, &signed, 0).unwrap();
    rig.assert_durable();
    let committed = rig.flash.copy_world();

    // New sessions, scheduler, RNG and workspaces; only encrypted NOR survives.
    let mut reboot = Rig::new(committed.copy_world(), 3);
    let mut host = reboot.open(&machine).unwrap();
    reboot.enroll(&mut host, &signed, 0).unwrap();
    reboot.assert_durable();
    assert_eq!(
        reboot.flash.raw(),
        committed.raw(),
        "exact replay must not rewrite flash"
    );
    let changed = signed_enrollment(&management, 0xc4);
    assert_eq!(
        reboot.enroll(&mut host, &changed, 1).unwrap_err().status,
        kes_protocol::Status::Replay
    );
    assert_eq!(reboot.flash.raw(), committed.raw());
    assert_eq!(
        reboot
            .send(&status_request(
                host.session_id(),
                RequestId::from_bytes([0xc5; 16]),
                2,
                [0; 32]
            ))
            .unwrap_err()
            .status,
        kes_protocol::Status::UnsupportedOperation
    );
}

#[test]
fn enrollment_transport_recovers_torn_nor_writes_without_false_success() {
    let management = SigningKey::from_bytes(&[0xc0; 32]);
    let machine = SigningKey::from_bytes(&MACHINE_SEED);
    let signed = signed_enrollment(&management, 0xc1);
    let baseline = provision(&management);
    let mut probe = Rig::new(baseline.copy_world(), 2);
    let mut host = probe.open(&machine).unwrap();
    probe.flash.arm_cut_after_bits(usize::MAX);
    probe.enroll(&mut host, &signed, 0).unwrap();
    let steps = probe.flash.steps();
    assert!(steps > 0);
    for cut in [0, steps / 2, steps - 1] {
        let mut rig = Rig::new(baseline.copy_world(), 2);
        let mut host = rig.open(&machine).unwrap();
        rig.flash.arm_cut_after_bits(cut);
        assert!(
            rig.enroll(&mut host, &signed, 0).is_err(),
            "cut {cut} returned success"
        );
        rig.flash.disarm();
        let mut reboot = Rig::new(rig.flash.copy_world(), 3);
        let mut host = reboot.open(&machine).unwrap();
        reboot.enroll(&mut host, &signed, 0).unwrap();
        reboot.assert_durable();
        let committed = reboot.flash.raw().to_vec();
        reboot.enroll(&mut host, &signed, 1).unwrap();
        assert_eq!(reboot.flash.raw(), committed);
    }
}

#[test]
fn ordinary_open_does_not_provision_blank_or_corrupt_storage() {
    let machine = SigningKey::from_bytes(&MACHINE_SEED);
    let mut blank = Rig::new(NorFlash::new(16384 + 32768 * kes_core::MAX_POOLS), 2);
    let before = blank.flash.raw().to_vec();
    assert!(blank.open(&machine).is_err());
    assert_eq!(blank.flash.raw(), before);
    let management = SigningKey::from_bytes(&[0xc0; 32]);
    let mut corrupt = provision(&management);
    // Destroy the authenticated directory's header, not merely unused space.
    corrupt.corrupt(0, 1).unwrap();
    let before = corrupt.raw().to_vec();
    let mut rig = Rig::new(corrupt, 2);
    assert!(rig.open(&machine).is_err());
    assert_eq!(rig.flash.raw(), before);
}
