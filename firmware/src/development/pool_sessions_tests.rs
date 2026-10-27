use super::*;
use ed25519_dalek::SigningKey;
use kes_core::{
    cbor::Value,
    session::{PendingHostOpen, begin_open},
    types::RequestId,
};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use zeroize::Zeroizing;

const DEVICE: DeviceId = DeviceId::from_bytes([1; 16]);
const NONCE: [u8; 32] = [2; 32];

fn authority(slot: usize, key: &SigningKey) -> PoolAuthority {
    PoolAuthority {
        slot: HardwareSlot::new(slot).unwrap(),
        pool: PoolId::from_bytes([slot as u8 + 10; 28]),
        incarnation: IncarnationId::from_bytes([slot as u8 + 20; 16]),
        public_key: key.verifying_key().to_bytes(),
        epoch: CredentialEpoch::new(4),
        revoked: false,
    }
}

fn request(
    authority: PoolAuthority,
    counter: u64,
    key: &SigningKey,
    hpke: &DeviceHpkeKey,
) -> (OpenRequest, PendingHostOpen) {
    let context = OpenContext::new(
        DEVICE,
        NONCE,
        authority.scope(),
        authority.epoch,
        counter,
        RequestId::from_bytes([counter as u8 + 30; 16]),
    );
    begin_open(
        context,
        &hpke.public_key(),
        key,
        &mut ChaCha20Rng::from_seed([7; 32]),
    )
    .unwrap()
}

fn unsigned_response(pending: &PendingPoolOpen<'_>, out: &mut [u8; 1024]) -> usize {
    let context = pending.context();
    let fields = pending.response_fields();
    let Scope::Pool { pool, incarnation } = context.scope else {
        panic!("pool OPEN")
    };
    let mut e = Encoder::new(out);
    e.map(9).unwrap();
    e.text("op").unwrap();
    e.text("OPEN").unwrap();
    e.text("mac").unwrap();
    e.bytes(&[0; 32]).unwrap();
    e.text("pool").unwrap();
    e.bytes(pool.as_bytes()).unwrap();
    e.text("device").unwrap();
    e.bytes(context.device.as_bytes()).unwrap();
    e.text("status").unwrap();
    e.text("OK").unwrap();
    e.text("payload").unwrap();
    e.map(2).unwrap();
    e.text("session").unwrap();
    e.bytes(&fields.session_id).unwrap();
    e.text("challenge_acknowledgement").unwrap();
    e.bytes(&fields.challenge_acknowledgement).unwrap();
    e.text("request").unwrap();
    e.bytes(context.request.as_bytes()).unwrap();
    e.text("version").unwrap();
    e.uint(1).unwrap();
    e.text("incarnation").unwrap();
    e.bytes(incarnation.as_bytes()).unwrap();
    e.finish().unwrap().encoded().len()
}

fn commit(pending: PendingPoolOpen<'_>, host: PendingHostOpen) {
    let mut bytes = [0; 1024];
    let length = unsigned_response(&pending, &mut bytes);
    let response = pending
        .commit(Value::parse(&bytes[..length]).unwrap().map().unwrap())
        .unwrap();
    // Verify the HPKE challenge acknowledgement AND response MAC as a real host.
    // The response's MAC is outside the response-MAC transcript, so update only
    // that canonical field before handing the complete map to the host.
    let offset = bytes[..length]
        .windows(34)
        .position(|w| w[0] == 0x58 && w[1] == 32 && w[2..] == [0; 32])
        .unwrap();
    bytes[offset + 2..offset + 34].copy_from_slice(&response.mac);
    host.complete(Value::parse(&bytes[..length]).unwrap().map().unwrap())
        .unwrap();
}

#[test]
fn signed_pool_open_rejects_cross_scope_wrong_key_and_stale_epoch() {
    let key = SigningKey::from_bytes(&[3; 32]);
    let wrong = SigningKey::from_bytes(&[4; 32]);
    let a = authority(0, &key);
    let b = authority(1, &wrong);
    let hpke = DeviceHpkeKey::from_seed(Zeroizing::new([5; 32]));
    let mut router = PoolSessions::new(DEVICE, NONCE);
    let mut sessions = SessionTable::new();
    let mut rng = ChaCha20Rng::from_seed([6; 32]);
    let (open, _) = request(a, 0, &key, &hpke);
    assert!(matches!(
        router.prepare_open(b, &open, &hpke, &mut rng, &mut sessions),
        Err(SessionError::WrongScope)
    ));
    let (open, _) = request(a, 0, &wrong, &hpke);
    assert!(matches!(
        router.prepare_open(a, &open, &hpke, &mut rng, &mut sessions),
        Err(SessionError::Authentication)
    ));
    let mut stale = a;
    stale.epoch = CredentialEpoch::new(3);
    let (open, _) = request(stale, 0, &key, &hpke);
    assert!(matches!(
        router.prepare_open(a, &open, &hpke, &mut rng, &mut sessions),
        Err(SessionError::CredentialChanged)
    ));
    assert_eq!(router.info_counter(a, &mut sessions).open_counter, 0);
    assert!(sessions.get(a.scope()).is_none());
}

#[test]
fn independent_counters_survive_disconnect_and_replay_fails_after_reboot() {
    let key = SigningKey::from_bytes(&[3; 32]);
    let a = authority(0, &key);
    let b = authority(1, &key);
    let hpke = DeviceHpkeKey::from_seed(Zeroizing::new([5; 32]));
    let mut router = PoolSessions::new(DEVICE, NONCE);
    let mut sessions = SessionTable::new();
    let mut rng = ChaCha20Rng::from_seed([6; 32]);
    let (open, host) = request(a, 0, &key, &hpke);
    commit(
        router
            .prepare_open(a, &open, &hpke, &mut rng, &mut sessions)
            .unwrap(),
        host,
    );
    assert!(sessions.get(a.scope()).unwrap().is_valid());
    assert_eq!(router.info_counter(a, &mut sessions).open_counter, 1);
    assert_eq!(router.info_counter(b, &mut sessions).open_counter, 0);
    let (other_open, other_host) = request(b, 0, &key, &hpke);
    commit(
        router
            .prepare_open(b, &other_open, &hpke, &mut rng, &mut sessions)
            .unwrap(),
        other_host,
    );
    assert!(sessions.get(a.scope()).unwrap().is_valid());
    assert!(sessions.get(b.scope()).unwrap().is_valid());
    assert_eq!(router.info_counter(a, &mut sessions).open_counter, 1);
    assert_eq!(router.info_counter(b, &mut sessions).open_counter, 1);
    router.disconnect(&mut sessions);
    assert!(sessions.get(a.scope()).is_none());
    assert!(sessions.get(b.scope()).is_none());
    assert!(matches!(
        router.prepare_open(a, &open, &hpke, &mut rng, &mut sessions),
        Err(SessionError::InvalidStructure)
    ));
    let mut rebooted = PoolSessions::new(DEVICE, [9; 32]);
    assert!(matches!(
        rebooted.prepare_open(a, &open, &hpke, &mut rng, &mut sessions),
        Err(SessionError::InvalidStructure)
    ));
}

#[test]
fn credential_recovery_changes_invalidate_sessions_without_resetting_counters() {
    let key = SigningKey::from_bytes(&[3; 32]);
    let a = authority(0, &key);
    let hpke = DeviceHpkeKey::from_seed(Zeroizing::new([5; 32]));
    let mut router = PoolSessions::new(DEVICE, NONCE);
    let mut sessions = SessionTable::new();
    let mut rng = ChaCha20Rng::from_seed([6; 32]);
    let (open, host) = request(a, 0, &key, &hpke);
    commit(
        router
            .prepare_open(a, &open, &hpke, &mut rng, &mut sessions)
            .unwrap(),
        host,
    );
    let mut revoked = a;
    revoked.revoked = true;
    assert_eq!(router.info_counter(revoked, &mut sessions).open_counter, 1);
    assert!(sessions.get(a.scope()).is_none());
    let (open, _) = request(a, 1, &key, &hpke);
    assert!(matches!(
        router.prepare_open(revoked, &open, &hpke, &mut rng, &mut sessions),
        Err(SessionError::Revoked)
    ));
    router.invalidate_slot(a.slot, &mut sessions);
    let mut reenrolled = a;
    reenrolled.incarnation = IncarnationId::from_bytes([99; 16]);
    assert_eq!(
        router.info_counter(reenrolled, &mut sessions).open_counter,
        1
    );
}

#[test]
fn uncommitted_open_does_not_consume_counter_or_install_session() {
    let key = SigningKey::from_bytes(&[3; 32]);
    let a = authority(0, &key);
    let hpke = DeviceHpkeKey::from_seed(Zeroizing::new([5; 32]));
    let mut router = PoolSessions::new(DEVICE, NONCE);
    let mut sessions = SessionTable::new();
    let mut rng = ChaCha20Rng::from_seed([6; 32]);
    let (open, _) = request(a, 0, &key, &hpke);
    drop(
        router
            .prepare_open(a, &open, &hpke, &mut rng, &mut sessions)
            .unwrap(),
    );
    assert_eq!(router.info_counter(a, &mut sessions).open_counter, 0);
    assert!(sessions.get(a.scope()).is_none());
}
