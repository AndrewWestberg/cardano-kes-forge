use cardano_kes_forge::host::operations::{Error, Identity, OperationRecord, State};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    record: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "kes-forge-operation-record-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            record: root.join("generate.operation.json"),
            root,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

fn identity() -> Identity {
    Identity {
        device: [1; 16],
        pool: Some([2; 28]),
        incarnation: Some([3; 16]),
        request: [4; 16],
        generation_number: Some(7),
    }
}

#[test]
fn identity_and_payload_are_durable_before_dispatch() {
    let fixture = Fixture::new();
    let record =
        OperationRecord::begin(&fixture.record, "GENERATE", identity(), b"canonical").unwrap();
    assert_eq!(record.state(), State::Pending);
    assert!(record.requires_status_reconciliation());
    let metadata = fs::metadata(&fixture.record).unwrap();
    assert_eq!(metadata.uid(), rustix::process::getuid().as_raw());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

    let resumed =
        OperationRecord::begin(&fixture.record, "GENERATE", identity(), b"canonical").unwrap();
    assert_eq!(resumed.identity(), identity());
    assert_eq!(resumed.canonical_payload(), Some(b"canonical".as_slice()));
    assert!(matches!(
        OperationRecord::begin(&fixture.record, "GENERATE", identity(), b"changed"),
        Err(Error::Conflict)
    ));
}

#[test]
fn restart_reconciles_unknown_without_rolling_back_committed_identity() {
    let fixture = Fixture::new();
    let mut record =
        OperationRecord::begin(&fixture.record, "GENERATE", identity(), b"canonical").unwrap();
    record.record_in_progress().unwrap();
    record.record_unknown().unwrap();

    let mut restarted = OperationRecord::load(&fixture.record).unwrap();
    assert_eq!(restarted.state(), State::Unknown);
    assert!(restarted.requires_status_reconciliation());
    restarted.record_in_progress().unwrap();
    restarted.record_committed(Some([9; 16])).unwrap();

    let mut committed = OperationRecord::load(&fixture.record).unwrap();
    assert_eq!(committed.state(), State::Committed);
    assert_eq!(committed.committed_generation(), Some([9; 16]));
    assert!(!committed.requires_status_reconciliation());
    assert!(matches!(committed.record_unknown(), Err(Error::Rollback)));
}

#[test]
fn reclaimed_generation_is_terminal_and_never_recreated() {
    let fixture = Fixture::new();
    let mut record =
        OperationRecord::begin(&fixture.record, "GENERATE", identity(), b"canonical").unwrap();
    record.record_in_progress().unwrap();
    record.record_result_reclaimed().unwrap();

    let mut restarted = OperationRecord::load(&fixture.record).unwrap();
    assert_eq!(restarted.state(), State::ResultReclaimed);
    assert!(!restarted.requires_status_reconciliation());
    assert!(matches!(
        restarted.record_in_progress(),
        Err(Error::Rollback)
    ));
    assert!(matches!(
        restarted.record_committed(Some([8; 16])),
        Err(Error::Rollback)
    ));
}
