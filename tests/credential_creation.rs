use cardano_kes_forge::host::{bootstrap, credentials};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "kes-forge-credential-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self { root }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn authority_creation_emits_matching_standard_keys_and_refuses_overwrite() {
    let fixture = Fixture::new();
    let public = fixture.root.join("management.public.json");
    let private = fixture.root.join("management.private.json");
    credentials::create_authority(bootstrap::AuthorityRole::Management, &public, &private).unwrap();
    let public_key = bootstrap::authority_public(
        &std::fs::read(&public).unwrap(),
        bootstrap::AuthorityRole::Management,
    )
    .unwrap();
    let private_key = bootstrap::authority_private(
        &std::fs::read(&private).unwrap(),
        bootstrap::AuthorityRole::Management,
    )
    .unwrap();
    assert_eq!(public_key, private_key.public);
    assert_eq!(std::fs::metadata(&private).unwrap().mode() & 0o777, 0o600);
    assert_eq!(
        std::fs::metadata(&private).unwrap().uid(),
        rustix::process::getuid().as_raw()
    );
    let before = std::fs::read(&private).unwrap();
    assert_eq!(
        credentials::create_authority(bootstrap::AuthorityRole::Management, &public, &private,),
        Err(credentials::Error::ExistingOutput)
    );
    assert_eq!(std::fs::read(&private).unwrap(), before);
}

#[test]
fn machine_creation_preserves_scope_identity_epoch_and_keypair() {
    let fixture = Fixture::new();
    let public = fixture.root.join("pool.public.json");
    let private = fixture.root.join("pool.private.json");
    let identity = credentials::MachineIdentity {
        scope: bootstrap::MachineScope::Pool,
        device: [0x11; 16],
        pool: Some([0x22; 28]),
        incarnation: Some([0x33; 16]),
        credential_epoch: 7,
    };
    credentials::create_machine(identity, &public, &private).unwrap();
    let public_key = bootstrap::machine_public(
        &std::fs::read(&public).unwrap(),
        bootstrap::MachineScope::Pool,
    )
    .unwrap();
    let private_key = bootstrap::machine_private(
        &std::fs::read(&private).unwrap(),
        bootstrap::MachineScope::Pool,
    )
    .unwrap();
    assert_eq!(public_key, private_key);
    assert_eq!(public_key.device, identity.device);
    assert_eq!(public_key.pool, identity.pool);
    assert_eq!(public_key.incarnation, identity.incarnation);
    assert_eq!(public_key.epoch, 7);

    assert_eq!(
        credentials::create_machine(
            credentials::MachineIdentity {
                scope: bootstrap::MachineScope::Management,
                pool: identity.pool,
                ..identity
            },
            &fixture.root.join("bad.public.json"),
            &fixture.root.join("bad.private.json"),
        ),
        Err(credentials::Error::InvalidIdentity)
    );
}
