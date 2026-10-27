//! Feature-bound, custody-separated host packages. This never installs system
//! files, provisions hardware, generates keys, or copies operator configuration.
use crate::evidence::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    Primary,
    Recovery,
    Management,
    Provisioning,
    Development,
}

impl Profile {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "primary" => Ok(Self::Primary),
            "recovery" => Ok(Self::Recovery),
            "management" => Ok(Self::Management),
            "provisioning" => Ok(Self::Provisioning),
            "development" => Ok(Self::Development),
            _ => Err(
                "profile must be primary, recovery, management, provisioning or development".into(),
            ),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Recovery => "recovery",
            Self::Management => "management",
            Self::Provisioning => "provisioning",
            Self::Development => "development",
        }
    }

    fn commands(self) -> &'static [&'static str] {
        match self {
            Self::Primary => &[
                "key-gen-KES",
                "status",
                "certify",
                "activate",
                "schedule",
                "backup fetch",
                "credential create",
                "management enrollment-create",
                "management prepare",
                "management apply",
                "firmware update",
            ],
            Self::Recovery => &[
                "backup recover",
                "recipient create",
                "recipient change-password",
            ],
            Self::Management => &["authority key-create", "management sign"],
            Self::Provisioning => &[
                "authority key-create",
                "provision inspect",
                "provision prepare",
                "provision apply",
            ],
            Self::Development => &[
                "key-gen-KES",
                "status",
                "certify",
                "activate",
                "schedule",
                "backup fetch",
                "credential create",
                "management enrollment-create",
                "management prepare",
                "management apply",
                "dev inspect",
            ],
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutableProfile {
    version: u32,
    profile: String,
    commands: Vec<String>,
}

fn validate_surface(profile: Profile, actual: &ExecutableProfile) -> Result<()> {
    if actual.version != 1 || actual.profile != profile.name() {
        return Err(format!(
            "executable installation profile does not match {}",
            profile.name()
        ));
    }
    let actual_set: BTreeSet<&str> = actual.commands.iter().map(String::as_str).collect();
    if actual_set.len() != actual.commands.len() {
        return Err("executable reported duplicate command capabilities".into());
    }
    let expected: BTreeSet<&str> = profile.commands().iter().copied().collect();
    let missing: Vec<_> = expected.difference(&actual_set).copied().collect();
    let forbidden: Vec<_> = actual_set.difference(&expected).copied().collect();
    if !missing.is_empty() || !forbidden.is_empty() {
        return Err(format!(
            "{} package is incomplete or violates custody: missing implemented command surface {missing:?}; forbidden command surface {forbidden:?}; no distributable manifest published",
            profile.name()
        ));
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct Package {
    pub manifest: PathBuf,
    pub manifest_sha256: String,
}

#[derive(Serialize)]
struct Artifact {
    path: String,
    sha256: String,
    size: u64,
}

#[derive(Serialize)]
struct Manifest {
    version: u32,
    kind: &'static str,
    profile: &'static str,
    target: &'static str,
    cargo_features: [&'static str; 1],
    default_features: bool,
    locked: bool,
    cargo_lock_sha256: String,
    cargo_toml_sha256: String,
    commands: Vec<String>,
    artifacts: Vec<Artifact>,
    usb_rules_included: bool,
    usb_access_prerequisite: &'static str,
    private_material_included: bool,
    hardware_actions_performed: bool,
    release_readiness_claimed: bool,
}

/// Build exactly one role. The output must not exist, and its parent must
/// already exist under trusted ownership. Failed runs remain visibly incomplete
/// (no package manifest); retry requires a fresh output path.
///
/// No USB rules are generated: an independently authorized legitimate USB ID
/// allocation and local access policy are prerequisites to system integration.
/// In particular, prototype USB IDs never become distributable authorization.
pub fn build(workspace: &Path, profile: Profile, output: &Path) -> Result<Package> {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return Err("host packaging supports Linux x86_64 only".into());
    }
    let workspace = workspace
        .canonicalize()
        .map_err(|e| format!("workspace: {e}"))?;
    let lock_hash = hash(&workspace.join("Cargo.lock"))?.0;
    let manifest_hash = hash(&workspace.join("Cargo.toml"))?.0;
    let directory = create_output(output)?;
    // Keep the output inode pinned even if an ancestor is renamed. Every write
    // and the Cargo target directory resolve through this held descriptor.
    let pinned = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    // Child processes resolve the descriptor through this still-running parent;
    // the descriptor itself is deliberately close-on-exec.
    let inherited_path = PathBuf::from(format!(
        "/proc/{}/fd/{}",
        std::process::id(),
        directory.as_raw_fd()
    ));
    let build_directory = inherited_path.join(".build");
    let mut command = Command::new("cargo");
    command
        .current_dir(&workspace)
        .args([
            "build",
            "--locked",
            "--release",
            "--no-default-features",
            "--features",
            profile.name(),
            "--package",
            "cardano-kes-forge",
            "--target",
            "x86_64-unknown-linux-gnu",
            "--bin",
            "kes-forge",
            "--target-dir",
        ])
        .arg(&build_directory);
    if profile == Profile::Primary {
        command.args(["--bin", "kes-forged"]);
    }
    let status = command
        .stdin(Stdio::null())
        .status()
        .map_err(|e| format!("start locked Cargo build: {e}"))?;
    if !status.success() {
        return Err(format!(
            "{} locked feature-isolated build failed ({status}); no package published",
            profile.name()
        ));
    }
    if hash(&workspace.join("Cargo.lock"))?.0 != lock_hash
        || hash(&workspace.join("Cargo.toml"))?.0 != manifest_hash
    {
        return Err("Cargo dependency inputs changed during packaging".into());
    }
    let binaries = build_directory.join("x86_64-unknown-linux-gnu/release");
    let mut artifacts = vec![stage(&binaries.join("kes-forge"), &pinned, "kes-forge")?];
    let executable = inherited_path.join("kes-forge");
    let actual = inspect(&executable, profile)?;
    if profile == Profile::Primary {
        artifacts.push(stage(&binaries.join("kes-forged"), &pinned, "kes-forged")?);
        validate_version(&inherited_path.join("kes-forged"), profile, "kes-forged")?;
    }
    fs::remove_dir_all(&build_directory).map_err(|e| format!("remove owned build staging: {e}"))?;
    let manifest = Manifest {
        version: 1,
        kind: "feature-bound-host-package",
        profile: profile.name(),
        target: "x86_64-unknown-linux-gnu",
        cargo_features: [profile.name()],
        default_features: false,
        locked: true,
        cargo_lock_sha256: lock_hash,
        cargo_toml_sha256: manifest_hash,
        commands: actual.commands,
        artifacts,
        usb_rules_included: false,
        usb_access_prerequisite: "Administrator must independently authorize legitimate allocated USB IDs and least-privilege access; no prototype-ID rule is supplied",
        private_material_included: false,
        hardware_actions_performed: false,
        release_readiness_claimed: false,
    };
    let bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| format!("encode public package manifest: {e}"))?;
    publish(&pinned.join("manifest.json"), &bytes, 0o600)?;
    let manifest_sha256 = hex(&Sha256::digest(&bytes));
    publish(
        &pinned.join("manifest.sha256"),
        format!("{manifest_sha256}  manifest.json\n").as_bytes(),
        0o600,
    )?;
    directory
        .sync_all()
        .map_err(|e| format!("sync package directory: {e}"))?;
    Ok(Package {
        manifest: output.join("manifest.json"),
        manifest_sha256,
    })
}

fn inspect(executable: &Path, profile: Profile) -> Result<ExecutableProfile> {
    validate_version(executable, profile, "kes-forge")?;
    let output = Command::new(executable)
        .arg("--installation-profile")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("inspect executable profile: {e}"))?;
    if !output.status.success() || output.stdout.len() > 16384 {
        return Err("executable lacks bounded --installation-profile introspection; cannot validate implemented role surface".into());
    }
    let actual: ExecutableProfile = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("invalid executable installation profile: {e}"))?;
    validate_surface(profile, &actual)?;
    // Exercise dispatch rejection on the actual feature-bound binary. No
    // accepted syntax or existing input is supplied, so probes cannot authorize
    // hardware mutation or generate/export private material.
    let all: BTreeSet<_> = [
        Profile::Primary,
        Profile::Recovery,
        Profile::Management,
        Profile::Provisioning,
        Profile::Development,
    ]
    .iter()
    .flat_map(|p| p.commands().iter().copied())
    .collect();
    for forbidden in all
        .into_iter()
        .filter(|name| !profile.commands().contains(name))
    {
        let result = Command::new(executable)
            .args(forbidden.split(' '))
            .arg("--package-denial-probe")
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("probe forbidden command {forbidden}: {e}"))?;
        if !matches!(result.status.code(), Some(2 | 3)) {
            return Err(format!(
                "forbidden command {forbidden} did not reject the {profile:?} package probe"
            ));
        }
    }
    Ok(actual)
}

fn validate_version(executable: &Path, profile: Profile, binary: &str) -> Result<()> {
    let output = Command::new(executable)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("execute staged binary: {e}"))?;
    let expected = format!(
        "{binary} {} ({})\n",
        env!("CARGO_PKG_VERSION"),
        profile.name()
    );
    if !output.status.success() || output.stdout != expected.as_bytes() {
        return Err(format!(
            "staged {binary} does not report the required {} profile/version",
            profile.name()
        ));
    }
    Ok(())
}

fn stage(source: &Path, directory: &Path, name: &str) -> Result<Artifact> {
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(source)
        .map_err(|e| format!("open built executable: {e}"))?;
    if !input.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("built executable is not a regular file".into());
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(directory.join(name))
        .map_err(|e| format!("stage executable without overwrite: {e}"))?;
    std::io::copy(&mut input, &mut output).map_err(|e| format!("copy executable: {e}"))?;
    output
        .sync_all()
        .map_err(|e| format!("sync executable: {e}"))?;
    let (sha256, size) = hash(&directory.join(name))?;
    Ok(Artifact {
        path: name.into(),
        sha256,
        size,
    })
}

fn publish(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|e| format!("publish package metadata without overwrite: {e}"))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("sync package metadata: {e}"))
}

fn hash(path: &Path) -> Result<(String, u64)> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|e| format!("open package hash input: {e}"))?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("package hash input must be a regular file".into());
    }
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut size = 0;
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|e| format!("hash package file: {e}"))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
        size += count as u64;
    }
    Ok((hex(&digest.finalize()), size))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("write to string");
    }
    output
}

fn create_output(path: &Path) -> Result<File> {
    use rustix::fs::{Mode, OFlags, mkdirat, open, openat};
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(path)
    };
    let mut components = absolute.components().peekable();
    let mut directory = File::from(
        open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| format!("open output root: {e}"))?,
    );
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            if component == Component::RootDir {
                continue;
            }
            return Err("package output must not contain dot or parent traversal".into());
        };
        let metadata = directory.metadata().map_err(|e| e.to_string())?;
        let uid = rustix::process::getuid().as_raw();
        let trusted_sticky = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
        if (metadata.uid() != 0 && metadata.uid() != uid)
            || (metadata.mode() & 0o022 != 0 && !trusted_sticky)
        {
            return Err("package output ancestor must be trusted-owner controlled and not group/other writable".into());
        }
        if components.peek().is_none() {
            if metadata.uid() != uid {
                return Err("package output parent must belong to the invoking owner".into());
            }
            mkdirat(&directory, name, Mode::from_raw_mode(0o700)).map_err(|e| {
                format!("create new owner-only package output (existing paths refused): {e}")
            })?;
            directory
                .sync_all()
                .map_err(|e| format!("sync new package output parent: {e}"))?;
        }
        directory = File::from(
            openat(
                &directory,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| format!("open package output ancestor without symlinks: {e}"))?,
        );
    }
    if absolute.parent().is_none() {
        return Err("package output must be a new directory".into());
    }
    Ok(directory)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn surface(profile: Profile) -> ExecutableProfile {
        ExecutableProfile {
            version: 1,
            profile: profile.name().into(),
            commands: profile.commands().iter().map(|s| (*s).into()).collect(),
        }
    }

    #[test]
    fn rejects_missing_implemented_surface() {
        let mut actual = surface(Profile::Development);
        actual.commands.retain(|s| s != "dev inspect");
        let error = validate_surface(Profile::Development, &actual).unwrap_err();
        assert!(error.contains("dev inspect"));
        let mut actual = surface(Profile::Provisioning);
        actual.commands.retain(|s| s != "provision apply");
        assert!(validate_surface(Profile::Provisioning, &actual).is_err());
    }

    #[test]
    fn primary_cannot_contain_offline_or_recovery_authority() {
        for forbidden in [
            "recipient create",
            "recipient change-password",
            "backup recover",
            "authority key-create",
            "management sign",
            "provision apply",
            "dev inspect",
        ] {
            let mut actual = surface(Profile::Primary);
            actual.commands.push(forbidden.into());
            assert!(
                validate_surface(Profile::Primary, &actual).is_err(),
                "{forbidden}"
            );
        }
    }

    #[test]
    fn profile_identity_and_duplicate_capabilities_are_rejected() {
        let mut actual = surface(Profile::Recovery);
        assert!(validate_surface(Profile::Primary, &actual).is_err());
        actual.commands.push("backup recover".into());
        assert!(validate_surface(Profile::Recovery, &actual).is_err());
        assert!(Profile::parse("primary,recovery").is_err());
    }

    #[test]
    fn package_output_refuses_collision_and_untrusted_parents() {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base =
            std::env::temp_dir().join(format!(".package-test-{}-{nonce}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
        let child = base.join("stage");
        create_output(&child).unwrap();
        assert!(create_output(&child).is_err());
        publish(
            &child.join("manifest.json"),
            b"existing-owner-content",
            0o600,
        )
        .unwrap();
        assert!(publish(&child.join("manifest.json"), b"replacement", 0o600).is_err());
        assert_eq!(
            fs::read(child.join("manifest.json")).unwrap(),
            b"existing-owner-content"
        );
        let link = base.join("symlink");
        std::os::unix::fs::symlink(&child, &link).unwrap();
        assert!(create_output(&link.join("nested")).is_err());
        fs::set_permissions(&base, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(create_output(&base.join("untrusted")).is_err());
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(&base).unwrap();
    }
}
