//! Public scenario declarations. Operational secrets are created only by the
//! owning workstation's supported workflows, never by this manifest generator.
use crate::evidence::{self, Result};
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;
use std::fs;
use std::io::Read;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Workstation {
    Primary,
    Recovery,
    Management,
    Provisioning,
    ColdAuthority,
    Development,
    Network,
    PowerController,
}

impl Workstation {
    const ALL: [Self; 8] = [
        Self::Primary,
        Self::Recovery,
        Self::Management,
        Self::Provisioning,
        Self::ColdAuthority,
        Self::Development,
        Self::Network,
        Self::PowerController,
    ];

    fn directory(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Recovery => "recovery",
            Self::Management => "management",
            Self::Provisioning => "provisioning",
            Self::ColdAuthority => "cold-authority",
            Self::Development => "development",
            Self::Network => "network",
            Self::PowerController => "power-controller",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Content {
    PublicRecord,
    PrivateOperationalFile,
    EncryptedArtifact,
    Executable,
    UnixSocket,
    PhysicalControllerEndpoint,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileReference {
    pub workstation: Workstation,
    pub path: PathBuf,
    pub content: Content,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkstationRuntime {
    pub workstation: Workstation,
    pub directory: PathBuf,
    pub must_not_share_workstation_with: Vec<Workstation>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimePolicy {
    pub root: PathBuf,
    pub directory_mode: u32,
    pub private_file_mode: u32,
    pub disable_core_dumps: bool,
    pub protect_transient_secret_memory: bool,
    pub populate_only_through_supported_workflows: bool,
    pub paths_are_local_to_the_named_workstation: bool,
    pub workstations: [WorkstationRuntime; 8],
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkScenario {
    pub network: ControlledNetwork,
    pub network_magic: u32,
    pub slots_per_kes_period: u64,
    pub max_kes_evolutions: u8,
    pub slot_length_milliseconds: u64,
    pub exact_shelley_genesis: FileReference,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlledNetwork {
    Controlled,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestKind {
    PublicScenarioDeclaration,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IrreversibleAuthorization {
    RequiredForEachAttendedCeremony,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PoolScenario {
    /// An ordering label, never a PoolId, device identity or hardware slot.
    pub case_label: String,
    pub enrollment_record: FileReference,
    pub cold_verification_key: FileReference,
    pub cold_signing_key: FileReference,
    pub recipient_public_key: FileReference,
    pub recipient_private_key_file: FileReference,
    pub machine_credential_public: FileReference,
    pub machine_credential_private: FileReference,
    pub vrf_verification_key: FileReference,
    pub vrf_signing_key: FileReference,
    pub connection: FileReference,
    pub kes_verification_key: FileReference,
    pub encrypted_initial_backup: FileReference,
    pub recovered_conventional_key: FileReference,
    pub operational_certificate: FileReference,
    pub certificate_counter: FileReference,
    pub leader_schedule: FileReference,
    pub signing_socket: FileReference,
    pub node_socket: FileReference,
    pub development_inspection: FileReference,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutableRequirement {
    pub name: String,
    pub file: FileReference,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PeerScenario {
    pub name: String,
    pub executable: FileReference,
    pub configuration: FileReference,
    pub topology: FileReference,
    pub socket: FileReference,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExecutable {
    pub path: PathBuf,
    pub sha256: String,
    pub version_output: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBaseline {
    pub provenance_file: PathBuf,
    pub source_commit: String,
    pub executable: NativeExecutable,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRequirements {
    pub silicon: String,
    pub minimum_qualification_revision: String,
    pub stock_clock_hz: u32,
    pub fitted_flash_bytes: u32,
    pub development_and_release_devices_must_differ: bool,
    pub development_identity: FileReference,
    pub release_identity: FileReference,
    pub provisioning_record: FileReference,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioManifest {
    pub version: u32,
    pub kind: ManifestKind,
    /// Public correlation only; never use this value to seed secret generation.
    pub scenario_id: String,
    pub disposable: bool,
    pub fixture_directory: PathBuf,
    pub runtime: RuntimePolicy,
    pub network: NetworkScenario,
    pub devices: DeviceRequirements,
    pub irreversible_authorization: IrreversibleAuthorization,
    pub cli_baseline: NativeBaseline,
    pub node_baseline: NativeBaseline,
    pub executables: Vec<ExecutableRequirement>,
    pub peers: [PeerScenario; 2],
    pub power_controller_executable: FileReference,
    pub qualification_executable: FileReference,
    pub power_controller_endpoint: FileReference,
    pub pools: [PoolScenario; 32],
}

fn role_path(root: &Path, role: Workstation) -> PathBuf {
    let mut path = root.to_path_buf();
    path.push(role.directory());
    path
}

fn reference(root: &Path, role: Workstation, relative: &str, content: Content) -> FileReference {
    let mut path = role_path(root, role);
    path.push(relative);
    FileReference {
        workstation: role,
        path,
        content,
    }
}

fn pool_file(
    root: &Path,
    role: Workstation,
    label: &str,
    name: &str,
    content: Content,
) -> FileReference {
    let mut path = role_path(root, role);
    path.push("pools");
    path.push(label);
    path.push(name);
    FileReference {
        workstation: role,
        path,
        content,
    }
}

fn pool(root: &Path, index: usize) -> PoolScenario {
    use Content::{EncryptedArtifact, PrivateOperationalFile, PublicRecord, UnixSocket};
    use Workstation::{ColdAuthority, Development, Management, Network, Primary, Recovery};
    let label = format!("pool-case-{:02}", index + 1);
    let file = |role, name, content| pool_file(root, role, &label, name, content);
    PoolScenario {
        enrollment_record: file(Management, "enrollment.json", PublicRecord),
        cold_verification_key: file(ColdAuthority, "cold.vkey", PublicRecord),
        cold_signing_key: file(ColdAuthority, "cold.skey", PrivateOperationalFile),
        recipient_public_key: file(Recovery, "recipient.pub.json", PublicRecord),
        recipient_private_key_file: file(Recovery, "recipient.key", PrivateOperationalFile),
        machine_credential_public: file(Primary, "credential.pub.json", PublicRecord),
        machine_credential_private: file(Primary, "credential.key.json", PrivateOperationalFile),
        vrf_verification_key: file(Primary, "vrf.vkey", PublicRecord),
        vrf_signing_key: file(Primary, "vrf.skey", PrivateOperationalFile),
        connection: file(Primary, "connection.json", PublicRecord),
        kes_verification_key: file(Primary, "kes.vkey", PublicRecord),
        encrypted_initial_backup: file(Primary, "initial.kesbkp01", EncryptedArtifact),
        recovered_conventional_key: file(Recovery, "recovered.kes.skey", PrivateOperationalFile),
        operational_certificate: file(ColdAuthority, "node.opcert", PublicRecord),
        certificate_counter: file(ColdAuthority, "opcert.counter", PublicRecord),
        leader_schedule: file(Network, "leadership-schedule.json", PublicRecord),
        signing_socket: file(Primary, "signing.sock", UnixSocket),
        node_socket: file(Primary, "node.sock", UnixSocket),
        development_inspection: file(Development, "current.kesdev01", PrivateOperationalFile),
        case_label: label,
    }
}

fn baseline(relative: &str, version: &str, commit: &str) -> Result<NativeBaseline> {
    // Provenance has additional source/build fields; only this public projection
    // enters a scenario. Executable existence/hash is checked by execution/freeze,
    // not falsely claimed by creation of a declaration on another workstation.
    #[derive(Deserialize)]
    struct Provenance {
        executable: NativeExecutable,
        source: Source,
    }
    #[derive(Deserialize)]
    struct Source {
        commit: String,
    }
    let project = Path::new(env!("CARGO_MANIFEST_DIR"));
    let provenance_file = project.join(relative);
    let provenance: Provenance = evidence::read_json(&provenance_file)?;
    let executable = provenance.executable;
    let expected_revision = format!("git rev {commit}");
    if provenance.source.commit != commit
        || !executable.path.is_absolute()
        || executable.sha256.len() != 64
        || !executable
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || !executable.version_output.starts_with(version)
        || !executable
            .version_output
            .lines()
            .any(|line| line == expected_revision)
    {
        return Err(
            "native baseline provenance does not match the independent pinned release".into(),
        );
    }
    Ok(NativeBaseline {
        provenance_file,
        source_commit: provenance.source.commit,
        executable,
    })
}

fn manifest(
    directory: &Path,
    runtime_root: &Path,
    scenario_id: String,
) -> Result<ScenarioManifest> {
    use Content::{Executable, PhysicalControllerEndpoint, PublicRecord, UnixSocket};
    use Workstation::{
        ColdAuthority, Development, Management, Network, PowerController, Primary, Provisioning,
        Recovery,
    };
    let mut executables = Vec::with_capacity(8);
    for role in [Primary, Recovery, Management, Provisioning, Development] {
        executables.push(ExecutableRequirement {
            name: format!("{}-operator", role.directory()),
            file: reference(runtime_root, role, "bin/kes-forge", Executable),
        });
    }
    for (name, role, path) in [
        ("daemon", Primary, "bin/kes-forged"),
        ("patched-node", Primary, "bin/cardano-node"),
        ("cold-certificate-cli", ColdAuthority, "bin/cardano-cli"),
    ] {
        executables.push(ExecutableRequirement {
            name: name.into(),
            file: reference(runtime_root, role, path, Executable),
        });
    }
    let workstations = Workstation::ALL.map(|role| {
        let must_not_share_workstation_with = match role {
            Recovery => vec![Primary, Provisioning],
            Provisioning => vec![Primary, Recovery],
            Management | ColdAuthority => vec![Primary],
            _ => Vec::new(),
        };
        WorkstationRuntime {
            workstation: role,
            directory: role_path(runtime_root, role),
            must_not_share_workstation_with,
        }
    });
    let peers = std::array::from_fn(|index| {
        let name = format!("validator-{:02}", index + 1);
        PeerScenario {
            executable: reference(runtime_root, Network, "bin/cardano-node", Executable),
            configuration: reference(
                runtime_root,
                Network,
                &format!("peers/{name}/config.json"),
                PublicRecord,
            ),
            topology: reference(
                runtime_root,
                Network,
                &format!("peers/{name}/topology.json"),
                PublicRecord,
            ),
            socket: reference(
                runtime_root,
                Network,
                &format!("peers/{name}/node.sock"),
                UnixSocket,
            ),
            name,
        }
    });
    Ok(ScenarioManifest {
        version: 1,
        kind: ManifestKind::PublicScenarioDeclaration,
        scenario_id,
        disposable: true,
        fixture_directory: directory.to_path_buf(),
        runtime: RuntimePolicy {
            root: runtime_root.to_path_buf(),
            directory_mode: 0o700,
            private_file_mode: 0o600,
            disable_core_dumps: true,
            protect_transient_secret_memory: true,
            populate_only_through_supported_workflows: true,
            paths_are_local_to_the_named_workstation: true,
            workstations,
        },
        network: NetworkScenario {
            network: ControlledNetwork::Controlled,
            network_magic: 42,
            slots_per_kes_period: 64,
            max_kes_evolutions: 64,
            slot_length_milliseconds: 1000,
            exact_shelley_genesis: reference(
                runtime_root,
                Network,
                "genesis/shelley.json",
                PublicRecord,
            ),
        },
        devices: DeviceRequirements {
            silicon: "RP2350".into(),
            minimum_qualification_revision: "A4".into(),
            stock_clock_hz: 150_000_000,
            fitted_flash_bytes: 4_194_304,
            development_and_release_devices_must_differ: true,
            development_identity: reference(
                runtime_root,
                Development,
                "device.identity.json",
                PublicRecord,
            ),
            release_identity: reference(
                runtime_root,
                Provisioning,
                "device.identity.json",
                PublicRecord,
            ),
            provisioning_record: reference(
                runtime_root,
                Provisioning,
                "provisioning.record.json",
                PublicRecord,
            ),
        },
        irreversible_authorization: IrreversibleAuthorization::RequiredForEachAttendedCeremony,
        cli_baseline: baseline(
            "oracles/cli-11.4/provenance.json",
            "cardano-cli 11.4.0.0 - ",
            "25f4d7a6b243d80ed7d716cc91b9c51d9265ace6",
        )?,
        node_baseline: baseline(
            "oracles/node-11.1.3/provenance.json",
            "cardano-node 11.1.3 - ",
            "938cba990357ae7c4b7f95c8f75dd9d31174bbeb",
        )?,
        executables,
        peers,
        power_controller_executable: reference(
            runtime_root,
            PowerController,
            "bin/power-controller",
            Executable,
        ),
        qualification_executable: reference(
            runtime_root,
            Primary,
            "bin/kes-foundation-qualification",
            Executable,
        ),
        power_controller_endpoint: reference(
            runtime_root,
            PowerController,
            "controller",
            PhysicalControllerEndpoint,
        ),
        pools: std::array::from_fn(|index| pool(runtime_root, index)),
    })
}

pub fn create(network: &str, pools: u8, output: &Path) -> Result<PathBuf> {
    if network != "controlled" || pools != 32 {
        return Err(
            "destructive scenarios require --network controlled --pools 32; mainnet is forbidden"
                .into(),
        );
    }
    match fs::symlink_metadata(output) {
        Ok(_) => return Err("refusing an existing fixture output path".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    let absolute = if output.is_absolute() {
        output.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| error.to_string())?
            .join(output)
    };
    let name = absolute
        .file_name()
        .ok_or("fixture output must name a new directory")?;
    let parent = fs::canonicalize(absolute.parent().ok_or("fixture output has no parent")?)
        .map_err(|error| format!("fixture parent must already exist: {error}"))?;
    let directory = parent.join(name);
    let mut random = [0u8; 16];
    fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut random))
        .map_err(|error| format!("public scenario identifier entropy unavailable: {error}"))?;
    let mut scenario_id = String::with_capacity(32);
    for byte in random {
        write!(&mut scenario_id, "{byte:02x}").map_err(|error| error.to_string())?;
    }
    let runtime_parent =
        fs::canonicalize(std::env::temp_dir()).map_err(|error| error.to_string())?;
    let runtime_root = runtime_parent.join(format!("kes-forge-runtime-{scenario_id}"));
    if runtime_root.starts_with(&directory) || directory.starts_with(&runtime_root) {
        return Err("operational runtime output must be separate from the fixture bundle".into());
    }
    let scenario = manifest(&directory, &runtime_root, scenario_id)?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .map_err(|error| format!("refusing to replace fixture output: {error}"))?;
    let path = directory.join("manifest.json");
    evidence::write_new_json(&path, &scenario)?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())?;
    Ok(path)
}
