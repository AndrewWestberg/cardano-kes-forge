use crate::evidence::{self, Definition, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_BUILD: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceBuild {
    pub id: String,
    pub manifest_path: PathBuf,
    pub package: String,
    pub features: Vec<String>,
    pub default_features: bool,
    pub target: Option<String>,
    pub profile: String,
    pub all_targets: bool,
    pub toolchain: String,
    pub rustflags: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Dependency {
    pub root: PathBuf,
    pub source: Option<String>,
    pub revision: Option<String>,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Compiler {
    pub rustup: PathBuf,
    pub rustup_sha256: String,
    pub cargo: PathBuf,
    pub cargo_sha256: String,
    pub rustc: PathBuf,
    pub rustc_sha256: String,
    pub cargo_version: String,
    pub rustc_version: String,
    pub host: String,
    pub binaries: PathBuf,
    pub binaries_sha256: String,
    pub libraries: PathBuf,
    pub libraries_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BuildProof {
    pub package_id: String,
    pub enabled_features: BTreeSet<String>,
    pub compiled_targets: BTreeSet<CompiledTarget>,
    pub metadata_sha256: String,
    pub compiler: Compiler,
    pub artifacts: u64,
    pub dependency_records: BTreeMap<PathBuf, String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceInventory {
    pub builds: BTreeMap<String, BuildProof>,
    pub dependencies: BTreeMap<String, Dependency>,
    pub compiled_inputs: BTreeMap<PathBuf, String>,
    pub cargo_configuration: BTreeMap<PathBuf, Option<String>>,
    pub build_script_inputs: BTreeMap<PathBuf, Option<String>>,
    pub environment: BTreeMap<String, Option<String>>,
}

#[derive(Deserialize)]
struct Metadata {
    packages: Vec<Package>,
    workspace_root: PathBuf,
    workspace_members: Vec<String>,
}

#[derive(Deserialize)]
struct Package {
    id: String,
    source: Option<String>,
    manifest_path: PathBuf,
    targets: Vec<Target>,
    name: String,
    features: BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct CompiledTarget {
    pub name: String,
    pub kind: Vec<String>,
    pub src_path: PathBuf,
}

#[derive(Deserialize)]
struct Target {
    src_path: PathBuf,
    test: bool,
    name: String,
    kind: Vec<String>,
}

impl Target {
    fn identity(&self) -> CompiledTarget {
        CompiledTarget {
            name: self.name.clone(),
            kind: self.kind.clone(),
            src_path: self.src_path.clone(),
        }
    }
}

struct Compilation {
    artifacts: u64,
    records: BTreeMap<PathBuf, String>,
    features: BTreeSet<String>,
    targets: BTreeSet<CompiledTarget>,
}

fn output(command: &mut Command, budget: u64, limit: usize) -> Result<Vec<u8>> {
    evidence::bounded_output(command, budget, limit)
}

fn rustup_launcher() -> Result<PathBuf> {
    let path = std::env::var_os("PATH").ok_or("PATH is required to locate rustup")?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join("rustup");
        if let Ok(metadata) = fs::metadata(&candidate)
            && metadata.is_file()
            && metadata.permissions().mode() & 0o111 != 0
        {
            return fs::canonicalize(candidate).map_err(|error| error.to_string());
        }
    }
    Err("rustup executable is unavailable on PATH".to_owned())
}

fn tool(toolchain: &str, name: &str) -> Result<PathBuf> {
    let bytes = output(
        Command::new(rustup_launcher()?).args(["which", "--toolchain", toolchain, name]),
        5000,
        4096,
    )?;
    let path = Path::new(
        std::str::from_utf8(&bytes)
            .map_err(|_| "non-UTF-8 Rust tool path")?
            .trim(),
    );
    if !path.is_absolute() {
        return Err("Rust tool is not an absolute path".to_owned());
    }
    fs::canonicalize(path).map_err(|error| format!("cannot resolve pinned Rust tool: {error}"))
}

fn compiler(build: &SourceBuild) -> Result<Compiler> {
    let rustup = rustup_launcher()?;
    let cargo = tool(&build.toolchain, "cargo")?;
    let rustc = tool(&build.toolchain, "rustc")?;
    let cargo_version = String::from_utf8(output(
        Command::new(&cargo).args(["--version", "--verbose"]),
        5000,
        65536,
    )?)
    .map_err(|_| "non-UTF-8 Cargo version")?;
    let rustc_version = String::from_utf8(output(
        Command::new(&rustc).args(["--version", "--verbose"]),
        5000,
        65536,
    )?)
    .map_err(|_| "non-UTF-8 compiler version")?;
    if build.toolchain == "1.99.1"
        && (!cargo_version.starts_with("cargo 1.99.1 ")
            || !rustc_version.starts_with("rustc 1.99.1 "))
        || build.toolchain.starts_with("nightly-")
            && (!cargo_version.contains("-nightly") || !rustc_version.contains("-nightly"))
    {
        return Err("resolved compiler/Cargo do not match the approved toolchain".to_owned());
    }
    let host = rustc_version
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .ok_or("compiler host triple missing")?
        .to_owned();
    let sysroot = output(
        Command::new(&rustc).args(["--print", "sysroot"]),
        5000,
        4096,
    )?;
    let libraries = Path::new(
        std::str::from_utf8(&sysroot)
            .map_err(|_| "non-UTF-8 Rust sysroot")?
            .trim(),
    )
    .join("lib");
    let binaries = cargo
        .parent()
        .ok_or("Cargo binary has no directory")?
        .to_owned();
    Ok(Compiler {
        rustup_sha256: evidence::file_hash(&rustup)?,
        rustup,
        cargo_version,
        rustc_version,
        host,
        cargo_sha256: evidence::file_hash(&cargo)?,
        rustc_sha256: evidence::file_hash(&rustc)?,
        binaries_sha256: evidence::input_hash(&binaries)?,
        binaries,
        libraries_sha256: evidence::input_hash(&libraries)?,
        cargo,
        rustc,
        libraries,
    })
}

fn cargo_home(workspace: &Path) -> Result<PathBuf> {
    let home = std::env::var_os("CARGO_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|value| !value.is_empty())
                .map(|home| PathBuf::from(home).join(".cargo"))
        })
        .ok_or("Cargo home unavailable: set a nonempty HOME or CARGO_HOME")?;
    Ok(if home.is_absolute() {
        home
    } else {
        workspace.join(home)
    })
}

fn base_command(
    build: &SourceBuild,
    workspace: &Path,
    cargo: &Path,
    rustc: &Path,
) -> Result<Command> {
    let home = std::env::var_os("HOME").ok_or("HOME is required for the pinned Cargo cache")?;
    let cargo_home = cargo_home(workspace)?;
    let binary_dir = cargo.parent().ok_or("Cargo binary has no directory")?;
    let rustup = rustup_launcher()?;
    let rustup_dir = rustup.parent().ok_or("rustup binary has no directory")?;
    let path = std::env::join_paths([
        binary_dir,
        rustup_dir,
        Path::new("/usr/bin"),
        Path::new("/bin"),
    ])
    .map_err(|error| format!("invalid pinned tool search path: {error}"))?;
    let mut command = Command::new(cargo);
    command
        .current_dir(workspace)
        .env_clear()
        .env("PATH", path)
        .env("HOME", home)
        .env("CARGO_HOME", cargo_home)
        .env("RUSTC", rustc)
        .env("CARGO_ENCODED_RUSTFLAGS", build.rustflags.join("\x1f"))
        .env("RUSTC_WRAPPER", "")
        .env("RUSTC_WORKSPACE_WRAPPER", "")
        .env("CLIPPY_CONF_DIR", workspace);
    if let Some(home) = std::env::var_os("RUSTUP_HOME") {
        command.env("RUSTUP_HOME", home);
    }
    Ok(command)
}

fn common_flags(command: &mut Command, build: &SourceBuild, workspace: &Path) -> Result<()> {
    command
        .arg("--manifest-path")
        .arg(evidence::resolve(workspace, &build.manifest_path)?)
        .args(["--locked", "--offline"]);
    if !build.default_features {
        command.arg("--no-default-features");
    }
    if !build.features.is_empty() {
        command.arg("--features").arg(build.features.join(","));
    }
    Ok(())
}

pub fn cargo_command(
    build: &SourceBuild,
    workspace: &Path,
    action: &str,
    target_dir: &Path,
    test_target: Option<&str>,
) -> Result<Command> {
    if !["check", "build", "clippy", "test", "bench"].contains(&action) {
        return Err("unsupported configured Cargo action".to_owned());
    }
    if test_target.is_some() && !matches!(action, "test" | "bench") {
        return Err("a named target requires the Cargo test or bench action".to_owned());
    }
    let cargo = tool(&build.toolchain, "cargo")?;
    let rustc = tool(&build.toolchain, "rustc")?;
    let mut command = base_command(build, workspace, &cargo, &rustc)?;
    command.arg(action);
    common_flags(&mut command, build, workspace)?;
    command
        .arg("--package")
        .arg(&build.package)
        .arg("--profile")
        .arg(&build.profile)
        .arg("--target-dir")
        .arg(target_dir);
    if let Some(target) = &build.target {
        command.arg("--target").arg(target);
    }
    if let Some(target) = test_target {
        command
            .arg(if action == "bench" {
                "--bench"
            } else {
                "--test"
            })
            .arg(target);
    } else if build.all_targets {
        command.arg("--all-targets");
    }
    Ok(command)
}

pub fn validate(builds: &[SourceBuild], features: &[String]) -> Result<()> {
    let mut ids = BTreeSet::new();
    for build in builds {
        if build.id.is_empty()
            || !ids.insert(&build.id)
            || build.package.is_empty()
            || !build
                .package
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || !["1.99.1", "nightly-2026-10-22"].contains(&build.toolchain.as_str())
            || build.profile.is_empty()
            || build
                .rustflags
                .iter()
                .any(|flag| flag.contains(['\0', '\x1f']))
        {
            return Err("invalid, duplicate or unpinned source-build configuration".to_owned());
        }
        let unique: BTreeSet<_> = build.features.iter().collect();
        if unique.len() != build.features.len()
            || unique
                .iter()
                .any(|feature| feature.is_empty() || feature.contains([',', '\0']))
        {
            return Err("invalid source-build features".to_owned());
        }
    }
    if !builds.is_empty() && ids != features.iter().collect() {
        return Err(
            "compiled source-build inventory must cover every frozen feature configuration exactly"
                .to_owned(),
        );
    }
    Ok(())
}

fn configuration(workspace: &Path) -> Result<BTreeMap<PathBuf, Option<String>>> {
    let mut paths = BTreeSet::new();
    for directory in workspace.ancestors() {
        paths.insert(directory.join(".cargo/config"));
        paths.insert(directory.join(".cargo/config.toml"));
    }
    let home = cargo_home(workspace)?;
    paths.insert(home.join("config"));
    paths.insert(home.join("config.toml"));
    paths
        .into_iter()
        .map(|path| {
            let hash = match fs::symlink_metadata(&path) {
                Ok(_) => Some(evidence::file_hash(&path)?),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(error.to_string()),
            };
            Ok((path, hash))
        })
        .collect()
}

fn dependency(
    package: &Package,
    workspace: &Path,
    files: &BTreeMap<String, String>,
) -> Result<Dependency> {
    let root = package
        .manifest_path
        .parent()
        .ok_or("package manifest has no parent")?
        .to_owned();
    let sha256 = if let Ok(relative) = root.strip_prefix(workspace) {
        evidence::resolve(workspace, &root)?;
        let subset: BTreeMap<_, _> = files
            .iter()
            .filter(|(path, _)| Path::new(path).starts_with(relative))
            .collect();
        evidence::json_hash(&subset)?
    } else {
        evidence::input_hash(&root)?
    };
    for target in &package.targets {
        if target.src_path.starts_with(workspace) {
            evidence::resolve(workspace, &target.src_path)?;
        }
    }
    Ok(Dependency {
        revision: evidence::dependency_revision(&root)?,
        root,
        source: package.source.clone(),
        sha256,
    })
}

fn metadata(
    build: &SourceBuild,
    workspace: &Path,
    compiler: &Compiler,
) -> Result<(Vec<u8>, Metadata)> {
    let mut command = base_command(build, workspace, &compiler.cargo, &compiler.rustc)?;
    command.args(["metadata", "--format-version", "1"]);
    common_flags(&mut command, build, workspace)?;
    // Target filtering drops host-only build dependencies of cross builds.
    // Compile the exact target below, but freeze the complete resolved source graph.
    let bytes = output(&mut command, 30000, 16 * 1024 * 1024)?;
    let metadata = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid resolved source graph: {error}"))?;
    Ok((bytes, metadata))
}

fn record_inputs(
    record: &Path,
    source_workspace: &Path,
    roots: &BTreeSet<PathBuf>,
    files: &mut BTreeMap<PathBuf, String>,
) -> Result<()> {
    let text = fs::read_to_string(record).map_err(|error| {
        format!(
            "missing compiler dependency record {}: {error}",
            record.display()
        )
    })?;
    let line = text
        .lines()
        .next()
        .ok_or("empty compiler dependency record")?;
    let (_, dependencies) = line
        .split_once(": ")
        .ok_or("invalid compiler dependency record")?;
    let mut token = String::new();
    let mut escaped = false;
    let mut paths = Vec::new();
    for character in dependencies.chars().chain(std::iter::once(' ')) {
        if escaped {
            token.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character.is_whitespace() {
            if !token.is_empty() {
                paths.push(std::mem::take(&mut token));
            }
        } else {
            token.push(character);
        }
    }
    if escaped || paths.is_empty() {
        return Err("incomplete compiler source dependencies".to_owned());
    }
    for path in paths {
        let path = Path::new(&path);
        let path = if path.is_absolute() {
            path.to_owned()
        } else {
            source_workspace.join(path)
        };
        let physical = fs::canonicalize(&path).map_err(|error| {
            format!(
                "cannot resolve compiled input {} from {}: {error}",
                path.display(),
                record.display()
            )
        })?;
        if !roots.iter().any(|root| physical.starts_with(root)) {
            return Err(format!(
                "compiled input {} is outside frozen source/dependency/tool roots; declare a public named input",
                path.display()
            ));
        }
        files.insert(path.clone(), compiled_hash(&path)?);
    }
    Ok(())
}

fn compiled_hash(path: &Path) -> Result<String> {
    let physical = fs::canonicalize(path)
        .map_err(|error| format!("cannot resolve compiled source: {error}"))?;
    if physical.components().any(|part| part.as_os_str() == ".git") {
        return Err("compiled source cannot reside in Git metadata".to_owned());
    }
    evidence::json_hash(&(physical.clone(), evidence::file_hash(&physical)?))
}

fn artifact_record(artifact: &Value) -> Result<PathBuf> {
    let files = artifact["filenames"]
        .as_array()
        .ok_or("compiler artifact filenames missing")?;
    for file in files {
        let path = Path::new(
            file.as_str()
                .ok_or("compiler artifact filename is not text")?,
        );
        let stem = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .ok_or("invalid compiler artifact path")?;
        let stem = if matches!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("rlib" | "rmeta" | "so")
        ) {
            stem.strip_prefix("lib").unwrap_or(stem)
        } else {
            stem
        };
        let record = path.with_file_name(format!("{stem}.d"));
        if record.is_file() {
            return Ok(record);
        }
    }
    if artifact["target"]["kind"]
        .as_array()
        .is_some_and(|kinds| kinds.iter().any(|kind| kind == "custom-build"))
    {
        let parent = Path::new(
            files
                .first()
                .and_then(Value::as_str)
                .ok_or("build script artifact missing")?,
        )
        .parent()
        .ok_or("build script parent missing")?;
        let records = fs::read_dir(parent)
            .map_err(|error| error.to_string())?
            .map(|entry| {
                entry
                    .map(|entry| entry.path())
                    .map_err(|error| error.to_string())
            })
            .collect::<Result<Vec<_>>>()?;
        let records: Vec<_> = records
            .into_iter()
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.starts_with("build_script_build-") && name.ends_with(".d")
                    })
            })
            .collect();
        if records.len() == 1 {
            return Ok(records[0].clone());
        }
    }
    Err("compiler artifact has no dependency record; source inventory is incomplete".to_owned())
}

fn compile(
    build: &SourceBuild,
    workspace: &Path,
    package_id: &str,
    roots: &BTreeSet<PathBuf>,
    metadata: &Metadata,
    inventory: &mut SourceInventory,
) -> Result<Compilation> {
    let parent = workspace.join("target/source-inventory");
    fs::create_dir_all(&parent).map_err(|error| error.to_string())?;
    let directory = parent.join(format!(
        "{}-{}-{}",
        std::process::id(),
        evidence::now_ms()?,
        NEXT_BUILD.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&directory)
        .map_err(|error| format!("source inventory output must be fresh: {error}"))?;
    let mut command = cargo_command(build, workspace, "check", &directory, None)?;
    command.arg("--message-format=json");
    let bytes = output(&mut command, 1800000, 16 * 1024 * 1024)
        .map_err(|error| format!("{} source compile failed: {error}", build.id))?;
    let mut records = BTreeMap::new();
    let mut selected = false;
    let mut enabled_features = BTreeSet::new();
    let mut artifacts = 0_u64;
    let mut targets = BTreeSet::new();
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let mut message: Value = serde_json::from_slice(line)
            .map_err(|error| format!("invalid compiler inventory message: {error}"))?;
        match message["reason"].as_str() {
            Some("compiler-artifact") => {
                if message["package_id"].as_str() == Some(package_id) {
                    selected = true;
                    for feature in message["features"]
                        .as_array()
                        .ok_or("compiled feature inventory missing")?
                    {
                        enabled_features.insert(
                            feature
                                .as_str()
                                .ok_or("invalid compiled feature")?
                                .to_owned(),
                        );
                    }
                }
                let record = artifact_record(&message)?;
                record_inputs(
                    &record,
                    &metadata.workspace_root,
                    roots,
                    &mut inventory.compiled_inputs,
                )?;
                records.insert(record.clone(), evidence::file_hash(&record)?);
                artifacts += 1;
                if message["package_id"].as_str() == Some(package_id) {
                    let target: Target = serde_json::from_value(message["target"].take())
                        .map_err(|error| format!("invalid compiled target: {error}"))?;
                    targets.insert(target.identity());
                }
            }
            Some("build-script-executed") => {
                build_script_inputs(&message, metadata, inventory, &mut records)?
            }
            Some("compiler-message")
                if message["package_id"].as_str() == Some(package_id)
                    && message["message"]["level"].as_str() == Some("warning") =>
            {
                return Err(format!(
                    "{} source inventory cannot freeze package compiler warnings",
                    build.id
                ));
            }
            Some("build-finished") if message["success"].as_bool() != Some(true) => {
                return Err("source inventory build incomplete".to_owned());
            }
            _ => {}
        }
    }
    if !selected || artifacts == 0 || records.is_empty() {
        return Err(
            "configured package was not compiled; source inventory is incomplete".to_owned(),
        );
    }
    Ok(Compilation {
        artifacts,
        records,
        features: enabled_features,
        targets,
    })
}

pub fn capture(
    workspace: &Path,
    definition: &Definition,
    files: &BTreeMap<String, String>,
) -> Result<SourceInventory> {
    let has_manifest = workspace.join("Cargo.toml").is_file();
    if has_manifest == definition.source_builds.is_empty() {
        return Err(
            "Rust workspaces require explicit complete pre-freeze source-build configurations"
                .to_owned(),
        );
    }
    if !has_manifest {
        return Ok(SourceInventory::default());
    }
    let mut inventory = SourceInventory {
        cargo_configuration: configuration(workspace)?,
        environment: public_environment()?,
        ..SourceInventory::default()
    };
    let mut compilers = BTreeMap::new();
    let mut required = BTreeMap::<String, BTreeSet<String>>::new();
    let mut verified = BTreeMap::<String, BTreeSet<String>>::new();
    let mut required_targets = BTreeSet::new();
    let mut root_graph = false;
    for build in &definition.source_builds {
        let compiler = captured_compiler(build, &mut compilers)?;
        let (bytes, metadata) = metadata(build, workspace, &compiler)?;
        let selected: Vec<_> = metadata
            .packages
            .iter()
            .filter(|package| package.name == build.package)
            .collect();
        if selected.len() != 1 {
            return Err("source-build package selection is missing or ambiguous".to_owned());
        }
        if (build.target.is_none() || build.target.as_deref() == Some(&compiler.host))
            && !build.all_targets
            && selected[0].targets.iter().any(|target| target.test)
        {
            return Err(
                "host source configurations must compile all supported test/bench targets"
                    .to_owned(),
            );
        }
        if metadata.workspace_root == workspace {
            root_graph = true;
            for package in metadata
                .packages
                .iter()
                .filter(|package| metadata.workspace_members.contains(&package.id))
            {
                required.insert(
                    package.id.clone(),
                    package
                        .features
                        .keys()
                        .filter(|name| name.as_str() != "default")
                        .cloned()
                        .collect(),
                );
                required_targets.extend(
                    package
                        .targets
                        .iter()
                        .filter(|target| !target.kind.iter().any(|kind| kind == "custom-build"))
                        .map(|target| (package.id.clone(), target.identity())),
                );
            }
        }
        let mut roots: BTreeSet<_> = metadata
            .packages
            .iter()
            .map(|package| {
                package
                    .manifest_path
                    .parent()
                    .ok_or_else(|| "dependency root missing".to_owned())
                    .map(Path::to_owned)
            })
            .collect::<Result<_>>()?;
        roots.insert(workspace.to_owned());
        roots.insert(compiler.libraries.clone());
        for input in definition.inputs.values() {
            roots.insert(
                fs::canonicalize(evidence::resolve_input(workspace, input)?)
                    .map_err(|error| error.to_string())?,
            );
        }
        for package in &metadata.packages {
            inventory
                .dependencies
                .insert(package.id.clone(), dependency(package, workspace, files)?);
        }
        let compilation = compile(
            build,
            workspace,
            &selected[0].id,
            &roots,
            &metadata,
            &mut inventory,
        )?;
        verified
            .entry(selected[0].id.clone())
            .or_default()
            .extend(compilation.features.iter().cloned());
        inventory.builds.insert(
            build.id.clone(),
            BuildProof {
                package_id: selected[0].id.clone(),
                enabled_features: compilation.features,
                compiled_targets: compilation.targets,
                metadata_sha256: format!("{:x}", Sha256::digest(&bytes)),
                compiler,
                artifacts: compilation.artifacts,
                dependency_records: compilation.records,
            },
        );
    }
    if !root_graph
        || required.iter().any(|(package, features)| {
            verified
                .get(package)
                .is_none_or(|compiled| !features.is_subset(compiled))
        })
    {
        return Err(
            "pre-freeze compilation omitted a workspace package or supported feature configuration"
                .to_owned(),
        );
    }
    for (package, target) in required_targets {
        if !inventory
            .builds
            .values()
            .any(|proof| proof.package_id == package && proof.compiled_targets.contains(&target))
        {
            return Err(format!(
                "supported target {} was not compiled in any approved feature configuration",
                target.name
            ));
        }
    }
    Ok(inventory)
}

pub fn revalidate(
    workspace: &Path,
    definition: &Definition,
    files: &BTreeMap<String, String>,
    frozen: &SourceInventory,
) -> Result<SourceInventory> {
    if workspace.join("Cargo.toml").is_file() == definition.source_builds.is_empty() {
        return Err("source-build inventory missing or no longer applicable".to_owned());
    }
    if definition.source_builds.is_empty() {
        return Ok(SourceInventory::default());
    }
    if frozen.builds.keys().collect::<BTreeSet<_>>()
        != definition
            .source_builds
            .iter()
            .map(|build| &build.id)
            .collect()
    {
        return Err("frozen compiler configuration proof incomplete".to_owned());
    }
    let mut current = frozen.clone();
    current.cargo_configuration = configuration(workspace)?;
    current.environment = public_environment()?;
    let mut compilers = BTreeMap::new();
    for build in &definition.source_builds {
        let proof = current
            .builds
            .get_mut(&build.id)
            .ok_or("missing compiler proof")?;
        proof.compiler = captured_compiler(build, &mut compilers)?;
        if proof.artifacts == 0 || proof.dependency_records.is_empty() {
            return Err("empty compiler proof".to_owned());
        }
        for (path, hash) in &mut proof.dependency_records {
            *hash = evidence::file_hash(path)?;
        }
    }
    for dependency in current.dependencies.values_mut() {
        dependency.revision = evidence::dependency_revision(&dependency.root)?;
        dependency.sha256 = if let Ok(relative) = dependency.root.strip_prefix(workspace) {
            let subset: BTreeMap<_, _> = files
                .iter()
                .filter(|(path, _)| Path::new(path).starts_with(relative))
                .collect();
            evidence::json_hash(&subset)?
        } else {
            evidence::input_hash(&dependency.root)?
        };
    }
    for (path, hash) in &mut current.compiled_inputs {
        *hash = compiled_hash(path)?;
    }
    for (path, hash) in &mut current.build_script_inputs {
        *hash = script_input_hash(path)?;
    }
    Ok(current)
}

fn captured_compiler(
    build: &SourceBuild,
    cache: &mut BTreeMap<String, Compiler>,
) -> Result<Compiler> {
    if let Some(compiler) = cache.get(&build.toolchain) {
        return Ok(compiler.clone());
    }
    let compiler = compiler(build)?;
    cache.insert(build.toolchain.clone(), compiler.clone());
    Ok(compiler)
}

fn public_environment() -> Result<BTreeMap<String, Option<String>>> {
    ["HOME", "CARGO_HOME", "RUSTUP_HOME"]
        .into_iter()
        .map(|name| {
            let value = std::env::var(name).map(Some).or_else(|error| match error {
                std::env::VarError::NotPresent => Ok(None),
                _ => Err(format!("non-UTF-8 public build environment {name}")),
            })?;
            Ok((name.to_owned(), value))
        })
        .collect()
}

fn script_input_hash(path: &Path) -> Result<Option<String>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
        Ok(_) => {
            let physical = fs::canonicalize(path).map_err(|error| error.to_string())?;
            if physical.components().any(|part| part.as_os_str() == ".git") {
                return Err("build-script data cannot hide in excluded Git metadata".to_owned());
            }
            Ok(Some(evidence::json_hash(&(
                physical.clone(),
                evidence::input_hash(&physical)?,
            ))?))
        }
    }
}

fn build_script_inputs(
    message: &Value,
    metadata: &Metadata,
    inventory: &mut SourceInventory,
    records: &mut BTreeMap<PathBuf, String>,
) -> Result<()> {
    let package = metadata
        .packages
        .iter()
        .find(|package| message["package_id"].as_str() == Some(package.id.as_str()))
        .ok_or("build script package is absent from resolved graph")?;
    let package_root = package
        .manifest_path
        .parent()
        .ok_or("build script source root missing")?;
    let out = Path::new(
        message["out_dir"]
            .as_str()
            .ok_or("build script output directory missing")?,
    );
    let package_directory = out
        .parent()
        .and_then(Path::file_name)
        .ok_or("invalid build script output location")?;
    let profile = out
        .ancestors()
        .find(|path| path.file_name().is_some_and(|name| name == "build"))
        .and_then(Path::parent)
        .ok_or("build script profile directory missing")?;
    let fingerprint_root = profile.join(".fingerprint");
    let package_directory = package_directory
        .to_str()
        .ok_or("non-UTF8 build script output location")?;
    let package_prefixes = [
        format!("{}-", package.name),
        format!("{}-", package.name.replace('-', "_")),
    ];
    let colocated = out
        .parent()
        .ok_or("invalid build script output parent")?
        .join("fingerprint");
    let mut directories = Vec::new();
    if colocated.is_dir() {
        directories.push(colocated);
    } else {
        for entry in fs::read_dir(&fingerprint_root).map_err(|error| {
            format!(
                "build script fingerprint root unavailable at {} for {}: {error}",
                fingerprint_root.display(),
                package.name
            )
        })? {
            let entry = entry.map_err(|error| error.to_string())?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "non-UTF8 build script fingerprint directory")?;
            let matching_package = package_prefixes
                .iter()
                .any(|prefix| name.starts_with(prefix))
                && (name == package_directory || name.ends_with(&format!("-{package_directory}")));
            if matching_package {
                directories.push(entry.path());
            }
        }
    }
    let mut paths = Vec::new();
    for directory in directories {
        for file in fs::read_dir(directory).map_err(|error| error.to_string())? {
            let path = file.map_err(|error| error.to_string())?.path();
            if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with("run-build-script-") && name.ends_with(".json")
                })
            {
                paths.push(path);
            }
        }
    }
    if paths.len() != 1 {
        return Err(format!(
            "missing or ambiguous executed build-script dependency record for {} ({package_directory})",
            package.name
        ));
    }
    let fingerprint: Value = evidence::read_json(&paths[0])?;
    records.insert(paths[0].clone(), evidence::file_hash(&paths[0])?);
    for local in fingerprint["local"]
        .as_array()
        .ok_or("build-script dependency inventory missing")?
    {
        if let Some(changed) = local.get("RerunIfChanged") {
            for path in changed["paths"]
                .as_array()
                .ok_or("build-script watched paths missing")?
            {
                let path = Path::new(path.as_str().ok_or("invalid watched build-script path")?);
                let path = if path.is_absolute() {
                    path.to_owned()
                } else {
                    package_root.join(path)
                };
                inventory
                    .build_script_inputs
                    .insert(path.clone(), script_input_hash(&path)?);
            }
        }
    }
    Ok(())
}
