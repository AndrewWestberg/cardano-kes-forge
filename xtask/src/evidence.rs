use crate::source_inventory::{self, SourceBuild, SourceInventory};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub type Result<T, E = String> = std::result::Result<T, E>;
pub const EXCLUSIONS: [&str; 3] = [".git", "target", "evidence"];
pub const SESSION_SUPERVISOR: &str = "/usr/bin/setsid";
pub const SIGNAL_TOOL: &str = "/bin/kill";
const MAX_DOCUMENT: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Gate {
    pub id: String,
    pub program: PathBuf,
    pub args: Vec<String>,
    pub scenarios: Vec<String>,
    pub minimum_cases: u64,
    pub hardware_required: bool,
    pub budget_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRegistration {
    pub program: PathBuf,
    pub version_args: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Definition {
    pub version: u8,
    pub increment: String,
    pub features: Vec<String>,
    pub source_builds: Vec<SourceBuild>,
    pub tools: Vec<ToolRegistration>,
    pub implemented_scopes: Vec<String>,
    pub future_scopes: Vec<String>,
    pub exclusions: Vec<String>,
    pub inputs: BTreeMap<String, PathBuf>,
    pub artifacts: BTreeMap<String, PathBuf>,
    pub coverage_baselines: BTreeMap<String, Option<String>>,
    pub performance: Option<PerformancePlan>,
    pub gates: Vec<Gate>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PerformancePlan {
    pub establish: bool,
    pub baseline_input: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub version: u8,
    pub maintainer: String,
    pub definition_sha256: String,
    pub approved: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    pub sha256: String,
    pub version: String,
    pub resolved_path: PathBuf,
    pub version_args: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub revision: String,
    pub source: String,
    pub source_files: BTreeMap<String, String>,
    pub inputs: BTreeMap<String, String>,
    pub input_revisions: BTreeMap<String, Option<String>>,
    pub source_inventory: SourceInventory,
    pub artifacts: BTreeMap<String, String>,
    pub tools: BTreeMap<PathBuf, Tool>,
    pub definition: String,
    pub approval: String,
    pub scope: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Frozen {
    pub version: u8,
    pub candidate: String,
    pub frozen_ms: u64,
    pub workspace: PathBuf,
    pub definition_path: PathBuf,
    pub approval_path: PathBuf,
    pub definition: Definition,
    pub identity: Identity,
    pub environment: BTreeMap<String, String>,
}

pub fn now_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system time precedes Unix epoch".to_owned())?
        .as_millis()
        .try_into()
        .map_err(|_| "timestamp overflow".to_owned())
}

pub fn json_hash<T: Serialize>(value: &T) -> Result<String> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| format!("cannot encode identity: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

pub fn file_hash(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "not a regular, non-symlink file: {}",
            path.display()
        ));
    }
    let mut input =
        File::open(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 16384];
    loop {
        let count = input
            .read(&mut buffer)
            .map_err(|error| format!("cannot hash {}: {error}", path.display()))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    let after = input.metadata().map_err(|error| error.to_string())?;
    if metadata.len() != after.len() || metadata.modified().ok() != after.modified().ok() {
        return Err(format!("input changed during hashing: {}", path.display()));
    }
    Ok(format!("{:x}", digest.finalize()))
}

pub(crate) fn json_bytes(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.len() > MAX_DOCUMENT {
        return Err(format!(
            "invalid or oversized JSON file: {}",
            path.display()
        ));
    }
    let input = File::open(path).map_err(|error| error.to_string())?;
    let mut bytes = Vec::new();
    input
        .take(MAX_DOCUMENT + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_DOCUMENT {
        return Err("JSON document grew beyond its bound".to_owned());
    }
    Ok(bytes)
}

pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    crate::strict_json::from_slice(&json_bytes(path)?)
        .map_err(|error| format!("invalid JSON in {}: {error}", path.display()))
}

pub fn write_new_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let parent = path.parent().ok_or("output has no parent")?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| {
            format!(
                "cannot create {} without replacement: {error}",
                path.display()
            )
        })?;
    serde_json::to_writer_pretty(&mut output, value).map_err(|error| error.to_string())?;
    output.write_all(b"\n").map_err(|error| error.to_string())?;
    output.sync_all().map_err(|error| error.to_string())?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())
}

fn unique_nonempty(values: &[String], name: &str) -> Result<()> {
    let mut seen = BTreeSet::new();
    if values.is_empty() {
        return Err(format!("empty {name}"));
    }
    for value in values {
        if value.trim().is_empty() || !seen.insert(value) {
            return Err(format!("empty or duplicate {name}"));
        }
    }
    Ok(())
}

pub fn required_fuzz_targets(increment: &str) -> &'static [&'static str] {
    match increment {
        "setup" => &[],
        "foundation" => &["frame", "certificate", "snapshot", "session"],
        _ => &["frame", "artifact", "certificate", "snapshot", "session"],
    }
}

fn validate_scopes(definition: &Definition) -> Result<()> {
    const SCOPES: [&str; 7] = [
        "infrastructure",
        "foundation",
        "US1",
        "US2",
        "US3",
        "US4",
        "US5",
    ];
    let count = match definition.increment.as_str() {
        "setup" => 1,
        "foundation" => 2,
        "US1" => 3,
        "US2" => 4,
        "US3" => 5,
        "US4" => 6,
        "US5" | "final" => 7,
        _ => return Err("unknown increment".to_owned()),
    };
    let implemented: BTreeSet<_> = definition
        .implemented_scopes
        .iter()
        .map(String::as_str)
        .collect();
    let future: BTreeSet<_> = definition
        .future_scopes
        .iter()
        .map(String::as_str)
        .collect();
    if implemented != SCOPES[..count].iter().copied().collect()
        || future != SCOPES[count..].iter().copied().collect()
        || future.len() != definition.future_scopes.len()
    {
        return Err("implemented/future scope inventory disagrees with increment".to_owned());
    }
    Ok(())
}

fn validate_gate_set(definition: &Definition, gates: &BTreeSet<&str>) -> Result<()> {
    let mut required = vec!["G1", "G2", "G4", "G5", "G12"];
    if definition.increment != "setup" {
        required.extend(["G3", "G6", "G7", "G8", "G9", "P0", "P1"]);
        if !matches!(definition.increment.as_str(), "foundation" | "US1") {
            required.push("G10");
        }
        if definition.increment == "final" {
            required.push("G11");
        }
        let mut physical = vec!["G8", "P1"];
        if definition.increment != "foundation" {
            physical.push("G9");
        }
        for id in physical {
            if !definition
                .gates
                .iter()
                .any(|gate| gate.id == id && gate.hardware_required)
            {
                return Err(format!("{id} requires actual qualified hardware"));
            }
        }
    }
    if required.iter().any(|id| !gates.contains(id)) {
        return Err("required applicability-matrix gate omitted".to_owned());
    }
    let known = [
        "G1", "G2", "G3", "G4", "G5", "G6", "G7", "G8", "G9", "G10", "G11", "G12", "P0", "P1",
    ];
    if gates.iter().any(|id| !known.contains(id)) {
        return Err("unknown gate".to_owned());
    }
    Ok(())
}

fn validate_baselines(definition: &Definition) -> Result<()> {
    let coverage = definition
        .gates
        .iter()
        .find(|gate| gate.id == "G5")
        .ok_or("missing coverage gate")?;
    let crates: BTreeSet<_> = coverage.scenarios.iter().collect();
    if crates != definition.coverage_baselines.keys().collect() {
        return Err("missing per-crate coverage baseline plan".to_owned());
    }
    for baseline in definition.coverage_baselines.values() {
        match baseline {
            Some(input) if definition.inputs.contains_key(input) => {}
            None if definition.increment != "final" => {}
            _ => return Err("missing approved coverage baseline input".to_owned()),
        }
    }
    match (
        &definition.performance,
        definition.gates.iter().any(|gate| gate.id == "P0"),
    ) {
        (None, false) => Ok(()),
        (Some(plan), true)
            if plan.establish
                && definition.increment == "foundation"
                && plan.baseline_input.is_none() =>
        {
            Ok(())
        }
        (Some(plan), true)
            if !plan.establish
                && plan
                    .baseline_input
                    .as_ref()
                    .is_some_and(|input| definition.inputs.contains_key(input)) =>
        {
            Ok(())
        }
        _ => Err("missing or unauthorized performance baseline plan".to_owned()),
    }
}

fn validate_artifacts(definition: &Definition) -> Result<()> {
    if definition.gates.iter().any(|gate| gate.hardware_required) {
        let firmware = if definition.increment == "foundation" {
            "firmware-development"
        } else {
            "firmware-release"
        };
        if !definition.artifacts.contains_key(firmware) {
            return Err("hardware gate lacks frozen firmware artifact".to_owned());
        }
    }
    if definition.increment == "final" {
        for name in [
            "operator-primary",
            "operator-recovery",
            "operator-management",
            "operator-provisioning",
            "operator-development",
            "daemon-primary",
            "firmware-development",
            "firmware-release",
        ] {
            if !definition.artifacts.contains_key(name) {
                return Err(format!("final package artifact omitted: {name}"));
            }
        }
    }
    Ok(())
}

pub fn validate_definition(definition: &Definition) -> Result<()> {
    if definition.version != 1 {
        return Err("unsupported definition version".to_owned());
    }
    if definition.exclusions != EXCLUSIONS {
        return Err("only the fixed generated-output exclusions are allowed".to_owned());
    }
    unique_nonempty(&definition.features, "feature inventory")?;
    unique_nonempty(
        &definition.implemented_scopes,
        "implemented scope inventory",
    )?;
    validate_scopes(definition)?;
    if definition.inputs.is_empty() {
        return Err("missing dependency/tool/configuration input inventory".to_owned());
    }
    let mut gates = BTreeSet::new();
    for gate in &definition.gates {
        if !gates.insert(gate.id.as_str())
            || gate.minimum_cases == 0
            || gate.budget_ms == 0
            || !gate.program.is_absolute()
        {
            return Err("duplicate/empty gate or non-absolute command".to_owned());
        }
        unique_nonempty(&gate.scenarios, "gate scenario inventory")?;
        if gate.id == "G3" && gate.minimum_cases < 10000 {
            return Err("G3 requires at least 10000 accepted sequences".to_owned());
        }
        if gate.id == "G7" && gate.minimum_cases < 64 {
            return Err("G7 requires all 64 periods".to_owned());
        }
        if gate.id == "G6"
            && required_fuzz_targets(&definition.increment)
                .iter()
                .any(|name| !gate.scenarios.iter().any(|scenario| scenario == name))
        {
            return Err("mandatory semantic fuzz target omitted".to_owned());
        }
    }
    source_inventory::validate(&definition.source_builds, &definition.features)?;
    let tools: BTreeSet<_> = definition.tools.iter().map(|tool| &tool.program).collect();
    if tools.len() != definition.tools.len()
        || definition
            .tools
            .iter()
            .any(|tool| !tool.program.is_absolute() || tool.version_args.is_empty())
    {
        return Err(
            "duplicate, non-absolute or version-command-free external tool registration".to_owned(),
        );
    }
    validate_gate_set(definition, &gates)?;
    validate_baselines(definition)?;
    validate_artifacts(definition)
}

fn walk(
    root: &Path,
    directory: &Path,
    files: &mut BTreeMap<String, String>,
    exclusions: bool,
) -> Result<()> {
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("cannot enumerate {}: {error}", directory.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let relative = path.strip_prefix(root).map_err(|error| error.to_string())?;
        let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        let root_excluded = relative.components().count() == 1
            && (relative == Path::new(".git") || exclusions && relative == Path::new("evidence"));
        let cargo_target = exclusions
            && metadata.is_dir()
            && relative.file_name().is_some_and(|name| name == "target");
        if root_excluded || cargo_target {
            continue;
        }
        if metadata.is_dir() {
            walk(root, &path, files, exclusions)?;
        } else if metadata.is_file() {
            let key = relative
                .to_str()
                .ok_or("source path is not UTF-8")?
                .to_owned();
            files.insert(key, file_hash(&path)?);
        } else if metadata.file_type().is_symlink() {
            let target =
                fs::canonicalize(&path).map_err(|error| format!("invalid source link: {error}"))?;
            let target_relative = target
                .strip_prefix(root)
                .map_err(|_| "source link escapes its input root")?;
            if target_relative
                .components()
                .next()
                .is_some_and(|part| part.as_os_str() == ".git")
            {
                return Err("source link targets excluded Git metadata".to_owned());
            }
            if exclusions {
                resolve(root, target_relative)?;
            }
            let link = fs::read_link(&path).map_err(|error| error.to_string())?;
            let spelling = link.to_str().ok_or("source link is not UTF-8")?;
            let key = relative
                .to_str()
                .ok_or("source path is not UTF-8")?
                .to_owned();
            files.insert(key, format!("symlink:{}", json_hash(&spelling)?));
        } else {
            return Err(format!(
                "special source file is not admissible: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn source_files(workspace: &Path) -> Result<BTreeMap<String, String>> {
    let mut files = BTreeMap::new();
    walk(workspace, workspace, &mut files, true)?;
    if files.is_empty() {
        return Err("empty source snapshot".to_owned());
    }
    Ok(files)
}

pub fn resolve(workspace: &Path, path: &Path) -> Result<PathBuf> {
    if path
        .components()
        .any(|part| matches!(part, Component::ParentDir))
    {
        return Err("parent traversal in frozen input path".to_owned());
    }
    let joined = if path.is_absolute() {
        path.to_owned()
    } else {
        workspace.join(path)
    };
    if let Ok(relative) = joined.strip_prefix(workspace)
        && relative
            .components()
            .next()
            .is_some_and(|part| EXCLUSIONS.iter().any(|name| part.as_os_str() == *name))
    {
        return Err(format!(
            "source/configuration input cannot be excluded from identity: {}",
            joined.display()
        ));
    }
    Ok(joined)
}

pub(crate) fn input_hash(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.is_dir() {
        let mut files = BTreeMap::new();
        walk(path, path, &mut files, false)?;
        if files.is_empty() {
            return Err("empty external dependency source".to_owned());
        }
        json_hash(&files)
    } else {
        file_hash(path)
    }
}

fn capture_identity(
    workspace: &Path,
    definition_path: &Path,
    approval_path: &Path,
    definition: &Definition,
    previous: Option<&SourceInventory>,
) -> Result<Identity> {
    let revision = git_revision(workspace)?;
    validate_workspace_sources(workspace)?;
    let source_files = source_files(workspace)?;
    let source_inventory = match previous {
        Some(previous) => {
            source_inventory::revalidate(workspace, definition, &source_files, previous)?
        }
        None => source_inventory::capture(workspace, definition, &source_files)?,
    };
    let mut inputs = BTreeMap::new();
    let mut input_revisions = BTreeMap::new();
    for (name, path) in &definition.inputs {
        if name.trim().is_empty() {
            return Err("empty input identity".to_owned());
        }
        let path = resolve_input(workspace, path)?;
        inputs.insert(name.clone(), input_hash(&path)?);
        input_revisions.insert(name.clone(), dependency_revision(&path)?);
    }
    let mut artifacts = BTreeMap::new();
    for (name, path) in &definition.artifacts {
        if name.trim().is_empty()
            || path
                .components()
                .any(|part| matches!(part, Component::ParentDir))
        {
            return Err("invalid artifact name or path".to_owned());
        }
        let path = if path.is_absolute() {
            path.clone()
        } else {
            workspace.join(path)
        };
        artifacts.insert(name.clone(), file_hash(&path)?);
    }
    let mut specifications: BTreeMap<PathBuf, Vec<String>> = definition
        .tools
        .iter()
        .map(|tool| (tool.program.clone(), tool.version_args.clone()))
        .collect();
    for program in definition
        .gates
        .iter()
        .map(|gate| gate.program.clone())
        .chain([
            PathBuf::from(SESSION_SUPERVISOR),
            PathBuf::from(SIGNAL_TOOL),
        ])
    {
        specifications
            .entry(program)
            .or_insert_with(|| vec!["--version".to_owned()]);
    }
    let mut tools = BTreeMap::new();
    for (program, version_args) in specifications {
        let resolved_path =
            fs::canonicalize(&program).map_err(|error| format!("cannot resolve tool: {error}"))?;
        let hash = file_hash(&resolved_path)?;
        let budget = definition
            .gates
            .iter()
            .filter(|gate| gate.program == program)
            .map(|gate| gate.budget_ms)
            .min()
            .unwrap_or(5000)
            .min(5000);
        let version = bounded_output(Command::new(&program).args(&version_args), budget, 65536)?;
        let version = std::str::from_utf8(&version)
            .map_err(|_| "tool version is not UTF-8")?
            .lines()
            .next()
            .filter(|line| !line.trim().is_empty())
            .ok_or("empty tool version")?
            .to_owned();
        tools.insert(
            program,
            Tool {
                sha256: hash,
                version,
                resolved_path,
                version_args,
            },
        );
    }
    if self::source_files(workspace)? != source_files {
        return Err("workspace changed during candidate capture".to_owned());
    }
    Ok(Identity {
        revision,
        source: json_hash(&source_files)?,
        source_files,
        source_inventory,
        inputs,
        input_revisions,
        artifacts,
        tools,
        definition: file_hash(definition_path)?,
        approval: file_hash(approval_path)?,
        scope: json_hash(definition)?,
    })
}

pub(crate) fn environment() -> BTreeMap<String, String> {
    let mut result = BTreeMap::from([
        ("os".to_owned(), std::env::consts::OS.to_owned()),
        ("architecture".to_owned(), std::env::consts::ARCH.to_owned()),
    ]);
    for (name, path) in [
        ("kernel", "/proc/sys/kernel/osrelease"),
        ("cpu", "/proc/cpuinfo"),
        ("memory", "/proc/meminfo"),
        (
            "governor",
            "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor",
        ),
    ] {
        let value = fs::read_to_string(path)
            .map(|value| value.trim_end().to_owned())
            .unwrap_or_else(|_| "unavailable".to_owned());
        result.insert(name.to_owned(), value);
    }
    result
}

pub fn freeze(
    workspace: &Path,
    definition_path: &Path,
    approval_path: &Path,
    evidence: &Path,
) -> Result<(PathBuf, Frozen)> {
    let workspace = fs::canonicalize(workspace).map_err(|error| error.to_string())?;
    let definition_path = resolve(&workspace, definition_path)?;
    let approval_path = resolve(&workspace, approval_path)?;
    let definition: Definition = read_json(&definition_path)?;
    validate_definition(&definition)?;
    let approval: Approval = read_json(&approval_path)?;
    if approval.version != 1
        || !approval.approved
        || approval.maintainer.trim().is_empty()
        || approval.definition_sha256 != file_hash(&definition_path)?
    {
        return Err("absent, unapproved or mismatched maintainer approval".to_owned());
    }
    let identity = capture_identity(
        &workspace,
        &definition_path,
        &approval_path,
        &definition,
        None,
    )?;
    let candidate = json_hash(&identity)?;
    let directory = evidence.join(&candidate);
    if directory.exists() {
        return Err("candidate already exists; refusing replacement".to_owned());
    }
    let frozen = Frozen {
        version: 1,
        candidate,
        frozen_ms: now_ms()?,
        workspace,
        definition_path,
        approval_path,
        definition,
        identity,
        environment: environment(),
    };
    write_new_json(&directory.join("freeze/manifest.json"), &frozen)?;
    Ok((directory, frozen))
}

pub fn load_current(directory: &Path) -> Result<Frozen> {
    let frozen: Frozen = read_json(&directory.join("freeze/manifest.json"))?;
    if frozen.version != 1
        || json_hash(&frozen.identity)? != frozen.candidate
        || directory.file_name().and_then(|name| name.to_str()) != Some(frozen.candidate.as_str())
    {
        return Err("tampered or misplaced candidate identity".to_owned());
    }
    validate_definition(&frozen.definition)?;
    let definition: Definition = read_json(&frozen.definition_path)?;
    if json_hash(&definition)? != json_hash(&frozen.definition)? {
        return Err("frozen definition changed".to_owned());
    }
    let approval: Approval = read_json(&frozen.approval_path)?;
    if approval.version != 1
        || !approval.approved
        || approval.maintainer.trim().is_empty()
        || approval.definition_sha256 != file_hash(&frozen.definition_path)?
    {
        return Err("candidate approval is absent or invalid".to_owned());
    }
    let current = capture_identity(
        &frozen.workspace,
        &frozen.definition_path,
        &frozen.approval_path,
        &definition,
        Some(&frozen.identity.source_inventory),
    )?;
    if current != frozen.identity {
        let inventory = &current.source_inventory;
        let frozen_inventory = &frozen.identity.source_inventory;
        let inventory_stale = [
            ("builds", inventory.builds != frozen_inventory.builds),
            (
                "dependencies",
                inventory.dependencies != frozen_inventory.dependencies,
            ),
            (
                "compiled-inputs",
                inventory.compiled_inputs != frozen_inventory.compiled_inputs,
            ),
            (
                "cargo-configuration",
                inventory.cargo_configuration != frozen_inventory.cargo_configuration,
            ),
            (
                "build-script-inputs",
                inventory.build_script_inputs != frozen_inventory.build_script_inputs,
            ),
            (
                "environment",
                inventory.environment != frozen_inventory.environment,
            ),
        ]
        .into_iter()
        .filter_map(|(name, changed)| changed.then_some(name))
        .collect::<Vec<_>>()
        .join("+");
        let stale = [
            ("revision", current.revision != frozen.identity.revision),
            ("source", current.source != frozen.identity.source),
            (
                "source-files",
                current.source_files != frozen.identity.source_files,
            ),
            ("source-inventory", !inventory_stale.is_empty()),
            ("inputs", current.inputs != frozen.identity.inputs),
            (
                "input-revisions",
                current.input_revisions != frozen.identity.input_revisions,
            ),
            ("artifacts", current.artifacts != frozen.identity.artifacts),
            ("tools", current.tools != frozen.identity.tools),
            (
                "definition",
                current.definition != frozen.identity.definition,
            ),
            ("approval", current.approval != frozen.identity.approval),
            ("scope", current.scope != frozen.identity.scope),
        ]
        .into_iter()
        .filter_map(|(name, changed)| changed.then_some(name))
        .collect::<Vec<_>>()
        .join(",");
        return Err(format!(
            "candidate identity is stale: {stale}; source-inventory={inventory_stale}"
        ));
    }
    Ok(frozen)
}

pub fn terminate_group(child: &mut Child) -> Result<ExitStatus> {
    let group = format!("-{}", child.id());
    let killed = Command::new("/bin/kill")
        .args(["-KILL", "--", &group])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("cannot terminate timed-out process group: {error}"))?;
    if !killed.success()
        && child
            .try_wait()
            .map_err(|error| error.to_string())?
            .is_none()
    {
        return Err("timed-out process group could not be terminated".to_owned());
    }
    child.wait().map_err(|error| error.to_string())
}

pub(crate) fn bounded_output(
    command: &mut Command,
    budget_ms: u64,
    limit: usize,
) -> Result<Vec<u8>> {
    let start = Instant::now();
    let output = crate::gates::tooling::run(command, budget_ms)?;
    if output.timed_out || start.elapsed() >= Duration::from_millis(budget_ms) {
        return Err("identity command exceeded its budget".to_owned());
    }
    if output.code != Some(0) {
        return Err("identity command failed".to_owned());
    }
    if output.stdout.len() > limit {
        return Err("identity-command output limit exceeded".to_owned());
    }
    Ok(output.stdout)
}

pub fn resolve_input(workspace: &Path, path: &Path) -> Result<PathBuf> {
    if path
        .components()
        .any(|part| matches!(part, Component::ParentDir))
    {
        return Err("parent traversal in explicitly bound input path".to_owned());
    }
    Ok(if path.is_absolute() {
        path.to_owned()
    } else {
        workspace.join(path)
    })
}

fn git_revision(directory: &Path) -> Result<String> {
    let output = bounded_output(
        Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(directory),
        5000,
        256,
    )?;
    let revision = std::str::from_utf8(&output)
        .map_err(|_| "source revision is not UTF-8")?
        .trim();
    if revision.len() != 40 && revision.len() != 64
        || !revision.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("invalid source revision".to_owned());
    }
    Ok(revision.to_owned())
}

pub(crate) fn dependency_revision(path: &Path) -> Result<Option<String>> {
    if path.is_dir() && path.ancestors().any(|parent| parent.join(".git").exists()) {
        git_revision(path).map(Some)
    } else {
        Ok(None)
    }
}

fn validate_workspace_sources(workspace: &Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let tracked = bounded_output(
        Command::new("git")
            .args(["ls-files", "--cached", "-z"])
            .current_dir(workspace),
        5000,
        16 * 1024 * 1024,
    )?;
    for path in tracked
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        resolve(workspace, Path::new(std::ffi::OsStr::from_bytes(path)))?;
    }
    Ok(())
}
