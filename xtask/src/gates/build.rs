use super::{cognitive_complexity::remaining, report, tooling, unavailable};
use crate::acceptance::{Report, Verdict};
use crate::evidence::{self, Frozen, Gate, Result};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

pub fn run(frozen: &Frozen, gate: &Gate, _out_dir: &Path) -> Result<Report> {
    let start = Instant::now();
    let mut value = unavailable(
        frozen,
        gate,
        "G1 requires nonempty measured source-build controls",
    );
    if frozen.definition.source_builds.is_empty() {
        return Ok(value);
    }
    let runtime = tooling::runtime_directory(frozen, gate)?;
    let measured = measure(frozen, gate, &runtime.path, start, &mut value);
    if let Err(error) = measured {
        value.verdict = Verdict::Unavailable;
        value.completed = false;
        value.measurements.insert("reason".into(), json!(error));
    }
    Ok(value)
}

fn measure(
    frozen: &Frozen,
    gate: &Gate,
    runtime: &Path,
    start: Instant,
    value: &mut Report,
) -> Result<()> {
    let config = tooling::config(&frozen.workspace)?;
    value
        .measurements
        .insert("clippy_config_sha256".into(), json!(config));
    let mut clean = true;
    let mut cases = 0;
    for build in &frozen.definition.source_builds {
        tooling::lint_flags(&build.rustflags)?;
        let tools = tooling::validate_tools(&build.toolchain, remaining(start, gate.budget_ms)?)?;
        value
            .measurements
            .insert(format!("tools:{}", build.toolchain), tools);
        let build_key = format!("build:{}", build.id);
        value
            .measurements
            .insert(build_key.clone(), Value::Object(serde_json::Map::new()));
        let bare_metal = build.target.as_deref() == Some("thumbv8m.main-none-eabihf");
        let actions: &[&str] = if bare_metal {
            &["check", "build", "clippy"]
        } else {
            &["check", "build", "test", "clippy"]
        };
        for &action in actions {
            let mut command = crate::source_inventory::cargo_command(
                build,
                &frozen.workspace,
                action,
                &runtime.join(tooling::component(&build.id)),
                None,
            )?;
            command.arg("--message-format=json");
            if action == "test"
                && build
                    .target
                    .as_deref()
                    .is_some_and(|target| target != "x86_64-unknown-linux-gnu")
            {
                command.arg("--no-run");
            }
            if action == "clippy" {
                command
                    .args(["--", "-D", "warnings", "-F", "clippy::cognitive_complexity"])
                    .env("CLIPPY_CONF_DIR", &frozen.workspace);
            }
            let output = tooling::run(&mut command, remaining(start, gate.budget_ms)?)?;
            clean &= tooling::success(&output);
            cases += 1;
            value.cases = cases;
            value
                .measurements
                .get_mut(&build_key)
                .and_then(Value::as_object_mut)
                .ok_or("internal build reading object missing")?
                .insert(action.into(), tooling::reading(&output));
            if action == "build"
                && build.profile == "release"
                && build.package == "cardano-kes-forge"
                && tooling::success(&output)
            {
                let smoke = release_help(&output, runtime, start, gate.budget_ms)?;
                clean &= smoke["passed"].as_bool() == Some(true);
                value
                    .measurements
                    .insert(format!("release-help:{}", build.id), smoke);
                cases += 1;
                value.cases = cases;
            }
        }
        // Cargo fmt has a different option surface; preserve the exact frozen manifest.
        let cargo =
            tooling::pinned_tool(&build.toolchain, "cargo", remaining(start, gate.budget_ms)?)?;
        let manifest = frozen.workspace.join(&build.manifest_path);
        let output = tooling::run(
            Command::new(cargo)
                .args(["fmt", "--check", "--manifest-path"])
                .arg(manifest)
                .current_dir(&frozen.workspace),
            remaining(start, gate.budget_ms)?,
        )?;
        clean &= tooling::success(&output);
        cases += 1;
        value.cases = cases;
        value
            .measurements
            .insert(format!("format:{}", build.id), tooling::reading(&output));
    }
    native_prerequisites(frozen, gate, runtime, start, &mut value.measurements)?;
    let (sensitive, probes) = sensitivity(gate, runtime, start)?;
    value.measurements.insert("sensitivity".into(), probes);
    value
        .measurements
        .insert("sensitivity_passed".into(), json!(sensitive));
    value
        .measurements
        .insert("physical_firmware_acceptance".into(), json!(false));
    value.measurements.insert(
        "firmware_behavior_requires_physical_qualification".into(),
        json!(true),
    );
    let expected: BTreeSet<_> = frozen
        .definition
        .source_builds
        .iter()
        .map(|build| build.id.as_str())
        .collect();
    let scenarios: BTreeMap<_, _> = gate
        .scenarios
        .iter()
        .filter(|name| expected.contains(name.as_str()))
        .map(|name| (name.clone(), 1))
        .collect();
    let scope_complete = scenarios.len() == gate.scenarios.len() && !scenarios.is_empty();
    let measurements = std::mem::take(&mut value.measurements);
    *value = report(frozen, gate, cases, scenarios, measurements);
    value.measurements.remove("reason");
    if !clean || !sensitive || !scope_complete || cases < gate.minimum_cases {
        value.verdict = Verdict::Fail;
        value.completed = false;
    }
    Ok(())
}

fn sensitivity(gate: &Gate, runtime: &Path, start: Instant) -> Result<(bool, Value)> {
    let directory = runtime.join("type-sensitivity");
    fs::create_dir(&directory).map_err(|error| error.to_string())?;
    let rustc = tooling::pinned_tool("1.99.1", "rustc", remaining(start, gate.budget_ms)?)?;
    let mut readings = serde_json::Map::new();
    let mut passed = true;
    for (name, source, negative) in [
        ("clean", "pub fn probe() -> u32 { 1 }\n", false),
        ("type-error", "pub fn probe() -> u32 { false }\n", true),
    ] {
        let path = directory.join(format!("{}.rs", name.replace('-', "_")));
        fs::write(&path, source).map_err(|error| error.to_string())?;
        let output = tooling::run(
            Command::new(&rustc)
                .arg(&path)
                .args([
                    "--crate-type=lib",
                    "--edition=2024",
                    "--emit=metadata",
                    "--error-format=json",
                    "--out-dir",
                ])
                .arg(&directory),
            remaining(start, gate.budget_ms)?,
        )?;
        let detected = if negative {
            !tooling::success(&output)
                && !output.timed_out
                && tooling::diagnostic_count(&output, "E0308") > 0
        } else {
            tooling::success(&output)
        };
        passed &= detected;
        readings.insert(name.into(), json!({"detected":detected,"source_sha256":evidence::file_hash(&path)?,"reading":tooling::reading(&output)}));
    }
    Ok((passed, Value::Object(readings)))
}

fn native_prerequisites(
    frozen: &Frozen,
    gate: &Gate,
    runtime: &Path,
    start: Instant,
    measurements: &mut BTreeMap<String, Value>,
) -> Result<()> {
    let required = frozen.definition.increment != "setup"
        || frozen.definition.inputs.iter().any(|(name, path)| {
            name.contains("oracle") || path.to_string_lossy().contains("xtask/oracles")
        });
    if !required {
        return Ok(());
    }
    let tools = native_tools(frozen, gate, runtime, start, measurements)?;
    let ghc = tools
        .executables
        .get("ghc")
        .ok_or("native prerequisite inventory lacks ghc")?;
    let cabal = tools
        .executables
        .get("cabal")
        .ok_or("native prerequisite inventory lacks cabal")?;
    if fs::canonicalize(ghc).map_err(|error| error.to_string())?
        != fs::canonicalize("/home/westbam/.ghcup/ghc/9.6.7/bin/ghc-9.6.7")
            .map_err(|error| error.to_string())?
    {
        return Err("native manifest compiler differs from the pinned oracle projects".into());
    }
    let gold = fs::canonicalize(
        tools
            .executables
            .get("ld.gold")
            .ok_or("native prerequisite inventory lacks ld.gold")?,
    )
    .map_err(|error| error.to_string())?;
    let helper_path = runtime.join("native-tools");
    let gold_output = tooling::run(
        Command::new(&gold).arg("--version"),
        remaining(start, gate.budget_ms)?,
    )?;
    if !tooling::success(&gold_output)
        || !String::from_utf8_lossy(&gold_output.stdout)
            .lines()
            .next()
            .is_some_and(|line| line.contains("GNU gold") && line.contains("2.44"))
    {
        return Err("missing/wrong GNU gold 2.44".into());
    }
    measurements.insert("native-tool:gold".into(), json!({"path":gold,"sha256":evidence::file_hash(&gold)?,"reading":tooling::reading(&gold_output)}));
    for (tool, expected) in [(ghc, "9.6.7"), (cabal, "3.12.1.0")] {
        let tool = fs::canonicalize(tool).map_err(|error| error.to_string())?;
        let output = tooling::run(
            Command::new(&tool).arg("--numeric-version"),
            remaining(start, gate.budget_ms)?,
        )?;
        if !tooling::success(&output) || String::from_utf8_lossy(&output.stdout).trim() != expected
        {
            return Err(format!("missing/wrong native tool: {}", tool.display()));
        }
        measurements.insert(format!("native-tool:{expected}"), json!({"sha256":evidence::file_hash(&tool)?,"version":expected,"reading":tooling::reading(&output)}));
    }
    for (project, package, version, commit) in [
        (
            "cli-11.4",
            "cardano-cli",
            "11.4.0.0",
            "25f4d7a6b243d80ed7d716cc91b9c51d9265ace6",
        ),
        (
            "node-11.1.3",
            "cardano-node",
            "11.1.3",
            "938cba990357ae7c4b7f95c8f75dd9d31174bbeb",
        ),
    ] {
        let directory = frozen.workspace.join("xtask/oracles").join(project);
        for file in ["cabal.project", "cabal.project.freeze", "provenance.json"] {
            let path = directory.join(file);
            let bound = frozen.definition.inputs.iter().any(|(name, input)| {
                frozen.workspace.join(input) == path
                    && frozen
                        .identity
                        .inputs
                        .get(name)
                        .is_some_and(|hash| evidence::file_hash(&path).as_ref() == Ok(hash))
            });
            if !bound {
                return Err(format!(
                    "native prerequisite not frozen: {}",
                    path.display()
                ));
            }
        }
        let provenance: Value = evidence::read_json(&directory.join("provenance.json"))?;
        if provenance["source"]["commit"].as_str() != Some(commit) {
            return Err(format!("wrong native provenance revision: {project}"));
        }
        let source = provenance["source"]["directory"]
            .as_str()
            .ok_or("native provenance has no source directory")?;
        let source = frozen.workspace.join(source);
        let source_bound = frozen.definition.inputs.iter().any(|(name, input)| {
            frozen.workspace.join(input) == source
                && frozen
                    .identity
                    .inputs
                    .get(name)
                    .is_some_and(|hash| evidence::input_hash(&source).as_ref() == Ok(hash))
        });
        if !source_bound {
            return Err(format!(
                "native release source tree is not frozen: {}",
                source.display()
            ));
        }
        let target = format!("{package}:exe:{package}");
        let builddir = frozen.workspace.join("target/oracles/build").join(project);
        let cache_preexisted = builddir.exists();
        measurements.insert(
            format!("native-cache:{project}"),
            json!({"builddir":builddir,"preexisted":cache_preexisted,"clean_rebuild":false}),
        );
        let options = [
            format!(
                "--project-file={}",
                directory.join("cabal.project").display()
            ),
            format!("--builddir={}", builddir.display()),
        ];
        let mut build = Command::new(cabal);
        build
            .current_dir(&directory)
            .arg("--config-file=../cabal.config")
            .args(["build", &target])
            .args(&options)
            .args(["--offline", "--disable-tests", "--disable-benchmarks"]);
        build
            .env_clear()
            .env(
                "HOME",
                std::env::var_os("HOME").ok_or("native build requires HOME")?,
            )
            .env("PATH", &helper_path)
            .env("LD", &gold);
        let output = tooling::run(&mut build, remaining(start, gate.budget_ms)?)?;
        measurements.insert(format!("native-build:{project}"), tooling::reading(&output));
        if !tooling::success(&output) {
            return Err(format!(
                "native release prerequisite build failed: {project}"
            ));
        }
        let output = tooling::run(
            Command::new(cabal)
                .current_dir(&directory)
                .env_clear()
                .env(
                    "HOME",
                    std::env::var_os("HOME").ok_or("native build requires HOME")?,
                )
                .env("PATH", &helper_path)
                .arg("--config-file=../cabal.config")
                .args(["list-bin", &target])
                .args(&options),
            remaining(start, gate.budget_ms)?,
        )?;
        if !tooling::success(&output) {
            return Err(format!("cannot locate release executable: {project}"));
        }
        let path = std::path::PathBuf::from(
            std::str::from_utf8(&output.stdout)
                .map_err(|error| error.to_string())?
                .trim(),
        );
        if !path.starts_with(&builddir) {
            return Err("native executable outside approved T004 oracle build directory".into());
        }
        let hash = evidence::file_hash(&path)?;
        measurements.insert(
            format!("native-binary:{project}"),
            json!({"path":path,"sha256":hash}),
        );
        if !frozen
            .identity
            .artifacts
            .values()
            .chain(frozen.identity.inputs.values())
            .any(|expected| expected == &hash)
        {
            return Err(format!(
                "native release executable does not match any frozen artifact/input: {project}"
            ));
        }
        let output = tooling::run(
            Command::new(&path).arg("--version"),
            remaining(start, gate.budget_ms)?,
        )?;
        let version_output = String::from_utf8_lossy(&output.stdout);
        let matches = tooling::success(&output)
            && version_output.starts_with(&format!("{package} {version} "))
            && version_output.contains(commit);
        measurements.insert(format!("native-identity:{project}"), json!({"path":path,"sha256":hash,"release":version,"commit":commit,"matches":matches,"reading":tooling::reading(&output)}));
        if !matches {
            return Err(format!(
                "native executable release/revision mismatch: {project}"
            ));
        }
    }
    Ok(())
}

fn release_help(
    build: &tooling::Output,
    runtime: &Path,
    start: Instant,
    budget: u64,
) -> Result<Value> {
    let executable = build
        .stdout
        .split(|byte| *byte == b'\n')
        .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
        .find(|event| {
            event["reason"] == "compiler-artifact"
                && event["target"]["name"] == "kes-forge"
                && event["executable"].is_string()
        })
        .and_then(|event| event["executable"].as_str().map(std::path::PathBuf::from))
        .ok_or("release build did not emit the actual kes-forge executable")?;
    if !executable.starts_with(runtime) {
        return Err("operator executable is outside disposable build output".into());
    }
    let hash = evidence::file_hash(&executable)?;
    let output = tooling::run(
        Command::new(&executable).arg("--help"),
        remaining(start, budget)?,
    )?;
    let passed = tooling::success(&output) && !output.stdout.is_empty();
    Ok(json!({"path":executable,"sha256":hash,"passed":passed,"reading":tooling::reading(&output)}))
}

fn require_native_input(frozen: &Frozen, path: &Path) -> Result<()> {
    let real = fs::canonicalize(path).map_err(|error| error.to_string())?;
    for (name, input) in &frozen.definition.inputs {
        let input = frozen.workspace.join(input);
        let Ok(resolved) = fs::canonicalize(&input) else {
            continue;
        };
        if (resolved == real || resolved.is_dir() && real.starts_with(&resolved))
            && frozen
                .identity
                .inputs
                .get(name)
                .is_some_and(|hash| evidence::input_hash(&input).as_ref() == Ok(hash))
        {
            return Ok(());
        }
    }
    Err(format!(
        "native tool is not a current frozen named input: {}",
        real.display()
    ))
}

/// Approved public native-tool closure. Paths identify real files, never an
/// ambient PATH search; every path is independently bound by a frozen input.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeTools {
    version: u8,
    executables: BTreeMap<String, std::path::PathBuf>,
    libraries: Vec<std::path::PathBuf>,
}

fn native_tools(
    frozen: &Frozen,
    gate: &Gate,
    runtime: &Path,
    start: Instant,
    measurements: &mut BTreeMap<String, Value>,
) -> Result<NativeTools> {
    let manifest = frozen
        .definition
        .inputs
        .get("native-oracle-prerequisites")
        .ok_or("missing frozen native-oracle-prerequisites input")?;
    let manifest = frozen.workspace.join(manifest);
    require_native_input(frozen, &manifest)?;
    let tools: NativeTools = evidence::read_json(&manifest)?;
    if tools.version != 1 || tools.libraries.is_empty() {
        return Err("invalid or empty native prerequisite closure".into());
    }
    for required in [
        "ghc", "cabal", "gcc", "ar", "ld.gold", "as", "cc1", "collect2", "sh", "bash", "ldd",
    ] {
        if !tools.executables.contains_key(required) {
            return Err(format!("native prerequisite inventory lacks {required}"));
        }
    }
    let directory = runtime.join("native-tools");
    fs::create_dir(&directory).map_err(|error| error.to_string())?;
    for (name, path) in &tools.executables {
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            || !path.is_absolute()
        {
            return Err("invalid native executable alias/path".into());
        }
        require_native_input(frozen, path)?;
        let real = fs::canonicalize(path).map_err(|error| error.to_string())?;
        std::os::unix::fs::symlink(&real, directory.join(name))
            .map_err(|error| error.to_string())?;
    }
    for library in &tools.libraries {
        if !library.is_absolute() {
            return Err("native library path is not absolute".into());
        }
        require_native_input(frozen, library)?;
    }
    let mut probes = serde_json::Map::new();
    for name in ["cc1", "collect2", "as"] {
        let output = tooling::run(
            Command::new(&tools.executables["gcc"])
                .env_clear()
                .env("PATH", &directory)
                .arg(format!("-print-prog-name={name}")),
            remaining(start, gate.budget_ms)?,
        )?;
        let found = native_path_output(&output)?;
        let found = if found.is_absolute() {
            found
        } else {
            directory.join(found)
        };
        if fs::canonicalize(found).map_err(|error| error.to_string())?
            != fs::canonicalize(&tools.executables[name]).map_err(|error| error.to_string())?
        {
            return Err(format!(
                "GCC helper disagrees with frozen inventory: {name}"
            ));
        }
        probes.insert(name.into(), tooling::reading(&output));
    }
    for name in [
        "crtbegin.o",
        "crtend.o",
        "crti.o",
        "crtn.o",
        "libgcc.a",
        "libgcc_s.so",
        "libc.so",
    ] {
        let output = tooling::run(
            Command::new(&tools.executables["gcc"])
                .env_clear()
                .env("PATH", &directory)
                .arg(format!("-print-file-name={name}")),
            remaining(start, gate.budget_ms)?,
        )?;
        let found = native_path_output(&output)?;
        if !found.is_absolute() {
            return Err(format!(
                "GCC cannot resolve required native link input {name}"
            ));
        }
        require_native_input(frozen, &found)?;
        probes.insert(name.into(), tooling::reading(&output));
    }
    let output = tooling::run(
        Command::new(&tools.executables["ghc"])
            .env_clear()
            .env("PATH", &directory)
            .arg("--print-libdir"),
        remaining(start, gate.budget_ms)?,
    )?;
    require_native_input(frozen, &native_path_output(&output)?)?;
    probes.insert("ghc-libdir".into(), tooling::reading(&output));
    for (name, path) in &tools.executables {
        let output = tooling::run(
            Command::new(&tools.executables["ldd"])
                .env_clear()
                .env("PATH", &directory)
                .arg(path),
            remaining(start, gate.budget_ms)?,
        )?;
        // Shell scripts/static helpers legitimately have no ELF dependencies.
        let text = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let no_dynamic_dependencies = text.contains("statically linked")
            || text.contains("not a dynamic executable")
            || stderr.contains("not a dynamic executable");
        if !tooling::success(&output) && !no_dynamic_dependencies {
            return Err(format!(
                "cannot discover native dynamic dependencies: {name}"
            ));
        }
        if output.timed_out || text.contains("not found") {
            return Err(format!("unavailable dynamic native dependency: {name}"));
        }
        for word in text.split_whitespace().filter(|word| word.starts_with('/')) {
            require_native_input(frozen, Path::new(word))?;
        }
        probes.insert(format!("dynamic:{name}"), tooling::reading(&output));
    }
    measurements.insert("native-prerequisite-probes".into(), Value::Object(probes));
    Ok(tools)
}

fn native_path_output(output: &tooling::Output) -> Result<std::path::PathBuf> {
    if !tooling::success(output) {
        return Err("native prerequisite path discovery failed".into());
    }
    let text = std::str::from_utf8(&output.stdout)
        .map_err(|error| error.to_string())?
        .trim();
    if text.is_empty() || text.lines().count() != 1 {
        return Err("native prerequisite path discovery was empty/ambiguous".into());
    }
    Ok(std::path::PathBuf::from(text))
}
