use xtask::{acceptance, evidence, gates, qualify};

use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let args: Vec<String> = match std::env::args_os()
        .skip(1)
        .map(|arg| arg.into_string())
        .collect()
    {
        Ok(args) => args,
        Err(_) => return failure("arguments must be UTF-8"),
    };
    if args.len() > 64 || args.iter().any(|arg| arg.len() > 4096) {
        return failure("argument limits exceeded");
    }
    match dispatch(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => failure(&error),
    }
}

fn failure(error: &str) -> ExitCode {
    eprintln!("{error}");
    ExitCode::FAILURE
}

fn options<'a>(args: &'a [String], names: &[&str]) -> evidence::Result<BTreeMap<&'a str, &'a str>> {
    if args.len() != names.len() * 2 {
        return Err("wrong number of command options".to_owned());
    }
    let mut result = BTreeMap::new();
    for pair in args.as_chunks::<2>().0 {
        if !names.contains(&pair[0].as_str())
            || pair[1].is_empty()
            || result.insert(pair[0].as_str(), pair[1].as_str()).is_some()
        {
            return Err("unknown, duplicate or empty command option".to_owned());
        }
    }
    Ok(result)
}

fn dispatch(args: &[String]) -> evidence::Result<()> {
    match args.first().map(String::as_str) {
        Some("--version") if args.len() == 1 => println!("xtask {}", env!("CARGO_PKG_VERSION")),
        Some("--help") if args.len() == 1 => {
            println!(
                "Usage: xtask toolchain | freeze --workspace DIR --definition FILE --approval FILE --evidence DIR\n       xtask gate run --candidate DIR --gate ID\n       xtask gate NAME --evidence DIR  (approved gate-run child)\n       xtask acceptance --candidate DIR\n       xtask package --workspace DIR --profile primary|recovery|management|provisioning|development --out-dir NEW_DIR\n       xtask fixture create --network controlled --pools 32 --out-dir DIR\n       xtask qualify feasibility --fixture FILE --evidence DIR\n       xtask qualify security-modes --hardware yes|no --evidence DIR\n       xtask qualify load --fixture FILE --rounds N --evidence DIR\n       xtask qualify load-software --evidence DIR\n       xtask qualify management-software --evidence DIR\n       xtask qualify power-loss-software --evidence DIR\n       xtask qualify power-loss --fixture FILE --cuts N --evidence DIR\n       xtask oracle self-check  (isolated disposable native lab only)"
            );
            println!("       xtask qualify recovery-files --fixture FILE --evidence DIR");
            println!("       xtask qualify interop --fixture FILE --evidence DIR");
        }
        Some("toolchain") if args.len() == 1 => toolchain()?,
        Some("oracle") if args.len() == 2 && args[1] == "self-check" => {
            println!("{}", xtask::oracles::self_check()?);
        }
        Some("package") => {
            let opts = options(&args[1..], &["--workspace", "--profile", "--out-dir"])?;
            let result = xtask::package::build(
                Path::new(opts["--workspace"]),
                xtask::package::Profile::parse(opts["--profile"])?,
                Path::new(opts["--out-dir"]),
            )?;
            println!(
                "{}",
                serde_json::to_string(&result).map_err(|error| error.to_string())?
            );
        }
        Some("fixture") if args.get(1).is_some_and(|arg| arg == "create") => {
            let opts = options(&args[2..], &["--network", "--pools", "--out-dir"])?;
            let pools = opts["--pools"]
                .parse::<u8>()
                .map_err(|_| "fixture creation requires exactly 32 pools")?;
            let path =
                xtask::fixture::create(opts["--network"], pools, Path::new(opts["--out-dir"]))?;
            println!("{}", serde_json::json!({"manifest":path}));
        }
        Some("qualify") if args.get(1).is_some_and(|arg| arg == "feasibility") => {
            let opts = options(&args[2..], &["--fixture", "--evidence"])?;
            qualify_feasibility(Path::new(opts["--fixture"]), Path::new(opts["--evidence"]))?;
        }
        Some("qualify") if args.get(1).is_some_and(|arg| arg == "security-modes") => {
            let opts = options(&args[2..], &["--hardware", "--evidence"])?;
            let hardware = match opts["--hardware"] {
                "yes" => true,
                "no" => false,
                _ => return Err("--hardware must be yes or no".to_owned()),
            };
            let report = qualify::security_modes::run(Path::new(opts["--evidence"]), hardware)?;
            println!(
                "{}",
                serde_json::to_string(&report)
                    .map_err(|error| format!("encode security-mode report: {error}"))?
            );
        }
        Some("qualify") if args.get(1).is_some_and(|arg| arg == "load") => {
            let opts = options(&args[2..], &["--fixture", "--rounds", "--evidence"])?;
            let rounds = opts["--rounds"]
                .parse::<u64>()
                .map_err(|_| "load rounds must be an unsigned integer")?;
            qualify_load(
                Path::new(opts["--fixture"]),
                rounds,
                Path::new(opts["--evidence"]),
            )?;
        }
        Some("qualify") if args.get(1).is_some_and(|arg| arg == "load-software") => {
            let opts = options(&args[2..], &["--evidence"])?;
            let result = qualify::load::software::run(Path::new(opts["--evidence"]))?;
            println!(
                "{}",
                serde_json::json!({
                    "version": 1,
                    "campaign": "foundation-load-software",
                    "verdict": "software-pass",
                    "cases": result.cases,
                    "deadline_misses": result.deadline_misses,
                    "a4_p1_acceptance": false,
                    "manifest": result.manifest,
                })
            );
        }
        Some("qualify") if args.get(1).is_some_and(|arg| arg == "management-software") => {
            let opts = options(&args[2..], &["--evidence"])?;
            qualify_management_software(Path::new(opts["--evidence"]))?;
        }
        Some("qualify") if args.get(1).is_some_and(|arg| arg == "recovery-files") => {
            let opts = options(&args[2..], &["--fixture", "--evidence"])?;
            let input = std::fs::read(opts["--fixture"])
                .map_err(|_| "recovery fixture unavailable".to_owned())?;
            if input.len() > 16_384 {
                return Err("recovery fixture exceeds size limit".into());
            }
            let inputs: qualify::recovery_files::Inputs = serde_json::from_slice(&input)
                .map_err(|_| "invalid recovery fixture".to_owned())?;
            let report = qualify::recovery_files::run(&inputs, Path::new(opts["--evidence"]))?;
            println!(
                "{}",
                serde_json::to_string(&report).map_err(|error| error.to_string())?
            );
        }
        Some("qualify") if args.get(1).is_some_and(|arg| arg == "interop") => {
            let opts = options(&args[2..], &["--fixture", "--evidence"])?;
            let input = std::fs::read(opts["--fixture"])
                .map_err(|_| "interop fixture unavailable".to_owned())?;
            if input.len() > 16_384 {
                return Err("interop fixture exceeds size limit".into());
            }
            let inputs: qualify::interop::Inputs =
                serde_json::from_slice(&input).map_err(|_| "invalid interop fixture".to_owned())?;
            let report = qualify::interop::run(&inputs)?;
            let path = Path::new(opts["--evidence"]).join("interop.json");
            evidence::write_new_json(&path, &report)?;
            println!(
                "{}",
                serde_json::to_string(&report).map_err(|error| error.to_string())?
            );
        }
        Some("qualify") if args.get(1).is_some_and(|arg| arg == "power-loss-software") => {
            let opts = options(&args[2..], &["--evidence"])?;
            qualify_power_loss_software(Path::new(opts["--evidence"]))?;
        }
        Some("qualify") if args.get(1).is_some_and(|arg| arg == "power-loss") => {
            let opts = options(&args[2..], &["--fixture", "--cuts", "--evidence"])?;
            let cuts = opts["--cuts"]
                .parse::<u64>()
                .map_err(|_| "physical cuts must be an unsigned integer")?;
            qualify_power_loss(
                Path::new(opts["--fixture"]),
                cuts,
                Path::new(opts["--evidence"]),
            )?;
        }
        Some("freeze") => {
            let opts = options(
                &args[1..],
                &["--workspace", "--definition", "--approval", "--evidence"],
            )?;
            let (directory, frozen) = evidence::freeze(
                Path::new(opts["--workspace"]),
                Path::new(opts["--definition"]),
                Path::new(opts["--approval"]),
                Path::new(opts["--evidence"]),
            )?;
            println!(
                "{}",
                serde_json::json!({"candidate":frozen.candidate,"directory":directory})
            );
        }
        Some("acceptance") => {
            let opts = options(&args[1..], &["--candidate"])?;
            println!("{}", acceptance::accept(Path::new(opts["--candidate"]))?);
        }
        Some("gate") if args.get(1).is_some_and(|arg| arg == "run") => {
            let opts = options(&args[2..], &["--candidate", "--gate"])?;
            println!(
                "{}",
                acceptance::run_gate(Path::new(opts["--candidate"]), opts["--gate"])?
            );
        }
        Some("gate") if args.len() >= 2 => registered_gate(&args[1], &args[2..])?,
        _ => return Err("unsupported command; use xtask --help".to_owned()),
    }
    Ok(())
}

fn registered_gate(name: &str, args: &[String]) -> evidence::Result<()> {
    let opts = options(args, &["--evidence"])?;
    let candidate = std::env::var_os("KESFORGE_CANDIDATE_ROOT").ok_or(
        "gate runner requires approved `xtask gate run --candidate DIR --gate ID` invocation",
    )?;
    let gate_id = std::env::var("KESFORGE_GATE").map_err(|_| "approved gate ID is missing")?;
    let candidate = std::fs::canonicalize(candidate).map_err(|error| error.to_string())?;
    let evidence_root =
        std::fs::canonicalize(opts["--evidence"]).map_err(|error| error.to_string())?;
    if candidate.parent() != Some(evidence_root.as_path()) {
        return Err("candidate is outside the requested evidence root".to_owned());
    }
    let frozen = evidence::load_current(&candidate)?;
    let gate = frozen
        .definition
        .gates
        .iter()
        .find(|gate| gate.id == gate_id)
        .ok_or("gate not approved")?;
    let directory = candidate.join(&gate.id);
    let report = gates::run(name, &frozen, gate, &directory)?;
    evidence::write_new_json(&directory.join("report.json"), &report)?;
    acceptance::validate_report(&frozen, gate, &report)?;
    Ok(())
}

fn qualification_gate(
    evidence_root: &Path,
    expected_gate: &str,
) -> evidence::Result<Option<(evidence::Frozen, evidence::Gate, std::path::PathBuf)>> {
    let Some(candidate) = std::env::var_os("KESFORGE_CANDIDATE_ROOT") else {
        return Ok(None);
    };
    let gate_id = std::env::var("KESFORGE_GATE").map_err(|_| "approved gate ID is missing")?;
    if gate_id != expected_gate {
        return Err(format!(
            "physical qualification command cannot measure {gate_id}"
        ));
    }
    let candidate = std::fs::canonicalize(candidate).map_err(|error| error.to_string())?;
    let evidence_root = std::fs::canonicalize(evidence_root).map_err(|error| error.to_string())?;
    if candidate.parent() != Some(evidence_root.as_path()) {
        return Err("candidate is outside the requested evidence root".to_owned());
    }
    let frozen = evidence::load_current(&candidate)?;
    let gate = frozen
        .definition
        .gates
        .iter()
        .find(|gate| gate.id == expected_gate)
        .cloned()
        .ok_or("physical gate not approved")?;
    let directory = candidate.join(expected_gate);
    Ok(Some((frozen, gate, directory)))
}

fn qualify_load(fixture: &Path, rounds: u64, evidence_root: &Path) -> evidence::Result<()> {
    let context = qualification_gate(evidence_root, "P1")?;
    let output = context
        .as_ref()
        .map_or_else(|| evidence_root.to_path_buf(), |(_, _, path)| path.clone());
    let result = qualify::load::run(fixture, rounds, &output)?;
    if let Some((frozen, gate, directory)) = context {
        let report = qualify::load::report(&frozen, &gate, &result)?;
        evidence::write_new_json(&directory.join("report.json"), &report)?;
        acceptance::validate_report(&frozen, &gate, &report)?;
    } else {
        println!(
            "{}",
            serde_json::json!({"version":1,"campaign":"load","verdict":"pass",
                "cases":result.cases,"rounds":result.rounds,
                "raw_sha256":result.identity.raw_sha256})
        );
    }
    Ok(())
}

fn qualify_management_software(evidence_root: &Path) -> evidence::Result<()> {
    if std::env::var_os("KESFORGE_CANDIDATE_ROOT").is_some() {
        return Err(
            "management software campaign is development evidence, not device acceptance".into(),
        );
    }
    let result = qualify::management::run_software(evidence_root)?;
    println!(
        "{}",
        serde_json::json!({
            "version": 1,
            "campaign": "management-lifecycle-software",
            "verdict": "software-pass",
            "scenarios": result.scenarios,
            "duration_ms": result.duration_ms,
            "log_sha256": result.log_sha256,
            "manifest": result.manifest,
        })
    );
    Ok(())
}

fn qualify_power_loss_software(evidence_root: &Path) -> evidence::Result<()> {
    if std::env::var_os("KESFORGE_CANDIDATE_ROOT").is_some() {
        return Err(
            "software operational campaign is development evidence, not physical G8 acceptance"
                .into(),
        );
    }
    let result = qualify::power_loss::run_software(evidence_root)?;
    println!(
        "{}",
        serde_json::json!({
            "version": 1,
            "campaign": "operational-software-power-loss",
            "verdict": "pass",
            "ordinary_recovery_cases": result.ordinary_recovery_cases,
            "intentional_corruption_cases": result.intentional_corruption_cases,
            "pool_count": result.pool_identities.len(),
            "boundary_count": result.operational_boundaries.len(),
            "scenarios": result.scenarios,
            "maximum_scenario_duration_ms": result.maximum_scenario_duration_ms,
            "manifest": result.manifest,
        })
    );
    Ok(())
}

fn qualify_power_loss(fixture: &Path, cuts: u64, evidence_root: &Path) -> evidence::Result<()> {
    let context = qualification_gate(evidence_root, "G8")?;
    let output = context
        .as_ref()
        .map_or_else(|| evidence_root.to_path_buf(), |(_, _, path)| path.clone());
    let result = qualify::power_loss::run(fixture, cuts, &output)?;
    if let Some((frozen, gate, directory)) = context {
        let report = qualify::power_loss::report(&frozen, &gate, &result)?;
        evidence::write_new_json(&directory.join("report.json"), &report)?;
        acceptance::validate_report(&frozen, &gate, &report)?;
    } else {
        println!(
            "{}",
            serde_json::json!({"version":1,"campaign":"power-loss","verdict":"pass",
                "cases":result.cases,"physical_cuts":result.physical_cuts,
                "raw_sha256":result.identity.raw_sha256})
        );
    }
    Ok(())
}

fn qualify_feasibility(fixture: &Path, evidence_root: &Path) -> evidence::Result<()> {
    if std::env::var_os("KESFORGE_CANDIDATE_ROOT").is_some() {
        return Err(
            "combined feasibility is exploratory; run approved G8/P1 gates separately".into(),
        );
    }
    let load_directory = evidence_root.join("P1-foundation");
    let faults_directory = evidence_root.join("G8-foundation");
    let load = qualify::load::run(fixture, 3, &load_directory)?;
    let faults = qualify::power_loss::run(
        fixture,
        qualify::power_loss::OPERATIONAL_BOUNDARIES.len() as u64,
        &faults_directory,
    )?;
    let summary = serde_json::json!({
        "version":1,
        "campaign":"foundation-feasibility",
        "verdict":"pass",
        "load":{"cases":load.cases,"raw_sha256":load.identity.raw_sha256},
        "power_loss":{"cases":faults.cases,"raw_sha256":faults.identity.raw_sha256}
    });
    evidence::write_new_json(&evidence_root.join("foundation-feasibility.json"), &summary)?;
    println!("{summary}");
    Ok(())
}

fn toolchain() -> Result<(), String> {
    for (tool, prefix) in [("rustc", "rustc 1.99.1 "), ("cargo", "cargo 1.99.1 ")] {
        let result = Command::new(tool)
            .arg("--version")
            .output()
            .map_err(|error| format!("cannot execute {tool}: {error}"))?;
        if !result.status.success() {
            return Err(format!(
                "{tool} version inspection failed: {}",
                result.status
            ));
        }
        let version = std::str::from_utf8(&result.stdout)
            .map_err(|_| format!("{tool} version is not UTF-8"))?;
        if !version.starts_with(prefix) {
            return Err(format!("required {prefix}; found {}", version.trim_end()));
        }
        print!("{version}");
    }
    Ok(())
}
