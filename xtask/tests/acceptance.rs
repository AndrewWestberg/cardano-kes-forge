use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    evidence: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "kes-forge-acceptance-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::write(
            root.join("source.rs"),
            "pub const PUBLIC_LIMIT: usize = 32;\n",
        )
        .unwrap();
        fs::write(root.join("Cargo.lock"), "# public disposable lock input\n").unwrap();
        for args in [
            vec!["init", "--quiet"],
            vec!["add", "source.rs", "Cargo.lock"],
            vec![
                "-c",
                "user.name=Acceptance Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--quiet",
                "-m",
                "test: initialize public candidate fixture",
            ],
        ] {
            assert!(
                Command::new("git")
                    .args(args)
                    .current_dir(&root)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let evidence = root.join("evidence");
        let definition = json!({
            "version": 1,
            "increment": "setup",
            "features": ["host:primary"],
            "source_builds": [],
            "tools": [],
            "implemented_scopes": ["infrastructure"],
            "future_scopes": ["foundation", "US1", "US2", "US3", "US4", "US5"],
            "exclusions": [".git", "target", "evidence"],
            "inputs": {"dependency-lock": "Cargo.lock"},
            "artifacts": {},
            "coverage_baselines": {"coverage":null},
            "performance": null,
            "gates": [
                {"id":"G1", "program":"/usr/bin/true", "args":[], "scenarios":["build"], "minimum_cases":1, "hardware_required":false, "budget_ms":1800000},
                {"id":"G2", "program":"/usr/bin/true", "args":[], "scenarios":["acceptance"], "minimum_cases":1, "hardware_required":false, "budget_ms":1200000},
                {"id":"G4", "program":"/usr/bin/true", "args":[], "scenarios":["mutation"], "minimum_cases":1, "hardware_required":false, "budget_ms":7200000},
                {"id":"G5", "program":"/usr/bin/true", "args":[], "scenarios":["coverage"], "minimum_cases":1, "hardware_required":false, "budget_ms":1200000},
                {"id":"G12", "program":"/usr/bin/true", "args":[], "scenarios":["complexity"], "minimum_cases":1, "hardware_required":false, "budget_ms":900000}
            ]
        });
        write_json(&root.join("definition.json"), &definition);
        let approval = json!({
            "version":1,
            "maintainer":"disposable infrastructure control, not product approval",
            "definition_sha256":sha(&fs::read(root.join("definition.json")).unwrap()),
            "approved":true
        });
        write_json(&root.join("approval.json"), &approval);
        Self { root, evidence }
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_xtask"))
            .args(args)
            .current_dir(&self.root)
            .output()
            .unwrap()
    }

    fn freeze(&self) -> (PathBuf, Value) {
        let result = self.run(&[
            "freeze",
            "--workspace",
            self.root.to_str().unwrap(),
            "--definition",
            "definition.json",
            "--approval",
            "approval.json",
            "--evidence",
            self.evidence.to_str().unwrap(),
        ]);
        assert!(
            result.status.success(),
            "freeze failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let result: Value = serde_json::from_slice(&result.stdout).unwrap();
        let directory = PathBuf::from(result["directory"].as_str().unwrap());
        let frozen = read_json(&directory.join("freeze/manifest.json"));
        (directory, frozen)
    }

    fn bundle(&self) -> PathBuf {
        let (directory, frozen) = self.freeze();
        for (gate, scenario) in [
            ("G1", "build"),
            ("G2", "acceptance"),
            ("G4", "mutation"),
            ("G5", "coverage"),
            ("G12", "complexity"),
        ] {
            fs::create_dir(directory.join(gate)).unwrap();
            let measurements = match gate {
                "G4" => {
                    json!({"modules":{"mutation":{"eligible_mutants":1,"detected_mutants":1,"critical_survivors":0}}})
                }
                "G5" => {
                    json!({"crates":{"coverage":{"line_coverage_percent":100,"changed_line_coverage_percent":100,"changed_branches_complete":true,"baseline_sha256":null}}})
                }
                "G12" => json!({"maximum_complexity":1,"threshold":25,"sensitivity_passed":true}),
                _ => json!({"sensitivity_passed":true}),
            };
            let report = json!({
                "version":1,
                "candidate":frozen["candidate"],
                "gate":gate,
                "identity":frozen["identity"],
                "features":["host:primary"],
                "scenarios":{scenario:1},
                "cases":1,
                "verdict":"pass",
                "completed":true,
                "hardware":null,
                "measurements":measurements
            });
            write_json(&directory.join(gate).join("report.json"), &report);
            let manifest = json!({
                "version":1,
                "candidate":frozen["candidate"],
                "gate":gate,
                "identity":frozen["identity"],
                "environment":frozen["environment"],
                "started_ms":frozen["frozen_ms"],
                "finished_ms":frozen["frozen_ms"],
                "process_exit":0,
                "duration_ms":0,
                "timed_out":false,
                "report_sha256":sha(&fs::read(directory.join(gate).join("report.json")).unwrap()),
                "verdict":"pass"
            });
            write_json(&directory.join(gate).join("manifest.json"), &manifest);
        }
        directory
    }

    fn accept(&self, directory: &Path) -> Output {
        self.run(&["acceptance", "--candidate", directory.to_str().unwrap()])
    }

    fn change_report(&self, directory: &Path, gate: &str, change: impl FnOnce(&mut Value)) {
        let path = directory.join(gate).join("report.json");
        let mut report = read_json(&path);
        change(&mut report);
        write_json(&path, &report);
        let manifest_path = directory.join(gate).join("manifest.json");
        let mut manifest = read_json(&manifest_path);
        manifest["report_sha256"] = json!(sha(&fs::read(&path).unwrap()));
        write_json(&manifest_path, &manifest);
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn write_json(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

#[test]
fn complete_disposable_bundle_is_accepted_without_claiming_product_qualification() {
    let fixture = Fixture::new();
    let directory = fixture.bundle();
    let result = fixture.accept(&directory);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(result["verdict"], "pass");
    assert_eq!(result["increment"], "setup");
}

#[test]
fn missing_required_gate_report_and_manifest_each_block_acceptance() {
    for missing in ["G1", "G1/report.json", "G1/manifest.json"] {
        let fixture = Fixture::new();
        let directory = fixture.bundle();
        let path = directory.join(missing);
        if path.is_dir() {
            fs::remove_dir_all(path).unwrap();
        } else {
            fs::remove_file(path).unwrap();
        }
        assert!(
            !fixture.accept(&directory).status.success(),
            "accepted missing {missing}"
        );
    }
}

#[test]
fn empty_failed_inconclusive_unavailable_and_partial_reports_are_rejected() {
    for (field, value) in [
        ("cases", json!(0)),
        ("verdict", json!("fail")),
        ("verdict", json!("inconclusive")),
        ("verdict", json!("unavailable")),
        ("completed", json!(false)),
        ("features", json!([])),
        ("scenarios", json!({})),
    ] {
        let fixture = Fixture::new();
        let directory = fixture.bundle();
        fixture.change_report(&directory, "G2", |report| report[field] = value);
        assert!(
            !fixture.accept(&directory).status.success(),
            "accepted invalid {field}"
        );
    }
}

#[test]
fn modified_source_invalidates_every_previously_passing_reading() {
    let fixture = Fixture::new();
    let directory = fixture.bundle();
    fs::write(
        fixture.root.join("source.rs"),
        "pub const PUBLIC_LIMIT: usize = 33;\n",
    )
    .unwrap();
    assert!(!fixture.accept(&directory).status.success());
}

#[test]
fn new_source_ignored_by_git_still_invalidates_candidate() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join(".gitignore"), "hidden-source.rs\n").unwrap();
    let directory = fixture.bundle();
    fs::write(
        fixture.root.join("hidden-source.rs"),
        "pub const BYPASS: bool = true;\n",
    )
    .unwrap();
    assert!(!fixture.accept(&directory).status.success());
}

#[test]
fn changed_dependency_definition_or_approval_invalidates_candidate() {
    for input in ["Cargo.lock", "definition.json", "approval.json"] {
        let fixture = Fixture::new();
        let directory = fixture.bundle();
        let mut contents = fs::read(fixture.root.join(input)).unwrap();
        contents.push(b' ');
        fs::write(fixture.root.join(input), contents).unwrap();
        assert!(
            !fixture.accept(&directory).status.success(),
            "accepted stale {input}"
        );
    }
}

#[test]
fn mixed_candidate_report_is_rejected_even_with_recomputed_report_hash() {
    let fixture = Fixture::new();
    let directory = fixture.bundle();
    fixture.change_report(&directory, "G1", |report| {
        report["candidate"] = json!("0".repeat(64))
    });
    assert!(!fixture.accept(&directory).status.success());
}

#[test]
fn altered_report_bytes_are_rejected() {
    let fixture = Fixture::new();
    let directory = fixture.bundle();
    let report = directory.join("G1/report.json");
    let mut bytes = fs::read(&report).unwrap();
    bytes.push(b' ');
    fs::write(report, bytes).unwrap();
    assert!(!fixture.accept(&directory).status.success());
}

#[test]
fn empty_mutation_campaign_and_unexplained_critical_survivor_are_rejected() {
    for (field, value) in [
        ("eligible_mutants", json!(0)),
        ("detected_mutants", json!(0)),
        ("critical_survivors", json!(1)),
    ] {
        let fixture = Fixture::new();
        let directory = fixture.bundle();
        fixture.change_report(&directory, "G4", |report| {
            report["measurements"]["modules"]["mutation"][field] = value
        });
        assert!(
            !fixture.accept(&directory).status.success(),
            "accepted {field}"
        );
    }
}

#[test]
fn source_exclusion_and_absent_or_mismatched_approval_block_freeze() {
    for invalid in ["source-exclusion", "missing-approval", "wrong-definition"] {
        let fixture = Fixture::new();
        if invalid == "missing-approval" {
            fs::remove_file(fixture.root.join("approval.json")).unwrap();
        } else if invalid == "wrong-definition" {
            let mut approval = read_json(&fixture.root.join("approval.json"));
            approval["definition_sha256"] = json!("0".repeat(64));
            write_json(&fixture.root.join("approval.json"), &approval);
        } else {
            let mut definition = read_json(&fixture.root.join("definition.json"));
            definition["exclusions"] = json!([".git", "target", "evidence", "source.rs"]);
            write_json(&fixture.root.join("definition.json"), &definition);
            let mut approval = read_json(&fixture.root.join("approval.json"));
            approval["definition_sha256"] =
                json!(sha(&fs::read(fixture.root.join("definition.json")).unwrap()));
            write_json(&fixture.root.join("approval.json"), &approval);
        }
        let result = fixture.run(&[
            "freeze",
            "--workspace",
            fixture.root.to_str().unwrap(),
            "--definition",
            "definition.json",
            "--approval",
            "approval.json",
            "--evidence",
            fixture.evidence.to_str().unwrap(),
        ]);
        assert!(!result.status.success(), "froze {invalid}");
    }
}

#[test]
fn successful_subprocess_without_required_measurement_is_not_a_gate_pass() {
    let fixture = Fixture::new();
    let (directory, _) = fixture.freeze();
    let result = fixture.run(&[
        "gate",
        "run",
        "--candidate",
        directory.to_str().unwrap(),
        "--gate",
        "G1",
    ]);
    assert!(!result.status.success());
    let manifest = read_json(&directory.join("G1/manifest.json"));
    assert_eq!(manifest["process_exit"], 0);
    assert_eq!(manifest["verdict"], "unavailable");
}

#[test]
fn required_hardware_cannot_be_omitted_or_replaced_by_exploratory_a2() {
    for revision in [None, Some("A2")] {
        let fixture = Fixture::new();
        let artifact = fixture.root.join("firmware.bin");
        fs::write(&artifact, b"public disposable artifact control").unwrap();
        let mut definition = read_json(&fixture.root.join("definition.json"));
        definition["gates"][0]["hardware_required"] = json!(true);
        definition["artifacts"]["firmware-release"] = json!("firmware.bin");
        reapprove_definition(&fixture, &definition);
        let directory = fixture.bundle();
        let hardware = revision.map_or(Value::Null, |revision| {
            json!({
                "silicon_revision":revision,"security_mode":"release-ready","qualified":true,
                "stock_clock":true,"flash_part":"public fixture","flash_capacity_bytes":4194304,
                "firmware_sha256":sha(&fs::read(&artifact).unwrap())
            })
        });
        fixture.change_report(&directory, "G1", |report| report["hardware"] = hardware);
        assert!(!fixture.accept(&directory).status.success());
    }
}

#[test]
fn implemented_scope_cannot_be_declared_future_and_final_cannot_omit_campaigns() {
    for invalid in ["overlapping-scope", "incomplete-final"] {
        let fixture = Fixture::new();
        let mut definition = read_json(&fixture.root.join("definition.json"));
        if invalid == "overlapping-scope" {
            definition["future_scopes"] = json!(["infrastructure", "foundation"]);
        } else {
            definition["increment"] = json!("final");
            definition["future_scopes"] = json!([]);
        }
        write_json(&fixture.root.join("definition.json"), &definition);
        let mut approval = read_json(&fixture.root.join("approval.json"));
        approval["definition_sha256"] =
            json!(sha(&fs::read(fixture.root.join("definition.json")).unwrap()));
        write_json(&fixture.root.join("approval.json"), &approval);
        let result = fixture.run(&[
            "freeze",
            "--workspace",
            fixture.root.to_str().unwrap(),
            "--definition",
            "definition.json",
            "--approval",
            "approval.json",
            "--evidence",
            fixture.evidence.to_str().unwrap(),
        ]);
        assert!(!result.status.success(), "froze {invalid}");
    }
}

#[test]
fn internal_source_symlink_is_bound_together_with_its_target() {
    let fixture = Fixture::new();
    std::os::unix::fs::symlink("source.rs", fixture.root.join("public-source-link.rs")).unwrap();
    let directory = fixture.bundle();
    fs::write(
        fixture.root.join("source.rs"),
        "pub const PUBLIC_LIMIT: usize = 31;\n",
    )
    .unwrap();
    assert!(!fixture.accept(&directory).status.success());
}

fn reapprove_definition(fixture: &Fixture, definition: &Value) {
    write_json(&fixture.root.join("definition.json"), definition);
    let mut approval = read_json(&fixture.root.join("approval.json"));
    approval["definition_sha256"] =
        json!(sha(&fs::read(fixture.root.join("definition.json")).unwrap()));
    write_json(&fixture.root.join("approval.json"), &approval);
}

#[test]
fn external_dependency_source_is_not_excluded_by_workspace_output_names() {
    let fixture = Fixture::new();
    let dependency = Fixture::new();
    fs::create_dir(dependency.root.join("target")).unwrap();
    let source = dependency.root.join("target/maintained.rs");
    fs::write(&source, "pub const VERSION: usize = 1;\n").unwrap();
    let mut definition = read_json(&fixture.root.join("definition.json"));
    definition["inputs"]["external-source"] = json!(dependency.root);
    reapprove_definition(&fixture, &definition);
    let directory = fixture.bundle();
    fs::write(source, "pub const VERSION: usize = 2;\n").unwrap();
    assert!(!fixture.accept(&directory).status.success());
}

#[test]
fn aggregate_mutation_success_cannot_hide_an_insensitive_required_module() {
    let fixture = Fixture::new();
    let mut definition = read_json(&fixture.root.join("definition.json"));
    definition["gates"][2]["scenarios"] = json!(["strong", "weak"]);
    reapprove_definition(&fixture, &definition);
    let directory = fixture.bundle();
    fixture.change_report(&directory, "G4", |report| {
        report["cases"] = json!(1000);
        report["scenarios"] = json!({"strong":900,"weak":100});
        report["measurements"] = json!({
            "eligible_mutants":1000,"detected_mutants":900,"critical_survivors":0,
            "modules":{
                "strong":{"eligible_mutants":900,"detected_mutants":900,"critical_survivors":0},
                "weak":{"eligible_mutants":100,"detected_mutants":0,"critical_survivors":0}
            }
        });
    });
    assert!(!fixture.accept(&directory).status.success());
}

#[test]
fn aggregate_coverage_cannot_hide_an_uncovered_required_crate() {
    let fixture = Fixture::new();
    let mut definition = read_json(&fixture.root.join("definition.json"));
    definition["gates"][3]["scenarios"] = json!(["large", "small"]);
    definition["coverage_baselines"] = json!({"large":null,"small":null});
    reapprove_definition(&fixture, &definition);
    let directory = fixture.bundle();
    fixture.change_report(&directory, "G5", |report| {
        report["cases"] = json!(1001);
        report["scenarios"] = json!({"large":1000,"small":1});
        report["measurements"] = json!({
            "line_coverage_percent":95,"changed_branches_complete":true,
            "crates":{
                "large":{"line_coverage_percent":100,"changed_line_coverage_percent":100,"changed_branches_complete":true,"baseline_sha256":null},
                "small":{"line_coverage_percent":0,"changed_line_coverage_percent":0,"changed_branches_complete":true,"baseline_sha256":null}
            }
        });
    });
    assert!(!fixture.accept(&directory).status.success());
}

#[test]
fn tool_version_query_is_stopped_before_exceeding_its_approved_budget() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    let program = fixture.root.join("slow-version");
    fs::write(&program, "#!/bin/sh\nsleep 2\n: > \"$0.late\"\n").unwrap();
    fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
    let mut definition = read_json(&fixture.root.join("definition.json"));
    definition["gates"][0]["program"] = json!(program);
    definition["gates"][0]["budget_ms"] = json!(50);
    reapprove_definition(&fixture, &definition);
    let result = fixture.run(&[
        "freeze",
        "--workspace",
        fixture.root.to_str().unwrap(),
        "--definition",
        "definition.json",
        "--approval",
        "approval.json",
        "--evidence",
        fixture.evidence.to_str().unwrap(),
    ]);
    assert!(!result.status.success());
    assert!(!fixture.root.join("slow-version.late").exists());
}

fn foundation_definition(fixture: &Fixture) -> Value {
    fs::create_dir(fixture.root.join("target")).unwrap();
    fs::write(
        fixture.root.join("target/firmware-control.bin"),
        b"public artifact validation control",
    )
    .unwrap();
    let mut definition = read_json(&fixture.root.join("definition.json"));
    definition["increment"] = json!("foundation");
    definition["implemented_scopes"] = json!(["infrastructure", "foundation"]);
    definition["future_scopes"] = json!(["US1", "US2", "US3", "US4", "US5"]);
    definition["artifacts"] = json!({"firmware-development":"target/firmware-control.bin"});
    definition["performance"] = json!({"establish":true,"baseline_input":null});
    let gates = definition["gates"].as_array_mut().unwrap();
    for (id, cases, hardware, scenarios) in [
        ("G3", 10000, false, vec!["lifecycle"]),
        (
            "G6",
            1,
            false,
            vec!["frame", "certificate", "snapshot", "session"],
        ),
        ("G7", 64, false, vec!["interop"]),
        ("G8", 1, true, vec!["power-cuts"]),
        ("G9", 1, false, vec!["session-isolation"]),
        ("P0", 1, false, vec!["crypto-benchmarks"]),
        ("P1", 1, true, vec!["physical-load"]),
    ] {
        gates.push(
            json!({"id":id,"program":"/usr/bin/true","args":[],"scenarios":scenarios,
            "minimum_cases":cases,"hardware_required":hardware,"budget_ms":86400000}),
        );
    }
    definition
}

fn public_report(
    frozen: &xtask::evidence::Frozen,
    gate: &xtask::evidence::Gate,
    measurements: Value,
) -> xtask::acceptance::Report {
    xtask::acceptance::Report {
        version: 1,
        candidate: frozen.candidate.clone(),
        gate: gate.id.clone(),
        identity: frozen.identity.clone(),
        features: frozen.definition.features.clone(),
        scenarios: gate
            .scenarios
            .iter()
            .map(|name| (name.clone(), 1))
            .collect(),
        cases: gate.minimum_cases,
        verdict: xtask::acceptance::Verdict::Pass,
        completed: true,
        hardware: None,
        measurements: serde_json::from_value(measurements).unwrap(),
    }
}

#[test]
fn mandatory_fuzz_target_inventory_and_each_target_reading_are_required() {
    let fixture = Fixture::new();
    let definition = foundation_definition(&fixture);
    reapprove_definition(&fixture, &definition);
    let (_, value) = fixture.freeze();
    let frozen: xtask::evidence::Frozen = serde_json::from_value(value).unwrap();
    let gate = frozen
        .definition
        .gates
        .iter()
        .find(|gate| gate.id == "G6")
        .unwrap();
    let mut report = public_report(&frozen, gate, json!({"targets":{}}));
    for name in &gate.scenarios {
        report.measurements.get_mut("targets").unwrap()[name] = json!({"seconds":3600,"executions":1000,"corpus_inputs":1,
            "sanitizers":true,"semantic_oracle":true,"findings":0});
    }
    assert_eq!(
        xtask::acceptance::validate_report(&frozen, gate, &report),
        Ok(())
    );
    report.measurements.get_mut("targets").unwrap()["session"] = Value::Null;
    assert!(xtask::acceptance::validate_report(&frozen, gate, &report).is_err());
    let mut definition = frozen.definition.clone();
    definition
        .gates
        .iter_mut()
        .find(|gate| gate.id == "G6")
        .unwrap()
        .scenarios = vec!["frame".to_owned()];
    assert!(xtask::evidence::validate_definition(&definition).is_err());
}

#[test]
fn production_security_gate_cannot_drop_its_hardware_requirement() {
    let fixture = Fixture::new();
    let mut value = foundation_definition(&fixture);
    fs::write(
        fixture.root.join("performance-baseline.json"),
        b"{\"public\":\"baseline control\"}",
    )
    .unwrap();
    value["increment"] = json!("US1");
    value["implemented_scopes"] = json!(["infrastructure", "foundation", "US1"]);
    value["future_scopes"] = json!(["US2", "US3", "US4", "US5"]);
    value["artifacts"]["firmware-release"] = json!("target/firmware-control.bin");
    value["inputs"]["performance-baseline"] = json!("performance-baseline.json");
    value["performance"] = json!({"establish":false,"baseline_input":"performance-baseline"});
    let mut definition: xtask::evidence::Definition = serde_json::from_value(value).unwrap();
    definition
        .gates
        .iter_mut()
        .find(|gate| gate.id == "G6")
        .unwrap()
        .scenarios
        .push("artifact".to_owned());
    definition
        .gates
        .iter_mut()
        .find(|gate| gate.id == "G9")
        .unwrap()
        .hardware_required = true;
    assert_eq!(xtask::evidence::validate_definition(&definition), Ok(()));
    definition
        .gates
        .iter_mut()
        .find(|gate| gate.id == "G9")
        .unwrap()
        .hardware_required = false;
    assert!(xtask::evidence::validate_definition(&definition).is_err());
}

#[test]
fn performance_report_cannot_relabel_an_approved_comparison_as_baseline_creation() {
    let fixture = Fixture::new();
    let mut definition = foundation_definition(&fixture);
    fs::write(
        fixture.root.join("performance-baseline.json"),
        b"{\"public\":\"prior measured samples control\"}",
    )
    .unwrap();
    definition["inputs"]["performance-baseline"] = json!("performance-baseline.json");
    definition["performance"] = json!({"establish":false,"baseline_input":"performance-baseline"});
    reapprove_definition(&fixture, &definition);
    let (_, value) = fixture.freeze();
    let frozen: xtask::evidence::Frozen = serde_json::from_value(value).unwrap();
    let gate = frozen
        .definition
        .gates
        .iter()
        .find(|gate| gate.id == "P0")
        .unwrap();
    let mut report = public_report(
        &frozen,
        gate,
        json!({
            "samples":100,"warmup_seconds":5,"measurement_seconds":10,"establishes_baseline":false,
            "independent_runs":3,"ratio_ci95_lower":0.98,"ratio_ci95_upper":1.02,"environment_variance":0.01,
            "baseline_sha256":frozen.identity.inputs["performance-baseline"],
            "core_allocations_per_operation":0,
            "controlled_delay_sensitivity":{"detected":true},
            "peak_buffers":{"journal_workspace_bytes":8192,"object_workspace_bytes":6144,
                "secret_cache_bytes":64,"public_tree_bytes":4064,"signing_state_bytes":608,
                "signature_bytes":448,"maximum_message_bytes":4096}
        }),
    );
    report.cases = 76;
    assert_eq!(
        xtask::acceptance::validate_report(&frozen, gate, &report),
        Ok(())
    );
    report
        .measurements
        .insert("establishes_baseline".to_owned(), json!(true));
    assert!(xtask::acceptance::validate_report(&frozen, gate, &report).is_err());
}

#[test]
fn generated_artifact_changes_and_unrelated_firmware_identity_invalidate_readings() {
    let fixture = Fixture::new();
    let definition = foundation_definition(&fixture);
    reapprove_definition(&fixture, &definition);
    let (directory, value) = fixture.freeze();
    let frozen: xtask::evidence::Frozen = serde_json::from_value(value).unwrap();
    let gate = frozen
        .definition
        .gates
        .iter()
        .find(|gate| gate.id == "G8")
        .unwrap();
    let mut report = public_report(
        &frozen,
        gate,
        json!({
            "physical_cuts":1,"corruption_trials":1,"ack_regressions":0,
            "lost_retained_artifacts":0,"cross_pool_mutations":0,
            "obsolete_secret_retained":0,"invalid_signatures":0,"successful_recoveries":1,
            "all_software_cut_points":true,"sensitivity_passed":true
        }),
    );
    report.hardware = Some(xtask::acceptance::Hardware {
        silicon_revision: "A4".to_owned(),
        security_mode: "development".to_owned(),
        qualified: true,
        stock_clock: true,
        flash_part: "public synthetic control".to_owned(),
        flash_capacity_bytes: 4194304,
        firmware_sha256: frozen.identity.artifacts["firmware-development"].clone(),
    });
    assert_eq!(
        xtask::acceptance::validate_report(&frozen, gate, &report),
        Ok(())
    );
    report
        .measurements
        .insert("corruption_trials".to_owned(), json!(0));
    assert!(xtask::acceptance::validate_report(&frozen, gate, &report).is_err());
    report
        .measurements
        .insert("corruption_trials".to_owned(), json!(1));
    report.hardware.as_mut().unwrap().firmware_sha256 = "0".repeat(64);
    assert!(xtask::acceptance::validate_report(&frozen, gate, &report).is_err());
    fs::write(
        fixture.root.join("target/firmware-control.bin"),
        b"changed public artifact control",
    )
    .unwrap();
    assert!(xtask::evidence::load_current(&directory).is_err());
    let (_, changed) = fixture.freeze();
    assert_eq!(frozen.identity.source, changed["identity"]["source"]);
}

#[test]
fn physical_load_requires_original_deadlines_and_detected_timing_sensitivity() {
    let fixture = Fixture::new();
    let definition = foundation_definition(&fixture);
    reapprove_definition(&fixture, &definition);
    let (_, value) = fixture.freeze();
    let frozen: xtask::evidence::Frozen = serde_json::from_value(value).unwrap();
    let gate = frozen
        .definition
        .gates
        .iter()
        .find(|gate| gate.id == "P1")
        .unwrap();
    let mut report = public_report(
        &frozen,
        gate,
        json!({
            "warm_requests":100,"rounds":3,"warm_within_100ms_fraction":1.0,
            "worst_admitted_ms":499,"worst_overload_ms":499,"worst_status_ms":1999,
            "maximum_message_bytes":4096,"pool_count":32,"invalid_signatures":0,
            "kes_ram_bytes":262144,"free_sram_bytes":32768,
            "original_admission_deadlines":true,"sensitivity_passed":true
        }),
    );
    report.hardware = Some(xtask::acceptance::Hardware {
        silicon_revision: "A4".to_owned(),
        security_mode: "development".to_owned(),
        qualified: true,
        stock_clock: true,
        flash_part: "public synthetic control".to_owned(),
        flash_capacity_bytes: 4194304,
        firmware_sha256: frozen.identity.artifacts["firmware-development"].clone(),
    });
    assert_eq!(
        xtask::acceptance::validate_report(&frozen, gate, &report),
        Ok(())
    );
    report
        .measurements
        .insert("sensitivity_passed".to_owned(), json!(false));
    assert!(xtask::acceptance::validate_report(&frozen, gate, &report).is_err());
    report
        .measurements
        .insert("sensitivity_passed".to_owned(), json!(true));
    report
        .measurements
        .insert("worst_admitted_ms".to_owned(), json!(501));
    assert!(xtask::acceptance::validate_report(&frozen, gate, &report).is_err());
}

#[test]
fn changed_line_coverage_cannot_regress_against_its_frozen_baseline() {
    let fixture = Fixture::new();
    let baseline = json!({"crate":"coverage","changed_line_coverage_percent":95});
    write_json(&fixture.root.join("coverage-baseline.json"), &baseline);
    let mut definition = read_json(&fixture.root.join("definition.json"));
    definition["inputs"]["coverage-baseline"] = json!("coverage-baseline.json");
    definition["coverage_baselines"]["coverage"] = json!("coverage-baseline");
    reapprove_definition(&fixture, &definition);
    let directory = fixture.bundle();
    fixture.change_report(&directory, "G5", |report| {
        report["measurements"]["crates"]["coverage"]["baseline_sha256"] = json!(sha(&fs::read(
            fixture.root.join("coverage-baseline.json")
        )
        .unwrap()));
        report["measurements"]["crates"]["coverage"]["changed_line_coverage_percent"] = json!(94);
    });
    assert!(!fixture.accept(&directory).status.success());
}

#[test]
fn maintained_source_cannot_be_hidden_under_a_generated_output_exclusion() {
    for tracked in [true, false] {
        let fixture = Fixture::new();
        fs::create_dir(fixture.root.join("target")).unwrap();
        fs::write(fixture.root.join("target/maintained.rs"), "fn main() {}\n").unwrap();
        if tracked {
            assert!(
                Command::new("git")
                    .args(["add", "-f", "target/maintained.rs"])
                    .current_dir(&fixture.root)
                    .status()
                    .unwrap()
                    .success()
            );
        } else {
            fs::write(fixture.root.join("Cargo.toml"), "[package]\nname=\"public-candidate-control\"\nversion=\"0.1.0\"\nedition=\"2024\"\n[[bin]]\nname=\"public-candidate-control\"\npath=\"target/maintained.rs\"\n").unwrap();
            fs::write(fixture.root.join("Cargo.lock"), "version = 4\n[[package]]\nname = \"public-candidate-control\"\nversion = \"0.1.0\"\n").unwrap();
        }
        let result = fixture.run(&[
            "freeze",
            "--workspace",
            fixture.root.to_str().unwrap(),
            "--definition",
            "definition.json",
            "--approval",
            "approval.json",
            "--evidence",
            fixture.evidence.to_str().unwrap(),
        ]);
        assert!(
            !result.status.success(),
            "excluded maintained source (tracked={tracked})"
        );
    }
}

#[test]
fn dependency_revision_change_invalidates_even_identical_source_bytes() {
    let fixture = Fixture::new();
    let dependency = Fixture::new();
    let mut definition = read_json(&fixture.root.join("definition.json"));
    definition["inputs"]["external-source"] = json!(dependency.root);
    reapprove_definition(&fixture, &definition);
    let directory = fixture.bundle();
    assert!(
        Command::new("git")
            .args([
                "-c",
                "user.name=Acceptance Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--quiet",
                "--allow-empty",
                "-m",
                "test: advance external source revision",
            ])
            .current_dir(&dependency.root)
            .status()
            .unwrap()
            .success()
    );
    assert!(!fixture.accept(&directory).status.success());
}

fn rust_source_fixture(fixture: &Fixture, dependency: Option<&Fixture>, include_output: bool) {
    let mut manifest = "[package]\nname=\"public-candidate-control\"\nversion=\"0.1.0\"\nedition=\"2024\"\n[lib]\npath=\"source.rs\"\n".to_owned();
    if let Some(dependency) = dependency {
        fs::write(dependency.root.join("Cargo.toml"), "[package]\nname=\"external-source-control\"\nversion=\"0.1.0\"\nedition=\"2024\"\n[lib]\npath=\"source.rs\"\n").unwrap();
        manifest.push_str(&format!(
            "[dependencies]\nexternal-source-control={{path={}}}\n",
            serde_json::to_string(dependency.root.to_str().unwrap()).unwrap()
        ));
    }
    fs::write(fixture.root.join("Cargo.toml"), manifest).unwrap();
    if include_output {
        fs::create_dir(fixture.root.join("target")).unwrap();
        fs::write(
            fixture.root.join("target/hidden.rs"),
            "pub const PUBLIC_LIMIT: usize = 32;\n",
        )
        .unwrap();
        fs::write(
            fixture.root.join("source.rs"),
            "#[path=\"target/hidden.rs\"] mod hidden;\npub use hidden::PUBLIC_LIMIT;\n",
        )
        .unwrap();
    }
    let mut definition = read_json(&fixture.root.join("definition.json"));
    definition["source_builds"] = json!([{
        "id":"host:primary", "manifest_path":"Cargo.toml", "package":"public-candidate-control",
        "features":[], "default_features":false, "target":null, "profile":"dev",
        "all_targets":true, "toolchain":"1.99.1", "rustflags":[]
    }]);
    reapprove_definition(fixture, &definition);
    assert!(
        Command::new("cargo")
            .args(["generate-lockfile", "--offline"])
            .current_dir(&fixture.root)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("cargo")
            .args(["check", "--offline", "--locked"])
            .current_dir(&fixture.root)
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn external_path_dependency_discovered_inputs_are_bound() {
    let fixture = Fixture::new();
    let dependency = Fixture::new();
    rust_source_fixture(&fixture, Some(&dependency), false);
    let directory = fixture.bundle();
    fs::write(
        dependency.root.join("source.rs"),
        "pub const PUBLIC_LIMIT: usize = 31;\n",
    )
    .unwrap();
    assert!(!fixture.accept(&directory).status.success());
}

#[test]
fn included_output_source_discovered_inputs_are_bound() {
    let fixture = Fixture::new();
    rust_source_fixture(&fixture, None, true);
    let directory = fixture.bundle();
    fs::write(
        fixture.root.join("target/hidden.rs"),
        "pub const PUBLIC_LIMIT: usize = 31;\n",
    )
    .unwrap();
    assert!(!fixture.accept(&directory).status.success());
}

#[test]
fn git_metadata_link_discovered_inputs_are_rejected() {
    let fixture = Fixture::new();
    let dependency = Fixture::new();
    fs::write(
        dependency.root.join(".git/hidden.rs"),
        "pub const PUBLIC_LIMIT: usize = 32;\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(".git/hidden.rs", dependency.root.join("linked.rs")).unwrap();
    let mut definition = read_json(&fixture.root.join("definition.json"));
    definition["inputs"]["external-source"] = json!(dependency.root);
    reapprove_definition(&fixture, &definition);
    let result = fixture.run(&[
        "freeze",
        "--workspace",
        fixture.root.to_str().unwrap(),
        "--definition",
        "definition.json",
        "--approval",
        "approval.json",
        "--evidence",
        fixture.evidence.to_str().unwrap(),
    ]);
    assert!(!result.status.success());
}

#[test]
fn duplicate_nested_mutation_counter_cannot_hide_a_survivor() {
    let fixture = Fixture::new();
    let directory = fixture.bundle();
    let path = directory.join("G4/report.json");
    let report = read_json(&path);
    let bytes = serde_json::to_string(&report).unwrap().replace(
        "\"detected_mutants\":1",
        "\"detected_mutants\":0,\"detected_mutants\":1",
    );
    fs::write(&path, bytes).unwrap();
    let manifest_path = directory.join("G4/manifest.json");
    let mut manifest = read_json(&manifest_path);
    manifest["report_sha256"] = json!(sha(&fs::read(&path).unwrap()));
    write_json(&manifest_path, &manifest);
    assert!(!fixture.accept(&directory).status.success());
}

#[test]
fn completed_process_observed_after_budget_cannot_produce_a_passing_gate() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    let producer = fixture.root.join("deadline-control.sh");
    fs::write(&producer,"#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf 'public deadline control 1\\n'; exit 0; fi\nsleep 0.05\ncp \"$KESFORGE_CANDIDATE_ROOT/template.json\" \"$KESFORGE_CANDIDATE_ROOT/G1/report.json\"\n").unwrap();
    fs::set_permissions(&producer, fs::Permissions::from_mode(0o700)).unwrap();
    let mut definition = read_json(&fixture.root.join("definition.json"));
    definition["gates"][0]["program"] = json!(producer);
    definition["gates"][0]["budget_ms"] = json!(50);
    reapprove_definition(&fixture, &definition);
    let (directory, frozen) = fixture.freeze();
    write_json(
        &directory.join("template.json"),
        &json!({
            "version":1,"candidate":frozen["candidate"],"gate":"G1","identity":frozen["identity"],
            "features":["host:primary"],"scenarios":{"build":1},"cases":1,"verdict":"pass",
            "completed":true,"hardware":null,"measurements":{"sensitivity_passed":true}
        }),
    );
    let result = fixture.run(&[
        "gate",
        "run",
        "--candidate",
        directory.to_str().unwrap(),
        "--gate",
        "G1",
    ]);
    assert!(!result.status.success());
    let manifest = read_json(&directory.join("G1/manifest.json"));
    assert_eq!(manifest["verdict"], "inconclusive");
    assert_eq!(manifest["timed_out"], true);
}

#[test]
fn every_declared_workspace_feature_is_compiled_before_freeze() {
    let fixture = Fixture::new();
    rust_source_fixture(&fixture, None, false);
    let mut manifest = fs::read_to_string(fixture.root.join("Cargo.toml")).unwrap();
    manifest.push_str("[features]\ndelayed=[]\n");
    fs::write(fixture.root.join("Cargo.toml"), manifest).unwrap();
    fs::create_dir_all(fixture.root.join("target")).unwrap();
    fs::write(
        fixture.root.join("target/delayed.rs"),
        "pub const PUBLIC_LIMIT: usize = 32;\n",
    )
    .unwrap();
    fs::write(fixture.root.join("source.rs"),"#[cfg(feature=\"delayed\")]\n#[path=\"target/delayed.rs\"]\npub mod delayed;\npub const PUBLIC_LIMIT: usize = 32;\n").unwrap();
    let result = fixture.run(&[
        "freeze",
        "--workspace",
        fixture.root.to_str().unwrap(),
        "--definition",
        "definition.json",
        "--approval",
        "approval.json",
        "--evidence",
        fixture.evidence.to_str().unwrap(),
    ]);
    assert!(!result.status.success());
    let mut definition = read_json(&fixture.root.join("definition.json"));
    let mut delayed = definition["source_builds"][0].clone();
    delayed["id"] = json!("host:delayed");
    delayed["features"] = json!(["delayed"]);
    definition["source_builds"]
        .as_array_mut()
        .unwrap()
        .push(delayed);
    definition["features"]
        .as_array_mut()
        .unwrap()
        .push(json!("host:delayed"));
    reapprove_definition(&fixture, &definition);
    let (directory, _) = fixture.freeze();
    assert!(xtask::evidence::load_current(&directory).is_ok());
    fs::write(
        fixture.root.join("target/delayed.rs"),
        "pub const PUBLIC_LIMIT: usize = 31;\n",
    )
    .unwrap();
    assert!(xtask::evidence::load_current(&directory).is_err());
}

#[test]
fn transitive_path_dependency_source_changes_invalidate_the_candidate() {
    let fixture = Fixture::new();
    let direct = Fixture::new();
    let transitive = Fixture::new();
    rust_source_fixture(&fixture, Some(&direct), false);
    fs::write(transitive.root.join("Cargo.toml"),"[package]\nname=\"transitive-source-control\"\nversion=\"0.1.0\"\nedition=\"2024\"\n[lib]\npath=\"source.rs\"\n").unwrap();
    let mut manifest = fs::read_to_string(direct.root.join("Cargo.toml")).unwrap();
    manifest.push_str(&format!(
        "[dependencies]\ntransitive-source-control={{path={}}}\n",
        serde_json::to_string(transitive.root.to_str().unwrap()).unwrap()
    ));
    fs::write(direct.root.join("Cargo.toml"), manifest).unwrap();
    assert!(
        Command::new("cargo")
            .args(["generate-lockfile", "--offline"])
            .current_dir(&fixture.root)
            .status()
            .unwrap()
            .success()
    );
    let (directory, _) = fixture.freeze();
    assert!(xtask::evidence::load_current(&directory).is_ok());
    fs::write(
        transitive.root.join("source.rs"),
        "pub const PUBLIC_LIMIT: usize = 31;\n",
    )
    .unwrap();
    assert!(xtask::evidence::load_current(&directory).is_err());
}

#[test]
fn declared_build_script_inputs_bind_contents_and_absence() {
    for present in [true, false] {
        let fixture = Fixture::new();
        rust_source_fixture(&fixture, None, false);
        fs::create_dir_all(fixture.root.join("target")).unwrap();
        if present {
            fs::write(fixture.root.join("target/build-input.txt"), "32").unwrap();
        }
        fs::write(
            fixture.root.join("source.rs"),
            "include!(concat!(env!(\"OUT_DIR\"),\"/generated.rs\"));\n",
        )
        .unwrap();
        fs::write(fixture.root.join("build.rs"),"use std::{fs,env,path::Path};\nfn main(){println!(\"cargo:rerun-if-changed=target/build-input.txt\");let n=fs::read_to_string(\"target/build-input.txt\").unwrap_or_else(|_|\"32\".into());fs::write(Path::new(&env::var(\"OUT_DIR\").unwrap()).join(\"generated.rs\"),format!(\"pub const PUBLIC_LIMIT: usize = {};\",n.trim())).unwrap();}\n").unwrap();
        let (directory, _) = fixture.freeze();
        assert!(xtask::evidence::load_current(&directory).is_ok());
        fs::write(fixture.root.join("target/build-input.txt"), "31").unwrap();
        assert!(xtask::evidence::load_current(&directory).is_err());
    }
}

#[test]
fn required_feature_target_needs_an_actual_compiler_artifact() {
    let fixture = Fixture::new();
    rust_source_fixture(&fixture, None, false);
    let mut manifest = fs::read_to_string(fixture.root.join("Cargo.toml")).unwrap();
    manifest.push_str("[features]\na=[]\nb=[]\n[[test]]\nname=\"combined\"\npath=\"combined.rs\"\nrequired-features=[\"a\",\"b\"]\n");
    fs::write(fixture.root.join("Cargo.toml"), manifest).unwrap();
    fs::create_dir_all(fixture.root.join("target")).unwrap();
    fs::write(fixture.root.join("combined.rs"),"#[path=\"target/hidden.rs\"] pub mod hidden;\n#[test] fn public_compiler_input(){std::hint::black_box(hidden::PUBLIC_LIMIT);}\n").unwrap();
    fs::write(
        fixture.root.join("target/hidden.rs"),
        "pub const PUBLIC_LIMIT: usize = 32;\n",
    )
    .unwrap();
    let mut definition = read_json(&fixture.root.join("definition.json"));
    let mut first = definition["source_builds"][0].clone();
    first["id"] = json!("build:a");
    first["features"] = json!(["a"]);
    let mut second = first.clone();
    second["id"] = json!("build:b");
    second["features"] = json!(["b"]);
    definition["features"] = json!(["build:a", "build:b"]);
    definition["source_builds"] = json!([first, second]);
    reapprove_definition(&fixture, &definition);
    let result = fixture.run(&[
        "freeze",
        "--workspace",
        fixture.root.to_str().unwrap(),
        "--definition",
        "definition.json",
        "--approval",
        "approval.json",
        "--evidence",
        fixture.evidence.to_str().unwrap(),
    ]);
    assert!(!result.status.success());
    let mut combined = definition["source_builds"][0].clone();
    combined["id"] = json!("build:combined");
    combined["features"] = json!(["a", "b"]);
    definition["features"]
        .as_array_mut()
        .unwrap()
        .push(json!("build:combined"));
    definition["source_builds"]
        .as_array_mut()
        .unwrap()
        .push(combined);
    reapprove_definition(&fixture, &definition);
    let (directory, _) = fixture.freeze();
    assert!(xtask::evidence::load_current(&directory).is_ok());
    fs::write(
        fixture.root.join("target/hidden.rs"),
        "pub const PUBLIC_LIMIT: usize = 31;\n",
    )
    .unwrap();
    assert!(xtask::evidence::load_current(&directory).is_err());
}

fn descendant_timeout_control(nested: bool) {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.root.join("target")).unwrap();
    let producer = fixture.root.join("descendant-control.sh");
    fs::write(&producer,"#!/bin/bash\nif [[ \"$1\" == \"--version\" ]]; then printf 'public descendant control 1\\n'; exit 0; fi\nset -m\n(sleep 0.5; printf public > target/detached.marker) &\nsleep 10\n").unwrap();
    fs::set_permissions(&producer, fs::Permissions::from_mode(0o700)).unwrap();
    let mut definition = read_json(&fixture.root.join("definition.json"));
    definition["gates"][0]["program"] = json!(producer);
    definition["gates"][0]["budget_ms"] = json!(200);
    reapprove_definition(&fixture, &definition);
    let (directory, frozen) = fixture.freeze();
    let mut command = if nested {
        let mut command = Command::new("/usr/bin/setsid");
        command
            .arg("--")
            .arg(env!("CARGO_BIN_EXE_xtask"))
            .env("KESFORGE_GATE_CONTROLLER", std::process::id().to_string())
            .env("KESFORGE_CANDIDATE_ROOT", &directory)
            .env("KESFORGE_GATE", "G1")
            .env(
                "KESFORGE_GATE_RUNTIME",
                fixture
                    .root
                    .join("target/gate-runtime")
                    .join(frozen["candidate"].as_str().unwrap())
                    .join("G1"),
            );
        command
    } else {
        Command::new(env!("CARGO_BIN_EXE_xtask"))
    };
    let result = command
        .args([
            "gate",
            "run",
            "--candidate",
            directory.to_str().unwrap(),
            "--gate",
            "G1",
        ])
        .current_dir(&fixture.root)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(
        directory.join("G1/manifest.json").is_file(),
        "controller failed before recording its verdict: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    std::thread::sleep(std::time::Duration::from_millis(600));
    assert!(!fixture.root.join("target/detached.marker").exists());
    assert!(
        !fixture
            .root
            .join("target/gate-runtime")
            .join(frozen["candidate"].as_str().unwrap())
            .join("G1")
            .exists()
    );
    assert_eq!(
        read_json(&directory.join("G1/manifest.json"))["verdict"],
        "inconclusive"
    );
}

#[test]
fn outer_timeout_stops_descendants_in_independent_process_groups() {
    descendant_timeout_control(false);
}

#[test]
fn nested_controller_timeout_stops_descendants_in_independent_process_groups() {
    descendant_timeout_control(true);
}

#[test]
fn cargo_home_configuration_is_bound_with_empty_and_relative_environment_values() {
    let rustup_home = Command::new("rustup")
        .args(["show", "home"])
        .output()
        .unwrap();
    assert!(rustup_home.status.success());
    let rustup_home = String::from_utf8(rustup_home.stdout).unwrap();
    for relative in [false, true] {
        let fixture = Fixture::new();
        let home = Fixture::new();
        rust_source_fixture(&fixture, None, false);
        fs::create_dir(home.root.join(".cargo")).unwrap();
        let configuration = home.root.join(".cargo/config.toml");
        fs::write(&configuration, "[env]\nPUBLIC_CONTROL = \"before\"\n").unwrap();
        fs::write(
            fixture.root.join("source.rs"),
            "pub const PUBLIC_CONTROL: &str = env!(\"PUBLIC_CONTROL\");\n",
        )
        .unwrap();
        let cargo_home = if relative {
            format!(
                "../{}/.cargo",
                home.root.file_name().unwrap().to_str().unwrap()
            )
        } else {
            String::new()
        };
        let run = |args: &[&str]| {
            Command::new(env!("CARGO_BIN_EXE_xtask"))
                .args(args)
                .current_dir(env!("CARGO_MANIFEST_DIR"))
                .env("HOME", &home.root)
                .env("RUSTUP_HOME", rustup_home.trim())
                .env("CARGO_HOME", &cargo_home)
                .output()
                .unwrap()
        };
        let frozen = run(&[
            "freeze",
            "--workspace",
            fixture.root.to_str().unwrap(),
            "--definition",
            "definition.json",
            "--approval",
            "approval.json",
            "--evidence",
            fixture.evidence.to_str().unwrap(),
        ]);
        assert!(
            frozen.status.success(),
            "{}",
            String::from_utf8_lossy(&frozen.stderr)
        );
        let frozen: Value = serde_json::from_slice(&frozen.stdout).unwrap();
        let directory = Path::new(frozen["directory"].as_str().unwrap());
        let initial = run(&[
            "gate",
            "run",
            "--candidate",
            directory.to_str().unwrap(),
            "--gate",
            "G1",
        ]);
        assert!(!initial.status.success());
        assert!(directory.join("G1/manifest.json").is_file());
        fs::write(&configuration, "[env]\nPUBLIC_CONTROL = \"after\"\n").unwrap();
        let stale = run(&[
            "gate",
            "run",
            "--candidate",
            directory.to_str().unwrap(),
            "--gate",
            "G2",
        ]);
        assert!(!stale.status.success());
        assert!(
            String::from_utf8_lossy(&stale.stderr).contains("identity is stale"),
            "{}",
            String::from_utf8_lossy(&stale.stderr)
        );
        assert!(!directory.join("G2/manifest.json").exists());
    }
}

#[test]
fn named_rust_producer_does_not_execute_other_package_targets() {
    let fixture = Fixture::new();
    rust_source_fixture(&fixture, None, false);
    fs::create_dir(fixture.root.join("tests")).unwrap();
    fs::write(
        fixture.root.join("tests/selected.rs"),
        r#"#[test]
fn authorization_workload() {
    let mut checked = 0;
    for pool in 0_u32..32 {
        let authorized = |requested| requested == pool;
        assert!(authorized(pool));
        assert!(!authorized(pool + 1));
        checked += 2;
    }
    println!("KES_GATE_SUMMARY {{\"cases\":{checked}}}");
}
"#,
    )
    .unwrap();
    fs::write(
        fixture.root.join("tests/unselected.rs"),
        "#[test]\nfn seeded_unrelated_failure() { panic!(\"unselected target executed\"); }\n",
    )
    .unwrap();
    let definition = read_json(&fixture.root.join("definition.json"));
    let build = serde_json::from_value(definition["source_builds"][0].clone()).unwrap();
    let output = xtask::source_inventory::cargo_command(
        &build,
        &fixture.root,
        "test",
        &fixture.root.join("target/named-producer"),
        Some("selected"),
    )
    .unwrap()
    .args(["--", "--nocapture"])
    .output()
    .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let summaries: Vec<Value> = stdout
        .lines()
        .filter_map(|line| line.strip_prefix("KES_GATE_SUMMARY "))
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(summaries, vec![json!({"cases":64})]);
}

#[test]
fn cross_compilation_binds_host_only_build_dependency_sources() {
    let fixture = Fixture::new();
    let dependency = Fixture::new();
    rust_source_fixture(&fixture, None, false);
    fs::write(
        dependency.root.join("Cargo.toml"),
        "[package]\nname=\"external-source-control\"\nversion=\"0.1.0\"\nedition=\"2024\"\n[lib]\npath=\"source.rs\"\n",
    )
    .unwrap();
    let mut manifest = fs::read_to_string(fixture.root.join("Cargo.toml")).unwrap();
    manifest.push_str(&format!(
        "[target.'cfg(unix)'.build-dependencies]\nexternal-source-control={{path={}}}\n",
        serde_json::to_string(dependency.root.to_str().unwrap()).unwrap()
    ));
    fs::write(fixture.root.join("Cargo.toml"), manifest).unwrap();
    fs::write(
        fixture.root.join("build.rs"),
        "fn main(){println!(\"cargo:rustc-env=PUBLIC_CONTROL={}\", external_source_control::PUBLIC_LIMIT);}\n",
    )
    .unwrap();
    fs::write(
        fixture.root.join("source.rs"),
        "#![no_std]\npub const PUBLIC_CONTROL: &str = env!(\"PUBLIC_CONTROL\");\n",
    )
    .unwrap();
    assert!(
        Command::new("cargo")
            .args(["generate-lockfile", "--offline"])
            .current_dir(&fixture.root)
            .status()
            .unwrap()
            .success()
    );
    let mut definition = read_json(&fixture.root.join("definition.json"));
    definition["source_builds"][0]["target"] = json!("thumbv8m.main-none-eabihf");
    definition["source_builds"][0]["all_targets"] = json!(false);
    reapprove_definition(&fixture, &definition);
    let (directory, _) = fixture.freeze();
    assert!(xtask::evidence::load_current(&directory).is_ok());
    fs::write(
        dependency.root.join("source.rs"),
        "pub const PUBLIC_LIMIT: usize = 31;\n",
    )
    .unwrap();
    assert!(xtask::evidence::load_current(&directory).is_err());
}

#[test]
fn same_behavior_rustup_launcher_replacement_invalidates_compiler_identity() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new();
    let launcher = Fixture::new();
    rust_source_fixture(&fixture, None, false);
    let actual = Command::new("/bin/sh")
        .args(["-c", "command -v rustup"])
        .output()
        .unwrap();
    assert!(actual.status.success());
    let actual = String::from_utf8(actual.stdout).unwrap();
    let wrapper = launcher.root.join("rustup");
    let script = format!(
        "#!/bin/sh\nexec '{}' \"$@\"\n",
        actual.trim().replace('\'', "'\\''")
    );
    fs::write(&wrapper, &script).unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
    let inherited = std::env::var_os("PATH").unwrap();
    let path = std::env::join_paths(
        std::iter::once(launcher.root.clone()).chain(std::env::split_paths(&inherited)),
    )
    .unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_xtask"))
            .args(args)
            .current_dir(&fixture.root)
            .env("PATH", &path)
            .output()
            .unwrap()
    };
    let frozen = run(&[
        "freeze",
        "--workspace",
        fixture.root.to_str().unwrap(),
        "--definition",
        "definition.json",
        "--approval",
        "approval.json",
        "--evidence",
        fixture.evidence.to_str().unwrap(),
    ]);
    assert!(
        frozen.status.success(),
        "{}",
        String::from_utf8_lossy(&frozen.stderr)
    );
    let frozen: Value = serde_json::from_slice(&frozen.stdout).unwrap();
    let directory = Path::new(frozen["directory"].as_str().unwrap());
    let initial = run(&[
        "gate",
        "run",
        "--candidate",
        directory.to_str().unwrap(),
        "--gate",
        "G1",
    ]);
    assert!(!initial.status.success());
    assert!(directory.join("G1/manifest.json").is_file());
    fs::write(
        &wrapper,
        format!("{script}# public replacement, same behavior\n"),
    )
    .unwrap();
    let stale = run(&[
        "gate",
        "run",
        "--candidate",
        directory.to_str().unwrap(),
        "--gate",
        "G2",
    ]);
    assert!(!stale.status.success());
    assert!(
        String::from_utf8_lossy(&stale.stderr).contains("identity is stale"),
        "{}",
        String::from_utf8_lossy(&stale.stderr)
    );
    assert!(!directory.join("G2/manifest.json").exists());
}

#[test]
fn fixture_collision_preserves_existing_data_and_dangling_links() {
    for dangling_link in [false, true] {
        let fixture = Fixture::new();
        let output = fixture.root.join("public-scenario");
        if dangling_link {
            std::os::unix::fs::symlink("missing-target", &output).unwrap();
        } else {
            fs::create_dir(&output).unwrap();
            write_json(
                &output.join("manifest.json"),
                &json!({"retained_public_marker":32}),
            );
        }
        let result = fixture.run(&[
            "fixture",
            "create",
            "--network",
            "controlled",
            "--pools",
            "32",
            "--out-dir",
            output.to_str().unwrap(),
        ]);
        assert!(!result.status.success());
        if dangling_link {
            assert_eq!(fs::read_link(&output).unwrap(), Path::new("missing-target"));
            assert!(!fixture.root.join("missing-target").exists());
        } else {
            assert_eq!(
                read_json(&output.join("manifest.json")),
                json!({"retained_public_marker":32})
            );
        }
    }
}

#[test]
fn mainnet_and_reduced_pool_fixture_requests_have_no_output_side_effects() {
    for (network, pools) in [("mainnet", "32"), ("controlled", "31")] {
        let fixture = Fixture::new();
        let output = fixture.root.join("public-scenario");
        let result = fixture.run(&[
            "fixture",
            "create",
            "--network",
            network,
            "--pools",
            pools,
            "--out-dir",
            output.to_str().unwrap(),
        ]);
        assert!(!result.status.success());
        assert!(!output.exists());
    }
}

#[test]
fn public_scenario_keeps_operational_secrets_off_bundle_and_trusted_roles_off_primary() {
    use std::os::unix::fs::PermissionsExt;
    use xtask::fixture::{ScenarioManifest, Workstation};

    let fixture = Fixture::new();
    let output = fixture.root.join("public-scenario");
    let result = fixture.run(&[
        "fixture",
        "create",
        "--network",
        "controlled",
        "--pools",
        "32",
        "--out-dir",
        output.to_str().unwrap(),
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result: Value = serde_json::from_slice(&result.stdout).unwrap();
    let path = Path::new(result["manifest"].as_str().unwrap());
    let scenario: ScenarioManifest = xtask::evidence::read_json(path).unwrap();
    assert!(!scenario.runtime.root.exists());
    assert!(scenario.runtime.root.is_absolute());
    assert!(!scenario.runtime.root.starts_with(&output));
    assert_eq!(
        fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let entries: Vec<_> = fs::read_dir(&output)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(entries, vec![std::ffi::OsString::from("manifest.json")]);
    for pool in &scenario.pools {
        for reference in [
            &pool.cold_signing_key,
            &pool.recipient_private_key_file,
            &pool.recovered_conventional_key,
            &pool.development_inspection,
        ] {
            assert_ne!(reference.workstation, Workstation::Primary);
        }
        for reference in [
            &pool.cold_signing_key,
            &pool.recipient_private_key_file,
            &pool.recovered_conventional_key,
            &pool.development_inspection,
            &pool.machine_credential_private,
            &pool.vrf_signing_key,
        ] {
            assert!(reference.path.is_absolute());
            assert!(reference.path.starts_with(&scenario.runtime.root));
            assert!(!reference.path.starts_with(&output));
            assert!(!reference.path.exists());
        }
    }
    for role in [Workstation::Recovery, Workstation::Provisioning] {
        let runtime = scenario
            .runtime
            .workstations
            .iter()
            .find(|runtime| runtime.workstation == role)
            .unwrap();
        assert!(
            runtime
                .must_not_share_workstation_with
                .contains(&Workstation::Primary)
        );
    }
}
