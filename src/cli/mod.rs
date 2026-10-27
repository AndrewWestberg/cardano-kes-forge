mod backup;
pub(crate) mod credentials;
#[cfg(feature = "development")]
mod development;
mod generation;
mod management;
#[cfg(feature = "provisioning")]
mod provision;
mod recipient;
mod rotation;
mod status;

use std::process::ExitCode;

pub fn run(binary: &str) -> ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    match arguments.next() {
        Some(command)
            if command == "status" && cfg!(any(feature = "primary", feature = "development")) =>
        {
            status::run(arguments.collect())
        }
        Some(command)
            if command == "key-gen-KES"
                && cfg!(any(feature = "primary", feature = "development")) =>
        {
            generation::run(arguments.collect())
        }
        Some(command)
            if (command == "certify" || command == "activate" || command == "schedule")
                && cfg!(any(feature = "primary", feature = "development")) =>
        {
            rotation::run(command.to_str().unwrap_or_default(), arguments.collect())
        }
        Some(command)
            if command == "credential"
                && cfg!(any(feature = "primary", feature = "development")) =>
        {
            credentials::run_credential(arguments.collect())
        }
        Some(command)
            if command == "authority"
                && cfg!(any(feature = "management", feature = "provisioning")) =>
        {
            credentials::run_authority(arguments.collect())
        }
        Some(command)
            if command == "management"
                && cfg!(any(
                    feature = "primary",
                    feature = "development",
                    feature = "management"
                )) =>
        {
            management::run(arguments.collect())
        }
        Some(command)
            if command == "backup" && cfg!(any(feature = "primary", feature = "development")) =>
        {
            backup::run_primary(arguments.collect())
        }
        Some(command) if command == "backup" && cfg!(feature = "recovery") => {
            backup::run_recovery(arguments.collect())
        }
        Some(command) if command == "recipient" && cfg!(feature = "recovery") => {
            recipient::run(arguments.collect())
        }
        #[cfg(feature = "development")]
        Some(command) if command == "dev" => {
            ExitCode::from(development::run(arguments.collect()) as u8)
        }
        #[cfg(feature = "provisioning")]
        Some(command) if command == "provision" => provision::run(arguments.collect()),
        Some(command) if command == "--installation-profile" && arguments.next().is_none() => {
            println!(
                "{}",
                serde_json::json!({
                    "version": 1,
                    "profile": crate::INSTALLATION_PROFILE,
                    "commands": installation_commands(),
                })
            );
            ExitCode::SUCCESS
        }
        Some(command) if command == "--version" && arguments.next().is_none() => {
            println!(
                "{binary} {} ({})",
                env!("CARGO_PKG_VERSION"),
                crate::INSTALLATION_PROFILE
            );
            ExitCode::SUCCESS
        }
        Some(command) if command == "--help" && arguments.next().is_none() => {
            println!(
                "Usage: {binary} COMMAND\n\nCommands:\n{}",
                profile_commands()
            );
            ExitCode::SUCCESS
        }
        Some(_) | None => usage(binary),
    }
}

fn installation_commands() -> &'static [&'static str] {
    if cfg!(feature = "development") {
        &[
            "key-gen-KES", "status", "certify", "activate", "schedule", "backup fetch",
            "credential create", "management enrollment-create", "management prepare",
            "management apply", "dev inspect",
        ]
    } else if cfg!(feature = "primary") {
        &[
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
        ]
    } else if cfg!(feature = "recovery") {
        &[
            "backup recover",
            "recipient create",
            "recipient change-password",
        ]
    } else if cfg!(feature = "management") {
        &["authority key-create", "management sign"]
    } else {
        &[
            "authority key-create",
            "provision inspect",
            "provision prepare",
        ]
    }
}

fn profile_commands() -> &'static str {
    if cfg!(feature = "primary") {
        "  key-gen-KES  Generate a device-backed KES generation\n  status       Inspect public device or pool status\n  certify      Certify a staged KES generation\n  activate     Activate a certified generation immediately\n  schedule     Schedule a certified replacement\n  backup       Fetch an encrypted KES backup\n  credential   Create a scoped machine credential\n  management   Prepare and apply public management authorizations"
    } else if cfg!(feature = "recovery") {
        "  backup       Recover an encrypted KES backup\n  recipient    Manage backup recipient keys"
    } else if cfg!(feature = "management") {
        "  authority    Manage offline management authority keys\n  management   Sign a prepared request using offline management authority"
    } else if cfg!(feature = "provisioning") {
        "  authority    Manage provisioning reviewer authority keys\n  provision    Inspect public inventory and review provisioning artifacts"
    } else {
        "  key-gen-KES  Generate a disposable device-backed KES generation\n  status       Inspect public disposable device or pool status\n  certify      Certify a staged disposable generation\n  activate     Activate a certified disposable generation\n  schedule     Schedule a certified disposable replacement\n  backup       Fetch an encrypted disposable KES backup\n  credential   Create a scoped development credential\n  management   Prepare and apply disposable management authorizations\n  dev          Inspect protected disposable current state"
    }
}

fn usage(binary: &str) -> ExitCode {
    eprintln!("Usage: {binary} COMMAND");
    ExitCode::from(2)
}
