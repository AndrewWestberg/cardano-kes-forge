mod backup;
pub(crate) mod credentials;
mod generation;
mod recipient;
mod rotation;

use std::process::ExitCode;

pub fn run(binary: &str) -> ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    match arguments.next() {
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

fn profile_commands() -> &'static str {
    if cfg!(feature = "primary") {
        "  key-gen-KES  Generate a device-backed KES generation\n  certify      Certify a staged KES generation\n  activate     Activate a certified generation immediately\n  schedule     Schedule a certified replacement\n  backup       Fetch an encrypted KES backup\n  credential   Create a scoped machine credential"
    } else if cfg!(feature = "recovery") {
        "  backup       Recover an encrypted KES backup\n  recipient    Manage backup recipient keys"
    } else if cfg!(feature = "management") {
        "  authority    Manage offline management authority keys"
    } else if cfg!(feature = "provisioning") {
        "  authority    Manage provisioning reviewer authority keys"
    } else {
        "  key-gen-KES  Generate a disposable device-backed KES generation\n  certify      Certify a staged disposable KES generation\n  activate     Activate a certified disposable generation\n  schedule     Schedule a certified disposable replacement\n  backup       Fetch an encrypted disposable KES backup\n  credential   Create a scoped development credential"
    }
}

fn usage(binary: &str) -> ExitCode {
    eprintln!("Usage: {binary} COMMAND");
    ExitCode::from(2)
}
