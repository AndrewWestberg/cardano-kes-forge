use crate::host::bootstrap::{AuthorityRole, MachineScope};
use crate::host::config::decode_hex;
use crate::host::credentials::{self, MachineIdentity};
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::process::ExitCode;

pub fn run_credential(arguments: Vec<OsString>) -> ExitCode {
    let Some((command, arguments)) = arguments.split_first() else {
        return credential_usage();
    };
    if command != "create" {
        return credential_usage();
    }
    let parsed = match parse_pairs(arguments) {
        Some(value) => value,
        None => return credential_usage(),
    };
    let scope = match required(&parsed, "--scope").and_then(OsStr::to_str) {
        Some("pool") => MachineScope::Pool,
        Some("management") => MachineScope::Management,
        _ => return credential_usage(),
    };
    let device = match required(&parsed, "--device-id")
        .and_then(OsStr::to_str)
        .and_then(decode_hex)
    {
        Some(value) => value,
        None => return credential_usage(),
    };
    let epoch = match required(&parsed, "--credential-epoch")
        .and_then(OsStr::to_str)
        .and_then(|value| value.parse().ok())
    {
        Some(value) => value,
        None => return credential_usage(),
    };
    let pool = optional_hex(&parsed, "--pool-id");
    let incarnation = optional_hex(&parsed, "--incarnation-id");
    if matches!(scope, MachineScope::Pool) != (pool.is_some() && incarnation.is_some())
        || matches!(scope, MachineScope::Management) && (pool.is_some() || incarnation.is_some())
    {
        return credential_usage();
    }
    let public_path = match required(&parsed, "--public-key-file") {
        Some(value) => PathBuf::from(value),
        None => return credential_usage(),
    };
    let private_path = match required(&parsed, "--private-key-file") {
        Some(value) => PathBuf::from(value),
        None => return credential_usage(),
    };
    let expected = if matches!(scope, MachineScope::Pool) {
        7
    } else {
        5
    };
    if parsed.len() != expected {
        return credential_usage();
    }
    match credentials::create_machine(
        MachineIdentity {
            scope,
            device,
            pool,
            incarnation,
            credential_epoch: epoch,
        },
        &public_path,
        &private_path,
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(7),
    }
}

pub fn run_authority(arguments: Vec<OsString>) -> ExitCode {
    let Some((command, arguments)) = arguments.split_first() else {
        return authority_usage();
    };
    if command != "key-create" {
        return authority_usage();
    }
    let parsed = match parse_pairs(arguments) {
        Some(value) if value.len() == 3 => value,
        _ => return authority_usage(),
    };
    let role = match required(&parsed, "--role").and_then(OsStr::to_str) {
        Some("management") if cfg!(feature = "management") => AuthorityRole::Management,
        Some("provisioning-reviewer") if cfg!(feature = "provisioning") => {
            AuthorityRole::ProvisioningReviewer
        }
        Some("management" | "provisioning-reviewer") => return ExitCode::from(3),
        _ => return authority_usage(),
    };
    let public_path = match required(&parsed, "--public-key-file") {
        Some(value) => PathBuf::from(value),
        None => return authority_usage(),
    };
    let private_path = match required(&parsed, "--private-key-file") {
        Some(value) => PathBuf::from(value),
        None => return authority_usage(),
    };
    match credentials::create_authority(role, &public_path, &private_path) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(7),
    }
}

fn parse_pairs(arguments: &[OsString]) -> Option<Vec<(OsString, OsString)>> {
    let mut parsed = Vec::with_capacity(arguments.len() / 2);
    let mut chunks = arguments.chunks_exact(2);
    for pair in &mut chunks {
        if !pair[0].as_encoded_bytes().starts_with(b"--")
            || parsed.iter().any(|(name, _)| name == &pair[0])
        {
            return None;
        }
        parsed.push((pair[0].clone(), pair[1].clone()));
    }
    if chunks.remainder().is_empty() {
        Some(parsed)
    } else {
        None
    }
}

fn required<'a>(parsed: &'a [(OsString, OsString)], name: &str) -> Option<&'a OsStr> {
    parsed
        .iter()
        .find(|(candidate, _)| candidate == name)
        .map(|(_, value)| value.as_os_str())
}

fn optional_hex<const N: usize>(parsed: &[(OsString, OsString)], name: &str) -> Option<[u8; N]> {
    required(parsed, name)
        .and_then(OsStr::to_str)
        .and_then(decode_hex)
}

fn credential_usage() -> ExitCode {
    eprintln!(
        "Usage: kes-forge credential create --device-id HEX32 --scope pool|management --credential-epoch UINT [--pool-id HEX56 --incarnation-id HEX32] --public-key-file FILE --private-key-file FILE"
    );
    ExitCode::from(2)
}

fn authority_usage() -> ExitCode {
    eprintln!(
        "Usage: kes-forge authority key-create --role management|provisioning-reviewer --public-key-file FILE --private-key-file FILE"
    );
    ExitCode::from(2)
}
