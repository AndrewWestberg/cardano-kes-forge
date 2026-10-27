use crate::host::{
    config::{DeviceConnection, decode_hex},
    management::{self, Error},
};
use std::{collections::BTreeMap, ffi::OsString, path::PathBuf, process::ExitCode};

/// Entrypoint after the top-level `management` token has been consumed.
pub fn run(arguments: Vec<OsString>) -> ExitCode {
    let json = arguments.iter().any(|a| a == "--json");
    let result = execute(arguments);
    match result {
        Ok(value) => {
            if json {
                println!("{value}")
            } else {
                println!("management operation completed")
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({"version":1,"code":error.code(),"scope":"device","deviceId":null,"poolId":null,"requestId":null})
                )
            } else {
                eprintln!("management operation failed: {}", error.code())
            }
            ExitCode::from(error.exit_code())
        }
    }
}
fn execute(arguments: Vec<OsString>) -> Result<serde_json::Value, Error> {
    let mut iter = arguments.into_iter();
    let command = iter.next().ok_or(Error::Invalid)?;
    let command = command.to_str().ok_or(Error::Invalid)?;
    let allowed: &[&str] = match command {
        "enrollment-create" => &[
            "--device-config",
            "--cold-verification-key-file",
            "--shelley-genesis",
            "--network-magic",
            "--recipient-public-key-file",
            "--machine-public-key-file",
            "--incarnation-id",
            "--out-file",
        ],
        "prepare" => &["--device-config", "--action", "--payload", "--out-file"],
        "sign" => &["--request", "--management-key", "--out-file"],
        "apply" => &["--device-config", "--authorization"],
        _ => return Err(Error::Invalid),
    };
    let mut flags = BTreeMap::new();
    let mut json = false;
    while let Some(flag) = iter.next() {
        let flag = flag.to_str().ok_or(Error::Invalid)?.to_owned();
        if flag == "--json" {
            if json {
                return Err(Error::Invalid);
            }
            json = true;
            continue;
        }
        if !allowed.contains(&flag.as_str()) {
            return Err(Error::Invalid);
        }
        let value = iter.next().ok_or(Error::Invalid)?;
        if value.is_empty() || flags.insert(flag, value).is_some() {
            return Err(Error::Invalid);
        }
    }
    if flags.len() != allowed.len() {
        return Err(Error::Invalid);
    }
    let path = |name: &str| -> Result<PathBuf, Error> {
        let value = flags.get(name).ok_or(Error::Invalid)?;
        let text = value.to_str().ok_or(Error::Invalid)?;
        if text.is_empty() || text.len() > 4096 || text.contains('\0') {
            return Err(Error::Invalid);
        }
        Ok(PathBuf::from(value))
    };
    let text = |name: &str| -> Result<&str, Error> {
        flags
            .get(name)
            .and_then(|s| s.to_str())
            .ok_or(Error::Invalid)
    };
    let device;
    let mut request = None;
    let mut pool = None;
    let mut revision = None;
    let result = match command {
        "sign" => {
            #[cfg(all(
                feature = "management",
                not(any(
                    feature = "primary",
                    feature = "development",
                    feature = "recovery",
                    feature = "provisioning"
                ))
            ))]
            {
                let bytes = management::read_public(&path("--request")?)?;
                let fields = management::parse_request(&bytes)?;
                device = Some(management::hex(fields.device.as_bytes()));
                request = Some(management::hex(fields.request.as_bytes()));
                pool = match fields.target {
                    kes_core::management::Target::Device => None,
                    kes_core::management::Target::Pool { pool, .. } => {
                        Some(management::hex(pool.as_bytes()))
                    }
                };
                revision = Some(fields.expected_revision.get());
                management::sign(
                    &path("--request")?,
                    &path("--management-key")?,
                    &path("--out-file")?,
                )?;
                serde_json::json!({"authorizationFile":path("--out-file")?})
            }
            #[cfg(not(all(
                feature = "management",
                not(any(
                    feature = "primary",
                    feature = "development",
                    feature = "recovery",
                    feature = "provisioning"
                ))
            )))]
            {
                return Err(Error::Security);
            }
        }
        "enrollment-create" | "prepare" | "apply" => {
            if !cfg!(any(feature = "primary", feature = "development"))
                || cfg!(any(
                    feature = "management",
                    feature = "recovery",
                    feature = "provisioning"
                ))
            {
                return Err(Error::Security);
            }
            let config_path = path("--device-config")?;
            let config = DeviceConnection::load(&config_path).map_err(|_| Error::Security)?;
            device = Some(management::hex(&config.device_id));
            match command {
                "enrollment-create" => {
                    let magic = text("--network-magic")?;
                    if magic.is_empty() || !magic.bytes().all(|b| b.is_ascii_digit()) {
                        return Err(Error::Invalid);
                    }
                    let magic = magic.parse::<u32>().map_err(|_| Error::Invalid)?;
                    let cold = path("--cold-verification-key-file")?;
                    let genesis = path("--shelley-genesis")?;
                    let recipient = path("--recipient-public-key-file")?;
                    let machine = path("--machine-public-key-file")?;
                    let output = path("--out-file")?;
                    management::enrollment_create(
                        management::EnrollmentInputs {
                            device_config: &config_path,
                            cold_key: &cold,
                            genesis: &genesis,
                            network_magic: magic,
                            recipient: &recipient,
                            machine: &machine,
                            incarnation: decode_hex(text("--incarnation-id")?)
                                .ok_or(Error::Invalid)?,
                        },
                        &output,
                    )?;
                    serde_json::json!({"payloadFile":output})
                }
                "prepare" => {
                    let out = path("--out-file")?;
                    management::prepare(
                        &config,
                        management::action(text("--action")?)?,
                        &path("--payload")?,
                        &out,
                    )?;
                    let bytes = management::read_public(&out)?;
                    let fields = management::parse_request(&bytes)?;
                    request = Some(management::hex(fields.request.as_bytes()));
                    pool = match fields.target {
                        kes_core::management::Target::Device => None,
                        kes_core::management::Target::Pool { pool, .. } => {
                            Some(management::hex(pool.as_bytes()))
                        }
                    };
                    revision = Some(fields.expected_revision.get());
                    serde_json::json!({"requestFile":out,"managementSequence":fields.sequence.get()})
                }
                "apply" => {
                    let outcome = management::apply(&config, &path("--authorization")?)?;
                    request = Some(management::hex(&outcome.request));
                    pool = outcome.pool.map(|p| management::hex(&p));
                    revision = Some(outcome.revision);
                    serde_json::json!({"managementSequence":outcome.sequence})
                }
                _ => unreachable!(),
            }
        }
        _ => return Err(Error::Invalid),
    };
    Ok(
        serde_json::json!({"version":1,"operation":format!("management {command}"),"requestId":request,"deviceId":device,"poolId":pool,"generationId":null,"revision":revision,"result":result}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unknown_flags_and_duplicates() {
        assert!(matches!(
            execute(["prepare", "--json", "--json"].map(OsString::from).to_vec()),
            Err(Error::Invalid)
        ));
        assert!(matches!(
            execute(
                ["sign", "--signing-key-file", "private"]
                    .map(OsString::from)
                    .to_vec()
            ),
            Err(Error::Invalid)
        ));
    }
    #[test]
    fn primary_has_no_offline_authority_command() {
        if cfg!(feature = "primary") {
            assert!(matches!(
                execute(
                    [
                        "sign",
                        "--request",
                        "request",
                        "--management-key",
                        "secret",
                        "--out-file",
                        "signed"
                    ]
                    .map(OsString::from)
                    .to_vec()
                ),
                Err(Error::Security)
            ));
        }
    }
}
