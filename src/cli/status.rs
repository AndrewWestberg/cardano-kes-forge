use crate::host::{
    client::{self, Error as ClientError, operator_status},
    config::{DeviceConnection, DeviceIdentity, Error as ConfigError, PublicPoolConnection},
};
use kes_protocol::{Envelope, EnvelopeKind, Operation};
use serde_json::{Value, json};
use std::{ffi::OsString, fs::File, io::Read, path::PathBuf, process::ExitCode};

pub fn run(arguments: Vec<OsString>) -> ExitCode {
    let json_output = arguments.iter().any(|a| a == "--json");
    let mut context = json!({"scope":"device","deviceId":null,"poolId":null,"requestId":null});
    match execute(arguments, &mut context) {
        Ok(value) => {
            if json_output {
                println!("{value}");
            } else {
                let result = &value["result"];
                println!(
                    "Device {}: security={}, health={}",
                    value["deviceId"], result["securityMode"], result["health"]
                );
                if !value["poolId"].is_null() {
                    println!(
                        "Pool {}: observation={}, ready={}, remainingValidityPeriods={}",
                        value["poolId"],
                        result["observation"]["state"],
                        result["ready"],
                        result["remainingValidityPeriods"]
                    );
                    println!(
                        "Active: {}; staged: {}",
                        result["active"], result["staged"]
                    );
                    for operation in crate::host::latency::Operation::ALL {
                        let name = operation.as_str();
                        let measurement = &result["latency"][name];
                        let sample = &measurement["sample"];
                        println!(
                            "{name}: state={}, durationMs={}, outcome={}, code={}, ageMs={}",
                            measurement["state"],
                            sample["durationMs"],
                            sample["outcome"],
                            sample["code"],
                            sample["ageMs"]
                        );
                    }
                }
                println!(
                    "Release evidence verified: {}",
                    result["releaseEvidenceVerified"]
                );
            }
            ExitCode::SUCCESS
        }
        Err((exit, code)) => {
            if json_output {
                println!(
                    "{}",
                    json!({"version":1,"operation":"STATUS","code":code,"scope":context["scope"],"deviceId":context["deviceId"],"poolId":context["poolId"],"requestId":context["requestId"]})
                );
            } else {
                eprintln!("status failed: {code}");
            }
            ExitCode::from(exit)
        }
    }
}

fn execute(arguments: Vec<OsString>, context: &mut Value) -> Result<Value, (u8, &'static str)> {
    let mut source = None;
    let mut json = false;
    let mut args = arguments.into_iter();
    while let Some(flag) = args.next() {
        if flag == "--json" {
            if json {
                return Err((2, "INVALID_ARGUMENTS"));
            }
            json = true;
        } else if flag == "--connection" || flag == "--device-config" {
            if source.is_some() {
                return Err((2, "INVALID_ARGUMENTS"));
            }
            let path = args
                .next()
                .filter(|v| !v.is_empty() && !v.to_string_lossy().starts_with("--"))
                .ok_or((2, "INVALID_ARGUMENTS"))?;
            source = Some((flag == "--connection", PathBuf::from(path)));
        } else {
            return Err((2, "INVALID_ARGUMENTS"));
        }
    }
    let (pool, path) = source.ok_or((2, "INVALID_ARGUMENTS"))?;
    context["scope"] = json!(if pool { "pool" } else { "device" });
    let mut request = [0; 16];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut request))
        .map_err(|_| (5, "ENTROPY_FAILURE"))?;
    context["requestId"] = json!(operator_status::hex(&request));
    let (mut result, verified) = if pool {
        let config = PublicPoolConnection::load(&path).map_err(config_error)?;
        context["deviceId"] = json!(operator_status::hex(&config.device_id));
        context["poolId"] = json!(operator_status::hex(&config.pool_id));
        let identity = DeviceIdentity::load(&config.device_identity_file).map_err(config_error)?;
        (
            operator_status::pool(&config, request).map_err(client_error)?,
            identity.verify_release_readiness().is_ok(),
        )
    } else {
        let config = DeviceConnection::load(&path).map_err(config_error)?;
        context["deviceId"] = json!(operator_status::hex(&config.device_id));
        let response = client::management_exchange(
            &config,
            request,
            Operation::Status,
            b"\xa1\x70host_diagnostics\xf5",
        )
        .map_err(client_error)?;
        let envelope = Envelope::parse(&response, EnvelopeKind::LocalResponse)
            .map_err(|_| (6, "INVALID_FRAME"))?;
        (
            operator_status::render(envelope, config.device_id, None, None, None, request)
                .map_err(client_error)?,
            config.identity.verify_release_readiness().is_ok(),
        )
    };
    result["result"]["releaseEvidenceVerified"] =
        json!(verified && result["result"]["securityMode"] == "release-ready");
    Ok(result)
}
fn config_error(error: ConfigError) -> (u8, &'static str) {
    match error {
        ConfigError::Invalid => (2, "INVALID_CONFIGURATION"),
        ConfigError::Security => (3, "AUTH_FAILED"),
        ConfigError::Unreadable => (7, "FILESYSTEM_ERROR"),
    }
}
fn client_error(error: ClientError) -> (u8, &'static str) {
    match error {
        ClientError::Security => (3, "AUTH_FAILED"),
        ClientError::Conflict => (4, "REVISION_CONFLICT"),
        ClientError::Integrity => (6, "INVALID_FRAME"),
        ClientError::Damaged => (6, "STATE_DAMAGED"),
        ClientError::Unavailable | ClientError::Uncertain => (5, "DEVICE_UNAVAILABLE"),
        ClientError::InProgress => (5, "IN_PROGRESS"),
        ClientError::Unknown => (5, "UNKNOWN"),
        ClientError::NotCommitted => (5, "NOT_COMMITTED"),
        ClientError::ResultReclaimed => (4, "RESULT_RECLAIMED"),
    }
}
