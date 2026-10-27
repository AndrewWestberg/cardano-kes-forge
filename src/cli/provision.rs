use crate::host::provisioning::workstation::{self, Error};
use std::{collections::BTreeMap, ffi::OsString, path::PathBuf, process::ExitCode};

/// Provisioning workstation only. No hardware write operation is provided.
pub fn run(arguments: Vec<OsString>) -> ExitCode {
    match execute(arguments) {
        Ok(()) => {
            println!("provisioning public output published");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!(
                "provisioning refused: {}: {}",
                error.code(),
                error.diagnostic()
            );
            ExitCode::from(error.exit_code())
        }
    }
}
fn execute(arguments: Vec<OsString>) -> Result<(), Error> {
    let mut iter = arguments.into_iter();
    let command = iter.next().ok_or(Error::Invalid)?;
    let command = command.to_str().ok_or(Error::Invalid)?;
    let required: &[&str] = match command {
        "inspect" => &["--usb-device", "--out-file"],
        "prepare" => &["--manifest", "--review-key", "--out-file"],
        "apply" => &[
            "--manifest",
            "--reviewer-public-key-file",
            "--review-key",
            "--out-file",
        ],
        _ => return Err(Error::Invalid),
    };
    let mut flags = BTreeMap::new();
    let mut authorize = false;
    while let Some(flag) = iter.next() {
        let flag = flag.to_str().ok_or(Error::Invalid)?.to_owned();
        if flag == "--authorize-irreversible" {
            if command != "apply" || authorize {
                return Err(Error::Invalid);
            }
            authorize = true;
            continue;
        }
        if !required.contains(&flag.as_str()) {
            return Err(Error::Invalid);
        }
        let value = iter.next().ok_or(Error::Invalid)?;
        let text = value.to_str().ok_or(Error::Invalid)?;
        if text.is_empty()
            || text.len() > 4096
            || text.contains('\0')
            || text.starts_with("--")
            || flags.insert(flag, value).is_some()
        {
            return Err(Error::Invalid);
        }
    }
    if flags.len() != required.len() || command == "apply" && !authorize {
        return Err(Error::Invalid);
    }
    if !cfg!(all(
        feature = "provisioning",
        not(any(
            feature = "primary",
            feature = "development",
            feature = "management",
            feature = "recovery"
        ))
    )) {
        return Err(Error::Profile);
    }
    let path = |name: &str| -> Result<PathBuf, Error> {
        Ok(PathBuf::from(flags.get(name).ok_or(Error::Invalid)?))
    };
    match command {
        "inspect" => workstation::inspect(
            flags
                .get("--usb-device")
                .and_then(|v| v.to_str())
                .ok_or(Error::Invalid)?,
            &path("--out-file")?,
        ),
        "prepare" => workstation::prepare(
            &path("--manifest")?,
            &path("--review-key")?,
            &path("--out-file")?,
        ),
        // Recognition is not implementation. Do not read private keys or touch
        // devices until the actual trusted mutation/check backend exists.
        "apply" => Err(Error::BackendUnavailable),
        _ => Err(Error::Invalid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn irreversible_consent_is_apply_only() {
        let args = [
            "inspect",
            "--usb-device",
            "bus=1,address=2",
            "--out-file",
            "out.json",
            "--authorize-irreversible",
        ]
        .map(OsString::from)
        .to_vec();
        assert!(matches!(execute(args), Err(Error::Invalid)));
    }
    #[test]
    fn apply_requires_explicit_consent_before_dispatch() {
        let args = [
            "apply",
            "--manifest",
            "missing.json",
            "--reviewer-public-key-file",
            "missing.pub",
            "--review-key",
            "missing.key",
            "--out-file",
            "out.json",
        ]
        .map(OsString::from)
        .to_vec();
        assert!(matches!(execute(args), Err(Error::Invalid)));
    }

    #[cfg(all(
        feature = "provisioning",
        not(any(
            feature = "primary",
            feature = "development",
            feature = "management",
            feature = "recovery"
        ))
    ))]
    #[test]
    fn authorized_apply_refuses_backend_without_reading_inputs() {
        let args = [
            "apply",
            "--manifest",
            "missing.json",
            "--reviewer-public-key-file",
            "missing.pub",
            "--review-key",
            "missing.key",
            "--out-file",
            "out.json",
            "--authorize-irreversible",
        ]
        .map(OsString::from)
        .to_vec();
        assert!(matches!(execute(args), Err(Error::BackendUnavailable)));
    }
}
