//! Development-only command; the parent dispatcher must feature-gate registration.
#![cfg(feature = "development")]
use crate::host::development::{self, Error};
use std::{collections::BTreeMap, ffi::OsString, path::Path};

pub fn run(arguments: Vec<OsString>) -> i32 {
    match parse(&arguments).and_then(|options| {
        development::inspect(
            Path::new(options["--connection"]),
            options["--usb-device"],
            generation(options["--generation"]).ok_or(Error::Usage)?,
            Path::new(options["--out-file"]),
            true,
        )
    }) {
        Ok(()) => {
            println!(
                "Protected disposable current-state inspection published (KESDEV01; not a backup)."
            );
            0
        }
        Err(error) => {
            let (code, message) = match error {
                Error::Usage => (
                    2,
                    "usage: kes-forge dev inspect --connection FILE --usb-device SELECTOR --generation HEX32 --allow-development --out-file FILE",
                ),
                Error::Security => (
                    3,
                    "development inspection refused: isolated development profile, pinned pool authority, locked buffers and a non-dumpable no-swap cgroup are required",
                ),
                Error::Unavailable => (
                    5,
                    "development device unavailable or authenticated inspection failed",
                ),
                Error::Integrity => (
                    6,
                    "development inspection context or state integrity failure",
                ),
                Error::Publication => (
                    7,
                    "protected publication failed; do not overwrite or assume an uncertain output is absent",
                ),
            };
            eprintln!("{message}");
            code
        }
    }
}

fn parse(arguments: &[OsString]) -> Result<BTreeMap<&str, &str>, Error> {
    if !development::development_profile() {
        return Err(Error::Security);
    }
    if arguments.first().and_then(|s| s.to_str()) != Some("inspect") {
        return Err(Error::Usage);
    }
    let mut options = BTreeMap::new();
    let mut allow = false;
    let mut cursor = 1;
    while cursor < arguments.len() {
        let key = arguments[cursor].to_str().ok_or(Error::Usage)?;
        cursor += 1;
        if key == "--allow-development" {
            if allow {
                return Err(Error::Usage);
            }
            allow = true;
            continue;
        }
        if !matches!(
            key,
            "--connection" | "--usb-device" | "--generation" | "--out-file"
        ) {
            return Err(Error::Usage);
        }
        let value = arguments
            .get(cursor)
            .and_then(|s| s.to_str())
            .filter(|s| !s.is_empty() && !s.starts_with("--"))
            .ok_or(Error::Usage)?;
        cursor += 1;
        if options.insert(key, value).is_some() {
            return Err(Error::Usage);
        }
    }
    if !allow || options.len() != 4 {
        return Err(Error::Usage);
    }
    generation(options["--generation"]).ok_or(Error::Usage)?;
    Ok(options)
}
fn generation(text: &str) -> Option<[u8; 16]> {
    if text.len() != 32 {
        return None;
    }
    let mut result = [0; 16];
    for (index, pair) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        fn nibble(byte: u8) -> Option<u8> {
            match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                _ => None,
            }
        }
        result[index] = nibble(pair[0])? * 16 + nibble(pair[1])?;
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(extra: &[&str]) -> Vec<OsString> {
        [
            "inspect",
            "--connection",
            "pool.json",
            "--usb-device",
            "bus=1,address=2",
            "--generation",
            "01010101010101010101010101010101",
            "--out-file",
            "current.kes-dev",
        ]
        .into_iter()
        .chain(extra.iter().copied())
        .map(OsString::from)
        .collect()
    }
    #[test]
    fn requires_explicit_opt_in_and_no_secret_stdout_switch() {
        if !development::development_profile() {
            return;
        }
        assert!(parse(&args(&[])).is_err());
        assert!(parse(&args(&["--allow-development"])).is_ok());
        assert!(parse(&args(&["--allow-development", "--json"])).is_err());
        assert!(parse(&args(&["--allow-development", "--allow-development"])).is_err());
    }
    #[test]
    fn generation_is_exact_lowercase_identifier() {
        assert!(generation("01010101010101010101010101010101").is_some());
        assert!(generation("AA010101010101010101010101010101").is_none());
        assert!(generation("01").is_none());
    }
}
