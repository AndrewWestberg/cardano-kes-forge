use crate::backup::password;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

pub fn run(arguments: Vec<OsString>) -> ExitCode {
    if arguments.first().is_some_and(|command| command == "create") {
        return create(arguments);
    }
    let path = match parse_change_password(arguments) {
        Ok(path) => path,
        Err(()) => return usage(),
    };
    match password::change_password_interactive(&path) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => failure(error),
    }
}

fn create(arguments: Vec<OsString>) -> ExitCode {
    let mut arguments = arguments.into_iter().skip(1);
    let mut public = None;
    let mut private = None;
    while let Some(flag) = arguments.next() {
        let Some(path) = arguments.next().map(PathBuf::from) else {
            return usage();
        };
        match flag.to_str() {
            Some("--public-key-file") if public.is_none() => public = Some(path),
            Some("--private-key-file") if private.is_none() => private = Some(path),
            _ => return usage(),
        }
    }
    let (Some(public), Some(private)) = (public, private) else {
        return usage();
    };
    if public == private
        || std::path::absolute(&public)
            .ok()
            .zip(std::path::absolute(&private).ok())
            .is_some_and(|(left, right)| left == right)
    {
        return usage();
    }
    for (path, restricted) in [(&public, false), (&private, true)] {
        if crate::host::management::validate_ancestry(path, restricted).is_err()
            || !matches!(
                std::fs::symlink_metadata(path),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound
            )
        {
            eprintln!("recipient output path is occupied or unsafe");
            return ExitCode::from(7);
        }
    }
    let (recipient, key) = match crate::backup::recipient::create_interactive() {
        Ok(pair) => pair,
        Err(error) => {
            let code = match error {
                crate::backup::recipient::Error::Entropy
                | crate::backup::recipient::Error::MemoryProtection => 5,
                _ => 2,
            };
            eprintln!("recipient creation failed with code {code}");
            return ExitCode::from(code);
        }
    };
    let public_bytes = match recipient.json() {
        Ok(bytes) => bytes,
        Err(_) => return ExitCode::from(6),
    };
    let mut encrypted = key.into_encoded();
    if crate::backup::publication::publish_secret(&private, &mut encrypted).is_err() {
        eprintln!("recipient private output could not be durably published");
        return ExitCode::from(7);
    }
    if crate::host::publication::publish_rotation_certificate(&public, &public_bytes).is_err() {
        eprintln!("recipient private output retained; public output publication failed");
        return ExitCode::from(7);
    }
    ExitCode::SUCCESS
}

fn parse_change_password(arguments: Vec<OsString>) -> Result<PathBuf, ()> {
    let mut arguments = arguments.into_iter();
    if arguments.next().as_deref() != Some("change-password".as_ref())
        || arguments.next().as_deref() != Some("--private-key-file".as_ref())
    {
        return Err(());
    }
    let path = arguments.next().map(PathBuf::from).ok_or(())?;
    if arguments.next().is_some() {
        return Err(());
    }
    Ok(path)
}

fn failure(error: password::Error) -> ExitCode {
    let code = match error {
        password::Error::InvalidInput
        | password::Error::InvalidReplacement
        | password::Error::Terminal => 2,
        password::Error::WrongPassword => 3,
        password::Error::Entropy | password::Error::MemoryProtection => 5,
        password::Error::Publication(_) => 7,
    };
    eprintln!("recipient password change failed with code {code}");
    ExitCode::from(code)
}

fn usage() -> ExitCode {
    eprintln!(
        "Usage: kes-forge recipient create --public-key-file FILE --private-key-file FILE\n       kes-forge recipient change-password --private-key-file FILE"
    );
    ExitCode::from(2)
}
