use crate::backup::password;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

pub fn run(arguments: Vec<OsString>) -> ExitCode {
    let path = match parse_change_password(arguments) {
        Ok(path) => path,
        Err(()) => return usage(),
    };
    match password::change_password_interactive(&path) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => failure(error),
    }
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
    eprintln!("Usage: kes-forge recipient change-password --private-key-file FILE");
    ExitCode::from(2)
}
