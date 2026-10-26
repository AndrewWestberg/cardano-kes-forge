pub mod backup;
pub mod cli;
pub mod host;

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("host tools support Linux x86_64 only");

const PROFILE_COUNT: u8 = cfg!(feature = "primary") as u8
    + cfg!(feature = "recovery") as u8
    + cfg!(feature = "management") as u8
    + cfg!(feature = "provisioning") as u8
    + cfg!(feature = "development") as u8;
const _: () = assert!(
    PROFILE_COUNT == 1,
    "select exactly one installation profile"
);

pub const INSTALLATION_PROFILE: &str = if cfg!(feature = "primary") {
    "primary"
} else if cfg!(feature = "recovery") {
    "recovery"
} else if cfg!(feature = "management") {
    "management"
} else if cfg!(feature = "provisioning") {
    "provisioning"
} else {
    "development"
};

pub fn build_metadata_command(binary: &str) -> std::process::ExitCode {
    let mut args = std::env::args_os().skip(1);
    match (args.next(), args.next()) {
        (Some(arg), None) if arg == "--version" => {
            println!(
                "{binary} {} ({INSTALLATION_PROFILE})",
                env!("CARGO_PKG_VERSION")
            );
            std::process::ExitCode::SUCCESS
        }
        (Some(arg), None) if arg == "--help" => {
            println!(
                "Usage: {binary} --version\n\n--version  Display package version and installation profile"
            );
            std::process::ExitCode::SUCCESS
        }
        _ => {
            eprintln!("Usage: {binary} --version");
            std::process::ExitCode::from(2)
        }
    }
}
