use cardano_kes_forge::host::{config::DaemonConfig, daemon::Daemon, usb::UsbWire};
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    match (arguments.next(), arguments.next(), arguments.next()) {
        (Some(option), None, None) if option == "--version" => {
            println!(
                "kes-forged {} ({})",
                env!("CARGO_PKG_VERSION"),
                cardano_kes_forge::INSTALLATION_PROFILE
            );
            ExitCode::SUCCESS
        }
        (Some(option), None, None) if option == "--help" => {
            print_help();
            ExitCode::SUCCESS
        }
        (Some(option), Some(path), None) if option == "--config" => run(PathBuf::from(path)),
        _ => usage(),
    }
}

fn run(path: PathBuf) -> ExitCode {
    let config = match DaemonConfig::load(&path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("kes-forged: invalid or unsafe configuration: {error:?}");
            return ExitCode::from(3);
        }
    };
    let wire = match UsbWire::open(&config.usb_device) {
        Ok(wire) => wire,
        Err(error) => {
            eprintln!("kes-forged: {error}");
            return ExitCode::from(4);
        }
    };
    let (daemon, socket_path) = match Daemon::from_static_config(config, wire) {
        Ok(service) => service,
        Err(error) => {
            eprintln!("kes-forged: inconsistent daemon routes: {error:?}");
            return ExitCode::from(3);
        }
    };
    match daemon.serve(&socket_path) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("kes-forged: service failed: {error}");
            ExitCode::from(5)
        }
    }
}

fn usage() -> ExitCode {
    eprintln!("Usage: kes-forged --config FILE");
    ExitCode::from(2)
}

fn print_help() {
    println!(
        "Usage: kes-forged --config FILE\n\n  --config FILE  Load the closed daemon configuration and own its USB device\n  --version      Display package version and installation profile\n  --help         Display this help"
    );
}
