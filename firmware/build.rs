use std::{env, fs, path::PathBuf};

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let linker_script = if env::var_os("CARGO_FEATURE_A2_DEVELOPMENT").is_some() {
        "memory-a2-development.x"
    } else if env::var_os("CARGO_FEATURE_USB_PREFLIGHT").is_some()
        || env::var_os("CARGO_FEATURE_A2_ENTROPY_DIAGNOSTIC").is_some()
    {
        "memory-preflight.x"
    } else {
        "memory.x"
    };
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("build output"));
    fs::copy(manifest.join(linker_script), output.join("memory.x"))
        .expect("copy selected firmware memory layout");

    println!("cargo:rustc-link-search={}", output.display());
    println!("cargo:rustc-link-arg-bin=kes-firmware=-Tlink.x");
    println!("cargo:rustc-link-arg-bin=kes-usb-preflight=-Tlink.x");
    println!("cargo:rustc-link-arg-bin=kes-a2-development=-Tlink.x");
    println!("cargo:rustc-link-arg-bin=kes-a2-identity-initialize=-Tlink.x");
    println!("cargo:rustc-link-arg-bin=kes-a2-entropy-diagnostic=-Tlink.x");
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed=memory-preflight.x");
    println!("cargo:rerun-if-changed=memory-a2-development.x");
}
