#[cfg(feature = "recovery")]
#[test]
fn same_recipient_output_path_is_rejected_before_password_prompt_or_publication() {
    use std::{fs, os::unix::fs::DirBuilderExt, process::Command};
    let directory = std::env::temp_dir().join(format!(
        "kes-recipient-output-collision-{}",
        std::process::id()
    ));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let output = directory.join("recipient.key");
    let result = Command::new(env!("CARGO_BIN_EXE_kes-forge"))
        .arg("recipient")
        .arg("create")
        .arg("--public-key-file")
        .arg(&output)
        .arg("--private-key-file")
        .arg(&output)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(!output.exists());
    fs::remove_dir(directory).unwrap();
}
