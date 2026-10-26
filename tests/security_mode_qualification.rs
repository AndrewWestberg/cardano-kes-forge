use cardano_kes_forge::host::qualification::{
    ChipRevision, QualificationDecision, QualificationProfile, SecurityObservation, qualify,
};

fn unlocked_a2(mode: &str) -> SecurityObservation<'_> {
    SecurityObservation {
        chip_revision: ChipRevision::A2,
        reported_security_mode: mode,
        secure_boot_enabled: false,
        debug_enabled: true,
        secure_debug_enabled: true,
    }
}

#[test]
fn unlocked_a2_is_accepted_only_for_reversible_development_qualification() {
    assert_eq!(
        qualify(
            unlocked_a2("development"),
            QualificationProfile::ReversibleDevelopment,
        ),
        QualificationDecision::Proceed
    );

    assert_eq!(
        qualify(unlocked_a2("development"), QualificationProfile::Release),
        QualificationDecision::Refuse(
            "release qualification requires A4 silicon, release firmware, secure boot, and locked debug"
        )
    );
}

#[test]
fn development_qualification_refuses_firmware_that_claims_release_mode() {
    assert_eq!(
        qualify(
            unlocked_a2("release-unprovisioned"),
            QualificationProfile::ReversibleDevelopment,
        ),
        QualificationDecision::Refuse(
            "reversible A2 qualification requires firmware reporting development security mode"
        )
    );
}
