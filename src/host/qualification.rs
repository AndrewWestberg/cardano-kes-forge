//! Host-side gating for destructive and release security qualification.
//!
//! BOOTSEL can recover flash, but it cannot reverse OTP writes. This policy
//! keeps RP2350 A2 testing in the reversible development lane and reserves
//! release qualification for locked A4 hardware.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChipRevision {
    A2,
    A4,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationProfile {
    ReversibleDevelopment,
    Release,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecurityObservation<'a> {
    pub chip_revision: ChipRevision,
    pub reported_security_mode: &'a str,
    pub secure_boot_enabled: bool,
    pub debug_enabled: bool,
    pub secure_debug_enabled: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationDecision {
    Proceed,
    Refuse(&'static str),
}

pub fn qualify(
    observation: SecurityObservation<'_>,
    profile: QualificationProfile,
) -> QualificationDecision {
    match profile {
        QualificationProfile::ReversibleDevelopment => {
            if observation.reported_security_mode != "development" {
                return QualificationDecision::Refuse(
                    "reversible A2 qualification requires firmware reporting development security mode",
                );
            }
            if observation.secure_boot_enabled
                || !observation.debug_enabled
                || !observation.secure_debug_enabled
            {
                return QualificationDecision::Refuse(
                    "reversible development qualification requires unlocked boot and debug recovery",
                );
            }
            QualificationDecision::Proceed
        }
        QualificationProfile::Release => {
            if observation.chip_revision != ChipRevision::A4
                || observation.reported_security_mode != "release-ready"
                || !observation.secure_boot_enabled
                || observation.debug_enabled
                || observation.secure_debug_enabled
            {
                return QualificationDecision::Refuse(
                    "release qualification requires A4 silicon, release firmware, secure boot, and locked debug",
                );
            }
            QualificationDecision::Proceed
        }
    }
}
