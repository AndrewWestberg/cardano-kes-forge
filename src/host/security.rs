use ed25519_dalek::{Signature, Verifier, VerifyingKey};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Development,
    ReleaseUnprovisioned,
    ReleaseReady,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    DevelopmentOptInRequired,
    UnsupportedSilicon,
    NotReady,
    StaleChallenge,
    ReplayedChallenge,
    InvalidBootNonce,
    PinMismatch,
    Authentication,
    ReleaseDowngrade,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pins {
    pub device: [u8; 16],
    pub identity_public_key: [u8; 32],
    pub silicon_revision: u16,
    pub rom_revision: String,
    pub flash_part: String,
    pub flash_capacity_bytes: u64,
    pub firmware_digest: [u8; 32],
    pub hardware_policy_digest: [u8; 32],
    pub security_version: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnlineEvidence {
    pub mode: Mode,
    pub challenge: [u8; 32],
    pub boot_nonce: [u8; 32],
    pub device: [u8; 16],
    pub silicon_revision: u16,
    pub rom_revision: String,
    pub flash_part: String,
    pub flash_capacity_bytes: u64,
    pub firmware_digest: [u8; 32],
    pub hardware_policy_digest: [u8; 32],
    pub security_version: u64,
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedOnlineEvidence {
    evidence: OnlineEvidence,
}

impl VerifiedOnlineEvidence {
    pub const fn evidence(&self) -> &OnlineEvidence {
        &self.evidence
    }
}

pub struct ReadinessVerifier {
    consumed_challenges: [[u8; 32]; 64],
    challenge_count: usize,
    next_challenge: usize,
}

impl Default for ReadinessVerifier {
    fn default() -> Self {
        Self {
            consumed_challenges: [[0; 32]; 64],
            challenge_count: 0,
            next_challenge: 0,
        }
    }
}

impl ReadinessVerifier {
    pub fn verify(
        &mut self,
        pins: &Pins,
        expected_challenge: [u8; 32],
        evidence: OnlineEvidence,
        allow_development: bool,
    ) -> Result<VerifiedOnlineEvidence, Error> {
        if self.consumed_challenges[..self.challenge_count].contains(&expected_challenge) {
            return Err(Error::ReplayedChallenge);
        }
        let verified = verify_online(pins, expected_challenge, evidence, allow_development)?;
        self.consumed_challenges[self.next_challenge] = expected_challenge;
        self.next_challenge = (self.next_challenge + 1) % self.consumed_challenges.len();
        self.challenge_count = self
            .challenge_count
            .saturating_add(1)
            .min(self.consumed_challenges.len());
        Ok(verified)
    }
}

fn verify_online(
    pins: &Pins,
    expected_challenge: [u8; 32],
    evidence: OnlineEvidence,
    allow_development: bool,
) -> Result<VerifiedOnlineEvidence, Error> {
    if evidence.challenge != expected_challenge {
        return Err(Error::StaleChallenge);
    }
    if evidence.boot_nonce == [0; 32] {
        return Err(Error::InvalidBootNonce);
    }
    let key =
        VerifyingKey::from_bytes(&pins.identity_public_key).map_err(|_| Error::Authentication)?;
    key.verify(
        &evidence_message(&evidence),
        &Signature::from_bytes(&evidence.signature),
    )
    .map_err(|_| Error::Authentication)?;
    if evidence.device != pins.device
        || evidence.silicon_revision != pins.silicon_revision
        || evidence.rom_revision != pins.rom_revision
        || evidence.flash_part != pins.flash_part
        || evidence.flash_capacity_bytes != pins.flash_capacity_bytes
    {
        return Err(Error::PinMismatch);
    }
    match evidence.mode {
        Mode::Development => {
            if !allow_development {
                return Err(Error::DevelopmentOptInRequired);
            }
            if evidence.silicon_revision != 2 && evidence.silicon_revision < 4 {
                return Err(Error::UnsupportedSilicon);
            }
        }
        Mode::ReleaseUnprovisioned => return Err(Error::NotReady),
        Mode::ReleaseReady => {
            if evidence.silicon_revision < 4 {
                return Err(Error::UnsupportedSilicon);
            }
            if evidence.firmware_digest != pins.firmware_digest
                || evidence.hardware_policy_digest != pins.hardware_policy_digest
                || evidence.security_version != pins.security_version
            {
                return Err(Error::PinMismatch);
            }
        }
    }
    Ok(VerifiedOnlineEvidence { evidence })
}

pub fn validate_transition(previous: Mode, next: Mode) -> Result<(), Error> {
    if matches!(previous, Mode::ReleaseUnprovisioned | Mode::ReleaseReady)
        && next == Mode::Development
    {
        Err(Error::ReleaseDowngrade)
    } else {
        Ok(())
    }
}

pub fn evidence_message(evidence: &OnlineEvidence) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(192 + evidence.rom_revision.len() + evidence.flash_part.len());
    message.extend_from_slice(b"cardano-kes-forge/online-security/v1");
    message.push(match evidence.mode {
        Mode::Development => 0,
        Mode::ReleaseUnprovisioned => 1,
        Mode::ReleaseReady => 2,
    });
    message.extend_from_slice(&evidence.challenge);
    message.extend_from_slice(&evidence.boot_nonce);
    message.extend_from_slice(&evidence.device);
    message.extend_from_slice(&evidence.silicon_revision.to_be_bytes());
    append_text(&mut message, &evidence.rom_revision);
    append_text(&mut message, &evidence.flash_part);
    message.extend_from_slice(&evidence.flash_capacity_bytes.to_be_bytes());
    message.extend_from_slice(&evidence.firmware_digest);
    message.extend_from_slice(&evidence.hardware_policy_digest);
    message.extend_from_slice(&evidence.security_version.to_be_bytes());
    message
}

fn append_text(output: &mut Vec<u8>, text: &str) {
    output.extend_from_slice(&(text.len() as u16).to_be_bytes());
    output.extend_from_slice(text.as_bytes());
}
