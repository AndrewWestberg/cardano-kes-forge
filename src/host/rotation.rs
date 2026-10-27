//! Device-authoritative public rotation state for one daemon pool route.
//! Staging/certification never changes the active signing descriptor.
use std::path::{Path, PathBuf};

/// Stable public handoff path consumed by a running native forging context.
/// The generation identifier prevents an unpublished or old certificate from
/// replacing the active certificate.
pub fn certificate_path(
    socket_path: &Path,
    connection_name: &str,
    generation: [u8; 16],
) -> PathBuf {
    let parent = socket_path.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!(
        ".kes-forge-{connection_name}-{}.operational-certificate.cbor",
        hex(&generation)
    ))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 15)] as char);
    }
    output
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Descriptor {
    pub generation: [u8; 16],
    pub generation_number: u64,
    pub verification_key: [u8; 32],
    pub certificate_digest: Option<[u8; 32]>,
    pub certificate_start: Option<u64>,
    pub revision: u64,
    pub relative_period: u64,
    pub lifecycle: String,
    pub health: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Intent {
    pub target_generation: [u8; 16],
    pub certificate_digest: [u8; 32],
    pub activation_absolute_period: u64,
    pub creation_request: [u8; 16],
    pub expected_active_generation: [u8; 16],
    pub committed_revision: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    StaleRevision,
    InvalidDescriptor,
    ContextMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct View<'a> {
    pub authoritative: bool,
    pub revision: Option<u64>,
    pub active: Option<&'a Descriptor>,
    pub staged: Option<&'a Descriptor>,
    pub intent: Option<&'a Intent>,
}

#[derive(Clone, Default)]
pub(crate) struct Cache {
    revision: Option<u64>,
    active: Option<Descriptor>,
    staged: Option<Descriptor>,
    intent: Option<Intent>,
    authoritative: bool,
}

impl Cache {
    pub(crate) fn mark_unreconciled(&mut self) {
        self.authoritative = false;
    }

    pub(crate) fn reconcile_status(
        &mut self,
        revision: u64,
        active: Option<Descriptor>,
        staged: Option<Descriptor>,
    ) -> Result<(), Error> {
        self.require_revision(revision)?;
        if active
            .as_ref()
            .is_some_and(|value| !active_lifecycle(value) || value.revision != revision)
            || staged
                .as_ref()
                .is_some_and(|value| !staged_lifecycle(value) || value.revision != revision)
        {
            return Err(Error::InvalidDescriptor);
        }
        if let (Some(active), Some(staged)) = (active.as_ref(), staged.as_ref())
            && active.generation == staged.generation
        {
            return Err(Error::ContextMismatch);
        }
        let intent = self.intent.take().filter(|intent| {
            active
                .as_ref()
                .is_some_and(|value| value.generation == intent.expected_active_generation)
                && staged
                    .as_ref()
                    .is_some_and(|value| value.generation == intent.target_generation)
                && revision >= intent.committed_revision
        });
        self.revision = Some(revision);
        self.active = active;
        self.staged = staged;
        self.intent = intent;
        self.authoritative = true;
        Ok(())
    }

    pub(crate) fn record_certified(&mut self, descriptor: Descriptor) -> Result<(), Error> {
        self.require_revision(descriptor.revision)?;
        if descriptor.lifecycle != "certified-staged"
            || descriptor.certificate_digest.is_none()
            || descriptor.certificate_start.is_none()
            || self
                .active
                .as_ref()
                .is_some_and(|active| active.generation == descriptor.generation)
        {
            return Err(Error::InvalidDescriptor);
        }
        self.revision = Some(descriptor.revision);
        self.staged = Some(descriptor);
        self.intent = None;
        self.authoritative = true;
        Ok(())
    }

    pub(crate) fn record_schedule(
        &mut self,
        descriptor: Descriptor,
        intent: Intent,
    ) -> Result<(), Error> {
        self.require_revision(descriptor.revision)?;
        if descriptor.lifecycle != "certified-staged"
            || descriptor.certificate_digest != Some(intent.certificate_digest)
            || descriptor.generation != intent.target_generation
            || descriptor.revision != intent.committed_revision
            || self
                .active
                .as_ref()
                .is_none_or(|active| active.generation != intent.expected_active_generation)
        {
            return Err(Error::ContextMismatch);
        }
        self.revision = Some(descriptor.revision);
        self.staged = Some(descriptor);
        self.intent = Some(intent);
        self.authoritative = true;
        Ok(())
    }

    pub(crate) fn record_active(&mut self, descriptor: Descriptor) -> Result<(), Error> {
        self.require_revision(descriptor.revision)?;
        if !active_lifecycle(&descriptor) {
            return Err(Error::InvalidDescriptor);
        }
        let activated_target = self
            .intent
            .as_ref()
            .is_some_and(|intent| intent.target_generation == descriptor.generation);
        if activated_target
            || self
                .active
                .as_ref()
                .is_some_and(|active| active.generation != descriptor.generation)
        {
            self.staged = None;
            self.intent = None;
        }
        self.revision = Some(descriptor.revision);
        self.active = Some(descriptor);
        self.authoritative = true;
        Ok(())
    }

    pub(crate) fn view(&self) -> View<'_> {
        View {
            authoritative: self.authoritative,
            revision: self.revision,
            active: self.active.as_ref(),
            staged: self.staged.as_ref(),
            intent: self.intent.as_ref(),
        }
    }

    fn require_revision(&self, revision: u64) -> Result<(), Error> {
        if self.revision.is_some_and(|current| revision < current) {
            Err(Error::StaleRevision)
        } else {
            Ok(())
        }
    }
}

fn active_lifecycle(descriptor: &Descriptor) -> bool {
    descriptor.certificate_digest.is_some()
        && descriptor.certificate_start.is_some()
        && matches!(descriptor.lifecycle.as_str(), "active" | "expired")
}

fn staged_lifecycle(descriptor: &Descriptor) -> bool {
    matches!(descriptor.lifecycle.as_str(), "staged" | "certified-staged")
}

#[cfg(test)]
mod tests {
    #[test]
    fn certificate_handoff_path_is_generation_scoped() {
        assert_eq!(
            certificate_path(
                Path::new("/run/cardano-kes-forge/device.sock"),
                "pool-0",
                [5; 16],
            ),
            PathBuf::from(
                "/run/cardano-kes-forge/.kes-forge-pool-0-05050505050505050505050505050505.operational-certificate.cbor"
            )
        );
    }

    use super::*;

    fn descriptor(generation: u8, revision: u64, lifecycle: &str) -> Descriptor {
        Descriptor {
            generation: [generation; 16],
            generation_number: u64::from(generation),
            verification_key: [generation; 32],
            certificate_digest: (lifecycle != "staged").then_some([generation; 32]),
            certificate_start: (lifecycle != "staged").then_some(100),
            revision,
            relative_period: 0,
            lifecycle: lifecycle.into(),
            health: "healthy".into(),
        }
    }

    #[test]
    fn staging_and_scheduling_never_replace_active_context() {
        let mut cache = Cache::default();
        cache
            .reconcile_status(3, Some(descriptor(1, 3, "active")), None)
            .unwrap();
        cache
            .record_certified(descriptor(2, 4, "certified-staged"))
            .unwrap();
        assert_eq!(cache.view().active.unwrap().generation, [1; 16]);
        cache
            .record_schedule(
                descriptor(2, 5, "certified-staged"),
                Intent {
                    target_generation: [2; 16],
                    certificate_digest: [2; 32],
                    activation_absolute_period: 112,
                    creation_request: [9; 16],
                    expected_active_generation: [1; 16],
                    committed_revision: 5,
                },
            )
            .unwrap();
        assert_eq!(cache.view().active.unwrap().generation, [1; 16]);
        assert_eq!(cache.view().intent.unwrap().target_generation, [2; 16]);
    }

    #[test]
    fn device_status_wins_and_lost_activation_ack_is_reconciled() {
        let mut cache = Cache::default();
        cache
            .reconcile_status(
                5,
                Some(descriptor(1, 5, "active")),
                Some(descriptor(2, 5, "certified-staged")),
            )
            .unwrap();
        cache
            .record_schedule(
                descriptor(2, 6, "certified-staged"),
                Intent {
                    target_generation: [2; 16],
                    certificate_digest: [2; 32],
                    activation_absolute_period: 112,
                    creation_request: [9; 16],
                    expected_active_generation: [1; 16],
                    committed_revision: 6,
                },
            )
            .unwrap();
        cache.mark_unreconciled();
        assert!(!cache.view().authoritative);
        cache
            .reconcile_status(7, Some(descriptor(2, 7, "active")), None)
            .unwrap();
        let view = cache.view();
        assert!(view.authoritative);
        assert_eq!(view.active.unwrap().generation, [2; 16]);
        assert!(view.staged.is_none());
        assert!(view.intent.is_none());
        assert_eq!(
            cache.reconcile_status(6, Some(descriptor(1, 6, "active")), None),
            Err(Error::StaleRevision)
        );
    }
}
