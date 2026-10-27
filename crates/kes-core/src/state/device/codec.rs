use super::*;
use crate::cbor::{Encoder, Value};
use crate::crypto::KesKey;
use crate::journal::codec::*;
use crate::journal::{JournalContext, JournalError, JournalScope, ObjectBinding, SnapshotCodec};
use crate::types::DeviceId;

impl SnapshotCodec for DirectoryCodec {
    type State = DirectorySnapshot;
    fn encode(
        state: &Self::State,
        context: JournalContext,
        out: &mut [u8],
    ) -> Result<usize, JournalError> {
        validate(state, context)?;
        let mut e = Encoder::new(out);
        e.array(9)?;
        e.uint(5)?;
        let c = &state.config;
        e.array(11)?;
        e.bytes(c.identity.device_id().as_bytes())?;
        e.bytes(c.identity.identity_verification_key())?;
        e.bytes(c.identity.provisioning_evidence_digest())?;
        e.uint(u64::from(c.silicon_revision))?;
        e.bytes(&c.firmware_digest)?;
        e.uint(c.security_version)?;
        e.bytes(&c.hardware_policy_digest)?;
        e.uint(match c.mode {
            DeviceMode::Development => 0,
            DeviceMode::Release => 1,
        })?;
        e.uint(match c.health {
            Health::Healthy => 0,
            Health::Damaged => 1,
            Health::Unavailable => 2,
        })?;
        e.bytes(&c.management_root_public_key)?;
        e.bytes(&c.management_transport_public_key)?;
        e.uint(state.revision.get())?;
        if let Some(retirement) = state.retirement {
            e.array(2)?;
            e.uint(retirement.revision.get())?;
            encode_replay(&mut e, &retirement.management_replay)?;
        } else {
            e.null()?;
        }
        e.array(state.live.iter().flatten().count())?;
        for entry in state.live.iter().flatten() {
            e.array(3)?;
            e.uint(entry.slot.get() as u64)?;
            e.bytes(entry.pool_id.as_bytes())?;
            e.bytes(entry.incarnation.as_bytes())?;
        }
        e.array(state.tombstones.iter().flatten().count())?;
        for t in state.tombstones.iter().flatten() {
            e.array(8)?;
            e.bytes(t.pool_id.as_bytes())?;
            e.bytes(t.last_incarnation.as_bytes())?;
            e.uint(t.management_sequence.get())?;
            encode_counter(&mut e, t.certificate_high_water)?;
            e.uint(t.generation_high_water.get())?;
            e.uint(t.deletion_revision.get())?;
            encode_replay(&mut e, &t.management_replay)?;
            if let Some(epoch) = t.credential_epoch {
                e.uint(epoch.get())?;
            } else {
                e.null()?;
            }
        }
        e.array(4)?;
        e.bytes(&state.credential.public_key)?;
        e.uint(state.credential.epoch.get())?;
        e.boolean(state.credential.revoked)?;
        if let Some(replay) = state.credential.management_replay {
            encode_replay(&mut e, &replay)?;
        } else {
            e.null()?;
        }
        if let Some(intent) = state.pending_deletion {
            e.array(4)?;
            e.uint(intent.slot.get() as u64)?;
            e.uint(intent.expected_pool_revision.get())?;
            e.uint(intent.pool_cleanup_revision.get())?;
            let t = intent.tombstone;
            e.array(8)?;
            e.bytes(t.pool_id.as_bytes())?;
            e.bytes(t.last_incarnation.as_bytes())?;
            e.uint(t.management_sequence.get())?;
            encode_counter(&mut e, t.certificate_high_water)?;
            e.uint(t.generation_high_water.get())?;
            e.uint(t.deletion_revision.get())?;
            encode_replay(&mut e, &t.management_replay)?;
            if let Some(epoch) = t.credential_epoch {
                e.uint(epoch.get())?;
            } else {
                e.null()?;
            }
        } else {
            e.null()?;
        }
        if let Some(intent) = state.pending_enrollment {
            let v = intent.enrollment;
            e.array(13)?;
            e.uint(intent.slot.get() as u64)?;
            e.bytes(v.incarnation.as_bytes())?;
            e.bytes(&v.cold_verification_key)?;
            e.uint(u64::from(v.network.network_magic()))?;
            e.bytes(v.network.genesis_hash().as_bytes())?;
            e.uint(v.network.slots_per_kes_period())?;
            e.uint(u64::from(v.network.max_kes_evolutions()))?;
            e.bytes(&v.machine_public_key)?;
            e.bytes(&v.recipient_public_key)?;
            e.bytes(&v.recipient_id)?;
            e.uint(v.management_sequence.get())?;
            e.bytes(v.management_request.as_bytes())?;
            e.bytes(&v.management_payload_digest)?;
        } else {
            e.null()?;
        }
        let length = e.finish()?.encoded().len();
        if length > 7536 {
            return Err(JournalError::SizeLimit);
        }
        Ok(length)
    }
    fn decode(input: &[u8], context: JournalContext) -> Result<Self::State, JournalError> {
        if input.len() > 7536 {
            return Err(JournalError::SizeLimit);
        }
        let mut p = array(Value::parse(input)?, 9)?;
        let version = uint(&mut p)?;
        if version != 4 && version != 5 {
            return Err(StateError::InvalidObject.into());
        }
        let mut c = array(next(&mut p)?, 11)?;
        let device = DeviceId::from_bytes(fixed(&mut c)?);
        let identity_key = fixed(&mut c)?;
        let provisioning = fixed(&mut c)?;
        let silicon_revision =
            u8::try_from(uint(&mut c)?).map_err(|_| StateError::InvalidObject)?;
        let firmware_digest = fixed(&mut c)?;
        let security_version = uint(&mut c)?;
        let hardware_policy_digest = fixed(&mut c)?;
        let mode = match uint(&mut c)? {
            0 => DeviceMode::Development,
            1 => DeviceMode::Release,
            _ => return Err(StateError::InvalidObject.into()),
        };
        let health = match uint(&mut c)? {
            0 => Health::Healthy,
            1 => Health::Damaged,
            2 => Health::Unavailable,
            _ => return Err(StateError::InvalidObject.into()),
        };
        let management_root_public_key = fixed(&mut c)?;
        let management_transport_public_key = fixed(&mut c)?;
        let config = DeviceConfig {
            identity: DeviceIdentityBinding::new(device, identity_key, provisioning),
            silicon_revision,
            firmware_digest,
            security_version,
            hardware_policy_digest,
            mode,
            health,
            management_root_public_key,
            management_transport_public_key,
        };
        let revision = Revision::new(uint(&mut p)?);
        let retirement_value = next(&mut p)?;
        let retirement = if retirement_value.is_null() {
            None
        } else {
            let mut r = array(retirement_value, 2)?;
            Some(DeviceRetirement {
                revision: Revision::new(uint(&mut r)?),
                management_replay: decode_replay(next(&mut r)?)?,
            })
        };
        let mut live = [None; crate::MAX_POOLS];
        let mut entries = next(&mut p)?.array()?;
        for slot in &mut live {
            let Some(value) = entries.next() else {
                break;
            };
            let mut e = array(value, 3)?;
            let index = usize::try_from(uint(&mut e)?).map_err(|_| StateError::InvalidObject)?;
            let hardware_slot = HardwareSlot::new(index).map_err(|_| StateError::InvalidObject)?;
            *slot = Some(DirectoryEntry::new(
                hardware_slot,
                PoolId::from_bytes(fixed(&mut e)?),
                IncarnationId::from_bytes(fixed(&mut e)?),
            ));
        }
        if entries.next().is_some() {
            return Err(StateError::Capacity.into());
        }
        let mut tombstones = [None; DIRECTORY_IDENTITY_CAPACITY];
        let mut entries = next(&mut p)?.array()?;
        for slot in &mut tombstones {
            let Some(value) = entries.next() else {
                break;
            };
            let mut t = array(value, if version == 4 { 7 } else { 8 })?;
            *slot = Some(PoolTombstone {
                pool_id: PoolId::from_bytes(fixed(&mut t)?),
                last_incarnation: IncarnationId::from_bytes(fixed(&mut t)?),
                management_sequence: ManagementSequence::new(uint(&mut t)?),
                certificate_high_water: decode_counter(next(&mut t)?)?,
                generation_high_water: GenerationNumber::new(uint(&mut t)?),
                deletion_revision: Revision::new(uint(&mut t)?),
                management_replay: decode_replay(next(&mut t)?)?,
                credential_epoch: if version == 4 {
                    None
                } else {
                    let value = next(&mut t)?;
                    if value.is_null() {
                        None
                    } else {
                        Some(CredentialEpoch::new(value.uint()?))
                    }
                },
            });
        }
        if entries.next().is_some() {
            return Err(StateError::DirectoryFull.into());
        }
        let mut credential_value = array(next(&mut p)?, 4)?;
        let credential = DeviceCredential {
            public_key: fixed(&mut credential_value)?,
            epoch: CredentialEpoch::new(uint(&mut credential_value)?),
            revoked: next(&mut credential_value)?.boolean()?,
            management_replay: {
                let replay = next(&mut credential_value)?;
                if replay.is_null() {
                    None
                } else {
                    Some(decode_replay(replay)?)
                }
            },
        };
        let pending_value = next(&mut p)?;
        let pending_deletion = if pending_value.is_null() {
            None
        } else {
            let mut intent = array(pending_value, 4)?;
            let slot = usize::try_from(uint(&mut intent)?)
                .map_err(|_| StateError::InvalidObject)
                .and_then(|slot| HardwareSlot::new(slot).map_err(|_| StateError::InvalidObject))?;
            let expected_pool_revision = Revision::new(uint(&mut intent)?);
            let pool_cleanup_revision = Revision::new(uint(&mut intent)?);
            let mut t = array(next(&mut intent)?, if version == 4 { 7 } else { 8 })?;
            Some(DeletionIntent {
                slot,
                expected_pool_revision,
                pool_cleanup_revision,
                tombstone: PoolTombstone {
                    pool_id: PoolId::from_bytes(fixed(&mut t)?),
                    last_incarnation: IncarnationId::from_bytes(fixed(&mut t)?),
                    management_sequence: ManagementSequence::new(uint(&mut t)?),
                    certificate_high_water: decode_counter(next(&mut t)?)?,
                    generation_high_water: GenerationNumber::new(uint(&mut t)?),
                    deletion_revision: Revision::new(uint(&mut t)?),
                    management_replay: decode_replay(next(&mut t)?)?,
                    credential_epoch: if version == 4 {
                        None
                    } else {
                        let value = next(&mut t)?;
                        if value.is_null() {
                            None
                        } else {
                            Some(CredentialEpoch::new(value.uint()?))
                        }
                    },
                },
            })
        };
        let pending_value = next(&mut p)?;
        let pending_enrollment = if pending_value.is_null() {
            None
        } else {
            let mut v = array(pending_value, 13)?;
            let slot = usize::try_from(uint(&mut v)?)
                .map_err(|_| StateError::InvalidObject)
                .and_then(|slot| HardwareSlot::new(slot).map_err(|_| StateError::InvalidObject))?;
            let incarnation = IncarnationId::from_bytes(fixed(&mut v)?);
            let cold_verification_key = fixed(&mut v)?;
            let magic = u32::try_from(uint(&mut v)?).map_err(|_| StateError::InvalidObject)?;
            let digest = crate::types::EnrolledGenesisHash::from_bytes(fixed(&mut v)?);
            let slots = uint(&mut v)?;
            let lifetime = uint(&mut v)?;
            let network =
                crate::types::NetworkBinding::from_enrolled_digest(magic, digest, slots, lifetime)
                    .map_err(|_| StateError::InvalidObject)?;
            let enrollment = super::super::pool::Enrollment {
                incarnation,
                cold_verification_key,
                network,
                machine_public_key: fixed(&mut v)?,
                recipient_public_key: fixed(&mut v)?,
                recipient_id: fixed(&mut v)?,
                management_sequence: ManagementSequence::new(uint(&mut v)?),
                management_request: crate::types::RequestId::from_bytes(fixed(&mut v)?),
                management_payload_digest: fixed(&mut v)?,
            };
            Some(EnrollmentIntent { slot, enrollment })
        };
        let state = DirectorySnapshot {
            config,
            revision,
            retirement,
            credential,
            pending_deletion,
            pending_enrollment,
            live,
            tombstones,
        };
        validate(&state, context)?;
        Ok(state)
    }
    fn revision(state: &Self::State) -> Revision {
        state.revision
    }
    fn set_recovery_revision(state: &mut Self::State, revision: Revision) {
        state.revision = revision;
        if let Some(intent) = state.pending_deletion.as_mut()
            && let Ok(deletion_revision) = revision.checked_increment()
        {
            intent.tombstone.deletion_revision = deletion_revision;
            intent.tombstone.management_replay.result = ManagementResult::Committed {
                revision: deletion_revision,
            };
        }
    }
    fn objects(_: &Self::State) -> [Option<ObjectBinding>; 2] {
        [None, None]
    }
    fn private_keys(_: &mut Self::State) -> [Option<&mut KesKey>; 2] {
        [None, None]
    }
}

fn validate(state: &DirectorySnapshot, context: JournalContext) -> Result<(), JournalError> {
    if context.scope != JournalScope::Directory
        || state.config.identity.device_id() != &context.device
    {
        return Err(JournalError::InvalidContext);
    }
    Device::from_authenticated_snapshot(state)?;
    if let Some(retirement) = &state.retirement
        && replay_revision(&retirement.management_replay) != retirement.revision
    {
        return Err(StateError::RevisionConflict.into());
    }
    for tombstone in state.tombstones.iter().flatten() {
        if replay_revision(&tombstone.management_replay) != tombstone.deletion_revision {
            return Err(StateError::RevisionConflict.into());
        }
    }
    Ok(())
}
