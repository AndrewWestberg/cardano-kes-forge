use super::*;
use crate::cbor::{Encoder, Value};
use crate::crypto::SUM6_V1;
use crate::journal::codec::*;
use crate::journal::{JournalContext, JournalError, JournalScope, ObjectBinding, SnapshotCodec};
use crate::types::EnrolledGenesisHash;

impl SnapshotCodec for PoolCodec {
    type State = PoolRegistration;

    fn encode(
        state: &Self::State,
        context: JournalContext,
        out: &mut [u8],
    ) -> Result<usize, JournalError> {
        validate(state, context)?;
        let mut e = Encoder::new(out);
        e.array(14)?;
        e.uint(1)?;
        e.bytes(state.pool_id.as_bytes())?;
        e.bytes(state.incarnation.as_bytes())?;
        e.bytes(&state.cold_verification_key)?;
        e.array(4)?;
        e.uint(u64::from(state.network.network_magic()))?;
        e.bytes(state.network.genesis_hash().as_bytes())?;
        e.uint(state.network.slots_per_kes_period())?;
        e.uint(u64::from(state.network.max_kes_evolutions()))?;
        e.array(3)?;
        e.bytes(&state.credential_public_key)?;
        e.uint(state.credential_epoch.get())?;
        e.boolean(state.credential_revoked)?;
        e.array(3)?;
        e.bytes(&state.recipient_public_key)?;
        e.bytes(&state.recipient_id)?;
        e.uint(state.recipient_policy_epoch)?;
        encode_replay(&mut e, &state.management_replay)?;
        e.uint(state.revision.get())?;
        e.uint(state.generation_high_water.get())?;
        encode_counter(&mut e, state.certificate_high_water)?;
        encode_generation(&mut e, state.current.as_ref())?;
        encode_generation(&mut e, state.staged.as_ref())?;
        encode_checkpoint(&mut e, state.generation_checkpoint)?;
        let length = e.finish()?.encoded().len();
        if length > Self::MAX_PLAINTEXT_BYTES {
            return Err(JournalError::SizeLimit);
        }
        Ok(length)
    }

    fn decode(input: &[u8], context: JournalContext) -> Result<Self::State, JournalError> {
        if input.len() > Self::MAX_PLAINTEXT_BYTES {
            return Err(JournalError::SizeLimit);
        }
        let mut p = array(Value::parse(input)?, 14)?;
        expect(&mut p, 1)?;
        let pool_id = PoolId::from_bytes(fixed(&mut p)?);
        let incarnation = IncarnationId::from_bytes(fixed(&mut p)?);
        let cold_verification_key = fixed(&mut p)?;
        let mut n = array(next(&mut p)?, 4)?;
        let magic = u32::try_from(uint(&mut n)?).map_err(|_| StateError::InvalidObject)?;
        let genesis = EnrolledGenesisHash::from_bytes(fixed(&mut n)?);
        let slots = uint(&mut n)?;
        let lifetime = uint(&mut n)?;
        let network = NetworkBinding::from_enrolled_digest(magic, genesis, slots, lifetime)
            .map_err(|_| StateError::InvalidObject)?;
        let mut c = array(next(&mut p)?, 3)?;
        let credential_public_key = fixed(&mut c)?;
        let credential_epoch = CredentialEpoch::new(uint(&mut c)?);
        let credential_revoked = next(&mut c)?.boolean()?;
        let mut r = array(next(&mut p)?, 3)?;
        let recipient_public_key = fixed(&mut r)?;
        let recipient_id = fixed(&mut r)?;
        let recipient_policy_epoch = uint(&mut r)?;
        let management_replay = decode_replay(next(&mut p)?)?;
        let revision = Revision::new(uint(&mut p)?);
        let generation_high_water = GenerationNumber::new(uint(&mut p)?);
        let certificate_high_water = decode_counter(next(&mut p)?)?;
        let current = decode_generation(next(&mut p)?)?;
        let staged = decode_generation(next(&mut p)?)?;
        let generation_checkpoint = decode_checkpoint(next(&mut p)?)?;
        let state = PoolRegistration {
            pool_id,
            incarnation,
            cold_verification_key,
            network,
            credential_public_key,
            credential_epoch,
            credential_revoked,
            recipient_public_key,
            recipient_id,
            recipient_policy_epoch,
            management_replay,
            revision,
            generation_high_water,
            certificate_high_water,
            current,
            staged,
            generation_checkpoint,
        };
        validate(&state, context)?;
        Ok(state)
    }

    fn revision(state: &Self::State) -> Revision {
        state.revision
    }
    fn set_recovery_revision(state: &mut Self::State, revision: Revision) {
        state.revision = revision;
    }
    fn objects(state: &Self::State) -> [Option<ObjectBinding>; 2] {
        let binding = |g: &KESGeneration| ObjectBinding {
            reference: g.public_object,
            verification_key: g.verification_key,
            backup_digest: g.backup_digest,
        };
        [
            state.current.as_ref().map(binding),
            state.staged.as_ref().map(binding),
        ]
    }
    fn private_keys(state: &mut Self::State) -> [Option<&mut KesKey>; 2] {
        [
            state.current.as_mut().map(|g| &mut g.secret.key),
            state.staged.as_mut().map(|g| &mut g.secret.key),
        ]
    }
}

fn validate(state: &PoolRegistration, context: JournalContext) -> Result<(), JournalError> {
    match context.scope {
        JournalScope::Pool {
            pool, incarnation, ..
        } if pool == state.pool_id && incarnation == state.incarnation => {}
        _ => return Err(JournalError::InvalidContext),
    }
    if PoolId::from_cold_verification_key(&state.cold_verification_key) != state.pool_id {
        return Err(StateError::InvalidPoolId.into());
    }
    let recipient: [u8; 32] = Sha256::digest(state.recipient_public_key).into();
    if recipient != state.recipient_id {
        return Err(StateError::InvalidRecipient.into());
    }
    if replay_revision(&state.management_replay) > state.revision {
        return Err(StateError::RevisionConflict.into());
    }
    validate_checkpoint(state)?;
    if let Some(current) = &state.current {
        validate_generation(state, current, false)?;
        if current
            .certificate
            .as_ref()
            .map(OperationalCertificate::counter)
            != state.certificate_high_water
        {
            return Err(StateError::CertificateConflict.into());
        }
    }
    if let Some(staged) = &state.staged {
        validate_generation(state, staged, true)?;
        if staged.number != state.generation_high_water {
            return Err(StateError::GenerationConflict.into());
        }
        if let Some(intent) = staged.activation_intent {
            let current = state.current.as_ref().ok_or(StateError::InvalidLifecycle)?;
            let certificate = staged
                .certificate
                .as_ref()
                .ok_or(StateError::InvalidLifecycle)?;
            let window = LifetimeWindow::new(certificate.start_period(), staged.lifetime)
                .map_err(StateError::from)?;
            if staged.lifecycle != Lifecycle::CertifiedStaged
                || intent.target_generation != staged.id
                || intent.certificate_digest != *certificate.digest()
                || intent.expected_active_generation != current.id
                || intent.committed_revision > state.revision
                || window
                    .relative_period(intent.activation_absolute_period)
                    .is_err()
            {
                return Err(StateError::InvalidLifecycle.into());
            }
        }
        if let Some(current) = &state.current
            && (staged.number <= current.number
                || staged.id == current.id
                || staged.creation_request == current.creation_request)
        {
            return Err(StateError::GenerationConflict.into());
        }
    }
    Ok(())
}

fn validate_generation(
    state: &PoolRegistration,
    g: &KESGeneration,
    staged: bool,
) -> Result<(), JournalError> {
    if g.pool != state.pool_id || g.incarnation != state.incarnation {
        return Err(StateError::InvalidObject.into());
    }
    if g.number.get() == 0 || g.number > state.generation_high_water {
        return Err(StateError::GenerationConflict.into());
    }
    if g.lifetime.get() != state.network.max_kes_evolutions()
        || g.relative_period.get() >= g.lifetime.get()
    {
        return Err(StateError::InvalidSecret.into());
    }
    if g.public_object.version != 1
        || g.public_object.generation != g.id
        || !(4105..=6144).contains(&usize::from(g.public_object.total_length))
    {
        return Err(StateError::InvalidObject.into());
    }
    let valid_lifecycle = if staged {
        matches!(g.lifecycle, Lifecycle::Staged | Lifecycle::CertifiedStaged)
    } else {
        matches!(g.lifecycle, Lifecycle::Active | Lifecycle::CurrentExpired)
    };
    if !valid_lifecycle || (staged && g.relative_period.get() != 0) {
        return Err(StateError::InvalidLifecycle.into());
    }
    if g.secret.is_erased() {
        if g.lifecycle != Lifecycle::CurrentExpired {
            return Err(StateError::InvalidSecret.into());
        }
    } else {
        if g.lifecycle == Lifecycle::CurrentExpired
            || g.secret.key.period().map_err(StateError::from)? != g.relative_period
            || g.secret.key.lifetime() != g.lifetime
            || g.secret.key.verification_key().map_err(StateError::from)? != g.verification_key
        {
            return Err(StateError::InvalidSecret.into());
        }
        g.secret.key.canonical_state().map_err(StateError::from)?;
    }
    match &g.certificate {
        None if g.lifecycle == Lifecycle::Staged => {}
        Some(certificate) if g.lifecycle != Lifecycle::Staged => {
            certificate
                .validate_bound(CertificateContext {
                    pool: state.pool_id,
                    cold_verification_key: &state.cold_verification_key,
                    kes_verification_key: &g.verification_key,
                    enrolled_network: &state.network,
                    request_network: &state.network,
                    lifetime: g.lifetime,
                    last_activated_counter: if staged {
                        state.certificate_high_water
                    } else {
                        None
                    },
                })
                .map_err(StateError::from)?;
        }
        _ => return Err(StateError::InvalidLifecycle.into()),
    }
    Ok(())
}

fn encode_generation(
    e: &mut Encoder<'_>,
    generation: Option<&KESGeneration>,
) -> Result<(), JournalError> {
    let Some(g) = generation else {
        e.null()?;
        return Ok(());
    };
    e.array(18)?;
    e.uint(1)?;
    e.uint(1)?;
    e.bytes(g.id.as_bytes())?;
    e.uint(g.number.get())?;
    e.bytes(g.creation_request.as_bytes())?;
    e.bytes(&g.creation_payload_digest)?;
    e.bytes(g.pool.as_bytes())?;
    e.bytes(g.incarnation.as_bytes())?;
    e.bytes(&g.verification_key)?;
    e.uint(u64::from(g.lifetime.get()))?;
    e.uint(u64::from(g.relative_period.get()))?;
    if let Some(key) = g.secret.key() {
        e.bytes(key.canonical_state().map_err(StateError::from)?.bytes())?;
    } else {
        e.null()?;
    }
    e.uint(match g.lifecycle {
        Lifecycle::Staged => 0,
        Lifecycle::CertifiedStaged => 1,
        Lifecycle::Active => 2,
        Lifecycle::CurrentExpired => 3,
        Lifecycle::Retired => return Err(StateError::InvalidLifecycle.into()),
    })?;
    e.array(4)?;
    e.uint(u64::from(g.public_object.version))?;
    e.bytes(g.public_object.generation.as_bytes())?;
    e.uint(u64::from(g.public_object.total_length))?;
    e.bytes(&g.public_object.digest)?;
    e.bytes(&g.backup_digest)?;
    e.bytes(&g.recipient_id)?;
    match &g.certificate {
        Some(certificate) => e.bytes(certificate.canonical_bytes())?,
        None => e.null()?,
    }
    encode_activation_intent(e, g.activation_intent.as_ref())?;
    Ok(())
}

fn decode_generation(value: Value<'_>) -> Result<Option<KESGeneration>, JournalError> {
    if value.is_null() {
        return Ok(None);
    }
    let mut p = array(value, 18)?;
    expect(&mut p, 1)?;
    expect(&mut p, 1)?;
    let id = GenerationId::from_bytes(fixed(&mut p)?);
    let number = GenerationNumber::new(uint(&mut p)?);
    let creation_request = RequestId::from_bytes(fixed(&mut p)?);
    let creation_payload_digest = fixed(&mut p)?;
    let pool = PoolId::from_bytes(fixed(&mut p)?);
    let incarnation = IncarnationId::from_bytes(fixed(&mut p)?);
    let verification_key = fixed(&mut p)?;
    let lifetime = KesLifetime::new(uint(&mut p)?).map_err(|_| StateError::InvalidSecret)?;
    let relative_period =
        RelativePeriod::new(uint(&mut p)?).map_err(|_| StateError::InvalidSecret)?;
    let secret_value = next(&mut p)?;
    let key = if secret_value.is_null() {
        KesKey::erased(lifetime)
    } else {
        KesKey::from_canonical(SUM6_V1, secret_value.bytes()?, relative_period, lifetime)
            .map_err(StateError::from)?
    };
    let secret = GenerationSecret { key };
    let lifecycle = match uint(&mut p)? {
        0 => Lifecycle::Staged,
        1 => Lifecycle::CertifiedStaged,
        2 => Lifecycle::Active,
        3 => Lifecycle::CurrentExpired,
        _ => return Err(StateError::InvalidLifecycle.into()),
    };
    let mut object = array(next(&mut p)?, 4)?;
    let version = u16::try_from(uint(&mut object)?).map_err(|_| StateError::InvalidObject)?;
    let generation = GenerationId::from_bytes(fixed(&mut object)?);
    let total_length = u16::try_from(uint(&mut object)?).map_err(|_| StateError::InvalidObject)?;
    let digest = fixed(&mut object)?;
    let public_object = PublicObjectRef {
        version,
        generation,
        total_length,
        digest,
    };
    let backup_digest = fixed(&mut p)?;
    let recipient_id = fixed(&mut p)?;
    let certificate_value = next(&mut p)?;
    let certificate = if certificate_value.is_null() {
        None
    } else {
        Some(
            OperationalCertificate::decode_and_verify(certificate_value.bytes()?)
                .map_err(StateError::from)?,
        )
    };
    let activation_intent = decode_activation_intent(next(&mut p)?)?;
    Ok(Some(KESGeneration {
        id,
        number,
        creation_request,
        creation_payload_digest,
        pool,
        incarnation,
        verification_key,
        lifetime,
        relative_period,
        secret,
        lifecycle,
        public_object,
        backup_digest,
        recipient_id,
        certificate,
        activation_intent,
    }))
}

fn encode_activation_intent(
    e: &mut Encoder<'_>,
    intent: Option<&ActivationIntent>,
) -> Result<(), JournalError> {
    let Some(intent) = intent else {
        e.uint(0)?;
        return Ok(());
    };
    e.array(7)?;
    e.uint(1)?;
    e.bytes(intent.target_generation.as_bytes())?;
    e.bytes(&intent.certificate_digest)?;
    e.uint(intent.activation_absolute_period.get())?;
    e.bytes(intent.creation_request.as_bytes())?;
    e.bytes(intent.expected_active_generation.as_bytes())?;
    e.uint(intent.committed_revision.get())?;
    Ok(())
}

fn decode_activation_intent(value: Value<'_>) -> Result<Option<ActivationIntent>, JournalError> {
    if value.uint() == Ok(0) {
        return Ok(None);
    }
    let mut p = array(value, 7)?;
    expect(&mut p, 1)?;
    Ok(Some(ActivationIntent {
        target_generation: GenerationId::from_bytes(fixed(&mut p)?),
        certificate_digest: fixed(&mut p)?,
        activation_absolute_period: AbsolutePeriod::new(uint(&mut p)?),
        creation_request: RequestId::from_bytes(fixed(&mut p)?),
        expected_active_generation: GenerationId::from_bytes(fixed(&mut p)?),
        committed_revision: Revision::new(uint(&mut p)?),
    }))
}

fn encode_checkpoint(
    e: &mut Encoder<'_>,
    checkpoint: Option<crate::generation::GenerationCheckpoint>,
) -> Result<(), JournalError> {
    use crate::generation::CheckpointOutcome;
    let Some(c) = checkpoint else {
        e.null()?;
        return Ok(());
    };
    e.array(12)?;
    e.bytes(c.request.as_bytes())?;
    e.bytes(&c.payload_digest)?;
    e.bytes(c.generation.as_bytes())?;
    e.uint(c.generation_number.get())?;
    e.uint(match c.outcome {
        CheckpointOutcome::InProgress => 0,
        CheckpointOutcome::NotCommitted => 1,
        CheckpointOutcome::Committed => 2,
    })?;
    e.uint(c.expected_revision.get())?;
    e.bytes(c.policy.pool.as_bytes())?;
    e.bytes(c.policy.incarnation.as_bytes())?;
    e.bytes(&c.policy.recipient_id)?;
    e.uint(c.policy.recipient_policy_epoch)?;
    e.uint(c.policy.credential_epoch.get())?;
    e.uint(c.attempt)?;
    Ok(())
}

fn decode_checkpoint(
    value: Value<'_>,
) -> Result<Option<crate::generation::GenerationCheckpoint>, JournalError> {
    use crate::generation::{CheckpointOutcome, GenerationCheckpoint};
    if value.is_null() {
        return Ok(None);
    }
    let mut c = array(value, 12)?;
    let request = RequestId::from_bytes(fixed(&mut c)?);
    let payload_digest = fixed(&mut c)?;
    let generation = GenerationId::from_bytes(fixed(&mut c)?);
    let generation_number = GenerationNumber::new(uint(&mut c)?);
    let outcome = match uint(&mut c)? {
        0 => CheckpointOutcome::InProgress,
        1 => CheckpointOutcome::NotCommitted,
        2 => CheckpointOutcome::Committed,
        _ => return Err(StateError::GenerationConflict.into()),
    };
    let expected_revision = Revision::new(uint(&mut c)?);
    let policy = GenerationPolicy {
        pool: PoolId::from_bytes(fixed(&mut c)?),
        incarnation: IncarnationId::from_bytes(fixed(&mut c)?),
        recipient_id: fixed(&mut c)?,
        recipient_policy_epoch: uint(&mut c)?,
        credential_epoch: CredentialEpoch::new(uint(&mut c)?),
    };
    let attempt = uint(&mut c)?;
    Ok(Some(GenerationCheckpoint {
        request,
        payload_digest,
        generation,
        generation_number,
        outcome,
        expected_revision,
        policy,
        attempt,
    }))
}

fn validate_checkpoint(state: &PoolRegistration) -> Result<(), JournalError> {
    use crate::generation::CheckpointOutcome;
    let Some(c) = state.generation_checkpoint else {
        return Ok(());
    };
    if c.policy.pool != state.pool_id
        || c.policy.incarnation != state.incarnation
        || c.policy.credential_epoch > state.credential_epoch
        || c.policy.recipient_policy_epoch > state.recipient_policy_epoch
        || (c.policy.recipient_policy_epoch == state.recipient_policy_epoch
            && c.policy.recipient_id != state.recipient_id)
        || c.expected_revision >= state.revision
        || c.generation_number.get() == 0
    {
        return Err(StateError::GenerationConflict.into());
    }
    let retained = [state.current.as_ref(), state.staged.as_ref()]
        .into_iter()
        .flatten()
        .find(|g| {
            g.id == c.generation
                || g.number == c.generation_number
                || g.creation_request == c.request
        });
    match c.outcome {
        CheckpointOutcome::Committed => {
            if c.generation_number > state.generation_high_water
                || retained.is_some_and(|g| {
                    g.id != c.generation
                        || g.number != c.generation_number
                        || g.creation_request != c.request
                        || g.creation_payload_digest != c.payload_digest
                })
            {
                return Err(StateError::GenerationConflict.into());
            }
        }
        CheckpointOutcome::InProgress | CheckpointOutcome::NotCommitted => {
            let next_number = state
                .generation_high_water
                .checked_increment()
                .map_err(|_| StateError::CounterOverflow)?;
            if c.generation_number != next_number
                || retained.is_some()
                || (c.outcome == CheckpointOutcome::InProgress
                    && (c.policy != state.generation_policy()
                        || state.credential_revoked
                        || state.staged.is_some()))
            {
                return Err(StateError::GenerationConflict.into());
            }
        }
    }
    Ok(())
}
