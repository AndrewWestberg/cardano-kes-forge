//! Exact-message signing after any required forward evolution is durably clean.

use crate::{
    activation::{DurablePool, EvolutionRequest, OperationContext, OperationError},
    certificate::CertificateError,
    crypto::{CryptoError, VerifiedPublicTree, verify},
    journal::{Flash, Journal, PoolCodec, Workspaces},
    state::{Actor, Lifecycle, StateError},
    types::{AbsolutePeriod, GenerationId, NetworkBinding},
};
use kes_summed_ed25519_adapted::SIGNATURE_BYTES;
use rand_chacha::rand_core::TryCryptoRng;
use sha2::{Digest, Sha256};

pub struct SigningRequest<'a> {
    pub actor: Actor,
    pub generation: GenerationId,
    pub certificate_digest: [u8; 32],
    pub absolute_period: AbsolutePeriod,
    pub network: &'a NetworkBinding,
    pub message: &'a [u8],
}

pub struct SigningResult {
    pub context: OperationContext,
    pub signature: [u8; SIGNATURE_BYTES],
    pub message_digest: [u8; 32],
}

impl DurablePool {
    pub fn sign<F: Flash, R: TryCryptoRng>(
        &mut self,
        journal: &Journal<PoolCodec>,
        flash: &mut F,
        rng: &mut R,
        work: &mut Workspaces<'_>,
        request: SigningRequest<'_>,
        tree: &VerifiedPublicTree<'_>,
    ) -> Result<SigningResult, OperationError> {
        let revision = self.state()?.revision();
        let evolved = self.evolve(
            journal,
            flash,
            rng,
            work,
            EvolutionRequest {
                actor: request.actor,
                expected_revision: revision,
                generation: request.generation,
                certificate_digest: request.certificate_digest,
                target_absolute_period: request.absolute_period,
                network: request.network,
            },
            tree,
        )?;
        let context = evolved.context;
        if context.lifecycle == Lifecycle::CurrentExpired {
            return Err(OperationError::State(StateError::Certificate(
                CertificateError::Expired,
            )));
        }
        let mut signature = [0; SIGNATURE_BYTES];
        let result = {
            let generation = self.current_generation(request.generation)?;
            let key = generation
                .secret()
                .key()
                .ok_or(OperationError::State(StateError::InvalidSecret))?;
            key.sign_into(context.relative_period, request.message, &mut signature)
                .map_err(OperationError::from)
                .and_then(|()| {
                    verify(
                        generation.verification_key(),
                        context.relative_period,
                        generation.lifetime(),
                        request.message,
                        &signature,
                    )
                    .map_err(|_| OperationError::SelfVerification)
                })
        };
        if let Err(error) = result {
            if invalidates(&error) {
                self.invalidate();
            }
            return Err(error);
        }
        Ok(SigningResult {
            context,
            signature,
            message_digest: Sha256::digest(request.message).into(),
        })
    }
}

impl From<CryptoError> for OperationError {
    fn from(error: CryptoError) -> Self {
        Self::State(StateError::Crypto(error))
    }
}

fn invalidates(error: &OperationError) -> bool {
    matches!(
        error,
        OperationError::SelfVerification
            | OperationError::State(StateError::InvalidSecret)
            | OperationError::State(StateError::Crypto(CryptoError::ErasedKey))
            | OperationError::State(StateError::Crypto(CryptoError::MalformedState))
            | OperationError::State(StateError::Crypto(CryptoError::InvalidPublicTree))
            | OperationError::State(StateError::Crypto(CryptoError::TreeMismatch))
            | OperationError::State(StateError::Crypto(CryptoError::PeriodMismatch))
    )
}
