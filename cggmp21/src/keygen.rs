mod non_threshold;
mod threshold;

use digest::Digest;
use generic_ec::hash_to_curve::FromHash;
use generic_ec::{Curve, Scalar};
use rand_core::{CryptoRng, RngCore};
use round_based::rounds_router::simple_store::RoundInputError;
use round_based::rounds_router::CompleteRoundError;
use round_based::{Mpc, MsgId, PartyIndex};
use thiserror::Error;

use crate::key_share::{IncompleteKeyShare, InvalidKeyShare, Valid};
use crate::security_level::SecurityLevel;
use crate::utils::HashMessageError;
use crate::ExecutionId;

pub type NonThresholdMsg<E, L, D> = non_threshold::Msg<E, L, D>;
pub type ThresholdMsg<E, L, D> = threshold::Msg<E, L, D>;

/// Key generation entry point
pub struct KeygenBuilder<E: Curve, L: SecurityLevel, D: Digest> {
    i: u16,
    n: u16,
    execution_id: ExecutionId<E, L, D>,
}

impl<E, L, D> KeygenBuilder<E, L, D>
where
    E: Curve,
    Scalar<E>: FromHash,
    L: SecurityLevel,
    D: Digest + Clone + 'static,
{
    /// Constructs [KeygenBuilder]
    ///
    /// Takes local party index $i$ and number of parties $n$
    pub fn new(i: u16, n: u16) -> Self {
        Self {
            i,
            n,
            execution_id: ExecutionId::default(),
        }
    }

    /// Specifies another hash function to use
    ///
    /// _Caution_: this function overwrites [execution ID](Self::set_execution_id). Make sure
    /// you specify execution ID **after** calling this function.
    pub fn set_digest<D2>(self) -> KeygenBuilder<E, L, D2>
    where
        D2: Digest + Clone + 'static,
    {
        KeygenBuilder {
            i: self.i,
            n: self.n,
            execution_id: Default::default(),
        }
    }

    /// Specifies [security level](crate::security_level)
    ///
    /// _Caution_: this function overwrites [execution ID](Self::set_execution_id). Make sure
    /// you specify execution ID **after** calling this function.
    pub fn set_security_level<L2>(self) -> KeygenBuilder<E, L2, D>
    where
        L2: SecurityLevel,
    {
        KeygenBuilder {
            i: self.i,
            n: self.n,
            execution_id: Default::default(),
        }
    }

    /// Specifies [execution ID](ExecutionId)
    pub fn set_execution_id(self, id: ExecutionId<E, L, D>) -> Self {
        Self {
            execution_id: id,
            ..self
        }
    }

    /// Starts key generation
    pub async fn start<R, M>(
        self,
        rng: &mut R,
        party: M,
    ) -> Result<Valid<IncompleteKeyShare<E, L>>, KeygenError<M::ReceiveError, M::SendError>>
    where
        R: RngCore + CryptoRng,
        M: Mpc<ProtocolMessage = non_threshold::Msg<E, L, D>>,
    {
        non_threshold::run_keygen(self.i, self.n, self.execution_id, rng, party).await
    }

    /// Starts threshold DKG
    pub async fn start_thresholdized<R, M>(
        self,
        t: u16,
        rng: &mut R,
        party: M,
    ) -> Result<Valid<IncompleteKeyShare<E, L>>, KeygenError<M::ReceiveError, M::SendError>>
    where
        R: RngCore + CryptoRng,
        M: Mpc<ProtocolMessage = threshold::Msg<E, L, D>>,
    {
        threshold::run_threshold_keygen(self.i, t, self.n, self.execution_id, rng, party).await
    }
}

/// Keygen failed
#[derive(Debug, Error)]
pub enum KeygenError<IErr, OErr> {
    /// Protocol was maliciously aborted by another party
    #[error("protocol was aborted by malicious party")]
    Aborted(
        #[source]
        #[from]
        KeygenAborted,
    ),
    /// Receiving message error
    #[error("receive message")]
    ReceiveMessage(#[source] CompleteRoundError<RoundInputError, IErr>),
    /// Sending message error
    #[error("send message")]
    SendError(#[source] OErr),
    /// Bug occurred
    #[error("bug occurred")]
    Bug(InternalError),
}

/// Error indicating that protocol was aborted by malicious party
///
/// It _can be_ cryptographically proven, but we do not support it yet.
#[derive(Debug, Error)]
pub enum KeygenAborted {
    #[error("party decommitment doesn't match commitment: {parties:?}")]
    InvalidDecommitment { parties: Vec<u16> },
    #[error("party provided invalid schnorr proof: {parties:?}")]
    InvalidSchnorrProof { parties: Vec<u16> },
    #[error("party secret share is not consistent: {parties:?}")]
    FeldmanVerificationFailed { parties: Vec<u16> },
    #[error("party data size is not suitable for threshold parameters: {parties:?}")]
    InvalidDataSize { parties: Vec<u16> },
    #[error("round1 wasn't reliable")]
    Round1NotReliable(Vec<(PartyIndex, MsgId)>),
}

/// Error indicating that internal bug was detected
///
/// Please, report this issue if you encounter it
#[derive(Debug, Error)]
#[error(transparent)]
pub struct InternalError(Bug);

#[derive(Debug, Error)]
enum Bug {
    #[error("hash to scalar returned error")]
    HashToScalarError(#[source] generic_ec::errors::HashError),
    #[error("`Tag` appears to be invalid `generic_ec::hash_to_curve::Tag`")]
    InvalidHashToCurveTag,
    #[error("resulting key share is not valid")]
    InvalidKeyShare(#[source] InvalidKeyShare),
    #[error("hash message")]
    HashMessage(#[source] HashMessageError),
}

impl<IErr, OErr> From<Bug> for KeygenError<IErr, OErr> {
    fn from(err: Bug) -> Self {
        KeygenError::Bug(InternalError(err))
    }
}
