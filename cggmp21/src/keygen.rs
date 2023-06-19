/// Non-threshold DKG specific types
mod non_threshold;
/// Threshold DKG specific types
mod threshold;

use digest::Digest;
use generic_ec::hash_to_curve::FromHash;
use generic_ec::{Curve, Scalar};
use rand_core::{CryptoRng, RngCore};
use round_based::{Mpc, MsgId, PartyIndex};
use thiserror::Error;

use crate::{
    errors::IoError,
    key_share::{IncompleteKeyShare, InvalidKeyShare},
    security_level::SecurityLevel,
    utils::HashMessageError,
    ExecutionId,
};

#[doc(no_inline)]
pub use self::msg::{non_threshold::Msg as NonThresholdMsg, threshold::Msg as ThresholdMsg};

#[doc = include_str!("../docs/mpc_message.md")]
pub mod msg {
    /// Messages types related to non threshold DKG protocol
    pub mod non_threshold {
        pub use crate::keygen::non_threshold::{
            Msg, MsgReliabilityCheck, MsgRound1, MsgRound2, MsgRound3,
        };
    }
    /// Messages types related to threshold DKG protocol
    pub mod threshold {
        pub use crate::keygen::threshold::{
            Msg, MsgReliabilityCheck, MsgRound1, MsgRound2Broad, MsgRound2Uni, MsgRound3,
        };
    }
}

/// Key generation entry point. You can call [`set_threshold`] to make it into a
/// threshold DKG
///
/// [`set_threshold`]: GenericKeygenBuilder::set_threshold
pub type KeygenBuilder<
    'a,
    E,
    L = crate::default_choice::SecurityLevel,
    D = crate::default_choice::Digest,
> = GenericKeygenBuilder<'a, E, NonThreshold, L, D>;

/// Threshold keygen builder
pub type ThresholdKeygenBuilder<
    'a,
    E,
    L = crate::default_choice::SecurityLevel,
    D = crate::default_choice::Digest,
> = GenericKeygenBuilder<'a, E, WithThreshold, L, D>;

/// Key generation entry point with choice for threshold or non-threshold
/// variant
pub struct GenericKeygenBuilder<'a, E: Curve, M, L: SecurityLevel, D: Digest> {
    i: u16,
    n: u16,
    reliable_broadcast_enforced: bool,
    optional_t: M,
    execution_id: ExecutionId<'a>,
    _params: std::marker::PhantomData<(E, L, D)>,
}

/// Indicates non-threshold DKG
pub struct NonThreshold;
/// Indicates threshold DKG
pub struct WithThreshold(u16);

impl<'a, E, L, D> GenericKeygenBuilder<'a, E, NonThreshold, L, D>
where
    E: Curve,
    Scalar<E>: FromHash,
    L: SecurityLevel,
    D: Digest + Clone + 'static,
{
    /// Constructs [KeygenBuilder]
    ///
    /// Takes local party index $i$ and number of parties $n$
    pub fn new(eid: ExecutionId<'a>, i: u16, n: u16) -> Self {
        Self {
            i,
            n,
            optional_t: NonThreshold,
            reliable_broadcast_enforced: true,
            execution_id: eid,
            _params: std::marker::PhantomData,
        }
    }
}

impl<'a, E, L, D, M> GenericKeygenBuilder<'a, E, M, L, D>
where
    E: Curve,
    Scalar<E>: FromHash,
    L: SecurityLevel,
    D: Digest + Clone + 'static,
{
    /// Specifies to generate key shares for a threshold scheme
    pub fn set_threshold(self, t: u16) -> GenericKeygenBuilder<'a, E, WithThreshold, L, D> {
        GenericKeygenBuilder {
            i: self.i,
            n: self.n,
            optional_t: WithThreshold(t),
            reliable_broadcast_enforced: self.reliable_broadcast_enforced,
            execution_id: self.execution_id,
            _params: std::marker::PhantomData,
        }
    }
    /// Specifies another hash function to use
    pub fn set_digest<D2>(self) -> GenericKeygenBuilder<'a, E, M, L, D2>
    where
        D2: Digest + Clone + 'static,
    {
        GenericKeygenBuilder {
            i: self.i,
            n: self.n,
            optional_t: self.optional_t,
            reliable_broadcast_enforced: self.reliable_broadcast_enforced,
            execution_id: self.execution_id,
            _params: std::marker::PhantomData,
        }
    }

    /// Specifies [security level](crate::security_level)
    pub fn set_security_level<L2>(self) -> GenericKeygenBuilder<'a, E, M, L2, D>
    where
        L2: SecurityLevel,
    {
        GenericKeygenBuilder {
            i: self.i,
            n: self.n,
            optional_t: self.optional_t,
            reliable_broadcast_enforced: self.reliable_broadcast_enforced,
            execution_id: self.execution_id,
            _params: std::marker::PhantomData,
        }
    }

    #[doc = include_str!("../docs/enforce_reliable_broadcast.md")]
    pub fn enforce_reliable_broadcast(self, enforce: bool) -> Self {
        Self {
            reliable_broadcast_enforced: enforce,
            ..self
        }
    }
}

impl<'a, E, L, D> GenericKeygenBuilder<'a, E, NonThreshold, L, D>
where
    E: Curve,
    Scalar<E>: FromHash,
    L: SecurityLevel,
    D: Digest + Clone + 'static,
{
    /// Starts key generation
    pub async fn start<R, M>(
        self,
        rng: &mut R,
        party: M,
    ) -> Result<IncompleteKeyShare<E>, KeygenError>
    where
        R: RngCore + CryptoRng,
        M: Mpc<ProtocolMessage = non_threshold::Msg<E, L, D>>,
    {
        non_threshold::run_keygen(
            self.i,
            self.n,
            self.reliable_broadcast_enforced,
            self.execution_id,
            rng,
            party,
        )
        .await
    }
}

impl<'a, E, L, D> GenericKeygenBuilder<'a, E, WithThreshold, L, D>
where
    E: Curve,
    Scalar<E>: FromHash,
    L: SecurityLevel,
    D: Digest + Clone + 'static,
{
    /// Starts threshold key generation
    pub async fn start<R, M>(
        self,
        rng: &mut R,
        party: M,
    ) -> Result<IncompleteKeyShare<E>, KeygenError>
    where
        R: RngCore + CryptoRng,
        M: Mpc<ProtocolMessage = threshold::Msg<E, L, D>>,
    {
        threshold::run_threshold_keygen(
            self.i,
            self.optional_t.0,
            self.n,
            self.reliable_broadcast_enforced,
            self.execution_id,
            rng,
            party,
        )
        .await
    }
}

#[derive(Debug, Error)]
#[error("keygen protocol is failed to complete")]
pub struct KeygenError(#[source] Reason);

crate::errors::impl_from! {
    impl From for KeygenError {
        err: KeygenAborted => KeygenError(Reason::Aborted(err)),
        err: IoError => KeygenError(Reason::IoError(err)),
        err: Bug => KeygenError(Reason::Bug(err)),
    }
}

#[derive(Debug, Error)]
enum Reason {
    /// Protocol was maliciously aborted by another party
    #[error("protocol was aborted by malicious party")]
    Aborted(
        #[source]
        #[from]
        KeygenAborted,
    ),
    #[error("i/o error")]
    IoError(#[source] IoError),
    /// Bug occurred
    #[error("bug occurred")]
    Bug(Bug),
}

/// Error indicating that protocol was aborted by malicious party
///
/// It _can be_ cryptographically proven, but we do not support it yet.
#[derive(Debug, Error)]
enum KeygenAborted {
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
    #[error("unexpected zero value")]
    NonZeroScalar,
}
