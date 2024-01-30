//! Threshold and non-threshold CGGMP21 DKG
#![allow(non_snake_case, clippy::too_many_arguments)]

pub mod progress;
pub mod security_level;

/// Non-threshold DKG specific types
mod non_threshold;
/// Threshold DKG specific types
mod threshold;

mod errors;
mod execution_id;
mod rng;
mod utils;

use digest::Digest;
use generic_ec::Curve;
use rand_core::{CryptoRng, RngCore};
use round_based::{Mpc, MsgId, PartyIndex};
use thiserror::Error;

#[doc(inline)]
pub use key_share;

use crate::progress::Tracer;
use crate::{
    errors::IoError,
    key_share::{CoreKeyShare, InvalidCoreShare},
    security_level::SecurityLevel,
};

pub use self::execution_id::ExecutionId;
#[doc(no_inline)]
pub use self::msg::{non_threshold::Msg as NonThresholdMsg, threshold::Msg as ThresholdMsg};

/// Defines default choice for digest and security level used across the crate
mod default_choice {
    pub type Digest = sha2::Sha256;
    pub type SecurityLevel = crate::security_level::SecurityLevel128;
}

#[doc = include_str!("../../cggmp21/docs/mpc_message.md")]
pub mod msg {
    /// Messages types related to non threshold DKG protocol
    pub mod non_threshold {
        pub use crate::non_threshold::{Msg, MsgReliabilityCheck, MsgRound1, MsgRound2, MsgRound3};
    }
    /// Messages types related to threshold DKG protocol
    pub mod threshold {
        pub use crate::threshold::{
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
    tracer: Option<&'a mut dyn Tracer>,
    #[cfg(feature = "hd-wallets")]
    hd_enabled: bool,
    _params: std::marker::PhantomData<(E, L, D)>,
}

/// Indicates non-threshold DKG
pub struct NonThreshold;
/// Indicates threshold DKG
pub struct WithThreshold(u16);

impl<'a, E, L, D> GenericKeygenBuilder<'a, E, NonThreshold, L, D>
where
    E: Curve,
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
            tracer: None,
            #[cfg(feature = "hd-wallets")]
            hd_enabled: false,
            _params: std::marker::PhantomData,
        }
    }
}

impl<'a, E, L, D, M> GenericKeygenBuilder<'a, E, M, L, D>
where
    E: Curve,
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
            tracer: self.tracer,
            #[cfg(feature = "hd-wallets")]
            hd_enabled: self.hd_enabled,
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
            tracer: self.tracer,
            #[cfg(feature = "hd-wallets")]
            hd_enabled: self.hd_enabled,
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
            tracer: self.tracer,
            #[cfg(feature = "hd-wallets")]
            hd_enabled: self.hd_enabled,
            _params: std::marker::PhantomData,
        }
    }

    /// Sets a tracer that tracks progress of protocol execution
    pub fn set_progress_tracer(mut self, tracer: &'a mut dyn Tracer) -> Self {
        self.tracer = Some(tracer);
        self
    }

    #[doc = include_str!("../../cggmp21/docs/enforce_reliable_broadcast.md")]
    pub fn enforce_reliable_broadcast(self, enforce: bool) -> Self {
        Self {
            reliable_broadcast_enforced: enforce,
            ..self
        }
    }

    #[cfg(feature = "hd-wallets")]
    /// Specifies whether HD derivation is enabled for a key
    pub fn hd_wallet(mut self, v: bool) -> Self {
        self.hd_enabled = v;
        self
    }
}

impl<'a, E, L, D> GenericKeygenBuilder<'a, E, NonThreshold, L, D>
where
    E: Curve,
    L: SecurityLevel,
    D: Digest + Clone + 'static,
{
    /// Starts key generation
    pub async fn start<R, M>(self, rng: &mut R, party: M) -> Result<CoreKeyShare<E>, KeygenError>
    where
        R: RngCore + CryptoRng,
        M: Mpc<ProtocolMessage = non_threshold::Msg<E, L, D>>,
    {
        non_threshold::run_keygen(
            self.tracer,
            self.i,
            self.n,
            self.reliable_broadcast_enforced,
            self.execution_id,
            rng,
            party,
            #[cfg(feature = "hd-wallets")]
            self.hd_enabled,
        )
        .await
    }
}

impl<'a, E, L, D> GenericKeygenBuilder<'a, E, WithThreshold, L, D>
where
    E: Curve,
    L: SecurityLevel,
    D: Digest + Clone + 'static,
{
    /// Starts threshold key generation
    pub async fn start<R, M>(self, rng: &mut R, party: M) -> Result<CoreKeyShare<E>, KeygenError>
    where
        R: RngCore + CryptoRng,
        M: Mpc<ProtocolMessage = threshold::Msg<E, L, D>>,
    {
        threshold::run_threshold_keygen(
            self.tracer,
            self.i,
            self.optional_t.0,
            self.n,
            self.reliable_broadcast_enforced,
            self.execution_id,
            rng,
            party,
            #[cfg(feature = "hd-wallets")]
            self.hd_enabled,
        )
        .await
    }
}

/// Keygen protocol error
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
    #[error("party decommitment doesn't match commitment: {0:?}")]
    InvalidDecommitment(Vec<utils::AbortBlame>),
    #[error("party provided invalid schnorr proof: {0:?}")]
    InvalidSchnorrProof(Vec<utils::AbortBlame>),
    #[error("party secret share is not consistent: {parties:?}")]
    FeldmanVerificationFailed { parties: Vec<u16> },
    #[error("party data size is not suitable for threshold parameters: {parties:?}")]
    InvalidDataSize { parties: Vec<u16> },
    #[error("round1 wasn't reliable")]
    Round1NotReliable(Vec<(PartyIndex, MsgId)>),
    #[cfg(feature = "hd-wallets")]
    #[error("party did not generate chain code: {0:?}")]
    MissingChainCode(Vec<utils::AbortBlame>),
}

#[derive(Debug, Error)]
enum Bug {
    #[error("resulting key share is not valid")]
    InvalidKeyShare(#[source] InvalidCoreShare),
    #[error("unexpected zero value")]
    NonZeroScalar,
    #[cfg(feature = "hd-wallets")]
    #[error("chain code is missing although we checked that it should be present")]
    NoChainCode,
}

/// Distributed key generation protocol
///
/// Each party of the protocol should have uniquely assigned index $i$ such that $0 \le i < n$
/// (where $n$ is amount of parties in the protocol).
pub fn keygen<E: Curve>(eid: ExecutionId, i: u16, n: u16) -> KeygenBuilder<E> {
    KeygenBuilder::new(eid, i, n)
}
