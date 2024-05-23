//! Threshold and non-threshold CGGMP21 DKG
//!
//! This crate provides an implementation of UC-secure DKG protocol taken from [CGGMP21] paper. Implementation is
//! fully `#![no_std]` compatible and WASM-friendly.
//!
//! [CGGMP21]: https://ia.cr/2021/060

#![allow(non_snake_case, clippy::too_many_arguments)]
#![forbid(missing_docs)]
#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

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

use alloc::vec::Vec;

use digest::Digest;
use generic_ec::Curve;
use rand_core::{CryptoRng, RngCore};
use round_based::{Mpc, MsgId, PartyIndex};

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

#[doc = include_str!("../docs/mpc_message.md")]
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
    _params: core::marker::PhantomData<(E, L, D)>,
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
            hd_enabled: true,
            _params: core::marker::PhantomData,
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
            _params: core::marker::PhantomData,
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
            _params: core::marker::PhantomData,
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
            _params: core::marker::PhantomData,
        }
    }

    /// Sets a tracer that tracks progress of protocol execution
    pub fn set_progress_tracer(mut self, tracer: &'a mut dyn Tracer) -> Self {
        self.tracer = Some(tracer);
        self
    }

    #[doc = include_str!("../docs/enforce_reliable_broadcast.md")]
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

    /// Returns a state machine that can be used to carry out the key generation protocol
    ///
    /// See [`round_based::state_machine`] for details on how that can be done.
    #[cfg(feature = "state-machine")]
    pub fn into_state_machine<R>(
        self,
        rng: &'a mut R,
    ) -> impl round_based::state_machine::StateMachine<
        Output = Result<CoreKeyShare<E>, KeygenError>,
        Msg = non_threshold::Msg<E, L, D>,
    > + 'a
    where
        R: RngCore + CryptoRng,
    {
        round_based::state_machine::wrap_protocol(|party| self.start(rng, party))
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

    /// Returns a state machine that can be used to carry out the key generation protocol
    ///
    /// See [`round_based::state_machine`] for details on how that can be done.
    #[cfg(feature = "state-machine")]
    pub fn into_state_machine<R>(
        self,
        rng: &'a mut R,
    ) -> impl round_based::state_machine::StateMachine<
        Output = Result<CoreKeyShare<E>, KeygenError>,
        Msg = threshold::Msg<E, L, D>,
    > + 'a
    where
        R: RngCore + CryptoRng,
    {
        round_based::state_machine::wrap_protocol(|party| self.start(rng, party))
    }
}

/// Keygen protocol error
#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
#[displaydoc("keygen protocol is failed to complete")]
pub struct KeygenError(#[cfg_attr(feature = "std", source)] Reason);

crate::errors::impl_from! {
    impl From for KeygenError {
        err: KeygenAborted => KeygenError(Reason::Aborted(err)),
        err: IoError => KeygenError(Reason::IoError(err)),
        err: Bug => KeygenError(Reason::Bug(err)),
    }
}

#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
enum Reason {
    /// Protocol was maliciously aborted by another party
    #[displaydoc("protocol was aborted by malicious party")]
    Aborted(#[cfg_attr(feature = "std", source)] KeygenAborted),
    #[displaydoc("i/o error")]
    IoError(#[cfg_attr(feature = "std", source)] IoError),
    /// Bug occurred
    #[displaydoc("bug occurred")]
    Bug(Bug),
}

impl From<KeygenAborted> for Reason {
    fn from(err: KeygenAborted) -> Self {
        Reason::Aborted(err)
    }
}

/// Error indicating that protocol was aborted by malicious party
///
/// It _can be_ cryptographically proven, but we do not support it yet.
#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
enum KeygenAborted {
    #[displaydoc("party decommitment doesn't match commitment: {0:?}")]
    InvalidDecommitment(Vec<utils::AbortBlame>),
    #[displaydoc("party provided invalid schnorr proof: {0:?}")]
    InvalidSchnorrProof(Vec<utils::AbortBlame>),
    #[displaydoc("party secret share is not consistent: {parties:?}")]
    FeldmanVerificationFailed { parties: Vec<u16> },
    #[displaydoc("party data size is not suitable for threshold parameters: {parties:?}")]
    InvalidDataSize { parties: Vec<u16> },
    #[displaydoc("round1 wasn't reliable")]
    Round1NotReliable(Vec<(PartyIndex, MsgId)>),
    #[cfg(feature = "hd-wallets")]
    #[displaydoc("party did not generate chain code: {0:?}")]
    MissingChainCode(Vec<utils::AbortBlame>),
}

#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
enum Bug {
    #[displaydoc("resulting key share is not valid")]
    InvalidKeyShare(#[cfg_attr(feature = "std", source)] InvalidCoreShare),
    #[displaydoc("unexpected zero value")]
    NonZeroScalar,
    #[cfg(feature = "hd-wallets")]
    #[displaydoc("chain code is missing although we checked that it should be present")]
    NoChainCode,
    #[displaydoc("key share of one of the signers is zero - probability of that is negligible")]
    ZeroShare,
    #[displaydoc("shared public key is zero - probability of that is negligible")]
    ZeroPk,
}

/// Distributed key generation protocol
///
/// Each party of the protocol should have uniquely assigned index $i$ such that $0 \le i < n$
/// (where $n$ is amount of parties in the protocol).
pub fn keygen<E: Curve>(eid: ExecutionId, i: u16, n: u16) -> KeygenBuilder<E> {
    KeygenBuilder::new(eid, i, n)
}
