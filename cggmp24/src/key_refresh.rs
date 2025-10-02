//! Key refresh & aux info generation protocols

/// Auxiliary info (re)generation protocol specific types
mod aux_only;

use digest::Digest;
use rand_core::{CryptoRng, RngCore};
use round_based::Mpc;
use thiserror::Error;

use crate::backend::Integer;
use crate::utils;
use crate::{
    errors::IoError, key_share::AuxInfo, progress::Tracer, security_level::SecurityLevel,
    utils::AbortBlame, ExecutionId,
};

#[doc(no_inline)]
pub use self::msg::Msg;

#[doc = include_str!("../docs/mpc_message.md")]
pub mod msg {
    pub use crate::key_refresh::aux_only::{
        Msg, MsgReliabilityCheck, MsgRound1, MsgRound2, MsgRound3,
    };
}

/// To speed up computations, it's possible to supply data to the algorithm
/// generated ahead of time
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PregeneratedPrimes<L = crate::default_choice::SecurityLevel> {
    primes: [Integer; 4],
    _phantom: std::marker::PhantomData<L>,
}

impl<L: SecurityLevel> TryFrom<[Integer; 4]> for PregeneratedPrimes<L> {
    type Error = [Integer; 4];

    /// Constructs pregenerated primes from 4 big numbers
    ///
    /// Returns `None` if big numbers are smaller than required by security level
    ///
    /// Function doesn't validate that provided numbers are primes. If they're not,
    /// key refresh protocol should fail with some ZK proof error.
    fn try_from(primes: [Integer; 4]) -> Result<Self, Self::Error> {
        if primes
            .iter()
            .any(|p| !crate::security_level::validate_secret_paillier_prime_size::<L>(p))
        {
            Err(primes)
        } else {
            Ok(Self {
                primes,
                _phantom: std::marker::PhantomData,
            })
        }
    }
}

impl<L: SecurityLevel> PregeneratedPrimes<L> {
    /// Returns stored primes
    pub fn into_primes(self) -> [Integer; 4] {
        self.primes
    }

    /// Returns a reference to stored primes
    pub fn primes_ref(&self) -> &[Integer; 4] {
        &self.primes
    }

    /// Generates primes. Takes some time.
    pub fn generate<R: RngCore>(rng: &mut R) -> Self {
        Self {
            primes: [(); 4].map(|_| Integer::generate_safe_prime(rng, L::RSA_PRIME_BITLEN)),
            _phantom: std::marker::PhantomData,
        }
    }
}

/// Entry point for key refresh and auxiliary info generation.
pub struct AuxInfoBuilder<'a, L, D = crate::default_choice::Digest>
where
    L: SecurityLevel,
    D: Digest,
{
    i: u16,
    n: u16,
    execution_id: ExecutionId<'a>,
    pregenerated: PregeneratedPrimes<L>,
    tracer: Option<&'a mut dyn Tracer>,
    enforce_reliable_broadcast: bool,
    precompute_multiexp_tables: bool,
    _digest: std::marker::PhantomData<D>,
}

impl<'a, L, D> AuxInfoBuilder<'a, L, D>
where
    L: SecurityLevel,
    D: Digest,
{
    /// Build key aux info generation operation. Start it with [`start`](Self::start).
    ///
    /// PregeneratedPrimes can be obtained with [`PregeneratedPrimes::generate`]
    pub fn new_aux_gen(
        eid: ExecutionId<'a>,
        i: u16,
        n: u16,
        pregenerated: PregeneratedPrimes<L>,
    ) -> Self {
        Self {
            i,
            n,
            execution_id: eid,
            pregenerated,
            tracer: None,
            enforce_reliable_broadcast: true,
            precompute_multiexp_tables: false,
            _digest: std::marker::PhantomData,
        }
    }

    /// Carry out the aux info generation procedure. Takes a lot of time
    pub async fn start<R, M>(self, rng: &mut R, party: M) -> Result<AuxInfo<L>, KeyRefreshError>
    where
        R: RngCore + CryptoRng,
        M: Mpc<ProtocolMessage = aux_only::Msg<D, L>>,
        L: SecurityLevel,
        D: Digest<OutputSize = digest::typenum::U32> + Clone + 'static,
    {
        aux_only::run_aux_gen(
            self.i,
            self.n,
            rng,
            party,
            self.execution_id,
            self.pregenerated,
            self.tracer,
            self.enforce_reliable_broadcast,
            self.precompute_multiexp_tables,
        )
        .await
    }

    /// Returns a state machine that can be used to carry out the aux info generation protocol
    ///
    /// See [`round_based::state_machine`] for details on how that can be done.
    #[cfg(feature = "state-machine")]
    pub fn into_state_machine<R>(
        self,
        rng: &'a mut R,
    ) -> impl round_based::state_machine::StateMachine<
        Output = Result<AuxInfo<L>, KeyRefreshError>,
        Msg = aux_only::Msg<D, L>,
    > + 'a
    where
        R: RngCore + CryptoRng,
        L: SecurityLevel,
        D: Digest<OutputSize = digest::typenum::U32> + Clone + 'static,
    {
        round_based::state_machine::wrap_protocol(|party| self.start(rng, party))
    }
}

impl<'a, L, D> AuxInfoBuilder<'a, L, D>
where
    L: SecurityLevel,
    D: Digest,
{
    /// Specifies another hash function to use
    pub fn set_digest<D2: Digest>(self) -> AuxInfoBuilder<'a, L, D2> {
        AuxInfoBuilder {
            i: self.i,
            n: self.n,
            execution_id: self.execution_id,
            pregenerated: self.pregenerated,
            tracer: self.tracer,
            enforce_reliable_broadcast: self.enforce_reliable_broadcast,
            precompute_multiexp_tables: self.precompute_multiexp_tables,
            _digest: std::marker::PhantomData,
        }
    }

    /// Sets a tracer that tracks progress of protocol execution
    pub fn set_progress_tracer(mut self, tracer: &'a mut dyn Tracer) -> Self {
        self.tracer = Some(tracer);
        self
    }

    #[doc = include_str!("../docs/enforce_reliable_broadcast.md")]
    pub fn enforce_reliable_broadcast(self, v: bool) -> Self {
        Self {
            enforce_reliable_broadcast: v,
            ..self
        }
    }

    /// Precomputes multiexponentiation tables for output aux data
    ///
    /// Enables optimization that makes signing and presigning faster. Precomputation takes a
    /// while and makes protocol a bit longer. It noticebly increases size of aux data both
    /// in RAM and on disk (after serialization).
    pub fn precompute_multiexp_tables(mut self, v: bool) -> Self {
        self.precompute_multiexp_tables = v;
        self
    }
}

/// Error of key refresh and aux info generation protocols
#[derive(Debug, Error)]
#[error("key refresh protocol failed to complete")]
pub struct KeyRefreshError(#[source] Reason);

crate::errors::impl_from! {
    impl From for KeyRefreshError {
        err: ProtocolAborted => KeyRefreshError(Reason::Aborted(err)),
        err: IoError => KeyRefreshError(Reason::IoError(err)),
        err: Bug => KeyRefreshError(Reason::InternalError(err)),
        err: utils::GenPedersenError => Bug::GenPedersen(err).into(),
    }
}

#[derive(Debug, Error)]
enum Reason {
    /// Protocol was maliciously aborted by another party
    #[error("protocol was aborted by malicious party")]
    Aborted(#[source] ProtocolAborted),
    #[error("i/o error")]
    IoError(#[source] IoError),
    #[error("internal error")]
    InternalError(#[from] Bug),
}

/// Unexpected error in operation not caused by other parties
#[derive(Debug, Error)]
enum Bug {
    #[error("Invalid key share geenrated")]
    InvalidShareGenerated(#[source] crate::key_share::InvalidKeyShare),
    #[error("couldn't prove a pi mod statement")]
    PiMod(#[source] paillier_zk::Error),
    #[error("couldn't prove a pi fac statement")]
    PiFac(#[source] paillier_zk::Error),
    #[error("couldn't prove prm statement")]
    PiPrm(#[source] crate::zk::ring_pedersen_parameters::ZkError),
    #[error("couldn't build multiexp tables")]
    BuildMultiexpTables(#[source] crate::key_share::InvalidKeyShare),
    #[error("generate pedersen params")]
    GenPedersen(#[source] utils::GenPedersenError),
}

/// Error indicating that protocol was aborted by malicious party
///
/// It _can be_ cryptographically proven, but we do not support it yet.
#[derive(Debug, Error)]
#[error("Protocol aborted; malicious parties: {parties:?}; reason: {reason}")]
struct ProtocolAborted {
    pub reason: ProtocolAbortReason,
    pub parties: Vec<AbortBlame>,
}

/// Reason for protocol abort: which exact check has failed
#[derive(Debug, Error)]
enum ProtocolAbortReason {
    #[error("decommitment doesn't match commitment")]
    InvalidDecommitment,
    #[error("provided invalid proof for Rmod")]
    InvalidModProof,
    #[error("provided invalid proof for Rfac")]
    InvalidFacProof,
    #[error("N, s and t parameters are invalid")]
    InvalidRingPedersenParameters,
    #[error("round 1 was not reliable")]
    Round1NotReliable,
}

macro_rules! make_factory {
    ($function:ident, $reason:ident) => {
        fn $function(parties: Vec<AbortBlame>) -> Self {
            Self {
                reason: ProtocolAbortReason::$reason,
                parties,
            }
        }
    };
}
impl ProtocolAborted {
    make_factory!(invalid_decommitment, InvalidDecommitment);
    make_factory!(invalid_mod_proof, InvalidModProof);
    make_factory!(invalid_fac_proof, InvalidFacProof);
    make_factory!(
        invalid_ring_pedersen_parameters,
        InvalidRingPedersenParameters
    );
    make_factory!(round1_not_reliable, Round1NotReliable);
}
