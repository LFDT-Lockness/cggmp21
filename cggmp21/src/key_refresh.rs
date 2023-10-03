//! Key refresh & aux info generation protocols

/// Auxiliary info (re)generation protocol specific types
mod aux_only;
/// Non-threshold key refresh specific types
mod non_threshold;

use digest::Digest;
use generic_ec::Curve;
use rand_core::{CryptoRng, RngCore};
use round_based::Mpc;
use thiserror::Error;

use crate::{
    errors::IoError,
    key_share::{AnyKeyShare, AuxInfo, DirtyIncompleteKeyShare, KeyShare},
    progress::Tracer,
    security_level::SecurityLevel,
    utils::AbortBlame,
    ExecutionId,
};
use crate::{fast_paillier, rug::Integer};

#[doc(no_inline)]
pub use self::msg::{aux_only::Msg as AuxOnlyMsg, non_threshold::Msg as NonThresholdMsg};

#[doc = include_str!("../docs/mpc_message.md")]
pub mod msg {
    /// Messages types related to aux information generation protocol
    pub mod aux_only {
        pub use crate::key_refresh::aux_only::{
            Msg, MsgReliabilityCheck, MsgRound1, MsgRound2, MsgRound3,
        };
    }
    /// Messages types related to non threshold key refresh protocol
    pub mod non_threshold {
        pub use crate::key_refresh::non_threshold::{
            Msg, MsgReliabilityCheck, MsgRound1, MsgRound2, MsgRound3,
        };
    }
}

/// To speed up computations, it's possible to supply data to the algorithm
/// generated ahead of time
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PregeneratedPrimes<L = crate::default_choice::SecurityLevel> {
    p: Integer,
    q: Integer,
    _phantom: std::marker::PhantomData<L>,
}

impl<L: SecurityLevel> PregeneratedPrimes<L> {
    /// Constructs pregenerated primes from two big numbers
    ///
    /// Returns `None` if big numbers are smaller than 4 * [L::SECURITY_BITS](SecurityLevel::SECURITY_BITS)
    ///
    /// Function doesn't validate that provided numbers are primes. If they're not,
    /// key refresh protocol should fail with some ZK proof error.
    pub fn new(p: Integer, q: Integer) -> Option<Self> {
        if !crate::security_level::validate_secret_paillier_key_size::<L>(&p, &q) {
            None
        } else {
            Some(Self {
                p,
                q,
                _phantom: std::marker::PhantomData,
            })
        }
    }

    /// Returns `p, q`
    pub fn split(self) -> (Integer, Integer) {
        (self.p, self.q)
    }

    /// Generates primes. Takes some time.
    pub fn generate<R: RngCore>(rng: &mut R) -> Self {
        Self {
            p: fast_paillier::utils::generate_safe_prime(rng, 4 * L::SECURITY_BITS),
            q: fast_paillier::utils::generate_safe_prime(rng, 4 * L::SECURITY_BITS),
            _phantom: std::marker::PhantomData,
        }
    }
}

/// A variant of [`GenericKeyRefreshBuilder`] that performs key refresh
pub type KeyRefreshBuilder<
    'a,
    E,
    L = crate::default_choice::SecurityLevel,
    D = crate::default_choice::Digest,
> = GenericKeyRefreshBuilder<'a, RefreshShare<'a, E>, L, D>;

/// A variant of [`GenericKeyRefreshBuilder`] that only generates auxiliary info
/// and doesn't require key shares
pub type AuxInfoGenerationBuilder<
    'a,
    L = crate::default_choice::SecurityLevel,
    D = crate::default_choice::Digest,
> = GenericKeyRefreshBuilder<'a, AuxOnly, L, D>;

/// Entry point for key refresh and auxiliary info generation.
pub struct GenericKeyRefreshBuilder<'a, M, L, D>
where
    L: SecurityLevel,
    D: Digest,
{
    target: M,
    execution_id: ExecutionId<'a>,
    pregenerated: PregeneratedPrimes<L>,
    tracer: Option<&'a mut dyn Tracer>,
    enforce_reliable_broadcast: bool,
    precompute_multiexp_tables: bool,
    precompute_crt: bool,
    _digest: std::marker::PhantomData<D>,
}

/// A marker for [`KeyRefreshBuilder`]
pub struct RefreshShare<'a, E: Curve>(&'a DirtyIncompleteKeyShare<E>);
/// A marker for [`AuxInfoGenerationBuilder`]
pub struct AuxOnly {
    i: u16,
    n: u16,
}

impl<'a, E, L, D> KeyRefreshBuilder<'a, E, L, D>
where
    E: Curve,
    L: SecurityLevel,
    D: Digest,
{
    /// Build key refresh operation. Start it with [`start`](Self::start).
    ///
    /// PregeneratedPrimes can be obtained with [`PregeneratedPrimes::generate`]
    pub fn new(
        eid: ExecutionId<'a>,
        key_share: &'a impl AnyKeyShare<E>,
        pregenerated: PregeneratedPrimes<L>,
    ) -> Self {
        Self {
            target: RefreshShare(key_share.core()),
            execution_id: eid,
            pregenerated,
            tracer: None,
            enforce_reliable_broadcast: true,
            precompute_multiexp_tables: false,
            precompute_crt: false,
            _digest: std::marker::PhantomData,
        }
    }

    /// Carry out the refresh procedure. Takes a lot of time
    pub async fn start<R, M>(self, rng: &mut R, party: M) -> Result<KeyShare<E, L>, KeyRefreshError>
    where
        R: RngCore + CryptoRng,
        M: Mpc<ProtocolMessage = NonThresholdMsg<E, D, L>>,
        E: Curve,
        L: SecurityLevel,
        D: Digest<OutputSize = digest::typenum::U32> + Clone + 'static,
    {
        non_threshold::run_refresh(
            rng,
            party,
            self.execution_id,
            self.pregenerated,
            self.tracer,
            self.enforce_reliable_broadcast,
            self.precompute_multiexp_tables,
            self.precompute_crt,
            self.target.0,
        )
        .await
    }
}

impl<'a, L, D> AuxInfoGenerationBuilder<'a, L, D>
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
            target: AuxOnly { i, n },
            execution_id: eid,
            pregenerated,
            tracer: None,
            enforce_reliable_broadcast: true,
            precompute_multiexp_tables: false,
            precompute_crt: false,
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
            self.target.i,
            self.target.n,
            rng,
            party,
            self.execution_id,
            self.pregenerated,
            self.tracer,
            self.enforce_reliable_broadcast,
            self.precompute_multiexp_tables,
            self.precompute_crt,
        )
        .await
    }
}

impl<'a, L, D, T> GenericKeyRefreshBuilder<'a, T, L, D>
where
    L: SecurityLevel,
    D: Digest,
{
    /// Specifies another hash function to use
    pub fn set_digest<D2: Digest>(self) -> GenericKeyRefreshBuilder<'a, T, L, D2> {
        GenericKeyRefreshBuilder {
            target: self.target,
            execution_id: self.execution_id,
            pregenerated: self.pregenerated,
            tracer: self.tracer,
            enforce_reliable_broadcast: self.enforce_reliable_broadcast,
            precompute_multiexp_tables: self.precompute_multiexp_tables,
            precompute_crt: self.precompute_crt,
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

    /// Precomputes CRT parameters
    ///
    /// Enables optimization of modular exponentiation in Zero-Knowledge proofs validation. Precomputation
    /// should be relatively fast. It increases size of key share in RAM and on disk, but not noticeably.
    ///
    /// Note: CRT parameters contain secret information. Leaking them exposes secret Paillier key. Keep
    /// [`AuxInfo::parties`](DirtyAuxInfo::parties) secret (as well as rest of the key share).
    pub fn precompute_crt(mut self, v: bool) -> Self {
        self.precompute_crt = v;
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
    #[error("Unexpected error when creating paillier decryption key")]
    PaillierKeyError,
    #[error("paillier enctyption failed")]
    PaillierEnc,
    #[error("Attempting to run protocol with too many parties")]
    TooManyParties,
    #[error("Invalid key share geenrated")]
    InvalidShareGenerated(#[source] crate::key_share::InvalidKeyShare),
    #[error("couldn't prove a pi mod statement")]
    PiMod(#[source] paillier_zk::Error),
    #[error("couldn't prove a pi fac statement")]
    PiFac(#[source] paillier_zk::Error),
    #[error("powmod not defined")]
    PowMod,
    #[error("couldn't prove prm statement")]
    PiPrm(#[source] crate::zk::ring_pedersen_parameters::ZkError),
    #[error("couldn't hash a message")]
    HashMessage(#[source] crate::utils::HashMessageError),
    #[error("spawned blocking routine panicked")]
    SpawnBlocking(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("couldn't build multiexp tables")]
    BuildMultiexpTables(#[source] crate::key_share::InvalidKeyShare),
    #[error("couldn't build CRT")]
    BuildCrt,
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
    #[error("provided invalid schnorr proof")]
    InvalidSchnorrProof,
    #[error("provided invalid proof for Rmod")]
    InvalidModProof,
    #[error("provided invalid proof for Rfac")]
    InvalidFacProof,
    #[error("N, s and t parameters are invalid")]
    InvalidRingPedersenParameters,
    #[error("X is malformed")]
    InvalidX,
    #[error("x doesn't correspond to X")]
    InvalidXShare,
    #[error("party sent a message with missing data")]
    InvalidDataSize,
    #[error("party message could not be decrypted")]
    PaillierDec,
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
    make_factory!(invalid_schnorr_proof, InvalidSchnorrProof);
    make_factory!(invalid_mod_proof, InvalidModProof);
    make_factory!(invalid_fac_proof, InvalidFacProof);
    make_factory!(
        invalid_ring_pedersen_parameters,
        InvalidRingPedersenParameters
    );
    make_factory!(invalid_x, InvalidX);
    make_factory!(invalid_x_share, InvalidXShare);
    make_factory!(invalid_data_size, InvalidDataSize);
    make_factory!(paillier_dec, PaillierDec);
    make_factory!(round1_not_reliable, Round1NotReliable);
}
