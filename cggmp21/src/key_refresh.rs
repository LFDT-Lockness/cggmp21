use digest::Digest;
use futures::SinkExt;
use generic_ec::{
    hash_to_curve::{self, FromHash},
    Curve, Point, Scalar, SecretScalar,
};
use generic_ec_zkp::{
    hash_commitment::{self, HashCommit},
    schnorr_pok,
};
use paillier_zk::{
    libpaillier, no_small_factor::non_interactive as π_fac, paillier_blum_modulus as π_mod,
    unknown_order::BigNumber,
};
use rand_core::{CryptoRng, RngCore};
use round_based::{
    rounds_router::{simple_store::RoundInput, RoundsRouter},
    Delivery, Mpc, MpcParty, Outgoing, ProtocolMessage,
};
use thiserror::Error;

use crate::{
    execution_id::ProtocolChoice,
    key_share::{IncompleteKeyShare, KeyShare, PartyAux, Valid},
    security_level::SecurityLevel,
    utils,
    utils::{
        but_nth, collect_blame, collect_simple_blame, iter_peers, mine_from, xor_array, AbortBlame,
    },
    zk::ring_pedersen_parameters as π_prm,
    ExecutionId,
};

/// Message of key refresh protocol
#[derive(ProtocolMessage, Clone)]
// 3 kilobytes for the largest option, and 2.5 kilobytes for second largest
#[allow(clippy::large_enum_variant)]
pub enum Msg<E: Curve, D: Digest> {
    Round1(MsgRound1<D>),
    Round2(MsgRound2<E, D>),
    Round3(MsgRound3<E>),
}

/// Message from round 1
#[derive(Clone)]
pub struct MsgRound1<D: Digest> {
    commitment: HashCommit<D>,
}
/// Message from round 2
#[derive(Clone)]
pub struct MsgRound2<E: Curve, D: Digest> {
    /// **X_i** in paper
    x: Vec<Point<E>>,
    /// **A_i** in paper
    sch_commits_a: Vec<schnorr_pok::Commit<E>>,
    Y: Point<E>,
    /// B_i in paper
    sch_commit_b: schnorr_pok::Commit<E>,
    N: BigNumber,
    s: BigNumber,
    t: BigNumber,
    /// psi_circonflexe_i in paper
    // this should be L::M instead, but no rustc support yet
    params_proof: π_prm::Proof<{ π_prm::SECURITY }>,
    /// rho_i in paper
    // ideally it would be [u8; L::SECURITY_BYTES], but no rustc support yet
    rho_bytes: Vec<u8>,
    /// u_i in paper
    decommit: hash_commitment::DecommitNonce<D>,
}
/// Unicast message of round 3, sent to each participant
#[derive(Clone)]
pub struct MsgRound3<E: Curve> {
    /// psi_i in paper
    // this should be L::M instead, but no rustc support yet
    mod_proof: (π_mod::Commitment, π_mod::Proof<{ π_prm::SECURITY }>),
    /// phi_i^j in paper
    fac_proof: π_fac::Proof,
    /// pi_i in paper
    sch_proof_y: schnorr_pok::Proof<E>,
    /// C_i^j in paper
    C: BigNumber,
    /// psi_i_j in paper
    ///
    /// Here in the paper you only send one proof, but later they require you to
    /// verify by all the other proofs, that are never sent. We fix this here
    /// and require each party to send every proof to everyone
    sch_proofs_x: Vec<schnorr_pok::Proof<E>>,
}

/// To speed up computations, it's possible to supply data to the algorithm
/// generated ahead of time
pub struct PregeneratedPrimes {
    p: BigNumber,
    q: BigNumber,
}

impl PregeneratedPrimes {
    /// Generate the structure. Takes some time.
    pub fn generate<L: SecurityLevel, R: RngCore>(rng: &mut R) -> Self {
        Self {
            p: BigNumber::safe_prime_from_rng(4 * L::SECURITY_BITS, rng),
            q: BigNumber::safe_prime_from_rng(4 * L::SECURITY_BITS, rng),
        }
    }
}

pub struct KeyRefreshBuilder<'a, E, L, D>
where
    E: Curve,
    L: SecurityLevel,
    D: Digest,
{
    core_share: &'a IncompleteKeyShare<E, L>,
    execution_id: ExecutionId<E, L, D>,
    pregenerated: Option<PregeneratedPrimes>,
}

impl<'a, E, L, D> KeyRefreshBuilder<'a, E, L, D>
where
    E: Curve,
    L: SecurityLevel,
    D: Digest,
{
    /// Build aux info generating operation. Start it with [`start`]
    pub fn new(core_share: &'a Valid<IncompleteKeyShare<E, L>>) -> Self {
        Self {
            core_share,
            execution_id: Default::default(),
            pregenerated: None,
        }
    }

    /// Build key refresh operation. Start it with [`start`]
    pub fn new_refresh(key_share: &'a Valid<KeyShare<E, L>>) -> Self {
        Self {
            core_share: &key_share.core,
            execution_id: Default::default(),
            pregenerated: None,
        }
    }

    /// Specifies another hash function to use
    ///
    /// _Caution_: this function overwrites [execution ID](Self::set_execution_id). Make sure
    /// you specify execution ID **after** calling this function.
    pub fn set_digest<D2: Digest>(self) -> KeyRefreshBuilder<'a, E, L, D2> {
        KeyRefreshBuilder {
            core_share: self.core_share,
            execution_id: Default::default(),
            pregenerated: None,
        }
    }

    pub fn set_execution_id(self, execution_id: ExecutionId<E, L, D>) -> Self {
        Self {
            execution_id,
            ..self
        }
    }

    pub fn set_pregenerated_data(self, pregenerated: PregeneratedPrimes) -> Self {
        Self {
            pregenerated: Some(pregenerated),
            ..self
        }
    }

    /// Carry out the refresh procedure. Takes a lot of time
    pub async fn start<R, M>(
        self,
        rng: &mut R,
        party: M,
    ) -> Result<Valid<KeyShare<E, L>>, KeyRefreshError<M::ReceiveError, M::SendError>>
    where
        R: RngCore + CryptoRng,
        M: Mpc<ProtocolMessage = Msg<E, D>>,
        E: Curve,
        Scalar<E>: FromHash,
        L: SecurityLevel,
        D: Digest<OutputSize = digest::typenum::U32> + Clone + 'static,
    {
        run_refresh(
            rng,
            party,
            self.execution_id,
            self.pregenerated,
            self.core_share,
        )
        .await
    }
}

async fn run_refresh<R, M, E, L, D>(
    mut rng: &mut R,
    party: M,
    execution_id: ExecutionId<E, L, D>,
    pregenerated: Option<PregeneratedPrimes>,
    core_share: &IncompleteKeyShare<E, L>,
) -> Result<Valid<KeyShare<E, L>>, KeyRefreshError<M::ReceiveError, M::SendError>>
where
    R: RngCore + CryptoRng,
    M: Mpc<ProtocolMessage = Msg<E, D>>,
    E: Curve,
    Scalar<E>: FromHash,
    L: SecurityLevel,
    D: Digest<OutputSize = digest::typenum::U32> + Clone + 'static,
{
    let i = core_share.i;
    let n = u16::try_from(core_share.public_shares.len()).map_err(|_| Bug::TooManyParties)?;

    let MpcParty { delivery, blocking, .. } = party.into_party();
    let (incomings, mut outgoings) = delivery.split();

    // Setup networking
    let mut rounds = RoundsRouter::<Msg<E, D>>::builder();
    let round1 = rounds.add_round(RoundInput::<MsgRound1<D>>::broadcast(i, n));
    let round2 = rounds.add_round(RoundInput::<MsgRound2<E, D>>::broadcast(i, n));
    let round3 = rounds.add_round(RoundInput::<MsgRound3<E>>::p2p(i, n));
    let mut rounds = rounds.listen(incomings);

    let execution_id = execution_id.evaluate(ProtocolChoice::Keygen);
    let sid = execution_id.as_slice();
    let tag_htc = hash_to_curve::Tag::new(&execution_id).ok_or(Bug::InvalidHashToCurveTag)?;
    let parties_shared_state = D::new_with_prefix(execution_id);

    // Round 1

    let PregeneratedPrimes { p, q } = match pregenerated {
        Some(x) => x,
        None => blocking.spawn(|| {
            // can't use rng from context as this worker can outlive it
            let mut rng = rand_core::OsRng::default();
            PregeneratedPrimes::generate::<L, _>(&mut rng)
        }).await.map_err(|_| KeyRefreshError::SpawnError)?
    };
    let N = &p * &q;
    let φ_N = (&p - 1) * (&q - 1);
    let dec =
        libpaillier::DecryptionKey::with_primes_unchecked(&p, &q).ok_or(Bug::PaillierKeyError)?;

    let y = SecretScalar::<E>::random(rng);
    let Y = Point::generator() * &y;
    // tau and B_i in paper
    let (sch_secret_b, sch_commit_b) = schnorr_pok::prover_commits_ephemeral_secret::<E, _>(rng);

    // *x_i* in paper
    // generate n-1 values first..
    let mut xs = (0..n - 1)
        .map(|_| SecretScalar::<E>::random(rng))
        .collect::<Vec<_>>();
    // then create a last element such that the sum is zero
    let mut x_last = -xs.iter().fold(Scalar::<E>::zero(), |s, x| s + x.as_ref());
    xs.push(SecretScalar::new(&mut x_last));
    debug_assert_eq!(
        xs.iter().fold(Scalar::<E>::zero(), |s, x| s + x.as_ref()),
        Scalar::zero()
    );
    // *X_i* in paper
    let Xs = xs
        .iter()
        .map(|x| Point::generator() * x)
        .collect::<Vec<_>>();

    let r = utils::sample_bigint_in_mult_group(rng, &N);
    let λ = BigNumber::from_rng(&φ_N, rng);
    let t = r.modmul(&r, &N);
    let s = t.modpow(&λ, &N);

    let proof_data = π_prm::Data {
        N: &N,
        s: &s,
        t: &t,
    };
    let params_proof = π_prm::prove(parties_shared_state.clone(), &mut rng, proof_data, &φ_N, &λ);

    // tau_j and A_i^j in paper
    let (sch_secrets_a, sch_commits_a) = iter_peers(i, n)
        .map(|_| schnorr_pok::prover_commits_ephemeral_secret::<E, _>(rng))
        .unzip::<_, _, Vec<_>, Vec<_>>();

    // rho_i in paper, this signer's share of bytes
    let mut rho_bytes = Vec::new();
    rho_bytes.resize(L::SECURITY_BYTES, 0);
    rng.fill_bytes(&mut rho_bytes);

    // V_i and u_i in paper
    let (hash_commit, decommit) = HashCommit::<D>::builder()
        .mix_bytes(sid)
        .mix(n)
        .mix(i)
        .mix_many(&Xs)
        .mix_many(sch_commits_a.iter().map(|a| a.0))
        .mix(Y)
        .mix_bytes(&N.to_bytes())
        .mix_bytes(&s.to_bytes())
        .mix_bytes(&t.to_bytes())
        // mix param proof
        .mix_bytes(&rho_bytes)
        .commit(rng);

    let commitment = MsgRound1 {
        commitment: hash_commit,
    };
    outgoings
        .send(Outgoing::broadcast(Msg::Round1(commitment.clone())))
        .await
        .map_err(KeyRefreshError::SendError)?;

    // Round 2
    let commitments = rounds
        .complete(round1)
        .await
        .map_err(KeyRefreshError::ReceiveMessage)?;
    let decommitment = MsgRound2 {
        x: Xs.clone(),
        sch_commits_a: sch_commits_a.clone(),
        Y,
        sch_commit_b: sch_commit_b.clone(),
        N: N.clone(),
        s: s.clone(),
        t: t.clone(),
        params_proof,
        rho_bytes: rho_bytes.clone(),
        decommit,
    };
    outgoings
        .send(Outgoing::broadcast(Msg::Round2(decommitment.clone())))
        .await
        .map_err(KeyRefreshError::SendError)?;

    // Round 3

    let decommitments = rounds
        .complete(round2)
        .await
        .map_err(KeyRefreshError::ReceiveMessage)?;

    // validate decommitments
    let blame = collect_blame(
        &decommitments,
        &commitments,
        |j, decommitment, commitment| {
            HashCommit::<D>::builder()
                .mix_bytes(sid)
                .mix(n)
                .mix(j)
                .mix_many(&decommitment.x)
                .mix_many(decommitment.sch_commits_a.iter().map(|a| a.0))
                .mix(decommitment.Y)
                .mix_bytes(decommitment.N.to_bytes())
                .mix_bytes(decommitment.s.to_bytes())
                .mix_bytes(decommitment.t.to_bytes())
                // mix param proof
                .mix_bytes(&decommitment.rho_bytes)
                .verify(&commitment.commitment, &decommitment.decommit)
                .is_err()
        },
    );
    if !blame.is_empty() {
        return Err(KeyRefreshError::Aborted(
            ProtocolAborted::invalid_decommitment(blame),
        ));
    }
    // Validate parties didn't skip any data
    let blame = collect_simple_blame(&decommitments, |decommitment| {
        let n = usize::from(n);
        decommitment.x.len() != n
            || decommitment.sch_commits_a.len() != n - 1
            || decommitment.rho_bytes.len() != L::SECURITY_BYTES
    });
    if !blame.is_empty() {
        return Err(KeyRefreshError::Aborted(
            ProtocolAborted::invalid_data_size(blame),
        ));
    }
    // validate parameters and param_proofs
    let blame = collect_simple_blame(&decommitments, |d| {
        if d.N.bit_length() < L::SECURITY_BYTES {
            true
        } else {
            let data = π_prm::Data {
                N: &d.N,
                s: &d.s,
                t: &d.t,
            };
            π_prm::verify(parties_shared_state.clone(), data, &d.params_proof).is_err()
        }
    });
    if !blame.is_empty() {
        return Err(KeyRefreshError::Aborted(
            ProtocolAborted::invalid_ring_pedersen_parameters(blame),
        ));
    }
    // validate Xs add to zero
    let blame = collect_simple_blame(&decommitments, |d| {
        d.x.iter().sum::<Point<E>>() != Point::zero()
    });
    if !blame.is_empty() {
        return Err(KeyRefreshError::Aborted(ProtocolAborted::invalid_x(blame)));
    }

    // encryption keys for each party
    let encs = decommitments
        .iter()
        .map(|d| utils::encryption_key_from_n(&d.N))
        .collect::<Vec<_>>();

    // rho in paper, collective random bytes
    let rho_bytes = decommitments
        .iter()
        .map(|d| &d.rho_bytes)
        .fold(rho_bytes, xor_array);

    // pi_i
    let sch_proof_y = {
        let challenge = Scalar::<E>::hash_concat(tag_htc, &[&i.to_be_bytes(), rho_bytes.as_ref()])
            .map_err(Bug::HashToScalarError)?;
        let challenge = schnorr_pok::Challenge { nonce: challenge };
        schnorr_pok::prove(&sch_secret_b, &challenge, &y)
    };

    // common data for messages
    let mod_proof = {
        let data = π_mod::Data { n: N.clone() };
        let pdata = π_mod::PrivateData {
            p: p.clone(),
            q: q.clone(),
        };
        π_mod::non_interactive::prove(parties_shared_state.clone(), &data, &pdata, &mut rng)
    };
    let challenge = Scalar::<E>::hash_concat(tag_htc, &[&i.to_be_bytes(), rho_bytes.as_ref()])
        .map_err(Bug::HashToScalarError)?;
    let challenge = schnorr_pok::Challenge { nonce: challenge };
    let π_fac_aux = π_fac::Aux {
        s: s.clone(),
        t: t.clone(),
        rsa_modulo: N.clone(),
    };
    let π_fac_security = π_fac::SecurityParams {
        l: L::ELL,
        epsilon: L::EPSILON,
        q: L::q(),
    };
    // message to each party
    let iterator =
        // use every share except ours
        but_nth(i, xs.iter())
        .zip(&encs)
        .zip(&sch_secrets_a)
        .zip(iter_peers(i, n));
    for (((x, enc), secret), j) in iterator {
        let sch_proofs_x = xs
            .iter()
            .map(|x_j| schnorr_pok::prove(secret, &challenge, x_j))
            .collect();
        let nonce = BigNumber::from_rng(enc.n(), &mut rng);
        let C = enc
            .encrypt(x.as_ref().to_be_bytes(), Some(nonce))
            .ok_or(Bug::PaillierEnc)?
            .0;
        let fac_proof = π_fac::prove(
            parties_shared_state.clone(),
            &π_fac_aux,
            π_fac::Data {
                n: &N,
                n_root: &utils::sqrt(&N),
            },
            π_fac::PrivateData { p: &p, q: &q },
            &π_fac_security,
            &mut rng,
        );

        let msg = MsgRound3 {
            mod_proof: mod_proof.clone(),
            fac_proof,
            sch_proof_y: sch_proof_y.clone(),
            sch_proofs_x,
            C,
        };
        outgoings
            .send(Outgoing::p2p(j, Msg::Round3(msg)))
            .await
            .map_err(KeyRefreshError::SendError)?;
    }

    // Output

    let shares_msg_b = rounds
        .complete(round3)
        .await
        .map_err(KeyRefreshError::ReceiveMessage)?;

    // x_j^i in paper. x_i^i is a share from self to self, so it was never sent,
    // so it's handled separately
    let my_share = &xs[usize::from(i)];
    let shares = shares_msg_b
        .iter()
        .map(|m| {
            let bytes = dec.decrypt(&m.C).ok_or(KeyRefreshError::PaillierDec)?;
            Scalar::from_be_bytes(bytes).map_err(KeyRefreshError::InvalidScalar)
        })
        .collect::<Result<Vec<_>, _>>()?;

    // verify shares are well-formed
    let blame = shares
        .iter()
        .zip(decommitments.iter_indexed())
        .filter_map(|(share, (j, msg_id, decommitment))| {
            let i = usize::from(i);
            let X = Point::generator() * share;
            if X != decommitment.x[i] {
                Some(AbortBlame::new(j, msg_id, msg_id))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    if !blame.is_empty() {
        return Err(KeyRefreshError::Aborted(ProtocolAborted::invalid_x_share(
            blame,
        )));
    }
    // It is possible at this point to report a bad party to others, but we
    // don't implement it now

    // verify sch proofs for y and x
    let blame = utils::try_collect_blame(
        &decommitments,
        &shares_msg_b,
        |j, decommitment, proof_msg| {
            let challenge =
                Scalar::<E>::hash_concat(tag_htc, &[&j.to_be_bytes(), rho_bytes.as_ref()])
                    .map_err(Bug::HashToScalarError)?;
            let challenge = schnorr_pok::Challenge { nonce: challenge };

            // proof for y, i.e. pi_j
            let sch_proof = &proof_msg.sch_proof_y;
            if sch_proof
                .verify(&decommitment.sch_commit_b, &challenge, &decommitment.Y)
                .is_err()
            {
                return Ok(true);
            }

            // x length is verified above
            if proof_msg.sch_proofs_x.len() != decommitment.x.len() {
                return Ok(true);
            }
            // proof for x, i.e. psi_j^k for every k
            for (sch_proof, x) in proof_msg.sch_proofs_x.iter().zip(&decommitment.x) {
                if sch_proof
                    .verify(mine_from(i, j, &decommitment.sch_commits_a), &challenge, x)
                    .is_err()
                {
                    return Ok(true);
                }
            }
            // explicit type ascription because it can't get inferred
            Ok::<_, Bug>(false)
        },
    )?;
    if !blame.is_empty() {
        return Err(KeyRefreshError::Aborted(
            ProtocolAborted::invalid_schnorr_proof(blame),
        ));
    }

    // verify mod proofs
    let blame = collect_blame(
        &decommitments,
        &shares_msg_b,
        |_, decommitment, proof_msg| {
            let data = π_mod::Data {
                n: decommitment.N.clone(),
            };
            let (ref comm, ref proof) = proof_msg.mod_proof;
            π_mod::non_interactive::verify(parties_shared_state.clone(), &data, comm, proof)
                .is_err()
        },
    );
    if !blame.is_empty() {
        return Err(KeyRefreshError::Aborted(
            ProtocolAborted::invalid_mod_proof(blame),
        ));
    }

    // verify fac proofs
    let blame = collect_blame(
        &decommitments,
        &shares_msg_b,
        |_, decommitment, proof_msg| {
            π_fac::verify(
                parties_shared_state.clone(),
                &π_fac::Aux {
                    s: decommitment.s.clone(),
                    t: decommitment.t.clone(),
                    rsa_modulo: decommitment.N.clone(),
                },
                π_fac::Data {
                    n: &decommitment.N,
                    n_root: &utils::sqrt(&decommitment.N),
                },
                &π_fac_security,
                &proof_msg.fac_proof,
            )
            .is_err()
        },
    );
    if !blame.is_empty() {
        return Err(KeyRefreshError::Aborted(
            ProtocolAborted::invalid_fac_proof(blame),
        ));
    }

    // verifications passed, compute final key shares

    let old_core_share = core_share.clone();
    let x_sum = shares.iter().fold(Scalar::zero(), |s, x| s + x) + my_share;
    let mut x_star = old_core_share.x + x_sum;
    let X_prods = (0..n).map(|k| {
        let k = usize::from(k);
        decommitments
            .iter_including_me(&decommitment)
            .map(|d| d.x[k])
            .sum::<Point<E>>()
    });
    let X_stars = old_core_share
        .public_shares
        .into_iter()
        .zip(X_prods)
        .map(|(x, p)| x + p)
        .collect();

    let new_core_share = IncompleteKeyShare {
        public_shares: X_stars,
        x: SecretScalar::new(&mut x_star),
        ..old_core_share
    };
    let party_auxes = decommitments
        .iter_including_me(&decommitment)
        .map(|d| PartyAux {
            N: d.N.clone(),
            s: d.s.clone(),
            t: d.t.clone(),
            Y: d.Y,
        })
        .collect();
    let key_share = KeyShare {
        core: new_core_share,
        p,
        q,
        y,
        parties: party_auxes,
    };

    Ok(key_share.try_into().map_err(Bug::InvalidShareGenerated)?)
}

#[derive(Debug, Error)]
pub enum KeyRefreshError<IErr, OErr> {
    /// Protocol was maliciously aborted by another party
    #[error("protocol was aborted by malicious party")]
    Aborted(#[source] ProtocolAborted),
    /// Receiving message error
    #[error("receive message")]
    ReceiveMessage(
        #[source]
        round_based::rounds_router::CompleteRoundError<
            round_based::rounds_router::simple_store::RoundInputError,
            IErr,
        >,
    ),
    /// Sending message error
    #[error("send message")]
    SendError(#[source] OErr),
    #[error("could not spawn worker thread")]
    SpawnError,
    #[error("internal error")]
    InternalError(#[from] Bug),
    #[error("couldn't decrypt a message")]
    PaillierDec,
    #[error("couldn't decode scalar bytes")]
    InvalidScalar(generic_ec::errors::InvalidScalar),
}

/// Unexpected error in operation not caused by other parties
#[derive(Debug, Error)]
pub enum Bug {
    #[error("`Tag` appears to be invalid `generic_ec::hash_to_curve::Tag`")]
    InvalidHashToCurveTag,
    #[error("Unexpected error when creating paillier decryption key")]
    PaillierKeyError,
    #[error("hash to scalar returned error")]
    HashToScalarError(#[source] generic_ec::errors::HashError),
    #[error("paillier enctyption failed")]
    PaillierEnc,
    #[error("Attempting to run protocol with too many parties")]
    TooManyParties,
    #[error("Invalid key share geenrated")]
    InvalidShareGenerated(#[source] crate::key_share::InvalidKeyShare),
}

/// Error indicating that protocol was aborted by malicious party
///
/// It _can be_ cryptographically proven, but we do not support it yet.
#[derive(Debug, Error)]
#[error("Protocol aborted; malicious parties: {parties:?}; reason: {reason}")]
pub struct ProtocolAborted {
    pub reason: ProtocolAbortReason,
    pub parties: Vec<AbortBlame>,
}

/// Reason for protocol abort: which exact check has failed
#[derive(Debug, Error)]
pub enum ProtocolAbortReason {
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
}
