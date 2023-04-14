mod aux_only;

use digest::Digest;
use futures::SinkExt;
use generic_ec::{
    hash_to_curve::{self, FromHash},
    Curve, Point, Scalar, SecretScalar,
};
use generic_ec_zkp::{hash_commitment::HashCommit, schnorr_pok};
use paillier_zk::{
    libpaillier, no_small_factor::non_interactive as π_fac, paillier_blum_modulus as π_mod,
    unknown_order::BigNumber, BigNumberExt, SafePaillierDecryptionExt, SafePaillierEncryptionExt,
};
use rand_core::{CryptoRng, RngCore};
use round_based::{
    rounds_router::{simple_store::RoundInput, RoundsRouter},
    Delivery, Mpc, MpcParty, Outgoing,
};
use thiserror::Error;

use crate::{
    errors::IoError,
    execution_id::ProtocolChoice,
    key_share::{AuxInfo, AnyKeyShare, DirtyIncompleteKeyShare, DirtyKeyShare, KeyShare, PartyAux, DirtyAuxInfo},
    progress::Tracer,
    security_level::SecurityLevel,
    utils,
    utils::{
        but_nth, collect_blame, collect_simple_blame, iter_peers, scalar_to_bignumber, xor_array,
        AbortBlame,
    },
    zk::ring_pedersen_parameters as π_prm,
    ExecutionId,
};

use self::msg::*;

#[doc = include_str!("../docs/mpc_message.md")]
pub mod msg {
    use digest::Digest;
    use generic_ec::{Curve, Point};
    use generic_ec_zkp::{
        hash_commitment::{self, HashCommit},
        schnorr_pok,
    };
    use paillier_zk::{
        no_small_factor::non_interactive as π_fac, paillier_blum_modulus as π_mod,
        unknown_order::BigNumber,
    };
    use round_based::ProtocolMessage;

    use crate::{security_level::SecurityLevel, zk::ring_pedersen_parameters as π_prm};

    /// Message of key refresh protocol
    #[derive(ProtocolMessage, Clone)]
    // 3 kilobytes for the largest option, and 2.5 kilobytes for second largest
    #[allow(clippy::large_enum_variant)]
    pub enum Msg<E: Curve, D: Digest, L: SecurityLevel> {
        Round1(MsgRound1<D>),
        Round2(MsgRound2<E, D, L>),
        Round3(MsgRound3<E>),
    }

    /// Message from round 1
    #[derive(Clone)]
    pub struct MsgRound1<D: Digest> {
        pub commitment: HashCommit<D>,
    }
    /// Message from round 2
    #[derive(Clone)]
    pub struct MsgRound2<E: Curve, D: Digest, L: SecurityLevel> {
        /// **X_i** in paper
        pub Xs: Vec<Point<E>>,
        /// **A_i** in paper
        pub sch_commits_a: Vec<schnorr_pok::Commit<E>>,
        pub N: BigNumber,
        pub s: BigNumber,
        pub t: BigNumber,
        /// psi_circonflexe_i in paper
        // this should be L::M instead, but no rustc support yet
        pub params_proof: π_prm::Proof<{ π_prm::SECURITY }>,
        /// rho_i in paper
        // ideally it would be [u8; L::SECURITY_BYTES], but no rustc support yet
        pub rho_bytes: L::Rid,
        /// u_i in paper
        pub decommit: hash_commitment::DecommitNonce<D>,
    }
    /// Unicast message of round 3, sent to each participant
    #[derive(Clone)]
    pub struct MsgRound3<E: Curve> {
        /// psi_i in paper
        // this should be L::M instead, but no rustc support yet
        pub mod_proof: (π_mod::Commitment, π_mod::Proof<{ π_prm::SECURITY }>),
        /// phi_i^j in paper
        pub fac_proof: π_fac::Proof,
        /// C_i^j in paper
        pub C: BigNumber,
        /// psi_i_j in paper
        ///
        /// Here in the paper you only send one proof, but later they require you to
        /// verify by all the other proofs, that are never sent. We fix this here
        /// and require each party to send every proof to everyone
        pub sch_proofs_x: Vec<schnorr_pok::Proof<E>>,
    }
}

/// To speed up computations, it's possible to supply data to the algorithm
/// generated ahead of time
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PregeneratedPrimes<L> {
    p: BigNumber,
    q: BigNumber,
    _phantom: std::marker::PhantomData<L>,
}

impl<L: SecurityLevel> PregeneratedPrimes<L> {
    pub fn new(p: BigNumber, q: BigNumber) -> Self {
        Self {
            p,
            q,
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn split(self) -> (BigNumber, BigNumber) {
        (self.p, self.q)
    }

    /// Generate the structure. Takes some time.
    pub fn generate<R: RngCore>(rng: &mut R) -> Self {
        Self {
            p: BigNumber::safe_prime_from_rng(4 * L::SECURITY_BITS, rng),
            q: BigNumber::safe_prime_from_rng(4 * L::SECURITY_BITS, rng),
            _phantom: std::marker::PhantomData,
        }
    }
}

pub type KeyRefreshBuilder<'a, E, L, D> =
    GenericKeyRefreshBuilder<'a, E, L, D, RefreshShare<'a, E, L>>;

pub struct GenericKeyRefreshBuilder<'a, E, L, D, M>
where
    E: Curve,
    L: SecurityLevel,
    D: Digest,
{
    target: M,
    execution_id: ExecutionId<E, L, D>,
    pregenerated: PregeneratedPrimes<L>,
    tracer: Option<&'a mut dyn Tracer>,
}

pub struct RefreshShare<'a, E: Curve, L: SecurityLevel>(&'a DirtyIncompleteKeyShare<E, L>);
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
    pub fn new(key_share: &'a impl AnyKeyShare<E, L>, pregenerated: PregeneratedPrimes<L>) -> Self {
        Self {
            target: RefreshShare(key_share.core()),
            execution_id: Default::default(),
            pregenerated,
            tracer: None,
        }
    }
}

impl<'a, E, L, D> GenericKeyRefreshBuilder<'a, E, L, D, AuxOnly>
where
    E: Curve,
    L: SecurityLevel,
    D: Digest,
{
    pub fn new_aux_gen(i: u16, n: u16, pregenerated: PregeneratedPrimes<L>) -> Self {
        Self {
            target: AuxOnly { i, n },
            execution_id: Default::default(),
            pregenerated,
            tracer: None,
        }
    }
}

impl<'a, E, L, D> KeyRefreshBuilder<'a, E, L, D>
where
    E: Curve,
    L: SecurityLevel,
    D: Digest,
{
    /// Specifies another hash function to use
    ///
    /// _Caution_: this function overwrites [execution ID](Self::set_execution_id). Make sure
    /// you specify execution ID **after** calling this function.
    pub fn set_digest<D2: Digest>(self) -> KeyRefreshBuilder<'a, E, L, D2> {
        KeyRefreshBuilder {
            target: self.target,
            execution_id: Default::default(),
            pregenerated: self.pregenerated,
            tracer: None,
        }
    }

    pub fn set_execution_id(self, execution_id: ExecutionId<E, L, D>) -> Self {
        Self {
            execution_id,
            ..self
        }
    }

    pub fn set_progress_tracer(mut self, tracer: &'a mut dyn Tracer) -> Self {
        self.tracer = Some(tracer);
        self
    }

    /// Carry out the refresh procedure. Takes a lot of time
    pub async fn start<R, M>(self, rng: &mut R, party: M) -> Result<KeyShare<E, L>, KeyRefreshError>
    where
        R: RngCore + CryptoRng,
        M: Mpc<ProtocolMessage = Msg<E, D, L>>,
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
            self.tracer,
            self.target.0,
        )
        .await
    }
}

impl<'a, E, L, D> GenericKeyRefreshBuilder<'a, E, L, D, AuxOnly>
where
    E: Curve,
    L: SecurityLevel,
    D: Digest,
{
    pub async fn start_aux_only<R, M>(
        self,
        rng: &mut R,
        party: M,
    ) -> Result<AuxInfo, KeyRefreshError>
    where
        R: RngCore + CryptoRng,
        M: Mpc<ProtocolMessage = aux_only::Msg<D>>,
        E: Curve,
        Scalar<E>: FromHash,
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
        )
        .await
    }
}

async fn run_refresh<R, M, E, L, D>(
    mut rng: &mut R,
    party: M,
    execution_id: ExecutionId<E, L, D>,
    pregenerated: PregeneratedPrimes<L>,
    mut tracer: Option<&mut dyn Tracer>,
    core_share: &DirtyIncompleteKeyShare<E, L>,
) -> Result<KeyShare<E, L>, KeyRefreshError>
where
    R: RngCore + CryptoRng,
    M: Mpc<ProtocolMessage = Msg<E, D, L>>,
    E: Curve,
    Scalar<E>: FromHash,
    L: SecurityLevel,
    D: Digest<OutputSize = digest::typenum::U32> + Clone + 'static,
{
    tracer.protocol_begins();

    tracer.stage("Retrieve auxiliary data");
    let i = core_share.i;
    let n = u16::try_from(core_share.public_shares.len()).map_err(|_| Bug::TooManyParties)?;

    tracer.stage("Setup networking");
    let MpcParty { delivery, .. } = party.into_party();
    let (incomings, mut outgoings) = delivery.split();

    let mut rounds = RoundsRouter::<Msg<E, D, L>>::builder();
    let round1 = rounds.add_round(RoundInput::<MsgRound1<D>>::broadcast(i, n));
    let round2 = rounds.add_round(RoundInput::<MsgRound2<E, D, L>>::broadcast(i, n));
    let round3 = rounds.add_round(RoundInput::<MsgRound3<E>>::p2p(i, n));
    let mut rounds = rounds.listen(incomings);

    tracer.stage("Precompute execution id and shared state");
    let execution_id = execution_id.evaluate(ProtocolChoice::Keygen);
    let sid = execution_id.as_slice();
    let tag_htc = hash_to_curve::Tag::new(&execution_id).ok_or(Bug::InvalidHashToCurveTag)?;
    let parties_shared_state = D::new_with_prefix(execution_id);

    // Round 1
    tracer.round_begins();

    tracer.stage("Retrieve primes (p and q)");
    let PregeneratedPrimes { p, q, .. } = pregenerated;
    tracer.stage("Compute paillier decryption key (N)");
    let N = &p * &q;
    let phi_N = (&p - 1) * (&q - 1);
    let dec =
        libpaillier::DecryptionKey::with_primes_unchecked(&p, &q).ok_or(Bug::PaillierKeyError)?;

    // *x_i* in paper
    tracer.stage("Generate secret x_i and public X_i");
    // generate n-1 values first..
    let mut xs = (0..n - 1)
        .map(|_| SecretScalar::<E>::random(rng))
        .collect::<Vec<_>>();
    // then create a last element such that the sum is zero
    let mut x_last = -xs.iter().sum::<Scalar<E>>();
    xs.push(SecretScalar::new(&mut x_last));
    debug_assert_eq!(xs.iter().sum::<Scalar<E>>(), Scalar::zero());
    // *X_i* in paper
    let Xs = xs
        .iter()
        .map(|x| Point::generator() * x)
        .collect::<Vec<_>>();

    tracer.stage("Generate auxiliary params r, λ, t, s");
    let r = utils::sample_bigint_in_mult_group(rng, &N);
    let lambda = BigNumber::from_rng(&phi_N, rng);
    let t = r.modmul(&r, &N);
    let s = t.powmod(&lambda, &N).map_err(|_| Bug::PowMod)?;

    tracer.stage("Prove Πprm (ψˆ_i)");
    let hat_psi = π_prm::prove(
        parties_shared_state.clone(),
        &mut rng,
        π_prm::Data {
            N: &N,
            s: &s,
            t: &t,
        },
        &phi_N,
        &lambda,
    )
    .map_err(Bug::PiPrm)?;

    tracer.stage("Compute schnorr commitment τ_j");
    // tau_j and A_i^j in paper
    let (taus, As) = (0..n)
        .map(|_| schnorr_pok::prover_commits_ephemeral_secret::<E, _>(rng))
        .unzip::<_, _, Vec<_>, Vec<_>>();

    tracer.stage("Sample random bytes");
    // rho_i in paper, this signer's share of bytes
    let mut rho_bytes = L::Rid::default();
    rng.fill_bytes(rho_bytes.as_mut());

    tracer.stage("Compute hash commitment and sample decommitment");
    // V_i and u_i in paper
    // TODO: decommitment should be kappa bits
    let (hash_commit, decommit) = HashCommit::<D>::builder()
        .mix_bytes(sid)
        .mix(n)
        .mix(i)
        .mix_many(&Xs)
        .mix_many(As.iter().map(|a| a.0))
        .mix_bytes(&N.to_bytes())
        .mix_bytes(&s.to_bytes())
        .mix_bytes(&t.to_bytes())
        .mix_many_bytes(hat_psi.commitment.iter().map(|x| x.to_bytes()))
        .mix_many_bytes(hat_psi.zs.iter().map(|x| x.to_bytes()))
        .mix_bytes(&rho_bytes)
        .commit(rng);

    tracer.send_msg();
    let commitment = MsgRound1 {
        commitment: hash_commit,
    };
    outgoings
        .send(Outgoing::broadcast(Msg::Round1(commitment.clone())))
        .await
        .map_err(IoError::send_message)?;
    tracer.msg_sent();

    // Round 2
    tracer.round_begins();

    tracer.receive_msgs();
    let commitments = rounds
        .complete(round1)
        .await
        .map_err(IoError::receive_message)?;
    tracer.msgs_received();
    tracer.send_msg();
    let decommitment = MsgRound2 {
        Xs: Xs.clone(),
        sch_commits_a: As.clone(),
        N: N.clone(),
        s: s.clone(),
        t: t.clone(),
        params_proof: hat_psi,
        rho_bytes: rho_bytes.clone(),
        decommit,
    };
    outgoings
        .send(Outgoing::broadcast(Msg::Round2(decommitment.clone())))
        .await
        .map_err(IoError::send_message)?;
    tracer.msg_sent();

    // Round 3
    tracer.round_begins();

    tracer.receive_msgs();
    let decommitments = rounds
        .complete(round2)
        .await
        .map_err(IoError::receive_message)?;
    tracer.msgs_received();

    // validate decommitments
    tracer.stage("Validate round 1 decommitments");
    let blame = collect_blame(&decommitments, &commitments, |j, decomm, comm| {
        HashCommit::<D>::builder()
            .mix_bytes(sid)
            .mix(n)
            .mix(j)
            .mix_many(&decomm.Xs)
            .mix_many(decomm.sch_commits_a.iter().map(|a| a.0))
            .mix_bytes(decomm.N.to_bytes())
            .mix_bytes(decomm.s.to_bytes())
            .mix_bytes(decomm.t.to_bytes())
            .mix_many_bytes(decomm.params_proof.commitment.iter().map(|x| x.to_bytes()))
            .mix_many_bytes(decomm.params_proof.zs.iter().map(|x| x.to_bytes()))
            .mix_bytes(&decomm.rho_bytes)
            .verify(&comm.commitment, &decomm.decommit)
            .is_err()
    });
    if !blame.is_empty() {
        return Err(ProtocolAborted::invalid_decommitment(blame).into());
    }
    // Validate parties didn't skip any data
    tracer.stage("Validate data sizes");
    let blame = collect_simple_blame(&decommitments, |decommitment| {
        let n = usize::from(n);
        decommitment.Xs.len() != n || decommitment.sch_commits_a.len() != n
    });
    if !blame.is_empty() {
        return Err(ProtocolAborted::invalid_data_size(blame).into());
    }
    // validate parameters and param_proofs
    tracer.stage("Validate П_prm (ψ_i)");
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
        return Err(ProtocolAborted::invalid_ring_pedersen_parameters(blame).into());
    }
    // validate Xs add to zero
    tracer.stage("Validate X_i");
    let blame = collect_simple_blame(&decommitments, |d| {
        d.Xs.iter().sum::<Point<E>>() != Point::zero()
    });
    if !blame.is_empty() {
        return Err(ProtocolAborted::invalid_x(blame).into());
    }

    tracer.stage("Compute paillier encryption keys");
    // encryption keys for each party
    let encs = decommitments
        .iter()
        .map(|d| utils::encryption_key_from_n(&d.N))
        .collect::<Vec<_>>();

    tracer.stage("Add together shared random bytes");
    // rho in paper, collective random bytes
    let rho_bytes = decommitments
        .iter()
        .map(|d| &d.rho_bytes)
        .fold(rho_bytes, xor_array);

    // common data for messages
    tracer.stage("Compute П_mod (ψ_i)");
    let psi = π_mod::non_interactive::prove(
        parties_shared_state.clone(),
        &π_mod::Data { n: N.clone() },
        &π_mod::PrivateData {
            p: p.clone(),
            q: q.clone(),
        },
        &mut rng,
    )
    .map_err(Bug::PiMod)?;
    tracer.stage("Assemble security params for П_fac (ф_i)");
    let π_fac_security = π_fac::SecurityParams {
        l: L::ELL,
        epsilon: L::EPSILON,
        q: L::q(),
    };
    let n_sqrt = utils::sqrt(&N);
    tracer.stage("Compute schnorr proof ψ_i^j");
    let challenge = Scalar::<E>::hash_concat(tag_htc, &[&i.to_be_bytes(), rho_bytes.as_ref()])
        .map_err(Bug::HashToScalarError)?;
    let challenge = schnorr_pok::Challenge { nonce: challenge };
    let psis = xs
        .iter()
        .zip(taus.iter())
        .map(|(x_j, secret_j)| schnorr_pok::prove(secret_j, &challenge, x_j))
        .collect::<Vec<_>>();
    tracer.stage("Prepare auxiliary params and security level for proofs");
    // message to each party
    let iterator =
        // use every share except ours
        but_nth(i, xs.iter())
        .zip(&encs)
        .zip(decommitments.iter())
        .zip(iter_peers(i, n));
    for (((x, enc), d), j) in iterator {
        tracer.stage("Paillier encryption of x_i^j");
        let (C, _) = enc
            .encrypt_with_random(&scalar_to_bignumber(x), &mut rng)
            .map_err(|_| Bug::PaillierEnc)?;
        tracer.stage("Compute П_fac (ф_i^j)");
        let phi = π_fac::prove(
            parties_shared_state.clone(),
            &π_fac::Aux {
                s: d.s.clone(),
                t: d.t.clone(),
                rsa_modulo: d.N.clone(),
            },
            π_fac::Data {
                n: &N,
                n_root: &n_sqrt,
            },
            π_fac::PrivateData { p: &p, q: &q },
            &π_fac_security,
            &mut rng,
        )
        .map_err(Bug::PiFac)?;

        tracer.send_msg();
        let msg = MsgRound3 {
            mod_proof: psi.clone(),
            fac_proof: phi.clone(),
            sch_proofs_x: psis.clone(),
            C,
        };
        outgoings
            .send(Outgoing::p2p(j, Msg::Round3(msg)))
            .await
            .map_err(IoError::send_message)?;
        tracer.msg_sent();
    }

    // Output
    tracer.round_begins();

    tracer.receive_msgs();
    let shares_msg_b = rounds
        .complete(round3)
        .await
        .map_err(IoError::receive_message)?;
    tracer.msgs_received();

    tracer.stage("Paillier decrypt x_j^i from C_j^i");
    // x_j^i in paper. x_i^i is a share from self to self, so it was never sent,
    // so it's handled separately
    let my_share = &xs[usize::from(i)];
    // If the share couldn't be decrypted, abort with a faulty party
    let (shares, blame) =
        utils::partition_results(shares_msg_b.iter_indexed().map(|(j, mid, m)| {
            let bigint = dec
                .decrypt_to_bigint(&m.C)
                .map_err(|_| AbortBlame::new(j, mid, mid))?;
            Ok::<_, AbortBlame>(bigint.to_scalar())
        }));
    if !blame.is_empty() {
        return Err(ProtocolAborted::paillier_dec(blame).into());
    }
    debug_assert_eq!(shares.len(), usize::from(n) - 1);

    tracer.stage("Validate shares");
    // verify shares are well-formed
    let blame = shares
        .iter()
        .zip(decommitments.iter_indexed())
        .filter_map(|(share, (j, msg_id, decommitment))| {
            let i = usize::from(i);
            let X = Point::generator() * share;
            if X != decommitment.Xs[i] {
                Some(AbortBlame::new(j, msg_id, msg_id))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    if !blame.is_empty() {
        return Err(ProtocolAborted::invalid_x_share(blame).into());
    }
    // It is possible at this point to report a bad party to others, but we
    // don't implement it now

    tracer.stage("Validate schnorr proofs п_j and ψ_j^k");
    // verify sch proofs for x
    let blame = utils::try_collect_blame(
        &decommitments,
        &shares_msg_b,
        |j, decommitment, proof_msg| {
            let challenge =
                Scalar::<E>::hash_concat(tag_htc, &[&j.to_be_bytes(), rho_bytes.as_ref()])
                    .map_err(Bug::HashToScalarError)?;
            let challenge = schnorr_pok::Challenge { nonce: challenge };

            // x length is verified above
            if proof_msg.sch_proofs_x.len() != decommitment.Xs.len() {
                return Ok(true);
            }
            // proof for x, i.e. psi_j^k for every k
            let iterator = proof_msg
                .sch_proofs_x
                .iter()
                .zip(&decommitment.Xs)
                .zip(&decommitment.sch_commits_a);
            for ((sch_proof, x), commit) in iterator {
                if sch_proof.verify(commit, &challenge, x).is_err() {
                    return Ok(true);
                }
            }
            // explicit type ascription because it can't get inferred
            Ok::<_, Bug>(false)
        },
    )?;
    if !blame.is_empty() {
        return Err(ProtocolAborted::invalid_schnorr_proof(blame).into());
    }

    tracer.stage("Validate ψ_j (П_mod)");
    // verify mod proofs
    let blame = collect_blame(
        &decommitments,
        &shares_msg_b,
        |_, decommitment, proof_msg| {
            let data = π_mod::Data {
                n: decommitment.N.clone(),
            };
            let (comm, proof) = &proof_msg.mod_proof;
            π_mod::non_interactive::verify(parties_shared_state.clone(), &data, comm, proof)
                .is_err()
        },
    );
    if !blame.is_empty() {
        return Err(ProtocolAborted::invalid_mod_proof(blame).into());
    }

    tracer.stage("Validate ф_j (П_fac)");
    // verify fac proofs
    let blame = collect_blame(
        &decommitments,
        &shares_msg_b,
        |_, decommitment, proof_msg| {
            π_fac::verify(
                parties_shared_state.clone(),
                &π_fac::Aux {
                    s: s.clone(),
                    t: t.clone(),
                    rsa_modulo: N.clone(),
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
        return Err(ProtocolAborted::invalid_fac_proof(blame).into());
    }

    // verifications passed, compute final key shares

    let old_core_share = core_share.clone();
    tracer.stage("Calculate new x_i");
    let x_sum = shares.iter().sum::<Scalar<E>>() + my_share;
    let mut x_star = old_core_share.x + x_sum;
    tracer.stage("Calculate new X_i");
    let X_sums = (0..n).map(|k| {
        let k = usize::from(k);
        decommitments
            .iter_including_me(&decommitment)
            .map(|d| d.Xs[k])
            .sum::<Point<E>>()
    });
    let X_stars = old_core_share
        .public_shares
        .into_iter()
        .zip(X_sums)
        .map(|(x, p)| x + p)
        .collect();

    tracer.stage("Assemble new core share");
    let new_core_share = DirtyIncompleteKeyShare {
        public_shares: X_stars,
        x: SecretScalar::new(&mut x_star),
        ..old_core_share
    };
    tracer.stage("Assemble auxiliary info");
    let party_auxes = decommitments
        .iter_including_me(&decommitment)
        .map(|d| PartyAux {
            N: d.N.clone(),
            s: d.s.clone(),
            t: d.t.clone(),
        })
        .collect();
    let aux = DirtyAuxInfo {
        p,
        q,
        parties: party_auxes,
    };
    let key_share = DirtyKeyShare {
        core: new_core_share,
        aux,
    };

    tracer.protocol_ends();
    Ok(key_share.try_into().map_err(Bug::InvalidShareGenerated)?)
}

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
    #[error("couldn't prove a pi mod statement")]
    PiMod(#[source] paillier_zk::Error),
    #[error("couldn't prove a pi fac statement")]
    PiFac(#[source] paillier_zk::Error),
    #[error("powmod not defined")]
    PowMod,
    #[error("couldn't prove prm statement")]
    PiPrm(#[source] crate::zk::ring_pedersen_parameters::ZkError),
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
}
