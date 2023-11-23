use digest::Digest;
use futures::SinkExt;
use generic_ec::{Curve, Point, Scalar, SecretScalar};
use generic_ec_zkp::schnorr_pok;
use paillier_zk::{
    fast_paillier,
    no_small_factor::non_interactive as π_fac,
    paillier_blum_modulus as π_mod,
    rug::{Complete, Integer},
    IntegerExt,
};
use rand_core::{CryptoRng, RngCore};
use round_based::ProtocolMessage;
use round_based::{
    rounds_router::{simple_store::RoundInput, RoundsRouter},
    Delivery, Mpc, MpcParty, Outgoing,
};
use serde::{Deserialize, Serialize};

use super::{Bug, KeyRefreshError, PregeneratedPrimes, ProtocolAborted};
use crate::{
    errors::IoError,
    key_share::{AuxInfo, DirtyAuxInfo, DirtyIncompleteKeyShare, KeyShare, PartyAux},
    progress::Tracer,
    security_level::SecurityLevel,
    utils,
    utils::{
        but_nth, collect_blame, collect_simple_blame, iter_peers, scalar_to_bignumber, xor_array,
        AbortBlame,
    },
    zk::ring_pedersen_parameters as π_prm,
    ExecutionId, IncompleteKeyShare,
};

/// Message of key refresh protocol
#[derive(ProtocolMessage, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
// 3 kilobytes for the largest option, and 2.5 kilobytes for second largest
#[allow(clippy::large_enum_variant)]
pub enum Msg<E: Curve, D: Digest, L: SecurityLevel> {
    /// Round 1 message
    Round1(MsgRound1<D>),
    /// Round 2 message
    Round2(MsgRound2<E, L>),
    /// Round 3 message
    Round3(MsgRound3<E>),
    /// Reliability check message (optional additional round)
    ReliabilityCheck(MsgReliabilityCheck<D>),
}

/// Message from round 1
#[derive(Clone, Serialize, Deserialize, udigest::Digestable)]
#[udigest(tag = "dfns.cggmp21.full_key_refresh.non_threshold.round1")]
#[udigest(bound = "")]
#[serde(bound = "")]
pub struct MsgRound1<D: Digest> {
    /// $V_i$
    #[udigest(as_bytes)]
    pub commitment: digest::Output<D>,
}
/// Message from round 2
#[derive(Clone, Serialize, Deserialize, udigest::Digestable)]
#[udigest(tag = "dfns.cggmp21.full_key_refresh.non_threshold.round2")]
#[udigest(bound = "")]
#[serde(bound = "")]
pub struct MsgRound2<E: Curve, L: SecurityLevel> {
    /// $\vec X_i$
    pub Xs: Vec<Point<E>>,
    /// $\vec A_i$
    pub sch_commits_a: Vec<schnorr_pok::Commit<E>>,
    /// $N_i$
    #[udigest(with = utils::encoding::integer)]
    pub N: Integer,
    /// $s_i$
    #[udigest(with = utils::encoding::integer)]
    pub s: Integer,
    /// $t_i$
    #[udigest(with = utils::encoding::integer)]
    pub t: Integer,
    /// $\hat \psi_i$
    // this should be L::M instead, but no rustc support yet
    pub params_proof: π_prm::Proof<{ crate::security_level::M }>,
    /// $\rho_i$
    // ideally it would be [u8; L::SECURITY_BYTES], but no rustc support yet
    #[serde(with = "hex")]
    #[udigest(as_bytes)]
    pub rho_bytes: L::Rid,
    /// $u_i$
    #[serde(with = "hex")]
    #[udigest(as_bytes)]
    pub decommit: L::Rid,
}
/// Unicast message of round 3, sent to each participant
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgRound3<E: Curve> {
    /// $\psi_i$
    // this should be L::M instead, but no rustc support yet
    pub mod_proof: (
        π_mod::Commitment,
        π_mod::Proof<{ crate::security_level::M }>,
    ),
    /// $\phi_i^j$
    pub fac_proof: π_fac::Proof,
    /// $C_i^j$
    pub C: Integer,
    /// $\psi_i^k$
    ///
    /// Here in the paper you only send one proof, but later they require you to
    /// verify by all the other proofs, that are never sent. We fix this here
    /// and require each party to send every proof to everyone
    pub sch_proofs_x: Vec<schnorr_pok::Proof<E>>,
}

/// Message of optional round that enforces reliability check
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgReliabilityCheck<D: Digest>(pub digest::Output<D>);

#[derive(udigest::Digestable)]
#[udigest(tag = "dfns.cggmp21.full_key_refresh.non_threshold.tag")]
enum Tag<'a> {
    /// Tag that includes the prover index
    Indexed {
        party_index: u16,
        #[udigest(as_bytes)]
        sid: &'a [u8],
    },
    /// Tag w/o party index
    Unindexed {
        #[udigest(as_bytes)]
        sid: &'a [u8],
    },
}

pub async fn run_refresh<R, M, E, L, D>(
    mut rng: &mut R,
    party: M,
    execution_id: ExecutionId<'_>,
    pregenerated: PregeneratedPrimes<L>,
    mut tracer: Option<&mut dyn Tracer>,
    reliable_broadcast_enforced: bool,
    build_multiexp_tables: bool,
    build_crt: bool,
    core_share: &DirtyIncompleteKeyShare<E>,
) -> Result<KeyShare<E, L>, KeyRefreshError>
where
    R: RngCore + CryptoRng,
    M: Mpc<ProtocolMessage = Msg<E, D, L>>,
    E: Curve,
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
    let round1_sync = rounds.add_round(RoundInput::<MsgReliabilityCheck<D>>::broadcast(i, n));
    let round2 = rounds.add_round(RoundInput::<MsgRound2<E, L>>::broadcast(i, n));
    let round3 = rounds.add_round(RoundInput::<MsgRound3<E>>::p2p(i, n));
    let mut rounds = rounds.listen(incomings);

    tracer.stage("Precompute execution id and shared state");
    let sid = execution_id.as_bytes();
    let tag = |j| {
        udigest::Tag::<D>::new_structured(Tag::Indexed {
            party_index: j,
            sid,
        })
    };
    let tag_i = tag(i);
    let parties_shared_state = D::new_with_prefix(D::digest(sid));

    // Round 1
    tracer.round_begins();

    tracer.stage("Retrieve primes (p and q)");
    let PregeneratedPrimes { p, q, .. } = pregenerated;
    tracer.stage("Compute paillier decryption key (N)");
    let N = (&p * &q).complete();
    let phi_N = (&p - 1u8).complete() * (&q - 1u8).complete();
    let dec: fast_paillier::DecryptionKey =
        fast_paillier::DecryptionKey::from_primes(p.clone(), q.clone())
            .map_err(|_| Bug::PaillierKeyError)?;

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
    let r = Integer::gen_invertible(&N, rng);
    let lambda = phi_N
        .random_below_ref(&mut utils::external_rand(rng))
        .into();
    let t = r.square().modulo(&N);
    let s = t.pow_mod_ref(&lambda, &N).ok_or(Bug::PowMod)?.into();

    tracer.stage("Prove Πprm (ψˆ_i)");
    let hat_psi = π_prm::prove(
        parties_shared_state.clone().chain_update(i.to_be_bytes()),
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
    let decommitment = MsgRound2 {
        Xs: Xs.clone(),
        sch_commits_a: As.clone(),
        N: N.clone(),
        s: s.clone(),
        t: t.clone(),
        params_proof: hat_psi,
        rho_bytes: rho_bytes.clone(),
        decommit: {
            let mut nonce = L::Rid::default();
            rng.fill_bytes(nonce.as_mut());
            nonce
        },
    };
    let hash_commit = tag_i.clone().digest(&decommitment);

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

    // Optional reliability check
    if reliable_broadcast_enforced {
        tracer.stage("Hash received msgs (reliability check)");
        let h_i = udigest::Tag::<D>::new_structured(&Tag::Unindexed { sid })
            .digest_iter(commitments.iter_including_me(&commitment));

        tracer.send_msg();
        outgoings
            .send(Outgoing::broadcast(Msg::ReliabilityCheck(
                MsgReliabilityCheck(h_i),
            )))
            .await
            .map_err(IoError::send_message)?;
        tracer.msg_sent();

        tracer.round_begins();

        tracer.receive_msgs();
        let hashes = rounds
            .complete(round1_sync)
            .await
            .map_err(IoError::receive_message)?;
        tracer.msgs_received();

        tracer.stage("Assert other parties hashed messages (reliability check)");
        let parties_have_different_hashes = hashes
            .into_iter_indexed()
            .filter(|(_j, _msg_id, h_j)| h_i != h_j.0)
            .map(|(j, msg_id, _)| AbortBlame::new(j, msg_id, msg_id))
            .collect::<Vec<_>>();
        if !parties_have_different_hashes.is_empty() {
            return Err(ProtocolAborted::round1_not_reliable(parties_have_different_hashes).into());
        }
    }

    tracer.send_msg();
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
        tag(j).digest(decomm) != comm.commitment
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
    let blame = collect_blame(&decommitments, &decommitments, |j, d, _| {
        if !crate::security_level::validate_public_paillier_key_size::<L>(&d.N) {
            true
        } else {
            let data = π_prm::Data {
                N: &d.N,
                s: &d.s,
                t: &d.t,
            };
            π_prm::verify(
                parties_shared_state.clone().chain_update(j.to_be_bytes()),
                data,
                &d.params_proof,
            )
            .is_err()
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
        .map(|d| fast_paillier::EncryptionKey::from_n(d.N.clone()))
        .collect::<Vec<_>>();

    tracer.stage("Add together shared random bytes");
    // rho in paper, collective random bytes
    let rho_bytes = decommitments
        .iter()
        .map(|d| &d.rho_bytes)
        .fold(rho_bytes, xor_array);

    // common data for messages
    let my_shared_state = parties_shared_state
        .clone()
        .chain_update(i.to_be_bytes())
        .chain_update(&rho_bytes);
    tracer.stage("Compute П_mod (ψ_i)");
    let psi = π_mod::non_interactive::prove(
        my_shared_state.clone(),
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
    let challenge = {
        let hash = |d: D| {
            d.chain_update(sid)
                .chain_update(i.to_be_bytes())
                .chain_update(rho_bytes.as_ref())
                .finalize()
        };
        let mut rng = paillier_zk::rng::HashRng::new(hash);
        Scalar::random(&mut rng)
    };
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
            .encrypt_with_random(&mut rng, &scalar_to_bignumber(x))
            .map_err(|_| Bug::PaillierEnc)?;
        tracer.stage("Compute П_fac (ф_i^j)");
        let phi = π_fac::prove(
            my_shared_state.clone(),
            &π_fac::Aux {
                s: d.s.clone(),
                t: d.t.clone(),
                rsa_modulo: d.N.clone(),
                multiexp: None,
                crt: None,
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
                .decrypt(&m.C)
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
            let challenge = {
                let hash = |d: D| {
                    d.chain_update(sid)
                        .chain_update(j.to_be_bytes())
                        .chain_update(rho_bytes.as_ref())
                        .finalize()
                };
                let mut rng = paillier_zk::rng::HashRng::new(hash);
                Scalar::random(&mut rng)
            };
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
        |j, decommitment, proof_msg| {
            let data = π_mod::Data {
                n: decommitment.N.clone(),
            };
            let (comm, proof) = &proof_msg.mod_proof;
            π_mod::non_interactive::verify(
                parties_shared_state
                    .clone()
                    .chain_update(j.to_be_bytes())
                    .chain_update(&rho_bytes),
                &data,
                comm,
                proof,
            )
            .is_err()
        },
    );
    if !blame.is_empty() {
        return Err(ProtocolAborted::invalid_mod_proof(blame).into());
    }

    tracer.stage("Validate ф_j (П_fac)");
    // verify fac proofs

    // note: `crt` contains private information
    let crt = if build_crt {
        Some(paillier_zk::fast_paillier::utils::CrtExp::build_n(&p, &q).ok_or(Bug::BuildCrt)?)
    } else {
        None
    };
    let phi_common_aux = π_fac::Aux {
        s: s.clone(),
        t: t.clone(),
        rsa_modulo: N.clone(),
        multiexp: None,
        crt: crt.clone(),
    };
    let blame = collect_blame(
        &decommitments,
        &shares_msg_b,
        |j, decommitment, proof_msg| {
            π_fac::verify(
                parties_shared_state
                    .clone()
                    .chain_update(j.to_be_bytes())
                    .chain_update(&rho_bytes),
                &phi_common_aux,
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
    let new_core_share: IncompleteKeyShare<E> = DirtyIncompleteKeyShare {
        public_shares: X_stars,
        x: SecretScalar::new(&mut x_star),
        ..old_core_share
    }
    .try_into()
    .map_err(Bug::InvalidShareGenerated)?;
    tracer.stage("Assemble auxiliary info");
    let mut party_auxes = decommitments
        .iter_including_me(&decommitment)
        .map(|d| PartyAux {
            N: d.N.clone(),
            s: d.s.clone(),
            t: d.t.clone(),
            multiexp: None,
            crt: None,
        })
        .collect::<Vec<_>>();
    party_auxes[usize::from(i)].crt = crt;
    let mut aux: AuxInfo<L> = DirtyAuxInfo {
        p,
        q,
        parties: party_auxes,
        security_level: std::marker::PhantomData,
    }
    .try_into()
    .map_err(Bug::InvalidShareGenerated)?;

    if build_multiexp_tables {
        tracer.stage("Build multiexp tables");

        aux.precompute_multiexp_tables()
            .map_err(Bug::BuildMultiexpTables)?;
    }

    tracer.stage("Assemble key share");
    let key_share = KeyShare::make(new_core_share, aux).map_err(Bug::InvalidShareGenerated)?;

    tracer.protocol_ends();
    Ok(key_share)
}
