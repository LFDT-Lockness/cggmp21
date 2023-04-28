use digest::Digest;
use futures::SinkExt;
use generic_ec::Curve;
use generic_ec_zkp::hash_commitment::{self, HashCommit};
use paillier_zk::{
    no_small_factor::non_interactive as π_fac, paillier_blum_modulus as π_mod,
    unknown_order::BigNumber, BigNumberExt,
};
use rand_core::{CryptoRng, RngCore};
use round_based::{
    rounds_router::{simple_store::RoundInput, RoundsRouter},
    Delivery, Mpc, MpcParty, Outgoing, ProtocolMessage,
};
use serde::{Deserialize, Serialize};

use crate::{
    errors::IoError,
    execution_id::ProtocolChoice,
    key_share::{AuxInfo, DirtyAuxInfo, PartyAux},
    progress::Tracer,
    security_level::SecurityLevel,
    utils,
    utils::{collect_blame, collect_simple_blame, hash_message, AbortBlame},
    zk::ring_pedersen_parameters as π_prm,
    ExecutionId,
};

use super::{Bug, KeyRefreshError, PregeneratedPrimes, ProtocolAborted};

/// Message of key refresh protocol
#[derive(ProtocolMessage, Clone)]
// 3 kilobytes for the largest option, and 2.5 kilobytes for second largest
#[allow(clippy::large_enum_variant)]
pub enum Msg<D: Digest> {
    Round1(MsgRound1<D>),
    Round2(MsgRound2<D>),
    Round3(MsgRound3),
    ReliabilityCheck(MsgReliabilityCheck<D>),
}

/// Message from round 1
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgRound1<D: Digest> {
    commitment: HashCommit<D>,
}
/// Message from round 2
#[derive(Clone)]
pub struct MsgRound2<D: Digest> {
    N: BigNumber,
    s: BigNumber,
    t: BigNumber,
    /// psi_circonflexe_i in paper
    // this should be L::M instead, but no rustc support yet
    params_proof: π_prm::Proof<{ π_prm::SECURITY }>,
    /// u_i in paper
    decommit: hash_commitment::DecommitNonce<D>,
}
/// Unicast message of round 3, sent to each participant
#[derive(Clone)]
pub struct MsgRound3 {
    /// psi_i in paper
    // this should be L::M instead, but no rustc support yet
    mod_proof: (π_mod::Commitment, π_mod::Proof<{ π_prm::SECURITY }>),
    /// phi_i^j in paper
    fac_proof: π_fac::Proof,
}

/// Message from an optional round that enforces reliability check
#[derive(Clone)]
pub struct MsgReliabilityCheck<D: Digest>(pub digest::Output<D>);

pub async fn run_aux_gen<R, M, E, L, D>(
    i: u16,
    n: u16,
    mut rng: &mut R,
    party: M,
    execution_id: ExecutionId<E, L, D>,
    pregenerated: PregeneratedPrimes<L>,
    mut tracer: Option<&mut dyn Tracer>,
    reliable_broadcast_enforced: bool,
) -> Result<AuxInfo, KeyRefreshError>
where
    R: RngCore + CryptoRng,
    M: Mpc<ProtocolMessage = Msg<D>>,
    E: Curve,
    L: SecurityLevel,
    D: Digest<OutputSize = digest::typenum::U32> + Clone + 'static,
{
    tracer.protocol_begins();

    tracer.stage("Retrieve auxiliary data");

    tracer.stage("Setup networking");
    let MpcParty { delivery, .. } = party.into_party();
    let (incomings, mut outgoings) = delivery.split();

    let mut rounds = RoundsRouter::<Msg<D>>::builder();
    let round1 = rounds.add_round(RoundInput::<MsgRound1<D>>::broadcast(i, n));
    let round1_sync = rounds.add_round(RoundInput::<MsgReliabilityCheck<D>>::broadcast(i, n));
    let round2 = rounds.add_round(RoundInput::<MsgRound2<D>>::broadcast(i, n));
    let round3 = rounds.add_round(RoundInput::<MsgRound3>::p2p(i, n));
    let mut rounds = rounds.listen(incomings);

    tracer.stage("Precompute execution id and shared state");
    let execution_id = execution_id.evaluate(ProtocolChoice::AuxDataGen);
    let sid = execution_id.as_slice();
    let parties_shared_state = D::new_with_prefix(execution_id);

    // Round 1
    tracer.round_begins();

    tracer.stage("Retrieve primes (p and q)");
    let PregeneratedPrimes { p, q, .. } = pregenerated;
    tracer.stage("Compute paillier decryption key (N)");
    let N = &p * &q;
    let phi_N = (&p - 1) * (&q - 1);

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

    tracer.stage("Compute hash commitment and sample decommitment");
    // V_i and u_i in paper
    // TODO: decommitment should be kappa bits
    let (hash_commit, decommit) = HashCommit::<D>::builder()
        .mix_bytes(sid)
        .mix(n)
        .mix(i)
        .mix_bytes(&N.to_bytes())
        .mix_bytes(&s.to_bytes())
        .mix_bytes(&t.to_bytes())
        .mix_many_bytes(hat_psi.commitment.iter().map(|x| x.to_bytes()))
        .mix_many_bytes(hat_psi.zs.iter().map(|x| x.to_bytes()))
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

    // Optional reliability check
    if reliable_broadcast_enforced {
        tracer.stage("Hash received msgs (reliability check)");
        let h_i = commitments
            .iter_including_me(&commitment)
            .try_fold(D::new(), hash_message)
            .map_err(Bug::HashMessage)?
            .finalize();

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
    let decommitment = MsgRound2 {
        N: N.clone(),
        s: s.clone(),
        t: t.clone(),
        params_proof: hat_psi,
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
            .mix_bytes(decomm.N.to_bytes())
            .mix_bytes(decomm.s.to_bytes())
            .mix_bytes(decomm.t.to_bytes())
            .mix_many_bytes(decomm.params_proof.commitment.iter().map(|x| x.to_bytes()))
            .mix_many_bytes(decomm.params_proof.zs.iter().map(|x| x.to_bytes()))
            .verify(&comm.commitment, &decomm.decommit)
            .is_err()
    });
    if !blame.is_empty() {
        return Err(ProtocolAborted::invalid_decommitment(blame).into());
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

    // message to each party
    for (j, _, d) in decommitments.iter_indexed() {
        tracer.send_msg();

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

        let msg = MsgRound3 {
            mod_proof: psi.clone(),
            fac_proof: phi.clone(),
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
    let phi_common_aux = π_fac::Aux {
        s: s.clone(),
        t: t.clone(),
        rsa_modulo: N.clone(),
    };
    let blame = collect_blame(
        &decommitments,
        &shares_msg_b,
        |_, decommitment, proof_msg| {
            π_fac::verify(
                parties_shared_state.clone(),
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

    tracer.protocol_ends();
    Ok(aux.try_into().map_err(Bug::InvalidShareGenerated)?)
}
