use digest::Digest;
use futures::SinkExt;
use paillier_zk::{
    no_small_factor::non_interactive as π_fac,
    paillier_blum_modulus as π_mod,
    rug::{Complete, Integer},
    IntegerExt,
};
use rand_core::{CryptoRng, RngCore};
use round_based::{
    blocking::SpawnBlocking,
    rounds_router::{simple_store::RoundInput, RoundsRouter},
    Delivery, Mpc, MpcParty, Outgoing, ProtocolMessage,
};
use serde::{Deserialize, Serialize};

use crate::{
    errors::IoError,
    key_share::{AuxInfo, DirtyAuxInfo, PartyAux},
    progress::Tracer,
    security_level::SecurityLevel,
    utils,
    utils::{collect_blame, AbortBlame},
    zk::ring_pedersen_parameters as π_prm,
    ExecutionId,
};

use super::{Bug, KeyRefreshError, PregeneratedPrimes, ProtocolAborted};

/// Message of key refresh protocol
#[derive(ProtocolMessage, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
// 3 kilobytes for the largest option, and 2.5 kilobytes for second largest
#[allow(clippy::large_enum_variant)]
pub enum Msg<D: Digest, L: SecurityLevel> {
    /// Round 1 message
    Round1(MsgRound1<D>),
    /// Round 2 message
    Round2(MsgRound2<L>),
    /// Round 3 message
    Round3(MsgRound3),
    /// Reliability check message (optional additional round)
    ReliabilityCheck(MsgReliabilityCheck<D>),
}

/// Message from round 1
#[derive(Clone, Serialize, Deserialize, udigest::Digestable)]
#[udigest(tag = "dfns.cggmp21.aux_gen.round1")]
#[udigest(bound = "")]
#[serde(bound = "")]
pub struct MsgRound1<D: Digest> {
    /// $V_i$
    #[udigest(as_bytes)]
    pub commitment: digest::Output<D>,
}
/// Message from round 2
#[derive(Clone, Serialize, Deserialize, udigest::Digestable)]
#[udigest(tag = "dfns.cggmp21.aux_gen.round2")]
#[udigest(bound = "")]
#[serde(bound = "")]
pub struct MsgRound2<L: SecurityLevel> {
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
pub struct MsgRound3 {
    /// $\psi_i$
    // this should be L::M instead, but no rustc support yet
    pub mod_proof: (
        π_mod::Commitment,
        π_mod::Proof<{ crate::security_level::M }>,
    ),
    /// $\phi_i^j$
    pub fac_proof: π_fac::Proof,
}

/// Message from an optional round that enforces reliability check
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgReliabilityCheck<D: Digest>(pub digest::Output<D>);

#[derive(udigest::Digestable)]
#[udigest(tag = "dfns.cggmp21.aux_gen.tag")]
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

pub async fn run_aux_gen<R, M, L, D>(
    i: u16,
    n: u16,
    mut rng: &mut R,
    party: M,
    execution_id: ExecutionId<'_>,
    pregenerated: PregeneratedPrimes<L>,
    mut tracer: Option<&mut dyn Tracer>,
    reliable_broadcast_enforced: bool,
    compute_multiexp_table: bool,
    compute_crt: bool,
) -> Result<AuxInfo<L>, KeyRefreshError>
where
    R: RngCore + CryptoRng,
    M: Mpc<ProtocolMessage = Msg<D, L>>,
    L: SecurityLevel,
    D: Digest<OutputSize = digest::typenum::U32> + Clone + 'static,
{
    tracer.protocol_begins();

    tracer.stage("Retrieve auxiliary data");

    tracer.stage("Setup networking");
    let MpcParty {
        delivery, blocking, ..
    } = party.into_party();
    let (incomings, mut outgoings) = delivery.split();

    let mut rounds = RoundsRouter::<Msg<D, L>>::builder();
    let round1 = rounds.add_round(RoundInput::<MsgRound1<D>>::broadcast(i, n));
    let round1_sync = rounds.add_round(RoundInput::<MsgReliabilityCheck<D>>::broadcast(i, n));
    let round2 = rounds.add_round(RoundInput::<MsgRound2<L>>::broadcast(i, n));
    let round3 = rounds.add_round(RoundInput::<MsgRound3>::p2p(i, n));
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

    tracer.stage("Sample random bytes");
    // rho_i in paper, this signer's share of bytes
    let mut rho_bytes = L::Rid::default();
    rng.fill_bytes(rho_bytes.as_mut());

    tracer.stage("Compute hash commitment and sample decommitment");
    // V_i and u_i in paper
    let decommitment = MsgRound2 {
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

    tracer.stage("Add together shared random bytes");
    // rho in paper, collective random bytes
    let rho_bytes = decommitments
        .iter()
        .map(|d| &d.rho_bytes)
        .fold(rho_bytes, utils::xor_array);

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

    // message to each party
    for (j, _, d) in decommitments.iter_indexed() {
        tracer.send_msg();

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

    let crt = if compute_crt {
        // note: `crt` contains private information
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

    if compute_multiexp_table {
        tracer.stage("Precompute multiexp tables");
        aux = blocking
            .spawn(move || {
                aux.precompute_multiexp_tables()?;
                Ok(aux)
            })
            .await
            .map_err(|err| Bug::SpawnBlocking(Box::new(err)))?
            .map_err(Bug::BuildMultiexpTables)?
    }

    tracer.protocol_ends();
    Ok(aux)
}
