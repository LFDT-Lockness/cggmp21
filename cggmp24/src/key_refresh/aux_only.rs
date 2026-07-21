use digest::Digest;
use futures::SinkExt;
use paillier_zk::{backend::Integer, no_small_factor as π_fac, paillier_blum_modulus as π_mod};
use rand_core::{CryptoRng, RngCore};
use round_based::{
    rounds_router::{simple_store::RoundInput, RoundsRouter},
    Delivery, Mpc, MpcParty, Outgoing, ProtocolMessage,
};
use serde::{Deserialize, Serialize};

use crate::{
    errors::IoError,
    key_share::{AuxInfo, DirtyAuxInfo, PedersenParams, Validate},
    progress::Tracer,
    security_level::SecurityLevel,
    utils::{self, collect_blame, AbortBlame},
    zk::ring_pedersen_parameters as π_prm,
    ExecutionId,
};

use super::{Bug, KeyRefreshError, PregeneratedPrimes, ProtocolAborted};

macro_rules! prefixed {
    ($name:tt) => {
        concat!("dfns.cggmp24.aux_gen.", $name)
    };
}

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
#[udigest(tag = prefixed!("round1"))]
#[udigest(bound = "")]
#[serde(bound = "")]
pub struct MsgRound1<D: Digest> {
    /// $V_i$
    #[udigest(as_bytes)]
    pub commitment: digest::Output<D>,
}
/// Message from round 2
#[derive(Clone, Serialize, Deserialize, udigest::Digestable)]
#[udigest(tag = prefixed!("round2"))]
#[udigest(bound = "")]
#[serde(bound = "")]
pub struct MsgRound2<L: SecurityLevel> {
    /// $N_i$
    #[udigest(as = utils::encoding::Integer)]
    pub N: Integer,
    /// $\hat N_i$
    #[udigest(as = utils::encoding::Integer)]
    pub hat_N: Integer,
    /// $s_i$
    #[udigest(as = utils::encoding::Integer)]
    pub s: Integer,
    /// $t_i$
    #[udigest(as = utils::encoding::Integer)]
    pub t: Integer,
    /// $\hat \psi_i$
    // this should be L::M instead, but no rustc support yet
    pub params_proof: π_prm::Proof<{ crate::security_level::M }>,
    /// $\rho_i$
    // ideally it would be [u8; L::SECURITY_BYTES], but no rustc support yet
    #[serde(with = "hex")]
    #[udigest(as_bytes)]
    pub rho_bytes: L::KappaBytes,
    /// $u_i$
    #[serde(with = "hex")]
    #[udigest(as_bytes)]
    pub decommit: L::KappaBytes,
}
/// Unicast message of round 3, sent to each participant
#[derive(Clone, Serialize, Deserialize)]
pub struct MsgRound3 {
    /// $\psi_i$
    // this should be L::M instead, but no rustc support yet
    pub mod_proof: π_mod::NiProof<{ crate::security_level::M }>,
    /// $\phi_i^j$
    pub fac_proof: π_fac::NiProof,
}

/// Message from an optional round that enforces reliability check
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgReliabilityCheck<D: Digest>(pub digest::Output<D>);

mod unambiguous {
    use digest::Digest;

    use crate::{ExecutionId, SecurityLevel};

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("proof_prm"))]
    pub struct ProofPrm<'a> {
        pub sid: ExecutionId<'a>,
        pub prover: u16,
    }

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("proof_mod"))]
    pub struct ProofMod<'a> {
        pub sid: ExecutionId<'a>,
        #[udigest(as_bytes)]
        pub rho: &'a [u8],
        pub prover: u16,
    }

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("proof_fac"))]
    #[udigest(bound = "")]
    pub struct ProofFac<'a> {
        pub sid: ExecutionId<'a>,
        #[udigest(as_bytes)]
        pub rho: &'a [u8],
        pub prover: u16,
    }

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("hash_commitment"))]
    #[udigest(bound = "")]
    pub struct HashCom<'a, L: SecurityLevel> {
        pub sid: ExecutionId<'a>,
        pub prover: u16,
        pub decommitment: &'a super::MsgRound2<L>,
    }

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("echo_round"))]
    #[udigest(bound = "")]
    pub struct Echo<'a, D: Digest> {
        pub sid: ExecutionId<'a>,
        pub commitment: &'a super::MsgRound1<D>,
    }
}

pub async fn run_aux_gen<R, M, L, D>(
    i: u16,
    n: u16,
    mut rng: &mut R,
    party: M,
    sid: ExecutionId<'_>,
    pregenerated: PregeneratedPrimes<L>,
    mut tracer: Option<&mut dyn Tracer>,
    reliable_broadcast_enforced: bool,
    compute_multiexp_table: bool,
) -> Result<AuxInfo<L>, KeyRefreshError>
where
    R: RngCore + CryptoRng,
    M: Mpc<ProtocolMessage = Msg<D, L>>,
    L: SecurityLevel,
    D: Digest + Clone + 'static,
{
    tracer.protocol_begins();

    tracer.stage("Retrieve auxiliary data");

    tracer.stage("Setup networking");
    let MpcParty { delivery, .. } = party.into_party();
    let (incomings, mut outgoings) = delivery.split();

    let mut rounds = RoundsRouter::<Msg<D, L>>::builder();
    let round1 = rounds.add_round(RoundInput::<MsgRound1<D>>::broadcast(i, n));
    let round1_sync = rounds.add_round(RoundInput::<MsgReliabilityCheck<D>>::broadcast(i, n));
    let round2 = rounds.add_round(RoundInput::<MsgRound2<L>>::broadcast(i, n));
    let round3 = rounds.add_round(RoundInput::<MsgRound3>::p2p(i, n));
    let mut rounds = rounds.listen(incomings);

    // Round 1
    tracer.round_begins();

    let [p, q, hat_p, hat_q] = pregenerated.into_primes();

    tracer.stage("Build Paillier key");
    let N = &p * &q;
    let N_crt = paillier_zk::fast_paillier::utils::CrtExp::build_n(&p, &q).ok_or(Bug::BuildNCrt)?;

    tracer.stage("Build Pedersen params");
    let (my_pedersen_params, phi_hat_N, lambda) =
        utils::generate_pedersen_params(rng, hat_p, hat_q)?;

    tracer.stage("Prove Πprm (ψˆ_i)");
    let hat_psi = π_prm::prove::<{ crate::security_level::M }, D>(
        &unambiguous::ProofPrm { sid, prover: i },
        &mut rng,
        &my_pedersen_params,
        &phi_hat_N,
        &lambda,
    )
    .map_err(Bug::PiPrm)?;

    tracer.stage("Sample random bytes");
    // rho_i in paper, this signer's share of bytes
    let mut rho_bytes = L::KappaBytes::default();
    rng.fill_bytes(rho_bytes.as_mut());

    tracer.stage("Compute hash commitment and sample decommitment");
    // V_i and u_i in paper
    let decommitment = MsgRound2 {
        N: N.clone(),
        hat_N: my_pedersen_params.hat_N.clone(),
        s: my_pedersen_params.s.clone(),
        t: my_pedersen_params.t.clone(),
        params_proof: hat_psi,
        rho_bytes: rho_bytes.clone(),
        decommit: {
            let mut nonce = L::KappaBytes::default();
            rng.fill_bytes(nonce.as_mut());
            nonce
        },
    };
    let hash_commit = udigest::hash::<D>(&unambiguous::HashCom {
        sid,
        prover: i,
        decommitment: &decommitment,
    });

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
        let h_i = udigest::hash_iter::<D>(
            commitments
                .iter_including_me(&commitment)
                .map(|commitment| unambiguous::Echo { sid, commitment }),
        );

        tracer.send_msg();
        outgoings
            .send(Outgoing::broadcast(Msg::ReliabilityCheck(
                MsgReliabilityCheck(h_i.clone()),
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
        let com_expected = udigest::hash::<D>(&unambiguous::HashCom {
            sid,
            prover: j,
            decommitment: decomm,
        });
        com_expected != comm.commitment
    });
    if !blame.is_empty() {
        return Err(ProtocolAborted::invalid_decommitment(blame).into());
    }
    // validate parameters and param_proofs
    tracer.stage("Validate pedersen params consistency");
    let blame = utils::collect_simple_blame(&decommitments, |_, d| {
        if [&d.N, &d.hat_N]
            .iter()
            .any(|biprime| !crate::security_level::validate_public_paillier_key_size::<L>(biprime))
        {
            return true;
        }
        !d.t.in_mult_group_of(&d.hat_N) || !d.s.in_mult_group_of(&d.hat_N)
    });
    if !blame.is_empty() {
        return Err(ProtocolAborted::invalid_ring_pedersen_parameters(blame).into());
    }
    tracer.stage("Construct aux info");
    let mut pedersen_params = decommitments
        .iter()
        .map(|d| PedersenParams {
            hat_N: d.hat_N.clone(),
            s: d.s.clone(),
            t: d.t.clone(),
            multiexp: None,
            crt: None,
        })
        .collect::<Vec<_>>();
    pedersen_params.insert(i.into(), my_pedersen_params);
    let mut aux = DirtyAuxInfo {
        p,
        q,
        N: decommitments
            .iter_including_me(&decommitment)
            .map(|d| d.N.clone())
            .collect::<Vec<_>>(),
        pedersen_params,
        security_level: std::marker::PhantomData,
    };
    if compute_multiexp_table {
        tracer.stage("Precompute multiexp tables");
        aux.precompute_multiexp_tables()
            .map_err(Bug::BuildMultiexpTables)?;
    }

    tracer.stage("Validate П_prm (ψˆ_i)");
    let blame = utils::collect_simple_blame(&decommitments, |j, d| {
        π_prm::verify::<{ crate::security_level::M }, D>(
            &unambiguous::ProofPrm { sid, prover: j },
            &aux.pedersen_params[usize::from(j)],
            &d.params_proof,
        )
        .is_err()
    });
    if !blame.is_empty() {
        return Err(ProtocolAborted::invalid_prm_proof(blame).into());
    }

    tracer.stage("Add together shared random bytes");
    // rho in paper, collective random bytes
    let rho_bytes = decommitments
        .iter()
        .map(|d| &d.rho_bytes)
        .fold(rho_bytes, utils::xor_array);

    // common data for messages
    tracer.stage("Compute П_mod (ψ_i)");
    let psi = π_mod::non_interactive::prove::<{ crate::security_level::M }, D>(
        &unambiguous::ProofMod {
            sid,
            rho: rho_bytes.as_ref(),
            prover: i,
        },
        π_mod::Data { n: &N },
        π_mod::PrivateData {
            p: &aux.p,
            q: &aux.q,
            crt: &N_crt,
        },
        &mut rng,
    )
    .map_err(Bug::PiMod)?;
    tracer.stage("Assemble security params for П_fac (ψ_i)");
    let π_fac_security = π_fac::SecurityParams {
        l: L::ELL,
        epsilon: L::EPSILON,
    };
    let n_sqrt = N.sqrt_ref().ok_or(Bug::NegativeModulus)?;

    // message to each party
    for j in utils::iter_peers(i, n) {
        tracer.send_msg();

        tracer.stage("Compute П_fac (ψ'_i,j)");
        let psi_prime = π_fac::non_interactive::prove::<D>(
            &unambiguous::ProofFac {
                sid,
                rho: rho_bytes.as_ref(),
                prover: i,
            },
            &(&aux.pedersen_params[usize::from(j)]).into(),
            π_fac::Data {
                n: &N,
                n_root: &n_sqrt,
            },
            π_fac::PrivateData {
                p: &aux.p,
                q: &aux.q,
            },
            &π_fac_security,
            &mut rng,
        )
        .map_err(Bug::PiFac)?;

        tracer.send_msg();
        let msg = MsgRound3 {
            mod_proof: psi.clone(),
            fac_proof: psi_prime.clone(),
        };
        outgoings
            .feed(Outgoing::p2p(j, Msg::Round3(msg)))
            .await
            .map_err(IoError::send_message)?;
        tracer.msg_sent();
    }

    tracer.send_msg();
    outgoings.flush().await.map_err(IoError::send_message)?;
    tracer.msg_sent();

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
            π_mod::non_interactive::verify::<{ crate::security_level::M }, D>(
                &unambiguous::ProofMod {
                    sid,
                    rho: rho_bytes.as_ref(),
                    prover: j,
                },
                π_mod::Data { n: &decommitment.N },
                &proof_msg.mod_proof,
                rng,
            )
            .is_err()
        },
    );
    if !blame.is_empty() {
        return Err(ProtocolAborted::invalid_mod_proof(blame).into());
    }

    tracer.stage("Validate ψ'_j,i (П_fac)");

    // verify fac proofs
    let phi_common_aux: π_fac::Aux = (&aux.pedersen_params[usize::from(i)]).into();
    let blame = collect_blame(
        &decommitments,
        &shares_msg_b,
        |j, decommitment, proof_msg| {
            let n_root = match decommitment.N.sqrt_ref() {
                Some(root) => root,
                None => return true,
            };
            π_fac::non_interactive::verify::<D>(
                &unambiguous::ProofFac {
                    sid,
                    rho: rho_bytes.as_ref(),
                    prover: j,
                },
                &phi_common_aux,
                π_fac::Data {
                    n: &decommitment.N,
                    n_root: &n_root,
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

    tracer.stage("Verify consistency of auxiliary info");
    let aux = aux
        .validate()
        .map_err(|err| Bug::InvalidShareGenerated(err.into_error()))?;

    tracer.protocol_ends();
    Ok(aux)
}
