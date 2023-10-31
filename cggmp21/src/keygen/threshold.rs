use digest::Digest;
use futures::SinkExt;
use generic_ec::{Curve, NonZero, Point, Scalar, SecretScalar};
use generic_ec_zkp::{polynomial::Polynomial, schnorr_pok};
use rand_core::{CryptoRng, RngCore};
use round_based::{
    rounds_router::simple_store::RoundInput, rounds_router::RoundsRouter, Delivery, Mpc, MpcParty,
    Outgoing, ProtocolMessage,
};
use serde::{Deserialize, Serialize};

use crate::key_share::DirtyIncompleteKeyShare;
use crate::progress::Tracer;
use crate::{
    errors::IoError,
    key_share::{IncompleteKeyShare, VssSetup},
    security_level::SecurityLevel,
    utils, ExecutionId,
};

use super::{Bug, KeygenAborted, KeygenError};

/// Message of key generation protocol
#[derive(ProtocolMessage, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum Msg<E: Curve, L: SecurityLevel, D: Digest> {
    /// Round 1 message
    Round1(MsgRound1<D>),
    /// Round 2a message
    Round2Broad(MsgRound2Broad<E, L>),
    /// Round 2b message
    Round2Uni(MsgRound2Uni<E>),
    /// Round 3 message
    Round3(MsgRound3<E>),
    /// Reliability check message (optional additional round)
    ReliabilityCheck(MsgReliabilityCheck<D>),
}

/// Message from round 1
#[derive(Clone, Serialize, Deserialize, udigest::Digestable)]
#[serde(bound = "")]
#[udigest(bound = "")]
#[udigest(tag = "dfns.cggmp21.keygen.threshold.round1")]
pub struct MsgRound1<D: Digest> {
    /// $V_i$
    #[udigest(as_bytes)]
    pub commitment: digest::Output<D>,
}
/// Message from round 2 broadcasted to everyone
#[derive(Clone, Serialize, Deserialize, udigest::Digestable)]
#[serde(bound = "")]
#[udigest(bound = "")]
#[udigest(tag = "dfns.cggmp21.keygen.threshold.round1")]
pub struct MsgRound2Broad<E: Curve, L: SecurityLevel> {
    /// `rid_i`
    #[serde(with = "hex::serde")]
    #[udigest(as_bytes)]
    pub rid: L::Rid,
    /// $\vec S_i$
    pub F: Polynomial<Point<E>>,
    /// $A_i$
    pub sch_commit: schnorr_pok::Commit<E>,
    /// $u_i$
    #[serde(with = "hex::serde")]
    #[udigest(as_bytes)]
    pub decommit: L::Rid,
}
/// Message from round 2 unicasted to each party
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgRound2Uni<E: Curve> {
    /// $\sigma_{i,j}$
    pub sigma: Scalar<E>,
}
/// Message from round 3
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgRound3<E: Curve> {
    /// $\psi_i$
    pub sch_proof: schnorr_pok::Proof<E>,
}
/// Message parties exchange to ensure reliability of broadcast channel
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgReliabilityCheck<D: Digest>(pub digest::Output<D>);

#[derive(udigest::Digestable)]
#[udigest(tag = "dfns.cggmp21.keygen.threshold.Tag")]
struct Tag<'a> {
    party_index: u16,
    #[udigest(as_bytes)]
    sid: &'a [u8],
}

pub async fn run_threshold_keygen<E, R, M, L, D>(
    mut tracer: Option<&mut dyn Tracer>,
    i: u16,
    t: u16,
    n: u16,
    reliable_broadcast_enforced: bool,
    execution_id: ExecutionId<'_>,
    rng: &mut R,
    party: M,
) -> Result<IncompleteKeyShare<E>, KeygenError>
where
    E: Curve,
    L: SecurityLevel,
    D: Digest + Clone + 'static,
    R: RngCore + CryptoRng,
    M: Mpc<ProtocolMessage = Msg<E, L, D>>,
{
    tracer.protocol_begins();

    tracer.stage("Setup networking");
    let MpcParty { delivery, .. } = party.into_party();
    let (incomings, mut outgoings) = delivery.split();

    let mut rounds = RoundsRouter::<Msg<E, L, D>>::builder();
    let round1 = rounds.add_round(RoundInput::<MsgRound1<D>>::broadcast(i, n));
    let round1_sync = rounds.add_round(RoundInput::<MsgReliabilityCheck<D>>::broadcast(i, n));
    let round2_broad = rounds.add_round(RoundInput::<MsgRound2Broad<E, L>>::broadcast(i, n));
    let round2_uni = rounds.add_round(RoundInput::<MsgRound2Uni<E>>::p2p(i, n));
    let round3 = rounds.add_round(RoundInput::<MsgRound3<E>>::broadcast(i, n));
    let mut rounds = rounds.listen(incomings);

    // Round 1
    tracer.round_begins();

    tracer.stage("Compute execution id");
    let sid = execution_id.as_bytes();
    let tag = |j| {
        udigest::Tag::<D>::new_structured(&Tag {
            party_index: j,
            sid,
        })
    };
    let tag_i = tag(i);

    tracer.stage("Sample rid_i, schnorr commitment, polynomial");
    let mut rid = L::Rid::default();
    rng.fill_bytes(rid.as_mut());

    let (r, h) = schnorr_pok::prover_commits_ephemeral_secret::<E, _>(rng);

    let f = Polynomial::<SecretScalar<E>>::sample(rng, usize::from(t) - 1);
    let F = &f * &Point::generator();
    let sigmas = (0..n)
        .map(|j| {
            let x = Scalar::from(j + 1);
            f.value(&x)
        })
        .collect::<Vec<_>>();
    debug_assert_eq!(sigmas.len(), usize::from(n));

    tracer.stage("Commit to public data");
    let my_decommitment = MsgRound2Broad {
        rid,
        F: F.clone(),
        sch_commit: h,
        decommit: {
            let mut nonce = L::Rid::default();
            rng.fill_bytes(nonce.as_mut());
            nonce
        },
    };
    let hash_commit = tag_i.clone().digest(&my_decommitment);

    tracer.send_msg();
    let my_commitment = MsgRound1 {
        commitment: hash_commit,
    };
    outgoings
        .send(Outgoing::broadcast(Msg::Round1(my_commitment.clone())))
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
        let h_i =
            udigest::Tag::<D>::new(sid).digest_iter(commitments.iter_including_me(&my_commitment));

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
            .map(|(j, msg_id, _)| (j, msg_id))
            .collect::<Vec<_>>();
        if !parties_have_different_hashes.is_empty() {
            return Err(KeygenAborted::Round1NotReliable(parties_have_different_hashes).into());
        }
    }

    tracer.send_msg();
    outgoings
        .send(Outgoing::broadcast(Msg::Round2Broad(
            my_decommitment.clone(),
        )))
        .await
        .map_err(IoError::send_message)?;

    for j in utils::iter_peers(i, n) {
        let message = MsgRound2Uni {
            sigma: sigmas[usize::from(j)],
        };
        outgoings
            .send(Outgoing::p2p(j, Msg::Round2Uni(message)))
            .await
            .map_err(IoError::send_message)?;
    }
    tracer.msg_sent();

    // Round 3
    tracer.round_begins();

    tracer.receive_msgs();
    let decommitments = rounds
        .complete(round2_broad)
        .await
        .map_err(IoError::receive_message)?;
    let sigmas_msg = rounds
        .complete(round2_uni)
        .await
        .map_err(IoError::receive_message)?;
    tracer.msgs_received();

    tracer.stage("Validate decommitments");
    let blame = commitments
        .iter_indexed()
        .zip(decommitments.iter())
        .filter(|((j, _, commitment), decommitment)| {
            let com_expected = tag(*j).digest(&decommitment);
            commitment.commitment != com_expected
        })
        .map(|t| t.0 .0)
        .collect::<Vec<_>>();
    if !blame.is_empty() {
        return Err(KeygenAborted::InvalidDecommitment { parties: blame }.into());
    }

    tracer.stage("Validate data size");
    let blame = decommitments
        .iter_indexed()
        .filter(|(_, _, d)| d.F.degree() + 1 != usize::from(t))
        .map(|t| t.0)
        .collect::<Vec<_>>();
    if !blame.is_empty() {
        return Err(KeygenAborted::InvalidDataSize { parties: blame }.into());
    }

    tracer.stage("Validate Feldmann VSS");
    let blame = decommitments
        .iter_indexed()
        .zip(sigmas_msg.iter())
        .filter(|((_, _, d), s)| {
            d.F.value::<_, Point<_>>(&Scalar::from(i + 1)) != Point::generator() * s.sigma
        })
        .map(|t| t.0 .0)
        .collect::<Vec<_>>();
    if !blame.is_empty() {
        return Err(KeygenAborted::FeldmanVerificationFailed { parties: blame }.into());
    }

    tracer.stage("Compute rid");
    let rid = decommitments
        .iter_including_me(&my_decommitment)
        .map(|d| &d.rid)
        .fold(L::Rid::default(), utils::xor_array);
    tracer.stage("Compute Ys");
    let polynomial_sum = decommitments
        .iter_including_me(&my_decommitment)
        .map(|d| &d.F)
        .sum::<Polynomial<_>>();
    let ys = (0..n)
        .map(|l| polynomial_sum.value(&Scalar::from(l + 1)))
        .collect::<Vec<_>>();
    tracer.stage("Compute sigma");
    let sigma: Scalar<E> = sigmas_msg.iter().map(|msg| msg.sigma).sum();
    let mut sigma = sigma + sigmas[usize::from(i)];
    let sigma = SecretScalar::new(&mut sigma);
    debug_assert_eq!(Point::generator() * &sigma, ys[usize::from(i)]);

    tracer.stage("Calculate challenge");
    let challenge = {
        let hash = |d: D| {
            d.chain_update(sid)
                .chain_update(i.to_be_bytes())
                .chain_update(rid.as_ref())
                .chain_update(&ys[usize::from(i)].to_bytes(true)) // y_i
                .chain_update(&my_decommitment.sch_commit.0.to_bytes(false)) // h
                .finalize()
        };
        let mut rng = paillier_zk::rng::HashRng::new(hash);
        Scalar::random(&mut rng)
    };
    let challenge = schnorr_pok::Challenge { nonce: challenge };

    tracer.stage("Prove knowledge of `sigma_i`");
    let z = schnorr_pok::prove(&r, &challenge, &sigma);

    tracer.send_msg();
    let my_sch_proof = MsgRound3 { sch_proof: z };
    outgoings
        .send(Outgoing::broadcast(Msg::Round3(my_sch_proof.clone())))
        .await
        .map_err(IoError::send_message)?;
    tracer.msg_sent();

    // Output round
    tracer.round_begins();

    tracer.receive_msgs();
    let sch_proofs = rounds
        .complete(round3)
        .await
        .map_err(IoError::receive_message)?;
    tracer.msgs_received();

    tracer.stage("Validate schnorr proofs");
    let mut blame = vec![];
    for ((j, decommitment), sch_proof) in utils::iter_peers(i, n)
        .zip(decommitments.iter())
        .zip(sch_proofs.iter())
    {
        let challenge = {
            let hash = |d: D| {
                d.chain_update(sid)
                    .chain_update(j.to_be_bytes())
                    .chain_update(rid.as_ref())
                    .chain_update(&ys[usize::from(j)].to_bytes(true)) // y_i
                    .chain_update(&decommitment.sch_commit.0.to_bytes(false)) // h
                    .finalize()
            };
            let mut rng = paillier_zk::rng::HashRng::new(hash);
            Scalar::random(&mut rng)
        };
        let challenge = schnorr_pok::Challenge { nonce: challenge };
        if sch_proof
            .sch_proof
            .verify(&decommitment.sch_commit, &challenge, &ys[usize::from(j)])
            .is_err()
        {
            blame.push(j);
        }
    }
    if !blame.is_empty() {
        return Err(KeygenAborted::InvalidSchnorrProof { parties: blame }.into());
    }

    tracer.stage("Derive resulting public key and other data");
    let y: Point<E> = decommitments
        .iter_including_me(&my_decommitment)
        .map(|d| d.F.coefs()[0])
        .sum();
    let key_shares_indexes = (1..=n)
        .map(|i| NonZero::from_scalar(Scalar::from(i)))
        .collect::<Option<Vec<_>>>()
        .ok_or(Bug::NonZeroScalar)?;

    tracer.protocol_ends();

    Ok(DirtyIncompleteKeyShare {
        curve: Default::default(),
        i,
        shared_public_key: y,
        public_shares: ys,
        vss_setup: Some(VssSetup {
            min_signers: t,
            I: key_shares_indexes,
        }),
        x: sigma,
    }
    .try_into()
    .map_err(Bug::InvalidKeyShare)?)
}
