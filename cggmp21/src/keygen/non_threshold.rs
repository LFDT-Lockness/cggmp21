use digest::Digest;
use futures::SinkExt;
use generic_ec::{Curve, Point, Scalar, SecretScalar};
use generic_ec_zkp::{
    hash_commitment::{self, HashCommit},
    schnorr_pok,
};
use rand_core::{CryptoRng, RngCore};
use round_based::{
    rounds_router::simple_store::RoundInput, rounds_router::RoundsRouter, Delivery, Mpc, MpcParty,
    Outgoing, ProtocolMessage,
};
use serde::{Deserialize, Serialize};

use crate::progress::Tracer;
use crate::{
    errors::IoError,
    key_share::{DirtyIncompleteKeyShare, IncompleteKeyShare},
    security_level::SecurityLevel,
    utils::{hash_message, xor_array},
    ExecutionId,
};

use super::{Bug, KeygenAborted, KeygenError};

/// Message of key generation protocol
#[derive(ProtocolMessage, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum Msg<E: Curve, L: SecurityLevel, D: Digest> {
    /// Round 1 message
    Round1(MsgRound1<D>),
    /// Reliability check message (optional additional round)
    ReliabilityCheck(MsgReliabilityCheck<D>),
    /// Round 2 message
    Round2(MsgRound2<E, L, D>),
    /// Round 3 message
    Round3(MsgRound3<E>),
}

/// Message from round 1
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgRound1<D: Digest> {
    /// $V_i$
    pub commitment: HashCommit<D>,
}
/// Message from round 2
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgRound2<E: Curve, L: SecurityLevel, D: Digest> {
    /// `rid_i`
    #[serde(with = "hex::serde")]
    pub rid: L::Rid,
    /// $X_i$
    pub X: Point<E>,
    /// $A_i$
    pub sch_commit: schnorr_pok::Commit<E>,
    /// $u_i$
    pub decommit: hash_commitment::DecommitNonce<D>,
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

pub async fn run_keygen<E, R, M, L, D>(
    mut tracer: Option<&mut dyn Tracer>,
    i: u16,
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
    let round2 = rounds.add_round(RoundInput::<MsgRound2<E, L, D>>::broadcast(i, n));
    let round3 = rounds.add_round(RoundInput::<MsgRound3<E>>::broadcast(i, n));
    let mut rounds = rounds.listen(incomings);

    // Round 1
    tracer.round_begins();

    tracer.stage("Compute execution id");
    let sid = execution_id.as_bytes();

    tracer.stage("Sample x_i, rid_i");
    let x_i = SecretScalar::<E>::random(rng);
    let X_i = Point::generator() * &x_i;

    let mut rid = L::Rid::default();
    rng.fill_bytes(rid.as_mut());

    tracer.stage("Sample schnorr commitment");
    let (sch_secret, sch_commit) = schnorr_pok::prover_commits_ephemeral_secret::<E, _>(rng);

    tracer.stage("Commit to public data");
    let (hash_commit, decommit) = HashCommit::<D>::builder()
        .mix_bytes(sid)
        .mix(n)
        .mix(i)
        .mix_bytes(&rid)
        .mix(X_i)
        .mix(sch_commit.0)
        .commit(rng);

    let my_commitment = MsgRound1 {
        commitment: hash_commit,
    };

    tracer.send_msg();
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
        .map_err(IoError::receive_message)?
        .into_vec_including_me(my_commitment);
    tracer.msgs_received();

    // Optional reliability check
    if reliable_broadcast_enforced {
        tracer.stage("Hash received msgs (reliability check)");
        let h_i = commitments
            .iter()
            .try_fold(D::new(), hash_message)
            .map_err(Bug::HashMessage)?
            .finalize();

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
        let round1_hashes = rounds
            .complete(round1_sync)
            .await
            .map_err(IoError::receive_message)?;
        tracer.msgs_received();

        tracer.stage("Assert other parties hashed messages (reliability check)");
        let parties_have_different_hashes = round1_hashes
            .into_iter_indexed()
            .filter(|(_j, _msg_id, hash_j)| hash_j.0 != h_i)
            .map(|(j, msg_id, _)| (j, msg_id))
            .collect::<Vec<_>>();
        if !parties_have_different_hashes.is_empty() {
            return Err(KeygenAborted::Round1NotReliable(parties_have_different_hashes).into());
        }
    }

    let my_decommitment = MsgRound2 {
        rid,
        X: X_i,
        sch_commit,
        decommit,
    };
    tracer.send_msg();
    outgoings
        .send(Outgoing::broadcast(Msg::Round2(my_decommitment.clone())))
        .await
        .map_err(IoError::send_message)?;
    tracer.msg_sent();

    // Round 3
    tracer.round_begins();

    tracer.receive_msgs();
    let decommitments = rounds
        .complete(round2)
        .await
        .map_err(IoError::receive_message)?
        .into_vec_including_me(my_decommitment);
    tracer.msgs_received();

    tracer.stage("Validate decommitments");
    let blame = (0u16..)
        .zip(&commitments)
        .zip(&decommitments)
        .filter(|((j, commitment), decommitment)| {
            HashCommit::<D>::builder()
                .mix_bytes(sid)
                .mix(n)
                .mix(j)
                .mix_bytes(&decommitment.rid)
                .mix(decommitment.X)
                .mix(decommitment.sch_commit.0)
                .verify(&commitment.commitment, &decommitment.decommit)
                .is_err()
        })
        .map(|((j, _), _)| j)
        .collect::<Vec<_>>();
    if !blame.is_empty() {
        return Err(KeygenAborted::InvalidDecommitment { parties: blame }.into());
    }

    tracer.stage("Calculate challege rid");
    let rid = decommitments
        .iter()
        .map(|d| &d.rid)
        .fold(L::Rid::default(), xor_array);
    let challenge = {
        let hash = |d: D| {
            d.chain_update(sid)
                .chain_update(i.to_be_bytes())
                .chain_update(rid.as_ref())
                .finalize()
        };
        let mut rng = paillier_zk::rng::HashRng::new(hash);
        Scalar::random(&mut rng)
    };
    let challenge = schnorr_pok::Challenge { nonce: challenge };

    tracer.stage("Prove knowledge of `x_i`");
    let sch_proof = schnorr_pok::prove(&sch_secret, &challenge, &x_i);

    tracer.send_msg();
    let my_sch_proof = MsgRound3 { sch_proof };
    outgoings
        .send(Outgoing::broadcast(Msg::Round3(my_sch_proof.clone())))
        .await
        .map_err(IoError::send_message)?;
    tracer.msg_sent();

    // Round 4
    tracer.round_begins();

    tracer.receive_msgs();
    let sch_proofs = rounds
        .complete(round3)
        .await
        .map_err(IoError::receive_message)?
        .into_vec_including_me(my_sch_proof);
    tracer.msgs_received();

    tracer.stage("Validate schnorr proofs");
    let mut blame = vec![];
    for ((j, decommitment), sch_proof) in (0u16..).zip(&decommitments).zip(&sch_proofs) {
        let challenge = {
            let hash = |d: D| {
                d.chain_update(sid)
                    .chain_update(j.to_be_bytes())
                    .chain_update(rid.as_ref())
                    .finalize()
            };
            let mut rng = paillier_zk::rng::HashRng::new(hash);
            Scalar::random(&mut rng)
        };
        let challenge = schnorr_pok::Challenge { nonce: challenge };
        if sch_proof
            .sch_proof
            .verify(&decommitment.sch_commit, &challenge, &decommitment.X)
            .is_err()
        {
            blame.push(j);
        }
    }
    if !blame.is_empty() {
        return Err(KeygenAborted::InvalidSchnorrProof { parties: blame }.into());
    }

    tracer.protocol_ends();

    Ok(DirtyIncompleteKeyShare {
        curve: Default::default(),
        i,
        shared_public_key: decommitments.iter().map(|d| d.X).sum(),
        public_shares: decommitments.iter().map(|d| d.X).collect(),
        x: x_i,
        vss_setup: None,
    }
    .try_into()
    .map_err(Bug::InvalidKeyShare)?)
}
