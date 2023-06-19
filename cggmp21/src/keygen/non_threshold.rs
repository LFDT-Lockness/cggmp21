use digest::Digest;
use futures::SinkExt;
use generic_ec::hash_to_curve::{self, FromHash};
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
    Round1(MsgRound1<D>),
    ReliabilityCheck(MsgReliabilityCheck<D>),
    Round2(MsgRound2<E, L, D>),
    Round3(MsgRound3<E>),
}

/// Message from round 1
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgRound1<D: Digest> {
    pub commitment: HashCommit<D>,
}
/// Message from round 2
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgRound2<E: Curve, L: SecurityLevel, D: Digest> {
    #[serde(with = "hex::serde")]
    pub rid: L::Rid,
    pub X: Point<E>,
    pub sch_commit: schnorr_pok::Commit<E>,
    pub decommit: hash_commitment::DecommitNonce<D>,
}
/// Message from round 3
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgRound3<E: Curve> {
    pub sch_proof: schnorr_pok::Proof<E>,
}
/// Message parties exchange to ensure reliability of broadcast channel
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgReliabilityCheck<D: Digest>(pub digest::Output<D>);

pub async fn run_keygen<E, R, M, L, D>(
    i: u16,
    n: u16,
    reliable_broadcast_enforced: bool,
    execution_id: ExecutionId<'_>,
    rng: &mut R,
    party: M,
) -> Result<IncompleteKeyShare<E>, KeygenError>
where
    E: Curve,
    Scalar<E>: FromHash,
    L: SecurityLevel,
    D: Digest + Clone + 'static,
    R: RngCore + CryptoRng,
    M: Mpc<ProtocolMessage = Msg<E, L, D>>,
{
    let MpcParty { delivery, .. } = party.into_party();
    let (incomings, mut outgoings) = delivery.split();

    // Setup networking
    let mut rounds = RoundsRouter::<Msg<E, L, D>>::builder();
    let round1 = rounds.add_round(RoundInput::<MsgRound1<D>>::broadcast(i, n));
    let round1_sync = rounds.add_round(RoundInput::<MsgReliabilityCheck<D>>::broadcast(i, n));
    let round2 = rounds.add_round(RoundInput::<MsgRound2<E, L, D>>::broadcast(i, n));
    let round3 = rounds.add_round(RoundInput::<MsgRound3<E>>::broadcast(i, n));
    let mut rounds = rounds.listen(incomings);

    // Round 1
    let sid = execution_id.as_bytes();
    let tag_htc = hash_to_curve::Tag::new(sid).ok_or(Bug::InvalidHashToCurveTag)?;

    let x_i = SecretScalar::<E>::random(rng);
    let X_i = Point::generator() * &x_i;

    let mut rid = L::Rid::default();
    rng.fill_bytes(rid.as_mut());

    let (sch_secret, sch_commit) = schnorr_pok::prover_commits_ephemeral_secret::<E, _>(rng);

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
    outgoings
        .send(Outgoing::broadcast(Msg::Round1(my_commitment.clone())))
        .await
        .map_err(IoError::send_message)?;

    // Round 2
    let commitments = rounds
        .complete(round1)
        .await
        .map_err(IoError::receive_message)?
        .into_vec_including_me(my_commitment);

    // Optional reliability check
    if reliable_broadcast_enforced {
        let h_i = commitments
            .iter()
            .try_fold(D::new(), hash_message)
            .map_err(Bug::HashMessage)?
            .finalize();
        outgoings
            .send(Outgoing::broadcast(Msg::ReliabilityCheck(
                MsgReliabilityCheck(h_i.clone()),
            )))
            .await
            .map_err(IoError::send_message)?;

        let round1_hashes = rounds
            .complete(round1_sync)
            .await
            .map_err(IoError::receive_message)?;
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
    outgoings
        .send(Outgoing::broadcast(Msg::Round2(my_decommitment.clone())))
        .await
        .map_err(IoError::send_message)?;

    // Round 3
    let decommitments = rounds
        .complete(round2)
        .await
        .map_err(IoError::receive_message)?
        .into_vec_including_me(my_decommitment);

    // Validate decommitments
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

    // Calculate challenge
    let rid = decommitments
        .iter()
        .map(|d| &d.rid)
        .fold(L::Rid::default(), xor_array);
    let challenge = Scalar::<E>::hash_concat(tag_htc, &[&i.to_be_bytes(), rid.as_ref()])
        .map_err(Bug::HashToScalarError)?;
    let challenge = schnorr_pok::Challenge { nonce: challenge };

    // Prove knowledge of `x_i`
    let sch_proof = schnorr_pok::prove(&sch_secret, &challenge, &x_i);

    let my_sch_proof = MsgRound3 { sch_proof };
    outgoings
        .send(Outgoing::broadcast(Msg::Round3(my_sch_proof.clone())))
        .await
        .map_err(IoError::send_message)?;

    // Round 4
    let sch_proofs = rounds
        .complete(round3)
        .await
        .map_err(IoError::receive_message)?
        .into_vec_including_me(my_sch_proof);

    let mut blame = vec![];
    for ((j, decommitment), sch_proof) in (0u16..).zip(&decommitments).zip(&sch_proofs) {
        let challenge = Scalar::<E>::hash_concat(tag_htc, &[&j.to_be_bytes(), rid.as_ref()])
            .map(|challenge| schnorr_pok::Challenge { nonce: challenge })
            .map_err(Bug::HashToScalarError)?;
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
