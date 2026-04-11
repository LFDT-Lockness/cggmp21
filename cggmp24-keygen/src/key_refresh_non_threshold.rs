use alloc::vec::Vec;

use digest::Digest;
use generic_ec::{Curve, NonZero, Point, Scalar, SecretScalar};
use generic_ec_zkp::schnorr_pok;
use rand_core::{CryptoRng, RngCore};
use round_based::{
    rounds_router::simple_store::RoundInput, rounds_router::RoundsRouter, Delivery, Mpc, MpcParty,
    Outgoing, ProtocolMessage, SinkExt,
};
use serde::{Deserialize, Serialize};

use crate::progress::Tracer;
use crate::{
    errors::IoError,
    key_share::{CoreKeyShare, DirtyCoreKeyShare, DirtyKeyInfo, Validate},
    security_level::SecurityLevel,
    utils, ExecutionId,
};

use super::{Bug, KeyRefreshAborted, KeyRefreshError};

macro_rules! prefixed {
    ($name:tt) => {
        concat!("dfns.cggmp24.key_refresh.non_threshold.", $name)
    };
}

/// Message of non-threshold key refresh protocol
#[derive(ProtocolMessage, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum Msg<E: Curve, L: SecurityLevel, D: Digest> {
    /// Round 1 message
    Round1(MsgRound1<D>),
    /// Reliability check message (optional additional round)
    ReliabilityCheck(MsgReliabilityCheck<D>),
    /// Round 2 broadcast message
    Round2Broad(MsgRound2Broad<E, L>),
    /// Round 2 unicast message
    Round2Uni(MsgRound2Uni<E>),
    /// Round 3 message
    Round3(MsgRound3<E>),
}

/// Message from round 1
#[derive(Clone, Serialize, Deserialize, udigest::Digestable)]
#[serde(bound = "")]
#[udigest(bound = "")]
#[udigest(tag = prefixed!("round1"))]
pub struct MsgRound1<D: Digest> {
    /// $V_i$
    #[udigest(as_bytes)]
    pub commitment: digest::Output<D>,
}
/// Message from round 2 broadcasted to everyone
#[serde_with::serde_as]
#[derive(Clone, Serialize, Deserialize, udigest::Digestable)]
#[serde(bound = "")]
#[udigest(bound = "")]
#[udigest(tag = prefixed!("round2_broad"))]
pub struct MsgRound2Broad<E: Curve, L: SecurityLevel> {
    /// `rid_i`
    #[serde_as(as = "utils::HexOrBin")]
    #[udigest(as_bytes)]
    pub rid: L::KappaBytes,
    /// $X_{i,j}$ — public commitments to per-party share updates
    pub X_updates: Vec<Point<E>>,
    /// $A_i$
    pub sch_commit: schnorr_pok::Commit<E>,
    /// $u_i$
    #[serde(with = "hex::serde")]
    #[udigest(as_bytes)]
    pub decommit: L::KappaBytes,
}
/// Message from round 2 unicasted to each party
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgRound2Uni<E: Curve> {
    /// $x_{i,j}$ — secret share update for party $j$
    pub x_update: Scalar<E>,
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

mod unambiguous {
    use crate::{ExecutionId, SecurityLevel};
    use generic_ec::Curve;

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("hash_commitment"))]
    #[udigest(bound = "")]
    pub struct HashCom<'a, E: Curve, L: SecurityLevel> {
        pub sid: ExecutionId<'a>,
        pub party_index: u16,
        pub decommitment: &'a super::MsgRound2Broad<E, L>,
    }

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("schnorr_pok"))]
    #[udigest(bound = "")]
    pub struct SchnorrPok<'a, E: Curve> {
        pub sid: ExecutionId<'a>,
        pub prover: u16,
        #[udigest(as_bytes)]
        pub rid: &'a [u8],
        pub X: &'a generic_ec::Point<E>,
        pub sch_commit: &'a generic_ec_zkp::schnorr_pok::Commit<E>,
    }

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("echo_round"))]
    #[udigest(bound = "")]
    pub struct Echo<'a, D: digest::Digest> {
        pub sid: ExecutionId<'a>,
        pub commitment: &'a super::MsgRound1<D>,
    }
}

/// Run non-threshold key refresh protocol (Figure 7 of CGGMP24, share-update only)
///
/// Each party i generates random values $x_{i,j}$ for all j with $\sum_j x_{i,j} = 0$,
/// sends $x_{i,j}$ privately to party j, and broadcasts commitments $X_{i,j} = g^{x_{i,j}}$.
/// Party j's new share is $x_j' = x_j + \sum_i x_{i,j}$.
/// The shared secret key is preserved since $\sum_j x_j' = \sum_j x_j + \sum_j \sum_i x_{i,j} = x$.
pub async fn run_key_refresh<E, R, M, L, D>(
    mut tracer: Option<&mut dyn Tracer>,
    i: u16,
    n: u16,
    reliable_broadcast_enforced: bool,
    sid: ExecutionId<'_>,
    rng: &mut R,
    party: M,
    current_key_share: &CoreKeyShare<E>,
) -> Result<CoreKeyShare<E>, KeyRefreshError>
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

    tracer.stage("Sample per-party share updates x_{i,j}");
    // Each party i picks random x_{i,j} for j != i, then sets x_{i,i} = -sum_{j!=i} x_{i,j}
    // so that sum_j x_{i,j} = 0
    let mut x_updates = Vec::with_capacity(usize::from(n));
    let mut sum = Scalar::<E>::zero();
    for j in 0..n {
        if j == i {
            x_updates.push(Scalar::<E>::zero()); // placeholder
        } else {
            let val = Scalar::<E>::random(rng);
            sum = sum + val;
            x_updates.push(val);
        }
    }
    x_updates[usize::from(i)] = -sum;

    // Compute public commitments X_{i,j} = g^{x_{i,j}}
    let X_updates: Vec<Point<E>> = x_updates
        .iter()
        .map(|x| Point::generator() * x)
        .collect();

    // The sum of X_{i,j} for my row should be the identity (zero point)
    debug_assert!(X_updates.iter().copied().sum::<Point<E>>().is_zero());

    // For the Schnorr proof, we prove knowledge of x_{i,i} (our self-update)
    let my_x_self_update = x_updates[usize::from(i)];
    let my_X_self_update = X_updates[usize::from(i)];

    let mut rid = L::KappaBytes::default();
    rng.fill_bytes(rid.as_mut());

    tracer.stage("Sample schnorr commitment");
    let (sch_secret, sch_commit) = schnorr_pok::prover_commits_ephemeral_secret::<E, _>(rng);

    tracer.stage("Commit to public data");
    let my_decommitment = MsgRound2Broad {
        rid,
        X_updates: X_updates.clone(),
        sch_commit: sch_commit.clone(),
        decommit: {
            let mut nonce = L::KappaBytes::default();
            rng.fill_bytes(nonce.as_mut());
            nonce
        },
    };
    let hash_commit = udigest::hash::<D>(&unambiguous::HashCom {
        sid,
        party_index: i,
        decommitment: &my_decommitment,
    });
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
        .map_err(IoError::receive_message)?;
    tracer.msgs_received();

    // Optional reliability check
    if reliable_broadcast_enforced {
        tracer.stage("Hash received msgs (reliability check)");
        let h_i = udigest::hash_iter::<D>(
            commitments
                .iter_including_me(&my_commitment)
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
            return Err(
                KeyRefreshAborted::Round1NotReliable(parties_have_different_hashes).into(),
            );
        }
    }

    tracer.send_msg();
    outgoings
        .feed(Outgoing::broadcast(Msg::Round2Broad(
            my_decommitment.clone(),
        )))
        .await
        .map_err(IoError::send_message)?;

    // Send p2p share updates x_{i,j} to each party j
    let messages = utils::iter_peers(i, n).map(|j| {
        let message = MsgRound2Uni {
            x_update: x_updates[usize::from(j)],
        };
        Outgoing::p2p(j, Msg::Round2Uni(message))
    });
    outgoings
        .send_all(&mut futures_util::stream::iter(messages.map(Ok)))
        .await
        .map_err(IoError::send_message)?;
    tracer.msg_sent();

    // Round 3
    tracer.round_begins();

    tracer.receive_msgs();
    let decommitments = rounds
        .complete(round2_broad)
        .await
        .map_err(IoError::receive_message)?;
    let x_updates_received = rounds
        .complete(round2_uni)
        .await
        .map_err(IoError::receive_message)?;
    tracer.msgs_received();

    tracer.stage("Validate decommitments");
    let blame = utils::collect_blame(&commitments, &decommitments, |j, com, decom| {
        let com_expected = udigest::hash::<D>(&unambiguous::HashCom {
            sid,
            party_index: j,
            decommitment: decom,
        });
        com.commitment != com_expected
    });
    if !blame.is_empty() {
        return Err(KeyRefreshAborted::InvalidDecommitment(blame).into());
    }

    tracer.stage("Validate data sizes");
    let blame = decommitments
        .iter_indexed()
        .filter(|(_, _, d)| d.X_updates.len() != usize::from(n))
        .map(|t| t.0)
        .collect::<Vec<_>>();
    if !blame.is_empty() {
        return Err(KeyRefreshAborted::InvalidDataSize { parties: blame }.into());
    }

    tracer.stage("Verify row sums of X_{j,*} are zero (updates preserve public key)");
    let blame = decommitments
        .iter_indexed()
        .filter(|(_, _, d)| !d.X_updates.iter().copied().sum::<Point<E>>().is_zero())
        .map(|t| t.0)
        .collect::<Vec<_>>();
    if !blame.is_empty() {
        return Err(KeyRefreshAborted::UpdatesDontSumToZero { parties: blame }.into());
    }

    tracer.stage("Verify received share updates against public commitments");
    // Each received x_{j,i} should satisfy g^{x_{j,i}} == X_{j,i}
    let blame = decommitments
        .iter_indexed()
        .zip(x_updates_received.iter())
        .filter(|((_, _, d), msg)| {
            d.X_updates[usize::from(i)] != Point::generator() * msg.x_update
        })
        .map(|t| t.0 .0)
        .collect::<Vec<_>>();
    if !blame.is_empty() {
        return Err(KeyRefreshAborted::ShareUpdateVerificationFailed { parties: blame }.into());
    }

    tracer.stage("Calculate challenge rid");
    let rid = decommitments
        .iter_including_me(&my_decommitment)
        .map(|d| &d.rid)
        .fold(L::KappaBytes::default(), utils::xor_array);
    let challenge = Scalar::from_hash::<D>(&unambiguous::SchnorrPok {
        sid,
        prover: i,
        rid: rid.as_ref(),
        X: &my_X_self_update,
        sch_commit: &sch_commit,
    });
    let challenge = schnorr_pok::Challenge { nonce: challenge };

    tracer.stage("Prove knowledge of self-update x_{i,i}");
    let sch_proof = schnorr_pok::prove(&sch_secret, &challenge, &my_x_self_update);

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
        .map_err(IoError::receive_message)?;
    tracer.msgs_received();

    tracer.stage("Validate schnorr proofs");
    let blame = utils::collect_blame(&decommitments, &sch_proofs, |j, decom, sch_proof| {
        let X_j_self = decom.X_updates[usize::from(j)];
        let challenge = Scalar::from_hash::<D>(&unambiguous::SchnorrPok {
            sid,
            prover: j,
            rid: rid.as_ref(),
            X: &X_j_self,
            sch_commit: &decom.sch_commit,
        });
        let challenge = schnorr_pok::Challenge { nonce: challenge };
        sch_proof
            .sch_proof
            .verify(&decom.sch_commit, &challenge, &X_j_self)
            .is_err()
    });
    if !blame.is_empty() {
        return Err(KeyRefreshAborted::InvalidSchnorrProof(blame).into());
    }

    tracer.stage("Compute updated key share");
    // New secret share: x_i' = x_i + sum_j x_{j,i}
    // = x_i + x_{i,i} + sum_{j!=i} x_{j,i}
    let total_update: Scalar<E> = x_updates_received.iter().map(|msg| msg.x_update).sum();
    let old_x: &Scalar<E> = current_key_share.x.as_ref();
    let mut new_x = *old_x + my_x_self_update + total_update;
    let new_x =
        NonZero::from_secret_scalar(SecretScalar::new(&mut new_x)).ok_or(Bug::ZeroShare)?;

    // New public shares: X_j' = X_j + sum_i X_{i,j}
    let new_public_shares = (0..n)
        .map(|j| {
            let j_idx = usize::from(j);
            let old_X_j = current_key_share.public_shares[j_idx];
            let update_sum: Point<E> = decommitments
                .iter_including_me(&my_decommitment)
                .map(|d| d.X_updates[j_idx])
                .sum();
            NonZero::from_point(*old_X_j + update_sum).ok_or(Bug::ZeroShare)
        })
        .collect::<Result<Vec<_>, _>>()?;

    tracer.protocol_ends();

    Ok(DirtyCoreKeyShare {
        i,
        key_info: DirtyKeyInfo {
            curve: Default::default(),
            shared_public_key: current_key_share.shared_public_key,
            public_shares: new_public_shares,
            vss_setup: None,
            #[cfg(feature = "hd-wallet")]
            chain_code: current_key_share.chain_code,
        },
        x: new_x,
    }
    .validate()
    .map_err(|e| Bug::InvalidKeyShare(e.into_error()))?)
}
