//! Non-threshold (n-of-n) key share refresh protocol
//!
//! Implements the share-refresh portion of CGGMP24 Figure 7, omitting
//! auxiliary data generation per [issue #162](https://github.com/LFDT-Lockness/cggmp21/issues/162).
//!
//! # Protocol
//!
//! All $n$ parties hold additive shares $x_i$ with $\sum x_i = x$.
//! Each party $i$ samples random values $\{x_i^{(j)}\}_{j=1..n}$ such
//! that $\sum_j x_i^{(j)} = 0$, creating a zero-sum contribution
//! for each party. After commit-decommit and Feldman verification,
//! each party computes:
//! $$x_i' = x_i + \sum_j x_j^{(i)}$$
//!
//! The secret is preserved because:
//! $$\sum_i x_i' = \sum_i x_i + \sum_i \sum_j x_j^{(i)} = x + \sum_j \sum_i x_j^{(i)} = x + \sum_j 0 = x$$
//!
//! # Rounds
//!
//! 1. **Commit**: hash commitment to public data and Schnorr commit
//! 2. **(Optional) Reliability check**: echo-broadcast
//! 3. **Decommit + P2P shares**: broadcast public commitments, unicast secret evaluations
//! 4. **Prove**: Schnorr proof of knowledge of new secret share

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

use super::{KeyRefreshError, RefreshAborted, RefreshBug};

macro_rules! prefixed {
    ($name:tt) => {
        concat!("dfns.cggmp24.key_refresh.non_threshold.", $name)
    };
}

/// Message of non-threshold key refresh protocol
#[derive(ProtocolMessage, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum Msg<E: Curve, L: SecurityLevel, D: Digest> {
    /// Round 1: hash commitment
    Round1(MsgRound1<D>),
    /// Reliability check message (optional)
    ReliabilityCheck(MsgReliabilityCheck<D>),
    /// Round 2a: decommitment (broadcast)
    Round2Broad(MsgRound2Broad<E, L>),
    /// Round 2b: secret share (P2P unicast)
    Round2Uni(MsgRound2Uni<E>),
    /// Round 3: Schnorr proof
    Round3(MsgRound3<E>),
}

/// Round 1 commitment message
#[derive(Clone, Serialize, Deserialize, udigest::Digestable)]
#[serde(bound = "")]
#[udigest(bound = "")]
#[udigest(tag = prefixed!("round1"))]
pub struct MsgRound1<D: Digest> {
    /// Hash commitment $V_i$
    #[udigest(as_bytes)]
    pub commitment: digest::Output<D>,
}

/// Round 2 broadcast: public commitments to zero-sum contributions
#[serde_with::serde_as]
#[derive(Clone, Serialize, Deserialize, udigest::Digestable)]
#[serde(bound = "")]
#[udigest(bound = "")]
#[udigest(tag = prefixed!("round2_broad"))]
pub struct MsgRound2Broad<E: Curve, L: SecurityLevel> {
    /// Random identifier contribution $rid_i$
    #[serde_as(as = "utils::HexOrBin")]
    #[udigest(as_bytes)]
    pub rid: L::KappaBytes,
    /// Public commitments $X_i^{(j)} = x_i^{(j)} \cdot G$ for all $j$
    pub X_contributions: Vec<Point<E>>,
    /// Schnorr commitment $A_i$
    pub sch_commit: schnorr_pok::Commit<E>,
    /// Decommitment nonce $u_i$
    #[serde(with = "hex::serde")]
    #[udigest(as_bytes)]
    pub decommit: L::KappaBytes,
}

/// Round 2 unicast: secret share contribution
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgRound2Uni<E: Curve> {
    /// $x_i^{(j)}$ — party $i$'s contribution to party $j$'s new share
    pub contribution: Scalar<E>,
}

/// Round 3: Schnorr proof of knowledge of new share
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgRound3<E: Curve> {
    /// Schnorr proof $\psi_i$
    pub sch_proof: schnorr_pok::Proof<E>,
}

/// Reliability check echo message
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgReliabilityCheck<D: Digest>(pub digest::Output<D>);

mod unambiguous {
    use crate::{ExecutionId, SecurityLevel};
    use generic_ec::{Curve, NonZero, Point};

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
        pub y: NonZero<Point<E>>,
        pub h: Point<E>,
    }

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("echo_round"))]
    #[udigest(bound = "")]
    pub struct Echo<'a, D: digest::Digest> {
        pub sid: ExecutionId<'a>,
        pub commitment: &'a super::MsgRound1<D>,
    }
}

/// Runs the non-threshold key refresh protocol following CGGMP24 Figure 7.
///
/// Takes an existing n-of-n key share and produces a new share with the
/// same public key but a different secret share value.
///
/// # Panics (debug)
/// Panics if `old_key_share` has `vss_setup` set (i.e., is a threshold share).
pub async fn run_key_refresh<E, R, M, L, D>(
    mut tracer: Option<&mut dyn Tracer>,
    old_key_share: &CoreKeyShare<E>,
    reliable_broadcast_enforced: bool,
    sid: ExecutionId<'_>,
    rng: &mut R,
    party: M,
) -> Result<CoreKeyShare<E>, KeyRefreshError>
where
    E: Curve,
    L: SecurityLevel,
    D: Digest + Clone + 'static,
    R: RngCore + CryptoRng,
    M: Mpc<ProtocolMessage = Msg<E, L, D>>,
{
    let i = old_key_share.i;
    let n = old_key_share.key_info.public_shares.len() as u16;

    debug_assert!(
        old_key_share.vss_setup.is_none(),
        "non-threshold refresh called on threshold key share"
    );

    tracer.protocol_begins();

    // ===== Setup =====
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

    // ===== Round 1: Sample zero-sum contributions and commit =====
    tracer.round_begins();

    tracer.stage("Sample rid, Schnorr commitment, zero-sum contributions");
    let mut rid = L::KappaBytes::default();
    rng.fill_bytes(rid.as_mut());

    let (sch_r, sch_h) = schnorr_pok::prover_commits_ephemeral_secret::<E, _>(rng);

    // Sample n-1 random scalars, then set the n-th so the total sums to zero.
    // x_contributions[j] is party i's contribution to party j's refresh delta.
    let mut x_contributions: Vec<Scalar<E>> = (0..n - 1)
        .map(|_| *SecretScalar::<E>::random(rng).as_ref())
        .collect();
    let partial_sum: Scalar<E> = x_contributions.iter().copied().sum();
    x_contributions.push(-partial_sum);
    debug_assert_eq!(x_contributions.len(), usize::from(n));

    // Public commitments X_i^(j) = x_i^(j) * G
    let X_contributions: Vec<Point<E>> = x_contributions
        .iter()
        .map(|s| Point::generator() * s)
        .collect();

    tracer.stage("Compute hash commitment");
    let my_decommitment = MsgRound2Broad {
        rid,
        X_contributions: X_contributions.clone(),
        sch_commit: sch_h,
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

    tracer.send_msg();
    let my_commitment = MsgRound1 {
        commitment: hash_commit,
    };
    outgoings
        .send(Outgoing::broadcast(Msg::Round1(my_commitment.clone())))
        .await
        .map_err(IoError::send_message)?;
    tracer.msg_sent();

    // ===== Round 2: Decommit + P2P =====
    tracer.round_begins();

    tracer.receive_msgs();
    let commitments = rounds
        .complete(round1)
        .await
        .map_err(IoError::receive_message)?;
    tracer.msgs_received();

    if reliable_broadcast_enforced {
        tracer.stage("Reliability check: hash round-1 messages");
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
        let hashes = rounds
            .complete(round1_sync)
            .await
            .map_err(IoError::receive_message)?;
        tracer.msgs_received();

        tracer.stage("Reliability check: verify echo hashes");
        let mismatched = hashes
            .into_iter_indexed()
            .filter(|(_j, _msg_id, h_j)| h_i != h_j.0)
            .map(|(j, msg_id, _)| (j, msg_id))
            .collect::<Vec<_>>();
        if !mismatched.is_empty() {
            return Err(RefreshAborted::Round1NotReliable(mismatched).into());
        }
    }

    tracer.send_msg();
    outgoings
        .feed(Outgoing::broadcast(Msg::Round2Broad(
            my_decommitment.clone(),
        )))
        .await
        .map_err(IoError::send_message)?;

    // Unicast x_i^(j) to each peer j
    let p2p_messages = utils::iter_peers(i, n).map(|j| {
        Outgoing::p2p(
            j,
            Msg::Round2Uni(MsgRound2Uni {
                contribution: x_contributions[usize::from(j)],
            }),
        )
    });
    outgoings
        .send_all(&mut futures_util::stream::iter(p2p_messages.map(Ok)))
        .await
        .map_err(IoError::send_message)?;
    tracer.msg_sent();

    // ===== Round 3: Verify and Prove =====
    tracer.round_begins();

    tracer.receive_msgs();
    let decommitments = rounds
        .complete(round2_broad)
        .await
        .map_err(IoError::receive_message)?;
    let contributions_msg = rounds
        .complete(round2_uni)
        .await
        .map_err(IoError::receive_message)?;
    tracer.msgs_received();

    tracer.stage("Validate decommitments");
    let blame = utils::collect_blame(&commitments, &decommitments, |j, com, decom| {
        let expected = udigest::hash::<D>(&unambiguous::HashCom {
            sid,
            party_index: j,
            decommitment: decom,
        });
        com.commitment != expected
    });
    if !blame.is_empty() {
        return Err(RefreshAborted::InvalidDecommitment(blame).into());
    }

    tracer.stage("Validate contribution vector lengths");
    let blame = decommitments
        .iter_indexed()
        .filter(|(_, _, d)| d.X_contributions.len() != usize::from(n))
        .map(|(j, _, _)| j)
        .collect::<Vec<_>>();
    if !blame.is_empty() {
        return Err(RefreshAborted::InvalidDataSize { parties: blame }.into());
    }

    tracer.stage("Validate zero-sum property of public contributions");
    let blame = decommitments
        .iter_indexed()
        .filter(|(_, _, d)| {
            let sum: Point<E> = d.X_contributions.iter().copied().sum();
            sum != Point::zero()
        })
        .map(|(j, _, _)| j)
        .collect::<Vec<_>>();
    if !blame.is_empty() {
        return Err(RefreshAborted::InvalidDataSize { parties: blame }.into());
    }

    tracer.stage("Validate Feldman (unicast matches public commitment)");
    // For each peer j: verify x_j^(i) * G == X_j^(i)
    let blame = decommitments
        .iter_indexed()
        .zip(contributions_msg.iter())
        .filter(|((_, _, d), c)| {
            d.X_contributions[usize::from(i)] != Point::generator() * c.contribution
        })
        .map(|((j, _, _), _)| j)
        .collect::<Vec<_>>();
    if !blame.is_empty() {
        return Err(RefreshAborted::FeldmanVerificationFailed { parties: blame }.into());
    }

    tracer.stage("Compute joint rid");
    let rid = decommitments
        .iter_including_me(&my_decommitment)
        .map(|d| &d.rid)
        .fold(L::KappaBytes::default(), utils::xor_array);

    tracer.stage("Compute refreshed secret share");
    // x_i' = x_i + sum_j x_j^(i)  (including own contribution)
    let contrib_from_others: Scalar<E> = contributions_msg.iter().map(|m| m.contribution).sum();
    let contrib_from_self = x_contributions[usize::from(i)];
    let mut new_x_scalar: Scalar<E> = contrib_from_others + contrib_from_self + &old_key_share.x;
    let new_x = SecretScalar::new(&mut new_x_scalar);
    let new_x = NonZero::from_secret_scalar(new_x).ok_or(RefreshBug::ZeroShare)?;

    tracer.stage("Compute new public shares");
    // For each party l: X_l' = X_l + sum_j X_j^(l)
    let new_public_shares: Vec<NonZero<Point<E>>> = (0..n)
        .map(|l| {
            let refresh_sum: Point<E> = decommitments
                .iter_including_me(&my_decommitment)
                .map(|d| d.X_contributions[usize::from(l)])
                .sum();
            let new_pub = old_key_share.key_info.public_shares[usize::from(l)] + refresh_sum;
            NonZero::from_point(new_pub).ok_or(RefreshBug::ZeroShare)
        })
        .collect::<Result<Vec<_>, _>>()?;

    tracer.stage("Prove knowledge of new share");
    let challenge = Scalar::from_hash::<D>(&unambiguous::SchnorrPok {
        sid,
        prover: i,
        rid: rid.as_ref(),
        y: new_public_shares[usize::from(i)],
        h: my_decommitment.sch_commit.0,
    });
    let challenge = schnorr_pok::Challenge { nonce: challenge };
    let sch_proof = schnorr_pok::prove(&sch_r, &challenge, &new_x);

    tracer.send_msg();
    outgoings
        .send(Outgoing::broadcast(Msg::Round3(MsgRound3 {
            sch_proof: sch_proof.clone(),
        })))
        .await
        .map_err(IoError::send_message)?;
    tracer.msg_sent();

    // ===== Output: Verify Schnorr proofs =====
    tracer.round_begins();

    tracer.receive_msgs();
    let sch_proofs = rounds
        .complete(round3)
        .await
        .map_err(IoError::receive_message)?;
    tracer.msgs_received();

    tracer.stage("Validate Schnorr proofs");
    let blame = utils::collect_blame(&decommitments, &sch_proofs, |j, decom, proof| {
        let ch = Scalar::from_hash::<D>(&unambiguous::SchnorrPok {
            sid,
            prover: j,
            rid: rid.as_ref(),
            y: new_public_shares[usize::from(j)],
            h: decom.sch_commit.0,
        });
        let ch = schnorr_pok::Challenge { nonce: ch };
        proof
            .sch_proof
            .verify(&decom.sch_commit, &ch, &new_public_shares[usize::from(j)])
            .is_err()
    });
    if !blame.is_empty() {
        return Err(RefreshAborted::InvalidSchnorrProof(blame).into());
    }

    // Sanity: public key must be preserved.
    // sum(new_public_shares) should equal old public key because
    // each party's contributions sum to zero.
    tracer.stage("Verify public key invariant");
    let pk_sum: Point<E> = new_public_shares.iter().copied().sum();
    if NonZero::from_point(pk_sum).ok_or(RefreshBug::ZeroPk)? != old_key_share.shared_public_key {
        return Err(RefreshBug::PublicKeyMismatch.into());
    }

    tracer.protocol_ends();

    Ok(DirtyCoreKeyShare {
        i,
        key_info: DirtyKeyInfo {
            curve: Default::default(),
            shared_public_key: old_key_share.shared_public_key,
            public_shares: new_public_shares,
            vss_setup: None,
            #[cfg(feature = "hd-wallet")]
            chain_code: old_key_share.key_info.chain_code,
        },
        x: new_x,
    }
    .validate()
    .map_err(|e| RefreshBug::InvalidKeyShare(e.into_error()))?)
}
