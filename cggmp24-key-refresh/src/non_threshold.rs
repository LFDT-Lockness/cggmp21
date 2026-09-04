//! Non-threshold (`n`-out-of-`n`) key share refresh.
#![allow(non_snake_case)]

use alloc::vec::Vec;

use digest::Digest;
use futures_util::SinkExt;
use generic_ec::{Curve, NonZero, Point, Scalar, SecretScalar};
use generic_ec_zkp::schnorr_pok;
use rand_core::{CryptoRng, RngCore};
use round_based::{
    rounds_router::{simple_store::RoundInput, RoundsRouter},
    Delivery, Mpc, MpcParty, Outgoing, ProtocolMessage,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::errors::IoError;
use crate::progress::Tracer;
use crate::security_level::SecurityLevel;
use crate::utils::{self, AbortBlame};
use crate::ExecutionId;
use crate::{DirtyIncompleteKeyShare, DirtyKeyInfo, IncompleteKeyShare, Validate};

use super::{Bug, KeyRefreshError, ProtocolAborted, Reason};

macro_rules! prefixed {
    ($name:tt) => {
        concat!("dfns.cggmp24.key_refresh.", $name)
    };
}

mod unambiguous {
    use super::{MsgRound1, MsgRound2};
    use crate::{ExecutionId, SecurityLevel};
    use digest::Digest;
    use generic_ec::{Curve, Point};
    use generic_ec_zkp::schnorr_pok;

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("hash_refresh_com"))]
    #[udigest(bound = "")]
    pub struct HashRefreshCom<'a, E: Curve, L: SecurityLevel> {
        pub sid: ExecutionId<'a>,
        pub prover: u16,
        pub decommitment: &'a MsgRound2<E, L>,
    }

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("echo_round"))]
    #[udigest(bound = "")]
    pub struct Echo<'a, D: Digest> {
        pub sid: ExecutionId<'a>,
        pub commitment: &'a MsgRound1<D>,
    }

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("refresh_mask"))]
    #[udigest(bound = "")]
    pub struct RefreshMask<'a, E: Curve> {
        pub sid: ExecutionId<'a>,
        #[udigest(as_bytes)]
        pub rid: &'a [u8],
        pub sender: u16,
        pub recipient: u16,
        pub dh_shared: &'a Point<E>,
    }

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("schnorr_pok"))]
    #[udigest(bound = "")]
    pub struct SchnorrPok<'a, E: Curve> {
        pub sid: ExecutionId<'a>,
        pub prover: u16,
        #[udigest(as_bytes)]
        pub rid: &'a [u8],
        pub X: &'a Point<E>,
        pub sch_commit: &'a schnorr_pok::Commit<E>,
    }
}

/// Message of key refresh protocol
#[derive(ProtocolMessage, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum Msg<E: Curve, L: SecurityLevel, D: Digest> {
    /// Round 1 message
    Round1(MsgRound1<D>),
    /// Reliability check message (optional additional round)
    ReliabilityCheck(MsgReliabilityCheck<D>),
    /// Round 2 message
    Round2(MsgRound2<E, L>),
    /// Round 3 broadcast message
    Round3Broadcast(MsgRound3Broadcast<E>),
    /// Round 3 unicast message
    Round3Unicast(MsgRound3Unicast<E>),
}

/// Message from round 1
#[serde_as]
#[derive(Clone, Serialize, Deserialize, udigest::Digestable)]
#[serde(bound = "")]
#[udigest(bound = "")]
#[udigest(tag = prefixed!("round1"))]
pub struct MsgRound1<D: Digest> {
    /// $V_i$
    #[serde_as(as = "utils::HexOrBin")]
    #[udigest(as_bytes)]
    pub commitment: digest::Output<D>,
}

/// Message from round 2
#[serde_as]
#[derive(Clone, Serialize, Deserialize, udigest::Digestable)]
#[serde(bound = "")]
#[udigest(bound = "")]
#[udigest(tag = prefixed!("round2"))]
pub struct MsgRound2<E: Curve, L: SecurityLevel> {
    /// `rid_i`
    #[serde_as(as = "utils::HexOrBin")]
    #[udigest(as_bytes)]
    pub rid: L::KappaBytes,
    /// $X'_{i,k}$
    pub x_prime_points: Vec<Point<E>>,
    /// $Y_{i,k}$
    pub y_points: Vec<Point<E>>,
    /// $A_{i,k}$
    pub sch_commits: Vec<schnorr_pok::Commit<E>>,
    /// $u_i$
    #[serde_as(as = "utils::HexOrBin")]
    #[udigest(as_bytes)]
    pub decommit: L::KappaBytes,
}

/// Message parties exchange to ensure reliability of broadcast channel
#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgReliabilityCheck<D: Digest> {
    /// Echo hash of round 1 commitments
    #[serde_as(as = "utils::HexOrBin")]
    pub hash: digest::Output<D>,
}

/// Round 3 broadcast message
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgRound3Broadcast<E: Curve> {
    /// $\hat\psi_{i,k}$
    pub sch_proofs: Vec<schnorr_pok::Proof<E>>,
}

/// Round 3 unicast message
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgRound3Unicast<E: Curve> {
    /// $C_{i,j}$
    pub c: Scalar<E>,
}

/// Output of the non-threshold key refresh protocol
pub struct KeyRefreshOutput<E: Curve, L: SecurityLevel> {
    /// Refreshed key share
    pub share: IncompleteKeyShare<E>,
    /// Ephemeral session identifier XOR'd from all parties' contributions
    pub rid: L::KappaBytes,
}

/// Carries out non-threshold key share refresh.
///
/// Refreshes additive secret shares without changing the joint public key.
/// Fails if `share` is a threshold key share.
///
/// `i` is this party's index in **this protocol run** (`0 <= i < n`), used for
/// `RoundsRouter` and message addressing. It need not equal `share.i` (indexes)
/// can be rotated between invocations). This n-out-of-n implementation still
/// requires all `share.n()` parties and treats `i` as the index into protocol
/// vectors of length `n` (and into `public_shares`). Callers should pass the
/// index this share occupies in `public_shares` (normally `share.i`).
pub async fn run_key_refresh<E, R, M, L, D>(
    rng: &mut R,
    party: M,
    sid: ExecutionId<'_>,
    i: u16,
    share: &IncompleteKeyShare<E>,
    mut tracer: Option<&mut dyn Tracer>,
    reliable_broadcast_enforced: bool,
) -> Result<KeyRefreshOutput<E, L>, KeyRefreshError>
where
    E: Curve,
    L: SecurityLevel,
    D: digest::Digest + Clone + 'static,
    R: RngCore + CryptoRng,
    M: Mpc<ProtocolMessage = Msg<E, L, D>>,
{
    if share.key_info.vss_setup.is_some() {
        return Err(Reason::NotThreshold.into());
    }
    let n = share.n();
    debug_assert!(i < n);

    let MpcParty { delivery, .. } = party.into_party();
    let (incomings, mut outgoings) = delivery.split();

    let mut rounds = RoundsRouter::<Msg<E, L, D>>::builder();
    let round1 = rounds.add_round(RoundInput::<MsgRound1<D>>::broadcast(i, n));
    let round1_sync = rounds.add_round(RoundInput::<MsgReliabilityCheck<D>>::broadcast(i, n));
    let round2 = rounds.add_round(RoundInput::<MsgRound2<E, L>>::broadcast(i, n));
    let round3_bc = rounds.add_round(RoundInput::<MsgRound3Broadcast<E>>::broadcast(i, n));
    let round3_p2p = rounds.add_round(RoundInput::<MsgRound3Unicast<E>>::p2p(i, n));
    let mut rounds = rounds.listen(incomings);

    // Round 1
    tracer.round_begins();
    let y = (0..n).map(|_| SecretScalar::random(rng)).collect::<Vec<_>>();
    // $\vec Y_i = (Y_{i,j} = y_{i,j} \cdot G)_{j \in [n]}$
    let Y = y
        .iter()
        .map(|y_ij| Point::generator() * y_ij)
        .collect::<Vec<_>>();

    let mut x_prime = (0..n - 1).map(|_| Scalar::random(rng)).collect::<Vec<_>>();
    let sum_head = x_prime.iter().sum::<Scalar<E>>();
    x_prime.push(-sum_head);
    debug_assert_eq!(x_prime.iter().sum::<Scalar<E>>(), Scalar::zero());

    let X_prime = x_prime
        .iter()
        .map(|x| Point::generator() * x)
        .collect::<Vec<_>>();

    let (tau, A) =
        core::iter::repeat_with(|| schnorr_pok::prover_commits_ephemeral_secret::<E, _>(rng))
            .take(usize::from(n))
            .unzip::<_, _, Vec<_>, Vec<_>>();

    let mut rid_i = L::KappaBytes::default();
    rng.fill_bytes(rid_i.as_mut());
    let mut u_i = L::KappaBytes::default();
    rng.fill_bytes(u_i.as_mut());

    let my_decommitment: MsgRound2<E, L> = MsgRound2 {
        rid: rid_i,
        x_prime_points: X_prime.clone(),
        y_points: Y.clone(),
        sch_commits: A.clone(),
        decommit: u_i,
    };
    // $V_i$ in the specsheet
    let hash_commit = udigest::hash::<D>(&unambiguous::HashRefreshCom {
        sid,
        prover: i,
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
                MsgReliabilityCheck { hash: h_i.clone() },
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
            .filter(|(_j, _msg_id, hash_j)| hash_j.hash != h_i)
            .map(|(j, msg_id, _)| AbortBlame::new(j, msg_id, msg_id))
            .collect::<Vec<_>>();
        if !parties_have_different_hashes.is_empty() {
            return Err(ProtocolAborted::round1_not_reliable(parties_have_different_hashes).into());
        }
    }

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
        .map_err(IoError::receive_message)?;
    tracer.msgs_received();

    tracer.stage("Validate decommitments");
    let blame = utils::collect_blame(&commitments, &decommitments, |j, com, decom| {
        let bad_len = decom.x_prime_points.len() != usize::from(n)
            || decom.y_points.len() != usize::from(n)
            || decom.sch_commits.len() != usize::from(n);
        let expected = udigest::hash::<D>(&unambiguous::HashRefreshCom {
            sid,
            prover: j,
            decommitment: decom,
        });
        let bad_com = com.commitment != expected;
        let sum: Point<E> = decom.x_prime_points.iter().copied().sum();
        let bad_sum = sum != Point::zero();
        bad_len || bad_com || bad_sum
    });
    if !blame.is_empty() {
        return Err(ProtocolAborted::invalid_decommitment(blame).into());
    }

    tracer.stage("Calculate challenge rid");
    let rid = decommitments
        .iter_including_me(&my_decommitment)
        .map(|d| &d.rid)
        .fold(L::KappaBytes::default(), utils::xor_array);

    tracer.stage("Mask refresh shares");
    // Column over peers $j \neq i$ of $Y_{j,i}$: entry $i$ of each peer's $\vec Y_j$
    // (their DH public intended for us). Zipped with $y_{i,j}$, this matches the
    // writeup Round-3 formula $y_{i,j} \cdot Y_{j,i}$.
    let Y_col = decommitments.iter().map(|d| d.y_points[usize::from(i)]);
    let rhos = utils::iter_peers(i, n)
        .zip(Y_col)
        .zip(utils::skip_ith(usize::from(i), &y))
        .map(|((j, Y_ji), y_ij)| {
            let dh = Y_ji * y_ij;
            Scalar::from_hash::<D>(&unambiguous::RefreshMask {
                sid,
                rid: rid.as_ref(),
                sender: i,
                recipient: j,
                dh_shared: &dh,
            })
        });
    let Cs = utils::skip_ith(usize::from(i), &x_prime)
        .zip(rhos)
        .map(|(x_prime_j, rho_j)| x_prime_j + rho_j)
        .collect::<Vec<_>>();

    tracer.stage("Prove knowledge of x' scalars");
    let psi_hat = X_prime
        .iter()
        .zip(&A)
        .zip(&tau)
        .zip(&x_prime)
        .map(|(((X_ij_prime, A_ij), tau_ij), x_ij)| {
            let e = Scalar::from_hash::<D>(&unambiguous::SchnorrPok {
                sid,
                prover: i,
                rid: rid.as_ref(),
                X: X_ij_prime,
                sch_commit: A_ij,
            });
            let challenge = schnorr_pok::Challenge { nonce: e };
            schnorr_pok::prove(tau_ij, &challenge, *x_ij)
        })
        .collect::<Vec<_>>();

    tracer.send_msg();
    outgoings
        .send(Outgoing::broadcast(Msg::Round3Broadcast(
            MsgRound3Broadcast {
                sch_proofs: psi_hat.clone(),
            },
        )))
        .await
        .map_err(IoError::send_message)?;

    for (j, C_j) in utils::iter_peers(i, n).zip(Cs) {
        outgoings
            .send(Outgoing::p2p(
                j,
                Msg::Round3Unicast(MsgRound3Unicast { c: C_j }),
            ))
            .await
            .map_err(IoError::send_message)?;
    }
    outgoings.flush().await.map_err(IoError::send_message)?;
    tracer.msg_sent();

    // Output
    tracer.round_begins();
    tracer.receive_msgs();
    let sch_proofs_r = rounds
        .complete(round3_bc)
        .await
        .map_err(IoError::receive_message)?;
    let masked = rounds
        .complete(round3_p2p)
        .await
        .map_err(IoError::receive_message)?;
    tracer.msgs_received();

    tracer.stage("Unmask refresh contributions");
    // Column over peers $j \neq i$ of $Y_{j,i}$: entry $i$ of each peer's $\vec Y_j$
    // basically their DH public intended for us
    let Y_col = decommitments.iter().map(|d| d.y_points[usize::from(i)]);
    // Column over peers $j \neq i$ of $X'_{j,i}$: entry $i$ of each peer's $\vec X'_j$
    let X_prime_col = decommitments
        .iter()
        .map(|d| d.x_prime_points[usize::from(i)]);

    let mut masked_blame = Vec::new();
    // $x'_{j,i}$ in the specsheet (unmasked contribution from each peer $j$ to us)
    let peer_contribs = masked
        .iter_indexed()
        .zip(Y_col)
        .zip(X_prime_col)
        .zip(utils::skip_ith(usize::from(i), &y))
        .filter_map(|((((j, msg_id, msg), Y_ji), X_prime_ji), y_ij)| {
            // specsheet: $\rho_{j,i}$ from $y_{j,i} \cdot Y_{i,j}$.
            // Same DH point as $y_{i,j} \cdot Y_{j,i}$ ($Y$ subscripts swapped vs the specsheet).
            let dh = Y_ji * y_ij;
            let rho = Scalar::from_hash::<D>(&unambiguous::RefreshMask {
                sid,
                rid: rid.as_ref(),
                sender: j,
                recipient: i,
                dh_shared: &dh,
            });
            let x_ji_prime = msg.c - rho;
            if Point::generator() * x_ji_prime != X_prime_ji {
                masked_blame.push(AbortBlame::new(j, msg_id, msg_id));
                return None;
            }
            Some(x_ji_prime)
        })
        .collect::<Vec<_>>();
    if !masked_blame.is_empty() {
        return Err(ProtocolAborted::invalid_masked_share(masked_blame).into());
    }

    tracer.stage("Validate schnorr proofs");
    let blame = utils::collect_blame(&decommitments, &sch_proofs_r, |j, decom, msg| {
        if msg.sch_proofs.len() != usize::from(n)
            || decom.x_prime_points.len() != usize::from(n)
            || decom.sch_commits.len() != usize::from(n)
        {
            return true;
        }
        decom
            .x_prime_points
            .iter()
            .zip(&decom.sch_commits)
            .zip(&msg.sch_proofs)
            .any(|((X_jk_prime, A_jk), proof)| {
                let challenge = Scalar::from_hash::<D>(&unambiguous::SchnorrPok {
                    sid,
                    prover: j,
                    rid: rid.as_ref(),
                    X: X_jk_prime,
                    sch_commit: A_jk,
                });
                let challenge = schnorr_pok::Challenge { nonce: challenge };
                proof.verify(A_jk, &challenge, X_jk_prime).is_err()
            })
    });
    if !blame.is_empty() {
        return Err(ProtocolAborted::invalid_schnorr_proof(blame).into());
    }

    tracer.stage("Update key share");
    let delta = peer_contribs.iter().sum::<Scalar<E>>() + x_prime[usize::from(i)];
    let mut x_star_scalar = &share.x + delta;
    let x_star = NonZero::from_secret_scalar(SecretScalar::new(&mut x_star_scalar))
        .ok_or(Bug::ZeroSecret)?;

    let public_shares = (0..n)
        .map(|k| {
            let k = usize::from(k);
            let delta = decommitments
                .iter_including_me(&my_decommitment)
                .map(|d| d.x_prime_points[k])
                .sum::<Point<E>>();
            NonZero::from_point(share.public_shares[k] + delta).ok_or(Bug::ZeroPublic)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let share_out = DirtyIncompleteKeyShare {
        i,
        x: x_star,
        key_info: DirtyKeyInfo {
            curve: Default::default(),
            shared_public_key: share.shared_public_key,
            public_shares,
            vss_setup: None,
            #[cfg(feature = "hd-wallet")]
            chain_code: share.chain_code,
        },
    }
    .validate()
    .map_err(|err| Bug::Invalid(err.into_error()))?;

    tracer.protocol_ends();

    Ok(KeyRefreshOutput {
        share: share_out,
        rid,
    })
}
