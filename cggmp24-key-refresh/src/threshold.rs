//! Threshold (`t`-out-of-`n`) key share refresh.
#![allow(non_snake_case)]

use alloc::vec::Vec;

use digest::Digest;
use futures_util::SinkExt;
use generic_ec::{Curve, NonZero, Point, Scalar, SecretScalar};
use generic_ec_zkp::{polynomial::Polynomial, schnorr_pok};
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
use crate::{DirtyIncompleteKeyShare, DirtyKeyInfo, IncompleteKeyShare, Validate, VssSetup};

use super::{Bug, InvalidArgs, KeyRefreshError, KeyRefreshOutput, ProtocolAborted, Reason};

macro_rules! prefixed {
    ($name:tt) => {
        concat!("dfns.cggmp24.key_refresh.threshold.", $name)
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

/// Message of threshold key refresh protocol
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
    /// $S_{i,k}$ for $k \in \[t\]$
    pub s_points: Vec<Point<E>>,
    /// $Y_{i,j}$ for $j \in \[n\]$
    pub y_points: Vec<Point<E>>,
    /// $A_{i,k}$ for $k \in \{1, \ldots, t-1\}$
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
    /// $\hat\psi_{i,k}$ for $k \in \{1, \ldots, t-1\}$
    pub sch_proofs: Vec<schnorr_pok::Proof<E>>,
}

/// Round 3 unicast message
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgRound3Unicast<E: Curve> {
    /// $C_{j,i}$
    pub c: Scalar<E>,
}

/// Carries out threshold key share refresh
///
/// Refreshes Shamir secret shares without changing the joint public key. Fails if `share`
/// is an additive (`n`-out-of-`n`) key share. Always uses §4.5.2, including when `t = n`.
///
/// Indexes of all participants of the protocol should match exactly their indexes from
/// the key generation protocol execution. E.g. if party occupied index `j` in keygen,
/// it must have the same index `j` in key refresh execution. In particular, the local
/// party has index [`share.i`](DirtyIncompleteKeyShare::i). Evaluation points and
/// public shares stay in keygen order. The returned share keeps that same index.
pub async fn run_threshold_key_refresh<E, R, M, L, D>(
    rng: &mut R,
    party: M,
    sid: ExecutionId<'_>,
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
    let vss = share
        .key_info
        .vss_setup
        .as_ref()
        .ok_or(Reason::ExpectedThresholdShare)?;
    let t = vss.min_signers;
    let t_usize = usize::from(t);

    let n = share.n();
    let i = share.i;
    if i >= n {
        return Err(InvalidArgs::PartyIndexOutOfBounds.into());
    }

    let I = &vss.I;
    let X = &share.public_shares;
    let n_usize = usize::from(n);
    let sch_len = t_usize.saturating_sub(1);

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
    let y = (0..n)
        .map(|_| SecretScalar::random(rng))
        .collect::<Vec<_>>();
    let Y = y
        .iter()
        .map(|y_ij| Point::generator() * y_ij)
        .collect::<Vec<_>>();

    // φ_i(x) = ∑_{k ∈ [t]} s_{i,k} x^k with s_{i,0} = 0, so that φ_i(0) = 0 and the refresh
    // leaves the shared secret untouched
    let s = core::iter::once(Scalar::zero())
        .chain((1..t_usize).map(|_| Scalar::random(rng)))
        .collect::<Vec<_>>();
    let phi = Polynomial::from_coefs(s.clone());
    let S = s
        .iter()
        .map(|s_k| Point::generator() * s_k)
        .collect::<Vec<_>>();

    let (tau, A): (Vec<_>, Vec<_>) = (0..sch_len)
        .map(|_| schnorr_pok::prover_commits_ephemeral_secret::<E, _>(rng))
        .unzip();

    let mut rid_i = L::KappaBytes::default();
    rng.fill_bytes(rid_i.as_mut());
    let mut u_i = L::KappaBytes::default();
    rng.fill_bytes(u_i.as_mut());

    let my_decommitment: MsgRound2<E, L> = MsgRound2 {
        rid: rid_i,
        s_points: S.clone(),
        y_points: Y.clone(),
        sch_commits: A.clone(),
        decommit: u_i,
    };
    // $V_i$ in the spec
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
        let bad_len = decom.s_points.len() != t_usize
            || decom.y_points.len() != n_usize
            || decom.sch_commits.len() != sch_len;
        let expected = udigest::hash::<D>(&unambiguous::HashRefreshCom {
            sid,
            prover: j,
            decommitment: decom,
        });
        let bad_com = com.commitment != expected;
        let bad_zero = decom.s_points.first() != Some(&Point::zero());
        bad_len || bad_com || bad_zero
    });
    if !blame.is_empty() {
        return Err(ProtocolAborted::invalid_decommitment(blame).into());
    }

    tracer.stage("Calculate challenge rid");
    let rid = decommitments
        .iter_including_me(&my_decommitment)
        .map(|d| &d.rid)
        .fold(L::KappaBytes::default(), utils::xor_array);

    // Every party's committed polynomial $\Phi_j(x) = \sum_k S_{j,k} x^k$ in the exponent.
    // `iter_including_me` inserts our own message at position `i`, so `S_polys[j]` belongs to
    // the party at protocol index `j`. Built once here because both the unmasking check and
    // the public share update evaluate all `n` of them.
    let S_polys = decommitments
        .iter_including_me(&my_decommitment)
        .map(|d| Polynomial::from_coefs(d.s_points.clone()))
        .collect::<Vec<_>>();

    tracer.stage("Mask refresh shares");
    // Peer $j$ published $Y_{j,i}$ for us in slot `i` of its `y_points`; pairing it with our
    // own $y_{i,j}$ gives the shared DH secret that masks $z_{i,j}$
    let Y_col = decommitments.iter().map(|d| d.y_points[usize::from(i)]);
    let Cs = utils::iter_peers(i, n)
        .zip(Y_col)
        .zip(utils::skip_ith(usize::from(i), &y))
        .map(|((j, Y_ji), y_ij)| {
            let dh = Y_ji * y_ij;
            let rho_ij = Scalar::from_hash::<D>(&unambiguous::RefreshMask {
                sid,
                rid: rid.as_ref(),
                sender: i,
                recipient: j,
                dh_shared: &dh,
            });
            let z_ij = phi.value::<_, Scalar<E>>(I[usize::from(j)].as_ref());
            z_ij + rho_ij
        })
        .collect::<Vec<_>>();

    tracer.stage("Prove knowledge of polynomial coefficients");
    // The $k = 0$ coefficient is fixed to zero and needs no proof, hence the `skip(1)`
    let psi_hat = S
        .iter()
        .skip(1)
        .zip(&A)
        .zip(&tau)
        .zip(s.iter().skip(1))
        .map(|(((S_ik, A_ik), tau_ik), s_ik)| {
            let e = Scalar::from_hash::<D>(&unambiguous::SchnorrPok {
                sid,
                prover: i,
                rid: rid.as_ref(),
                X: S_ik,
                sch_commit: A_ik,
            });
            let challenge = schnorr_pok::Challenge { nonce: e };
            schnorr_pok::prove(tau_ik, &challenge, s_ik)
        })
        .collect::<Vec<_>>();

    tracer.send_msg();
    let messages = core::iter::once(Outgoing::broadcast(Msg::Round3Broadcast(
        MsgRound3Broadcast {
            sch_proofs: psi_hat.clone(),
        },
    )))
    .chain(
        utils::iter_peers(i, n)
            .zip(Cs)
            .map(|(j, c_ij)| Outgoing::p2p(j, Msg::Round3Unicast(MsgRound3Unicast { c: c_ij }))),
    );
    outgoings
        .send_all(&mut futures_util::stream::iter(messages.map(Ok)))
        .await
        .map_err(IoError::send_message)?;
    tracer.msg_sent();

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
    let Y_col = decommitments.iter().map(|d| d.y_points[usize::from(i)]);
    let I_i = I[usize::from(i)];

    // $z_{j,i}$ in the spec: peer $j$'s contribution to our share, recovered by stripping
    // the DH mask. Checked afterwards against $\Phi_j(I_i)$.
    let peer_contribs = masked
        .iter_indexed()
        .zip(Y_col)
        .zip(utils::skip_ith(usize::from(i), &y))
        .map(|(((j, _msg_id, msg), Y_ji), y_ij)| {
            let dh = Y_ji * y_ij;
            let rho_ji = Scalar::from_hash::<D>(&unambiguous::RefreshMask {
                sid,
                rid: rid.as_ref(),
                sender: j,
                recipient: i,
                dh_shared: &dh,
            });
            msg.c - rho_ji
        })
        .collect::<Vec<_>>();

    let masked_blame = peer_contribs
        .iter()
        .zip(masked.iter_indexed())
        .filter_map(|(&z_ji, (j, msg_id, _msg))| {
            (Point::generator() * z_ji
                != S_polys[usize::from(j)].value::<_, Point<E>>(I_i.as_ref()))
            .then_some(AbortBlame::new(j, msg_id, msg_id))
        })
        .collect::<Vec<_>>();
    if !masked_blame.is_empty() {
        return Err(ProtocolAborted::invalid_masked_share(masked_blame).into());
    }

    tracer.stage("Validate schnorr proofs");
    let blame = utils::collect_blame(&decommitments, &sch_proofs_r, |j, decom, msg| {
        if msg.sch_proofs.len() != sch_len {
            return true;
        }
        decom
            .s_points
            .iter()
            .skip(1)
            .zip(&decom.sch_commits)
            .zip(&msg.sch_proofs)
            .any(|((S_k, A_k), proof)| {
                let challenge = Scalar::from_hash::<D>(&unambiguous::SchnorrPok {
                    sid,
                    prover: j,
                    rid: rid.as_ref(),
                    X: S_k,
                    sch_commit: A_k,
                });
                let challenge = schnorr_pok::Challenge { nonce: challenge };
                proof.verify(A_k, &challenge, S_k).is_err()
            })
    });
    if !blame.is_empty() {
        return Err(ProtocolAborted::invalid_schnorr_proof(blame).into());
    }

    tracer.stage("Update key share");
    // The new sharing polynomial is $f^*(x) = f(x) + \sum_j \varphi_j(x)$; since every
    // $\varphi_j(0) = 0$, the shared secret is unchanged
    let z_ii = phi.value::<_, Scalar<E>>(I_i.as_ref());
    let delta = peer_contribs.iter().sum::<Scalar<E>>() + z_ii;
    let mut x_star_scalar = &share.x + delta;
    let x_star = NonZero::from_secret_scalar(SecretScalar::new(&mut x_star_scalar))
        .ok_or(Bug::ZeroSecret)?;

    let public_shares = I
        .iter()
        .zip(X.iter())
        .map(|(I_j, X_j)| {
            let delta = S_polys
                .iter()
                .map(|Phi_k| Phi_k.value::<_, Point<E>>(I_j.as_ref()))
                .sum::<Point<E>>();
            NonZero::from_point(*X_j + delta).ok_or(Bug::ZeroPublic)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let share_out = DirtyIncompleteKeyShare {
        i,
        x: x_star,
        key_info: DirtyKeyInfo {
            curve: Default::default(),
            shared_public_key: share.shared_public_key,
            public_shares,
            vss_setup: Some(VssSetup {
                min_signers: t,
                I: vss.I.clone(),
            }),
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
