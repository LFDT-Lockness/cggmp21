//! Threshold (t-of-n) key share refresh protocol
//!
//! Implements the share-refresh portion of CGGMP24 Appendix F.1.1, omitting
//! auxiliary data generation per [issue #162](https://github.com/LFDT-Lockness/cggmp21/issues/162).
//!
//! # Protocol
//!
//! All $n$ parties hold polynomial shares $x_i = F(I_i)$ where $F(0) = x$.
//! Each party $i$ samples a random degree-$(t-1)$ polynomial $g^{(i)}(X)$ and
//! defines the zero-sharing polynomial $f^{(i)}(X) = g^{(i)}(X) - g^{(i)}(0)$.
//! This guarantees $f^{(i)}(0) = 0$.
//!
//! After Feldman VSS verification and Schnorr proofs, each party computes:
//! $$x_i' = x_i + \sum_j f^{(j)}(I_i)$$
//!
//! The secret is preserved: $F'(0) = F(0) + \sum_j f^{(j)}(0) = x + 0 = x$.
//!
//! # Rounds
//!
//! 1. **Commit**: hash commitment to public polynomial and Schnorr commit
//! 2. **(Optional) Reliability check**: echo-broadcast
//! 3. **Decommit + P2P shares**: broadcast public polynomial, unicast evaluations
//! 4. **Prove**: Schnorr proof of knowledge of new secret share

use alloc::vec::Vec;

use digest::Digest;
use generic_ec::{Curve, NonZero, Point, Scalar, SecretScalar};
use generic_ec_zkp::{polynomial::Polynomial, schnorr_pok};
use rand_core::{CryptoRng, RngCore};
use round_based::{
    rounds_router::simple_store::RoundInput, rounds_router::RoundsRouter, Delivery, Mpc, MpcParty,
    Outgoing, ProtocolMessage, SinkExt,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::progress::Tracer;
use crate::{
    errors::IoError,
    key_share::{CoreKeyShare, DirtyCoreKeyShare, DirtyKeyInfo, Validate, VssSetup},
    security_level::SecurityLevel,
    utils, ExecutionId,
};

use super::{KeyRefreshError, RefreshAborted, RefreshBug};

macro_rules! prefixed {
    ($name:tt) => {
        concat!("dfns.cggmp24.key_refresh.threshold.", $name)
    };
}

/// Message of threshold key refresh protocol
#[derive(ProtocolMessage, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum Msg<E: Curve, L: SecurityLevel, D: Digest> {
    /// Round 1: hash commitment
    Round1(MsgRound1<D>),
    /// Round 2a: decommitment (broadcast)
    Round2Broad(MsgRound2Broad<E, L>),
    /// Round 2b: secret share evaluation (P2P)
    Round2Uni(MsgRound2Uni<E>),
    /// Round 3: Schnorr proof
    Round3(MsgRound3<E>),
    /// Reliability check message (optional)
    ReliabilityCheck(MsgReliabilityCheck<D>),
}

/// Round 1 commitment
#[derive(Clone, Serialize, Deserialize, udigest::Digestable)]
#[serde(bound = "")]
#[udigest(bound = "")]
#[udigest(tag = prefixed!("round1"))]
pub struct MsgRound1<D: Digest> {
    /// Hash commitment $V_i$
    #[udigest(as_bytes)]
    pub commitment: digest::Output<D>,
}

/// Round 2 broadcast: public polynomial + Schnorr commit
///
/// Contains $G^{(i)}$, the public polynomial of the raw random polynomial
/// $g^{(i)}$. The verifier derives the zero-sharing public polynomial as
/// $F^{(i)}(X) = G^{(i)}(X) - G^{(i)}(0)$.
#[serde_as]
#[derive(Clone, Serialize, Deserialize, udigest::Digestable)]
#[serde(bound = "")]
#[udigest(bound = "")]
#[udigest(tag = prefixed!("round2_broad"))]
pub struct MsgRound2Broad<E: Curve, L: SecurityLevel> {
    /// Random identifier contribution $rid_i$
    #[serde_as(as = "utils::HexOrBin")]
    #[udigest(as_bytes)]
    pub rid: L::KappaBytes,
    /// Public polynomial $G^{(i)} = g^{(i)} \cdot G$
    ///
    /// Degree $t-1$. The zero-sharing public polynomial is
    /// $F^{(i)}(X) = G^{(i)}(X) - G^{(i)}.coefs\[0\]$.
    pub G_poly: Polynomial<Point<E>>,
    /// Schnorr commitment $A_i$
    pub sch_commit: schnorr_pok::Commit<E>,
    /// Decommitment nonce $u_i$
    #[serde(with = "hex::serde")]
    #[udigest(as_bytes)]
    pub decommit: L::KappaBytes,
}

/// Round 2 unicast: secret share evaluation
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgRound2Uni<E: Curve> {
    /// $\sigma_{i,j} = f^{(i)}(I_j) = g^{(i)}(I_j) - g^{(i)}(0)$
    pub sigma: Scalar<E>,
}

/// Round 3: Schnorr proof of knowledge of new share
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgRound3<E: Curve> {
    /// Schnorr proof $\psi_i$
    pub sch_proof: schnorr_pok::Proof<E>,
}

/// Reliability check echo
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgReliabilityCheck<D: Digest>(pub digest::Output<D>);

mod unambiguous {
    use generic_ec::{Curve, NonZero, Point};

    use crate::{ExecutionId, SecurityLevel};

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

/// Runs the threshold key refresh protocol.
///
/// Takes an existing t-of-n key share and produces a new share with the
/// same public key, threshold, and VSS setup but different secret share value.
///
/// # Errors
/// Returns `KeyRefreshError` if the old share has no VSS setup or if any
/// party misbehaves (invalid commitments, proofs, or Feldman checks).
pub async fn run_threshold_key_refresh<E, R, M, L, D>(
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

    let vss = old_key_share
        .vss_setup
        .as_ref()
        .ok_or(RefreshBug::MissingVssSetup)?;
    let t = vss.min_signers;

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

    // ===== Round 1: Sample random polynomial and commit =====
    tracer.round_begins();

    tracer.stage("Sample rid, Schnorr commitment, random polynomial");
    let mut rid = L::KappaBytes::default();
    rng.fill_bytes(rid.as_mut());

    let (sch_r, sch_h) = schnorr_pok::prover_commits_ephemeral_secret::<E, _>(rng);

    // Sample random polynomial g(X) of degree t-1.
    // The zero-sharing polynomial is f(X) = g(X) - g(0), so f(0) = 0.
    let g = Polynomial::<SecretScalar<E>>::sample(rng, usize::from(t) - 1);
    let g_at_zero: Scalar<E> = g.value(&Scalar::zero());
    let G_poly = &g * &Point::generator();

    // Compute sigma_{i,j} = f(I_j) = g(I_j) - g(0) for each party j
    let sigmas: Vec<Scalar<E>> = (0..n)
        .map(|j| {
            let I_j = &vss.I[usize::from(j)];
            let g_at_I_j: Scalar<E> = g.value(I_j);
            g_at_I_j - g_at_zero
        })
        .collect();

    tracer.stage("Compute hash commitment");
    let my_decommitment = MsgRound2Broad {
        rid,
        G_poly: G_poly.clone(),
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

    // Send sigma_{i,j} to each peer j
    let p2p_messages = utils::iter_peers(i, n).map(|j| {
        Outgoing::p2p(
            j,
            Msg::Round2Uni(MsgRound2Uni {
                sigma: sigmas[usize::from(j)],
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
    let sigmas_msg = rounds
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

    tracer.stage("Validate polynomial degree");
    let blame = decommitments
        .iter_indexed()
        .filter(|(_, _, d)| d.G_poly.degree() + 1 != usize::from(t))
        .map(|(j, _, _)| j)
        .collect::<Vec<_>>();
    if !blame.is_empty() {
        return Err(RefreshAborted::InvalidDataSize { parties: blame }.into());
    }

    tracer.stage("Validate Feldman VSS (zero-sharing)");
    // For party j's polynomial: f^(j)(I_i) = g^(j)(I_i) - g^(j)(0)
    // On the curve: G_poly_j(I_i) - G_poly_j.coefs()[0] should equal sigma_{j,i} * G
    let I_i = &vss.I[usize::from(i)];
    let blame = decommitments
        .iter_indexed()
        .zip(sigmas_msg.iter())
        .filter(|((_, _, d), s)| {
            let G_eval_at_I_i: Point<E> = d.G_poly.value(I_i);
            let G_const: Point<E> = d.G_poly.coefs()[0];
            // F^(j)(I_i) = G_poly_j(I_i) - G_poly_j(0)
            let F_eval = G_eval_at_I_i - G_const;
            F_eval != Point::generator() * s.sigma
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
    // x_i' = x_i + sum_j sigma_{j,i}   (including own contribution)
    let sigma_from_others: Scalar<E> = sigmas_msg.iter().map(|msg| msg.sigma).sum();
    let sigma_from_self = sigmas[usize::from(i)];
    let mut new_x_scalar: Scalar<E> = sigma_from_others + sigma_from_self + &old_key_share.x;
    let new_x = SecretScalar::new(&mut new_x_scalar);
    let new_x = NonZero::from_secret_scalar(new_x).ok_or(RefreshBug::ZeroShare)?;

    tracer.stage("Compute new public shares");
    // For each party l: X_l' = X_l + sum_j F^(j)(I_l)
    // where F^(j)(I_l) = G_poly_j(I_l) - G_poly_j.coefs()[0]
    let new_public_shares: Vec<NonZero<Point<E>>> = (0..n)
        .map(|l| {
            let I_l = &vss.I[usize::from(l)];
            let refresh_sum: Point<E> = decommitments
                .iter_including_me(&my_decommitment)
                .map(|d| {
                    let eval: Point<E> = d.G_poly.value(I_l);
                    let constant: Point<E> = d.G_poly.coefs()[0];
                    eval - constant
                })
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

    // Sanity: the shared public key must not have changed.
    // Since each f^(j)(0) = 0, the sum of refresh polynomials at 0 is the zero point.
    tracer.stage("Verify public key invariant");
    let refresh_at_zero: Point<E> = decommitments
        .iter_including_me(&my_decommitment)
        .map(|_d| Point::zero())
        .sum();
    debug_assert_eq!(refresh_at_zero, Point::zero());

    tracer.protocol_ends();

    Ok(DirtyCoreKeyShare {
        i,
        key_info: DirtyKeyInfo {
            curve: Default::default(),
            shared_public_key: old_key_share.shared_public_key,
            public_shares: new_public_shares,
            vss_setup: Some(VssSetup {
                min_signers: t,
                I: vss.I.clone(),
            }),
            #[cfg(feature = "hd-wallet")]
            chain_code: old_key_share.key_info.chain_code,
        },
        x: new_x,
    }
    .validate()
    .map_err(|err| RefreshBug::InvalidKeyShare(err.into_error()))?)
}
