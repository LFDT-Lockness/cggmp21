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

use super::{Bug, KeyRefreshAborted, KeyRefreshError};

macro_rules! prefixed {
    ($name:tt) => {
        concat!("dfns.cggmp24.key_refresh.threshold.", $name)
    };
}

/// Message of threshold key refresh protocol
#[derive(ProtocolMessage, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum Msg<E: Curve, L: SecurityLevel, D: Digest> {
    /// Round 1 message
    Round1(MsgRound1<D>),
    /// Round 2a broadcast message
    Round2Broad(MsgRound2Broad<E, L>),
    /// Round 2b unicast message
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
#[udigest(tag = prefixed!("round1"))]
pub struct MsgRound1<D: Digest> {
    /// $V_i$
    #[udigest(as_bytes)]
    pub commitment: digest::Output<D>,
}
/// Message from round 2 broadcasted to everyone
#[serde_as]
#[derive(Clone, Serialize, Deserialize, udigest::Digestable)]
#[serde(bound = "")]
#[udigest(bound = "")]
#[udigest(tag = prefixed!("round2_broad"))]
pub struct MsgRound2Broad<E: Curve, L: SecurityLevel> {
    /// `rid_i`
    #[serde_as(as = "utils::HexOrBin")]
    #[udigest(as_bytes)]
    pub rid: L::KappaBytes,
    /// $\vec F_i$ — commitment polynomial (public coefficients of update polynomial with zero constant term)
    pub F: Polynomial<Point<E>>,
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
    /// $\sigma_{i,j}$ — evaluation of update polynomial at party j's index
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

mod unambiguous {
    use generic_ec::{Curve, Point};

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
        pub y: Point<E>,
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

/// Run threshold key refresh protocol (CGGMP24 Appendix F.1.1, share-update only)
///
/// Each party i generates a random degree-$(t-1)$ polynomial $f_i(x)$ with $f_i(0) = 0$,
/// shares evaluations $f_i(j)$ with each party j via Feldman VSS, and proves knowledge.
/// Party j's new share is $x_j' = x_j + \sum_i f_i(j)$.
/// The shared secret key is preserved since $F(0) = \sum_i f_i(0) = 0$.
pub async fn run_threshold_key_refresh<E, R, M, L, D>(
    mut tracer: Option<&mut dyn Tracer>,
    i: u16,
    t: u16,
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

    tracer.stage("Sample update polynomial with zero constant term, rid_i, schnorr commitment");
    let mut rid = L::KappaBytes::default();
    rng.fill_bytes(rid.as_mut());

    let (r, h) = schnorr_pok::prover_commits_ephemeral_secret::<E, _>(rng);

    // Generate degree-(t-1) polynomial f_i with f_i(0) = 0
    // That means the constant term is zero, and we sample t-1 random coefficients
    let f = Polynomial::<SecretScalar<E>>::sample_with_const_term(
        rng,
        usize::from(t) - 1,
        SecretScalar::new(&mut Scalar::<E>::zero()),
    );
    let F = &f * &Point::generator();

    // Verify constant term is zero (public commitment)
    debug_assert!(F.coefs()[0].is_zero());

    // Evaluate f_i at each party's index
    let sigmas: Vec<Scalar<E>> = (0..n)
        .map(|j| {
            let x = Scalar::from(j + 1);
            f.value(&x)
        })
        .collect();

    tracer.stage("Commit to public data");
    let my_decommitment = MsgRound2Broad {
        rid,
        F: F.clone(),
        sch_commit: h,
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

    let messages = utils::iter_peers(i, n).map(|j| {
        let message = MsgRound2Uni {
            sigma: sigmas[usize::from(j)],
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
    let sigmas_msg = rounds
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

    tracer.stage("Validate polynomial degrees");
    let blame = decommitments
        .iter_indexed()
        .filter(|(_, _, d)| d.F.degree() + 1 != usize::from(t))
        .map(|t| t.0)
        .collect::<Vec<_>>();
    if !blame.is_empty() {
        return Err(KeyRefreshAborted::InvalidDataSize { parties: blame }.into());
    }

    tracer.stage("Verify constant terms are zero (updates must preserve secret key)");
    let blame = decommitments
        .iter_indexed()
        .filter(|(_, _, d)| !d.F.coefs()[0].is_zero())
        .map(|t| t.0)
        .collect::<Vec<_>>();
    if !blame.is_empty() {
        return Err(KeyRefreshAborted::NonZeroConstantTerm { parties: blame }.into());
    }

    tracer.stage("Validate Feldman VSS for update polynomials");
    let blame = decommitments
        .iter_indexed()
        .zip(sigmas_msg.iter())
        .filter(|((_, _, d), s)| {
            d.F.value::<_, Point<_>>(&Scalar::from(i + 1)) != Point::generator() * s.sigma
        })
        .map(|t| t.0 .0)
        .collect::<Vec<_>>();
    if !blame.is_empty() {
        return Err(KeyRefreshAborted::FeldmanVerificationFailed { parties: blame }.into());
    }

    tracer.stage("Compute rid");
    let rid = decommitments
        .iter_including_me(&my_decommitment)
        .map(|d| &d.rid)
        .fold(L::KappaBytes::default(), utils::xor_array);

    tracer.stage("Compute updated public shares");
    // The sum of update polynomials (public): F_sum = sum_i F_i
    let polynomial_update_sum = decommitments
        .iter_including_me(&my_decommitment)
        .map(|d| &d.F)
        .sum::<Polynomial<_>>();

    // New public shares: Y_j' = Y_j + F_sum(j+1)
    let new_public_shares = (0..n)
        .map(|l| {
            let old_Y_l = current_key_share.public_shares[usize::from(l)];
            let update = polynomial_update_sum.value::<_, Point<E>>(&Scalar::from(l + 1));
            NonZero::from_point(*old_Y_l + update).ok_or(Bug::ZeroShare)
        })
        .collect::<Result<Vec<_>, _>>()?;

    tracer.stage("Compute updated secret share");
    // sigma_update_i = sum_j sigma_{j,i} (received from others) + sigma_{i,i} (own)
    let sigma_update: Scalar<E> = sigmas_msg.iter().map(|msg| msg.sigma).sum();
    let mut new_x =
        {
            let old_x: &Scalar<E> = current_key_share.x.as_ref();
            *old_x + sigma_update + sigmas[usize::from(i)]
        };
    let new_x =
        NonZero::from_secret_scalar(SecretScalar::new(&mut new_x)).ok_or(Bug::ZeroShare)?;
    debug_assert_eq!(
        Point::generator() * &new_x,
        new_public_shares[usize::from(i)]
    );

    tracer.stage("Calculate challenge");
    let challenge = Scalar::from_hash::<D>(&unambiguous::SchnorrPok {
        sid,
        prover: i,
        rid: rid.as_ref(),
        y: *new_public_shares[usize::from(i)],
        h: my_decommitment.sch_commit.0,
    });
    let challenge = schnorr_pok::Challenge { nonce: challenge };

    tracer.stage("Prove knowledge of updated share");
    let z = schnorr_pok::prove(&r, &challenge, &new_x);

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
    let blame = utils::collect_blame(&decommitments, &sch_proofs, |j, decom, sch_proof| {
        let challenge = Scalar::from_hash::<D>(&unambiguous::SchnorrPok {
            sid,
            prover: j,
            rid: rid.as_ref(),
            y: *new_public_shares[usize::from(j)],
            h: decom.sch_commit.0,
        });
        let challenge = schnorr_pok::Challenge { nonce: challenge };
        let y_j: Point<E> = *new_public_shares[usize::from(j)];
        sch_proof
            .sch_proof
            .verify(&decom.sch_commit, &challenge, &y_j)
            .is_err()
    });
    if !blame.is_empty() {
        return Err(KeyRefreshAborted::InvalidSchnorrProof(blame).into());
    }

    tracer.stage("Construct updated key share");
    let key_shares_indexes = (1..=n)
        .map(|idx| NonZero::from_scalar(Scalar::from(idx)))
        .collect::<Option<Vec<_>>>()
        .ok_or(Bug::NonZeroScalar)?;

    tracer.protocol_ends();

    Ok(DirtyCoreKeyShare {
        i,
        key_info: DirtyKeyInfo {
            curve: Default::default(),
            shared_public_key: current_key_share.shared_public_key,
            public_shares: new_public_shares,
            vss_setup: Some(VssSetup {
                min_signers: t,
                I: key_shares_indexes,
            }),
            #[cfg(feature = "hd-wallet")]
            chain_code: current_key_share.chain_code,
        },
        x: new_x,
    }
    .validate()
    .map_err(|err| Bug::InvalidKeyShare(err.into_error()))?)
}
