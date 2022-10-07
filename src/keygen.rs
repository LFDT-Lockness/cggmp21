#![allow(non_snake_case)]

use digest::Digest;
use futures::SinkExt;
use generic_ec::hash_to_curve::{self, FromHash};
use generic_ec::{Curve, Point, Scalar, SecretScalar};
use generic_ec_zkp::{
    hash_commitment::{self, HashCommit},
    schnorr_pok,
};
use phantom_type::PhantomType;
use rand_core::{CryptoRng, RngCore};
use round_based::{
    rounds::simple_store::{RoundInput, RoundInputError},
    rounds::{CompleteRoundError, Rounds},
    Delivery, Mpc, MpcParty, Outgoing, ProtocolMessage,
};
use thiserror::Error;

const SECURITY_BITS: usize = 256;
const SECURITY_BYTES: usize = SECURITY_BITS / 8;

#[derive(ProtocolMessage, Clone)]
pub enum Msg<E: Curve, D: Digest> {
    Round1(MsgRound1<D>),
    Round2(MsgRound2<E, D>),
    Round3(MsgRound3<E>),
}

#[derive(Clone)]
pub struct MsgRound1<D: Digest> {
    commitment: HashCommit<D>,
}
#[derive(Clone)]
pub struct MsgRound2<E: Curve, D: Digest> {
    rid: [u8; SECURITY_BYTES],
    X: Point<E>,
    sch_commit: schnorr_pok::Commit<E>,
    decommit: hash_commitment::DecommitNonce<D>,
}
#[derive(Clone)]
pub struct MsgRound3<E: Curve> {
    sch_proof: schnorr_pok::Proof<E>,
}

pub struct Keygen<R, E: Curve, D> {
    rng: R,
    i: u16,
    n: u16,
    tag: Tag<E>,
    _ph: PhantomType<(E, D)>,
}

impl<R, E, D> Keygen<R, E, D>
where
    R: RngCore + CryptoRng,
    E: Curve,
    Scalar<E>: FromHash,
    D: Digest + Clone + 'static,
{
    pub fn new(rng: R, i: u16, n: u16) -> Self {
        Self {
            rng,
            i,
            n,
            tag: Tag::default(),
            _ph: PhantomType::new(),
        }
    }

    pub fn set_tag(self, tag: Tag<E>) -> Self {
        Self { tag, ..self }
    }

    pub async fn start<M>(
        mut self,
        party: M,
    ) -> Result<IncompleteKeyShare<E>, KeygenError<M::ReceiveError, M::SendError>>
    where
        M: Mpc<ProtocolMessage = Msg<E, D>>,
    {
        let MpcParty { delivery, .. } = party.into_party();
        let (incomings, mut outgoings) = delivery.split();

        // Setup networking
        let mut rounds = Rounds::<Msg<E, D>>::builder();
        let round1 = rounds.add_round(RoundInput::<MsgRound1<D>>::broadcast(self.i, self.n));
        let round2 = rounds.add_round(RoundInput::<MsgRound2<E, D>>::broadcast(self.i, self.n));
        let round3 = rounds.add_round(RoundInput::<MsgRound3<E>>::broadcast(self.i, self.n));
        let mut rounds = rounds.listen(incomings);

        // Round 1
        let sid = self.tag.as_bytes();
        let tag_htc = self
            .tag
            .as_hash_to_curve_tag()
            .ok_or(BugReason::InvalidHashToCurveTag)?;

        let x_i = SecretScalar::<E>::random(&mut self.rng);
        let X_i = Point::generator() * &x_i;

        let mut rid = [0u8; SECURITY_BYTES];
        self.rng.fill_bytes(&mut rid);

        let (sch_secret, sch_commit) =
            schnorr_pok::prover_commits_ephemeral_secret::<E, _>(&mut self.rng);

        let (hash_commit, decommit) = HashCommit::<D>::builder()
            .mix_bytes(sid)
            .mix(self.n)
            .mix(self.i)
            .mix_bytes(&rid)
            .mix(X_i)
            .mix(&sch_commit.0)
            .commit(&mut self.rng);

        let my_commitment = MsgRound1 {
            commitment: hash_commit,
        };
        outgoings
            .send(Outgoing::reliable_broadcast(Msg::Round1(
                my_commitment.clone(),
            )))
            .await
            .map_err(KeygenError::SendError)?;

        // Round 2
        let commitments = rounds
            .complete(round1)
            .await
            .map_err(KeygenError::ReceiveMessage)?
            .into_vec_including_me(my_commitment);

        let my_decommitment = MsgRound2 {
            rid,
            X: X_i,
            sch_commit,
            decommit,
        };
        outgoings
            .send(Outgoing::broadcast(Msg::Round2(my_decommitment.clone())))
            .await
            .map_err(KeygenError::SendError)?;

        // Round 3
        let decommitments = rounds
            .complete(round2)
            .await
            .map_err(KeygenError::ReceiveMessage)?
            .into_vec_including_me(my_decommitment);

        // Validate decommitments
        let blame = (0u16..)
            .zip(&commitments)
            .zip(&decommitments)
            .filter(|((j, commitment), decommitment)| {
                HashCommit::<D>::builder()
                    .mix_bytes(sid)
                    .mix(self.n)
                    .mix(j)
                    .mix_bytes(&decommitment.rid)
                    .mix(decommitment.X)
                    .mix(&decommitment.sch_commit.0)
                    .verify(&commitment.commitment, &decommitment.decommit)
                    .is_err()
            })
            .map(|((j, _), _)| j)
            .collect::<Vec<_>>();
        if !blame.is_empty() {
            return Err(ProtocolAborted::InvalidDecommitment { parties: blame }.into());
        }

        // Calculate challenge
        let mut rid = [0u8; 32];
        for decommitment in &decommitments {
            rid.iter_mut()
                .zip(&decommitment.rid)
                .for_each(|(x, r_i)| *x ^= r_i);
        }
        let challenge = Scalar::<E>::hash_concat(tag_htc, &[&self.i.to_be_bytes(), &rid])
            .map_err(BugReason::HashToScalarError)?;
        let challenge = schnorr_pok::Challenge { nonce: challenge };

        // Prove knowledge of `x_i`
        let sch_proof = schnorr_pok::prove(&sch_secret, &challenge, &x_i);

        let my_sch_proof = MsgRound3 { sch_proof };
        outgoings
            .send(Outgoing::broadcast(Msg::Round3(my_sch_proof.clone())))
            .await
            .map_err(KeygenError::SendError)?;

        // Round 3
        let sch_proofs = rounds
            .complete(round3)
            .await
            .map_err(KeygenError::ReceiveMessage)?
            .into_vec_including_me(my_sch_proof);

        let mut blame = vec![];
        for ((j, decommitment), sch_proof) in (0u16..).zip(&decommitments).zip(&sch_proofs) {
            let challenge = Scalar::<E>::hash_concat(tag_htc, &[&j.to_be_bytes(), &rid])
                .map(|challenge| schnorr_pok::Challenge { nonce: challenge })
                .map_err(BugReason::HashToScalarError)?;
            if sch_proof
                .sch_proof
                .verify(&decommitment.sch_commit, &challenge, &decommitment.X)
                .is_err()
            {
                blame.push(j);
            }
        }
        if !blame.is_empty() {
            return Err(ProtocolAborted::InvalidSchnorrProof { parties: blame }.into());
        }

        Ok(IncompleteKeyShare {
            shared_public_key: decommitments.iter().map(|d| d.X).sum(),
            rid,
            public_shares: decommitments.iter().map(|d| d.X).collect(),
            x_i,
        })
    }
}

pub struct Tag<E: Curve> {
    tag: [u8; 32],
    _curve: PhantomType<E>,
}

impl<E: Curve> Tag<E> {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.tag
    }

    fn as_hash_to_curve_tag(&self) -> Option<hash_to_curve::Tag> {
        hash_to_curve::Tag::new(self.as_bytes())
    }
}

impl<E: Curve> Default for Tag<E> {
    fn default() -> Self {
        sha2::Sha256::new().into()
    }
}

impl<E: Curve, D: Digest<OutputSize = digest::typenum::U32>> From<D> for Tag<E> {
    fn from(hash: D) -> Self {
        Tag {
            tag: hash
                .chain_update("-CGGMP21-DFNS-KEYGEN-")
                .chain_update(E::CURVE_NAME.as_bytes())
                .finalize()
                .into(),
            _curve: PhantomType::new(),
        }
    }
}

pub struct IncompleteKeyShare<E: Curve> {
    pub shared_public_key: Point<E>,
    pub rid: [u8; SECURITY_BYTES],
    pub public_shares: Vec<Point<E>>,
    pub x_i: SecretScalar<E>,
}

/// Keygen failed error
#[derive(Debug, Error)]
pub enum KeygenError<IErr, OErr> {
    #[error("protocol was aborted by malicious party")]
    Aborted(
        #[source]
        #[from]
        ProtocolAborted,
    ),
    #[error("receive message")]
    ReceiveMessage(#[source] CompleteRoundError<RoundInputError, IErr>),
    #[error("send message")]
    SendError(#[source] OErr),
    #[error("bug occurred")]
    Bug(Bug),
}

/// Protocol was aborted by malicious party
///
/// It _can be_ cryptographically proven, but we do not support it yet.
#[derive(Debug, Error)]
pub enum ProtocolAborted {
    #[error("party decommitment doesn't match commitment: {parties:?}")]
    InvalidDecommitment { parties: Vec<u16> },
    #[error("party provided invalid schnorr proof: {parties:?}")]
    InvalidSchnorrProof { parties: Vec<u16> },
}

/// Bug occurred
///
/// Please, report this issue
#[derive(Debug, Error)]
#[error(transparent)]
pub struct Bug(BugReason);

#[derive(Debug, Error)]
enum BugReason {
    #[error("hash to scalar returned error")]
    HashToScalarError(#[source] generic_ec::errors::HashError),
    #[error("`Tag` appears to be invalid `generic_ec::hash_to_curve::Tag`")]
    InvalidHashToCurveTag,
}

impl<IErr, OErr> From<BugReason> for KeygenError<IErr, OErr> {
    fn from(err: BugReason) -> Self {
        KeygenError::Bug(Bug(err))
    }
}
