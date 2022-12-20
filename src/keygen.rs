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
    rounds::simple_store::{RoundInput, RoundInputError},
    rounds::{CompleteRoundError, Rounds},
    Delivery, Mpc, MpcParty, Outgoing, ProtocolMessage,
};
use thiserror::Error;

use crate::execution_id::ProtocolChoice;
use crate::key_share::IncompleteKeyShare;
use crate::security_level::SecurityLevel;
use crate::ExecutionId;

/// Message of key generation protocol
#[derive(ProtocolMessage, Clone)]
pub enum Msg<E: Curve, L: SecurityLevel, D: Digest> {
    Round1(MsgRound1<D>),
    Round2(MsgRound2<E, L, D>),
    Round3(MsgRound3<E>),
}

/// Message from round 1
#[derive(Clone)]
pub struct MsgRound1<D: Digest> {
    commitment: HashCommit<D>,
}
/// Message from round 2
#[derive(Clone)]
pub struct MsgRound2<E: Curve, L: SecurityLevel, D: Digest> {
    rid: L::Rid,
    X: Point<E>,
    sch_commit: schnorr_pok::Commit<E>,
    decommit: hash_commitment::DecommitNonce<D>,
}
/// Message from round 3
#[derive(Clone)]
pub struct MsgRound3<E: Curve> {
    sch_proof: schnorr_pok::Proof<E>,
}

/// Key generation entry point
pub struct KeygenBuilder<E: Curve, L: SecurityLevel, D: Digest> {
    i: u16,
    n: u16,
    execution_id: ExecutionId<E, L, D>,
}

impl<E, L, D> KeygenBuilder<E, L, D>
where
    E: Curve,
    Scalar<E>: FromHash,
    L: SecurityLevel,
    D: Digest + Clone + 'static,
{
    /// Constructs [KeygenBuilder]
    ///
    /// Takes local party index $i$ and number of parties $n$
    pub fn new(i: u16, n: u16) -> Self {
        Self {
            i,
            n,
            execution_id: ExecutionId::default(),
        }
    }

    /// Specifies another hash function to use
    ///
    /// _Caution_: this function overwrites [execution ID](Self::set_execution_id). Make sure
    /// you specify execution ID **after** calling this function.
    pub fn set_digest<D2>(self) -> KeygenBuilder<E, L, D2>
    where
        D2: Digest + Clone + 'static,
    {
        KeygenBuilder {
            i: self.i,
            n: self.n,
            execution_id: Default::default(),
        }
    }

    /// Specifies [security level](crate::security_level)
    ///
    /// _Caution_: this function overwrites [execution ID](Self::set_execution_id). Make sure
    /// you specify execution ID **after** calling this function.
    pub fn set_security_level<L2>(self) -> KeygenBuilder<E, L2, D>
    where
        L2: SecurityLevel,
    {
        KeygenBuilder {
            i: self.i,
            n: self.n,
            execution_id: Default::default(),
        }
    }

    /// Specifies [execution ID](ExecutionId)
    pub fn set_execution_id(self, id: ExecutionId<E, L, D>) -> Self {
        Self {
            execution_id: id,
            ..self
        }
    }

    /// Starts key generation
    pub async fn start<R, M>(
        self,
        rng: &mut R,
        party: M,
    ) -> Result<IncompleteKeyShare<E, L>, KeygenError<M::ReceiveError, M::SendError>>
    where
        R: RngCore + CryptoRng,
        M: Mpc<ProtocolMessage = Msg<E, L, D>>,
    {
        let MpcParty { delivery, .. } = party.into_party();
        let (incomings, mut outgoings) = delivery.split();

        // Setup networking
        let mut rounds = Rounds::<Msg<E, L, D>>::builder();
        let round1 = rounds.add_round(RoundInput::<MsgRound1<D>>::broadcast(self.i, self.n));
        let round2 = rounds.add_round(RoundInput::<MsgRound2<E, L, D>>::broadcast(self.i, self.n));
        let round3 = rounds.add_round(RoundInput::<MsgRound3<E>>::broadcast(self.i, self.n));
        let mut rounds = rounds.listen(incomings);

        // Round 1
        let execution_id = self.execution_id.evaluate(ProtocolChoice::Keygen);
        let sid = execution_id.as_slice();
        let tag_htc = hash_to_curve::Tag::new(&execution_id).ok_or(Bug::InvalidHashToCurveTag)?;

        let x_i = SecretScalar::<E>::random(rng);
        let X_i = Point::generator() * &x_i;

        let mut rid = L::Rid::default();
        rng.fill_bytes(rid.as_mut());

        let (sch_secret, sch_commit) = schnorr_pok::prover_commits_ephemeral_secret::<E, _>(rng);

        let (hash_commit, decommit) = HashCommit::<D>::builder()
            .mix_bytes(sid)
            .mix(self.n)
            .mix(self.i)
            .mix_bytes(&rid)
            .mix(X_i)
            .mix(sch_commit.0)
            .commit(rng);

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
                    .mix(decommitment.sch_commit.0)
                    .verify(&commitment.commitment, &decommitment.decommit)
                    .is_err()
            })
            .map(|((j, _), _)| j)
            .collect::<Vec<_>>();
        if !blame.is_empty() {
            return Err(ProtocolAborted::InvalidDecommitment { parties: blame }.into());
        }

        // Calculate challenge
        let rid = decommitments
            .iter()
            .map(|d| &d.rid)
            .fold(L::Rid::default(), xor_array);
        let challenge = Scalar::<E>::hash_concat(tag_htc, &[&self.i.to_be_bytes(), rid.as_ref()])
            .map_err(Bug::HashToScalarError)?;
        let challenge = schnorr_pok::Challenge { nonce: challenge };

        // Prove knowledge of `x_i`
        let sch_proof = schnorr_pok::prove(&sch_secret, &challenge, &x_i);

        let my_sch_proof = MsgRound3 { sch_proof };
        outgoings
            .send(Outgoing::broadcast(Msg::Round3(my_sch_proof.clone())))
            .await
            .map_err(KeygenError::SendError)?;

        // Round 4
        let sch_proofs = rounds
            .complete(round3)
            .await
            .map_err(KeygenError::ReceiveMessage)?
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
            return Err(ProtocolAborted::InvalidSchnorrProof { parties: blame }.into());
        }

        Ok(IncompleteKeyShare {
            curve: Default::default(),
            i: self.i,
            shared_public_key: decommitments.iter().map(|d| d.X).sum(),
            rid,
            public_shares: decommitments.iter().map(|d| d.X).collect(),
            x: x_i,
        })
    }
}

fn xor_array<A, B>(mut a: A, b: B) -> A
where
    A: AsMut<[u8]>,
    B: AsRef<[u8]>,
{
    a.as_mut()
        .iter_mut()
        .zip(b.as_ref())
        .for_each(|(a_i, b_i)| *a_i ^= *b_i);
    a
}

/// Keygen failed
#[derive(Debug, Error)]
pub enum KeygenError<IErr, OErr> {
    /// Protocol was maliciously aborted by another party
    #[error("protocol was aborted by malicious party")]
    Aborted(
        #[source]
        #[from]
        ProtocolAborted,
    ),
    /// Receiving message error
    #[error("receive message")]
    ReceiveMessage(#[source] CompleteRoundError<RoundInputError, IErr>),
    /// Sending message error
    #[error("send message")]
    SendError(#[source] OErr),
    /// Bug occurred
    #[error("bug occurred")]
    Bug(InternalError),
}

/// Error indicating that protocol was aborted by malicious party
///
/// It _can be_ cryptographically proven, but we do not support it yet.
#[derive(Debug, Error)]
pub enum ProtocolAborted {
    #[error("party decommitment doesn't match commitment: {parties:?}")]
    InvalidDecommitment { parties: Vec<u16> },
    #[error("party provided invalid schnorr proof: {parties:?}")]
    InvalidSchnorrProof { parties: Vec<u16> },
}

/// Error indicating that internal bug was detected
///
/// Please, report this issue if you encounter it
#[derive(Debug, Error)]
#[error(transparent)]
pub struct InternalError(Bug);

#[derive(Debug, Error)]
enum Bug {
    #[error("hash to scalar returned error")]
    HashToScalarError(#[source] generic_ec::errors::HashError),
    #[error("`Tag` appears to be invalid `generic_ec::hash_to_curve::Tag`")]
    InvalidHashToCurveTag,
}

impl<IErr, OErr> From<Bug> for KeygenError<IErr, OErr> {
    fn from(err: Bug) -> Self {
        KeygenError::Bug(InternalError(err))
    }
}
