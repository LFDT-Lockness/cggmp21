use digest::Digest;
use futures::SinkExt;
use generic_ec::{
    hash_to_curve::{self, FromHash},
    Curve, Point, Scalar, SecretScalar,
};
use generic_ec_zkp::{
    hash_commitment::{self, HashCommit},
    schnorr_pok,
};
use paillier_zk::{libpaillier, paillier_blum_modulus as π_mod, unknown_order::BigNumber};
use rand_core::{CryptoRng, RngCore};
use round_based::{
    rounds_router::{simple_store::RoundInput, RoundsRouter},
    Delivery, Mpc, MpcParty, Outgoing, ProtocolMessage,
};
use thiserror::Error;

use crate::{
    execution_id::ProtocolChoice,
    key_share::{IncompleteKeyShare, KeyShare, PartyAux},
    security_level::SecurityLevel,
    utils,
    utils::xor_array,
    zk::ring_pedersen_parameters as π_prm,
    ExecutionId,
};

/// Message of key refresh protocol
#[derive(ProtocolMessage, Clone)]
pub enum Msg<E: Curve, D: Digest> {
    Round1(MsgRound1<D>),
    Round2(MsgRound2<E, D>),
    Round3(MsgRound3<E>),
}

/// Message from round 1
#[derive(Clone)]
pub struct MsgRound1<D: Digest> {
    commitment: HashCommit<D>,
}
/// Message from round 2
#[derive(Clone)]
pub struct MsgRound2<E: Curve, D: Digest> {
    /// **X_i** in paper
    x: Vec<Point<E>>,
    /// **A_i** in paper
    sch_commits_a: Vec<schnorr_pok::Commit<E>>,
    Y: Point<E>,
    /// B_i in paper
    sch_commit_b: schnorr_pok::Commit<E>,
    N: BigNumber,
    s: BigNumber,
    t: BigNumber,
    /// psi_circonflexe_i in paper
    params_proof: π_prm::Proof<{ π_prm::SECURITY }>, // TODO
    /// rho_i in paper
    rho_bytes: Vec<u8>, // FIXME: [u8; L::SECURITY_BYTES]
    /// u_i in paper
    decommit: hash_commitment::DecommitNonce<D>,
}
/// Unicast message of round 3, sent to each participant
#[derive(Clone)]
pub struct MsgRound3<E: Curve> {
    /// psi_i in paper
    mod_proof: (π_mod::Commitment, π_mod::Proof<{ π_prm::SECURITY }>), // TODO
    /// phi_i^j in paper
    fac_proof: (), // TODO
    /// pi_i in paper
    sch_proof_y: schnorr_pok::Proof<E>,
    /// C_i^j in paper
    C: BigNumber,
    /// psi_i_j in paper
    ///
    /// Here in the paper you only send one proof, but later they require you to
    /// verify by all the other proofs, that are never sent. We fix this here
    /// and require each party to send every proof to everyone
    sch_proofs_x: Vec<schnorr_pok::Proof<E>>,
}

/*
sch - denis's code as `schnorr_pok`
prm - cggmp page 37, crate::zk::ring_pedersen_parameters
mod - paillier_zk::paillier_blum_modulus
fac - cggmp page 66
*/

pub struct KeyRefreshBuilder<E: Curve, L: SecurityLevel, D: Digest> {
    core_share: IncompleteKeyShare<E, L>,
    execution_id: ExecutionId<E, L, D>,
}

impl<E: Curve, L: SecurityLevel, D: Digest> KeyRefreshBuilder<E, L, D> {
    pub fn new(core_share: IncompleteKeyShare<E, L>) -> Self {
        Self {
            core_share,
            execution_id: Default::default(),
        }
    }

    pub fn new_refresh(key_share: KeyShare<E, L>) -> Self {
        Self {
            core_share: key_share.core,
            execution_id: Default::default(),
        }
    }

    pub fn with_digest<D2: Digest>(this: KeyRefreshBuilder<E, L, D2>) -> KeyRefreshBuilder<E, L, D2> {
        this
    }

    pub fn set_execution_id(self, execution_id: ExecutionId<E, L, D>) -> Self {
        Self {
            execution_id,
            ..self
        }
    }

    pub async fn start<R, M>(
        self,
        rng: &mut R,
        party: M,
    ) -> Result<KeyShare<E, L>, KeyRefreshError<M::ReceiveError, M::SendError>>
    where
        R: RngCore + CryptoRng,
        M: Mpc<ProtocolMessage = Msg<E, D>>,
        E: Curve,
        Scalar<E>: FromHash,
        L: SecurityLevel,
        D: Digest<OutputSize = digest::typenum::U32> + Clone + 'static,
    {
        run_refresh(
            rng,
            party,
            self.execution_id,
            self.core_share,
        ).await
    }
}

pub async fn run_refresh<R, M, E, L, D>(
    mut rng: &mut R,
    party: M,
    execution_id: ExecutionId<E, L, D>,
    core_share: IncompleteKeyShare<E, L>,
) -> Result<KeyShare<E, L>, KeyRefreshError<M::ReceiveError, M::SendError>>
where
    R: RngCore + CryptoRng,
    M: Mpc<ProtocolMessage = Msg<E, D>>,
    E: Curve,
    Scalar<E>: FromHash,
    L: SecurityLevel,
    D: Digest<OutputSize = digest::typenum::U32> + Clone + 'static,
{
    let i = core_share.i;
    let n = core_share.public_shares.len() as u16;

    let MpcParty { delivery, .. } = party.into_party();
    let (incomings, mut outgoings) = delivery.split();

    // Setup networking
    let mut rounds = RoundsRouter::<Msg<E, D>>::builder();
    let round1 = rounds.add_round(RoundInput::<MsgRound1<D>>::broadcast(i, n));
    let round2 = rounds.add_round(RoundInput::<MsgRound2<E, D>>::broadcast(i, n));
    let round3 = rounds.add_round(RoundInput::<MsgRound3<E>>::p2p(i, n));
    let mut rounds = rounds.listen(incomings);

    let execution_id = execution_id.evaluate(ProtocolChoice::Keygen);
    let sid = execution_id.as_slice();
    let tag_htc = hash_to_curve::Tag::new(&execution_id)
        .ok_or(KeyRefreshError::Bug("invalid hash to curve tag"))?;
    let parties_shared_state = D::new_with_prefix(&execution_id);

    // Round 1

    let p = BigNumber::safe_prime_from_rng(4 * L::SECURITY_BITS, rng);
    let q = BigNumber::safe_prime_from_rng(4 * L::SECURITY_BITS, rng);
    let N = &p * &q;
    let φ_N = (&p - 1) * (&q - 1);
    let dec = libpaillier::DecryptionKey::with_primes_unchecked(&p, &q)
        .ok_or(KeyRefreshError::Bug("Creating decryption key"))?;

    let y = SecretScalar::<E>::random(rng);
    let Y = Point::generator() * &y;
    // tau and B_i in paper
    let (sch_secret_b, sch_commit_b) = schnorr_pok::prover_commits_ephemeral_secret::<E, _>(rng);

    // *x_i* in paper
    // generate n-1 values first..
    let mut xs = (0..n - 1)
        .map(|_| SecretScalar::<E>::random(rng))
        .collect::<Vec<_>>();
    // then create a last element such that the sum is zero
    let mut x_last = -xs.iter().fold(Scalar::<E>::zero(), |s, x| s + x.as_ref());
    xs.push(SecretScalar::new(&mut x_last));
    drop(x_last);
    debug_assert_eq!(
        xs.iter().fold(Scalar::<E>::zero(), |s, x| s + x.as_ref()),
        Scalar::zero()
    );
    // *X_i* in paper
    let Xs = xs
        .iter()
        .map(|x| Point::generator() * x)
        .collect::<Vec<_>>();

    let r = utils::gen_invertible(&N, rng);
    let λ = BigNumber::from_rng(&φ_N, rng);
    let t = r.modmul(&r, &N);
    let s = t.modpow(&λ, &N);

    let proof_data = π_prm::Data {
        N: &N,
        s: &s,
        t: &t,
    };
    let params_proof = π_prm::prove(parties_shared_state.clone(), &mut rng, proof_data, &φ_N, &λ);

    // tau_j and A_i^j in paper
    // TODO: don't commit for myself
    let (sch_secrets_a, sch_commits_a) = (0..n)
        .map(|_| schnorr_pok::prover_commits_ephemeral_secret::<E, _>(rng))
        .unzip::<_, _, Vec<_>, Vec<_>>();

    // rho_i in paper, this signer's share of bytes
    let mut rho_bytes = Vec::new();
    rho_bytes.resize(L::SECURITY_BYTES, 0);
    rng.fill_bytes(&mut rho_bytes);

    let (hash_commit, decommit) = HashCommit::<D>::builder()
        .mix_bytes(sid)
        .mix(n)
        .mix(i)
        .mix_many(&Xs)
        .mix_many(sch_commits_a.iter().map(|a| a.0))
        .mix(&Y)
        .mix_bytes(&N.to_bytes())
        .mix_bytes(&s.to_bytes())
        .mix_bytes(&t.to_bytes())
        // mix param proof
        .mix_bytes(&rho_bytes)
        .commit(rng);

    let commitment = MsgRound1 {
        commitment: hash_commit,
    };
    outgoings
        .send(Outgoing::broadcast(Msg::Round1(commitment.clone())))
        .await
        .map_err(KeyRefreshError::SendError)?;

    // Round 2
    let commitments = rounds
        .complete(round1)
        .await
        .map_err(KeyRefreshError::ReceiveMessage)?;
    let decommitment = MsgRound2 {
        x: Xs.clone(),
        sch_commits_a: sch_commits_a.clone(),
        Y,
        sch_commit_b: sch_commit_b.clone(),
        N: N.clone(),
        s,
        t,
        params_proof,
        rho_bytes: rho_bytes.clone(),
        decommit,
    };
    outgoings
        .send(Outgoing::broadcast(Msg::Round2(decommitment.clone())))
        .await
        .map_err(KeyRefreshError::SendError)?;

    // Round 3

    let decommitments = rounds
        .complete(round2)
        .await
        .map_err(KeyRefreshError::ReceiveMessage)?;

    // validate decommitments
    let blame = commitments
        .iter_indexed()
        .zip(decommitments.iter_indexed())
        .filter(|((j, _, commitment), (j_, _, decommitment))| {
            debug_assert_eq!(j, j_);
            HashCommit::<D>::builder()
                .mix_bytes(sid)
                .mix(n)
                .mix(j)
                .mix_many(&decommitment.x)
                .mix_many(decommitment.sch_commits_a.iter().map(|a| a.0))
                .mix(&decommitment.Y)
                .mix_bytes(&decommitment.N.to_bytes())
                .mix_bytes(&decommitment.s.to_bytes())
                .mix_bytes(&decommitment.t.to_bytes())
                // mix param proof
                .mix_bytes(&decommitment.rho_bytes)
                .verify(&commitment.commitment, &decommitment.decommit)
                .is_err()
        })
        .map(|tuple| tuple.0 .0)
        .collect::<Vec<_>>();
    if !blame.is_empty() {
        return Err(KeyRefreshError::Aborted(
            ProtocolAborted::InvalidDecommitment { parties: blame },
        ));
    }
    // validate parameters and param_proofs
    let blame = decommitments
        .iter_indexed()
        .filter(|(_, _, d)| {
            if d.N.bit_length() < L::SECURITY_BYTES {
                true
            } else {
                let data = π_prm::Data {
                    N: &d.N,
                    s: &d.s,
                    t: &d.t,
                };
                π_prm::verify(parties_shared_state.clone(), data, &d.params_proof).is_err()
            }
        })
        .map(|t| t.0)
        .collect::<Vec<_>>();
    if !blame.is_empty() {
        return Err(KeyRefreshError::Aborted(
            ProtocolAborted::InvalidRingPedersenParameters { parties: blame },
        ));
    }
    // validate Xs add to zero
    let blame = decommitments
        .iter_indexed()
        .filter(|(_, _, d)| {
            d.x.len() != (n as usize) || d.x.iter().sum::<Point<E>>() != Point::zero()
        })
        .map(|t| t.0)
        .collect::<Vec<_>>();
    if !blame.is_empty() {
        return Err(KeyRefreshError::Aborted(
            // TODO reason
            ProtocolAborted::InvalidX { parties: blame },
        ));
    }

    let party_auxes = decommitments
        .iter_including_me(&decommitment)
        .map(|d| PartyAux {
            N: d.N.clone(),
            s: d.s.clone(),
            t: d.t.clone(),
            Y: d.Y.clone(),
        })
        .collect::<Vec<_>>();
    // TODO: don't create key for self
    let encs = party_auxes
        .iter()
        .map(|aux| utils::encryption_key_from_n(&aux.N))
        .collect::<Vec<_>>();

    // rho in paper, collective random bytes
    let rho_bytes = decommitments
        .iter()
        .map(|d| &d.rho_bytes)
        .fold(rho_bytes, xor_array);

    // pi_i
    let sch_proof_y = {
        let challenge = Scalar::<E>::hash_concat(tag_htc, &[&i.to_be_bytes(), rho_bytes.as_ref()])
            .map_err(|_| KeyRefreshError::Bug("hash failed"))?;
        let challenge = schnorr_pok::Challenge { nonce: challenge };
        schnorr_pok::prove(&sch_secret_b, &challenge, &y)
    };

    // common data for messages
    let mod_proof = {
        let data = π_mod::Data { n: N.clone() };
        let pdata = π_mod::PrivateData {
            p: p.clone(),
            q: q.clone(),
        };
        π_mod::non_interactive::prove(parties_shared_state.clone(), &data, &pdata, rng)
    };
    let challenge = Scalar::<E>::hash_concat(tag_htc, &[&i.to_be_bytes(), rho_bytes.as_ref()])
        .map_err(|_| KeyRefreshError::Bug("hash failed"))?;
    let challenge = schnorr_pok::Challenge { nonce: challenge };
    // save a message we would send to ourself
    // TODO: don't do that. Don't encrypt message for self
    let mut my_msg = None;
    // message to each party
    for (j, ((x, enc), secret)) in xs.iter().zip(&encs).zip(&sch_secrets_a).enumerate() {
        let j = j as u16;

        let sch_proofs_x = xs
            .iter()
            .map(|x_j| schnorr_pok::prove(secret, &challenge, &x_j))
            .collect();
        let C = enc
            .encrypt(x.as_ref().to_be_bytes(), None)
            .ok_or(KeyRefreshError::Bug("encryption failed"))?
            .0;
        let fac_proof = ();

        let msg = MsgRound3 {
            mod_proof: mod_proof.clone(),
            fac_proof,
            sch_proof_y: sch_proof_y.clone(),
            sch_proofs_x,
            C,
        };
        if j == i {
            my_msg = Some(msg);
        } else {
            outgoings
                .send(Outgoing::p2p(j, Msg::Round3(msg)))
                .await
                .map_err(KeyRefreshError::SendError)?;
        }
    }
    // safe because j, i <- 0..n
    let my_msg = my_msg.unwrap();

    // Output

    let shares_msg_b = rounds
        .complete(round3)
        .await
        .map_err(KeyRefreshError::ReceiveMessage)?;

    // TODO: don't decrypt message for self
    let shares = shares_msg_b
        .iter_including_me(&my_msg)
        .map(|m| {
            let bytes = dec.decrypt(&m.C).ok_or(KeyRefreshError::PaillierDec)?;
            Scalar::from_be_bytes(bytes).map_err(|e| KeyRefreshError::InvalidScalar(e))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // TODO: verify shares are well formed
    // TODO: verify fac_proofs
    // verify sch proofs for y and x
    let blame = utils::collect_blame(
        decommitments
            .iter_indexed()
            .zip(shares_msg_b.iter_indexed()),
        |((j, _, decommitment), (j_, _, proof_msg))| {
            debug_assert_eq!(j, j_);
            let i = i as usize;

            let challenge =
                Scalar::<E>::hash_concat(tag_htc, &[&j.to_be_bytes(), rho_bytes.as_ref()])
                    .map_err(|_| KeyRefreshError::Bug("hash failed"))?;
            let challenge = schnorr_pok::Challenge { nonce: challenge };

            // proof for y, i.e. pi_j
            let sch_proof = &proof_msg.sch_proof_y;
            if sch_proof
                .verify(&decommitment.sch_commit_b, &challenge, &decommitment.Y)
                .is_err()
            {
                return Ok(Some(j));
            }

            // proof for x, i.e. psi_j^k for every k
            for (sch_proof, x) in proof_msg.sch_proofs_x.iter().zip(&decommitment.x) {
                // TODO: when the commit for self isn't sent, this can't be obtained by
                // simple indexing
                if sch_proof
                    .verify(&decommitment.sch_commits_a[i], &challenge, x)
                    .is_err()
                {
                    return Ok(Some(j));
                }
            }
            Ok(None)
        },
    )?;
    if !blame.is_empty() {
        return Err(KeyRefreshError::Aborted(
            ProtocolAborted::InvalidSchnorrProof { parties: blame },
        ));
    }

    // verify mod proofs
    let blame = decommitments
        .iter_indexed()
        .zip(shares_msg_b.iter())
        .filter_map(|((j, _, decommitment), proof_msg)| {
            let data = π_mod::Data {
                n: decommitment.N.clone(),
            };
            let (ref comm, ref proof) = proof_msg.mod_proof;
            if π_mod::non_interactive::verify(parties_shared_state.clone(), &data, &comm, &proof)
                .is_err()
            {
                Some(j)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    if !blame.is_empty() {
        return Err(KeyRefreshError::Aborted(
            // TODO: not schnorr
            ProtocolAborted::InvalidSchnorrProof { parties: blame },
        ));
    }

    let x_sum = shares.iter().fold(Scalar::zero(), |s, x| s + x);
    let mut x_star = core_share.x + x_sum;
    let X_prods = (0..n).map(|k| {
        let k = k as usize;
        decommitments
            .iter_including_me(&decommitment)
            .map(|d| d.x[k])
            .sum::<Point<E>>()
    });
    let X_stars = core_share
        .public_shares
        .into_iter()
        .zip(X_prods)
        .map(|(x, p)| x + p)
        .collect();

    let new_core_share = IncompleteKeyShare {
        curve: core_share.curve,
        i, // FIXME: known in core_share as well
        shared_public_key: core_share.shared_public_key,
        rid: core_share.rid,
        public_shares: X_stars,
        x: SecretScalar::new(&mut x_star),
    };
    let key_share = KeyShare {
        core: new_core_share,
        p,
        q,
        y,
        parties: party_auxes,
    };

    Ok(key_share)
}

#[derive(Debug, Error)]
pub enum KeyRefreshError<IErr, OErr> {
    /// Protocol was maliciously aborted by another party
    #[error("protocol was aborted by malicious party")]
    Aborted(#[source] ProtocolAborted),
    /// Receiving message error
    #[error("receive message")]
    ReceiveMessage(
        #[source]
        round_based::rounds_router::CompleteRoundError<
            round_based::rounds_router::simple_store::RoundInputError,
            IErr,
        >,
    ),
    /// Sending message error
    #[error("send message")]
    SendError(#[source] OErr),
    /// Bug occurred
    #[error("bug occurred")]
    Bug(&'static str),
    #[error("couldn't decrypt a message")]
    PaillierDec,
    #[error("couldn't decode scalar bytes")]
    InvalidScalar(generic_ec::errors::InvalidScalar),
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
    #[error("party N, s and t parameters are invalid")]
    InvalidRingPedersenParameters { parties: Vec<u16> },
    #[error("party X is malformed")]
    InvalidX { parties: Vec<u16> },
}

#[cfg(test)]
#[generic_tests::define(attrs(tokio::test, test_case::case))]
mod test {
    use generic_ec::{hash_to_curve::FromHash, Point};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use round_based::simulation::Simulation;
    use sha2::Sha256;

    use crate::key_share::Valid;
    use crate::{security_level::ReasonablySecure, ExecutionId};

    #[test_case::case(5; "n3")]
    #[tokio::test]
    async fn keygen_works<E: generic_ec::Curve>(n: u16)
    where
        generic_ec::Scalar<E>: FromHash,
        Point<E>: generic_ec::coords::HasAffineX<E>,
    {
        let mut rng = rand_dev::DevRng::new();

        let keygen_execution_id: [u8; 32] = rng.gen();
        let keygen_execution_id =
            ExecutionId::<E, ReasonablySecure>::from_bytes(&keygen_execution_id);

        // Create keyshare cores

        let mut simulation = Simulation::<crate::keygen::Msg<E, ReasonablySecure, Sha256>>::new();
        let mut outputs = vec![];
        for i in 0..n {
            let party = simulation.add_party();
            let keygen_execution_id = keygen_execution_id.clone();
            let mut party_rng = ChaCha20Rng::from_seed(rng.gen());

            outputs.push(async move {
                crate::keygen(i, n)
                    .set_execution_id(keygen_execution_id)
                    .start(&mut party_rng, party)
                    .await
            })
        }

        let key_shares = futures::future::try_join_all(outputs)
            .await
            .expect("keygen failed");

        // Create keyshares proper

        let mut simulation = Simulation::<super::Msg<E, Sha256>>::new();
        let outputs = key_shares
            .into_iter()
            .map(|incomplete_share| {
                let party = simulation.add_party();
                let keygen_execution_id = keygen_execution_id.clone();
                let mut party_rng = ChaCha20Rng::from_seed(rng.gen());
                async move {
                    super::run_refresh(
                        &mut party_rng,
                        party,
                        keygen_execution_id,
                        incomplete_share.into(),
                    )
                    .await
                }
            });

        let key_shares = futures::future::try_join_all(outputs)
            .await
            .expect("keygen failed");

        for (i, key_share) in key_shares.iter().enumerate() {
            let i = i as u16;
            assert_eq!(i, key_share.core.i);
            assert_eq!(
                key_share.core.shared_public_key,
                key_shares[0].core.shared_public_key
            );
            assert_eq!(key_share.core.rid.as_ref(), key_shares[0].core.rid.as_ref());
            assert_eq!(
                key_share.core.public_shares,
                key_shares[0].core.public_shares
            );
            assert_eq!(
                Point::<E>::generator() * &key_share.core.x,
                key_share.core.public_shares[usize::from(i)]
            );
        }
        assert_eq!(
            key_shares[0].core.shared_public_key,
            key_shares[0].core.public_shares.iter().sum::<Point<E>>()
        );
        let key_shares = key_shares
            .into_iter()
            .map(|s| s.try_into().unwrap())
            .collect::<Vec<Valid<_>>>();

        // Sign and verify the signature

        let mut simulation = Simulation::<crate::signing::Msg<E, Sha256>>::new();
        let message_to_sign = b"Dfns rules!";
        let message_to_sign = crate::signing::Message::new::<Sha256>(message_to_sign);

        let mut outputs = vec![];
        for share in &key_shares {
            let party = simulation.add_party();
            let signing_execution_id = keygen_execution_id.clone();
            let mut party_rng = ChaCha20Rng::from_seed(rng.gen());

            outputs.push(async move {
                crate::signing(share)
                    .set_execution_id(signing_execution_id)
                    .sign(&mut party_rng, party, message_to_sign)
                    .await
            });
        }

        let signatures = futures::future::try_join_all(outputs)
            .await
            .expect("signing failed");

        signatures[0]
            .verify(&key_shares[0].core.shared_public_key, &message_to_sign)
            .expect("signature is not valid");

        assert!(signatures.iter().all(|s_i| signatures[0] == *s_i));
    }

    #[instantiate_tests(<generic_ec::curves::Secp256r1>)]
    mod secp256r1 {}
}
