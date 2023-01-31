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
use paillier_zk::{unknown_order::BigNumber, libpaillier};
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
    util::xor_array,
    utils, ExecutionId,
};

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
    /// **X_j** in paper
    x: Vec<Point<E>>,
    sch_commits_a: Vec<schnorr_pok::Commit<E>>,
    Y: Point<E>,
    sch_commit_b: schnorr_pok::Commit<E>,
    N: BigNumber,
    s: BigNumber,
    t: BigNumber,
    params_proof: (),   // TODO
    rho_bytes: Vec<u8>, // FIXME: [u8; L::SECURITY_BYTES]
    decommit: hash_commitment::DecommitNonce<D>,
}

#[derive(Clone)]
pub struct MsgRound3<E: Curve> {
    mod_proof: (),       // TODO
    fac_proofs: Vec<()>, // TODO
    sch_proof_y: schnorr_pok::Proof<E>,
    C: Vec<BigNumber>, // TODO: each participant receives their own C and
                       // sch_proof_x
    sch_proof_xs: Vec<schnorr_pok::Proof<E>>,
}

pub async fn refresh<R, M, E, L, D>(
    rng: &mut R,
    party: M,
    i: u16,
    n: u16,
    execution_id: ExecutionId<E, L, D>,
    core_share: IncompleteKeyShare<E, L>,
) -> Result<KeyShare<E, L>, KeyRefreshError<M::ReceiveError, M::SendError>>
where
    R: RngCore + CryptoRng,
    M: Mpc<ProtocolMessage = Msg<E, D>>,
    E: Curve,
    Scalar<E>: FromHash,
    L: SecurityLevel,
    D: Digest + Clone + 'static,
{
    let MpcParty { delivery, .. } = party.into_party();
    let (incomings, mut outgoings) = delivery.split();

    // Setup networking
    let mut rounds = RoundsRouter::<Msg<E, D>>::builder();
    let round1 = rounds.add_round(RoundInput::<MsgRound1<D>>::broadcast(i, n));
    let round2 = rounds.add_round(RoundInput::<MsgRound2<E, D>>::broadcast(i, n));
    let round3 = rounds.add_round(RoundInput::<MsgRound3<E>>::broadcast(i, n));
    let mut rounds = rounds.listen(incomings);

    let execution_id = execution_id.evaluate(ProtocolChoice::Keygen);
    let sid = execution_id.as_slice();
    let tag_htc = hash_to_curve::Tag::new(&execution_id)
        .ok_or(KeyRefreshError::Bug("invalid hash to curve tag"))?;

    // Round 1

    let p = BigNumber::safe_prime_from_rng(4 * L::SECURITY_BITS, rng);
    let q = BigNumber::safe_prime_from_rng(4 * L::SECURITY_BITS, rng);
    let N = &p * &q;
    let φ_N = (&p - 1) * (&q - 1);
    let dec = libpaillier::DecryptionKey::with_primes_unchecked(&p, &q)
        .ok_or(KeyRefreshError::Bug("Creating decryption key"))?;

    let y = SecretScalar::<E>::random(rng);
    let Y = Point::generator() * &y;
    let (sch_secret_b, sch_commit_b) = schnorr_pok::prover_commits_ephemeral_secret::<E, _>(rng);

    // *x_i* in paper
    let mut xs = (0..n - 1)
        .map(|_| SecretScalar::<E>::random(rng))
        .collect::<Vec<_>>();
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

    let r = gen_invertible(&N, rng);
    let λ = BigNumber::from_rng(&φ_N, rng);
    let t = r.modmul(&r, &N);
    let s = t.modpow(&λ, &N);

    let my_aux = PartyAux { N, s, t, Y };

    let params_proof = (); // TODO

    // tau_j and A_i^j
    let (sch_secrets_a, sch_commits_a) = (0..(n - 1))
        .map(|_| schnorr_pok::prover_commits_ephemeral_secret::<E, _>(rng))
        .unzip::<_, _, Vec<_>, Vec<_>>();

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
        .mix_bytes(&my_aux.N.to_bytes())
        .mix_bytes(&my_aux.s.to_bytes())
        .mix_bytes(&my_aux.t.to_bytes())
        // mix param proof
        .mix_bytes(&rho_bytes)
        .commit(rng);

    outgoings
        .send(Outgoing::broadcast(Msg::Round1(MsgRound1 {
            commitment: hash_commit,
        })))
        .await
        .map_err(KeyRefreshError::SendError)?;

    // Round 2
    let commitments = rounds
        .complete(round1)
        .await
        .map_err(KeyRefreshError::ReceiveMessage)?
        .into_vec_without_me();
    let decommitment = MsgRound2 {
        x: Xs.clone(),
        sch_commits_a: sch_commits_a.clone(),
        Y: my_aux.Y.clone(),
        sch_commit_b: sch_commit_b.clone(),
        N: my_aux.N.clone(),
        s: my_aux.s.clone(),
        t: my_aux.t.clone(),
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
        .map_err(KeyRefreshError::ReceiveMessage)?
        .into_vec_including_me(decommitment);

    // TODO: validate params_proofs
    // TODO: validate decommitments
    // TODO: validate everyone sent the correct amount of bytes

    let party_auxes = decommitments
        .iter()
        .map(|d| PartyAux {
            N: d.N.clone(),
            s: d.s.clone(),
            t: d.t.clone(),
            Y: d.Y.clone(),
        })
        .collect::<Vec<_>>();
    let encs = party_auxes
        .iter()
        .map(|aux| utils::encryption_key_from_n(&aux.N))
        .collect::<Vec<_>>();

    let rho_bytes = decommitments
        .iter()
        .map(|d| &d.rho_bytes)
        .fold(rho_bytes, xor_array);

    // psi_i
    let mod_proof = (); // TODO
                        // phi_j,i
    let fac_proofs = Vec::new(); //TODO
                                 // psi_i^j
    let sch_proof_xs = sch_secrets_a
        .iter()
        .zip(xs.iter())
        .map(|(secret, x)| {
            let challenge =
                Scalar::<E>::hash_concat(tag_htc, &[&i.to_be_bytes(), rho_bytes.as_ref()])
                    .map_err(|_| KeyRefreshError::Bug("hash failed"))?;
            let challenge = schnorr_pok::Challenge { nonce: challenge };
            Ok(schnorr_pok::prove(secret, &challenge, &x))
        })
        .collect::<Result<Vec<_>, _>>()?;
    // C_i^j
    let Cs = xs
        .iter()
        .zip(encs.iter())
        .map(|(x, enc)| {
            enc.encrypt(x.as_ref().to_be_bytes(), None)
                .ok_or(KeyRefreshError::Bug("encryption failed"))
                .map(|x| x.0)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let sch_proof_y = {
        let challenge = Scalar::<E>::hash_concat(tag_htc, &[&i.to_be_bytes(), rho_bytes.as_ref()])
            .map_err(|_| KeyRefreshError::Bug("hash failed"))?;
        let challenge = schnorr_pok::Challenge { nonce: challenge };
        schnorr_pok::prove(&sch_secret_b, &challenge, &y)
    };

    let msg = MsgRound3 {
        mod_proof,
        fac_proofs,
        sch_proof_xs,
        sch_proof_y,
        C: Cs,
    };
    outgoings
        .send(Outgoing::broadcast(Msg::Round3(msg.clone())))
        .await
        .map_err(KeyRefreshError::SendError)?;

    // Output

    let shares_msg = rounds.complete(round3).await.map_err(KeyRefreshError::ReceiveMessage)?
        .into_vec_including_me(msg);
    let shares = shares_msg.iter().map(|m| {
        // TODO: in fact you should only receive your c in the first place
        let my_c = m.C[i as usize].clone();
        dec.decrypt(&my_c).ok_or(KeyRefreshError::PaillierDec)
    }).collect::<Result<Vec<_>, _>>()?;

    // TODO: verify shares are well formed
    // TODO: verify mod_proofs
    // TODO: verify fac_proofs
    // TODO: verify sch_proofs

    let x_sum = shares.iter().fold(Scalar::zero(), |s, x| s + Scalar::from_be_bytes(x).unwrap());
    let mut x_star = core_share.x + x_sum;
    let X_prods = (0..n).map(|k| {
        let k = k as usize;
        decommitments.iter().map(|d| d.x[k]).sum::<Point<E>>()
    });
    let X_stars = core_share.public_shares.into_iter().zip(X_prods).map(|(x, p)| x + p).collect();

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

fn gen_invertible<R: RngCore>(modulo: &BigNumber, rng: &mut R) -> BigNumber {
    loop {
        let r = BigNumber::from_rng(&modulo, rng);
        if r.gcd(&modulo) == BigNumber::one() {
            break r;
        }
    }
}

#[derive(Debug, Error)]
pub enum KeyRefreshError<IErr, OErr> {
    /// Protocol was maliciously aborted by another party
    #[error("protocol was aborted by malicious party")]
    Aborted(&'static str),
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
}

#[cfg(test)]
#[generic_tests::define(attrs(tokio::test, test_case::case))]
mod test {
    use generic_ec::{hash_to_curve::FromHash, Point};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use round_based::simulation::Simulation;
    use sha2::Sha256;

    use crate::{security_level::ReasonablySecure, ExecutionId};
    use crate::key_share::Valid;

    #[test_case::case(2; "n2")]
    #[tokio::test]
    async fn keygen_works<E: generic_ec::Curve>(n: u16)
    where
        generic_ec::Scalar<E> : FromHash,
        Point<E>: generic_ec::coords::HasAffineX<E> ,
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
        let outputs = key_shares.into_iter().enumerate().map(|(i, incomplete_share)| {
            let party = simulation.add_party();
            let keygen_execution_id = keygen_execution_id.clone();
            let mut party_rng = ChaCha20Rng::from_seed(rng.gen());
            async move {
                super::refresh(
                    &mut party_rng,
                    party,
                    i as u16,
                    n,
                    keygen_execution_id,
                    incomplete_share.into(),
                ).await
            }
        });

        let key_shares = futures::future::try_join_all(outputs)
            .await
            .expect("keygen failed");

        for (i, key_share) in key_shares.iter().enumerate() {
            let i = i as u16;
            assert_eq!(i, key_share.core.i);
            assert_eq!(key_share.core.shared_public_key, key_shares[0].core.shared_public_key);
            assert_eq!(key_share.core.rid.as_ref(), key_shares[0].core.rid.as_ref());
            assert_eq!(key_share.core.public_shares, key_shares[0].core.public_shares);
            assert_eq!(
                Point::<E>::generator() * &key_share.core.x,
                key_share.core.public_shares[usize::from(i)]
            );
        }
        assert_eq!(
            key_shares[0].core.shared_public_key,
            key_shares[0].core.public_shares.iter().sum::<Point<E>>()
        );
        let key_shares = key_shares.into_iter().map(|s| s.try_into().unwrap()).collect::<Vec<Valid<_>>>();

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
