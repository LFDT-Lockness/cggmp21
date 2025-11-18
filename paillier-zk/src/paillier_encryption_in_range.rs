//! ZK-proof of paillier encryption in range. Called Пenc or Renc in the CGGMP24
//! paper.
//!
//! ## Description
//!
//! A party P has `key`, `pkey` - public and private keys in paillier
//! cryptosystem. P also has `plaintext`, `nonce`, and
//! `ciphertext = key.encrypt_with(plaintext, nonce)`.
//!
//! P wants to prove that `plaintext` is at most `l` bits, without disclosing
//! it, the `pkey`, and `nonce`

//! ## Example
//!
//! ```
//! use paillier_zk::{paillier_encryption_in_range as p, IntegerExt};
//! use fast_paillier::backend::Integer;
//! # mod pregenerated {
//! #     use super::*;
//! #     paillier_zk::load_pregenerated_data!(
//! #         verifier_aux: p::Aux,
//! #         prover_decryption_key: fast_paillier::DecryptionKey,
//! #     );
//! # }
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//!
//! let shared_state = "some shared state";
//!
//! let mut rng = rand_core::OsRng;
//! # let mut rng = rand_dev::DevRng::new();
//!
//! // 0. Setup: prover and verifier share common Ring-Pedersen parameters:
//!
//! let aux: p::Aux = pregenerated::verifier_aux();
//! let security = p::SecurityParams {
//!     l: 256,
//!     epsilon: 512,
//!     q: Integer::curve_order::<generic_ec::curves::Secp256k1>(),
//! };
//!
//! // 1. Setup: prover prepares the paillier keys
//!
//! let private_key: fast_paillier::DecryptionKey =
//!     pregenerated::prover_decryption_key();
//! let key = private_key.encryption_key();
//!
//! // 2. Setup: prover has some plaintext and encrypts it
//!
//! let plaintext = Integer::from_rng_half_pm(&mut rng, &(Integer::one() << security.l));
//! let (ciphertext, nonce) = key.encrypt_with_random(&mut rng, &plaintext)?;
//!
//! // 3. Prover computes a non-interactive proof that plaintext is at most 1024 bits:
//!
//! let data = p::Data { key, ciphertext: &ciphertext };
//! let proof = p::non_interactive::prove::<sha2::Sha256>(
//!     &shared_state,
//!     &aux,
//!     data,
//!     p::PrivateData {
//!         plaintext: &plaintext,
//!         nonce: &nonce,
//!     },
//!     &security,
//!     &mut rng,
//! )?;
//!
//! // 4. Prover sends this data to verifier
//!
//! # fn send(_: &p::Data, _: &p::NiProof) {  }
//! send(&data, &proof);
//!
//! // 5. Verifier receives the data and the proof and verifies it
//!
//! # let recv = || (data, proof);
//! let (data, proof) = recv();
//! p::non_interactive::verify::<sha2::Sha256>(
//!     &shared_state,
//!     &aux,
//!     data,
//!     &security,
//!     &proof,
//! );
//! # Ok(()) }
//! ```
//!
//! If the verification succeeded, verifier can continue communication with prover

use fast_paillier::backend::Integer;
use fast_paillier::{AnyEncryptionKey, Ciphertext, Nonce};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub use crate::common::Aux;
pub use crate::common::InvalidProof;

/// Security parameters for proof. Choosing the values is a tradeoff between
/// speed and chance of rejecting a valid proof or accepting an invalid proof
#[derive(Debug, Clone, udigest::Digestable)]
#[udigest(bound = "")]
pub struct SecurityParams {
    /// l in paper, security parameter for bit size of plaintext: it needs to
    /// be in range [-2^l; 2^l] or equivalently 2^l
    pub l: usize,
    /// Epsilon in paper, slackness parameter
    pub epsilon: usize,
    /// Determines a domain of challenges
    ///
    /// Must be equal to order of the curve
    #[udigest(as = crate::common::encoding::Integer)]
    pub q: Integer,
}

/// Public data that both parties know
#[derive(Debug, Clone, Copy, udigest::Digestable)]
pub struct Data<'a> {
    /// N0 in paper, public key that k -> K was encrypted on
    #[udigest(as = crate::common::encoding::AnyEncryptionKey)]
    pub key: &'a dyn AnyEncryptionKey,
    /// K in paper
    #[udigest(as = &crate::common::encoding::Integer)]
    pub ciphertext: &'a Ciphertext,
}

/// Private data of prover
#[derive(Clone, Copy)]
pub struct PrivateData<'a> {
    /// k in paper, plaintext of K
    pub plaintext: &'a Integer,
    /// rho in paper, nonce of encryption k -> K
    pub nonce: &'a Nonce,
}

// As described in cggmp24 at page 33
/// Prover's first message, obtained by [`interactive::commit`]
#[derive(Debug, Clone, udigest::Digestable)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Commitment {
    #[udigest(as = crate::common::encoding::Integer)]
    pub s: Integer,
    #[udigest(as = crate::common::encoding::Integer)]
    pub a: Integer,
    #[udigest(as = crate::common::encoding::Integer)]
    pub c: Integer,
}

/// Prover's data accompanying the commitment. Kept as state between rounds in
/// the interactive protocol.
#[derive(Clone)]
pub struct PrivateCommitment {
    pub alpha: Integer,
    pub mu: Integer,
    pub r: Integer,
    pub gamma: Integer,
}

/// Verifier's challenge to prover. Can be obtained deterministically by
/// [`non_interactive::challenge`] or randomly by [`interactive::challenge`]
pub type Challenge = Integer;

// As described in cggmp24 at page 33
/// The ZK proof. Computed by [`interactive::prove`].
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Proof {
    pub z1: Integer,
    pub z2: Integer,
    pub z3: Integer,
}

/// The non-interactive ZK proof. Computed by [`non_interactive::prove`].
/// Combines commitment and proof.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NiProof {
    pub commitment: Commitment,
    pub proof: Proof,
}

/// The interactive version of the ZK proof. Should be completed in 3 rounds:
/// prover commits to data, verifier responds with a random challenge, and
/// prover gives proof with commitment and challenge.
pub mod interactive {
    use fast_paillier::backend::Integer;

    use crate::{
        common::{fail_if, fail_if_ne, InvalidProofReason},
        BadExponent, Error,
    };

    use crate::common::{IntegerExt, InvalidProof};

    use super::{
        Aux, Challenge, Commitment, Data, PrivateCommitment, PrivateData, Proof, SecurityParams,
    };

    /// Create random commitment
    pub fn commit(
        aux: &Aux,
        data: Data,
        pdata: PrivateData,
        security: &SecurityParams,
        rng: &mut impl rand_core::RngCore,
    ) -> Result<(Commitment, PrivateCommitment), Error> {
        let two_to_l_plus_e = Integer::one() << (security.l + security.epsilon);
        let hat_n_at_two_to_l = (Integer::one() << security.l) * &aux.rsa_modulo;
        let hat_n_at_two_to_l_plus_e =
            (Integer::one() << (security.l + security.epsilon)) * &aux.rsa_modulo;

        let alpha = Integer::from_rng_half_pm(rng, &two_to_l_plus_e);
        let mu = Integer::from_rng_half_pm(rng, &hat_n_at_two_to_l);
        let r = Integer::sample_in_mult_group_of(rng, data.key.n());
        let gamma = Integer::from_rng_half_pm(rng, &hat_n_at_two_to_l_plus_e);

        let s = aux.combine(pdata.plaintext, &mu)?;
        let a = data.key.encrypt_with(&alpha, &r)?;
        let c = aux.combine(&alpha, &gamma)?;

        Ok((
            Commitment { s, a, c },
            PrivateCommitment {
                alpha,
                mu,
                r,
                gamma,
            },
        ))
    }

    /// Compute proof for given data and prior protocol values
    pub fn prove(
        data: Data,
        pdata: PrivateData,
        private_commitment: &PrivateCommitment,
        challenge: &Challenge,
    ) -> Result<Proof, Error> {
        let z1 = &private_commitment.alpha + (challenge * pdata.plaintext);
        let nonce_to_challenge_mod_n: Integer = pdata
            .nonce
            .pow_mod_ref(challenge, data.key.n())
            .ok_or(BadExponent::undefined())?;
        let z2 = (&private_commitment.r * nonce_to_challenge_mod_n).modulo(data.key.n());
        let z3 = &private_commitment.gamma + (challenge * &private_commitment.mu);
        Ok(Proof { z1, z2, z3 })
    }

    /// Verify the proof
    pub fn verify(
        aux: &Aux,
        data: Data,
        commitment: &Commitment,
        security: &SecurityParams,
        challenge: &Challenge,
        proof: &Proof,
    ) -> Result<(), InvalidProof> {
        fail_if(
            InvalidProofReason::RangeCheck(1),
            data.ciphertext.in_mult_group_of(data.key.nn()),
        )?;
        fail_if(
            InvalidProofReason::RangeCheck(2),
            aux.is_in_mult_group(&commitment.s),
        )?;
        fail_if(
            InvalidProofReason::RangeCheck(3),
            commitment.a.in_mult_group_of(data.key.nn()),
        )?;
        fail_if(
            InvalidProofReason::RangeCheck(4),
            aux.is_in_mult_group(&commitment.c),
        )?;

        fail_if(
            InvalidProofReason::RangeCheck(5),
            proof
                .z1
                .is_in_half_pm(&(Integer::one() << (security.l + security.epsilon))),
        )?;
        fail_if(
            InvalidProofReason::RangeCheck(6),
            proof.z3.is_in_half_pm(
                &(&aux.rsa_modulo * (Integer::one() << (security.l + security.epsilon + 1))),
            ),
        )?;

        {
            let lhs = data
                .key
                .encrypt_with(&proof.z1, &proof.z2)
                .map_err(|_| InvalidProofReason::PaillierEnc)?;
            let rhs = {
                let e_at_k = data
                    .key
                    .omul(challenge, data.ciphertext)
                    .map_err(|_| InvalidProofReason::PaillierOp)?;
                data.key
                    .oadd(&commitment.a, &e_at_k)
                    .map_err(|_| InvalidProofReason::PaillierOp)?
            };
            fail_if_ne(InvalidProofReason::EqualityCheck(2), lhs, rhs)?;
        }

        {
            let lhs = aux.combine(&proof.z1, &proof.z3)?;
            let s_to_e = aux.pow_mod(&commitment.s, challenge)?;
            let rhs = (&commitment.c * s_to_e).modulo(&aux.rsa_modulo);
            fail_if_ne(InvalidProofReason::EqualityCheck(3), lhs, rhs)?;
        }

        Ok(())
    }

    /// Generate random challenge
    ///
    /// `security` parameter is used to generate challenge in correct range
    pub fn challenge(rng: &mut impl rand_core::RngCore, security: &SecurityParams) -> Challenge {
        Integer::from_rng_half_pm(rng, &security.q)
    }
}

/// The non-interactive version of proof. Completed in one round, for example
/// see the documentation of parent module.
pub mod non_interactive {
    use digest::Digest;

    use crate::{Error, InvalidProof};

    use super::{Aux, Challenge, Commitment, Data, NiProof, PrivateData, SecurityParams};

    /// Compute proof for the given data, producing random commitment and
    /// deriving determenistic challenge.
    ///
    /// Obtained from the above interactive proof via Fiat-Shamir heuristic.
    pub fn prove<D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: Data,
        pdata: PrivateData,
        security: &SecurityParams,
        rng: &mut impl rand_core::RngCore,
    ) -> Result<NiProof, Error> {
        let (commitment, pcomm) = super::interactive::commit(aux, data, pdata, security, rng)?;
        let challenge = challenge::<D>(shared_state, aux, data, &commitment, security);
        let proof = super::interactive::prove(data, pdata, &pcomm, &challenge)?;
        Ok(NiProof { commitment, proof })
    }

    /// Deterministically compute challenge based on prior known values in protocol
    pub fn challenge<D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: Data,
        commitment: &Commitment,
        security: &SecurityParams,
    ) -> Challenge {
        let tag = "paillier_zk.encryption_in_range.ni_challenge";
        let seed = udigest::inline_struct!(tag {
            security,
            shared_state,
            aux: aux.digest_public_data(),
            data,
            commitment,
        });
        let mut rng = rand_hash::HashRng::<D, _>::from_seed(seed);
        super::interactive::challenge(&mut rng, security)
    }

    /// Verify the proof, deriving challenge independently from same data
    pub fn verify<D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: Data,
        security: &SecurityParams,
        proof: &NiProof,
    ) -> Result<(), InvalidProof> {
        let challenge = challenge::<D>(shared_state, aux, data, &proof.commitment, security);
        super::interactive::verify(
            aux,
            data,
            &proof.commitment,
            security,
            &challenge,
            &proof.proof,
        )
    }
}

#[cfg(test)]
mod test {
    use fast_paillier::backend::Integer;
    use sha2::Digest;

    use crate::common::{IntegerExt, InvalidProofReason};

    fn run_with<D: Digest>(
        mut rng: &mut impl rand_core::CryptoRngCore,
        security: super::SecurityParams,
        plaintext: Integer,
    ) -> Result<(), crate::common::InvalidProof> {
        let aux = crate::common::test::aux(&mut rng);
        let private_key = crate::common::test::random_key(&mut rng).unwrap();
        let key = private_key.encryption_key();
        let (ciphertext, nonce) = key.encrypt_with_random(&mut rng, &plaintext).unwrap();
        let data = super::Data {
            key,
            ciphertext: &ciphertext,
        };
        let pdata = super::PrivateData {
            plaintext: &plaintext,
            nonce: &nonce,
        };

        let shared_state = "shared state";
        let proof =
            super::non_interactive::prove::<D>(&shared_state, &aux, data, pdata, &security, rng)
                .unwrap();
        super::non_interactive::verify::<D>(&shared_state, &aux, data, &security, &proof)
    }

    #[test]
    fn passing() {
        let mut rng = rand_dev::DevRng::new();
        let security = super::SecurityParams {
            l: 256,
            epsilon: 512,
            q: Integer::curve_order::<generic_ec::curves::Secp256k1>(),
        };
        let plaintext = Integer::from_rng_half_pm(&mut rng, &(Integer::one() << security.l));
        let r = run_with::<sha2::Sha256>(&mut rng, security, plaintext);
        match r {
            Ok(()) => (),
            Err(e) => panic!("{e:?}"),
        }
    }
    #[test]
    fn failing() {
        let mut rng = rand_dev::DevRng::new();
        let security = super::SecurityParams {
            l: 256,
            epsilon: 512,
            q: Integer::curve_order::<generic_ec::curves::Secp256k1>(),
        };
        let plaintext = (Integer::one() << (security.l + security.epsilon)) + 1;
        let r = run_with::<sha2::Sha256>(&mut rng, security, plaintext);
        match r.map_err(|e| e.reason()) {
            Ok(()) => panic!("proof should not pass"),
            Err(InvalidProofReason::RangeCheck(_)) => (),
            Err(e) => panic!("proof should not fail with {e:?}"),
        }
    }
}
