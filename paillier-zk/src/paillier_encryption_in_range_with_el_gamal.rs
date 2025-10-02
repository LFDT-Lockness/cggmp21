//! ZK-proof of paillier encryption in range with El-Gamal commitment.
//! Called Пenc-elg or Renc-elg in the CGGMP24
//! paper.
//!
//! ## Description
//!
//! Common (public) inputs: verifier's [`Aux`] data, [`SecurityParams`] containing
//! $\ell$ and $\varepsilon$, [curve `E`](Curve), Paillier public `key`, a `ciphertext`,
//! and elliptic points $A, B, X$.
//!
//! Prover secret inputs: `plaintext`, `nonce`, scalars $a, b$, such that:
//! * `plaintext` $\in \pm 2^\ell$
//! * `ciphertext == key.encrypt_with(plaintext, nonce)`
//! * $A = a \cdot G$
//! * $B = b \cdot G$
//! * $X = (a b + \text{plaintext}) \cdot G$
//!
//! Proof guarantees that `plaintext` $\in \pm 2^{\ell + \varepsilon}$.
//!
//! ## Example
//!
//! ```
//! use paillier_zk::{paillier_encryption_in_range_with_el_gamal as p, IntegerExt};
//! use fast_paillier::backend::Integer;
//! use generic_ec::{Point, Scalar, curves::Secp256k1 as E};
//! # mod pregenerated {
//! #     use super::*;
//! #     paillier_zk::load_pregenerated_data!(
//! #         verifier_aux: p::Aux,
//! #         someone_encryption_key: fast_paillier::EncryptionKey,
//! #     );
//! # }
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//!
//! let shared_state = "some shared state";
//!
//! let mut rng = rand_core::OsRng;
//! # let mut rng = rand_dev::DevRng::new();
//!
//! // Both parties know predefined security parameters and verifier's aux data
//! let aux: p::Aux = pregenerated::verifier_aux();
//! let security = p::SecurityParams {
//!     l: 1024,
//!     epsilon: 128,
//! };
//! // ...and someone's encryption key
//! let key: fast_paillier::EncryptionKey =
//!     pregenerated::someone_encryption_key();
//!
//! // Prover knows its secret `pdata` and `a`
//! let a = Scalar::random(&mut rng);
//! let pdata = p::PrivateData {
//!     plaintext: &Integer::from_rng_half_pm(&mut rng, &(Integer::one() << security.l)),
//!     nonce: &Integer::sample_in_mult_group_of(&mut rng, key.n()),
//!     b: &Scalar::random(&mut rng),
//! };
//!
//! // Both parties know the public data
//! let data = p::Data {
//!     key: &key,
//!     ciphertext: &key
//!         .encrypt_with(pdata.plaintext, pdata.nonce)
//!         .unwrap(),
//!     a: &(Point::generator() * a),
//!     b: &(Point::generator() * pdata.b),
//!     x: &(Point::generator() * (a * pdata.b + pdata.plaintext.to_scalar())),
//! };
//!
//! // Prover computes a non-interactive proof:
//! let proof = p::non_interactive::prove::<E, sha2::Sha256>(
//!     &shared_state,
//!     &aux,
//!     data,
//!     pdata,
//!     &security,
//!     &mut rng,
//! )?;
//!
//! // Prover sends this data to verifier
//! # use generic_ec::Curve;
//! # fn send<E: Curve>(_: &p::Data<E>, _: &p::NiProof<E>) {  }
//! send(&data, &proof);
//!
//! // Verifier receives the data and the proof and verifies it
//! # let recv = || (data, proof);
//! let (data, proof) = recv();
//! p::non_interactive::verify::<E, sha2::Sha256>(
//!     &shared_state,
//!     &aux,
//!     data,
//!     &proof,
//!     &security,
//! );
//! # Ok(()) }
//! ```
//!
//! If the verification succeeded, verifier can continue communication with prover

use fast_paillier::backend::Integer;
use fast_paillier::{AnyEncryptionKey, Ciphertext, Nonce, Plaintext};
use generic_ec::{Curve, Point, Scalar};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub use crate::common::Aux;
pub use crate::common::InvalidProof;

/// Security parameters for proof. Choosing the values is a tradeoff between
/// security, speed and correctness
#[derive(Debug, Clone, udigest::Digestable)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecurityParams {
    /// $\ell$ in paper
    pub l: usize,
    /// $\varepsilon$ in paper, slackness parameter
    pub epsilon: usize,
}

/// Public data that both parties know
#[derive(Debug, Clone, Copy, udigest::Digestable)]
#[udigest(bound = "")]
pub struct Data<'a, C: Curve> {
    /// $N_0$ in paper
    #[udigest(as = crate::common::encoding::AnyEncryptionKey)]
    pub key: &'a dyn AnyEncryptionKey,
    /// $C$ in paper
    #[udigest(as = &crate::common::encoding::Integer)]
    pub ciphertext: &'a Ciphertext,
    /// $A$ in paper
    pub a: &'a Point<C>,
    /// $B$ in paper
    pub b: &'a Point<C>,
    /// $X$ in paper
    pub x: &'a Point<C>,
}

/// Private data of prover
#[derive(Clone, Copy)]
pub struct PrivateData<'a, E: Curve> {
    /// $x$ in paper
    pub plaintext: &'a Plaintext,
    /// $\rho$ in paper
    pub nonce: &'a Nonce,
    /// $b$ in paper
    pub b: &'a Scalar<E>,
}

/// Prover's public commitment
#[derive(Debug, Clone, udigest::Digestable)]
#[udigest(bound = "")]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct Commitment<E: Curve> {
    #[udigest(as = crate::common::encoding::Integer)]
    pub s: Integer,
    #[udigest(as = crate::common::encoding::Integer)]
    pub t: Integer,
    #[udigest(as = crate::common::encoding::Integer)]
    pub d: Integer,
    pub y: Point<E>,
    pub z: Point<E>,
}

/// Prover's secret commitment nonce
#[derive(Clone)]
pub struct PrivateCommitment<E: Curve> {
    pub alpha: Integer,
    pub mu: Integer,
    pub r: Integer,
    pub beta: Scalar<E>,
    pub gamma: Integer,
}

/// Verifier's challenge to prover. Can be obtained deterministically by
/// [`non_interactive::challenge`] or randomly by [`interactive::challenge`]
pub type Challenge = Integer;

/// Range Proof with El-Gamal commitment. Computed by [`interactive::prove`]
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct Proof<E: Curve> {
    pub z1: Integer,
    pub z2: Integer,
    pub z3: Integer,
    pub w: Scalar<E>,
}

/// The non-interactive ZK proof. Computed by [`non_interactive::prove`].
/// Combines commitment and proof.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct NiProof<E: Curve> {
    pub commitment: Commitment<E>,
    pub proof: Proof<E>,
}

/// The interactive version of the ZK proof. Should be completed in 3 rounds:
/// prover commits to data, verifier responds with a random challenge, and
/// prover gives proof with commitment and challenge.
pub mod interactive {
    use fast_paillier::backend::Integer;
    use generic_ec::{Curve, Point, Scalar};
    use rand_core::RngCore;

    use crate::{
        common::{fail_if, fail_if_ne, InvalidProofReason},
        BadExponent, Error,
    };

    use crate::common::{IntegerExt, InvalidProof};

    use super::{
        Aux, Challenge, Commitment, Data, PrivateCommitment, PrivateData, Proof, SecurityParams,
    };

    /// Create random commitment
    pub fn commit<E: Curve>(
        aux: &Aux,
        data: Data<E>,
        pdata: PrivateData<E>,
        security: &SecurityParams,
        rng: &mut impl RngCore,
    ) -> Result<(Commitment<E>, PrivateCommitment<E>), Error> {
        let two_to_l_plus_e = Integer::one() << (security.l + security.epsilon);
        let n_j_at_two_to_l = (Integer::one() << security.l) * &aux.rsa_modulo;
        let n_j_at_two_to_l_plus_e = &two_to_l_plus_e * &aux.rsa_modulo;

        let alpha = Integer::from_rng_half_pm(rng, &two_to_l_plus_e);
        let mu = Integer::from_rng_half_pm(rng, &n_j_at_two_to_l);
        let r = Integer::sample_in_mult_group_of(rng, data.key.n());
        let beta = Scalar::random(rng);
        let gamma = Integer::from_rng_half_pm(rng, &n_j_at_two_to_l_plus_e);

        let s = aux.combine(pdata.plaintext, &mu)?;
        let t = aux.combine(&alpha, &gamma)?;
        let d = data.key.encrypt_with(&alpha, &r)?;
        let y = data.a * beta + Point::<E>::generator() * alpha.to_scalar();
        let z = Point::<E>::generator() * beta;

        Ok((
            Commitment { s, t, d, y, z },
            PrivateCommitment {
                alpha,
                mu,
                r,
                beta,
                gamma,
            },
        ))
    }

    /// Compute proof for given data and prior protocol values
    pub fn prove<E: Curve>(
        data: Data<E>,
        pdata: PrivateData<E>,
        private_commitment: &PrivateCommitment<E>,
        challenge: &Challenge,
    ) -> Result<Proof<E>, Error> {
        let z1 = &private_commitment.alpha + (challenge * pdata.plaintext);
        let z2 = {
            let nonce_to_challenge_mod_n: Integer = pdata
                .nonce
                .pow_mod_ref(challenge, data.key.n())
                .ok_or(BadExponent::undefined())?;
            (&private_commitment.r * nonce_to_challenge_mod_n).modulo(data.key.n())
        };
        let z3 = &private_commitment.gamma + (challenge * &private_commitment.mu);
        let w = private_commitment.beta + (challenge.to_scalar() * pdata.b);
        Ok(Proof { z1, z2, z3, w })
    }

    /// Verify the proof
    pub fn verify<E: Curve>(
        aux: &Aux,
        data: Data<E>,
        commitment: &Commitment<E>,
        security: &SecurityParams,
        challenge: &Challenge,
        proof: &Proof<E>,
    ) -> Result<(), InvalidProof> {
        // Verify that inputs are in expected domains:
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
            aux.is_in_mult_group(&commitment.t),
        )?;
        fail_if(
            InvalidProofReason::RangeCheck(4),
            commitment.d.in_mult_group_of(data.key.nn()),
        )?;

        // Verify statement
        {
            let lhs = data
                .key
                .encrypt_with(&proof.z1, &proof.z2)
                .map_err(|_| InvalidProofReason::PaillierEnc)?;
            let rhs = {
                let e_at_c = data
                    .key
                    .omul(challenge, data.ciphertext)
                    .map_err(|_| InvalidProofReason::PaillierOp)?;
                data.key
                    .oadd(&commitment.d, &e_at_c)
                    .map_err(|_| InvalidProofReason::PaillierOp)?
            };
            fail_if_ne(InvalidProofReason::EqualityCheck(5), lhs, rhs)?;
        }
        {
            let lhs = data.a * proof.w + Point::<E>::generator() * proof.z1.to_scalar();
            let rhs = commitment.y + data.x * challenge.to_scalar();
            fail_if_ne(InvalidProofReason::EqualityCheck(6), lhs, rhs)?;
        }
        {
            let lhs = Point::<E>::generator() * proof.w;
            let rhs = commitment.z + data.b * challenge.to_scalar();
            fail_if_ne(InvalidProofReason::EqualityCheck(7), lhs, rhs)?;
        }
        {
            let lhs = aux.combine(&proof.z1, &proof.z3)?;
            let rhs = {
                let s_to_e = aux.pow_mod(&commitment.s, challenge)?;
                (&commitment.t * s_to_e).modulo(&aux.rsa_modulo)
            };
            fail_if_ne(InvalidProofReason::EqualityCheck(8), lhs, rhs)?;
        }

        fail_if(
            InvalidProofReason::RangeCheck(9),
            proof
                .z1
                .is_in_half_pm(&(Integer::one() << (security.l + security.epsilon))),
        )?;

        Ok(())
    }

    /// Generate random challenge
    ///
    /// `security` parameter is used to generate challenge in correct range
    pub fn challenge<E: Curve>(rng: &mut impl RngCore) -> Challenge {
        Integer::from_rng_half_pm(rng, &Integer::curve_order::<E>())
    }
}

/// The non-interactive version of proof. Completed in one round, for example
/// see the documentation of parent module.
pub mod non_interactive {
    use digest::Digest;
    use generic_ec::Curve;

    use crate::{Error, InvalidProof};

    use super::{Aux, Challenge, Commitment, Data, NiProof, PrivateData, SecurityParams};

    /// Compute proof for the given data, producing random commitment and
    /// deriving deterministic challenge.
    ///
    /// Obtained from the above interactive proof via Fiat-Shamir heuristic.
    pub fn prove<E: Curve, D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: Data<E>,
        pdata: PrivateData<E>,
        security: &SecurityParams,
        rng: &mut impl rand_core::RngCore,
    ) -> Result<NiProof<E>, Error> {
        let (commitment, pcomm) = super::interactive::commit(aux, data, pdata, security, rng)?;
        let challenge = challenge::<E, D>(shared_state, aux, data, &commitment, security);
        let proof = super::interactive::prove(data, pdata, &pcomm, &challenge)?;
        Ok(NiProof { commitment, proof })
    }

    /// Verify the proof, deriving challenge independently from same data
    pub fn verify<E: Curve, D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: Data<E>,
        proof: &NiProof<E>,
        security: &SecurityParams,
    ) -> Result<(), InvalidProof> {
        let challenge = challenge::<E, D>(shared_state, aux, data, &proof.commitment, security);
        super::interactive::verify(
            aux,
            data,
            &proof.commitment,
            security,
            &challenge,
            &proof.proof,
        )
    }

    /// Deterministically compute challenge based on prior known values in protocol
    pub fn challenge<E: Curve, D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: Data<E>,
        commitment: &Commitment<E>,
        security: &SecurityParams,
    ) -> Challenge {
        let tag = "paillier_zk.encryption_in_range_with_el_gamal.ni_challenge";
        let seed = udigest::inline_struct!(tag {
            shared_state,
            aux: aux.digest_public_data(),
            security,
            data,
            commitment,
        });
        let mut rng = rand_hash::HashRng::<D, _>::from_seed(seed);
        super::interactive::challenge::<E>(&mut rng)
    }
}

#[cfg(test)]
mod test {
    use fast_paillier::backend::Integer;
    use generic_ec::{Curve, Point, Scalar};
    use sha2::Digest;

    use crate::common::{IntegerExt, InvalidProofReason};

    fn run_with<E: Curve, D: Digest>(
        mut rng: &mut impl rand_core::CryptoRngCore,
        security: super::SecurityParams,
        plaintext: Integer,
    ) -> Result<(), crate::common::InvalidProof> {
        let aux = crate::common::test::aux(&mut rng);

        let private_key = crate::common::test::random_key(&mut rng).unwrap();
        let a = Scalar::random(rng);
        let pdata = super::PrivateData {
            plaintext: &plaintext,
            nonce: &Integer::sample_in_mult_group_of(rng, private_key.n()),
            b: &Scalar::random(rng),
        };

        let data = super::Data {
            key: private_key.encryption_key(),
            ciphertext: &private_key
                .encrypt_with(pdata.plaintext, pdata.nonce)
                .unwrap(),
            a: &(Point::generator() * a),
            b: &(Point::generator() * pdata.b),
            x: &(Point::generator() * (a * pdata.b + pdata.plaintext.to_scalar())),
        };

        let shared_state = "shared state";
        let proof =
            super::non_interactive::prove::<E, D>(&shared_state, &aux, data, pdata, &security, rng)
                .unwrap();
        super::non_interactive::verify::<E, D>(&shared_state, &aux, data, &proof, &security)
    }

    fn passing_test<C: Curve, D: Digest>() {
        let mut rng = rand_dev::DevRng::new();
        let security = super::SecurityParams {
            l: 1024,
            epsilon: 300,
        };
        let plaintext = Integer::from_rng_half_pm(&mut rng, &(Integer::one() << security.l));
        run_with::<C, D>(&mut rng, security, plaintext).expect("proof failed");
    }

    fn failing_test<C: Curve, D: Digest>() {
        let mut rng = rand_dev::DevRng::new();
        let security = super::SecurityParams {
            l: 1024,
            epsilon: 300,
        };
        let plaintext = (Integer::one() << (security.l + security.epsilon - 1)) + 1;
        let r = run_with::<C, D>(&mut rng, security, plaintext).expect_err("proof should not pass");
        match r.reason() {
            InvalidProofReason::RangeCheck(9) => (),
            e => panic!("proof should not fail with: {e:?}"),
        }
    }

    #[test]
    fn passing_p256() {
        passing_test::<generic_ec::curves::Secp256r1, sha2::Sha256>()
    }
    #[test]
    fn failing_p256_add() {
        failing_test::<generic_ec::curves::Secp256r1, sha2::Sha256>()
    }

    #[test]
    fn passing_million() {
        passing_test::<crate::curve::C, sha2::Sha256>()
    }
    #[test]
    fn failing_million_add() {
        failing_test::<crate::curve::C, sha2::Sha256>()
    }
}
