//! ZK-proof for factoring of a RSA modulus. Called Пfac or Rfac in the CGGMP24
//! paper.
//!
//! ## Description
//!
//! Both parties agree on verifier [aux data](Aux) and [security level](SecurityParams). Common input is
//! `n > 4*security.l`. Prover additionally knows primes `p, q < pow(2, security.l) * sqrt(n)`.
//!
//! Proof guarantees that each `p, q > pow(2, security.l)`.
//!
//! ## Example
//!
//! ```rust
//! use fast_paillier::backend::Integer;
//! use paillier_zk::no_small_factor as p;
//! # mod pregenerated {
//! #     use super::*;
//! #     paillier_zk::load_pregenerated_data!(
//! #         verifier_aux: p::Aux,
//! #         primes_1536bits: [Integer; 4],
//! #     );
//! # }
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let shared_state = "some shared state";
//! let mut rng = rand_core::OsRng;
//! # let mut rng = rand_dev::DevRng::new();
//!
//! // 0. Setup: prover and verifier share common Ring-Pedersen parameters, and
//! // agree on the level of security
//!
//! let aux: p::Aux = pregenerated::verifier_aux();
//! let security = p::SecurityParams {
//!     l: 256,
//!     epsilon: 512,
//! };
//!
//! // 1. Prover prepares the data to obtain proof about
//!
//! let [p, q, ..] = pregenerated::primes_1536bits();
//! let n = &p * &q;
//! let n_root = n.sqrt_ref().unwrap();
//! let data = p::Data {
//!     n: &n,
//!     n_root: &n_root,
//! };
//!
//! // 2. Prover computes a non-interactive proof that both factors are large enough
//!
//! let proof = p::non_interactive::prove::<sha2::Sha256>(
//!     &shared_state,
//!     &aux,
//!     data,
//!     p::PrivateData { p: &p, q: &q },
//!     &security,
//!     &mut rng,
//! )?;
//!
//! // 4. Prover sends this data to verifier
//!
//! # fn send(_: &Integer, _: &p::NiProof) {  }
//! send(data.n, &proof);
//!
//! // 5. Verifier receives the data and the proof and verifies it
//!
//! # let recv = || (data.n, proof);
//! let (n, proof) = recv();
//! let n_root = n.sqrt_ref().unwrap();
//! let data = p::Data {
//!     n: &n,
//!     n_root: &n_root,
//! };
//! p::non_interactive::verify::<sha2::Sha256>(&shared_state, &aux, data, &security, &proof)?;
//! # Ok(()) }
//! ```
//!
//! If the verification succeeded, verifier can continue communication with prover

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use fast_paillier::backend::Integer;

pub use crate::common::{Aux, InvalidProof};

/// Security parameters for proof. Choosing the values is a tradeoff between
/// speed and chance of rejecting a valid proof or accepting an invalid proof
#[derive(Debug, Clone, udigest::Digestable)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecurityParams {
    /// l in paper, security parameter for bit size of plaintext: it needs to
    /// differ from sqrt(n) not more than by 2^l
    pub l: usize,
    /// Epsilon in paper, slackness parameter
    pub epsilon: usize,
}

/// Public data that both parties know
#[derive(Debug, Clone, Copy, udigest::Digestable)]
pub struct Data<'a> {
    /// N_i in the spec
    #[udigest(as = &crate::common::encoding::Integer)]
    pub n: &'a Integer,
    /// A number close to square root of n
    #[udigest(as = &crate::common::encoding::Integer)]
    pub n_root: &'a Integer,
}

/// Private data of prover
#[derive(Debug, Clone, Copy)]
pub struct PrivateData<'a> {
    pub p: &'a Integer,
    pub q: &'a Integer,
}

/// Prover's data accompanying the commitment. Kept as state between rounds in
/// the interactive protocol.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PrivateCommitment {
    pub alpha: Integer,
    pub beta: Integer,
    pub mu: Integer,
    pub nu: Integer,
    pub r: Integer,
    pub x: Integer,
    pub y: Integer,
}

/// Prover's first message, obtained by [`interactive::commit`]
#[derive(Debug, Clone, udigest::Digestable)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Commitment {
    #[udigest(as = crate::common::encoding::Integer)]
    pub p: Integer,
    #[udigest(as = crate::common::encoding::Integer)]
    pub q: Integer,
    #[udigest(as = crate::common::encoding::Integer)]
    pub a: Integer,
    #[udigest(as = crate::common::encoding::Integer)]
    pub b: Integer,
    #[udigest(as = crate::common::encoding::Integer)]
    pub t: Integer,
}

/// Verifier's challenge to prover. Can be obtained deterministically by
/// [`non_interactive::challenge`] or randomly by [`interactive::challenge`]
pub type Challenge = Integer;

/// The ZK proof, computed by [`interactive::prove`]
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Proof {
    pub z1: Integer,
    pub z2: Integer,
    pub w1: Integer,
    pub w2: Integer,
    pub v: Integer,
}

/// The non-interactive ZK proof. Computed by [`non_interactive::prove`].
/// Combines commitment and proof.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NiProof {
    commitment: Commitment,
    proof: Proof,
}

/// Interactive version of the proof
pub mod interactive {
    use fast_paillier::backend::Integer;
    use rand_core::RngCore;

    use crate::{
        common::{fail_if, fail_if_ne, IntegerExt, InvalidProofReason},
        Error,
    };

    use super::{
        Aux, Challenge, Commitment, Data, InvalidProof, PrivateCommitment, PrivateData, Proof,
        SecurityParams,
    };

    /// Create random commitment
    pub fn commit<R: RngCore>(
        aux: &Aux,
        data: Data,
        pdata: PrivateData,
        security: &SecurityParams,
        mut rng: R,
    ) -> Result<(Commitment, PrivateCommitment), Error> {
        let two_to_l = Integer::one() << security.l;
        let two_to_l_plus_e = Integer::one() << (security.l + security.epsilon);
        let n_root_at_two_to_l_plus_e = &two_to_l_plus_e * data.n_root;
        let aux_n_at_two_to_l = &two_to_l * &aux.rsa_modulo;
        let aux_n_at_two_to_l_plus_e = &two_to_l_plus_e * &aux.rsa_modulo;
        let n_at_aux_n = &aux.rsa_modulo * data.n;

        let alpha = Integer::from_rng_half_pm(&mut rng, &n_root_at_two_to_l_plus_e);
        let beta = Integer::from_rng_half_pm(&mut rng, &n_root_at_two_to_l_plus_e);
        let mu = Integer::from_rng_half_pm(&mut rng, &aux_n_at_two_to_l);
        let nu = Integer::from_rng_half_pm(&mut rng, &aux_n_at_two_to_l);
        let r = Integer::from_rng_half_pm(&mut rng, &(&two_to_l_plus_e * &n_at_aux_n));
        let x = Integer::from_rng_half_pm(&mut rng, &aux_n_at_two_to_l_plus_e);
        let y = Integer::from_rng_half_pm(&mut rng, &aux_n_at_two_to_l_plus_e);

        let p = aux.combine(pdata.p, &mu)?;
        let q = aux.combine(pdata.q, &nu)?;
        let a = aux.combine(&alpha, &x)?;
        let b = aux.combine(&beta, &y)?;
        let t = aux
            .rsa_modulo
            .combine(&q, &alpha, &aux.t, &r)
            .ok_or_else(crate::BadExponent::undefined)?;

        let commitment = Commitment { p, q, a, b, t };
        let private_commitment = PrivateCommitment {
            alpha,
            beta,
            mu,
            nu,
            r,
            x,
            y,
        };
        Ok((commitment, private_commitment))
    }

    /// Generate random challenge
    ///
    /// `security` parameter is used to generate challenge in correct range
    pub fn challenge<R: RngCore>(security: &SecurityParams, rng: &mut R) -> Challenge {
        Integer::from_rng_half_pm(rng, &(Integer::one() << security.l))
    }

    /// Compute proof for given data and prior protocol values
    pub fn prove(
        pdata: PrivateData,
        pcomm: &PrivateCommitment,
        challenge: &Challenge,
    ) -> Result<Proof, Error> {
        Ok(Proof {
            z1: &pcomm.alpha + challenge * pdata.p,
            z2: &pcomm.beta + challenge * pdata.q,
            w1: &pcomm.x + challenge * &pcomm.mu,
            w2: &pcomm.y + challenge * &pcomm.nu,
            v: &pcomm.r - challenge * (&pcomm.nu * pdata.p),
        })
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
        // Verify that inputs are in expected domains
        fail_if(
            InvalidProofReason::RangeCheck(0),
            aux.is_in_mult_group(&commitment.p),
        )?;
        fail_if(
            InvalidProofReason::RangeCheck(1),
            aux.is_in_mult_group(&commitment.q),
        )?;
        fail_if(
            InvalidProofReason::RangeCheck(2),
            aux.is_in_mult_group(&commitment.a),
        )?;
        fail_if(
            InvalidProofReason::RangeCheck(3),
            aux.is_in_mult_group(&commitment.b),
        )?;
        fail_if(
            InvalidProofReason::RangeCheck(4),
            aux.is_in_mult_group(&commitment.t),
        )?;
        // Verify the statement
        // range check for N_i
        {
            let n_bits: usize = data
                .n
                .significant_bits()
                .try_into()
                .map_err(|_| InvalidProofReason::Conversion)?;
            fail_if(InvalidProofReason::RangeCheck(5), n_bits >= 4 * security.l)?;
        }
        {
            let lhs = aux.combine(&proof.z1, &proof.w1)?;
            let p_to_e = aux.pow_mod(&commitment.p, challenge)?;
            let rhs = (&commitment.a * p_to_e).modulo(&aux.rsa_modulo);
            fail_if_ne(InvalidProofReason::EqualityCheck(6), &lhs, &rhs)?;
            fail_if(
                InvalidProofReason::MultGroupCheck(7),
                aux.is_in_mult_group(&lhs),
            )?;
        }
        {
            let lhs = aux.combine(&proof.z2, &proof.w2)?;
            let q_to_e = aux.pow_mod(&commitment.q, challenge)?;
            let rhs = (&commitment.b * q_to_e).modulo(&aux.rsa_modulo);
            fail_if_ne(InvalidProofReason::EqualityCheck(8), &lhs, &rhs)?;
            fail_if(
                InvalidProofReason::MultGroupCheck(9),
                aux.is_in_mult_group(&lhs),
            )?;
        }
        {
            let r = aux.pow_mod(&aux.s, data.n)?;
            let q_to_z1 = aux.pow_mod(&commitment.q, &proof.z1)?;
            let t_to_v = aux.pow_mod(&aux.t, &proof.v)?;
            let lhs = (q_to_z1 * t_to_v).modulo(&aux.rsa_modulo);
            let rhs = (&commitment.t * aux.pow_mod(&r, challenge)?).modulo(&aux.rsa_modulo);
            fail_if_ne(InvalidProofReason::EqualityCheck(10), &lhs, &rhs)?;
            fail_if(
                InvalidProofReason::MultGroupCheck(11),
                aux.is_in_mult_group(&lhs),
            )?;
        }
        let range = (Integer::from(1) << (security.l + security.epsilon)) * data.n_root;
        // range check for z1
        fail_if(
            InvalidProofReason::RangeCheck(12),
            proof.z1.is_in_half_pm(&range),
        )?;
        // range check for z2
        fail_if(
            InvalidProofReason::RangeCheck(13),
            proof.z2.is_in_half_pm(&range),
        )?;

        Ok(())
    }
}

/// Non-interactive version of the proof
pub mod non_interactive {
    use digest::Digest;

    pub use crate::{Error, InvalidProof};

    pub use super::{Aux, Challenge, Data, NiProof, PrivateData, SecurityParams};

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
        let proof = super::interactive::prove(pdata, &pcomm, &challenge)?;
        Ok(NiProof { commitment, proof })
    }

    /// Deterministically compute challenge based on prior known values in protocol
    pub fn challenge<D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: Data,
        commitment: &super::Commitment,
        security: &SecurityParams,
    ) -> Challenge {
        let tag = "paillier_zk.no_small_factor.ni_challenge";
        let seed = udigest::inline_struct!(tag {
            shared_state,
            security,
            aux: aux.digest_public_data(),
            data,
            commitment,
        });
        let mut rng = rand_hash::HashRng::<D, _>::from_seed(&seed);
        super::interactive::challenge(security, &mut rng)
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
    use crate::common::test::generate_blum_prime;
    use crate::common::InvalidProofReason;

    #[test]
    fn passing() {
        type D = sha2::Sha256;

        let n_bitlen = 3072;
        let security = super::SecurityParams {
            l: 256,
            epsilon: 512,
        };

        let mut rng = rand_dev::DevRng::new();
        let p = generate_blum_prime(&mut rng, n_bitlen / 2);
        let q = generate_blum_prime(&mut rng, n_bitlen / 2);
        let n = &p * &q;
        let n_root = n.sqrt_ref().unwrap();
        let data = super::Data {
            n: &n,
            n_root: &n_root,
        };

        assert!(n.significant_bits() >= u64::from(n_bitlen) - 1);

        let aux = crate::common::test::aux(&mut rng);
        let shared_state = "shared state";
        let proof = super::non_interactive::prove::<D>(
            &shared_state,
            &aux,
            data,
            super::PrivateData { p: &p, q: &q },
            &security,
            &mut rng,
        )
        .unwrap();
        let r = super::non_interactive::verify::<D>(&shared_state, &aux, data, &security, &proof);
        match r {
            Ok(()) => (),
            Err(e) => panic!("Proof should not fail with {e:?}"),
        }
    }

    #[test]
    fn failing() {
        type D = sha2::Sha256;

        let n_bitlen = 3072;
        let security = super::SecurityParams {
            l: 256,
            epsilon: 512,
        };

        let mut rng = rand_dev::DevRng::new();
        let p = generate_blum_prime(&mut rng, n_bitlen - (security.l as u32) / 2);
        let q = generate_blum_prime(&mut rng, security.l as u32 / 2);
        let n = &p * &q;
        let n_root = n.sqrt_ref().unwrap();
        let data = super::Data {
            n: &n,
            n_root: &n_root,
        };

        assert!(n.significant_bits() >= u64::from(n_bitlen) - 1);

        let aux = crate::common::test::aux(&mut rng);
        let shared_state = "shared state";
        let proof = super::non_interactive::prove::<D>(
            &shared_state,
            &aux,
            data,
            super::PrivateData { p: &p, q: &q },
            &security,
            &mut rng,
        )
        .unwrap();
        let r = super::non_interactive::verify::<D>(&shared_state, &aux, data, &security, &proof)
            .expect_err("proof should not pass");
        match r.reason() {
            InvalidProofReason::RangeCheck(12) => (),
            e => panic!("Proof should not fail with {e:?}"),
        }
    }
}
