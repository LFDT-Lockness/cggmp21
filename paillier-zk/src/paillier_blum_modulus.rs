//! ZK-proof of Paillier-Blum modulus. Called Пmod or Rmod in the CGGMP24 paper.
//!
//! ## Description
//! A party P has a Paillier-Blum modulus `N = pq`, with p and q being primes such
//! that `gcd(N, phi(N)) = 1` and `p,q = 3 \mod 4`. P wants to prove that those
//! equalities about N hold, without disclosing p and q.
//!
//! ## Example
//! ```rust
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use fast_paillier::backend::Integer;
//! let mut rng = rand_core::OsRng;
//! # let mut rng = rand_dev::DevRng::new();
//!
//! // 0. Prover P derives two Blum primes and makes a Paillier-Blum modulus
//! let p = Integer::generate_safe_prime(&mut rng, 256);
//! let q = Integer::generate_safe_prime(&mut rng, 256);
//! let n = &p * &q;
//!
//! // 1. P computes a non-interactive proof that `n` is a Paillier-Blum modulus:
//! use paillier_zk::paillier_blum_modulus as p;
//!
//! // Security parameter
//! const SECURITY: usize = 33;
//! // Verifier and prover share the same state
//! let shared_state = "some shared state";
//!
//! let data = p::Data { n: &n };
//! let pdata = p::PrivateData { p: &p, q: &q };
//!
//! let proof =
//!     p::non_interactive::prove::<{SECURITY}, sha2::Sha256>(
//!         &shared_state,
//!         data,
//!         pdata,
//!         &mut rng,
//!     )?;
//!
//! // 2. P sends `data, commitment, proof` to the verifier V
//!
//! # fn send(_: &p::Data, _: &p::NiProof<{SECURITY}>) { }
//! send(&data, &proof);
//!
//! // 3. V receives and verifies the proof:
//!
//! # let recv = || (data, proof);
//! let (data, proof) = recv();
//!
//! p::non_interactive::verify::<{SECURITY}, sha2::Sha256>(
//!     &shared_state,
//!     data,
//!     &proof,
//! )?;
//! # Ok(()) }
//! ```
//! If the verification succeeded, V can continue communication with P

use fast_paillier::backend::Integer;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Public data that both parties know: the Paillier-Blum modulus
#[derive(Debug, Clone, Copy, udigest::Digestable)]
pub struct Data<'a> {
    #[udigest(as = &crate::common::encoding::Integer)]
    pub n: &'a Integer,
}

/// Private data of prover
#[derive(Clone, Copy)]
pub struct PrivateData<'a> {
    pub p: &'a Integer,
    pub q: &'a Integer,
}

/// Prover's first message, obtained by [`interactive::commit`]
#[derive(Debug, Clone, udigest::Digestable)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Commitment {
    #[udigest(as = crate::common::encoding::Integer)]
    pub w: Integer,
}

/// Verifier's challenge to prover. Can be obtained deterministically by
/// [`non_interactive::challenge`] or randomly by [`interactive::challenge`]
///
/// Consists of `M` singular challenges
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Challenge<const M: usize> {
    pub ys: [Integer; M],
}

/// A part of proof. Having enough of those guarantees security
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ProofPoint {
    pub x: Integer,
    pub a: bool,
    pub b: bool,
    pub z: Integer,
}

/// The ZK proof. Computed by [`interactive::prove`].
/// Consists of M proofs for each challenge
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Proof<const M: usize> {
    #[cfg_attr(
        // A trick to serialize arbitrary size arrays
        feature = "serde",
        serde(with = "serde_with::As::<[serde_with::Same; M]>")
    )]
    pub points: [ProofPoint; M],
}

/// The non-interactive ZK proof. Computed by [`non_interactive::prove`].
/// Combines commitment and proof.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NiProof<const M: usize> {
    pub commitment: Commitment,
    pub proof: Proof<M>,
}

/// The interactive version of the ZK proof. Should be completed in 3 rounds:
/// prover commits to data, verifier responds with a random challenge, and
/// prover gives proof with commitment and challenge.
pub mod interactive {
    use fast_paillier::backend::Integer;
    use rand_core::RngCore;

    use crate::common::{
        fail_if,
        sqrt::{blum_sqrt, find_residue, sample_invertible_with_neg_jacobi},
    };
    use crate::{BadExponent, Error, ErrorReason, InvalidProof, InvalidProofReason};

    use super::{Challenge, Commitment, Data, PrivateData, Proof, ProofPoint};

    /// Create random commitment
    pub fn commit<R: RngCore>(Data { n }: Data, rng: &mut R) -> Commitment {
        Commitment {
            w: sample_invertible_with_neg_jacobi(n, rng),
        }
    }

    /// Compute proof for given data and prior protocol values
    pub fn prove<const M: usize>(
        Data { n }: Data,
        PrivateData { p, q }: PrivateData,
        Commitment { ref w }: &Commitment,
        challenge: &Challenge<M>,
    ) -> Result<Proof<M>, Error> {
        let blum_sqrt = |x| blum_sqrt(&x, p, q, n);
        let phi = (p - 1u8) * (q - 1u8);
        let n_inverse = n.invert_ref(&phi).ok_or(ErrorReason::Invert)?;

        // We do an extra allocation as workaround while `array::try_map` is not stable
        let points = challenge
            .ys
            .iter()
            .map(|y| {
                let z = y
                    .pow_mod_ref(&n_inverse, n)
                    .ok_or(BadExponent::undefined())?;
                let (a, b, y_) = find_residue(y, w, p, q, n).ok_or(ErrorReason::FindResidue)?;
                let x = blum_sqrt(blum_sqrt(y_));
                Ok(ProofPoint { x, a, b, z })
            })
            .collect::<Result<Vec<_>, ErrorReason>>()?
            .try_into()
            .map_err(|_| ErrorReason::Length)?;
        Ok(Proof { points })
    }

    /// Verify the proof. If this succeeds, the relation Rmod holds with chance
    /// `1/2^M`
    pub fn verify<const M: usize>(
        data: Data,
        commitment: &Commitment,
        challenge: &Challenge<M>,
        proof: &Proof<M>,
    ) -> Result<(), InvalidProof> {
        if data.n.is_probably_prime(25) != fast_paillier::backend::IsPrime::No {
            return Err(InvalidProofReason::ModulusIsPrime.into());
        }
        if data.n.is_even() {
            return Err(InvalidProofReason::ModulusIsEven.into());
        }
        fail_if(
            InvalidProofReason::RangeCheck(1),
            commitment.w.in_mult_group_of(data.n),
        )?;

        for (point, y) in proof.points.iter().zip(challenge.ys.iter()) {
            fail_if(
                InvalidProofReason::RangeCheck(2),
                point.x.in_mult_group_of(data.n),
            )?;
            fail_if(
                InvalidProofReason::RangeCheck(3),
                point.z.in_mult_group_of(data.n),
            )?;
            if point
                .z
                .pow_mod_ref(data.n, data.n)
                .ok_or(InvalidProofReason::ModPow)?
                != *y
            {
                return Err(InvalidProofReason::IncorrectNthRoot.into());
            }
            let y = if point.a { data.n - y } else { y.clone() };
            let y = if point.b {
                (y * &commitment.w).modulo(data.n)
            } else {
                y
            };
            if point
                .x
                .pow_mod_ref(&4_u32.into(), data.n)
                .ok_or(InvalidProofReason::ModPow)?
                != y
            {
                return Err(InvalidProofReason::IncorrectFourthRoot.into());
            }
        }
        Ok(())
    }

    /// Generate random challenge
    ///
    /// `data` parameter is used to generate challenge in correct range
    pub fn challenge<const M: usize, R: RngCore>(Data { n }: Data, rng: &mut R) -> Challenge<M> {
        let ys = [(); M].map(|()| Integer::sample_in_mult_group_of(rng, n));
        Challenge { ys }
    }
}

/// The non-interactive version of proof. Completed in one round, for example
/// see the documentation of parent module.
pub mod non_interactive {
    use digest::Digest;

    use crate::{Error, InvalidProof};

    use super::{Challenge, Commitment, Data, NiProof, PrivateData};

    /// Compute proof for the given data, producing random commitment and
    /// deriving determenistic challenge.
    ///
    /// Obtained from the above interactive proof via Fiat-Shamir heuristic.
    pub fn prove<const M: usize, D: Digest>(
        shared_state: &impl udigest::Digestable,
        data: Data,
        pdata: PrivateData,
        rng: &mut impl rand_core::RngCore,
    ) -> Result<NiProof<M>, Error> {
        let commitment = super::interactive::commit(data, rng);
        let challenge = challenge::<M, D>(shared_state, data, &commitment);
        let proof = super::interactive::prove(data, pdata, &commitment, &challenge)?;
        Ok(NiProof { commitment, proof })
    }

    /// Verify the proof, deriving challenge independently from same data
    pub fn verify<const M: usize, D: Digest>(
        shared_state: &impl udigest::Digestable,
        data: Data,
        proof: &NiProof<M>,
    ) -> Result<(), InvalidProof> {
        let challenge = challenge::<M, D>(shared_state, data, &proof.commitment);
        super::interactive::verify(data, &proof.commitment, &challenge, &proof.proof)
    }

    /// Deterministically compute challenge based on prior known values in protocol
    pub fn challenge<const M: usize, D: Digest>(
        shared_state: &impl udigest::Digestable,
        data: Data,
        commitment: &Commitment,
    ) -> Challenge<M> {
        let tag = "paillier_zk.blum_modulus.ni_challenge";
        let seed = udigest::inline_struct!(tag {
            shared_state,
            data,
            commitment,
        });
        let mut rng = rand_hash::HashRng::<D, _>::from_seed(seed);

        super::interactive::challenge(data, &mut rng)
    }
}

#[cfg(test)]
mod test {
    use crate::common::test::generate_blum_prime;

    type D = sha2::Sha256;

    #[test]
    fn passing() {
        let mut rng = rand_dev::DevRng::new();
        let p = generate_blum_prime(&mut rng, 256);
        let q = generate_blum_prime(&mut rng, 256);
        let n = &p * &q;
        let data = super::Data { n: &n };
        let pdata = super::PrivateData { p: &p, q: &q };
        let shared_state = "shared state";
        let proof =
            super::non_interactive::prove::<65, D>(&shared_state, data, pdata, &mut rng).unwrap();
        let r = super::non_interactive::verify::<65, D>(&shared_state, data, &proof);
        match r {
            Ok(()) => (),
            Err(e) => panic!("{e:?}"),
        }
    }

    #[test]
    fn failing() {
        let mut rng = rand_dev::DevRng::new();
        let p = generate_blum_prime(&mut rng, 256);
        let q = loop {
            // non blum prime
            let q = fast_paillier::backend::Integer::generate_prime(&mut rng, 256);
            if q.mod_u(4) == 1 {
                break q;
            }
        };
        let n = &p * &q;
        let data = super::Data { n: &n };
        let pdata = super::PrivateData { p: &p, q: &q };
        let shared_state = "shared state";
        let proof =
            super::non_interactive::prove::<65, D>(&shared_state, data, pdata, &mut rng).unwrap();
        let r = super::non_interactive::verify::<65, D>(&shared_state, data, &proof);
        if r.is_ok() {
            panic!("proof should not pass");
        }
    }
}
