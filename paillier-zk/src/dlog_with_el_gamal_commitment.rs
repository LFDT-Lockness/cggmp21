//! ZK-proof of discrete log with El-Gamal commitment.
//! Called Пelog or Relog in the CGGMP24 papers.
//!
//! ## Description
//!
//! Common inputs:
//! - Curve `E` with generator $G$ of prime subgroup of size $q$
//! - $L, M, X, Y, H$ are points on curve `E`
//!
//! Prover has secret inputs $y, \lambda$ (scalars modulo $q$) such that $L = \lambda G,
//! M = \lambda X + y G, Y = y H$
//!
//! ## Example
//!
//! ```rust
//! use paillier_zk::{dlog_with_el_gamal_commitment as p};
//! use generic_ec::{Point, Scalar, curves::Secp256k1 as E};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Prover and verifier have a shared protocol state
//! let shared_state = "some shared state";
//!
//! let mut rng = rand_core::OsRng;
//! # let mut rng = rand_dev::DevRng::new();
//!
//! // Prover knows lambda, y
//!
//! let pdata = p::PrivateData {
//!     lambda: &Scalar::random(&mut rng),
//!     y: &Scalar::random(&mut rng),
//! };
//!
//! // Common data known by both prover and verifier:
//!
//! let x = Point::generator() * Scalar::random(&mut rng);
//! let h = Point::generator() * Scalar::random(&mut rng);
//!
//! let data = p::Data {
//!     l: &(Point::generator() * pdata.lambda),
//!     m: &(Point::generator() * pdata.y + x * pdata.lambda),
//!     x: &x,
//!     y: &(h * pdata.y),
//!     h: &h,
//! };
//!
//! // Generate non-interactive proof
//! let proof =
//!     p::non_interactive::prove::<E, sha2::Sha256>(
//!         &shared_state,
//!         data,
//!         pdata,
//!         &mut rng,
//!     )?;
//!
//! // Proof and the data are sent to the verifier
//!
//! # use generic_ec::Curve;
//! # fn send<E: Curve>(_: &p::Data<E>, _: &p::NiProof<E>) {  }
//! send(&data, &proof);
//!
//! // Verifier receives the data and the proof and verifies them
//!
//! # let recv = || (data, proof);
//! let (data, proof) = recv();
//! let r = p::non_interactive::verify::<E, sha2::Sha256>(
//!     &shared_state,
//!     data,
//!     &proof,
//! )?;
//! #
//! # Ok(()) }
//! ```
//!
//! If the verification succeeded, verifier can continue communication with prover

use generic_ec::{Curve, Point, Scalar};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub use crate::common::{Aux, InvalidProof};

/// Public data that both parties know
#[derive(Debug, Clone, Copy, udigest::Digestable)]
#[udigest(bound = "")]
pub struct Data<'a, E: Curve> {
    /// L in paper, obtained as g^\lambda
    pub l: &'a Point<E>,
    /// M in paper, obtained as g^y X^\lambda
    pub m: &'a Point<E>,
    /// X in paper
    pub x: &'a Point<E>,
    /// Y in paper, obtained as h^y
    pub y: &'a Point<E>,
    /// h in paper
    pub h: &'a Point<E>,
}

/// Private data of prover
#[derive(Clone, Copy)]
pub struct PrivateData<'a, E: Curve> {
    /// y or epsilon in paper, log of Y base h
    pub y: &'a Scalar<E>,
    /// lambda in paper, preimage of L
    pub lambda: &'a Scalar<E>,
}

/// Prover's first message, obtained by [`interactive::commit`]
#[derive(Debug, Clone, udigest::Digestable)]
#[udigest(bound = "")]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct Commitment<E: Curve> {
    pub a: Point<E>,
    pub n: Point<E>,
    pub b: Point<E>,
}

/// Prover's data accompanying the commitment. Kept as state between rounds in
/// the interactive protocol.
#[derive(Clone)]
pub struct PrivateCommitment<E: Curve> {
    pub alpha: Scalar<E>,
    pub m: Scalar<E>,
}

/// Verifier's challenge to prover. Can be obtained deterministically by
/// [`non_interactive::challenge`] or randomly by [`interactive::challenge`]
pub type Challenge<E> = Scalar<E>;

/// The ZK proof. Computed by [`interactive::prove`].
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct Proof<E: Curve> {
    pub z: Scalar<E>,
    pub u: Scalar<E>,
}

/// The non-interactive ZK proof. Computed by [`non_interactive::prove`].
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
    use generic_ec::{Curve, Point, Scalar};
    use rand_core::RngCore;

    use crate::common::{fail_if_ne, InvalidProof, InvalidProofReason};
    use crate::Error;

    use super::*;

    /// Create random commitment
    pub fn commit<E: Curve>(
        data: Data<E>,
        rng: &mut impl RngCore,
    ) -> Result<(Commitment<E>, PrivateCommitment<E>), Error> {
        let alpha = Scalar::random(rng);
        let m = Scalar::random(rng);

        let a = Point::<E>::generator() * alpha;
        let n = Point::<E>::generator() * m + data.x * alpha;
        let b = data.h * m;

        let commitment = Commitment { a, n, b };
        let private_commitment = PrivateCommitment { alpha, m };
        Ok((commitment, private_commitment))
    }

    /// Compute proof for given data and prior protocol values
    pub fn prove<E: Curve>(
        pdata: PrivateData<E>,
        pcomm: &PrivateCommitment<E>,
        challenge: &Challenge<E>,
    ) -> Result<Proof<E>, Error> {
        let z = pcomm.alpha + challenge * pdata.lambda;
        let u = pcomm.m + challenge * pdata.y;
        Ok(Proof { z, u })
    }

    /// Verify the proof
    pub fn verify<E: Curve>(
        data: Data<E>,
        commitment: &Commitment<E>,
        challenge: &Challenge<E>,
        proof: &Proof<E>,
    ) -> Result<(), InvalidProof> {
        // Three equality checks
        {
            let lhs = Point::<E>::generator() * proof.z;
            let rhs = commitment.a + data.l * challenge;
            fail_if_ne(InvalidProofReason::EqualityCheck(1), lhs, rhs)?;
        }
        {
            let lhs = Point::<E>::generator() * proof.u + data.x * proof.z;
            let rhs = commitment.n + data.m * challenge;
            fail_if_ne(InvalidProofReason::EqualityCheck(2), lhs, rhs)?;
        }
        {
            let lhs = data.h * proof.u;
            let rhs = commitment.b + data.y * challenge;
            fail_if_ne(InvalidProofReason::EqualityCheck(3), lhs, rhs)?;
        }

        Ok(())
    }

    /// Generate random challenge
    pub fn challenge<E: Curve>(rng: &mut impl RngCore) -> Challenge<E> {
        Scalar::random(rng)
    }
}

/// The non-interactive version of proof. Completed in one round, for example
/// see the documentation of parent module.
pub mod non_interactive {
    use digest::Digest;
    use generic_ec::Curve;

    use crate::{Error, InvalidProof};

    use super::{Challenge, Commitment, Data, NiProof, PrivateData};

    /// Compute proof for the given data, producing random commitment and
    /// deriving deterministic challenge.
    ///
    /// Obtained from the above interactive proof via Fiat-Shamir heuristic.
    pub fn prove<E: Curve, D: Digest>(
        shared_state: &impl udigest::Digestable,
        data: Data<E>,
        pdata: PrivateData<E>,
        rng: &mut impl rand_core::RngCore,
    ) -> Result<NiProof<E>, Error> {
        let (commitment, pcomm) = super::interactive::commit(data, rng)?;
        let challenge = challenge::<E, D>(shared_state, data, &commitment);
        let proof = super::interactive::prove::<E>(pdata, &pcomm, &challenge)?;
        Ok(NiProof { commitment, proof })
    }

    /// Verify the proof, deriving challenge independently from same data
    pub fn verify<E: Curve, D: Digest>(
        shared_state: &impl udigest::Digestable,
        data: Data<E>,
        proof: &NiProof<E>,
    ) -> Result<(), InvalidProof> {
        let challenge = challenge::<E, D>(shared_state, data, &proof.commitment);
        super::interactive::verify::<E>(data, &proof.commitment, &challenge, &proof.proof)
    }

    /// Deterministically compute challenge based on prior known values in protocol
    pub fn challenge<E: Curve, D: Digest>(
        shared_state: &impl udigest::Digestable,
        data: Data<E>,
        commitment: &Commitment<E>,
    ) -> Challenge<E> {
        let tag = "paillier_zk.dlog_with_el_gamal.ni_challenge";
        let seed = udigest::inline_struct!(tag {
            shared_state,
            data,
            commitment,
        });
        let mut rng = rand_hash::HashRng::<D, _>::from_seed(seed);
        super::interactive::challenge(&mut rng)
    }
}

#[cfg(test)]
mod test {
    use generic_ec::{Curve, Point, Scalar};
    use sha2::Digest;

    use crate::common::InvalidProofReason;

    fn run<E: Curve, D: Digest>(
        rng: &mut impl rand_core::CryptoRngCore,
        data: super::Data<E>,
        pdata: super::PrivateData<E>,
    ) -> Result<(), crate::common::InvalidProof> {
        let shared_state = "shared state";

        let proof = super::non_interactive::prove::<E, D>(&shared_state, data, pdata, rng).unwrap();
        super::non_interactive::verify::<E, D>(&shared_state, data, &proof)
    }

    fn passing_test<E: Curve, D: Digest>() {
        let mut rng = rand_dev::DevRng::new();

        let pdata = super::PrivateData {
            y: &Scalar::random(&mut rng),
            lambda: &Scalar::random(&mut rng),
        };

        let h = Point::<E>::generator() * Scalar::random(&mut rng);
        let x = Point::<E>::generator() * Scalar::random(&mut rng);

        let data = super::Data {
            l: &(Point::<E>::generator() * pdata.lambda),
            m: &(Point::<E>::generator() * pdata.y + x * pdata.lambda),
            x: &x,
            y: &(h * pdata.y),
            h: &h,
        };
        run::<E, D>(&mut rng, data, pdata).expect("proof failed");
    }

    fn failing_check_lambda_<E: Curve, D: Digest>() {
        // Scenario where the prover P does not know lambda
        let mut rng = rand_dev::DevRng::new();

        let mut pdata = super::PrivateData {
            y: &Scalar::random(&mut rng),
            lambda: &Scalar::random(&mut rng),
        };

        let h = Point::<E>::generator() * Scalar::random(&mut rng);
        let x = Point::<E>::generator() * Scalar::random(&mut rng);

        let data = super::Data {
            l: &(Point::<E>::generator() * pdata.lambda),
            m: &(Point::<E>::generator() * pdata.y + x * pdata.lambda),
            x: &x,
            y: &(h * pdata.y),
            h: &h,
        };

        // Replace lambda with another value
        let fake_lambda = Scalar::random(&mut rng);
        pdata.lambda = &fake_lambda;

        let err = run::<E, D>(&mut rng, data, pdata).expect_err("proof should not pass");
        match err.reason() {
            InvalidProofReason::EqualityCheck(1) => (),
            e => panic!("proof should not fail with {e:?}"),
        }
    }

    fn failing_check_y_<E: Curve, D: Digest>() {
        // Scenario where the prover P does not know y
        let mut rng = rand_dev::DevRng::new();

        let mut pdata = super::PrivateData {
            y: &Scalar::random(&mut rng),
            lambda: &Scalar::random(&mut rng),
        };

        let h = Point::<E>::generator() * Scalar::random(&mut rng);
        let x = Point::<E>::generator() * Scalar::random(&mut rng);

        let data = super::Data {
            l: &(Point::<E>::generator() * pdata.lambda),
            m: &(Point::<E>::generator() * pdata.y + x * pdata.lambda),
            x: &x,
            y: &(h * pdata.y),
            h: &h,
        };

        // Replace y with another value
        let fake_y = Scalar::random(&mut rng);
        pdata.y = &fake_y;

        let r = run::<E, D>(&mut rng, data, pdata).expect_err("proof should not pass");
        match r.reason() {
            InvalidProofReason::EqualityCheck(2) => (),
            e => panic!("proof should not fail with {e:?}"),
        }
    }

    #[test]
    fn passing_p256() {
        passing_test::<generic_ec::curves::Secp256r1, sha2::Sha256>()
    }

    #[test]
    fn passing_million() {
        passing_test::<crate::curve::E, sha2::Sha256>()
    }
    #[test]
    fn failing_check_1_p256() {
        failing_check_lambda_::<generic_ec::curves::Secp256r1, sha2::Sha256>()
    }

    #[test]
    fn failing_check_1_million() {
        failing_check_lambda_::<crate::curve::E, sha2::Sha256>()
    }
    #[test]
    fn failing_check_2_p256() {
        failing_check_y_::<generic_ec::curves::Secp256r1, sha2::Sha256>()
    }

    #[test]
    fn failing_check_2_million() {
        failing_check_y_::<crate::curve::E, sha2::Sha256>()
    }
}
