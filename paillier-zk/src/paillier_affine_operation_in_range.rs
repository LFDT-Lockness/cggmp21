//! ZK-proof of paillier operation with group commitment in range. Called Пaff-g
//! or Raff-g in the CGGMP24 paper.
//!
//! ## Description
//!
//! A party P performs a paillier affine operation with C, Y, and X
//! obtaining `D = C*X + Y`. `X` and `Y` are encrypted values of `x` and `y`. P
//! then wants to prove that `y` and `x` are at most `L` and `L'` bits,
//! correspondingly, and P doesn't want to disclose none of the plaintexts
//!
//! Given:
//! - `key0`, `pkey0`, `key1`, `pkey1` - pairs of public and private keys in
//!   paillier cryptosystem
//! - `rho_y`, `rho` - nonces in paillier encryption
//! - `x`, `y` - some numbers
//! - `q`, `g` such that `<g> = Zq*` - prime order group
//! - `C` is some ciphertext encrypted by `key0`
//! - `Y = key1.encrypt(y, rho_y)`
//! - `X = g * x`
//! - `D = oadd(enc(y, rho), omul(x, C))` where `enc`, `oadd` and `omul` are
//!   paillier encryption, homomorphic addition and multiplication with `key0`
//!
//! Prove:
//! - `bitsize(abs(x)) <= l`
//! - `bitsize(abs(y)) <= l_prime`
//!
//! Disclosing only: `key0`, `key1`, `C`, `D`, `Y`, `X`
//!
//! ## Example
//!
//! ```rust
//! use paillier_zk::{paillier_affine_operation_in_range as p, IntegerExt};
//! use rug::{Integer, Complete};
//! use generic_ec::{Point, curves::Secp256k1 as E};
//! # mod pregenerated {
//! #     use super::*;
//! #     paillier_zk::load_pregenerated_data!(
//! #         verifier_aux: p::Aux,
//! #         someone_encryption_key0: fast_paillier::EncryptionKey,
//! #         someone_encryption_key1: fast_paillier::EncryptionKey,
//! #     );
//! # }
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Prover and verifier have a shared protocol state
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
//!     l_prime: 256 * 5,
//!     epsilon: 256 * 2,
//! };
//!
//! // 1. Setup: prover prepares the paillier keys
//!
//! // C and D are encrypted by this key
//! let n_j: fast_paillier::EncryptionKey = pregenerated::someone_encryption_key0();
//! // Y is encrypted using this key
//! let n_i: fast_paillier::EncryptionKey = pregenerated::someone_encryption_key1();
//!
//! // C is some number encrypted using n_j. Neither of parties
//! // need to know the plaintext
//! let ciphertext_c = Integer::gen_invertible(&n_j.nn(), &mut rng);
//!
//! // 2. Setup: prover prepares all plaintexts
//!
//! // x in paper
//! let plaintext_x = Integer::from_rng_half_pm(
//!     &(Integer::ONE << security.l).complete(),
//!     &mut rng,
//! );
//! // y in paper
//! let plaintext_y = Integer::from_rng_half_pm(
//!     &(Integer::ONE << security.l_prime).complete(),
//!     &mut rng,
//! );
//!
//! // 3. Setup: prover encrypts everything on correct keys and remembers some nonces
//!
//! // X in paper
//! let ciphertext_x = Point::<E>::generator() * plaintext_x.to_scalar();
//! // Y and ρ_y in paper
//! let (ciphertext_y, rho_y) = n_i.encrypt_with_random(
//!     &mut rng,
//!     &(plaintext_y),
//! )?;
//! // ρ in paper
//! let (ciphertext_y_by_n_j, rho) = n_j.encrypt_with_random(
//!     &mut rng,
//!     &(plaintext_y)
//! )?;
//! // D in paper
//! let ciphertext_d = n_j
//!     .oadd(
//!         &n_j.omul(&plaintext_x, &ciphertext_c)?,
//!         &ciphertext_y_by_n_j,
//!     )?;
//!
//! // 4. Prover computes a non-interactive proof that plaintext_x and
//! //    plaintext_y are at most `l` and `l_prime` bits
//!
//! let data = p::Data {
//!     n_j: &n_j,
//!     n_i: &n_i,
//!     c: &ciphertext_c,
//!     d: &ciphertext_d,
//!     x: &ciphertext_x,
//!     y: &ciphertext_y,
//! };
//! let pdata = p::PrivateData {
//!     x: &plaintext_x,
//!     y: &plaintext_y,
//!     rho: &rho,
//!     rho_y: &rho_y,
//! };
//! let proof =
//!     p::non_interactive::prove::<E, sha2::Sha256>(
//!         &shared_state,
//!         &aux,
//!         data,
//!         pdata,
//!         &security,
//!         &mut rng,
//!     )?;
//!
//! // 5. Prover sends this data to verifier
//!
//! # use generic_ec::Curve;
//! # fn send<E: Curve>(_: &p::Data<E>, _: &p::NiProof<E>) {  }
//! send(&data, &proof);
//!
//! // 6. Verifier receives the data and the proof and verifies it
//!
//! # let recv = || (data, proof);
//! let (data, proof) = recv();
//! let r = p::non_interactive::verify::<E, sha2::Sha256>(
//!     &shared_state,
//!     &aux,
//!     data,
//!     &security,
//!     &proof,
//! )?;
//! #
//! # Ok(()) }
//! ```
//!
//! If the verification succeeded, verifier can continue communication with prover

use fast_paillier::{AnyEncryptionKey, Ciphertext, Nonce};
use generic_ec::{Curve, Point};
use rug::Integer;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub use crate::common::{Aux, InvalidProof};

/// Security parameters for proof. Choosing the values is a tradeoff between
/// speed and chance of rejecting a valid proof or accepting an invalid proof
#[derive(Debug, Clone, udigest::Digestable)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecurityParams {
    /// l in paper, bit size of +-x
    pub l: usize,
    /// l' in paper, bit size of +-y
    pub l_prime: usize,
    /// Epsilon in paper, slackness parameter
    pub epsilon: usize,
}

/// Public data that both parties know
#[derive(Debug, Clone, Copy, udigest::Digestable)]
#[udigest(bound = "")]
pub struct Data<'a, E: Curve> {
    /// N_j in the spec, public key that C was encrypted on
    #[udigest(as = crate::common::encoding::AnyEncryptionKey)]
    pub n_j: &'a dyn AnyEncryptionKey,
    /// Ni in the spec, public key that y -> Y was encrypted on
    #[udigest(as = crate::common::encoding::AnyEncryptionKey)]
    pub n_i: &'a dyn AnyEncryptionKey,
    /// C in the spec, some data encrypted on Nj
    #[udigest(as = &crate::common::encoding::Integer)]
    pub c: &'a Ciphertext,
    /// D in the spec, result of affine transformation of C with x and y
    #[udigest(as = &crate::common::encoding::Integer)]
    pub d: &'a Integer,
    /// Y in the spec, y encrypted on Ni
    #[udigest(as = &crate::common::encoding::Integer)]
    pub y: &'a Ciphertext,
    /// X in the spec, obtained as `x G`
    pub x: &'a Point<E>,
}

/// Private data of prover
#[derive(Clone, Copy)]
pub struct PrivateData<'a> {
    /// x in the spec, preimage of X
    pub x: &'a Integer,
    /// y in the spec, preimage of Y
    pub y: &'a Integer,
    /// rho in the spec, nonce in encryption of y for additive action
    pub rho: &'a Nonce,
    /// rho_y in the spec, nonce in encryption of y to obtain Y
    pub rho_y: &'a Nonce,
}

/// Prover's first message, obtained by [`interactive::commit`]
#[derive(Debug, Clone, udigest::Digestable)]
#[udigest(bound = "")]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct Commitment<E: Curve> {
    #[udigest(as = crate::common::encoding::Integer)]
    pub a: Integer,
    pub b_x: Point<E>,
    #[udigest(as = crate::common::encoding::Integer)]
    pub b_y: Integer,
    #[udigest(as = crate::common::encoding::Integer)]
    pub e: Integer,
    #[udigest(as = crate::common::encoding::Integer)]
    pub s: Integer,
    #[udigest(as = crate::common::encoding::Integer)]
    pub f: Integer,
    #[udigest(as = crate::common::encoding::Integer)]
    pub t: Integer,
}

/// Prover's data accompanying the commitment. Kept as state between rounds in
/// the interactive protocol.
#[derive(Clone)]
pub struct PrivateCommitment {
    pub alpha: Integer,
    pub beta: Integer,
    pub r: Integer,
    pub r_y: Integer,
    pub gamma: Integer,
    pub delta: Integer,
    pub m: Integer,
    pub mu: Integer,
}

/// Verifier's challenge to prover. Can be obtained deterministically by
/// [`non_interactive::challenge`] or randomly by [`interactive::challenge`]
pub type Challenge = Integer;

/// The ZK proof. Computed by [`interactive::prove`].
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Proof {
    pub z1: Integer,
    pub z2: Integer,
    pub z3: Integer,
    pub z4: Integer,
    pub w: Integer,
    pub w_y: Integer,
}

/// The non-interactive ZK proof. Computed by [`non_interactive::prove`].
/// Combines commitment and proof.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct NiProof<E: Curve> {
    pub commitment: Commitment<E>,
    pub proof: Proof,
}

/// The interactive version of the ZK proof. Should be completed in 3 rounds:
/// prover commits to data, verifier responds with a random challenge, and
/// prover gives proof with commitment and challenge.
pub mod interactive {
    use generic_ec::{Curve, Point};
    use rand_core::RngCore;
    use rug::{Complete, Integer};

    use crate::common::{fail_if, fail_if_ne, IntegerExt, InvalidProof, InvalidProofReason};
    use crate::Error;

    use super::*;

    /// Create random commitment
    pub fn commit<E: Curve, R: RngCore>(
        aux: &Aux,
        data: Data<E>,
        pdata: PrivateData,
        security: &SecurityParams,
        mut rng: R,
    ) -> Result<(Commitment<E>, PrivateCommitment), Error> {
        let two_to_l = (Integer::ONE << security.l).complete();
        let two_to_l_e = (Integer::ONE << (security.l + security.epsilon)).complete();
        let two_to_l_prime_e = (Integer::ONE << (security.l_prime + security.epsilon)).complete();
        let hat_n_at_two_to_l_e = (&aux.rsa_modulo * &two_to_l_e).complete();
        let hat_n_at_two_to_l = (&aux.rsa_modulo * &two_to_l).complete();

        let alpha = Integer::from_rng_half_pm(&two_to_l_e, &mut rng);
        let beta = Integer::from_rng_half_pm(&two_to_l_prime_e, &mut rng);
        let r = Integer::gen_invertible(data.n_j.n(), &mut rng);
        let r_y = Integer::gen_invertible(data.n_i.n(), &mut rng);
        let gamma = Integer::from_rng_half_pm(&hat_n_at_two_to_l_e, &mut rng);
        let delta = Integer::from_rng_half_pm(&hat_n_at_two_to_l_e, &mut rng);
        let m = Integer::from_rng_half_pm(&hat_n_at_two_to_l, &mut rng);
        let mu = Integer::from_rng_half_pm(&hat_n_at_two_to_l, &mut rng);

        let commitment = Commitment {
            a: {
                let beta_enc_key0 = data.n_j.encrypt_with(&beta, &r)?;
                let alpha_at_c = data.n_j.omul(&alpha, data.c)?;
                data.n_j.oadd(&alpha_at_c, &beta_enc_key0)?
            },
            b_x: Point::<E>::generator() * alpha.to_scalar(),
            b_y: data.n_i.encrypt_with(&beta, &r_y)?,
            e: aux.combine(&alpha, &gamma)?,
            s: aux.combine(pdata.x, &m)?,
            f: aux.combine(&beta, &delta)?,
            t: aux.combine(pdata.y, &mu)?,
        };
        let private_commitment = PrivateCommitment {
            alpha,
            beta,
            r,
            r_y,
            gamma,
            m,
            delta,
            mu,
        };
        Ok((commitment, private_commitment))
    }

    /// Compute proof for given data and prior protocol values
    pub fn prove<E: Curve>(
        data: Data<E>,
        pdata: PrivateData,
        pcomm: &PrivateCommitment,
        challenge: &Challenge,
    ) -> Result<Proof, Error> {
        Ok(Proof {
            z1: (&pcomm.alpha + challenge * pdata.x).complete(),
            z2: (&pcomm.beta + challenge * pdata.y).complete(),
            z3: (&pcomm.gamma + challenge * &pcomm.m).complete(),
            z4: (&pcomm.delta + challenge * &pcomm.mu).complete(),
            w: data
                .n_j
                .n()
                .combine(&pcomm.r, Integer::ONE, pdata.rho, challenge)?,
            // TODO: this can be optimized as prover knows n_i factorization
            w_y: data
                .n_i
                .n()
                .combine(&pcomm.r_y, Integer::ONE, pdata.rho_y, challenge)?,
        })
    }

    /// Verify the proof
    pub fn verify<E: Curve>(
        aux: &Aux,
        data: Data<E>,
        commitment: &Commitment<E>,
        security: &SecurityParams,
        challenge: &Challenge,
        proof: &Proof,
    ) -> Result<(), InvalidProof> {
        // Five equality checks and two range checks
        {
            let lhs = {
                let e_at_d = data
                    .n_j
                    .omul(challenge, data.d)
                    .map_err(|_| InvalidProofReason::PaillierOp)?;
                data.n_j
                    .oadd(&commitment.a, &e_at_d)
                    .map_err(|_| InvalidProofReason::PaillierOp)?
            };
            let rhs = {
                let z1_at_c = data
                    .n_j
                    .omul(&proof.z1, data.c)
                    .map_err(|_| InvalidProofReason::PaillierOp)?;
                let enc = data
                    .n_j
                    .encrypt_with(&proof.z2, &proof.w)
                    .map_err(|_| InvalidProofReason::PaillierEnc)?;
                data.n_j
                    .oadd(&z1_at_c, &enc)
                    .map_err(|_| InvalidProofReason::PaillierOp)?
            };
            fail_if_ne(InvalidProofReason::EqualityCheck(1), lhs, rhs)?;
        }
        {
            let lhs = Point::<E>::generator() * proof.z1.to_scalar();
            let rhs = commitment.b_x + data.x * challenge.to_scalar();
            fail_if_ne(InvalidProofReason::EqualityCheck(2), lhs, rhs)?;
        }
        {
            let lhs = {
                let e_at_y = data
                    .n_i
                    .omul(challenge, data.y)
                    .map_err(|_| InvalidProofReason::PaillierOp)?;
                data.n_i
                    .oadd(&commitment.b_y, &e_at_y)
                    .map_err(|_| InvalidProofReason::PaillierOp)?
            };
            let rhs = data
                .n_i
                .encrypt_with(&proof.z2, &proof.w_y)
                .map_err(|_| InvalidProofReason::PaillierEnc)?;
            fail_if_ne(InvalidProofReason::EqualityCheck(3), lhs, rhs)?;
        }
        {
            let lhs = aux.combine(&proof.z1, &proof.z3)?;
            let s_to_e = aux.pow_mod(&commitment.s, challenge)?;
            let rhs = (&commitment.e * s_to_e).modulo(&aux.rsa_modulo);
            fail_if_ne(InvalidProofReason::EqualityCheck(4), lhs, rhs)?;
        }
        {
            let lhs = aux.combine(&proof.z2, &proof.z4)?;
            let t_to_e = aux.pow_mod(&commitment.t, challenge)?;
            let rhs = (&commitment.f * t_to_e).modulo(&aux.rsa_modulo);
            fail_if_ne(InvalidProofReason::EqualityCheck(5), lhs, rhs)?;
        }
        fail_if(
            InvalidProofReason::RangeCheck(6),
            proof
                .z1
                .is_in_half_pm(&(Integer::ONE << (security.l + security.epsilon)).complete()),
        )?;
        fail_if(
            InvalidProofReason::RangeCheck(7),
            proof
                .z2
                .is_in_half_pm(&(Integer::ONE << (security.l_prime + security.epsilon)).complete()),
        )?;
        Ok(())
    }

    /// Generate random challenge
    pub fn challenge<E: Curve>(rng: &mut impl rand_core::RngCore) -> Integer {
        let q = Integer::curve_order::<E>();
        Integer::from_rng_half_pm(&q, rng)
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
    /// deriving determenistic challenge.
    ///
    /// Obtained from the above interactive proof via Fiat-Shamir heuristic.
    pub fn prove<E: Curve, D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: Data<E>,
        pdata: PrivateData,
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
        security: &SecurityParams,
        proof: &NiProof<E>,
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
        let tag = "paillier_zk.paillier_affine_operation_in_range.ni_challenge";
        let aux = aux.digest_public_data();
        let seed = udigest::inline_struct!(tag {
            shared_state,
            aux,
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
    use generic_ec::{Curve, Point};
    use rug::{Complete, Integer};
    use sha2::Digest;

    use crate::common::test::random_key;
    use crate::common::{IntegerExt, InvalidProofReason};

    fn run<R: rand_core::RngCore + rand_core::CryptoRng, E: Curve, D: Digest>(
        rng: &mut R,
        security: super::SecurityParams,
        x: Integer,
        y: Integer,
    ) -> Result<(), crate::common::InvalidProof> {
        let dk0 = random_key(rng).unwrap();
        let dk1 = random_key(rng).unwrap();
        let ek0 = dk0.encryption_key().clone();
        let ek1 = dk1.encryption_key().clone();

        let (c, _) = {
            let plaintext = Integer::from_rng_half_pm(ek0.n(), rng);
            ek0.encrypt_with_random(rng, &plaintext).unwrap()
        };

        let (y_enc_ek1, rho_y) = ek1.encrypt_with_random(rng, &y).unwrap();

        let (y_enc_ek0, rho) = ek0.encrypt_with_random(rng, &y).unwrap();
        let x_at_c = ek0.omul(&x, &c).unwrap();
        let d = ek0.oadd(&x_at_c, &y_enc_ek0).unwrap();

        let data = super::Data {
            n_j: &ek0,
            n_i: &ek1,
            c: &c,
            d: &d,
            y: &y_enc_ek1,
            x: &(x.to_scalar::<E>() * Point::generator()),
        };
        let pdata = super::PrivateData {
            x: &x,
            y: &y,
            rho: &rho,
            rho_y: &rho_y,
        };

        let aux = crate::common::test::aux(rng);

        let shared_state = "shared state";

        let proof =
            super::non_interactive::prove::<E, D>(&shared_state, &aux, data, pdata, &security, rng)
                .unwrap();
        super::non_interactive::verify::<E, D>(&shared_state, &aux, data, &security, &proof)
    }

    fn passing_test<E: Curve, D: Digest>() {
        let mut rng = rand_dev::DevRng::new();
        let security = super::SecurityParams {
            l: 1024,
            l_prime: 1024,
            epsilon: 300,
        };
        let x = Integer::from_rng_half_pm(&(Integer::ONE << security.l).complete(), &mut rng);
        let y = Integer::from_rng_half_pm(&(Integer::ONE << security.l_prime).complete(), &mut rng);
        run::<_, E, D>(&mut rng, security, x, y).expect("proof failed");
    }

    fn failing_on_additive<E: Curve, D: Digest>() {
        let mut rng = rand_dev::DevRng::new();
        let security = super::SecurityParams {
            l: 1024,
            l_prime: 1024,
            epsilon: 300,
        };
        let x = Integer::from_rng_half_pm(&(Integer::ONE << security.l).complete(), &mut rng);
        let y = (Integer::ONE << (security.l_prime + security.epsilon - 1)).complete() + 1;
        let r = run::<_, E, D>(&mut rng, security, x, y).expect_err("proof should not pass");
        match r.reason() {
            InvalidProofReason::RangeCheck(7) => (),
            e => panic!("proof should not fail with: {e:?}"),
        }
    }

    fn failing_on_multiplicative<E: Curve, D: Digest>() {
        let mut rng = rand_dev::DevRng::new();
        let security = super::SecurityParams {
            l: 1024,
            l_prime: 1024,
            epsilon: 300,
        };
        let x = (Integer::ONE << (security.l + security.epsilon - 1)).complete() + 1;
        let y = Integer::from_rng_half_pm(&(Integer::ONE << security.l_prime).complete(), &mut rng);
        let r = run::<_, E, D>(&mut rng, security, x, y).expect_err("proof should not pass");
        match r.reason() {
            InvalidProofReason::RangeCheck(6) => (),
            e => panic!("proof should not fail with: {e:?}"),
        }
    }

    #[test]
    fn passing_p256() {
        passing_test::<generic_ec::curves::Secp256r1, sha2::Sha256>()
    }
    #[test]
    fn failing_p256_add() {
        failing_on_additive::<generic_ec::curves::Secp256r1, sha2::Sha256>()
    }
    #[test]
    fn failing_p256_mul() {
        failing_on_multiplicative::<generic_ec::curves::Secp256r1, sha2::Sha256>()
    }

    #[test]
    fn passing_million() {
        passing_test::<crate::curve::E, sha2::Sha256>()
    }
    #[test]
    fn failing_million_add() {
        failing_on_additive::<crate::curve::E, sha2::Sha256>()
    }
    #[test]
    fn failing_million_mul() {
        failing_on_multiplicative::<crate::curve::E, sha2::Sha256>()
    }
}
