//! Пprm or Rprm in the paper. Proof that s ⋮ t modulo N. Non-interactive
//! version only.
use digest::Digest;
use paillier_zk::{
    fast_paillier::utils,
    rug::{Complete, Integer},
};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use thiserror::Error;

struct Challenge<const M: usize> {
    es: [bool; M],
}

/// Data to construct proof about
#[derive(Clone, Copy, udigest::Digestable)]
pub struct Data<'a> {
    #[udigest(with = crate::utils::encoding::integer)]
    pub N: &'a Integer,
    #[udigest(with = crate::utils::encoding::integer)]
    pub s: &'a Integer,
    #[udigest(with = crate::utils::encoding::integer)]
    pub t: &'a Integer,
}

/// The ZK proof. Computed by [`prove`].
///
/// Parameter `M` is security level. The probability of an adversary generating
/// a correct proof for incorrect data is $2^{-M}$. You can use M defined here
/// as [`SECURITY`]
#[serde_as]
#[derive(Clone, Serialize, Deserialize, udigest::Digestable)]
pub struct Proof<const M: usize> {
    #[serde_as(as = "[_; M]")]
    #[udigest(with = crate::utils::encoding::integers_list)]
    pub commitment: [Integer; M],
    #[serde_as(as = "[_; M]")]
    #[udigest(with = crate::utils::encoding::integers_list)]
    pub zs: [Integer; M],
}

fn derive_challenge<const M: usize, D: Digest>(
    shared_state: &impl udigest::Digestable,
    data: Data,
    commitment: &[Integer; M],
) -> Challenge<M> {
    #[derive(udigest::Digestable)]
    #[udigest(tag = "dfns.ring_pedersen_parameters.seed")]
    struct Seed<'a, S: udigest::Digestable, const M: usize> {
        shared_state: &'a S,
        data: Data<'a>,
        #[udigest(with = crate::utils::encoding::integers_list)]
        commitment: &'a [Integer; M],
    }

    let mut rng = rand_hash::HashRng::<D, _>::from_seed(Seed::<_, M> {
        shared_state,
        data,
        commitment,
    });

    // generate bools by hand since we don't have rand
    let mut es = [false; M];
    let mut current = rng.next_u32();
    let mut bits_generated = 0;
    for e_ref in es.iter_mut() {
        if bits_generated == 32 {
            current = rng.next_u32();
            bits_generated = 0;
        }
        *e_ref = (current & 1) == 1;
        current >>= 1;
    }
    Challenge { es }
}

/// Compute the proof for the given data, producing random commitment and
/// deriving deterministic challenge based on `shared_state` and `data`
///
/// - `phi` - $φ(N) = (p-1)(q-1)$
/// - `lambda` - λ such that $s = t^λ$
pub fn prove<const M: usize, D: Digest>(
    shared_state: &impl udigest::Digestable,
    rng: &mut impl rand_core::RngCore,
    data: Data,
    phi: &Integer,
    lambda: &Integer,
) -> Result<Proof<M>, ZkError> {
    let private_commitment =
        [(); M].map(|()| phi.random_below_ref(&mut utils::external_rand(rng)).into());
    let commitment = private_commitment
        .clone()
        .map(|a| data.t.pow_mod_ref(&a, data.N).map(|r| r.into()));
    // TODO: since array::try_map is not stable yet, we have to be hacky here
    let commitment = if commitment.iter().any(Option::is_none) {
        return Err(Reason::PowMod.into());
    } else {
        // We made sure that every item in the array is `Some(_)`
        #[allow(clippy::unwrap_used)]
        commitment.map(Option::unwrap)
    };

    let challenge: Challenge<M> = derive_challenge::<M, D>(shared_state, data, &commitment);

    let mut zs = private_commitment;
    for (z_ref, e) in zs.iter_mut().zip(&challenge.es) {
        if *e {
            *z_ref += lambda;
            z_ref.modulo_mut(phi);
        }
    }
    Ok(Proof { commitment, zs })
}

/// Verify the proof. Derives determenistic challenge based on `shared_state`
/// and `data`.
pub fn verify<const M: usize, D: Digest>(
    shared_state: &impl udigest::Digestable,
    data: Data,
    proof: &Proof<M>,
) -> Result<(), InvalidProof> {
    let challenge: Challenge<M> = derive_challenge::<M, D>(shared_state, data, &proof.commitment);
    for ((z, a), e) in proof.zs.iter().zip(&proof.commitment).zip(&challenge.es) {
        let lhs: Integer = data.t.pow_mod_ref(z, data.N).ok_or(InvalidProof)?.into();
        if *e {
            let rhs = (data.s * a).complete().modulo(data.N);
            if lhs != rhs {
                return Err(InvalidProof);
            }
        } else if lhs != *a {
            return Err(InvalidProof);
        }
    }
    Ok(())
}

#[derive(Debug, Error)]
#[error(transparent)]
pub struct ZkError(#[from] Reason);

#[derive(Debug, Error)]
enum Reason {
    #[error("pow mod undefined")]
    PowMod,
}

/// Witness that proof is invalid
#[derive(Debug)]
pub struct InvalidProof;

// running with M=64 completed in 1.22 on my machine in debug build
#[cfg(test)]
mod test {
    use paillier_zk::{
        rug::{Complete, Integer},
        IntegerExt,
    };

    use crate::utils;

    type D = sha2::Sha256;

    #[test]
    fn passing() {
        let mut rng = rand_dev::DevRng::new();
        let shared_state = "shared state";

        let p = utils::generate_blum_prime(&mut rng, 256);
        let q = utils::generate_blum_prime(&mut rng, 256);
        let n = (&p * &q).complete();
        let phi = (&p - 1u8).complete() * (&q - 1u8).complete();

        let r = Integer::gen_invertible(&n, &mut rng);
        let lambda = phi
            .random_below_ref(&mut utils::external_rand(&mut rng))
            .into();
        let t = r.square().modulo(&n);
        let s = t.pow_mod_ref(&lambda, &n).unwrap().into();

        let data = super::Data {
            N: &n,
            s: &s,
            t: &t,
        };

        let proof: super::Proof<16> =
            super::prove::<16, D>(&shared_state, &mut rng, data, &phi, &lambda).unwrap();
        super::verify::<16, D>(&shared_state, data, &proof).expect("proof should pass");
    }

    #[test]
    fn failing() {
        let mut rng = rand_dev::DevRng::new();
        let shared_state = "shared state";

        let p = utils::generate_blum_prime(&mut rng, 256);
        let q = utils::generate_blum_prime(&mut rng, 256);
        let n = (&p * &q).complete();
        let phi = (&p - 1u8).complete() * (&q - 1u8).complete();

        let r = Integer::gen_invertible(&n, &mut rng);
        let lambda = phi
            .random_below_ref(&mut utils::external_rand(&mut rng))
            .into();
        let t = r.square().modulo(&n);
        let correct_s: Integer = t.pow_mod_ref(&lambda, &n).unwrap().into();
        let s = (correct_s + 1u8).modulo(&n);

        let data = super::Data {
            N: &n,
            s: &s,
            t: &t,
        };

        let proof: super::Proof<16> =
            super::prove::<16, D>(&shared_state, &mut rng, data, &phi, &lambda).unwrap();
        if super::verify::<16, D>(&shared_state, data, &proof).is_ok() {
            panic!("proof should fail");
        }
    }
}
