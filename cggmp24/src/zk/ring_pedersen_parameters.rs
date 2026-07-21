//! Пprm or Rprm in the paper. Proof that s ⋮ t modulo N. Non-interactive
//! version only.
use digest::Digest;
use paillier_zk::backend::Integer;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use thiserror::Error;

struct Challenge<const M: usize> {
    es: [bool; M],
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
    #[udigest(as = [crate::utils::encoding::Integer; M])]
    pub commitment: [Integer; M],
    #[serde_as(as = "[_; M]")]
    #[udigest(as = [crate::utils::encoding::Integer; M])]
    pub zs: [Integer; M],
}

fn derive_challenge<const M: usize, D: Digest>(
    shared_state: &impl udigest::Digestable,
    data: &crate::key_share::PedersenParams,
    commitment: &[Integer; M],
) -> Challenge<M> {
    #[derive(udigest::Digestable)]
    #[udigest(tag = "dfns.ring_pedersen_parameters.seed")]
    struct Seed<'a, S: udigest::Digestable, const M: usize> {
        shared_state: &'a S,
        #[udigest(as = &crate::utils::encoding::Integer)]
        hat_N: &'a Integer,
        #[udigest(as = &crate::utils::encoding::Integer)]
        s: &'a Integer,
        #[udigest(as = &crate::utils::encoding::Integer)]
        t: &'a Integer,
        #[udigest(as = &[crate::utils::encoding::Integer; M])]
        commitment: &'a [Integer; M],
    }

    let mut rng = rand_hash::HashRng::<D, _>::from_seed(Seed::<_, M> {
        shared_state,
        hat_N: &data.hat_N,
        s: &data.s,
        t: &data.t,
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
/// Private data:
/// - `phi` - $φ(N) = (p-1)(q-1)$
/// - `lambda` - λ such that $s = t^λ$
/// - `N_crt` is CRT built for fast exponentiation on `data.N`
pub fn prove<const M: usize, D: Digest>(
    shared_state: &impl udigest::Digestable,
    rng: &mut impl rand_core::RngCore,
    data: &crate::key_share::PedersenParams,
    phi: &Integer,
    lambda: &Integer,
) -> Result<Proof<M>, ZkError> {
    let private_commitment = [(); M].map(|()| phi.random_below_ref(rng));
    let commitment = private_commitment.clone().map(|a| {
        if let Some(crt) = &data.crt {
            crt.exp(&data.t, &crt.prepare_exponent(&a))
        } else {
            data.t.pow_mod_ref(&a, &data.hat_N)
        }
    });
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
    data: &crate::key_share::PedersenParams,
    proof: &Proof<M>,
) -> Result<(), InvalidProof> {
    // Verify that inputs are in expected domains
    if !data.s.in_mult_group_of(&data.hat_N) {
        return Err(InvalidProof);
    }
    if !data.t.in_mult_group_of(&data.hat_N) {
        return Err(InvalidProof);
    }
    for (A_i, z_i) in proof.commitment.iter().zip(&proof.zs) {
        if !A_i.in_mult_group_of(&data.hat_N) || z_i.cmp0().is_lt() || *z_i >= data.hat_N {
            return Err(InvalidProof);
        }
    }

    // Verify statement
    let challenge: Challenge<M> = derive_challenge::<M, D>(shared_state, data, &proof.commitment);
    for ((z, a), e) in proof.zs.iter().zip(&proof.commitment).zip(&challenge.es) {
        let lhs: Integer = data.t.pow_mod_ref(z, &data.hat_N).ok_or(InvalidProof)?;
        if *e {
            let rhs = (&data.s * a).modulo(&data.hat_N);
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
    use paillier_zk::backend::Integer;

    use crate::utils;

    type D = sha2::Sha256;

    #[test]
    fn passing() {
        let mut rng = rand_dev::DevRng::new();
        let shared_state = "shared state";

        let p = utils::generate_blum_prime(&mut rng, 256);
        let q = utils::generate_blum_prime(&mut rng, 256);
        let n_crt = paillier_zk::fast_paillier::utils::CrtExp::build_n(&p, &q).unwrap();
        let n = &p * &q;
        let phi = (&p - 1u8) * (&q - 1u8);

        let r = Integer::sample_in_mult_group_of(&mut rng, &n);
        let lambda = phi.random_below_ref(&mut rng);
        let t = r.square().modulo(&n);
        let s = t.pow_mod_ref(&lambda, &n).unwrap();

        let data = crate::key_share::PedersenParams {
            hat_N: n,
            s,
            t,
            multiexp: None,
            crt: Some(n_crt),
        };

        let proof: super::Proof<16> =
            super::prove::<16, D>(&shared_state, &mut rng, &data, &phi, &lambda).unwrap();
        super::verify::<16, D>(&shared_state, &data, &proof).expect("proof should pass");
    }

    #[test]
    fn failing() {
        let mut rng = rand_dev::DevRng::new();
        let shared_state = "shared state";

        let p = utils::generate_blum_prime(&mut rng, 256);
        let q = utils::generate_blum_prime(&mut rng, 256);
        let n_crt = paillier_zk::fast_paillier::utils::CrtExp::build_n(&p, &q).unwrap();
        let n = &p * &q;
        let phi = (&p - 1u8) * (&q - 1u8);

        let r = Integer::sample_in_mult_group_of(&mut rng, &n);
        let lambda = phi.random_below_ref(&mut rng);
        let t = r.square().modulo(&n);
        let correct_s = t.pow_mod_ref(&lambda, &n).unwrap();
        let s = (correct_s + 1u8).modulo(&n);

        let data = crate::key_share::PedersenParams {
            hat_N: n,
            s,
            t,
            multiexp: None,
            crt: Some(n_crt),
        };

        let proof: super::Proof<16> =
            super::prove::<16, D>(&shared_state, &mut rng, &data, &phi, &lambda).unwrap();
        if super::verify::<16, D>(&shared_state, &data, &proof).is_ok() {
            panic!("proof should fail");
        }
    }
}
