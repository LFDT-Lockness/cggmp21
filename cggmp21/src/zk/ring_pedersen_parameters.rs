//! Пprm or Rprm in the paper. Proof that s ⋮ t modulo N. Non-interactive
//! version only.
use digest::{typenum::U32, Digest};
use paillier_zk::{unknown_order::BigNumber, BigNumberExt};
use rand_core::{RngCore, SeedableRng};
use thiserror::Error;

/// A reasonable security level for proof
pub const SECURITY: usize = 64;

struct Challenge<const M: usize> {
    es: [bool; M],
}

/// Data to construct proof about
#[derive(Clone, Copy)]
pub struct Data<'a> {
    pub N: &'a BigNumber,
    pub s: &'a BigNumber,
    pub t: &'a BigNumber,
}

/// The ZK proof. Computed by [`prove`].
///
/// Parameter `M` is security level. The probability of an adversary generating
/// a correct proof for incorrect data is $2^{-M}$. You can use M defined here
/// as [`SECURITY`]
#[derive(Clone)]
pub struct Proof<const M: usize> {
    pub commitment: [BigNumber; M],
    pub zs: [BigNumber; M],
}

fn derive_challenge<const M: usize, D>(shared_state: D, data: Data) -> Challenge<M>
where
    D: Digest<OutputSize = U32>,
{
    let seed = shared_state
        .chain_update(&data.N.to_bytes())
        .chain_update(&data.s.to_bytes())
        .chain_update(&data.t.to_bytes())
        .finalize();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed.into());

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
pub fn prove<const M: usize, R, D>(
    shared_state: D,
    mut rng: R,
    data: Data,
    phi: &BigNumber,
    lambda: &BigNumber,
) -> Result<Proof<M>, ZkError>
where
    D: Digest<OutputSize = U32>,
    R: RngCore,
{
    let private_commitment = [(); M].map(|()| BigNumber::from_rng(phi, &mut rng));
    let commitment = private_commitment
        .clone()
        .map(|a| data.t.powmod(&a, data.N));
    // TODO: since array::try_map is not stable yet, we have to be hacky here
    let commitment = if commitment.iter().any(Result::is_err) {
        return Err(Reason::PowMod.into());
    } else {
        // We made sure that every item in the array is `Ok(_)`
        #[allow(clippy::unwrap_used)]
        commitment.map(Result::unwrap)
    };

    let challenge: Challenge<M> = derive_challenge(shared_state, data);

    let mut zs = private_commitment;
    for (z_ref, e) in zs.iter_mut().zip(&challenge.es) {
        if *e {
            *z_ref = z_ref.modadd(lambda, phi);
        }
    }
    Ok(Proof { commitment, zs })
}

/// Verify the proof. Derives determenistic challenge based on `shared_state`
/// and `data`.
pub fn verify<const M: usize, D>(
    shared_state: D,
    data: Data,
    proof: &Proof<M>,
) -> Result<(), InvalidProof>
where
    D: Digest<OutputSize = U32>,
{
    let challenge: Challenge<M> = derive_challenge(shared_state, data);
    for ((z, a), e) in proof.zs.iter().zip(&proof.commitment).zip(&challenge.es) {
        let lhs = data.t.powmod(z, data.N).map_err(|_| InvalidProof)?;
        if *e {
            let rhs = data.s.modmul(a, data.N);
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
    use paillier_zk::{unknown_order::BigNumber, BigNumberExt};

    #[test]
    fn passing() {
        let mut rng = rand_core::OsRng::default();
        let shared_state = sha2::Sha256::default();

        let p = BigNumber::prime_from_rng(256, &mut rng);
        let q = BigNumber::prime_from_rng(256, &mut rng);
        let n = &p * &q;
        let phi = (&p - 1) * (&q - 1);

        let r = crate::utils::sample_bigint_in_mult_group(&mut rng, &n);
        let lambda = BigNumber::from_rng(&phi, &mut rng);
        let t = r.modmul(&r, &n);
        let s = t.powmod(&lambda, &n).unwrap();

        let data = super::Data {
            N: &n,
            s: &s,
            t: &t,
        };

        let proof: super::Proof<16> = super::prove(
            shared_state.clone(),
            rand_core::OsRng::default(),
            data,
            &phi,
            &lambda,
        )
        .unwrap();
        super::verify(shared_state, data, &proof).expect("proof should pass");
    }

    #[test]
    fn failing() {
        let mut rng = rand_core::OsRng::default();
        let shared_state = sha2::Sha256::default();

        let p = BigNumber::prime_from_rng(256, &mut rng);
        let q = BigNumber::prime_from_rng(256, &mut rng);
        let n = &p * &q;
        let phi = (&p - 1) * (&q - 1);

        let r = crate::utils::sample_bigint_in_mult_group(&mut rng, &n);
        let lambda = BigNumber::from_rng(&phi, &mut rng);
        let t = r.modmul(&r, &n);
        let correct_s = t.powmod(&lambda, &n).unwrap();
        let s = correct_s.modadd(&BigNumber::one(), &n);

        let data = super::Data {
            N: &n,
            s: &s,
            t: &t,
        };

        let proof: super::Proof<16> = super::prove(
            shared_state.clone(),
            rand_core::OsRng::default(),
            data,
            &phi,
            &lambda,
        )
        .unwrap();
        if super::verify(shared_state, data, &proof).is_ok() {
            panic!("proof should fail");
        }
    }
}
