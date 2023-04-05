use std::iter;

use paillier_zk::libpaillier::unknown_order::BigNumber;
use paillier_zk::BigNumberExt;
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;

use generic_ec::{Curve, NonZero, Point, Scalar, SecretScalar};

use crate::{
    key_share::{IncompleteKeyShare, InvalidKeyShare, KeyShare, PartyAux, Valid, VssSetup},
    security_level::SecurityLevel,
    utils::{lagrange_coefficient, sample_bigint_in_mult_group},
};

pub fn mock_keygen<E: Curve, L: SecurityLevel, R: RngCore + CryptoRng>(
    rng: &mut R,
    t: Option<u16>,
    n: u16,
) -> Result<Vec<Valid<KeyShare<E, L>>>, TrustedDealerError> {
    let key_shares_indexes = (1..=n)
        .map(|i| NonZero::from_scalar(Scalar::from(i)))
        .collect::<Option<Vec<_>>>()
        .ok_or(Reason::DeriveKeyShareIndex)?;
    let secret_shares = if let Some(t) = t {
        let polynomial_coef = iter::repeat_with(|| SecretScalar::<E>::random(rng))
            .take(t.into())
            .collect::<Vec<_>>();
        let f = |x: &NonZero<Scalar<E>>| {
            polynomial_coef
                .iter()
                .rev()
                .fold(Scalar::zero(), |acc, coef_i| acc * x + coef_i)
        };
        key_shares_indexes
            .iter()
            .map(|I_i| f(I_i))
            .map(|mut x_i| SecretScalar::new(&mut x_i))
            .collect::<Vec<_>>()
    } else {
        iter::repeat_with(|| SecretScalar::<E>::random(rng))
            .take(n.into())
            .collect::<Vec<_>>()
    };
    let public_shares = secret_shares
        .iter()
        .map(|s_i| Point::generator() * s_i)
        .collect::<Vec<_>>();
    let shared_public_key = if let Some(t) = t {
        let I = &key_shares_indexes[0..usize::from(t)];
        let lagrange_coefs = (0..t).map(|j| lagrange_coefficient(Scalar::zero(), j, I));
        lagrange_coefs
            .zip(&public_shares)
            .try_fold(Point::zero(), |acc, (lambda_j, X_j)| {
                Some(acc + lambda_j? * X_j)
            })
            .ok_or(Reason::DerivePublicKey)?
    } else {
        public_shares.iter().sum()
    };

    let vss_setup = t.map(|t| VssSetup {
        min_signers: t,
        I: key_shares_indexes,
    });

    let mut rid = L::Rid::default();
    rng.fill_bytes(rid.as_mut());

    let core_shares = (0u16..)
        .zip(secret_shares)
        .map(|(i, x_i)| IncompleteKeyShare::<E, L> {
            curve: Default::default(),
            i,
            n,
            shared_public_key,
            rid: rid.clone(),
            public_shares: public_shares.clone(),
            x: x_i,
            vss_setup: vss_setup.clone(),
        });

    let primes_setups = iter::repeat_with(|| generate_primes_setup::<L, _>(rng))
        .take(n.into())
        .collect::<Result<Vec<_>, _>>()?;

    let parties_aux = primes_setups
        .iter()
        .map(|primes_setup| PartyAux {
            N: primes_setup.N.clone(),
            s: primes_setup.s.clone(),
            t: primes_setup.t.clone(),
        })
        .collect::<Vec<_>>();

    let key_shares = core_shares
        .zip(primes_setups)
        .map(|(core_share, primes_setup)| {
            KeyShare {
                p: primes_setup.p,
                q: primes_setup.q,
                parties: parties_aux.clone(),
                core: core_share,
            }
            .try_into()
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(Reason::InvalidKeyShare)?;
    Ok(key_shares)
}

struct PartyPrimesSetup {
    p: BigNumber,
    q: BigNumber,
    N: BigNumber,
    s: BigNumber,
    t: BigNumber,
}

fn generate_primes_setup<L: SecurityLevel, R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<PartyPrimesSetup, TrustedDealerError> {
    let p = BigNumber::safe_prime_from_rng(L::SECURITY_BITS * 4, rng);
    let q = BigNumber::safe_prime_from_rng(L::SECURITY_BITS * 4, rng);
    let N = &p * &q;
    let φ_N = (&p - 1) * (&q - 1);

    let r = sample_bigint_in_mult_group(rng, &N);
    let λ = BigNumber::from_rng(&φ_N, rng);

    let t = BigNumber::modmul(&r, &r, &N);
    let s = BigNumber::powmod(&t, &λ, &N).map_err(|_| Reason::PowMod)?;

    Ok(PartyPrimesSetup { p, q, N, s, t })
}

#[derive(Debug, Error)]
#[error(transparent)]
pub struct TrustedDealerError(#[from] Reason);

#[derive(Debug, Error)]
enum Reason {
    #[error("trusted dealer failed to generate shares due to internal error")]
    InvalidKeyShare(#[source] InvalidKeyShare),
    #[error("pow mod undefined")]
    PowMod,
    #[error("deriving key share index failed")]
    DeriveKeyShareIndex,
    #[error("deriving public key failed")]
    DerivePublicKey,
}
