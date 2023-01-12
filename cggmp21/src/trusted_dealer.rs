use std::iter;

use paillier_zk::libpaillier::unknown_order::BigNumber;
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;

use generic_ec::{Curve, Point, SecretScalar};

use crate::{
    key_share::{IncompleteKeyShare, InvalidKeyShare, KeyShare, PartyAux, Valid},
    security_level::SecurityLevel,
    utils::sample_bigint_in_mult_group,
};

pub fn mock_keygen<E: Curve, L: SecurityLevel, R: RngCore + CryptoRng>(
    rng: &mut R,
    n: u16,
) -> Result<Vec<Valid<KeyShare<E, L>>>, TrustedDealerError> {
    let secret_shares = iter::repeat_with(|| SecretScalar::<E>::random(rng))
        .take(n.into())
        .collect::<Vec<_>>();
    let public_shares = secret_shares
        .iter()
        .map(|s_i| Point::generator() * s_i)
        .collect::<Vec<_>>();
    let shared_public_key = public_shares.iter().sum();

    let mut rid = L::Rid::default();
    rng.fill_bytes(rid.as_mut());

    let core_shares = (0u16..)
        .zip(secret_shares)
        .map(|(i, x_i)| IncompleteKeyShare::<E, L> {
            curve: Default::default(),
            i,
            shared_public_key,
            rid: rid.clone(),
            public_shares: public_shares.clone(),
            x: x_i,
        });

    let primes_setups = iter::repeat_with(|| generate_primes_setup::<L, _>(rng))
        .take(n.into())
        .collect::<Vec<_>>();

    let y = iter::repeat_with(|| SecretScalar::<E>::random(rng))
        .take(n.into())
        .collect::<Vec<_>>();
    let Y = y
        .iter()
        .map(|y_i| Point::generator() * y_i)
        .collect::<Vec<_>>();

    let parties_aux = primes_setups
        .iter()
        .zip(Y)
        .map(|(primes_setup, Y_i)| PartyAux {
            N: primes_setup.N.clone(),
            s: primes_setup.s.clone(),
            t: primes_setup.t.clone(),
            Y: Y_i,
        })
        .collect::<Vec<_>>();

    core_shares
        .zip(primes_setups)
        .zip(y)
        .map(|((core_share, primes_setup), y_i)| {
            KeyShare {
                p: primes_setup.p,
                q: primes_setup.q,
                y: y_i,
                parties: parties_aux.clone(),
                core: core_share,
            }
            .try_into()
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(TrustedDealerError)
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
) -> PartyPrimesSetup {
    let p = BigNumber::safe_prime_from_rng(L::SECURITY_BITS * 4, rng);
    let q = BigNumber::safe_prime_from_rng(L::SECURITY_BITS * 4, rng);
    let N = &p * &q;
    let φ_N = (&p - 1) * (&q - 1);

    let r = sample_bigint_in_mult_group(rng, &N);
    let λ = BigNumber::from_rng(&φ_N, rng);

    let t = BigNumber::modmul(&r, &r, &N);
    let s = BigNumber::modpow(&t, &λ, &N);

    PartyPrimesSetup { p, q, N, s, t }
}

#[derive(Debug, Error)]
#[error("trusted dealer failed to generate shares due to internal error")]
pub struct TrustedDealerError(InvalidKeyShare);
