use std::iter;

use paillier_zk::libpaillier::unknown_order::BigNumber;
use rand_core::{CryptoRng, RngCore};

use generic_ec::{Curve, Point, SecretScalar};

use crate::{
    key_share::{IncompleteKeyShare, KeyShare, PartyAux, Valid},
    security_level::SecurityLevel,
    utils::sample_bigint_in_mult_group,
};

pub fn mock_keygen<E: Curve, L: SecurityLevel, R: RngCore + CryptoRng>(
    rng: &mut R,
    n: u16,
) -> Vec<Valid<KeyShare<E, L>>> {
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
        .expect("resulting shares are not valid")
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

#[cfg(test)]
pub mod cached_shares {
    use std::path::Path;

    use generic_ec::Curve;

    use crate::{
        key_share::{KeyShare, Valid},
        security_level::SecurityLevel,
    };

    pub fn load<E: Curve, L: SecurityLevel>(n: u16) -> Vec<Valid<KeyShare<E, L>>> {
        let file_path = Path::new("test-data")
            .join("key_shares")
            .join(format!("n{n}-{curve}.json", curve = E::CURVE_NAME));
        let key_shares = std::fs::read(file_path).expect("read key shares");
        serde_json::from_slice(&key_shares).expect("deserialize key shares")
    }

    pub fn save<E: Curve, L: SecurityLevel>(key_shares: &[Valid<KeyShare<E, L>>]) {
        let n = key_shares.len();
        let file_path = Path::new("test-data")
            .join("key_shares")
            .join(format!("n{n}-{curve}.json", curve = E::CURVE_NAME));
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(file_path)
            .expect("open file");
        serde_json::to_writer_pretty(&mut file, key_shares).expect("serialize and write key shares")
    }
}

#[cfg(test)]
#[generic_tests::define]
mod test {
    use generic_ec::{Curve, Point, Scalar};
    use rand_dev::DevRng;

    use crate::security_level::ReasonablySecure;

    use super::mock_keygen;

    #[test]
    #[ignore = "key shares generation is time consuming"]
    fn trusted_dealer_generates_correct_shares<E: Curve>() {
        let mut rng = DevRng::new();

        for n in [2, 3, 5, 7, 10] {
            let shares = mock_keygen::<E, ReasonablySecure, _>(&mut rng, n);
            let reconstructed_private_key: Scalar<E> = shares.iter().map(|s_i| &s_i.core.x).sum();
            shares.iter().enumerate().for_each(|(i, s_i)| {
                s_i.validate()
                    .unwrap_or_else(|e| panic!("{i} share not valid: {e}"))
            });
            assert_eq!(
                shares[0].core.shared_public_key,
                Point::generator() * reconstructed_private_key
            );
            super::cached_shares::save(&shares);
        }
    }

    #[instantiate_tests(<generic_ec::curves::Secp256r1>)]
    mod secp256r1 {}
}
