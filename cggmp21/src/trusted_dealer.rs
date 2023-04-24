use std::{iter, marker::PhantomData};

use paillier_zk::libpaillier::unknown_order::BigNumber;
use paillier_zk::BigNumberExt;
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;

use generic_ec::{Curve, NonZero, Point, Scalar, SecretScalar};

use crate::{
    key_share::{
        DirtyAuxInfo, DirtyIncompleteKeyShare, DirtyKeyShare, IncompleteKeyShare, InvalidKeyShare,
        KeyShare, PartyAux, VssSetup,
    },
    security_level::SecurityLevel,
    utils::sample_bigint_in_mult_group,
};

pub fn builder<E: Curve, L: SecurityLevel>(n: u16) -> TrustedDealerBuilder<E, L> {
    TrustedDealerBuilder {
        t: None,
        n,
        shared_secret_key: None,
        _ph: PhantomData,
    }
}

pub struct TrustedDealerBuilder<E: Curve, L: SecurityLevel> {
    t: Option<u16>,
    n: u16,
    shared_secret_key: Option<SecretScalar<E>>,
    _ph: PhantomData<L>,
}

impl<E: Curve, L: SecurityLevel> TrustedDealerBuilder<E, L> {
    pub fn set_threshold(self, t: Option<u16>) -> Self {
        Self { t, ..self }
    }

    pub fn set_shared_secret_key(self, sk: SecretScalar<E>) -> Self {
        Self {
            shared_secret_key: Some(sk),
            ..self
        }
    }

    pub fn generate_core_shares(
        self,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Vec<IncompleteKeyShare<E, L>>, TrustedDealerError> {
        let shared_secret_key = self
            .shared_secret_key
            .unwrap_or_else(|| SecretScalar::random(rng));
        let key_shares_indexes = (1..=self.n)
            .map(|i| NonZero::from_scalar(Scalar::from(i)))
            .collect::<Option<Vec<_>>>()
            .ok_or(Reason::DeriveKeyShareIndex)?;
        let (shared_public_key, secret_shares) = if let Some(t) = self.t {
            let polynomial_coef = iter::once(shared_secret_key)
                .chain(iter::repeat_with(|| SecretScalar::<E>::random(rng)).take((t - 1).into()))
                .collect::<Vec<_>>();
            let f = |x: &Scalar<E>| {
                polynomial_coef
                    .iter()
                    .rev()
                    .fold(Scalar::zero(), |acc, coef_i| acc * x + coef_i)
            };
            let pk = Point::generator() * f(&Scalar::zero());
            let shares = key_shares_indexes
                .iter()
                .map(|I_i| f(I_i))
                .map(|mut x_i| SecretScalar::new(&mut x_i))
                .collect::<Vec<_>>();
            (pk, shares)
        } else {
            let mut shares = iter::repeat_with(|| SecretScalar::<E>::random(rng))
                .take((self.n - 1).into())
                .collect::<Vec<_>>();
            shares.push(SecretScalar::new(
                &mut (shared_secret_key - shares.iter().sum::<Scalar<E>>()),
            ));
            let pk = shares.iter().map(|x_j| Point::generator() * x_j).sum();
            (pk, shares)
        };

        let public_shares = secret_shares
            .iter()
            .map(|s_i| Point::generator() * s_i)
            .collect::<Vec<_>>();

        let vss_setup = self.t.map(|t| VssSetup {
            min_signers: t,
            I: key_shares_indexes,
        });

        let mut rid = L::Rid::default();
        rng.fill_bytes(rid.as_mut());

        Ok((0u16..)
            .zip(secret_shares)
            .map(|(i, x_i)| {
                DirtyIncompleteKeyShare::<E, L> {
                    curve: Default::default(),
                    i,
                    shared_public_key,
                    rid: rid.clone(),
                    public_shares: public_shares.clone(),
                    x: x_i,
                    vss_setup: vss_setup.clone(),
                }
                .try_into()
                .map_err(Reason::InvalidKeyShare)
            })
            .collect::<Result<Vec<_>, _>>()?)
    }

    pub fn generate_shares(
        self,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Vec<KeyShare<E, L>>, TrustedDealerError> {
        let n = self.n;

        let core_key_shares = self.generate_core_shares(rng)?;
        let primes_setup = iter::repeat_with(|| generate_primes_setup::<L, _>(rng))
            .take(n.into())
            .collect::<Result<Vec<_>, _>>()?;

        let parties_pubic_aux = primes_setup
            .iter()
            .map(|s| PartyAux {
                N: s.N.clone(),
                s: s.s.clone(),
                t: s.t.clone(),
            })
            .collect::<Vec<_>>();

        let key_shares = core_key_shares
            .into_iter()
            .zip(primes_setup)
            .map(|(core_key_share, primes_setup)| {
                DirtyKeyShare {
                    core: core_key_share.into_inner(),
                    aux: DirtyAuxInfo {
                        p: primes_setup.p,
                        q: primes_setup.q,
                        parties: parties_pubic_aux.clone(),
                    },
                }
                .try_into()
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(Reason::InvalidKeyShare)?;

        Ok(key_shares)
    }
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
}
