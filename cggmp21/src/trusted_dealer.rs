//! Trusted dealer
//!
//! Trusted dealer can be used to generate key shares in one place. Note
//! that in creates SPOF/T (single point of failure/trust). Trusted
//! dealer is mainly intended to be used in tests, or it can be used to
//! import key into TSS.
//!
//! ## Example
//! Import a key into 3-out-of-5 TSS:
//! ```rust,no_run
//! # use rand::rngs::OsRng;
//! # let mut rng = OsRng;
//! use cggmp21::{supported_curves::Secp256k1, security_level::ReasonablySecure};
//! use cggmp21::generic_ec::SecretScalar;
//!
//! let secret_key_to_be_imported = SecretScalar::<Secp256k1>::random(&mut OsRng);
//!
//! let key_shares = cggmp21::trusted_dealer::builder::<Secp256k1, ReasonablySecure>(5)
//!     .set_threshold(Some(3))
//!     .set_shared_secret_key(secret_key_to_be_imported)
//!     .generate_shares(&mut rng)?;
//! # Ok::<_, cggmp21::trusted_dealer::TrustedDealerError>(())
//! ```

use std::{iter, marker::PhantomData};

use generic_ec::{Curve, NonZero, Point, Scalar, SecretScalar};
use generic_ec_zkp::polynomial::Polynomial;
use paillier_zk::libpaillier::unknown_order::BigNumber;
use paillier_zk::BigNumberExt;
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;

use crate::{
    key_share::{
        DirtyAuxInfo, DirtyIncompleteKeyShare, DirtyKeyShare, IncompleteKeyShare, InvalidKeyShare,
        KeyShare, PartyAux, VssSetup,
    },
    security_level::SecurityLevel,
    utils::sample_bigint_in_mult_group,
};

/// Construct a trusted dealer builder
///
/// Takes amount of key shares `n` to be generated
///
/// Alias to [`TrustedDealerBuilder::new`]
pub fn builder<E: Curve, L: SecurityLevel>(n: u16) -> TrustedDealerBuilder<E, L> {
    TrustedDealerBuilder {
        t: None,
        n,
        shared_secret_key: None,
        _ph: PhantomData,
    }
}

/// Trusted dealer builder
pub struct TrustedDealerBuilder<E: Curve, L: SecurityLevel> {
    t: Option<u16>,
    n: u16,
    shared_secret_key: Option<SecretScalar<E>>,
    _ph: PhantomData<L>,
}

impl<E: Curve, L: SecurityLevel> TrustedDealerBuilder<E, L> {
    /// Construct a trusted dealer builder
    ///
    /// Takes amount of key shares `n` to be generated
    pub fn new(n: u16) -> Self {
        TrustedDealerBuilder {
            t: None,
            n,
            shared_secret_key: None,
            _ph: PhantomData,
        }
    }

    /// Sets threshold value
    ///
    /// If threshold is `Some(_)`, resulting key shares will be generated
    /// using t-out-of-n VSS scheme. If it's `None`, trusted dealer will
    /// generate additive key shares in n-out-ouf-n scheme.
    ///
    /// Note that setting `t=Some(n)` is not the same as setting `t=None`.
    /// Both produce n-out-of-n key shares, but `t=Some(n)` mocks threshold
    /// key generation with `threshold=n`, `t=None` mock non-threshold key
    /// generation.
    ///
    /// Default: `None`
    pub fn set_threshold(self, t: Option<u16>) -> Self {
        Self { t, ..self }
    }

    /// Sets shared secret key to be generated
    ///
    /// Resulting key shares will share specified secret key.
    pub fn set_shared_secret_key(self, sk: SecretScalar<E>) -> Self {
        Self {
            shared_secret_key: Some(sk),
            ..self
        }
    }

    /// Generates [`IncompleteKeyShare`]s
    ///
    /// Returns error if provided inputs are invalid, or if internal
    /// error has occurred.
    pub fn generate_core_shares(
        self,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Vec<IncompleteKeyShare<E>>, TrustedDealerError> {
        let shared_secret_key = self
            .shared_secret_key
            .unwrap_or_else(|| SecretScalar::random(rng));
        let key_shares_indexes = (1..=self.n)
            .map(|i| NonZero::from_scalar(Scalar::from(i)))
            .collect::<Option<Vec<_>>>()
            .ok_or(Reason::DeriveKeyShareIndex)?;
        let (shared_public_key, secret_shares) = if let Some(t) = self.t {
            let f = Polynomial::sample_with_const_term(rng, usize::from(t) - 1, shared_secret_key);
            let pk = Point::generator() * f.value::<_, Scalar<_>>(&Scalar::zero());
            let shares = key_shares_indexes
                .iter()
                .map(|I_i| f.value(I_i))
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
                DirtyIncompleteKeyShare::<E> {
                    curve: Default::default(),
                    i,
                    shared_public_key,
                    public_shares: public_shares.clone(),
                    x: x_i,
                    vss_setup: vss_setup.clone(),
                }
                .try_into()
                .map_err(Reason::InvalidKeyShare)
            })
            .collect::<Result<Vec<_>, _>>()?)
    }

    /// Generates [`KeyShare`]s
    ///
    /// Returns error if provided inputs are invalid, or if internal
    /// error has occurred.
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
                        security_level: std::marker::PhantomData,
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

/// Error explaining why trusted dealer failed to generate shares
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
