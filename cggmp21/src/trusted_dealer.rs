//! Trusted dealer
//!
//! Trusted dealer can be used to generate key shares in one place. Note
//! that it creates an SPOF/T (single point of failure/trust). Trusted
//! dealer is mainly intended to be used in tests, or it can be used to
//! import key into TSS.
//!
//! ## Example
//! Import a key into 3-out-of-5 TSS:
//! ```rust,no_run
//! # use rand::rngs::OsRng;
//! # let mut rng = OsRng;
//! use cggmp21::{supported_curves::Secp256k1, security_level::SecurityLevel128};
//! use cggmp21::generic_ec::SecretScalar;
//!
//! let secret_key_to_be_imported = SecretScalar::<Secp256k1>::random(&mut rng);
//!
//! let key_shares = cggmp21::trusted_dealer::builder::<Secp256k1, SecurityLevel128>(5)
//!     .set_threshold(Some(3))
//!     .set_shared_secret_key(secret_key_to_be_imported)
//!     .generate_shares(&mut rng)?;
//! # Ok::<_, cggmp21::trusted_dealer::TrustedDealerError>(())
//! ```

use std::{iter, marker::PhantomData};

use generic_ec::{Curve, NonZero, SecretScalar};
use paillier_zk::{
    rug::{Complete, Integer},
    IntegerExt,
};
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;

use crate::{
    key_share::{
        AuxInfo, DirtyAuxInfo, IncompleteKeyShare, InvalidKeyShare, KeyShare, PartyAux, Validate,
    },
    security_level::SecurityLevel,
    utils,
};

/// Construct a trusted dealer builder
///
/// Takes amount of key shares `n` to be generated
///
/// Alias to [`TrustedDealerBuilder::new`]
pub fn builder<E: Curve, L: SecurityLevel>(n: u16) -> TrustedDealerBuilder<E, L> {
    TrustedDealerBuilder::new(n)
}

type CoreBuilder<E> = key_share::trusted_dealer::TrustedDealerBuilder<E>;

/// Trusted dealer builder
pub struct TrustedDealerBuilder<E: Curve, L: SecurityLevel> {
    inner: CoreBuilder<E>,
    n: u16,
    pregenerated_primes: Option<Vec<(Integer, Integer)>>,
    enable_mulitexp: bool,
    enable_crt: bool,
    _ph: PhantomData<L>,
}

impl<E: Curve, L: SecurityLevel> TrustedDealerBuilder<E, L> {
    /// Construct a trusted dealer builder
    ///
    /// Takes amount of key shares `n` to be generated
    pub fn new(n: u16) -> Self {
        TrustedDealerBuilder {
            inner: CoreBuilder::new(n),
            n,
            pregenerated_primes: None,
            enable_mulitexp: false,
            enable_crt: false,
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
        Self {
            inner: self.inner.set_threshold(t),
            ..self
        }
    }

    /// Sets shared secret key to be generated
    ///
    /// Resulting key shares will share specified secret key.
    pub fn set_shared_secret_key(self, sk: NonZero<SecretScalar<E>>) -> Self {
        Self {
            inner: self.inner.set_shared_secret_key(sk),
            ..self
        }
    }

    /// Sets pregenerated primes to use
    ///
    /// `primes` should have exactly `n` pairs of primes.
    pub fn set_pregenerated_primes(self, primes: Vec<(Integer, Integer)>) -> Self {
        Self {
            pregenerated_primes: Some(primes),
            ..self
        }
    }

    /// Enables multiexp optimization
    ///
    /// It takes additional time to precompute multiexp tables, and it makes the key shares larger,
    /// but it makes the signing and presignature generation protocols faster
    pub fn enable_multiexp(self, v: bool) -> Self {
        Self {
            enable_mulitexp: v,
            ..self
        }
    }

    /// Enables CRT optimization
    ///
    /// CRT optimization makes ZK proofs verification faster, and by doing so it makes the overall performance better
    pub fn enable_crt(self, v: bool) -> Self {
        Self {
            enable_crt: v,
            ..self
        }
    }

    /// Specifies that the key being generated shall support HD derivation
    #[cfg(feature = "hd-wallets")]
    pub fn hd_wallet(self, v: bool) -> Self {
        Self {
            inner: self.inner.hd_wallet(v),
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
        self.inner
            .generate_shares(rng)
            .map_err(Reason::CoreError)
            .map_err(TrustedDealerError)
    }

    /// Generates [`KeyShare`]s
    ///
    /// Returns error if provided inputs are invalid, or if internal
    /// error has occurred.
    pub fn generate_shares(
        mut self,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Vec<KeyShare<E, L>>, TrustedDealerError> {
        let n = self.n;
        let enable_multiexp = self.enable_mulitexp;
        let enable_crt = self.enable_crt;

        let primes = self.pregenerated_primes.take();
        let core_key_shares = self.inner.generate_shares(rng).map_err(Reason::CoreError)?;
        let aux_data = if let Some(primes) = primes {
            generate_aux_data_with_primes(rng, primes, enable_multiexp, enable_crt)?
        } else {
            generate_aux_data(rng, n, enable_multiexp, enable_crt)?
        };

        let key_shares = core_key_shares
            .into_iter()
            .zip(aux_data)
            .map(|(core, aux)| KeyShare::from_parts((core, aux)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| Reason::InvalidKeyShare(err.into_error()))?;

        Ok(key_shares)
    }
}

/// Generates auxiliary data for `n` signers
///
/// Auxiliary data can be used to "complete" core key share using [`KeyShare::from_parts`] constructor.
///
/// `enable_multiexp` and `enable_crt` flags configure whether to enable [multiexp](TrustedDealerBuilder::enable_multiexp)
/// and [CRT](TrustedDealerBuilder::enable_crt) optimizations.
pub fn generate_aux_data<L: SecurityLevel, R: RngCore + CryptoRng>(
    rng: &mut R,
    n: u16,
    enable_multiexp: bool,
    enable_crt: bool,
) -> Result<Vec<AuxInfo<L>>, TrustedDealerError> {
    let primes =
        iter::repeat_with(|| crate::key_refresh::PregeneratedPrimes::<L>::generate(rng).split())
            .take(n.into())
            .collect::<Vec<_>>();

    generate_aux_data_with_primes(rng, primes, enable_multiexp, enable_crt)
}

/// Generates auxiliary data for `n` signers using provided pregenerated primes
///
/// `pregenerated_primes` should have exactly `n` pairs of primes.
///
/// `enable_multiexp` and `enable_crt` flags configure whether to enable [multiexp](TrustedDealerBuilder::enable_multiexp)
/// and [CRT](TrustedDealerBuilder::enable_crt) optimizations.
pub fn generate_aux_data_with_primes<L: SecurityLevel, R: RngCore + CryptoRng>(
    rng: &mut R,
    pregenerated_primes: Vec<(Integer, Integer)>,
    enable_multiexp: bool,
    enable_crt: bool,
) -> Result<Vec<AuxInfo<L>>, TrustedDealerError> {
    let public_aux_data = pregenerated_primes
        .iter()
        .map(|(p, q)| {
            let N = (p * q).complete();

            let φ_N = (p - 1u8).complete() * (q - 1u8).complete();

            let r = Integer::gen_invertible(&N, rng);
            let λ = φ_N.random_below_ref(&mut utils::external_rand(rng)).into();

            let t = r.square().modulo(&N);
            let s = t.pow_mod_ref(&λ, &N).ok_or(Reason::PowMod)?.into();

            let mut aux = PartyAux {
                N,
                s,
                t,
                multiexp: None,
                crt: None,
            };
            if enable_multiexp {
                aux.precompute_multiexp_table::<L>()
                    .map_err(Reason::BuildMultiexp)?;
            }
            Ok(aux)
        })
        .collect::<Result<Vec<_>, Reason>>()?;

    pregenerated_primes
        .into_iter()
        .enumerate()
        .map(|(i, (p, q))| {
            let mut public_aux_data = public_aux_data.clone();
            if enable_crt {
                public_aux_data[i]
                    .precompute_crt(&p, &q)
                    .map_err(Reason::BuildCrt)?;
            }

            DirtyAuxInfo {
                p,
                q,
                parties: public_aux_data,
                security_level: PhantomData,
            }
            .validate()
            .map_err(|err| Reason::InvalidKeyShare(err.into_error()))
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(TrustedDealerError)
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
    #[error("couldn't build a CRT")]
    BuildCrt(#[source] InvalidKeyShare),
    #[error("couldn't build multiexp tables")]
    BuildMultiexp(#[source] InvalidKeyShare),
    #[error(transparent)]
    CoreError(#[from] key_share::trusted_dealer::TrustedDealerError),
}
