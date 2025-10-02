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
//! use cggmp24::{supported_curves::Secp256k1, security_level::SecurityLevel128};
//! use cggmp24::generic_ec::{SecretScalar, NonZero};
//!
//! let secret_key_to_be_imported = NonZero::<SecretScalar<Secp256k1>>::random(&mut rng);
//!
//! let key_shares = cggmp24::trusted_dealer::builder::<Secp256k1, SecurityLevel128>(5)
//!     .set_threshold(Some(3))
//!     .set_shared_secret_key(secret_key_to_be_imported)
//!     .generate_shares(&mut rng)?;
//! # Ok::<_, cggmp24::trusted_dealer::TrustedDealerError>(())
//! ```

use std::{iter, marker::PhantomData};

use generic_ec::{Curve, NonZero, SecretScalar};
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;

use crate::{
    key_share::{AuxInfo, DirtyAuxInfo, IncompleteKeyShare, InvalidKeyShare, KeyShare, Validate},
    security_level::SecurityLevel,
    utils, PregeneratedPrimes,
};

/// Construct a trusted dealer builder
///
/// Takes amount of key shares `n` to be generated
///
/// Alias to [`TrustedDealerBuilder::new`]
pub fn builder<E: Curve, L: SecurityLevel>(n: u16) -> TrustedDealerBuilder<E, L> {
    TrustedDealerBuilder::new(n)
}

type CoreBuilder<E> = cggmp24_keygen::key_share::trusted_dealer::TrustedDealerBuilder<E>;

/// Trusted dealer builder
pub struct TrustedDealerBuilder<E: Curve, L: SecurityLevel> {
    inner: CoreBuilder<E>,
    n: u16,
    pregenerated_primes: Option<Vec<PregeneratedPrimes<L>>>,
    enable_mulitexp: bool,
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
    pub fn set_pregenerated_primes(self, primes: Vec<PregeneratedPrimes<L>>) -> Self {
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

    /// Specifies that the key being generated shall support HD derivation
    #[cfg(feature = "hd-wallet")]
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

        let primes = self.pregenerated_primes.take();
        let core_key_shares = self.inner.generate_shares(rng).map_err(Reason::CoreError)?;
        let aux_data = if let Some(primes) = primes {
            generate_aux_data_with_primes(rng, primes, enable_multiexp)?
        } else {
            generate_aux_data(rng, n, enable_multiexp)?
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
/// `enable_multiexp` flag configures whether to enable [multiexp](TrustedDealerBuilder::enable_multiexp)
/// optimization.
pub fn generate_aux_data<L: SecurityLevel, R: RngCore + CryptoRng>(
    rng: &mut R,
    n: u16,
    enable_multiexp: bool,
) -> Result<Vec<AuxInfo<L>>, TrustedDealerError> {
    let primes = iter::repeat_with(|| crate::key_refresh::PregeneratedPrimes::<L>::generate(rng))
        .take(n.into())
        .collect::<Vec<_>>();

    generate_aux_data_with_primes(rng, primes, enable_multiexp)
}

/// Generates auxiliary data for `n` signers using provided pregenerated primes
///
/// `pregenerated_primes` should have exactly `n` pairs of primes.
///
/// `enable_multiexp` flag configures whether to enable [multiexp](TrustedDealerBuilder::enable_multiexp)
/// optimization.
pub fn generate_aux_data_with_primes<L: SecurityLevel, R: RngCore + CryptoRng>(
    rng: &mut R,
    pregenerated_primes: Vec<crate::PregeneratedPrimes<L>>,
    enable_multiexp: bool,
) -> Result<Vec<AuxInfo<L>>, TrustedDealerError> {
    let (N, pedersen_params) = pregenerated_primes
        .iter()
        .map(|primes| {
            let [p, q, hat_p, hat_q] = primes.primes_ref();
            let N = p * q;

            let (mut params, _phi, _lambda) =
                utils::generate_pedersen_params(rng, hat_p.clone(), hat_q.clone())?;

            if enable_multiexp {
                params
                    .precompute_multiexp_table::<L>()
                    .map_err(Reason::BuildMultiexp)?;
            }
            Ok((N, params))
        })
        .collect::<Result<(Vec<_>, Vec<_>), Reason>>()?;

    pregenerated_primes
        .into_iter()
        .enumerate()
        .map(|(i, primes)| {
            let mut pedersen_params = pedersen_params.clone();
            for (j, params) in pedersen_params.iter_mut().enumerate() {
                if i != j {
                    params.crt = None;
                }
            }

            let [p, q, _, _] = primes.into_primes();

            DirtyAuxInfo {
                p,
                q,
                N: N.clone(),
                pedersen_params,
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
    #[error("couldn't build multiexp tables")]
    BuildMultiexp(#[source] InvalidKeyShare),
    #[error(transparent)]
    CoreError(#[from] cggmp24_keygen::key_share::trusted_dealer::TrustedDealerError),
    #[error("generate pedersen params")]
    GenPedersen(#[from] utils::GenPedersenError),
}
