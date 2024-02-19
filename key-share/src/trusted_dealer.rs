//! Trusted dealer
//!
//! Trusted dealer can be used to generate key shares in one place. Note
//! that in creates SPOF/T (single point of failure/trust). Trusted
//! dealer is mainly intended to be used in tests.
//!
//! ## Example
//! Import a key into 3-out-of-5 TSS:
//! ```rust,no_run
//! # use rand_core::OsRng;
//! # let mut rng = OsRng;
//! use generic_ec::{curves::Secp256k1, SecretScalar};
//!
//! let secret_key_to_be_imported = SecretScalar::<Secp256k1>::random(&mut OsRng);
//!
//! let key_shares = key_share::trusted_dealer::builder::<Secp256k1>(5)
//!     .set_threshold(Some(3))
//!     .set_shared_secret_key(secret_key_to_be_imported)
//!     .generate_shares(&mut rng)?;
//! # Ok::<_, key_share::trusted_dealer::TrustedDealerError>(())
//! ```

use generic_ec::{Curve, Point, Scalar, SecretScalar};

use crate::{CoreKeyShare, VssSetup};

/// Construct a trusted dealer builder
///
/// Takes amount of key shares `n` to be generated
///
/// Alias to [`TrustedDealerBuilder::new`]
pub fn builder<E: Curve>(n: u16) -> TrustedDealerBuilder<E> {
    TrustedDealerBuilder::new(n)
}

/// Trusted dealer builder
pub struct TrustedDealerBuilder<E: Curve> {
    t: Option<u16>,
    n: u16,
    shared_secret_key: Option<SecretScalar<E>>,
    #[cfg(feature = "hd-wallets")]
    enable_hd: bool,
}

impl<E: Curve> TrustedDealerBuilder<E> {
    /// Construct a trusted dealer builder
    ///
    /// Takes amount of key shares `n` to be generated
    pub fn new(n: u16) -> Self {
        TrustedDealerBuilder {
            t: None,
            n,
            shared_secret_key: None,
            #[cfg(feature = "hd-wallets")]
            enable_hd: false,
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

    /// Specifies that the key being generated shall support HD derivation
    #[cfg(feature = "hd-wallets")]
    pub fn hd_wallet(self, v: bool) -> Self {
        Self {
            enable_hd: v,
            ..self
        }
    }

    /// Generates [`CoreKeyShare`]s
    ///
    /// Returns error if provided inputs are invalid, or if internal
    /// error has occurred.
    pub fn generate_shares(
        self,
        rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    ) -> Result<Vec<CoreKeyShare<E>>, TrustedDealerError> {
        let shared_secret_key = self
            .shared_secret_key
            .unwrap_or_else(|| SecretScalar::random(rng));
        let key_shares_indexes = (1..=self.n)
            .map(|i| generic_ec::NonZero::from_scalar(Scalar::from(i)))
            .collect::<Option<Vec<_>>>()
            .ok_or(Reason::DeriveKeyShareIndex)?;
        let (shared_public_key, secret_shares) = if let Some(t) = self.t {
            let f = generic_ec_zkp::polynomial::Polynomial::sample_with_const_term(
                rng,
                usize::from(t) - 1,
                shared_secret_key,
            );
            let pk = Point::generator() * f.value::<_, Scalar<_>>(&Scalar::zero());
            let shares = key_shares_indexes
                .iter()
                .map(|I_i| f.value(I_i))
                .map(|mut x_i| SecretScalar::new(&mut x_i))
                .collect::<Vec<_>>();
            (pk, shares)
        } else {
            let mut shares = std::iter::repeat_with(|| SecretScalar::<E>::random(rng))
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

        #[cfg(feature = "hd-wallets")]
        let chain_code = if self.enable_hd {
            let mut code = slip_10::ChainCode::default();
            rng.fill_bytes(&mut code);
            Some(code)
        } else {
            None
        };

        Ok((0u16..)
            .zip(secret_shares)
            .map(|(i, x_i)| {
                crate::Validate::validate(crate::DirtyCoreKeyShare::<E> {
                    i,
                    key_info: crate::DirtyKeyInfo {
                        curve: Default::default(),
                        shared_public_key,
                        public_shares: public_shares.clone(),
                        vss_setup: vss_setup.clone(),
                        #[cfg(feature = "hd-wallets")]
                        chain_code,
                    },
                    x: x_i,
                })
                .map_err(|err| Reason::InvalidKeyShare(err.into_error()))
            })
            .collect::<Result<Vec<_>, _>>()?)
    }
}

/// Error explaining why trusted dealer failed to generate shares
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct TrustedDealerError(#[from] Reason);

#[derive(Debug, thiserror::Error)]
enum Reason {
    #[error("trusted dealer failed to generate shares due to internal error")]
    InvalidKeyShare(#[source] crate::InvalidCoreShare),
    #[error("deriving key share index failed")]
    DeriveKeyShareIndex,
}
