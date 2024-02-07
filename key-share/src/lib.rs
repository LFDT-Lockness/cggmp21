//! Key share of Threshold Signature Scheme (TSS)
//!
//! TSS protocols often share the same structure of key share. Having a separate crate with definition of the
//! key share struct help reusing the code, keeping different implementations compatible and interopable.
//!
//! The crate provides [`DirtyCoreKeyShare`] that contains data such as: secret share, other signers commitments,
//! public key and etc.
//!
//! [`DirtyCoreKeyShare`] may contain any data, not necessarily consistent. TSS protocol implementations typically
//! don't want to handle inconsistent key shares and would rather assume that it's valid. [`Valid<T>`](Valid)
//! is a type-guard stating that the value `T` it holds was validated. So, `Valid<DirtyCoreKeyShare>` (or
//! [`CoreKeyShare`] type alias) can be used to express that only valid key shares are accepted.

#![allow(non_snake_case)]
#![deny(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unused_crate_dependencies)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

use generic_ec::{serde::CurveName, Curve, NonZero, Point, Scalar, SecretScalar};
use generic_ec_zkp::polynomial::lagrange_coefficient;

mod utils;
mod valid;

pub use self::valid::{Valid, Validate, ValidateError, ValidateFromParts};

/// Core key share
///
/// Core key share is type alias to [`DirtyCoreKeyShare`] wrapped into [`Valid<T>`](Valid), meaning
/// that the key share has been validated that:
/// * Number of signers `n` doesn't overflow [`u16::MAX`], and that n >= 2
/// * Signer index `i` is less than `n`
/// * Signer public commitment matches the secret share
/// * Threshold value is within range `2 <= t <= n`
/// * All signers commitments sum up to public key
///
/// It's impossible to obtain [`CoreKeyShare`] for the key share that doesn't meet above requirements.
///
/// Only immutable access to the key share is provided. If you need to change content of the key share,
/// you need to obtain dirty key share via [`Valid::into_inner`], modify the key share, and validate it
/// again to obtain `CoreKeyShare`.
pub type CoreKeyShare<E> = Valid<DirtyCoreKeyShare<E>>;

#[cfg(feature = "serde")]
use serde_with::As;

/// Dirty (unvalidated) core key share
///
/// Key share can be either polynomial or additive:
/// * Polynomial key share:
///   * Supports any threshold $2 \le t \le n$
///   * All signers co-share a secret polynomial $F(x)$ with degree $deg(F) = t-1$
///   * Signer with index $i$ (index is in range $0 \le i < n$) holds secret share $x_i = F(I_i)$
///   * Shared secret key is $\sk = F(0)$.
///
///   If key share is polynomial, [`vss_setup`](Self::vss_setup) fiels should be `Some(_)`.
///
///   $I_j$ mentioned above is defined in [`VssSetup::I`]. Reasonable default would be $I_j = j+1$.
/// * Additive key share:
///   * Always non-threshold (i.e. $t=n$)
///   * Signer with index $i$ holds a secret share $x_i$
///   * All signers share a secret key that is sum of all secret shares $\sk = \sum_{j \in \[n\]} x_j$.
///
///   Advantage of additive share is that DKG protocol that yields additive share is a bit more efficient.
///
/// # HD wallets support
/// If `hd-wallets` feature is enabled, key share provides basic support of deterministic key derivation:
/// * [`chain_code`](Self::chain_code) field is added. If it's `Some(_)`, then the key is HD-capable.
///   `(shared_public_key, chain_code)` is extended public key of the wallet (can be retrieved via
///   [extended_public_key](DirtyCoreKeyShare::extended_public_key) method).
///   * Setting `chain_code` to `None` disables HD wallets support for the key
/// * Convenient methods are provided such as [derive_child_public_key](DirtyCoreKeyShare::derive_child_public_key)
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct DirtyCoreKeyShare<E: Curve> {
    /// Guard that ensures curve consistency for deseraization
    pub curve: CurveName<E>,
    /// Index of local party in key generation protocol
    pub i: u16,
    /// Public key corresponding to shared secret key. Corresponds to _X_ in paper.
    #[cfg_attr(feature = "serde", serde(with = "As::<generic_ec::serde::Compact>"))]
    pub shared_public_key: Point<E>,
    /// Public shares of all signers sharing the key
    ///
    /// `public_shares[i]` corresponds to public share (or public commitment) of $\ith$ party.
    #[cfg_attr(
        feature = "serde",
        serde(with = "As::<Vec<generic_ec::serde::Compact>>")
    )]
    pub public_shares: Vec<Point<E>>,
    /// Verifiable secret sharing setup, present if key was generated using VSS scheme
    pub vss_setup: Option<VssSetup<E>>,
    /// Chain code associated with the key, if HD wallets support was enabled
    #[cfg(feature = "hd-wallets")]
    #[cfg_attr(
        feature = "serde",
        serde(default),
        serde(with = "As::<Option<utils::HexOrBin>>")
    )]
    pub chain_code: Option<slip_10::ChainCode>,
    /// Secret share $x_i$
    #[cfg_attr(feature = "serde", serde(with = "As::<generic_ec::serde::Compact>"))]
    pub x: SecretScalar<E>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
/// Secret sharing setup of a key
pub struct VssSetup<E: Curve> {
    /// Threshold parameter
    ///
    /// Specifies how many signers are required to perform signing
    pub min_signers: u16,
    /// Key shares indexes
    ///
    /// `I[i]` corresponds to key share index of a $\ith$ signer
    pub I: Vec<NonZero<Scalar<E>>>,
}

impl<E: Curve> Validate for DirtyCoreKeyShare<E> {
    type Error = InvalidCoreShare;

    fn is_valid(&self) -> Result<(), Self::Error> {
        let n: u16 = self
            .public_shares
            .len()
            .try_into()
            .map_err(|_| InvalidShareReason::NOverflowsU16)?;

        if n < 2 {
            return Err(InvalidShareReason::TooFewParties.into());
        }
        if self.i >= n {
            return Err(InvalidShareReason::PartyIndexOutOfBounds.into());
        }

        let party_public_share = self.public_shares[usize::from(self.i)];
        if party_public_share != Point::generator() * &self.x {
            return Err(InvalidShareReason::PartySecretShareDoesntMatchPublicShare.into());
        }

        match &self.vss_setup {
            Some(vss_setup) => validate_vss_key_share(self, n, vss_setup)?,
            None => validate_non_vss_key_share(self)?,
        }

        Ok(())
    }
}

#[allow(clippy::nonminimal_bool)]
fn validate_vss_key_share<E: Curve>(
    key_share: &DirtyCoreKeyShare<E>,
    n: u16,
    vss_setup: &VssSetup<E>,
) -> Result<(), InvalidCoreShare> {
    let t = vss_setup.min_signers;

    if !(2 <= t) {
        return Err(InvalidShareReason::ThresholdTooSmall.into());
    }
    if !(t <= n) {
        return Err(InvalidShareReason::ThresholdTooLarge.into());
    }
    if vss_setup.I.len() != usize::from(n) {
        return Err(InvalidShareReason::ILen.into());
    }

    // Now we need to check that public key shares indeed form a public key.
    // We do that in two steps:
    // 1. Take `t` first public key shares, derive a public key and compare
    //    with public key specified in key share
    // 2. Using first `t` public key shares, derive other `n-t` public shares
    //    and compare with the ones specified in the key share

    let first_t_shares = &key_share.public_shares[0..usize::from(t)];
    let indexes = &vss_setup.I[0..usize::from(t)];
    let interpolation = |x: Scalar<E>| {
        let lagrange_coefficients =
            (0..usize::from(t)).map(|j| lagrange_coefficient(x, j, indexes));
        lagrange_coefficients
            .zip(first_t_shares)
            .try_fold(Point::zero(), |acc, (lambda_j, X_j)| {
                Some(acc + lambda_j? * X_j)
            })
            .ok_or(InvalidShareReason::INotPairwiseDistinct)
    };
    let reconstructed_pk = interpolation(Scalar::zero())?;
    if reconstructed_pk != key_share.shared_public_key {
        return Err(InvalidShareReason::SharesDontMatchPublicKey.into());
    }

    for (&j, public_share_j) in vss_setup
        .I
        .iter()
        .zip(&key_share.public_shares)
        .skip(t.into())
    {
        if interpolation(j.into())? != *public_share_j {
            return Err(InvalidShareReason::SharesDontMatchPublicKey.into());
        }
    }

    Ok(())
}

fn validate_non_vss_key_share<E: Curve>(
    key_share: &DirtyCoreKeyShare<E>,
) -> Result<(), InvalidCoreShare> {
    if key_share.shared_public_key != key_share.public_shares.iter().sum::<Point<E>>() {
        return Err(InvalidShareReason::SharesDontMatchPublicKey.into());
    }
    Ok(())
}

#[cfg(feature = "hd-wallets")]
impl<E: Curve> DirtyCoreKeyShare<E> {
    /// Checks whether the key is HD-capable
    pub fn is_hd_wallet(&self) -> bool {
        self.chain_code.is_some()
    }

    /// Returns extended public key, if HD support was enabled
    pub fn extended_public_key(&self) -> Option<slip_10::ExtendedPublicKey<E>> {
        Some(slip_10::ExtendedPublicKey {
            public_key: self.shared_public_key,
            chain_code: self.chain_code?,
        })
    }

    /// Derives child public key, if it's HD key
    pub fn derive_child_public_key<ChildIndex>(
        &self,
        derivation_path: impl IntoIterator<Item = ChildIndex>,
    ) -> Result<
        slip_10::ExtendedPublicKey<E>,
        HdError<<ChildIndex as TryInto<slip_10::NonHardenedIndex>>::Error>,
    >
    where
        slip_10::NonHardenedIndex: TryFrom<ChildIndex>,
    {
        let epub = self.extended_public_key().ok_or(HdError::DisabledHd)?;
        slip_10::try_derive_child_public_key_with_path(
            &epub,
            derivation_path.into_iter().map(|index| index.try_into()),
        )
        .map_err(HdError::InvalidPath)
    }
}

impl<E: Curve> CoreKeyShare<E> {
    /// Returns amount of key co-holders
    pub fn n(&self) -> u16 {
        #[allow(clippy::expect_used)]
        self.public_shares
            .len()
            .try_into()
            .expect("valid key share is guaranteed to have amount of signers fitting into u16")
    }

    /// Returns threshold
    ///
    /// Threshold is an amount of signers required to cooperate in order to sign a message
    /// and/or generate presignature
    pub fn min_signers(&self) -> u16 {
        self.vss_setup
            .as_ref()
            .map(|s| s.min_signers)
            .unwrap_or_else(|| self.n())
    }

    /// Returns public key shared by signers
    pub fn shared_public_key(&self) -> Point<E> {
        self.shared_public_key
    }
}

/// Error indicating that key share is not valid
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct InvalidCoreShare(#[from] InvalidShareReason);

#[derive(Debug, thiserror::Error)]
enum InvalidShareReason {
    #[error("`n` overflows u16")]
    NOverflowsU16,
    #[error("amount of parties `n` is less than 2: n < 2")]
    TooFewParties,
    #[error("party index `i` out of bounds: i >= n")]
    PartyIndexOutOfBounds,
    #[error("party secret share doesn't match its public share: public_shares[i] != G x")]
    PartySecretShareDoesntMatchPublicShare,
    #[error("list of public shares doesn't match shared public key: public_shares.sum() != shared_public_key")]
    SharesDontMatchPublicKey,
    #[error("threshold value is too small (can't be less than 2)")]
    ThresholdTooSmall,
    #[error("threshold valud cannot exceed amount of signers")]
    ThresholdTooLarge,
    #[error("mismatched length of I: I.len() != n")]
    ILen,
    #[error("indexes of shares in I are not pairwise distinct")]
    INotPairwiseDistinct,
}

/// Error related to HD key derivation
#[derive(Debug, thiserror::Error)]
pub enum HdError<E> {
    /// HD derivation is disabled for the key
    #[error("HD derivation is disabled for the key")]
    DisabledHd,
    /// Derivation path is not valid
    #[error("derivation path is not valid")]
    InvalidPath(#[source] E),
}

impl<T> From<ValidateError<T, InvalidCoreShare>> for InvalidCoreShare {
    fn from(err: ValidateError<T, InvalidCoreShare>) -> Self {
        err.into_error()
    }
}
