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
#![no_std]

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

use alloc::vec::Vec;
use core::{fmt, ops};

use generic_ec::{serde::CurveName, Curve, NonZero, Point, Scalar, SecretScalar};
use generic_ec_zkp::polynomial::lagrange_coefficient;

#[cfg(feature = "spof")]
pub mod trusted_dealer;
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
/// Public Key Info
///
/// Type alias to [`DirtyKeyInfo`] wrapped into [`Valid<T>`](Valid), meaning that the key info
/// has been validated that:
/// * Number of signers `n` doesn't overflow [`u16::MAX`], and that n >= 2
/// * Threshold value is within range `2 <= t <= n`
/// * All signers commitments sum up to public key
///
/// It's impossible to obtain [`KeyInfo`] that doesn't meet above requirements.
///
/// Only immutable access to the key info is provided. If you need to change content of the key info,
/// you need to obtain dirty key info via [`Valid::into_inner`], modify the key info, and validate it
/// again to obtain [`KeyInfo`].
pub type KeyInfo<E> = Valid<DirtyKeyInfo<E>>;

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
///   If key share is polynomial, [`vss_setup`](DirtyKeyInfo::vss_setup) fiels should be `Some(_)`.
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
/// * [`chain_code`](DirtyKeyInfo::chain_code) field is added. If it's `Some(_)`, then the key is HD-capable.
///   `(shared_public_key, chain_code)` is extended public key of the wallet (can be retrieved via
///   [extended_public_key](DirtyCoreKeyShare::extended_public_key) method).
///   * Setting `chain_code` to `None` disables HD wallets support for the key
/// * Convenient methods are provided such as [derive_child_public_key](DirtyCoreKeyShare::derive_child_public_key)
///
/// # Serialization format via `serde`
/// We make our best effort to keep serialization format the same between the versions (even with breaking changes),
/// and so far we've never introduced breaking change into the serialization format. This ensures that newer versions
/// of library are able to deserialize the key shares produced by the old version version of the library.
///
/// It's unlikely, but at some point, we might introduce a breaking change into the serialization format. In this case,
/// we'll announce it and publish the migration instructions.
///
/// Not every serde backend supports features that we use to ensure backwards compatibility. We require that field names
/// are being serialized, that helps us adding new fields as the library grows. We strongly advise using either
/// [`serde_json`](https://docs.rs/serde_json/), if verbose/human-readable format is needed, or
/// [`ciborium`](https://docs.rs/ciborium/latest/ciborium/), if you'd like to opt for binary format. Other serialization
/// backends are not tested and may not work or stop working at some point (like [bincode](https://github.com/dfns/cggmp21/issues/89) did)
/// or be not backwards compatible between certain versions.
///
/// If you need the smallest size of serialized key share, we advise implementing serialization manually (all fields of
/// the key share are public!).
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct DirtyCoreKeyShare<E: Curve> {
    /// Index of local party in key generation protocol
    pub i: u16,
    /// Public key info
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub key_info: DirtyKeyInfo<E>,
    /// Secret share $x_i$
    #[cfg_attr(feature = "serde", serde(with = "As::<generic_ec::serde::Compact>"))]
    pub x: NonZero<SecretScalar<E>>,
}

/// Public Key Info
///
/// Contains public information about the TSS key, including shared public key, commitments to
/// secret shares and etc.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
#[cfg_attr(feature = "udigest", derive(udigest::Digestable))]
pub struct DirtyKeyInfo<E: Curve> {
    /// Guard that ensures curve consistency for deseraization
    #[cfg_attr(feature = "udigest", udigest(with = utils::encoding::curve_name))]
    pub curve: CurveName<E>,
    /// Public key corresponding to shared secret key. Corresponds to _X_ in paper.
    #[cfg_attr(feature = "serde", serde(with = "As::<generic_ec::serde::Compact>"))]
    pub shared_public_key: NonZero<Point<E>>,
    /// Public shares of all signers sharing the key
    ///
    /// `public_shares[i]` corresponds to public share (or public commitment) of $\ith$ party.
    #[cfg_attr(
        feature = "serde",
        serde(with = "As::<Vec<generic_ec::serde::Compact>>")
    )]
    pub public_shares: Vec<NonZero<Point<E>>>,
    /// Verifiable secret sharing setup, present if key was generated using VSS scheme
    pub vss_setup: Option<VssSetup<E>>,
    /// Chain code associated with the key, if HD wallets support was enabled
    #[cfg(feature = "hd-wallets")]
    #[cfg_attr(
        feature = "serde",
        serde(default),
        serde(with = "As::<Option<utils::HexOrBin>>")
    )]
    #[cfg_attr(feature = "udigest", udigest(with = utils::encoding::maybe_bytes))]
    pub chain_code: Option<slip_10::ChainCode>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
#[cfg_attr(feature = "udigest", derive(udigest::Digestable))]
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
        let party_public_share = self
            .public_shares
            .get(usize::from(self.i))
            .ok_or(InvalidShareReason::PartyIndexOutOfBounds)?;
        if *party_public_share != Point::generator() * &self.x {
            return Err(InvalidShareReason::PartySecretShareDoesntMatchPublicShare.into());
        }

        self.key_info.is_valid()?;

        Ok(())
    }
}

impl<E: Curve> ValidateFromParts<(u16, DirtyKeyInfo<E>, NonZero<SecretScalar<E>>)>
    for DirtyCoreKeyShare<E>
{
    fn validate_parts(
        (i, key_info, x): &(u16, DirtyKeyInfo<E>, NonZero<SecretScalar<E>>),
    ) -> Result<(), Self::Error> {
        let party_public_share = key_info
            .public_shares
            .get(usize::from(*i))
            .ok_or(InvalidShareReason::PartyIndexOutOfBounds)?;
        if *party_public_share != Point::generator() * x {
            return Err(InvalidShareReason::PartySecretShareDoesntMatchPublicShare.into());
        }

        Ok(())
    }

    fn from_parts((i, key_info, x): (u16, DirtyKeyInfo<E>, NonZero<SecretScalar<E>>)) -> Self {
        Self { i, key_info, x }
    }
}

impl<E: Curve> Validate for DirtyKeyInfo<E> {
    type Error = InvalidCoreShare;

    fn is_valid(&self) -> Result<(), Self::Error> {
        match &self.vss_setup {
            Some(vss_setup) => {
                validate_vss_key_info(self.shared_public_key, &self.public_shares, vss_setup)
            }
            None => validate_non_vss_key_info(self.shared_public_key, &self.public_shares),
        }
    }
}

#[allow(clippy::nonminimal_bool)]
fn validate_vss_key_info<E: Curve>(
    shared_public_key: NonZero<Point<E>>,
    public_shares: &[NonZero<Point<E>>],
    vss_setup: &VssSetup<E>,
) -> Result<(), InvalidCoreShare> {
    let n: u16 = public_shares
        .len()
        .try_into()
        .map_err(|_| InvalidShareReason::NOverflowsU16)?;
    if n < 2 {
        return Err(InvalidShareReason::TooFewParties.into());
    }

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

    let first_t_shares = &public_shares[0..usize::from(t)];
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
    if reconstructed_pk != shared_public_key {
        return Err(InvalidShareReason::SharesDontMatchPublicKey.into());
    }

    for (&j, public_share_j) in vss_setup.I.iter().zip(public_shares).skip(t.into()) {
        if interpolation(j.into())? != *public_share_j {
            return Err(InvalidShareReason::SharesDontMatchPublicKey.into());
        }
    }

    Ok(())
}

fn validate_non_vss_key_info<E: Curve>(
    shared_public_key: NonZero<Point<E>>,
    public_shares: &[NonZero<Point<E>>],
) -> Result<(), InvalidCoreShare> {
    let n: u16 = public_shares
        .len()
        .try_into()
        .map_err(|_| InvalidShareReason::NOverflowsU16)?;
    if n < 2 {
        return Err(InvalidShareReason::TooFewParties.into());
    }
    if shared_public_key != public_shares.iter().sum::<Point<E>>() {
        return Err(InvalidShareReason::SharesDontMatchPublicKey.into());
    }
    Ok(())
}

impl<E: Curve> DirtyKeyInfo<E> {
    /// Returns share preimage associated with j-th signer
    ///
    /// * For additive shares, share preimage is defined as `j+1`
    /// * For VSS-shares, share preimage is scalar $I_j$ such that $x_j = F(I_j)$ where
    ///   $F(x)$ is polynomial co-shared by the signers and $x_j$ is secret share of j-th
    ///   signer
    ///
    /// Note: if you have no idea what it is, probably you don't need it.
    pub fn share_preimage(&self, j: u16) -> Option<NonZero<Scalar<E>>> {
        if let Some(vss_setup) = self.vss_setup.as_ref() {
            vss_setup.I.get(usize::from(j)).copied()
        } else if usize::from(j) < self.public_shares.len() {
            #[allow(clippy::expect_used)]
            Some(
                NonZero::from_scalar(Scalar::one() + Scalar::from(j))
                    .expect("1 + i_u16 is guaranteed to be nonzero"),
            )
        } else {
            None
        }
    }
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
            public_key: self.shared_public_key.into_inner(),
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
    pub fn shared_public_key(&self) -> NonZero<Point<E>> {
        self.shared_public_key
    }
}

impl<E: Curve> ops::Deref for DirtyCoreKeyShare<E> {
    type Target = DirtyKeyInfo<E>;
    fn deref(&self) -> &Self::Target {
        &self.key_info
    }
}
impl<E: Curve> AsRef<DirtyKeyInfo<E>> for DirtyCoreKeyShare<E> {
    fn as_ref(&self) -> &DirtyKeyInfo<E> {
        &self.key_info
    }
}
impl<E: Curve> AsRef<CoreKeyShare<E>> for CoreKeyShare<E> {
    fn as_ref(&self) -> &CoreKeyShare<E> {
        self
    }
}

/// Error indicating that key share is not valid
#[derive(Debug)]
pub struct InvalidCoreShare(InvalidShareReason);

#[derive(Debug)]
enum InvalidShareReason {
    NOverflowsU16,
    TooFewParties,
    PartyIndexOutOfBounds,
    PartySecretShareDoesntMatchPublicShare,
    SharesDontMatchPublicKey,
    ThresholdTooSmall,
    ThresholdTooLarge,
    ILen,
    INotPairwiseDistinct,
}

impl fmt::Display for InvalidCoreShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            InvalidShareReason::NOverflowsU16 => f.write_str("`n` overflows u16"),
            InvalidShareReason::TooFewParties => {
                f.write_str("amount of parties `n` is less than 2: n < 2")
            }
            InvalidShareReason::PartyIndexOutOfBounds => {
                f.write_str("party index `i` out of bounds: i >= n")
            }
            InvalidShareReason::PartySecretShareDoesntMatchPublicShare => f.write_str(
                "party secret share doesn't match its public share: public_shares[i] != G x",
            ),
            InvalidShareReason::SharesDontMatchPublicKey => f.write_str(
                "list of public shares doesn't match shared public key: \
                public_shares.sum() != shared_public_key",
            ),
            InvalidShareReason::ThresholdTooSmall => {
                f.write_str("threshold value is too small (can't be less than 2)")
            }
            InvalidShareReason::ThresholdTooLarge => {
                f.write_str("threshold valud cannot exceed amount of signers")
            }
            InvalidShareReason::ILen => f.write_str("mismatched length of I: I.len() != n"),
            InvalidShareReason::INotPairwiseDistinct => {
                f.write_str("indexes of shares in I are not pairwise distinct")
            }
        }
    }
}
#[cfg(feature = "std")]
impl std::error::Error for InvalidCoreShare {}

impl From<InvalidShareReason> for InvalidCoreShare {
    fn from(err: InvalidShareReason) -> Self {
        Self(err)
    }
}

/// Error related to HD key derivation
#[derive(Debug)]
pub enum HdError<E> {
    /// HD derivation is disabled for the key
    DisabledHd,
    /// Derivation path is not valid
    InvalidPath(E),
}

impl<E> fmt::Display for HdError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DisabledHd => f.write_str("HD derivation is disabled for the key"),
            Self::InvalidPath(_) => f.write_str("derivation path is not valid"),
        }
    }
}
#[cfg(feature = "std")]
impl<E> std::error::Error for HdError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DisabledHd => None,
            Self::InvalidPath(err) => Some(err),
        }
    }
}

impl<T> From<ValidateError<T, InvalidCoreShare>> for InvalidCoreShare {
    fn from(err: ValidateError<T, InvalidCoreShare>) -> Self {
        err.into_error()
    }
}

/// Reconstructs a secret key from set of at least
/// [`min_signers`](CoreKeyShare::min_signers) key shares
///
/// Requires at least [`min_signers`](CoreKeyShare::min_signers) distinct key
/// shares. Returns error if input is invalid.
///
/// Note that, normally, secret key is not supposed to be reconstructed, and key
/// shares should never be at one place. This basically defeats purpose of MPC and
/// creates single point of failure/trust.
#[cfg(feature = "spof")]
pub fn reconstruct_secret_key<E: Curve>(
    key_shares: &[impl AsRef<CoreKeyShare<E>>],
) -> Result<SecretScalar<E>, ReconstructError> {
    if key_shares.is_empty() {
        return Err(ReconstructErrorReason::NoKeyShares.into());
    }

    let t = key_shares[0].as_ref().min_signers();
    let pk = key_shares[0].as_ref().shared_public_key;
    let vss = &key_shares[0].as_ref().vss_setup;
    let X = &key_shares[0].as_ref().public_shares;

    if key_shares[1..].iter().any(|s| {
        t != s.as_ref().min_signers()
            || pk != s.as_ref().shared_public_key
            || *vss != s.as_ref().vss_setup
            || *X != s.as_ref().public_shares
    }) {
        return Err(ReconstructErrorReason::DifferentKeyShares.into());
    }

    if key_shares.len() < usize::from(t) {
        return Err(ReconstructErrorReason::TooFewKeyShares {
            len: key_shares.len(),
            t,
        }
        .into());
    }

    if let Some(VssSetup { I, .. }) = vss {
        let S = key_shares.iter().map(|s| s.as_ref().i).collect::<Vec<_>>();
        let I = crate::utils::subset(&S, I).ok_or(ReconstructErrorReason::Subset)?;
        let lagrange_coefficients =
            (0..).map(|j| generic_ec_zkp::polynomial::lagrange_coefficient(Scalar::zero(), j, &I));
        let mut sk = lagrange_coefficients
            .zip(key_shares)
            .try_fold(Scalar::zero(), |acc, (lambda_j, key_share_j)| {
                Some(acc + lambda_j? * &key_share_j.as_ref().x)
            })
            .ok_or(ReconstructErrorReason::Interpolation)?;
        Ok(SecretScalar::new(&mut sk))
    } else {
        let mut sk = key_shares
            .iter()
            .map(|s| &s.as_ref().x)
            .fold(Scalar::zero(), |acc, x_j| acc + x_j);
        Ok(SecretScalar::new(&mut sk))
    }
}

/// Error indicating that [key reconstruction](reconstruct_secret_key) failed
#[cfg(feature = "spof")]
#[derive(Debug)]
pub struct ReconstructError(ReconstructErrorReason);

#[cfg(feature = "spof")]
#[derive(Debug)]
enum ReconstructErrorReason {
    NoKeyShares,
    DifferentKeyShares,
    TooFewKeyShares { len: usize, t: u16 },
    Subset,
    Interpolation,
}

#[cfg(feature = "spof")]
impl fmt::Display for ReconstructError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("secret key reconstruction error")
    }
}
#[cfg(feature = "spof")]
#[cfg(feature = "std")]
impl std::error::Error for ReconstructError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

#[cfg(feature = "spof")]
impl fmt::Display for ReconstructErrorReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoKeyShares => f.write_str("no key shares provided"),
            Self::DifferentKeyShares => f.write_str(
                "provided key shares doesn't seem to share \
                the same key or belong to the same generation",
            ),
            Self::TooFewKeyShares { len, t } => write!(
                f,
                "expected at least `t={t}` key shares, but {len} \
                key shares were provided"
            ),
            Self::Subset => f.write_str("subset function returned error (seems like a bug)"),
            Self::Interpolation => f.write_str("interpolation failed (seems like a bug)"),
        }
    }
}
#[cfg(feature = "spof")]
#[cfg(feature = "std")]
impl std::error::Error for ReconstructErrorReason {}

#[cfg(feature = "spof")]
impl From<ReconstructErrorReason> for ReconstructError {
    fn from(err: ReconstructErrorReason) -> Self {
        Self(err)
    }
}
