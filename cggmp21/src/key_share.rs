//! Key share

use std::convert::TryFrom;
use std::{fmt, ops};

use generic_ec::serde::{Compact, CurveName};
use generic_ec::{Curve, NonZero, Point, Scalar, SecretScalar};
use paillier_zk::libpaillier::unknown_order::BigNumber;
use paillier_zk::paillier_encryption_in_range as π_enc;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use thiserror::Error;

use crate::security_level::SecurityLevel;
use crate::utils::{lagrange_coefficient, subset};

/// Key share
///
#[doc = include_str!("../docs/key_share.md")]
///
#[doc = include_str!("../docs/validated_key_share_note.md")]
pub type KeyShare<E, L> = Valid<DirtyKeyShare<E, L>>;

/// Incomplete (core) key share
///
#[doc = include_str!("../docs/incomplete_key_share.md")]
///
#[doc = include_str!("../docs/validated_key_share_note.md")]
pub type IncompleteKeyShare<E, L> = Valid<DirtyIncompleteKeyShare<E, L>>;

pub type AuxInfo = Valid<DirtyAuxInfo>;

/// Dirty (unvalidated) incomplete key share
///
#[doc = include_str!("../docs/incomplete_key_share.md")]
#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct DirtyIncompleteKeyShare<E: Curve, L: SecurityLevel> {
    pub curve: CurveName<E>,
    /// Index of local party in key generation protocol
    pub i: u16,
    /// Public key corresponding to shared secret key. Corresponds to _X_ in paper.
    #[serde_as(as = "Compact")]
    pub shared_public_key: Point<E>,
    /// Randomness derived at key generation
    #[serde(with = "hex")]
    pub rid: L::Rid,
    /// Public shares of all parties sharing the key
    ///
    /// `public_shares[i]` corresponds to public share of $\ith$ party.
    /// Corresponds to **X** = $(X_i)_i$ in paper
    #[serde_as(as = "Vec<Compact>")]
    pub public_shares: Vec<Point<E>>,
    /// Verifiable secret sharing setup, present if key was generated using VSS scheme
    pub vss_setup: Option<VssSetup<E>>,
    /// Secret share $x_i$
    #[serde_as(as = "Compact")]
    pub x: SecretScalar<E>,
}

/// Dirty aux info
#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct DirtyAuxInfo {
    /// Secret prime $p$
    pub p: BigNumber,
    /// Secret prime $q$
    pub q: BigNumber,
    /// Public auxiliary data of all parties sharing the key
    ///
    /// `parties[i]` corresponds to public auxiliary data of $\ith$ party
    pub parties: Vec<PartyAux>,
}

/// Dirty (unvalidated) key share
///
#[doc = include_str!("../docs/key_share.md")]
#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct DirtyKeyShare<E: Curve, L: SecurityLevel> {
    /// Core key share
    pub core: DirtyIncompleteKeyShare<E, L>,
    /// Auxiliary info
    pub aux: DirtyAuxInfo,
}

/// Party public auxiliary data
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct PartyAux {
    /// $N_i = p_i \cdot q_i$
    pub N: BigNumber,
    /// Ring-Perdesten parameter $s_i$
    pub s: BigNumber,
    /// Ring-Perdesten parameter $t_i$
    pub t: BigNumber,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound = "")]
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

impl<E: Curve, L: SecurityLevel> DirtyIncompleteKeyShare<E, L> {
    /// Validates a share
    ///
    /// Performs consistency checks against a key share, returns `Ok(())` if share looks OK.
    pub fn validate(&self) -> Result<(), InvalidKeyShare> {
        let n: u16 = self
            .public_shares
            .len()
            .try_into()
            .map_err(|_| InvalidKeyShareReason::NOverflowsU16)?;

        if n < 2 {
            return Err(InvalidKeyShareReason::TooFewParties.into());
        }
        if self.i >= n {
            return Err(InvalidKeyShareReason::PartyIndexOutOfBounds.into());
        }

        let party_public_share = self.public_shares[usize::from(self.i)];
        if party_public_share != Point::generator() * &self.x {
            return Err(InvalidKeyShareReason::PartySecretShareDoesntMatchPublicShare.into());
        }

        match &self.vss_setup {
            Some(vss_setup) => self.validate_vss_key_share(n, vss_setup)?,
            None => self.validate_non_vss_key_share()?,
        }

        Ok(())
    }

    fn validate_vss_key_share(
        &self,
        n: u16,
        vss_setup: &VssSetup<E>,
    ) -> Result<(), InvalidKeyShare> {
        let t = vss_setup.min_signers;

        if !(2 <= t) {
            return Err(InvalidKeyShareReason::ThresholdTooSmall.into());
        }
        if !(t <= n) {
            return Err(InvalidKeyShareReason::ThresholdTooLarge.into());
        }
        if vss_setup.I.len() != usize::from(n) {
            return Err(InvalidKeyShareReason::ILen.into());
        }

        // Now we need to check that public key shares indeed form a public key.
        // We do that in two steps:
        // 1. Take `t` first public key shares, derive a public key and compare
        //    with public key specified in key share
        // 2. Using first `t` public key shares, derive other `n-t` public shares
        //    and compare with the ones specified in the key share

        let first_t_shares = &self.public_shares[0..usize::from(t)];
        let indexes = &vss_setup.I[0..usize::from(t)];
        let interpolation = |x: Scalar<E>| {
            let lagrange_coefficients = (0..t).map(|j| lagrange_coefficient(x, j, indexes));
            lagrange_coefficients
                .zip(first_t_shares)
                .try_fold(Point::zero(), |acc, (lambda_j, X_j)| {
                    Some(acc + lambda_j? * X_j)
                })
                .ok_or(InvalidKeyShareReason::INotPairwiseDistinct)
        };
        let reconstructed_pk = interpolation(Scalar::zero())?;
        if reconstructed_pk != self.shared_public_key {
            return Err(InvalidKeyShareReason::SharesDontMatchPublicKey.into());
        }

        for (&j, public_share_j) in vss_setup.I.iter().zip(&self.public_shares).skip(t.into()) {
            if interpolation(j.into())? != *public_share_j {
                return Err(InvalidKeyShareReason::SharesDontMatchPublicKey.into());
            }
        }

        Ok(())
    }

    fn validate_non_vss_key_share(&self) -> Result<(), InvalidKeyShare> {
        if self.shared_public_key != self.public_shares.iter().sum::<Point<E>>() {
            return Err(InvalidKeyShareReason::SharesDontMatchPublicKey.into());
        }
        Ok(())
    }
}

impl DirtyAuxInfo {
    /// Performs consistency checks against aux info, returns a valid share
    /// you can use with other algorithms
    pub fn validate(&self) -> Result<(), InvalidKeyShare> {
        if self
            .parties
            .iter()
            .any(|p| p.s.gcd(&p.N) != BigNumber::one() || p.t.gcd(&p.N) != BigNumber::one())
        {
            return Err(InvalidKeyShareReason::StGcdN.into());
        }

        Ok(())
    }
}

impl<E: Curve, L: SecurityLevel> DirtyKeyShare<E, L> {
    pub fn make(core: IncompleteKeyShare<E, L>, aux: AuxInfo) -> Result<Self, InvalidKeyShare> {
        let r = Self {
            core: core.0,
            aux: aux.0,
        };
        r.validate_consistency()?;
        Ok(r)
    }

    /// Perform consistency check between core and aux
    fn validate_consistency(&self) -> Result<(), InvalidKeyShare> {
        if self.core.public_shares.len() != self.aux.parties.len() {
            return Err(InvalidKeyShareReason::AuxLen.into());
        }

        let N_i = &self.aux.parties[usize::from(self.core.i)].N;
        if *N_i != &self.aux.p * &self.aux.q {
            return Err(InvalidKeyShareReason::PrimesMul.into());
        }

        Ok(())
    }

    /// Validates a share
    ///
    /// Performs consistency checks against a key share, returns `Ok(())` if share looks OK.
    pub fn validate(&self) -> Result<(), InvalidKeyShare> {
        self.core.validate()?;
        self.aux.validate()?;
        self.validate_consistency()
    }
}

impl<E: Curve, L: SecurityLevel> AsRef<DirtyIncompleteKeyShare<E, L>> for DirtyKeyShare<E, L> {
    fn as_ref(&self) -> &DirtyIncompleteKeyShare<E, L> {
        &self.core
    }
}

impl<E: Curve, L: SecurityLevel> AsRef<DirtyIncompleteKeyShare<E, L>>
    for DirtyIncompleteKeyShare<E, L>
{
    fn as_ref(&self) -> &DirtyIncompleteKeyShare<E, L> {
        self
    }
}

impl<E: Curve, L: SecurityLevel> ops::Deref for DirtyKeyShare<E, L> {
    type Target = DirtyIncompleteKeyShare<E, L>;

    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

mod sealed {
    pub trait Sealed {}
}

/// Any (validated) key share
///
/// Implemented for both [KeyShare] and [IncompleteKeyShare]. Used in methods
/// that accept both types of key shares, like [reconstruct_secret_key].
pub trait AnyKeyShare<E: Curve, L: SecurityLevel>: sealed::Sealed {
    fn core(&self) -> &DirtyIncompleteKeyShare<E, L>;

    /// Returns amount of key co-holders
    fn n(&self) -> u16 {
        #[allow(clippy::expect_used)]
        self.core()
            .public_shares
            .len()
            .try_into()
            .expect("valid key share is guaranteed to have amount of signers fitting into u16")
    }

    /// Returns threshold
    ///
    /// Threshold is an amount of signers required to cooperate in order to sign a message
    /// and/or generate presignature
    fn min_signers(&self) -> u16 {
        self.core()
            .vss_setup
            .as_ref()
            .map(|s| s.min_signers)
            .unwrap_or_else(|| self.n())
    }
}

impl<E: Curve, L: SecurityLevel> sealed::Sealed for KeyShare<E, L> {}
impl<E: Curve, L: SecurityLevel> AnyKeyShare<E, L> for KeyShare<E, L> {
    fn core(&self) -> &DirtyIncompleteKeyShare<E, L> {
        &self.core
    }
}
impl<E: Curve, L: SecurityLevel> sealed::Sealed for IncompleteKeyShare<E, L> {}
impl<E: Curve, L: SecurityLevel> AnyKeyShare<E, L> for IncompleteKeyShare<E, L> {
    fn core(&self) -> &DirtyIncompleteKeyShare<E, L> {
        self
    }
}
impl<T> sealed::Sealed for &T where T: sealed::Sealed {}
impl<E: Curve, L: SecurityLevel, T> AnyKeyShare<E, L> for &T
where
    T: AnyKeyShare<E, L>,
{
    fn core(&self) -> &DirtyIncompleteKeyShare<E, L> {
        <T as AnyKeyShare<E, L>>::core(self)
    }
}

impl<E: Curve, L: SecurityLevel> AsRef<IncompleteKeyShare<E, L>> for IncompleteKeyShare<E, L> {
    fn as_ref(&self) -> &IncompleteKeyShare<E, L> {
        self
    }
}

/// Reconstructs a secret key from set of at least [`min_signers`](KeyShare::min_signers) key shares
///
/// Requires at least [`min_signers`](KeyShare::min_signers) distinct key shares from the same generation
/// (key refresh produces key shares of the next generation). Accepts both [`KeyShare`] and [`IncompleteKeyShare`].
/// Returns error if input is invalid.
///
/// Note that, normally, secret key is not supposed to be reconstructed, and key
/// shares should never be at one place. This basically defeats purpose of MPC and
/// creates single point of failure/trust.
pub fn reconstruct_secret_key<E: Curve, L: SecurityLevel>(
    key_shares: &[impl AnyKeyShare<E, L>],
) -> Result<SecretScalar<E>, ReconstructError> {
    if key_shares.is_empty() {
        return Err(ReconstructErrorReason::NoKeyShares.into());
    }

    let t = key_shares[0].min_signers();
    let pk = key_shares[0].core().shared_public_key;
    let vss = &key_shares[0].core().vss_setup;
    let X = &key_shares[0].core().public_shares;

    if key_shares[1..].iter().any(|s| {
        t != s.min_signers()
            || pk != s.core().shared_public_key
            || *vss != s.core().vss_setup
            || *X != s.core().public_shares
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
        let S = key_shares.iter().map(|s| s.core().i).collect::<Vec<_>>();
        let I = subset(&S, I).ok_or(ReconstructErrorReason::Subset)?;
        let lagrange_coefficients = (0..t).map(|j| lagrange_coefficient(Scalar::zero(), j, &I));
        let mut sk = lagrange_coefficients
            .zip(key_shares)
            .try_fold(Scalar::zero(), |acc, (lambda_j, key_share_j)| {
                Some(acc + lambda_j? * &key_share_j.core().x)
            })
            .ok_or(ReconstructErrorReason::Interpolation)?;
        Ok(SecretScalar::new(&mut sk))
    } else {
        let mut sk = key_shares
            .iter()
            .map(|s| &s.core().x)
            .fold(Scalar::zero(), |acc, x_j| acc + x_j);
        Ok(SecretScalar::new(&mut sk))
    }
}

impl From<&PartyAux> for π_enc::Aux {
    fn from(aux: &PartyAux) -> Self {
        Self {
            s: aux.s.clone(),
            t: aux.t.clone(),
            rsa_modulo: aux.N.clone(),
        }
    }
}

/// Valid key share
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(into = "T", try_from = "T")]
#[serde(bound(
    serialize = "T: Clone + Serialize + From<Self>",
    deserialize = "T: Deserialize<'de>, Self: TryFrom<T>, <Self as TryFrom<T>>::Error: fmt::Display"
))]
pub struct Valid<T>(T);

impl<T> Valid<T> {
    /// Returns a dirty key share
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> AsRef<T> for Valid<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<E: Curve, L: SecurityLevel> TryFrom<DirtyIncompleteKeyShare<E, L>>
    for IncompleteKeyShare<E, L>
{
    type Error = InvalidKeyShare;
    fn try_from(key_share: DirtyIncompleteKeyShare<E, L>) -> Result<Self, Self::Error> {
        key_share.validate()?;
        Ok(Self(key_share))
    }
}

impl<E: Curve, L: SecurityLevel> TryFrom<DirtyKeyShare<E, L>> for KeyShare<E, L> {
    type Error = InvalidKeyShare;
    fn try_from(key_share: DirtyKeyShare<E, L>) -> Result<Self, Self::Error> {
        key_share.validate()?;
        Ok(Self(key_share))
    }
}

impl<E: Curve, L: SecurityLevel> From<IncompleteKeyShare<E, L>> for DirtyIncompleteKeyShare<E, L> {
    fn from(x: IncompleteKeyShare<E, L>) -> Self {
        x.0
    }
}

impl<E: Curve, L: SecurityLevel> From<KeyShare<E, L>> for DirtyKeyShare<E, L> {
    fn from(x: KeyShare<E, L>) -> Self {
        x.0
    }
}

impl<T> ops::Deref for Valid<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Error indicating that key share is not valid
#[derive(Debug, Error)]
#[error(transparent)]
pub struct InvalidKeyShare(#[from] InvalidKeyShareReason);

#[derive(Debug, Error)]
enum InvalidKeyShareReason {
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
    #[error("size of parties auxiliary data list doesn't match `n`: n != parties.len()")]
    AuxLen,
    #[error("N_i != p q")]
    PrimesMul,
    #[error("gcd(s_j, N_j) != 1 or gcd(t_j, N_j) != 1")]
    StGcdN,
    #[error("threshold value is too small (can't be less than 2)")]
    ThresholdTooSmall,
    #[error("threshold valud cannot exceed amount of signers")]
    ThresholdTooLarge,
    #[error("mismatched length of I: I.len() != n")]
    ILen,
    #[error("indexes of shares in I are not pairwise distinct")]
    INotPairwiseDistinct,
}

#[derive(Debug, Error)]
#[error("secret key reconstruction error")]
pub struct ReconstructError(
    #[source]
    #[from]
    ReconstructErrorReason,
);

#[derive(Debug, Error)]
enum ReconstructErrorReason {
    #[error("no key shares provided")]
    NoKeyShares,
    #[error(
        "provided key shares doesn't seem to share the same key or belong to the same generation"
    )]
    DifferentKeyShares,
    #[error("expected at least `t={t}` key shares, but {len} key shares were provided")]
    TooFewKeyShares { len: usize, t: u16 },
    #[error("subset function returned error (seems like a bug)")]
    Subset,
    #[error("interpolation failed (seems like a bug)")]
    Interpolation,
}
