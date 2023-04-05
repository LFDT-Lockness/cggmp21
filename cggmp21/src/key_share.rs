//! Key share

use std::convert::TryFrom;
use std::{fmt, ops};

use generic_ec::serde::{Compact, CurveName};
use generic_ec::{Curve, NonZero, Point, Scalar, SecretScalar};
use paillier_zk::libpaillier::unknown_order::BigNumber;
use paillier_zk::paillier_encryption_in_range as π_enc;
use serde::{de, Deserialize, Serialize};
use serde_with::serde_as;
use thiserror::Error;

use crate::security_level::SecurityLevel;
use crate::utils::{lagrange_coefficient, subset};

/// Core key share
///
/// Core key share is obtained as an output of [key generation protocol](crate::keygen()).
/// It can not be used in signing protocol as it lacks of required auxiliary information.
/// You need to carry out [key refresh protocol](crate::refresh) to obtain "completed"
/// [KeyShare].
#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct IncompleteKeyShare<E: Curve, L: SecurityLevel> {
    pub curve: CurveName<E>,
    /// Index of local party in key generation protocol
    pub i: u16,
    /// Amount of key co-holders
    pub n: u16,
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

/// Key share
///
/// Key share is obtained as output of [key refresh protocol](crate::refresh).
/// It contains a [core share](IncompleteKeyShare) and auxiliary data required to
/// carry out signing.
///
/// Compared to the paper, we removed the El-Gamal private key as it's not used
/// for 3-round presigning, which is the only one we provide
#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct KeyShare<E: Curve, L: SecurityLevel> {
    /// Core key share
    pub core: IncompleteKeyShare<E, L>,
    /// Secret prime $p$
    pub p: BigNumber,
    /// Secret prime $q$
    pub q: BigNumber,
    /// Public auxiliary data of all parties sharing the key
    ///
    /// `parties[i]` corresponds to public auxiliary data of $\ith$ party
    pub parties: Vec<PartyAux>,
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

impl<E: Curve, L: SecurityLevel> IncompleteKeyShare<E, L> {
    /// Validates a share
    ///
    /// Performs consistency checks against a key share, returns `Ok(())` if share looks OK.
    pub fn validate(&self) -> Result<(), InvalidKeyShare> {
        if self.n < 2 {
            return Err(ErrorReason::TooFewParties.into());
        }
        if self.i >= self.n {
            return Err(ErrorReason::PartyIndexOutOfBounds.into());
        }

        if self.public_shares.len() != usize::from(self.n) {
            return Err(ErrorReason::PublicSharesLen.into());
        }

        let party_public_share = self.public_shares[usize::from(self.i)];
        if party_public_share != Point::generator() * &self.x {
            return Err(ErrorReason::PartySecretShareDoesntMatchPublicShare.into());
        }

        match &self.vss_setup {
            Some(vss_setup) => self.validate_vss_key_share(vss_setup)?,
            None => self.validate_non_vss_key_share()?,
        }

        Ok(())
    }

    fn validate_vss_key_share(&self, vss_setup: &VssSetup<E>) -> Result<(), InvalidKeyShare> {
        let t = vss_setup.min_signers;

        if !(2 <= t) {
            return Err(ErrorReason::ThresholdTooSmall.into());
        }
        if !(t <= self.n) {
            return Err(ErrorReason::ThresholdTooLarge.into());
        }
        if vss_setup.I.len() != usize::from(self.n) {
            return Err(ErrorReason::ILen.into());
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
                .ok_or(ErrorReason::INotPairwiseDistinct)
        };
        let reconstructed_pk = interpolation(Scalar::zero())?;
        if reconstructed_pk != self.shared_public_key {
            return Err(ErrorReason::SharesDontMatchPublicKey.into());
        }

        for (&j, public_share_j) in vss_setup.I.iter().zip(&self.public_shares).skip(t.into()) {
            if interpolation(j.into())? != *public_share_j {
                return Err(ErrorReason::SharesDontMatchPublicKey.into());
            }
        }

        Ok(())
    }

    fn validate_non_vss_key_share(&self) -> Result<(), InvalidKeyShare> {
        if self.shared_public_key != self.public_shares.iter().sum::<Point<E>>() {
            return Err(ErrorReason::SharesDontMatchPublicKey.into());
        }
        Ok(())
    }

    /// Returns threshold
    ///
    /// Threshold is an amount of signers required to cooperate in order to sign a message
    /// and/or generate presignature
    pub fn min_signers(&self) -> u16 {
        self.vss_setup
            .as_ref()
            .map(|s| s.min_signers)
            .unwrap_or(self.n)
    }

    /// Reconstructs a secret key from set of `t` key shares
    ///
    /// Requires exactly `t` distinct key shares from the same generation (key refresh
    /// produces key shares of the next generation). Returns error if input is invalid.
    ///
    /// Note that, normally, secret key is not supposed to be reconstructed, and key
    /// shares should never be at one place. This basically defeats purpose of MPC and
    /// creates single point of failure/trust.
    pub fn reconstruct_secret_key(key_shares: &[Self]) -> Result<SecretScalar<E>, InvalidKeyShare> {
        if key_shares.is_empty() {
            return Err(ReconstructError::NoKeyShares.into());
        }

        let t = key_shares[0].min_signers();
        let pk = key_shares[0].shared_public_key;
        let vss = &key_shares[0].vss_setup;
        let X = &key_shares[0].public_shares;

        if key_shares[1..].iter().any(|s| {
            t != s.min_signers()
                || pk != s.shared_public_key
                || *vss != s.vss_setup
                || *X != s.public_shares
        }) {
            return Err(ReconstructError::DifferentKeyShares.into());
        }

        if key_shares.len() != usize::from(t) {
            return Err(ReconstructError::KeySharesLen {
                len: key_shares.len(),
                t,
            }
            .into());
        }

        if let Some(VssSetup { I, .. }) = vss {
            let S = key_shares.iter().map(|s| s.i).collect::<Vec<_>>();
            let I = subset(&S, &I).ok_or(ReconstructError::Subset)?;
            let lagrange_coefficients = (0..t).map(|j| lagrange_coefficient(Scalar::zero(), j, &I));
            let mut sk = lagrange_coefficients
                .zip(key_shares)
                .try_fold(Scalar::zero(), |acc, (lambda_j, key_share_j)| {
                    Some(acc + lambda_j? * &key_share_j.x)
                })
                .ok_or(ReconstructError::Interpolation)?;
            Ok(SecretScalar::new(&mut sk))
        } else {
            let mut sk = key_shares
                .iter()
                .map(|s| &s.x)
                .fold(Scalar::zero(), |acc, x_j| acc + x_j);
            Ok(SecretScalar::new(&mut sk))
        }
    }
}

impl<E: Curve, L: SecurityLevel> KeyShare<E, L> {
    /// Validates a share
    ///
    /// Performs consistency checks against a key share, returns `Ok(())` if share looks OK.
    pub fn validate(&self) -> Result<(), InvalidKeyShare> {
        self.core.validate()?;

        if self.core.public_shares.len() != self.parties.len() {
            return Err(ErrorReason::AuxLen.into());
        }

        let N_i = &self.parties[usize::from(self.core.i)].N;
        if *N_i != &self.p * &self.q {
            return Err(ErrorReason::PrimesMul.into());
        }

        if self
            .parties
            .iter()
            .any(|p| p.s.gcd(&p.N) != BigNumber::one() || p.t.gcd(&p.N) != BigNumber::one())
        {
            return Err(ErrorReason::StGcdN.into());
        }

        Ok(())
    }

    /// Returns threshold
    ///
    /// Threshold is an amount of signers required to cooperate in order to sign a message
    /// and/or generate presignature
    pub fn min_signers(&self) -> u16 {
        self.core.min_signers()
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
#[derive(Debug, Clone, Serialize)]
#[serde(transparent)]
pub struct Valid<T>(T);

impl<E: Curve, L: SecurityLevel> TryFrom<IncompleteKeyShare<E, L>>
    for Valid<IncompleteKeyShare<E, L>>
{
    type Error = InvalidKeyShare;
    fn try_from(key_share: IncompleteKeyShare<E, L>) -> Result<Self, Self::Error> {
        key_share.validate()?;
        Ok(Self(key_share))
    }
}

impl<E: Curve, L: SecurityLevel> TryFrom<KeyShare<E, L>> for Valid<KeyShare<E, L>> {
    type Error = InvalidKeyShare;
    fn try_from(key_share: KeyShare<E, L>) -> Result<Self, Self::Error> {
        key_share.validate()?;
        Ok(Self(key_share))
    }
}

impl<E: Curve, L: SecurityLevel> From<Valid<IncompleteKeyShare<E, L>>>
    for IncompleteKeyShare<E, L>
{
    fn from(x: Valid<IncompleteKeyShare<E, L>>) -> Self {
        x.0
    }
}

impl<E: Curve, L: SecurityLevel> From<Valid<KeyShare<E, L>>> for KeyShare<E, L> {
    fn from(x: Valid<KeyShare<E, L>>) -> Self {
        x.0
    }
}

impl<T> ops::Deref for Valid<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'de, T> Deserialize<'de> for Valid<T>
where
    T: Deserialize<'de>,
    Valid<T>: TryFrom<T>,
    <Valid<T> as TryFrom<T>>::Error: fmt::Display,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = T::deserialize(deserializer)?;
        Valid::try_from(value).map_err(<D::Error as de::Error>::custom)
    }
}

/// Error indicating that key share is not valid
#[derive(Debug, Error)]
#[error(transparent)]
pub struct InvalidKeyShare(#[from] ErrorReason);

#[derive(Debug, Error)]
enum ErrorReason {
    #[error("amount of parties `n` is less than 2: n < 2")]
    TooFewParties,
    #[error("party index `i` out of bounds: i >= n")]
    PartyIndexOutOfBounds,
    #[error("party secret share doesn't match its public share: public_shares[i] != G x")]
    PartySecretShareDoesntMatchPublicShare,
    #[error("list of public shares doesn't match shared public key: public_shares.sum() != shared_public_key")]
    SharesDontMatchPublicKey,
    #[error("amount of parties public key shares doesn't match `n`: n != public_shares.len()")]
    PublicSharesLen,
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
    #[error("reconstructing key shares resulted into error")]
    Reconstruct(ReconstructError),
}

#[derive(Debug, Error)]
enum ReconstructError {
    #[error("no key shares provided")]
    NoKeyShares,
    #[error(
        "provided key shares doesn't seem to share the same key or belong to the same generation"
    )]
    DifferentKeyShares,
    #[error("expected exactly `t={t}` key shares, but {len} key shares were provided")]
    KeySharesLen { len: usize, t: u16 },
    #[error("subset function returned error (seems like a bug)")]
    Subset,
    #[error("interpolation failed (seems like a bug)")]
    Interpolation,
}

impl From<ReconstructError> for InvalidKeyShare {
    fn from(err: ReconstructError) -> Self {
        InvalidKeyShare(ErrorReason::Reconstruct(err))
    }
}
