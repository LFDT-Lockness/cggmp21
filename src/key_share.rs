//! Key share

use std::convert::TryFrom;
use std::{fmt, ops};

use generic_ec::serde::{Compact, CurveName};
use generic_ec::{Curve, Point, SecretScalar};
use paillier_zk::libpaillier::unknown_order::BigNumber;
use paillier_zk::paillier_encryption_in_range as π_enc;
use serde::{de, Deserialize, Serialize};
use serde_with::serde_as;
use thiserror::Error;

use crate::security_level::SecurityLevel;

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
    /// Public key corresponding to shared secret key
    #[serde_as(as = "Compact")]
    pub shared_public_key: Point<E>,
    /// Randomness derived at key generation
    #[serde(with = "hex")]
    pub rid: L::Rid,
    /// Public shares of all parties sharing the key
    ///
    /// `public_shares[i]` corresponds to public share of $\ith$ party
    #[serde_as(as = "Vec<Compact>")]
    pub public_shares: Vec<Point<E>>,
    /// Secret share $x_i$
    #[serde_as(as = "Compact")]
    pub x: SecretScalar<E>,
}

/// Key share
///
/// Key share is obtained as output of [key refresh protocol](crate::refresh).
/// It contains a [core share](IncompleteKeyShare) and auxiliary data required to
/// carry out signing.
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
    /// El-Gamal private key
    #[serde_as(as = "Compact")]
    pub y: SecretScalar<E>,
    /// Public auxiliary data of all parties sharing the key
    ///
    /// `parties[i]` corresponds to public auxiliary data of $\ith$ party
    pub parties: Vec<PartyAux<E>>,
}

/// Party public auxiliary data
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct PartyAux<E: Curve> {
    /// $N_i = p_i \cdot q_i$
    pub N: BigNumber,
    /// Ring-Perdesten parameter $s_i$
    pub s: BigNumber,
    /// Ring-Perdesten parameter $t_i$
    pub t: BigNumber,
    /// El-Gamal public key
    #[serde_as(as = "Compact")]
    pub Y: Point<E>,
}

impl<E: Curve, L: SecurityLevel> IncompleteKeyShare<E, L> {
    /// Validates a share
    ///
    /// Performs consistency checks against a key share, returns `Ok(())` if share looks OK.
    pub fn validate(&self) -> Result<(), InvalidKeyShare> {
        let n: u16 = self
            .public_shares
            .len()
            .try_into()
            .or(Err(ErrorReason::PartiesNumberOverflowU16))?;
        if self.i >= n {
            return Err(ErrorReason::PartyIndexOutOfBounds.into());
        }

        let party_public_share = self.public_shares[usize::from(self.i)];
        if party_public_share != Point::generator() * &self.x {
            return Err(ErrorReason::PartySecretShareDoesntMatchPublicShare.into());
        }

        if self.shared_public_key != self.public_shares.iter().sum::<Point<E>>() {
            return Err(ErrorReason::SharesDontMatchPublicKey.into());
        }
        Ok(())
    }
}

impl<E: Curve, L: SecurityLevel> KeyShare<E, L> {
    /// Validates a share
    ///
    /// Performs consistency checks against a key share, returns `Ok(())` if share looks OK.
    pub fn validate(&self) -> Result<(), InvalidKeyShare> {
        self.core.validate()?;

        if self.core.public_shares.len() != self.parties.len() {
            return Err(ErrorReason::AuxWrongLength.into());
        }

        let el_gamal_public = self.parties[usize::from(self.core.i)].Y;
        if el_gamal_public != Point::generator() * &self.y {
            return Err(ErrorReason::ElGamalKey.into());
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
}

impl<E: Curve> From<&PartyAux<E>> for π_enc::Aux {
    fn from(aux: &PartyAux<E>) -> Self {
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
    #[error("number of parties `n` overflow u16::MAX (implying `n = public_shares.len()`)")]
    PartiesNumberOverflowU16,
    #[error("party index `i` out of bounds: i >= n")]
    PartyIndexOutOfBounds,
    #[error("party secret share doesn't match its public share: public_shares[i] != G x")]
    PartySecretShareDoesntMatchPublicShare,
    #[error("list of public shares doesn't match shared public key: public_shares.sum() != shared_public_key")]
    SharesDontMatchPublicKey,
    #[error("size of parties auxiliary data list doesn't match `n`: n != parties.len()")]
    AuxWrongLength,
    #[error("party El-Gamal secret key doesn't match public key: y_i G != Y_i")]
    ElGamalKey,
    #[error("N_i != p q")]
    PrimesMul,
    #[error("gcd(s_j, N_j) != 1 or gcd(t_j, N_j) != 1")]
    StGcdN,
}
