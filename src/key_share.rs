use generic_ec::{Curve, Point, SecretScalar};
use libpaillier::unknown_order::BigNumber;
use thiserror::Error;

use crate::security_level::SecurityLevel;

#[derive(Clone)]
pub struct IncompleteKeyShare<E: Curve, L: SecurityLevel> {
    pub i: u16,
    pub shared_public_key: Point<E>,
    pub rid: L::Rid,
    pub public_shares: Vec<Point<E>>,
    pub x: SecretScalar<E>,
}

#[derive(Clone)]
pub struct KeyShare<E: Curve, L: SecurityLevel> {
    pub core: IncompleteKeyShare<E, L>,
    pub p: BigNumber,
    pub q: BigNumber,
    pub y: SecretScalar<E>,
    pub parties: Vec<PartyAux<E>>,
}

#[derive(Debug, Clone)]
pub struct PartyAux<E: Curve> {
    pub N: BigNumber,
    pub s: BigNumber,
    pub t: BigNumber,
    pub Y: Point<E>,
}

impl<E: Curve, L: SecurityLevel> IncompleteKeyShare<E, L> {
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
