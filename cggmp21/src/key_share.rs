//! Key share

use std::ops;
use std::sync::Arc;

use generic_ec::{Curve, Point, SecretScalar};
use paillier_zk::paillier_encryption_in_range as π_enc;
use paillier_zk::rug::{Complete, Integer};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::security_level::SecurityLevel;

#[doc(inline)]
pub use cggmp21_keygen::key_share::{
    CoreKeyShare as IncompleteKeyShare, DirtyCoreKeyShare as DirtyIncompleteKeyShare, DirtyKeyInfo,
    HdError, InvalidCoreShare as InvalidIncompleteKeyShare, KeyInfo, Valid, Validate,
    ValidateError, ValidateFromParts, VssSetup,
};

/// Key share
///
#[doc = include_str!("../../docs/key_share.md")]
///
#[doc = include_str!("../../docs/validated_key_share_note.md")]
#[doc = include_str!("../../docs/validated_key_share_disclaimer.md")]
pub type KeyShare<E, L = crate::default_choice::SecurityLevel> = Valid<DirtyKeyShare<E, L>>;

/// Auxiliary information
pub type AuxInfo<L = crate::default_choice::SecurityLevel> = Valid<DirtyAuxInfo<L>>;

/// Dirty aux info
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct DirtyAuxInfo<L: SecurityLevel = crate::default_choice::SecurityLevel> {
    /// Secret prime $p$
    pub p: Integer,
    /// Secret prime $q$
    pub q: Integer,
    /// Public auxiliary data of all parties sharing the key
    ///
    /// `parties[i]` corresponds to public auxiliary data of $\ith$ party
    pub parties: Vec<PartyAux>,
    /// Security level that was used to generate aux info
    #[serde(skip)]
    pub security_level: std::marker::PhantomData<L>,
}

/// Dirty (unvalidated) key share
///
#[doc = include_str!("../../docs/key_share.md")]
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct DirtyKeyShare<E: Curve, L: SecurityLevel = crate::default_choice::SecurityLevel> {
    /// Core key share
    pub core: DirtyIncompleteKeyShare<E>,
    /// Auxiliary info
    pub aux: DirtyAuxInfo<L>,
}

/// Party public auxiliary data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct PartyAux {
    /// $N_i = p_i \cdot q_i$
    pub N: Integer,
    /// Ring-Perdesten parameter $s_i$
    pub s: Integer,
    /// Ring-Perdesten parameter $t_i$
    pub t: Integer,
    /// Precomputed table for faster multiexponentiation
    #[serde(default)]
    pub multiexp: Option<Arc<paillier_zk::multiexp::MultiexpTable>>,
    /// Enables faster modular exponentiation when factorization of `N` is known
    ///
    /// Note that it is extreamly sensitive! Leaking `crt` exposes Paillier private key.
    #[serde(default)]
    pub crt: Option<paillier_zk::fast_paillier::utils::CrtExp>,
}

impl<L: SecurityLevel> Validate for DirtyAuxInfo<L> {
    type Error = InvalidKeyShare;

    fn is_valid(&self) -> Result<(), InvalidKeyShare> {
        if self.parties.iter().any(|p| {
            p.s.gcd_ref(&p.N).complete() != *Integer::ONE
                || p.t.gcd_ref(&p.N).complete() != *Integer::ONE
        }) {
            return Err(InvalidKeyShareReason::StGcdN.into());
        }

        if !crate::security_level::validate_secret_paillier_key_size::<L>(&self.p, &self.q) {
            return Err(InvalidKeyShareReason::PaillierSkTooSmall.into());
        }

        if let Some(invalid_aux) = self
            .parties
            .iter()
            .find(|p| !crate::security_level::validate_public_paillier_key_size::<L>(&p.N))
        {
            return Err(InvalidKeyShareReason::PaillierPkTooSmall {
                required: 8 * L::SECURITY_BITS - 1,
                actual: invalid_aux.N.significant_bits(),
            }
            .into());
        }

        Ok(())
    }
}

impl<L: SecurityLevel> DirtyAuxInfo<L> {
    /// Precomputes multiexponentiation tables
    ///
    /// Enables optimization that makes signing and presigning faster. Precomputation may take a while.
    /// It noticebly increases size of aux data both in RAM and on disk (after serialization).
    ///
    /// Returns error if building a multiexp table failed. In this case, the key share stays unmodified.
    /// On success, multiexp tables are saved into the key share (old tables, if present, are overwritten).
    pub fn precompute_multiexp_tables(&mut self) -> Result<(), InvalidKeyShare> {
        let (x_bits, y_bits) = crate::security_level::max_exponents_size::<L>();
        let tables = self
            .parties
            .iter()
            .map(|aux_i| {
                paillier_zk::multiexp::MultiexpTable::build(
                    &aux_i.s,
                    &aux_i.t,
                    x_bits,
                    y_bits,
                    aux_i.N.clone(),
                )
                .map(Arc::new)
            })
            .collect::<Option<Vec<_>>>()
            .ok_or(InvalidKeyShareReason::BuildMultiexpTable)?;
        self.parties
            .iter_mut()
            .zip(tables)
            .for_each(|(aux_i, table_i)| aux_i.multiexp = Some(table_i));
        Ok(())
    }

    /// Returns size of all multiexp tables (in bytes) stored within key share
    pub fn multiexp_tables_size(&self) -> usize {
        self.parties
            .iter()
            .map(|aux_i| {
                aux_i
                    .multiexp
                    .as_ref()
                    .map(|t| t.size_in_bytes())
                    .unwrap_or(0)
            })
            .sum()
    }

    /// Precomputes CRT parameters
    ///
    /// Refer to [`PartyAux::precompute_crt`] for the docs.
    pub fn precompute_crt(&mut self, i: u16) -> Result<(), InvalidKeyShare> {
        let aux_i = self
            .parties
            .get_mut(usize::from(i))
            .ok_or(InvalidKeyShareReason::CrtINotInRange)?;
        aux_i.precompute_crt(&self.p, &self.q)
    }
}

impl PartyAux {
    /// Precompute multiexponentiation table
    ///
    /// Enables optimization that makes signing and presigning faster. Precomputation may take a while.
    /// It noticebly increases size of aux data both in RAM and on disk (after serialization).
    ///
    /// Returns error if building a multiexp table failed. On success, multiexp tables are saved (old
    /// tables, if present, are overwritten).
    ///
    /// Note that provided security level must match the actual security level being used in the
    /// protocol. Otherwise, optimization won't work, and it actually will make the protocol slower.
    pub fn precompute_multiexp_table<L: SecurityLevel>(&mut self) -> Result<(), InvalidKeyShare> {
        let (x_bits, y_bits) = crate::security_level::max_exponents_size::<L>();
        let multiexp = paillier_zk::multiexp::MultiexpTable::build(
            &self.s,
            &self.t,
            x_bits,
            y_bits,
            self.N.clone(),
        )
        .map(Arc::new)
        .ok_or(InvalidKeyShareReason::BuildMultiexpTable)?;
        self.multiexp = Some(multiexp);
        Ok(())
    }

    /// Precomputes CRT parameters
    ///
    /// Enables optimization of modular exponentiation in Zero-Knowledge proofs validation. Precomputation
    /// should be relatively fast. It increases size of key share in RAM and on disk, but not noticeably.
    ///
    /// Takes primes `p`, `q` as input that correspond to signer Paillier secret key.
    ///
    /// Returns error if provided primes do not correspond to a Paillier secret key of the signer, or if
    /// precomputation failed. On success, updates CRT params stored within the structure (old params, if
    /// present, are overwritten)
    ///
    /// Note: CRT parameters contain secret information. Leaking them exposes secret Paillier key. Keep
    /// [`AuxInfo::parties`](DirtyAuxInfo::parties) secret (as well as rest of the key share).
    pub fn precompute_crt(&mut self, p: &Integer, q: &Integer) -> Result<(), InvalidKeyShare> {
        if (p * q).complete() != self.N {
            return Err(InvalidKeyShareReason::CrtInvalidPq.into());
        }
        let crt = paillier_zk::fast_paillier::utils::CrtExp::build_n(p, q)
            .ok_or(InvalidKeyShareReason::BuildCrt)?;
        self.crt = Some(crt);
        Ok(())
    }
}

impl<E: Curve, L: SecurityLevel> Validate for DirtyKeyShare<E, L> {
    type Error = InvalidKeyShare;

    fn is_valid(&self) -> Result<(), InvalidKeyShare> {
        self.core.is_valid()?;
        self.aux.is_valid()?;
        Self::validate_consistency(&self.core, &self.aux)
    }
}

impl<E: Curve, L: SecurityLevel> ValidateFromParts<(IncompleteKeyShare<E>, AuxInfo<L>)>
    for DirtyKeyShare<E, L>
{
    fn validate_parts(
        (core, aux): &(IncompleteKeyShare<E>, AuxInfo<L>),
    ) -> Result<(), Self::Error> {
        Self::validate_consistency(core, aux)
    }

    fn from_parts((core, aux): (IncompleteKeyShare<E>, AuxInfo<L>)) -> Self {
        Self {
            core: core.into_inner(),
            aux: aux.into_inner(),
        }
    }
}

impl<E: Curve, L: SecurityLevel> DirtyKeyShare<E, L> {
    /// Perform consistency check between core and aux
    fn validate_consistency(
        core: &DirtyIncompleteKeyShare<E>,
        aux: &DirtyAuxInfo<L>,
    ) -> Result<(), InvalidKeyShare> {
        if core.public_shares.len() != aux.parties.len() {
            return Err(InvalidKeyShareReason::AuxLen.into());
        }

        let N_i = &aux.parties[usize::from(core.i)].N;
        if *N_i != (&aux.p * &aux.q).complete() {
            return Err(InvalidKeyShareReason::PrimesMul.into());
        }

        Ok(())
    }
}

impl<E: Curve> DirtyKeyShare<E> {
    /// Precomputes CRT parameters
    ///
    /// Enables optimization of modular exponentiation in Zero-Knowledge proofs validation. Precomputation
    /// should be relatively fast. It increases size of key share in RAM and on disk, but not noticeably.
    ///
    /// Returns error if precomputation failed. In this case, the key share stays unmodified. On success,
    /// CRT parameters are saved into the key share (old params, if present, are overwritten)
    ///
    /// Note: CRT parameters contain secret information. Leaking them exposes secret Paillier key. Keep
    /// [`AuxInfo::parties`](DirtyAuxInfo::parties) secret (as well as rest of the key share).
    pub fn precompute_crt(&mut self) -> Result<(), InvalidKeyShare> {
        let i = self.core.i;
        self.aux.precompute_crt(i)
    }
}

impl<E: Curve, L: SecurityLevel> AsRef<DirtyIncompleteKeyShare<E>> for DirtyKeyShare<E, L> {
    fn as_ref(&self) -> &DirtyIncompleteKeyShare<E> {
        &self.core
    }
}
impl<E: Curve, L: SecurityLevel> AsRef<DirtyAuxInfo<L>> for DirtyKeyShare<E, L> {
    fn as_ref(&self) -> &DirtyAuxInfo<L> {
        &self.aux
    }
}

impl<E: Curve, L: SecurityLevel> ops::Deref for DirtyKeyShare<E, L> {
    type Target = DirtyIncompleteKeyShare<E>;

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
pub trait AnyKeyShare<E: Curve>: AsRef<IncompleteKeyShare<E>> + sealed::Sealed {
    /// Returns amount of key co-holders
    fn n(&self) -> u16 {
        #[allow(clippy::expect_used)]
        self.as_ref()
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
        self.as_ref()
            .vss_setup
            .as_ref()
            .map(|s| s.min_signers)
            .unwrap_or_else(|| self.n())
    }

    /// Returns public key shared by signers
    fn shared_public_key(&self) -> Point<E> {
        self.as_ref().shared_public_key
    }
}

impl<E: Curve, L: SecurityLevel> sealed::Sealed for KeyShare<E, L> {}
impl<E: Curve, L: SecurityLevel> AnyKeyShare<E> for KeyShare<E, L> {}
impl<E: Curve> sealed::Sealed for IncompleteKeyShare<E> {}
impl<E: Curve> AnyKeyShare<E> for IncompleteKeyShare<E> {}
impl<T> sealed::Sealed for &T where T: sealed::Sealed {}
impl<E: Curve, T> AnyKeyShare<E> for &T where T: AnyKeyShare<E> {}

/// Reconstructs a secret key from set of at least [`min_signers`](KeyShare::min_signers) key shares
///
/// Requires at least [`min_signers`](KeyShare::min_signers) distinct key shares from the same generation
/// (key refresh produces key shares of the next generation). Accepts both [`KeyShare`] and [`IncompleteKeyShare`].
/// Returns error if input is invalid.
///
/// Note that, normally, secret key is not supposed to be reconstructed, and key
/// shares should never be at one place. This basically defeats purpose of MPC and
/// creates single point of failure/trust.
#[cfg(feature = "spof")]
pub fn reconstruct_secret_key<E: Curve>(
    key_shares: &[impl AnyKeyShare<E>],
) -> Result<SecretScalar<E>, ReconstructError> {
    key_share::reconstruct_secret_key(key_shares)
}

impl From<&PartyAux> for π_enc::Aux {
    fn from(aux: &PartyAux) -> Self {
        Self {
            s: aux.s.clone(),
            t: aux.t.clone(),
            rsa_modulo: aux.N.clone(),
            multiexp: aux.multiexp.clone(),
            crt: aux.crt.clone(),
        }
    }
}

/// Error indicating that key share is not valid
#[derive(Debug, Error)]
#[error(transparent)]
pub struct InvalidKeyShare(#[from] InvalidKeyShareReason);

#[derive(Debug, Error)]
enum InvalidKeyShareReason {
    #[error(transparent)]
    InvalidCoreShare(InvalidIncompleteKeyShare),
    #[error("size of parties auxiliary data list doesn't match `n`: n != parties.len()")]
    AuxLen,
    #[error("N_i != p q")]
    PrimesMul,
    #[error("gcd(s_j, N_j) != 1 or gcd(t_j, N_j) != 1")]
    StGcdN,
    #[error("paillier secret key doesn't match security level (primes are too small)")]
    PaillierSkTooSmall,
    #[error("paillier public key of one of the signers doesn't match security level: required bit length = {required}, actual = {actual}")]
    PaillierPkTooSmall { required: u32, actual: u32 },
    #[error("couldn't build a multiexp table")]
    BuildMultiexpTable,
    #[error("provided index `i` does not correspond to an index of the signer at key generation")]
    CrtINotInRange,
    #[error("provided primes `p`, `q` do not correspond to signer Paillier public key")]
    CrtInvalidPq,
    #[error("couldn't build CRT parameters")]
    BuildCrt,
}

/// Error indicating that [key reconstruction](reconstruct_secret_key) failed
#[cfg(feature = "spof")]
pub use key_share::ReconstructError;

impl From<InvalidIncompleteKeyShare> for InvalidKeyShare {
    fn from(err: InvalidIncompleteKeyShare) -> Self {
        Self(InvalidKeyShareReason::InvalidCoreShare(err))
    }
}

impl<T> From<ValidateError<T, InvalidIncompleteKeyShare>> for InvalidKeyShare {
    fn from(err: ValidateError<T, InvalidIncompleteKeyShare>) -> Self {
        err.into_error().into()
    }
}

impl<T> From<ValidateError<T, InvalidKeyShare>> for InvalidKeyShare {
    fn from(err: cggmp21_keygen::key_share::ValidateError<T, InvalidKeyShare>) -> Self {
        err.into_error()
    }
}
