#![doc = include_str!("../README.md")]
#![deny(clippy::disallowed_methods)]
#![cfg_attr(
    not(test),
    deny(clippy::panic, clippy::unwrap_used, clippy::expect_used)
)]

use thiserror::Error;

mod common;
pub mod dlog_with_el_gamal_commitment;
pub mod multiexp;
pub mod no_small_factor;
pub mod paillier_affine_operation_in_range;
pub mod paillier_blum_modulus;
pub mod paillier_encryption_in_range;
pub mod paillier_encryption_in_range_with_el_gamal;

#[cfg(test)]
mod curve;

#[cfg(all(doctest, not(feature = "__internal_doctest")))]
compile_error!("doctest require that `__internal_doctest` feature is turned on");

#[cfg(feature = "__internal_doctest")]
#[doc(hidden)]
pub mod _doctest;

use common::InvalidProofReason;
pub use common::{BadExponent, IntegerExt, InvalidProof, PaillierError};
pub use fast_paillier::{self, backend};

/// Library general error type
#[derive(Debug, Error)]
#[error(transparent)]
pub struct Error(#[from] ErrorReason);

#[derive(Debug, Error)]
enum ErrorReason {
    #[error("couldn't evaluate modpow")]
    ModPow(
        #[source]
        #[from]
        BadExponent,
    ),
    #[error("couldn't find residue")]
    FindResidue,
    #[error("couldn't encrypt a message")]
    Encryption,
    #[error("can't find multiplicative inverse")]
    Invert,
    #[error("paillier error")]
    Paillier(#[source] fast_paillier::Error),
    #[error("bug: vec has unexpected length")]
    Length,
}

impl From<BadExponent> for Error {
    fn from(err: BadExponent) -> Self {
        Error(ErrorReason::ModPow(err))
    }
}

impl From<PaillierError> for Error {
    fn from(_err: PaillierError) -> Self {
        Error(ErrorReason::Encryption)
    }
}

impl From<fast_paillier::Error> for Error {
    fn from(err: fast_paillier::Error) -> Self {
        Self(ErrorReason::Paillier(err))
    }
}
