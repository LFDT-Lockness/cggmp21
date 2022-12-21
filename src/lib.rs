#![allow(non_snake_case, mixed_script_confusables, uncommon_codepoints)]

use generic_ec::{coords::HasAffineX, hash_to_curve::FromHash, Curve, Point, Scalar};
use key_share::{KeyShare, Valid};
pub use round_based;
use security_level::SecurityLevel;
use sha2::Sha256;
use signing::SigningBuilder;

mod execution_id;
pub mod key_share;
pub mod keygen;
pub mod security_level;
pub mod signing;
pub mod trusted_dealer;
mod utils;

pub use self::execution_id::ExecutionId;

/// Distributed key generation protocol
///
/// Instantiates [KeygenBuilder] with [ReasonablySecure] security level
/// and sha2-256 digest.
///
/// [KeygenBuilder]: keygen::KeygenBuilder
/// [ReasonablySecure]: security_level::ReasonablySecure
pub fn keygen<E>(
    i: u16,
    n: u16,
) -> keygen::KeygenBuilder<E, security_level::ReasonablySecure, sha2::Sha256>
where
    E: Curve,
    Scalar<E>: FromHash,
{
    keygen::KeygenBuilder::new(i, n)
}

pub fn signing<E, L>(key_share: &Valid<KeyShare<E, L>>) -> SigningBuilder<E, L, Sha256>
where
    E: Curve,
    L: SecurityLevel,
    Point<E>: HasAffineX<E>,
    Scalar<E>: FromHash,
{
    SigningBuilder::new(key_share)
}
