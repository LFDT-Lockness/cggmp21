#![allow(non_snake_case, mixed_script_confusables, uncommon_codepoints)]
#![forbid(clippy::disallowed_methods, unused_crate_dependencies)]

pub use {
    paillier_zk, paillier_zk::libpaillier, paillier_zk::libpaillier::unknown_order, round_based,
};

use generic_ec::{coords::HasAffineX, hash_to_curve::FromHash, Curve, Point, Scalar};
use key_share::{IncompleteKeyShare, KeyShare, Valid};
use security_level::SecurityLevel;
use sha2::Sha256;
use signing::SigningBuilder;

mod execution_id;
pub mod key_refresh;
pub mod key_share;
pub mod keygen;
pub mod progress;
pub mod security_level;
pub mod signing;
pub mod supported_curves;
pub mod trusted_dealer;
mod utils;
pub mod zk;

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

/// Protocol for finalizing the keygen by generating aux info and performing
/// initial key refresh.
pub fn aux_info_gen<E, L>(
    core_share: &Valid<IncompleteKeyShare<E, L>>,
) -> key_refresh::KeyRefreshBuilder<E, L, Sha256>
where
    E: Curve,
    L: SecurityLevel,
{
    key_refresh::KeyRefreshBuilder::new(core_share)
}

/// Protocol for performing key refresh
pub fn key_refresh<E, L>(
    key_share: &Valid<KeyShare<E, L>>,
) -> key_refresh::KeyRefreshBuilder<E, L, Sha256>
where
    E: Curve,
    L: SecurityLevel,
{
    key_refresh::KeyRefreshBuilder::new_refresh(key_share)
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
