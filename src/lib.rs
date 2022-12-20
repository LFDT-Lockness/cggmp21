#![allow(non_snake_case, mixed_script_confusables)]

pub use round_based;

mod execution_id;
pub mod key_share;
pub mod keygen;
pub mod security_level;
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
    E: generic_ec::Curve,
    generic_ec::Scalar<E>: generic_ec::hash_to_curve::FromHash,
{
    keygen::KeygenBuilder::new(i, n)
}
