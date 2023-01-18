//! Curves supported by this crate
//!
//! This crate re-exports curves that are checked to work correctly with our CGGMP implementation.
//! Generally, this crate can work with any curve as long as it satisfies constraints (check out
//! [`SigningBuilder`](crate::signing::SigningBuilder) generic constraints), but it might have
//! unexpected consequences: for instance, [default security level](crate::security_level::ReasonablySecure)
//! might not be compatible with another curve, which might result into unexpected runtime error or
//! reduced security of the protocol.

#[cfg(feature = "curve-secp256k1")]
pub use generic_ec::curves::Secp256k1;
#[cfg(feature = "curve-secp256r1")]
pub use generic_ec::curves::Secp256r1;

pub use generic_ec::Curve;

#[cfg(test)]
#[allow(dead_code)]
mod check_compatibility {
    use generic_ec::{
        coords::AlwaysHasAffineX, hash_to_curve::FromHash, Curve, NonZero, Point, Scalar,
    };

    fn curve_is_compatible<E: Curve>()
    where
        Scalar<E>: FromHash,
        NonZero<Point<E>>: AlwaysHasAffineX<E>,
    {
    }

    fn supported_curves_are_compatible() {
        #[cfg(feature = "curve-secp256k1")]
        curve_is_compatible::<super::Secp256k1>();
        #[cfg(feature = "curve-secp256r1")]
        curve_is_compatible::<super::Secp256r1>();
    }
}
