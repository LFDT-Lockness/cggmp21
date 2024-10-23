#[cfg(all(feature = "serde", feature = "hd-wallet"))]
mod hex_or_bin;

#[cfg(all(feature = "serde", feature = "hd-wallet"))]
pub use hex_or_bin::HexOrBin;

// `hex` dependnecy is only needed when both `serde` and `hd-wallets` features are on.
// However, we can't express that in Cargo.toml, so whenever `serde` feature is on and
// `hd-wallets` is off, unused dependency is introduced.
#[cfg(all(feature = "serde", not(feature = "hd-wallet")))]
use hex as _;

#[cfg(feature = "udigest")]
pub mod encoding {
    pub struct CurveName;
    impl<E: generic_ec::Curve> udigest::DigestAs<generic_ec::serde::CurveName<E>> for CurveName {
        fn digest_as<B: udigest::Buffer>(
            _value: &generic_ec::serde::CurveName<E>,
            encoder: udigest::encoding::EncodeValue<B>,
        ) {
            encoder.encode_leaf_value(E::CURVE_NAME)
        }
    }
}

/// Returns `[list[indexes[0]], list[indexes[1]], ..., list[indexes[n-1]]]`
///
/// Result is `None` if any of `indexes[i]` is out of range of `list`
#[cfg(feature = "spof")]
pub fn subset<T: Clone, I: Into<usize> + Copy>(
    indexes: &[I],
    list: &[T],
) -> Option<alloc::vec::Vec<T>> {
    indexes
        .iter()
        .map(|&i| list.get(i.into()).cloned())
        .collect()
}
