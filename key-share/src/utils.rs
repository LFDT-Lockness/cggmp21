#[cfg(all(feature = "serde", feature = "hd-wallets"))]
mod hex_or_bin;

#[cfg(all(feature = "serde", feature = "hd-wallets"))]
pub use hex_or_bin::HexOrBin;

// `hex` dependnecy is only needed when both `serde` and `hd-wallets` features are on.
// However, we can't express that in Cargo.toml, so whenever `serde` feature is on and
// `hd-wallets` is off, unused dependency is introduced.
#[cfg(all(feature = "serde", not(feature = "hd-wallets")))]
use hex as _;

#[cfg(feature = "udigest")]
pub mod encoding {
    pub fn curve_name<B: udigest::Buffer, E: generic_ec::Curve>(
        _value: &generic_ec::serde::CurveName<E>,
        encoder: udigest::encoding::EncodeValue<B>,
    ) {
        encoder.encode_leaf_value(E::CURVE_NAME)
    }

    #[cfg(feature = "hd-wallets")]
    pub fn maybe_bytes<B: udigest::Buffer>(
        m: &Option<impl AsRef<[u8]>>,
        encoder: udigest::encoding::EncodeValue<B>,
    ) {
        use udigest::Digestable;
        m.as_ref().map(udigest::Bytes).unambiguously_encode(encoder)
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
