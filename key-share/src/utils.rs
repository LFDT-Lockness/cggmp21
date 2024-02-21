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
    #[cfg(feature = "hd-wallets")]
    pub fn maybe_bytes<B: udigest::Buffer>(
        m: &Option<impl AsRef<[u8]>>,
        encoder: udigest::encoding::EncodeValue<B>,
    ) {
        use udigest::Digestable;
        m.as_ref().map(udigest::Bytes).unambiguously_encode(encoder)
    }
}
