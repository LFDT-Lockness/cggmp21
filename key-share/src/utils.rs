#[cfg(feature = "serde")]
mod hex_or_bin;

#[cfg(feature = "serde")]
pub use hex_or_bin::HexOrBin;
