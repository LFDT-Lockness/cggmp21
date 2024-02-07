//! Security level of CGGMP DKG protocol
//!
//! Security level is defined as set of parameters in the CGGMP paper. Higher security level gives more
//! security but makes protocol execution slower.
//!
//! We provide a predefined default [SecurityLevel128].
//!
//! You can define your own security level using macro [define_security_level]. Be sure that you properly
//! analyzed the CGGMP paper and you understand implications. Inconsistent security level may cause unexpected
//! unverbose runtime error or reduced security of the protocol.

/// Security level of the DKG protocol
///
/// You should not implement this trait manually. Use [define_security_level] macro instead.
pub trait SecurityLevel: Clone + Sync + Send + 'static {
    /// $\kappa$ bits of security
    const SECURITY_BITS: u32;
    /// $\kappa/8$ bytes of security
    const SECURITY_BYTES: usize;

    /// Static array of $\kappa/8$ bytes
    type Rid: AsRef<[u8]>
        + AsMut<[u8]>
        + Default
        + Clone
        + hex::FromHex<Error = hex::FromHexError>
        + Send
        + Sync
        + Unpin
        + 'static;
}

/// Internal module that's powers `define_security_level` macro
#[doc(hidden)]
pub mod _internal {
    use hex::FromHex;

    #[derive(Clone)]
    pub struct Rid<const N: usize>([u8; N]);

    impl<const N: usize> AsRef<[u8]> for Rid<N> {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    impl<const N: usize> AsMut<[u8]> for Rid<N> {
        fn as_mut(&mut self) -> &mut [u8] {
            &mut self.0
        }
    }

    impl<const N: usize> Default for Rid<N> {
        fn default() -> Self {
            Self([0u8; N])
        }
    }

    impl<const N: usize> FromHex for Rid<N>
    where
        [u8; N]: FromHex,
    {
        type Error = <[u8; N] as FromHex>::Error;
        fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
            FromHex::from_hex(hex).map(Self)
        }
    }
}

/// Defines security level of CGGMP21 DKG protocol
///
/// ## Example
///
/// This code defines security level corresponding to $\kappa=1024$ (note: choice of parameters is random,
/// it does not correspond to meaningful security level):
/// ```rust
/// use cggmp21_keygen::security_level::define_security_level;
///
/// #[derive(Clone)]
/// pub struct MyLevel;
/// define_security_level!(MyLevel{
///     security_bits = 1024,
/// });
/// ```
#[macro_export]
macro_rules! define_security_level {
    ($struct_name:ident {
        security_bits = $k:expr$(,)?
    }) => {
        impl $crate::security_level::SecurityLevel for $struct_name {
            const SECURITY_BITS: u32 = $k;
            const SECURITY_BYTES: usize = $k / 8;
            type Rid = $crate::security_level::_internal::Rid<{ $k / 8 }>;
        }
    };
}

#[doc(inline)]
pub use define_security_level;

/// 128-bits security level
///
/// This security level is intended to provide 128 bits of security for the protocol when run with up to 128 participants.
#[derive(Clone)]
pub struct SecurityLevel128;
define_security_level!(SecurityLevel128{
    security_bits = 384,
});
