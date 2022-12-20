//! Security level of CGGMP protocol
//!
//! Security level is measured in bits and defined as $\kappa$ and $\varepsilon$ in paper. Higher
//! security level gives more security but makes protocol execution slower.
//!
//! We provide two predefined security levels: [ReasonablySecure], which should be used in production,
//! and [DevelopmentOnly], which is insecure but fast and can be used for testing.
//!
//! You can define your own security level using macro [define_security_level]. Be sure that you properly
//! analyzed the paper and you understand implications.

use libpaillier::unknown_order::BigNumber;

/// Security level of the protocol
///
/// You should not implement this trait manually. Use [define_security_level] macro instead.
pub trait SecurityLevel: Clone + Sync + Send + 'static {
    /// $\kappa$ bits of security
    const SECURITY_BITS: usize;
    /// $\kappa/8$ bytes of security
    const SECURITY_BYTES: usize;

    /// $\varepsilon$ bits
    const EPSILON: usize;

    /// $\ell$ parameter
    const ELL: usize;
    /// $\ell'$ parameter
    const ELL_PRIME: usize;

    /// $m$ parameter
    const M: usize;

    /// Static array of $\kappa/8$ bytes
    type Rid: AsRef<[u8]>
        + AsMut<[u8]>
        + Default
        + Clone
        + hex::FromHex<Error = hex::FromHexError>
        + Send
        + Sync
        + 'static;

    /// $\q$ parameter
    ///
    /// Note that it's not a prime or curve order, it's another security parameter that's
    /// determines security level.
    fn q() -> BigNumber;
}

/// Internal module that's powers `define_security_level` macro
#[doc(hidden)]
pub mod _internal {
    use hex::FromHex;
    pub use libpaillier::unknown_order::BigNumber;

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

/// Defines security level
///
/// ## Example
///
/// Let's define security level corresponding to $\kappa=1024$, $\varepsilon=128$, $\ell = \ell' = 1024$,
/// $m = 50$, and $q = 2^{48}-1$:
/// ```rust
/// use cggmp21::security_level::define_security_level;
/// use libpaillier::unknown_order::BigNumber;
///
/// #[derive(Clone)]
/// pub struct MyLevel;
/// define_security_level!(MyLevel{
///     security_bits = 1024,
///     epsilon = 128,
///     ell = 1024,
///     ell_prime = 1024,
///     m = 50,
///     q = (BigNumber::one() << 48) - 1,
/// });
/// ```
#[macro_export]
macro_rules! define_security_level {
    ($struct_name:ident {
        security_bits = $k:expr,
        epsilon = $e:expr,
        ell = $ell:expr,
        ell_prime = $ell_prime:expr,
        m = $m:expr,
        q = $q:expr,
    }) => {
        impl $crate::security_level::SecurityLevel for $struct_name {
            const SECURITY_BITS: usize = $k;
            const SECURITY_BYTES: usize = $k / 8;
            const EPSILON: usize = $e;
            const ELL: usize = $ell;
            const ELL_PRIME: usize = $ell_prime;
            const M: usize = $m;
            type Rid = $crate::security_level::_internal::Rid<{$k / 8}>;

            fn q() -> $crate::security_level::_internal::BigNumber {
                $q
            }
        }
    };
}

#[doc(inline)]
pub use define_security_level;

/// Reasonably secure security level
///
/// This security level is suitable for most use-cases.
#[derive(Clone)]
pub struct ReasonablySecure;
define_security_level!(ReasonablySecure{
    security_bits = 256,
    epsilon = 512,
    ell = 1024,
    ell_prime = 1024,
    m = 30,
    q = (BigNumber::one() << 256) - 1,
});
