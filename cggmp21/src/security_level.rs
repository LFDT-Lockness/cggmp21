//! Security level of CGGMP protocol
//!
//! Security level is defined as set of parameters in the CGGMP paper. Higher security level gives more
//! security but makes protocol execution slower.
//!
//! We provide a predefined default [SecurityLevel128].
//!
//! You can define your own security level using macro [define_security_level]. Be sure that you properly
//! analyzed the CGGMP paper and you understand implications. Inconsistent security level may cause unexpected
//! unverbose runtime error or reduced security of the protocol.

use crate::rug::Integer;

/// Hardcoded value for parameter $m$ of security level
///
/// Currently, [security parameter $m$](SecurityLevel::M) is hardcoded to this constant. We're going to fix that
/// once `feature(generic_const_exprs)` is stable.
pub const M: usize = 128;

/// Security level of the protocol
///
/// You should not implement this trait manually. Use [define_security_level] macro instead.
pub trait SecurityLevel: Clone + Sync + Send + 'static {
    /// $\kappa$ bits of security
    const SECURITY_BITS: u32;
    /// $\kappa/8$ bytes of security
    const SECURITY_BYTES: usize;

    /// $\varepsilon$ bits
    const EPSILON: usize;

    /// $\ell$ parameter
    const ELL: usize;
    /// $\ell'$ parameter
    const ELL_PRIME: usize;

    /// $m$ parameter
    ///
    /// **Note:** currently, security parameter $m$ is hardcoded to [`M = 128`](M) due to compiler limitations.
    /// If you implement this trait directly, actual value of $m$ will be ignored. If you're using [define_security_level] macro
    /// it will produce a compilation error if different value of $m$ is set. We're going to fix that once `generic_const_exprs`
    /// feature is stable.
    const M: usize;

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

    /// $q$ parameter
    ///
    /// Note that it's not curve order, and it doesn't need to be a prime, it's another security parameter
    /// that determines security level.
    fn q() -> Integer;
}

/// Determines max size of exponents
///
/// During the CGGMP21 protocol, we often calculate $s^x t^y \mod N$. Given the security level
/// we can determine max size of $x$ and $y$ in bits.
///
/// Size of exponents can be used to build a [multiexp table](paillier_zk::multiexp).
///
/// Returns `(x_bits, y_bits)`
pub fn max_exponents_size<L: SecurityLevel>() -> (u32, u32) {
    use std::cmp;

    let x_bits = cmp::max(
        L::ELL as u32 + L::EPSILON as u32 + 4 * L::SECURITY_BITS,
        (L::ELL_PRIME + L::EPSILON) as _,
    );
    let y_bits = (L::ELL + L::EPSILON) as u32 + 8 * L::SECURITY_BITS;

    (x_bits, y_bits)
}

/// Internal module that's powers `define_security_level` macro
#[doc(hidden)]
pub mod _internal {
    use hex::FromHex;

    pub use crate::rug::Integer;

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
/// This code defines security level corresponding to $\kappa=1024$, $\varepsilon=128$, $\ell = \ell' = 1024$,
/// $m = 128$, and $q = 2^{48}-1$ (note: choice of parameters is random, it does not correspond to meaningful
/// security level):
/// ```rust
/// use cggmp21::security_level::define_security_level;
/// use cggmp21::rug::Integer;
///
/// #[derive(Clone)]
/// pub struct MyLevel;
/// define_security_level!(MyLevel{
///     security_bits = 1024,
///     epsilon = 128,
///     ell = 1024,
///     ell_prime = 1024,
///     m = 128,
///     q = (Integer::ONE.clone() << 48_u32) - 1,
/// });
/// ```
///
/// **Note:** currently, security parameter $m$ is hardcoded to the [`M = 128`](M) due to compiler limitations.
/// Setting any other value of $m$ results into compilation error. We're going to fix that once `generic_const_exprs`
/// feature is stable.
#[macro_export]
macro_rules! define_security_level {
    ($struct_name:ident {
        security_bits = $k:expr,
        epsilon = $e:expr,
        ell = $ell:expr,
        ell_prime = $ell_prime:expr,
        m = 128,
        q = $q:expr,
    }) => {
        impl $crate::security_level::SecurityLevel for $struct_name {
            const SECURITY_BITS: u32 = $k;
            const SECURITY_BYTES: usize = $k / 8;
            const EPSILON: usize = $e;
            const ELL: usize = $ell;
            const ELL_PRIME: usize = $ell_prime;
            const M: usize = 128;
            type Rid = $crate::security_level::_internal::Rid<{$k / 8}>;

            fn q() -> $crate::security_level::_internal::Integer {
                $q
            }
        }
    };
    ($struct_name:ident {
        security_bits = $k:expr,
        epsilon = $e:expr,
        ell = $ell:expr,
        ell_prime = $ell_prime:expr,
        m = $m:expr,
        q = $q:expr,
    }) => {
        compile_error!(concat!("Currently, we can not set security parameter M to anything but 128 (you set m=", stringify!($m), ")"));
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
    epsilon = 230,
    ell = 256,
    ell_prime = 848,
    m = 128,
    q = (Integer::ONE << 128_u32).into(),
});

/// Checks that public paillier key meets security level constraints
pub(crate) fn validate_public_paillier_key_size<L: SecurityLevel>(N: &Integer) -> bool {
    N.significant_bits() >= 8 * L::SECURITY_BITS - 1
}

/// Checks that secret paillier key meets security level constraints
pub(crate) fn validate_secret_paillier_key_size<L: SecurityLevel>(
    p: &Integer,
    q: &Integer,
) -> bool {
    p.significant_bits() >= 4 * L::SECURITY_BITS && q.significant_bits() >= 4 * L::SECURITY_BITS
}
