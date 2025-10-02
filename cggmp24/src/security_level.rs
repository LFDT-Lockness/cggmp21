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

use crate::backend::Integer;

/// Security level of CGGMP24 DKG protocol
pub use cggmp24_keygen::security_level::SecurityLevel as KeygenSecurityLevel;

/// Hardcoded value for parameter $m$ of security level
///
/// Currently, security parameter $m$ is hardcoded to this constant. We're going to fix that
/// once `feature(generic_const_exprs)` is stable.
pub const M: usize = 128;

/// Security level of the CGGMP24 protocol
///
/// You should not implement this trait manually. Use [define_security_level] macro instead.
pub trait SecurityLevel: KeygenSecurityLevel {
    /// Length of RSA prime that matches the security level
    const RSA_PRIME_BITLEN: u32;
    /// Minimal length of RSA public key (bi-prime $N = pq$) that matches the
    /// security level
    const RSA_PUBKEY_BITLEN: u32;

    /// $\varepsilon$ bits
    const EPSILON: usize;

    /// $\ell$ parameter
    const ELL: usize;
    /// $\ell'$ parameter
    const ELL_PRIME: usize;
}

/// Determines max size of exponents
///
/// During the CGGMP24 protocol, we often calculate $s^x t^y \mod N$. Given the security level
/// we can determine max size of $x$ and $y$ in bits.
///
/// Size of exponents can be used to build a [multiexp table](paillier_zk::multiexp).
///
/// Returns `(x_bits, y_bits)`
pub fn max_exponents_size<L: SecurityLevel>() -> (u32, u32) {
    use std::cmp;

    let x_bits = cmp::max(
        L::ELL as u32 + L::EPSILON as u32 + L::RSA_PRIME_BITLEN,
        (L::ELL_PRIME + L::EPSILON) as _,
    );
    let y_bits = (L::ELL + L::EPSILON) as u32 + (L::RSA_PUBKEY_BITLEN + 4);

    (x_bits, y_bits)
}

/// Internal module that's powers `define_security_level` macro
#[doc(hidden)]
pub mod _internal {

    pub use crate::backend::Integer;
    pub use cggmp24_keygen::security_level::{
        define_security_level as define_keygen_security_level, SecurityLevel as KeygenSecurityLevel,
    };
}

/// Defines security level
///
/// ## Example
///
/// This code defines security level corresponding to $\kappa=1024$, RSA prime bitlen = 256,
/// RSA public key bitlen = 511, $\varepsilon=128$, $\ell = \ell' = 1024$, and $m = 128$ (note:
/// choice of parameters is random, it does not correspond to meaningful security level):
/// ```rust
/// use cggmp24::security_level::define_security_level;
///
/// #[derive(Clone)]
/// pub struct MyLevel;
/// define_security_level!(MyLevel {
///     kappa_bits: 1024,
///     rsa_prime_bitlen: 256,
///     rsa_pubkey_bitlen: 511,
///     epsilon: 128,
///     ell: 1024,
///     ell_prime: 1024,
///     m: 128,
/// });
/// ```
///
/// **Note:** currently, security parameter $m$ is hardcoded to the [`M = 128`](M) due to compiler limitations.
/// Setting any other value of $m$ results into compilation error. We're going to fix that once `generic_const_exprs`
/// feature is stable.
#[macro_export]
macro_rules! define_security_level {
    ($struct_name:ident {
        kappa_bits: $k:expr,
        rsa_prime_bitlen: $rsa_prime_bitlen:expr,
        rsa_pubkey_bitlen: $rsa_pubkey_bitlen:expr,
        epsilon: $e:expr,
        ell: $ell:expr,
        ell_prime: $ell_prime:expr,
        m: $m:tt,
    }) => {
        $crate::define_security_level! {
            $struct_name {
                rsa_prime_bitlen: $rsa_prime_bitlen,
                rsa_pubkey_bitlen: $rsa_pubkey_bitlen,
                epsilon: $e,
                ell: $ell,
                ell_prime: $ell_prime,
                m: $m,
            }
        }
        $crate::security_level::_internal::define_keygen_security_level! {
            $struct_name {
                kappa_bits: $k,
            }
        }
    };
    ($struct_name:ident {
        rsa_prime_bitlen: $rsa_prime_bitlen:expr,
        rsa_pubkey_bitlen: $rsa_pubkey_bitlen:expr,
        epsilon: $e:expr,
        ell: $ell:expr,
        ell_prime: $ell_prime:expr,
        m: 128,
    }) => {
        impl $crate::security_level::SecurityLevel for $struct_name {
            const RSA_PRIME_BITLEN: u32 = $rsa_prime_bitlen;
            const RSA_PUBKEY_BITLEN: u32 = $rsa_pubkey_bitlen;
            const EPSILON: usize = $e;
            const ELL: usize = $ell;
            const ELL_PRIME: usize = $ell_prime;
        }
    };
    ($struct_name:ident {
        rsa_prime_bitlen: $rsa_prime_bitlen:expr,
        rsa_pubkey_bitlen: $rsa_pubkey_bitlen:expr,
        epsilon: $e:expr,
        ell: $ell:expr,
        ell_prime: $ell_prime:expr,
        m: $m:tt,
    }) => {
        compile_error!(concat!("Currently, we can not set security parameter M to anything but 128 (you set m=", stringify!($m), ")"));
    };
}

#[doc(inline)]
pub use define_security_level;

#[doc(inline)]
pub use cggmp24_keygen::security_level::SecurityLevel128;
define_security_level!(SecurityLevel128 {
    rsa_prime_bitlen: 1536,
    rsa_pubkey_bitlen: 3071,
    epsilon: 256 * 2,
    ell: 256,
    ell_prime: 256 * 5,
    m: 128,
});

/// Checks that public paillier key meets security level constraints
pub(crate) fn validate_public_paillier_key_size<L: SecurityLevel>(N: &Integer) -> bool {
    N.significant_bits() >= u64::from(L::RSA_PUBKEY_BITLEN)
}

/// Checks that a prime, that is a part of secret paillier key, meets security level constraints
pub(crate) fn validate_secret_paillier_prime_size<L: SecurityLevel>(prime: &Integer) -> bool {
    prime.significant_bits() >= u64::from(L::RSA_PRIME_BITLEN)
}
