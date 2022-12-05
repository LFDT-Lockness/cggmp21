//! Security level of CGGMP protocol
//!
//! Security level is measured in bits and defined as $\kappa$ and $\varepsilon$ in paper. Higher
//! security level gives more security but makes protocol execution slower.
//!
//! We provide two predefined security levels: [ReasonablySecure], which should be used in production,
//! and [DevelopmentOnly], which is insecure but fast and can be used for testing.
//!
//! You can define your own security level using macros [define_security_level]. Be sure that you properly
//! analyzed the paper and you understand implications.

/// Security level of the protocol
///
/// You should not implement this trait manually. Use [define_security_level] macro instead.
pub trait SecurityLevel: Clone + Sync + Send + 'static {
    /// $\kappa$ bits of security
    const SECURITY_BITS: usize;
    /// $\kappa/8$ bytes of security
    const SECURITY_BYTES: usize;

    /// $\varepsilon$ bits
    const EPSILON_BITS: usize;

    /// Static array of $\kappa/8$ bytes
    type Rid: AsRef<[u8]> + AsMut<[u8]> + Default + Clone + Send + Sync + 'static;
}

#[doc(hidden)]
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

/// Defines security level
///
/// ## Example
///
/// Let's define security level corresponding to $\kappa=1024$ and $\varepsilon=16$:
/// ```rust
/// use cggmp21::security_level::define_security_level;
///
/// #[derive(Clone)]
/// pub struct MyLevel;
/// define_security_level!(MyLevel{ security_bits = 1024, epsilon_bits = 16 });
/// ```
#[macro_export]
macro_rules! define_security_level {
    ($struct_name:ident { security_bits = $k:expr, epsilon_bits = $e:expr }) => {
        impl $crate::security_level::SecurityLevel for $struct_name {
            const SECURITY_BITS: usize = $k;
            const SECURITY_BYTES: usize = $k / 8;
            const EPSILON_BITS: usize = $e;
            type Rid = $crate::security_level::Rid<{$k / 8}>;
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
define_security_level!(ReasonablySecure{ security_bits = 256, epsilon_bits = 8 });

/// Security level suitable for testing
///
/// __Warning:__ this security level is insecure
#[derive(Clone)]
pub struct DevelopmentOnly;
define_security_level!(DevelopmentOnly{ security_bits = 32, epsilon_bits = 2 });
