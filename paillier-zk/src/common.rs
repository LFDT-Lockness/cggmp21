pub mod sqrt;

use std::sync::Arc;

use fast_paillier::backend::Integer;
use generic_ec::Scalar;

/// Auxiliary data known to both prover and verifier
#[cfg_attr(
    feature = "__internal_doctest",
    derive(serde::Serialize, serde::Deserialize)
)]
#[derive(Clone, Debug)]
pub struct Aux {
    /// ring-pedersen parameter
    pub s: Integer,
    /// ring-pedersen parameter
    pub t: Integer,
    /// N^ in paper
    pub rsa_modulo: Integer,
    /// Precomuted table for computing `s^x t^y mod rsa_modulo` faster
    ///
    /// If absent, optimization is disabled.
    #[cfg_attr(feature = "__internal_doctest", serde(skip))]
    pub multiexp: Option<Arc<crate::multiexp::MultiexpTable>>,
    #[cfg_attr(feature = "__internal_doctest", serde(skip))]
    pub crt: Option<fast_paillier::utils::CrtExp>,
}

impl Aux {
    /// Returns `s^x t^y mod rsa_modulo`
    pub fn combine(&self, x: &Integer, y: &Integer) -> Result<Integer, BadExponent> {
        if let Some(table) = &self.multiexp {
            match table.prod_exp(x, y) {
                Some(res) => return Ok(res),
                None if cfg!(debug_assertions) => {
                    return Err(BadExponentReason::ExpSize {
                        exp_size: (x.significant_bits(), y.significant_bits()),
                        max_exp_size: table.max_exponents_size(),
                    }
                    .into())
                }
                None => {
                    // When debug assertions are disabled, we fallback to naive exponentiation
                }
            }
        }

        // Naive exponentiation when optimizations are not enabled
        self.rsa_modulo
            .combine(&self.s, x, &self.t, y)
            .ok_or_else(BadExponent::undefined)
    }

    /// Returns `x^e mod rsa_modulo`
    pub fn pow_mod(&self, x: &Integer, e: &Integer) -> Result<Integer, BadExponent> {
        match &self.crt {
            Some(crt) => {
                let e = crt.prepare_exponent(e);
                crt.exp(x, &e).ok_or_else(BadExponent::undefined)
            }
            None => Ok(x
                .pow_mod_ref(e, &self.rsa_modulo)
                .ok_or_else(BadExponent::undefined)?),
        }
    }

    /// Checks if `x` is in multiplicative group Z<super>*</super><sub>N</sub> where `N = ` [`rsa_modulo`](Self::rsa_modulo)
    pub fn is_in_mult_group(&self, x: &Integer) -> bool {
        x.in_mult_group_of(&self.rsa_modulo)
    }

    /// Returns a stripped version of `Aux` that contains only public data which can be digested
    /// via [`udigest::Digestable`]
    pub fn digest_public_data(&self) -> impl udigest::Digestable {
        udigest::inline_struct!("paillier_zk.aux" {
            s: udigest::Bytes(self.s.to_bytes_msf()),
            t: udigest::Bytes(self.t.to_bytes_msf()),
            rsa_modulo: udigest::Bytes(self.rsa_modulo.to_bytes_msf()),
        })
    }
}

/// Error indicating that proof is invalid
#[derive(Debug, Clone, thiserror::Error)]
#[error("invalid proof")]
pub struct InvalidProof(
    #[source]
    #[from]
    InvalidProofReason,
);

/// Reason for failure. If the proof fails, you should only be interested in a
/// reason for debugging purposes
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, Clone, Copy, thiserror::Error)]
pub enum InvalidProofReason {
    /// One equality doesn't hold. Parameterized by equality index
    #[error("equality check failed {0}")]
    EqualityCheck(usize),
    /// Check that integer belongs to multiplicative group failed. Parameterized by equality index
    #[error("mult group check failed {0}")]
    MultGroupCheck(usize),
    /// One range check doesn't hold. Parameterized by check index
    #[error("range check failed {0}")]
    RangeCheck(usize),
    /// Encryption of supplied data failed when attempting to verify
    #[error("encryption failed")]
    Encryption,
    #[error("paillier encryption failed")]
    PaillierEnc,
    #[error("paillier homomorphic op failed")]
    PaillierOp,
    /// Failed to evaluate powmod
    #[error("powmod failed")]
    ModPow,
    /// Paillier-Blum modulus is prime
    #[error("modulus is prime")]
    ModulusIsPrime,
    /// Paillier-Blum modulus is even
    #[error("modulus is even")]
    ModulusIsEven,
    /// Proof's z value in n-th power does not equal commitment value
    #[error("incorrect nth root")]
    IncorrectNthRoot,
    /// Proof's x value in 4-th power does not equal commitment value
    #[error("incorrect 4th root")]
    IncorrectFourthRoot,
    /// Conversion failed (e.g. from u32 to usize)
    #[error("conversion failed")]
    Conversion,
}

impl InvalidProof {
    #[cfg(test)]
    pub(crate) fn reason(&self) -> InvalidProofReason {
        self.0
    }
}

impl From<BadExponent> for InvalidProof {
    fn from(_err: BadExponent) -> Self {
        InvalidProofReason::ModPow.into()
    }
}

impl From<PaillierError> for InvalidProof {
    fn from(_err: PaillierError) -> Self {
        InvalidProof(InvalidProofReason::Encryption)
    }
}

/// Error indicating that encryption failed
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("paillier encryption failed")]
pub struct PaillierError;

pub trait IntegerExt: Sized {
    /// Embed BigInt into chosen scalar type
    fn to_scalar<C: generic_ec::Curve>(&self) -> Scalar<C>;

    /// Returns prime order of curve C
    fn curve_order<C: generic_ec::Curve>() -> Self;

    /// Generates a random integer in interval
    /// `[-range/2; range/2]` if range is even
    /// `[-(range-1)/2; (range-1)/2]` if range is odd
    fn from_rng_half_pm<R: rand_core::RngCore>(rng: &mut R, range: &Self) -> Self;

    /// Checks whether `self` is in interval
    /// `[-range/2; range/2]` when range is even
    /// `[-(range-1)/2; (range-1)/2]` when range is odd
    fn is_in_half_pm(&self, range: &Self) -> bool;
}

impl IntegerExt for Integer {
    fn to_scalar<C: generic_ec::Curve>(&self) -> Scalar<C> {
        let bytes_be = self.to_bytes_msf();
        let s = Scalar::<C>::from_be_bytes_mod_order(bytes_be);
        if self.cmp0().is_ge() {
            s
        } else {
            -s
        }
    }

    fn curve_order<C: generic_ec::Curve>() -> Self {
        let order_minus_one = -Scalar::<C>::one();
        let i = Integer::from_bytes_msf(&order_minus_one.to_be_bytes());
        i + 1
    }

    fn from_rng_half_pm<R: rand_core::RngCore>(rng: &mut R, range: &Self) -> Self {
        if range.is_even() {
            let half_range = range >> 1;
            let range_plus_one = range + 1u32;
            range_plus_one.random_below(rng) - half_range
        } else {
            // range is odd, so half of the range minus one is range / 2
            let half_range_minus_one = range >> 1;
            range.random_below_ref(rng) - half_range_minus_one
        }
    }

    fn is_in_half_pm(&self, range: &Self) -> bool {
        // If range is even, range >> 1 is exactly range / 2
        // If range is odd, range >> 1 == (range - 1) >> 1 == (range - 1) / 2 as
        // the lowest bit is discarded either way
        let bound = range >> 1;
        self.cmp_abs(&bound).is_le()
    }
}

/// Error indicating that computation cannot be evaluated because of bad exponent
///
/// Returned by [`Aux::pow_mod`] and other functions that do exponentiation internally
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error(transparent)]
pub struct BadExponent(#[from] BadExponentReason);

impl BadExponent {
    /// Constructs an error that exponent is undefined
    pub fn undefined() -> Self {
        Self(BadExponentReason::Undefined)
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
enum BadExponentReason {
    #[error("exponent is undefined")]
    Undefined,
    #[error("multiexp error: exponent size is too large (exponents size: {exp_size:?}, max exponent size: {max_exp_size:?})")]
    ExpSize {
        exp_size: (u64, u64),
        max_exp_size: (usize, usize),
    },
}

/// Returns `Err(err)` if `assertion` is false
pub fn fail_if<E>(err: E, assertion: bool) -> Result<(), E> {
    if assertion {
        Ok(())
    } else {
        Err(err)
    }
}

/// Returns `Err(err)` if `lhs != rhs`
pub fn fail_if_ne<T: PartialEq, E>(err: E, lhs: T, rhs: T) -> Result<(), E> {
    if lhs == rhs {
        Ok(())
    } else {
        Err(err)
    }
}

pub mod encoding {
    /// Digests a fast-paillier backend integer
    pub struct Integer;
    impl udigest::DigestAs<fast_paillier::backend::Integer> for Integer {
        fn digest_as<B: udigest::Buffer>(
            value: &fast_paillier::backend::Integer,
            encoder: udigest::encoding::EncodeValue<B>,
        ) {
            let digits = value.to_bytes_msf();
            encoder.encode_leaf_value(digits)
        }
    }

    /// Digests any encryption key
    pub struct AnyEncryptionKey;
    impl udigest::DigestAs<&dyn fast_paillier::AnyEncryptionKey> for AnyEncryptionKey {
        fn digest_as<B: udigest::Buffer>(
            value: &&dyn fast_paillier::AnyEncryptionKey,
            encoder: udigest::encoding::EncodeValue<B>,
        ) {
            Integer::digest_as(value.n(), encoder)
        }
    }
}

/// A common logic shared across tests and doctests
#[cfg(test)]
pub mod test {
    use fast_paillier::backend::Integer;

    pub fn random_key<R: rand_core::RngCore>(rng: &mut R) -> Option<fast_paillier::DecryptionKey> {
        let p = generate_blum_prime(rng, 1024);
        let q = generate_blum_prime(rng, 1024);
        fast_paillier::DecryptionKey::from_primes(p, q).ok()
    }

    pub fn aux<R: rand_core::RngCore>(rng: &mut R) -> super::Aux {
        let p = generate_blum_prime(rng, 1024);
        let q = generate_blum_prime(rng, 1024);
        let n = &p * &q;

        let (s, t) = {
            let phi_n = (p - 1u8) * (q - 1u8);
            let r = Integer::sample_in_mult_group_of(rng, &n);
            let lambda = phi_n.random_below(rng);

            let t = r.square().modulo(&n);
            let s = t.pow_mod_ref(&lambda, &n).unwrap();

            (s, t)
        };

        super::Aux {
            s,
            t,
            rsa_modulo: n,
            multiexp: None,
            crt: None,
        }
    }

    pub fn generate_blum_prime(rng: &mut impl rand_core::RngCore, bits_size: u32) -> Integer {
        loop {
            let n = Integer::generate_prime(rng, bits_size);
            if n.mod_u(4) == 3 {
                break n;
            }
        }
    }
}

#[cfg(test)]
mod _test {
    use fast_paillier::backend::Integer;

    use super::IntegerExt;

    #[test]
    fn to_scalar_encoding() {
        type E = generic_ec::curves::Secp256k1;

        let bytes = [123u8, 231u8];
        let int = u16::from_be_bytes(bytes);
        let bn = Integer::from(int);
        let scalar = bn.to_scalar();
        assert_eq!(scalar, generic_ec::Scalar::<E>::from(int));

        assert_eq!(bn.to_bytes_msf(), &bytes);

        let curve_order = Integer::curve_order::<E>();
        assert_eq!(curve_order.to_scalar(), generic_ec::Scalar::<E>::zero());
        assert_eq!(
            (curve_order - 1u8).to_scalar(),
            -generic_ec::Scalar::<E>::one()
        );
    }

    #[test]
    fn multiexp() {
        let mut rng = rand_dev::DevRng::new();
        let mut aux = super::test::aux(&mut rng);
        let table = std::sync::Arc::new(
            crate::multiexp::MultiexpTable::build(&aux.s, &aux.t, 512, 448, aux.rsa_modulo.clone())
                .unwrap(),
        );
        let (x_bits, y_bits) = table.max_exponents_size();
        aux.multiexp = Some(table);

        // Corner case: upper bound
        let x_max = (Integer::one() << x_bits) - 1;
        let y_max = (Integer::one() << y_bits) - 1;
        let actual = aux.combine(&x_max, &y_max).unwrap();
        let expected = aux
            .rsa_modulo
            .combine(&aux.s, &x_max, &aux.t, &y_max)
            .unwrap();
        assert_eq!(actual, expected);

        // Corner case: lower bound
        let x_min = -&x_max;
        let y_min = -&y_max;
        let actual = aux.combine(&x_min, &y_min).unwrap();
        let expected = aux
            .rsa_modulo
            .combine(&aux.s, &x_min, &aux.t, &y_min)
            .unwrap();
        assert_eq!(actual, expected);

        // Random integers within the range
        for _ in 0..100 {
            let x = (&x_max + 1u8).random_below(&mut rng);
            let y = (&y_max + 1u8).random_below(&mut rng);

            let x = if rand::Rng::gen(&mut rng) { x } else { -x };
            let y = if rand::Rng::gen(&mut rng) { y } else { -y };

            println!("x: {x}");
            println!("y: {y}");

            let actual = aux.combine(&x, &y).unwrap();
            let expected = aux.rsa_modulo.combine(&aux.s, &x, &aux.t, &y).unwrap();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn test_from_rng_half_pm_bounds() {
        let mut rng = rand_dev::DevRng::new();
        // Testing even case
        let range = Integer::from(10);
        let upper_bound = &range >> 1;
        let lower_bound = -&upper_bound;
        let mut min = Integer::from(0);
        let mut max = Integer::from(0);

        // Obtaining lower and upper bounds
        for _ in 0..10000 {
            let value = Integer::from_rng_half_pm(&mut rng, &range);
            if value > max {
                max.clone_from(&value);
            }
            if value < min {
                min.clone_from(&value);
            }
        }

        assert_eq!(
            min, lower_bound,
            "Minimum value {min} did not match expected lower bound {lower_bound}"
        );
        assert_eq!(
            max, upper_bound,
            "Maximum value {max} did not match expected upper bound {upper_bound}"
        );

        // Testing odd case
        let range = Integer::from(9);
        let range_minus_one = &range - Integer::one();
        let upper_bound = range_minus_one >> 1;
        let lower_bound = -&upper_bound;
        let mut min = Integer::from(0);
        let mut max = Integer::from(0);

        // Obtaining lower and upper bounds
        for _ in 0..10000 {
            let value = Integer::from_rng_half_pm(&mut rng, &range);
            if value > max {
                max.clone_from(&value);
            }
            if value < min {
                min.clone_from(&value);
            }
        }

        assert_eq!(
            min, lower_bound,
            "Minimum value {min} did not match expected lower bound {lower_bound}"
        );
        assert_eq!(
            max, upper_bound,
            "Maximum value {max} did not match expected upper bound {upper_bound}"
        );
    }

    #[test]
    fn test_is_in_half_pm() {
        // Testing even case
        let range = Integer::from(10);
        let a_1 = Integer::from(-6);
        let a_2 = Integer::from(-5);
        let a_3 = Integer::from(5);
        let a_4 = Integer::from(6);
        assert!(
            !a_1.is_in_half_pm(&range),
            "{a_1} should be outside [-range/2,range/2]"
        );
        assert!(
            a_2.is_in_half_pm(&range),
            "{a_2} should be in [-range/2,range/2]"
        );
        assert!(
            a_3.is_in_half_pm(&range),
            "{a_3} should be in [-range/2,range/2]"
        );
        assert!(
            !a_4.is_in_half_pm(&range),
            "{a_4} should be outside [-range/2,range/2]"
        );

        // Testing odd case
        let range = Integer::from(9);
        let a_1 = Integer::from(-5);
        let a_2 = Integer::from(-4);
        let a_3 = Integer::from(4);
        let a_4 = Integer::from(5);
        assert!(
            !a_1.is_in_half_pm(&range),
            "{a_1} should be outside [-(range-1)/2,(range-1)/2]"
        );
        assert!(
            a_2.is_in_half_pm(&range),
            "{a_1} should be in [-(range-1)/2,(range-1)/2]"
        );
        assert!(
            a_3.is_in_half_pm(&range),
            "{a_3} should be in [-(range-1)/2,(range-1)/2]"
        );
        assert!(
            !a_4.is_in_half_pm(&range),
            "{a_4} should be outside [-(range-1)/2,(range-1)/2]"
        );
    }
}
