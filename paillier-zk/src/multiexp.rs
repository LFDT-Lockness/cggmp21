//! Optimized multiexponentiation with precomputations
//!
//! Many ZK proofs often require computing `s^x t^y mod N` with s, t, and N being known in advance.
//! This module provides [`MultiexpTable`] that can compute multiexponent faster.

#![allow(non_snake_case)]

use std::sync::OnceLock;

use crypto_bigint::{
    modular::{BoxedMontyForm, BoxedMontyParams},
    BoxedUint, Odd,
};
use fast_paillier::backend::Integer;

/// Precomputed table for performing faster multiexponentiation
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MultiexpTable {
    s: Vec<Integer>,
    ell_x: Integer,
    s_to_ell_x: Integer,
    t: Vec<Integer>,
    ell_y: Integer,
    t_to_ell_y: Integer,
    N: Integer,
    #[cfg_attr(feature = "serde", serde(skip))]
    monty: OnceLock<Option<MontyTable>>,
}

#[derive(Debug, Clone)]
struct MontyTable {
    params: BoxedMontyParams,
    s: Vec<BoxedMontyForm>,
    s_to_ell_x: BoxedMontyForm,
    t: Vec<BoxedMontyForm>,
    t_to_ell_y: BoxedMontyForm,
}

impl MultiexpTable {
    /// Builds a multiexponentiation table to perform `s^x t^y mod N` faster
    /// where `x` and `y` are up to `x_bits` and `y_bits`
    ///
    /// Returns `None` is `s` or `t` are non-positive or if any of them are not co-prime to `N` or
    /// if `N` is less than 2.
    pub fn build(s: &Integer, t: &Integer, x_bits: u32, y_bits: u32, N: Integer) -> Option<Self> {
        if s.cmp0().is_le()
            || t.cmp0().is_le()
            || N <= Integer::one()
            || !s.gcd_ref(&N).is_one()
            || !t.gcd_ref(&N).is_one()
        {
            return None;
        }
        let k_x = x_bits / 8 + 1;
        let k_y = y_bits / 8 + 1;
        let mut s_table = Vec::with_capacity(k_x.try_into().ok()?);
        let mut t_table = Vec::with_capacity(k_y.try_into().ok()?);

        let radix = Integer::from(256u32);
        let mut s_power = s.pow_mod_ref(&Integer::one(), &N)?;
        for i in 0..k_x {
            s_table.push(s_power.clone());
            if i + 1 < k_x {
                s_power = s_power.pow_mod_ref(&radix, &N)?;
            }
        }
        let mut t_power = t.pow_mod_ref(&Integer::one(), &N)?;
        for i in 0..k_y {
            t_table.push(t_power.clone());
            if i + 1 < k_y {
                t_power = t_power.pow_mod_ref(&radix, &N)?;
            }
        }

        // smallest negative value possible for `x`
        let ell_x = -(Integer::one() << (k_x * 8)) + 1;
        let s_to_ell_x = s.pow_mod_ref(&ell_x, &N)?;
        // smallest negative value possible for `y`
        let ell_y = -(Integer::one() << (k_y * 8)) + 1;
        let t_to_ell_y = t.pow_mod_ref(&ell_y, &N)?;

        let table = Self {
            s: s_table,
            ell_x,
            s_to_ell_x,
            t: t_table,
            ell_y,
            t_to_ell_y,
            N,
            monty: OnceLock::new(),
        };
        let _ = table.monty.set(MontyTable::build(&table));
        Some(table)
    }

    /// Calculates `s^x t^y mod N`
    ///
    /// Returns `None` if either `x` or `y` do not fit into `x_bits` or `y_bits` provided in [`MultiexpTable::build`].
    pub fn prod_exp(&self, x: &Integer, y: &Integer) -> Option<Integer> {
        let x_is_neg = x.cmp0().is_lt();
        // `x_digits` correspond to digits of `x` is it's non-negative, and `x - ell_x` otherwise
        let x_digits = if !x_is_neg {
            x.to_bytes_lsf()
        } else {
            let x = x - &self.ell_x;
            if x.cmp0().is_lt() {
                // `x` is less than lower bound
                return None;
            }
            x.to_bytes_lsf()
        };

        let y_is_neg = y.cmp0().is_lt();
        // `y_digits` correspond to digits of `y` is it's non-negative, and `y - ell_y` otherwise
        let y_digits = if !y_is_neg {
            y.to_bytes_lsf()
        } else {
            let y = y - &self.ell_y;
            if y.cmp0().is_lt() {
                // `y` is less than lower bound
                return None;
            }
            y.to_bytes_lsf()
        };

        if x_digits.len() > self.s.len() || y_digits.len() > self.t.len() {
            // `x` or `y` are higher than upper bound
            return None;
        }

        match self.monty.get_or_init(|| MontyTable::build(self)) {
            Some(table) => Some(table.prod_exp(&x_digits, &y_digits, x_is_neg, y_is_neg)),
            None => Some(self.prod_exp_standard(&x_digits, &y_digits, x_is_neg, y_is_neg)),
        }
    }

    fn prod_exp_standard(
        &self,
        x_digits: &[u8],
        y_digits: &[u8],
        x_is_neg: bool,
        y_is_neg: bool,
    ) -> Integer {
        let mut digits_table = [(); 255].map(|_| None);
        build_integer_digits_table(&mut digits_table, &self.s, x_digits, &self.N);
        build_integer_digits_table(&mut digits_table, &self.t, y_digits, &self.N);

        let mut res = Integer::one();
        let mut acc = Integer::one();
        for d in digits_table.iter().rev() {
            if let Some(d) = d {
                acc = (acc * d) % &self.N;
            }
            res = (res * &acc) % &self.N;
        }

        if x_is_neg {
            res = (res * &self.s_to_ell_x) % &self.N;
        }
        if y_is_neg {
            res = (res * &self.t_to_ell_y) % &self.N;
        }
        res
    }

    /// Returns max size of exponents (in bits) that can be computed
    ///
    /// Max exponent size is guaranteed to be equal or greater than `x_bits` and `y_bits`
    /// provided in [MultiexpTable::build]
    pub fn max_exponents_size(&self) -> (usize, usize) {
        (self.s.len() * 8, self.t.len() * 8)
    }

    /// Estimates size of the table in RAM in bytes
    pub fn size_in_bytes(&self) -> usize {
        let Self {
            s,
            ell_x,
            s_to_ell_x,
            t,
            ell_y,
            t_to_ell_y,
            N,
            monty: _,
        } = self;

        // A few bytes to encode length of Vec `s` and `t`
        let vec_len = 2 * (usize::BITS as usize / 8);
        // And a few bytes more to encode length of each integer
        let int_len = (5 + s.len() + t.len()) * (usize::BITS as usize / 8);

        let s: usize = s.iter().map(|s_i| s_i.significant_dwords()).sum();
        let ell_x = ell_x.significant_dwords();
        let s_to_ell_x = s_to_ell_x.significant_dwords();
        let t: usize = t.iter().map(|t_i| t_i.significant_dwords()).sum();
        let ell_y = ell_y.significant_dwords();
        let t_to_ell_y = t_to_ell_y.significant_dwords();
        let N = N.significant_dwords();

        let limbs_bytes =
            (u32::BITS as usize / 8) * (s + ell_x + s_to_ell_x + t + ell_y + t_to_ell_y + N);

        let monty = self
            .monty
            .get()
            .and_then(Option::as_ref)
            .map(MontyTable::size_in_bytes)
            .unwrap_or(0);

        vec_len + int_len + limbs_bytes + monty
    }
}

fn build_integer_digits_table(
    table: &mut [Option<Integer>; 255],
    base: &[Integer],
    digits: &[u8],
    N: &Integer,
) {
    for (i, digit) in digits.iter().copied().enumerate() {
        if digit != 0 {
            match &mut table[usize::from(digit - 1)] {
                Some(out) => {
                    *out *= &base[i];
                    *out %= N;
                }
                out @ None => *out = Some(base[i].clone()),
            }
        }
    }
}

impl MontyTable {
    fn build(table: &MultiexpTable) -> Option<Self> {
        if table.N.is_even() {
            return None;
        }

        let modulus = BoxedUint::from_be_slice_vartime(&table.N.to_bytes_msf());
        let modulus = Option::<Odd<BoxedUint>>::from(Odd::new(modulus))?;
        let params = BoxedMontyParams::new_vartime(modulus);
        let convert = |value: &Integer| {
            BoxedUint::from_be_slice(&value.to_bytes_msf(), params.bits_precision())
                .ok()
                .map(|value| BoxedMontyForm::new(value, &params))
        };

        Some(Self {
            s: table.s.iter().map(convert).collect::<Option<_>>()?,
            s_to_ell_x: convert(&table.s_to_ell_x)?,
            t: table.t.iter().map(convert).collect::<Option<_>>()?,
            t_to_ell_y: convert(&table.t_to_ell_y)?,
            params,
        })
    }

    fn prod_exp(
        &self,
        x_digits: &[u8],
        y_digits: &[u8],
        x_is_neg: bool,
        y_is_neg: bool,
    ) -> Integer {
        let mut digits_table = [(); 255].map(|_| None);
        build_monty_digits_table(&mut digits_table, &self.s, x_digits);
        build_monty_digits_table(&mut digits_table, &self.t, y_digits);

        let mut res = BoxedMontyForm::one(&self.params);
        let mut acc = BoxedMontyForm::one(&self.params);
        for d in digits_table.iter().rev() {
            if let Some(d) = d {
                acc *= d;
            }
            res *= &acc;
        }

        if x_is_neg {
            res *= &self.s_to_ell_x;
        }
        if y_is_neg {
            res *= &self.t_to_ell_y;
        }

        Integer::from_bytes_msf(&res.retrieve().to_be_bytes())
    }

    fn size_in_bytes(&self) -> usize {
        let values = self.s.len() + self.t.len() + 2;
        // Include cached residues and the modulus parameters retained by the shared Arc.
        (values + 4) * usize::try_from(self.params.bits_precision() / 8).unwrap_or(usize::MAX)
    }
}

fn build_monty_digits_table(
    table: &mut [Option<BoxedMontyForm>; 255],
    base: &[BoxedMontyForm],
    digits: &[u8],
) {
    for (i, digit) in digits.iter().copied().enumerate() {
        if digit != 0 {
            match &mut table[usize::from(digit - 1)] {
                Some(out) => {
                    *out *= &base[i];
                }
                out @ None => *out = Some(base[i].clone()),
            }
        }
    }
}

#[cfg(test)]
mod test {
    use fast_paillier::backend::Integer;

    use super::MultiexpTable;

    #[test]
    fn multiexp_works() {
        check_multiexp(Integer::from(100003));
        check_multiexp(Integer::from(100000));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serialized_table_rebuilds_monty_cache() {
        let table = MultiexpTable::build(
            &Integer::from(3),
            &Integer::from(7),
            48,
            32,
            Integer::from(100003),
        )
        .unwrap();
        let encoded = serde_json::to_vec(&table).unwrap();
        let restored: MultiexpTable = serde_json::from_slice(&encoded).unwrap();

        assert!(restored.monty.get().is_none());
        assert_eq!(
            restored
                .prod_exp(&Integer::from(-12345), &Integer::from(6789))
                .unwrap(),
            table
                .prod_exp(&Integer::from(-12345), &Integer::from(6789))
                .unwrap()
        );
        assert!(restored.monty.get().is_some_and(Option::is_some));
    }

    fn check_multiexp(N: Integer) {
        let s = Integer::from(3);
        let t = Integer::from(7);

        let x_bits = 48;
        let y_bits = 32;

        let table = MultiexpTable::build(&s, &t, x_bits, y_bits, N.clone()).unwrap();

        let mut rng = rand_dev::DevRng::new();

        for _ in 0..100 {
            let mut x = Integer::random_bits(x_bits, &mut rng);
            if rand::Rng::gen(&mut rng) {
                x = -x
            }

            let mut y = Integer::random_bits(y_bits, &mut rng);
            if rand::Rng::gen(&mut rng) {
                y = -y
            }
            println!("x={x} y={y}");

            let actual = table.prod_exp(&x, &y).unwrap();
            let expected = (s.pow_mod_ref(&x, &N).unwrap() * t.pow_mod_ref(&y, &N).unwrap()) % &N;
            assert_eq!(actual, expected);
        }
    }
}
