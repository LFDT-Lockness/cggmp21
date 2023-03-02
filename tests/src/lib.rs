use anyhow::{bail, Context, Result};
use cggmp21::{
    key_share::{KeyShare, Valid},
    security_level::ReasonablySecure,
    unknown_order::BigNumber,
};
use generic_ec::Curve;
use rand::RngCore;
use serde_json::{Map, Value};

// You can't disable clippy warnings inside a macro, so we isolate macro calls
// into a module and disable warnings this way
mod cached {
    #![allow(clippy::unwrap_used)]
    use crate::{PrecomputedKeyShares, PregeneratedPrimes};

    lazy_static::lazy_static! {
        pub static ref CACHED_SHARES: PrecomputedKeyShares =
            PrecomputedKeyShares::from_serialized(
                include_str!("../../test-data/precomputed_shares.json")
            ).unwrap();
        pub static ref CACHED_PRIMES: PregeneratedPrimes =
            PregeneratedPrimes::from_serialized(
                include_str!("../../test-data/pregenerated_primes.json")
            ).unwrap();
    }
}
pub use cached::*;

pub struct PrecomputedKeyShares {
    shares: Map<String, Value>,
}

impl PrecomputedKeyShares {
    pub fn empty() -> Self {
        Self {
            shares: Default::default(),
        }
    }
    #[allow(clippy::should_implement_trait)]
    pub fn from_serialized(shares: &str) -> Result<Self> {
        let shares = serde_json::from_str(shares).context("parse shares")?;
        Ok(Self { shares })
    }

    pub fn to_serialized(&self) -> Result<String> {
        serde_json::to_string_pretty(&self.shares).context("serialize shares")
    }

    pub fn get_shares<E: Curve>(
        &self,
        n: u16,
    ) -> Result<Vec<Valid<KeyShare<E, ReasonablySecure>>>> {
        let key_shares = self
            .shares
            .get(&format!("n={n},curve={}", E::CURVE_NAME))
            .context("shares not found")?;
        serde_json::from_value(key_shares.clone()).context("parse key shares")
    }

    pub fn add_shares<E: Curve>(
        &mut self,
        n: u16,
        shares: &[Valid<KeyShare<E, ReasonablySecure>>],
    ) -> Result<()> {
        if usize::from(n) != shares.len() {
            bail!("expected {n} key shares, only {} provided", shares.len());
        }
        let key_shares = serde_json::to_value(shares).context("serialize shares")?;
        self.shares
            .insert(format!("n={n},curve={}", E::CURVE_NAME), key_shares);
        Ok(())
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PregeneratedPrimes {
    primes: Vec<BigNumber>,
    bitsize: usize,
}

impl PregeneratedPrimes {
    pub fn from_serialized(repr: &str) -> Result<Self> {
        serde_json::from_str(repr).context("parse primes")
    }

    pub fn to_serialized(&self) -> Result<String> {
        serde_json::to_string(self).context("serialize primes")
    }

    /// Iterate over numbers, producing pregenerated pairs for key refresh
    pub fn iter<L>(&self) -> PrimesIterator<L>
    where
        L: cggmp21::security_level::SecurityLevel,
    {
        if self.bitsize != 4 * L::SECURITY_BITS {
            panic!("Attempting to use generated primes while expecting wrong bit size");
        }
        PrimesIterator {
            inner: self.primes.iter(),
            _phantom: std::marker::PhantomData,
        }
    }

    /// Generate `amount * 2` numbers (exactly `amount` of pregenerated pairs
    /// for key refresh) at given security level
    pub fn generate<R, L>(amount: usize, rng: &mut R) -> Self
    where
        L: cggmp21::security_level::SecurityLevel,
        R: RngCore,
    {
        let primes = (0..amount)
            .flat_map(|_| {
                let (p, q) = cggmp21::key_refresh::PregeneratedPrimes::<L>::generate(rng).split();
                [p, q]
            })
            .collect();
        let bitsize = 4 * L::SECURITY_BITS;

        Self { primes, bitsize }
    }
}

/// It's easier to adapt bignumber iterator than fight with serializing
/// PregeneratedPrimes, especially as a quick solution for tests
pub struct PrimesIterator<'a, L> {
    inner: std::slice::Iter<'a, BigNumber>,
    _phantom: std::marker::PhantomData<L>,
}

impl<'a, L> Iterator for PrimesIterator<'a, L>
where
    L: cggmp21::security_level::SecurityLevel,
{
    type Item = cggmp21::key_refresh::PregeneratedPrimes<L>;

    fn next(&mut self) -> Option<Self::Item> {
        let p = self.inner.next()?.clone();
        let q = self.inner.next()?.clone();
        Some(cggmp21::key_refresh::PregeneratedPrimes::new(p, q))
    }
}
