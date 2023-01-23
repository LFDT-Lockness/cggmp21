use anyhow::{bail, Context, Result};
use cggmp21::{
    key_share::{KeyShare, Valid},
    security_level::ReasonablySecure,
};
use generic_ec::Curve;
use serde_json::{Map, Value};

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
    pub fn from_str(shares: &str) -> Result<Self> {
        let shares = serde_json::from_str(shares).context("parse shares")?;
        Ok(Self { shares })
    }

    pub fn to_string(&self) -> Result<String> {
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
