use anyhow::{Context, Result};
use cggmp21::{security_level::ReasonablySecure, trusted_dealer::mock_keygen};
use cggmp21_tests::PrecomputedKeyShares;
use generic_ec::{curves::Secp256r1, hash_to_curve::FromHash, Curve, Scalar};
use rand::{rngs::OsRng, CryptoRng, RngCore};

fn main() -> Result<()> {
    let mut rng = OsRng;
    let mut cache = PrecomputedKeyShares::empty();
    precompute_shares_for_curve::<Secp256r1, _>(&mut rng, &mut cache)?;
    let cache_json = cache.to_string().context("serialize cache")?;
    println!("{}", cache_json);
    Ok(())
}

fn precompute_shares_for_curve<E: Curve, R: RngCore + CryptoRng>(
    rng: &mut R,
    cache: &mut PrecomputedKeyShares,
) -> Result<()>
where
    Scalar<E>: FromHash,
{
    for n in [2, 3, 5, 7, 10] {
        let shares = mock_keygen::<E, ReasonablySecure, _>(rng, n).context("generate shares")?;
        cache.add_shares(n, &shares).context("add shares")?;
    }
    Ok(())
}
