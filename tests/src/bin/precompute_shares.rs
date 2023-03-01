use anyhow::{Context, Result};
use cggmp21::supported_curves::{Secp256k1, Secp256r1};
use cggmp21::{security_level::ReasonablySecure, trusted_dealer::mock_keygen};
use cggmp21_tests::{PrecomputedKeyShares, PregeneratedPrimes};
use generic_ec::{hash_to_curve::FromHash, Curve, Scalar};
use rand::{rngs::OsRng, CryptoRng, RngCore};

fn main() -> Result<()> {
    let mut args = std::env::args();
    let exec = args.next().unwrap();
    match args.next() {
        Some(cmd) if cmd == "shares" => precompute_shares()?,
        Some(cmd) if cmd == "primes" => precompute_primes()?,
        _ => eprintln!("Usage: {exec} [shares,primes]\n\tPregenerate test data and print it to stdout")
    }
    Ok(())
}

fn precompute_shares() -> Result<()> {
    let mut rng = OsRng;
    let mut cache = PrecomputedKeyShares::empty();

    precompute_shares_for_curve::<Secp256r1, _>(&mut rng, &mut cache)?;
    precompute_shares_for_curve::<Secp256k1, _>(&mut rng, &mut cache)?;

    let cache_json = cache.to_serialized().context("serialize cache")?;
    println!("{cache_json}");
    Ok(())
}

fn precompute_primes() -> Result<()> {
    let mut rng = OsRng;
    let json = PregeneratedPrimes::generate::<_, ReasonablySecure>(10, &mut rng).to_serialized()?;
    println!("{json}");
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
