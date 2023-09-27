use anyhow::{Context, Result};
use cggmp21::supported_curves::{Secp256k1, Secp256r1, Stark};
use cggmp21::{
    security_level::{ReasonablySecure, SecurityLevel},
    trusted_dealer,
};
use cggmp21_tests::{generate_blum_prime, PrecomputedKeyShares, PregeneratedPrimes};
use generic_ec::Curve;
use rand::{rngs::OsRng, CryptoRng, RngCore};

fn main() -> Result<()> {
    match args() {
        Operation::GenShares => precompute_shares(),
        Operation::GenPrimes => precompute_primes(),
    }
}

#[derive(Clone, Debug)]
enum Operation {
    GenShares,
    GenPrimes,
}

fn args() -> Operation {
    use bpaf::Parser;
    let shares = bpaf::command("shares", bpaf::pure(Operation::GenShares).to_options())
        .help("Pregenerate key shares");
    let primes = bpaf::command("primes", bpaf::pure(Operation::GenPrimes).to_options())
        .help("Pregenerate primes for key refresh");
    bpaf::construct!([shares, primes])
        .to_options()
        .descr("Pregenerate test data and print it to stdout")
        .run()
}

fn precompute_shares() -> Result<()> {
    let mut rng = OsRng;
    let mut cache = PrecomputedKeyShares::empty();

    precompute_shares_for_curve::<Secp256r1, _>(&mut rng, &mut cache)?;
    precompute_shares_for_curve::<Secp256k1, _>(&mut rng, &mut cache)?;
    precompute_shares_for_curve::<Stark, _>(&mut rng, &mut cache)?;

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
) -> Result<()> {
    for n in [2, 3, 5, 7, 10] {
        let threshold_values = [None, Some(2), Some(3), Some(5), Some(7)];
        for t in threshold_values
            .into_iter()
            .filter(|t| t.map(|t| t <= n).unwrap_or(true))
        {
            eprintln!("t={t:?},n={n},curve={}", E::CURVE_NAME);
            let primes = std::iter::repeat_with(|| {
                let p = generate_blum_prime(rng, ReasonablySecure::SECURITY_BITS * 4);
                let q = generate_blum_prime(rng, ReasonablySecure::SECURITY_BITS * 4);
                (p, q)
            })
            .take(n.into())
            .collect();
            let shares = trusted_dealer::builder::<E, ReasonablySecure>(n)
                .set_threshold(t)
                .set_pregenerated_primes(primes)
                .generate_shares(rng)
                .context("generate shares")?;
            cache.add_shares(t, n, &shares).context("add shares")?;
        }
    }
    Ok(())
}
