use anyhow::{bail, Context, Result};
use cggmp21::supported_curves::{Secp256k1, Secp256r1, Stark};
use cggmp21::{
    security_level::{KeygenSecurityLevel, SecurityLevel128},
    trusted_dealer,
};
use cggmp21_tests::{generate_blum_prime, PrecomputedKeyShares, PregeneratedPrimes};
use generic_ec::Curve;
use rand::{rngs::OsRng, CryptoRng, RngCore};

fn main() -> Result<()> {
    match args() {
        Operation::GenShares => precompute_shares(),
        Operation::GenOldShares { out_dir } => generate_old_share(&out_dir),
        Operation::GenPrimes => precompute_primes(),
    }
}

#[derive(Clone, Debug)]
#[allow(clippy::enum_variant_names)]
enum Operation {
    GenShares,
    GenOldShares { out_dir: std::path::PathBuf },
    GenPrimes,
}

fn args() -> Operation {
    use bpaf::Parser;
    let shares = bpaf::command("shares", bpaf::pure(Operation::GenShares).to_options())
        .help("Pregenerate key shares");
    let primes = bpaf::command("primes", bpaf::pure(Operation::GenPrimes).to_options())
        .help("Pregenerate primes for key refresh");

    let out_dir = bpaf::long("out-dir")
        .help("path to an existing directory where to save generated shares")
        .argument("PATH");
    let old_shares = bpaf::construct!(Operation::GenOldShares { out_dir })
        .to_options()
        .command("old-shares")
        .help("Generates old shares; see ./test-data/old-shares");

    bpaf::construct!([shares, primes, old_shares])
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
    let json = PregeneratedPrimes::generate::<_, SecurityLevel128>(10, &mut rng).to_serialized()?;
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
            for hd_enabled in [false, true] {
                eprintln!(
                    "t={t:?},n={n},curve={},hd_enabled={hd_enabled}",
                    E::CURVE_NAME
                );
                let primes = std::iter::repeat_with(|| {
                    let p = generate_blum_prime(rng, SecurityLevel128::SECURITY_BITS * 4);
                    let q = generate_blum_prime(rng, SecurityLevel128::SECURITY_BITS * 4);
                    (p, q)
                })
                .take(n.into())
                .collect();
                let shares = trusted_dealer::builder::<E, SecurityLevel128>(n)
                    .set_threshold(t)
                    .set_pregenerated_primes(primes)
                    .hd_wallet(hd_enabled)
                    .generate_shares(rng)
                    .context("generate shares")?;
                cache
                    .add_shares(t, n, hd_enabled, &shares)
                    .context("add shares")?;
            }
        }
    }
    Ok(())
}

fn generate_old_share(out_dir: &std::path::Path) -> Result<()> {
    let stats = out_dir.metadata().context("stat out-dir")?;
    if !stats.is_dir() {
        bail!("`out-dir` is not a dir")
    }

    generate_old_shares_for_curve::<cggmp21::supported_curves::Secp256k1>(out_dir, "secp256k1")?;
    generate_old_shares_for_curve::<cggmp21::supported_curves::Secp256r1>(out_dir, "secp256r1")?;
    generate_old_shares_for_curve::<cggmp21::supported_curves::Stark>(out_dir, "stark")
}

fn generate_old_shares_for_curve<E: Curve>(out_dir: &std::path::Path, prefix: &str) -> Result<()> {
    for enable_threshold in [true, false] {
        for enable_hd in [true, false] {
            let key_shares =
                cggmp21::trusted_dealer::builder::<E, cggmp21::security_level::SecurityLevel128>(5)
                    .set_threshold(if enable_threshold { Some(3) } else { None })
                    .hd_wallet(enable_hd)
                    .generate_core_shares(&mut OsRng)
                    .context("generate core shares")?;
            let out_path = out_dir.join(format!(
                "{prefix}-threshold-{enable_threshold}-hd-{enable_hd}"
            ));

            // serialize via json
            {
                let mut out_path = out_path.clone();
                out_path.set_extension("json");

                let json =
                    serde_json::to_string_pretty(&key_shares[0]).context("serialize into json")?;
                std::fs::write(out_path, json).context("save json to file")?
            }
            // serialize via cbor
            {
                let mut out_path = out_path.clone();
                out_path.set_extension("cbor");

                let mut cbor = vec![];
                ciborium::into_writer(&key_shares[0], &mut cbor).context("serialize into cbor")?;
                std::fs::write(out_path, cbor).context("save cbor to file")?
            }
        }
    }

    Ok(())
}
