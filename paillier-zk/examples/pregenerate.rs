//! Pregenerates aux data and keys
//!
//! This example shows how aux data can be generated to set up proofs. Generated data is used by doctests.

use anyhow::{Context, Result};
use fast_paillier::backend::Integer;

fn main() -> Result<()> {
    let mut rng = rand_core::OsRng;

    // Generate primes
    {
        let primes = [(); 4].map(|_| generate_blum_prime(&mut rng, 1536));

        let primes_json = serde_json::to_vec_pretty(&primes).unwrap();
        std::fs::write("./test-data/primes_1536bits.json", primes_json).unwrap();
    }

    // Generate Verifier's aux data
    {
        let p = generate_blum_prime(&mut rng, 1536);
        let q = generate_blum_prime(&mut rng, 1536);
        let n = &p * &q;

        let (s, t) = {
            let phi_n = (p.clone() - 1u8) * (q.clone() - 1u8);
            let r = Integer::sample_in_mult_group_of(&mut rng, &n);
            let lambda = phi_n.random_below(&mut rng);

            let t = r.square().modulo(&n);
            let s = t.pow_mod_ref(&lambda, &n).unwrap().into();

            (s, t)
        };

        let aux = paillier_zk::paillier_encryption_in_range::Aux {
            s,
            t,
            rsa_modulo: n,
            multiexp: None,
            crt: None,
        };

        let aux_json = serde_json::to_vec_pretty(&aux).context("serialzie aux")?;
        std::fs::write("./test-data/verifier_aux.json", aux_json).context("save aux")?;
    }

    // Generate a bunch of paillier keys
    generate_paillier_key(
        &mut rng,
        Some("./test-data/prover_decryption_key.json".as_ref()),
        Some("./test-data/prover_encryption_key.json".as_ref()),
    )?;
    generate_paillier_key(
        &mut rng,
        None, // "someone's" secret decryption key remains unknown
        Some("./test-data/someone_encryption_key0.json".as_ref()),
    )?;
    generate_paillier_key(
        &mut rng,
        None, // "someone's" secret decryption key remains unknown
        Some("./test-data/someone_encryption_key1.json".as_ref()),
    )?;

    Ok(())
}

fn generate_paillier_key(
    rng: &mut impl rand_core::RngCore,
    output_dk: Option<&std::path::Path>,
    output_ek: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    // 1536 bits primes used for paillier key achieve 128 bits security
    let p = generate_blum_prime(rng, 1536);
    let q = generate_blum_prime(rng, 1536);

    let dk: fast_paillier::DecryptionKey =
        fast_paillier::DecryptionKey::from_primes(p, q).context("generated p, q are invalid")?;
    let ek = dk.encryption_key();

    if let Some(path) = output_dk {
        let dk_json = serde_json::to_vec_pretty(&dk).context("serialize decryption key")?;
        std::fs::write(path, dk_json).context("save decryption key")?;
    }

    if let Some(path) = output_ek {
        let ek_json = serde_json::to_vec_pretty(&ek).context("serialize encryption key")?;
        std::fs::write(path, ek_json).context("save encryption key")?;
    }

    Ok(())
}

/// Note: Blum primes MUST NOT be used in real system
///
/// Blum primes are faster to generate so we use them for the tests, however they do not meet
/// security requirements of the proofs. Safe primes MUST BE used intead of blum primes.
///
/// Safe primes can be generated using [`fast_paillier::utils::generate_safe_prime`]
fn generate_blum_prime(rng: &mut impl rand_core::RngCore, bits_size: u32) -> Integer {
    loop {
        let n = Integer::generate_prime(rng, bits_size);
        if n.mod_u(4) == 3 {
            break n;
        }
    }
}
