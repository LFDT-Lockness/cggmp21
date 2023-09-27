#[generic_tests::define]
mod test {
    use cggmp21::{define_security_level, key_share::reconstruct_secret_key};
    use generic_ec::{Curve, Point, SecretScalar};
    use rand::{seq::SliceRandom, Rng};
    use rand_dev::DevRng;

    use cggmp21::trusted_dealer;

    /// Dummy security level that enables fast key generation
    #[derive(Clone)]
    struct DummyLevel;
    define_security_level!(DummyLevel {
        security_bits = 32,
        epsilon = 64,
        ell = 128,
        ell_prime = 128,
        m = 128,
        q = (cggmp21::rug::Integer::ONE.clone() << 128) - 1,
    });

    #[test]
    fn trusted_dealer_generates_correct_shares<E: Curve>() {
        let mut rng = DevRng::new();
        let thresholds = [None, Some(2), Some(3), Some(5), Some(7), Some(10)];

        for n in [2, 3, 7, 10] {
            for &t in thresholds
                .iter()
                .filter(|t| t.map(|t| t <= n).unwrap_or(true))
            {
                println!("t={t:?} n={n}");
                let sk = SecretScalar::random(&mut rng);
                let shares = trusted_dealer::builder::<E, DummyLevel>(n)
                    .set_threshold(t)
                    .set_shared_secret_key(sk.clone())
                    .generate_shares(&mut rng)
                    .unwrap();

                // Choose `t` random key shares and reconstruct a secret key
                let t = t.unwrap_or(n);
                let t_shares = shares
                    .choose_multiple(&mut rng, t.into())
                    .cloned()
                    .collect::<Vec<_>>();

                let sk_reconstructed = reconstruct_secret_key(&t_shares).unwrap();
                assert_eq!(sk.as_ref(), sk_reconstructed.as_ref());
                assert_eq!(
                    Point::generator() * &sk_reconstructed,
                    shares[0].core.shared_public_key
                );

                // Check that `reconstruct_secret_key` works well with more than `t` shares
                let k = rng.gen_range((n.min(t + 1))..=n);
                let k_shares = shares
                    .choose_multiple(&mut rng, k.into())
                    .cloned()
                    .collect::<Vec<_>>();
                let sk_reconstructed2 = reconstruct_secret_key(&k_shares).unwrap();
                assert_eq!(sk_reconstructed.as_ref(), sk_reconstructed2.as_ref());
            }
        }
    }

    #[instantiate_tests(<cggmp21::supported_curves::Secp256r1>)]
    mod secp256r1 {}
    #[instantiate_tests(<cggmp21::supported_curves::Secp256k1>)]
    mod secp256k1 {}
    #[instantiate_tests(<cggmp21::supported_curves::Stark>)]
    mod stark {}
}
