#[generic_tests::define]
mod test {
    use cggmp21::{define_security_level, key_share::IncompleteKeyShare};
    use generic_ec::{Curve, Point};
    use rand::seq::SliceRandom;
    use rand_dev::DevRng;

    use cggmp21::trusted_dealer::mock_keygen;

    /// Dummy security level that enables fast key generation
    #[derive(Clone)]
    struct DummyLevel;
    define_security_level!(DummyLevel {
        security_bits = 32,
        epsilon = 64,
        ell = 128,
        ell_prime = 128,
        m = 1,
        q = (cggmp21::unknown_order::BigNumber::one() << 128) - 1,
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
                let shares = mock_keygen::<E, DummyLevel, _>(&mut rng, t, n).unwrap();

                // Choose `t` random key shares and reconstruct a secret key
                let t = t.unwrap_or(n);
                let t_shares = shares
                    .choose_multiple(&mut rng, t.into())
                    .map(|s| s.core.clone())
                    .collect::<Vec<_>>();

                let sk = IncompleteKeyShare::reconstruct_secret_key(&t_shares).unwrap();
                assert_eq!(Point::generator() * sk, shares[0].core.shared_public_key);
            }
        }
    }

    #[instantiate_tests(<cggmp21::supported_curves::Secp256r1>)]
    mod secp256r1 {}
    #[instantiate_tests(<cggmp21::supported_curves::Secp256k1>)]
    mod secp256k1 {}
}
