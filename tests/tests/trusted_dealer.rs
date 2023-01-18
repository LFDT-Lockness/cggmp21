#[generic_tests::define]
mod test {
    use cggmp21::define_security_level;
    use generic_ec::{Curve, Point, Scalar};
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

        for n in [2, 3, 7, 10] {
            let shares = mock_keygen::<E, DummyLevel, _>(&mut rng, n).unwrap();
            let reconstructed_private_key: Scalar<E> = shares.iter().map(|s_i| &s_i.core.x).sum();
            shares.iter().enumerate().for_each(|(i, s_i)| {
                s_i.validate()
                    .unwrap_or_else(|e| panic!("{i} share not valid: {e}"))
            });
            assert_eq!(
                shares[0].core.shared_public_key,
                Point::generator() * reconstructed_private_key
            );
        }
    }

    #[instantiate_tests(<cggmp21::supported_curves::Secp256r1>)]
    mod secp256r1 {}
    #[instantiate_tests(<cggmp21::supported_curves::Secp256k1>)]
    mod secp256k1 {}
}
