#[generic_tests::define(attrs(tokio::test, test_case::case))]
mod generic {
    use generic_ec::{hash_to_curve::FromHash, Curve, NonZero, Point, Scalar};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rand_dev::DevRng;
    use round_based::simulation::Simulation;
    use sha2::Sha256;

    use cggmp21::{security_level::ReasonablySecure, ExecutionId};

    #[test_case::case(3; "n3")]
    #[test_case::case(5; "n5")]
    #[test_case::case(7; "n7")]
    #[test_case::case(10; "n10")]
    #[tokio::test]
    async fn keygen_works<E: Curve>(n: u16)
    where
        Scalar<E>: FromHash,
    {
        use cggmp21::keygen::Msg;
        let mut rng = DevRng::new();

        let keygen_execution_id: [u8; 32] = rng.gen();
        let keygen_execution_id =
            ExecutionId::<E, ReasonablySecure>::from_bytes(&keygen_execution_id);
        let mut simulation = Simulation::<Msg<E, ReasonablySecure, Sha256>>::new();

        let mut outputs = vec![];
        for i in 0..n {
            let party = simulation.add_party();
            let keygen_execution_id = keygen_execution_id.clone();
            let mut party_rng = ChaCha20Rng::from_seed(rng.gen());

            outputs.push(async move {
                cggmp21::keygen(i, n)
                    .set_execution_id(keygen_execution_id)
                    .start(&mut party_rng, party)
                    .await
            })
        }

        let key_shares = futures::future::try_join_all(outputs)
            .await
            .expect("keygen failed");

        for (i, key_share) in (0u16..).zip(&key_shares) {
            assert_eq!(key_share.i, i);
            assert_eq!(key_share.shared_public_key, key_shares[0].shared_public_key);
            assert_eq!(key_share.rid.as_ref(), key_shares[0].rid.as_ref());
            assert_eq!(key_share.public_shares, key_shares[0].public_shares);
            assert_eq!(
                Point::<E>::generator() * &key_share.x,
                key_share.public_shares[usize::from(i)]
            );
        }
        assert_eq!(
            key_shares[0].shared_public_key,
            key_shares[0].public_shares.iter().sum::<Point<E>>()
        );
    }

    #[test_case::case(2, 3; "t2n3")]
    #[test_case::case(5, 7; "t5n7")]
    #[tokio::test]
    async fn threshold_keygen_works<E: Curve>(t: u16, n: u16)
    where
        Scalar<E>: FromHash,
    {
        use cggmp21::keygen::ThresholdMsg;
        let mut rng = DevRng::new();

        let keygen_execution_id: [u8; 32] = rng.gen();
        let keygen_execution_id =
            ExecutionId::<E, ReasonablySecure>::from_bytes(&keygen_execution_id);
        let mut simulation = Simulation::<ThresholdMsg<E, ReasonablySecure, Sha256>>::new();

        let mut outputs = vec![];
        for i in 0..n {
            let party = simulation.add_party();
            let keygen_execution_id = keygen_execution_id.clone();
            let mut party_rng = ChaCha20Rng::from_seed(rng.gen());

            outputs.push(async move {
                cggmp21::keygen(i, n)
                    .set_execution_id(keygen_execution_id)
                    .start_thresholdized(t, &mut party_rng, party)
                    .await
            })
        }

        let key_shares = futures::future::try_join_all(outputs)
            .await
            .expect("keygen failed");

        for (i, key_share) in (0u16..).zip(&key_shares) {
            assert_eq!(key_share.i, i);
            assert_eq!(key_share.shared_public_key, key_shares[0].shared_public_key);
            assert_eq!(key_share.rid.as_ref(), key_shares[0].rid.as_ref());
            assert_eq!(key_share.public_shares, key_shares[0].public_shares);
            assert_eq!(
                Point::<E>::generator() * &key_share.x,
                key_share.public_shares[usize::from(i)]
            );
        }

        let points = (1..=n)
            .map(|x| NonZero::from_scalar(Scalar::from(x)).unwrap())
            .collect::<Vec<_>>();
        let secret_key: Scalar<_> = key_shares
            .iter()
            .enumerate()
            .map(|(i, share)| {
                &share.x
                    * cggmp21::utils::lagrange_coefficient(Scalar::zero(), i as u16, &points)
                        .unwrap()
            })
            .sum();
        let public_key = Point::generator() * secret_key;
        assert_eq!(public_key, key_shares[0].shared_public_key);
    }

    #[instantiate_tests(<cggmp21::supported_curves::Secp256k1>)]
    mod secp256k1 {}
    #[instantiate_tests(<cggmp21::supported_curves::Secp256r1>)]
    mod secp256r1 {}
}
