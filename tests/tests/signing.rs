#[generic_tests::define(attrs(tokio::test, test_case::case))]
mod generic {
    use cggmp21_tests::external_verifier::ExternalVerifier;
    use generic_ec::{coords::HasAffineX, hash_to_curve::FromHash, Curve, Point, Scalar};
    use rand::{Rng, RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rand_dev::DevRng;
    use round_based::simulation::Simulation;
    use sha2::Sha256;

    use cggmp21::signing::{Message, Msg};
    use cggmp21::{security_level::ReasonablySecure, ExecutionId};

    #[test_case::case(2; "n2")]
    #[test_case::case(3; "n3")]
    #[tokio::test]
    async fn signing_works<E: Curve, V>(n: u16)
    where
        Point<E>: HasAffineX<E>,
        Scalar<E>: FromHash,
        V: ExternalVerifier<E>,
    {
        let mut rng = DevRng::new();

        let shares = cggmp21_tests::CACHED_SHARES
            .get_shares::<E>(n)
            .expect("retrieve cached shares");

        let signing_execution_id: [u8; 32] = rng.gen();
        let signing_execution_id =
            ExecutionId::<E, ReasonablySecure>::from_bytes(&signing_execution_id);
        let mut simulation = Simulation::<Msg<E, Sha256>>::new();

        let mut original_message_to_sign = [0u8; 100];
        rng.fill_bytes(&mut original_message_to_sign);
        let message_to_sign = Message::new::<Sha256>(&original_message_to_sign);

        let mut outputs = vec![];
        for share in &shares {
            let party = simulation.add_party();
            let signing_execution_id = signing_execution_id.clone();
            let mut party_rng = ChaCha20Rng::from_seed(rng.gen());

            outputs.push(async move {
                cggmp21::signing(share)
                    .set_execution_id(signing_execution_id)
                    .sign(&mut party_rng, party, message_to_sign)
                    .await
            });
        }

        let signatures = futures::future::try_join_all(outputs)
            .await
            .expect("signing failed");

        signatures[0]
            .verify(&shares[0].core.shared_public_key, &message_to_sign)
            .expect("signature is not valid");

        assert!(signatures.iter().all(|s_i| signatures[0] == *s_i));

        V::verify(
            &shares[0].core.shared_public_key,
            &signatures[0],
            &original_message_to_sign,
        )
        .expect("external verification failed")
    }

    #[instantiate_tests(<cggmp21::supported_curves::Secp256k1, cggmp21_tests::external_verifier::blockchains::Bitcoin>)]
    mod secp256k1 {}
    #[instantiate_tests(<cggmp21::supported_curves::Secp256r1, cggmp21_tests::external_verifier::Noop>)]
    mod secp256r1 {}
}
