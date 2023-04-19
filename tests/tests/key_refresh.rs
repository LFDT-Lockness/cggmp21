#[generic_tests::define(attrs(tokio::test, test_case::case))]
mod generic {
    use generic_ec::{hash_to_curve::FromHash, Point};
    use rand::seq::SliceRandom;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use round_based::simulation::Simulation;
    use sha2::Sha256;

    use cggmp21::{security_level::ReasonablySecure, ExecutionId};

    #[test_case::case(3; "n3")]
    #[test_case::case(5; "n5")]
    #[tokio::test]
    async fn key_refresh_works<E: generic_ec::Curve>(n: u16)
    where
        generic_ec::Scalar<E>: FromHash,
        Point<E>: generic_ec::coords::HasAffineX<E>,
    {
        let mut rng = rand_dev::DevRng::new();

        let shares = cggmp21_tests::CACHED_SHARES
            .get_shares::<E>(None, n)
            .expect("retrieve cached shares");
        let mut primes = cggmp21_tests::CACHED_PRIMES.iter();

        // Perform refresh

        let refresh_execution_id: [u8; 32] = rng.gen();
        let refresh_execution_id =
            ExecutionId::<E, ReasonablySecure>::from_bytes(&refresh_execution_id);
        let mut simulation =
            Simulation::<cggmp21::key_refresh::msg::Msg<E, Sha256, ReasonablySecure>>::new();
        let outputs = shares.iter().map(|share| {
            let party = simulation.add_party();
            let refresh_execution_id = refresh_execution_id.clone();
            let mut party_rng = ChaCha20Rng::from_seed(rng.gen());
            let pregenerated_data = primes.next().expect("Can't fetch primes");
            async move {
                cggmp21::key_refresh(share, pregenerated_data)
                    .set_execution_id(refresh_execution_id)
                    .start(&mut party_rng, party)
                    .await
            }
        });

        let key_shares = futures::future::try_join_all(outputs)
            .await
            .expect("keygen failed");

        // validate key shares

        for (i, key_share) in key_shares.iter().enumerate() {
            let i = i as u16;
            assert_eq!(i, key_share.core.i);
            assert_eq!(
                key_share.core.shared_public_key,
                key_shares[0].core.shared_public_key
            );
            assert_eq!(key_share.core.rid.as_ref(), key_shares[0].core.rid.as_ref());
            assert_eq!(
                key_share.core.public_shares,
                key_shares[0].core.public_shares
            );
            assert_eq!(
                Point::<E>::generator() * &key_share.core.x,
                key_share.core.public_shares[usize::from(i)]
            );
        }
        assert_eq!(
            key_shares[0].core.shared_public_key,
            key_shares[0].core.public_shares.iter().sum::<Point<E>>()
        );
        for key_share in &key_shares {
            assert_eq!(
                key_share.core.shared_public_key,
                shares[0].core.shared_public_key
            );
        }

        // attempt to sign with new shares and verify the signature

        let signing_execution_id = ExecutionId::<E, ReasonablySecure>::from_bytes(&[228; 32]);
        let mut simulation = Simulation::<cggmp21::signing::msg::Msg<E, Sha256>>::new();
        let message_to_sign = cggmp21::signing::DataToSign::digest::<Sha256>(&[42; 100]);
        let participants = &(0..n).collect::<Vec<_>>();
        let outputs = key_shares.iter().map(|share| {
            let party = simulation.add_party();
            let signing_execution_id = signing_execution_id.clone();
            let mut party_rng = ChaCha20Rng::from_seed(rng.gen());
            async move {
                cggmp21::signing(share.core.i, participants, share)
                    .set_execution_id(signing_execution_id)
                    .sign(&mut party_rng, party, message_to_sign)
                    .await
            }
        });
        let signatures = futures::future::try_join_all(outputs)
            .await
            .expect("signing failed");

        for signature in &signatures {
            signature
                .verify(&key_shares[0].core.shared_public_key, &message_to_sign)
                .expect("signature is not valid");
        }
    }

    #[test_case::case(2, 3; "t2n3")]
    #[test_case::case(3, 5; "t3n5")]
    #[tokio::test]
    async fn aux_gen_works<E: generic_ec::Curve>(t: u16, n: u16)
    where
        generic_ec::Scalar<E>: FromHash,
        Point<E>: generic_ec::coords::HasAffineX<E>,
    {
        let mut rng = rand_dev::DevRng::new();

        let shares = cggmp21_tests::CACHED_SHARES
            .get_shares::<E>(Some(t), n)
            .expect("retrieve cached shares");
        let mut primes = cggmp21_tests::CACHED_PRIMES.iter();

        // Perform refresh

        let refresh_execution_id: [u8; 32] = rng.gen();
        let refresh_execution_id =
            ExecutionId::<E, ReasonablySecure>::from_bytes(&refresh_execution_id);
        let mut simulation = Simulation::<cggmp21::key_refresh::msg::AuxOnlyMsg<Sha256>>::new();
        let outputs = (0..n).map(|i| {
            let party = simulation.add_party();
            let refresh_execution_id = refresh_execution_id.clone();
            let mut party_rng = ChaCha20Rng::from_seed(rng.gen());
            let pregenerated_data = primes.next().expect("Can't fetch primes");
            async move {
                cggmp21::aux_info_gen(i, n, pregenerated_data)
                    .set_execution_id(refresh_execution_id)
                    .start(&mut party_rng, party)
                    .await
            }
        });

        let aux_infos = futures::future::try_join_all(outputs)
            .await
            .expect("keygen failed");

        // validate key shares

        let key_shares = shares
            .into_iter()
            .zip(aux_infos.into_iter())
            .map(|(share, aux)| share.update_aux(aux).unwrap())
            .collect::<Vec<_>>();

        // attempt to sign with new shares and verify the signature

        let signing_execution_id = ExecutionId::<E, ReasonablySecure>::from_bytes(&[228; 32]);
        let mut simulation = Simulation::<cggmp21::signing::msg::Msg<E, Sha256>>::new();
        let message_to_sign = cggmp21::signing::DataToSign::digest::<Sha256>(&[42; 100]);

        // choose t participants
        let mut participants = (0..n).collect::<Vec<_>>();
        participants.shuffle(&mut rng);
        let participants = &participants[..usize::from(t)];
        println!("Signers: {participants:?}");
        let participants_shares = participants.iter().map(|i| &key_shares[usize::from(*i)]);

        let outputs = participants_shares.zip(0..).map(|(share, i)| {
            let party = simulation.add_party();
            let signing_execution_id = signing_execution_id.clone();
            let mut party_rng = ChaCha20Rng::from_seed(rng.gen());
            async move {
                cggmp21::signing(i, participants, share)
                    .set_execution_id(signing_execution_id)
                    .sign(&mut party_rng, party, message_to_sign)
                    .await
            }
        });
        let signatures = futures::future::try_join_all(outputs)
            .await
            .expect("signing failed");

        for signature in &signatures {
            signature
                .verify(&key_shares[0].core.shared_public_key, &message_to_sign)
                .expect("signature is not valid");
        }
    }

    #[instantiate_tests(<cggmp21::supported_curves::Secp256r1>)]
    mod secp256r1 {}
    #[instantiate_tests(<cggmp21::supported_curves::Secp256k1>)]
    mod secp256k1 {}
}
