#[generic_tests::define(attrs(tokio::test, test_case::case))]
mod generic {
    use generic_ec::Point;
    use rand::seq::SliceRandom;
    use rand::Rng;
    use round_based::simulation::Simulation;
    use sha2::Sha256;

    use cggmp21::{security_level::ReasonablySecure, ExecutionId};

    #[test_case::case(3, false; "n3")]
    #[test_case::case(5, false; "n5")]
    #[test_case::case(5, true; "n5-reliable")]
    #[tokio::test]
    async fn key_refresh_works<E: generic_ec::Curve>(n: u16, reliable_broadcast: bool)
    where
        Point<E>: generic_ec::coords::HasAffineX<E>,
    {
        let mut rng = rand_dev::DevRng::new();

        let shares = cggmp21_tests::CACHED_SHARES
            .get_shares::<E, ReasonablySecure>(None, n)
            .expect("retrieve cached shares");
        let mut primes = cggmp21_tests::CACHED_PRIMES.iter();

        // Perform refresh

        let eid: [u8; 32] = rng.gen();
        let eid = ExecutionId::new(&eid);
        let mut simulation =
            Simulation::<cggmp21::key_refresh::NonThresholdMsg<E, Sha256, ReasonablySecure>>::new();
        let outputs = shares.iter().map(|share| {
            let party = simulation.add_party();
            let mut party_rng = rng.fork();
            let pregenerated_data = primes.next().expect("Can't fetch primes");
            async move {
                cggmp21::key_refresh(eid, share, pregenerated_data)
                    .enforce_reliable_broadcast(reliable_broadcast)
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

        let mut simulation = Simulation::<cggmp21::signing::msg::Msg<E, Sha256>>::new();

        let eid: [u8; 32] = rng.gen();
        let eid = ExecutionId::new(&eid);

        let message_to_sign = cggmp21::signing::DataToSign::digest::<Sha256>(&[42; 100]);
        let participants = &(0..n).collect::<Vec<_>>();
        let outputs = key_shares.iter().map(|share| {
            let party = simulation.add_party();
            let mut party_rng = rng.fork();
            async move {
                cggmp21::signing(eid, share.core.i, participants, share)
                    .enforce_reliable_broadcast(reliable_broadcast)
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

    #[test_case::case(2, 3, false; "t2n3")]
    #[test_case::case(3, 5, false; "t3n5")]
    #[test_case::case(3, 5, true; "t3n5-reliable")]
    #[tokio::test]
    async fn aux_gen_works<E: generic_ec::Curve>(t: u16, n: u16, reliable_broadcast: bool)
    where
        Point<E>: generic_ec::coords::HasAffineX<E>,
    {
        let mut rng = rand_dev::DevRng::new();

        let shares = cggmp21_tests::CACHED_SHARES
            .get_shares::<E, ReasonablySecure>(Some(t), n)
            .expect("retrieve cached shares");
        let mut primes = cggmp21_tests::CACHED_PRIMES.iter();

        // Perform refresh

        let mut simulation =
            Simulation::<cggmp21::key_refresh::AuxOnlyMsg<Sha256, ReasonablySecure>>::new();

        let eid: [u8; 32] = rng.gen();
        let eid = ExecutionId::new(&eid);

        let outputs = (0..n).map(|i| {
            let party = simulation.add_party();
            let mut party_rng = rng.fork();
            let pregenerated_data = primes.next().expect("Can't fetch primes");
            async move {
                cggmp21::aux_info_gen(eid, i, n, pregenerated_data)
                    .enforce_reliable_broadcast(reliable_broadcast)
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

        let mut simulation = Simulation::<cggmp21::signing::msg::Msg<E, Sha256>>::new();

        let eid: [u8; 32] = rng.gen();
        let eid = ExecutionId::new(&eid);

        let message_to_sign = cggmp21::signing::DataToSign::digest::<Sha256>(&[42; 100]);

        // choose t participants
        let mut participants = (0..n).collect::<Vec<_>>();
        participants.shuffle(&mut rng);
        let participants = &participants[..usize::from(t)];
        println!("Signers: {participants:?}");
        let participants_shares = participants.iter().map(|i| &key_shares[usize::from(*i)]);

        let outputs = participants_shares.zip(0..).map(|(share, i)| {
            let party = simulation.add_party();
            let mut party_rng = rng.fork();
            async move {
                cggmp21::signing(eid, i, participants, share)
                    .enforce_reliable_broadcast(reliable_broadcast)
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
    #[instantiate_tests(<generic_ec::curves::Stark>)]
    mod stark {}
}
