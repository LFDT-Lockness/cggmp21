#[generic_tests::define(attrs(tokio::test, test_case::case, cfg_attr))]
mod generic {
    use cggmp21_tests::external_verifier::ExternalVerifier;
    use generic_ec::{coords::HasAffineX, Curve, Point};
    use rand::seq::SliceRandom;
    use rand::{Rng, RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rand_dev::DevRng;
    use round_based::simulation::Simulation;
    use sha2::Sha256;

    use cggmp21::signing::{msg::Msg, DataToSign};
    use cggmp21::{security_level::SecurityLevel128, ExecutionId};

    #[test_case::case(None, 2, false, false; "n2")]
    #[test_case::case(None, 2, true, false; "n2-reliable")]
    #[test_case::case(Some(2), 2, false, false; "t2n2")]
    #[test_case::case(None, 3, false, false; "n3")]
    #[test_case::case(Some(2), 3, false, false; "t2n3")]
    #[test_case::case(Some(3), 3, false, false; "t3n3")]
    #[cfg_attr(feature = "hd-wallets", test_case::case(None, 3, false, true; "n3-hd"))]
    #[cfg_attr(feature = "hd-wallets", test_case::case(Some(2), 3, false, true; "t2n3-hd"))]
    #[cfg_attr(feature = "hd-wallets", test_case::case(Some(3), 3, false, true; "t3n3-hd"))]
    #[tokio::test]
    async fn signing_works<E: Curve, V>(
        t: Option<u16>,
        n: u16,
        reliable_broadcast: bool,
        hd_wallet: bool,
    ) where
        Point<E>: HasAffineX<E>,
        V: ExternalVerifier<E>,
    {
        #[cfg(not(feature = "hd-wallets"))]
        assert!(!hd_wallet);

        let mut rng = DevRng::new();

        let shares = cggmp21_tests::CACHED_SHARES
            .get_shares::<E, SecurityLevel128>(t, n, hd_wallet)
            .expect("retrieve cached shares");

        let mut simulation = Simulation::<Msg<E, Sha256>>::new();

        let eid: [u8; 32] = rng.gen();
        let eid = ExecutionId::new(&eid);

        let mut original_message_to_sign = [0u8; 100];
        rng.fill_bytes(&mut original_message_to_sign);
        let message_to_sign = DataToSign::digest::<Sha256>(&original_message_to_sign);

        #[cfg(feature = "hd-wallets")]
        let derivation_path = if hd_wallet {
            Some(cggmp21_tests::random_derivation_path(&mut rng))
        } else {
            None
        };

        // Choose `t` signers to perform signing
        let t = shares[0].min_signers();
        let mut participants = (0..n).collect::<Vec<_>>();
        participants.shuffle(&mut rng);
        let participants = &participants[..usize::from(t)];
        println!("Signers: {participants:?}");
        let participants_shares = participants.iter().map(|i| &shares[usize::from(*i)]);

        let mut outputs = vec![];
        for (i, share) in (0..).zip(participants_shares) {
            let party = simulation.add_party();
            let mut party_rng = ChaCha20Rng::from_seed(rng.gen());

            #[cfg(feature = "hd-wallets")]
            let derivation_path = derivation_path.clone();

            outputs.push(async move {
                let signing = cggmp21::signing(eid, i, participants, share)
                    .enforce_reliable_broadcast(reliable_broadcast);

                #[cfg(feature = "hd-wallets")]
                let signing = if let Some(derivation_path) = derivation_path {
                    signing.set_derivation_path(derivation_path).unwrap()
                } else {
                    signing
                };

                signing.sign(&mut party_rng, party, message_to_sign).await
            });
        }

        let signatures = futures::future::try_join_all(outputs)
            .await
            .expect("signing failed");

        #[cfg(feature = "hd-wallets")]
        let public_key = if let Some(path) = &derivation_path {
            shares[0]
                .derive_child_public_key(path.iter().cloned())
                .unwrap()
                .public_key
        } else {
            shares[0].shared_public_key
        };
        #[cfg(not(feature = "hd-wallets"))]
        let public_key = shares[0].shared_public_key;

        signatures[0]
            .verify(&public_key, &message_to_sign)
            .expect("signature is not valid");

        assert!(signatures.iter().all(|s_i| signatures[0] == *s_i));

        V::verify(&public_key, &signatures[0], &original_message_to_sign)
            .expect("external verification failed")
    }

    #[instantiate_tests(<cggmp21::supported_curves::Secp256k1, cggmp21_tests::external_verifier::blockchains::Bitcoin>)]
    mod secp256k1 {}
    #[instantiate_tests(<cggmp21::supported_curves::Secp256r1, cggmp21_tests::external_verifier::Noop>)]
    mod secp256r1 {}
    #[instantiate_tests(<cggmp21::supported_curves::Stark, cggmp21_tests::external_verifier::blockchains::StarkNet>)]
    mod stark {}
}
