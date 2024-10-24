#[generic_tests::define(attrs(tokio::test, test_case::case, cfg_attr))]
mod generic {
    use std::iter;

    use cggmp21_tests::external_verifier::ExternalVerifier;
    use generic_ec::{coords::HasAffineX, Curve, Point};
    use rand::seq::SliceRandom;
    use rand::{Rng, RngCore};
    use rand_dev::DevRng;
    use round_based::simulation::{Simulation, SimulationSync};
    use sha2::Sha256;

    use cggmp21::key_share::AnyKeyShare;
    use cggmp21::signing::{msg::Msg, DataToSign};
    use cggmp21::{security_level::SecurityLevel128, ExecutionId};

    #[test_case::case(None, 2, false, false; "n2")]
    #[test_case::case(None, 2, true, false; "n2-reliable")]
    #[test_case::case(Some(2), 2, false, false; "t2n2")]
    #[test_case::case(None, 3, false, false; "n3")]
    #[test_case::case(Some(2), 3, false, false; "t2n3")]
    #[test_case::case(Some(3), 3, false, false; "t3n3")]
    #[cfg_attr(feature = "hd-wallet", test_case::case(None, 3, false, true; "n3-hd"))]
    #[cfg_attr(feature = "hd-wallet", test_case::case(Some(2), 3, false, true; "t2n3-hd"))]
    #[cfg_attr(feature = "hd-wallet", test_case::case(Some(3), 3, false, true; "t3n3-hd"))]
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
        #[cfg(not(feature = "hd-wallet"))]
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

        #[cfg(feature = "hd-wallet")]
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
            let mut party_rng = rng.fork();

            #[cfg(feature = "hd-wallet")]
            let derivation_path = derivation_path.clone();

            outputs.push(async move {
                let signing = cggmp21::signing(eid, i, participants, share)
                    .enforce_reliable_broadcast(reliable_broadcast);

                #[cfg(feature = "hd-wallet")]
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

        #[cfg(feature = "hd-wallet")]
        let public_key = if let Some(path) = &derivation_path {
            generic_ec::NonZero::from_point(
                shares[0]
                    .derive_child_public_key::<cggmp21::hd_wallet::Slip10Like, _>(
                        path.iter().cloned(),
                    )
                    .unwrap()
                    .public_key,
            )
            .unwrap()
        } else {
            shares[0].shared_public_key
        };
        #[cfg(not(feature = "hd-wallet"))]
        let public_key = shares[0].shared_public_key;

        signatures[0]
            .verify(&public_key, &message_to_sign)
            .expect("signature is not valid");

        assert!(signatures.iter().all(|s_i| signatures[0] == *s_i));

        V::verify(&public_key, &signatures[0], &original_message_to_sign)
            .expect("external verification failed")
    }

    #[test_case::case(Some(3), 5, false; "t3n5")]
    #[cfg_attr(feature = "hd-wallet", test_case::case(Some(3), 5, true; "t3n5-hd"))]
    #[tokio::test]
    async fn signing_with_presigs<E: Curve, V>(t: Option<u16>, n: u16, hd_wallet: bool)
    where
        Point<E>: HasAffineX<E>,
        V: ExternalVerifier<E>,
    {
        #[cfg(not(feature = "hd-wallet"))]
        assert!(!hd_wallet);

        let mut rng = DevRng::new();

        let shares = cggmp21_tests::CACHED_SHARES
            .get_shares::<E, SecurityLevel128>(t, n, hd_wallet)
            .expect("retrieve cached shares");

        let mut simulation = Simulation::<Msg<E, Sha256>>::new();

        let eid: [u8; 32] = rng.gen();
        let eid = ExecutionId::new(&eid);

        // Choose `t` signers to generate presignature
        let t = shares[0].min_signers();
        let mut participants = (0..n).collect::<Vec<_>>();
        participants.shuffle(&mut rng);
        let participants = &participants[..usize::from(t)];
        println!("Signers: {participants:?}");

        let participants_shares = participants.iter().map(|i| &shares[usize::from(*i)]);

        let mut outputs = vec![];
        for (i, share) in (0..).zip(participants_shares) {
            let party = simulation.add_party();
            let mut party_rng = rng.fork();

            outputs.push(async move {
                cggmp21::signing(eid, i, participants, share)
                    .generate_presignature(&mut party_rng, party)
                    .await
            });
        }

        let presignatures = futures::future::try_join_all(outputs)
            .await
            .expect("signing failed");

        // Now, that we have presignatures generated, we learn (generate) a messages to sign
        // and the derivation path (if hd is enabled)
        let mut original_message_to_sign = [0u8; 100];
        rng.fill_bytes(&mut original_message_to_sign);
        let message_to_sign = DataToSign::digest::<Sha256>(&original_message_to_sign);

        #[cfg(feature = "hd-wallet")]
        let derivation_path = if hd_wallet {
            Some(cggmp21_tests::random_derivation_path(&mut rng))
        } else {
            None
        };

        let partial_signatures = presignatures
            .into_iter()
            .map(|presig| {
                #[cfg(feature = "hd-wallet")]
                let presig = if let Some(derivation_path) = &derivation_path {
                    let epub = shares[0].extended_public_key().expect("not hd wallet");
                    presig
                        .set_derivation_path(epub, derivation_path.iter().copied())
                        .unwrap()
                } else {
                    presig
                };
                presig.issue_partial_signature(message_to_sign)
            })
            .collect::<Vec<_>>();

        let signature = cggmp21::PartialSignature::combine(&partial_signatures)
            .expect("invalid partial sigantures");

        #[cfg(feature = "hd-wallet")]
        let public_key = if let Some(path) = &derivation_path {
            generic_ec::NonZero::from_point(
                shares[0]
                    .derive_child_public_key::<cggmp21::hd_wallet::Slip10Like, _>(
                        path.iter().cloned(),
                    )
                    .unwrap()
                    .public_key,
            )
            .unwrap()
        } else {
            shares[0].shared_public_key
        };
        #[cfg(not(feature = "hd-wallet"))]
        let public_key = shares[0].shared_public_key;

        signature
            .verify(&public_key, &message_to_sign)
            .expect("signature is not valid");

        V::verify(&public_key, &signature, &original_message_to_sign)
            .expect("external verification failed")
    }

    #[test_case::case(None, 3, false; "n3")]
    #[test_case::case(Some(3), 5, false; "t3n5")]
    #[cfg_attr(feature = "hd-wallet", test_case::case(None, 3, true; "n3-hd"))]
    #[cfg_attr(feature = "hd-wallet", test_case::case(Some(3), 5, true; "t3n5-hd"))]
    fn signing_sync<E: Curve, V>(t: Option<u16>, n: u16, hd_wallet: bool)
    where
        Point<E>: HasAffineX<E>,
        V: ExternalVerifier<E>,
    {
        #[cfg(not(feature = "hd-wallet"))]
        assert!(!hd_wallet);

        let mut rng = DevRng::new();

        let shares = cggmp21_tests::CACHED_SHARES
            .get_shares::<E, SecurityLevel128>(t, n, hd_wallet)
            .expect("retrieve cached shares");

        let eid: [u8; 32] = rng.gen();
        let eid = ExecutionId::new(&eid);

        let mut original_message_to_sign = [0u8; 100];
        rng.fill_bytes(&mut original_message_to_sign);
        let message_to_sign = DataToSign::digest::<Sha256>(&original_message_to_sign);

        #[cfg(feature = "hd-wallet")]
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

        let mut signer_rng = iter::repeat_with(|| rng.fork())
            .take(n.into())
            .collect::<Vec<_>>();

        let mut simulation = SimulationSync::with_capacity(n);

        for ((i, share), signer_rng) in (0..).zip(participants_shares).zip(&mut signer_rng) {
            simulation.add_party({
                let signing = cggmp21::signing(eid, i, participants, share);

                #[cfg(feature = "hd-wallet")]
                let signing = if let Some(derivation_path) = derivation_path.clone() {
                    signing.set_derivation_path(derivation_path).unwrap()
                } else {
                    signing
                };

                signing.sign_sync(signer_rng, message_to_sign)
            })
        }

        let signatures = simulation
            .run()
            .unwrap()
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        #[cfg(feature = "hd-wallet")]
        let public_key = if let Some(path) = &derivation_path {
            generic_ec::NonZero::from_point(
                shares[0]
                    .derive_child_public_key::<cggmp21::hd_wallet::Slip10Like, _>(
                        path.iter().cloned(),
                    )
                    .unwrap()
                    .public_key,
            )
            .unwrap()
        } else {
            shares[0].shared_public_key
        };
        #[cfg(not(feature = "hd-wallet"))]
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
