#[generic_tests::define(attrs(tokio::test, test_case::case, cfg_attr))]
mod generic {
    use generic_ec::{Curve, Point};
    use rand::{seq::SliceRandom, Rng, RngCore};
    use rand_dev::DevRng;
    use round_based::simulation::Simulation;
    use sha2::Sha256;

    use cggmp21::keygen::ThresholdMsg;
    use cggmp21::{
        key_share::{IncompleteKeyShare, KeyShare},
        security_level::SecurityLevel128,
        ExecutionId,
    };

    type Share<E> = KeyShare<E>;
    type Incomplete<E> = IncompleteKeyShare<E>;

    #[test_case::case(2, 3, false; "t2n3")]
    #[test_case::case(3, 5, false; "t3n5")]
    #[cfg_attr(feature = "hd-wallets", test_case::case(3, 5, true; "t3n5-hd"))]
    #[tokio::test]
    async fn full_pipeline_works<E: Curve>(t: u16, n: u16, hd_enabled: bool)
    where
        Point<E>: generic_ec::coords::HasAffineX<E>,
    {
        let mut rng = DevRng::new();
        let incomplete_shares = run_keygen(t, n, hd_enabled, &mut rng).await;
        let shares = run_aux_gen(incomplete_shares, &mut rng).await;
        run_signing(&shares, hd_enabled, &mut rng).await;
    }

    async fn run_keygen<E>(t: u16, n: u16, hd_enabled: bool, rng: &mut DevRng) -> Vec<Incomplete<E>>
    where
        E: Curve,
    {
        #[cfg(not(feature = "hd-wallets"))]
        assert!(!hd_enabled);

        let mut simulation = Simulation::<ThresholdMsg<E, SecurityLevel128, Sha256>>::new();

        let eid: [u8; 32] = rng.gen();
        let eid = ExecutionId::new(&eid);

        let mut outputs = vec![];
        for i in 0..n {
            let party = simulation.add_party();
            let mut party_rng = rng.fork();

            outputs.push(async move {
                let keygen = cggmp21::keygen(eid, i, n).set_threshold(t);

                #[cfg(feature = "hd-wallets")]
                let keygen = keygen.hd_wallet(hd_enabled);

                keygen.start(&mut party_rng, party).await
            })
        }

        futures::future::try_join_all(outputs)
            .await
            .expect("keygen failed")
    }

    async fn run_aux_gen<E>(shares: Vec<Incomplete<E>>, rng: &mut DevRng) -> Vec<Share<E>>
    where
        E: Curve,
    {
        let mut primes = cggmp21_tests::CACHED_PRIMES.iter();
        let n = shares.len().try_into().unwrap();

        let mut simulation =
            Simulation::<cggmp21::key_refresh::AuxOnlyMsg<Sha256, SecurityLevel128>>::new();

        let eid: [u8; 32] = rng.gen();
        let eid = ExecutionId::new(&eid);

        let outputs = (0..n).map(|i| {
            let party = simulation.add_party();
            let mut party_rng = rng.fork();
            let pregenerated_data = primes.next().expect("Can't fetch primes");
            async move {
                cggmp21::aux_info_gen(eid, i, n, pregenerated_data)
                    .start(&mut party_rng, party)
                    .await
            }
        });

        let aux_infos = futures::future::try_join_all(outputs)
            .await
            .expect("keygen failed");

        shares
            .into_iter()
            .zip(aux_infos.into_iter())
            .map(|(core, aux)| Share::make(core, aux).expect("Couldn't make share from parts"))
            .collect()
    }

    async fn run_signing<E>(shares: &[Share<E>], random_derivation_path: bool, rng: &mut DevRng)
    where
        E: Curve,
        Point<E>: generic_ec::coords::HasAffineX<E>,
    {
        #[cfg(not(feature = "hd-wallets"))]
        assert!(!random_derivation_path);

        let t = shares[0].min_signers();
        let n = shares.len().try_into().unwrap();

        #[cfg(feature = "hd-wallets")]
        let (derivation_path, public_key) = if random_derivation_path {
            let (path, child_pub) = cggmp21_tests::random_derivation_path(
                rng,
                &shares[0].extended_public_key().unwrap(),
            );
            (Some(path), child_pub)
        } else {
            (None, shares[0].shared_public_key)
        };
        #[cfg(not(feature = "hd-wallets"))]
        let public_key = shares[0].shared_public_key;

        let mut simulation = Simulation::<cggmp21::signing::msg::Msg<E, Sha256>>::new();

        let eid: [u8; 32] = rng.gen();
        let eid = ExecutionId::new(&eid);

        let mut original_message_to_sign = [0u8; 100];
        rng.fill_bytes(&mut original_message_to_sign);
        let message_to_sign =
            cggmp21::signing::DataToSign::digest::<Sha256>(&original_message_to_sign);

        // Choose `t` signers to perform signing
        let mut participants = (0..n).collect::<Vec<_>>();
        participants.shuffle(rng);
        let participants = &participants[..usize::from(t)];
        println!("Signers: {participants:?}");
        let participants_shares = participants.iter().map(|i| &shares[usize::from(*i)]);

        let mut outputs = vec![];
        for (i, share) in (0..).zip(participants_shares) {
            let party = simulation.add_party();
            let mut party_rng = rng.fork();

            #[cfg(feature = "hd-wallets")]
            let derivation_path = derivation_path.clone();

            outputs.push(async move {
                let signing = cggmp21::signing(eid, i, participants, share);

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

        signatures[0]
            .verify(&public_key, &message_to_sign)
            .expect("signature is not valid");

        assert!(signatures.iter().all(|s_i| signatures[0] == *s_i));
    }

    #[instantiate_tests(<cggmp21::supported_curves::Secp256r1>)]
    mod secp256r1 {}
    #[instantiate_tests(<cggmp21::supported_curves::Secp256k1>)]
    mod secp256k1 {}
    #[instantiate_tests(<cggmp21::supported_curves::Stark>)]
    mod stark {}
}
