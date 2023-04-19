#[generic_tests::define(attrs(tokio::test, test_case::case))]
mod generic {
    use generic_ec::{hash_to_curve::FromHash, Curve, Point, Scalar};
    use rand::{seq::SliceRandom, Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rand_dev::DevRng;
    use round_based::simulation::Simulation;
    use sha2::Sha256;

    use cggmp21::keygen::ThresholdMsg;
    use cggmp21::{
        key_share::{AnyKeyShare, IncompleteKeyShare, KeyShare},
        security_level::ReasonablySecure,
        ExecutionId,
    };

    type Share<E> = KeyShare<E, ReasonablySecure>;
    type Incomplete<E> = IncompleteKeyShare<E, ReasonablySecure>;

    #[test_case::case(2, 3; "t2n3")]
    #[test_case::case(4, 7; "t4n7")]
    #[tokio::test]
    async fn full_pipeline_works<E: Curve>(t: u16, n: u16)
    where
        Scalar<E>: FromHash,
        Point<E>: generic_ec::coords::HasAffineX<E>,
    {
        let mut rng = DevRng::new();
        let incomplete_shares = run_keygen(t, n, &mut rng).await;
        let shares = run_refresh(incomplete_shares, &mut rng).await;
        run_signing(&shares, &mut rng).await;
    }

    async fn run_keygen<E, R>(t: u16, n: u16, rng: &mut R) -> Vec<Incomplete<E>>
    where
        E: Curve,
        Scalar<E>: FromHash,
        R: rand::RngCore,
    {
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
                    .set_threshold(t)
                    .start(&mut party_rng, party)
                    .await
            })
        }

        futures::future::try_join_all(outputs)
            .await
            .expect("keygen failed")
    }

    async fn run_refresh<E, R>(shares: Vec<Incomplete<E>>, rng: &mut R) -> Vec<Share<E>>
    where
        E: Curve,
        Scalar<E>: FromHash,
        R: rand::RngCore,
    {
        let mut primes = cggmp21_tests::CACHED_PRIMES.iter();
        let n = shares.len().try_into().unwrap();

        let refresh_execution_id: [u8; 32] = rng.gen();
        let refresh_execution_id =
            ExecutionId::<E, ReasonablySecure>::from_bytes(&refresh_execution_id);
        let mut simulation = Simulation::<cggmp21::key_refresh::AuxOnlyMsg<Sha256>>::new();

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

        shares
            .into_iter()
            .zip(aux_infos.into_iter())
            .map(|(core, aux)| Share::make(core, aux).expect("Couldn't make share from parts"))
            .collect()
    }

    async fn run_signing<E, R>(shares: &[Share<E>], rng: &mut R)
    where
        E: Curve,
        Scalar<E>: FromHash,
        Point<E>: generic_ec::coords::HasAffineX<E>,
        R: rand::RngCore,
    {
        let t = shares[0].min_signers();
        let n = shares.len().try_into().unwrap();

        let signing_execution_id: [u8; 32] = rng.gen();
        let signing_execution_id =
            ExecutionId::<E, ReasonablySecure>::from_bytes(&signing_execution_id);
        let mut simulation = Simulation::<cggmp21::signing::msg::Msg<E, Sha256>>::new();

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
            let signing_execution_id = signing_execution_id.clone();
            let mut party_rng = ChaCha20Rng::from_seed(rng.gen());

            outputs.push(async move {
                cggmp21::signing(i, participants, share)
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
    }

    #[instantiate_tests(<cggmp21::supported_curves::Secp256r1>)]
    mod secp256r1 {}
    #[instantiate_tests(<cggmp21::supported_curves::Secp256k1>)]
    mod secp256k1 {}
}
