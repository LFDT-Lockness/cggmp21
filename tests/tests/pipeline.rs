#[generic_tests::define(attrs(tokio::test, test_case::case))]
mod generic {
    use generic_ec::{Curve, Point};
    use rand::{seq::SliceRandom, Rng};
    use rand_dev::DevRng;
    use round_based::simulation::Simulation;
    use sha2::Sha256;

    use cggmp21::keygen::ThresholdMsg;
    use cggmp21::{
        key_share::{IncompleteKeyShare, KeyShare},
        security_level::ReasonablySecure,
        ExecutionId,
    };

    type Share<E> = KeyShare<E>;
    type Incomplete<E> = IncompleteKeyShare<E>;

    #[test_case::case(2, 3; "t2n3")]
    #[test_case::case(4, 7; "t4n7")]
    #[tokio::test]
    async fn full_pipeline_works<E: Curve>(t: u16, n: u16)
    where
        Point<E>: generic_ec::coords::HasAffineX<E>,
    {
        let mut rng = DevRng::new();
        let incomplete_shares = run_keygen(t, n, &mut rng).await;
        let shares = run_refresh(incomplete_shares, &mut rng).await;
        run_signing(&shares, &mut rng).await;
    }

    async fn run_keygen<E>(t: u16, n: u16, rng: &mut DevRng) -> Vec<Incomplete<E>>
    where
        E: Curve,
    {
        let mut simulation = Simulation::<ThresholdMsg<E, ReasonablySecure, Sha256>>::new();

        let eid: [u8; 32] = rng.gen();
        let eid = ExecutionId::new(&eid);

        let mut outputs = vec![];
        for i in 0..n {
            let party = simulation.add_party();
            let mut party_rng = rng.fork();

            outputs.push(async move {
                cggmp21::keygen(eid, i, n)
                    .set_threshold(t)
                    .start(&mut party_rng, party)
                    .await
            })
        }

        futures::future::try_join_all(outputs)
            .await
            .expect("keygen failed")
    }

    async fn run_refresh<E>(shares: Vec<Incomplete<E>>, rng: &mut DevRng) -> Vec<Share<E>>
    where
        E: Curve,
    {
        let mut primes = cggmp21_tests::CACHED_PRIMES.iter();
        let n = shares.len().try_into().unwrap();

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

    async fn run_signing<E>(shares: &[Share<E>], rng: &mut DevRng)
    where
        E: Curve,
        Point<E>: generic_ec::coords::HasAffineX<E>,
    {
        use rand::RngCore;

        let t = shares[0].min_signers();
        let n = shares.len().try_into().unwrap();

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

            outputs.push(async move {
                cggmp21::signing(eid, i, participants, share)
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
    #[instantiate_tests(<cggmp21::supported_curves::Stark>)]
    mod stark {}
}
