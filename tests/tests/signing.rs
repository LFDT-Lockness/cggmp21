#[generic_tests::define(attrs(tokio::test, test_case::case))]
mod generic {
    use cggmp21_tests::external_verifier::ExternalVerifier;
    use generic_ec::{coords::HasAffineX, hash_to_curve::FromHash, Curve, Point, Scalar};
    use rand::seq::SliceRandom;
    use rand::{Rng, RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rand_dev::DevRng;
    use round_based::simulation::Simulation;
    use sha2::Sha256;

    use cggmp21::signing::{msg::Msg, DataToSign};
    use cggmp21::{security_level::ReasonablySecure, ExecutionId};

    #[test_case::case(None, 2, false; "n2")]
    #[test_case::case(None, 2, true; "n2-reliable")]
    #[test_case::case(Some(2), 2, false; "t2n2")]
    #[test_case::case(None, 3, false; "n3")]
    #[test_case::case(Some(2), 3, false; "t2n3")]
    #[test_case::case(Some(3), 3, false; "t3n3")]
    #[tokio::test]
    async fn signing_works<E: Curve, V>(t: Option<u16>, n: u16, reliable_broadcast: bool)
    where
        Point<E>: HasAffineX<E>,
        Scalar<E>: FromHash,
        V: ExternalVerifier<E>,
    {
        let mut rng = DevRng::new();

        let shares = cggmp21_tests::CACHED_SHARES
            .get_shares::<E, ReasonablySecure>(t, n)
            .expect("retrieve cached shares");

        let mut simulation = Simulation::<Msg<E, Sha256>>::new();

        let eid: [u8; 32] = rng.gen();
        let eid = ExecutionId::new(&eid);

        let mut original_message_to_sign = [0u8; 100];
        rng.fill_bytes(&mut original_message_to_sign);
        let message_to_sign = DataToSign::digest::<Sha256>(&original_message_to_sign);

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

            outputs.push(async move {
                cggmp21::signing(eid, i, participants, share)
                    .enforce_reliable_broadcast(reliable_broadcast)
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
