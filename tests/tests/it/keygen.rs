#[generic_tests::define(attrs(tokio::test, test_case::case, cfg_attr))]
mod generic {
    use std::iter;

    use generic_ec::{Curve, Point};
    use rand::{seq::SliceRandom, Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rand_dev::DevRng;
    use round_based::simulation::{Simulation, SimulationSync};
    use sha2::Sha256;

    use cggmp21::keygen::{NonThresholdMsg, ThresholdMsg};
    use cggmp21::{
        key_share::reconstruct_secret_key, security_level::SecurityLevel128, ExecutionId,
    };

    #[test_case::case(3, false, false; "n3")]
    #[test_case::case(5, false, false; "n5")]
    #[test_case::case(7, false, false; "n7")]
    #[test_case::case(10, false, false; "n10")]
    #[test_case::case(10, true, false; "n10-reliable")]
    #[cfg_attr(feature = "hd-wallets", test_case::case(3, false, true; "n3-hd"))]
    #[cfg_attr(feature = "hd-wallets", test_case::case(5, false, true; "n5-hd"))]
    #[cfg_attr(feature = "hd-wallets", test_case::case(7, false, true; "n7-hd"))]
    #[cfg_attr(feature = "hd-wallets", test_case::case(10, false, true; "n10-hd"))]
    #[tokio::test]
    async fn keygen_works<E: Curve>(n: u16, reliable_broadcast: bool, hd_wallet: bool) {
        #[cfg(not(feature = "hd-wallets"))]
        assert!(!hd_wallet);

        let mut rng = DevRng::new();

        let mut simulation = Simulation::<NonThresholdMsg<E, SecurityLevel128, Sha256>>::new();

        let eid: [u8; 32] = rng.gen();
        let eid = ExecutionId::new(&eid);

        let mut outputs = vec![];
        for i in 0..n {
            let party = simulation.add_party();
            let mut party_rng = rng.fork();

            outputs.push(async move {
                let keygen =
                    cggmp21::keygen(eid, i, n).enforce_reliable_broadcast(reliable_broadcast);

                #[cfg(feature = "hd-wallets")]
                let keygen = keygen.hd_wallet(hd_wallet);

                keygen.start(&mut party_rng, party).await
            })
        }

        let key_shares = futures::future::try_join_all(outputs)
            .await
            .expect("keygen failed");

        validate_keygen_output(&mut rng, &key_shares, hd_wallet);
    }

    #[test_case::case(2, 3, false, false; "t2n3")]
    #[test_case::case(3, 5, false, false; "t3n5")]
    #[test_case::case(3, 5, true, false; "t3n5-reliable")]
    #[cfg_attr(feature = "hd-wallets", test_case::case(2, 3, false, true; "t2n3-hd"))]
    #[cfg_attr(feature = "hd-wallets", test_case::case(3, 5, false, true; "t3n5-hd"))]
    #[tokio::test]
    async fn threshold_keygen_works<E: Curve>(
        t: u16,
        n: u16,
        reliable_broadcast: bool,
        hd_wallet: bool,
    ) {
        #[cfg(not(feature = "hd-wallets"))]
        assert!(!hd_wallet);

        let mut rng = DevRng::new();

        let mut simulation = Simulation::<ThresholdMsg<E, SecurityLevel128, Sha256>>::new();

        let eid: [u8; 32] = rng.gen();
        let eid = ExecutionId::new(&eid);

        let mut outputs = vec![];
        for i in 0..n {
            let party = simulation.add_party();
            let mut party_rng = ChaCha20Rng::from_seed(rng.gen());

            outputs.push(async move {
                let keygen = cggmp21::keygen(eid, i, n)
                    .enforce_reliable_broadcast(reliable_broadcast)
                    .set_threshold(t);

                #[cfg(feature = "hd-wallets")]
                let keygen = keygen.hd_wallet(hd_wallet);

                keygen.start(&mut party_rng, party).await
            })
        }

        let key_shares = futures::future::try_join_all(outputs)
            .await
            .expect("keygen failed");

        validate_keygen_output(&mut rng, &key_shares, hd_wallet);
    }

    #[test_case::case(3, 5, false; "t3n5")]
    #[cfg_attr(feature = "hd-wallets", test_case::case(3, 5, true; "t3n5-hd"))]
    fn threshold_keygen_sync_works<E: Curve>(t: u16, n: u16, hd_wallet: bool) {
        #[cfg(not(feature = "hd-wallets"))]
        assert!(!hd_wallet);

        let mut rng = DevRng::new();

        let eid: [u8; 32] = rng.gen();
        let eid = ExecutionId::new(&eid);

        let mut party_rng = iter::repeat_with(|| rng.fork())
            .take(n.into())
            .collect::<Vec<_>>();

        let mut simulation = SimulationSync::with_capacity(n);
        for (i, party_rng) in (0..).zip(&mut party_rng) {
            simulation.add_party({
                let keygen = cggmp21::keygen::<E>(eid, i, n).set_threshold(t);

                #[cfg(feature = "hd-wallets")]
                let keygen = keygen.hd_wallet(hd_wallet);

                keygen.into_state_machine(party_rng)
            })
        }
        let key_shares = simulation
            .run()
            .unwrap()
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        validate_keygen_output(&mut rng, &key_shares, hd_wallet);
    }

    fn validate_keygen_output<E: generic_ec::Curve>(
        rng: &mut impl rand::RngCore,
        key_shares: &[cggmp21::IncompleteKeyShare<E>],
        hd_wallet: bool,
    ) {
        #[cfg(not(feature = "hd-wallets"))]
        assert!(!hd_wallet);

        for (i, key_share) in (0u16..).zip(key_shares) {
            assert_eq!(key_share.i, i);
            assert_eq!(key_share.shared_public_key, key_shares[0].shared_public_key);
            assert_eq!(key_share.public_shares, key_shares[0].public_shares);
            assert_eq!(
                Point::<E>::generator() * &key_share.x,
                key_share.public_shares[usize::from(i)]
            );
        }

        #[cfg(feature = "hd-wallets")]
        if hd_wallet {
            assert!(key_shares[0].chain_code.is_some());
            for key_share in &key_shares[1..] {
                assert_eq!(key_share.chain_code, key_shares[0].chain_code);
            }
        } else {
            for key_share in key_shares {
                assert_eq!(key_share.chain_code, None);
            }
        }

        // Choose `t` random key shares and reconstruct a secret key
        let t = key_shares[0].min_signers();
        let t_shares = key_shares
            .choose_multiple(rng, t.into())
            .cloned()
            .collect::<Vec<_>>();

        let sk = reconstruct_secret_key(&t_shares).unwrap();
        assert_eq!(Point::generator() * sk, key_shares[0].shared_public_key);
    }

    #[instantiate_tests(<cggmp21::supported_curves::Secp256k1>)]
    mod secp256k1 {}
    #[instantiate_tests(<cggmp21::supported_curves::Secp256r1>)]
    mod secp256r1 {}
    #[instantiate_tests(<cggmp21::supported_curves::Stark>)]
    mod stark {}
}
