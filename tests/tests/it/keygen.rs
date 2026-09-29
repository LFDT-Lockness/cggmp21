use std::iter;

use generic_ec::{Curve, Point};
use rand::{seq::SliceRandom, Rng};
use rand_dev::DevRng;

use cggmp24::{key_share::reconstruct_secret_key, ExecutionId};

cggmp24_tests::test_suite! {
    test: keygen_works,
    generics: all_curves_and_hd,
    suites: {
        n3: (3, false),
        n5: (5, false),
        n7: (7, false),
        n10: (10, false),
        n10_reliable: (10, true),
    }
}
fn keygen_works<E, Hd>(n: u16, reliable_broadcast: bool)
where
    E: Curve + cggmp24_tests::CurveParams,
    Hd: cggmp24_tests::OptionalHd<E>,
{
    let mut rng = DevRng::new();

    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let key_shares = round_based::sim::run(n, |i, party| {
        let party = cggmp24_tests::buffer_outgoing(party);
        let mut party_rng = rng.fork();

        async move {
            let keygen = cggmp24::keygen::<E>(eid, i, n)
                .set_security_level::<E::SecurityLevel>()
                .set_digest::<E::Digest>()
                .enforce_reliable_broadcast(reliable_broadcast);

            #[cfg(feature = "hd-wallet")]
            let keygen = keygen.hd_wallet(Hd::ENABLED);

            keygen.start(&mut party_rng, party).await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    validate_keygen_output::<E, Hd>(&mut rng, &key_shares);
}

cggmp24_tests::test_suite! {
    test: threshold_keygen_works,
    generics: all_curves_and_hd,
    suites: {
        t2n3: (2, 3, false),
        t3n5: (3, 5, false),
        t3n5_reliable: (3, 5, true),
    }
}
fn threshold_keygen_works<E, Hd>(t: u16, n: u16, reliable_broadcast: bool)
where
    E: Curve + cggmp24_tests::CurveParams,
    Hd: cggmp24_tests::OptionalHd<E>,
{
    let mut rng = DevRng::new();

    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let key_shares = round_based::sim::run(n, |i, party| {
        let party = cggmp24_tests::buffer_outgoing(party);
        let mut party_rng = rng.fork();

        async move {
            let keygen = cggmp24::keygen::<E>(eid, i, n)
                .set_security_level::<E::SecurityLevel>()
                .set_digest::<E::Digest>()
                .enforce_reliable_broadcast(reliable_broadcast)
                .set_threshold(t);

            #[cfg(feature = "hd-wallet")]
            let keygen = keygen.hd_wallet(Hd::ENABLED);

            keygen.start(&mut party_rng, party).await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    validate_keygen_output::<E, Hd>(&mut rng, &key_shares);
}

cggmp24_tests::test_suite! {
    test: threshold_keygen_sync_works,
    generics: all_curves_and_hd,
    suites: {
        t3n5: (3, 5),
    }
}
fn threshold_keygen_sync_works<E, Hd>(t: u16, n: u16)
where
    E: Curve + cggmp24_tests::CurveParams,
    Hd: cggmp24_tests::OptionalHd<E>,
{
    let mut rng = DevRng::new();

    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let mut party_rng = iter::repeat_with(|| rng.fork())
        .take(n.into())
        .collect::<Vec<_>>();

    let mut simulation = round_based::sim::Simulation::with_capacity(n);
    for (i, party_rng) in (0..).zip(&mut party_rng) {
        simulation.add_party({
            let keygen = cggmp24::keygen::<E>(eid, i, n)
                .set_security_level::<E::SecurityLevel>()
                .set_digest::<E::Digest>()
                .set_threshold(t);

            #[cfg(feature = "hd-wallet")]
            let keygen = keygen.hd_wallet(Hd::ENABLED);

            keygen.into_state_machine(party_rng)
        })
    }
    let key_shares = simulation
        .run()
        .unwrap()
        .into_vec()
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    validate_keygen_output::<E, Hd>(&mut rng, &key_shares);
}

pub(crate) fn validate_keygen_output<E: generic_ec::Curve, Hd: cggmp24_tests::OptionalHd<E>>(
    rng: &mut impl rand::RngCore,
    key_shares: &[cggmp24::IncompleteKeyShare<E>],
) {
    for (i, key_share) in (0u16..).zip(key_shares) {
        assert_eq!(key_share.i, i);
        assert_eq!(key_share.shared_public_key, key_shares[0].shared_public_key);
        assert_eq!(key_share.public_shares, key_shares[0].public_shares);
        assert_eq!(
            Point::<E>::generator() * &key_share.x,
            key_share.public_shares[usize::from(i)]
        );
    }

    #[cfg(feature = "hd-wallet")]
    if Hd::ENABLED {
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
