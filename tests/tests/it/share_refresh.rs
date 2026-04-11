use generic_ec::{Curve, Point};
use rand::{seq::SliceRandom, Rng};
use rand_dev::DevRng;

use cggmp24::{key_share::reconstruct_secret_key, ExecutionId};

cggmp24_tests::test_suite! {
    test: non_threshold_share_refresh_works,
    generics: all_curves,
    suites: {
        n3: (3, false),
        n5: (5, false),
        n5_reliable: (5, true),
    }
}
fn non_threshold_share_refresh_works<E>(n: u16, reliable_broadcast: bool)
where
    E: Curve + cggmp24_tests::CurveParams,
{
    let mut rng = DevRng::new();

    // First, generate key shares via keygen
    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let key_shares = round_based::sim::run(n, |i, party| {
        let party = cggmp24_tests::buffer_outgoing(party);
        let mut party_rng = rng.fork();

        async move {
            cggmp24::keygen::<E>(eid, i, n)
                .set_security_level::<E::SecurityLevel>()
                .set_digest::<E::Digest>()
                .enforce_reliable_broadcast(false)
                .start(&mut party_rng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    let original_pk = key_shares[0].shared_public_key;
    let original_sk = reconstruct_secret_key(&key_shares).unwrap();

    // Now run key share refresh
    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let refreshed_shares = round_based::sim::run_with_setup(
        key_shares.iter(),
        |i, party, key_share| {
            let party = cggmp24_tests::buffer_outgoing(party);
            let mut party_rng = rng.fork();
            async move {
                cggmp24::share_refresh::<E>(eid, i, n, key_share)
                    .set_security_level::<E::SecurityLevel>()
                    .set_digest::<E::Digest>()
                    .enforce_reliable_broadcast(reliable_broadcast)
                    .start(&mut party_rng, party)
                    .await
            }
        },
    )
    .unwrap()
    .expect_ok()
    .into_vec();

    // Verify: public key is preserved
    for share in &refreshed_shares {
        assert_eq!(share.shared_public_key, original_pk);
    }

    // Verify: each party's public share matches their secret share
    for (i, share) in refreshed_shares.iter().enumerate() {
        assert_eq!(
            Point::<E>::generator() * &share.x,
            share.public_shares[i]
        );
    }

    // Verify: secret shares changed (with overwhelming probability)
    let shares_changed = key_shares
        .iter()
        .zip(&refreshed_shares)
        .any(|(old, new)| Point::<E>::generator() * &old.x != Point::<E>::generator() * &new.x);
    assert!(shares_changed, "secret shares should change after refresh");

    // Verify: reconstructed secret key is the same
    let refreshed_sk = reconstruct_secret_key(&refreshed_shares).unwrap();
    assert_eq!(
        Point::<E>::generator() * &original_sk,
        Point::<E>::generator() * &refreshed_sk,
        "reconstructed secret key should be preserved"
    );
}

cggmp24_tests::test_suite! {
    test: threshold_share_refresh_works,
    generics: all_curves,
    suites: {
        t2n3: (2, 3, false),
        t3n5: (3, 5, false),
        t3n5_reliable: (3, 5, true),
    }
}
fn threshold_share_refresh_works<E>(t: u16, n: u16, reliable_broadcast: bool)
where
    E: Curve + cggmp24_tests::CurveParams,
{
    let mut rng = DevRng::new();

    // First, generate threshold key shares via keygen
    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let key_shares = round_based::sim::run(n, |i, party| {
        let party = cggmp24_tests::buffer_outgoing(party);
        let mut party_rng = rng.fork();

        async move {
            cggmp24::keygen::<E>(eid, i, n)
                .set_security_level::<E::SecurityLevel>()
                .set_digest::<E::Digest>()
                .enforce_reliable_broadcast(false)
                .set_threshold(t)
                .start(&mut party_rng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    let original_pk = key_shares[0].shared_public_key;

    // Reconstruct secret key from t shares
    let t_shares: Vec<_> = key_shares
        .choose_multiple(&mut rng, t.into())
        .cloned()
        .collect();
    let original_sk = reconstruct_secret_key(&t_shares).unwrap();

    // Now run threshold key share refresh
    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let refreshed_shares = round_based::sim::run_with_setup(
        key_shares.iter(),
        |i, party, key_share| {
            let party = cggmp24_tests::buffer_outgoing(party);
            let mut party_rng = rng.fork();
            async move {
                cggmp24::share_refresh::<E>(eid, i, n, key_share)
                    .set_security_level::<E::SecurityLevel>()
                    .set_digest::<E::Digest>()
                    .enforce_reliable_broadcast(reliable_broadcast)
                    .set_threshold(t)
                    .start(&mut party_rng, party)
                    .await
            }
        },
    )
    .unwrap()
    .expect_ok()
    .into_vec();

    // Verify: public key is preserved
    for share in &refreshed_shares {
        assert_eq!(share.shared_public_key, original_pk);
    }

    // Verify: each party's public share matches their secret share
    for (i, share) in refreshed_shares.iter().enumerate() {
        assert_eq!(
            Point::<E>::generator() * &share.x,
            share.public_shares[i]
        );
    }

    // Verify: secret shares changed
    let shares_changed = key_shares
        .iter()
        .zip(&refreshed_shares)
        .any(|(old, new)| Point::<E>::generator() * &old.x != Point::<E>::generator() * &new.x);
    assert!(shares_changed, "secret shares should change after refresh");

    // Verify: reconstructed secret key is the same (using t random shares)
    let t_refreshed: Vec<_> = refreshed_shares
        .choose_multiple(&mut rng, t.into())
        .cloned()
        .collect();
    let refreshed_sk = reconstruct_secret_key(&t_refreshed).unwrap();
    assert_eq!(
        Point::<E>::generator() * &original_sk,
        Point::<E>::generator() * &refreshed_sk,
        "reconstructed secret key should be preserved after threshold refresh"
    );
}
