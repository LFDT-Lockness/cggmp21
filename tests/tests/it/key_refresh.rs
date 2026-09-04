use generic_ec::Point;
use rand::Rng;

use crate::keygen::validate_keygen_output;
use cggmp24::ExecutionId;

cggmp24_tests::test_suite! {
    test: key_refresh_works,
    generics: all_curves,
    suites: {
        n3: (3, false),
        n5: (5, false),
        n5_reliable: (5, true),
    }
}
fn key_refresh_works<E>(n: u16, reliable_broadcast: bool)
where
    E: generic_ec::Curve + cggmp24_tests::CurveParams,
    Point<E>: generic_ec::coords::HasAffineX<E>,
{
    let mut rng = rand_dev::DevRng::new();

    // Keygen (non-threshold n-of-n)
    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let incomplete_shares = round_based::sim::run(n, |i, party| {
        let party = cggmp24_tests::buffer_outgoing(party);
        let mut party_rng = rng.fork();
        async move {
            cggmp24::keygen::<E>(eid, i, n)
                .set_security_level::<E::SecurityLevel>()
                .set_digest::<E::Digest>()
                .enforce_reliable_broadcast(reliable_broadcast)
                .start(&mut party_rng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    let original_pk = incomplete_shares[0].shared_public_key;
    let original_public_shares: Vec<_> = incomplete_shares
        .iter()
        .map(|s| s.public_shares.clone())
        .collect();

    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let refreshed = round_based::sim::run(n, |i, party| {
        let party = cggmp24_tests::buffer_outgoing(party);
        let mut party_rng = rng.fork();
        let share = &incomplete_shares[usize::from(i)];
        async move {
            cggmp24_key_refresh::non_threshold::run_key_refresh::<E, _, _, E::SecurityLevel, E::Digest>(
                &mut party_rng,
                party,
                eid,
                i,
                share,
                None,
                reliable_broadcast,
            )
            .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    let shares: Vec<_> = refreshed.into_iter().map(|o| o.share).collect();
    validate_keygen_output::<E, cggmp24_tests::HdDisabled>(&mut rng, &shares);

    for (i, share) in shares.iter().enumerate() {
        assert_eq!(share.shared_public_key, original_pk);
        assert!(share.vss_setup.is_none());
        assert_ne!(share.public_shares, original_public_shares[i]);
    }
}
