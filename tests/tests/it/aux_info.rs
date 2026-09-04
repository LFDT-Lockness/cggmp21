use generic_ec::Point;
use rand::seq::SliceRandom;
use rand::Rng;

use cggmp24::{
    key_share::{DirtyKeyShare, Validate},
    ExecutionId,
};

cggmp24_tests::test_suite! {
    test: aux_gen_works,
    generics: all_curves,
    suites: {
        t2n3: (2, 3, false),
        t3n5: (3, 5, false),
        t3n5_reliable: (3, 5, true),
    }
}
fn aux_gen_works<E>(t: u16, n: u16, reliable_broadcast: bool)
where
    E: generic_ec::Curve + cggmp24_tests::CurveParams,
    Point<E>: generic_ec::coords::HasAffineX<E>,
    cggmp24_tests::PrecomputedKeyShares: cggmp24_tests::HasAuxOfLevel<E::SecurityLevel>,
{
    let mut rng = rand_dev::DevRng::new();

    let shares = cggmp24_tests::cached::SHARES.get_shares::<E>(Some(t), n, false);
    let mut primes = cggmp24_tests::cached::PRIMES.iter::<E::SecurityLevel>();

    // Perform refresh

    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let aux_infos = round_based::sim::run(n, |i, party| {
        let party = cggmp24_tests::buffer_outgoing(party);
        let mut party_rng = rng.fork();
        let pregenerated_data = primes.next().expect("Can't fetch primes");
        async move {
            cggmp24::aux_info_gen(eid, i, n, pregenerated_data)
                .set_digest::<E::Digest>()
                .enforce_reliable_broadcast(reliable_broadcast)
                .start(&mut party_rng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    // validate key shares

    let key_shares = shares
        .into_iter()
        .zip(aux_infos)
        .map(|(share, aux)| {
            DirtyKeyShare {
                core: share.into_inner().core,
                aux: aux.into_inner(),
            }
            .validate()
            .unwrap()
        })
        .collect::<Vec<_>>();

    // attempt to sign with new shares and verify the signature

    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let message_to_sign = cggmp24::signing::DataToSign::digest::<E::Digest>(&[42; 100]);

    // choose t participants
    let mut participants = (0..n).collect::<Vec<_>>();
    participants.shuffle(&mut rng);
    let participants = &participants[..usize::from(t)];
    println!("Signers: {participants:?}");
    let participants_shares = participants.iter().map(|i| &key_shares[usize::from(*i)]);

    let mut tracers = (0..t)
        .map(|i| cggmp24::progress::Stderr::new().with_prefix(i))
        .collect::<Vec<_>>();
    let sig = round_based::sim::run_with_setup(
        participants_shares.zip(&mut tracers),
        |i, party, (share, tracer)| {
            let party = cggmp24_tests::buffer_outgoing(party);
            let mut party_rng = rng.fork();
            async move {
                cggmp24::signing(eid, i, participants, share)
                    .set_progress_tracer(tracer)
                    .enforce_reliable_broadcast(reliable_broadcast)
                    .sign(&mut party_rng, party, &message_to_sign)
                    .await
            }
        },
    )
    .unwrap()
    .expect_ok()
    .expect_eq();

    sig.verify(&key_shares[0].core.shared_public_key, &message_to_sign)
        .expect("signature is not valid");
}
