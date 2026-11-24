use std::iter;

use cggmp24_tests::external_verifier::ExternalVerifier;
use generic_ec::{coords::HasAffineX, Curve, Point};
use rand::seq::SliceRandom;
use rand::{Rng, RngCore};
use rand_dev::DevRng;

use cggmp24::key_share::AnyKeyShare;
use cggmp24::signing::DataToSign;
use cggmp24::ExecutionId;

cggmp24_tests::test_suite! {
    test: signing_works,
    generics: all_curves_and_hd,
    suites: {
        n2: (None, 2, false),
        n2_reliable: (None, 2, true),
        t2n2: (Some(2), 2, false),
        n3: (None, 3, false),
        t2n3: (Some(2), 3, false),
        t3n3: (Some(3), 3, false),
    }
}

fn signing_works<E, Hd>(t: Option<u16>, n: u16, reliable_broadcast: bool)
where
    E: Curve + cggmp24_tests::CurveParams,
    Point<E>: HasAffineX<E>,
    Hd: cggmp24_tests::OptionalHd<E>,
    cggmp24_tests::PrecomputedKeyShares: cggmp24_tests::HasAuxOfLevel<E::SecurityLevel>,
{
    let mut rng = DevRng::new();

    let shares = cggmp24_tests::cached::SHARES.get_shares::<E>(t, n, Hd::ENABLED);

    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let mut original_message_to_sign = [0u8; 100];
    rng.fill_bytes(&mut original_message_to_sign);
    let message_to_sign = DataToSign::digest::<E::Digest>(&original_message_to_sign);

    let optional_hd = Hd::generate_derivation_path(&mut rng);

    // Choose `t` signers to perform signing
    let t = shares[0].min_signers();
    let mut participants = (0..n).collect::<Vec<_>>();
    participants.shuffle(&mut rng);
    let participants = &participants[..usize::from(t)];
    println!("Signers: {participants:?}");
    let participants_shares = participants.iter().map(|i| &shares[usize::from(*i)]);

    let sig = round_based::sim::run_with_setup(participants_shares, |i, party, share| {
        let party = cggmp24_tests::buffer_outgoing(party);
        let mut party_rng = rng.fork();

        let signing = cggmp24::signing(eid, i, participants, share)
            .set_digest::<E::Digest>()
            .enforce_reliable_broadcast(reliable_broadcast);

        let signing = optional_hd.apply(signing);

        async move { signing.sign(&mut party_rng, party, &message_to_sign).await }
    })
    .unwrap()
    .expect_ok()
    .expect_eq();

    let public_key = optional_hd.derive_child_pk(&shares[0].core);

    sig.verify(&public_key, &message_to_sign)
        .expect("signature is not valid");

    E::ExVerifier::verify(&public_key, &sig, &original_message_to_sign)
        .expect("external verification failed")
}

cggmp24_tests::test_suite! {
    test: signing_with_presigs,
    generics: all_curves_and_hd,
    suites: {
        t3n5: (Some(3), 5),
    }
}

fn signing_with_presigs<E, Hd>(t: Option<u16>, n: u16)
where
    E: Curve + cggmp24_tests::CurveParams,
    Point<E>: HasAffineX<E>,
    Hd: cggmp24_tests::OptionalHd<E>,
    cggmp24_tests::PrecomputedKeyShares: cggmp24_tests::HasAuxOfLevel<E::SecurityLevel>,
{
    let mut rng = DevRng::new();

    let shares = cggmp24_tests::cached::SHARES.get_shares::<E>(t, n, Hd::ENABLED);

    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    // Choose `t` signers to generate presignature
    let t = shares[0].min_signers();
    let mut participants = (0..n).collect::<Vec<_>>();
    participants.shuffle(&mut rng);
    let participants = &participants[..usize::from(t)];
    println!("Signers: {participants:?}");

    let participants_shares = participants.iter().map(|i| &shares[usize::from(*i)]);

    let optional_hd = Hd::generate_derivation_path(&mut rng);

    let presigs = round_based::sim::run_with_setup(participants_shares, |i, party, share| {
        let party = cggmp24_tests::buffer_outgoing(party);
        let mut party_rng = rng.fork();
        let optional_hd = optional_hd.clone();

        async move {
            let signing = cggmp24::signing(eid, i, participants, share).set_digest::<E::Digest>();
            let signing = optional_hd.apply(signing);
            signing.generate_presignature(&mut party_rng, party).await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    // Now, that we have presignatures generated, we learn (generate) a messages to sign
    // and the derivation path (if hd is enabled)
    let mut original_message_to_sign = [0u8; 100];
    rng.fill_bytes(&mut original_message_to_sign);
    let message_to_sign = DataToSign::digest::<E::Digest>(&original_message_to_sign);

    // all presig commitments must be same
    for (i, (_, commitment)) in presigs.iter().enumerate() {
        assert_eq!(presigs[0].1, *commitment, "cmp(0, {i})")
    }
    let (_, commitments) = presigs[0].clone();

    let partial_signatures = presigs
        .into_iter()
        .map(|(presig, _commitments)| presig.issue_partial_signature(message_to_sign))
        .collect::<Vec<_>>();

    let signature =
        cggmp24::PartialSignature::combine(&partial_signatures, &commitments, message_to_sign)
            .expect("invalid partial sigantures");

    let public_key = optional_hd.derive_child_pk(&shares[0].core);

    signature
        .verify(&public_key, &message_to_sign)
        .expect("signature is not valid");

    E::ExVerifier::verify(&public_key, &signature, &original_message_to_sign)
        .expect("external verification failed")
}

cggmp24_tests::test_suite! {
    test: signing_sync,
    generics: all_curves_and_hd,
    suites: {
        n3: (None, 3),
        t3n5: (Some(3), 5),
    }
}

fn signing_sync<E, Hd>(t: Option<u16>, n: u16)
where
    E: Curve + cggmp24_tests::CurveParams,
    Point<E>: HasAffineX<E>,
    Hd: cggmp24_tests::OptionalHd<E>,
    cggmp24_tests::PrecomputedKeyShares: cggmp24_tests::HasAuxOfLevel<E::SecurityLevel>,
{
    let mut rng = DevRng::new();

    let shares = cggmp24_tests::cached::SHARES.get_shares::<E>(t, n, Hd::ENABLED);

    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let mut original_message_to_sign = [0u8; 100];
    rng.fill_bytes(&mut original_message_to_sign);
    let message_to_sign = DataToSign::digest::<E::Digest>(&original_message_to_sign);

    let optional_hd = Hd::generate_derivation_path(&mut rng);

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

    let mut simulation = round_based::sim::Simulation::with_capacity(n);

    for ((i, share), signer_rng) in (0..).zip(participants_shares).zip(&mut signer_rng) {
        simulation.add_party({
            let signing = cggmp24::signing(eid, i, participants, share).set_digest::<E::Digest>();
            let signing = optional_hd.apply(signing);

            signing.sign_sync(signer_rng, &message_to_sign)
        })
    }

    let sig = simulation.run().unwrap().expect_ok().expect_eq();

    let public_key = optional_hd.derive_child_pk(&shares[0].core);

    sig.verify(&public_key, &message_to_sign)
        .expect("signature is not valid");

    E::ExVerifier::verify(&public_key, &sig, &original_message_to_sign)
        .expect("external verification failed")
}
