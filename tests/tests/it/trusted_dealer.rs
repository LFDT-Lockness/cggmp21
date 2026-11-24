use cggmp24::{define_security_level, key_share::reconstruct_secret_key};
use generic_ec::{Curve, NonZero, Point, Scalar, SecretScalar};
use rand::{seq::SliceRandom, Rng};
use rand_dev::DevRng;

use cggmp24::trusted_dealer;

/// Dummy security level that enables fast key generation
#[derive(Clone)]
struct DummyLevel;
define_security_level!(DummyLevel {
    kappa_bits: 32,
    rsa_prime_bitlen: 100,
    rsa_pubkey_bitlen: 100,
    epsilon: 64,
    ell: 128,
    ell_prime: 128,
    m: 128,
});

cggmp24_tests::test_suite! {
    test: trusted_dealer_generates_correct_shares,
    generics: all_curves,
    suites: {
        test: (),
    }
}
fn trusted_dealer_generates_correct_shares<E: Curve>() {
    let mut rng = DevRng::new();
    let thresholds = [None, Some(2), Some(3), Some(5), Some(7), Some(10)];

    for n in [2, 3, 7, 10] {
        for &t in thresholds
            .iter()
            .filter(|t| t.map(|t| t <= n).unwrap_or(true))
        {
            println!("t={t:?} n={n}");
            let sk = NonZero::<SecretScalar<_>>::random(&mut rng);
            let shares = trusted_dealer::builder::<E, DummyLevel>(n)
                .set_threshold(t)
                .set_shared_secret_key(sk.clone())
                .generate_shares(&mut rng)
                .unwrap();

            // Choose `t` random key shares and reconstruct a secret key
            let t = t.unwrap_or(n);
            let t_shares = shares
                .choose_multiple(&mut rng, t.into())
                .cloned()
                .collect::<Vec<_>>();

            let sk_reconstructed = reconstruct_secret_key(&t_shares).unwrap();
            assert_eq!(
                {
                    let sk: &Scalar<E> = sk.as_ref();
                    sk
                },
                sk_reconstructed.as_ref()
            );
            assert_eq!(
                Point::generator() * &sk_reconstructed,
                shares[0].core.shared_public_key
            );

            // Check that `reconstruct_secret_key` works well with more than `t` shares
            let k = rng.gen_range((n.min(t + 1))..=n);
            let k_shares = shares
                .choose_multiple(&mut rng, k.into())
                .cloned()
                .collect::<Vec<_>>();
            let sk_reconstructed2 = reconstruct_secret_key(&k_shares).unwrap();
            assert_eq!(sk_reconstructed.as_ref(), sk_reconstructed2.as_ref());
        }
    }
}

#[test]
fn rejects_duplicate_vss_preimages() {
    use cggmp24::key_share::{DirtyKeyInfo, Validate, VssSetup};
    use generic_ec::curves::Secp256k1 as E;

    let mut rng = DevRng::new();
    let idx = |v: u16| NonZero::from_scalar(Scalar::<E>::from(v)).unwrap();

    // Linear polynomial f(x) = a0 + a1 * x for t = 2
    let a0 = Scalar::<E>::random(&mut rng);
    let a1 = Scalar::<E>::random(&mut rng);
    let shared_public_key = NonZero::from_point(Point::generator() * a0).unwrap();

    let make_key_info = |preimages: Vec<NonZero<Scalar<E>>>| {
        let public_shares = preimages
            .iter()
            .map(|&x| NonZero::from_point(Point::generator() * (a0 + a1 * x)).unwrap())
            .collect();
        DirtyKeyInfo {
            curve: Default::default(),
            shared_public_key,
            public_shares,
            vss_setup: Some(VssSetup {
                min_signers: 2,
                I: preimages,
            }),
        }
    };

    // Valid distinct preimages
    assert!(make_key_info(vec![idx(1), idx(2), idx(3), idx(4)])
        .validate()
        .is_ok());

    // Duplicate within the first `t` entries
    let err = make_key_info(vec![idx(1), idx(1), idx(3), idx(4)])
        .validate()
        .unwrap_err();
    assert!(format!("{err:?}").contains("INotPairwiseDistinct"));

    // Duplicate spanning the first `t` and remaining `n - t` entries
    let err = make_key_info(vec![idx(1), idx(2), idx(1), idx(4)])
        .validate()
        .unwrap_err();
    assert!(format!("{err:?}").contains("INotPairwiseDistinct"));

    // Duplicate strictly outside the first `t` entries (issue #243)
    let err = make_key_info(vec![idx(1), idx(2), idx(3), idx(3)])
        .validate()
        .unwrap_err();
    assert!(format!("{err:?}").contains("INotPairwiseDistinct"));
}
