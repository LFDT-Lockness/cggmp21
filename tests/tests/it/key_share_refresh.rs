//! Integration tests for key share refresh protocol
//!
//! Tests both non-threshold and threshold refresh, verifying:
//! 1. Secret key is preserved after refresh
//! 2. Individual shares change
//! 3. Public key is preserved
//! 4. Multiple refresh rounds work correctly
//! 5. Old shares are incompatible with new shares

use generic_ec::{Curve, Point};
use rand::Rng;
use rand_dev::DevRng;

use cggmp24::{
    key_share::reconstruct_secret_key, keygen::key_refresh, ExecutionId, IncompleteKeyShare,
};

/// Helper: run non-threshold keygen for n parties
fn run_non_threshold_keygen<E>(rng: &mut DevRng, n: u16) -> Vec<IncompleteKeyShare<E>>
where
    E: Curve,
{
    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    round_based::sim::run(n, |i, party| {
        let mut party_rng = rng.fork();
        async move {
            cggmp24::keygen::<E>(eid, i, n)
                .enforce_reliable_broadcast(false)
                .start(&mut party_rng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec()
}

/// Helper: run threshold keygen for t-of-n
fn run_threshold_keygen<E>(rng: &mut DevRng, t: u16, n: u16) -> Vec<IncompleteKeyShare<E>>
where
    E: Curve,
{
    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    round_based::sim::run(n, |i, party| {
        let mut party_rng = rng.fork();
        async move {
            cggmp24::keygen::<E>(eid, i, n)
                .set_threshold(t)
                .enforce_reliable_broadcast(false)
                .start(&mut party_rng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec()
}

/// Helper: run non-threshold share refresh
fn run_non_threshold_refresh<E>(
    rng: &mut DevRng,
    old_shares: &[IncompleteKeyShare<E>],
) -> Vec<IncompleteKeyShare<E>>
where
    E: Curve,
{
    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    round_based::sim::run_with_setup(old_shares.iter(), |_i, party, share| {
        let mut party_rng = rng.fork();
        async move {
            key_refresh(eid, share)
                .enforce_reliable_broadcast(false)
                .start(&mut party_rng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec()
}

/// Helper: run threshold share refresh
fn run_threshold_refresh<E>(
    rng: &mut DevRng,
    old_shares: &[IncompleteKeyShare<E>],
) -> Vec<IncompleteKeyShare<E>>
where
    E: Curve,
{
    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    round_based::sim::run_with_setup(old_shares.iter(), |_i, party, share| {
        let mut party_rng = rng.fork();
        async move {
            key_refresh(eid, share)
                .set_threshold()
                .enforce_reliable_broadcast(false)
                .start(&mut party_rng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec()
}

// ===== Non-threshold tests =====

#[test]
fn non_threshold_refresh_preserves_secret_n3() {
    use generic_ec::curves::Secp256k1;

    let mut rng = DevRng::new();
    let n = 3u16;

    let old_shares = run_non_threshold_keygen::<Secp256k1>(&mut rng, n);
    let old_pk = old_shares[0].shared_public_key;

    let old_sk = reconstruct_secret_key(&old_shares).unwrap();
    assert_eq!(Point::generator() * &old_sk, old_pk);

    let new_shares = run_non_threshold_refresh(&mut rng, &old_shares);

    // Public key unchanged
    for share in &new_shares {
        assert_eq!(share.shared_public_key, old_pk);
    }

    // Secret key unchanged
    let new_sk = reconstruct_secret_key(&new_shares).unwrap();
    assert_eq!(Point::generator() * &new_sk, old_pk);

    // Individual shares DID change
    for (old, new) in old_shares.iter().zip(&new_shares) {
        assert_ne!(
            Point::<Secp256k1>::generator() * &old.x,
            Point::generator() * &new.x,
            "share {} did not change after refresh",
            old.i
        );
    }

    // Public shares changed but still consistent
    for (i, share) in new_shares.iter().enumerate() {
        assert_eq!(
            Point::<Secp256k1>::generator() * &share.x,
            share.public_shares[i],
            "public share mismatch at index {}",
            i
        );
    }
}

#[test]
fn non_threshold_refresh_multiple_rounds_n3() {
    use generic_ec::curves::Secp256k1;

    let mut rng = DevRng::new();
    let n = 3u16;

    let shares = run_non_threshold_keygen::<Secp256k1>(&mut rng, n);
    let pk = shares[0].shared_public_key;
    let original_sk = reconstruct_secret_key(&shares).unwrap();

    let shares = run_non_threshold_refresh(&mut rng, &shares);
    assert_eq!(shares[0].shared_public_key, pk);

    let shares = run_non_threshold_refresh(&mut rng, &shares);
    assert_eq!(shares[0].shared_public_key, pk);

    let shares = run_non_threshold_refresh(&mut rng, &shares);
    assert_eq!(shares[0].shared_public_key, pk);

    let final_sk = reconstruct_secret_key(&shares).unwrap();
    assert_eq!(
        Point::<Secp256k1>::generator() * &final_sk,
        Point::generator() * &original_sk,
    );
}

#[test]
fn non_threshold_refresh_n5() {
    use generic_ec::curves::Secp256k1;

    let mut rng = DevRng::new();
    let n = 5u16;

    let old_shares = run_non_threshold_keygen::<Secp256k1>(&mut rng, n);
    let pk = old_shares[0].shared_public_key;

    let new_shares = run_non_threshold_refresh(&mut rng, &old_shares);

    let new_sk = reconstruct_secret_key(&new_shares).unwrap();
    assert_eq!(Point::generator() * &new_sk, pk);
}

// ===== Threshold tests =====

#[test]
fn threshold_refresh_preserves_secret_t2n3() {
    use generic_ec::curves::Secp256k1;

    let mut rng = DevRng::new();
    let (t, n) = (2u16, 3u16);

    let old_shares = run_threshold_keygen::<Secp256k1>(&mut rng, t, n);
    let pk = old_shares[0].shared_public_key;

    let old_sk = reconstruct_secret_key(&old_shares[..usize::from(t)]).unwrap();
    assert_eq!(Point::generator() * &old_sk, pk);

    let new_shares = run_threshold_refresh(&mut rng, &old_shares);

    for share in &new_shares {
        assert_eq!(share.shared_public_key, pk);
    }

    assert_eq!(new_shares[0].min_signers(), t);

    let new_sk = reconstruct_secret_key(&new_shares[..usize::from(t)]).unwrap();
    assert_eq!(Point::generator() * &new_sk, pk);

    for (old, new) in old_shares.iter().zip(&new_shares) {
        assert_ne!(
            Point::<Secp256k1>::generator() * &old.x,
            Point::generator() * &new.x,
            "threshold share {} did not change",
            old.i
        );
    }

    assert_eq!(new_shares[0].vss_setup, old_shares[0].vss_setup);
}

#[test]
fn threshold_refresh_multiple_rounds_t2n3() {
    use generic_ec::curves::Secp256k1;

    let mut rng = DevRng::new();
    let (t, n) = (2u16, 3u16);

    let shares = run_threshold_keygen::<Secp256k1>(&mut rng, t, n);
    let pk = shares[0].shared_public_key;

    let shares = run_threshold_refresh(&mut rng, &shares);
    let shares = run_threshold_refresh(&mut rng, &shares);
    let shares = run_threshold_refresh(&mut rng, &shares);

    let sk = reconstruct_secret_key(&shares[..usize::from(t)]).unwrap();
    assert_eq!(Point::generator() * &sk, pk);
}

#[test]
fn threshold_refresh_t3n5() {
    use generic_ec::curves::Secp256k1;

    let mut rng = DevRng::new();
    let (t, n) = (3u16, 5u16);

    let old_shares = run_threshold_keygen::<Secp256k1>(&mut rng, t, n);
    let pk = old_shares[0].shared_public_key;

    let new_shares = run_threshold_refresh(&mut rng, &old_shares);

    let sk_012 = reconstruct_secret_key(&new_shares[0..3]).unwrap();
    assert_eq!(Point::generator() * &sk_012, pk);

    let sk_234 = reconstruct_secret_key(&new_shares[2..5]).unwrap();
    assert_eq!(Point::generator() * &sk_234, pk);
}

// ===== Cross-epoch security tests =====

#[test]
fn old_shares_invalid_after_refresh_non_threshold() {
    use generic_ec::curves::Secp256k1;

    let mut rng = DevRng::new();
    let n = 3u16;

    let old_shares = run_non_threshold_keygen::<Secp256k1>(&mut rng, n);
    let new_shares = run_non_threshold_refresh(&mut rng, &old_shares);

    // Mixing old and new shares should NOT reconstruct correctly.
    let mixed_sum: Point<Secp256k1> = Point::generator() * &old_shares[0].x
        + Point::generator() * &new_shares[1].x
        + Point::generator() * &new_shares[2].x;

    assert_ne!(
        mixed_sum, old_shares[0].shared_public_key,
        "mixed old+new shares should not reconstruct the secret"
    );
}

// ===== Consistency tests =====

#[test]
fn refresh_public_share_consistency() {
    use generic_ec::curves::Secp256k1;

    let mut rng = DevRng::new();
    let n = 3u16;

    let old = run_non_threshold_keygen::<Secp256k1>(&mut rng, n);
    let new_shares = run_non_threshold_refresh(&mut rng, &old);

    for i in 0..n {
        for j in 0..n {
            assert_eq!(
                new_shares[usize::from(i)].public_shares,
                new_shares[usize::from(j)].public_shares,
                "parties {} and {} disagree on public shares",
                i,
                j
            );
        }
    }
}
