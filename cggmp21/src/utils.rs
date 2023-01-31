use digest::Digest;
use generic_ec::{Curve, Scalar};
use paillier_zk::libpaillier::{unknown_order::BigNumber, EncryptionKey};
use paillier_zk::{
    group_element_vs_paillier_encryption_in_range as π_log,
    paillier_affine_operation_in_range as π_aff, paillier_encryption_in_range as π_enc,
};
use rand_core::RngCore;
use serde::Serialize;
use thiserror::Error;

use crate::security_level::SecurityLevel;

/// Samples $x \gets \Z^*_N$
pub fn sample_bigint_in_mult_group<R: RngCore>(rng: &mut R, N: &BigNumber) -> BigNumber {
    loop {
        let x = BigNumber::from_rng(N, rng);
        if x.gcd(N) == BigNumber::one() {
            break x;
        }
    }
}

/// Constructs `EncryptionKey` from $N = p * q$
///
/// `EncryptionKey` from `libpaillier` currently lack of this constructor. This function should
/// be removed once [PR] is merged and changes are released.
///
/// [PR]: https://github.com/mikelodder7/paillier-rs/pull/6
pub fn encryption_key_from_n(N: &BigNumber) -> EncryptionKey {
    // `expect` usage excuse: we reviewed code of `from_bytes` constructor, it never returns error.
    #[allow(clippy::expect_used)]
    EncryptionKey::from_bytes(N.to_bytes()).expect("`from_bytes` should never fail")
}

/// Converts `&Scalar<E>` into BigNumber
pub fn scalar_to_bignumber<E: Curve>(scalar: impl AsRef<Scalar<E>>) -> BigNumber {
    BigNumber::from_slice(scalar.as_ref().to_be_bytes())
}

pub struct SecurityParams {
    pub π_aff: π_aff::SecurityParams,
    pub π_log: π_log::SecurityParams,
    pub π_enc: π_enc::SecurityParams,
}

impl SecurityParams {
    pub fn new<L: SecurityLevel>() -> Self {
        Self {
            π_aff: π_aff::SecurityParams {
                l_x: L::ELL,
                l_y: L::ELL_PRIME,
                epsilon: L::EPSILON,
            },
            π_log: π_log::SecurityParams {
                l: L::ELL,
                epsilon: L::EPSILON,
            },
            π_enc: π_enc::SecurityParams {
                l: L::ELL,
                epsilon: L::EPSILON,
                q: L::q(),
            },
        }
    }
}

pub fn hash_message<T, D>(digest: D, message: &T) -> Result<D, HashMessageError>
where
    T: Serialize,
    D: Digest,
{
    struct Writer<D: Digest>(D);
    impl<D: Digest> std::io::Write for Writer<D> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.update(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Writer(digest);
    serde_json::to_writer(&mut writer, message).map_err(HashMessageError)?;
    Ok(writer.0)
}

#[derive(Debug, Error)]
#[error("failed to hash message")]
pub struct HashMessageError(#[source] serde_json::Error);

pub fn xor_array<A, B>(mut a: A, b: B) -> A
where
    A: AsMut<[u8]>,
    B: AsRef<[u8]>,
{
    a.as_mut()
        .iter_mut()
        .zip(b.as_ref())
        .for_each(|(a_i, b_i)| *a_i ^= *b_i);
    a
}

pub fn vec_of<A: Copy>(len: usize, a: A) -> Vec<A> {
    let mut r = Vec::with_capacity(len);
    r.resize(len, a);
    r
}

pub fn gen_invertible<R: RngCore>(modulo: &BigNumber, rng: &mut R) -> BigNumber {
    loop {
        let r = BigNumber::from_rng(&modulo, rng);
        if r.gcd(&modulo) == BigNumber::one() {
            break r;
        }
    }
}

pub fn collect_blame<I, T, F, E>(iter: I, mut f: F) -> Result<Vec<u16>, E>
where
    I: Iterator<Item = T>,
    F: FnMut(T) -> Result<Option<u16>, E>,
{
    let mut r = Vec::new();
    for x in iter {
        match f(x)? {
            Some(i) => r.push(i),
            None => (),
        }
    }
    Ok(r)
}
