use digest::Digest;
use generic_ec::{Curve, Scalar};
use paillier_zk::libpaillier::{unknown_order::BigNumber, EncryptionKey};
use paillier_zk::{
    group_element_vs_paillier_encryption_in_range as π_log,
    paillier_affine_operation_in_range as π_aff, paillier_encryption_in_range as π_enc,
};
use rand_core::RngCore;
use round_based::rounds_router::simple_store::RoundMsgs;
use round_based::{MsgId, PartyIndex};
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
                q: L::q(),
            },
            π_log: π_log::SecurityParams {
                l: L::ELL,
                epsilon: L::EPSILON,
                q: L::q(),
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

/// For some messages it is possible to precisely identify where the fault
/// happened and which party is to blame. Use this struct to collect present the
/// blame.
///
/// In the future we might want to replace the data_message and proof_message
/// with a generic vec of messages.
#[derive(Debug)]
pub struct AbortBlame {
    /// Party which can be blamed for breaking the protocol
    pub faulty_party: PartyIndex,
    /// Message with initial data
    pub data_message: MsgId,
    /// Message with some kind of proof related to the data
    pub proof_message: MsgId,
}

impl AbortBlame {
    pub fn new(faulty_party: PartyIndex, data_message: MsgId, proof_message: MsgId) -> Self {
        Self {
            faulty_party,
            data_message,
            proof_message,
        }
    }
}

/// Filter returns `true` for every __faulty__ message pair
pub fn collect_blame<D, P, F>(
    data_messages: &RoundMsgs<D>,
    proof_messages: &RoundMsgs<P>,
    mut filter: F,
) -> Vec<AbortBlame>
where
    F: FnMut(PartyIndex, &D, &P) -> bool,
{
    data_messages
        .iter_indexed()
        .zip(proof_messages.iter_indexed())
        .filter_map(|((j, data_msg_id, data), (_, proof_msg_id, proof))| {
            if filter(j, data, proof) {
                Some(AbortBlame::new(j, data_msg_id, proof_msg_id))
            } else {
                None
            }
        })
        .collect()
}

/// Filter returns `true` for every __faulty__ message. Data and proof are set
/// to the same message.
pub fn collect_simple_blame<D, F>(messages: &RoundMsgs<D>, mut filter: F) -> Vec<AbortBlame>
where
    F: FnMut(&D) -> bool,
{
    messages
        .iter_indexed()
        .filter_map(|(j, msg_id, data)| {
            if filter(data) {
                Some(AbortBlame::new(j, msg_id, msg_id))
            } else {
                None
            }
        })
        .collect()
}

/// Same as [`collect_blame`], but filter can fail, in which case whole blame
/// collection will fail. So to not lose security the error type should be some
/// kind of unrecoverable internal assertion failure.
pub fn try_collect_blame<E, D, P, F>(
    data_messages: &RoundMsgs<D>,
    proof_messages: &RoundMsgs<P>,
    mut filter: F,
) -> Result<Vec<AbortBlame>, E>
where
    F: FnMut(PartyIndex, &D, &P) -> Result<bool, E>,
{
    let mut r = Vec::new();
    for ((j, data_msg_id, data), (_, proof_msg_id, proof)) in data_messages
        .iter_indexed()
        .zip(proof_messages.iter_indexed())
    {
        if filter(j, data, proof)? {
            r.push(AbortBlame::new(j, data_msg_id, proof_msg_id));
        }
    }
    Ok(r)
}

/// Iterate peers of i-th party
pub fn iter_peers(i: u16, n: u16) -> impl Iterator<Item = u16> {
    (0..n).filter(move |x| *x != i)
}

/// Get i-th message from j-th party in vector
pub fn mine_from<V, O>(i: u16, j: u16, v: &V) -> &O
where
    V: std::ops::Index<usize, Output = O>,
{
    if i < j {
        v.index(usize::from(i))
    } else {
        v.index(usize::from(i) - 1)
    }
}

/// Drop n-th item from iteration
pub fn but_nth<T, I: Iterator<Item = T>>(n: u16, iter: I) -> impl Iterator<Item = T> {
    iter.enumerate()
        .filter(move |(i, _)| *i != usize::from(n))
        .map(|(_, x)| x)
}

/// Binary search for rounded down square root. For non-positive numbers returns
/// one
pub fn sqrt(x: &BigNumber) -> BigNumber {
    let mut low = BigNumber::one();
    let mut high = x.clone();
    while low < &high - 1 {
        let mid = (&high + &low) / 2;
        let test: BigNumber = &mid * &mid;
        match test.cmp(x) {
            std::cmp::Ordering::Equal => return mid,
            std::cmp::Ordering::Less => {
                low = mid;
            }
            std::cmp::Ordering::Greater => {
                high = mid;
            }
        }
    }
    low
}

#[cfg(test)]
mod test {
    #[test]
    fn test_sqrt() {
        use super::{sqrt, BigNumber};
        assert_eq!(sqrt(&BigNumber::from(-5)), BigNumber::from(1));
        assert_eq!(sqrt(&BigNumber::from(1)), BigNumber::from(1));
        assert_eq!(sqrt(&BigNumber::from(2)), BigNumber::from(1));
        assert_eq!(sqrt(&BigNumber::from(3)), BigNumber::from(1));
        assert_eq!(sqrt(&BigNumber::from(4)), BigNumber::from(2));
        assert_eq!(sqrt(&BigNumber::from(5)), BigNumber::from(2));
        assert_eq!(sqrt(&BigNumber::from(6)), BigNumber::from(2));
        assert_eq!(sqrt(&BigNumber::from(7)), BigNumber::from(2));
        assert_eq!(sqrt(&BigNumber::from(8)), BigNumber::from(2));
        assert_eq!(sqrt(&BigNumber::from(9)), BigNumber::from(3));
        assert_eq!(
            sqrt(&(BigNumber::from(1) << 1024)),
            BigNumber::from(1) << 512
        );

        let modulo = BigNumber::one() << 1024;
        let mut rng = rand_dev::DevRng::new();
        for _ in 0..100 {
            let x = BigNumber::from_rng(&modulo, &mut rng);
            let root = sqrt(&x);
            assert!(&root * &root <= x);
            let root = root + 1;
            assert!(&root * &root > x);
        }
    }
}
