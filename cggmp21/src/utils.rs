use generic_ec::{Curve, Scalar};
use paillier_zk::rug::{self, Integer};
use paillier_zk::{
    group_element_vs_paillier_encryption_in_range as pi_log,
    paillier_affine_operation_in_range as pi_aff, paillier_encryption_in_range as pi_enc,
};
use round_based::rounds_router::simple_store::RoundMsgs;
use round_based::{MsgId, PartyIndex};

use crate::security_level::SecurityLevel;

pub use paillier_zk::fast_paillier::utils::external_rand;

mod hex_or_bin;
pub use hex_or_bin::HexOrBin;

/// Converts `&Scalar<E>` into Integer
pub fn scalar_to_bignumber<E: Curve>(scalar: impl AsRef<Scalar<E>>) -> Integer {
    Integer::from_digits(&scalar.as_ref().to_be_bytes(), rug::integer::Order::Msf)
}

pub struct SecurityParams {
    pub pi_aff: pi_aff::SecurityParams,
    pub pi_log: pi_log::SecurityParams,
    pub pi_enc: pi_enc::SecurityParams,
}

impl SecurityParams {
    pub fn new<L: SecurityLevel>() -> Self {
        Self {
            pi_aff: pi_aff::SecurityParams {
                l_x: L::ELL,
                l_y: L::ELL_PRIME,
                epsilon: L::EPSILON,
                q: L::q(),
            },
            pi_log: pi_log::SecurityParams {
                l: L::ELL,
                epsilon: L::EPSILON,
                q: L::q(),
            },
            pi_enc: pi_enc::SecurityParams {
                l: L::ELL,
                epsilon: L::EPSILON,
                q: L::q(),
            },
        }
    }
}

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

/// Drop n-th item from iteration
pub fn but_nth<T, I: IntoIterator<Item = T>>(n: u16, iter: I) -> impl Iterator<Item = T> {
    iter.into_iter()
        .enumerate()
        .filter(move |(i, _)| *i != usize::from(n))
        .map(|(_, x)| x)
}

/// Binary search for rounded down square root. For non-positive numbers returns
/// one
pub fn sqrt(x: &Integer) -> Integer {
    if x.cmp0().is_le() {
        Integer::ONE.clone()
    } else {
        x.sqrt_ref().into()
    }
}

/// Partition into vector of errors and vector of values
pub fn partition_results<I, A, B>(iter: I) -> (Vec<A>, Vec<B>)
where
    I: Iterator<Item = Result<A, B>>,
{
    let mut oks = Vec::new();
    let mut errs = Vec::new();
    for i in iter {
        match i {
            Ok(ok) => oks.push(ok),
            Err(err) => errs.push(err),
        }
    }
    (oks, errs)
}

/// Returns `[list[indexes[0]], list[indexes[1]], ..., list[indexes[n-1]]]`
///
/// Result is `None` if any of `indexes[i]` is out of range of `list`
pub fn subset<T: Clone, I: Into<usize> + Copy>(indexes: &[I], list: &[T]) -> Option<Vec<T>> {
    indexes
        .iter()
        .map(|&i| list.get(i.into()).map(T::clone))
        .collect()
}

/// Generates **unsafe** blum primes
///
/// Blum primes are faster to generate than safe primes, and they don't break correctness of CGGMP protocol.
/// However, they do break security of the protocol.
///
/// Only supposed to be used in the tests.
#[cfg(test)]
pub fn generate_blum_prime(rng: &mut impl rand_core::RngCore, bits_size: u32) -> Integer {
    loop {
        let mut n: Integer = Integer::random_bits(bits_size, &mut external_rand(rng)).into();
        n.set_bit(bits_size - 1, true);
        n.next_prime_mut();

        if n.mod_u(4) == 3 {
            break n;
        }
    }
}

/// Unambiguous encoding for different types for which it was not defined
pub mod encoding {
    use paillier_zk::rug;

    pub fn integer<B: udigest::Buffer>(
        x: &rug::Integer,
        encoder: udigest::encoding::EncodeValue<B>,
    ) {
        encoder
            .encode_leaf()
            .chain(x.to_digits(rug::integer::Order::Msf));
    }

    pub fn integers_list<B: udigest::Buffer>(
        list: &[rug::Integer],
        encoder: udigest::encoding::EncodeValue<B>,
    ) {
        let mut encoder = encoder.encode_list();
        for x in list {
            integer(x, encoder.add_item())
        }
    }

    #[cfg(feature = "hd-wallets")]
    pub fn maybe_bytes<B: udigest::Buffer>(
        m: &Option<impl AsRef<[u8]>>,
        encoder: udigest::encoding::EncodeValue<B>,
    ) {
        use udigest::Digestable;
        m.as_ref().map(udigest::Bytes).unambiguously_encode(encoder)
    }
}

#[cfg(test)]
mod test {
    use paillier_zk::rug::Complete;

    #[test]
    fn test_sqrt() {
        use super::{sqrt, Integer};
        assert_eq!(sqrt(&Integer::from(-5)), Integer::from(1));
        assert_eq!(sqrt(&Integer::from(1)), Integer::from(1));
        assert_eq!(sqrt(&Integer::from(2)), Integer::from(1));
        assert_eq!(sqrt(&Integer::from(3)), Integer::from(1));
        assert_eq!(sqrt(&Integer::from(4)), Integer::from(2));
        assert_eq!(sqrt(&Integer::from(5)), Integer::from(2));
        assert_eq!(sqrt(&Integer::from(6)), Integer::from(2));
        assert_eq!(sqrt(&Integer::from(7)), Integer::from(2));
        assert_eq!(sqrt(&Integer::from(8)), Integer::from(2));
        assert_eq!(sqrt(&Integer::from(9)), Integer::from(3));
        assert_eq!(sqrt(&(Integer::from(1) << 1024)), Integer::from(1) << 512);

        let modulo = (Integer::ONE << 1024_u32).complete();
        let mut rng = rand_dev::DevRng::new();
        for _ in 0..100 {
            let x = modulo
                .random_below_ref(&mut super::external_rand(&mut rng))
                .into();
            let root = sqrt(&x);
            assert!(root.square_ref().complete() <= x);
            let root = root + 1u8;
            assert!(root.square_ref().complete() > x);
        }
    }
}
