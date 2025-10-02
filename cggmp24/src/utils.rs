use generic_ec::{Curve, Scalar};
use paillier_zk::backend::Integer;
use paillier_zk::IntegerExt;
use paillier_zk::{
    paillier_affine_operation_in_range as pi_aff,
    paillier_encryption_in_range_with_el_gamal as pi_enc_elg,
};
use round_based::rounds_router::simple_store::RoundMsgs;
use round_based::{MsgId, PartyIndex};

use crate::security_level::SecurityLevel;

/// Converts `&Scalar<E>` into Integer
pub fn scalar_to_pm_bignumber<E: Curve>(scalar: impl AsRef<Scalar<E>>) -> Integer {
    let q = Integer::curve_order::<E>();
    let x = Integer::from_bytes_msf(&scalar.as_ref().to_be_bytes());
    let half_q = (q.clone() - 1) / 2;
    if x <= half_q {
        x
    } else {
        x - q
    }
}

pub struct SecurityParams {
    pub pi_aff: pi_aff::SecurityParams,
    pub pi_enc_elg: pi_enc_elg::SecurityParams,
}

impl SecurityParams {
    pub fn new<L: SecurityLevel>() -> Self {
        Self {
            pi_aff: pi_aff::SecurityParams {
                l_x: L::ELL,
                l_y: L::ELL_PRIME,
                epsilon: L::EPSILON,
            },
            pi_enc_elg: pi_enc_elg::SecurityParams {
                l: L::ELL,
                epsilon: L::EPSILON,
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
#[allow(dead_code)] // removes false-positive warnings
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

/// Filter returns `Some(data)` for every __faulty__ message pair
pub fn collect_blame_with_data<D, P, T, F>(
    data_messages: &RoundMsgs<D>,
    proof_messages: &RoundMsgs<P>,
    mut filter: F,
) -> Vec<(AbortBlame, T)>
where
    F: FnMut(PartyIndex, &D, &P) -> Option<T>,
{
    data_messages
        .iter_indexed()
        .zip(proof_messages.iter_indexed())
        .filter_map(|((j, data_msg_id, data), (_, proof_msg_id, proof))| {
            filter(j, data, proof).map(|data| (AbortBlame::new(j, data_msg_id, proof_msg_id), data))
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

/// Iterate peers of i-th party
pub fn iter_peers(i: u16, n: u16) -> impl Iterator<Item = u16> {
    (0..n).filter(move |x| *x != i)
}

/// Binary search for rounded down square root. For non-positive numbers returns
/// one
pub fn sqrt(x: &Integer) -> Integer {
    x.sqrt_ref().unwrap_or_else(Integer::one)
}

/// Returns `[list[indexes[0]], list[indexes[1]], ..., list[indexes[n-1]]]`
///
/// Result is `None` if any of `indexes[i]` is out of range of `list`
pub fn subset<T: Clone, I: Into<usize> + Copy>(indexes: &[I], list: &[T]) -> Option<Vec<T>> {
    indexes
        .iter()
        .map(|&i| list.get(i.into()).cloned())
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
        let n = Integer::generate_prime(rng, bits_size);

        if n.mod_u(4) == 3 {
            break n;
        }
    }
}

/// Takes safe primes p, q, generates and outputs [`PedersenParams`], `phi`, `lambda`
pub fn generate_pedersen_params(
    rng: &mut impl rand_core::CryptoRngCore,
    p: Integer,
    q: Integer,
) -> Result<(crate::key_share::PedersenParams, Integer, Integer), GenPedersenError> {
    let crt = paillier_zk::fast_paillier::utils::CrtExp::build_n(&p, &q)
        .ok_or(GenPedersenError::BuildCrt)?;
    let N = &p * &q;
    let phi_N = (&p - 1u8) * (&q - 1u8);

    let r = Integer::sample_in_mult_group_of(rng, &N);
    let lambda = Integer::random_below(phi_N.clone() >> 2, rng);

    let t = r.square().modulo(&N);
    let s = crt
        .exp(&t, &crt.prepare_exponent(&lambda))
        .ok_or(GenPedersenError::PowMod)?;

    let params = crate::key_share::PedersenParams {
        hat_N: N,
        s,
        t,
        multiexp: None,
        crt: Some(crt),
    };

    Ok((params, phi_N, lambda))
}

#[derive(thiserror::Error, Debug)]
pub enum GenPedersenError {
    #[error("build crt")]
    BuildCrt,
    #[error("pow mod")]
    PowMod,
}

/// Unambiguous encoding for different types for which it was not defined
pub mod encoding {
    use paillier_zk::backend;

    pub struct Integer;
    impl udigest::DigestAs<backend::Integer> for Integer {
        fn digest_as<B: udigest::Buffer>(
            x: &backend::Integer,
            encoder: udigest::encoding::EncodeValue<B>,
        ) {
            encoder.encode_leaf_value(x.to_bytes_msf())
        }
    }
}

#[cfg(test)]
mod test {
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
        assert_eq!(
            sqrt(&(Integer::from(1) << 1024_u32)),
            Integer::from(1) << 512_u32
        );

        let modulo = Integer::one() << 1024_u32;
        let mut rng = rand_dev::DevRng::new();
        for _ in 0..100 {
            let x = modulo.random_below_ref(&mut rng);
            let root = sqrt(&x);
            assert!(root.square_ref() <= x);
            let root = root + 1u8;
            assert!(root.square_ref() > x);
        }
    }
}
