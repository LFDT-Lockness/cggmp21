use alloc::vec::Vec;

use round_based::rounds_router::simple_store::RoundMsgs;
use round_based::{MsgId, PartyIndex};

mod hex_or_bin;
pub use hex_or_bin::HexOrBin;

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
#[cfg(feature = "hd-wallets")]
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

/// Unambiguous encoding for different types for which it was not defined
pub mod encoding {
    #[cfg(feature = "hd-wallets")]
    pub fn maybe_bytes<B: udigest::Buffer>(
        m: &Option<impl AsRef<[u8]>>,
        encoder: udigest::encoding::EncodeValue<B>,
    ) {
        use udigest::Digestable;
        m.as_ref().map(udigest::Bytes).unambiguously_encode(encoder)
    }
}
