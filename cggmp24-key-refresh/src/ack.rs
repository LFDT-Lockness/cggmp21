//! Final acknowledgement of the refreshed shares.
//!
//! Each party proves knowledge of its new share and echoes every proof it accepts.
//! The round finishes only once a valid proof is held for every index. Early messages
//! sit in [`PerSenderBuf`], which is capped per sender so one party cannot close the round.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::convert::Infallible;

use futures_util::SinkExt;
use generic_ec::{Curve, NonZero, Point, Scalar, SecretScalar};
use generic_ec_zkp::schnorr_pok;
use rand_core::{CryptoRng, RngCore};
use round_based::rounds_router::round_buf::RoundBuf;
use round_based::rounds_router::{BufferedRound, RoundsRouter};
use round_based::{Incoming, Outgoing, ProtocolMessage, RoundMessage};
use serde::{Deserialize, Serialize};

use crate::errors::{IoError, StdError};
use crate::progress::Tracer;

macro_rules! define_refresh_ack {
    ($tag:expr) => {
        /// Challenge input for the ACK proof of a new share.
        ///
        /// The fields are the session id, the prover index, `rid`, the ACK commitment,
        /// and every new public share, in party order.
        #[derive(udigest::Digestable)]
        #[udigest(tag = $tag)]
        #[udigest(bound = "")]
        pub struct RefreshAck<'a, E: generic_ec::Curve> {
            pub sid: $crate::ExecutionId<'a>,
            pub prover: u16,
            #[udigest(as_bytes)]
            pub rid: &'a [u8],
            pub sch_commit: &'a generic_ec_zkp::schnorr_pok::Commit<E>,
            pub public_shares: &'a [generic_ec::NonZero<generic_ec::Point<E>>],
        }
    };
}
pub(crate) use define_refresh_ack;

/// Acknowledgement of one party's refreshed share
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgAck<E: Curve> {
    /// `None` when the sender is proving its own new share.
    /// `Some(k)` when this message forwards party `k`'s proof.
    pub relayed_from: Option<u16>,
    /// $A^*_k$
    pub sch_commit: schnorr_pok::Commit<E>,
    /// $\psi^*_k$
    pub sch_proof: schnorr_pok::Proof<E>,
}

/// Queues at most `n` not-yet-read messages from each sender.
///
/// The ACK round reads messages one by one (`add_buffered_round`, `next_msg_in`).
/// This buffer is ours. `RoundBufBounded` is the wrong buffer for this round.
///
/// `RoundBufBounded` stores every not-yet-read message of the round in one queue.
/// [`RoundBuf::add_message`] returns an error once that queue is full. The router
/// then wants no more messages and drops later ones for the round. After the
/// messages already queued have been read, `next_msg_in` returns that error and
/// closes the round.
///
/// Each round has its own queue. That does not keep the ACK queue empty while this
/// party is still finishing an earlier round. `complete` reads the single incoming
/// stream and files each message by round number. ACK messages that arrive during
/// rounds 1–3 are appended before this party has called `next_msg_in`.
///
/// A party can use that window. It sends more ACK messages than the cap to one
/// victim, then lets the last round-3 message through. The victim's ACK round
/// returns an error. The other honest parties never saw the flood, finish, and
/// adopt the new share. The victim does not.
///
/// The standalone consensus example does not hit this. It calls `next_msg_in`
/// immediately, so its queue stays about one message deep. The overflow needs an
/// earlier round still sitting in `complete`.
///
/// This buffer keeps a separate count per authenticated sender. The cap is `n`
/// queued messages from that sender. A further message from the same sender is
/// discarded, and [`RoundBuf::add_message`] still returns `Ok`. The round stays
/// open. Discarding the new message, rather than the oldest, matters: junk that
/// arrives while the queue is full does not push out a message already queued.
///
/// `n` is the most an honest party sends: its own proof, plus one forward of each
/// of the other `n - 1` proofs. A flood fills only that sender's slots. A forward
/// from an honest party uses the honest sender's slots. The sender index is the
/// one on the incoming message. `relayed_from` is not used for the cap, so a party
/// cannot spend another party's slots by claiming to relay them.
///
/// The cap counts messages still queued, and it assumes the transport delivers
/// each message at most once. An at-least-once transport can replay an honest
/// sender until a later forward is dropped. A relay from another party uses that
/// party's own slots, so the dropped copy is not the only way the proof arrives.
///
/// This bound is not part of the protocol. It is there so one party cannot close
/// another party's ACK round.
pub(crate) struct PerSenderBuf<M> {
    cap: usize,
    queued: Vec<usize>,
    messages: VecDeque<Incoming<M>>,
}

impl<M> PerSenderBuf<M> {
    /// `n` is the number of parties and the per-sender cap.
    pub(crate) fn new(n: u16) -> Self {
        let n = usize::from(n);
        Self {
            cap: n,
            queued: alloc::vec![0; n],
            messages: VecDeque::new(),
        }
    }

    fn slot(&self, sender: u16) -> Option<usize> {
        let sender = usize::from(sender);
        (sender < self.queued.len()).then_some(sender)
    }
}

impl<M: 'static> RoundBuf for PerSenderBuf<M> {
    type Msg = M;
    type Error = Infallible;

    fn add_message(&mut self, msg: Incoming<Self::Msg>) -> Result<(), Self::Error> {
        if let Some(slot) = self.slot(msg.sender) {
            if self.queued[slot] < self.cap {
                self.queued[slot] += 1;
                self.messages.push_back(msg);
            }
        }
        Ok(())
    }

    fn next_message(&mut self) -> Option<Incoming<Self::Msg>> {
        let msg = self.messages.pop_front()?;
        if let Some(slot) = self.slot(msg.sender) {
            self.queued[slot] -= 1;
        }
        Some(msg)
    }
}

/// Which ACK slots are already filled.
pub(crate) struct AckSlots {
    filled: Vec<bool>,
}

impl AckSlots {
    pub(crate) fn new(n: u16) -> Self {
        Self {
            filled: alloc::vec![false; usize::from(n)],
        }
    }

    /// The local proof occupies this party's slot before any message is received.
    pub(crate) fn accept_local(&mut self, i: u16) {
        self.filled[usize::from(i)] = true;
    }

    #[cfg(test)]
    pub(crate) fn is_filled(&self, index: u16) -> bool {
        self.filled
            .get(usize::from(index))
            .copied()
            .unwrap_or(false)
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.filled.iter().all(|filled| *filled)
    }

    /// A direct message is a candidate only for the sender. A forward is a candidate only
    /// for `relayed_from`. An index that is already filled, or out of range, is not a candidate.
    fn open_slot(&self, sender: u16, relayed_from: Option<u16>) -> Option<u16> {
        let index = relayed_from.unwrap_or(sender);
        let slot = usize::from(index);
        if slot >= self.filled.len() || self.filled[slot] {
            None
        } else {
            Some(index)
        }
    }
}

/// Keeps the first message that `verify` accepts for an open slot.
///
/// Returns the filled index. Invalid and duplicate messages return `None` and leave the slots
/// unchanged.
pub(crate) fn consider<E, F>(
    slots: &mut AckSlots,
    sender: u16,
    msg: &MsgAck<E>,
    mut verify: F,
) -> Option<u16>
where
    E: Curve,
    F: FnMut(u16, &MsgAck<E>) -> bool,
{
    let index = slots.open_slot(sender, msg.relayed_from)?;
    if verify(index, msg) {
        slots.filled[usize::from(index)] = true;
        Some(index)
    } else {
        None
    }
}

/// Proves `x*_i`, broadcasts it, and echoes each newly accepted proof.
///
/// `challenge(prover, commitment)` is the ACK challenge for that prover's commitment and the
/// full vector of new public shares. `into_msg` wraps [`MsgAck`] in the protocol message.
///
/// The local proof fills slot `i` and is sent with `relayed_from: None`. A direct message fills
/// only the sender's slot. A forward fills only `relayed_from`. The first valid proof for a slot
/// is kept. This returns once every slot is filled.
pub(crate) async fn collect_acks<E, M, S, RecvErr, Out, SendErr, R, F, G>(
    rng: &mut R,
    outgoings: &mut Out,
    rounds: &mut RoundsRouter<M, S>,
    ack_round: &mut BufferedRound<PerSenderBuf<MsgAck<E>>>,
    i: u16,
    n: u16,
    x_star: &NonZero<SecretScalar<E>>,
    public_shares: &[NonZero<Point<E>>],
    tracer: &mut Option<&mut dyn Tracer>,
    mut challenge: F,
    into_msg: G,
) -> Result<(), IoError>
where
    E: Curve,
    R: RngCore + CryptoRng,
    M: ProtocolMessage + RoundMessage<MsgAck<E>> + 'static,
    S: futures_util::Stream<Item = Result<Incoming<M>, RecvErr>> + Unpin,
    RecvErr: core::error::Error + Send + Sync + 'static,
    Out: futures_util::Sink<Outgoing<M>, Error = SendErr> + Unpin,
    SendErr: StdError + Send + Sync + 'static,
    F: FnMut(u16, &schnorr_pok::Commit<E>) -> Scalar<E>,
    G: Fn(MsgAck<E>) -> M,
{
    debug_assert_eq!(public_shares.len(), usize::from(n));
    debug_assert!(usize::from(i) < usize::from(n));

    let mut slots = AckSlots::new(n);
    let (tau_star, commit_star) = schnorr_pok::prover_commits_ephemeral_secret::<E, _>(rng);
    let challenge_star = challenge(i, &commit_star);
    let proof_star = schnorr_pok::prove(
        &tau_star,
        &schnorr_pok::Challenge {
            nonce: challenge_star,
        },
        x_star,
    );
    slots.accept_local(i);

    tracer.round_begins();
    tracer.send_msg();
    outgoings
        .send(Outgoing::broadcast(into_msg(MsgAck {
            relayed_from: None,
            sch_commit: commit_star,
            sch_proof: proof_star,
        })))
        .await
        .map_err(IoError::send_message)?;
    tracer.msg_sent();

    loop {
        if slots.is_complete() {
            break;
        }
        tracer.receive_msgs();
        let incoming = rounds
            .next_msg_in(ack_round)
            .await
            .map_err(IoError::receive_buffered)?;
        tracer.msgs_received();

        let Some(index) = consider(&mut slots, incoming.sender, &incoming.msg, |index, msg| {
            let nonce = challenge(index, &msg.sch_commit);
            msg.sch_proof
                .verify(
                    &msg.sch_commit,
                    &schnorr_pok::Challenge { nonce },
                    public_shares[usize::from(index)].as_ref(),
                )
                .is_ok()
        }) else {
            continue;
        };

        tracer.send_msg();
        outgoings
            .send(Outgoing::broadcast(into_msg(MsgAck {
                relayed_from: Some(index),
                sch_commit: incoming.msg.sch_commit.clone(),
                sch_proof: incoming.msg.sch_proof.clone(),
            })))
            .await
            .map_err(IoError::send_message)?;
        tracer.msg_sent();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use generic_ec::curves::Secp256k1;
    use generic_ec::{NonZero, Point, Scalar, SecretScalar};
    use generic_ec_zkp::schnorr_pok;
    use rand_core::{CryptoRng, RngCore};
    use round_based::rounds_router::round_buf::RoundBuf;
    use round_based::{Incoming, MessageType, RoundMessage};
    use sha2::Sha256;

    use super::{consider, AckSlots, MsgAck, PerSenderBuf};
    use crate::security_level::SecurityLevel128;
    use crate::ExecutionId;

    type E = Secp256k1;
    type SecretShare = NonZero<SecretScalar<E>>;
    type PublicShare = NonZero<Point<E>>;

    #[derive(udigest::Digestable)]
    #[udigest(tag = "dfns.cggmp24.key_refresh.test.refresh_ack")]
    #[udigest(bound = "")]
    struct TestAck<'a> {
        sid: ExecutionId<'a>,
        prover: u16,
        #[udigest(as_bytes)]
        rid: &'a [u8],
        sch_commit: &'a schnorr_pok::Commit<E>,
        public_shares: &'a [NonZero<Point<E>>],
    }

    fn challenge<'a>(
        sid: ExecutionId<'a>,
        rid: &'a [u8],
        prover: u16,
        sch_commit: &'a schnorr_pok::Commit<E>,
        public_shares: &'a [NonZero<Point<E>>],
    ) -> Scalar<E> {
        Scalar::from_hash::<Sha256>(&TestAck {
            sid,
            prover,
            rid,
            sch_commit,
            public_shares,
        })
    }

    fn verify(
        sid: ExecutionId<'_>,
        rid: &[u8],
        public_shares: &[NonZero<Point<E>>],
        index: u16,
        msg: &MsgAck<E>,
    ) -> bool {
        let nonce = challenge(sid, rid, index, &msg.sch_commit, public_shares);
        msg.sch_proof
            .verify(
                &msg.sch_commit,
                &schnorr_pok::Challenge { nonce },
                public_shares[usize::from(index)].as_ref(),
            )
            .is_ok()
    }

    fn sample_shares<R: RngCore + CryptoRng>(
        rng: &mut R,
        n: u16,
    ) -> (Vec<SecretShare>, Vec<PublicShare>) {
        let secrets = (0..n)
            .map(|_| NonZero::<SecretScalar<E>>::random(rng))
            .collect::<Vec<_>>();
        let public_shares = secrets
            .iter()
            .map(|secret| Point::generator() * secret)
            .collect();
        (secrets, public_shares)
    }

    fn prove<R: RngCore + CryptoRng>(
        rng: &mut R,
        sid: ExecutionId<'_>,
        rid: &[u8],
        prover: u16,
        secret: &NonZero<SecretScalar<E>>,
        public_shares: &[NonZero<Point<E>>],
    ) -> MsgAck<E> {
        let (tau_star, commit_star) = schnorr_pok::prover_commits_ephemeral_secret::<E, _>(rng);
        let challenge_star = challenge(sid, rid, prover, &commit_star, public_shares);
        let proof_star = schnorr_pok::prove(
            &tau_star,
            &schnorr_pok::Challenge {
                nonce: challenge_star,
            },
            secret,
        );
        MsgAck {
            relayed_from: None,
            sch_commit: commit_star,
            sch_proof: proof_star,
        }
    }

    fn incoming(sender: u16, msg: u32) -> Incoming<u32> {
        Incoming {
            id: u64::from(msg),
            sender,
            msg_type: MessageType::Broadcast,
            msg,
        }
    }

    #[test]
    fn ack_round_number_is_appended() {
        assert_eq!(
            <crate::non_threshold::Msg<E, SecurityLevel128, Sha256> as RoundMessage<MsgAck<E>>>::ROUND,
            6
        );
        assert_eq!(
            <crate::threshold::Msg<E, SecurityLevel128, Sha256> as RoundMessage<MsgAck<E>>>::ROUND,
            6
        );
    }

    #[test]
    fn direct_acks_complete_and_a_duplicate_is_ignored() {
        let mut rng = rand_dev::DevRng::new();
        let (secrets, public_shares) = sample_shares(&mut rng, 3);
        let sid_bytes = [7u8; 32];
        let rid = [9u8; 32];
        let sid = ExecutionId::new(&sid_bytes);
        let mut slots = AckSlots::new(3);
        slots.accept_local(0);

        let ack1 = prove(&mut rng, sid, &rid, 1, &secrets[1], &public_shares);
        assert_eq!(
            consider(&mut slots, 1, &ack1, |index, msg| {
                verify(sid, &rid, &public_shares, index, msg)
            }),
            Some(1)
        );
        assert_eq!(
            consider(&mut slots, 1, &ack1, |index, msg| {
                verify(sid, &rid, &public_shares, index, msg)
            }),
            None
        );

        let ack2 = prove(&mut rng, sid, &rid, 2, &secrets[2], &public_shares);
        assert_eq!(
            consider(&mut slots, 2, &ack2, |index, msg| {
                verify(sid, &rid, &public_shares, index, msg)
            }),
            Some(2)
        );
        assert!(slots.is_complete());
    }

    #[test]
    fn forward_fills_the_relayed_slot() {
        let mut rng = rand_dev::DevRng::new();
        let (secrets, public_shares) = sample_shares(&mut rng, 3);
        let sid_bytes = [7u8; 32];
        let rid = [9u8; 32];
        let sid = ExecutionId::new(&sid_bytes);
        let mut slots = AckSlots::new(3);
        slots.accept_local(0);

        let mut forwarded = prove(&mut rng, sid, &rid, 2, &secrets[2], &public_shares);
        forwarded.relayed_from = Some(2);
        assert_eq!(
            consider(&mut slots, 1, &forwarded, |index, msg| {
                verify(sid, &rid, &public_shares, index, msg)
            }),
            Some(2)
        );
        assert!(!slots.is_filled(1));
        assert!(slots.is_filled(2));
        assert!(!slots.is_complete());

        let ack1 = prove(&mut rng, sid, &rid, 1, &secrets[1], &public_shares);
        assert_eq!(
            consider(&mut slots, 1, &ack1, |index, msg| {
                verify(sid, &rid, &public_shares, index, msg)
            }),
            Some(1)
        );
        assert!(slots.is_complete());
    }

    #[test]
    fn direct_message_does_not_fill_another_index() {
        let mut rng = rand_dev::DevRng::new();
        let (secrets, public_shares) = sample_shares(&mut rng, 3);
        let sid_bytes = [7u8; 32];
        let rid = [9u8; 32];
        let sid = ExecutionId::new(&sid_bytes);
        let mut slots = AckSlots::new(3);
        let ack0 = prove(&mut rng, sid, &rid, 0, &secrets[0], &public_shares);
        assert_eq!(
            consider(&mut slots, 1, &ack0, |index, msg| {
                verify(sid, &rid, &public_shares, index, msg)
            }),
            None
        );
        assert!(!slots.is_filled(0));
        assert!(!slots.is_filled(1));
        assert!(!slots.is_complete());
    }

    #[test]
    fn junk_ack_is_ignored() {
        let mut rng = rand_dev::DevRng::new();
        let (_secrets, public_shares) = sample_shares(&mut rng, 3);
        let sid_bytes = [7u8; 32];
        let rid = [9u8; 32];
        let sid = ExecutionId::new(&sid_bytes);
        let mut slots = AckSlots::new(3);
        slots.accept_local(0);
        let junk = MsgAck {
            relayed_from: None,
            sch_commit: schnorr_pok::Commit(Point::generator() * Scalar::<E>::random(&mut rng)),
            sch_proof: schnorr_pok::Proof(Scalar::random(&mut rng)),
        };
        assert_eq!(
            consider(&mut slots, 1, &junk, |index, msg| {
                verify(sid, &rid, &public_shares, index, msg)
            }),
            None
        );
        assert!(!slots.is_filled(1));
        assert!(!slots.is_complete());
    }

    #[test]
    fn missing_slot_does_not_complete() {
        let mut rng = rand_dev::DevRng::new();
        let (secrets, public_shares) = sample_shares(&mut rng, 3);
        let sid_bytes = [7u8; 32];
        let rid = [9u8; 32];
        let sid = ExecutionId::new(&sid_bytes);
        let mut slots = AckSlots::new(3);
        slots.accept_local(0);
        let ack1 = prove(&mut rng, sid, &rid, 1, &secrets[1], &public_shares);
        consider(&mut slots, 1, &ack1, |index, msg| {
            verify(sid, &rid, &public_shares, index, msg)
        });
        assert!(slots.is_filled(1));
        assert!(!slots.is_filled(2));
        assert!(!slots.is_complete());
    }

    #[test]
    fn one_sender_cannot_crowd_out_another() {
        let n = 3u16;
        let mut buf = PerSenderBuf::new(n);
        for id in 0..n {
            buf.add_message(incoming(0, u32::from(id))).unwrap();
        }
        buf.add_message(incoming(0, 999)).unwrap();
        buf.add_message(incoming(1, 7)).unwrap();

        let queued = core::iter::from_fn(|| buf.next_message())
            .map(|msg| (msg.sender, msg.msg))
            .collect::<Vec<_>>();
        assert_eq!(queued, alloc::vec![(0, 0), (0, 1), (0, 2), (1, 7)]);

        buf.add_message(incoming(0, 5)).unwrap();
        let next = buf.next_message().unwrap();
        assert_eq!((next.sender, next.msg), (0, 5));
    }

    #[cfg(feature = "state-machine")]
    #[test]
    fn withheld_direct_ack_is_replaced_by_forward() {
        use round_based::state_machine::{wrap_protocol, ProceedResult, StateMachine};
        use round_based::{Delivery, Mpc, MpcParty, ProtocolMessage};
        use serde::{Deserialize, Serialize};

        #[derive(Clone, ProtocolMessage, Serialize, Deserialize)]
        #[serde(bound = "")]
        enum TestMsg {
            Ack(MsgAck<E>),
        }

        #[derive(udigest::Digestable)]
        #[udigest(tag = "dfns.cggmp24.key_refresh.test.refresh_ack")]
        #[udigest(bound = "")]
        struct Challenge<'a> {
            sid: ExecutionId<'a>,
            prover: u16,
            #[udigest(as_bytes)]
            rid: &'a [u8],
            sch_commit: &'a schnorr_pok::Commit<E>,
            public_shares: &'a [NonZero<Point<E>>],
        }

        async fn run<R, Party>(
            mut rng: R,
            party: Party,
            i: u16,
            secret: NonZero<SecretScalar<E>>,
            public_shares: Vec<NonZero<Point<E>>>,
            sid: ExecutionId<'static>,
            rid: [u8; 32],
        ) -> Result<(), crate::errors::IoError>
        where
            R: RngCore + CryptoRng,
            Party: Mpc<ProtocolMessage = TestMsg>,
        {
            let MpcParty { delivery, .. } = party.into_party();
            let (incomings, mut outgoings) = delivery.split();
            let mut rounds = round_based::rounds_router::RoundsRouter::<TestMsg>::builder();
            let mut ack_round = rounds.add_buffered_round(PerSenderBuf::new(3));
            let mut rounds = rounds.listen(incomings);
            let mut tracer = None;
            super::collect_acks(
                &mut rng,
                &mut outgoings,
                &mut rounds,
                &mut ack_round,
                i,
                3,
                &secret,
                &public_shares,
                &mut tracer,
                |prover, sch_commit| {
                    Scalar::from_hash::<Sha256>(&Challenge {
                        sid,
                        prover,
                        rid: &rid,
                        sch_commit,
                        public_shares: &public_shares,
                    })
                },
                TestMsg::Ack,
            )
            .await
        }

        fn proceed(
            party: &mut impl StateMachine<Msg = TestMsg, Output = Result<(), crate::errors::IoError>>,
        ) -> (Vec<TestMsg>, Option<Result<(), crate::errors::IoError>>) {
            let mut sent = Vec::new();
            loop {
                match party.proceed() {
                    ProceedResult::SendMsg(msg) => sent.push(msg.msg),
                    ProceedResult::NeedsOneMoreMessage => return (sent, None),
                    ProceedResult::Yielded => {}
                    ProceedResult::Output(out) => return (sent, Some(out)),
                    ProceedResult::Error(err) => panic!("state machine error: {err}"),
                }
            }
        }

        fn feed(sender: u16, msg: &TestMsg) -> Incoming<TestMsg> {
            Incoming {
                id: 0,
                sender,
                msg_type: MessageType::P2P,
                msg: msg.clone(),
            }
        }

        fn ack(msg: &TestMsg) -> &MsgAck<E> {
            match msg {
                TestMsg::Ack(ack) => ack,
            }
        }

        let mut rng = rand_dev::DevRng::new();
        let (secrets, public_shares) = sample_shares(&mut rng, 3);
        static SID_BYTES: [u8; 32] = [4u8; 32];
        let rid = [6u8; 32];
        let sid = ExecutionId::new(&SID_BYTES);

        let secret0 = secrets[0].clone();
        let secret1 = secrets[1].clone();
        let secret2 = secrets[2].clone();
        let shares0 = public_shares.clone();
        let shares1 = public_shares.clone();
        let shares2 = public_shares;
        let rng0 = rng.fork();
        let rng1 = rng.fork();
        let rng2 = rng.fork();

        let mut party0 =
            wrap_protocol(move |party| run(rng0, party, 0, secret0, shares0, sid, rid));
        let mut party1 =
            wrap_protocol(move |party| run(rng1, party, 1, secret1, shares1, sid, rid));
        let mut party2 =
            wrap_protocol(move |party| run(rng2, party, 2, secret2, shares2, sid, rid));

        let (own0, output) = proceed(&mut party0);
        assert!(output.is_none() && own0.len() == 1);
        let (own2, output) = proceed(&mut party2);
        assert!(output.is_none() && own2.len() == 1);
        let (_own1, output) = proceed(&mut party1);
        assert!(output.is_none());

        // Party 2 accepts party 0 and forwards that proof. Party 1 never sees party 0's direct ACK.
        party2
            .received_msg(feed(0, &own0[0]))
            .unwrap_or_else(|_| panic!("party 2 rejected party 0's ack"));
        let (forward, output) = proceed(&mut party2);
        assert!(output.is_none());
        assert!(matches!(ack(&forward[0]).relayed_from, Some(0)));
        assert_eq!(ack(&forward[0]).sch_commit.0, ack(&own0[0]).sch_commit.0);

        // Party 1 has its own slot and party 2's direct slot, and is still missing party 0.
        party1
            .received_msg(feed(2, &own2[0]))
            .unwrap_or_else(|_| panic!("party 1 rejected party 2's ack"));
        let (_relay, output) = proceed(&mut party1);
        assert!(output.is_none());

        party1
            .received_msg(feed(2, &forward[0]))
            .unwrap_or_else(|_| panic!("party 1 rejected the forward"));
        let (_relay, output) = proceed(&mut party1);
        output
            .expect("party 1 finishes from party 2's forward")
            .unwrap();
    }
}
