//! Final acknowledgement of the refreshed shares.
//!
//! Each party proves knowledge of its new share and echoes every proof it accepts.
//! The round finishes only once a valid proof is held for every index. Early messages
//! sit in a [`round_based::rounds_router::round_buf::RoundBufBounded`] capped at `n`
//! messages from each party for the whole round.

use futures_util::SinkExt;
use generic_ec::{Curve, NonZero, Point, Scalar, SecretScalar};
use generic_ec_zkp::schnorr_pok;
use rand_core::{CryptoRng, RngCore};
use round_based::rounds_router::round_buf::RoundBufBounded;
use round_based::rounds_router::simple_store::RoundInput;
use round_based::rounds_router::{BufferedRound, MessagesStore, RoundsRouter};
use round_based::{Incoming, MessageType, Outgoing, ProtocolMessage, RoundMessage};
use serde::{Deserialize, Serialize};

use crate::errors::{IoError, StdError};
use crate::progress::Tracer;

/// Challenge input for the ACK proof of a new share.
///
/// The fields are the session id, the prover index, `rid`, the ACK commitment, and every new
/// public share, in party order.
pub(crate) struct RefreshAck<'a, E: Curve> {
    pub sid: crate::ExecutionId<'a>,
    pub prover: u16,
    pub rid: &'a [u8],
    pub sch_commit: &'a schnorr_pok::Commit<E>,
    pub public_shares: &'a [NonZero<Point<E>>],
}

impl<'a, E: Curve> RefreshAck<'a, E> {
    /// The non-threshold and threshold protocols use different tags.
    pub fn digest_with_tag(self, tag: &'a str) -> impl udigest::Digestable + 'a {
        udigest::inline_struct!(tag {
            sid: self.sid,
            prover: self.prover,
            rid: udigest::Bytes(self.rid),
            sch_commit: self.sch_commit,
            public_shares: self.public_shares,
        })
    }
}

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

/// Runs the termination consensus: prove `x*_i`, then echo each newly accepted proof.
///
/// `challenge(prover, commitment)` is the ACK challenge for that prover's commitment and the
/// full vector of new public shares. `into_msg` wraps [`MsgAck`] in the protocol message.
///
/// The local proof is broadcast with `relayed_from: None`. This party does not wait to receive
/// its own proof back. A direct message is a proof of the sender's share. A message with
/// `relayed_from: Some(k)` is a proof of party `k`'s share. The first valid proof for a party
/// is kept and echoed. An invalid proof, a duplicate, and an index outside the party set are
/// ignored. This returns once every other party's proof is held.
pub(crate) async fn consensus_on_termination<E, M, S, RecvErr, Out, SendErr, R, F, G>(
    rng: &mut R,
    outgoings: &mut Out,
    rounds: &mut RoundsRouter<M, S>,
    ack_round: &mut BufferedRound<RoundBufBounded<MsgAck<E>>>,
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

    let mut slots = RoundInput::<()>::p2p(i, n);
    let (tau_star, commit_star) = schnorr_pok::prover_commits_ephemeral_secret::<E, _>(rng);
    let challenge_star = challenge(i, &commit_star);
    let proof_star = schnorr_pok::prove(
        &tau_star,
        &schnorr_pok::Challenge {
            nonce: challenge_star,
        },
        x_star,
    );
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

    while slots.wants_more() {
        tracer.receive_msgs();
        let incoming = rounds
            .next_msg_in(ack_round)
            .await
            .map_err(IoError::receive_buffered)?;
        tracer.msgs_received();

        // A direct message proves the sender's share. A forward proves `relayed_from`.
        let index = incoming.msg.relayed_from.unwrap_or(incoming.sender);
        // This party, a filled slot, and an index past the party set are not open.
        if !slots.needs_msg_from(index) {
            continue;
        }
        let nonce = challenge(index, &incoming.msg.sch_commit);
        if incoming
            .msg
            .sch_proof
            .verify(
                &incoming.msg.sch_commit,
                &schnorr_pok::Challenge { nonce },
                public_shares[usize::from(index)].as_ref(),
            )
            .is_err()
        {
            continue;
        }
        // Record as p2p so a broadcast delivery and a p2p delivery both fit the store.
        slots
            .add_message(Incoming {
                id: incoming.id,
                sender: index,
                msg_type: MessageType::P2P,
                msg: (),
            })
            .map_err(|err| IoError::ReceiveMessage(alloc::boxed::Box::new(err)))?;

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

    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    use generic_ec::curves::Secp256k1;
    use generic_ec::{NonZero, Point, Scalar, SecretScalar};
    use generic_ec_zkp::schnorr_pok;
    use rand_core::{CryptoRng, RngCore};

    use futures_util::sink::Sink;
    use futures_util::stream;
    use round_based::rounds_router::round_buf::RoundBufBounded;
    use round_based::{Incoming, MessageType, Outgoing, ProtocolMessage, RoundMessage};
    use serde::{Deserialize, Serialize};
    use sha2::Sha256;

    use super::{MsgAck, RefreshAck};
    use crate::security_level::SecurityLevel128;
    use crate::ExecutionId;

    type E = Secp256k1;
    type SecretShare = NonZero<SecretScalar<E>>;
    type PublicShare = NonZero<Point<E>>;

    fn challenge(
        sid: ExecutionId<'_>,
        rid: &[u8],
        prover: u16,
        sch_commit: &schnorr_pok::Commit<E>,
        public_shares: &[NonZero<Point<E>>],
    ) -> Scalar<E> {
        let ack = RefreshAck {
            sid,
            prover,
            rid,
            sch_commit,
            public_shares,
        }
        .digest_with_tag("dfns.cggmp24.key_refresh.test.refresh_ack");
        Scalar::from_hash::<Sha256>(&ack)
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

    #[derive(Clone, ProtocolMessage, Serialize, Deserialize)]
    #[serde(bound = "")]
    enum TestMsg {
        Ack(MsgAck<E>),
    }

    fn ack(msg: &TestMsg) -> &MsgAck<E> {
        match msg {
            TestMsg::Ack(ack) => ack,
        }
    }

    struct Outbox(Vec<TestMsg>);

    impl Sink<Outgoing<TestMsg>> for Outbox {
        type Error = core::convert::Infallible;

        fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn start_send(self: Pin<&mut Self>, item: Outgoing<TestMsg>) -> Result<(), Self::Error> {
            self.get_mut().0.push(item.msg);
            Ok(())
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(core::ptr::null(), &VTABLE)
        }
        fn no_op(_: *const ()) {}
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);

        let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
        let mut context = Context::from_waker(&waker);
        let mut future = core::pin::pin!(future);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("termination consensus is still waiting"),
        }
    }

    /// Party 0 runs the termination round on a fixed list of incoming messages.
    fn run_party0(
        rng: &mut (impl RngCore + CryptoRng),
        secret: &SecretShare,
        public_shares: &[PublicShare],
        sid: ExecutionId<'_>,
        rid: &[u8],
        incoming: Vec<(u16, MsgAck<E>)>,
    ) -> (Vec<MsgAck<E>>, Result<(), crate::errors::IoError>) {
        let incoming = incoming
            .into_iter()
            .enumerate()
            .map(|(id, (sender, msg))| {
                Ok::<_, core::convert::Infallible>(Incoming {
                    id: u64::try_from(id).expect("message id fits in u64"),
                    sender,
                    msg_type: MessageType::Broadcast,
                    msg: TestMsg::Ack(msg),
                })
            })
            .collect::<Vec<_>>();
        let mut rounds = round_based::rounds_router::RoundsRouter::<TestMsg>::builder();
        let mut ack_round = rounds.add_buffered_round(RoundBufBounded::new(3, 3));
        let mut rounds = rounds.listen(stream::iter(incoming));
        let mut outbox = Outbox(Vec::new());
        let mut tracer = None;
        let result = block_on(super::consensus_on_termination(
            rng,
            &mut outbox,
            &mut rounds,
            &mut ack_round,
            0,
            3,
            secret,
            public_shares,
            &mut tracer,
            |prover, sch_commit| challenge(sid, rid, prover, sch_commit, public_shares),
            TestMsg::Ack,
        ));
        let sent = outbox.0.into_iter().map(|msg| ack(&msg).clone()).collect();
        (sent, result)
    }

    fn echoes(sent: &[MsgAck<E>]) -> &[MsgAck<E>] {
        &sent[1..]
    }

    #[test]
    fn index_past_the_end_is_ignored() {
        let mut rng = rand_dev::DevRng::new();
        let (secrets, public_shares) = sample_shares(&mut rng, 3);
        let sid_bytes = [7u8; 32];
        let rid = [9u8; 32];
        let sid = ExecutionId::new(&sid_bytes);
        let mut out_of_range = prove(&mut rng, sid, &rid, 1, &secrets[1], &public_shares);
        out_of_range.relayed_from = Some(3);
        let ack1 = prove(&mut rng, sid, &rid, 1, &secrets[1], &public_shares);
        let ack2 = prove(&mut rng, sid, &rid, 2, &secrets[2], &public_shares);

        let (sent, result) = run_party0(
            &mut rng,
            &secrets[0],
            &public_shares,
            sid,
            &rid,
            alloc::vec![(1, out_of_range), (1, ack1.clone()), (2, ack2.clone()),],
        );
        result.unwrap_or_else(|err| panic!("termination consensus failed: {err}"));
        let echoed = echoes(&sent);
        assert_eq!(echoed.len(), 2);
        assert_eq!(echoed[0].relayed_from, Some(1));
        assert_eq!(echoed[0].sch_commit.0, ack1.sch_commit.0);
        assert_eq!(echoed[1].relayed_from, Some(2));
        assert_eq!(echoed[1].sch_commit.0, ack2.sch_commit.0);
    }

    #[test]
    fn direct_acks_complete_and_a_duplicate_is_ignored() {
        let mut rng = rand_dev::DevRng::new();
        let (secrets, public_shares) = sample_shares(&mut rng, 3);
        let sid_bytes = [7u8; 32];
        let rid = [9u8; 32];
        let sid = ExecutionId::new(&sid_bytes);
        let ack1 = prove(&mut rng, sid, &rid, 1, &secrets[1], &public_shares);
        let ack2 = prove(&mut rng, sid, &rid, 2, &secrets[2], &public_shares);

        let (sent, result) = run_party0(
            &mut rng,
            &secrets[0],
            &public_shares,
            sid,
            &rid,
            alloc::vec![(1, ack1.clone()), (1, ack1.clone()), (2, ack2.clone())],
        );
        result.unwrap_or_else(|err| panic!("termination consensus failed: {err}"));
        let echoed = echoes(&sent);
        assert_eq!(echoed.len(), 2);
        assert_eq!(echoed[0].relayed_from, Some(1));
        assert_eq!(echoed[0].sch_commit.0, ack1.sch_commit.0);
        assert_eq!(echoed[1].relayed_from, Some(2));
        assert_eq!(echoed[1].sch_commit.0, ack2.sch_commit.0);
    }

    #[test]
    fn forward_fills_the_relayed_slot() {
        let mut rng = rand_dev::DevRng::new();
        let (secrets, public_shares) = sample_shares(&mut rng, 3);
        let sid_bytes = [7u8; 32];
        let rid = [9u8; 32];
        let sid = ExecutionId::new(&sid_bytes);
        let mut forwarded = prove(&mut rng, sid, &rid, 2, &secrets[2], &public_shares);
        forwarded.relayed_from = Some(2);
        let ack1 = prove(&mut rng, sid, &rid, 1, &secrets[1], &public_shares);

        let (sent, result) = run_party0(
            &mut rng,
            &secrets[0],
            &public_shares,
            sid,
            &rid,
            alloc::vec![(1, forwarded.clone()), (1, ack1.clone())],
        );
        result.unwrap_or_else(|err| panic!("termination consensus failed: {err}"));
        let echoed = echoes(&sent);
        assert_eq!(echoed.len(), 2);
        assert_eq!(echoed[0].relayed_from, Some(2));
        assert_eq!(echoed[0].sch_commit.0, forwarded.sch_commit.0);
        assert_eq!(echoed[1].relayed_from, Some(1));
        assert_eq!(echoed[1].sch_commit.0, ack1.sch_commit.0);
    }

    #[test]
    fn direct_message_does_not_fill_another_index() {
        let mut rng = rand_dev::DevRng::new();
        let (secrets, public_shares) = sample_shares(&mut rng, 3);
        let sid_bytes = [7u8; 32];
        let rid = [9u8; 32];
        let sid = ExecutionId::new(&sid_bytes);
        let ack0 = prove(&mut rng, sid, &rid, 0, &secrets[0], &public_shares);
        let ack1 = prove(&mut rng, sid, &rid, 1, &secrets[1], &public_shares);
        let ack2 = prove(&mut rng, sid, &rid, 2, &secrets[2], &public_shares);

        let (sent, result) = run_party0(
            &mut rng,
            &secrets[0],
            &public_shares,
            sid,
            &rid,
            alloc::vec![(1, ack0), (1, ack1.clone()), (2, ack2.clone())],
        );
        result.unwrap_or_else(|err| panic!("termination consensus failed: {err}"));
        let echoed = echoes(&sent);
        assert_eq!(echoed.len(), 2);
        assert_eq!(echoed[0].relayed_from, Some(1));
        assert_eq!(echoed[0].sch_commit.0, ack1.sch_commit.0);
        assert_eq!(echoed[1].relayed_from, Some(2));
        assert_eq!(echoed[1].sch_commit.0, ack2.sch_commit.0);
    }

    #[test]
    fn junk_ack_is_ignored() {
        let mut rng = rand_dev::DevRng::new();
        let (secrets, public_shares) = sample_shares(&mut rng, 3);
        let sid_bytes = [7u8; 32];
        let rid = [9u8; 32];
        let sid = ExecutionId::new(&sid_bytes);
        let junk = MsgAck {
            relayed_from: None,
            sch_commit: schnorr_pok::Commit(Point::generator() * Scalar::<E>::random(&mut rng)),
            sch_proof: schnorr_pok::Proof(Scalar::random(&mut rng)),
        };
        let ack1 = prove(&mut rng, sid, &rid, 1, &secrets[1], &public_shares);
        let ack2 = prove(&mut rng, sid, &rid, 2, &secrets[2], &public_shares);

        let (sent, result) = run_party0(
            &mut rng,
            &secrets[0],
            &public_shares,
            sid,
            &rid,
            alloc::vec![(1, junk), (1, ack1.clone()), (2, ack2.clone())],
        );
        result.unwrap_or_else(|err| panic!("termination consensus failed: {err}"));
        let echoed = echoes(&sent);
        assert_eq!(echoed.len(), 2);
        assert_eq!(echoed[0].sch_commit.0, ack1.sch_commit.0);
        assert_eq!(echoed[1].sch_commit.0, ack2.sch_commit.0);
    }

    #[test]
    fn missing_slot_does_not_complete() {
        let mut rng = rand_dev::DevRng::new();
        let (secrets, public_shares) = sample_shares(&mut rng, 3);
        let sid_bytes = [7u8; 32];
        let rid = [9u8; 32];
        let sid = ExecutionId::new(&sid_bytes);
        let ack1 = prove(&mut rng, sid, &rid, 1, &secrets[1], &public_shares);

        let (sent, result) = run_party0(
            &mut rng,
            &secrets[0],
            &public_shares,
            sid,
            &rid,
            alloc::vec![(1, ack1.clone())],
        );
        assert!(result.is_err());
        let echoed = echoes(&sent);
        assert_eq!(echoed.len(), 1);
        assert_eq!(echoed[0].relayed_from, Some(1));
        assert_eq!(echoed[0].sch_commit.0, ack1.sch_commit.0);
    }

    #[cfg(feature = "state-machine")]
    #[test]
    fn withheld_direct_ack_is_replaced_by_forward() {
        use round_based::state_machine::{wrap_protocol, ProceedResult, StateMachine};
        use round_based::{Delivery, Mpc, MpcParty};

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
            let mut ack_round = rounds.add_buffered_round(RoundBufBounded::new(3, 3));
            let mut rounds = rounds.listen(incomings);
            let mut tracer = None;
            super::consensus_on_termination(
                &mut rng,
                &mut outgoings,
                &mut rounds,
                &mut ack_round,
                i,
                3,
                &secret,
                &public_shares,
                &mut tracer,
                |prover, sch_commit| challenge(sid, &rid, prover, sch_commit, &public_shares),
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
