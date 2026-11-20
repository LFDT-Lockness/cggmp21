# ACK buffer

The ACK round reads messages one by one through round-based's buffered-round API (`add_buffered_round`, `next_msg_in`). The buffer implementation is ours. `RoundBufBounded` is the wrong buffer for this round.

## What goes wrong with a shared cap

`RoundBufBounded` stores every not-yet-read message of the round in one queue. `add_message` returns `RoundBufOverflow` once that queue is full. The router remembers the error, reports that the round wants no more messages, and drops later messages for the round. After the messages already queued have been read, `next_msg_in` returns that error and closes the round.

Each round has its own queue. That does not keep the ACK queue empty while the party is still finishing an earlier round. `complete` reads the single incoming stream and files each message into the queue for its round number. ACK messages that arrive during rounds 1–3 are appended to the ACK queue before this party has called `next_msg_in`.

A party can use that window. It sends more ACK messages than the cap to one victim, then lets the last round-3 message through. The victim's ACK round returns an error. The other honest parties never saw the flood, their queues are fine, and they finish and adopt the new share. The victim does not. That is the selective-abort split the ACK round is there to close.

The standalone consensus example does not hit this. It calls `next_msg_in` immediately, so its queue stays about one message deep. The overflow needs an earlier round still sitting in `complete`.

## What this crate does

`PerSenderBuf` keeps a separate count per authenticated sender. The cap is `n` queued messages from that sender. A further message from the same sender is discarded, and `add_message` still returns `Ok`. The round stays open, so a message that arrives later is still delivered.

Discarding the new message, rather than the oldest, matters. Junk that arrives while the queue is full does not push a message already queued out of it.

`n` is the most an honest party sends: its own proof, plus one forward of each of the other `n - 1` proofs. A flood from one sender fills only that sender's slots. A forward from an honest party uses the honest sender's slots, so it still fits. The sender index is the one on the incoming message. `relayed_from` is not used for the cap, so a party cannot spend another party's slots by claiming to relay them.

This bound is not part of the protocol spec. It is there so one party cannot close another party's ACK round.
