# Threshold ECDSA based on CGGMP21 paper

[CGGMP21] is a state-of-art ECDSA TSS protocol that supports 1-round signing (requires preprocessing),
identifiable abort, provides two signing protocols (3+1 and 5+1 rounds with different complexity
of abort identification) and key refresh protocol out of the box.

This crate implements:
* Threshold and non-threshold key generation
* 3+1 rounds threshold and non-threshold signing
* Auxiliary info generation protocol
* Key refresh for non-threshold keys

We also provide auxiliary tools like:
* Secret key reconstruction (exporting key from TSS)
* Trusted dealer (importing key into TSS)

This crate **does not** support (currently):
* Threshold key refresh
* Identifiable abort
* 5+1 rounds signing protocol

## Running protocol

### Networking
In order to run protocol, you need to define how signer can communicate with other signers. We
use `round_based` framework that handles network part. Basically, you need to define: a stream
of `incoming` messages and sink of `outgoing` messages:

```rust
let incoming: impl Stream<Item = Result<Incoming<Msg>>>;
let outgoing: impl Sink<Outgoing<Msg>>;
```

where:
* `Msg` is protocol message (e.g. `signing::msg::Msg`)
* `round_based::Incoming` and `round_based::Outgoing` wrap `Msg` and provide additional data (e.g. sender/recepient)
* `futures::Stream` and `futures::Sink` are well-known async primitives.

Then, construct a `round_based::MpcParty`:
```rust
let delivery = (incoming, outgoing);
let party = round_based::MpcParty::connected(delivery);
```

Make sure that communication layer complies with security requirements:
* All messages sent between parties must be authenticated
* All p2p messages must be encrypted

Now you're ready to generate a key!

### Distributed Key Generation
```rust
use cggmp21::supported_curves::Secp256k1;

let eid = cggmp21::ExecutionId::new(b"execution id, unique per protocol execution");
let i = /* signer index (0 <= i < n) */;
let n = /* amount of signers taking part in key generation */;
let t = /* threshold */;

let incomplete_key_share = cggmp21::keygen::<Secp256k1>(eid, i, n)
    .set_threshold(t)
    .start(&mut OsRng, party)
    .await?;
```
This code outputs `IncompleteKeyShare`. Note that this key share is not ready yet to do signing. You need to "complete" it
by generating auxiliary info (see below).

### Auxiliary info generation
After key generation, all signers need to take part in auxiliary information generation. Make sure all signers occupy exactly
the same indexes as at keygen.
```rust
// Primes generation can take a while
let pregenerated_primes = cggmp21::PregeneratedPrimes::generate(&mut OsRng);

let eid = cggmp21::ExecutionId::new(b"execution id, unique per protocol execution");
let i = /* signer index, same as at keygen */;
let n = /* amount of signers */;

let aux_info = cggmp21::aux_info_gen(eid, i, n, pregenerated_primes)
    .start(&mut OsRng, party)
    .await?;
```

After keygen and aux info gen are done, you can make a "complete" key share that can be used for signing:
```rust
let key_share = cggmp21::KeyShare::make(incomplete_key_share, aux_info)?;
```

### Signing
Once completed key share is obtained, signers can do signing or generate presignatures. In either case, threshold amount of
signers must take part in the protocol. Similar to previous protocols, at signing each signer needs to be assigned an index
`0 <= i < min_signers`, but we also need to know which index each signer occupied at keygen.

In the example below, we do a full signing:
```rust
let eid = cggmp21::ExecutionId::new(b"execution id, unique per protocol execution");

let i = /* signer index (0 <= i < min_signers) */;
let parties_indexes_at_keygen: [u16; MIN_SIGNERS] =
    /* parties_indexes_at_keygen[i] is index which i-th party occupied at keygen */;
let key_share = /* completed key share */;

let data_to_sign = cggmp21::DataToSign::digest::<Sha256>(b"data to be signed");

let signature = cggmp21::signing(eid, i, &parties_indexes_at_keygen, &key_share)
    .sign(&mut OsRng, party, data_to_sign)
    .await?;
```

Alternatively, you can generate presignature and use it to sign data:
1. Use `SigningBuilder::generate_presignature` to run presignature generation protocol
2. Once signing request is received, each signer issues a partial signature using
   `Presignature::issue_partial_signature`
3. Combine threshold amount of partial signatures using `PartialSignature::combine` to
   obtain a regular signature

**Never reuse presignatures!** If you use the same presignature to sign two different messages,
it leaks private key to anyone who can observe the signatures.

## Implementation vs CGGMP21 paper differences
Original CGGMP21 paper only defines non-threshold (n-out-of-n) protocol. To support threshold
(t-out-of-n) signing, we defined our own CGGMP21-like key generation and threshold signing
protocol which works based on original non-threshold signing protocol. However, we keep both
threshold and non-threshold versions of the protocols in the crate, so if you opt for non-threshold
protocol, you will be running original protocol defined in the paper.

There are other differences in the implementation compared to original paper (mostly typo fixes),
they are all documented in [the spec].

[CGGMP21]: https://ia.cr/2021/060
[the spec]: https://github.com/dfns-labs/cggmp21/tree/m/docs/spec.pdf
[security guidelines]: #security-guidelines
