<!-- cargo-rdme start -->

![License](https://img.shields.io/crates/l/cggmp21.svg)
[![Docs](https://docs.rs/cggmp21/badge.svg)](https://docs.rs/cggmp21)
[![Crates io](https://img.shields.io/crates/v/cggmp21.svg)](https://crates.io/crates/cggmp21)
[![Discord](https://img.shields.io/discord/905194001349627914?logo=discord&logoColor=ffffff&label=Discord)][in Discord]

# Threshold ECDSA based on [CGGMP21] paper

<!-- TOC STARTS -->

- [Running the protocol](#running-the-protocol)
  * [Networking](#networking)
    + [Signer indices](#signer-indices)
  * [Execution ID](#execution-id)
  * [Auxiliary info generation](#auxiliary-info-generation)
    + [On reusability of the auxiliary data](#on-reusability-of-the-auxiliary-data)
  * [Distributed Key Generation (DKG)](#distributed-key-generation-dkg)
  * [Signing](#signing)
- [Sync API](#sync-api)
- [HD wallets support](#hd-wallets-support)
- [SPOF code: Key Import and Export](#spof-code-key-import-and-export)
- [Differences between the implementation and CGGMP21](#differences-between-the-implementation-and-cggmp21)
- [Timing attacks](#timing-attacks)
- [Join us in Discord!](#join-us-in-discord)

<!-- TOC ENDS -->

[CGGMP21] is a state-of-art ECDSA TSS protocol that supports 1-round signing (requires preprocessing),
identifiable abort, provides two signing protocols (3+1 and 5+1 rounds with different complexity
of abort identification) and key refresh protocol out of the box.

This crate implements:
* Threshold (i.e., t-out-of-n) and non-threshold (i.e., n-out-of-n) key generation
* (3+1)-round general threshold and non-threshold signing
* Auxiliary info generation protocol
* Key refresh for non-threshold keys
* HD-wallets support based on [slip10] standard (compatible with [bip32]) \
  Requires `hd-wallets` feature

A self-contained description of the protocols we implemented is available [here][the spec].

We also provide auxiliary tools like:
* Secret key reconstruction (exporting key from TSS)
* Trusted dealer (importing key into TSS)

This crate **does not** (currently) support:
* Key refresh for threshold keys (i.e., t-out-of-n)
* Identifiable abort
* The (5+1)-round signing protocol

Our implementation has been audited by Kudelski. Report can be found [here][report].

> About notion of threshold and non-threshold keys: originally, CGGMP21 paper does not have support of
arbitrary `t` and only works with non-threshold n-out-of-n keys. We have added support of arbitrary
threshold $2 \le t \le n$, however, we made it possible to opt out therhsoldness so original CGGMP21
protocol can be carried out if needed.

## Running the protocol

### Networking
The most essential part of running an interactive protocol is to define how parties can communicate with
each other. Our `cggmp21` library is agnostic to the network layer and only requires you to provide two
things: a stream of incoming messages and a sink for outgoing messages, i.e.:

```rust
let incoming: impl Stream<Item = Result<Incoming<Msg>>>;
let outgoing: impl Sink<Outgoing<Msg>>;
```

where:
* `Msg` is a protocol message (e.g., `signing::msg::Msg`)
* `round_based::Incoming` and `round_based::Outgoing` wrap `Msg` and provide additional data (e.g., sender/recepient)
* `futures::Stream` and `futures::Sink` are well-known async primitives.

Once you have that, you can construct an `MpcParty`:


```rust
let delivery = (incoming, outgoing);
let party = round_based::MpcParty::connected(delivery);
```

The concrete networking implementation to use will depend heavily on the specific application.
Some applications may use libp2p; others may prefer having a central delivery server or a database
(like Redis or Postgres); some specific applications may want to communicate over a public
blockchain, and so on.

Whatever networking implementation you use, keep in mind that:

* All messages must be authenticated \
  Whenever one party receives a message from another, the receiver should cryptographically
  verify that the message comes from the claimed sender.
* All p2p messages must be encrypted \
  Only the designated recipient should be able to read the message

#### Signer indices
Our library uses indices to uniquely refer to particular signers sharing a key. Each index `i`
is an unsigned integer `u16` with $0 \le i < n$ where `n` is the total number of parties.

All signers should have the same view about each others' indices. For instance, if Signer A
holds index 2, then all other signers must agree that i=2 corresponds to Signer A.

Assuming some sort of PKI (which would anyway likely be used to ensure secure communication,
as described above), each signer has a public key that uniquely identifies that signer.
It is then possible to assign unique indices to the signers by lexicographically sorting the
signers' public keys, and letting the index of a signer be the position of that signer's public
key in the sorted list.

### Execution ID
Execution of our protocols requires all participants to agree on unique execution ID (aka
session identifier) that is assumed never to repeat. This string provides context separation
between different executions of the protocol to ensure that an adversary cannot replay messages
from one execution to another.

Once signers can talk to each other and share an execution ID, they're ready to do MPC!

### Auxiliary info generation
In the usual flow, signers run a protocol for auxiliary-data generation before running distributed
key generation. This protocol sets up certain parameters (in particular, Paillier moduli
for each of the signers) that will be used during the signing protocols. This protocol can be
run as follows:

```rust
// Prime generation can take a while
let pregenerated_primes = cggmp21::PregeneratedPrimes::generate(&mut OsRng);

let eid = cggmp21::ExecutionId::new(b"execution id, unique per protocol execution");
let i = /* signer index, same as at keygen */;
let n = /* number of signers */;

let aux_info = cggmp21::aux_info_gen(eid, i, n, pregenerated_primes)
    .start(&mut OsRng, party)
    .await?;
```

The auxiliary-data generation protocol is computationally heavy as it requires the generation
of safe primes and involves several zero-knowledge (ZK) proofs.

#### On reusability of the auxiliary data
The CGGMP21 paper assumes that new auxiliary data is generated for each secret key that is shared.
However, examination of the proof shows that this is not necessary, and a fixed group of signers
can use the same auxiliary data for the secure sharing/usage of multiple keys.

### Distributed Key Generation (DKG)
The DKG protocol involves all signers who will co-share a key. All signers need to agree on
some basic parameters including the participants' indices, the execution ID, and the
threshold value (i.e., t). The protocol can be executed as

```rust
use cggmp21::supported_curves::Secp256k1;

let eid = cggmp21::ExecutionId::new(b"execution id, unique per protocol execution");
let i = /* signer index (0 <= i < n) */;
let n = /* number of signers taking part in key generation */;
let t = /* threshold */;

let incomplete_key_share = cggmp21::keygen::<Secp256k1>(eid, i, n)
    .set_threshold(t)
    .start(&mut OsRng, party)
    .await?;
```

The above produces an `IncompleteKeyShare`. An incomplete key share can be saved on disk by serializing using
[`serde` crate][serde]. Treat this material appropriately as it contains sensitive information.

Assuming auxiliary-data generation has already been done (see above), you can "complete" the
key share using:

```rust
let key_share = cggmp21::KeyShare::from_parts((incomplete_key_share, aux_info))?;
```

### Signing
Once signers have a set of "completed" key shares, they can sign or generate presignatures.
In either case, exactly the threshold number (i.e., t) of signers must take part in the protocol.
As in the DKG protocol, each signer needs to be assigned a unique index, now in the range from 0
to t-1. But the signers also need to know which index each signer occupied at the time of keygen.

In the example below, we do a full signing:
```rust
let eid = cggmp21::ExecutionId::new(b"execution id, unique per protocol execution");

let i = /* signer index (0 <= i < min_signers) */;
let parties_indexes_at_keygen: [u16; MIN_SIGNERS] =
    /* parties_indexes_at_keygen[i] is the index the i-th party had at keygen */;
let key_share = /* completed key share */;

let data_to_sign = cggmp21::DataToSign::digest::<Sha256>(b"data to be signed");

let signature = cggmp21::signing(eid, i, &parties_indexes_at_keygen, &key_share)
    .sign(&mut OsRng, party, data_to_sign)
    .await?;
```

Alternatively, you can generate a presignature and later use it to sign:
1. Use `SigningBuilder::generate_presignature` to run the presignature generation protocol
2. Later, when a signing request is received, each signer issues a partial signature using
   `Presignature::issue_partial_signature`
3. A threshold number of partial signatures can be combined using `PartialSignature::combine` to
   obtain a full signature

**Never reuse presignatures!** If you use the same presignature to sign two different messages,
the private key may be leaked.

## Sync API
Every protocol is defined as async function. If you need to run a protocol in non-async environment,
library provides a wrapper that allows you to execute protocol using sync API only.

To use it, you need to enable `state-machine` feature. Then, for every protocol definition, you can
find a companion function that returns `StateMachine`
which can be used to carry out the protocol. For instance, if you do presignature generation, use
`signing::SigningBuilder::generate_presignature_sync`.

## HD wallets support
Library supports non-hardened deterministic key derivation based on [slip10] standard (compatible
with [bip32]). It allows signers to generate a master key once, and then use it to instantaneously
derive as many child keys as needed. Child key derivation takes place within signing protocol
practically at no cost.

In order to use HD wallets, `hd-wallets` feature must be enabled. Then, a master key needs to be
generated by running a regular key generation protocol with `hd_wallet`
set to `true`.

When master key is generated, you can issue a signature for child key by setting
derivation path in the signing.

## SPOF code: Key Import and Export
CGGMP21 protocol is designed to avoid Single Point of Failure by guaranteeing that attacker would
need to compromise threshold amount of nodes to obtain a secret key. However, some use-cases may
require you to create a SPOF, for instance, importing an existing key into TSS and exporting key
from TSS.

Such use-cases contradict to nature of MPC so we don't include those primitives by default.
However, you may opt for them by enabling `spof` feature, then you can use `trusted_dealer`
for key import and `key_share::reconstruct_secret_key` for key export.

## Differences between the implementation and CGGMP21
[CGGMP21] only defines a non-threshold protocol. To support general thresholds,
we defined our own CGGMP21-like key generation and threshold signing
protocols. However, we keep both
threshold and non-threshold versions of the protocols in the crate, so if you opt for the non-threshold
protocol, you will be running the original protocol defined in the paper.

There are other (small) differences in the implementation compared to the original paper (mostly typo fixes);
they are all documented in [the spec].

[CGGMP21]: https://ia.cr/2021/060
[the spec]: https://lfdt-lockness.github.io/cggmp21/cggmp21-spec.pdf
[security guidelines]: #security-guidelines
[slip10]: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
[bip32]: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
[report]: https://github.com/LFDT-Lockness/cggmp21/blob/m/docs/audit_report.pdf
[serde]: https://serde.rs/

## Timing attacks
Timing attacks are type of side-channel attacks that leak sensitive information through duration of
execution. We consider timing attacks out of scope as they are nearly impossible to perform for such
complicated protcol as CGGMP21 and impossible to do in our specific deployment. Thus, we intentionally
don't do constant-time operations which gives us a significant performance boost.

## Join us in Discord!
Feel free to reach out to us [in Discord]!

[in Discord]: https://discordapp.com/channels/905194001349627914/1285268686147424388

<!-- cargo-rdme end -->
