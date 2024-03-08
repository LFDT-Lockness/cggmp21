![License](https://img.shields.io/crates/l/cggmp21.svg)
[![Docs](https://docs.rs/cggmp21/badge.svg)](https://docs.rs/cggmp21)
[![Crates io](https://img.shields.io/crates/v/cggmp21.svg)](https://crates.io/crates/cggmp21)

# Threshold ECDSA based on [CGGMP21] paper

[CGGMP21] is a state-of-art ECDSA TSS protocol that supports 1-round signing (requires preprocessing),
identifiable abort, provides two signing protocols (3+1 and 5+1 rounds with different complexity
of abort identification) and key refresh protocol out of the box.

This crate implements:
* General threshold (i.e., t-out-of-n) and full threshold (i.e., n-out-of-n) key generation
* (3+1)-round general threshold and full threshold signing
* Auxiliary info generation protocol
* Key refresh for full-threshold keys
* HD-wallets support based on [slip10] standard (compatible with [bip32]) \
  Requires `hd-wallets` feature

We also provide auxiliary tools like:
* Secret key reconstruction (exporting key from TSS)
* Trusted dealer (importing key into TSS)

This crate **does not** (currently) support:
* Key refresh for general thresholds
* Identifiable abort
* The (5+1)-round signing protocol

## Running the protocol

### Networking
In order to run the protocol, you need to define how each signer can communicate with other signers. We
use a `round_based` framework that handles networking. Basically, you need to define a stream
of `incoming` messages and sink of `outgoing` messages:

```rust
let incoming: impl Stream<Item = Result<Incoming<Msg>>>;
let outgoing: impl Sink<Outgoing<Msg>>;
```

where:
* `Msg` is a protocol message (e.g., `signing::msg::Msg`)
* `round_based::Incoming` and `round_based::Outgoing` wrap `Msg` and provide additional data (e.g., sender/recepient)
* `futures::Stream` and `futures::Sink` are well-known async primitives.

Then, construct a `round_based::MpcParty`:
```rust
let delivery = (incoming, outgoing);
let party = round_based::MpcParty::connected(delivery);
```

#### Signer indexes
Each signer in a protocol execution (keygen/signing/etc.) occupies a unique index $i$ ($0 \le i < n$,
where $n$ is number of parties overall). For instance, if Signer A occupies index `2`, then all
other signers must agree that `i=2` corresponds to Signer A.

Assuming you have a PKI (which is anyway needed to comply with [security requirements]) and each signer
has a public key uniqely idenitifying that signer, you can assign unique indexes to the signers as follows:
1. Make a list of signers' public keys
2. Sort the list of public keys
3. Assign each signer an index `i` such that `i` corresponds to the position of the signer's public key in the
   sorted list of public keys

[security requirements]: #security

#### Security
Make sure that the communication layer complies with security requirements:
* All messages sent must be authenticated
* All p2p messages must be encrypted

### Execution ID
When executing a protocol, signers need to agree on a unique identifier of the protocol execution `ExecutionId`.
The Execution ID needs to be unique per protocol execution (keygen/signing/etc.), otherwise it may compromise security.
The Execution ID needs to be the same for all signers taking part in the protocol, otherwise protocol will abort.
Execution ID **does not** need to be secret.

Once signers can talk to each other and share an execution ID, they're ready to generate a key!

### Distributed Key Generation
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
This code outputs `IncompleteKeyShare`. Note that this key share is not yet ready to do signing. You need to “complete” it
by generating auxiliary info (see below).

### Auxiliary info generation
After key generation, all signers need to take part in generation of auxiliary information. Make sure all signers occupy exactly
the same indexes as at keygen.
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

After keygen and aux info gen are done, you can make a “complete” key share that can be used for signing:
```rust
let key_share = cggmp21::KeyShare::from_parts((incomplete_key_share, aux_info))?;
```

### Signing
Once a complete key share is obtained, signers can sign or generate presignatures. In either case, the required threshold t of
signers must take part in the protocol. Each signer needs to be assigned a unique index
`0 <= i < t`, but we also need to know which index each signer had at keygen.

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
3. The requisite number of partial signatures can be combined using `PartialSignature::combine` to
   obtain a full signature

**Never reuse presignatures!** If you use the same presignature to sign two different messages,
it leaks information about key shares to anyone who can observe the signatures.

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

## Differences between the implementation and [CGGMP21]
[CGGMP21] only defines a full threshold protocol. To support general thresholds,
we defined our own CGGMP21-like key generation and threshold signing
protocols. However, we keep both
general threshold and full threshold versions of the protocols in the crate, so if you opt for the full threshold
protocol, you will be running the original protocol defined in the paper.

There are other (small) differences in the implementation compared to the original paper (mostly typo fixes);
they are all documented in [the spec].

[CGGMP21]: https://ia.cr/2021/060
[the spec]: https://dfns.github.io/cggmp21/cggmp21-spec.pdf
[security guidelines]: #security-guidelines
[slip10]: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
[bip32]: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

## Timing attacks
Timing attacks are type of side-channel attacks that leak sensitive information through duration of
execution. We consider timing attacks out of scope as they are nearly impossible to perform for such
complicated protcol as CGGMP21 and impossible to do in our specific deployment. Thus, we intentionally
don't do constant-time operations which gives us a significant performance boost.
