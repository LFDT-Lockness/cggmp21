//! Signing protocol

use digest::Digest;
use futures::SinkExt;
use generic_ec::{coords::AlwaysHasAffineX, Curve, NonZero, Point, Scalar, SecretScalar};
use generic_ec_zkp::polynomial::lagrange_coefficient_at_zero;
use paillier_zk::{backend::Integer, fast_paillier};
use paillier_zk::{
    dlog_with_el_gamal_commitment as pi_elog, paillier_affine_operation_in_range as pi_aff,
    paillier_encryption_in_range_with_el_gamal as pi_enc_elg, IntegerExt,
};
use rand_core::{CryptoRng, RngCore};
use round_based::{
    rounds_router::{simple_store::RoundInput, RoundsRouter},
    runtime::AsyncRuntime,
    Delivery, Mpc, MpcParty, Outgoing, PartyIndex,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::errors::IoError;
use crate::key_share::{InvalidKeyShare, KeyShare, PedersenParams, VssSetup};
use crate::progress::Tracer;
use crate::{security_level::SecurityLevel, utils, ExecutionId};

use self::msg::*;

/// A message digest that is guaranteed to have a known preimage, making it safe for signing.
///
/// This struct wraps a scalar value ([`Scalar<E>`](Scalar)) that represents the cryptographic hash
/// of a message. It is the primary and recommended type for all signing operations in this library.
///
/// ## Purpose and Safety
///
/// The key security feature of `DataToSign` is its construction method. An instance of this struct
/// can only be created by providing the original message bytes to the library's API. The library
/// then performs the hashing internally.
///
/// This design acts as a type-safe guard, ensuring that the system will only ever sign a hash for
/// which the original message (the "preimage") is known and has been processed by the library.
/// This prevents a critical class of signature forgery attacks where an attacker provides a raw,
/// maliciously crafted hash (refer to [`PrehashedDataToSign`] docs to learn more about this attack).
#[derive(Debug, Clone, Copy)]
pub struct DataToSign<E: Curve>(Scalar<E>);

impl<E: Curve> DataToSign<E> {
    /// Construct a `DataToSign` by hashing `data` with algorithm `D`
    pub fn digest<D: Digest>(data: &[u8]) -> Self {
        DataToSign(Scalar::from_be_bytes_mod_order(D::digest(data)))
    }

    /// Constructs a `DataToSign` from output of given digest
    pub fn from_digest<D: Digest>(hash: D) -> Self {
        DataToSign(Scalar::from_be_bytes_mod_order(hash.finalize()))
    }

    /// Returns a scalar that represents a data to be signed
    pub fn to_scalar(self) -> Scalar<E> {
        self.0
    }
}

/// A pre-hashed message digest intended for signing, where the original message (preimage) may
/// be unknown.
///
/// This struct wraps a scalar value representing a message digest. Unlike its safer counterpart,
/// [`DataToSign`], this struct can be constructed directly from a raw scalar, bypassing the safety
/// check that ensures the original message is known.
///
/// ## Context: `PrehashedDataToSign` vs. `DataToSign`
/// This library provides two types for data to be signed:
///
/// * [`DataToSign`] **(Recommended)**: This is the safe, default option. Its API requires you to
///   provide the original message bytes. The library then handles the hashing internally. This acts
///   as a type-safe guard, guaranteeing that the signature corresponds to a known message.
/// * `PrehashedDataToSign` **(Advanced)**: This is a low-level type for specific, advanced use
///   cases. It contains a hash that was computed externally.
///
/// This `PrehashedDataToSign` struct is only accepted by library functions where it is safe to do
/// so—specifically, in the full interactive signing protocol where the forgery attacks described
/// below are not applicable.
///
/// ## ⚠️ Assume Preimage Known: Advanced Use Only
/// This library offers a feature flag named `insecure-assume-preimage-known` for
/// highly specialized use cases. When enabled, this feature exposes the method
/// [`PrehashedDataToSign::insecure_assume_preimage_known`] which allows you to convert a
/// `PrehashedDataToSign` directly into a [`DataToSign`]. This is a powerful but extremely dangerous
/// operation. It overrides the library's type safety, telling the system to trust that a known
/// original message exists for the given hash, even if one does not.
///
/// This feature **completely bypasses** the security guarantees provided by the [`DataToSign`] type
/// and should almost never be used.
///
/// ### Potential Attack: Signature Forgery via Raw Hash Signing
///
/// This attack, detailed in [this paper](https://eprint.iacr.org/2021/1330.pdf) (Section 1.1.2, “An
/// attack on ECDSA with presignatures”), enables signature forgery when a system signs raw hashes
/// in combination with presignatures.
///
/// The core idea is that an attacker can forge a signature for a message of their choice, `m'`, by
/// tricking the system into signing a different, maliciously crafted hash, `h`.
///
/// Here’s a simplified breakdown of how it works:
///
/// * **Message Selection**: The attacker first chooses a target message, `m'`, that they want a
///   forged signature for
/// * **Malicious Hash Construction**: Instead of submitting `h' = H(m')`, the attacker uses the
///   hash of their target message, `H(m')`, and public data from the presignature to compute a new,
///   malicious hash value, `h`. This `h` has no known preimage and appears random.
/// * **Signing Request**: The attacker submits this raw hash `h` to the signing protocol.
/// * **Forgery**: The protocol signs `h` and returns a signature component. The attacker then uses
///   this component to mathematically compute the final, valid signature for their original target
///   message, `m'`.
///
/// Essentially, the attacker exploits the signing algorithm's structure. By carefully crafting
/// the hash input, they can predict and manipulate the output to forge a signature for an entirely
/// different message. This is why **signing a hash without knowing its original message (preimage)
/// is extremely dangerous** in this context.
#[derive(Clone, Copy, Debug)]
pub struct PrehashedDataToSign<E: Curve>(Scalar<E>);

impl<E: Curve> PrehashedDataToSign<E> {
    /// Constructs a `PrehashedDataToSign` from scalar
    ///
    /// `scalar` must be output of cryptographic hash function applied to original message to be signed
    pub fn from_scalar(scalar: Scalar<E>) -> Self {
        Self(scalar)
    }

    /// Returns a scalar that represents a data to be signed
    pub fn to_scalar(self) -> Scalar<E> {
        self.0
    }

    /// Converts a `PrehashedDataToSign` directly into a [`DataToSign`]
    ///
    /// **⚠️ Extremely dangerous operation.** It overrides the library's type safety, telling the
    /// system to trust that a known original message exists for the given hash, even if one does
    /// not. Read [`PrehashedDataToSign`] docs to learn why it's dangerous.
    ///
    /// It's **only** safe to use this method if you have either:
    ///
    /// 1. Hashed the original message yourself to generate this scalar (prefer directly using
    ///    [`DataToSign`] when possible).
    /// 2. Can otherwise completely verify and trust the source of the prehashed data.
    #[cfg(feature = "insecure-assume-preimage-known")]
    pub fn insecure_assume_preimage_known(self) -> DataToSign<E> {
        DataToSign(self.0)
    }
}

mod internal {
    pub trait Sealed {}
}

/// Data to be signed, regardless of whether original message to be signed is known or not
///
/// This library accepts `&dyn AnyDataToSign` **only if** it doesn't matter for security whether
/// original message is known or not.
pub trait AnyDataToSign<E: Curve>: Send + Sync + internal::Sealed {
    /// Returns a scalar that represents a data to be signed
    fn to_scalar(&self) -> Scalar<E>;
}
impl<E: Curve> internal::Sealed for DataToSign<E> {}
impl<E: Curve> internal::Sealed for PrehashedDataToSign<E> {}

impl<E: Curve> AnyDataToSign<E> for DataToSign<E> {
    fn to_scalar(&self) -> Scalar<E> {
        self.0
    }
}
impl<E: Curve> AnyDataToSign<E> for PrehashedDataToSign<E> {
    fn to_scalar(&self) -> Scalar<E> {
        self.0
    }
}

/// Presignature, can be used to issue a [partial signature](PartialSignature) without interacting with other signers
///
/// [Threshold](crate::key_share::AnyKeyShare::min_signers) amount of partial signatures (from different signers) can be [combined](PartialSignature::combine) into regular signature
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Presignature<E: Curve> {
    /// $\Gamma$ component of presignature
    pub Gamma: NonZero<Point<E>>,
    /// $\tilde k_i$ component of presignature
    pub tilde_k: SecretScalar<E>,
    /// $\tilde \chi_i$ component of presignature
    pub tilde_chi: SecretScalar<E>,
}

/// Public part of the presignature that can be used to verify partial signatures from other parties
///
/// They are used to validate partial signature produced by the signers from a presignature
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresignaturePublicData<E: Curve> {
    /// $\Gamma$ presignature commitment
    pub Gamma: NonZero<Point<E>>,
    /// $(\tilde \Delta_j, \tilde S_j)_{j\in\[n\]}$
    pub commitments: Vec<PresignatureCommitment<E>>,
}

/// Presignature commitment, used to verify partial signature correctness
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresignatureCommitment<E: Curve> {
    /// $\tilde \Delta_j$
    pub tilde_Delta: Point<E>,
    /// $\tilde \S_j$
    pub tilde_S: Point<E>,
}

/// Partial signature issued by signer for given message
///
/// Can be obtained using [`Presignature::issue_partial_signature`]. Partial signature doesn't carry any sensitive inforamtion.
///
/// Threshold amount of partial signatures can be combined into a regular signature using [`PartialSignature::combine`]
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct PartialSignature<E: Curve> {
    /// $\sigma$ component of partial signature
    pub sigma: Scalar<E>,
}

/// ECDSA signature
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Debug)]
#[serde(bound = "")]
pub struct Signature<E: Curve> {
    /// $r$ component of signature
    pub r: NonZero<Scalar<E>>,
    /// $s$ component of signature
    pub s: NonZero<Scalar<E>>,
}

macro_rules! prefixed {
    ($name:tt) => {
        concat!("dfns.cggmp24.signing.", $name)
    };
}

#[doc = include_str!("../docs/mpc_message.md")]
pub mod msg {
    use digest::Digest;
    use generic_ec::Curve;
    use generic_ec::{Point, Scalar};

    use paillier_zk::fast_paillier;
    use paillier_zk::{
        dlog_with_el_gamal_commitment as pi_elog, paillier_affine_operation_in_range as pi_aff,
        paillier_encryption_in_range_with_el_gamal as pi_enc_elg,
    };
    use round_based::ProtocolMessage;
    use serde::{Deserialize, Serialize};

    use crate::utils;

    use super::PartialSignature;

    /// Signing protocol message
    ///
    /// Enumerates messages from all rounds
    #[derive(Clone, ProtocolMessage, Serialize, Deserialize)]
    #[serde(bound = "")]
    #[allow(clippy::large_enum_variant)]
    pub enum Msg<E: Curve, D: Digest> {
        /// Round 1a message
        Round1a(MsgRound1a<E>),
        /// Round 1b message
        Round1b(MsgRound1b<E>),
        /// Round 2 message
        Round2(MsgRound2<E>),
        /// Round 3 message
        Round3(MsgRound3<E>),
        /// Round 4 message
        Round4(MsgRound4<E>),
        /// Reliability check message (optional additional round)
        ReliabilityCheck(MsgReliabilityCheck<D>),
    }

    /// Message from round 1a
    #[derive(Clone, Serialize, Deserialize, udigest::Digestable)]
    #[serde(bound = "")]
    #[udigest(tag = prefixed!("round1"))]
    #[udigest(bound = "")]
    pub struct MsgRound1a<E: Curve> {
        /// $K_i$
        #[udigest(as = utils::encoding::Integer)]
        pub K: fast_paillier::Ciphertext,
        /// $G_i$
        #[udigest(as = utils::encoding::Integer)]
        pub G: fast_paillier::Ciphertext,
        /// $Y_i$
        pub Y: Point<E>,
        /// $A_{i,1}$
        pub A1: Point<E>,
        /// $A_{i,2}$
        pub A2: Point<E>,
        /// $B_{i,1}$
        pub B1: Point<E>,
        /// $B_{i,2}$
        pub B2: Point<E>,
    }

    /// Message from round 1b
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(bound = "")]
    pub struct MsgRound1b<E: Curve> {
        /// $\psi^0_{j,i}$
        pub psi0: pi_enc_elg::NiProof<E>,
        /// $\psi^1_{j,i}$
        pub psi1: pi_enc_elg::NiProof<E>,
    }

    /// Message from round 2
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(bound = "")]
    pub struct MsgRound2<E: Curve> {
        /// $\Gamma_i$
        pub Gamma: Point<E>,
        /// $D_{j,i}$
        pub D: fast_paillier::Ciphertext,
        /// $F_{j,i}$
        pub F: fast_paillier::Ciphertext,
        /// $\hat D_{j,i}$
        pub hat_D: fast_paillier::Ciphertext,
        /// $\hat F_{j,i}$
        pub hat_F: fast_paillier::Ciphertext,
        /// $\psi_i$
        pub tilde_psi: pi_elog::NiProof<E>,
        /// $\psi_{j,i}$
        pub psi_j: pi_aff::NiProof<E>,
        /// $\hat \psi_{j,i}$
        pub hat_psi_j: pi_aff::NiProof<E>,
    }

    /// Message from round 3
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(bound = "")]
    pub struct MsgRound3<E: Curve> {
        /// $\delta_i$
        pub delta: Scalar<E>,
        /// $S_i$
        pub S: Point<E>,
        /// $\Delta_i$
        pub Delta: Point<E>,
        /// $\psi'_i$
        pub psi_prime: pi_elog::NiProof<E>,
    }

    /// Message from round 4
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(bound = "")]
    pub struct MsgRound4<E: Curve> {
        /// $\sigma_i$
        pub partial_sig: PartialSignature<E>,
    }

    /// Message from auxiliary round for reliability check
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(bound = "")]
    pub struct MsgReliabilityCheck<D: Digest>(pub digest::Output<D>);
}

mod unambiguous {
    use crate::ExecutionId;

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("proof_enc"))]
    pub struct ProofEnc<'a> {
        pub sid: ExecutionId<'a>,
        pub prover: u16,
        /// Either `0` (corresponds to $\psi^0_{j,i}$) or `1` (corresponds to $\psi^1_{j,i}$)
        pub num: u8,
    }

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("proof_psi"))]
    pub struct ProofPsi<'a> {
        pub sid: ExecutionId<'a>,
        pub prover: u16,
        pub hat: bool,
    }

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("proof_elog"))]
    pub struct ProofElog<'a> {
        pub sid: ExecutionId<'a>,
        pub prover: u16,
        pub prime: bool,
    }

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("echo_round"))]
    #[udigest(bound = "")]
    pub struct Echo<'a, E: generic_ec::Curve> {
        pub sid: ExecutionId<'a>,
        pub ciphertexts: &'a super::MsgRound1a<E>,
    }
}

/// Signing entry point
pub struct SigningBuilder<
    'r,
    E,
    L = crate::default_choice::SecurityLevel,
    D = crate::default_choice::Digest,
> where
    E: Curve,
    L: SecurityLevel,
    D: Digest,
{
    i: PartyIndex,
    parties_indexes_at_keygen: &'r [PartyIndex],
    key_share: &'r KeyShare<E, L>,
    execution_id: ExecutionId<'r>,
    tracer: Option<&'r mut dyn Tracer>,
    enforce_reliable_broadcast: bool,
    _digest: std::marker::PhantomData<D>,

    #[cfg(feature = "hd-wallet")]
    additive_shift: Option<Scalar<E>>,
}

impl<'r, E, L, D> SigningBuilder<'r, E, L, D>
where
    E: Curve,
    NonZero<Point<E>>: AlwaysHasAffineX<E>,
    L: SecurityLevel,
    D: Digest<OutputSize = digest::typenum::U32> + Clone + 'static,
{
    /// Construct a signing builder
    pub fn new(
        eid: ExecutionId<'r>,
        i: PartyIndex,
        parties_indexes_at_keygen: &'r [PartyIndex],
        secret_key_share: &'r KeyShare<E, L>,
    ) -> Self {
        Self {
            i,
            parties_indexes_at_keygen,
            key_share: secret_key_share,
            execution_id: eid,
            tracer: None,
            enforce_reliable_broadcast: true,
            _digest: std::marker::PhantomData,
            #[cfg(feature = "hd-wallet")]
            additive_shift: None,
        }
    }

    /// Specifies another hash function to use
    pub fn set_digest<D2>(self) -> SigningBuilder<'r, E, L, D2>
    where
        D2: Digest,
    {
        SigningBuilder {
            i: self.i,
            parties_indexes_at_keygen: self.parties_indexes_at_keygen,
            key_share: self.key_share,
            tracer: self.tracer,
            enforce_reliable_broadcast: self.enforce_reliable_broadcast,
            execution_id: self.execution_id,
            _digest: std::marker::PhantomData,
            #[cfg(feature = "hd-wallet")]
            additive_shift: self.additive_shift,
        }
    }

    /// Specifies a tracer that tracks progress of protocol execution
    pub fn set_progress_tracer(mut self, tracer: &'r mut dyn Tracer) -> Self {
        self.tracer = Some(tracer);
        self
    }

    #[doc = include_str!("../docs/enforce_reliable_broadcast.md")]
    pub fn enforce_reliable_broadcast(self, v: bool) -> Self {
        Self {
            enforce_reliable_broadcast: v,
            ..self
        }
    }

    /// Specifies HD derivation path
    ///
    /// ## Example
    /// Set derivation path to m/1/999
    ///
    /// ```rust,no_run
    /// # let eid = cggmp24::ExecutionId::new(b"protocol nonce");
    /// # let (i, parties_indexes_at_keygen, key_share): (u16, Vec<u16>, cggmp24::KeyShare<cggmp24::supported_curves::Secp256k1>)
    /// # = unimplemented!();
    /// cggmp24::signing(eid, i, &parties_indexes_at_keygen, &key_share)
    ///     .set_derivation_path([1, 999])?
    /// # ; Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// ## Derivation algorithm
    /// This method uses [`hd_wallet::Slip10`] derivation algorithm, which can only be used with secp256k1
    /// and secp256r1 curves. If you need to use another one, see
    /// [`set_derivation_path_with_algo`](Self::set_derivation_path_with_algo)
    #[cfg(all(feature = "hd-wallet", feature = "hd-slip10"))]
    pub fn set_derivation_path<Index>(
        self,
        path: impl IntoIterator<Item = Index>,
    ) -> Result<
        Self,
        crate::key_share::HdError<<Index as TryInto<hd_wallet::NonHardenedIndex>>::Error>,
    >
    where
        hd_wallet::Slip10: hd_wallet::HdWallet<E>,
        hd_wallet::NonHardenedIndex: TryFrom<Index>,
    {
        self.set_derivation_path_with_algo::<hd_wallet::Slip10, _>(path)
    }

    /// Specifies HD derivation path, using HD derivation algorithm [`hd_wallet::HdWallet`]
    #[cfg(feature = "hd-wallet")]
    pub fn set_derivation_path_with_algo<Hd: hd_wallet::HdWallet<E>, Index>(
        mut self,
        path: impl IntoIterator<Item = Index>,
    ) -> Result<
        Self,
        crate::key_share::HdError<<Index as TryInto<hd_wallet::NonHardenedIndex>>::Error>,
    >
    where
        hd_wallet::NonHardenedIndex: TryFrom<Index>,
    {
        use crate::key_share::HdError;
        let public_key = self
            .key_share
            .extended_public_key()
            .ok_or(HdError::DisabledHd)?;
        self.additive_shift = Some(
            derive_additive_shift::<E, Hd, _>(public_key, path).map_err(HdError::InvalidPath)?,
        );
        Ok(self)
    }

    /// Starts presignature generation protocol
    pub async fn generate_presignature<R, M>(
        self,
        rng: &mut R,
        party: M,
    ) -> Result<(Presignature<E>, PresignaturePublicData<E>), SigningError>
    where
        R: RngCore + CryptoRng,
        M: Mpc<ProtocolMessage = Msg<E, D>>,
    {
        match signing_t_out_of_n(
            self.tracer,
            rng,
            party,
            self.execution_id,
            self.i,
            self.key_share,
            self.parties_indexes_at_keygen,
            None,
            self.enforce_reliable_broadcast,
            #[cfg(feature = "hd-wallet")]
            self.additive_shift,
            #[cfg(not(feature = "hd-wallet"))]
            None,
        )
        .await?
        {
            ProtocolOutput::Presignature(presig) => Ok(presig),
            ProtocolOutput::Signature(_) => Err(Bug::UnexpectedProtocolOutput.into()),
        }
    }

    /// Returns a state machine that can be used to carry out the presignature generation protocol
    ///
    /// See [`round_based::state_machine`] for details on how that can be done.
    #[cfg(feature = "state-machine")]
    pub fn generate_presignature_sync<R>(
        self,
        rng: &'r mut R,
    ) -> impl round_based::state_machine::StateMachine<
        Output = Result<(Presignature<E>, PresignaturePublicData<E>), SigningError>,
        Msg = Msg<E, D>,
    > + 'r
    where
        R: RngCore + CryptoRng,
    {
        round_based::state_machine::wrap_protocol(|party| self.generate_presignature(rng, party))
    }

    /// Starts signing protocol
    ///
    /// `message_to_sign` can be either [`DataToSign`] (original message being signed is known) or
    /// [`PrehashedDataToSign`] (only hash of the message being signed is known), protocol is secure
    /// regardless. However, the best practice is to use [`DataToSign`] whenever possible.
    pub async fn sign<R, M>(
        self,
        rng: &mut R,
        party: M,
        message_to_sign: &dyn AnyDataToSign<E>,
    ) -> Result<Signature<E>, SigningError>
    where
        R: RngCore + CryptoRng,
        M: Mpc<ProtocolMessage = Msg<E, D>>,
    {
        match signing_t_out_of_n(
            self.tracer,
            rng,
            party,
            self.execution_id,
            self.i,
            self.key_share,
            self.parties_indexes_at_keygen,
            Some(message_to_sign.to_scalar()),
            self.enforce_reliable_broadcast,
            #[cfg(feature = "hd-wallet")]
            self.additive_shift,
            #[cfg(not(feature = "hd-wallet"))]
            None,
        )
        .await?
        {
            ProtocolOutput::Signature(sig) => Ok(sig),
            ProtocolOutput::Presignature(_) => Err(Bug::UnexpectedProtocolOutput.into()),
        }
    }

    /// Returns a state machine that can be used to carry out the signing protocol
    ///
    /// See [`round_based::state_machine`] for details on how that can be done.
    ///
    /// `message_to_sign` can be either [`DataToSign`] (original message being signed is known) or
    /// [`PrehashedDataToSign`] (only hash of the message being signed is known), protocol is secure
    /// regardless. However, the best practice is to use [`DataToSign`] whenever possible.
    #[cfg(feature = "state-machine")]
    pub fn sign_sync<R>(
        self,
        rng: &'r mut R,
        message_to_sign: &'r dyn AnyDataToSign<E>,
    ) -> impl round_based::state_machine::StateMachine<
        Output = Result<Signature<E>, SigningError>,
        Msg = Msg<E, D>,
    > + 'r
    where
        R: RngCore + CryptoRng,
    {
        round_based::state_machine::wrap_protocol(move |party| {
            self.sign(rng, party, message_to_sign)
        })
    }
}

/// t-out-of-n signing
///
/// CGGMP paper doesn't support threshold signing out of the box. However, threshold signing
/// can be easily implemented on top of CGGMP's [`signing_n_out_of_n`] by converting polynomial
/// (VSS) key shares into additive (by multiplying at lagrange coefficient) and calling
/// t-out-of-t protocol. The trick is described in more details in the spec.
async fn signing_t_out_of_n<M, E, L, D, R>(
    mut tracer: Option<&mut dyn Tracer>,
    rng: &mut R,
    party: M,
    sid: ExecutionId<'_>,
    i: PartyIndex,
    key_share: &KeyShare<E, L>,
    S: &[PartyIndex],
    message_to_sign: Option<Scalar<E>>,
    enforce_reliable_broadcast: bool,
    additive_shift: Option<Scalar<E>>,
) -> Result<ProtocolOutput<E>, SigningError>
where
    M: Mpc<ProtocolMessage = Msg<E, D>>,
    E: Curve,
    L: SecurityLevel,
    D: Digest<OutputSize = digest::typenum::U32> + Clone + 'static,
    R: RngCore + CryptoRng,
    NonZero<Point<E>>: AlwaysHasAffineX<E>,
{
    tracer.protocol_begins();
    tracer.stage("Map t-out-of-n protocol to t-out-of-t");

    // Validate arguments
    let n: u16 = key_share
        .aux
        .pedersen_params
        .len()
        .try_into()
        .map_err(|_| Bug::PartiesNumberExceedsU16)?;
    let t = key_share
        .core
        .vss_setup
        .as_ref()
        .map(|s| s.min_signers)
        .unwrap_or(n);
    if S.len() != usize::from(t) {
        return Err(InvalidArgs::MismatchedAmountOfParties.into());
    }
    if !(i < t) {
        return Err(InvalidArgs::SignerIndexOutOfBounds.into());
    }
    if S.iter().any(|&S_j| S_j >= n) {
        return Err(InvalidArgs::InvalidS.into());
    }

    // Assemble x_i and \vec X
    let (mut x_i, mut X) = if let Some(VssSetup { I, .. }) = &key_share.core.vss_setup {
        // For t-out-of-n keys generated via VSS DKG scheme
        let I = utils::subset(S, I).ok_or(Bug::Subset)?;
        let X = utils::subset(S, &key_share.core.public_shares).ok_or(Bug::Subset)?;

        let lambda_i = lagrange_coefficient_at_zero(usize::from(i), &I).ok_or(Bug::LagrangeCoef)?;
        let x_i = (lambda_i * &key_share.core.x).into_secret();

        let lambda = (0..t).map(|j| lagrange_coefficient_at_zero(usize::from(j), &I));
        let X = lambda
            .zip(&X)
            .map(|(lambda_j, X_j)| Some(lambda_j? * X_j))
            .collect::<Option<Vec<_>>>()
            .ok_or(Bug::LagrangeCoef)?;

        (x_i, X)
    } else {
        // For n-out-of-n keys generated using original CGGMP DKG
        let X = utils::subset(S, &key_share.core.public_shares).ok_or(Bug::Subset)?;
        (key_share.core.x.clone(), X)
    };
    debug_assert_eq!(key_share.core.shared_public_key, X.iter().sum::<Point<E>>());

    // Apply additive shift
    let shift = additive_shift.unwrap_or(Scalar::zero());
    let Shift = Point::generator() * shift;

    X[0] = NonZero::from_point(X[0] + Shift).ok_or(Bug::DerivedChildKeyZero)?;
    if i == 0 {
        x_i = NonZero::from_scalar(x_i + shift)
            .ok_or(Bug::DerivedChildShareZero)?
            .into_secret();
    }
    debug_assert_eq!(
        key_share.core.shared_public_key + Shift,
        X.iter().sum::<Point<E>>()
    );

    // Assemble rest of the data
    let (p_i, q_i) = (&key_share.aux.p, &key_share.aux.q);
    let N = utils::subset(S, &key_share.aux.N)
        .ok_or(Bug::Subset)?
        .into_iter()
        .map(fast_paillier::EncryptionKey::from_n)
        .collect::<Vec<_>>();
    let R = utils::subset(S, &key_share.aux.pedersen_params).ok_or(Bug::Subset)?;

    // t-out-of-t signing
    signing_n_out_of_n::<_, _, L, _, _>(
        tracer,
        rng,
        party,
        sid,
        i,
        t,
        &x_i,
        &X,
        key_share.core.shared_public_key + Shift,
        p_i,
        q_i,
        &N,
        &R,
        message_to_sign,
        enforce_reliable_broadcast,
    )
    .await
}

/// Original CGGMP n-out-of-n signing
///
/// Implementation has very little differences compared to original CGGMP protocol: we added broadcast
/// reliability check, fixed some typos in CGGMP, etc. Differences are covered in the specs.
async fn signing_n_out_of_n<M, E, L, D, R>(
    mut tracer: Option<&mut dyn Tracer>,
    rng: &mut R,
    party: M,
    sid: ExecutionId<'_>,
    i: PartyIndex,
    n: u16,
    x_i: &NonZero<SecretScalar<E>>,
    X: &[NonZero<Point<E>>],
    pk: Point<E>,
    p_i: &Integer,
    q_i: &Integer,
    N: &[fast_paillier::EncryptionKey],
    R: &[PedersenParams],
    message_to_sign: Option<Scalar<E>>,
    enforce_reliable_broadcast: bool,
) -> Result<ProtocolOutput<E>, SigningError>
where
    M: Mpc<ProtocolMessage = Msg<E, D>>,
    E: Curve,
    L: SecurityLevel,
    D: Digest<OutputSize = digest::typenum::U32> + Clone + 'static,
    R: RngCore + CryptoRng,
    NonZero<Point<E>>: AlwaysHasAffineX<E>,
{
    let MpcParty {
        delivery, runtime, ..
    } = party.into_party();
    let (incomings, mut outgoings) = delivery.split();

    tracer.stage("Retrieve auxiliary data");
    let R_i = &R[usize::from(i)];

    let dec_i: fast_paillier::DecryptionKey =
        fast_paillier::DecryptionKey::from_primes(p_i.clone(), q_i.clone())
            .map_err(|_| Bug::InvalidOwnPaillierKey)?;

    tracer.stage("Precompute execution id and security params");
    let security_params = crate::utils::SecurityParams::new::<L>();

    tracer.stage("Setup networking");
    let mut rounds = RoundsRouter::<Msg<E, D>>::builder();
    let round1a = rounds.add_round(RoundInput::<MsgRound1a<E>>::broadcast(i, n));
    let round1b = rounds.add_round(RoundInput::<MsgRound1b<E>>::p2p(i, n));
    let round1a_sync = rounds.add_round(RoundInput::<MsgReliabilityCheck<D>>::broadcast(i, n));
    let round2 = rounds.add_round(RoundInput::<MsgRound2<E>>::p2p(i, n));
    let round3 = rounds.add_round(RoundInput::<MsgRound3<E>>::broadcast(i, n));
    let round4 = rounds.add_round(RoundInput::<MsgRound4<E>>::broadcast(i, n));
    let mut rounds = rounds.listen(incomings);

    // Round 1
    tracer.round_begins();

    tracer.stage("Generate local ephemeral secrets (k_i, y_i, p_i, v_i)");
    let gamma_i = SecretScalar::<E>::random(rng);
    let k_i = SecretScalar::<E>::random(rng);

    let v_i = Integer::sample_in_mult_group_of(rng, dec_i.n());
    let rho_i = Integer::sample_in_mult_group_of(rng, dec_i.n());

    tracer.stage("Encrypt G_i and K_i");
    let G_i = dec_i
        .encrypt_with(&utils::scalar_to_pm_bignumber(&gamma_i), &v_i)
        .map_err(|_| Bug::PaillierEnc(BugSource::G_i))?;
    let K_i = dec_i
        .encrypt_with(&utils::scalar_to_pm_bignumber(&k_i), &rho_i)
        .map_err(|_| Bug::PaillierEnc(BugSource::K_i))?;

    tracer.stage("Generate a_i, b_i, A_i1, A_i2, B_i1, B_i2");
    let Y_i = {
        let y_i = SecretScalar::<E>::random(rng);
        Point::generator() * y_i
    };
    let a_i = SecretScalar::<E>::random(rng);
    let b_i = SecretScalar::<E>::random(rng);

    let A_i1 = &a_i * Point::generator();
    let A_i2 = &a_i * Y_i + &k_i * Point::generator();

    let B_i1 = &b_i * Point::generator();
    let B_i2 = &b_i * Y_i + &gamma_i * Point::generator();

    tracer.send_msg();
    outgoings
        .feed(Outgoing::broadcast(Msg::Round1a(MsgRound1a {
            K: K_i.clone(),
            G: G_i.clone(),
            Y: Y_i,
            A1: A_i1,
            A2: A_i2,
            B1: B_i1,
            B2: B_i2,
        })))
        .await
        .map_err(IoError::send_message)?;
    tracer.msg_sent();

    for j in utils::iter_peers(i, n) {
        tracer.stage("Prove psi0_ji, psi1_ji");
        let R_j = &R[usize::from(j)];

        let psi0_ji = pi_enc_elg::non_interactive::prove::<E, D>(
            &unambiguous::ProofEnc {
                sid,
                prover: i,
                num: 0,
            },
            &R_j.into(),
            pi_enc_elg::Data {
                key: &dec_i,
                ciphertext: &K_i,
                a: &Y_i,
                b: &A_i1,
                x: &A_i2,
            },
            pi_enc_elg::PrivateData {
                plaintext: &utils::scalar_to_pm_bignumber(&k_i),
                nonce: &rho_i,
                b: a_i.as_ref(),
            },
            &security_params.pi_enc_elg,
            rng,
        )
        .map_err(|e| Bug::PiEncElg(BugSource::psi0, e))?;

        let psi1_ji = pi_enc_elg::non_interactive::prove::<E, D>(
            &unambiguous::ProofEnc {
                sid,
                prover: i,
                num: 1,
            },
            &R_j.into(),
            pi_enc_elg::Data {
                key: &dec_i,
                ciphertext: &G_i,
                a: &Y_i,
                b: &B_i1,
                x: &B_i2,
            },
            pi_enc_elg::PrivateData {
                plaintext: &utils::scalar_to_pm_bignumber(&gamma_i),
                nonce: &v_i,
                b: b_i.as_ref(),
            },
            &security_params.pi_enc_elg,
            rng,
        )
        .map_err(|e| Bug::PiEncElg(BugSource::psi1, e))?;

        tracer.send_msg();
        outgoings
            .feed(Outgoing::p2p(
                j,
                Msg::Round1b(MsgRound1b {
                    psi0: psi0_ji,
                    psi1: psi1_ji,
                }),
            ))
            .await
            .map_err(IoError::send_message)?;
        tracer.msg_sent();
    }
    tracer.send_msg();
    outgoings.flush().await.map_err(IoError::send_message)?;
    tracer.msg_sent();

    // Round 2
    tracer.round_begins();

    tracer.receive_msgs();
    // Contains G_j, K_j sent by other parties
    let ciphertexts = rounds
        .complete(round1a)
        .await
        .map_err(IoError::receive_message)?;
    let psi_proofs = rounds
        .complete(round1b)
        .await
        .map_err(IoError::receive_message)?;
    tracer.msgs_received();

    // Reliability check (if enabled)
    if enforce_reliable_broadcast {
        tracer.stage("Hash received msgs (reliability check)");
        let h_i = udigest::hash_iter::<D>(
            ciphertexts
                .iter_including_me(&MsgRound1a {
                    K: K_i.clone(),
                    G: G_i.clone(),
                    Y: Y_i,
                    A1: A_i1,
                    A2: A_i2,
                    B1: B_i1,
                    B2: B_i2,
                })
                .map(|ciphertexts| unambiguous::Echo { sid, ciphertexts }),
        );

        tracer.send_msg();
        outgoings
            .send(Outgoing::broadcast(Msg::ReliabilityCheck(
                MsgReliabilityCheck(h_i),
            )))
            .await
            .map_err(IoError::send_message)?;
        tracer.msg_sent();

        tracer.round_begins();

        tracer.receive_msgs();
        let round1a_hashes = rounds
            .complete(round1a_sync)
            .await
            .map_err(IoError::receive_message)?;
        tracer.msgs_received();
        tracer.stage("Assert other parties hashed messages (reliability check)");
        let parties_have_different_hashes =
            utils::collect_simple_blame(&round1a_hashes, |hash| hash.0 != h_i);
        if !parties_have_different_hashes.is_empty() {
            return Err(SigningAborted::Round1aNotReliable(parties_have_different_hashes).into());
        }
    }

    // Step 1. Verify proofs
    tracer.stage("Verify psi0, psi1 proofs");
    let faulty_parties =
        utils::collect_blame_with_data(&ciphertexts, &psi_proofs, |j, ciphertexts, proof| {
            let N_j = &N[usize::from(j)];
            pi_enc_elg::non_interactive::verify::<E, D>(
                &unambiguous::ProofEnc {
                    sid,
                    prover: j,
                    num: 0,
                },
                &R_i.into(),
                pi_enc_elg::Data {
                    key: N_j,
                    ciphertext: &ciphertexts.K,
                    a: &ciphertexts.Y,
                    b: &ciphertexts.A1,
                    x: &ciphertexts.A2,
                },
                &proof.psi0,
                &security_params.pi_enc_elg,
            )
            .err()?;
            pi_enc_elg::non_interactive::verify::<E, D>(
                &unambiguous::ProofEnc {
                    sid,
                    prover: j,
                    num: 1,
                },
                &R_i.into(),
                pi_enc_elg::Data {
                    key: N_j,
                    ciphertext: &ciphertexts.G,
                    a: &ciphertexts.Y,
                    b: &ciphertexts.B1,
                    x: &ciphertexts.B2,
                },
                &proof.psi1,
                &security_params.pi_enc_elg,
            )
            .err()
        });

    if !faulty_parties.is_empty() {
        return Err(SigningAborted::EncProofOfK(faulty_parties).into());
    }
    runtime.yield_now().await;

    // Step 2
    let Gamma_i = Point::generator() * &gamma_i;

    tracer.stage("Prove tilde_psi_i");
    let tilde_psi_i = pi_elog::non_interactive::prove::<E, D>(
        &unambiguous::ProofElog {
            sid,
            prover: i,
            prime: false,
        },
        pi_elog::Data {
            l: &B_i1,
            m: &B_i2,
            x: &Y_i,
            y: &Gamma_i,
            h: &Point::generator().to_point(),
        },
        pi_elog::PrivateData {
            y: gamma_i.as_ref(),
            lambda: b_i.as_ref(),
        },
        rng,
    )
    .map_err(|e| Bug::PiElog(BugSource::psi, e))?;
    runtime.yield_now().await;

    let J = Integer::one() << L::ELL_PRIME;

    let mut beta_sum = Scalar::zero();
    let mut hat_beta_sum = Scalar::zero();
    for (j, _, ciphertext_j) in ciphertexts.iter_indexed() {
        tracer.stage("Sample random r, hat_r, s, hat_s, beta, hat_beta");
        let R_j = &R[usize::from(j)];
        let enc_j = &N[usize::from(j)];

        let r_ij = dec_i.n().random_below_ref(rng);
        let hat_r_ij = dec_i.n().random_below_ref(rng);
        let s_ij = enc_j.n().random_below_ref(rng);
        let hat_s_ij = enc_j.n().random_below_ref(rng);

        let beta_ij = Integer::from_rng_half_pm(rng, &J);
        let hat_beta_ij = Integer::from_rng_half_pm(rng, &J);

        beta_sum += beta_ij.to_scalar();
        hat_beta_sum += hat_beta_ij.to_scalar();

        tracer.stage("Encrypt D_ji");
        // D_ji = (gamma_i * K_j) + enc_j(-beta_ij, s_ij)
        let D_ji = {
            let gamma_i_times_K_j = enc_j
                .omul(&utils::scalar_to_pm_bignumber(&gamma_i), &ciphertext_j.K)
                .map_err(|_| Bug::PaillierOp(BugSource::gamma_i_times_K_j))?;
            let neg_beta_ij_enc = enc_j
                .encrypt_with(&-&beta_ij, &s_ij)
                .map_err(|_| Bug::PaillierEnc(BugSource::neg_beta_ij_enc))?;
            enc_j
                .oadd(&gamma_i_times_K_j, &neg_beta_ij_enc)
                .map_err(|_| Bug::PaillierOp(BugSource::D_ji))?
        };

        tracer.stage("Encrypt F_ji");
        let F_ji = dec_i
            .encrypt_with(&-&beta_ij, &r_ij)
            .map_err(|_| Bug::PaillierEnc(BugSource::F_ji))?;

        tracer.stage("Encrypt hat_D_ji");
        // Dˆ_ji = (x_i * K_j) + enc_j(-hat_beta_ij, hat_s_ij)
        let hat_D_ji = {
            let x_i_times_K_j = enc_j
                .omul(&utils::scalar_to_pm_bignumber(x_i), &ciphertext_j.K)
                .map_err(|_| Bug::PaillierOp(BugSource::x_i_times_K_j))?;
            let neg_hat_beta_ij_enc = enc_j
                .encrypt_with(&-&hat_beta_ij, &hat_s_ij)
                .map_err(|_| Bug::PaillierEnc(BugSource::hat_beta_ij_enc))?;
            enc_j
                .oadd(&x_i_times_K_j, &neg_hat_beta_ij_enc)
                .map_err(|_| Bug::PaillierOp(BugSource::hat_D))?
        };
        runtime.yield_now().await;

        tracer.stage("Encrypt hat_F_ji");
        let hat_F_ji = dec_i
            .encrypt_with(&-&hat_beta_ij, &hat_r_ij)
            .map_err(|_| Bug::PaillierEnc(BugSource::hat_F))?;

        tracer.stage("Prove psi_ji");
        let psi_ji = pi_aff::non_interactive::prove::<E, D>(
            &unambiguous::ProofPsi {
                sid,
                prover: i,
                hat: false,
            },
            &R_j.into(),
            pi_aff::Data {
                key_j: enc_j,
                key_i: &dec_i,
                c: &ciphertext_j.K,
                d: &D_ji,
                y: &F_ji,
                x: &Gamma_i,
            },
            pi_aff::PrivateData {
                x: &utils::scalar_to_pm_bignumber(&gamma_i),
                y: &-&beta_ij,
                nonce: &s_ij,
                nonce_y: &r_ij,
            },
            &security_params.pi_aff,
            &mut *rng,
        )
        .map_err(|e| Bug::PiAffG(BugSource::psi, e))?;
        runtime.yield_now().await;

        tracer.stage("Prove psiˆ_ji");
        let hat_psi_ji = pi_aff::non_interactive::prove::<E, D>(
            &unambiguous::ProofPsi {
                sid,
                prover: i,
                hat: true,
            },
            &R_j.into(),
            pi_aff::Data {
                key_j: enc_j,
                key_i: &dec_i,
                c: &ciphertext_j.K,
                d: &hat_D_ji,
                y: &hat_F_ji,
                x: &(Point::generator() * x_i),
            },
            pi_aff::PrivateData {
                x: &utils::scalar_to_pm_bignumber(x_i),
                y: &-&hat_beta_ij,
                nonce: &hat_s_ij,
                nonce_y: &hat_r_ij,
            },
            &security_params.pi_aff,
            &mut *rng,
        )
        .map_err(|e| Bug::PiAffG(BugSource::hat_psi, e))?;
        runtime.yield_now().await;

        tracer.send_msg();
        outgoings
            .feed(Outgoing::p2p(
                j,
                Msg::Round2(MsgRound2 {
                    Gamma: Gamma_i,
                    D: D_ji,
                    F: F_ji,
                    hat_D: hat_D_ji,
                    hat_F: hat_F_ji,
                    tilde_psi: tilde_psi_i.clone(),
                    psi_j: psi_ji,
                    hat_psi_j: hat_psi_ji,
                }),
            ))
            .await
            .map_err(IoError::send_message)?;
        tracer.msg_sent();
    }
    tracer.send_msg();
    outgoings.flush().await.map_err(IoError::send_message)?;
    tracer.msg_sent();

    // Round 3
    tracer.round_begins();

    // Step 1
    tracer.receive_msgs();
    let round2_msgs = rounds
        .complete(round2)
        .await
        .map_err(IoError::receive_message)?;
    tracer.msgs_received();

    let faulty_parties =
        utils::collect_blame_with_data(&round2_msgs, &ciphertexts, |j, msg, ciphertexts| {
            tracer.stage("Retrieve auxiliary data");
            let X_j = X[usize::from(j)];
            let enc_j = &N[usize::from(j)];

            tracer.stage("Validate tilde_psi_j");
            let tilde_psi_invalid = pi_elog::non_interactive::verify::<E, D>(
                &unambiguous::ProofElog {
                    sid,
                    prover: j,
                    prime: false,
                },
                pi_elog::Data {
                    l: &ciphertexts.B1,
                    m: &ciphertexts.B2,
                    x: &ciphertexts.Y,
                    y: &msg.Gamma,
                    h: &Point::generator().to_point(),
                },
                &msg.tilde_psi,
            )
            .err();

            tracer.stage("Validate psi_i,j");
            let psi_j_invalid = pi_aff::non_interactive::verify::<E, D>(
                &unambiguous::ProofPsi {
                    sid,
                    prover: j,
                    hat: false,
                },
                &R_i.into(),
                pi_aff::Data {
                    key_j: &dec_i,
                    key_i: enc_j,
                    c: &K_i,
                    d: &msg.D,
                    y: &msg.F,
                    x: &msg.Gamma,
                },
                &security_params.pi_aff,
                &msg.psi_j,
            )
            .err();

            tracer.stage("Validate hat_psi_i,j");
            let hat_psi_j_invalid = pi_aff::non_interactive::verify::<E, D>(
                &unambiguous::ProofPsi {
                    sid,
                    prover: j,
                    hat: true,
                },
                &R_i.into(),
                pi_aff::Data {
                    key_j: &dec_i,
                    key_i: enc_j,
                    c: &K_i,
                    d: &msg.hat_D,
                    y: &msg.hat_F,
                    x: &X_j,
                },
                &security_params.pi_aff,
                &msg.hat_psi_j,
            )
            .err();

            if tilde_psi_invalid.is_some() || psi_j_invalid.is_some() || hat_psi_j_invalid.is_some()
            {
                Some((tilde_psi_invalid, psi_j_invalid, hat_psi_j_invalid))
            } else {
                None
            }
        });
    if !faulty_parties.is_empty() {
        return Err(SigningAborted::InvalidPsi(faulty_parties).into());
    }
    runtime.yield_now().await;

    // Step 2
    tracer.stage("Compute Gamma, Delta_i, delta_i, chi_i");
    let Gamma = Gamma_i + round2_msgs.iter().map(|msg| msg.Gamma).sum::<Point<E>>();
    let Delta_i = Gamma * &k_i;

    let alpha_sum =
        round2_msgs
            .iter()
            .map(|msg| &msg.D)
            .try_fold(Scalar::<E>::zero(), |sum, D_ij| {
                let alpha_ij = dec_i
                    .decrypt(D_ij)
                    .map_err(|_| Bug::PaillierDec(BugSource::alpha))?;
                Ok::<_, Bug>(sum + alpha_ij.to_scalar())
            })?;
    let hat_alpha_sum =
        round2_msgs
            .iter()
            .map(|msg| &msg.hat_D)
            .try_fold(Scalar::zero(), |sum, hat_D_ij| {
                let hat_alpha_ij = dec_i
                    .decrypt(hat_D_ij)
                    .map_err(|_| Bug::PaillierDec(BugSource::hat_alpha))?;
                Ok::<_, Bug>(sum + hat_alpha_ij.to_scalar())
            })?;

    let delta_i = gamma_i.as_ref() * k_i.as_ref() + alpha_sum + beta_sum;
    let chi_i = x_i * k_i.as_ref() + hat_alpha_sum + hat_beta_sum;
    let S_i = chi_i * Gamma;
    runtime.yield_now().await;

    tracer.stage("Prove psi_prime");
    let psi_prime_i = pi_elog::non_interactive::prove::<E, D>(
        &unambiguous::ProofElog {
            sid,
            prover: i,
            prime: true,
        },
        pi_elog::Data {
            l: &A_i1,
            m: &A_i2,
            x: &Y_i,
            y: &Delta_i,
            h: &Gamma,
        },
        pi_elog::PrivateData {
            y: k_i.as_ref(),
            lambda: a_i.as_ref(),
        },
        rng,
    )
    .map_err(|e| Bug::PiLog(BugSource::psi_prime, e))?;

    tracer.send_msg();
    let my_round3_msg = MsgRound3 {
        delta: delta_i,
        S: S_i,
        Delta: Delta_i,
        psi_prime: psi_prime_i,
    };
    outgoings
        .send(Outgoing::broadcast(Msg::Round3(my_round3_msg.clone())))
        .await
        .map_err(IoError::send_message)?;
    tracer.msg_sent();

    // Output
    tracer.named_round_begins("Presig output");

    // Step 1
    tracer.receive_msgs();
    let round3_msgs = rounds
        .complete(round3)
        .await
        .map_err(IoError::receive_message)?;
    tracer.msgs_received();

    tracer.stage("Validate psi_prime_prime");
    let faulty_parties =
        utils::collect_blame_with_data(&round3_msgs, &ciphertexts, |j, msg_j, ciphertext_j| {
            pi_elog::non_interactive::verify::<E, D>(
                &unambiguous::ProofElog {
                    sid,
                    prover: j,
                    prime: true,
                },
                pi_elog::Data {
                    l: &ciphertext_j.A1,
                    m: &ciphertext_j.A2,
                    x: &ciphertext_j.Y,
                    y: &msg_j.Delta,
                    h: &Gamma,
                },
                &msg_j.psi_prime,
            )
            .err()
        });
    if !faulty_parties.is_empty() {
        return Err(SigningAborted::InvalidPsiPrimePrime(faulty_parties).into());
    }
    runtime.yield_now().await;

    // Step 2
    tracer.stage("Calculate presignature");
    let delta = delta_i + round3_msgs.iter().map(|m| m.delta).sum::<Scalar<E>>();
    let Delta = Delta_i + round3_msgs.iter().map(|m| m.Delta).sum::<Point<E>>();
    let S = S_i + round3_msgs.iter().map(|m| m.S).sum::<Point<E>>();

    if Point::generator() * delta != Delta || pk * delta != S {
        // Following the protocol, party should broadcast additional proofs
        // to convince others it didn't cheat. However, since identifiable
        // abort is not implemented yet, this part of the protocol is missing
        return Err(SigningAborted::MismatchedDelta.into());
    }

    let delta_inv = delta.invert().ok_or(Bug::Zero(BugSource::delta))?;

    let tilde_k_i = SecretScalar::new(&mut (k_i * delta_inv));
    let tilde_chi_i = SecretScalar::new(&mut (chi_i * delta_inv));

    let Gamma = NonZero::from_point(Gamma).ok_or(Bug::Zero(BugSource::Gamma))?;

    let commitments = round3_msgs
        .iter_including_me(&my_round3_msg)
        .map(|m| PresignatureCommitment {
            tilde_Delta: delta_inv * m.Delta,
            tilde_S: delta_inv * m.S,
        })
        .collect::<Vec<_>>();
    let commitments = PresignaturePublicData { Gamma, commitments };

    let presig = Presignature {
        Gamma,
        tilde_k: tilde_k_i,
        tilde_chi: tilde_chi_i,
    };

    // If message is not specified, protocol terminates here and outputs partial
    // signature
    let Some(message_to_sign) = message_to_sign else {
        tracer.protocol_ends();
        return Ok(ProtocolOutput::Presignature((presig, commitments)));
    };

    // Signing
    tracer.named_round_begins("Partial signing");

    // Round 1

    // SECURITY: we can safely sign a digest even if its preimage is unknown, because the attack
    // described in [`PrehashedDataToSign`] can only be done if message to be signed is chosen
    // after presignature is generated. Since we do a full signing, we know that message was
    // chosen before presig was generated.
    let message_to_sign = DataToSign(message_to_sign);

    let partial_sig = presig.issue_partial_signature(message_to_sign);

    tracer.send_msg();
    outgoings
        .send(Outgoing::broadcast(Msg::Round4(MsgRound4 { partial_sig })))
        .await
        .map_err(IoError::send_message)?;
    tracer.msg_sent();

    // Output
    tracer.named_round_begins("Signature reconstruction");

    tracer.receive_msgs();
    let partial_sigs = rounds
        .complete(round4)
        .await
        .map_err(IoError::receive_message)?;
    tracer.msgs_received();

    let partial_sigs = partial_sigs
        .into_vec_including_me(MsgRound4 { partial_sig })
        .into_iter()
        .map(|m| m.partial_sig)
        .collect::<Vec<_>>();

    // Following the protocol, party should broadcast additional proofs
    // to convince others it didn't cheat. However, since identifiable
    // abort is not implemented yet, this part of the protocol is missing
    let sig = PartialSignature::combine(&partial_sigs, &commitments, message_to_sign)
        .ok_or(SigningAborted::SignatureInvalid)?;

    tracer.protocol_ends();
    Ok(ProtocolOutput::Signature(sig))
}

impl<E> Presignature<E>
where
    E: Curve,
    NonZero<Point<E>>: AlwaysHasAffineX<E>,
{
    /// Issues partial signature for given message
    ///
    /// **Never reuse presignatures!** If you use the same presignatures to sign two different
    /// messages, it leaks the private key!
    ///
    /// When signing using a presignature, it's important that you know a message that's being
    /// signed (not just its hash!). For this reason, this function only accepts [`DataToSign`] that
    /// can only be constructed when original message is known. Refer to [`PrehashedDataToSign`]
    /// docs to learn more about possible attack when signing a hash of the message without knowing
    /// the preimage.
    pub fn issue_partial_signature(self, message_to_sign: DataToSign<E>) -> PartialSignature<E> {
        let r = self.Gamma.x().to_scalar();
        let m = message_to_sign.to_scalar();
        let sigma_i = self.tilde_k.as_ref() * m + r * self.tilde_chi.as_ref();
        PartialSignature { sigma: sigma_i }
    }
}

#[cfg(feature = "hd-wallet")]
fn derive_additive_shift<E: Curve, Hd: hd_wallet::HdWallet<E>, Index>(
    mut epub: hd_wallet::ExtendedPublicKey<E>,
    path: impl IntoIterator<Item = Index>,
) -> Result<Scalar<E>, <Index as TryInto<hd_wallet::NonHardenedIndex>>::Error>
where
    hd_wallet::NonHardenedIndex: TryFrom<Index>,
{
    let mut additive_shift = Scalar::<E>::zero();

    for child_index in path {
        let child_index: hd_wallet::NonHardenedIndex = child_index.try_into()?;
        let shift = Hd::derive_public_shift(&epub, child_index);

        additive_shift += shift.shift;
        epub = shift.child_public_key;
    }

    Ok(additive_shift)
}

impl<E: Curve> PartialSignature<E>
where
    NonZero<Point<E>>: AlwaysHasAffineX<E>,
{
    /// Combines threshold amount of partial signatures into regular signature
    ///
    /// Returns `None` if input is malformed.
    ///
    /// `combine` may return a signature that's invalid for public key and message it was issued for.
    /// This would mean that some of signers cheated and aborted the protocol. You need to validate
    /// resulting signature to be sure that no one aborted the protocol.
    pub fn combine(
        partial_signatures: &[PartialSignature<E>],
        commitments: &PresignaturePublicData<E>,
        m: DataToSign<E>,
    ) -> Option<Signature<E>> {
        if partial_signatures.is_empty()
            || partial_signatures.len() != commitments.commitments.len()
        {
            None
        } else {
            let r = commitments.Gamma.x().to_scalar();
            let r = NonZero::from_scalar(r)?;
            let m = m.to_scalar();
            for (partial_sig, commitment) in partial_signatures.iter().zip(&commitments.commitments)
            {
                if partial_sig.sigma * commitments.Gamma
                    != m * commitment.tilde_Delta + r * commitment.tilde_S
                {
                    return None;
                }
            }
            let sigma = partial_signatures.iter().map(|s| &s.sigma).sum();
            let sigma = NonZero::from_scalar(sigma)?;
            Some(Signature { r, s: sigma }.normalize_s())
        }
    }
}

impl<E: Curve> Signature<E>
where
    NonZero<Point<E>>: AlwaysHasAffineX<E>,
{
    /// Verifies that signature matches specified public key and message
    pub fn verify(
        &self,
        public_key: &Point<E>,
        message: &dyn AnyDataToSign<E>,
    ) -> Result<(), InvalidSignature> {
        let r = (Point::generator() * message.to_scalar() + public_key * self.r) * self.s.invert();
        let r = NonZero::from_point(r).ok_or(InvalidSignature)?;

        if *self.r == r.x().to_scalar() {
            Ok(())
        } else {
            Err(InvalidSignature)
        }
    }
}

impl<E: Curve> Signature<E> {
    /// Create signature struct from `r` and `s` values
    pub fn from_raw_parts(r: NonZero<Scalar<E>>, s: NonZero<Scalar<E>>) -> Self {
        Self { r, s }
    }
    /// Normilizes the signature
    ///
    /// Given that $(r, s)$ is valid signature, $(r, -s)$ is also a valid signature. Some applications (like Bitcoin)
    /// remove this ambiguity by restricting $s$ to be in lower half. This method normailizes the signature by picking
    /// $s$ that is in lower half.
    ///
    /// Note that signing protocol implemented within this crate ouputs normalized signature by default.
    pub fn normalize_s(self) -> Self {
        let neg_s = -self.s;
        if neg_s < self.s {
            Signature { s: neg_s, ..self }
        } else {
            self
        }
    }

    /// Writes serialized signature to the bytes buffer
    ///
    /// Bytes buffer size must be at least [`Signature::serialized_len()`], otherwise content
    /// of output buffer is unspecified.
    pub fn write_to_slice(&self, out: &mut [u8]) {
        if out.len() < Self::serialized_len() {
            return;
        }
        let scalar_size = Scalar::<E>::serialized_len();
        out[0..scalar_size].copy_from_slice(&self.r.to_be_bytes());
        out[scalar_size..2 * scalar_size].copy_from_slice(&self.s.to_be_bytes());
    }

    /// Reads serialized signature from the bytes buffer.
    ///
    /// Bytes buffer size must be equal to [`Signature::serialized_len()`] and
    /// none of the signature parts should be 0. If this doesn't hold, returns
    /// `None`
    pub fn read_from_slice(inp: &[u8]) -> Option<Self> {
        if inp.len() != Self::serialized_len() {
            return None;
        }
        let r_bytes = &inp[0..inp.len() / 2];
        let s_bytes = &inp[inp.len() / 2..];
        let r = generic_ec::Scalar::from_be_bytes(r_bytes)
            .ok()?
            .try_into()
            .ok()?;
        let s = generic_ec::Scalar::from_be_bytes(s_bytes)
            .ok()?
            .try_into()
            .ok()?;
        Some(Self::from_raw_parts(r, s))
    }

    /// Returns size of bytes buffer that can fit serialized signature
    pub fn serialized_len() -> usize {
        2 * Scalar::<E>::serialized_len()
    }
}

enum ProtocolOutput<E: Curve> {
    Presignature((Presignature<E>, PresignaturePublicData<E>)),
    Signature(Signature<E>),
}

/// Error indicating that signing protocol failed
#[derive(Debug, Error)]
#[error("signing protocol failed")]
pub struct SigningError(#[source] Reason);

crate::errors::impl_from! {
    impl From for SigningError {
        err: InvalidArgs => SigningError(Reason::InvalidArgs(err)),
        err: InvalidKeyShare => SigningError(Reason::InvalidKeyShare(err)),
        err: SigningAborted => SigningError(Reason::Aborted(err)),
        err: IoError => SigningError(Reason::IoError(err)),
        err: Bug => SigningError(Reason::Bug(err)),
    }
}

/// Error indicating that signing failed
#[derive(Debug, Error)]
enum Reason {
    #[error("invalid arguments")]
    InvalidArgs(
        #[from]
        #[source]
        InvalidArgs,
    ),
    #[error("provided key share is not valid")]
    InvalidKeyShare(
        #[from]
        #[source]
        InvalidKeyShare,
    ),
    /// Signing protocol was maliciously aborted by another party
    #[error("protocol was maliciously aborted by another party")]
    Aborted(
        #[source]
        #[from]
        SigningAborted,
    ),
    #[error("i/o error")]
    IoError(#[source] IoError),
    /// Bug occurred
    #[error("bug occurred")]
    Bug(Bug),
}

/// Error indicating that protocol was aborted by malicious party
///
/// It _can be_ cryptographically proven, but we do not support it yet.
#[allow(clippy::type_complexity)]
#[derive(Debug, Error)]
enum SigningAborted {
    #[error("pi_enc::verify(K) failed")]
    EncProofOfK(Vec<(utils::AbortBlame, paillier_zk::InvalidProof)>),
    #[error("ψ_j, ψ_j,i or ψˆ_ji proofs are invalid: {0:?}")]
    InvalidPsi(
        Vec<(
            utils::AbortBlame,
            (
                Option<paillier_zk::InvalidProof>,
                Option<paillier_zk::InvalidProof>,
                Option<paillier_zk::InvalidProof>,
            ),
        )>,
    ),
    #[error("ψ'' proof is invalid")]
    InvalidPsiPrimePrime(Vec<(utils::AbortBlame, paillier_zk::InvalidProof)>),
    #[error("Delta != G * delta")]
    MismatchedDelta,
    #[error("resulting signature is not valid")]
    SignatureInvalid,
    #[error("other parties received different broadcast messages at round1a")]
    Round1aNotReliable(Vec<utils::AbortBlame>),
}

#[derive(Debug, Error)]
enum InvalidArgs {
    #[error("exactly `threshold` amount of parties should take part in signing")]
    MismatchedAmountOfParties,
    #[error("signer index `i` is out of bounds (must be < n)")]
    SignerIndexOutOfBounds,
    #[error("party index in S is out of bounds (must be < n)")]
    InvalidS,
}

#[derive(Debug, Error)]
enum Bug {
    #[error("own paillier decryption key is not valid")]
    InvalidOwnPaillierKey,
    #[error("invalid key share: number of parties exceeds u16")]
    PartiesNumberExceedsU16,
    #[error("couldn't encrypt a scalar with paillier encryption key: {0:?}")]
    PaillierEnc(BugSource),
    #[error("paillier addition/multiplication failed: {0:?}")]
    PaillierOp(BugSource),
    #[error("π enc elg failed to prove statement {0:?}")]
    PiEncElg(BugSource, paillier_zk::Error),
    #[error("π elog failed to prove statement {0:?}")]
    PiElog(BugSource, #[source] paillier_zk::Error),
    #[error("π aff-g failed to prove statement {0:?}")]
    PiAffG(BugSource, #[source] paillier_zk::Error),
    #[error("π log* failed to prove statement: {0:?}")]
    PiLog(BugSource, #[source] paillier_zk::Error),
    #[error("couldn't decrypt a message: {0:?}")]
    PaillierDec(BugSource),
    #[error("{0:?} is zero")]
    Zero(BugSource),
    #[error("unexpected protocol output")]
    UnexpectedProtocolOutput,
    #[error("derive lagrange coef")]
    LagrangeCoef,
    #[error("subset function returned error")]
    Subset,
    #[error("derived child key is zero - probability of that is negligible")]
    DerivedChildKeyZero,
    #[error("derived child share is zero - probability of that is negligible")]
    DerivedChildShareZero,
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
enum BugSource {
    G_i,
    K_i,
    gamma_i_times_K_j,
    neg_beta_ij_enc,
    D_ji,
    F_ji,
    x_i_times_K_j,
    hat_beta_ij_enc,
    hat_D,
    hat_F,
    psi0,
    psi1,
    psi,
    hat_psi,
    alpha,
    hat_alpha,
    psi_prime,

    delta,
    Gamma,
}

/// Error indicating that signature is not valid for given public key and message
#[derive(Debug, Error)]
#[error("signature is not valid")]
pub struct InvalidSignature;

#[cfg(test)]
mod test {
    fn read_write_signature<E: generic_ec::Curve>() {
        let mut rng = rand_dev::DevRng::new();
        for _ in 0..10 {
            let r = generic_ec::NonZero::<generic_ec::Scalar<E>>::random(&mut rng);
            let s = generic_ec::NonZero::<generic_ec::Scalar<E>>::random(&mut rng);
            let signature = super::Signature::from_raw_parts(r, s);
            let mut bytes = vec![0; super::Signature::<E>::serialized_len()];
            signature.write_to_slice(&mut bytes);
            let signature2 = super::Signature::read_from_slice(&bytes).unwrap();
            assert!(signature == signature2, "signatures equal");
        }
    }

    #[test]
    fn read_write_signature_secp256k1() {
        read_write_signature::<crate::supported_curves::Secp256k1>()
    }
    #[test]
    fn read_write_signature_secp256r1() {
        read_write_signature::<crate::supported_curves::Secp256r1>()
    }
    #[test]
    fn read_write_signature_stark() {
        read_write_signature::<crate::supported_curves::Stark>()
    }
}
