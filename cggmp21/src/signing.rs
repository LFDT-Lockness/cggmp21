use digest::Digest;
use futures::SinkExt;
use generic_ec::{
    coords::AlwaysHasAffineX, hash_to_curve::FromHash, Curve, NonZero, Point, Scalar, SecretScalar,
};
use paillier_zk::libpaillier::{unknown_order::BigNumber, Ciphertext, DecryptionKey};
use paillier_zk::{
    group_element_vs_paillier_encryption_in_range as π_log, libpaillier,
    paillier_affine_operation_in_range as π_aff, paillier_encryption_in_range as π_enc,
};
use rand_core::{CryptoRng, RngCore};
use round_based::{
    rounds_router::{
        simple_store::{RoundInput, RoundInputError},
        CompleteRoundError, RoundsRouter,
    },
    Delivery, Mpc, MpcParty, MsgId, Outgoing, PartyIndex, ProtocolMessage,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::utils::{hash_message, HashMessageError};
use crate::{
    execution_id::ProtocolChoice,
    key_share::{InvalidKeyShare, KeyShare, Valid},
    security_level::SecurityLevel,
    utils::{encryption_key_from_n, sample_bigint_in_mult_group, scalar_to_bignumber},
    ExecutionId,
};

/// A (prehashed) message to sign
#[derive(Debug, Clone, Copy)]
pub struct Message([u8; 32]);

impl Message {
    /// Construct a `Message` by hashing `data` with algorithm `D`
    pub fn new<D>(data: &[u8]) -> Self
    where
        D: Digest<OutputSize = digest::typenum::U32>,
    {
        Message(D::digest(data).into())
    }

    /// Constructs a `Message` from `hash = H(message)`
    pub fn from_digest<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = digest::typenum::U32>,
    {
        Message(hash.finalize().into())
    }

    /// Constructs a `Message` from `message_hash = H(message)`
    ///
    /// ** Note: [Message::new] and [Message::from_digest] are preferred way to construct the `Message` **
    ///
    /// `message_hash` must be an output of cryptographic function of 32 bytes length. If
    /// `message_hash` is not 32 bytes size, `Err(InvalidMessage)` is returned.
    pub fn from_slice(message_hash: &[u8]) -> Result<Self, InvalidMessage> {
        message_hash.try_into().map(Self).or(Err(InvalidMessage))
    }

    fn to_scalar<E: Curve>(self) -> Scalar<E> {
        Scalar::from_be_bytes_mod_order(self.0)
    }
}

pub struct Presignature<E: Curve> {
    pub R: NonZero<Point<E>>,
    pub k: SecretScalar<E>,
    pub chi: SecretScalar<E>,
}

pub struct PartialSignature<E: Curve> {
    pub r: Scalar<E>,
    pub σ: Scalar<E>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Signature<E: Curve> {
    pub r: NonZero<Scalar<E>>,
    pub s: NonZero<Scalar<E>>,
}

#[derive(Clone, ProtocolMessage)]
#[allow(clippy::large_enum_variant)]
pub enum Msg<E: Curve, D: Digest> {
    Round1a(MsgRound1a),
    Round1b(MsgRound1b),
    Round2(MsgRound2<E>),
    Round3(MsgRound3<E>),
    Round4(MsgRound4<E>),
    SyncState(MsgSyncState<D>),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MsgRound1a {
    pub K: libpaillier::Ciphertext,
    pub G: libpaillier::Ciphertext,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MsgRound1b {
    pub ψ0: (π_enc::Commitment, π_enc::Proof),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgRound2<E: Curve> {
    pub Γ: Point<E>,
    pub D: Ciphertext,
    pub F: Ciphertext,
    pub Dˆ: Ciphertext,
    pub Fˆ: Ciphertext,
    pub ψ: (π_aff::Commitment<E>, π_aff::Proof),
    pub ψˆ: (π_aff::Commitment<E>, π_aff::Proof),
    pub ψ_prime: (π_log::Commitment<E>, π_log::Proof),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgRound3<E: Curve> {
    pub delta: Scalar<E>,
    pub Delta: Point<E>,
    pub ψ_prime_prime: (π_log::Commitment<E>, π_log::Proof),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgRound4<E: Curve> {
    pub σ: Scalar<E>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgSyncState<D: Digest>(digest::Output<D>);

pub struct SigningBuilder<'k, E, L, D>
where
    E: Curve,
    L: SecurityLevel,
    D: Digest,
{
    key_share: &'k Valid<KeyShare<E, L>>,
    execution_id: ExecutionId<E, L, D>,
}

impl<'k, E, L, D> SigningBuilder<'k, E, L, D>
where
    E: Curve,
    Scalar<E>: FromHash,
    NonZero<Point<E>>: AlwaysHasAffineX<E>,
    L: SecurityLevel,
    D: Digest<OutputSize = digest::typenum::U32> + Clone + 'static,
{
    pub fn new(secret_key_share: &'k Valid<KeyShare<E, L>>) -> Self {
        Self {
            key_share: secret_key_share,
            execution_id: Default::default(),
        }
    }

    pub fn set_digest<D2>(self) -> SigningBuilder<'k, E, L, D2>
    where
        D2: Digest,
    {
        SigningBuilder {
            key_share: self.key_share,
            execution_id: Default::default(),
        }
    }

    pub fn set_execution_id(self, execution_id: ExecutionId<E, L, D>) -> Self {
        Self {
            execution_id,
            ..self
        }
    }

    fn other_parties(&self) -> impl Iterator<Item = PartyIndex> {
        let i = self.key_share.core.i;
        let n = self.key_share.parties.len();
        (0u16..).take(n).filter(move |j| i != *j)
    }

    pub async fn generate_presignature<R, M>(
        self,
        rng: &mut R,
        party: M,
    ) -> Result<Presignature<E>, SigningError<M::ReceiveError, M::SendError>>
    where
        R: RngCore + CryptoRng,
        M: Mpc<ProtocolMessage = Msg<E, D>>,
    {
        match self.run(rng, party, None).await? {
            ProtocolOutput::Presignature(presig) => Ok(presig),
            ProtocolOutput::Signature(_) => Err(Bug::UnexpectedProtocolOutput.into()),
        }
    }

    pub async fn sign<R, M>(
        self,
        rng: &mut R,
        party: M,
        message_to_sign: Message,
    ) -> Result<Signature<E>, SigningError<M::ReceiveError, M::SendError>>
    where
        R: RngCore + CryptoRng,
        M: Mpc<ProtocolMessage = Msg<E, D>>,
    {
        match self.run(rng, party, Some(message_to_sign)).await? {
            ProtocolOutput::Signature(sig) => Ok(sig),
            ProtocolOutput::Presignature(_) => Err(Bug::UnexpectedProtocolOutput.into()),
        }
    }

    fn validate_security_level() -> Result<(), InvalidSecurityLevel> {
        let n_size = BigNumber::one() << (L::SECURITY_BITS * 4 + 1);
        let q_minus_one = BigNumber::from_slice(&Scalar::<E>::from(-1).to_be_bytes());
        if n_size < q_minus_one {
            return Err(InvalidSecurityLevel::SecurityLevelTooSmall);
        }

        let q = q_minus_one + BigNumber::one();
        if L::EPSILON < q.bit_length() {
            return Err(InvalidSecurityLevel::EpsilonTooSmall);
        }
        let another_q = L::q();
        if L::EPSILON < another_q.bit_length() {
            return Err(InvalidSecurityLevel::EpsilonTooSmall);
        }

        Ok(())
    }

    async fn run<R, M>(
        self,
        rng: &mut R,
        party: M,
        message_to_sign: Option<Message>,
    ) -> Result<ProtocolOutput<E>, SigningError<M::ReceiveError, M::SendError>>
    where
        R: RngCore + CryptoRng,
        M: Mpc<ProtocolMessage = Msg<E, D>>,
    {
        let MpcParty { delivery, .. } = party.into_party();
        let (incomings, mut outgoings) = delivery.split();

        // Validate input
        Self::validate_security_level()?;
        let i = self.key_share.core.i;
        let n: u16 = self
            .key_share
            .core
            .public_shares
            .len()
            .try_into()
            .or(Err(Bug::PartiesNumberExceedsU16))?;
        let aux_i = &self.key_share.parties[usize::from(i)];
        let N_i = &aux_i.N;
        let enc_i = encryption_key_from_n(N_i);
        let dec_i = DecryptionKey::with_primes(&self.key_share.p, &self.key_share.q)
            .ok_or(Bug::InvalidOwnPaillierKey)?;

        let execution_id = self.execution_id.evaluate(ProtocolChoice::Presigning3);
        let security_params = crate::utils::SecurityParams::new::<L>();

        // Setup networking
        let mut rounds = RoundsRouter::<Msg<E, D>>::builder();
        let round1a = rounds.add_round(RoundInput::<MsgRound1a>::broadcast(i, n));
        let round1b = rounds.add_round(RoundInput::<MsgRound1b>::p2p(i, n));
        let round1a_sync = rounds.add_round(RoundInput::<MsgSyncState<D>>::broadcast(i, n));
        let round2 = rounds.add_round(RoundInput::<MsgRound2<E>>::p2p(i, n));
        let round3 = rounds.add_round(RoundInput::<MsgRound3<E>>::p2p(i, n));
        let round4 = rounds.add_round(RoundInput::<MsgRound4<E>>::broadcast(i, n));
        let mut rounds = rounds.listen(incomings);

        // Round 1
        let k_i = SecretScalar::<E>::random(rng);
        let y_i = SecretScalar::<E>::random(rng);
        let p_i = sample_bigint_in_mult_group(rng, N_i);
        let v_i = sample_bigint_in_mult_group(rng, N_i);

        let G_i = enc_i
            .encrypt(y_i.as_ref().to_be_bytes(), Some(v_i.clone()))
            .ok_or(Bug::PaillierEnc(BugSource::G_i))?
            .0;
        let K_i = enc_i
            .encrypt(k_i.as_ref().to_be_bytes(), Some(p_i.clone()))
            .ok_or(Bug::PaillierEnc(BugSource::K_i))?
            .0;

        outgoings
            .send(Outgoing::broadcast(Msg::Round1a(MsgRound1a {
                K: K_i.clone(),
                G: G_i.clone(),
            })))
            .await
            .map_err(SigningError::SendError)?;

        let parties_shared_state = D::new_with_prefix(execution_id);
        for j in self.other_parties() {
            let aux_j = &self.key_share.parties[usize::from(j)];
            let data = π_enc::Data {
                key: enc_i.clone(),
                ciphertext: K_i.clone(),
            };
            let pdata = π_enc::PrivateData {
                plaintext: scalar_to_bignumber(&k_i),
                nonce: p_i.clone(),
            };

            let ψ0_i = π_enc::non_interactive::prove(
                parties_shared_state.clone(),
                &aux_j.into(),
                &data,
                &pdata,
                &security_params.π_enc,
                &mut *rng,
            );
            outgoings
                .send(Outgoing::p2p(j, Msg::Round1b(MsgRound1b { ψ0: ψ0_i })))
                .await
                .map_err(SigningError::SendError)?;
        }

        // Round 2

        let ciphertexts = rounds
            .complete(round1a)
            .await
            .map_err(SigningError::ReceiveMessage)?;
        let proofs = rounds
            .complete(round1b)
            .await
            .map_err(SigningError::ReceiveMessage)?;

        // Ensure reliability of round1a: broadcast hash(ciphertexts)
        let ciphertexts_hash = ciphertexts
            .iter_including_me(&MsgRound1a {
                K: K_i.clone(),
                G: G_i.clone(),
            })
            .try_fold(D::new(), hash_message)
            .map_err(Bug::HashMessage)?
            .finalize();
        outgoings
            .send(Outgoing::broadcast(Msg::SyncState(MsgSyncState(
                ciphertexts_hash,
            ))))
            .await
            .map_err(SigningError::SendError)?;

        // Step 1. Verify proofs
        {
            let mut faulty_parties = vec![];
            for ((j, msg1_id, ciphertext), (_, msg2_id, proof)) in
                ciphertexts.iter_indexed().zip(proofs.iter_indexed())
            {
                let aux_j = &self.key_share.parties[usize::from(j)];
                let data = π_enc::Data {
                    key: encryption_key_from_n(&aux_j.N),
                    ciphertext: ciphertext.K.clone(),
                };
                if π_enc::non_interactive::verify(
                    parties_shared_state.clone(),
                    &aux_i.into(),
                    &data,
                    &proof.ψ0.0,
                    &security_params.π_enc,
                    &proof.ψ0.1,
                )
                .is_err()
                {
                    faulty_parties.push((j, msg1_id, msg2_id))
                }
            }

            if !faulty_parties.is_empty() {
                return Err(SigningAborted::EncProofOfK(faulty_parties).into());
            }
        }

        // Ensure reliability of round1a: receive hash(ciphertexts) from others
        {
            let round1a_hashes = rounds
                .complete(round1a_sync)
                .await
                .map_err(SigningError::ReceiveMessage)?;
            let parties_have_different_hashes = round1a_hashes
                .into_iter_indexed()
                .filter(|(_j, _msg_id, hash)| hash.0 != ciphertexts_hash)
                .map(|(j, msg_id, _)| (j, msg_id))
                .collect::<Vec<_>>();
            if !parties_have_different_hashes.is_empty() {
                return Err(
                    SigningAborted::Round1aNotReliable(parties_have_different_hashes).into(),
                );
            }
        }

        // Step 2
        let Γ_i = Point::generator() * &y_i;
        let J = BigNumber::one() << (L::ELL_PRIME + 1);

        let mut β_sum = Scalar::zero();
        let mut βˆ_sum = Scalar::zero();
        for (j, _, ciphertext) in ciphertexts.iter_indexed() {
            let aux_j = &self.key_share.parties[usize::from(j)];
            let N_j = &aux_j.N;
            let enc_j = encryption_key_from_n(N_j);

            let r_ij = BigNumber::from_rng(N_i, rng);
            let rˆ_ij = BigNumber::from_rng(N_i, rng);
            let s_ij = BigNumber::from_rng(N_j, rng);
            let sˆ_ij = BigNumber::from_rng(N_j, rng);

            let β_ij = BigNumber::from_rng(&J, rng);
            let βˆ_ij = BigNumber::from_rng(&J, rng);

            β_sum += Scalar::from_be_bytes_mod_order(β_ij.to_bytes());
            βˆ_sum += Scalar::from_be_bytes_mod_order(βˆ_ij.to_bytes());

            // D_ji = (y_i * K_j) + enc_j(β_ij, s_ij)
            let D_ji = {
                let y_i_times_K_j = enc_j
                    .mul(&ciphertext.K, &scalar_to_bignumber(&y_i))
                    .ok_or(Bug::PaillierOp(BugSource::y_i_times_K_j))?;
                let β_ij_enc = enc_j
                    .encrypt(β_ij.to_bytes(), Some(s_ij.clone()))
                    .ok_or(Bug::PaillierEnc(BugSource::β_ij_enc))?
                    .0;
                enc_j
                    .add(&y_i_times_K_j, &β_ij_enc)
                    .ok_or(Bug::PaillierOp(BugSource::D_ji))?
            };

            let F_ji = enc_i
                .encrypt(β_ij.to_bytes(), Some(r_ij.clone()))
                .ok_or(Bug::PaillierEnc(BugSource::F_ji))?
                .0;

            // Dˆ_ji = (x_i * K_j) + enc_j(βˆ_ij, sˆ_ij)
            let Dˆ_ji = {
                let x_i_times_K_j = enc_j
                    .mul(&ciphertext.K, &scalar_to_bignumber(&self.key_share.core.x))
                    .ok_or(Bug::PaillierOp(BugSource::x_i_times_K_j))?;
                let βˆ_ij_enc = enc_j
                    .encrypt(βˆ_ij.to_bytes(), Some(sˆ_ij.clone()))
                    .ok_or(Bug::PaillierEnc(BugSource::βˆ_ij_enc))?
                    .0;
                enc_j
                    .add(&x_i_times_K_j, &βˆ_ij_enc)
                    .ok_or(Bug::PaillierOp(BugSource::Dˆ_ji))?
            };

            let Fˆ_ji = enc_i
                .encrypt(βˆ_ij.to_bytes(), Some(rˆ_ij.clone()))
                .ok_or(Bug::PaillierEnc(BugSource::Fˆ_ji))?
                .0;

            let ψ_ji = π_aff::non_interactive::prove(
                parties_shared_state.clone(),
                &aux_j.into(),
                &π_aff::Data {
                    key0: enc_j.clone(),
                    key1: enc_i.clone(),
                    c: ciphertext.K.clone(),
                    d: D_ji.clone(),
                    y: F_ji.clone(),
                    x: Γ_i,
                },
                &π_aff::PrivateData {
                    x: scalar_to_bignumber(&y_i),
                    y: β_ij.clone(),
                    nonce: s_ij.clone(),
                    nonce_y: r_ij.clone(),
                },
                &security_params.π_aff,
                &mut *rng,
            )
            .map_err(|e| Bug::ΠAffG(BugSource::ψ_ji, e))?;

            let ψˆ_ji = π_aff::non_interactive::prove(
                parties_shared_state.clone(),
                &aux_j.into(),
                &π_aff::Data {
                    key0: enc_j.clone(),
                    key1: enc_i.clone(),
                    c: ciphertext.K.clone(),
                    d: Dˆ_ji.clone(),
                    y: Fˆ_ji.clone(),
                    x: Point::generator() * &self.key_share.core.x,
                },
                &π_aff::PrivateData {
                    x: scalar_to_bignumber(&self.key_share.core.x),
                    y: βˆ_ij.clone(),
                    nonce: sˆ_ij.clone(),
                    nonce_y: rˆ_ij.clone(),
                },
                &security_params.π_aff,
                &mut *rng,
            )
            .map_err(|e| Bug::ΠAffG(BugSource::ψˆ_ji, e))?;

            let ψ_prime_ji = π_log::non_interactive::prove(
                parties_shared_state.clone(),
                &aux_j.into(),
                &π_log::Data {
                    key0: enc_i.clone(),
                    c: G_i.clone(),
                    x: Γ_i,
                    g: Point::<E>::generator().to_point(),
                },
                &π_log::PrivateData {
                    x: scalar_to_bignumber(&y_i),
                    nonce: v_i.clone(),
                },
                &security_params.π_log,
                &mut *rng,
            )
            .map_err(|e| Bug::ΠLog(BugSource::ψ_prime_ji, e))?;

            outgoings
                .send(Outgoing::p2p(
                    j,
                    Msg::Round2(MsgRound2 {
                        Γ: Γ_i,
                        D: D_ji,
                        F: F_ji,
                        Dˆ: Dˆ_ji,
                        Fˆ: Fˆ_ji,
                        ψ: ψ_ji,
                        ψˆ: ψˆ_ji,
                        ψ_prime: ψ_prime_ji,
                    }),
                ))
                .await
                .map_err(SigningError::SendError)?;
        }

        // Round 3

        // Step 1
        let round2_msgs = rounds
            .complete(round2)
            .await
            .map_err(SigningError::ReceiveMessage)?;

        let mut faulty_parties = vec![];
        for ((j, msg_id, msg), (_, ciphertext_msg_id, ciphertexts)) in
            round2_msgs.iter_indexed().zip(ciphertexts.iter_indexed())
        {
            let X_j = self.key_share.core.public_shares[usize::from(j)];
            let aux_j = &self.key_share.parties[usize::from(j)];
            let enc_j = encryption_key_from_n(&aux_j.N);

            // Verify ψ
            let ψ_invalid = {
                let data = π_aff::Data {
                    key0: enc_i.clone(),
                    key1: enc_j.clone(),
                    // c: msg.D.clone(),
                    // d: K_i.clone(),
                    c: K_i.clone(),
                    d: msg.D.clone(),
                    y: msg.F.clone(),
                    x: msg.Γ,
                };
                π_aff::non_interactive::verify(
                    parties_shared_state.clone(),
                    &aux_i.into(),
                    &data,
                    &msg.ψ.0,
                    &security_params.π_aff,
                    &msg.ψ.1,
                )
                .err()
            };

            let ψˆ_invalid = {
                let data = π_aff::Data {
                    key0: enc_i.clone(),
                    key1: enc_j.clone(),
                    // c: msg.Dˆ.clone(),
                    // d: K_i.clone(),
                    c: K_i.clone(),
                    d: msg.Dˆ.clone(),
                    y: msg.Fˆ.clone(),
                    x: X_j,
                };
                π_aff::non_interactive::verify(
                    parties_shared_state.clone(),
                    &aux_i.into(),
                    &data,
                    &msg.ψˆ.0,
                    &security_params.π_aff,
                    &msg.ψˆ.1,
                )
                .err()
            };

            let ψ_prime_invalid = {
                let data = π_log::Data {
                    key0: enc_j.clone(),
                    c: ciphertexts.G.clone(),
                    x: msg.Γ,
                    g: Point::<E>::generator().to_point(),
                };
                π_log::non_interactive::verify(
                    parties_shared_state.clone(),
                    &aux_i.into(),
                    &data,
                    &msg.ψ_prime.0,
                    &security_params.π_log,
                    &msg.ψ_prime.1,
                )
                .err()
            };

            if ψ_invalid.is_some() || ψˆ_invalid.is_some() || ψ_prime_invalid.is_some() {
                faulty_parties.push((
                    j,
                    ciphertext_msg_id,
                    msg_id,
                    (ψ_invalid, ψˆ_invalid, ψ_prime_invalid),
                ))
            }
        }

        if !faulty_parties.is_empty() {
            return Err(SigningAborted::InvalidΨ(faulty_parties).into());
        }

        // Step 2
        let Γ = Γ_i
            + round2_msgs
                .iter_indexed()
                .map(|(_, _, msg)| msg.Γ)
                .sum::<Point<E>>();
        let Delta_i = Γ * &k_i;

        let α_sum =
            round2_msgs
                .iter()
                .map(|msg| &msg.D)
                .try_fold(Scalar::<E>::zero(), |sum, D_ij| {
                    let α_ij = dec_i
                        .decrypt(D_ij)
                        .ok_or(Bug::PaillierDec(BugSource::α_ij))?;
                    Ok::<_, Bug>(sum + Scalar::<E>::from_be_bytes_mod_order(α_ij))
                })?;
        let αˆ_sum =
            round2_msgs
                .iter()
                .map(|msg| &msg.Dˆ)
                .try_fold(Scalar::zero(), |sum, Dˆ_ij| {
                    let αˆ_ij = dec_i
                        .decrypt(Dˆ_ij)
                        .ok_or(Bug::PaillierDec(BugSource::αˆ_ij))?;
                    Ok::<_, Bug>(sum + Scalar::<E>::from_be_bytes_mod_order(αˆ_ij))
                })?;

        let delta_i = y_i.as_ref() * k_i.as_ref() + α_sum - β_sum;
        let chi_i = self.key_share.core.x.as_ref() * k_i.as_ref() + αˆ_sum - βˆ_sum;

        for j in self.other_parties() {
            let aux_j = &self.key_share.parties[usize::from(j)];
            let ψ_prime_prime = π_log::non_interactive::prove(
                parties_shared_state.clone(),
                &aux_j.into(),
                &π_log::Data {
                    key0: enc_i.clone(),
                    c: K_i.clone(),
                    x: Delta_i,
                    g: Γ,
                },
                &π_log::PrivateData {
                    x: scalar_to_bignumber(&k_i),
                    nonce: p_i.clone(),
                },
                &security_params.π_log,
                &mut *rng,
            )
            .map_err(|e| Bug::ΠLog(BugSource::ψ_prime_prime, e))?;

            outgoings
                .send(Outgoing::p2p(
                    j,
                    Msg::Round3(MsgRound3 {
                        delta: delta_i,
                        Delta: Delta_i,
                        ψ_prime_prime,
                    }),
                ))
                .await
                .map_err(SigningError::SendError)?;
        }

        // Output

        // Step 1
        let round3_msgs = rounds
            .complete(round3)
            .await
            .map_err(SigningError::ReceiveMessage)?;

        let mut faulty_parties = vec![];
        for ((j, msg_id, msg), (_, ciphertext_id, ciphertext_j)) in
            round3_msgs.iter_indexed().zip(ciphertexts.iter_indexed())
        {
            let aux_j = &self.key_share.parties[usize::from(j)];
            let enc_j = encryption_key_from_n(&aux_j.N);

            let data = π_log::Data {
                key0: enc_j.clone(),
                c: ciphertext_j.K.clone(),
                x: msg.Delta,
                g: Γ,
            };

            if π_log::non_interactive::verify(
                parties_shared_state.clone(),
                &aux_i.into(),
                &data,
                &msg.ψ_prime_prime.0,
                &security_params.π_log,
                &msg.ψ_prime_prime.1,
            )
            .is_err()
            {
                faulty_parties.push((j, ciphertext_id, msg_id))
            }
        }

        if !faulty_parties.is_empty() {
            return Err(SigningAborted::InvalidΨPrimePrime(faulty_parties).into());
        }

        // Step 2
        let delta = delta_i + round3_msgs.iter().map(|m| m.delta).sum::<Scalar<E>>();
        let Delta = Delta_i + round3_msgs.iter().map(|m| m.Delta).sum::<Point<E>>();

        if Point::generator() * delta != Delta {
            // Following the protocol, party should broadcast additional proofs
            // to convince others it didn't cheat. However, since identifiable
            // abort is not implemented yet, this part of the protocol is missing
            return Err(SigningAborted::MismatchedDelta.into());
        }

        let R = Γ * delta.invert().ok_or(Bug::ZeroDelta)?;
        let R = NonZero::from_point(R).ok_or(Bug::ZeroR)?;
        let presig = Presignature {
            R,
            k: k_i,
            chi: SecretScalar::new(&mut chi_i.clone()),
        };

        // If message is not specified, protocol terminates here and outputs partial
        // signature
        let Some(message_to_sign) = message_to_sign else {
            return Ok(ProtocolOutput::Presignature(presig))
        };

        // Signing

        // Round 1
        let partial_sig = presig.partially_sign(message_to_sign);
        outgoings
            .send(Outgoing::broadcast(Msg::Round4(MsgRound4 {
                σ: partial_sig.σ,
            })))
            .await
            .map_err(SigningError::SendError)?;

        // Output
        let partial_sigs = rounds
            .complete(round4)
            .await
            .map_err(SigningError::ReceiveMessage)?;
        let sig = {
            let r = NonZero::from_scalar(partial_sig.r);
            let s = NonZero::from_scalar(
                partial_sig.σ + partial_sigs.iter().map(|m| m.σ).sum::<Scalar<E>>(),
            );
            Option::zip(r, s).map(|(r, s)| Signature { r, s })
        };
        let sig_invalid = match &sig {
            Some(sig) => sig
                .verify(&self.key_share.core.shared_public_key, &message_to_sign)
                .is_err(),
            None => true,
        };
        if sig_invalid {
            // Following the protocol, party should broadcast additional proofs
            // to convince others it didn't cheat. However, since identifiable
            // abort is not implemented yet, this part of the protocol is missing
            return Err(SigningAborted::SignatureInvalid.into());
        }
        let sig = sig.ok_or(SigningAborted::SignatureInvalid)?;

        Ok(ProtocolOutput::Signature(sig))
    }
}

impl<E> Presignature<E>
where
    E: Curve,
    NonZero<Point<E>>: AlwaysHasAffineX<E>,
{
    pub fn partially_sign(self, message_to_sign: Message) -> PartialSignature<E> {
        let r = self.R.x().to_scalar();
        let m = message_to_sign.to_scalar::<E>();
        let σ_i = self.k.as_ref() * m + r * self.chi.as_ref();
        PartialSignature { r, σ: σ_i }
    }
}

impl<E: Curve> PartialSignature<E> {
    pub fn combine(partial_signatures: &[PartialSignature<E>]) -> Option<Signature<E>> {
        if partial_signatures.is_empty() {
            None
        } else {
            let r = NonZero::from_scalar(partial_signatures[0].r)?;
            let s = NonZero::from_scalar(partial_signatures.iter().map(|s| s.σ).sum())?;
            Some(Signature { r, s })
        }
    }
}

impl<E: Curve> Signature<E>
where
    NonZero<Point<E>>: AlwaysHasAffineX<E>,
{
    /// Verifies that signature matches specified public key and message
    pub fn verify(&self, public_key: &Point<E>, message: &Message) -> Result<(), InvalidSignature> {
        let r =
            (Point::generator() * message.to_scalar::<E>() + public_key * self.r) * self.s.invert();
        let r = NonZero::from_point(r).ok_or(InvalidSignature)?;

        if *self.r == r.x().to_scalar() {
            Ok(())
        } else {
            Err(InvalidSignature)
        }
    }
}

enum ProtocolOutput<E: Curve> {
    Presignature(Presignature<E>),
    Signature(Signature<E>),
}

#[derive(Debug, Error)]
#[error("message to sign is not valid")]
pub struct InvalidMessage;

/// Error indicating that signing failed
#[derive(Debug, Error)]
pub enum SigningError<IErr, OErr> {
    #[error("provided key share is not valid")]
    InvalidKeyShare(
        #[from]
        #[source]
        InvalidKeyShare,
    ),
    #[error("invalid security level")]
    InvalidSecurityLevel(
        #[source]
        #[from]
        InvalidSecurityLevel,
    ),
    /// Signing protocol was maliciously aborted by another party
    #[error("signing protocol was maliciously aborted by another party")]
    Aborted(
        #[source]
        #[from]
        SigningAborted,
    ),
    /// Receiving message error
    #[error("receive message")]
    ReceiveMessage(#[source] CompleteRoundError<RoundInputError, IErr>),
    /// Sending message error
    #[error("send message")]
    SendError(#[source] OErr),
    /// Bug occurred
    #[error("bug occurred")]
    Bug(InternalError),
}

/// Error indicating that protocol was aborted by malicious party
///
/// It _can be_ cryptographically proven, but we do not support it yet.
#[allow(clippy::type_complexity)]
#[derive(Debug, Error)]
pub enum SigningAborted {
    #[error("π_enc::verify(K) failed")]
    EncProofOfK(Vec<(PartyIndex, MsgId, MsgId)>),
    #[error("ψ, ψˆ, or ψ' proofs are invalid")]
    InvalidΨ(
        Vec<(
            PartyIndex,
            MsgId,
            MsgId,
            (
                Option<paillier_zk::InvalidProof>,
                Option<paillier_zk::InvalidProof>,
                Option<paillier_zk::InvalidProof>,
            ),
        )>,
    ),
    #[error("ψ'' proof is invalid")]
    InvalidΨPrimePrime(Vec<(PartyIndex, MsgId, MsgId)>),
    #[error("Delta != G * delta")]
    MismatchedDelta,
    #[error("resulting signature is not valid")]
    SignatureInvalid,
    #[error("other parties received different broadcast messages at round1a")]
    Round1aNotReliable(Vec<(PartyIndex, MsgId)>),
}

#[derive(Debug, Error)]
pub enum InvalidSecurityLevel {
    #[error("specified security level is too small to carry out protocol")]
    SecurityLevelTooSmall,
    #[error("epsilon is too small to carry out protocol")]
    EpsilonTooSmall,
}

/// Error indicating that internal bug was detected
///
/// Please, report this issue if you encounter it
#[derive(Debug, Error)]
#[error(transparent)]
pub struct InternalError(Bug);

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
    #[error("π aff-g failed to prove statement {0:?}: {1:?}")]
    ΠAffG(BugSource, paillier_zk::ProtocolError),
    #[error("π log* failed to prove statement: {0:?}")]
    ΠLog(BugSource, paillier_zk::ProtocolError),
    #[error("couldn't decrypt a message: {0:?}")]
    PaillierDec(BugSource),
    #[error("delta is zero")]
    ZeroDelta,
    #[error("R is zero")]
    ZeroR,
    #[error("unexpected protocol output")]
    UnexpectedProtocolOutput,
    #[error("reliable broadcast")]
    HashMessage(#[source] HashMessageError),
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
enum BugSource {
    G_i,
    K_i,
    y_i_times_K_j,
    β_ij_enc,
    D_ji,
    F_ji,
    x_i_times_K_j,
    βˆ_ij_enc,
    Dˆ_ji,
    Fˆ_ji,
    ψ_ji,
    ψˆ_ji,
    ψ_prime_ji,
    α_ij,
    αˆ_ij,
    ψ_prime_prime,
}

#[derive(Debug, Error)]
#[error("signature is not valid")]
pub struct InvalidSignature;

impl<IErr, OErr> From<Bug> for SigningError<IErr, OErr> {
    fn from(e: Bug) -> Self {
        SigningError::Bug(InternalError(e))
    }
}

#[cfg(test)]
mod misc_tests {
    use paillier_zk::libpaillier::{unknown_order::BigNumber, DecryptionKey, EncryptionKey};
    use rand_dev::DevRng;

    // Since libpaillier crate encrypts vectors (not bigints), we need to be sure that
    // bigint<->bytes conversion works properly and all additivity properties work as
    // expected
    #[test]
    fn paillier_additivity_works() {
        let mut rng = DevRng::new();

        let p = BigNumber::prime_from_rng(32, &mut rng);
        let q = BigNumber::prime_from_rng(32, &mut rng);

        let dec = DecryptionKey::with_primes(&p, &q).unwrap();
        let enc = EncryptionKey::from(&dec);

        let a = enc.encrypt(BigNumber::one().to_bytes(), None).unwrap().0;
        let b = enc.encrypt(BigNumber::one().to_bytes(), None).unwrap().0;

        let sum = enc.add(&a, &b).unwrap();
        let sum = dec.decrypt(&sum).unwrap();

        assert_eq!(BigNumber::from_slice(sum), BigNumber::from(2));

        let a = BigNumber::one();
        let b = enc.n() - BigNumber::one();

        let a = enc.encrypt(a.to_bytes(), None).unwrap().0;
        let b = enc.encrypt(b.to_bytes(), None).unwrap().0;

        let sum = enc.add(&a, &b).unwrap();
        let sum = dec.decrypt(&sum).unwrap();

        assert_eq!(BigNumber::from_slice(&sum), BigNumber::zero());
    }
}

#[cfg(test)]
#[generic_tests::define(attrs(tokio::test, test_case::case))]
mod protocol_tests {
    use generic_ec::{coords::HasAffineX, hash_to_curve::FromHash, Curve, Point, Scalar};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rand_dev::DevRng;
    use round_based::simulation::Simulation;
    use sha2::Sha256;

    use crate::{security_level::ReasonablySecure, ExecutionId};

    #[test_case::case(2; "n2")]
    #[test_case::case(3; "n3")]
    #[test_case::case(5; "n5")]
    #[test_case::case(7; "n7")]
    #[tokio::test]
    async fn signing_works<E: Curve>(n: u16)
    where
        Point<E>: HasAffineX<E>,
        Scalar<E>: FromHash,
    {
        let mut rng = DevRng::new();

        let shares = crate::trusted_dealer::cached_shares::load::<E, ReasonablySecure>(n);

        let signing_execution_id: [u8; 32] = rng.gen();
        let signing_execution_id =
            ExecutionId::<E, ReasonablySecure>::from_bytes(&signing_execution_id);
        let mut simulation = Simulation::<super::Msg<E, Sha256>>::new();

        let message_to_sign = b"Dfns rules!";
        let message_to_sign = super::Message::new::<Sha256>(message_to_sign);

        let mut outputs = vec![];
        for share in &shares {
            let party = simulation.add_party();
            let signing_execution_id = signing_execution_id.clone();
            let mut party_rng = ChaCha20Rng::from_seed(rng.gen());

            outputs.push(async move {
                crate::signing(share)
                    .set_execution_id(signing_execution_id)
                    .sign(&mut party_rng, party, message_to_sign)
                    .await
            });
        }

        let signatures = futures::future::try_join_all(outputs)
            .await
            .expect("signing failed");

        signatures[0]
            .verify(&shares[0].core.shared_public_key, &message_to_sign)
            .expect("signature is not valid");

        assert!(signatures.iter().all(|s_i| signatures[0] == *s_i));
    }

    #[instantiate_tests(<generic_ec::curves::Secp256r1>)]
    mod secp256r1 {}
}
