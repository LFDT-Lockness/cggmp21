use digest::Digest;
use futures::SinkExt;
use generic_ec::{
    coords::AlwaysHasAffineX, hash_to_curve::FromHash, Curve, NonZero, Point, Scalar, SecretScalar,
};
use paillier_zk::libpaillier::{unknown_order::BigNumber, Ciphertext, DecryptionKey};
use paillier_zk::{
    group_element_vs_paillier_encryption_in_range as pi_log, libpaillier,
    paillier_affine_operation_in_range as pi_aff, paillier_encryption_in_range as pi_enc,
    BigNumberExt, SafePaillierDecryptionExt, SafePaillierEncryptionExt,
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

use crate::progress::Tracer;
use crate::utils::{hash_message, HashMessageError};
use crate::{
    execution_id::ProtocolChoice,
    key_share::{InvalidKeyShare, KeyShare, Valid},
    security_level::SecurityLevel,
    utils::{encryption_key_from_n, scalar_to_bignumber},
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
    pub sigma: Scalar<E>,
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
    pub psi0: (pi_enc::Commitment, pi_enc::Proof),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgRound2<E: Curve> {
    pub Gamma: Point<E>,
    pub D: Ciphertext,
    pub F: Ciphertext,
    pub hat_D: Ciphertext,
    pub hat_F: Ciphertext,
    pub psi: (pi_aff::Commitment<E>, pi_aff::Proof),
    pub hat_psi: (pi_aff::Commitment<E>, pi_aff::Proof),
    pub psi_prime: (pi_log::Commitment<E>, pi_log::Proof),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgRound3<E: Curve> {
    pub delta: Scalar<E>,
    pub Delta: Point<E>,
    pub psi_prime_prime: (pi_log::Commitment<E>, pi_log::Proof),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgRound4<E: Curve> {
    pub sigma: Scalar<E>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgSyncState<D: Digest>(digest::Output<D>);

pub struct SigningBuilder<'r, E, L, D>
where
    E: Curve,
    L: SecurityLevel,
    D: Digest,
{
    key_share: &'r Valid<KeyShare<E, L>>,
    execution_id: ExecutionId<E, L, D>,
    tracer: Option<&'r mut dyn Tracer>,
}

impl<'r, E, L, D> SigningBuilder<'r, E, L, D>
where
    E: Curve,
    Scalar<E>: FromHash,
    NonZero<Point<E>>: AlwaysHasAffineX<E>,
    L: SecurityLevel,
    D: Digest<OutputSize = digest::typenum::U32> + Clone + 'static,
{
    pub fn new(secret_key_share: &'r Valid<KeyShare<E, L>>) -> Self {
        Self {
            key_share: secret_key_share,
            execution_id: Default::default(),
            tracer: None,
        }
    }

    pub fn set_digest<D2>(self) -> SigningBuilder<'r, E, L, D2>
    where
        D2: Digest,
    {
        SigningBuilder {
            key_share: self.key_share,
            tracer: self.tracer,
            execution_id: Default::default(),
        }
    }

    pub fn set_progress_tracer(mut self, tracer: &'r mut dyn Tracer) -> Self {
        self.tracer = Some(tracer);
        self
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
        mut self,
        rng: &mut R,
        party: M,
        message_to_sign: Option<Message>,
    ) -> Result<ProtocolOutput<E>, SigningError<M::ReceiveError, M::SendError>>
    where
        R: RngCore + CryptoRng,
        M: Mpc<ProtocolMessage = Msg<E, D>>,
    {
        self.tracer.protocol_begins();

        let MpcParty { delivery, .. } = party.into_party();
        let (incomings, mut outgoings) = delivery.split();

        self.tracer.stage("Validate security level");
        Self::validate_security_level()?;

        self.tracer.stage("Retrieve auxiliary data");
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

        self.tracer
            .stage("Precompute execution id and security params");
        let execution_id = self.execution_id.evaluate(ProtocolChoice::Presigning3);
        let security_params = crate::utils::SecurityParams::new::<L>();

        self.tracer.stage("Setup networking");
        let mut rounds = RoundsRouter::<Msg<E, D>>::builder();
        let round1a = rounds.add_round(RoundInput::<MsgRound1a>::broadcast(i, n));
        let round1b = rounds.add_round(RoundInput::<MsgRound1b>::p2p(i, n));
        let round1a_sync = rounds.add_round(RoundInput::<MsgSyncState<D>>::broadcast(i, n));
        let round2 = rounds.add_round(RoundInput::<MsgRound2<E>>::p2p(i, n));
        let round3 = rounds.add_round(RoundInput::<MsgRound3<E>>::p2p(i, n));
        let round4 = rounds.add_round(RoundInput::<MsgRound4<E>>::broadcast(i, n));
        let mut rounds = rounds.listen(incomings);

        // Round 1
        self.tracer.round_begins();

        self.tracer
            .stage("Generate local ephemeral secrets (k_i, y_i, p_i, v_i)");
        let gamma_i = SecretScalar::<E>::random(rng);
        let k_i = SecretScalar::<E>::random(rng);

        let v_i = BigNumber::gen_inversible(N_i, rng);
        let rho_i = BigNumber::gen_inversible(N_i, rng);

        self.tracer.stage("Encrypt G_i and K_i");
        let G_i = enc_i
            .encrypt_with(&scalar_to_bignumber(&gamma_i), &v_i)
            .map_err(|_| Bug::PaillierEnc(BugSource::G_i))?;
        let K_i = enc_i
            .encrypt_with(&scalar_to_bignumber(&k_i), &rho_i)
            .map_err(|_| Bug::PaillierEnc(BugSource::K_i))?;

        self.tracer.send_msg();
        outgoings
            .send(Outgoing::broadcast(Msg::Round1a(MsgRound1a {
                K: K_i.clone(),
                G: G_i.clone(),
            })))
            .await
            .map_err(SigningError::SendError)?;
        self.tracer.msg_sent();

        let parties_shared_state = D::new_with_prefix(execution_id);
        for j in self.other_parties() {
            self.tracer.stage("Prove ψ0_j");
            let aux_j = &self.key_share.parties[usize::from(j)];

            let psi0 = pi_enc::non_interactive::prove(
                parties_shared_state.clone().chain_update(i.to_be_bytes()),
                &aux_j.into(),
                &pi_enc::Data {
                    key: enc_i.clone(),
                    ciphertext: K_i.clone(),
                },
                &pi_enc::PrivateData {
                    plaintext: scalar_to_bignumber(&k_i),
                    nonce: rho_i.clone(),
                },
                &security_params.pi_enc,
                &mut *rng,
            )
            .map_err(|e| Bug::PiEnc(BugSource::psi0, e))?;

            self.tracer.send_msg();
            outgoings
                .send(Outgoing::p2p(j, Msg::Round1b(MsgRound1b { psi0 })))
                .await
                .map_err(SigningError::SendError)?;
            self.tracer.msg_sent();
        }

        // Round 2
        self.tracer.round_begins();

        self.tracer.receive_msgs();
        // Contains G_j, K_j sent by other parties
        let ciphertexts = rounds
            .complete(round1a)
            .await
            .map_err(SigningError::ReceiveMessage)?;
        let psi0 = rounds
            .complete(round1b)
            .await
            .map_err(SigningError::ReceiveMessage)?;
        self.tracer.msgs_received();

        // Step 1. Ensure reliability of round1a: broadcast hash(ciphertexts)
        self.tracer.stage("Hash received msgs (reliability check)");
        let h_i = ciphertexts
            .iter_including_me(&MsgRound1a {
                K: K_i.clone(),
                G: G_i.clone(),
            })
            .try_fold(D::new(), hash_message)
            .map_err(Bug::HashMessage)?
            .finalize();

        self.tracer.send_msg();
        outgoings
            .send(Outgoing::broadcast(Msg::SyncState(MsgSyncState(h_i))))
            .await
            .map_err(SigningError::SendError)?;
        self.tracer.msg_sent();

        // Step 2. Verify proofs
        self.tracer.stage("Verify psi0 proofs");
        {
            let mut faulty_parties = vec![];
            for ((j, msg1_id, ciphertext), (_, msg2_id, proof)) in
                ciphertexts.iter_indexed().zip(psi0.iter_indexed())
            {
                let aux_j = &self.key_share.parties[usize::from(j)];
                if pi_enc::non_interactive::verify(
                    parties_shared_state.clone().chain_update(j.to_be_bytes()),
                    &aux_i.into(),
                    &pi_enc::Data {
                        key: encryption_key_from_n(&aux_j.N),
                        ciphertext: ciphertext.K.clone(),
                    },
                    &proof.psi0.0,
                    &security_params.pi_enc,
                    &proof.psi0.1,
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

        // Step 3
        let Gamma_i = Point::generator() * &gamma_i;
        let J = BigNumber::one() << L::ELL_PRIME;

        let mut beta_sum = Scalar::zero();
        let mut hat_beta_sum = Scalar::zero();
        for (j, _, ciphertext_j) in ciphertexts.iter_indexed() {
            self.tracer
                .stage("Sample random r, hat_r, s, hat_s, beta, hat_beta");
            let aux_j = &self.key_share.parties[usize::from(j)];
            let N_j = &aux_j.N;
            let enc_j = encryption_key_from_n(N_j);

            let r_ij = BigNumber::from_rng(N_i, rng);
            let hat_r_ij = BigNumber::from_rng(N_i, rng);
            let s_ij = BigNumber::from_rng(N_j, rng);
            let hat_s_ij = BigNumber::from_rng(N_j, rng);

            let beta_ij = BigNumber::from_rng_pm(&J, rng);
            let hat_beta_ij = BigNumber::from_rng_pm(&J, rng);

            beta_sum += beta_ij.to_scalar();
            hat_beta_sum += hat_beta_ij.to_scalar();

            self.tracer.stage("Encrypt D_ji");
            // D_ji = (gamma_i * K_j) + enc_j(-beta_ij, s_ij)
            let D_ji = {
                let gamma_i_times_K_j = enc_j
                    .omul(&scalar_to_bignumber(&gamma_i), &ciphertext_j.K)
                    .map_err(|_| Bug::PaillierOp(BugSource::gamma_i_times_K_j))?;
                let neg_beta_ij_enc = enc_j
                    .encrypt_with(&-&beta_ij, &s_ij)
                    .map_err(|_| Bug::PaillierEnc(BugSource::neg_beta_ij_enc))?;
                enc_j
                    .oadd(&gamma_i_times_K_j, &neg_beta_ij_enc)
                    .map_err(|_| Bug::PaillierOp(BugSource::D_ji))?
            };

            self.tracer.stage("Encrypt F_ji");
            let F_ji = enc_i
                .encrypt_with(&-&beta_ij, &r_ij)
                .map_err(|_| Bug::PaillierEnc(BugSource::F_ji))?;

            self.tracer.stage("Encrypt hat_D_ji");
            // Dˆ_ji = (x_i * K_j) + enc_j(-hat_beta_ij, hat_s_ij)
            let hat_D_ji = {
                let x_i_times_K_j = enc_j
                    .omul(
                        &scalar_to_bignumber(&self.key_share.core.x),
                        &ciphertext_j.K,
                    )
                    .map_err(|_| Bug::PaillierOp(BugSource::x_i_times_K_j))?;
                let neg_hat_beta_ij_enc = enc_j
                    .encrypt_with(&-&hat_beta_ij, &hat_s_ij)
                    .map_err(|_| Bug::PaillierEnc(BugSource::hat_beta_ij_enc))?;
                enc_j
                    .oadd(&x_i_times_K_j, &neg_hat_beta_ij_enc)
                    .map_err(|_| Bug::PaillierOp(BugSource::hat_D))?
            };

            self.tracer.stage("Encrypt hat_F_ji");
            let hat_F_ji = enc_i
                .encrypt_with(&-&hat_beta_ij, &hat_r_ij)
                .map_err(|_| Bug::PaillierEnc(BugSource::hat_F))?;

            self.tracer.stage("Prove psi_ji");
            let psi_cst = parties_shared_state.clone().chain_update(i.to_be_bytes());
            let psi_ji = pi_aff::non_interactive::prove(
                psi_cst.clone(),
                &aux_j.into(),
                &pi_aff::Data {
                    key0: enc_j.clone(),
                    key1: enc_i.clone(),
                    c: ciphertext_j.K.clone(),
                    d: D_ji.clone(),
                    y: F_ji.clone(),
                    x: Gamma_i,
                },
                &pi_aff::PrivateData {
                    x: scalar_to_bignumber(&gamma_i),
                    y: -&beta_ij,
                    nonce: s_ij.clone(),
                    nonce_y: r_ij.clone(),
                },
                &security_params.pi_aff,
                &mut *rng,
            )
            .map_err(|e| Bug::PiAffG(BugSource::psi, e))?;

            self.tracer.stage("Prove psiˆ_ji");
            let hat_psi_ji = pi_aff::non_interactive::prove(
                psi_cst.clone(),
                &aux_j.into(),
                &pi_aff::Data {
                    key0: enc_j.clone(),
                    key1: enc_i.clone(),
                    c: ciphertext_j.K.clone(),
                    d: hat_D_ji.clone(),
                    y: hat_F_ji.clone(),
                    x: Point::generator() * &self.key_share.core.x,
                },
                &pi_aff::PrivateData {
                    x: scalar_to_bignumber(&self.key_share.core.x),
                    y: -&hat_beta_ij,
                    nonce: hat_s_ij.clone(),
                    nonce_y: hat_r_ij.clone(),
                },
                &security_params.pi_aff,
                &mut *rng,
            )
            .map_err(|e| Bug::PiAffG(BugSource::hat_psi, e))?;

            self.tracer.stage("Prove psi_prime_ji ");
            let psi_prime_ji = pi_log::non_interactive::prove(
                psi_cst,
                &aux_j.into(),
                &pi_log::Data {
                    key0: enc_i.clone(),
                    c: G_i.clone(),
                    x: Gamma_i,
                    b: Point::<E>::generator().to_point(),
                },
                &pi_log::PrivateData {
                    x: scalar_to_bignumber(&gamma_i),
                    nonce: v_i.clone(),
                },
                &security_params.pi_log,
                &mut *rng,
            )
            .map_err(|e| Bug::PiLog(BugSource::psi_prime, e))?;

            self.tracer.send_msg();
            outgoings
                .send(Outgoing::p2p(
                    j,
                    Msg::Round2(MsgRound2 {
                        Gamma: Gamma_i,
                        D: D_ji,
                        F: F_ji,
                        hat_D: hat_D_ji,
                        hat_F: hat_F_ji,
                        psi: psi_ji,
                        hat_psi: hat_psi_ji,
                        psi_prime: psi_prime_ji,
                    }),
                ))
                .await
                .map_err(SigningError::SendError)?;
            self.tracer.msg_sent();
        }

        // Round 3
        self.tracer.round_begins();

        // Step 1. Ensure reliability of round1a: receive hash(ciphertexts) from others
        {
            self.tracer.receive_msgs();
            let round1a_hashes = rounds
                .complete(round1a_sync)
                .await
                .map_err(SigningError::ReceiveMessage)?;
            self.tracer.msgs_received();
            self.tracer
                .stage("Assert other parties hashed messages (reliability check)");
            let parties_have_different_hashes = round1a_hashes
                .into_iter_indexed()
                .filter(|(_j, _msg_id, hash)| hash.0 != h_i)
                .map(|(j, msg_id, _)| (j, msg_id))
                .collect::<Vec<_>>();
            if !parties_have_different_hashes.is_empty() {
                return Err(
                    SigningAborted::Round1aNotReliable(parties_have_different_hashes).into(),
                );
            }
        }

        // Step 2
        self.tracer.receive_msgs();
        let round2_msgs = rounds
            .complete(round2)
            .await
            .map_err(SigningError::ReceiveMessage)?;
        self.tracer.msgs_received();

        let mut faulty_parties = vec![];
        for ((j, msg_id, msg), (_, ciphertext_msg_id, ciphertexts)) in
            round2_msgs.iter_indexed().zip(ciphertexts.iter_indexed())
        {
            self.tracer.stage("Retrieve auxiliary data");
            let X_j = self.key_share.core.public_shares[usize::from(j)];
            let aux_j = &self.key_share.parties[usize::from(j)];
            let enc_j = encryption_key_from_n(&aux_j.N);
            let cst_j = parties_shared_state.clone().chain_update(j.to_be_bytes());

            self.tracer.stage("Validate psi");
            let psi_invalid = pi_aff::non_interactive::verify(
                cst_j.clone(),
                &aux_i.into(),
                &pi_aff::Data {
                    key0: enc_i.clone(),
                    key1: enc_j.clone(),
                    c: K_i.clone(),
                    d: msg.D.clone(),
                    y: msg.F.clone(),
                    x: msg.Gamma,
                },
                &msg.psi.0,
                &security_params.pi_aff,
                &msg.psi.1,
            )
            .err();

            self.tracer.stage("Validate hat_psi");
            let hat_psi_invalid = pi_aff::non_interactive::verify(
                cst_j.clone(),
                &aux_i.into(),
                &pi_aff::Data {
                    key0: enc_i.clone(),
                    key1: enc_j.clone(),
                    c: K_i.clone(),
                    d: msg.hat_D.clone(),
                    y: msg.hat_F.clone(),
                    x: X_j,
                },
                &msg.hat_psi.0,
                &security_params.pi_aff,
                &msg.hat_psi.1,
            )
            .err();

            self.tracer.stage("Validate psi_prime");
            let psi_prime_invalid = pi_log::non_interactive::verify(
                cst_j,
                &aux_i.into(),
                &pi_log::Data {
                    key0: enc_j.clone(),
                    c: ciphertexts.G.clone(),
                    x: msg.Gamma,
                    b: Point::<E>::generator().to_point(),
                },
                &msg.psi_prime.0,
                &security_params.pi_log,
                &msg.psi_prime.1,
            )
            .err();

            if psi_invalid.is_some() || hat_psi_invalid.is_some() || psi_prime_invalid.is_some() {
                faulty_parties.push((
                    j,
                    ciphertext_msg_id,
                    msg_id,
                    (psi_invalid, hat_psi_invalid, psi_prime_invalid),
                ))
            }
        }

        if !faulty_parties.is_empty() {
            return Err(SigningAborted::InvalidPsi(faulty_parties).into());
        }

        // Step 3
        self.tracer.stage("Compute Gamma, Delta_i, delta_i, chi_i");
        let Gamma = Gamma_i + round2_msgs.iter().map(|msg| msg.Gamma).sum::<Point<E>>();
        let Delta_i = Gamma * &k_i;

        let alpha_sum =
            round2_msgs
                .iter()
                .map(|msg| &msg.D)
                .try_fold(Scalar::<E>::zero(), |sum, D_ij| {
                    let alpha_ij = dec_i
                        .decrypt_to_bigint(D_ij)
                        .map_err(|_| Bug::PaillierDec(BugSource::alpha))?;
                    Ok::<_, Bug>(sum + alpha_ij.to_scalar())
                })?;
        let hat_alpha_sum = round2_msgs.iter().map(|msg| &msg.hat_D).try_fold(
            Scalar::zero(),
            |sum, hat_D_ij| {
                let hat_alpha_ij = dec_i
                    .decrypt_to_bigint(hat_D_ij)
                    .map_err(|_| Bug::PaillierDec(BugSource::hat_alpha))?;
                Ok::<_, Bug>(sum + hat_alpha_ij.to_scalar())
            },
        )?;

        let delta_i = gamma_i.as_ref() * k_i.as_ref() + alpha_sum + beta_sum;
        let chi_i = self.key_share.core.x.as_ref() * k_i.as_ref() + hat_alpha_sum + hat_beta_sum;

        for j in self.other_parties() {
            self.tracer.stage("Prove psi_prime_prime");
            let aux_j = &self.key_share.parties[usize::from(j)];
            let psi_prime_prime = pi_log::non_interactive::prove(
                parties_shared_state.clone().chain_update(i.to_be_bytes()),
                &aux_j.into(),
                &pi_log::Data {
                    key0: enc_i.clone(),
                    c: K_i.clone(),
                    x: Delta_i,
                    b: Gamma,
                },
                &pi_log::PrivateData {
                    x: scalar_to_bignumber(&k_i),
                    nonce: rho_i.clone(),
                },
                &security_params.pi_log,
                &mut *rng,
            )
            .map_err(|e| Bug::PiLog(BugSource::psi_prime_prime, e))?;

            self.tracer.send_msg();
            outgoings
                .send(Outgoing::p2p(
                    j,
                    Msg::Round3(MsgRound3 {
                        delta: delta_i,
                        Delta: Delta_i,
                        psi_prime_prime,
                    }),
                ))
                .await
                .map_err(SigningError::SendError)?;
            self.tracer.msg_sent();
        }

        // Output
        self.tracer.named_round_begins("Presig output");

        // Step 1
        self.tracer.receive_msgs();
        let round3_msgs = rounds
            .complete(round3)
            .await
            .map_err(SigningError::ReceiveMessage)?;
        self.tracer.msgs_received();

        self.tracer.stage("Validate psi_prime_prime");
        let mut faulty_parties = vec![];
        for ((j, msg_id, msg_j), (_, ciphertext_id, ciphertext_j)) in
            round3_msgs.iter_indexed().zip(ciphertexts.iter_indexed())
        {
            let aux_j = &self.key_share.parties[usize::from(j)];
            let enc_j = encryption_key_from_n(&aux_j.N);

            let data = pi_log::Data {
                key0: enc_j.clone(),
                c: ciphertext_j.K.clone(),
                x: msg_j.Delta,
                b: Gamma,
            };

            if pi_log::non_interactive::verify(
                parties_shared_state.clone().chain_update(j.to_be_bytes()),
                &aux_i.into(),
                &data,
                &msg_j.psi_prime_prime.0,
                &security_params.pi_log,
                &msg_j.psi_prime_prime.1,
            )
            .is_err()
            {
                faulty_parties.push((j, ciphertext_id, msg_id))
            }
        }

        if !faulty_parties.is_empty() {
            return Err(SigningAborted::InvalidPsiPrimePrime(faulty_parties).into());
        }

        // Step 2
        self.tracer.stage("Calculate presignature");
        let delta = delta_i + round3_msgs.iter().map(|m| m.delta).sum::<Scalar<E>>();
        let Delta = Delta_i + round3_msgs.iter().map(|m| m.Delta).sum::<Point<E>>();

        if Point::generator() * delta != Delta {
            // Following the protocol, party should broadcast additional proofs
            // to convince others it didn't cheat. However, since identifiable
            // abort is not implemented yet, this part of the protocol is missing
            return Err(SigningAborted::MismatchedDelta.into());
        }

        let R = Gamma * delta.invert().ok_or(Bug::ZeroDelta)?;
        let R = NonZero::from_point(R).ok_or(Bug::ZeroR)?;
        let presig = Presignature {
            R,
            k: k_i,
            chi: SecretScalar::new(&mut chi_i.clone()),
        };

        // If message is not specified, protocol terminates here and outputs partial
        // signature
        let Some(message_to_sign) = message_to_sign else {
            self.tracer.protocol_ends();
            return Ok(ProtocolOutput::Presignature(presig))
        };

        // Signing
        self.tracer.named_round_begins("Partial signing");

        // Round 1
        let partial_sig = presig.partially_sign(message_to_sign);

        self.tracer.send_msg();
        outgoings
            .send(Outgoing::broadcast(Msg::Round4(MsgRound4 {
                sigma: partial_sig.sigma,
            })))
            .await
            .map_err(SigningError::SendError)?;
        self.tracer.msg_sent();

        // Output
        self.tracer.named_round_begins("Signature reconstruction");

        self.tracer.receive_msgs();
        let partial_sigs = rounds
            .complete(round4)
            .await
            .map_err(SigningError::ReceiveMessage)?;
        self.tracer.msgs_received();
        let sig = {
            let r = NonZero::from_scalar(partial_sig.r);
            let s = NonZero::from_scalar(
                partial_sig.sigma + partial_sigs.iter().map(|m| m.sigma).sum::<Scalar<E>>(),
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

        self.tracer.protocol_ends();
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
        let sigma_i = self.k.as_ref() * m + r * self.chi.as_ref();
        PartialSignature { r, sigma: sigma_i }
    }
}

impl<E: Curve> PartialSignature<E> {
    pub fn combine(partial_signatures: &[PartialSignature<E>]) -> Option<Signature<E>> {
        if partial_signatures.is_empty() {
            None
        } else {
            let r = NonZero::from_scalar(partial_signatures[0].r)?;
            let s = NonZero::from_scalar(partial_signatures.iter().map(|s| s.sigma).sum())?;
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
    #[error("pi_enc::verify(K) failed")]
    EncProofOfK(Vec<(PartyIndex, MsgId, MsgId)>),
    #[error("ψ, ψˆ, or ψ' proofs are invalid")]
    InvalidPsi(
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
    InvalidPsiPrimePrime(Vec<(PartyIndex, MsgId, MsgId)>),
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
    #[error("π enc failed to prove statement {0:?}: {1:?}")]
    PiEnc(BugSource, paillier_zk::Error),
    #[error("π aff-g failed to prove statement {0:?}: {1:?}")]
    PiAffG(BugSource, paillier_zk::Error),
    #[error("π log* failed to prove statement: {0:?}")]
    PiLog(BugSource, paillier_zk::Error),
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
    gamma_i_times_K_j,
    neg_beta_ij_enc,
    D_ji,
    F_ji,
    x_i_times_K_j,
    hat_beta_ij_enc,
    hat_D,
    hat_F,
    psi0,
    psi,
    hat_psi,
    psi_prime,
    alpha,
    hat_alpha,
    psi_prime_prime,
}

#[derive(Debug, Error)]
#[error("signature is not valid")]
pub struct InvalidSignature;

impl<IErr, OErr> From<Bug> for SigningError<IErr, OErr> {
    fn from(e: Bug) -> Self {
        SigningError::Bug(InternalError(e))
    }
}
