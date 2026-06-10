use cggmp24::signing::Signature;
use generic_ec::{Curve, Point};

/// Verifies signature produced by cggmp24 implemenation using external library
pub trait ExternalVerifier<E: Curve> {
    fn verify(
        public_key: &Point<E>,
        signature: &Signature<E>,
        message: &[u8],
    ) -> anyhow::Result<()>;
}

/// Doesn't do any external verification
pub struct Noop;

impl<E: Curve> ExternalVerifier<E> for Noop {
    fn verify(
        _public_key: &Point<E>,
        _signature: &Signature<E>,
        _message: &[u8],
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

pub mod blockchains {
    use anyhow::Context;
    use cggmp24::supported_curves::{Secp256k1, Secp384r1, Stark};

    use crate::{convert_stark_scalar, external_verifier::ExternalVerifier};

    /// Verifies ECDSA signature using the same library as used in Bitcoin
    pub struct Bitcoin;

    impl ExternalVerifier<Secp256k1> for Bitcoin {
        fn verify(
            public_key: &generic_ec::Point<Secp256k1>,
            signature: &cggmp24::signing::Signature<Secp256k1>,
            message: &[u8],
        ) -> anyhow::Result<()> {
            let public_key = secp256k1::PublicKey::from_slice(&public_key.to_bytes(true))
                .context("public key is not valid")?;
            let message =
                secp256k1::Message::from_hashed_data::<secp256k1::hashes::sha256::Hash>(message);

            let mut signature_bytes = [0u8; 64];
            signature.write_to_slice(&mut signature_bytes);
            let signature = secp256k1::ecdsa::Signature::from_compact(&signature_bytes)
                .context("malformed signature")?;

            signature
                .verify(&message, &public_key)
                .context("invalid siganture")
        }
    }

    /// Verifies ECDSA/P-384 signature using the RustCrypto `p384` crate
    pub struct NistP384;

    impl ExternalVerifier<Secp384r1> for NistP384 {
        fn verify(
            public_key: &generic_ec::Point<Secp384r1>,
            signature: &cggmp24::signing::Signature<Secp384r1>,
            message: &[u8],
        ) -> anyhow::Result<()> {
            use p384::ecdsa::signature::Verifier as _;

            let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(&public_key.to_bytes(true))
                .context("invalid public key")?;

            let mut sig_bytes = [0u8; 96];
            signature.write_to_slice(&mut sig_bytes);
            let sig = p384::ecdsa::Signature::try_from(sig_bytes.as_slice())
                .context("malformed signature")?;

            vk.verify(message, &sig).context("invalid signature")
        }
    }

    pub struct StarkNet;

    impl ExternalVerifier<Stark> for StarkNet {
        fn verify(
            public_key: &generic_ec::Point<Stark>,
            signature: &cggmp24::Signature<Stark>,
            message: &[u8],
        ) -> anyhow::Result<()> {
            use generic_ec::coords::HasAffineX;
            let message_to_sign = cggmp24::DataToSign::<Stark>::digest::<sha2::Sha256>(message);
            let public_key_x = public_key
                .x()
                .ok_or(anyhow::Error::msg("No affine x for public key"))?
                .to_scalar();

            let public_key = convert_stark_scalar(&public_key_x)?;
            let message = convert_stark_scalar(&message_to_sign.to_scalar())?;
            let r = convert_stark_scalar(&signature.r)?;
            let s = convert_stark_scalar(&signature.s)?;

            let r = starknet_crypto::verify(&public_key, &message, &r, &s)?;
            if !r {
                anyhow::bail!("Signature verification failed");
            }
            Ok(())
        }
    }
}
