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
    use cggmp24::supported_curves::{Secp256k1, Stark};

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

/// Verifies ECDSA signatures on NIST P-256 (`secp256r1`) using `p256` crate
pub struct P256;

impl ExternalVerifier<cggmp24::supported_curves::Secp256r1> for P256 {
    fn verify(
        public_key: &Point<cggmp24::supported_curves::Secp256r1>,
        signature: &Signature<cggmp24::supported_curves::Secp256r1>,
        message: &[u8],
    ) -> anyhow::Result<()> {
        use anyhow::Context;
        use p256::ecdsa::{signature::Verifier, Signature as EcdsaSig, VerifyingKey};

        let verifying_key = VerifyingKey::from_sec1_bytes(&public_key.to_bytes(true))
            .map_err(|e| anyhow::anyhow!("public key is not valid: {e}"))?;
        let mut signature_bytes = [0u8; 64];
        signature.write_to_slice(&mut signature_bytes);
        let signature = EcdsaSig::from_slice(&signature_bytes).context("malformed signature")?;

        verifying_key
            .verify(message, &signature)
            .map_err(|e| anyhow::anyhow!("invalid signature: {e}"))
    }
}

/// Verifies ECDSA signatures on NIST P-384 (`secp384r1`) using `p384` crate
pub struct P384;

impl ExternalVerifier<cggmp24::supported_curves::Secp384r1> for P384 {
    fn verify(
        public_key: &Point<cggmp24::supported_curves::Secp384r1>,
        signature: &Signature<cggmp24::supported_curves::Secp384r1>,
        message: &[u8],
    ) -> anyhow::Result<()> {
        use anyhow::Context;
        use p384::ecdsa::{signature::hazmat::PrehashVerifier, Signature as EcdsaSig, VerifyingKey};
        use sha2::Digest;

        let verifying_key = VerifyingKey::from_sec1_bytes(&public_key.to_bytes(true))
            .map_err(|e| anyhow::anyhow!("public key is not valid: {e}"))?;
        let mut signature_bytes = [0u8; 96];
        signature.write_to_slice(&mut signature_bytes);
        let signature = EcdsaSig::from_slice(&signature_bytes).context("malformed signature")?;

        // Signing tests hash the message with SHA-256 (`DataToSign::digest::<Sha256>`)
        let digest = sha2::Sha256::digest(message);
        verifying_key
            .verify_prehash(&digest, &signature)
            .map_err(|e| anyhow::anyhow!("invalid signature: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use generic_ec::{NonZero, Scalar};

    #[test]
    fn p256_and_p384_reject_invalid_signatures() {
        let mut rng = rand_dev::DevRng::new();

        let sk256 = Scalar::<cggmp24::supported_curves::Secp256r1>::random(&mut rng);
        let pk256 = Point::generator() * sk256;
        let bad_sig256 = Signature {
            r: NonZero::from_scalar(Scalar::one()).unwrap(),
            s: NonZero::from_scalar(Scalar::one()).unwrap(),
        };
        assert!(P256::verify(&pk256, &bad_sig256, b"test message").is_err());

        let sk384 = Scalar::<cggmp24::supported_curves::Secp384r1>::random(&mut rng);
        let pk384 = Point::generator() * sk384;
        let bad_sig384 = Signature {
            r: NonZero::from_scalar(Scalar::one()).unwrap(),
            s: NonZero::from_scalar(Scalar::one()).unwrap(),
        };
        assert!(P384::verify(&pk384, &bad_sig384, b"test message").is_err());
    }
}
