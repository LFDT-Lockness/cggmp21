use std::marker::PhantomData;

use digest::Digest;
use generic_ec::Curve;
use sha2::Sha256;

use crate::security_level::SecurityLevel;

/// Protocol execution ID
///
/// Each protocol execution should have unique execution ID for better security hygiene.
/// All parties taking part in the protocol must share the same execution ID,
/// otherwise protocol will abort with unverbose error.
pub struct ExecutionId<E: Curve, L: SecurityLevel, D: Digest = Sha256> {
    id: digest::Output<D>,
    _ph: PhantomData<fn() -> (E, L)>,
}

impl<E: Curve, L: SecurityLevel, D: Digest> ExecutionId<E, L, D> {
    /// Constructs execution ID from hash
    ///
    /// You can salt any information, which uniquely identifies this protocol execution,
    /// into the hash.
    pub fn from_digest(hash: D) -> Self {
        Self {
            id: hash.finalize(),
            _ph: PhantomData,
        }
    }

    /// Constructs execution ID from byte string
    ///
    /// Byte string should uniquely identify this protocol execution.
    pub fn from_bytes(id: &[u8]) -> Self {
        Self {
            id: D::digest(id),
            _ph: PhantomData,
        }
    }

    /// Derives execution ID
    ///
    /// Execution ID is derived from provided hashed identifier `H(m)` as follows:
    /// ```text
    /// ID = H(H(m) || "-CGGMP21-DFNS-{PROTOCOL_NAME}-{CURVE_NAME}"
    ///     || "-K-{SECURITY_LEVEL}"
    ///     || "-E-{EPSILON}"
    ///     || "-L-{ELL}"
    ///     || "-L'-{ELL_PRIME}"
    ///     || "-M-{M}"
    ///     || "-Q-{Q}")
    /// ```
    ///
    /// If `H(m)` wasn't provided, it's replaced with zeroes byte string of the same size as `H(m)`
    /// output.
    pub(crate) fn evaluate(&self, protocol: ProtocolChoice) -> digest::Output<D> {
        let security_bits = u16::try_from(L::SECURITY_BITS).unwrap_or(u16::MAX);
        let epsilon = u16::try_from(L::EPSILON).unwrap_or(u16::MAX);
        let ell = u16::try_from(L::ELL).unwrap_or(u16::MAX);
        let ell_prime = u16::try_from(L::ELL_PRIME).unwrap_or(u16::MAX);
        let m = u16::try_from(L::M).unwrap_or(u16::MAX);
        let q = L::q().to_bytes();

        D::new()
            .chain_update(&self.id)
            .chain_update(b"-CGGMP21-DFNS-")
            .chain_update(protocol.as_bytes())
            .chain_update(b"-")
            .chain_update(E::CURVE_NAME)
            .chain_update(b"-K-")
            .chain_update(security_bits.to_be_bytes())
            .chain_update(b"-E-")
            .chain_update(epsilon.to_be_bytes())
            .chain_update(b"-L-")
            .chain_update(ell.to_be_bytes())
            .chain_update(b"-L'-")
            .chain_update(ell_prime.to_be_bytes())
            .chain_update(b"-M-")
            .chain_update(m.to_be_bytes())
            .chain_update(b"-Q-")
            .chain_update(q)
            .finalize()
    }
}

impl<E: Curve, L: SecurityLevel, D: Digest> Default for ExecutionId<E, L, D> {
    fn default() -> Self {
        Self {
            id: Default::default(),
            _ph: PhantomData,
        }
    }
}

impl<E: Curve, L: SecurityLevel, D: Digest> Clone for ExecutionId<E, L, D> {
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            _ph: PhantomData,
        }
    }
}

pub(crate) enum ProtocolChoice {
    Keygen,
    Presigning3,
}

impl ProtocolChoice {
    fn as_bytes(&self) -> &'static [u8] {
        match self {
            Self::Keygen => b"KEYGEN",
            Self::Presigning3 => b"PRESIGNING3",
        }
    }
}
