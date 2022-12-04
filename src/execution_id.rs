use std::marker::PhantomData;

use digest::Digest;
use generic_ec::Curve;

use crate::security_level::SecurityLevel;

/// Protocol execution ID
///
/// Each protocol execution should have unique execution ID for better security hygiene.
/// All parties taking part in the protocol must share the same execution ID,
/// otherwise protocol will abort with unverbose error.
pub struct ExecutionId<E: Curve, L: SecurityLevel, D: Digest> {
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
    /// ID = H(H(m) || "-CGGMP21-DFNS-{PROTOCOL_NAME}-{CURVE_NAME}-K-{SECURITY_LEVEL}-E-{EPSILON}")
    /// ```
    ///
    /// If `H(m)` wasn't provided, it's replaced with zeroes byte string of the same size as `H(m)`
    /// output.
    pub(crate) fn evaluate(self, protocol: ProtocolChoice) -> digest::Output<D> {
        let security_bits = u16::try_from(L::SECURITY_BITS).unwrap_or(u16::MAX);
        let epsilon = u16::try_from(L::EPSILON_BITS).unwrap_or(u16::MAX);
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

pub(crate) enum ProtocolChoice {
    Keygen,
}

impl ProtocolChoice {
    fn as_bytes(&self) -> &'static [u8] {
        match self {
            Self::Keygen => b"keygen",
        }
    }
}
