//! CGGMP24 key share refresh
//!
//! This crate implements share refresh from [CGGMP24] Figure 7 without Paillier/Pedersen
//! regeneration. Non-threshold (`n`-out-of-`n`) refresh is supported
//!
//! [CGGMP24]: https://ia.cr/2021/060

#![allow(non_snake_case, clippy::too_many_arguments)]
#![forbid(missing_docs)]
#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod errors;
/// Non-threshold (`n`-out-of-`n`) key share refresh
pub mod non_threshold;
mod utils;

/// Protocol progress tracing
pub mod progress {
    #[doc(inline)]
    pub use cggmp24_keygen::progress::{Event, Tracer};
    #[cfg(feature = "std")]
    pub use cggmp24_keygen::progress::{PerfProfiler, PerfReport, Stderr};
}

/// Security level parameters
pub mod security_level {
    #[doc(inline)]
    pub use cggmp24_keygen::security_level::{
        define_security_level, SecurityLevel, SecurityLevel128, SecurityLevel192,
    };
}

use alloc::vec::Vec;

#[doc(inline)]
pub use key_share::{
    CoreKeyShare as IncompleteKeyShare, DirtyCoreKeyShare as DirtyIncompleteKeyShare, DirtyKeyInfo,
    InvalidCoreShare, Validate,
};

use crate::errors::IoError;
use crate::security_level::SecurityLevel;

pub use self::non_threshold::KeyRefreshOutput;
#[doc(no_inline)]
pub use self::non_threshold::Msg as NonThresholdMsg;
pub use cggmp24_keygen::ExecutionId;

/// Message types for the non-threshold key refresh protocol
pub mod msg {
    /// Messages for non-threshold (`n`-out-of-`n`) key refresh
    pub mod non_threshold {
        pub use crate::non_threshold::{
            Msg, MsgReliabilityCheck, MsgRound1, MsgRound2, MsgRound3Broadcast, MsgRound3Unicast,
        };
    }
}

/// Key refresh protocol error
#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
#[displaydoc("key refresh protocol failed to complete")]
pub struct KeyRefreshError(#[cfg_attr(feature = "std", source)] Reason);

crate::errors::impl_from! {
    impl From for KeyRefreshError {
        err: ProtocolAborted => KeyRefreshError(Reason::Aborted(err)),
        err: IoError => KeyRefreshError(Reason::IoError(err)),
        err: Bug => KeyRefreshError(Reason::Bug(err)),
        err: Reason => KeyRefreshError(err),
    }
}

#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
enum Reason {
    /// Protocol was maliciously aborted by another party
    #[displaydoc("protocol was aborted by malicious party")]
    Aborted(#[cfg_attr(feature = "std", source)] ProtocolAborted),
    #[displaydoc("i/o error")]
    IoError(#[cfg_attr(feature = "std", source)] IoError),
    /// Bug occurred
    #[displaydoc("bug occurred")]
    Bug(#[cfg_attr(feature = "std", source)] Bug),
    /// Threshold key share passed to non-threshold refresh
    #[displaydoc("threshold key share is not supported by non-threshold key refresh")]
    NotThreshold,
}

impl From<ProtocolAborted> for Reason {
    fn from(err: ProtocolAborted) -> Self {
        Reason::Aborted(err)
    }
}

/// Error indicating that protocol was aborted by malicious party
#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
enum ProtocolAborted {
    #[displaydoc("party decommitment doesn't match commitment: {0:?}")]
    InvalidDecommitment(Vec<utils::AbortBlame>),
    #[displaydoc("party provided invalid masked share: {0:?}")]
    InvalidMaskedShare(Vec<utils::AbortBlame>),
    #[displaydoc("party provided invalid schnorr proof: {0:?}")]
    InvalidSchnorrProof(Vec<utils::AbortBlame>),
    #[displaydoc("round1 wasn't reliable")]
    Round1NotReliable(Vec<utils::AbortBlame>),
}

#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
enum Bug {
    #[displaydoc("resulting key share is not valid")]
    Invalid(#[cfg_attr(feature = "std", source)] InvalidCoreShare),
    #[displaydoc("unexpected zero value")]
    ZeroSecret,
    #[displaydoc("unexpected zero public share")]
    ZeroPublic,
}

macro_rules! make_factory {
    ($function:ident, $variant:ident) => {
        fn $function(parties: Vec<utils::AbortBlame>) -> Self {
            Self::$variant(parties)
        }
    };
}

impl ProtocolAborted {
    make_factory!(invalid_decommitment, InvalidDecommitment);
    make_factory!(invalid_masked_share, InvalidMaskedShare);
    make_factory!(invalid_schnorr_proof, InvalidSchnorrProof);
    make_factory!(round1_not_reliable, Round1NotReliable);
}
