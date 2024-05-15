use alloc::boxed::Box;
use core::convert::Infallible;

use round_based::rounds_router::{
    errors::{self as router_error, CompleteRoundError},
    simple_store::RoundInputError,
};

mod std_error {
    #[cfg(feature = "std")]
    pub use std::error::Error as StdError;

    #[cfg(not(feature = "std"))]
    pub trait StdError: core::fmt::Display + core::fmt::Debug {}
    #[cfg(not(feature = "std"))]
    impl<E: core::fmt::Display + core::fmt::Debug> StdError for E {}
}
pub use std_error::StdError;

pub type BoxedError = Box<dyn StdError + Send + Sync>;

#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum IoError {
    #[displaydoc("send message")]
    SendMessage(#[cfg_attr(feature = "std", source)] BoxedError),
    #[displaydoc("receive message")]
    ReceiveMessage(#[cfg_attr(feature = "std", source)] BoxedError),
    #[displaydoc("got eof while recieving messages")]
    ReceiveMessageEof,
    #[displaydoc("route received message (possibly malicious behavior)")]
    RouteReceivedError(
        #[cfg_attr(feature = "std", source)]
        router_error::CompleteRoundError<RoundInputError, Infallible>,
    ),
}

impl IoError {
    pub fn send_message<E: StdError + Send + Sync + 'static>(err: E) -> Self {
        Self::SendMessage(Box::new(err))
    }

    pub fn receive_message<E: StdError + Send + Sync + 'static>(
        err: CompleteRoundError<RoundInputError, E>,
    ) -> Self {
        match err {
            CompleteRoundError::Io(router_error::IoError::Io(e)) => {
                Self::ReceiveMessage(Box::new(e))
            }
            CompleteRoundError::Io(router_error::IoError::UnexpectedEof) => Self::ReceiveMessageEof,

            CompleteRoundError::ProcessMessage(e) => {
                Self::RouteReceivedError(CompleteRoundError::ProcessMessage(e))
            }
            CompleteRoundError::Other(e) => Self::RouteReceivedError(CompleteRoundError::Other(e)),
        }
    }
}

macro_rules! impl_from {
    (impl From for $target:ty {
        $($var:ident: $ty:ty => $new:expr),+,
    }) => {$(
        impl From<$ty> for $target {
            fn from($var: $ty) -> Self {
                $new
            }
        }
    )+}
}

pub(crate) use impl_from;
