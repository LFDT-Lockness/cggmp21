//! Fixes serde serialization of the key share
//!
//! This module contains structs that help us implementing `serde::{Serialize, Deserialize}`
//! for [`crate::DirtyCoreKeyShare`].
//!
//! Context: we used to have key share struct flatten, with all DirtyKeyInfo fields being
//! right in the key share. However, at some point, we've decided to move all public common
//! fields into a separate structure. In order to keep serialization format compatible,
//! we used `#[serde(flatten)]` attribute, to make on-wire data appear like all the fields
//! are still in the same struct. It turned out, that `#[serde(flatten)]` is buggy, and,
//! specifically, it does not preserve `is_human_readable` flag, which broke (de)serialization
//! code and compatibility with old key shares.
//!
//! See the issue for more details on the `serde` problem: <https://github.com/serde-rs/serde/issues/2704>
//!
//! Until the issue in `serde` crate is addressed, we have to use a workaround in this module.
//! We basically reimplement `flatten` attribute manually at the cost of extra allocations.

use generic_ec::{serde::CurveName, Curve, NonZero, Point, SecretScalar};
use serde_with::As;

macro_rules! core_key_share {
    ($($(#[$attr:meta])*pub $field:ident: $ty:ty),+$(,)?) => {
        pub mod ser {
            use super::*;

            #[derive(serde::Serialize)]
            #[serde(bound = "")]
            pub struct CoreKeyShare<'a, E: Curve> {$(
                $(#[$attr])*
                pub $field: &'a $ty,
            )+}
        }
        pub mod de {
            use super::*;

            #[derive(serde::Deserialize)]
            #[serde(bound = "")]
            pub struct CoreKeyShare<E: Curve> {$(
                $(#[$attr])*
                pub $field: $ty,
            )+}
        }
    };
}

core_key_share! {
    pub curve: CurveName<E>,
    pub i: u16,
    #[serde(with = "As::<generic_ec::serde::Compact>")]
    pub shared_public_key: NonZero<Point<E>>,
    #[serde(with = "As::<Vec<generic_ec::serde::Compact>>")]
    pub public_shares: Vec<NonZero<Point<E>>>,
    pub vss_setup: Option<crate::VssSetup<E>>,
    #[cfg(feature = "hd-wallets")]
    #[cfg_attr(
        feature = "serde",
        serde(default),
        serde(with = "As::<Option<crate::utils::HexOrBin>>")
    )]
    pub chain_code: Option<slip_10::ChainCode>,
    #[serde(with = "As::<generic_ec::serde::Compact>")]
    pub x: NonZero<SecretScalar<E>>,
}
