use cggmp21_tests::PrecomputedKeyShares;

lazy_static::lazy_static! {
    pub static ref CACHED_SHARES: PrecomputedKeyShares =
        PrecomputedKeyShares::from_str(include_str!("../../../test-data/precomputed_shares.json"))
            .unwrap();
}
