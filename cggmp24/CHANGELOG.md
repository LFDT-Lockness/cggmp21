# CGGMP24 releases

## v0.7.0

Changes:
* All protocols have been updated to follow the latest CGGMP24 paper revision.
* Change big integer backend to be abstract, selectable between rug and num-bigint [#13]

Breaking changes:
* The structure `cggmp24::key_share::AuxInfo` has been updated and consequently `cggmp24::KeyShare`
  have been affected.
  * Key shares and auxiliary data generated with previous library versions are not compatible and
    cannot be deserialized by this new version.
  * The core data within `cggmp24::IncompleteKeyShare` remains backward compatible and can be
    deserialized from older versions.

Please refer to the [migration manual](./../CGGMP21_MIGRATION.md) for detailed instructions on how
to upgrade your existing key share data.

# CGGMP21 releases

## v0.6.0
* Update `hd-wallet` dep to v0.6 [#120]

[#120]: https://github.com/LFDT-Lockness/cggmp21/pull/120

## v0.5.2
* Fix missing macros in `katex-header.html` (only affects rendered docs) [#122]

[#122]: https://github.com/LFDT-Lockness/cggmp21/pull/122

## v0.5.1
* Update `katex-header.html` injected into docs [#121]

[#121]: https://github.com/LFDT-Lockness/cggmp21/pull/121

## v0.5.0
* BREAKING: use `hd-wallet` crate for HD support instead of `slip-10` [#115]
* BREAKING: rename `hd-wallets` feature into `hd-wallet` [#115]
* Update `key-share` to v0.5
* Update `cggmp21-keygen` to v0.4

[#115]: https://github.com/LFDT-Lockness/cggmp21/pull/115

## v0.4.2
* Update links in the documentation and crate settings after moving the repo [#113]

[#113]: https://github.com/LFDT-Lockness/cggmp21/pull/113

## v0.4.1
* Take advantage of `#[udigest(as = ...)]` attribute [#106]

[#106]: https://github.com/LFDT-Lockness/cggmp21/pull/106

## v0.4.0
* security fix: derive challenges for zero-knowledge proof unambiguously
* Update `udigest` to v0.2
* Update `generic-ec` to v0.4
* Update `slip-10` to v0.4

## v0.3.0
* Provide sync API to carry out provided protocols [#100]
* Update `round-based` dep to `v0.3` [#100]
* Update `generic-ec`, `slip-10`, `paillier-zk` deps to latest version [#101]
* Optimize key share verification and signing using new features of `generic-ec` [#101]

[#100]: https://github.com/LFDT-Lockness/cggmp21/pull/100
[#101]: https://github.com/LFDT-Lockness/cggmp21/pull/101

## v0.2.1
* Bump key-share to `^0.2.3` [#99]

[#99]: https://github.com/LFDT-Lockness/cggmp21/pull/99

## v0.2.0
* Add support of HD wallets compatible with BIP-32 and SLIP-10 [#68],
  [#74], [#75]
* Restructure the library: move reusable structs and functionalities into separate
  sub-crates [#72], [#76], [#77], [#79]
* Move public info of the key share into separate struct `KeyInfo` [#80]
* Prohibit key shares with zero secret share or secret key [#82]
* Add specs and audit report [#70], [#85]

[#68]: https://github.com/LFDT-Lockness/cggmp21/pull/68
[#70]: https://github.com/LFDT-Lockness/cggmp01/pull/70
[#72]: https://github.com/LFDT-Lockness/cggmp21/pull/72
[#74]: https://github.com/LFDT-Lockness/cggmp21/pull/74
[#75]: https://github.com/LFDT-Lockness/cggmp21/pull/75
[#76]: https://github.com/LFDT-Lockness/cggmp21/pull/76
[#77]: https://github.com/LFDT-Lockness/cggmp21/pull/77
[#79]: https://github.com/LFDT-Lockness/cggmp21/pull/79
[#80]: https://github.com/LFDT-Lockness/cggmp21/pull/80
[#82]: https://github.com/LFDT-Lockness/cggmp21/pull/82
[#85]: https://github.com/LFDT-Lockness/cggmp51/pull/85

## v0.1.1
Minor release fixing docs compilation issues in [#69].

[#69]: https://github.com/LFDT-Lockness/cggmp21/pull/69

## v0.1.0

Initial release
