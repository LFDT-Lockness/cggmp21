# Changelog

## v0.3.0
* Provide sync API to carry out provided protocols [#100]
* Update `round-based` dep to `v0.3` [#100]
* Update `generic-ec`, `slip-10`, `paillier-zk` deps to latest version [#101]
* Optimize key share verification and signing using new features of `generic-ec` [#101]

[#100]: https://github.com/dfns/cggmp21/pull/100
[#101]: https://github.com/dfns/cggmp21/pull/101

## v0.2.1
* Bump key-share to `^0.2.3` [#99]

[#99]: https://github.com/dfns/cggmp21/pull/99

## v0.2.0
* Add support of HD wallets compatible with BIP-32 and SLIP-10 [#68],
  [#74], [#75]
* Restructure the library: move reusable structs and functionalities into separate
  sub-crates [#72], [#76], [#77], [#79]
* Move public info of the key share into separate struct `KeyInfo` [#80]
* Prohibit key shares with zero secret share or secret key [#82]
* Add specs and audit report [#70], [#85]

[#68]: https://github.com/dfns/cggmp21/pull/68
[#70]: https://github.com/dfns/cggmp01/pull/70
[#72]: https://github.com/dfns/cggmp21/pull/72
[#74]: https://github.com/dfns/cggmp21/pull/74
[#75]: https://github.com/dfns/cggmp21/pull/75
[#76]: https://github.com/dfns/cggmp21/pull/76
[#77]: https://github.com/dfns/cggmp21/pull/77
[#79]: https://github.com/dfns/cggmp21/pull/79
[#80]: https://github.com/dfns/cggmp21/pull/80
[#82]: https://github.com/dfns/cggmp21/pull/82
[#85]: https://github.com/dfns/cggmp51/pull/85

## v0.1.1
Minor release fixing docs compilation issues in [#69].

[#69]: https://github.com/dfns/cggmp21/pull/69

## v0.1.0

Initial release
