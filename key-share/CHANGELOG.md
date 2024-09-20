# Changelog

## v0.4.3
* Update links in the documentation and crate settings after moving the repo [#113]

[#113]: https://github.com/LFDT-Lockness/cggmp21/pull/113

## v0.4.2
* Take advantage of `#[udigest(as = ...)]` attribute [#106]

[#106]: https://github.com/LFDT-Lockness/cggmp21/pull/106

## v0.4.1
* Add HD-related methods to `DirtyKeyInfo` [#104]

[#104]: https://github.com/LFDT-Lockness/cggmp21/pull/104

## v0.4.0
* Update `udigest` to v0.2
* Update `generic-ec` to v0.4
* Update `slip-10` to v0.4

## v0.3.0
* Update `generic-ec` and `slip-10` deps to latest version [#101]
* Optimize key share verification using new features of `generic-ec` [#101]

[#101]: https://github.com/LFDT-Lockness/cggmp21/pull/101

## v0.2.3
* Reduce size of serialized key share [#96]

[#96]: https://github.com/LFDT-Lockness/cggmp21/pull/96

## v0.2.2
* Add `no_std` support [#92]

[#92]: https://github.com/LFDT-Lockness/cggmp21/pull/92

## v0.2.1
* Fix key share (de)serialization issue [#93]
* Add a notice about the serialization to key share docs [#91]

[#91]: https://github.com/LFDT-Lockness/cggmp21/pull/91
[#93]: https://github.com/LFDT-Lockness/cggmp21/pull/93

## v0.2.0
**YANKED**: this release is yanked because it had an issue with key share (de)serialization
that was addressed in v0.2.1

* Add support of HD wallets compatible with BIP-32 and SLIP-10 [#68],
  [#74], [#75]
* Prohibit key shares with zero secret share or secret key [#82]

[#68]: https://github.com/LFDT-Lockness/cggmp21/pull/68
[#74]: https://github.com/LFDT-Lockness/cggmp21/pull/74
[#75]: https://github.com/LFDT-Lockness/cggmp21/pull/75
[#82]: https://github.com/LFDT-Lockness/cggmp21/pull/82

## v0.1.0
**YANKED**: this release is yanked because it had an issue with key share (de)serialization
that was addressed in v0.2.1

Initial release
