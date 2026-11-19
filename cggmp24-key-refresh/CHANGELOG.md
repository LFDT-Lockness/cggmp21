# CGGMP24 key refresh releases

## v0.7.0

* With reliable broadcast enabled, refresh exchanges one more hash over the Round 3 Schnorr proofs, so honest parties agree on that broadcast. Round numbers of the existing messages are unchanged.
* Initial release: non-threshold (`n`-out-of-`n`) share refresh.
* Add threshold (`t`-out-of-`n`) share refresh.
