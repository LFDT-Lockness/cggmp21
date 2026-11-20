# CGGMP24 key refresh releases

## v0.7.0

* Refresh ends with an ACK round. A party replaces its old share only once it holds a Schnorr proof of every new share, echoing each proof as it accepts it. `round-based` is patched to the unreleased buffered-round API for that round. Round numbers of the existing messages are unchanged.
* With reliable broadcast enabled, refresh exchanges one more hash over the Round 3 Schnorr proofs, so honest parties agree on that broadcast. Round numbers of the existing messages are unchanged.
* Initial release: non-threshold (`n`-out-of-`n`) share refresh.
* Add threshold (`t`-out-of-`n`) share refresh.
