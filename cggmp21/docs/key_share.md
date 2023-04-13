Key share is obtained as output of [key refresh protocol](mod@crate::key_refresh).
It contains a [core share](IncompleteKeyShare) and auxiliary data required to
carry out signing.

Compared to the paper, we removed the El-Gamal private key as it's not used
for 3-round presigning, which is the only one we provide
