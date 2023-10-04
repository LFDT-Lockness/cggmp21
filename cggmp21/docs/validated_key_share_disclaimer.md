##### CRT and multiexponent optimizations

[CRT parameters] and [multiexponentiation tables] are not checked for correctness
as there's no simple and/or efficient way to do so. If you have chosen to 
benefit from those optimizations, be aware that invalid/inconsistent data
may lead to unexpected and unverbose protocol termination and as well to
security breach.

[CRT parameters]: crate::key_refresh::GenericKeyRefreshBuilder::precompute_crt
[multiexponentiation tables]: crate::key_refresh::GenericKeyRefreshBuilder::precompute_multiexp_tables