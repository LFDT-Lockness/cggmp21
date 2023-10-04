### Correctness

This key share was checked to be valid and consistent. In order to
keep it valid and consistent, only immutable access to its fields is
provided. In case mutable access is needed, it can be converted into
dirty key share using [`.into_inner()`](Valid::into_inner) method.

