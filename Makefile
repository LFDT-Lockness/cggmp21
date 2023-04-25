.PHONY: docs docs-open

docs:
	RUSTDOCFLAGS="--html-in-header katex-header.html --cfg docsrs" cargo +nightly doc --no-deps

docs-open:
	RUSTDOCFLAGS="--html-in-header katex-header.html --cfg docsrs" cargo +nightly doc --no-deps --open

docs-private:
	RUSTDOCFLAGS="--html-in-header katex-header.html --cfg docsrs" cargo +nightly doc --no-deps --document-private-items
