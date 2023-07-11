.PHONY: docs docs-open docs-private readme readme-check

docs:
	RUSTDOCFLAGS="--html-in-header katex-header.html --cfg docsrs" cargo +nightly doc --no-deps

docs-open:
	RUSTDOCFLAGS="--html-in-header katex-header.html --cfg docsrs" cargo +nightly doc --no-deps --open

docs-private:
	RUSTDOCFLAGS="--html-in-header katex-header.html --cfg docsrs" cargo +nightly doc --no-deps --document-private-items

readme:
	cargo readme -i src/lib.rs -r cggmp21/ -t ../docs/README.tpl --no-indent-headings \
		| sed -E 's/(\/\*.+\*\/)/\1;/' \
		| sed -E '/^\[`.+`\]:/d' \
		| sed -E 's/\[`([^`]*)`\]/`\1`/g' \
		| sed -E 's/\[([^\]+)\]\([^)]+\)/\1/g' \
		| sed -E '/^#$$/d' \
		> README.md
