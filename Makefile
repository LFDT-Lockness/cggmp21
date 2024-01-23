.PHONY: docs docs-open docs-private readme readme-check

docs:
	RUSTDOCFLAGS="--html-in-header katex-header.html --cfg docsrs" cargo +nightly doc --all-features --no-deps

docs-open:
	RUSTDOCFLAGS="--html-in-header katex-header.html --cfg docsrs" cargo +nightly doc --all-features --no-deps --open

docs-private:
	RUSTDOCFLAGS="--html-in-header katex-header.html --cfg docsrs" cargo +nightly doc --all-features --no-deps --document-private-items

readme:
	cargo readme -i src/lib.rs -r cggmp21/ -t ../docs/README.tpl --no-indent-headings \
		| sed -E 's/(\/\*.+\*\/)/\1;/' \
		| sed -E '/^\[`.+`\]:/d' \
		| sed -E 's/\[`([^`]*)`\]/`\1`/g' \
		| perl -ne 's/(?<!!)\[([^\[]+?)\]\([^\(]+?\)/\1/g; print;' \
		| sed -E '/^#$$/d' \
		> README.md
