.PHONY: docs docs-open docs-private readme readme-check

docs:
	RUSTDOCFLAGS="--html-in-header katex-header.html --cfg docsrs" cargo +nightly doc --all-features --no-deps

docs-open:
	RUSTDOCFLAGS="--html-in-header katex-header.html --cfg docsrs" cargo +nightly doc --all-features --no-deps --open

docs-private:
	RUSTDOCFLAGS="--html-in-header katex-header.html --cfg docsrs" cargo +nightly doc --all-features --no-deps --document-private-items

readme:
	cargo rdme -w cggmp21 -r README.md && \
	cat README.md \
		| sed -E 's/(\/\*.+\*\/)/\1;/' \
		| sed -E '/^\[`.+`\]:/d' \
		| sed -E 's/\[`([^`]*)`\]\(.+?\)/`\1`/g' \
		| sed -E 's/\[`([^`]*)`\]/`\1`/g' \
		| perl -ne 's/(?<!!)\[([^\[]+?)\]\([^\(]+?\)/\1/g; print;' \
		| sed -E '/^#$$/d' \
		| sed -e '/<!-- TOC -->/{r docs/toc-cggmp21.md' -e 'd}' \
		> README-2.md && \
	mv README-2.md README.md

toc-cggmp21:
	echo '<!-- TOC STARTS -->' > docs/toc-cggmp21.md
	echo >> docs/toc-cggmp21.md
	markdown-toc --no-firsth1 - < README.md >> docs/toc-cggmp21.md
	echo >> docs/toc-cggmp21.md
	echo >> docs/toc-cggmp21.md
	echo '<!-- TOC ENDS -->' >> docs/toc-cggmp21.md
