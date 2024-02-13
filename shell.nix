let # Rust
    rust_overlay = import (builtins.fetchTarball "https://github.com/oxalica/rust-overlay/archive/master.tar.gz");
    pkgs = import <nixpkgs> { overlays = [ rust_overlay ]; };
    rustVersion = "1.75.0";
    rust = pkgs.rust-bin.stable.${rustVersion}.default.override {
      extensions = [
        "rust-src" # for rust-analyzer
      ];
    };
    # Latex
    tex = (pkgs.texlive.combine {
      inherit (pkgs.texlive) scheme-small
        collection-mathscience preprint;
    });
    

in pkgs.stdenv.mkDerivation {
  name = "signers-env";
  nativeBuildInputs = [
    rust pkgs.rust-analyzer tex
  ];
  buildInputs = [];
}
