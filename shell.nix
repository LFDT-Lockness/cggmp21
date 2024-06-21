let # Rust
  pkgs = import <nixpkgs> { overlays = [ rustOverlay ]; };
  lib = pkgs.lib;
  isDarwin = pkgs.hostPlatform.isDarwin;

  rustVersion = "1.75.0";
  rustOverlay = import (builtins.fetchTarball "https://github.com/oxalica/rust-overlay/archive/master.tar.gz");

  rust = pkgs.rust-bin.stable.${rustVersion}.default.override {
    extensions = [
      "rust-src" # for rust-analyzer
    ];
  };
  # Latex
  tex = (pkgs.texlive.combine {
    inherit (pkgs.texlive) scheme-small
      collection-mathscience preprint amsmath;
  });

in pkgs.stdenv.mkDerivation {
  name = "signers-env";
  nativeBuildInputs = [
    rust pkgs.rust-analyzer tex pkgs.gnum4
  ];
  buildInputs = lib.optionals isDarwin [pkgs.darwin.apple_sdk.frameworks.Security];
}
