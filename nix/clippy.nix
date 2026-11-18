{
  lib,
  rustPlatform,
  clippy,
  pkg-config,
  zstd,
}:
let
  manifest = lib.importTOML ../Cargo.toml;
in
rustPlatform.buildRustPackage {
  pname = "strata-clippy";
  inherit (manifest.workspace.package) version;
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../crates
    ];
  };
  cargoLock.lockFile = ../Cargo.lock;
  nativeBuildInputs = [
    clippy
    pkg-config
  ];
  buildInputs = [ zstd ];
  buildPhase = ''
    runHook preBuild
    cargo clippy --offline --workspace --all-targets -- -D warnings
    runHook postBuild
  '';
  doCheck = false;
  installPhase = "touch $out";
}
