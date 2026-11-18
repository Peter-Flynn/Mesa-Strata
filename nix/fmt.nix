{
  lib,
  runCommand,
  rustfmt,
}:
let
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../rustfmt.toml
      ../crates
      ../fuzz/Cargo.toml
      ../fuzz/fuzz_targets
    ];
  };
in
runCommand "strata-fmt"
  {
    nativeBuildInputs = [ rustfmt ];
  }
  ''
    cd ${src}
    rustfmt --check --edition 2024 $(find crates fuzz -name '*.rs')
    touch $out
  ''
