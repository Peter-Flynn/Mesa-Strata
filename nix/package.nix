{
  lib,
  rustPlatform,
  pkg-config,
  zfs,
  zstd,
}:
let
  manifest = lib.importTOML ../Cargo.toml;
in
rustPlatform.buildRustPackage {
  pname = "strata";
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

  nativeBuildInputs = [ pkg-config ];
  # libzfs_core and libnvpair for the `lzc` feature.
  buildInputs = [
    zfs
    zstd
  ];

  cargoBuildFlags = [
    "-p"
    "strata-zfsd"
    "-p"
    "strata-netd"
    "-p"
    "strata-client"
  ];
  buildFeatures = [
    "strata-zfsd/lzc"
    "strata-client/lzc"
  ];
  # The tests run against the fake ZFS, so they need neither libzfs_core nor a pool.
  checkFeatures = [ ];
  cargoTestFlags = [ "--workspace" ];

  meta = {
    description = "Block-level backups to a NixOS/ZFS server";
    license = lib.licenses.mit;
    mainProgram = "strata";
    platforms = lib.platforms.linux;
  };
}
