{
  description = "Strata: block-level backups to a NixOS/ZFS server";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f system nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAll (
        system: pkgs: {
          strata = pkgs.callPackage ./nix/package.nix { };
          default = self.packages.${system}.strata;
        }
      );

      nixosModules = {
        server = import ./nix/server.nix self;
        client = import ./nix/client.nix self;
      };

      checks = forAll (
        system: pkgs:
        let
          vmTest = file: pkgs.testers.runNixOSTest (import file self);
        in
        {
          package = self.packages.${system}.strata;
          clippy = pkgs.callPackage ./nix/clippy.nix { };
          fmt = pkgs.callPackage ./nix/fmt.nix { };
          vm-backup-restore = vmTest ./nix/tests/backup-restore.nix;
          vm-crash-resume = vmTest ./nix/tests/crash-resume.nix;
        }
      );

      formatter = forAll (system: pkgs: pkgs.nixfmt-rfc-style);
    };
}
