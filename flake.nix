{
  description = "herdr API over iroh, with a stdio MCP server";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    crane.url = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      crane,
      flake-utils,
      rust-overlay,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ rust-overlay.overlays.default ];
        pkgs = import nixpkgs { inherit system overlays; };
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [
            "rust-src"
            "clippy"
            "rustfmt"
          ];
        };
        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;
        src = craneLib.cleanCargoSource ./.;
        commonArgs = {
          inherit src;
          strictDeps = true;
        };
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;
        herdr-iroh = craneLib.buildPackage (
          commonArgs
          // {
            inherit cargoArtifacts;
            pname = "herdr-iroh";
            doCheck = true;
            meta = {
              mainProgram = "herdr-iroh";
              description = "Relay a local herdr socket over iroh and drive it from MCP";
              license = pkgs.lib.licenses.asl20;
            };
          }
        );
      in
      {
        checks = {
          inherit herdr-iroh;
        };
        packages = {
          inherit herdr-iroh;
          default = herdr-iroh;
        };
        devShells.default = craneLib.devShell {
          inputsFrom = [ herdr-iroh ];
          packages = [ rustToolchain ];
        };
      }
    )
    // {
      nixosModules.herdr-iroh =
        { pkgs, lib, ... }:
        {
          imports = [ ./nix/module.nix ];
          services.herdr-iroh.package = lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        };
    };
}
