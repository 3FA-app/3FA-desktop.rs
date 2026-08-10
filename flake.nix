{
  description = "3FA desktop authenticator dev shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    flake-utils.url = "github:numtide/flake-utils";
    ores-sops.url = "github:ORESoftware/ores-sops";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      ores-sops,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ ores-sops.overlays.default ];
        };
      in
      {
        devShells.default = import ./nix/devshell.nix {
          inherit pkgs;
          oresSopsShellHook = ores-sops.lib.shellHook;
        };
      }
    );
}
