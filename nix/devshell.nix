{ pkgs, oresSopsShellHook }:
pkgs.mkShell {
  packages =
    with pkgs;
    [
      rustc
      cargo
      clippy
      rustfmt
      rust-analyzer
      pkg-config
      openssl
      pkgs.ores-sops
      sops
      age
      just
      python3
    ]
    ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [ pkgs.libiconv ];

  shellHook = oresSopsShellHook;
}
