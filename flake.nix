{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  };

  outputs =
    {
      nixpkgs,
      ...
    }:
    let
      eachSystem = nixpkgs.lib.genAttrs [
        "x86_64-linux"
        "aarch64-linux"
        "riscv64-linux"
      ];
    in
    {
      devShells = eachSystem (
        system: with nixpkgs.legacyPackages.${system}; {
          default =
            (mkShell.override {
              stdenv = useWildLinker clangStdenv;
            })
              rec {
                nativeBuildInputs = [
                  pyrefly
                  (rustup.overrideAttrs (old: {
                    doCheck = false;
                  }))
                  pkg-config
                  nixfmt-rfc-style
                  nil
                  python3
                  wild
                ];

                buildInputs = [
                  wayland
                  alsa-lib
                  libxkbcommon
                  vulkan-loader
                ];

                RUSTC_BOOTSTRAP = 1;
                LD_LIBRARY_PATH = lib.makeLibraryPath buildInputs;
              };
        }
      );
    };
}
