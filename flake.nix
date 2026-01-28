{
  description = "Gravity OS development environment";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    crane.url = "github:ipetkov/crane";
  };

  outputs =
    {
      self,
      nixpkgs,
      crane,
    }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "riscv64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      pkgsFor =
        system:
        import nixpkgs {
          inherit system;
        };
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          nativeCraneLib = crane.mkLib pkgs;

          pkgsCross = import nixpkgs {
            inherit system;
            crossSystem = {
              config = "aarch64-unknown-none-elf";
              useLLVM = true;
              linker = "lld";
              libc = null;
              rust.rustcTarget = "aarch64-unknown-none-softfloat";
            };
          };
          crossCraneLib = crane.mkLib pkgsCross;

          commonArgs = {
            src = self;
            strictDeps = true;
            doCheck = false;
          };

          callPackage = pkgs.lib.callPackageWith (
            pkgs
            // {
              commonArgs = commonArgs;
            }
          );
        in
        {
          kernel = callPackage ./src/kernel/package.nix {
            craneLib = crossCraneLib;
            stdenv = pkgsCross.stdenv;
          };

          dyld = callPackage ./src/lib/dyld/package.nix {
            craneLib = crossCraneLib;
            stdenv = pkgsCross.stdenv;
          };

          ipsw = callPackage ./src/tools/ipsw/package.nix {
            craneLib = nativeCraneLib;
          };

          gravity-setup = callPackage ./src/tools/gravity-setup/package.nix {
            craneLib = nativeCraneLib;
          };

          linker-wrapper = callPackage ./src/tools/linker-wrapper/package.nix {
            craneLib = nativeCraneLib;
          };

          vfdecrypt = callPackage ./src/lib/vfdecrypt/package.nix {
            craneLib = nativeCraneLib;
          };

          ipsw-downloader = callPackage ./src/lib/ipsw-downloader/package.nix {
            craneLib = nativeCraneLib;
          };

          hfsplus = callPackage ./src/lib/hfsplus/package.nix {
            craneLib = nativeCraneLib;
          };

          apple-dmg = callPackage ./src/lib/apple-dmg/package.nix {
            craneLib = nativeCraneLib;
          };

          default = self.packages.${system}.kernel;
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        with pkgs;
        {
          default = mkShell {
            nativeBuildInputs = [
              rustc
              cargo
              cargo-edit
              rustfmt
              rust-analyzer
              clippy
              qemu
              mtools
              pkg-config
              nixfmt
              pkg-config
              nix-output-monitor
              rust-bindgen
              watchman
              jujutsu
              gitMinimal
            ]
            ++ lib.optionals stdenv.isDarwin [
              darwin.apple_sdk.frameworks.Security
              darwin.apple_sdk.frameworks.SystemConfiguration
            ];

            buildInputs = [
              aws-lc
            ];

            OPENSSL_DIR = aws-lc.dev;
            OPENSSL_LIB_DIR = "${aws-lc}/lib";
          };
        }
      );

      checks = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          nativeCraneLib = crane.mkLib pkgs;
          pkgsCross = import nixpkgs {
            inherit system;
            crossSystem = {
              config = "aarch64-unknown-none-elf";
              useLLVM = true;
              linker = "lld";
              libc = null;
              rust.rustcTarget = "aarch64-unknown-none-softfloat";
            };
          };
          crossCraneLib = crane.mkLib pkgsCross;
          commonArgs = {
            src = self;
            strictDeps = true;
            doCheck = false;
            nativeBuildInputs = [
              pkgs.pkg-config
              pkgs.rust-bindgen
            ];
            buildInputs = [
              pkgs.aws-lc
            ];
            OPENSSL_DIR = pkgs.aws-lc.dev;
            OPENSSL_LIB_DIR = "${pkgs.aws-lc}/lib";
          };

          nativeArtifacts = nativeCraneLib.buildDepsOnly (
            commonArgs
            // {
              cargoExtraArgs = "--workspace --exclude kernel --exclude dyld";
            }
          );
        in
        {
          clippy = nativeCraneLib.cargoClippy (
            commonArgs
            // {
              cargoArtifacts = nativeArtifacts;
              cargoClippyExtraArgs = "--workspace --exclude kernel --exclude dyld --all-targets -- -D warnings";
            }
          );

          clippy-kernel = crossCraneLib.buildPackage (
            commonArgs
            // {
              pname = "clippy-kernel";
              version = "0.0.1";
              cargoExtraArgs = "--package kernel --package dyld";

              buildPhaseCargoCommand = ''
                SYSROOT=$(${pkgsCross.buildPackages.rustc}/bin/rustc --print sysroot)
                export RUSTFLAGS="-C linker=${pkgsCross.stdenv.cc.targetPrefix}cc -C linker-flavor=gcc -C link-arg=-fuse-ld=lld -C link-arg=-nostdlib --sysroot $SYSROOT"
                cargo clippy --package kernel --package dyld --target aarch64-unknown-none-softfloat -- -D warnings
              '';

              nativeBuildInputs = commonArgs.nativeBuildInputs ++ [
                pkgs.clippy
              ];
              installPhase = "touch $out";
              doCheck = false;
            }
          );
        }
      );

      apps = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          gravity-setup = self.packages.${system}.gravity-setup;
          kernel = self.packages.${system}.kernel;
        in
        {
          default = {
            type = "app";
            program = toString (
              pkgs.writeShellScript "run-gravity-os" ''
                export PATH="${
                  pkgs.lib.makeBinPath [
                    gravity-setup
                    pkgs.qemu
                    pkgs.openssl
                    pkgs.curl
                  ]
                }:$PATH"

                echo "Running gravity-setup..."
                gravity-setup --output disk.img --work-dir work

                echo "Running QEMU..."
                qemu-system-aarch64 \
                  -machine virt \
                  -cpu cortex-a57 \
                  -m 1024 \
                  -nographic \
                  -kernel ${kernel}/bin/kernel \
                  -drive file=disk.img,format=raw,if=none,id=drive0,cache=writeback \
                  -device virtio-blk-pci,drive=drive0,bootindex=0 \
                  -device virtio-rng-pci
              ''
            );
          };
        }
      );
    };
}
