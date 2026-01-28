{
  craneLib,
  commonArgs,
  stdenv,
  ...
}:

craneLib.buildPackage (
  commonArgs
  // {
    pname = "gravity-kernel";
    version = "0.1.0";

    cargoExtraArgs = "--manifest-path src/kernel/Cargo.toml";

    nativeBuildInputs = (commonArgs.nativeBuildInputs or [ ]) ++ [
      stdenv.cc
    ];

    RUSTFLAGS = "-Clinker=clang -Clink-arg=--ld-path=ld.lld -Clink-arg=-nostdlib -Clink-arg=--target=aarch64-unknown-none-elf";
  }
)
