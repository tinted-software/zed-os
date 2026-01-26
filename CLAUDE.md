# CLAUDE.md

This file provides guidance for interacting with the Zed OS codebase.

## Project Overview

Zed OS is an operating system built with the Zed Editor. It is a Rust-based kernel targeting ARM64 (aarch64-unknown-none-softfloat). It aims to run ios 5 ARMv7 userspace binaries.

## Build and Test

### Prerequisites

- Rust nightly toolchain with `aarch64-unknown-none-softfloat` target
- QEMU (qemu-system-aarch64) for emulation

### Building the Kernel

```bash
# Make the rootfs disk
cargo run -p make-disk

# Build the kernel
cargo build --package zedos-kernel --target aarch64-unknown-none-softfloat -Zbuild-std=core,alloc
```

### Running the Kernel

```bash
cargo run --package zedos-kernel --target aarch64-unknown-none-softfloat -Zbuild-std=core,alloc
```

## Workspace Structure

- `kernel/` - Main kernel source code
- `libs/` - Shared libraries
- `tools/` - Utility tools
- `rootfs/` - Root filesystem
