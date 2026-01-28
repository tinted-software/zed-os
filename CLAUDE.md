# CLAUDE.md

This file provides guidance for interacting with the Zed OS codebase.

## Project Overview

Zed OS is an operating system built with the Zed Editor. It is a Rust-based kernel targeting ARM64 (aarch64-unknown-none-softfloat). It aims to run ios 5 ARMv7 userspace binaries.

## Build and Test

### Prerequisites

- Rust nightly toolchain with `aarch64-unknown-none-softfloat` target
- QEMU (qemu-system-aarch64) for emulation
- Buck2 and Reindeer

### Building the Kernel

```bash
# Build the kernel
buck2 build //src/kernel:kernel --target-platforms //platforms:kernel-arm64
```

### Running the Kernel

TODO.

## Workspace Structure

- `kernel/` - Main kernel source code
- `libs/` - Shared libraries
- `tools/` - Utility tools
- `rootfs/` - Root filesystem
