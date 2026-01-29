# CLAUDE.md

This file provides guidance for interacting with the GravityOS codebase.

## Project Overview

GravityOS is a Rust-based operating system and kernel targeting ARM64 (aarch64-unknown-none-softfloat). It aims to run ios 5 ARMv7 userspace binaries.

## Build and Test

### Prerequisites

- Rust nightly
- QEMU (qemu-system-aarch64)

### Building the Kernel

```bash
cargo build --target aarch64-unknown-none-softfloat -p kernel
```

### Running the Kernel

```bash
cargo run -p gravity-setup
```

## Workspace Structure

- `kernel/` - Main kernel source code
- `libs/` - Shared libraries
- `tools/` - Utility tools
- `rootfs/` - Root filesystem
