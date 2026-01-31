# iOS 5 Emulator

A minimal iOS 5 iBEC emulator built with Cranelift, RASN, and Thiserror.

## Components

### 1. ARMv7 Decoder (`decoder.rs`)
- Decodes ARM instructions from binary data
- Supports data processing, load/store, and branch instructions
- Handles conditional execution and various operand types
- Implements proper ARM instruction format parsing

### 2. IMG4 Parser (`img4.rs`) 
- Parses IMG4/IMG3 firmware containers
- Handles DFU file format detection
- ASN.1 decoding with RASN library
- Error handling with thiserror

### 3. CPU Emulator (`cpu.rs`)
- ARM CPU state simulation with 16 registers
- Memory management with HashMap-based storage
- Instruction execution engine
- Support for MOV, ADD, SUB, LDR, STR, B, BL, CMP instructions

### 4. Main Emulator (`main.rs`)
- File loading and parsing
- AES-256-CBC decryption support
- Integration of all components
- CPU state tracking and debugging output

## Features

- **Firmware Loading**: Loads iBEC.k48ap.RELEASE.dfu files
- **Format Detection**: Auto-detects DFU vs raw IMG4 format
- **Decryption**: AES-256-CBC with provided IV/Key
- **ARM Decoding**: Comprehensive ARMv7 instruction decoder
- **CPU Emulation**: Basic ARM CPU emulation with register tracking
- **JIT Ready**: Built with Cranelift for future JIT compilation

## Usage

```bash
cargo build --bin emulator
./target/debug/emulator
```

## Output

The emulator provides detailed output including:
- File loading statistics
- Decryption status
- Instruction count and details
- CPU execution trace
- Final register state

This provides a foundation for iOS 5 bootloader analysis and emulation.
