use aes::{Aes128, Aes192, Aes256};
use cbc::Decryptor;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use std::fs::File;
use std::io::Read;
use std::io::Write;
use thiserror::Error;

mod cpu;
mod decoder;
mod hardware;
mod img3;
mod img4;
mod jit;

use cpu::ArmCpu;
use hardware::Hardware;

extern "C" fn jit_read_helper(cpu_ptr: *mut ArmCpu, addr: u32) -> u32 {
    let cpu = unsafe { &mut *cpu_ptr };
    cpu.read_memory(addr).unwrap_or(0)
}

extern "C" fn jit_write_helper(cpu_ptr: *mut ArmCpu, addr: u32, val: u32) {
    let cpu = unsafe { &mut *cpu_ptr };
    let _ = cpu.write_memory(addr, val);
}

#[derive(Error, Debug)]
pub enum EmulatorError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("File not found: {0}")]
    FileNotFound(String),
    #[error("IMG3 error: {0}")]
    Img3(#[from] img3::Img3Error),
    #[error("Decryption error: {0}")]
    Decryption(String),
    #[error("Decoder error: {0}")]
    Decoder(String),
    #[error("CPU error: {0}")]
    Cpu(#[from] cpu::CpuError),
}

pub type Result<T> = std::result::Result<T, EmulatorError>;

fn decrypt_payload(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let mut buf = data.to_vec();

    match key.len() {
        16 => {
            let mut cipher = Decryptor::<Aes128>::new_from_slices(key, iv)
                .map_err(|e| EmulatorError::Decryption(e.to_string()))?;
            for chunk in buf.chunks_mut(16) {
                if chunk.len() == 16 {
                    cipher.decrypt_block_mut(chunk.into());
                }
            }
        }
        24 => {
            let mut cipher = Decryptor::<Aes192>::new_from_slices(key, iv)
                .map_err(|e| EmulatorError::Decryption(e.to_string()))?;
            for chunk in buf.chunks_mut(16) {
                if chunk.len() == 16 {
                    cipher.decrypt_block_mut(chunk.into());
                }
            }
        }
        32 => {
            let mut cipher = Decryptor::<Aes256>::new_from_slices(key, iv)
                .map_err(|e| EmulatorError::Decryption(e.to_string()))?;
            for chunk in buf.chunks_mut(16) {
                if chunk.len() == 16 {
                    cipher.decrypt_block_mut(chunk.into());
                }
            }
        }
        _ => {
            return Err(EmulatorError::Decryption(format!(
                "Unsupported key size: {}",
                key.len()
            )));
        }
    }

    Ok(buf)
}

fn main() -> Result<()> {
    println!("iOS 5 iBEC Emulator");
    println!("==================");

    let ibec_path = "work/Firmware/dfu/iBEC.k48ap.RELEASE.dfu";
    let mut ibec_file =
        File::open(ibec_path).map_err(|_| EmulatorError::FileNotFound(ibec_path.to_string()))?;
    let mut ibec_data = Vec::new();
    ibec_file.read_to_end(&mut ibec_data)?;

    println!("Loaded {} bytes from {}", ibec_data.len(), ibec_path);

    // Parse as IMG3 file
    let img3 = img3::Img3File::parse(&ibec_data)?;

    println!("IMG3 Header:");
    let magic = img3.header.magic;
    let full_size = img3.header.full_size;
    let ident = img3.header.ident;
    println!("  Magic: 0x{:08x}", magic);
    println!("  Full size: {}", full_size);
    println!("  Ident: 0x{:08x}", ident);
    println!("  Tags: {}", img3.tags.len());

    // List all tags
    for (i, tag) in img3.tags.iter().enumerate() {
        let bytes = tag.magic.to_le_bytes();
        let tag_name = std::str::from_utf8(&bytes).unwrap_or("????");
        print!(
            "  Tag {}: {} (0x{:08x}) - {} bytes",
            i,
            tag_name,
            tag.magic,
            tag.data.len()
        );
        if tag_name == "GABK" {
            print!(": {}", hex::encode(&tag.data));
        }
        if tag_name == "SREV" {
            let s = std::str::from_utf8(&tag.data).unwrap_or("????");
            print!(": {}", s);
        }
        println!();
    }

    // Get encrypted data section
    let encrypted_data = img3
        .get_data_section()
        .ok_or_else(|| EmulatorError::Decoder("DATA section not found".to_string()))?;

    println!("Encrypted data size: {} bytes", encrypted_data.len());

    // Use provided IV and key
    let iv = hex::decode("bde7b0d5cf7861479d81eb23f99d2e9e").unwrap();
    let key =
        hex::decode("1ba1f38e6a5b4841c1716c11acae9ee0fb471e50362a3b0dd8d98019f174a2f2").unwrap();

    // Decrypt payload
    let decrypted_payload = decrypt_payload(encrypted_data, &key, &iv)?;
    println!("Successfully decrypted payload");
    std::fs::write("work/Firmware/dfu/iBEC_decrypted.bin", &decrypted_payload).unwrap();
    println!("Payload size: {} bytes", decrypted_payload.len());

    // Hexdump start of payload
    for i in (0..(0x400.min(decrypted_payload.len()))).step_by(16) {
        print!("{:08x}: ", 0x80000000 + i as u32);
        for j in 0..16 {
            if i + j < decrypted_payload.len() {
                print!("{:02x} ", decrypted_payload[i + j]);
            } else {
                print!("   ");
            }
        }
        print!(" |");
        for j in 0..16 {
            if i + j < decrypted_payload.len() {
                let c = decrypted_payload[i + j];
                if c >= 0x20 && c <= 0x7E {
                    print!("{}", c as char);
                } else {
                    print!(".");
                }
            }
        }
        println!("|");
    }

    // Check memory around PC+8+24 = 0x80000000+8+24 = 0x80000020
    let check_addr = 0x80000020u32 as i32;
    println!(
        "Memory at 0x{:08x}: {:02x?}",
        check_addr,
        &decrypted_payload[0x20..0x24]
    );

    // Check memory at 0x108 where LDR will actually read from
    println!(
        "Memory at 0x80000108: {:02x?}",
        &decrypted_payload[0x108..0x10c]
    );

    // Check instruction at 0x8000000c (the branch)
    let branch_offset = 0x0c;
    println!(
        "Branch instruction at 0x8000000c: {:02x?}",
        &decrypted_payload[branch_offset..branch_offset + 4]
    );

    // Check the LDR instruction at 0x80000024
    let ldr_offset = 0x24;
    println!(
        "LDR instruction at 0x80000024: {:02x?}",
        &decrypted_payload[ldr_offset..ldr_offset + 4]
    );

    // Check memory at relocation entry point (0x9c8)
    println!("Relocated code area hexdump (starting at 0x9c8):");
    for i in (0x9c8..(0x9c8 + 0x40.min(decrypted_payload.len() - 0x9c8))).step_by(16) {
        print!("{:08x}: ", 0x80000000 + i as u32);
        for j in 0..16 {
            print!("{:02x} ", decrypted_payload[i + j]);
        }
        println!();
    }

    println!("Literal pool dump at 0x80000300:");
    for i in (0x300..0x340).step_by(16) {
        print!("{:08x}: ", 0x80000000 + i as u32);
        for j in 0..16 {
            print!("{:02x} ", decrypted_payload[i + j]);
        }
        println!();
    }

    // Run CPU emulator
    let mut cpu = ArmCpu::new();
    let hardware = Hardware::new();
    cpu.load_memory(0x80000000, &decrypted_payload);
    cpu.set_hardware(hardware);
    cpu.pc = 0x80000000;

    // Initialize some registers with reasonable values
    cpu.registers[13] = 0x80010000; // Stack pointer
    cpu.registers[14] = 0x80000004; // Link register

    // Simulate NVRAM initialization for iBEC
    cpu.registers[0] = 0x84000000; // NVRAM base
    cpu.registers[1] = 0x85000000; // Boot args
    cpu.registers[2] = 0x86000000; // Kernel args

    println!("Running CPU emulation...");
    let mut step = 0;
    let mut decoded_cache: std::collections::HashMap<u32, decoder::Instruction> =
        std::collections::HashMap::new();

    let mut jit = jit::Jit::new();
    let mut block_sizes: std::collections::HashMap<u32, u64> = std::collections::HashMap::new();
    let mut last_watch_val = 0;
    let mut compilations = 0;

    while step < 10_000_000_000 {
        let pc = cpu.pc;

        // 1. Try JIT
        if let Some(code_ptr) = jit.get_block(pc) {
            let func: extern "C" fn(
                *mut ArmCpu,
                *mut u32,
                *mut u8,
                *mut u32,
                extern "C" fn(*mut ArmCpu, u32) -> u32,
                extern "C" fn(*mut ArmCpu, u32, u32),
            ) = unsafe { std::mem::transmute(code_ptr) };
            func(
                &mut cpu,
                cpu.registers.as_mut_ptr(),
                cpu.ram.as_mut_ptr(),
                &mut cpu.cpsr,
                jit_read_helper,
                jit_write_helper,
            );
            cpu.pc = cpu.registers[15];
            let size = *block_sizes.get(&pc).unwrap_or(&1);
            step += size;
            if step % 1000000 < size {
                eprintln!(
                    "[Step {}] PC=0x{:08x}, JIT cache: {}",
                    step, cpu.pc, compilations
                );
                eprintln!(
                    "Registers: R0={:08x} R1={:08x} R2={:08x} R3={:08x} SP={:08x} LR={:08x} CPSR={:08x}",
                    cpu.registers[0],
                    cpu.registers[1],
                    cpu.registers[2],
                    cpu.registers[3],
                    cpu.registers[13],
                    cpu.registers[14],
                    cpu.cpsr
                );
            }
            continue;
        }

        // 2. Block discovery and compilation if not in cache
        let mut block_insns = Vec::new();
        let mut curr_pc = pc;
        for _ in 0..100 {
            // Ensure instruction is decoded
            if !decoded_cache.contains_key(&curr_pc) {
                let mut insn_bytes = [0u8; 4];
                for i in 0..4 {
                    insn_bytes[i] = cpu.memory.get(&(curr_pc + i as u32)).copied().unwrap_or(0);
                }
                let is_thumb = (cpu.cpsr >> 5) & 1 != 0;
                if let Ok(insns) = decoder::decode(&insn_bytes, is_thumb) {
                    if !insns.is_empty() {
                        decoded_cache.insert(curr_pc, insns[0].clone());
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
            let insn = decoded_cache.get(&curr_pc).unwrap().clone();
            block_insns.push((curr_pc, insn.clone()));

            // Basic block terminator check
            let m = insn.mnemonic.as_str();
            if m == "b"
                || m == "bl"
                || m == "bx"
                || m == "blx"
                || m == "cbz"
                || m == "cbnz"
                || m == "it"
                || m == "svc"
                || m == "eret"
                || m == "pop"
                || m == "pop.w"
                || insn
                    .operands
                    .iter()
                    .any(|o| matches!(o, decoder::Operand::Register(15)))
            {
                break;
            }
            curr_pc += insn.size as u32;
        }

        let is_thumb = (cpu.cpsr >> 5) & 1 != 0;
        if let Some(code_ptr) = jit.compile_block(pc, &block_insns, is_thumb) {
            let func: extern "C" fn(
                *mut ArmCpu,
                *mut u32,
                *mut u8,
                *mut u32,
                extern "C" fn(*mut ArmCpu, u32) -> u32,
                extern "C" fn(*mut ArmCpu, u32, u32),
            ) = unsafe { std::mem::transmute(code_ptr) };
            func(
                &mut cpu,
                cpu.registers.as_mut_ptr(),
                cpu.ram.as_mut_ptr(),
                &mut cpu.cpsr,
                jit_read_helper,
                jit_write_helper,
            );
            cpu.pc = cpu.registers[15];
            block_sizes.insert(pc, block_insns.len() as u64);
            step += block_insns.len() as u64;
            compilations += 1;
            continue;
        }

        // 3. Fallback to interpreter
        if let Some(insn) = decoded_cache.get(&pc) {
            let insn = insn.clone();
            let old_pc = cpu.pc;
            cpu.pc_modified = false;
            if let Err(e) = cpu.execute(&insn) {
                println!("    Error at PC 0x{:08x}: {}", old_pc, e);
                break;
            }
            if !cpu.pc_modified {
                cpu.pc += insn.size as u32;
            }
            step += 1;
        } else {
            println!("  Failed to decode at 0x{:08x}", pc);
            break;
        }

        // Minimal UART hook via memory watch
        if let Ok(v0) = cpu.read_memory(0x5FFF7F24) {
            if v0 != last_watch_val && v0 != 0 {
                if v0 >= 0x20 && v0 <= 0x7E {
                    print!("{}", v0 as u8 as char);
                } else if v0 == 0x0a || v0 == 0x0d {
                    if v0 == 0x0a {
                        println!();
                    }
                }
                let _ = std::io::stdout().flush();
                last_watch_val = v0;
            }
        }

        if step % 10_000 == 0 {
            eprintln!(
                "[Step {}] PC=0x{:08x}, JIT cache: {}",
                step, cpu.pc, compilations
            );
        }
    }

    println!("Final CPU state:");
    cpu.dump_registers();
    Ok(())
}
