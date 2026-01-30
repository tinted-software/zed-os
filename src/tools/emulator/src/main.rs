use aes::{Aes128, Aes192, Aes256};
use cbc::Decryptor;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use std::fs::File;
use std::io::Read;
use thiserror::Error;

mod cpu;
mod decoder;
mod hardware;
mod img3;
mod img4;

use cpu::ArmCpu;
use hardware::Hardware;

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

    // Decode ARM instructions
    let instructions = decoder::decode(&decrypted_payload).map_err(EmulatorError::Decoder)?;

    println!("Decoded {} instructions", instructions.len());

    // Run CPU emulator
    let mut cpu = ArmCpu::new();
    let mut hardware = Hardware::new();
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

    while step < 20_000_000 {
        let pc = cpu.pc;

        // Ensure instruction is decoded
        if !decoded_cache.contains_key(&pc) {
            let mut insn_bytes = [0u8; 4];
            let mut all_zero = true;
            for i in 0..4 {
                let b = cpu.memory.get(&(pc + i as u32)).copied().unwrap_or(0);
                if b != 0 {
                    all_zero = false;
                }
                insn_bytes[i] = b;
            }

            if all_zero {
                println!("  {}: PC at zero memory: 0x{:08x}", step, pc);
                break;
            }

            match decoder::decode(&insn_bytes) {
                Ok(insns) => {
                    if !insns.is_empty() {
                        decoded_cache.insert(pc, insns[0].clone());
                    } else {
                        println!("  {}: Failed to decode at 0x{:08x}", step, pc);
                        break;
                    }
                }
                Err(_) => {
                    println!("  {}: Decoder error at 0x{:08x}", step, pc);
                    break;
                }
            }
        }

        let insn = decoded_cache.get(&pc).unwrap().clone();

        if step < 100 || (step > 197420 && step < 197430) {
            println!(
                "  {}: PC=0x{:08x} T={} {} (cond: 0x{:x}) {:?}",
                step,
                cpu.pc,
                (cpu.cpsr >> 5) & 1,
                insn.mnemonic,
                insn.condition,
                insn.operands
            );
        }

        let old_pc = cpu.pc;
        cpu.pc_modified = false;
        if let Err(e) = cpu.execute(&insn) {
            println!("    Error at PC 0x{:08x}: {}", old_pc, e);
            break;
        }

        // Only increment PC if it wasn't changed by the instruction
        if !cpu.pc_modified {
            cpu.pc += 4;
        }

        step += 1;
    }

    println!("Final CPU state:");
    println!("  PC: 0x{:08x}", cpu.pc);
    println!("  R0: 0x{:08x}", cpu.registers[0]);
    println!("  R1: 0x{:08x}", cpu.registers[1]);
    println!("  R2: 0x{:08x}", cpu.registers[2]);

    Ok(())
}
