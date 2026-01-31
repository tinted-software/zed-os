use crate::decoder::{Instruction, Operand};
use crate::hardware::Hardware;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CpuError {
    #[error("Invalid register: {0}")]
    InvalidRegister(u8),
    #[error("Memory access error at 0x{0:x}")]
    MemoryAccess(u32),
    #[error("Unsupported instruction: {0}")]
    UnsupportedInstruction(String),
}

pub type Result<T> = std::result::Result<T, CpuError>;

pub struct ArmCpu {
    pub registers: [u32; 16],
    pub memory: HashMap<u32, u8>,
    pub ram: Vec<u8>, // 256MB of primary RAM
    pub pc: u32,
    pub cpsr: u32,
    pub hardware: Option<Hardware>,
    pub pc_modified: bool,
    pub it_state: u8,
}

impl ArmCpu {
    pub fn new() -> Self {
        Self {
            registers: [0; 16],
            memory: HashMap::new(),
            ram: vec![0u8; 256 * 1024 * 1024],
            pc: 0,
            cpsr: 0,
            hardware: None,
            pc_modified: false,
            it_state: 0,
        }
    }

    pub fn set_hardware(&mut self, hardware: Hardware) {
        self.hardware = Some(hardware);
    }

    pub fn load_memory(&mut self, addr: u32, data: &[u8]) {
        for (i, &byte) in data.iter().enumerate() {
            let curr_addr = addr + i as u32;
            self.memory.insert(curr_addr, byte);

            // Also load into fast RAM if it's in a RAM range
            // Ranges: 0x40000000..0x48000000 and 0x80000000..0x88000000
            if (curr_addr >= 0x40000000 && curr_addr < 0x50000000)
                || (curr_addr >= 0x80000000 && curr_addr < 0x90000000)
            {
                let offset = (curr_addr & 0x0FFFFFFF) as usize;
                if offset < self.ram.len() {
                    self.ram[offset] = byte;
                }
            }
        }
    }

    pub fn get_reg(&self, reg: u8) -> u32 {
        if reg == 15 {
            let is_thumb = (self.cpsr >> 5) & 1 != 0;
            if is_thumb {
                self.pc.wrapping_add(4)
            } else {
                self.pc.wrapping_add(8)
            }
        } else {
            self.registers[reg as usize]
        }
    }

    pub fn get_reg_dp(&self, reg: u8) -> u32 {
        if reg == 15 {
            let is_thumb = (self.cpsr >> 5) & 1 != 0;
            if is_thumb {
                (self.pc.wrapping_add(4)) & !3
            } else {
                self.pc.wrapping_add(8)
            }
        } else {
            self.registers[reg as usize]
        }
    }

    pub fn dump_registers(&self) {
        println!("  PC: 0x{:08x}", self.pc);
        for i in 0..16 {
            print!("  R{:02}: 0x{:08x}", i, self.registers[i]);
            if (i + 1) % 4 == 0 {
                println!();
            }
        }
        println!("  CPSR: 0x{:08x}", self.cpsr);
    }

    pub fn set_reg(&mut self, reg: u8, val: u32) {
        if reg == 15 {
            self.pc = val;
            self.pc_modified = true;
        } else {
            self.registers[reg as usize] = val;
        }
    }

    fn get_mem_addr(&mut self, instruction: &Instruction, op_idx: usize) -> Result<u32> {
        if let Operand::Memory(base_reg, offset) = &instruction.operands[op_idx] {
            let base_val = self.get_reg_dp(*base_reg);
            let mut offset_val = *offset as u32;

            if instruction.operands.len() > op_idx + 1 {
                match &instruction.operands[op_idx + 1] {
                    Operand::Register(rm) => {
                        offset_val = self.get_reg_dp(*rm);
                    }
                    Operand::Shift(rm, type_, amount) => {
                        let val = self.get_reg_dp(*rm);
                        let amt = *amount as u32;
                        offset_val = match type_ {
                            0 => val.wrapping_shl(amt),
                            1 => val.wrapping_shr(amt),
                            2 => (val as i32).wrapping_shr(amt) as u32,
                            3 => val.rotate_right(amt),
                            _ => val,
                        };
                    }
                    _ => {}
                }
            }

            let bits = if instruction.operands.len() > op_idx + 1 {
                match instruction.operands.last() {
                    Some(Operand::Immediate(b)) => *b as u8,
                    _ => 0b10, // P=1, W=0
                }
            } else {
                0b10
            };

            let p = (bits >> 1) & 1;
            let w = bits & 1;

            let addr = if p == 1 {
                base_val.wrapping_add(offset_val)
            } else {
                base_val
            };

            if w == 1 {
                let next_base = if p == 1 {
                    addr
                } else {
                    base_val.wrapping_add(offset_val)
                };
                self.set_reg(*base_reg, next_base);
            }

            return Ok(addr);
        }
        Err(CpuError::UnsupportedInstruction(
            "Invalid memory operand".to_string(),
        ))
    }

    pub fn read_memory(&self, addr: u32) -> Result<u32> {
        // NVRAM/Environment variables (common iBEC addresses)
        match addr {
            // NVRAM base addresses - simulate boot environment
            0x84000000..=0x84000FFF => return Ok(0x626F6F74), // "boot"
            0x85000000..=0x85000FFF => return Ok(0x61726773), // "args"
            0x86000000..=0x86000FFF => return Ok(0x6B65726E), // "kern"
            0x87000000..=0x87000FFF => return Ok(0x64656275), // "debu"
            // Boot flags and status
            0x88000000..=0x88000FFF => return Ok(0x1), // Boot status
            0x89000000..=0x89000FFF => return Ok(0x0), // Debug flags
            _ => {}
        }
        // Check hardware peripherals first
        if let Some(ref hw) = self.hardware {
            if let Some(val) = hw.read(addr) {
                return Ok(val);
            }
        }

        // Fast RAM access (map everything to first 256MB via mask 0x0FFFFFFF)
        let ram_offset = (addr & 0x0FFFFFFF) as usize;
        if ram_offset + 3 < self.ram.len() {
            let val = u32::from_le_bytes([
                self.ram[ram_offset],
                self.ram[ram_offset + 1],
                self.ram[ram_offset + 2],
                self.ram[ram_offset + 3],
            ]);
            return Ok(val);
        }

        let mut value = 0u32;
        for i in 0..4 {
            if let Some(&byte) = self.memory.get(&(addr + i)) {
                value |= (byte as u32) << (i * 8);
            } else {
                return Ok(0);
            }
        }
        Ok(value)
    }

    pub fn write_memory(&mut self, addr: u32, value: u32) -> Result<()> {
        // Check hardware peripherals
        if let Some(ref mut hw) = self.hardware {
            if hw.write(addr, value) {
                return Ok(());
            }
        }

        let ram_offset = (addr & 0x0FFFFFFF) as usize;
        if ram_offset + 3 < self.ram.len() {
            let bytes = value.to_le_bytes();
            self.ram[ram_offset] = bytes[0];
            self.ram[ram_offset + 1] = bytes[1];
            self.ram[ram_offset + 2] = bytes[2];
            self.ram[ram_offset + 3] = bytes[3];
            return Ok(());
        }

        // Log unmapped writes outside of RAM/Hardware
        if addr > 0x1000 {
            // println!("Unmapped Write: 0x{:08x} = 0x{:08x}", addr, value);
        }

        for i in 0..4 {
            self.memory
                .insert(addr + i, ((value >> (i * 8)) & 0xFF) as u8);
        }
        Ok(())
    }

    pub fn advance_it_state(&mut self) {
        if self.it_state & 0x7 != 0 {
            // bits 4:0 are shifted
            let mut it = self.it_state & 0x1F;
            it <<= 1;
            if (it & 0x7) == 0 {
                self.it_state = 0;
            } else {
                self.it_state = (self.it_state & 0xE0) | (it & 0x1F);
            }
        } else if self.it_state != 0 {
            // Only one instruction in IT block, and it's done
            self.it_state = 0;
        }
    }

    pub fn execute(&mut self, instruction: &Instruction) -> Result<()> {
        let condition = if self.it_state & 0xF != 0 {
            self.it_state >> 4
        } else {
            instruction.condition
        };

        if !self.check_condition(condition) {
            self.advance_it_state();
            return Ok(());
        }

        let mnemonic = if instruction.mnemonic.ends_with('s')
            && instruction.mnemonic != "tst"
            && instruction.mnemonic != "teq"
            && instruction.mnemonic != "cmn"
            && instruction.mnemonic != "cmp"
        {
            &instruction.mnemonic[..instruction.mnemonic.len() - 1]
        } else {
            instruction.mnemonic.as_str()
        };

        let res = match mnemonic {
            "mov" | "movw" => self.exec_mov(instruction),
            "movt" => self.exec_movt(instruction),
            "add" | "addw" => self.exec_add(instruction),
            "adc" => self.exec_adc(instruction),
            "sbc" => self.exec_sbc(instruction),
            "sub" | "subw" => self.exec_sub(instruction),
            "rsb" => self.exec_rsb(instruction),
            "rsc" => self.exec_rsc(instruction),
            "ldr" => self.exec_ldr(instruction),
            "str" => self.exec_str(instruction),
            "b" => self.exec_branch(instruction),
            "bl" => self.exec_branch_link(instruction),
            "cmp" => self.exec_cmp(instruction),
            "orr" => self.exec_orr(instruction),
            "and" => self.exec_and(instruction),
            "eor" => self.exec_eor(instruction),
            "bic" => self.exec_bic(instruction),
            "mvn" => self.exec_mvn(instruction),
            "tst" => self.exec_tst(instruction),
            "teq" => self.exec_teq(instruction),
            "cmn" => self.exec_cmn(instruction),
            "ldm" => self.exec_ldm(instruction),
            "stm" => self.exec_stm(instruction),
            "bx" => self.exec_bx(instruction),
            "blx" => self.exec_blx(instruction),
            "push" => self.exec_push(instruction),
            "pop" => self.exec_pop(instruction),
            "ldrb" => self.exec_ldrb(instruction),
            "strb" => self.exec_strb(instruction),
            "ldrh" => self.exec_ldrh(instruction),
            "strh" => self.exec_strh(instruction),
            "ldrd" => self.exec_ldrd(instruction),
            "strd" => self.exec_strd(instruction),
            "ldrex" => self.exec_ldrex(instruction),
            "strex" => self.exec_strex(instruction),
            "ldrsb" => {
                let addr = self.get_mem_addr(instruction, 1)?;
                let val = self.read_memory(addr)? as i8 as i32 as u32;
                if let Some(Operand::Register(rd)) = instruction.operands.get(0) {
                    self.set_reg(*rd, val);
                }
                Ok(())
            }
            "ldrsh" => {
                let addr = self.get_mem_addr(instruction, 1)?;
                let low = self.read_memory(addr)? as u32;
                let high = self.read_memory(addr.wrapping_add(1))? as u32;
                let val = ((high << 8) | low) as i16 as i32 as u32;
                if let Some(Operand::Register(rd)) = instruction.operands.get(0) {
                    self.set_reg(*rd, val);
                }
                Ok(())
            }
            "tbb" | "tbh" => self.exec_tb(instruction),
            "uxtb" | "uxth" | "sxtb" | "sxth" => self.exec_extend(instruction),
            "swi" | "svc" => Ok(()), // Software interrupt
            "msr" | "mrs" => self.exec_msr_mrs(instruction),
            "mul" | "mla" => Ok(()), // Multiply instructions
            "lsl" | "lsr" | "asr" | "ror" => self.exec_shift(instruction),
            "rev" | "rev16" | "revsh" => self.exec_rev(instruction),
            "clz" => self.exec_clz(instruction),
            "cbz" | "cbnz" => self.exec_cbz(instruction),
            "bfc" => self.exec_bfc(instruction),
            "bfi" => self.exec_bfi(instruction),
            "ubfx" => self.exec_ubfx(instruction),
            "sbfx" => self.exec_sbfx(instruction),
            "it" => self.exec_it(instruction),
            "nop" => Ok(()),
            _ => {
                if instruction.mnemonic.starts_with("unknown_t") {
                    println!(
                        "Warning: Skipping unknown thumb instruction: {}",
                        instruction.mnemonic
                    );
                    Ok(())
                } else {
                    Err(CpuError::UnsupportedInstruction(
                        instruction.mnemonic.clone(),
                    ))
                }
            }
        };
        self.advance_it_state();
        res
    }

    fn exec_bx(&mut self, instruction: &Instruction) -> Result<()> {
        if let Some(Operand::Register(reg)) = instruction.operands.first() {
            let target = self.get_reg(*reg);
            // iBEC might switch to Thumb mode if bit 0 is set
            if target & 1 != 0 {
                self.set_reg(15, target & !1);
                self.cpsr |= 0x20; // Set T bit
            } else {
                self.set_reg(15, target);
                self.cpsr &= !0x20;
            }
        }
        Ok(())
    }

    fn exec_blx(&mut self, instruction: &Instruction) -> Result<()> {
        if let Some(Operand::Register(reg)) = instruction.operands.first() {
            let target = self.get_reg(*reg);
            let return_addr = self.pc.wrapping_add(instruction.size as u32) | 1;
            self.set_reg(14, return_addr);

            if target & 1 != 0 {
                self.set_reg(15, target & !1);
                self.cpsr |= 0x20; // Set T bit
            } else {
                self.set_reg(15, target);
                self.cpsr &= !0x20;
            }
        }
        Ok(())
    }

    fn interworking_branch(&mut self, target: u32) {
        if target & 1 != 0 {
            self.pc = target & !1;
            self.cpsr |= 0x20; // Thumb
        } else {
            self.pc = target & !3;
            self.cpsr &= !0x20; // ARM
        }
        self.pc_modified = true;
    }

    fn update_flags(&mut self, result: u32, carry: Option<bool>, overflow: Option<bool>) {
        self.cpsr &= !0xF0000000;
        if result == 0 {
            self.cpsr |= 0x40000000; // Z flag
        }
        if (result as i32) < 0 {
            self.cpsr |= 0x80000000; // N flag
        }
        if let Some(c) = carry {
            if c {
                self.cpsr |= 0x20000000; // C flag
            }
        }
        if let Some(v) = overflow {
            if v {
                self.cpsr |= 0x10000000; // V flag
            }
        }
    }

    fn exec_mov(&mut self, instruction: &Instruction) -> Result<()> {
        if instruction.operands.len() < 2 {
            return Ok(());
        }

        let value = match &instruction.operands[1] {
            Operand::Register(reg) => self.get_reg_dp(*reg),
            Operand::Immediate(imm) => *imm as u32,
            _ => return Ok(()),
        };

        if let Operand::Register(reg) = &instruction.operands[0] {
            if *reg == 15 {
                self.interworking_branch(value);
            }
            self.set_reg(*reg, value);
            if instruction.mnemonic.ends_with('s') {
                self.update_flags(value, None, None);
            }
        }

        Ok(())
    }

    fn exec_movt(&mut self, instruction: &Instruction) -> Result<()> {
        if let (Some(Operand::Register(rd)), Some(Operand::Immediate(imm))) =
            (instruction.operands.get(0), instruction.operands.get(1))
        {
            let current_val = self.get_reg(*rd);
            let new_val = (current_val & 0xFFFF) | ((*imm as u32) << 16);
            self.set_reg(*rd, new_val);
        }
        Ok(())
    }

    fn exec_add(&mut self, instruction: &Instruction) -> Result<()> {
        if instruction.operands.len() < 2 {
            return Ok(());
        }

        let (rd, val1, val2) = if instruction.operands.len() == 3 {
            let r = match instruction.operands[0] {
                Operand::Register(r) => r,
                _ => 0,
            };
            let v1 = match &instruction.operands[1] {
                Operand::Register(r) => self.get_reg_dp(*r),
                _ => 0,
            };
            let v2 = match &instruction.operands[2] {
                Operand::Register(r) => self.get_reg_dp(*r),
                Operand::Immediate(imm) => *imm as u32,
                Operand::Shift(r, type_, amount) => {
                    let val = self.get_reg_dp(*r);
                    let amt = *amount as u32;
                    match type_ {
                        0 => val.wrapping_shl(amt),
                        1 => val.wrapping_shr(amt),
                        2 => (val as i32).wrapping_shr(amt) as u32,
                        3 => val.rotate_right(amt),
                        _ => val,
                    }
                }
                _ => 0,
            };
            (r, v1, v2)
        } else {
            let r = match instruction.operands[0] {
                Operand::Register(r) => r,
                _ => 0,
            };
            let v1 = self.get_reg_dp(r);
            let v2 = match &instruction.operands[1] {
                Operand::Register(r) => self.get_reg_dp(*r),
                Operand::Immediate(imm) => *imm as u32,
                Operand::Shift(r, type_, amount) => {
                    let val = self.get_reg_dp(*r);
                    let amt = *amount as u32;
                    match type_ {
                        0 => val.wrapping_shl(amt),
                        1 => val.wrapping_shr(amt),
                        2 => (val as i32).wrapping_shr(amt) as u32,
                        3 => val.rotate_right(amt),
                        _ => val,
                    }
                }
                _ => 0,
            };
            (r, v1, v2)
        };

        let (result, carry) = val1.overflowing_add(val2);
        self.set_reg(rd, result);

        if instruction.mnemonic.ends_with('s') {
            let overflow = ((val1 ^ result) & (val2 ^ result) & 0x80000000) != 0;
            self.update_flags(result, Some(carry), Some(overflow));
        }

        Ok(())
    }

    fn exec_sub(&mut self, instruction: &Instruction) -> Result<()> {
        if instruction.operands.len() < 2 {
            return Ok(());
        }

        let (rd, val1, val2) = if instruction.operands.len() == 3 {
            let r = match instruction.operands[0] {
                Operand::Register(r) => r,
                _ => 0,
            };
            let v1 = match &instruction.operands[1] {
                Operand::Register(r) => self.get_reg_dp(*r),
                _ => 0,
            };
            let v2 = match &instruction.operands[2] {
                Operand::Register(r) => self.get_reg_dp(*r),
                Operand::Immediate(imm) => *imm as u32,
                Operand::Shift(r, type_, amount) => {
                    let val = self.get_reg_dp(*r);
                    let amt = *amount as u32;
                    match type_ {
                        0 => val.wrapping_shl(amt),
                        1 => val.wrapping_shr(amt),
                        2 => (val as i32).wrapping_shr(amt) as u32,
                        3 => val.rotate_right(amt),
                        _ => val,
                    }
                }
                _ => 0,
            };
            (r, v1, v2)
        } else {
            let r = match instruction.operands[0] {
                Operand::Register(r) => r,
                _ => 0,
            };
            let v1 = self.get_reg_dp(r);
            let v2 = match &instruction.operands[1] {
                Operand::Register(r) => self.get_reg_dp(*r),
                Operand::Immediate(imm) => *imm as u32,
                Operand::Shift(r, type_, amount) => {
                    let val = self.get_reg_dp(*r);
                    let amt = *amount as u32;
                    match type_ {
                        0 => val.wrapping_shl(amt),
                        1 => val.wrapping_shr(amt),
                        2 => (val as i32).wrapping_shr(amt) as u32,
                        3 => val.rotate_right(amt),
                        _ => val,
                    }
                }
                _ => 0,
            };
            (r, v1, v2)
        };

        let (result, borrow) = val1.overflowing_sub(val2);
        self.set_reg(rd, result);

        if instruction.mnemonic.ends_with('s') {
            let overflow = ((val1 ^ val2) & (val1 ^ result) & 0x80000000) != 0;
            self.update_flags(result, Some(!borrow), Some(overflow));
        }

        Ok(())
    }

    fn exec_bfc(&mut self, instruction: &Instruction) -> Result<()> {
        if let (
            Some(Operand::Register(rd)),
            Some(Operand::Immediate(lsb)),
            Some(Operand::Immediate(width)),
        ) = (
            instruction.operands.get(0),
            instruction.operands.get(1),
            instruction.operands.get(2),
        ) {
            let mut val = self.get_reg(*rd);
            let mask = ((1u32 << *width).wrapping_sub(1)) << *lsb;
            val &= !mask;
            self.set_reg(*rd, val);
        }
        Ok(())
    }

    fn exec_bfi(&mut self, instruction: &Instruction) -> Result<()> {
        if let (
            Some(Operand::Register(rd)),
            Some(Operand::Register(rn)),
            Some(Operand::Immediate(lsb)),
            Some(Operand::Immediate(width)),
        ) = (
            instruction.operands.get(0),
            instruction.operands.get(1),
            instruction.operands.get(2),
            instruction.operands.get(3),
        ) {
            let dest_val = self.get_reg(*rd);
            let src_val = self.get_reg(*rn);
            let mask = (1u32 << *width).wrapping_sub(1); // Unshifted mask for source
            let insert_bits = (src_val & mask) << *lsb;
            let dest_mask = !(mask << *lsb);

            let result = (dest_val & dest_mask) | insert_bits;
            self.set_reg(*rd, result);
        }
        Ok(())
    }

    fn exec_ubfx(&mut self, instruction: &Instruction) -> Result<()> {
        if let (
            Some(Operand::Register(rd)),
            Some(Operand::Register(rn)),
            Some(Operand::Immediate(lsb)),
            Some(Operand::Immediate(width)),
        ) = (
            instruction.operands.get(0),
            instruction.operands.get(1),
            instruction.operands.get(2),
            instruction.operands.get(3),
        ) {
            let val = self.get_reg(*rn);
            let mask = (1u32 << *width).wrapping_sub(1);
            let result = (val >> *lsb) & mask;
            self.set_reg(*rd, result);
        }
        Ok(())
    }

    fn exec_sbfx(&mut self, instruction: &Instruction) -> Result<()> {
        if let (
            Some(Operand::Register(rd)),
            Some(Operand::Register(rn)),
            Some(Operand::Immediate(lsb)),
            Some(Operand::Immediate(width)),
        ) = (
            instruction.operands.get(0),
            instruction.operands.get(1),
            instruction.operands.get(2),
            instruction.operands.get(3),
        ) {
            let val = self.get_reg(*rn);
            let shifted = val >> *lsb;
            let bits = 32 - *width;
            let result = ((shifted << bits) as i32) >> bits;
            self.set_reg(*rd, result as u32);
        }
        Ok(())
    }

    fn exec_ldr(&mut self, instruction: &Instruction) -> Result<()> {
        if instruction.operands.len() < 2 {
            return Ok(());
        }

        let bits = if instruction.operands.len() >= 3 {
            if let Operand::Immediate(b) = instruction.operands[2] {
                b as u8
            } else {
                0b10
            }
        } else {
            0b10 // P=1, W=0
        };

        let p = (bits >> 1) & 1;
        let w = bits & 1;

        match &instruction.operands[1] {
            Operand::Memory(base_reg, offset) => {
                let base_val = self.get_reg_dp(*base_reg);
                let mut offset_val = *offset as u32;
                if instruction.operands.len() >= 3 {
                    if let Operand::Register(rm) = instruction.operands[2] {
                        offset_val = self.get_reg_dp(rm);
                    }
                }

                let addr = if p == 1 {
                    base_val.wrapping_add(offset_val)
                } else {
                    base_val
                };

                let mut value = self.read_memory(addr)?;

                // HACK: Intercept uninitialized console object
                if addr == 0x5FFF7F24 && value == 0 {
                    /*
                    println!(
                        "HACK: Intercepted console object load at {:08x}. Substituting dummy vtable.",
                        addr
                    );
                    */
                    value = 0x5FF22EFD; // bx lr (Thumb)
                }

                if let Operand::Register(rd) = &instruction.operands[0] {
                    if *rd == 15 {
                        self.interworking_branch(value);
                    } else {
                        self.set_reg(*rd, value);
                    }
                }

                if w == 1 || p == 0 {
                    let new_base = base_val.wrapping_add(offset_val);
                    self.set_reg(*base_reg, new_base);
                }
            }
            _ => return Ok(()),
        }

        Ok(())
    }

    fn exec_str(&mut self, instruction: &Instruction) -> Result<()> {
        if instruction.operands.len() < 2 {
            return Ok(());
        }

        let value = match &instruction.operands[0] {
            Operand::Register(reg) => self.get_reg_dp(*reg),
            _ => return Ok(()),
        };

        let bits = if instruction.operands.len() >= 3 {
            if let Operand::Immediate(b) = instruction.operands[2] {
                b as u8
            } else {
                0b10
            }
        } else {
            0b10 // P=1, W=0
        };

        let p = (bits >> 1) & 1;
        let w = bits & 1;

        match &instruction.operands[1] {
            Operand::Memory(base_reg, offset) => {
                let base_val = self.get_reg_dp(*base_reg);
                let mut offset_val = *offset as u32;
                if instruction.operands.len() >= 3 {
                    if let Operand::Register(rm) = instruction.operands[2] {
                        offset_val = self.get_reg_dp(rm);
                    }
                }

                let addr = if p == 1 {
                    base_val.wrapping_add(offset_val)
                } else {
                    base_val
                };

                self.write_memory(addr, value)?;

                if w == 1 || p == 0 {
                    let new_base = base_val.wrapping_add(offset_val);
                    self.set_reg(*base_reg, new_base);
                }
            }
            _ => {}
        }

        Ok(())
    }

    fn exec_branch(&mut self, instruction: &Instruction) -> Result<()> {
        if let Some(Operand::Immediate(offset)) = instruction.operands.first() {
            let new_pc = self.get_reg(15).wrapping_add(*offset as u32);
            self.set_reg(15, new_pc);
        }
        Ok(())
    }

    fn exec_branch_link(&mut self, instruction: &Instruction) -> Result<()> {
        let return_addr = self.pc.wrapping_add(instruction.size as u32) | 1;
        self.set_reg(14, return_addr);
        self.exec_branch(instruction)
    }

    fn exec_push(&mut self, instruction: &Instruction) -> Result<()> {
        if instruction.operands.len() == 3 {
            return self.exec_stm(instruction);
        }

        let reg_list = match &instruction.operands[0] {
            Operand::Immediate(imm) => *imm as u32,
            _ => return Ok(()),
        };

        // PUSH uses SP (R13)
        let mut sp = self.registers[13];
        let num_regs = reg_list.count_ones();
        sp = sp.wrapping_sub(num_regs * 4);
        let new_sp = sp;

        let mut addr = new_sp;
        for i in 0..16 {
            if (reg_list >> i) & 1 != 0 {
                let val = self.get_reg(i as u8);
                self.write_memory(addr, val)?;
                addr = addr.wrapping_add(4);
            }
        }

        self.registers[13] = new_sp;
        Ok(())
    }

    fn exec_pop(&mut self, instruction: &Instruction) -> Result<()> {
        if instruction.operands.len() == 3 {
            return self.exec_ldm(instruction);
        }

        let reg_list = match &instruction.operands[0] {
            Operand::Immediate(imm) => *imm as u32,
            _ => return Ok(()),
        };

        let mut addr = self.registers[13];
        let num_regs = reg_list.count_ones();
        let new_sp = addr.wrapping_add(num_regs * 4);

        for i in 0..16 {
            if (reg_list >> i) & 1 != 0 {
                let val = self.read_memory(addr)?;
                if i == 15 {
                    self.interworking_branch(val);
                } else {
                    self.set_reg(i as u8, val);
                }
                addr = addr.wrapping_add(4);
            }
        }

        self.registers[13] = new_sp;
        Ok(())
    }

    fn exec_ldrb(&mut self, instruction: &Instruction) -> Result<()> {
        if instruction.operands.len() < 2 {
            return Ok(());
        }

        let rd = match instruction.operands[0] {
            Operand::Register(r) => r,
            _ => return Ok(()),
        };

        let addr = match &instruction.operands[1] {
            Operand::Memory(rn, offset) => {
                let base = self.get_reg(*rn);
                base.wrapping_add(*offset as u32)
            }
            _ => return Ok(()),
        };

        let val = self.memory.get(&addr).copied().unwrap_or(0) as u32;
        self.set_reg(rd, val);
        Ok(())
    }

    fn exec_strb(&mut self, instruction: &Instruction) -> Result<()> {
        if instruction.operands.len() < 2 {
            return Ok(());
        }

        let rd = match instruction.operands[0] {
            Operand::Register(r) => r,
            _ => return Ok(()),
        };

        let addr = match &instruction.operands[1] {
            Operand::Memory(rn, offset) => {
                let base = self.get_reg(*rn);
                base.wrapping_add(*offset as u32)
            }
            _ => return Ok(()),
        };

        let val = self.get_reg(rd) as u8;
        self.memory.insert(addr, val);
        Ok(())
    }

    fn exec_msr_mrs(&mut self, instruction: &Instruction) -> Result<()> {
        if instruction.mnemonic == "mrs" {
            if let Some(Operand::Register(rd)) = instruction.operands.get(0) {
                self.set_reg(*rd, self.cpsr);
            }
        } else if instruction.mnemonic == "msr" {
            if let Some(Operand::Register(rn)) = instruction.operands.get(1) {
                let val = self.get_reg(*rn);
                self.cpsr = val;
            }
        }
        Ok(())
    }

    fn exec_ldrd(&mut self, instruction: &Instruction) -> Result<()> {
        if let (Some(Operand::Register(rt)), Some(Operand::Register(rt2))) =
            (instruction.operands.get(0), instruction.operands.get(1))
        {
            let addr = self.get_mem_addr(instruction, 2)?;
            // println!("LDRD at {:08x}, addr {:08x}", self.pc, addr);
            let val = self.read_memory(addr)?;
            let val2 = self.read_memory(addr.wrapping_add(4))?;
            self.set_reg(*rt, val);
            self.set_reg(*rt2, val2);
        }
        Ok(())
    }

    fn exec_strd(&mut self, instruction: &Instruction) -> Result<()> {
        if let (Some(Operand::Register(rt)), Some(Operand::Register(rt2))) =
            (instruction.operands.get(0), instruction.operands.get(1))
        {
            let val = self.get_reg(*rt);
            let val2 = self.get_reg(*rt2);
            let addr = self.get_mem_addr(instruction, 2)?;
            // println!("STRD at {:08x}, addr {:08x} val {:08x} {:08x}", self.pc, addr, val, val2);
            self.write_memory(addr, val)?;
            self.write_memory(addr.wrapping_add(4), val2)?;
        }
        Ok(())
    }

    fn exec_ldrex(&mut self, instruction: &Instruction) -> Result<()> {
        // Treat as normal LDR
        // LDREX Rt, [Rn, #imm]
        if let Some(Operand::Register(rt)) = instruction.operands.get(0) {
            let addr = self.get_mem_addr(instruction, 1)?;
            let val = self.read_memory(addr)?;
            self.set_reg(*rt, val);
        }
        Ok(())
    }

    fn exec_strex(&mut self, instruction: &Instruction) -> Result<()> {
        // STREX Rd, Rt, [Rn, #imm]
        // Store Rt to [Rn, #imm], write 0 to Rd (success)
        if let (Some(Operand::Register(rd)), Some(Operand::Register(rt))) =
            (instruction.operands.get(0), instruction.operands.get(1))
        {
            let val = self.get_reg(*rt);
            let addr = self.get_mem_addr(instruction, 2)?;
            self.write_memory(addr, val)?;
            self.set_reg(*rd, 0); // 0 = Success
        }
        Ok(())
    }

    fn exec_cmp(&mut self, instruction: &Instruction) -> Result<()> {
        if instruction.operands.len() < 2 {
            return Ok(());
        }

        let val1 = match &instruction.operands[0] {
            Operand::Register(reg) => self.get_reg_dp(*reg),
            _ => return Ok(()),
        };

        let val2 = match &instruction.operands[1] {
            Operand::Register(reg) => self.get_reg_dp(*reg),
            Operand::Immediate(imm) => *imm as u32,
            _ => return Ok(()),
        };

        let result = val1.wrapping_sub(val2);

        // Update CPSR flags
        self.cpsr &= !0xF0000000;
        if result == 0 {
            self.cpsr |= 0x40000000; // Z flag
        }
        if (result as i32) < 0 {
            self.cpsr |= 0x80000000; // N flag
        }
        if val1 >= val2 {
            self.cpsr |= 0x20000000; // C flag (unsigned >=)
        }

        Ok(())
    }

    fn exec_orr(&mut self, instruction: &Instruction) -> Result<()> {
        if instruction.operands.len() < 3 {
            return Ok(());
        }

        let val1 = match &instruction.operands[1] {
            Operand::Register(reg) => self.get_reg_dp(*reg),
            _ => return Ok(()),
        };

        let val2 = match &instruction.operands[2] {
            Operand::Register(reg) => self.get_reg_dp(*reg),
            Operand::Immediate(imm) => *imm as u32,
            _ => return Ok(()),
        };

        if let Operand::Register(reg) = &instruction.operands[0] {
            self.set_reg(*reg, val1 | val2);
        }

        Ok(())
    }

    fn exec_and(&mut self, instruction: &Instruction) -> Result<()> {
        if instruction.operands.len() < 3 {
            return Ok(());
        }

        let val1 = match &instruction.operands[1] {
            Operand::Register(reg) => self.get_reg_dp(*reg),
            _ => return Ok(()),
        };

        let val2 = match &instruction.operands[2] {
            Operand::Register(reg) => self.get_reg_dp(*reg),
            Operand::Immediate(imm) => *imm as u32,
            _ => return Ok(()),
        };

        if let Operand::Register(reg) = &instruction.operands[0] {
            self.set_reg(*reg, val1 & val2);
        }

        Ok(())
    }

    fn exec_eor(&mut self, instruction: &Instruction) -> Result<()> {
        if instruction.operands.len() < 3 {
            return Ok(());
        }

        let val1 = match &instruction.operands[1] {
            Operand::Register(reg) => self.get_reg_dp(*reg),
            _ => return Ok(()),
        };

        let val2 = match &instruction.operands[2] {
            Operand::Register(reg) => self.get_reg_dp(*reg),
            Operand::Immediate(imm) => *imm as u32,
            _ => return Ok(()),
        };

        if let Operand::Register(reg) = &instruction.operands[0] {
            self.set_reg(*reg, val1 ^ val2);
        }

        Ok(())
    }

    fn exec_bic(&mut self, instruction: &Instruction) -> Result<()> {
        if instruction.operands.len() < 3 {
            return Ok(());
        }

        let val1 = match &instruction.operands[1] {
            Operand::Register(reg) => self.get_reg_dp(*reg),
            _ => return Ok(()),
        };

        let val2 = match &instruction.operands[2] {
            Operand::Register(reg) => self.get_reg_dp(*reg),
            Operand::Immediate(imm) => *imm as u32,
            _ => return Ok(()),
        };

        if let Operand::Register(reg) = &instruction.operands[0] {
            self.set_reg(*reg, val1 & !val2);
        }

        Ok(())
    }

    fn exec_rsb(&mut self, instruction: &Instruction) -> Result<()> {
        if instruction.operands.len() < 3 {
            return Ok(());
        }

        let val1 = match &instruction.operands[1] {
            Operand::Register(reg) => self.get_reg(*reg),
            _ => return Ok(()),
        };

        let val2 = match &instruction.operands[2] {
            Operand::Register(reg) => self.get_reg(*reg),
            Operand::Immediate(imm) => *imm as u32,
            _ => return Ok(()),
        };

        if let Operand::Register(reg) = &instruction.operands[0] {
            self.set_reg(*reg, val2.wrapping_sub(val1)); // RSB: Rd = Rm - Rn
        }

        Ok(())
    }

    fn exec_mvn(&mut self, instruction: &Instruction) -> Result<()> {
        if instruction.operands.len() < 2 {
            return Ok(());
        }

        let value = match &instruction.operands[1] {
            Operand::Register(reg) => self.get_reg_dp(*reg),
            Operand::Immediate(imm) => *imm as u32,
            _ => return Ok(()),
        };

        if let Operand::Register(reg) = &instruction.operands[0] {
            self.set_reg(*reg, !value); // MVN: bitwise NOT
        }

        Ok(())
    }

    fn exec_adc(&mut self, instruction: &Instruction) -> Result<()> {
        if instruction.operands.len() < 3 {
            return Ok(());
        }

        let val1 = match &instruction.operands[1] {
            Operand::Register(reg) => self.get_reg(*reg),
            _ => return Ok(()),
        };

        let val2 = match &instruction.operands[2] {
            Operand::Register(reg) => self.get_reg(*reg),
            Operand::Immediate(imm) => *imm as u32,
            _ => return Ok(()),
        };

        let carry = if self.cpsr & 0x20000000 != 0 { 1 } else { 0 };

        if let Operand::Register(reg) = &instruction.operands[0] {
            self.set_reg(*reg, val1.wrapping_add(val2).wrapping_add(carry));
        }

        Ok(())
    }

    fn exec_sbc(&mut self, instruction: &Instruction) -> Result<()> {
        if instruction.operands.len() < 3 {
            return Ok(());
        }

        let val1 = match &instruction.operands[1] {
            Operand::Register(reg) => self.get_reg(*reg),
            _ => return Ok(()),
        };

        let val2 = match &instruction.operands[2] {
            Operand::Register(reg) => self.get_reg(*reg),
            Operand::Immediate(imm) => *imm as u32,
            _ => return Ok(()),
        };

        let carry = if self.cpsr & 0x20000000 != 0 { 1 } else { 0 };

        if let Operand::Register(reg) = &instruction.operands[0] {
            self.set_reg(*reg, val1.wrapping_sub(val2).wrapping_sub(1 - carry));
        }

        Ok(())
    }

    fn exec_rsc(&mut self, instruction: &Instruction) -> Result<()> {
        if instruction.operands.len() < 3 {
            return Ok(());
        }

        let val1 = match &instruction.operands[1] {
            Operand::Register(reg) => self.get_reg(*reg),
            _ => return Ok(()),
        };

        let val2 = match &instruction.operands[2] {
            Operand::Register(reg) => self.get_reg(*reg),
            Operand::Immediate(imm) => *imm as u32,
            _ => return Ok(()),
        };

        let carry = if self.cpsr & 0x20000000 != 0 { 1 } else { 0 };

        if let Operand::Register(reg) = &instruction.operands[0] {
            self.set_reg(*reg, val2.wrapping_sub(val1).wrapping_sub(1 - carry));
        }

        Ok(())
    }

    fn exec_tst(&mut self, instruction: &Instruction) -> Result<()> {
        if instruction.operands.len() < 2 {
            return Ok(());
        }

        let val1 = match &instruction.operands[0] {
            Operand::Register(reg) => self.get_reg_dp(*reg),
            _ => return Ok(()),
        };

        let val2 = match &instruction.operands[1] {
            Operand::Register(reg) => self.get_reg_dp(*reg),
            Operand::Immediate(imm) => *imm as u32,
            _ => return Ok(()),
        };

        let result = val1 & val2;
        self.cpsr &= !0xF0000000;
        if result == 0 {
            self.cpsr |= 0x40000000; // Z flag
        }
        if (result as i32) < 0 {
            self.cpsr |= 0x80000000; // N flag
        }

        Ok(())
    }

    fn exec_teq(&mut self, instruction: &Instruction) -> Result<()> {
        if instruction.operands.len() < 2 {
            return Ok(());
        }

        let val1 = match &instruction.operands[0] {
            Operand::Register(reg) => self.get_reg(*reg),
            _ => return Ok(()),
        };

        let val2 = match &instruction.operands[1] {
            Operand::Register(reg) => self.get_reg(*reg),
            Operand::Immediate(imm) => *imm as u32,
            _ => return Ok(()),
        };

        let result = val1 ^ val2;
        self.cpsr &= !0xF0000000;
        if result == 0 {
            self.cpsr |= 0x40000000; // Z flag
        }
        if (result as i32) < 0 {
            self.cpsr |= 0x80000000; // N flag
        }

        Ok(())
    }

    fn exec_cmn(&mut self, instruction: &Instruction) -> Result<()> {
        if instruction.operands.len() < 2 {
            return Ok(());
        }

        let val1 = match &instruction.operands[0] {
            Operand::Register(reg) => self.get_reg(*reg),
            _ => return Ok(()),
        };

        let val2 = match &instruction.operands[1] {
            Operand::Register(reg) => self.get_reg(*reg),
            Operand::Immediate(imm) => *imm as u32,
            _ => return Ok(()),
        };

        let result = val1.wrapping_add(val2);
        self.cpsr &= !0xF0000000;
        if result == 0 {
            self.cpsr |= 0x40000000; // Z flag
        }
        if (result as i32) < 0 {
            self.cpsr |= 0x80000000; // N flag
        }
        if (val1 as u64) + (val2 as u64) >= 0x100000000 {
            self.cpsr |= 0x20000000; // C flag
        }

        Ok(())
    }

    fn exec_ldm(&mut self, instruction: &Instruction) -> Result<()> {
        if instruction.operands.len() < 3 {
            return Ok(());
        }

        let base_reg = match &instruction.operands[0] {
            Operand::Register(reg) => *reg,
            _ => return Ok(()),
        };

        let reg_list = match &instruction.operands[1] {
            Operand::Immediate(imm) => *imm as u16,
            _ => return Ok(()),
        };

        let bits = match &instruction.operands[2] {
            Operand::Immediate(imm) => *imm as u8,
            _ => return Ok(()),
        };

        let p = (bits >> 2) & 1;
        let u = (bits >> 1) & 1;
        let w = bits & 1;

        let mut addr = self.get_reg(base_reg);
        let num_regs = reg_list.count_ones();

        if u == 0 {
            addr = addr.wrapping_sub(num_regs * 4);
        }

        let start_addr = addr;
        let mut current_addr = addr;

        for i in 0..16 {
            if (reg_list >> i) & 1 != 0 {
                if p == 1 {
                    current_addr = current_addr.wrapping_add(4);
                }
                let val = self.read_memory(current_addr)?;
                if i == 15 {
                    self.interworking_branch(val);
                } else {
                    self.set_reg(i as u8, val);
                }
                if p == 0 {
                    current_addr = current_addr.wrapping_add(4);
                }
            }
        }

        if w == 1 {
            let next_base = if u == 1 {
                start_addr.wrapping_add(num_regs * 4)
            } else {
                start_addr
            };
            self.set_reg(base_reg, next_base);
        }

        Ok(())
    }

    fn exec_stm(&mut self, instruction: &Instruction) -> Result<()> {
        if instruction.operands.len() < 3 {
            return Ok(());
        }

        let base_reg = match &instruction.operands[0] {
            Operand::Register(reg) => *reg,
            _ => return Ok(()),
        };

        let reg_list = match &instruction.operands[1] {
            Operand::Immediate(imm) => *imm as u16,
            _ => return Ok(()),
        };

        let bits = match &instruction.operands[2] {
            Operand::Immediate(imm) => *imm as u8,
            _ => return Ok(()),
        };

        let p = (bits >> 2) & 1;
        let u = (bits >> 1) & 1;
        let w = bits & 1;

        let mut addr = self.get_reg(base_reg);
        let num_regs = reg_list.count_ones();

        if u == 0 {
            addr = addr.wrapping_sub(num_regs * 4);
        }

        let start_addr = addr;
        let mut current_addr = addr;

        for i in 0..16 {
            if (reg_list >> i) & 1 != 0 {
                if p == 1 {
                    current_addr = current_addr.wrapping_add(4);
                }
                let val = self.get_reg(i as u8);
                self.write_memory(current_addr, val)?;
                if p == 0 {
                    current_addr = current_addr.wrapping_add(4);
                }
            }
        }

        if w == 1 {
            let next_base = if u == 1 {
                start_addr.wrapping_add(num_regs * 4)
            } else {
                start_addr
            };
            self.set_reg(base_reg, next_base);
        }

        Ok(())
    }

    fn check_condition(&self, cond: u8) -> bool {
        let n = (self.cpsr >> 31) & 1;
        let z = (self.cpsr >> 30) & 1;
        let c = (self.cpsr >> 29) & 1;
        let v = (self.cpsr >> 28) & 1;

        match cond {
            0x0 => z == 1,           // EQ
            0x1 => z == 0,           // NE
            0x2 => c == 1,           // CS/HS
            0x3 => c == 0,           // CC/LO
            0x4 => n == 1,           // MI
            0x5 => n == 0,           // PL
            0x6 => v == 1,           // VS
            0x7 => v == 0,           // VC
            0x8 => c == 1 && z == 0, // HI
            0x9 => c == 0 || z == 1, // LS
            0xA => n == v,           // GE
            0xB => n != v,           // LT
            0xC => z == 0 && n == v, // GT
            0xD => z == 1 || n != v, // LE
            0xE => true,             // AL (always)
            0xF => false,            // NV (never)
            _ => false,
        }
    }

    fn exec_shift(&mut self, instruction: &Instruction) -> Result<()> {
        if instruction.operands.len() < 2 {
            return Ok(());
        }

        let rd = match instruction.operands[0] {
            Operand::Register(r) => r,
            _ => return Ok(()),
        };

        let (val, amount) = if instruction.operands.len() == 3 {
            let v = match &instruction.operands[1] {
                Operand::Register(r) => self.get_reg_dp(*r),
                _ => 0,
            };
            let a = match &instruction.operands[2] {
                Operand::Register(r) => self.get_reg_dp(*r),
                Operand::Immediate(imm) => *imm as u32,
                _ => 0,
            };
            (v, a)
        } else {
            let v = self.get_reg_dp(rd);
            let a = match &instruction.operands[1] {
                Operand::Register(r) => self.get_reg_dp(*r),
                Operand::Immediate(imm) => *imm as u32,
                _ => 0,
            };
            (v, a)
        };

        let result = match instruction.mnemonic.as_str() {
            "lsl" => val.wrapping_shl(amount % 32),
            "lsr" => val.wrapping_shr(amount % 32),
            "asr" => (val as i32).wrapping_shr(amount % 32) as u32,
            "ror" => val.rotate_right(amount % 32),
            _ => val,
        };

        self.set_reg(rd, result);
        self.update_flags(result, None, None);
        Ok(())
    }

    fn exec_cbz(&mut self, instruction: &Instruction) -> Result<()> {
        if let (Some(Operand::Register(rn)), Some(Operand::Immediate(offset))) =
            (instruction.operands.get(0), instruction.operands.get(1))
        {
            let val = self.get_reg(*rn);
            let is_cbnz = instruction.mnemonic == "cbnz";
            if (val == 0 && !is_cbnz) || (val != 0 && is_cbnz) {
                let new_pc = self.pc.wrapping_add(4).wrapping_add(*offset as u32);
                self.set_reg(15, new_pc);
            }
        }
        Ok(())
    }

    fn exec_tb(&mut self, instruction: &Instruction) -> Result<()> {
        if let (Some(Operand::Register(rn)), Some(Operand::Register(rm))) =
            (instruction.operands.get(0), instruction.operands.get(1))
        {
            let base = self.get_reg_dp(*rn);
            let index = self.get_reg(*rm);
            let is_tbh = instruction.mnemonic == "tbh";

            let addr = if is_tbh {
                base.wrapping_add(index << 1)
            } else {
                base.wrapping_add(index)
            };

            let offset = if is_tbh {
                let low = self.read_memory(addr)? & 0xFF;
                let high = self.read_memory(addr.wrapping_add(1))? & 0xFF;
                (high << 8) | low
            } else {
                self.read_memory(addr)? & 0xFF
            };

            let new_pc = self.pc.wrapping_add(4).wrapping_add(offset << 1);
            self.pc = new_pc;
            self.pc_modified = true;
        }
        Ok(())
    }

    fn exec_rev(&mut self, instruction: &Instruction) -> Result<()> {
        if let (Some(Operand::Register(rd)), Some(Operand::Register(rm))) =
            (instruction.operands.get(0), instruction.operands.get(1))
        {
            let val = self.get_reg(*rm);
            let result = match instruction.mnemonic.as_str() {
                "rev" => val.swap_bytes(),
                "rev16" => ((val & 0xFF00FF00) >> 8) | ((val & 0x00FF00FF) << 8),
                "revsh" => (((val & 0xFF) << 8) | ((val >> 8) & 0xFF)) as i16 as i32 as u32,
                _ => val,
            };
            self.set_reg(*rd, result);
        }
        Ok(())
    }

    fn exec_clz(&mut self, instruction: &Instruction) -> Result<()> {
        if let (Some(Operand::Register(rd)), Some(Operand::Register(rm))) =
            (instruction.operands.get(0), instruction.operands.get(1))
        {
            let val = self.get_reg(*rm);
            let result = val.leading_zeros();
            self.set_reg(*rd, result as u32);
        }
        Ok(())
    }

    fn exec_it(&mut self, instruction: &Instruction) -> Result<()> {
        let cond = match instruction.operands[0] {
            Operand::Immediate(imm) => imm as u8,
            _ => 0xE,
        };
        let mask = match instruction.operands[1] {
            Operand::Immediate(imm) => imm as u8,
            _ => 0,
        };
        self.it_state = (cond << 4) | mask;
        Ok(())
    }

    fn exec_ldrh(&mut self, instruction: &Instruction) -> Result<()> {
        if let Some(Operand::Register(rd)) = instruction.operands.get(0) {
            let addr = self.get_mem_addr(instruction, 1)?;
            let low = self.read_memory(addr)? as u32;
            let high = self.read_memory(addr.wrapping_add(1))? as u32;
            let val = (high << 8) | low;
            self.set_reg(*rd, val);
        }
        Ok(())
    }

    fn exec_strh(&mut self, instruction: &Instruction) -> Result<()> {
        if let Some(Operand::Register(rd)) = instruction.operands.get(0) {
            let val = self.get_reg(*rd);
            let addr = self.get_mem_addr(instruction, 1)?;
            self.memory.insert(addr, (val & 0xFF) as u8);
            self.memory
                .insert(addr.wrapping_add(1), ((val >> 8) & 0xFF) as u8);
        }
        Ok(())
    }

    fn exec_extend(&mut self, instruction: &Instruction) -> Result<()> {
        if let (Some(Operand::Register(rd)), Some(Operand::Register(rm))) =
            (instruction.operands.get(0), instruction.operands.get(1))
        {
            let val = self.get_reg(*rm);
            let result = match instruction.mnemonic.as_str() {
                "uxtb" | "uxtbs" => val & 0xFF,
                "uxth" | "uxths" => val & 0xFFFF,
                "sxtb" | "sxtbs" => (val as i8 as i32) as u32,
                "sxth" | "sxths" => (val as i16 as i32) as u32,
                _ => val,
            };
            self.set_reg(*rd, result);
        }
        Ok(())
    }
}
