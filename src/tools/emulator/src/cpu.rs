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
    pub pc: u32,
    pub cpsr: u32,
    pub hardware: Option<Hardware>,
    pub pc_modified: bool,
}

impl ArmCpu {
    pub fn new() -> Self {
        Self {
            registers: [0; 16],
            memory: HashMap::new(),
            pc: 0,
            cpsr: 0,
            hardware: None,
            pc_modified: false,
        }
    }

    pub fn set_hardware(&mut self, hardware: Hardware) {
        self.hardware = Some(hardware);
    }

    pub fn load_memory(&mut self, addr: u32, data: &[u8]) {
        for (i, &byte) in data.iter().enumerate() {
            self.memory.insert(addr + i as u32, byte);
        }
    }

    pub fn get_reg(&self, reg: u8) -> u32 {
        if reg == 15 {
            self.pc.wrapping_add(8)
        } else {
            self.registers[reg as usize]
        }
    }

    pub fn set_reg(&mut self, reg: u8, val: u32) {
        if reg == 15 {
            self.pc = val;
            self.pc_modified = true;
        } else {
            self.registers[reg as usize] = val;
        }
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

        // Device tree UART address (0x80020010)
        match addr {
            0x80020010 => return Ok(0x6),              // TX Status - ready
            0x80020014 => return Ok(0x60),             // Line Status - TX empty
            0x80020018 => return Ok(0x0),              // FIFO Status - empty
            0x80020000..=0x8002003F => return Ok(0x0), // Other UART regs
            _ => {}
        }

        // iPad 1,1 (k48ap) Apple A4 UART0 registers
        match addr {
            // UART0 TX Status - always ready
            0x82500010 => return Ok(0x6),
            // UART0 Line Status - TX empty
            0x82500014 => return Ok(0x60),
            // UART0 FIFO Status - empty
            0x82500018 => return Ok(0x0),
            // Other UART registers - safe defaults
            0x82500000..=0x8250003F => return Ok(0x0),
            _ => {}
        }

        // Check hardware peripherals
        if let Some(ref hw) = self.hardware {
            if let Some(value) = hw.read(addr) {
                return Ok(value);
            }
        }

        // Check if address is within loaded memory range
        if !self.memory.contains_key(&addr) {
            // For invalid memory access, return 0 instead of error to continue execution
            return Ok(0);
        }

        let mut value = 0u32;
        for i in 0..4 {
            if let Some(&byte) = self.memory.get(&(addr + i)) {
                value |= (byte as u32) << (i * 8);
            } else {
                // If any byte is missing, return 0
                return Ok(0);
            }
        }
        Ok(value)
    }

    pub fn write_memory(&mut self, addr: u32, value: u32) -> Result<()> {
        // Apple A4 UART0 TX register
        if addr == 0x82500020 {
            let ch = (value & 0xFF) as u8;
            print!("{}", ch as char);
            std::io::Write::flush(&mut std::io::stdout()).unwrap();
            return Ok(());
        }

        // Check hardware peripherals
        if let Some(ref mut hw) = self.hardware {
            if hw.write(addr, value) {
                return Ok(());
            }
        }

        for i in 0..4 {
            self.memory
                .insert(addr + i, ((value >> (i * 8)) & 0xFF) as u8);
        }
        Ok(())
    }

    pub fn execute(&mut self, instruction: &Instruction) -> Result<()> {
        // Check condition code
        if !self.check_condition(instruction.condition) {
            return Ok(()); // Skip instruction if condition not met
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

        match mnemonic {
            "mov" => self.exec_mov(instruction),
            "add" => self.exec_add(instruction),
            "adc" => self.exec_adc(instruction),
            "sbc" => self.exec_sbc(instruction),
            "sub" => self.exec_sub(instruction),
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
            "swi" | "svc" => Ok(()),                 // Software interrupt
            "msr" | "mrs" => Ok(()),                 // Status register access
            "mul" | "mla" => Ok(()),                 // Multiply instructions
            "lsl" | "lsr" | "asr" | "ror" => Ok(()), // Shift instructions
            "nop" => Ok(()),
            _ => Err(CpuError::UnsupportedInstruction(
                instruction.mnemonic.clone(),
            )),
        }
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
            Operand::Register(reg) => self.get_reg(*reg),
            Operand::Immediate(imm) => *imm as u32,
            _ => return Ok(()),
        };

        if let Operand::Register(reg) = &instruction.operands[0] {
            self.set_reg(*reg, value);
            if instruction.mnemonic.ends_with('s') {
                self.update_flags(value, None, None);
            }
        }

        Ok(())
    }

    fn exec_add(&mut self, instruction: &Instruction) -> Result<()> {
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

        let (result, carry) = val1.overflowing_add(val2);

        if let Operand::Register(reg) = &instruction.operands[0] {
            self.set_reg(*reg, result);
            if instruction.mnemonic.ends_with('s') {
                let overflow = ((val1 ^ result) & (val2 ^ result) & 0x80000000) != 0;
                self.update_flags(result, Some(carry), Some(overflow));
            }
        }

        Ok(())
    }

    fn exec_sub(&mut self, instruction: &Instruction) -> Result<()> {
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

        let (result, borrow) = val1.overflowing_sub(val2);

        if let Operand::Register(reg) = &instruction.operands[0] {
            self.set_reg(*reg, result);
            if instruction.mnemonic.ends_with('s') {
                let carry = !borrow;
                let overflow = ((val1 ^ val2) & (val1 ^ result) & 0x80000000) != 0;
                self.update_flags(result, Some(carry), Some(overflow));
            }
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
                let base_val = self.get_reg(*base_reg);
                let offset_val = *offset as u32;

                let addr = if p == 1 {
                    base_val.wrapping_add(offset_val)
                } else {
                    base_val
                };

                let value = self.read_memory(addr)?;

                if let Operand::Register(rd) = &instruction.operands[0] {
                    self.set_reg(*rd, value);
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
            Operand::Register(reg) => self.get_reg(*reg),
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
                let base_val = self.get_reg(*base_reg);
                let offset_val = *offset as u32;

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
            let new_pc = self.pc.wrapping_add(8).wrapping_add(*offset as u32);
            self.set_reg(15, new_pc);
        }
        Ok(())
    }

    fn exec_branch_link(&mut self, instruction: &Instruction) -> Result<()> {
        let return_addr = self.pc.wrapping_add(4);
        self.set_reg(14, return_addr); // Save return address in LR
        self.exec_branch(instruction)
    }

    fn exec_cmp(&mut self, instruction: &Instruction) -> Result<()> {
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
            Operand::Register(reg) => self.get_reg(*reg),
            _ => return Ok(()),
        };

        let val2 = match &instruction.operands[2] {
            Operand::Register(reg) => self.get_reg(*reg),
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
            Operand::Register(reg) => self.get_reg(*reg),
            _ => return Ok(()),
        };

        let val2 = match &instruction.operands[2] {
            Operand::Register(reg) => self.get_reg(*reg),
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
            Operand::Register(reg) => self.get_reg(*reg),
            _ => return Ok(()),
        };

        let val2 = match &instruction.operands[2] {
            Operand::Register(reg) => self.get_reg(*reg),
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
            Operand::Register(reg) => self.get_reg(*reg),
            _ => return Ok(()),
        };

        let val2 = match &instruction.operands[2] {
            Operand::Register(reg) => self.get_reg(*reg),
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
            Operand::Register(reg) => self.get_reg(*reg),
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
            Operand::Register(reg) => self.get_reg(*reg),
            _ => return Ok(()),
        };

        let val2 = match &instruction.operands[1] {
            Operand::Register(reg) => self.get_reg(*reg),
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
                self.set_reg(i as u8, val);
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
}
