#[derive(Debug, Clone)]
pub struct Instruction {
    pub mnemonic: String,
    pub operands: Vec<Operand>,
    pub condition: u8,
    pub size: usize,
}

#[derive(Debug, Clone)]
pub enum Operand {
    Register(u8),
    Immediate(i32),
    Shift(u8, u8, u8), // Register, Type, Amount
    Memory(u8, i32),
}

pub fn decode(code: &[u8], is_thumb: bool) -> Result<Vec<Instruction>, String> {
    let mut instructions = Vec::new();

    if is_thumb {
        if code.len() < 2 {
            return Err("Insufficient bytes for Thumb instruction".to_string());
        }
        let hw1 = u16::from_le_bytes([code[0], code[1]]);

        // Check for Thumb-2 32-bit instruction
        // Thumb-2 prefix bits: 11101, 11110, 11111
        let prefix = (hw1 >> 11) & 0x1F;
        if prefix >= 0x1D {
            if code.len() < 4 {
                return Err("Insufficient bytes for Thumb-2 instruction".to_string());
            }
            let hw2 = u16::from_le_bytes([code[2], code[3]]);
            decode_thumb32(hw1, hw2, &mut instructions)?;
        } else {
            decode_thumb16(hw1, &mut instructions)?;
        }
    } else {
        if code.len() < 4 {
            return Err("Insufficient bytes for ARM instruction".to_string());
        }
        let word = u32::from_le_bytes([code[0], code[1], code[2], code[3]]);
        let cond = (word >> 28) & 0xF;
        let op = (word >> 25) & 0x7;

        match op {
            0b000 => decode_data_processing(word, cond, &mut instructions)?,
            0b001 => decode_data_processing_imm(word, cond, &mut instructions)?,
            0b010 => decode_load_store(word, cond, &mut instructions)?,
            0b100 => decode_ldm_stm(word, cond, &mut instructions)?,
            0b101 => decode_branch(word, cond, &mut instructions)?,
            _ => {
                instructions.push(Instruction {
                    mnemonic: "nop".to_string(),
                    operands: vec![],
                    condition: cond as u8,
                    size: 4,
                });
            }
        }
    }

    Ok(instructions)
}

fn decode_thumb16(hw: u16, instructions: &mut Vec<Instruction>) -> Result<(), String> {
    let _op = hw >> 8;

    // PUSH/POP (Reg list)
    if (hw & 0xFE00) == 0xB400 {
        // PUSH {reglist}
        let _l = (hw >> 11) & 1; // Not used for push/pop in this mask
        let mnemonic = "push";
        let regs = hw & 0xFF; // lower 8 regs
        let m = (hw >> 8) & 1; // LR for PUSH, PC for POP
        let mut reg_list = regs as u32;
        if m == 1 {
            reg_list |= 1 << 14; // LR
        }
        instructions.push(Instruction {
            mnemonic: mnemonic.to_string(),
            operands: vec![Operand::Immediate(reg_list as i32)],
            condition: 0xE,
            size: 2,
        });
        return Ok(());
    }
    if (hw & 0xFE00) == 0xBC00 {
        // POP {reglist}
        let mnemonic = "pop";
        let regs = hw & 0xFF;
        let m = (hw >> 8) & 1;
        let mut reg_list = regs as u32;
        if m == 1 {
            reg_list |= 1 << 15; // PC
        }
        instructions.push(Instruction {
            mnemonic: mnemonic.to_string(),
            operands: vec![Operand::Immediate(reg_list as i32)],
            condition: 0xE,
            size: 2,
        });
        return Ok(());
    }

    // MOV/CMP/ADD/SUB (Immediate)
    // 001 op Rd imm8
    if (hw & 0xE000) == 0x2000 {
        let op = (hw >> 11) & 3;
        let rd = (hw >> 8) & 7;
        let imm = hw & 0xFF;
        let mnemonic = match op {
            0 => "movs",
            1 => "cmp",
            2 => "adds",
            3 => "subs",
            _ => "unknown",
        };
        instructions.push(Instruction {
            mnemonic: mnemonic.to_string(),
            operands: vec![Operand::Register(rd as u8), Operand::Immediate(imm as i32)],
            condition: 0xE,
            size: 2,
        });
        return Ok(());
    }

    // ADD/SUB (3-operand)
    if (hw & 0xF800) == 0x1800 {
        let op = (hw >> 9) & 3; // bits 10:9
        let rn_rm = (hw >> 6) & 7;
        let rn = (hw >> 3) & 7;
        let rd = hw & 7;

        // 00011 00 Rm Rn Rd -> ADD Rd, Rn, Rm
        // 00011 01 imm3 Rn Rd -> SUB Rd, Rn, imm3 (wait, bit 10 is 0 for these)
        // Correct encoding: 0001 1 op ...
        // op=0: ADD Reg, op=1: SUB Reg, op=2: ADD Imm, op=3: SUB Imm
        let mnemonic = match op {
            0 => "adds",
            1 => "subs",
            2 => "adds",
            3 => "subs",
            _ => "unknown",
        };
        let mut operands = vec![Operand::Register(rd as u8), Operand::Register(rn as u8)];
        if op < 2 {
            operands.push(Operand::Register(rn_rm as u8));
        } else {
            operands.push(Operand::Immediate(rn_rm as i32));
        }

        instructions.push(Instruction {
            mnemonic: mnemonic.to_string(),
            operands,
            condition: 0xE,
            size: 2,
        });
        return Ok(());
    }

    // Data processing (2-operand)
    if (hw & 0xFC00) == 0x4000 {
        let opcode = (hw >> 6) & 0xF;
        let rm = (hw >> 3) & 7;
        let rd = hw & 7;
        let mnemonic = match opcode {
            0x0 => "ands",
            0x1 => "eors",
            0x2 => "lsls",
            0x3 => "lsrs",
            0x4 => "asrs",
            0x5 => "adcs",
            0x6 => "sbcs",
            0x7 => "rors",
            0x8 => "tst",
            0x9 => "rsbs",
            0xA => "cmp",
            0xB => "cmn",
            0xC => "orrs",
            0xD => "muls",
            0xE => "bics",
            0xF => "mvns",
            _ => "unknown_dp",
        };
        instructions.push(Instruction {
            mnemonic: mnemonic.to_string(),
            operands: vec![Operand::Register(rd as u8), Operand::Register(rm as u8)],
            condition: 0xE,
            size: 2,
        });
        return Ok(());
    }

    // Load/Store (Register offset)
    if (hw & 0xF000) == 0x5000 {
        let op = (hw >> 9) & 7;
        let rm = (hw >> 6) & 7;
        let rn = (hw >> 3) & 7;
        let rd = hw & 7;
        let mnemonic = match op {
            0 => "str",
            1 => "strh",
            2 => "strb",
            3 => "ldrsb",
            4 => "ldr",
            5 => "ldrh",
            6 => "ldrb",
            7 => "ldrsh",
            _ => "unknown_lsr",
        };
        instructions.push(Instruction {
            mnemonic: mnemonic.to_string(),
            operands: vec![
                Operand::Register(rd as u8),
                Operand::Memory(rn as u8, 0),
                Operand::Register(rm as u8),
            ],
            condition: 0xE,
            size: 2,
        });
        return Ok(());
    }

    // REV/REV16/REVSH
    if (hw & 0xFFC0) == 0xBA00 {
        let op = (hw >> 6) & 3;
        let rs = (hw >> 3) & 7;
        let rd = hw & 7;
        let mnemonic = match op {
            0 => "rev",
            1 => "rev16",
            3 => "revsh",
            _ => "unknown_misc",
        };
        instructions.push(Instruction {
            mnemonic: mnemonic.to_string(),
            operands: vec![Operand::Register(rd as u8), Operand::Register(rs as u8)],
            condition: 0xE,
            size: 2,
        });
        return Ok(());
    }

    // NOP and other hints
    if (hw & 0xFF00) == 0xBF00 {
        if (hw & 0x000F) != 0 {
            // IT block
            let cond = (hw >> 4) & 0xF;
            let mask = hw & 0xF;
            instructions.push(Instruction {
                mnemonic: "it".to_string(),
                operands: vec![
                    Operand::Immediate(cond as i32),
                    Operand::Immediate(mask as i32),
                ],
                condition: 0xE,
                size: 2,
            });
            return Ok(());
        }
        instructions.push(Instruction {
            mnemonic: "nop".to_string(),
            operands: vec![],
            condition: 0xE,
            size: 2,
        });
        return Ok(());
    }

    // CBZ/CBNZ
    if (hw & 0xF500) == 0xB100 {
        let op = (hw >> 11) & 1; // 0 = CBZ, 1 = CBNZ
        let i = (hw >> 9) & 1;
        let imm5 = (hw >> 3) & 0x1F;
        let rn = hw & 0x7;
        let imm6 = (i << 6) | (imm5 << 1);
        let mnemonic = if op == 1 { "cbnz" } else { "cbz" };
        instructions.push(Instruction {
            mnemonic: mnemonic.to_string(),
            operands: vec![Operand::Register(rn as u8), Operand::Immediate(imm6 as i32)],
            condition: 0xE,
            size: 2,
        });
        return Ok(());
    }

    // BX/BLX (Register)
    if (hw & 0xFF00) == 0x4700 {
        let rm = (hw >> 3) & 0xF;
        let l = (hw >> 7) & 1;
        let mnemonic = if l == 1 { "blx" } else { "bx" };
        instructions.push(Instruction {
            mnemonic: mnemonic.to_string(),
            operands: vec![Operand::Register(rm as u8)],
            condition: 0xE,
            size: 2,
        });
        return Ok(());
    }

    // LDR (Literal/PC-relative)
    if (hw & 0xF800) == 0x4800 {
        let rd = (hw >> 8) & 7;
        let imm = (hw & 0xFF) << 2;
        instructions.push(Instruction {
            mnemonic: "ldr".to_string(),
            operands: vec![Operand::Register(rd as u8), Operand::Memory(15, imm as i32)],
            condition: 0xE,
            size: 2,
        });
        return Ok(());
    }

    // Special Data Processing (High registers)
    if (hw & 0xFC00) == 0x4400 {
        let opcode = (hw >> 8) & 3;
        let h1 = (hw >> 7) & 1;
        let h2 = (hw >> 6) & 1;
        let rm = ((hw >> 3) & 7) | (h2 << 3);
        let rd = (hw & 7) | (h1 << 3);

        let mnemonic = match opcode {
            0 => "add",
            1 => "cmp",
            2 => "mov",
            _ => "unknown_sdp",
        };

        if mnemonic != "unknown_sdp" {
            instructions.push(Instruction {
                mnemonic: mnemonic.to_string(),
                operands: vec![Operand::Register(rd as u8), Operand::Register(rm as u8)],
                condition: 0xE,
                size: 2,
            });
            return Ok(());
        }
    }

    // ADD/SUB SP, #imm
    if (hw & 0xFF00) == 0xB000 {
        let op = (hw >> 7) & 1;
        let imm = (hw & 0x7F) << 2;
        let mnemonic = if op == 1 { "sub" } else { "add" };
        instructions.push(Instruction {
            mnemonic: mnemonic.to_string(),
            operands: vec![Operand::Register(13), Operand::Immediate(imm as i32)],
            condition: 0xE,
            size: 2,
        });
        return Ok(());
    }

    // STR/LDR Rd, [SP, #imm]
    if (hw & 0xF000) == 0x9000 {
        let l = (hw >> 11) & 1;
        let rd = (hw >> 8) & 7;
        let imm = (hw & 0xFF) << 2;
        let mnemonic = if l == 1 { "ldr" } else { "str" };
        instructions.push(Instruction {
            mnemonic: mnemonic.to_string(),
            operands: vec![
                Operand::Register(rd as u8),
                Operand::Memory(13, imm as i32),
                Operand::Immediate(0b10), // P=1, W=0
            ],
            condition: 0xE,
            size: 2,
        });
        return Ok(());
    }

    // LDR/STR Rd, [Rn, #imm] (5-bit imm)
    if (hw & 0xF000) == 0x6000 {
        let l = (hw >> 11) & 1;
        let imm = ((hw >> 6) & 0x1F) << 2;
        let rn = (hw >> 3) & 7;
        let rd = hw & 7;
        let mnemonic = if l == 1 { "ldr" } else { "str" };
        instructions.push(Instruction {
            mnemonic: mnemonic.to_string(),
            operands: vec![
                Operand::Register(rd as u8),
                Operand::Memory(rn as u8, imm as i32),
                Operand::Immediate(0b10),
            ],
            condition: 0xE,
            size: 2,
        });
        return Ok(());
    }

    // ADD Rd, SP, #imm
    if (hw & 0xF800) == 0xA800 {
        let rd = (hw >> 8) & 7;
        let imm = (hw & 0xFF) << 2;
        instructions.push(Instruction {
            mnemonic: "add".to_string(),
            operands: vec![
                Operand::Register(rd as u8),
                Operand::Register(13),
                Operand::Immediate(imm as i32),
            ],
            condition: 0xE,
            size: 2,
        });
        return Ok(());
    }

    // B imm11
    if (hw & 0xF800) == 0xE000 {
        let imm11 = hw & 0x7FF;
        // Sign extend 11-bit
        let mut offset = (imm11 as i32) << 1;
        if offset & 0x1000 != 0 {
            offset |= 0xFFFFE000u32 as i32;
        }
        instructions.push(Instruction {
            mnemonic: "b".to_string(),
            operands: vec![Operand::Immediate(offset)],
            condition: 0xE,
            size: 2,
        });
        return Ok(());
    }

    // ADR Rd, label
    if (hw & 0xF800) == 0xA000 {
        let rd = (hw >> 8) & 7;
        let imm = (hw & 0xFF) << 2;
        instructions.push(Instruction {
            mnemonic: "add".to_string(),
            operands: vec![
                Operand::Register(rd as u8),
                Operand::Register(15),
                Operand::Immediate(imm as i32),
            ],
            condition: 0xE,
            size: 2,
        });
        return Ok(());
    }

    // B<cond> imm8
    if (hw & 0xF000) == 0xD000 {
        let cond = (hw >> 8) & 0xF;
        if cond == 0xF {
            // SWI/SVC or other, but 0xDF is SVC
            instructions.push(Instruction {
                mnemonic: "svc".to_string(),
                operands: vec![Operand::Immediate((hw & 0xFF) as i32)],
                condition: 0xE,
                size: 2,
            });
        } else {
            let imm8 = hw & 0xFF;
            let offset = (imm8 as i8 as i32) << 1;
            instructions.push(Instruction {
                mnemonic: "b".to_string(),
                operands: vec![Operand::Immediate(offset)],
                condition: cond as u8,
                size: 2,
            });
        }
        return Ok(());
    }

    // LDRB Rd, [Rn, #imm5]
    if (hw & 0xF800) == 0x7800 {
        let imm = (hw >> 6) & 0x1F;
        let rn = (hw >> 3) & 7;
        let rd = hw & 7;
        instructions.push(Instruction {
            mnemonic: "ldrb".to_string(),
            operands: vec![
                Operand::Register(rd as u8),
                Operand::Memory(rn as u8, imm as i32),
                Operand::Immediate(0b10),
            ],
            condition: 0xE,
            size: 2,
        });
        return Ok(());
    }
    // Extend instructions (UXTB, UXTH, SXTB, SXTH)
    if (hw & 0xFF00) == 0xB200 {
        let op = (hw >> 6) & 3;
        let rn = (hw >> 3) & 7;
        let rd = hw & 7;
        let mnemonic = match op {
            0 => "sxtb",
            1 => "sxth",
            2 => "uxtb",
            3 => "uxth",
            _ => "unknown",
        };
        instructions.push(Instruction {
            mnemonic: mnemonic.to_string(),
            operands: vec![Operand::Register(rd as u8), Operand::Register(rn as u8)],
            condition: 0xE,
            size: 2,
        });
        return Ok(());
    }

    // Default: unknown Thumb-16
    instructions.push(Instruction {
        mnemonic: format!("unknown_t16_{:04x}", hw),
        operands: vec![],
        condition: 0xE,
        size: 2,
    });

    Ok(())
}

fn decode_thumb32(hw1: u16, hw2: u16, instructions: &mut Vec<Instruction>) -> Result<(), String> {
    // UBFX (T1)
    if (hw1 & 0xFFF0) == 0xF3C0 {
        let rn = hw1 & 0xF;
        let rd = (hw2 >> 8) & 0xF;
        let imm3 = (hw2 >> 12) & 7;
        let imm2 = (hw2 >> 6) & 3;
        let lsb = (imm3 << 2) | imm2;
        let widthminus1 = hw2 & 0x1F;
        let width = widthminus1 + 1;

        instructions.push(Instruction {
            mnemonic: "ubfx".to_string(),
            operands: vec![
                Operand::Register(rd as u8),
                Operand::Register(rn as u8),
                Operand::Immediate(lsb as i32),
                Operand::Immediate(width as i32),
            ],
            condition: 0xE,
            size: 4,
        });
        return Ok(());
    }

    // SBFX (T1)
    if (hw1 & 0xFFF0) == 0xF340 {
        let rn = hw1 & 0xF;
        let rd = (hw2 >> 8) & 0xF;
        let imm3 = (hw2 >> 12) & 7;
        let imm2 = (hw2 >> 6) & 3;
        let lsb = (imm3 << 2) | imm2;
        let widthminus1 = hw2 & 0x1F;
        let width = widthminus1 + 1;

        instructions.push(Instruction {
            mnemonic: "sbfx".to_string(),
            operands: vec![
                Operand::Register(rd as u8),
                Operand::Register(rn as u8),
                Operand::Immediate(lsb as i32),
                Operand::Immediate(width as i32),
            ],
            condition: 0xE,
            size: 4,
        });
        return Ok(());
    }

    // BFC / BFI (T1)
    if (hw1 & 0xFFE0) == 0xF360 {
        let rn = hw1 & 0xF;
        let rd = (hw2 >> 8) & 0xF;
        let msb = hw2 & 0x1F;
        let imm3 = (hw2 >> 12) & 7;
        let imm2 = (hw2 >> 6) & 3;
        let lsb = (imm3 << 2) | imm2;
        let width = msb as i32 - lsb as i32 + 1;

        if width > 0 {
            if rn == 15 {
                // BFC
                instructions.push(Instruction {
                    mnemonic: "bfc".to_string(),
                    operands: vec![
                        Operand::Register(rd as u8),
                        Operand::Immediate(lsb as i32),
                        Operand::Immediate(width),
                    ],
                    condition: 0xE,
                    size: 4,
                });
            } else {
                // BFI
                instructions.push(Instruction {
                    mnemonic: "bfi".to_string(),
                    operands: vec![
                        Operand::Register(rd as u8),
                        Operand::Register(rn as u8),
                        Operand::Immediate(lsb as i32),
                        Operand::Immediate(width),
                    ],
                    condition: 0xE,
                    size: 4,
                });
            }
            return Ok(());
        }
    }

    // LDR (register) T2 (F85x)
    if (hw1 & 0xFFF0) == 0xF850 {
        let rn = hw1 & 0xF;
        let rt = (hw2 >> 12) & 0xF;
        let rm = hw2 & 0xF;
        let imm2 = (hw2 >> 4) & 3;

        instructions.push(Instruction {
            mnemonic: "ldr".to_string(),
            operands: vec![
                Operand::Register(rt as u8),
                Operand::Memory(rn as u8, 0),            // Base
                Operand::Shift(rm as u8, 0, imm2 as u8), // Offset
                Operand::Immediate(0b10),                // P=1, W=0
            ],
            condition: 0xE,
            size: 4,
        });
        return Ok(());
    }

    // BL/BLX (Immediate)
    if (hw1 & 0xF800) == 0xF000 && (hw2 & 0xC000) == 0xC000 {
        // Matches 1111 0xxx xxxx xxxx
        let s = (hw1 >> 10) & 1;
        let j1 = (hw2 >> 13) & 1;
        let j2 = (hw2 >> 11) & 1;
        let imm10 = hw1 & 0x3FF;
        let imm11 = hw2 & 0x7FF;

        let i1 = (!(j1 ^ s)) & 1;
        let i2 = (!(j2 ^ s)) & 1;

        let mut offset = (s as i32) << 24;
        offset |= (i1 as i32) << 23;
        offset |= (i2 as i32) << 22;
        offset |= (imm10 as i32) << 12;
        offset |= (imm11 as i32) << 1;

        // Sign extend 25-bit
        if offset & 0x01000000 != 0 {
            offset |= 0xFE000000u32 as i32;
        }

        let is_blx = (hw2 & 0x1000) == 0; // If bit 12 of hw2 is 0, it's BLX

        instructions.push(Instruction {
            mnemonic: if is_blx { "blx" } else { "bl" }.to_string(),
            operands: vec![Operand::Immediate(offset)],
            condition: 0xE,
            size: 4,
        });
        return Ok(());
    }

    // LDR/STR (Immediate) 32-bit
    if (hw1 & 0xFF00) == 0xF800 && (hw2 & 0x0800) != 0 {
        // P=1, W=0, U=1 (implied by imm12)
        let l = (hw1 >> 4) & 1;
        let rn = hw1 & 0xF;
        let rd = (hw2 >> 12) & 0xF;
        let imm12 = hw2 & 0xFFF;
        let mnemonic = if l == 1 { "ldr" } else { "str" };

        instructions.push(Instruction {
            mnemonic: mnemonic.to_string(),
            operands: vec![
                Operand::Register(rd as u8),
                Operand::Memory(rn as u8, imm12 as i32),
                Operand::Immediate(0b10), // P=1, W=0
            ],
            condition: 0xE,
            size: 4,
        });
        return Ok(());
    }

    // LDR (Literal) 32-bit
    if (hw1 & 0xFF7F) == 0xF85F {
        let u = (hw1 >> 7) & 1;
        let rd = (hw2 >> 12) & 0xF;
        let imm12 = hw2 & 0xFFF;
        let offset = if u == 1 {
            imm12 as i32
        } else {
            -(imm12 as i32)
        };

        instructions.push(Instruction {
            mnemonic: "ldr".to_string(),
            operands: vec![Operand::Register(rd as u8), Operand::Memory(15, offset)],
            condition: 0xE,
            size: 4,
        });
        return Ok(());
    }

    // LDRD/STRD (Immediate)
    if (hw1 & 0xFFE0) == 0xE9C0 {
        let p = (hw1 >> 8) & 1;
        let u = (hw1 >> 7) & 1;
        let w = (hw1 >> 5) & 1;
        let l = (hw1 >> 4) & 1;
        let rn = hw1 & 0xF;
        let rt = (hw2 >> 12) & 0xF;
        let rt2 = (hw2 >> 8) & 0xF;
        let imm8 = hw2 & 0xFF;
        let offset = (imm8 as i32) << 2;

        let mnemonic = if l == 1 { "ldrd" } else { "strd" };
        let offset_val = if u == 1 { offset } else { -offset };
        let bits = (p << 1) | w;

        instructions.push(Instruction {
            mnemonic: mnemonic.to_string(),
            operands: vec![
                Operand::Register(rt as u8),
                Operand::Register(rt2 as u8),
                Operand::Memory(rn as u8, offset_val),
                Operand::Immediate(bits as i32),
            ],
            condition: 0xE,
            size: 4,
        });
        return Ok(());
    }

    // LDREX/STREX
    if (hw1 & 0xFFC0) == 0xE840 {
        let l = (hw1 >> 4) & 1; // 1=LDREX, 0=STREX
        let rn = hw1 & 0xF;
        let rt = (hw2 >> 12) & 0xF;
        let imm8 = hw2 & 0xFF; // imm8 << 2

        if l == 1 {
            // LDREX
            instructions.push(Instruction {
                mnemonic: "ldrex".to_string(),
                operands: vec![
                    Operand::Register(rt as u8),
                    Operand::Memory(rn as u8, (imm8 as i32) << 2), // LDREX can have offset
                ],
                condition: 0xE,
                size: 4,
            });
        } else {
            // STREX Rd, Rt, [Rn, #imm]
            // STREX returns status in Rd, stores Rt to Memory
            let rd = (hw2 >> 8) & 0xF; // Status register
            instructions.push(Instruction {
                mnemonic: "strex".to_string(),
                operands: vec![
                    Operand::Register(rd as u8),
                    Operand::Register(rt as u8),
                    Operand::Memory(rn as u8, (imm8 as i32) << 2),
                ],
                condition: 0xE,
                size: 4,
            });
        }
        return Ok(());
    }

    // ADDW: F20.
    if (hw1 & 0xFFF0) == 0xF200 {
        let rn = hw1 & 0xF;
        let rd = (hw2 >> 8) & 0xF;
        let i = (hw1 >> 10) & 1;
        let imm3 = (hw2 >> 12) & 7;
        let imm8 = hw2 & 0xFF;
        let imm12 = (i as i32) << 11 | (imm3 as i32) << 8 | (imm8 as i32);
        instructions.push(Instruction {
            mnemonic: "addw".to_string(),
            operands: vec![
                Operand::Register(rd as u8),
                Operand::Register(rn as u8),
                Operand::Immediate(imm12),
            ],
            condition: 0xE,
            size: 4,
        });
        return Ok(());
    }

    // SUBW: F2A.
    if (hw1 & 0xFFF0) == 0xF2A0 {
        let rn = hw1 & 0xF;
        let rd = (hw2 >> 8) & 0xF;
        let i = (hw1 >> 10) & 1;
        let imm3 = (hw2 >> 12) & 7;
        let imm8 = hw2 & 0xFF;
        let imm12 = (i as i32) << 11 | (imm3 as i32) << 8 | (imm8 as i32);
        instructions.push(Instruction {
            mnemonic: "subw".to_string(),
            operands: vec![
                Operand::Register(rd as u8),
                Operand::Register(rn as u8),
                Operand::Immediate(imm12),
            ],
            condition: 0xE,
            size: 4,
        });
        return Ok(());
    }

    // MOVW: F24.
    if (hw1 & 0xFBF0) == 0xF240 {
        let rd = (hw2 >> 8) & 0xF;
        let i = (hw1 >> 10) & 1;
        let imm4 = hw1 & 0xF;
        let imm3 = (hw2 >> 12) & 7;
        let imm8 = hw2 & 0xFF;
        let imm16 = (imm4 as i32) << 12 | (i as i32) << 11 | (imm3 as i32) << 8 | (imm8 as i32);
        instructions.push(Instruction {
            mnemonic: "movw".to_string(),
            operands: vec![Operand::Register(rd as u8), Operand::Immediate(imm16)],
            condition: 0xE,
            size: 4,
        });
        return Ok(());
    }

    // MOVT: F2C.
    if (hw1 & 0xFBF0) == 0xF2C0 {
        let rd = (hw2 >> 8) & 0xF;
        let i = (hw1 >> 10) & 1;
        let imm4 = hw1 & 0xF;
        let imm3 = (hw2 >> 12) & 7;
        let imm8 = hw2 & 0xFF;
        let imm16 = (imm4 as i32) << 12 | (i as i32) << 11 | (imm3 as i32) << 8 | (imm8 as i32);
        instructions.push(Instruction {
            mnemonic: "movt".to_string(),
            operands: vec![Operand::Register(rd as u8), Operand::Immediate(imm16)],
            condition: 0xE,
            size: 4,
        });
        return Ok(());
    }
    if (hw1 & 0xFFF0) == 0xE8D0 && (hw2 & 0xFFE0) == 0xF000 {
        let h = (hw2 >> 4) & 1;
        let rn = hw1 & 0xF;
        let rm = hw2 & 0xF;
        instructions.push(Instruction {
            mnemonic: if h == 1 { "tbh" } else { "tbb" }.to_string(),
            operands: vec![Operand::Register(rn as u8), Operand::Register(rm as u8)],
            condition: 0xE,
            size: 4,
        });
        return Ok(());
    }

    // B<c>.W (Branch Conditional Wide) T3
    if (hw1 & 0xF800) == 0xF000 && (hw2 & 0xD000) == 0x8000 {
        let s = (hw1 >> 10) & 1;
        let cond = (hw1 >> 6) & 0xF;
        let imm6 = hw1 & 0x3F;
        let j1 = (hw2 >> 13) & 1;
        let j2 = (hw2 >> 11) & 1;
        let imm11 = hw2 & 0x7FF;

        let mut offset = (s as i32) << 20;
        offset |= (j2 as i32) << 19;
        offset |= (j1 as i32) << 18;
        offset |= (imm6 as i32) << 12;
        offset |= (imm11 as i32) << 1;

        if offset & 0x00100000 != 0 {
            offset |= 0xFFE00000u32 as i32;
        }

        // Avoid predicting AL (0xE) or invalid condition as conditional branch if unnecessary,
        // but B<c>.W allows AL (encoding T3). If cond=1110, it is AL.
        // However, standard B.W (T4) is usually preferred for AL.
        // But if code uses T3 for AL, we handle it.

        instructions.push(Instruction {
            mnemonic: "b".to_string(),
            operands: vec![Operand::Immediate(offset)],
            condition: cond as u8,
            size: 4,
        });
        return Ok(());
    }

    // B.W (Branch Wide)
    if (hw1 & 0xF800) == 0xF000 && (hw2 & 0xD000) == 0x9000 {
        let s = (hw1 >> 10) & 1;
        let j1 = (hw2 >> 13) & 1;
        let j2 = (hw2 >> 11) & 1;
        let imm10 = hw1 & 0x3FF;
        let imm11 = hw2 & 0x7FF;

        let i1 = (!(j1 ^ s)) & 1;
        let i2 = (!(j2 ^ s)) & 1;

        let mut offset = (s as i32) << 24;
        offset |= (i1 as i32) << 23;
        offset |= (i2 as i32) << 22;
        offset |= (imm10 as i32) << 12;
        offset |= (imm11 as i32) << 1;

        if offset & 0x01000000 != 0 {
            offset |= 0xFE000000u32 as i32;
        }

        instructions.push(Instruction {
            mnemonic: "b".to_string(),
            operands: vec![Operand::Immediate(offset)],
            condition: 0xE,
            size: 4,
        });
        return Ok(());
    }

    // BFC / BFI (T1)
    if (hw1 & 0xFFE0) == 0xF360 {
        let rn = hw1 & 0xF;
        let rd = (hw2 >> 8) & 0xF;
        let msb = hw2 & 0x1F;
        let imm3 = (hw2 >> 12) & 7;
        let imm2 = (hw2 >> 6) & 3;
        let lsb = (imm3 << 2) | imm2;
        let width = msb as i32 - lsb as i32 + 1;

        if width > 0 {
            if rn == 15 {
                // BFC
                instructions.push(Instruction {
                    mnemonic: "bfc".to_string(),
                    operands: vec![
                        Operand::Register(rd as u8),
                        Operand::Immediate(lsb as i32),
                        Operand::Immediate(width),
                    ],
                    condition: 0xE,
                    size: 4,
                });
            } else {
                // BFI
                instructions.push(Instruction {
                    mnemonic: "bfi".to_string(),
                    operands: vec![
                        Operand::Register(rd as u8),
                        Operand::Register(rn as u8),
                        Operand::Immediate(lsb as i32),
                        Operand::Immediate(width),
                    ],
                    condition: 0xE,
                    size: 4,
                });
            }
            return Ok(());
        }
    }

    // LDR (register) T2 (F85x)
    if (hw1 & 0xFFF0) == 0xF850 {
        let rn = hw1 & 0xF;
        let rt = (hw2 >> 12) & 0xF;
        let rm = hw2 & 0xF;
        let imm2 = (hw2 >> 4) & 3;

        instructions.push(Instruction {
            mnemonic: "ldr".to_string(),
            operands: vec![
                Operand::Register(rt as u8),
                Operand::Memory(rn as u8, 0),            // Base
                Operand::Shift(rm as u8, 0, imm2 as u8), // Offset
                Operand::Immediate(0b10),                // P=1, W=0
            ],
            condition: 0xE,
            size: 4,
        });
        return Ok(());
    }

    // ADD/SUB (register) T2/T3 (EB0x / EBAx)
    if (hw1 & 0xFF00) == 0xEB00 {
        let op = (hw1 >> 4) & 0xF;
        let rn = hw1 & 0xF;
        let rd = (hw2 >> 8) & 0xF;
        let rm = hw2 & 0xF;
        let type_ = (hw2 >> 4) & 3;
        let imm3 = (hw2 >> 12) & 7;
        let imm2 = (hw2 >> 6) & 3;
        let amount = ((imm3 << 2) | imm2) as u8;

        if op == 0 {
            // ADD
            instructions.push(Instruction {
                mnemonic: "add".to_string(),
                operands: vec![
                    Operand::Register(rd as u8),
                    Operand::Register(rn as u8),
                    Operand::Shift(rm as u8, type_ as u8, amount),
                ],
                condition: 0xE,
                size: 4,
            });
            return Ok(());
        } else if op == 0xA {
            // SUB
            instructions.push(Instruction {
                mnemonic: "sub".to_string(),
                operands: vec![
                    Operand::Register(rd as u8),
                    Operand::Register(rn as u8),
                    Operand::Shift(rm as u8, type_ as u8, amount),
                ],
                condition: 0xE,
                size: 4,
            });
            return Ok(());
        }
    }

    // Data processing (Modified immediate)
    if ((hw1 & 0xFB00) == 0xF100 || (hw1 & 0xFB00) == 0xF000) && (hw2 & 0x8000) == 0 {
        let rn = (hw1 >> 0) & 0xF;
        let rd = (hw2 >> 8) & 0xF;
        let i = (hw1 >> 10) & 1;
        let imm3 = (hw2 >> 12) & 7;
        let imm8 = hw2 & 0xFF;

        let op = (hw1 >> 5) & 0xF;
        let s = (hw1 >> 4) & 1;

        // Very simplified ARM modified immediate
        let imm = (i << 11) | (imm3 << 8) | imm8;

        let mnemonic_base = match op {
            0x0 => {
                if rd == 0xF && s == 1 {
                    "tst"
                } else {
                    "and"
                }
            }
            0x1 => "bic",
            0x2 => {
                if rn == 0xF {
                    "mov"
                } else {
                    "orr"
                }
            }
            0x3 => {
                if rn == 0xF {
                    "mvn"
                } else {
                    "orn"
                }
            }
            0x4 => {
                if rd == 0xF && s == 1 {
                    "teq"
                } else {
                    "eor"
                }
            }
            0x8 => {
                if rd == 0xF && s == 1 {
                    "cmn"
                } else {
                    "add"
                }
            }
            0xA => "adc",
            0xB => "sbc",
            0xD => {
                if rd == 0xF && s == 1 {
                    "cmp"
                } else {
                    "sub"
                }
            }
            0xE => "rsb",
            _ => "unknown_dp_t32",
        };

        let mut mnemonic = mnemonic_base.to_string();
        if s == 1
            && !mnemonic.ends_with('t')
            && mnemonic != "cmp"
            && mnemonic != "cmn"
            && mnemonic != "tst"
            && mnemonic != "teq"
        {
            mnemonic.push('s');
        }

        instructions.push(Instruction {
            mnemonic,
            operands: vec![
                Operand::Register(rd as u8),
                Operand::Register(rn as u8),
                Operand::Immediate(imm as i32),
            ],
            condition: 0xE,
            size: 4,
        });
        return Ok(());
    }

    // PUSH.W / POP.W / LDM / STM wide
    if (hw1 & 0xFE40) == 0xE800 {
        let l = (hw1 >> 4) & 1; // Load/Store
        let rn = hw1 & 0xF;
        let p = (hw1 >> 8) & 1; // Pre/Post
        let u = (hw1 >> 7) & 1; // Up/Down
        let w = (hw1 >> 5) & 1; // Write-back
        let reg_list = hw2 as u32;

        let mnemonic = if l == 1 {
            if rn == 13 && p == 0 && u == 1 && w == 1 {
                "pop"
            } else {
                "ldm"
            }
        } else {
            if rn == 13 && p == 1 && u == 0 && w == 1 {
                "push"
            } else {
                "stm"
            }
        };

        let mut operands = vec![Operand::Register(rn as u8)];
        operands.push(Operand::Immediate(reg_list as i32));
        // bits: P, U, W
        operands.push(Operand::Immediate(((p << 2) | (u << 1) | w) as i32));

        instructions.push(Instruction {
            mnemonic: mnemonic.to_string(),
            operands,
            condition: 0xE,
            size: 4,
        });
        return Ok(());
    }

    // PUSH.W variant 2
    if (hw1 & 0xFFF0) == 0xE920 {
        let rn = hw1 & 0xF;
        if rn == 13 {
            let reg_list = hw2 as u32;
            instructions.push(Instruction {
                mnemonic: "push".to_string(),
                operands: vec![Operand::Immediate(reg_list as i32)],
                condition: 0xE,
                size: 4,
            });
            return Ok(());
        }
    }

    // LDR.W Rd, [PC, #imm12]
    if (hw1 & 0xFF7F) == 0xF85F {
        let rd = (hw2 >> 12) & 0xF;
        let imm = hw2 & 0xFFF;
        instructions.push(Instruction {
            mnemonic: "ldr".to_string(),
            operands: vec![Operand::Register(rd as u8), Operand::Memory(15, imm as i32)],
            condition: 0xE,
            size: 4,
        });
        return Ok(());
    }

    // LDR/STR (Immediate/Register offset)
    if (hw1 & 0xFE00) == 0xF800 {
        let rn = hw1 & 0xF;
        let rt = (hw2 >> 12) & 0xF;

        let op_bits = (hw1 >> 4) & 0x1F;
        let mnemonic = match op_bits {
            0x08 | 0x28 => "strb",
            0x09 | 0x29 => "ldrb",
            0x10 | 0x30 => "strh",
            0x11 | 0x31 => "ldrh",
            0x18 | 0x38 | 0x0C | 0x2C => "str",
            0x19 | 0x39 | 0x0D | 0x2D => "ldr",
            _ => "unknown_t32_ls",
        };

        if mnemonic != "unknown_t32_ls" {
            let mut operands = vec![Operand::Register(rt as u8)];
            if (hw2 & 0x0800) != 0 {
                // 12-bit immediate
                let imm = hw2 & 0x0FFF;
                operands.push(Operand::Memory(rn as u8, imm as i32));
                // Add P=1, W=0 (bits 0b10) for normal immediate
                operands.push(Operand::Immediate(0b10));
            } else {
                // 8-bit immediate with P, U, W or register offset
                let sub_op = (hw2 >> 8) & 7;
                if sub_op == 0 {
                    // Register offset
                    let rm = hw2 & 0xF;
                    operands.push(Operand::Memory(rn as u8, 0));
                    operands.push(Operand::Register(rm as u8));
                } else {
                    // 8-bit immediate
                    let p = (hw2 >> 10) & 1;
                    let u = (hw2 >> 9) & 1;
                    let w = (hw2 >> 8) & 1;
                    let imm8 = hw2 & 0xFF;
                    let offset = if u == 1 { imm8 as i32 } else { -(imm8 as i32) };
                    operands.push(Operand::Memory(rn as u8, offset));
                    operands.push(Operand::Immediate(((p << 1) | w) as i32));
                }
            }

            instructions.push(Instruction {
                mnemonic: mnemonic.to_string(),
                operands,
                condition: 0xE,
                size: 4,
            });
            return Ok(());
        }
    }

    // Default: unknown Thumb-32
    instructions.push(Instruction {
        mnemonic: format!("unknown_t32_{:04x}_{:04x}", hw1, hw2),
        operands: vec![],
        condition: 0xE,
        size: 4,
    });

    Ok(())
}

fn decode_data_processing(
    word: u32,
    cond: u32,
    instructions: &mut Vec<Instruction>,
) -> Result<(), String> {
    let s = (word >> 20) & 1;
    let opcode = (word >> 21) & 0xF;
    let rd = (word >> 12) & 0xF;
    let rn = (word >> 16) & 0xF;
    let rm = word & 0xF;

    // Check for BX (Branch and Exchange)
    if (word & 0x0FFFFFF0) == 0x012FFF10 {
        instructions.push(Instruction {
            mnemonic: "bx".to_string(),
            operands: vec![Operand::Register(rm as u8)],
            condition: cond as u8,
            size: 4,
        });
        return Ok(());
    }

    let mnemonic_base = match opcode {
        0x0 => "and",
        0x1 => "eor",
        0x2 => "sub",
        0x3 => "rsb",
        0x4 => "add",
        0x5 => "adc",
        0x6 => "sbc",
        0x7 => "rsc",
        0x8 => "tst",
        0x9 => "teq",
        0xA => "cmp",
        0xB => "cmn",
        0xC => "orr",
        0xD => "mov",
        0xE => "bic",
        0xF => "mvn",
        _ => "unknown",
    };

    let mut mnemonic = mnemonic_base.to_string();
    if s == 1 && !matches!(mnemonic_base, "cmp" | "tst" | "teq" | "cmn") {
        mnemonic.push('s');
    }

    let mut operands = Vec::new();
    match mnemonic_base {
        "mov" | "mvn" => {
            operands.push(Operand::Register(rd as u8));
            operands.push(Operand::Register(rm as u8));
        }
        "cmp" | "tst" | "teq" | "cmn" => {
            operands.push(Operand::Register(rn as u8));
            operands.push(Operand::Register(rm as u8));
        }
        _ => {
            operands.push(Operand::Register(rd as u8));
            operands.push(Operand::Register(rn as u8));
            operands.push(Operand::Register(rm as u8));
        }
    }

    instructions.push(Instruction {
        mnemonic,
        operands,
        condition: cond as u8,
        size: 4,
    });

    Ok(())
}

fn decode_data_processing_imm(
    word: u32,
    cond: u32,
    instructions: &mut Vec<Instruction>,
) -> Result<(), String> {
    let s = (word >> 20) & 1;
    let opcode = (word >> 21) & 0xF;
    let rd = (word >> 12) & 0xF;
    let rn = (word >> 16) & 0xF;
    let imm_val = word & 0xFF;
    let rotate = (word >> 8) & 0xF;

    // ARM immediate rotation: value is rotated right by (rotate * 2) bits
    let imm = imm_val.rotate_right(rotate * 2);

    let mnemonic_base = match opcode {
        0x0 => "and",
        0x1 => "eor",
        0x2 => "sub",
        0x3 => "rsb",
        0x4 => "add",
        0x5 => "adc",
        0x6 => "sbc",
        0x7 => "rsc",
        0x8 => "tst",
        0x9 => "teq",
        0xA => "cmp",
        0xB => "cmn",
        0xC => "orr",
        0xD => "mov",
        0xE => "bic",
        0xF => "mvn",
        _ => "unknown",
    };

    let mut mnemonic = mnemonic_base.to_string();
    if s == 1 && !matches!(mnemonic_base, "cmp" | "tst" | "teq" | "cmn") {
        mnemonic.push('s');
    }

    let mut operands = Vec::new();
    match mnemonic_base {
        "mov" | "mvn" => {
            operands.push(Operand::Register(rd as u8));
            operands.push(Operand::Immediate(imm as i32));
        }
        "cmp" | "tst" | "teq" | "cmn" => {
            operands.push(Operand::Register(rn as u8));
            operands.push(Operand::Immediate(imm as i32));
        }
        _ => {
            operands.push(Operand::Register(rd as u8));
            operands.push(Operand::Register(rn as u8));
            operands.push(Operand::Immediate(imm as i32));
        }
    }

    instructions.push(Instruction {
        mnemonic,
        operands,
        condition: cond as u8,
        size: 4,
    });

    Ok(())
}

fn decode_load_store(
    word: u32,
    cond: u32,
    instructions: &mut Vec<Instruction>,
) -> Result<(), String> {
    let p = (word >> 24) & 1; // Pre/Post index
    let u = (word >> 23) & 1; // Up/Down bit
    let w = (word >> 21) & 1; // Write-back
    let l = (word >> 20) & 1; // Load/Store
    let rd = (word >> 12) & 0xF;
    let rn = (word >> 16) & 0xF;
    let offset = word & 0xFFF;

    let mnemonic = if l == 1 { "ldr" } else { "str" };

    // Apply sign based on U bit
    let signed_offset = if u == 1 {
        offset as i32
    } else {
        -(offset as i32)
    };

    instructions.push(Instruction {
        mnemonic: mnemonic.to_string(),
        operands: vec![
            Operand::Register(rd as u8),
            Operand::Memory(rn as u8, signed_offset),
            Operand::Immediate(((p << 1) | w) as i32),
        ],
        condition: cond as u8,
        size: 4,
    });

    Ok(())
}

fn decode_branch(word: u32, cond: u32, instructions: &mut Vec<Instruction>) -> Result<(), String> {
    let l = (word >> 24) & 1;
    let offset = word & 0xFFFFFF;

    // Sign extend 24-bit offset to 32-bit
    let signed_offset = if offset & 0x800000 != 0 {
        ((offset | 0xFF000000) as i32) << 2
    } else {
        (offset as i32) << 2
    };

    let mnemonic = if l == 1 { "bl" } else { "b" };

    instructions.push(Instruction {
        mnemonic: mnemonic.to_string(),
        operands: vec![Operand::Immediate(signed_offset)],
        condition: cond as u8,
        size: 4,
    });

    Ok(())
}

fn decode_ldm_stm(word: u32, cond: u32, instructions: &mut Vec<Instruction>) -> Result<(), String> {
    let p = (word >> 24) & 1; // Pre/Post index
    let u = (word >> 23) & 1; // Up/Down
    let _s = (word >> 22) & 1; // PSR or force user mode
    let w = (word >> 21) & 1; // Write-back
    let l = (word >> 20) & 1; // Load/Store
    let rn = (word >> 16) & 0xF;
    let reg_list = word & 0xFFFF;

    let mnemonic = if l == 1 { "ldm" } else { "stm" };

    // Add base register
    let mut operands = vec![Operand::Register(rn as u8)];

    // Add bitmask as an immediate (simplified)
    operands.push(Operand::Immediate(reg_list as i32));

    // Add P, U, W bits as an immediate to help executor
    let bits = (p << 2) | (u << 1) | w;
    operands.push(Operand::Immediate(bits as i32));

    instructions.push(Instruction {
        mnemonic: mnemonic.to_string(),
        operands,
        condition: cond as u8,
        size: 4,
    });

    Ok(())
}
