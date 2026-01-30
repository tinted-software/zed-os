#[derive(Debug, Clone)]
pub struct Instruction {
    pub mnemonic: String,
    pub operands: Vec<Operand>,
    pub condition: u8,
}

#[derive(Debug, Clone)]
pub enum Operand {
    Register(u8),
    Immediate(i32),
    RegShift(u8, u8),
    Memory(u8, i32),
}

pub fn decode(code: &[u8]) -> Result<Vec<Instruction>, String> {
    let mut instructions = Vec::new();
    let mut pc = 0;

    while pc < code.len() {
        if pc + 4 > code.len() {
            break;
        }
        let word = u32::from_le_bytes([code[pc], code[pc + 1], code[pc + 2], code[pc + 3]]);

        let cond = (word >> 28) & 0xF;
        let op = (word >> 25) & 0x7;

        match op {
            0b000 => decode_data_processing(word, cond, &mut instructions)?,
            0b001 => decode_data_processing_imm(word, cond, &mut instructions)?,
            0b010 => decode_load_store(word, cond, &mut instructions)?,
            0b100 => decode_ldm_stm(word, cond, &mut instructions)?,
            0b101 => decode_branch(word, cond, &mut instructions)?,
            _ => {
                // Unknown instruction, skip
                instructions.push(Instruction {
                    mnemonic: "nop".to_string(),
                    operands: vec![],
                    condition: cond as u8,
                });
            }
        }

        pc += 4;
    }

    Ok(instructions)
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
    });

    Ok(())
}

fn decode_ldm_stm(word: u32, cond: u32, instructions: &mut Vec<Instruction>) -> Result<(), String> {
    let p = (word >> 24) & 1; // Pre/Post index
    let u = (word >> 23) & 1; // Up/Down
    let s = (word >> 22) & 1; // PSR or force user mode
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
    });

    Ok(())
}
