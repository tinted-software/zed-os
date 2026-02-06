use crate::decoder::{Instruction, Operand};
use cranelift::codegen::isa::CallConv;
use cranelift::jit::{JITBuilder, JITModule};
use cranelift::module::{Linkage, Module};
use cranelift::prelude::*;
use std::collections::HashMap;

pub struct Jit {
    module: JITModule,
    ctx: codegen::Context,
    builder_ctx: FunctionBuilderContext,
    cache: HashMap<u32, *const u8>,
}

impl Jit {
    pub fn new() -> Self {
        let mut flag_builder = settings::builder();
        flag_builder.set("use_colocated_libcalls", "false").unwrap();
        flag_builder.set("is_pic", "false").unwrap();
        let isa_builder = cranelift::native::builder().unwrap_or_else(|msg| {
            panic!("host machine is not supported: {}", msg);
        });
        let isa = isa_builder
            .finish(settings::Flags::new(flag_builder))
            .unwrap();
        let builder = JITBuilder::with_isa(isa, cranelift::module::default_libcall_names());

        let module = JITModule::new(builder);
        Self {
            module,
            ctx: codegen::Context::new(),
            builder_ctx: FunctionBuilderContext::new(),
            cache: HashMap::new(),
        }
    }

    pub fn get_block(&self, addr: u32) -> Option<*const u8> {
        self.cache.get(&addr).copied()
    }

    fn check_block_supported(&self, instructions: &[(u32, Instruction)]) -> bool {
        if instructions.is_empty() {
            return false;
        }
        for (_, insn) in instructions {
            if !is_insn_supported(insn) {
                return false;
            }
        }
        true
    }

    pub fn compile_block(
        &mut self,
        addr: u32,
        instructions: &[(u32, Instruction)],
        is_thumb: bool,
    ) -> Option<*const u8> {
        if let Some(ptr) = self.cache.get(&addr) {
            return Some(*ptr);
        }

        if !self.check_block_supported(instructions) {
            return None;
        }

        self.ctx.func.clear();
        self.ctx
            .func
            .signature
            .params
            .push(AbiParam::new(types::I64)); // cpu ptr
        self.ctx
            .func
            .signature
            .params
            .push(AbiParam::new(types::I64)); // regs ptr
        self.ctx
            .func
            .signature
            .params
            .push(AbiParam::new(types::I64)); // ram ptr
        self.ctx
            .func
            .signature
            .params
            .push(AbiParam::new(types::I64)); // cpsr ptr
        self.ctx
            .func
            .signature
            .params
            .push(AbiParam::new(types::I64)); // read_helper
        self.ctx
            .func
            .signature
            .params
            .push(AbiParam::new(types::I64)); // write_helper

        let mut builder = FunctionBuilder::new(&mut self.ctx.func, &mut self.builder_ctx);
        let block = builder.create_block();
        builder.append_block_params_for_function_params(block);
        builder.switch_to_block(block);

        let cpu_ptr = builder.block_params(block)[0];
        let regs_ptr = builder.block_params(block)[1];
        let ram_ptr = builder.block_params(block)[2];
        let cpsr_ptr = builder.block_params(block)[3];
        let read_helper = builder.block_params(block)[4];
        let write_helper = builder.block_params(block)[5];

        let mut terminal = false;
        for (insn_pc, insn) in instructions {
            let pc_val = builder.ins().iconst(types::I32, *insn_pc as i64);
            store_reg(&mut builder, regs_ptr, 15, pc_val);

            if translate_insn(
                &mut builder,
                insn,
                cpu_ptr,
                regs_ptr,
                ram_ptr,
                cpsr_ptr,
                read_helper,
                write_helper,
                *insn_pc,
                is_thumb,
            ) {
                terminal = true;
                break;
            }

            let next_pc = builder
                .ins()
                .iconst(types::I32, (*insn_pc + insn.size as u32) as i64);
            store_reg(&mut builder, regs_ptr, 15, next_pc);
        }

        if !terminal {
            builder.ins().return_(&[]);
        }
        builder.seal_block(block);
        builder.finalize();

        let id = self
            .module
            .declare_function(
                &format!("block_{:x}", addr),
                Linkage::Export,
                &self.ctx.func.signature,
            )
            .unwrap();
        self.module.define_function(id, &mut self.ctx).unwrap();
        self.module.clear_context(&mut self.ctx);
        self.module.finalize_definitions().unwrap();
        let code = self.module.get_finalized_function(id);
        self.cache.insert(addr, code);
        Some(code)
    }
}

fn is_insn_supported(insn: &Instruction) -> bool {
    // Basic ARM/Thumb instructions
    match insn.mnemonic.as_str() {
        "mov" | "movs" | "mov.w" | "mvn" | "mvns" => true,
        "add" | "adds" | "add.w" | "addw" => true,
        "sub" | "subs" | "sub.w" | "subw" | "rsb" | "rsbs" => true,
        "and" | "ands" | "orr" | "orrs" | "eor" | "eors" | "bic" | "bics" => true,
        "lsl" | "lsls" | "lsr" | "lsrs" | "asr" | "asrs" | "ror" | "rors" => true,
        "cmp" | "cmp.w" | "cmn" | "tst" | "teq" => true,
        "ldr" | "str" | "ldrb" | "strb" | "ldrh" | "strh" => {
            if insn.operands.len() < 2 {
                return false;
            }
            true
        }
        "b" | "beq" | "bne" | "bcs" | "bcc" | "bmi" | "bpl" | "bhi" | "bls" | "bge" | "blt"
        | "bgt" | "ble" => {
            if insn.operands.is_empty() {
                return false;
            }
            matches!(insn.operands[0], Operand::Immediate(_))
        }
        "bl" | "blx" | "bx" => true,
        "push" | "pop" | "push.w" | "pop.w" => true,
        "ldm" | "stm" | "ldmia" | "stmia" | "ldmdb" | "stmdb" => true,
        "nop" => true,
        "ubfx" | "sbfx" | "bfc" | "bfi" => true,
        "clz" => true,
        _ => false,
    }
}

fn translate_insn(
    builder: &mut FunctionBuilder,
    insn: &Instruction,
    cpu_ptr: Value,
    regs_ptr: Value,
    ram_ptr: Value,
    cpsr_ptr: Value,
    read_helper: Value,
    write_helper: Value,
    insn_pc: u32,
    is_thumb: bool,
) -> bool {
    let mut terminal = false;

    // Handle condition code wrapping for non-branch instructions
    let is_branch_mnemonic = matches!(
        insn.mnemonic.as_str(),
        "b" | "beq"
            | "bne"
            | "bcs"
            | "bcc"
            | "bmi"
            | "bpl"
            | "bhi"
            | "bls"
            | "bge"
            | "blt"
            | "bgt"
            | "ble"
            | "bl"
            | "blx"
            | "bx"
    );

    let cond_block: Option<(Block, Block)> = None;

    match insn.mnemonic.as_str() {
        "mov" | "movs" | "mov.w" => {
            if insn.operands.len() >= 2 {
                let val = load_operand(builder, &insn.operands[1], regs_ptr, insn_pc, is_thumb);
                if let Operand::Register(rd) = insn.operands[0] {
                    store_reg(builder, regs_ptr, rd, val);
                    if insn.mnemonic.contains('s') {
                        update_flags_zn(builder, cpsr_ptr, val);
                    }
                    if rd == 15 {
                        builder.ins().return_(&[]);
                        terminal = true;
                    }
                }
            }
        }
        "mvn" | "mvns" => {
            if insn.operands.len() >= 2 {
                let val = load_operand(builder, &insn.operands[1], regs_ptr, insn_pc, is_thumb);
                let res = builder.ins().bnot(val);
                if let Operand::Register(rd) = insn.operands[0] {
                    store_reg(builder, regs_ptr, rd, res);
                    if insn.mnemonic.contains('s') {
                        update_flags_zn(builder, cpsr_ptr, res);
                    }
                }
            }
        }
        "add" | "adds" | "add.w" | "addw" => {
            if insn.operands.len() >= 2 {
                let lhs = load_operand(
                    builder,
                    if insn.operands.len() == 3 {
                        &insn.operands[1]
                    } else {
                        &insn.operands[0]
                    },
                    regs_ptr,
                    insn_pc,
                    is_thumb,
                );
                let rhs = load_operand(
                    builder,
                    if insn.operands.len() == 3 {
                        &insn.operands[2]
                    } else {
                        &insn.operands[1]
                    },
                    regs_ptr,
                    insn_pc,
                    is_thumb,
                );
                let res = builder.ins().iadd(lhs, rhs);
                if let Operand::Register(rd) = insn.operands[0] {
                    store_reg(builder, regs_ptr, rd, res);
                    if insn.mnemonic.contains('s') {
                        update_flags_zn(builder, cpsr_ptr, res);
                    }
                    if rd == 15 {
                        builder.ins().return_(&[]);
                        terminal = true;
                    }
                }
            }
        }
        "sub" | "subs" | "sub.w" | "subw" => {
            if insn.operands.len() >= 2 {
                let lhs = load_operand(
                    builder,
                    if insn.operands.len() == 3 {
                        &insn.operands[1]
                    } else {
                        &insn.operands[0]
                    },
                    regs_ptr,
                    insn_pc,
                    is_thumb,
                );
                let rhs = load_operand(
                    builder,
                    if insn.operands.len() == 3 {
                        &insn.operands[2]
                    } else {
                        &insn.operands[1]
                    },
                    regs_ptr,
                    insn_pc,
                    is_thumb,
                );
                let res = builder.ins().isub(lhs, rhs);
                if let Operand::Register(rd) = insn.operands[0] {
                    store_reg(builder, regs_ptr, rd, res);
                    if insn.mnemonic.contains('s') {
                        update_flags_zn(builder, cpsr_ptr, res);
                    }
                    if rd == 15 {
                        builder.ins().return_(&[]);
                        terminal = true;
                    }
                }
            }
        }
        "rsb" | "rsbs" => {
            if insn.operands.len() >= 2 {
                let lhs = load_operand(
                    builder,
                    if insn.operands.len() == 3 {
                        &insn.operands[1]
                    } else {
                        &insn.operands[0]
                    },
                    regs_ptr,
                    insn_pc,
                    is_thumb,
                );
                let rhs = load_operand(
                    builder,
                    if insn.operands.len() == 3 {
                        &insn.operands[2]
                    } else {
                        &insn.operands[1]
                    },
                    regs_ptr,
                    insn_pc,
                    is_thumb,
                );
                let res = builder.ins().isub(rhs, lhs);
                if let Operand::Register(rd) = insn.operands[0] {
                    store_reg(builder, regs_ptr, rd, res);
                    if insn.mnemonic.contains('s') {
                        update_flags_zn(builder, cpsr_ptr, res);
                    }
                }
            }
        }
        "and" | "ands" | "orr" | "orrs" | "eor" | "eors" | "bic" | "bics" => {
            if insn.operands.len() >= 2 {
                let lhs = load_operand(
                    builder,
                    if insn.operands.len() == 3 {
                        &insn.operands[1]
                    } else {
                        &insn.operands[0]
                    },
                    regs_ptr,
                    insn_pc,
                    is_thumb,
                );
                let rhs = load_operand(
                    builder,
                    if insn.operands.len() == 3 {
                        &insn.operands[2]
                    } else {
                        &insn.operands[1]
                    },
                    regs_ptr,
                    insn_pc,
                    is_thumb,
                );
                let res = match insn.mnemonic.as_str() {
                    "and" | "ands" => builder.ins().band(lhs, rhs),
                    "orr" | "orrs" => builder.ins().bor(lhs, rhs),
                    "eor" | "eors" => builder.ins().bxor(lhs, rhs),
                    _ => {
                        let inv_rhs = builder.ins().bnot(rhs);
                        builder.ins().band(lhs, inv_rhs)
                    }
                };
                if let Operand::Register(rd) = insn.operands[0] {
                    store_reg(builder, regs_ptr, rd, res);
                    if insn.mnemonic.contains('s') {
                        update_flags_zn(builder, cpsr_ptr, res);
                    }
                }
            }
        }
        "lsl" | "lsls" | "lsr" | "lsrs" | "asr" | "asrs" => {
            if insn.operands.len() >= 2 {
                let lhs = load_operand(
                    builder,
                    if insn.operands.len() == 3 {
                        &insn.operands[1]
                    } else {
                        &insn.operands[0]
                    },
                    regs_ptr,
                    insn_pc,
                    is_thumb,
                );
                let rhs = load_operand(
                    builder,
                    if insn.operands.len() == 3 {
                        &insn.operands[2]
                    } else {
                        &insn.operands[1]
                    },
                    regs_ptr,
                    insn_pc,
                    is_thumb,
                );
                let res = match insn.mnemonic.as_str() {
                    "lsl" | "lsls" => builder.ins().ishl(lhs, rhs),
                    "lsr" | "lsrs" => builder.ins().ushr(lhs, rhs),
                    _ => builder.ins().sshr(lhs, rhs), // asr
                };
                if let Operand::Register(rd) = insn.operands[0] {
                    store_reg(builder, regs_ptr, rd, res);
                    if insn.mnemonic.contains('s') {
                        update_flags_zn(builder, cpsr_ptr, res);
                    }
                }
            }
        }
        "cmp" | "cmp.w" => {
            if insn.operands.len() >= 2 {
                let lhs = load_operand(builder, &insn.operands[0], regs_ptr, insn_pc, is_thumb);
                let rhs = load_operand(builder, &insn.operands[1], regs_ptr, insn_pc, is_thumb);
                update_flags_cmp(builder, cpsr_ptr, lhs, rhs);
            }
        }
        "cmn" | "tst" | "teq" => {
            if insn.operands.len() >= 2 {
                let lhs = load_operand(builder, &insn.operands[0], regs_ptr, insn_pc, is_thumb);
                let rhs = load_operand(builder, &insn.operands[1], regs_ptr, insn_pc, is_thumb);
                let res = match insn.mnemonic.as_str() {
                    "cmn" => builder.ins().iadd(lhs, rhs),
                    "tst" => builder.ins().band(lhs, rhs),
                    _ => builder.ins().bxor(lhs, rhs), // teq
                };
                update_flags_zn(builder, cpsr_ptr, res);
            }
        }
        "ldr" | "str" | "ldrb" | "strb" | "ldrh" | "strh" => {
            let is_load = insn.mnemonic.starts_with('l');
            let ty = if insn.mnemonic.ends_with('b') {
                types::I8
            } else if insn.mnemonic.ends_with('h') {
                types::I16
            } else {
                types::I32
            };
            let bits = if insn.operands.len() >= 3 {
                if let Operand::Immediate(b) = insn.operands[2] {
                    b as u8
                } else {
                    0b10
                }
            } else {
                0b10
            };
            let p = (bits >> 1) & 1;
            let w = bits & 1;

            if let (Operand::Register(rt), Operand::Memory(rn, offset)) =
                (&insn.operands[0], &insn.operands[1])
            {
                let base = load_reg_with_pc(builder, regs_ptr, *rn, insn_pc, is_thumb);
                let off_val = builder.ins().iconst(types::I32, *offset as i64);
                let addr = if p == 1 {
                    builder.ins().iadd(base, off_val)
                } else {
                    base
                };

                if is_load {
                    let val = jit_mem_read(builder, cpu_ptr, ram_ptr, read_helper, addr, ty);
                    store_reg(builder, regs_ptr, *rt, val);
                    if *rt == 15 {
                        builder.ins().return_(&[]);
                        terminal = true;
                    }
                } else {
                    let val = load_reg(builder, regs_ptr, *rt);
                    jit_mem_write(builder, cpu_ptr, ram_ptr, write_helper, addr, val, ty);
                }
                if w == 1 || p == 0 {
                    let new_base = builder.ins().iadd(base, off_val);
                    store_reg(builder, regs_ptr, *rn, new_base);
                }
            }
        }
        "b" | "beq" | "bne" | "bcs" | "bcc" | "bmi" | "bpl" | "bhi" | "bls" | "bge" | "blt"
        | "bgt" | "ble" => {
            if let Operand::Immediate(offset) = insn.operands[0] {
                let target_pc = (insn_pc as i32 + (if is_thumb { 4 } else { 8 }) + offset) as u32;
                let target_val = builder.ins().iconst(types::I32, target_pc as i64);
                let next_pc_val = builder
                    .ins()
                    .iconst(types::I32, (insn_pc + insn.size as u32) as i64);

                let cond = if insn.mnemonic == "b" {
                    insn.condition
                } else {
                    match &insn.mnemonic[1..] {
                        "eq" => 0x0,
                        "ne" => 0x1,
                        "cs" => 0x2,
                        "cc" => 0x3,
                        "mi" => 0x4,
                        "pl" => 0x5,
                        "vs" => 0x6,
                        "vc" => 0x7,
                        "hi" => 0x8,
                        "ls" => 0x9,
                        "ge" => 0xA,
                        "lt" => 0xB,
                        "gt" => 0xC,
                        "le" => 0xD,
                        _ => 0xE,
                    }
                };

                if cond == 0xE {
                    store_reg(builder, regs_ptr, 15, target_val);
                } else {
                    let cond_met = check_cond_jit(builder, cpsr_ptr, cond);
                    let final_pc = builder.ins().select(cond_met, target_val, next_pc_val);
                    store_reg(builder, regs_ptr, 15, final_pc);
                }
                builder.ins().return_(&[]);
                terminal = true;
            }
        }
        "bl" | "blx" => {
            let target = match insn.operands[0] {
                Operand::Immediate(offset) => {
                    (insn_pc as i32 + (if is_thumb { 4 } else { 8 }) + offset) as u32
                }
                _ => 0,
            };
            let lr_val = builder
                .ins()
                .iconst(types::I32, (insn_pc + insn.size as u32) as i64 | 1);
            store_reg(builder, regs_ptr, 14, lr_val);
            if let Operand::Register(r) = insn.operands[0] {
                let target_reg = load_reg(builder, regs_ptr, r);
                store_reg(builder, regs_ptr, 15, target_reg);
            } else {
                let target_val = builder.ins().iconst(types::I32, target as i64);
                store_reg(builder, regs_ptr, 15, target_val);
            }
            builder.ins().return_(&[]);
            terminal = true;
        }
        "bx" => {
            if let Operand::Register(r) = insn.operands[0] {
                let target = load_reg(builder, regs_ptr, r);
                store_reg(builder, regs_ptr, 15, target);
                builder.ins().return_(&[]);
                terminal = true;
            }
        }
        "push" | "push.w" => {
            if let Operand::Immediate(reg_list) = insn.operands[0] {
                let mut sp = load_reg(builder, regs_ptr, 13);
                let bits = reg_list as u32;
                for i in (0..16).rev() {
                    if (bits >> i) & 1 == 1 {
                        sp = builder.ins().iadd_imm(sp, -4);
                        let val = load_reg(builder, regs_ptr, i as u8);
                        jit_mem_write(builder, cpu_ptr, ram_ptr, write_helper, sp, val, types::I32);
                    }
                }
                store_reg(builder, regs_ptr, 13, sp);
            }
        }
        "pop" | "pop.w" => {
            if let Operand::Immediate(reg_list) = insn.operands[0] {
                let mut sp = load_reg(builder, regs_ptr, 13);
                let bits = reg_list as u32;
                let mut pc_updated = false;
                for i in 0..16 {
                    if (bits >> i) & 1 == 1 {
                        let val =
                            jit_mem_read(builder, cpu_ptr, ram_ptr, read_helper, sp, types::I32);
                        store_reg(builder, regs_ptr, i as u8, val);
                        sp = builder.ins().iadd_imm(sp, 4);
                        if i == 15 {
                            pc_updated = true;
                        }
                    }
                }
                store_reg(builder, regs_ptr, 13, sp);
                if pc_updated {
                    builder.ins().return_(&[]);
                    terminal = true;
                }
            }
        }
        "ldm" | "ldmia" | "ldmdb" | "stm" | "stmia" | "stmdb" => {
            if let (Operand::Register(rn), Operand::Immediate(reg_list), Operand::Immediate(bits)) =
                (&insn.operands[0], &insn.operands[1], &insn.operands[2])
            {
                let is_load = insn.mnemonic.starts_with('l');
                let u = (bits >> 1) & 1;
                let w = bits & 1;
                let mut addr = load_reg(builder, regs_ptr, *rn);
                let mask_val = *reg_list as u32;
                if u == 0 {
                    addr = builder
                        .ins()
                        .iadd_imm(addr, -((mask_val.count_ones() * 4) as i64));
                }
                let start_addr = addr;
                let mut curr_addr = start_addr;
                let mut pc_updated = false;
                for i in 0..16 {
                    if (mask_val >> i) & 1 == 1 {
                        if is_load {
                            let val = jit_mem_read(
                                builder,
                                cpu_ptr,
                                ram_ptr,
                                read_helper,
                                curr_addr,
                                types::I32,
                            );
                            store_reg(builder, regs_ptr, i as u8, val);
                            if i == 15 {
                                pc_updated = true;
                            }
                        } else {
                            let val = load_reg(builder, regs_ptr, i as u8);
                            jit_mem_write(
                                builder,
                                cpu_ptr,
                                ram_ptr,
                                write_helper,
                                curr_addr,
                                val,
                                types::I32,
                            );
                        }
                        curr_addr = builder.ins().iadd_imm(curr_addr, 4);
                    }
                }
                if w == 1 {
                    store_reg(
                        builder,
                        regs_ptr,
                        *rn,
                        if u == 1 { curr_addr } else { start_addr },
                    );
                }
                if pc_updated {
                    builder.ins().return_(&[]);
                    terminal = true;
                }
            }
        }
        "ubfx" => {
            let rd = match insn.operands[0] {
                Operand::Register(r) => r,
                _ => 0,
            };
            let rn = match insn.operands[1] {
                Operand::Register(r) => r,
                _ => 0,
            };
            let lsb = match insn.operands[2] {
                Operand::Immediate(i) => i as u8,
                _ => 0,
            };
            let width = match insn.operands[3] {
                Operand::Immediate(i) => i as u8,
                _ => 0,
            };
            let val = load_reg(builder, regs_ptr, rn);
            let shifted = builder.ins().ushr_imm(val, lsb as i64);
            let mask = (1u64 << width) - 1;
            let res = builder.ins().band_imm(shifted, mask as i64);
            store_reg(builder, regs_ptr, rd, res);
        }
        "clz" => {
            let rd = match insn.operands[0] {
                Operand::Register(r) => r,
                _ => 0,
            };
            let rn = match insn.operands[1] {
                Operand::Register(r) => r,
                _ => 0,
            };
            let val = load_reg(builder, regs_ptr, rn);
            let res = builder.ins().clz(val);
            store_reg(builder, regs_ptr, rd, res);
        }
        "nop" => {}
        _ => {}
    }

    if let Some((merge_block, original_block)) = cond_block {
        if !terminal {
            builder.ins().jump(merge_block, &[]);
        }
        builder.switch_to_block(merge_block);
        // Seal the merge block here since we're done with conditional execution
        builder.seal_block(merge_block);
        // Don't switch back to the original block since it's already sealed by the brif
    }

    terminal
}

fn jit_mem_read(
    builder: &mut FunctionBuilder,
    cpu_ptr: Value,
    ram_ptr: Value,
    helper: Value,
    addr: Value,
    ty: Type,
) -> Value {
    let mut sig = Signature::new(CallConv::SystemV);
    sig.params.push(AbiParam::new(types::I64));
    sig.params.push(AbiParam::new(types::I32));
    sig.returns.push(AbiParam::new(types::I32));
    let sig_ref = builder.import_signature(sig);

    let is_ram = builder
        .ins()
        .icmp_imm(IntCC::UnsignedGreaterThanOrEqual, addr, 0x40000000);
    let ram_block = builder.create_block();
    let helper_block = builder.create_block();
    let merge_block = builder.create_block();

    let res_var = builder.declare_var(types::I32);

    builder
        .ins()
        .brif(is_ram, ram_block, &[], helper_block, &[]);

    builder.switch_to_block(ram_block);
    let mask = builder.ins().iconst(types::I32, 0x0FFFFFFF);
    let off = builder.ins().band(addr, mask);
    let off64 = builder.ins().uextend(types::I64, off);
    let paddr = builder.ins().iadd(ram_ptr, off64);
    let val = builder.ins().load(ty, MemFlags::new(), paddr, 0);
    let val32 = if ty == types::I32 {
        val
    } else {
        builder.ins().uextend(types::I32, val)
    };
    builder.def_var(res_var, val32);
    builder.ins().jump(merge_block, &[]);

    builder.switch_to_block(helper_block);
    let call = builder
        .ins()
        .call_indirect(sig_ref, helper, &[cpu_ptr, addr]);
    let hval = builder.inst_results(call)[0];
    builder.def_var(res_var, hval);
    builder.ins().jump(merge_block, &[]);

    builder.switch_to_block(merge_block);
    builder.seal_block(ram_block);
    builder.seal_block(helper_block);
    builder.seal_block(merge_block);
    builder.use_var(res_var)
}

fn jit_mem_write(
    builder: &mut FunctionBuilder,
    cpu_ptr: Value,
    ram_ptr: Value,
    helper: Value,
    addr: Value,
    val: Value,
    ty: Type,
) {
    let mut sig = Signature::new(CallConv::SystemV);
    sig.params.push(AbiParam::new(types::I64));
    sig.params.push(AbiParam::new(types::I32));
    sig.params.push(AbiParam::new(types::I32));
    let sig_ref = builder.import_signature(sig);

    let is_ram = builder
        .ins()
        .icmp_imm(IntCC::UnsignedGreaterThanOrEqual, addr, 0x40000000);
    let ram_block = builder.create_block();
    let helper_block = builder.create_block();
    let merge_block = builder.create_block();
    builder
        .ins()
        .brif(is_ram, ram_block, &[], helper_block, &[]);

    builder.switch_to_block(ram_block);
    let mask = builder.ins().iconst(types::I32, 0x0FFFFFFF);
    let off = builder.ins().band(addr, mask);
    let off64 = builder.ins().uextend(types::I64, off);
    let paddr = builder.ins().iadd(ram_ptr, off64);
    let val_trunc = if ty == types::I32 {
        val
    } else {
        builder.ins().ireduce(ty, val)
    };
    builder.ins().store(MemFlags::new(), val_trunc, paddr, 0);
    builder.ins().jump(merge_block, &[]);

    builder.switch_to_block(helper_block);
    builder
        .ins()
        .call_indirect(sig_ref, helper, &[cpu_ptr, addr, val]);
    builder.ins().jump(merge_block, &[]);

    builder.switch_to_block(merge_block);
    builder.seal_block(ram_block);
    builder.seal_block(helper_block);
    builder.seal_block(merge_block);
}

fn load_reg_with_pc(
    builder: &mut FunctionBuilder,
    regs_ptr: Value,
    reg: u8,
    insn_pc: u32,
    is_thumb: bool,
) -> Value {
    if reg == 15 {
        builder.ins().iconst(
            types::I32,
            (insn_pc + (if is_thumb { 4 } else { 8 })) as i64,
        )
    } else {
        load_reg(builder, regs_ptr, reg)
    }
}

fn load_operand(
    builder: &mut FunctionBuilder,
    op: &Operand,
    regs_ptr: Value,
    insn_pc: u32,
    is_thumb: bool,
) -> Value {
    match op {
        Operand::Register(r) => load_reg_with_pc(builder, regs_ptr, *r, insn_pc, is_thumb),
        Operand::Immediate(imm) => builder.ins().iconst(types::I32, *imm as i64),
        _ => builder.ins().iconst(types::I32, 0),
    }
}

fn update_flags_zn(builder: &mut FunctionBuilder, cpsr_ptr: Value, res: Value) {
    let old_cpsr = builder.ins().load(types::I32, MemFlags::new(), cpsr_ptr, 0);
    let mask = builder.ins().iconst(types::I32, 0x3FFFFFFF);
    let mut new_cpsr = builder.ins().band(old_cpsr, mask);
    let z_val = builder.ins().iconst(types::I32, 0x40000000);
    let n_val = builder.ins().iconst(types::I32, 0x80000000u32 as i64);
    let zero = builder.ins().iconst(types::I32, 0);
    let is_zero = builder.ins().icmp_imm(IntCC::Equal, res, 0);
    let z_flag = builder.ins().select(is_zero, z_val, zero);
    new_cpsr = builder.ins().bor(new_cpsr, z_flag);
    let is_neg = builder.ins().icmp_imm(IntCC::SignedLessThan, res, 0);
    let n_flag = builder.ins().select(is_neg, n_val, zero);
    new_cpsr = builder.ins().bor(new_cpsr, n_flag);
    builder.ins().store(MemFlags::new(), new_cpsr, cpsr_ptr, 0);
}

fn update_flags_cmp(builder: &mut FunctionBuilder, cpsr_ptr: Value, lhs: Value, rhs: Value) {
    let old_cpsr = builder.ins().load(types::I32, MemFlags::new(), cpsr_ptr, 0);
    let mask = builder.ins().iconst(types::I32, 0x0FFFFFFF);
    let mut new_cpsr = builder.ins().band(old_cpsr, mask);
    let zero = builder.ins().iconst(types::I32, 0);
    let z_val = builder.ins().iconst(types::I32, 0x40000000);
    let n_val = builder.ins().iconst(types::I32, 0x80000000u32 as i64);
    let c_val = builder.ins().iconst(types::I32, 0x20000000);
    let v_val = builder.ins().iconst(types::I32, 0x10000000);
    let is_eq = builder.ins().icmp(IntCC::Equal, lhs, rhs);
    let z_flag = builder.ins().select(is_eq, z_val, zero);
    new_cpsr = builder.ins().bor(new_cpsr, z_flag);
    let res = builder.ins().isub(lhs, rhs);
    let is_neg = builder.ins().icmp_imm(IntCC::SignedLessThan, res, 0);
    let n_flag = builder.ins().select(is_neg, n_val, zero);
    new_cpsr = builder.ins().bor(new_cpsr, n_flag);
    let is_geu = builder
        .ins()
        .icmp(IntCC::UnsignedGreaterThanOrEqual, lhs, rhs);
    let c_flag = builder.ins().select(is_geu, c_val, zero);
    new_cpsr = builder.ins().bor(new_cpsr, c_flag);
    let xor1 = builder.ins().bxor(lhs, rhs);
    let xor2 = builder.ins().bxor(lhs, res);
    let v_and = builder.ins().band(xor1, xor2);
    let is_v = builder.ins().icmp_imm(IntCC::SignedLessThan, v_and, 0);
    let v_flag = builder.ins().select(is_v, v_val, zero);
    new_cpsr = builder.ins().bor(new_cpsr, v_flag);
    builder.ins().store(MemFlags::new(), new_cpsr, cpsr_ptr, 0);
}

fn check_cond_jit(builder: &mut FunctionBuilder, cpsr_ptr: Value, cond: u8) -> Value {
    let cpsr = builder.ins().load(types::I32, MemFlags::new(), cpsr_ptr, 0);
    let n_un = builder.ins().ushr_imm(cpsr, 31);
    let cpsr_shr30 = builder.ins().ushr_imm(cpsr, 30);
    let z_un = builder.ins().band_imm(cpsr_shr30, 1);
    let cpsr_shr29 = builder.ins().ushr_imm(cpsr, 29);
    let c_un = builder.ins().band_imm(cpsr_shr29, 1);
    let cpsr_shr28 = builder.ins().ushr_imm(cpsr, 28);
    let v_un = builder.ins().band_imm(cpsr_shr28, 1);

    match cond {
        0x0 => builder.ins().icmp_imm(IntCC::Equal, z_un, 1), // EQ
        0x1 => builder.ins().icmp_imm(IntCC::Equal, z_un, 0), // NE
        0x2 => builder.ins().icmp_imm(IntCC::Equal, c_un, 1), // CS
        0x3 => builder.ins().icmp_imm(IntCC::Equal, c_un, 0), // CC
        0x4 => builder.ins().icmp_imm(IntCC::Equal, n_un, 1), // MI
        0x5 => builder.ins().icmp_imm(IntCC::Equal, n_un, 0), // PL
        0x6 => builder.ins().icmp_imm(IntCC::Equal, v_un, 1), // VS
        0x7 => builder.ins().icmp_imm(IntCC::Equal, v_un, 0), // VC
        0x8 => {
            // HI
            let cset = builder.ins().icmp_imm(IntCC::Equal, c_un, 1);
            let zclr = builder.ins().icmp_imm(IntCC::Equal, z_un, 0);
            builder.ins().band(cset, zclr)
        }
        0x9 => {
            // LS
            let cclr = builder.ins().icmp_imm(IntCC::Equal, c_un, 0);
            let zset = builder.ins().icmp_imm(IntCC::Equal, z_un, 1);
            builder.ins().bor(cclr, zset)
        }
        0xA => builder.ins().icmp(IntCC::Equal, n_un, v_un), // GE
        0xB => builder.ins().icmp(IntCC::NotEqual, n_un, v_un), // LT
        0xC => {
            // GT
            let neq = builder.ins().icmp(IntCC::Equal, n_un, v_un);
            let zclr = builder.ins().icmp_imm(IntCC::Equal, z_un, 0);
            builder.ins().band(neq, zclr)
        }
        0xD => {
            // LE
            let nne = builder.ins().icmp(IntCC::NotEqual, n_un, v_un);
            let zset = builder.ins().icmp_imm(IntCC::Equal, z_un, 1);
            builder.ins().bor(nne, zset)
        }
        _ => builder.ins().iconst(types::I8, 1),
    }
}

fn load_reg(builder: &mut FunctionBuilder, regs_ptr: Value, reg: u8) -> Value {
    builder
        .ins()
        .load(types::I32, MemFlags::new(), regs_ptr, (reg as i32) * 4)
}

fn store_reg(builder: &mut FunctionBuilder, regs_ptr: Value, reg: u8, val: Value) {
    builder
        .ins()
        .store(MemFlags::new(), val, regs_ptr, (reg as i32) * 4);
}
