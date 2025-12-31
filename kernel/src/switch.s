.global __switch_to
.global kernel_thread_starter

__switch_to:
    /* x0 = prev_ctx, x1 = next_ctx */
    /* Save Callee-saved registers */
    str x19, [x0, #0]
    str x20, [x0, #8]
    str x21, [x0, #16]
    str x22, [x0, #24]
    str x23, [x0, #32]
    str x24, [x0, #40]
    str x25, [x0, #48]
    str x26, [x0, #56]
    str x27, [x0, #64]
    str x28, [x0, #72]
    str x29, [x0, #80]
    str x30, [x0, #88] /* LR */
    mov x19, sp
    str x19, [x0, #96] /* SP */

    /* Restore next context */
    ldr x19, [x1, #0]
    ldr x20, [x1, #8]
    ldr x21, [x1, #16]
    ldr x22, [x1, #24]
    ldr x23, [x1, #32]
    ldr x24, [x1, #40]
    ldr x25, [x1, #48]
    ldr x26, [x1, #56]
    ldr x27, [x1, #64]
    ldr x28, [x1, #72]
    ldr x29, [x1, #80]
    ldr x30, [x1, #88]
    ldr x9,  [x1, #96]
    mov sp, x9

    ret

/* 
 * void kernel_thread_starter(u64 user_entry, u64 user_stack, u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5, u64 flags);
 * x19 = user_entry
 * x20 = user_stack
 * x21..x26 = args (r0..r5)
 * x27 = flags
 */
kernel_thread_starter:
    msr elr_el1, x19
    msr sp_el0, x20
    
    /* Verify SP_EL0 */
    mrs x0, sp_el0
    cmp x0, x20
    b.ne . /* Hang if SP_EL0 set failed */
    
    /* Set arguments r0..r5 */
    mov x0, x21
    mov x1, x22
    mov x2, x23
    mov x3, x24
    mov x4, x25
    mov x5, x26

    /* Zero out remaining registers to avoid leaking kernel data and confusing dyld (e.g. r8) */
    mov x6, #0
    mov x7, #0
    mov x8, #0
    mov x9, #0
    mov x10, #0
    mov x11, #0
    mov x12, #0
    mov x13, #0
    mov x14, #0
    mov x15, #0
    mov x16, #0
    mov x17, #0
    mov x18, #0
    
    /* Set TLS (x28 holds tls_base from Process::new context.regs[9]) */
    msr tpidrro_el0, x28
    msr tpidr_el0, x28  /* Set both RW and RO for good measure */

    /* x19, x20, x21..x26 are saved callee-saved, we don't need to zero them for security 
       as much as correctness for the *guest* state visible in A32.
       AArch32 views x0..x14 as r0..r14. x15.. are high bits or not visible directly.
       But let's be safe.
    */
    
    /* x27: bit 0 = is_a32, bit 1 = is_thumb */
    tst x27, #1
    b.eq .a64_start
    
    /* AArch32 EL0 User */
    mov x28, #0x10 /* Use x28 as scratch for SPSR */
    tst x27, #2
    b.eq .set_spsr
    orr x28, x28, #0x20 /* Set T bit for Thumb */
    b .set_spsr

.a64_start:
    /* SPSR_EL1: EL0t, IRQ/FIQ masked */
    mov x28, #0x3c0

.set_spsr:
    /* Clear other registers */
    mov x0, xzr
    mov x1, xzr
    mov x2, xzr
    mov x3, xzr
    mov x4, xzr
    mov x5, xzr
    /* x6-x18 already zeroed? No, I need to zero them or trust they are clean? */
    /* I previously zeroed them but replaced file content might have removed it? */
    /* Let's clear x6-x18 just to be safe */
    mov x6, xzr
    mov x7, xzr
    mov x8, xzr
    mov x9, xzr
    mov x10, xzr
    mov x11, xzr
    mov x12, xzr
    /* mov x13, xzr  <-- Don't clear r13? */
    mov x13, x20     /* Hack: Set x13 to User SP just in case QEMU uses it for A32 R13 */
    mov x14, xzr
    mov x15, xzr
    mov x16, xzr
    mov x17, xzr
    mov x18, xzr

    /* Verify x20 (stack) is not 0 */
    cmp x20, #0
    b.eq . /* Hang if stack is 0 */

    /* Barriers to ensure I-cache sees user code and state is consistent */
    dsb ish
    ic ialluis
    isb

    /* Enable FP/ASIMD (CPACR_EL1 bits 20-21) */
    mrs x9, cpacr_el1
    orr x9, x9, #(0x3 << 20)
    msr cpacr_el1, x9
    isb

    msr spsr_el1, x28
    eret

