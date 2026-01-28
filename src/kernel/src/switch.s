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
    mov x9,  sp
    str x9,  [x0, #88] /* sp at index 11 */
    str x30, [x0, #96] /* x30 at index 12 */

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
    ldr x9,  [x1, #88]
    mov sp, x9
    ldr x30, [x1, #96]

    ret

/* 
 * void kernel_thread_starter(u64 user_entry, u64 user_stack, u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5, u64 flags);
 * x19 = user_entry
 * x20 = user_stack
 * x21..x26 = args (x0..x5)
 * x27 = flags (spsr)
 * x28 = tls_base
 */
kernel_thread_starter:
    msr elr_el1, x19
    msr sp_el0, x20
    /* AArch32 uses X13 as SP (R13) and X14 as LR (R14) */
    mov x13, x20
    mov x14, #0
    
    /* Set arguments x0..x5 from x21..x26 */
    mov x0, x21
    mov x1, x22
    mov x2, x23
    mov x3, x24
    mov x4, x25
    mov x5, x26

    /* Zero out remaining registers */
    mov x6, #0
    mov x7, #0
    mov x8, #0
    mov x9, #0
    mov x10, #0
    mov x11, #0
    mov x12, #0
    mov x15, #0
    mov x16, #0
    mov x17, #0
    mov x18, #0
    
    /* Set TLS (x28 holds tls_base) */
    msr tpidr_el0, x28
    msr tpidrro_el0, x28

    /* SPSR_EL1 from flags (x27) */
    msr spsr_el1, x27

    /* Barriers */
    dsb ish
    ic ialluis
    isb

    eret