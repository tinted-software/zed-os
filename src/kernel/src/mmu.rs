use crate::kprintln;
use core::arch::asm;

// Basic AArch64 paging (4KB pages, 32-bit VA space)
// TCR.T0SZ = 32 means 4GB address space.
// We start at L1. Each L1 entry covers 1GB.
// L1 entry can point to L2 table. Each L2 entry covers 2MB.

const TABLE_ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;
const BLOCK_ADDR_MASK: u64 = 0x0000_FFFF_FFE0_0000; // For 2MB blocks, bits [47:21]
// Level 3 entries are for 4KB pages.
const DESC_VALID: u64 = 1 << 0;
const DESC_TABLE: u64 = 1 << 1; // Used in L0, L1, L2
const DESC_PAGE: u64 = 1 << 1; // Used in L3
const DESC_BLOCK: u64 = 0 << 1; // Used in L1, L2

// Access permissions and attributes
const AP_RW_EL1: u64 = 0 << 6;
const AP_RW_EL0_EL1: u64 = 1 << 6;
const AP_RO_EL1: u64 = 2 << 6;
const AP_RO_EL0_EL1: u64 = 3 << 6;
const AF: u64 = 1 << 10;
const SH_INNER: u64 = 3 << 8;
const MAIR_DEV: u64 = 0 << 2;
const MAIR_MEM: u64 = 1 << 2;

// Execute never bits
const UXN: u64 = 1 << 54;
const PXN: u64 = 1 << 53;

#[repr(C, align(4096))]
#[derive(Copy, Clone)]
struct PageTable([u64; 512]);

static mut L1_TABLE: PageTable = PageTable([0; 512]);
static mut L2_TABLES: [PageTable; 4] = [PageTable([0; 512]); 4];

// Pool for dynamically allocated L2 and L3 tables
static mut L2_POOL: [PageTable; 16] = [PageTable([0; 512]); 16];
static mut L2_ALLOC_IDX: usize = 0;
static mut L3_POOL: [PageTable; 2048] = [PageTable([0; 512]); 2048];
static mut L3_ALLOC_IDX: usize = 0;

pub fn init() {
    kprintln!("MMU: Initializing 3-level hierarchy (T0SZ=32)...");

    unsafe {
        // 1. MAIR_EL1: Index 0=Device, Index 1=Normal
        let mair: u64 = 0x0000_0000_0000_FF04; // Attr0=Device, Attr1=Normal
        asm!("msr mair_el1, {}", in(reg) mair);

        // 2. Map 4GB using L1 -> L2 (2MB blocks)
        for i in 0..512 {
            L1_TABLE.0[i] = 0;
        }
        for i in 0..4 {
            // L1[i] -> L2_TABLES[i]
            L1_TABLE.0[i] = (core::ptr::addr_of!(L2_TABLES[i]) as u64) | DESC_VALID | DESC_TABLE;

            for j in 0..512 {
                let paddr = (i as u64 * 1024 * 1024 * 1024) + (j as u64 * 0x200000);

                // Skip mapping PCI space (0x10000000 - 0x40000000) as Normal memory
                // We will map these specifically as Device memory later
                if paddr >= 0x10000000 && paddr < 0x40000000 {
                    continue;
                }

                // Map everything as Normal (MAIR_MEM) for now to ensure kernel code/stack work
                // MAIR Index 1 is Normal memory
                let attr = MAIR_MEM;
                L2_TABLES[i].0[j] = paddr | DESC_VALID | DESC_BLOCK | attr | AF | AP_RW_EL1;
            }
        }

        asm!("dsb sy");

        // 3. TCR_EL1: T0SZ=32, TG0=4KB, EPD1=1, WBWA, Shareable, etc.
        let tcr: u64 = 0x5b5103520;
        asm!("msr tcr_el1, {}", in(reg) tcr);

        // 4. TTBR0_EL1: Point to L1_TABLE
        let ttbr0 = core::ptr::addr_of!(L1_TABLE) as u64;
        asm!("msr ttbr0_el1, {}", in(reg) ttbr0);

        // 5. Invalidate TLB and I-cache
        asm!("tlbi vmalle1is", "ic ialluis", "dsb sy", "isb");

        // 6. Enable MMU with RES1 bits
        let mut sctlr: u64;
        asm!("mrs {}, sctlr_el1", out(reg) sctlr);

        // SCTLR_EL1 RES1 bits

        sctlr |= (1 << 29) | (1 << 28) | (1 << 22) | (1 << 20) | (1 << 11);

        // SCTLR_EL1.M = 1 (Enable MMU)

        sctlr |= 1;

        // SCTLR_EL1.I = 0 (Disable I-cache for now)

        // SCTLR_EL1.C = 0 (Disable D-cache for now)

        sctlr &= !((1 << 12) | (1 << 2));

        asm!("msr sctlr_el1, {}", in(reg) sctlr);
        asm!("isb");

        kprintln!("MMU: Enabled.");

        // Finalize identity mapping for 0-4GB before adding specialized regions
        asm!("dsb sy", "isb");
    }

    // Map UART specifically as Device memory
    // UART is at 0x09000000
    map_range(0x09000000, 0x09000000, 4096, MapPermission::KernelRWDevice);

    // Map PCI ECAM (Virtual 0x20000000 -> Physical 0x40_1000_0000)
    // Highmem ECAM is 256MB
    map_range(
        0x20000000,
        0x40_1000_0000,
        0x10000000,
        MapPermission::KernelRWDevice,
    );

    // Map PCI MMIO space (0x10000000+)
    map_range(
        0x10000000,
        0x10000000,
        0x10000000,
        MapPermission::KernelRWDevice,
    );

    // Map CommPage at 0xFFFF0000
    // CommPage needs to be UserRO. Map 16KB (4 pages).
    populate_commpage();
    map_range(
        0xFFFF0000,
        core::ptr::addr_of!(COMMPAGE_STORAGE) as u64,
        16384,
        MapPermission::UserRO,
    );
}

fn populate_commpage() {
    unsafe {
        let cp = core::ptr::addr_of_mut!(COMMPAGE_STORAGE) as *mut u8;
        // iOS 5 commpage version 13
        core::ptr::write(cp.add(0x1E) as *mut u16, 13);
        // Active CPUs
        core::ptr::write(cp.add(0x22) as *mut u8, 1);
        // Physical CPUs
        core::ptr::write(cp.add(0x23) as *mut u8, 1);
        // Logical CPUs
        core::ptr::write(cp.add(0x24) as *mut u8, 1);
    }
}

pub static mut COMMPAGE_STORAGE: [u8; 65536] = [0; 65536];

#[derive(Copy, Clone, PartialEq)]
pub enum MapPermission {
    KernelRW,
    KernelRO,
    KernelRWDevice,
    UserRW,
    UserRO,
    UserRX,
    UserRWX, // Not recommended but maybe needed for dyld bounce?
}

fn get_ap_bits(perm: MapPermission) -> u64 {
    match perm {
        MapPermission::KernelRW => AP_RW_EL1,
        MapPermission::KernelRO => AP_RO_EL1,
        MapPermission::KernelRWDevice => AP_RW_EL1,
        MapPermission::UserRW => AP_RW_EL0_EL1,
        MapPermission::UserRO => AP_RO_EL0_EL1,
        MapPermission::UserRX => AP_RO_EL0_EL1,
        MapPermission::UserRWX => AP_RW_EL0_EL1,
    }
}

fn get_xn_bits(perm: MapPermission) -> u64 {
    match perm {
        MapPermission::UserRX | MapPermission::UserRWX => 0, // Both EL0 and EL1 can execute (PXN=0, UXN=0)
        MapPermission::UserRO | MapPermission::UserRW => UXN | PXN,
        MapPermission::KernelRWDevice => UXN | PXN,
        MapPermission::KernelRO | MapPermission::KernelRW => UXN, // Kernel non-exec
    }
}

pub fn map_range(vaddr: u64, paddr: u64, size: u64, perm: MapPermission) {
    let start_v = vaddr & !0xFFF;
    let end_v = (vaddr + size + 0xFFF) & !0xFFF;
    let mut curr_p = paddr & !0xFFF;

    for curr_v in (start_v..end_v).step_by(0x1000) {
        let l1_idx = (curr_v >> 30) as usize;
        let l2_idx = ((curr_v >> 21) & 0x1FF) as usize;
        let l3_idx = ((curr_v >> 12) & 0x1FF) as usize;

        unsafe {
            if l1_idx >= 512 {
                continue;
            }

            // Ensure L2 exists
            if (L1_TABLE.0[l1_idx] & DESC_VALID) == 0 {
                // Allocate from L2_POOL
                if L2_ALLOC_IDX >= 16 {
                    panic!("Out of L2 tables!");
                }
                let l2_table_ptr = &mut L2_POOL[L2_ALLOC_IDX];
                L2_ALLOC_IDX += 1;
                // Zero out the new table
                for entry in l2_table_ptr.0.iter_mut() {
                    *entry = 0;
                }
                let l2_table_addr = l2_table_ptr as *const _ as u64;
                L1_TABLE.0[l1_idx] = l2_table_addr | DESC_VALID | DESC_TABLE;
            }

            let l2_ptr = (L1_TABLE.0[l1_idx] & TABLE_ADDR_MASK) as *mut PageTable;

            // Ensure L3 exists (pointing from L2)
            let l2_entry = (*l2_ptr).0[l2_idx];
            if (l2_entry & DESC_VALID) == 0 {
                // New table
                if L3_ALLOC_IDX >= 2048 {
                    panic!("Out of L3 tables!");
                }
                let l3_table_ptr = &mut L3_POOL[L3_ALLOC_IDX];
                L3_ALLOC_IDX += 1;
                // Zero out the new table
                for entry in l3_table_ptr.0.iter_mut() {
                    *entry = 0;
                }
                let l3_table_addr = l3_table_ptr as *const _ as u64;

                (*l2_ptr).0[l2_idx] = l3_table_addr | DESC_VALID | DESC_TABLE;
            } else if (l2_entry & DESC_TABLE) == 0 {
                // It was a block mapping! Split it.
                kprintln!("MMU: Splitting block at vaddr {:x}", curr_v & !0x1FFFFF);
                // For 2MB blocks, the address is at bits [47:21]
                let block_paddr = l2_entry & BLOCK_ADDR_MASK;
                let block_flags = l2_entry & !TABLE_ADDR_MASK;

                let l3_idx_to_use = L3_ALLOC_IDX;
                L3_ALLOC_IDX += 1;
                if L3_ALLOC_IDX >= 2048 {
                    panic!("Out of L3 tables!");
                }

                // Populate the new L3 table with 512 pages from the block
                for p in 0..512 {
                    core::ptr::write_volatile(
                        &mut L3_POOL[l3_idx_to_use].0[p],
                        (block_paddr + (p as u64 * 0x1000))
                            | DESC_VALID
                            | DESC_PAGE
                            | (block_flags & !DESC_TABLE),
                    );
                }

                core::ptr::write_volatile(
                    &mut (*l2_ptr).0[l2_idx],
                    (&L3_POOL[l3_idx_to_use] as *const _ as u64) | DESC_VALID | DESC_TABLE,
                );
            }

            let l3_ptr = ((*l2_ptr).0[l2_idx] & TABLE_ADDR_MASK) as *mut PageTable;
            let ap = get_ap_bits(perm);
            let xn = get_xn_bits(perm);
            let is_device = perm == MapPermission::KernelRWDevice;
            let attr = if is_device { MAIR_DEV } else { MAIR_MEM };
            let sh = if is_device { 0 } else { SH_INNER };

            core::ptr::write_volatile(
                &mut (*l3_ptr).0[l3_idx],
                curr_p | DESC_VALID | DESC_PAGE | attr | AF | sh | ap | xn,
            );

            // Debug: verify first and last mapping
            if curr_v == start_v || curr_v + 0x1000 >= end_v {
                kprintln!(
                    "map_range: v={:x} p={:x} L1={} L2={} L3={} entry={:016x}",
                    curr_v,
                    curr_p,
                    l1_idx,
                    l2_idx,
                    l3_idx,
                    core::ptr::read_volatile(&(*l3_ptr).0[l3_idx])
                );
            }

            curr_p += 0x1000;
        }
    }

    unsafe {
        asm!("dsb ish", "tlbi vmalle1is", "dsb ish", "isb");
    }
}
