use crate::kprintln;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use goblin::mach::{Mach, MachO};

pub struct MachOLoader {
    pub entry: u64,
    pub header_addr: u64,
    pub dylinker: Option<String>,
}

pub fn setup_stack(sp: u64, exec_path: &str, mh_addr: u64) -> u64 {
    // Darwin ARMv7 stack layout:
    // [NULL-terminated strings...]
    // [Alignment]
    // [apple[N]] ptr to strings
    // [NULL]
    // [envp[N]] ptr to strings (NULL for now)
    // [NULL]
    // [argv[N]] ptr to strings
    // [argc]

    let mut current_sp = sp;

    // Copy strings to stack
    let mut strings = vec![
        exec_path,
        "dyld_shared_cache_base_address=0x30000000",
        "executable_path=/bin/initial",
    ];
    let mut string_ptrs = vec![];

    for s in strings {
        let bytes = s.as_bytes();
        current_sp -= (bytes.len() + 1) as u64;
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), current_sp as *mut u8, bytes.len());
            core::ptr::write((current_sp + bytes.len() as u64) as *mut u8, 0);
        }
        string_ptrs.push(current_sp);
    }

    // Align SP to 16 bytes
    current_sp &= !15;

    // Values (32-bit for ARMv7)
    // [NULL]
    // [apple[N]] ptr to strings
    // [NULL]
    // [envp[N]] (NULL)
    // [NULL]
    // [argv[N]] ptr to strings
    // [argc]

    let values = [
        mh_addr as u32,        // mach_header (at sp)
        1u32,                  // argc (at sp+4)
        string_ptrs[0] as u32, // argv[0]
        0u32,                  // argv[1] (NULL)
        0u32,                  // env[0] (NULL)
        string_ptrs[0] as u32, // apple[0] (exec path)
        string_ptrs[1] as u32, // apple[1] (cache base)
        string_ptrs[2] as u32, // apple[2] (exec path again)
        0u32,                  // apple[3] (NULL)
    ];

    current_sp -= (values.len() * 4) as u64;
    let stack_top = current_sp;

    unsafe {
        core::ptr::copy_nonoverlapping(values.as_ptr(), current_sp as *mut u32, values.len());
    }

    stack_top
}

fn segname_to_str(segname: &[u8; 16]) -> &str {
    core::str::from_utf8(segname)
        .ok()
        .unwrap_or("")
        .trim_matches('\0')
}

impl MachOLoader {
    pub fn load(data: &[u8], load_offset: u64) -> Option<Self> {
        let mach = Mach::parse(data).ok()?;

        match mach {
            Mach::Binary(macho) => Self::load_macho(&macho, data, load_offset),
            Mach::Fat(fat) => {
                // Find armv7 slice
                for arch in fat.arches().ok()? {
                    if arch.cputype == goblin::mach::constants::cputype::CPU_TYPE_ARM {
                        let offset = arch.offset as usize;
                        let size = arch.size as usize;
                        let slice = &data[offset..offset + size];
                        let macho = MachO::parse(slice, 0).ok()?;
                        return Self::load_macho(&macho, slice, load_offset);
                    }
                }
                None
            }
        }
    }

    pub fn map_shared_cache(data: &[u8]) -> Option<()> {
        kprintln!("Mapping dyld shared cache...");
        if !data.starts_with(b"dyld_v1   armv7") {
            kprintln!("Invalid shared cache magic");
            return None;
        }

        // v1 shared cache header
        let mapping_offset = u32::from_le_bytes(data[16..20].try_into().ok()?) as usize;
        let mapping_count = u32::from_le_bytes(data[20..24].try_into().ok()?) as usize;

        for i in 0..mapping_count {
            let off = mapping_offset + i * 32;
            let address = u64::from_le_bytes(data[off..off + 8].try_into().ok()?);
            let size = u64::from_le_bytes(data[off + 8..off + 16].try_into().ok()?);
            let file_off = u64::from_le_bytes(data[off + 16..off + 24].try_into().ok()?);
            let max_prot = u32::from_le_bytes(data[off + 24..off + 28].try_into().ok()?);

            kprintln!(
                "Mapping cache segment at {:x} (size {:x}, prot {:x})",
                address,
                size,
                max_prot
            );

            let phys_addr = (data.as_ptr() as u64) + file_off;
            kprintln!(
                "  data.ptr={:x}, file_off={:x} -> phys={:x}",
                data.as_ptr() as u64,
                file_off,
                phys_addr
            );
            kprintln!(
                "  First bytes: {:02x} {:02x} {:02x} {:02x}",
                data[file_off as usize],
                data[file_off as usize + 1],
                data[file_off as usize + 2],
                data[file_off as usize + 3]
            );

            let perm = if (max_prot & 4) != 0 {
                crate::mmu::MapPermission::UserRX
            } else if (max_prot & 2) != 0 {
                crate::mmu::MapPermission::UserRW
            } else {
                crate::mmu::MapPermission::UserRO
            };

            crate::mmu::map_range(address, phys_addr, size, perm);

            // Verify mapping worked by reading from mapped address
            if i == 0 {
                unsafe {
                    let mapped_ptr = address as *const u32;
                    let first_word = *mapped_ptr;
                    kprintln!("  VERIFY: Read from {:x} = {:08x}", address, first_word);
                }
            }
        }

        Some(())
    }

    fn load_macho(macho: &MachO, data: &[u8], load_offset: u64) -> Option<Self> {
        kprintln!("Loading Mach-O binary with slide {:x}...", load_offset);

        let mut dylinker = None;

        for cmd in &macho.load_commands {
            match &cmd.command {
                goblin::mach::load_command::CommandVariant::LoadDylinker(d) => {
                    let name_offset = d.name as usize;
                    let name_ptr = &data[cmd.offset + name_offset..];
                    if let Some(name_bytes) = name_ptr.split(|&b| b == 0).next() {
                        if let Ok(name) = core::str::from_utf8(name_bytes) {
                            dylinker = Some(String::from(name));
                        }
                    }
                }
                goblin::mach::load_command::CommandVariant::Unixthread(t)
                | goblin::mach::load_command::CommandVariant::Thread(t) => {
                    kprintln!(
                        "Found LC_UNIXTHREAD/THREAD: flavor={}, count={}",
                        t.flavor,
                        t.count
                    );
                    // ARM_THREAD_STATE = 1
                    if t.flavor == 1 {
                        let data_offset = cmd.offset + 16;
                        let count = t.count as usize;
                        if data_offset + count * 4 <= data.len() {
                            // Use byte-wise reading to avoid alignment issues
                            let read_u32 = |off: usize| -> u32 {
                                u32::from_le_bytes(
                                    data[data_offset + off * 4..data_offset + off * 4 + 4]
                                        .try_into()
                                        .unwrap(),
                                )
                            };
                            let r0 = read_u32(0);
                            let sp = read_u32(13);
                            let lr = read_u32(14);
                            let pc = read_u32(15);
                            let cpsr = read_u32(16);
                            kprintln!(
                                "Thread Registers: R0={:x}, SP={:x}, LR={:x}, PC={:x}, CPSR={:x}",
                                r0,
                                sp,
                                lr,
                                pc,
                                cpsr
                            );
                        }

                        kprintln!("Entry point from thread command: {:x}", macho.entry);
                    }
                }
                _ => {}
            }
        }

        let mut header_addr = load_offset; // Fallback

        for segment in &macho.segments {
            let segname = segname_to_str(&segment.segname);
            if segname == "__PAGEZERO" {
                continue;
            }

            let vm_addr = segment.vmaddr + load_offset;
            let file_off = segment.fileoff as usize;
            let file_size = segment.filesize as usize;
            let mem_size = segment.vmsize as usize;
            let prot = segment.initprot;

            if file_off == 0 && file_size > 0 {
                header_addr = vm_addr;
                kprintln!("Found Mach-O header at {:x}", header_addr);
            }

            kprintln!(
                "Mapping segment {} at {:x} (size {:x}, prot {:x})",
                segname,
                vm_addr,
                mem_size,
                prot
            );

            let perm = match (prot & 1 != 0, prot & 2 != 0, prot & 4 != 0) {
                (true, true, true) => crate::mmu::MapPermission::UserRWX,
                (true, true, false) => crate::mmu::MapPermission::UserRW,
                (true, false, true) => crate::mmu::MapPermission::UserRX,
                (true, false, false) => crate::mmu::MapPermission::UserRO,
                _ => crate::mmu::MapPermission::UserRO,
            };

            // Map the segment as RW first so kernel can copy data into it
            crate::mmu::map_range(
                vm_addr,
                vm_addr,
                mem_size as u64,
                crate::mmu::MapPermission::UserRW,
            );

            if file_size > 0 {
                let src = &data[file_off..file_off + file_size];
                unsafe {
                    core::ptr::copy_nonoverlapping(src.as_ptr(), vm_addr as *mut u8, file_size);
                }
            }

            if mem_size > file_size {
                unsafe {
                    core::ptr::write_bytes(
                        (vm_addr + file_size as u64) as *mut u8,
                        0,
                        mem_size - file_size,
                    );
                }
            }

            // Now apply final permissions
            crate::mmu::map_range(vm_addr, vm_addr, mem_size as u64, perm);
        }

        Some(Self {
            entry: (macho.entry as u64) + load_offset,
            header_addr,
            dylinker,
        })
    }
}
