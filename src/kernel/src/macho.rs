use crate::kprintln;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use goblin::mach::{Mach, MachO};

pub struct MachOLoader {
    pub entry: u64,
    pub header_addr: u64,
    pub dylinker: Option<String>,
    pub is_64bit: bool,
}

pub fn setup_stack(sp: u64, exec_path: &str, mh_addr: u64, is_64bit: bool) -> u64 {
    let mut current_sp = sp;

    // Copy strings to stack
    let strings = vec![
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

    // Align SP
    if is_64bit {
        current_sp &= !15;
    } else {
        current_sp &= !3;
    }

    if is_64bit {
        // 64-bit values
        let values = [
            mh_addr,        // mach_header (at sp)
            1u64,           // argc (at sp+8)
            string_ptrs[0], // argv[0]
            0u64,           // argv[1] (NULL)
            0u64,           // envp[0] (NULL)
            string_ptrs[0], // apple[0] (exec path)
            string_ptrs[1], // apple[1] (cache base)
            string_ptrs[2], // apple[2] (exec path again)
            0u64,           // apple[3] (NULL)
        ];

        current_sp -= (values.len() * 8) as u64;
        let stack_top = current_sp;
        unsafe {
            core::ptr::copy_nonoverlapping(values.as_ptr(), current_sp as *mut u64, values.len());
        }
        stack_top
    } else {
        // 32-bit values for ARMv7 Darwin
        // Order: mach_header, argc, argv[0...n], NULL, envp[0...m], NULL, apple[0...k], NULL
        let values = [
            mh_addr as u32,        // mach_header (at sp)
            1u32,                  // argc (at sp+4)
            string_ptrs[0] as u32, // argv[0]
            0u32,                  // argv[1] (NULL)
            0u32,                  // envp[0] (NULL)
            string_ptrs[0] as u32, // apple[0] (exec path)
            string_ptrs[1] as u32, // apple[1] (dyld_shared_cache_base_address)
            string_ptrs[2] as u32, // apple[2] (executable_path)
            mh_addr as u32,        // apple[3] (mach_header)
            0u32,                  // apple[4] (NULL)
        ];

        // Ensure 16-byte alignment for the whole stack frame
        let bytes_needed = values.len() * 4;
        current_sp -= bytes_needed as u64;
        current_sp &= !15;

        let stack_top = current_sp;
        unsafe {
            let p = stack_top as *mut u32;
            for (i, &v) in values.iter().enumerate() {
                core::ptr::write(p.add(i), v);
            }
        }
        stack_top
    }
}

fn segname_to_str(segname: &[u8; 16]) -> &str {
    core::str::from_utf8(segname)
        .ok()
        .unwrap_or("")
        .trim_matches('\0')
}

impl MachOLoader {
    pub fn load(data: &[u8], load_offset: u64) -> Option<Self> {
        kprintln!("MachOLoader::load: data len {:x}", data.len());
        let mach = match Mach::parse(data) {
            Ok(m) => m,
            Err(e) => {
                kprintln!("Mach::parse failed: {:?}. Checking for raw MachO...", e);
                if let Ok(macho) = MachO::parse(data, 0) {
                    kprintln!(
                        "Successfully parsed raw MachO (cputype={:?})",
                        macho.header.cputype
                    );
                    return Self::load_macho(&macho, data, load_offset);
                }
                return None;
            }
        };

        match mach {
            Mach::Binary(macho) => Self::load_macho(&macho, data, load_offset),
            Mach::Fat(fat) => {
                let arches = fat.arches().ok()?;
                kprintln!("Fat MachO found with {} architectures", arches.len());
                // Prefer arm64 if available, otherwise armv7
                let arch = arches
                    .iter()
                    .find(|a| a.cputype == goblin::mach::constants::cputype::CPU_TYPE_ARM64)
                    .or_else(|| {
                        arches
                            .iter()
                            .find(|a| a.cputype == goblin::mach::constants::cputype::CPU_TYPE_ARM)
                    });

                if let Some(arch) = arch {
                    let offset = arch.offset as usize;
                    let size = arch.size as usize;
                    kprintln!(
                        "Selected arch cputype {:x} at offset {:x} size {:x}",
                        arch.cputype,
                        offset,
                        size
                    );
                    let slice = &data[offset..offset + size];
                    let macho = MachO::parse(slice, 0).ok()?;
                    return Self::load_macho(&macho, slice, load_offset);
                }
                None
            }
        }
    }

    fn load_macho(macho: &MachO, data: &[u8], load_offset: u64) -> Option<Self> {
        let is_64bit = macho.header.cputype == goblin::mach::constants::cputype::CPU_TYPE_ARM64;
        kprintln!(
            "Loading Mach-O binary (64-bit: {}) with slide {:x}...",
            is_64bit,
            load_offset
        );

        // Dump first 32 bytes of MachO header
        if data.len() >= 32 {
            let p = data.as_ptr() as *const u32;
            unsafe {
                kprintln!(
                    "MachO Header: {:08x} {:08x} {:08x} {:08x}",
                    core::ptr::read(p),
                    core::ptr::read(p.add(1)),
                    core::ptr::read(p.add(2)),
                    core::ptr::read(p.add(3))
                );
                kprintln!(
                    "              {:08x} {:08x} {:08x} {:08x}",
                    core::ptr::read(p.add(4)),
                    core::ptr::read(p.add(5)),
                    core::ptr::read(p.add(6)),
                    core::ptr::read(p.add(7))
                );
            }
        }

        let mut dylinker = None;

        for cmd in &macho.load_commands {
            if let goblin::mach::load_command::CommandVariant::LoadDylinker(d) = &cmd.command {
                let name_offset = d.name as usize;
                let name_ptr = &data[cmd.offset + name_offset..];
                if let Some(name_bytes) = name_ptr.split(|&b| b == 0).next()
                    && let Ok(name) = core::str::from_utf8(name_bytes)
                {
                    dylinker = Some(String::from(name));
                }
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
                _ => crate::mmu::MapPermission::UserRWX,
            };

            // Allocate physical memory for this segment
            let layout = core::alloc::Layout::from_size_align(mem_size, 4096).unwrap();
            let phys_ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
            if phys_ptr.is_null() {
                panic!("Failed to allocate physical memory for segment");
            }
            let paddr = phys_ptr as u64;

            // Map the segment
            crate::mmu::map_range(
                vm_addr,
                paddr,
                mem_size as u64,
                crate::mmu::MapPermission::UserRW,
            );

            if file_size > 0 {
                let src = &data[file_off..file_off + file_size];
                unsafe {
                    core::ptr::copy_nonoverlapping(src.as_ptr(), vm_addr as *mut u8, file_size);
                }
            }

            // Now apply final permissions
            crate::mmu::map_range(vm_addr, paddr, mem_size as u64, perm);
        }

        Some(Self {
            entry: macho.entry + load_offset,

            header_addr,

            dylinker,

            is_64bit,
        })
    }
}
