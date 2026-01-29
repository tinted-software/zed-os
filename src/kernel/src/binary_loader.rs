use crate::kprintln;
use alloc::string::String;
use alloc::vec;
use goblin::elf::Elf;
use goblin::mach::{Mach, MachO};

pub struct BinaryLoader {
    pub entry: u64,
    pub header_addr: u64,
    pub dylinker: Option<String>,
    pub is_64bit: bool,
    pub flags: u32,
}

pub fn setup_stack(
    sp: u64,
    exec_path: &str,
    mh_addr: u64,
    is_64bit: bool,
    sc_base: u64,
    main_header: u64,
) -> u64 {
    let mut current_sp = sp;

    // Copy strings to stack
    let sc_base_str = alloc::format!("dyld_shared_cache_base_address={:x}", sc_base);
    let exec_path_var = alloc::format!("executable_path={}", exec_path);
    let strings = vec![exec_path, sc_base_str.as_str(), exec_path_var.as_str()];
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
            string_ptrs[0], // apple[0] (exec path - raw)
            string_ptrs[1], // apple[1] (cache base)
            string_ptrs[2], // apple[2] (executable_path var)
            0u64,           // apple[3] (NULL)
        ];

        current_sp -= (values.len() * 8) as u64;
        let stack_top = current_sp;
        unsafe {
            core::ptr::copy_nonoverlapping(values.as_ptr(), current_sp as *mut u64, values.len());
        }
        stack_top
    } else {
        // 32-bit values
        // dyld expects [sp] = mh_addr (its own header)
        // main_header is passed in apple[] args
        let values = [
            mh_addr as u32,        // mach_header
            1u32,                  // argc
            string_ptrs[0] as u32, // argv[0]
            0u32,                  // argv[1] (NULL)
            0u32,                  // envp[0] (NULL)
            string_ptrs[1] as u32, // apple[0] (cache base)
            string_ptrs[2] as u32, // apple[1] (executable_path var)
            main_header as u32,    // apple[2] (main executable header)
            0u32,                  // apple[3] (NULL)
        ];

        current_sp -= (values.len() * 4) as u64;
        let stack_top = current_sp;
        unsafe {
            core::ptr::copy_nonoverlapping(values.as_ptr(), current_sp as *mut u32, values.len());
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

impl BinaryLoader {
    pub fn load(data: &[u8], load_offset: u64) -> Option<Self> {
        kprintln!("BinaryLoader::load: data len {:x}", data.len());

        // Try Mach-O first
        if let Ok(mach) = Mach::parse(data) {
            return match mach {
                Mach::Binary(macho) => Self::load_macho(&macho, data, load_offset),
                Mach::Fat(fat) => {
                    let arches = fat.arches().ok()?;
                    kprintln!("Fat MachO found with {} architectures", arches.len());
                    let arch = arches
                        .iter()
                        .find(|a| a.cputype == goblin::mach::constants::cputype::CPU_TYPE_ARM64)
                        .or_else(|| {
                            arches.iter().find(|a| {
                                a.cputype == goblin::mach::constants::cputype::CPU_TYPE_ARM
                            })
                        })?;

                    let offset = arch.offset as usize;
                    let size = arch.size as usize;
                    let slice = &data[offset..offset + size];
                    let macho = MachO::parse(slice, 0).ok()?;
                    Self::load_macho(&macho, slice, load_offset)
                }
            };
        }

        // Try ELF
        if let Ok(elf) = Elf::parse(data) {
            return Self::load_elf(&elf, data, load_offset);
        }

        kprintln!("Unsupported binary format");
        None
    }

    fn load_macho(macho: &MachO, data: &[u8], load_offset: u64) -> Option<Self> {
        // ... (existing load_macho code remains mostly the same, but returns Self)
        let is_64bit = macho.header.cputype == goblin::mach::constants::cputype::CPU_TYPE_ARM64;
        kprintln!(
            "Loading Mach-O binary (64-bit: {}) with slide {:x}, entry: {:x}, flags: {:x}",
            is_64bit,
            load_offset,
            macho.entry,
            macho.header.flags
        );

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

        let mut header_addr = load_offset;
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
            }

            kprintln!(
                "  Mach-O Segment: {} vaddr={:x} file_off={:x} file_size={:x} mem_size={:x}",
                segname,
                vm_addr,
                file_off,
                file_size,
                mem_size
            );

            let perm = match (prot & 1 != 0, prot & 2 != 0, prot & 4 != 0) {
                _ => crate::mmu::MapPermission::UserRWX,
            };

            let data_size = (file_size + 4095) & !4095;
            if data_size > 0 {
                let layout = core::alloc::Layout::from_size_align(data_size, 4096).unwrap();
                let phys_ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
                let paddr = phys_ptr as u64;
                crate::mmu::map_range(
                    vm_addr,
                    paddr,
                    data_size as u64,
                    crate::mmu::MapPermission::UserRW,
                );
                let src = &data[file_off..file_off + file_size];
                unsafe {
                    core::ptr::copy_nonoverlapping(src.as_ptr(), paddr as *mut u8, file_size);
                }
                crate::mmu::map_range(vm_addr, paddr, data_size as u64, perm);
            }
            if mem_size > data_size {
                let padding_addr = vm_addr + data_size as u64;
                let padding_size = (mem_size - data_size) as u64;
                crate::mmu::map_zero_range(padding_addr, padding_size, perm);
            }
        }

        Some(Self {
            entry: macho.entry + load_offset,
            header_addr,
            dylinker,
            is_64bit,
            flags: macho.header.flags,
        })
    }

    fn load_elf(elf: &Elf, data: &[u8], load_offset: u64) -> Option<Self> {
        let is_64bit = elf.is_64;
        kprintln!(
            "Loading ELF binary (64-bit: {}) with slide {:x}, entry: {:x}...",
            is_64bit,
            load_offset,
            elf.entry
        );

        let mut min_vaddr = u64::MAX;
        for ph in &elf.program_headers {
            kprintln!(
                "  ELF PHDR: type={:x} vaddr={:x} mem_size={:x} file_off={:x} file_size={:x}",
                ph.p_type,
                ph.p_vaddr,
                ph.p_memsz,
                ph.p_offset,
                ph.p_filesz
            );
            if ph.p_type == goblin::elf::program_header::PT_LOAD {
                let vm_addr = ph.p_vaddr + load_offset;
                if vm_addr < min_vaddr {
                    min_vaddr = vm_addr;
                }

                let file_off = ph.p_offset as usize;
                let file_size = ph.p_filesz as usize;
                let mem_size = ph.p_memsz as usize;

                kprintln!(
                    "  ELF Segment: vaddr={:x} mem_size={:x} file_off={:x} file_size={:x}",
                    vm_addr,
                    mem_size,
                    file_off,
                    file_size
                );

                let perm = crate::mmu::MapPermission::UserRWX;

                let data_size = (file_size + 4095) & !4095;
                if data_size > 0 {
                    let layout = core::alloc::Layout::from_size_align(data_size, 4096).unwrap();
                    let phys_ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
                    let paddr = phys_ptr as u64;
                    crate::mmu::map_range(
                        vm_addr,
                        paddr,
                        data_size as u64,
                        crate::mmu::MapPermission::UserRW,
                    );
                    let src = &data[file_off..file_off + file_size];
                    kprintln!(
                        "  Copying {:x} bytes from file_off {:x} to paddr {:x}",
                        file_size,
                        file_off,
                        paddr
                    );
                    if file_size >= 16 {
                        kprintln!("  Source bytes: {:02x?}", &src[0..16]);
                    }
                    unsafe {
                        core::ptr::copy_nonoverlapping(src.as_ptr(), paddr as *mut u8, file_size);
                    }
                    if file_size >= 16 {
                        let dst_slice =
                            unsafe { core::slice::from_raw_parts(paddr as *const u8, 16) };
                        kprintln!("  Dest bytes:   {:02x?}", dst_slice);
                    }
                    crate::mmu::map_range(vm_addr, paddr, data_size as u64, perm);
                }
                if mem_size > data_size {
                    let padding_addr = vm_addr + data_size as u64;
                    let padding_size = (mem_size - data_size) as u64;
                    crate::mmu::map_zero_range(padding_addr, padding_size, perm);
                }
            }
        }

        if min_vaddr == u64::MAX {
            min_vaddr = load_offset;
        }

        Some(Self {
            entry: elf.entry + load_offset,
            header_addr: min_vaddr,
            dylinker: None,
            is_64bit,
            flags: 0,
        })
    }
}
