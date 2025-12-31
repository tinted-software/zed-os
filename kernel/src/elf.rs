use goblin::elf;

pub fn load_elf(data: &[u8]) -> Option<u64> {
    let elf = elf::Elf::parse(data).ok()?;

    // Simple loader: just iterate program headers and copy to memory
    // In a real OS, we'd map pages. Here we assume identity mapping and no overlap.
    for ph in elf.program_headers {
        if ph.p_type == elf::program_header::PT_LOAD {
            let dest = ph.p_paddr as *mut u8;
            let offset = ph.p_offset as usize;
            let size = ph.p_filesz as usize;
            let mem_size = ph.p_memsz as usize;

            if size > 0 {
                let src = &data[offset..offset + size];
                unsafe {
                    core::ptr::copy_nonoverlapping(src.as_ptr(), dest, size);
                }
            }

            // Zero out remaining memory (BSS)
            if mem_size > size {
                unsafe {
                    core::ptr::write_bytes(dest.add(size), 0, mem_size - size);
                }
            }
        }
    }

    Some(elf.entry)
}
