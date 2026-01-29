use crate::LoaderError;
use core::slice;
use goblin::elf::Elf;

pub struct ElfContext<'a> {
    pub elf: Elf<'a>,
    pub base_addr: usize,
    pub slide: usize,
}

impl<'a> ElfContext<'a> {
    pub unsafe fn parse(header_ptr: *const u8, slide: usize) -> Result<Self, LoaderError> {
        let data = unsafe { slice::from_raw_parts(header_ptr, 1024 * 1024) };
        let elf = Elf::parse(data)?;

        Some(Self {
            elf,
            base_addr: header_ptr as usize,
            slide,
        })
        .ok_or(LoaderError::RelocationError("Failed to create ELF context"))
    }

    pub fn find_symbol(&self, name: &str) -> Option<usize> {
        for sym in self.elf.syms.iter() {
            if let Some(sym_name) = self.elf.strtab.get_at(sym.st_name) {
                if sym_name == name && sym.st_value != 0 {
                    return Some(sym.st_value as usize + self.slide);
                }
            }
        }
        None
    }

    pub unsafe fn apply_relocations(
        &mut self,
        libraries: &[ElfContext<'a>],
        lookup_symbol: impl Fn(&str) -> Option<usize>,
    ) -> Result<(), LoaderError> {
        // Basic relocation support (R_AARCH64_RELATIVE, R_AARCH64_GLOB_DAT, etc.)
        for rel in self.elf.dynrels.iter() {
            let r_type = rel.r_type;
            let r_offset = rel.r_offset as usize + self.slide;
            let r_addend = rel.r_addend.unwrap_or(0);
            let r_sym = rel.r_sym;

            match r_type {
                goblin::elf::reloc::R_AARCH64_RELATIVE => {
                    let ptr = r_offset as *mut usize;
                    // Usually RELATIVE is base + addend. If base_addr is where it's loaded.
                    // If slide is the offset from preferred.
                    // Let's assume slide for now as that's what we use in MachO
                    unsafe { *ptr = (self.slide as i64 + r_addend) as usize };
                }
                goblin::elf::reloc::R_AARCH64_GLOB_DAT
                | goblin::elf::reloc::R_AARCH64_JUMP_SLOT => {
                    if let Some(sym_name) = self
                        .elf
                        .dynstrtab
                        .get_at(self.elf.dynsyms.get(r_sym).unwrap().st_name)
                    {
                        let mut found = false;
                        // 1. Lookup
                        if let Some(addr) = lookup_symbol(sym_name) {
                            unsafe { *(r_offset as *mut usize) = addr };
                            found = true;
                        } else {
                            // 2. Libraries
                            for lib in libraries {
                                if let Some(addr) = lib.find_symbol(sym_name) {
                                    unsafe { *(r_offset as *mut usize) = addr };
                                    found = true;
                                    break;
                                }
                            }
                        }

                        if !found {
                            // Weak symbol?
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}
