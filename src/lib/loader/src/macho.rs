use crate::LoaderError;
use core::slice;
use goblin::mach::MachO;

// Re-export goblin structures that might be useful
pub use goblin::mach;

pub struct MachOContext<'a> {
    pub macho: MachO<'a>,
    pub base_addr: usize,
    pub slide: usize,
}

impl<'a> MachOContext<'a> {
    pub unsafe fn parse(header_ptr: *const u8, slide: usize) -> Result<Self, LoaderError> {
        // Mach-O headers are reasonably small initially.
        let data = unsafe { slice::from_raw_parts(header_ptr, 1024 * 1024) }; // Safety: Hope it's mapped
        let macho = MachO::parse(data, 0)?;

        Ok(Self {
            macho,
            base_addr: header_ptr as usize,
            slide,
        })
    }

    pub fn find_symbol(&self, name: &str) -> Option<usize> {
        for sym in self.macho.symbols() {
            if let Ok((sym_name, nlist)) = sym {
                if sym_name == name && nlist.n_value != 0 {
                    return Some(nlist.n_value as usize + self.slide);
                }
            }
        }
        None
    }

    pub unsafe fn apply_relocations(
        &mut self,
        libraries: &[MachOContext<'a>],
        lookup_symbol: impl Fn(&str) -> Option<usize>,
    ) -> Result<(), LoaderError> {
        let slide = self.slide;
        for cmd in &self.macho.load_commands {
            if let goblin::mach::load_command::CommandVariant::DyldInfoOnly(dyld_info) =
                &cmd.command
            {
                if dyld_info.rebase_size > 0 {
                    let rebase_data = unsafe {
                        slice::from_raw_parts(
                            (self.base_addr + dyld_info.rebase_off as usize) as *const u8,
                            dyld_info.rebase_size as usize,
                        )
                    };
                    (unsafe { self.perform_rebase(rebase_data, slide) })?;
                }
                if dyld_info.bind_size > 0 {
                    let bind_data = unsafe {
                        slice::from_raw_parts(
                            (self.base_addr + dyld_info.bind_off as usize) as *const u8,
                            dyld_info.bind_size as usize,
                        )
                    };
                    (unsafe { self.perform_bind(bind_data, slide, libraries, &lookup_symbol) })?;
                }
            }
        }
        Ok(())
    }

    unsafe fn perform_bind(
        &self,
        data: &[u8],
        slide: usize,
        libraries: &[MachOContext<'a>],
        lookup_symbol: &impl Fn(&str) -> Option<usize>,
    ) -> Result<(), LoaderError> {
        let mut cursor = 0;
        let mut seg_offset = 0;
        let mut segment_address = 0;
        let mut library_ordinal = 0;
        let mut symbol_name = "";

        while cursor < data.len() {
            let byte = data[cursor];
            cursor += 1;
            let opcode = byte & 0xf0;
            let immediate = byte & 0x0f;

            match opcode {
                0x00 => break, // DONE
                0x10 => library_ordinal = immediate as usize,
                0x20 => library_ordinal = decode_uleb128(data, &mut cursor),
                0x30 => {}
                0x40 => {
                    let start = cursor;
                    while data[cursor] != 0 {
                        cursor += 1;
                    }
                    symbol_name = unsafe { core::str::from_utf8_unchecked(&data[start..cursor]) };
                    cursor += 1; // skip NULL
                }
                0x50 => {}
                0x60 => {
                    decode_sleb128(data, &mut cursor);
                }
                0x70 => {
                    let seg_index = immediate as usize;
                    seg_offset = decode_uleb128(data, &mut cursor);
                    if let Some(segment) = self.macho.segments.get(seg_index) {
                        segment_address = segment.vmaddr as usize + slide;
                    }
                }
                0x80 => {
                    seg_offset += decode_uleb128(data, &mut cursor);
                }
                0x90 => {
                    unsafe {
                        self.bind_at(
                            segment_address + seg_offset,
                            symbol_name,
                            library_ordinal,
                            libraries,
                            lookup_symbol,
                        )
                    };
                    seg_offset += 8;
                }
                0xA0 => {
                    unsafe {
                        self.bind_at(
                            segment_address + seg_offset,
                            symbol_name,
                            library_ordinal,
                            libraries,
                            lookup_symbol,
                        )
                    };
                    seg_offset += decode_uleb128(data, &mut cursor) + 8;
                }
                0xB0 => {
                    unsafe {
                        self.bind_at(
                            segment_address + seg_offset,
                            symbol_name,
                            library_ordinal,
                            libraries,
                            lookup_symbol,
                        )
                    };
                    seg_offset += immediate as usize * 8 + 8;
                }
                0xC0 => {
                    let count = decode_uleb128(data, &mut cursor);
                    let skip = decode_uleb128(data, &mut cursor);
                    for _ in 0..count {
                        unsafe {
                            self.bind_at(
                                segment_address + seg_offset,
                                symbol_name,
                                library_ordinal,
                                libraries,
                                lookup_symbol,
                            )
                        };
                        seg_offset += skip + 8;
                    }
                }
                _ => return Err(LoaderError::RelocationError("Unknown bind opcode")),
            }
        }
        Ok(())
    }

    unsafe fn bind_at(
        &self,
        addr: usize,
        name: &str,
        _ordinal: usize,
        libraries: &[MachOContext<'a>],
        lookup_symbol: &impl Fn(&str) -> Option<usize>,
    ) {
        // First try the provided lookup function (e.g. shared cache)
        if let Some(sym_addr) = lookup_symbol(name) {
            let ptr = addr as *mut usize;
            unsafe { *ptr = sym_addr };
            return;
        }

        // Then look in all loaded libraries
        for lib in libraries {
            if let Some(sym_addr) = lib.find_symbol(name) {
                let ptr = addr as *mut usize;
                unsafe { *ptr = sym_addr };
                return;
            }
        }
    }

    unsafe fn perform_rebase(&self, data: &[u8], slide: usize) -> Result<(), LoaderError> {
        let mut cursor = 0;
        let mut seg_offset = 0;
        let mut segment_address = 0;

        while cursor < data.len() {
            let byte = data[cursor];
            cursor += 1;
            let opcode = byte & 0xf0;
            let immediate = byte & 0x0f;

            match opcode {
                0x00 => break, // DONE
                0x10 => {}
                0x20 => {
                    let seg_index = immediate as usize;
                    seg_offset = decode_uleb128(data, &mut cursor);
                    if let Some(segment) = self.macho.segments.get(seg_index) {
                        segment_address = segment.vmaddr as usize + slide;
                    }
                }
                0x30 => {
                    decode_sleb128(data, &mut cursor);
                }
                0x40 => {
                    seg_offset += immediate as usize * 8;
                }
                0x50 => {
                    seg_offset += decode_uleb128(data, &mut cursor);
                }
                0x60 => {
                    for _ in 0..immediate {
                        unsafe { self.rebase_at(segment_address + seg_offset, slide) };
                        seg_offset += 8;
                    }
                }
                0x70 => {
                    let count = decode_uleb128(data, &mut cursor);
                    for _ in 0..count {
                        unsafe { self.rebase_at(segment_address + seg_offset, slide) };
                        seg_offset += 8;
                    }
                }
                0x80 => {
                    unsafe { self.rebase_at(segment_address + seg_offset, slide) };
                    seg_offset += immediate as usize * 8 + 8;
                }
                0x90 => {
                    let count = decode_uleb128(data, &mut cursor);
                    let skip = decode_uleb128(data, &mut cursor);
                    for _ in 0..count {
                        unsafe { self.rebase_at(segment_address + seg_offset, slide) };
                        seg_offset += skip + 8;
                    }
                }
                _ => return Err(LoaderError::RelocationError("Unknown rebase opcode")),
            }
        }
        Ok(())
    }

    unsafe fn rebase_at(&self, addr: usize, slide: usize) {
        unsafe {
            let ptr = addr as *mut usize;
            *ptr += slide;
        }
    }
}

fn decode_uleb128(data: &[u8], cursor: &mut usize) -> usize {
    let mut result = 0;
    let mut shift = 0;
    while *cursor < data.len() {
        let byte = data[*cursor];
        *cursor += 1;
        result |= ((byte & 0x7f) as usize) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    result
}

fn decode_sleb128(data: &[u8], cursor: &mut usize) -> isize {
    let mut result = 0;
    let mut shift = 0;
    let mut byte = 0;
    while *cursor < data.len() {
        byte = data[*cursor];
        *cursor += 1;
        result |= ((byte & 0x7f) as isize) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
    }
    if (shift < 64) && (byte & 0x40 != 0) {
        result |= -(1 << shift);
    }
    result
}
