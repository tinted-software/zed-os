use core::slice;

#[repr(C)]
pub struct DyldCacheHeader {
    pub magic: [u8; 16],
    pub mapping_offset: u32,
    pub mapping_count: u32,
    pub images_offset: u32,
    pub images_count: u32,
    pub dyld_base_address: u64,
}

#[repr(C)]
pub struct DyldCacheImageInfo {
    pub address: u64,
    pub mod_time: u64,
    pub inode: u64,
    pub path_offset: u32,
    pub pad: u32,
}

pub struct SharedCache {
    base_addr: *const u8,
}

impl SharedCache {
    pub unsafe fn from_addr(addr: usize) -> Option<Self> {
        if addr == 0 {
            return None;
        }

        // TODO: Map the shared cache in kernel and validate it here.
        // For now, returning None avoids a data abort if 0x30000000 is not mapped.
        None
        /*
        let header = &*(addr as *const DyldCacheHeader);
        if &header.magic[0..4] != b"dyld" {
            return None;
        }
        Some(Self {
            base_addr: addr as *const u8,
        })
        */
    }

    pub unsafe fn find_dylib(&self, path: &str) -> Option<*const u8> {
        unsafe {
            let header = &*(self.base_addr as *const DyldCacheHeader);
            let images = slice::from_raw_parts(
                self.base_addr.add(header.images_offset as usize) as *const DyldCacheImageInfo,
                header.images_count as usize,
            );

            for image in images {
                let image_path_ptr = self.base_addr.add(image.path_offset as usize) as *const u8;
                let mut len = 0;
                while *image_path_ptr.add(len) != 0 {
                    len += 1;
                }
                let image_path =
                    core::str::from_utf8(slice::from_raw_parts(image_path_ptr, len)).ok()?;
                if image_path == path {
                    return Some(image.address as *const u8);
                }
            }
            None
        }
    }
}
