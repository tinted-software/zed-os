//! Simple TAR filesystem reader (ustar format)

use alloc::string::String;
use alloc::vec::Vec;

const TAR_BLOCK_SIZE: usize = 512;

#[repr(C)]
struct TarHeader {
    name: [u8; 100],
    mode: [u8; 8],
    uid: [u8; 8],
    gid: [u8; 8],
    size: [u8; 12],
    mtime: [u8; 12],
    checksum: [u8; 8],
    typeflag: u8,
    linkname: [u8; 100],
    magic: [u8; 6],
    version: [u8; 2],
    uname: [u8; 32],
    gname: [u8; 32],
    devmajor: [u8; 8],
    devminor: [u8; 8],
    prefix: [u8; 155],
    _pad: [u8; 12],
}

pub struct TarFile {
    pub name: String,
    pub size: usize,
    pub data_offset: usize,
}

pub struct TarFs {
    data: Vec<u8>,
    files: Vec<TarFile>,
}

impl TarFs {
    /// Create a new TarFs from raw data
    pub fn new(data: Vec<u8>) -> Self {
        let mut fs = Self {
            data,
            files: Vec::new(),
        };
        fs.parse();
        fs
    }

    fn parse(&mut self) {
        let mut offset = 0;

        while offset + TAR_BLOCK_SIZE <= self.data.len() {
            let header = unsafe { &*(self.data.as_ptr().add(offset) as *const TarHeader) };

            // Check for end of archive (all zeros)
            if header.name[0] == 0 {
                break;
            }

            // Parse name
            let name_end = header.name.iter().position(|&b| b == 0).unwrap_or(100);
            let name = String::from_utf8_lossy(&header.name[..name_end]).into_owned();

            // Parse size (octal)
            let size = parse_octal(&header.size);

            let data_offset = offset + TAR_BLOCK_SIZE;

            // Only add regular files
            if header.typeflag == b'0' || header.typeflag == 0 {
                self.files.push(TarFile {
                    name,
                    size,
                    data_offset,
                });
            }

            // Move to next header (size rounded up to block boundary)
            let blocks = (size + TAR_BLOCK_SIZE - 1) / TAR_BLOCK_SIZE;
            offset = data_offset + blocks * TAR_BLOCK_SIZE;
        }
    }

    /// Find a file by path
    pub fn find(&self, path: &str) -> Option<&TarFile> {
        // Normalize path (remove leading /)
        let normalized = path.trim_start_matches('/');
        self.files.iter().find(|f| {
            let fname = f.name.trim_start_matches('/').trim_start_matches("./");
            fname == normalized
        })
    }

    /// Read file data
    pub fn read(&self, file: &TarFile) -> &[u8] {
        &self.data[file.data_offset..file.data_offset + file.size]
    }

    /// List all files
    pub fn list(&self) -> &[TarFile] {
        &self.files
    }
}

fn parse_octal(data: &[u8]) -> usize {
    let mut result = 0usize;
    for &b in data {
        if b == 0 || b == b' ' {
            break;
        }
        if b >= b'0' && b <= b'7' {
            result = result * 8 + (b - b'0') as usize;
        }
    }
    result
}
