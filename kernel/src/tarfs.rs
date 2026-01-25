//! Simple TAR filesystem reader (ustar format)

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

/// Trait for reading from a block device
pub trait BlockReader: Send + Sync {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> bool;
}

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

#[derive(Clone)]
pub struct TarFile {
    pub name: String,
    pub size: usize,
    pub data_offset: u64, // Absolute byte offset
}

pub struct TarFs {
    device: Arc<dyn BlockReader>,
    files: Vec<TarFile>,
}

impl TarFs {
    /// Create a new TarFs from a block reader
    pub fn new(device: Arc<dyn BlockReader>, base_offset: u64) -> Self {
        let mut files = Vec::new();
        let mut current_offset = 0u64;
        let mut header_buf = [0u8; 512];

        loop {
            if !device.read_at(base_offset + current_offset, &mut header_buf) {
                break;
            }

            let header = unsafe { &*(header_buf.as_ptr() as *const TarHeader) };

            if header.name[0] == 0 {
                break;
            }

            let name_end = header.name.iter().position(|&b| b == 0).unwrap_or(100);
            let mut name = String::from_utf8_lossy(&header.name[..name_end]).into_owned();

            if header.magic[0] == b'u'
                && header.magic[1] == b's'
                && header.magic[2] == b't'
                && header.magic[3] == b'a'
                && header.magic[4] == b'r'
            {
                let prefix_end = header.prefix.iter().position(|&b| b == 0).unwrap_or(155);
                if prefix_end > 0 {
                    let prefix = String::from_utf8_lossy(&header.prefix[..prefix_end]);
                    name = alloc::format!("{}/{}", prefix, name);
                }
            }

            let size = parse_octal(&header.size);
            let data_offset = current_offset + 512;

            // Only add regular files
            if header.typeflag == b'0' || header.typeflag == 0 {
                files.push(TarFile {
                    name,
                    size,
                    data_offset: base_offset + data_offset,
                });
            } else if header.typeflag == b'1' || header.typeflag == b'2' {
                // Hard link or Symbolic link
                let linkname_end = header.linkname.iter().position(|&b| b == 0).unwrap_or(100);
                let mut linkname =
                    String::from_utf8_lossy(&header.linkname[..linkname_end]).into_owned();

                // If it's a relative symlink, try to resolve it relative to the current file's directory
                if header.typeflag == b'2'
                    && !linkname.starts_with('/')
                    && let Some(parent) = name.rfind('/')
                {
                    let dir = &name[..parent];
                    linkname = alloc::format!("{}/{}", dir, linkname);
                }

                // Find target info
                let target_info = files
                    .iter()
                    .find(|f| {
                        let f_norm = f.name.trim_start_matches('/').trim_start_matches("./");
                        let l_norm = linkname.trim_start_matches('/').trim_start_matches("./");
                        f_norm == l_norm
                    })
                    .map(|f| (f.size, f.data_offset, f.name.clone()));

                if let Some((t_size, t_offset, t_name)) = target_info {
                    crate::kprintln!("TarFs: Resolved link {} -> {}", name, t_name);
                    files.push(TarFile {
                        name,
                        size: t_size,
                        data_offset: t_offset,
                    });
                } else {
                    // crate::kprintln!("TarFs: Link target not found: {} -> {}", name, linkname);
                    // For now, don't push if target not found.
                    // In a real FS we would store the link and resolve at open.
                }
            }

            let data_blocks = size.div_ceil(512);
            current_offset = data_offset + (data_blocks * 512) as u64;
        }

        Self { device, files }
    }

    /// Find a file by path
    pub fn find(&self, path: &str) -> Option<&TarFile> {
        let normalized = path.trim_start_matches('/');

        if let Some(f) = self.files.iter().find(|f| {
            let fname = f.name.trim_start_matches('/').trim_start_matches("./");
            fname == normalized
        }) {
            return Some(f);
        }

        // Suffix heuristic
        if let Some(filename) = path.split('/').next_back() {
            let suffix = alloc::format!("/{}", filename);
            let candidates = self
                .files
                .iter()
                .filter(|f| f.name.ends_with(&suffix) || f.name == filename);
            if let Some(f) = candidates.max_by_key(|f| f.name.len()) {
                return Some(f);
            }
        }
        None
    }

    pub fn open(self: &Arc<Self>, path: &str) -> Option<Box<dyn crate::vfs::File>> {
        let file_info = self.find(path)?.clone();
        Some(Box::new(TarFileHandle {
            fs: self.clone(),
            file_info,
            pos: 0,
        }))
    }

    pub fn list(&self) -> &[TarFile] {
        &self.files
    }
}

pub struct TarFileHandle {
    fs: Arc<TarFs>,
    file_info: TarFile,
    pos: u64,
}

impl crate::vfs::File for TarFileHandle {
    fn read(&mut self, buf: &mut [u8]) -> usize {
        let remaining = self.file_info.size as u64 - self.pos;
        let to_read = (buf.len() as u64).min(remaining);

        if to_read == 0 {
            return 0;
        }

        if self.fs.device.read_at(
            self.file_info.data_offset + self.pos,
            &mut buf[..to_read as usize],
        ) {
            self.pos += to_read;
            to_read as usize
        } else {
            0
        }
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> usize {
        let remaining = (self.file_info.size as u64).saturating_sub(offset);
        let to_read = (buf.len() as u64).min(remaining);

        if to_read == 0 {
            return 0;
        }

        if self.fs.device.read_at(
            self.file_info.data_offset + offset,
            &mut buf[..to_read as usize],
        ) {
            to_read as usize
        } else {
            0
        }
    }

    fn seek(&mut self, pos: u64) {
        self.pos = pos.min(self.file_info.size as u64);
    }

    fn size(&self) -> u64 {
        self.file_info.size as u64
    }
}

fn parse_octal(data: &[u8]) -> usize {
    let mut result = 0usize;
    for &b in data {
        if b == 0 || b == b' ' {
            break;
        }
        if (b'0'..=b'7').contains(&b) {
            result = result * 8 + (b - b'0') as usize;
        }
    }
    result
}
