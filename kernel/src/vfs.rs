//! Simple Virtual Filesystem abstraction

use crate::tarfs::TarFs;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

static VFS: Mutex<Option<Vfs>> = Mutex::new(None);

pub trait File: Send + Sync {
    fn read(&mut self, buf: &mut [u8]) -> usize;
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> usize;
    fn seek(&mut self, pos: u64);
    fn size(&self) -> u64;

    fn read_to_end(&mut self) -> Vec<u8> {
        let mut chunk = [0u8; 4096];
        let mut buf = Vec::new();

        loop {
            let read = self.read(&mut chunk);
            if read == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..read]);
        }

        buf
    }
}

pub struct Vfs {
    tarfs: Arc<TarFs>,
}

pub struct FileHandle {
    pub file: Box<dyn File>,
}

impl Vfs {
    pub fn new(tarfs: TarFs) -> Self {
        Self {
            tarfs: Arc::new(tarfs),
        }
    }
}

/// Initialize the VFS with a TAR filesystem
pub fn init(tarfs: TarFs) {
    let mut vfs = VFS.lock();
    *vfs = Some(Vfs::new(tarfs));
}

/// Open a file by path
pub fn open(path: &str) -> Option<FileHandle> {
    if path == "/dev/random" || path == "/dev/urandom" {
        return Some(FileHandle {
            file: Box::new(RandomFile { pos: 0 }),
        });
    }

    let vfs = VFS.lock();
    let vfs = vfs.as_ref()?;

    if let Some(file) = vfs.tarfs.open(path) {
        Some(FileHandle { file })
    } else {
        if path.contains("IOKit") {
            crate::kprintln!("VFS: Failed to find IOKit. Listing candidates:");
            for file in vfs.tarfs.list() {
                if file.name.contains("IOKit") || file.name.starts_with("System") {
                    crate::kprintln!("  Candidate: '{}'", file.name);
                }
            }
        }
        None
    }
}

struct RandomFile {
    pos: u64,
}

impl File for RandomFile {
    fn read(&mut self, buf: &mut [u8]) -> usize {
        for b in buf.iter_mut() {
            *b = 0x42; // Not very random, but good enough for a stub
        }
        buf.len()
    }
    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> usize {
        for b in buf.iter_mut() {
            *b = 0x42;
        }
        buf.len()
    }
    fn seek(&mut self, pos: u64) {
        self.pos = pos;
    }
    fn size(&self) -> u64 {
        u64::MAX
    }
}

impl FileHandle {
    /// Read bytes from file
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        self.file.read(buf)
    }

    /// Read at offset
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> usize {
        self.file.read_at(offset, buf)
    }

    /// Get file size
    pub fn size(&self) -> u64 {
        self.file.size()
    }

    /// Read bytes from file to end
    pub fn read_to_end(&mut self) -> Vec<u8> {
        self.file.read_to_end()
    }
}
