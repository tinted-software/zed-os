//! Simple Virtual Filesystem abstraction

use crate::hfsfs::HfsFs;
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
    hfsfs: Arc<HfsFs>,
}

pub struct FileHandle {
    pub file: Box<dyn File>,
}

impl Vfs {
    pub fn new(hfsfs: HfsFs) -> Self {
        Self {
            hfsfs: Arc::new(hfsfs),
        }
    }
}

/// Initialize the VFS with an HFS+ filesystem
pub fn init(hfsfs: HfsFs) {
    let mut vfs = VFS.lock();
    *vfs = Some(Vfs::new(hfsfs));
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

    if let Some(file) = vfs.hfsfs.open(path) {
        Some(FileHandle { file })
    } else {
        None
    }
}

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

static mut RANDOM_RNG: Option<ChaCha20Rng> = None;

struct RandomFile {
    pos: u64,
}

impl File for RandomFile {
    fn read(&mut self, buf: &mut [u8]) -> usize {
        unsafe {
            let rng_ptr = core::ptr::addr_of_mut!(RANDOM_RNG);
            if (*rng_ptr).is_none() {
                *rng_ptr = Some(ChaCha20Rng::from_seed([0x42; 32]));
            }
            if let Some(ref mut rng) = *rng_ptr {
                rng.fill_bytes(buf);
            }
        }
        buf.len()
    }
    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> usize {
        unsafe {
            let rng_ptr = core::ptr::addr_of_mut!(RANDOM_RNG);
            if (*rng_ptr).is_none() {
                *rng_ptr = Some(ChaCha20Rng::from_seed([0x42; 32]));
            }
            if let Some(ref mut rng) = *rng_ptr {
                rng.fill_bytes(buf);
            }
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

    /// Seek to position
    pub fn seek(&mut self, pos: u64) {
        self.file.seek(pos);
    }

    /// Read bytes from file to end
    pub fn read_to_end(&mut self) -> Vec<u8> {
        self.file.read_to_end()
    }
}
