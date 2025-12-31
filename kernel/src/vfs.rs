//! Simple Virtual Filesystem abstraction

use crate::tarfs::TarFs;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

static VFS: Mutex<Option<Vfs>> = Mutex::new(None);

pub struct Vfs {
    tarfs: Arc<TarFs>,
}

pub struct FileHandle {
    data: Vec<u8>,
    pos: usize,
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
    let vfs = VFS.lock();
    let vfs = vfs.as_ref()?;

    let file = vfs.tarfs.find(path)?;
    let data = vfs.tarfs.read(file).to_vec();

    Some(FileHandle { data, pos: 0 })
}

/// Stat a file (returns size)
pub fn stat(path: &str) -> Option<usize> {
    let vfs = VFS.lock();
    let vfs = vfs.as_ref()?;

    let file = vfs.tarfs.find(path)?;
    Some(file.size)
}

impl FileHandle {
    /// Read bytes from file
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let remaining = self.data.len() - self.pos;
        let to_read = buf.len().min(remaining);

        buf[..to_read].copy_from_slice(&self.data[self.pos..self.pos + to_read]);
        self.pos += to_read;

        to_read
    }

    /// Get all data
    pub fn read_all(&self) -> &[u8] {
        &self.data
    }

    /// Seek to position
    pub fn seek(&mut self, pos: usize) {
        self.pos = pos.min(self.data.len());
    }

    /// Get file size
    pub fn size(&self) -> usize {
        self.data.len()
    }
}
