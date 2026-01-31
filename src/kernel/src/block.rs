//! Block device traits

extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

pub trait BlockReader: Send + Sync {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> bool;
    fn size(&self) -> u64;
}

pub trait ReadSeek: hfsplus::Read + hfsplus::Seek + Send {}
impl<T: hfsplus::Read + hfsplus::Seek + Send> ReadSeek for T {}

pub struct DeviceWrapper {
    device: Arc<dyn BlockReader>,
    base_offset: u64,
    pos: u64,
}

impl DeviceWrapper {
    pub fn new(device: Arc<dyn BlockReader>, base_offset: u64) -> Self {
        Self {
            device,
            base_offset,
            pos: 0,
        }
    }
}

impl hfsplus::Read for DeviceWrapper {
    fn read(&mut self, buf: &mut [u8]) -> hfsplus::Result<usize> {
        if self.device.read_at(self.base_offset + self.pos, buf) {
            self.pos += buf.len() as u64;
            Ok(buf.len())
        } else {
            Err(hfsplus::Error::InvalidData(String::from("Read failed")))
        }
    }
}

impl hfsplus::Seek for DeviceWrapper {
    fn seek(&mut self, pos: hfsplus::SeekFrom) -> hfsplus::Result<u64> {
        match pos {
            hfsplus::SeekFrom::Start(s) => self.pos = s,
            hfsplus::SeekFrom::Current(c) => self.pos = (self.pos as i64 + c) as u64,
            hfsplus::SeekFrom::End(e) => {
                let size = self.device.size();
                self.pos = (size as i64 + e) as u64;
            }
        }
        Ok(self.pos)
    }
}

impl binrw::io::Read for DeviceWrapper {
    fn read(&mut self, buf: &mut [u8]) -> binrw::io::Result<usize> {
        if self.device.read_at(self.base_offset + self.pos, buf) {
            self.pos += buf.len() as u64;
            Ok(buf.len())
        } else {
            Err(binrw::io::Error::new(
                binrw::io::ErrorKind::Other,
                "Read failed",
            ))
        }
    }
}

impl binrw::io::Seek for DeviceWrapper {
    fn seek(&mut self, pos: binrw::io::SeekFrom) -> binrw::io::Result<u64> {
        match pos {
            binrw::io::SeekFrom::Start(s) => self.pos = s,
            binrw::io::SeekFrom::Current(c) => self.pos = (self.pos as i64 + c) as u64,
            binrw::io::SeekFrom::End(e) => {
                let size = self.device.size();
                self.pos = (size as i64 + e) as u64;
            }
        }
        Ok(self.pos)
    }
}

pub struct BufReader<R> {
    inner: R,
    buffer: Vec<u8>,
    pos: usize,
    cap: usize,
}

impl<R> BufReader<R> {
    pub fn with_capacity(cap: usize, inner: R) -> Self {
        Self {
            inner,
            buffer: vec![0; cap],
            pos: 0,
            cap: 0,
        }
    }
}

impl<R: hfsplus::Read + hfsplus::Seek> hfsplus::Read for BufReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> hfsplus::Result<usize> {
        if self.pos >= self.cap {
            if buf.len() >= self.buffer.len() {
                return self.inner.read(buf);
            }
            self.pos = 0;
            self.cap = self.inner.read(&mut self.buffer)?;
            if self.cap == 0 {
                return Ok(0);
            }
        }
        let n = core::cmp::min(buf.len(), self.cap - self.pos);
        buf[..n].copy_from_slice(&self.buffer[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl<R: hfsplus::Read + hfsplus::Seek> hfsplus::Seek for BufReader<R> {
    fn seek(&mut self, pos: hfsplus::SeekFrom) -> hfsplus::Result<u64> {
        if let hfsplus::SeekFrom::Current(n) = pos {
            let new_pos = self.pos as i64 + n;
            if new_pos >= 0 && new_pos <= self.cap as i64 {
                self.pos = new_pos as usize;
                return self.inner.seek(hfsplus::SeekFrom::Current(0));
            }
        }
        self.pos = 0;
        self.cap = 0;
        self.inner.seek(pos)
    }
}

impl<R: binrw::io::Read + binrw::io::Seek> binrw::io::Read for BufReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> binrw::io::Result<usize> {
        if self.pos >= self.cap {
            if buf.len() >= self.buffer.len() {
                return self.inner.read(buf);
            }
            self.pos = 0;
            self.cap = self.inner.read(&mut self.buffer)?;
            if self.cap == 0 {
                return Ok(0);
            }
        }
        let n = core::cmp::min(buf.len(), self.cap - self.pos);
        buf[..n].copy_from_slice(&self.buffer[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl<R: binrw::io::Read + binrw::io::Seek> binrw::io::Seek for BufReader<R> {
    fn seek(&mut self, pos: binrw::io::SeekFrom) -> binrw::io::Result<u64> {
        if let binrw::io::SeekFrom::Current(n) = pos {
            let new_pos = self.pos as i64 + n;
            if new_pos >= 0 && new_pos <= self.cap as i64 {
                self.pos = new_pos as usize;
                return self.inner.seek(binrw::io::SeekFrom::Current(0));
            }
        }
        self.pos = 0;
        self.cap = 0;
        self.inner.seek(pos)
    }
}
