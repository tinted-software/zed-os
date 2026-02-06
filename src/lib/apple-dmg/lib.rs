#![no_std]

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use binrw::io::{Read, Seek, SeekFrom};
use derive_more::derive::Display;

#[cfg(feature = "std")]
use std::io::{BufReader, BufWriter};

#[cfg(feature = "std")]
use std::path::Path;

#[derive(Debug, Display)]
pub enum DmgError {
    #[display("Invalid signature: expected {expected:?}, found {found:?}")]
    InvalidSignature { expected: [u8; 4], found: [u8; 4] },
    #[display("Invalid version: {_0}")]
    InvalidVersion(u32),
    #[display("Invalid header size: {_0}")]
    InvalidHeaderSize(u32),
    #[display("IO error: {_0}")]
    Io(alloc::string::String),
    #[display("Decompression failed: {_0}")]
    DecompressionFailed(alloc::string::String),
    #[display("Compression failed: {_0}")]
    CompressionFailed(alloc::string::String),
    #[display("Plist error: {_0}")]
    PlistError(alloc::string::String),
    #[display("Unsupported chunk type: {_0:?}")]
    UnsupportedChunkType(u32),
    #[display("Negative seek")]
    NegativeSeek,
    #[display("Other: {_0}")]
    Other(alloc::string::String),
}

#[cfg(feature = "std")]
impl std::error::Error for DmgError {}

#[cfg(not(feature = "std"))]
impl core::error::Error for DmgError {}

pub type Result<T> = core::result::Result<T, DmgError>;

#[cfg(feature = "std")]
pub use {
    fatfs::{Dir, FileSystem, FormatVolumeOptions, FsOptions, ReadWriteSeek},
    fscommon::BufStream,
    std::fs::File,
};

mod mbr;
pub use crate::mbr::{PartRecord, ProtectiveMBR};

mod blkx;
mod koly;
mod xml;

pub use crate::{blkx::*, koly::*, xml::*};

pub struct DmgReader<R: Read + Seek> {
    koly: KolyTrailer,
    xml: Plist,
    r: R,
}

#[cfg(feature = "std")]
impl DmgReader<BufReader<File>> {
    pub fn open(path: &Path) -> Result<Self> {
        let r = BufReader::with_capacity(
            10 * 1024 * 1024,
            File::open(path).map_err(|e| DmgError::Io(e.to_string()))?,
        );
        Self::new(r)
    }
}

impl<R: Read + Seek> DmgReader<R> {
    pub fn new(mut r: R) -> Result<Self> {
        let koly = KolyTrailer::read_from(&mut r)?;
        r.seek(SeekFrom::Start(koly.plist_offset))
            .map_err(|e| DmgError::Io(e.to_string()))?;
        let mut _xml_data = Vec::with_capacity(koly.plist_length as usize);

        #[cfg(feature = "std")]
        {
            use std::io::Read as _;
            let r_std = &mut r;
            r_std
                .take(koly.plist_length)
                .read_to_end(&mut _xml_data)
                .map_err(|e| DmgError::Io(e.to_string()))?;
        }
        #[cfg(not(feature = "std"))]
        {
            let mut buf = vec![0u8; koly.plist_length as usize];
            r.read_exact(&mut buf)
                .map_err(|e| DmgError::Io(e.to_string()))?;
            _xml_data = buf;
        }

        #[cfg(not(feature = "plist"))]
        return Err(DmgError::Other(
            "Plist parsing not supported in no_std yet".to_string(),
        ));

        #[cfg(feature = "plist")]
        {
            let xml: Plist = plist::from_reader_xml(&_xml_data[..])
                .map_err(|e| DmgError::PlistError(e.to_string()))?;
            Ok(Self { koly, xml, r })
        }
    }

    pub fn koly(&self) -> &KolyTrailer {
        &self.koly
    }

    pub fn plist(&self) -> &Plist {
        &self.xml
    }

    #[cfg(feature = "std")]
    pub fn sector(
        &mut self,
        chunk: &BlkxChunk,
    ) -> Result<alloc::boxed::Box<dyn std::io::Read + '_>> {
        let ty = chunk.ty().expect("unknown chunk type");
        match ty {
            ChunkType::Ignore | ChunkType::Zero => {
                use std::io::Read as _;
                Ok(alloc::boxed::Box::new(
                    std::io::repeat(0).take(chunk.sector_count * 512),
                ))
            }
            ChunkType::Comment => Ok(alloc::boxed::Box::new(std::io::empty())),
            ChunkType::Raw => {
                use std::io::Read as _;
                self.r
                    .seek(SeekFrom::Start(chunk.compressed_offset))
                    .map_err(|e| DmgError::Io(e.to_string()))?;
                Ok(alloc::boxed::Box::new(
                    (&mut self.r).take(chunk.compressed_length),
                ))
            }
            ChunkType::Zlib => {
                self.r
                    .seek(SeekFrom::Start(chunk.compressed_offset))
                    .map_err(|e| DmgError::Io(e.to_string()))?;
                let mut compressed = vec![0u8; chunk.compressed_length as usize];
                self.r
                    .read_exact(&mut compressed)
                    .map_err(|e| DmgError::Io(e.to_string()))?;
                let decompressed =
                    decompress_zlib(&compressed, (chunk.sector_count * 512) as usize)?;
                Ok(alloc::boxed::Box::new(std::io::Cursor::new(decompressed)))
            }
            ChunkType::Adc | ChunkType::Bzlib | ChunkType::Lzfse => unimplemented!(),
            ChunkType::Term => Ok(alloc::boxed::Box::new(std::io::empty())),
        }
    }

    pub fn partition_data(&mut self, i: usize) -> Result<Vec<u8>> {
        let table = self.plist().partitions()[i]
            .table()
            .map_err(|e| DmgError::Other(e.to_string()))?;

        #[cfg(feature = "std")]
        {
            let mut partition = Vec::new();
            for chunk in &table.chunks {
                if chunk.ty() == Some(ChunkType::Term) {
                    continue;
                }
                let mut sector_reader = self.sector(chunk)?;
                std::io::copy(&mut sector_reader, &mut partition)
                    .map_err(|e| DmgError::Io(e.to_string()))?;
            }
            Ok(partition)
        }
        #[cfg(not(feature = "std"))]
        {
            let _ = table;
            return Err(DmgError::Other(
                "partition_data not supported in no_std".to_string(),
            ));
        }
    }

    #[cfg(feature = "std")]
    pub fn copy_partition_to<W: std::io::Write>(&mut self, i: usize, mut writer: W) -> Result<u64> {
        let table = self.plist().partitions()[i]
            .table()
            .map_err(|e| DmgError::Other(e.to_string()))?;
        let mut total = 0;
        let mut buffer = vec![0u8; 1024 * 1024];
        for chunk in &table.chunks {
            if chunk.ty() == Some(ChunkType::Term) {
                continue;
            }
            let mut sector_reader = self.sector(chunk)?;
            loop {
                use std::io::Read as _;
                let n = sector_reader
                    .read(&mut buffer)
                    .map_err(|e| DmgError::Io(e.to_string()))?;
                if n == 0 {
                    break;
                }
                writer
                    .write_all(&buffer[..n])
                    .map_err(|e| DmgError::Io(e.to_string()))?;
                total += n as u64;
            }
        }
        Ok(total)
    }

    pub fn into_partition_reader(self, i: usize) -> Result<DmgPartitionReader<R>> {
        let table = self.plist().partitions()[i]
            .table()
            .map_err(|e| DmgError::Other(e.to_string()))?;
        let total_size = table
            .chunks
            .iter()
            .filter(|c| c.ty() != Some(ChunkType::Term))
            .map(|c| c.sector_count * 512)
            .sum::<u64>();
        Ok(DmgPartitionReader {
            r: self.r,
            chunks: table.chunks,
            pos: 0,
            total_size,
            cache: BTreeMap::new(),
            cache_order: Vec::new(),
        })
    }
}

pub struct DmgPartitionReader<R: Read + Seek> {
    r: R,
    chunks: Vec<BlkxChunk>,
    pos: u64,
    total_size: u64,
    cache: BTreeMap<usize, Vec<u8>>,
    cache_order: Vec<usize>,
}

const MAX_CACHE_CHUNKS: usize = 256;

impl<R: Read + Seek> DmgPartitionReader<R> {
    fn get_chunk_at_pos(&self, pos: u64) -> Option<(usize, &BlkxChunk)> {
        let sector = pos / 512;

        if let Some(&last_idx) = self.cache_order.last() {
            let c = &self.chunks[last_idx];
            if sector >= c.sector_number && sector < c.sector_number + c.sector_count {
                return Some((last_idx, c));
            }
            if last_idx + 1 < self.chunks.len() {
                let c = &self.chunks[last_idx + 1];
                if sector >= c.sector_number && sector < c.sector_number + c.sector_count {
                    return Some((last_idx + 1, c));
                }
            }
        }

        let result = self.chunks.binary_search_by(|c| {
            if sector < c.sector_number {
                core::cmp::Ordering::Greater
            } else if sector >= c.sector_number + c.sector_count {
                core::cmp::Ordering::Less
            } else {
                core::cmp::Ordering::Equal
            }
        });

        match result {
            Ok(idx) => Some((idx, &self.chunks[idx])),
            Err(_) => None,
        }
    }

    fn load_chunk(&mut self, idx: usize) -> Result<()> {
        if self.cache.contains_key(&idx) {
            if let Some(pos) = self.cache_order.iter().position(|&i| i == idx) {
                self.cache_order.remove(pos);
            }
            self.cache_order.push(idx);
            return Ok(());
        }

        let chunk = &self.chunks[idx];
        let mut data = Vec::with_capacity((chunk.sector_count * 512) as usize);

        let ty = chunk.ty().expect("unknown chunk type");
        match ty {
            ChunkType::Ignore | ChunkType::Zero => {
                data.resize((chunk.sector_count * 512) as usize, 0);
            }
            ChunkType::Comment => {}
            ChunkType::Raw => {
                self.r
                    .seek(SeekFrom::Start(chunk.compressed_offset))
                    .map_err(|e| DmgError::Io(e.to_string()))?;
                data.resize(chunk.compressed_length as usize, 0);
                self.r
                    .read_exact(&mut data)
                    .map_err(|e| DmgError::Io(e.to_string()))?;
            }
            ChunkType::Zlib => {
                self.r
                    .seek(SeekFrom::Start(chunk.compressed_offset))
                    .map_err(|e| DmgError::Io(e.to_string()))?;
                let mut compressed = vec![0u8; chunk.compressed_length as usize];
                self.r
                    .read_exact(&mut compressed)
                    .map_err(|e| DmgError::Io(e.to_string()))?;

                data = decompress_zlib(&compressed, (chunk.sector_count * 512) as usize)?;
            }
            _ => return Err(DmgError::UnsupportedChunkType(chunk.r#type)),
        }

        if self.cache.len() >= MAX_CACHE_CHUNKS && !self.cache_order.is_empty() {
            let oldest = self.cache_order.remove(0);
            self.cache.remove(&oldest);
        }

        self.cache.insert(idx, data);
        self.cache_order.push(idx);
        Ok(())
    }

    fn internal_read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let (idx, chunk_start_sectors, chunk_sector_count) = match self.get_chunk_at_pos(self.pos) {
            Some((idx, chunk)) => (idx, chunk.sector_number, chunk.sector_count),
            None => return Ok(0),
        };

        self.load_chunk(idx)?;

        let chunk_data = &self.cache[&idx];
        let offset_in_chunk = (self.pos - chunk_start_sectors * 512) as usize;
        let available = chunk_data.len().saturating_sub(offset_in_chunk);

        if available == 0 {
            self.pos = (chunk_start_sectors + chunk_sector_count) * 512;
            return self.internal_read(buf);
        }

        let n = core::cmp::min(buf.len(), available);
        buf[..n].copy_from_slice(&chunk_data[offset_in_chunk..offset_in_chunk + n]);
        self.pos += n as u64;
        Ok(n)
    }

    fn internal_seek(&mut self, pos: SeekFrom) -> Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(s) => s as i64,
            SeekFrom::Current(c) => self.pos as i64 + c,
            SeekFrom::End(e) => self.total_size as i64 + e,
        };

        if new_pos < 0 {
            return Err(DmgError::NegativeSeek);
        }

        self.pos = new_pos as u64;
        Ok(self.pos)
    }
}

impl<R: Read + Seek> Read for DmgPartitionReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> binrw::io::Result<usize> {
        self.internal_read(buf)
            .map_err(|e| binrw::io::Error::new(binrw::io::ErrorKind::Other, e.to_string()))
    }
}

impl<R: Read + Seek> Seek for DmgPartitionReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> binrw::io::Result<u64> {
        self.internal_seek(pos)
            .map_err(|e| binrw::io::Error::new(binrw::io::ErrorKind::Other, e.to_string()))
    }
}

impl<R: Read + Seek> hfsplus::Read for DmgPartitionReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> hfsplus::Result<usize> {
        self.internal_read(buf)
            .map_err(|e| hfsplus::Error::InvalidData(e.to_string()))
    }
}

impl<R: Read + Seek> hfsplus::Seek for DmgPartitionReader<R> {
    fn seek(&mut self, pos: hfsplus::SeekFrom) -> hfsplus::Result<u64> {
        let pos = match pos {
            hfsplus::SeekFrom::Start(s) => SeekFrom::Start(s),
            hfsplus::SeekFrom::Current(c) => SeekFrom::Current(c),
            hfsplus::SeekFrom::End(e) => SeekFrom::End(e),
        };
        self.internal_seek(pos)
            .map_err(|e| hfsplus::Error::InvalidData(e.to_string()))
    }
}

#[cfg(feature = "std")]
pub struct DmgWriter<W: std::io::Write + std::io::Seek> {
    xml: Plist,
    w: W,
    data_hasher: crc32fast::Hasher,
    main_hasher: crc32fast::Hasher,
    sector_number: u64,
    compressed_offset: u64,
}

#[cfg(feature = "std")]
impl DmgWriter<BufWriter<File>> {
    pub fn create(path: &Path) -> Result<Self> {
        let w = BufWriter::new(
            File::options()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(path)
                .map_err(|e| DmgError::Io(e.to_string()))?,
        );
        Ok(Self::new(w))
    }
}

#[cfg(feature = "std")]
impl<W: std::io::Write + std::io::Seek> DmgWriter<W> {
    pub fn new(w: W) -> Self {
        Self {
            xml: Default::default(),
            w,
            data_hasher: crc32fast::Hasher::new(),
            main_hasher: crc32fast::Hasher::new(),
            sector_number: 0,
            compressed_offset: 0,
        }
    }

    pub fn create_fat32(mut self, fat32: &[u8]) -> Result<()> {
        if fat32.len() % 512 != 0 {
            return Err(DmgError::Other(
                "FAT32 size must be multiple of 512".to_string(),
            ));
        }
        let sector_count = fat32.len() as u64 / 512;
        let mut mbr = ProtectiveMBR::new();
        let mut partition = PartRecord::new_protective(Some(
            sector_count
                .try_into()
                .map_err(|_| DmgError::Other("Too many sectors".to_string()))?,
        ));
        partition.os_type = 11;
        mbr.set_partition(0, partition);
        let mbr = mbr.to_bytes().to_vec();
        self.add_partition("Master Boot Record (MBR : 0)", &mbr)?;
        self.add_partition("FAT32 (FAT32 : 1)", fat32)?;
        self.finish()?;
        Ok(())
    }

    pub fn add_partition(&mut self, name: &str, bytes: &[u8]) -> Result<()> {
        if bytes.len() % 512 != 0 {
            return Err(DmgError::Other(
                "Partition size must be multiple of 512".to_string(),
            ));
        }
        let id = self.xml.partitions().len() as u32;
        let name = name.to_string();
        let mut table = BlkxTable::new(id, self.sector_number, crc32fast::hash(bytes));
        for chunk in bytes.chunks(2048 * 512) {
            let compressed = compress_zlib(chunk)?;
            let compressed_length = compressed.len() as u64;
            let sector_count = chunk.len() as u64 / 512;
            self.w
                .write_all(&compressed)
                .map_err(|e| DmgError::Io(e.to_string()))?;
            self.data_hasher.update(&compressed);
            table.add_chunk(BlkxChunk::new(
                ChunkType::Zlib,
                self.sector_number,
                sector_count,
                self.compressed_offset,
                compressed_length,
            ));
            self.sector_number += sector_count;
            self.compressed_offset += compressed_length;
        }
        table.add_chunk(BlkxChunk::term(self.sector_number, self.compressed_offset));
        self.main_hasher.update(&table.checksum.data[..4]);
        self.xml
            .add_partition(Partition::new(id as i32 - 1, name, table));
        Ok(())
    }

    pub fn finish(mut self) -> Result<()> {
        let mut xml = vec![];
        plist::to_writer_xml(&mut xml, &self.xml).map_err(|e| DmgError::Other(e.to_string()))?;
        let pos = self
            .w
            .seek(std::io::SeekFrom::End(0))
            .map_err(|e| DmgError::Io(e.to_string()))?;
        let data_digest = self.data_hasher.finalize();
        let main_digest = self.main_hasher.finalize();
        let koly = KolyTrailer::new(
            pos,
            self.sector_number,
            pos,
            xml.len() as _,
            data_digest,
            main_digest,
        );
        self.w
            .write_all(&xml)
            .map_err(|e| DmgError::Io(e.to_string()))?;
        koly.write_to(&mut self.w)?;
        Ok(())
    }
}

// https://wiki.samba.org/index.php/UNIX_Extensions#Storing_symlinks_on_Windows_servers
#[cfg(feature = "std")]
fn symlink(target: &str) -> Result<Vec<u8>> {
    let xsym = alloc::format!(
        "XSym\n{:04}\n{:x}\n{}\n",
        target.len(),
        md5::compute(target.as_bytes()),
        target,
    );
    let mut xsym = xsym.into_bytes();
    if xsym.len() > 1067 {
        return Err(DmgError::Other("Symlink target too long".to_string()));
    }
    xsym.resize(1067, b' ');
    Ok(xsym)
}

#[cfg(feature = "std")]
fn add_dir<T: ReadWriteSeek>(src: &Path, dest: &Dir<'_, T>) -> Result<()> {
    for entry in std::fs::read_dir(src).map_err(|e| DmgError::Io(e.to_string()))? {
        let entry = entry.map_err(|e| DmgError::Io(e.to_string()))?;
        let file_name = entry.file_name();
        let file_name = file_name.to_str().unwrap();
        let source = src.join(file_name);
        let file_type = entry.file_type().map_err(|e| DmgError::Io(e.to_string()))?;
        if file_type.is_dir() {
            let d = dest
                .create_dir(file_name)
                .map_err(|e| DmgError::Other(e.to_string()))?;
            add_dir(&source, &d)?;
        } else if file_type.is_file() {
            let mut f = dest
                .create_file(file_name)
                .map_err(|e| DmgError::Other(e.to_string()))?;
            std::io::copy(
                &mut std::fs::File::open(source).map_err(|e| DmgError::Io(e.to_string()))?,
                &mut f,
            )
            .map_err(|e| DmgError::Io(e.to_string()))?;
        } else if file_type.is_symlink() {
            let target = std::fs::read_link(&source).map_err(|e| DmgError::Io(e.to_string()))?;
            let xsym = symlink(target.to_str().unwrap())?;
            let mut f = dest
                .create_file(file_name)
                .map_err(|e| DmgError::Other(e.to_string()))?;
            std::io::copy(&mut &xsym[..], &mut f).map_err(|e| DmgError::Io(e.to_string()))?;
        }
    }
    Ok(())
}

#[cfg(feature = "std")]
pub fn create_dmg(dir: &Path, dmg: &Path, volume_label: &str, total_sectors: u32) -> Result<()> {
    let mut fat32 = vec![0; total_sectors as usize * 512];
    {
        let mut volume_label_bytes = [0; 11];
        let end = core::cmp::min(volume_label_bytes.len(), volume_label.len());
        volume_label_bytes[..end].copy_from_slice(&volume_label.as_bytes()[..end]);
        let volume_options = FormatVolumeOptions::new()
            .volume_label(volume_label_bytes)
            .bytes_per_sector(512)
            .total_sectors(total_sectors);
        let mut disk = BufStream::new(binrw::io::Cursor::new(&mut fat32));
        fatfs::format_volume(&mut disk, volume_options)
            .map_err(|e| DmgError::Other(e.to_string()))?;
        let fs =
            FileSystem::new(disk, FsOptions::new()).map_err(|e| DmgError::Other(e.to_string()))?;
        let file_name = dir.file_name().unwrap().to_str().unwrap();
        let dest = fs
            .root_dir()
            .create_dir(file_name)
            .map_err(|e| DmgError::Other(e.to_string()))?;
        add_dir(dir, &dest)?;
    }
    DmgWriter::create(dmg)?.create_fat32(&fat32)
}

fn decompress_zlib(compressed: &[u8], uncompressed_size: usize) -> Result<Vec<u8>> {
    use zlib_rs::ReturnCode;
    use zlib_rs::c_api::z_stream;
    use zlib_rs::inflate::{InflateConfig, InflateStream, inflate, init};

    unsafe extern "C" fn zalloc_dmg(
        _opaque: *mut core::ffi::c_void,
        items: core::ffi::c_uint,
        size: core::ffi::c_uint,
    ) -> *mut core::ffi::c_void {
        let size = items as usize * size as usize;
        let layout = match core::alloc::Layout::from_size_align(size + 16, 16) {
            Ok(l) => l,
            Err(_) => return core::ptr::null_mut(),
        };
        let ptr = unsafe { alloc::alloc::alloc(layout) };
        if ptr.is_null() {
            return core::ptr::null_mut();
        }
        unsafe {
            ptr.cast::<usize>().write(size);
            ptr.add(16).cast()
        }
    }

    unsafe extern "C" fn zfree_dmg(_opaque: *mut core::ffi::c_void, ptr: *mut core::ffi::c_void) {
        if ptr.is_null() {
            return;
        }
        unsafe {
            let real_ptr = ptr.sub(16);
            let size = real_ptr.cast::<usize>().read();
            let layout = core::alloc::Layout::from_size_align(size + 16, 16).unwrap();
            alloc::alloc::dealloc(real_ptr.cast(), layout);
        }
    }

    let mut strm = z_stream {
        next_in: compressed.as_ptr() as *mut _,
        avail_in: compressed.len() as _,
        zalloc: Some(zalloc_dmg),
        zfree: Some(zfree_dmg),
        opaque: core::ptr::null_mut(),
        ..Default::default()
    };

    let config = InflateConfig { window_bits: 15 };

    if init(&mut strm, config) != ReturnCode::Ok {
        return Err(DmgError::DecompressionFailed(
            "inflateInit failed".to_string(),
        ));
    }

    let mut decompressed = vec![0u8; uncompressed_size];
    let strm_infl = unsafe { InflateStream::from_stream_mut(&mut strm).unwrap() };

    strm.next_out = decompressed.as_mut_ptr();
    strm.avail_out = decompressed.len() as _;

    let ret = unsafe { inflate(strm_infl, zlib_rs::InflateFlush::Finish) };
    let _ = zlib_rs::inflate::end(strm_infl);

    if ret == ReturnCode::StreamEnd || (ret == ReturnCode::Ok && strm.avail_out == 0) {
        Ok(decompressed)
    } else {
        Err(DmgError::DecompressionFailed(alloc::format!(
            "inflate failed: {:?}",
            ret
        )))
    }
}

#[cfg(feature = "std")]
fn compress_zlib(data: &[u8]) -> Result<Vec<u8>> {
    use zlib_rs::ReturnCode;
    use zlib_rs::c_api::z_stream;
    use zlib_rs::deflate::{DeflateConfig, DeflateStream, deflate, init};

    let mut strm = z_stream {
        next_in: data.as_ptr() as *mut _,
        avail_in: data.len() as _,
        ..Default::default()
    };

    let config = DeflateConfig::new(6); // Default compression

    if init(&mut strm, config) != ReturnCode::Ok {
        return Err(DmgError::CompressionFailed(
            "deflateInit failed".to_string(),
        ));
    }

    let mut compressed = vec![0u8; data.len() + 128]; // Slightly larger buffer
    strm.next_out = compressed.as_mut_ptr();
    strm.avail_out = compressed.len() as _;

    let deflate_strm = unsafe { DeflateStream::from_stream_mut(&mut strm).unwrap() };
    let ret = deflate(deflate_strm, zlib_rs::DeflateFlush::Finish);
    let _ = zlib_rs::deflate::end(deflate_strm);

    if ret == ReturnCode::StreamEnd {
        let len = compressed.len() - strm.avail_out as usize;
        compressed.truncate(len);
        Ok(compressed)
    } else {
        Err(DmgError::CompressionFailed(alloc::format!(
            "deflate failed: {:?}",
            ret
        )))
    }
}
