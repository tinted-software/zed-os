// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate alloc;
use crate::alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use binrw::{BinRead, BinReaderExt, BinWrite, BinWriterExt, binrw};

use crate::koly::UdifChecksum;

use crate::{DmgError, Result};

#[binrw]
#[derive(Clone, Debug, Eq, PartialEq)]
#[br(big, magic = b"mish")]
#[bw(big, magic = b"mish")]
pub struct BlkxTable {
    /// currently 1
    pub version: u32,
    /// starting sector
    pub sector_number: u64,
    /// number of sectors
    pub sector_count: u64,
    /// seems always to be 0
    pub data_offset: u64,
    /// seems to be a magic constant for zlib describing the buffer size
    /// required for decompressing a chunk.
    pub buffers_needed: u32,
    /// not sure what this is, setting it to the partition index
    pub block_descriptors: u32,
    pub reserved: [u8; 24],
    pub checksum: UdifChecksum,
    /// chunk table
    #[br(temp)]
    #[bw(calc = chunks.len() as u32)]
    num_chunks: u32,
    #[br(count = num_chunks)]
    pub chunks: Vec<BlkxChunk>,
}

impl Default for BlkxTable {
    fn default() -> Self {
        Self {
            version: 1,
            sector_number: 0,
            sector_count: 0,
            data_offset: 0,
            //  number was taken from hdiutil
            buffers_needed: 2056,
            block_descriptors: 0,
            reserved: [0; 24],
            checksum: UdifChecksum::default(),
            chunks: vec![],
        }
    }
}

impl BlkxTable {
    pub fn new(index: u32, sector: u64, checksum: u32) -> Self {
        Self {
            block_descriptors: index,
            sector_number: sector,
            checksum: UdifChecksum::new(checksum),
            ..Default::default()
        }
    }

    pub fn add_chunk(&mut self, mut chunk: BlkxChunk) {
        chunk.sector_number = self.sector_count;
        self.sector_count += chunk.sector_count;
        self.chunks.push(chunk);
    }

    pub fn read_from<R: binrw::io::Read + binrw::io::Seek>(r: &mut R) -> Result<Self> {
        r.read_be().map_err(|e| {
            if let binrw::Error::BadMagic { .. } = &e {
                DmgError::InvalidSignature {
                    expected: *b"mish",
                    found: [0, 0, 0, 0], // Simplified
                }
            } else {
                DmgError::Io(e.to_string())
            }
        })
    }

    pub fn write_to<W: binrw::io::Write + binrw::io::Seek>(&self, w: &mut W) -> Result<()> {
        w.write_be(self).map_err(|e| DmgError::Io(e.to_string()))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, BinRead, BinWrite)]
#[br(big)]
#[bw(big)]
pub struct BlkxChunk {
    /// compression type used for this chunk
    pub r#type: u32,
    pub comment: u32,
    pub sector_number: u64,
    pub sector_count: u64,
    pub compressed_offset: u64,
    pub compressed_length: u64,
}

impl Default for BlkxChunk {
    fn default() -> Self {
        Self {
            r#type: ChunkType::Raw as _,
            comment: 0,
            sector_number: 0,
            sector_count: 0,
            compressed_offset: 0,
            compressed_length: 0,
        }
    }
}

impl BlkxChunk {
    pub fn new(
        ty: ChunkType,
        sector_number: u64,
        sector_count: u64,
        compressed_offset: u64,
        compressed_length: u64,
    ) -> Self {
        Self {
            r#type: ty as _,
            sector_number,
            sector_count,
            compressed_offset,
            compressed_length,
            ..Default::default()
        }
    }

    pub fn term(sector_number: u64, compressed_offset: u64) -> Self {
        Self::new(ChunkType::Term, sector_number, 0, compressed_offset, 0)
    }

    pub fn ty(self) -> Option<ChunkType> {
        ChunkType::from_u32(self.r#type)
    }
}

/// Possible compression types of the BlkxChunk.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChunkType {
    Zero = 0x0000_0000,
    Raw = 0x0000_0001,
    Ignore = 0x0000_0002,
    Comment = 0x7fff_fffe,
    Adc = 0x8000_0004,
    Zlib = 0x8000_0005,
    Bzlib = 0x8000_0006,
    Lzfse = 0x8000_0007,
    Term = 0xffff_ffff,
}

impl ChunkType {
    pub fn from_u32(ty: u32) -> Option<Self> {
        Some(match ty {
            x if x == ChunkType::Zero as u32 => ChunkType::Zero,
            x if x == ChunkType::Raw as u32 => ChunkType::Raw,
            x if x == ChunkType::Ignore as u32 => ChunkType::Ignore,
            x if x == ChunkType::Comment as u32 => ChunkType::Comment,
            x if x == ChunkType::Adc as u32 => ChunkType::Adc,
            x if x == ChunkType::Zlib as u32 => ChunkType::Zlib,
            x if x == ChunkType::Bzlib as u32 => ChunkType::Bzlib,
            x if x == ChunkType::Lzfse as u32 => ChunkType::Lzfse,
            x if x == ChunkType::Term as u32 => ChunkType::Term,
            _ => return None,
        })
    }
}
