// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::alloc::string::ToString;
use binrw::{BinRead, BinReaderExt, BinWrite, BinWriterExt, binrw};

use crate::{DmgError, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq, BinRead, BinWrite)]
#[br(big)]
#[bw(big)]
pub struct UdifChecksum {
    pub r#type: u32,
    pub size: u32,
    pub data: [u8; 128],
}

impl Default for UdifChecksum {
    fn default() -> Self {
        Self {
            r#type: 2,
            size: 32,
            data: [0; 128],
        }
    }
}

impl UdifChecksum {
    pub fn new(crc32: u32) -> Self {
        let mut data = [0; 128];
        data[..4].copy_from_slice(&crc32.to_be_bytes());
        Self {
            data,
            ..Default::default()
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self::new(crc32fast::hash(bytes))
    }
}

impl From<UdifChecksum> for u32 {
    fn from(checksum: UdifChecksum) -> Self {
        let mut data = [0; 4];
        data.copy_from_slice(&checksum.data[..4]);
        u32::from_be_bytes(data)
    }
}

const KOLY_SIZE: i64 = 512;

/// DMG trailer describing file content.
///
/// This is the main structure defining a DMG.
#[binrw]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[br(big, magic = b"koly")]
#[bw(big, magic = b"koly")]
pub struct KolyTrailer {
    pub version: u32,
    #[br(temp, assert(header_size == 512))]
    #[bw(calc = 512)]
    header_size: u32,
    pub flags: u32,
    pub running_data_fork_offset: u64,
    pub data_fork_offset: u64,
    pub data_fork_length: u64,
    pub resource_fork_offset: u64,
    pub resource_fork_length: u64,
    pub segment_number: u32,
    pub segment_count: u32,
    pub segment_id: [u8; 16],
    pub data_fork_digest: UdifChecksum,
    pub plist_offset: u64,
    pub plist_length: u64,
    pub reserved1: [u8; 64],
    pub code_signature_offset: u64,
    pub code_signature_size: u64,
    pub reserved2: [u8; 40],
    pub main_digest: UdifChecksum,
    pub image_variant: u32,
    pub sector_count: u64,
    pub reserved3: [u8; 12],
}

impl Default for KolyTrailer {
    fn default() -> Self {
        Self {
            version: 4,
            flags: 1,
            running_data_fork_offset: 0,
            data_fork_offset: 0,
            data_fork_length: 0,
            resource_fork_offset: 0,
            resource_fork_length: 0,
            segment_number: 1,
            segment_count: 1,
            segment_id: [0; 16],
            data_fork_digest: UdifChecksum::default(),
            plist_offset: 0,
            plist_length: 0,
            reserved1: [0; 64],
            code_signature_offset: 0,
            code_signature_size: 0,
            reserved2: [0; 40],
            main_digest: UdifChecksum::default(),
            image_variant: 1,
            sector_count: 0,
            reserved3: [0; 12],
        }
    }
}

impl KolyTrailer {
    #[cfg(feature = "std")]
    pub fn new(
        data_fork_length: u64,
        sectors: u64,
        plist_offset: u64,
        plist_length: u64,
        data_digest: u32,
        main_digest: u32,
    ) -> Self {
        let mut segment_id = [0; 16];
        let _ = getrandom::fill(&mut segment_id);
        Self {
            data_fork_length,
            sector_count: sectors,
            plist_offset,
            plist_length,
            data_fork_digest: UdifChecksum::new(data_digest),
            main_digest: UdifChecksum::new(main_digest),
            segment_id,
            ..Default::default()
        }
    }

    /// Construct an instance by reading from a seekable reader.
    ///
    /// The trailer is the final 512 bytes of the seekable stream.
    pub fn read_from<R: binrw::io::Read + binrw::io::Seek>(r: &mut R) -> Result<Self> {
        r.seek(binrw::io::SeekFrom::End(-KOLY_SIZE))
            .map_err(|e| DmgError::Io(e.to_string()))?;
        r.read_be().map_err(|e| {
            if let binrw::Error::AssertFail { .. } = &e {
                DmgError::InvalidHeaderSize(0) // Simplified
            } else if let binrw::Error::BadMagic { .. } = &e {
                DmgError::InvalidSignature {
                    expected: *b"koly",
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
