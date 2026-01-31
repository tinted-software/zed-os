#![allow(dead_code)]

use alloc::vec::Vec;
use ruzstd::decoding::StreamingDecoder;
use ruzstd::encoding::{CompressionLevel, compress_to_vec};
use ruzstd::io::Read;

/// A simple compressed memory allocator (zram-like).
/// It takes input data (e.g. a page), compresses it using Zstd,
/// and stores it. It returns a handle to the stored data.
pub struct ZAllocator {
    // In a real zsmalloc, we would have size classes and dedicated pages.
    // Here we wrap the system allocator but provide compression.
    // We use a simple counter for handles.
    // For now, let's simpler: just provide compress/decompress helpers
    // and maybe a simple store if needed.
}

// Global buffer for compression to avoid constant reallocation?
// Thread safety issues if we have multiple cores.
// Let's stick to allocating for now.

/// Compress data using Zstd.
/// Returns a Vec<u8> containing the compressed data.
pub fn zcompress(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    // ruzstd::encoding::compress_to_vec returns Vec<u8>
    // We use CompressionLevel::Default (equivalent to level 3 usually, but ruzstd is different)
    Ok(compress_to_vec(data, CompressionLevel::Default))
}

/// Decompress data using Zstd.
/// We don't know the exact uncompressed size usually, unless stored.
/// But for pages, we usually know (e.g. 4096 or 16384).
/// For generic use, we might need a loop or header.
/// However, zstd frames include content size if not disabled.
pub fn zdecompress(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut decoder = StreamingDecoder::new(data).map_err(|_| "Decompression init failed")?;
    let mut buffer = Vec::new();
    decoder
        .read_to_end(&mut buffer)
        .map_err(|_| "Decompression failed")?;
    Ok(buffer)
}
/// A "ZRAM" block device simulator.
/// Stores pages in a compressed format in memory.
pub struct ZRamDevice {
    blocks: Vec<Option<Vec<u8>>>,
    block_size: usize,
}

impl ZRamDevice {
    pub fn new(num_blocks: usize, block_size: usize) -> Self {
        let mut blocks = Vec::with_capacity(num_blocks);
        for _ in 0..num_blocks {
            blocks.push(None);
        }
        Self { blocks, block_size }
    }

    pub fn write_block(&mut self, index: usize, data: &[u8]) -> Result<(), &'static str> {
        if index >= self.blocks.len() || data.len() != self.block_size {
            return Err("Invalid argument");
        }

        // Compress
        let compressed = zcompress(data)?;
        // Store
        self.blocks[index] = Some(compressed);
        Ok(())
    }

    pub fn read_block(&self, index: usize, out: &mut [u8]) -> Result<(), &'static str> {
        if index >= self.blocks.len() || out.len() != self.block_size {
            return Err("Invalid argument");
        }

        if let Some(ref compressed) = self.blocks[index] {
            let mut decoder =
                StreamingDecoder::new(&compressed[..]).map_err(|_| "Decompression init failed")?;
            decoder
                .read_exact(out)
                .map_err(|_| "Decompression failed")?;
            Ok(())
        } else {
            // Block not present, return zeros?
            out.fill(0);
            Ok(())
        }
    }
}
