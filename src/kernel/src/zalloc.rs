#![allow(dead_code)]

use alloc::vec;
use alloc::vec::Vec;

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
    // zstd-safe is a safe wrapper around zstd-sys.
    // It does not have stream::encode_all. We must use simple API.

    // Estimate bounds
    let bound = zstd_safe::compress_bound(data.len());
    let mut buffer = vec![0u8; bound];

    // Level 1 for speed
    match zstd_safe::compress(&mut buffer[..], data, 1) {
        Ok(len) => {
            buffer.truncate(len);
            Ok(buffer)
        }
        Err(_) => Err("Compression failed"),
    }
}

/// Decompress data using Zstd.
/// We don't know the exact uncompressed size usually, unless stored.
/// But for pages, we usually know (e.g. 4096 or 16384).
/// For generic use, we might need a loop or header.
/// However, zstd frames include content size if not disabled.
pub fn zdecompress(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    // Try to find content size
    let content_size = zstd_safe::get_frame_content_size(data).unwrap_or(None);

    let mut capacity = if let Some(size) = content_size {
        size as usize
    } else {
        // Fallback: Guess 4x compression or just 4096 for pages
        4096 * 4
    };

    // Safety check for OOM vectors
    if capacity > 16 * 1024 * 1024 {
        capacity = 16 * 1024 * 1024;
    }

    let mut buffer = vec![0u8; capacity];

    match zstd_safe::decompress(&mut buffer[..], data) {
        Ok(len) => {
            buffer.truncate(len);
            Ok(buffer)
        }
        Err(_) => Err("Decompression failed"),
    }
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
            // We know the expected output size is self.block_size
            match zstd_safe::decompress(out, compressed) {
                Ok(len) => {
                    if len != self.block_size {
                        return Err("Decompressed size mismatch");
                    }
                    Ok(())
                }
                Err(_) => Err("Decompression failed"),
            }
        } else {
            // Block not present, return zeros?
            out.fill(0);
            Ok(())
        }
    }
}
