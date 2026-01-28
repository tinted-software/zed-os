use apple_dmg::{ChunkType, DmgReader};
use clap::Parser;
use flate2::bufread::ZlibDecoder;
use hfsplus::HFSVolume;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use ipsw_downloader::fetch_firmware_url;
use memmap2::MmapMut;
use rayon::prelude::*;
use std::cmp::min;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::time::Instant;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use vfdecrypt::decrypt;

#[derive(Error, Debug)]
pub enum SetupError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("DMG error: {0}")]
    Dmg(String),
    #[error("HFS+ error: {0}")]
    Hfs(String),
    #[error("Download error: {0}")]
    Download(String),
    #[error("VFDecrypt error: {0}")]
    Decrypt(String),
    #[error("Zip error: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("Error: {0}")]
    Other(String),
}

#[derive(Parser, Debug)]
#[command(name = "gravity-setup", ignore_errors = true)]
struct Args {
    /// Device Identifier (e.g., iPad1,1)
    #[arg(long, default_value = "iPad1,1")]
    device: String,

    /// Build ID (e.g., 9B206)
    #[arg(long, default_value = "9B206")]
    build: String,

    /// Rootfs decryption key
    #[arg(
        long,
        default_value = "f7bb9fd8aa3102484ab9c847dacfd3d73f1f430acb49ed7a422226f2410acee17664c91b"
    )]
    key: String,

    /// Output disk image path
    #[arg(long, default_value = "disk.img")]
    output: PathBuf,

    /// Work directory for intermediate files
    #[arg(long, default_value = "work")]
    work_dir: PathBuf,

    /// Disk size in MB
    #[arg(long, default_value_t = 1536)]
    size_mb: u64,

    /// Rootfs offset in MB
    #[arg(long, default_value_t = 400)]
    rootfs_offset_mb: u64,
}

#[derive(Clone, Copy)]
struct SafePtr(*mut u8);
unsafe impl Send for SafePtr {}
unsafe impl Sync for SafePtr {}

struct OffsetFile {
    file: File,
    offset: u64,
}

impl Read for OffsetFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

impl Seek for OffsetFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let actual_pos = match pos {
            SeekFrom::Start(s) => SeekFrom::Start(self.offset + s),
            SeekFrom::Current(c) => SeekFrom::Current(c),
            SeekFrom::End(e) => SeekFrom::End(e),
        };
        let new_pos = self.file.seek(actual_pos)?;
        Ok(new_pos.saturating_sub(self.offset))
    }
}

impl hfsplus::Read for OffsetFile {
    fn read(&mut self, buf: &mut [u8]) -> hfsplus::Result<usize> {
        Read::read(self, buf).map_err(|e| hfsplus::Error::InvalidData(e.to_string()))
    }
}

impl hfsplus::Seek for OffsetFile {
    fn seek(&mut self, pos: hfsplus::SeekFrom) -> hfsplus::Result<u64> {
        let std_pos = match pos {
            hfsplus::SeekFrom::Start(s) => SeekFrom::Start(s),
            hfsplus::SeekFrom::Current(c) => SeekFrom::Current(c),
            hfsplus::SeekFrom::End(e) => SeekFrom::End(e),
        };
        Seek::seek(self, std_pos).map_err(|e| hfsplus::Error::InvalidData(e.to_string()))
    }
}

#[tokio::main]
async fn main() -> Result<(), SetupError> {
    let args = Args::parse();
    let mp = MultiProgress::new();
    let total_start = Instant::now();

    std::fs::create_dir_all(&args.work_dir)?;

    // 1. Fetch IPSW URL
    let start = Instant::now();
    println!(
        "Step 1: Fetching firmware URL for {} build {}...",
        args.device, args.build
    );
    let ipsw_url = fetch_firmware_url(&args.device, &args.build)
        .await
        .map_err(|e| SetupError::Download(e.to_string()))?
        .ok_or_else(|| SetupError::Other("Firmware not found".to_string()))?;
    println!("  Done in {:?}", start.elapsed());

    // 2. Download IPSW
    let ipsw_path = args.work_dir.join("firmware.ipsw");
    if !ipsw_path.exists() {
        println!("Step 2: Downloading IPSW...");
        download_ipsw(&ipsw_url, &ipsw_path, &mp).await?;
    } else {
        println!("Step 2: IPSW already downloaded, skipping.");
    }

    // 3. Extract Rootfs DMG (optimized)
    let start = Instant::now();
    let rootfs_dmg_encrypted = args.work_dir.join("rootfs_encrypted.dmg");
    if !rootfs_dmg_encrypted.exists() {
        println!("Step 3: Extracting rootfs DMG from IPSW...");
        let file = File::open(&ipsw_path).map_err(|e| {
            SetupError::Other(format!(
                "Failed to open IPSW at {}: {}",
                ipsw_path.display(),
                e
            ))
        })?;
        let mut archive = zip::ZipArchive::new(file)
            .map_err(|e| SetupError::Other(format!("Failed to open IPSW as ZIP: {}", e)))?;

        let mut largest_name = String::new();
        let mut largest_size = 0;
        let mut largest_index = 0;

        for i in 0..archive.len() {
            let file = archive.by_index(i)?;
            if file.name().ends_with(".dmg") && file.size() > largest_size {
                largest_size = file.size();
                largest_name = file.name().to_string();
                largest_index = i;
            }
        }

        if largest_size == 0 {
            return Err(SetupError::Other("No DMG found in IPSW".to_string()));
        }

        println!(
            "  Extracting {} ({} MB)...",
            largest_name,
            largest_size / 1024 / 1024
        );
        let mut rootfs_zip = archive.by_index(largest_index)?;
        let mut output = File::create(&rootfs_dmg_encrypted)?;

        let pb = mp.add(ProgressBar::new(largest_size));
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
            .unwrap()
            .progress_chars("#>-"));

        let mut buffer = vec![0u8; 1024 * 1024];
        loop {
            let n = rootfs_zip.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            output.write_all(&buffer[..n])?;
            pb.inc(n as u64);
        }
        pb.finish_with_message("Extraction complete");
        println!("  Done in {:?}", start.elapsed());
    } else {
        println!("Step 3: Rootfs DMG already extracted, skipping.");
    }

    // 4. Decrypt Rootfs DMG
    let start = Instant::now();
    let rootfs_dmg = args.work_dir.join("rootfs.dmg");
    if !rootfs_dmg.exists() {
        println!("Step 4: Decrypting rootfs DMG...");
        let mut input = File::open(&rootfs_dmg_encrypted)?;
        let mut output = File::create(&rootfs_dmg)?;
        decrypt(&mut input, &mut output, &args.key)
            .map_err(|e| SetupError::Decrypt(e.to_string()))?;
        println!("  Done in {:?}", start.elapsed());
    } else {
        println!("Step 4: Rootfs DMG already decrypted, skipping.");
    }

    println!(
        "Step 5: Creating final disk image {}...",
        args.output.display()
    );
    create_disk_image(&rootfs_dmg, &args, &mp)?;
    println!("  Done in {:?}", start.elapsed());

    println!("Total time: {:?}", total_start.elapsed());
    println!("Success! Disk image created at {}", args.output.display());
    Ok(())
}

async fn download_ipsw(url: &str, output: &Path, mp: &MultiProgress) -> Result<(), SetupError> {
    let client = reqwest::Client::new();
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| SetupError::Download(e.to_string()))?;
    let total_size = response.content_length().unwrap_or(0);

    let pb = mp.add(ProgressBar::new(total_size));
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
        .unwrap()
        .progress_chars("#>-"));

    let mut file = tokio::fs::File::create(output).await?;
    let mut downloaded: u64 = 0;
    let mut stream = response.bytes_stream();

    use futures_util::StreamExt;
    while let Some(item) = stream.next().await {
        let chunk = item.map_err(|e| SetupError::Download(e.to_string()))?;
        file.write_all(&chunk).await?;
        downloaded = min(downloaded + (chunk.len() as u64), total_size);
        pb.set_position(downloaded);
    }

    pb.finish_with_message("Download complete");
    Ok(())
}

fn create_disk_image(rootfs_dmg: &Path, args: &Args, mp: &MultiProgress) -> Result<(), SetupError> {
    let mut dmg = DmgReader::open(rootfs_dmg).map_err(|e| SetupError::Dmg(e.to_string()))?;

    // Find HFS+ partition
    let mut hfs_table = None;
    for i in 0..dmg.plist().partitions().len() {
        let table = dmg
            .partition_table(i)
            .map_err(|e| SetupError::Dmg(e.to_string()))?;
        if let Some(chunk) = table
            .chunks
            .iter()
            .find(|c| c.ty() != Some(ChunkType::Comment))
        {
            let mut reader = dmg
                .sector(chunk)
                .map_err(|e| SetupError::Dmg(e.to_string()))?;
            let mut header = vec![0u8; 2048];
            let _ = reader.read_exact(&mut header);
            if header.len() >= 1026
                && (&header[1024..1026] == b"H+" || &header[1024..1026] == b"HX")
            {
                hfs_table = Some(table);
                break;
            }
        }
    }

    let hfs_table = hfs_table.unwrap();

    let output_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&args.output)?;
    output_file.set_len(args.size_mb * 1024 * 1024)?;

    let mut mmap = unsafe { MmapMut::map_mut(&output_file)? };
    let mmap_ptr = SafePtr(mmap.as_mut_ptr());

    println!("  Parallel rootfs decompression...");
    let rootfs_offset = (args.rootfs_offset_mb * 1024 * 1024) as usize;
    let dmg_file = File::open(rootfs_dmg)?;

    let pb = mp.add(ProgressBar::new(hfs_table.chunks.len() as u64));
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} chunks ({eta})")
        .unwrap()
        .progress_chars("#>-"));

    hfs_table
        .chunks
        .par_iter()
        .try_for_each(|chunk| -> Result<(), SetupError> {
            let p = mmap_ptr;
            let ty = chunk
                .ty()
                .ok_or_else(|| SetupError::Dmg("Unknown chunk type".to_string()))?;
            let output_pos = rootfs_offset + (chunk.sector_number * 512) as usize;

            match ty {
                ChunkType::Zero | ChunkType::Ignore => {}
                ChunkType::Raw => {
                    let mut data = vec![0u8; chunk.compressed_length as usize];
                    dmg_file.read_exact_at(&mut data, chunk.compressed_offset)?;
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            data.as_ptr(),
                            p.0.add(output_pos),
                            data.len(),
                        );
                    }
                }
                ChunkType::Zlib => {
                    let mut compressed = vec![0u8; chunk.compressed_length as usize];
                    dmg_file.read_exact_at(&mut compressed, chunk.compressed_offset)?;
                    let mut decoder = ZlibDecoder::new(&compressed[..]);
                    let mut decompressed = Vec::with_capacity((chunk.sector_count * 512) as usize);
                    decoder.read_to_end(&mut decompressed)?;
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            decompressed.as_ptr(),
                            p.0.add(output_pos),
                            decompressed.len(),
                        );
                    }
                }
                _ => {}
            }
            // Increment periodically to avoid too much lock contention on MultiProgress
            if chunk.sector_number % 100 == 0 {
                pb.inc(100);
            }
            Ok(())
        })?;
    pb.set_position(hfs_table.chunks.len() as u64);
    pb.finish_with_message("Rootfs decompressed");
    mmap.flush()?;
    drop(mmap);

    Ok(())
}
