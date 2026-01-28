use apple_dmg::DmgReader;
use clap::Parser;
use hfsplus::HFSVolume;
use std::fs::{self, File};
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DiskError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("DMG error: {0}")]
    Dmg(String),
    #[error("HFS+ error: {0}")]
    Hfs(String),
}

#[derive(Parser, Debug)]
#[command()]
struct Args {
    /// Path to iOS rootfs DMG
    #[arg(long)]
    ios_dmg: PathBuf,

    /// Output disk image path
    #[arg(long, default_value = "disk.img")]
    output: PathBuf,

    /// Disk size in MB
    #[arg(long, default_value_t = 512)]
    size_mb: u64,

    /// Rootfs offset in MB
    #[arg(long, default_value_t = 400)]
    rootfs_offset_mb: u64,
}

fn main() -> Result<(), DiskError> {
    let args = Args::parse();

    println!("Reading DMG {}...", args.ios_dmg.display());
    let mut dmg = DmgReader::open(&args.ios_dmg).map_err(|e| DiskError::Dmg(e.to_string()))?;

    // Find the HFS+ partition. It's usually the largest one or the one with HFS+ signature.
    let mut hfs_data = None;
    for i in 0..dmg.plist().partitions().len() {
        let data = dmg
            .partition_data(i)
            .map_err(|e| DiskError::Dmg(e.to_string()))?;
        if data.len() > 1024 && (&data[1024..1026] == b"H+" || &data[1024..1026] == b"HX") {
            hfs_data = Some(data);
            break;
        }
    }

    let hfs_data =
        hfs_data.ok_or_else(|| DiskError::Hfs("No HFS+ partition found in DMG".to_string()))?;
    let volume =
        HFSVolume::load(Cursor::new(hfs_data)).map_err(|e| DiskError::Hfs(format!("{:?}", e)))?;

    println!("Creating disk image {}...", args.output.display());
    let mut disk_file = File::create(&args.output)?;
    disk_file.set_len(args.size_mb * 1024 * 1024)?;

    println!("Copying shared cache...");
    let shared_cache_path = "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_armv7";
    if let Ok(record) = volume.borrow().get_path_record(shared_cache_path) {
        if let hfsplus::CatalogBody::File(file) = record.body {
            let mut fork = hfsplus::Fork::load(
                volume.borrow().file.clone(),
                file.fileID,
                0,
                volume.clone(),
                &file.dataFork,
            )
            .map_err(|e| DiskError::Hfs(e.to_string()))?;
            let data = fork.read_all().map_err(|e| DiskError::Hfs(e.to_string()))?;
            disk_file.write_all(&data)?;
            println!("Shared cache written");
        }
    } else {
        println!("WARNING: Shared cache not found at {}", shared_cache_path);
    }

    println!("Creating rootfs.tar...");
    let mut tar_builder = tar::Builder::new(Vec::new());

    let binaries = ["/bin/ls", "/bin/cat", "/bin/echo", "/usr/lib/dyld"];

    for path in binaries {
        if let Ok(record) = volume.borrow().get_path_record(path) {
            if let hfsplus::CatalogBody::File(file) = record.body {
                let mut fork = hfsplus::Fork::load(
                    volume.borrow().file.clone(),
                    file.fileID,
                    0,
                    volume.clone(),
                    &file.dataFork,
                )
                .map_err(|e| DiskError::Hfs(e.to_string()))?;
                let data = fork.read_all().map_err(|e| DiskError::Hfs(e.to_string()))?;

                let mut header = tar::Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_mode(0o755);
                tar_builder.append_data(
                    &mut header,
                    path.trim_start_matches('/'),
                    Cursor::new(data),
                )?;
            }
        }
    }

    // Copying Frameworks is complex with this HFS+ lib as it doesn't support recursive walking easily.
    // For now, let's just skip it or implement a simple walk if possible.
    // The current lib has get_children_id.

    println!("Writing rootfs at {}MB offset", args.rootfs_offset_mb);
    let tar_data = tar_builder.into_inner()?;
    disk_file.seek(SeekFrom::Start(args.rootfs_offset_mb * 1024 * 1024))?;
    disk_file.write_all(&tar_data)?;

    println!("Disk image created: {}", args.output.display());
    println!("Done!");
    Ok(())
}
