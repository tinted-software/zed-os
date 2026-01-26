use clap::Parser;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DiskError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to iOS root directory
    #[arg(long, default_value = "Telluride9A405.K48OS")]
    ios_root: PathBuf,

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

    println!("Creating disk image {}...", args.output.display());
    let mut disk_file = File::create(&args.output)?;
    disk_file.set_len(args.size_mb * 1024 * 1024)?;

    println!("Copying shared cache...");
    let shared_cache_path = args
        .ios_root
        .join("System/Library/Caches/com.apple.dyld/dyld_shared_cache_armv7");
    if shared_cache_path.exists() {
        let mut cache_file = File::open(&shared_cache_path)?;
        let mut buffer = Vec::new();
        cache_file.read_to_end(&mut buffer)?;
        disk_file.write_all(&buffer)?;
        println!("Shared cache written");
    } else {
        println!(
            "WARNING: Shared cache not found at {}",
            shared_cache_path.display()
        );
        println!("Creating empty placeholder...");
    }

    println!("Creating rootfs.tar...");
    let rootfs_dir = Path::new("rootfs_tmp");
    if rootfs_dir.exists() {
        fs::remove_dir_all(rootfs_dir)?;
    }
    fs::create_dir_all(rootfs_dir.join("bin"))?;
    fs::create_dir_all(rootfs_dir.join("usr/lib"))?;
    fs::create_dir_all(rootfs_dir.join("System/Library"))?;

    if args.ios_root.exists() {
        let binaries = [
            ("bin/ls", "bin/ls"),
            ("bin/cat", "bin/cat"),
            ("bin/echo", "bin/echo"),
            ("usr/lib/dyld", "usr/lib/dyld"),
        ];

        for (src, dst) in binaries {
            let src_path = args.ios_root.join(src);
            if src_path.exists() {
                fs::copy(&src_path, rootfs_dir.join(dst))?;
            }
        }

        println!("Copying Frameworks...");
        let frameworks_src = args.ios_root.join("System/Library/Frameworks");
        if frameworks_src.exists() {
            copy_dir_all(
                &frameworks_src,
                rootfs_dir.join("System/Library/Frameworks"),
            )?;
        }
    }

    let mut tar_builder = tar::Builder::new(Vec::new());
    tar_builder.append_dir_all(".", rootfs_dir)?;
    let tar_data = tar_builder.into_inner()?;

    println!("Writing rootfs at {}MB offset", args.rootfs_offset_mb);
    disk_file.seek(SeekFrom::Start(args.rootfs_offset_mb * 1024 * 1024))?;
    disk_file.write_all(&tar_data)?;

    println!("Disk image created: {}", args.output.display());

    // Cleanup
    fs::remove_dir_all(rootfs_dir)?;

    println!("Done!");
    Ok(())
}

fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> io::Result<()> {
    fs::create_dir_all(&dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(entry.path(), dst.as_ref().join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), dst.as_ref().join(entry.file_name()))?;
        }
    }
    Ok(())
}
