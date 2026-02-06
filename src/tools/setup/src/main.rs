use clap::Parser;
use derive_more::derive::Display;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use ipsw_downloader::fetch_firmware_url;
use rootcause::{Report, report};
use std::cmp::min;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;
use tokio::io::AsyncWriteExt;
use vfdecrypt::decrypt;

#[derive(Debug, Display)]
pub enum SetupError {
    #[display("IO error: {_0}")]
    Io(io::Error),
    #[display("DMG error: {_0}")]
    Dmg(String),
    #[display("HFS+ error: {_0}")]
    Hfs(String),
    #[display("Download error: {_0}")]
    Download(String),
    #[display("VFDecrypt error: {_0}")]
    Decrypt(String),
    #[display("Zip error: {_0}")]
    Zip(zip::result::ZipError),
    #[display("Error: {_0}")]
    Other(String),
}

impl std::error::Error for SetupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SetupError::Io(e) => Some(e),
            SetupError::Zip(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for SetupError {
    fn from(err: io::Error) -> Self {
        SetupError::Io(err)
    }
}

impl From<zip::result::ZipError> for SetupError {
    fn from(err: zip::result::ZipError) -> Self {
        SetupError::Zip(err)
    }
}

#[derive(Parser, Debug)]
#[command(name = "gravity-setup")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Setup the OS (fetch IPSW, decryptl)
    Setup(Args),
    // Build the workspace for the CI
    Ci,
    /// Run the kernel in QEMU
    Qemu(QemuArgs),
}

#[derive(Parser, Debug)]
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
}

#[derive(Parser, Debug)]
struct QemuArgs {
    /// Path to the kernel binary
    #[arg(
        long,
        default_value = "target/aarch64-unknown-none-softfloat/debug/kernel"
    )]
    kernel: PathBuf,

    /// Memory size
    #[arg(long, default_value = "1G")]
    memory: String,

    /// Number of CPUs
    #[arg(long, default_value_t = 1)]
    cpus: u32,

    /// Whether to run in nographic mode
    #[arg(long, default_value_t = true)]
    nographic: bool,
}

#[tokio::main]
async fn main() -> Result<(), Report<SetupError>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Setup(args) => setup(args).await,
        Commands::Qemu(args) => qemu(args),
        Commands::Ci => ci(),
    }
}

fn ci() -> Result<(), Report<SetupError>> {
    let total_start = Instant::now();

    if !std::process::Command::new("cargo")
        .arg("build")
        .arg("-Zbuild-std=core,alloc,compiler_builtins")
        .arg("-Zbuild-std-features=compiler-builtins-mem")
        .arg("--target")
        .arg("aarch64-unknown-none-softfloat")
        .arg("-p")
        .arg("kernel")
        .arg("-p")
        .arg("dyld")
        .env(
            "RUSTFLAGS",
            "-Zsanitizer=kcfi -Clink-arg=--ld-path=ld.lld -Clinker=clang -Clink-arg=--target=aarch64-unknown-none-elf -Clink-arg=-nostdlib",
        )
        .status()
        .map_err(|e| report!(SetupError::Other(e.to_string())))?
        .success()
    {
        return Err(report!(SetupError::Other(
            "Failed to build kernel or dyld".to_string(),
        )));
    }

    println!("✨ Done in {:?}", total_start.elapsed());

    Ok(())
}

async fn setup(args: Args) -> Result<(), Report<SetupError>> {
    let mp = MultiProgress::new();
    let total_start = Instant::now();

    std::fs::create_dir_all(&args.work_dir).map_err(|e| {
        report!(SetupError::Io(e)).context(SetupError::Other(format!(
            "Failed to create work directory: {}",
            args.work_dir.display()
        )))
    })?;

    println!(
        "Fetching firmware URL for {} build {}...",
        args.device, args.build
    );
    let ipsw_url = fetch_firmware_url(&args.device, &args.build)
        .await
        .map_err(|e| report!(SetupError::Download(e.to_string())))?
        .ok_or_else(|| {
            report!(SetupError::Other(format!(
                "Firmware not found for device {} build {}",
                args.device, args.build
            )))
        })?;

    // 2. Download IPSW
    let ipsw_path = args.work_dir.join("firmware.ipsw");
    if !ipsw_path.exists() {
        println!("Downloading IPSW...");
        download_ipsw(&ipsw_url, &ipsw_path, &mp).await?;
    } else {
        println!("IPSW already downloaded, skipping.");
    }

    // 3. Extract Rootfs DMG (optimized)
    let rootfs_dmg_encrypted = args.work_dir.join("rootfs_encrypted.dmg");
    if !rootfs_dmg_encrypted.exists() {
        println!("Extracting rootfs DMG from IPSW...");
        let file = File::open(&ipsw_path).map_err(|e| {
            report!(SetupError::Io(e)).context(SetupError::Other(format!(
                "Failed to open IPSW at {}",
                ipsw_path.display()
            )))
        })?;
        let mut archive = zip::ZipArchive::new(file).map_err(|e| {
            report!(SetupError::Zip(e))
                .context(SetupError::Other("Failed to open IPSW as ZIP".to_string()))
        })?;

        let mut largest_name = String::new();
        let mut largest_size = 0;
        let mut largest_index = 0;

        for i in 0..archive.len() {
            let file = archive.by_index(i).map_err(|e| {
                report!(SetupError::Zip(e))
                    .context(SetupError::Other(format!("Failed to read ZIP entry {}", i)))
            })?;
            if file.name().ends_with(".dmg") && file.size() > largest_size {
                largest_size = file.size();
                largest_name = file.name().to_string();
                largest_index = i;
            }
        }

        if largest_size == 0 {
            return Err(report!(SetupError::Other(format!(
                "No DMG found in IPSW at {}",
                ipsw_path.display()
            ))));
        }

        println!(
            "Extracting {} ({} MB)...",
            largest_name,
            largest_size / 1024 / 1024
        );
        let mut rootfs_zip = archive.by_index(largest_index).map_err(|e| {
            report!(SetupError::Zip(e)).context(SetupError::Other(format!(
                "Failed to access DMG entry: {}",
                largest_name
            )))
        })?;
        let mut output = File::create(&rootfs_dmg_encrypted).map_err(|e| {
            report!(SetupError::Io(e)).context(SetupError::Other(format!(
                "Failed to create output file: {}",
                rootfs_dmg_encrypted.display()
            )))
        })?;

        let pb = mp.add(ProgressBar::new(largest_size));
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
            .unwrap()
            .progress_chars("#>-"));

        let mut buffer = vec![0u8; 1024 * 1024];
        loop {
            let n = rootfs_zip.read(&mut buffer).map_err(|e| {
                report!(SetupError::Io(e)).context(SetupError::Other(format!(
                    "Failed to read from {}",
                    largest_name
                )))
            })?;
            if n == 0 {
                break;
            }
            output.write_all(&buffer[..n]).map_err(|e| {
                report!(SetupError::Io(e)).context(SetupError::Other(format!(
                    "Failed to write to {}",
                    rootfs_dmg_encrypted.display()
                )))
            })?;
            pb.inc(n as u64);
        }
        pb.finish_with_message("Extraction complete");
    } else {
        println!("Rootfs DMG already extracted, skipping.");
    }

    // 4. Decrypt Rootfs DMG
    let rootfs_dmg = args.work_dir.join("rootfs.dmg");
    if !rootfs_dmg.exists() {
        println!("Decrypting rootfs DMG...");
        let mut input = File::open(&rootfs_dmg_encrypted).map_err(|e| {
            report!(SetupError::Io(e)).context(SetupError::Other(format!(
                "Failed to open encrypted DMG: {}",
                rootfs_dmg_encrypted.display()
            )))
        })?;
        let mut output = File::create(&rootfs_dmg).map_err(|e| {
            report!(SetupError::Io(e)).context(SetupError::Other(format!(
                "Failed to create output file: {}",
                rootfs_dmg.display()
            )))
        })?;
        decrypt(&mut input, &mut output, &args.key)
            .map_err(|e| report!(SetupError::Decrypt(e.to_string())))?;
    } else {
        println!("Rootfs DMG already decrypted, skipping.");
    }

    println!("✨ Done in {:?}", total_start.elapsed());
    Ok(())
}

fn qemu(args: QemuArgs) -> Result<(), Report<SetupError>> {
    println!("🚀 Starting QEMU...");
    let mut cmd = std::process::Command::new("qemu-system-aarch64");
    cmd.arg("-machine")
        .arg("virt")
        .arg("-cpu")
        .arg("cortex-a57")
        .arg("-m")
        .arg(&args.memory)
        .arg("-smp")
        .arg(args.cpus.to_string())
        .arg("-kernel")
        .arg(&args.kernel)
        .arg("-drive")
        .arg("file=work/rootfs.dmg,format=raw,if=virtio")
        .arg("-serial")
        .arg("mon:stdio");

    if args.nographic {
        cmd.arg("-nographic");
    }

    let status = cmd
        .status()
        .map_err(|e| report!(SetupError::Other(format!("Failed to run QEMU: {}", e))))?;

    if !status.success() {
        return Err(report!(SetupError::Other(
            "QEMU exited with error".to_string()
        )));
    }

    Ok(())
}

async fn download_ipsw(
    url: &str,
    output: &Path,
    mp: &MultiProgress,
) -> Result<(), Report<SetupError>> {
    let client = reqwest::Client::new();
    let response = client.get(url).send().await.map_err(|e| {
        report!(SetupError::Download(e.to_string())).context(SetupError::Download(format!(
            "Failed to download IPSW from {}",
            url
        )))
    })?;
    let total_size = response.content_length().unwrap_or(0);

    let pb = mp.add(ProgressBar::new(total_size));
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
        .unwrap()
        .progress_chars("#>-"));

    let mut file = tokio::fs::File::create(output).await.map_err(|e| {
        report!(SetupError::Io(e)).context(SetupError::Other(format!(
            "Failed to create output file: {}",
            output.display()
        )))
    })?;
    let mut downloaded: u64 = 0;
    let mut stream = response.bytes_stream();

    use futures_util::StreamExt;
    while let Some(item) = stream.next().await {
        let chunk = item.map_err(|e| report!(SetupError::Download(e.to_string())))?;
        file.write_all(&chunk).await.map_err(|e| {
            report!(SetupError::Io(e)).context(SetupError::Other(
                "Failed to write downloaded data".to_string(),
            ))
        })?;
        downloaded = min(downloaded + (chunk.len() as u64), total_size);
        pb.set_position(downloaded);
    }

    pb.finish_with_message("Download complete");
    Ok(())
}
