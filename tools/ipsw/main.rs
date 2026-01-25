use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use ipsw_downloader::fetch_firmware_url;
use std::cmp::min;
use std::path::PathBuf;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Download an IPSW
    Download {
        /// The URL to download
        #[arg(long)]
        url: Option<String>,

        /// Device Identifier (e.g., iPhone1,1)
        #[arg(long)]
        device: Option<String>,

        /// Build ID (e.g., 1A543a)
        #[arg(long)]
        build: Option<String>,

        /// Output file path. If not provided, the filename from the URL will be used.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Download {
            url,
            device,
            build,
            output,
        } => {
            let download_url = if let Some(u) = url {
                u
            } else if let (Some(d), Some(b)) = (device, build) {
                println!("Fetching URL for device: {} build: {}...", d, b);
                match fetch_firmware_url(&d, &b).await? {
                    Some(u) => u,
                    None => {
                        eprintln!(
                            "Could not find firmware for device '{}' and build '{}'",
                            d, b
                        );
                        std::process::exit(1);
                    }
                }
            } else {
                eprintln!("Error: You must provide either --url OR (--device and --build)");
                std::process::exit(1);
            };

            download_ipsw(&download_url, output).await?;
        }
    }

    Ok(())
}

async fn download_ipsw(
    url: &str,
    output: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();

    // Send a HEAD request first to get the content length and validate the URL
    let head_resp = client.head(url).send().await?;
    if !head_resp.status().is_success() {
        return Err(format!("Failed to access URL: {}", head_resp.status()).into());
    }

    let total_size = head_resp
        .headers()
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|ct_len| ct_len.to_str().ok())
        .and_then(|ct_len| ct_len.parse::<u64>().ok())
        .unwrap_or(0);

    // Determine output filename
    let filename = match output {
        Some(path) => path,
        None => {
            let fname = url
                .rsplit_once('/')
                .map(|(_, name)| name)
                .unwrap_or("download.ipsw");
            PathBuf::from(fname)
        }
    };

    println!("Downloading to: {}", filename.display());

    let mut response = client.get(url).send().await?;
    if !response.status().is_success() {
        return Err(format!("Failed to download: {}", response.status()).into());
    }

    let pb = ProgressBar::new(total_size);
    pb.set_style(ProgressStyle::default_bar()
        .template("{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")?
        .progress_chars("#>-    "));
    pb.set_message(format!("Downloading {}", filename.display()));

    let mut file = File::create(&filename).await?;
    let mut downloaded: u64 = 0;

    while let Some(chunk) = response.chunk().await? {
        file.write_all(&chunk).await?;
        let new = min(downloaded + (chunk.len() as u64), total_size);
        downloaded = new;
        pb.set_position(new);
    }

    pb.finish_with_message(format!("Downloaded {} successfully", filename.display()));

    Ok(())
}
