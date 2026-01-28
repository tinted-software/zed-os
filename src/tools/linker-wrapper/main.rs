use std::env;
use std::process::Command;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut final_args = Vec::new();

    // Mandatory for ld64
    final_args.push("-arch".to_string());
    final_args.push("arm64".to_string());

    // Add platform version to satisfy newer ld64
    final_args.push("-platform_version".to_string());
    final_args.push("macos".to_string());
    final_args.push("13.0.0".to_string());
    final_args.push("13.0.0".to_string());

    let mut skip_next = false;
    for (i, arg) in args.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }

        match arg.as_str() {
            "-fuse-ld=lld"
            | "--fix-cortex-a53-843419"
            | "--as-needed"
            | "--eh-frame-hdr"
            | "--gc-sections" => {
                // Ignore
            }
            "-flavor" => {
                skip_next = true;
            }
            "-Bstatic" => {
                final_args.push("-static".to_string());
            }
            "-Bdynamic" => {
                final_args.push("-dynamic".to_string());
            }
            "-z" => {
                skip_next = true;
            }
            "-arch" => {
                // Ignore rustc's arch if it passes one, we'll use ours
                skip_next = true;
            }
            "-mmacosx-version-min=11.0.0" => {
                skip_next = true;
            }
            "-Wl,-dead_strip" => {
                skip_next = true;
            }
            "-nodefaultlibs" => {
                skip_next = true;
            }
            _ => {
                if arg.starts_with("-fuse-ld=") {
                    continue;
                }
                final_args.push(arg.clone());
            }
        }
    }

    eprintln!("Wrapper running: ld64.lld {:?}", final_args);

    let status = Command::new("ld64.lld")
        .args(&final_args)
        .status()
        .expect("failed to execute ld64.lld");

    std::process::exit(status.code().unwrap_or(1));
}
