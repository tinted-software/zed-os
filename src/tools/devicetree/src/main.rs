use aes::Aes256;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use cbc::Decryptor;
use std::fs::File;
use std::io::Read;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DeviceTreeError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("IMG3 parse error: {0}")]
    Img3(String),
    #[error("Decryption error: {0}")]
    Decryption(String),
    #[error("Device tree parse error: {0}")]
    Parse(String),
}

type Result<T> = std::result::Result<T, DeviceTreeError>;

#[derive(Debug)]
struct Img3Header {
    magic: u32,
    full_size: u32,
    ident: u32,
}

#[derive(Debug)]
struct Img3Tag {
    magic: u32,
    data: Vec<u8>,
}

#[derive(Debug)]
struct Img3File {
    header: Img3Header,
    tags: Vec<Img3Tag>,
}

impl Img3File {
    fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 20 {
            return Err(DeviceTreeError::Img3("File too small".to_string()));
        }

        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let full_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let _data_size = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let _skip_dist = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let ident = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);

        let header = Img3Header {
            magic,
            full_size,
            ident,
        };
        let mut tags = Vec::new();
        let mut offset = 20;

        while offset < data.len() {
            if offset + 12 > data.len() {
                break;
            }

            let tag_magic = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            let total_length = u32::from_le_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]);
            let data_length = u32::from_le_bytes([
                data[offset + 8],
                data[offset + 9],
                data[offset + 10],
                data[offset + 11],
            ]);

            if total_length < 12 || offset + total_length as usize > data.len() {
                break;
            }

            let tag_data = data[offset + 12..offset + 12 + data_length as usize].to_vec();
            tags.push(Img3Tag {
                magic: tag_magic,
                data: tag_data,
            });

            offset += total_length as usize;
        }

        Ok(Img3File { header, tags })
    }

    fn get_data_section(&self) -> Option<&[u8]> {
        self.tags
            .iter()
            .find(|tag| tag.magic == 0x44415441) // "DATA"
            .map(|tag| tag.data.as_slice())
    }
}

fn decrypt_payload(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let mut buf = data.to_vec();
    let mut cipher = Decryptor::<Aes256>::new_from_slices(key, iv)
        .map_err(|e| DeviceTreeError::Decryption(e.to_string()))?;

    for chunk in buf.chunks_mut(16) {
        if chunk.len() == 16 {
            cipher.decrypt_block_mut(chunk.into());
        }
    }
    Ok(buf)
}

#[derive(Debug)]
struct DeviceTreeNode {
    name: String,
    properties: Vec<DeviceTreeProperty>,
    children: Vec<DeviceTreeNode>,
}

#[derive(Debug)]
struct DeviceTreeProperty {
    name: String,
    value: Vec<u8>,
}

fn parse_device_tree(data: &[u8]) -> Result<()> {
    println!("Analyzing device tree structure...");

    // Search for UART nodes and extract register information
    let mut uart_nodes = Vec::new();

    // Look for UART node patterns
    for (i, window) in data.windows(5).enumerate() {
        if let Ok(s) = std::str::from_utf8(window) {
            if s.starts_with("uart")
                && (s
                    .chars()
                    .nth(4)
                    .map_or(false, |c| c.is_ascii_digit() || c == '\0'))
            {
                // Found a UART node, look for register properties nearby
                let start = i.saturating_sub(100);
                let end = (i + 200).min(data.len());
                let section = &data[start..end];

                // Look for register addresses (reg property)
                for (j, reg_window) in section.windows(8).enumerate() {
                    // Check for potential register base addresses
                    let addr = u32::from_be_bytes([
                        reg_window[0],
                        reg_window[1],
                        reg_window[2],
                        reg_window[3],
                    ]);
                    let size = u32::from_be_bytes([
                        reg_window[4],
                        reg_window[5],
                        reg_window[6],
                        reg_window[7],
                    ]);

                    // Filter for reasonable UART addresses
                    if (addr >= 0x80000000 && addr < 0x90000000)
                        || (addr >= 0x3C000000 && addr < 0x40000000)
                    {
                        let uart_name = std::str::from_utf8(window)
                            .unwrap_or("uart?")
                            .trim_end_matches('\0');
                        uart_nodes.push(format!(
                            "{}: Base=0x{:08x}, Size=0x{:x}",
                            uart_name, addr, size
                        ));
                    }
                }
            }
        }
    }

    // Also search for known UART base addresses directly
    let known_uart_bases = [
        (0x82500000u32, "UART0 (Apple A4)"),
        (0x82500040u32, "UART1 (Apple A4)"),
        (0x82500080u32, "UART2 (Apple A4)"),
        (0x825000C0u32, "UART3 (Apple A4)"),
    ];

    for (base, name) in &known_uart_bases {
        let base_bytes_be = base.to_be_bytes();
        let base_bytes_le = base.to_le_bytes();

        for (i, window) in data.windows(4).enumerate() {
            if window == base_bytes_be || window == base_bytes_le {
                println!("Found {} at offset 0x{:x}", name, i);
            }
        }
    }

    if uart_nodes.is_empty() {
        println!("No UART register information found");

        // Fallback: show all UART string references
        println!("\nUART string references:");
        for (i, window) in data.windows(10).enumerate() {
            if let Ok(s) = std::str::from_utf8(window) {
                if s.contains("uart") || s.contains("UART") {
                    let clean = s
                        .chars()
                        .take_while(|c| c.is_ascii_graphic())
                        .collect::<String>();
                    if clean.len() > 3 {
                        println!("  0x{:x}: {}", i, clean);
                    }
                }
            }
        }
    } else {
        println!("\nUART Register Information:");
        for node in uart_nodes {
            println!("  {}", node);
        }
    }

    Ok(())
}

fn parse_node(data: &[u8], offset: &mut usize) -> Result<DeviceTreeNode> {
    if *offset + 8 > data.len() {
        return Err(DeviceTreeError::Parse("Unexpected end of data".to_string()));
    }

    let num_props = u32::from_be_bytes([
        data[*offset],
        data[*offset + 1],
        data[*offset + 2],
        data[*offset + 3],
    ]);
    let num_children = u32::from_be_bytes([
        data[*offset + 4],
        data[*offset + 5],
        data[*offset + 6],
        data[*offset + 7],
    ]);
    *offset += 8;

    // Read properties
    let mut properties = Vec::new();
    for _ in 0..num_props {
        if *offset + 8 > data.len() {
            break;
        }

        let name_len = u32::from_be_bytes([
            data[*offset],
            data[*offset + 1],
            data[*offset + 2],
            data[*offset + 3],
        ]);
        let value_len = u32::from_be_bytes([
            data[*offset + 4],
            data[*offset + 5],
            data[*offset + 6],
            data[*offset + 7],
        ]);
        *offset += 8;

        if *offset + name_len as usize + value_len as usize > data.len() {
            break;
        }

        let name = String::from_utf8_lossy(&data[*offset..*offset + name_len as usize])
            .trim_end_matches('\0')
            .to_string();
        *offset += name_len as usize;

        let value = data[*offset..*offset + value_len as usize].to_vec();
        *offset += value_len as usize;

        properties.push(DeviceTreeProperty { name, value });
    }

    // Read children
    let mut children = Vec::new();
    for _ in 0..num_children {
        if let Ok(child) = parse_node(data, offset) {
            children.push(child);
        }
    }

    let name = properties
        .iter()
        .find(|p| p.name == "name")
        .map(|p| {
            String::from_utf8_lossy(&p.value)
                .trim_end_matches('\0')
                .to_string()
        })
        .unwrap_or_else(|| "unnamed".to_string());

    Ok(DeviceTreeNode {
        name,
        properties,
        children,
    })
}

fn find_uart_nodes(node: &DeviceTreeNode, path: &str) -> Vec<String> {
    let mut results = Vec::new();
    let current_path = if path.is_empty() {
        node.name.clone()
    } else {
        format!("{}/{}", path, node.name)
    };

    if node.name.contains("uart") || node.name.contains("serial") {
        let mut info = format!("UART Node: {}", current_path);

        for prop in &node.properties {
            match prop.name.as_str() {
                "reg" if prop.value.len() >= 8 => {
                    let addr = u32::from_be_bytes([
                        prop.value[0],
                        prop.value[1],
                        prop.value[2],
                        prop.value[3],
                    ]);
                    let size = u32::from_be_bytes([
                        prop.value[4],
                        prop.value[5],
                        prop.value[6],
                        prop.value[7],
                    ]);
                    info.push_str(&format!(
                        "\n  Address: 0x{:08x}, Size: 0x{:08x}",
                        addr, size
                    ));
                }
                "compatible" => {
                    let compat = String::from_utf8_lossy(&prop.value)
                        .trim_end_matches('\0')
                        .to_string();
                    info.push_str(&format!("\n  Compatible: {}", compat));
                }
                "clock-frequency" if prop.value.len() >= 4 => {
                    let freq = u32::from_be_bytes([
                        prop.value[0],
                        prop.value[1],
                        prop.value[2],
                        prop.value[3],
                    ]);
                    info.push_str(&format!("\n  Clock: {} Hz", freq));
                }
                _ => {}
            }
        }
        results.push(info);
    }

    for child in &node.children {
        results.extend(find_uart_nodes(child, &current_path));
    }

    results
}

fn main() -> Result<()> {
    let dt_path = "work/Firmware/all_flash/all_flash.k48ap.production/DeviceTree.k48ap.img3";
    let mut dt_file = File::open(dt_path)?;
    let mut dt_data = Vec::new();
    dt_file.read_to_end(&mut dt_data)?;

    println!("Apple Device Tree Parser");
    println!("=======================");

    // Parse IMG3 and decrypt
    let img3 = Img3File::parse(&dt_data)?;
    let encrypted_data = img3
        .get_data_section()
        .ok_or_else(|| DeviceTreeError::Img3("DATA section not found".to_string()))?;

    let iv = hex::decode("e0a3aa63dae431e573c9827dd3636dd1").unwrap();
    let key =
        hex::decode("50208af7c2de617854635fb4fc4eaa8cddab0e9035ea25abf81b0fa8b0b5654f").unwrap();
    let decrypted_data = decrypt_payload(encrypted_data, &key, &iv)?;

    // Extract UART information
    parse_device_tree(&decrypted_data)?;

    Ok(())
}
