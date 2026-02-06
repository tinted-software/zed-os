use aes::Aes256;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use cbc::Decryptor;
use derive_more::derive::Display;
use std::fs::File;
use std::io::Read;

#[derive(Debug, Display)]
pub enum DeviceTreeError {
    #[display("I/O error: {_0}")]
    Io(std::io::Error),
    #[display("IMG3 parse error: {_0}")]
    Img3(String),
    #[display("Decryption error: {_0}")]
    Decryption(String),
    #[display("Device tree parse error: {_0}")]
    Parse(String),
}

impl std::error::Error for DeviceTreeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DeviceTreeError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for DeviceTreeError {
    fn from(err: std::io::Error) -> Self {
        DeviceTreeError::Io(err)
    }
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

fn parse_node(data: &[u8], offset: &mut usize) -> Result<DeviceTreeNode> {
    if *offset + 8 > data.len() {
        return Err(DeviceTreeError::Parse("Unexpected end of data".to_string()));
    }

    let num_props = u32::from_le_bytes([
        data[*offset],
        data[*offset + 1],
        data[*offset + 2],
        data[*offset + 3],
    ]);
    let num_children = u32::from_le_bytes([
        data[*offset + 4],
        data[*offset + 5],
        data[*offset + 6],
        data[*offset + 7],
    ]);
    *offset += 8;

    println!(
        "Node at offset 0x{:x}: {} props, {} children",
        *offset - 8,
        num_props,
        num_children
    );
    if num_props > 1000 || num_children > 1000 {
        return Err(DeviceTreeError::Parse(format!(
            "Suspicious node counts: props={}, children={}",
            num_props, num_children
        )));
    }

    // Read properties
    let mut properties = Vec::new();
    for _ in 0..num_props {
        if *offset + 32 + 4 > data.len() {
            break;
        }

        let name = String::from_utf8_lossy(&data[*offset..*offset + 32])
            .trim_end_matches('\0')
            .to_string();
        *offset += 32;

        let value_len = u32::from_le_bytes([
            data[*offset],
            data[*offset + 1],
            data[*offset + 2],
            data[*offset + 3],
        ]);
        *offset += 4;

        if *offset + value_len as usize > data.len() {
            break;
        }

        let value = data[*offset..*offset + value_len as usize].to_vec();
        *offset += value_len as usize;
        // Align to 4 bytes
        *offset = (*offset + 3) & !3;

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

fn print_tree(node: &DeviceTreeNode, depth: usize) {
    let indent = "  ".repeat(depth);
    println!("{}{}", indent, node.name);

    if node.name == "chosen" || node.name == "memory-map" {
        for prop in &node.properties {
            println!("{}  prop {}: size={}", indent, prop.name, prop.value.len());
            if prop.value.len() == 8 {
                let v1 = u32::from_le_bytes([
                    prop.value[0],
                    prop.value[1],
                    prop.value[2],
                    prop.value[3],
                ]);
                let v2 = u32::from_le_bytes([
                    prop.value[4],
                    prop.value[5],
                    prop.value[6],
                    prop.value[7],
                ]);
                println!("{}    values: 0x{:08x} 0x{:08x}", indent, v1, v2);
            }
        }
    }

    for prop in &node.properties {
        if prop.name == "reg" && prop.value.len() >= 8 {
            let addr =
                u32::from_le_bytes([prop.value[0], prop.value[1], prop.value[2], prop.value[3]]);
            let size =
                u32::from_le_bytes([prop.value[4], prop.value[5], prop.value[6], prop.value[7]]);
            println!("{}  reg: base=0x{:08x} size=0x{:x}", indent, addr, size);
        }
        if prop.name == "compatible" {
            let s = String::from_utf8_lossy(&prop.value)
                .trim_matches('\0')
                .to_string();
            println!("{}  compatible: {}", indent, s);
        }
    }

    for child in &node.children {
        print_tree(child, depth + 1);
    }
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

    // Hexdump decrypted data
    println!("Decrypted Data Hexdump (first 256 bytes):");
    for i in (0..256.min(decrypted_data.len())).step_by(16) {
        print!("{:04x}: ", i);
        for j in 0..16 {
            if i + j < decrypted_data.len() {
                print!("{:02x} ", decrypted_data[i + j]);
            }
        }
        print!(" |");
        for j in 0..16 {
            if i + j < decrypted_data.len() {
                let c = decrypted_data[i + j];
                if c >= 0x20 && c <= 0x7E {
                    print!("{}", c as char);
                } else {
                    print!(".");
                }
            }
        }
        println!("|");
    }

    // Parse the tree structure
    println!("Parsing Device Tree structure...");
    let mut offset = 0;
    let root = parse_node(&decrypted_data, &mut offset)?;

    // Print the full tree
    print_tree(&root, 0);

    Ok(())
}
