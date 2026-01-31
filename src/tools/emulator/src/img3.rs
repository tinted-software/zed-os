use thiserror::Error;

#[derive(Error, Debug)]
pub enum Img3Error {
    #[error("Invalid IMG3 format: {0}")]
    Format(String),
    #[error("Tag not found: {0}")]
    TagNotFound(String),
    #[error("Invalid tag data")]
    InvalidTag,
}

pub type Result<T> = std::result::Result<T, Img3Error>;

#[repr(C, packed)]
pub struct Img3Header {
    pub magic: u32, // "3gmI" (little endian)
    pub full_size: u32,
    pub size_no_pack: u32,
    pub sig_check_area: u32,
    pub ident: u32,
}

pub struct Img3Tag {
    pub magic: u32,
    pub total_length: u32,
    pub data_length: u32,
    pub data: Vec<u8>,
}

pub struct Img3File {
    pub header: Img3Header,
    pub tags: Vec<Img3Tag>,
}

impl Img3File {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < std::mem::size_of::<Img3Header>() {
            return Err(Img3Error::Format("File too small".to_string()));
        }

        let header: Img3Header = unsafe { std::ptr::read(data.as_ptr() as *const _) };

        if header.magic != 0x496d6733 {
            // "3gmI" in little endian
            return Err(Img3Error::Format("Invalid IMG3 magic".to_string()));
        }

        let mut tags = Vec::new();
        let mut offset = std::mem::size_of::<Img3Header>();

        while offset + 12 <= data.len() {
            let magic = u32::from_le_bytes([
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

            if offset + total_length as usize > data.len() {
                break;
            }

            let tag_data = data[offset + 12..offset + 12 + data_length as usize].to_vec();

            tags.push(Img3Tag {
                magic,
                total_length,
                data_length,
                data: tag_data,
            });

            offset += total_length as usize;
        }

        Ok(Img3File { header, tags })
    }

    pub fn find_tag(&self, magic: u32) -> Option<&Img3Tag> {
        self.tags.iter().find(|tag| tag.magic == magic)
    }

    pub fn get_data_section(&self) -> Option<&[u8]> {
        self.find_tag(0x44415441).map(|tag| tag.data.as_slice()) // "ATAD"
    }

    pub fn get_kbag(&self) -> Option<&[u8]> {
        self.find_tag(0x4b424147).map(|tag| tag.data.as_slice()) // "GABK"
    }
}
