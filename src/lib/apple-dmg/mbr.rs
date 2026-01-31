use binrw::{BinRead, BinWrite};

#[derive(Clone, Copy, Debug, Default, BinRead, BinWrite)]
#[br(little)]
#[bw(little)]
pub struct PartRecord {
    pub boot_indicator: u8,
    pub start_head: u8,
    pub start_sector: u8,
    pub start_track: u8,
    pub os_type: u8,
    pub end_head: u8,
    pub end_sector: u8,
    pub end_track: u8,
    pub lb_start: u32,
    pub lb_len: u32,
}

impl PartRecord {
    pub fn new_protective(size_sectors: Option<u32>) -> Self {
        let lb_len = size_sectors.unwrap_or(0xFFFFFFFF);
        Self {
            boot_indicator: 0,
            start_head: 0x00,
            start_sector: 0x02,
            start_track: 0x00,
            os_type: 0xEE,
            end_head: 0xFF,
            end_sector: 0xFF,
            end_track: 0xFF,
            lb_start: 1,
            lb_len,
        }
    }
}

#[derive(Debug, BinRead, BinWrite)]
#[br(little)]
#[bw(little)]
pub struct ProtectiveMBR {
    #[br(seek_before = binrw::io::SeekFrom::Start(446))]
    #[bw(seek_before = binrw::io::SeekFrom::Start(446))]
    pub partitions: [PartRecord; 4],
    #[br(assert(signature == [0x55, 0xAA]))]
    pub signature: [u8; 2],
}

impl ProtectiveMBR {
    pub fn new() -> Self {
        Self {
            partitions: [PartRecord::default(); 4],
            signature: [0x55, 0xAA],
        }
    }

    pub fn set_partition(&mut self, index: usize, partition: PartRecord) {
        if index < 4 {
            self.partitions[index] = partition;
        }
    }

    pub fn to_bytes(&self) -> [u8; 512] {
        use binrw::BinWriterExt;
        let mut buf = [0u8; 512];
        let mut cursor = binrw::io::Cursor::new(&mut buf[..]);
        cursor.write_le(self).unwrap();
        buf
    }
}
