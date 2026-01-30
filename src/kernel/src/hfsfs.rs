use crate::block::{BlockReader, BufReader, DeviceWrapper, ReadSeek};
use crate::kprintln;
use alloc::boxed::Box;
use alloc::sync::Arc;
use hfsplus::{CatalogBody, Fork, HFSVolume, Read, Seek, SeekFrom};
use spin::Mutex;

pub struct HfsFs {
    volume: Arc<Mutex<HFSVolume<Box<dyn ReadSeek>>>>,
}

impl HfsFs {
    pub fn new(device: Arc<dyn BlockReader>, base_offset: u64) -> Self {
        kprintln!("HfsFs: Initializing with offset {:x}", base_offset);
        let wrapper = DeviceWrapper::new(device, base_offset);
        let buffered = BufReader::with_capacity(64 * 1024, wrapper);
        Self::new_from_reader(Box::new(buffered))
    }

    pub fn new_from_reader(reader: Box<dyn ReadSeek>) -> Self {
        kprintln!("HfsFs: Loading HFS+ volume...");

        // Manual HFSVolume::load but with kernel logs
        let mut file = reader;
        file.seek(hfsplus::SeekFrom::Start(1024)).unwrap();
        let header = hfsplus::HFSPlusVolumeHeader::import(&mut file).unwrap();

        let file_arc: Arc<Mutex<Box<dyn ReadSeek>>> = Arc::new(Mutex::new(file));
        let volume = Arc::new(Mutex::new(hfsplus::HFSVolume {
            file: Arc::clone(&file_arc),
            header,
            catalog_btree: None,
            extents_btree: None,
        }));

        kprintln!("HFS+: Loading catalog fork...");
        let catalog_data = volume.lock().header.catalog_file;
        let catalog_fork = Fork::load(
            Arc::clone(&file_arc),
            hfsplus::K_HFSCATALOG_FILE_ID,
            0,
            &*volume.lock(),
            &catalog_data,
        )
        .unwrap();

        kprintln!("HFS+: Loading extents fork...");
        let extents_data = volume.lock().header.extents_file;
        let extents_fork = Fork::load(
            Arc::clone(&file_arc),
            hfsplus::K_HFSEXTENTS_FILE_ID,
            0,
            &*volume.lock(),
            &extents_data,
        )
        .unwrap();

        kprintln!("HFS+: Opening catalog B-tree...");
        let temp_btree = hfsplus::BTree::<_, hfsplus::CatalogKey, hfsplus::CatalogRecord>::open(
            catalog_fork.clone(),
        )
        .unwrap();
        let compare_type = temp_btree.header.header.key_compare_type;
        let catalog_enum = if compare_type == 0xBC {
            let btree = hfsplus::BTree::<
                _,
                hfsplus::CatalogKey<hfsplus::HFSStringBinary>,
                hfsplus::CatalogRecord<hfsplus::HFSStringBinary>,
            >::open(catalog_fork)
            .unwrap();
            hfsplus::CatalogBTreeEnum::Binary(Arc::new(Mutex::new(btree)))
        } else {
            hfsplus::CatalogBTreeEnum::CaseFolding(Arc::new(Mutex::new(temp_btree)))
        };
        volume.lock().catalog_btree = Some(catalog_enum);
        kprintln!("HFS+: Opening extents B-tree...");
        volume.lock().extents_btree = Some(Arc::new(Mutex::new(
            hfsplus::BTree::open(extents_fork).unwrap(),
        )));

        kprintln!("HfsFs: HFS+ volume loaded successfully");
        Self { volume }
    }

    pub fn open(&self, path: &str) -> Option<Box<dyn crate::vfs::File>> {
        kprintln!("HfsFs: open '{}'", path);
        let vol = self.volume.lock();
        let record = vol.get_path_record(path).ok()?;
        if let CatalogBody::File(file_info) = record.body {
            let mut fork_data = &file_info.data_fork;
            let mut fork_type = 0;
            if fork_data.logical_size == 0 && file_info.resource_fork.logical_size > 0 {
                fork_data = &file_info.resource_fork;
                fork_type = 0xFF;
            }

            let fork = Fork::load(
                Arc::clone(&vol.file),
                file_info.file_id,
                fork_type,
                &*vol,
                fork_data,
            )
            .ok()?;

            Some(Box::new(HfsFileHandle {
                fork: Mutex::new(fork),
            }))
        } else {
            None
        }
    }
}

impl crate::vfs::FileSystem for HfsFs {
    fn open(&self, path: &str) -> Option<Box<dyn crate::vfs::File>> {
        self.open(path)
    }
}

pub struct HfsFileHandle {
    fork: Mutex<Fork<Box<dyn ReadSeek>>>,
}

impl crate::vfs::File for HfsFileHandle {
    fn read(&mut self, buf: &mut [u8]) -> usize {
        self.fork.lock().read(buf).unwrap_or(0)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> usize {
        let mut fork = self.fork.lock();
        let old_pos = fork.position;
        fork.seek(SeekFrom::Start(offset)).unwrap_or(0);
        let read = fork.read(buf).unwrap_or(0);
        fork.seek(SeekFrom::Start(old_pos)).unwrap_or(0);
        read
    }

    fn seek(&mut self, pos: u64) {
        self.fork.lock().seek(SeekFrom::Start(pos)).unwrap_or(0);
    }

    fn size(&self) -> u64 {
        self.fork.lock().logical_size
    }
}
