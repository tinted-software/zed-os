#![allow(non_snake_case, unused)]
#![allow(non_upper_case_globals, unused_variables)]
#![allow(unused)]

use std::io::{self, Read, Write};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

#[derive(Debug, Copy, Clone)]
pub struct HFSPlusBSDInfo {
    pub ownerID: u32,
    pub groupID: u32,
    pub adminFlags: u8,
    pub ownerFlags: u8,
    pub fileMode: u16,
    pub special: u32,
}

impl HFSPlusBSDInfo {
    pub fn import(source: &mut dyn Read) -> io::Result<Self> {
        Ok(Self {
            ownerID: source.read_u32::<BigEndian>()?,
            groupID: source.read_u32::<BigEndian>()?,
            adminFlags: source.read_u8()?,
            ownerFlags: source.read_u8()?,
            fileMode: source.read_u16::<BigEndian>()?,
            special: source.read_u32::<BigEndian>()?,
        })
    }
}

pub const S_ISUID: u16 = 0o0004000;
pub const S_ISGID: u16 = 0o0002000;
pub const S_ISTXT: u16 = 0o0001000;

pub const S_IRWXU: u16 = 0o0000700;
pub const S_IRUSR: u16 = 0o0000400;
pub const S_IWUSR: u16 = 0o0000200;
pub const S_IXUSR: u16 = 0o0000100;

pub const S_IRWXG: u16 = 0o0000070;
pub const S_IRGRP: u16 = 0o0000040;
pub const S_IWGRP: u16 = 0o0000020;
pub const S_IXGRP: u16 = 0o0000010;

pub const S_IRWXO: u16 = 0o0000007;
pub const S_IROTH: u16 = 0o0000004;
pub const S_IWOTH: u16 = 0o0000002;
pub const S_IXOTH: u16 = 0o0000001;

pub const S_IFMT: u16 = 0o0170000;
pub const S_IFIFO: u16 = 0o0010000;
pub const S_IFCHR: u16 = 0o0020000;
pub const S_IFDIR: u16 = 0o0040000;
pub const S_IFBLK: u16 = 0o0060000;
pub const S_IFREG: u16 = 0o0100000;
pub const S_IFLNK: u16 = 0o0120000;
pub const S_IFSOCK: u16 = 0o0140000;
pub const S_IFWHT: u16 = 0o0160000;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct HFSPlusForkData {
    pub logicalSize: u64,
    pub clumpSize: u32,
    pub totalBlocks: u32,
    pub extents: HFSPlusExtentRecord,
}

pub type HFSPlusExtentRecord = [HFSPlusExtentDescriptor; 8];

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct HFSPlusExtentDescriptor {
    pub startBlock: u32,
    pub blockCount: u32,
}

impl HFSPlusForkData {
    pub fn import(source: &mut dyn Read) -> io::Result<Self> {
        Ok(Self {
            logicalSize: source.read_u64::<BigEndian>()?,
            clumpSize: source.read_u32::<BigEndian>()?,
            totalBlocks: source.read_u32::<BigEndian>()?,
            extents: import_record(source)?,
        })
    }

    pub fn export(&self, source: &mut dyn Write) -> io::Result<()> {
        source.write_u64::<BigEndian>(self.logicalSize)?;
        source.write_u32::<BigEndian>(self.clumpSize)?;
        source.write_u32::<BigEndian>(self.totalBlocks)?;
        export_record(&self.extents, source)?;
        Ok(())
    }
}

pub fn import_record(source: &mut dyn Read) -> io::Result<HFSPlusExtentRecord> {
    Ok([
        HFSPlusExtentDescriptor::import(source)?,
        HFSPlusExtentDescriptor::import(source)?,
        HFSPlusExtentDescriptor::import(source)?,
        HFSPlusExtentDescriptor::import(source)?,
        HFSPlusExtentDescriptor::import(source)?,
        HFSPlusExtentDescriptor::import(source)?,
        HFSPlusExtentDescriptor::import(source)?,
        HFSPlusExtentDescriptor::import(source)?,
    ])
}

pub fn export_record(record: &[HFSPlusExtentDescriptor], source: &mut dyn Write) -> io::Result<()> {
    for r in record {
        r.export(source)?;
    }
    Ok(())
}

impl HFSPlusExtentDescriptor {
    pub fn import(source: &mut dyn Read) -> io::Result<Self> {
        Ok(Self {
            startBlock: source.read_u32::<BigEndian>()?,
            blockCount: source.read_u32::<BigEndian>()?,
        })
    }

    pub fn export(&self, source: &mut dyn Write) -> io::Result<()> {
        source.write_u32::<BigEndian>(self.startBlock)?;
        source.write_u32::<BigEndian>(self.blockCount)?;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct HFSPlusVolumeHeader {
    pub signature: u16,
    pub version: u16,
    pub attributes: u32,
    pub lastMountedVersion: u32,
    pub journalInfoBlock: u32,
    pub createDate: u32,
    pub modifyDate: u32,
    pub backupDate: u32,
    pub checkedDate: u32,
    pub fileCount: u32,
    pub folderCount: u32,
    pub blockSize: u32,
    pub totalBlocks: u32,
    pub freeBlocks: u32,
    pub nextAllocation: u32,
    pub rsrcClumpSize: u32,
    pub dataClumpSize: u32,
    pub nextCatalogID: u32,
    pub writeCount: u32,
    pub encodingsBitmap: u64,
    pub finderInfo: [u32; 8],
    pub allocationFile: HFSPlusForkData,
    pub extentsFile: HFSPlusForkData,
    pub catalogFile: HFSPlusForkData,
    pub attributesFile: HFSPlusForkData,
    pub startupFile: HFSPlusForkData,
}

impl HFSPlusVolumeHeader {
    pub fn import(source: &mut dyn Read) -> io::Result<Self> {
        Ok(Self {
            signature: source.read_u16::<BigEndian>()?,
            version: source.read_u16::<BigEndian>()?,
            attributes: source.read_u32::<BigEndian>()?,
            lastMountedVersion: source.read_u32::<BigEndian>()?,
            journalInfoBlock: source.read_u32::<BigEndian>()?,
            createDate: source.read_u32::<BigEndian>()?,
            modifyDate: source.read_u32::<BigEndian>()?,
            backupDate: source.read_u32::<BigEndian>()?,
            checkedDate: source.read_u32::<BigEndian>()?,
            fileCount: source.read_u32::<BigEndian>()?,
            folderCount: source.read_u32::<BigEndian>()?,
            blockSize: source.read_u32::<BigEndian>()?,
            totalBlocks: source.read_u32::<BigEndian>()?,
            freeBlocks: source.read_u32::<BigEndian>()?,
            nextAllocation: source.read_u32::<BigEndian>()?,
            rsrcClumpSize: source.read_u32::<BigEndian>()?,
            dataClumpSize: source.read_u32::<BigEndian>()?,
            nextCatalogID: source.read_u32::<BigEndian>()?,
            writeCount: source.read_u32::<BigEndian>()?,
            encodingsBitmap: source.read_u64::<BigEndian>()?,
            finderInfo: [
                source.read_u32::<BigEndian>()?,
                source.read_u32::<BigEndian>()?,
                source.read_u32::<BigEndian>()?,
                source.read_u32::<BigEndian>()?,
                source.read_u32::<BigEndian>()?,
                source.read_u32::<BigEndian>()?,
                source.read_u32::<BigEndian>()?,
                source.read_u32::<BigEndian>()?,
            ],
            allocationFile: HFSPlusForkData::import(source)?,
            extentsFile: HFSPlusForkData::import(source)?,
            catalogFile: HFSPlusForkData::import(source)?,
            attributesFile: HFSPlusForkData::import(source)?,
            startupFile: HFSPlusForkData::import(source)?,
        })
    }
}

pub const HFSP_SIGNATURE: u16 = 0x482b;
pub const HFSX_SIGNATURE: u16 = 0x4858;

#[derive(Debug, PartialEq, Eq)]
pub struct BTNodeDescriptor {
    pub fLink: u32,
    pub bLink: u32,
    pub kind: i8,
    pub height: u8,
    pub numRecords: u16,
    pub reserved: u16,
}

impl BTNodeDescriptor {
    pub fn import(source: &mut dyn Read) -> io::Result<Self> {
        Ok(Self {
            fLink: source.read_u32::<BigEndian>()?,
            bLink: source.read_u32::<BigEndian>()?,
            kind: source.read_i8()?,
            height: source.read_u8()?,
            numRecords: source.read_u16::<BigEndian>()?,
            reserved: source.read_u16::<BigEndian>()?,
        })
    }

    pub fn export(&self, source: &mut dyn Write) -> io::Result<()> {
        source.write_u32::<BigEndian>(self.fLink)?;
        source.write_u32::<BigEndian>(self.bLink)?;
        source.write_i8(self.kind)?;
        source.write_u8(self.height)?;
        source.write_u16::<BigEndian>(self.numRecords)?;
        source.write_u16::<BigEndian>(self.reserved)?;
        Ok(())
    }
}

pub const kBTLeafNode: i8 = -1;
pub const kBTIndexNode: i8 = 0;
pub const kBTHeaderNode: i8 = 1;
pub const kBTMapNode: i8 = 2;

#[derive(Debug, PartialEq, Eq)]
pub struct BTHeaderRec {
    pub treeDepth: u16,
    pub rootNode: u32,
    pub leafRecords: u32,
    pub firstLeafNode: u32,
    pub lastLeafNode: u32,
    pub nodeSize: u16,
    pub maxKeyLength: u16,
    pub totalNodes: u32,
    pub freeNodes: u32,
    pub reserved1: u16,
    pub clumpSize: u32,
    pub btreeType: u8,
    pub keyCompareType: u8,
    pub attributes: u32,
    pub reserved3: [u32; 16],
}

impl BTHeaderRec {
    pub fn import(source: &mut dyn Read) -> io::Result<Self> {
        Ok(Self {
            treeDepth: source.read_u16::<BigEndian>()?,
            rootNode: source.read_u32::<BigEndian>()?,
            leafRecords: source.read_u32::<BigEndian>()?,
            firstLeafNode: source.read_u32::<BigEndian>()?,
            lastLeafNode: source.read_u32::<BigEndian>()?,
            nodeSize: source.read_u16::<BigEndian>()?,
            maxKeyLength: source.read_u16::<BigEndian>()?,
            totalNodes: source.read_u32::<BigEndian>()?,
            freeNodes: source.read_u32::<BigEndian>()?,
            reserved1: source.read_u16::<BigEndian>()?,
            clumpSize: source.read_u32::<BigEndian>()?,
            btreeType: source.read_u8()?,
            keyCompareType: source.read_u8()?,
            attributes: source.read_u32::<BigEndian>()?,
            reserved3: [
                source.read_u32::<BigEndian>()?,
                source.read_u32::<BigEndian>()?,
                source.read_u32::<BigEndian>()?,
                source.read_u32::<BigEndian>()?,
                source.read_u32::<BigEndian>()?,
                source.read_u32::<BigEndian>()?,
                source.read_u32::<BigEndian>()?,
                source.read_u32::<BigEndian>()?,
                source.read_u32::<BigEndian>()?,
                source.read_u32::<BigEndian>()?,
                source.read_u32::<BigEndian>()?,
                source.read_u32::<BigEndian>()?,
                source.read_u32::<BigEndian>()?,
                source.read_u32::<BigEndian>()?,
                source.read_u32::<BigEndian>()?,
                source.read_u32::<BigEndian>()?,
            ],
        })
    }

    pub fn export(&self, source: &mut dyn Write) -> io::Result<()> {
        source.write_u16::<BigEndian>(self.treeDepth)?;
        source.write_u32::<BigEndian>(self.rootNode)?;
        source.write_u32::<BigEndian>(self.leafRecords)?;
        source.write_u32::<BigEndian>(self.firstLeafNode)?;
        source.write_u32::<BigEndian>(self.lastLeafNode)?;
        source.write_u16::<BigEndian>(self.nodeSize)?;
        source.write_u16::<BigEndian>(self.maxKeyLength)?;
        source.write_u32::<BigEndian>(self.totalNodes)?;
        source.write_u32::<BigEndian>(self.freeNodes)?;
        source.write_u16::<BigEndian>(self.reserved1)?;
        source.write_u32::<BigEndian>(self.clumpSize)?;
        source.write_u8(self.btreeType)?;
        source.write_u8(self.keyCompareType)?;
        source.write_u32::<BigEndian>(self.attributes)?;
        for r in &self.reserved3 {
            source.write_u32::<BigEndian>(*r)?;
        }
        Ok(())
    }
}

pub type HFSCatalogNodeID = u32;
pub const kHFSCatalogFileID: HFSCatalogNodeID = 4;
pub const kHFSExtentsFileID: HFSCatalogNodeID = 3;

pub const kHFSPlusFolderRecord: i16 = 0x0001;
pub const kHFSPlusFileRecord: i16 = 0x0002;
pub const kHFSPlusFolderThreadRecord: i16 = 0x0003;
pub const kHFSPlusFileThreadRecord: i16 = 0x0004;

#[derive(Debug, Copy, Clone)]
pub struct HFSPlusCatalogFolder {
    pub flags: u16,
    pub valence: u32,
    pub folderID: HFSCatalogNodeID,
    pub createDate: u32,
    pub contentModDate: u32,
    pub attributeModDate: u32,
    pub accessDate: u32,
    pub backupDate: u32,
    pub permissions: HFSPlusBSDInfo,
    pub userInfo: FolderInfo,
    pub finderInfo: ExtendedFolderInfo,
    pub textEncoding: u32,
    pub reserved: u32,
}

impl HFSPlusCatalogFolder {
    pub fn import(source: &mut dyn Read) -> io::Result<Self> {
        Ok(Self {
            flags: source.read_u16::<BigEndian>()?,
            valence: source.read_u32::<BigEndian>()?,
            folderID: source.read_u32::<BigEndian>()?,
            createDate: source.read_u32::<BigEndian>()?,
            contentModDate: source.read_u32::<BigEndian>()?,
            attributeModDate: source.read_u32::<BigEndian>()?,
            accessDate: source.read_u32::<BigEndian>()?,
            backupDate: source.read_u32::<BigEndian>()?,
            permissions: HFSPlusBSDInfo::import(source)?,
            userInfo: FolderInfo::import(source)?,
            finderInfo: ExtendedFolderInfo::import(source)?,
            textEncoding: source.read_u32::<BigEndian>()?,
            reserved: source.read_u32::<BigEndian>()?,
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct HFSPlusCatalogFile {
    pub flags: u16,
    pub reserved1: u32,
    pub fileID: HFSCatalogNodeID,
    pub createDate: u32,
    pub contentModDate: u32,
    pub attributeModDate: u32,
    pub accessDate: u32,
    pub backupDate: u32,
    pub permissions: HFSPlusBSDInfo,
    pub userInfo: FileInfo,
    pub finderInfo: ExtendedFileInfo,
    pub textEncoding: u32,
    pub reserved2: u32,
    pub dataFork: HFSPlusForkData,
    pub resourceFork: HFSPlusForkData,
}

impl HFSPlusCatalogFile {
    pub fn import(source: &mut dyn Read) -> io::Result<Self> {
        Ok(Self {
            flags: source.read_u16::<BigEndian>()?,
            reserved1: source.read_u32::<BigEndian>()?,
            fileID: source.read_u32::<BigEndian>()?,
            createDate: source.read_u32::<BigEndian>()?,
            contentModDate: source.read_u32::<BigEndian>()?,
            attributeModDate: source.read_u32::<BigEndian>()?,
            accessDate: source.read_u32::<BigEndian>()?,
            backupDate: source.read_u32::<BigEndian>()?,
            permissions: HFSPlusBSDInfo::import(source)?,
            userInfo: FileInfo::import(source)?,
            finderInfo: ExtendedFileInfo::import(source)?,
            textEncoding: source.read_u32::<BigEndian>()?,
            reserved2: source.read_u32::<BigEndian>()?,
            dataFork: HFSPlusForkData::import(source)?,
            resourceFork: HFSPlusForkData::import(source)?,
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Point {
    pub v: i16,
    pub h: i16,
}
impl Point {
    pub fn import(source: &mut dyn Read) -> io::Result<Self> {
        Ok(Self {
            v: source.read_i16::<BigEndian>()?,
            h: source.read_i16::<BigEndian>()?,
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Rect {
    pub top: i16,
    pub left: i16,
    pub bottom: i16,
    pub right: i16,
}
impl Rect {
    pub fn import(source: &mut dyn Read) -> io::Result<Self> {
        Ok(Self {
            top: source.read_i16::<BigEndian>()?,
            left: source.read_i16::<BigEndian>()?,
            bottom: source.read_i16::<BigEndian>()?,
            right: source.read_i16::<BigEndian>()?,
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct FileInfo {
    pub fileType: u32,
    pub fileCreator: u32,
    pub finderFlags: u16,
    pub location: Point,
    pub reservedField: u16,
}
impl FileInfo {
    pub fn import(source: &mut dyn Read) -> io::Result<Self> {
        Ok(Self {
            fileType: source.read_u32::<BigEndian>()?,
            fileCreator: source.read_u32::<BigEndian>()?,
            finderFlags: source.read_u16::<BigEndian>()?,
            location: Point::import(source)?,
            reservedField: source.read_u16::<BigEndian>()?,
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ExtendedFileInfo {
    pub reserved1: [i16; 4],
    pub extendedFinderFlags: u16,
    pub reserved2: i16,
    pub putAwayFolderID: i32,
}
impl ExtendedFileInfo {
    pub fn import(source: &mut dyn Read) -> io::Result<Self> {
        Ok(Self {
            reserved1: [
                source.read_i16::<BigEndian>()?,
                source.read_i16::<BigEndian>()?,
                source.read_i16::<BigEndian>()?,
                source.read_i16::<BigEndian>()?,
            ],
            extendedFinderFlags: source.read_u16::<BigEndian>()?,
            reserved2: source.read_i16::<BigEndian>()?,
            putAwayFolderID: source.read_i32::<BigEndian>()?,
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct FolderInfo {
    pub windowBounds: Rect,
    pub finderFlags: u16,
    pub location: Point,
    pub reservedField: u16,
}
impl FolderInfo {
    pub fn import(source: &mut dyn Read) -> io::Result<Self> {
        Ok(Self {
            windowBounds: Rect::import(source)?,
            finderFlags: source.read_u16::<BigEndian>()?,
            location: Point::import(source)?,
            reservedField: source.read_u16::<BigEndian>()?,
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ExtendedFolderInfo {
    pub scrollPosition: Point,
    pub reserved1: i32,
    pub extendedFinderFlags: u16,
    pub reserved2: i16,
    pub putAwayFolderID: i32,
}
impl ExtendedFolderInfo {
    pub fn import(source: &mut dyn Read) -> io::Result<Self> {
        Ok(Self {
            scrollPosition: Point::import(source)?,
            reserved1: source.read_i32::<BigEndian>()?,
            extendedFinderFlags: source.read_u16::<BigEndian>()?,
            reserved2: source.read_i16::<BigEndian>()?,
            putAwayFolderID: source.read_i32::<BigEndian>()?,
        })
    }
}

#[derive(Debug)]
pub struct HFSPlusExtentKey {
    pub keyLength: u16,
    pub forkType: u8,
    pub pad: u8,
    pub fileID: u32,
    pub startBlock: u32,
}
impl HFSPlusExtentKey {
    pub fn import(source: &mut dyn Read) -> io::Result<Self> {
        Ok(Self {
            keyLength: source.read_u16::<BigEndian>()?,
            forkType: source.read_u8()?,
            pad: source.read_u8()?,
            fileID: source.read_u32::<BigEndian>()?,
            startBlock: source.read_u32::<BigEndian>()?,
        })
    }
    pub fn export(&self, source: &mut dyn Write) -> io::Result<()> {
        source.write_u16::<BigEndian>(self.keyLength)?;
        source.write_u8(self.forkType)?;
        source.write_u8(self.pad)?;
        source.write_u32::<BigEndian>(self.fileID)?;
        source.write_u32::<BigEndian>(self.startBlock)?;
        Ok(())
    }
}
