//! Virtio-blk driver using PCI transport for QEMU virt machine

use crate::block::BlockReader;
use crate::kprintln;
use alloc::vec;
use alloc::vec::Vec;
use core::arch::asm;
use core::ptr::{read_volatile, write_volatile};
use spin::Mutex;

/// Clean cache range for DMA
fn cache_clean_range(addr: usize, len: usize) {
    let mut curr = addr & !63;
    let end = addr + len;
    while curr < end {
        unsafe {
            asm!("dc cvac, {0}", in(reg) curr);
        }
        curr += 64;
    }
    unsafe {
        asm!("dsb sy");
    }
}

fn cache_invalidate_range(addr: usize, len: usize) {
    let mut curr = addr & !63;
    let end = addr + len;
    while curr < end {
        unsafe {
            asm!("dc ivac, {0}", in(reg) curr);
        }
        curr += 64;
    }
    unsafe {
        asm!("dsb sy");
    }
}

// QEMU virt PCI ECAM base address (mapped to 0x40_1000_0000 physical)
const PCI_ECAM_BASE: usize = 0x2000_0000;

// PCI config space offsets
const PCI_VENDOR_ID: usize = 0x00;
const PCI_DEVICE_ID: usize = 0x02;
const PCI_COMMAND: usize = 0x04;
const PCI_STATUS: usize = 0x06;
const PCI_BAR0: usize = 0x10;
const PCI_CAP_PTR: usize = 0x34;

// Virtio PCI capability types
const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;

// Virtio PCI common configuration offsets
const VIRTIO_PCI_COMMON_GFSELECT: usize = 0x08;
const VIRTIO_PCI_COMMON_GF: usize = 0x0c;
const VIRTIO_PCI_COMMON_STATUS: usize = 0x14;
const VIRTIO_PCI_COMMON_Q_SELECT: usize = 0x16;
const VIRTIO_PCI_COMMON_Q_SIZE: usize = 0x18;
const VIRTIO_PCI_COMMON_Q_NOTIFY_OFF: usize = 0x1e;
const VIRTIO_PCI_COMMON_Q_ENABLE: usize = 0x1c;
const VIRTIO_PCI_COMMON_Q_DESCLO: usize = 0x20;
const VIRTIO_PCI_COMMON_Q_AVAILLO: usize = 0x28;
const VIRTIO_PCI_COMMON_Q_USEDLO: usize = 0x30;

// Virtio feature bits
const VIRTIO_F_VERSION_1: u32 = 1 << 0;

// Virtio status bits
const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
const VIRTIO_STATUS_DRIVER: u8 = 2;
const VIRTIO_STATUS_FEATURES_OK: u8 = 8;
const VIRTIO_STATUS_DRIVER_OK: u8 = 4;

const VIRTIO_BLK_T_IN: u32 = 0;
const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

const QUEUE_SIZE: usize = 16;

const VIRTIO_VENDOR_ID: u16 = 0x1af4;
const VIRTIO_BLK_DEVICE_ID_LEGACY: u16 = 0x1001;
const VIRTIO_BLK_DEVICE_ID_MODERN: u16 = 0x1042;

#[repr(C)]
struct VirtqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C)]
struct VirtqAvail {
    flags: u16,
    idx: u16,
    ring: [u16; QUEUE_SIZE],
}

#[repr(C)]
struct VirtqUsedElem {
    id: u32,
    len: u32,
}

#[repr(C)]
struct VirtqUsed {
    flags: u16,
    idx: u16,
    ring: [VirtqUsedElem; QUEUE_SIZE],
}

#[repr(C)]
struct VirtioBlkReq {
    req_type: u32,
    reserved: u32,
    sector: u64,
}

pub struct VirtioBlk {
    notify_addr: usize,
    desc: *mut VirtqDesc,
    avail: *mut VirtqAvail,
    used: *mut VirtqUsed,
    last_used_idx: u16,
    req_buf: *mut VirtioBlkReq,
    status_buf: *mut u8,
    next_desc_idx: u16,
}

unsafe impl Send for VirtioBlk {}

fn pci_config_addr(bus: u8, dev: u8, func: u8, offset: usize) -> usize {
    PCI_ECAM_BASE
        + ((bus as usize) << 20)
        + ((dev as usize) << 15)
        + ((func as usize) << 12)
        + offset
}

fn pci_read16(bus: u8, dev: u8, func: u8, offset: usize) -> u16 {
    unsafe { read_volatile(pci_config_addr(bus, dev, func, offset) as *const u16) }
}

fn pci_read32(bus: u8, dev: u8, func: u8, offset: usize) -> u32 {
    unsafe { read_volatile(pci_config_addr(bus, dev, func, offset) as *const u32) }
}

fn pci_write16(bus: u8, dev: u8, func: u8, offset: usize, val: u16) {
    unsafe { write_volatile(pci_config_addr(bus, dev, func, offset) as *mut u16, val) }
}

fn pci_read8(bus: u8, dev: u8, func: u8, offset: usize) -> u8 {
    unsafe { read_volatile(pci_config_addr(bus, dev, func, offset) as *const u8) }
}

fn pci_write32(bus: u8, dev: u8, func: u8, offset: usize, val: u32) {
    unsafe { write_volatile(pci_config_addr(bus, dev, func, offset) as *mut u32, val) }
}

struct VirtioCaps {
    common_cfg_bar: u8,
    common_cfg_offset: u32,
    notify_bar: u8,
    notify_offset: u32,
    notify_off_mult: u32,
}

fn find_virtio_caps(bus: u8, dev: u8, func: u8) -> Option<VirtioCaps> {
    let status_cmd = pci_read32(bus, dev, func, PCI_COMMAND);
    let status = (status_cmd >> 16) as u16;
    if (status & 0x10) == 0 {
        return None;
    }

    let mut cap_ptr = pci_read8(bus, dev, func, PCI_CAP_PTR) as usize;
    let mut caps = VirtioCaps {
        common_cfg_bar: 0,
        common_cfg_offset: 0,
        notify_bar: 0,
        notify_offset: 0,
        notify_off_mult: 0,
    };

    while cap_ptr != 0 {
        let cap_id = pci_read8(bus, dev, func, cap_ptr);
        if cap_id == 0x09 {
            let cfg_type = pci_read8(bus, dev, func, cap_ptr + 3);
            let bar = pci_read8(bus, dev, func, cap_ptr + 4);
            let offset = pci_read32(bus, dev, func, cap_ptr + 8);
            match cfg_type {
                VIRTIO_PCI_CAP_COMMON_CFG => {
                    caps.common_cfg_bar = bar;
                    caps.common_cfg_offset = offset;
                }
                VIRTIO_PCI_CAP_NOTIFY_CFG => {
                    caps.notify_bar = bar;
                    caps.notify_offset = offset;
                    caps.notify_off_mult = pci_read32(bus, dev, func, cap_ptr + 16);
                }
                _ => {}
            }
        }
        cap_ptr = pci_read8(bus, dev, func, cap_ptr + 1) as usize;
    }
    Some(caps)
}

static mut PCI_MMIO_ALLOC_NEXT: u32 = 0x1000_0000;

fn pci_assign_bar(bus: u8, dev: u8, func: u8, bar_num: u8) -> u32 {
    let bar_offset = PCI_BAR0 + (bar_num as usize) * 4;
    let current = pci_read32(bus, dev, func, bar_offset);
    if (current & !0xF) != 0 {
        return current & !0xF;
    }
    pci_write32(bus, dev, func, bar_offset, 0xFFFFFFFF);
    let size_mask = pci_read32(bus, dev, func, bar_offset);
    if size_mask == 0 || size_mask == 0xFFFFFFFF {
        return 0;
    }
    let size = !(size_mask & !0xF) + 1;
    unsafe {
        let aligned = (PCI_MMIO_ALLOC_NEXT + size - 1) & !(size - 1);
        pci_write32(bus, dev, func, bar_offset, aligned);
        PCI_MMIO_ALLOC_NEXT = aligned + size;
        aligned
    }
}

fn scan_pci() -> Option<(u8, u8, u8, VirtioCaps)> {
    kprintln!("Virtio: Scanning PCI bus...");
    for dev in 0..32 {
        let id_val = pci_read32(0, dev, 0, PCI_VENDOR_ID);
        let vendor = (id_val & 0xFFFF) as u16;
        let device = (id_val >> 16) as u16;

        if vendor == 0xFFFF {
            continue;
        }
        kprintln!(
            "PCI: Found device {:04x}:{:04x} at 0:{}:0",
            vendor,
            device,
            dev
        );
        if vendor == VIRTIO_VENDOR_ID
            && (device == VIRTIO_BLK_DEVICE_ID_LEGACY || device == VIRTIO_BLK_DEVICE_ID_MODERN)
        {
            kprintln!("Virtio: Found blk device, enabling...");
            let cmd_status = pci_read32(0, dev, 0, PCI_COMMAND);
            let cmd = (cmd_status & 0xFFFF) as u16;
            pci_write16(0, dev, 0, PCI_COMMAND, cmd | 0x06);
            if let Some(caps) = find_virtio_caps(0, dev, 0) {
                pci_assign_bar(0, dev, 0, caps.common_cfg_bar);
                if caps.notify_bar != caps.common_cfg_bar {
                    pci_assign_bar(0, dev, 0, caps.notify_bar);
                }
                return Some((0, dev, 0, caps));
            }
        }
    }
    None
}

impl VirtioBlk {
    pub fn new() -> Option<Self> {
        let (bus, dev, func, caps) = scan_pci()?;
        kprintln!("Virtio: Blk device configured, BARs assigned");
        let bar_offset = PCI_BAR0 + (caps.common_cfg_bar as usize) * 4;
        let bar = pci_read32(bus, dev, func, bar_offset) & !0xF;
        if bar == 0 {
            return None;
        }
        kprintln!("Virtio: BAR at {:x}", bar);
        let common_cfg = bar as usize + caps.common_cfg_offset as usize;
        let notify_cap_base = bar as usize + caps.notify_offset as usize;

        unsafe {
            write_volatile((common_cfg + VIRTIO_PCI_COMMON_STATUS) as *mut u8, 0);
            let mut status = VIRTIO_STATUS_ACKNOWLEDGE;
            write_volatile((common_cfg + VIRTIO_PCI_COMMON_STATUS) as *mut u8, status);
            status |= VIRTIO_STATUS_DRIVER;
            write_volatile((common_cfg + VIRTIO_PCI_COMMON_STATUS) as *mut u8, status);
            kprintln!("Virtio: Status set to DRIVER");
            write_volatile((common_cfg + VIRTIO_PCI_COMMON_GFSELECT) as *mut u32, 1);
            write_volatile(
                (common_cfg + VIRTIO_PCI_COMMON_GF) as *mut u32,
                VIRTIO_F_VERSION_1,
            );
            status |= VIRTIO_STATUS_FEATURES_OK;
            write_volatile((common_cfg + VIRTIO_PCI_COMMON_STATUS) as *mut u8, status);

            // Check status
            let check = read_volatile((common_cfg + VIRTIO_PCI_COMMON_STATUS) as *const u8);
            if (check & VIRTIO_STATUS_FEATURES_OK) == 0 {
                kprintln!("Virtio: Features NOT OK ({:x})", check);
                return None;
            }
            kprintln!("Virtio: Features OK");

            write_volatile((common_cfg + VIRTIO_PCI_COMMON_Q_SELECT) as *mut u16, 0);
            write_volatile(
                (common_cfg + VIRTIO_PCI_COMMON_Q_SIZE) as *mut u16,
                QUEUE_SIZE as u16,
            );
            let queue_notify_off =
                read_volatile((common_cfg + VIRTIO_PCI_COMMON_Q_NOTIFY_OFF) as *const u16);
            let notify_addr =
                notify_cap_base + (queue_notify_off as usize) * (caps.notify_off_mult as usize);

            let desc_size = core::mem::size_of::<VirtqDesc>() * QUEUE_SIZE;
            let avail_size = core::mem::size_of::<VirtqAvail>();
            let used_size = core::mem::size_of::<VirtqUsed>();
            let total = desc_size + avail_size + used_size + 4096;
            let queue_mem: Vec<u8> = alloc::vec![0u8; total + 4096];
            let ptr = queue_mem.as_ptr() as usize;
            let aligned = (ptr + 4095) & !4095;
            core::mem::forget(queue_mem);

            let desc = aligned as *mut VirtqDesc;
            let avail = (aligned + desc_size) as *mut VirtqAvail;
            let used = (aligned + desc_size + avail_size) as *mut VirtqUsed;

            write_volatile(
                (common_cfg + VIRTIO_PCI_COMMON_Q_DESCLO) as *mut u32,
                aligned as u32,
            );
            write_volatile(
                (common_cfg + VIRTIO_PCI_COMMON_Q_AVAILLO) as *mut u32,
                (aligned + desc_size) as u32,
            );
            write_volatile(
                (common_cfg + VIRTIO_PCI_COMMON_Q_USEDLO) as *mut u32,
                (aligned + desc_size + avail_size) as u32,
            );
            write_volatile((common_cfg + VIRTIO_PCI_COMMON_Q_ENABLE) as *mut u16, 1);
            status |= VIRTIO_STATUS_DRIVER_OK;
            write_volatile((common_cfg + VIRTIO_PCI_COMMON_STATUS) as *mut u8, status);

            let req_layout =
                alloc::alloc::Layout::from_size_align(core::mem::size_of::<VirtioBlkReq>(), 16)
                    .unwrap();
            let req_buf = alloc::alloc::alloc(req_layout) as *mut VirtioBlkReq;
            let status_layout = alloc::alloc::Layout::from_size_align(4, 4).unwrap();
            let status_buf = alloc::alloc::alloc(status_layout);

            kprintln!("Virtio: Blk device ready");

            Some(Self {
                notify_addr,
                desc,
                avail,
                used,
                last_used_idx: 0,
                req_buf,
                status_buf,
                next_desc_idx: 0,
            })
        }
    }

    fn allocate_desc(&mut self) -> u16 {
        let idx = self.next_desc_idx;
        self.next_desc_idx = (self.next_desc_idx + 1) % QUEUE_SIZE as u16;
        idx
    }

    pub fn read_sectors(&mut self, sector: u64, buf: &mut [u8]) -> bool {
        // kprintln!("Virtio: read_sectors sector={} len={}", sector, buf.len());
        if !buf.len().is_multiple_of(512) {
            return false;
        }
        let req = VirtioBlkReq {
            req_type: VIRTIO_BLK_T_IN,
            reserved: 0,
            sector,
        };
        unsafe {
            core::ptr::write(self.req_buf, req);
            *self.status_buf = 0xFF;
            let h = self.allocate_desc();
            let d = self.allocate_desc();
            let s = self.allocate_desc();
            (*self.desc.add(h as usize)) = VirtqDesc {
                addr: self.req_buf as u64,
                len: core::mem::size_of::<VirtioBlkReq>() as u32,
                flags: VIRTQ_DESC_F_NEXT,
                next: d,
            };
            (*self.desc.add(d as usize)) = VirtqDesc {
                addr: buf.as_ptr() as u64,
                len: buf.len() as u32,
                flags: VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE,
                next: s,
            };
            (*self.desc.add(s as usize)) = VirtqDesc {
                addr: self.status_buf as u64,
                len: 1,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            };
            cache_clean_range(self.req_buf as usize, 16);
            cache_clean_range(self.desc as usize, 512);
            cache_invalidate_range(buf.as_ptr() as usize, buf.len());
            let a_idx = (*self.avail).idx;
            (*self.avail).ring[(a_idx % QUEUE_SIZE as u16) as usize] = h;
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            (*self.avail).idx = a_idx.wrapping_add(1);
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            write_volatile(self.notify_addr as *mut u16, 0);
            let mut count = 0;
            while (*self.used).idx == self.last_used_idx {
                core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
                cache_invalidate_range(core::ptr::addr_of!((*self.used).idx) as usize, 2);
                count += 1;
                if count > 1000000 {
                    return false;
                }
            }
            self.last_used_idx = (*self.used).idx;
            cache_invalidate_range(buf.as_ptr() as usize, buf.len());
            // kprintln!("Virtio: read_sectors complete");
            *self.status_buf == 0
        }
    }
}

impl BlockReader for Mutex<VirtioBlk> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> bool {
        let mut blk = self.lock();
        let start_sector = offset / 512;
        if offset.is_multiple_of(512) && buf.len().is_multiple_of(512) {
            return blk.read_sectors(start_sector, buf);
        }
        let end_sector = (offset + buf.len() as u64).div_ceil(512);
        let mut temp = vec![0u8; ((end_sector - start_sector) * 512) as usize];
        if blk.read_sectors(start_sector, &mut temp) {
            let off = (offset % 512) as usize;
            buf.copy_from_slice(&temp[off..off + buf.len()]);
            true
        } else {
            false
        }
    }
}

pub fn init() -> Option<VirtioBlk> {
    VirtioBlk::new()
}
