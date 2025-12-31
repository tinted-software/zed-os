//! Virtio-blk driver using PCI transport for QEMU virt machine
//!
//! QEMU virt machine PCI configuration:
//! - ECAM base: 0x3f000000 (256MB window)
//! - PCI MMIO: 0x10000000 - 0x3effffff
//! - PCI IO: 0x3eff0000 - 0x3effffff

use crate::kprintln;
use alloc::vec::Vec;
use core::arch::asm;
use core::ptr::{read_volatile, write_volatile};

/// Clean cache line to point of coherency (for DMA)
#[inline(always)]
fn cache_clean(addr: usize) {
    unsafe {
        asm!("dc cvac, {}", in(reg) addr, options(nostack, preserves_flags));
    }
}

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

// QEMU virt PCI ECAM base address
const PCI_ECAM_BASE: usize = 0x3f00_0000;

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
const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

// Virtio PCI common configuration offsets
const VIRTIO_PCI_COMMON_DFSELECT: usize = 0x00; // Device feature select
const VIRTIO_PCI_COMMON_DF: usize = 0x04; // Device features
const VIRTIO_PCI_COMMON_GFSELECT: usize = 0x08; // Guest feature select
const VIRTIO_PCI_COMMON_GF: usize = 0x0c; // Guest features
const VIRTIO_PCI_COMMON_STATUS: usize = 0x14;
const VIRTIO_PCI_COMMON_Q_SELECT: usize = 0x16;
const VIRTIO_PCI_COMMON_Q_SIZE: usize = 0x18;
const VIRTIO_PCI_COMMON_Q_NOTIFY_OFF: usize = 0x1e; // queue_notify_off - per-queue notify offset
const VIRTIO_PCI_COMMON_Q_ENABLE: usize = 0x1c;
const VIRTIO_PCI_COMMON_Q_DESCLO: usize = 0x20;
const VIRTIO_PCI_COMMON_Q_DESCHI: usize = 0x24;
const VIRTIO_PCI_COMMON_Q_AVAILLO: usize = 0x28;
const VIRTIO_PCI_COMMON_Q_AVAILHI: usize = 0x2c;
const VIRTIO_PCI_COMMON_Q_USEDLO: usize = 0x30;
const VIRTIO_PCI_COMMON_Q_USEDHI: usize = 0x34;

// Virtio feature bits
const VIRTIO_F_VERSION_1: u32 = 1 << 0; // Feature bit 32 in high word

// Virtio status bits
const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
const VIRTIO_STATUS_DRIVER: u8 = 2;
const VIRTIO_STATUS_FEATURES_OK: u8 = 8;
const VIRTIO_STATUS_DRIVER_OK: u8 = 4;

const VIRTIO_BLK_T_IN: u32 = 0;
const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

const QUEUE_SIZE: usize = 16;
const SECTOR_SIZE: usize = 512;

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
    common_cfg: usize,
    notify_addr: usize,
    desc: *mut VirtqDesc,
    avail: *mut VirtqAvail,
    used: *mut VirtqUsed,
    last_used_idx: u16,
    req_buf: *mut VirtioBlkReq,
    status_buf: *mut u8,
    next_desc_idx: u16,
}

/// Calculate ECAM config address for bus/device/function
fn pci_config_addr(bus: u8, dev: u8, func: u8, offset: usize) -> usize {
    PCI_ECAM_BASE
        + ((bus as usize) << 20)
        + ((dev as usize) << 15)
        + ((func as usize) << 12)
        + offset
}

/// Read 16-bit from PCI config space
fn pci_read16(bus: u8, dev: u8, func: u8, offset: usize) -> u16 {
    unsafe { read_volatile(pci_config_addr(bus, dev, func, offset) as *const u16) }
}

/// Read 32-bit from PCI config space
fn pci_read32(bus: u8, dev: u8, func: u8, offset: usize) -> u32 {
    unsafe { read_volatile(pci_config_addr(bus, dev, func, offset) as *const u32) }
}

/// Write 16-bit to PCI config space
fn pci_write16(bus: u8, dev: u8, func: u8, offset: usize, val: u16) {
    unsafe { write_volatile(pci_config_addr(bus, dev, func, offset) as *mut u16, val) }
}

/// Read 8-bit from PCI config space
fn pci_read8(bus: u8, dev: u8, func: u8, offset: usize) -> u8 {
    unsafe { read_volatile(pci_config_addr(bus, dev, func, offset) as *const u8) }
}

struct VirtioCaps {
    common_cfg_bar: u8,
    common_cfg_offset: u32,
    notify_bar: u8,
    notify_offset: u32,
    notify_off_mult: u32,
}

fn find_virtio_caps(bus: u8, dev: u8, func: u8) -> Option<VirtioCaps> {
    let status = pci_read16(bus, dev, func, PCI_STATUS);
    if (status & 0x10) == 0 {
        kprintln!("VirtIO PCI: No capabilities list");
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
            // Vendor specific - Virtio
            let cfg_type = pci_read8(bus, dev, func, cap_ptr + 3);
            let bar = pci_read8(bus, dev, func, cap_ptr + 4);
            let offset = pci_read32(bus, dev, func, cap_ptr + 8);

            match cfg_type {
                VIRTIO_PCI_CAP_COMMON_CFG => {
                    caps.common_cfg_bar = bar;
                    caps.common_cfg_offset = offset;
                    kprintln!("VirtIO: Common cfg at BAR{} offset {:x}", bar, offset);
                }
                VIRTIO_PCI_CAP_NOTIFY_CFG => {
                    caps.notify_bar = bar;
                    caps.notify_offset = offset;
                    caps.notify_off_mult = pci_read32(bus, dev, func, cap_ptr + 16);
                    kprintln!("VirtIO: Notify at BAR{} offset {:x}", bar, offset);
                }
                _ => {}
            }
        }

        cap_ptr = pci_read8(bus, dev, func, cap_ptr + 1) as usize;
    }

    Some(caps)
}

// PCI MMIO base for BAR assignment (QEMU virt PCI MMIO window)
const PCI_MMIO_ALLOC_BASE: u32 = 0x1000_0000;
static mut PCI_MMIO_ALLOC_NEXT: u32 = 0x1000_0000;

/// Write 32-bit to PCI config space
fn pci_write32(bus: u8, dev: u8, func: u8, offset: usize, val: u32) {
    unsafe { write_volatile(pci_config_addr(bus, dev, func, offset) as *mut u32, val) }
}

/// Assign BAR if not already configured
fn pci_assign_bar(bus: u8, dev: u8, func: u8, bar_num: u8) -> u32 {
    let bar_offset = PCI_BAR0 + (bar_num as usize) * 4;
    let current = pci_read32(bus, dev, func, bar_offset);

    if (current & !0xF) != 0 {
        return current & !0xF;
    }

    // Determine BAR size by writing all 1s and reading back
    pci_write32(bus, dev, func, bar_offset, 0xFFFFFFFF);
    let size_mask = pci_read32(bus, dev, func, bar_offset);

    if size_mask == 0 || size_mask == 0xFFFFFFFF {
        pci_write32(bus, dev, func, bar_offset, 0);
        return 0;
    }

    let size = !(size_mask & !0xF) + 1;

    // Allocate MMIO space (align to size)
    unsafe {
        let aligned = (PCI_MMIO_ALLOC_NEXT + size - 1) & !(size - 1);
        pci_write32(bus, dev, func, bar_offset, aligned);
        PCI_MMIO_ALLOC_NEXT = aligned + size;
        kprintln!(
            "PCI: Assigned BAR{} = {:08x} (size {:x})",
            bar_num,
            aligned,
            size
        );
        aligned
    }
}

fn scan_pci() -> Option<(u8, u8, u8, VirtioCaps)> {
    for dev in 0..32 {
        let vendor = pci_read16(0, dev, 0, PCI_VENDOR_ID);
        if vendor == 0xFFFF {
            continue;
        }

        let device = pci_read16(0, dev, 0, PCI_DEVICE_ID);
        kprintln!(
            "PCI {:02x}:00.0 vendor={:04x} device={:04x}",
            dev,
            vendor,
            device
        );

        if vendor == VIRTIO_VENDOR_ID
            && (device == VIRTIO_BLK_DEVICE_ID_LEGACY || device == VIRTIO_BLK_DEVICE_ID_MODERN)
        {
            kprintln!("VirtIO: Found block device at {:02x}:00.0", dev);

            // Enable MMIO and bus master
            let cmd = pci_read16(0, dev, 0, PCI_COMMAND);
            pci_write16(0, dev, 0, PCI_COMMAND, cmd | 0x06);

            if let Some(caps) = find_virtio_caps(0, dev, 0) {
                // Assign BARs that are needed
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
        kprintln!("VirtIO PCI: Scanning...");

        let (bus, dev, func, caps) = scan_pci()?;

        // Read the BAR that contains the virtio config (usually BAR4 for modern virtio)
        let bar_offset = PCI_BAR0 + (caps.common_cfg_bar as usize) * 4;
        let bar = pci_read32(bus, dev, func, bar_offset) & !0xF;
        kprintln!("VirtIO: BAR{} = {:08x}", caps.common_cfg_bar, bar);

        if bar == 0 {
            kprintln!(
                "VirtIO: BAR{} not configured, device may need initialization",
                caps.common_cfg_bar
            );
            return None;
        }

        let common_cfg = bar as usize + caps.common_cfg_offset as usize;
        // Notify base from capability - will add queue-specific offset after selecting queue
        let notify_cap_base = bar as usize + caps.notify_offset as usize;

        kprintln!(
            "VirtIO: Common cfg at {:x}, notify base at {:x}",
            common_cfg,
            notify_cap_base
        );

        unsafe {
            // Reset
            write_volatile((common_cfg + VIRTIO_PCI_COMMON_STATUS) as *mut u8, 0);

            // Acknowledge
            let mut status = VIRTIO_STATUS_ACKNOWLEDGE;
            write_volatile((common_cfg + VIRTIO_PCI_COMMON_STATUS) as *mut u8, status);

            // Driver
            status |= VIRTIO_STATUS_DRIVER;
            write_volatile((common_cfg + VIRTIO_PCI_COMMON_STATUS) as *mut u8, status);

            // Read device features (low 32 bits)
            write_volatile((common_cfg + VIRTIO_PCI_COMMON_DFSELECT) as *mut u32, 0);
            let features_lo = read_volatile((common_cfg + VIRTIO_PCI_COMMON_DF) as *const u32);

            // Read device features (high 32 bits, contains VIRTIO_F_VERSION_1)
            write_volatile((common_cfg + VIRTIO_PCI_COMMON_DFSELECT) as *mut u32, 1);
            let features_hi = read_volatile((common_cfg + VIRTIO_PCI_COMMON_DF) as *const u32);

            kprintln!(
                "VirtIO: Device features lo={:08x} hi={:08x}",
                features_lo,
                features_hi
            );

            // Accept VIRTIO_F_VERSION_1 (bit 32, which is bit 0 in high word)
            write_volatile((common_cfg + VIRTIO_PCI_COMMON_GFSELECT) as *mut u32, 0);
            write_volatile((common_cfg + VIRTIO_PCI_COMMON_GF) as *mut u32, 0); // No low features

            write_volatile((common_cfg + VIRTIO_PCI_COMMON_GFSELECT) as *mut u32, 1);
            write_volatile(
                (common_cfg + VIRTIO_PCI_COMMON_GF) as *mut u32,
                VIRTIO_F_VERSION_1,
            ); // Accept VERSION_1

            // Features OK
            status |= VIRTIO_STATUS_FEATURES_OK;
            write_volatile((common_cfg + VIRTIO_PCI_COMMON_STATUS) as *mut u8, status);

            // Check that features were accepted
            let status_check = read_volatile((common_cfg + VIRTIO_PCI_COMMON_STATUS) as *const u8);
            if (status_check & VIRTIO_STATUS_FEATURES_OK) == 0 {
                kprintln!("VirtIO: Features not accepted!");
                return None;
            }

            // Select queue 0
            write_volatile((common_cfg + VIRTIO_PCI_COMMON_Q_SELECT) as *mut u16, 0);

            let dev_queue_size =
                read_volatile((common_cfg + VIRTIO_PCI_COMMON_Q_SIZE) as *const u16);

            // Set queue size to our supported size (16)
            write_volatile(
                (common_cfg + VIRTIO_PCI_COMMON_Q_SIZE) as *mut u16,
                QUEUE_SIZE as u16,
            );

            // Read back to verify
            let actual_queue_size =
                read_volatile((common_cfg + VIRTIO_PCI_COMMON_Q_SIZE) as *const u16);

            // Read queue_notify_off for this queue to calculate actual notify address
            let queue_notify_off =
                read_volatile((common_cfg + VIRTIO_PCI_COMMON_Q_NOTIFY_OFF) as *const u16);

            // Calculate actual notify address: notify_base + queue_notify_off * notify_off_multiplier
            let notify_addr =
                notify_cap_base + (queue_notify_off as usize) * (caps.notify_off_mult as usize);

            kprintln!(
                "VirtIO: Dev size={}, Our size={}, notify_off={}, final notify addr={:x}",
                dev_queue_size,
                actual_queue_size,
                queue_notify_off,
                notify_addr
            );

            // Allocate queues (page aligned)
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

            // Set queue addresses
            write_volatile(
                (common_cfg + VIRTIO_PCI_COMMON_Q_DESCLO) as *mut u32,
                aligned as u32,
            );
            write_volatile((common_cfg + VIRTIO_PCI_COMMON_Q_DESCHI) as *mut u32, 0);
            write_volatile(
                (common_cfg + VIRTIO_PCI_COMMON_Q_AVAILLO) as *mut u32,
                (aligned + desc_size) as u32,
            );
            write_volatile((common_cfg + VIRTIO_PCI_COMMON_Q_AVAILHI) as *mut u32, 0);
            write_volatile(
                (common_cfg + VIRTIO_PCI_COMMON_Q_USEDLO) as *mut u32,
                (aligned + desc_size + avail_size) as u32,
            );
            write_volatile((common_cfg + VIRTIO_PCI_COMMON_Q_USEDHI) as *mut u32, 0);

            // Enable queue
            write_volatile((common_cfg + VIRTIO_PCI_COMMON_Q_ENABLE) as *mut u16, 1);

            // Ensure memory is visible before proceeding
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            cache_clean_range(aligned, total); // Flush entire queue region

            // Driver OK
            status |= VIRTIO_STATUS_DRIVER_OK;
            write_volatile((common_cfg + VIRTIO_PCI_COMMON_STATUS) as *mut u8, status);

            // Allocate request and status buffers (must be in DMA-able memory)
            // Use separate allocation to ensure alignment
            let req_layout =
                alloc::alloc::Layout::from_size_align(core::mem::size_of::<VirtioBlkReq>(), 16)
                    .unwrap();
            let req_buf = alloc::alloc::alloc(req_layout) as *mut VirtioBlkReq;

            let status_layout = alloc::alloc::Layout::from_size_align(4, 4).unwrap();
            let status_buf = alloc::alloc::alloc(status_layout);

            kprintln!(
                "VirtIO: desc={:x} avail={:x} used={:x}",
                desc as usize,
                avail as usize,
                used as usize
            );
            kprintln!(
                "VirtIO: req_buf={:x} status_buf={:x}",
                req_buf as usize,
                status_buf as usize
            );
            kprintln!("VirtIO: Block device ready");

            Some(Self {
                common_cfg,
                notify_addr,
                desc,
                avail,
                used,
                last_used_idx: 0,
                req_buf,
                status_buf,
                next_desc_idx: 0, // Initialize the new field
            })
        }
    }

    // New helper function to allocate a descriptor
    fn allocate_desc(&mut self) -> u16 {
        let idx = self.next_desc_idx;
        self.next_desc_idx = (self.next_desc_idx + 1) % QUEUE_SIZE as u16;
        idx
    }

    pub fn read_sectors(&mut self, sector: u64, buf: &mut [u8]) -> bool {
        if buf.len() % 512 != 0 {
            return false;
        }

        let total_sectors = buf.len() / 512;
        let mut sectors_read = 0;

        // Max sectors per request (limited by queue size/descriptors).
        // We have 3 descriptors per request (head, data, status).
        // Queue size is 16. So we can't do too many parallel, but we do synchronous.
        // But we can attach a large buffer to one descriptor?
        // VirtIO block supports arbitrary length.
        // Let's safe limit to 1MB per request (2048 sectors) or 64KB if cautious.
        // QEMU usually handles large requests fine.
        const SECTORS_PER_CHUNK: usize = 256; // 128KB per request

        while sectors_read < total_sectors {
            let chunk_sectors = core::cmp::min(SECTORS_PER_CHUNK, total_sectors - sectors_read);
            let chunk_size = chunk_sectors * 512;
            let offset = sectors_read * 512;

            // kprintln!("VirtIO: Reading sector {}/{} ({} sectors)", sector + sectors_read as u64, total_sectors, chunk_sectors);

            if !self.read_sector_chunk(
                sector + sectors_read as u64,
                &mut buf[offset..offset + chunk_size],
            ) {
                return false;
            }

            sectors_read += chunk_sectors;
        }

        true
    }

    fn read_sector_chunk(&mut self, sector: u64, buf: &mut [u8]) -> bool {
        let req = VirtioBlkReq {
            req_type: VIRTIO_BLK_T_IN, // Use VIRTIO_BLK_T_IN for read
            reserved: 0,
            sector,
        };

        // We need to keep req and status alive until device is done
        // In this synchronous implementation, it's fine.
        unsafe {
            core::ptr::write(self.req_buf, req);
            *self.status_buf = 0xFF; // Initialize status to non-zero
        }

        let head_idx = self.allocate_desc();
        if head_idx >= QUEUE_SIZE as u16 {
            // Compare with u16
            kprintln!("VirtIO: Failed to allocate head descriptor");
            return false;
        }

        let data_idx = self.allocate_desc();
        if data_idx >= QUEUE_SIZE as u16 {
            // Compare with u16
            kprintln!("VirtIO: Failed to allocate data descriptor");
            return false;
        }

        let status_idx = self.allocate_desc();
        if status_idx >= QUEUE_SIZE as u16 {
            // Compare with u16
            kprintln!("VirtIO: Failed to allocate status descriptor");
            return false;
        }

        unsafe {
            // Descriptor 1: Request Header (Read-only for device)
            (*self.desc.add(head_idx as usize)) = VirtqDesc {
                addr: self.req_buf as u64,
                len: core::mem::size_of::<VirtioBlkReq>() as u32,
                flags: VIRTQ_DESC_F_NEXT,
                next: data_idx,
            };

            // Descriptor 2: Data Buffer (Write-only for device)
            (*self.desc.add(data_idx as usize)) = VirtqDesc {
                addr: buf.as_ptr() as u64,
                len: buf.len() as u32,
                flags: VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE,
                next: status_idx,
            };

            // Descriptor 3: Status (Write-only for device)
            (*self.desc.add(status_idx as usize)) = VirtqDesc {
                addr: self.status_buf as u64,
                len: 1,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            };

            // Flush cache for all DMA buffers before notifying device
            cache_clean_range(self.req_buf as usize, core::mem::size_of::<VirtioBlkReq>());
            cache_clean_range(
                self.desc.add(head_idx as usize) as usize,
                core::mem::size_of::<VirtqDesc>(),
            );
            cache_clean_range(
                self.desc.add(data_idx as usize) as usize,
                core::mem::size_of::<VirtqDesc>(),
            );
            cache_clean_range(
                self.desc.add(status_idx as usize) as usize,
                core::mem::size_of::<VirtqDesc>(),
            );
            // Also invalidate the data buffer to ensure device can write to it cleanly
            cache_invalidate_range(buf.as_ptr() as usize, buf.len());
            cache_invalidate_range(self.status_buf as usize, 1);

            // Add to Available Ring
            let avail_idx = (*self.avail).idx;
            (*self.avail).ring[(avail_idx % QUEUE_SIZE as u16) as usize] = head_idx;

            // Memory barrier
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

            (*self.avail).idx = avail_idx.wrapping_add(1);

            // Notify device
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            write_volatile(self.notify_addr as *mut u16, 0); // Queue 0

            // Wait for completion (busy wait)
            let mut count = 0;
            loop {
                core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
                // Ensure we see the latest value from RAM
                cache_invalidate_range(core::ptr::addr_of!((*self.used).idx) as usize, 2);
                if (*self.used).idx != self.last_used_idx {
                    break;
                }
                count += 1;
                if count > 10000000 {
                    kprintln!(
                        "VirtIO: Timeout waiting for used idx! (last_used={}, current={})",
                        self.last_used_idx,
                        (*self.used).idx
                    );
                    return false;
                }
            }
            self.last_used_idx = (*self.used).idx;

            // Invalidate again after device write to ensure we read fresh data
            cache_invalidate_range(buf.as_ptr() as usize, SECTOR_SIZE);
            cache_invalidate_range(self.status_buf as usize, 1);

            if *self.status_buf != 0 {
                return false;
            }
            *self.status_buf == 0
        }
    }
}

pub fn init() -> Option<VirtioBlk> {
    VirtioBlk::new()
}
