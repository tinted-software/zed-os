#![no_std]
#![no_main]

// Enable alloc crate
extern crate alloc;

mod binary_loader;
mod block;
mod heap;
mod hfsfs;
mod ipc;
mod mem;
mod mmu;
mod process;
mod scheduler;
mod uart;
mod vfs;
mod virtio;
mod zalloc;

use crate::scheduler::{Process, SCHEDULER};
use alloc::string::String;
use core::arch::asm;
use core::arch::global_asm;
use core::panic::PanicInfo;

global_asm!(include_str!("boot.s"));
global_asm!(include_str!("vectors.s"));
global_asm!(include_str!("switch.s"));

#[unsafe(no_mangle)]
pub extern "C" fn kmain() {
    kprintln!("Hello from GravityOS (fixed 2). Spawning AArch64 processes...");

    process::init_vectors();

    mmu::init();

    unsafe extern "C" {
        static _end: u8;
    }

    let kernel_end = unsafe { &_end as *const u8 as u64 };
    let heap_start = (kernel_end + 0x1FFFFF) & !0x1FFFFF; // Align to 2MB
    let heap_end = 0x7F00_0000u64; // Leave 16MB for stack at the top of 1GB RAM
    let heap_size = (heap_end - heap_start) as usize;

    heap::init_heap(heap_start, heap_size);

    kprintln!("Heap initialized");

    kprintln!("Vectors initialized");

    if let Some(blk) = virtio::init() {
        kprintln!("Initializing VFS from disk...");
        let blk_shared = alloc::sync::Arc::new(spin::Mutex::new(blk));

        let wrapper = block::DeviceWrapper::new(
            alloc::sync::Arc::clone(&blk_shared) as alloc::sync::Arc<dyn block::BlockReader>,
            0,
        );
        let buffered = block::BufReader::with_capacity(128 * 1024, wrapper);

        let hfsfs = if let Ok(dmg) = apple_dmg::DmgReader::new(buffered) {
            kprintln!(
                "Found Apple DMG ({} partitions)",
                dmg.plist().partitions().len()
            );
            let mut hfs_part_idx = None;
            for (idx, part) in dmg.plist().partitions().iter().enumerate() {
                if part.name.contains("Apple_HFS")
                    || part.name.contains("Customer Software")
                    || part.name.contains("HFS")
                {
                    hfs_part_idx = Some(idx);
                    break;
                }
            }

            let idx = hfs_part_idx.unwrap_or(dmg.plist().partitions().len() - 1);
            kprintln!(
                "Using partition {} ('{}')",
                idx,
                dmg.plist().partitions()[idx].name
            );

            let part_reader = dmg
                .into_partition_reader(idx)
                .expect("Failed to create partition reader");
            hfsfs::HfsFs::new_from_reader(alloc::boxed::Box::new(part_reader))
        } else {
            kprintln!("No DMG found, falling back to raw HFS+ at 400MB");
            hfsfs::HfsFs::new(blk_shared, 400 * 1024 * 1024)
        };

        vfs::init(alloc::boxed::Box::new(hfsfs));
        kprintln!("VFS initialized");
        load_and_map_shared_cache();
    } else {
        kprintln!("No virtio disk found");
    }

    // Note: 0x40000000 seems to be used by dyld for CommPage or similar absolute reference.
    let load_offset = 0x3FFF_F000;
    kprintln!("Using load_offset: {:x}", load_offset);

    // Populate CommPage (0xFFFF0000) with shared cache address (0x30000000)
    unsafe {
        crate::mmu::COMMPAGE_STORAGE[0] = b'c';
        crate::mmu::COMMPAGE_STORAGE[1] = b'o';
        crate::mmu::COMMPAGE_STORAGE[2] = b'm';
        crate::mmu::COMMPAGE_STORAGE[3] = b'm';

        let version_ptr = &mut crate::mmu::COMMPAGE_STORAGE[0x1E] as *mut u8 as *mut u16;
        *version_ptr = 13;

        crate::mmu::COMMPAGE_STORAGE[0x22] = 1;

        let pgsize_ptr = &mut crate::mmu::COMMPAGE_STORAGE[0x24] as *mut u8 as *mut u32;
        *pgsize_ptr = 4096;

        let sc_addr = 0x3000_0000u32;
        for offset in [0x28, 0x38, 0x68, 0x70, 0x88, 0x90] {
            let sc_ptr = &mut crate::mmu::COMMPAGE_STORAGE[offset] as *mut u8 as *mut u32;
            *sc_ptr = sc_addr;
        }

        kprintln!(
            "Populated CommPage at 0xffff0000 with SC address {:x} at multiple offsets",
            sc_addr
        );
    }

    kprintln!("Opening /sbin/launchd...");
    let main_bin = {
        let mut file = vfs::open("/sbin/launchd").expect("Failed to open launchd");
        kprintln!("Reading /sbin/launchd ({} bytes)...", file.size());
        file.read_to_end()
    };

    // Try to load dyld from VFS first (the 32-bit one from rootfs),
    // fallback to embedded 64-bit rust dyld if not found or if needed.
    let mut dyld_bin = None;
    if let Some(mut file) = vfs::open("/usr/lib/dyld") {
        kprintln!("Found system dyld at /usr/lib/dyld (size {})", file.size());
        dyld_bin = Some(file.read_to_end());
    }

    let dyld_bin = dyld_bin.expect("Failed to load dyld");

    kprintln!("Parsing Mach-O binaries...");

    // Check if main binary is PIE and needs to be slid
    let mut main_load_offset = 0;

    // Temporary load to check flags
    if let Some(temp_loader) = binary_loader::BinaryLoader::load(&main_bin, 0) {
        if (temp_loader.flags & 0x200000) != 0 {
            // MH_PIE
            kprintln!("Main binary is PIE. Sliding to 0x40000000 to avoid Page Zero.");
            main_load_offset = 0x40000000;
        } else {
            kprintln!("Main binary is NOT PIE. Loading at 0.");
        }
    }

    let main_loader = binary_loader::BinaryLoader::load(&main_bin, main_load_offset);
    if let Some(loader) = main_loader {
        let mut loader_is_64bit = loader.is_64bit;
        let (entry, path, dyld_mh, main_mh, _dyld_slide) = if let Some(dyld_path) = loader.dylinker
        {
            kprintln!("Binary requests dylinker: {}", dyld_path);
            let dyld_load_offset = 0;
            let dyld_loader = binary_loader::BinaryLoader::load(&dyld_bin, dyld_load_offset)
                .expect("Failed to load dyld");
            loader_is_64bit = dyld_loader.is_64bit;
            (
                dyld_loader.entry,
                String::from("/sbin/launchd"),
                dyld_loader.header_addr,
                loader.header_addr,
                0,
            )
        } else {
            (
                loader.entry + main_load_offset,
                String::from("/sbin/launchd"),
                loader.header_addr,
                loader.header_addr,
                0,
            )
        };

        let (user_stack_base, user_sp_initial, user_stack_size) = {
            let size = 1024 * 1024;
            // Move stack to 0x20000000 (512MB)
            let stack_addr = 0x20000000u64;
            let layout = core::alloc::Layout::from_size_align(size, 4096).unwrap();
            let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
            if ptr.is_null() {
                panic!("Failed to allocate stack");
            }
            // Use ptr as backing, but map to stack_addr
            let paddr = ptr as u64;
            (stack_addr, stack_addr + size as u64, size)
        };
        // Allocate physical memory for stack and map it
        {
            let layout = core::alloc::Layout::from_size_align(user_stack_size, 4096).unwrap();
            let phys_ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
            if phys_ptr.is_null() {
                panic!("Failed to allocate physical stack");
            }
            crate::mmu::map_range(
                user_stack_base,
                phys_ptr as u64,
                user_stack_size as u64,
                crate::mmu::MapPermission::UserRW,
            );
        }

        // HACK: dyld accesses 5 * SP. Map it.
        let mystery_addr = user_stack_base * 5;
        kprintln!("Mapping mystery region at {:x}...", mystery_addr);
        {
            // Map 16MB to be safe (FAR was at ~5MB offset) we use 2MB alignment for speed
            let size = 16 * 1024 * 1024;
            let layout = core::alloc::Layout::from_size_align(size, 0x200000).unwrap();
            let phys_ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
            crate::mmu::map_range(
                mystery_addr,
                phys_ptr as u64,
                size as u64,
                crate::mmu::MapPermission::UserRW,
            );
        }

        // Map Page Zero (0x0 - 0x10000) - 64KB to handle low jumps
        {
            let size = 64 * 1024;
            let layout = core::alloc::Layout::from_size_align(size, 4096).unwrap();
            let phys_ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };

            crate::mmu::map_range(
                0,
                phys_ptr as u64,
                size as u64,
                crate::mmu::MapPermission::UserRW,
            );
        }

        // Map Mystery Region 2 (0x08000000)
        // dyld accesses 0x0859454c.
        {
            let addr = 0x08000000;
            let size = 16 * 1024 * 1024;
            let layout = core::alloc::Layout::from_size_align(size, 0x200000).unwrap();
            let phys_ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
            crate::mmu::map_range(
                addr,
                phys_ptr as u64,
                size as u64,
                crate::mmu::MapPermission::UserRW,
            );
        }

        kprintln!("Initial User SP: {:x}", user_sp_initial);
        let new_sp = binary_loader::setup_stack(
            user_sp_initial,
            &path,
            dyld_mh,
            loader_is_64bit,
            0x30000000,
            main_mh,
        );
        kprintln!("Stack setup complete. New User SP: {:x}", new_sp);

        let args = if loader_is_64bit {
            [
                loader.header_addr,
                0,
                new_sp + 8,
                new_sp + 16,
                new_sp + 32,
                new_sp + 40,
            ]
        } else {
            // AArch32: sp points to argc.
            // macho::setup_stack handled the vector layout.
            // We just need to tell the thread to start with sp.
            // The registers r0, r1 etc are usually for specific dyld entry.
            // In modern dyld:
            // r0 = mach_header of main app? No, r0 is 0 usually.
            // sp points to argc.
            // Actually, if dyld is dynamic linker, kernel entry:
            // sp -> argc
            // But we are setting registers for Process::new.
            // Process::new sets x0...x7 from args array.
            // For dyld start:
            // x0 = 0
            // x1 = 0
            // x2 = 0
            // x3 = 0
            // sp = new_sp
            // So we need clear args.
            [0, 0, 0, 0, 0, 0]
        };

        let (tls_base, tls_size) = {
            let size = 4096;
            let layout = core::alloc::Layout::from_size_align(size, 4096).unwrap();
            let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
            if ptr.is_null() {
                panic!("Failed to allocate TLS");
            }
            (ptr as u64, size)
        };
        crate::mmu::map_range(
            tls_base,
            tls_base,
            tls_size as u64,
            crate::mmu::MapPermission::UserRW,
        );
        kprintln!("Mapped TLS at {:x}", tls_base);
        unsafe {
            core::ptr::write(tls_base as *mut u32, tls_base as u32);
        }

        let process = Process::new(entry, new_sp, &args, tls_base, loader_is_64bit);
        let pid = process.pid;

        let mut sched = SCHEDULER.lock();
        sched.add_process(process);
        sched.schedule_next();

        kprintln!(
            "Ready to switch to PID {} at {:x} (SP: {:x}, SPSR: {:x})",
            pid,
            entry,
            new_sp,
            sched.current_process.as_ref().unwrap().context.regs[8]
        );
    } else {
        panic!("Failed to parse MAIN_BIN");
    }

    kprintln!("Ready to switch context...");

    let mut boot_ctx = process::CpuContext::default();
    unsafe {
        let next_ctx_ptr = {
            let sched = SCHEDULER.lock();
            if let Some(curr) = &sched.current_process {
                &curr.context as *const _
            } else {
                kprintln!("No process to run! Hanging...");
                loop {
                    asm!("wfe");
                }
            }
        };

        kprintln!("Switching to first process...");
        unsafe extern "C" {
            fn __switch_to(prev: *mut process::CpuContext, next: *const process::CpuContext);
        }
        __switch_to(&mut boot_ctx, next_ctx_ptr);
    }

    loop {
        unsafe { asm!("wfe") };
    }
}

fn load_and_map_shared_cache() {
    let sc_paths = [
        "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_armv7",
        "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_armv6",
    ];

    let mut sc_file = None;
    for path in sc_paths {
        if let Some(file) = vfs::open(path) {
            kprintln!("Found shared cache at {}", path);
            sc_file = Some(file);
            break;
        }
    }

    let mut file = match sc_file {
        Some(f) => f,
        None => {
            kprintln!("Shared cache NOT found in HFS+ volume");
            return;
        }
    };

    let size = file.size();
    kprintln!("Shared cache size: {} bytes", size);

    // Read header for debug
    let mut header = [0u8; 128];
    file.read_at(0, &mut header);

    kprintln!("Shared cache header dump:");
    for i in 0..8 {
        let offset = i * 16;
        kprintln!(
            "  {:02x}: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
            offset,
            header[offset],
            header[offset + 1],
            header[offset + 2],
            header[offset + 3],
            header[offset + 4],
            header[offset + 5],
            header[offset + 6],
            header[offset + 7],
            header[offset + 8],
            header[offset + 9],
            header[offset + 10],
            header[offset + 11],
            header[offset + 12],
            header[offset + 13],
            header[offset + 14],
            header[offset + 15]
        );
    }

    if let Ok(magic) = core::str::from_utf8(&header[0..16]) {
        kprintln!("Shared cache header magic: {:?}", magic);
    }
    let base_addr = u64::from_le_bytes(header[32..40].try_into().unwrap_or([0; 8]));
    kprintln!("Shared cache expected base address: {:x}", base_addr);

    let mapping_offset = u32::from_le_bytes(header[16..20].try_into().unwrap_or([0; 4])) as u64;
    let mapping_count = u32::from_le_bytes(header[20..24].try_into().unwrap_or([0; 4])) as usize;
    kprintln!(
        "Shared cache mappings: count={} offset={:x}",
        mapping_count,
        mapping_offset
    );

    // Dump mappings
    let mut mapping_buf = [0u8; 32]; // Each mapping is 32 bytes
    for i in 0..mapping_count {
        file.read_at(mapping_offset + (i * 32) as u64, &mut mapping_buf);
        let address = u64::from_le_bytes(mapping_buf[0..8].try_into().unwrap());
        let size = u64::from_le_bytes(mapping_buf[8..16].try_into().unwrap());
        let file_offset = u64::from_le_bytes(mapping_buf[16..24].try_into().unwrap());
        kprintln!(
            "  Mapping {}: addr={:x} size={:x} file_off={:x}",
            i,
            address,
            size,
            file_offset
        );
    }

    // Allocate physical memory for shared cache from heap (must be page aligned)
    let alloc_size = (size as usize + 4095) & !4095;
    let layout = core::alloc::Layout::from_size_align(alloc_size, 4096).unwrap();
    let phys_ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
    if phys_ptr.is_null() {
        kprintln!("Failed to allocate memory for shared cache!");
        return;
    }

    kprintln!(
        "Loading shared cache into memory at {:x}...",
        phys_ptr as usize
    );
    let mut loaded = 0;
    while loaded < size as usize {
        let chunk_size = core::cmp::min(1024 * 1024, size as usize - loaded);
        let slice = unsafe { core::slice::from_raw_parts_mut(phys_ptr.add(loaded), chunk_size) };
        file.read(slice);
        loaded += chunk_size;
        if loaded % (50 * 1024 * 1024) == 0 {
            kprintln!("  Loaded {} MB...", loaded / 1024 / 1024);
        }
    }

    let sc_base = 0x3000_0000u64;
    kprintln!("Mapping shared cache to vaddr {:x}...", sc_base);
    crate::mmu::map_range(
        sc_base,
        phys_ptr as u64,
        alloc_size as u64,
        crate::mmu::MapPermission::UserRWX, // Initially RWX for dyld
    );
    kprintln!("Shared cache mapped successfully.");
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    kprintln!("Kernel Panic: {:?}", info);
    loop {
        unsafe { asm!("wfe") };
    }
}
