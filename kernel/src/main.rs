#![no_std]
#![no_main]

// Enable alloc crate
extern crate alloc;

mod elf;
mod heap;
mod macho;
mod mmu;
mod process;
mod scheduler;
mod tarfs;
mod uart;
mod vfs;
mod virtio;

use crate::scheduler::{Process, SCHEDULER};
use alloc::string::String;
use alloc::vec;
use core::arch::asm;
use core::arch::global_asm;
use core::panic::PanicInfo;

global_asm!(include_str!("boot.s"));
global_asm!(include_str!("vectors.s"));
global_asm!(include_str!("switch.s"));

// static USER_PROGRAM: &[u8] =
// include_bytes!("../../target/aarch64-unknown-none-softfloat/release/user");

#[unsafe(no_mangle)]
pub extern "C" fn kmain() {
    kprintln!("Hello from GravityOS. Spawning iOS 5 ARMv7 processes...");

    process::init_vectors();

    mmu::init();

    heap::init_heap();

    kprintln!("Vectors initialized");

    // Initialize virtio block device and load shared cache
    let mut shared_cache_data: &[u8] = &[];

    if let Some(mut blk) = virtio::init() {
        kprintln!("Loading shared cache from disk...");

        // Shared cache is at sector 0, ~200MB (actual is ~190MB)
        const SHARED_CACHE_SIZE: usize = 200 * 1024 * 1024;

        const SHARED_CACHE_SECTORS: usize = SHARED_CACHE_SIZE / 512;

        // Allocate page-aligned buffer (4KB alignment) to ensure correct MMU mapping
        use alloc::alloc::{Layout, alloc_zeroed};
        let layout = Layout::from_size_align(SHARED_CACHE_SIZE, 4096).unwrap();
        let cache_ptr = unsafe { alloc_zeroed(layout) };
        if cache_ptr.is_null() {
            panic!("Failed to allocate shared cache buffer");
        }

        // Create a Vec from the raw allocation for reading
        let mut cache_buf = unsafe {
            alloc::vec::Vec::from_raw_parts(cache_ptr, SHARED_CACHE_SIZE, SHARED_CACHE_SIZE)
        };

        if blk.read_sectors(0, &mut cache_buf) {
            kprintln!(
                "Shared cache loaded ({} bytes, aligned to {:x})",
                SHARED_CACHE_SIZE,
                cache_buf.as_ptr() as usize
            );
            // Map shared cache to its expected address (0x2fe00000 area)
            // For now, store in a static location
            static mut SHARED_CACHE_STORAGE: Option<alloc::vec::Vec<u8>> = None;
            unsafe {
                SHARED_CACHE_STORAGE = Some(cache_buf);
                if let Some(ref data) = SHARED_CACHE_STORAGE {
                    shared_cache_data = data.as_slice();
                }
            }
        } else {
            kprintln!("Failed to read shared cache from disk");
        }

        // Load rootfs.tar from disk (at 400MB offset)
        const ROOTFS_OFFSET: u64 = 400 * 1024 * 1024 / 512;
        const ROOTFS_SIZE: usize = 50 * 1024 * 1024; // 50MB max
        const ROOTFS_SECTORS: usize = ROOTFS_SIZE / 512;

        let mut rootfs_buf = vec![0u8; ROOTFS_SIZE];
        if blk.read_sectors(ROOTFS_OFFSET, &mut rootfs_buf) {
            kprintln!("Rootfs loaded, initializing VFS...");
            let tarfs = tarfs::TarFs::new(rootfs_buf);
            kprintln!("Found {} files in rootfs", tarfs.list().len());
            vfs::init(tarfs);
        }
    } else {
        kprintln!("No virtio disk found, using embedded binaries");
    }

    // iOS 5 ARMv7 Darwin executables
    static MAIN_BIN: &[u8] = include_bytes!("test_bin.bin");
    static DYLD_BIN: &[u8] = include_bytes!("dyld.bin");

    if !shared_cache_data.is_empty() {
        macho::MachOLoader::map_shared_cache(shared_cache_data);
    }

    // Note: 0x40000000 seems to be used by dyld for CommPage or similar absolute reference.
    // We move the app to 0x5000_0000.
    let load_offset = 0x3FFF_F000;
    kprintln!("Using load_offset: {:x}", load_offset);

    // Populate CommPage (0xFFFF0000) with shared cache address (0x30000000)
    // Offset 0x28 commonly used for shared cache base in Darwin ARM
    unsafe {
        // Signature "comm" at 0x0?
        crate::mmu::COMMPAGE_STORAGE[0] = b'c';
        crate::mmu::COMMPAGE_STORAGE[1] = b'o';
        crate::mmu::COMMPAGE_STORAGE[2] = b'm';
        crate::mmu::COMMPAGE_STORAGE[3] = b'm';

        // Set version at 0x1E (u16)
        unsafe {
            let version_ptr = &mut crate::mmu::COMMPAGE_STORAGE[0x1E] as *mut u8 as *mut u16;
            *version_ptr = 13;
        }

        let sc_addr = 0x3000_0000u32;
        // Try both 0x28 and 0x38 for shared cache base in CommPage
        let sc_ptr_28 = &mut crate::mmu::COMMPAGE_STORAGE[0x28] as *mut u8 as *mut u32;
        *sc_ptr_28 = sc_addr;
        let sc_ptr_38 = &mut crate::mmu::COMMPAGE_STORAGE[0x38] as *mut u8 as *mut u32;
        *sc_ptr_38 = sc_addr;

        kprintln!(
            "Populated CommPage at 0xffff0000 with SC address {:x} (offs 0x28, 0x38)",
            sc_addr
        );
    }

    let main_loader = macho::MachOLoader::load(MAIN_BIN, load_offset);
    if let Some(loader) = main_loader {
        let (entry, path) = if let Some(dyld_path) = loader.dylinker {
            kprintln!("Binary requests dylinker: {}", dyld_path);
            let dyld_loader =
                macho::MachOLoader::load(DYLD_BIN, load_offset).expect("Failed to load dyld");
            (dyld_loader.entry, dyld_path)
        } else {
            (loader.entry + load_offset, String::from("/bin/initial"))
        };

        // Allocate and map user stack
        let (user_stack_base, user_sp_initial, user_stack_size) = {
            let size = 1024 * 1024;
            let buf = vec![0u8; size];
            let base = buf.as_ptr() as u64;
            core::mem::forget(buf);
            (base, base + size as u64, size)
        };
        crate::mmu::map_range(
            user_stack_base,
            user_stack_base,
            user_stack_size as u64,
            crate::mmu::MapPermission::UserRW,
        );

        // Setup BSD/Mach stack layout
        kprintln!("Initial User SP: {:x}", user_sp_initial);
        // Pass the actual address where the Mach-O header was loaded (mapped)
        let new_sp = macho::setup_stack(user_sp_initial, &path, loader.header_addr);
        kprintln!("Stack setup complete. New User SP: {:x}", new_sp);

        // Initial User SP: new_sp points to mh_addr.
        // Stack:
        // [new_sp]     : mh_addr
        // [new_sp + 4] : 1 (argc)
        // [new_sp + 8] : path_ptr (argv[0])
        // [new_sp + 12]: 0 (argv[1] NULL)
        // [new_sp + 16]: 0 (env[0] NULL)
        // [new_sp + 20]: path_ptr (apple[0])
        // [new_sp + 24]: 0 (apple[1] NULL)

        // Prepare args for dyld: r0=base, r1=slide, r2=argc_ptr, r3=argv_ptr, r4=env_ptr, r5=apple_ptr
        let args = [
            loader.header_addr, // r0: mach_header
            load_offset,        // r1: slide
            new_sp + 4,         // r2: argcptr
            new_sp + 8,         // r3: argvptr
            new_sp + 16,        // r4: envp
            new_sp + 20,        // r5: apple
        ];

        // Allocate TLS page (4KB)
        let (tls_base, _, tls_size) = {
            let size = 4096;
            let buf = vec![0u8; size];
            let base = buf.as_ptr() as u64;
            core::mem::forget(buf);
            (base, base + size as u64, size)
        };
        crate::mmu::map_range(
            tls_base,
            tls_base,
            tls_size as u64,
            crate::mmu::MapPermission::UserRW,
        );
        // Fill TLS with some pattern if needed, but 0 is usually fine for initial state.
        // dyld expects [tls] to point to itself? The crash was ldr r1, [r1].
        // If r1 spans 0, crash. If r1 points to tls_base, ldr r1, [tls_base] loads first word.
        // We should probably write a pointer to itself at tls_base?
        // Darwin lazy binding might expect it.
        // Let's write self-reference.
        unsafe {
            core::ptr::write(tls_base as *mut u32, tls_base as u32);
        }

        let mut process = Process::new(entry, new_sp, &args, tls_base);

        let mut sched = SCHEDULER.lock();
        sched.add_process(process);
        sched.schedule_next();
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

    kprintln!(
        "Returned to kmain loop? This shouldn't happen for the first switch unless it returns."
    );

    loop {
        unsafe { asm!("wfe") };
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    kprintln!("Kernel Panic: {:?}", info);
    loop {
        unsafe { asm!("wfe") };
    }
}
