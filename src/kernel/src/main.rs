#![no_std]
#![no_main]

// Enable alloc crate
extern crate alloc;

mod block;
mod heap;
mod hfsfs;
mod ipc;
mod macho;
mod mem;
mod mmu;
mod process;
mod scheduler;
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

#[unsafe(no_mangle)]
pub extern "C" fn kmain() {
    kprintln!("Hello from GravityOS (fixed 2). Spawning AArch64 processes...");

    process::init_vectors();

    mmu::init();

    heap::init_heap();

    kprintln!("Heap initialized");

    kprintln!("Vectors initialized");

    // Initialize virtio block device and load shared cache
    // let mut shared_cache_data: &[u8] = &[];

    if let Some(blk) = virtio::init() {
        kprintln!("Initializing VFS from disk...");
        let blk_shared = alloc::sync::Arc::new(spin::Mutex::new(blk));
        let hfsfs = hfsfs::HfsFs::new(blk_shared, 400 * 1024 * 1024);
        vfs::init(hfsfs);
        kprintln!("VFS initialized");
    } else {
        kprintln!("No virtio disk found");
    }

    // Note: 0x40000000 seems to be used by dyld for CommPage or similar absolute reference.
    // We move the app to 0x4000_0000.
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
        let version_ptr = &mut crate::mmu::COMMPAGE_STORAGE[0x1E] as *mut u8 as *mut u16;
        *version_ptr = 13;

        // Set ncpus at 0x22 (u8)
        crate::mmu::COMMPAGE_STORAGE[0x22] = 1;

        // Set pagesize at 0x24 (u32)
        let pgsize_ptr = &mut crate::mmu::COMMPAGE_STORAGE[0x24] as *mut u8 as *mut u32;
        *pgsize_ptr = 4096;

        let sc_addr = 0x3000_0000u32;
        // Try all common shared cache base offsets in CommPage
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
    kprintln!("Opening /usr/lib/dyld...");
    let dyld_bin = {
        let mut file = vfs::open("/usr/lib/dyld").expect("Failed to open dyld");
        kprintln!("Reading /usr/lib/dyld ({} bytes)...", file.size());
        file.read_to_end()
    };
    kprintln!("Parsing Mach-O binaries...");
    let main_load_offset = 0; // Use linked address for launchd if possible
    let main_loader = macho::MachOLoader::load(&main_bin, main_load_offset);
    if let Some(loader) = main_loader {
        let mut loader_is_64bit = loader.is_64bit;
        let (entry, path, dyld_mh, _dyld_slide) = if let Some(dyld_path) = loader.dylinker {
            kprintln!("Binary requests dylinker: {}", dyld_path);
            let dyld_load_offset = 0x2fe00000;
            let dyld_loader =
                macho::MachOLoader::load(&dyld_bin, dyld_load_offset).expect("Failed to load dyld");
            loader_is_64bit = dyld_loader.is_64bit;
            (dyld_loader.entry, dyld_path, dyld_loader.header_addr, 0)
        } else {
            (
                loader.entry + main_load_offset,
                String::from("/bin/initial"),
                0,
                0,
            )
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
        let new_sp =
            macho::setup_stack(user_sp_initial, &path, loader.header_addr, loader_is_64bit);
        kprintln!("Stack setup complete. New User SP: {:x}", new_sp);

        // Prepare args for dyld bootstrap:
        // Darwin ARMv7: r0=dyld_mh, r1=slide, r2=&argc, r3=argv, r4=envp, r5=apple
        let args = if loader_is_64bit {
            [
                loader.header_addr,
                0, // slide
                new_sp + 8,
                new_sp + 16,
                new_sp + 32,
                new_sp + 40,
            ]
        } else {
            [
                dyld_mh,     // r0: dyld's own mach_header
                0,           // r1: dyld's own slide
                new_sp + 4,  // r2: &argc (sp+4 points to argc=1)
                new_sp + 8,  // r3: argv
                new_sp + 16, // r4: envp
                new_sp + 20, // r5: apple
            ]
        };

        // Allocate TLS page (4KB), ensuring 4KB alignment
        let (tls_base, tls_size) = {
            let size = 4096;
            use alloc::alloc::{Layout, alloc_zeroed};
            let layout = Layout::from_size_align(size, 4096).unwrap();
            let ptr = unsafe { alloc_zeroed(layout) };
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
        // Fill TLS with self-reference at offset 0
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

        kprintln!("ERROR: __switch_to returned to kmain!");
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
