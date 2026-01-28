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
    kprintln!("Hello from GravityOS. Spawning AArch64 processes...");

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

    kprintln!("Opening /sbin/launchd...");
    let main_bin = {
        let mut file = vfs::open("/sbin/launchd").expect("Failed to open launchd");
        kprintln!("Reading /sbin/launchd ({} bytes)...", file.size());
        let data = file.read_to_end();
        if data.len() >= 320 {
            kprintln!(
                "launchd header: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
                data[0],
                data[1],
                data[2],
                data[3],
                data[4],
                data[5],
                data[6],
                data[7]
            );
            kprintln!("launchd at 256:");
            for i in 0..4 {
                let off = 256 + i * 16;
                kprintln!(
                    "  {:03x}: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}  {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
                    off,
                    data[off + 0],
                    data[off + 1],
                    data[off + 2],
                    data[off + 3],
                    data[off + 4],
                    data[off + 5],
                    data[off + 6],
                    data[off + 7],
                    data[off + 8],
                    data[off + 9],
                    data[off + 10],
                    data[off + 11],
                    data[off + 12],
                    data[off + 13],
                    data[off + 14],
                    data[off + 15]
                );
            }
        }
        data
    };
    kprintln!("Opening /usr/lib/dyld...");
    let dyld_bin = {
        let mut file = vfs::open("/usr/lib/dyld").expect("Failed to open dyld");
        kprintln!("Reading /usr/lib/dyld ({} bytes)...", file.size());
        let data = file.read_to_end();
        if data.len() >= 320 {
            kprintln!(
                "dyld header: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
                data[0],
                data[1],
                data[2],
                data[3],
                data[4],
                data[5],
                data[6],
                data[7]
            );
            kprintln!("dyld at 256:");
            for i in 0..4 {
                let off = 256 + i * 16;
                kprintln!(
                    "  {:03x}: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}  {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
                    off,
                    data[off + 0],
                    data[off + 1],
                    data[off + 2],
                    data[off + 3],
                    data[off + 4],
                    data[off + 5],
                    data[off + 6],
                    data[off + 7],
                    data[off + 8],
                    data[off + 9],
                    data[off + 10],
                    data[off + 11],
                    data[off + 12],
                    data[off + 13],
                    data[off + 14],
                    data[off + 15]
                );
            }
        } else if data.len() > 0 {
            kprintln!(
                "dyld raw header: {:02x} {:02x} {:02x} {:02x}",
                data[0],
                data[1],
                data[2],
                data[3]
            );
        }
        data
    };
    kprintln!("Parsing Mach-O binaries...");
    let main_loader = macho::MachOLoader::load(&main_bin, load_offset);
    if let Some(loader) = main_loader {
        let mut loader_is_64bit = loader.is_64bit;
        let (entry, path) = if let Some(dyld_path) = loader.dylinker {
            kprintln!("Binary requests dylinker: {}", dyld_path);
            let dyld_loader =
                macho::MachOLoader::load(&dyld_bin, load_offset).expect("Failed to load dyld");
            loader_is_64bit = dyld_loader.is_64bit;
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
            new_sp + 8,         // r2: argcptr
            new_sp + 16,        // r3: argvptr
            new_sp + 32,        // r4: envp
            new_sp + 40,        // r5: apple
        ];

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
        // Fill TLS with some pattern if needed, but 0 is usually fine for initial state.
        // dyld expects [tls] to point to itself? The crash was ldr r1, [r1].
        // If r1 spans 0, crash. If r1 points to tls_base, ldr r1, [tls_base] loads first word.
        // We should probably write a pointer to itself at tls_base?
        // Darwin lazy binding might expect it.
        // Let's write self-reference.
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
