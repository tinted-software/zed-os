#![no_std]
#![no_main]

extern crate alloc;
use core::panic::PanicInfo;
use linked_list_allocator::LockedHeap;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

static HEAP_SPACE: [u8; 1024 * 1024] = [0u8; 1024 * 1024]; // 1MB heap

/// # Safety
///
/// Initializes the global allocator with a static heap buffer.
/// Must be called only once at startup.
unsafe fn init_heap() {
    unsafe {
        ALLOCATOR
            .lock()
            .init(HEAP_SPACE.as_ptr() as *mut u8, HEAP_SPACE.len())
    };
}

mod cache;
mod macho;

use crate::cache::SharedCache;
use crate::macho::MachOContext;
use alloc::vec::Vec;

pub struct DyldState<'a> {
    pub main_executable: MachOContext<'a>,
    pub libraries: Vec<MachOContext<'a>>,
    pub cache: SharedCache,
}

impl<'a> DyldState<'a> {
    /// # Safety
    ///
    /// `mh` must be a valid pointer to a Mach-O header.
    pub unsafe fn new(mh: *const u8, slide: usize, cache: SharedCache) -> Self {
        let main_ctx =
            unsafe { MachOContext::parse(mh, slide).expect("Failed to parse main Mach-O") };
        Self {
            main_executable: main_ctx,
            libraries: Vec::new(),
            cache,
        }
    }
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "__TEXT,__text")]
/// # Safety
///
/// Entry point for the dynamic linker.
/// Pointers must be valid.
pub unsafe extern "C" fn dyld_start(
    mh: *const u8,
    slide: usize,
    argc_ptr: *const u64,
    _argv_ptr: *const *const u8,
    _env_ptr: *const *const u8,
    _apple_ptr: *const *const u8,
) -> ! {
    unsafe {
        init_heap();
        print("Hello from Rust dyld!\n");

        // Print arguments for verification
        print("Mach-O Header: ");
        print_hex(mh as u64);
        print("\n");

        print("Slide: ");
        print_hex(slide as u64);
        print("\n");

        if !argc_ptr.is_null() {
            print("Argc: ");
            print_hex(*argc_ptr);
            print("\n");
        }

        // Find shared cache
        let sc_base = 0x30000000usize;
        // TODO: Parse apple_ptr to find dyld_shared_cache_base_address

        let cache = SharedCache::from_addr(sc_base).expect("Failed to find shared cache");
        print("Shared cache found at ");
        print_hex(sc_base as u64);
        print("\n");

        let mut state = DyldState::new(mh, slide, cache);

        // Process dependent dylibs
        for cmd in &state.main_executable.macho.load_commands {
            if let goblin::mach::load_command::CommandVariant::LoadDylib(dylib_cmd) = &cmd.command {
                let offset = dylib_cmd.dylib.name as usize;
                let name_ptr = mh.add(cmd.offset + offset);
                let mut len = 0;
                while *name_ptr.add(len) != 0 {
                    len += 1;
                }
                let name =
                    core::str::from_utf8_unchecked(core::slice::from_raw_parts(name_ptr, len));

                print("Loading dylib: ");
                print(name);
                print("\n");

                if let Some(dylib_addr) = state.cache.find_dylib(name) {
                    print("  Found in cache at ");
                    print_hex(dylib_addr as u64);
                    print("\n");
                    // Parse and add to state
                    if let Some(lib_ctx) = MachOContext::parse(dylib_addr, 0) {
                        // Slide 0 for cache?
                        state.libraries.push(lib_ctx);
                    }
                } else {
                    print("  NOT found in cache\n");
                }
            }
        }

        // Apply relocations
        state
            .main_executable
            .apply_relocations(&state.libraries, &state.cache)
            .expect("Failed to apply relocations");

        print("Jumping to entry point: ");
        print_hex(state.main_executable.macho.entry + slide as u64);
        print("\n");

        let entry: extern "C" fn() =
            core::mem::transmute(state.main_executable.macho.entry + slide as u64);
        entry();

        loop {
            // For now, just yield or hang
            core::arch::asm!("svc #0", in("x8") 0u64);
        }
    }
}

fn print(s: &str) {
    let bytes = s.as_bytes();
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") 2u64, // sys_write
            in("x0") 1u64, // stdout
            in("x1") bytes.as_ptr() as u64,
            in("x2") bytes.len() as u64,
        );
    }
}

fn print_hex(val: u64) {
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..16 {
        let nibble = (val >> (60 - i * 4)) & 0xf;
        buf[i + 2] = if nibble < 10 {
            b'0' + nibble as u8
        } else {
            b'a' + (nibble - 10) as u8
        };
    }
    print(unsafe { core::str::from_utf8_unchecked(&buf) });
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    print("dyld PANIC!\n");
    loop {
        unsafe { core::arch::asm!("wfe") };
    }
}
