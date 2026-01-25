use crate::kprintln;
use crate::scheduler::SCHEDULER;
use core::arch::asm;

#[repr(C)]
#[derive(Debug, Default)]
pub struct TrapFrame {
    pub x: [u64; 31],
    pub __reserved: u64, // for alignment
    pub elr: u64,
    pub spsr: u64,
    pub sp_el0: u64,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct CpuContext {
    pub regs: [u64; 13], // x19..x28, x29, sp, x30
}

#[unsafe(no_mangle)]
pub extern "C" fn handle_sync_exception(frame: &mut TrapFrame) {
    let esr: u64;
    let far: u64;
    let sp_el0: u64;
    unsafe {
        asm!("mrs {}, esr_el1", out(reg) esr);
        asm!("mrs {}, far_el1", out(reg) far);
        asm!("mrs {}, sp_el0", out(reg) sp_el0);
    }
    frame.sp_el0 = sp_el0;

    let ec = esr >> 26;
    let iss = esr & 0x1FFFFFF;

    match ec {
        0x15 => {
            // EC 0x15 = SVC instruction in AArch64
            handle_a64_syscall(frame);
        }
        0x11 => {
            // EC 0x11 = SVC instruction in AArch32
            handle_a32_syscall(frame);
        }
        _ => {
            kprintln!(
                "Unknown exception! ESR: {:x} EC: {:x} ISS: {:x} FAR: {:x} PC: {:x} SPSR: {:x}",
                esr,
                ec,
                iss,
                far,
                frame.elr,
                frame.spsr
            );
            kprintln!(
                "regs: x0={:x} x1={:x} x2={:x} x3={:x}",
                frame.x[0],
                frame.x[1],
                frame.x[2],
                frame.x[3]
            );
            kprintln!(
                "      x4={:x} x5={:x} x6={:x} x7={:x}",
                frame.x[4],
                frame.x[5],
                frame.x[6],
                frame.x[7]
            );
            kprintln!(
                "      x8={:x} x9={:x} x10={:x} x11={:x}",
                frame.x[8],
                frame.x[9],
                frame.x[10],
                frame.x[11]
            );

            let sp_el0: u64;
            unsafe { asm!("mrs {}, sp_el0", out(reg) sp_el0) };

            kprintln!(
                "      x12={:x} sp_el0={:x} lr={:x}",
                frame.x[12],
                sp_el0,
                frame.elr
            );

            // Dump code around PC (backwards and forwards)
            kprintln!("Code at PC:");
            dump_mem((frame.elr & !0xF).saturating_sub(32), 64);

            // Dump memory around FAR if it was a data abort
            if ec == 0x24 || ec == 0x25 {
                kprintln!("Data at FAR:");
                dump_mem(far & !0xF, 32);
            }

            loop {
                unsafe { asm!("wfe") }
            }
        }
    }
}

fn dump_mem(addr: u64, len: u64) {
    for i in (0..len).step_by(16) {
        let curr = addr + i;
        // Basic safety check for known mapped user/kernel regions
        if (0x30000000..0x80000000).contains(&curr) || (0x10000000..0x20000000).contains(&curr) {
            // OK
        } else {
            // kprintln!("{:08x}: <unmapped>", curr);
            continue;
        }

        unsafe {
            let p = curr as *const u32;
            kprintln!(
                "{:08x}: {:08x} {:08x} {:08x} {:08x}",
                curr,
                core::ptr::read_volatile(p.offset(0)),
                core::ptr::read_volatile(p.offset(1)),
                core::ptr::read_volatile(p.offset(2)),
                core::ptr::read_volatile(p.offset(3))
            );
        }
    }
}

fn handle_a64_syscall(frame: &mut TrapFrame) {
    let syscall_num = frame.x[8];

    match syscall_num {
        0 => sys_yield(),
        1 => sys_exit(),
        2 => sys_write(frame.x[0], frame.x[1], frame.x[2]),
        3 => frame.x[0] = sys_spawn(frame.x[0], frame.x[1]),
        4 => frame.x[0] = sys_getpid(),
        _ => {
            kprintln!("Unknown A64 syscall: {}", syscall_num);
        }
    }
}

fn handle_a32_syscall(frame: &mut TrapFrame) {
    // Darwin ARMv7 convention: syscall number in R12 (frame.x[12])
    // Mach traps are negative, BSD are positive.
    let r12 = (frame.x[12] & 0xFFFF_FFFF) as u32;
    // Sign-extend 32-bit register to 64-bit/32-bit signed integer
    let syscall_num = r12 as i32;

    // Check if it's 0x80000000 (Mach absolute)
    if r12 == 0x80000000 {
        // kprintln!("Handling raw mach trap 0x80000000 (swtch/yield equivalent?)");
        frame.x[0] = 1; // Success
        return;
    }

    kprintln!(
        "A32 Syscall: {} (R12: {:x}, PC: {:x}) r0={:x} r1={:x} r2={:x} r3={:x} r4={:x} r5={:x} r6={:x} r7={:x}",
        syscall_num,
        r12,
        frame.elr,
        frame.x[0],
        frame.x[1],
        frame.x[2],
        frame.x[3],
        frame.x[4],
        frame.x[5],
        frame.x[6],
        frame.x[7]
    );

    // Set Carry flag (bit 29) in SPSR to indicate success or failure.
    // XNU/BSD Convention: Carry Clear (0) = Success, Carry Set (1) = Error.
    // Arguments: r0 = error code (if error) or return value (if success).

    // Default to success (Clear Carry)
    frame.spsr &= !(1 << 29);

    if syscall_num < 0 {
        let trap_num = syscall_num.wrapping_neg();
        handle_mach_trap(frame, trap_num);
    } else {
        handle_bsd_syscall(frame, syscall_num);
    }
}

fn handle_mach_trap(frame: &mut TrapFrame, trap_num: i32) {
    kprintln!(
        "Mach Trap {}: r0={:x} r1={:x} r2={:x} r3={:x} PC: {:x}",
        trap_num,
        frame.x[0],
        frame.x[1],
        frame.x[2],
        frame.x[3],
        frame.elr
    );

    match trap_num {
        3 => {
            // mach_port_allocate or task_self?
            if frame.x[2] > 0x1000 {
                let name_ptr = frame.x[2];
                let mut scheduler = SCHEDULER.lock();
                if let Some(proc) = &mut scheduler.current_process {
                    let name = proc.ipc_space.allocate_port();
                    unsafe {
                        core::ptr::write_volatile(name_ptr as *mut u32, name);
                        core::arch::asm!("dsb sy", "isb");
                    }
                    frame.x[0] = 0; // KERN_SUCCESS
                } else {
                    frame.x[0] = 5; // KERN_FAILURE
                }
            } else {
                frame.x[0] = 1; // Return port 1 (task self)
            }
        }
        10..=13 => {
            // VM traps (allocate, deallocate, map, copy)
            let addr_ptr = frame.x[1];
            let size = frame.x[2];
            let anywhere = frame.x[3] != 0;
            static NEXT_VM: core::sync::atomic::AtomicU64 =
                core::sync::atomic::AtomicU64::new(0x7000_0000);

            unsafe {
                let mut addr = if anywhere || addr_ptr < 0x1000 {
                    0
                } else {
                    core::ptr::read_unaligned(addr_ptr as *const u32) as u64
                };
                if addr == 0 || addr < 0x1000 {
                    addr = NEXT_VM.fetch_add(
                        (size + 0xFFF) & !0xFFF,
                        core::sync::atomic::Ordering::Relaxed,
                    );
                }
                crate::mmu::map_range(addr, addr, size, crate::mmu::MapPermission::UserRW);
                if addr_ptr > 0x1000 {
                    core::ptr::write_volatile(addr_ptr as *mut u32, addr as u32);
                    core::arch::asm!("dsb sy", "isb");
                }

                frame.x[0] = 0; // KERN_SUCCESS
            }
        }
        26 => {
            let mut scheduler = SCHEDULER.lock();
            if let Some(proc) = &mut scheduler.current_process {
                let name = proc.ipc_space.allocate_port();
                frame.x[0] = name as u64;
            } else {
                frame.x[0] = 0;
            }
        }
        27 => frame.x[0] = 3,
        28 => frame.x[0] = 1,
        29 => frame.x[0] = 4,
        31 => {
            let msg = frame.x[0] as *mut crate::ipc::MachMsgHeader;
            let option = frame.x[1] as u32;
            let send_size = frame.x[2] as u32;
            let rcv_size = frame.x[3] as u32;
            let rcv_name = frame.x[4] as u32;
            let timeout = frame.x[5] as u32;

            let mut scheduler = SCHEDULER.lock();
            if let Some(proc) = &mut scheduler.current_process {
                let ret = crate::ipc::mach_msg(
                    msg,
                    option,
                    send_size,
                    rcv_size,
                    rcv_name,
                    timeout,
                    0,
                    &mut proc.ipc_space,
                );
                unsafe {
                    core::arch::asm!("dsb sy", "isb");
                }
                frame.x[0] = ret as u64;
            } else {
                frame.x[0] = 0x10000003;
            }
        }
        _ => {
            kprintln!("Unknown Mach trap: {}", trap_num);
            frame.x[0] = 0;
        }
    }
    kprintln!("Mach Trap {} returned {:x}", trap_num, frame.x[0]);
}

fn sys_write(fd: u64, buf: u64, len: u64) {
    if fd == 1 || fd == 2 || fd == 4 {
        let slice = unsafe { core::slice::from_raw_parts(buf as *const u8, len as usize) };
        if let Ok(s) = core::str::from_utf8(slice) {
            kprintln!("sys_write: {}", s);
        }
    }
}

fn handle_bsd_syscall(frame: &mut TrapFrame, syscall_num: i32) {
    kprintln!(
        "BSD Syscall {}: r0={:x} r1={:x} r2={:x} r3={:x} r4={:x} r5={:x} PC: {:x}",
        syscall_num,
        frame.x[0],
        frame.x[1],
        frame.x[2],
        frame.x[3],
        frame.x[4],
        frame.x[5],
        frame.elr
    );

    match syscall_num {
        0 => {
            // indir syscall
            let real_syscall = frame.x[0];
            let mut saved = [0u64; 6];
            saved[1..6].copy_from_slice(&frame.x[1..6]);
            for i in 0..6 {
                frame.x[i] = frame.x[i + 1];
            }
            handle_bsd_syscall(frame, real_syscall as i32);
            frame.x[1..6].copy_from_slice(&saved[1..6]);
        }
        1 => sys_exit(),
        3 => {
            // read
            let fd = frame.x[0];
            let buf = frame.x[1];
            let nbyte = frame.x[2];

            if fd == 100 {
                let cache_base = 0x30000000 as *const u8;
                unsafe {
                    core::ptr::copy_nonoverlapping(cache_base, buf as *mut u8, nbyte as usize);
                }
                frame.x[0] = nbyte;
            } else if fd < 32 {
                let mut bytes_read = 0;
                let mut success = false;
                {
                    let mut scheduler = SCHEDULER.lock();
                    if let Some(proc) = &mut scheduler.current_process
                        && let Some(Some(file)) = proc.files.get_mut(fd as usize)
                    {
                        let slice = unsafe {
                            core::slice::from_raw_parts_mut(buf as *mut u8, nbyte as usize)
                        };
                        bytes_read = file.read(slice);
                        success = true;
                    }
                }

                if success {
                    kprintln!("sys_read: Read {} bytes from fd {}", bytes_read, fd);
                    frame.x[0] = bytes_read as u64;
                } else {
                    kprintln!("sys_read: Bad fd {} (not open)", fd);
                    frame.x[0] = 9; // EBADF
                    frame.spsr |= 1 << 29; // Set Carry
                }
            } else {
                frame.x[0] = 9; // EBADF
                frame.spsr |= 1 << 29;
            }
        }
        4 => sys_write(frame.x[0], frame.x[1], frame.x[2]),
        5 => {
            // open
            let path_ptr = frame.x[0];
            let slice = unsafe { core::slice::from_raw_parts(path_ptr as *const u8, 256) };
            let len = slice.iter().position(|&c| c == 0).unwrap_or(256);
            if let Ok(path) = core::str::from_utf8(&slice[..len]) {
                kprintln!("sys_open: {}", path);

                // Try VFS
                if let Some(handle) = crate::vfs::open(path) {
                    let mut scheduler = SCHEDULER.lock();
                    if let Some(proc) = &mut scheduler.current_process
                        && let Some(fd) = proc.files.iter().position(|f| f.is_none())
                    {
                        proc.files[fd] = Some(handle);
                        kprintln!("sys_open: Opened {} as fd {}", path, fd);
                        frame.x[0] = fd as u64;
                        return;
                    }
                    frame.x[0] = 24; // EMFILE
                    frame.spsr |= 1 << 29; // Set Carry
                    return;
                }

                if path.contains("dyld_shared_cache") {
                    frame.x[0] = 100;
                    return;
                }

                kprintln!("sys_open: Failed to open '{}' in VFS", path);
            }
            frame.x[0] = 2; // ENOENT
            frame.spsr |= 1 << 29; // Set Carry
        }
        6 => {
            // close
            let fd = frame.x[0];
            if fd < 32 {
                let mut scheduler = SCHEDULER.lock();
                if let Some(proc) = &mut scheduler.current_process
                    && (fd as usize) < proc.files.len()
                {
                    proc.files[fd as usize] = None;
                }
            }
            frame.x[0] = 0;
        }
        20 => frame.x[0] = sys_getpid(),
        24 | 25 => frame.x[0] = 0,       // getuid, geteuid
        43 | 47 | 126 => frame.x[0] = 0, // getgid, getegid
        74 => frame.x[0] = 0,            // mprotect
        116 => frame.x[0] = 0,           // gettimeofday
        153 => {
            // pread
            let fd = frame.x[0];
            let buf = frame.x[1];
            let nbyte = frame.x[2];
            // off_t is 64-bit, usually at r4/r5 with padding in r3 for ARMv7.
            let mut offset = frame.x[4] | (frame.x[5] << 32);

            // Heuristic: if offset is crazy high, try r3/r4
            if offset > 0x0000_1000_0000_0000 {
                offset = frame.x[3] | (frame.x[4] << 32);
            }

            if fd == 100 {
                let cache_base = (0x30000000 + offset) as *const u8;
                unsafe {
                    core::ptr::copy_nonoverlapping(cache_base, buf as *mut u8, nbyte as usize);
                }
                frame.x[0] = nbyte;
            } else if fd < 32 {
                let mut bytes_read = 0;
                let mut success = false;
                {
                    let mut scheduler = SCHEDULER.lock();
                    if let Some(proc) = &mut scheduler.current_process
                        && let Some(Some(file)) = proc.files.get(fd as usize)
                    {
                        let slice = unsafe {
                            core::slice::from_raw_parts_mut(buf as *mut u8, nbyte as usize)
                        };
                        bytes_read = file.read_at(offset, slice);
                        success = true;
                    }
                }

                if success {
                    kprintln!(
                        "sys_pread: Read {} bytes from fd {} at offset {}",
                        bytes_read,
                        fd,
                        offset
                    );
                    frame.x[0] = bytes_read as u64;
                } else {
                    kprintln!("sys_pread: Bad fd {} (not open)", fd);
                    frame.x[0] = 9; // EBADF
                    frame.spsr |= 1 << 29;
                }
            } else {
                frame.x[0] = 9; // EBADF
                frame.spsr |= 1 << 29;
            }
        }
        169 => frame.x[0] = 0, // csops
        189 => {
            // fstat64
            let fd = frame.x[0];
            let mut size = 0;
            if fd == 100 {
                size = 200 * 1024 * 1024;
            } else if fd < 32 {
                let mut scheduler = SCHEDULER.lock();
                if let Some(proc) = &mut scheduler.current_process
                    && let Some(Some(file)) = proc.files.get(fd as usize)
                {
                    size = file.size() as i64;
                }
            }
            populate_stat64(frame.x[1], size);
            frame.x[0] = 0;
        }
        92 => {
            // fcntl
            let fd = frame.x[0];
            let cmd = frame.x[1];
            kprintln!("sys_fcntl: fd={} cmd={:x}", fd, cmd);
            frame.x[0] = 0; // Success
        }
        196 => {
            // getdirentries
            frame.x[0] = 0; // End of entries
        }
        197 => {
            // mmap(addr, len, prot, flags, fd, offset)
            let addr = frame.x[0];
            let len = frame.x[1];
            let prot = frame.x[2];
            let flags = frame.x[3];
            let fd = frame.x[4];
            // off_t is 64-bit, usually at r6/r7 with padding in r5.
            let mut offset = frame.x[6] | (frame.x[7] << 32);
            if offset > 0x0000_1000_0000_0000 {
                offset = frame.x[5] | (frame.x[6] << 32);
            }

            kprintln!(
                "sys_mmap: addr={:x} len={:x} prot={:x} flags={:x} fd={} offset={:x}",
                addr,
                len,
                prot,
                flags,
                fd,
                offset
            );

            let mut final_addr = addr;
            static NEXT_MMAP: core::sync::atomic::AtomicU64 =
                core::sync::atomic::AtomicU64::new(0x8000_0000);

            if final_addr == 0 {
                final_addr = NEXT_MMAP.fetch_add(
                    (len + 0xFFF) & !0xFFF,
                    core::sync::atomic::Ordering::Relaxed,
                );
            }

            let perm = if (prot & 2) != 0 {
                crate::mmu::MapPermission::UserRWX
            } else {
                crate::mmu::MapPermission::UserRX
            };

            if fd == 100 {
                // Shared cache mapping
                let cache_phys = 0x5000_0000 + offset;
                crate::mmu::map_range(final_addr, cache_phys, len, perm);
                frame.x[0] = final_addr;
                return;
            }

            // Allocate and map
            let mut data = alloc::vec![0u8; len as usize];

            if fd < 32 {
                let mut success = false;
                {
                    let mut scheduler = SCHEDULER.lock();
                    if let Some(proc) = &mut scheduler.current_process
                        && let Some(Some(file)) = proc.files.get(fd as usize)
                    {
                        file.read_at(offset, &mut data);
                        success = true;
                    }
                }
                if !success && fd != 0xFFFFFFFF && (fd as i32) != -1 {
                    kprintln!("sys_mmap: Failed to read from fd {}", fd);
                }
            }

            let phys = data.as_ptr() as u64;
            core::mem::forget(data);

            crate::mmu::map_range(final_addr, phys, len, perm);
            frame.x[0] = final_addr;
        }
        220 => {
            // getattrlist
            frame.x[0] = 0;
        }
        199 => frame.x[0] = 0, // shmsys
        202 => {
            // sysctl(name, namelen, oldp, oldlenp, newp, newlen)
            let name_ptr = frame.x[0];
            let namelen = frame.x[1];
            let oldp = frame.x[2];
            let oldlenp = frame.x[3];

            unsafe {
                if namelen >= 2 {
                    let mib = core::slice::from_raw_parts(name_ptr as *const i32, namelen as usize);
                    // kprintln!("sysctl mib: {:?}", mib);

                    if mib[0] == 6 {
                        // CTL_HW
                        match mib[1] {
                            7 => {
                                // HW_PAGESIZE
                                if oldp != 0 {
                                    *(oldp as *mut u32) = 4096;
                                }
                                if oldlenp != 0 {
                                    *(oldlenp as *mut u32) = 4;
                                }
                                frame.x[0] = 0;
                                return;
                            }
                            3 => {
                                // HW_NCPU
                                if oldp != 0 {
                                    *(oldp as *mut u32) = 1;
                                }
                                if oldlenp != 0 {
                                    *(oldlenp as *mut u32) = 4;
                                }
                                frame.x[0] = 0;
                                return;
                            }
                            _ => {}
                        }
                    }
                    if mib[0] == 1 {
                        // CTL_KERN
                        if mib[1] == 24 {
                            // KERN_ARGMAX
                            if oldp != 0 {
                                *(oldp as *mut u32) = 65536;
                            }
                            if oldlenp != 0 {
                                *(oldlenp as *mut u32) = 4;
                            }
                            frame.x[0] = 0;
                            return;
                        }
                    }
                }
            }
            frame.x[0] = 0;
        }
        33 => frame.x[0] = 0, // access
        190 | 338 => {
            // lstat, stat64
            populate_stat64(frame.x[1], 200 * 1024 * 1024);
            frame.x[0] = 0;
        }
        327 => frame.x[0] = 0, // issetugid
        294 => {
            // shared_region_check_np
            let addr_ptr = frame.x[0];
            if addr_ptr != 0 {
                unsafe {
                    core::ptr::write_volatile(addr_ptr as *mut u32, 0x30000000);
                    core::arch::asm!("dsb sy", "isb");
                }
            }
            frame.x[0] = 0;
        }
        37 | 46 | 48 | 54 | 423 => frame.x[0] = 0, // kill, sigaction, sigprocmask, ioctl, sem_open
        _ => {
            kprintln!("Unknown BSD syscall: {}", syscall_num);
            frame.x[0] = (-1i32 as u32) as u64;
        }
    }
    kprintln!("BSD Syscall {} returned {:x}", syscall_num, frame.x[0]);
}

fn sys_yield() {
    unsafe {
        unsafe extern "C" {
            fn __switch_to(prev: *mut CpuContext, next: *const CpuContext);
        }

        let pointers = {
            let mut scheduler = SCHEDULER.lock();
            scheduler.schedule_next()
        };

        if let Some((prev, next)) = pointers {
            __switch_to(prev.expect("No prev context in sys_yield"), next);
        }
    }
}

fn sys_exit() {
    kprintln!("Process Exiting");
    loop {
        unsafe { asm!("wfe") }
    }
}

fn sys_spawn(fn_ptr: u64, arg: u64) -> u64 {
    let mut scheduler = SCHEDULER.lock();
    // For now, kernel-spawned threads in EL0/A32 might need a real stack,
    // but this sys_spawn is for A64 syscalls which we aren't using for dyld yet.
    let process = crate::scheduler::Process::new(fn_ptr, 0, &[arg], 0);
    let pid = process.pid;
    scheduler.add_process(process);
    pid
}

fn populate_stat64(ptr: u64, size: i64) {
    // Basic stat64 struct population for Darwin ARMv7
    // st_mode @ +4 (u16)
    // st_ino @ +8 (u64)
    // st_uid/gid @ 16/20
    // st_size @ +96 (i64) usually.
    unsafe {
        let p = ptr as *mut u8;
        // Zero out first
        core::ptr::write_bytes(p, 0, 128);

        // st_mode: S_IFREG (0100000) | 0755 = 0x81ed
        // Flood potential offsets for mode (u16)
        *(p.add(4) as *mut u16) = 0x81ed;
        *(p.add(8) as *mut u16) = 0x81ed; // If st_ino is 32-bit

        // st_nlink: 1 (at 6)
        *(p.add(6) as *mut u16) = 1;

        // st_ino: random non-zero
        core::ptr::write_unaligned(p.add(8) as *mut u64, 12345);
        core::ptr::write_unaligned(p.add(12) as *mut u64, 12345); // If mode moved

        // st_size: large enough (e.g. 200MB for shared cache, 4096 for dummy IOKit)
        // We really should differentiate based on filename, but we don't pass it here easily.
        // populate_stat64(ptr) is called for both.
        // Let's set a safe large size for shared cache. But invalid for small IOKit?
        // Wait, current calls:
        // if path.contains("dyld_shared_cache") || path.contains("IOKit") { populate... }
        // We can pass the size.
        // For now, let's just leave it large. dyld handles large files mapped partially.
        // Actually, let's try 4096 to see if it helps IOKit.
        // But shared cache IS 200MB.
        core::ptr::write_unaligned(p.add(60) as *mut i64, size);
        core::ptr::write_unaligned(p.add(64) as *mut i64, size);
        core::ptr::write_unaligned(p.add(72) as *mut i64, size);
        core::ptr::write_unaligned(p.add(96) as *mut i64, size);

        // st_mtimespec (important for cache validation?)
        // Set to non-zero (e.g. 1000)
        core::ptr::write_unaligned(p.add(44) as *mut i64, 1000); // 32-bit time at 36+?
        // time_t 4 bytes -> atimespec(28..36), mtimespec(36..44)
        if core::ptr::read_unaligned(p.add(44) as *const u64) == 0 {
            *(p.add(36) as *mut u32) = 1000;
            *(p.add(44) as *mut u32) = 1000;
        }
    }
}

fn sys_getpid() -> u64 {
    1
}

pub fn init_vectors() {
    unsafe extern "C" {
        static vectors: u8;
    }
    unsafe {
        asm!("msr vbar_el1, {}", in(reg) &vectors);
    }
}
