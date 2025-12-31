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
    unsafe {
        asm!("mrs {}, esr_el1", out(reg) esr);
        asm!("mrs {}, far_el1", out(reg) far);
    }

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
        if (curr >= 0x30000000 && curr < 0x80000000) || (curr >= 0x10000000 && curr < 0x20000000) {
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
        kprintln!("Handling raw mach trap 0x80000000 (swtch/yield equivalent?)");
        frame.x[0] = 1; // Success
        return;
    }

    kprintln!(
        "A32 Syscall: {} (R12: {:x}, PC: {:x})",
        syscall_num,
        r12,
        frame.elr
    );

    // Set Carry flag (bit 29) in SPSR to indicate success or failure.
    // XNU/BSD Convention: Carry Clear (0) = Success, Carry Set (1) = Error.
    // Arguments: r0 = error code (if error) or return value (if success).

    // Default to success (Clear Carry)
    frame.spsr &= !(1 << 29);

    if syscall_num < 0 {
        // Handle standard Mach traps (negative numbers).
        // Mach traps usually return kern_return_t in r0.
        // Logic: if r0 != 0 (KERN_SUCCESS), should we set Carry?
        // Actually, Mach traps might not use the Carry convention like BSD.
        // They are often bare function calls.
        // But for A32 SVC, let's assume standard AAPCS/Mach convention.
        // Usually Mach traps just return the value in r0.
        let trap_num = syscall_num.wrapping_neg();
        handle_mach_trap(frame, trap_num);
    } else {
        handle_bsd_syscall(frame, syscall_num);
        // Check if syscall handler set r0 to error?
        // My handlers mostly set r0=0 for success.
        // If I want to return error, I should set Carry.
        // For now, assume handlers return 0 on success.
        // If handler wanted to fail, it should have returned -1?
        // Actually handlers in this code modify frame.x[0] directly.
        // If frame.x[0] is large (pointer), it's clearly not an error code.
    }
}

fn handle_mach_trap(frame: &mut TrapFrame, trap_num: i32) {
    match trap_num {
        3 => {
            // mach_port_allocate (stub)
            frame.x[0] = 0; // KERN_SUCCESS
        }
        26 => {
            // mach_reply_port
            frame.x[0] = 2; // Port 2
        }
        27 => {
            // thread_self_trap
            frame.x[0] = 3; // Port 3
        }
        28 => {
            // task_self_trap
            frame.x[0] = 1; // Port 1
        }
        29 => {
            // host_self_trap
            frame.x[0] = 4; // Port 4
        }
        31 => {
            // mach_msg_trap
            let msg = frame.x[0];
            let option = frame.x[1];
            kprintln!("mach_msg_trap: msg={:x}, option={:x}", msg, option);
            frame.x[0] = 0; // Success
        }
        10 | 11 | -10 | -11 => {
            // vm_allocate
            let addr_ptr = frame.x[1] as u64;
            let size = frame.x[2] as u64;
            let anywhere = frame.x[3] != 0;

            kprintln!(
                "vm_allocate: ptr={:x}, size={:x}, anywhere={}",
                addr_ptr,
                size,
                anywhere
            );

            static NEXT_HEAP: core::sync::atomic::AtomicU64 =
                core::sync::atomic::AtomicU64::new(0x8000_0000);

            unsafe {
                let mut addr = core::ptr::read_unaligned(addr_ptr as *const u32) as u64;
                if anywhere || addr == 0 {
                    addr = NEXT_HEAP.fetch_add(size, core::sync::atomic::Ordering::Relaxed);
                }

                crate::mmu::map_range(addr, addr, size, crate::mmu::MapPermission::UserRW);
                *(addr_ptr as *mut u32) = addr as u32;
            }

            frame.x[0] = 0; // KERN_SUCCESS
        }
        12 | -12 => {
            // vm_deallocate
            frame.x[0] = 0;
        }
        13 | -13 => {
            // vm_map
            let addr_ptr = frame.x[1] as u64;
            let size = frame.x[2] as u64;

            kprintln!("vm_map: ptr={:x}, size={:x}", addr_ptr, size);

            static NEXT_MAP: core::sync::atomic::AtomicU64 =
                core::sync::atomic::AtomicU64::new(0x9000_0000);

            unsafe {
                let mut addr = core::ptr::read_unaligned(addr_ptr as *const u32) as u64;
                if addr == 0 {
                    addr = NEXT_MAP.fetch_add(size, core::sync::atomic::Ordering::Relaxed);
                }
                crate::mmu::map_range(addr, addr, size, crate::mmu::MapPermission::UserRW);
                *(addr_ptr as *mut u32) = addr as u32;
            }
            frame.x[0] = 0;
        }
        61 => {
            frame.x[0] = 1; // Success
        }
        _ => {
            kprintln!("Unknown Mach trap: {}", trap_num);
            frame.x[0] = 0x10000003; // mach_send_invalid_dest?
        }
    }
}

fn sys_write(fd: u64, buf: u64, len: u64) {
    if fd == 1 || fd == 2 || fd == 4 {
        let slice = unsafe { core::slice::from_raw_parts(buf as *const u8, len as usize) };
        if let Ok(s) = core::str::from_utf8(slice) {
            kprintln!("sys_write: {}", s);
        } else {
            // Print invalid UTF-8 as raw bytes or lossy
            // kprintln!("sys_write: invalid utf8");
            // kprintln!("sys_write (raw): {:?}", slice);
            if let Ok(s) = core::str::from_utf8(slice) {
                // print!("{}", s); // Print to UART - unavailable in no_std
                kprintln!("sys_write: {}", s);
            };
            // let s_lossy = String::from_utf8_lossy(slice);
            // kprintln!("sys_write (lossy): {}", s_lossy);
        }
    } else {
        kprintln!("sys_write: fd {} not supported", fd);
    }
}

fn handle_bsd_syscall(frame: &mut TrapFrame, syscall_num: i32) {
    kprintln!(
        "BSD Syscall {}: r0={:x} r1={:x} r2={:x} r3={:x} r4={:x} r5={:x}",
        syscall_num,
        frame.x[0],
        frame.x[1],
        frame.x[2],
        frame.x[3],
        frame.x[4],
        frame.x[5]
    );
    match syscall_num {
        0 => {
            // indir syscall
            // x0 is the syscall number, x1...x6 are the arguments
            let real_syscall = frame.x[0];
            kprintln!("Indirect syscall: {}", real_syscall);

            // Save original registers to satisfy DARWIN/AAPCS convention
            let mut saved = [0u64; 6];
            for i in 0..6 {
                saved[i] = frame.x[i];
            }

            // Shift arguments: r1 -> r0, r2 -> r1, etc.
            for i in 0..6 {
                frame.x[i] = frame.x[i + 1];
            }

            handle_bsd_syscall(frame, real_syscall as i32);

            // After syscall, r0 has return value. Restore r1..r5.
            for i in 1..6 {
                frame.x[i] = saved[i];
            }
            kprintln!(
                "After restore: r0={:x} r5={:x} (saved[5]={:x})",
                frame.x[0],
                frame.x[5],
                saved[5]
            );
        }
        1 => sys_exit(),
        3 => {
            // read(fd, buf, nbyte)
            let fd = frame.x[0];
            let buf = frame.x[1];
            let nbyte = frame.x[2];

            if fd == 100 {
                // Reading shared cache.
                let cache_base = 0x30000000 as *const u8;
                unsafe {
                    core::ptr::copy_nonoverlapping(cache_base, buf as *mut u8, nbyte as usize);
                }
                frame.x[0] = nbyte;
                kprintln!("sys_read: fd=100 read {} bytes from cache", nbyte);
            } else {
                // For other files (like /dev/random), return some dummy data
                unsafe {
                    core::ptr::write_bytes(buf as *mut u8, 0x42, nbyte as usize);
                }
                frame.x[0] = nbyte;
                kprintln!("sys_read: fd={} read {} bytes (dummy content)", fd, nbyte);
            }
        }
        4 => sys_write(frame.x[0], frame.x[1], frame.x[2]),
        5 => {
            // open(path, flags, mode)
            let path_ptr = frame.x[0];
            let slice = unsafe { core::slice::from_raw_parts(path_ptr as *const u8, 256) };
            let len = slice.iter().position(|&c| c == 0).unwrap_or(256);
            if let Ok(path) = core::str::from_utf8(&slice[..len]) {
                kprintln!("sys_open: {}", path);
                if path.contains("dyld_shared_cache") {
                    frame.x[0] = 100;
                    return;
                }
            } else {
                kprintln!("sys_open: <invalid utf8>");
            }
            frame.x[0] = 3; // Give back a fake FD generic
        }
        6 => {
            // close(fd)
            frame.x[0] = 0;
        }
        20 => frame.x[0] = sys_getpid(),
        74 => {
            // mprotect(addr, len, prot)
            frame.x[0] = 0;
        }
        116 => {
            // gettimeofday(tp, tzp)
            frame.x[0] = 0;
        }
        153 => {
            // pread(fd, buf, nbyte, offset)
            // AArch32 convention for 64-bit off_t in Syscall:
            // Standard: r0=fd, r1=buf, r2=nbyte, r3=pad?, r4=off_lo, r5=off_hi
            // HOWEVER, based on logs:
            // BSD Syscall 153: r0=65 r1=5faffaf8 r2=1000 r3=0 r4=0 r5=1000
            // r5 matches r2 (nbyte). This suggests offset might be r3/r4?

            let fd = frame.x[0];
            let buf = frame.x[1];
            let nbyte = frame.x[2];

            let mut offset = frame.x[4] | (frame.x[5] << 32);

            if offset == 0x1000_0000_0000 {
                // Suspicious pattern: r5 == r2. Assume r3/r4 is the offset.
                offset = frame.x[3] | (frame.x[4] << 32);
            }

            if fd == 100 {
                let cache_base = (0x30000000 + offset) as *const u8;
                unsafe {
                    core::ptr::copy_nonoverlapping(cache_base, buf as *mut u8, nbyte as usize);
                }
                frame.x[0] = nbyte;
            } else {
                frame.x[0] = 0;
            }
            kprintln!(
                "sys_pread: fd={} buf={:08x} nbyte={:x} offset={:x} -> return {:x}",
                fd,
                buf,
                nbyte,
                offset,
                frame.x[0]
            );
        }
        169 => {
            // csops(pid, ops, useraddr, usersize)
            let pid = frame.x[0];
            let ops = frame.x[1];
            kprintln!("sys_csops: pid={}, ops={}", pid, ops);
            frame.x[0] = 0; // Success
        }
        189 => {
            // fstat64(fd, stat)
            let fd = frame.x[0];
            let stat_ptr = frame.x[1];
            if fd == 100 {
                populate_stat64(stat_ptr, 200 * 1024 * 1024);
                frame.x[0] = 0;
            } else {
                populate_stat64(stat_ptr, 0); // e.g. stdout
                frame.x[0] = 0;
            }
        }
        197 => {
            // mmap(addr, len, prot, flags, fd, pos)
            let addr = frame.x[0];
            let len = frame.x[1];
            let fd = frame.x[4];
            kprintln!("sys_mmap: addr={:x}, len={:x}, fd={}", addr, len, fd);

            if fd == 100 {
                // Mapping shared cache!
                kprintln!("sys_mmap: mapping shared cache at 0x30000000");
                frame.x[0] = 0x30000000;
            } else {
                // Anonymous mapping or other file
                if addr != 0 {
                    use crate::mmu::{MapPermission, map_range};
                    use alloc::alloc::{Layout, alloc_zeroed};
                    let layout = Layout::from_size_align(len as usize, 4096).unwrap();
                    let ptr = unsafe { alloc_zeroed(layout) };
                    if !ptr.is_null() {
                        unsafe {
                            map_range(addr, ptr as u64, len, MapPermission::UserRW);
                        }
                        frame.x[0] = addr;
                    } else {
                        frame.x[0] = 0;
                    }
                } else {
                    frame.x[0] = 0;
                }
            }
        }
        199 => {
            // shmsys
            frame.x[0] = 0;
        }
        202 => {
            // sysctl(name, namelen, oldp, oldlenp, newp, newlen)
            // Args (A32): r0=name, r1=namelen, r2=oldp, r3=oldlenp, r4=newp, r5=newlen
            let name_ptr = frame.x[0];
            let namelen = frame.x[1];
            let oldp = frame.x[2];
            let oldlenp = frame.x[3];

            kprintln!("sys_sysctl: name={:x}, len={}", name_ptr, namelen);

            unsafe {
                if namelen >= 2 {
                    let mib = core::slice::from_raw_parts(name_ptr as *const i32, namelen as usize);
                    kprintln!("sysctl mib: {:?}", mib);

                    // HW_PAGESIZE (CTL_HW=6, HW_PAGESIZE=7)
                    if mib[0] == 6 && mib[1] == 7 {
                        if oldp != 0 && oldlenp != 0 {
                            *(oldp as *mut u32) = 4096;
                            *(oldlenp as *mut u32) = 4;
                        }
                        frame.x[0] = 0; // Success
                        return;
                    }
                }
            }
            frame.x[0] = 0; // Determine if we should fail or fake success?
            // Returning 0 (success) might be safer than failure for unknown sysctls.
        }
        24 => {
            // getuid
            frame.x[0] = 0;
        }
        25 => {
            // geteuid
            frame.x[0] = 0;
        }
        43 => {
            // getegid
            frame.x[0] = 0;
        }
        47 => {
            // getgid
            frame.x[0] = 0;
        }
        126 => {
            // getegid (alternate number?) or setegid?
            // Actually getegid is often 43.
            // But let's check logs. dyld calls 126.
            frame.x[0] = 0;
        }
        157 => {
            // getfsstat
            frame.x[0] = 0;
        }
        220 => {
            // getattrlist
            frame.x[0] = 0;
        }
        33 => {
            // access(path, flags)
            frame.x[0] = 0; // Success (file exists/accessible)
        }
        190 => {
            // lstat
            // Similar to stat64 but checks symlinks
            let path_ptr = frame.x[0];
            let stat_ptr = frame.x[1];
            // Reuse stat logic?
            let slice = unsafe { core::slice::from_raw_parts(path_ptr as *const u8, 256) };
            let len = slice.iter().position(|&c| c == 0).unwrap_or(256);
            if let Ok(path) = core::str::from_utf8(&slice[..len]) {
                kprintln!("sys_lstat: {}", path);
                if path.contains("dyld_shared_cache") {
                    populate_stat64(stat_ptr, 200 * 1024 * 1024);
                    frame.x[0] = 0;
                    return;
                }
            }
            frame.x[0] = -1i64 as u64;
            // IMPORTANT: Set Carry Flag?
            // If we return -1, we should Set Carry.
            // But for now, we rely on the generic carry logic (SUCCESS default).
            // To fail, we MUST set carry.
            frame.spsr |= 1 << 29;
            frame.x[0] = 2; // ENOENT
        }
        327 => {
            // issetugid
            frame.x[0] = 0; // Not setuid
        }
        294 => {
            // shared_region_check_np(uintptr_t *address)
            let addr_ptr = frame.x[0];
            if addr_ptr != 0 {
                unsafe {
                    // Write shared cache base to user pointer
                    let val: u32 = 0x30000000;
                    core::ptr::write_volatile(addr_ptr as *mut u32, val);

                    // Memory barriers to ensure user-space sees the write
                    core::arch::asm!("dsb sy", "isb");

                    let verify = *(addr_ptr as *const u32);
                    kprintln!(
                        "sys_shared_region_check_np: wrote 0x30000000 to user addr {:x}, verify: {:x}",
                        addr_ptr,
                        verify
                    );

                    // Dump first 32 bytes of shared cache header to verify mapping
                    let cache_ptr = 0x30000000 as *const u32;
                    kprintln!(
                        "Cache header: {:08x} {:08x} {:08x} {:08x}",
                        *cache_ptr.add(0),
                        *cache_ptr.add(1),
                        *cache_ptr.add(2),
                        *cache_ptr.add(3)
                    );
                }
            }
            frame.x[0] = 0; // Success
        }
        338 => {
            // stat64_extended(path, stat, flags) ? Or just stat64(path, stat)?
            // In ARMv7, r0=path, r1=stat.
            let path_ptr = frame.x[0];
            let stat_ptr = frame.x[1];

            let slice = unsafe { core::slice::from_raw_parts(path_ptr as *const u8, 256) };
            let len = slice.iter().position(|&c| c == 0).unwrap_or(256);
            if let Ok(path) = core::str::from_utf8(&slice[..len]) {
                kprintln!("sys_stat64: {}", path);
                if path.contains("dyld_shared_cache") {
                    populate_stat64(stat_ptr, 200 * 1024 * 1024);
                    frame.x[0] = 0;
                    return;
                }
            }
            frame.x[0] = -1i64 as u64; // Not found
        }
        37 => {
            // kill(pid, sig) - ignore for now
            let pid = frame.x[0];
            let sig = frame.x[1];
            kprintln!("sys_kill: pid={}, sig={} (ignored)", pid, sig);
            frame.x[0] = 0; // Success
        }
        46 => {
            // sigaction(signum, act, oldact) - stub
            let signum = frame.x[0];
            kprintln!("sys_sigaction: signum={} (stub)", signum);
            frame.x[0] = 0; // Success
        }
        48 => {
            // sigprocmask(how, set, oset) - stub
            let how = frame.x[0];
            kprintln!("sys_sigprocmask: how={} (stub)", how);
            frame.x[0] = 0; // Success
        }
        54 => {
            // ioctl(fd, cmd, arg - stub
            let fd = frame.x[0];
            let cmd = frame.x[1];
            kprintln!("sys_ioctl: fd={}, cmd={:x} (stub)", fd, cmd);
            frame.x[0] = 0; // Success
        }
        423 => {
            // sem_open(name, oflag, mode, value) - return fake semaphore handle
            kprintln!("sys_sem_open (stub, returning fake handle)");
            frame.x[0] = 0x1000; // Fake semaphore handle
        }
        _ => {
            kprintln!(
                "Unknown BSD syscall: {} PC: {:x} R0: {:x} R1: {:x}",
                syscall_num,
                frame.elr,
                frame.x[0],
                frame.x[1]
            );
            frame.x[0] = (-1i32 as u32) as u64; // Error
        }
    }
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
    let scheduler = SCHEDULER.lock();
    if let Some(p) = &scheduler.current_process {
        p.pid
    } else {
        0
    }
}

pub fn init_vectors() {
    unsafe extern "C" {
        static vectors: u8;
    }
    unsafe {
        asm!("msr vbar_el1, {}", in(reg) &vectors);
    }
}
