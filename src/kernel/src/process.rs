use crate::kprintln;
use crate::scheduler::SCHEDULER;
use core::arch::asm;

#[repr(C)]
#[derive(Debug, Default)]
pub struct TrapFrame {
    pub x: [u64; 31],
    pub __padding: u64,
    pub elr: u64,
    pub spsr: u64,
    pub sp_el0: u64,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct CpuContext {
    pub regs: [u64; 13], // x19..x28, x29, sp, x30
}

static mut EXCEPTION_COUNT: u32 = 0;
static mut IN_EXCEPTION: bool = false;

#[unsafe(no_mangle)]
pub extern "C" fn handle_sync_exception(frame: &mut TrapFrame) {
    unsafe {
        if IN_EXCEPTION {
            // Recursive exception!
            kprintln!(
                "RECURSIVE EXCEPTION! SPSR: {:x} PC: {:x} FAR: {:x}",
                frame.spsr,
                frame.elr,
                0 // FAR
            );
            loop {
                asm!("wfe")
            }
        }
        IN_EXCEPTION = true;
        EXCEPTION_COUNT += 1;
        if EXCEPTION_COUNT > 1000 {
            loop {
                asm!("wfe")
            }
        }
    }

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
            handle_a32_syscall(frame, iss as u32);
        }
        _ => {
            let is_a32 = (frame.spsr & 0x10) != 0;
            let pc = if is_a32 && (frame.spsr & 0x20) != 0 {
                frame.elr | 1 // Thumb
            } else {
                frame.elr
            };
            kprintln!(
                "Unknown exception! ESR: {:x} EC: {:x} ISS: {:x} FAR: {:x} PC: {:x} SPSR: {:x}",
                esr,
                ec,
                iss,
                far,
                pc,
                frame.spsr
            );

            dump_registers(frame);

            kprintln!("sp_el0={:016x}", frame.sp_el0);

            // Dump code around PC
            kprintln!("Code at PC:");
            dump_mem((pc & !0x3F).saturating_sub(64), 128);

            // Dump stack
            kprintln!("Stack at SP:");
            dump_mem(frame.sp_el0 & !0x3F, 256);

            // Dump memory around FAR if it was a data abort
            if ec == 0x24 || ec == 0x25 {
                kprintln!("Data at FAR ({:x}):", far);
                dump_mem(far & !0x3F, 128);
            }

            unsafe {
                IN_EXCEPTION = false;
            }
            loop {
                unsafe { asm!("wfe") }
            }
        }
    }
    unsafe {
        IN_EXCEPTION = false;
    }
}

fn dump_registers(frame: &TrapFrame) {
    // Print registers with AArch32 aliases for clarity
    for i in 0..15 {
        let name = match i {
            13 => "sp/r13",
            14 => "lr/r14",
            _ => {
                if i <= 12 {
                    [
                        "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11",
                        "r12",
                    ][i]
                } else {
                    ""
                }
            }
        };
        kprintln!("x{:02} ({:6}) = {:016x}", i, name, frame.x[i]);
    }
    for i in 15..31 {
        kprintln!("x{:02}          = {:016x}", i, frame.x[i]);
    }
}

fn dump_mem(addr: u64, len: u64) {
    for i in (0..len).step_by(16) {
        let curr = addr + i;
        // Basic safety check for known mapped user/kernel regions
        let is_ram = (0x20000000..0x80000000).contains(&curr);
        let is_io = (0x09000000..0x09001000).contains(&curr); // UART
        let is_low = (0..0x20000000).contains(&curr); // Low mem (app + dyld + heap)
        let is_sc = (0x30000000..0x40000000).contains(&curr); // Shared cache

        if !is_ram && !is_io && !is_low && !is_sc {
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

fn handle_a32_syscall(frame: &mut TrapFrame, iss: u32) {
    let r12 = frame.x[12] as i32;
    let r7 = frame.x[7] as i32;

    // In AArch32 iOS/macOS:
    // SVC 0x80 (ISS=0x80) always uses R12 for the syscall number.
    // SVC 0 (ISS=0) usually uses R7 for BSD syscalls.
    let syscall_num = if iss == 0x80 { r12 } else { r7 };

    if syscall_num != 4 {
        // Don't spam write
        kprintln!(
            "A32 Syscall: num={} (ISS={:x}) R0={:x} R1={:x} R2={:x} R3={:x} R4={:x} PC={:x}",
            syscall_num,
            iss,
            frame.x[0],
            frame.x[1],
            frame.x[2],
            frame.x[3],
            frame.x[4],
            frame.elr
        );
    }

    if syscall_num < 0 || syscall_num as u32 == 0x80000000 {
        // Mach trap
        handle_a32_mach_trap(frame, syscall_num, iss);
    } else {
        // BSD syscall
        handle_a32_syscall_internal(frame, syscall_num);
    }
}

fn handle_a32_mach_trap(frame: &mut TrapFrame, syscall_num: i32, _iss: u32) {
    let res = match syscall_num {
        -3 => {
            // mach_absolute_time
            let cnt: u64;
            unsafe {
                asm!("mrs {}, cntpct_el0", out(reg) cnt);
            }
            frame.x[0] = cnt & 0xFFFFFFFF;
            frame.x[1] = cnt >> 32;
            return; // Already set x0, x1
        }
        -2147483648 => {
            // Mach trap 0
            0
        }
        -26 => {
            // mach_reply_port
            let mut sched = SCHEDULER.lock();
            if let Some(space) = sched.current_ipc_space() {
                space.allocate_port() as u64
            } else {
                0x200
            }
        }
        -27 => {
            // thread_self_trap
            3
        }
        -28 => {
            // task_self_trap
            2
        }
        -29 => {
            // host_self_trap
            1
        }
        -31 => {
            // mach_msg_trap(msg, option, send_size, rcv_size, rcv_name, timeout, notify)
            let msg = frame.x[0] as *mut crate::ipc::MachMsgHeader;
            let option = frame.x[1] as u32;
            let send_size = frame.x[2] as u32;
            let rcv_size = frame.x[3] as u32;
            let rcv_name = frame.x[4] as u32;
            let timeout = frame.x[5] as u32;

            if !msg.is_null() && (option & crate::ipc::MACH_SEND_MSG) != 0 {
                let h = unsafe { *msg };
                kprintln!(
                    "mach_msg_trap SEND: id={:x} remote={:x} local={:x} size={:x} bits={:x}",
                    h.msgh_id,
                    h.msgh_remote_port,
                    h.msgh_local_port,
                    h.msgh_size,
                    h.msgh_bits
                );
                // Dump first 24 bytes of message
                dump_mem(frame.x[0], 24);
            }

            let mut sched = SCHEDULER.lock();
            if let Some(space) = sched.current_ipc_space() {
                let res = crate::ipc::mach_msg(
                    msg, option, send_size, rcv_size, rcv_name, timeout, 0, space,
                );

                if res == 0 && (option & crate::ipc::MACH_RCV_MSG) != 0 {
                    unsafe {
                        let mut header = core::ptr::read_volatile(msg);
                        header.msgh_local_port = rcv_name;
                        core::ptr::write_volatile(msg, header);

                        kprintln!(
                            "mach_msg_trap RCV: id={:x} remote={:x} local={:x} size={:x} bits={:x}",
                            header.msgh_id,
                            header.msgh_remote_port,
                            header.msgh_local_port,
                            header.msgh_size,
                            header.msgh_bits
                        );
                        dump_mem(frame.x[0], 24);
                    }
                }
                res as u64
            } else {
                0x10000003
            }
        }
        -89 => {
            // mach_timebase_info_trap
            let info_ptr = frame.x[0] as *mut u32;
            if !info_ptr.is_null() {
                let freq: u64;
                unsafe {
                    asm!("mrs {}, cntfrq_el0", out(reg) freq);
                }
                unsafe {
                    *info_ptr = 1_000_000_000; // numer
                    *info_ptr.add(1) = freq as u32; // denom
                }
            }
            0
        }
        _ => {
            kprintln!("Unknown Mach trap: {}", syscall_num);
            0
        }
    };
    frame.x[0] = res;
    kprintln!("Mach trap {} returned {:x}", syscall_num, res);
}

fn handle_a32_syscall_internal(frame: &mut TrapFrame, syscall_num: i32) {
    match syscall_num {
        0 => {
            // syscall(num, ...)
            let real_num = frame.x[0] as i32;
            frame.x[0] = frame.x[1];
            frame.x[1] = frame.x[2];
            frame.x[2] = frame.x[3];
            frame.x[3] = frame.x[4];
            handle_a32_syscall_internal(frame, real_num);
        }
        1 => sys_exit(),
        3 => {
            // read(fd, buf, len)
            let fd = frame.x[0] as usize;
            let buf_ptr = frame.x[1] as *mut u8;
            let len = frame.x[2] as usize;

            let mut sched = SCHEDULER.lock();
            let mut read_len = 0;
            if let Some(proc) = sched.current_process.as_mut()
                && fd < proc.files.len()
                && let Some(handle) = &mut proc.files[fd]
            {
                let slice = unsafe { core::slice::from_raw_parts_mut(buf_ptr, len) };
                read_len = handle.read(slice);
            }
            frame.x[0] = read_len as u64;
            frame.spsr &= !0x20000000;
        }
        4 => sys_write(frame.x[0], frame.x[1], frame.x[2]),
        5 => {
            // open(path, flags, mode)
            let path_ptr = frame.x[0] as *const u8;
            let mut path_buf = [0u8; 128];
            let mut i = 0;
            while i < 127 {
                let c = unsafe { core::ptr::read(path_ptr.add(i)) };
                if c == 0 {
                    break;
                }
                path_buf[i] = c;
                i += 1;
            }
            let path_str = core::str::from_utf8(&path_buf[..i]).unwrap_or("invalid");
            kprintln!("sys_open: {}", path_str);

            if let Some(handle) = crate::vfs::open(path_str) {
                let mut sched = SCHEDULER.lock();
                if let Some(proc) = sched.current_process.as_mut() {
                    let mut found_fd = None;
                    for (fd, slot) in proc.files.iter_mut().enumerate() {
                        if slot.is_none() {
                            *slot = Some(handle);
                            found_fd = Some(fd);
                            break;
                        }
                    }
                    if let Some(fd) = found_fd {
                        frame.x[0] = fd as u64;
                        frame.spsr &= !0x20000000;
                    } else {
                        frame.x[0] = 24; // EMFILE
                        frame.spsr |= 0x20000000;
                    }
                }
            } else {
                frame.x[0] = 2; // ENOENT
                frame.spsr |= 0x20000000;
            }
        }
        6 => {
            // close(fd)
            let fd = frame.x[0] as usize;
            let mut sched = SCHEDULER.lock();
            if let Some(proc) = sched.current_process.as_mut()
                && fd < proc.files.len()
            {
                proc.files[fd] = None;
            }
            frame.x[0] = 0;
            frame.spsr &= !0x20000000;
        }
        20 => {
            // getpid
            let pid = {
                let sched = SCHEDULER.lock();
                sched.current_process.as_ref().map(|p| p.pid).unwrap_or(0)
            };
            frame.x[0] = pid;
            frame.spsr &= !0x20000000;
        }
        24 => {
            frame.x[0] = 501;
            frame.spsr &= !0x20000000;
        } // getuid
        25 => {
            frame.x[0] = 501;
            frame.spsr &= !0x20000000;
        } // geteuid
        26 => {
            frame.x[0] = 20;
            frame.spsr &= !0x20000000;
        } // getgid
        33 => {
            // access(path, mode)
            frame.x[0] = 2; // ENOENT
            frame.spsr |= 0x20000000;
        }
        37 => {
            // kill
            let pid = frame.x[0] as i32;
            let sig = frame.x[1] as i32;
            kprintln!("A32 Syscall: num=37 (kill) pid={} sig={}", pid, sig);
            frame.x[0] = 0;
            frame.spsr &= !0x20000000;

            if sig == 6 || sig == 9 {
                kprintln!("Process {} killed/aborted. Stopping execution.", pid);
                loop {
                    unsafe { asm!("wfe") }
                }
            }
        }
        43 => {
            frame.x[0] = 20;
            frame.spsr &= !0x20000000;
        } // getegid
        46 => {
            // sigaction
            frame.x[0] = 0;
            frame.spsr &= !0x20000000;
        }
        48 => {
            // sigprocmask(how, set, oset)
            let how = frame.x[0] as i32;
            let set_ptr = frame.x[1] as *const u32;
            let oset_ptr = frame.x[2] as *mut u32;

            let mut sched = SCHEDULER.lock();
            if let Some(proc) = sched.current_process.as_mut() {
                if !oset_ptr.is_null() {
                    unsafe {
                        core::ptr::write(oset_ptr, proc.signal_mask);
                    }
                }

                if !set_ptr.is_null() {
                    let set = unsafe { core::ptr::read(set_ptr) };
                    match how {
                        1 => proc.signal_mask |= set,  // SIG_BLOCK
                        2 => proc.signal_mask &= !set, // SIG_UNBLOCK
                        3 => proc.signal_mask = set,   // SIG_SETMASK
                        _ => {
                            frame.x[0] = 22; // EINVAL
                            frame.spsr |= 0x20000000;
                            return;
                        }
                    }
                }
                frame.x[0] = 0;
                frame.spsr &= !0x20000000;
            } else {
                frame.x[0] = 1; // EPERM/ESRCH
                frame.spsr |= 0x20000000;
            }
        }
        54 => {
            // ioctl
            frame.x[0] = 0;
            frame.spsr &= !0x20000000;
        }
        58 => {
            // readlink
            frame.x[0] = 2; // ENOENT
            frame.spsr |= 0x20000000;
        }
        73 => {
            // munmap(addr, len)
            frame.x[0] = 0;
            frame.spsr &= !0x20000000;
        }
        74 => {
            // mprotect(addr, len, prot)
            frame.x[0] = 0;
            frame.spsr &= !0x20000000;
        }
        92 => {
            // fcntl
            frame.x[0] = 0;
            frame.spsr &= !0x20000000;
        }
        100 => {
            // getpriority
            frame.x[0] = 0;
            frame.spsr &= !0x20000000;
        }
        116 => {
            // gettimeofday
            let tv = frame.x[0] as *mut u32;
            if !tv.is_null() {
                static mut SEC: u32 = 1643328000; // Jan 27 2022-ish
                static mut USEC: u32 = 0;
                unsafe {
                    USEC += 1000;
                    if USEC >= 1000000 {
                        USEC = 0;
                        SEC += 1;
                    }
                    core::ptr::write_volatile(tv, SEC);
                    core::ptr::write_volatile(tv.add(1), USEC);
                }
            }
            frame.x[0] = 0;
            frame.spsr &= !0x20000000;
        }
        126 => {
            // setreuid
            frame.x[0] = 0;
            frame.spsr &= !0x20000000;
        }
        153 => {
            // pread(fd, buf, len, offset)
            let fd = frame.x[0] as usize;
            let buf_ptr = frame.x[1] as *mut u8;
            let len = frame.x[2] as usize;

            let mut sched = SCHEDULER.lock();
            let mut read_len = 0;
            if let Some(proc) = sched.current_process.as_mut()
                && fd < proc.files.len()
                && let Some(handle) = &mut proc.files[fd]
            {
                let slice = unsafe { core::slice::from_raw_parts_mut(buf_ptr, len) };
                read_len = handle.read(slice);
            }
            frame.x[0] = read_len as u64;
            frame.spsr &= !0x20000000;
        }
        196 => {
            // getdirentries
            frame.x[0] = 0; // End of entries
            frame.spsr &= !0x20000000;
        }
        197 => {
            // mmap(addr, len, prot, flags, fd, offset)
            let addr = frame.x[0];
            let len = frame.x[1];
            let fd = frame.x[4] as i32;

            let map_addr = if addr == 0 {
                static mut NEXT_MMAP: u64 = 0x70000000;
                unsafe {
                    let res = NEXT_MMAP;
                    NEXT_MMAP += (len + 0xFFF) & !0xFFF;
                    res
                }
            } else {
                addr
            };

            // Allocate physical memory for the mapping from heap
            let layout = core::alloc::Layout::from_size_align(len as usize, 4096).unwrap();
            let phys_ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
            if phys_ptr.is_null() {
                frame.x[0] = 12; // ENOMEM
                frame.spsr |= 0x20000000;
                return;
            }
            let paddr = phys_ptr as u64;

            crate::mmu::map_range(map_addr, paddr, len, crate::mmu::MapPermission::UserRWX);

            if fd != -1 {
                let mut sched = SCHEDULER.lock();
                if let Some(proc) = sched.current_process.as_mut() {
                    let fd = fd as usize;
                    if fd < proc.files.len()
                        && let Some(handle) = &mut proc.files[fd]
                    {
                        let slice = unsafe {
                            core::slice::from_raw_parts_mut(map_addr as *mut u8, len as usize)
                        };
                        handle.read(slice);
                    }
                }
            }

            frame.x[0] = map_addr;
            frame.spsr &= !0x20000000;
        }
        202 => {
            // sysctl
            let name = frame.x[0] as *const i32;
            let namelen = frame.x[1] as u32;
            let oldp = frame.x[2] as *mut u8;
            let oldlenp = frame.x[3] as *mut u32;

            if namelen >= 2 {
                let m0 = unsafe { *name };
                let m1 = unsafe { *name.add(1) };
                if m0 == 1 {
                    // CTL_KERN
                    match m1 {
                        1 => {
                            // KERN_OSTYPE
                            if !oldp.is_null() {
                                unsafe {
                                    core::ptr::copy_nonoverlapping(b"Darwin\0".as_ptr(), oldp, 7);
                                }
                            }
                        }
                        4 => {
                            // KERN_VERSION
                            if !oldp.is_null() {
                                unsafe {
                                    core::ptr::copy_nonoverlapping(
                                        b"Darwin Kernel Version 11.0.0\0".as_ptr(),
                                        oldp,
                                        29,
                                    );
                                }
                            }
                        }
                        8 => {
                            // KERN_ARGMAX
                            if !oldp.is_null() {
                                unsafe {
                                    *(oldp as *mut u32) = 262144;
                                }
                            }
                        }
                        35 => {
                            // KERN_POSIX_HIRES_TIMER
                            if !oldp.is_null() {
                                unsafe {
                                    *(oldp as *mut u32) = 1;
                                }
                            }
                        }
                        14 => {
                            // KERN_PROC
                            frame.x[0] = 2; // ENOENT
                            frame.spsr |= 0x20000000;
                            return;
                        }
                        _ => {}
                    }
                }
                if m0 == 6 {
                    // CTL_HW
                    match m1 {
                        2 => {
                            // HW_PAGESIZE
                            if !oldp.is_null() {
                                unsafe {
                                    *(oldp as *mut u32) = 4096;
                                }
                            }
                            if !oldlenp.is_null() {
                                unsafe {
                                    *oldlenp = 4;
                                }
                            }
                        }
                        3 => {
                            // HW_NCPU
                            if !oldp.is_null() {
                                unsafe {
                                    *(oldp as *mut u32) = 1;
                                }
                            }
                            if !oldlenp.is_null() {
                                unsafe {
                                    *oldlenp = 4;
                                }
                            }
                        }
                        24 => {
                            // HW_MEMSIZE (int64)
                            if !oldp.is_null() {
                                unsafe {
                                    *(oldp as *mut u64) = 1024 * 1024 * 1024;
                                }
                            }
                            if !oldlenp.is_null() {
                                unsafe {
                                    *oldlenp = 8;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            frame.x[0] = 0;
            frame.spsr &= !0x20000000;
        }
        220 => {
            // getattrlist
            frame.x[0] = 2; // ENOENT
            frame.spsr |= 0x20000000;
        }
        274 => {
            // sysctlbyname(name, oldp, oldlenp, newp, newlen)
            let name_ptr = frame.x[0] as *const u8;
            let mut name_buf = [0u8; 64];
            let mut i = 0;
            while i < 63 {
                let c = unsafe { core::ptr::read(name_ptr.add(i)) };
                if c == 0 {
                    break;
                }
                name_buf[i] = c;
                i += 1;
            }
            if let Ok(name) = core::str::from_utf8(&name_buf[..i]) {
                kprintln!("A32 Syscall: num=274 (sysctlbyname) name='{}'", name);
            }

            frame.x[0] = 2; // ENOENT
            frame.spsr |= 0x20000000;
        }
        281 => {
            // sigaltstack
            frame.x[0] = 0;
            frame.spsr &= !0x20000000;
        }
        294 => {
            // shared_region_check_np(uint64_t *start_address)
            kprintln!(
                "A32 Syscall: num=294 (shared_region_check_np) ptr={:x}",
                frame.x[0]
            );
            let ptr = frame.x[0] as *mut u64;
            // Return the address where we mapped the cache
            unsafe {
                *ptr = 0x30000000;
            }
            frame.x[0] = 0; // Success
            frame.spsr &= !0x20000000;
        }
        -3 => {
            // mach_absolute_time()
            // Return a monotonic time. For now, just a counter or generic large number.
            // AArch32 result in r0:r1.
            static mut TIME_COUNTER: u64 = 0x8000;
            let t = unsafe {
                TIME_COUNTER += 1000;
                TIME_COUNTER
            };
            frame.x[0] = t & 0xFFFFFFFF; // r0
            frame.x[1] = (t >> 32) & 0xFFFFFFFF; // r1
            frame.spsr &= !0x20000000;
        }
        -11 => {
            // mach_vm_read(target_task, address, size, &data, &msg_type)
            // This is complex as it involves VM copy.
            // For now, let's claim success but return 0 bytes read?
            // Or maybe just ENOTSUP (46) if it's not critical.
            // The crash at 2fe17e1f right after might suggest it expects valid return values.
            // Let's print arguments.
            kprintln!(
                "mach_vm_read: task={} addr={:x} size={:x} data_ptr={:x}",
                frame.x[0],
                frame.x[1],
                frame.x[2],
                frame.x[3]
            );

            // Return KERN_FAILURE (5) to indicate we didn't read anything
            frame.x[0] = 5;
            frame.spsr &= !0x20000000;
        }
        301 => {
            // psynch_mutexwait
            frame.x[0] = 0;
            frame.spsr &= !0x20000000;
        }
        316 => {
            // getentropy(buf, len)
            let buf_ptr = frame.x[0] as *mut u8;
            let len = frame.x[1] as usize;
            let slice = unsafe { core::slice::from_raw_parts_mut(buf_ptr, len) };
            for b in slice.iter_mut() {
                *b = 0x42; // "Random"
            }
            frame.x[0] = 0;
            frame.spsr &= !0x20000000;
        }
        327 => {
            // issetugid
            kprintln!("A32 Syscall: num=327 (issetugid) -> 0");
            frame.x[0] = 0;
            frame.spsr &= !0x20000000;
        }
        338 => {
            // stat64(path, buf)
            let path_ptr = frame.x[0] as *const u8;
            let stat_ptr = frame.x[1] as *mut u8;
            let mut path_buf = [0u8; 128];
            let mut i = 0;
            while i < 127 {
                let c = unsafe { core::ptr::read(path_ptr.add(i)) };
                if c == 0 {
                    break;
                }
                path_buf[i] = c;
                i += 1;
            }
            let path_str = core::str::from_utf8(&path_buf[..i]).unwrap_or("");
            if let Some(handle) = crate::vfs::open(path_str) {
                unsafe {
                    core::ptr::write_bytes(stat_ptr, 0, 100);
                    // Darwin stat64: st_size is at offset 64 (8 bytes)
                    *(stat_ptr.add(64) as *mut u64) = handle.size();
                    // st_mode is at offset 4 (2 bytes)
                    *(stat_ptr.add(4) as *mut u16) = 0o100644;
                }
                frame.x[0] = 0;
                frame.spsr &= !0x20000000;
            } else {
                frame.x[0] = 2; // ENOENT
                frame.spsr |= 0x20000000;
            }
        }
        339 => {
            // fstat64(fd, buf)
            let fd = frame.x[0] as usize;
            let stat_ptr = frame.x[1] as *mut u8;
            let mut sched = SCHEDULER.lock();
            if let Some(proc) = sched.current_process.as_mut()
                && fd < proc.files.len()
                && let Some(handle) = &proc.files[fd]
            {
                unsafe {
                    core::ptr::write_bytes(stat_ptr, 0, 100);
                    *(stat_ptr.add(64) as *mut u64) = handle.size();
                    *(stat_ptr.add(4) as *mut u16) = 0o100644;
                }
                frame.x[0] = 0;
                frame.spsr &= !0x20000000;
                return;
            }
            frame.x[0] = 9; // EBADF
            frame.spsr |= 0x20000000;
        }
        340 => {
            // lstat64
            let path_ptr = frame.x[0] as *const u8;
            let stat_ptr = frame.x[1] as *mut u8;
            let mut path_buf = [0u8; 128];
            let mut i = 0;
            while i < 127 {
                let c = unsafe { core::ptr::read(path_ptr.add(i)) };
                if c == 0 {
                    break;
                }
                path_buf[i] = c;
                i += 1;
            }
            let path_str = core::str::from_utf8(&path_buf[..i]).unwrap_or("");
            if let Some(handle) = crate::vfs::open(path_str) {
                unsafe {
                    core::ptr::write_bytes(stat_ptr, 0, 100);
                    *(stat_ptr.add(64) as *mut u64) = handle.size();
                    *(stat_ptr.add(4) as *mut u16) = 0o100644;
                }
                frame.x[0] = 0;
                frame.spsr &= !0x20000000;
            } else {
                frame.x[0] = 2; // ENOENT
                frame.spsr |= 0x20000000;
            }
        }
        423 => {
            // csops
            frame.x[0] = 0;
            frame.spsr &= !0x20000000;
        }
        388 => {
            // __mac_get_fd
            frame.x[0] = 0;
            frame.spsr &= !0x20000000;
        }
        438 => {
            // shared_region_map_and_slide_np(fd, count, mappings, slide, ...)
            let fd = frame.x[0] as usize;
            let count = frame.x[1] as usize;
            let mappings = frame.x[2] as *const crate::ipc::SharedRegionMapping;

            let slide = frame.x[3] as usize;

            kprintln!(
                "A32 Syscall: num=438 (shared_region_map_and_slide_np) fd={} count={} mappings_ptr={:x} slide={:x}",
                fd,
                count,
                frame.x[2],
                slide
            );
            dump_mem(frame.x[2], count as u64 * 32);

            let mut sched = SCHEDULER.lock();
            if let Some(proc) = sched.current_process.as_mut()
                && fd < proc.files.len()
                && let Some(handle) = &mut proc.files[fd]
            {
                let file_size = handle.size();
                for i in 0..count {
                    let m = unsafe { core::ptr::read(mappings.add(i)) };
                    kprintln!(
                        "  Mapping SR segment: addr={:x} size={:x} off={:x} prot={:x}",
                        m.address,
                        m.size,
                        m.file_offset,
                        m.init_prot
                    );

                    // Only allocate/load what's actually in the file
                    let data_size_unaligned = if m.file_offset < file_size {
                        core::cmp::min(m.size, file_size - m.file_offset)
                    } else {
                        0
                    };
                    let mut data_size =
                        core::cmp::min(m.size, (data_size_unaligned + 4095) & !4095);

                    // CLIP: Do not map into kernel space (> 1GB)
                    let max_user_addr = 0x40000000;
                    if m.address >= max_user_addr {
                        kprintln!("  Skipping segment outside user range: {:x}", m.address);
                        continue;
                    }
                    if m.address + data_size > max_user_addr {
                        kprintln!(
                            "  Clipping data part from {:x} to {:x}",
                            m.address + data_size,
                            max_user_addr
                        );
                        data_size = max_user_addr - m.address;
                    }

                    // Map the data part (file-backed)
                    if data_size > 0 {
                        let alloc_size = (data_size + 4095) & !4095;
                        let layout =
                            core::alloc::Layout::from_size_align(alloc_size as usize, 4096)
                                .unwrap();
                        let phys_ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
                        if phys_ptr.is_null() {
                            panic!(
                                "Failed to allocate physical memory for shared region segment (data size={:x})",
                                data_size
                            );
                        }
                        let paddr = phys_ptr as u64;

                        // Read data from shared cache file into the physical buffer
                        handle.seek(m.file_offset);
                        let total_to_read = core::cmp::min(data_size_unaligned, data_size) as usize;
                        let mut offset = 0;
                        while offset < total_to_read {
                            let chunk_size = core::cmp::min(1024 * 1024, total_to_read - offset);
                            let slice = unsafe {
                                core::slice::from_raw_parts_mut(
                                    (phys_ptr as usize + offset) as *mut u8,
                                    chunk_size,
                                )
                            };
                            handle.read(slice);
                            offset += chunk_size;
                        }

                        // Now map the data part to the user's address
                        crate::mmu::map_range(
                            m.address,
                            paddr,
                            data_size,
                            crate::mmu::MapPermission::UserRWX,
                        );
                    }

                    kprintln!("  Mapped segment {:x} successfully", m.address);
                }
            }

            frame.x[0] = 0; // KERN_SUCCESS
            frame.spsr &= !0x20000000;
        }
        _ => {
            kprintln!(
                "Unknown A32 syscall: num={} R0={:x} PC={:x} SP={:x} LR={:x}",
                syscall_num,
                frame.x[0],
                frame.elr,
                frame.x[13],
                frame.x[14]
            );
            kprintln!("Code at PC:");
            dump_mem((frame.elr & !0xF).saturating_sub(32), 64);
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

fn sys_write(fd: u64, buf: u64, len: u64) {
    if fd == 1 || fd == 2 || fd == 4 {
        let slice = unsafe { core::slice::from_raw_parts(buf as *const u8, len as usize) };
        if let Ok(s) = core::str::from_utf8(slice) {
            kprintln!("sys_write(fd={}): {}", fd, s);
        } else {
            kprintln!("sys_write(fd={}): [Binary Data] {:?}", fd, slice);
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
    // For now, kernel-spawned threads in EL0
    let process = crate::scheduler::Process::new(fn_ptr, 0, core::slice::from_ref(&arg), 0, true);
    let pid = process.pid;
    scheduler.add_process(process);
    pid
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
