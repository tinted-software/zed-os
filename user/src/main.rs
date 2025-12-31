#![no_std]
#![no_main]

use core::arch::asm;
use core::panic::PanicInfo;

fn sys_yield() {
    unsafe {
        asm!("svc #0", in("x8") 0);
    }
}

fn sys_write(s: &str) {
    unsafe {
        asm!(
            "svc #0",
            in("x8") 2,
            in("x0") s.as_ptr(),
            in("x1") s.len(),
        );
    }
}

fn sys_spawn(f: fn(u64), arg: u64) -> u64 {
    let pid: u64;
    unsafe {
        asm!(
            "svc #0",
            in("x8") 3,
            in("x0") f as u64,
            in("x1") arg,
            lateout("x0") pid,
        );
    }
    pid
}

fn sys_getpid() -> u64 {
    let pid: u64;
    unsafe {
        asm!(
            "svc #0",
            in("x8") 4,
            lateout("x0") pid,
        );
    }
    pid
}

fn worker(arg: u64) {
    loop {
        sys_write("Worker Thread (Arg ");
        // Print arg (single digit hack)
        let digit = b'0' + (arg as u8);
        let buf = [digit];
        unsafe {
            asm!(
               "svc #0",
               in("x8") 2,
               in("x0") buf.as_ptr(),
               in("x1") 1,
            );
        }
        sys_write(")\n");

        sys_yield();
        for _ in 0..1000000 {
            unsafe { asm!("nop") }
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let pid = sys_getpid();

    sys_write("Main Thread Started. PID: ");
    let digit = b'0' + (pid as u8);
    let buf = [digit];
    sys_write(core::str::from_utf8(&buf).unwrap());
    sys_write("\n");

    if pid == 1 {
        sys_write("Spawning Worker...\n");
        let worker_pid = sys_spawn(worker, 5);
        sys_write("Spawned PID ");
        let digit = b'0' + (worker_pid as u8);
        let buf = [digit];
        sys_write(core::str::from_utf8(&buf).unwrap());
        sys_write("\n");
    }

    loop {
        sys_write("Main Loop\n");
        sys_yield();
        for _ in 0..2000000 {
            unsafe { asm!("nop") }
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
