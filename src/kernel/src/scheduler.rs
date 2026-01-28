use crate::ipc::IpcSpace;
use crate::kprintln;
use crate::process::CpuContext;
use crate::vfs::FileHandle;
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

static PID_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum ProcessState {
    Ready,
    Running,
    Dead,
}

pub struct Process {
    pub pid: u64,
    pub state: ProcessState,
    pub context: CpuContext,
    pub stack: Vec<u8>,
    pub ipc_space: IpcSpace,
    pub files: Vec<Option<FileHandle>>,
    pub signal_mask: u32,
}

impl Process {
    pub fn new(
        entry_point: u64,
        user_sp: u64,
        args: &[u64],
        tls_base: u64,
        is_64bit: bool,
    ) -> Self {
        let stack_size = 64 * 1024;
        let stack = vec![0u8; stack_size];
        let sp = (stack.as_ptr() as u64 + stack.len() as u64) & !15;

        kprintln!(
            "Creating process: KStack top {:x}, UStack top {:x}",
            sp,
            user_sp
        );

        let mut context = CpuContext::default();
        context.regs[11] = sp; // sp

        unsafe extern "C" {
            fn kernel_thread_starter();
        }
        context.regs[12] = kernel_thread_starter as *const () as u64; // x30/lr

        let mut actual_entry = entry_point;
        let mut spsr = 0x3c0u64; // Sets bits 9,8,7,6 (DAIF masked)
        if !is_64bit {
            if (entry_point & 1) != 0 {
                spsr |= 0x20; // T bit (Thumb mode)
                actual_entry &= !1;
            }
            spsr &= !(1 << 9); // Clear E bit for AArch32 Little Endian
            spsr |= 0x10; // User mode (A32)
        }
        context.regs[0] = actual_entry; // x19
        context.regs[1] = user_sp; // x20
        context.regs[8] = spsr; // x27 (spsr)
        context.regs[9] = tls_base; // x28 -> TLS
        kprintln!(
            "Process::new: entry={:x} (actual={:x}), user_sp={:x}, spsr={:x} -> regs[0]={:x}, regs[1]={:x}",
            entry_point,
            actual_entry,
            user_sp,
            spsr,
            context.regs[0],
            context.regs[1]
        );

        // Pass up to 6 args in x21..x26 (context.regs[2..8])
        context.regs[2..(args.len().min(6) + 2)].copy_from_slice(&args[..args.len().min(6)]);

        context.regs[10] = 0; // x29 (frame pointer)

        Self {
            pid: PID_COUNTER.fetch_add(1, Ordering::Relaxed),
            state: ProcessState::Ready,
            context,
            stack,
            ipc_space: IpcSpace::new(),
            files: {
                let mut f = Vec::with_capacity(32);
                f.push(crate::vfs::open("/dev/random")); // stdin
                f.push(crate::vfs::open("/dev/random")); // stdout
                f.push(crate::vfs::open("/dev/random")); // stderr
                for _ in 3..32 {
                    f.push(None);
                }
                f
            },
            signal_mask: 0,
        }
    }
}

pub struct Scheduler {
    pub processes: VecDeque<Box<Process>>,
    pub current_process: Option<Box<Process>>,
}

impl Scheduler {
    pub const fn new() -> Self {
        Self {
            processes: VecDeque::new(),
            current_process: None,
        }
    }

    pub fn add_process(&mut self, process: Process) {
        self.processes.push_back(Box::new(process));
    }

    // Returns (ptr_to_prev_ctx, ptr_to_next_ctx)
    // Box<Process> ensures memory location of Process struct is stable on heap.
    pub fn schedule_next(&mut self) -> Option<(Option<*mut CpuContext>, *const CpuContext)> {
        if let Some(next_proc) = self.processes.pop_front() {
            // We have a next process.

            // If there is a current process, put it back in queue.
            if let Some(mut prev) = self.current_process.take() {
                prev.state = ProcessState::Ready;
                self.processes.push_back(prev);
            }

            // Promote next to current
            self.current_process = Some(next_proc);

            // Now we need pointers.

            let next_ctx_ptr = &self.current_process.as_ref().unwrap().context as *const CpuContext;

            // Prev address? It is now at the BACK of the queue.
            let prev_ctx_ptr = self
                .processes
                .back_mut()
                .map(|p| &mut p.context as *mut CpuContext);

            Some((prev_ctx_ptr, next_ctx_ptr))
        } else {
            // No ready process. Keep running current.
            None
        }
    }

    pub fn current_pid(&self) -> u64 {
        self.current_process.as_ref().map(|p| p.pid).unwrap_or(0)
    }

    pub fn current_ipc_space(&mut self) -> Option<&mut IpcSpace> {
        self.current_process.as_mut().map(|p| &mut p.ipc_space)
    }
}

pub static SCHEDULER: Mutex<Scheduler> = Mutex::new(Scheduler::new());
