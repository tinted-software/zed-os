use crate::kprintln;
use crate::process::CpuContext;
use alloc::boxed::Box;
use alloc::collections::VecDeque;
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
    pub is_aarch32: bool,
}

impl Process {
    pub fn new(entry_point: u64, user_sp: u64, args: &[u64], tls_base: u64) -> Self {
        let stack_size = 64 * 1024;
        let mut stack = Vec::with_capacity(stack_size);
        unsafe { stack.set_len(stack_size) };
        let sp = stack.as_ptr() as u64 + stack.len() as u64;

        kprintln!(
            "Creating process: KStack top {:x}, UStack top {:x}",
            sp,
            user_sp
        );

        let mut context = CpuContext::default();
        context.regs[12] = sp; // sp

        unsafe extern "C" {
            fn kernel_thread_starter();
        }
        context.regs[11] = kernel_thread_starter as *const () as u64; // x30/lr

        context.regs[0] = entry_point; // x19
        context.regs[1] = user_sp; // x20
        context.regs[9] = tls_base; // x28 -> TLS
        kprintln!(
            "Process::new: entry={:x}, user_sp={:x} -> regs[0]={:x}, regs[1]={:x}",
            entry_point,
            user_sp,
            context.regs[0],
            context.regs[1]
        );

        // Pass up to 6 args in x21..x26
        for i in 0..args.len().min(6) {
            context.regs[2 + i] = args[i];
        }

        // Detect if entry point is Thumb (bit 0 set)
        let is_thumb = (entry_point & 1) != 0;
        let is_a32 = true; // For now assume all new processes are A32 for iOS 5

        let mut flags = 0u64;
        if is_a32 {
            flags |= 1;
        }
        if is_thumb {
            flags |= 2;
        }
        context.regs[8] = flags; // x27

        Self {
            pid: PID_COUNTER.fetch_add(1, Ordering::Relaxed),
            state: ProcessState::Ready,
            context,
            stack,
            is_aarch32: is_a32,
        }
    }

    pub fn set_user_sp(&mut self, sp: u64) {
        self.context.regs[1] = sp; // x20
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

            return Some((prev_ctx_ptr, next_ctx_ptr));
        } else {
            // No ready process. Keep running current.
            return None;
        }
    }
}

pub static SCHEDULER: Mutex<Scheduler> = Mutex::new(Scheduler::new());
