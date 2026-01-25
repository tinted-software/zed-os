use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

pub type MachPort = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortRight {
    Receive,
    Send,
    SendOnce,
    DeadName,
}

pub struct Port {
    pub messages: Vec<Vec<u8>>,
}

impl Port {
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
        }
    }
}

pub struct IpcSpace {
    pub ports: BTreeMap<MachPort, Arc<Mutex<Port>>>,
    // Map port name to (Port, Right)
    // For now, simplify: we just store the port.
    // In reality, we need to know what right we have.
    // But for a single-process/stub implementation, this is fine.
    pub next_name: u32,
}

impl IpcSpace {
    pub fn new() -> Self {
        Self {
            ports: BTreeMap::new(),
            next_name: 0x100, // Start user ports at 0x100
        }
    }

    pub fn allocate_port(&mut self) -> MachPort {
        let name = self.next_name;
        self.next_name += 1;
        let port = Arc::new(Mutex::new(Port::new()));
        self.ports.insert(name, port);
        name
    }

    pub fn get_port(&self, name: MachPort) -> Option<Arc<Mutex<Port>>> {
        self.ports.get(&name).cloned()
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct MachMsgHeader {
    pub msgh_bits: u32,
    pub msgh_size: u32,
    pub msgh_remote_port: u32,
    pub msgh_local_port: u32,
    pub msgh_reserved: u32,
    pub msgh_id: i32,
}

pub const MACH_SEND_MSG: u32 = 0x00000001;
pub const MACH_RCV_MSG: u32 = 0x00000002;

pub const MACH_MSG_SUCCESS: u32 = 0x00000000;
pub const MACH_RCV_TIMED_OUT: u32 = 0x10004003;
pub const MACH_SEND_INVALID_DEST: u32 = 0x10000003;

pub fn mach_msg(
    msg: *mut MachMsgHeader,
    option: u32,
    _send_size: u32,
    rcv_size: u32,
    rcv_name: MachPort,
    _timeout: u32,
    _notify: u32,
    space: &mut IpcSpace,
) -> u32 {
    // Validate pointer
    if msg.is_null() {
        return 0x10000000; // KERN_INVALID_ADDRESS
    }

    // Read header
    let header = unsafe { core::ptr::read_volatile(msg) };

    // kprintln!("ipc: mach_msg id={} bits={:x} local={:x} remote={:x} opt={:x}",
    //     header.msgh_id, header.msgh_bits, header.msgh_local_port, header.msgh_remote_port, option);

    if (option & MACH_SEND_MSG) != 0 {
        // Sending
        let dest_name = header.msgh_remote_port;
        if let Some(port) = space.get_port(dest_name) {
            let mut p = port.lock();
            // Copy message body
            let size = header.msgh_size as usize;
            let mut buf = alloc::vec![0u8; size];
            unsafe {
                core::ptr::copy_nonoverlapping(msg as *const u8, buf.as_mut_ptr(), size);
            }
            p.messages.push(buf);
            // kprintln!("ipc: sent message to port {:x} (qlen={})", dest_name, p.messages.len());
        } else {
            // kprintln!("ipc: invalid dest port {:x}", dest_name);
            return MACH_SEND_INVALID_DEST;
        }
    }

    if (option & MACH_RCV_MSG) != 0 {
        // Receiving
        // rcv_name is where we listen.
        // But mach_msg usually receives on msgh_local_port?
        // No, the syscall arg `rcv_name` specifies the receive right.

        // kprintln!("ipc: receiving on port {:x}", rcv_name);

        if let Some(port) = space.get_port(rcv_name) {
            let mut p = port.lock();
            if let Some(data) = p.messages.pop() {
                // Copy out
                if data.len() > rcv_size as usize {
                    // Message too large
                    // header.msgh_bits |= MACH_RCV_TOO_LARGE; // bit 10?
                    // header.msgh_size = data.len() as u32;
                    // unsafe { core::ptr::write_volatile(msg, header); }
                    return 0x10004004; // MACH_RCV_TOO_LARGE
                }

                unsafe {
                    core::ptr::copy_nonoverlapping(data.as_ptr(), msg as *mut u8, data.len());
                }
                // kprintln!("ipc: received message ({} bytes)", data.len());
                return MACH_MSG_SUCCESS;
            } else {
                // No messages
                // If timeout is 0, return immediately
                return MACH_RCV_TIMED_OUT;
            }
        } else {
            return 0x10000003; // MACH_PORT_UNKNOWN / invalid name
        }
    }

    MACH_MSG_SUCCESS
}
