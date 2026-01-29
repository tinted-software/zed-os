use crate::kprintln;
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
    pub next_name: u32,
}

impl IpcSpace {
    pub fn new() -> Self {
        let mut space = Self {
            ports: BTreeMap::new(),
            next_name: 0x200, // Start user ports at 0x200
        };
        // Pre-allocate some common ports: 1=host, 2=task, 3=thread
        for i in 1..=3 {
            space
                .ports
                .insert(i as MachPort, Arc::new(Mutex::new(Port::new())));
        }
        space
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

    if (option & MACH_SEND_MSG) != 0 {
        let dest_name = header.msgh_remote_port;

        // Synchronous Host RPCs: Generate and queue a reply immediately
        if (dest_name == 1 || dest_name == 2 || dest_name == 3)
            && (3400..3500).contains(&header.msgh_id)
        {
            handle_host_rpc(&header, msg, space);
        } else if let Some(port) = space.get_port(dest_name) {
            let mut p = port.lock();
            // Copy message body
            let size = header.msgh_size as usize;
            let mut buf = alloc::vec![0u8; size];
            unsafe {
                core::ptr::copy_nonoverlapping(msg as *const u8, buf.as_mut_ptr(), size);
            }
            // Keep queue size small to avoid heap exhaustion
            if p.messages.len() > 10 {
                p.messages.remove(0);
            }
            p.messages.push(buf);
        } else {
            return MACH_SEND_INVALID_DEST;
        }
    }

    if (option & MACH_RCV_MSG) != 0 {
        // Receiving
        if let Some(port) = space.get_port(rcv_name) {
            let mut p = port.lock();
            if let Some(data) = p.messages.pop() {
                let mut size = data.len();
                // Copy out
                if size > rcv_size as usize {
                    // If it's just a few bytes larger, truncate it instead of failing
                    if size <= (rcv_size as usize + 16) {
                        size = rcv_size as usize;
                    } else {
                        p.messages.push(data); // Put it back
                        return 0x10004004; // MACH_RCV_TOO_LARGE
                    }
                }

                unsafe {
                    core::ptr::copy_nonoverlapping(data.as_ptr(), msg as *mut u8, size);
                    // Header is already in the data, but we might need to update some fields
                    // relative to the receiver's view.
                    (*msg).msgh_local_port = rcv_name;
                }
                return MACH_MSG_SUCCESS;
            } else {
                return MACH_RCV_TIMED_OUT;
            }
        } else {
            return 0x10000003; // MACH_PORT_UNKNOWN / invalid name
        }
    }

    MACH_MSG_SUCCESS
}

fn handle_host_rpc(header: &MachMsgHeader, _msg: *mut MachMsgHeader, space: &mut IpcSpace) {
    let reply_port_name = header.msgh_local_port;
    if let Some(port) = space.get_port(reply_port_name) {
        let mut p = port.lock();
        let mut reply = alloc::vec![0u8; 256];
        let r_hdr = reply.as_mut_ptr() as *mut MachMsgHeader;
        unsafe {
            (*r_hdr).msgh_bits = 0x12; // MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0)
            (*r_hdr).msgh_remote_port = 0; // Kernel/Host
            (*r_hdr).msgh_local_port = reply_port_name;
            (*r_hdr).msgh_id = header.msgh_id + 100;

            // Get flavor (first int after header)
            let flavor = *(_msg as *const i32).add(6);
            kprintln!("Host RPC id={} flavor={}", header.msgh_id, flavor);

            match header.msgh_id {
                3409 => {
                    // host_info
                    (*r_hdr).msgh_size = 100; // Larger buffer
                    let data_ptr = reply.as_mut_ptr().add(24) as *mut i32;
                    core::ptr::write_bytes(data_ptr, 0, 76);

                    if flavor == 1 {
                        // HOST_BASIC_INFO
                        *data_ptr = 1; // max_cpus
                        *data_ptr.add(1) = 1; // avail_cpus
                        *data_ptr.add(2) = 1024 * 1024 * 1024; // memory_size
                        *data_ptr.add(3) = 12; // cpu_type: ARM
                        *data_ptr.add(4) = 9; // cpu_subtype: V7
                        *data_ptr.add(5) = 1; // cpu_threadtype
                        *data_ptr.add(6) = 1; // physical_cpu
                        *data_ptr.add(7) = 1; // physical_cpu_max
                        *data_ptr.add(8) = 1; // logical_cpu
                        *data_ptr.add(9) = 1; // logical_cpu_max
                        *(data_ptr.add(10) as *mut u64) = 1024 * 1024 * 1024; // max_mem
                    }
                }
                3402 => {
                    // host_page_size
                    (*r_hdr).msgh_size = 28;
                    let data_ptr = reply.as_mut_ptr().add(24) as *mut u32;
                    *data_ptr = 4096;
                }
                3406 => {
                    // host_get_clock_service
                    (*r_hdr).msgh_size = 28;
                    let data_ptr = reply.as_mut_ptr().add(24) as *mut u32;
                    *data_ptr = 0x104; // Fake clock port
                }
                3407 => {
                    // host_kernel_version
                    (*r_hdr).msgh_size = 128;
                    let data_ptr = reply.as_mut_ptr().add(24) as *mut u8;
                    let ver = b"Darwin Kernel Version 11.0.0: arm-v7; root:xnu-1699.22.73~1/RELEASE_ARM_S5L8940X\0";
                    core::ptr::copy_nonoverlapping(ver.as_ptr(), data_ptr, ver.len().min(100));
                }
                _ => {
                    (*r_hdr).msgh_size = 24;
                }
            }
            reply.truncate((*r_hdr).msgh_size as usize);
        }
        // Keep queue size small
        if p.messages.len() > 10 {
            p.messages.remove(0);
        }
        p.messages.push(reply);
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SharedRegionMapping {
    pub address: u64,
    pub size: u64,
    pub file_offset: u64,
    pub max_prot: u32,
    pub init_prot: u32,
}
