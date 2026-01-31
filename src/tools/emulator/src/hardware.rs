use std::collections::HashMap;
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Uart;

impl Uart {
    pub fn new() -> Self {
        Self {}
    }

    pub fn read(&self, offset: u32) -> u32 {
        match offset {
            0x10 => 0x6, // UTRSTAT - TX empty | RX empty(0) | TX buf empty
            0x14 => 0x0, // UERSTAT
            0x18 => 0x0, // UFSTAT - RX FIFO count 0, TX FIFO count 0
            _ => 0,
        }
    }

    pub fn write(&mut self, offset: u32, value: u32) {
        match offset {
            0x20 => {
                // UTXH - Transmit char
                let c = value as u8;
                print!("{}", c as char);
                let _ = io::stdout().flush();
            }
            _ => {
                // eprintln!("UART Write: Offset 0x{:x}, Value 0x{:x}", offset, value);
            }
        }
    }
}

pub struct Timer {
    pub control: u32,
}

impl Timer {
    pub fn new() -> Self {
        Self { control: 0 }
    }

    pub fn read(&self, offset: u32) -> u32 {
        match offset {
            0x00 => self.control, // TCON
            0x04 => {
                // TCNT - Return generic time-based counter
                let start = SystemTime::now();
                let since_epoch = start.duration_since(UNIX_EPOCH).unwrap();
                (since_epoch.as_micros() & 0xFFFFFFFF) as u32
            }
            _ => 0,
        }
    }

    pub fn write(&mut self, offset: u32, value: u32) {
        match offset {
            0x00 => self.control = value,
            _ => {}
        }
    }
}

pub struct GenericStub {
    pub name: String,
    pub regs: HashMap<u32, u32>,
}

impl GenericStub {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            regs: HashMap::new(),
        }
    }

    pub fn read(&self, offset: u32) -> u32 {
        let val = *self.regs.get(&offset).unwrap_or(&0);
        // eprintln!("{} Read: Offset 0x{:x}, Value 0x{:x}", self.name, offset, val);
        val
    }

    pub fn write(&mut self, offset: u32, value: u32) {
        // eprintln!("{} Write: Offset 0x{:x}, Value 0x{:x}", self.name, offset, value);
        self.regs.insert(offset, value);
    }
}

pub struct Usb {
    pub regs: HashMap<u32, u32>,
}

impl Usb {
    pub fn new() -> Self {
        let mut regs = HashMap::new();
        // DWC2 ID register
        regs.insert(0x40, 0x4f54280a); // GSNPSID - Synopsys OTG ID
        regs.insert(0x44, 0x4f54280a);
        // GRSTCTL - AHB Idle bit should be 1
        regs.insert(0x10, 0x80000000);
        // GINTSTS - Interrupt status
        regs.insert(0x14, 0x04000000);
        // GHWCFG2 - Hardware Config 2
        regs.insert(0x48, 0x228ddd10);
        Self { regs }
    }

    pub fn read(&self, offset: u32) -> u32 {
        let val = *self.regs.get(&offset).unwrap_or(&0);
        if offset != 0x14 && offset != 0x10 {
            eprintln!("USB Read: Offset 0x{:04x}, Value 0x{:08x}", offset, val);
        }
        val
    }

    pub fn write(&mut self, offset: u32, mut value: u32) {
        if offset < 0x2000 {
            eprintln!("USB Write: Offset 0x{:04x}, Value 0x{:08x}", offset, value);
        }

        match offset {
            0x10 => {
                // GRSTCTL
                if (value & 1) != 0 {
                    value &= !1; // Clear Soft Reset
                    value |= 0x80000000; // Set AHB Idle
                }
                if (value & 2) != 0 {
                    value &= !2; // Clear HSOTG Soft Reset
                }
            }
            0x14 => {
                // GINTSTS (W1C bits)
                let old_val = *self.regs.get(&offset).unwrap_or(&0);
                value = old_val & !value;
            }
            _ => {}
        }

        self.regs.insert(offset, value);
    }
}

pub struct Hardware {
    pub uart0: Uart,
    pub timer: Timer,
    pub vic: GenericStub,
    pub pmgr: GenericStub,
    pub usb: Usb,
    pub usb_ehci: GenericStub,
    pub usb_ohci0: GenericStub,
    pub usb_ohci1: GenericStub,
    pub gpio: GenericStub,
    pub otgphy: GenericStub,
    pub iop: GenericStub,
    pub dart1: GenericStub,
    pub dart2: GenericStub,
}

impl Hardware {
    pub fn new() -> Self {
        Self {
            uart0: Uart::new(),
            timer: Timer::new(),
            vic: GenericStub::new("VIC"),
            pmgr: GenericStub::new("PMGR"),
            usb: Usb::new(),
            usb_ehci: GenericStub::new("EHCI"),
            usb_ohci0: GenericStub::new("OHCI0"),
            usb_ohci1: GenericStub::new("OHCI1"),
            gpio: GenericStub::new("GPIO"),
            otgphy: GenericStub::new("OTGPHY"),
            iop: GenericStub::new("IOP"),
            dart1: GenericStub::new("DART1"),
            dart2: GenericStub::new("DART2"),
        }
    }

    fn get_canonical(&self, addr: u32) -> u32 {
        addr & 0x7FFFFFFF
    }

    pub fn read(&self, addr: u32) -> Option<u32> {
        let caddr = self.get_canonical(addr);

        if caddr >= 0x02500000 && caddr <= 0x02500FFF {
            return Some(self.uart0.read(caddr - 0x02500000));
        }
        if caddr >= 0x3C700000 && caddr <= 0x3C700FFF {
            return Some(self.timer.read(caddr - 0x3C700000));
        }
        if caddr >= 0x3F200000 && caddr <= 0x3F23FFFF {
            return Some(self.vic.read(caddr - 0x3F200000));
        }
        if caddr >= 0x3F100000 && caddr <= 0x3F107FFF {
            return Some(self.pmgr.read(caddr - 0x3F100000));
        }
        // USB
        if caddr >= 0x3F108000 && caddr <= 0x3F118000 {
            // Device
            return Some(self.usb.read(caddr - 0x3F108000));
        }
        if caddr >= 0x3F408000 && caddr <= 0x3F418000 {
            // EHCI
            return Some(self.usb_ehci.read(caddr - 0x3F408000));
        }
        if caddr >= 0x3F508000 && caddr <= 0x3F518000 {
            // OHCI0
            return Some(self.usb_ohci0.read(caddr - 0x3F508000));
        }
        if caddr >= 0x3F608000 && caddr <= 0x3F618000 {
            // OHCI1
            return Some(self.usb_ohci1.read(caddr - 0x3F608000));
        }

        if caddr >= 0x06000000 && caddr <= 0x06000FFF {
            return Some(self.otgphy.read(caddr - 0x06000000));
        }
        if caddr >= 0x06300000 && caddr <= 0x06300FFF {
            return Some(self.iop.read(caddr - 0x06300000));
        }
        if caddr >= 0x08d00000 && caddr <= 0x08d00FFF {
            return Some(self.dart1.read(caddr - 0x08d00000));
        }
        if caddr >= 0x09d00000 && caddr <= 0x09d00FFF {
            return Some(self.dart2.read(caddr - 0x09d00000));
        }
        if caddr >= 0x3FA00000 && caddr <= 0x3FA00FFF {
            return Some(self.gpio.read(caddr - 0x3FA00000));
        }

        None
    }

    pub fn write(&mut self, addr: u32, value: u32) -> bool {
        let caddr = self.get_canonical(addr);

        if caddr >= 0x02500000 && caddr <= 0x02500FFF {
            self.uart0.write(caddr - 0x02500000, value);
            return true;
        }
        if caddr >= 0x3C700000 && caddr <= 0x3C700FFF {
            self.timer.write(caddr - 0x3C700000, value);
            return true;
        }
        if caddr >= 0x3F200000 && caddr <= 0x3F23FFFF {
            self.vic.write(caddr - 0x3F200000, value);
            return true;
        }
        if caddr >= 0x3F100000 && caddr <= 0x3F107FFF {
            self.pmgr.write(caddr - 0x3F100000, value);
            return true;
        }
        // USB
        if caddr >= 0x3F108000 && caddr <= 0x3F118000 {
            self.usb.write(caddr - 0x3F108000, value);
            return true;
        }
        if caddr >= 0x3F408000 && caddr <= 0x3F418000 {
            self.usb_ehci.write(caddr - 0x3F408000, value);
            return true;
        }
        if caddr >= 0x3F508000 && caddr <= 0x3F518000 {
            self.usb_ohci0.write(caddr - 0x3F508000, value);
            return true;
        }
        if caddr >= 0x3F608000 && caddr <= 0x3F618000 {
            self.usb_ohci1.write(caddr - 0x3F608000, value);
            return true;
        }

        if caddr >= 0x06000000 && caddr <= 0x06000FFF {
            if (caddr - 0x06000000) == 0x8 {
                eprintln!("OTGPHY Reset write: 0x{:x}", value);
            }
            self.otgphy.write(caddr - 0x06000000, value);
            return true;
        }
        if caddr >= 0x06300000 && caddr <= 0x06300FFF {
            self.iop.write(caddr - 0x06300000, value);
            return true;
        }
        if caddr >= 0x08d00000 && caddr <= 0x08d00FFF {
            self.dart1.write(caddr - 0x08d00000, value);
            return true;
        }
        if caddr >= 0x09d00000 && caddr <= 0x09d00FFF {
            self.dart2.write(caddr - 0x09d00000, value);
            return true;
        }
        if caddr >= 0x3FA00000 && caddr <= 0x3FA00FFF {
            self.gpio.write(caddr - 0x3FA00000, value);
            return true;
        }

        false
    }
}
