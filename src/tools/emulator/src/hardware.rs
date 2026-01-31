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
            _ => {}
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

pub struct Vic;

impl Vic {
    pub fn new() -> Self {
        Self
    }

    pub fn read(&self, offset: u32) -> u32 {
        // Implement read logic or return default
        0
    }

    pub fn write(&mut self, offset: u32, value: u32) {
        // Log VIC writes for debugging
        // println!("VIC Write: Offset 0x{:x}, Value 0x{:x}", offset, value);
    }
}

pub struct Usb;

impl Usb {
    pub fn new() -> Self {
        Self
    }

    pub fn read(&self, offset: u32) -> u32 {
        0
    }

    pub fn write(&mut self, offset: u32, value: u32) {
        // println!("USB Write: Offset 0x{:x}, Value 0x{:x}", offset, value);
    }
}

pub struct Hardware {
    pub uart0: Uart,
    pub timer: Timer,
    pub vic: Vic,
    pub usb: Usb,
}

impl Hardware {
    pub fn new() -> Self {
        Self {
            uart0: Uart::new(),
            timer: Timer::new(),
            vic: Vic::new(),
            usb: Usb::new(),
        }
    }

    pub fn read(&self, addr: u32) -> Option<u32> {
        // UART0
        if addr >= 0x82500000 && addr <= 0x82500040 {
            return Some(self.uart0.read(addr - 0x82500000));
        }

        // Also check 0x80020000 (Device Tree/Alternate UART)
        if addr >= 0x80020000 && addr <= 0x80020040 {
            return Some(self.uart0.read(addr - 0x80020000));
        }

        // Timer
        if addr >= 0x3C700000 && addr <= 0x3C700040 {
            return Some(self.timer.read(addr - 0x3C700000));
        }

        // VIC
        if addr >= 0xBFF00000 && addr <= 0xBFFFFFFF {
            return Some(self.vic.read(addr - 0xBFF00000));
        }

        // USB (Guessing range based on typical S5L)
        if addr >= 0x80080000 && addr <= 0x8009FFFF {
            return Some(self.usb.read(addr - 0x80080000));
        }

        None
    }

    pub fn write(&mut self, addr: u32, value: u32) -> bool {
        // UART0
        if addr >= 0x82500000 && addr <= 0x82500040 {
            self.uart0.write(addr - 0x82500000, value);
            return true;
        }

        // Timer
        if addr >= 0x3C700000 && addr <= 0x3C700040 {
            self.timer.write(addr - 0x3C700000, value);
            return true;
        }

        // VIC
        if addr >= 0xBFF00000 && addr <= 0xBFFFFFFF {
            self.vic.write(addr - 0xBFF00000, value);
            return true;
        }

        // USB
        if addr >= 0x80080000 && addr <= 0x8009FFFF {
            self.usb.write(addr - 0x80080000, value);
            return true;
        }

        false
    }
}
